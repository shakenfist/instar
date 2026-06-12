//! Snapshot operation: list / apply / create / delete qcow2 internal snapshots.
//!
//! Phase 8 of `PLAN-snapshot.md` lands `MODE_APPLY`, the last
//! mutating mode; `MODE_LIST` (phase 3), `MODE_CREATE` (phase 6)
//! and `MODE_DELETE` (phase 7) are unchanged in behaviour
//! (delete's find now goes through the shared raw-table finder
//! in name-only mode).
//!
//! Flow:
//! 1. Read [`SnapshotConfig`] at [`OPERATION_CONFIG_ADDR`] and
//!    validate magic + sector-size invariant.
//! 2. Read sector 0 from device 0 and run
//!    [`detect_format_from_header`].
//! 3. Refuse non-qcow2 sources with `ERROR_UNSUPPORTED_FORMAT`.
//! 4. Parse the qcow2 header (`QcowHeader::parse`) to recover
//!    `virtual_size`, `nb_snapshots`, `snapshots_offset`.
//! 5. Dispatch on `config.mode`:
//!    - `MODE_LIST` (0): stream snapshot entries via
//!      [`qcow2::for_each_snapshot_entry`] and convert each entry to
//!      a [`SnapshotEntryRecord`] with
//!      [`qcow2::snapshot_entry_to_record`]; send via
//!      `call_table.send_snapshot_entry`.
//!    - `MODE_CREATE` (2): the 12-step qemu-faithful create
//!      (`run_create`).
//!    - `MODE_DELETE` (3): the qemu-faithful delete
//!      (`run_delete`).
//!    - `MODE_APPLY` (1): the qemu-faithful apply / "goto"
//!      (`run_apply`).
//!    - Otherwise: `ERROR_INVALID_CONFIG` for the unknown mode.
//! 6. Build a [`SnapshotResult`] and emit it via
//!    `send_snapshot_result`, then signal `send_complete`.
//!
//! `MODE_CREATE` / `MODE_DELETE` / `MODE_APPLY` are the mutating
//! paths. The input
//! image is opened RW on slot 0 (the host uses
//! `BackingStore::open_rw_existing` with a generous capacity hint so
//! the guest can write past EOF to grow the file on demand). All
//! reads / writes go through the sector-bounce RMW helpers
//! (`read_input_byte_range` / `write_input_byte_range`), modelled on
//! the commit binary. The create writeback ordering mirrors qemu's
//! `qcow2_snapshot_create` + `qcow2_write_snapshots`:
//!
//!   A: L1 copy, dirty L2s, rewritten active L1, dirty refblocks
//!   fsync
//!   B: new snapshot table
//!   fsync
//!   C: the 12-byte header write at offset 60 (nb_snapshots +
//!      snapshots_offset) — the commit point
//!   fsync
//!   D: free the old snapshot table's clusters (skipped when there
//!      was no old table)
//!   fsync
//!
//! The delete writeback ordering mirrors qemu's
//! `qcow2_snapshot_delete` (find -> compact -> write table ->
//! header -> decrement chain -> free L1 -> free old table ->
//! COPIED refresh on the active chain), adapted to the staged
//! model with the header write as the commit point:
//!
//!   precheck: read-only refcount validation before ANY write
//!     (no qemu equivalent; a corrupt image fails here with the
//!     file untouched)
//!   A: compacted table + refblocks carrying the table-allocation
//!      bumps only (skipped when the remaining count is 0)
//!   fsync
//!   B: the 12-byte header write at offset 60 (nb_snapshots - 1 +
//!      the new table offset, or 0 / 0 when the table empties) —
//!      the commit point
//!   fsync
//!   (in-memory: chain decrements via update_snapshot_refcount,
//!    snapshot-L1 free, old-table free — qemu's "we won't recover
//!    but just leak clusters" zone — then the COPIED refresh over
//!    the ACTIVE chain and over the DELETED chain's staged L2s,
//!    both at post-decrement refcounts)
//!   C: refblocks (now carrying the decrements) + active L1 +
//!      active L2 set + the deleted chain's SURVIVING L2s
//!      (refcount >= 1 — shared with another snapshot or the
//!      active chain — with refreshed COPIED flags, matching
//!      qemu's -1-walk flush; freed L2s are never written, the
//!      cache-discard exemption)
//!   fsync
//!
//! The apply writeback ordering mirrors qemu's
//! `qcow2_snapshot_goto` (find -> validate geometry -> +1 walk
//! over the snapshot's chain -> pwrite_sync of the snapshot's L1
//! over the active L1 -> -1 walk over the old active chain ->
//! addend-0 COPIED refresh), adapted to the staged model — see
//! `run_apply`'s doc comment for the group A / B / C breakdown
//! (B, the active-L1 overwrite, is the commit point; apply never
//! touches the snapshot table or the header).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use qcow2::{
    QcowHeader, AUTOCLEAR_FEATURES_OFFSET, INCOMPAT_COMPRESSION, INCOMPAT_CORRUPT, INCOMPAT_DIRTY,
    INCOMPAT_EXTENDED_L2, INCOMPAT_EXTERNAL_DATA, L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COMPRESSED,
    OFLAG_COPIED,
};
use shared::{
    format_detection::detect_format_from_header, validate_call_table, CallTable, ImageFormat,
    SnapshotConfig, SnapshotResult, CALL_TABLE_ADDR, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR,
    SCRATCH_MEM_BASE,
};
use snapshot::qcow2::{
    alloc_contiguous_clusters_in_refblocks, check_refcount_after_addend,
    precheck_snapshot_refcount, read_refcount_in_block, set_refcount_in_block,
    update_copied_flags_for_l1, update_snapshot_refcount, AllocCursor, SnapshotRefcountOp,
};
use snapshot::table::{
    build_snapshot_table, build_snapshot_table_without, find_snapshot_in_table, format_decimal_u64,
    serialize_snapshot_entry, snapshot_table_byte_len, MatchMode, NewSnapshotEntry,
};
use snapshot::SnapshotError;

// ---------------------------------------------------------------------------
// Scratch layout
// ---------------------------------------------------------------------------
//
// List mode (phase 3) only needs HEADER_BUF + CACHE_BUF_A. Create
// mode (phase 6) adds the commit-style staging regions: the raw old
// snapshot table, the active L1, the L1 copy, the L2 staging arena,
// the refcount table, the refblock host-offset array, the refblocks
// arena, the new-table build buffer, and a sector-sized RMW bounce
// buffer. Delete mode (phase 7) appends a second L1 + L2 staging
// set for the deleted snapshot's chain (regions whose lifetimes
// don't overlap — L1_COPY_BUF — are create-only and left unused by
// delete). Apply mode (phase 8) stages both chains exactly like
// delete (the target snapshot's chain in the SNAP_* regions, the
// old active chain in the create-mode regions) and repurposes
// NEW_TABLE_BUF — apply allocates no snapshot table — for the
// zero-padded new-L1 working copy.

const HEADER_BUF: usize = SCRATCH_MEM_BASE;
const CACHE_BUF_A: usize = HEADER_BUF + MAX_SECTOR_SIZE;

// Create-mode staging (each region's start follows the previous).
const OLD_TABLE_BUF: usize = CACHE_BUF_A + MAX_SECTOR_SIZE;
const OLD_TABLE_LIMIT: usize = 64 * 1024;

const ACTIVE_L1_BUF: usize = OLD_TABLE_BUF + OLD_TABLE_LIMIT;
const ACTIVE_L1_LIMIT: usize = 64 * 1024;

const L1_COPY_BUF: usize = ACTIVE_L1_BUF + ACTIVE_L1_LIMIT;
const L1_COPY_LIMIT: usize = 64 * 1024;

const L2_STAGING: usize = L1_COPY_BUF + L1_COPY_LIMIT;
const L2_STAGING_LIMIT: usize = 2 * 1024 * 1024;

const RT_BUF: usize = L2_STAGING + L2_STAGING_LIMIT;
const RT_LIMIT: usize = 64 * 1024;

const RB_OFFSETS: usize = RT_BUF + RT_LIMIT;
const RB_OFFSETS_LIMIT: usize = 16 * 1024;

const REFBLOCKS_BUF: usize = RB_OFFSETS + RB_OFFSETS_LIMIT;
const REFBLOCKS_LIMIT: usize = 2 * 1024 * 1024;

const NEW_TABLE_BUF: usize = REFBLOCKS_BUF + REFBLOCKS_LIMIT;
const NEW_TABLE_LIMIT: usize = 66 * 1024;

const RMW_BOUNCE: usize = NEW_TABLE_BUF + NEW_TABLE_LIMIT;
const RMW_BOUNCE_LIMIT: usize = MAX_SECTOR_SIZE;

// Delete-mode staging (phase 7): the deleted snapshot's L1 and its
// L2 set form a SECOND staged chain (delete needs both chains: the
// snapshot's for the decrement walk, the active's for the COPIED
// refresh — no dedup between them, see phase plan open question 6).
const SNAP_L1_BUF: usize = RMW_BOUNCE + RMW_BOUNCE_LIMIT;
const SNAP_L1_LIMIT: usize = 64 * 1024;

const SNAP_L2_STAGING: usize = SNAP_L1_BUF + SNAP_L1_LIMIT;
const SNAP_L2_STAGING_LIMIT: usize = 2 * 1024 * 1024;

const _: () = assert!(
    SNAP_L2_STAGING + SNAP_L2_STAGING_LIMIT <= shared::ALLOC_HEAP_BASE,
    "snapshot create/delete scratch layout overlaps the allocator heap"
);

/// Upper bound on staged L2 tables. 256 covers a 128 GiB qcow2
/// with 64 KiB clusters; same bound as the commit binary.
const MAX_STAGED_L2: usize = 256;
/// Upper bound on staged refcount blocks (constrained by
/// `REFBLOCKS_LIMIT / cluster_size`); same bound as commit.
const MAX_REFBLOCKS: usize = 32;

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Build a populated `SnapshotResult` and send it via the call
/// table, then signal `send_complete` so the host VMM knows the
/// guest has finished.
///
/// # Safety
///
/// `call_table` must be the validated initialised CallTable from
/// `_start`.
unsafe fn finish(
    call_table: &CallTable,
    mode: u32,
    error: u32,
    snapshots_emitted: u32,
    bytes_read: u64,
) -> u64 {
    finish_with_id(call_table, mode, error, snapshots_emitted, bytes_read, &[])
}

/// Like [`finish`] but populates `assigned_id` (used by
/// `MODE_CREATE`).
///
/// # Safety
///
/// Same contract as [`finish`].
unsafe fn finish_with_id(
    call_table: &CallTable,
    mode: u32,
    error: u32,
    snapshots_emitted: u32,
    bytes_read: u64,
    assigned_id: &[u8],
) -> u64 {
    let mut id_buf = [0u8; 64];
    let id_len = assigned_id.len().min(64);
    id_buf[..id_len].copy_from_slice(&assigned_id[..id_len]);
    let result = SnapshotResult {
        magic: SnapshotResult::MAGIC,
        mode,
        error,
        _pad: 0,
        snapshots_emitted,
        assigned_id_len: id_len as u32,
        assigned_id: id_buf,
        _reserved: [0; 96],
    };
    (call_table.send_snapshot_result)(&result);
    let success = error == SnapshotResult::ERROR_OK;
    (call_table.send_complete)(b"snapshot\0".as_ptr(), bytes_read, success);
    bytes_read
}

// ---------------------------------------------------------------------------
// Sector-bounce RMW helpers for input slot 0
// ---------------------------------------------------------------------------

/// Read `len` bytes from input device `dev` at `byte_offset` into
/// `dst_ptr`. Sub-sector reads go through the bounce buffer at
/// `RMW_BOUNCE`. Mirrors commit's `read_input_byte_range`.
unsafe fn read_input_byte_range(
    call_table: &CallTable,
    dev: u32,
    sector_size: usize,
    byte_offset: u64,
    dst_ptr: *mut u8,
    len: usize,
) -> bool {
    if len == 0 {
        return true;
    }
    let bounce_ptr = RMW_BOUNCE as *mut u8;
    let mut done: usize = 0;
    let mut cur = byte_offset;
    while done < len {
        let sector = cur / sector_size as u64;
        let in_off = (cur % sector_size as u64) as usize;
        let take = (sector_size - in_off).min(len - done);
        if in_off == 0 && take == sector_size {
            if !(call_table.read_input_sector)(dev, sector, dst_ptr.add(done), sector_size) {
                return false;
            }
        } else {
            if !(call_table.read_input_sector)(dev, sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(bounce_ptr.add(in_off), dst_ptr.add(done), take);
        }
        done += take;
        cur += take as u64;
    }
    true
}

/// Write `bytes` to input device `dev` at `byte_offset`. Sub-sector
/// writes go through read-modify-write via the bounce buffer at
/// `RMW_BOUNCE`. Mirrors commit's `write_input_byte_range`.
unsafe fn write_input_byte_range(
    call_table: &CallTable,
    dev: u32,
    sector_size: usize,
    byte_offset: u64,
    bytes: &[u8],
) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let bounce_ptr = RMW_BOUNCE as *mut u8;
    let mut done: usize = 0;
    let mut cur = byte_offset;
    while done < bytes.len() {
        let sector = cur / sector_size as u64;
        let in_off = (cur % sector_size as u64) as usize;
        let take = (sector_size - in_off).min(bytes.len() - done);
        if in_off == 0 && take == sector_size {
            if !(call_table.write_input_sector)(dev, sector, bytes.as_ptr().add(done), sector_size)
            {
                return false;
            }
        } else {
            if !(call_table.read_input_sector)(dev, sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(bytes.as_ptr().add(done), bounce_ptr.add(in_off), take);
            if !(call_table.write_input_sector)(dev, sector, bounce_ptr, sector_size) {
                return false;
            }
        }
        done += take;
        cur += take as u64;
    }
    true
}

fn read_u64_be(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

// ---------------------------------------------------------------------------
// Staged L2 bookkeeping
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct StagedL2 {
    l1_idx: u32,
    host_offset: u64,
}

/// One staged L1->L2 chain: the L2 clusters referenced by an L1,
/// copied into a scratch arena at `base`, with the (l1_idx, host
/// offset) bookkeeping needed to look a staged L2 up by L1 index
/// and to write it back. Create stages one chain (the active L1);
/// delete stages two (the deleted snapshot's chain for the
/// decrement walk, the active chain for the COPIED refresh).
struct StagedL2Set {
    /// Scratch base address of the first staged L2 cluster.
    base: usize,
    /// Bytes per staged L2 cluster (== the qcow2 cluster size).
    cluster_size_usize: usize,
    /// Number of populated `entries`.
    count: usize,
    /// (l1_idx, host_offset) per staged L2, in staging order.
    entries: [StagedL2; MAX_STAGED_L2],
}

impl StagedL2Set {
    /// Shared view of the staged L2 bytes for `l1_idx`, if staged.
    fn l2_for_index(&self, l1_idx: u32) -> Option<&'static [u8]> {
        let mut k = 0usize;
        while k < self.count {
            if self.entries[k].l1_idx == l1_idx {
                let ptr = (self.base + k * self.cluster_size_usize) as *const u8;
                // SAFETY: the staging arena was populated by
                // stage_l2_set and is exclusively owned by this set.
                return Some(unsafe { core::slice::from_raw_parts(ptr, self.cluster_size_usize) });
            }
            k += 1;
        }
        None
    }

    /// Mutable view of the staged L2 bytes for `l1_idx`, if staged.
    fn l2_for_index_mut(&self, l1_idx: u32) -> Option<&'static mut [u8]> {
        let mut k = 0usize;
        while k < self.count {
            if self.entries[k].l1_idx == l1_idx {
                let ptr = (self.base + k * self.cluster_size_usize) as *mut u8;
                // SAFETY: as above; the COPIED-flag pass visits each
                // L1 index once, so no aliasing mutable views exist.
                return Some(unsafe {
                    core::slice::from_raw_parts_mut(ptr, self.cluster_size_usize)
                });
            }
            k += 1;
        }
        None
    }
}

fn map_snapshot_error(e: SnapshotError) -> u32 {
    u32::from(e)
}

// ---------------------------------------------------------------------------
// Shared staging helpers (create + delete)
// ---------------------------------------------------------------------------
//
// Factored out of phase 6's run_create so MODE_DELETE composes the
// same stages instead of copy-pasting them. Behaviourally identical
// to the phase 6 inline code (same gate order, same messages, same
// error codes) — re-verified by re-running the phase 6 harnesses.

/// The mutating-mode feature gates (phase 6 step 1, shared by
/// delete): encryption, external data file, compression,
/// dirty / corrupt, the bitmaps autoclear bit, and the
/// `refcount_bits == 16` allocator restriction. Returns the
/// `SnapshotResult::ERROR_*` code on refusal.
///
/// # Safety
///
/// `call_table` must be the validated CallTable; `header` the
/// staged sector-0 slice.
unsafe fn mutating_feature_gates(
    call_table: &CallTable,
    hdr: &QcowHeader,
    header: &[u8],
) -> Option<u32> {
    if hdr.crypt_method != 0 {
        (call_table.verbose_print)(b"snapshot: LUKS/encrypted refused\n\0".as_ptr());
        return Some(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    if hdr.has_external_data || (hdr.incompatible_features & INCOMPAT_EXTERNAL_DATA) != 0 {
        (call_table.verbose_print)(b"snapshot: external data file refused\n\0".as_ptr());
        return Some(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    if hdr.compression_type != 0 || (hdr.incompatible_features & INCOMPAT_COMPRESSION) != 0 {
        (call_table.verbose_print)(b"snapshot: compression refused\n\0".as_ptr());
        return Some(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    if (hdr.incompatible_features & (INCOMPAT_DIRTY | INCOMPAT_CORRUPT)) != 0
        || hdr.dirty
        || hdr.corrupt
    {
        (call_table.verbose_print)(b"snapshot: dirty/corrupt image refused\n\0".as_ptr());
        return Some(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    // Bitmaps extension: autoclear feature bit 0, raw header u64 at
    // offset 88 (AUTOCLEAR_FEATURES_OFFSET). QcowHeader does not
    // surface autoclear bits, so read them from the staged sector.
    if header.len() >= AUTOCLEAR_FEATURES_OFFSET + 8 {
        let autoclear = read_u64_be(header, AUTOCLEAR_FEATURES_OFFSET);
        if (autoclear & 0x1) != 0 {
            (call_table.verbose_print)(b"snapshot: bitmaps extension refused\n\0".as_ptr());
            return Some(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
        }
    }
    if hdr.refcount_bits != 16 {
        (call_table.verbose_print)(b"snapshot: refcount_bits != 16 refused\n\0".as_ptr());
        return Some(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    None
}

/// Stage the raw on-disk snapshot table into `OLD_TABLE_BUF` and
/// return its exact byte length (phase 6's two-phase read: stage
/// up to the bound, then measure with `snapshot_table_byte_len`).
/// The caller must only invoke this when `nb_snapshots > 0`.
///
/// # Safety
///
/// `call_table` must be the validated CallTable.
unsafe fn stage_old_table(
    call_table: &CallTable,
    sector_size: usize,
    input_capacity: u64,
    snapshots_offset: u64,
    nb_snapshots: u32,
) -> Result<usize, u32> {
    let stage_len = OLD_TABLE_LIMIT;
    // Clamp the read to the device size to avoid reading past EOF.
    let dev_bytes = input_capacity.saturating_mul(sector_size as u64);
    let avail = dev_bytes.saturating_sub(snapshots_offset);
    let to_read = (stage_len as u64).min(avail) as usize;
    if to_read == 0
        || !read_input_byte_range(
            call_table,
            0,
            sector_size,
            snapshots_offset,
            OLD_TABLE_BUF as *mut u8,
            to_read,
        )
    {
        return Err(SnapshotResult::ERROR_PARSE_FAILED);
    }
    let old_slice = core::slice::from_raw_parts(OLD_TABLE_BUF as *const u8, to_read);
    match snapshot_table_byte_len(old_slice, nb_snapshots) {
        Ok(n) => {
            if n > OLD_TABLE_LIMIT {
                return Err(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
            }
            Ok(n)
        }
        Err(e) => Err(map_snapshot_error(e)),
    }
}

/// Stage every L2 table referenced by the L1 at `l1_ptr` into the
/// staging arena at `staging_base`, applying the compressed-cluster
/// gate to each staged table (phase 6's inline walk). Returns the
/// populated [`StagedL2Set`].
///
/// # Safety
///
/// `call_table` must be the validated CallTable; `l1_ptr` must
/// point at `l1_size_bytes` staged L1 bytes; the staging arena
/// `[staging_base, staging_base + staging_limit)` must be unused
/// scratch.
unsafe fn stage_l2_set(
    call_table: &CallTable,
    sector_size: usize,
    l1_ptr: *const u8,
    l1_size_bytes: usize,
    cluster_size_usize: usize,
    extended_l2: bool,
    staging_base: usize,
    staging_limit: usize,
) -> Result<StagedL2Set, u32> {
    let mut set = StagedL2Set {
        base: staging_base,
        cluster_size_usize,
        count: 0,
        entries: [StagedL2 {
            l1_idx: 0,
            host_offset: 0,
        }; MAX_STAGED_L2],
    };
    let l1_buf = core::slice::from_raw_parts(l1_ptr, l1_size_bytes);
    let mut cursor = staging_base;
    let cap_end = staging_base + staging_limit;
    let l1_entries = l1_size_bytes / 8;
    for i in 0..l1_entries {
        let entry = read_u64_be(l1_buf, i * 8);
        let l2_host = entry & L1_OFFSET_MASK;
        if l2_host == 0 {
            continue;
        }
        if set.count >= MAX_STAGED_L2 || cursor + cluster_size_usize > cap_end {
            return Err(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
        }
        if !read_input_byte_range(
            call_table,
            0,
            sector_size,
            l2_host,
            cursor as *mut u8,
            cluster_size_usize,
        ) {
            return Err(SnapshotResult::ERROR_PARSE_FAILED);
        }
        // Gate on compressed entries during the L2 walk.
        let l2_slice = core::slice::from_raw_parts(cursor as *const u8, cluster_size_usize);
        let stride = if extended_l2 { 16usize } else { 8usize };
        let mut j = 0usize;
        while j + 8 <= cluster_size_usize {
            let e = read_u64_be(l2_slice, j);
            if (e & OFLAG_COMPRESSED) != 0 {
                (call_table.verbose_print)(b"snapshot: compressed cluster refused\n\0".as_ptr());
                return Err(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
            }
            j += stride;
        }
        set.entries[set.count] = StagedL2 {
            l1_idx: i as u32,
            host_offset: l2_host,
        };
        set.count += 1;
        cursor += cluster_size_usize;
    }
    Ok(set)
}

/// Stage the refcount table into `RT_BUF`, collect the contiguous
/// refblock host offsets into `RB_OFFSETS` (the v1 contiguity
/// gate: populated refblocks must run gap-free from refcount-table
/// index 0), and stage the refblock bytes into `REFBLOCKS_BUF`.
/// Returns the refblock count.
///
/// # Safety
///
/// `call_table` must be the validated CallTable.
unsafe fn stage_refblocks(
    call_table: &CallTable,
    hdr: &QcowHeader,
    sector_size: usize,
) -> Result<usize, u32> {
    let cluster_size_usize = hdr.cluster_size as usize;
    let rt_size = (hdr.refcount_table_clusters as usize).saturating_mul(cluster_size_usize);
    if rt_size > RT_LIMIT {
        return Err(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    if rt_size > 0
        && !read_input_byte_range(
            call_table,
            0,
            sector_size,
            hdr.refcount_table_offset,
            RT_BUF as *mut u8,
            rt_size,
        )
    {
        return Err(SnapshotResult::ERROR_PARSE_FAILED);
    }
    let rt = core::slice::from_raw_parts(RT_BUF as *const u8, rt_size);

    // Collect refblock host offsets. v1 requires the populated
    // refblocks to be contiguous from refcount-table index 0 (no
    // gaps), so the flat allocator / refblock-mapping math is sound.
    // The first zero RT entry terminates the contiguous run.
    let mut refblock_count: usize = 0;
    {
        let mut i = 0usize;
        let mut seen_zero = false;
        while i + 8 <= rt_size {
            let entry = read_u64_be(rt, i) & L1_OFFSET_MASK;
            if entry != 0 {
                if seen_zero {
                    // Non-contiguous refblock layout: refuse (v1).
                    (call_table.verbose_print)(
                        b"snapshot: non-contiguous refcount table refused\n\0".as_ptr(),
                    );
                    return Err(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
                }
                refblock_count += 1;
            } else {
                seen_zero = true;
            }
            i += 8;
        }
    }
    if refblock_count == 0 || refblock_count > MAX_REFBLOCKS {
        return Err(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    let rb_offsets_ptr = RB_OFFSETS as *mut u64;
    let rb_offsets = core::slice::from_raw_parts_mut(rb_offsets_ptr, refblock_count);
    for (k, slot) in rb_offsets.iter_mut().enumerate() {
        *slot = read_u64_be(rt, k * 8) & L1_OFFSET_MASK;
    }
    let rb_total = refblock_count.saturating_mul(cluster_size_usize);
    if rb_total > REFBLOCKS_LIMIT {
        return Err(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    for (k, host_off) in rb_offsets.iter().copied().enumerate() {
        let dst = (REFBLOCKS_BUF + k * cluster_size_usize) as *mut u8;
        if !read_input_byte_range(
            call_table,
            0,
            sector_size,
            host_off,
            dst,
            cluster_size_usize,
        ) {
            return Err(SnapshotResult::ERROR_PARSE_FAILED);
        }
    }
    Ok(refblock_count)
}

/// The cluster-host-offset -> (staged refblock byte offset, entry
/// index) mapping closure both refcount walks use. Refblocks are
/// contiguous from RT index 0, so refblock slot == cluster_index /
/// entries_per_refblock.
fn rb_lookup(
    cluster_size: u64,
    entries_per_refblock: u64,
    refblock_count: usize,
    cluster_size_usize: usize,
) -> impl Fn(u64) -> Option<(usize, u64)> + Copy {
    move |host_offset: u64| {
        let cluster_index = host_offset / cluster_size;
        let rb_slot = (cluster_index / entries_per_refblock) as usize;
        let entry_local = cluster_index % entries_per_refblock;
        if rb_slot >= refblock_count {
            return None;
        }
        Some((rb_slot * cluster_size_usize, entry_local))
    }
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "snapshot");

    (call_table.verbose_print)(b"snapshot: start\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const SnapshotConfig);
    let sector_size_ok = config.sector_size >= 512
        && config.sector_size as usize <= MAX_SECTOR_SIZE
        && config.sector_size.is_power_of_two();
    if !config.is_valid() || !sector_size_ok {
        return finish(
            call_table,
            config.mode,
            SnapshotResult::ERROR_INVALID_CONFIG,
            0,
            0,
        );
    }

    let sector_size = config.sector_size as usize;
    let mut bytes_read: u64 = 0;

    // Read first sector for format detection and qcow2 header parse.
    let header_ptr = HEADER_BUF as *mut u8;
    if !(call_table.read_input_sector)(0, 0, header_ptr, sector_size) {
        return finish(
            call_table,
            config.mode,
            SnapshotResult::ERROR_IO,
            0,
            bytes_read,
        );
    }
    bytes_read += sector_size as u64;

    let header = core::slice::from_raw_parts(header_ptr, sector_size);
    let format = detect_format_from_header(header, sector_size, false);
    if format != ImageFormat::Qcow2 {
        (call_table.verbose_print)(b"snapshot: non-qcow2 source rejected\n\0".as_ptr());
        return finish(
            call_table,
            config.mode,
            SnapshotResult::ERROR_UNSUPPORTED_FORMAT,
            0,
            bytes_read,
        );
    }

    let hdr = match QcowHeader::parse(header) {
        Some(h) => h,
        None => {
            return finish(
                call_table,
                config.mode,
                SnapshotResult::ERROR_PARSE_FAILED,
                0,
                bytes_read,
            );
        }
    };
    let virtual_size = hdr.virtual_size;
    let nb_snapshots = hdr.nb_snapshots;
    let snapshots_offset = hdr.snapshots_offset;

    match config.mode {
        SnapshotConfig::MODE_LIST => {
            if nb_snapshots == 0 {
                return finish(
                    call_table,
                    SnapshotConfig::MODE_LIST,
                    SnapshotResult::ERROR_OK,
                    0,
                    bytes_read,
                );
            }

            let input_capacity = (call_table.get_input_capacity)(0);
            let cache_a = CACHE_BUF_A as *mut u8;
            let mut snapshots_emitted: u32 = 0;
            let all_visited = qcow2::for_each_snapshot_entry(
                call_table,
                0,
                nb_snapshots,
                snapshots_offset,
                sector_size,
                input_capacity,
                cache_a,
                &mut bytes_read,
                |entry| -> bool {
                    let record = qcow2::snapshot_entry_to_record(entry, virtual_size);
                    (call_table.send_snapshot_entry)(&record);
                    snapshots_emitted += 1;
                    true
                },
            );
            if !all_visited {
                return finish(
                    call_table,
                    SnapshotConfig::MODE_LIST,
                    SnapshotResult::ERROR_IO,
                    snapshots_emitted,
                    bytes_read,
                );
            }
            finish(
                call_table,
                SnapshotConfig::MODE_LIST,
                SnapshotResult::ERROR_OK,
                snapshots_emitted,
                bytes_read,
            )
        }
        SnapshotConfig::MODE_CREATE => {
            run_create(call_table, config, &hdr, header, sector_size, bytes_read)
        }
        SnapshotConfig::MODE_APPLY => {
            run_apply(call_table, config, &hdr, header, sector_size, bytes_read)
        }
        SnapshotConfig::MODE_DELETE => {
            run_delete(call_table, config, &hdr, header, sector_size, bytes_read)
        }
        _ => finish(
            call_table,
            config.mode,
            SnapshotResult::ERROR_INVALID_CONFIG,
            0,
            bytes_read,
        ),
    }
}

/// MODE_CREATE: the 12-step qemu-faithful create.
///
/// # Safety
///
/// `call_table` is the validated table; `header` is the staged
/// sector-0 slice at `HEADER_BUF`; `hdr` is its parse.
unsafe fn run_create(
    call_table: &CallTable,
    config: &SnapshotConfig,
    hdr: &QcowHeader,
    header: &[u8],
    sector_size: usize,
    mut bytes_read: u64,
) -> u64 {
    let mode = SnapshotConfig::MODE_CREATE;

    macro_rules! fail {
        ($err:expr) => {
            return finish(call_table, mode, $err, 0, bytes_read)
        };
    }

    // ----- Step 1: feature gates (shared with delete) --------------------
    if let Some(code) = mutating_feature_gates(call_table, hdr, header) {
        fail!(code);
    }

    let cluster_size = hdr.cluster_size;
    let cluster_size_usize = cluster_size as usize;
    let cluster_bits = hdr.cluster_bits;
    let extended_l2 = (hdr.incompatible_features & INCOMPAT_EXTENDED_L2) != 0 || hdr.extended_l2;
    let l1_size = hdr.l1_size;
    let l1_size_bytes = (l1_size as usize).saturating_mul(8);

    // Staging bound checks (same posture as commit).
    if l1_size_bytes > ACTIVE_L1_LIMIT || l1_size_bytes > L1_COPY_LIMIT {
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }

    // ----- Step 2: stream existing entries -> max_id, old table len -----
    if hdr.nb_snapshots >= 16 {
        (call_table.verbose_print)(b"snapshot: 16-snapshot v1 cap reached\n\0".as_ptr());
        fail!(SnapshotResult::ERROR_SNAPSHOT_TABLE_FULL);
    }

    let input_capacity = (call_table.get_input_capacity)(0);
    let mut max_id: u64 = 0;
    if hdr.nb_snapshots > 0 {
        let cache_a = CACHE_BUF_A as *mut u8;
        let ok = qcow2::for_each_snapshot_entry(
            call_table,
            0,
            hdr.nb_snapshots,
            hdr.snapshots_offset,
            sector_size,
            input_capacity,
            cache_a,
            &mut bytes_read,
            |entry| -> bool {
                let id = snapshot::table::parse_decimal_id(&entry.id[..entry.id_len as usize])
                    .unwrap_or(0);
                if id > max_id {
                    max_id = id;
                }
                true
            },
        );
        if !ok {
            fail!(SnapshotResult::ERROR_IO);
        }
    }

    // Stage the raw old snapshot table and cross-check its byte
    // length against the streamed walk.
    let old_table_len = if hdr.nb_snapshots > 0 {
        match stage_old_table(
            call_table,
            sector_size,
            input_capacity,
            hdr.snapshots_offset,
            hdr.nb_snapshots,
        ) {
            Ok(n) => n,
            Err(code) => fail!(code),
        }
    } else {
        0
    };

    // ----- Step 3: assign the new ID = max_id + 1 -----------------------
    let mut id_buf = [0u8; 24];
    let new_id = max_id.saturating_add(1);
    let id_len = format_decimal_u64(new_id, &mut id_buf);
    if id_len == 0 {
        fail!(SnapshotResult::ERROR_PARSE_FAILED);
    }

    // ----- Stage active L1 ----------------------------------------------
    let active_l1_ptr = ACTIVE_L1_BUF as *mut u8;
    if l1_size_bytes > 0
        && !read_input_byte_range(
            call_table,
            0,
            sector_size,
            hdr.l1_table_offset,
            active_l1_ptr,
            l1_size_bytes,
        )
    {
        fail!(SnapshotResult::ERROR_PARSE_FAILED);
    }

    // ----- Stage L2 tables referenced by the active L1 ------------------
    let active_set = match stage_l2_set(
        call_table,
        sector_size,
        active_l1_ptr,
        l1_size_bytes,
        cluster_size_usize,
        extended_l2,
        L2_STAGING,
        L2_STAGING_LIMIT,
    ) {
        Ok(s) => s,
        Err(code) => fail!(code),
    };

    // ----- Stage the refcount table and refblocks -----------------------
    let refblock_count = match stage_refblocks(call_table, hdr, sector_size) {
        Ok(n) => n,
        Err(code) => fail!(code),
    };
    let rb_offsets = core::slice::from_raw_parts(RB_OFFSETS as *const u64, refblock_count);
    let rb_total = refblock_count.saturating_mul(cluster_size_usize);

    let entries_per_refblock = (cluster_size * 8) / 16;

    // ----- Step 5 (open question 6): copy active L1 verbatim BEFORE -----
    // any flag rewrite, exactly like qemu.
    if l1_size_bytes > 0 {
        core::ptr::copy_nonoverlapping(active_l1_ptr, L1_COPY_BUF as *mut u8, l1_size_bytes);
    }

    // ----- Step 4: allocate the snapshot's L1 copy clusters -------------
    // ceil(l1_size * 8 / cluster_size) contiguous clusters. For a
    // 0-byte virtual disk (l1_size == 0) qemu allocates 0 bytes and
    // stores the active l1_table_offset (which is itself 0); we mirror
    // that — no allocation, snap_l1_offset = hdr.l1_table_offset.
    let mut alloc_cursor = AllocCursor::default();
    let refblocks = core::slice::from_raw_parts_mut(REFBLOCKS_BUF as *mut u8, rb_total);

    let l1_copy_clusters = (l1_size_bytes as u64).div_ceil(cluster_size).max(0);
    let snap_l1_offset = if l1_copy_clusters == 0 {
        hdr.l1_table_offset
    } else {
        match alloc_contiguous_clusters_in_refblocks(
            refblocks,
            cluster_size,
            16,
            refblock_count as u64,
            0,
            l1_copy_clusters,
            &mut alloc_cursor,
        ) {
            Ok(off) => off,
            Err(SnapshotError::RefcountExhausted) => {
                fail!(SnapshotResult::ERROR_ALLOCATION_FAILED)
            }
            Err(e) => fail!(map_snapshot_error(e)),
        }
    };

    // ----- Step 8: serialise the new entry + build the new table --------
    let arg_len = (config.arg_len as usize).min(config.arg.len());
    let name = &config.arg[..arg_len];
    let new_entry = NewSnapshotEntry {
        l1_table_offset: snap_l1_offset,
        l1_size,
        id: &id_buf[..id_len],
        name,
        date_sec: config.date_sec,
        date_nsec: config.date_nsec,
        vm_clock_nsec: 0,
        vm_state_size: 0,
        vm_state_size_large: 0,
        disk_size: hdr.virtual_size,
        icount: 0,
    };
    // Serialise the new entry into a stack scratch buffer first,
    // then build the full table. Sized for the worst case: 40-byte
    // header + 24-byte extra data + 24-byte id + 256-byte name.
    let mut entry_buf = [0u8; 40 + 24 + 24 + 256];
    let new_entry_len = match serialize_snapshot_entry(&new_entry, &mut entry_buf) {
        Ok(n) => n,
        Err(e) => fail!(map_snapshot_error(e)),
    };

    let old_table_slice = if old_table_len > 0 {
        core::slice::from_raw_parts(OLD_TABLE_BUF as *const u8, old_table_len)
    } else {
        &[]
    };
    let new_table = core::slice::from_raw_parts_mut(NEW_TABLE_BUF as *mut u8, NEW_TABLE_LIMIT);
    let new_table_len = match build_snapshot_table(
        old_table_slice,
        old_table_len,
        &entry_buf[..new_entry_len],
        new_table,
    ) {
        Ok(n) => n,
        Err(e) => fail!(map_snapshot_error(e)),
    };

    // Allocate contiguous clusters for the new snapshot table.
    let new_table_clusters = (new_table_len as u64).div_ceil(cluster_size).max(1);
    let new_table_offset = match alloc_contiguous_clusters_in_refblocks(
        refblocks,
        cluster_size,
        16,
        refblock_count as u64,
        0,
        new_table_clusters,
        &mut alloc_cursor,
    ) {
        Ok(off) => off,
        Err(SnapshotError::RefcountExhausted) => fail!(SnapshotResult::ERROR_ALLOCATION_FAILED),
        Err(e) => fail!(map_snapshot_error(e)),
    };

    // ----- Step 6: refcount pass (IncrementForCreate) over active L1 ----
    // rb_lookup maps a cluster's host offset to (byte offset within
    // the staged refblocks buffer, entry-local index).
    let refblock_byte_offset_for_cluster = rb_lookup(
        cluster_size,
        entries_per_refblock,
        refblock_count,
        cluster_size_usize,
    );

    {
        let active_l1_slice = core::slice::from_raw_parts(active_l1_ptr, l1_size_bytes);
        match update_snapshot_refcount(
            SnapshotRefcountOp::IncrementForCreate {
                snapshot_l1: active_l1_slice,
            },
            refblocks,
            cluster_bits,
            16,
            extended_l2,
            |i| active_set.l2_for_index(i),
            refblock_byte_offset_for_cluster,
        ) {
            Ok(()) => {}
            Err(SnapshotError::RefcountOverflow { .. }) => {
                fail!(SnapshotResult::ERROR_REFCOUNT_OVERFLOW)
            }
            Err(e) => fail!(map_snapshot_error(e)),
        }
    }

    // ----- Step 7: COPIED-flag rewrite over the active L1 / L2 ----------
    // refcount_for_cluster reads the current refcount from the staged
    // refblocks (post-increment).
    let refcount_for_cluster = |host_offset: u64| -> Option<u64> {
        let (base, entry_local) = refblock_byte_offset_for_cluster(host_offset)?;
        let block = &refblocks[base..base + cluster_size_usize];
        read_refcount_in_block(block, entry_local, 16).ok()
    };
    {
        let active_l1_mut = core::slice::from_raw_parts_mut(active_l1_ptr, l1_size_bytes);
        if let Err(e) = update_copied_flags_for_l1(
            active_l1_mut,
            cluster_bits,
            |i| active_set.l2_for_index_mut(i),
            refcount_for_cluster,
            extended_l2,
        ) {
            fail!(map_snapshot_error(e));
        }
    }

    // ----- Step 9: writeback group A ------------------------------------
    // L1 copy (from PRE-flag-rewrite bytes), dirty L2s, rewritten
    // active L1, refblocks. fsync.
    if l1_copy_clusters > 0 {
        let l1_copy = core::slice::from_raw_parts(L1_COPY_BUF as *const u8, l1_size_bytes);
        if !write_input_byte_range(call_table, 0, sector_size, snap_l1_offset, l1_copy) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    // Dirty L2s: every staged L2 (each had at least one allocated
    // entry, so its COPIED flags changed during the create's 1->2
    // refcount transition). Write them all back.
    for k in 0..active_set.count {
        let l2 = core::slice::from_raw_parts(
            (L2_STAGING + k * cluster_size_usize) as *const u8,
            cluster_size_usize,
        );
        if !write_input_byte_range(
            call_table,
            0,
            sector_size,
            active_set.entries[k].host_offset,
            l2,
        ) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    // Rewritten active L1.
    if l1_size_bytes > 0 {
        let active_l1 = core::slice::from_raw_parts(active_l1_ptr, l1_size_bytes);
        if !write_input_byte_range(call_table, 0, sector_size, hdr.l1_table_offset, active_l1) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    // Refblocks (covering the data/L2 increments and the new
    // allocations).
    for (k, host_off) in rb_offsets.iter().copied().enumerate() {
        let block = &refblocks[k * cluster_size_usize..(k + 1) * cluster_size_usize];
        if !write_input_byte_range(call_table, 0, sector_size, host_off, block) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    if !(call_table.fsync_input)(0) {
        fail!(SnapshotResult::ERROR_IO);
    }

    // ----- Step 10: writeback group B (new snapshot table) --------------
    {
        let table_bytes = core::slice::from_raw_parts(NEW_TABLE_BUF as *const u8, new_table_len);
        if !write_input_byte_range(call_table, 0, sector_size, new_table_offset, table_bytes) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    if !(call_table.fsync_input)(0) {
        fail!(SnapshotResult::ERROR_IO);
    }

    // ----- Step 11: writeback group C (the commit point) ----------------
    // 12 bytes at header offset 60: nb_snapshots (u32 BE) +
    // snapshots_offset (u64 BE).
    let mut header_patch = [0u8; 12];
    header_patch[0..4].copy_from_slice(&(hdr.nb_snapshots + 1).to_be_bytes());
    header_patch[4..12].copy_from_slice(&new_table_offset.to_be_bytes());
    if !write_input_byte_range(call_table, 0, sector_size, 60, &header_patch) {
        fail!(SnapshotResult::ERROR_IO);
    }
    if !(call_table.fsync_input)(0) {
        fail!(SnapshotResult::ERROR_IO);
    }

    // ----- Step 12: writeback group D (free old table) ------------------
    // Decrement the old table's clusters in the staged refblocks and
    // write those refblocks back. Skipped when there was no old
    // table. Phase 7 (open question 3) aligned this free to a
    // decrement, qemu's semantics: identical bytes on well-formed
    // images (the old table's refcount is 1) but an underflow now
    // surfaces a double-free bookkeeping bug instead of masking it.
    if hdr.nb_snapshots > 0 && old_table_len > 0 {
        let old_table_clusters = (old_table_len as u64).div_ceil(cluster_size).max(1);
        let first_cluster = hdr.snapshots_offset / cluster_size;
        let mut touched = [false; MAX_REFBLOCKS];
        for c in 0..old_table_clusters {
            let cluster_index = first_cluster + c;
            let rb_slot = (cluster_index / entries_per_refblock) as usize;
            let entry_local = cluster_index % entries_per_refblock;
            if rb_slot >= refblock_count {
                // Old table lives outside the staged refblocks; can't
                // free it safely. Leave it (it merely leaks).
                continue;
            }
            let base = rb_slot * cluster_size_usize;
            let block = &mut refblocks[base..base + cluster_size_usize];
            let freed = read_refcount_in_block(block, entry_local, 16)
                .and_then(|cur| check_refcount_after_addend(cur, -1, 16))
                .and_then(|new_val| set_refcount_in_block(block, entry_local, 16, new_val));
            if freed.is_err() {
                fail!(SnapshotResult::ERROR_IO);
            }
            if rb_slot < MAX_REFBLOCKS {
                touched[rb_slot] = true;
            }
        }
        for (k, host_off) in rb_offsets.iter().copied().enumerate() {
            if k >= MAX_REFBLOCKS || !touched[k] {
                continue;
            }
            let block = &refblocks[k * cluster_size_usize..(k + 1) * cluster_size_usize];
            if !write_input_byte_range(call_table, 0, sector_size, host_off, block) {
                fail!(SnapshotResult::ERROR_IO);
            }
        }
        if !(call_table.fsync_input)(0) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }

    let _ = L2_OFFSET_MASK;
    let _ = OFLAG_COPIED;
    finish_with_id(
        call_table,
        mode,
        SnapshotResult::ERROR_OK,
        0,
        bytes_read,
        &id_buf[..id_len],
    )
}

/// MODE_DELETE: the qemu-faithful delete (phase 7).
///
/// Mirrors `qcow2_snapshot_delete` from qemu 10.0.x, adapted to
/// the staged model (see the module docs for the write-group
/// ordering). Matching is by NAME ONLY, first match in table
/// order — `bdrv_snapshot_find` does a plain `strcmp(sn->name,
/// name)` scan and **ID matching does not exist** on the qemu 10
/// delete path (phase plan fact 2; `qcow2::find_snapshot`'s
/// id-or-name semantics are deliberately not used). The find
/// walks the RAW staged table so the comparison covers the full
/// on-disk name, independent of the bounded parser's 63-byte
/// id/name truncation; an empty argument is allowed and matches
/// an empty-named snapshot.
///
/// # Safety
///
/// `call_table` is the validated table; `header` is the staged
/// sector-0 slice at `HEADER_BUF`; `hdr` is its parse.
unsafe fn run_delete(
    call_table: &CallTable,
    config: &SnapshotConfig,
    hdr: &QcowHeader,
    header: &[u8],
    sector_size: usize,
    bytes_read: u64,
) -> u64 {
    let mode = SnapshotConfig::MODE_DELETE;

    macro_rules! fail {
        ($err:expr) => {
            return finish(call_table, mode, $err, 0, bytes_read)
        };
    }

    // ----- Step 1: feature gates (identical set to create) ---------------
    if let Some(code) = mutating_feature_gates(call_table, hdr, header) {
        fail!(code);
    }

    let cluster_size = hdr.cluster_size;
    let cluster_size_usize = cluster_size as usize;
    let cluster_bits = hdr.cluster_bits;
    let extended_l2 = (hdr.incompatible_features & INCOMPAT_EXTENDED_L2) != 0 || hdr.extended_l2;
    let active_l1_bytes = (hdr.l1_size as usize).saturating_mul(8);
    if active_l1_bytes > ACTIVE_L1_LIMIT {
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }

    // ----- Step 2: find the target by name (first match) -----------------
    // Not-found must be decided before any write; an image with no
    // snapshots can't match anything (qemu prints "snapshot not
    // found" and exits 1 without touching the file).
    if hdr.nb_snapshots == 0 {
        (call_table.verbose_print)(b"snapshot: delete on 0-snapshot image\n\0".as_ptr());
        fail!(SnapshotResult::ERROR_NOT_FOUND);
    }
    let input_capacity = (call_table.get_input_capacity)(0);
    let old_table_len = match stage_old_table(
        call_table,
        sector_size,
        input_capacity,
        hdr.snapshots_offset,
        hdr.nb_snapshots,
    ) {
        Ok(n) => n,
        Err(code) => fail!(code),
    };
    let old_table = core::slice::from_raw_parts(OLD_TABLE_BUF as *const u8, old_table_len);

    // The argument is passed through verbatim by the host. An
    // arg_len beyond the wire buffer cannot be compared and so
    // matches nothing (parity: qemu-img-created names are at most
    // 255 bytes, and qemu's own matcher would find nothing either).
    // The find walks the RAW staged table via the shared finder
    // (phase 8a refactor) in NameOnly mode — behaviourally
    // identical to phase 7's inline walk.
    let arg_len = config.arg_len as usize;
    let mut found = None;
    if arg_len <= config.arg.len() {
        let needle = &config.arg[..arg_len];
        found = match find_snapshot_in_table(
            old_table,
            old_table_len,
            hdr.nb_snapshots,
            needle,
            MatchMode::NameOnly,
        ) {
            Ok(f) => f,
            Err(e) => fail!(map_snapshot_error(e)),
        };
    }
    let found = match found {
        Some(f) => f,
        None => {
            (call_table.verbose_print)(b"snapshot: no snapshot with that name\n\0".as_ptr());
            fail!(SnapshotResult::ERROR_NOT_FOUND);
        }
    };
    let remove_idx = found.index;
    let snap_l1_offset = found.l1_table_offset;
    let snap_l1_size = found.l1_size;

    // ----- Step 3: stage BOTH chains --------------------------------------
    // The snapshot's L1 + L2 set feed the decrement walk (read-only
    // staging); the active L1 + L2 set feed the COPIED refresh
    // (mutated in place). Shared L2 clusters appear in both staged
    // sets — deliberately no dedup (phase plan open question 6).
    let snap_l1_bytes = (snap_l1_size as usize).saturating_mul(8);
    if snap_l1_bytes > SNAP_L1_LIMIT {
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    let snap_l1_ptr = SNAP_L1_BUF as *mut u8;
    if snap_l1_bytes > 0
        && !read_input_byte_range(
            call_table,
            0,
            sector_size,
            snap_l1_offset,
            snap_l1_ptr,
            snap_l1_bytes,
        )
    {
        fail!(SnapshotResult::ERROR_PARSE_FAILED);
    }
    let snap_set = match stage_l2_set(
        call_table,
        sector_size,
        snap_l1_ptr,
        snap_l1_bytes,
        cluster_size_usize,
        extended_l2,
        SNAP_L2_STAGING,
        SNAP_L2_STAGING_LIMIT,
    ) {
        Ok(s) => s,
        Err(code) => fail!(code),
    };

    let active_l1_ptr = ACTIVE_L1_BUF as *mut u8;
    if active_l1_bytes > 0
        && !read_input_byte_range(
            call_table,
            0,
            sector_size,
            hdr.l1_table_offset,
            active_l1_ptr,
            active_l1_bytes,
        )
    {
        fail!(SnapshotResult::ERROR_PARSE_FAILED);
    }
    let active_set = match stage_l2_set(
        call_table,
        sector_size,
        active_l1_ptr,
        active_l1_bytes,
        cluster_size_usize,
        extended_l2,
        L2_STAGING,
        L2_STAGING_LIMIT,
    ) {
        Ok(s) => s,
        Err(code) => fail!(code),
    };

    let refblock_count = match stage_refblocks(call_table, hdr, sector_size) {
        Ok(n) => n,
        Err(code) => fail!(code),
    };
    let rb_offsets = core::slice::from_raw_parts(RB_OFFSETS as *const u64, refblock_count);
    let rb_total = refblock_count.saturating_mul(cluster_size_usize);
    let refblocks = core::slice::from_raw_parts_mut(REFBLOCKS_BUF as *mut u8, rb_total);
    let entries_per_refblock = (cluster_size * 8) / 16;
    let refblock_byte_offset_for_cluster = rb_lookup(
        cluster_size,
        entries_per_refblock,
        refblock_count,
        cluster_size_usize,
    );

    let snap_l1_clusters = (snap_l1_bytes as u64).div_ceil(cluster_size);
    let old_table_clusters = (old_table_len as u64).div_ceil(cluster_size);

    // ----- Step 5: pre-validation walk, BEFORE any disk write ------------
    // (qemu has no equivalent; its first underflow would surface
    // after the commit point. Failing here leaves the file
    // untouched and is structurally invisible on success.)
    {
        let snap_l1 = core::slice::from_raw_parts(snap_l1_ptr as *const u8, snap_l1_bytes);
        match precheck_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete {
                snapshot_l1: snap_l1,
            },
            refblocks,
            cluster_bits,
            16,
            extended_l2,
            |i| snap_set.l2_for_index(i),
            refblock_byte_offset_for_cluster,
        ) {
            Ok(()) => {}
            Err(SnapshotError::RefcountOverflow { .. }) => {
                fail!(SnapshotResult::ERROR_REFCOUNT_OVERFLOW)
            }
            Err(e) => fail!(map_snapshot_error(e)),
        }
    }
    // Refcount >= 1 on the snapshot's L1 clusters and the old
    // table's clusters: the leak-zone decrements must not underflow.
    for (first_offset, count) in [
        (snap_l1_offset, snap_l1_clusters),
        (hdr.snapshots_offset, old_table_clusters),
    ] {
        let first_cluster = first_offset / cluster_size;
        for c in 0..count {
            let (base, entry_local) =
                match refblock_byte_offset_for_cluster((first_cluster + c) * cluster_size) {
                    Some(t) => t,
                    None => fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE),
                };
            let block = &refblocks[base..base + cluster_size_usize];
            match read_refcount_in_block(block, entry_local, 16) {
                Ok(0) => fail!(SnapshotResult::ERROR_PARSE_FAILED),
                Ok(_) => {}
                Err(e) => fail!(map_snapshot_error(e)),
            }
        }
    }

    // ----- Steps 4 + 6: compacted table build + allocation ---------------
    // Skipped entirely when the remaining count is 0 (fact 3: qemu
    // writes header nb_snapshots = 0 / snapshots_offset = 0 and
    // allocates no new table).
    let remaining = hdr.nb_snapshots - 1;
    let mut alloc_cursor = AllocCursor::default();
    let mut new_table_len: usize = 0;
    let mut new_table_offset: u64 = 0;
    if remaining > 0 {
        let new_table = core::slice::from_raw_parts_mut(NEW_TABLE_BUF as *mut u8, NEW_TABLE_LIMIT);
        new_table_len = match build_snapshot_table_without(
            old_table,
            old_table_len,
            hdr.nb_snapshots,
            remove_idx,
            new_table,
        ) {
            Ok(n) => n,
            Err(e) => fail!(map_snapshot_error(e)),
        };
        let new_table_clusters = (new_table_len as u64).div_ceil(cluster_size).max(1);
        new_table_offset = match alloc_contiguous_clusters_in_refblocks(
            refblocks,
            cluster_size,
            16,
            refblock_count as u64,
            0,
            new_table_clusters,
            &mut alloc_cursor,
        ) {
            Ok(off) => off,
            Err(SnapshotError::RefcountExhausted) => {
                fail!(SnapshotResult::ERROR_ALLOCATION_FAILED)
            }
            Err(e) => fail!(map_snapshot_error(e)),
        };
    }

    // ----- Step 7: write group A (skipped when remaining == 0) -----------
    // Compacted table bytes + all staged refblocks, which at this
    // moment carry ONLY the table-allocation bumps (every decrement
    // is staged after group B, so a crash here leaks the orphaned
    // compacted table and nothing else).
    if remaining > 0 {
        let table_bytes = core::slice::from_raw_parts(NEW_TABLE_BUF as *const u8, new_table_len);
        if !write_input_byte_range(call_table, 0, sector_size, new_table_offset, table_bytes) {
            fail!(SnapshotResult::ERROR_IO);
        }
        for (k, host_off) in rb_offsets.iter().copied().enumerate() {
            let block = &refblocks[k * cluster_size_usize..(k + 1) * cluster_size_usize];
            if !write_input_byte_range(call_table, 0, sector_size, host_off, block) {
                fail!(SnapshotResult::ERROR_IO);
            }
        }
        if !(call_table.fsync_input)(0) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }

    // ----- Step 8: write group B (the commit point) -----------------------
    // 12 bytes at header offset 60: nb_snapshots - 1 (u32 BE) + the
    // new table offset, or 0 / 0 when the table is now empty.
    let mut header_patch = [0u8; 12];
    header_patch[0..4].copy_from_slice(&remaining.to_be_bytes());
    header_patch[4..12].copy_from_slice(&new_table_offset.to_be_bytes());
    if !write_input_byte_range(call_table, 0, sector_size, 60, &header_patch) {
        fail!(SnapshotResult::ERROR_IO);
    }
    if !(call_table.fsync_input)(0) {
        fail!(SnapshotResult::ERROR_IO);
    }

    // ----- Step 9: in-memory decrements (qemu's leak zone) ---------------
    // Order matches qcow2_snapshot_delete: the chain walk, then the
    // snapshot's L1 clusters, then the old table's clusters — all
    // decrements (never set-to-0), so an underflow surfaces a
    // bookkeeping bug. A failure past this point leaves a
    // consistent-but-leaky image and a non-zero exit, the same
    // failure mode qemu has (impossible in practice given step 5).
    {
        let snap_l1 = core::slice::from_raw_parts(snap_l1_ptr as *const u8, snap_l1_bytes);
        match update_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete {
                snapshot_l1: snap_l1,
            },
            refblocks,
            cluster_bits,
            16,
            extended_l2,
            |i| snap_set.l2_for_index(i),
            refblock_byte_offset_for_cluster,
        ) {
            Ok(()) => {}
            Err(e) => fail!(map_snapshot_error(e)),
        }
    }
    for (first_offset, count) in [
        (snap_l1_offset, snap_l1_clusters),
        (hdr.snapshots_offset, old_table_clusters),
    ] {
        let first_cluster = first_offset / cluster_size;
        for c in 0..count {
            let (base, entry_local) =
                match refblock_byte_offset_for_cluster((first_cluster + c) * cluster_size) {
                    Some(t) => t,
                    None => fail!(SnapshotResult::ERROR_IO),
                };
            let block = &mut refblocks[base..base + cluster_size_usize];
            let freed = read_refcount_in_block(block, entry_local, 16)
                .and_then(|cur| check_refcount_after_addend(cur, -1, 16))
                .and_then(|new_val| set_refcount_in_block(block, entry_local, 16, new_val));
            if freed.is_err() {
                fail!(SnapshotResult::ERROR_IO);
            }
        }
    }

    // ----- COPIED refresh over the ACTIVE chain ---------------------------
    // qemu's trailing qcow2_update_snapshot_refcount(active, 0):
    // a pure flag refresh against the post-decrement refcounts.
    // Shared data clusters that dropped 2 -> 1 get COPIED SET (the
    // reverse direction from create); clusters still shared with
    // other snapshots stay cleared.
    let refcount_for_cluster = |host_offset: u64| -> Option<u64> {
        let (base, entry_local) = refblock_byte_offset_for_cluster(host_offset)?;
        let block = &refblocks[base..base + cluster_size_usize];
        read_refcount_in_block(block, entry_local, 16).ok()
    };
    {
        let active_l1_mut = core::slice::from_raw_parts_mut(active_l1_ptr, active_l1_bytes);
        if let Err(e) = update_copied_flags_for_l1(
            active_l1_mut,
            cluster_bits,
            |i| active_set.l2_for_index_mut(i),
            refcount_for_cluster,
            extended_l2,
        ) {
            fail!(map_snapshot_error(e));
        }
    }

    // ----- COPIED refresh over the DELETED chain's staged L2s -------------
    // qemu's -1 walk over the deleted snapshot's L1 also recomputes
    // COPIED on the visited L2 entries (post-decrement refcounts)
    // and flushes the dirty L2s whose clusters were NOT freed — an
    // L2 shared with a *different* snapshot survives at refcount
    // >= 1 and lands on disk with refreshed flags (e.g. a shared
    // data cluster that dropped 2 -> 1 gains COPIED inside the
    // surviving snapshot's L2). Only the walked L1 is exempt from
    // writeback ("Update L1 only if addend >= 0"); it is also
    // being freed. Refresh the staged deleted chain here; group C
    // writes back the surviving (refcount > 0) snap-set L2s. The
    // snap L1 buffer is mutated in place but never written. Found
    // by the phase 13 differential fuzzer (soak2 iteration 209);
    // same mechanism as MODE_APPLY's step 10b.
    {
        let snap_l1_mut = core::slice::from_raw_parts_mut(snap_l1_ptr, snap_l1_bytes);
        if let Err(e) = update_copied_flags_for_l1(
            snap_l1_mut,
            cluster_bits,
            |i| snap_set.l2_for_index_mut(i),
            refcount_for_cluster,
            extended_l2,
        ) {
            fail!(map_snapshot_error(e));
        }
    }

    // ----- Step 10: write group C -----------------------------------------
    // All staged refblocks (now carrying the decrements), the
    // active L1, the active L2 set, and the deleted chain's
    // surviving L2s.
    for (k, host_off) in rb_offsets.iter().copied().enumerate() {
        let block = &refblocks[k * cluster_size_usize..(k + 1) * cluster_size_usize];
        if !write_input_byte_range(call_table, 0, sector_size, host_off, block) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    if active_l1_bytes > 0 {
        let active_l1 = core::slice::from_raw_parts(active_l1_ptr as *const u8, active_l1_bytes);
        if !write_input_byte_range(call_table, 0, sector_size, hdr.l1_table_offset, active_l1) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    for k in 0..active_set.count {
        let l2 = core::slice::from_raw_parts(
            (L2_STAGING + k * cluster_size_usize) as *const u8,
            cluster_size_usize,
        );
        if !write_input_byte_range(
            call_table,
            0,
            sector_size,
            active_set.entries[k].host_offset,
            l2,
        ) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    // Surviving deleted-chain L2s: write back the staged snap-set
    // L2s whose own cluster's post-decrement refcount is still
    // non-zero (shared with another snapshot or the active chain;
    // a physical L2 in both staged sets is written twice with
    // identical bytes). Freed L2s (refcount 0) are skipped — never
    // written, matching qemu's cache discard.
    for k in 0..snap_set.count {
        let host_off = snap_set.entries[k].host_offset;
        match refcount_for_cluster(host_off) {
            Some(0) => continue, // freed: never written
            Some(_) => {}
            None => fail!(SnapshotResult::ERROR_IO),
        }
        let l2 = core::slice::from_raw_parts(
            (SNAP_L2_STAGING + k * cluster_size_usize) as *const u8,
            cluster_size_usize,
        );
        if !write_input_byte_range(call_table, 0, sector_size, host_off, l2) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    if !(call_table.fsync_input)(0) {
        fail!(SnapshotResult::ERROR_IO);
    }

    finish(call_table, mode, SnapshotResult::ERROR_OK, 0, bytes_read)
}

/// Number of L1 entries whose masked L2 offset is non-zero —
/// exactly the entries for which the refcount walks invoke their
/// `l2_for_index` closure, in walk order. MODE_APPLY's precheck
/// uses this to split one `SwapForApply` closure across the two
/// staged chains (the dry-run walks `from_l1` fully, then
/// `to_l1`).
fn count_allocated_l1_entries(l1_bytes: &[u8]) -> usize {
    let mut n = 0usize;
    let entries = l1_bytes.len() / 8;
    for i in 0..entries {
        if (read_u64_be(l1_bytes, i * 8) & L1_OFFSET_MASK) != 0 {
            n += 1;
        }
    }
    n
}

/// MODE_APPLY: the qemu-faithful apply / "goto" (phase 8).
///
/// Mirrors `qcow2_snapshot_goto` from qemu 10.0.x, adapted to the
/// staged model. Matching is **ID first, then name** — two FULL
/// passes over the raw table (`find_snapshot_by_id_or_name`: a
/// later entry matching by ID beats an earlier entry matching by
/// name; phase plan fact 2 — the opposite asymmetry from
/// delete's name-only matcher). Apply rewrites the **active L1
/// in place**; it never touches the snapshot table or the
/// header. Write-group ordering (phase plan, Situation):
///
///   precheck: SwapForApply, read-only, both directions, before
///     ANY write
///   (in-memory: +1 walk over the snapshot's chain)
///   A: all staged refblocks (increments only)
///   fsync
///   B: the snapshot's RAW L1 content, zero-padded to
///      hdr.l1_size * 8, at hdr.l1_table_offset — stale flags
///      intact (the commit point; mirrors qemu's pwrite_sync)
///   fsync
///   (in-memory: -1 walk over the staged OLD active chain, then
///    the final-state COPIED refresh over the padded new-L1 copy
///    + the snapshot's L2 set, and over the staged old active
///    chain — qemu's -1 walk also refreshes the old chain's L2
///    entries and flushes the survivors)
///   C: all staged refblocks (now carrying the decrements) + the
///      refreshed L1 to BOTH locations — hdr.l1_table_offset at
///      the padded length and sn.l1_table_offset at
///      sn.l1_size * 8 (replicating the snapshot-stored-L1 flag
///      write qemu's +1 walk performs, fact 6) — + the dirty
///      snapshot-set L2s + the SURVIVING old-active L2s (final
///      refcount > 0; e.g. shared with another snapshot). Freed
///      old-active L2s are NEVER written.
///   fsync
///
/// One final-state flag pass suffices because after an apply
/// every cluster reachable from the new active chain has
/// refcount >= 2 (the snapshot still references everything the
/// new active L1 does), so every COPIED flag ends clear in both
/// qemu's mid-state write and the final state — identical bytes
/// (phase plan, "The key flag invariant").
///
/// Geometry refusals (`ERROR_L1_SIZE_MISMATCH`): a stored
/// `disk_size` differing from the current virtual size (qemu
/// TRUNCATES the image here — fact 3; instar refuses, open
/// question 1; an absent disk_size — the finder's 0 sentinel —
/// matches, mirroring `qcow2_read_snapshots`' default of the
/// current virtual size), and `sn.l1_size > hdr.l1_size` (qemu
/// grows the active L1; instar refuses, fact 4). A smaller
/// snapshot L1 takes the zero-pad path, like qemu.
///
/// # Safety
///
/// `call_table` is the validated table; `header` is the staged
/// sector-0 slice at `HEADER_BUF`; `hdr` is its parse.
unsafe fn run_apply(
    call_table: &CallTable,
    config: &SnapshotConfig,
    hdr: &QcowHeader,
    header: &[u8],
    sector_size: usize,
    bytes_read: u64,
) -> u64 {
    let mode = SnapshotConfig::MODE_APPLY;

    macro_rules! fail {
        ($err:expr) => {
            return finish(call_table, mode, $err, 0, bytes_read)
        };
    }

    // ----- Step 1: feature gates (identical set to create/delete) --------
    if let Some(code) = mutating_feature_gates(call_table, hdr, header) {
        fail!(code);
    }

    let cluster_size = hdr.cluster_size;
    let cluster_size_usize = cluster_size as usize;
    let cluster_bits = hdr.cluster_bits;
    let extended_l2 = (hdr.incompatible_features & INCOMPAT_EXTENDED_L2) != 0 || hdr.extended_l2;
    let active_l1_bytes = (hdr.l1_size as usize).saturating_mul(8);
    if active_l1_bytes > ACTIVE_L1_LIMIT || active_l1_bytes > NEW_TABLE_LIMIT {
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }

    // ----- Step 2: find the target, ID then name (two full passes) -------
    // Not-found must be decided before any write; an image with no
    // snapshots can't match anything.
    if hdr.nb_snapshots == 0 {
        (call_table.verbose_print)(b"snapshot: apply on 0-snapshot image\n\0".as_ptr());
        fail!(SnapshotResult::ERROR_NOT_FOUND);
    }
    let input_capacity = (call_table.get_input_capacity)(0);
    let old_table_len = match stage_old_table(
        call_table,
        sector_size,
        input_capacity,
        hdr.snapshots_offset,
        hdr.nb_snapshots,
    ) {
        Ok(n) => n,
        Err(code) => fail!(code),
    };
    let old_table = core::slice::from_raw_parts(OLD_TABLE_BUF as *const u8, old_table_len);

    // The argument is passed through verbatim by the host; an
    // arg_len beyond the wire buffer can match nothing.
    let arg_len = config.arg_len as usize;
    let mut found = None;
    if arg_len <= config.arg.len() {
        let needle = &config.arg[..arg_len];
        found = match find_snapshot_in_table(
            old_table,
            old_table_len,
            hdr.nb_snapshots,
            needle,
            MatchMode::IdThenName,
        ) {
            Ok(f) => f,
            Err(e) => fail!(map_snapshot_error(e)),
        };
    }
    let found = match found {
        Some(f) => f,
        None => {
            (call_table.verbose_print)(b"snapshot: no snapshot with that ID or name\n\0".as_ptr());
            fail!(SnapshotResult::ERROR_NOT_FOUND);
        }
    };

    // ----- Step 3: geometry checks ----------------------------------------
    // disk_size: 0 is the finder's "absent extra data" sentinel —
    // qemu's reader defaults an absent disk_size to the CURRENT
    // virtual size, so the check passes (open question 5); a
    // genuinely-zero disk_size on a 0-byte image also matches.
    if found.disk_size_or_zero != 0 && found.disk_size_or_zero != hdr.virtual_size {
        (call_table.verbose_print)(b"snapshot: disk_size mismatch refused\n\0".as_ptr());
        fail!(SnapshotResult::ERROR_L1_SIZE_MISMATCH);
    }
    // l1_size: larger-than-active needs qemu's L1 grow — refused in
    // v1 (only reachable on hand-crafted images given the disk_size
    // refusal above). Smaller takes the zero-pad path below.
    if found.l1_size > hdr.l1_size {
        (call_table.verbose_print)(
            b"snapshot: snapshot L1 larger than active refused\n\0".as_ptr(),
        );
        fail!(SnapshotResult::ERROR_L1_SIZE_MISMATCH);
    }

    // ----- Step 4: stage BOTH chains + the refblocks ----------------------
    // The snapshot's chain feeds the increment walk and the flag
    // refresh; the active chain feeds the decrement walk. Shared
    // L2 clusters appear in both staged sets (no dedup, same
    // posture as delete).
    let snap_l1_bytes = (found.l1_size as usize).saturating_mul(8);
    if snap_l1_bytes > SNAP_L1_LIMIT {
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    let snap_l1_ptr = SNAP_L1_BUF as *mut u8;
    if snap_l1_bytes > 0
        && !read_input_byte_range(
            call_table,
            0,
            sector_size,
            found.l1_table_offset,
            snap_l1_ptr,
            snap_l1_bytes,
        )
    {
        fail!(SnapshotResult::ERROR_PARSE_FAILED);
    }
    let snap_set = match stage_l2_set(
        call_table,
        sector_size,
        snap_l1_ptr,
        snap_l1_bytes,
        cluster_size_usize,
        extended_l2,
        SNAP_L2_STAGING,
        SNAP_L2_STAGING_LIMIT,
    ) {
        Ok(s) => s,
        Err(code) => fail!(code),
    };

    let active_l1_ptr = ACTIVE_L1_BUF as *mut u8;
    if active_l1_bytes > 0
        && !read_input_byte_range(
            call_table,
            0,
            sector_size,
            hdr.l1_table_offset,
            active_l1_ptr,
            active_l1_bytes,
        )
    {
        fail!(SnapshotResult::ERROR_PARSE_FAILED);
    }
    let active_set = match stage_l2_set(
        call_table,
        sector_size,
        active_l1_ptr,
        active_l1_bytes,
        cluster_size_usize,
        extended_l2,
        L2_STAGING,
        L2_STAGING_LIMIT,
    ) {
        Ok(s) => s,
        Err(code) => fail!(code),
    };

    let refblock_count = match stage_refblocks(call_table, hdr, sector_size) {
        Ok(n) => n,
        Err(code) => fail!(code),
    };
    let rb_offsets = core::slice::from_raw_parts(RB_OFFSETS as *const u64, refblock_count);
    let rb_total = refblock_count.saturating_mul(cluster_size_usize);
    let refblocks = core::slice::from_raw_parts_mut(REFBLOCKS_BUF as *mut u8, rb_total);
    let entries_per_refblock = (cluster_size * 8) / 16;
    let refblock_byte_offset_for_cluster = rb_lookup(
        cluster_size,
        entries_per_refblock,
        refblock_count,
        cluster_size_usize,
    );

    // The padded new-L1 working copy: the snapshot's RAW L1 bytes
    // zero-padded to the active L1's byte size. Apply allocates no
    // snapshot table, so the (otherwise unused) NEW_TABLE_BUF
    // region hosts it — its 66 KiB limit covers the 64 KiB
    // ACTIVE_L1_LIMIT (checked above).
    let padded_l1_ptr = NEW_TABLE_BUF as *mut u8;
    if snap_l1_bytes > 0 {
        core::ptr::copy_nonoverlapping(snap_l1_ptr as *const u8, padded_l1_ptr, snap_l1_bytes);
    }
    if active_l1_bytes > snap_l1_bytes {
        core::ptr::write_bytes(
            padded_l1_ptr.add(snap_l1_bytes),
            0,
            active_l1_bytes - snap_l1_bytes,
        );
    }

    // ----- Step 5: precheck (SwapForApply), BEFORE any write --------------
    // Validates the decrement side (old active chain) for
    // underflow and the increment side (snapshot chain) for
    // overflow against the staged refblocks. The dry-run walks
    // from_l1 fully, then to_l1; one closure serves both staged
    // sets by counting calls against the from-chain's allocated
    // L1 entry count (the same pattern the phase 5 SwapForApply
    // unit test models).
    {
        let active_l1 = core::slice::from_raw_parts(active_l1_ptr as *const u8, active_l1_bytes);
        let snap_l1 = core::slice::from_raw_parts(snap_l1_ptr as *const u8, snap_l1_bytes);
        let from_allocated = count_allocated_l1_entries(active_l1);
        let mut calls = 0usize;
        match precheck_snapshot_refcount(
            SnapshotRefcountOp::SwapForApply {
                from_l1: active_l1,
                to_l1: snap_l1,
            },
            refblocks,
            cluster_bits,
            16,
            extended_l2,
            |i| {
                calls += 1;
                if calls <= from_allocated {
                    active_set.l2_for_index(i)
                } else {
                    snap_set.l2_for_index(i)
                }
            },
            refblock_byte_offset_for_cluster,
        ) {
            Ok(()) => {}
            Err(SnapshotError::RefcountOverflow { .. }) => {
                fail!(SnapshotResult::ERROR_REFCOUNT_OVERFLOW)
            }
            Err(e) => fail!(map_snapshot_error(e)),
        }
    }

    // ----- Step 6: in-memory +1 walk over the snapshot's chain ------------
    // (IncrementForCreate is the inc walk; the create-flavoured
    // name is cosmetic — open question 3.)
    {
        let snap_l1 = core::slice::from_raw_parts(snap_l1_ptr as *const u8, snap_l1_bytes);
        match update_snapshot_refcount(
            SnapshotRefcountOp::IncrementForCreate {
                snapshot_l1: snap_l1,
            },
            refblocks,
            cluster_bits,
            16,
            extended_l2,
            |i| snap_set.l2_for_index(i),
            refblock_byte_offset_for_cluster,
        ) {
            Ok(()) => {}
            Err(SnapshotError::RefcountOverflow { .. }) => {
                fail!(SnapshotResult::ERROR_REFCOUNT_OVERFLOW)
            }
            Err(e) => fail!(map_snapshot_error(e)),
        }
    }

    // ----- Step 7: write group A (refblocks, increments only) -------------
    // A crash after this leaves over-referenced refcounts: leaks,
    // repairable by qemu-img check -r leaks; never a dangling
    // reference.
    for (k, host_off) in rb_offsets.iter().copied().enumerate() {
        let block = &refblocks[k * cluster_size_usize..(k + 1) * cluster_size_usize];
        if !write_input_byte_range(call_table, 0, sector_size, host_off, block) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    if !(call_table.fsync_input)(0) {
        fail!(SnapshotResult::ERROR_IO);
    }

    // ----- Step 8: write group B (the commit point) ------------------------
    // The padded RAW snapshot-L1 content — stale flags intact —
    // over the active L1 offset, mirroring qemu's bdrv_pwrite_sync
    // (the refreshed bytes land in group C, exactly as qemu's
    // addend-0 walk overwrites its own raw copy later).
    if active_l1_bytes > 0 {
        let padded = core::slice::from_raw_parts(padded_l1_ptr as *const u8, active_l1_bytes);
        if !write_input_byte_range(call_table, 0, sector_size, hdr.l1_table_offset, padded) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    if !(call_table.fsync_input)(0) {
        fail!(SnapshotResult::ERROR_IO);
    }

    // ----- Step 9: in-memory -1 walk over the staged OLD active chain -----
    // qemu's "decrease refcount of clusters of current L1 table"
    // — done from the in-memory (staged) old L1, which is why the
    // just-committed on-disk L1 is irrelevant here. Failures past
    // the commit point leave a consistent image with leaks /
    // stale flags, qemu's own best-effort posture.
    {
        let active_l1 = core::slice::from_raw_parts(active_l1_ptr as *const u8, active_l1_bytes);
        match update_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete {
                snapshot_l1: active_l1,
            },
            refblocks,
            cluster_bits,
            16,
            extended_l2,
            |i| active_set.l2_for_index(i),
            refblock_byte_offset_for_cluster,
        ) {
            Ok(()) => {}
            Err(e) => fail!(map_snapshot_error(e)),
        }
    }

    // ----- Step 10: final-state COPIED refresh over the NEW chain ---------
    // One pass at final-state refcounts over the padded new-L1
    // copy + the snapshot's staged L2 set (see the flag-invariant
    // note in the function docs). The pad entries are zero and
    // are skipped by the walker.
    let refcount_for_cluster = |host_offset: u64| -> Option<u64> {
        let (base, entry_local) = refblock_byte_offset_for_cluster(host_offset)?;
        let block = &refblocks[base..base + cluster_size_usize];
        read_refcount_in_block(block, entry_local, 16).ok()
    };
    {
        let padded_l1_mut = core::slice::from_raw_parts_mut(padded_l1_ptr, active_l1_bytes);
        if let Err(e) = update_copied_flags_for_l1(
            padded_l1_mut,
            cluster_bits,
            |i| snap_set.l2_for_index_mut(i),
            refcount_for_cluster,
            extended_l2,
        ) {
            fail!(map_snapshot_error(e));
        }
    }

    // ----- Step 10b: COPIED refresh over the SURVIVING old chain ----------
    // qemu's -1 walk also recomputes COPIED on the OLD active
    // chain's L2 entries (post-decrement == final refcounts) and
    // flushes the dirty L2s whose clusters were NOT freed —
    // e.g. an old-active L2 shared with a *different* snapshot
    // survives at refcount >= 1 and lands on disk with refreshed
    // flags (verified empirically: s1, write, s2, apply s1 -> the
    // s2-shared L2's data entry gains COPIED under qemu). Only
    // the walked L1 is exempt from writeback ("Update L1 only if
    // addend >= 0"). Refresh the staged old chain here; group C
    // writes back the surviving (refcount > 0) active-set L2s.
    // The old L1 buffer is mutated in place but never written.
    {
        let active_l1_mut = core::slice::from_raw_parts_mut(active_l1_ptr, active_l1_bytes);
        if let Err(e) = update_copied_flags_for_l1(
            active_l1_mut,
            cluster_bits,
            |i| active_set.l2_for_index_mut(i),
            refcount_for_cluster,
            extended_l2,
        ) {
            fail!(map_snapshot_error(e));
        }
    }

    // ----- Step 11: write group C ------------------------------------------
    // All staged refblocks (now carrying the decrements), the
    // refreshed L1 to BOTH locations at their two lengths, the
    // dirty snapshot-set L2s, and the surviving old-active L2s
    // (refreshed in step 10b; a physical L2 shared by both sets
    // is written twice with identical bytes). The freed
    // old-active-only L2s are never written (qemu's
    // cache_discards drops them).
    for (k, host_off) in rb_offsets.iter().copied().enumerate() {
        let block = &refblocks[k * cluster_size_usize..(k + 1) * cluster_size_usize];
        if !write_input_byte_range(call_table, 0, sector_size, host_off, block) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    if active_l1_bytes > 0 {
        let padded = core::slice::from_raw_parts(padded_l1_ptr as *const u8, active_l1_bytes);
        // The active L1 offset: the full padded length.
        if !write_input_byte_range(call_table, 0, sector_size, hdr.l1_table_offset, padded) {
            fail!(SnapshotResult::ERROR_IO);
        }
        // The snapshot's stored L1: its own sn.l1_size * 8 length
        // (the write that replicates qemu's +1-walk flag scrub of
        // the stored L1 — fact 6).
        if snap_l1_bytes > 0
            && !write_input_byte_range(
                call_table,
                0,
                sector_size,
                found.l1_table_offset,
                &padded[..snap_l1_bytes],
            )
        {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    for k in 0..snap_set.count {
        let l2 = core::slice::from_raw_parts(
            (SNAP_L2_STAGING + k * cluster_size_usize) as *const u8,
            cluster_size_usize,
        );
        if !write_input_byte_range(
            call_table,
            0,
            sector_size,
            snap_set.entries[k].host_offset,
            l2,
        ) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    // Surviving old-active L2s (step 10b): write back the staged
    // active-set L2s whose own cluster's final refcount is still
    // non-zero. Freed L2s (refcount 0) are skipped — never
    // written, matching qemu's cache discard.
    for k in 0..active_set.count {
        let host_off = active_set.entries[k].host_offset;
        match refcount_for_cluster(host_off) {
            Some(0) => continue, // freed: never written
            Some(_) => {}
            None => fail!(SnapshotResult::ERROR_IO),
        }
        let l2 = core::slice::from_raw_parts(
            (L2_STAGING + k * cluster_size_usize) as *const u8,
            cluster_size_usize,
        );
        if !write_input_byte_range(call_table, 0, sector_size, host_off, l2) {
            fail!(SnapshotResult::ERROR_IO);
        }
    }
    if !(call_table.fsync_input)(0) {
        fail!(SnapshotResult::ERROR_IO);
    }

    finish(call_table, mode, SnapshotResult::ERROR_OK, 0, bytes_read)
}
