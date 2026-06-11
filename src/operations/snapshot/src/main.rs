//! Snapshot operation: list / apply / create / delete qcow2 internal snapshots.
//!
//! Phase 6 of `PLAN-snapshot.md` lands `MODE_CREATE` end-to-end;
//! `MODE_LIST` (phase 3) is unchanged. `MODE_APPLY` / `MODE_DELETE`
//! remain stubs (phases 7 / 8).
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
//!    - `MODE_APPLY` / `MODE_DELETE` (1/3): stub returns
//!      `ERROR_INVALID_CONFIG`.
//!    - Otherwise: `ERROR_INVALID_CONFIG` for the unknown mode.
//! 6. Build a [`SnapshotResult`] and emit it via
//!    `send_snapshot_result`, then signal `send_complete`.
//!
//! `MODE_CREATE` is the canonical mutating path. The input image is
//! opened RW on slot 0 (the host uses
//! `BackingStore::open_rw_existing` with a generous capacity hint so
//! the guest can write past EOF to grow the file on demand). All
//! reads / writes go through the sector-bounce RMW helpers
//! (`read_input_byte_range` / `write_input_byte_range`), modelled on
//! the commit binary. The writeback ordering mirrors qemu's
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
    alloc_contiguous_clusters_in_refblocks, update_copied_flags_for_l1, update_snapshot_refcount,
    AllocCursor, SnapshotRefcountOp,
};
use snapshot::table::{
    build_snapshot_table, format_decimal_u64, serialize_snapshot_entry, snapshot_table_byte_len,
    NewSnapshotEntry,
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
// buffer.

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

const _: () = assert!(
    RMW_BOUNCE + RMW_BOUNCE_LIMIT <= shared::ALLOC_HEAP_BASE,
    "snapshot create scratch layout overlaps the allocator heap"
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

fn map_snapshot_error(e: SnapshotError) -> u32 {
    u32::from(e)
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
            (call_table.verbose_print)(b"snapshot: mode 1 not implemented in v1\n\0".as_ptr());
            finish(
                call_table,
                SnapshotConfig::MODE_APPLY,
                SnapshotResult::ERROR_INVALID_CONFIG,
                0,
                bytes_read,
            )
        }
        SnapshotConfig::MODE_DELETE => {
            (call_table.verbose_print)(b"snapshot: mode 3 not implemented in v1\n\0".as_ptr());
            finish(
                call_table,
                SnapshotConfig::MODE_DELETE,
                SnapshotResult::ERROR_INVALID_CONFIG,
                0,
                bytes_read,
            )
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

    // ----- Step 1: feature gates ----------------------------------------
    if hdr.crypt_method != 0 {
        (call_table.verbose_print)(b"snapshot: LUKS/encrypted refused\n\0".as_ptr());
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    if hdr.has_external_data || (hdr.incompatible_features & INCOMPAT_EXTERNAL_DATA) != 0 {
        (call_table.verbose_print)(b"snapshot: external data file refused\n\0".as_ptr());
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    if hdr.compression_type != 0 || (hdr.incompatible_features & INCOMPAT_COMPRESSION) != 0 {
        (call_table.verbose_print)(b"snapshot: compression refused\n\0".as_ptr());
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    if (hdr.incompatible_features & (INCOMPAT_DIRTY | INCOMPAT_CORRUPT)) != 0
        || hdr.dirty
        || hdr.corrupt
    {
        (call_table.verbose_print)(b"snapshot: dirty/corrupt image refused\n\0".as_ptr());
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    // Bitmaps extension: autoclear feature bit 0, raw header u64 at
    // offset 88 (AUTOCLEAR_FEATURES_OFFSET). QcowHeader does not
    // surface autoclear bits, so read them from the staged sector.
    if header.len() >= AUTOCLEAR_FEATURES_OFFSET + 8 {
        let autoclear = read_u64_be(header, AUTOCLEAR_FEATURES_OFFSET);
        if (autoclear & 0x1) != 0 {
            (call_table.verbose_print)(b"snapshot: bitmaps extension refused\n\0".as_ptr());
            fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
        }
    }
    if hdr.refcount_bits != 16 {
        (call_table.verbose_print)(b"snapshot: refcount_bits != 16 refused\n\0".as_ptr());
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
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
        // First stage enough bytes: read up to OLD_TABLE_LIMIT from
        // snapshots_offset, then measure precisely.
        // We do a two-phase read: read the whole bounded region,
        // then trim to the measured length.
        let stage_len = OLD_TABLE_LIMIT;
        // Clamp the read to the device size to avoid reading past EOF.
        let dev_bytes = input_capacity.saturating_mul(sector_size as u64);
        let avail = dev_bytes.saturating_sub(hdr.snapshots_offset);
        let to_read = (stage_len as u64).min(avail) as usize;
        if to_read == 0
            || !read_input_byte_range(
                call_table,
                0,
                sector_size,
                hdr.snapshots_offset,
                OLD_TABLE_BUF as *mut u8,
                to_read,
            )
        {
            fail!(SnapshotResult::ERROR_PARSE_FAILED);
        }
        let old_slice = core::slice::from_raw_parts(OLD_TABLE_BUF as *const u8, to_read);
        match snapshot_table_byte_len(old_slice, hdr.nb_snapshots) {
            Ok(n) => {
                if n > OLD_TABLE_LIMIT {
                    fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
                }
                n
            }
            Err(e) => fail!(map_snapshot_error(e)),
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
    let mut staged_l2 = [StagedL2 {
        l1_idx: 0,
        host_offset: 0,
    }; MAX_STAGED_L2];
    let mut staged_l2_count: usize = 0;
    {
        let l1_buf = core::slice::from_raw_parts(active_l1_ptr, l1_size_bytes);
        let mut cursor = L2_STAGING;
        let cap_end = L2_STAGING + L2_STAGING_LIMIT;
        for i in 0..l1_size as usize {
            let entry = read_u64_be(l1_buf, i * 8);
            let l2_host = entry & L1_OFFSET_MASK;
            if l2_host == 0 {
                continue;
            }
            if staged_l2_count >= MAX_STAGED_L2 || cursor + cluster_size_usize > cap_end {
                fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
            }
            if !read_input_byte_range(
                call_table,
                0,
                sector_size,
                l2_host,
                cursor as *mut u8,
                cluster_size_usize,
            ) {
                fail!(SnapshotResult::ERROR_PARSE_FAILED);
            }
            // Gate on compressed entries during the L2 walk.
            let l2_slice = core::slice::from_raw_parts(cursor as *const u8, cluster_size_usize);
            let stride = if extended_l2 { 16usize } else { 8usize };
            let mut j = 0usize;
            while j + 8 <= cluster_size_usize {
                let e = read_u64_be(l2_slice, j);
                if (e & OFLAG_COMPRESSED) != 0 {
                    (call_table.verbose_print)(
                        b"snapshot: compressed cluster refused\n\0".as_ptr(),
                    );
                    fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
                }
                j += stride;
            }
            staged_l2[staged_l2_count] = StagedL2 {
                l1_idx: i as u32,
                host_offset: l2_host,
            };
            staged_l2_count += 1;
            cursor += cluster_size_usize;
        }
    }

    // ----- Stage the refcount table and refblocks -----------------------
    let rt_size = (hdr.refcount_table_clusters as usize).saturating_mul(cluster_size_usize);
    if rt_size > RT_LIMIT {
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
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
        fail!(SnapshotResult::ERROR_PARSE_FAILED);
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
                    fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
                }
                refblock_count += 1;
            } else {
                seen_zero = true;
            }
            i += 8;
        }
    }
    if refblock_count == 0 || refblock_count > MAX_REFBLOCKS {
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
    }
    let rb_offsets_ptr = RB_OFFSETS as *mut u64;
    let rb_offsets = core::slice::from_raw_parts_mut(rb_offsets_ptr, refblock_count);
    {
        for (k, slot) in rb_offsets.iter_mut().enumerate() {
            *slot = read_u64_be(rt, k * 8) & L1_OFFSET_MASK;
        }
    }
    let rb_total = refblock_count.saturating_mul(cluster_size_usize);
    if rb_total > REFBLOCKS_LIMIT {
        fail!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE);
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
            fail!(SnapshotResult::ERROR_PARSE_FAILED);
        }
    }

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
    // The closure maps a cluster's host offset to (byte offset within
    // the staged refblocks buffer, entry-local index). Refblocks are
    // contiguous from RT index 0, so refblock slot == cluster_index /
    // entries_per_refblock.
    let l2_for_index = |l1_idx: u32| -> Option<&'static [u8]> {
        let mut k = 0usize;
        while k < staged_l2_count {
            if staged_l2[k].l1_idx == l1_idx {
                let ptr = (L2_STAGING + k * cluster_size_usize) as *const u8;
                return Some(core::slice::from_raw_parts(ptr, cluster_size_usize));
            }
            k += 1;
        }
        None
    };
    let refblock_byte_offset_for_cluster = |host_offset: u64| -> Option<(usize, u64)> {
        let cluster_index = host_offset / cluster_size;
        let rb_slot = (cluster_index / entries_per_refblock) as usize;
        let entry_local = cluster_index % entries_per_refblock;
        if rb_slot >= refblock_count {
            return None;
        }
        Some((rb_slot * cluster_size_usize, entry_local))
    };

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
            l2_for_index,
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
        let cluster_index = host_offset / cluster_size;
        let rb_slot = (cluster_index / entries_per_refblock) as usize;
        let entry_local = cluster_index % entries_per_refblock;
        if rb_slot >= refblock_count {
            return None;
        }
        let base = rb_slot * cluster_size_usize;
        let block = &refblocks[base..base + cluster_size_usize];
        snapshot::qcow2::read_refcount_in_block(block, entry_local, 16).ok()
    };
    // l2_for_index_mut hands back mutable L2 slices for the flag pass.
    let l2_for_index_mut = |l1_idx: u32| -> Option<&'static mut [u8]> {
        let mut k = 0usize;
        while k < staged_l2_count {
            if staged_l2[k].l1_idx == l1_idx {
                let ptr = (L2_STAGING + k * cluster_size_usize) as *mut u8;
                return Some(core::slice::from_raw_parts_mut(ptr, cluster_size_usize));
            }
            k += 1;
        }
        None
    };
    {
        let active_l1_mut = core::slice::from_raw_parts_mut(active_l1_ptr, l1_size_bytes);
        if let Err(e) = update_copied_flags_for_l1(
            active_l1_mut,
            cluster_bits,
            l2_for_index_mut,
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
    for k in 0..staged_l2_count {
        let l2 = core::slice::from_raw_parts(
            (L2_STAGING + k * cluster_size_usize) as *const u8,
            cluster_size_usize,
        );
        if !write_input_byte_range(call_table, 0, sector_size, staged_l2[k].host_offset, l2) {
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
    // Decrement the old table's clusters to 0 in the staged refblocks
    // and write those refblocks back. Skipped when there was no old
    // table.
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
            if snapshot::qcow2::set_refcount_in_block(block, entry_local, 16, 0).is_err() {
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
