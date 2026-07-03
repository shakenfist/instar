//! Bitmap operation: mutate a qcow2 image's persistent dirty
//! bitmaps (`qemu-img bitmap` parity).
//!
//! Phase 4 of `PLAN-bitmap`. The guest is the `no_std` / `no_main`
//! KVM-guest binary `bitmap.bin`: it reads the [`BitmapConfig`] the
//! host wrote at [`OPERATION_CONFIG_ADDR`], validates the call table
//! and config, dispatches on the target format, drives the Phase-3
//! planner crate over the ordered action list, performs the on-disk
//! data-cluster work the crate cannot, writes everything back under
//! a crash-safe autoclear dance, and returns a [`BitmapResult`].
//!
//! **This is step 4d: merge on-disk orchestration, on top of 4c's
//! metadata-action loop + write-back + autoclear dance** for the five
//! metadata actions (add / remove / clear / enable / disable). On top
//! of 4b's header read + gates + host cross-check + staging,
//! `run_qcow2` applies the ordered action list in memory
//! (double-buffering the directory, threading one [`AllocCursor`] and
//! the staged refblocks), performs the on-disk data-cluster work the
//! Phase-3 crate cannot (walking a freed/cleared bitmap's on-disk
//! table to free its data clusters), and writes everything back under
//! the crash-safe autoclear dance (clear autoclear → write
//! clusters/directory/refblocks → rewrite the bitmaps extension → set
//! autoclear, leaving it clear when the last bitmap was removed).
//!
//! **Merge (`ACTION_MERGE`)** is handled by a dedicated flow
//! ([`run_merge`]) since it mutates only the destination bitmap's
//! *table entries* and *data clusters* (never the directory), so it
//! does not fit 4c's directory-centric write-back. An invocation is
//! **either** all-metadata-actions (the 4c path) **or** a single
//! merge action (the 4d path); an invocation that mixes merge with
//! other actions is refused with `ERROR_UNSUPPORTED_ACTION` (v1
//! restriction — the host/tests drive them separately). v1 merge
//! supports a **single** `--merge` source (the first entry of the
//! merge-source pool); a multi-source request is applied as N
//! sequential single-source merges into the destination. Non-qcow2
//! targets are refused with `ERROR_UNSUPPORTED_FORMAT` (v1 is
//! qcow2-only).
//!
//! **First-add / no-extension case:** when the image has no bitmaps
//! extension yet, the first `--add` creates a new `EXT_BITMAPS`
//! header-extension record in place (overwriting the terminating
//! `EXT_END`, appending a fresh one), guarded by a header-cluster
//! room check; if there is no room it returns
//! `ERROR_SCRATCH_TOO_SMALL`.
//!
//! Device idiom (Phase 5 host, mirrored here): the image is attached
//! **input read-write** at slot 0, so the runner reads/writes via
//! `read_input_sector(0, ..)` / `write_input_sector(0, ..)` /
//! `fsync_input(0)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use bitmap::action::{
    action_add, action_clear, action_disable, action_enable, action_remove, ActionOutcome,
    BitmapGeometry, MAX_TABLE_CLUSTERS,
};
use bitmap::directory::serialize_bitmaps_extension;
use bitmap::merge::{merge_cluster_action, merge_validate, or_bitmap_data, MergeClusterAction};
use qcow2::bitmap::{
    decode_bitmap_table_entry, default_granularity, encode_bitmap_table_entry,
    granularity_bits_valid, BitmapTableEntry, AUTOCLEAR_BITMAPS_BIT,
};
use qcow2::{
    header_extension_area_end, parse_header_extensions, QcowHeader, AUTOCLEAR_FEATURES_OFFSET,
    EXT_BITMAPS, EXT_END, HEADER_LENGTH_OFFSET, INCOMPAT_CORRUPT, INCOMPAT_DIRTY, L1_OFFSET_MASK,
};
use shared::{
    validate_call_table, write_be_u32, BitmapConfig, BitmapResult, CallTable, ImageFormat,
    ALLOC_HEAP_BASE, CALL_TABLE_ADDR, MAX_BITMAP_ACTIONS, MAX_CLUSTER_SIZE, MAX_SECTOR_SIZE,
    OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
};
use snapshot::qcow2::{alloc_contiguous_clusters_in_refblocks, set_refcount_in_block, AllocCursor};
use snapshot::SnapshotError;

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// ---------------------------------------------------------------------------
// Scratch layout (Open question 4)
// ---------------------------------------------------------------------------
//
// Named regions carved forward from `SCRATCH_MEM_BASE`, mirroring
// snapshot's `:136-180` idiom, with a compile-time assert that the
// top stays below `ALLOC_HEAP_BASE` (the bump-allocator heap). Every
// region is start = previous_start + previous_limit.
//
// The big regions are the six cluster-sized (`MAX_CLUSTER_SIZE` =
// 2 MiB) buffers — HEADER_BUF, REFBLOCKS_BUF, TABLE_BUF, DATA_A,
// DATA_B, ZERO_BUF — plus the two 64 KiB directory double-buffers,
// the 64 KiB refcount table, the 16 KiB refblock-offset array, and
// the one-sector RMW bounce. The staged directory is bounded by
// `BITMAP_DIR_LIMIT` (64 KiB, like snapshot's `OLD_TABLE_LIMIT`); a
// larger directory is refused with `ERROR_SCRATCH_TOO_SMALL`.
//
// TABLE_BUF / DATA_A / DATA_B / ZERO_BUF are unused in 4b (they are
// carved now so the layout is stable): 4c walks a bitmap's on-disk
// table in TABLE_BUF and zero-fills with ZERO_BUF; 4d reads/OR's
// bitmap data clusters through DATA_A / DATA_B.

/// The bitmaps directory staging bound. A directory larger than this
/// is refused with `ERROR_SCRATCH_TOO_SMALL` (matches snapshot's
/// 64 KiB `OLD_TABLE_LIMIT` posture).
const BITMAP_DIR_LIMIT: usize = 64 * 1024;

const HEADER_BUF: usize = SCRATCH_MEM_BASE;
const HEADER_LIMIT: usize = MAX_CLUSTER_SIZE;

const DIR_A: usize = HEADER_BUF + HEADER_LIMIT;
const DIR_A_LIMIT: usize = BITMAP_DIR_LIMIT;

const DIR_B: usize = DIR_A + DIR_A_LIMIT;
const DIR_B_LIMIT: usize = BITMAP_DIR_LIMIT;

const RT_BUF: usize = DIR_B + DIR_B_LIMIT;
const RT_LIMIT: usize = 64 * 1024;

const RB_OFFSETS: usize = RT_BUF + RT_LIMIT;
const RB_OFFSETS_LIMIT: usize = 16 * 1024;

const REFBLOCKS_BUF: usize = RB_OFFSETS + RB_OFFSETS_LIMIT;
const REFBLOCKS_LIMIT: usize = 2 * 1024 * 1024;

const TABLE_BUF: usize = REFBLOCKS_BUF + REFBLOCKS_LIMIT;
const TABLE_LIMIT: usize = MAX_CLUSTER_SIZE;

const DATA_A: usize = TABLE_BUF + TABLE_LIMIT;
const DATA_A_LIMIT: usize = MAX_CLUSTER_SIZE;

const DATA_B: usize = DATA_A + DATA_A_LIMIT;
const DATA_B_LIMIT: usize = MAX_CLUSTER_SIZE;

const ZERO_BUF: usize = DATA_B + DATA_B_LIMIT;
const ZERO_LIMIT: usize = MAX_CLUSTER_SIZE;

const RMW_BOUNCE: usize = ZERO_BUF + ZERO_LIMIT;
const RMW_BOUNCE_LIMIT: usize = MAX_SECTOR_SIZE;

const TOP_REGION_END: usize = RMW_BOUNCE + RMW_BOUNCE_LIMIT;

const _: () = assert!(
    TOP_REGION_END <= ALLOC_HEAP_BASE,
    "bitmap scratch layout overlaps the allocator heap"
);

/// Upper bound on staged refcount blocks (constrained by
/// `REFBLOCKS_LIMIT / cluster_size`); same bound as snapshot.
const MAX_REFBLOCKS: usize = 32;

// ---------------------------------------------------------------------------
// Result construction
// ---------------------------------------------------------------------------

/// Build a [`BitmapResult`] echoing the target format and reporting
/// the given error code, with no actions applied. The resulting
/// bitmap count is carried over from the host-probed `nb_bitmaps`
/// since a refusal leaves the image untouched.
fn make_result(config: &BitmapConfig, action: u32, error: u32) -> BitmapResult {
    BitmapResult {
        magic: BitmapResult::MAGIC,
        target_format: config.target_format,
        error,
        action,
        actions_applied: 0,
        resulting_nb_bitmaps: config.nb_bitmaps,
        _reserved: [0u8; 40],
    }
}

// ---------------------------------------------------------------------------
// Sector-bounce RMW helpers for input slot 0 (copied from snapshot)
// ---------------------------------------------------------------------------

/// Read `len` bytes from input device `dev` at `byte_offset` into
/// `dst_ptr`. Sub-sector reads go through the bounce buffer at
/// `RMW_BOUNCE`. Copied from snapshot's `read_input_byte_range`.
///
/// # Safety
///
/// `call_table` must be the validated CallTable; `dst_ptr` must
/// point at `len` writable bytes.
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
/// `RMW_BOUNCE`. Copied from snapshot's `write_input_byte_range`.
///
/// # Safety
///
/// `call_table` must be the validated CallTable.
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

/// Read a big-endian u64 from `buf` at `off`. Copied from snapshot;
/// the qcow2 crate's `be_u64` is private. Callers guarantee
/// `off + 8 <= buf.len()`.
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
// Refblock staging (copied / adapted from snapshot)
// ---------------------------------------------------------------------------

/// Staged refcount state: the refblock count and the host byte
/// offset that staged-refblock index 0 maps to. Refblocks are
/// contiguous from refcount-table index 0 (the v1 gate below), so
/// index 0 always covers cluster 0 ⇒ `host_refblocks_start == 0`.
/// Carried explicitly to mirror snapshot's model and to feed
/// `refblock_byte_offset_for_cluster` in 4c/4d.
#[derive(Clone, Copy)]
struct StagedRefblocks {
    refblock_count: usize,
    host_refblocks_start: u64,
}

/// Stage the refcount table into `RT_BUF`, collect the contiguous
/// refblock host offsets into `RB_OFFSETS` (the v1 contiguity gate:
/// populated refblocks must run gap-free from refcount-table index
/// 0), and stage the refblock bytes into `REFBLOCKS_BUF`. Copied
/// from snapshot's `stage_refblocks`, with the error codes remapped
/// to `BitmapResult`.
///
/// # Safety
///
/// `call_table` must be the validated CallTable.
unsafe fn stage_refblocks(
    call_table: &CallTable,
    hdr: &QcowHeader,
    sector_size: usize,
) -> Result<StagedRefblocks, u32> {
    let cluster_size_usize = hdr.cluster_size as usize;
    let rt_size = (hdr.refcount_table_clusters as usize).saturating_mul(cluster_size_usize);
    // We only ever consult the populated prefix of the refcount table:
    // the run must be contiguous from index 0 and no longer than
    // `MAX_REFBLOCKS` (refused below), so the meaningful entries always
    // live in the first `MAX_REFBLOCKS * 8` bytes. At large cluster
    // sizes a single refcount-table cluster (up to `MAX_CLUSTER_SIZE`)
    // exceeds the 64 KiB `RT_BUF`; rather than refuse the image, stage
    // only the leading `RT_LIMIT` bytes. The trailing entries we skip
    // are guaranteed zero for any image within the supported envelope
    // (a populated entry beyond `RT_LIMIT` would imply far more than
    // `MAX_REFBLOCKS` refblocks). `RT_LIMIT` is a whole number of
    // sectors, so the bounded read stays sector-aligned.
    let rt_read = rt_size.min(RT_LIMIT);
    if rt_read > 0
        && !read_input_byte_range(
            call_table,
            0,
            sector_size,
            hdr.refcount_table_offset,
            RT_BUF as *mut u8,
            rt_read,
        )
    {
        return Err(BitmapResult::ERROR_READ_FAILED);
    }
    let rt = core::slice::from_raw_parts(RT_BUF as *const u8, rt_read);

    // Collect refblock host offsets. v1 requires the populated
    // refblocks to be contiguous from refcount-table index 0 (no
    // gaps), so the flat allocator / refblock-mapping math is sound.
    // The first zero RT entry terminates the contiguous run.
    let mut refblock_count: usize = 0;
    {
        let mut i = 0usize;
        let mut seen_zero = false;
        while i + 8 <= rt_read {
            let entry = read_u64_be(rt, i) & L1_OFFSET_MASK;
            if entry != 0 {
                if seen_zero {
                    // Non-contiguous refblock layout: refuse (v1).
                    (call_table.verbose_print)(
                        b"bitmap: non-contiguous refcount table refused\n\0".as_ptr(),
                    );
                    return Err(BitmapResult::ERROR_PARSE_FAILED);
                }
                refblock_count += 1;
            } else {
                seen_zero = true;
            }
            i += 8;
        }
    }
    if refblock_count == 0 || refblock_count > MAX_REFBLOCKS {
        return Err(BitmapResult::ERROR_SCRATCH_TOO_SMALL);
    }
    let rb_offsets_ptr = RB_OFFSETS as *mut u64;
    let rb_offsets = core::slice::from_raw_parts_mut(rb_offsets_ptr, refblock_count);
    for (k, slot) in rb_offsets.iter_mut().enumerate() {
        *slot = read_u64_be(rt, k * 8) & L1_OFFSET_MASK;
    }
    let rb_total = refblock_count.saturating_mul(cluster_size_usize);
    if rb_total > REFBLOCKS_LIMIT {
        return Err(BitmapResult::ERROR_SCRATCH_TOO_SMALL);
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
            return Err(BitmapResult::ERROR_READ_FAILED);
        }
    }
    Ok(StagedRefblocks {
        refblock_count,
        // Refblocks contiguous from RT index 0 ⇒ index 0 covers
        // cluster 0 ⇒ byte offset 0.
        host_refblocks_start: 0,
    })
}

/// The cluster-host-offset -> (staged refblock byte offset, entry
/// index) mapping closure the 4c/4d refcount walks will use.
/// Refblocks are contiguous from RT index 0, so refblock slot ==
/// cluster_index / entries_per_refblock. Copied from snapshot's
/// `rb_lookup`.
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

// ---------------------------------------------------------------------------
// qcow2 runner
// ---------------------------------------------------------------------------

/// Drive the bitmap mutation over a qcow2 image.
///
/// Reads the full header cluster, parses the header and bitmaps
/// extension, runs the gate battery (Mission §2) — refusing *before
/// any write* so a refusal leaves the image byte-identical —
/// cross-checks the host-probed [`BitmapConfig`] fields against the
/// guest's own re-parse, stages the bitmaps directory + refcount
/// table + refblocks into scratch, then hands off to [`run_actions`]
/// which applies the ordered action list (4c) and writes back under
/// the autoclear dance. `ACTION_MERGE` is deferred to 4d.
///
/// `#[inline(never)]` is load-bearing. Built for `x86_64-unknown-none`
/// with `opt-level = "z"` + `lto = true`, inlining a large runner body
/// into the `extern "C"` `_start` (which already carries the call-table
/// validation, config read, and result/send plumbing) has miscompiled
/// `_start` on the sibling ops (the guest jumped mid-function, hit an
/// invalid opcode, and — with no IDT — triple-faulted). Keeping
/// `run_qcow2` out of line makes both functions small enough to codegen
/// correctly and is the shape the working amend/resize/rebase ops use.
/// Do not remove without re-verifying `instar bitmap` end-to-end.
///
/// # Safety
///
/// `call_table` must be the validated CallTable; the image is
/// attached input-RW at slot 0.
#[inline(never)]
unsafe fn run_qcow2(call_table: &CallTable, config: &BitmapConfig) -> BitmapResult {
    // Guard the sector size before any division in the RMW helpers.
    let sector_size = config.sector_size as usize;
    if config.sector_size < 512 || sector_size > MAX_SECTOR_SIZE || !sector_size.is_power_of_two() {
        (call_table.verbose_print)(b"bitmap: invalid sector_size\n\0".as_ptr());
        return make_result(config, 0, BitmapResult::ERROR_PARSE_FAILED);
    }

    // --- Read sector 0 to recover cluster_size, then the whole cluster ---
    let header_ptr = HEADER_BUF as *mut u8;
    if !(call_table.read_input_sector)(0, 0, header_ptr, sector_size) {
        return make_result(config, 0, BitmapResult::ERROR_READ_FAILED);
    }
    let sector0 = core::slice::from_raw_parts(header_ptr as *const u8, sector_size);
    let hdr0 = match QcowHeader::parse(sector0) {
        Some(h) => h,
        None => return make_result(config, 0, BitmapResult::ERROR_PARSE_FAILED),
    };

    // Bound the cluster to the scratch buffer before reading it.
    let cluster_size_usize = hdr0.cluster_size as usize;
    if cluster_size_usize > HEADER_LIMIT {
        (call_table.verbose_print)(b"bitmap: cluster_size exceeds HEADER_BUF\n\0".as_ptr());
        return make_result(config, 0, BitmapResult::ERROR_SCRATCH_TOO_SMALL);
    }

    // Read the full first cluster over the same buffer (the header
    // extensions — including the bitmaps extension — live past the
    // first sector). Skip the re-read when a cluster is one sector.
    if cluster_size_usize > sector_size
        && !read_input_byte_range(
            call_table,
            0,
            sector_size,
            0,
            header_ptr,
            cluster_size_usize,
        )
    {
        return make_result(config, 0, BitmapResult::ERROR_READ_FAILED);
    }
    let header = core::slice::from_raw_parts(header_ptr as *const u8, cluster_size_usize);
    let hdr = match QcowHeader::parse(header) {
        Some(h) => h,
        None => return make_result(config, 0, BitmapResult::ERROR_PARSE_FAILED),
    };

    // --- Gate battery (refuse before any write) --------------------------

    // qcow2 v2 cannot store persistent dirty bitmaps.
    if hdr.version < 3 {
        (call_table.verbose_print)(b"bitmap: qcow2 v2 cannot store bitmaps\n\0".as_ptr());
        return make_result(config, 0, BitmapResult::ERROR_UNSUPPORTED_VERSION);
    }

    // DIRTY / CORRUPT: refuse to touch an image another writer may
    // hold open, or a known-corrupt image. There is no dedicated
    // ERROR_DIRTY in BitmapResult, so map to ERROR_PARSE_FAILED with
    // an explanatory verbose_print (documented in the phase notes).
    if (hdr.incompatible_features & (INCOMPAT_DIRTY | INCOMPAT_CORRUPT)) != 0
        || hdr.dirty
        || hdr.corrupt
    {
        (call_table.verbose_print)(b"bitmap: dirty/corrupt image refused\n\0".as_ptr());
        return make_result(config, 0, BitmapResult::ERROR_PARSE_FAILED);
    }

    // v1 reuses the 16-bit-only refcount allocator.
    if hdr.refcount_bits != 16 {
        (call_table.verbose_print)(b"bitmap: refcount_bits != 16 refused\n\0".as_ptr());
        return make_result(config, 0, BitmapResult::ERROR_UNSUPPORTED_REFCOUNT_WIDTH);
    }

    // Parse the bitmaps extension + read the autoclear word @88. The
    // qcow2 crate walks the extension chain and folds in the autoclear
    // bit 0 consistency check for us (bitmaps_present ⇔ extension +
    // bit set; bitmaps_inconsistent ⇔ extension present but bit clear).
    let ext = parse_header_extensions(header, &hdr);
    let autoclear = if header.len() >= AUTOCLEAR_FEATURES_OFFSET + 8 {
        read_u64_be(header, AUTOCLEAR_FEATURES_OFFSET)
    } else {
        0
    };

    // A bitmaps extension present but autoclear-inconsistent (bit 0
    // clear) is refused UNLESS every requested action is --remove:
    // qemu allows removing inconsistent bitmaps, nothing else. Map to
    // ERROR_BITMAP_IN_USE (documented) — the bitmaps are stale/in-use
    // from the guest's point of view.
    if ext.bitmaps_inconsistent {
        let n = (config.num_actions as usize).min(shared::MAX_BITMAP_ACTIONS);
        let all_remove = n > 0
            && config.actions[..n]
                .iter()
                .all(|&a| a == BitmapConfig::ACTION_REMOVE);
        if !all_remove {
            (call_table.verbose_print)(
                b"bitmap: inconsistent bitmaps; only --remove allowed\n\0".as_ptr(),
            );
            return make_result(config, 0, BitmapResult::ERROR_BITMAP_IN_USE);
        }
    }

    // --- Host cross-check (defensive; mirrors amend/rebase) --------------
    //
    // Every field the guest can independently re-derive from the
    // header + bitmaps extension must equal what the host probed and
    // wrote into BitmapConfig. Any disagreement ⇒ ERROR_HEADER_MISMATCH.
    //
    // Derive the guest's view of nb_bitmaps / directory location from
    // the parsed extension: when there is no usable extension (neither
    // present nor inconsistent), those are 0. When inconsistent, the
    // extension body still carries the fields, so use them.
    let ext_has_body = ext.bitmaps_present || ext.bitmaps_inconsistent;
    let guest_nb_bitmaps = if ext_has_body {
        ext.bitmap_nb_bitmaps
    } else {
        0
    };
    let guest_dir_offset = if ext_has_body {
        ext.bitmap_directory_offset
    } else {
        0
    };
    let guest_dir_size = if ext_has_body {
        ext.bitmap_directory_size
    } else {
        0
    };

    let mismatch = config.cluster_size as u64 != hdr.cluster_size
        || config.current_version != hdr.version
        || config.current_refcount_bits != hdr.refcount_bits
        || config.virtual_size != hdr.virtual_size
        || config.current_autoclear_features != autoclear
        || config.current_incompatible_features != hdr.incompatible_features
        || config.nb_bitmaps != guest_nb_bitmaps
        || config.bitmap_directory_offset != guest_dir_offset
        || config.bitmap_directory_size != guest_dir_size;
    if mismatch {
        (call_table.verbose_print)(b"bitmap: host cross-check mismatch\n\0".as_ptr());
        return make_result(config, 0, BitmapResult::ERROR_HEADER_MISMATCH);
    }

    // --- Stage the bitmaps directory into DIR_A --------------------------
    //
    // When there is no extension (or nb_bitmaps == 0), the directory
    // is empty (len 0). Otherwise bound its size by BITMAP_DIR_LIMIT
    // and read it from the extension's directory offset.
    let dir_len = guest_dir_size as usize;
    if guest_nb_bitmaps > 0 && guest_dir_offset != 0 {
        if dir_len > DIR_A_LIMIT {
            (call_table.verbose_print)(b"bitmap: directory exceeds scratch\n\0".as_ptr());
            return make_result(config, 0, BitmapResult::ERROR_SCRATCH_TOO_SMALL);
        }
        if !read_input_byte_range(
            call_table,
            0,
            sector_size,
            guest_dir_offset,
            DIR_A as *mut u8,
            dir_len,
        ) {
            return make_result(config, 0, BitmapResult::ERROR_READ_FAILED);
        }
    }
    // `dir_len` (possibly 0) + DIR_A now hold the staged directory for
    // 4c to double-buffer into DIR_B.

    // --- Stage the refcount table + refblocks ----------------------------
    let staged = match stage_refblocks(call_table, &hdr, sector_size) {
        Ok(s) => s,
        Err(e) => return make_result(config, 0, e),
    };
    // `staged.refblock_count` refblocks are now in REFBLOCKS_BUF, their
    // host offsets in RB_OFFSETS, and `staged.host_refblocks_start`
    // (== 0) is the byte offset staged-refblock 0 maps to.

    // --- num_actions guard (do not slice out of bounds) ------------------
    let num_actions = config.num_actions as usize;
    if num_actions == 0 || num_actions > MAX_BITMAP_ACTIONS {
        (call_table.verbose_print)(b"bitmap: num_actions out of range\n\0".as_ptr());
        return make_result(config, 0, BitmapResult::ERROR_UNSUPPORTED_ACTION);
    }

    // --- Merge vs metadata dispatch (v1: never mixed) --------------------
    //
    // Merge mutates only the destination bitmap's *table entries* and
    // *data clusters* (not the directory), so it uses a dedicated flow
    // rather than 4c's directory-centric write-back. v1 restricts an
    // invocation to EITHER all-metadata-actions OR a single merge
    // action: a mix is refused with ERROR_UNSUPPORTED_ACTION (the
    // host/tests drive them separately; documented in the module doc
    // and the phase-4 plan).
    let actions = &config.actions[..num_actions];
    let any_merge = actions.iter().any(|&a| a == BitmapConfig::ACTION_MERGE);
    if any_merge {
        let all_merge = actions.iter().all(|&a| a == BitmapConfig::ACTION_MERGE);
        if !all_merge || num_actions != 1 {
            // Merge mixed with other actions (or repeated) — refuse.
            (call_table.verbose_print)(b"bitmap: merge must be the sole action (v1)\n\0".as_ptr());
            return make_result(
                config,
                BitmapConfig::ACTION_MERGE as u32,
                BitmapResult::ERROR_UNSUPPORTED_ACTION,
            );
        }
        return run_merge(
            call_table,
            config,
            sector_size,
            &hdr,
            dir_len,
            guest_nb_bitmaps,
            staged,
        );
    }

    // --- Locate the bitmaps extension body offset in HEADER_BUF ----------
    //
    // parse_header_extensions did not hand us the byte offset of the
    // EXT_BITMAPS record body, so re-walk the chain to find it (for the
    // in-place rewrite path) or the EXT_END position (for the first-add
    // create-extension path). Both are guest-side of the write-back.
    let ext_body_offset = find_bitmaps_ext_body_offset(header, &hdr);

    // --- Run the ordered action loop + write-back + autoclear dance ------
    run_actions(
        call_table,
        config,
        sector_size,
        &hdr,
        dir_len,
        guest_nb_bitmaps,
        ext_body_offset,
        staged,
    )
}

// ---------------------------------------------------------------------------
// Header-extension helpers
// ---------------------------------------------------------------------------

/// Walk the header-extension chain in `header` and return the byte
/// offset of the EXT_BITMAPS record's 24-byte body (the offset just
/// past its 8-byte type/len record header), or `None` if there is no
/// EXT_BITMAPS record.
///
/// Mirrors [`parse_header_extensions`]'s walk exactly (same bounds
/// checks) but reports position rather than parsed fields.
#[inline(never)]
fn find_bitmaps_ext_body_offset(header: &[u8], hdr: &QcowHeader) -> Option<usize> {
    if hdr.version < 3 || header.len() < HEADER_LENGTH_OFFSET + 4 {
        return None;
    }
    let header_length = read_u32_be(header, HEADER_LENGTH_OFFSET) as usize;
    let mut ext_offset = header_length;
    while ext_offset + 8 <= header.len() {
        let ext_type = read_u32_be(header, ext_offset);
        let ext_len = read_u32_be(header, ext_offset + 4) as usize;
        if ext_type == EXT_END {
            break;
        }
        if ext_offset + 8 + ext_len > header.len() {
            break;
        }
        if ext_type == EXT_BITMAPS {
            return Some(ext_offset + 8);
        }
        let padded_len = (ext_len + 7) & !7;
        ext_offset += 8 + padded_len;
    }
    None
}

/// Read a big-endian u32 from `buf` at `off`; returns 0 if the read
/// would run out of bounds (callers pre-bound their offsets, this is
/// a panic-free fallback).
fn read_u32_be(buf: &[u8], off: usize) -> u32 {
    match buf.get(off..off + 4) {
        Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Action loop + write-back + autoclear dance (step 4c)
// ---------------------------------------------------------------------------

/// Maximum number of table clusters the guest may accumulate to
/// zero-fill in a single invocation. Each `add` contributes up to
/// [`MAX_TABLE_CLUSTERS`] and each `clear` its table clusters; with
/// [`MAX_BITMAP_ACTIONS`] actions this bounds the accumulation list.
const MAX_ZERO_CLUSTERS: usize = MAX_BITMAP_ACTIONS * MAX_TABLE_CLUSTERS;

/// A fixed-capacity list of host cluster offsets to zero-fill on
/// write-back (an `add`'s newly-allocated table clusters, a `clear`'s
/// table clusters after their data is freed).
struct ZeroList {
    offsets: [u64; MAX_ZERO_CLUSTERS],
    len: usize,
}

impl ZeroList {
    fn new() -> Self {
        Self {
            offsets: [0; MAX_ZERO_CLUSTERS],
            len: 0,
        }
    }

    /// Push one cluster offset; returns false if the list is full.
    fn push(&mut self, off: u64) -> bool {
        if self.len >= MAX_ZERO_CLUSTERS {
            return false;
        }
        self.offsets[self.len] = off;
        self.len += 1;
        true
    }
}

/// Number of refcount entries per staged refcount block
/// (`cluster_size * 8 / refcount_bits`). Refcount width is gated to
/// 16 upstream, so this is well-defined.
fn entries_per_refblock(cluster_size: u64) -> u64 {
    (cluster_size * 8) / 16
}

/// Free the **data** clusters of a bitmap whose on-disk table lives at
/// `table_offset` (`table_size` entries), by walking the table in
/// `TABLE_BUF` and setting each `Allocated` cluster's refcount to 0 in
/// the staged `REFBLOCKS_BUF`.
///
/// The Phase-3 crate already freed the *table* clusters (for `remove`)
/// or left them allocated (for `clear`); this frees only the data
/// clusters the crate could not see, exactly as the 3c design split
/// prescribes. Read-only device I/O (staging the table); the frees are
/// in-memory refblock mutations.
///
/// # Safety
///
/// `call_table` must be the validated CallTable.
#[inline(never)]
unsafe fn free_bitmap_data_clusters(
    call_table: &CallTable,
    sector_size: usize,
    cluster_size: u64,
    refblock_count: usize,
    table_offset: u64,
    table_size: u32,
) -> Result<(), u32> {
    if table_size == 0 || table_offset == 0 {
        return Ok(());
    }
    let cluster_size_usize = cluster_size as usize;
    let epr = entries_per_refblock(cluster_size);
    let lookup = rb_lookup(cluster_size, epr, refblock_count, cluster_size_usize);
    let refblocks = core::slice::from_raw_parts_mut(
        REFBLOCKS_BUF as *mut u8,
        refblock_count * cluster_size_usize,
    );

    // The bitmap table is `table_size` u64 words. Walk it one cluster
    // of entries at a time through TABLE_BUF so an arbitrarily large
    // table never needs more than one cluster of scratch.
    let entries_per_cluster = cluster_size / 8;
    if entries_per_cluster == 0 {
        return Err(BitmapResult::ERROR_INTERNAL_OVERFLOW);
    }
    let mut remaining = table_size as u64;
    let mut entry_index: u64 = 0;
    while remaining > 0 {
        let take = remaining.min(entries_per_cluster);
        let bytes = (take as usize) * 8;
        let cluster_ord = entry_index / entries_per_cluster;
        let table_chunk_off = table_offset
            .checked_add(
                cluster_ord
                    .checked_mul(cluster_size)
                    .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?,
            )
            .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
        if !read_input_byte_range(
            call_table,
            0,
            sector_size,
            table_chunk_off,
            TABLE_BUF as *mut u8,
            bytes,
        ) {
            return Err(BitmapResult::ERROR_READ_FAILED);
        }
        let table = core::slice::from_raw_parts(TABLE_BUF as *const u8, bytes);
        let mut i = 0usize;
        while i + 8 <= bytes {
            let raw = read_u64_be(table, i);
            match decode_bitmap_table_entry(raw) {
                Some(BitmapTableEntry::Allocated(off)) => {
                    // Free this data cluster: refcount -> 0.
                    let (rb_start, entry_local) =
                        lookup(off).ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
                    let block = refblocks
                        .get_mut(rb_start..rb_start + cluster_size_usize)
                        .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
                    if set_refcount_in_block(block, entry_local, 16, 0).is_err() {
                        return Err(BitmapResult::ERROR_INTERNAL_OVERFLOW);
                    }
                }
                // AllZeroes / AllOnes own no data cluster; nothing to free.
                Some(_) => {}
                // A bad table word ⇒ refuse rather than corrupt refcounts.
                None => return Err(BitmapResult::ERROR_PARSE_FAILED),
            }
            i += 8;
        }
        entry_index += take;
        remaining -= take;
    }
    Ok(())
}

/// The ordered action loop, the write-back, and the crash-safe
/// autoclear dance (Open question 1). Only reached after every gate
/// passed and staging succeeded.
///
/// The loop mutates only scratch (the DIR_A/DIR_B double-buffer and
/// REFBLOCKS_BUF in memory) plus read-only table-walk reads, so any
/// action error returns immediately with the image byte-identical.
/// Only after all actions succeed does the write-back touch the disk,
/// guarded by clearing the autoclear bitmaps bit first and restoring
/// it last.
///
/// `#[inline(never)]` for the same codegen-miscompile reason as
/// `run_qcow2` (a large body inlined into `_start` triple-faults).
///
/// # Safety
///
/// `call_table` must be the validated CallTable; the image is attached
/// input-RW at slot 0. `dir_len` bytes of the staged directory are in
/// DIR_A; `staged` describes REFBLOCKS_BUF / RB_OFFSETS.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn run_actions(
    call_table: &CallTable,
    config: &BitmapConfig,
    sector_size: usize,
    hdr: &QcowHeader,
    dir_len: usize,
    initial_nb_bitmaps: u32,
    ext_body_offset: Option<usize>,
    staged: StagedRefblocks,
) -> BitmapResult {
    let cluster_size = hdr.cluster_size;
    let cluster_size_usize = cluster_size as usize;
    let refblock_count = staged.refblock_count;

    // Resolve the shared target name and its (add-only) granularity.
    let name_len = config.name_len as usize;
    if name_len == 0 || name_len > config.name.len() {
        return make_result(config, 0, BitmapResult::ERROR_NAME_TOO_LONG);
    }
    let name = &config.name[..name_len];

    // Convert the requested granularity (bytes; 0 => default) to bits
    // and validate the range once (add is the only consumer).
    let granularity_bytes = if config.granularity == 0 {
        default_granularity(cluster_size)
    } else {
        config.granularity
    };
    let granularity_bits = match bytes_to_bits(granularity_bytes) {
        Some(b) if granularity_bits_valid(b) => b,
        _ => return make_result(config, 0, BitmapResult::ERROR_GRANULARITY_RANGE),
    };

    let geom = BitmapGeometry {
        cluster_size,
        cluster_bits: hdr.cluster_bits,
        refcount_bits: 16,
        virtual_size: hdr.virtual_size,
        refblock_count: refblock_count as u64,
        host_refblocks_start: staged.host_refblocks_start,
    };

    let refblocks = core::slice::from_raw_parts_mut(
        REFBLOCKS_BUF as *mut u8,
        refblock_count * cluster_size_usize,
    );

    let mut cursor = AllocCursor::default();
    let mut zeros = ZeroList::new();

    // Directory double-buffer: `cur_in` names which scratch buffer
    // holds the current directory; the action writes the other one.
    let mut cur_in_a = true;
    let mut cur_len = dir_len;
    let mut cur_nb = initial_nb_bitmaps;
    let mut last_action: u32 = 0;
    let mut extension_present = initial_nb_bitmaps > 0;

    for &opcode in &config.actions[..config.num_actions as usize] {
        last_action = opcode as u32;
        let (in_ptr, out_ptr, in_limit, out_limit) = if cur_in_a {
            (DIR_A, DIR_B, DIR_A_LIMIT, DIR_B_LIMIT)
        } else {
            (DIR_B, DIR_A, DIR_B_LIMIT, DIR_A_LIMIT)
        };
        let old_dir = core::slice::from_raw_parts(in_ptr as *const u8, in_limit);
        let out_dir = core::slice::from_raw_parts_mut(out_ptr as *mut u8, out_limit);

        let outcome: ActionOutcome = match opcode {
            BitmapConfig::ACTION_ADD => match action_add(
                old_dir,
                cur_len,
                cur_nb,
                name,
                granularity_bits,
                refblocks,
                &mut cursor,
                &geom,
                out_dir,
            ) {
                Ok(o) => o,
                Err(e) => return make_result(config, last_action, u32::from(e)),
            },
            BitmapConfig::ACTION_REMOVE => {
                let o = match action_remove(
                    old_dir, cur_len, cur_nb, name, refblocks, &geom, out_dir,
                ) {
                    Ok(o) => o,
                    Err(e) => return make_result(config, last_action, u32::from(e)),
                };
                // Free the removed bitmap's data clusters (crate freed
                // the table clusters; guest frees the data clusters).
                if let Err(e) = free_bitmap_data_clusters(
                    call_table,
                    sector_size,
                    cluster_size,
                    refblock_count,
                    o.freed_table_offset,
                    o.freed_table_size,
                ) {
                    return make_result(config, last_action, e);
                }
                o
            }
            BitmapConfig::ACTION_CLEAR => {
                let o =
                    match action_clear(old_dir, cur_len, cur_nb, name, refblocks, &geom, out_dir) {
                        Ok(o) => o,
                        Err(e) => return make_result(config, last_action, u32::from(e)),
                    };
                // Free the data clusters, then remember to zero the
                // (still-allocated) table clusters on write-back.
                if let Err(e) = free_bitmap_data_clusters(
                    call_table,
                    sector_size,
                    cluster_size,
                    refblock_count,
                    o.freed_table_offset,
                    o.freed_table_size,
                ) {
                    return make_result(config, last_action, e);
                }
                if o.zero_freed_table {
                    let table_clusters = table_cluster_count(o.freed_table_size, cluster_size);
                    for k in 0..table_clusters {
                        let off = match o
                            .freed_table_offset
                            .checked_add(k.wrapping_mul(cluster_size))
                        {
                            Some(v) => v,
                            None => {
                                return make_result(
                                    config,
                                    last_action,
                                    BitmapResult::ERROR_INTERNAL_OVERFLOW,
                                )
                            }
                        };
                        if !zeros.push(off) {
                            return make_result(
                                config,
                                last_action,
                                BitmapResult::ERROR_SCRATCH_TOO_SMALL,
                            );
                        }
                    }
                }
                o
            }
            BitmapConfig::ACTION_ENABLE => {
                match action_enable(old_dir, cur_len, cur_nb, name, out_dir) {
                    Ok(o) => o,
                    Err(e) => return make_result(config, last_action, u32::from(e)),
                }
            }
            BitmapConfig::ACTION_DISABLE => {
                match action_disable(old_dir, cur_len, cur_nb, name, out_dir) {
                    Ok(o) => o,
                    Err(e) => return make_result(config, last_action, u32::from(e)),
                }
            }
            BitmapConfig::ACTION_MERGE => {
                // Merge is 4d; refuse for now (image untouched — the
                // loop has only mutated scratch up to this point).
                return make_result(config, last_action, BitmapResult::ERROR_UNSUPPORTED_ACTION);
            }
            _ => return make_result(config, last_action, BitmapResult::ERROR_UNSUPPORTED_ACTION),
        };

        // Record add's newly-allocated table clusters to zero-fill.
        for k in 0..outcome.num_table_clusters_to_zero {
            if !zeros.push(outcome.table_clusters_to_zero[k]) {
                return make_result(config, last_action, BitmapResult::ERROR_SCRATCH_TOO_SMALL);
            }
        }

        cur_len = outcome.new_dir_len;
        cur_nb = outcome.new_nb_bitmaps;
        extension_present = outcome.extension_now_present;
        cur_in_a = !cur_in_a; // ping-pong: out becomes next in.
    }

    // The final directory is in whichever buffer `cur_in_a` now names.
    let final_dir_ptr = if cur_in_a { DIR_A } else { DIR_B };
    let final_len = cur_len;
    let final_nb = cur_nb;

    // --- Write-back + autoclear dance ------------------------------------
    match write_back(
        call_table,
        config,
        sector_size,
        hdr,
        &staged,
        ext_body_offset,
        final_dir_ptr,
        final_len,
        final_nb,
        extension_present,
        &zeros,
    ) {
        Ok(()) => {}
        Err(e) => return make_result(config, last_action, e),
    }

    let mut result = make_result(config, last_action, BitmapResult::ERROR_OK);
    result.actions_applied = config.num_actions;
    result.resulting_nb_bitmaps = final_nb;
    result
}

/// Number of clusters a bitmap table of `table_size` entries occupies:
/// `ceil(table_size * 8 / cluster_size)`. Panic-free.
fn table_cluster_count(table_size: u32, cluster_size: u64) -> u64 {
    if cluster_size == 0 {
        return 0;
    }
    ((table_size as u64).saturating_mul(8)).div_ceil(cluster_size)
}

/// Convert a power-of-two granularity in **bytes** to `granularity_bits`
/// (`log2`). Returns `None` if `bytes` is 0 or not a power of two.
fn bytes_to_bits(bytes: u64) -> Option<u8> {
    if bytes == 0 || !bytes.is_power_of_two() {
        return None;
    }
    Some(bytes.trailing_zeros() as u8)
}

/// The crash-safe write-back: clear the autoclear bitmaps bit, write
/// the new/zeroed clusters + directory + refblocks, rewrite (or drop /
/// create) the bitmaps extension, then set the autoclear bit back
/// (unless the last bitmap was removed). fsync barriers model
/// `check --repair`'s `repair_all_qcow2`.
///
/// # Safety
///
/// `call_table` must be the validated CallTable; the image is attached
/// input-RW at slot 0. `final_dir_ptr`/`final_len` name the final
/// directory in scratch; the header cluster is in HEADER_BUF.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn write_back(
    call_table: &CallTable,
    config: &BitmapConfig,
    sector_size: usize,
    hdr: &QcowHeader,
    staged: &StagedRefblocks,
    ext_body_offset: Option<usize>,
    final_dir_ptr: usize,
    final_len: usize,
    final_nb: u32,
    extension_present: bool,
    zeros: &ZeroList,
) -> Result<(), u32> {
    let cluster_size = hdr.cluster_size;
    let cluster_size_usize = cluster_size as usize;
    let refblock_count = staged.refblock_count;

    // The old directory occupies this many clusters at the old offset.
    let old_dir_offset = config.bitmap_directory_offset;
    let old_dir_clusters = if old_dir_offset != 0 {
        div_ceil_u64(config.bitmap_directory_size, cluster_size)
    } else {
        0
    };
    let new_dir_clusters = if final_nb > 0 {
        div_ceil_u64(final_len as u64, cluster_size).max(1)
    } else {
        0
    };

    let refblocks = core::slice::from_raw_parts_mut(
        REFBLOCKS_BUF as *mut u8,
        refblock_count * cluster_size_usize,
    );
    let epr = entries_per_refblock(cluster_size);
    let lookup = rb_lookup(cluster_size, epr, refblock_count, cluster_size_usize);

    // ---- Decide directory placement (in refblocks; no disk write yet) ---
    let mut dir_offset = old_dir_offset;
    let mut cursor = AllocCursor::default();
    if final_nb == 0 {
        // Last bitmap removed: no directory. Free the old dir clusters.
        free_cluster_run(
            refblocks,
            &lookup,
            cluster_size,
            old_dir_offset,
            old_dir_clusters,
        )?;
        dir_offset = 0;
    } else if old_dir_offset != 0 && new_dir_clusters <= old_dir_clusters {
        // Fits in place: keep dir_offset. Free the now-unused tail
        // clusters for refcount cleanliness.
        if new_dir_clusters < old_dir_clusters {
            let tail_start = old_dir_offset
                .checked_add(new_dir_clusters.wrapping_mul(cluster_size))
                .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
            free_cluster_run(
                refblocks,
                &lookup,
                cluster_size,
                tail_start,
                old_dir_clusters - new_dir_clusters,
            )?;
        }
    } else {
        // Grew, or there was no directory before (first add): allocate
        // fresh contiguous clusters and free the old ones (if any).
        let new_off = alloc_contiguous_clusters_in_refblocks(
            refblocks,
            cluster_size,
            16,
            refblock_count as u64,
            staged.host_refblocks_start,
            new_dir_clusters,
            &mut cursor,
        )
        .map_err(|_| BitmapResult::ERROR_NO_SPACE)?;
        if old_dir_offset != 0 {
            free_cluster_run(
                refblocks,
                &lookup,
                cluster_size,
                old_dir_offset,
                old_dir_clusters,
            )?;
        }
        dir_offset = new_off;
    }

    // ---- Step 2: CLEAR the autoclear bitmaps bit, fsync -----------------
    // From here a crash leaves the bitmaps ignorable (autoclear clear).
    rmw_feature_word(
        call_table,
        sector_size,
        AUTOCLEAR_FEATURES_OFFSET as u64,
        |w| w & !AUTOCLEAR_BITMAPS_BIT,
    )?;
    let _ = (call_table.fsync_input)(0);

    // ---- Step 4: write zeroed/table clusters, directory, refblocks ------
    // Ensure ZERO_BUF holds a full cluster of zeros (fresh scratch).
    core::ptr::write_bytes(ZERO_BUF as *mut u8, 0, cluster_size_usize);
    let zero_slice = core::slice::from_raw_parts(ZERO_BUF as *const u8, cluster_size_usize);
    for k in 0..zeros.len {
        if !write_input_byte_range(call_table, 0, sector_size, zeros.offsets[k], zero_slice) {
            return Err(BitmapResult::ERROR_WRITE_FAILED);
        }
    }

    // Write the final directory bytes (in place or relocated).
    if final_nb > 0 && dir_offset != 0 && final_len > 0 {
        let dir_slice = core::slice::from_raw_parts(final_dir_ptr as *const u8, final_len);
        if !write_input_byte_range(call_table, 0, sector_size, dir_offset, dir_slice) {
            return Err(BitmapResult::ERROR_WRITE_FAILED);
        }
    }

    // Write the mutated refblocks back to their on-disk locations
    // (captured in RB_OFFSETS during staging). Written AFTER the
    // clusters they account for so a crash cannot leave a
    // refcounted-but-unwritten cluster claimed.
    let rb_offsets = core::slice::from_raw_parts(RB_OFFSETS as *const u64, refblock_count);
    for (k, &host_off) in rb_offsets.iter().enumerate() {
        let src = (REFBLOCKS_BUF + k * cluster_size_usize) as *const u8;
        let block = core::slice::from_raw_parts(src, cluster_size_usize);
        if !write_input_byte_range(call_table, 0, sector_size, host_off, block) {
            return Err(BitmapResult::ERROR_WRITE_FAILED);
        }
    }
    let _ = (call_table.fsync_input)(0);

    // ---- Step 5: write the bitmaps extension in the header --------------
    write_bitmaps_extension(
        call_table,
        sector_size,
        hdr,
        ext_body_offset,
        final_nb,
        final_len as u64,
        dir_offset,
    )?;
    let _ = (call_table.fsync_input)(0);

    // ---- Step 6: SET the autoclear bit back (unless last removed) -------
    if extension_present && final_nb > 0 {
        rmw_feature_word(
            call_table,
            sector_size,
            AUTOCLEAR_FEATURES_OFFSET as u64,
            |w| w | AUTOCLEAR_BITMAPS_BIT,
        )?;
        let _ = (call_table.fsync_input)(0);
    }

    Ok(())
}

/// `ceil(a / b)`, panic-free (returns 0 if `b == 0`).
fn div_ceil_u64(a: u64, b: u64) -> u64 {
    if b == 0 {
        0
    } else {
        a.div_ceil(b)
    }
}

/// Free `count` consecutive clusters starting at `start` by setting
/// each refcount to 0 in the staged refblocks.
fn free_cluster_run<F>(
    refblocks: &mut [u8],
    lookup: &F,
    cluster_size: u64,
    start: u64,
    count: u64,
) -> Result<(), u32>
where
    F: Fn(u64) -> Option<(usize, u64)>,
{
    let cluster_size_usize = cluster_size as usize;
    for k in 0..count {
        let off = start
            .checked_add(
                k.checked_mul(cluster_size)
                    .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?,
            )
            .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
        let (rb_start, entry_local) = lookup(off).ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
        let block = refblocks
            .get_mut(rb_start..rb_start + cluster_size_usize)
            .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
        if set_refcount_in_block(block, entry_local, 16, 0).is_err() {
            return Err(BitmapResult::ERROR_INTERNAL_OVERFLOW);
        }
    }
    Ok(())
}

/// Read-modify-write the 8-byte feature word at `offset`: read it,
/// apply `f`, write it back. Used to clear/set the autoclear bitmaps
/// bit. Models `check --repair`'s corrupt-bit RMW.
///
/// # Safety
///
/// `call_table` must be the validated CallTable.
unsafe fn rmw_feature_word<F>(
    call_table: &CallTable,
    sector_size: usize,
    offset: u64,
    f: F,
) -> Result<(), u32>
where
    F: FnOnce(u64) -> u64,
{
    let mut buf = [0u8; 8];
    if !read_input_byte_range(call_table, 0, sector_size, offset, buf.as_mut_ptr(), 8) {
        return Err(BitmapResult::ERROR_READ_FAILED);
    }
    let word = u64::from_be_bytes(buf);
    let new = f(word).to_be_bytes();
    if !write_input_byte_range(call_table, 0, sector_size, offset, &new) {
        return Err(BitmapResult::ERROR_WRITE_FAILED);
    }
    Ok(())
}

/// Write the bitmaps extension body in the header on disk.
///
/// Three cases:
/// - `final_nb == 0`: write a benign empty body (nb=0, size=0,
///   offset=0) into the existing extension record if there is one; no
///   record to create.
/// - `ext_body_offset` present (an EXT_BITMAPS record already exists):
///   overwrite its 24-byte body in place.
/// - No record yet and `final_nb > 0` (first add on an image with no
///   bitmaps extension): CREATE a new EXT_BITMAPS record by
///   overwriting the terminating EXT_END with the new record and
///   writing a fresh EXT_END after it, all within the header cluster.
///
/// # Safety
///
/// `call_table` must be the validated CallTable; HEADER_BUF holds the
/// staged header cluster.
#[inline(never)]
unsafe fn write_bitmaps_extension(
    call_table: &CallTable,
    sector_size: usize,
    hdr: &QcowHeader,
    ext_body_offset: Option<usize>,
    final_nb: u32,
    dir_size: u64,
    dir_offset: u64,
) -> Result<(), u32> {
    let mut body = [0u8; 24];
    let (nb, size, off) = if final_nb == 0 {
        (0u32, 0u64, 0u64)
    } else {
        (final_nb, dir_size, dir_offset)
    };
    serialize_bitmaps_extension(nb, size, off, &mut body)
        .map_err(|_| BitmapResult::ERROR_INTERNAL_OVERFLOW)?;

    if let Some(body_off) = ext_body_offset {
        // In-place body rewrite of the existing EXT_BITMAPS record.
        if !write_input_byte_range(call_table, 0, sector_size, body_off as u64, &body) {
            return Err(BitmapResult::ERROR_WRITE_FAILED);
        }
        return Ok(());
    }

    // No existing extension. If the last bitmap was removed there is
    // nothing to create (there was no extension to begin with in this
    // branch); return cleanly.
    if final_nb == 0 {
        return Ok(());
    }

    // First add on an image with no bitmaps extension: create a new
    // EXT_BITMAPS record before the terminating EXT_END, all within
    // the staged header cluster in HEADER_BUF.
    let cluster_size_usize = hdr.cluster_size as usize;
    let header = core::slice::from_raw_parts_mut(HEADER_BUF as *mut u8, cluster_size_usize);
    let header_ro = core::slice::from_raw_parts(HEADER_BUF as *const u8, cluster_size_usize);
    let header_length = read_u32_be(header_ro, HEADER_LENGTH_OFFSET) as usize;

    // Find where EXT_END currently sits (its record header offset).
    let ext_end_after = match header_extension_area_end(header_ro, header_length) {
        Some(v) => v, // offset just past the 8-byte EXT_END header.
        None => return Err(BitmapResult::ERROR_PARSE_FAILED),
    };
    let ext_end_off = ext_end_after
        .checked_sub(8)
        .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;

    // The new record is [type:u32][len=24:u32][24-byte body], then a
    // fresh 8-byte EXT_END after it. It replaces the old EXT_END at
    // `ext_end_off` and needs 8 + 24 + 8 = 40 bytes from there.
    let need_end = ext_end_off
        .checked_add(8 + 24 + 8)
        .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
    if need_end > cluster_size_usize {
        // No room in the header cluster for a new extension record.
        (call_table.verbose_print)(
            b"bitmap: no header room to create bitmaps extension\n\0".as_ptr(),
        );
        return Err(BitmapResult::ERROR_SCRATCH_TOO_SMALL);
    }

    // Write the record header + body + new EXT_END into HEADER_BUF.
    write_be_u32(header, ext_end_off, EXT_BITMAPS);
    write_be_u32(header, ext_end_off + 4, 24);
    header[ext_end_off + 8..ext_end_off + 8 + 24].copy_from_slice(&body);
    // New EXT_END record (type 0, len 0).
    write_be_u32(header, ext_end_off + 32, EXT_END);
    write_be_u32(header, ext_end_off + 36, 0);

    // Persist just the affected header byte range [ext_end_off, need_end).
    let patch = core::slice::from_raw_parts(
        (HEADER_BUF + ext_end_off) as *const u8,
        need_end - ext_end_off,
    );
    if !write_input_byte_range(call_table, 0, sector_size, ext_end_off as u64, patch) {
        return Err(BitmapResult::ERROR_WRITE_FAILED);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Merge on-disk orchestration (step 4d)
// ---------------------------------------------------------------------------

/// Resolve merge source `k`'s name slice within `config.merge_source_pool`,
/// summing the preceding `merge_source_lens`. Returns `None` if the
/// declared lengths run past the pool (a malformed config).
fn merge_source_name(config: &BitmapConfig, k: usize) -> Option<&[u8]> {
    let mut start: usize = 0;
    for i in 0..k {
        start = start.checked_add(config.merge_source_lens[i] as usize)?;
    }
    let len = config.merge_source_lens[k] as usize;
    let end = start.checked_add(len)?;
    config.merge_source_pool.get(start..end)
}

/// Map a `snapshot::qcow2` allocator error onto the bitmap ABI:
/// exhaustion ⇒ `ERROR_NO_SPACE`, unsupported width ⇒
/// `ERROR_UNSUPPORTED_REFCOUNT_WIDTH`, anything else ⇒
/// `ERROR_INTERNAL_OVERFLOW`.
fn alloc_err_to_code(e: SnapshotError) -> u32 {
    match e {
        SnapshotError::RefcountExhausted => BitmapResult::ERROR_NO_SPACE,
        SnapshotError::Unsupported => BitmapResult::ERROR_UNSUPPORTED_REFCOUNT_WIDTH,
        _ => BitmapResult::ERROR_INTERNAL_OVERFLOW,
    }
}

/// Merge orchestration + crash-safe autoclear dance for
/// `ACTION_MERGE`.
///
/// Merge OR-s each source bitmap's set bits into the destination
/// bitmap. Unlike the metadata actions it does **not** change the
/// directory (the destination's directory entry — its table
/// offset/size — is unchanged); it mutates only the destination's
/// bitmap **table entries** and its **data clusters**, plus the
/// refcounts of freshly-allocated / freed data clusters. It therefore
/// runs its own write-back rather than 4c's directory-centric one.
///
/// The full pre-flight (`merge_validate` for every source) runs
/// *before* any write, so a validation refusal leaves the image
/// byte-identical. Once validated, the flow is:
///   1. self-merge only ⇒ no-op success (OR-ing a bitmap into itself
///      changes nothing).
///   2. CLEAR the autoclear bitmaps bit, fsync — a crash from here
///      leaves the bitmaps ignorable.
///   3. For each source, walk `table_size` table indices, applying the
///      per-index [`MergeClusterAction`] (Skip / CopyAllOnes /
///      OrIntoExisting / AllocDestFromSource): read/OR/write data
///      clusters, allocate/free dest clusters, and rewrite dest table
///      entries in place. fsync once after the loop.
///   4. Write the mutated refblocks back, fsync.
///   5. SET the autoclear bit back, fsync (merge never removes the
///      last bitmap, so autoclear is always restored).
///
/// `#[inline(never)]` for the same codegen-miscompile reason as
/// `run_qcow2` / `run_actions`.
///
/// # Safety
///
/// `call_table` must be the validated CallTable; the image is attached
/// input-RW at slot 0. `dir_len` bytes of the staged directory are in
/// DIR_A; `staged` describes REFBLOCKS_BUF / RB_OFFSETS.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn run_merge(
    call_table: &CallTable,
    config: &BitmapConfig,
    sector_size: usize,
    hdr: &QcowHeader,
    dir_len: usize,
    nb_bitmaps: u32,
    staged: StagedRefblocks,
) -> BitmapResult {
    let merge_action = BitmapConfig::ACTION_MERGE as u32;
    let cluster_size = hdr.cluster_size;

    // Dest name (shared target). Guard the length as run_actions does.
    let name_len = config.name_len as usize;
    if name_len == 0 || name_len > config.name.len() {
        return make_result(config, merge_action, BitmapResult::ERROR_NAME_TOO_LONG);
    }
    let dest_name = &config.name[..name_len];

    // At least one source is required for a merge.
    let num_sources = config.num_merge_sources as usize;
    if num_sources == 0 || num_sources > shared::MAX_MERGE_SOURCES {
        (call_table.verbose_print)(b"bitmap: merge requires 1..=8 sources\n\0".as_ptr());
        return make_result(config, merge_action, BitmapResult::ERROR_UNSUPPORTED_ACTION);
    }

    let geom = BitmapGeometry {
        cluster_size,
        cluster_bits: hdr.cluster_bits,
        refcount_bits: 16,
        virtual_size: hdr.virtual_size,
        refblock_count: staged.refblock_count as u64,
        host_refblocks_start: staged.host_refblocks_start,
    };

    // The staged directory lives in DIR_A (dir_len bytes). merge_validate
    // reads it read-only; the directory is never rewritten for merge.
    let dir = core::slice::from_raw_parts(DIR_A as *const u8, dir_len);

    // --- Pre-flight: validate every source (no write) --------------------
    //
    // Validating all sources up front keeps a refusal image-byte-identical
    // even for a multi-source request. `all_self` tracks whether every
    // source is a self-merge (⇒ whole invocation is a no-op).
    let mut all_self = true;
    for k in 0..num_sources {
        let src_name = match merge_source_name(config, k) {
            Some(s) if !s.is_empty() => s,
            _ => {
                (call_table.verbose_print)(b"bitmap: bad merge source name\n\0".as_ptr());
                return make_result(
                    config,
                    merge_action,
                    BitmapResult::ERROR_MERGE_SOURCE_NOT_FOUND,
                );
            }
        };
        match merge_validate(dir, nb_bitmaps, dest_name, src_name, &geom) {
            Ok(spec) => {
                if !spec.self_merge {
                    all_self = false;
                }
            }
            Err(e) => return make_result(config, merge_action, u32::from(e)),
        }
    }

    // Every source is a self-merge (or the sole source is) ⇒ no-op success.
    if all_self {
        let mut result = make_result(config, merge_action, BitmapResult::ERROR_OK);
        result.actions_applied = 1;
        result.resulting_nb_bitmaps = nb_bitmaps;
        return result;
    }

    // --- Autoclear dance around the data mutation ------------------------
    match write_back_merge(
        call_table,
        config,
        sector_size,
        hdr,
        &staged,
        dir,
        nb_bitmaps,
        dest_name,
        num_sources,
        &geom,
    ) {
        Ok(()) => {}
        Err(e) => return make_result(config, merge_action, e),
    }

    let mut result = make_result(config, merge_action, BitmapResult::ERROR_OK);
    result.actions_applied = 1;
    result.resulting_nb_bitmaps = nb_bitmaps;
    result
}

/// The crash-safe merge write-back: clear the autoclear bitmaps bit,
/// apply every source merge (per-index table walk + data I/O + dest
/// table-entry rewrites), write the mutated refblocks, then set the
/// autoclear bit back. fsync barriers mirror `check --repair`.
///
/// # Safety
///
/// `call_table` must be the validated CallTable; the image is attached
/// input-RW at slot 0. `dir` names the staged directory; REFBLOCKS_BUF
/// / RB_OFFSETS are described by `staged`.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn write_back_merge(
    call_table: &CallTable,
    config: &BitmapConfig,
    sector_size: usize,
    hdr: &QcowHeader,
    staged: &StagedRefblocks,
    dir: &[u8],
    nb_bitmaps: u32,
    dest_name: &[u8],
    num_sources: usize,
    geom: &BitmapGeometry,
) -> Result<(), u32> {
    let cluster_size = hdr.cluster_size;
    let cluster_size_usize = cluster_size as usize;
    let refblock_count = staged.refblock_count;

    // Clamp the cluster size to the DATA_A / DATA_B scratch regions
    // before any per-cluster data I/O (bounds the reads/writes below).
    if cluster_size_usize > DATA_A_LIMIT || cluster_size_usize > DATA_B_LIMIT {
        return Err(BitmapResult::ERROR_SCRATCH_TOO_SMALL);
    }

    // One shared AllocCursor + refblocks buffer across every source, so
    // sequential merges into the same dest allocate without collision.
    let mut cursor = AllocCursor::default();

    // ---- CLEAR the autoclear bitmaps bit, fsync -------------------------
    // From here a crash leaves the bitmaps ignorable (autoclear clear).
    rmw_feature_word(
        call_table,
        sector_size,
        AUTOCLEAR_FEATURES_OFFSET as u64,
        |w| w & !AUTOCLEAR_BITMAPS_BIT,
    )?;
    let _ = (call_table.fsync_input)(0);

    // ---- Apply each source merge (data I/O + dest table rewrites) -------
    for k in 0..num_sources {
        let src_name = match merge_source_name(config, k) {
            Some(s) if !s.is_empty() => s,
            _ => return Err(BitmapResult::ERROR_MERGE_SOURCE_NOT_FOUND),
        };
        // Re-validate against the (unchanged) directory to recover the
        // fresh source/dest table offsets for this source.
        let spec = merge_validate(dir, nb_bitmaps, dest_name, src_name, geom).map_err(u32::from)?;
        if spec.self_merge {
            continue; // OR-ing a bitmap into itself changes nothing.
        }
        merge_one_source(
            call_table,
            sector_size,
            cluster_size,
            refblock_count,
            staged.host_refblocks_start,
            spec.source.entry.bitmap_table_offset,
            spec.dest.entry.bitmap_table_offset,
            spec.table_size,
            &mut cursor,
        )?;
    }
    let _ = (call_table.fsync_input)(0);

    // ---- Write the mutated refblocks back, fsync ------------------------
    let rb_offsets = core::slice::from_raw_parts(RB_OFFSETS as *const u64, refblock_count);
    for (k, &host_off) in rb_offsets.iter().enumerate() {
        let src = (REFBLOCKS_BUF + k * cluster_size_usize) as *const u8;
        let block = core::slice::from_raw_parts(src, cluster_size_usize);
        if !write_input_byte_range(call_table, 0, sector_size, host_off, block) {
            return Err(BitmapResult::ERROR_WRITE_FAILED);
        }
    }
    let _ = (call_table.fsync_input)(0);

    // ---- SET the autoclear bit back, fsync ------------------------------
    // Merge never removes the last bitmap, so autoclear is always restored.
    rmw_feature_word(
        call_table,
        sector_size,
        AUTOCLEAR_FEATURES_OFFSET as u64,
        |w| w | AUTOCLEAR_BITMAPS_BIT,
    )?;
    let _ = (call_table.fsync_input)(0);

    Ok(())
}

/// Merge a single source bitmap into the destination, incrementally,
/// one bitmap-table entry at a time.
///
/// Source and dest tables have equal `granularity` and equal
/// `table_size` (`merge_validate` enforces), so index `i` of the
/// source pairs with index `i` of the dest. For each `i` the 8-byte
/// table words are read directly from disk (no whole-table staging —
/// the tables may be multi-cluster) and the [`MergeClusterAction`]
/// applied:
/// - `Skip`: nothing.
/// - `CopyAllOnes`: free any allocated dest data cluster, set the dest
///   table entry to the all-ones sentinel.
/// - `OrIntoExisting`: read source (DATA_A) + dest (DATA_B) data
///   clusters, OR source into dest, write dest back.
/// - `AllocDestFromSource`: allocate a fresh dest data cluster, copy
///   the source data cluster (source bits == the new dest bits since
///   dest was all-zeroes) into it, point the dest table entry at it.
///
/// Dest table-entry rewrites and data writes happen here under the
/// autoclear guard; the refblocks are flushed once by the caller.
///
/// # Safety
///
/// `call_table` must be the validated CallTable; the image is attached
/// input-RW at slot 0. REFBLOCKS_BUF holds `refblock_count` staged
/// blocks; DATA_A / DATA_B are cluster-sized scratch.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn merge_one_source(
    call_table: &CallTable,
    sector_size: usize,
    cluster_size: u64,
    refblock_count: usize,
    host_refblocks_start: u64,
    source_table_offset: u64,
    dest_table_offset: u64,
    table_size: u32,
    cursor: &mut AllocCursor,
) -> Result<(), u32> {
    let cluster_size_usize = cluster_size as usize;
    let epr = entries_per_refblock(cluster_size);
    let lookup = rb_lookup(cluster_size, epr, refblock_count, cluster_size_usize);
    let refblocks = core::slice::from_raw_parts_mut(
        REFBLOCKS_BUF as *mut u8,
        refblock_count * cluster_size_usize,
    );

    for i in 0..table_size as u64 {
        let byte_i = i
            .checked_mul(8)
            .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
        let src_word_off = source_table_offset
            .checked_add(byte_i)
            .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
        let dst_word_off = dest_table_offset
            .checked_add(byte_i)
            .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;

        // Read the two 8-byte table words directly from disk.
        let mut src_buf = [0u8; 8];
        let mut dst_buf = [0u8; 8];
        if !read_input_byte_range(
            call_table,
            0,
            sector_size,
            src_word_off,
            src_buf.as_mut_ptr(),
            8,
        ) {
            return Err(BitmapResult::ERROR_READ_FAILED);
        }
        if !read_input_byte_range(
            call_table,
            0,
            sector_size,
            dst_word_off,
            dst_buf.as_mut_ptr(),
            8,
        ) {
            return Err(BitmapResult::ERROR_READ_FAILED);
        }
        let src_raw = u64::from_be_bytes(src_buf);
        let dst_raw = u64::from_be_bytes(dst_buf);

        let action = merge_cluster_action(src_raw, dst_raw).map_err(u32::from)?;
        match action {
            MergeClusterAction::Skip => {}
            MergeClusterAction::CopyAllOnes => {
                // Free any allocated dest data cluster, then set the
                // dest table entry to the all-ones sentinel.
                if let Some(BitmapTableEntry::Allocated(off)) = decode_bitmap_table_entry(dst_raw) {
                    let (rb_start, entry_local) =
                        lookup(off).ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
                    let block = refblocks
                        .get_mut(rb_start..rb_start + cluster_size_usize)
                        .ok_or(BitmapResult::ERROR_INTERNAL_OVERFLOW)?;
                    if set_refcount_in_block(block, entry_local, 16, 0).is_err() {
                        return Err(BitmapResult::ERROR_INTERNAL_OVERFLOW);
                    }
                }
                let new_entry = encode_bitmap_table_entry(&BitmapTableEntry::AllOnes);
                let bytes = new_entry.to_be_bytes();
                if !write_input_byte_range(call_table, 0, sector_size, dst_word_off, &bytes) {
                    return Err(BitmapResult::ERROR_WRITE_FAILED);
                }
            }
            MergeClusterAction::OrIntoExisting => {
                // Both allocated: read source (DATA_A) + dest (DATA_B),
                // OR source into dest, write dest back. Decode both
                // offsets (validated Allocated by merge_cluster_action).
                let src_off = alloc_offset(src_raw)?;
                let dst_off = alloc_offset(dst_raw)?;
                if !read_input_byte_range(
                    call_table,
                    0,
                    sector_size,
                    src_off,
                    DATA_A as *mut u8,
                    cluster_size_usize,
                ) {
                    return Err(BitmapResult::ERROR_READ_FAILED);
                }
                if !read_input_byte_range(
                    call_table,
                    0,
                    sector_size,
                    dst_off,
                    DATA_B as *mut u8,
                    cluster_size_usize,
                ) {
                    return Err(BitmapResult::ERROR_READ_FAILED);
                }
                let src_data = core::slice::from_raw_parts(DATA_A as *const u8, cluster_size_usize);
                let dst_data =
                    core::slice::from_raw_parts_mut(DATA_B as *mut u8, cluster_size_usize);
                or_bitmap_data(dst_data, src_data).map_err(u32::from)?;
                if !write_input_byte_range(call_table, 0, sector_size, dst_off, dst_data) {
                    return Err(BitmapResult::ERROR_WRITE_FAILED);
                }
            }
            MergeClusterAction::AllocDestFromSource => {
                // Source allocated, dest all-zeroes: allocate a fresh
                // dest data cluster, copy source bits in (they ARE the
                // new dest bits, since dest was zero), point the dest
                // table entry at it.
                let src_off = alloc_offset(src_raw)?;
                let new_off = alloc_contiguous_clusters_in_refblocks(
                    refblocks,
                    cluster_size,
                    16,
                    refblock_count as u64,
                    host_refblocks_start,
                    1,
                    cursor,
                )
                .map_err(alloc_err_to_code)?;
                if !read_input_byte_range(
                    call_table,
                    0,
                    sector_size,
                    src_off,
                    DATA_A as *mut u8,
                    cluster_size_usize,
                ) {
                    return Err(BitmapResult::ERROR_READ_FAILED);
                }
                let src_data = core::slice::from_raw_parts(DATA_A as *const u8, cluster_size_usize);
                if !write_input_byte_range(call_table, 0, sector_size, new_off, src_data) {
                    return Err(BitmapResult::ERROR_WRITE_FAILED);
                }
                let new_entry = encode_bitmap_table_entry(&BitmapTableEntry::Allocated(new_off));
                let bytes = new_entry.to_be_bytes();
                if !write_input_byte_range(call_table, 0, sector_size, dst_word_off, &bytes) {
                    return Err(BitmapResult::ERROR_WRITE_FAILED);
                }
            }
        }
    }
    Ok(())
}

/// Decode a raw table word expected to be `Allocated` and return its
/// host offset. A non-`Allocated` word here is an internal
/// inconsistency (the [`MergeClusterAction`] guaranteed `Allocated`),
/// mapped to `ERROR_INTERNAL_OVERFLOW`.
fn alloc_offset(raw: u64) -> Result<u64, u32> {
    match decode_bitmap_table_entry(raw) {
        Some(BitmapTableEntry::Allocated(off)) => Ok(off),
        _ => Err(BitmapResult::ERROR_INTERNAL_OVERFLOW),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the bitmap operation.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`BitmapConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - Attached the image as an **input read-write** device at slot 0.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "bitmap");
    (call_table.verbose_print)(b"bitmap: start\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const BitmapConfig);
    if !config.is_valid() {
        let result = make_result(config, 0, BitmapResult::ERROR_PARSE_FAILED);
        (call_table.send_bitmap_result)(&result);
        (call_table.send_complete)(b"bitmap\0".as_ptr(), 0, false);
        return 0;
    }

    // v1 is qcow2-only; the host launches the guest only for qcow2,
    // but defend in depth against any other target_format.
    let result = if ImageFormat::from_u32(config.target_format) == ImageFormat::Qcow2 {
        run_qcow2(call_table, config)
    } else {
        make_result(config, 0, BitmapResult::ERROR_UNSUPPORTED_FORMAT)
    };

    let ok = result.error == BitmapResult::ERROR_OK;
    (call_table.send_bitmap_result)(&result);
    (call_table.send_complete)(b"bitmap\0".as_ptr(), 0, ok);
    0
}
