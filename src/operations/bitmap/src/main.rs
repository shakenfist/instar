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
//! **This is step 4b: header read + gates + host cross-check +
//! staging.** `run_qcow2` now reads the full header cluster, parses
//! the header and the bitmaps extension, runs the refuse-before-any-
//! write gate battery (Mission §2), cross-checks the host-probed
//! [`BitmapConfig`] fields against the guest's own re-parse, and
//! stages the bitmaps directory + refcount table + refblocks into
//! scratch. It STILL returns a placeholder result
//! (`ERROR_UNSUPPORTED_ACTION`, no actions applied) — the action
//! loop (4c) and the merge orchestration (4d) fill in the mutation.
//! Non-qcow2 targets are refused with `ERROR_UNSUPPORTED_FORMAT`
//! (v1 is qcow2-only).
//!
//! Device idiom (Phase 5 host, mirrored here): the image is attached
//! **input read-write** at slot 0, so the runner reads/writes via
//! `read_input_sector(0, ..)` / `write_input_sector(0, ..)` /
//! `fsync_input(0)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use qcow2::{
    parse_header_extensions, QcowHeader, AUTOCLEAR_FEATURES_OFFSET, INCOMPAT_CORRUPT,
    INCOMPAT_DIRTY, L1_OFFSET_MASK,
};
use shared::{
    validate_call_table, BitmapConfig, BitmapResult, CallTable, ImageFormat, ALLOC_HEAP_BASE,
    CALL_TABLE_ADDR, MAX_CLUSTER_SIZE, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
};

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
/// Retained for 4c/4d (the write-back + autoclear dance); unused in
/// 4b, which never writes. Marked `#[allow(dead_code)]` so the 4b
/// build stays warning-clean without deleting the helper the later
/// steps depend on.
///
/// # Safety
///
/// `call_table` must be the validated CallTable.
#[allow(dead_code)]
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
    if rt_size > RT_LIMIT {
        return Err(BitmapResult::ERROR_SCRATCH_TOO_SMALL);
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
        return Err(BitmapResult::ERROR_READ_FAILED);
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
///
/// Retained for 4c/4d; unused in 4b. `#[allow(dead_code)]` keeps the
/// 4b build warning-clean.
#[allow(dead_code)]
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
/// **Step 4b.** Reads the full header cluster, parses the header and
/// bitmaps extension, runs the gate battery (Mission §2) — refusing
/// *before any write* so a refusal leaves the image byte-identical —
/// cross-checks the host-probed [`BitmapConfig`] fields against the
/// guest's own re-parse, and stages the bitmaps directory + refcount
/// table + refblocks into scratch. It then returns a placeholder
/// `ERROR_UNSUPPORTED_ACTION` result: the action loop (4c) and the
/// merge orchestration (4d) replace that with real mutation.
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
    let _ = staged;

    // --- Placeholder result (4c/4d replace this) -------------------------
    //
    // 4c: run the action loop here using the staged DIR_A + REFBLOCKS_BUF
    // (double-buffering DIR_A<->DIR_B, threading one AllocCursor), then
    // the write-back + autoclear dance. Until then, staging is exercised
    // structurally but no action is applied and the image is untouched.
    make_result(config, 0, BitmapResult::ERROR_UNSUPPORTED_ACTION)
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
