//! Commit operation: merge an overlay's allocated clusters
//! into its backing image.
//!
//! Phase 7 of `PLAN-rebase-commit.md`. Reads a `CommitConfig`
//! from `OPERATION_CONFIG_ADDR`, reads sector 0 of the overlay
//! (input slot 0, opened RW) and sector 0 of the backing (the
//! output device, opened RW), detects each format, dispatches
//! to the matching per-format runner, and reports the outcome
//! via `send_commit_result` + `send_complete`.
//!
//! qcow2 runner (step 7c) walks the overlay's L1 + L2, reads
//! every allocated cluster's data from the overlay via
//! `read_input_sector(0, ...)`, finds (or allocates via the
//! planner) the matching cluster on the backing, writes the
//! data via `write_output_sector`, then runs a batched
//! overlay-clear pass that zeros the overlay's L2 + refcount
//! entries via `write_input_sector(0, ...)`. Step 7d adds the
//! vmdk runner; for now `run_vmdk` is a stub.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use commit::{
    allocate_backing_cluster_qcow2, plan_commit_qcow2, BackingAllocationState, CommitError,
    Qcow2CommitOpts,
};
use qcow2::{
    QcowHeader, INCOMPAT_CORRUPT, INCOMPAT_DIRTY, INCOMPAT_EXTENDED_L2, INCOMPAT_EXTERNAL_DATA,
    L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COMPRESSED, OFLAG_COPIED,
};
use shared::{
    format_detection::detect_format_from_header, validate_call_table, CallTable, CommitConfig,
    CommitResult, ImageFormat, CALL_TABLE_ADDR, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR,
    SCRATCH_MEM_BASE,
};

// ---------------------------------------------------------------------------
// Scratch layout
// ---------------------------------------------------------------------------
//
// Commit stages metadata from both the overlay (input slot 0)
// and the backing (output device) into scratch before the
// per-cluster loop. Eleven regions, sized for a worst-case
// 64 GiB qcow2 with 64 KiB clusters.

const HEADER_BUF: usize = SCRATCH_MEM_BASE;
const BACKING_HEADER_BUF: usize = HEADER_BUF + MAX_SECTOR_SIZE;

const OVERLAY_L1_BUF: usize = BACKING_HEADER_BUF + MAX_SECTOR_SIZE;
const OVERLAY_L1_LIMIT: usize = MAX_SECTOR_SIZE;
const OVERLAY_L2_STAGING: usize = OVERLAY_L1_BUF + OVERLAY_L1_LIMIT;
const OVERLAY_L2_LIMIT: usize = 2 * 1024 * 1024;
const OVERLAY_RT_BUF: usize = OVERLAY_L2_STAGING + OVERLAY_L2_LIMIT;
const OVERLAY_RT_LIMIT: usize = MAX_SECTOR_SIZE;

const BACKING_L1_BUF: usize = OVERLAY_RT_BUF + OVERLAY_RT_LIMIT;
const BACKING_L1_LIMIT: usize = MAX_SECTOR_SIZE;
const BACKING_L2_STAGING: usize = BACKING_L1_BUF + BACKING_L1_LIMIT;
const BACKING_L2_LIMIT: usize = 2 * 1024 * 1024;
const BACKING_RT_BUF: usize = BACKING_L2_STAGING + BACKING_L2_LIMIT;
const BACKING_RT_LIMIT: usize = MAX_SECTOR_SIZE;
const BACKING_RB_OFFSETS: usize = BACKING_RT_BUF + BACKING_RT_LIMIT;
const BACKING_RB_OFFSETS_LIMIT: usize = 16 * 1024;
const BACKING_REFBLOCKS_BUF: usize = BACKING_RB_OFFSETS + BACKING_RB_OFFSETS_LIMIT;
const BACKING_REFBLOCKS_LIMIT: usize = 2 * 1024 * 1024;

const PLANNER_SCRATCH: usize = BACKING_REFBLOCKS_BUF + BACKING_REFBLOCKS_LIMIT;
const PLANNER_SCRATCH_LIMIT: usize = 3 * 1024 * 1024;
const DATA_BUF: usize = PLANNER_SCRATCH + PLANNER_SCRATCH_LIMIT;
const DATA_BUF_LIMIT: usize = 1024 * 1024;

const _: () = assert!(
    DATA_BUF + DATA_BUF_LIMIT <= shared::ALLOC_HEAP_BASE,
    "commit scratch layout overlaps the allocator heap"
);

/// Upper bound on staged L2 tables per side. 256 covers a
/// 128 GiB qcow2 with 64 KiB clusters
/// (`128 GiB / (64 KiB * 8192 entries/L2) = 256`).
const MAX_STAGED_L2: usize = 256;
/// Upper bound on backing refcount blocks (constrained by
/// `BACKING_REFBLOCKS_LIMIT / cluster_size`).
const MAX_REFBLOCKS: usize = 32;

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// ---------------------------------------------------------------------------
// Result construction
// ---------------------------------------------------------------------------

unsafe fn send_result(
    call_table: &CallTable,
    overlay_format: u32,
    backing_format: u32,
    clusters_committed: u64,
    bytes_committed: u64,
    overlay_clusters_cleared: u64,
    error: u32,
) {
    let result = CommitResult {
        magic: CommitResult::MAGIC,
        overlay_format,
        backing_format,
        error,
        clusters_committed,
        bytes_committed,
        overlay_clusters_cleared,
        _reserved: [0; 56],
    };
    (call_table.send_commit_result)(&result);
}

fn err_result(overlay_format: u32, backing_format: u32, error: u32) -> CommitResult {
    CommitResult {
        magic: CommitResult::MAGIC,
        overlay_format,
        backing_format,
        error,
        clusters_committed: 0,
        bytes_committed: 0,
        overlay_clusters_cleared: 0,
        _reserved: [0; 56],
    }
}

/// Map a `CommitError` from the planner crate to the matching
/// `CommitResult::ERROR_*` wire code. Phase 7 step 7a appended
/// codes 8..=13 so every variant has a distinct destination.
fn map_commit_error(e: CommitError) -> u32 {
    match e {
        CommitError::UnsupportedFormat | CommitError::UnsupportedSubformat => {
            CommitResult::ERROR_UNSUPPORTED_FORMAT
        }
        CommitError::ExternalDataFile => CommitResult::ERROR_EXTERNAL_DATA_FILE,
        CommitError::LuksUnsupported => CommitResult::ERROR_LUKS_UNSUPPORTED,
        CommitError::OverlayLargerThanBacking => CommitResult::ERROR_OVERLAY_LARGER_THAN_BACKING,
        CommitError::BackingTooSmall => CommitResult::ERROR_BACKING_TOO_SMALL,
        CommitError::HeaderMismatch => CommitResult::ERROR_HEADER_MISMATCH,
        CommitError::OverlayCorrupt => CommitResult::ERROR_OVERLAY_CORRUPT,
        CommitError::BackingCorrupt => CommitResult::ERROR_BACKING_CORRUPT,
        CommitError::ScratchTooSmall => CommitResult::ERROR_SCRATCH_TOO_SMALL,
        CommitError::RefcountExhausted => CommitResult::ERROR_REFCOUNT_EXHAUSTED,
        CommitError::ParseFailed => CommitResult::ERROR_PARSE_FAILED,
        CommitError::Overflow => CommitResult::ERROR_INTERNAL_OVERFLOW,
    }
}

// ---------------------------------------------------------------------------
// Sector-level I/O helpers
// ---------------------------------------------------------------------------

/// Read `len` bytes from the output device. Handles sub-sector
/// reads via a single-sector bounce buffer at `HEADER_BUF`.
/// Used for staging the backing's metadata.
unsafe fn read_output_byte_range(
    call_table: &CallTable,
    sector_size: usize,
    byte_offset: u64,
    dst_ptr: *mut u8,
    len: usize,
) -> bool {
    if len == 0 {
        return true;
    }
    let bounce_ptr = HEADER_BUF as *mut u8;
    let mut written: usize = 0;
    let mut cur_offset = byte_offset;
    while written < len {
        let sector = cur_offset / sector_size as u64;
        let in_sector_off = (cur_offset % sector_size as u64) as usize;
        let take = (sector_size - in_sector_off).min(len - written);

        if in_sector_off == 0 && take == sector_size {
            let dst = dst_ptr.add(written);
            if !(call_table.read_output_sector)(sector, dst, sector_size) {
                return false;
            }
        } else {
            if !(call_table.read_output_sector)(sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(
                bounce_ptr.add(in_sector_off),
                dst_ptr.add(written),
                take,
            );
        }
        written += take;
        cur_offset += take as u64;
    }
    true
}

/// Write `bytes` to the output device at `byte_offset`.
/// Handles sub-sector writes via read-modify-write through the
/// bounce buffer at `HEADER_BUF`. Used for the backing's
/// cluster data and metadata writes.
unsafe fn write_output_byte_range(
    call_table: &CallTable,
    sector_size: usize,
    byte_offset: u64,
    bytes: &[u8],
) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let bounce_ptr = HEADER_BUF as *mut u8;
    let mut written: usize = 0;
    let mut cur_offset = byte_offset;
    while written < bytes.len() {
        let sector = cur_offset / sector_size as u64;
        let in_sector_off = (cur_offset % sector_size as u64) as usize;
        let take = (sector_size - in_sector_off).min(bytes.len() - written);

        if in_sector_off == 0 && take == sector_size {
            let src = bytes.as_ptr().add(written);
            if !(call_table.write_output_sector)(sector, src, sector_size) {
                return false;
            }
        } else {
            if !(call_table.read_output_sector)(sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(written),
                bounce_ptr.add(in_sector_off),
                take,
            );
            if !(call_table.write_output_sector)(sector, bounce_ptr, sector_size) {
                return false;
            }
        }
        written += take;
        cur_offset += take as u64;
    }
    true
}

/// Read `len` bytes from an input device. Bounce buffer is the
/// tail of `DATA_BUF` (the data buffer is sector-sized in v1's
/// cluster sweep so the tail is always free between reads).
unsafe fn read_input_byte_range(
    call_table: &CallTable,
    device_idx: u32,
    sector_size: usize,
    byte_offset: u64,
    dst_ptr: *mut u8,
    len: usize,
) -> bool {
    if len == 0 {
        return true;
    }
    let bounce_ptr = (DATA_BUF + DATA_BUF_LIMIT - MAX_SECTOR_SIZE) as *mut u8;
    let mut written: usize = 0;
    let mut cur_offset = byte_offset;
    while written < len {
        let sector = cur_offset / sector_size as u64;
        let in_sector_off = (cur_offset % sector_size as u64) as usize;
        let take = (sector_size - in_sector_off).min(len - written);

        if in_sector_off == 0 && take == sector_size {
            let dst = dst_ptr.add(written);
            if !(call_table.read_input_sector)(device_idx, sector, dst, sector_size) {
                return false;
            }
        } else {
            if !(call_table.read_input_sector)(device_idx, sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(
                bounce_ptr.add(in_sector_off),
                dst_ptr.add(written),
                take,
            );
        }
        written += take;
        cur_offset += take as u64;
    }
    true
}

/// Write `bytes` to an input device at `byte_offset` (used for
/// the overlay-clear pass; requires the host to have opened
/// `device_idx` RW). Sub-sector writes go through
/// read-modify-write via the bounce buffer at the tail of
/// `DATA_BUF`.
unsafe fn write_input_byte_range(
    call_table: &CallTable,
    device_idx: u32,
    sector_size: usize,
    byte_offset: u64,
    bytes: &[u8],
) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let bounce_ptr = (DATA_BUF + DATA_BUF_LIMIT - MAX_SECTOR_SIZE) as *mut u8;
    let mut written: usize = 0;
    let mut cur_offset = byte_offset;
    while written < bytes.len() {
        let sector = cur_offset / sector_size as u64;
        let in_sector_off = (cur_offset % sector_size as u64) as usize;
        let take = (sector_size - in_sector_off).min(bytes.len() - written);

        if in_sector_off == 0 && take == sector_size {
            let src = bytes.as_ptr().add(written);
            if !(call_table.write_input_sector)(device_idx, sector, src, sector_size) {
                return false;
            }
        } else {
            if !(call_table.read_input_sector)(device_idx, sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(written),
                bounce_ptr.add(in_sector_off),
                take,
            );
            if !(call_table.write_input_sector)(device_idx, sector, bounce_ptr, sector_size) {
                return false;
            }
        }
        written += take;
        cur_offset += take as u64;
    }
    true
}

// ---------------------------------------------------------------------------
// Per-side L2 staging
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct StagedL2 {
    l1_idx: u32,
    host_offset: u64,
    dirty: bool,
}

fn find_staged_l2(staged: &[StagedL2; MAX_STAGED_L2], count: usize, l1_idx: u32) -> Option<usize> {
    let mut i = 0;
    while i < count {
        if staged[i].l1_idx == l1_idx {
            return Some(i);
        }
        i += 1;
    }
    None
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

fn write_u64_be(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

/// Stage one side's L1 table + every L2 table whose covering
/// L1 entry is non-zero. Reads via the provided callback so
/// the same function works for input slot 0 (the overlay) and
/// the output device (the backing).
///
/// Returns the number of L2 tables staged on success.
unsafe fn stage_side(
    call_table: &CallTable,
    sector_size: usize,
    l1_table_offset: u64,
    l1_size: u32,
    cluster_size_usize: usize,
    l1_ptr: *mut u8,
    l2_staging_base: usize,
    l2_capacity_bytes: usize,
    staged: &mut [StagedL2; MAX_STAGED_L2],
    read_byte_range: impl Fn(u64, *mut u8, usize) -> bool,
) -> Result<usize, CommitError> {
    let l1_size_bytes = (l1_size as usize).saturating_mul(8);
    if l1_size_bytes > OVERLAY_L1_LIMIT {
        return Err(CommitError::ScratchTooSmall);
    }
    if l1_size_bytes > 0 && !read_byte_range(l1_table_offset, l1_ptr, l1_size_bytes) {
        return Err(CommitError::ParseFailed);
    }
    let l1_buf = core::slice::from_raw_parts(l1_ptr, l1_size_bytes);
    let mut count = 0usize;
    let mut cursor = l2_staging_base;
    let cap_end = l2_staging_base + l2_capacity_bytes;
    for i in 0..l1_size as usize {
        let entry = read_u64_be(l1_buf, i * 8);
        let l2_host = entry & L1_OFFSET_MASK;
        if l2_host == 0 {
            continue;
        }
        if count >= MAX_STAGED_L2 || cursor + cluster_size_usize > cap_end {
            return Err(CommitError::ScratchTooSmall);
        }
        if !read_byte_range(l2_host, cursor as *mut u8, cluster_size_usize) {
            return Err(CommitError::ParseFailed);
        }
        staged[count] = StagedL2 {
            l1_idx: i as u32,
            host_offset: l2_host,
            dirty: false,
        };
        count += 1;
        cursor += cluster_size_usize;
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// qcow2 commit runner
// ---------------------------------------------------------------------------

unsafe fn run_qcow2(call_table: &CallTable, config: &CommitConfig) -> CommitResult {
    let sector_size = (call_table.get_output_sector_size)();
    let overlay_header = core::slice::from_raw_parts(HEADER_BUF as *const u8, sector_size);
    let backing_header_slice =
        core::slice::from_raw_parts(BACKING_HEADER_BUF as *const u8, sector_size);

    let overlay = match QcowHeader::parse(overlay_header) {
        Some(p) => p,
        None => return err(config, CommitResult::ERROR_PARSE_FAILED),
    };
    let backing = match QcowHeader::parse(backing_header_slice) {
        Some(p) => p,
        None => return err(config, CommitResult::ERROR_PARSE_FAILED),
    };

    // Validation arms mirror the planner's, with a couple of
    // guest-only constraints layered on top.
    if overlay.dirty || overlay.corrupt {
        return err(config, CommitResult::ERROR_OVERLAY_CORRUPT);
    }
    if backing.dirty || backing.corrupt {
        return err(config, CommitResult::ERROR_BACKING_CORRUPT);
    }
    if overlay.has_external_data
        || (overlay.incompatible_features & INCOMPAT_EXTERNAL_DATA) != 0
        || backing.has_external_data
        || (backing.incompatible_features & INCOMPAT_EXTERNAL_DATA) != 0
    {
        return err(config, CommitResult::ERROR_EXTERNAL_DATA_FILE);
    }
    if (overlay.incompatible_features & (INCOMPAT_DIRTY | INCOMPAT_CORRUPT)) != 0 {
        return err(config, CommitResult::ERROR_OVERLAY_CORRUPT);
    }
    if (backing.incompatible_features & (INCOMPAT_DIRTY | INCOMPAT_CORRUPT)) != 0 {
        return err(config, CommitResult::ERROR_BACKING_CORRUPT);
    }
    if overlay.crypt_method != 0 || backing.crypt_method != 0 {
        return err(config, CommitResult::ERROR_LUKS_UNSUPPORTED);
    }
    // v1 cluster-size match.
    if overlay.cluster_size != backing.cluster_size {
        return err(config, CommitResult::ERROR_UNSUPPORTED_FORMAT);
    }
    // v1 extended-L2 refusal on either side — `entries_per_l2`
    // below assumes 8-byte entries.
    if (overlay.incompatible_features & INCOMPAT_EXTENDED_L2) != 0
        || (backing.incompatible_features & INCOMPAT_EXTENDED_L2) != 0
    {
        return err(config, CommitResult::ERROR_UNSUPPORTED_FORMAT);
    }
    if overlay.refcount_bits != 16 || backing.refcount_bits != 16 {
        return err(config, CommitResult::ERROR_UNSUPPORTED_FORMAT);
    }
    if backing.virtual_size < overlay.virtual_size {
        return err(config, CommitResult::ERROR_OVERLAY_LARGER_THAN_BACKING);
    }

    let cluster_size = overlay.cluster_size;
    let cluster_size_usize = cluster_size as usize;
    if cluster_size_usize > DATA_BUF_LIMIT {
        return err(config, CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }
    let entries_per_l2 = cluster_size / 8;

    // ----- Stage overlay metadata (input slot 0) ------------
    let mut overlay_staged_l2 = [StagedL2 {
        l1_idx: 0,
        host_offset: 0,
        dirty: false,
    }; MAX_STAGED_L2];
    let overlay_staged_count = match stage_side(
        call_table,
        sector_size,
        overlay.l1_table_offset,
        overlay.l1_size,
        cluster_size_usize,
        OVERLAY_L1_BUF as *mut u8,
        OVERLAY_L2_STAGING,
        OVERLAY_L2_LIMIT,
        &mut overlay_staged_l2,
        |off, dst, len| read_input_byte_range(call_table, 0, sector_size, off, dst, len),
    ) {
        Ok(n) => n,
        Err(e) => return err(config, map_commit_error(e)),
    };

    // Overlay refcount table (used by the clear pass to find
    // each refblock's host offset).
    let overlay_rt_size = (overlay.refcount_table_clusters as usize) * cluster_size_usize;
    if overlay_rt_size > OVERLAY_RT_LIMIT {
        return err(config, CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }
    if overlay_rt_size > 0
        && !read_input_byte_range(
            call_table,
            0,
            sector_size,
            overlay.refcount_table_offset,
            OVERLAY_RT_BUF as *mut u8,
            overlay_rt_size,
        )
    {
        return err(config, CommitResult::ERROR_PARSE_FAILED);
    }

    // ----- Stage backing metadata (output device) -----------
    let mut backing_staged_l2 = [StagedL2 {
        l1_idx: 0,
        host_offset: 0,
        dirty: false,
    }; MAX_STAGED_L2];
    let mut backing_staged_count = match stage_side(
        call_table,
        sector_size,
        backing.l1_table_offset,
        backing.l1_size,
        cluster_size_usize,
        BACKING_L1_BUF as *mut u8,
        BACKING_L2_STAGING,
        BACKING_L2_LIMIT,
        &mut backing_staged_l2,
        |off, dst, len| read_output_byte_range(call_table, sector_size, off, dst, len),
    ) {
        Ok(n) => n,
        Err(e) => return err(config, map_commit_error(e)),
    };

    let backing_rt_size = (backing.refcount_table_clusters as usize) * cluster_size_usize;
    if backing_rt_size > BACKING_RT_LIMIT {
        return err(config, CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }
    if backing_rt_size > 0
        && !read_output_byte_range(
            call_table,
            sector_size,
            backing.refcount_table_offset,
            BACKING_RT_BUF as *mut u8,
            backing_rt_size,
        )
    {
        return err(config, CommitResult::ERROR_PARSE_FAILED);
    }
    let backing_rt = core::slice::from_raw_parts(BACKING_RT_BUF as *const u8, backing_rt_size);

    // Walk the backing's refcount table to collect the list of
    // refblock host offsets, then stage each refblock.
    let mut refblock_count: usize = 0;
    {
        let mut i = 0;
        while i + 8 <= backing_rt_size {
            if read_u64_be(backing_rt, i) != 0 {
                refblock_count += 1;
            }
            i += 8;
        }
    }
    if refblock_count > MAX_REFBLOCKS {
        return err(config, CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }
    let rb_offsets_ptr = BACKING_RB_OFFSETS as *mut u64;
    let rb_offsets = core::slice::from_raw_parts_mut(rb_offsets_ptr, refblock_count);
    {
        let mut i = 0;
        let mut out = 0;
        while i + 8 <= backing_rt_size {
            let entry = read_u64_be(backing_rt, i);
            if entry != 0 {
                rb_offsets[out] = entry;
                out += 1;
            }
            i += 8;
        }
    }
    let backing_rb_total_bytes = refblock_count.saturating_mul(cluster_size_usize);
    if backing_rb_total_bytes > BACKING_REFBLOCKS_LIMIT {
        return err(config, CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }
    for (i, host_off) in rb_offsets.iter().copied().enumerate() {
        let dst = (BACKING_REFBLOCKS_BUF + i * cluster_size_usize) as *mut u8;
        if !read_output_byte_range(call_table, sector_size, host_off, dst, cluster_size_usize) {
            return err(config, CommitResult::ERROR_PARSE_FAILED);
        }
    }
    let backing_rb_buf =
        core::slice::from_raw_parts(BACKING_REFBLOCKS_BUF as *const u8, backing_rb_total_bytes);

    // ----- Plan ---------------------------------------------
    let capacity_sectors_backing = (call_table.get_output_capacity)();
    let backing_file_size = capacity_sectors_backing.saturating_mul(sector_size as u64);
    let opts = Qcow2CommitOpts {
        overlay_header,
        overlay_file_size: (call_table.get_input_capacity)(0).saturating_mul(sector_size as u64),
        backing_header: backing_header_slice,
        backing_file_size,
        backing_refcount_table: backing_rt,
        backing_refblock_host_offsets: rb_offsets,
        backing_refcount_blocks: backing_rb_buf,
        backing_refblock_count: refblock_count as u32,
    };
    let planner_scratch =
        core::slice::from_raw_parts_mut(PLANNER_SCRATCH as *mut u8, PLANNER_SCRATCH_LIMIT);
    let mut ctx = match plan_commit_qcow2(&opts, planner_scratch) {
        Ok(c) => c,
        Err(e) => return err(config, map_commit_error(e)),
    };

    // ----- Per-cluster commit loop --------------------------
    let mut state = BackingAllocationState::default();
    let mut clusters_committed: u64 = 0;
    let mut bytes_committed: u64 = 0;
    let mut backing_l1_dirty = false;
    let mut backing_l2_slots_used = backing_staged_count;
    let l2_slot_capacity = BACKING_L2_LIMIT / cluster_size_usize;

    let overlay_l1_buf =
        core::slice::from_raw_parts(OVERLAY_L1_BUF as *const u8, (overlay.l1_size as usize) * 8);
    let backing_l1_buf =
        core::slice::from_raw_parts_mut(BACKING_L1_BUF as *mut u8, (backing.l1_size as usize) * 8);

    let data_buf = DATA_BUF as *mut u8;

    for cluster_idx in 0..ctx.overlay_cluster_count {
        let l1_idx = cluster_idx / entries_per_l2;
        let l2_inner_idx = (cluster_idx % entries_per_l2) as usize;
        if l1_idx >= overlay.l1_size as u64 {
            break;
        }
        let l1_idx_usize = l1_idx as usize;

        // Decode overlay L2 entry.
        let overlay_l1_entry = read_u64_be(overlay_l1_buf, l1_idx_usize * 8);
        if (overlay_l1_entry & L1_OFFSET_MASK) == 0 {
            continue;
        }
        let overlay_slot =
            match find_staged_l2(&overlay_staged_l2, overlay_staged_count, l1_idx as u32) {
                Some(s) => s,
                None => return err(config, CommitResult::ERROR_HEADER_MISMATCH),
            };
        let overlay_l2_slice = core::slice::from_raw_parts(
            (OVERLAY_L2_STAGING + overlay_slot * cluster_size_usize) as *const u8,
            cluster_size_usize,
        );
        let overlay_l2_entry = read_u64_be(overlay_l2_slice, l2_inner_idx * 8);
        if overlay_l2_entry == 0 {
            continue;
        }
        if overlay_l2_entry & OFLAG_COMPRESSED != 0 {
            return err(config, CommitResult::ERROR_UNSUPPORTED_FORMAT);
        }
        let overlay_host_offset = overlay_l2_entry & L2_OFFSET_MASK;
        if overlay_host_offset == 0 {
            continue;
        }

        // Read the overlay cluster's data.
        if !read_input_byte_range(
            call_table,
            0,
            sector_size,
            overlay_host_offset,
            data_buf,
            cluster_size_usize,
        ) {
            return err(config, CommitResult::ERROR_PARSE_FAILED);
        }

        // Decode backing L2 (allocating an L2 table if the
        // backing L1 entry is zero).
        let backing_l1_entry = read_u64_be(backing_l1_buf, l1_idx_usize * 8);
        let backing_l2_host = backing_l1_entry & L1_OFFSET_MASK;
        let target_backing_slot;
        if backing_l2_host != 0 {
            target_backing_slot =
                match find_staged_l2(&backing_staged_l2, backing_staged_count, l1_idx as u32) {
                    Some(s) => s,
                    None => return err(config, CommitResult::ERROR_HEADER_MISMATCH),
                };
        } else {
            // Allocate a fresh L2 table on the backing.
            if backing_staged_count >= MAX_STAGED_L2 || backing_l2_slots_used >= l2_slot_capacity {
                return err(config, CommitResult::ERROR_SCRATCH_TOO_SMALL);
            }
            let new_l2_host = match allocate_backing_cluster_qcow2(&mut ctx, &mut state) {
                Ok(off) => off,
                Err(e) => return err(config, map_commit_error(e)),
            };
            // Zero the freshly-claimed L2 table in scratch.
            let new_slot = backing_l2_slots_used;
            core::ptr::write_bytes(
                (BACKING_L2_STAGING + new_slot * cluster_size_usize) as *mut u8,
                0,
                cluster_size_usize,
            );
            backing_staged_l2[backing_staged_count] = StagedL2 {
                l1_idx: l1_idx as u32,
                host_offset: new_l2_host,
                dirty: true,
            };
            backing_staged_count += 1;
            backing_l2_slots_used += 1;
            // Update backing L1.
            write_u64_be(backing_l1_buf, l1_idx_usize * 8, new_l2_host | OFLAG_COPIED);
            backing_l1_dirty = true;
            target_backing_slot = new_slot;
        }

        // Find (or allocate) a backing cluster for this guest
        // offset.
        let backing_l2_byte = target_backing_slot * cluster_size_usize + l2_inner_idx * 8;
        let backing_l2_entry = {
            let slice = core::slice::from_raw_parts(
                (BACKING_L2_STAGING + target_backing_slot * cluster_size_usize) as *const u8,
                cluster_size_usize,
            );
            read_u64_be(slice, l2_inner_idx * 8)
        };
        let backing_data_host = if (backing_l2_entry & L2_OFFSET_MASK) != 0 {
            backing_l2_entry & L2_OFFSET_MASK
        } else {
            let off = match allocate_backing_cluster_qcow2(&mut ctx, &mut state) {
                Ok(off) => off,
                Err(e) => return err(config, map_commit_error(e)),
            };
            let l2_slice = core::slice::from_raw_parts_mut(
                BACKING_L2_STAGING as *mut u8,
                backing_l2_slots_used * cluster_size_usize,
            );
            write_u64_be(l2_slice, backing_l2_byte, off | OFLAG_COPIED);
            backing_staged_l2[target_backing_slot].dirty = true;
            off
        };

        // Write the cluster's data into the backing.
        let data_slice = core::slice::from_raw_parts(data_buf, cluster_size_usize);
        if !write_output_byte_range(call_table, sector_size, backing_data_host, data_slice) {
            return err(config, CommitResult::ERROR_HEADER_MISMATCH);
        }

        clusters_committed += 1;
        bytes_committed = bytes_committed.saturating_add(cluster_size);
    }

    // ----- Flush dirty backing metadata --------------------
    // Order: backing L2 → backing L1 (if grown) → backing
    // refcount blocks. Mirrors the master plan's atomicity
    // section: every reachable backing cluster's content is
    // durable before any pointer that makes it reachable.
    for i in 0..backing_staged_count {
        if !backing_staged_l2[i].dirty {
            continue;
        }
        let slice = core::slice::from_raw_parts(
            (BACKING_L2_STAGING + i * cluster_size_usize) as *const u8,
            cluster_size_usize,
        );
        if !write_output_byte_range(
            call_table,
            sector_size,
            backing_staged_l2[i].host_offset,
            slice,
        ) {
            return err(config, CommitResult::ERROR_HEADER_MISMATCH);
        }
    }
    if backing_l1_dirty
        && !write_output_byte_range(
            call_table,
            sector_size,
            backing.l1_table_offset,
            backing_l1_buf,
        )
    {
        return err(config, CommitResult::ERROR_HEADER_MISMATCH);
    }
    for i in 0..refblock_count {
        let byte = i / 8;
        let bit = i % 8;
        let is_dirty = ctx
            .backing_dirty
            .get(byte)
            .map(|b| (b & (1u8 << bit)) != 0)
            .unwrap_or(false);
        if !is_dirty {
            continue;
        }
        let slice = &ctx.backing_refblocks[i * cluster_size_usize..(i + 1) * cluster_size_usize];
        if !write_output_byte_range(call_table, sector_size, rb_offsets[i], slice) {
            return err(config, CommitResult::ERROR_HEADER_MISMATCH);
        }
    }

    // ----- Overlay-clear pass ------------------------------
    // Re-walk the overlay's allocated clusters and zero each
    // L2 entry + refcount entry via `write_input_sector`. We
    // know nothing has mutated the staged overlay L1 / L2
    // bytes during the data loop, so this is a straight
    // re-traversal.
    let overlay_rt = core::slice::from_raw_parts(OVERLAY_RT_BUF as *const u8, overlay_rt_size);
    let overlay_entries_per_refblock = ctx.overlay_entries_per_refblock;
    let mut overlay_clusters_cleared: u64 = 0;
    let zeros_8 = [0u8; 8];
    let zeros_2 = [0u8; 2];
    for cluster_idx in 0..ctx.overlay_cluster_count {
        let l1_idx = cluster_idx / entries_per_l2;
        let l2_inner_idx = (cluster_idx % entries_per_l2) as usize;
        if l1_idx >= overlay.l1_size as u64 {
            break;
        }
        let l1_idx_usize = l1_idx as usize;
        let overlay_l1_entry = read_u64_be(overlay_l1_buf, l1_idx_usize * 8);
        let overlay_l2_host = overlay_l1_entry & L1_OFFSET_MASK;
        if overlay_l2_host == 0 {
            continue;
        }
        let slot = match find_staged_l2(&overlay_staged_l2, overlay_staged_count, l1_idx as u32) {
            Some(s) => s,
            None => continue,
        };
        let l2_slice = core::slice::from_raw_parts(
            (OVERLAY_L2_STAGING + slot * cluster_size_usize) as *const u8,
            cluster_size_usize,
        );
        let overlay_l2_entry = read_u64_be(l2_slice, l2_inner_idx * 8);
        if overlay_l2_entry == 0 || overlay_l2_entry & OFLAG_COMPRESSED != 0 {
            continue;
        }
        let overlay_host_offset = overlay_l2_entry & L2_OFFSET_MASK;
        if overlay_host_offset == 0 {
            continue;
        }

        // Zero the overlay's L2 entry.
        let l2_byte_offset = overlay_l2_host + (l2_inner_idx as u64) * 8;
        if !write_input_byte_range(call_table, 0, sector_size, l2_byte_offset, &zeros_8) {
            return err(config, CommitResult::ERROR_HEADER_MISMATCH);
        }

        // Zero the overlay's refcount entry. 16-bit width
        // only in v1.
        let cluster_in_overlay = overlay_host_offset / cluster_size;
        let refblock_idx = cluster_in_overlay / overlay_entries_per_refblock;
        let entry_in_refblock = cluster_in_overlay % overlay_entries_per_refblock;
        let rt_idx = (refblock_idx as usize) * 8;
        if rt_idx + 8 > overlay_rt_size {
            return err(config, CommitResult::ERROR_OVERLAY_CORRUPT);
        }
        let refblock_host = read_u64_be(overlay_rt, rt_idx) & L1_OFFSET_MASK;
        if refblock_host == 0 {
            return err(config, CommitResult::ERROR_OVERLAY_CORRUPT);
        }
        let rc_byte = refblock_host + entry_in_refblock * 2;
        if !write_input_byte_range(call_table, 0, sector_size, rc_byte, &zeros_2) {
            return err(config, CommitResult::ERROR_HEADER_MISMATCH);
        }

        overlay_clusters_cleared += 1;
    }

    // ----- Defensive backing-header re-read -----------------
    let mut redo = [0u8; MAX_SECTOR_SIZE];
    if !(call_table.read_output_sector)(0, redo.as_mut_ptr(), sector_size) {
        return err(config, CommitResult::ERROR_HEADER_MISMATCH);
    }
    let redo_parsed = match QcowHeader::parse(&redo[..sector_size]) {
        Some(p) => p,
        None => return err(config, CommitResult::ERROR_HEADER_MISMATCH),
    };
    if redo_parsed.virtual_size != backing.virtual_size
        || redo_parsed.cluster_size != backing.cluster_size
        || redo_parsed.l1_table_offset != backing.l1_table_offset
    {
        return err(config, CommitResult::ERROR_HEADER_MISMATCH);
    }

    CommitResult {
        magic: CommitResult::MAGIC,
        overlay_format: config.overlay_format,
        backing_format: config.backing_format,
        error: CommitResult::ERROR_OK,
        clusters_committed,
        bytes_committed,
        overlay_clusters_cleared,
        _reserved: [0; 56],
    }
}

fn err(config: &CommitConfig, error: u32) -> CommitResult {
    err_result(config.overlay_format, config.backing_format, error)
}

/// vmdk commit runner. Step 7d stub.
unsafe fn run_vmdk(_call_table: &CallTable, config: &CommitConfig) -> CommitResult {
    err_result(
        config.overlay_format,
        config.backing_format,
        CommitResult::ERROR_UNSUPPORTED_FORMAT,
    )
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the commit operation.
///
/// # Safety
///
/// Called by the core binary after it has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`CommitConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - Attached the backing as the output device (opened RW).
/// - Attached the overlay at input slot 0 (opened RW so the
///   guest can use `write_input_sector(0, ...)` for the
///   overlay-clear pass).
/// - Optionally attached the backing's own ancestor chain at
///   input slots `[config.backing_chain_first,
///   config.backing_chain_first + config.backing_chain_count)`
///   (v1 ignores these slots).
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "commit");
    (call_table.verbose_print)(b"commit: start\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const CommitConfig);
    if !config.is_valid() {
        send_result(
            call_table,
            ImageFormat::Unknown as u32,
            ImageFormat::Unknown as u32,
            0,
            0,
            0,
            CommitResult::ERROR_PARSE_FAILED,
        );
        (call_table.send_complete)(b"commit\0".as_ptr(), 0, false);
        return 0;
    }

    let sector_size = (call_table.get_output_sector_size)();

    if !(call_table.read_input_sector)(0, 0, HEADER_BUF as *mut u8, sector_size) {
        send_result(
            call_table,
            config.overlay_format,
            config.backing_format,
            0,
            0,
            0,
            CommitResult::ERROR_PARSE_FAILED,
        );
        (call_table.send_complete)(b"commit\0".as_ptr(), 0, false);
        return 0;
    }
    if !(call_table.read_output_sector)(0, BACKING_HEADER_BUF as *mut u8, sector_size) {
        send_result(
            call_table,
            config.overlay_format,
            config.backing_format,
            0,
            0,
            0,
            CommitResult::ERROR_PARSE_FAILED,
        );
        (call_table.send_complete)(b"commit\0".as_ptr(), 0, false);
        return 0;
    }
    let overlay_header = core::slice::from_raw_parts(HEADER_BUF as *const u8, sector_size);
    let overlay_format = detect_format_from_header(overlay_header, sector_size, false);

    let result = match overlay_format {
        ImageFormat::Qcow2 => run_qcow2(call_table, config),
        ImageFormat::Vmdk4 => run_vmdk(call_table, config),
        _ => err_result(
            config.overlay_format,
            config.backing_format,
            CommitResult::ERROR_UNSUPPORTED_FORMAT,
        ),
    };

    let ok = result.error == CommitResult::ERROR_OK;
    (call_table.send_commit_result)(&result);
    (call_table.send_complete)(b"commit\0".as_ptr(), 0, ok);
    0
}
