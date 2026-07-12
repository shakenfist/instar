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
//! qcow2 runner (step 7c, re-composed by phase 4 of
//! `PLAN-qcow2-write-infrastructure`) walks the overlay's L1 +
//! L2 and reads every allocated cluster's data from the overlay
//! via `read_input_sector(0, ...)` exactly as before; the
//! backing side is planned per overlay cluster by
//! `qcow2_write::plan_write` (allocation, classification
//! refusals, L2 window management) and executed literally by
//! `qcow2_write_exec::execute`, with one `plan_flush` epoch
//! replacing the inline L2 → L1 → refblock flush. The batched
//! overlay-clear pass that zeros the overlay's L2 + refcount
//! entries via `write_input_sector(0, ...)` is untouched, as is
//! the whole vmdk runner (step 7d).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use commit::{
    allocate_backing_grain_vmdk, plan_commit_qcow2, plan_commit_vmdk, BackingGrainAllocationState,
    CommitError, Qcow2CommitOpts, VmdkCommitOpts,
};
use qcow2::{
    QcowHeader, INCOMPAT_CORRUPT, INCOMPAT_DIRTY, INCOMPAT_EXTENDED_L2, INCOMPAT_EXTERNAL_DATA,
    L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COMPRESSED,
};
use qcow2_write::{
    check_envelope, new_state, plan_flush, plan_write, DataSource, Gate, RegionId, StagedRegions,
    StagingConfig, Step, StepBuf, StepKind, TargetDevice, WriteError, WriteState, MAX_L2_SLOTS,
};
use qcow2_write_exec::{execute, CallTableIo, Regions};
use shared::{
    format_detection::detect_format_from_header, validate_call_table, CallTable, CommitConfig,
    CommitResult, ImageFormat, CALL_TABLE_ADDR, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR,
    SCRATCH_MEM_BASE,
};
use vmdk::{Vmdk4HeaderFull, FLAG_COMPRESSED};

// ---------------------------------------------------------------------------
// Scratch layout
// ---------------------------------------------------------------------------
//
// Commit stages metadata from both the overlay (input slot 0)
// and the backing (output device) into scratch before the
// per-cluster loop. Fixed regions only, each derived from the
// previous one's end (the c84743e ordering discipline); the
// whole ladder is const-asserted below the allocator heap.
//
// The overlay side (L1 + eagerly staged L2s + refcount table)
// is unchanged from phase 7 of PLAN-rebase-commit. The backing
// side is the phase-4 qcow2-write carve: staged L1, staged
// refcount table, staged refblocks as a dense prefix from host
// cluster 0 (single copy — the planner mutates it in place),
// a fixed-slot L2 window, the step buffer, the planner bounce
// region and the executor's RMW/fill service sectors. The old
// `PLANNER_SCRATCH` region (the 3 MiB duplicate refblock copy
// plan_commit_qcow2 carved) is retained only for the vmdk
// runner, whose planner still carves its backing GD/GT copies
// from it.

const HEADER_BUF: usize = SCRATCH_MEM_BASE;
const BACKING_HEADER_BUF: usize = HEADER_BUF + MAX_SECTOR_SIZE;

const OVERLAY_L1_BUF: usize = BACKING_HEADER_BUF + MAX_SECTOR_SIZE;
const OVERLAY_L1_LIMIT: usize = MAX_SECTOR_SIZE;
const OVERLAY_L2_STAGING: usize = OVERLAY_L1_BUF + OVERLAY_L1_LIMIT;
const OVERLAY_L2_LIMIT: usize = 2 * 1024 * 1024;
const OVERLAY_RT_BUF: usize = OVERLAY_L2_STAGING + OVERLAY_L2_LIMIT;
const OVERLAY_RT_LIMIT: usize = MAX_SECTOR_SIZE;

/// Staged backing L1 table (`RegionId::L1`).
const BACKING_L1_BUF: usize = OVERLAY_RT_BUF + OVERLAY_RT_LIMIT;
const BACKING_L1_LIMIT: usize = MAX_SECTOR_SIZE;
/// Backing L2 window (`RegionId::L2Slot`) for the qcow2 runner:
/// `min(MAX_L2_SLOTS, BACKING_L2_LIMIT / cluster_size)` slots
/// (>= 2 slots at the 1 MiB cluster envelope enforced by the
/// `DATA_BUF_LIMIT` gate). The vmdk runner reuses the region as
/// its backing grain-table staging, exactly as before.
const BACKING_L2_STAGING: usize = BACKING_L1_BUF + BACKING_L1_LIMIT;
const BACKING_L2_LIMIT: usize = 2 * 1024 * 1024;
/// Staged backing refcount table (`RegionId::RefcountTable`).
const BACKING_RT_BUF: usize = BACKING_L2_STAGING + BACKING_L2_LIMIT;
const BACKING_RT_LIMIT: usize = MAX_SECTOR_SIZE;
/// Grain-table host-offset arrays for the vmdk runner (the
/// qcow2 runner no longer needs refblock offsets — plan_flush
/// reads them from the staged refcount table).
const BACKING_RB_OFFSETS: usize = BACKING_RT_BUF + BACKING_RT_LIMIT;
const BACKING_RB_OFFSETS_LIMIT: usize = 16 * 1024;
/// Staged backing refblocks (`RegionId::Refblocks`), a dense
/// prefix covering host clusters from zero. Capacity per
/// phase-4 decision 5: byte-capacity-driven with the
/// `qcow2_write::MAX_REFBLOCKS` (2048) count cap on top —
/// strictly wider than the old 32-refblock cap on every
/// cluster size (48 refblocks at 64 KiB clusters, the count
/// cap below ~1.5 KiB clusters).
const BACKING_REFBLOCKS_BUF: usize = BACKING_RB_OFFSETS + BACKING_RB_OFFSETS_LIMIT;
const BACKING_REFBLOCKS_LIMIT: usize = 3 * 1024 * 1024;

/// vmdk planner scratch (backing GD + GT copies + dirty maps;
/// bounded by the staging limits at ~2.1 MiB worst case). The
/// qcow2 runner no longer uses this region — its refblocks are
/// staged once and mutated in place by the qcow2-write planner.
const PLANNER_SCRATCH: usize = BACKING_REFBLOCKS_BUF + BACKING_REFBLOCKS_LIMIT;
const PLANNER_SCRATCH_LIMIT: usize = 2 * 1024 * 1024 + 256 * 1024;

/// Step window for the qcow2-write planner, carved as
/// `[Step; STEP_CAPACITY]` (scratch-carved, never `static` —
/// the `.bss`/HEADER_MISMATCH hazard class).
const STEP_BUF: usize = PLANNER_SCRATCH + PLANNER_SCRATCH_LIMIT;
const STEP_BUF_LIMIT: usize = 64 * 1024;
const STEP_CAPACITY: usize = STEP_BUF_LIMIT / core::mem::size_of::<Step>();

/// Cluster-sized planner bounce region (`RegionId::Bounce`).
/// v1 step programs only name it as a filler, but the region
/// must exist and cover a full cluster.
const PLANNER_BOUNCE: usize = STEP_BUF + STEP_BUF_LIMIT;
const PLANNER_BOUNCE_LIMIT: usize = 1024 * 1024;

/// Overlay cluster data (`RegionId::CallerData`); the tail
/// doubles as the input-side sub-sector bounce, as before.
const DATA_BUF: usize = PLANNER_BOUNCE + PLANNER_BOUNCE_LIMIT;
const DATA_BUF_LIMIT: usize = 1024 * 1024;

/// Sector-sized bounce buffer used by `read_output_byte_range`
/// and `write_output_byte_range` for sub-sector accesses on
/// the output device. Located off `HEADER_BUF` /
/// `BACKING_HEADER_BUF` so backing metadata reads don't
/// clobber the stable overlay-header slice that
/// `plan_commit_qcow2` re-parses.
const OUTPUT_BOUNCE: usize = DATA_BUF + DATA_BUF_LIMIT;
const OUTPUT_BOUNCE_LIMIT: usize = MAX_SECTOR_SIZE;

/// Executor service buffer: sub-sector RMW bounce.
const RMW_SECTOR: usize = OUTPUT_BOUNCE + OUTPUT_BOUNCE_LIMIT;
const RMW_SECTOR_LIMIT: usize = MAX_SECTOR_SIZE;
/// Executor service buffer: ZeroRange/FillRange synthesis.
const FILL_SECTOR: usize = RMW_SECTOR + RMW_SECTOR_LIMIT;
const FILL_SECTOR_LIMIT: usize = MAX_SECTOR_SIZE;

const _: () = assert!(
    FILL_SECTOR + FILL_SECTOR_LIMIT <= shared::ALLOC_HEAP_BASE,
    "commit scratch layout overlaps the allocator heap"
);
const _: () = assert!(
    STEP_BUF % core::mem::align_of::<Step>() == 0,
    "step buffer must be aligned for [Step; N]"
);
const _: () = assert!(
    STEP_CAPACITY >= 512,
    "step window unexpectedly small; the decision-1 loop assumes 1300+ steps"
);
// At the largest cluster commit accepts (DATA_BUF_LIMIT), the
// planner bounce still covers a whole cluster and the L2 window
// still has at least two slots.
const _: () = assert!(PLANNER_BOUNCE_LIMIT >= DATA_BUF_LIMIT);
const _: () = assert!(BACKING_L2_LIMIT / DATA_BUF_LIMIT >= 2);

/// Upper bound on staged L2 tables per side. 256 covers a
/// 128 GiB qcow2 with 64 KiB clusters
/// (`128 GiB / (64 KiB * 8192 entries/L2) = 256`).
const MAX_STAGED_L2: usize = 256;

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

/// Map a `qcow2_write::Gate` envelope refusal on the BACKING
/// header to a `CommitResult::ERROR_*` wire code (phase-4
/// decision 6). Every gate that duplicates an existing op gate
/// keeps that gate's code — and is unreachable in practice
/// because the op gates run first, in their existing order. The
/// one genuinely new refusal family is
/// [`Gate::UnknownIncompatible`] (the zstd compression-type bit
/// or any unknown incompatible bit): commit previously proceeded
/// in violation of the qcow2 spec (divergence D1).
fn map_backing_gate(gate: Gate) -> u32 {
    match gate {
        Gate::UnknownIncompatible => CommitResult::ERROR_BACKING_UNSUPPORTED,
        Gate::RefcountWidth | Gate::ExtendedL2 => CommitResult::ERROR_UNSUPPORTED_FORMAT,
        Gate::ExternalDataFile => CommitResult::ERROR_EXTERNAL_DATA_FILE,
        Gate::Encryption => CommitResult::ERROR_LUKS_UNSUPPORTED,
        Gate::DirtyCorrupt => CommitResult::ERROR_BACKING_CORRUPT,
        Gate::HasSnapshots => CommitResult::ERROR_BACKING_HAS_SNAPSHOTS,
        // QcowHeader::parse cannot yield other versions; defends
        // direct construction.
        Gate::UnsupportedVersion => CommitResult::ERROR_PARSE_FAILED,
        // Caller-config refusal: the op built an out-of-range
        // StagingConfig (an op bug, not an image property).
        Gate::InvalidStagingConfig => CommitResult::ERROR_SCRATCH_TOO_SMALL,
    }
}

/// Map a `qcow2_write::WriteError` from `plan_write` /
/// `plan_flush` to a `CommitResult::ERROR_*` wire code (phase-4
/// decision 6). `BufFull` is the windowing resume signal, never
/// surfaced as an error — the driving loop consumes it; it only
/// lands here if the loop is broken (an op bug).
fn map_write_error(e: WriteError) -> u32 {
    match e {
        // The allocator ran out of staged refblocks; phase 6's
        // refcount-growth planner lifts this. Keeps wire 11.
        WriteError::RefcountExhausted => CommitResult::ERROR_REFCOUNT_EXHAUSTED,
        // Compressed backing L2 entry: the code the overlay side
        // already uses for compressed entries. Before phase 4
        // this shape was silently corrupted (divergence D2).
        WriteError::CompressedCluster => CommitResult::ERROR_UNSUPPORTED_FORMAT,
        // Classification refusals on inconsistent-but-gate-passing
        // backings (divergences D3/D4). NeedsBackingFill is
        // unreachable for commit's full-cluster (EOV-tail-clamped)
        // requests after the 4q amendment; mapped here
        // defensively.
        WriteError::SnapshotShared
        | WriteError::SnapshotSharedL2Table
        | WriteError::RefcountInconsistent
        | WriteError::RefcountCoverage
        | WriteError::UnknownL1Entry
        | WriteError::UnknownL2Entry
        | WriteError::StagedRegionsMismatch
        | WriteError::NeedsBackingFill => CommitResult::ERROR_BACKING_INCONSISTENT,
        // Planner-protocol misuse or bounds violations indicate
        // an op bug, not an image property — the same family as
        // the guest-side arithmetic checks.
        WriteError::BufFull
        | WriteError::NotImplemented
        | WriteError::OutOfBounds
        | WriteError::ResumeMismatch => CommitResult::ERROR_INTERNAL_OVERFLOW,
    }
}

// ---------------------------------------------------------------------------
// Sector-level I/O helpers
// ---------------------------------------------------------------------------

/// Read `len` bytes from the output device. Handles sub-sector
/// reads via a single-sector bounce buffer at `OUTPUT_BOUNCE`.
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
    let bounce_ptr = OUTPUT_BOUNCE as *mut u8;
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
/// bounce buffer at `OUTPUT_BOUNCE`. Used for the backing's
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
    let bounce_ptr = OUTPUT_BOUNCE as *mut u8;
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
// qcow2 backing-side staging + step-window plumbing (phase 4)
// ---------------------------------------------------------------------------

/// Geometry of the backing-side scratch carve for one run,
/// threaded to the [`StagedRegions`] / [`Regions`] view
/// builders so the planner and executor alias the exact same
/// buffers (the two halves of the qcow2-write decision-1 loop).
#[derive(Clone, Copy)]
struct BackingCarve {
    cluster_size: usize,
    /// Staged backing L1 bytes at `BACKING_L1_BUF`.
    l1_bytes: usize,
    /// Staged backing refcount-table bytes at `BACKING_RT_BUF`.
    rt_bytes: usize,
    /// Staged refblock bytes (dense prefix) at
    /// `BACKING_REFBLOCKS_BUF`.
    rb_bytes: usize,
    /// L2 window bytes (`l2_slots * cluster_size`) at
    /// `BACKING_L2_STAGING`.
    l2_window_bytes: usize,
}

/// The planner's view of the staged backing buffers.
///
/// # Safety
///
/// The returned slices alias the fixed scratch regions; the
/// caller must not hold a [`Regions`] view (or any other
/// aliasing borrow) at the same time. The decision-1 loop
/// guarantees this: plan with the staged view, drop it, execute
/// with the regions view.
unsafe fn staged_view<'a>(carve: &BackingCarve) -> StagedRegions<'a> {
    StagedRegions {
        l1: core::slice::from_raw_parts(BACKING_L1_BUF as *const u8, carve.l1_bytes),
        l2_window: core::slice::from_raw_parts(
            BACKING_L2_STAGING as *const u8,
            carve.l2_window_bytes,
        ),
        refcount_table: core::slice::from_raw_parts(BACKING_RT_BUF as *const u8, carve.rt_bytes),
        refblocks: core::slice::from_raw_parts_mut(
            BACKING_REFBLOCKS_BUF as *mut u8,
            carve.rb_bytes,
        ),
    }
}

/// Execute the emitted step window against the scratch-carved
/// regions and reset the buffer. Returns `false` if any step's
/// device I/O failed (the caller maps that to
/// `ERROR_HEADER_MISMATCH`, the code the replaced
/// `write_output_byte_range` call sites used).
///
/// # Safety
///
/// As for [`staged_view`]: the regions alias the fixed scratch
/// carve, so no [`StagedRegions`] view may be live across this
/// call.
unsafe fn exec_window(
    io: &mut CallTableIo<'_>,
    steps: &mut StepBuf<'_>,
    carve: &BackingCarve,
) -> bool {
    let mut regions = Regions {
        l1: core::slice::from_raw_parts_mut(BACKING_L1_BUF as *mut u8, carve.l1_bytes),
        l2_window: core::slice::from_raw_parts_mut(
            BACKING_L2_STAGING as *mut u8,
            carve.l2_window_bytes,
        ),
        refcount_table: core::slice::from_raw_parts_mut(BACKING_RT_BUF as *mut u8, carve.rt_bytes),
        refblocks: core::slice::from_raw_parts_mut(
            BACKING_REFBLOCKS_BUF as *mut u8,
            carve.rb_bytes,
        ),
        bounce: core::slice::from_raw_parts_mut(PLANNER_BOUNCE as *mut u8, carve.cluster_size),
        caller_data: core::slice::from_raw_parts_mut(DATA_BUF as *mut u8, carve.cluster_size),
        rmw_sector: core::slice::from_raw_parts_mut(RMW_SECTOR as *mut u8, RMW_SECTOR_LIMIT),
        fill_sector: core::slice::from_raw_parts_mut(FILL_SECTOR as *mut u8, FILL_SECTOR_LIMIT),
        cluster_size: carve.cluster_size,
    };
    let ok = execute(steps.steps(), &mut regions, io).is_ok();
    steps.reset();
    ok
}

/// Stage the backing's L1, refcount table and refblocks for the
/// qcow2-write planner. Refblocks are staged per the
/// [`StagedRegions`] dense-prefix contract: the populated
/// refcount-table entries must run gap-free from index 0
/// (bench/bitmap's contiguity gate). A sparse (holed) refcount
/// table refuses as `ERROR_BACKING_INCONSISTENT` BEFORE any
/// mutation — under the old dense-compaction staging this shape
/// was silently misallocated (phase-4 divergence D4, a live
/// defect: holed RTs are stock-producible via discard +
/// `qemu-img resize --shrink` and pass `qemu-img check`).
/// Entries with reserved low bits or a missing/misaligned
/// masked offset refuse the same way (plan_flush would refuse
/// them as `StagedRegionsMismatch`, but only after data writes;
/// staging-time refusal keeps it pre-mutation).
///
/// # Safety
///
/// `call_table` must be the validated CallTable and the scratch
/// carve unused by any live view.
unsafe fn stage_backing_qcow2(
    call_table: &CallTable,
    sector_size: usize,
    backing: &QcowHeader,
) -> Result<BackingCarve, u32> {
    let cluster_size_usize = backing.cluster_size as usize;

    // Backing L1 (same limit and codes as the old stage_side).
    let l1_bytes = (backing.l1_size as usize).saturating_mul(8);
    if l1_bytes > BACKING_L1_LIMIT {
        return Err(CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }
    if l1_bytes > 0
        && !read_output_byte_range(
            call_table,
            sector_size,
            backing.l1_table_offset,
            BACKING_L1_BUF as *mut u8,
            l1_bytes,
        )
    {
        return Err(CommitResult::ERROR_PARSE_FAILED);
    }

    // Backing refcount table (whole table, as before).
    let rt_bytes = (backing.refcount_table_clusters as usize) * cluster_size_usize;
    if rt_bytes > BACKING_RT_LIMIT {
        return Err(CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }
    if rt_bytes > 0
        && !read_output_byte_range(
            call_table,
            sector_size,
            backing.refcount_table_offset,
            BACKING_RT_BUF as *mut u8,
            rt_bytes,
        )
    {
        return Err(CommitResult::ERROR_PARSE_FAILED);
    }
    let rt = core::slice::from_raw_parts(BACKING_RT_BUF as *const u8, rt_bytes);

    // Dense-prefix walk: count populated entries, refuse on the
    // first gap-then-populated pattern and on malformed entries.
    let mut refblock_count: usize = 0;
    {
        let mut seen_zero = false;
        let mut i = 0usize;
        while i + 8 <= rt_bytes {
            let entry = read_u64_be(rt, i);
            if entry == 0 {
                seen_zero = true;
            } else {
                if seen_zero {
                    return Err(CommitResult::ERROR_BACKING_INCONSISTENT);
                }
                let host = entry & L1_OFFSET_MASK;
                if entry & 0x1ff != 0 || host == 0 || host % cluster_size_usize as u64 != 0 {
                    return Err(CommitResult::ERROR_BACKING_INCONSISTENT);
                }
                refblock_count += 1;
            }
            i += 8;
        }
    }

    // Capacity: staged bytes and the crate's count cap
    // (decision 5 — strictly wider than the old 32-refblock
    // cap on every cluster size).
    let refblock_cap = qcow2_write::MAX_REFBLOCKS.min(BACKING_REFBLOCKS_LIMIT / cluster_size_usize);
    if refblock_count > refblock_cap {
        return Err(CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }
    for j in 0..refblock_count {
        let host = read_u64_be(rt, j * 8) & L1_OFFSET_MASK;
        let dst = (BACKING_REFBLOCKS_BUF + j * cluster_size_usize) as *mut u8;
        if !read_output_byte_range(call_table, sector_size, host, dst, cluster_size_usize) {
            return Err(CommitResult::ERROR_PARSE_FAILED);
        }
    }

    let l2_slots = MAX_L2_SLOTS.min(BACKING_L2_LIMIT / cluster_size_usize);
    Ok(BackingCarve {
        cluster_size: cluster_size_usize,
        l1_bytes,
        rt_bytes,
        rb_bytes: refblock_count * cluster_size_usize,
        l2_window_bytes: l2_slots * cluster_size_usize,
    })
}

/// Initialise the scratch-carved step window and hand back the
/// `[Step]` storage. Every slot is written (via `ptr::write`,
/// no read of the uninitialised memory) before the slice
/// exists.
///
/// # Safety
///
/// The `STEP_BUF` region must be unused by any live borrow.
unsafe fn init_step_storage() -> &'static mut [Step] {
    let filler = Step {
        kind: StepKind::ZeroRange,
        device: TargetDevice::Output,
        region: RegionId::Bounce,
        region_offset: 0,
        disk_offset: 0,
        len: 0,
        value: 0,
    };
    let ptr = STEP_BUF as *mut Step;
    for i in 0..STEP_CAPACITY {
        ptr.add(i).write(filler);
    }
    core::slice::from_raw_parts_mut(ptr, STEP_CAPACITY)
}

// ---------------------------------------------------------------------------
// qcow2 commit runner
// ---------------------------------------------------------------------------

/// `#[inline(never)]` is load-bearing: built for
/// `x86_64-unknown-none` with `opt-level = "z"` + `lto = true`,
/// inlining a large runner into the `extern "C"` `_start` can
/// miscompile it (see the note on `run_qcow2` in
/// `src/operations/amend/src/main.rs`). The phase-4 rework made
/// this function strictly larger, so keep it out of line.
#[inline(never)]
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
    // Interim phase-2 gates: internal snapshots on EITHER side
    // are refused before any staging or mutation.
    //
    // Backing (GitHub issue #420): committing into a backing
    // with internal snapshots silently corrupts them (v1
    // overwrites snapshot-shared data clusters in place and
    // allocates through snapshot-shared L2 tables without COW).
    //
    // Overlay (issue #423, the overlay-side sibling of issue
    // #420): the post-commit overlay-clear pass zeroes
    // active L2 entries and decrements the referenced data
    // clusters without accounting for the snapshot's reference,
    // leaving snapshot-shared clusters at refcount=0
    // reference=1. Phase 1's second-order probe missed this
    // (exit code and snapshot read-back agree with qemu); the
    // phase-2 step-2a parity test proved the resulting overlay
    // is check-dirty where qemu's is clean.
    //
    // The real fix for both sides (snapshot-aware COW and
    // refcounting) lands in phase 7 of
    // PLAN-qcow2-write-infrastructure.
    if backing.nb_snapshots > 0 {
        return err(config, CommitResult::ERROR_BACKING_HAS_SNAPSHOTS);
    }
    if overlay.nb_snapshots > 0 {
        return err(config, CommitResult::ERROR_OVERLAY_HAS_SNAPSHOTS);
    }
    if backing.virtual_size < overlay.virtual_size {
        return err(config, CommitResult::ERROR_OVERLAY_LARGER_THAN_BACKING);
    }

    // qcow2-write envelope on the BACKING (phase-4 decision 6):
    // runs after the op gates above, which cover every Gate
    // except UnknownIncompatible with their existing codes —
    // so the only refusal this can add is the zstd/unknown
    // incompatible-bit gate (ERROR_BACKING_UNSUPPORTED). Before
    // any staging or mutation.
    if let Err(gate) = check_envelope(&backing) {
        return err(config, map_backing_gate(gate));
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

    // ----- Cross-image validation (planner crate) -----------
    let capacity_sectors_backing = (call_table.get_output_capacity)();
    let backing_file_size = capacity_sectors_backing.saturating_mul(sector_size as u64);
    let opts = Qcow2CommitOpts {
        overlay_header,
        overlay_file_size: (call_table.get_input_capacity)(0).saturating_mul(sector_size as u64),
        backing_header: backing_header_slice,
        backing_file_size,
    };
    let ctx = match plan_commit_qcow2(&opts) {
        Ok(c) => c,
        Err(e) => return err(config, map_commit_error(e)),
    };

    // ----- Stage backing metadata (output device) -----------
    // L1 + refcount table + refblocks as a dense prefix,
    // contiguity-gated (phase-4 decision 4). Backing L2 tables
    // are no longer staged eagerly: the qcow2-write planner
    // loads them into the fixed-slot window on demand.
    let carve = match stage_backing_qcow2(call_table, sector_size, &backing) {
        Ok(c) => c,
        Err(code) => return err(config, code),
    };

    // ----- qcow2-write planner state -------------------------
    let staging_config = StagingConfig {
        l2_slots: carve.l2_window_bytes / cluster_size_usize,
        max_refblocks: qcow2_write::MAX_REFBLOCKS,
        device: TargetDevice::Output,
    };
    let mut wstate: WriteState = match new_state(&backing, &staging_config) {
        Ok(s) => s,
        Err(gate) => return err(config, map_backing_gate(gate)),
    };
    let step_storage = init_step_storage();
    let mut step_buf = StepBuf::new(step_storage);
    // Input slot 0 (the overlay) is opened RW by the host, so
    // it has the fsync capability; commit's programs only emit
    // barriers on the Output device, which degrade to Ordering
    // (divergence D8 — zero fsyncs, exactly as before).
    let mut io = CallTableIo::new(call_table, true);

    // ----- Per-cluster commit loop --------------------------
    let mut clusters_committed: u64 = 0;
    let mut bytes_committed: u64 = 0;

    let overlay_l1_buf =
        core::slice::from_raw_parts(OVERLAY_L1_BUF as *const u8, (overlay.l1_size as usize) * 8);

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

        // Plan the backing-side write for this cluster through
        // qcow2-write (allocation, classification, L2 window
        // management) and execute each emitted window via the
        // step executor. The request is the full cluster,
        // clamped to the virtual size on the tail cluster of an
        // unaligned image (phase-4 decision 7 / divergence D9 —
        // bytes beyond EOV are not virtual content; the planner
        // zero-fills the beyond-EOV remainder).
        let voff = cluster_idx.saturating_mul(cluster_size);
        let win_len = cluster_size.min(backing.virtual_size - voff);
        loop {
            let planned = {
                let mut staged = staged_view(&carve);
                plan_write(
                    &mut wstate,
                    &mut staged,
                    voff,
                    win_len,
                    DataSource::CallerData { offset: 0 },
                    &mut step_buf,
                )
            };
            match planned {
                Ok(_) => {
                    if !exec_window(&mut io, &mut step_buf, &carve) {
                        return err(config, CommitResult::ERROR_HEADER_MISMATCH);
                    }
                    break;
                }
                Err(WriteError::BufFull) => {
                    // Window boundary (buffer full or a
                    // LoadCluster whose bytes the planner
                    // needs): execute, reset, resume with
                    // IDENTICAL arguments.
                    if !exec_window(&mut io, &mut step_buf, &carve) {
                        return err(config, CommitResult::ERROR_HEADER_MISMATCH);
                    }
                }
                Err(e) => {
                    // Execute the already-emitted window FIRST:
                    // this reproduces the pre-migration
                    // bytes-written-up-to-the-refusal behaviour,
                    // keeping refusal paths byte-identical to
                    // the old composition (phase-4 step 4b). The
                    // planner error dominates any exec failure.
                    let _ = exec_window(&mut io, &mut step_buf, &carve);
                    return err(config, map_write_error(e));
                }
            }
        }

        clusters_committed += 1;
        bytes_committed = bytes_committed.saturating_add(cluster_size);
    }

    // ----- Flush dirty backing metadata --------------------
    // One plan_flush epoch: dirty L2 window slots → staged L1
    // (if dirty) → dirty refblocks (refcounts last), the same
    // final bytes and granularity as the old inline flush.
    // Barriers degrade to Ordering on the fsync-less output
    // device (divergence D8).
    loop {
        let planned = {
            let mut staged = staged_view(&carve);
            plan_flush(&mut wstate, &mut staged, &mut step_buf)
        };
        match planned {
            Ok(_) => {
                if !exec_window(&mut io, &mut step_buf, &carve) {
                    return err(config, CommitResult::ERROR_HEADER_MISMATCH);
                }
                break;
            }
            Err(WriteError::BufFull) => {
                if !exec_window(&mut io, &mut step_buf, &carve) {
                    return err(config, CommitResult::ERROR_HEADER_MISMATCH);
                }
            }
            Err(e) => {
                let _ = exec_window(&mut io, &mut step_buf, &carve);
                return err(config, map_write_error(e));
            }
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

// ---------------------------------------------------------------------------
// vmdk commit runner (step 7d)
// ---------------------------------------------------------------------------
//
// vmdk's per-side metadata is shallower than qcow2: a single
// grain directory of u32 LE sector pointers, and one grain
// table per allocated GD entry (also u32 LE sector pointers).
// No refcount table. v1 reuses the qcow2 scratch regions:
// `OVERLAY_L1_BUF` / `BACKING_L1_BUF` for the grain
// directories, `OVERLAY_L2_STAGING` / `BACKING_L2_STAGING`
// for the GTs, and `OVERLAY_RT_BUF` / `BACKING_RT_BUF` for
// the descriptor bytes (only used for the defensive re-read
// check).

/// Reuse [`StagedL2`] for vmdk: `l1_idx` carries the GD entry
/// index, `host_offset` carries the GT's host sector (not byte
/// offset — vmdk pointers are sector-granularity), `dirty`
/// flags GT bytes the allocator has mutated.
type StagedGt = StagedL2;

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn write_u32_le(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

unsafe fn stage_vmdk_side(
    sector_size: usize,
    gd_offset_sectors: u64,
    num_gd_entries: u32,
    num_gtes_per_gt: u32,
    gd_ptr: *mut u8,
    gt_staging_base: usize,
    gt_capacity_bytes: usize,
    staged: &mut [StagedGt; MAX_STAGED_L2],
    read_byte_range: impl Fn(u64, *mut u8, usize) -> bool,
) -> Result<usize, CommitError> {
    let gd_bytes = (num_gd_entries as usize)
        .checked_mul(4)
        .ok_or(CommitError::Overflow)?;
    if gd_bytes > OVERLAY_L1_LIMIT {
        return Err(CommitError::ScratchTooSmall);
    }
    if gd_bytes > 0 && !read_byte_range(gd_offset_sectors * 512, gd_ptr, gd_bytes) {
        return Err(CommitError::ParseFailed);
    }
    let gd_buf = core::slice::from_raw_parts(gd_ptr, gd_bytes);
    let gt_size_bytes = (num_gtes_per_gt as usize)
        .checked_mul(4)
        .ok_or(CommitError::Overflow)?;
    let mut count = 0usize;
    let mut cursor = gt_staging_base;
    let cap_end = gt_staging_base + gt_capacity_bytes;
    let _ = sector_size; // bounce buffer comes from helper's own region
    for i in 0..num_gd_entries as usize {
        let gd_entry = read_u32_le(gd_buf, i * 4);
        if gd_entry == 0 {
            continue;
        }
        let gt_host_byte = (gd_entry as u64) * 512;
        if count >= MAX_STAGED_L2 || cursor + gt_size_bytes > cap_end {
            return Err(CommitError::ScratchTooSmall);
        }
        if !read_byte_range(gt_host_byte, cursor as *mut u8, gt_size_bytes) {
            return Err(CommitError::ParseFailed);
        }
        staged[count] = StagedGt {
            l1_idx: i as u32,
            host_offset: gd_entry as u64, // host sector, not bytes
            dirty: false,
        };
        count += 1;
        cursor += gt_size_bytes;
    }
    Ok(count)
}

unsafe fn run_vmdk(call_table: &CallTable, config: &CommitConfig) -> CommitResult {
    let sector_size = (call_table.get_output_sector_size)();
    let overlay_header = core::slice::from_raw_parts(HEADER_BUF as *const u8, sector_size);
    let backing_header_slice =
        core::slice::from_raw_parts(BACKING_HEADER_BUF as *const u8, sector_size);

    let overlay = match Vmdk4HeaderFull::parse(overlay_header) {
        Some(p) => p,
        None => return err(config, CommitResult::ERROR_PARSE_FAILED),
    };
    let backing = match Vmdk4HeaderFull::parse(backing_header_slice) {
        Some(p) => p,
        None => return err(config, CommitResult::ERROR_PARSE_FAILED),
    };

    if (overlay.flags & FLAG_COMPRESSED) != 0 || (backing.flags & FLAG_COMPRESSED) != 0 {
        return err(config, CommitResult::ERROR_UNSUPPORTED_FORMAT);
    }
    if overlay.grain_size_sectors != backing.grain_size_sectors
        || overlay.num_gtes_per_gt != backing.num_gtes_per_gt
    {
        return err(config, CommitResult::ERROR_UNSUPPORTED_FORMAT);
    }
    if backing.virtual_size < overlay.virtual_size {
        return err(config, CommitResult::ERROR_OVERLAY_LARGER_THAN_BACKING);
    }
    if overlay.grain_size_sectors == 0 || overlay.num_gtes_per_gt == 0 {
        return err(config, CommitResult::ERROR_OVERLAY_CORRUPT);
    }
    if backing.grain_size_sectors == 0 || backing.num_gtes_per_gt == 0 {
        return err(config, CommitResult::ERROR_BACKING_CORRUPT);
    }

    let overlay_num_gd = match overlay.num_gd_entries() {
        Some(n) => n,
        None => return err(config, CommitResult::ERROR_OVERLAY_CORRUPT),
    };
    let backing_num_gd = match backing.num_gd_entries() {
        Some(n) => n,
        None => return err(config, CommitResult::ERROR_BACKING_CORRUPT),
    };

    let grain_size_sectors = overlay.grain_size_sectors as u32;
    let num_gtes_per_gt = overlay.num_gtes_per_gt;
    let grain_size_bytes = overlay.grain_size_bytes;
    let grain_size_bytes_usize = grain_size_bytes as usize;
    if grain_size_bytes_usize > DATA_BUF_LIMIT {
        return err(config, CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }

    // ----- Stage overlay GD + GTs (input slot 0) -----------
    let mut overlay_staged_gt = [StagedGt {
        l1_idx: 0,
        host_offset: 0,
        dirty: false,
    }; MAX_STAGED_L2];
    let overlay_staged_count = match stage_vmdk_side(
        sector_size,
        overlay.gd_offset_sectors,
        overlay_num_gd,
        num_gtes_per_gt,
        OVERLAY_L1_BUF as *mut u8,
        OVERLAY_L2_STAGING,
        OVERLAY_L2_LIMIT,
        &mut overlay_staged_gt,
        |off, dst, len| read_input_byte_range(call_table, 0, sector_size, off, dst, len),
    ) {
        Ok(n) => n,
        Err(e) => return err(config, map_commit_error(e)),
    };

    // ----- Stage overlay descriptor (for length validation
    //       and the planner opts) -----------------------------
    let overlay_desc_size = (overlay.desc_size_sectors * 512) as usize;
    if overlay_desc_size > OVERLAY_RT_LIMIT {
        return err(config, CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }
    if overlay_desc_size > 0
        && !read_input_byte_range(
            call_table,
            0,
            sector_size,
            overlay.desc_offset_sectors * 512,
            OVERLAY_RT_BUF as *mut u8,
            overlay_desc_size,
        )
    {
        return err(config, CommitResult::ERROR_PARSE_FAILED);
    }

    // ----- Stage backing GD + GTs (output device) ----------
    let mut backing_staged_gt = [StagedGt {
        l1_idx: 0,
        host_offset: 0,
        dirty: false,
    }; MAX_STAGED_L2];
    let backing_staged_count = match stage_vmdk_side(
        sector_size,
        backing.gd_offset_sectors,
        backing_num_gd,
        num_gtes_per_gt,
        BACKING_L1_BUF as *mut u8,
        BACKING_L2_STAGING,
        BACKING_L2_LIMIT,
        &mut backing_staged_gt,
        |off, dst, len| read_output_byte_range(call_table, sector_size, off, dst, len),
    ) {
        Ok(n) => n,
        Err(e) => return err(config, map_commit_error(e)),
    };

    let backing_desc_size = (backing.desc_size_sectors * 512) as usize;
    if backing_desc_size > BACKING_RT_LIMIT {
        return err(config, CommitResult::ERROR_SCRATCH_TOO_SMALL);
    }
    if backing_desc_size > 0
        && !read_output_byte_range(
            call_table,
            sector_size,
            backing.desc_offset_sectors * 512,
            BACKING_RT_BUF as *mut u8,
            backing_desc_size,
        )
    {
        return err(config, CommitResult::ERROR_PARSE_FAILED);
    }

    // ----- Plan ---------------------------------------------
    let gt_size_bytes = (num_gtes_per_gt as usize) * 4;
    let overlay_gd_bytes = (overlay_num_gd as usize) * 4;
    let backing_gd_bytes = (backing_num_gd as usize) * 4;
    let overlay_gd_slice =
        core::slice::from_raw_parts(OVERLAY_L1_BUF as *const u8, overlay_gd_bytes);
    let overlay_gt_slice = core::slice::from_raw_parts(
        OVERLAY_L2_STAGING as *const u8,
        overlay_staged_count * gt_size_bytes,
    );
    let overlay_desc_slice =
        core::slice::from_raw_parts(OVERLAY_RT_BUF as *const u8, overlay_desc_size);
    let backing_gd_slice =
        core::slice::from_raw_parts(BACKING_L1_BUF as *const u8, backing_gd_bytes);
    let backing_gt_slice = core::slice::from_raw_parts(
        BACKING_L2_STAGING as *const u8,
        backing_staged_count * gt_size_bytes,
    );
    let backing_desc_slice =
        core::slice::from_raw_parts(BACKING_RT_BUF as *const u8, backing_desc_size);

    let overlay_gt_hosts_buf =
        core::slice::from_raw_parts_mut(BACKING_RB_OFFSETS as *mut u64, overlay_staged_count);
    for (i, gt) in overlay_staged_gt
        .iter()
        .take(overlay_staged_count)
        .enumerate()
    {
        overlay_gt_hosts_buf[i] = gt.host_offset;
    }
    let backing_gt_hosts_buf = core::slice::from_raw_parts_mut(
        (BACKING_RB_OFFSETS + overlay_staged_count * 8) as *mut u64,
        backing_staged_count,
    );
    for (i, gt) in backing_staged_gt
        .iter()
        .take(backing_staged_count)
        .enumerate()
    {
        backing_gt_hosts_buf[i] = gt.host_offset;
    }

    let capacity_sectors_backing = (call_table.get_output_capacity)();
    let backing_file_size = capacity_sectors_backing.saturating_mul(sector_size as u64);
    let overlay_file_size = (call_table.get_input_capacity)(0).saturating_mul(sector_size as u64);

    let opts = VmdkCommitOpts {
        overlay_header,
        overlay_descriptor: overlay_desc_slice,
        overlay_grain_size_sectors: grain_size_sectors,
        overlay_num_gtes_per_gt: num_gtes_per_gt,
        overlay_num_gd_entries: overlay_num_gd,
        overlay_gd_offset_sectors: overlay.gd_offset_sectors,
        overlay_grain_directory: overlay_gd_slice,
        overlay_grain_tables: overlay_gt_slice,
        overlay_allocated_gt_host_sectors: overlay_gt_hosts_buf,
        overlay_allocated_gt_count: overlay_staged_count as u32,
        overlay_virtual_size: overlay.virtual_size,
        overlay_file_size,
        backing_header: backing_header_slice,
        backing_descriptor: backing_desc_slice,
        backing_grain_size_sectors: grain_size_sectors,
        backing_num_gtes_per_gt: num_gtes_per_gt,
        backing_num_gd_entries: backing_num_gd,
        backing_gd_offset_sectors: backing.gd_offset_sectors,
        backing_grain_directory: backing_gd_slice,
        backing_grain_tables: backing_gt_slice,
        backing_allocated_gt_host_sectors: backing_gt_hosts_buf,
        backing_allocated_gt_count: backing_staged_count as u32,
        backing_virtual_size: backing.virtual_size,
        backing_file_size,
    };
    let planner_scratch =
        core::slice::from_raw_parts_mut(PLANNER_SCRATCH as *mut u8, PLANNER_SCRATCH_LIMIT);
    let mut ctx = match plan_commit_vmdk(&opts, planner_scratch) {
        Ok(c) => c,
        Err(e) => return err(config, map_commit_error(e)),
    };

    // ----- Per-grain commit loop ----------------------------
    let mut state = match BackingGrainAllocationState::at_eof(backing_file_size, grain_size_sectors)
    {
        Ok(s) => s,
        Err(e) => return err(config, map_commit_error(e)),
    };
    let mut clusters_committed: u64 = 0;
    let mut bytes_committed: u64 = 0;
    let data_buf = DATA_BUF as *mut u8;

    let backing_gt_buf_mut = core::slice::from_raw_parts_mut(
        BACKING_L2_STAGING as *mut u8,
        backing_staged_count * gt_size_bytes,
    );

    for grain_idx in 0..ctx.overlay_grain_count {
        let gd_idx = grain_idx / (num_gtes_per_gt as u64);
        let gte_inner = (grain_idx % (num_gtes_per_gt as u64)) as usize;
        if gd_idx >= overlay_num_gd as u64 {
            break;
        }
        let gd_idx_u32 = gd_idx as u32;

        // Decode overlay GD/GT.
        let overlay_slot =
            match find_staged_l2(&overlay_staged_gt, overlay_staged_count, gd_idx_u32) {
                Some(s) => s,
                None => continue, // GD entry is zero — nothing allocated here.
            };
        let overlay_gt = core::slice::from_raw_parts(
            (OVERLAY_L2_STAGING + overlay_slot * gt_size_bytes) as *const u8,
            gt_size_bytes,
        );
        let gte = read_u32_le(overlay_gt, gte_inner * 4);
        if gte == 0 {
            continue;
        }
        let overlay_grain_host_byte = (gte as u64) * 512;

        // Read the overlay grain's data.
        if !read_input_byte_range(
            call_table,
            0,
            sector_size,
            overlay_grain_host_byte,
            data_buf,
            grain_size_bytes_usize,
        ) {
            return err(config, CommitResult::ERROR_PARSE_FAILED);
        }

        // Locate the matching backing GT. v1 skips grains
        // whose covering backing GD entry is zero
        // (GD-extension follow-up).
        let backing_slot =
            match find_staged_l2(&backing_staged_gt, backing_staged_count, gd_idx_u32) {
                Some(s) => s,
                None => continue,
            };
        let backing_gte_off = backing_slot * gt_size_bytes + gte_inner * 4;
        let backing_gte = read_u32_le(backing_gt_buf_mut, backing_gte_off);
        let backing_grain_host_byte = if backing_gte != 0 {
            (backing_gte as u64) * 512
        } else {
            let off = match allocate_backing_grain_vmdk(&mut ctx, &mut state) {
                Ok(off) => off,
                Err(e) => return err(config, map_commit_error(e)),
            };
            let sector = (off / 512) as u32;
            write_u32_le(backing_gt_buf_mut, backing_gte_off, sector);
            backing_staged_gt[backing_slot].dirty = true;
            off
        };

        let data_slice = core::slice::from_raw_parts(data_buf, grain_size_bytes_usize);
        if !write_output_byte_range(call_table, sector_size, backing_grain_host_byte, data_slice) {
            return err(config, CommitResult::ERROR_HEADER_MISMATCH);
        }

        clusters_committed += 1;
        bytes_committed = bytes_committed.saturating_add(grain_size_bytes);
    }

    // ----- Flush dirty backing GTs --------------------------
    for i in 0..backing_staged_count {
        if !backing_staged_gt[i].dirty {
            continue;
        }
        let slice = core::slice::from_raw_parts(
            (BACKING_L2_STAGING + i * gt_size_bytes) as *const u8,
            gt_size_bytes,
        );
        let host_byte = backing_staged_gt[i].host_offset * 512;
        if !write_output_byte_range(call_table, sector_size, host_byte, slice) {
            return err(config, CommitResult::ERROR_HEADER_MISMATCH);
        }
    }

    // ----- Overlay-clear pass ------------------------------
    let zeros_4 = [0u8; 4];
    let mut overlay_clusters_cleared: u64 = 0;
    for grain_idx in 0..ctx.overlay_grain_count {
        let gd_idx = grain_idx / (num_gtes_per_gt as u64);
        let gte_inner = (grain_idx % (num_gtes_per_gt as u64)) as usize;
        if gd_idx >= overlay_num_gd as u64 {
            break;
        }
        let slot = match find_staged_l2(&overlay_staged_gt, overlay_staged_count, gd_idx as u32) {
            Some(s) => s,
            None => continue,
        };
        let overlay_gt = core::slice::from_raw_parts(
            (OVERLAY_L2_STAGING + slot * gt_size_bytes) as *const u8,
            gt_size_bytes,
        );
        let gte = read_u32_le(overlay_gt, gte_inner * 4);
        if gte == 0 {
            continue;
        }
        // Was this grain committed? v1 commits every
        // allocated overlay grain whose covering backing GD
        // entry is non-zero; otherwise it was skipped. Mirror
        // the data-loop's skip predicate.
        if find_staged_l2(&backing_staged_gt, backing_staged_count, gd_idx as u32).is_none() {
            continue;
        }

        let gte_byte_offset = overlay_staged_gt[slot].host_offset * 512 + (gte_inner as u64) * 4;
        if !write_input_byte_range(call_table, 0, sector_size, gte_byte_offset, &zeros_4) {
            return err(config, CommitResult::ERROR_HEADER_MISMATCH);
        }
        overlay_clusters_cleared += 1;
    }

    // ----- Defensive backing-header re-read -----------------
    let mut redo = [0u8; MAX_SECTOR_SIZE];
    if !(call_table.read_output_sector)(0, redo.as_mut_ptr(), sector_size) {
        return err(config, CommitResult::ERROR_HEADER_MISMATCH);
    }
    let redo_parsed = match Vmdk4HeaderFull::parse(&redo[..sector_size]) {
        Some(p) => p,
        None => return err(config, CommitResult::ERROR_HEADER_MISMATCH),
    };
    if redo_parsed.virtual_size != backing.virtual_size
        || redo_parsed.grain_size_sectors != backing.grain_size_sectors
        || redo_parsed.gd_offset_sectors != backing.gd_offset_sectors
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
