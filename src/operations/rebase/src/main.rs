//! Rebase operation: change an overlay's backing-file reference.
//!
//! Phase 3 of `PLAN-rebase-commit.md`. Reads a `RebaseConfig`
//! from `OPERATION_CONFIG_ADDR`, reads sector 0 of the output
//! device (the overlay being rebased), detects the format,
//! dispatches to the matching per-format runner, and reports
//! the outcome via `send_rebase_result` + `send_complete`.
//!
//! The qcow2 safe-mode runner (re-composed by phase 5 of
//! `PLAN-qcow2-write-infrastructure`) walks every guest
//! cluster, probes the overlay's ORIGINAL pre-run mapping to
//! decide whether the cluster needs comparing at all, reads
//! the old and new chains through the untouched chain reader,
//! and for divergent clusters plans the overlay write via
//! `qcow2_write::plan_write` (allocation, classification
//! refusals, L2 window management) executed literally by
//! `qcow2_write_exec::execute`. One `plan_flush` epoch replaces
//! the inline L2 → L1 → refblock flush; the deferred
//! header/backing-path patch group (`apply_rebase_plan`) still
//! lands last. The `-u` metadata-only path, unsafe detach and
//! the whole vmdk runner are untouched.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use qcow2::{QcowHeader, L1_OFFSET_MASK};
use qcow2_write::{
    check_envelope, new_state, plan_flush, plan_write, DataSource, Gate, RegionId, StagedRegions,
    StagingConfig, Step, StepBuf, StepKind, TargetDevice, WriteError, WriteState, MAX_L2_SLOTS,
};
use qcow2_write_exec::{execute, read_bytes, CallTableIo, Regions};
use rebase::{
    plan_rebase_qcow2, plan_rebase_vmdk, Qcow2RebaseOpts, Qcow2RebaseOutput, RebaseError,
    RebaseMode, RebasePatch, RebasePlan, VmdkRebaseOpts, VmdkRebaseOutput,
};
use shared::{
    format_detection::detect_format_from_header, validate_call_table, CallTable, ChainConfig,
    ImageFormat, RebaseConfig, RebaseResult, CALL_TABLE_ADDR, CHAIN_CONFIG_ADDR, MAX_CHAIN_DEVICES,
    MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
};

// ---------------------------------------------------------------------------
// Scratch layout
// ---------------------------------------------------------------------------
//
// SCRATCH_MEM_BASE..ALLOC_HEAP_BASE is ~12.44 MiB of guest
// memory. Two carves share it; they never coexist at runtime
// because exactly one per-format runner executes per
// invocation:
//
// 1. The qcow2 SAFE-MODE ladder (phase 5 of
//    PLAN-qcow2-write-infrastructure): fixed regions only,
//    each derived from the previous one's end (the c84743e
//    ordering discipline), const-asserted below the allocator
//    heap. This replaced the old EXISTING_STATE growable
//    staging arena and the 4 MiB PLANNER_SCRATCH duplicate
//    refblock copy.
//
// 2. The -u / unsafe-detach / vmdk carve (EXISTING_STATE +
//    PLANNER_SCRATCH), retained byte-for-byte at its original
//    addresses and sizes so those untouched paths keep their
//    exact behaviour (including the vmdk runner's up-to-4-MiB
//    descriptor staging and planner slot). It ALIASES the
//    safe-mode ladder's address space; the safe runner never
//    references it and vice versa.

/// First sector of the output device; also the single-sector
/// bounce buffer for partial-sector reads and writes (all
/// runners).
const HEADER_BUF: usize = SCRATCH_MEM_BASE;

// ----- qcow2 safe-mode ladder --------------------------------

/// Stable copy of the overlay header. `read_byte_range` uses
/// HEADER_BUF as a sub-sector bounce, so staging reads would
/// clobber the header there; the planner re-parses this copy.
const STABLE_HEADER_BUF: usize = HEADER_BUF + MAX_SECTOR_SIZE;
/// Staged overlay L1 table (`RegionId::L1`) — the copy the
/// qcow2-write planner classifies through and the executor
/// patches.
const OVERLAY_L1_BUF: usize = STABLE_HEADER_BUF + MAX_SECTOR_SIZE;
const OVERLAY_L1_LIMIT: usize = MAX_SECTOR_SIZE;
/// Read-only copy of the ORIGINAL pre-run L1 table for the
/// skip probe (decision 1): the probe must consult the
/// overlay's pre-run mapping, never the planner's patched L1.
const ORIG_L1_BUF: usize = OVERLAY_L1_BUF + OVERLAY_L1_LIMIT;
const ORIG_L1_LIMIT: usize = MAX_SECTOR_SIZE;
/// Staged overlay refcount table (`RegionId::RefcountTable`).
/// Staged as a bounded PREFIX (`min(rt_size, limit)` — bench's
/// model): the planner only reads the entries covering the
/// staged refblocks (`refblock_count * 8` bytes, <= 16 KiB at
/// the 2048-refblock cap), so a 1 MiB-cluster refcount table
/// larger than this buffer must not refuse (the old staging
/// budget allowed it; see the phase-5 envelope computation).
const OVERLAY_RT_BUF: usize = ORIG_L1_BUF + ORIG_L1_LIMIT;
const OVERLAY_RT_LIMIT: usize = MAX_SECTOR_SIZE;
/// Staged overlay refblocks (`RegionId::Refblocks`), a dense
/// prefix covering host clusters from zero, contiguity-gated
/// at staging (divergence R-D4's fix). Capacity:
/// byte-capacity-driven with the `qcow2_write::MAX_REFBLOCKS`
/// (2048) count cap on top.
const OVERLAY_REFBLOCKS_BUF: usize = OVERLAY_RT_BUF + OVERLAY_RT_LIMIT;
const OVERLAY_REFBLOCKS_LIMIT: usize = 3 * 1024 * 1024;
/// Overlay L2 window (`RegionId::L2Slot`):
/// `min(MAX_L2_SLOTS, OVERLAY_L2_LIMIT / cluster_size)` slots
/// (>= 2 at the 1 MiB cluster envelope). Unlike the retired
/// stage-everything arena, eviction is reachable and accepted
/// (R-D5): the walk never revisits a table, so an evicted
/// table is written exactly once and never reloaded.
const OVERLAY_L2_STAGING: usize = OVERLAY_REFBLOCKS_BUF + OVERLAY_REFBLOCKS_LIMIT;
const OVERLAY_L2_LIMIT: usize = 2 * 1024 * 1024;
/// Probe L2 buffer (decision 1): one cluster-sized slot holding
/// the ORIGINAL on-disk L2 table for the walk's current
/// `l1_idx`, reloaded on `l1_idx` change (the walk is
/// monotonic, so exactly one read per populated table).
const PROBE_L2_BUF: usize = OVERLAY_L2_STAGING + OVERLAY_L2_LIMIT;
const PROBE_L2_LIMIT: usize = 1024 * 1024;
/// Step window for the qcow2-write planner, carved as
/// `[Step; STEP_CAPACITY]` (scratch-carved, never `static` —
/// the `.bss`/HEADER_MISMATCH hazard class).
const STEP_BUF: usize = PROBE_L2_BUF + PROBE_L2_LIMIT;
const STEP_BUF_LIMIT: usize = 64 * 1024;
const STEP_CAPACITY: usize = STEP_BUF_LIMIT / core::mem::size_of::<Step>();
/// Cluster-sized planner bounce region (`RegionId::Bounce`).
const PLANNER_BOUNCE: usize = STEP_BUF + STEP_BUF_LIMIT;
const PLANNER_BOUNCE_LIMIT: usize = 1024 * 1024;
/// Residual scratch for `plan_rebase_qcow2`'s safe-mode
/// deferred-metadata plan (12-byte header rewrite + 1024-byte
/// path buffer = 1036 bytes needed). The deferred plan borrows
/// this region until `apply_rebase_plan` at the very end, so
/// nothing else may alias it.
const SAFE_PLAN_SCRATCH: usize = PLANNER_BOUNCE + PLANNER_BOUNCE_LIMIT;
const SAFE_PLAN_SCRATCH_LIMIT: usize = 2048;
/// Executor service buffer: sub-sector RMW bounce.
const RMW_SECTOR: usize = SAFE_PLAN_SCRATCH + SAFE_PLAN_SCRATCH_LIMIT;
const RMW_SECTOR_LIMIT: usize = MAX_SECTOR_SIZE;
/// Executor service buffer: ZeroRange/FillRange synthesis.
const FILL_SECTOR: usize = RMW_SECTOR + RMW_SECTOR_LIMIT;
const FILL_SECTOR_LIMIT: usize = MAX_SECTOR_SIZE;
/// Per-chain-device L1/L2 sector caches the qcow2 crate's
/// `Qcow2State` populates. Safe-mode rebase reads the old and
/// new backing chains through these states.
const CHAIN_CACHES: usize = FILL_SECTOR + FILL_SECTOR_LIMIT;
const CHAIN_CACHES_LIMIT: usize = MAX_CHAIN_DEVICES * 2 * MAX_SECTOR_SIZE;
/// Two cluster-sized buffers (`old_buf` and `new_buf`) the
/// comparison loop reads one cluster from each chain into.
/// `old_buf` doubles as `RegionId::CallerData` — the planner's
/// data source for the copy.
const COMPARE_BUFS: usize = CHAIN_CACHES + CHAIN_CACHES_LIMIT;
/// Per-side cluster buffer cap. Safe-mode rebase reads one
/// overlay cluster from each chain into a buffer of this size;
/// `cluster_size > COMPARE_BUF_SIZE` is rejected with
/// `ERROR_SCRATCH_TOO_SMALL`.
const COMPARE_BUF_SIZE: usize = 1024 * 1024;
const COMPARE_BUFS_LIMIT: usize = COMPARE_BUF_SIZE * 2;

// ----- -u / unsafe-detach / vmdk carve (aliases the ladder) --

/// Staged existing-file metadata for the untouched paths:
/// the vmdk descriptor, and the vmdk CID-probe scratch at the
/// tail. Original address and size.
const EXISTING_STATE: usize = HEADER_BUF + MAX_SECTOR_SIZE;
const EXISTING_STATE_LIMIT: usize = 4 * 1024 * 1024;
/// The byte buffer passed to `plan_rebase_*` by the untouched
/// `-u` and vmdk runners. Original address and size (the vmdk
/// planner requires `scratch >= descriptor slot size`).
const PLANNER_SCRATCH: usize = EXISTING_STATE + EXISTING_STATE_LIMIT;
const PLANNER_SCRATCH_LIMIT: usize = 4 * 1024 * 1024;

// Compile-time checks: both carves fit below the allocator
// heap (which sits at the top of scratch), and the step buffer
// is aligned for `[Step; N]`.
const _: () = assert!(
    COMPARE_BUFS + COMPARE_BUFS_LIMIT <= shared::ALLOC_HEAP_BASE,
    "rebase safe-mode scratch ladder overlaps the allocator heap"
);
const _: () = assert!(
    PLANNER_SCRATCH + PLANNER_SCRATCH_LIMIT <= shared::ALLOC_HEAP_BASE,
    "rebase unsafe/vmdk scratch carve overlaps the allocator heap"
);
const _: () = assert!(
    STEP_BUF % core::mem::align_of::<Step>() == 0,
    "step buffer must be aligned for [Step; N]"
);
const _: () = assert!(
    STEP_CAPACITY >= 512,
    "step window unexpectedly small; the decision-1 loop assumes 1300+ steps"
);
// At the largest cluster rebase accepts (COMPARE_BUF_SIZE), the
// planner bounce and the probe buffer still cover a whole
// cluster and the L2 window still has at least two slots.
const _: () = assert!(PLANNER_BOUNCE_LIMIT >= COMPARE_BUF_SIZE);
const _: () = assert!(PROBE_L2_LIMIT >= COMPARE_BUF_SIZE);
const _: () = assert!(OVERLAY_L2_LIMIT / COMPARE_BUF_SIZE >= 2);
// The deferred-metadata planner needs 12 + 1024 bytes.
const _: () = assert!(SAFE_PLAN_SCRATCH_LIMIT >= 12 + 1024);

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
    mode: u32,
    clusters_copied: u64,
    bytes_copied: u64,
    error: u32,
) {
    let result = RebaseResult {
        magic: RebaseResult::MAGIC,
        overlay_format,
        mode,
        error,
        clusters_copied,
        bytes_copied,
        _reserved: [0; 56],
    };
    (call_table.send_rebase_result)(&result);
}

fn err_result(overlay_format: u32, mode: u32, error: u32) -> RebaseResult {
    RebaseResult {
        magic: RebaseResult::MAGIC,
        overlay_format,
        mode,
        error,
        clusters_copied: 0,
        bytes_copied: 0,
        _reserved: [0; 56],
    }
}

/// Map a `RebaseError` from the planner crate to the matching
/// `RebaseResult::ERROR_*` wire code. Every variant has a
/// distinct destination after phase 3 step 3a appended codes
/// 7..=13.
fn map_rebase_error(e: RebaseError) -> u32 {
    match e {
        RebaseError::UnsupportedFormat | RebaseError::UnsupportedSubformat => {
            RebaseResult::ERROR_UNSUPPORTED_FORMAT
        }
        RebaseError::NewBackingIncompatible => RebaseResult::ERROR_NEW_BACKING_INCOMPATIBLE,
        RebaseError::ExternalDataFile => RebaseResult::ERROR_EXTERNAL_DATA_FILE,
        RebaseError::LuksUnsupported => RebaseResult::ERROR_LUKS_UNSUPPORTED,
        RebaseError::ChainDepth => RebaseResult::ERROR_CHAIN_DEPTH,
        RebaseError::HeaderMismatch => RebaseResult::ERROR_HEADER_MISMATCH,
        RebaseError::OverlayCorrupt => RebaseResult::ERROR_OVERLAY_CORRUPT,
        RebaseError::BackingPathTooLong => RebaseResult::ERROR_BACKING_PATH_TOO_LONG,
        RebaseError::ScratchTooSmall => RebaseResult::ERROR_SCRATCH_TOO_SMALL,
        RebaseError::RefcountExhausted => RebaseResult::ERROR_REFCOUNT_EXHAUSTED,
        RebaseError::DescriptorTooLarge => RebaseResult::ERROR_DESCRIPTOR_TOO_LARGE,
        RebaseError::ParseFailed => RebaseResult::ERROR_PARSE_FAILED,
        RebaseError::Overflow => RebaseResult::ERROR_INTERNAL_OVERFLOW,
    }
}

/// Map a `qcow2_write::Gate` envelope refusal on the OVERLAY
/// header to a `RebaseResult::ERROR_*` wire code (phase-5
/// decision 6). Every gate that duplicates an existing op or
/// planner gate keeps that gate's code — and is unreachable in
/// practice because those run first, in their existing order.
/// The genuinely new refusal family is
/// [`Gate::UnknownIncompatible`] (zstd / unknown incompatible
/// bits — rebase previously proceeded in violation of the
/// spec) plus [`Gate::ExtendedL2`] (safe mode previously
/// misread 16-byte L2 entries as 8-byte and silently corrupted
/// the overlay — divergence R-D1).
fn map_overlay_gate(gate: Gate) -> u32 {
    match gate {
        Gate::UnknownIncompatible | Gate::ExtendedL2 => RebaseResult::ERROR_OVERLAY_UNSUPPORTED,
        Gate::RefcountWidth => RebaseResult::ERROR_UNSUPPORTED_FORMAT,
        Gate::ExternalDataFile => RebaseResult::ERROR_EXTERNAL_DATA_FILE,
        Gate::Encryption => RebaseResult::ERROR_LUKS_UNSUPPORTED,
        Gate::DirtyCorrupt => RebaseResult::ERROR_OVERLAY_CORRUPT,
        Gate::HasSnapshots => RebaseResult::ERROR_OVERLAY_HAS_SNAPSHOTS,
        // QcowHeader::parse cannot yield other versions; defends
        // direct construction.
        Gate::UnsupportedVersion => RebaseResult::ERROR_PARSE_FAILED,
        // Caller-config refusal: the op built an out-of-range
        // StagingConfig (an op bug, not an image property).
        Gate::InvalidStagingConfig => RebaseResult::ERROR_SCRATCH_TOO_SMALL,
    }
}

/// Map a `qcow2_write::WriteError` from `plan_write` /
/// `plan_flush` to a `RebaseResult::ERROR_*` wire code (phase-5
/// decision 6). `BufFull` is the windowing resume signal, never
/// surfaced as an error — the driving loop consumes it; it only
/// lands here if the loop is broken (an op bug).
fn map_write_error(e: WriteError) -> u32 {
    match e {
        // The allocator ran out of staged refblocks; phase 6's
        // refcount-growth planner lifts this. Keeps wire 10 and
        // its message (pinned by TestRebaseStagedL2Growth).
        WriteError::RefcountExhausted => RebaseResult::ERROR_REFCOUNT_EXHAUSTED,
        // Unreachable behind the decision-1 skip probe (any
        // non-zero original L2 entry — compressed included —
        // skips the cluster before the planner sees it); mapped
        // defensively to the existing unsupported-format code.
        WriteError::CompressedCluster => RebaseResult::ERROR_UNSUPPORTED_FORMAT,
        // Classification refusals on inconsistent-but-gate-
        // passing overlays (divergence R-D3/R-D4).
        // NeedsBackingFill is unreachable for rebase's
        // full-cluster (EOV-tail-clamped) requests after the 4q
        // amendment; mapped here defensively.
        WriteError::SnapshotShared
        | WriteError::SnapshotSharedL2Table
        | WriteError::RefcountInconsistent
        | WriteError::RefcountCoverage
        | WriteError::UnknownL1Entry
        | WriteError::UnknownL2Entry
        | WriteError::StagedRegionsMismatch
        | WriteError::NeedsBackingFill => RebaseResult::ERROR_OVERLAY_INCONSISTENT,
        // Planner-protocol misuse or bounds violations indicate
        // an op bug, not an image property — the same family as
        // the guest-side arithmetic checks.
        WriteError::BufFull
        | WriteError::NotImplemented
        | WriteError::OutOfBounds
        | WriteError::ResumeMismatch => RebaseResult::ERROR_INTERNAL_OVERFLOW,
    }
}

// ---------------------------------------------------------------------------
// Sector-level I/O helpers (modelled on resize)
// ---------------------------------------------------------------------------

/// Read `len` bytes starting at `byte_offset` into the buffer
/// at `dst_ptr`. Handles non-sector-aligned starts/ends via a
/// small bounce buffer at `HEADER_BUF`.
unsafe fn read_byte_range(
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

/// Write `bytes` starting at `byte_offset`. Handles partial
/// leading/trailing sectors via read-modify-write through the
/// bounce buffer at `HEADER_BUF`.
unsafe fn write_byte_range(
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

/// Apply a complete `RebasePlan` to the output device.
/// Patches are applied in slice order; ordering is load-
/// bearing for crash safety (path bytes before header field
/// rewrite, refcount/L2 before path relocation Append).
unsafe fn apply_rebase_plan(call_table: &CallTable, plan: &RebasePlan<'_>) -> bool {
    let sector_size = (call_table.get_output_sector_size)();
    for patch in plan.patches() {
        let ok = match patch {
            RebasePatch::Write { byte_offset, bytes }
            | RebasePatch::Append { byte_offset, bytes } => {
                write_byte_range(call_table, sector_size, *byte_offset, bytes)
            }
        };
        if !ok {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Per-format runners (stubs in step 3b)
// ---------------------------------------------------------------------------

/// qcow2 rebase runner.
///
/// Dispatches on the `FLAG_UNSAFE` bit of [`RebaseConfig`] and
/// delegates to [`run_qcow2_unsafe`] or [`run_qcow2_safe`].
/// Safe mode is a stub in step 3c that returns
/// `ERROR_UNSUPPORTED_FORMAT`; step 3e fills it in.
unsafe fn run_qcow2(call_table: &CallTable, config: &RebaseConfig) -> RebaseResult {
    if config.is_unsafe() {
        run_qcow2_unsafe(call_table, config)
    } else {
        run_qcow2_safe(call_table, config)
    }
}

/// qcow2 unsafe-mode (`-u`) rebase: reads the overlay header,
/// calls the planner with `RebaseMode::Unsafe`, and applies
/// the resulting patches in order. No chain comparison, no
/// data copy.
unsafe fn run_qcow2_unsafe(call_table: &CallTable, config: &RebaseConfig) -> RebaseResult {
    let sector_size = (call_table.get_output_sector_size)();
    let header_bytes = core::slice::from_raw_parts(HEADER_BUF as *const u8, sector_size);

    // The overlay's file size is the host's capacity hint (in
    // sectors). Unsafe mode does not grow the file, so any
    // value the planner can subsequently treat as "current EOF"
    // is fine.
    let capacity_sectors = (call_table.get_output_capacity)();
    let overlay_file_size = capacity_sectors.saturating_mul(sector_size as u64);

    // The new backing path slice; only the first
    // new_backing_path_len bytes are valid input.
    let path_len = config.new_backing_path_len as usize;
    let new_backing_path = if path_len <= config.new_backing_path.len() {
        &config.new_backing_path[..path_len]
    } else {
        // Defensive: a malformed host-side config that
        // claims a longer length than the buffer holds is
        // a parse failure.
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_UNSAFE,
            RebaseResult::ERROR_PARSE_FAILED,
        );
    };

    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Unsafe,
        overlay_header: header_bytes,
        overlay_file_size,
        refcount_table: &[],
        refblock_host_offsets: &[],
        refcount_blocks: &[],
        refblock_count: 0,
        new_backing_virtual_size: config.overlay_virtual_size,
        new_backing_path,
        detach: config.is_detach(),
    };

    let scratch =
        core::slice::from_raw_parts_mut(PLANNER_SCRATCH as *mut u8, PLANNER_SCRATCH_LIMIT);
    let out = match plan_rebase_qcow2(&opts, scratch) {
        Ok(o) => o,
        Err(e) => {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_UNSAFE,
                map_rebase_error(e),
            );
        }
    };

    let plan = match out {
        Qcow2RebaseOutput::Unsafe { plan } => plan,
        Qcow2RebaseOutput::Safe { .. } => {
            // Defensive: the planner shouldn't return Safe
            // when we asked for Unsafe; if it does, treat it
            // as an internal mismatch.
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_UNSAFE,
                RebaseResult::ERROR_INTERNAL_OVERFLOW,
            );
        }
    };

    if !apply_rebase_plan(call_table, &plan) {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_UNSAFE,
            RebaseResult::ERROR_HEADER_MISMATCH,
        );
    }

    RebaseResult {
        magic: RebaseResult::MAGIC,
        overlay_format: config.overlay_format,
        mode: RebaseResult::MODE_UNSAFE,
        error: RebaseResult::ERROR_OK,
        clusters_copied: 0,
        bytes_copied: 0,
        _reserved: [0; 56],
    }
}

// ---------------------------------------------------------------------------
// qcow2 safe-mode staging + step-window plumbing (phase 5)
// ---------------------------------------------------------------------------

/// Geometry of the safe-mode scratch carve for one run,
/// threaded to the [`StagedRegions`] / [`Regions`] view
/// builders so the planner and executor alias the exact same
/// buffers (the two halves of the qcow2-write decision-1 loop).
#[derive(Clone, Copy)]
struct OverlayCarve {
    cluster_size: usize,
    /// Staged overlay L1 bytes at `OVERLAY_L1_BUF` (and the
    /// original copy at `ORIG_L1_BUF`).
    l1_bytes: usize,
    /// Staged refcount-table prefix bytes at `OVERLAY_RT_BUF`.
    rt_bytes: usize,
    /// Staged refblock bytes (dense prefix) at
    /// `OVERLAY_REFBLOCKS_BUF`.
    rb_bytes: usize,
    /// L2 window bytes (`l2_slots * cluster_size`) at
    /// `OVERLAY_L2_STAGING`.
    l2_window_bytes: usize,
}

/// The planner's view of the staged overlay buffers.
///
/// # Safety
///
/// The returned slices alias the fixed scratch regions; the
/// caller must not hold a [`Regions`] view (or any other
/// aliasing borrow) at the same time. The decision-1 loop
/// guarantees this: plan with the staged view, drop it, execute
/// with the regions view.
unsafe fn staged_view<'a>(carve: &OverlayCarve) -> StagedRegions<'a> {
    StagedRegions {
        l1: core::slice::from_raw_parts(OVERLAY_L1_BUF as *const u8, carve.l1_bytes),
        l2_window: core::slice::from_raw_parts(
            OVERLAY_L2_STAGING as *const u8,
            carve.l2_window_bytes,
        ),
        refcount_table: core::slice::from_raw_parts(OVERLAY_RT_BUF as *const u8, carve.rt_bytes),
        refblocks: core::slice::from_raw_parts_mut(
            OVERLAY_REFBLOCKS_BUF as *mut u8,
            carve.rb_bytes,
        ),
    }
}

/// Execute the emitted step window against the scratch-carved
/// regions and reset the buffer. Returns `false` if any step's
/// device I/O failed (the caller maps that to
/// `ERROR_HEADER_MISMATCH`, the code the replaced
/// `write_byte_range` call sites used).
///
/// # Safety
///
/// As for [`staged_view`]: the regions alias the fixed scratch
/// carve, so no [`StagedRegions`] view may be live across this
/// call.
unsafe fn exec_window(
    io: &mut CallTableIo<'_>,
    steps: &mut StepBuf<'_>,
    carve: &OverlayCarve,
) -> bool {
    let mut regions = Regions {
        l1: core::slice::from_raw_parts_mut(OVERLAY_L1_BUF as *mut u8, carve.l1_bytes),
        l2_window: core::slice::from_raw_parts_mut(
            OVERLAY_L2_STAGING as *mut u8,
            carve.l2_window_bytes,
        ),
        refcount_table: core::slice::from_raw_parts_mut(OVERLAY_RT_BUF as *mut u8, carve.rt_bytes),
        refblocks: core::slice::from_raw_parts_mut(
            OVERLAY_REFBLOCKS_BUF as *mut u8,
            carve.rb_bytes,
        ),
        bounce: core::slice::from_raw_parts_mut(PLANNER_BOUNCE as *mut u8, carve.cluster_size),
        caller_data: core::slice::from_raw_parts_mut(COMPARE_BUFS as *mut u8, carve.cluster_size),
        rmw_sector: core::slice::from_raw_parts_mut(RMW_SECTOR as *mut u8, RMW_SECTOR_LIMIT),
        fill_sector: core::slice::from_raw_parts_mut(FILL_SECTOR as *mut u8, FILL_SECTOR_LIMIT),
        cluster_size: carve.cluster_size,
    };
    let ok = execute(steps.steps(), &mut regions, io).is_ok();
    steps.reset();
    ok
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

/// Stage the overlay's L1 (twice: the planner's mutable copy
/// and the skip probe's read-only original), refcount-table
/// prefix and refblocks for the qcow2-write planner. Refblocks
/// are staged per the [`StagedRegions`] dense-prefix contract:
/// the populated refcount-table entries must run gap-free from
/// index 0 (bench's contiguity gate). A sparse (holed) refcount
/// table refuses as `ERROR_OVERLAY_INCONSISTENT` BEFORE any
/// mutation — under the old dense-compaction staging this shape
/// was silently misallocated (divergence R-D4, a live defect:
/// holed RTs are stock-producible via discard + `qemu-img
/// resize --shrink` and pass `qemu-img check`; the rebase
/// sibling of GitHub issue #428). Entries with reserved low
/// bits or a missing/misaligned masked offset refuse the same
/// way.
///
/// # Safety
///
/// `call_table` must be the validated CallTable and the scratch
/// carve unused by any live view.
#[inline(never)]
unsafe fn stage_overlay_qcow2(
    call_table: &CallTable,
    sector_size: usize,
    overlay: &QcowHeader,
) -> Result<OverlayCarve, u32> {
    let cluster_size_usize = overlay.cluster_size as usize;

    // Overlay L1: read once, then duplicate into the probe's
    // original copy (identical bytes, one device read).
    let l1_bytes = (overlay.l1_size as usize).saturating_mul(8);
    if l1_bytes > OVERLAY_L1_LIMIT {
        return Err(RebaseResult::ERROR_SCRATCH_TOO_SMALL);
    }
    if l1_bytes > 0 {
        if !read_byte_range(
            call_table,
            sector_size,
            overlay.l1_table_offset,
            OVERLAY_L1_BUF as *mut u8,
            l1_bytes,
        ) {
            return Err(RebaseResult::ERROR_PARSE_FAILED);
        }
        core::ptr::copy_nonoverlapping(
            OVERLAY_L1_BUF as *const u8,
            ORIG_L1_BUF as *mut u8,
            l1_bytes,
        );
    }

    // Overlay refcount table: a bounded prefix (bench's model).
    // The planner reads only the entries covering the staged
    // refblocks; entries beyond the prefix would describe
    // refblocks past the staging cap anyway.
    let rt_size = (overlay.refcount_table_clusters as usize).saturating_mul(cluster_size_usize);
    let rt_bytes = rt_size.min(OVERLAY_RT_LIMIT);
    if rt_bytes > 0
        && !read_byte_range(
            call_table,
            sector_size,
            overlay.refcount_table_offset,
            OVERLAY_RT_BUF as *mut u8,
            rt_bytes,
        )
    {
        return Err(RebaseResult::ERROR_PARSE_FAILED);
    }
    let rt = core::slice::from_raw_parts(OVERLAY_RT_BUF as *const u8, rt_bytes);

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
                    return Err(RebaseResult::ERROR_OVERLAY_INCONSISTENT);
                }
                let host = entry & L1_OFFSET_MASK;
                if entry & 0x1ff != 0 || host == 0 || host % cluster_size_usize as u64 != 0 {
                    return Err(RebaseResult::ERROR_OVERLAY_INCONSISTENT);
                }
                refblock_count += 1;
            }
            i += 8;
        }
    }

    // Capacity: staged bytes and the crate's count cap. The
    // old MAX_REFBLOCKS staging refusal was also
    // ERROR_SCRATCH_TOO_SMALL, so the code is unchanged.
    let refblock_cap = qcow2_write::MAX_REFBLOCKS.min(OVERLAY_REFBLOCKS_LIMIT / cluster_size_usize);
    if refblock_count > refblock_cap {
        return Err(RebaseResult::ERROR_SCRATCH_TOO_SMALL);
    }
    for j in 0..refblock_count {
        let host = read_u64_be(rt, j * 8) & L1_OFFSET_MASK;
        let dst = (OVERLAY_REFBLOCKS_BUF + j * cluster_size_usize) as *mut u8;
        if !read_byte_range(call_table, sector_size, host, dst, cluster_size_usize) {
            return Err(RebaseResult::ERROR_PARSE_FAILED);
        }
    }

    let l2_slots = MAX_L2_SLOTS.min(OVERLAY_L2_LIMIT / cluster_size_usize);
    Ok(OverlayCarve {
        cluster_size: cluster_size_usize,
        l1_bytes,
        rt_bytes,
        rb_bytes: refblock_count * cluster_size_usize,
        l2_window_bytes: l2_slots * cluster_size_usize,
    })
}

/// qcow2 safe-mode rebase. Validates the overlay, plans the
/// deferred header/backing-path metadata via the rebase
/// planner, stages the overlay's metadata for qcow2-write,
/// walks every guest cluster (skipping clusters the ORIGINAL
/// overlay already mapped), and for clusters whose old-chain
/// content differs from the new-chain content plans a copy
/// into the overlay through `qcow2_write::plan_write` so the
/// swap to the new backing preserves the overlay's observed
/// semantics.
///
/// `#[inline(never)]` is load-bearing: built for
/// `x86_64-unknown-none` with `opt-level = "z"` + `lto = true`,
/// inlining a large runner into the `extern "C"` `_start` can
/// miscompile it (see the note on `run_qcow2` in
/// `src/operations/amend/src/main.rs`). The phase-5 rework made
/// this function strictly larger, so keep it out of line.
#[inline(never)]
unsafe fn run_qcow2_safe(call_table: &CallTable, config: &RebaseConfig) -> RebaseResult {
    let sector_size = (call_table.get_output_sector_size)();
    // Copy the header out of HEADER_BUF before any other reads:
    // `read_byte_range` uses HEADER_BUF as a sub-sector bounce
    // buffer, so any partial-sector staging read (L1, refcount
    // table, etc.) would clobber HEADER_BUF and break the
    // planner's re-parse downstream. The stable copy lives in
    // its own ladder slot.
    let stable_header_ptr = STABLE_HEADER_BUF as *mut u8;
    core::ptr::copy_nonoverlapping(HEADER_BUF as *const u8, stable_header_ptr, sector_size);
    let header_bytes = core::slice::from_raw_parts(stable_header_ptr, sector_size);

    let parsed = match QcowHeader::parse(header_bytes) {
        Some(p) => p,
        None => {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_SAFE,
                RebaseResult::ERROR_PARSE_FAILED,
            );
        }
    };

    // v1 covers refcount_bits == 16 only; this matches the
    // planner's safe-mode coverage (see qcow2.rs step 2c).
    if parsed.refcount_bits != 16 {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_SAFE,
            RebaseResult::ERROR_UNSUPPORTED_FORMAT,
        );
    }

    // Interim phase-2 gate (GitHub issue #421): refuse
    // safe-mode rebase of an overlay with internal snapshots
    // before any staging or writes. Safe mode writes new
    // mappings into snapshot-shared L2 tables in place and sets
    // refcount=1 on clusters that two L1 trees reference, so a
    // routine `qemu-img snapshot -d` afterwards frees clusters
    // the active view still maps — physical data loss. This
    // runner is only entered without FLAG_UNSAFE (see
    // `run_qcow2`), so the gate also covers safe detach; the
    // `-u` metadata-only path only rewrites the header region,
    // which is never snapshot-shared, and stays allowed. The
    // real fix (snapshot-aware COW) lands in phase 7 of
    // PLAN-qcow2-write-infrastructure.
    if parsed.nb_snapshots > 0 {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_SAFE,
            RebaseResult::ERROR_OVERLAY_HAS_SNAPSHOTS,
        );
    }

    let cluster_size = parsed.cluster_size;
    if cluster_size == 0 || cluster_size > COMPARE_BUF_SIZE as u64 {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_SAFE,
            RebaseResult::ERROR_SCRATCH_TOO_SMALL,
        );
    }
    let cluster_size_usize = cluster_size as usize;

    let path_len = config.new_backing_path_len as usize;
    let new_backing_path = if path_len <= config.new_backing_path.len() {
        &config.new_backing_path[..path_len]
    } else {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_SAFE,
            RebaseResult::ERROR_PARSE_FAILED,
        );
    };

    // ----- Plan the rebase via the safe-mode planner -------
    // The slimmed planner performs the legacy shared validation
    // (dirty/corrupt bits, external data, LUKS, oversized or
    // mismatched path, new-backing size) in its existing order
    // and returns the overlay geometry plus the deferred
    // header/backing-path patch group applied after the loop.
    // The deferred plan borrows SAFE_PLAN_SCRATCH until
    // `apply_rebase_plan` at the very end.
    let capacity_sectors = (call_table.get_output_capacity)();
    let overlay_file_size = capacity_sectors.saturating_mul(sector_size as u64);

    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Safe,
        overlay_header: header_bytes,
        overlay_file_size,
        refcount_table: &[],
        refblock_host_offsets: &[],
        refcount_blocks: &[],
        refblock_count: 0,
        new_backing_virtual_size: config.overlay_virtual_size,
        new_backing_path,
        detach: config.is_detach(),
    };

    let planner_scratch =
        core::slice::from_raw_parts_mut(SAFE_PLAN_SCRATCH as *mut u8, SAFE_PLAN_SCRATCH_LIMIT);
    let out = match plan_rebase_qcow2(&opts, planner_scratch) {
        Ok(o) => o,
        Err(e) => {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_SAFE,
                map_rebase_error(e),
            );
        }
    };

    let (context, deferred_metadata) = match out {
        Qcow2RebaseOutput::Safe {
            context,
            deferred_metadata,
        } => (context, deferred_metadata),
        Qcow2RebaseOutput::Unsafe { .. } => {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_SAFE,
                RebaseResult::ERROR_INTERNAL_OVERFLOW,
            );
        }
    };

    // ----- qcow2-write envelope on the overlay (decision 6) --
    // Runs after the op gates and the planner's legacy
    // validation, which together cover every Gate except
    // UnknownIncompatible and ExtendedL2 with their existing
    // codes — so the only refusals this adds are the
    // spec-mandated zstd/unknown-incompatible-bit gate and the
    // extended-L2 gate (ERROR_OVERLAY_UNSUPPORTED; divergence
    // R-D1 — extended-L2 safe rebase was live silent
    // corruption). Before any staging or mutation.
    if let Err(gate) = check_envelope(&parsed) {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_SAFE,
            map_overlay_gate(gate),
        );
    }

    // ----- Stage overlay metadata (qcow2-write carve) --------
    // L1 (twice: planner + probe copies), refcount-table
    // prefix, and refblocks as a dense prefix, contiguity-gated
    // (divergence R-D4's fix — pre-mutation refusal of the
    // holed-RT shape the old dense compaction misallocated).
    // Pre-existing L2 tables are no longer staged eagerly: the
    // qcow2-write planner loads them into the fixed-slot window
    // on demand, and the skip probe reads the ORIGINAL tables
    // through its own buffer (this lifts the old MAX_STAGED_L2
    // staging refusal — the R-D6 widening).
    let carve = match stage_overlay_qcow2(call_table, sector_size, &parsed) {
        Ok(c) => c,
        Err(code) => {
            return err_result(config.overlay_format, RebaseResult::MODE_SAFE, code);
        }
    };

    // ----- qcow2-write planner state -------------------------
    let staging_config = StagingConfig {
        l2_slots: carve.l2_window_bytes / cluster_size_usize,
        max_refblocks: qcow2_write::MAX_REFBLOCKS.min(OVERLAY_REFBLOCKS_LIMIT / cluster_size_usize),
        device: TargetDevice::Output,
    };
    let mut wstate: WriteState = match new_state(&parsed, &staging_config) {
        Ok(s) => s,
        Err(gate) => {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_SAFE,
                map_overlay_gate(gate),
            );
        }
    };
    let step_storage = init_step_storage();
    let mut step_buf = StepBuf::new(step_storage);
    // The rebase guest's input slots are read-only chain
    // members and every emitted step targets the fsync-less
    // Output device (the overlay), so Durability barriers
    // degrade to Ordering — zero fsyncs, exactly as before
    // (divergence R-D8).
    let mut io = CallTableIo::new(call_table, false);

    // ----- Initialise chain-reader state -------------------
    let chain_config = &*(CHAIN_CONFIG_ADDR as *const ChainConfig);
    if !chain_config.is_valid() {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_SAFE,
            RebaseResult::ERROR_PARSE_FAILED,
        );
    }

    let device_count = {
        let old_end = config
            .old_chain_first
            .saturating_add(config.old_chain_count);
        let new_end = config
            .new_chain_first
            .saturating_add(config.new_chain_count);
        old_end.max(new_end) as usize
    };
    if device_count > MAX_CHAIN_DEVICES {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_SAFE,
            RebaseResult::ERROR_CHAIN_DEPTH,
        );
    }

    let mut chain_states = qcow2::ChainStates::default();
    let mut bytes_read: u64 = 0;
    if device_count > 0
        && !qcow2::init_chain_states(
            call_table,
            chain_config,
            &mut chain_states,
            device_count,
            sector_size,
            CHAIN_CACHES,
            &mut bytes_read,
        )
    {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_SAFE,
            RebaseResult::ERROR_PARSE_FAILED,
        );
    }

    // ----- Per-cluster comparison loop ---------------------
    let old_buf = COMPARE_BUFS as *mut u8;
    let new_buf = old_buf.add(COMPARE_BUF_SIZE);
    let entries_per_l2 = cluster_size / 8;
    let mut clusters_copied: u64 = 0;
    let mut bytes_copied: u64 = 0;

    let orig_l1 = core::slice::from_raw_parts(ORIG_L1_BUF as *const u8, carve.l1_bytes);
    // l1_idx of the ORIGINAL L2 table currently held in the
    // probe buffer; u64::MAX means none. The walk is monotonic
    // in l1_idx, so each populated original table is read
    // exactly once.
    let mut probe_loaded_l1_idx: u64 = u64::MAX;

    for cluster_idx in 0..context.overlay_cluster_count {
        let guest_offset = cluster_idx.checked_mul(cluster_size).ok_or(()).unwrap_or(0);

        let l1_idx = cluster_idx / entries_per_l2;
        let l2_inner_idx = (cluster_idx % entries_per_l2) as usize;
        if l1_idx >= parsed.l1_size as u64 {
            // Guest offset is past the L1 table's coverage —
            // nothing more to compare.
            break;
        }
        let l1_idx_usize = l1_idx as usize;

        // Skip probe (phase-5 decision 1): consult the
        // ORIGINAL pre-run overlay mapping only. A cluster the
        // overlay already mapped before this run is skipped —
        // any non-zero L2 entry (compressed, zero-flag and
        // garbage entries included), byte-for-byte today's
        // predicate. The probe NEVER consults the planner's
        // staged L1 or window: patches only ever cover
        // already-visited clusters, and fresh tables were
        // L1-empty originally (unmapped by definition — never
        // probed from disk).
        let orig_l1_entry = read_u64_be(orig_l1, l1_idx_usize * 8);
        if orig_l1_entry & L1_OFFSET_MASK != 0 {
            let orig_l2_host = orig_l1_entry & L1_OFFSET_MASK;
            if probe_loaded_l1_idx != l1_idx {
                let dst =
                    core::slice::from_raw_parts_mut(PROBE_L2_BUF as *mut u8, cluster_size_usize);
                let rmw = core::slice::from_raw_parts_mut(RMW_SECTOR as *mut u8, RMW_SECTOR_LIMIT);
                if read_bytes(&mut io, TargetDevice::Output, orig_l2_host, dst, rmw).is_err() {
                    return err_result(
                        config.overlay_format,
                        RebaseResult::MODE_SAFE,
                        RebaseResult::ERROR_PARSE_FAILED,
                    );
                }
                probe_loaded_l1_idx = l1_idx;
            }
            let entry = {
                let probe =
                    core::slice::from_raw_parts(PROBE_L2_BUF as *const u8, cluster_size_usize);
                read_u64_be(probe, l2_inner_idx * 8)
            };
            if entry != 0 {
                // Overlay already owned the cluster before the
                // run; nothing to copy.
                continue;
            }
        }

        // Read the old and new chains at this guest offset.
        if !read_chain_cluster(
            call_table,
            config.old_chain_first,
            config.old_chain_count,
            chain_config,
            &mut chain_states,
            guest_offset,
            cluster_size,
            old_buf,
            sector_size,
        ) {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_SAFE,
                RebaseResult::ERROR_PARSE_FAILED,
            );
        }
        if !read_chain_cluster(
            call_table,
            config.new_chain_first,
            config.new_chain_count,
            chain_config,
            &mut chain_states,
            guest_offset,
            cluster_size,
            new_buf,
            sector_size,
        ) {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_SAFE,
                RebaseResult::ERROR_PARSE_FAILED,
            );
        }

        if buffers_eq(old_buf, new_buf, cluster_size_usize) {
            continue;
        }

        // Divergent: plan the copy of the old-chain content
        // into the overlay through qcow2-write (allocation,
        // classification, L2 window management) and execute
        // each emitted window via the step executor. The
        // request is the full cluster, clamped to the virtual
        // size on the tail cluster of an unaligned image (the
        // 4q EOV-tail rule / divergence R-D9 — bytes beyond
        // EOV are not virtual content; the planner zero-fills
        // the beyond-EOV remainder). `old_buf` doubles as
        // `RegionId::CallerData`.
        let win_len = cluster_size.min(parsed.virtual_size - guest_offset);
        loop {
            let planned = {
                let mut staged = staged_view(&carve);
                plan_write(
                    &mut wstate,
                    &mut staged,
                    guest_offset,
                    win_len,
                    DataSource::CallerData { offset: 0 },
                    &mut step_buf,
                )
            };
            match planned {
                Ok(_) => {
                    if !exec_window(&mut io, &mut step_buf, &carve) {
                        return err_result(
                            config.overlay_format,
                            RebaseResult::MODE_SAFE,
                            RebaseResult::ERROR_HEADER_MISMATCH,
                        );
                    }
                    break;
                }
                Err(WriteError::BufFull) => {
                    // Window boundary (buffer full or a
                    // LoadCluster whose bytes the planner
                    // needs): execute, reset, resume with
                    // IDENTICAL arguments.
                    if !exec_window(&mut io, &mut step_buf, &carve) {
                        return err_result(
                            config.overlay_format,
                            RebaseResult::MODE_SAFE,
                            RebaseResult::ERROR_HEADER_MISMATCH,
                        );
                    }
                }
                Err(e) => {
                    // Execute the already-emitted window FIRST:
                    // this reproduces the pre-migration
                    // bytes-written-up-to-the-refusal behaviour,
                    // keeping refusal paths byte-identical to
                    // the old composition (divergence R-D10 /
                    // commit 4b's rule). The planner error
                    // dominates any exec failure.
                    let _ = exec_window(&mut io, &mut step_buf, &carve);
                    return err_result(
                        config.overlay_format,
                        RebaseResult::MODE_SAFE,
                        map_write_error(e),
                    );
                }
            }
        }

        clusters_copied += 1;
        bytes_copied = bytes_copied.saturating_add(cluster_size);
    }

    // ----- Flush dirty overlay metadata --------------------
    // One plan_flush epoch: dirty L2 window slots → staged L1
    // (if dirty) → dirty refblocks (refcounts last), the same
    // final bytes as the old inline flush. Barriers degrade to
    // Ordering on the fsync-less output device (R-D8). The
    // deferred header/backing-path patch group lands AFTER
    // this — preserving the "header lands after refcounts"
    // order.
    loop {
        let planned = {
            let mut staged = staged_view(&carve);
            plan_flush(&mut wstate, &mut staged, &mut step_buf)
        };
        match planned {
            Ok(_) => {
                if !exec_window(&mut io, &mut step_buf, &carve) {
                    return err_result(
                        config.overlay_format,
                        RebaseResult::MODE_SAFE,
                        RebaseResult::ERROR_HEADER_MISMATCH,
                    );
                }
                break;
            }
            Err(WriteError::BufFull) => {
                if !exec_window(&mut io, &mut step_buf, &carve) {
                    return err_result(
                        config.overlay_format,
                        RebaseResult::MODE_SAFE,
                        RebaseResult::ERROR_HEADER_MISMATCH,
                    );
                }
            }
            Err(e) => {
                let _ = exec_window(&mut io, &mut step_buf, &carve);
                return err_result(
                    config.overlay_format,
                    RebaseResult::MODE_SAFE,
                    map_write_error(e),
                );
            }
        }
    }

    if !apply_rebase_plan(call_table, &deferred_metadata) {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_SAFE,
            RebaseResult::ERROR_HEADER_MISMATCH,
        );
    }

    RebaseResult {
        magic: RebaseResult::MAGIC,
        overlay_format: config.overlay_format,
        mode: RebaseResult::MODE_SAFE,
        error: RebaseResult::ERROR_OK,
        clusters_copied,
        bytes_copied,
        _reserved: [0; 56],
    }
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

/// Byte-equality compare of two raw buffers. Reads in usize
/// chunks where alignment allows; otherwise falls back to a
/// byte loop. Both pointers must point to at least `len` bytes.
unsafe fn buffers_eq(a: *const u8, b: *const u8, len: usize) -> bool {
    let mut i = 0;
    while i < len {
        if *a.add(i) != *b.add(i) {
            return false;
        }
        i += 1;
    }
    true
}

/// vmdk rebase runner.
///
/// v1 only supports unsafe mode. Safe mode is blocked on
/// phase 2 step 2e (the grain allocator) and returns
/// `ERROR_UNSUPPORTED_FORMAT` for now.
unsafe fn run_vmdk(call_table: &CallTable, config: &RebaseConfig) -> RebaseResult {
    if config.is_unsafe() {
        run_vmdk_unsafe(call_table, config)
    } else {
        err_result(
            config.overlay_format,
            RebaseResult::MODE_SAFE,
            RebaseResult::ERROR_UNSUPPORTED_FORMAT,
        )
    }
}

/// vmdk monolithicSparse unsafe-mode rebase.
unsafe fn run_vmdk_unsafe(call_table: &CallTable, config: &RebaseConfig) -> RebaseResult {
    let sector_size = (call_table.get_output_sector_size)();
    let header_bytes = core::slice::from_raw_parts(HEADER_BUF as *const u8, sector_size);

    // Parse the overlay's binary header to get descriptor
    // location and virtual size.
    let parsed = match vmdk::Vmdk4Header::parse(header_bytes) {
        Some(p) => p,
        None => {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_UNSAFE,
                RebaseResult::ERROR_PARSE_FAILED,
            );
        }
    };

    let desc_byte_offset = match parsed.desc_offset_sectors.checked_mul(512) {
        Some(v) => v,
        None => {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_UNSAFE,
                RebaseResult::ERROR_INTERNAL_OVERFLOW,
            );
        }
    };
    let desc_byte_size = match parsed.desc_size_sectors.checked_mul(512) {
        Some(v) => v,
        None => {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_UNSAFE,
                RebaseResult::ERROR_INTERNAL_OVERFLOW,
            );
        }
    };
    let desc_byte_size_usize = desc_byte_size as usize;
    if desc_byte_size_usize > EXISTING_STATE_LIMIT {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_UNSAFE,
            RebaseResult::ERROR_SCRATCH_TOO_SMALL,
        );
    }

    // Read the descriptor region into EXISTING_STATE scratch.
    let desc_ptr = EXISTING_STATE as *mut u8;
    if !read_byte_range(
        call_table,
        sector_size,
        desc_byte_offset,
        desc_ptr,
        desc_byte_size_usize,
    ) {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_UNSAFE,
            RebaseResult::ERROR_PARSE_FAILED,
        );
    }
    let descriptor_bytes = core::slice::from_raw_parts(desc_ptr, desc_byte_size_usize);

    // Resolve the new parent CID by probing the first device
    // of the new chain (if any). The descriptor rewriter
    // falls back to the qemu-img sentinel 0xffffffff when
    // we can't extract a real CID (non-vmdk backing, detach,
    // or read failure).
    let new_parent_cid = if config.is_detach() || config.new_chain_count == 0 {
        0xffff_ffff_u32
    } else {
        extract_parent_cid_from_input(call_table, config.new_chain_first, sector_size)
            .unwrap_or(0xffff_ffff)
    };

    let path_len = config.new_backing_path_len as usize;
    let new_backing_path = if path_len <= config.new_backing_path.len() {
        &config.new_backing_path[..path_len]
    } else {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_UNSAFE,
            RebaseResult::ERROR_PARSE_FAILED,
        );
    };

    let opts = VmdkRebaseOpts::unsafe_only(
        parsed.virtual_size,
        descriptor_bytes,
        desc_byte_size as u32,
        desc_byte_offset,
        parsed.virtual_size,
        new_backing_path,
        new_parent_cid,
        config.is_detach(),
    );

    let scratch =
        core::slice::from_raw_parts_mut(PLANNER_SCRATCH as *mut u8, PLANNER_SCRATCH_LIMIT);
    let out = match plan_rebase_vmdk(&opts, scratch) {
        Ok(o) => o,
        Err(e) => {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_UNSAFE,
                map_rebase_error(e),
            );
        }
    };

    let plan = match out {
        VmdkRebaseOutput::Unsafe { plan } => plan,
        VmdkRebaseOutput::Safe { .. } => {
            return err_result(
                config.overlay_format,
                RebaseResult::MODE_UNSAFE,
                RebaseResult::ERROR_INTERNAL_OVERFLOW,
            );
        }
    };

    if !apply_rebase_plan(call_table, &plan) {
        return err_result(
            config.overlay_format,
            RebaseResult::MODE_UNSAFE,
            RebaseResult::ERROR_HEADER_MISMATCH,
        );
    }

    RebaseResult {
        magic: RebaseResult::MAGIC,
        overlay_format: config.overlay_format,
        mode: RebaseResult::MODE_UNSAFE,
        error: RebaseResult::ERROR_OK,
        clusters_copied: 0,
        bytes_copied: 0,
        _reserved: [0; 56],
    }
}

/// Probe an input device's sector 0 for a vmdk header and, if
/// found, follow it to the descriptor and extract the
/// `CID=` value. Returns `None` for non-vmdk or unparseable
/// input. Uses the tail of EXISTING_STATE as a scratch
/// region (the unsafe-mode runner has already moved on from
/// it).
unsafe fn extract_parent_cid_from_input(
    call_table: &CallTable,
    device_idx: u32,
    sector_size: usize,
) -> Option<u32> {
    // Stage the new device's header in a scratch sector
    // outside HEADER_BUF (which still holds the overlay's
    // header).
    let in_header_ptr = (EXISTING_STATE + EXISTING_STATE_LIMIT - MAX_SECTOR_SIZE) as *mut u8;
    if !(call_table.read_input_sector)(device_idx, 0, in_header_ptr, sector_size) {
        return None;
    }
    let in_header = core::slice::from_raw_parts(in_header_ptr, sector_size);

    let parsed = vmdk::Vmdk4Header::parse(in_header)?;
    let desc_byte_offset = parsed.desc_offset_sectors.checked_mul(512)?;
    let desc_byte_size_usize = parsed.desc_size_sectors.checked_mul(512)? as usize;
    if desc_byte_size_usize == 0 || desc_byte_size_usize > 64 * 1024 {
        return None;
    }

    // Read the new backing's descriptor into the same tail
    // scratch slot (overwriting the header we just read; we
    // don't need it again).
    let desc_ptr = in_header_ptr;
    if !read_input_byte_range(
        call_table,
        device_idx,
        sector_size,
        desc_byte_offset,
        desc_ptr,
        desc_byte_size_usize,
    ) {
        return None;
    }
    let desc_bytes = core::slice::from_raw_parts(desc_ptr, desc_byte_size_usize);

    let mut info = shared::VmdkInfo::default();
    vmdk::parse_descriptor(desc_bytes, desc_bytes.len(), &mut info);
    Some(info.cid)
}

/// Sector-aligned byte-range read against an *input* device.
/// Modelled on read_byte_range but routes through
/// read_input_sector instead of read_output_sector.
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
    // Use a fresh bounce slot at the tail of EXISTING_STATE
    // so we don't clobber the destination (which is also in
    // EXISTING_STATE's tail). The bounce slot sits one
    // sector before dst_ptr.
    let bounce_ptr = dst_ptr.sub(MAX_SECTOR_SIZE);
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

// ---------------------------------------------------------------------------
// Chain reader (step 3f)
// ---------------------------------------------------------------------------

/// Read whatever data the backing chain at
/// `[chain_first, chain_first + chain_count)` provides at
/// `guest_offset` into `out_buf`. Walks the chain top-to-base,
/// returning the first member that owns the cluster. If no
/// member owns it, `out_buf` is zero-filled and the call still
/// returns `true` (the safe-mode comparison loop treats
/// "everywhere unallocated reads as zeros" identically on both
/// chains).
///
/// v1 supports qcow2 and raw chain members. vmdk / vhd / vhdx
/// chain members force the call to return `false`: the qcow2
/// crate's chain reader is not built with their feature flags
/// in the rebase binary, so it would silently misread their
/// data as raw sectors. Phase 3 future-work tracks promotion
/// to a shared crate that handles the full chain-member set.
///
/// # Safety
///
/// `call_table` must be valid. `chain_config` must describe the
/// referenced devices. `chain_states` must already be
/// initialised for every qcow2 member via
/// [`qcow2::init_chain_states`]. `out_buf` must point to at
/// least `cluster_size` writable bytes.
unsafe fn read_chain_cluster(
    call_table: &CallTable,
    chain_first: u32,
    chain_count: u32,
    chain_config: &ChainConfig,
    chain_states: &mut qcow2::ChainStates,
    guest_offset: u64,
    cluster_size: u64,
    out_buf: *mut u8,
    sector_size: usize,
) -> bool {
    if chain_count == 0 {
        // No chain at this slot range: read as zeros. Mirrors
        // the all-unallocated path inside the qcow2 chain
        // reader.
        core::ptr::write_bytes(out_buf, 0, cluster_size as usize);
        return true;
    }

    // Pre-flight: every chain member must be a format the
    // chain reader can handle in this build. Without the
    // `vmdk-input` / `vhd-input` / `vhdx-input` features the
    // qcow2 crate falls through to `read_raw_sectors` for
    // unrecognised formats, which is wrong for any image
    // whose data isn't laid out at the guest-virtual offset.
    for i in 0..chain_count {
        let idx = (chain_first + i) as usize;
        if idx >= MAX_CHAIN_DEVICES {
            return false;
        }
        match chain_config.devices[idx].detected_format() {
            ImageFormat::Qcow2 | ImageFormat::Raw => {}
            _ => return false,
        }
    }

    // `compressed_buf` and `staging_buf` are gated behind the
    // `decompress` / `vmdk-decompress` features, neither of
    // which the rebase binary enables. They are formally
    // required by the function signature but never touched in
    // this build; passing a stable in-scratch pointer keeps
    // the call defined.
    let dummy_buf = CHAIN_CACHES as *mut u8;
    let mut staging_cluster_offset = u64::MAX;
    let mut bytes_read: u64 = 0;
    qcow2::read_chain_virtual_cluster(
        call_table,
        chain_first as usize,
        chain_count as usize,
        guest_offset,
        out_buf,
        cluster_size,
        sector_size,
        chain_config,
        chain_states,
        dummy_buf,
        dummy_buf,
        &mut staging_cluster_offset,
        None,
        None,
        512,
        &mut bytes_read,
    )
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the rebase operation.
///
/// # Safety
///
/// Called by the core binary after it has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`RebaseConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - Attached the overlay as the output device (opened RW).
/// - For safe mode: attached the old chain at input slots
///   [`config.old_chain_first`, `config.old_chain_first +
///   config.old_chain_count`) and the new chain at input
///   slots [`config.new_chain_first`, `config.new_chain_first
///   + config.new_chain_count`).
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "rebase");
    (call_table.verbose_print)(b"rebase: start\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const RebaseConfig);
    if !config.is_valid() {
        send_result(
            call_table,
            ImageFormat::Unknown as u32,
            RebaseResult::MODE_UNSAFE,
            0,
            0,
            RebaseResult::ERROR_PARSE_FAILED,
        );
        (call_table.send_complete)(b"rebase\0".as_ptr(), 0, false);
        return 0;
    }

    let sector_size = (call_table.get_output_sector_size)();

    // Read sector 0 to detect the format. The overlay is the
    // output device.
    if !(call_table.read_output_sector)(0, HEADER_BUF as *mut u8, sector_size) {
        send_result(
            call_table,
            config.overlay_format,
            if config.is_unsafe() {
                RebaseResult::MODE_UNSAFE
            } else {
                RebaseResult::MODE_SAFE
            },
            0,
            0,
            RebaseResult::ERROR_PARSE_FAILED,
        );
        (call_table.send_complete)(b"rebase\0".as_ptr(), 0, false);
        return 0;
    }
    let header = core::slice::from_raw_parts(HEADER_BUF as *const u8, sector_size);
    let format = detect_format_from_header(header, sector_size, false);

    let result = match format {
        ImageFormat::Qcow2 => run_qcow2(call_table, config),
        ImageFormat::Vmdk4 => run_vmdk(call_table, config),
        _ => err_result(
            config.overlay_format,
            if config.is_unsafe() {
                RebaseResult::MODE_UNSAFE
            } else {
                RebaseResult::MODE_SAFE
            },
            RebaseResult::ERROR_UNSUPPORTED_FORMAT,
        ),
    };

    let _ = CHAIN_CACHES_LIMIT;
    let _ = COMPARE_BUFS_LIMIT;

    let ok = result.error == RebaseResult::ERROR_OK;
    (call_table.send_rebase_result)(&result);
    (call_table.send_complete)(b"rebase\0".as_ptr(), 0, ok);
    0
}
