//! Rebase operation: change an overlay's backing-file reference.
//!
//! Phase 3 of `PLAN-rebase-commit.md`. Reads a `RebaseConfig`
//! from `OPERATION_CONFIG_ADDR`, reads sector 0 of the output
//! device (the overlay being rebased), detects the format,
//! dispatches to the matching per-format runner, and reports
//! the outcome via `send_rebase_result` + `send_complete`.
//!
//! Scope at step 3b (this commit): scaffolding. The per-format
//! runners return `ERROR_UNSUPPORTED_FORMAT`; steps 3c–3e fill
//! in qcow2 unsafe, vmdk unsafe, and qcow2 safe-mode logic.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

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
// SCRATCH_MEM_BASE..SCRATCH_MEM_END is ~12.9 MiB of guest
// memory. The rebase guest carves it into five regions:
//
//   HEADER_BUF        — first sector of the output device, also
//                       used as a single-sector bounce buffer
//                       for partial-sector reads and writes.
//   EXISTING_STATE    — staged existing-file metadata: parsed
//                       descriptor (vmdk), L1 table + staged
//                       L2 tables + refcount table +
//                       refcount-block host offsets + refcount
//                       blocks (qcow2 safe mode), with one
//                       sector at the tail reserved as a
//                       second bounce buffer for read-modify-
//                       write that must not clobber
//                       HEADER_BUF.
//   PLANNER_SCRATCH   — the byte buffer passed to plan_rebase_*.
//   CHAIN_CACHES      — per-chain-device L1/L2 sector caches the
//                       qcow2 crate's `Qcow2State` populates
//                       (`MAX_CHAIN_DEVICES * 2 * MAX_SECTOR_SIZE`).
//                       Safe-mode rebase reads the old and new
//                       backing chains through these states.
//   COMPARE_BUFS      — two cluster-sized scratch buffers
//                       (`old_buf` and `new_buf`) used by the
//                       safe-mode comparison loop to read one
//                       cluster from each chain before
//                       comparing them. Reserved by step 3f;
//                       consumed by step 3e.

const HEADER_BUF: usize = SCRATCH_MEM_BASE;
const EXISTING_STATE: usize = HEADER_BUF + MAX_SECTOR_SIZE;
const EXISTING_STATE_LIMIT: usize = 4 * 1024 * 1024;
const PLANNER_SCRATCH: usize = EXISTING_STATE + EXISTING_STATE_LIMIT;
const PLANNER_SCRATCH_LIMIT: usize = 4 * 1024 * 1024;
const CHAIN_CACHES: usize = PLANNER_SCRATCH + PLANNER_SCRATCH_LIMIT;
const CHAIN_CACHES_LIMIT: usize = MAX_CHAIN_DEVICES * 2 * MAX_SECTOR_SIZE;
const COMPARE_BUFS: usize = CHAIN_CACHES + CHAIN_CACHES_LIMIT;
/// Per-side cluster buffer cap. Safe-mode rebase reads one
/// overlay cluster from each chain into a buffer of this size;
/// `cluster_size > COMPARE_BUF_SIZE` is rejected with
/// `ERROR_SCRATCH_TOO_SMALL`.
const COMPARE_BUF_SIZE: usize = 1024 * 1024;
const COMPARE_BUFS_LIMIT: usize = COMPARE_BUF_SIZE * 2;

// Compile-time check that the scratch carve fits below the
// allocator heap (which sits at the top of scratch).
const _: () = assert!(
    COMPARE_BUFS + COMPARE_BUFS_LIMIT <= shared::ALLOC_HEAP_BASE,
    "rebase scratch layout overlaps the allocator heap"
);

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

// ---------------------------------------------------------------------------
// Sector-level I/O helpers (modelled on resize)
// ---------------------------------------------------------------------------

/// Read `len` bytes starting at `byte_offset` into the buffer
/// at `dst_ptr`. Handles non-sector-aligned starts/ends via a
/// small bounce buffer at `HEADER_BUF`.
#[allow(dead_code)]
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
#[allow(dead_code)]
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

/// qcow2 safe-mode rebase: drives the per-cluster comparison
/// loop. Filled in by step 3e; currently returns
/// `ERROR_UNSUPPORTED_FORMAT`.
unsafe fn run_qcow2_safe(_call_table: &CallTable, config: &RebaseConfig) -> RebaseResult {
    err_result(
        config.overlay_format,
        RebaseResult::MODE_SAFE,
        RebaseResult::ERROR_UNSUPPORTED_FORMAT,
    )
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

    // Silence dead-code on the scratch-layout constants until
    // step 3e wires the safe-mode runner through them. Step 3f
    // added `read_chain_cluster` and the `CHAIN_CACHES` /
    // `COMPARE_BUFS` regions; only the helper and the chain
    // cache region are exercised before step 3e ships.
    let _ = PLANNER_SCRATCH;
    let _ = PLANNER_SCRATCH_LIMIT;
    let _ = EXISTING_STATE_LIMIT;
    let _ = CHAIN_CACHES_LIMIT;
    let _ = COMPARE_BUFS;
    let _ = COMPARE_BUFS_LIMIT;
    let _ = COMPARE_BUF_SIZE;
    let _: unsafe fn(
        &CallTable,
        u32,
        u32,
        &ChainConfig,
        &mut qcow2::ChainStates,
        u64,
        u64,
        *mut u8,
        usize,
    ) -> bool = read_chain_cluster;

    let ok = result.error == RebaseResult::ERROR_OK;
    (call_table.send_rebase_result)(&result);
    (call_table.send_complete)(b"rebase\0".as_ptr(), 0, ok);
    0
}
