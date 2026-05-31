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

use rebase::RebaseError;
use shared::{
    format_detection::detect_format_from_header, validate_call_table, CallTable, ImageFormat,
    RebaseConfig, RebaseResult, CALL_TABLE_ADDR, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR,
    SCRATCH_MEM_BASE,
};

// ---------------------------------------------------------------------------
// Scratch layout
// ---------------------------------------------------------------------------
//
// The rebase guest uses the same three-region carve as the
// resize guest. SCRATCH_MEM_BASE..SCRATCH_MEM_END is ~12.9 MiB
// of guest memory:
//
//   HEADER_BUF        — first sector of the output device, also
//                       used as a single-sector bounce buffer
//                       for partial-sector reads and writes.
//   EXISTING_STATE    — staged existing-file metadata: parsed
//                       descriptor (vmdk), L1 table + L2
//                       region + refcount table + refcount
//                       blocks (qcow2 safe mode), with one
//                       sector at the tail reserved as a
//                       second bounce buffer for read-modify-
//                       write that must not clobber
//                       HEADER_BUF.
//   PLANNER_SCRATCH   — the byte buffer passed to plan_rebase_*.

const HEADER_BUF: usize = SCRATCH_MEM_BASE;
const EXISTING_STATE: usize = HEADER_BUF + MAX_SECTOR_SIZE;
const EXISTING_STATE_LIMIT: usize = 4 * 1024 * 1024;
const PLANNER_SCRATCH: usize = EXISTING_STATE + EXISTING_STATE_LIMIT;
const PLANNER_SCRATCH_LIMIT: usize = 8 * 1024 * 1024;

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

// ---------------------------------------------------------------------------
// Per-format runners (stubs in step 3b)
// ---------------------------------------------------------------------------

/// qcow2 rebase runner. Filled in by steps 3c (unsafe) and 3e
/// (safe).
unsafe fn run_qcow2(_call_table: &CallTable, config: &RebaseConfig) -> RebaseResult {
    let mode = if config.is_unsafe() {
        RebaseResult::MODE_UNSAFE
    } else {
        RebaseResult::MODE_SAFE
    };
    err_result(
        config.overlay_format,
        mode,
        RebaseResult::ERROR_UNSUPPORTED_FORMAT,
    )
}

/// vmdk rebase runner. Filled in by step 3d (unsafe) and a
/// follow-up that depends on phase 2 step 2e (safe).
unsafe fn run_vmdk(_call_table: &CallTable, config: &RebaseConfig) -> RebaseResult {
    let mode = if config.is_unsafe() {
        RebaseResult::MODE_UNSAFE
    } else {
        RebaseResult::MODE_SAFE
    };
    err_result(
        config.overlay_format,
        mode,
        RebaseResult::ERROR_UNSUPPORTED_FORMAT,
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

    // Silence dead-code on PLANNER_SCRATCH constants until
    // steps 3c/3d/3e use them.
    let _ = PLANNER_SCRATCH;
    let _ = PLANNER_SCRATCH_LIMIT;
    let _ = EXISTING_STATE_LIMIT;

    let ok = result.error == RebaseResult::ERROR_OK;
    (call_table.send_rebase_result)(&result);
    (call_table.send_complete)(b"rebase\0".as_ptr(), 0, ok);
    0
}
