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
//! Scope at step 7b (this commit): scaffolding. The per-format
//! runners return `ERROR_UNSUPPORTED_FORMAT`; steps 7c and 7d
//! fill in the qcow2 and vmdk commit loops.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    format_detection::detect_format_from_header, validate_call_table, CallTable, CommitConfig,
    CommitResult, ImageFormat, CALL_TABLE_ADDR, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR,
    SCRATCH_MEM_BASE,
};

// ---------------------------------------------------------------------------
// Scratch layout
// ---------------------------------------------------------------------------
//
// Step 7b carves the first two slots only — the overlay and
// backing header buffers. Steps 7c and 7d extend the layout
// with the per-side L1 / L2 / refcount staging the per-cluster
// loop needs.

/// Overlay header buffer (also doubles as a bounce buffer for
/// sub-sector reads against the overlay input device).
const HEADER_BUF: usize = SCRATCH_MEM_BASE;
/// Backing header buffer.
const BACKING_HEADER_BUF: usize = HEADER_BUF + MAX_SECTOR_SIZE;
/// Free region for future staging carved in steps 7c / 7d.
#[allow(dead_code)]
const SCRATCH_FREE_BASE: usize = BACKING_HEADER_BUF + MAX_SECTOR_SIZE;

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

// ---------------------------------------------------------------------------
// Per-format runners (stubs in step 7b)
// ---------------------------------------------------------------------------

/// qcow2 commit runner. Step 7b stub.
unsafe fn run_qcow2(_call_table: &CallTable, config: &CommitConfig) -> CommitResult {
    err_result(
        config.overlay_format,
        config.backing_format,
        CommitResult::ERROR_UNSUPPORTED_FORMAT,
    )
}

/// vmdk commit runner. Step 7b stub.
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

    // Read sector 0 from the overlay (input slot 0).
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
    // Read sector 0 from the backing (output device).
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
