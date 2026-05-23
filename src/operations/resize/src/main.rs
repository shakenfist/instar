//! Resize operation: in-place mutation of an existing disk image.
//!
//! Phase 7 of `PLAN-resize.md`.  Step 7b ships this stub that
//! just returns `ERROR_UNSUPPORTED_FORMAT` — its purpose is to
//! prove the build pipeline (workspace member, linker, size
//! check, build script) before step 7c lands the real
//! implementation.
//!
//! The plan:
//!   1. Read `ResizeConfig` from `OPERATION_CONFIG_ADDR`.
//!   2. Read sector 0 of the output device via the new
//!      `read_output_sector` call-table primitive.
//!   3. Detect the format and dispatch to a per-format
//!      `run_<fmt>` (qcow2/vhd/vhdx/vmdk/raw) that stages the
//!      bytes the planner's opts struct needs, calls
//!      `crates/resize::plan_resize_*`, and applies the patches
//!      via the new patch applicator.
//!   4. Send a `ResizeResult` via `send_resize_result`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    validate_call_table, CallTable, ImageFormat, ResizeConfig, ResizeResult, CALL_TABLE_ADDR,
    OPERATION_CONFIG_ADDR,
};

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Build a `ResizeResult` and send it via the call table.
///
/// # Safety
///
/// `call_table` must be valid (architectural invariant).
unsafe fn send_result(
    call_table: &CallTable,
    target: u32,
    resolved_new_virtual_size: u64,
    file_size_before: u64,
    file_size_after: u64,
    action: u32,
    error: u32,
) {
    let result = ResizeResult {
        magic: ResizeResult::MAGIC,
        target_format: target,
        resolved_new_virtual_size,
        file_size_before,
        file_size_after,
        action,
        error,
    };
    (call_table.send_resize_result)(&result);
}

/// Entry point for the resize operation.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`ResizeConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - Attached the output device (the file to resize, opened
///   read-write).
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "resize");
    (call_table.verbose_print)(b"resize: start (stub)\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const ResizeConfig);
    if !config.is_valid() {
        send_result(
            call_table,
            ImageFormat::Unknown as u32,
            0,
            0,
            0,
            ResizeResult::ACTION_NOOP,
            ResizeResult::ERROR_INVALID_OPTION,
        );
        (call_table.send_complete)(b"resize\0".as_ptr(), 0, false);
        return 0;
    }

    // Phase 7c replaces this stub with the full implementation.
    send_result(
        call_table,
        config.target_format,
        0,
        config.current_virtual_size,
        0,
        ResizeResult::ACTION_NOOP,
        ResizeResult::ERROR_UNSUPPORTED_FORMAT,
    );
    (call_table.send_complete)(b"resize\0".as_ptr(), 0, false);
    0
}
