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
//! **This is step 4a: the registered, size-checked skeleton.** The
//! qcow2 runner is a stub that returns `ERROR_UNSUPPORTED_ACTION`;
//! the header read + gates + staging (4b), the metadata-action loop
//! + write-back + autoclear dance (4c), and the merge on-disk
//! orchestration (4d) fill it in. Non-qcow2 targets are refused with
//! `ERROR_UNSUPPORTED_FORMAT` (v1 is qcow2-only).
//!
//! Device idiom (Phase 5 host, mirrored here): the image is attached
//! **input read-write** at slot 0, so the runner reads/writes via
//! `read_input_sector(0, ..)` / `write_input_sector(0, ..)` /
//! `fsync_input(0)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    validate_call_table, BitmapConfig, BitmapResult, CallTable, ImageFormat, CALL_TABLE_ADDR,
    OPERATION_CONFIG_ADDR,
};

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
// qcow2 runner
// ---------------------------------------------------------------------------

/// Drive the bitmap mutation over a qcow2 image.
///
/// **Stub (step 4a).** Steps 4b–4d fill this in: 4b reads the header
/// cluster, runs the gates + host cross-check, and stages the
/// directory / refcount table / refblocks; 4c runs the
/// add/remove/clear/enable/disable action loop and the write-back +
/// autoclear dance; 4d adds the merge on-disk orchestration. Until
/// then the runner refuses every request with
/// `ERROR_UNSUPPORTED_ACTION`, leaving the image byte-identical.
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
#[inline(never)]
unsafe fn run_qcow2(_call_table: &CallTable, config: &BitmapConfig) -> BitmapResult {
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
