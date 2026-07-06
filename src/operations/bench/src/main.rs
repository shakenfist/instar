//! Bench operation: measure guest-side image read/write throughput
//! (`qemu-img bench` parity).
//!
//! **This is the phase-3a stub**: it validates the call table and
//! casts the [`shared::BenchConfig`] the host wrote at
//! [`OPERATION_CONFIG_ADDR`], but does not yet read or write a
//! single byte of the target image. Every invocation — valid
//! config or not — takes the same path: emit a [`shared::BenchResult`]
//! reporting `ERROR_BAD_CONFIG` and terminate. Phase 3b replaces
//! this body with the real chain setup and request loop (Mission
//! §1 of `PLAN-bench-phase-03-guest-read.md`); nothing launches this
//! binary before phase 4's host CLI exists, so the stub is
//! build- and size-gated only.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    validate_call_table, BenchConfig, BenchResult, CallTable, CALL_TABLE_ADDR,
    OPERATION_CONFIG_ADDR,
};

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Entry point.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`BenchConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - Initialised input device 0 and routed virtio-block I/O
///   through the call table.
///
/// These invariants hold by construction of the host-side VMM; no
/// other caller is architecturally possible.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "bench");

    // Phase-3a stub: the config is cast (to exercise the ABI the
    // real op will consume) but not otherwise inspected. Every
    // path -- `config.is_valid()` succeeding or failing -- ends
    // the same way until phase 3b lands the real request loop.
    let _config = &*(OPERATION_CONFIG_ADDR as *const BenchConfig);

    let result = BenchResult {
        magic: BenchResult::MAGIC,
        error: BenchResult::ERROR_BAD_CONFIG,
        requests_completed: 0,
        flushes_issued: 0,
        error_detail: 0,
        _reserved: [0; 32],
    };
    (call_table.send_bench_result)(&result);
    (call_table.send_complete)(b"bench\0".as_ptr(), 0, false);
    0
}
