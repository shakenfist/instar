//! Create operation: emit empty-image metadata for a target format.
//!
//! Step 2d ships a stub _start that immediately reports completion
//! with no work done. Step 2e fills in the real dispatch + write loop.
//!
//! See `docs/plans/PLAN-create-phase-02-guest-op.md` for the design.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{validate_call_table, CallTable, CALL_TABLE_ADDR};

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Entry point. Stub: returns 0 and reports failure so any
/// accidental invocation before step 2e is obvious.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has written a populated
/// [`CallTable`] at [`CALL_TABLE_ADDR`]. Until step 2e wires the
/// real implementation no other invariants are required (the stub
/// neither reads CreateConfig nor touches input/output devices).
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "create");
    (call_table.verbose_print)(b"create: stub _start (phase 2d)\n\0".as_ptr());
    (call_table.send_complete)(b"create\0".as_ptr(), 0, false);
    0
}
