//! Bare-metal guest binary for KVM hello world.
//!
//! This binary runs directly on a vCPU with no OS. It writes "Hello" to the
//! serial port (0x3f8) and then halts.

#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

/// Serial port address (COM1).
const SERIAL_PORT: u16 = 0x3f8;

/// Write a byte to the serial port.
#[inline]
fn serial_write(byte: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") SERIAL_PORT,
            in("al") byte,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Write a string to the serial port.
fn serial_print(s: &str) {
    for byte in s.bytes() {
        serial_write(byte);
    }
}

/// Entry point - called directly by the VMM after setting up long mode.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Write "Hello" to serial port
    serial_print("Hello from KVM guest!\n");

    // Signal completion via HLT
    unsafe {
        asm!("hlt", options(nomem, nostack));
    }

    // Should never reach here, but loop forever just in case
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Write panic indicator to serial
    serial_print("PANIC!\n");

    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}
