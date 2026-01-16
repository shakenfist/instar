//! Serial port output for the bare-metal guest.

use core::arch::asm;

/// Serial port address (COM1)
const SERIAL_PORT: u16 = 0x3f8;

/// Write a byte to the serial port
#[inline]
pub fn serial_write(byte: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") SERIAL_PORT,
            in("al") byte,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Write a string to the serial port
pub fn serial_print(s: &str) {
    for byte in s.bytes() {
        serial_write(byte);
    }
}
