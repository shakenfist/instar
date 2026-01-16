//! Serial port output for the bare-metal guest.
//!
//! Supports both raw text output and framed protobuf messages.

use core::arch::asm;
use guest_protocol::{encode_framed, guest_, FRAME_HEADER_SIZE, MAX_MESSAGE_SIZE};

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

/// Write a string to the serial port (for debugging/fallback)
#[allow(dead_code)]
pub fn serial_print(s: &str) {
    for byte in s.bytes() {
        serial_write(byte);
    }
}

/// Send a framed protobuf message over serial
pub fn send_message(msg: &guest_::GuestMessage) {
    let mut buf = [0u8; FRAME_HEADER_SIZE + MAX_MESSAGE_SIZE];
    if let Some(len) = encode_framed(msg, &mut buf) {
        for &byte in &buf[..len] {
            serial_write(byte);
        }
    }
}

/// Send an init message
pub fn send_init(stage: &str, device: &str, address: u64) {
    let msg = guest_protocol::init_message(stage, device, address);
    send_message(&msg);
}

/// Send a capacity message
pub fn send_capacity(device: &str, sectors: u64, bytes: u64) {
    let msg = guest_protocol::capacity_message(device, sectors, bytes);
    send_message(&msg);
}

/// Send a progress message
pub fn send_progress(operation: &str, current: u64, total: u64, percent: u32) {
    let msg = guest_protocol::progress_message(operation, current, total, percent);
    send_message(&msg);
}

/// Send an error message
pub fn send_error(operation: &str, device: &str, sector: u64, status: u32) {
    let msg = guest_protocol::error_message(operation, device, sector, status);
    send_message(&msg);
}

/// Send a completion message
pub fn send_complete(operation: &str, count: u64, success: bool) {
    let msg = guest_protocol::complete_message(operation, count, success);
    send_message(&msg);
}
