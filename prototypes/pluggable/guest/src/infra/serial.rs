//! Serial port I/O for the bare-metal guest.
//!
//! Supports both raw I/O and framed protobuf messages.
//! The serial port is used bidirectionally:
//! - Guest reads configuration from VMM at startup
//! - Guest writes status/progress messages to VMM

use core::arch::asm;
use guest_protocol::{
    decode_vmm_config_framed, encode_framed, guest_, FRAME_HEADER_SIZE, MAX_MESSAGE_SIZE,
};

/// Serial port base address (COM1 - protobuf messages)
const SERIAL_PORT: u16 = 0x3f8;

/// Debug serial port (COM2 - plain text debug output)
const DEBUG_PORT: u16 = 0x2f8;

/// Line Status Register offset
const LSR_OFFSET: u16 = 5;

/// LSR bit: Data Ready
const LSR_DR: u8 = 0x01;

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

/// Read a byte from the serial port
#[inline]
pub fn serial_read() -> u8 {
    let value: u8;
    unsafe {
        asm!(
            "in al, dx",
            out("al") value,
            in("dx") SERIAL_PORT,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Read the Line Status Register
#[inline]
fn read_lsr() -> u8 {
    let value: u8;
    unsafe {
        asm!(
            "in al, dx",
            out("al") value,
            in("dx") SERIAL_PORT + LSR_OFFSET,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Check if data is available to read
#[inline]
pub fn serial_data_ready() -> bool {
    (read_lsr() & LSR_DR) != 0
}

/// Device configuration received from VMM
#[derive(Clone)]
pub struct DeviceConfig {
    pub input_sector_size: usize,
    pub output_sector_size: usize,
    /// Progress update interval: 0=every 10 sectors, 1-99=every N%, 100=none
    pub progress_percent: u32,
    /// Operation to perform (for future extension)
    pub operation: Operation,
}

/// Available operations
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Copy data from input to output
    Copy,
    /// Report info about the input device (future)
    Info,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            input_sector_size: 512,
            output_sector_size: 512,
            progress_percent: 0, // Legacy behavior
            operation: Operation::Copy,
        }
    }
}

/// Read configuration from serial port at startup.
///
/// Blocks until a complete VmmConfig message is received, or returns
/// default config if no data is available after initial check.
pub fn read_config() -> DeviceConfig {
    let mut config = DeviceConfig::default();

    // Check if VMM has queued config data
    if !serial_data_ready() {
        // No config available, use defaults
        return config;
    }

    // Read the framed message
    let mut buf = [0u8; FRAME_HEADER_SIZE + MAX_MESSAGE_SIZE];
    let mut pos = 0;

    // Read header first (2 bytes)
    while pos < FRAME_HEADER_SIZE {
        if serial_data_ready() {
            buf[pos] = serial_read();
            pos += 1;
        } else {
            core::hint::spin_loop();
        }
    }

    // Parse message length from header
    let msg_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let total_len = FRAME_HEADER_SIZE + msg_len;

    if total_len > buf.len() {
        // Message too large, use defaults
        return config;
    }

    // Read the rest of the message
    while pos < total_len {
        if serial_data_ready() {
            buf[pos] = serial_read();
            pos += 1;
        } else {
            core::hint::spin_loop();
        }
    }

    // Decode the config message
    if let Some((vmm_config, _)) = decode_vmm_config_framed(&buf[..total_len]) {
        // Extract device configurations
        for dev in vmm_config.devices.iter() {
            let name: &str = dev.name.as_str();
            let sector_size = dev.sector_size as usize;

            if name == "input" {
                config.input_sector_size = sector_size;
            } else if name == "output" {
                config.output_sector_size = sector_size;
            }
        }

        // Extract progress interval
        config.progress_percent = vmm_config.progress_percent;
    }

    config
}

/// Write a string to the serial port (for debugging/fallback)
#[allow(dead_code)]
pub fn serial_print(s: &str) {
    for byte in s.bytes() {
        serial_write(byte);
    }
}

/// Write a byte to the debug port (COM2)
#[inline]
pub fn debug_write(byte: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") DEBUG_PORT,
            in("al") byte,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Write a string to the debug port (COM2 - plain text, no protobuf)
pub fn debug_print(s: &str) {
    for byte in s.bytes() {
        debug_write(byte);
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
