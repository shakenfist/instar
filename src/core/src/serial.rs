//! Serial port I/O for the core guest.
//!
//! Handles VMM communication via serial ports.

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

/// Read a byte from the serial port
#[inline]
fn serial_read() -> u8 {
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
fn serial_data_ready() -> bool {
    (read_lsr() & LSR_DR) != 0
}

/// Device configuration received from VMM
#[derive(Clone)]
pub struct DeviceConfig {
    pub input_sector_size: usize,
    pub output_sector_size: usize,
    pub progress_percent: u32,
    /// Whether an output device is configured (info ops don't need one)
    pub has_output_device: bool,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            input_sector_size: 512,
            output_sector_size: 512,
            progress_percent: 10,
            has_output_device: false,
        }
    }
}

/// Read configuration from serial port at startup
pub fn read_config() -> DeviceConfig {
    let mut config = DeviceConfig::default();

    if !serial_data_ready() {
        return config;
    }

    let mut buf = [0u8; FRAME_HEADER_SIZE + MAX_MESSAGE_SIZE];
    let mut pos = 0;

    while pos < FRAME_HEADER_SIZE {
        if serial_data_ready() {
            buf[pos] = serial_read();
            pos += 1;
        } else {
            core::hint::spin_loop();
        }
    }

    let msg_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let total_len = FRAME_HEADER_SIZE + msg_len;

    if total_len > buf.len() {
        return config;
    }

    while pos < total_len {
        if serial_data_ready() {
            buf[pos] = serial_read();
            pos += 1;
        } else {
            core::hint::spin_loop();
        }
    }

    if let Some((vmm_config, _)) = decode_vmm_config_framed(&buf[..total_len]) {
        for dev in vmm_config.devices.iter() {
            let name: &str = dev.name.as_str();
            let sector_size = dev.sector_size as usize;

            if name == "input" {
                config.input_sector_size = sector_size;
            } else if name == "output" {
                config.output_sector_size = sector_size;
                config.has_output_device = true;
            }
        }
        config.progress_percent = vmm_config.progress_percent;
    }

    config
}

/// Write a byte to the debug port (COM2)
#[inline]
fn debug_write(byte: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") DEBUG_PORT,
            in("al") byte,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Write a string to the debug port
pub fn debug_print(s: &str) {
    for byte in s.bytes() {
        debug_write(byte);
    }
}

/// Send a framed protobuf message over serial
fn send_message(msg: &guest_::GuestMessage) {
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

/// Send an info result message
#[allow(clippy::too_many_arguments)]
pub fn send_info_result(
    format: &str,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: &str,
    external_data_file: &str,
) {
    let msg = guest_protocol::info_result_message(
        format,
        version,
        virtual_size,
        actual_size,
        cluster_size,
        flags,
        backing_file,
        external_data_file,
    );
    send_message(&msg);
}

/// Send an info result message with QCOW2-specific information
#[allow(clippy::too_many_arguments)]
pub fn send_info_result_qcow2(
    format: &str,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: &str,
    external_data_file: &str,
    qcow2_info: &shared::Qcow2Info,
) {
    let qcow2_data = guest_protocol::Qcow2InfoData {
        compat: qcow2_info.compat_str(),
        compression_type: qcow2_info.compression_type_str(),
        lazy_refcounts: qcow2_info.lazy_refcounts,
        refcount_bits: qcow2_info.refcount_bits,
        dirty: qcow2_info.dirty,
        corrupt: qcow2_info.corrupt,
        extended_l2: qcow2_info.extended_l2,
        backing_format: qcow2_info.backing_format_str(),
    };

    let msg = guest_protocol::info_result_message_with_qcow2(
        format,
        version,
        virtual_size,
        actual_size,
        cluster_size,
        flags,
        backing_file,
        external_data_file,
        &qcow2_data,
    );
    send_message(&msg);
}

/// Send an info result message with VMDK-specific information
#[allow(clippy::too_many_arguments)]
pub fn send_info_result_vmdk(
    format: &str,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: &str,
    external_data_file: &str,
    vmdk_info: &shared::VmdkInfo,
) {
    let vmdk_data = guest_protocol::VmdkInfoData {
        cid: vmdk_info.cid,
        parent_cid: vmdk_info.parent_cid,
        create_type: vmdk_info.create_type_str(),
    };

    let msg = guest_protocol::info_result_message_with_vmdk(
        format,
        version,
        virtual_size,
        actual_size,
        cluster_size,
        flags,
        backing_file,
        external_data_file,
        &vmdk_data,
    );
    send_message(&msg);
}
