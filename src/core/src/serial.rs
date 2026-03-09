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
    /// Number of input devices (1 for single-image, >1 for chain)
    pub input_device_count: usize,
    /// Sector sizes for additional input devices (index 0 = device 1)
    pub extra_input_sector_sizes: [usize; 15],
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            input_sector_size: 512,
            output_sector_size: 512,
            progress_percent: 10,
            has_output_device: false,
            input_device_count: 1,
            extra_input_sector_sizes: [0; 15],
        }
    }
}

/// Parse a device index from ASCII digit bytes (e.g., b"1" -> 1).
fn parse_device_index(digits: &[u8]) -> usize {
    let mut result: usize = 0;
    for &b in digits {
        if b >= b'0' && b <= b'9' {
            result = result * 10 + (b - b'0') as usize;
        } else {
            return 0;
        }
    }
    result
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
        let mut input_count: usize = 0;
        for dev in vmm_config.devices.iter() {
            let name: &str = dev.name.as_str();
            let sector_size = dev.sector_size as usize;

            if name == "input" {
                config.input_sector_size = sector_size;
                input_count += 1;
            } else if name.len() > 5 && name.as_bytes()[..5] == *b"input" {
                // Parse "input1" through "input15"
                let idx = parse_device_index(&name.as_bytes()[5..]);
                if idx > 0 && idx <= 15 {
                    config.extra_input_sector_sizes[idx - 1] = sector_size;
                    input_count += 1;
                }
            } else if name == "output" {
                config.output_sector_size = sector_size;
                config.has_output_device = true;
            }
        }
        config.input_device_count = input_count;
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
        nb_snapshots: qcow2_info.nb_snapshots,
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

/// Format a UUID as a string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
fn format_uuid(uuid: &[u8; 16]) -> [u8; 36] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 36];

    // VDI uses little-endian UUID format (time_low, time_mid, time_hi are LE)
    // Format: time_low (4 bytes LE) - time_mid (2 bytes LE) - time_hi (2 bytes LE)
    //         - clock_seq (2 bytes BE) - node (6 bytes BE)

    // time_low (bytes 0-3, little-endian)
    buf[0] = HEX[(uuid[3] >> 4) as usize];
    buf[1] = HEX[(uuid[3] & 0xf) as usize];
    buf[2] = HEX[(uuid[2] >> 4) as usize];
    buf[3] = HEX[(uuid[2] & 0xf) as usize];
    buf[4] = HEX[(uuid[1] >> 4) as usize];
    buf[5] = HEX[(uuid[1] & 0xf) as usize];
    buf[6] = HEX[(uuid[0] >> 4) as usize];
    buf[7] = HEX[(uuid[0] & 0xf) as usize];
    buf[8] = b'-';

    // time_mid (bytes 4-5, little-endian)
    buf[9] = HEX[(uuid[5] >> 4) as usize];
    buf[10] = HEX[(uuid[5] & 0xf) as usize];
    buf[11] = HEX[(uuid[4] >> 4) as usize];
    buf[12] = HEX[(uuid[4] & 0xf) as usize];
    buf[13] = b'-';

    // time_hi_and_version (bytes 6-7, little-endian)
    buf[14] = HEX[(uuid[7] >> 4) as usize];
    buf[15] = HEX[(uuid[7] & 0xf) as usize];
    buf[16] = HEX[(uuid[6] >> 4) as usize];
    buf[17] = HEX[(uuid[6] & 0xf) as usize];
    buf[18] = b'-';

    // clock_seq_hi_and_reserved, clock_seq_low (bytes 8-9, big-endian)
    buf[19] = HEX[(uuid[8] >> 4) as usize];
    buf[20] = HEX[(uuid[8] & 0xf) as usize];
    buf[21] = HEX[(uuid[9] >> 4) as usize];
    buf[22] = HEX[(uuid[9] & 0xf) as usize];
    buf[23] = b'-';

    // node (bytes 10-15, big-endian)
    buf[24] = HEX[(uuid[10] >> 4) as usize];
    buf[25] = HEX[(uuid[10] & 0xf) as usize];
    buf[26] = HEX[(uuid[11] >> 4) as usize];
    buf[27] = HEX[(uuid[11] & 0xf) as usize];
    buf[28] = HEX[(uuid[12] >> 4) as usize];
    buf[29] = HEX[(uuid[12] & 0xf) as usize];
    buf[30] = HEX[(uuid[13] >> 4) as usize];
    buf[31] = HEX[(uuid[13] & 0xf) as usize];
    buf[32] = HEX[(uuid[14] >> 4) as usize];
    buf[33] = HEX[(uuid[14] & 0xf) as usize];
    buf[34] = HEX[(uuid[15] >> 4) as usize];
    buf[35] = HEX[(uuid[15] & 0xf) as usize];

    buf
}

/// Send an info result message with VDI-specific information
#[allow(clippy::too_many_arguments)]
pub fn send_info_result_vdi(
    format: &str,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: &str,
    external_data_file: &str,
    vdi_info: &shared::VdiInfo,
) {
    // Format UUID as string
    let uuid_bytes = format_uuid(&vdi_info.uuid);
    // Safety: uuid_bytes contains only ASCII hex digits and dashes
    let uuid_str = unsafe { core::str::from_utf8_unchecked(&uuid_bytes) };

    let vdi_data = guest_protocol::VdiInfoData {
        image_type: vdi_info.image_type,
        block_size: vdi_info.block_size,
        blocks_in_image: vdi_info.blocks_in_image,
        blocks_allocated: vdi_info.blocks_allocated,
        uuid: uuid_str,
    };

    let msg = guest_protocol::info_result_message_with_vdi(
        format,
        version,
        virtual_size,
        actual_size,
        cluster_size,
        flags,
        backing_file,
        external_data_file,
        &vdi_data,
    );
    send_message(&msg);
}

/// Send an info result message with LUKS-specific information
#[allow(clippy::too_many_arguments)]
pub fn send_info_result_luks(
    format: &str,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: &str,
    external_data_file: &str,
    luks_info: &shared::LuksInfo,
) {
    let luks_data = guest_protocol::LuksInfoData {
        cipher: luks_info.cipher_str(),
        cipher_mode: luks_info.cipher_mode_str(),
        hash: luks_info.hash_str(),
        uuid: luks_info.uuid_str(),
        payload_offset: luks_info.payload_offset,
        master_key_length: luks_info.master_key_length,
        active_key_slots: luks_info.active_key_slots,
        inner_format: luks_info.inner_format_str(),
        inner_virtual_size: luks_info.inner_virtual_size,
    };

    let msg = guest_protocol::info_result_message_with_luks(
        format,
        version,
        virtual_size,
        actual_size,
        cluster_size,
        flags,
        backing_file,
        external_data_file,
        &luks_data,
    );
    send_message(&msg);
}

/// Send a check result message
#[allow(clippy::too_many_arguments)]
pub fn send_check_result(result: &shared::CheckResult) {
    let format_name = result.detected_format().name();
    let msg = guest_protocol::check_result_message(
        format_name,
        result.total_errors,
        result.corruptions,
        result.leaks,
        result.refcount_errors,
        result.image_end_offset,
        result.clusters_checked,
        result.clusters_allocated,
        result.fragmentation,
        result.flags,
        result.chain_errors,
    );
    send_message(&msg);
}

/// Send a compare result message
pub fn send_compare_result(result: &shared::CompareResult) {
    let msg = guest_protocol::compare_result_message(
        result.is_identical(),
        result.first_mismatch_offset,
        result.total_bytes_compared,
        result.flags,
    );
    send_message(&msg);
}
