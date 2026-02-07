//! Guest protocol crate for structured guest-to-VMM communication.
//!
//! This crate provides Protocol Buffers-based messaging for bare-metal guests
//! to communicate with the VMM over the serial port. It is designed to be
//! no_std and no_alloc compatible.
//!
//! # Framing
//!
//! Messages are framed with a 2-byte little-endian length prefix:
//! ```text
//! [len_lo][len_hi][protobuf_data...]
//! ```
//!
//! # Example (Guest Side)
//!
//! ```ignore
//! use guest_protocol::{guest_, encode_framed, progress_message};
//!
//! let msg = progress_message("copy", 512, 2048, 25);
//!
//! let mut buf = [0u8; 128];
//! let len = encode_framed(&msg, &mut buf).unwrap();
//! serial_write(&buf[..len]);
//! ```

#![no_std]
// Suppress warnings from micropb-generated code
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_imports)]
#![allow(unused_parens)]

// Include the generated protobuf code
include!(concat!(env!("OUT_DIR"), "/guest.rs"));

use micropb::{MessageEncode, PbEncoder};

/// Maximum message size (excluding 2-byte length prefix).
///
/// This is sized to accommodate InfoResultMessage with file paths up to 1024
/// characters each (QCOW2 spec allows 1023 bytes for backing file path).
/// This approach trades stack efficiency for simplicity.
///
/// TODO: Consider refactoring to caller-provided buffers if stack usage
/// becomes a concern in deeply nested call stacks.
pub const MAX_MESSAGE_SIZE: usize = 2200;

/// Frame header size (2-byte little-endian length)
pub const FRAME_HEADER_SIZE: usize = 2;

/// Encode a GuestMessage with length-prefix framing into a buffer.
///
/// Returns the total number of bytes written (header + message), or None if
/// the buffer is too small.
///
/// # Arguments
///
/// * `msg` - The GuestMessage to encode
/// * `buf` - Output buffer (must be at least FRAME_HEADER_SIZE + message size)
///
/// # Returns
///
/// The total number of bytes written, or None if encoding failed.
pub fn encode_framed(msg: &guest_::GuestMessage, buf: &mut [u8]) -> Option<usize> {
    if buf.len() < FRAME_HEADER_SIZE {
        return None;
    }

    // Encode message into a heapless Vec first
    let mut encode_buf: heapless::Vec<u8, MAX_MESSAGE_SIZE> = heapless::Vec::new();
    let mut encoder = PbEncoder::new(&mut encode_buf);

    msg.encode(&mut encoder).ok()?;

    let msg_len = encode_buf.len();
    if msg_len > u16::MAX as usize {
        return None;
    }

    let total_len = FRAME_HEADER_SIZE + msg_len;
    if buf.len() < total_len {
        return None;
    }

    // Write length prefix (little-endian)
    let len_bytes = (msg_len as u16).to_le_bytes();
    buf[0] = len_bytes[0];
    buf[1] = len_bytes[1];

    // Copy encoded message to output buffer
    buf[FRAME_HEADER_SIZE..total_len].copy_from_slice(&encode_buf);

    Some(total_len)
}

/// Helper to push a string's chars into a heapless String.
fn push_str(dest: &mut heapless::String<32>, src: &str) {
    dest.clear();
    for c in src.chars() {
        let _ = dest.push(c);
    }
}

/// Helper to push a string into a 48-char heapless String (for UUID: 36 chars).
fn push_str_48(dest: &mut heapless::String<48>, src: &str) {
    dest.clear();
    for c in src.chars() {
        if dest.push(c).is_err() {
            break;
        }
    }
}

/// Helper to create an info-level init message.
pub fn init_message(stage: &str, device: &str, address: u64) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Info;

    let mut init = guest_::InitMessage::default();
    push_str(&mut init.stage, stage);
    push_str(&mut init.device, device);
    init.address = address;

    msg.payload = Some(guest_::GuestMessage_::Payload::Init(init));
    msg
}

/// Helper to create a capacity message.
pub fn capacity_message(device: &str, sectors: u64, bytes: u64) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Info;

    let mut cap = guest_::CapacityMessage::default();
    push_str(&mut cap.device, device);
    cap.sectors = sectors;
    cap.bytes = bytes;

    msg.payload = Some(guest_::GuestMessage_::Payload::Capacity(cap));
    msg
}

/// Helper to create a progress message.
pub fn progress_message(
    operation: &str,
    current: u64,
    total: u64,
    percent: u32,
) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Progress;

    let mut progress = guest_::ProgressMessage::default();
    push_str(&mut progress.operation, operation);
    progress.current = current;
    progress.total = total;
    progress.percent = percent;

    msg.payload = Some(guest_::GuestMessage_::Payload::Progress(progress));
    msg
}

/// Helper to create an error message.
pub fn error_message(
    operation: &str,
    device: &str,
    sector: u64,
    status: u32,
) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Error;

    let mut error = guest_::ErrorMessage::default();
    push_str(&mut error.operation, operation);
    push_str(&mut error.device, device);
    error.sector = sector;
    error.status = status;

    msg.payload = Some(guest_::GuestMessage_::Payload::Error(error));
    msg
}

/// Helper to create a completion message.
pub fn complete_message(operation: &str, count: u64, success: bool) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Complete;

    let mut complete = guest_::CompleteMessage::default();
    push_str(&mut complete.operation, operation);
    complete.count = count;
    complete.success = success;

    msg.payload = Some(guest_::GuestMessage_::Payload::Complete(complete));
    msg
}

/// Helper to push a string into a heapless String of larger capacity (1024).
/// QCOW2 spec allows backing file paths up to 1023 bytes.
fn push_str_1024(dest: &mut heapless::String<1024>, src: &str) {
    dest.clear();
    for c in src.chars() {
        if dest.push(c).is_err() {
            break; // String is full, truncate
        }
    }
}

/// Helper to create an info result message.
///
/// # Arguments
///
/// * `format` - Detected format name ("raw", "qcow2", "vmdk", etc.)
/// * `version` - Format version (e.g., 2 or 3 for QCOW2)
/// * `virtual_size` - Virtual disk size in bytes
/// * `actual_size` - Actual file size in bytes
/// * `cluster_size` - Cluster/grain size in bytes
/// * `flags` - Feature flags bitfield
/// * `backing_file` - Backing file path (empty string if none)
/// * `external_data_file` - External data file path (empty string if none)
#[allow(clippy::too_many_arguments)]
pub fn info_result_message(
    format: &str,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: &str,
    external_data_file: &str,
) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Info;

    let mut info = guest_::InfoResultMessage::default();
    push_str(&mut info.format, format);
    info.version = version;
    info.virtual_size = virtual_size;
    info.actual_size = actual_size;
    info.cluster_size = cluster_size;
    info.flags = flags;
    push_str_1024(&mut info.backing_file, backing_file);
    push_str_1024(&mut info.external_data_file, external_data_file);

    msg.payload = Some(guest_::GuestMessage_::Payload::InfoResult(info));
    msg
}

/// QCOW2 format-specific information for info_result_message_with_qcow2.
pub struct Qcow2InfoData {
    /// Compatibility version ("0.10" or "1.1")
    pub compat: &'static str,
    /// Compression type ("zlib" or "zstd")
    pub compression_type: &'static str,
    /// Whether lazy refcounts are enabled
    pub lazy_refcounts: bool,
    /// Number of refcount bits (typically 16)
    pub refcount_bits: u32,
    /// Whether the image is marked dirty (not cleanly closed)
    pub dirty: bool,
    /// Whether the image is marked corrupt
    pub corrupt: bool,
    /// Whether extended L2 entries are used
    pub extended_l2: bool,
    /// Backing file format (from header extension, e.g., "qcow2", "raw")
    pub backing_format: &'static str,
}

/// Helper to create an info result message with QCOW2-specific information.
#[allow(clippy::too_many_arguments)]
pub fn info_result_message_with_qcow2(
    format: &str,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: &str,
    external_data_file: &str,
    qcow2_info: &Qcow2InfoData,
) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Info;

    let mut info = guest_::InfoResultMessage::default();
    push_str(&mut info.format, format);
    info.version = version;
    info.virtual_size = virtual_size;
    info.actual_size = actual_size;
    info.cluster_size = cluster_size;
    info.flags = flags;
    push_str_1024(&mut info.backing_file, backing_file);
    push_str_1024(&mut info.external_data_file, external_data_file);

    // Set QCOW2-specific information
    push_str(&mut info.qcow2_info.compat, qcow2_info.compat);
    push_str(
        &mut info.qcow2_info.compression_type,
        qcow2_info.compression_type,
    );
    info.qcow2_info.lazy_refcounts = qcow2_info.lazy_refcounts;
    info.qcow2_info.refcount_bits = qcow2_info.refcount_bits;
    info.qcow2_info.dirty = qcow2_info.dirty;
    info.qcow2_info.corrupt = qcow2_info.corrupt;
    info.qcow2_info.extended_l2 = qcow2_info.extended_l2;
    push_str(
        &mut info.qcow2_info.backing_format,
        qcow2_info.backing_format,
    );

    // Mark qcow2_info as present so the encoder includes it
    info._has.set_qcow2_info();

    msg.payload = Some(guest_::GuestMessage_::Payload::InfoResult(info));
    msg
}

/// VMDK format-specific information for info_result_message_with_vmdk.
pub struct VmdkInfoData<'a> {
    /// Content ID (CID)
    pub cid: u32,
    /// Parent Content ID (parentCID) - 0xFFFFFFFF if no parent
    pub parent_cid: u32,
    /// Create type (e.g., "monolithicSparse")
    pub create_type: &'a str,
}

/// Helper to create an info result message with VMDK-specific information.
#[allow(clippy::too_many_arguments)]
pub fn info_result_message_with_vmdk(
    format: &str,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: &str,
    external_data_file: &str,
    vmdk_info: &VmdkInfoData,
) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Info;

    let mut info = guest_::InfoResultMessage::default();
    push_str(&mut info.format, format);
    info.version = version;
    info.virtual_size = virtual_size;
    info.actual_size = actual_size;
    info.cluster_size = cluster_size;
    info.flags = flags;
    push_str_1024(&mut info.backing_file, backing_file);
    push_str_1024(&mut info.external_data_file, external_data_file);

    // Set VMDK-specific information
    info.vmdk_info.cid = vmdk_info.cid;
    info.vmdk_info.parent_cid = vmdk_info.parent_cid;
    push_str(&mut info.vmdk_info.create_type, vmdk_info.create_type);

    // Mark vmdk_info as present so the encoder includes it
    info._has.set_vmdk_info();

    msg.payload = Some(guest_::GuestMessage_::Payload::InfoResult(info));
    msg
}

/// VDI format-specific information for info_result_message_with_vdi.
pub struct VdiInfoData<'a> {
    /// Image type (1=dynamic, 2=fixed)
    pub image_type: u32,
    /// Block size in bytes
    pub block_size: u32,
    /// Total number of blocks in the image
    pub blocks_in_image: u32,
    /// Number of blocks currently allocated
    pub blocks_allocated: u32,
    /// Image UUID as a formatted string
    pub uuid: &'a str,
}

/// Helper to create an info result message with VDI-specific information.
#[allow(clippy::too_many_arguments)]
pub fn info_result_message_with_vdi(
    format: &str,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: &str,
    external_data_file: &str,
    vdi_info: &VdiInfoData,
) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Info;

    let mut info = guest_::InfoResultMessage::default();
    push_str(&mut info.format, format);
    info.version = version;
    info.virtual_size = virtual_size;
    info.actual_size = actual_size;
    info.cluster_size = cluster_size;
    info.flags = flags;
    push_str_1024(&mut info.backing_file, backing_file);
    push_str_1024(&mut info.external_data_file, external_data_file);

    // Set VDI-specific information
    info.vdi_info.image_type = vdi_info.image_type;
    info.vdi_info.block_size = vdi_info.block_size;
    info.vdi_info.blocks_in_image = vdi_info.blocks_in_image;
    info.vdi_info.blocks_allocated = vdi_info.blocks_allocated;
    push_str_48(&mut info.vdi_info.uuid, vdi_info.uuid);

    // Mark vdi_info as present so the encoder includes it
    info._has.set_vdi_info();

    msg.payload = Some(guest_::GuestMessage_::Payload::InfoResult(info));
    msg
}

/// Helper to create a check result message.
///
/// # Arguments
///
/// * `format` - Detected format name ("raw", "qcow2", "vmdk", etc.)
/// * `total_errors` - Total number of errors found
/// * `corruptions` - Number of corruptions
/// * `leaks` - Number of leaks
/// * `refcount_errors` - Number of refcount inconsistencies
/// * `image_end_offset` - Highest byte offset in use
/// * `clusters_checked` - Total clusters checked
/// * `clusters_allocated` - Total allocated clusters
/// * `fragmentation` - Fragmentation percentage (0-100)
/// * `flags` - Status flags bitfield
#[allow(clippy::too_many_arguments)]
pub fn check_result_message(
    format: &str,
    total_errors: u32,
    corruptions: u32,
    leaks: u32,
    refcount_errors: u32,
    image_end_offset: u64,
    clusters_checked: u64,
    clusters_allocated: u64,
    fragmentation: u32,
    flags: u32,
) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Info;

    let mut result = guest_::CheckResultMessage::default();
    push_str(&mut result.format, format);
    result.total_errors = total_errors;
    result.corruptions = corruptions;
    result.leaks = leaks;
    result.refcount_errors = refcount_errors;
    result.image_end_offset = image_end_offset;
    result.clusters_checked = clusters_checked;
    result.clusters_allocated = clusters_allocated;
    result.fragmentation = fragmentation;
    result.flags = flags;

    msg.payload = Some(guest_::GuestMessage_::Payload::CheckResult(result));
    msg
}

// =============================================================================
// VMM -> Guest configuration message support
// =============================================================================

use micropb::{MessageDecode, PbDecoder};

/// Decode a VmmConfig message from a framed buffer (for guest side).
///
/// Returns the decoded config and the number of bytes consumed,
/// or None if decoding failed or buffer is incomplete.
pub fn decode_vmm_config_framed(buf: &[u8]) -> Option<(guest_::VmmConfig, usize)> {
    if buf.len() < FRAME_HEADER_SIZE {
        return None;
    }

    let msg_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let total_len = FRAME_HEADER_SIZE + msg_len;

    if buf.len() < total_len {
        return None;
    }

    let msg_buf = &buf[FRAME_HEADER_SIZE..total_len];
    let mut decoder = PbDecoder::new(msg_buf);
    let mut config = guest_::VmmConfig::default();

    config.decode(&mut decoder, msg_buf.len()).ok()?;

    Some((config, total_len))
}

#[cfg(feature = "std")]
mod decode {
    //! Decoding support for VMM side (requires std feature).

    use super::guest_;
    use micropb::{MessageDecode, PbDecoder};

    /// Decode a framed message from a buffer.
    ///
    /// Returns the decoded message and the number of bytes consumed,
    /// or None if decoding failed or buffer is incomplete.
    pub fn decode_framed(buf: &[u8]) -> Option<(guest_::GuestMessage, usize)> {
        if buf.len() < super::FRAME_HEADER_SIZE {
            return None;
        }

        let msg_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let total_len = super::FRAME_HEADER_SIZE + msg_len;

        if buf.len() < total_len {
            return None;
        }

        let msg_buf = &buf[super::FRAME_HEADER_SIZE..total_len];
        let mut decoder = PbDecoder::new(msg_buf);
        let mut msg = guest_::GuestMessage::default();

        msg.decode(&mut decoder, msg_buf.len()).ok()?;

        Some((msg, total_len))
    }
}

#[cfg(feature = "std")]
pub use decode::decode_framed;

#[cfg(feature = "std")]
extern crate alloc;

#[cfg(feature = "std")]
mod vmm_config_support {
    //! VmmConfig encoding support for VMM side (requires std feature).

    extern crate alloc;
    use alloc::vec::Vec;

    use super::guest_;
    use super::MAX_MESSAGE_SIZE;
    use micropb::{MessageEncode, PbEncoder};

    /// Encode a VmmConfig message with length-prefix framing into a Vec.
    ///
    /// Returns the encoded bytes, or None if encoding failed.
    pub fn encode_vmm_config_framed(config: &guest_::VmmConfig) -> Option<Vec<u8>> {
        // Encode message into a heapless Vec first (micropb requires PbWrite trait)
        let mut encode_buf: heapless::Vec<u8, MAX_MESSAGE_SIZE> = heapless::Vec::new();
        let mut encoder = PbEncoder::new(&mut encode_buf);
        config.encode(&mut encoder).ok()?;

        let msg_len = encode_buf.len();
        if msg_len > u16::MAX as usize {
            return None;
        }

        // Build framed message with length prefix
        let mut result = Vec::with_capacity(super::FRAME_HEADER_SIZE + msg_len);
        let len_bytes = (msg_len as u16).to_le_bytes();
        result.push(len_bytes[0]);
        result.push(len_bytes[1]);
        result.extend_from_slice(&encode_buf);

        Some(result)
    }

    /// Helper to create a VmmConfig with device sector sizes and progress interval.
    ///
    /// # Arguments
    ///
    /// * `input_sector_size` - Sector size for input device in bytes
    /// * `output_sector_size` - Sector size for output device in bytes
    /// * `progress_percent` - Progress update interval (0=none, 1=every 1%, etc.)
    pub fn vmm_config(
        input_sector_size: u32,
        output_sector_size: u32,
        progress_percent: u32,
    ) -> guest_::VmmConfig {
        let mut config = guest_::VmmConfig::default();

        // Add input device config
        let mut input_dev = guest_::DeviceConfig::default();
        super::push_str(&mut input_dev.name, "input");
        input_dev.sector_size = input_sector_size;
        let _ = config.devices.push(input_dev);

        // Add output device config
        let mut output_dev = guest_::DeviceConfig::default();
        super::push_str(&mut output_dev.name, "output");
        output_dev.sector_size = output_sector_size;
        let _ = config.devices.push(output_dev);

        // Set progress interval
        config.progress_percent = progress_percent;

        config
    }

    /// Helper to create a VmmConfig with only an input device.
    ///
    /// Use this for operations that don't need an output device (e.g., info).
    ///
    /// # Arguments
    ///
    /// * `input_sector_size` - Sector size for input device in bytes
    pub fn vmm_config_input_only(input_sector_size: u32) -> guest_::VmmConfig {
        let mut config = guest_::VmmConfig::default();

        // Add input device config only
        let mut input_dev = guest_::DeviceConfig::default();
        super::push_str(&mut input_dev.name, "input");
        input_dev.sector_size = input_sector_size;
        let _ = config.devices.push(input_dev);

        // No progress reporting needed for info
        config.progress_percent = 100;

        config
    }
}

#[cfg(feature = "std")]
pub use vmm_config_support::{encode_vmm_config_framed, vmm_config, vmm_config_input_only};
