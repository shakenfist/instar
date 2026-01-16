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
//! use guest_protocol::{GuestMessage, Level, ProgressMessage, encode_framed};
//!
//! let msg = GuestMessage {
//!     level: Level::Progress,
//!     payload: guest_protocol::guest_message::Payload::Progress(
//!         ProgressMessage {
//!             operation: "copy".into(),
//!             current: 512,
//!             total: 2048,
//!             percent: 25,
//!         }
//!     ),
//!     ..Default::default()
//! };
//!
//! let mut buf = [0u8; 128];
//! let len = encode_framed(&msg, &mut buf).unwrap();
//! serial_write(&buf[..len]);
//! ```

#![no_std]
#![cfg_attr(not(feature = "std"), no_std)]

// Include the generated protobuf code
include!(concat!(env!("OUT_DIR"), "/guest.rs"));

use micropb::{MessageEncode, PbEncoder};

/// Maximum message size (excluding 2-byte length prefix)
pub const MAX_MESSAGE_SIZE: usize = 256;

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

    // Encode message into buffer after the header
    let msg_buf = &mut buf[FRAME_HEADER_SIZE..];
    let mut encoder = PbEncoder::new(msg_buf);

    msg.encode(&mut encoder).ok()?;

    let msg_len = encoder.len();
    if msg_len > u16::MAX as usize {
        return None;
    }

    // Write length prefix (little-endian)
    let len_bytes = (msg_len as u16).to_le_bytes();
    buf[0] = len_bytes[0];
    buf[1] = len_bytes[1];

    Some(FRAME_HEADER_SIZE + msg_len)
}

/// Helper to create an info-level init message.
pub fn init_message(stage: &str, device: &str, address: u64) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Info as i32;

    let mut init = guest_::InitMessage::default();
    init.stage.clear();
    for b in stage.bytes() {
        let _ = init.stage.push(b);
    }
    init.device.clear();
    for b in device.bytes() {
        let _ = init.device.push(b);
    }
    init.address = address;

    msg.payload = guest_::guest_message::Payload::Init(init);
    msg
}

/// Helper to create a capacity message.
pub fn capacity_message(device: &str, sectors: u64, bytes: u64) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Info as i32;

    let mut cap = guest_::CapacityMessage::default();
    cap.device.clear();
    for b in device.bytes() {
        let _ = cap.device.push(b);
    }
    cap.sectors = sectors;
    cap.bytes = bytes;

    msg.payload = guest_::guest_message::Payload::Capacity(cap);
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
    msg.level = guest_::Level::Progress as i32;

    let mut progress = guest_::ProgressMessage::default();
    progress.operation.clear();
    for b in operation.bytes() {
        let _ = progress.operation.push(b);
    }
    progress.current = current;
    progress.total = total;
    progress.percent = percent;

    msg.payload = guest_::guest_message::Payload::Progress(progress);
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
    msg.level = guest_::Level::Error as i32;

    let mut error = guest_::ErrorMessage::default();
    error.operation.clear();
    for b in operation.bytes() {
        let _ = error.operation.push(b);
    }
    error.device.clear();
    for b in device.bytes() {
        let _ = error.device.push(b);
    }
    error.sector = sector;
    error.status = status;

    msg.payload = guest_::guest_message::Payload::Error(error);
    msg
}

/// Helper to create a completion message.
pub fn complete_message(operation: &str, count: u64, success: bool) -> guest_::GuestMessage {
    let mut msg = guest_::GuestMessage::default();
    msg.level = guest_::Level::Complete as i32;

    let mut complete = guest_::CompleteMessage::default();
    complete.operation.clear();
    for b in operation.bytes() {
        let _ = complete.operation.push(b);
    }
    complete.count = count;
    complete.success = success;

    msg.payload = guest_::guest_message::Payload::Complete(complete);
    msg
}

#[cfg(feature = "std")]
mod decode {
    //! Decoding support for VMM side (requires std feature).

    use super::guest;
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
