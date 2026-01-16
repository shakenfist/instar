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
