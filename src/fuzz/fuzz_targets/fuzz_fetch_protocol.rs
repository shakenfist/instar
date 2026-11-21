#![no_main]
use fetch_protocol::{negotiate_block_size, InitReply, InitRequest, ReadReply, ReadRequest, Status};
use libfuzzer_sys::fuzz_target;

fn le_u32(bytes: &[u8]) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[..4]);
    u32::from_le_bytes(raw)
}

fuzz_target!(|data: &[u8]| {
    // Every decoder must reject arbitrary bytes with an error rather than
    // panic; none of them is required to succeed.
    let _ = InitRequest::decode(data);
    let _ = ReadRequest::decode(data, 64 * 1024);
    let _ = ReadReply::decode(data, 64 * 1024);
    // The fetcher recovers an id from a request it is about to refuse, so
    // this reads bytes that failed every other check.
    let _ = ReadRequest::peek_id(data);

    if let Ok(reply) = InitReply::decode(data) {
        let _ = reply.accepted_block_size(64 * 1024);
    }

    // Derive the negotiated values from the input so the length and
    // overflow checks against them are explored, not just a typical size.
    // The first twelve bytes are two datagram sizes and a maximum block;
    // the rest is the datagram.
    if data.len() >= 12 {
        let ours = le_u32(&data[0..4]);
        let theirs = le_u32(&data[4..8]);
        let max_block = le_u32(&data[8..12]);
        let datagram = &data[12..];

        let _ = negotiate_block_size(ours, theirs);
        let _ = Status::from_u32(ours);
        let _ = ReadRequest::decode(datagram, max_block);
        let _ = ReadRequest::peek_id(datagram);
        let _ = ReadReply::decode(datagram, max_block);
        if let Ok(reply) = InitReply::decode(datagram) {
            let _ = reply.accepted_block_size(ours);
            let _ = reply.accepted_block_size(max_block);
        }
    }
});
