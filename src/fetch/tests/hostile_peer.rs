//! A peer on the other end of the socket that is not the fetcher, and does
//! not play fair.
//!
//! The fetcher is the untrusted half of instar's host-side partition, so the
//! privileged side has to survive a peer that was replaced, subverted, or
//! simply built wrong. Each test here puts a hand-rolled peer on the socket
//! and requires the same three things of the client: an `io::Error` rather
//! than a panic, promptly rather than eventually, and not one byte of a
//! rejected reply written into the caller's buffer.
//!
//! The client's unit tests already cover a reply for an id that was never
//! requested, each error status, a status outside the enum, a garbage
//! datagram, a peer that hangs up, a silent peer and a refused init. What is
//! here is the rest: claims that are large rather than malformed, a datagram
//! that outgrows the negotiation, a reply replayed from an earlier request,
//! and a peer that leaves part way through a split read.
//!
//! Every test is bounded. The reply timeout below is short enough that a
//! client which waited for a peer that is never going to answer fails the
//! test instead of stalling the suite.

use std::io;
use std::thread::JoinHandle;
use std::time::Duration;

use fetch_protocol::{
    negotiate_block_size, FetchClient, InitReply, InitRequest, ReadReply, ReadRequest,
    SeqPacketSocket, Status, DEFAULT_BLOCK_SIZE, READ_REPLY_LEN,
};

/// Block size the peer advertises.
///
/// Comfortably smaller than anything the socket could carry, which is what
/// lets a test send a datagram that is legal for the socket and illegal for
/// the negotiation.
const BLOCK: u32 = 4096;

/// Capacity the peer advertises, except where a test advertises its own.
const CAPACITY: u64 = 1 << 20;

/// How long the client waits for a reply before failing the read.
const REPLY_TIMEOUT: Duration = Duration::from_millis(2000);

/// Socket buffer the negotiation tests ask for, small enough that the
/// kernel's grant is what bounds a datagram.
const SMALL_SOCKET_BUFFER: u32 = 4096;

/// The peer's thread, joined when the test finishes.
///
/// Joining matters: the peer owns its end of the socket, and a test that
/// returned without waiting for it could leave the socket open past the end
/// of the test and the panic of a misbehaving peer unreported.
struct Peer {
    handle: Option<JoinHandle<()>>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join().expect("the peer thread panicked");
        }
    }
}

/// Put `script` on the far end of a socketpair, behind an init reply of
/// `init`, and return whatever the client made of it.
///
/// `socket_buffer`, when given, is asked for on this side's end before the
/// init exchange, so that the datagram ceiling the client advertises is the
/// one the kernel granted for that request.
fn connect<F>(
    socket_buffer: Option<u32>,
    init: InitReply,
    script: F,
) -> (io::Result<FetchClient>, Peer)
where
    F: FnOnce(&SeqPacketSocket) + Send + 'static,
{
    let (ours, theirs) = SeqPacketSocket::pair().expect("socketpair");
    if let Some(bytes) = socket_buffer {
        ours.set_send_buffer_size(bytes).expect("SO_SNDBUF");
        ours.set_recv_buffer_size(bytes).expect("SO_RCVBUF");
    }
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        let len = theirs.recv(&mut buf).expect("peer: init request");
        InitRequest::decode(&buf[..len]).expect("peer: the init request decodes");
        theirs.send(&init.encode()).expect("peer: init reply");
        script(&theirs);
        // theirs is dropped here, so a client still waiting sees the close
        // rather than the timeout.
    });
    let mut client = FetchClient::new(ours);
    if let Ok(client) = &mut client {
        client.set_reply_timeout(REPLY_TIMEOUT).expect("timeout");
    }
    let peer = Peer {
        handle: Some(handle),
    };
    (client, peer)
}

/// A client talking to `script` behind a sane init reply.
fn client_for<F>(script: F) -> (FetchClient, Peer)
where
    F: FnOnce(&SeqPacketSocket) + Send + 'static,
{
    let (client, peer) = connect(None, InitReply::new(Status::Ok, BLOCK, CAPACITY), script);
    (client.expect("the init exchange succeeds"), peer)
}

/// Receive and decode one read request.
fn next_request(sock: &SeqPacketSocket) -> ReadRequest {
    let mut buf = [0u8; 256];
    let len = sock.recv(&mut buf).expect("peer: request");
    ReadRequest::decode(&buf[..len], BLOCK).expect("peer: the request decodes")
}

/// Answer a request in full, with `fill` for every byte.
fn answer(sock: &SeqPacketSocket, request: &ReadRequest, fill: u8) {
    let payload = vec![fill; request.length as usize];
    let reply = ReadReply::new(request.id, Status::Ok, request.length);
    sock.send(&reply.encode_datagram(&payload).expect("peer: datagram"))
        .expect("peer: reply");
}

/// The largest datagram a socket asking for `bytes` of buffer can manage.
///
/// Measured rather than computed: the kernel clamps the request to its own
/// maximum and then doubles what is left, so the granted buffer is not the
/// number that was asked for and the ceiling it implies is not derivable from
/// a sysctl by inspection.
fn max_datagram_for(bytes: u32) -> u32 {
    let (socket, _other) = SeqPacketSocket::pair().expect("socketpair");
    socket.set_send_buffer_size(bytes).expect("SO_SNDBUF");
    socket.set_recv_buffer_size(bytes).expect("SO_RCVBUF");
    socket.max_datagram().expect("max datagram")
}

/// A capacity is a number from the peer, and a large one must not become a
/// large allocation or an arithmetic trap.
///
/// `u64::MAX` is the worst such number: the reply buffer must stay sized by
/// the block rather than the capacity, a read whose end lands exactly on
/// `u64::MAX` must be attempted rather than overflowing, and one that would
/// pass it must be refused without asking the peer at all.
#[test]
fn an_advertised_capacity_of_the_whole_address_space_is_handled() {
    let (client, peer) = connect(None, InitReply::new(Status::Ok, BLOCK, u64::MAX), |sock| {
        // The one request that does go out asks for bytes at the very top
        // of the address space, which no source has. Refuse it the way a
        // fetcher would.
        let request = next_request(sock);
        let reply = ReadReply::new(request.id, Status::OutOfRange, 0);
        sock.send(&reply.encode_datagram(&[]).expect("peer: datagram"))
            .expect("peer: reply");
    });
    let mut client = client.expect("a huge capacity is not itself a protocol error");
    assert_eq!(client.capacity(), u64::MAX);
    assert_eq!(client.block_size(), BLOCK);

    // A read whose end would pass u64::MAX is refused here, before any
    // request is built, because no offset can describe it.
    let mut buf = [0xA5u8; 16];
    let err = client
        .read_at(u64::MAX - 8, &mut buf)
        .expect_err("a read past the end of the address space must fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("overflows"), "{err}");

    // A read ending exactly on u64::MAX is inside the advertised capacity, so
    // it is asked for; the peer's refusal is what ends it.
    let err = client
        .read_at(u64::MAX - 16, &mut buf)
        .expect_err("the peer refused the read");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("outside"), "{err}");
    assert_eq!(buf, [0xA5u8; 16], "a refused read wrote to the buffer");

    drop(client);
    drop(peer);
}

/// A reply may not claim more than the negotiation allowed, whatever it
/// carries.
///
/// The claim is checked before the datagram's own size is, so that a peer
/// cannot use a large claimed length to reach past the datagram: the length
/// is refused first and nothing is borrowed at all.
#[test]
fn a_reply_claiming_more_than_the_negotiated_maximum_is_refused() {
    let (mut client, peer) = client_for(|sock| {
        let request = next_request(sock);
        // A header on its own, claiming a payload larger than the block both
        // sides agreed on.
        let header = ReadReply::new(request.id, Status::Ok, BLOCK + 512);
        sock.send(&header.encode()).expect("peer: reply");
    });
    let mut buf = [0xA5u8; 64];
    let err = client
        .read_at(0, &mut buf)
        .expect_err("a length past the negotiated maximum must fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("exceeds the negotiated maximum"),
        "{err}"
    );
    assert_eq!(buf, [0xA5u8; 64], "a refused reply wrote to the buffer");
    drop(client);
    drop(peer);
}

/// A reply may not claim more than its own datagram holds.
///
/// The claimed length is inside the negotiated block here, so the only thing
/// that can catch it is comparing the claim against the bytes that actually
/// arrived.
#[test]
fn a_reply_claiming_more_payload_than_the_datagram_carries_is_refused() {
    let (mut client, peer) = client_for(|sock| {
        let request = next_request(sock);
        let mut datagram = ReadReply::new(request.id, Status::Ok, 2048)
            .encode()
            .to_vec();
        datagram.extend_from_slice(&[0xCCu8; 8]);
        sock.send(&datagram).expect("peer: reply");
    });
    let mut buf = [0xA5u8; 64];
    let err = client
        .read_at(0, &mut buf)
        .expect_err("a claim larger than the datagram must fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("claims 2048 payload bytes"),
        "{err}"
    );
    assert_eq!(buf, [0xA5u8; 64], "a refused reply wrote to the buffer");
    drop(client);
    drop(peer);
}

/// A datagram larger than the negotiation allowed is an error, not a
/// truncation.
///
/// This is what `MSG_TRUNC` on the receive is for. The reply here is
/// well-formed in its first `READ_REPLY_LEN + BLOCK` bytes and then carries
/// another block of payload beyond them, so a receive that reported only what
/// fitted would hand the client a header claiming a full block, a full
/// block of payload to go with it, and no sign that anything had been
/// discarded -- the peer's bytes accepted as the answer. With `MSG_TRUNC` the
/// real length comes back and the mismatch is the error below.
#[test]
fn a_datagram_larger_than_the_negotiated_maximum_is_refused() {
    let (mut client, peer) = client_for(|sock| {
        let request = next_request(sock);
        let mut datagram = ReadReply::new(request.id, Status::Ok, request.length)
            .encode()
            .to_vec();
        let oversized = datagram.len() + request.length as usize + BLOCK as usize;
        datagram.resize(oversized, 0xDD);
        sock.send(&datagram).expect("peer: reply");
    });
    let mut buf = vec![0xA5u8; BLOCK as usize];
    let err = client
        .read_at(0, &mut buf)
        .expect_err("an oversized datagram must fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("datagram into a"), "{err}");
    assert!(
        buf.iter().all(|byte| *byte == 0xA5),
        "an oversized reply wrote to the buffer"
    );
    drop(client);
    drop(peer);
}

/// A reply from an earlier request is not an answer to the current one.
///
/// A split read sends one request per block, and the ids are the only thing
/// that distinguishes one block's answer from another's. A peer that replays
/// the first block's reply, id and all, is offering the wrong bytes for the
/// second block; accepting it would fill the caller's buffer with the wrong
/// contents and report success.
#[test]
fn a_reply_replayed_from_an_earlier_block_is_refused() {
    let (mut client, peer) = client_for(|sock| {
        let first = next_request(sock);
        answer(sock, &first, 0x11);
        // The client now asks for the next block. Answer it with the first
        // block's id and the first block's bytes.
        let second = next_request(sock);
        let payload = vec![0x11u8; second.length as usize];
        let reply = ReadReply::new(first.id, Status::Ok, second.length);
        sock.send(&reply.encode_datagram(&payload).expect("peer: datagram"))
            .expect("peer: reply");
    });
    let mut buf = vec![0xA5u8; 2 * BLOCK as usize];
    let err = client
        .read_at(0, &mut buf)
        .expect_err("a replayed reply must fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("is the one in flight"), "{err}");
    // The first block was answered honestly and is allowed to be there; the
    // second must not have been filled from the replay.
    assert!(
        buf[BLOCK as usize..].iter().all(|byte| *byte == 0xA5),
        "the replayed payload was written to the buffer"
    );
    drop(client);
    drop(peer);
}

/// A peer that leaves part way through a split read fails the whole read.
///
/// The first block arrives, the second never does. A read that filled what it
/// could and returned success would be the worst possible outcome: the caller
/// would parse a buffer whose tail is whatever it held before.
#[test]
fn a_peer_that_closes_part_way_through_a_split_read_is_an_error() {
    let (mut client, peer) = client_for(|sock| {
        let first = next_request(sock);
        answer(sock, &first, 0x11);
        // Take the second request and then leave, closing the socket.
        let _ = next_request(sock);
    });
    let mut buf = vec![0xA5u8; 2 * BLOCK as usize];
    let err = client
        .read_at(0, &mut buf)
        .expect_err("a peer that leaves mid-read must fail");
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert!(err.to_string().contains("closed the connection"), "{err}");
    assert!(
        buf[BLOCK as usize..].iter().all(|byte| *byte == 0xA5),
        "the unanswered block was reported as read"
    );
    drop(client);
    drop(peer);
}

/// The block size the peer proposes is clamped to what this side can carry.
///
/// The ceiling is the one the kernel granted for this socket, not a constant:
/// the same proposal that is refused on a small buffer is accepted on a
/// larger one. A peer whose proposal were taken on trust would have the
/// privileged side sending requests whose replies cannot arrive.
#[test]
fn a_peer_advertising_a_block_this_side_cannot_carry_is_refused() {
    let ceiling = max_datagram_for(SMALL_SOCKET_BUFFER);
    let usable = negotiate_block_size(ceiling, ceiling).expect("a small buffer is still usable");
    assert!(
        usable < DEFAULT_BLOCK_SIZE,
        "the small buffer was granted more than expected: {usable}"
    );

    let (client, peer) = connect(
        Some(SMALL_SOCKET_BUFFER),
        InitReply::new(Status::Ok, DEFAULT_BLOCK_SIZE, CAPACITY),
        |_| {},
    );
    let err = client.expect_err("a block this socket cannot carry must be refused");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("exceeds the negotiated maximum"),
        "{err}"
    );
    drop(peer);

    // The same socket accepts the block that grant does allow, and a reply
    // that size really fits: the refusal above is the ceiling being enforced,
    // not the small buffer being unusable.
    let (client, peer) = connect(
        Some(SMALL_SOCKET_BUFFER),
        InitReply::new(Status::Ok, usable, CAPACITY),
        move |sock| {
            let request = next_request_of(sock, usable);
            answer(sock, &request, 0x77);
        },
    );
    let mut client = client.expect("the granted block is accepted");
    assert_eq!(client.block_size(), usable);
    let mut buf = vec![0u8; usable as usize];
    client
        .read_at(0, &mut buf)
        .expect("a full block still fits");
    assert!(buf.iter().all(|byte| *byte == 0x77));
    assert!(
        READ_REPLY_LEN + usable as usize <= ceiling as usize,
        "the negotiated block does not fit the {ceiling}-byte datagram ceiling"
    );
    drop(client);
    drop(peer);
}

/// Receive and decode one read request against a block size other than
/// [`BLOCK`].
fn next_request_of(sock: &SeqPacketSocket, block: u32) -> ReadRequest {
    let mut buf = [0u8; 256];
    let len = sock.recv(&mut buf).expect("peer: request");
    ReadRequest::decode(&buf[..len], block).expect("peer: the request decodes")
}
