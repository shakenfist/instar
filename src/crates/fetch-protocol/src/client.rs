//! The privileged side's end of the fetch channel: a client that turns
//! offset-addressed reads into request and reply datagrams.
//!
//! [`FetchClient::read_at`] has the same signature and the same contract as
//! the VMM's local backing store -- fill the whole buffer or return an error
//! -- so that the two can be used interchangeably by whatever sits above
//! them.
//!
//! # Trust
//!
//! The peer is assumed hostile, so nothing it sends is believed until it has
//! been checked against what this side asked for:
//!
//! * Only bytes from a reply whose status is [`Status::Ok`] are ever copied
//!   or counted. A reply may carry an error status and a non-zero length;
//!   those bytes are not data.
//! * A reply is matched to its request by id. A reply for an id that was not
//!   asked for is an error, not something to skip: with one request in flight
//!   there is never a legitimate reason to see one.
//! * A reply's payload must be exactly the length requested. A short answer
//!   to a read that was inside the advertised capacity means the source
//!   changed or the peer is wrong, and partially filling the caller's buffer
//!   would hide that.
//! * Every error message is written here, from a status value or a number.
//!   The peer sends no text and its bytes are never interpolated into one.
//!
//! # Status to error kind
//!
//! | Status        | `io::ErrorKind`  | Meaning to this side                      |
//! |---------------|------------------|-------------------------------------------|
//! | `BadRequest`  | `InvalidInput`   | the peer rejected a request this side built |
//! | `Unsupported` | `Unsupported`    | the peer does not implement what was asked |
//! | `OutOfRange`  | `InvalidInput`   | the range lies outside the capacity        |
//! | `ShortRead`   | `UnexpectedEof`  | the source ended before the range did      |
//! | `IoError`     | `Other`          | reading the source failed                  |
//!
//! A reply that cannot be decoded, names an unknown status or id, or carries
//! the wrong amount of payload is `InvalidData`.

use std::io;
use std::time::Duration;

use crate::socket::SeqPacketSocket;
use crate::wire::{
    InitReply, InitRequest, ReadReply, ReadRequest, Status, INIT_REPLY_LEN, READ_REPLY_LEN,
};

/// How long a reply may take before the client gives up on the peer.
const DEFAULT_REPLY_TIMEOUT: Duration = Duration::from_secs(60);

/// The error kind and sentence for a status that is not [`Status::Ok`].
///
/// Returns `None` for `Ok`, which is not an error. The sentences are fixed
/// text from this crate; `what` names the operation, also from this crate.
fn status_error(status: Status, what: &str) -> Option<io::Error> {
    let (kind, sentence) = match status {
        Status::Ok => return None,
        Status::BadRequest => (
            io::ErrorKind::InvalidInput,
            "the fetcher rejected the request as malformed",
        ),
        Status::Unsupported => (
            io::ErrorKind::Unsupported,
            "the fetcher does not support the request",
        ),
        Status::OutOfRange => (
            io::ErrorKind::InvalidInput,
            "the requested range is outside the fetcher's capacity",
        ),
        Status::ShortRead => (
            io::ErrorKind::UnexpectedEof,
            "the fetcher's source ended before the requested range",
        ),
        Status::IoError => (
            io::ErrorKind::Other,
            "the fetcher failed to read its source",
        ),
    };
    Some(io::Error::new(kind, format!("fetch {what}: {sentence}")))
}

/// A connection to a fetcher, after a successful init exchange.
#[derive(Debug)]
pub struct FetchClient {
    socket: SeqPacketSocket,
    block_size: u32,
    capacity: u64,
    next_id: u64,
    /// Reused for every reply: a header plus at most one block.
    recv_buf: Vec<u8>,
    /// Set once an exchange has failed, after which this client is done.
    ///
    /// A request that was sent but not answered -- a timeout, a socket
    /// error, a reply that did not decode -- leaves the stream with an
    /// answer still owed on it. The reply may yet arrive, and it would then
    /// be read as the answer to whatever was asked next. Request ids make
    /// that detectable rather than silent, because a stale reply carries an
    /// older id than the one in flight, but detecting it on every later read
    /// turns one failure into a run of misleading ones. There is also
    /// nothing useful to do with a half-finished conversation: the socket
    /// cannot be resynchronised without knowing how many answers are
    /// outstanding, which is exactly what has been lost. So the first
    /// failure ends the client, and the caller opens another one.
    failed: bool,
}

impl FetchClient {
    /// Perform the init exchange over `socket` and return a ready client.
    ///
    /// Fails if the fetcher refuses, speaks a different version, or proposes
    /// a block size this side cannot carry.
    pub fn new(socket: SeqPacketSocket) -> io::Result<Self> {
        socket.set_recv_timeout(DEFAULT_REPLY_TIMEOUT)?;
        // The socket arrives already sized by whoever created the pair, and
        // this measures what it was given rather than changing it: a caller
        // that deliberately chose a smaller buffer must not have it put
        // back.
        let max_datagram = socket.max_datagram()?;
        socket.send(&InitRequest::new(max_datagram).encode())?;

        let mut init = [0u8; INIT_REPLY_LEN];
        let len = recv_nonempty(&socket, &mut init, "init reply")?;
        let reply = InitReply::decode(&init[..len])?;
        if let Some(err) = status_error(reply.status, "initialisation") {
            return Err(err);
        }
        let block_size = reply.accepted_block_size(max_datagram)?;

        let buf_len = READ_REPLY_LEN
            .checked_add(block_size as usize)
            .ok_or_else(|| io::Error::other("fetch block size overflows the reply buffer"))?;
        Ok(Self {
            socket,
            block_size,
            capacity: reply.capacity,
            next_id: 1,
            failed: false,
            recv_buf: vec![0u8; buf_len],
        })
    }

    /// The negotiated block size: the most payload one reply carries.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// The size in bytes of the source, as the fetcher advertised it.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Change how long a reply may take before the read fails.
    pub fn set_reply_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.socket.set_recv_timeout(timeout)
    }

    /// Fill `buf` with the bytes at `offset`, or return an error.
    ///
    /// A read larger than the negotiated block is split into several
    /// requests, one in flight at a time. A range reaching past the
    /// advertised capacity is refused without asking the peer. On error the
    /// contents of `buf` are unspecified, but no byte from a failed reply is
    /// ever written to it.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let len = u64::try_from(buf.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "read length too large"))?;
        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("read of {len} bytes at offset {offset} overflows a 64-bit offset"),
            )
        })?;
        if end > self.capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "read of {len} bytes at offset {offset} extends past the fetcher's \
                     capacity of {} bytes",
                    self.capacity
                ),
            ));
        }

        let mut position = offset;
        for chunk in buf.chunks_mut(self.block_size as usize) {
            self.read_block(position, chunk)?;
            position += chunk.len() as u64;
        }
        Ok(())
    }

    /// One request and its reply, for at most one block.
    fn read_block(&mut self, offset: u64, chunk: &mut [u8]) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "this fetch connection already failed and cannot be reused",
            ));
        }
        // Anything that returns early from here on leaves an answer owed on
        // the socket, so every path out but the last one ends the client.
        self.failed = true;
        // chunks_mut of a block-sized slice cannot exceed the block, which
        // is a u32, so this conversion cannot fail.
        let length = u32::try_from(chunk.len())
            .map_err(|_| io::Error::other("fetch block does not fit a 32-bit length"))?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.socket
            .send(&ReadRequest::new(id, offset, length).encode())?;

        let got = recv_nonempty(&self.socket, &mut self.recv_buf, "read reply")?;
        let (header, payload) = ReadReply::decode(&self.recv_buf[..got], self.block_size)?;
        if header.id != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "fetch reply is for request {} but request {id} is the one in flight",
                    header.id
                ),
            ));
        }
        // The status is judged before the payload is looked at: bytes that
        // arrive with an error status are not data.
        if let Some(err) = status_error(header.status, "read") {
            return Err(err);
        }
        if payload.len() != chunk.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "fetch reply carries {} bytes for a {}-byte read at offset {offset}",
                    payload.len(),
                    chunk.len()
                ),
            ));
        }
        chunk.copy_from_slice(payload);
        self.failed = false;
        Ok(())
    }
}

/// Receive one datagram, treating an empty one as the peer having gone.
fn recv_nonempty(socket: &SeqPacketSocket, buf: &mut [u8], what: &str) -> io::Result<usize> {
    let len = socket.recv(buf)?;
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("the fetcher closed the connection before sending its {what}"),
        ));
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ReadReply, ReadRequest};
    use std::thread::JoinHandle;

    const BLOCK: u32 = 4096;
    const CAPACITY: u64 = 64 * 1024;

    /// The byte at an offset of the pretend source.
    fn pattern(offset: u64) -> u8 {
        (offset.wrapping_mul(7).wrapping_add(offset >> 8) & 0xff) as u8
    }

    /// Run a hand-rolled peer: answer the init exchange with `init`, then
    /// hand the socket to `script`. The peer thread owns its end, so when it
    /// finishes the client sees a closed connection rather than a hang.
    fn spawn_peer<F>(init: InitReply, script: F) -> io::Result<(FetchClientResult, JoinHandle<()>)>
    where
        F: FnOnce(&SeqPacketSocket) + Send + 'static,
    {
        let (ours, theirs) = SeqPacketSocket::pair()?;
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let len = theirs.recv(&mut buf).expect("peer: init request");
            InitRequest::decode(&buf[..len]).expect("peer: decode init");
            theirs.send(&init.encode()).expect("peer: init reply");
            script(&theirs);
        });
        let client = FetchClient::new(ours);
        Ok((client, handle))
    }

    type FetchClientResult = io::Result<FetchClient>;

    /// Receive and decode one request.
    fn next_request(sock: &SeqPacketSocket) -> ReadRequest {
        let mut buf = [0u8; 64];
        let len = sock.recv(&mut buf).expect("peer: request");
        ReadRequest::decode(&buf[..len], BLOCK).expect("peer: decode request")
    }

    /// Answer requests faithfully until the client hangs up.
    fn serve_pattern(sock: &SeqPacketSocket) {
        let mut buf = [0u8; 64];
        while let Ok(len) = sock.recv(&mut buf) {
            if len == 0 {
                return;
            }
            let req = ReadRequest::decode(&buf[..len], BLOCK).expect("peer: decode request");
            let payload: Vec<u8> = (0..u64::from(req.length))
                .map(|i| pattern(req.offset + i))
                .collect();
            let reply = ReadReply::new(req.id, Status::Ok, req.length);
            sock.send(&reply.encode_datagram(&payload).expect("peer: encode"))
                .expect("peer: reply");
        }
    }

    fn good_init() -> InitReply {
        InitReply::new(Status::Ok, BLOCK, CAPACITY)
    }

    fn client_for<F>(script: F) -> io::Result<(FetchClient, JoinHandle<()>)>
    where
        F: FnOnce(&SeqPacketSocket) + Send + 'static,
    {
        let (client, handle) = spawn_peer(good_init(), script)?;
        let client = client?;
        client.set_reply_timeout(Duration::from_secs(10))?;
        Ok((client, handle))
    }

    #[test]
    fn init_records_block_size_and_capacity() -> io::Result<()> {
        let (client, handle) = client_for(serve_pattern)?;
        assert_eq!(client.block_size(), BLOCK);
        assert_eq!(client.capacity(), CAPACITY);
        drop(client);
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn normal_read_fills_the_buffer() -> io::Result<()> {
        let (mut client, handle) = client_for(serve_pattern)?;
        let mut buf = [0u8; 100];
        client.read_at(10, &mut buf)?;
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, pattern(10 + i as u64));
        }
        drop(client);
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn read_larger_than_a_block_splits_and_handles_a_ragged_tail() -> io::Result<()> {
        let (mut client, handle) = client_for(serve_pattern)?;
        // Two and a bit blocks, starting off a block boundary.
        let mut buf = vec![0u8; 2 * BLOCK as usize + 123];
        client.read_at(77, &mut buf)?;
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, pattern(77 + i as u64), "byte {i}");
        }
        drop(client);
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn split_read_uses_distinct_increasing_ids() -> io::Result<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        let (mut client, handle) = client_for(move |sock| {
            let mut buf = [0u8; 64];
            while let Ok(len) = sock.recv(&mut buf) {
                if len == 0 {
                    return;
                }
                let req = ReadRequest::decode(&buf[..len], BLOCK).expect("peer: decode");
                tx.send((req.id, req.offset, req.length))
                    .expect("peer: report");
                let payload = vec![0u8; req.length as usize];
                let reply = ReadReply::new(req.id, Status::Ok, req.length);
                sock.send(&reply.encode_datagram(&payload).expect("peer: encode"))
                    .expect("peer: reply");
            }
        })?;
        let mut buf = vec![0u8; 3 * BLOCK as usize];
        client.read_at(0, &mut buf)?;
        drop(client);
        handle.join().expect("peer thread");
        let seen: Vec<_> = rx.try_iter().collect();
        assert_eq!(seen.len(), 3);
        assert!(seen[0].0 < seen[1].0 && seen[1].0 < seen[2].0);
        assert_eq!(seen[1].1, u64::from(BLOCK));
        assert_eq!(seen[2].2, BLOCK);
        Ok(())
    }

    #[test]
    fn empty_read_succeeds_without_traffic() -> io::Result<()> {
        let (mut client, handle) = client_for(serve_pattern)?;
        client.read_at(CAPACITY, &mut [])?;
        drop(client);
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn read_past_capacity_is_refused_locally() -> io::Result<()> {
        let (mut client, handle) = client_for(serve_pattern)?;
        let mut buf = [0u8; 16];
        let err = client
            .read_at(CAPACITY - 8, &mut buf)
            .expect_err("past end");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = client
            .read_at(u64::MAX - 4, &mut buf)
            .expect_err("overflow");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("overflows"), "{err}");
        drop(client);
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn reply_with_an_unrequested_id_is_an_error() -> io::Result<()> {
        let (mut client, handle) = client_for(|sock| {
            let req = next_request(sock);
            let wrong = req.id + 1000;
            let payload = vec![0xaau8; req.length as usize];
            let reply = ReadReply::new(wrong, Status::Ok, req.length);
            sock.send(&reply.encode_datagram(&payload).expect("peer: encode"))
                .expect("peer: reply");
        })?;
        let mut buf = [0u8; 32];
        let err = client.read_at(0, &mut buf).expect_err("wrong id");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("in flight"), "{err}");
        assert_eq!(buf, [0u8; 32], "payload of a rejected reply was copied");
        handle.join().expect("peer thread");
        Ok(())
    }

    /// For each error status, the peer answers with that status and a full
    /// payload of 0xee. The client must report the mapped kind and leave the
    /// buffer untouched.
    fn error_status_case(status: Status, kind: io::ErrorKind, fragment: &str) -> io::Result<()> {
        let (mut client, handle) = client_for(move |sock| {
            let req = next_request(sock);
            let payload = vec![0xeeu8; req.length as usize];
            let reply = ReadReply::new(req.id, status, req.length);
            sock.send(&reply.encode_datagram(&payload).expect("peer: encode"))
                .expect("peer: reply");
        })?;
        let mut buf = [0u8; 64];
        let err = client.read_at(0, &mut buf).expect_err("error status");
        assert_eq!(err.kind(), kind, "{status:?}: {err}");
        assert!(err.to_string().contains(fragment), "{status:?}: {err}");
        assert_eq!(buf, [0u8; 64], "{status:?}: error payload was copied");
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn bad_request_status() -> io::Result<()> {
        error_status_case(Status::BadRequest, io::ErrorKind::InvalidInput, "malformed")
    }

    #[test]
    fn unsupported_status() -> io::Result<()> {
        error_status_case(
            Status::Unsupported,
            io::ErrorKind::Unsupported,
            "does not support",
        )
    }

    #[test]
    fn out_of_range_status() -> io::Result<()> {
        error_status_case(Status::OutOfRange, io::ErrorKind::InvalidInput, "outside")
    }

    #[test]
    fn short_read_status_is_an_error_not_a_partial_fill() -> io::Result<()> {
        error_status_case(
            Status::ShortRead,
            io::ErrorKind::UnexpectedEof,
            "ended before",
        )
    }

    #[test]
    fn io_error_status() -> io::Result<()> {
        error_status_case(Status::IoError, io::ErrorKind::Other, "failed to read")
    }

    #[test]
    fn ok_reply_with_the_wrong_length_is_an_error() -> io::Result<()> {
        let (mut client, handle) = client_for(|sock| {
            let req = next_request(sock);
            let short = req.length - 1;
            let payload = vec![0x55u8; short as usize];
            let reply = ReadReply::new(req.id, Status::Ok, short);
            sock.send(&reply.encode_datagram(&payload).expect("peer: encode"))
                .expect("peer: reply");
        })?;
        let mut buf = [0u8; 32];
        let err = client.read_at(0, &mut buf).expect_err("short payload");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("31 bytes for a 32-byte"), "{err}");
        assert_eq!(buf, [0u8; 32]);
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn reply_with_a_status_outside_the_enum_is_an_error() -> io::Result<()> {
        let (mut client, handle) = client_for(|sock| {
            let req = next_request(sock);
            let mut datagram = ReadReply::new(req.id, Status::Ok, 0).encode().to_vec();
            // Status lives at bytes 4..8; 0x4242 is not defined.
            datagram[4..8].copy_from_slice(&0x4242u32.to_le_bytes());
            sock.send(&datagram).expect("peer: reply");
        })?;
        let mut buf = [0u8; 32];
        let err = client.read_at(0, &mut buf).expect_err("unknown status");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("unknown status"), "{err}");
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn garbage_reply_is_an_error() -> io::Result<()> {
        let (mut client, handle) = client_for(|sock| {
            let _ = next_request(sock);
            sock.send(&[1, 2, 3]).expect("peer: reply");
        })?;
        let mut buf = [0u8; 32];
        let err = client.read_at(0, &mut buf).expect_err("garbage");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("short of its"), "{err}");
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn peer_that_hangs_up_is_an_error() -> io::Result<()> {
        let (mut client, handle) = client_for(|sock| {
            let _ = next_request(sock);
        })?;
        let mut buf = [0u8; 32];
        let err = client.read_at(0, &mut buf).expect_err("hangup");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn silent_peer_times_out() -> io::Result<()> {
        let (mut client, handle) = client_for(|sock| {
            let _ = next_request(sock);
            std::thread::sleep(Duration::from_millis(800));
        })?;
        client.set_reply_timeout(Duration::from_millis(100))?;
        let mut buf = [0u8; 32];
        let err = client.read_at(0, &mut buf).expect_err("timeout");
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{err}"
        );
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn refused_init_is_an_error_for_each_status() -> io::Result<()> {
        let cases = [
            (Status::BadRequest, io::ErrorKind::InvalidInput),
            (Status::Unsupported, io::ErrorKind::Unsupported),
            (Status::OutOfRange, io::ErrorKind::InvalidInput),
            (Status::ShortRead, io::ErrorKind::UnexpectedEof),
            (Status::IoError, io::ErrorKind::Other),
        ];
        for (status, kind) in cases {
            let (client, handle) = spawn_peer(InitReply::new(status, 0, 0), |_| {})?;
            let err = client.expect_err("refused init");
            assert_eq!(err.kind(), kind, "{status:?}: {err}");
            assert!(err.to_string().contains("initialisation"), "{err}");
            handle.join().expect("peer thread");
        }
        Ok(())
    }

    #[test]
    fn init_with_an_unusable_block_size_is_an_error() -> io::Result<()> {
        for block in [0, 100, crate::wire::MAX_BLOCK_SIZE + 512] {
            let (client, handle) = spawn_peer(InitReply::new(Status::Ok, block, CAPACITY), |_| {})?;
            let err = client.expect_err("bad block size");
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidData,
                "block {block}: {err}"
            );
            handle.join().expect("peer thread");
        }
        Ok(())
    }

    #[test]
    fn init_with_a_bad_magic_is_an_error() -> io::Result<()> {
        let mut reply = InitReply::new(Status::Ok, BLOCK, CAPACITY);
        reply.magic = 0xdead_beef;
        let (ours, theirs) = SeqPacketSocket::pair()?;
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            theirs.recv(&mut buf).expect("peer: init request");
            // encode() writes the field as given, so this is a forged magic.
            theirs.send(&reply.encode()).expect("peer: init reply");
        });
        let err = FetchClient::new(ours).expect_err("bad magic");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        handle.join().expect("peer thread");
        Ok(())
    }
    /// A failed exchange ends the client rather than leaving it usable.
    ///
    /// The request that failed is still owed an answer, so a later read on
    /// the same connection could be handed the stale reply. The first
    /// failure is reported as itself; every attempt after it says the
    /// connection is finished.
    #[test]
    fn a_failed_exchange_ends_the_connection() {
        let (client, handle) = spawn_peer(InitReply::new(Status::Ok, BLOCK, CAPACITY), |sock| {
            // Answer the first request with someone else's id, then say
            // nothing more. A client that kept going would send a second
            // request and read this reply as its answer.
            let request = next_request(sock);
            let reply = ReadReply::new(request.id.wrapping_add(7), Status::Ok, request.length);
            let payload = vec![0u8; request.length as usize];
            sock.send(&reply.encode_datagram(&payload).expect("peer: datagram"))
                .expect("peer: reply");
            // Hold the socket open so a second request would not see EOF.
            std::thread::sleep(std::time::Duration::from_millis(250));
        })
        .expect("pair");
        let mut client = client.expect("init");

        let mut buf = [0u8; 512];
        let first = client.read_at(0, &mut buf).expect_err("wrong id must fail");
        assert_eq!(first.kind(), io::ErrorKind::InvalidData);
        assert!(
            first.to_string().contains("is the one in flight"),
            "unexpected first error: {first}"
        );

        let second = client
            .read_at(0, &mut buf)
            .expect_err("a failed client must refuse further reads");
        assert_eq!(second.kind(), io::ErrorKind::BrokenPipe);
        assert!(
            second.to_string().contains("already failed"),
            "unexpected second error: {second}"
        );

        drop(client);
        handle.join().expect("peer thread");
    }
}
