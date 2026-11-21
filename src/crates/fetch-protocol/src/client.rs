//! The privileged side's end of the fetch channel: a client that turns
//! offset-addressed reads into request and reply datagrams.
//!
//! [`FetchClient::read_at`] has the same signature and the same contract as
//! the VMM's local backing store -- fill the whole buffer or return an error
//! -- so that the two can be used interchangeably by whatever sits above
//! them. That contract includes what happens past the end of the source:
//! the block device's capacity is the source's length rounded up to a whole
//! sector, so the guest's last read legitimately reaches past it, and both
//! stores answer the overhang with zeros rather than an error.
//!
//! The capacity is what the fetcher advertised at init and is not re-read,
//! so a source that grows afterwards reads back as zeros past the advertised
//! size and one that shrinks fails with `UnexpectedEof`. That is also what
//! the local store does with a file that changes under it, which is what
//! keeps the two interchangeable.
//!
//! # Time
//!
//! The bound on a read is a deadline for the whole call, not for each
//! datagram. A read larger than the negotiated block is several round
//! trips, and a peer that answered each one just inside a per-datagram
//! timeout could hold the privileged process for as long as it liked while
//! never tripping it.
//!
//! The deadline covers both directions. A peer that stops answering blocks
//! the reply, and a peer that stops reading blocks the request in the
//! kernel once its receive buffer is full; both are the same hang from this
//! side, so both are bounded.
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
//! | `ShortRead`   | `UnexpectedEof`  | the source ended inside the advertised range |
//! | `IoError`     | `Other`          | reading the source failed                  |
//!
//! A reply that cannot be decoded, names an unknown status or id, or carries
//! the wrong amount of payload is `InvalidData`.

use std::io;
use std::time::{Duration, Instant};

use crate::socket::SeqPacketSocket;
use crate::wire::{
    InitReply, InitRequest, ReadReply, ReadRequest, Status, INIT_REPLY_LEN, READ_REPLY_LEN,
};

/// How long a whole read may take before the client gives up on the peer.
const DEFAULT_REPLY_TIMEOUT: Duration = Duration::from_secs(60);

/// The least time left on a read's deadline that is worth a round trip.
///
/// `SO_RCVTIMEO` is a `timeval`, so anything under a microsecond rounds to
/// zero, which the kernel reads as no timeout at all. Giving up a
/// millisecond early is cheaper than reasoning about that boundary.
const MIN_REPLY_WINDOW: Duration = Duration::from_millis(1);

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
    /// How long one call to [`FetchClient::read_at`] may take in total.
    reply_timeout: Duration,
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
        // Both directions, because a peer that stops reading blocks a send
        // in the kernel just as a peer that stops answering blocks a recv.
        socket.set_send_timeout(DEFAULT_REPLY_TIMEOUT)?;
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
            reply_timeout: DEFAULT_REPLY_TIMEOUT,
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

    /// Change how long a whole [`FetchClient::read_at`] may take.
    ///
    /// The timeout bounds the call rather than each datagram, so a read that
    /// splits into several round trips gets this long for all of them
    /// together.
    pub fn set_reply_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        // A deadline shorter than the window a round trip is given would
        // fail every read before sending anything, which is a stuck client
        // rather than a tight one. Refusing it here is the same guard the
        // socket applies to a timeout that would round away to none.
        if timeout < MIN_REPLY_WINDOW {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "a reply timeout of {timeout:?} is below the {MIN_REPLY_WINDOW:?} a round \
                     trip is given, so no read could ever be attempted"
                ),
            ));
        }
        self.socket.set_recv_timeout(timeout)?;
        self.socket.set_send_timeout(timeout)?;
        self.reply_timeout = timeout;
        Ok(())
    }

    /// Fill `buf` with the bytes at `offset`, or return an error.
    ///
    /// A read larger than the negotiated block is split into several
    /// requests, one in flight at a time, and the whole call shares one
    /// deadline. On error the contents of `buf` are unspecified, but no byte
    /// from a failed reply is ever written to it.
    ///
    /// Bytes past the advertised capacity are zeros, and are never asked of
    /// the peer. This is the local backing store's behaviour and the reason
    /// is the same: a block device's capacity is its source's length rounded
    /// up to a whole sector, so a guest reading the last sector of a source
    /// that is not a sector multiple is reading past the end of it legally.
    /// The zeros are this side's, not the peer's.
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
            if offset >= self.capacity {
                // Entirely past the source: all zeros, and no round trip.
                buf.fill(0);
                return Ok(());
            }
            // Partly past it: fetch what the source has, zero the overhang.
            // The subtraction is below `len`, so the cast cannot truncate.
            let present = (self.capacity - offset) as usize;
            let (wanted, past_end) = buf.split_at_mut(present);
            self.fetch(offset, wanted)?;
            past_end.fill(0);
            return Ok(());
        }

        self.fetch(offset, buf)
    }

    /// Fetch a range that lies wholly inside the advertised capacity.
    fn fetch(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        // One deadline for the whole call. A per-datagram bound would let a
        // peer answer each block just inside it and still hold this process
        // for as long as the read has blocks.
        let deadline = Instant::now() + self.reply_timeout;
        let mut position = offset;
        for chunk in buf.chunks_mut(self.block_size as usize) {
            self.read_block(deadline, position, chunk)?;
            position += chunk.len() as u64;
        }
        Ok(())
    }

    /// The error for a read whose deadline ran out at `offset`.
    ///
    /// `stage` says what the peer had not done, because the two ends of a
    /// round trip fail differently: a peer that has stopped reading blocks
    /// the request, and a peer that has stopped answering blocks the reply.
    fn timed_out(&self, offset: u64, stage: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "the fetcher did not finish this read within {:?}; it {stage} at offset {offset}",
                self.reply_timeout
            ),
        )
    }

    /// One request and its reply, for at most one block.
    fn read_block(&mut self, deadline: Instant, offset: u64, chunk: &mut [u8]) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "this fetch connection already failed and cannot be reused",
            ));
        }
        // Anything that returns early from here on leaves an answer owed on
        // the socket, so every path out but the last one ends the client.
        self.failed = true;
        // What is left of the read's deadline is what this block gets.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining < MIN_REPLY_WINDOW {
            return Err(self.timed_out(offset, "had run out of time before the request for"));
        }
        self.socket.set_recv_timeout(remaining)?;
        self.socket.set_send_timeout(remaining)?;
        // chunks_mut of a block-sized slice cannot exceed the block, which
        // is a u32, so this conversion cannot fail.
        let length = u32::try_from(chunk.len())
            .map_err(|_| io::Error::other("fetch block does not fit a 32-bit length"))?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if let Err(err) = self
            .socket
            .send(&ReadRequest::new(id, offset, length).encode())
        {
            // A full peer receive buffer blocks the send itself, and an
            // expired `SO_SNDTIMEO` surfaces the same way an expired
            // `SO_RCVTIMEO` does.
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                return Err(self.timed_out(offset, "had not taken the request for"));
            }
            return Err(err);
        }

        let got = match recv_nonempty(&self.socket, &mut self.recv_buf, "read reply") {
            Ok(got) => got,
            // The kernel reports an expired `SO_RCVTIMEO` as `EAGAIN`, which
            // renders as "resource temporarily unavailable" and names
            // neither the peer nor the deadline it missed.
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(self.timed_out(offset, "was still answering"));
            }
            Err(err) => return Err(err),
        };
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
        let mut client = client?;
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
    fn a_read_overhanging_the_source_is_zero_filled_not_refused() -> io::Result<()> {
        // What the local backing store does, and what the block device's
        // rounded-up capacity makes the guest's last read look like.
        let (mut client, handle) = client_for(serve_pattern)?;
        let mut buf = [0xA5u8; 16];
        client.read_at(CAPACITY - 8, &mut buf)?;
        for (i, byte) in buf[..8].iter().enumerate() {
            assert_eq!(*byte, pattern(CAPACITY - 8 + i as u64), "byte {i}");
        }
        assert_eq!(&buf[8..], &[0u8; 8], "the overhang is this side's zeros");
        drop(client);
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn a_read_wholly_past_the_source_asks_the_peer_for_nothing() -> io::Result<()> {
        // The peer fails the test if it is asked: zeros for bytes that do
        // not exist are this side's to produce, and a request for them
        // would be answered `OutOfRange` anyway.
        let (mut client, handle) = client_for(|sock| {
            let mut buf = [0u8; 64];
            let len = sock.recv(&mut buf).expect("peer: recv");
            assert_eq!(len, 0, "the client asked for bytes past the capacity");
        })?;
        let mut buf = [0xA5u8; 32];
        client.read_at(CAPACITY, &mut buf)?;
        assert_eq!(&buf[..], &[0u8; 32]);
        let mut buf = [0xA5u8; 32];
        client.read_at(CAPACITY + 4096, &mut buf)?;
        assert_eq!(&buf[..], &[0u8; 32]);
        drop(client);
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn a_read_that_overflows_the_offset_space_is_refused() -> io::Result<()> {
        let (mut client, handle) = client_for(serve_pattern)?;
        let mut buf = [0u8; 16];
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
    fn a_deadline_too_short_for_a_round_trip_is_refused_not_accepted() -> io::Result<()> {
        // Accepting one would leave a client that fails every read without
        // sending anything, which looks like a dead peer rather than a
        // deadline the caller chose.
        let (client, handle) = spawn_peer(good_init(), |_sock| {})?;
        let mut client = client?;
        for timeout in [Duration::ZERO, Duration::from_micros(999)] {
            let err = client.set_reply_timeout(timeout).expect_err("refused");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
            assert!(err.to_string().contains("round trip"), "{err}");
        }
        // The floor itself is accepted: the guard is a floor, not a minimum
        // anyone has to guess at.
        client.set_reply_timeout(MIN_REPLY_WINDOW)?;
        drop(client);
        handle.join().expect("peer thread");
        Ok(())
    }

    #[test]
    fn the_deadline_bounds_the_whole_read_not_each_reply() -> io::Result<()> {
        // Every reply arrives well inside the timeout; together they do not.
        // A per-datagram bound passes this and a per-read bound fails it,
        // which is the whole difference being tested.
        let (client, handle) = spawn_peer(good_init(), |sock| {
            let mut buf = [0u8; 64];
            while let Ok(len) = sock.recv(&mut buf) {
                if len == 0 {
                    return;
                }
                let Ok(req) = ReadRequest::decode(&buf[..len], BLOCK) else {
                    return;
                };
                std::thread::sleep(Duration::from_millis(200));
                let payload = vec![0u8; req.length as usize];
                let reply = ReadReply::new(req.id, Status::Ok, req.length);
                if sock
                    .send(&reply.encode_datagram(&payload).expect("peer: encode"))
                    .is_err()
                {
                    return;
                }
            }
        })?;
        let mut client = client?;
        client.set_reply_timeout(Duration::from_secs(1))?;
        // Eight blocks at 200 ms each is 1.6 s of answers, none of which is
        // itself late.
        let mut buf = vec![0u8; 8 * BLOCK as usize];
        let started = Instant::now();
        let err = client.read_at(0, &mut buf).expect_err("deadline");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert!(err.to_string().contains("did not finish"), "{err}");
        assert!(
            started.elapsed() < Duration::from_millis(1600),
            "gave up after {:?}, which is the whole read",
            started.elapsed()
        );
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
