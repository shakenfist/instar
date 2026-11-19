//! Reads a real file through the real `instar-fetch` binary, and checks every
//! byte against `pread` on the same file.
//!
//! Everything else in this crate's tests exercises a piece: the decoder
//! against hand-made datagrams, the status decisions against a pretend
//! source, the client against a hand-rolled peer. This is the only test that
//! runs the whole thing -- a spawned process, an inherited descriptor, a
//! `SOCK_SEQPACKET` socket, the init negotiation and a few hundred reads --
//! and the only one that can catch a disagreement between the two sides that
//! both halves implement consistently with their own tests.
//!
//! The oracle is `pread` on the same file, through
//! [`std::os::unix::fs::FileExt::read_exact_at`]. Byte-identical or the test
//! fails: there is no tolerance to express for a read of a file.
//!
//! # Why the test lives in this package
//!
//! Cargo defines `CARGO_BIN_EXE_<name>` only for integration tests in the
//! same package as the binary, so a test here is handed the exact path of the
//! binary cargo just built for it. Nothing has to search for it, derive it
//! from the test executable's own location, or guess at a profile directory,
//! and there is no case where the binary is missing to skip over.
//!
//! # Passing the descriptors
//!
//! The fetcher takes two descriptor numbers and opens nothing, so the test
//! has to place the socket and the file on known numbers in the child.
//! `std::process::Command` has no way to pass a descriptor, so `pre_exec`
//! does it with `dup2`, which is the one thing it can safely do between the
//! fork and the exec.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fetch_protocol::{
    negotiate_block_size, FetchClient, InitReply, InitRequest, ReadReply, ReadRequest,
    SeqPacketSocket, Status, DEFAULT_BLOCK_SIZE, MAX_BLOCK_SIZE, READ_REPLY_LEN,
};
use std::io::Write;
use tempfile::NamedTempFile;

/// Size of the file served.
///
/// Deliberately not a multiple of any block size the negotiation can settle
/// on, so that the last block is always a partial one and the arithmetic for
/// a ragged tail is exercised by every whole-file read.
const IMAGE_LEN: usize = 1_052_673;

/// Seed for the pseudo-random contents and for the random read schedule.
///
/// Fixed so that a failure can be reproduced exactly: the same offsets and
/// lengths are read in the same order on every run and every host.
const SEED: u64 = 0x0DDB_A11A_5EED_1234;

/// How long a reply may take before a read fails.
///
/// Every test is bounded by this. A fetcher that wedges has to make the suite
/// fail rather than make it hang, and the client's own default is minutes.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Socket buffer the negotiation test asks for on its own end of the pair.
///
/// Small enough that the kernel's grant, and not the protocol's default or
/// its ceiling, is what decides the block size.
const SMALL_SOCKET_BUFFER: u32 = 4096;

/// Descriptor number the child finds the socket on.
const CHILD_SOCKET_FD: RawFd = 10;

/// Descriptor number the child finds the file on.
const CHILD_FILE_FD: RawFd = 11;

/// SplitMix64, so that the contents and the read schedule are reproducible
/// without a dependency.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`, which must not be zero.
    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

/// A file of known pseudo-random bytes, removed when the test finishes.
struct TempImage {
    // `NamedTempFile` creates with `O_EXCL` under a random name and removes
    // the file when it is dropped. A predictable name in a shared temporary
    // directory would let another user pre-create it as a symlink and have
    // the test truncate whatever it pointed at.
    file: NamedTempFile,
}

impl TempImage {
    fn new(len: usize) -> io::Result<Self> {
        let mut rng = Rng(SEED);
        let mut bytes = vec![0u8; len];
        for byte in bytes.iter_mut() {
            *byte = (rng.next_u64() & 0xff) as u8;
        }
        let mut file = NamedTempFile::new()?;
        file.write_all(&bytes)?;
        file.flush()?;
        Ok(Self { file })
    }

    fn open(&self) -> io::Result<File> {
        File::open(self.file.path())
    }
}

/// The spawned fetcher, reaped when the test finishes.
struct Fetcher {
    child: Child,
}

impl Fetcher {
    /// Wait for the fetcher to exit and return its status.
    ///
    /// `Drop` still runs afterwards; killing and waiting on an already
    /// reaped child fails harmlessly, and both results are discarded there.
    fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        self.child.wait()
    }
}

impl Drop for Fetcher {
    fn drop(&mut self) {
        // The client's socket is dropped first, so a well-behaved fetcher has
        // already seen the close and is exiting. Killing it anyway means a
        // fetcher that did not exit leaves no stray process behind, and
        // waiting means no zombie either.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Duplicate a descriptor onto a number at or above `lowest`.
///
/// The child's two `dup2` calls must not have a source that is also one of
/// their destinations: `dup2(n, n)` is a no-op that leaves `FD_CLOEXEC` set,
/// which would hand the fetcher a descriptor that `exec` then closes. Moving
/// both descriptors above the destinations first makes that impossible rather
/// than unlikely.
fn dup_above<T: AsRawFd>(source: &T, lowest: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC only duplicates the descriptor, and the result
    // is checked before it is treated as one.
    let raw = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, lowest) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl reported a new descriptor, which this process owns and
    // nothing else holds.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Spawn the fetcher with `socket` and `file` on the numbers it is told.
fn spawn_fetcher(socket: SeqPacketSocket, file: &File) -> io::Result<Fetcher> {
    let socket_copy = dup_above(&socket, CHILD_FILE_FD + 1)?;
    let file_copy = dup_above(file, CHILD_FILE_FD + 1)?;
    let socket_raw = socket_copy.as_raw_fd();
    let file_raw = file_copy.as_raw_fd();

    let mut command = Command::new(env!("CARGO_BIN_EXE_instar-fetch"));
    command
        .arg(CHILD_SOCKET_FD.to_string())
        .arg(CHILD_FILE_FD.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // The fetcher's diagnostics are one line each and are not what this
        // test is about; inheriting them would interleave them with the test
        // harness's own output on every spawn.
        .stderr(Stdio::null());
    // SAFETY: the closure runs in the forked child, between fork and exec,
    // where only async-signal-safe work is allowed. It does two dup2 calls
    // and builds an io::Error from errno, neither of which allocates or
    // takes a lock.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(socket_raw, CHILD_SOCKET_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::dup2(file_raw, CHILD_FILE_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;

    // The parent keeps no copy of either descriptor: the fetcher's end of the
    // socket has to be the only one left, or it never sees the client hang up
    // and the test waits for a process that is waiting for it.
    drop(socket);
    drop(socket_copy);
    drop(file_copy);
    Ok(Fetcher { child })
}

/// A client talking to a real fetcher, and the file to check it against.
struct Rig {
    // Declaration order is drop order: the client goes first so the fetcher
    // sees the socket close and exits on its own, then the fetcher is reaped,
    // and the file is removed last.
    client: FetchClient,
    // Held only to be dropped, which reaps the process.
    _fetcher: Fetcher,
    oracle: File,
    image: TempImage,
    /// The largest datagram this side's socket could manage, read back from
    /// the kernel before the init exchange.
    max_datagram: u32,
}

impl Rig {
    /// A rig with the socket buffers the kernel gives by default.
    fn new() -> io::Result<Self> {
        Self::with_socket_buffer(None)
    }

    /// A rig serving a file of `len` bytes instead of the usual one.
    fn with_image_len(len: usize) -> io::Result<Self> {
        Self::build(None, len)
    }

    /// A rig, optionally asking for `bytes` of socket buffer in both
    /// directions on this side of the pair before the negotiation runs.
    fn with_socket_buffer(bytes: Option<u32>) -> io::Result<Self> {
        Self::build(bytes, IMAGE_LEN)
    }

    fn build(bytes: Option<u32>, image_len: usize) -> io::Result<Self> {
        let image = TempImage::new(image_len)?;
        let served = image.open()?;
        let oracle = image.open()?;

        let (ours, theirs) = SeqPacketSocket::pair()?;
        if let Some(bytes) = bytes {
            ours.set_send_buffer_size(bytes)?;
            ours.set_recv_buffer_size(bytes)?;
        }
        let max_datagram = ours.max_datagram()?;

        let fetcher = spawn_fetcher(theirs, &served)?;
        drop(served);

        let mut client = FetchClient::new(ours)?;
        client.set_reply_timeout(REPLY_TIMEOUT)?;
        Ok(Self {
            client,
            _fetcher: fetcher,
            oracle,
            image,
            max_datagram,
        })
    }

    /// Read `len` bytes at `offset` both ways, and require them to agree.
    fn check(&mut self, offset: u64, len: usize) {
        let mut served = vec![0xA5u8; len];
        self.client
            .read_at(offset, &mut served)
            .unwrap_or_else(|err| panic!("read of {len} bytes at offset {offset} failed: {err}"));

        let mut expected = vec![0x5Au8; len];
        self.oracle
            .read_exact_at(&mut expected, offset)
            .unwrap_or_else(|err| panic!("pread of {len} bytes at offset {offset} failed: {err}"));

        // Comparing with assert_eq! would dump two buffers of up to a
        // megabyte into the failure message, which hides the one fact that
        // matters: where they first differ.
        if served != expected {
            let at = served
                .iter()
                .zip(expected.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(len);
            panic!(
                "read of {len} bytes at offset {offset} differs from pread at byte {at}: \
                 the protocol gave {:#04x}, the file holds {:#04x}",
                served.get(at).copied().unwrap_or_default(),
                expected.get(at).copied().unwrap_or_default()
            );
        }
    }

    /// The block size the init exchange settled on.
    fn block(&self) -> usize {
        self.client.block_size() as usize
    }
}

#[test]
fn the_advertised_capacity_is_the_size_of_the_file() -> io::Result<()> {
    let rig = Rig::new()?;
    assert_eq!(rig.client.capacity(), IMAGE_LEN as u64);
    // The file is served from an inherited descriptor and the fetcher takes
    // no path, so the capacity it found can only have come from that
    // descriptor.
    assert!(rig.image.file.path().exists());
    Ok(())
}

#[test]
fn a_read_at_offset_zero_matches_pread() -> io::Result<()> {
    let mut rig = Rig::new()?;
    rig.check(0, 4096);
    Ok(())
}

#[test]
fn a_one_byte_read_matches_pread() -> io::Result<()> {
    let mut rig = Rig::new()?;
    let block = rig.block() as u64;
    for offset in [0, 1, 511, block - 1, block, block + 1, IMAGE_LEN as u64 - 1] {
        rig.check(offset, 1);
    }
    Ok(())
}

#[test]
fn the_last_partial_block_matches_pread() -> io::Result<()> {
    let mut rig = Rig::new()?;
    let block = rig.block();
    // The file is not a whole number of blocks, so the tail is always short
    // of one -- the case where a fetcher that answered a full block anyway
    // would be reporting bytes past the end of the file.
    let tail_start = (IMAGE_LEN / block) * block;
    let tail = IMAGE_LEN - tail_start;
    assert!(tail > 0 && tail < block, "block {block} divides the image");
    rig.check(tail_start as u64, tail);
    // And the last byte on its own, which is the tightest version of the
    // same case.
    rig.check(IMAGE_LEN as u64 - 1, 1);
    Ok(())
}

#[test]
fn a_read_spanning_a_block_boundary_matches_pread() -> io::Result<()> {
    let mut rig = Rig::new()?;
    let block = rig.block() as u64;
    // Straddling the boundary two ways: a few bytes either side of it, and a
    // read that starts just before it and ends well past it.
    rig.check(block - 7, 14);
    rig.check(block - 1, block as usize + 2);
    Ok(())
}

#[test]
fn a_read_larger_than_the_negotiated_block_matches_pread() -> io::Result<()> {
    let mut rig = Rig::new()?;
    let block = rig.block();
    // Two whole blocks and a ragged tail, starting off a block boundary, so
    // that no request after the first is block-aligned.
    rig.check(77, 2 * block + 123);
    Ok(())
}

#[test]
fn the_whole_file_matches_pread() -> io::Result<()> {
    let mut rig = Rig::new()?;
    rig.check(0, IMAGE_LEN);
    Ok(())
}

#[test]
fn a_few_hundred_seeded_offsets_and_lengths_match_pread() -> io::Result<()> {
    let mut rig = Rig::new()?;
    let block = rig.block();
    let capacity = IMAGE_LEN as u64;
    let mut rng = Rng(SEED ^ 0xFFFF);
    for round in 0..300u32 {
        let offset = rng.below(capacity);
        // Most reads are the size the guest's own are or smaller; every tenth
        // is large enough to be split into several requests.
        let want = if round % 10 == 0 { 3 * block } else { 65536 };
        let room = (capacity - offset).min(want as u64);
        let len = rng.below(room + 1) as usize;
        rig.check(offset, len);
    }
    Ok(())
}

/// A read overhanging the end of the file is zeros, not an error.
///
/// This is the shape the guest's own reads have: the block device's capacity
/// is the image's length rounded up to a whole sector, so the last sector of
/// any image that is not a sector multiple reaches past the file. The local
/// backing store zero-pads it, and a fetcher that refused it would fail
/// every such image once the two are interchangeable.
#[test]
fn a_read_overhanging_the_end_of_the_file_is_zero_filled() -> io::Result<()> {
    let mut rig = Rig::new()?;
    // The last 64 KiB sector of this file, as the VMM would round it up.
    let sector = 65536usize;
    let last = (IMAGE_LEN / sector) * sector;
    let present = IMAGE_LEN - last;
    let mut served = vec![0xA5u8; sector];
    rig.client.read_at(last as u64, &mut served)?;

    let mut expected = vec![0x5Au8; present];
    rig.oracle.read_exact_at(&mut expected, last as u64)?;
    assert_eq!(&served[..present], &expected[..], "the bytes that exist");
    assert!(
        served[present..].iter().all(|byte| *byte == 0),
        "the overhang is not zero filled"
    );

    // A read that begins past the end is all zeros too, and asks the fetcher
    // for nothing: the request would be refused `OutOfRange` if it were sent.
    let mut served = vec![0xA5u8; 4096];
    rig.client.read_at(IMAGE_LEN as u64 + 4096, &mut served)?;
    assert!(served.iter().all(|byte| *byte == 0));

    // An offset that cannot be reached at all is still a refusal.
    let err = rig
        .client
        .read_at(u64::MAX - 4, &mut served)
        .expect_err("an overflowing offset must fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    Ok(())
}

/// A source with no bytes at all still serves, and serves only zeros.
///
/// An empty file is a legal image file and a plausible mistake, and it is
/// the one capacity where every read is entirely overhang.
#[test]
fn an_empty_file_serves_zeros_without_a_round_trip() -> io::Result<()> {
    let mut rig = Rig::with_image_len(0)?;
    assert_eq!(rig.client.capacity(), 0);
    let mut served = vec![0xA5u8; 8192];
    rig.client.read_at(0, &mut served)?;
    assert!(served.iter().all(|byte| *byte == 0));
    rig.client.read_at(1 << 40, &mut served)?;
    assert!(served.iter().all(|byte| *byte == 0));
    Ok(())
}

/// A descriptor that is not a regular file is refused before init.
///
/// A pipe has no size to advertise and cannot answer a positional read, so
/// the fetcher refuses it outright rather than failing every request. This
/// is a parent-side mistake, which makes it worth proving through the real
/// binary: the exit status and the socket close are what the parent sees.
#[test]
fn a_pipe_is_refused_before_the_init_reply() -> io::Result<()> {
    let (read_end, _write_end) = pipe_pair()?;
    let (ours, theirs) = SeqPacketSocket::pair()?;
    let mut fetcher = spawn_fetcher(theirs, &read_end)?;

    let err = FetchClient::new(ours).expect_err("a pipe has no capacity to serve");
    // Which error depends on a race the parent cannot win either way: a
    // fetcher that has already exited makes the client's `send` of the init
    // request `ECONNRESET`, while one still exiting takes the datagram and
    // the close turns the `recv` into end-of-stream. Both are the same fact
    // -- the fetcher refused before saying anything -- and a caller reading
    // this has to treat them alike.
    assert!(
        matches!(
            err.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
        ),
        "unexpected kind: {err:?}"
    );

    let status = fetcher.wait()?;
    assert_eq!(status.code(), Some(1), "{status}");
    Ok(())
}

/// A datagram longer than the fetcher's buffer is refused by its id.
///
/// The fetcher's claim is that every request it can read an id from is
/// answered, so that the privileged side never waits for a reply that was
/// never coming. An oversized datagram is the shape where the id survives
/// but the request does not: `MSG_TRUNC` reports the real length while the
/// kernel keeps only the head. This drives it through the real binary,
/// because the client cannot send the shape -- it is a hostile peer's
/// datagram, and the point is what the fetcher does with it.
#[test]
fn a_datagram_longer_than_a_request_is_refused_by_its_id() -> io::Result<()> {
    let image = TempImage::new(IMAGE_LEN)?;
    let served = image.open()?;
    let (ours, theirs) = SeqPacketSocket::pair()?;
    let max_datagram = ours.max_datagram()?;
    let mut fetcher = spawn_fetcher(theirs, &served)?;
    drop(served);
    ours.set_recv_timeout(REPLY_TIMEOUT)?;

    // The init exchange by hand, because what follows it is not something a
    // client can be asked to send.
    ours.send(&InitRequest::new(max_datagram).encode())?;
    let mut buf = vec![0u8; READ_REPLY_LEN + MAX_BLOCK_SIZE as usize];
    let len = ours.recv(&mut buf)?;
    let init = InitReply::decode(&buf[..len]).expect("the init reply decodes");
    let block_size = init
        .accepted_block_size(max_datagram)
        .expect("a block size");

    // A well-formed read request with 4 KiB of rubbish stuck on the end:
    // longer than the fetcher's 1 KiB request buffer, so the kernel delivers
    // the head and discards the rest.
    let id = 0x5151_5151_5151_5151;
    let mut overlong = ReadRequest::new(id, 0, 512).encode().to_vec();
    overlong.resize(overlong.len() + 4096, 0xEE);
    ours.send(&overlong)?;

    let len = ours.recv(&mut buf)?;
    let (reply, payload) = ReadReply::decode(&buf[..len], block_size).expect("a reply decodes");
    assert_eq!(reply.id, id, "the refusal names the request that caused it");
    assert_eq!(reply.status, Status::BadRequest, "{:?}", reply.status);
    assert!(payload.is_empty(), "a refusal carries no bytes");

    // And the fetcher is still serving: a refusal is not a reason to stop.
    let wanted = 512usize;
    ours.send(&ReadRequest::new(id + 1, 0, wanted as u32).encode())?;
    let len = ours.recv(&mut buf)?;
    let (reply, payload) = ReadReply::decode(&buf[..len], block_size).expect("a reply decodes");
    assert_eq!(reply.id, id + 1);
    assert_eq!(reply.status, Status::Ok, "{:?}", reply.status);
    let mut expected = vec![0u8; wanted];
    image.open()?.read_exact_at(&mut expected, 0)?;
    assert_eq!(
        payload,
        &expected[..],
        "the bytes after a refusal are right"
    );

    drop(ours);
    fetcher.wait()?;
    Ok(())
}

/// A pipe, as its read end and the write end that keeps it open.
fn pipe_pair() -> io::Result<(File, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe fills the two-element array it is given, and the result
    // is checked before either descriptor is used.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are fresh from pipe and owned here, so each
    // has exactly one owner from this point on.
    unsafe { Ok((File::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// The block size has to follow what the kernel granted, not a constant.
///
/// Neither the protocol's default nor its ceiling is reachable on a socket
/// this small, so if the negotiation were reading a sysctl, assuming a
/// default, or trusting the fetcher's proposal, the block would come out at
/// one of those numbers instead of the one derived from the grant.
#[test]
fn a_small_socket_buffer_lowers_the_negotiated_block_and_reads_still_split() -> io::Result<()> {
    let mut rig = Rig::with_socket_buffer(Some(SMALL_SOCKET_BUFFER))?;
    let block = rig.client.block_size();

    // The kernel clamps the request and then doubles it, so the granted
    // buffer is not the number that was asked for; the block has to be
    // whatever that grant allows. A 4 KiB request is granted 8 KiB on a
    // stock Linux host, which settles the block at 7680 bytes.
    let expected = negotiate_block_size(rig.max_datagram, rig.max_datagram)
        .expect("a small buffer is still usable");
    assert_eq!(
        block, expected,
        "negotiated {block} from a {} byte datagram ceiling",
        rig.max_datagram
    );
    assert!(
        block < DEFAULT_BLOCK_SIZE,
        "the block did not follow the grant: {block}"
    );
    assert!(block < MAX_BLOCK_SIZE, "the block reached the ceiling");

    // A read several times the block still has to come back byte-identical,
    // which can only happen by splitting: the fetcher refuses a single
    // request longer than the block it negotiated.
    rig.check(1234, 3 * block as usize + 57);
    // And the whole file, which at this block size is a few hundred round
    // trips including a ragged last one.
    rig.check(0, IMAGE_LEN);
    Ok(())
}
