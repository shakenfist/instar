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
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use fetch_protocol::{
    negotiate_block_size, FetchClient, SeqPacketSocket, DEFAULT_BLOCK_SIZE, MAX_BLOCK_SIZE,
};

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
    path: PathBuf,
}

impl TempImage {
    fn new(len: usize) -> io::Result<Self> {
        // The counter keeps concurrently-running tests in the same binary off
        // each other's file, since cargo runs them on several threads.
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "instar-fetch-end-to-end-{}-{unique}.img",
            std::process::id()
        ));
        let mut rng = Rng(SEED);
        let mut bytes = vec![0u8; len];
        for byte in bytes.iter_mut() {
            *byte = (rng.next_u64() & 0xff) as u8;
        }
        std::fs::write(&path, &bytes)?;
        Ok(Self { path })
    }

    fn open(&self) -> io::Result<File> {
        File::open(&self.path)
    }
}

impl Drop for TempImage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The spawned fetcher, reaped when the test finishes.
struct Fetcher {
    child: Child,
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

    /// A rig, optionally asking for `bytes` of socket buffer in both
    /// directions on this side of the pair before the negotiation runs.
    fn with_socket_buffer(bytes: Option<u32>) -> io::Result<Self> {
        let image = TempImage::new(IMAGE_LEN)?;
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

        let client = FetchClient::new(ours)?;
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
    assert!(rig.image.path.exists());
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

#[test]
fn a_read_past_the_end_of_the_file_is_refused() -> io::Result<()> {
    let mut rig = Rig::new()?;
    let mut buf = [0u8; 64];
    // The capacity came from the fetcher at init, so this is refused here
    // rather than asked for: the privileged side does not send a request it
    // already knows is outside what was offered.
    let err = rig
        .client
        .read_at(IMAGE_LEN as u64 - 8, &mut buf)
        .expect_err("a read reaching past the end must fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("capacity"), "{err}");
    // And a read entirely past the end, which is the same refusal.
    let err = rig
        .client
        .read_at(IMAGE_LEN as u64 + 4096, &mut buf)
        .expect_err("a read beyond the end must fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    Ok(())
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
