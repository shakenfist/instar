//! `instar-fetch`: serves the bytes of one already-open file over the fetch
//! protocol, and does nothing else at all.
//!
//! This is the untrusted half of instar's host-side partition. The process
//! that holds `/dev/kvm` and the user's credentials spawns this one, hands it
//! two descriptors, and from then on talks to it only in fixed-size headers
//! over a `SOCK_SEQPACKET` socket. Everything this process can be made to do
//! by a malformed message is bounded by what those two descriptors allow.
//!
//! # Why it takes descriptor numbers and not a path
//!
//! Resolving a path is an exercise of the invoking user's authority, and
//! that authority belongs on the privileged side. So the privileged side
//! opens the image and passes the open descriptor; this process never calls
//! `open` on anything, which is what lets it be confined to no filesystem
//! access whatsoever rather than having to be permitted to reach the image.
//! There is deliberately no path argument and no fallback that would accept
//! one, because such a fallback is exactly the hole the confinement would
//! then have to leave open.
//!
//! # What it never does
//!
//! It never panics on anything that arrives over the socket. A malformed
//! datagram is a reply with a status, or a line on this process's own
//! stderr, and never an abort: the privileged side is waiting for an answer,
//! and a crash turns a refusable request into a hang for it to time out.
//!
//! There is one shape it answers with silence, and it is a limit rather than
//! a choice: a datagram too short to contain a request id. A reply is
//! addressed by the id it carries back, so there is nothing to address, and
//! inventing one would put an id on the wire that the peer never used --
//! which a peer that had lost framing could match to a different request in
//! flight and read as a refusal of that one. A client's read deadline is
//! what covers this, and no correct client can produce the shape: the
//! request header is fixed-size, so a short datagram means the peer is
//! already not speaking the protocol.
//!
//! Nothing it says to the privileged side is text. Diagnostics go to stderr,
//! one line each, where the parent can route them into its own log; the
//! socket carries only numbers from a closed vocabulary, so nothing this
//! process writes can become unsanitised text in a user's terminal.
//!
//! # Exit status
//!
//! `0` when the peer closes the socket, which is how a normal run ends, and
//! for `--help`, which serves no bytes and touches no descriptor; `2` for a
//! usage error, before any descriptor is touched; `1` for everything else,
//! each case preceded by a line on stderr saying what failed.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

use fetch_protocol::{
    negotiate_block_size, Datagram, InitReply, InitRequest, ProtocolError, ReadReply, ReadRequest,
    SeqPacketSocket, Status,
};

/// What to print when the arguments do not make sense.
const USAGE: &str = "\
usage: instar-fetch <socket-fd> <file-fd>

  socket-fd  an inherited AF_UNIX/SOCK_SEQPACKET socket connected to instar
  file-fd    an inherited, open, readable regular file to serve

Both arguments are descriptor numbers that the parent process has already
opened. instar-fetch takes no paths and opens nothing.";

/// The flag the privileged side names the confinement layers with.
const CONFINE_FLAG: &str = "--confine=";

/// Buffer for one incoming datagram.
///
/// Every message the privileged side sends is at most a 32-byte header, so
/// this is far larger than anything legitimate. The slack is deliberate: a
/// datagram that is merely malformed still lands in the buffer, which means
/// its request id can be recovered and the request refused by id, whereas a
/// buffer sized exactly to the header would turn the same mistake into an
/// unanswerable receive error. A datagram larger than this is refused by the
/// id in the prefix the kernel kept, which `MSG_TRUNC` makes detectable
/// rather than silent.
const REQUEST_BUFFER: usize = 1024;

/// The bytes being served.
///
/// A trait rather than a bare `File` so that the status decisions in
/// [`read_source`] can be exercised against a source that is short, or that
/// fails on demand, without needing a filesystem to arrange it.
trait Source {
    /// Read into `buf` starting at `offset`, returning the bytes read, which
    /// may be fewer than asked for and is zero at the end of the source.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;
}

impl Source for File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        FileExt::read_at(self, buf, offset)
    }
}

/// The two descriptors this process was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Args {
    /// The SEQPACKET socket connected to the privileged side.
    socket_fd: RawFd,
    /// The file whose bytes are served.
    file_fd: RawFd,
}

/// What the command line asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Invocation {
    /// Serve the file on the socket.
    Serve(Args),
    /// Print the usage and stop.
    Help,
}

fn main() -> ExitCode {
    match parse_args(std::env::args_os()) {
        Ok(Invocation::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Serve(args)) => match serve(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("instar-fetch: {err}");
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            eprintln!("instar-fetch: {err}");
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Parse the command line: exactly two descriptor numbers, or a request for
/// the usage.
fn parse_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Invocation, String> {
    let mut positional = Vec::new();
    for arg in args.into_iter().skip(1) {
        let text = arg
            .to_str()
            .ok_or_else(|| {
                "arguments must be descriptor numbers, and this one is not text".to_string()
            })?
            .to_string();
        if text == "-h" || text == "--help" {
            return Ok(Invocation::Help);
        }
        // `--confine=<list>` is the privileged side naming the confinement
        // layers it expects this process to apply to itself. Reading the list
        // belongs with the policy that applies it, which is not this loop;
        // what this loop needs is for the flag not to be counted as one of
        // the descriptor numbers.
        if text.starts_with(CONFINE_FLAG) {
            continue;
        }
        positional.push(text);
    }
    let [socket, file] = positional.as_slice() else {
        return Err(format!(
            "expected two descriptor numbers, got {}",
            positional.len()
        ));
    };
    let socket_fd = parse_fd("socket", socket)?;
    let file_fd = parse_fd("file", file)?;
    if socket_fd == file_fd {
        return Err(format!(
            "the socket and the file are both descriptor {socket_fd}, which cannot be both"
        ));
    }
    Ok(Invocation::Serve(Args { socket_fd, file_fd }))
}

/// Parse one descriptor number, refusing the three standard descriptors.
///
/// Descriptors 0, 1 and 2 are this process's own plumbing -- and stderr in
/// particular is where every diagnostic goes -- so a parent that passes one
/// of them has made a mistake worth naming rather than discovering as
/// garbled output.
fn parse_fd(label: &str, text: &str) -> Result<RawFd, String> {
    let fd: RawFd = text
        .parse()
        .map_err(|_| format!("the {label} argument must be a descriptor number, not {text:?}"))?;
    if fd < 3 {
        return Err(format!(
            "the {label} argument is descriptor {fd}, which is one of this process's own \
             standard descriptors"
        ));
    }
    Ok(fd)
}

/// Take ownership of a descriptor number the parent passed.
///
/// The check is not ceremony. Building an `OwnedFd` from a number that is not
/// open would leave this process believing it owns a descriptor it does not,
/// and closing it later would close whatever had since been opened onto that
/// number. Failing here instead means a mistyped descriptor is a sentence on
/// stderr before anything has been read.
fn adopt_fd(raw: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: F_GETFD only reads the descriptor's flags; it does not alter,
    // consume or close anything, and the result is checked before the number
    // is treated as a descriptor.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the fcntl above proves the descriptor is open. The parent
    // passed it on the command line for this process to own, and this is the
    // only place that adopts it, so no other owner exists.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Run the init exchange and then serve reads until the peer goes away.
fn serve(args: Args) -> io::Result<()> {
    let socket_fd = adopt_fd(args.socket_fd).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("descriptor {} is not open: {err}", args.socket_fd),
        )
    })?;
    let socket = SeqPacketSocket::from_fd(socket_fd).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "descriptor {} cannot serve as the fetch socket: {err}",
                args.socket_fd
            ),
        )
    })?;
    let file = File::from(adopt_fd(args.file_fd).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("descriptor {} is not open: {err}", args.file_fd),
        )
    })?);

    // The capacity is the file's own size, read from the descriptor rather
    // than from a path, and a non-regular file is refused: a pipe or a
    // terminal has no size to advertise and cannot answer a positional read
    // at all, so serving one would mean failing every request instead of the
    // init.
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "descriptor {} is not a regular file, so it has no capacity to serve",
                args.file_fd
            ),
        ));
    }
    let capacity = metadata.len();

    // Ask for the largest buffer a block could need, in both directions, and
    // then read back what was granted: the ceiling is derived from the grant
    // and never from a sysctl or a constant. A kernel that refuses the
    // request is not fatal -- the negotiation simply settles lower.
    if let Err(err) = socket.request_largest_buffers() {
        eprintln!("instar-fetch: could not enlarge the socket buffers: {err}");
    }
    let max_datagram = socket.max_datagram()?;

    let mut datagram = [0u8; REQUEST_BUFFER];
    let block_size = match initialise(&socket, &mut datagram, max_datagram, capacity)? {
        Some(block_size) => block_size,
        None => return Ok(()),
    };
    eprintln!(
        "instar-fetch: serving {capacity} bytes in blocks of at most {block_size} bytes \
         on a {max_datagram}-byte datagram ceiling"
    );

    loop {
        let len = match socket.recv_allowing_overlong(&mut datagram)? {
            Datagram::Whole(0) => {
                eprintln!("instar-fetch: the peer closed the socket, exiting");
                return Ok(());
            }
            Datagram::Whole(len) => len,
            // The remainder of an oversized datagram is already gone: the
            // kernel discarded it on delivery, so there is nothing to
            // resynchronise. What it kept is the head of the datagram,
            // which is where the request id lives, so this is refused by id
            // like any other malformed request rather than dropped in
            // silence. Keep serving: the next message may be sound.
            Datagram::Overlong { len, kept } => {
                eprintln!(
                    "instar-fetch: refusing a {len}-byte datagram, which is longer than a \
                     request"
                );
                refuse_overlong(&socket, &datagram[..kept])?;
                continue;
            }
        };
        answer(&socket, &file, capacity, block_size, &datagram[..len])?;
    }
}

/// Perform the init exchange, returning the settled block size, or `None` if
/// the peer closed the socket before sending anything.
fn initialise(
    socket: &SeqPacketSocket,
    datagram: &mut [u8],
    max_datagram: u32,
    capacity: u64,
) -> io::Result<Option<u32>> {
    let len = socket.recv(datagram)?;
    if len == 0 {
        eprintln!("instar-fetch: the peer closed the socket before the init exchange");
        return Ok(None);
    }

    let request = match InitRequest::decode(&datagram[..len]) {
        Ok(request) => request,
        Err(err) => return Err(refuse_init(socket, err)),
    };
    let block_size = match negotiate_block_size(max_datagram, request.max_datagram) {
        Ok(block_size) => block_size,
        Err(err) => return Err(refuse_init(socket, err)),
    };
    socket.send(&InitReply::new(Status::Ok, block_size, capacity).encode())?;
    Ok(Some(block_size))
}

/// Tell the peer its init was refused, and turn the refusal into the error
/// this process exits on.
///
/// A reply is sent even when the magic was wrong and the peer may not speak
/// this protocol at all: a well-formed refusal is 32 bytes and lets a peer
/// that does speak it report the reason, whereas silence leaves it waiting
/// for a timeout. The reply carries this build's own version, so a version
/// mismatch is detectable from either end of it.
fn refuse_init(socket: &SeqPacketSocket, err: ProtocolError) -> io::Error {
    let status = match err {
        ProtocolError::VersionMismatch { .. } => Status::Unsupported,
        _ => Status::BadRequest,
    };
    if let Err(send_err) = socket.send(&InitReply::new(status, 0, 0).encode()) {
        eprintln!("instar-fetch: could not report the refusal to the peer: {send_err}");
    }
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("refusing the init request: {err}"),
    )
}

/// Refuse a datagram that was longer than the request buffer, by its id.
///
/// `head` is the prefix the kernel kept. A request header is fixed-size and
/// far shorter than that buffer, so the id is present whenever the peer sent
/// anything header-shaped at all; the one shape left unanswered is the same
/// one [`answer`] leaves unanswered, for the same reason.
fn refuse_overlong(socket: &SeqPacketSocket, head: &[u8]) -> io::Result<()> {
    match ReadRequest::peek_id(head) {
        Some(id) => reply(socket, id, Status::BadRequest, &[]),
        None => {
            eprintln!(
                "instar-fetch: the datagram is too short to carry a request id, so \
                 there is nothing to answer"
            );
            Ok(())
        }
    }
}

/// Answer one datagram from the peer.
///
/// Returning `Err` means the socket itself failed and the process is done; a
/// request this process will not satisfy is a reply with a status, not an
/// error, because the peer is owed an answer either way.
fn answer(
    socket: &SeqPacketSocket,
    source: &dyn Source,
    capacity: u64,
    block_size: u32,
    datagram: &[u8],
) -> io::Result<()> {
    let request = match ReadRequest::decode(datagram, block_size) {
        Ok(request) => request,
        Err(err) => {
            // An opcode from a later version of the protocol is refused as
            // unsupported and the socket stays open: this process is not the
            // one that decides whether the peer can carry on without it.
            // Everything else malformed is the peer's own bug, and is
            // answered by the id if the datagram was long enough to carry
            // one.
            let (status, id) = match err {
                ProtocolError::UnknownOpcode { id, .. } => (Status::Unsupported, Some(id)),
                _ => (Status::BadRequest, ReadRequest::peek_id(datagram)),
            };
            eprintln!("instar-fetch: refusing a request: {err}");
            match id {
                Some(id) => return reply(socket, id, status, &[]),
                None => {
                    // Silence, deliberately: see the module header. An
                    // invented id is worse than nothing, because the peer
                    // may match it to a request that is really outstanding.
                    eprintln!(
                        "instar-fetch: the datagram is too short to carry a request id, so \
                         there is nothing to answer"
                    );
                    return Ok(());
                }
            }
        }
    };

    match read_source(source, capacity, &request) {
        Ok((status, payload)) => {
            if status != Status::Ok {
                eprintln!(
                    "instar-fetch: request {} for {} bytes at offset {} answered {status:?} \
                     with {} bytes",
                    request.id,
                    request.length,
                    request.offset,
                    payload.len()
                );
            }
            reply(socket, request.id, status, &payload)
        }
        Err(err) => {
            eprintln!(
                "instar-fetch: reading {} bytes at offset {} failed: {err}",
                request.length, request.offset
            );
            reply(socket, request.id, Status::IoError, &[])
        }
    }
}

/// Read what a request asks for, and decide which status describes the
/// outcome.
///
/// The three outcomes that are not simply `Ok` are distinguished on purpose,
/// because the privileged side acts on them differently:
///
/// * A request that starts at or beyond the advertised capacity asks for
///   bytes that were never offered, which is the privileged side's own bug,
///   and gets [`Status::OutOfRange`].
/// * A request that starts inside the capacity but reaches past the end of
///   the source gets the bytes that do exist and [`Status::ShortRead`] --
///   never `Ok` with a short payload, which would let a truncated source
///   look like a successful read of zeroes.
/// * A request of zero bytes inside the capacity is satisfied by sending
///   nothing, since there is no shortfall to report.
///
/// `Err` means the source itself failed; the caller renders it and answers
/// [`Status::IoError`].
fn read_source(
    source: &dyn Source,
    capacity: u64,
    request: &ReadRequest,
) -> io::Result<(Status, Vec<u8>)> {
    let length = request.length as usize;
    if length == 0 {
        if request.offset > capacity {
            return Ok((Status::OutOfRange, Vec::new()));
        }
        return Ok((Status::Ok, Vec::new()));
    }
    if request.offset >= capacity {
        return Ok((Status::OutOfRange, Vec::new()));
    }

    // The request's length is already bounded by the negotiated block size,
    // which the decoder enforced, so this allocation is bounded too.
    let available = capacity - request.offset;
    let want = usize::try_from(available).unwrap_or(usize::MAX).min(length);
    let mut payload = vec![0u8; want];
    let mut filled = 0;
    while filled < want {
        let at = request.offset.saturating_add(filled as u64);
        match source.read_at(&mut payload[filled..], at) {
            // The source ended earlier than its own size said it would,
            // which a file being truncated under us does.
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    payload.truncate(filled);
    let status = if filled < length {
        Status::ShortRead
    } else {
        Status::Ok
    };
    Ok((status, payload))
}

/// Send one read reply.
fn reply(socket: &SeqPacketSocket, id: u64, status: Status, payload: &[u8]) -> io::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::other("a payload longer than the protocol can describe"))?;
    let datagram = ReadReply::new(id, status, length).encode_datagram(payload)?;
    socket.send(&datagram)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source of known bytes, so the status decisions can be checked
    /// against a capacity that does and does not match the bytes behind it.
    struct Bytes(Vec<u8>);

    impl Source for Bytes {
        fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(self.0.len());
            let end = (start + buf.len()).min(self.0.len());
            buf[..end - start].copy_from_slice(&self.0[start..end]);
            Ok(end - start)
        }
    }

    /// A source that fails, which no file reliably does on demand.
    struct Failing;

    impl Source for Failing {
        fn read_at(&self, _buf: &mut [u8], _offset: u64) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }

    fn argv(args: &[&str]) -> Vec<OsString> {
        std::iter::once(OsString::from("instar-fetch"))
            .chain(args.iter().map(OsString::from))
            .collect()
    }

    fn request(offset: u64, length: u32) -> ReadRequest {
        ReadRequest::new(7, offset, length)
    }

    #[test]
    fn two_descriptor_numbers_are_the_whole_command_line() {
        assert_eq!(
            parse_args(argv(&["3", "4"])).expect("parses"),
            Invocation::Serve(Args {
                socket_fd: 3,
                file_fd: 4,
            })
        );
    }

    #[test]
    fn help_is_answered_without_descriptors() {
        assert_eq!(
            parse_args(argv(&["--help"])).expect("parses"),
            Invocation::Help
        );
        assert_eq!(parse_args(argv(&["-h"])).expect("parses"), Invocation::Help);
    }

    #[test]
    fn a_missing_or_extra_argument_is_refused() {
        assert!(parse_args(argv(&["3"])).is_err());
        assert!(parse_args(argv(&[])).is_err());
        assert!(parse_args(argv(&["3", "4", "5"])).is_err());
    }

    /// A path argument is the mistake this CLI exists to make impossible, so
    /// it has to fail rather than be interpreted.
    #[test]
    fn a_path_is_not_a_descriptor_number() {
        let err = parse_args(argv(&["3", "/tmp/image.qcow2"])).expect_err("refused");
        assert!(err.contains("descriptor number"), "{err}");
    }

    #[test]
    fn the_standard_descriptors_are_refused() {
        assert!(parse_args(argv(&["0", "4"])).is_err());
        assert!(parse_args(argv(&["3", "2"])).is_err());
    }

    #[test]
    fn one_descriptor_cannot_be_both_the_socket_and_the_file() {
        let err = parse_args(argv(&["3", "3"])).expect_err("refused");
        assert!(err.contains("cannot be both"), "{err}");
    }

    #[test]
    fn a_whole_read_inside_the_capacity_is_ok() {
        let source = Bytes((0u8..=255).collect());
        let (status, payload) = read_source(&source, 256, &request(16, 32)).expect("reads");
        assert_eq!(status, Status::Ok);
        assert_eq!(payload, (16u8..48).collect::<Vec<u8>>());
    }

    #[test]
    fn a_read_reaching_past_the_end_is_a_short_read_of_what_exists() {
        let source = Bytes((0u8..=255).collect());
        let (status, payload) = read_source(&source, 256, &request(240, 64)).expect("reads");
        assert_eq!(status, Status::ShortRead);
        assert_eq!(payload, (240u8..=255).collect::<Vec<u8>>());
    }

    /// The source being shorter than the capacity advertised at init is what
    /// a file truncated under the fetcher looks like, and it must not read as
    /// a successful read of zeroes.
    #[test]
    fn a_source_shorter_than_the_capacity_is_a_short_read() {
        let source = Bytes(vec![0xA5; 10]);
        let (status, payload) = read_source(&source, 4096, &request(0, 64)).expect("reads");
        assert_eq!(status, Status::ShortRead);
        assert_eq!(payload, vec![0xA5; 10]);
    }

    #[test]
    fn a_read_at_or_past_the_capacity_is_out_of_range() {
        let source = Bytes((0u8..=255).collect());
        let (status, payload) = read_source(&source, 256, &request(256, 8)).expect("reads");
        assert_eq!(status, Status::OutOfRange);
        assert!(payload.is_empty());
        let (status, _) = read_source(&source, 256, &request(4096, 8)).expect("reads");
        assert_eq!(status, Status::OutOfRange);
    }

    #[test]
    fn a_zero_length_read_inside_the_capacity_asks_for_nothing() {
        let source = Bytes((0u8..=255).collect());
        let (status, payload) = read_source(&source, 256, &request(16, 0)).expect("reads");
        assert_eq!(status, Status::Ok);
        assert!(payload.is_empty());
    }

    #[test]
    fn a_failing_source_is_reported_rather_than_answered() {
        let err = read_source(&Failing, 4096, &request(0, 512)).expect_err("fails");
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
    }
}
