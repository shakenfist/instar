//! The one socket the two sides share.
//!
//! `SOCK_SEQPACKET` is the point of this module: it keeps message boundaries
//! in the kernel, so the privileged side never has to reassemble a stream or
//! recover from a framing desynchronisation. One `recv` is one message, or an
//! error.
//!
//! Rust's standard library cannot create one. `std::os::unix::net` offers
//! `UnixStream`, whose constructors hardcode `SOCK_STREAM`, and
//! `UnixDatagram`, whose constructors hardcode `SOCK_DGRAM`, and nothing that
//! takes a socket type -- confirmed against the standard library source the
//! toolchain ships, and asserted by a test below. So the choice is a
//! third-party socket crate in the process that holds `/dev/kvm`, or a
//! handful of `libc` calls behind a type that owns its descriptor. This is
//! the second, in the same shape as the VMM's ioeventfd wrapper: a raw call,
//! its return value checked, and the descriptor owned by something that
//! closes it.
//!
//! It is a socketpair rather than a socket bound to a path because the
//! privileged side is the fetcher's parent. There is no name for anything
//! else to connect to, no directory to choose, no mode to get wrong, and
//! nothing for a filesystem sandbox to have to permit.

use crate::wire::{MAX_BLOCK_SIZE, READ_REPLY_LEN};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// Bytes the kernel charges against the socket buffer for each datagram, on
/// top of its payload.
///
/// A socket whose granted buffer is `n` bytes carries a single datagram of at
/// most `n - 32`, which is where the largest datagram either side can manage
/// comes from. The figure is not derivable from any sysctl by inspection:
/// `SO_SNDBUF` as granted is already not the value that was asked for, since
/// the kernel clamps the request to `wmem_max` and then doubles it. So both
/// sides read back what they were actually granted and derive the ceiling
/// from that, which is what [`SeqPacketSocket::max_datagram`] does.
pub const DATAGRAM_OVERHEAD: u32 = 32;

/// The socket buffer each side asks for, so that the negotiation can reach
/// the largest block the protocol permits.
///
/// A full payload, its reply header, and the per-datagram overhead the kernel
/// charges on top. What a side can actually offer is the buffer it was
/// granted, not this figure, so it is only ever a request.
pub const WANTED_SOCKET_BUFFER: u32 = MAX_BLOCK_SIZE + READ_REPLY_LEN as u32 + DATAGRAM_OVERHEAD;

/// What one `recv` delivered.
///
/// A `SOCK_SEQPACKET` socket keeps message boundaries, so a datagram larger
/// than the buffer offered for it is not a short read to be continued: the
/// kernel copies what fits, discards the rest, and the message is gone. The
/// two cases are distinguished rather than merged because the only side that
/// meets the second one is the fetcher, which still owes the peer an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datagram {
    /// The whole datagram, of this length, is in the buffer.
    Whole(usize),
    /// The datagram was longer than the buffer: `kept` bytes of its `len`
    /// are in the buffer and the remainder has been discarded.
    Overlong { len: usize, kept: usize },
}

/// One end of an `AF_UNIX`/`SOCK_SEQPACKET` socketpair.
///
/// The descriptor is owned: it is closed when the socket is dropped, and
/// nothing else holds a copy unless it was deliberately duplicated.
#[derive(Debug)]
pub struct SeqPacketSocket {
    fd: OwnedFd,
}

impl SeqPacketSocket {
    /// Create a connected pair of `SOCK_SEQPACKET` sockets.
    ///
    /// Both ends are created with `SOCK_CLOEXEC`, so neither leaks into an
    /// unrelated child; the end handed to a fetcher is duplicated onto a
    /// known descriptor number deliberately, which clears the flag for that
    /// copy alone.
    pub fn pair() -> io::Result<(Self, Self)> {
        let mut fds = [-1 as libc::c_int; 2];
        // SAFETY: fds is a two-element array of c_int, which is exactly what
        // socketpair writes on success. The return value is checked before
        // either descriptor is looked at.
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socketpair reported success, so both entries are fresh
        // descriptors this process owns and nothing else holds.
        let first = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: as above, for the other end of the same pair.
        let second = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let (first, second) = (Self { fd: first }, Self { fd: second });
        // Size both ends here, because what a side can offer in the
        // negotiation is the buffer it was granted and the default grant is
        // below the largest block this protocol defines. Doing it at
        // creation keeps it the owner's decision: a caller that wants
        // something smaller -- a test proving the negotiation really does
        // follow the grant, for instance -- shrinks it afterwards and
        // nothing silently puts it back. A refusal is not fatal; the
        // negotiation settles lower.
        let _ = first.request_largest_buffers();
        let _ = second.request_largest_buffers();
        Ok((first, second))
    }

    /// Adopt a descriptor that is already a `SOCK_SEQPACKET` socket, such as
    /// one inherited from a parent process.
    ///
    /// The type is verified rather than assumed: a fetcher handed the wrong
    /// descriptor number should fail immediately and say so, not read a
    /// header out of whatever that descriptor happens to be.
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let actual = socket_type_of(fd.as_raw_fd())?;
        if actual != libc::SOCK_SEQPACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("descriptor is socket type {actual}, not SOCK_SEQPACKET"),
            ));
        }
        Ok(Self { fd })
    }

    /// Send one datagram.
    ///
    /// A `SOCK_SEQPACKET` send is all or nothing, so a short send is treated
    /// as a protocol failure rather than something to retry from. `send` is
    /// made with `MSG_NOSIGNAL`: a peer that has died must become an error
    /// this side can report, never a `SIGPIPE` that takes the process down
    /// mid-operation.
    pub fn send(&self, datagram: &[u8]) -> io::Result<()> {
        // SAFETY: the pointer and length describe `datagram`, which outlives
        // the call, and the result is checked before it is used.
        let ret = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                datagram.as_ptr().cast(),
                datagram.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        let sent = usize::try_from(ret).unwrap_or(0);
        if sent != datagram.len() {
            return Err(io::Error::other(format!(
                "sent {sent} of {} bytes of one datagram",
                datagram.len()
            )));
        }
        Ok(())
    }

    /// Receive one datagram, returning its length.
    ///
    /// A return of zero means the peer closed its end: nothing in this
    /// protocol sends an empty datagram.
    ///
    /// `MSG_TRUNC` is what makes an oversized datagram detectable. Without
    /// it, a peer sending more than the buffer holds looks exactly like a
    /// peer sending a short message, because the kernel discards the
    /// remainder either way; with it, the real length comes back and the
    /// mismatch becomes an error instead of a silently truncated header.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.recv_allowing_overlong(buf)? {
            Datagram::Whole(len) => Ok(len),
            Datagram::Overlong { len, .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "peer sent a {len}-byte datagram into a {}-byte buffer",
                    buf.len()
                ),
            )),
        }
    }

    /// Receive one datagram, reporting an oversized one instead of refusing
    /// it.
    ///
    /// [`SeqPacketSocket::recv`] is the right call for a side that has
    /// nothing to say to a peer that overran the buffer. A fetcher does: it
    /// owes an answer, and the bytes that fit still carry the request id at
    /// its fixed offset, so the datagram can be refused by id rather than
    /// dropped in silence. The remainder is gone either way -- the kernel
    /// discarded it as the datagram was delivered -- so this reports the
    /// prefix it kept and the length that was really sent.
    pub fn recv_allowing_overlong(&self, buf: &mut [u8]) -> io::Result<Datagram> {
        // SAFETY: the pointer and length describe `buf`, which outlives the
        // call and is only read from after the length is validated below.
        let ret = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        let len = usize::try_from(ret).unwrap_or(usize::MAX);
        if len > buf.len() {
            return Ok(Datagram::Overlong {
                len,
                kept: buf.len(),
            });
        }
        Ok(Datagram::Whole(len))
    }

    /// The granted send buffer, as the kernel reports it.
    pub fn send_buffer_size(&self) -> io::Result<u32> {
        option_as_u32(self.int_option(libc::SO_SNDBUF)?)
    }

    /// The granted receive buffer, as the kernel reports it.
    pub fn recv_buffer_size(&self) -> io::Result<u32> {
        option_as_u32(self.int_option(libc::SO_RCVBUF)?)
    }

    /// Ask for a send buffer of `bytes`. The kernel grants what it likes;
    /// read it back with [`SeqPacketSocket::send_buffer_size`].
    pub fn set_send_buffer_size(&self, bytes: u32) -> io::Result<()> {
        self.set_int_option(libc::SO_SNDBUF, bytes)
    }

    /// Ask for a receive buffer of `bytes`. The kernel grants what it likes;
    /// read it back with [`SeqPacketSocket::recv_buffer_size`].
    pub fn set_recv_buffer_size(&self, bytes: u32) -> io::Result<()> {
        self.set_int_option(libc::SO_RCVBUF, bytes)
    }

    /// Give up on a `recv` that has waited this long.
    ///
    /// A privileged process that waits forever on an untrusted peer is a
    /// hang, so the side that can afford to time out should.
    ///
    /// A timeout under a microsecond is refused rather than rounded. The
    /// option is a `timeval`, and `{0, 0}` means *no* timeout to the kernel,
    /// so rounding down would quietly remove the bound a caller was asking
    /// to tighten -- the one failure this setting exists to prevent.
    pub fn set_recv_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.set_timeout(libc::SO_RCVTIMEO, "receive", timeout)
    }

    /// Give up on a `send` that has waited this long.
    ///
    /// The receive side is the obvious one to bound, but it is not the only
    /// unbounded wait on the socket. `SOCK_SEQPACKET` blocks a `send` whose
    /// datagram will not fit in the peer's receive buffer, so a peer that
    /// stops reading holds the sender in the kernel for as long as it likes
    /// -- the same hang as a peer that stops answering, reached from the
    /// other direction. A privileged process must bound both.
    pub fn set_send_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.set_timeout(libc::SO_SNDTIMEO, "send", timeout)
    }

    /// Set one of the two `timeval` timeouts.
    ///
    /// A timeout under a microsecond is refused rather than rounded, for the
    /// reason given on [`SeqPacketSocket::set_recv_timeout`].
    fn set_timeout(&self, option: libc::c_int, what: &str, timeout: Duration) -> io::Result<()> {
        if timeout.as_micros() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a {what} timeout below one microsecond would mean no timeout at all"),
            ));
        }
        let timeval = libc::timeval {
            tv_sec: libc::time_t::try_from(timeout.as_secs())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "timeout too large"))?,
            tv_usec: libc::suseconds_t::from(timeout.subsec_micros()),
        };
        let len = u32::try_from(std::mem::size_of::<libc::timeval>())
            .map_err(|_| io::Error::other("timeval size does not fit a socklen_t"))?;
        // SAFETY: the pointer and length describe one timeval, which is what
        // both timeout options expect, and the result is checked.
        let ret = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                std::ptr::addr_of!(timeval).cast(),
                len,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Ask the kernel for buffers large enough to carry the largest block
    /// the protocol permits.
    ///
    /// Both ends have to do this, and the reason is not symmetry for its own
    /// sake. The ceiling a side can offer is the buffer it was *granted*,
    /// and the default grant is smaller than the largest block this protocol
    /// defines -- so a side that never asks silently caps the negotiation
    /// below the protocol's own maximum, whatever the other side can manage.
    /// The cap is invisible in a default configuration, where the block is
    /// far below either figure, and would surface much later as a ceiling
    /// nobody chose.
    ///
    /// The kernel grants what it likes: it clamps the request to `wmem_max`
    /// and then doubles it, so the figure that matters is always the one
    /// read back afterwards and never the one asked for. A refusal is not
    /// fatal either -- the negotiation simply settles lower -- so a caller
    /// that has nowhere to report the error may ignore it.
    pub fn request_largest_buffers(&self) -> io::Result<()> {
        self.set_send_buffer_size(WANTED_SOCKET_BUFFER)?;
        self.set_recv_buffer_size(WANTED_SOCKET_BUFFER)
    }

    /// The largest single datagram this end can send or receive.
    ///
    /// Both directions are accounted for by taking the smaller of the two
    /// granted buffers, so the figure means the same thing whichever way a
    /// datagram is travelling, and the init exchange can settle on the
    /// smaller of the two sides' figures without further qualification.
    pub fn max_datagram(&self) -> io::Result<u32> {
        let send = self.send_buffer_size()?;
        let recv = self.recv_buffer_size()?;
        Ok(send.min(recv).saturating_sub(DATAGRAM_OVERHEAD))
    }

    /// Read an integer socket option at `SOL_SOCKET`.
    fn int_option(&self, name: libc::c_int) -> io::Result<libc::c_int> {
        let mut value: libc::c_int = 0;
        let mut len = u32::try_from(std::mem::size_of::<libc::c_int>())
            .map_err(|_| io::Error::other("c_int size does not fit a socklen_t"))?;
        // SAFETY: value is a c_int and len is its size, which is what an
        // integer socket option expects; both outlive the call, and the
        // result is checked before value is read.
        let ret = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                std::ptr::addr_of_mut!(value).cast(),
                std::ptr::addr_of_mut!(len),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }

    /// Set an integer socket option at `SOL_SOCKET`.
    fn set_int_option(&self, name: libc::c_int, value: u32) -> io::Result<()> {
        let value = libc::c_int::try_from(value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "option value too large"))?;
        let len = u32::try_from(std::mem::size_of::<libc::c_int>())
            .map_err(|_| io::Error::other("c_int size does not fit a socklen_t"))?;
        // SAFETY: value is a c_int and len is its size, which is what an
        // integer socket option expects; both outlive the call, and the
        // result is checked.
        let ret = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                std::ptr::addr_of!(value).cast(),
                len,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl AsRawFd for SeqPacketSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for SeqPacketSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl From<SeqPacketSocket> for OwnedFd {
    fn from(socket: SeqPacketSocket) -> Self {
        socket.fd
    }
}

/// Convert a socket option's `c_int` to the unsigned size it represents.
fn option_as_u32(value: libc::c_int) -> io::Result<u32> {
    u32::try_from(value).map_err(|_| io::Error::other("socket option is negative"))
}

/// The `SO_TYPE` of a descriptor, which is an error if it is not a socket.
fn socket_type_of(fd: RawFd) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = u32::try_from(std::mem::size_of::<libc::c_int>())
        .map_err(|_| io::Error::other("c_int size does not fit a socklen_t"))?;
    // SAFETY: value is a c_int and len is its size, which is what SO_TYPE
    // expects; both outlive the call, and the result is checked before value
    // is read.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::addr_of_mut!(value).cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixDatagram, UnixStream};

    #[test]
    fn a_pair_is_seqpacket_and_close_on_exec() {
        let (a, b) = SeqPacketSocket::pair().expect("socketpair");
        assert_eq!(
            socket_type_of(a.as_raw_fd()).expect("SO_TYPE"),
            libc::SOCK_SEQPACKET
        );
        assert_eq!(
            socket_type_of(b.as_raw_fd()).expect("SO_TYPE"),
            libc::SOCK_SEQPACKET
        );
        // SAFETY: a owns a live descriptor and F_GETFD only reads its flags.
        let flags = unsafe { libc::fcntl(a.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0, "fcntl failed: {}", io::Error::last_os_error());
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    }

    /// The reason this module exists at all: neither of the standard
    /// library's socket pair constructors can be asked for SEQPACKET, so if
    /// one of them ever grows the ability this test is where it will show up.
    #[test]
    fn the_standard_library_offers_only_stream_and_datagram() {
        let (stream, _other) = UnixStream::pair().expect("UnixStream::pair");
        assert_eq!(
            socket_type_of(stream.as_raw_fd()).expect("SO_TYPE"),
            libc::SOCK_STREAM
        );
        let (datagram, _other) = UnixDatagram::pair().expect("UnixDatagram::pair");
        assert_eq!(
            socket_type_of(datagram.as_raw_fd()).expect("SO_TYPE"),
            libc::SOCK_DGRAM
        );
    }

    #[test]
    fn from_fd_refuses_a_descriptor_that_is_not_seqpacket() {
        let (stream, _other) = UnixStream::pair().expect("UnixStream::pair");
        let err = SeqPacketSocket::from_fd(OwnedFd::from(stream)).expect_err("not seqpacket");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn from_fd_accepts_an_inherited_seqpacket_descriptor() {
        let (a, _b) = SeqPacketSocket::pair().expect("socketpair");
        let adopted = SeqPacketSocket::from_fd(OwnedFd::from(a)).expect("adopts");
        assert_eq!(
            socket_type_of(adopted.as_raw_fd()).expect("SO_TYPE"),
            libc::SOCK_SEQPACKET
        );
    }

    #[test]
    fn message_boundaries_survive() {
        let (a, b) = SeqPacketSocket::pair().expect("socketpair");
        a.send(&[1u8; 100]).expect("send");
        a.send(&[2u8; 7]).expect("send");
        let mut buf = [0u8; 4096];
        assert_eq!(b.recv(&mut buf).expect("recv"), 100);
        assert_eq!(buf[0], 1);
        assert_eq!(b.recv(&mut buf).expect("recv"), 7);
        assert_eq!(buf[0], 2);
    }

    #[test]
    fn an_oversized_datagram_is_an_error_not_a_truncation() {
        let (a, b) = SeqPacketSocket::pair().expect("socketpair");
        a.send(&[0u8; 100]).expect("send");
        let mut buf = [0u8; 10];
        let err = b.recv(&mut buf).expect_err("oversized datagram");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Send `datagram` and receive it back, or return `None` if the kernel
    /// could not find the memory for it.
    ///
    /// A datagram of the default ceiling is several hundred kilobytes, which
    /// the kernel must allocate as one physically contiguous `skb` -- an
    /// order-7 allocation at 416 KiB. On a host whose free memory is
    /// fragmented that allocation fails with `ENOBUFS`, which says nothing
    /// about the size being derived correctly and is not a property this
    /// crate can assert. The protocol never asks for it either: the
    /// negotiation caps a block at 64 KiB, two orders of magnitude below the
    /// sizes that need a high-order allocation.
    fn round_trip(a: &SeqPacketSocket, b: &SeqPacketSocket, datagram: &[u8]) -> Option<Vec<u8>> {
        match a.send(datagram) {
            Ok(()) => {}
            Err(err) if err.raw_os_error() == Some(libc::ENOBUFS) => return None,
            Err(err) => panic!("send of {} bytes failed: {err:?}", datagram.len()),
        }
        let mut buf = vec![0u8; datagram.len()];
        assert_eq!(b.recv(&mut buf).expect("recv"), datagram.len());
        Some(buf)
    }

    #[test]
    fn a_datagram_of_the_derived_maximum_really_sends() {
        let (a, b) = SeqPacketSocket::pair().expect("socketpair");
        let max = a.max_datagram().expect("max datagram") as usize;
        assert!(
            max >= 4096,
            "default socket buffer is unexpectedly small: {max}"
        );
        match round_trip(&a, &b, &vec![0xC3u8; max]) {
            Some(got) => assert_eq!(got[max - 1], 0xC3),
            None => {
                // The host could not allocate a datagram that size. What the
                // protocol will actually ask of this socket still has to go
                // through, and that is the assertion worth keeping here.
                let block = crate::wire::DEFAULT_BLOCK_SIZE as usize + READ_REPLY_LEN;
                let got = round_trip(&a, &b, &vec![0xC3u8; block])
                    .expect("a full negotiated block sends");
                assert_eq!(got[block - 1], 0xC3);
            }
        }
    }

    #[test]
    fn the_derived_maximum_tracks_a_smaller_buffer() {
        let (a, b) = SeqPacketSocket::pair().expect("socketpair");
        a.set_send_buffer_size(2048).expect("set SO_SNDBUF");
        b.set_recv_buffer_size(2048).expect("set SO_RCVBUF");
        let max = a.max_datagram().expect("max datagram");
        assert!(max < 65536, "a 2 KiB request granted a large buffer: {max}");
        // The block this buffer settles on is what a read reply will actually
        // carry, so that is the size worth proving still fits.
        let block = crate::wire::negotiate_block_size(max, max).expect("usable block");
        let datagram = crate::wire::READ_REPLY_LEN + block as usize;
        a.send(&vec![0x5Au8; datagram])
            .expect("a negotiated block still sends");
        let mut buf = vec![0u8; datagram];
        assert_eq!(b.recv(&mut buf).expect("recv"), datagram);
    }

    #[test]
    fn a_closed_peer_is_an_error_not_a_signal() {
        let (a, b) = SeqPacketSocket::pair().expect("socketpair");
        drop(b);
        let err = a.send(&[0u8; 16]).expect_err("the peer is gone");
        assert_eq!(err.raw_os_error(), Some(libc::EPIPE));
    }

    #[test]
    fn a_closed_peer_reads_as_end_of_stream() {
        let (a, b) = SeqPacketSocket::pair().expect("socketpair");
        drop(a);
        let mut buf = [0u8; 64];
        assert_eq!(b.recv(&mut buf).expect("recv"), 0);
    }

    #[test]
    fn a_recv_timeout_expires_rather_than_waiting() {
        let (a, _b) = SeqPacketSocket::pair().expect("socketpair");
        a.set_recv_timeout(Duration::from_millis(50))
            .expect("set SO_RCVTIMEO");
        let mut buf = [0u8; 64];
        let err = a.recv(&mut buf).expect_err("nothing was sent");
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "unexpected kind: {err:?}"
        );
    }

    #[test]
    fn a_send_timeout_expires_rather_than_blocking_on_a_peer_that_stopped_reading() {
        // The sending runs on its own thread with a watchdog, because the
        // failure this guards against is an unbounded block: without the
        // timeout the send never returns, and a test that waits for it
        // would hang the suite instead of failing it. A hung run says far
        // less than a failed one, and costs whatever the CI timeout is.
        let (done, waiting) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (a, b) = SeqPacketSocket::pair().expect("socketpair");
            a.set_send_buffer_size(2048).expect("set SO_SNDBUF");
            b.set_recv_buffer_size(2048).expect("set SO_RCVBUF");
            a.set_send_timeout(Duration::from_millis(50))
                .expect("set SO_SNDTIMEO");
            // `b` never reads, so its receive buffer fills and the send
            // blocks. The loop is bounded so that a kernel which never
            // blocks is a failure rather than a spin.
            let datagram = vec![0u8; 512];
            for _ in 0..1000 {
                match a.send(&datagram) {
                    Ok(()) => continue,
                    Err(err) => {
                        let _ = done.send(Some(err.kind()));
                        return;
                    }
                }
            }
            let _ = done.send(None);
        });
        match waiting.recv_timeout(Duration::from_secs(10)) {
            Ok(Some(kind)) => assert!(
                matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut),
                "unexpected kind: {kind:?}"
            ),
            Ok(None) => panic!("a 2 KiB receive buffer accepted 1000 datagrams without blocking"),
            // The thread is still blocked in `send` and stays that way
            // until the process ends, which is what the bound is supposed
            // to make impossible.
            Err(_) => panic!("the send did not give up: SO_SNDTIMEO is not bounding it"),
        }
    }

    #[test]
    fn a_timeout_that_would_round_to_no_timeout_is_refused() {
        // `{0, 0}` means wait forever, so accepting these would turn the
        // tightest possible bound into none at all.
        let (a, _b) = SeqPacketSocket::pair().expect("socketpair");
        for timeout in [Duration::ZERO, Duration::from_nanos(999)] {
            // Both directions: the option and the trap are the same.
            let err = a.set_recv_timeout(timeout).expect_err("refused");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
            let err = a.set_send_timeout(timeout).expect_err("refused");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        }
        // One microsecond is representable, so it is accepted and the
        // socket really does stop waiting.
        a.set_recv_timeout(Duration::from_micros(1))
            .expect("one microsecond");
        a.set_send_timeout(Duration::from_micros(1))
            .expect("one microsecond");
        let mut buf = [0u8; 64];
        assert!(a.recv(&mut buf).is_err(), "a 1 us timeout should expire");
    }

    #[test]
    fn an_overlong_datagram_keeps_its_head_for_the_side_that_must_answer() {
        let (a, b) = SeqPacketSocket::pair().expect("socketpair");
        let sent: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        a.send(&sent).expect("send");
        let mut buf = [0u8; 64];
        match b
            .recv_allowing_overlong(&mut buf)
            .expect("the datagram arrived")
        {
            Datagram::Overlong { len, kept } => {
                assert_eq!(len, sent.len(), "the real length is reported");
                assert_eq!(kept, buf.len(), "the buffer was filled");
                assert_eq!(&buf[..], &sent[..buf.len()], "the head is the head");
            }
            other => panic!("expected an overlong datagram, got {other:?}"),
        }
        // The strict call, which the privileged side uses, still refuses it.
        a.send(&sent).expect("send");
        let err = b.recv(&mut buf).expect_err("oversized datagram");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
    /// The buffer each side asks for has to be able to carry the largest
    /// block the protocol permits.
    ///
    /// The negotiation aims for the smaller default rather than this
    /// ceiling, so nothing today depends on the figure being this large.
    /// That is the point: raising the default later should be a change to
    /// one constant, not a discovery that the sockets were never sized for
    /// it.
    #[test]
    fn the_wanted_buffer_covers_the_largest_block() {
        let ceiling = WANTED_SOCKET_BUFFER - DATAGRAM_OVERHEAD;
        assert!(
            ceiling - READ_REPLY_LEN as u32 >= MAX_BLOCK_SIZE,
            "the requested buffer cannot carry the protocol's largest block"
        );
    }
    /// Asking for the largest buffers grows a socket that was made smaller.
    #[test]
    fn requesting_the_largest_buffers_grows_a_small_socket() {
        let (socket, _peer) = SeqPacketSocket::pair().expect("pair");
        socket.set_send_buffer_size(4096).expect("shrink send");
        socket.set_recv_buffer_size(4096).expect("shrink recv");
        let small = socket.max_datagram().expect("small");
        socket.request_largest_buffers().expect("ask");
        let asked = socket.max_datagram().expect("asked");
        assert!(
            asked > small,
            "asking did not grow the buffers: {small} then {asked}"
        );
    }

    /// A pair has already asked, so asking again changes nothing.
    ///
    /// The ceiling a side can offer in the negotiation is the buffer it was
    /// granted, and the default grant is below the largest block this
    /// protocol defines -- so a pair that did not ask would leave the
    /// negotiation unable to reach that block however small the request.
    /// Comparing a fresh pair against the same pair after an explicit ask
    /// says whether the constructor did it, without naming a figure that
    /// depends on the host's own limits.
    #[test]
    fn a_pair_has_already_asked_for_the_largest_buffers() {
        let (socket, _peer) = SeqPacketSocket::pair().expect("pair");
        let fresh = socket.max_datagram().expect("fresh");
        socket.request_largest_buffers().expect("ask again");
        assert_eq!(
            socket.max_datagram().expect("asked"),
            fresh,
            "a fresh pair was not already sized: asking again changed it"
        );
    }
}
