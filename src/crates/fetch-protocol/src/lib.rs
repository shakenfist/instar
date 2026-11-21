//! The channel between instar's privileged host process and an untrusted
//! fetcher that serves image bytes to it.
//!
//! The host process holds `/dev/kvm` and the user's credentials; the fetcher
//! holds whatever it takes to produce bytes, and is assumed hostile. The two
//! are joined by one `AF_UNIX`/`SOCK_SEQPACKET` socket and nothing else: no
//! shared memory, no filesystem path, no serialisation library. Everything
//! the privileged side parses is a fixed-size `#[repr(C)]` header followed by
//! opaque bytes, and every decode bounds-checks the datagram against the
//! header's own size before it reads a single field.
//!
//! The model is borrowed from virtio-blk and NBD -- capacity discovered at
//! init, offset-addressed reads, a typed status rather than a bare errno,
//! request ids with replies that need not arrive in order -- but neither
//! mechanism is: a virtqueue would hand the untrusted side a writable
//! mapping the privileged side dereferences, and speaking real NBD would
//! mean parsing a negotiated, extensible protocol from a hostile peer. The
//! shape is worth stealing; the implementations are not.
//!
//! # What is deliberately absent
//!
//! There is no free-form text anywhere on the wire. A failure is a value
//! from [`Status`], and the sentence a user eventually reads is written by
//! the privileged side from that value. A reason string from the fetcher
//! would be attacker-influenced text heading for a terminal, and would need
//! sanitising, length bounds and encoding validation in the one process that
//! can least afford a parsing mistake. The fetcher's own stderr remains
//! available for diagnostics that never become part of the protocol.
//!
//! # Layout
//!
//! * [`wire`] -- the four headers, their encode and decode, the status
//!   vocabulary, and the block-size negotiation.
//! * [`client`] -- the privileged side's reader: init exchange, then
//!   `read_at` over request and reply datagrams.
//! * [`socket`] -- the `SOCK_SEQPACKET` socketpair and the handful of
//!   `libc` calls it takes to own one safely.

pub mod client;
pub mod socket;
pub mod wire;

pub use client::FetchClient;
pub use socket::{Datagram, SeqPacketSocket, DATAGRAM_OVERHEAD};
pub use wire::{
    negotiate_block_size, InitReply, InitRequest, ProtocolError, ReadReply, ReadRequest, Status,
    BLOCK_SIZE_GRANULARITY, DEFAULT_BLOCK_SIZE, INIT_REPLY_LEN, INIT_REQUEST_LEN, MAGIC,
    MAX_BLOCK_SIZE, MIN_BLOCK_SIZE, OPCODE_READ, READ_REPLY_LEN, READ_REQUEST_LEN, VERSION,
};
