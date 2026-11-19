//! The wire format: four fixed-size headers, a typed status, and the
//! block-size negotiation.
//!
//! # Endianness
//!
//! Every multi-byte field is little-endian on the wire, written with
//! `to_le_bytes` and read with `from_le_bytes`. The socket never leaves the
//! machine, so native order would work on every host instar supports, but
//! being explicit makes the layout below a documented fact rather than a
//! property of whichever machine did the build, and it keeps a captured
//! datagram -- a fuzz corpus entry, say -- meaningful on any host.
//!
//! # Layout
//!
//! Each header is `#[repr(C)]` with no implicit padding: the structs are
//! laid out so that every field is naturally aligned and the total size is a
//! multiple of the alignment without the compiler inserting anything. The
//! unit tests assert `size_of` and the offset of every field, so a reordering
//! that would have changed the wire format breaks a test instead.
//!
//! No datagram is ever reinterpreted as one of these structs. Decoding reads
//! one field at a time from the bytes and validates as it goes, which is what
//! lets a status field be a real enum: a value outside the enum becomes an
//! error rather than an invalid discriminant sitting in a live struct. The
//! layout is `#[repr(C)]` so that the offsets are a stated contract and the
//! tests can hold the encoder to them, not so that anything can be cast.
//!
//! ```text
//! InitRequest   16 bytes   magic 0   version 4   max_datagram 8   flags 12
//! InitReply     32 bytes   magic 0   version 4   status 8   block_size 12
//!                          capacity 16   flags 24
//! ReadRequest   32 bytes   opcode 0   length 4   id 8   offset 16   flags 24
//! ReadReply     24 bytes   opcode 0   status 4   id 8   length 16   flags 20
//! ```
//!
//! A read reply's payload follows its header in the same datagram, so the
//! datagram is exactly `READ_REPLY_LEN + length` bytes long. The other three
//! messages are exactly their header length; trailing bytes are a protocol
//! error rather than something to ignore, because nothing this crate sends
//! produces them.
//!
//! Every `flags` field is reserved and must be zero. It exists so that a
//! later flag bit does not need a new message or a version bump; a peer that
//! sets a bit this build does not know is refused rather than guessed at.

use std::fmt;
use std::io;

/// Magic at the head of both init messages.
///
/// Chosen so that the little-endian encoding reads as `INFT` in a hexdump of
/// the datagram, which is the form a person debugging a desynchronised
/// channel actually sees.
pub const MAGIC: u32 = u32::from_le_bytes(*b"INFT");

/// Version of this wire format.
///
/// A mismatch is fatal and names both versions: the fetcher is found by
/// probing the executable's own directory and then the packaged library
/// directory, so a development build talking to a packaged fetcher (or the
/// reverse) is a mistake that will happen, and it is far cheaper to detect
/// here than to debug as a stream of nonsense headers.
pub const VERSION: u32 = 1;

/// Opcode of a read request.
///
/// It is the only opcode this version defines. Values 2 and 3 are reserved
/// for the flush and capacity-requery messages the model this protocol
/// borrows from has; a request carrying either is refused today, which is
/// what lets a fetcher answer with [`Status::Unsupported`] rather than
/// guessing.
pub const OPCODE_READ: u32 = 1;

/// Block size both ends can carry without asking the kernel for a larger
/// socket buffer, and the size the guest's own reads actually are.
///
/// It is the fallback when no negotiated size is available. The negotiated
/// ceiling is usually larger; see [`negotiate_block_size`].
pub const DEFAULT_BLOCK_SIZE: u32 = 65536;

/// Largest block size the negotiation will settle on, however much socket
/// buffer the kernel grants.
///
/// A larger datagram buys less than it costs: the payload has to be copied
/// either way, and a block this size already amortises a round trip over
/// four of the guest's reads.
pub const MAX_BLOCK_SIZE: u32 = 262_144;

/// Smallest usable block size: one traditional sector.
///
/// A negotiation that cannot reach this is refused outright rather than
/// settling on something that would split every read into hundreds of round
/// trips.
pub const MIN_BLOCK_SIZE: u32 = 512;

/// The negotiated block size is rounded down to a multiple of this, so that
/// a split read stays sector-aligned whatever the socket buffer happened to
/// allow.
pub const BLOCK_SIZE_GRANULARITY: u32 = 512;

/// First status value reserved for later use and refused today.
pub const RESERVED_STATUS_FIRST: u32 = 6;

/// Last status value reserved for later use and refused today.
pub const RESERVED_STATUS_LAST: u32 = 11;

/// Size of an encoded [`InitRequest`].
pub const INIT_REQUEST_LEN: usize = 16;

/// Size of an encoded [`InitReply`].
pub const INIT_REPLY_LEN: usize = 32;

/// Size of an encoded [`ReadRequest`].
pub const READ_REQUEST_LEN: usize = 32;

/// Size of an encoded [`ReadReply`] header, before its payload.
pub const READ_REPLY_LEN: usize = 24;

/// How a request ended.
///
/// The vocabulary is a closed set owned by the privileged side. It is rich
/// enough to be acted on -- a range error is the host's own bug, an I/O error
/// is the source's -- and it cannot carry a payload, which is the point: the
/// sentence a user reads is written here, from a number, never by the peer.
///
/// Values [`RESERVED_STATUS_FIRST`] to [`RESERVED_STATUS_LAST`] are reserved
/// for a fetcher that speaks to something further away than a file, in the
/// order `NOT_FOUND`, `FORBIDDEN`, `RANGE_UNSUPPORTED`, `SOURCE_CHANGED`,
/// `NETWORK`, `TIMEOUT`. They are documented rather than defined: adding one
/// is a deliberate change to this enum and to the sentence that renders it,
/// and until then a peer sending one is refused like any other unknown value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Status {
    /// The request was satisfied in full.
    Ok = 0,
    /// The request was malformed: a reserved field set, a length past the
    /// negotiated maximum, an offset and length that overflow.
    BadRequest = 1,
    /// The request was well formed but asks for something this fetcher does
    /// not implement, such as an opcode from a later version.
    Unsupported = 2,
    /// The requested range lies outside the capacity the fetcher advertised.
    OutOfRange = 3,
    /// The source ended before the requested length; the reply carries the
    /// bytes that did exist, and the privileged side decides whether a short
    /// read is survivable.
    ShortRead = 4,
    /// Reading the source failed.
    IoError = 5,
}

impl Status {
    /// The wire value of this status.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Decode a wire value, refusing anything this version does not define.
    pub fn from_u32(raw: u32) -> Result<Self, ProtocolError> {
        match raw {
            0 => Ok(Self::Ok),
            1 => Ok(Self::BadRequest),
            2 => Ok(Self::Unsupported),
            3 => Ok(Self::OutOfRange),
            4 => Ok(Self::ShortRead),
            5 => Ok(Self::IoError),
            _ => Err(ProtocolError::UnknownStatus { status: raw }),
        }
    }
}

/// Everything that can be wrong with a datagram, or with a negotiation.
///
/// Each variant carries numbers this side computed or read, never text from
/// the peer, so rendering one cannot put a peer's bytes on a terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// The datagram is shorter than the header it claims to be.
    ShortDatagram {
        /// Which message was expected, as a literal from this crate.
        message: &'static str,
        /// Bytes the header needs.
        need: usize,
        /// Bytes the datagram actually carried.
        got: usize,
    },
    /// The datagram is longer than the message it claims to be.
    TrailingBytes {
        /// Which message was expected, as a literal from this crate.
        message: &'static str,
        /// Bytes beyond the end of the message.
        extra: usize,
    },
    /// An init message did not start with [`MAGIC`].
    BadMagic {
        /// The magic that was there instead.
        found: u32,
    },
    /// The peer speaks a different version of this protocol.
    ///
    /// Both ends link this crate, so the versions differ only when the two
    /// binaries came from different builds. The rendered sentence names the
    /// two sides as "this build" and "the peer" so that it reads correctly
    /// whichever end of the socket produced it.
    VersionMismatch {
        /// The version this build speaks.
        ours: u32,
        /// The version the peer claims.
        theirs: u32,
    },
    /// A request carried an opcode this version does not define.
    UnknownOpcode {
        /// The opcode that was asked for.
        opcode: u32,
        /// The request id, so that a fetcher can refuse the request by id
        /// rather than dropping it and leaving the peer waiting.
        id: u64,
    },
    /// A reply carried a status value this version does not define.
    UnknownStatus {
        /// The status that was claimed.
        status: u32,
    },
    /// A field reserved for later use was not zero.
    ReservedNotZero {
        /// Which field, as a literal from this crate.
        field: &'static str,
    },
    /// A length exceeds the negotiated maximum.
    LengthTooLarge {
        /// The length that was asked for or claimed.
        length: u32,
        /// The maximum in force.
        max: u32,
    },
    /// An offset and length together overflow a 64-bit offset.
    OffsetOverflow {
        /// The offset asked for.
        offset: u64,
        /// The length asked for.
        length: u32,
    },
    /// A read reply claims more payload than its datagram carries.
    PayloadTruncated {
        /// Payload bytes the header claims.
        claimed: u32,
        /// Payload bytes present after the header.
        available: usize,
    },
    /// The socket buffers on the two sides cannot carry a usable block.
    BlockSizeUnusable {
        /// The largest datagram the smaller side can manage.
        max_datagram: u32,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortDatagram { message, need, got } => write!(
                f,
                "fetch {message} datagram is {got} bytes, short of its {need}-byte header"
            ),
            Self::TrailingBytes { message, extra } => {
                write!(
                    f,
                    "fetch {message} datagram has {extra} unexpected trailing bytes"
                )
            }
            Self::BadMagic { found } => {
                write!(
                    f,
                    "fetch init datagram has magic {found:#010x}, expected {MAGIC:#010x}"
                )
            }
            Self::VersionMismatch { ours, theirs } => write!(
                f,
                "fetch protocol version mismatch: this build speaks version {ours}, \
                 the peer speaks version {theirs}"
            ),
            Self::UnknownOpcode { opcode, id } => {
                write!(f, "fetch request {id} carries unknown opcode {opcode}")
            }
            Self::UnknownStatus { status } => {
                write!(f, "fetch reply carries unknown status {status}")
            }
            Self::ReservedNotZero { field } => {
                write!(f, "fetch {field} is reserved and must be zero")
            }
            Self::LengthTooLarge { length, max } => write!(
                f,
                "fetch transfer of {length} bytes exceeds the negotiated maximum of {max}"
            ),
            Self::OffsetOverflow { offset, length } => write!(
                f,
                "fetch read of {length} bytes at offset {offset} overflows a 64-bit offset"
            ),
            Self::PayloadTruncated { claimed, available } => write!(
                f,
                "fetch read reply claims {claimed} payload bytes but carries {available}"
            ),
            Self::BlockSizeUnusable { max_datagram } => write!(
                f,
                "a socket buffer allowing only {max_datagram}-byte datagrams cannot carry a \
                 {MIN_BLOCK_SIZE}-byte block"
            ),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<ProtocolError> for io::Error {
    fn from(err: ProtocolError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, err.to_string())
    }
}

/// Settle on a block size from what each side can actually carry.
///
/// Both arguments are the largest single datagram that side can send or
/// receive, which each side reads back from the kernel rather than deriving
/// from a sysctl: the granted socket buffer is not the value that was asked
/// for, and the ceiling it implies is not derivable from the sysctl by
/// inspection. The smaller side wins, the read reply's header is deducted,
/// the result is capped at [`MAX_BLOCK_SIZE`] and rounded down to
/// [`BLOCK_SIZE_GRANULARITY`], and anything below [`MIN_BLOCK_SIZE`] is
/// refused rather than used.
pub fn negotiate_block_size(ours: u32, theirs: u32) -> Result<u32, ProtocolError> {
    let datagram = ours.min(theirs);
    let payload = datagram.saturating_sub(READ_REPLY_LEN as u32);
    let capped = payload.min(MAX_BLOCK_SIZE);
    let aligned = capped - (capped % BLOCK_SIZE_GRANULARITY);
    if aligned < MIN_BLOCK_SIZE {
        return Err(ProtocolError::BlockSizeUnusable {
            max_datagram: datagram,
        });
    }
    Ok(aligned)
}

/// Read a little-endian `u32` at a constant offset.
///
/// Callers length-check the datagram against the whole header before reading
/// any field, and every call site uses a constant offset inside that header,
/// so the slicing cannot be out of range. The layout tests pin those
/// constants to the struct they describe.
fn get_u32(buf: &[u8], off: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(raw)
}

/// Read a little-endian `u64` at a constant offset. See [`get_u32`].
fn get_u64(buf: &[u8], off: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(raw)
}

/// Write a little-endian `u32` at a constant offset into a fixed-size buffer.
fn put_u32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// Write a little-endian `u64` at a constant offset into a fixed-size buffer.
fn put_u64(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

/// Check a payload-free message's length exactly.
fn check_exact(message: &'static str, need: usize, got: usize) -> Result<(), ProtocolError> {
    if got < need {
        return Err(ProtocolError::ShortDatagram { message, need, got });
    }
    if got > need {
        return Err(ProtocolError::TrailingBytes {
            message,
            extra: got - need,
        });
    }
    Ok(())
}

/// The first datagram: what the privileged side can carry, and who it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct InitRequest {
    /// Always [`MAGIC`].
    pub magic: u32,
    /// Always [`VERSION`] on a message this build sends.
    pub version: u32,
    /// Largest single datagram this side can send or receive.
    pub max_datagram: u32,
    /// Reserved; must be zero.
    pub flags: u32,
}

impl InitRequest {
    const MAGIC_OFF: usize = 0;
    const VERSION_OFF: usize = 4;
    const MAX_DATAGRAM_OFF: usize = 8;
    const FLAGS_OFF: usize = 12;

    /// A well-formed init request advertising what this side can carry.
    pub fn new(max_datagram: u32) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            max_datagram,
            flags: 0,
        }
    }

    /// Encode to its datagram.
    pub fn encode(&self) -> [u8; INIT_REQUEST_LEN] {
        let mut out = [0u8; INIT_REQUEST_LEN];
        put_u32(&mut out, Self::MAGIC_OFF, self.magic);
        put_u32(&mut out, Self::VERSION_OFF, self.version);
        put_u32(&mut out, Self::MAX_DATAGRAM_OFF, self.max_datagram);
        put_u32(&mut out, Self::FLAGS_OFF, self.flags);
        out
    }

    /// Decode a datagram received from the privileged side.
    pub fn decode(datagram: &[u8]) -> Result<Self, ProtocolError> {
        check_exact("init request", INIT_REQUEST_LEN, datagram.len())?;
        let magic = get_u32(datagram, Self::MAGIC_OFF);
        if magic != MAGIC {
            return Err(ProtocolError::BadMagic { found: magic });
        }
        let version = get_u32(datagram, Self::VERSION_OFF);
        if version != VERSION {
            return Err(ProtocolError::VersionMismatch {
                ours: VERSION,
                theirs: version,
            });
        }
        let flags = get_u32(datagram, Self::FLAGS_OFF);
        if flags != 0 {
            return Err(ProtocolError::ReservedNotZero {
                field: "init request flags",
            });
        }
        Ok(Self {
            magic,
            version,
            max_datagram: get_u32(datagram, Self::MAX_DATAGRAM_OFF),
            flags,
        })
    }
}

/// The answer to an [`InitRequest`]: the settled block size and the capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct InitReply {
    /// Always [`MAGIC`].
    pub magic: u32,
    /// The version the fetcher speaks.
    pub version: u32,
    /// Whether the fetcher accepted the init at all.
    pub status: Status,
    /// Largest payload a single read reply may carry, as settled by
    /// [`negotiate_block_size`] on the fetcher's side.
    pub block_size: u32,
    /// Size of the source in bytes.
    pub capacity: u64,
    /// Reserved; must be zero.
    pub flags: u64,
}

impl InitReply {
    const MAGIC_OFF: usize = 0;
    const VERSION_OFF: usize = 4;
    const STATUS_OFF: usize = 8;
    const BLOCK_SIZE_OFF: usize = 12;
    const CAPACITY_OFF: usize = 16;
    const FLAGS_OFF: usize = 24;

    /// A well-formed init reply.
    pub fn new(status: Status, block_size: u32, capacity: u64) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            status,
            block_size,
            capacity,
            flags: 0,
        }
    }

    /// Encode to its datagram.
    pub fn encode(&self) -> [u8; INIT_REPLY_LEN] {
        let mut out = [0u8; INIT_REPLY_LEN];
        put_u32(&mut out, Self::MAGIC_OFF, self.magic);
        put_u32(&mut out, Self::VERSION_OFF, self.version);
        put_u32(&mut out, Self::STATUS_OFF, self.status.as_u32());
        put_u32(&mut out, Self::BLOCK_SIZE_OFF, self.block_size);
        put_u64(&mut out, Self::CAPACITY_OFF, self.capacity);
        put_u64(&mut out, Self::FLAGS_OFF, self.flags);
        out
    }

    /// Decode a datagram received from the fetcher.
    ///
    /// The block size is read but not judged here: a reply whose status is an
    /// error carries no meaningful block size, and the privileged side wants
    /// to report the status rather than a size complaint. Once the status is
    /// known to be [`Status::Ok`], [`InitReply::accepted_block_size`] is what
    /// decides whether the proposal is one this side can live with.
    pub fn decode(datagram: &[u8]) -> Result<Self, ProtocolError> {
        check_exact("init reply", INIT_REPLY_LEN, datagram.len())?;
        let magic = get_u32(datagram, Self::MAGIC_OFF);
        if magic != MAGIC {
            return Err(ProtocolError::BadMagic { found: magic });
        }
        let version = get_u32(datagram, Self::VERSION_OFF);
        if version != VERSION {
            return Err(ProtocolError::VersionMismatch {
                ours: VERSION,
                theirs: version,
            });
        }
        let flags = get_u64(datagram, Self::FLAGS_OFF);
        if flags != 0 {
            return Err(ProtocolError::ReservedNotZero {
                field: "init reply flags",
            });
        }
        Ok(Self {
            magic,
            version,
            status: Status::from_u32(get_u32(datagram, Self::STATUS_OFF))?,
            block_size: get_u32(datagram, Self::BLOCK_SIZE_OFF),
            capacity: get_u64(datagram, Self::CAPACITY_OFF),
            flags,
        })
    }

    /// Clamp the fetcher's proposed block size to what this side can carry.
    ///
    /// `our_max_datagram` is the largest datagram this side's own socket can
    /// manage, read back from the kernel. A fetcher proposing more than that
    /// is refused rather than trusted, because the datagram it implies would
    /// arrive truncated or not at all; a proposal below [`MIN_BLOCK_SIZE`] or
    /// above [`MAX_BLOCK_SIZE`] is refused for the same reason the
    /// negotiation would not have produced one.
    pub fn accepted_block_size(&self, our_max_datagram: u32) -> Result<u32, ProtocolError> {
        let ours = negotiate_block_size(our_max_datagram, our_max_datagram)?;
        if self.block_size < MIN_BLOCK_SIZE {
            return Err(ProtocolError::BlockSizeUnusable {
                max_datagram: self.block_size.saturating_add(READ_REPLY_LEN as u32),
            });
        }
        if self.block_size > MAX_BLOCK_SIZE {
            return Err(ProtocolError::LengthTooLarge {
                length: self.block_size,
                max: MAX_BLOCK_SIZE,
            });
        }
        if self.block_size > ours {
            return Err(ProtocolError::LengthTooLarge {
                length: self.block_size,
                max: ours,
            });
        }
        Ok(self.block_size)
    }
}

/// A request for `length` bytes at `offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReadRequest {
    /// Always [`OPCODE_READ`] on a message this build sends.
    pub opcode: u32,
    /// Payload bytes wanted; at most the negotiated block size.
    pub length: u32,
    /// Chosen by the requesting side; the reply carries it back.
    pub id: u64,
    /// Byte offset into the source.
    pub offset: u64,
    /// Reserved; must be zero.
    pub flags: u64,
}

impl ReadRequest {
    const OPCODE_OFF: usize = 0;
    const LENGTH_OFF: usize = 4;
    const ID_OFF: usize = 8;
    const OFFSET_OFF: usize = 16;
    const FLAGS_OFF: usize = 24;

    /// A well-formed read request.
    pub fn new(id: u64, offset: u64, length: u32) -> Self {
        Self {
            opcode: OPCODE_READ,
            length,
            id,
            offset,
            flags: 0,
        }
    }

    /// Encode to its datagram.
    pub fn encode(&self) -> [u8; READ_REQUEST_LEN] {
        let mut out = [0u8; READ_REQUEST_LEN];
        put_u32(&mut out, Self::OPCODE_OFF, self.opcode);
        put_u32(&mut out, Self::LENGTH_OFF, self.length);
        put_u64(&mut out, Self::ID_OFF, self.id);
        put_u64(&mut out, Self::OFFSET_OFF, self.offset);
        put_u64(&mut out, Self::FLAGS_OFF, self.flags);
        out
    }

    /// The id of a request this side could not otherwise decode.
    ///
    /// A fetcher that refuses a request still wants to answer it by id, so
    /// that the peer learns the outcome instead of waiting for a reply that
    /// never comes. The id sits at a fixed offset inside the header, so it
    /// can be recovered from any datagram long enough to hold the header,
    /// whatever is wrong with the rest of it.
    pub fn peek_id(datagram: &[u8]) -> Option<u64> {
        if datagram.len() < READ_REQUEST_LEN {
            return None;
        }
        Some(get_u64(datagram, Self::ID_OFF))
    }

    /// Decode a datagram received from the privileged side.
    ///
    /// `max_block` is the negotiated block size. The length is checked
    /// against it before the request is accepted, and the offset and length
    /// are checked for overflow, so a fetcher never has to reason about
    /// either.
    pub fn decode(datagram: &[u8], max_block: u32) -> Result<Self, ProtocolError> {
        check_exact("read request", READ_REQUEST_LEN, datagram.len())?;
        let opcode = get_u32(datagram, Self::OPCODE_OFF);
        let id = get_u64(datagram, Self::ID_OFF);
        if opcode != OPCODE_READ {
            return Err(ProtocolError::UnknownOpcode { opcode, id });
        }
        let flags = get_u64(datagram, Self::FLAGS_OFF);
        if flags != 0 {
            return Err(ProtocolError::ReservedNotZero {
                field: "read request flags",
            });
        }
        let length = get_u32(datagram, Self::LENGTH_OFF);
        if length > max_block {
            return Err(ProtocolError::LengthTooLarge {
                length,
                max: max_block,
            });
        }
        let offset = get_u64(datagram, Self::OFFSET_OFF);
        if offset.checked_add(u64::from(length)).is_none() {
            return Err(ProtocolError::OffsetOverflow { offset, length });
        }
        Ok(Self {
            opcode,
            length,
            id,
            offset,
            flags,
        })
    }
}

/// The answer to a [`ReadRequest`], followed by its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReadReply {
    /// Always [`OPCODE_READ`] on a message this build sends.
    pub opcode: u32,
    /// How the read ended.
    pub status: Status,
    /// The id of the request being answered.
    pub id: u64,
    /// Payload bytes following this header in the same datagram.
    pub length: u32,
    /// Reserved; must be zero.
    pub flags: u32,
}

impl ReadReply {
    const OPCODE_OFF: usize = 0;
    const STATUS_OFF: usize = 4;
    const ID_OFF: usize = 8;
    const LENGTH_OFF: usize = 16;
    const FLAGS_OFF: usize = 20;

    /// A well-formed read reply header for a payload of `length` bytes.
    pub fn new(id: u64, status: Status, length: u32) -> Self {
        Self {
            opcode: OPCODE_READ,
            status,
            id,
            length,
            flags: 0,
        }
    }

    /// Encode the header. The payload follows it in the same datagram.
    pub fn encode(&self) -> [u8; READ_REPLY_LEN] {
        let mut out = [0u8; READ_REPLY_LEN];
        put_u32(&mut out, Self::OPCODE_OFF, self.opcode);
        put_u32(&mut out, Self::STATUS_OFF, self.status.as_u32());
        put_u64(&mut out, Self::ID_OFF, self.id);
        put_u32(&mut out, Self::LENGTH_OFF, self.length);
        put_u32(&mut out, Self::FLAGS_OFF, self.flags);
        out
    }

    /// Encode the whole datagram, header and payload together.
    ///
    /// The payload has to be the length the header claims; a mismatch is a
    /// bug on this side, and catching it here is cheaper than shipping a
    /// datagram the peer will refuse.
    pub fn encode_datagram(&self, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if payload.len() != self.length as usize {
            return Err(ProtocolError::PayloadTruncated {
                claimed: self.length,
                available: payload.len(),
            });
        }
        let mut out = Vec::with_capacity(READ_REPLY_LEN + payload.len());
        out.extend_from_slice(&self.encode());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Decode a datagram received from the fetcher, returning the header and
    /// a borrow of its payload.
    ///
    /// `max_block` is the negotiated block size. The claimed length is
    /// checked against it, and then against the datagram's own size, before
    /// the payload is borrowed -- so a reply claiming more than it carries,
    /// or more than was ever agreed, cannot become an out-of-bounds read.
    pub fn decode(datagram: &[u8], max_block: u32) -> Result<(Self, &[u8]), ProtocolError> {
        if datagram.len() < READ_REPLY_LEN {
            return Err(ProtocolError::ShortDatagram {
                message: "read reply",
                need: READ_REPLY_LEN,
                got: datagram.len(),
            });
        }
        let opcode = get_u32(datagram, Self::OPCODE_OFF);
        if opcode != OPCODE_READ {
            return Err(ProtocolError::UnknownOpcode {
                opcode,
                id: get_u64(datagram, Self::ID_OFF),
            });
        }
        let flags = get_u32(datagram, Self::FLAGS_OFF);
        if flags != 0 {
            return Err(ProtocolError::ReservedNotZero {
                field: "read reply flags",
            });
        }
        let length = get_u32(datagram, Self::LENGTH_OFF);
        if length > max_block {
            return Err(ProtocolError::LengthTooLarge {
                length,
                max: max_block,
            });
        }
        let available = datagram.len() - READ_REPLY_LEN;
        let claimed = length as usize;
        if claimed > available {
            return Err(ProtocolError::PayloadTruncated {
                claimed: length,
                available,
            });
        }
        if claimed < available {
            return Err(ProtocolError::TrailingBytes {
                message: "read reply",
                extra: available - claimed,
            });
        }
        let header = Self {
            opcode,
            status: Status::from_u32(get_u32(datagram, Self::STATUS_OFF))?,
            id: get_u64(datagram, Self::ID_OFF),
            length,
            flags,
        };
        Ok((header, &datagram[READ_REPLY_LEN..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    // The magic has to be legible in a hexdump of the datagram, which is the
    // whole reason for choosing it over an arbitrary number.
    #[test]
    fn magic_reads_as_text_on_the_wire() {
        assert_eq!(MAGIC.to_le_bytes(), *b"INFT");
    }

    #[test]
    fn init_request_layout() {
        assert_eq!(size_of::<InitRequest>(), INIT_REQUEST_LEN);
        assert_eq!(align_of::<InitRequest>(), 4);
        assert_eq!(offset_of!(InitRequest, magic), InitRequest::MAGIC_OFF);
        assert_eq!(offset_of!(InitRequest, version), InitRequest::VERSION_OFF);
        assert_eq!(
            offset_of!(InitRequest, max_datagram),
            InitRequest::MAX_DATAGRAM_OFF
        );
        assert_eq!(offset_of!(InitRequest, flags), InitRequest::FLAGS_OFF);
        assert_eq!(InitRequest::MAGIC_OFF, 0);
        assert_eq!(InitRequest::VERSION_OFF, 4);
        assert_eq!(InitRequest::MAX_DATAGRAM_OFF, 8);
        assert_eq!(InitRequest::FLAGS_OFF, 12);
    }

    #[test]
    fn init_reply_layout() {
        assert_eq!(size_of::<InitReply>(), INIT_REPLY_LEN);
        assert_eq!(align_of::<InitReply>(), 8);
        assert_eq!(offset_of!(InitReply, magic), InitReply::MAGIC_OFF);
        assert_eq!(offset_of!(InitReply, version), InitReply::VERSION_OFF);
        assert_eq!(offset_of!(InitReply, status), InitReply::STATUS_OFF);
        assert_eq!(offset_of!(InitReply, block_size), InitReply::BLOCK_SIZE_OFF);
        assert_eq!(offset_of!(InitReply, capacity), InitReply::CAPACITY_OFF);
        assert_eq!(offset_of!(InitReply, flags), InitReply::FLAGS_OFF);
        assert_eq!(InitReply::MAGIC_OFF, 0);
        assert_eq!(InitReply::VERSION_OFF, 4);
        assert_eq!(InitReply::STATUS_OFF, 8);
        assert_eq!(InitReply::BLOCK_SIZE_OFF, 12);
        assert_eq!(InitReply::CAPACITY_OFF, 16);
        assert_eq!(InitReply::FLAGS_OFF, 24);
    }

    #[test]
    fn read_request_layout() {
        assert_eq!(size_of::<ReadRequest>(), READ_REQUEST_LEN);
        assert_eq!(align_of::<ReadRequest>(), 8);
        assert_eq!(offset_of!(ReadRequest, opcode), ReadRequest::OPCODE_OFF);
        assert_eq!(offset_of!(ReadRequest, length), ReadRequest::LENGTH_OFF);
        assert_eq!(offset_of!(ReadRequest, id), ReadRequest::ID_OFF);
        assert_eq!(offset_of!(ReadRequest, offset), ReadRequest::OFFSET_OFF);
        assert_eq!(offset_of!(ReadRequest, flags), ReadRequest::FLAGS_OFF);
        assert_eq!(ReadRequest::OPCODE_OFF, 0);
        assert_eq!(ReadRequest::LENGTH_OFF, 4);
        assert_eq!(ReadRequest::ID_OFF, 8);
        assert_eq!(ReadRequest::OFFSET_OFF, 16);
        assert_eq!(ReadRequest::FLAGS_OFF, 24);
    }

    #[test]
    fn read_reply_layout() {
        assert_eq!(size_of::<ReadReply>(), READ_REPLY_LEN);
        assert_eq!(align_of::<ReadReply>(), 8);
        assert_eq!(offset_of!(ReadReply, opcode), ReadReply::OPCODE_OFF);
        assert_eq!(offset_of!(ReadReply, status), ReadReply::STATUS_OFF);
        assert_eq!(offset_of!(ReadReply, id), ReadReply::ID_OFF);
        assert_eq!(offset_of!(ReadReply, length), ReadReply::LENGTH_OFF);
        assert_eq!(offset_of!(ReadReply, flags), ReadReply::FLAGS_OFF);
        assert_eq!(ReadReply::OPCODE_OFF, 0);
        assert_eq!(ReadReply::STATUS_OFF, 4);
        assert_eq!(ReadReply::ID_OFF, 8);
        assert_eq!(ReadReply::LENGTH_OFF, 16);
        assert_eq!(ReadReply::FLAGS_OFF, 20);
    }

    #[test]
    fn init_request_round_trip() {
        let msg = InitRequest::new(212_960);
        let bytes = msg.encode();
        assert_eq!(bytes.len(), INIT_REQUEST_LEN);
        assert_eq!(InitRequest::decode(&bytes), Ok(msg));
    }

    #[test]
    fn init_reply_round_trip() {
        let msg = InitReply::new(Status::Ok, 65536, 8 * 1024 * 1024);
        let bytes = msg.encode();
        assert_eq!(bytes.len(), INIT_REPLY_LEN);
        assert_eq!(InitReply::decode(&bytes), Ok(msg));
    }

    #[test]
    fn read_request_round_trip() {
        let msg = ReadRequest::new(7, 65536, 4096);
        let bytes = msg.encode();
        assert_eq!(bytes.len(), READ_REQUEST_LEN);
        assert_eq!(ReadRequest::decode(&bytes, 65536), Ok(msg));
    }

    #[test]
    fn read_reply_round_trip() {
        let payload = [0xABu8; 512];
        let msg = ReadReply::new(9, Status::Ok, payload.len() as u32);
        let datagram = msg
            .encode_datagram(&payload)
            .expect("payload matches header");
        assert_eq!(datagram.len(), READ_REPLY_LEN + payload.len());
        let (header, body) = ReadReply::decode(&datagram, 65536).expect("decodes");
        assert_eq!(header, msg);
        assert_eq!(body, &payload[..]);
    }

    #[test]
    fn fields_are_little_endian_on_the_wire() {
        let request = ReadRequest::new(0x0102_0304_0506_0708, 0x1122_3344_5566_7788, 0x9ABC_DEF0);
        let bytes = request.encode();
        assert_eq!(
            &bytes[ReadRequest::ID_OFF..ReadRequest::ID_OFF + 8],
            &[8, 7, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(
            &bytes[ReadRequest::OFFSET_OFF..ReadRequest::OFFSET_OFF + 8],
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        assert_eq!(
            &bytes[ReadRequest::LENGTH_OFF..ReadRequest::LENGTH_OFF + 4],
            &[0xF0, 0xDE, 0xBC, 0x9A]
        );
    }

    #[test]
    fn every_status_round_trips() {
        for status in [
            Status::Ok,
            Status::BadRequest,
            Status::Unsupported,
            Status::OutOfRange,
            Status::ShortRead,
            Status::IoError,
        ] {
            assert_eq!(Status::from_u32(status.as_u32()), Ok(status));
        }
    }

    #[test]
    fn datagram_shorter_than_the_header_is_refused() {
        for n in 0..INIT_REQUEST_LEN {
            let short = vec![0u8; n];
            assert_eq!(
                InitRequest::decode(&short),
                Err(ProtocolError::ShortDatagram {
                    message: "init request",
                    need: INIT_REQUEST_LEN,
                    got: n
                })
            );
        }
        assert!(matches!(
            InitReply::decode(&[0u8; INIT_REPLY_LEN - 1]),
            Err(ProtocolError::ShortDatagram { .. })
        ));
        assert!(matches!(
            ReadRequest::decode(&[0u8; READ_REQUEST_LEN - 1], 65536),
            Err(ProtocolError::ShortDatagram { .. })
        ));
        assert!(matches!(
            ReadReply::decode(&[0u8; READ_REPLY_LEN - 1], 65536),
            Err(ProtocolError::ShortDatagram { .. })
        ));
    }

    #[test]
    fn datagram_longer_than_the_message_is_refused() {
        let mut bytes = InitRequest::new(65536).encode().to_vec();
        bytes.push(0);
        assert_eq!(
            InitRequest::decode(&bytes),
            Err(ProtocolError::TrailingBytes {
                message: "init request",
                extra: 1
            })
        );

        let payload = [0u8; 16];
        let mut datagram = ReadReply::new(1, Status::Ok, payload.len() as u32)
            .encode_datagram(&payload)
            .expect("payload matches header");
        datagram.push(0);
        assert_eq!(
            ReadReply::decode(&datagram, 65536),
            Err(ProtocolError::TrailingBytes {
                message: "read reply",
                extra: 1
            })
        );
    }

    #[test]
    fn bad_magic_is_refused() {
        let found: u32 = 0xDEAD_BEEF;
        let mut bytes = InitRequest::new(65536).encode();
        put_u32(&mut bytes, InitRequest::MAGIC_OFF, found);
        assert_eq!(
            InitRequest::decode(&bytes),
            Err(ProtocolError::BadMagic { found })
        );

        let mut bytes = InitReply::new(Status::Ok, 65536, 1).encode();
        put_u32(&mut bytes, InitReply::MAGIC_OFF, 0);
        assert_eq!(
            InitReply::decode(&bytes),
            Err(ProtocolError::BadMagic { found: 0 })
        );
    }

    #[test]
    fn version_mismatch_names_both_versions() {
        let mut bytes = InitReply::new(Status::Ok, 65536, 1).encode();
        put_u32(&mut bytes, InitReply::VERSION_OFF, VERSION + 1);
        let err = InitReply::decode(&bytes).expect_err("a version mismatch is fatal");
        assert_eq!(
            err,
            ProtocolError::VersionMismatch {
                ours: VERSION,
                theirs: VERSION + 1
            }
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains(&format!("version {VERSION}")),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("version {}", VERSION + 1)),
            "{rendered}"
        );

        let mut bytes = InitRequest::new(65536).encode();
        put_u32(&mut bytes, InitRequest::VERSION_OFF, 99);
        assert_eq!(
            InitRequest::decode(&bytes),
            Err(ProtocolError::VersionMismatch {
                ours: VERSION,
                theirs: 99
            })
        );
    }

    #[test]
    fn unknown_opcode_is_refused_with_its_id() {
        let mut bytes = ReadRequest::new(42, 0, 512).encode();
        put_u32(&mut bytes, ReadRequest::OPCODE_OFF, 2);
        assert_eq!(
            ReadRequest::decode(&bytes, 65536),
            Err(ProtocolError::UnknownOpcode { opcode: 2, id: 42 })
        );
        assert_eq!(ReadRequest::peek_id(&bytes), Some(42));
        assert_eq!(ReadRequest::peek_id(&bytes[..READ_REQUEST_LEN - 1]), None);
    }

    #[test]
    fn unknown_status_is_refused() {
        let mut bytes = InitReply::new(Status::Ok, 65536, 1).encode();
        put_u32(&mut bytes, InitReply::STATUS_OFF, 4096);
        assert_eq!(
            InitReply::decode(&bytes),
            Err(ProtocolError::UnknownStatus { status: 4096 })
        );

        let mut datagram = ReadReply::new(1, Status::Ok, 0)
            .encode_datagram(&[])
            .expect("payload matches header");
        put_u32(&mut datagram, ReadReply::STATUS_OFF, u32::MAX);
        assert_eq!(
            ReadReply::decode(&datagram, 65536),
            Err(ProtocolError::UnknownStatus { status: u32::MAX })
        );
    }

    #[test]
    fn reserved_status_values_are_not_yet_accepted() {
        for raw in RESERVED_STATUS_FIRST..=RESERVED_STATUS_LAST {
            assert_eq!(
                Status::from_u32(raw),
                Err(ProtocolError::UnknownStatus { status: raw })
            );
        }
    }

    #[test]
    fn reserved_flags_must_be_zero() {
        let mut bytes = InitRequest::new(65536).encode();
        put_u32(&mut bytes, InitRequest::FLAGS_OFF, 1);
        assert_eq!(
            InitRequest::decode(&bytes),
            Err(ProtocolError::ReservedNotZero {
                field: "init request flags"
            })
        );

        let mut bytes = InitReply::new(Status::Ok, 65536, 1).encode();
        put_u64(&mut bytes, InitReply::FLAGS_OFF, 1 << 40);
        assert_eq!(
            InitReply::decode(&bytes),
            Err(ProtocolError::ReservedNotZero {
                field: "init reply flags"
            })
        );

        let mut bytes = ReadRequest::new(1, 0, 512).encode();
        put_u64(&mut bytes, ReadRequest::FLAGS_OFF, 1);
        assert_eq!(
            ReadRequest::decode(&bytes, 65536),
            Err(ProtocolError::ReservedNotZero {
                field: "read request flags"
            })
        );

        let mut datagram = ReadReply::new(1, Status::Ok, 0)
            .encode_datagram(&[])
            .expect("payload matches header");
        put_u32(&mut datagram, ReadReply::FLAGS_OFF, 1);
        assert_eq!(
            ReadReply::decode(&datagram, 65536),
            Err(ProtocolError::ReservedNotZero {
                field: "read reply flags"
            })
        );
    }

    #[test]
    fn length_past_the_negotiated_maximum_is_refused() {
        let bytes = ReadRequest::new(1, 0, 65537).encode();
        assert_eq!(
            ReadRequest::decode(&bytes, 65536),
            Err(ProtocolError::LengthTooLarge {
                length: 65537,
                max: 65536
            })
        );

        // A reply is refused on its claimed length alone, before anything
        // tries to borrow a payload that size.
        let payload = [0u8; 64];
        let mut datagram = ReadReply::new(1, Status::Ok, payload.len() as u32)
            .encode_datagram(&payload)
            .expect("payload matches header");
        put_u32(&mut datagram, ReadReply::LENGTH_OFF, u32::MAX);
        assert_eq!(
            ReadReply::decode(&datagram, 512),
            Err(ProtocolError::LengthTooLarge {
                length: u32::MAX,
                max: 512
            })
        );
    }

    #[test]
    fn offset_plus_length_overflow_is_refused() {
        let bytes = ReadRequest::new(1, u64::MAX - 7, 512).encode();
        assert_eq!(
            ReadRequest::decode(&bytes, 65536),
            Err(ProtocolError::OffsetOverflow {
                offset: u64::MAX - 7,
                length: 512
            })
        );
    }

    #[test]
    fn reply_claiming_more_payload_than_it_carries_is_refused() {
        let payload = [0u8; 64];
        let mut datagram = ReadReply::new(1, Status::Ok, payload.len() as u32)
            .encode_datagram(&payload)
            .expect("payload matches header");
        put_u32(&mut datagram, ReadReply::LENGTH_OFF, 4096);
        assert_eq!(
            ReadReply::decode(&datagram, 65536),
            Err(ProtocolError::PayloadTruncated {
                claimed: 4096,
                available: 64
            })
        );
    }

    #[test]
    fn encode_datagram_refuses_a_payload_that_does_not_match_its_header() {
        let header = ReadReply::new(1, Status::Ok, 512);
        assert_eq!(
            header.encode_datagram(&[0u8; 511]),
            Err(ProtocolError::PayloadTruncated {
                claimed: 512,
                available: 511
            })
        );
    }

    #[test]
    fn negotiation_takes_the_smaller_side() {
        // The larger side's buffer is irrelevant: a datagram has to leave one
        // socket and arrive at the other.
        let small = 4064;
        let large = 425_952;
        assert_eq!(
            negotiate_block_size(small, large),
            negotiate_block_size(large, small)
        );
        assert_eq!(negotiate_block_size(small, large), Ok(3584));
    }

    #[test]
    fn negotiation_caps_at_the_maximum_block_size() {
        assert_eq!(negotiate_block_size(u32::MAX, u32::MAX), Ok(MAX_BLOCK_SIZE));
        // The measured ceiling on a host with the default wmem_max, both
        // before and after asking the kernel for more, is well above the cap.
        assert_eq!(negotiate_block_size(212_960, 212_960), Ok(212_480));
        assert_eq!(negotiate_block_size(425_952, 425_952), Ok(MAX_BLOCK_SIZE));
    }

    #[test]
    fn negotiation_rounds_down_to_the_granularity() {
        let block = negotiate_block_size(70_000, 70_000).expect("usable");
        assert_eq!(block % BLOCK_SIZE_GRANULARITY, 0);
        assert!(block <= 70_000 - READ_REPLY_LEN as u32);
    }

    #[test]
    fn negotiation_refuses_a_buffer_too_small_to_be_useful() {
        assert_eq!(
            negotiate_block_size(512, 512),
            Err(ProtocolError::BlockSizeUnusable { max_datagram: 512 })
        );
        assert_eq!(
            negotiate_block_size(0, 65536),
            Err(ProtocolError::BlockSizeUnusable { max_datagram: 0 })
        );
    }

    #[test]
    fn a_greedy_peer_block_size_is_clamped_to_what_this_side_can_carry() {
        // The fetcher proposes more than this side's socket can receive.
        let reply = InitReply::new(Status::Ok, 65536, 1 << 30);
        assert_eq!(
            reply.accepted_block_size(4064),
            Err(ProtocolError::LengthTooLarge {
                length: 65536,
                max: 3584
            })
        );
        // And a proposal past the protocol's own ceiling is refused whatever
        // the socket would allow.
        let reply = InitReply::new(Status::Ok, MAX_BLOCK_SIZE + 512, 1 << 30);
        assert_eq!(
            reply.accepted_block_size(u32::MAX),
            Err(ProtocolError::LengthTooLarge {
                length: MAX_BLOCK_SIZE + 512,
                max: MAX_BLOCK_SIZE
            })
        );
    }

    #[test]
    fn an_acceptable_peer_block_size_is_taken_as_offered() {
        let reply = InitReply::new(Status::Ok, DEFAULT_BLOCK_SIZE, 1 << 30);
        assert_eq!(reply.accepted_block_size(212_960), Ok(DEFAULT_BLOCK_SIZE));
    }

    #[test]
    fn a_peer_block_size_below_the_minimum_is_refused() {
        let reply = InitReply::new(Status::Ok, MIN_BLOCK_SIZE - 1, 1 << 30);
        assert!(matches!(
            reply.accepted_block_size(212_960),
            Err(ProtocolError::BlockSizeUnusable { .. })
        ));
    }

    #[test]
    fn a_decode_error_becomes_invalid_data_and_keeps_its_sentence() {
        let err: io::Error = ProtocolError::BadMagic { found: 0 }.into();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("magic"), "{err}");
    }
}
