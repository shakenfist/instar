//! VHDX (Hyper-V Virtual Hard Disk v2) format parsing.
//!
//! Provides VHDX header, region table, metadata, and BAT parsing,
//! block lookup for dynamic VHDX images, and output builders for
//! creating new VHDX images.
//!
//! VHDX uses CRC-32C checksums, GUID-identified metadata, 64-bit BAT
//! entries with interleaved sector bitmap entries, and 1MB-aligned
//! structures. All on-disk fields are little-endian.
//!
//! # Parent locators are staged, and owned
//!
//! [`VhdxParentLocator`] owns its decoded keys and values in fixed
//! arrays, so [`VhdxMetadata`] is several kilobytes when an image
//! carries a parent locator. The sibling VHD crate made the opposite
//! choice: `VhdParentInfo` borrows the undecoded parent name and
//! decodes into a buffer the caller supplies. One phase, two answers,
//! so the reason is worth stating rather than leaving a later reader
//! to decide the pair is simply inconsistent.
//!
//! The difference is where the bytes come from. A VHD's locator fields
//! live in a header the caller has already read, so a borrow is free
//! and the caller keeps control of the decode cost. A VHDX's locator
//! item lives at an arbitrary offset in the metadata region and has to
//! be assembled from sector reads into a staging buffer that dies with
//! the call — there is nothing left to borrow from afterwards, and
//! `no_std` with no allocator rules out the obvious alternative of
//! boxing it. Owning the decoded strings is what lets `parse_metadata`
//! return a value that outlives its own scratch buffer.
//!
//! The cost is bounded and paid on the stack: `MAX_PARENT_LOCATOR_*`
//! cap the item at eight entries with a 96-byte key and a 780-byte
//! value each, roughly 7.3 KB inside a 4 MiB guest stack
//! (`STACK_SIZE`, `src/vmm/src/main.rs`). See decision 7 of
//! `docs/plans/PLAN-differencing-phase-03-parse.md`.

#![no_std]
#![allow(clippy::too_many_arguments)]

use shared::{
    le_u16, le_u32, le_u64, utf16_to_utf8, utf8_to_utf16, write_le_u16, write_le_u32, write_le_u64,
    AllocationSummary, CallTable, MapExtent, MapExtentCoalescer, MapExtentState, MAX_SECTOR_SIZE,
};

// ============================================================================
// CRC-32C (Castagnoli) implementation
// ============================================================================

/// CRC-32C lookup table (Castagnoli polynomial 0x1EDC6F41,
/// bit-reversed: 0x82F63B78). Computed at compile time.
const CRC32C_TABLE: [u32; 256] = {
    let poly: u32 = 0x82F6_3B78;
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Compute CRC-32C over `data`, treating bytes at
/// `checksum_offset..checksum_offset+4` as zero (the checksum field).
pub fn compute_crc32c(data: &[u8], checksum_offset: usize) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for (i, &byte) in data.iter().enumerate() {
        let b = if i >= checksum_offset && i < checksum_offset + 4 {
            0u8
        } else {
            byte
        };
        crc = CRC32C_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

// ============================================================================
// VHDX constants
// ============================================================================

/// File identifier signature: "vhdxfile" as LE u64.
pub const FILE_IDENTIFIER_SIGNATURE: u64 = 0x656C_6966_7864_6876;

/// Header 1 offset (64KB into file).
pub const HEADER1_OFFSET: u64 = 0x10000;
/// Header 2 offset (128KB into file).
pub const HEADER2_OFFSET: u64 = 0x20000;
/// Region table 1 offset (192KB into file).
pub const REGION_TABLE1_OFFSET: u64 = 0x30000;
/// Region table 2 offset (256KB into file).
pub const REGION_TABLE2_OFFSET: u64 = 0x40000;

/// Header signature: "head" as LE u32.
pub const HEADER_SIGNATURE: u32 = 0x6461_6568;
/// Region table signature: "regi" as LE u32.
pub const REGION_TABLE_SIGNATURE: u32 = 0x6967_6572;
/// Metadata table signature: "metadata" as LE u64.
pub const METADATA_TABLE_SIGNATURE: u64 = 0x6174_6164_6174_656D;

/// Header size in bytes (4KB of data within a 64KB region).
pub const HEADER_SIZE: usize = 4096;
/// Header checksum offset within the 4KB header.
pub const HEADER_CHECKSUM_OFFSET: usize = 4;
/// Header sequence number offset.
pub const HEADER_SEQUENCE_NUMBER_OFFSET: usize = 8;
/// Header file_write_guid offset (16 bytes).
pub const HEADER_FILE_WRITE_GUID_OFFSET: usize = 16;
/// Header data_write_guid offset (16 bytes).
pub const HEADER_DATA_WRITE_GUID_OFFSET: usize = 32;
/// Header log_guid offset (16 bytes).
pub const HEADER_LOG_GUID_OFFSET: usize = 48;
/// Header log_version offset (u16).
pub const HEADER_LOG_VERSION_OFFSET: usize = 64;
/// Header version offset (u16).
pub const HEADER_VERSION_OFFSET: usize = 66;
/// Header log_length offset (u32).
pub const HEADER_LOG_LENGTH_OFFSET: usize = 68;
/// Header log_offset offset (u64).
pub const HEADER_LOG_OFFSET_OFFSET: usize = 72;

/// Region table header size (signature + checksum + entry_count + reserved).
pub const REGION_TABLE_HEADER_SIZE: usize = 16;
/// Region table entry size (GUID + offset + length + required).
pub const REGION_TABLE_ENTRY_SIZE: usize = 32;
/// Region table checksum offset.
pub const REGION_TABLE_CHECKSUM_OFFSET: usize = 4;
/// Region table entry count offset.
pub const REGION_TABLE_ENTRY_COUNT_OFFSET: usize = 8;
/// Maximum region table entries.
pub const MAX_REGION_TABLE_ENTRIES: u32 = 2047;

/// Metadata table header size (signature, reserved, entry count,
/// reserved), ahead of the first table entry.
pub const METADATA_TABLE_HEADER_SIZE: usize = 32;
/// Metadata table entry size.
pub const METADATA_TABLE_ENTRY_SIZE: usize = 32;
/// Metadata table entry count offset, an LE u16 within the header.
pub const METADATA_TABLE_ENTRY_COUNT_OFFSET: usize = 10;
/// Maximum metadata table entries.
pub const MAX_METADATA_TABLE_ENTRIES: u16 = 2047;

// BAT region GUID: 2DC27766-F623-4200-9D64-115E9BFD4A08
pub const BAT_REGION_GUID: [u8; 16] = [
    0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08,
];

// Metadata region GUID: 8B7CA206-4790-4B9A-B8FE-575F050F886E
pub const METADATA_REGION_GUID: [u8; 16] = [
    0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E,
];

// File Parameters GUID: CAA16737-FA36-4D43-B3B6-33F0AA44E76B
const FILE_PARAMETERS_GUID: [u8; 16] = [
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B,
];

// Virtual Disk Size GUID: 2FA54224-CD1B-4876-B211-5DBED83BF4B8
const VIRTUAL_DISK_SIZE_GUID: [u8; 16] = [
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8,
];

// Logical Sector Size GUID: 8141BF1D-A96F-4709-BA47-F233A8FAAB5F
const LOGICAL_SECTOR_SIZE_GUID: [u8; 16] = [
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F,
];

// Physical Sector Size GUID: CDA348C7-445D-4471-9CC9-E9885251C556
const PHYSICAL_SECTOR_SIZE_GUID: [u8; 16] = [
    0xC7, 0x48, 0xA3, 0xCD, 0x5D, 0x44, 0x71, 0x44, 0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56,
];

/// Parent Locator metadata item GUID: A8D35F2D-B30B-454D-ABF7-D3D84834AB0C.
///
/// This is the *metadata item* identifier, the `ItemID` of the table
/// entry that registers the item. It is not the locator *type* GUID
/// that the item's own header carries -- that one is
/// [`VHDX_PARENT_LOCATOR_TYPE_GUID`], and the two are easy to confuse
/// because both appear in a differencing image and both are stored
/// bytes_le. Public so that a caller laying out a metadata region can
/// find the entry [`build_parent_locator`] wrote.
pub const PARENT_LOCATOR_GUID: [u8; 16] = [
    0x2D, 0x5F, 0xD3, 0xA8, 0x0B, 0xB3, 0x4D, 0x45, 0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C,
];

// BAT entry states (bits 0-2).
/// Block not present (unallocated, reads as zero).
pub const PAYLOAD_BLOCK_NOT_PRESENT: u64 = 0;
/// Block undefined (transitional state).
pub const PAYLOAD_BLOCK_UNDEFINED: u64 = 1;
/// Block reads as all zeros.
pub const PAYLOAD_BLOCK_ZERO: u64 = 2;
/// Block unmapped.
pub const PAYLOAD_BLOCK_UNMAPPED: u64 = 3;
/// Block fully present (allocated, data at file offset).
pub const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
/// Block partially present (differencing disk only).
pub const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u64 = 7;

/// Mask for extracting the file offset from a BAT entry (bits 20-63).
/// The offset is in units of 1 MB.
pub const BAT_ENTRY_OFFSET_MASK: u64 = 0xFFFF_FFFF_FFF0_0000;
/// Mask for extracting the state from a BAT entry (bits 0-2).
pub const BAT_ENTRY_STATE_MASK: u64 = 0x07;

/// Default block size (32 MiB, same as QEMU default).
pub const DEFAULT_BLOCK_SIZE: u32 = 32 * 1024 * 1024;

/// VHDX version we support (1).
pub const VHDX_VERSION: u16 = 1;

/// Alignment for VHDX regions and payload (1 MB).
pub const MB_ALIGN: u64 = 1024 * 1024;

// ============================================================================
// Cached sector read helper (little-endian u64)
// ============================================================================

shared::cached_read!(read_u64_le_cached, u64, le, 8);

// ============================================================================
// VHDX header parsing
// ============================================================================

/// Parsed VHDX header fields.
pub struct VhdxHeader {
    pub signature: u32,
    pub checksum: u32,
    pub sequence_number: u64,
    pub data_write_guid: [u8; 16],
    pub log_guid: [u8; 16],
    pub log_length: u32,
    pub log_offset: u64,
}

impl VhdxHeader {
    /// Parse a VHDX header from a 4096-byte buffer.
    ///
    /// Validates the signature and CRC-32C checksum.
    /// Returns `None` if invalid.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }

        let signature = le_u32(buf, 0);
        if signature != HEADER_SIGNATURE {
            return None;
        }

        let checksum = le_u32(buf, HEADER_CHECKSUM_OFFSET);
        let computed = compute_crc32c(&buf[..HEADER_SIZE], HEADER_CHECKSUM_OFFSET);
        if checksum != computed {
            return None;
        }

        let sequence_number = le_u64(buf, HEADER_SEQUENCE_NUMBER_OFFSET);

        let mut data_write_guid = [0u8; 16];
        data_write_guid.copy_from_slice(
            &buf[HEADER_DATA_WRITE_GUID_OFFSET..HEADER_DATA_WRITE_GUID_OFFSET + 16],
        );

        let mut log_guid = [0u8; 16];
        log_guid.copy_from_slice(&buf[HEADER_LOG_GUID_OFFSET..HEADER_LOG_GUID_OFFSET + 16]);

        let log_length = le_u32(buf, HEADER_LOG_LENGTH_OFFSET);
        let log_offset = le_u64(buf, HEADER_LOG_OFFSET_OFFSET);

        Some(VhdxHeader {
            signature,
            checksum,
            sequence_number,
            data_write_guid,
            log_guid,
            log_length,
            log_offset,
        })
    }
}

// ============================================================================
// VHDX region table parsing
// ============================================================================

/// A region entry from the VHDX region table.
pub struct VhdxRegionEntry {
    pub guid: [u8; 16],
    pub file_offset: u64,
    pub length: u32,
    pub required: u32,
}

/// Parse a VHDX region table from a 64KB buffer.
///
/// Validates the signature and CRC-32C checksum. Returns the entries.
/// Returns `None` if the table is invalid.
pub fn parse_region_table(buf: &[u8]) -> Option<([VhdxRegionEntry; 2], u32)> {
    if buf.len() < REGION_TABLE_HEADER_SIZE {
        return None;
    }

    let sig = le_u32(buf, 0);
    if sig != REGION_TABLE_SIGNATURE {
        return None;
    }

    let checksum = le_u32(buf, REGION_TABLE_CHECKSUM_OFFSET);
    // CRC-32C is computed over the full 64KB region table
    let crc_len = if buf.len() >= 65536 { 65536 } else { buf.len() };
    let computed = compute_crc32c(&buf[..crc_len], REGION_TABLE_CHECKSUM_OFFSET);
    if checksum != computed {
        return None;
    }

    let entry_count = le_u32(buf, REGION_TABLE_ENTRY_COUNT_OFFSET);
    if entry_count > MAX_REGION_TABLE_ENTRIES {
        return None;
    }

    // We need exactly 2 entries: BAT and Metadata
    let mut bat_entry = VhdxRegionEntry {
        guid: [0; 16],
        file_offset: 0,
        length: 0,
        required: 0,
    };
    let mut metadata_entry = VhdxRegionEntry {
        guid: [0; 16],
        file_offset: 0,
        length: 0,
        required: 0,
    };
    let mut found_bat = false;
    let mut found_metadata = false;

    for i in 0..entry_count.min(8) {
        let off = REGION_TABLE_HEADER_SIZE + (i as usize * REGION_TABLE_ENTRY_SIZE);
        if off + REGION_TABLE_ENTRY_SIZE > buf.len() {
            break;
        }

        let mut guid = [0u8; 16];
        guid.copy_from_slice(&buf[off..off + 16]);

        let file_offset = le_u64(buf, off + 16);
        let length = le_u32(buf, off + 24);
        let required = le_u32(buf, off + 28);

        if guid == BAT_REGION_GUID {
            bat_entry = VhdxRegionEntry {
                guid,
                file_offset,
                length,
                required,
            };
            found_bat = true;
        } else if guid == METADATA_REGION_GUID {
            metadata_entry = VhdxRegionEntry {
                guid,
                file_offset,
                length,
                required,
            };
            found_metadata = true;
        }
    }

    if !found_bat || !found_metadata {
        return None;
    }

    Some(([bat_entry, metadata_entry], entry_count))
}

// ============================================================================
// VHDX parent locator metadata item
// ============================================================================
//
// The layout parsed here is pinned, offset by offset, in
// `docs/plans/PLAN-differencing-phase-01-pin.md` under "VHDX — the
// parent locator metadata item", against `xxd` of real Hyper-V
// images. That section is the authority; nothing here rediscovers it.
//
// Item layout (SPEC(VHDX) 2.6.2.6.1 and 2.6.2.6.2), all offsets
// relative to the start of the metadata item:
//
//   +0   LocatorType     16 bytes, GUID in mixed-endian bytes_le form
//   +16  Reserved         2 bytes, LE u16, MUST be 0
//   +18  KeyValueCount    2 bytes, LE u16
//   +20  entries          12 bytes each:
//          +0  KeyOffset    LE u32, relative to the item start
//          +4  ValueOffset  LE u32, relative to the item start
//          +8  KeyLength    LE u16, bytes
//          +10 ValueLength  LE u16, bytes
//
// Keys and values are UTF-16 **little** endian, so every call to
// `utf16_to_utf8` below passes `big_endian = false`. (The VHD parent
// name is UTF-16 big endian; that asymmetry is real and is why the
// endianness is named at each call site.)

/// Parent locator type GUID: B04AEFB7-D19E-4A81-B789-25B8E9445913.
///
/// SPEC(VHDX) 2.6.2.6.3 defines exactly one parent locator type and
/// this is it. Stored, like every VHDX GUID, in mixed-endian
/// "bytes_le" form: first three groups little-endian, last two big.
pub const VHDX_PARENT_LOCATOR_TYPE_GUID: [u8; 16] = [
    0xB7, 0xEF, 0x4A, 0xB0, 0x9E, 0xD1, 0x81, 0x4A, 0xB7, 0x89, 0x25, 0xB8, 0xE9, 0x44, 0x59, 0x13,
];

/// Bytes of parent locator header: type GUID, reserved, key/value count.
pub const PARENT_LOCATOR_HEADER_SIZE: usize = 20;

/// Bytes of one parent locator key/value entry.
pub const PARENT_LOCATOR_ENTRY_SIZE: usize = 12;

/// Key/value entries retained from one parent locator item.
///
/// **A parser resource bound, not a spec limit.** SPEC(VHDX) 2.6.2.6.1
/// stores `KeyValueCount` as a u16 and sets no upper bound at all.
/// Hyper-V writes five entries (`parent_linkage`,
/// `absolute_win32_path`, `relative_path`, `volume_path`,
/// `parent_linkage2`) and instar writes two, so this clears real images
/// with room to spare. An item claiming more is parsed up to the limit
/// and the locator is marked `EntryCountExceedsCapacity` rather than
/// dropped, so a later phase knows entries went unread and can say so.
pub const MAX_PARENT_LOCATOR_ENTRIES: usize = 8;

/// Longest key that is decoded, **in UTF-16 source bytes**: 64 bytes,
/// which is 32 code units. The `_BYTES` suffix is load-bearing — an
/// emitter sizing a scratch buffer from this constant gets the cap it
/// expects only because the name says bytes.
///
/// **A parser resource bound, not a spec limit.** SPEC(VHDX) 2.6.2.6.2
/// stores `KeyLength` as a u16 and constrains it no further. The
/// longest key any known producer writes is `absolute_win32_path`, 19
/// characters. A longer key is marked `KeyTooLong` with its raw offset
/// and length intact.
pub const MAX_PARENT_LOCATOR_KEY_UTF16_BYTES: usize = 64;

/// Longest value that is decoded, **in UTF-16 source bytes**: 520
/// bytes, which is 260 code units — Windows `MAX_PATH`. The `_BYTES`
/// suffix is load-bearing: [`build_parent_locator`] enforces the
/// emitter's path cap by handing the encoder a scratch buffer of
/// exactly this many bytes, so a reader who took the old name at face
/// value and sized it in code units would quietly double the cap.
///
/// **A parser resource bound, not a spec limit.** SPEC(VHDX) 2.6.2.6.2
/// stores `ValueLength` as a u16 and fixes no path length, and a
/// Windows extended-length path — one prefixed `\\?\` — may legitimately
/// run to tens of thousands of characters. Such a value is marked
/// `ValueTooLong` here, so a phase reading that defect must treat it as
/// possibly *our* bound rather than evidence of a hostile image. The
/// entry keeps its raw `value_offset` and `value_length`, which is
/// what a later phase would need to re-read it into a bigger buffer.
/// The longest measured Hyper-V value is an 88-character `volume_path`.
pub const MAX_PARENT_LOCATOR_VALUE_UTF16_BYTES: usize = 520;

/// Buffer for a decoded key.
///
/// One UTF-16 code unit (2 source bytes) encodes to at most 3 UTF-8
/// bytes, and a surrogate pair (4 source bytes) to exactly 4, so UTF-8
/// output is never more than 3/2 of the UTF-16 input. A key within
/// `MAX_PARENT_LOCATOR_KEY_UTF16_BYTES` therefore always fits here, and
/// `utf16_to_utf8` can only refuse it for being ill-formed.
pub const MAX_PARENT_LOCATOR_KEY_UTF8: usize = MAX_PARENT_LOCATOR_KEY_UTF16_BYTES * 3 / 2;

/// Buffer for a decoded value. See `MAX_PARENT_LOCATOR_KEY_UTF8` for
/// why 3/2 of the UTF-16 cap is always enough.
pub const MAX_PARENT_LOCATOR_VALUE_UTF8: usize = MAX_PARENT_LOCATOR_VALUE_UTF16_BYTES * 3 / 2;

/// Largest parent locator item `parse_metadata` will stage into memory.
///
/// **A parser resource bound, not a spec limit.** The measured Hyper-V
/// item is 674 bytes in total, and [`build_parent_locator`]'s own
/// tests pin typical output far below that — 196 bytes for a
/// relative path (`"parent.vhdx"`) and 232 for an absolute one
/// (`"/srv/images/parent.vhdx"`). The number this bound has to
/// clear, though, is the emitter's *worst* case, which is larger
/// than Hyper-V's item: 148 bytes of header, entries and the
/// `parent_linkage` pair, plus 38 for the `absolute_win32_path` key,
/// plus a value at the 260-code-unit cap — 148 + 38 + 520 = **706
/// bytes**. That is what clears 4096 with room, and it is the figure
/// a reader needs. A larger item is not parsed at all —
/// rather than truncated, because a truncated item would report
/// in-item offsets as out of bounds and invent defects the image does
/// not have. The refusal is recorded as
/// `VhdxParentLocatorState::NotStaged`, carrying the item's declared
/// offset and length, so that "we declined to stage it" stays
/// distinguishable from "there is no locator item".
pub const MAX_PARENT_LOCATOR_ITEM: usize = 4096;

/// Lowest offset, relative to the metadata region start, at which a
/// metadata item may begin.
///
/// **A spec limit, not a parser resource bound**, which is why it has
/// no "measured Hyper-V value clears it" note: SPEC(VHDX) 2.6.1.2
/// requires the offset be at least 64 KB and that items not overlap,
/// as recorded in `docs/plans/PLAN-differencing-phase-01-pin.md`,
/// "The metadata table entry" — the first 64 KB of the region is
/// reserved for the table. Hyper-V's measured parent locator sits at
/// `0x10028`, immediately above the floor, and so does the one
/// instar's own [`build_parent_locator`] writes.
pub const METADATA_ITEMS_MIN_OFFSET: u32 = 0x10000;

/// Offset, relative to the metadata region start, at which
/// [`build_metadata`]'s own items currently end.
///
/// **Documentation and a test convenience, not the emitter's input.**
/// [`build_parent_locator`] takes the offset as a parameter, and
/// callers in this tree pass [`build_metadata`]'s return value, so a
/// sixth built-in item moves the locator instead of colliding with it.
/// This constant records what that return value is today.
///
/// Not a magic number copied from Hyper-V: it is where instar's own
/// [`build_metadata`] leaves off. That function puts item data at
/// [`METADATA_ITEMS_MIN_OFFSET`] and its five items consume
/// 8 + 8 + 4 + 4 + 16 = 40 bytes, so the next free byte is `0x10028`.
/// Hyper-V's measured `fat-differential.vhdx` puts its parent locator
/// at the same offset for the same reason
/// (`docs/plans/PLAN-differencing-phase-01-pin.md`, "VHDX -- the parent
/// locator metadata item"), which is a coincidence worth knowing about
/// rather than a constraint: SPEC(VHDX) 2.6.1.2 requires only that an
/// item start at or above 64 KB and that items not overlap.
pub const PARENT_LOCATOR_ITEM_OFFSET: u32 = 0x10028;

/// The keys instar cares about, per
/// `PLAN-differencing-phase-01-pin.md`, "VHDX — which keys instar
/// should write".
///
/// `parent_linkage` is required by SPEC(VHDX) 2.6.2.6.3 and is the
/// parent's `DataWriteGuid` rendered as a braced GUID string. At least
/// one of the three path keys must be present.
pub const KEY_PARENT_LINKAGE: &[u8] = b"parent_linkage";
/// Path relative to the differencing child.
pub const KEY_RELATIVE_PATH: &[u8] = b"relative_path";
/// Path via a Windows volume GUID. instar never writes this one.
pub const KEY_VOLUME_PATH: &[u8] = b"volume_path";
/// Absolute Windows path. Note that Hyper-V's own value lacks the
/// `\\?\` prefix SPEC(VHDX) requires, so a parser must not reject a
/// value for missing it (pin, "Which keys Hyper-V writes").
pub const KEY_ABSOLUTE_WIN32_PATH: &[u8] = b"absolute_win32_path";

/// Why a parent locator item that the metadata table *does* list was
/// not staged into memory and parsed.
///
/// Each of these is a property of the surrounding image or of a parser
/// resource bound, not of the locator's contents, which is why they are
/// separate from `VhdxParentLocatorDefect`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VhdxParentLocatorNotStaged {
    /// The declared length is below `PARENT_LOCATOR_HEADER_SIZE`, so
    /// the item cannot even hold its own header.
    ItemTooShort,
    /// The declared length exceeds `MAX_PARENT_LOCATOR_ITEM`, a parser
    /// resource bound rather than a spec limit.
    ItemExceedsParserBound,
    /// The item's file offset is outside the input, or the offset
    /// arithmetic overflowed.
    ItemOutsideInput,
    /// The input device refused a sector read, or the sector size is
    /// unusable.
    ReadFailed,
    /// The item does not lie inside the metadata region the region
    /// table declares: it starts below `METADATA_ITEMS_MIN_OFFSET`, or
    /// it ends past the region's declared length.
    ///
    /// Distinct from `ItemOutsideInput`, which is about the file. An
    /// item can be comfortably inside a large image and still be
    /// nowhere near the metadata region — that is the shape of a
    /// crafted table entry, and reading it would parse unrelated image
    /// bytes as a parent locator.
    ItemOutsideMetadataRegion,
    /// The image does not claim a parent (`HasParent` is clear in the
    /// file parameters item), so the listed item was not read.
    ///
    /// Not `Absent`: the metadata table really does list a parent
    /// locator item, and an image carrying one while denying it has a
    /// parent is anomalous in a way a later phase may want to report.
    /// Recording it here rather than collapsing it keeps decision 4's
    /// distinction intact while costing the sector reads only to
    /// images that will actually use them.
    ImageClaimsNoParent,
}

/// What `parse_metadata` found where a parent locator item would be.
///
/// Three states rather than an `Option`, because "the metadata table
/// lists no parent locator item" and "it lists one that we declined to
/// stage" mean different things to a later phase: the first says the
/// image is structurally broken if it also claims a parent, the second
/// says instar hit its own limit and should say so differently. The
/// declined case keeps the item's declared offset and length, which are
/// the facts that explain the decision (decision 4 of
/// `docs/plans/PLAN-differencing-phase-03-parse.md`, applied at the
/// item level).
//
// The parsed variant is several KB and the others are a handful of
// bytes, which is what `large_enum_variant` objects to. Its remedy —
// boxing — is not available: this crate is `no_std` with no allocator,
// and the large variant is the ordinary case for a differencing image.
#[allow(clippy::large_enum_variant)]
pub enum VhdxParentLocatorState {
    /// The metadata table listed no parent locator item.
    Absent,
    /// The table listed one, and it was not staged. `item_offset` is
    /// relative to the metadata region start, as the table stores it,
    /// and `item_length` is the table's declared length.
    NotStaged {
        /// The metadata table entry's Offset field.
        item_offset: u32,
        /// The metadata table entry's Length field.
        item_length: u32,
        /// Why staging was declined.
        reason: VhdxParentLocatorNotStaged,
    },
    /// The table listed one and it was parsed. Malformed contents are
    /// marked inside the locator, not reported here.
    Parsed(VhdxParentLocator),
}

impl VhdxParentLocatorState {
    /// True only for `Absent`: the metadata table listed no item.
    ///
    /// Deliberately not true for `NotStaged`, which is the distinction
    /// this type exists to make.
    pub fn is_absent(&self) -> bool {
        matches!(self, VhdxParentLocatorState::Absent)
    }

    /// The parsed locator, if there is one.
    pub fn parsed(&self) -> Option<&VhdxParentLocator> {
        match self {
            VhdxParentLocatorState::Parsed(locator) => Some(locator),
            _ => None,
        }
    }
}

/// The first structural problem found in a parent locator item or one
/// of its entries.
///
/// A defect marks the offending entry; it never removes it. Phase 4
/// has to be able to say *why* it is refusing an image, and a dropped
/// entry is indistinguishable from an absent one (decision 4 of
/// `docs/plans/PLAN-differencing-phase-03-parse.md`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VhdxParentLocatorDefect {
    /// `key_value_count` claims more entries than the item's bytes can
    /// hold. Locator-level.
    EntryCountExceedsItem,
    /// `key_value_count` claims more entries than the parser retains.
    /// Locator-level.
    EntryCountExceedsCapacity,
    /// `key_offset + key_length` overflows, or lands outside the item.
    KeyOutOfBounds,
    /// `value_offset + value_length` overflows, or lands outside the item.
    ValueOutOfBounds,
    /// The key is longer than `MAX_PARENT_LOCATOR_KEY_UTF16_BYTES`.
    KeyTooLong,
    /// The value is longer than `MAX_PARENT_LOCATOR_VALUE_UTF16_BYTES`, which
    /// is a parser resource bound rather than a spec limit — a legitimate
    /// Windows extended-length path can exceed it. The raw
    /// `value_offset` and `value_length` are preserved for a caller that
    /// wants to re-read it.
    ValueTooLong,
    /// The key is not well-formed UTF-16LE (odd length, or an unpaired
    /// surrogate). `utf16_to_utf8` refuses rather than substituting
    /// `U+FFFD`, so this is a refusal and not a mangled string.
    KeyUndecodable,
    /// The value is not well-formed UTF-16LE.
    ValueUndecodable,
    /// An earlier entry in the same item already used this key.
    /// SPEC(VHDX) 2.6.2.6.2: "All keys must be unique."
    DuplicateKey,
}

/// One key/value entry of a parent locator item.
///
/// The four raw fields are preserved exactly as they were read, for
/// every entry, whether or not the entry is well formed — that is what
/// lets a later phase report the entry it refused. `defect` records the
/// first structural problem found, in this order: key bounds, key
/// length, key decoding, value bounds, value length, value decoding,
/// duplicate key. The key is resolved before the value is looked at, so
/// that a malformed value still comes back attached to a named key.
#[derive(Copy, Clone)]
pub struct VhdxParentLocatorEntry {
    /// Raw `KeyOffset`, relative to the start of the item.
    pub key_offset: u32,
    /// Raw `ValueOffset`, relative to the start of the item.
    pub value_offset: u32,
    /// Raw `KeyLength`, in bytes of UTF-16.
    pub key_length: u16,
    /// Raw `ValueLength`, in bytes of UTF-16.
    pub value_length: u16,
    /// The first structural problem found with this entry, if any.
    pub defect: Option<VhdxParentLocatorDefect>,
    key: [u8; MAX_PARENT_LOCATOR_KEY_UTF8],
    key_len: usize,
    value: [u8; MAX_PARENT_LOCATOR_VALUE_UTF8],
    value_len: usize,
}

impl VhdxParentLocatorEntry {
    fn new(key_offset: u32, value_offset: u32, key_length: u16, value_length: u16) -> Self {
        VhdxParentLocatorEntry {
            key_offset,
            value_offset,
            key_length,
            value_length,
            defect: None,
            key: [0u8; MAX_PARENT_LOCATOR_KEY_UTF8],
            key_len: 0,
            value: [0u8; MAX_PARENT_LOCATOR_VALUE_UTF8],
            value_len: 0,
        }
    }

    /// The decoded key as UTF-8. Empty when the key could not be
    /// decoded, in which case `defect` says why.
    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    /// The decoded value as UTF-8. Empty when the value could not be
    /// decoded, or when decoding stopped at an earlier defect.
    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

/// A parsed parent locator metadata item.
pub struct VhdxParentLocator {
    /// The `LocatorType` GUID, bytes_le, exactly as stored. Compare it
    /// with `is_vhdx_locator_type()`; a foreign type is reported rather
    /// than refused, because what to do about it is policy.
    pub locator_type: [u8; 16],
    /// The reserved u16 at item offset +16. SPEC(VHDX) says it MUST be
    /// zero; it is preserved rather than checked.
    pub reserved: u16,
    /// `KeyValueCount` as stored, which may exceed the number of
    /// entries actually retained — compare with `entries().len()`.
    pub key_value_count: u16,
    /// The first item-level structural problem found, if any.
    pub defect: Option<VhdxParentLocatorDefect>,
    entries: [VhdxParentLocatorEntry; MAX_PARENT_LOCATOR_ENTRIES],
    entry_count: usize,
}

impl VhdxParentLocator {
    /// The entries retained, in the order the item lists them.
    pub fn entries(&self) -> &[VhdxParentLocatorEntry] {
        &self.entries[..self.entry_count]
    }

    /// True when `locator_type` is the one type SPEC(VHDX) defines.
    pub fn is_vhdx_locator_type(&self) -> bool {
        self.locator_type == VHDX_PARENT_LOCATOR_TYPE_GUID
    }

    /// The first entry whose decoded key matches `key` exactly.
    ///
    /// SPEC(VHDX) 2.6.2.6.2: "The key string is case sensitive", so
    /// this comparison is too. Entries carrying a defect are returned
    /// like any other; the caller inspects `defect`.
    pub fn find(&self, key: &[u8]) -> Option<&VhdxParentLocatorEntry> {
        self.entries().iter().find(|entry| entry.key() == key)
    }

    /// The value of a key, only when the entry carrying it is free of
    /// defects.
    pub fn value_of(&self, key: &[u8]) -> Option<&[u8]> {
        let entry = self.find(key)?;
        if entry.defect.is_some() {
            return None;
        }
        Some(entry.value())
    }

    /// The `parent_linkage` value: the parent's `DataWriteGuid` as a
    /// braced GUID string, e.g. `{f88d4d92-6fcc-408d-9bef-9b7c89f15c89}`.
    ///
    /// Returned exactly as the image spells it. Use `linkage_matches`
    /// to compare it, never `==`: SPEC(VHDX) fixes no case, qemu and
    /// libuuid render GUIDs lowercase and Hyper-V uppercases them.
    pub fn parent_linkage(&self) -> Option<&[u8]> {
        self.value_of(KEY_PARENT_LINKAGE)
    }

    /// The `relative_path` value, the path relative to the child.
    pub fn relative_path(&self) -> Option<&[u8]> {
        self.value_of(KEY_RELATIVE_PATH)
    }

    /// The `volume_path` value, a path via a Windows volume GUID.
    pub fn volume_path(&self) -> Option<&[u8]> {
        self.value_of(KEY_VOLUME_PATH)
    }

    /// The `absolute_win32_path` value.
    pub fn absolute_win32_path(&self) -> Option<&[u8]> {
        self.value_of(KEY_ABSOLUTE_WIN32_PATH)
    }

    /// Which path key a consumer should report or open first, answering
    /// for VHDX the same question `VhdState::preferred_locator` answers
    /// for VHD -- though the two shapes differ enough that this is a much
    /// smaller decision. VHDX carries at most one locator *item*, and
    /// that item is a flat key/value bag rather than VHD's eight
    /// platform-typed slots, so there is no ambiguity to resolve between
    /// competing entries -- only a choice of which of up to three path
    /// keys is most useful when several are present.
    ///
    /// Preference order, highest first:
    ///
    /// 1. `relative_path` -- resolved against the child's own directory,
    ///    so it is the one path here that survives moving both files
    ///    together to a different machine or mount point. It is also
    ///    the closest analog to what qcow2's `backing_file` header field
    ///    usually holds, which is the shape every other format's
    ///    `backing_file` reporting in this tree already reads as.
    /// 2. `absolute_win32_path` -- a real filesystem path, just one
    ///    anchored to a specific drive letter, so it is still useful to
    ///    show even though it will not resolve if the parent moved.
    /// 3. `volume_path` -- a path via a Windows volume GUID
    ///    (`\\?\Volume{...}\...`). Correct only on the exact machine
    ///    that minted the GUID, so it is the least broadly useful of the
    ///    three and is offered only when nothing else is present.
    ///
    /// `parent_linkage` (the parent's `DataWriteGuid`) is deliberately
    /// never returned here: it identifies the parent for verification,
    /// it is not a path to it.
    ///
    /// Returns `None` when no path key is present -- an item that
    /// carries only `parent_linkage`, say, or one whose path entries all
    /// failed to decode (`value_of` already excludes entries marked
    /// `defect`).
    pub fn preferred_path(&self) -> Option<&[u8]> {
        self.relative_path()
            .or_else(|| self.absolute_win32_path())
            .or_else(|| self.volume_path())
    }

    /// Whether this item's `parent_linkage` names `expected`, compared
    /// ASCII case-insensitively.
    ///
    /// Both operands are expected in the braced form SPEC(VHDX)
    /// mandates; the braces are compared like any other character.
    /// Case insensitivity is required because the case of a GUID string
    /// is not fixed by the spec and differs between producers.
    pub fn linkage_matches(&self, expected: &[u8]) -> bool {
        match self.parent_linkage() {
            Some(linkage) => linkage.eq_ignore_ascii_case(expected),
            None => false,
        }
    }

    fn note_defect(&mut self, defect: VhdxParentLocatorDefect) {
        if self.defect.is_none() {
            self.defect = Some(defect);
        }
    }
}

/// Decode one entry's key and value out of `item`, returning the first
/// structural problem found, or `None` when the entry is well formed.
///
/// Every offset here comes from the image, so every one of them is
/// summed with `checked_add` and compared against `item.len()` before
/// it is used to index. A `u32` offset plus a `u16` length cannot
/// actually wrap a 64-bit `usize`, so in practice it is the comparison
/// that rejects a hostile entry — the `checked_add` is there so that
/// the safety of the indexing does not rest on that reasoning.
fn decode_entry_strings(
    item: &[u8],
    entry: &mut VhdxParentLocatorEntry,
) -> Option<VhdxParentLocatorDefect> {
    // The key is resolved first, so that an entry whose *value* is
    // malformed still comes back knowing which key it belongs to —
    // that is the difference between "this image's relative_path is
    // out of bounds" and "something in this image is out of bounds".

    // Key bounds.
    let key_end = match (entry.key_offset as usize).checked_add(entry.key_length as usize) {
        Some(end) if end <= item.len() => end,
        _ => return Some(VhdxParentLocatorDefect::KeyOutOfBounds),
    };

    if entry.key_length as usize > MAX_PARENT_LOCATOR_KEY_UTF16_BYTES {
        return Some(VhdxParentLocatorDefect::KeyTooLong);
    }

    // Safe: key_end <= item.len() was checked above, and key_offset
    // <= key_end because key_end is their sum.
    let key_src = &item[entry.key_offset as usize..key_end];
    match utf16_to_utf8(key_src, false, &mut entry.key) {
        Some(written) => entry.key_len = written,
        None => return Some(VhdxParentLocatorDefect::KeyUndecodable),
    }

    // Value bounds, checked the same way.
    let value_end = match (entry.value_offset as usize).checked_add(entry.value_length as usize) {
        Some(end) if end <= item.len() => end,
        _ => return Some(VhdxParentLocatorDefect::ValueOutOfBounds),
    };

    if entry.value_length as usize > MAX_PARENT_LOCATOR_VALUE_UTF16_BYTES {
        return Some(VhdxParentLocatorDefect::ValueTooLong);
    }

    let value_src = &item[entry.value_offset as usize..value_end];
    match utf16_to_utf8(value_src, false, &mut entry.value) {
        Some(written) => entry.value_len = written,
        None => return Some(VhdxParentLocatorDefect::ValueUndecodable),
    }

    None
}

/// Parse a parent locator metadata item from its bytes.
///
/// `item` is the item's own bytes, starting at the `LocatorType` GUID,
/// because every offset inside the item is relative to that point.
///
/// Takes a byte slice and performs no I/O, so a fuzz target can be
/// pointed straight at it (decision 7 of
/// `docs/plans/PLAN-differencing-phase-03-parse.md`). This is a
/// deliberate departure from the local precedent —
/// `qcow2::read_backing_file` (`src/crates/qcow2/src/lib.rs:683`) does
/// its own call-table I/O — and not a claim that qcow2 agrees; the
/// staging read lives in `parse_metadata` instead.
///
/// Returns `None` only when `item` is too short to hold the parent
/// locator header, in which case there is nothing to preserve.
/// Everything else is parsed and, where malformed, marked.
pub fn parse_parent_locator(item: &[u8]) -> Option<VhdxParentLocator> {
    if item.len() < PARENT_LOCATOR_HEADER_SIZE {
        return None;
    }

    let mut locator_type = [0u8; 16];
    locator_type.copy_from_slice(&item[..16]);

    let mut locator = VhdxParentLocator {
        locator_type,
        reserved: le_u16(item, 16),
        key_value_count: le_u16(item, 18),
        defect: None,
        entries: [VhdxParentLocatorEntry::new(0, 0, 0, 0); MAX_PARENT_LOCATOR_ENTRIES],
        entry_count: 0,
    };

    // How many entries the item's own bytes can hold. The subtraction
    // cannot underflow: the length check above already established
    // item.len() >= PARENT_LOCATOR_HEADER_SIZE.
    let entries_that_fit = (item.len() - PARENT_LOCATOR_HEADER_SIZE) / PARENT_LOCATOR_ENTRY_SIZE;

    let mut usable = locator.key_value_count as usize;
    if usable > entries_that_fit {
        locator.note_defect(VhdxParentLocatorDefect::EntryCountExceedsItem);
        usable = entries_that_fit;
    }
    if usable > MAX_PARENT_LOCATOR_ENTRIES {
        locator.note_defect(VhdxParentLocatorDefect::EntryCountExceedsCapacity);
        usable = MAX_PARENT_LOCATOR_ENTRIES;
    }

    for i in 0..usable {
        // usable <= entries_that_fit bounds this, but the arithmetic is
        // still done with checked operations rather than trusting that
        // reasoning to survive a later edit.
        let entry_start = match i
            .checked_mul(PARENT_LOCATOR_ENTRY_SIZE)
            .and_then(|off| off.checked_add(PARENT_LOCATOR_HEADER_SIZE))
        {
            Some(start) => start,
            None => break,
        };
        match entry_start.checked_add(PARENT_LOCATOR_ENTRY_SIZE) {
            Some(end) if end <= item.len() => {}
            _ => break,
        }

        let mut entry = VhdxParentLocatorEntry::new(
            le_u32(item, entry_start),
            le_u32(item, entry_start + 4),
            le_u16(item, entry_start + 8),
            le_u16(item, entry_start + 10),
        );
        entry.defect = decode_entry_strings(item, &mut entry);

        // SPEC(VHDX) 2.6.2.6.2 requires keys to be unique. A repeat is
        // marked on the later entry; the earlier one keeps its meaning.
        if entry.defect.is_none() && entry.key_len > 0 {
            for previous in locator.entries() {
                if previous.key_len > 0 && previous.key() == entry.key() {
                    entry.defect = Some(VhdxParentLocatorDefect::DuplicateKey);
                    break;
                }
            }
        }

        locator.entries[locator.entry_count] = entry;
        locator.entry_count += 1;
    }

    Some(locator)
}

// ============================================================================
// VHDX metadata parsing
// ============================================================================

/// Parsed VHDX metadata fields.
pub struct VhdxMetadata {
    pub block_size: u32,
    pub virtual_disk_size: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub has_parent: bool,
    /// What was found where a parent locator item would be.
    ///
    /// `Absent` means the metadata table listed no parent locator item
    /// — which, on an image whose `has_parent` is set, is a broken
    /// image. `NotStaged` means the table listed one that this parser
    /// declined to read, and carries the item's declared offset, its
    /// declared length and the reason. `Parsed` means it was read; any
    /// problem with its *contents* is marked inside the locator rather
    /// than reported here.
    ///
    /// Nothing consumes this yet: phase 3 of the differencing plan
    /// parses, and phase 4 decides what to do about what it finds.
    /// `has_parent` above still comes from the file parameters flags
    /// and is unaffected by anything here.
    pub parent_locator: VhdxParentLocatorState,
}

/// Parse VHDX metadata from the metadata region.
///
/// Reads the metadata table and locates items by GUID. Requires
/// sector-based I/O via `call_table`.
///
/// `metadata_length` is the metadata region's declared Length, from
/// the region table entry the caller matched on `METADATA_REGION_GUID`
/// (entry offset `+24`). It is what bounds a parent locator item: the
/// table's own `Offset` field is image-supplied and otherwise
/// unconstrained, so without the region's extent an item can claim to
/// live anywhere in the file. A caller with no region length to hand
/// should pass 0, which refuses every locator item rather than
/// reading an unbounded one.
///
/// # Safety
///
/// `call_table` must be valid.
pub unsafe fn parse_metadata(
    call_table: &CallTable,
    device_idx: u32,
    metadata_offset: u64,
    metadata_length: u32,
    sector_size: usize,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> Option<VhdxMetadata> {
    // Read metadata table header sector
    let table_sector = metadata_offset / sector_size as u64;
    let table_off_in_sector = (metadata_offset % sector_size as u64) as usize;

    if table_sector >= input_capacity {
        return None;
    }

    let mut buffer = [0u8; MAX_SECTOR_SIZE];
    if !(call_table.read_input_sector)(device_idx, table_sector, buffer.as_mut_ptr(), sector_size) {
        return None;
    }
    *bytes_read += sector_size as u64;

    // Verify metadata table signature
    let sig = le_u64(&buffer, table_off_in_sector);
    if sig != METADATA_TABLE_SIGNATURE {
        return None;
    }

    // Entry count at offset 10 (u16 LE)
    let entry_count = le_u16(&buffer, table_off_in_sector + 10);
    if entry_count > MAX_METADATA_TABLE_ENTRIES {
        return None;
    }

    // Parse entries (each 32 bytes, starting at offset 32 in the table)
    // Track item offsets and lengths within the metadata region
    let mut file_params_offset: u32 = 0;
    let mut virtual_size_offset: u32 = 0;
    let mut logical_ss_offset: u32 = 0;
    let mut physical_ss_offset: u32 = 0;
    let mut parent_loc_offset: u32 = 0;
    let mut parent_loc_length: u32 = 0;
    let mut found_file_params = false;
    let mut found_virtual_size = false;
    let mut found_logical_ss = false;
    let mut found_physical_ss = false;
    let mut found_parent_loc = false;

    for i in 0..entry_count.min(32) {
        let entry_start = table_off_in_sector + 32 + (i as usize * METADATA_TABLE_ENTRY_SIZE);
        if entry_start + METADATA_TABLE_ENTRY_SIZE > sector_size {
            // Entry crosses sector boundary; for simplicity, read
            // next sector if needed. Typically the metadata table
            // fits in one sector (32 + 32*entries < 4096 for <127 entries).
            break;
        }

        let mut guid = [0u8; 16];
        guid.copy_from_slice(&buffer[entry_start..entry_start + 16]);
        let item_offset = le_u32(&buffer, entry_start + 16);

        if guid == FILE_PARAMETERS_GUID {
            file_params_offset = item_offset;
            found_file_params = true;
        } else if guid == VIRTUAL_DISK_SIZE_GUID {
            virtual_size_offset = item_offset;
            found_virtual_size = true;
        } else if guid == LOGICAL_SECTOR_SIZE_GUID {
            logical_ss_offset = item_offset;
            found_logical_ss = true;
        } else if guid == PHYSICAL_SECTOR_SIZE_GUID {
            physical_ss_offset = item_offset;
            found_physical_ss = true;
        } else if guid == PARENT_LOCATOR_GUID {
            parent_loc_offset = item_offset;
            // Metadata table entry Length, at entry offset +20
            // (SPEC(VHDX) 2.6.1.2). The other items are fixed-size so
            // the existing reads ignore it; the parent locator is not.
            parent_loc_length = le_u32(&buffer, entry_start + 20);
            found_parent_loc = true;
        }
    }

    // File Parameters and Virtual Disk Size are required
    if !found_file_params || !found_virtual_size {
        return None;
    }
    // Logical and physical sector sizes are required
    if !found_logical_ss || !found_physical_ss {
        return None;
    }

    // Read File Parameters item (8 bytes: u32 block_size + u32 flags)
    let fp_abs_offset = metadata_offset + file_params_offset as u64;
    let fp_sector = fp_abs_offset / sector_size as u64;
    let fp_off_in_sector = (fp_abs_offset % sector_size as u64) as usize;

    if fp_sector >= input_capacity || fp_off_in_sector + 8 > sector_size {
        return None;
    }
    if !(call_table.read_input_sector)(device_idx, fp_sector, buffer.as_mut_ptr(), sector_size) {
        return None;
    }
    *bytes_read += sector_size as u64;

    let block_size = le_u32(&buffer, fp_off_in_sector);
    let fp_flags = le_u32(&buffer, fp_off_in_sector + 4);
    let has_parent = (fp_flags & 2) != 0; // Bit 1: HasParent

    // Validate block size: must be power of 2, 1MB..=256MB
    if block_size == 0
        || (block_size & (block_size - 1)) != 0
        || !(1024 * 1024..=256 * 1024 * 1024).contains(&block_size)
    {
        return None;
    }

    // Read Virtual Disk Size (8 bytes LE u64)
    let vs_abs_offset = metadata_offset + virtual_size_offset as u64;
    let vs_sector = vs_abs_offset / sector_size as u64;
    let vs_off_in_sector = (vs_abs_offset % sector_size as u64) as usize;

    if vs_sector >= input_capacity || vs_off_in_sector + 8 > sector_size {
        return None;
    }
    if !(call_table.read_input_sector)(device_idx, vs_sector, buffer.as_mut_ptr(), sector_size) {
        return None;
    }
    *bytes_read += sector_size as u64;

    let virtual_disk_size = le_u64(&buffer, vs_off_in_sector);

    // Read Logical Sector Size (4 bytes LE u32)
    let ls_abs_offset = metadata_offset + logical_ss_offset as u64;
    let ls_sector = ls_abs_offset / sector_size as u64;
    let ls_off_in_sector = (ls_abs_offset % sector_size as u64) as usize;

    if ls_sector >= input_capacity || ls_off_in_sector + 4 > sector_size {
        return None;
    }
    if !(call_table.read_input_sector)(device_idx, ls_sector, buffer.as_mut_ptr(), sector_size) {
        return None;
    }
    *bytes_read += sector_size as u64;

    let logical_sector_size = le_u32(&buffer, ls_off_in_sector);

    // Read Physical Sector Size (4 bytes LE u32)
    let ps_abs_offset = metadata_offset + physical_ss_offset as u64;
    let ps_sector = ps_abs_offset / sector_size as u64;
    let ps_off_in_sector = (ps_abs_offset % sector_size as u64) as usize;

    if ps_sector >= input_capacity || ps_off_in_sector + 4 > sector_size {
        return None;
    }
    if !(call_table.read_input_sector)(device_idx, ps_sector, buffer.as_mut_ptr(), sector_size) {
        return None;
    }
    *bytes_read += sector_size as u64;

    let physical_sector_size = le_u32(&buffer, ps_off_in_sector);

    // Parent locator item, if the metadata table listed one *and* the
    // image claims a parent. Staged through the same sector reads as
    // every other item above and then handed to `parse_parent_locator`
    // as a plain byte slice, so that the parser itself does no I/O. An
    // item the parser declines to stage comes back as `NotStaged`,
    // never as `Absent`, so that a later phase can tell a resource
    // refusal from a missing item; a locator that is present but
    // malformed comes back marked, not dropped.
    //
    // The `has_parent` gate matters twice. It keeps the extra sector
    // reads — and so `bytes_read` — off every image that will never
    // use them, which is all of them until phase 4. And it means an
    // image that lists a locator item while denying it has a parent is
    // reported as `ImageClaimsNoParent` rather than read: that
    // combination is anomalous, and the anomaly is worth more to a
    // later phase than the item's contents would be.
    //
    // `buffer` is reused as the sector staging buffer here, which is
    // safe because every other item has already been read out of it.
    let parent_locator = match (found_parent_loc, has_parent) {
        (false, _) => VhdxParentLocatorState::Absent,
        (true, false) => VhdxParentLocatorState::NotStaged {
            item_offset: parent_loc_offset,
            item_length: parent_loc_length,
            reason: VhdxParentLocatorNotStaged::ImageClaimsNoParent,
        },
        (true, true) => stage_parent_locator(
            call_table,
            device_idx,
            metadata_offset,
            parent_loc_offset,
            parent_loc_length,
            metadata_length,
            sector_size,
            input_capacity,
            bytes_read,
            &mut buffer,
        ),
    };

    Some(VhdxMetadata {
        block_size,
        virtual_disk_size,
        logical_sector_size,
        physical_sector_size,
        has_parent,
        parent_locator,
    })
}

/// Stage a parent locator metadata item into memory and parse it.
///
/// The item is read through the same `read_input_sector` call table
/// entry every other metadata item uses, one sector at a time, and the
/// assembled bytes are then handed to `parse_parent_locator`. Keeping
/// the I/O here rather than in the parser is what lets the parser be a
/// pure `&[u8] -> Option<_>` function that a fuzz target can drive.
///
/// Never returns `Absent`: the caller only calls this when the metadata
/// table listed an item, so a refusal here comes back as `NotStaged`
/// with the item's declared offset and length and the reason.
///
/// # Safety
///
/// `call_table` must be valid.
unsafe fn stage_parent_locator(
    call_table: &CallTable,
    device_idx: u32,
    metadata_offset: u64,
    item_offset: u32,
    item_length: u32,
    metadata_length: u32,
    sector_size: usize,
    input_capacity: u64,
    bytes_read: &mut u64,
    buffer: &mut [u8; MAX_SECTOR_SIZE],
) -> VhdxParentLocatorState {
    // Every early return goes through here, so no path can lose the
    // fact that an item was listed.
    let declined = |reason| VhdxParentLocatorState::NotStaged {
        item_offset,
        item_length,
        reason,
    };

    if sector_size == 0 || sector_size > MAX_SECTOR_SIZE {
        return declined(VhdxParentLocatorNotStaged::ReadFailed);
    }

    let item_len = match plan_parent_locator_staging(item_offset, item_length, metadata_length) {
        Ok(len) => len,
        Err(reason) => return declined(reason),
    };

    // The item's absolute file offset. Both operands come from the
    // image, so the sum is checked.
    let item_start = match metadata_offset.checked_add(u64::from(item_offset)) {
        Some(start) => start,
        None => return declined(VhdxParentLocatorNotStaged::ItemOutsideInput),
    };

    let mut item = [0u8; MAX_PARENT_LOCATOR_ITEM];
    let mut copied = 0usize;
    while copied < item_len {
        let position = match item_start.checked_add(copied as u64) {
            Some(position) => position,
            None => return declined(VhdxParentLocatorNotStaged::ItemOutsideInput),
        };
        let sector = position / sector_size as u64;
        let offset_in_sector = (position % sector_size as u64) as usize;

        if sector >= input_capacity {
            return declined(VhdxParentLocatorNotStaged::ItemOutsideInput);
        }
        if !(call_table.read_input_sector)(device_idx, sector, buffer.as_mut_ptr(), sector_size) {
            return declined(VhdxParentLocatorNotStaged::ReadFailed);
        }
        *bytes_read += sector_size as u64;

        // offset_in_sector < sector_size by construction, so the
        // subtraction cannot underflow, and `min` bounds the copy by
        // what is left of the item as well as by the sector.
        let available = sector_size - offset_in_sector;
        let remaining = item_len - copied;
        let take = if available < remaining {
            available
        } else {
            remaining
        };

        // Both ranges are within their buffers: offset_in_sector + take
        // <= sector_size <= MAX_SECTOR_SIZE, and copied + take <=
        // item_len <= MAX_PARENT_LOCATOR_ITEM.
        item[copied..copied + take]
            .copy_from_slice(&buffer[offset_in_sector..offset_in_sector + take]);
        copied += take;
    }

    match parse_parent_locator(&item[..item_len]) {
        Some(locator) => VhdxParentLocatorState::Parsed(locator),
        // Unreachable: `plan_parent_locator_staging` already refused
        // anything shorter than the header, which is the only case
        // `parse_parent_locator` rejects. Reported rather than
        // collapsed to `Absent` all the same.
        None => declined(VhdxParentLocatorNotStaged::ItemTooShort),
    }
}

/// Decide whether the item a metadata table entry describes can be
/// staged, given the metadata region it claims to live in.
///
/// Pure, so that the decision the staging path makes can be tested
/// without a call table. Returns the length to stage, or the reason it
/// was refused.
///
/// `item_offset` and `metadata_length` are both relative to the
/// metadata region start, exactly as the region table and the metadata
/// table store them. Bounding the item against the region — rather
/// than only against the file, which the sector loop already does — is
/// what stops a crafted `Offset` of, say, `0x8000_0000` from making
/// the parser read two gigabytes into the image and parse whatever it
/// finds there as a parent locator.
///
/// The checks are ordered so the reported reason is the most
/// structural one that applies. An item too short to hold its own
/// header is malformed wherever it sits; an item outside the region is
/// not ours to read at any length; only an item that is genuinely
/// inside the region gets to be refused for exceeding a bound that is
/// instar's rather than the format's.
fn plan_parent_locator_staging(
    item_offset: u32,
    item_length: u32,
    metadata_length: u32,
) -> Result<usize, VhdxParentLocatorNotStaged> {
    let item_len = item_length as usize;
    if item_len < PARENT_LOCATOR_HEADER_SIZE {
        return Err(VhdxParentLocatorNotStaged::ItemTooShort);
    }
    // SPEC(VHDX) 2.6.1.2: the first 64 KB of the metadata region is
    // the table, so no item may begin below it.
    if item_offset < METADATA_ITEMS_MIN_OFFSET {
        return Err(VhdxParentLocatorNotStaged::ItemOutsideMetadataRegion);
    }
    // Both operands are image-supplied u32s, so the sum is checked
    // rather than reasoned about. u64 would not wrap here, but the
    // safety of the bound should not rest on that argument.
    match item_offset.checked_add(item_length) {
        Some(end) if end <= metadata_length => {}
        _ => return Err(VhdxParentLocatorNotStaged::ItemOutsideMetadataRegion),
    }
    if item_len > MAX_PARENT_LOCATOR_ITEM {
        return Err(VhdxParentLocatorNotStaged::ItemExceedsParserBound);
    }
    Ok(item_len)
}

// ============================================================================
// Allocation scanner (pure helper)
// ============================================================================

/// Count VHDX payload-block entries that are FULLY_PRESENT or
/// PARTIALLY_PRESENT in a BAT byte slice, skipping the interleaved
/// sector-bitmap entries.
///
/// Each entry is a little-endian u64 with the state in the low
/// 3 bits. The BAT layout is repeating groups of `chunk_ratio`
/// payload-block entries followed by one sector-bitmap entry. The
/// helper stops counting once it has visited `total_payload_blocks`
/// payload entries (later entries are unused tail; some images may
/// allocate extra BAT space and zero-fill the unused region).
///
/// `bat_bytes` may have a trailing partial entry — incomplete u64
/// entries at the tail are ignored.
///
/// `chunk_ratio == 0` is invalid; the helper returns 0 in that case
/// rather than dividing by zero.
///
/// Note: `PARTIALLY_PRESENT` is counted as one full block here. That
/// is a slight overcount for adversarial input (the exact answer
/// would sum the sector-bitmap bits), but matches qemu-img-compatible
/// upper-bound semantics that `required` is allowed to honor. instar's
/// writer only emits `FULLY_PRESENT` or `NOT_PRESENT`, so this only
/// affects externally-produced images.
pub fn count_allocated_in_bat(
    bat_bytes: &[u8],
    chunk_ratio: u32,
    total_payload_blocks: u32,
) -> u64 {
    let (count, _) =
        count_allocated_in_bat_chunk(bat_bytes, chunk_ratio, total_payload_blocks, 0, 0);
    count
}

/// Classify one VHDX payload BAT entry into a single `MapExtent`.
///
/// Mirrors `block_lookup`'s payload-state decision tree, augmented
/// with `PAYLOAD_BLOCK_PARTIALLY_PRESENT` treated as `Data` for v1
/// (matches `scan_allocation`'s allocated-overcount posture; the
/// per-sector-bitmap walk that qemu-img map performs for this state
/// is listed as future work in PLAN-map.md).
///
/// State decoding (low 3 bits of `entry`):
/// - `NOT_PRESENT (0)`, `UNDEFINED (1)`, `UNMAPPED (3)`: `Hole`.
/// - `ZERO (2)`: `ZeroAllocated`.
/// - `FULLY_PRESENT (6)`: `Data { file_offset: entry &
///   BAT_ENTRY_OFFSET_MASK }`.
/// - `PARTIALLY_PRESENT (7)`: `Data { file_offset: entry &
///   BAT_ENTRY_OFFSET_MASK }` (v1 simplification).
/// - Anything else (reserved): `Hole` (defensive — only states
///   0..=3, 6, 7 are spec-defined).
///
/// `block_size_bytes` is the extent's length; `virtual_offset` is
/// the virtual address of the block's first byte. The caller is
/// responsible for clamping `length` against virtual_size if the
/// block straddles end-of-image.
pub fn classify_vhdx_bat_entry(
    entry: u64,
    virtual_offset: u64,
    block_size_bytes: u64,
) -> MapExtent {
    let state = entry & BAT_ENTRY_STATE_MASK;
    let ext_state = match state {
        PAYLOAD_BLOCK_NOT_PRESENT | PAYLOAD_BLOCK_UNDEFINED | PAYLOAD_BLOCK_UNMAPPED => {
            MapExtentState::Hole
        }
        PAYLOAD_BLOCK_ZERO => MapExtentState::ZeroAllocated,
        PAYLOAD_BLOCK_FULLY_PRESENT | PAYLOAD_BLOCK_PARTIALLY_PRESENT => MapExtentState::Data {
            file_offset: entry & BAT_ENTRY_OFFSET_MASK,
        },
        _ => MapExtentState::Hole,
    };
    MapExtent {
        start: virtual_offset,
        length: block_size_bytes,
        state: ext_state,
    }
}

/// Incremental variant of `count_allocated_in_bat` for chunked BAT
/// walks across multiple cached sector reads.
///
/// `start_entry_index` is the global BAT entry index (counting both
/// payload and sector-bitmap slots) of the first u64 in `bat_bytes`.
/// `payload_seen` is the number of payload entries already visited
/// before this chunk. Returns `(count_in_this_chunk,
/// payload_seen_after_this_chunk)`.
pub(crate) fn count_allocated_in_bat_chunk(
    bat_bytes: &[u8],
    chunk_ratio: u32,
    total_payload_blocks: u32,
    start_entry_index: u64,
    payload_seen_in: u64,
) -> (u64, u64) {
    if chunk_ratio == 0 {
        return (0, payload_seen_in);
    }
    let group = chunk_ratio as u64 + 1;
    let total_payload = total_payload_blocks as u64;
    let mut count: u64 = 0;
    let mut payload_seen = payload_seen_in;
    for (offset, chunk) in bat_bytes.chunks_exact(8).enumerate() {
        let i = start_entry_index + offset as u64;
        let slot_in_group = i % group;
        if slot_in_group < chunk_ratio as u64 {
            // Payload-block entry.
            if payload_seen >= total_payload {
                // Cap reached; the rest of the BAT is unused tail.
                // Once capped we will never count again.
                break;
            }
            payload_seen += 1;
            let entry = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
            let state = entry & BAT_ENTRY_STATE_MASK;
            if state == PAYLOAD_BLOCK_FULLY_PRESENT || state == PAYLOAD_BLOCK_PARTIALLY_PRESENT {
                count += 1;
            }
        }
        // slot_in_group == chunk_ratio: sector-bitmap entry — skip.
    }
    (count, payload_seen)
}

// ============================================================================
// Block lookup result
// ============================================================================

/// Result of looking up a virtual offset in the VHDX BAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdxBlockLookup {
    /// Block is not present (reads as zero).
    NotPresent,
    /// Block is explicitly zeroed.
    Zero,
    /// Block is allocated at the given host byte offset.
    Present { host_byte_offset: u64 },
}

// ============================================================================
// VHDX state for BAT I/O
// ============================================================================

/// Runtime state for reading VHDX blocks from a device.
pub struct VhdxState {
    pub device_idx: u32,
    pub block_size: u32,
    pub virtual_disk_size: u64,
    pub logical_sector_size: u32,
    pub bat_offset: u64,
    pub total_bat_entries: u32,
    pub chunk_ratio: u32,
    /// `HasParent` from the file parameters metadata item: the image
    /// is a differencing (parent-referencing) VHDX whose real content
    /// lives partly in a parent file.
    ///
    /// `init` deliberately does **not** refuse such an image. Read
    /// entry points test this flag and refuse with a diagnosis of
    /// their own (see `PLAN-differencing-phase-04-read-policy.md`,
    /// decision 3), which keeps VHDX symmetric with VHD -- whose
    /// `VhdState::init` likewise accepts `DISK_TYPE_DIFFERENCING` and
    /// exposes `disk_type` -- and leaves both formats initialising
    /// successfully for the composition work in phases 11-16.
    ///
    /// **A consumer that composes sector data must test this.** An
    /// image with it set reads as zeros wherever the parent holds the
    /// data.
    pub has_parent: bool,
    // Sector cache for BAT reads
    pub bat_cached_sector: u64,
    pub bat_cache_buf: *mut u8,
    // Sector cache for data reads
    pub data_cached_sector: u64,
    pub data_cache_buf: *mut u8,
}

impl VhdxState {
    /// Initialize VHDX state by reading headers, region table, and
    /// metadata.
    ///
    /// Returns `None` if the image is invalid or I/O fails.
    ///
    /// A differencing (parent-referencing) image initialises
    /// successfully and reports itself through
    /// [`VhdxState::has_parent`]; refusing it is the caller's policy
    /// decision, not this crate's. See that field.
    ///
    /// # Safety
    ///
    /// `bat_cache_buf` and `data_cache_buf` must each point to at
    /// least `MAX_SECTOR_SIZE` writable bytes. `call_table` must be
    /// valid.
    pub unsafe fn init(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        bat_cache_buf: *mut u8,
        data_cache_buf: *mut u8,
        bytes_read: &mut u64,
    ) -> Option<Self> {
        let actual_size = input_capacity.checked_mul(sector_size as u64)?;

        // Need at least space for region table 1
        if actual_size < REGION_TABLE1_OFFSET + 65536 {
            return None;
        }

        // --- Read and select active header ---
        let header = Self::read_active_header(
            call_table,
            device_idx,
            sector_size,
            input_capacity,
            bytes_read,
        )?;

        // Check for dirty log (non-zero log_guid)
        let _is_dirty = header.log_guid != [0u8; 16];
        // We continue for read-only operations even if dirty.

        // --- Read region table 1 ---
        let region_table_sector = REGION_TABLE1_OFFSET / sector_size as u64;
        // We need to read the full 64KB region table for CRC validation.
        // Read it in a 4KB buffer (just header + entries) — the CRC
        // covers the full 64KB but we only have MAX_SECTOR_SIZE buffer.
        // For 512-byte sectors, read the first sector to get header +
        // a few entries, then validate.
        //
        // Actually, the CRC covers the full 64KB. We need to read
        // all of it. Since we can't buffer 64KB, we'll do a simpler
        // approach: read the region table header and entries, and
        // skip full CRC validation (we validate entry contents
        // instead). Full CRC validation is done in check operation.

        if region_table_sector >= input_capacity {
            return None;
        }
        let mut rt_buffer = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(
            device_idx,
            region_table_sector,
            rt_buffer.as_mut_ptr(),
            sector_size,
        ) {
            return None;
        }
        *bytes_read += sector_size as u64;

        let rt_off = (REGION_TABLE1_OFFSET % sector_size as u64) as usize;
        let sig = le_u32(&rt_buffer, rt_off);
        if sig != REGION_TABLE_SIGNATURE {
            return None;
        }

        let entry_count = le_u32(&rt_buffer, rt_off + REGION_TABLE_ENTRY_COUNT_OFFSET);
        if entry_count > MAX_REGION_TABLE_ENTRIES {
            return None;
        }

        // Find BAT and Metadata regions
        let mut bat_offset: u64 = 0;
        let mut bat_length: u32 = 0;
        let mut metadata_offset: u64 = 0;
        // The metadata region's declared Length, which bounds where a
        // metadata item may live. Read here rather than assumed,
        // because the region table is where the image states it.
        let mut metadata_length: u32 = 0;
        let mut found_bat = false;
        let mut found_metadata = false;

        for i in 0..entry_count.min(8) {
            let eoff = rt_off + REGION_TABLE_HEADER_SIZE + (i as usize * REGION_TABLE_ENTRY_SIZE);
            if eoff + REGION_TABLE_ENTRY_SIZE > sector_size {
                break;
            }

            let mut guid = [0u8; 16];
            guid.copy_from_slice(&rt_buffer[eoff..eoff + 16]);

            if guid == BAT_REGION_GUID {
                bat_offset = le_u64(&rt_buffer, eoff + 16);
                bat_length = le_u32(&rt_buffer, eoff + 24);
                found_bat = true;
            } else if guid == METADATA_REGION_GUID {
                metadata_offset = le_u64(&rt_buffer, eoff + 16);
                metadata_length = le_u32(&rt_buffer, eoff + 24);
                found_metadata = true;
            }
        }

        if !found_bat || !found_metadata {
            return None;
        }

        // Validate offsets
        if bat_offset >= actual_size || metadata_offset >= actual_size {
            return None;
        }

        // --- Parse metadata ---
        let metadata = parse_metadata(
            call_table,
            device_idx,
            metadata_offset,
            metadata_length,
            sector_size,
            input_capacity,
            bytes_read,
        )?;

        // A differencing image is *not* refused here: `has_parent` is
        // carried out on the returned state instead, and the read entry
        // points refuse it by name (decision 3 of
        // `docs/plans/PLAN-differencing-phase-04-read-policy.md`). A bare
        // `None` here was indistinguishable from a corrupt header, which
        // is what issue #548 complained about, and it left VHDX
        // structurally different from VHD for the composition phases to
        // reconcile later.

        // Validate sector sizes
        if metadata.logical_sector_size != 512 && metadata.logical_sector_size != 4096 {
            return None;
        }

        // Calculate chunk_ratio = (2^23 * logical_sector_size) / block_size
        let chunk_ratio =
            ((1u64 << 23) * metadata.logical_sector_size as u64) / metadata.block_size as u64;
        if chunk_ratio == 0 {
            return None;
        }

        // Calculate total BAT entries (payload blocks + SB blocks)
        let total_blocks = metadata
            .virtual_disk_size
            .div_ceil(metadata.block_size as u64);
        // SB entries: one per chunk_ratio payload blocks
        let sb_entries = if chunk_ratio > 0 {
            total_blocks.div_ceil(chunk_ratio)
        } else {
            0
        };
        let total_bat_entries = total_blocks + sb_entries;

        // Validate BAT counts fit in u32 (a malicious image
        // could claim extreme virtual_disk_size that would
        // overflow u32 on truncation).
        let total_bat_entries_u32 = u32::try_from(total_bat_entries).ok()?;
        let chunk_ratio_u32 = u32::try_from(chunk_ratio).ok()?;

        // Validate BAT region can hold all entries
        let needed_bat_bytes = total_bat_entries * 8;
        if needed_bat_bytes > bat_length as u64 {
            return None;
        }

        Some(VhdxState {
            device_idx,
            block_size: metadata.block_size,
            virtual_disk_size: metadata.virtual_disk_size,
            logical_sector_size: metadata.logical_sector_size,
            bat_offset,
            total_bat_entries: total_bat_entries_u32,
            chunk_ratio: chunk_ratio_u32,
            has_parent: metadata.has_parent,
            bat_cached_sector: u64::MAX,
            bat_cache_buf,
            data_cached_sector: u64::MAX,
            data_cache_buf,
        })
    }

    /// Read both VHDX headers and return the active one.
    ///
    /// The active header is the one with the higher sequence number.
    /// Header 1 wins a tie: the sequence number is what distinguishes
    /// the two headers, so a tie is not a case the format describes,
    /// and preferring header 1 is this implementation's choice rather
    /// than a rule read off the spec. It is pinned by a test because
    /// callers now depend on it. When only one header parses, that one
    /// is active; when neither does, there is no header at all.
    ///
    /// [`VhdxState::init`] uses this, so a caller that needs the active
    /// header's own fields — a differencing child needs its parent's
    /// `DataWriteGuid` — gets the same header `init` used rather than a
    /// second selection rule that can drift from it.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid and `device_idx` must be attached.
    pub unsafe fn read_active_header(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<VhdxHeader> {
        let header1 = Self::read_header(
            call_table,
            device_idx,
            HEADER1_OFFSET,
            sector_size,
            input_capacity,
            bytes_read,
        );
        let header2 = Self::read_header(
            call_table,
            device_idx,
            HEADER2_OFFSET,
            sector_size,
            input_capacity,
            bytes_read,
        );

        match (header1, header2) {
            (Some(h1), Some(h2)) => {
                if h1.sequence_number >= h2.sequence_number {
                    Some(h1)
                } else {
                    Some(h2)
                }
            }
            (Some(h1), None) => Some(h1),
            (None, Some(h2)) => Some(h2),
            (None, None) => None,
        }
    }

    /// Read and parse a VHDX header from a given offset.
    unsafe fn read_header(
        call_table: &CallTable,
        device_idx: u32,
        header_offset: u64,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<VhdxHeader> {
        // We need 4096 bytes for the header. Read enough sectors.
        let start_sector = header_offset / sector_size as u64;
        let sectors_needed = HEADER_SIZE.div_ceil(sector_size);

        // We need a 4KB buffer for CRC validation. Use a stack buffer.
        let mut header_buf = [0u8; HEADER_SIZE];
        let mut sector_buf = [0u8; MAX_SECTOR_SIZE];

        let mut bytes_copied = 0usize;
        for s in 0..sectors_needed {
            let sector_idx = start_sector + s as u64;
            if sector_idx >= input_capacity {
                return None;
            }
            if !(call_table.read_input_sector)(
                device_idx,
                sector_idx,
                sector_buf.as_mut_ptr(),
                sector_size,
            ) {
                return None;
            }
            *bytes_read += sector_size as u64;

            let copy_start = if s == 0 {
                (header_offset % sector_size as u64) as usize
            } else {
                0
            };
            let copy_end = sector_size.min(copy_start + (HEADER_SIZE - bytes_copied));
            let copy_len = copy_end - copy_start;
            header_buf[bytes_copied..bytes_copied + copy_len]
                .copy_from_slice(&sector_buf[copy_start..copy_end]);
            bytes_copied += copy_len;
            if bytes_copied >= HEADER_SIZE {
                break;
            }
        }

        VhdxHeader::parse(&header_buf)
    }

    /// Look up the host location for a given virtual byte offset.
    ///
    /// Reads the BAT entry for the containing block, accounting for
    /// interleaved sector bitmap entries.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. Cache buffers must still be valid.
    pub unsafe fn block_lookup(
        &mut self,
        call_table: &CallTable,
        virtual_offset: u64,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<VhdxBlockLookup> {
        let block_index = virtual_offset / self.block_size as u64;

        let total_payload_blocks = self.virtual_disk_size.div_ceil(self.block_size as u64);
        if block_index >= total_payload_blocks {
            return Some(VhdxBlockLookup::NotPresent);
        }

        // BAT index accounts for interleaved SB entries:
        // every chunk_ratio payload entries, one SB entry follows
        let sb_entries_before = block_index / self.chunk_ratio as u64;
        let bat_index = block_index + sb_entries_before;

        // Read BAT entry (8 bytes LE)
        let bat_byte_offset = self.bat_offset + bat_index * 8;

        let bat_entry = read_u64_le_cached(
            call_table,
            self.device_idx,
            bat_byte_offset,
            sector_size,
            input_capacity,
            &mut self.bat_cached_sector,
            self.bat_cache_buf,
            bytes_read,
        )?;

        let state = bat_entry & BAT_ENTRY_STATE_MASK;
        let file_offset = bat_entry & BAT_ENTRY_OFFSET_MASK;

        match state {
            PAYLOAD_BLOCK_NOT_PRESENT | PAYLOAD_BLOCK_UNDEFINED | PAYLOAD_BLOCK_UNMAPPED => {
                Some(VhdxBlockLookup::NotPresent)
            }
            PAYLOAD_BLOCK_ZERO => Some(VhdxBlockLookup::Zero),
            PAYLOAD_BLOCK_FULLY_PRESENT => {
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::Present {
                    host_byte_offset: file_offset + intra_block_offset,
                })
            }
            // PARTIALLY_PRESENT resolves against the parent, which
            // nothing can compose yet. `init` no longer refuses a
            // differencing image (the read entry points do, on
            // `has_parent`), so this arm is the backstop for a caller
            // that skipped that check: fail rather than invent data.
            _ => None,
        }
    }

    /// Walk the BAT and produce an `AllocationSummary`.
    ///
    /// Reads the BAT region in `MAX_SECTOR_SIZE`-sized cached sector
    /// chunks, threads a running BAT entry index through
    /// [`count_allocated_in_bat_chunk`] so interleaved sector-bitmap
    /// entries are correctly skipped across chunk boundaries, and
    /// multiplies the resulting payload-block count by `block_size`.
    ///
    /// Returns `None` if any I/O call fails. The caller treats `None`
    /// as an unrecoverable format error.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. `bat_cache_buf` must still be valid
    /// and point to at least `MAX_SECTOR_SIZE` writable bytes.
    // NOTE: Single-table sector-walking loop below is duplicated
    // near-verbatim in `vhd::VhdState::scan_allocation`. See the
    // matching NOTE there for the rationale on deferring the
    // shared helper extraction. The qcow2 and vmdk scanners have
    // a two-level walk structure (L1→L2, GD→GT) that doesn't fit
    // the same shape.
    pub unsafe fn scan_allocation(
        &mut self,
        call_table: &CallTable,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<AllocationSummary> {
        let virtual_size = self.virtual_disk_size;
        // Guard against degenerate input: zero virtual size or zero
        // BAT entries means nothing to scan.
        if virtual_size == 0 || self.total_bat_entries == 0 || self.chunk_ratio == 0 {
            return Some(AllocationSummary::clamp(
                virtual_size,
                0,
                // TODO(#286): populate from target_unit_size when this
                // scanner is converted to target-aware accounting.
                0,
            ));
        }

        let total_payload_blocks_u64 = virtual_size.div_ceil(self.block_size as u64);
        // Already validated to fit u32 in init.
        let total_payload_blocks = u32::try_from(total_payload_blocks_u64).ok()?;

        let total_bat_bytes = (self.total_bat_entries as u64).checked_mul(8)?;
        let bat_start_sector = self.bat_offset / sector_size as u64;
        let bat_end_byte = self.bat_offset.checked_add(total_bat_bytes)?;
        // Round up to the next sector boundary so we cover any partial
        // sector at the end of the BAT.
        let bat_end_sector = bat_end_byte.checked_add(sector_size as u64 - 1)? / sector_size as u64;

        let mut allocated_blocks: u64 = 0;
        // Global BAT entry index (counts both payload and sector-bitmap
        // slots) of the next u64 to be visited.
        let mut entry_index: u64 = 0;
        let mut payload_seen: u64 = 0;
        // Bytes of BAT we have logically consumed so far (used to bound
        // the slice handed to the helper so sector padding is ignored).
        let mut bat_bytes_consumed: u64 = 0;

        let mut sector = bat_start_sector;
        while sector < bat_end_sector {
            if sector >= input_capacity {
                return None;
            }
            if !(call_table.read_input_sector)(
                self.device_idx,
                sector,
                self.bat_cache_buf,
                sector_size,
            ) {
                return None;
            }
            // Invalidate the byte-level BAT cache: scan_allocation
            // overwrites bat_cache_buf with its own raw reads, so any
            // future read_u64_le_cached must reload from disk.
            self.bat_cached_sector = u64::MAX;
            *bytes_read += sector_size as u64;

            let sector_byte_start = sector * sector_size as u64;
            // Offset of the first BAT byte within this sector's buffer.
            let buf_start = if sector_byte_start < self.bat_offset {
                (self.bat_offset - sector_byte_start) as usize
            } else {
                0
            };
            let buf_end =
                sector_size.min((bat_end_byte.saturating_sub(sector_byte_start)) as usize);
            if buf_end <= buf_start {
                sector += 1;
                continue;
            }
            let chunk =
                core::slice::from_raw_parts(self.bat_cache_buf.add(buf_start), buf_end - buf_start);

            // Clamp to the meaningful BAT bytes (ignore sector padding
            // at the tail of the final sector).
            let meaningful_len =
                (total_bat_bytes - bat_bytes_consumed).min((buf_end - buf_start) as u64) as usize;
            let meaningful = &chunk[..meaningful_len];

            // Trim to an 8-byte boundary — the global entry rotation
            // requires that each chunk processed by the helper start
            // on a BAT entry boundary. The BAT itself is u64-aligned
            // by construction (offset is 1MB-aligned, length is a
            // multiple of 8), but a sector may end mid-entry.
            let aligned_len = meaningful_len - (meaningful_len % 8);
            let aligned = &meaningful[..aligned_len];

            let (chunk_count, new_payload_seen) = count_allocated_in_bat_chunk(
                aligned,
                self.chunk_ratio,
                total_payload_blocks,
                entry_index,
                payload_seen,
            );
            allocated_blocks += chunk_count;
            // Advance the global entry index by the number of complete
            // entries we processed.
            entry_index += (aligned_len / 8) as u64;
            payload_seen = new_payload_seen;
            bat_bytes_consumed += aligned_len as u64;

            // If we trimmed bytes off this sector (mid-entry tail),
            // we must NOT advance to the next sector — we need to
            // re-read so the trailing bytes are included. But because
            // sector_size is a multiple of 8 in practice (>= 512) and
            // the BAT is u64-aligned, aligned_len == meaningful_len in
            // all real cases. Still, be defensive: if aligned_len <
            // meaningful_len we skip the trailing partial entry, since
            // it cannot be a complete BAT entry by definition.
            sector += 1;
        }

        // `block_size` (default 32 MiB) is often larger than
        // `virtual_size` for small images, so the per-block count can
        // overshoot. AllocationSummary::clamp enforces the invariant
        // allocated_bytes <= virtual_size at construction;
        // `measure_<fmt>` would otherwise reject the summary as
        // InvalidSize. Mirrors the qcow2 out-of-bounds skip
        // established in PLAN-fuzzing-bugs phase 2.
        let allocated_bytes = allocated_blocks.saturating_mul(self.block_size as u64);

        Some(AllocationSummary::clamp(
            virtual_size,
            allocated_bytes,
            // TODO(#286): populate from target_unit_size when this
            // scanner is converted to target-aware accounting.
            0,
        ))
    }

    /// Walk the VHDX BAT (skipping interleaved sector-bitmap
    /// entries) and emit a coalesced `MapExtent` stream covering
    /// `[0, virtual_disk_size)`.
    ///
    /// Mirrors `scan_allocation`'s sector-walking shell and
    /// chunk_ratio-aware BAT-entry rotation, but classifies each
    /// payload entry via [`classify_vhdx_bat_entry`] and pushes the
    /// result through a `MapExtentCoalescer` that persists for the
    /// whole walk. Sector-bitmap entries (every `chunk_ratio`
    /// payload entries) are skipped, as are payload entries past
    /// `total_payload_blocks` (BAT tail padding).
    ///
    /// A trailing `Hole` covers any virtual range past the last
    /// walked block up to `virtual_disk_size` so emitted extents
    /// partition `[0, virtual_disk_size)`.
    ///
    /// PAYLOAD_BLOCK_PARTIALLY_PRESENT is treated as Data (v1
    /// simplification matching scan_allocation; the per-sector-bitmap
    /// walk is future work).
    ///
    /// Returns `Some(())` on success (including early termination);
    /// `None` on I/O failure.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. `bat_cache_buf` must still point
    /// to at least `MAX_SECTOR_SIZE` writable bytes.
    pub unsafe fn map_extents<F: FnMut(MapExtent) -> bool>(
        &mut self,
        call_table: &CallTable,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
        emit: &mut F,
    ) -> Option<()> {
        let virtual_size = self.virtual_disk_size;
        if virtual_size == 0 || self.total_bat_entries == 0 || self.chunk_ratio == 0 {
            return Some(());
        }

        let block_size = self.block_size as u64;
        let total_payload_blocks_u64 = virtual_size.div_ceil(block_size);
        let total_payload_blocks = u32::try_from(total_payload_blocks_u64).ok()?;

        let total_bat_bytes = (self.total_bat_entries as u64).checked_mul(8)?;
        let bat_start_sector = self.bat_offset / sector_size as u64;
        let bat_end_byte = self.bat_offset.checked_add(total_bat_bytes)?;
        let bat_end_sector = bat_end_byte.checked_add(sector_size as u64 - 1)? / sector_size as u64;

        let mut coalescer = MapExtentCoalescer::new(emit);
        let mut next_unwalked: u64 = 0;
        let group = self.chunk_ratio as u64 + 1;
        let mut entry_index: u64 = 0;
        let mut payload_seen: u64 = 0;
        let mut bat_bytes_consumed: u64 = 0;

        let mut sector = bat_start_sector;
        'walk: while sector < bat_end_sector {
            if sector >= input_capacity {
                return None;
            }
            if !(call_table.read_input_sector)(
                self.device_idx,
                sector,
                self.bat_cache_buf,
                sector_size,
            ) {
                return None;
            }
            self.bat_cached_sector = u64::MAX;
            *bytes_read += sector_size as u64;

            let sector_byte_start = sector * sector_size as u64;
            let buf_start = if sector_byte_start < self.bat_offset {
                (self.bat_offset - sector_byte_start) as usize
            } else {
                0
            };
            let buf_end =
                sector_size.min((bat_end_byte.saturating_sub(sector_byte_start)) as usize);
            if buf_end <= buf_start {
                sector += 1;
                continue;
            }
            let chunk =
                core::slice::from_raw_parts(self.bat_cache_buf.add(buf_start), buf_end - buf_start);
            let meaningful_len =
                (total_bat_bytes - bat_bytes_consumed).min((buf_end - buf_start) as u64) as usize;
            let meaningful = &chunk[..meaningful_len];
            let aligned_len = meaningful_len - (meaningful_len % 8);
            let aligned = &meaningful[..aligned_len];

            for (offset, raw) in aligned.chunks_exact(8).enumerate() {
                let i = entry_index + offset as u64;
                let slot_in_group = i % group;
                if slot_in_group >= self.chunk_ratio as u64 {
                    // Sector-bitmap entry — skip.
                    continue;
                }
                // Payload entry.
                if payload_seen >= total_payload_blocks as u64 {
                    // BAT tail past the last payload block; nothing
                    // more to emit.
                    break 'walk;
                }
                let block_virt = payload_seen.saturating_mul(block_size);
                if block_virt >= virtual_size {
                    break 'walk;
                }
                let block_visible = block_size.min(virtual_size - block_virt);
                let entry = u64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]);

                let mut ext = classify_vhdx_bat_entry(entry, block_virt, block_size);
                if ext.length > block_visible {
                    ext.length = block_visible;
                }
                let cont = coalescer.push(ext);
                next_unwalked = block_virt.saturating_add(block_visible);
                payload_seen += 1;
                if !cont {
                    break 'walk;
                }
            }

            entry_index += (aligned_len / 8) as u64;
            bat_bytes_consumed += aligned_len as u64;
            sector += 1;
        }

        if next_unwalked < virtual_size {
            let _ = coalescer.push(MapExtent {
                start: next_unwalked,
                length: virtual_size - next_unwalked,
                state: MapExtentState::Hole,
            });
        }
        let _ = coalescer.finish();
        Some(())
    }
}

// ============================================================================
// Output builders
// ============================================================================

/// Build a VHDX file identifier (64KB region at offset 0).
///
/// `buf` must be at least 64KB and should be pre-zeroed.
/// Writes the "vhdxfile" signature and creator string.
pub fn build_file_identifier(buf: &mut [u8]) {
    // Signature: "vhdxfile" at offset 0 (LE u64)
    write_le_u64(buf, 0, FILE_IDENTIFIER_SIGNATURE);
    // Creator: UTF-16LE "instar" starting at offset 8
    let creator = b"instar";
    for (i, &ch) in creator.iter().enumerate() {
        buf[8 + i * 2] = ch;
        buf[8 + i * 2 + 1] = 0;
    }
}

/// Build a VHDX header (4KB).
///
/// `buf` must be at least 4096 bytes and should be pre-zeroed.
/// CRC-32C checksum is computed and written automatically.
pub fn build_header(buf: &mut [u8], sequence_number: u64) {
    // Signature
    write_le_u32(buf, 0, HEADER_SIGNATURE);
    // Sequence number
    write_le_u64(buf, HEADER_SEQUENCE_NUMBER_OFFSET, sequence_number);
    // file_write_guid (16 bytes at offset 16): set deterministically
    // based on sequence number
    let seq_bytes = sequence_number.to_le_bytes();
    buf[HEADER_FILE_WRITE_GUID_OFFSET..HEADER_FILE_WRITE_GUID_OFFSET + 8]
        .copy_from_slice(&seq_bytes);
    buf[HEADER_FILE_WRITE_GUID_OFFSET + 8] = 0x01;
    // data_write_guid: same pattern
    buf[HEADER_DATA_WRITE_GUID_OFFSET..HEADER_DATA_WRITE_GUID_OFFSET + 8]
        .copy_from_slice(&seq_bytes);
    buf[HEADER_DATA_WRITE_GUID_OFFSET + 8] = 0x02;
    // log_guid: all zeros (clean image)
    // log_version: 0
    // version: 1
    write_le_u16(buf, HEADER_VERSION_OFFSET, VHDX_VERSION);
    // log_length: 1MB (minimum, even if empty)
    write_le_u32(buf, HEADER_LOG_LENGTH_OFFSET, MB_ALIGN as u32);
    // log_offset: 0x100000 (1MB into file)
    write_le_u64(buf, HEADER_LOG_OFFSET_OFFSET, 0x10_0000);

    // Compute CRC-32C
    let checksum = compute_crc32c(&buf[..HEADER_SIZE], HEADER_CHECKSUM_OFFSET);
    write_le_u32(buf, HEADER_CHECKSUM_OFFSET, checksum);
}

/// Build a VHDX region table (64KB).
///
/// `buf` must be at least 64KB and should be pre-zeroed.
/// CRC-32C checksum is computed and written automatically.
pub fn build_region_table(
    buf: &mut [u8],
    bat_offset: u64,
    bat_length: u32,
    metadata_offset: u64,
    metadata_length: u32,
) {
    // Signature
    write_le_u32(buf, 0, REGION_TABLE_SIGNATURE);
    // Entry count: 2 (BAT + Metadata)
    write_le_u32(buf, REGION_TABLE_ENTRY_COUNT_OFFSET, 2);

    // Entry 0: BAT
    let e0 = REGION_TABLE_HEADER_SIZE;
    buf[e0..e0 + 16].copy_from_slice(&BAT_REGION_GUID);
    write_le_u64(buf, e0 + 16, bat_offset);
    write_le_u32(buf, e0 + 24, bat_length);
    write_le_u32(buf, e0 + 28, 1); // required

    // Entry 1: Metadata
    let e1 = e0 + REGION_TABLE_ENTRY_SIZE;
    buf[e1..e1 + 16].copy_from_slice(&METADATA_REGION_GUID);
    write_le_u64(buf, e1 + 16, metadata_offset);
    write_le_u32(buf, e1 + 24, metadata_length);
    write_le_u32(buf, e1 + 28, 1); // required

    // CRC-32C over full 64KB
    let crc_len = if buf.len() >= 65536 { 65536 } else { buf.len() };
    let checksum = compute_crc32c(&buf[..crc_len], REGION_TABLE_CHECKSUM_OFFSET);
    write_le_u32(buf, REGION_TABLE_CHECKSUM_OFFSET, checksum);
}

/// Build VHDX metadata region content.
///
/// Writes the metadata table header and all required metadata items
/// into `buf`. `buf` should be pre-zeroed and at least 64KB.
///
/// Returns the number of bytes written (for the metadata table +
/// items; the full region is 1MB on disk).
pub fn build_metadata(
    buf: &mut [u8],
    block_size: u32,
    virtual_disk_size: u64,
    logical_sector_size: u32,
    physical_sector_size: u32,
    has_parent: bool,
) -> usize {
    // Metadata table header (32 bytes)
    write_le_u64(buf, 0, METADATA_TABLE_SIGNATURE);
    // Reserved u16 at offset 8
    // Entry count at offset 10
    let entry_count: u16 = 5; // FileParams, VirtualSize, LogicalSS, PhysicalSS, VirtualDiskID
    write_le_u16(buf, 10, entry_count);
    // Reserved 20 bytes at offset 12..32

    // Item data starts at offset 0x10000 (64KB into metadata region)
    // This is the standard layout used by QEMU and Hyper-V.
    let items_base: u32 = 0x10000;

    // Entry 0: File Parameters at items_base+0 (8 bytes)
    let e = 32;
    buf[e..e + 16].copy_from_slice(&FILE_PARAMETERS_GUID);
    write_le_u32(buf, e + 16, items_base); // offset
    write_le_u32(buf, e + 20, 8); // length
    write_le_u32(buf, e + 24, 0x04); // flags: IsRequired | IsVirtualDisk

    // Entry 1: Virtual Disk Size at items_base+8 (8 bytes)
    let e = 32 + METADATA_TABLE_ENTRY_SIZE;
    buf[e..e + 16].copy_from_slice(&VIRTUAL_DISK_SIZE_GUID);
    write_le_u32(buf, e + 16, items_base + 8);
    write_le_u32(buf, e + 20, 8);
    write_le_u32(buf, e + 24, 0x04);

    // Entry 2: Logical Sector Size at items_base+16 (4 bytes)
    let e = 32 + 2 * METADATA_TABLE_ENTRY_SIZE;
    buf[e..e + 16].copy_from_slice(&LOGICAL_SECTOR_SIZE_GUID);
    write_le_u32(buf, e + 16, items_base + 16);
    write_le_u32(buf, e + 20, 4);
    write_le_u32(buf, e + 24, 0x04);

    // Entry 3: Physical Sector Size at items_base+20 (4 bytes)
    let e = 32 + 3 * METADATA_TABLE_ENTRY_SIZE;
    buf[e..e + 16].copy_from_slice(&PHYSICAL_SECTOR_SIZE_GUID);
    write_le_u32(buf, e + 16, items_base + 20);
    write_le_u32(buf, e + 20, 4);
    write_le_u32(buf, e + 24, 0x04);

    // Entry 4: Virtual Disk ID at items_base+24 (16 bytes)
    let e = 32 + 4 * METADATA_TABLE_ENTRY_SIZE;
    // Virtual Disk ID GUID: BECA12AB-B2E6-4523-93EF-C309E000C746
    let vdisk_id_guid: [u8; 16] = [
        0xAB, 0x12, 0xCA, 0xBE, 0xE6, 0xB2, 0x23, 0x45, 0x93, 0xEF, 0xC3, 0x09, 0xE0, 0x00, 0xC7,
        0x46,
    ];
    buf[e..e + 16].copy_from_slice(&vdisk_id_guid);
    write_le_u32(buf, e + 16, items_base + 24);
    write_le_u32(buf, e + 20, 16);
    write_le_u32(buf, e + 24, 0x04);

    // Now write the actual item data at items_base within the buffer
    // Note: items_base is relative to the metadata region start.
    // We write items_base bytes into the buffer (which IS the
    // metadata region). If buf is <64KB, we can't place items
    // at offset 0x10000. Caller must provide a large enough buffer
    // or handle this differently.
    //
    // For output, the caller writes the table portion and items
    // portion separately. Return the table size here, and let
    // the caller know the items offset.

    // Actually, for simplicity we write everything into one buffer.
    // The caller should provide a buffer >= items_base + 40.
    if buf.len() >= items_base as usize + 40 {
        let ib = items_base as usize;
        // File Parameters: block_size (u32) + flags (u32)
        write_le_u32(buf, ib, block_size);
        let flags: u32 = if has_parent { 2 } else { 0 };
        write_le_u32(buf, ib + 4, flags);

        // Virtual Disk Size (u64)
        write_le_u64(buf, ib + 8, virtual_disk_size);

        // Logical Sector Size (u32)
        write_le_u32(buf, ib + 16, logical_sector_size);

        // Physical Sector Size (u32)
        write_le_u32(buf, ib + 20, physical_sector_size);

        // Virtual Disk ID (16 bytes) — deterministic from virtual_disk_size
        let size_bytes = virtual_disk_size.to_le_bytes();
        for i in 0..8 {
            buf[ib + 24 + i] = size_bytes[i];
        }
        // Fill remaining 8 bytes with block_size-derived pattern
        let bs_bytes = block_size.to_le_bytes();
        for i in 0..4 {
            buf[ib + 32 + i] = bs_bytes[i];
        }
        buf[ib + 36] = b'V';
        buf[ib + 37] = b'H';
        buf[ib + 38] = b'D';
        buf[ib + 39] = b'X';
    }

    items_base as usize + 40
}

/// What an output builder in this crate refuses to write.
///
/// Shaped after `vhd::VhdBuildError` so the two differencing emitters
/// read the same way, but deliberately not the same list: VHDX has no
/// fixed-size parent name field and no eight-slot locator table, so
/// there is no analogue of `LocatorSlotOutOfRange` or
/// `LocatorLengthExceedsSpace`, and it does have a key namespace, which
/// VHD's platform codes are not.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VhdxBuildError {
    /// The metadata region handed in is shorter than the parent locator
    /// item would need. Checked before anything is written, so a
    /// refusal leaves the region exactly as it was -- see
    /// [`build_parent_locator`] on why that ordering matters.
    BufferTooSmall,
    /// The path's UTF-16 encoding exceeds
    /// [`MAX_PARENT_LOCATOR_VALUE_UTF16_BYTES`], which this crate's own
    /// parser marks [`VhdxParentLocatorDefect::ValueTooLong`]. Counted
    /// during encoding, never estimated from the UTF-8 length: a
    /// character outside the BMP costs two code units, and a BMP
    /// character can cost three UTF-8 bytes.
    PathTooLong,
    /// The path is empty. An empty value would give the entry
    /// `ValueLength == 0`, and a path key naming nothing is not a path
    /// key SPEC(VHDX) 2.6.2.6.3's "at least one entry" is satisfied by.
    PathEmpty,
    /// The path key is neither [`KEY_RELATIVE_PATH`] nor
    /// [`KEY_ABSOLUTE_WIN32_PATH`]. [`KEY_VOLUME_PATH`] is refused like
    /// any other: it needs a Windows volume GUID no Linux producer can
    /// obtain, so instar never writes it.
    UnknownKey,
}

/// Bytes in the braced GUID string `parent_linkage` carries:
/// `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
pub const GUID_STRING_LEN: usize = 38;

/// Write one byte as two lowercase hex digits.
///
/// Does nothing when `dst` cannot hold the pair, so the caller's
/// arithmetic is never load-bearing for memory safety.
fn write_hex_pair(dst: &mut [u8], byte: u8) {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    if dst.len() < 2 {
        return;
    }
    // Both indices are masked to 0..16, so neither can leave HEX.
    dst[0] = HEX[(byte >> 4) as usize];
    dst[1] = HEX[(byte & 0x0f) as usize];
}

/// Render a 16-byte GUID as the lowercase braced string SPEC(VHDX)
/// 2.6.2.6.3 requires of `parent_linkage`.
///
/// VHDX stores GUIDs in "bytes_le" form, so the rendering is
/// mixed-endian: the first three groups are byte-reversed and the last
/// two are not. Getting that wrong produces a string that round-trips
/// through instar perfectly -- [`VhdxParentLocator::linkage_matches`]
/// compares it as an opaque byte string -- and is rejected by Hyper-V,
/// which is why this is one function rather than something each caller
/// spells out. The worked example pinned by measurement
/// (`docs/plans/PLAN-differencing-phase-01-pin.md`, "parent_linkage is
/// the parent's DataWriteGuid") is parent header bytes
/// `92 4d 8d f8 cc 6f 8d 40 9b ef 9b 7c 89 f1 5c 89` rendering as
/// `{f88d4d92-6fcc-408d-9bef-9b7c89f15c89}`.
///
/// The crate is `no_std` with no allocator, so the result is returned
/// by value in a fixed array rather than formatted into a string.
pub fn render_guid_braced(guid: &[u8; 16]) -> [u8; GUID_STRING_LEN] {
    // (source byte, output offset) for each of the sixteen hex pairs.
    // The first three groups read their bytes backwards -- 3,2,1,0 then
    // 5,4 then 7,6 -- and the last two read them in stored order, which
    // is the whole of the bytes_le rule written out where it can be
    // checked against the pin by eye.
    const PAIRS: [(usize, usize); 16] = [
        (3, 1),
        (2, 3),
        (1, 5),
        (0, 7),
        (5, 10),
        (4, 12),
        (7, 15),
        (6, 17),
        (8, 20),
        (9, 22),
        (10, 25),
        (11, 27),
        (12, 29),
        (13, 31),
        (14, 33),
        (15, 35),
    ];

    // Every position a hex pair does not claim is a separator, so
    // starting from dashes leaves 9, 14, 19 and 24 correct for free.
    let mut out = [b'-'; GUID_STRING_LEN];
    out[0] = b'{';
    out[GUID_STRING_LEN - 1] = b'}';
    for &(src, dst) in PAIRS.iter() {
        if let Some(slot) = out.get_mut(dst..dst + 2) {
            write_hex_pair(slot, guid[src]);
        }
    }
    out
}

/// Expand an ASCII string into UTF-16 little endian, returning the
/// bytes written.
///
/// `shared::utf8_to_utf16` encodes the caller-supplied path, which may
/// hold any character. The two path keys, `parent_linkage` and the
/// rendered GUID are ASCII by construction -- they are this crate's own
/// constants and its own output -- so expanding them here avoids
/// turning a `&[u8]` constant back into a `&str` purely to hand it to
/// an encoder that would take the same branch for every byte. A byte
/// above `0x7F` cannot reach this function, and would be expanded as a
/// Latin-1 code unit if one did.
///
/// Stops at whatever `dst` holds, so the caller's arithmetic is never
/// load-bearing for memory safety.
fn write_ascii_utf16le(dst: &mut [u8], src: &[u8]) -> usize {
    let mut written = 0usize;
    for &byte in src.iter() {
        match dst.get_mut(written..written + 2) {
            Some(unit) => {
                unit[0] = byte;
                unit[1] = 0;
            }
            None => break,
        }
        written += 2;
    }
    written
}

/// Append a parent locator metadata item to an already-built metadata
/// region, making the image a differencing child.
///
/// `metadata` is the metadata region [`build_metadata`] has already
/// written, starting at the metadata table signature.
/// `parent_data_write_guid` is the parent's active-header
/// `DataWriteGuid`, which SPEC(VHDX) 2.6.2.6.3 makes the value of
/// `parent_linkage`; it is rendered here by [`render_guid_braced`]
/// rather than by the caller, because the mixed-endian rendering is a
/// property of the format and a second implementation of it is a second
/// chance to get it wrong. `path_key` must be [`KEY_RELATIVE_PATH`] or
/// [`KEY_ABSOLUTE_WIN32_PATH`]; anything else, [`KEY_VOLUME_PATH`]
/// included, is [`VhdxBuildError::UnknownKey`].
///
/// This is a *second* function rather than arguments on
/// [`build_metadata`], for the same reason
/// `vhd::build_dynamic_header_parent` is separate from
/// `vhd::build_dynamic_header`: a non-differencing image must keep
/// taking exactly the path it takes today, byte for byte, and a diff
/// that touches [`build_metadata`] cannot show that.
///
/// # What it writes
///
/// The item lands at `item_offset` -- pass [`build_metadata`]'s return
/// value -- and is registered
/// by table entry index 5, at
/// `METADATA_TABLE_HEADER_SIZE + 5 * METADATA_TABLE_ENTRY_SIZE`, with
/// `Offset` the item offset, `Length` the item's exact byte length,
/// flags `0x00000004` (IsRequired only, measured from Hyper-V) and
/// `Reserved2` zero. The table's entry count is rewritten from five to
/// six. The item itself carries two entries -- `parent_linkage` and the
/// one path key -- with the keys laid out before the values and no
/// padding, so the item is exactly `148 + key + value` bytes.
///
/// Strings are UTF-16 **little** endian with **no** terminator
/// (SPEC(VHDX) 2.6.2.6.2). That is the opposite endianness to VHD's
/// parent unicode name field, which is UTF-16 big endian; the two
/// formats' emitters are separate functions in separate crates partly
/// so that the flag cannot be carried across by copy and paste.
/// `path_value` is encoded exactly as given: a `str` may legally hold
/// an embedded NUL, and SPEC(VHDX) 2.6.2.6.2 forbids one in a locator
/// string, but no path a caller can obtain from a filesystem API
/// contains one, so it is not refused here.
///
/// # Ordering, and what a refusal leaves behind
///
/// Every refusal happens before a byte is written, and the item body is
/// written before the table entry, which is written before the entry
/// count. A metadata region can therefore never be left claiming six
/// items with five present -- a half-applied write is a region that
/// still describes exactly the five items [`build_metadata`] wrote.
///
/// Returns the item's length in bytes.
pub fn build_parent_locator(
    metadata: &mut [u8],
    item_offset: u32,
    parent_data_write_guid: &[u8; 16],
    path_key: &[u8],
    path_value: &str,
) -> Result<usize, VhdxBuildError> {
    if path_key != KEY_RELATIVE_PATH && path_key != KEY_ABSOLUTE_WIN32_PATH {
        return Err(VhdxBuildError::UnknownKey);
    }
    if path_value.is_empty() {
        return Err(VhdxBuildError::PathEmpty);
    }

    // Encode the path into scratch first, and let the scratch's size be
    // what enforces the length limit. Counting code units separately
    // would be a second implementation of the same rule, and the one
    // this crate's parser applies is a byte count against
    // MAX_PARENT_LOCATOR_VALUE_UTF16_BYTES -- so the cap is enforced by
    // handing the encoder exactly that many bytes. A character outside
    // the BMP costs two code units here because it costs two there.
    let mut value_utf16 = [0u8; MAX_PARENT_LOCATOR_VALUE_UTF16_BYTES];
    let value_len =
        utf8_to_utf16(path_value, false, &mut value_utf16).ok_or(VhdxBuildError::PathTooLong)?;

    let linkage = render_guid_braced(parent_data_write_guid);

    // Item-relative offsets, in the order the item is laid out:
    // header, both entries, both keys, both values. Hyper-V interleaves
    // its keys and values instead; SPEC(VHDX) 2.6.2.6.2 fixes no
    // ordering ("there is no ordering to the entries") and grouping
    // them makes the item's length a sum of five terms rather than of
    // ten. Every term is bounded -- the keys by their own constants,
    // the value by the scratch above -- so none of this arithmetic can
    // overflow.
    let linkage_key_len = KEY_PARENT_LINKAGE.len() * 2;
    let linkage_value_len = GUID_STRING_LEN * 2;
    let path_key_len = path_key.len() * 2;

    let entry_parent_linkage = PARENT_LOCATOR_HEADER_SIZE;
    let entry_path = entry_parent_linkage + PARENT_LOCATOR_ENTRY_SIZE;
    let linkage_key_off = entry_path + PARENT_LOCATOR_ENTRY_SIZE;
    let path_key_off = linkage_key_off + linkage_key_len;
    let linkage_value_off = path_key_off + path_key_len;
    let path_value_off = linkage_value_off + linkage_value_len;
    let item_len = path_value_off + value_len;

    // Where this entry goes is read from the region rather than
    // assumed. The table says how many items it already describes, and
    // the caller says where item data ends -- `build_metadata` returns
    // exactly that. Hardcoding "entry five, and the item at 0x10028"
    // would encode "build_metadata wrote five items totalling 40
    // bytes" in three places with no assertion, and a sixth built-in
    // item would then be silently overwritten. That failure would not
    // announce itself: an image whose metadata items overlap is read
    // back as sound by this crate's own parser.
    if metadata.len() < METADATA_TABLE_HEADER_SIZE {
        return Err(VhdxBuildError::BufferTooSmall);
    }
    let entry_count = le_u16(metadata, METADATA_TABLE_ENTRY_COUNT_OFFSET) as usize;
    let table_entry_off = METADATA_TABLE_HEADER_SIZE + entry_count * METADATA_TABLE_ENTRY_SIZE;

    // SPEC(VHDX) 2.6.1.2 puts item data at least 64 KB into the region;
    // callers in this tree get the offset from `build_metadata`, which
    // satisfies it by construction.
    debug_assert!(item_offset >= METADATA_ITEMS_MIN_OFFSET);

    let item_start = item_offset as usize;
    let item_end = item_start + item_len;

    // Every bound is checked before anything is written: the item must
    // fit, the new table entry must fit, and the growing table must not
    // have reached the item data it describes.
    if metadata.len() < item_end
        || metadata.len() < table_entry_off + METADATA_TABLE_ENTRY_SIZE
        || table_entry_off + METADATA_TABLE_ENTRY_SIZE > item_start
    {
        return Err(VhdxBuildError::BufferTooSmall);
    }

    // The item body. Every index below is inside item_len, which is
    // item.len() by construction.
    let item = &mut metadata[item_start..item_end];
    item[..16].copy_from_slice(&VHDX_PARENT_LOCATOR_TYPE_GUID);
    write_le_u16(item, 16, 0);
    write_le_u16(item, 18, 2);

    write_le_u32(item, entry_parent_linkage, linkage_key_off as u32);
    write_le_u32(item, entry_parent_linkage + 4, linkage_value_off as u32);
    write_le_u16(item, entry_parent_linkage + 8, linkage_key_len as u16);
    write_le_u16(item, entry_parent_linkage + 10, linkage_value_len as u16);

    write_le_u32(item, entry_path, path_key_off as u32);
    write_le_u32(item, entry_path + 4, path_value_off as u32);
    write_le_u16(item, entry_path + 8, path_key_len as u16);
    write_le_u16(item, entry_path + 10, value_len as u16);

    // `write_ascii_utf16le` stops short if its destination is too
    // small, so what it wrote is checked against what the entries
    // above declare. The slices are exactly sized by construction and
    // the two cannot disagree today; if they ever did, the item would
    // declare more bytes than exist and a reader would take whatever
    // followed -- silent truncation rather than a refusal.
    // The calls are bound to locals first: `debug_assert_eq!` does not
    // evaluate its arguments in a release build, so asserting on the
    // call itself would compile the writes away.
    let wrote_linkage_key =
        write_ascii_utf16le(&mut item[linkage_key_off..path_key_off], KEY_PARENT_LINKAGE);
    let wrote_path_key = write_ascii_utf16le(&mut item[path_key_off..linkage_value_off], path_key);
    let wrote_linkage_value =
        write_ascii_utf16le(&mut item[linkage_value_off..path_value_off], &linkage);
    debug_assert_eq!(wrote_linkage_key, linkage_key_len);
    debug_assert_eq!(wrote_path_key, path_key_len);
    debug_assert_eq!(wrote_linkage_value, linkage_value_len);
    item[path_value_off..].copy_from_slice(&value_utf16[..value_len]);

    // Then the table entry, and only then the count: see "Ordering"
    // above.
    let e = table_entry_off;
    metadata[e..e + 16].copy_from_slice(&PARENT_LOCATOR_GUID);
    write_le_u32(metadata, e + 16, item_offset);
    write_le_u32(metadata, e + 20, item_len as u32);
    // Flags: bit 2, IsRequired, and nothing else -- measured from
    // Hyper-V's own entry, whose raw bytes are in the pin. IsUser (bit
    // 0) and IsVirtualDisk (bit 1) stay clear: a parent locator is
    // neither user metadata nor a property of the virtual disk the
    // image presents.
    write_le_u32(metadata, e + 24, 0x0000_0004);
    write_le_u32(metadata, e + 28, 0);
    write_le_u16(
        metadata,
        METADATA_TABLE_ENTRY_COUNT_OFFSET,
        (entry_count + 1) as u16,
    );

    Ok(item_len)
}

/// Construct a BAT entry from state and file offset.
///
/// `file_offset` must be MB-aligned (low 20 bits zero).
#[inline]
pub fn build_bat_entry(state: u64, file_offset: u64) -> u64 {
    (file_offset & BAT_ENTRY_OFFSET_MASK) | (state & BAT_ENTRY_STATE_MASK)
}

/// Calculate the total number of BAT entries needed for a given
/// virtual size and block size.
///
/// Returns `(total_bat_entries, chunk_ratio, total_payload_blocks)`.
/// Returns `None` if the layout overflows u32 (e.g. extreme
/// virtual_disk_size from a malicious image).
pub fn calculate_bat_layout(
    virtual_disk_size: u64,
    block_size: u32,
    logical_sector_size: u32,
) -> Option<(u32, u32, u32)> {
    let total_blocks_u64 = virtual_disk_size.div_ceil(block_size as u64);
    let chunk_ratio_u64 = (1u64 << 23) * logical_sector_size as u64 / block_size as u64;
    let total_blocks = u32::try_from(total_blocks_u64).ok()?;
    let chunk_ratio = u32::try_from(chunk_ratio_u64).ok()?;
    let sb_entries = if chunk_ratio > 0 {
        total_blocks.div_ceil(chunk_ratio)
    } else {
        0
    };
    let total_bat_entries = total_blocks.checked_add(sb_entries)?;
    Some((total_bat_entries, chunk_ratio, total_blocks))
}

// ============================================================================
// Tests
// ============================================================================

// The parent locator staging tests need a lock around the global
// fixture their `extern "C"` reader serves from. Same reason, and the
// same shape, as `crates/qcow2`.
#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // CRC-32C tests
    // ====================================================================

    #[test]
    fn crc32c_empty() {
        let data = [];
        assert_eq!(compute_crc32c(&data, usize::MAX), 0x0000_0000);
    }

    #[test]
    fn crc32c_check_value() {
        // Standard CRC-32C check value for "123456789"
        let data = b"123456789";
        assert_eq!(compute_crc32c(data, usize::MAX), 0xE306_9283);
    }

    #[test]
    fn crc32c_zeros_512() {
        let data = [0u8; 512];
        let crc = compute_crc32c(&data, usize::MAX);
        // All-zeros should produce a consistent non-zero CRC
        assert_ne!(crc, 0);
    }

    #[test]
    fn crc32c_skips_checksum_field() {
        let mut data = [0u8; 16];
        data[0] = 0x42;
        // Place some non-zero at the checksum offset
        data[4] = 0xFF;
        data[5] = 0xFF;
        data[6] = 0xFF;
        data[7] = 0xFF;
        // CRC should treat bytes 4..8 as zero
        let crc_with_field = compute_crc32c(&data, 4);

        data[4] = 0;
        data[5] = 0;
        data[6] = 0;
        data[7] = 0;
        let crc_zeroed = compute_crc32c(&data, usize::MAX);

        assert_eq!(crc_with_field, crc_zeroed);
    }

    // ====================================================================
    // VhdxHeader tests
    // ====================================================================

    fn make_valid_header(seq: u64) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        write_le_u32(&mut buf, 0, HEADER_SIGNATURE);
        write_le_u64(&mut buf, HEADER_SEQUENCE_NUMBER_OFFSET, seq);
        write_le_u16(&mut buf, HEADER_VERSION_OFFSET, VHDX_VERSION);
        write_le_u32(&mut buf, HEADER_LOG_LENGTH_OFFSET, MB_ALIGN as u32);
        write_le_u64(&mut buf, HEADER_LOG_OFFSET_OFFSET, 0x10_0000);
        let crc = compute_crc32c(&buf, HEADER_CHECKSUM_OFFSET);
        write_le_u32(&mut buf, HEADER_CHECKSUM_OFFSET, crc);
        buf
    }

    #[test]
    fn header_parse_valid() {
        let buf = make_valid_header(42);
        let hdr = VhdxHeader::parse(&buf).unwrap();
        assert_eq!(hdr.signature, HEADER_SIGNATURE);
        assert_eq!(hdr.sequence_number, 42);
        assert_eq!(hdr.log_guid, [0u8; 16]);
    }

    #[test]
    fn header_parse_bad_signature() {
        let mut buf = make_valid_header(1);
        buf[0] = 0; // Corrupt signature
        assert!(VhdxHeader::parse(&buf).is_none());
    }

    #[test]
    fn header_parse_bad_crc() {
        let mut buf = make_valid_header(1);
        buf[100] ^= 0xFF; // Corrupt data
        assert!(VhdxHeader::parse(&buf).is_none());
    }

    #[test]
    fn header_parse_short_buffer() {
        assert!(VhdxHeader::parse(&[0u8; 100]).is_none());
    }

    #[test]
    fn header_select_higher_sequence() {
        let h1 = make_valid_header(10);
        let h2 = make_valid_header(20);
        let hdr1 = VhdxHeader::parse(&h1).unwrap();
        let hdr2 = VhdxHeader::parse(&h2).unwrap();
        assert!(hdr2.sequence_number > hdr1.sequence_number);
    }

    // ====================================================================
    // BAT entry tests
    // ====================================================================

    #[test]
    fn bat_entry_encode_decode() {
        let offset: u64 = 4 * MB_ALIGN; // 4MB
        let entry = build_bat_entry(PAYLOAD_BLOCK_FULLY_PRESENT, offset);

        let state = entry & BAT_ENTRY_STATE_MASK;
        let decoded_offset = entry & BAT_ENTRY_OFFSET_MASK;

        assert_eq!(state, PAYLOAD_BLOCK_FULLY_PRESENT);
        assert_eq!(decoded_offset, offset);
    }

    #[test]
    fn bat_entry_not_present() {
        let entry = build_bat_entry(PAYLOAD_BLOCK_NOT_PRESENT, 0);
        assert_eq!(entry, 0);
    }

    #[test]
    fn bat_entry_zero_state() {
        let entry = build_bat_entry(PAYLOAD_BLOCK_ZERO, 0);
        assert_eq!(entry & BAT_ENTRY_STATE_MASK, PAYLOAD_BLOCK_ZERO);
        assert_eq!(entry & BAT_ENTRY_OFFSET_MASK, 0);
    }

    // ====================================================================
    // BAT layout calculation tests
    // ====================================================================

    #[test]
    fn bat_layout_1gb_32mb_blocks() {
        let (total, chunk_ratio, payload_blocks) =
            calculate_bat_layout(1024 * 1024 * 1024, DEFAULT_BLOCK_SIZE, 512).unwrap();
        assert_eq!(payload_blocks, 32); // 1GB / 32MB
        assert_eq!(chunk_ratio, 128); // (2^23 * 512) / 32MB
                                      // SB entries = ceil(32/128) = 1
        assert_eq!(total, 33);
    }

    #[test]
    fn bat_layout_4gb_32mb_blocks() {
        let (total, chunk_ratio, payload_blocks) =
            calculate_bat_layout(4u64 * 1024 * 1024 * 1024, DEFAULT_BLOCK_SIZE, 512).unwrap();
        assert_eq!(payload_blocks, 128);
        assert_eq!(chunk_ratio, 128);
        // 128 payload + ceil(128/128)=1 SB
        assert_eq!(total, 129);
    }

    #[test]
    fn bat_layout_256mb_1mb_blocks() {
        let (total, chunk_ratio, payload_blocks) =
            calculate_bat_layout(256 * 1024 * 1024, 1024 * 1024, 512).unwrap();
        assert_eq!(payload_blocks, 256);
        assert_eq!(chunk_ratio, 4096); // (2^23 * 512) / 1MB
                                       // SB entries = ceil(256/4096) = 1
        assert_eq!(total, 257);
    }

    #[test]
    fn bat_layout_overflow_returns_none() {
        // Extreme virtual_disk_size that would overflow u32
        assert!(calculate_bat_layout(u64::MAX, 1024 * 1024, 512).is_none());
        // Large enough to overflow u32 total_blocks with 1MB blocks:
        // 1 << 53 bytes / 1MB = 1 << 33 blocks > u32::MAX
        assert!(calculate_bat_layout(1u64 << 53, 1024 * 1024, 512).is_none());
    }

    #[test]
    fn bat_layout_large_but_valid() {
        // 1 PiB (1 << 50) with 1MB blocks = 1 << 30 blocks,
        // fits in u32 — should succeed
        assert!(calculate_bat_layout(1u64 << 50, 1024 * 1024, 512).is_some());
    }

    // ====================================================================
    // Output builder tests
    // ====================================================================

    #[test]
    fn file_identifier_signature() {
        let mut buf = [0u8; 512];
        build_file_identifier(&mut buf);
        let sig = le_u64(&buf, 0);
        assert_eq!(sig, FILE_IDENTIFIER_SIGNATURE);
        // Check creator "instar" in UTF-16LE (6 chars, each followed
        // by a zero byte)
        let creator = b"instar";
        for (i, &ch) in creator.iter().enumerate() {
            assert_eq!(buf[8 + i * 2], ch);
            assert_eq!(buf[8 + i * 2 + 1], 0);
        }
    }

    #[test]
    fn header_builder_crc_valid() {
        let mut buf = [0u8; HEADER_SIZE];
        build_header(&mut buf, 1);
        // The built header should parse successfully (CRC validates)
        let hdr = VhdxHeader::parse(&buf).unwrap();
        assert_eq!(hdr.sequence_number, 1);
    }

    #[test]
    fn header_builder_data_write_guid_matches_written_bytes() {
        let mut buf = [0u8; HEADER_SIZE];
        build_header(&mut buf, 7);
        let hdr = VhdxHeader::parse(&buf).unwrap();
        let mut expected = [0u8; 16];
        expected.copy_from_slice(
            &buf[HEADER_DATA_WRITE_GUID_OFFSET..HEADER_DATA_WRITE_GUID_OFFSET + 16],
        );
        assert_eq!(hdr.data_write_guid, expected);
    }

    #[test]
    fn region_table_builder() {
        let mut buf = [0u8; 65536];
        build_region_table(&mut buf, 0x200000, 0x10000, 0x300000, 0x100000);

        // Should parse back
        let sig = le_u32(&buf, 0);
        assert_eq!(sig, REGION_TABLE_SIGNATURE);

        let entry_count = le_u32(&buf, REGION_TABLE_ENTRY_COUNT_OFFSET);
        assert_eq!(entry_count, 2);

        // Verify CRC
        let stored_crc = le_u32(&buf, REGION_TABLE_CHECKSUM_OFFSET);
        let computed_crc = compute_crc32c(&buf, REGION_TABLE_CHECKSUM_OFFSET);
        assert_eq!(stored_crc, computed_crc);
    }

    // ====================================================================
    // count_allocated_in_bat tests (phase 2d)
    // ====================================================================

    /// Build an 8-byte LE BAT entry with the given state and a deterministic
    /// nonzero offset (so we can detect accidental state/offset confusion).
    fn make_bat_entry(state: u64, offset_mb: u64) -> [u8; 8] {
        let entry = (state & BAT_ENTRY_STATE_MASK) | ((offset_mb << 20) & BAT_ENTRY_OFFSET_MASK);
        entry.to_le_bytes()
    }

    #[test]
    fn count_allocated_in_bat_empty() {
        assert_eq!(count_allocated_in_bat(&[], 128, 0), 0);
    }

    #[test]
    fn count_allocated_in_bat_single_fully_present() {
        let buf = make_bat_entry(PAYLOAD_BLOCK_FULLY_PRESENT, 4);
        assert_eq!(count_allocated_in_bat(&buf, 128, 1), 1);
    }

    #[test]
    fn count_allocated_in_bat_total_zero_caps_count() {
        // One fully-present entry but the caller says zero payload blocks;
        // the cap clips the count to zero.
        let buf = make_bat_entry(PAYLOAD_BLOCK_FULLY_PRESENT, 4);
        assert_eq!(count_allocated_in_bat(&buf, 128, 0), 0);
    }

    /// Write an 8-byte LE BAT entry into `buf` at position `i * 8`.
    fn put_bat_entry(buf: &mut [u8], i: usize, state: u64, offset_mb: u64) {
        let bytes = make_bat_entry(state, offset_mb);
        buf[i * 8..i * 8 + 8].copy_from_slice(&bytes);
    }

    #[test]
    fn count_allocated_in_bat_group_with_bitmap_skipped() {
        // chunk_ratio=8: layout is 8 payload entries then 1 bitmap.
        // All 8 payload entries are FULLY_PRESENT. The bitmap entry
        // (deliberately set to FULLY_PRESENT to verify it is skipped
        // by position, not by state) must not be counted.
        let mut buf = [0u8; 9 * 8];
        for i in 0..8 {
            put_bat_entry(&mut buf, i, PAYLOAD_BLOCK_FULLY_PRESENT, (i + 1) as u64);
        }
        put_bat_entry(&mut buf, 8, PAYLOAD_BLOCK_FULLY_PRESENT, 99);
        assert_eq!(count_allocated_in_bat(&buf, 8, 8), 8);
    }

    #[test]
    fn count_allocated_in_bat_mixed_states() {
        // chunk_ratio=8: 3 FULLY_PRESENT + 1 PARTIALLY_PRESENT + 2 ZERO
        // + 1 NOT_PRESENT + 1 UNDEFINED, then a bitmap entry.
        let mut buf = [0u8; 9 * 8];
        put_bat_entry(&mut buf, 0, PAYLOAD_BLOCK_FULLY_PRESENT, 1);
        put_bat_entry(&mut buf, 1, PAYLOAD_BLOCK_FULLY_PRESENT, 2);
        put_bat_entry(&mut buf, 2, PAYLOAD_BLOCK_FULLY_PRESENT, 3);
        put_bat_entry(&mut buf, 3, PAYLOAD_BLOCK_PARTIALLY_PRESENT, 4);
        put_bat_entry(&mut buf, 4, PAYLOAD_BLOCK_ZERO, 0);
        put_bat_entry(&mut buf, 5, PAYLOAD_BLOCK_ZERO, 0);
        put_bat_entry(&mut buf, 6, PAYLOAD_BLOCK_NOT_PRESENT, 0);
        put_bat_entry(&mut buf, 7, PAYLOAD_BLOCK_UNDEFINED, 0);
        // Bitmap entry slot (the 9th, slot_in_group == chunk_ratio).
        put_bat_entry(&mut buf, 8, PAYLOAD_BLOCK_FULLY_PRESENT, 99);
        // 3 FULLY_PRESENT + 1 PARTIALLY_PRESENT = 4
        assert_eq!(count_allocated_in_bat(&buf, 8, 8), 4);
    }

    #[test]
    fn count_allocated_in_bat_chunk_ratio_zero_returns_zero() {
        let buf = make_bat_entry(PAYLOAD_BLOCK_FULLY_PRESENT, 1);
        // Bogus input — must not panic, must not divide by zero.
        assert_eq!(count_allocated_in_bat(&buf, 0, 1), 0);
        assert_eq!(count_allocated_in_bat(&[], 0, 0), 0);
    }

    #[test]
    fn count_allocated_in_bat_total_payload_blocks_clips() {
        // 10 payload entries all FULLY_PRESENT, chunk_ratio large enough
        // that no bitmap entry is interleaved within the first 10 slots.
        // Pass total_payload_blocks=5 → expect exactly 5.
        let mut buf = [0u8; 10 * 8];
        for i in 0..10 {
            put_bat_entry(&mut buf, i, PAYLOAD_BLOCK_FULLY_PRESENT, (i + 1) as u64);
        }
        assert_eq!(count_allocated_in_bat(&buf, 128, 5), 5);
    }

    #[test]
    fn count_allocated_in_bat_trailing_partial_entry_ignored() {
        // One complete FULLY_PRESENT entry, then 7 trailing bytes that
        // cannot form a u64. chunks_exact(8) drops the tail.
        let mut buf = [0u8; 8 + 7];
        let entry = make_bat_entry(PAYLOAD_BLOCK_FULLY_PRESENT, 1);
        buf[..8].copy_from_slice(&entry);
        for b in &mut buf[8..] {
            *b = 0xFF;
        }
        assert_eq!(count_allocated_in_bat(&buf, 128, 1), 1);
    }

    #[test]
    fn count_allocated_in_bat_partially_present_counts_as_one() {
        // Pin the documented overcount semantics: PARTIALLY_PRESENT
        // counts as one full block (not as a fraction of one).
        let buf = make_bat_entry(PAYLOAD_BLOCK_PARTIALLY_PRESENT, 7);
        assert_eq!(count_allocated_in_bat(&buf, 128, 1), 1);
    }

    #[test]
    fn count_allocated_in_bat_unmapped_and_reserved_states_do_not_count() {
        // UNMAPPED (3) and reserved states (4, 5) all count as 0 bytes.
        let mut buf = [0u8; 3 * 8];
        put_bat_entry(&mut buf, 0, PAYLOAD_BLOCK_UNMAPPED, 0);
        put_bat_entry(&mut buf, 1, 4, 0);
        put_bat_entry(&mut buf, 2, 5, 0);
        assert_eq!(count_allocated_in_bat(&buf, 128, 3), 0);
    }

    #[test]
    fn count_allocated_in_bat_two_full_groups() {
        // chunk_ratio=2: two groups of 2 payload + 1 bitmap = 6 entries.
        // Group 0 payload[0] = FULLY, payload[1] = ZERO, bitmap = whatever.
        // Group 1 payload[0] = FULLY, payload[1] = FULLY, bitmap = whatever.
        let mut buf = [0u8; 6 * 8];
        put_bat_entry(&mut buf, 0, PAYLOAD_BLOCK_FULLY_PRESENT, 1);
        put_bat_entry(&mut buf, 1, PAYLOAD_BLOCK_ZERO, 0);
        // Slot 2 is the bitmap (group 0, slot_in_group == chunk_ratio).
        put_bat_entry(&mut buf, 2, PAYLOAD_BLOCK_FULLY_PRESENT, 99);
        put_bat_entry(&mut buf, 3, PAYLOAD_BLOCK_FULLY_PRESENT, 2);
        put_bat_entry(&mut buf, 4, PAYLOAD_BLOCK_FULLY_PRESENT, 3);
        // Slot 5 is the second-group bitmap.
        put_bat_entry(&mut buf, 5, PAYLOAD_BLOCK_FULLY_PRESENT, 99);
        // Three FULLY_PRESENT payloads at positions 0, 3, 4. The two
        // bitmap-slot entries are skipped despite their state.
        let count = count_allocated_in_bat(&buf, 2, 4);
        assert_eq!(count, 3);
    }

    #[test]
    fn count_allocated_in_bat_chunk_incremental_matches_whole() {
        // Build a BAT spanning multiple "sector"-sized chunks and check
        // that incremental processing yields the same answer as a
        // whole-buffer call. chunk_ratio=4 → group of 5. Build 3 groups
        // (15 entries, 120 bytes).
        let mut buf = [0u8; 15 * 8];
        for group in 0..3 {
            for p in 0..4 {
                // Alternate FULLY_PRESENT and ZERO.
                let state = if (group + p) % 2 == 0 {
                    PAYLOAD_BLOCK_FULLY_PRESENT
                } else {
                    PAYLOAD_BLOCK_ZERO
                };
                put_bat_entry(&mut buf, group * 5 + p, state, (group * 4 + p + 1) as u64);
            }
            // Bitmap entry.
            put_bat_entry(&mut buf, group * 5 + 4, PAYLOAD_BLOCK_FULLY_PRESENT, 99);
        }
        let chunk_ratio = 4u32;
        let total_payload_blocks = 12u32;
        let whole = count_allocated_in_bat(&buf, chunk_ratio, total_payload_blocks);

        // Now process incrementally, splitting at an 8-byte boundary
        // mid-group (5 entries / 40 bytes — past one bitmap slot).
        let split = 5 * 8;
        let (count_a, payload_seen_a) =
            count_allocated_in_bat_chunk(&buf[..split], chunk_ratio, total_payload_blocks, 0, 0);
        let (count_b, _) = count_allocated_in_bat_chunk(
            &buf[split..],
            chunk_ratio,
            total_payload_blocks,
            (split / 8) as u64,
            payload_seen_a,
        );
        assert_eq!(count_a + count_b, whole);
    }

    #[test]
    fn metadata_builder() {
        let mut buf = [0u8; 0x10000 + 64];
        let written = build_metadata(
            &mut buf,
            DEFAULT_BLOCK_SIZE,
            1024 * 1024 * 1024,
            512,
            4096,
            false,
        );
        assert!(written > 0);

        // Check signature
        let sig = le_u64(&buf, 0);
        assert_eq!(sig, METADATA_TABLE_SIGNATURE);

        // Check entry count
        let entry_count = le_u16(&buf, 10);
        assert_eq!(entry_count, 5);

        // Check block size at items area
        let bs = le_u32(&buf, 0x10000);
        assert_eq!(bs, DEFAULT_BLOCK_SIZE);

        // Check virtual disk size
        let vs = le_u64(&buf, 0x10000 + 8);
        assert_eq!(vs, 1024 * 1024 * 1024);
    }

    // ====================================================================
    // classify_vhdx_bat_entry tests
    // ====================================================================

    fn make_bat_entry_u64(state: u64, file_offset_mb: u64) -> u64 {
        ((file_offset_mb << 20) & BAT_ENTRY_OFFSET_MASK) | (state & BAT_ENTRY_STATE_MASK)
    }

    #[test]
    fn classify_vhdx_not_present_is_hole() {
        let e = classify_vhdx_bat_entry(
            make_bat_entry_u64(PAYLOAD_BLOCK_NOT_PRESENT, 0),
            0,
            32 << 20,
        );
        assert_eq!(e.state, MapExtentState::Hole);
        assert_eq!(e.length, 32 << 20);
    }

    #[test]
    fn classify_vhdx_undefined_is_hole() {
        let e =
            classify_vhdx_bat_entry(make_bat_entry_u64(PAYLOAD_BLOCK_UNDEFINED, 10), 0, 32 << 20);
        assert_eq!(e.state, MapExtentState::Hole);
    }

    #[test]
    fn classify_vhdx_unmapped_is_hole() {
        let e = classify_vhdx_bat_entry(make_bat_entry_u64(PAYLOAD_BLOCK_UNMAPPED, 0), 0, 32 << 20);
        assert_eq!(e.state, MapExtentState::Hole);
    }

    #[test]
    fn classify_vhdx_zero_is_zero_alloc() {
        // PAYLOAD_BLOCK_ZERO (2) → ZeroAllocated regardless of any
        // file_offset bits.
        let e = classify_vhdx_bat_entry(make_bat_entry_u64(PAYLOAD_BLOCK_ZERO, 5), 0, 32 << 20);
        assert_eq!(e.state, MapExtentState::ZeroAllocated);
    }

    #[test]
    fn classify_vhdx_fully_present_is_data() {
        // file_offset is stored as 1 MiB units in the high bits.
        let e = classify_vhdx_bat_entry(
            make_bat_entry_u64(PAYLOAD_BLOCK_FULLY_PRESENT, 5),
            0,
            32 << 20,
        );
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 5 << 20
            }
        );
    }

    #[test]
    fn classify_vhdx_partially_present_is_data_in_v1() {
        // v1 simplification: treat PARTIALLY_PRESENT as Data with
        // the recorded file_offset. Per-sector-bitmap walking is
        // future work.
        let e = classify_vhdx_bat_entry(
            make_bat_entry_u64(PAYLOAD_BLOCK_PARTIALLY_PRESENT, 100),
            0,
            32 << 20,
        );
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 100 << 20
            }
        );
    }

    #[test]
    fn classify_vhdx_reserved_state_is_hole() {
        // States 4 and 5 are reserved by the VHDX spec — emit
        // defensively as Hole.
        let entry = make_bat_entry_u64(4, 5);
        let e = classify_vhdx_bat_entry(entry, 0, 32 << 20);
        assert_eq!(e.state, MapExtentState::Hole);
    }

    // ====================================================================
    // Parent locator metadata item tests
    // ====================================================================
    //
    // All in memory: the crate is no_std and must test without
    // instar-testdata present. The shapes are modelled on the Hyper-V
    // item measured in PLAN-differencing-phase-01-pin.md, "VHDX — the
    // parent locator metadata item".

    /// Encode `text` as UTF-16 little endian, returning bytes written.
    fn utf16le(text: &str, dst: &mut [u8]) -> usize {
        let mut written = 0usize;
        let mut units = [0u16; 2];
        for ch in text.chars() {
            for unit in ch.encode_utf16(&mut units) {
                dst[written..written + 2].copy_from_slice(&unit.to_le_bytes());
                written += 2;
            }
        }
        written
    }

    /// Build a parent locator item: header, one entry per pair, then
    /// the key and value strings laid out after the entry array.
    /// Returns the item length.
    fn build_locator_item(pairs: &[(&str, &str)], buf: &mut [u8]) -> usize {
        buf[..16].copy_from_slice(&VHDX_PARENT_LOCATOR_TYPE_GUID);
        write_le_u16(buf, 16, 0);
        write_le_u16(buf, 18, pairs.len() as u16);

        let mut data = PARENT_LOCATOR_HEADER_SIZE + pairs.len() * PARENT_LOCATOR_ENTRY_SIZE;
        for (i, (key, value)) in pairs.iter().enumerate() {
            let key_offset = data;
            let key_length = utf16le(key, &mut buf[data..]);
            data += key_length;
            let value_offset = data;
            let value_length = utf16le(value, &mut buf[data..]);
            data += value_length;

            let entry = PARENT_LOCATOR_HEADER_SIZE + i * PARENT_LOCATOR_ENTRY_SIZE;
            write_le_u32(buf, entry, key_offset as u32);
            write_le_u32(buf, entry + 4, value_offset as u32);
            write_le_u16(buf, entry + 8, key_length as u16);
            write_le_u16(buf, entry + 10, value_length as u16);
        }
        data
    }

    /// The offset of entry `i`'s 12-byte record within the item.
    fn entry_offset(i: usize) -> usize {
        PARENT_LOCATOR_HEADER_SIZE + i * PARENT_LOCATOR_ENTRY_SIZE
    }

    const HYPERV_LINKAGE: &str = "{f88d4d92-6fcc-408d-9bef-9b7c89f15c89}";

    #[test]
    fn parent_locator_well_formed_item() {
        // The five keys Hyper-V writes, minus parent_linkage2, in the
        // order the measured image lists them.
        let mut buf = [0u8; 1024];
        let len = build_locator_item(
            &[
                ("parent_linkage", HYPERV_LINKAGE),
                (
                    "absolute_win32_path",
                    r"C:\Projects\dfvfs\test_data\fat-parent.vhdx",
                ),
                ("relative_path", r".\fat-parent.vhdx"),
                (
                    "volume_path",
                    r"\\?\Volume{5e0bd954-71b2-4bff-a928-082af7ab0f8f}\fat-parent.vhdx",
                ),
            ],
            &mut buf,
        );

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        assert!(locator.is_vhdx_locator_type());
        assert_eq!(locator.reserved, 0);
        assert_eq!(locator.key_value_count, 4);
        assert_eq!(locator.defect, None);
        assert_eq!(locator.entries().len(), 4);
        for entry in locator.entries() {
            assert_eq!(entry.defect, None);
        }

        assert_eq!(locator.parent_linkage(), Some(HYPERV_LINKAGE.as_bytes()));
        assert_eq!(
            locator.absolute_win32_path(),
            Some(r"C:\Projects\dfvfs\test_data\fat-parent.vhdx".as_bytes())
        );
        assert_eq!(
            locator.relative_path(),
            Some(r".\fat-parent.vhdx".as_bytes())
        );
        assert_eq!(
            locator.volume_path(),
            Some(r"\\?\Volume{5e0bd954-71b2-4bff-a928-082af7ab0f8f}\fat-parent.vhdx".as_bytes())
        );

        // The raw fields survive alongside the decoded strings.
        let linkage = locator.find(b"parent_linkage").unwrap();
        assert_eq!(linkage.key_offset as usize, entry_offset(4));
        assert_eq!(linkage.key_length, 28); // 14 characters
        assert_eq!(linkage.value_length, 76); // 38 characters
    }

    #[test]
    fn parent_locator_item_too_short_for_header() {
        let buf = [0u8; PARENT_LOCATOR_HEADER_SIZE - 1];
        assert!(parse_parent_locator(&buf).is_none());
    }

    #[test]
    fn parent_locator_key_value_count_exceeds_item() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        // Claim far more entries than the item's bytes can describe.
        write_le_u16(&mut buf, 18, 4096);

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        assert_eq!(locator.key_value_count, 4096);
        assert_eq!(
            locator.defect,
            Some(VhdxParentLocatorDefect::EntryCountExceedsItem)
        );
        // Never more entries than the item can hold, and never more
        // than the parser retains.
        assert!(
            locator.entries().len()
                <= (len - PARENT_LOCATOR_HEADER_SIZE) / PARENT_LOCATOR_ENTRY_SIZE
        );
        assert!(locator.entries().len() <= MAX_PARENT_LOCATOR_ENTRIES);
    }

    #[test]
    fn parent_locator_key_value_count_exceeds_capacity() {
        // Nine well-formed entries: the item can hold them all, the
        // parser retains eight and says so.
        let mut buf = [0u8; 2048];
        let pairs = [
            ("k0", "v0"),
            ("k1", "v1"),
            ("k2", "v2"),
            ("k3", "v3"),
            ("k4", "v4"),
            ("k5", "v5"),
            ("k6", "v6"),
            ("k7", "v7"),
            ("k8", "v8"),
        ];
        let len = build_locator_item(&pairs, &mut buf);

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        assert_eq!(locator.key_value_count, 9);
        assert_eq!(
            locator.defect,
            Some(VhdxParentLocatorDefect::EntryCountExceedsCapacity)
        );
        assert_eq!(locator.entries().len(), MAX_PARENT_LOCATOR_ENTRIES);
    }

    #[test]
    fn parent_locator_key_offset_past_region_end() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        // Point the key one byte past the end of the item.
        write_le_u32(&mut buf, entry_offset(0), len as u32);

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        let entry = &locator.entries()[0];
        assert_eq!(entry.defect, Some(VhdxParentLocatorDefect::KeyOutOfBounds));
        // The key is resolved first, so a key this broken leaves the
        // value undecoded too — but both raw descriptors survive, which
        // is what lets a later phase say which entry it refused.
        assert_eq!(entry.key(), b"");
        assert_eq!(entry.value(), b"");
        assert_eq!(entry.key_offset as usize, len);
        assert_eq!(entry.key_length, 26);
        assert!(locator.find(b"relative_path").is_none());
    }

    #[test]
    fn parent_locator_key_offset_overflows() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        // key_offset + key_length wraps a u32. The parser widens to
        // usize and uses checked_add, so this is a refusal rather than
        // a wrap into a legal-looking in-item range.
        write_le_u32(&mut buf, entry_offset(0), u32::MAX);
        write_le_u16(&mut buf, entry_offset(0) + 8, 26);

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        assert_eq!(
            locator.entries()[0].defect,
            Some(VhdxParentLocatorDefect::KeyOutOfBounds)
        );
    }

    #[test]
    fn parent_locator_value_longer_than_parser_decodes() {
        let mut buf = [0u8; 4096];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        // Claim a value one code unit past the parser's bound, still
        // inside the item so the bounds check passes and the length
        // check is what fires.
        let over = (MAX_PARENT_LOCATOR_VALUE_UTF16_BYTES + 2) as u16;
        write_le_u32(&mut buf, entry_offset(0) + 4, 32);
        write_le_u16(&mut buf, entry_offset(0) + 10, over);
        let item_len = 32 + over as usize;
        assert!(item_len > len);

        let locator = parse_parent_locator(&buf[..item_len]).unwrap();
        let entry = &locator.entries()[0];
        assert_eq!(entry.defect, Some(VhdxParentLocatorDefect::ValueTooLong));
        // A resource bound, not a verdict on the image: the key still
        // decoded, and the raw descriptor is preserved precisely so a
        // caller that wants the value can go and read it.
        assert_eq!(entry.key(), b"relative_path");
        assert_eq!(entry.value_offset, 32);
        assert_eq!(entry.value_length, over);
    }

    #[test]
    fn parent_locator_value_decodes_as_nothing() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        // Unpaired high surrogate (0xD800 little endian) at the start
        // of the value. Refused, not replaced with U+FFFD: a locator
        // value becomes a path the host opens, and a substituted
        // character manufactures a path the image never contained.
        let value_offset = le_u32(&buf, entry_offset(0) + 4) as usize;
        buf[value_offset] = 0x00;
        buf[value_offset + 1] = 0xD8;

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        let entry = &locator.entries()[0];
        assert_eq!(
            entry.defect,
            Some(VhdxParentLocatorDefect::ValueUndecodable)
        );
        assert_eq!(entry.key(), b"relative_path");
        assert_eq!(entry.value(), b"");
        // Findable by key, but the accessor still hands back nothing.
        assert!(locator.find(b"relative_path").is_some());
        assert_eq!(locator.relative_path(), None);
    }

    #[test]
    fn parent_locator_value_of_odd_length_decodes_as_nothing() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        // An odd byte length cannot be UTF-16 at all.
        write_le_u16(&mut buf, entry_offset(0) + 10, 25);

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        assert_eq!(
            locator.entries()[0].defect,
            Some(VhdxParentLocatorDefect::ValueUndecodable)
        );
    }

    #[test]
    fn parent_locator_value_offset_past_region_end() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        // Point the value one byte past the end of the item.
        write_le_u32(&mut buf, entry_offset(0) + 4, len as u32);

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        assert_eq!(locator.entries().len(), 1);
        let entry = &locator.entries()[0];
        assert_eq!(
            entry.defect,
            Some(VhdxParentLocatorDefect::ValueOutOfBounds)
        );
        // Marked, not dropped: the raw fields are still readable, and
        // the key that did decode is still there.
        assert_eq!(entry.value_offset as usize, len);
        assert_eq!(entry.value_length, 26);
        assert_eq!(entry.key(), b"relative_path");
        assert_eq!(entry.value(), b"");
        // ... but nothing hands the caller a value from a bad entry.
        assert_eq!(locator.relative_path(), None);
    }

    #[test]
    fn parent_locator_value_length_overflows_offset() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        // offset + length as far out as the fields can express it. The
        // sum is representable in a 64-bit usize, so it is the bounds
        // comparison that refuses it; on a narrower usize the
        // checked_add refuses it first. Either way the entry is marked
        // and no byte outside the item is read.
        write_le_u32(&mut buf, entry_offset(0) + 4, u32::MAX);
        write_le_u16(&mut buf, entry_offset(0) + 10, u16::MAX);

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        let entry = &locator.entries()[0];
        assert_eq!(
            entry.defect,
            Some(VhdxParentLocatorDefect::ValueOutOfBounds)
        );
        assert_eq!(entry.value_offset, u32::MAX);
        assert_eq!(entry.value_length, u16::MAX);
    }

    #[test]
    fn parent_locator_duplicate_key() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(
            &[
                ("relative_path", r".\first.vhdx"),
                ("relative_path", r".\second.vhdx"),
            ],
            &mut buf,
        );

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        assert_eq!(locator.entries().len(), 2);
        // The first use of the key stands; the repeat is marked.
        assert_eq!(locator.entries()[0].defect, None);
        assert_eq!(
            locator.entries()[1].defect,
            Some(VhdxParentLocatorDefect::DuplicateKey)
        );
        // The duplicate keeps its decoded value, so a later phase can
        // report what the two entries disagreed about.
        assert_eq!(locator.entries()[1].value(), r".\second.vhdx".as_bytes());
        // find() and value_of() resolve to the first entry.
        assert_eq!(locator.relative_path(), Some(r".\first.vhdx".as_bytes()));
    }

    #[test]
    fn parent_locator_key_decodes_as_nothing() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        // Overwrite the first code unit of the key with an unpaired
        // high surrogate (0xD800 little endian). utf16_to_utf8 refuses
        // it rather than substituting U+FFFD.
        let key_offset = le_u32(&buf, entry_offset(0)) as usize;
        buf[key_offset] = 0x00;
        buf[key_offset + 1] = 0xD8;

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        let entry = &locator.entries()[0];
        assert_eq!(entry.defect, Some(VhdxParentLocatorDefect::KeyUndecodable));
        assert_eq!(entry.key(), b"");
        assert_eq!(entry.value(), b"");
        // An entry with no usable key is not findable, but it is still
        // present and still carries its raw fields.
        assert_eq!(locator.entries().len(), 1);
        assert_eq!(entry.key_length, 26);
        assert!(locator.find(b"relative_path").is_none());
    }

    #[test]
    fn parent_locator_key_longer_than_parser_decodes() {
        let mut buf = [0u8; 1024];
        // 33 code units, one past MAX_PARENT_LOCATOR_KEY_UTF16_BYTES / 2.
        let len = build_locator_item(&[("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "value")], &mut buf);

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        let entry = &locator.entries()[0];
        assert_eq!(
            entry.key_length as usize,
            MAX_PARENT_LOCATOR_KEY_UTF16_BYTES + 2
        );
        assert_eq!(entry.defect, Some(VhdxParentLocatorDefect::KeyTooLong));
    }

    #[test]
    fn parent_locator_linkage_compares_case_insensitively() {
        // SPEC(VHDX) fixes no case for the braced GUID string: qemu and
        // libuuid write it lowercase, Hyper-V uppercase.
        let upper = "{F88D4D92-6FCC-408D-9BEF-9B7C89F15C89}";
        let lower = HYPERV_LINKAGE;

        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("parent_linkage", upper)], &mut buf);
        let locator = parse_parent_locator(&buf[..len]).unwrap();

        // Parsed faithfully: what the image wrote is what comes back.
        assert_eq!(locator.parent_linkage(), Some(upper.as_bytes()));
        // Compared case-insensitively, in both directions.
        assert!(locator.linkage_matches(lower.as_bytes()));
        assert!(locator.linkage_matches(upper.as_bytes()));
        // And it is a comparison, not a shrug: a different GUID, and a
        // GUID missing its braces, both fail.
        assert!(!locator.linkage_matches("{00000000-0000-0000-0000-000000000000}".as_bytes()));
        assert!(!locator.linkage_matches("f88d4d92-6fcc-408d-9bef-9b7c89f15c89".as_bytes()));

        let mut lower_buf = [0u8; 1024];
        let lower_len = build_locator_item(&[("parent_linkage", lower)], &mut lower_buf);
        let lower_locator = parse_parent_locator(&lower_buf[..lower_len]).unwrap();
        assert!(lower_locator.linkage_matches(upper.as_bytes()));
    }

    #[test]
    fn parent_locator_missing_linkage_matches_nothing() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        let locator = parse_parent_locator(&buf[..len]).unwrap();
        assert_eq!(locator.parent_linkage(), None);
        assert!(!locator.linkage_matches(HYPERV_LINKAGE.as_bytes()));
    }

    // ------------------------------------------------------------------
    // preferred_path() -- differencing phase 4, step 4c
    // ------------------------------------------------------------------

    #[test]
    fn preferred_path_prefers_relative_path() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(
            &[
                ("parent_linkage", HYPERV_LINKAGE),
                (
                    "absolute_win32_path",
                    r"C:\instar-testdata\vhdx-diff-parent.vhdx",
                ),
                ("relative_path", r".\vhdx-diff-parent.vhdx"),
            ],
            &mut buf,
        );
        let locator = parse_parent_locator(&buf[..len]).unwrap();

        assert_eq!(
            locator.preferred_path(),
            Some(&br".\vhdx-diff-parent.vhdx"[..])
        );
    }

    #[test]
    fn preferred_path_falls_back_to_absolute_win32_path() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(
            &[
                ("parent_linkage", HYPERV_LINKAGE),
                (
                    "absolute_win32_path",
                    r"C:\instar-testdata\vhdx-diff-parent.vhdx",
                ),
            ],
            &mut buf,
        );
        let locator = parse_parent_locator(&buf[..len]).unwrap();

        assert_eq!(
            locator.preferred_path(),
            Some(&br"C:\instar-testdata\vhdx-diff-parent.vhdx"[..])
        );
    }

    #[test]
    fn preferred_path_falls_back_to_volume_path() {
        let mut buf = [0u8; 1024];
        let value = r"\\?\Volume{5e0bd954-71b2-4bff-a928-082af7ab0f8f}\vhdx-diff-parent.vhdx";
        let len = build_locator_item(&[("volume_path", value)], &mut buf);
        let locator = parse_parent_locator(&buf[..len]).unwrap();

        assert_eq!(locator.preferred_path(), Some(value.as_bytes()));
    }

    #[test]
    fn preferred_path_none_when_no_path_key_present() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("parent_linkage", HYPERV_LINKAGE)], &mut buf);
        let locator = parse_parent_locator(&buf[..len]).unwrap();

        assert_eq!(locator.preferred_path(), None);
    }

    #[test]
    fn parent_locator_declined_item_is_distinguishable_from_absent() {
        // The state `parse_metadata` records when the metadata table
        // lists no parent locator item at all.
        let absent = VhdxParentLocatorState::Absent;
        assert!(absent.is_absent());
        assert!(absent.parsed().is_none());

        // The decision `stage_parent_locator` makes for a differencing
        // image whose table *does* list an item, one byte past the
        // parser's staging bound. This is the same function the staging
        // path calls, so the test exercises the real decision rather
        // than a hand-built state.
        let over_cap = (MAX_PARENT_LOCATOR_ITEM + 1) as u32;
        // 0x10028 is where Hyper-V and instar both place the item, and
        // 1 MiB is the metadata region every real writer declares, so
        // only the length is on trial here.
        let reason = plan_parent_locator_staging(0x1_0028, over_cap, 0x10_0000).unwrap_err();
        assert_eq!(reason, VhdxParentLocatorNotStaged::ItemExceedsParserBound);

        let declined = VhdxParentLocatorState::NotStaged {
            // 0x10028 is where Hyper-V and instar both place the item.
            item_offset: 0x1_0028,
            item_length: over_cap,
            reason,
        };

        // The two are told apart: a refusal is not an absence.
        assert!(!declined.is_absent());
        assert!(declined.parsed().is_none());

        // And the refusal keeps the facts that explain it, so a later
        // phase can report the length it declined and, if it wants,
        // re-read the item with a bigger buffer.
        match declined {
            VhdxParentLocatorState::NotStaged {
                item_offset,
                item_length,
                reason,
            } => {
                assert_eq!(item_offset, 0x1_0028);
                assert_eq!(item_length, over_cap);
                assert_eq!(reason, VhdxParentLocatorNotStaged::ItemExceedsParserBound);
            }
            _ => panic!("expected NotStaged"),
        }

        // The bound is a bound, not a blanket refusal: the measured
        // Hyper-V item stages, and an item too short for its own header
        // is refused for a different, distinguishable reason.
        assert_eq!(
            plan_parent_locator_staging(0x1_0028, 674, 0x10_0000),
            Ok(674)
        );
        assert_eq!(
            plan_parent_locator_staging(
                0x1_0028,
                (PARENT_LOCATOR_HEADER_SIZE - 1) as u32,
                0x10_0000
            ),
            Err(VhdxParentLocatorNotStaged::ItemTooShort)
        );
        assert_eq!(
            plan_parent_locator_staging(0x1_0028, MAX_PARENT_LOCATOR_ITEM as u32, 0x10_0000),
            Ok(MAX_PARENT_LOCATOR_ITEM)
        );

        // The region bound is checked before the parser's own bound,
        // so an item that is both outside the region and too large
        // reports the structural problem rather than instar's limit.
        assert_eq!(
            plan_parent_locator_staging(0x8000_0000, over_cap, 0x10_0000),
            Err(VhdxParentLocatorNotStaged::ItemOutsideMetadataRegion)
        );
        // A region large enough to contain it puts it back on trial
        // for its length.
        assert_eq!(
            plan_parent_locator_staging(0x1_0028, over_cap, 0xFFFF_FFFF),
            Err(VhdxParentLocatorNotStaged::ItemExceedsParserBound)
        );
        // Overflowing the end offset is a refusal, not a wrap.
        assert_eq!(
            plan_parent_locator_staging(0xFFFF_FFFF, 674, 0xFFFF_FFFF),
            Err(VhdxParentLocatorNotStaged::ItemOutsideMetadataRegion)
        );
    }

    #[test]
    fn parent_locator_foreign_locator_type_is_reported_not_refused() {
        let mut buf = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut buf);
        buf[0] ^= 0xFF;

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        assert!(!locator.is_vhdx_locator_type());
        assert_eq!(
            locator.locator_type[0],
            VHDX_PARENT_LOCATOR_TYPE_GUID[0] ^ 0xFF
        );
        assert_eq!(locator.relative_path(), Some(r".\parent.vhdx".as_bytes()));
    }

    // ====================================================================
    // Parent locator staging: the sector-assembly path
    // ====================================================================

    /// Bytes of the metadata region the staging fixture serves.
    ///
    /// 64 KB of metadata table plus room for items above
    /// `METADATA_ITEMS_MIN_OFFSET`, which is where a real item has to
    /// start.
    const STAGE_REGION_LEN: usize = 0x11000;

    /// A whole VHDX metadata region in memory, served one sector at a
    /// time through a `CallTable`, so the staging loop can be driven
    /// without a device.
    ///
    /// The region sits at file offset 0 in this fixture, so the sector
    /// arithmetic the test reasons about is the arithmetic the loop
    /// does — a non-zero `metadata_offset` would only hide it.
    struct StageFixture {
        region: [u8; STAGE_REGION_LEN],
        /// Sector reads to serve before the reader starts refusing.
        /// `u32::MAX` means "never refuse".
        reads_before_failure: u32,
        /// Sector reads served so far.
        reads: u32,
    }

    // The reader is an `extern "C" fn` and so closes over nothing: the
    // fixture has to be a global, and the lock is what keeps
    // concurrently-running tests off each other's bytes. Same shape as
    // `crates/qcow2`'s `STREAMING_FIXTURE`.
    static STAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut STAGE_FIXTURE: StageFixture = StageFixture {
        region: [0u8; STAGE_REGION_LEN],
        reads_before_failure: u32::MAX,
        reads: 0,
    };

    /// Serve one sector out of the fixture, refusing once the read
    /// budget is spent.
    ///
    /// Every access goes through a raw pointer rather than a reference,
    /// because a reference to a `static mut` is what `static_mut_refs`
    /// forbids.
    unsafe extern "C" fn stage_read_sector(
        _device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        let served = core::ptr::addr_of_mut!(STAGE_FIXTURE.reads);
        let budget = core::ptr::addr_of!(STAGE_FIXTURE.reads_before_failure).read();
        if served.read() >= budget {
            return false;
        }
        served.write(served.read() + 1);

        let start = (sector as usize).saturating_mul(sector_size);
        match start.checked_add(sector_size) {
            Some(end) if end <= STAGE_REGION_LEN => {}
            _ => return false,
        }
        let base = core::ptr::addr_of!(STAGE_FIXTURE.region) as *const u8;
        core::ptr::copy_nonoverlapping(base.add(start), out_buf, sector_size);
        true
    }

    /// Zero the fixture, place `item` at `item_offset` inside the
    /// region, and set the read budget.
    ///
    /// # Safety
    ///
    /// The caller must hold `STAGE_LOCK` for as long as it then uses
    /// the fixture.
    unsafe fn install_staged_item(item: &[u8], item_offset: usize, reads_before_failure: u32) {
        assert!(item_offset + item.len() <= STAGE_REGION_LEN);
        let region = core::ptr::addr_of_mut!(STAGE_FIXTURE.region) as *mut u8;
        core::ptr::write_bytes(region, 0, STAGE_REGION_LEN);
        core::ptr::copy_nonoverlapping(item.as_ptr(), region.add(item_offset), item.len());
        core::ptr::addr_of_mut!(STAGE_FIXTURE.reads).write(0);
        core::ptr::addr_of_mut!(STAGE_FIXTURE.reads_before_failure).write(reads_before_failure);
    }

    /// A `CallTable` with every function pointer set to a
    /// trivially-correct stub, so a test can override the one entry it
    /// cares about.
    ///
    /// Duplicated from `crates/qcow2`'s test module rather than shared,
    /// because the type is 40-odd `extern "C"` pointers with distinct
    /// signatures and `shared` has no test-support surface to put it
    /// behind. If a third crate needs one, that is the point to factor
    /// it out.
    fn stub_call_table() -> shared::CallTable {
        unsafe extern "C" fn s_get_dev_count() -> u32 {
            1
        }
        unsafe extern "C" fn s_read_in(_: u32, _: u64, _: *mut u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_in_cap(_: u32) -> u64 {
            8
        }
        unsafe extern "C" fn s_in_secsz(_: u32) -> usize {
            512
        }
        unsafe extern "C" fn s_write_out(_: u64, _: *const u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_out_cap() -> u64 {
            0
        }
        unsafe extern "C" fn s_out_secsz() -> usize {
            512
        }
        unsafe extern "C" fn s_prog_int() -> u32 {
            100
        }
        unsafe extern "C" fn s_send_prog(_: *const u8, _: u64, _: u64, _: u32) {}
        unsafe extern "C" fn s_send_err(_: *const u8, _: *const u8, _: u64, _: u32) {}
        unsafe extern "C" fn s_send_complete(_: *const u8, _: u64, _: bool) {}
        unsafe extern "C" fn s_dbg(_: *const u8) {}
        unsafe extern "C" fn s_verb(_: *const u8) {}
        unsafe extern "C" fn s_get_op_cfg() -> shared::ConfigResult {
            shared::ConfigResult {
                ptr: core::ptr::null(),
                len: 0,
            }
        }
        unsafe extern "C" fn s_get_chain_cfg() -> shared::ConfigResult {
            shared::ConfigResult {
                ptr: core::ptr::null(),
                len: 0,
            }
        }
        unsafe extern "C" fn s_send_info(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
        ) {
        }
        unsafe extern "C" fn s_send_info_q(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::Qcow2Info,
        ) {
        }
        unsafe extern "C" fn s_send_info_v(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::VmdkInfo,
        ) {
        }
        unsafe extern "C" fn s_send_info_vdi(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::VdiInfo,
        ) {
        }
        unsafe extern "C" fn s_send_info_l(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::LuksInfo,
        ) {
        }
        unsafe extern "C" fn s_send_check(_: *const shared::CheckResult) {}
        unsafe extern "C" fn s_send_compare(_: *const shared::CompareResult) {}
        unsafe extern "C" fn s_send_measure(_: *const shared::MeasureResult) {}
        unsafe extern "C" fn s_send_create(_: *const shared::CreateResult) {}
        unsafe extern "C" fn s_read_out(_: u64, _: *mut u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_send_resize(_: *const shared::ResizeResult) {}
        unsafe extern "C" fn s_send_rebase(_: *const shared::RebaseResult) {}
        unsafe extern "C" fn s_send_commit(_: *const shared::CommitResult) {}
        unsafe extern "C" fn s_write_in(_: u32, _: u64, _: *const u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_send_map_ex(_: *const shared::MapExtentRecord) {}
        unsafe extern "C" fn s_send_map_res(_: *const shared::MapResult) {}
        unsafe extern "C" fn s_send_snap_ent(_: *const shared::SnapshotEntryRecord) {}
        unsafe extern "C" fn s_send_snap_res(_: *const shared::SnapshotResult) {}
        unsafe extern "C" fn s_fsync_in(_: u32) -> bool {
            true
        }
        unsafe extern "C" fn s_send_amend(_: *const shared::AmendResult) {}
        unsafe extern "C" fn s_send_bitmap(_: *const shared::BitmapResult) {}
        unsafe extern "C" fn s_send_bench_start() {}
        unsafe extern "C" fn s_send_bench_result(_: *const shared::BenchResult) {}
        shared::CallTable {
            magic: shared::CallTable::MAGIC,
            version: shared::CallTable::VERSION,
            get_input_device_count: s_get_dev_count,
            read_input_sector: s_read_in,
            get_input_capacity: s_in_cap,
            get_input_sector_size: s_in_secsz,
            write_output_sector: s_write_out,
            get_output_capacity: s_out_cap,
            get_output_sector_size: s_out_secsz,
            get_progress_interval: s_prog_int,
            send_progress: s_send_prog,
            send_error: s_send_err,
            send_complete: s_send_complete,
            debug_print: s_dbg,
            verbose_print: s_verb,
            get_operation_config: s_get_op_cfg,
            get_chain_config: s_get_chain_cfg,
            send_info_result: s_send_info,
            send_info_result_qcow2: s_send_info_q,
            send_info_result_vmdk: s_send_info_v,
            send_info_result_vdi: s_send_info_vdi,
            send_info_result_luks: s_send_info_l,
            send_check_result: s_send_check,
            send_compare_result: s_send_compare,
            send_measure_result: s_send_measure,
            send_create_result: s_send_create,
            read_output_sector: s_read_out,
            send_resize_result: s_send_resize,
            send_rebase_result: s_send_rebase,
            send_commit_result: s_send_commit,
            write_input_sector: s_write_in,
            send_map_extent: s_send_map_ex,
            send_map_result: s_send_map_res,
            send_snapshot_entry: s_send_snap_ent,
            send_snapshot_result: s_send_snap_res,
            fsync_input: s_fsync_in,
            send_amend_result: s_send_amend,
            send_bitmap_result: s_send_bitmap,
            send_bench_start: s_send_bench_start,
            send_bench_result: s_send_bench_result,
        }
    }
    /// Take the fixture lock, ignoring poisoning.
    ///
    /// A test that fails while holding the lock would otherwise turn
    /// every other staging test into a `PoisonError`, hiding the one
    /// real failure behind a screen of unrelated ones.
    fn stage_lock() -> std::sync::MutexGuard<'static, ()> {
        STAGE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Replace the whole fixture region and reset the read budget.
    ///
    /// # Safety
    ///
    /// The caller must hold `STAGE_LOCK` for as long as it then uses
    /// the fixture.
    unsafe fn install_staged_region(bytes: &[u8]) {
        assert!(bytes.len() <= STAGE_REGION_LEN);
        let region = core::ptr::addr_of_mut!(STAGE_FIXTURE.region) as *mut u8;
        core::ptr::write_bytes(region, 0, STAGE_REGION_LEN);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), region, bytes.len());
        core::ptr::addr_of_mut!(STAGE_FIXTURE.reads).write(0);
        core::ptr::addr_of_mut!(STAGE_FIXTURE.reads_before_failure).write(u32::MAX);
    }

    /// A call table whose only working entry is the fixture reader.
    fn stage_call_table() -> shared::CallTable {
        shared::CallTable {
            read_input_sector: stage_read_sector,
            ..stub_call_table()
        }
    }

    /// Drive `stage_parent_locator` against the fixture.
    ///
    /// # Safety
    ///
    /// The caller must hold `STAGE_LOCK`.
    unsafe fn stage(
        item_offset: u32,
        item_length: u32,
        metadata_length: u32,
        sector_size: usize,
        input_capacity: u64,
    ) -> (VhdxParentLocatorState, u64) {
        let call_table = stage_call_table();
        let mut buffer = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let state = stage_parent_locator(
            &call_table,
            0,
            0,
            item_offset,
            item_length,
            metadata_length,
            sector_size,
            input_capacity,
            &mut bytes_read,
            &mut buffer,
        );
        (state, bytes_read)
    }

    /// The reason a `NotStaged` state carries, or a panic.
    fn not_staged_reason(state: &VhdxParentLocatorState) -> VhdxParentLocatorNotStaged {
        match state {
            VhdxParentLocatorState::NotStaged { reason, .. } => *reason,
            _ => panic!("expected NotStaged"),
        }
    }

    #[test]
    fn staged_item_straddling_sector_boundaries_is_assembled() {
        let _guard = stage_lock();

        // A long absolute path pads the item past 1 KB so that it
        // covers a whole middle sector as well as two partial ones.
        let long_path = {
            let mut path = std::string::String::from(r"C:\vms\");
            while path.len() < 240 {
                path.push('a');
            }
            path.push_str(".vhdx");
            path
        };
        let mut item = [0u8; 1024];
        let len = build_locator_item(
            &[
                ("parent_linkage", HYPERV_LINKAGE),
                ("relative_path", r".\parent.vhdx"),
                ("absolute_win32_path", long_path.as_str()),
            ],
            &mut item,
        );

        // Deliberately not sector-aligned, and long enough to span
        // three 512-byte sectors: the assembly loop's offset-in-sector
        // arithmetic and its `available`/`remaining` minimum are the
        // point of the test, and an aligned item exercises neither.
        // Three sectors also means one iteration copies a whole sector,
        // which two sectors would never reach.
        let item_offset = METADATA_ITEMS_MIN_OFFSET as usize + 500;
        assert!(item_offset % 512 != 0);
        assert!((item_offset % 512) + len > 512);

        let (state, bytes_read) = unsafe {
            install_staged_item(&item[..len], item_offset, u32::MAX);
            stage(
                item_offset as u32,
                len as u32,
                0x10_0000,
                512,
                (STAGE_REGION_LEN / 512) as u64,
            )
        };

        let locator = match &state {
            VhdxParentLocatorState::Parsed(locator) => locator,
            other => panic!("expected Parsed, got {:?}", not_staged_reason(other)),
        };
        assert!(locator.is_vhdx_locator_type());
        assert_eq!(locator.parent_linkage(), Some(HYPERV_LINKAGE.as_bytes()));
        assert_eq!(locator.relative_path(), Some(r".\parent.vhdx".as_bytes()));

        // Reassembly across sectors is the claim, so the sector count
        // is asserted rather than left implied.
        let first = item_offset / 512;
        let last = (item_offset + len - 1) / 512;
        assert_eq!(bytes_read, ((last - first + 1) * 512) as u64);
        assert!(last > first + 1, "fixture should span three sectors");
    }

    #[test]
    fn staged_item_past_input_capacity_is_declined() {
        let _guard = stage_lock();

        let mut item = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut item);
        let item_offset = METADATA_ITEMS_MIN_OFFSET as usize;

        // The item is inside the metadata region the table declares,
        // and inside the fixture, but the device says it has only two
        // sectors. The region bound and the device bound are different
        // facts, and this is the one that catches a region declared
        // larger than the image.
        let (state, bytes_read) = unsafe {
            install_staged_item(&item[..len], item_offset, u32::MAX);
            stage(item_offset as u32, len as u32, 0x10_0000, 512, 2)
        };

        assert_eq!(
            not_staged_reason(&state),
            VhdxParentLocatorNotStaged::ItemOutsideInput
        );
        // Declined before any read: a refusal must not cost I/O.
        assert_eq!(bytes_read, 0);
    }

    #[test]
    fn staged_item_is_declined_when_a_read_fails_partway() {
        let _guard = stage_lock();

        let mut item = [0u8; 1024];
        let len = build_locator_item(
            &[
                ("parent_linkage", HYPERV_LINKAGE),
                ("relative_path", r".\parent.vhdx"),
            ],
            &mut item,
        );
        let item_offset = METADATA_ITEMS_MIN_OFFSET as usize + 500;

        // One sector is served, then the device refuses. A partially
        // assembled item must not be parsed: half an item parses to
        // plausible-looking nonsense, which is worse than no answer.
        let (state, bytes_read) = unsafe {
            install_staged_item(&item[..len], item_offset, 1);
            stage(
                item_offset as u32,
                len as u32,
                0x10_0000,
                512,
                (STAGE_REGION_LEN / 512) as u64,
            )
        };

        assert_eq!(
            not_staged_reason(&state),
            VhdxParentLocatorNotStaged::ReadFailed
        );
        // The one successful read is still accounted for.
        assert_eq!(bytes_read, 512);
    }

    #[test]
    fn staged_item_outside_the_metadata_region_is_declined() {
        let _guard = stage_lock();

        let mut item = [0u8; 1024];
        let len = build_locator_item(&[("relative_path", r".\parent.vhdx")], &mut item);

        // A crafted table entry pointing far past the region. Without
        // the region bound this reads unrelated image bytes and parses
        // them as a parent locator; the sector loop alone would not
        // stop it on a large enough image.
        let capacity = (STAGE_REGION_LEN / 512) as u64;
        let (state, bytes_read) = unsafe {
            install_staged_item(&item[..len], METADATA_ITEMS_MIN_OFFSET as usize, u32::MAX);
            stage(0x8000_0000, len as u32, 0x10_0000, 512, capacity)
        };
        assert_eq!(
            not_staged_reason(&state),
            VhdxParentLocatorNotStaged::ItemOutsideMetadataRegion
        );
        assert_eq!(bytes_read, 0);

        // And the floor: the first 64 KB of the region is the metadata
        // table itself, so an item claiming to start inside it is
        // refused even though those bytes are readable.
        let (state, _) = unsafe { stage(0x8000, len as u32, 0x10_0000, 512, capacity) };
        assert_eq!(
            not_staged_reason(&state),
            VhdxParentLocatorNotStaged::ItemOutsideMetadataRegion
        );

        // An item that starts legally but runs off the end of the
        // region is refused for the same reason.
        let (state, _) = unsafe { stage(0xF_F000, 0x2000, 0x10_0000, 512, capacity) };
        assert_eq!(
            not_staged_reason(&state),
            VhdxParentLocatorNotStaged::ItemOutsideMetadataRegion
        );
    }

    // ====================================================================
    // parse_metadata: the parent locator gate
    // ====================================================================

    /// Build a whole metadata region: the five items `build_metadata`
    /// writes, plus optionally a sixth table entry and item for a
    /// parent locator, laid out the way the phase 1 pin's generator
    /// lays out Hyper-V's.
    fn metadata_region(has_parent: bool, with_locator: bool) -> std::vec::Vec<u8> {
        let mut region = std::vec![0u8; STAGE_REGION_LEN];
        build_metadata(
            &mut region,
            1024 * 1024,
            64 * 1024 * 1024,
            512,
            512,
            has_parent,
        );

        if with_locator {
            let mut item = [0u8; 1024];
            let len = build_locator_item(
                &[
                    ("parent_linkage", HYPERV_LINKAGE),
                    ("relative_path", r".\parent.vhdx"),
                ],
                &mut item,
            );
            // 0x10028 is the first free byte above the five existing
            // items, and is where Hyper-V puts its locator too.
            let item_offset: u32 = 0x1_0028;
            let at = item_offset as usize;
            region[at..at + len].copy_from_slice(&item[..len]);

            let e = 32 + 5 * METADATA_TABLE_ENTRY_SIZE;
            region[e..e + 16].copy_from_slice(&PARENT_LOCATOR_GUID);
            write_le_u32(&mut region, e + 16, item_offset);
            write_le_u32(&mut region, e + 20, len as u32);
            write_le_u32(&mut region, e + 24, 0x04);
            write_le_u16(&mut region, 10, 6);
        }
        region
    }

    /// Parse the fixture region as metadata sitting at file offset 0.
    ///
    /// # Safety
    ///
    /// The caller must hold `STAGE_LOCK`.
    unsafe fn parse_fixture_metadata() -> (Option<VhdxMetadata>, u64) {
        let call_table = stage_call_table();
        let mut bytes_read = 0u64;
        let metadata = parse_metadata(
            &call_table,
            0,
            0,
            0x10_0000,
            512,
            (STAGE_REGION_LEN / 512) as u64,
            &mut bytes_read,
        );
        (metadata, bytes_read)
    }

    #[test]
    fn ordinary_image_has_no_parent_locator_and_reads_nothing_extra() {
        let _guard = stage_lock();

        let region = metadata_region(false, false);
        let (metadata, bytes_read) = unsafe {
            install_staged_region(&region);
            parse_fixture_metadata()
        };

        let metadata = metadata.expect("ordinary metadata should parse");
        assert!(!metadata.has_parent);
        // Absent, not a stale or garbage locator: the table listed no
        // item, which is the only thing `Absent` is allowed to mean.
        assert!(metadata.parent_locator.is_absent());
        assert!(metadata.parent_locator.parsed().is_none());

        // The five reads this function always did — table, file
        // parameters, virtual size, logical and physical sector size —
        // and not one more. This is the unit-level form of the phase's
        // no-behaviour-change claim: an image without a parent costs
        // exactly what it cost before.
        assert_eq!(bytes_read, 5 * 512);
    }

    #[test]
    fn locator_item_without_has_parent_is_reported_not_read() {
        let _guard = stage_lock();

        // A metadata table listing a parent locator item while the file
        // parameters item denies having a parent. Anomalous, and the
        // anomaly is the interesting fact — so it comes back as a
        // distinct refusal rather than as `Absent` (which would claim
        // the table listed nothing) or as a parse (which would spend
        // reads on an image that will never use the answer).
        let region = metadata_region(false, true);
        let (metadata, bytes_read) = unsafe {
            install_staged_region(&region);
            parse_fixture_metadata()
        };

        let metadata = metadata.expect("metadata should parse");
        assert!(!metadata.has_parent);
        assert!(!metadata.parent_locator.is_absent());
        assert!(metadata.parent_locator.parsed().is_none());
        match metadata.parent_locator {
            VhdxParentLocatorState::NotStaged {
                item_offset,
                item_length,
                reason,
            } => {
                assert_eq!(item_offset, 0x1_0028);
                assert!(item_length > 0);
                assert_eq!(reason, VhdxParentLocatorNotStaged::ImageClaimsNoParent);
            }
            _ => panic!("expected NotStaged"),
        }
        // Reported without reading the item.
        assert_eq!(bytes_read, 5 * 512);
    }

    #[test]
    fn differencing_image_parses_its_parent_locator() {
        let _guard = stage_lock();

        let region = metadata_region(true, true);
        let (metadata, bytes_read) = unsafe {
            install_staged_region(&region);
            parse_fixture_metadata()
        };

        let metadata = metadata.expect("differencing metadata should parse");
        assert!(metadata.has_parent);
        let locator = metadata
            .parent_locator
            .parsed()
            .expect("a differencing image's locator should be staged and parsed");
        assert!(locator.is_vhdx_locator_type());
        assert_eq!(locator.parent_linkage(), Some(HYPERV_LINKAGE.as_bytes()));
        assert_eq!(locator.relative_path(), Some(r".\parent.vhdx".as_bytes()));

        // The five metadata reads, plus whatever the item cost. The
        // extra reads land only here, which is what the `has_parent`
        // gate buys.
        assert!(bytes_read > 5 * 512);
    }

    // ====================================================================
    // Parent locator emitting (build_parent_locator, render_guid_braced)
    // ====================================================================

    /// A metadata region with the five items `build_metadata` writes,
    /// sized to hold a parent locator item above them.
    fn built_metadata_region() -> std::vec::Vec<u8> {
        let mut region = std::vec![0u8; 0x11000];
        build_metadata(
            &mut region,
            2 * 1024 * 1024,
            64 * 1024 * 1024,
            512,
            4096,
            true,
        );
        region
    }

    /// `utf16le` into a fresh buffer. The encoder is this module's
    /// existing one, which goes through `char::encode_utf16` rather
    /// than through the builder's own ASCII expander, so a test
    /// comparing against it is not comparing the builder with itself.
    fn utf16le_vec(text: &str) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; text.len() * 4];
        let written = utf16le(text, &mut buf);
        buf.truncate(written);
        buf
    }

    /// The parent's DataWriteGuid measured in
    /// `docs/plans/PLAN-differencing-phase-01-pin.md`, whose child's
    /// `parent_linkage` was measured to be
    /// `{f88d4d92-6fcc-408d-9bef-9b7c89f15c89}`.
    const PIN_PARENT_DATA_WRITE_GUID: [u8; 16] = [
        0x92, 0x4d, 0x8d, 0xf8, 0xcc, 0x6f, 0x8d, 0x40, 0x9b, 0xef, 0x9b, 0x7c, 0x89, 0xf1, 0x5c,
        0x89,
    ];

    #[test]
    fn render_guid_braced_matches_pin_worked_example() {
        // Asserted against the *measured* pair in the pin -- a real
        // parent's header bytes and the string a real Hyper-V child
        // carries for them -- and not against instar's own output,
        // because a wrong group order round-trips through instar
        // perfectly and fails only against Hyper-V.
        assert_eq!(
            &render_guid_braced(&PIN_PARENT_DATA_WRITE_GUID),
            b"{f88d4d92-6fcc-408d-9bef-9b7c89f15c89}"
        );
    }

    #[test]
    fn render_guid_braced_group_order_is_mixed_endian() {
        // Sixteen distinct bytes, so every position in the output
        // identifies the source byte it came from. A rendering that
        // byte-reversed all five groups, or none of them, differs from
        // this in the bytes it prints rather than only in their case.
        let guid: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        assert_eq!(
            &render_guid_braced(&guid),
            b"{03020100-0504-0706-0809-0a0b0c0d0e0f}"
        );
    }

    #[test]
    fn build_parent_locator_appends_where_the_table_says_it_ends() {
        // The entry index, the new count and the item offset are all
        // read rather than assumed, so that adding a sixth built-in
        // metadata item moves the locator instead of overwriting it.
        // A region whose table already claims three items must get the
        // locator as entry three, and a count of four -- if any of the
        // three were hardcoded for `build_metadata`'s five, this test
        // reports the hardcoded value.
        let mut region = built_metadata_region();
        write_le_u16(&mut region, METADATA_TABLE_ENTRY_COUNT_OFFSET, 3);

        let item_offset = PARENT_LOCATOR_ITEM_OFFSET + 0x200;
        let item_len = build_parent_locator(
            &mut region,
            item_offset,
            &PIN_PARENT_DATA_WRITE_GUID,
            KEY_RELATIVE_PATH,
            "parent.vhdx",
        )
        .expect("locator should build");

        assert_eq!(le_u16(&region, METADATA_TABLE_ENTRY_COUNT_OFFSET), 4);

        let e = METADATA_TABLE_HEADER_SIZE + 3 * METADATA_TABLE_ENTRY_SIZE;
        assert_eq!(&region[e..e + 16], &PARENT_LOCATOR_GUID);
        assert_eq!(le_u32(&region, e + 16), item_offset);
        assert_eq!(le_u32(&region, e + 20) as usize, item_len);

        // Entry four is whatever `build_metadata` left there -- the
        // builder appended at the declared index and reached no
        // further. (It is not zero: `build_metadata` writes five
        // entries, so index four is its Virtual Disk ID entry.)
        let pristine = built_metadata_region();
        let e4 = METADATA_TABLE_HEADER_SIZE + 4 * METADATA_TABLE_ENTRY_SIZE;
        assert_eq!(
            &region[e4..e4 + METADATA_TABLE_ENTRY_SIZE],
            &pristine[e4..e4 + METADATA_TABLE_ENTRY_SIZE]
        );
        let item = &region[item_offset as usize..item_offset as usize + item_len];
        assert_eq!(&item[..16], &VHDX_PARENT_LOCATOR_TYPE_GUID);
    }

    #[test]
    fn build_parent_locator_refuses_a_table_that_reaches_the_item() {
        // The growing table must not run into the item data it
        // describes. A count that puts the next entry past the item
        // offset is refused rather than written over the item.
        let mut region = built_metadata_region();
        let item_offset = PARENT_LOCATOR_ITEM_OFFSET;
        let reaches = ((item_offset as usize - METADATA_TABLE_HEADER_SIZE)
            / METADATA_TABLE_ENTRY_SIZE) as u16;
        write_le_u16(&mut region, METADATA_TABLE_ENTRY_COUNT_OFFSET, reaches);
        assert_eq!(
            build_parent_locator(
                &mut region,
                item_offset,
                &PIN_PARENT_DATA_WRITE_GUID,
                KEY_RELATIVE_PATH,
                "parent.vhdx",
            ),
            Err(VhdxBuildError::BufferTooSmall)
        );
        // Refused before writing: the count is as it was left.
        assert_eq!(le_u16(&region, METADATA_TABLE_ENTRY_COUNT_OFFSET), reaches);
    }

    #[test]
    fn build_parent_locator_lays_out_every_field_at_the_pinned_offset() {
        let mut region = built_metadata_region();
        let item_len = build_parent_locator(
            &mut region,
            PARENT_LOCATOR_ITEM_OFFSET,
            &PIN_PARENT_DATA_WRITE_GUID,
            KEY_RELATIVE_PATH,
            "parent.vhdx",
        )
        .expect("locator should build");

        // 148 + key + value, with no padding: relative_path is 13
        // characters (26 bytes) and "parent.vhdx" 11 (22 bytes).
        assert_eq!(item_len, 148 + 26 + 22);

        let start = PARENT_LOCATOR_ITEM_OFFSET as usize;
        assert_eq!(start, 0x10028);
        let item = &region[start..start + item_len];

        // Header: locator type GUID, reserved, KeyValueCount.
        assert_eq!(&item[..16], &VHDX_PARENT_LOCATOR_TYPE_GUID);
        assert_eq!(le_u16(item, 16), 0);
        assert_eq!(le_u16(item, 18), 2);

        // Entry 0, parent_linkage: key at +44 (28 bytes), value at +98
        // (76 bytes).
        assert_eq!(le_u32(item, 20), 44);
        assert_eq!(le_u32(item, 24), 98);
        assert_eq!(le_u16(item, 28), 28);
        assert_eq!(le_u16(item, 30), 76);

        // Entry 1, the path key: key at +72 (26 bytes), value at +174
        // (22 bytes).
        assert_eq!(le_u32(item, 32), 72);
        assert_eq!(le_u32(item, 36), 174);
        assert_eq!(le_u16(item, 40), 26);
        assert_eq!(le_u16(item, 42), 22);

        // Keys before values, each UTF-16 little endian with no NUL
        // terminator and no padding between them.
        assert_eq!(&item[44..72], &utf16le_vec("parent_linkage")[..]);
        assert_eq!(&item[72..98], &utf16le_vec("relative_path")[..]);
        assert_eq!(
            &item[98..174],
            &utf16le_vec("{f88d4d92-6fcc-408d-9bef-9b7c89f15c89}")[..]
        );
        assert_eq!(&item[174..196], &utf16le_vec("parent.vhdx")[..]);
    }

    #[test]
    fn build_parent_locator_writes_the_metadata_table_entry() {
        let mut region = built_metadata_region();
        assert_eq!(le_u16(&region, METADATA_TABLE_ENTRY_COUNT_OFFSET), 5);

        let item_len = build_parent_locator(
            &mut region,
            PARENT_LOCATOR_ITEM_OFFSET,
            &PIN_PARENT_DATA_WRITE_GUID,
            KEY_RELATIVE_PATH,
            "parent.vhdx",
        )
        .expect("locator should build");

        assert_eq!(le_u16(&region, METADATA_TABLE_ENTRY_COUNT_OFFSET), 6);

        let e = METADATA_TABLE_HEADER_SIZE + 5 * METADATA_TABLE_ENTRY_SIZE;
        assert_eq!(e, 0xC0);
        assert_eq!(&region[e..e + 16], &PARENT_LOCATOR_GUID);
        assert_eq!(le_u32(&region, e + 16), 0x10028);
        assert_eq!(le_u32(&region, e + 20), item_len as u32);
        assert_eq!(le_u32(&region, e + 24), 0x0000_0004);
        assert_eq!(le_u32(&region, e + 28), 0);

        // The five entries build_metadata wrote are untouched: the
        // locator is appended, not rewritten over one of them.
        let file_params = METADATA_TABLE_HEADER_SIZE;
        assert_eq!(le_u32(&region, file_params + 16), 0x10000);
        assert_eq!(le_u32(&region, file_params + 20), 8);
    }

    #[test]
    fn build_parent_locator_round_trips_through_parse_parent_locator() {
        let mut region = built_metadata_region();
        let item_len = build_parent_locator(
            &mut region,
            PARENT_LOCATOR_ITEM_OFFSET,
            &PIN_PARENT_DATA_WRITE_GUID,
            KEY_RELATIVE_PATH,
            "../images/parent.vhdx",
        )
        .expect("locator should build");

        let start = PARENT_LOCATOR_ITEM_OFFSET as usize;
        let locator =
            parse_parent_locator(&region[start..start + item_len]).expect("item should parse");

        assert_eq!(locator.defect, None);
        assert!(locator.is_vhdx_locator_type());
        assert_eq!(locator.reserved, 0);
        assert_eq!(locator.key_value_count, 2);
        assert_eq!(locator.entries().len(), 2);
        for entry in locator.entries() {
            assert_eq!(entry.defect, None);
        }
        assert_eq!(
            locator.parent_linkage(),
            Some(&b"{f88d4d92-6fcc-408d-9bef-9b7c89f15c89}"[..])
        );
        assert!(locator.linkage_matches(&render_guid_braced(&PIN_PARENT_DATA_WRITE_GUID)));
        assert_eq!(
            locator.preferred_path(),
            Some(&b"../images/parent.vhdx"[..])
        );
        assert_eq!(locator.relative_path(), Some(&b"../images/parent.vhdx"[..]));
        assert_eq!(locator.absolute_win32_path(), None);
        assert_eq!(locator.volume_path(), None);
    }

    #[test]
    fn build_parent_locator_round_trips_an_absolute_win32_path_key() {
        let mut region = built_metadata_region();
        let item_len = build_parent_locator(
            &mut region,
            PARENT_LOCATOR_ITEM_OFFSET,
            &PIN_PARENT_DATA_WRITE_GUID,
            KEY_ABSOLUTE_WIN32_PATH,
            "/srv/images/parent.vhdx",
        )
        .expect("locator should build");

        // absolute_win32_path is six characters longer than
        // relative_path, and the item grows by exactly those twelve
        // bytes plus the longer value.
        assert_eq!(item_len, 148 + 38 + 46);

        let start = PARENT_LOCATOR_ITEM_OFFSET as usize;
        let locator =
            parse_parent_locator(&region[start..start + item_len]).expect("item should parse");
        assert_eq!(locator.defect, None);
        assert_eq!(
            locator.absolute_win32_path(),
            Some(&b"/srv/images/parent.vhdx"[..])
        );
        assert_eq!(locator.relative_path(), None);
        assert_eq!(
            locator.preferred_path(),
            Some(&b"/srv/images/parent.vhdx"[..])
        );
    }

    #[test]
    fn build_parent_locator_refuses_a_key_it_does_not_emit() {
        let mut region = built_metadata_region();
        let pristine = region.clone();

        // volume_path is a real spec key, and refused like any other:
        // it needs a Windows volume GUID no Linux producer can obtain.
        assert_eq!(
            build_parent_locator(
                &mut region,
                PARENT_LOCATOR_ITEM_OFFSET,
                &PIN_PARENT_DATA_WRITE_GUID,
                KEY_VOLUME_PATH,
                "x"
            ),
            Err(VhdxBuildError::UnknownKey)
        );
        assert_eq!(
            build_parent_locator(
                &mut region,
                PARENT_LOCATOR_ITEM_OFFSET,
                &PIN_PARENT_DATA_WRITE_GUID,
                KEY_PARENT_LINKAGE,
                "x"
            ),
            Err(VhdxBuildError::UnknownKey)
        );
        assert_eq!(
            build_parent_locator(
                &mut region,
                PARENT_LOCATOR_ITEM_OFFSET,
                &PIN_PARENT_DATA_WRITE_GUID,
                b"relative_pat",
                "x"
            ),
            Err(VhdxBuildError::UnknownKey)
        );
        assert_eq!(region, pristine);
    }

    #[test]
    fn build_parent_locator_refuses_an_empty_path() {
        let mut region = built_metadata_region();
        let pristine = region.clone();
        assert_eq!(
            build_parent_locator(
                &mut region,
                PARENT_LOCATOR_ITEM_OFFSET,
                &PIN_PARENT_DATA_WRITE_GUID,
                KEY_RELATIVE_PATH,
                ""
            ),
            Err(VhdxBuildError::PathEmpty)
        );
        assert_eq!(region, pristine);
    }

    #[test]
    fn build_parent_locator_path_limit_is_260_utf16_code_units() {
        // 260 code units is MAX_PARENT_LOCATOR_VALUE_UTF16_BYTES (520 bytes),
        // the bound this crate's own parser marks ValueTooLong past --
        // so 260 must build and parse clean, and 261 must be refused
        // rather than written and then flagged by our own reader.
        let longest = core::str::from_utf8(&[b'a'; 260]).expect("ascii is utf-8");
        let too_long = core::str::from_utf8(&[b'a'; 261]).expect("ascii is utf-8");

        let mut region = built_metadata_region();
        let item_len = build_parent_locator(
            &mut region,
            PARENT_LOCATOR_ITEM_OFFSET,
            &PIN_PARENT_DATA_WRITE_GUID,
            KEY_RELATIVE_PATH,
            longest,
        )
        .expect("260 code units should build");
        assert_eq!(item_len, 148 + 26 + 520);

        let start = PARENT_LOCATOR_ITEM_OFFSET as usize;
        let locator =
            parse_parent_locator(&region[start..start + item_len]).expect("item should parse");
        assert_eq!(locator.defect, None);
        assert_eq!(locator.preferred_path(), Some(&[b'a'; 260][..]));

        let mut fresh = built_metadata_region();
        let pristine = fresh.clone();
        assert_eq!(
            build_parent_locator(
                &mut fresh,
                PARENT_LOCATOR_ITEM_OFFSET,
                &PIN_PARENT_DATA_WRITE_GUID,
                KEY_RELATIVE_PATH,
                too_long
            ),
            Err(VhdxBuildError::PathTooLong)
        );
        assert_eq!(fresh, pristine);
    }

    #[test]
    fn build_parent_locator_counts_a_non_bmp_character_as_two_code_units() {
        // U+1F600 is one character, one `char`, four UTF-8 bytes and
        // *two* UTF-16 code units. The limit is code units, so 130 of
        // them exhaust the same budget 260 ASCII characters do, and 131
        // overruns it -- even though 131 characters is half the
        // character count the ASCII case accepts.
        let mut buf = [0u8; 131 * 4];
        for chunk in buf.chunks_mut(4) {
            chunk.copy_from_slice("\u{1F600}".as_bytes());
        }
        let at_limit = core::str::from_utf8(&buf[..130 * 4]).expect("well-formed utf-8");
        let over_limit = core::str::from_utf8(&buf).expect("well-formed utf-8");
        assert_eq!(at_limit.chars().count(), 130);
        assert_eq!(over_limit.chars().count(), 131);

        let mut region = built_metadata_region();
        let item_len = build_parent_locator(
            &mut region,
            PARENT_LOCATOR_ITEM_OFFSET,
            &PIN_PARENT_DATA_WRITE_GUID,
            KEY_RELATIVE_PATH,
            at_limit,
        )
        .expect("260 code units should build");
        assert_eq!(item_len, 148 + 26 + 520);

        let mut fresh = built_metadata_region();
        assert_eq!(
            build_parent_locator(
                &mut fresh,
                PARENT_LOCATOR_ITEM_OFFSET,
                &PIN_PARENT_DATA_WRITE_GUID,
                KEY_RELATIVE_PATH,
                over_limit
            ),
            Err(VhdxBuildError::PathTooLong)
        );
    }

    #[test]
    fn build_parent_locator_refuses_a_short_region_without_writing() {
        // One byte short of the item's end. Nothing may be written --
        // in particular the entry count must still say five, or the
        // region would describe an item that is not there.
        let mut region = std::vec![0u8; 0x11000];
        build_metadata(
            &mut region,
            2 * 1024 * 1024,
            64 * 1024 * 1024,
            512,
            4096,
            true,
        );
        let item_len = 148 + 26 + 22;
        region.truncate(PARENT_LOCATOR_ITEM_OFFSET as usize + item_len - 1);
        let pristine = region.clone();

        assert_eq!(
            build_parent_locator(
                &mut region,
                PARENT_LOCATOR_ITEM_OFFSET,
                &PIN_PARENT_DATA_WRITE_GUID,
                KEY_RELATIVE_PATH,
                "parent.vhdx"
            ),
            Err(VhdxBuildError::BufferTooSmall)
        );
        assert_eq!(region, pristine);
        assert_eq!(le_u16(&region, METADATA_TABLE_ENTRY_COUNT_OFFSET), 5);

        // And exactly the item's length is enough.
        let mut exact = std::vec![0u8; 0x11000];
        build_metadata(
            &mut exact,
            2 * 1024 * 1024,
            64 * 1024 * 1024,
            512,
            4096,
            true,
        );
        exact.truncate(PARENT_LOCATOR_ITEM_OFFSET as usize + item_len);
        assert_eq!(
            build_parent_locator(
                &mut exact,
                PARENT_LOCATOR_ITEM_OFFSET,
                &PIN_PARENT_DATA_WRITE_GUID,
                KEY_RELATIVE_PATH,
                "parent.vhdx"
            ),
            Ok(item_len)
        );
    }

    // ====================================================================
    // Active-header selection
    // ====================================================================

    /// Enough of a VHDX file to hold both headers: header 2 starts at
    /// `HEADER2_OFFSET` and is `HEADER_SIZE` long.
    const HEADERS_REGION_LEN: usize = HEADER2_OFFSET as usize + HEADER_SIZE;

    /// The two header slots of a VHDX file, served one sector at a time
    /// through a `CallTable`, so `read_active_header` can be driven
    /// without a device. Nothing else in the file is populated —
    /// selection reads the headers and nothing further.
    struct HeadersFixture {
        region: [u8; HEADERS_REGION_LEN],
    }

    // Same shape and the same reason as `STAGE_FIXTURE`: the reader is
    // an `extern "C" fn` and closes over nothing, so the fixture has to
    // be a global and the lock is what keeps concurrent tests off each
    // other's bytes.
    static HEADERS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut HEADERS_FIXTURE: HeadersFixture = HeadersFixture {
        region: [0u8; HEADERS_REGION_LEN],
    };

    fn headers_lock() -> std::sync::MutexGuard<'static, ()> {
        HEADERS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Serve one sector out of the headers fixture.
    ///
    /// Every access goes through a raw pointer rather than a reference,
    /// because a reference to a `static mut` is what `static_mut_refs`
    /// forbids.
    unsafe extern "C" fn headers_read_sector(
        _device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        let start = (sector as usize).saturating_mul(sector_size);
        match start.checked_add(sector_size) {
            Some(end) if end <= HEADERS_REGION_LEN => {}
            _ => return false,
        }
        let base = core::ptr::addr_of!(HEADERS_FIXTURE.region) as *const u8;
        core::ptr::copy_nonoverlapping(base.add(start), out_buf, sector_size);
        true
    }

    /// Zero the fixture and place each supplied header image in its
    /// slot. A `None` slot is left as zeros, which fails
    /// `VhdxHeader::parse`'s signature check — an unparseable header.
    ///
    /// # Safety
    ///
    /// The caller must hold `HEADERS_LOCK` for as long as it then uses
    /// the fixture.
    unsafe fn install_headers(header1: Option<&[u8]>, header2: Option<&[u8]>) {
        let region = core::ptr::addr_of_mut!(HEADERS_FIXTURE.region) as *mut u8;
        core::ptr::write_bytes(region, 0, HEADERS_REGION_LEN);
        for (offset, image) in [
            (HEADER1_OFFSET as usize, header1),
            (HEADER2_OFFSET as usize, header2),
        ] {
            if let Some(bytes) = image {
                assert_eq!(bytes.len(), HEADER_SIZE);
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), region.add(offset), HEADER_SIZE);
            }
        }
    }

    /// Run `VhdxState::read_active_header` against the fixture.
    ///
    /// # Safety
    ///
    /// The caller must hold `HEADERS_LOCK`.
    unsafe fn read_active(sector_size: usize) -> Option<VhdxHeader> {
        let call_table = shared::CallTable {
            read_input_sector: headers_read_sector,
            ..stub_call_table()
        };
        let mut bytes_read = 0u64;
        VhdxState::read_active_header(
            &call_table,
            0,
            sector_size,
            (HEADERS_REGION_LEN / sector_size) as u64,
            &mut bytes_read,
        )
    }

    /// A header with the given sequence number, as `build_header`
    /// writes it — including the `DataWriteGuid` it derives from that
    /// sequence number, which is what makes the two headers in a test
    /// distinguishable.
    fn header_image(sequence_number: u64) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        build_header(&mut buf, sequence_number);
        buf
    }

    fn guid_of(buf: &[u8]) -> [u8; 16] {
        let mut guid = [0u8; 16];
        guid.copy_from_slice(
            &buf[HEADER_DATA_WRITE_GUID_OFFSET..HEADER_DATA_WRITE_GUID_OFFSET + 16],
        );
        guid
    }

    #[test]
    fn active_header_is_the_higher_sequence_number() {
        // Header 2 is the newer one, so its DataWriteGuid is the
        // identity a differencing child of this parent must record.
        for sector_size in [512usize, 4096] {
            let _guard = headers_lock();
            let h1 = header_image(1);
            let h2 = header_image(9);
            let active = unsafe {
                install_headers(Some(&h1), Some(&h2));
                read_active(sector_size)
            }
            .expect("both headers parse");
            assert_eq!(active.sequence_number, 9, "sector_size {sector_size}");
            assert_eq!(
                active.data_write_guid,
                guid_of(&h2),
                "sector_size {sector_size}"
            );
            assert_ne!(active.data_write_guid, guid_of(&h1));
        }
    }

    #[test]
    fn active_header_is_header_one_when_sequence_numbers_tie() {
        // `build_header` derives the GUID from the sequence number, so
        // two headers with the same sequence number would be
        // indistinguishable. Give header 2 a marker GUID and re-checksum
        // it, so a wrong tie-break is visible rather than silent.
        for sector_size in [512usize, 4096] {
            let _guard = headers_lock();
            let h1 = header_image(5);
            let mut h2 = header_image(5);
            let marker = [0xa5u8; 16];
            h2[HEADER_DATA_WRITE_GUID_OFFSET..HEADER_DATA_WRITE_GUID_OFFSET + 16]
                .copy_from_slice(&marker);
            let checksum = compute_crc32c(&h2[..HEADER_SIZE], HEADER_CHECKSUM_OFFSET);
            write_le_u32(&mut h2, HEADER_CHECKSUM_OFFSET, checksum);
            assert!(VhdxHeader::parse(&h2).is_some(), "re-checksummed header 2");

            let active = unsafe {
                install_headers(Some(&h1), Some(&h2));
                read_active(sector_size)
            }
            .expect("both headers parse");
            assert_eq!(active.sequence_number, 5, "sector_size {sector_size}");
            assert_eq!(
                active.data_write_guid,
                guid_of(&h1),
                "a tie must pick header 1, sector_size {sector_size}"
            );
            assert_ne!(active.data_write_guid, marker);
        }
    }

    #[test]
    fn active_header_falls_back_to_the_one_that_parses() {
        let h = header_image(3);

        let from_header2 = {
            let _guard = headers_lock();
            unsafe {
                install_headers(None, Some(&h));
                read_active(512)
            }
        }
        .expect("header 2 parses");
        assert_eq!(from_header2.data_write_guid, guid_of(&h));

        let from_header1 = {
            let _guard = headers_lock();
            unsafe {
                install_headers(Some(&h), None);
                read_active(512)
            }
        }
        .expect("header 1 parses");
        assert_eq!(from_header1.data_write_guid, guid_of(&h));
    }

    #[test]
    fn no_active_header_when_neither_parses() {
        let _guard = headers_lock();
        let active = unsafe {
            install_headers(None, None);
            read_active(512)
        };
        assert!(active.is_none());
    }
}
