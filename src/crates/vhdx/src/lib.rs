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
    le_u16, le_u32, le_u64, utf16_to_utf8, write_le_u16, write_le_u32, write_le_u64,
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

/// Metadata table entry size.
pub const METADATA_TABLE_ENTRY_SIZE: usize = 32;
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

// Parent Locator GUID: A8D35F2D-B30B-454D-ABF7-D3D84834AB0C
const PARENT_LOCATOR_GUID: [u8; 16] = [
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

        let mut log_guid = [0u8; 16];
        log_guid.copy_from_slice(&buf[HEADER_LOG_GUID_OFFSET..HEADER_LOG_GUID_OFFSET + 16]);

        let log_length = le_u32(buf, HEADER_LOG_LENGTH_OFFSET);
        let log_offset = le_u64(buf, HEADER_LOG_OFFSET_OFFSET);

        Some(VhdxHeader {
            signature,
            checksum,
            sequence_number,
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

/// Longest key, in UTF-16 source bytes, that is decoded: 32 code units.
///
/// **A parser resource bound, not a spec limit.** SPEC(VHDX) 2.6.2.6.2
/// stores `KeyLength` as a u16 and constrains it no further. The
/// longest key any known producer writes is `absolute_win32_path`, 19
/// characters. A longer key is marked `KeyTooLong` with its raw offset
/// and length intact.
pub const MAX_PARENT_LOCATOR_KEY_UTF16: usize = 64;

/// Longest value, in UTF-16 source bytes, that is decoded: 260 code
/// units, Windows `MAX_PATH`.
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
pub const MAX_PARENT_LOCATOR_VALUE_UTF16: usize = 520;

/// Buffer for a decoded key.
///
/// One UTF-16 code unit (2 source bytes) encodes to at most 3 UTF-8
/// bytes, and a surrogate pair (4 source bytes) to exactly 4, so UTF-8
/// output is never more than 3/2 of the UTF-16 input. A key within
/// `MAX_PARENT_LOCATOR_KEY_UTF16` therefore always fits here, and
/// `utf16_to_utf8` can only refuse it for being ill-formed.
pub const MAX_PARENT_LOCATOR_KEY_UTF8: usize = MAX_PARENT_LOCATOR_KEY_UTF16 * 3 / 2;

/// Buffer for a decoded value. See `MAX_PARENT_LOCATOR_KEY_UTF8` for
/// why 3/2 of the UTF-16 cap is always enough.
pub const MAX_PARENT_LOCATOR_VALUE_UTF8: usize = MAX_PARENT_LOCATOR_VALUE_UTF16 * 3 / 2;

/// Largest parent locator item `parse_metadata` will stage into memory.
///
/// **A parser resource bound, not a spec limit.** The measured Hyper-V
/// item is 674 bytes in total and instar's will be smaller, so this
/// clears real images with room. A larger item is not parsed at all —
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
/// instar's own `build_metadata` would write.
pub const METADATA_ITEMS_MIN_OFFSET: u32 = 0x10000;

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
    /// The key is longer than `MAX_PARENT_LOCATOR_KEY_UTF16`.
    KeyTooLong,
    /// The value is longer than `MAX_PARENT_LOCATOR_VALUE_UTF16`, which
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

    if entry.key_length as usize > MAX_PARENT_LOCATOR_KEY_UTF16 {
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

    if entry.value_length as usize > MAX_PARENT_LOCATOR_VALUE_UTF16 {
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
    /// Returns `None` if the image is invalid, a differencing disk,
    /// or I/O fails.
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

        let header = match (&header1, &header2) {
            (Some(h1), Some(h2)) => {
                if h1.sequence_number >= h2.sequence_number {
                    h1
                } else {
                    h2
                }
            }
            (Some(h1), None) => h1,
            (None, Some(h2)) => h2,
            (None, None) => return None,
        };

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

        // Reject differencing disks
        if metadata.has_parent {
            return None;
        }

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
            bat_cached_sector: u64::MAX,
            bat_cache_buf,
            data_cached_sector: u64::MAX,
            data_cache_buf,
        })
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
            // PARTIALLY_PRESENT requires parent — we rejected
            // differencing disks in init, so treat as error.
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
        let over = (MAX_PARENT_LOCATOR_VALUE_UTF16 + 2) as u16;
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
        // 33 code units, one past MAX_PARENT_LOCATOR_KEY_UTF16 / 2.
        let len = build_locator_item(&[("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "value")], &mut buf);

        let locator = parse_parent_locator(&buf[..len]).unwrap();
        let entry = &locator.entries()[0];
        assert_eq!(entry.key_length as usize, MAX_PARENT_LOCATOR_KEY_UTF16 + 2);
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
}
