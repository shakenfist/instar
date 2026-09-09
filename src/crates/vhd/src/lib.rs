//! VHD/VPC (Virtual Hard Disk) format parsing.
//!
//! Provides VHD footer and dynamic header parsing, BAT (Block Allocation
//! Table) reading, and block lookup for dynamic VHD images. Fixed VHDs
//! (disk_type=2) are treated as raw data with a trailing footer.
//!
//! # Parent locators do no I/O
//!
//! The differencing-image parsers in this module ([`VhdParentInfo`],
//! [`VhdParentLocatorTable`]) take byte slices and never touch a
//! [`CallTable`]. Where locator platform data lives outside the 1024-byte
//! header, the caller reads it and hands it over as a [`VhdImageWindow`].
//!
//! This is a deliberate departure from the local precedent, and it is
//! worth naming so a later reader does not conclude the module is simply
//! inconsistent. `qcow2::read_backing_file` is the shape this module
//! follows in one respect — the header keeps the offset and length, and a
//! separate function produces the string — but it takes a `CallTable` and
//! reads sectors itself. This module does not, so that phase 9 can point a
//! coverage-guided fuzz target at [`VhdParentInfo::parse`] the way
//! `fuzz_vhd_footer` points at [`VhdFooter::parse`]. See decision 7 of
//! `docs/plans/PLAN-differencing-phase-03-parse.md`.

#![no_std]
#![allow(clippy::too_many_arguments)]

use shared::{
    be_u16, be_u32, be_u64, utf16_to_utf8, write_be_u16, write_be_u32, write_be_u64,
    AllocationSummary, CallTable, MapExtent, MapExtentCoalescer, MapExtentState, MAX_SECTOR_SIZE,
};

// ============================================================================
// VHD footer field offsets (all big-endian)
// ============================================================================

/// Footer size in bytes.
pub const FOOTER_SIZE: usize = 512;

/// Footer cookie offset: "conectix" (8 bytes, big-endian).
pub const FOOTER_COOKIE_OFFSET: usize = 0;
/// Footer features offset (u32 BE).
pub const FOOTER_FEATURES_OFFSET: usize = 8;
/// Footer format version offset (u32 BE).
pub const FOOTER_FORMAT_VERSION_OFFSET: usize = 12;
/// Footer data offset (u64 BE) — offset to dynamic header.
pub const FOOTER_DATA_OFFSET_OFFSET: usize = 16;
/// Footer timestamp offset (u32 BE).
pub const FOOTER_TIMESTAMP_OFFSET: usize = 24;
/// Footer creator application offset (4 bytes).
pub const FOOTER_CREATOR_APP_OFFSET: usize = 28;
/// Footer creator version offset (u32 BE).
pub const FOOTER_CREATOR_VERSION_OFFSET: usize = 32;
/// Footer creator host OS offset (u32 BE).
pub const FOOTER_CREATOR_HOST_OFFSET: usize = 36;
/// Footer original size offset (u64 BE).
pub const FOOTER_ORIGINAL_SIZE_OFFSET: usize = 40;
/// Footer current size offset (u64 BE).
pub const FOOTER_CURRENT_SIZE_OFFSET: usize = 48;
/// Footer disk geometry offset (4 bytes: CHS).
pub const FOOTER_GEOMETRY_OFFSET: usize = 56;
/// Footer disk type offset (u32 BE).
pub const FOOTER_DISK_TYPE_OFFSET: usize = 60;
/// Footer checksum offset (u32 BE).
pub const FOOTER_CHECKSUM_OFFSET: usize = 64;
/// Footer unique ID offset (16 bytes UUID).
pub const FOOTER_UUID_OFFSET: usize = 68;
/// Footer saved state offset (u8).
pub const FOOTER_SAVED_STATE_OFFSET: usize = 84;

// ============================================================================
// VHD dynamic header field offsets (all big-endian)
// ============================================================================

/// Dynamic header size in bytes.
pub const DYNAMIC_HEADER_SIZE: usize = 1024;

/// Dynamic header cookie offset: "cxsparse" (8 bytes).
pub const DYN_COOKIE_OFFSET: usize = 0;
/// Dynamic header data offset (u64 BE) — unused, should be 0xFFFFFFFFFFFFFFFF.
pub const DYN_DATA_OFFSET_OFFSET: usize = 8;
/// Dynamic header table offset (u64 BE) — byte offset to BAT.
pub const DYN_TABLE_OFFSET_OFFSET: usize = 16;
/// Dynamic header version offset (u32 BE).
pub const DYN_HEADER_VERSION_OFFSET: usize = 24;
/// Dynamic header max table entries (u32 BE) — number of BAT entries.
pub const DYN_MAX_TABLE_ENTRIES_OFFSET: usize = 28;
/// Dynamic header block size (u32 BE) — bytes per data block.
pub const DYN_BLOCK_SIZE_OFFSET: usize = 32;
/// Dynamic header checksum offset (u32 BE).
pub const DYN_CHECKSUM_OFFSET: usize = 36;

// ----------------------------------------------------------------------------
// Differencing-only dynamic header fields. Offsets and endiannesses are
// pinned in docs/plans/PLAN-differencing-phase-01-pin.md, "VHD — the
// dynamic header of a differencing child"; every row there is backed by an
// xxd of a Hyper-V image.
// ----------------------------------------------------------------------------

/// Parent unique id offset: 16 opaque bytes, the parent footer's bytes
/// 68..84 copied verbatim. Not byte-swapped and not a parsed UUID.
pub const DYN_PARENT_UNIQUE_ID_OFFSET: usize = 40;
/// Parent timestamp offset (u32 BE), seconds since 2000-01-01.
pub const DYN_PARENT_TIMESTAMP_OFFSET: usize = 56;
/// Parent unicode name offset. UTF-16 **BIG** endian — the opposite of the
/// locator platform data 512 bytes further on.
pub const DYN_PARENT_NAME_OFFSET: usize = 64;
/// Parent unicode name field size in bytes: 256 UTF-16 code units.
///
/// This is the bound for *parsing*: a name filling all 512 bytes with no
/// terminator is valid and complete, and a reader must never scan past the
/// field looking for one (decision 3; over-reading here is libvhdi defect
/// C). instar's own *emitter* refuses at 256 code units and accepts at
/// most 255, so that everything instar writes keeps a terminating NUL
/// inside the field and reads back correctly through libvhdi
/// (PLAN-differencing-phase-01-pin.md:716). The two numbers are opposite
/// directions of the same field, not a typo in either.
pub const DYN_PARENT_NAME_SIZE: usize = 512;
/// Parent locator table offset: 8 entries of 24 bytes.
pub const DYN_PARENT_LOCATORS_OFFSET: usize = 576;

/// Number of parent locator entries. Fixed at 8 by SPEC(VHD).
pub const PARENT_LOCATOR_COUNT: usize = 8;
/// Size of one parent locator entry in bytes.
pub const PARENT_LOCATOR_ENTRY_SIZE: usize = 24;
/// Size of the whole parent locator table in bytes.
pub const PARENT_LOCATOR_TABLE_SIZE: usize = PARENT_LOCATOR_COUNT * PARENT_LOCATOR_ENTRY_SIZE;

/// Locator entry: platform code offset (4 ASCII bytes, not byte-swapped).
pub const LOC_PLATFORM_CODE_OFFSET: usize = 0;
/// Locator entry: platform data space offset (u32 BE, a byte count).
pub const LOC_DATA_SPACE_OFFSET: usize = 4;
/// Locator entry: platform data length offset (u32 BE, bytes).
pub const LOC_DATA_LENGTH_OFFSET: usize = 8;
/// Locator entry: reserved offset (u32 BE).
pub const LOC_RESERVED_OFFSET: usize = 12;
/// Locator entry: platform data offset (u64 BE, absolute in the file).
pub const LOC_DATA_OFFSET_OFFSET: usize = 16;

/// Worst-case UTF-8 length of a fully populated parent unicode name.
///
/// 256 UTF-16 code units; the worst case is 256 code units in
/// `U+0800..=U+FFFF` at three UTF-8 bytes each. Surrogate pairs are
/// cheaper (two code units produce four bytes), so 768 is the tight bound.
/// A caller passing `[0u8; MAX_PARENT_NAME_UTF8]` to
/// [`VhdParentInfo::decode_name`] can never be refused for want of space.
pub const MAX_PARENT_NAME_UTF8: usize = 768;

// ============================================================================
// VHD constants
// ============================================================================

/// VHD footer cookie: "conectix" (big-endian u64).
pub const VHD_COOKIE: u64 = 0x636f_6e65_6374_6978;

/// VHD dynamic header cookie: "cxsparse" (big-endian u64).
pub const CXSPARSE_COOKIE: u64 = 0x6378_7370_6172_7365;

/// VHD format version 1.0 (stored as major.minor in u32 BE).
pub const VHD_VERSION_1_0: u32 = 0x0001_0000;

/// Disk type: Fixed (raw data + footer).
pub const DISK_TYPE_FIXED: u32 = 2;
/// Disk type: Dynamic (footer + dynamic header + BAT + blocks).
pub const DISK_TYPE_DYNAMIC: u32 = 3;
/// Disk type: Differencing (has parent locators).
pub const DISK_TYPE_DIFFERENCING: u32 = 4;

/// BAT entry value indicating an unallocated block.
pub const BAT_UNALLOCATED: u32 = 0xFFFF_FFFF;

/// Default block size (2 MiB).
pub const DEFAULT_BLOCK_SIZE: u32 = 2 * 1024 * 1024;

/// VHD features: reserved bit (must be set).
pub const FEATURES_RESERVED: u32 = 0x0000_0002;

// ============================================================================
// VHD footer parsing
// ============================================================================

/// Parsed VHD footer fields.
pub struct VhdFooter {
    pub cookie: u64,
    pub features: u32,
    pub format_version: u32,
    pub data_offset: u64,
    pub original_size: u64,
    pub current_size: u64,
    pub cylinders: u16,
    pub heads: u8,
    pub sectors_per_track: u8,
    pub disk_type: u32,
    pub checksum: u32,
    pub uuid: [u8; 16],
}

impl VhdFooter {
    /// Parse a VHD footer from raw bytes.
    ///
    /// `buf` must contain at least 512 bytes starting at the footer.
    /// Returns `None` if the buffer is too small or the cookie is invalid.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < FOOTER_SIZE {
            return None;
        }

        let cookie = be_u64(buf, FOOTER_COOKIE_OFFSET);
        if cookie != VHD_COOKIE {
            return None;
        }

        let features = be_u32(buf, FOOTER_FEATURES_OFFSET);
        let format_version = be_u32(buf, FOOTER_FORMAT_VERSION_OFFSET);
        let data_offset = be_u64(buf, FOOTER_DATA_OFFSET_OFFSET);
        let original_size = be_u64(buf, FOOTER_ORIGINAL_SIZE_OFFSET);
        let current_size = be_u64(buf, FOOTER_CURRENT_SIZE_OFFSET);

        let cylinders = be_u16(buf, FOOTER_GEOMETRY_OFFSET);
        let heads = buf[FOOTER_GEOMETRY_OFFSET + 2];
        let sectors_per_track = buf[FOOTER_GEOMETRY_OFFSET + 3];

        let disk_type = be_u32(buf, FOOTER_DISK_TYPE_OFFSET);
        let checksum = be_u32(buf, FOOTER_CHECKSUM_OFFSET);

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[FOOTER_UUID_OFFSET..FOOTER_UUID_OFFSET + 16]);

        Some(VhdFooter {
            cookie,
            features,
            format_version,
            data_offset,
            original_size,
            current_size,
            cylinders,
            heads,
            sectors_per_track,
            disk_type,
            checksum,
            uuid,
        })
    }
}

// ============================================================================
// VHD dynamic header parsing
// ============================================================================

/// Parsed VHD dynamic header fields.
pub struct VhdDynamicHeader {
    pub cookie: u64,
    pub table_offset: u64,
    pub header_version: u32,
    pub max_table_entries: u32,
    pub block_size: u32,
    pub checksum: u32,
}

impl VhdDynamicHeader {
    /// Parse a VHD dynamic header from raw bytes.
    ///
    /// `buf` must contain at least 1024 bytes starting at the dynamic
    /// header. Returns `None` if the buffer is too small or the cookie
    /// is invalid.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < DYNAMIC_HEADER_SIZE {
            return None;
        }

        let cookie = be_u64(buf, DYN_COOKIE_OFFSET);
        if cookie != CXSPARSE_COOKIE {
            return None;
        }

        let table_offset = be_u64(buf, DYN_TABLE_OFFSET_OFFSET);
        let header_version = be_u32(buf, DYN_HEADER_VERSION_OFFSET);
        let max_table_entries = be_u32(buf, DYN_MAX_TABLE_ENTRIES_OFFSET);
        let block_size = be_u32(buf, DYN_BLOCK_SIZE_OFFSET);
        let checksum = be_u32(buf, DYN_CHECKSUM_OFFSET);

        Some(VhdDynamicHeader {
            cookie,
            table_offset,
            header_version,
            max_table_entries,
            block_size,
            checksum,
        })
    }
}

// ============================================================================
// VHD parent locator parsing (differencing images)
// ============================================================================
//
// Layout authority: docs/plans/PLAN-differencing-phase-01-pin.md, sections
// "VHD — the dynamic header of a differencing child" and "VHD — the eight
// parent locator entries". Every offset there is backed by an xxd of a
// Hyper-V-produced image; do not rediscover them.

/// Bytes the caller has read out of the image, tagged with the absolute
/// file offset of `bytes[0]`.
///
/// Locator platform data lives at an absolute file offset outside the
/// 1024-byte dynamic header, and this parser performs no I/O, so the
/// caller reads whatever it likes — a sector, two sectors, an mmap of the
/// whole file — and hands the bytes over tagged with where they came from.
/// The parser, rather than the caller, then turns an offset read out of
/// the image into a slice index: [`VhdImageWindow::slice_at`] is the only
/// place in this module where that conversion happens.
///
/// The same type serves both sides of the sandbox boundary. A guest
/// operation fills a `[u8; MAX_SECTOR_SIZE]` through the call table and
/// wraps it; the host wraps a `pread` buffer or a whole-file mapping.
#[derive(Debug, Clone, Copy)]
pub struct VhdImageWindow<'a> {
    /// Absolute file offset of `bytes[0]`.
    pub file_offset: u64,
    /// The bytes the caller has read.
    pub bytes: &'a [u8],
}

impl<'a> VhdImageWindow<'a> {
    /// The `len` bytes at absolute file offset `offset`, or `None` when
    /// that range is not wholly inside this window.
    ///
    /// Every step is checked: `offset >= self.file_offset`, both the
    /// relative start and the length convert to `usize` without
    /// truncation, and `rel.checked_add(len)` is compared against
    /// `bytes.len()` before any indexing.
    pub fn slice_at(&self, offset: u64, len: u64) -> Option<&'a [u8]> {
        if offset < self.file_offset {
            return None;
        }
        let rel = usize::try_from(offset - self.file_offset).ok()?;
        let len = usize::try_from(len).ok()?;
        let end = rel.checked_add(len)?;
        if end > self.bytes.len() {
            return None;
        }
        Some(&self.bytes[rel..end])
    }
}

/// The image extents a locator's platform data must not collide with.
///
/// A pair of bare `u64`s would be silently swappable at a call site, and
/// both bounds here police values read out of untrusted image data.
///
/// **The BAT is deliberately not covered.** A locator whose platform data
/// points into the block allocation table is not marked malformed, because
/// the only source for the BAT's extent is `table_offset` and
/// `max_table_entries` in the very header whose locators are being
/// validated — using an untrusted header to validate its own contents
/// proves nothing. Phase 11 (host-side chain walking) must not assume this
/// parser has already refused such an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhdImageBounds {
    /// Total image length in bytes.
    pub image_len: u64,
    /// Absolute file offset of the 1024-byte dynamic header — the
    /// footer's `data_offset`, 512 for everything in the corpus and for
    /// everything instar emits.
    pub header_offset: u64,
}

/// The platform code of a parent locator entry: four ASCII bytes stored in
/// file order and **not** byte-swapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdPlatform {
    /// Four zero bytes: the slot is unused.
    Unused,
    /// `W2ku` — absolute Unicode (UTF-16LE) pathname on Windows.
    W2ku,
    /// `W2ru` — Unicode (UTF-16LE) path relative to the differencing disk.
    W2ru,
    /// `Wi2k` — deprecated absolute Windows path.
    Wi2k,
    /// `Wi2r` — deprecated relative Windows path.
    Wi2r,
    /// `MacX` — a UTF-8 `file://` URL. Not decoded by this crate.
    MacX,
    /// `Mac ` — an opaque Mac OS alias blob. Not decoded by this crate.
    Mac,
    /// Any other four bytes, preserved verbatim.
    Other([u8; 4]),
}

impl VhdPlatform {
    /// Decode four raw platform code bytes.
    pub fn from_code(code: [u8; 4]) -> Self {
        match &code {
            [0, 0, 0, 0] => VhdPlatform::Unused,
            b"W2ku" => VhdPlatform::W2ku,
            b"W2ru" => VhdPlatform::W2ru,
            b"Wi2k" => VhdPlatform::Wi2k,
            b"Wi2r" => VhdPlatform::Wi2r,
            b"MacX" => VhdPlatform::MacX,
            b"Mac " => VhdPlatform::Mac,
            _ => VhdPlatform::Other(code),
        }
    }

    /// Selection rank for [`VhdParentLocatorTable::preferred_locator`]:
    /// `W2ru` (0) before `W2ku` (1) before `Wi2r` (2) before `Wi2k` (3).
    /// `None` for every non-Windows code, which is never selected
    /// (decision 5 of PLAN-differencing-phase-03-parse.md).
    pub fn preference(self) -> Option<u8> {
        match self {
            VhdPlatform::W2ru => Some(0),
            VhdPlatform::W2ku => Some(1),
            VhdPlatform::Wi2r => Some(2),
            VhdPlatform::Wi2k => Some(3),
            _ => None,
        }
    }

    /// Whether this code's platform data is a UTF-16 **little** endian
    /// string that [`VhdParentLocator::decode_path`] will decode.
    pub fn is_utf16le_path(self) -> bool {
        matches!(
            self,
            VhdPlatform::W2ku | VhdPlatform::W2ru | VhdPlatform::Wi2k | VhdPlatform::Wi2r
        )
    }
}

/// Why a parent locator entry, or an attempt to decode its platform data,
/// was refused.
///
/// Decision 4: a malformed entry is *marked*, not dropped, and its raw
/// fields are preserved, so phase 4 can say why it is refusing. The first
/// six variants are set at parse time and are purely structural; the last
/// three arise only when a caller asks for the string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdLocatorDefect {
    /// The platform code is populated but `platform_data_length` is zero:
    /// a locator that names nothing.
    EmptyData,
    /// `platform_data_offset + platform_data_length` overflows `u64`.
    OffsetOverflow,
    /// The platform data range extends past the end of the image.
    DataOutsideImage,
    /// The platform data range intersects the footer, either the copy at
    /// file offset 0 or the trailing one.
    OverlapsFooter,
    /// The platform data range intersects the 1024-byte dynamic header.
    OverlapsHeader,
    /// `platform_data_length` exceeds `platform_data_space`.
    LengthExceedsSpace,
    /// The caller supplied no window, or one that does not cover this
    /// entry's platform data range. Distinguishable from a decode failure
    /// on purpose: the caller can widen the window and retry.
    DataNotSupplied,
    /// The platform code is not one this crate decodes (`MacX` is UTF-8,
    /// `Mac ` is opaque, anything else is unknown).
    UnsupportedPlatformCode,
    /// `shared::utf16_to_utf8` refused: an odd byte count, an unpaired
    /// surrogate, or output that did not fit the caller's buffer.
    Undecodable,
}

/// One parent locator entry: 24 bytes at header offset
/// `+576 + slot * 24`.
///
/// Every raw field is preserved whether or not the entry validated;
/// `defect` records the first structural problem found. All four numeric
/// fields are big-endian in the image. `platform_code` is ASCII in file
/// order and is **not** byte-swapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhdParentLocator {
    /// Raw platform code bytes, exactly as they lie at `+0`.
    pub platform_code: [u8; 4],
    /// Platform data space at `+4`. A **byte** count, not the 512-byte
    /// sector count SPEC(VHD)'s wording implies — see the pin's "Where
    /// SPEC(VHD) and Hyper-V disagree: platform data space", where the
    /// sector reading is shown to be arithmetically impossible on both
    /// measured Hyper-V images.
    pub platform_data_space: u32,
    /// Platform data length at `+8`, in bytes, with no terminator.
    pub platform_data_length: u32,
    /// Reserved at `+12`. Preserved so later phases can assert that
    /// Hyper-V writes zero here.
    pub reserved: u32,
    /// Platform data offset at `+16`: an absolute byte offset in the file.
    pub platform_data_offset: u64,
    /// The first structural defect found, or `None`.
    pub defect: Option<VhdLocatorDefect>,
}

impl VhdParentLocator {
    /// An all-zero, unused entry.
    pub const EMPTY: VhdParentLocator = VhdParentLocator {
        platform_code: [0; 4],
        platform_data_space: 0,
        platform_data_length: 0,
        reserved: 0,
        platform_data_offset: 0,
        defect: None,
    };

    /// Parse one 24-byte entry and validate its offsets against `bounds`.
    ///
    /// Never returns `None` for a malformed entry: the entry comes back
    /// with `defect` set, raw fields intact (decision 4). `None` means
    /// only that `entry` is shorter than [`PARENT_LOCATOR_ENTRY_SIZE`].
    pub fn parse(entry: &[u8], bounds: &VhdImageBounds) -> Option<Self> {
        if entry.len() < PARENT_LOCATOR_ENTRY_SIZE {
            return None;
        }

        let mut platform_code = [0u8; 4];
        platform_code
            .copy_from_slice(&entry[LOC_PLATFORM_CODE_OFFSET..LOC_PLATFORM_CODE_OFFSET + 4]);
        let platform_data_space = be_u32(entry, LOC_DATA_SPACE_OFFSET);
        let platform_data_length = be_u32(entry, LOC_DATA_LENGTH_OFFSET);
        let reserved = be_u32(entry, LOC_RESERVED_OFFSET);
        let platform_data_offset = be_u64(entry, LOC_DATA_OFFSET_OFFSET);

        let defect = locator_defect(
            platform_code,
            platform_data_space,
            platform_data_length,
            platform_data_offset,
            bounds,
        );

        Some(VhdParentLocator {
            platform_code,
            platform_data_space,
            platform_data_length,
            reserved,
            platform_data_offset,
            defect,
        })
    }

    /// The decoded platform code.
    pub fn platform(&self) -> VhdPlatform {
        VhdPlatform::from_code(self.platform_code)
    }

    /// Whether the slot is empty (four zero platform code bytes).
    ///
    /// An unused slot is not a defect, and an unused slot appearing after
    /// a populated one does **not** terminate the table: SPEC(VHD) defines
    /// no sentinel, and the ordinary Hyper-V shape is two populated
    /// entries followed by six zero slots.
    pub fn is_unused(&self) -> bool {
        self.platform_code == [0u8; 4]
    }

    /// Whether this entry could name the parent: populated, defect-free,
    /// and carrying a Windows platform code.
    pub fn is_candidate(&self) -> bool {
        !self.is_unused() && self.defect.is_none() && self.platform().preference().is_some()
    }

    /// This entry's raw platform data bytes, trimmed at the first `0x0000`
    /// UTF-16 code unit if there is one.
    ///
    /// This is what [`VhdParentLocatorTable::preferred_locator`] compares
    /// when two entries share a platform code: equal codes share an
    /// encoding, UTF-16 encoding is injective, and the only wrinkle — one
    /// blob carrying a terminating NUL where the other does not — is
    /// removed by the trim. So the comparison needs no decode and no
    /// scratch buffer. A `0x0000` code unit is two zero bytes in either
    /// byte order, so the trim does not depend on endianness.
    pub fn raw_path_bytes<'a>(
        &self,
        data: &VhdImageWindow<'a>,
    ) -> Result<&'a [u8], VhdLocatorDefect> {
        if let Some(defect) = self.defect {
            return Err(defect);
        }
        if self.is_unused() {
            return Err(VhdLocatorDefect::EmptyData);
        }
        let bytes = data
            .slice_at(self.platform_data_offset, self.platform_data_length as u64)
            .ok_or(VhdLocatorDefect::DataNotSupplied)?;
        Ok(trim_at_nul_code_unit(bytes))
    }

    /// Decode this entry's platform data into `dst` as UTF-8, returning
    /// the number of bytes written.
    ///
    /// The platform data of `W2ku` / `W2ru` / `Wi2k` / `Wi2r` is UTF-16
    /// **LITTLE** endian — the opposite of the parent unicode name field
    /// 512 bytes earlier in the header. This is the call site that passes
    /// `big_endian = false` to `shared::utf16_to_utf8`; the other, in
    /// [`VhdParentInfo::decode_name`], passes `true`.
    ///
    /// Any other platform code is refused with `UnsupportedPlatformCode`
    /// rather than guessed at: `MacX` platform data is UTF-8 and `Mac `
    /// is an opaque blob, and `vhd-diff-locator-conflicting.vhd` exists in
    /// part to catch a reader that decodes every entry the same way.
    pub fn decode_path(
        &self,
        data: &VhdImageWindow<'_>,
        dst: &mut [u8],
    ) -> Result<usize, VhdLocatorDefect> {
        if let Some(defect) = self.defect {
            return Err(defect);
        }
        if self.is_unused() {
            return Err(VhdLocatorDefect::EmptyData);
        }
        if !self.platform().is_utf16le_path() {
            return Err(VhdLocatorDefect::UnsupportedPlatformCode);
        }
        let bytes = self.raw_path_bytes(data)?;
        utf16_to_utf8(bytes, false, dst).ok_or(VhdLocatorDefect::Undecodable)
    }
}

/// The first structural defect of a locator entry, or `None`.
///
/// Checked in this order: empty data, offset overflow, past end of image,
/// footer overlap, header overlap, length beyond space. An unused slot
/// (four zero platform code bytes) has no defect.
///
/// Every comparison here is on values read out of the image, so the
/// addition uses `checked_add` and nothing is indexed.
fn locator_defect(
    platform_code: [u8; 4],
    platform_data_space: u32,
    platform_data_length: u32,
    platform_data_offset: u64,
    bounds: &VhdImageBounds,
) -> Option<VhdLocatorDefect> {
    if platform_code == [0u8; 4] {
        return None;
    }
    if platform_data_length == 0 {
        return Some(VhdLocatorDefect::EmptyData);
    }

    let start = platform_data_offset;
    let end = match start.checked_add(platform_data_length as u64) {
        Some(end) => end,
        None => return Some(VhdLocatorDefect::OffsetOverflow),
    };
    if end > bounds.image_len {
        return Some(VhdLocatorDefect::DataOutsideImage);
    }

    // The footer copy at file offset 0, and the trailing footer. Both are
    // refused under one defect: a locator naming either is equally wrong.
    if ranges_overlap(start, end, 0, FOOTER_SIZE as u64) {
        return Some(VhdLocatorDefect::OverlapsFooter);
    }
    if let Some(tail_start) = bounds.image_len.checked_sub(FOOTER_SIZE as u64) {
        if ranges_overlap(start, end, tail_start, bounds.image_len) {
            return Some(VhdLocatorDefect::OverlapsFooter);
        }
    }

    let header_end = bounds
        .header_offset
        .saturating_add(DYNAMIC_HEADER_SIZE as u64);
    if ranges_overlap(start, end, bounds.header_offset, header_end) {
        return Some(VhdLocatorDefect::OverlapsHeader);
    }

    if platform_data_length > platform_data_space {
        return Some(VhdLocatorDefect::LengthExceedsSpace);
    }

    None
}

/// Whether two half-open ranges intersect.
fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

/// Truncate at the first `0x0000` UTF-16 code unit, if there is one.
fn trim_at_nul_code_unit(bytes: &[u8]) -> &[u8] {
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 {
            return &bytes[..i];
        }
        i += 2;
    }
    bytes
}

/// Why [`VhdParentLocatorTable::preferred_locator`] could not choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmbiguityReason {
    /// Both entries' platform data was available and the two differ.
    ContentsDiffer,
    /// No window covering both entries' platform data was supplied, so
    /// whether they agree is unknown. Conservatively ambiguous: this is a
    /// security boundary, and "I could not check whether they agree" must
    /// not read as "they agree".
    ContentsUnknown,
}

/// The outcome of selecting the entry that names the parent (decision 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferredLocator {
    /// Exactly one entry wins. `slot` indexes
    /// [`VhdParentLocatorTable::entries`].
    Found { slot: usize },
    /// No entry carries a Windows platform code, or every entry that does
    /// is unused or malformed. The caller reads `entries` to say why —
    /// decision 4 keeps the reason on the entries rather than duplicating
    /// it here.
    NotFound,
    /// Two entries share the winning platform code and do not agree.
    /// `first` is the lowest-slot winner; `second` is the lowest slot
    /// carrying the same code that disagrees with it. A third or later
    /// conflicting duplicate is not reported.
    Ambiguous {
        first: usize,
        second: usize,
        reason: AmbiguityReason,
    },
}

/// The eight parent locator entries, in slot order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhdParentLocatorTable {
    /// Slots 1..8 of SPEC(VHD), indexed 0..8.
    pub entries: [VhdParentLocator; PARENT_LOCATOR_COUNT],
}

impl VhdParentLocatorTable {
    /// Parse the 192-byte locator table, validating each entry's offsets
    /// against `bounds`.
    ///
    /// Returns `None` only if `table` is shorter than
    /// [`PARENT_LOCATOR_TABLE_SIZE`]. Malformed entries are marked, not
    /// dropped.
    pub fn parse(table: &[u8], bounds: &VhdImageBounds) -> Option<Self> {
        if table.len() < PARENT_LOCATOR_TABLE_SIZE {
            return None;
        }
        let mut entries = [VhdParentLocator::EMPTY; PARENT_LOCATOR_COUNT];
        for (slot, entry) in entries.iter_mut().enumerate() {
            let off = slot * PARENT_LOCATOR_ENTRY_SIZE;
            *entry = VhdParentLocator::parse(&table[off..off + PARENT_LOCATOR_ENTRY_SIZE], bounds)?;
        }
        Some(VhdParentLocatorTable { entries })
    }

    /// Select the entry that names the parent: `W2ru` before `W2ku`
    /// before `Wi2r` before `Wi2k`, never a non-Windows code, never an
    /// unused slot, never one carrying a `defect`. Slot order is not a
    /// tiebreaker between *different* platform codes.
    ///
    /// If more than one entry carries the winning code, their platform
    /// data is compared byte-for-byte (see
    /// [`VhdParentLocator::raw_path_bytes`]). Equal contents are not
    /// ambiguous and yield the lowest such slot; a disagreement, or
    /// contents that cannot be reached because `data` is `None` or too
    /// narrow, yields `Ambiguous`.
    ///
    /// **This decides which entry names the parent, and nothing else.**
    /// Whether an ambiguous table is refused, warned about, or resolved to
    /// the relative entry is phase 4's policy.
    ///
    /// Two consequences worth stating, because they surprise people:
    ///
    /// * A table whose eight entries name eight different parents can
    ///   still return `Found`. Ambiguity here means *two entries sharing a
    ///   platform code disagree*, not *the entries disagree*. Precedence
    ///   between different codes is a fact about the format, so a `W2ru`
    ///   entry legitimately beats seven dissenting others. That is what
    ///   `vhd-diff-locator-conflicting.vhd` exercises, and its manifest
    ///   description explicitly permits this branch: a reader must
    ///   "either select by platform code rather than by slot order, or
    ///   refuse a table where two entries share a platform code and
    ///   disagree". instar does the former.
    /// * A parent unicode name (header `+64`) that disagrees with the
    ///   winning locator is **not** ambiguity and is not checked at all in
    ///   this phase.
    pub fn preferred_locator(&self, data: Option<&VhdImageWindow<'_>>) -> PreferredLocator {
        // Best (lowest) preference rank among candidate entries.
        let mut best_rank: Option<u8> = None;
        for entry in self.entries.iter() {
            if !entry.is_candidate() {
                continue;
            }
            // `is_candidate` proved the rank is Some.
            if let Some(rank) = entry.platform().preference() {
                best_rank = Some(match best_rank {
                    Some(current) if current <= rank => current,
                    _ => rank,
                });
            }
        }
        let best_rank = match best_rank {
            Some(rank) => rank,
            None => return PreferredLocator::NotFound,
        };

        // Winner is the lowest slot carrying the best rank; every other
        // slot with that same rank carries the same platform code, so its
        // contents must agree.
        let mut winner: Option<usize> = None;
        for (slot, entry) in self.entries.iter().enumerate() {
            if !entry.is_candidate() || entry.platform().preference() != Some(best_rank) {
                continue;
            }
            let first = match winner {
                None => {
                    winner = Some(slot);
                    continue;
                }
                Some(first) => first,
            };

            let reason = match data {
                None => Some(AmbiguityReason::ContentsUnknown),
                Some(window) => {
                    match (
                        self.entries[first].raw_path_bytes(window),
                        entry.raw_path_bytes(window),
                    ) {
                        (Ok(a), Ok(b)) if a == b => None,
                        (Ok(_), Ok(_)) => Some(AmbiguityReason::ContentsDiffer),
                        _ => Some(AmbiguityReason::ContentsUnknown),
                    }
                }
            };
            if let Some(reason) = reason {
                return PreferredLocator::Ambiguous {
                    first,
                    second: slot,
                    reason,
                };
            }
        }

        match winner {
            Some(slot) => PreferredLocator::Found { slot },
            None => PreferredLocator::NotFound,
        }
    }
}

/// The parent identity of a differencing VHD: the dynamic header fields a
/// plain dynamic VHD leaves zero.
///
/// A sibling of [`VhdDynamicHeader`] rather than an extension of it, for
/// three reasons. Validating a locator offset needs the image length and
/// the header's file offset, which `VhdDynamicHeader::parse` does not take
/// and which its eight call sites have no reason to supply. Those call
/// sites build the header by value on the stack — `VhdState::init` does it
/// in a frame that already holds two `MAX_SECTOR_SIZE` buffers — and would
/// pay for parent fields none of them read. And keeping the two apart
/// means this phase changes nothing about how a non-differencing dynamic
/// VHD is parsed.
///
/// The parent unicode name is kept **undecoded**: `name_utf16_be` borrows
/// the 512-byte field, and a caller that wants a string calls
/// [`VhdParentInfo::decode_name`] with its own buffer, so the 768-byte
/// worst-case UTF-8 cost lands only in frames that ask for it.
#[derive(Debug, Clone, Copy)]
pub struct VhdParentInfo<'a> {
    /// Parent unique id at `+40`: 16 opaque bytes, the parent footer's
    /// bytes 68..84 copied verbatim. Not byte-swapped, not reformatted.
    pub unique_id: [u8; 16],
    /// Parent timestamp at `+56`, BE u32, seconds since 2000-01-01.
    /// Hyper-V writes zero, and so does instar.
    pub timestamp: u32,
    /// The 512 raw bytes of the parent unicode name field at `+64`,
    /// undecoded. Always exactly [`DYN_PARENT_NAME_SIZE`] long.
    pub name_utf16_be: &'a [u8],
    /// The eight parent locator entries at `+576`.
    pub locators: VhdParentLocatorTable,
}

impl<'a> VhdParentInfo<'a> {
    /// Parse the parent fields out of a 1024-byte dynamic header.
    ///
    /// `header` must be at least [`DYNAMIC_HEADER_SIZE`] bytes and carry
    /// the `cxsparse` cookie — the same precondition
    /// [`VhdDynamicHeader::parse`] enforces, so the two agree about what a
    /// dynamic header is. `bounds` describes the image the header came
    /// from and is used only to validate locator offsets.
    ///
    /// Returns `None` only for a short or non-`cxsparse` buffer. A hostile
    /// locator table does not fail the parse; its entries come back with
    /// `defect` set (decision 4).
    ///
    /// **This cannot check that the image is differencing.** `disk_type`
    /// lives in the footer, not the header, so the caller gates on
    /// `footer.disk_type == DISK_TYPE_DIFFERENCING`; this parses the
    /// fields where they lie. On a plain dynamic VHD they read as zero.
    ///
    /// No I/O and no allocation: this is the entry point phase 9 points a
    /// fuzz target at.
    pub fn parse(header: &'a [u8], bounds: &VhdImageBounds) -> Option<Self> {
        if header.len() < DYNAMIC_HEADER_SIZE {
            return None;
        }
        if be_u64(header, DYN_COOKIE_OFFSET) != CXSPARSE_COOKIE {
            return None;
        }

        // Every offset below is a compile-time constant inside a length
        // already proven above: no arithmetic on image data happens here.
        let mut unique_id = [0u8; 16];
        unique_id.copy_from_slice(
            &header[DYN_PARENT_UNIQUE_ID_OFFSET..DYN_PARENT_UNIQUE_ID_OFFSET + 16],
        );
        let timestamp = be_u32(header, DYN_PARENT_TIMESTAMP_OFFSET);
        let name_utf16_be =
            &header[DYN_PARENT_NAME_OFFSET..DYN_PARENT_NAME_OFFSET + DYN_PARENT_NAME_SIZE];
        let locators = VhdParentLocatorTable::parse(
            &header[DYN_PARENT_LOCATORS_OFFSET
                ..DYN_PARENT_LOCATORS_OFFSET + PARENT_LOCATOR_TABLE_SIZE],
            bounds,
        )?;

        Some(VhdParentInfo {
            unique_id,
            timestamp,
            name_utf16_be,
            locators,
        })
    }

    /// Decode the parent unicode name into `dst` as UTF-8, returning the
    /// number of bytes written.
    ///
    /// The name is UTF-16 **BIG** endian — the opposite of the locator
    /// platform data. This is the call site that passes
    /// `big_endian = true` to `shared::utf16_to_utf8`; the other, in
    /// [`VhdParentLocator::decode_path`], passes `false`.
    ///
    /// The 512-byte field is the bound: the decode stops at the first
    /// `0x0000` code unit if there is one, and otherwise consumes all 256
    /// code units. It never looks past the field for a terminator
    /// (decision 3 — over-reading here is libvhdi defect C, and
    /// `vhd-diff-locator-overlong.vhd` exists to catch it).
    ///
    /// A `dst` of [`MAX_PARENT_NAME_UTF8`] bytes can never be too small.
    pub fn decode_name(&self, dst: &mut [u8]) -> Option<usize> {
        utf16_to_utf8(self.name_utf16_be, true, dst)
    }
}

// ============================================================================
// Checksum computation
// ============================================================================

/// Compute the VHD checksum for a buffer.
///
/// The checksum is the one's complement of the sum of all bytes in the
/// structure, with the checksum field itself set to zero during computation.
pub fn compute_checksum(buf: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i >= checksum_offset && i < checksum_offset + 4 {
            continue;
        }
        sum = sum.wrapping_add(b as u32);
    }
    !sum
}

// ============================================================================
// CHS geometry calculation (VPC algorithm)
// ============================================================================

/// Maximum CHS-addressable sector count (16-bit cylinders × 16 heads ×
/// 255 sectors/track): qemu vpc.c's `VHD_MAX_SECTORS` / `VHD_MAX_GEOMETRY`.
pub const VHD_MAX_SECTORS: u64 = 65535 * 16 * 255;

/// CHS geometry from a sector count — an exact mirror of qemu vpc.c's
/// `calculate_geometry` (itself the VHD-spec / Virtual PC algorithm).
/// All divisions floor, `heads` rounds up, and the 17 → 31 → 63
/// sectors-per-track ladder escalates whenever `cylinders × heads`
/// would overflow the current head count; disks of at least
/// `65535 * 16 * 63` sectors use 255 sectors/track. The returned
/// product `cylinders * heads * spt` may be slightly below
/// `total_sectors` (everything floors) — qemu's create path compensates
/// with the upward search in [`chs_rounded_size`].
fn calculate_geometry(total_sectors: u64) -> (u16, u8, u8) {
    let total_sectors = total_sectors.min(VHD_MAX_SECTORS);

    if total_sectors >= 65535 * 16 * 63 {
        let cyl_times_heads = total_sectors / 255;
        return ((cyl_times_heads / 16) as u16, 16, 255);
    }

    let mut sectors_per_track: u64 = 17;
    let mut cyl_times_heads = total_sectors / sectors_per_track;
    let mut heads = cyl_times_heads.div_ceil(1024);
    if heads < 4 {
        heads = 4;
    }

    if cyl_times_heads >= (heads * 1024) || heads > 16 {
        sectors_per_track = 31;
        heads = 16;
        cyl_times_heads = total_sectors / sectors_per_track;
    }

    if cyl_times_heads >= (heads * 1024) {
        sectors_per_track = 63;
        heads = 16;
        cyl_times_heads = total_sectors / sectors_per_track;
    }

    (
        (cyl_times_heads / heads) as u16,
        heads as u8,
        sectors_per_track as u8,
    )
}

/// Compute CHS geometry for a VHD from a size in bytes (floor to whole
/// sectors), mirroring qemu vpc.c's `calculate_geometry`.
///
/// Returns `(cylinders, heads, sectors_per_track)`.
pub fn compute_vhd_geometry(size: u64) -> (u16, u8, u8) {
    calculate_geometry(size / 512)
}

/// The upward candidate search shared by [`chs_rounded_size`] and
/// [`chs_rounded_geometry`] — the loop inside qemu vpc.c's
/// `calculate_rounded_image_size`. Walks candidate sector counts up
/// from `requested` (already clamped to `VHD_MAX_SECTORS`) until the
/// floor [`calculate_geometry`] product covers the request, and returns
/// the geometry of that final candidate. For `requested == 0` the loop
/// never runs and the geometry stays `(0, 0, 0)`, exactly as qemu's
/// zero-initialised cyls/heads/secs do.
///
/// NOTE: the returned geometry is generally NOT the floor geometry of
/// its own product. The search evaluates geometry at the CANDIDATE
/// (e.g. 104465 sectors → heads = ceil(6145/1024) = 7) while the
/// product can sit below a head-count boundary (104363 sectors →
/// heads = ceil(6139/1024) = 6), so `calculate_geometry(product)` may
/// return different, smaller-product CHS — the divergence behind
/// issue #413. Re-running the search on the product DOES reproduce the
/// same geometry: every candidate in `[product, final)` was already
/// rejected with a product `< requested <= product`, so the re-search
/// stops at the same final candidate (`fuzz_chs_rounded_size`
/// invariant 5 pins this).
fn chs_covering_search(requested: u64) -> (u16, u8, u8) {
    let mut geometry = (0u16, 0u8, 0u8);
    let mut candidate = requested;
    while requested > geometry.0 as u64 * geometry.1 as u64 * geometry.2 as u64 {
        geometry = calculate_geometry(candidate);
        candidate += 1;
    }
    geometry
}

/// Compute the CHS-rounded virtual size that `qemu-img dd -O vpc` /
/// `qemu-img create -f vpc` declare for an arbitrary requested size —
/// an exact mirror of qemu vpc.c's `calculate_rounded_image_size`.
///
/// qemu rounds the request up to whole sectors, then searches upward
/// from that sector count for the first candidate whose (floor)
/// [`calculate_geometry`] product covers the request; the product
/// becomes the footer's current_size (what `qemu-img info` reports as
/// the virtual size) and the candidate's geometry — returned by
/// [`chs_rounded_geometry`], NOT the floor geometry of the product —
/// becomes the footer CHS.
///
/// Two edges depart from the plain search:
///   * The max-geometry window: when only the full `(65535,16,255)`
///     ceiling can cover the request, qemu keeps the EXACT sector-
///     rounded request as the size (the footer CHS then addresses
///     slightly more than current_size). Mirrored here.
///   * Oversize requests: qemu refuses anything past 2040 GiB
///     (`VHD_MAX_SECTORS`); instar's convert path instead clamps to
///     the ceiling, preserving long-standing saturation behaviour
///     (`fuzz_chs_rounded_size` invariant 3).
pub fn chs_rounded_size(size: u64) -> u64 {
    // An empty window (size 0) has no CHS geometry; qemu-img dd produces a
    // 0-virtual-size VHD for count=0.
    if size == 0 {
        return 0;
    }
    let requested = size.div_ceil(512).min(VHD_MAX_SECTORS);

    let (c, h, s) = chs_covering_search(requested);
    let product = c as u64 * h as u64 * s as u64;
    if product == VHD_MAX_SECTORS {
        requested * 512
    } else {
        product * 512
    }
}

/// The footer CHS that `qemu-img create -f vpc` / `convert -O vpc` /
/// `dd -O vpc` write for a request of `size` bytes: the geometry of
/// the candidate qemu's `calculate_rounded_image_size` search lands on
/// (see [`chs_covering_search`]). Its product covers the request
/// exactly ([`chs_rounded_size`]`(size) / 512`) except in the
/// max-geometry window, where the ceiling geometry addresses slightly
/// more than the kept size. A zero request has no geometry (qemu
/// writes CHS `(0, 0, 0)` for a count=0 dd, empirically verified
/// against qemu-img 10.0.8).
pub fn chs_rounded_geometry(size: u64) -> (u16, u8, u8) {
    if size == 0 {
        return (0, 0, 0);
    }
    chs_covering_search(size.div_ceil(512).min(VHD_MAX_SECTORS))
}

/// Footer CHS for a VHD declaring `current_size` bytes.
///
/// For sizes qemu-img itself would declare — fixed points of
/// [`chs_rounded_size`], which is what instar's dd path stamps — this
/// is the upward-search geometry [`chs_rounded_geometry`], reproducing
/// qemu's footer bytes exactly. The floor geometry of the same size
/// can differ AND under-address it (issue #413: 53433856 bytes is
/// 104363 sectors = 877×7×17, but the floor geometry is 1023×6×17 =
/// only 104346 sectors), so recomputing via [`compute_vhd_geometry`]
/// here would truncate the disk for CHS-honouring readers.
///
/// For any other size — instar's verbatim-size convert/create/resize
/// paths, whose declared sizes qemu-img never produces — keep the
/// VHD-spec floor geometry, matching Hyper-V/disk2vhd-style writers
/// (current_size authoritative, CHS a floor approximation) and prior
/// instar behaviour.
pub fn footer_geometry(current_size: u64) -> (u16, u8, u8) {
    if chs_rounded_size(current_size) == current_size {
        chs_rounded_geometry(current_size)
    } else {
        compute_vhd_geometry(current_size)
    }
}

// ============================================================================
// Allocation scanning — pure helper
// ============================================================================

/// Count allocated entries in a dynamic-VHD BAT byte slice.
///
/// Each entry is a big-endian u32 sector pointer. The unallocated
/// marker is `0xFFFF_FFFF`. Any other value indicates an allocated
/// block.
///
/// `bat_bytes` may have a trailing partial entry (length not a
/// multiple of 4); the trailing bytes are ignored. The caller is
/// expected to pass a slice covering exactly `total_blocks * 4`
/// bytes after BAT padding.
pub fn count_allocated_in_bat(bat_bytes: &[u8]) -> u64 {
    bat_bytes
        .chunks_exact(4)
        .filter(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]) != BAT_UNALLOCATED)
        .count() as u64
}

/// Classify one dynamic-VHD BAT entry into a single `MapExtent`.
///
/// Mirrors `VhdState::block_lookup`'s dynamic-VHD decision tree:
///
/// - `entry == BAT_UNALLOCATED` (0xFFFF_FFFF): `Hole`.
/// - Otherwise: `Data { file_offset = entry * 512 +
///   block_data_offset }`. The BAT entry is the absolute sector
///   number of the block's sector-bitmap; the payload starts
///   `block_data_offset` bytes later.
///
/// `block_size_bytes` is the extent's length. `virtual_offset` is
/// the virtual address of the block's first byte; the caller is
/// responsible for clamping `length` against virtual_size if the
/// block straddles end-of-image.
pub fn classify_vhd_bat_entry(
    entry: u32,
    virtual_offset: u64,
    block_size_bytes: u64,
    block_data_offset: u64,
) -> MapExtent {
    let state = if entry == BAT_UNALLOCATED {
        MapExtentState::Hole
    } else {
        let block_host_offset = (entry as u64).saturating_mul(512);
        MapExtentState::Data {
            file_offset: block_host_offset.saturating_add(block_data_offset),
        }
    };
    MapExtent {
        start: virtual_offset,
        length: block_size_bytes,
        state,
    }
}

// ============================================================================
// Block lookup result
// ============================================================================

/// Result of looking up a virtual offset in the VHD BAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockLookup {
    /// The block is not allocated (reads as zeros or from parent).
    Unallocated,
    /// The block is allocated at the given host byte offset
    /// (past the sector bitmap, pointing to the data region).
    Allocated { host_byte_offset: u64 },
}

// ============================================================================
// VHD state for BAT I/O
// ============================================================================

/// Runtime state for reading VHD blocks from a device.
///
/// Analogous to `qcow2::Qcow2State` and `vmdk::VmdkState`. Maintains
/// a sector cache for BAT reads.
pub struct VhdState {
    pub device_idx: u32,
    pub disk_type: u32,
    pub block_size: u32,
    pub block_data_offset: u32,
    pub max_table_entries: u32,
    pub table_offset: u64,
    pub current_size: u64,
    // Sector cache for BAT reads
    pub bat_cached_sector: u64,
    pub bat_cache_buf: *mut u8,
    // Sector cache for data reads (reused for sector bitmap skip)
    pub data_cached_sector: u64,
    pub data_cache_buf: *mut u8,
}

impl VhdState {
    /// Initialize VHD state by reading footer and dynamic header.
    ///
    /// For dynamic VHDs: reads the footer (first sector), then the
    /// dynamic header, validates, and sets up state.
    ///
    /// For fixed VHDs: reads the footer from the last sector,
    /// validates, and sets up minimal state (no BAT needed).
    ///
    /// Returns `None` if the footer/header is invalid or I/O fails.
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
        // Read first sector (contains footer copy for dynamic VHDs,
        // or raw data for fixed VHDs).
        let mut first_sector = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(device_idx, 0, first_sector.as_mut_ptr(), sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;

        // Try parsing footer from first sector
        let footer = VhdFooter::parse(&first_sector);

        if footer.is_none() {
            // No footer at start — try the last sector (fixed VHD
            // only has footer at end).
            let last_sector_idx = input_capacity.checked_sub(1)?;
            let mut last_sector = [0u8; MAX_SECTOR_SIZE];
            if !(call_table.read_input_sector)(
                device_idx,
                last_sector_idx,
                last_sector.as_mut_ptr(),
                sector_size,
            ) {
                return None;
            }
            *bytes_read += sector_size as u64;

            // For large sectors the footer is at the start of the
            // last sector (footer is only 512 bytes).
            let footer = VhdFooter::parse(&last_sector)?;
            return Self::init_fixed(
                footer,
                device_idx,
                input_capacity,
                sector_size,
                bat_cache_buf,
                data_cache_buf,
            );
        }

        // Provably Some here (the None arm returned above); `?`
        // keeps that invariant without a panic path.
        let footer = footer?;

        if footer.disk_type == DISK_TYPE_FIXED {
            return Self::init_fixed(
                footer,
                device_idx,
                input_capacity,
                sector_size,
                bat_cache_buf,
                data_cache_buf,
            );
        }

        if footer.disk_type != DISK_TYPE_DYNAMIC && footer.disk_type != DISK_TYPE_DIFFERENCING {
            return None;
        }

        // Read dynamic header at footer.data_offset
        let dyn_byte_offset = footer.data_offset;
        let actual_size = input_capacity.checked_mul(sector_size as u64)?;
        if dyn_byte_offset >= actual_size {
            return None;
        }
        // Dynamic header is 1024 bytes. We need to read enough
        // sectors to cover it.
        let dyn_sector = dyn_byte_offset / sector_size as u64;
        let dyn_off_in_sector = (dyn_byte_offset % sector_size as u64) as usize;

        // Read up to 2 sectors to ensure we get the full 1024-byte header
        let mut dyn_buf = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(
            device_idx,
            dyn_sector,
            dyn_buf.as_mut_ptr(),
            sector_size,
        ) {
            return None;
        }
        *bytes_read += sector_size as u64;

        // If the dynamic header doesn't fit in the first sector,
        // read the next one too. For typical VHDs the footer is at
        // offset 0 and the dynamic header at offset 512, so with
        // 512-byte sectors we need to read sector 1 + sector 2.
        // With larger sectors, it fits in one.
        let dyn_available = sector_size - dyn_off_in_sector;
        let mut dyn_header_bytes = [0u8; DYNAMIC_HEADER_SIZE];
        if dyn_available >= DYNAMIC_HEADER_SIZE {
            dyn_header_bytes.copy_from_slice(
                &dyn_buf[dyn_off_in_sector..dyn_off_in_sector + DYNAMIC_HEADER_SIZE],
            );
        } else {
            // First part from this sector
            dyn_header_bytes[..dyn_available]
                .copy_from_slice(&dyn_buf[dyn_off_in_sector..sector_size]);
            // Read next sector
            let next_sector = dyn_sector + 1;
            if next_sector >= input_capacity {
                return None;
            }
            if !(call_table.read_input_sector)(
                device_idx,
                next_sector,
                dyn_buf.as_mut_ptr(),
                sector_size,
            ) {
                return None;
            }
            *bytes_read += sector_size as u64;
            let remaining = DYNAMIC_HEADER_SIZE - dyn_available;
            dyn_header_bytes[dyn_available..DYNAMIC_HEADER_SIZE]
                .copy_from_slice(&dyn_buf[..remaining]);
        }

        let dyn_header = VhdDynamicHeader::parse(&dyn_header_bytes)?;

        // Validate
        if dyn_header.block_size == 0 {
            return None;
        }
        // Block size must be a power of 2
        if (dyn_header.block_size & (dyn_header.block_size - 1)) != 0 {
            return None;
        }
        if dyn_header.max_table_entries == 0 {
            return None;
        }

        // Validate BAT offset
        let bat_byte_offset = dyn_header.table_offset;
        if bat_byte_offset >= actual_size {
            return None;
        }
        let bat_size_bytes = (dyn_header.max_table_entries as u64).checked_mul(4)?;
        let bat_end = bat_byte_offset.checked_add(bat_size_bytes)?;
        if bat_end > actual_size {
            return None;
        }

        // Sector bitmap size: ceil(block_size / 512 / 8) rounded up
        // to next 512-byte boundary.
        let sectors_per_block = dyn_header.block_size / 512;
        let bitmap_bytes = (sectors_per_block.div_ceil(8) + 511) & !511;

        Some(VhdState {
            device_idx,
            disk_type: footer.disk_type,
            block_size: dyn_header.block_size,
            block_data_offset: bitmap_bytes,
            max_table_entries: dyn_header.max_table_entries,
            table_offset: dyn_header.table_offset,
            current_size: footer.current_size,
            bat_cached_sector: u64::MAX,
            bat_cache_buf,
            data_cached_sector: u64::MAX,
            data_cache_buf,
        })
    }

    /// Initialize state for a fixed VHD.
    ///
    /// Fixed VHDs have raw data from offset 0 with a 512-byte footer
    /// appended at the end. No BAT or dynamic header exists.
    fn init_fixed(
        footer: VhdFooter,
        device_idx: u32,
        _input_capacity: u64,
        _sector_size: usize,
        bat_cache_buf: *mut u8,
        data_cache_buf: *mut u8,
    ) -> Option<Self> {
        Some(VhdState {
            device_idx,
            disk_type: DISK_TYPE_FIXED,
            block_size: 0,
            block_data_offset: 0,
            max_table_entries: 0,
            table_offset: 0,
            current_size: footer.current_size,
            bat_cached_sector: u64::MAX,
            bat_cache_buf,
            data_cached_sector: u64::MAX,
            data_cache_buf,
        })
    }

    /// Check if this is a fixed VHD (raw data, no BAT).
    pub fn is_fixed(&self) -> bool {
        self.disk_type == DISK_TYPE_FIXED
    }

    /// Look up the host location for a given virtual byte offset.
    ///
    /// For dynamic VHDs: reads the BAT entry for the containing block.
    /// If allocated, returns the host byte offset past the sector
    /// bitmap. If unallocated (0xFFFFFFFF), returns `Unallocated`.
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
    ) -> Option<BlockLookup> {
        if self.is_fixed() {
            // Fixed VHDs: data is at the same offset as virtual
            return Some(BlockLookup::Allocated {
                host_byte_offset: virtual_offset,
            });
        }

        // Calculate which block this virtual offset falls in
        let block_idx = virtual_offset / self.block_size as u64;

        if block_idx >= self.max_table_entries as u64 {
            return Some(BlockLookup::Unallocated);
        }

        // Read BAT entry (u32 BE at table_offset + block_idx * 4)
        let bat_byte_offset = self.table_offset.checked_add(block_idx.checked_mul(4)?)?;

        let bat_entry = read_u32_be_cached(
            call_table,
            self.device_idx,
            bat_byte_offset,
            sector_size,
            input_capacity,
            &mut self.bat_cached_sector,
            self.bat_cache_buf,
            bytes_read,
        )?;

        if bat_entry == BAT_UNALLOCATED {
            return Some(BlockLookup::Unallocated);
        }

        // BAT entry is the absolute sector number (512-byte sectors)
        // of the block's sector bitmap. Data follows the bitmap.
        let block_host_offset = (bat_entry as u64).checked_mul(512)?;
        let data_start = block_host_offset.checked_add(self.block_data_offset as u64)?;

        // Offset within the block
        let intra_block_offset = virtual_offset % self.block_size as u64;

        Some(BlockLookup::Allocated {
            host_byte_offset: data_start + intra_block_offset,
        })
    }

    /// Walk the BAT and produce an `AllocationSummary`.
    ///
    /// For Fixed VHDs (no BAT), `allocated_bytes == virtual_size`.
    /// For Dynamic VHDs, walks the BAT in `MAX_SECTOR_SIZE`-sized cached
    /// chunks and counts entries != `0xFFFF_FFFF`, multiplying by
    /// `block_size`.
    ///
    /// Returns `None` if any I/O call fails. The caller treats `None`
    /// as an unrecoverable format error.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. `bat_cache_buf` must still be valid
    /// and point to at least `MAX_SECTOR_SIZE` writable bytes.
    // NOTE: The sector-walking loop below (buf_start / buf_end /
    // meaningful_len / per-sector read) is duplicated near-verbatim in
    // `vhdx::VhdxState::scan_allocation`. The two formats walk single
    // contiguous BAT tables; the only differences are the entry
    // decoder (`count_allocated_in_bat` vs the vhdx chunk_ratio-aware
    // variant) and one cache-invalidation line. Extracting a shared
    // `walk_table_sectors(call_table, byte_offset, byte_len, ...,
    // FnMut(&[u8]))` helper into `shared` is captured as future work
    // in PLAN-measure.md; deferred because the FnMut + &mut self
    // borrow interaction adds non-trivial complexity for marginal
    // line-count reduction.
    pub unsafe fn scan_allocation(
        &mut self,
        call_table: &CallTable,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<AllocationSummary> {
        // Fixed VHDs: every byte is allocated — no BAT to walk.
        if self.disk_type == DISK_TYPE_FIXED {
            return Some(AllocationSummary::clamp(
                self.current_size,
                self.current_size,
                // TODO(#286): populate from target_unit_size when this
                // scanner is converted to target-aware accounting.
                0,
            ));
        }

        // Dynamic (and Differencing) VHDs: walk the BAT.
        // The BAT is a contiguous u32-be array of `max_table_entries`
        // entries starting at `table_offset` (byte offset).
        let total_bat_bytes = (self.max_table_entries as u64).checked_mul(4)?;
        let bat_start_sector = self.table_offset / sector_size as u64;
        let bat_end_byte = self.table_offset.checked_add(total_bat_bytes)?;
        // Round up to the next sector boundary so we cover any partial
        // sector at the end of the BAT.
        let bat_end_sector = bat_end_byte.checked_add(sector_size as u64 - 1)? / sector_size as u64;

        let mut allocated_blocks: u64 = 0;
        // Bytes of BAT we have logically consumed so far (used to bound
        // the count so padding at the end of the last sector is ignored).
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
            *bytes_read += sector_size as u64;

            // Determine the byte range within this sector that belongs
            // to the BAT (accounting for the first sector's intra-sector
            // offset and clamping to `total_bat_bytes`).
            let sector_byte_start = sector * sector_size as u64;
            // Offset of the first BAT byte within this sector's buffer.
            let buf_start = if sector_byte_start < self.table_offset {
                (self.table_offset - sector_byte_start) as usize
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

            // Clamp to the meaningful BAT bytes (ignore sector padding).
            let meaningful_len =
                (total_bat_bytes - bat_bytes_consumed).min((buf_end - buf_start) as u64) as usize;
            let meaningful = &chunk[..meaningful_len];

            allocated_blocks += count_allocated_in_bat(meaningful);
            bat_bytes_consumed += meaningful_len as u64;

            sector += 1;
        }

        // `block_size` (typically 2 MiB) frequently exceeds the
        // virtual_size of small images, so a single allocated block can
        // make `allocated_blocks * block_size` overshoot `current_size`.
        // AllocationSummary::clamp enforces allocated_bytes <=
        // virtual_size at construction; `measure_<fmt>` rejects
        // summaries that violate it, which would surface to the user
        // as "source image is unsupported format". Mirrors the qcow2
        // out-of-bounds skip established in PLAN-fuzzing-bugs phase 2.
        let allocated_bytes = allocated_blocks.saturating_mul(self.block_size as u64);

        Some(AllocationSummary::clamp(
            self.current_size,
            allocated_bytes,
            // TODO(#286): populate from target_unit_size when this
            // scanner is converted to target-aware accounting.
            0,
        ))
    }

    /// Walk the dynamic-VHD BAT (or short-circuit for fixed VHDs)
    /// and emit a coalesced `MapExtent` stream covering
    /// `[0, current_size)`.
    ///
    /// For fixed VHDs: a single Data extent at file_offset 0
    /// covering the whole virtual size. No BAT walk.
    ///
    /// For dynamic / differencing VHDs: walks the BAT exactly like
    /// `scan_allocation`'s sector-walking shell, classifies each
    /// entry via [`classify_vhd_bat_entry`], and pushes the result
    /// through a `MapExtentCoalescer` that persists for the whole
    /// walk so consecutive Data blocks with contiguous payload
    /// offsets coalesce into one extent.
    ///
    /// A trailing `Hole` covers any virtual range past the last
    /// walked block up to `current_size` so emitted extents
    /// partition `[0, current_size)`.
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
        if self.current_size == 0 {
            return Some(());
        }

        if self.disk_type == DISK_TYPE_FIXED {
            let _ = emit(MapExtent {
                start: 0,
                length: self.current_size,
                state: MapExtentState::Data { file_offset: 0 },
            });
            return Some(());
        }

        let block_size = self.block_size as u64;
        let block_data_offset = self.block_data_offset as u64;
        let total_bat_bytes = (self.max_table_entries as u64).checked_mul(4)?;
        let bat_start_sector = self.table_offset / sector_size as u64;
        let bat_end_byte = self.table_offset.checked_add(total_bat_bytes)?;
        let bat_end_sector = bat_end_byte.checked_add(sector_size as u64 - 1)? / sector_size as u64;

        let mut coalescer = MapExtentCoalescer::new(emit);
        let mut next_unwalked: u64 = 0;
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
            *bytes_read += sector_size as u64;

            let sector_byte_start = sector * sector_size as u64;
            let buf_start = if sector_byte_start < self.table_offset {
                (self.table_offset - sector_byte_start) as usize
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

            let chunk_entry_count = (meaningful_len as u64) / 4;
            let base_entry_index = bat_bytes_consumed / 4;

            for k in 0..chunk_entry_count {
                let off = (k as usize) * 4;
                let entry = u32::from_be_bytes([
                    meaningful[off],
                    meaningful[off + 1],
                    meaningful[off + 2],
                    meaningful[off + 3],
                ]);
                let global_idx = base_entry_index + k;
                let block_virt = global_idx.saturating_mul(block_size);
                if block_virt >= self.current_size {
                    break 'walk;
                }
                let block_visible = block_size.min(self.current_size - block_virt);

                let mut ext =
                    classify_vhd_bat_entry(entry, block_virt, block_size, block_data_offset);
                if ext.length > block_visible {
                    ext.length = block_visible;
                }
                let cont = coalescer.push(ext);
                next_unwalked = block_virt.saturating_add(block_visible);
                if !cont {
                    break 'walk;
                }
            }

            bat_bytes_consumed += meaningful_len as u64;
            sector += 1;
        }

        if next_unwalked < self.current_size {
            let _ = coalescer.push(MapExtent {
                start: next_unwalked,
                length: self.current_size - next_unwalked,
                state: MapExtentState::Hole,
            });
        }
        let _ = coalescer.finish();
        Some(())
    }
}

// ============================================================================
// Cached sector read helper (big-endian u32)
// ============================================================================

shared::cached_read!(read_u32_be_cached, u32, be, 4);

// ============================================================================
// VHD footer/header builder helpers (for output)
// ============================================================================

/// Build a VHD footer into `buf`.
///
/// `buf` must be at least 512 bytes and should be pre-zeroed.
/// The checksum field is computed and written automatically.
pub fn build_footer(
    buf: &mut [u8],
    current_size: u64,
    disk_type: u32,
    data_offset: u64,
    uuid: &[u8; 16],
) {
    // Cookie: "conectix"
    write_be_u64(buf, FOOTER_COOKIE_OFFSET, VHD_COOKIE);
    // Features: reserved bit
    write_be_u32(buf, FOOTER_FEATURES_OFFSET, FEATURES_RESERVED);
    // Format version: 1.0
    write_be_u32(buf, FOOTER_FORMAT_VERSION_OFFSET, VHD_VERSION_1_0);
    // Data offset (to dynamic header, or 0xFFFFFFFFFFFFFFFF for fixed)
    write_be_u64(buf, FOOTER_DATA_OFFSET_OFFSET, data_offset);
    // Timestamp: 0 (we don't track creation time)
    write_be_u32(buf, FOOTER_TIMESTAMP_OFFSET, 0);
    // Creator application: "qem2".
    //
    // This is qemu's `force_size` marker, and it is load-bearing
    // rather than cosmetic. qemu's vpc_open derives the disk size
    // from the footer's CHS geometry unless the creator app is
    // "win " (Hyper-V) or "qem2", or the CHS is at its maximum.
    // instar keeps the requested size verbatim and writes the
    // VHD-spec FLOOR geometry for sizes qemu itself would never
    // produce (see `footer_geometry`), so its CHS product can
    // address less than the declared current_size — for a 2 MiB
    // image, 8192 bytes less. With any other creator app every
    // qemu before 10.0 therefore reads instar's VHDs short and
    // silently truncates the tail; qemu 10.0 changed the default,
    // which is why this stayed invisible on a 10.x dev host.
    //
    // "qem2" makes every version from 6.0.0 to 10.2.0 honour
    // current_size, which is exactly the "current_size is
    // authoritative" contract `footer_geometry` already documents.
    // Verified against instar-testdata's static per-version
    // qemu-img builds; see PLAN-distro-matrix-ci-phase-02b.
    buf[FOOTER_CREATOR_APP_OFFSET] = b'q';
    buf[FOOTER_CREATOR_APP_OFFSET + 1] = b'e';
    buf[FOOTER_CREATOR_APP_OFFSET + 2] = b'm';
    buf[FOOTER_CREATOR_APP_OFFSET + 3] = b'2';
    // Creator version: 1.0
    write_be_u32(buf, FOOTER_CREATOR_VERSION_OFFSET, 0x0001_0000);
    // Creator host OS: "Wi2k" (Windows) — standard value
    write_be_u32(buf, FOOTER_CREATOR_HOST_OFFSET, 0x5769_326B);
    // Original size = current size
    write_be_u64(buf, FOOTER_ORIGINAL_SIZE_OFFSET, current_size);
    // Current size
    write_be_u64(buf, FOOTER_CURRENT_SIZE_OFFSET, current_size);
    // Geometry: qemu's upward-search CHS for qemu-roundable sizes,
    // VHD-spec floor otherwise (see footer_geometry).
    let (cyl, heads, spt) = footer_geometry(current_size);
    write_be_u16(buf, FOOTER_GEOMETRY_OFFSET, cyl);
    buf[FOOTER_GEOMETRY_OFFSET + 2] = heads;
    buf[FOOTER_GEOMETRY_OFFSET + 3] = spt;
    // Disk type
    write_be_u32(buf, FOOTER_DISK_TYPE_OFFSET, disk_type);
    // UUID
    buf[FOOTER_UUID_OFFSET..FOOTER_UUID_OFFSET + 16].copy_from_slice(uuid);
    // Saved state: 0
    buf[FOOTER_SAVED_STATE_OFFSET] = 0;

    // Compute and write checksum (must be last)
    let checksum = compute_checksum(buf, FOOTER_CHECKSUM_OFFSET);
    write_be_u32(buf, FOOTER_CHECKSUM_OFFSET, checksum);
}

/// Build a VHD dynamic header into `buf`.
///
/// `buf` must be at least 1024 bytes and should be pre-zeroed.
/// The checksum field is computed and written automatically.
pub fn build_dynamic_header(
    buf: &mut [u8],
    table_offset: u64,
    max_table_entries: u32,
    block_size: u32,
) {
    // Cookie: "cxsparse"
    write_be_u64(buf, DYN_COOKIE_OFFSET, CXSPARSE_COOKIE);
    // Data offset: unused, should be 0xFFFFFFFFFFFFFFFF
    write_be_u64(buf, DYN_DATA_OFFSET_OFFSET, 0xFFFF_FFFF_FFFF_FFFF);
    // Table offset (BAT byte offset)
    write_be_u64(buf, DYN_TABLE_OFFSET_OFFSET, table_offset);
    // Header version: 1.0
    write_be_u32(buf, DYN_HEADER_VERSION_OFFSET, VHD_VERSION_1_0);
    // Max table entries
    write_be_u32(buf, DYN_MAX_TABLE_ENTRIES_OFFSET, max_table_entries);
    // Block size
    write_be_u32(buf, DYN_BLOCK_SIZE_OFFSET, block_size);

    // Compute and write checksum (must be last)
    let checksum = compute_checksum(buf, DYN_CHECKSUM_OFFSET);
    write_be_u32(buf, DYN_CHECKSUM_OFFSET, checksum);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // VhdFooter::parse tests
    // ====================================================================

    /// Build a minimal VHD footer buffer.
    fn make_footer(current_size: u64, disk_type: u32, data_offset: u64) -> [u8; 512] {
        let mut buf = [0u8; 512];
        write_be_u64(&mut buf, FOOTER_COOKIE_OFFSET, VHD_COOKIE);
        write_be_u32(&mut buf, FOOTER_FEATURES_OFFSET, FEATURES_RESERVED);
        write_be_u32(&mut buf, FOOTER_FORMAT_VERSION_OFFSET, VHD_VERSION_1_0);
        write_be_u64(&mut buf, FOOTER_DATA_OFFSET_OFFSET, data_offset);
        write_be_u64(&mut buf, FOOTER_ORIGINAL_SIZE_OFFSET, current_size);
        write_be_u64(&mut buf, FOOTER_CURRENT_SIZE_OFFSET, current_size);
        let (cyl, heads, spt) = compute_vhd_geometry(current_size);
        write_be_u16(&mut buf, FOOTER_GEOMETRY_OFFSET, cyl);
        buf[FOOTER_GEOMETRY_OFFSET + 2] = heads;
        buf[FOOTER_GEOMETRY_OFFSET + 3] = spt;
        write_be_u32(&mut buf, FOOTER_DISK_TYPE_OFFSET, disk_type);
        let checksum = compute_checksum(&buf, FOOTER_CHECKSUM_OFFSET);
        write_be_u32(&mut buf, FOOTER_CHECKSUM_OFFSET, checksum);
        buf
    }

    #[test]
    fn footer_parse_dynamic() {
        let size = 1024 * 1024 * 1024; // 1 GiB
        let buf = make_footer(size, DISK_TYPE_DYNAMIC, 512);
        let footer = VhdFooter::parse(&buf).unwrap();
        assert_eq!(footer.cookie, VHD_COOKIE);
        assert_eq!(footer.current_size, size);
        assert_eq!(footer.disk_type, DISK_TYPE_DYNAMIC);
        assert_eq!(footer.data_offset, 512);
    }

    #[test]
    fn footer_parse_fixed() {
        let size = 512 * 1024 * 1024; // 512 MiB
        let data_off = 0xFFFF_FFFF_FFFF_FFFF;
        let buf = make_footer(size, DISK_TYPE_FIXED, data_off);
        let footer = VhdFooter::parse(&buf).unwrap();
        assert_eq!(footer.disk_type, DISK_TYPE_FIXED);
        assert_eq!(footer.data_offset, data_off);
    }

    #[test]
    fn footer_parse_short_buffer() {
        assert!(VhdFooter::parse(&[0u8; 511]).is_none());
        assert!(VhdFooter::parse(&[0u8; 0]).is_none());
    }

    #[test]
    fn footer_parse_bad_cookie() {
        let mut buf = make_footer(1024 * 1024, DISK_TYPE_DYNAMIC, 512);
        buf[0] = 0; // Corrupt cookie
        assert!(VhdFooter::parse(&buf).is_none());
    }

    // ====================================================================
    // VhdDynamicHeader::parse tests
    // ====================================================================

    /// Build a minimal VHD dynamic header buffer.
    fn make_dynamic_header(
        table_offset: u64,
        max_table_entries: u32,
        block_size: u32,
    ) -> [u8; 1024] {
        let mut buf = [0u8; 1024];
        write_be_u64(&mut buf, DYN_COOKIE_OFFSET, CXSPARSE_COOKIE);
        write_be_u64(&mut buf, DYN_DATA_OFFSET_OFFSET, 0xFFFF_FFFF_FFFF_FFFF);
        write_be_u64(&mut buf, DYN_TABLE_OFFSET_OFFSET, table_offset);
        write_be_u32(&mut buf, DYN_HEADER_VERSION_OFFSET, VHD_VERSION_1_0);
        write_be_u32(&mut buf, DYN_MAX_TABLE_ENTRIES_OFFSET, max_table_entries);
        write_be_u32(&mut buf, DYN_BLOCK_SIZE_OFFSET, block_size);
        let checksum = compute_checksum(&buf, DYN_CHECKSUM_OFFSET);
        write_be_u32(&mut buf, DYN_CHECKSUM_OFFSET, checksum);
        buf
    }

    #[test]
    fn dynamic_header_parse_valid() {
        let buf = make_dynamic_header(1536, 512, DEFAULT_BLOCK_SIZE);
        let hdr = VhdDynamicHeader::parse(&buf).unwrap();
        assert_eq!(hdr.cookie, CXSPARSE_COOKIE);
        assert_eq!(hdr.table_offset, 1536);
        assert_eq!(hdr.max_table_entries, 512);
        assert_eq!(hdr.block_size, DEFAULT_BLOCK_SIZE);
    }

    #[test]
    fn dynamic_header_parse_short_buffer() {
        assert!(VhdDynamicHeader::parse(&[0u8; 1023]).is_none());
        assert!(VhdDynamicHeader::parse(&[0u8; 0]).is_none());
    }

    #[test]
    fn dynamic_header_parse_bad_cookie() {
        let mut buf = make_dynamic_header(1536, 512, DEFAULT_BLOCK_SIZE);
        buf[0] = 0; // Corrupt cookie
        assert!(VhdDynamicHeader::parse(&buf).is_none());
    }

    // ====================================================================
    // Parent locator tests (differencing VHDs)
    //
    // In-memory only: the crate is no_std and must test without the
    // instar-testdata repository present. The phase 2 fixtures are
    // consumed for real by phase 8's integration tests; the adversarial
    // shapes below reconstruct them as byte buffers.
    // ====================================================================

    use shared::write_le_u16;

    /// Test image geometry: an 8192-byte image whose dynamic header sits
    /// at 512, leaving 2048..4096 free for locator platform data.
    const TEST_BOUNDS: VhdImageBounds = VhdImageBounds {
        image_len: 8192,
        header_offset: 512,
    };
    /// Absolute file offset of the locator-data window used by the tests.
    const WIN_BASE: u64 = 2048;
    /// Bytes of window reserved per locator slot.
    const SLOT_STRIDE: usize = 128;

    /// Encode `s` as UTF-16 into `dst`, returning the byte count.
    fn enc_utf16(s: &str, big_endian: bool, dst: &mut [u8]) -> usize {
        let mut n = 0usize;
        let mut units = [0u16; 2];
        for ch in s.chars() {
            for unit in ch.encode_utf16(&mut units).iter() {
                if big_endian {
                    write_be_u16(dst, n, *unit);
                } else {
                    write_le_u16(dst, n, *unit);
                }
                n += 2;
            }
        }
        n
    }

    /// A dynamic header carrying a parent unique id, a zero timestamp and
    /// `name` in the UTF-16BE parent unicode name field. Locator slots are
    /// left zero; `put_locator` populates them.
    fn make_diff_header(name: &str) -> [u8; 1024] {
        let mut buf = make_dynamic_header(1536, 512, DEFAULT_BLOCK_SIZE);
        // The parent unique id from the pin's xxd of fat-differential.vhd.
        buf[DYN_PARENT_UNIQUE_ID_OFFSET..DYN_PARENT_UNIQUE_ID_OFFSET + 16].copy_from_slice(&[
            0x5f, 0xa2, 0x1a, 0x55, 0xf3, 0x94, 0xaa, 0x4d, 0x99, 0x58, 0x19, 0x51, 0xa6, 0x7d,
            0x55, 0x40,
        ]);
        write_be_u32(&mut buf, DYN_PARENT_TIMESTAMP_OFFSET, 0);
        let mut tmp = [0u8; DYN_PARENT_NAME_SIZE];
        let n = enc_utf16(name, true, &mut tmp);
        assert!(n <= DYN_PARENT_NAME_SIZE);
        buf[DYN_PARENT_NAME_OFFSET..DYN_PARENT_NAME_OFFSET + n].copy_from_slice(&tmp[..n]);
        buf
    }

    /// Write one locator entry into `buf`.
    fn put_locator(
        buf: &mut [u8; 1024],
        slot: usize,
        code: &[u8; 4],
        space: u32,
        length: u32,
        offset: u64,
    ) {
        let off = DYN_PARENT_LOCATORS_OFFSET + slot * PARENT_LOCATOR_ENTRY_SIZE;
        buf[off + LOC_PLATFORM_CODE_OFFSET..off + LOC_PLATFORM_CODE_OFFSET + 4]
            .copy_from_slice(code);
        write_be_u32(buf, off + LOC_DATA_SPACE_OFFSET, space);
        write_be_u32(buf, off + LOC_DATA_LENGTH_OFFSET, length);
        write_be_u64(buf, off + LOC_DATA_OFFSET_OFFSET, offset);
    }

    /// Write `path` as UTF-16LE into slot `slot` of the window and point a
    /// locator entry at it.
    fn put_locator_path(
        buf: &mut [u8; 1024],
        win: &mut [u8; 2048],
        slot: usize,
        code: &[u8; 4],
        path: &str,
    ) {
        let rel = slot * SLOT_STRIDE;
        let n = enc_utf16(path, false, &mut win[rel..rel + SLOT_STRIDE]);
        put_locator(
            buf,
            slot,
            code,
            SLOT_STRIDE as u32,
            n as u32,
            WIN_BASE + rel as u64,
        );
    }

    fn window(win: &[u8]) -> VhdImageWindow<'_> {
        VhdImageWindow {
            file_offset: WIN_BASE,
            bytes: win,
        }
    }

    // -------- parent identity fields ------------------------------------

    #[test]
    fn parent_fields_parse() {
        let buf = make_diff_header(".\\fat-parent.vhd");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.unique_id,
            [
                0x5f, 0xa2, 0x1a, 0x55, 0xf3, 0x94, 0xaa, 0x4d, 0x99, 0x58, 0x19, 0x51, 0xa6, 0x7d,
                0x55, 0x40
            ]
        );
        assert_eq!(info.timestamp, 0);
        assert_eq!(info.name_utf16_be.len(), DYN_PARENT_NAME_SIZE);
        let mut out = [0u8; MAX_PARENT_NAME_UTF8];
        let n = info.decode_name(&mut out).unwrap();
        assert_eq!(&out[..n], b".\\fat-parent.vhd");
    }

    #[test]
    fn parent_timestamp_is_big_endian() {
        let mut buf = make_diff_header("p.vhd");
        write_be_u32(&mut buf, DYN_PARENT_TIMESTAMP_OFFSET, 0x0102_0304);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(info.timestamp, 0x0102_0304);
        // Proof it is not being read little endian.
        assert_eq!(
            &buf[DYN_PARENT_TIMESTAMP_OFFSET..DYN_PARENT_TIMESTAMP_OFFSET + 4],
            &[0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn parent_name_is_utf16_big_endian() {
        // The exact leading bytes of the pin's xxd at offset 576.
        let buf = make_diff_header("C:");
        assert_eq!(
            &buf[DYN_PARENT_NAME_OFFSET..DYN_PARENT_NAME_OFFSET + 4],
            &[0x00, 0x43, 0x00, 0x3a]
        );
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; MAX_PARENT_NAME_UTF8];
        let n = info.decode_name(&mut out).unwrap();
        assert_eq!(&out[..n], b"C:");
        // Decoding the same bytes little endian must NOT produce "C:".
        // This is the swap the phase is most likely to make.
        let mut wrong = [0u8; MAX_PARENT_NAME_UTF8];
        let m = utf16_to_utf8(info.name_utf16_be, false, &mut wrong).unwrap();
        assert_ne!(&wrong[..m], b"C:");
    }

    #[test]
    fn parent_name_absolute_windows_path() {
        let buf = make_diff_header("C:\\Projects\\dfvfs\\test_data\\fat-parent.vhd");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; MAX_PARENT_NAME_UTF8];
        let n = info.decode_name(&mut out).unwrap();
        assert_eq!(&out[..n], b"C:\\Projects\\dfvfs\\test_data\\fat-parent.vhd");
    }

    #[test]
    fn parent_name_dotdot_traversal_is_parsed_not_resolved() {
        let buf = make_diff_header("../../../etc/passwd");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; MAX_PARENT_NAME_UTF8];
        let n = info.decode_name(&mut out).unwrap();
        // The parser reports the string faithfully and does nothing with
        // it. Refusing a traversal is phase 4's job, resolving it is
        // phase 11's, and neither belongs here.
        assert_eq!(&out[..n], b"../../../etc/passwd");
    }

    #[test]
    fn parent_name_absolute_posix_path_is_parsed_not_opened() {
        let buf = make_diff_header("/etc/passwd");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; MAX_PARENT_NAME_UTF8];
        let n = info.decode_name(&mut out).unwrap();
        assert_eq!(&out[..n], b"/etc/passwd");
    }

    #[test]
    fn parent_name_unc_path() {
        let buf = make_diff_header("\\\\attacker\\share\\probe");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; MAX_PARENT_NAME_UTF8];
        let n = info.decode_name(&mut out).unwrap();
        assert_eq!(&out[..n], b"\\\\attacker\\share\\probe");
    }

    #[test]
    fn parent_name_url() {
        let buf = make_diff_header("http://attacker.example/probe");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; MAX_PARENT_NAME_UTF8];
        let n = info.decode_name(&mut out).unwrap();
        assert_eq!(&out[..n], b"http://attacker.example/probe");
    }

    #[test]
    fn parent_name_256_code_units_with_no_terminator() {
        // vhd-diff-locator-overlong.vhd's shape: the field is full, there
        // is no NUL, and the bytes immediately after it are the locator
        // table. libvhdi defect C over-reads two bytes into that table and
        // reports a 257th character.
        let mut buf = make_dynamic_header(1536, 512, DEFAULT_BLOCK_SIZE);
        for i in 0..256 {
            write_be_u16(&mut buf, DYN_PARENT_NAME_OFFSET + i * 2, b'A' as u16);
        }
        // A populated locator immediately after the name field, whose
        // first bytes would decode as further characters if read.
        put_locator(&mut buf, 0, b"W2ru", 128, 32, WIN_BASE);

        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; MAX_PARENT_NAME_UTF8];
        let n = info.decode_name(&mut out).unwrap();
        assert_eq!(n, 256, "a full field is 256 code units, not 257");
        assert!(out[..n].iter().all(|&b| b == b'A'));
        // The borrowed field stops exactly at the locator table.
        assert_eq!(info.name_utf16_be.len(), DYN_PARENT_NAME_SIZE);
        assert_eq!(
            DYN_PARENT_NAME_OFFSET + DYN_PARENT_NAME_SIZE,
            DYN_PARENT_LOCATORS_OFFSET
        );
    }

    #[test]
    fn parent_name_dst_too_small_is_refused() {
        let buf = make_diff_header("abcdefgh");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; 7];
        assert_eq!(info.decode_name(&mut out), None);
    }

    #[test]
    fn parent_info_parse_short_buffer_or_bad_cookie() {
        assert!(VhdParentInfo::parse(&[0u8; 1023], &TEST_BOUNDS).is_none());
        let mut buf = make_diff_header("p.vhd");
        buf[0] = 0;
        assert!(VhdParentInfo::parse(&buf, &TEST_BOUNDS).is_none());
    }

    #[test]
    fn parent_info_parses_on_a_plain_dynamic_header() {
        // Caller-gated: disk_type lives in the footer, so the parser
        // cannot tell a dynamic header from a differencing one. On a
        // plain dynamic header every parent field reads as zero.
        let buf = make_dynamic_header(1536, 512, DEFAULT_BLOCK_SIZE);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(info.unique_id, [0u8; 16]);
        assert_eq!(info.timestamp, 0);
        let mut out = [0u8; MAX_PARENT_NAME_UTF8];
        assert_eq!(info.decode_name(&mut out), Some(0));
        assert!(info.locators.entries.iter().all(|e| e.is_unused()));
        assert_eq!(
            info.locators.preferred_locator(None),
            PreferredLocator::NotFound
        );
    }

    // -------- locator table structure -----------------------------------

    #[test]
    fn locator_table_hyperv_shape() {
        // Two populated entries followed by six zero slots, as both
        // measured Hyper-V images have.
        let mut buf = make_diff_header("C:\\Projects\\fat-parent.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(
            &mut buf,
            &mut win,
            0,
            b"W2ku",
            "C:\\Projects\\fat-parent.vhd",
        );
        put_locator_path(&mut buf, &mut win, 1, b"W2ru", ".\\fat-parent.vhd");

        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let e = &info.locators.entries;
        assert_eq!(e[0].platform(), VhdPlatform::W2ku);
        assert_eq!(e[1].platform(), VhdPlatform::W2ru);
        assert!(e[0].defect.is_none() && e[1].defect.is_none());
        assert!(e[2..].iter().all(|x| x.is_unused() && x.defect.is_none()));
        // Platform code is ASCII in file order, not byte-swapped.
        assert_eq!(&e[0].platform_code, b"W2ku");
        // Platform data space is a byte count, not a sector count.
        assert_eq!(e[0].platform_data_space, SLOT_STRIDE as u32);
    }

    #[test]
    fn locator_zero_slot_after_populated_one_does_not_end_the_table() {
        // SPEC(VHD) defines no sentinel: a zero slot is skipped, not a
        // terminator and not a defect. This is the common Hyper-V shape.
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(&mut buf, &mut win, 0, b"W2ku", "C:\\p.vhd");
        // slot 1 left zero
        put_locator_path(&mut buf, &mut win, 2, b"W2ru", ".\\p.vhd");

        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert!(info.locators.entries[1].is_unused());
        assert_eq!(info.locators.entries[1].defect, None);
        assert_eq!(info.locators.entries[2].platform(), VhdPlatform::W2ru);
        // The W2ru entry past the gap still wins.
        assert_eq!(
            info.locators.preferred_locator(Some(&window(&win))),
            PreferredLocator::Found { slot: 2 }
        );
    }

    #[test]
    fn locator_data_offset_past_end_of_image() {
        let mut buf = make_diff_header("p.vhd");
        put_locator(&mut buf, 0, b"W2ru", 512, 32, TEST_BOUNDS.image_len - 8);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.entries[0].defect,
            Some(VhdLocatorDefect::DataOutsideImage)
        );
    }

    #[test]
    fn locator_data_overlapping_head_footer_copy() {
        let mut buf = make_diff_header("p.vhd");
        put_locator(&mut buf, 0, b"W2ru", 512, 32, 256);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.entries[0].defect,
            Some(VhdLocatorDefect::OverlapsFooter)
        );
    }

    #[test]
    fn locator_data_overlapping_tail_footer() {
        let mut buf = make_diff_header("p.vhd");
        // image_len 8192, tail footer 7680..8192.
        put_locator(&mut buf, 0, b"W2ru", 512, 32, 7680);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.entries[0].defect,
            Some(VhdLocatorDefect::OverlapsFooter)
        );
    }

    #[test]
    fn locator_data_overlapping_dynamic_header() {
        let mut buf = make_diff_header("p.vhd");
        // Header 512..1536; a locator claiming its own header bytes.
        put_locator(&mut buf, 0, b"W2ru", 512, 64, 1024);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.entries[0].defect,
            Some(VhdLocatorDefect::OverlapsHeader)
        );
    }

    #[test]
    fn locator_length_exceeds_space() {
        let mut buf = make_diff_header("p.vhd");
        put_locator(&mut buf, 0, b"W2ru", 32, 64, WIN_BASE);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.entries[0].defect,
            Some(VhdLocatorDefect::LengthExceedsSpace)
        );
    }

    #[test]
    fn locator_offset_overflow() {
        let mut buf = make_diff_header("p.vhd");
        put_locator(&mut buf, 0, b"W2ru", 512, 64, u64::MAX - 8);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.entries[0].defect,
            Some(VhdLocatorDefect::OffsetOverflow)
        );
    }

    #[test]
    fn locator_populated_code_with_zero_length() {
        let mut buf = make_diff_header("p.vhd");
        put_locator(&mut buf, 0, b"W2ru", 512, 0, WIN_BASE);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.entries[0].defect,
            Some(VhdLocatorDefect::EmptyData)
        );
    }

    #[test]
    fn locator_malformed_entry_preserves_raw_fields() {
        // Decision 4: marked, not dropped, and phase 4 can say why.
        let mut buf = make_diff_header("p.vhd");
        put_locator(&mut buf, 0, b"W2ru", 0x1234, 0x5678, 0xdead_beef);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let e = &info.locators.entries[0];
        assert!(e.defect.is_some());
        assert_eq!(&e.platform_code, b"W2ru");
        assert_eq!(e.platform_data_space, 0x1234);
        assert_eq!(e.platform_data_length, 0x5678);
        assert_eq!(e.platform_data_offset, 0xdead_beef);
        assert!(!e.is_candidate());
    }

    #[test]
    fn locator_reserved_field_is_preserved() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(&mut buf, &mut win, 0, b"W2ru", ".\\p.vhd");
        let off = DYN_PARENT_LOCATORS_OFFSET + LOC_RESERVED_OFFSET;
        write_be_u32(&mut buf, off, 0xabad_1dea);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(info.locators.entries[0].reserved, 0xabad_1dea);
    }

    #[test]
    fn locator_table_parse_short_buffer() {
        assert!(VhdParentLocatorTable::parse(&[0u8; 191], &TEST_BOUNDS).is_none());
        assert!(VhdParentLocatorTable::parse(&[0u8; 192], &TEST_BOUNDS).is_some());
        assert!(VhdParentLocator::parse(&[0u8; 23], &TEST_BOUNDS).is_none());
    }

    // -------- decoding platform data ------------------------------------

    #[test]
    fn decode_path_is_utf16_little_endian() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(
            &mut buf,
            &mut win,
            0,
            b"W2ku",
            "C:\\Projects\\fat-parent.vhd",
        );
        // The exact leading bytes of the pin's xxd at offset 4096.
        assert_eq!(&win[..4], &[0x43, 0x00, 0x3a, 0x00]);

        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; 1024];
        let n = info.locators.entries[0]
            .decode_path(&window(&win), &mut out)
            .unwrap();
        assert_eq!(&out[..n], b"C:\\Projects\\fat-parent.vhd");
    }

    #[test]
    fn decode_path_adversarial_shapes_are_reported_verbatim() {
        for (slot, path) in [
            (0usize, "/etc/passwd"),
            (1, "../../../etc/passwd"),
            (2, "\\\\attacker\\share\\probe"),
            (3, "http://attacker.example/probe"),
        ] {
            let mut buf = make_diff_header(path);
            let mut win = [0u8; 2048];
            put_locator_path(&mut buf, &mut win, slot, b"W2ru", path);
            let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
            let mut out = [0u8; 1024];
            let n = info.locators.entries[slot]
                .decode_path(&window(&win), &mut out)
                .unwrap();
            assert_eq!(&out[..n], path.as_bytes());
        }
    }

    #[test]
    fn decode_path_refuses_non_windows_platform_codes() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(&mut buf, &mut win, 0, b"MacX", "file:///p.vhd");
        put_locator_path(&mut buf, &mut win, 1, b"Mac ", "opaque");
        put_locator_path(&mut buf, &mut win, 2, b"Xtra", "unknown");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; 1024];
        for slot in 0..3 {
            assert_eq!(
                info.locators.entries[slot].decode_path(&window(&win), &mut out),
                Err(VhdLocatorDefect::UnsupportedPlatformCode)
            );
        }
        assert_eq!(info.locators.entries[0].platform(), VhdPlatform::MacX);
        assert_eq!(info.locators.entries[1].platform(), VhdPlatform::Mac);
        assert_eq!(
            info.locators.entries[2].platform(),
            VhdPlatform::Other(*b"Xtra")
        );
    }

    #[test]
    fn decode_path_without_a_window_is_data_not_supplied() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(&mut buf, &mut win, 0, b"W2ru", ".\\p.vhd");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; 1024];
        // A window that does not reach the entry's data: the caller can
        // widen it and retry, which is why this is not `Undecodable`.
        let narrow = VhdImageWindow {
            file_offset: WIN_BASE,
            bytes: &win[..4],
        };
        assert_eq!(
            info.locators.entries[0].decode_path(&narrow, &mut out),
            Err(VhdLocatorDefect::DataNotSupplied)
        );
        let elsewhere = VhdImageWindow {
            file_offset: 4096,
            bytes: &win[..],
        };
        assert_eq!(
            info.locators.entries[0].decode_path(&elsewhere, &mut out),
            Err(VhdLocatorDefect::DataNotSupplied)
        );
    }

    #[test]
    fn decode_path_refuses_an_unpaired_surrogate() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        // Lone high surrogate, little endian.
        win[0] = 0x3d;
        win[1] = 0xd8;
        win[2] = b'a';
        win[3] = 0x00;
        put_locator(&mut buf, 0, b"W2ru", SLOT_STRIDE as u32, 4, WIN_BASE);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; 1024];
        assert_eq!(
            info.locators.entries[0].decode_path(&window(&win), &mut out),
            Err(VhdLocatorDefect::Undecodable)
        );
    }

    #[test]
    fn decode_path_refuses_an_odd_length_blob() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        let n = enc_utf16(".\\p.vhd", false, &mut win);
        put_locator(
            &mut buf,
            0,
            b"W2ru",
            SLOT_STRIDE as u32,
            n as u32 - 1,
            WIN_BASE,
        );
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; 1024];
        assert_eq!(
            info.locators.entries[0].decode_path(&window(&win), &mut out),
            Err(VhdLocatorDefect::Undecodable)
        );
    }

    #[test]
    fn decode_path_on_a_malformed_entry_reports_the_structural_defect() {
        let mut buf = make_diff_header("p.vhd");
        let win = [0u8; 2048];
        put_locator(&mut buf, 0, b"W2ru", 512, 32, TEST_BOUNDS.image_len - 8);
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        let mut out = [0u8; 1024];
        assert_eq!(
            info.locators.entries[0].decode_path(&window(&win), &mut out),
            Err(VhdLocatorDefect::DataOutsideImage)
        );
    }

    // -------- preferred_locator -----------------------------------------

    #[test]
    fn preferred_locator_prefers_w2ru_over_w2ku() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        // W2ku first in slot order, as Hyper-V writes it.
        put_locator_path(&mut buf, &mut win, 0, b"W2ku", "C:\\p.vhd");
        put_locator_path(&mut buf, &mut win, 1, b"W2ru", ".\\p.vhd");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.preferred_locator(Some(&window(&win))),
            PreferredLocator::Found { slot: 1 }
        );
    }

    #[test]
    fn preferred_locator_full_precedence_order() {
        let mut win = [0u8; 2048];
        let codes: [&[u8; 4]; 4] = [b"Wi2k", b"Wi2r", b"W2ku", b"W2ru"];
        // Add the codes one at a time, worst first; the newly added code
        // must always win because it outranks everything already there.
        let mut buf = make_diff_header("p.vhd");
        for (i, code) in codes.iter().enumerate() {
            put_locator_path(&mut buf, &mut win, i, code, "p.vhd");
            let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
            assert_eq!(
                info.locators.preferred_locator(Some(&window(&win))),
                PreferredLocator::Found { slot: i },
                "adding {:?} should win",
                core::str::from_utf8(*code).unwrap()
            );
        }
    }

    #[test]
    fn preferred_locator_never_selects_a_non_windows_code() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(&mut buf, &mut win, 0, b"MacX", "file:///p.vhd");
        put_locator_path(&mut buf, &mut win, 1, b"Mac ", "opaque");
        put_locator_path(&mut buf, &mut win, 2, b"Xtra", "unknown");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.preferred_locator(Some(&window(&win))),
            PreferredLocator::NotFound
        );
    }

    #[test]
    fn preferred_locator_skips_malformed_entries() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        // A W2ru that points past the end of the image, and a sound W2ku.
        put_locator(&mut buf, 0, b"W2ru", 512, 32, TEST_BOUNDS.image_len - 8);
        put_locator_path(&mut buf, &mut win, 1, b"W2ku", "C:\\p.vhd");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.preferred_locator(Some(&window(&win))),
            PreferredLocator::Found { slot: 1 }
        );
        // NotFound carries no reason: the caller reads the entries.
        let mut only_bad = make_diff_header("p.vhd");
        put_locator(
            &mut only_bad,
            0,
            b"W2ru",
            512,
            32,
            TEST_BOUNDS.image_len - 8,
        );
        let bad = VhdParentInfo::parse(&only_bad, &TEST_BOUNDS).unwrap();
        assert_eq!(
            bad.locators.preferred_locator(Some(&window(&win))),
            PreferredLocator::NotFound
        );
        assert_eq!(
            bad.locators.entries[0].defect,
            Some(VhdLocatorDefect::DataOutsideImage)
        );
    }

    #[test]
    fn preferred_locator_duplicate_code_that_agrees_is_not_ambiguous() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(&mut buf, &mut win, 0, b"W2ru", ".\\p.vhd");
        put_locator_path(&mut buf, &mut win, 1, b"W2ru", ".\\p.vhd");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.preferred_locator(Some(&window(&win))),
            PreferredLocator::Found { slot: 0 }
        );
    }

    #[test]
    fn preferred_locator_duplicate_code_that_agrees_modulo_a_terminator() {
        // One blob carries a trailing NUL code unit inside its declared
        // length and the other does not. Trimming makes them equal.
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        let n = enc_utf16(".\\p.vhd", false, &mut win[0..SLOT_STRIDE]);
        put_locator(&mut buf, 0, b"W2ru", SLOT_STRIDE as u32, n as u32, WIN_BASE);
        let m = enc_utf16(".\\p.vhd", false, &mut win[SLOT_STRIDE..2 * SLOT_STRIDE]);
        put_locator(
            &mut buf,
            1,
            b"W2ru",
            SLOT_STRIDE as u32,
            m as u32 + 2, // includes the NUL terminator
            WIN_BASE + SLOT_STRIDE as u64,
        );
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.preferred_locator(Some(&window(&win))),
            PreferredLocator::Found { slot: 0 }
        );
    }

    #[test]
    fn preferred_locator_duplicate_code_that_disagrees_is_ambiguous() {
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(&mut buf, &mut win, 0, b"W2ru", ".\\p.vhd");
        put_locator_path(&mut buf, &mut win, 1, b"W2ru", ".\\other.vhd");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.preferred_locator(Some(&window(&win))),
            PreferredLocator::Ambiguous {
                first: 0,
                second: 1,
                reason: AmbiguityReason::ContentsDiffer,
            }
        );
    }

    #[test]
    fn preferred_locator_duplicate_code_without_data_is_ambiguous_unknown() {
        // "I could not check whether they agree" must not read as "they
        // agree": this is a security boundary.
        let mut buf = make_diff_header("p.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(&mut buf, &mut win, 0, b"W2ru", ".\\p.vhd");
        put_locator_path(&mut buf, &mut win, 1, b"W2ru", ".\\p.vhd");
        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.preferred_locator(None),
            PreferredLocator::Ambiguous {
                first: 0,
                second: 1,
                reason: AmbiguityReason::ContentsUnknown,
            }
        );
        // A window too narrow to reach the second entry is the same
        // answer, not a decode failure.
        let narrow = VhdImageWindow {
            file_offset: WIN_BASE,
            bytes: &win[..SLOT_STRIDE],
        };
        assert_eq!(
            info.locators.preferred_locator(Some(&narrow)),
            PreferredLocator::Ambiguous {
                first: 0,
                second: 1,
                reason: AmbiguityReason::ContentsUnknown,
            }
        );
    }

    #[test]
    fn preferred_locator_eight_disagreeing_entries_with_a_duplicate() {
        // vhd-diff-locator-conflicting.vhd's shape: all eight slots
        // populated, mutually disagreeing, with two sharing a code and
        // each blob encoded as its own code requires.
        let mut buf = make_diff_header(".\\name-field.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(&mut buf, &mut win, 0, b"W2ru", ".\\one.vhd");
        put_locator_path(&mut buf, &mut win, 1, b"W2ru", ".\\two.vhd");
        put_locator_path(&mut buf, &mut win, 2, b"W2ku", "C:\\three.vhd");
        put_locator_path(&mut buf, &mut win, 3, b"Wi2r", ".\\four.vhd");
        put_locator_path(&mut buf, &mut win, 4, b"Wi2k", "C:\\five.vhd");
        put_locator_path(&mut buf, &mut win, 5, b"MacX", "file:///six.vhd");
        put_locator_path(&mut buf, &mut win, 6, b"Mac ", "seven");
        put_locator_path(&mut buf, &mut win, 7, b"Xtra", "eight");

        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert!(info.locators.entries.iter().all(|e| e.defect.is_none()));
        assert_eq!(
            info.locators.preferred_locator(Some(&window(&win))),
            PreferredLocator::Ambiguous {
                first: 0,
                second: 1,
                reason: AmbiguityReason::ContentsDiffer,
            }
        );
    }

    #[test]
    fn preferred_locator_eight_disagreeing_entries_without_a_duplicate() {
        // Same table with the duplicate removed. Ambiguity means "two
        // entries sharing a code disagree", NOT "the entries disagree":
        // precedence between different codes is a fact about the format,
        // so W2ru legitimately beats six dissenting others and the answer
        // is confident. The parent unicode name naming a ninth candidate
        // is not ambiguity either, and is not checked in this phase.
        let mut buf = make_diff_header(".\\name-field.vhd");
        let mut win = [0u8; 2048];
        put_locator_path(&mut buf, &mut win, 0, b"W2ku", "C:\\one.vhd");
        put_locator_path(&mut buf, &mut win, 1, b"Wi2r", ".\\two.vhd");
        put_locator_path(&mut buf, &mut win, 2, b"Wi2k", "C:\\three.vhd");
        put_locator_path(&mut buf, &mut win, 3, b"MacX", "file:///four.vhd");
        put_locator_path(&mut buf, &mut win, 4, b"Mac ", "five");
        put_locator_path(&mut buf, &mut win, 5, b"Xtra", "six");
        put_locator_path(&mut buf, &mut win, 6, b"W2ru", ".\\seven.vhd");

        let info = VhdParentInfo::parse(&buf, &TEST_BOUNDS).unwrap();
        assert_eq!(
            info.locators.preferred_locator(Some(&window(&win))),
            PreferredLocator::Found { slot: 6 }
        );
        let mut out = [0u8; 1024];
        let n = info.locators.entries[6]
            .decode_path(&window(&win), &mut out)
            .unwrap();
        assert_eq!(&out[..n], b".\\seven.vhd");
        // The name field disagrees with the winner and nothing complains.
        let mut name = [0u8; MAX_PARENT_NAME_UTF8];
        let m = info.decode_name(&mut name).unwrap();
        assert_eq!(&name[..m], b".\\name-field.vhd");
    }

    // -------- window bounds ---------------------------------------------

    #[test]
    fn window_slice_at_bounds() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let w = VhdImageWindow {
            file_offset: 1000,
            bytes: &bytes,
        };
        assert_eq!(w.slice_at(1000, 8), Some(&bytes[..]));
        assert_eq!(w.slice_at(1004, 4), Some(&bytes[4..]));
        assert_eq!(w.slice_at(1008, 0), Some(&bytes[8..]));
        // Before the window.
        assert_eq!(w.slice_at(999, 1), None);
        // Past the end.
        assert_eq!(w.slice_at(1004, 5), None);
        assert_eq!(w.slice_at(1009, 0), None);
        // Arithmetic that would overflow or truncate.
        assert_eq!(w.slice_at(u64::MAX, 8), None);
        assert_eq!(w.slice_at(1000, u64::MAX), None);
    }

    // ====================================================================
    // Checksum tests
    // ====================================================================

    #[test]
    fn checksum_zeros() {
        let buf = [0u8; 512];
        // All zeros → sum = 0 → complement = 0xFFFFFFFF
        assert_eq!(compute_checksum(&buf, FOOTER_CHECKSUM_OFFSET), !0u32);
    }

    #[test]
    fn checksum_footer_round_trip() {
        let buf = make_footer(1024 * 1024 * 1024, DISK_TYPE_DYNAMIC, 512);
        let stored = be_u32(&buf, FOOTER_CHECKSUM_OFFSET);
        let computed = compute_checksum(&buf, FOOTER_CHECKSUM_OFFSET);
        assert_eq!(stored, computed);
    }

    #[test]
    fn checksum_dynamic_header_round_trip() {
        let buf = make_dynamic_header(1536, 512, DEFAULT_BLOCK_SIZE);
        let stored = be_u32(&buf, DYN_CHECKSUM_OFFSET);
        let computed = compute_checksum(&buf, DYN_CHECKSUM_OFFSET);
        assert_eq!(stored, computed);
    }

    // ====================================================================
    // CHS geometry tests
    // ====================================================================

    #[test]
    fn geometry_small_disk() {
        // 40 MiB disk
        let size = 40 * 1024 * 1024;
        let (cyl, heads, spt) = compute_vhd_geometry(size);
        assert!(cyl > 0);
        assert!(heads >= 4);
        assert!(spt >= 17);
        // Total addressable should cover the size
        let addressable = cyl as u64 * heads as u64 * spt as u64 * 512;
        assert!(addressable >= size || addressable >= cyl as u64 * heads as u64 * spt as u64 * 512);
    }

    #[test]
    fn geometry_1gib_disk() {
        // 1 GiB disk
        let size = 1024 * 1024 * 1024;
        let (cyl, heads, spt) = compute_vhd_geometry(size);
        assert!(cyl > 0);
        assert!(heads > 0);
        assert!(spt > 0);
    }

    #[test]
    fn geometry_large_disk() {
        // 2 TiB disk (max CHS)
        let size = 2u64 * 1024 * 1024 * 1024 * 1024;
        let (cyl, heads, spt) = compute_vhd_geometry(size);
        assert_eq!(cyl, 65535);
        assert_eq!(heads, 16);
        assert_eq!(spt, 255);
    }

    #[test]
    fn geometry_zero_disk() {
        let (_cyl, _heads, spt) = compute_vhd_geometry(0);
        // Zero size: total_sectors = 0, should still produce valid geometry
        assert_eq!(spt, 17); // Falls into small disk branch
    }

    // ====================================================================
    // build_footer / build_dynamic_header round-trip tests
    // ====================================================================

    #[test]
    fn build_footer_round_trip() {
        let size = 1024 * 1024 * 1024; // 1 GiB
        let uuid = [1u8; 16];
        let mut buf = [0u8; 512];
        build_footer(&mut buf, size, DISK_TYPE_DYNAMIC, 512, &uuid);

        let footer = VhdFooter::parse(&buf).unwrap();
        assert_eq!(footer.current_size, size);
        assert_eq!(footer.original_size, size);
        assert_eq!(footer.disk_type, DISK_TYPE_DYNAMIC);
        assert_eq!(footer.data_offset, 512);
        assert_eq!(footer.uuid, uuid);

        // Verify checksum
        let computed = compute_checksum(&buf, FOOTER_CHECKSUM_OFFSET);
        assert_eq!(footer.checksum, computed);
    }

    #[test]
    fn build_footer_creator_app_is_qem2() {
        // Do not "tidy" this to a friendlier identifier. qemu's
        // vpc_open uses the footer's CHS product as the disk size
        // unless the creator app is "win " or "qem2" (or the CHS is
        // maxed), and instar writes floor geometry that can address
        // less than current_size. Any other creator app makes every
        // qemu before 10.0 truncate instar's VHDs.
        let mut buf = [0u8; 512];
        build_footer(
            &mut buf,
            2 * 1024 * 1024,
            DISK_TYPE_DYNAMIC,
            512,
            &[0u8; 16],
        );
        assert_eq!(
            &buf[FOOTER_CREATOR_APP_OFFSET..FOOTER_CREATOR_APP_OFFSET + 4],
            b"qem2",
        );
    }

    #[test]
    fn build_footer_declares_a_size_old_readers_can_reach() {
        // The defect this guards: a footer whose CHS product is
        // smaller than current_size is only safe because "qem2"
        // tells the reader to ignore the geometry. Assert the pairing
        // holds for the sizes that exposed it -- 2 MiB floors to
        // 60/4/17 = 2088960, 8192 short of the declared 2097152.
        for size in [2 * 1024 * 1024u64, 100 * 1024 * 1024, 1024 * 1024 * 1024] {
            let mut buf = [0u8; 512];
            build_footer(&mut buf, size, DISK_TYPE_DYNAMIC, 512, &[0u8; 16]);
            let footer = VhdFooter::parse(&buf).unwrap();
            assert_eq!(footer.current_size, size);

            let (c, h, s) = footer_geometry(size);
            let chs_bytes = c as u64 * h as u64 * s as u64 * 512;
            if chs_bytes < size {
                assert_eq!(
                    &buf[FOOTER_CREATOR_APP_OFFSET..FOOTER_CREATOR_APP_OFFSET + 4],
                    b"qem2",
                    "size {size} has under-addressing CHS ({chs_bytes}) and so \
                     REQUIRES the qem2 creator app to be read correctly",
                );
            }
        }
    }

    #[test]
    fn build_dynamic_header_round_trip() {
        let mut buf = [0u8; 1024];
        build_dynamic_header(&mut buf, 1536, 512, DEFAULT_BLOCK_SIZE);

        let hdr = VhdDynamicHeader::parse(&buf).unwrap();
        assert_eq!(hdr.table_offset, 1536);
        assert_eq!(hdr.max_table_entries, 512);
        assert_eq!(hdr.block_size, DEFAULT_BLOCK_SIZE);

        // Verify checksum
        let computed = compute_checksum(&buf, DYN_CHECKSUM_OFFSET);
        assert_eq!(hdr.checksum, computed);
    }

    // ====================================================================
    // count_allocated_in_bat tests
    // ====================================================================

    /// Helper: encode a u32 as 4 big-endian bytes.
    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    #[test]
    fn bat_count_empty() {
        // Empty slice → 0 allocated entries.
        assert_eq!(count_allocated_in_bat(&[]), 0);
    }

    #[test]
    fn bat_count_all_allocated() {
        // 4 entries, all with small non-0xFFFFFFFF values → all allocated.
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&be32(0x0000_0001));
        buf[4..8].copy_from_slice(&be32(0x0000_0002));
        buf[8..12].copy_from_slice(&be32(0x0000_0003));
        buf[12..16].copy_from_slice(&be32(0x0000_0004));
        assert_eq!(count_allocated_in_bat(&buf), 4);
    }

    #[test]
    fn bat_count_all_unallocated() {
        // 4 entries, all 0xFFFFFFFF → 0 allocated.
        let buf = [0xFF_u8; 16];
        assert_eq!(count_allocated_in_bat(&buf), 0);
    }

    #[test]
    fn bat_count_mixed() {
        // 5 entries: entries 0 and 3 are allocated, entries 1, 2, 4 are not.
        // Expected: 2.
        let mut buf = [0u8; 20];
        buf[0..4].copy_from_slice(&be32(0x0000_0010)); // allocated
        buf[4..8].copy_from_slice(&be32(BAT_UNALLOCATED)); // unallocated
        buf[8..12].copy_from_slice(&be32(BAT_UNALLOCATED)); // unallocated
        buf[12..16].copy_from_slice(&be32(0x0000_0020)); // allocated
        buf[16..20].copy_from_slice(&be32(BAT_UNALLOCATED)); // unallocated
        assert_eq!(count_allocated_in_bat(&buf), 2);
    }

    #[test]
    fn bat_count_trailing_partial_entry() {
        // 3 complete entries + 1 trailing byte (13 bytes total).
        // chunks_exact(4) must discard the tail and count only 3 entries.
        // Entries: allocated, unallocated, allocated → expected 2.
        let mut buf = [0u8; 13];
        buf[0..4].copy_from_slice(&be32(0x0000_0001)); // allocated
        buf[4..8].copy_from_slice(&be32(BAT_UNALLOCATED)); // unallocated
        buf[8..12].copy_from_slice(&be32(0x0000_0002)); // allocated
        buf[12] = 0x00; // trailing garbage byte — must be ignored
        assert_eq!(count_allocated_in_bat(&buf), 2);
    }

    #[test]
    fn bat_count_large_every_seventh_allocated() {
        // 1024 entries, with every 7th entry allocated (indices 0, 7, 14, ...).
        // Count = number of i in 0..1024 where i % 7 == 0.
        let mut buf = [0xFF_u8; 1024 * 4];
        let mut expected: u64 = 0;
        for i in 0usize..1024 {
            if i % 7 == 0 {
                let off = i * 4;
                buf[off..off + 4].copy_from_slice(&be32(i as u32));
                expected += 1;
            }
        }
        // Verify expected: ceil(1023 / 7) + 1 = 146 + 1 = 147.
        assert_eq!(expected, 147);
        assert_eq!(count_allocated_in_bat(&buf), 147);
    }

    #[test]
    fn bat_count_zero_value_is_allocated() {
        // BAT entry value 0 is a valid sector pointer → must count as allocated.
        // Only 0xFFFFFFFF is the unallocated sentinel.
        let buf = be32(0x0000_0000);
        assert_eq!(count_allocated_in_bat(&buf), 1);
    }

    // ====================================================================
    // classify_vhd_bat_entry tests
    // ====================================================================

    #[test]
    fn classify_vhd_unallocated_is_hole() {
        let e = classify_vhd_bat_entry(BAT_UNALLOCATED, 0, 2 * 1024 * 1024, 512);
        assert_eq!(e.state, MapExtentState::Hole);
        assert_eq!(e.length, 2 * 1024 * 1024);
    }

    #[test]
    fn classify_vhd_allocated_is_data_with_bitmap_offset() {
        // Block starts at sector 10, bitmap is 512 bytes (1 sector),
        // so payload starts at byte 10*512 + 512 = 5632.
        let e = classify_vhd_bat_entry(10, 0, 2 * 1024 * 1024, 512);
        assert_eq!(e.state, MapExtentState::Data { file_offset: 5632 });
    }

    #[test]
    fn classify_vhd_allocated_zero_sector() {
        // BAT entry of 0 is a valid sector pointer (sector 0); payload
        // starts at block_data_offset bytes.
        let e = classify_vhd_bat_entry(0, 0, 2 * 1024 * 1024, 512);
        assert_eq!(e.state, MapExtentState::Data { file_offset: 512 });
    }

    #[test]
    fn classify_vhd_large_block_index() {
        // 2 MiB block at sector 1000.
        let e = classify_vhd_bat_entry(1000, 4 * 1024 * 1024, 2 * 1024 * 1024, 1024);
        assert_eq!(e.start, 4 * 1024 * 1024);
        assert_eq!(e.length, 2 * 1024 * 1024);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 1000 * 512 + 1024
            }
        );
    }

    #[test]
    fn classify_vhd_max_sector_pointer_minus_one() {
        // 0xFFFFFFFE is allocated (only 0xFFFFFFFF is unallocated).
        let e = classify_vhd_bat_entry(0xFFFF_FFFE, 0, 2 * 1024 * 1024, 512);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 0xFFFF_FFFEu64 * 512 + 512
            }
        );
    }

    #[test]
    fn classify_vhd_block_data_offset_zero() {
        // A theoretical zero-bitmap layout: payload starts exactly at
        // sector boundary.
        let e = classify_vhd_bat_entry(100, 0, 4096, 0);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 100 * 512
            }
        );
    }

    // ====================================================================
    // chs_rounded_size tests
    // ====================================================================

    /// Verified against `qemu-img create -f vpc <size>` (virtual-size
    /// via `qemu-img info`, CHS + current_size read from the footer),
    /// qemu-img 10.0.8. The `(35651584, ...)` row is the differential-
    /// fuzz dd window from issue #382 (69632 sectors), where the old
    /// one-pass ceil approximation produced 35807232 with a footer CHS
    /// (822/5/17) that did not even match its own current_size; qemu's
    /// upward search lands on 820/5/17 = 69700 sectors. The >=1.6 GiB
    /// rows pin the removal of the non-qemu `65535*3*17` "medium-large"
    /// 255-sectors-per-track branch (qemu switches to 255 spt only at
    /// 65535*16*63 sectors). The `(53426191, ...)` row is issue #413:
    /// qemu's search lands on candidate 104465 whose geometry
    /// 877×7×17 = 104363 covers the 104349-sector request, but the
    /// FLOOR geometry of 104363 sectors is 1023×6×17 = 104346 (the
    /// candidate sits above a head-count boundary, ceil(6145/1024) = 7
    /// heads, while its product sits below one, ceil(6139/1024) = 6) —
    /// so the footer CHS must come from the search, not from
    /// re-flooring current_size. The final three rows pin the
    /// max-geometry window edges (footer CHS from the search; in the
    /// window current_size keeps the exact request while the ceiling
    /// CHS addresses slightly more).
    #[test]
    fn chs_rounded_size_matches_qemu() {
        let cases: &[(u64, u64, (u16, u8, u8))] = &[
            (512, 34816, (1, 4, 17)),
            (1000, 34816, (1, 4, 17)),
            (3000, 34816, (1, 4, 17)),
            (34816, 34816, (1, 4, 17)),
            (34817, 69632, (2, 4, 17)),
            (65536, 69632, (2, 4, 17)),
            (131072, 139264, (4, 4, 17)),
            (1048576, 1079296, (31, 4, 17)),
            (35553280, 35581952, (1022, 4, 17)),
            (35651584, 35686400, (820, 5, 17)),
            (35686400, 35686400, (820, 5, 17)),
            (53426191, 53433856, (877, 7, 17)),
            (53433856, 53433856, (877, 7, 17)),
            (1073741824, 1073995776, (2081, 16, 63)),
            (1610612736, 1610735616, (3121, 16, 63)),
            (1711249920, 1711374336, (3316, 16, 63)),
            (1711250432, 1711374336, (3316, 16, 63)),
            (2147483648, 2147991552, (4162, 16, 63)),
            (3221225472, 3221471232, (6242, 16, 63)),
            (10737418240, 10737893376, (20806, 16, 63)),
            (
                65534 * 16 * 255 * 512,
                65534 * 16 * 255 * 512,
                (65534, 16, 255),
            ),
            (
                (65534 * 16 * 255 + 1) * 512,
                (65534 * 16 * 255 + 1) * 512,
                (65535, 16, 255),
            ),
            (
                65535 * 16 * 255 * 512,
                65535 * 16 * 255 * 512,
                (65535, 16, 255),
            ),
        ];
        assert_eq!(chs_rounded_size(0), 0);
        assert_eq!(chs_rounded_geometry(0), (0, 0, 0));
        assert_eq!(footer_geometry(0), (0, 0, 0));
        for &(input, expected, chs) in cases {
            let r = chs_rounded_size(input);
            assert_eq!(
                r, expected,
                "chs_rounded_size({input}) should be {expected}"
            );
            assert_eq!(
                chs_rounded_geometry(input),
                chs,
                "search CHS for input {input}"
            );
            assert_eq!(
                footer_geometry(r),
                chs,
                "footer CHS recomputed from rounded size {r} (input {input})"
            );
        }
    }

    /// For each CHS-rounded size r, the footer geometry must address r
    /// exactly: c * h * spt * 512 == r. This holds for every input
    /// whose rounded size is a geometry product — i.e. everything
    /// below the max-geometry window (the top ~2 MiB below the
    /// 2040 GiB ceiling, where qemu keeps the exact sector-rounded
    /// request instead). Note this is the SEARCH geometry
    /// ([`footer_geometry`] / [`chs_rounded_geometry`]); the floor
    /// [`compute_vhd_geometry`] of r can address less (issue #413).
    ///
    /// Skips r == 0 (no CHS geometry for empty disks).
    #[test]
    fn chs_rounded_size_is_chs_consistent() {
        let inputs: &[u64] = &[
            512,
            1000,
            3000,
            34816,
            34817,
            65536,
            131072,
            1048576,
            1073741824,
            // Extras not in the qemu table, including the spt=255
            // branch (>= 65535*16*63 sectors) the old implementation
            // excluded:
            2_000_000,
            500_000_000,
            10_737_418_240,
            35_651_584,
            65535 * 16 * 63 * 512,
            100_000_000_000,
            // Issue #413: the fuzzer input whose rounded size is not a
            // floor-geometry fixed point.
            53_426_191,
        ];
        for &s in inputs {
            let r = chs_rounded_size(s);
            assert_ne!(
                r, 0,
                "chs_rounded_size({s}) must not be 0 for non-zero input"
            );
            let (c, h, spt) = footer_geometry(r);
            let reconstructed = c as u64 * h as u64 * spt as u64 * 512;
            assert_eq!(
                reconstructed, r,
                "geometry round-trip failed for input={s}: \
                 chs_rounded_size={r}, c={c} h={h} spt={spt}, \
                 c*h*spt*512={reconstructed}"
            );
        }
    }

    /// Issue #413 divergence pin: for a qemu-rounded size the footer
    /// CHS is the upward-search geometry, which can differ from the
    /// floor geometry of the same byte count; for a size qemu-img
    /// would never declare (not a fixed point of chs_rounded_size) the
    /// footer keeps the VHD-spec floor geometry.
    #[test]
    fn footer_geometry_search_vs_floor() {
        // 104363 sectors: search and floor geometries differ, and only
        // the search geometry addresses the whole disk.
        let rounded = 53433856u64;
        assert_eq!(footer_geometry(rounded), (877, 7, 17));
        assert_eq!(compute_vhd_geometry(rounded), (1023, 6, 17));

        // 1 GiB is not a qemu-roundable size (qemu-img would declare
        // 1073995776); verbatim-size writers keep the floor geometry.
        let gib = 1024u64 * 1024 * 1024;
        assert_ne!(chs_rounded_size(gib), gib);
        assert_eq!(footer_geometry(gib), (2080, 16, 63));
        assert_eq!(footer_geometry(gib), compute_vhd_geometry(gib));
    }

    /// build_footer must write the search geometry for qemu-rounded
    /// sizes (issue #413) and CHS (0,0,0) for a zero-size disk
    /// (empirically what qemu-img 10.0.8 writes for a count=0 dd).
    #[test]
    fn build_footer_writes_search_geometry() {
        let uuid = [0u8; 16];
        let mut buf = [0u8; 512];
        build_footer(&mut buf, 53433856, DISK_TYPE_DYNAMIC, 512, &uuid);
        assert_eq!(
            (
                u16::from_be_bytes([buf[FOOTER_GEOMETRY_OFFSET], buf[FOOTER_GEOMETRY_OFFSET + 1]]),
                buf[FOOTER_GEOMETRY_OFFSET + 2],
                buf[FOOTER_GEOMETRY_OFFSET + 3],
            ),
            (877u16, 7u8, 17u8),
            "footer CHS for 53433856 bytes must be qemu's search geometry"
        );

        let mut zbuf = [0u8; 512];
        build_footer(&mut zbuf, 0, DISK_TYPE_DYNAMIC, 512, &uuid);
        assert_eq!(
            &zbuf[FOOTER_GEOMETRY_OFFSET..FOOTER_GEOMETRY_OFFSET + 4],
            &[0u8; 4],
            "zero-size footer CHS must be (0,0,0) as qemu writes"
        );
    }

    /// The max-geometry window: requests the largest sub-ceiling
    /// geometry (65534×16×255) cannot cover round to the EXACT sector
    /// count (qemu keeps the request), and anything past the ceiling
    /// clamps to it (where qemu would refuse).
    #[test]
    fn chs_rounded_size_max_geometry_window() {
        let window_start = 65534u64 * 16 * 255; // largest sub-ceiling product
        assert_eq!(
            chs_rounded_size(window_start * 512),
            window_start * 512,
            "largest sub-ceiling product is a fixed point"
        );
        let in_window = window_start + 1;
        assert_eq!(
            chs_rounded_size(in_window * 512),
            in_window * 512,
            "window sizes keep their exact sector count"
        );
        assert_eq!(
            chs_rounded_size(in_window * 512 - 511),
            in_window * 512,
            "sub-sector window request rounds up to whole sectors"
        );
        assert_eq!(
            chs_rounded_size(VHD_MAX_SECTORS * 512),
            VHD_MAX_SECTORS * 512
        );
        assert_eq!(
            chs_rounded_size(VHD_MAX_SECTORS * 512 + 512),
            VHD_MAX_SECTORS * 512,
            "oversize requests clamp to the CHS ceiling"
        );
    }

    /// chs_rounded_size must never return a value smaller than its input
    /// (for non-zero inputs).
    #[test]
    fn chs_rounded_size_rounds_up() {
        let inputs: &[u64] = &[
            1,
            511,
            512,
            513,
            34815,
            34816,
            34817,
            69631,
            69632,
            130000,
            131072,
            131073,
            1_000_000,
            1_048_576,
            1_073_741_824,
            10_737_418_240,
        ];
        for &s in inputs {
            let r = chs_rounded_size(s);
            assert!(r >= s, "chs_rounded_size({s}) = {r} is less than the input");
        }
    }
}
