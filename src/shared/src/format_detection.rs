//! Format detection for disk images.
//!
//! This module provides shared format detection logic for identifying disk image
//! formats from their headers. It is used by multiple operations (info, check,
//! convert, resize) to avoid code duplication.

use crate::ImageFormat;

// Magic numbers for format detection (big-endian where noted)
/// QCOW2 magic: "QFI\xfb" (big-endian at offset 0)
pub const QCOW2_MAGIC: u32 = 0x514649fb;
/// QCOW1 magic: "QFI" (big-endian at offset 0, 3 bytes)
pub const QCOW1_MAGIC: u32 = 0x514649;
/// VMDK4 magic: "VMDK" (little-endian at offset 0)
pub const VMDK4_MAGIC: u32 = 0x564d444b;
/// VMDK3 magic: "COWD" (little-endian at offset 0)
pub const VMDK3_MAGIC: u32 = 0x434f5744;
/// VHD cookie: "conectix" (big-endian at footer offset 0)
pub const VHD_COOKIE: u64 = 0x636f6e6563746978;
/// VDI magic signature (little-endian at offset 64)
pub const VDI_MAGIC: u32 = 0xbeda107f;
/// QED magic: "QED\0" (little-endian at offset 0)
pub const QED_MAGIC: u32 = 0x00444551;
/// VHDX signature: "vhdxfile" (little-endian at offset 0)
pub const VHDX_SIGNATURE: u64 = 0x656c696678646876;
/// VDI signature offset in header
pub const VDI_SIGNATURE_OFFSET: usize = 64;
/// LUKS magic: "LUKS\xba\xbe" (6 bytes at offset 0)
pub const LUKS_MAGIC: [u8; 6] = [0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe];
/// VMDK text descriptor leading comment. A monolithicFlat VMDK has
/// a descriptor file (distinct from the flat extent file) whose
/// first line is exactly this string — no binary magic. Detection
/// is strict on this prefix so random text files can't be
/// misidentified.
pub const VMDK_DESCRIPTOR_MAGIC: &[u8] = b"# Disk DescriptorFile";

// ISO 9660 format constants
/// ISO 9660 Primary Volume Descriptor byte offset (sector 16 for 2048-byte CD sectors)
pub const ISO_MAGIC_BYTE_OFFSET: usize = 32769;
/// ISO 9660 standard identifier "CD001"
pub const ISO_MAGIC: [u8; 5] = *b"CD001";

// Parallels format constants (qemu block/parallels.c `parallels_probe`)
/// Legacy Parallels magic (16 bytes at offset 0, no NUL terminator).
pub const PARALLELS_MAGIC_V1: [u8; 16] = *b"WithoutFreeSpace";
/// Extended Parallels magic (16 bytes at offset 0, no NUL terminator).
pub const PARALLELS_MAGIC_V2: [u8; 16] = *b"WithouFreSpacExt";
/// Offset of the LE u32 version field, which must equal 2.
pub const PARALLELS_VERSION_OFFSET: usize = 16;
/// Only version 2 headers are recognised by qemu's probe.
pub const PARALLELS_VERSION: u32 = 2;
/// qemu's probe requires a 64-byte buffer even though only the first
/// 20 bytes are inspected.
pub const PARALLELS_HEADER_MIN_LEN: usize = 64;

// Bochs format constants (qemu block/bochs.c `bochs_probe`)
/// qemu's probe requires a full 512-byte header buffer.
pub const BOCHS_HEADER_MIN_LEN: usize = 512;
/// "Bochs Virtual HD Image" magic, NUL-terminated within the 32-byte
/// field at bytes 0..32.
pub const BOCHS_MAGIC: &[u8] = b"Bochs Virtual HD Image";
/// "Redolog" type string, NUL-terminated within the 16-byte field at
/// bytes 32..48.
pub const BOCHS_REDOLOG_TYPE: &[u8] = b"Redolog";
/// "Growing" subtype string, NUL-terminated within the 16-byte field
/// at bytes 48..64.
pub const BOCHS_GROWING_TYPE: &[u8] = b"Growing";
/// Offset of the LE u32 version field.
pub const BOCHS_VERSION_OFFSET: usize = 64;
/// Bochs header version 1 (`HEADER_V1` in qemu).
pub const BOCHS_VERSION_1: u32 = 0x0001_0000;
/// Bochs header version 2 (`HEADER_VERSION` in qemu).
pub const BOCHS_VERSION_2: u32 = 0x0002_0000;

// cloop format constants (qemu block/cloop.c `cloop_probe`)
/// Exact V2.0 shell-script magic at offset 0. qemu's probe compares
/// `min(strlen(magic), buf_size)` bytes, so a truncated file that
/// prefix-matches still probes as cloop there; instar deliberately
/// requires the full magic (recorded as a quirk — degenerate
/// truncated files only). The length used for detection is derived
/// from this literal (`CLOOP_MAGIC.len()`), not hard-coded, so the
/// two can never drift apart.
pub const CLOOP_MAGIC: &[u8] =
    b"#!/bin/sh\n#V2.0 Format\nmodprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1\n";

// DMG format constants (qemu block/dmg.c `dmg_find_koly_offset` / trailer layout)
/// "koly" trailer magic (4 bytes, big-endian layout follows).
pub const DMG_KOLY_MAGIC: [u8; 4] = *b"koly";
/// Size of the koly trailer block.
pub const DMG_KOLY_TRAILER_LEN: usize = 512;
/// Offset within the koly trailer of the BE u64 SectorCount field.
pub const DMG_KOLY_SECTOR_COUNT_OFFSET: usize = 0x1ec;

/// Compare a NUL-terminated ASCII string against a fixed-width field.
///
/// Mirrors qemu's `strcmp` against a fixed-size buffer field (used by
/// the Bochs probe): `field` must start with `expected` followed
/// immediately by a NUL byte. Bytes after that NUL are not inspected —
/// `strcmp` never looks past the first terminator in either string —
/// so trailing garbage beyond the NUL does not affect the result.
fn field_matches_nul_terminated(field: &[u8], expected: &[u8]) -> bool {
    field.len() > expected.len()
        && field[..expected.len()] == *expected
        && field[expected.len()] == 0
}

/// Detect image format from header bytes.
///
/// This function examines the first bytes of an image to identify its format
/// based on magic numbers and header structures.
///
/// # Arguments
///
/// * `buffer` - Buffer containing at least the first sector of the image
/// * `len` - Number of valid bytes in the buffer
/// * `extra_detail` - If true, detect additional formats like LUKS that qemu-img
///   doesn't recognize. If false, these are left as Raw for compatibility.
///
/// # Returns
///
/// The detected `ImageFormat`. Returns `Raw` if no known format is detected
/// from the header (this may be overridden by VHD footer detection or partition
/// table validation depending on the caller).
pub fn detect_format_from_header(buffer: &[u8], len: usize, _extra_detail: bool) -> ImageFormat {
    if len < 8 {
        return ImageFormat::Unknown;
    }

    // Check QCOW2/QCOW1 magic (big-endian)
    let magic_be = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    if magic_be == QCOW2_MAGIC {
        return ImageFormat::Qcow2;
    }
    // QCOW1 has 3-byte magic
    if (magic_be >> 8) == QCOW1_MAGIC {
        return ImageFormat::Qcow1;
    }

    // Check VMDK magic (little-endian)
    let magic_le = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    if magic_le == VMDK4_MAGIC {
        return ImageFormat::Vmdk4;
    }
    if magic_le == VMDK3_MAGIC {
        return ImageFormat::Vmdk3;
    }

    // Check QED magic (little-endian "QED\0")
    if magic_le == QED_MAGIC {
        return ImageFormat::Qed;
    }

    // Check VHDX magic (little-endian, "vhdxfile" signature)
    let vhdx_sig = u64::from_le_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]);
    if vhdx_sig == VHDX_SIGNATURE {
        return ImageFormat::Vhdx;
    }

    // Check for VHD/VPC magic "conectix" (big-endian)
    // Dynamic VHDs have a footer copy at the start of the file
    let vhd_cookie = u64::from_be_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]);
    if vhd_cookie == VHD_COOKIE {
        return ImageFormat::Vhd;
    }

    // Check VDI magic at offset 64 (little-endian)
    // VDI header starts with text signature, magic is at offset 64
    if len >= VDI_SIGNATURE_OFFSET + 4 {
        let vdi_magic = u32::from_le_bytes([
            buffer[VDI_SIGNATURE_OFFSET],
            buffer[VDI_SIGNATURE_OFFSET + 1],
            buffer[VDI_SIGNATURE_OFFSET + 2],
            buffer[VDI_SIGNATURE_OFFSET + 3],
        ]);
        if vdi_magic == VDI_MAGIC {
            return ImageFormat::Vdi;
        }
    }

    // Check LUKS magic at offset 0 (6 bytes: "LUKS\xba\xbe")
    // Always detect LUKS so chain discovery and convert can handle it.
    // The info output display uses extra_detail to control LUKS-specific
    // reporting for qemu-img compatibility.
    if len >= 6 && buffer[0..6] == LUKS_MAGIC {
        return ImageFormat::Luks;
    }

    // Check Parallels magic (16 bytes @0, legacy or extended) with a
    // version LE u32 == 2 @16. Detection and info only — no read path.
    if len >= PARALLELS_HEADER_MIN_LEN
        && (buffer[0..16] == PARALLELS_MAGIC_V1 || buffer[0..16] == PARALLELS_MAGIC_V2)
    {
        let version = u32::from_le_bytes([
            buffer[PARALLELS_VERSION_OFFSET],
            buffer[PARALLELS_VERSION_OFFSET + 1],
            buffer[PARALLELS_VERSION_OFFSET + 2],
            buffer[PARALLELS_VERSION_OFFSET + 3],
        ]);
        if version == PARALLELS_VERSION {
            return ImageFormat::Parallels;
        }
    }

    // Check Bochs growing-disk magic: three NUL-terminated strings in
    // fixed-width fields plus a version field, requiring a full
    // 512-byte header buffer (mirrors qemu's `strcmp`-against-buffer
    // probe, which only cares that a NUL follows the expected prefix —
    // it does not require the rest of the fixed-width field to be
    // zero). Detection and info only — no read path.
    if len >= BOCHS_HEADER_MIN_LEN
        && field_matches_nul_terminated(&buffer[0..32], BOCHS_MAGIC)
        && field_matches_nul_terminated(&buffer[32..48], BOCHS_REDOLOG_TYPE)
        && field_matches_nul_terminated(&buffer[48..64], BOCHS_GROWING_TYPE)
    {
        let version = u32::from_le_bytes([
            buffer[BOCHS_VERSION_OFFSET],
            buffer[BOCHS_VERSION_OFFSET + 1],
            buffer[BOCHS_VERSION_OFFSET + 2],
            buffer[BOCHS_VERSION_OFFSET + 3],
        ]);
        if version == BOCHS_VERSION_1 || version == BOCHS_VERSION_2 {
            return ImageFormat::Bochs;
        }
    }

    // Check cloop's exact 83-byte V2.0 shell-script magic @0.
    // Deliberate divergence from qemu: qemu's probe compares
    // min(strlen(magic), buf_size) bytes, so a truncated file that
    // prefix-matches still probes as cloop there; instar requires the
    // full magic (quirk: degenerate truncated files only). Detection
    // and info only — no read path.
    if len >= CLOOP_MAGIC.len() && buffer[..CLOOP_MAGIC.len()] == *CLOOP_MAGIC {
        return ImageFormat::Cloop;
    }

    // Check for a VMDK text descriptor (monolithicFlat and related
    // two-file formats). Done after every binary magic check so
    // real VMDK4 sparse files (which begin with KDMV) are never
    // misclassified.
    if len >= VMDK_DESCRIPTOR_MAGIC.len()
        && &buffer[..VMDK_DESCRIPTOR_MAGIC.len()] == VMDK_DESCRIPTOR_MAGIC
    {
        return ImageFormat::VmdkDescriptor;
    }

    // Fixed VHD has its signature only at the end, handled separately by caller
    // If no known format detected from header, assume raw (may be overridden)
    ImageFormat::Raw
}

/// Detect VHD format from file footer (last 512 bytes).
///
/// Fixed VHDs store their footer only at the end of the file, so this function
/// should be called when the header-based detection returns Raw but the caller
/// suspects it might be a fixed VHD.
///
/// # Arguments
///
/// * `buffer` - Buffer containing the last sector of the file
///
/// # Returns
///
/// `ImageFormat::Vhd` if the buffer contains a valid VHD cookie, otherwise `Raw`.
pub fn detect_vhd_footer(buffer: &[u8]) -> ImageFormat {
    if buffer.len() < 8 {
        return ImageFormat::Raw;
    }

    // VHD footer starts with "conectix" cookie (big-endian)
    let cookie = u64::from_be_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]);

    if cookie == VHD_COOKIE {
        return ImageFormat::Vhd;
    }

    ImageFormat::Raw
}

/// Locate a DMG "koly" trailer within a buffer holding the final
/// bytes of a file.
///
/// Mirrors qemu's `dmg_find_koly_offset`, which scans the last 1024
/// bytes of the file: candidate trailer start offsets run from
/// `len - 1023` to `len - 512` inclusive (the koly block is 512 bytes
/// and must end at or before `len`, but qemu tolerates up to 511
/// bytes of trailing padding after the real trailer). Files shorter
/// than 512 bytes can never hold a full trailer and are rejected
/// outright.
///
/// # Arguments
///
/// * `buffer` - the final `buffer.len()` bytes of the file, i.e.
///   `buffer[i]` is file byte `len - buffer.len() + i`. Callers are
///   expected to supply up to the last 1024 bytes (the fixed-VHD
///   `footer_buffer` pattern, sized for two 512-byte sectors); a
///   shorter buffer simply narrows how much of the candidate window
///   can be checked.
/// * `len` - total length of the file in bytes.
///
/// # Returns
///
/// The absolute file offset of the koly magic if found within both
/// qemu's candidate window and the supplied buffer, otherwise `None`.
pub fn detect_dmg_koly_offset(buffer: &[u8], len: usize) -> Option<usize> {
    if len < DMG_KOLY_TRAILER_LEN || buffer.is_empty() {
        return None;
    }

    // qemu's candidate window: [len - 1023, len - 512], clamped so it
    // never underflows for files just over the minimum length.
    let window_start = len.saturating_sub(1023);
    let window_end = len - DMG_KOLY_TRAILER_LEN;

    // buffer holds the final buffer.len() bytes of the file; map
    // absolute file offsets back to buffer indices.
    let buffer_base = len.saturating_sub(buffer.len());

    let mut offset = window_start;
    while offset <= window_end {
        if offset >= buffer_base {
            let idx = offset - buffer_base;
            if idx + 4 <= buffer.len() && buffer[idx..idx + 4] == DMG_KOLY_MAGIC {
                return Some(offset);
            }
        }
        offset += 1;
    }

    None
}

/// Read and validate a DMG trailer's SectorCount field.
///
/// SectorCount is a BE u64 at `koly_offset + 0x1ec`. qemu rejects a
/// negative (top-bit-set) sector count as a corrupt trailer
/// (`block/dmg.c`); mirror that rejection here.
///
/// # Arguments
///
/// * `buffer` - the same tail buffer passed to
///   `detect_dmg_koly_offset`.
/// * `len` - total length of the file in bytes.
/// * `koly_offset` - absolute file offset of the koly magic, as
///   returned by `detect_dmg_koly_offset`.
///
/// # Returns
///
/// `Some(sector_count)` if the field lies entirely within both
/// `buffer` and the file, and the top bit is clear. Otherwise `None`.
pub fn dmg_sector_count(buffer: &[u8], len: usize, koly_offset: usize) -> Option<u64> {
    let buffer_base = len.saturating_sub(buffer.len());
    let field_offset = koly_offset.checked_add(DMG_KOLY_SECTOR_COUNT_OFFSET)?;
    let field_end = field_offset.checked_add(8)?;

    if field_offset < buffer_base || field_end > len {
        return None;
    }

    let idx = field_offset - buffer_base;
    if idx + 8 > buffer.len() {
        return None;
    }

    let raw = u64::from_be_bytes([
        buffer[idx],
        buffer[idx + 1],
        buffer[idx + 2],
        buffer[idx + 3],
        buffer[idx + 4],
        buffer[idx + 5],
        buffer[idx + 6],
        buffer[idx + 7],
    ]);

    if raw & (1u64 << 63) != 0 {
        return None;
    }

    Some(raw)
}

/// Detect ISO 9660 format from buffer at the standard offset.
///
/// ISO 9660 format has the Primary Volume Descriptor at byte offset 32768.
/// The identifier "CD001" is at bytes 1-5 of the PVD.
///
/// # Arguments
///
/// * `buffer` - Buffer starting at byte offset `ISO_MAGIC_BYTE_OFFSET` (32769)
///
/// # Returns
///
/// `ImageFormat::Iso` if the buffer contains the ISO 9660 identifier, otherwise `Raw`.
pub fn detect_iso_at_offset(buffer: &[u8], offset: usize) -> ImageFormat {
    if buffer.len() >= offset + 5 && buffer[offset..offset + 5] == ISO_MAGIC {
        return ImageFormat::Iso;
    }
    ImageFormat::Raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_vmdk_descriptor_magic() {
        let desc = b"# Disk DescriptorFile\nversion=1\nCID=abcd\n";
        assert_eq!(
            detect_format_from_header(desc, desc.len(), false),
            ImageFormat::VmdkDescriptor
        );
    }

    #[test]
    fn does_not_misidentify_random_comment_file() {
        let junk = b"# Some random text file\nfoo bar\n";
        // Leading '#' isn't enough; the full descriptor prefix must match.
        assert_eq!(
            detect_format_from_header(junk, junk.len(), false),
            ImageFormat::Raw
        );
    }

    #[test]
    fn vmdk_sparse_binary_still_detected_as_vmdk4() {
        // KDMV magic at offset 0 (little-endian).
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&VMDK4_MAGIC.to_le_bytes());
        assert_eq!(
            detect_format_from_header(&buf, buf.len(), false),
            ImageFormat::Vmdk4
        );
    }

    // ------------------------------------------------------------------
    // Parallels
    // ------------------------------------------------------------------

    // First 64 bytes of instar-testdata's downloaded/qemu-iotests/parallels-v1
    // fixture (WithoutFreeSpace magic, version 2).
    const PARALLELS_V1_FIXTURE_HEADER: [u8; 64] = [
        0x57, 0x69, 0x74, 0x68, 0x6f, 0x75, 0x74, 0x46, 0x72, 0x65, 0x65, 0x53, 0x70, 0x61, 0x63,
        0x65, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    // First 64 bytes of instar-testdata's downloaded/qemu-iotests/parallels-v2
    // fixture (WithouFreSpacExt magic, version 2).
    const PARALLELS_V2_FIXTURE_HEADER: [u8; 64] = [
        0x57, 0x69, 0x74, 0x68, 0x6f, 0x75, 0x46, 0x72, 0x65, 0x53, 0x70, 0x61, 0x63, 0x45, 0x78,
        0x74, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn detects_parallels_v1_from_fixture_header() {
        assert_eq!(
            detect_format_from_header(
                &PARALLELS_V1_FIXTURE_HEADER,
                PARALLELS_V1_FIXTURE_HEADER.len(),
                false
            ),
            ImageFormat::Parallels
        );
    }

    #[test]
    fn detects_parallels_v2_from_fixture_header() {
        assert_eq!(
            detect_format_from_header(
                &PARALLELS_V2_FIXTURE_HEADER,
                PARALLELS_V2_FIXTURE_HEADER.len(),
                false
            ),
            ImageFormat::Parallels
        );
    }

    #[test]
    fn parallels_wrong_version_is_raw() {
        let mut buf = PARALLELS_V1_FIXTURE_HEADER;
        buf[16..20].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            detect_format_from_header(&buf, buf.len(), false),
            ImageFormat::Raw
        );
    }

    #[test]
    fn parallels_truncated_header_is_raw() {
        // 63 bytes: one short of PARALLELS_HEADER_MIN_LEN.
        let buf = &PARALLELS_V1_FIXTURE_HEADER[..63];
        assert_eq!(
            detect_format_from_header(buf, buf.len(), false),
            ImageFormat::Raw
        );
    }

    // ------------------------------------------------------------------
    // Bochs
    // ------------------------------------------------------------------

    fn bochs_header(version: u32) -> [u8; BOCHS_HEADER_MIN_LEN] {
        let mut buf = [0u8; BOCHS_HEADER_MIN_LEN];
        buf[0..BOCHS_MAGIC.len()].copy_from_slice(BOCHS_MAGIC);
        buf[32..32 + BOCHS_REDOLOG_TYPE.len()].copy_from_slice(BOCHS_REDOLOG_TYPE);
        buf[48..48 + BOCHS_GROWING_TYPE.len()].copy_from_slice(BOCHS_GROWING_TYPE);
        buf[BOCHS_VERSION_OFFSET..BOCHS_VERSION_OFFSET + 4].copy_from_slice(&version.to_le_bytes());
        buf
    }

    #[test]
    fn detects_bochs_from_fixture_style_header() {
        // Matches instar-testdata's downloaded/qemu-iotests/empty.bochs
        // header layout (version 2 growing redolog).
        let buf = bochs_header(BOCHS_VERSION_2);
        assert_eq!(
            detect_format_from_header(&buf, buf.len(), false),
            ImageFormat::Bochs
        );
    }

    #[test]
    fn detects_bochs_version_1() {
        let buf = bochs_header(BOCHS_VERSION_1);
        assert_eq!(
            detect_format_from_header(&buf, buf.len(), false),
            ImageFormat::Bochs
        );
    }

    #[test]
    fn bochs_wrong_version_is_raw() {
        let buf = bochs_header(0x0003_0000);
        assert_eq!(
            detect_format_from_header(&buf, buf.len(), false),
            ImageFormat::Raw
        );
    }

    #[test]
    fn bochs_truncated_header_is_raw() {
        // 511 bytes: one short of BOCHS_HEADER_MIN_LEN.
        let full = bochs_header(BOCHS_VERSION_2);
        let buf = &full[..511];
        assert_eq!(
            detect_format_from_header(buf, buf.len(), false),
            ImageFormat::Raw
        );
    }

    // ------------------------------------------------------------------
    // cloop
    // ------------------------------------------------------------------

    #[test]
    fn detects_cloop_from_exact_magic() {
        // CLOOP_MAGIC is byte-identical to the first 83 bytes of
        // instar-testdata's downloaded/qemu-iotests/simple-pattern.cloop
        // fixture (verified by hexdump during implementation).
        assert_eq!(
            detect_format_from_header(CLOOP_MAGIC, CLOOP_MAGIC.len(), false),
            ImageFormat::Cloop
        );
    }

    #[test]
    fn cloop_truncated_magic_is_raw() {
        // One byte short of the full magic: instar requires the exact
        // magic (deliberate divergence from qemu's prefix-match probe;
        // documented as a quirk).
        let buf = &CLOOP_MAGIC[..CLOOP_MAGIC.len() - 1];
        assert_eq!(
            detect_format_from_header(buf, buf.len(), false),
            ImageFormat::Raw
        );
    }

    // ------------------------------------------------------------------
    // DMG koly trailer
    // ------------------------------------------------------------------

    #[test]
    fn detects_koly_within_window() {
        let len: usize = 2048;
        let mut buf = [0u8; 1024]; // last 1024 bytes of the file
        let koly_offset = 1200; // comfortably inside [1025, 1536]
        let idx = koly_offset - (len - buf.len());
        buf[idx..idx + 4].copy_from_slice(&DMG_KOLY_MAGIC);
        assert_eq!(detect_dmg_koly_offset(&buf, len), Some(koly_offset));
    }

    #[test]
    fn detects_koly_at_window_start_edge() {
        let len: usize = 2048;
        let mut buf = [0u8; 1024];
        let window_start = len - 1023; // 1025
        let idx = window_start - (len - buf.len());
        buf[idx..idx + 4].copy_from_slice(&DMG_KOLY_MAGIC);
        assert_eq!(detect_dmg_koly_offset(&buf, len), Some(window_start));
    }

    #[test]
    fn detects_koly_at_window_end_edge() {
        let len: usize = 2048;
        let mut buf = [0u8; 1024];
        let window_end = len - 512; // 1536
        let idx = window_end - (len - buf.len());
        buf[idx..idx + 4].copy_from_slice(&DMG_KOLY_MAGIC);
        assert_eq!(detect_dmg_koly_offset(&buf, len), Some(window_end));
    }

    #[test]
    fn koly_outside_window_below_start_is_none() {
        let len: usize = 2048;
        let mut buf = [0u8; 1024];
        let just_below_start = len - 1024; // window_start - 1
        let idx = just_below_start - (len - buf.len());
        buf[idx..idx + 4].copy_from_slice(&DMG_KOLY_MAGIC);
        assert_eq!(detect_dmg_koly_offset(&buf, len), None);
    }

    #[test]
    fn koly_outside_window_above_end_is_none() {
        let len: usize = 2048;
        let mut buf = [0u8; 1024];
        let just_above_end = len - 511; // window_end + 1
        let idx = just_above_end - (len - buf.len());
        buf[idx..idx + 4].copy_from_slice(&DMG_KOLY_MAGIC);
        assert_eq!(detect_dmg_koly_offset(&buf, len), None);
    }

    #[test]
    fn sub_512_byte_file_never_matches_koly() {
        let len: usize = 511;
        let mut buf = [0u8; 511];
        // Even with a koly magic present, files this short can never
        // hold a full trailer.
        buf[0..4].copy_from_slice(&DMG_KOLY_MAGIC);
        assert_eq!(detect_dmg_koly_offset(&buf, len), None);
    }

    #[test]
    fn dmg_sector_count_reads_valid_value() {
        let len: usize = 2048;
        let mut buf = [0u8; 1024];
        let koly_offset = 1200;
        let idx = koly_offset - (len - buf.len());
        buf[idx..idx + 4].copy_from_slice(&DMG_KOLY_MAGIC);
        let sector_count_idx = idx + DMG_KOLY_SECTOR_COUNT_OFFSET;
        buf[sector_count_idx..sector_count_idx + 8].copy_from_slice(&20480u64.to_be_bytes());
        assert_eq!(dmg_sector_count(&buf, len, koly_offset), Some(20480));
    }

    #[test]
    fn dmg_sector_count_rejects_top_bit_set() {
        let len: usize = 2048;
        let mut buf = [0u8; 1024];
        let koly_offset = 1200;
        let idx = koly_offset - (len - buf.len());
        buf[idx..idx + 4].copy_from_slice(&DMG_KOLY_MAGIC);
        let sector_count_idx = idx + DMG_KOLY_SECTOR_COUNT_OFFSET;
        // Top bit set: qemu rejects this as a corrupt/negative total.
        let negative: u64 = 0x8000_0000_0000_0001;
        buf[sector_count_idx..sector_count_idx + 8].copy_from_slice(&negative.to_be_bytes());
        assert_eq!(dmg_sector_count(&buf, len, koly_offset), None);
    }
}
