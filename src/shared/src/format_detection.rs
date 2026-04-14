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
}
