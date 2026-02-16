//! VMDK (VMware Virtual Machine Disk) format parsing.
//!
//! Provides VMDK4 binary header parsing and text descriptor parsing
//! for extracting metadata (version, capacity, grain size, CID,
//! parentCID, createType).

#![no_std]

use shared::{CallTable, VmdkInfo, MAX_SECTOR_SIZE};

// VMDK4 binary header offsets (all little-endian)
pub const VERSION_OFFSET: usize = 4;
pub const CAPACITY_OFFSET: usize = 12;
pub const GRAIN_SIZE_OFFSET: usize = 20;
pub const DESC_OFFSET_OFFSET: usize = 28; // Descriptor offset in 512-byte sectors
pub const DESC_SIZE_OFFSET: usize = 36; // Descriptor size in 512-byte sectors

/// Read a little-endian u32 from a byte slice.
#[inline]
fn le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read a little-endian u64 from a byte slice.
#[inline]
fn le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Parsed VMDK4 binary header fields.
pub struct Vmdk4Header {
    pub version: u32,
    pub capacity_sectors: u64,
    pub virtual_size: u64,
    pub grain_size_sectors: u64,
    pub cluster_size: u32,
    pub desc_offset_sectors: u64,
    pub desc_size_sectors: u64,
}

impl Vmdk4Header {
    /// Parse a VMDK4 binary header from raw bytes.
    ///
    /// `header` must contain at least 44 bytes (through desc_size field).
    /// Returns `None` if the buffer is too small.
    pub fn parse(header: &[u8]) -> Option<Self> {
        if header.len() < 44 {
            return None;
        }

        let version = le_u32(header, VERSION_OFFSET);
        let capacity_sectors = le_u64(header, CAPACITY_OFFSET);
        let grain_size_sectors = le_u64(header, GRAIN_SIZE_OFFSET);
        let desc_offset_sectors = le_u64(header, DESC_OFFSET_OFFSET);
        let desc_size_sectors = le_u64(header, DESC_SIZE_OFFSET);

        let virtual_size = capacity_sectors.checked_mul(512)?;
        let cluster_size = u32::try_from(grain_size_sectors.checked_mul(512)?).ok()?;

        Some(Vmdk4Header {
            version,
            capacity_sectors,
            virtual_size,
            grain_size_sectors,
            cluster_size,
            desc_offset_sectors,
            desc_size_sectors,
        })
    }
}

/// Read and parse the VMDK descriptor from the image.
///
/// Uses the descriptor offset/size from the binary header to read the
/// descriptor text and parse CID, parentCID, and createType fields.
///
/// # Safety
///
/// `call_table` must point to a valid initialized call table.
pub unsafe fn read_and_parse_descriptor(
    call_table: &CallTable,
    device_idx: u32,
    header: &Vmdk4Header,
    vmdk_info: &mut VmdkInfo,
) {
    if header.desc_offset_sectors == 0 || header.desc_size_sectors == 0 {
        return;
    }

    let input_sector_size = (call_table.get_input_sector_size)(device_idx);
    let desc_byte_offset = match header.desc_offset_sectors.checked_mul(512) {
        Some(v) => v,
        None => return,
    };
    let desc_sector = desc_byte_offset / input_sector_size as u64;
    let offset_within_sector = (desc_byte_offset % input_sector_size as u64) as usize;

    let mut desc_buffer = [0u8; MAX_SECTOR_SIZE];

    if (call_table.read_input_sector)(
        device_idx,
        desc_sector,
        desc_buffer.as_mut_ptr(),
        input_sector_size,
    ) {
        let desc_data = &desc_buffer[offset_within_sector..input_sector_size];
        parse_descriptor(desc_data, desc_data.len(), vmdk_info);
    }
}

/// Parse VMDK descriptor text to extract CID, parentCID, and createType.
pub fn parse_descriptor(buffer: &[u8], len: usize, vmdk_info: &mut VmdkInfo) {
    let end = buffer[..len].iter().position(|&b| b == 0).unwrap_or(len);
    let text = &buffer[..end];

    let mut pos = 0;
    while pos < text.len() {
        let line_end = text[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(text.len());

        let line = &text[pos..line_end];

        if line.starts_with(b"CID=") {
            if let Some(cid) = parse_hex_value(&line[4..]) {
                vmdk_info.cid = cid;
            }
        } else if line.starts_with(b"parentCID=") {
            if let Some(parent_cid) = parse_hex_value(&line[10..]) {
                vmdk_info.parent_cid = parent_cid;
            }
        } else if line.starts_with(b"createType=") {
            let value_start = 12; // After 'createType="'
            if line.len() > value_start && line[11] == b'"' {
                if let Some(quote_end) = line[value_start..].iter().position(|&b| b == b'"') {
                    vmdk_info.set_create_type(&line[value_start..value_start + quote_end]);
                }
            }
        }

        pos = line_end + 1;
    }
}

/// Parse a hexadecimal value from a byte slice (no 0x prefix).
pub fn parse_hex_value(bytes: &[u8]) -> Option<u32> {
    let mut value: u32 = 0;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            b' ' | b'\r' | b'\n' | 0 => break,
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit as u32)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::VmdkInfo;

    // ========================================================================
    // parse_hex_value tests
    // ========================================================================

    #[test]
    fn hex_simple_values() {
        assert_eq!(parse_hex_value(b"0"), Some(0));
        assert_eq!(parse_hex_value(b"1"), Some(1));
        assert_eq!(parse_hex_value(b"a"), Some(10));
        assert_eq!(parse_hex_value(b"ff"), Some(255));
        assert_eq!(parse_hex_value(b"FF"), Some(255));
        assert_eq!(parse_hex_value(b"fffffffe"), Some(0xFFFFFFFE));
    }

    #[test]
    fn hex_empty_input() {
        assert_eq!(parse_hex_value(b""), Some(0));
    }

    #[test]
    fn hex_invalid_chars() {
        assert_eq!(parse_hex_value(b"xyz"), None);
        assert_eq!(parse_hex_value(b"0g"), None);
    }

    #[test]
    fn hex_overflow() {
        // ffffffff is u32::MAX, adding one more digit overflows
        assert_eq!(parse_hex_value(b"ffffffff"), Some(u32::MAX));
        assert_eq!(parse_hex_value(b"100000000"), None);
    }

    #[test]
    fn hex_stops_at_whitespace_and_null() {
        assert_eq!(parse_hex_value(b"ff "), Some(255));
        assert_eq!(parse_hex_value(b"ff\r"), Some(255));
        assert_eq!(parse_hex_value(b"ff\n"), Some(255));
        assert_eq!(parse_hex_value(b"ff\0"), Some(255));
    }

    // ========================================================================
    // Vmdk4Header::parse tests
    // ========================================================================

    /// Build a minimal 44-byte VMDK4 header buffer.
    fn make_vmdk4_header(
        version: u32,
        capacity: u64,
        grain_size: u64,
        desc_offset: u64,
        desc_size: u64,
    ) -> [u8; 44] {
        let mut buf = [0u8; 44];
        buf[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&version.to_le_bytes());
        buf[CAPACITY_OFFSET..CAPACITY_OFFSET + 8].copy_from_slice(&capacity.to_le_bytes());
        buf[GRAIN_SIZE_OFFSET..GRAIN_SIZE_OFFSET + 8].copy_from_slice(&grain_size.to_le_bytes());
        buf[DESC_OFFSET_OFFSET..DESC_OFFSET_OFFSET + 8].copy_from_slice(&desc_offset.to_le_bytes());
        buf[DESC_SIZE_OFFSET..DESC_SIZE_OFFSET + 8].copy_from_slice(&desc_size.to_le_bytes());
        buf
    }

    #[test]
    fn vmdk4_parse_valid() {
        let buf = make_vmdk4_header(1, 2097152, 128, 1, 20);
        let hdr = Vmdk4Header::parse(&buf).unwrap();
        assert_eq!(hdr.version, 1);
        assert_eq!(hdr.capacity_sectors, 2097152);
        assert_eq!(hdr.virtual_size, 2097152 * 512);
        assert_eq!(hdr.grain_size_sectors, 128);
        assert_eq!(hdr.cluster_size, 128 * 512);
        assert_eq!(hdr.desc_offset_sectors, 1);
        assert_eq!(hdr.desc_size_sectors, 20);
    }

    #[test]
    fn vmdk4_parse_short_buffer() {
        assert!(Vmdk4Header::parse(&[0u8; 43]).is_none());
        assert!(Vmdk4Header::parse(&[]).is_none());
    }

    #[test]
    fn vmdk4_parse_capacity_overflow() {
        // capacity_sectors so large that capacity * 512 overflows u64
        let buf = make_vmdk4_header(1, u64::MAX, 128, 0, 0);
        assert!(Vmdk4Header::parse(&buf).is_none());
    }

    #[test]
    fn vmdk4_parse_grain_size_overflow() {
        // grain_size_sectors so large that grain_size * 512 overflows u32
        let huge_grain = (u32::MAX as u64) + 1; // won't fit in u32 after *512
        let buf = make_vmdk4_header(1, 2048, huge_grain, 0, 0);
        assert!(Vmdk4Header::parse(&buf).is_none());
    }

    // ========================================================================
    // parse_descriptor tests
    // ========================================================================

    #[test]
    fn descriptor_parses_cid_and_parent_cid() {
        let desc = b"CID=fffffffe\nparentCID=12345678\n";
        let mut info = VmdkInfo::new();
        parse_descriptor(desc, desc.len(), &mut info);
        assert_eq!(info.cid, 0xFFFFFFFE);
        assert_eq!(info.parent_cid, 0x12345678);
    }

    #[test]
    fn descriptor_parses_create_type() {
        let desc = b"createType=\"monolithicSparse\"\n";
        let mut info = VmdkInfo::new();
        parse_descriptor(desc, desc.len(), &mut info);
        assert_eq!(info.create_type_str(), "monolithicSparse");
    }

    #[test]
    fn descriptor_handles_null_terminated_buffer() {
        let mut buf = [0u8; 64];
        let text = b"CID=abcd\n";
        buf[..text.len()].copy_from_slice(text);
        let mut info = VmdkInfo::new();
        parse_descriptor(&buf, buf.len(), &mut info);
        assert_eq!(info.cid, 0xABCD);
    }

    #[test]
    fn descriptor_ignores_unknown_lines() {
        let desc = b"version=1\nCID=1\nsomething=else\n";
        let mut info = VmdkInfo::new();
        parse_descriptor(desc, desc.len(), &mut info);
        assert_eq!(info.cid, 1);
        assert_eq!(info.parent_cid, 0xFFFFFFFF); // default unchanged
    }
}
