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

        Some(Vmdk4Header {
            version,
            capacity_sectors,
            virtual_size: capacity_sectors * 512,
            grain_size_sectors,
            cluster_size: (grain_size_sectors * 512) as u32,
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
    let desc_byte_offset = header.desc_offset_sectors * 512;
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
