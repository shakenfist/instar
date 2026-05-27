//! VHDX (Hyper-V Virtual Hard Disk v2) format parsing.
//!
//! Provides VHDX header, region table, metadata, and BAT parsing,
//! block lookup for dynamic VHDX images, and output builders for
//! creating new VHDX images.
//!
//! VHDX uses CRC-32C checksums, GUID-identified metadata, 64-bit BAT
//! entries with interleaved sector bitmap entries, and 1MB-aligned
//! structures. All on-disk fields are little-endian.

#![no_std]
#![allow(clippy::too_many_arguments)]

use shared::{
    le_u16, le_u32, le_u64, write_le_u16, write_le_u32, write_le_u64, AllocationSummary, CallTable,
    MAX_SECTOR_SIZE,
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
// VHDX metadata parsing
// ============================================================================

/// Parsed VHDX metadata fields.
pub struct VhdxMetadata {
    pub block_size: u32,
    pub virtual_disk_size: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub has_parent: bool,
}

/// Parse VHDX metadata from the metadata region.
///
/// Reads the metadata table and locates items by GUID. Requires
/// sector-based I/O via `call_table`.
///
/// # Safety
///
/// `call_table` must be valid.
pub unsafe fn parse_metadata(
    call_table: &CallTable,
    device_idx: u32,
    metadata_offset: u64,
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

    // If parent locator is found but we don't use it, that's fine.
    // We just note has_parent from file parameters flags.
    let _ = parent_loc_offset;
    let _ = found_parent_loc;

    Some(VhdxMetadata {
        block_size,
        virtual_disk_size,
        logical_sector_size,
        physical_sector_size,
        has_parent,
    })
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
            return Some(AllocationSummary {
                virtual_size,
                allocated_bytes: 0,
                // TODO(#286): populate from target_unit_size when this
                // scanner is converted to target-aware accounting.
                target_units_with_data: 0,
            });
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
        // overshoot. Clamp at `virtual_size` so callers see the
        // invariant allocated_bytes <= virtual_size — `measure_<fmt>`
        // would otherwise reject the summary as InvalidSize. Mirrors
        // the qcow2 out-of-bounds skip established in
        // PLAN-fuzzing-bugs phase 2.
        let allocated_bytes = allocated_blocks
            .saturating_mul(self.block_size as u64)
            .min(virtual_size);

        Some(AllocationSummary {
            virtual_size,
            allocated_bytes,
            // TODO(#286): populate from target_unit_size when this
            // scanner is converted to target-aware accounting.
            target_units_with_data: 0,
        })
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
}
