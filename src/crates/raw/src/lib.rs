//! Raw disk image format validation.
//!
//! Provides MBR and GPT partition table detection for validating that a
//! file is a legitimate raw disk image (not an arbitrary file). This is
//! a key security feature: without a recognized format header, a file
//! must have a valid partition table to be accepted as a raw disk image.

#![no_std]

// MBR constants
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_SIGNATURE: u16 = 0xAA55; // Little-endian: bytes 0x55, 0xAA
const MBR_PARTITION_TABLE_OFFSET: usize = 0x1BE; // 446
const MBR_PARTITION_ENTRY_SIZE: usize = 16;
const MBR_BOOT_INACTIVE: u8 = 0x00;
const MBR_BOOT_ACTIVE: u8 = 0x80;

// GPT constants
const GPT_PROTECTIVE_MBR_TYPE: u8 = 0xEE;

/// Partition table type for RAW image validation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PartitionTableType {
    /// No valid partition table found
    None,
    /// MBR (Master Boot Record) partition table
    Mbr,
    /// GPT (GUID Partition Table) with protective MBR
    Gpt,
}

/// Detect partition table type from the first sector.
///
/// Detection logic:
/// 1. Check for MBR signature (0x55AA at offset 510)
/// 2. Check for GPT protective MBR (partition type 0xEE)
/// 3. Validate MBR boot indicators (must be 0x00 or 0x80)
///
/// `buffer` must contain at least 512 bytes (the first sector).
pub fn detect_partition_table(buffer: &[u8]) -> PartitionTableType {
    if buffer.len() < 512 {
        return PartitionTableType::None;
    }

    let signature = u16::from_le_bytes([
        buffer[MBR_SIGNATURE_OFFSET],
        buffer[MBR_SIGNATURE_OFFSET + 1],
    ]);

    if signature != MBR_SIGNATURE {
        return PartitionTableType::None;
    }

    let mut valid_mbr = false;
    let mut has_gpt_protective = false;

    for i in 0..4 {
        let entry_offset = MBR_PARTITION_TABLE_OFFSET + (i * MBR_PARTITION_ENTRY_SIZE);
        let boot_indicator = buffer[entry_offset];
        let partition_type = buffer[entry_offset + 4];

        if partition_type == 0x00 {
            continue;
        }

        if partition_type == GPT_PROTECTIVE_MBR_TYPE {
            has_gpt_protective = true;
        }

        if boot_indicator != MBR_BOOT_INACTIVE && boot_indicator != MBR_BOOT_ACTIVE {
            return PartitionTableType::None;
        }

        valid_mbr = true;
    }

    if has_gpt_protective {
        return PartitionTableType::Gpt;
    }

    if valid_mbr {
        return PartitionTableType::Mbr;
    }

    // Valid MBR signature but no partition entries - boot sector
    PartitionTableType::Mbr
}
