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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionTableType {
    /// No valid partition table found
    None,
    /// MBR (Master Boot Record) partition table
    Mbr,
    /// GPT (GUID Partition Table) with protective MBR
    Gpt,
}

/// Compute an allocation summary for a raw image.
///
/// Raw images carry no allocation metadata — every byte in the
/// virtual range is treated as allocated. This mirrors how
/// `qemu-img measure` treats raw input: it reports
/// `fully-allocated == virtual_size`.
///
/// `target_unit_size` is the unit size of the target format (qcow2
/// cluster, vhd/vhdx block, vmdk grain) so that the measure
/// calculators can compute `data_units_required` directly without
/// re-deriving it from `allocated_bytes`. Pass `0` to skip
/// `target_units_with_data` population (callers that don't yet pass
/// a target unit size). See bug #286.
pub fn scan_allocation(virtual_size: u64, target_unit_size: u64) -> shared::AllocationSummary {
    let target_units_with_data = if target_unit_size == 0 || virtual_size == 0 {
        0
    } else {
        virtual_size.saturating_add(target_unit_size - 1) / target_unit_size
    };
    shared::AllocationSummary {
        virtual_size,
        allocated_bytes: virtual_size,
        target_units_with_data,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a 512-byte sector buffer with MBR signature.
    fn mbr_sector() -> [u8; 512] {
        let mut buf = [0u8; 512];
        // MBR signature 0x55AA at offset 510 (little-endian)
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf
    }

    // ---- scan_allocation ----

    #[test]
    fn raw_scan_zero() {
        let s = scan_allocation(0, 0);
        assert_eq!(s.virtual_size, 0);
        assert_eq!(s.allocated_bytes, 0);
    }

    #[test]
    fn raw_scan_one_sector() {
        let s = scan_allocation(512, 0);
        assert_eq!(s.allocated_bytes, 512);
    }

    #[test]
    fn raw_scan_one_gib() {
        let s = scan_allocation(1024 * 1024 * 1024, 0);
        assert_eq!(s.virtual_size, s.allocated_bytes);
        assert_eq!(s.allocated_bytes, 1 << 30);
    }

    #[test]
    fn raw_scan_max_u64() {
        // raw treats every byte as allocated, so the calculation is
        // saturating-safe even at u64::MAX.
        let s = scan_allocation(u64::MAX, 0);
        assert_eq!(s.virtual_size, u64::MAX);
        assert_eq!(s.allocated_bytes, u64::MAX);
    }

    // ---- Buffer too short ----

    #[test]
    fn too_short_returns_none() {
        assert_eq!(
            detect_partition_table(&[0u8; 511]),
            PartitionTableType::None
        );
        assert_eq!(detect_partition_table(&[]), PartitionTableType::None);
    }

    // ---- No MBR signature ----

    #[test]
    fn no_signature_returns_none() {
        let buf = [0u8; 512];
        assert_eq!(detect_partition_table(&buf), PartitionTableType::None);
    }

    #[test]
    fn wrong_signature_returns_none() {
        let mut buf = [0u8; 512];
        buf[510] = 0xAA;
        buf[511] = 0x55; // Reversed — wrong endianness
        assert_eq!(detect_partition_table(&buf), PartitionTableType::None);
    }

    // ---- Valid MBR (boot sector with signature but no partitions) ----

    #[test]
    fn signature_only_is_mbr() {
        let buf = mbr_sector();
        // All partition entries are zeroed → "boot sector" path
        assert_eq!(detect_partition_table(&buf), PartitionTableType::Mbr);
    }

    // ---- Valid MBR with active partition ----

    #[test]
    fn mbr_with_active_partition() {
        let mut buf = mbr_sector();
        let entry = MBR_PARTITION_TABLE_OFFSET;
        buf[entry] = MBR_BOOT_ACTIVE; // boot indicator
        buf[entry + 4] = 0x83; // Linux partition type
        assert_eq!(detect_partition_table(&buf), PartitionTableType::Mbr);
    }

    #[test]
    fn mbr_with_inactive_partition() {
        let mut buf = mbr_sector();
        let entry = MBR_PARTITION_TABLE_OFFSET;
        buf[entry] = MBR_BOOT_INACTIVE;
        buf[entry + 4] = 0x07; // NTFS
        assert_eq!(detect_partition_table(&buf), PartitionTableType::Mbr);
    }

    // ---- Invalid boot indicator ----

    #[test]
    fn invalid_boot_indicator_returns_none() {
        let mut buf = mbr_sector();
        let entry = MBR_PARTITION_TABLE_OFFSET;
        buf[entry] = 0x42; // Not 0x00 or 0x80
        buf[entry + 4] = 0x83; // Non-empty partition type
        assert_eq!(detect_partition_table(&buf), PartitionTableType::None);
    }

    // ---- GPT protective MBR ----

    #[test]
    fn gpt_protective_mbr() {
        let mut buf = mbr_sector();
        let entry = MBR_PARTITION_TABLE_OFFSET;
        buf[entry] = MBR_BOOT_INACTIVE;
        buf[entry + 4] = GPT_PROTECTIVE_MBR_TYPE; // 0xEE
        assert_eq!(detect_partition_table(&buf), PartitionTableType::Gpt);
    }

    // ---- Multiple partitions ----

    #[test]
    fn multiple_valid_partitions() {
        let mut buf = mbr_sector();
        for i in 0..4 {
            let entry = MBR_PARTITION_TABLE_OFFSET + i * MBR_PARTITION_ENTRY_SIZE;
            buf[entry] = MBR_BOOT_INACTIVE;
            buf[entry + 4] = 0x83;
        }
        assert_eq!(detect_partition_table(&buf), PartitionTableType::Mbr);
    }

    #[test]
    fn second_partition_invalid_boot_indicator() {
        let mut buf = mbr_sector();
        // First partition valid
        let e0 = MBR_PARTITION_TABLE_OFFSET;
        buf[e0] = MBR_BOOT_INACTIVE;
        buf[e0 + 4] = 0x83;
        // Second partition has invalid boot indicator
        let e1 = MBR_PARTITION_TABLE_OFFSET + MBR_PARTITION_ENTRY_SIZE;
        buf[e1] = 0xFF;
        buf[e1 + 4] = 0x07;
        assert_eq!(detect_partition_table(&buf), PartitionTableType::None);
    }
}
