//! Info operation: detect image format and report metadata.
//!
//! This operation reads the first sector(s) from the input virtio-block device
//! to detect the image format based on magic numbers and header structures.
//! Results are sent via protobuf InfoResultMessage over the serial command channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    CallTable, ImageFormat, InfoConfig, InfoResult, Qcow2Info, VmdkInfo, CALL_TABLE_ADDR,
    MAX_SECTOR_SIZE,
};

// Magic numbers for format detection (big-endian where noted)
const QCOW2_MAGIC: u32 = 0x514649fb; // "QFI\xfb" (big-endian at offset 0)
const QCOW1_MAGIC: u32 = 0x514649; // "QFI" (big-endian at offset 0, 3 bytes)
const VMDK4_MAGIC: u32 = 0x564d444b; // "VMDK" (little-endian at offset 0)
const VMDK3_MAGIC: u32 = 0x434f5744; // "COWD" (little-endian at offset 0)
const VHD_COOKIE: u64 = 0x636f6e6563746978; // "conectix" (big-endian at footer offset 0)

// VHD footer offsets (big-endian)
const VHD_FOOTER_CREATOR_APP_OFFSET: usize = 28; // Creator application (4 bytes ASCII)
const VHD_FOOTER_DISK_SIZE_OFFSET: usize = 40; // Original/virtual size in bytes (8 bytes)
const VHD_FOOTER_DISK_GEOMETRY_OFFSET: usize = 56; // CHS geometry (4 bytes: cyls[2], heads[1], secs[1])

// VHD maximum CHS geometry (indicates current_size should be used instead)
const VHD_MAX_CHS_CYLS: u16 = 65535;
const VHD_MAX_CHS_HEADS: u8 = 16;
const VHD_MAX_CHS_SECS: u8 = 255;

// QCOW2 header offsets (big-endian)
const QCOW2_VERSION_OFFSET: usize = 4;
const QCOW2_BACKING_FILE_OFFSET_OFFSET: usize = 8;
const QCOW2_BACKING_FILE_SIZE_OFFSET: usize = 16;
const QCOW2_CLUSTER_BITS_OFFSET: usize = 20;
const QCOW2_SIZE_OFFSET: usize = 24;
const QCOW2_CRYPT_METHOD_OFFSET: usize = 32;
const QCOW2_INCOMPATIBLE_FEATURES_OFFSET: usize = 72; // v3 only

// Additional QCOW2 header offsets for format-specific info
const QCOW2_L1_SIZE_OFFSET: usize = 36; // Number of L1 table entries
const QCOW2_L1_TABLE_OFFSET_OFFSET: usize = 40; // L1 table file offset
const QCOW2_COMPATIBLE_FEATURES_OFFSET: usize = 80; // v3 only
const QCOW2_REFCOUNT_ORDER_OFFSET: usize = 96; // refcount_bits = 1 << refcount_order
const QCOW2_COMPRESSION_TYPE_OFFSET: usize = 104; // v3 only (0=zlib, 1=zstd)

// QCOW2 incompatible feature bits
const QCOW2_INCOMPAT_DIRTY: u64 = 1 << 0;
const QCOW2_INCOMPAT_CORRUPT: u64 = 1 << 1;
const QCOW2_INCOMPAT_EXTERNAL_DATA: u64 = 1 << 2;
const QCOW2_INCOMPAT_COMPRESSION: u64 = 1 << 3;
const QCOW2_INCOMPAT_EXTENDED_L2: u64 = 1 << 4;

// QCOW2 compatible feature bits
const QCOW2_COMPAT_LAZY_REFCOUNTS: u64 = 1 << 0;

// Maximum backing file path length (QCOW2 spec allows up to 1023 bytes)
const MAX_BACKING_FILE_LEN: usize = 1024;

// MBR (Master Boot Record) partition table detection
// MBR signature is 0x55AA at offset 510-511 (big-endian, bytes are 0x55, 0xAA)
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_SIGNATURE: u16 = 0xAA55; // Little-endian: bytes 0x55, 0xAA

// MBR partition table entry offsets (4 entries at 0x1BE, 0x1CE, 0x1DE, 0x1EE)
const MBR_PARTITION_TABLE_OFFSET: usize = 0x1BE;
const MBR_PARTITION_ENTRY_SIZE: usize = 16;

// Valid MBR boot indicator values (first byte of partition entry)
const MBR_BOOT_INACTIVE: u8 = 0x00;
const MBR_BOOT_ACTIVE: u8 = 0x80;

// GPT (GUID Partition Table) detection
// GPT protective MBR has partition type 0xEE
const GPT_PROTECTIVE_MBR_TYPE: u8 = 0xEE;
// GPT header signature "EFI PART" at LBA 1 (sector 1)
const GPT_SIGNATURE: u64 = 0x5452415020494645; // "EFI PART" in little-endian

// QCOW2 header extension constants
const QCOW2_HEADER_EXTENSION_OFFSET: usize = 104; // First extension after fixed header (v3)
const QCOW2_EXT_BACKING_FORMAT: u32 = 0xE2792ACA; // Backing file format extension type
const QCOW2_EXT_END: u32 = 0x00000000; // End of extensions marker

// VMDK4 header offsets (little-endian)
const VMDK4_VERSION_OFFSET: usize = 4;
const VMDK4_CAPACITY_OFFSET: usize = 12;
const VMDK4_GRAIN_SIZE_OFFSET: usize = 20;
const VMDK4_DESC_OFFSET_OFFSET: usize = 28; // Descriptor offset in sectors
const VMDK4_DESC_SIZE_OFFSET: usize = 36; // Descriptor size in sectors

// VHDX format constants (all offsets and values are little-endian)
// VHDX region table is at fixed offset 192KB (0x30000)
const VHDX_REGION_TABLE_OFFSET: u64 = 0x30000;
// VHDX region table signature "regi"
const VHDX_REGION_TABLE_SIG: u32 = 0x69676572;
// VHDX metadata region GUID: 8b7ca206-4790-4b9a-b8fe-575f050f886e
// First 4 bytes in little-endian: 0x8b7ca206
const VHDX_METADATA_GUID_FIRST4: u32 = 0x8b7ca206;
// VHDX metadata table signature "metadata"
const VHDX_METADATA_TABLE_SIG: u64 = 0x617461646174656d;
// Standard metadata item offsets (relative to metadata region)
// These are defined by the VHDX spec and consistent across implementations
const VHDX_METADATA_ITEM_OFFSET: u64 = 0x10000; // File Parameters start here
                                                // Within metadata items:
                                                // - Offset 0: Block Size (4 bytes LE)
                                                // - Offset 8: Virtual Disk Size (8 bytes LE)

/// Entry point called by core after devices are initialized.
///
/// Returns the number of bytes read.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    // Verify call table is valid
    if call_table.magic != CallTable::MAGIC {
        (call_table.debug_print)(b"info: bad magic\n\0".as_ptr());
        return 0;
    }
    if call_table.version != CallTable::VERSION {
        (call_table.debug_print)(b"info: bad version\n\0".as_ptr());
        return 0;
    }

    (call_table.debug_print)(b"info: start\n\0".as_ptr());

    // Get operation config (optional)
    let config_result = (call_table.get_operation_config)();
    let config = &*(config_result.ptr as *const InfoConfig);
    let detailed = if config.is_valid() {
        config.should_report_detailed()
    } else {
        true // Default to detailed
    };

    // Get device parameters
    let input_capacity = (call_table.get_input_capacity)();
    let input_sector_size = (call_table.get_input_sector_size)();

    // Calculate actual file size
    let actual_size = input_capacity * input_sector_size as u64;

    (call_table.debug_print)(b"info: reading header\n\0".as_ptr());

    // Buffer for reading data
    let mut buffer = [0u8; MAX_SECTOR_SIZE];

    // Read first sector
    if !(call_table.read_input_sector)(0, buffer.as_mut_ptr(), input_sector_size) {
        (call_table.send_error)(b"info\0".as_ptr(), b"input\0".as_ptr(), 0, 1);
        return 0;
    }

    let bytes_read = input_sector_size as u64;

    // Initialize result structure
    let mut result = InfoResult::new();
    result.actual_size = actual_size;

    // Detect format based on magic numbers (first sector)
    let mut format = detect_format_header(&buffer, input_sector_size);

    // Buffer for VHD footer (may be reused)
    let mut footer_buffer = [0u8; MAX_SECTOR_SIZE];

    // If no format detected from header, try VHD detection (footer at end of file)
    if format == ImageFormat::Raw && input_capacity > 0 {
        (call_table.debug_print)(b"info: checking VHD footer\n\0".as_ptr());
        let last_sector = input_capacity - 1;
        if (call_table.read_input_sector)(
            last_sector,
            footer_buffer.as_mut_ptr(),
            input_sector_size,
        ) {
            format = detect_vhd_footer(&footer_buffer);
        }
    }

    // For RAW format: validate partition table unless unsafe quirks is enabled.
    // This prevents arbitrary files (like /etc/passwd) from being accepted as
    // valid disk images, which is the root cause of backing file disclosure attacks.
    if format == ImageFormat::Raw {
        let unsafe_quirks = config.is_valid() && config.unsafe_quirks_enabled();

        if !unsafe_quirks {
            // Check for valid partition table
            let partition_type = detect_partition_table(&buffer);

            match partition_type {
                PartitionTableType::Mbr => {
                    (call_table.debug_print)(b"info: found MBR partition table\n\0".as_ptr());
                    result.flags |= InfoResult::FLAG_HAS_MBR;
                }
                PartitionTableType::Gpt => {
                    (call_table.debug_print)(b"info: found GPT partition table\n\0".as_ptr());
                    result.flags |= InfoResult::FLAG_HAS_GPT;
                }
                PartitionTableType::None => {
                    // No valid partition table found - reject as unknown format
                    // This is the secure default: only accept files that are
                    // recognizably disk images
                    (call_table.debug_print)(
                        b"info: no partition table, rejecting as unknown\n\0".as_ptr(),
                    );
                    format = ImageFormat::Unknown;
                }
            }
        } else {
            // Unsafe quirks mode: accept any file as RAW (qemu-img compatible
            // but insecure). Still detect partition table for informational
            // purposes.
            let partition_type = detect_partition_table(&buffer);
            match partition_type {
                PartitionTableType::Mbr => {
                    result.flags |= InfoResult::FLAG_HAS_MBR;
                }
                PartitionTableType::Gpt => {
                    result.flags |= InfoResult::FLAG_HAS_GPT;
                }
                PartitionTableType::None => {
                    // Accept anyway in unsafe mode
                    (call_table.debug_print)(
                        b"info: no partition table (unsafe quirks)\n\0".as_ptr(),
                    );
                }
            }
        }
    }

    result.format = format as u32;

    (call_table.debug_print)(b"info: detected format\n\0".as_ptr());

    // Format-specific information structures
    let mut qcow2_info = Qcow2Info::new();
    let mut vmdk_info = VmdkInfo::new();

    // Buffer for backing file path (null-terminated)
    let mut backing_file_buf = [0u8; MAX_BACKING_FILE_LEN + 1];

    // Parse format-specific metadata if detailed reporting enabled
    if detailed {
        match format {
            ImageFormat::Qcow2 => {
                parse_qcow2_header(
                    &buffer,
                    &mut result,
                    &mut qcow2_info,
                    call_table,
                    &mut backing_file_buf,
                    input_sector_size,
                );
            }
            ImageFormat::Vmdk4 => {
                parse_vmdk4_header(&buffer, &mut result, &mut vmdk_info, call_table);
                // Set compressed flag if createType indicates compression (e.g., streamOptimized)
                if vmdk_info.create_type_str() == "streamOptimized" {
                    result.flags |= InfoResult::FLAG_COMPRESSED;
                }
            }
            ImageFormat::Vhd => {
                // VHD footer may be in first sector (dynamic) or last sector (fixed)
                // Use first sector buffer if it has the footer, otherwise use footer_buffer
                let vhd_cookie = u64::from_be_bytes([
                    buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6],
                    buffer[7],
                ]);
                if vhd_cookie == VHD_COOKIE {
                    parse_vhd_footer(&buffer, &mut result);
                } else {
                    parse_vhd_footer(&footer_buffer, &mut result);
                }
            }
            ImageFormat::Vhdx => {
                // VHDX requires reading metadata from specific regions
                parse_vhdx_metadata(&mut result, actual_size, call_table);
            }
            _ => {
                // For raw and unknown formats, virtual size = actual size
                result.virtual_size = actual_size;
            }
        }
    }

    // Get format string for protobuf message
    let format_str = format_to_str(format);

    // Send result via protobuf over serial
    // Use format-specific functions to include format-specific info
    if format == ImageFormat::Qcow2 {
        (call_table.send_info_result_qcow2)(
            format_str,
            result.version,
            result.virtual_size,
            result.actual_size,
            result.cluster_size,
            result.flags,
            backing_file_buf.as_ptr(),
            b"\0".as_ptr(), // external_data_file (empty for now)
            &qcow2_info,
        );
    } else if format == ImageFormat::Vmdk4 {
        (call_table.send_info_result_vmdk)(
            format_str,
            result.version,
            result.virtual_size,
            result.actual_size,
            result.cluster_size,
            result.flags,
            b"\0".as_ptr(), // backing_file (empty for now)
            b"\0".as_ptr(), // external_data_file (empty for now)
            &vmdk_info,
        );
    } else {
        (call_table.send_info_result)(
            format_str,
            result.version,
            result.virtual_size,
            result.actual_size,
            result.cluster_size,
            result.flags,
            b"\0".as_ptr(), // backing_file (empty for now)
            b"\0".as_ptr(), // external_data_file (empty for now)
        );
    }

    (call_table.send_complete)(b"info\0".as_ptr(), bytes_read, true);
    (call_table.debug_print)(b"info: done\n\0".as_ptr());

    bytes_read
}

/// Convert ImageFormat to a null-terminated C string
fn format_to_str(format: ImageFormat) -> *const u8 {
    match format {
        ImageFormat::Unknown => b"unknown\0".as_ptr(),
        ImageFormat::Raw => b"raw\0".as_ptr(),
        ImageFormat::Qcow2 => b"qcow2\0".as_ptr(),
        ImageFormat::Qcow1 => b"qcow1\0".as_ptr(),
        ImageFormat::Vmdk4 => b"vmdk\0".as_ptr(),
        ImageFormat::Vmdk3 => b"vmdk3\0".as_ptr(),
        ImageFormat::Vhd => b"vpc\0".as_ptr(), // qemu-img calls VHD format "vpc"
        ImageFormat::Vhdx => b"vhdx\0".as_ptr(),
    }
}

/// Detect image format based on magic numbers in file header (first sector)
fn detect_format_header(buffer: &[u8], len: usize) -> ImageFormat {
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

    // Check VHDX magic (little-endian, "vhdxfile" signature)
    let vhdx_sig = u64::from_le_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]);
    // "vhdxfile" in little-endian
    if vhdx_sig == 0x656c696678646876 {
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

    // Fixed VHD has its signature only at the end, handled separately
    // If no known format detected from header, assume raw (may be overridden)
    ImageFormat::Raw
}

/// Detect VHD format from file footer (last 512 bytes)
fn detect_vhd_footer(buffer: &[u8]) -> ImageFormat {
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

/// Partition table type for RAW image validation
#[derive(Clone, Copy, PartialEq, Eq)]
enum PartitionTableType {
    /// No valid partition table found
    None,
    /// MBR (Master Boot Record) partition table
    Mbr,
    /// GPT (GUID Partition Table)
    Gpt,
}

/// Detect partition table type from the first sector (MBR/GPT detection)
///
/// This is used for RAW format validation. Files without a recognized format
/// header must have a valid partition table to be accepted as RAW disk images
/// in secure mode (without --unsafe-quirks).
///
/// Detection logic:
/// 1. Check for MBR signature (0x55AA at offset 510)
/// 2. Check for GPT protective MBR (partition type 0xEE)
/// 3. Validate MBR boot indicators (must be 0x00 or 0x80)
fn detect_partition_table(buffer: &[u8]) -> PartitionTableType {
    // Need at least 512 bytes for MBR detection
    if buffer.len() < 512 {
        return PartitionTableType::None;
    }

    // Check MBR signature at offset 510-511
    let signature = u16::from_le_bytes([
        buffer[MBR_SIGNATURE_OFFSET],
        buffer[MBR_SIGNATURE_OFFSET + 1],
    ]);

    if signature != MBR_SIGNATURE {
        return PartitionTableType::None;
    }

    // Valid MBR signature found. Now check partition entries.
    // MBR has 4 partition entries starting at offset 0x1BE (446)
    let mut valid_mbr = false;
    let mut has_gpt_protective = false;

    for i in 0..4 {
        let entry_offset = MBR_PARTITION_TABLE_OFFSET + (i * MBR_PARTITION_ENTRY_SIZE);

        // Boot indicator (first byte of partition entry)
        let boot_indicator = buffer[entry_offset];

        // Partition type (5th byte of partition entry)
        let partition_type = buffer[entry_offset + 4];

        // Skip empty partitions (type 0x00)
        if partition_type == 0x00 {
            continue;
        }

        // Check for GPT protective MBR
        if partition_type == GPT_PROTECTIVE_MBR_TYPE {
            has_gpt_protective = true;
        }

        // Boot indicator must be 0x00 (inactive) or 0x80 (active)
        if boot_indicator != MBR_BOOT_INACTIVE && boot_indicator != MBR_BOOT_ACTIVE {
            // Invalid boot indicator - this isn't a valid MBR
            return PartitionTableType::None;
        }

        // Found at least one valid partition entry
        valid_mbr = true;
    }

    // If we found GPT protective MBR, report as GPT
    // (full GPT header validation would require reading sector 1)
    if has_gpt_protective {
        return PartitionTableType::Gpt;
    }

    // If we found valid MBR entries, report as MBR
    if valid_mbr {
        return PartitionTableType::Mbr;
    }

    // Valid MBR signature but no partition entries - could be a boot sector
    // or a filesystem without partitioning. Accept it as valid.
    PartitionTableType::Mbr
}

/// Parse VHD footer and populate result
///
/// VHD virtual size calculation varies by creator application:
/// - "vpc " (Virtual PC) and "qemu": Use CHS geometry calculation
/// - "qem2", "win " (Hyper-V), "d2v " (Disk2vhd), etc.: Use disk_size field
///
/// Exception: If CHS geometry is at maximum (65535×16×255), use disk_size
/// regardless of creator, to avoid truncation for large disks.
fn parse_vhd_footer(buffer: &[u8], result: &mut InfoResult) {
    // VHD footer structure (all fields big-endian):
    // Offset 0: Cookie "conectix" (8 bytes) - already verified
    // Offset 28: Creator application (4 bytes ASCII)
    // Offset 40: Disk size (8 bytes) - virtual disk capacity
    // Offset 48: Data size (8 bytes) - physical data extent
    // Offset 56: Disk geometry (4 bytes) - CHS values
    // Offset 60: Disk Type (4 bytes) - 2=fixed, 3=dynamic, 4=differencing

    // Read creator application (4 bytes ASCII at offset 28)
    let creator_app = &buffer[VHD_FOOTER_CREATOR_APP_OFFSET..VHD_FOOTER_CREATOR_APP_OFFSET + 4];

    // Read disk size (virtual size) at offset 40
    let disk_size = u64::from_be_bytes([
        buffer[VHD_FOOTER_DISK_SIZE_OFFSET],
        buffer[VHD_FOOTER_DISK_SIZE_OFFSET + 1],
        buffer[VHD_FOOTER_DISK_SIZE_OFFSET + 2],
        buffer[VHD_FOOTER_DISK_SIZE_OFFSET + 3],
        buffer[VHD_FOOTER_DISK_SIZE_OFFSET + 4],
        buffer[VHD_FOOTER_DISK_SIZE_OFFSET + 5],
        buffer[VHD_FOOTER_DISK_SIZE_OFFSET + 6],
        buffer[VHD_FOOTER_DISK_SIZE_OFFSET + 7],
    ]);

    // Read CHS geometry at offset 56
    // Format: cylinders (2 bytes BE) + heads (1 byte) + sectors per track (1 byte)
    let cyls = u16::from_be_bytes([
        buffer[VHD_FOOTER_DISK_GEOMETRY_OFFSET],
        buffer[VHD_FOOTER_DISK_GEOMETRY_OFFSET + 1],
    ]);
    let heads = buffer[VHD_FOOTER_DISK_GEOMETRY_OFFSET + 2];
    let secs = buffer[VHD_FOOTER_DISK_GEOMETRY_OFFSET + 3];

    // Check if CHS is at maximum (indicates disk_size should be used)
    let chs_at_max =
        cyls == VHD_MAX_CHS_CYLS && heads == VHD_MAX_CHS_HEADS && secs == VHD_MAX_CHS_SECS;

    // Determine if this creator uses CHS geometry for size calculation
    // "vpc " (Virtual PC) and "qemu" use CHS; others use disk_size field
    let use_chs = (creator_app == b"vpc " || creator_app == b"qemu") && !chs_at_max;

    if use_chs {
        // Calculate virtual size from CHS geometry (in sectors × 512 bytes)
        let total_sectors = cyls as u64 * heads as u64 * secs as u64;
        result.virtual_size = total_sectors * 512;
    } else {
        // Use disk_size field directly
        result.virtual_size = disk_size;
    }

    // Disk geometry at offset 56 - qemu uses this as cluster_size
    // VHD format: cylinders(2) + heads(1) + sectors(1)
    // For VPC/VHD, cluster_size is typically 2 MiB (0x200000)
    result.cluster_size = 2 * 1024 * 1024; // 2 MiB default for VHD
}

/// Parse VHDX metadata to extract virtual size and block size (cluster_size)
///
/// VHDX format stores metadata in a separate region. The layout is:
/// - Region Table at 0x30000 (192KB) - contains region entries with GUIDs and offsets
/// - Metadata Region (offset from region table) - contains metadata table and items
/// - Metadata items include File Parameters (block size) and Virtual Disk Size
unsafe fn parse_vhdx_metadata(result: &mut InfoResult, actual_size: u64, call_table: &CallTable) {
    let input_sector_size = (call_table.get_input_sector_size)();
    let mut buffer = [0u8; MAX_SECTOR_SIZE];

    // Step 1: Read region table at offset 0x30000 to find metadata region offset
    let region_table_sector = VHDX_REGION_TABLE_OFFSET / input_sector_size as u64;
    let region_table_offset_in_sector =
        (VHDX_REGION_TABLE_OFFSET % input_sector_size as u64) as usize;

    if !(call_table.read_input_sector)(region_table_sector, buffer.as_mut_ptr(), input_sector_size)
    {
        // Failed to read region table, fall back to actual size
        result.virtual_size = actual_size;
        return;
    }

    // Verify region table signature "regi" (0x69676572 in little-endian)
    let region_sig = u32::from_le_bytes([
        buffer[region_table_offset_in_sector],
        buffer[region_table_offset_in_sector + 1],
        buffer[region_table_offset_in_sector + 2],
        buffer[region_table_offset_in_sector + 3],
    ]);
    if region_sig != VHDX_REGION_TABLE_SIG {
        (call_table.debug_print)(b"info: VHDX bad region sig\n\0".as_ptr());
        result.virtual_size = actual_size;
        return;
    }

    // Entry count at offset 8 (little-endian u32)
    let entry_count = u32::from_le_bytes([
        buffer[region_table_offset_in_sector + 8],
        buffer[region_table_offset_in_sector + 9],
        buffer[region_table_offset_in_sector + 10],
        buffer[region_table_offset_in_sector + 11],
    ]);

    // Search for metadata region entry (GUID starts with 0x8b7ca206)
    // Each entry is 32 bytes starting at offset 16
    let mut metadata_region_offset: u64 = 0;
    for i in 0..entry_count.min(8) {
        // Limit to 8 entries for safety
        let entry_offset = region_table_offset_in_sector + 16 + (i as usize * 32);
        if entry_offset + 32 > input_sector_size {
            break;
        }

        // Check first 4 bytes of GUID (little-endian)
        let guid_first4 = u32::from_le_bytes([
            buffer[entry_offset],
            buffer[entry_offset + 1],
            buffer[entry_offset + 2],
            buffer[entry_offset + 3],
        ]);

        if guid_first4 == VHDX_METADATA_GUID_FIRST4 {
            // Found metadata region - get file offset at entry offset + 16
            metadata_region_offset = u64::from_le_bytes([
                buffer[entry_offset + 16],
                buffer[entry_offset + 17],
                buffer[entry_offset + 18],
                buffer[entry_offset + 19],
                buffer[entry_offset + 20],
                buffer[entry_offset + 21],
                buffer[entry_offset + 22],
                buffer[entry_offset + 23],
            ]);
            break;
        }
    }

    if metadata_region_offset == 0 {
        (call_table.debug_print)(b"info: VHDX no metadata region\n\0".as_ptr());
        result.virtual_size = actual_size;
        return;
    }

    // Step 2: Read metadata table to verify and locate items
    let metadata_table_sector = metadata_region_offset / input_sector_size as u64;
    let metadata_table_offset_in_sector =
        (metadata_region_offset % input_sector_size as u64) as usize;

    if !(call_table.read_input_sector)(
        metadata_table_sector,
        buffer.as_mut_ptr(),
        input_sector_size,
    ) {
        result.virtual_size = actual_size;
        return;
    }

    // Verify metadata table signature "metadata" (0x617461646174656d in little-endian)
    let metadata_sig = u64::from_le_bytes([
        buffer[metadata_table_offset_in_sector],
        buffer[metadata_table_offset_in_sector + 1],
        buffer[metadata_table_offset_in_sector + 2],
        buffer[metadata_table_offset_in_sector + 3],
        buffer[metadata_table_offset_in_sector + 4],
        buffer[metadata_table_offset_in_sector + 5],
        buffer[metadata_table_offset_in_sector + 6],
        buffer[metadata_table_offset_in_sector + 7],
    ]);
    if metadata_sig != VHDX_METADATA_TABLE_SIG {
        (call_table.debug_print)(b"info: VHDX bad metadata sig\n\0".as_ptr());
        result.virtual_size = actual_size;
        return;
    }

    // Step 3: Read metadata items at standard offset (metadata_region + 0x10000)
    // The File Parameters and Virtual Disk Size items are at fixed offsets in the items area
    let metadata_items_offset = metadata_region_offset + VHDX_METADATA_ITEM_OFFSET;
    let metadata_items_sector = metadata_items_offset / input_sector_size as u64;
    let metadata_items_offset_in_sector =
        (metadata_items_offset % input_sector_size as u64) as usize;

    if !(call_table.read_input_sector)(
        metadata_items_sector,
        buffer.as_mut_ptr(),
        input_sector_size,
    ) {
        result.virtual_size = actual_size;
        return;
    }

    // File Parameters: Block Size at offset 0 (little-endian u32)
    let block_size = u32::from_le_bytes([
        buffer[metadata_items_offset_in_sector],
        buffer[metadata_items_offset_in_sector + 1],
        buffer[metadata_items_offset_in_sector + 2],
        buffer[metadata_items_offset_in_sector + 3],
    ]);
    result.cluster_size = block_size;

    // Virtual Disk Size at offset 8 (little-endian u64)
    let virtual_size = u64::from_le_bytes([
        buffer[metadata_items_offset_in_sector + 8],
        buffer[metadata_items_offset_in_sector + 9],
        buffer[metadata_items_offset_in_sector + 10],
        buffer[metadata_items_offset_in_sector + 11],
        buffer[metadata_items_offset_in_sector + 12],
        buffer[metadata_items_offset_in_sector + 13],
        buffer[metadata_items_offset_in_sector + 14],
        buffer[metadata_items_offset_in_sector + 15],
    ]);
    result.virtual_size = virtual_size;

    (call_table.debug_print)(b"info: VHDX parsed ok\n\0".as_ptr());
}

/// Parse QCOW2 header and populate result and format-specific info
///
/// Also reads the backing file path if present.
unsafe fn parse_qcow2_header(
    buffer: &[u8],
    result: &mut InfoResult,
    qcow2_info: &mut Qcow2Info,
    call_table: &CallTable,
    backing_file_buf: &mut [u8; MAX_BACKING_FILE_LEN + 1],
    input_sector_size: usize,
) {
    // Version (big-endian u32 at offset 4)
    let version = u32::from_be_bytes([
        buffer[QCOW2_VERSION_OFFSET],
        buffer[QCOW2_VERSION_OFFSET + 1],
        buffer[QCOW2_VERSION_OFFSET + 2],
        buffer[QCOW2_VERSION_OFFSET + 3],
    ]);
    result.version = version;

    // Set compat based on version: v2 = 0.10, v3 = 1.1
    qcow2_info.compat = if version >= 3 { 1 } else { 0 };

    // Cluster bits (big-endian u32 at offset 20)
    let cluster_bits = u32::from_be_bytes([
        buffer[QCOW2_CLUSTER_BITS_OFFSET],
        buffer[QCOW2_CLUSTER_BITS_OFFSET + 1],
        buffer[QCOW2_CLUSTER_BITS_OFFSET + 2],
        buffer[QCOW2_CLUSTER_BITS_OFFSET + 3],
    ]);
    result.cluster_size = 1u32 << cluster_bits;

    // L1 table info for qemu-style disk size calculation
    // qemu-img calculates disk size as: ceil((l1_offset + l1_size * 8) / 512) * 512
    let l1_size = u32::from_be_bytes([
        buffer[QCOW2_L1_SIZE_OFFSET],
        buffer[QCOW2_L1_SIZE_OFFSET + 1],
        buffer[QCOW2_L1_SIZE_OFFSET + 2],
        buffer[QCOW2_L1_SIZE_OFFSET + 3],
    ]);
    let l1_table_offset = u64::from_be_bytes([
        buffer[QCOW2_L1_TABLE_OFFSET_OFFSET],
        buffer[QCOW2_L1_TABLE_OFFSET_OFFSET + 1],
        buffer[QCOW2_L1_TABLE_OFFSET_OFFSET + 2],
        buffer[QCOW2_L1_TABLE_OFFSET_OFFSET + 3],
        buffer[QCOW2_L1_TABLE_OFFSET_OFFSET + 4],
        buffer[QCOW2_L1_TABLE_OFFSET_OFFSET + 5],
        buffer[QCOW2_L1_TABLE_OFFSET_OFFSET + 6],
        buffer[QCOW2_L1_TABLE_OFFSET_OFFSET + 7],
    ]);

    // Calculate qemu-style disk size: highest offset rounded up to 512-byte sector
    let l1_table_end = l1_table_offset + (l1_size as u64) * 8;
    let qemu_disk_size = ((l1_table_end + 511) / 512) * 512;
    result.actual_size = qemu_disk_size;

    // Virtual size (big-endian u64 at offset 24)
    result.virtual_size = u64::from_be_bytes([
        buffer[QCOW2_SIZE_OFFSET],
        buffer[QCOW2_SIZE_OFFSET + 1],
        buffer[QCOW2_SIZE_OFFSET + 2],
        buffer[QCOW2_SIZE_OFFSET + 3],
        buffer[QCOW2_SIZE_OFFSET + 4],
        buffer[QCOW2_SIZE_OFFSET + 5],
        buffer[QCOW2_SIZE_OFFSET + 6],
        buffer[QCOW2_SIZE_OFFSET + 7],
    ]);

    // Encryption method (big-endian u32 at offset 32)
    let crypt_method = u32::from_be_bytes([
        buffer[QCOW2_CRYPT_METHOD_OFFSET],
        buffer[QCOW2_CRYPT_METHOD_OFFSET + 1],
        buffer[QCOW2_CRYPT_METHOD_OFFSET + 2],
        buffer[QCOW2_CRYPT_METHOD_OFFSET + 3],
    ]);
    if crypt_method != 0 {
        result.flags |= InfoResult::FLAG_ENCRYPTED;
    }

    // Backing file offset and size
    let backing_offset = u64::from_be_bytes([
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 1],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 2],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 3],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 4],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 5],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 6],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 7],
    ]);
    let backing_size = u32::from_be_bytes([
        buffer[QCOW2_BACKING_FILE_SIZE_OFFSET],
        buffer[QCOW2_BACKING_FILE_SIZE_OFFSET + 1],
        buffer[QCOW2_BACKING_FILE_SIZE_OFFSET + 2],
        buffer[QCOW2_BACKING_FILE_SIZE_OFFSET + 3],
    ]);

    if backing_offset != 0 && backing_size > 0 {
        result.flags |= InfoResult::FLAG_HAS_BACKING_FILE;
        (call_table.debug_print)(b"info: has backing file\n\0".as_ptr());

        // Read the backing file name from the image
        // Limit to our buffer size (protocol supports 1024 chars)
        let read_size = core::cmp::min(backing_size as usize, MAX_BACKING_FILE_LEN);

        // Calculate which sector contains the backing file offset
        let backing_sector = backing_offset / input_sector_size as u64;
        let offset_in_sector = (backing_offset % input_sector_size as u64) as usize;

        // Use a temporary buffer for the sector
        let mut sector_buf = [0u8; MAX_SECTOR_SIZE];

        if (call_table.read_input_sector)(
            backing_sector,
            sector_buf.as_mut_ptr(),
            input_sector_size,
        ) {
            // Calculate how many bytes we can read from this sector
            let bytes_in_first_sector =
                core::cmp::min(read_size, input_sector_size - offset_in_sector);

            // Copy the backing file name to our buffer
            for i in 0..bytes_in_first_sector {
                backing_file_buf[i] = sector_buf[offset_in_sector + i];
            }

            // If the backing file spans sectors, read the next sector(s)
            let mut bytes_read = bytes_in_first_sector;
            let mut current_sector = backing_sector + 1;

            while bytes_read < read_size {
                if !(call_table.read_input_sector)(
                    current_sector,
                    sector_buf.as_mut_ptr(),
                    input_sector_size,
                ) {
                    break;
                }

                let bytes_to_copy = core::cmp::min(read_size - bytes_read, input_sector_size);

                for i in 0..bytes_to_copy {
                    backing_file_buf[bytes_read + i] = sector_buf[i];
                }

                bytes_read += bytes_to_copy;
                current_sector += 1;
            }

            // Ensure null termination
            backing_file_buf[bytes_read] = 0;
        }
    }

    // Default compression type (zlib)
    qcow2_info.compression_type = 0;

    // For v2, refcount_bits is always 16 (refcount_order = 4)
    // For v3+, read refcount_order from offset 96
    if version >= 3 {
        // Refcount order (big-endian u32 at offset 96) - refcount_bits = 1 << refcount_order
        let refcount_order = u32::from_be_bytes([
            buffer[QCOW2_REFCOUNT_ORDER_OFFSET],
            buffer[QCOW2_REFCOUNT_ORDER_OFFSET + 1],
            buffer[QCOW2_REFCOUNT_ORDER_OFFSET + 2],
            buffer[QCOW2_REFCOUNT_ORDER_OFFSET + 3],
        ]);
        qcow2_info.refcount_bits = 1u32 << refcount_order;
    } else {
        qcow2_info.refcount_bits = 16;
    }

    // Version 3 specific features
    if version >= 3 {
        // Incompatible features (big-endian u64 at offset 72)
        let incompat = u64::from_be_bytes([
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 1],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 2],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 3],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 4],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 5],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 6],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 7],
        ]);

        if (incompat & QCOW2_INCOMPAT_DIRTY) != 0 {
            result.flags |= InfoResult::FLAG_DIRTY;
            qcow2_info.dirty = true;
        }
        if (incompat & QCOW2_INCOMPAT_CORRUPT) != 0 {
            result.flags |= InfoResult::FLAG_CORRUPT;
            qcow2_info.corrupt = true;
        }
        if (incompat & QCOW2_INCOMPAT_EXTERNAL_DATA) != 0 {
            result.flags |= InfoResult::FLAG_HAS_EXTERNAL_DATA;
            (call_table.debug_print)(b"info: has external data\n\0".as_ptr());
        }
        if (incompat & QCOW2_INCOMPAT_COMPRESSION) != 0 {
            result.flags |= InfoResult::FLAG_COMPRESSED;
        }
        if (incompat & QCOW2_INCOMPAT_EXTENDED_L2) != 0 {
            qcow2_info.extended_l2 = true;
        }

        // Compatible features (big-endian u64 at offset 80)
        let compat = u64::from_be_bytes([
            buffer[QCOW2_COMPATIBLE_FEATURES_OFFSET],
            buffer[QCOW2_COMPATIBLE_FEATURES_OFFSET + 1],
            buffer[QCOW2_COMPATIBLE_FEATURES_OFFSET + 2],
            buffer[QCOW2_COMPATIBLE_FEATURES_OFFSET + 3],
            buffer[QCOW2_COMPATIBLE_FEATURES_OFFSET + 4],
            buffer[QCOW2_COMPATIBLE_FEATURES_OFFSET + 5],
            buffer[QCOW2_COMPATIBLE_FEATURES_OFFSET + 6],
            buffer[QCOW2_COMPATIBLE_FEATURES_OFFSET + 7],
        ]);

        if (compat & QCOW2_COMPAT_LAZY_REFCOUNTS) != 0 {
            qcow2_info.lazy_refcounts = true;
        }

        // Compression type (u8 at offset 104) - 0=zlib, 1=zstd
        qcow2_info.compression_type = buffer[QCOW2_COMPRESSION_TYPE_OFFSET];

        // Parse header extensions (v3+)
        // Header length is at offset 100 (big-endian u32)
        let header_length =
            u32::from_be_bytes([buffer[100], buffer[101], buffer[102], buffer[103]]) as usize;

        // Extensions start at header_length offset
        // Each extension: type (4 bytes BE), length (4 bytes BE), data (length bytes, padded to 8)
        let mut ext_offset = header_length;
        while ext_offset + 8 <= buffer.len() {
            let ext_type = u32::from_be_bytes([
                buffer[ext_offset],
                buffer[ext_offset + 1],
                buffer[ext_offset + 2],
                buffer[ext_offset + 3],
            ]);
            let ext_len = u32::from_be_bytes([
                buffer[ext_offset + 4],
                buffer[ext_offset + 5],
                buffer[ext_offset + 6],
                buffer[ext_offset + 7],
            ]) as usize;

            // End of extensions
            if ext_type == QCOW2_EXT_END {
                break;
            }

            // Check if we have enough data for this extension
            if ext_offset + 8 + ext_len > buffer.len() {
                break;
            }

            // Handle backing format extension
            if ext_type == QCOW2_EXT_BACKING_FORMAT && ext_len > 0 {
                let format_bytes = &buffer[ext_offset + 8..ext_offset + 8 + ext_len];
                qcow2_info.backing_format = shared::BackingFormat::from_bytes(format_bytes);
                (call_table.debug_print)(b"info: found backing format ext\n\0".as_ptr());
            }

            // Move to next extension (data is padded to 8-byte boundary)
            let padded_len = (ext_len + 7) & !7;
            ext_offset += 8 + padded_len;
        }
    }
}

/// Parse VMDK4 header and populate result and VMDK-specific info
unsafe fn parse_vmdk4_header(
    buffer: &[u8],
    result: &mut InfoResult,
    vmdk_info: &mut VmdkInfo,
    call_table: &CallTable,
) {
    // Version (little-endian u32 at offset 4)
    let version = u32::from_le_bytes([
        buffer[VMDK4_VERSION_OFFSET],
        buffer[VMDK4_VERSION_OFFSET + 1],
        buffer[VMDK4_VERSION_OFFSET + 2],
        buffer[VMDK4_VERSION_OFFSET + 3],
    ]);
    result.version = version;

    // Capacity in sectors (little-endian u64 at offset 12)
    let capacity_sectors = u64::from_le_bytes([
        buffer[VMDK4_CAPACITY_OFFSET],
        buffer[VMDK4_CAPACITY_OFFSET + 1],
        buffer[VMDK4_CAPACITY_OFFSET + 2],
        buffer[VMDK4_CAPACITY_OFFSET + 3],
        buffer[VMDK4_CAPACITY_OFFSET + 4],
        buffer[VMDK4_CAPACITY_OFFSET + 5],
        buffer[VMDK4_CAPACITY_OFFSET + 6],
        buffer[VMDK4_CAPACITY_OFFSET + 7],
    ]);
    // VMDK uses 512-byte sectors for capacity
    result.virtual_size = capacity_sectors * 512;

    // Grain size in sectors (little-endian u64 at offset 20)
    let grain_size = u64::from_le_bytes([
        buffer[VMDK4_GRAIN_SIZE_OFFSET],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 1],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 2],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 3],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 4],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 5],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 6],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 7],
    ]);
    // Grain size is similar to cluster size
    result.cluster_size = (grain_size * 512) as u32;

    // Descriptor offset in sectors (little-endian u64 at offset 28)
    let desc_offset_sectors = u64::from_le_bytes([
        buffer[VMDK4_DESC_OFFSET_OFFSET],
        buffer[VMDK4_DESC_OFFSET_OFFSET + 1],
        buffer[VMDK4_DESC_OFFSET_OFFSET + 2],
        buffer[VMDK4_DESC_OFFSET_OFFSET + 3],
        buffer[VMDK4_DESC_OFFSET_OFFSET + 4],
        buffer[VMDK4_DESC_OFFSET_OFFSET + 5],
        buffer[VMDK4_DESC_OFFSET_OFFSET + 6],
        buffer[VMDK4_DESC_OFFSET_OFFSET + 7],
    ]);

    // Descriptor size in sectors (little-endian u64 at offset 36)
    let desc_size_sectors = u64::from_le_bytes([
        buffer[VMDK4_DESC_SIZE_OFFSET],
        buffer[VMDK4_DESC_SIZE_OFFSET + 1],
        buffer[VMDK4_DESC_SIZE_OFFSET + 2],
        buffer[VMDK4_DESC_SIZE_OFFSET + 3],
        buffer[VMDK4_DESC_SIZE_OFFSET + 4],
        buffer[VMDK4_DESC_SIZE_OFFSET + 5],
        buffer[VMDK4_DESC_SIZE_OFFSET + 6],
        buffer[VMDK4_DESC_SIZE_OFFSET + 7],
    ]);

    // Read and parse the descriptor if present
    if desc_offset_sectors > 0 && desc_size_sectors > 0 {
        (call_table.debug_print)(b"info: reading VMDK descriptor\n\0".as_ptr());

        // Get input sector size (this is the virtio device's sector size, which may differ
        // from VMDK's internal 512-byte sectors)
        let input_sector_size = (call_table.get_input_sector_size)();

        // VMDK header stores offsets in 512-byte sectors. Convert to byte offset,
        // then to the actual device sector number.
        let desc_byte_offset = desc_offset_sectors * 512;
        let desc_sector = desc_byte_offset / input_sector_size as u64;
        let offset_within_sector = (desc_byte_offset % input_sector_size as u64) as usize;

        // Read the sector containing the descriptor
        let mut desc_buffer = [0u8; MAX_SECTOR_SIZE];

        if (call_table.read_input_sector)(desc_sector, desc_buffer.as_mut_ptr(), input_sector_size)
        {
            // Parse the descriptor text starting at the correct offset within the sector
            // The descriptor typically starts within the sector at offset_within_sector
            let desc_data = &desc_buffer[offset_within_sector..input_sector_size];
            parse_vmdk_descriptor(desc_data, desc_data.len(), vmdk_info);
        }
    }
}

/// Parse VMDK descriptor text to extract CID, parentCID, and createType
fn parse_vmdk_descriptor(buffer: &[u8], len: usize, vmdk_info: &mut VmdkInfo) {
    // Find null terminator or end of buffer
    let end = buffer[..len].iter().position(|&b| b == 0).unwrap_or(len);
    let text = &buffer[..end];

    // Parse line by line (newline separated)
    let mut pos = 0;
    while pos < text.len() {
        // Find end of line
        let line_end = text[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(text.len());

        let line = &text[pos..line_end];

        // Parse CID=<hex>
        if line.starts_with(b"CID=") {
            if let Some(cid) = parse_hex_value(&line[4..]) {
                vmdk_info.cid = cid;
            }
        }
        // Parse parentCID=<hex>
        else if line.starts_with(b"parentCID=") {
            if let Some(parent_cid) = parse_hex_value(&line[10..]) {
                vmdk_info.parent_cid = parent_cid;
            }
        }
        // Parse createType="<string>"
        else if line.starts_with(b"createType=") {
            // Skip createType=" and find closing quote
            let value_start = 12; // After 'createType="'
            if line.len() > value_start && line[11] == b'"' {
                // Find closing quote
                if let Some(quote_end) = line[value_start..].iter().position(|&b| b == b'"') {
                    vmdk_info.set_create_type(&line[value_start..value_start + quote_end]);
                }
            }
        }

        pos = line_end + 1;
    }
}

/// Parse a hex value from ASCII bytes (without 0x prefix)
fn parse_hex_value(bytes: &[u8]) -> Option<u32> {
    let mut value: u32 = 0;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            b' ' | b'\r' | b'\n' | 0 => break, // End of value (space terminates)
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit as u32)?;
    }
    Some(value)
}

/// Get the call table from the fixed address
unsafe fn get_call_table() -> &'static CallTable {
    &*(CALL_TABLE_ADDR as *const CallTable)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        let call_table = get_call_table();
        if call_table.magic == CallTable::MAGIC {
            (call_table.send_error)(b"panic\0".as_ptr(), b"info\0".as_ptr(), 0, 0xDEAD);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
