//! Info operation: detect image format and report metadata.
//!
//! This operation reads the first sector(s) from the input virtio-block device
//! to detect the image format based on magic numbers and header structures.
//! Results are sent via protobuf InfoResultMessage over the serial command channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    format_detection::{
        detect_format_from_header, detect_iso_at_offset, detect_vhd_footer, ISO_MAGIC_BYTE_OFFSET,
        VDI_SIGNATURE_OFFSET, VHD_COOKIE,
    },
    CallTable, ImageFormat, InfoConfig, InfoResult, Qcow2Info, VdiInfo, VmdkInfo, CALL_TABLE_ADDR,
    MAX_SECTOR_SIZE,
};

// Note: Magic numbers for format detection are in shared::format_detection

// VHD footer offsets (big-endian)
const VHD_FOOTER_CREATOR_APP_OFFSET: usize = 28; // Creator application (4 bytes ASCII)
const VHD_FOOTER_DISK_SIZE_OFFSET: usize = 40; // Original/virtual size in bytes (8 bytes)
const VHD_FOOTER_DISK_GEOMETRY_OFFSET: usize = 56; // CHS geometry (4 bytes: cyls[2], heads[1], secs[1])

// VHD maximum CHS geometry (indicates current_size should be used instead)
const VHD_MAX_CHS_CYLS: u16 = 65535;
const VHD_MAX_CHS_HEADS: u8 = 16;
const VHD_MAX_CHS_SECS: u8 = 255;

// Maximum backing file path length (QCOW2 spec allows up to 1023 bytes)
const MAX_BACKING_FILE_LEN: usize = 1024;

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

// VDI header offsets (all little-endian)
// Note: VDI_SIGNATURE_OFFSET is in shared::format_detection
const VDI_VERSION_OFFSET: usize = 68; // Version (1.1 = 0x00010001)
const VDI_HEADER_SIZE_OFFSET: usize = 72; // Size of header
const VDI_IMAGE_TYPE_OFFSET: usize = 76; // 1=dynamic, 2=fixed
const VDI_DISK_SIZE_OFFSET: usize = 368; // Virtual disk size in bytes (u64)
const VDI_BLOCK_SIZE_OFFSET: usize = 376; // Block size in bytes (u32)
const VDI_BLOCKS_IN_IMAGE_OFFSET: usize = 384; // Total blocks (u32)
const VDI_BLOCKS_ALLOCATED_OFFSET: usize = 388; // Allocated blocks (u32)
const VDI_UUID_OFFSET: usize = 392; // UUID (16 bytes)

// QED format constants (deprecated QEMU format, all little-endian)
// Note: QED_MAGIC is in shared::format_detection
const QED_CLUSTER_SIZE_OFFSET: usize = 4; // Cluster size in bytes (u32)
const QED_TABLE_SIZE_OFFSET: usize = 8; // L1/L2 table size in clusters (u32)
const QED_HEADER_SIZE_OFFSET: usize = 12; // Header size in bytes (u32)
const QED_IMAGE_SIZE_OFFSET: usize = 48; // Virtual size in bytes (u64)
const QED_BACKING_FILENAME_OFFSET_OFFSET: usize = 56; // Backing filename offset (u32)
const QED_BACKING_FILENAME_SIZE_OFFSET: usize = 60; // Backing filename size (u32)

// Note: ISO_MAGIC_BYTE_OFFSET and ISO_MAGIC are in shared::format_detection

// LUKS format constants (Linux encrypted container)
// LUKS magic is "LUKS\xba\xbe" (6 bytes) at offset 0
// Note: LUKS_MAGIC is in shared::format_detection
const LUKS_VERSION_OFFSET: usize = 6; // Version (big-endian u16)

/// Entry point called by core after devices are initialized.
///
/// Returns the number of bytes read.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    // Verify call table is valid (always print these errors)
    if call_table.magic != CallTable::MAGIC {
        (call_table.debug_print)(b"info: bad magic\n\0".as_ptr());
        return 0;
    }
    if call_table.version != CallTable::VERSION {
        (call_table.debug_print)(b"info: bad version\n\0".as_ptr());
        return 0;
    }

    // Get operation config (optional)
    let config_result = (call_table.get_operation_config)();
    let config = &*(config_result.ptr as *const InfoConfig);
    let detailed = if config.is_valid() {
        config.should_report_detailed()
    } else {
        true // Default to detailed
    };
    // Extra detail mode enables detection of formats like LUKS that qemu-img
    // doesn't recognize. Without it, these formats are reported as "raw" for
    // qemu-img compatibility.
    let extra_detail = config.is_valid() && config.extra_detail_enabled();

    (call_table.verbose_print)(b"info: start\n\0".as_ptr());

    // Get device parameters (device 0 = primary input)
    let input_capacity = (call_table.get_input_capacity)(0);
    let input_sector_size = (call_table.get_input_sector_size)(0);

    // Calculate device capacity (may be padded to sector boundary)
    let device_capacity = input_capacity * input_sector_size as u64;

    (call_table.verbose_print)(b"info: reading header\n\0".as_ptr());

    // Buffer for reading data
    let mut buffer = [0u8; MAX_SECTOR_SIZE];

    // Read first sector (device 0, sector 0)
    if !(call_table.read_input_sector)(0, 0, buffer.as_mut_ptr(), input_sector_size) {
        (call_table.send_error)(b"info\0".as_ptr(), b"input\0".as_ptr(), 0, 1);
        return 0;
    }

    let bytes_read = input_sector_size as u64;

    // Initialize result structure
    // Note: actual_size is left as 0 for non-QCOW2 formats. The VMM uses
    // max(real_file_size, actual_size) for "file length", so 0 means the
    // VMM will use the real file size from the filesystem. Only QCOW2 sets
    // actual_size to the computed header-based size (qemu_disk_size).
    // Setting actual_size to device_capacity here would be WRONG because
    // device_capacity may be padded to a sector boundary, producing
    // incorrect "file length" values for non-QCOW2 formats.
    let mut result = InfoResult::new();

    // Detect format based on magic numbers (first sector)
    // Pass extra_detail flag to control detection of formats like LUKS that qemu-img
    // doesn't recognize - these are only shown with --extra-detail
    let mut format = detect_format_from_header(&buffer, input_sector_size, extra_detail);

    // Buffer for VHD footer (may be reused)
    let mut footer_buffer = [0u8; MAX_SECTOR_SIZE];

    // If no format detected from header, try VHD detection (footer at end of file)
    if format == ImageFormat::Raw && input_capacity > 0 {
        (call_table.verbose_print)(b"info: checking VHD footer\n\0".as_ptr());
        let last_sector = input_capacity - 1;
        if (call_table.read_input_sector)(
            0,
            last_sector,
            footer_buffer.as_mut_ptr(),
            input_sector_size,
        ) {
            format = detect_vhd_footer(&footer_buffer);
        }
    }

    // Check if unsafe quirks mode is enabled (qemu-img compatible but insecure)
    let unsafe_quirks = config.is_valid() && config.unsafe_quirks_enabled();

    // If still no format detected, try ISO 9660 detection (magic at byte offset 32769)
    // Note: qemu-img treats ISO as "raw", so we only detect ISO in safe mode.
    // With --unsafe-quirks, ISO files will be reported as "raw" for qemu-img compatibility.
    if format == ImageFormat::Raw && !unsafe_quirks {
        (call_table.verbose_print)(b"info: checking ISO 9660\n\0".as_ptr());
        // ISO magic is at byte offset 32769 ("CD001" at 32768+1)
        // Check if the magic is already in our first sector buffer
        if input_sector_size >= ISO_MAGIC_BYTE_OFFSET + 5 {
            // Large sector size: magic is in first sector
            format = detect_iso_at_offset(&buffer, ISO_MAGIC_BYTE_OFFSET);
        } else {
            // Small sector size: need to read the sector containing the magic
            let iso_sector = ISO_MAGIC_BYTE_OFFSET as u64 / input_sector_size as u64;
            let offset_in_sector = ISO_MAGIC_BYTE_OFFSET % input_sector_size;
            if input_capacity > iso_sector {
                if (call_table.read_input_sector)(
                    0,
                    iso_sector,
                    footer_buffer.as_mut_ptr(),
                    input_sector_size,
                ) {
                    format = detect_iso_at_offset(&footer_buffer, offset_in_sector);
                }
            }
        }
    }

    // For RAW format: validate partition table unless unsafe quirks is enabled.
    // This prevents arbitrary files (like /etc/passwd) from being accepted as
    // valid disk images, which is the root cause of backing file disclosure attacks.
    if format == ImageFormat::Raw {
        if !unsafe_quirks {
            // Check for valid partition table
            let partition_type = raw::detect_partition_table(&buffer);

            match partition_type {
                raw::PartitionTableType::Mbr => {
                    (call_table.verbose_print)(b"info: found MBR partition table\n\0".as_ptr());
                    result.flags |= InfoResult::FLAG_HAS_MBR;
                }
                raw::PartitionTableType::Gpt => {
                    (call_table.verbose_print)(b"info: found GPT partition table\n\0".as_ptr());
                    result.flags |= InfoResult::FLAG_HAS_GPT;
                }
                raw::PartitionTableType::None => {
                    // No valid partition table found - reject as unknown format
                    // This is the secure default: only accept files that are
                    // recognizably disk images
                    (call_table.verbose_print)(
                        b"info: no partition table, rejecting as unknown\n\0".as_ptr(),
                    );
                    format = ImageFormat::Unknown;
                }
            }
        } else {
            // Unsafe quirks mode: accept any file as RAW (qemu-img compatible
            // but insecure). Still detect partition table for informational
            // purposes.
            let partition_type = raw::detect_partition_table(&buffer);
            match partition_type {
                raw::PartitionTableType::Mbr => {
                    result.flags |= InfoResult::FLAG_HAS_MBR;
                }
                raw::PartitionTableType::Gpt => {
                    result.flags |= InfoResult::FLAG_HAS_GPT;
                }
                raw::PartitionTableType::None => {
                    // Accept anyway in unsafe mode
                    (call_table.verbose_print)(
                        b"info: no partition table (unsafe quirks)\n\0".as_ptr(),
                    );
                }
            }
        }
    }

    result.format = format as u32;

    (call_table.verbose_print)(b"info: detected format\n\0".as_ptr());

    // Get format string for protobuf message
    let format_str = format_to_str(format);

    // Parse format-specific metadata and send results
    // Format-specific structs are created only within their respective branches
    match format {
        ImageFormat::Qcow2 => {
            let mut qcow2_info = Qcow2Info::new();
            let mut backing_file_buf = [0u8; MAX_BACKING_FILE_LEN + 1];

            if detailed {
                (call_table.verbose_print)(b"info: parsing qcow2\n\0".as_ptr());
                parse_qcow2_header(
                    &buffer,
                    &mut result,
                    &mut qcow2_info,
                    call_table,
                    &mut backing_file_buf,
                    input_sector_size,
                    input_capacity,
                );
            }

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
        }
        ImageFormat::Vmdk4 => {
            let mut vmdk_info = VmdkInfo::new();

            if detailed {
                parse_vmdk4_header(&buffer, &mut result, &mut vmdk_info, call_table);
                // Set compressed flag if createType indicates compression
                if vmdk_info.create_type_str() == "streamOptimized" {
                    result.flags |= InfoResult::FLAG_COMPRESSED;
                }
            }

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
        }
        ImageFormat::Vdi => {
            let mut vdi_info = VdiInfo::new();

            if detailed {
                parse_vdi_header(&buffer, &mut result, &mut vdi_info);
            }

            (call_table.send_info_result_vdi)(
                format_str,
                result.version,
                result.virtual_size,
                result.actual_size,
                result.cluster_size,
                result.flags,
                b"\0".as_ptr(), // backing_file (empty for now)
                b"\0".as_ptr(), // external_data_file (empty for now)
                &vdi_info,
            );
        }
        ImageFormat::Vhd => {
            if detailed {
                // VHD footer may be in first sector (dynamic) or last sector (fixed)
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

            (call_table.send_info_result)(
                format_str,
                result.version,
                result.virtual_size,
                result.actual_size,
                result.cluster_size,
                result.flags,
                b"\0".as_ptr(),
                b"\0".as_ptr(),
            );
        }
        ImageFormat::Vhdx => {
            if detailed {
                parse_vhdx_metadata(&mut result, device_capacity, call_table);
            }

            (call_table.send_info_result)(
                format_str,
                result.version,
                result.virtual_size,
                result.actual_size,
                result.cluster_size,
                result.flags,
                b"\0".as_ptr(),
                b"\0".as_ptr(),
            );
        }
        ImageFormat::Qed => {
            if detailed {
                parse_qed_header(&buffer, &mut result);
            }

            (call_table.send_info_result)(
                format_str,
                result.version,
                result.virtual_size,
                result.actual_size,
                result.cluster_size,
                result.flags,
                b"\0".as_ptr(),
                b"\0".as_ptr(),
            );
        }
        ImageFormat::Luks => {
            if detailed {
                parse_luks_header(&buffer, &mut result);
            }

            (call_table.send_info_result)(
                format_str,
                result.version,
                result.virtual_size,
                result.actual_size,
                result.cluster_size,
                result.flags,
                b"\0".as_ptr(),
                b"\0".as_ptr(),
            );
        }
        _ => {
            // For raw and unknown formats, virtual size = actual size
            if detailed {
                result.virtual_size = device_capacity;
            }

            (call_table.send_info_result)(
                format_str,
                result.version,
                result.virtual_size,
                result.actual_size,
                result.cluster_size,
                result.flags,
                b"\0".as_ptr(),
                b"\0".as_ptr(),
            );
        }
    }

    (call_table.send_complete)(b"info\0".as_ptr(), bytes_read, true);
    (call_table.verbose_print)(b"info: done\n\0".as_ptr());

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
        ImageFormat::Vdi => b"vdi\0".as_ptr(),
        ImageFormat::Qed => b"qed\0".as_ptr(),
        ImageFormat::Iso => b"iso\0".as_ptr(),
        ImageFormat::Luks => b"luks\0".as_ptr(),
    }
}

// Note: detect_format_from_header, detect_vhd_footer, detect_iso_at_offset are
// now in shared::format_detection
// Note: detect_partition_table is in the raw crate

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
unsafe fn parse_vhdx_metadata(
    result: &mut InfoResult,
    device_capacity: u64,
    call_table: &CallTable,
) {
    let input_sector_size = (call_table.get_input_sector_size)(0);
    let mut buffer = [0u8; MAX_SECTOR_SIZE];

    // Step 1: Read region table at offset 0x30000 to find metadata region offset
    let region_table_sector = VHDX_REGION_TABLE_OFFSET / input_sector_size as u64;
    let region_table_offset_in_sector =
        (VHDX_REGION_TABLE_OFFSET % input_sector_size as u64) as usize;

    if !(call_table.read_input_sector)(
        0,
        region_table_sector,
        buffer.as_mut_ptr(),
        input_sector_size,
    ) {
        // Failed to read region table, fall back to actual size
        result.virtual_size = device_capacity;
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
        result.virtual_size = device_capacity;
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
        result.virtual_size = device_capacity;
        return;
    }

    // Step 2: Read metadata table to verify and locate items
    let metadata_table_sector = metadata_region_offset / input_sector_size as u64;
    let metadata_table_offset_in_sector =
        (metadata_region_offset % input_sector_size as u64) as usize;

    if !(call_table.read_input_sector)(
        0,
        metadata_table_sector,
        buffer.as_mut_ptr(),
        input_sector_size,
    ) {
        result.virtual_size = device_capacity;
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
        result.virtual_size = device_capacity;
        return;
    }

    // Step 3: Read metadata items at standard offset (metadata_region + 0x10000)
    // The File Parameters and Virtual Disk Size items are at fixed offsets in the items area
    let metadata_items_offset = metadata_region_offset + VHDX_METADATA_ITEM_OFFSET;
    let metadata_items_sector = metadata_items_offset / input_sector_size as u64;
    let metadata_items_offset_in_sector =
        (metadata_items_offset % input_sector_size as u64) as usize;

    if !(call_table.read_input_sector)(
        0,
        metadata_items_sector,
        buffer.as_mut_ptr(),
        input_sector_size,
    ) {
        result.virtual_size = device_capacity;
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

    (call_table.verbose_print)(b"info: VHDX parsed ok\n\0".as_ptr());
}

/// Parse QCOW2 header and populate result and format-specific info
///
/// Uses `qcow2::QcowHeader::parse()` for field extraction and
/// `qcow2::read_backing_file()` for backing file path reading.
unsafe fn parse_qcow2_header(
    buffer: &[u8],
    result: &mut InfoResult,
    qcow2_info: &mut Qcow2Info,
    call_table: &CallTable,
    backing_file_buf: &mut [u8; MAX_BACKING_FILE_LEN + 1],
    input_sector_size: usize,
    input_capacity: u64,
) {
    let hdr = match qcow2::QcowHeader::parse(buffer) {
        Some(h) => h,
        None => return,
    };

    result.version = hdr.version;
    qcow2_info.compat = hdr.compat_value();
    result.cluster_size = hdr.cluster_size as u32;
    result.actual_size = hdr.qemu_disk_size();
    result.virtual_size = hdr.virtual_size;
    qcow2_info.refcount_bits = hdr.refcount_bits;
    qcow2_info.compression_type = hdr.compression_type;

    if hdr.crypt_method != 0 {
        result.flags |= InfoResult::FLAG_ENCRYPTED;
    }

    // Read backing file path using shared crate
    if hdr.backing_file_offset != 0 && hdr.backing_file_size > 0 {
        result.flags |= InfoResult::FLAG_HAS_BACKING_FILE;
        (call_table.verbose_print)(b"info: has backing file\n\0".as_ptr());
        qcow2::read_backing_file(
            call_table,
            0,
            &hdr,
            backing_file_buf,
            input_sector_size,
            input_capacity,
        );
    }

    // Version 3 specific features
    if hdr.version >= 3 {
        if hdr.dirty {
            result.flags |= InfoResult::FLAG_DIRTY;
            qcow2_info.dirty = true;
        }
        if hdr.corrupt {
            result.flags |= InfoResult::FLAG_CORRUPT;
            qcow2_info.corrupt = true;
        }
        if hdr.has_external_data {
            result.flags |= InfoResult::FLAG_HAS_EXTERNAL_DATA;
            (call_table.verbose_print)(b"info: has external data\n\0".as_ptr());
        }
        if (hdr.incompatible_features & qcow2::INCOMPAT_COMPRESSION) != 0 {
            result.flags |= InfoResult::FLAG_COMPRESSED;
        }
        if hdr.extended_l2 {
            qcow2_info.extended_l2 = true;
        }
        if hdr.lazy_refcounts {
            qcow2_info.lazy_refcounts = true;
        }

        // Parse header extensions for backing format
        let backing_format = qcow2::parse_header_extensions(buffer, &hdr);
        if backing_format != shared::BackingFormat::None {
            qcow2_info.backing_format = backing_format;
            (call_table.verbose_print)(b"info: found backing format ext\n\0".as_ptr());
        }
    }
}

/// Parse VMDK4 header and populate result and VMDK-specific info.
///
/// Uses `vmdk::Vmdk4Header::parse()` for binary header extraction and
/// `vmdk::read_and_parse_descriptor()` for descriptor I/O + parsing.
unsafe fn parse_vmdk4_header(
    buffer: &[u8],
    result: &mut InfoResult,
    vmdk_info: &mut VmdkInfo,
    call_table: &CallTable,
) {
    let hdr = match vmdk::Vmdk4Header::parse(buffer) {
        Some(h) => h,
        None => return,
    };

    result.version = hdr.version;
    result.virtual_size = hdr.virtual_size;
    result.cluster_size = hdr.cluster_size;

    // Read and parse the descriptor if present
    if hdr.desc_offset_sectors > 0 && hdr.desc_size_sectors > 0 {
        (call_table.verbose_print)(b"info: reading VMDK descriptor\n\0".as_ptr());
        vmdk::read_and_parse_descriptor(call_table, 0, &hdr, vmdk_info);
    }
}

/// Parse VDI header and populate result and VDI-specific info
///
/// VDI header structure (all little-endian):
/// - Offset 0-63: Text signature ("<<< Oracle VM VirtualBox Disk Image >>>\n")
/// - Offset 64-67: Magic signature (0xbeda107f)
/// - Offset 68-71: Version (0x00010001 for 1.1)
/// - Offset 72-75: Header size
/// - Offset 76-79: Image type (1=dynamic, 2=fixed)
/// - Offset 368-375: Virtual disk size in bytes
/// - Offset 376-379: Block size in bytes
/// - Offset 384-387: Total blocks
/// - Offset 388-391: Allocated blocks
/// - Offset 392-407: UUID (16 bytes)
fn parse_vdi_header(buffer: &[u8], result: &mut InfoResult, vdi_info: &mut VdiInfo) {
    // Ensure buffer is large enough for VDI header (at least 408 bytes for UUID end)
    if buffer.len() < VDI_UUID_OFFSET + 16 {
        return;
    }

    // Version (little-endian u32 at offset 68)
    let version = u32::from_le_bytes([
        buffer[VDI_VERSION_OFFSET],
        buffer[VDI_VERSION_OFFSET + 1],
        buffer[VDI_VERSION_OFFSET + 2],
        buffer[VDI_VERSION_OFFSET + 3],
    ]);
    result.version = version;

    // Image type (little-endian u32 at offset 76)
    vdi_info.image_type = u32::from_le_bytes([
        buffer[VDI_IMAGE_TYPE_OFFSET],
        buffer[VDI_IMAGE_TYPE_OFFSET + 1],
        buffer[VDI_IMAGE_TYPE_OFFSET + 2],
        buffer[VDI_IMAGE_TYPE_OFFSET + 3],
    ]);

    // Virtual disk size (little-endian u64 at offset 368)
    result.virtual_size = u64::from_le_bytes([
        buffer[VDI_DISK_SIZE_OFFSET],
        buffer[VDI_DISK_SIZE_OFFSET + 1],
        buffer[VDI_DISK_SIZE_OFFSET + 2],
        buffer[VDI_DISK_SIZE_OFFSET + 3],
        buffer[VDI_DISK_SIZE_OFFSET + 4],
        buffer[VDI_DISK_SIZE_OFFSET + 5],
        buffer[VDI_DISK_SIZE_OFFSET + 6],
        buffer[VDI_DISK_SIZE_OFFSET + 7],
    ]);

    // Block size (little-endian u32 at offset 376)
    vdi_info.block_size = u32::from_le_bytes([
        buffer[VDI_BLOCK_SIZE_OFFSET],
        buffer[VDI_BLOCK_SIZE_OFFSET + 1],
        buffer[VDI_BLOCK_SIZE_OFFSET + 2],
        buffer[VDI_BLOCK_SIZE_OFFSET + 3],
    ]);
    // Use block_size as cluster_size for consistency with other formats
    result.cluster_size = vdi_info.block_size;

    // Blocks in image (little-endian u32 at offset 384)
    vdi_info.blocks_in_image = u32::from_le_bytes([
        buffer[VDI_BLOCKS_IN_IMAGE_OFFSET],
        buffer[VDI_BLOCKS_IN_IMAGE_OFFSET + 1],
        buffer[VDI_BLOCKS_IN_IMAGE_OFFSET + 2],
        buffer[VDI_BLOCKS_IN_IMAGE_OFFSET + 3],
    ]);

    // Blocks allocated (little-endian u32 at offset 388)
    vdi_info.blocks_allocated = u32::from_le_bytes([
        buffer[VDI_BLOCKS_ALLOCATED_OFFSET],
        buffer[VDI_BLOCKS_ALLOCATED_OFFSET + 1],
        buffer[VDI_BLOCKS_ALLOCATED_OFFSET + 2],
        buffer[VDI_BLOCKS_ALLOCATED_OFFSET + 3],
    ]);

    // UUID (16 bytes at offset 392)
    vdi_info
        .uuid
        .copy_from_slice(&buffer[VDI_UUID_OFFSET..VDI_UUID_OFFSET + 16]);
}

/// Parse QED header and populate result
///
/// QED header structure (all little-endian):
/// - Offset 0-3: Magic ("QED\0" = 0x00444551)
/// - Offset 4-7: Cluster size in bytes
/// - Offset 8-11: Table size (L1/L2) in clusters
/// - Offset 12-15: Header size in bytes
/// - Offset 48-55: Virtual disk size in bytes
/// - Offset 56-59: Backing filename offset
/// - Offset 60-63: Backing filename size
fn parse_qed_header(buffer: &[u8], result: &mut InfoResult) {
    // Ensure buffer is large enough for QED header (at least 64 bytes)
    if buffer.len() < 64 {
        return;
    }

    // Cluster size (little-endian u32 at offset 4)
    result.cluster_size = u32::from_le_bytes([
        buffer[QED_CLUSTER_SIZE_OFFSET],
        buffer[QED_CLUSTER_SIZE_OFFSET + 1],
        buffer[QED_CLUSTER_SIZE_OFFSET + 2],
        buffer[QED_CLUSTER_SIZE_OFFSET + 3],
    ]);

    // Virtual disk size (little-endian u64 at offset 48)
    result.virtual_size = u64::from_le_bytes([
        buffer[QED_IMAGE_SIZE_OFFSET],
        buffer[QED_IMAGE_SIZE_OFFSET + 1],
        buffer[QED_IMAGE_SIZE_OFFSET + 2],
        buffer[QED_IMAGE_SIZE_OFFSET + 3],
        buffer[QED_IMAGE_SIZE_OFFSET + 4],
        buffer[QED_IMAGE_SIZE_OFFSET + 5],
        buffer[QED_IMAGE_SIZE_OFFSET + 6],
        buffer[QED_IMAGE_SIZE_OFFSET + 7],
    ]);

    // Check for backing file (offset at 56, size at 60)
    let backing_offset = u32::from_le_bytes([
        buffer[QED_BACKING_FILENAME_OFFSET_OFFSET],
        buffer[QED_BACKING_FILENAME_OFFSET_OFFSET + 1],
        buffer[QED_BACKING_FILENAME_OFFSET_OFFSET + 2],
        buffer[QED_BACKING_FILENAME_OFFSET_OFFSET + 3],
    ]);
    let backing_size = u32::from_le_bytes([
        buffer[QED_BACKING_FILENAME_SIZE_OFFSET],
        buffer[QED_BACKING_FILENAME_SIZE_OFFSET + 1],
        buffer[QED_BACKING_FILENAME_SIZE_OFFSET + 2],
        buffer[QED_BACKING_FILENAME_SIZE_OFFSET + 3],
    ]);

    // If backing file exists, set the flag
    if backing_offset > 0 && backing_size > 0 {
        result.flags |= InfoResult::FLAG_HAS_BACKING_FILE;
    }
}

/// Parse LUKS header and populate result
///
/// LUKS header structure:
/// - Offset 0-5: Magic "LUKS\xba\xbe" (6 bytes)
/// - Offset 6-7: Version (big-endian u16, 1 for LUKS1, 2 for LUKS2)
///
/// LUKS doesn't have a virtual size in the header - the encrypted container
/// size is determined by the underlying block device.
fn parse_luks_header(buffer: &[u8], result: &mut InfoResult) {
    // Ensure buffer is large enough for LUKS header (at least 8 bytes)
    if buffer.len() < 8 {
        return;
    }

    // Version (big-endian u16 at offset 6)
    result.version =
        u16::from_be_bytes([buffer[LUKS_VERSION_OFFSET], buffer[LUKS_VERSION_OFFSET + 1]]) as u32;

    // Mark as encrypted
    result.flags |= InfoResult::FLAG_ENCRYPTED;
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
