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
    validate_call_table, CallTable, ImageFormat, InfoConfig, InfoResult, LuksInfo, Qcow2Info,
    VdiInfo, VmdkInfo, ARGON2_MEM_BASE, CALL_TABLE_ADDR, MAX_SECTOR_SIZE, SCRATCH_MEM_BASE,
    SCRATCH_MEM_SIZE,
};

// Crypto imports for LUKS decryption
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes128, Aes256};
use argon2::Argon2;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;
use sha2::{Digest, Sha256};

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
const LUKS_CIPHER_NAME_OFFSET: usize = 8; // Cipher name (32 bytes, null-padded)
const LUKS_CIPHER_MODE_OFFSET: usize = 40; // Cipher mode (32 bytes, null-padded)
const LUKS_HASH_SPEC_OFFSET: usize = 72; // Hash spec (32 bytes, null-padded)
const LUKS_PAYLOAD_OFFSET_OFFSET: usize = 104; // Payload offset in sectors (u32 BE)
const LUKS_KEY_BYTES_OFFSET: usize = 108; // Master key length in bytes (u32 BE)
const LUKS_UUID_OFFSET: usize = 168; // UUID (36 bytes, null-padded)
const LUKS_KEY_SLOT_BASE: usize = 208; // First key slot (8 x 48 bytes)
const LUKS_KEY_SLOT_SIZE: usize = 48; // Size of each key slot
const LUKS_NUM_KEY_SLOTS: usize = 8; // Number of key slots in LUKS v1
const LUKS_KEY_SLOT_ACTIVE: u32 = 0x00AC71F3; // Active key slot magic
const LUKS_V1_HEADER_SIZE: usize = 592; // LUKS v1 full header size

// LUKS v1 additional offsets for decryption
const LUKS_MK_DIGEST_OFFSET: usize = 112; // Master key digest (20 bytes, PBKDF2 hash)
const LUKS_MK_DIGEST_SALT_OFFSET: usize = 132; // MK digest salt (32 bytes)
const LUKS_MK_DIGEST_ITER_OFFSET: usize = 164; // MK digest iterations (u32 BE)

// Key slot sub-field offsets (relative to slot start)
const LUKS_SLOT_ITERATIONS_OFFSET: usize = 4; // PBKDF2 iterations (u32 BE)
const LUKS_SLOT_SALT_OFFSET: usize = 8; // Salt (32 bytes)
const LUKS_SLOT_KEY_MATERIAL_OFFSET: usize = 40; // Key material offset in sectors (u32 BE)
const LUKS_SLOT_STRIPES_OFFSET: usize = 44; // AF stripe count (u32 BE)

// LUKS v1 AFsplitter default stripe count
const LUKS_DEFAULT_STRIPES: u32 = 4000;

// LUKS v2 binary header offsets
const LUKS2_HEADER_SIZE_OFFSET: usize = 8; // Header size including JSON area (u64 BE)
const LUKS2_UUID_OFFSET: usize = 168; // UUID (40 bytes, null-terminated)
const LUKS2_BINARY_HEADER_SIZE: usize = 4096; // Binary header is always 4096 bytes

// Maximum JSON area to read for metadata scanning (first 16 KiB covers typical
// cryptsetup output which is ~2-4 KiB of JSON).
const LUKS2_JSON_SCAN_SIZE: usize = 16384;

/// Entry point called by core after devices are initialized.
///
/// Returns the number of bytes read.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    validate_call_table!(call_table, "info");

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
            let mut external_data_file_buf = [0u8; MAX_BACKING_FILE_LEN + 1];

            if detailed {
                (call_table.verbose_print)(b"info: parsing qcow2\n\0".as_ptr());
                parse_qcow2_header(
                    &buffer,
                    &mut result,
                    &mut qcow2_info,
                    call_table,
                    &mut backing_file_buf,
                    &mut external_data_file_buf,
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
                external_data_file_buf.as_ptr(),
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
            let mut luks_info = LuksInfo::new();

            // Always parse LUKS header — chain discovery needs payload_offset
            // for virtual_size calculation even without --extra-detail.
            parse_luks_header(
                &buffer,
                &mut result,
                &mut luks_info,
                call_table,
                input_sector_size,
            );

            // Set virtual size to the payload area size (inner image).
            // LUKS v1 payload_offset is in 512-byte sectors.
            // LUKS v2 uses data_offset from JSON (stored in payload_offset).
            if luks_info.payload_offset > 0 {
                let payload_byte_offset = luks_info.payload_offset as u64 * 512;
                if device_capacity > payload_byte_offset {
                    result.virtual_size = device_capacity - payload_byte_offset;
                }
            }

            // Attempt LUKS decryption if passphrase provided
            if config.is_valid() && config.has_passphrase() {
                let decrypt_result = if result.version == 1 {
                    try_luks1_decrypt(&buffer, config, call_table, input_sector_size)
                } else if result.version == 2 {
                    try_luks2_decrypt(&buffer, &luks_info, config, call_table, input_sector_size)
                } else {
                    None
                };

                if let Some((inner_fmt, inner_vsize)) = decrypt_result {
                    luks_info.set_inner_format(inner_fmt.name());
                    luks_info.inner_virtual_size = inner_vsize;
                } else if result.version == 1 || result.version == 2 {
                    (call_table.debug_print)(
                        b"luks: decryption failed (wrong passphrase?)\n\0".as_ptr(),
                    );
                }
            }

            (call_table.send_info_result_luks)(
                format_str,
                result.version,
                result.virtual_size,
                result.actual_size,
                result.cluster_size,
                result.flags,
                b"\0".as_ptr(),
                b"\0".as_ptr(),
                &luks_info,
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
    external_data_file_buf: &mut [u8; MAX_BACKING_FILE_LEN + 1],
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

    if hdr.nb_snapshots > 0 {
        result.flags |= InfoResult::FLAG_HAS_SNAPSHOTS;
        qcow2_info.nb_snapshots = hdr.nb_snapshots;
        (call_table.verbose_print)(b"info: image has snapshots\n\0".as_ptr());
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

        // Parse header extensions for backing format and data file name
        let ext_results = qcow2::parse_header_extensions(buffer, &hdr);
        if ext_results.backing_format != shared::BackingFormat::None {
            qcow2_info.backing_format = ext_results.backing_format;
            (call_table.verbose_print)(b"info: found backing format ext\n\0".as_ptr());
        }

        // Extract external data file name from header extension
        if ext_results.data_file_name_len > 0 {
            let off = ext_results.data_file_name_offset;
            let len = ext_results.data_file_name_len.min(MAX_BACKING_FILE_LEN);
            external_data_file_buf[..len].copy_from_slice(&buffer[off..off + len]);
            external_data_file_buf[len] = 0; // null-terminate
            (call_table.verbose_print)(b"info: found data file ext\n\0".as_ptr());
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

/// Parse LUKS header and populate result and LUKS-specific info.
///
/// For LUKS v1: parses the full 592-byte binary header including cipher,
/// mode, hash, UUID, payload offset, key bytes, and key slot status.
///
/// For LUKS v2: parses the binary header (first 512 bytes) for version,
/// label, checksum algorithm, salt, and UUID. The JSON metadata area
/// (which contains keyslot/segment details) is not parsed here.
///
/// LUKS doesn't have a virtual size in the header — the encrypted
/// container size is determined by the underlying block device.
unsafe fn parse_luks_header(
    buffer: &[u8],
    result: &mut InfoResult,
    luks_info: &mut LuksInfo,
    call_table: &CallTable,
    input_sector_size: usize,
) {
    // Ensure buffer is large enough for basic LUKS header
    if buffer.len() < 8 {
        return;
    }

    // Version (big-endian u16 at offset 6)
    let version =
        u16::from_be_bytes([buffer[LUKS_VERSION_OFFSET], buffer[LUKS_VERSION_OFFSET + 1]]);
    result.version = version as u32;

    // Mark as encrypted
    result.flags |= InfoResult::FLAG_ENCRYPTED;

    if version == 1 && buffer.len() >= LUKS_V1_HEADER_SIZE {
        // LUKS v1: parse full binary header

        // Cipher name (32 bytes, null-padded, at offset 8)
        copy_null_padded(
            &buffer[LUKS_CIPHER_NAME_OFFSET..LUKS_CIPHER_NAME_OFFSET + 32],
            &mut luks_info.cipher,
        );

        // Cipher mode (32 bytes, null-padded, at offset 40)
        copy_null_padded(
            &buffer[LUKS_CIPHER_MODE_OFFSET..LUKS_CIPHER_MODE_OFFSET + 32],
            &mut luks_info.cipher_mode,
        );

        // Hash spec (32 bytes, null-padded, at offset 72)
        copy_null_padded(
            &buffer[LUKS_HASH_SPEC_OFFSET..LUKS_HASH_SPEC_OFFSET + 32],
            &mut luks_info.hash,
        );

        // Payload offset in 512-byte sectors (big-endian u32 at offset 104)
        luks_info.payload_offset = u32::from_be_bytes([
            buffer[LUKS_PAYLOAD_OFFSET_OFFSET],
            buffer[LUKS_PAYLOAD_OFFSET_OFFSET + 1],
            buffer[LUKS_PAYLOAD_OFFSET_OFFSET + 2],
            buffer[LUKS_PAYLOAD_OFFSET_OFFSET + 3],
        ]);

        // Master key length in bytes (big-endian u32 at offset 108)
        luks_info.master_key_length = u32::from_be_bytes([
            buffer[LUKS_KEY_BYTES_OFFSET],
            buffer[LUKS_KEY_BYTES_OFFSET + 1],
            buffer[LUKS_KEY_BYTES_OFFSET + 2],
            buffer[LUKS_KEY_BYTES_OFFSET + 3],
        ]);

        // UUID (36 bytes, null-padded, at offset 168)
        let uuid_end = (LUKS_UUID_OFFSET + 36).min(LUKS_UUID_OFFSET + 37);
        let uuid_src = &buffer[LUKS_UUID_OFFSET..uuid_end];
        let copy_len = uuid_src.len().min(luks_info.uuid.len());
        luks_info.uuid[..copy_len].copy_from_slice(&uuid_src[..copy_len]);

        // Count active key slots
        let mut active_slots = 0u32;
        for i in 0..LUKS_NUM_KEY_SLOTS {
            let slot_offset = LUKS_KEY_SLOT_BASE + i * LUKS_KEY_SLOT_SIZE;
            if slot_offset + 4 > buffer.len() {
                break;
            }
            let state = u32::from_be_bytes([
                buffer[slot_offset],
                buffer[slot_offset + 1],
                buffer[slot_offset + 2],
                buffer[slot_offset + 3],
            ]);
            if state == LUKS_KEY_SLOT_ACTIVE {
                active_slots += 1;
            }
        }
        luks_info.active_key_slots = active_slots;
    } else if version == 2 && buffer.len() >= LUKS2_UUID_OFFSET + 36 {
        // LUKS v2: parse binary header fields and JSON metadata area

        // UUID (40 bytes, null-terminated, at offset 168 in LUKS v2)
        let uuid_src = &buffer[LUKS2_UUID_OFFSET..LUKS2_UUID_OFFSET + 36];
        let copy_len = uuid_src.len().min(luks_info.uuid.len());
        luks_info.uuid[..copy_len].copy_from_slice(&uuid_src[..copy_len]);

        // Read the JSON metadata area. The JSON starts at offset 4096
        // (right after the 4096-byte binary header).
        //
        // If the input sector size is >= 4096 + minimum JSON size, the
        // JSON is already in `buffer` (which is MAX_SECTOR_SIZE = 64 KiB).
        // Otherwise, read additional sectors into scratch memory.
        if input_sector_size > LUKS2_BINARY_HEADER_SIZE && buffer.len() > LUKS2_BINARY_HEADER_SIZE {
            // JSON is in the already-read first sector
            let json_data = &buffer[LUKS2_BINARY_HEADER_SIZE..];
            let json_len = json_data
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(json_data.len());
            if json_len > 0 {
                parse_luks2_json(&json_data[..json_len], luks_info, call_table);
            }
        } else if input_sector_size <= LUKS2_BINARY_HEADER_SIZE {
            // Need to read sectors containing the JSON area
            let json_buf =
                core::slice::from_raw_parts_mut(SCRATCH_MEM_BASE as *mut u8, LUKS2_JSON_SCAN_SIZE);

            let json_start_sector = LUKS2_BINARY_HEADER_SIZE / input_sector_size;
            let sectors_to_read = LUKS2_JSON_SCAN_SIZE / input_sector_size;
            let mut json_bytes_read = 0usize;
            for i in 0..sectors_to_read {
                let sector = (json_start_sector + i) as u64;
                let offset = i * input_sector_size;
                if !(call_table.read_input_sector)(
                    0,
                    sector,
                    json_buf[offset..].as_mut_ptr(),
                    input_sector_size,
                ) {
                    break;
                }
                json_bytes_read = offset + input_sector_size;
            }

            if json_bytes_read > 0 {
                let json_data = &json_buf[..json_bytes_read];
                let json_len = json_data
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(json_data.len());
                if json_len > 0 {
                    parse_luks2_json(&json_data[..json_len], luks_info, call_table);
                }
            }
        }
    }
}

/// Parse LUKS2 JSON metadata to extract cipher, mode, and hash.
///
/// LUKS2 stores its metadata as JSON. We scan for specific patterns
/// rather than fully parsing JSON, since we're in a no_std environment.
///
/// Key patterns we look for:
/// - `"encryption":"aes-xts-plain64"` (in segments section) → cipher + mode
/// - `"hash":"sha256"` (in digests or AF section) → hash algorithm
/// - `"key_size":64` (in keyslots area section) → master key length
/// - `"offset":"..."` (in segments section) → payload offset
unsafe fn parse_luks2_json(json: &[u8], luks_info: &mut LuksInfo, call_table: &CallTable) {
    (call_table.verbose_print)(b"luks2: parsing JSON metadata\n\0".as_ptr());

    // Extract encryption string from segments section.
    // Look for "segments" first, then "encryption" within it.
    if let Some(seg_pos) = find_pattern(json, b"\"segments\"") {
        if let Some(enc) = extract_json_string(&json[seg_pos..], b"\"encryption\"") {
            // Split "aes-xts-plain64" into cipher="aes" and mode="xts-plain64"
            if let Some(dash_pos) = enc.iter().position(|&b| b == b'-') {
                let cipher = &enc[..dash_pos];
                let mode = &enc[dash_pos + 1..];
                copy_null_padded(cipher, &mut luks_info.cipher);
                copy_null_padded(mode, &mut luks_info.cipher_mode);
            } else {
                copy_null_padded(enc, &mut luks_info.cipher);
            }
        }

        // Extract payload offset from segments: "offset":"16777216"
        if let Some(off_str) = extract_json_string(&json[seg_pos..], b"\"offset\"") {
            let offset_bytes = parse_ascii_u64(off_str);
            if offset_bytes > 0 {
                // Convert bytes to 512-byte sectors for consistency with LUKS1
                luks_info.payload_offset = (offset_bytes / 512) as u32;
            }
        }
    }

    // Extract hash from digests section
    if let Some(dig_pos) = find_pattern(json, b"\"digests\"") {
        if let Some(hash) = extract_json_string(&json[dig_pos..], b"\"hash\"") {
            copy_null_padded(hash, &mut luks_info.hash);
        }
    }

    // Extract key_size from keyslots area section
    if let Some(ks_pos) = find_pattern(json, b"\"keyslots\"") {
        if let Some(ks_val) = extract_json_number(&json[ks_pos..], b"\"key_size\"") {
            luks_info.master_key_length = ks_val as u32;
        }

        // Count active key slots by counting "kdf" entries in keyslots.
        // Each active keyslot has exactly one "kdf" sub-object.
        let ks_end = find_pattern(&json[ks_pos..], b"\"segments\"")
            .map(|p| ks_pos + p)
            .unwrap_or(json.len());
        let ks_section = &json[ks_pos..ks_end];
        let mut active = 0u32;
        let mut search_from = 0;
        while let Some(pos) = find_pattern(&ks_section[search_from..], b"\"kdf\"") {
            active += 1;
            search_from += pos + 5;
            if search_from >= ks_section.len() {
                break;
            }
        }
        luks_info.active_key_slots = active;
    }
}

/// Find a byte pattern in a slice, returning the position of the match start.
fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.len() > data.len() {
        return None;
    }
    for i in 0..=data.len() - pattern.len() {
        if data[i..i + pattern.len()] == *pattern {
            return Some(i);
        }
    }
    None
}

/// Extract a JSON string value following a key pattern.
///
/// Looks for `key:"value"` or `key: "value"` and returns the value bytes.
/// The search is limited to the next 256 bytes after the key.
fn extract_json_string<'a>(data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let key_pos = find_pattern(data, key)?;
    let after_key = key_pos + key.len();
    let search_end = (after_key + 256).min(data.len());
    let rest = &data[after_key..search_end];

    // Find the colon, then the opening quote
    let colon_pos = rest.iter().position(|&b| b == b':')?;
    let after_colon = &rest[colon_pos + 1..];
    let quote_start = after_colon.iter().position(|&b| b == b'"')?;
    let value_start = quote_start + 1;
    let value_bytes = &after_colon[value_start..];
    let quote_end = value_bytes.iter().position(|&b| b == b'"')?;

    Some(&value_bytes[..quote_end])
}

/// Extract a JSON numeric value following a key pattern.
///
/// Looks for `key:123` or `key: 123` and returns the parsed number.
fn extract_json_number(data: &[u8], key: &[u8]) -> Option<u64> {
    let key_pos = find_pattern(data, key)?;
    let after_key = key_pos + key.len();
    let search_end = (after_key + 64).min(data.len());
    let rest = &data[after_key..search_end];

    // Find the colon, then the first digit
    let colon_pos = rest.iter().position(|&b| b == b':')?;
    let after_colon = &rest[colon_pos + 1..];
    let digit_start = after_colon.iter().position(|&b| b.is_ascii_digit())?;
    let digits = &after_colon[digit_start..];
    let digit_end = digits
        .iter()
        .position(|&b| !b.is_ascii_digit())
        .unwrap_or(digits.len());

    Some(parse_ascii_u64(&digits[..digit_end]))
}

/// Parse an ASCII decimal number from a byte slice.
fn parse_ascii_u64(data: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for &b in data {
        if b.is_ascii_digit() {
            result = result.saturating_mul(10).saturating_add((b - b'0') as u64);
        }
    }
    result
}

/// Copy a null-padded string from source to destination buffer.
/// Ensures the destination is null-terminated.
fn copy_null_padded(src: &[u8], dst: &mut [u8]) {
    let end = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    let copy_len = end.min(dst.len() - 1);
    dst[..copy_len].copy_from_slice(&src[..copy_len]);
    dst[copy_len] = 0;
}

/// LUKS v1 key slot parameters extracted from the header.
struct LuksKeySlot {
    iterations: u32,
    salt: [u8; 32],
    key_material_offset: u32, // in 512-byte sectors
    stripes: u32,
}

/// LUKS v2 key slot parameters extracted from JSON metadata.
struct Luks2KeySlot {
    // KDF parameters (Argon2id)
    kdf_time: u32,       // iterations (time cost)
    kdf_memory: u32,     // memory in KiB
    kdf_cpus: u32,       // parallelism
    kdf_salt: [u8; 32],  // decoded from base64
    kdf_salt_len: usize, // actual salt length

    // Key material area
    area_offset: u64, // byte offset of key material
    area_size: u64,   // byte size of key material

    // AF splitter
    af_stripes: u32,      // typically 4000
    af_hash_sha256: bool, // true=sha256, false=sha1

    // Key size
    key_size: u32, // 32 or 64 bytes
}

/// LUKS v2 digest parameters extracted from JSON metadata.
struct Luks2Digest {
    digest_type_pbkdf2: bool, // true = pbkdf2 verification
    hash_sha256: bool,        // true=sha256
    iterations: u32,
    salt: [u8; 32],
    salt_len: usize,
    digest: [u8; 32], // expected digest value
    digest_len: usize,
}

/// Decode standard base64 (with + / = padding) into output buffer.
/// Returns the number of bytes written, or 0 on error.
fn base64_decode(input: &[u8], output: &mut [u8]) -> usize {
    #[inline]
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut out_pos = 0;
    let mut i = 0;
    // Strip trailing padding
    let end = input
        .iter()
        .rposition(|&b| b != b'=')
        .map(|p| p + 1)
        .unwrap_or(0);

    while i + 1 < end {
        let n = match (i + 1..end.min(i + 4)).count() + 1 {
            c if c >= 2 => c,
            _ => break,
        };

        let a = match decode_char(input[i]) {
            Some(v) => v as u32,
            None => return out_pos,
        };
        let b = match decode_char(input[i + 1]) {
            Some(v) => v as u32,
            None => return out_pos,
        };

        if out_pos >= output.len() {
            return out_pos;
        }
        output[out_pos] = ((a << 2) | (b >> 4)) as u8;
        out_pos += 1;

        if n > 2 && i + 2 < end {
            let c = match decode_char(input[i + 2]) {
                Some(v) => v as u32,
                None => return out_pos,
            };
            if out_pos >= output.len() {
                return out_pos;
            }
            output[out_pos] = ((b << 4) | (c >> 2)) as u8;
            out_pos += 1;

            if n > 3 && i + 3 < end {
                let d = match decode_char(input[i + 3]) {
                    Some(v) => v as u32,
                    None => return out_pos,
                };
                if out_pos >= output.len() {
                    return out_pos;
                }
                output[out_pos] = ((c << 6) | d) as u8;
                out_pos += 1;
            }
        }

        i += 4;
    }
    out_pos
}

/// Extract full LUKS v2 keyslot parameters from JSON metadata.
///
/// Parses KDF (argon2id), AF (stripes, hash), area (offset, size),
/// and key_size from the first keyslot in the JSON.
fn parse_luks2_keyslot(json: &[u8]) -> Option<Luks2KeySlot> {
    let ks_pos = find_pattern(json, b"\"keyslots\"")?;
    let ks_data = &json[ks_pos..];

    // Find keyslot section boundary (ends at "tokens" or "segments")
    let ks_end = find_pattern(ks_data, b"\"tokens\"")
        .or_else(|| find_pattern(ks_data, b"\"segments\""))
        .unwrap_or(ks_data.len());
    let ks_section = &ks_data[..ks_end];

    // Check KDF type is argon2id
    let kdf_pos = find_pattern(ks_section, b"\"kdf\"")?;
    let kdf_data = &ks_section[kdf_pos..];
    let kdf_type = extract_json_string(kdf_data, b"\"type\"")?;
    if kdf_type != b"argon2id" {
        return None;
    }

    let kdf_time = extract_json_number(kdf_data, b"\"time\"")? as u32;
    let kdf_memory = extract_json_number(kdf_data, b"\"memory\"")? as u32;
    let kdf_cpus = extract_json_number(kdf_data, b"\"cpus\"")? as u32;

    // Decode base64 salt
    let salt_b64 = extract_json_string(kdf_data, b"\"salt\"")?;
    let mut kdf_salt = [0u8; 32];
    let kdf_salt_len = base64_decode(salt_b64, &mut kdf_salt);
    if kdf_salt_len == 0 {
        return None;
    }

    // Key size
    let key_size = extract_json_number(ks_section, b"\"key_size\"")? as u32;

    // AF parameters
    let af_pos = find_pattern(ks_section, b"\"af\"")?;
    let af_data = &ks_section[af_pos..];
    let af_stripes = extract_json_number(af_data, b"\"stripes\"").unwrap_or(4000) as u32;
    let af_hash = extract_json_string(af_data, b"\"hash\"").unwrap_or(b"sha256");
    let af_hash_sha256 = af_hash == b"sha256";

    // Area parameters
    let area_pos = find_pattern(ks_section, b"\"area\"")?;
    let area_data = &ks_section[area_pos..];
    let area_offset_str = extract_json_string(area_data, b"\"offset\"")?;
    let area_offset = parse_ascii_u64(area_offset_str);
    let area_size_str = extract_json_string(area_data, b"\"size\"")?;
    let area_size = parse_ascii_u64(area_size_str);

    Some(Luks2KeySlot {
        kdf_time,
        kdf_memory,
        kdf_cpus,
        kdf_salt,
        kdf_salt_len,
        area_offset,
        area_size,
        af_stripes,
        af_hash_sha256,
        key_size,
    })
}

/// Extract LUKS v2 digest parameters from JSON metadata.
fn parse_luks2_digest(json: &[u8]) -> Option<Luks2Digest> {
    let dig_pos = find_pattern(json, b"\"digests\"")?;
    let dig_data = &json[dig_pos..];

    // Find digest section boundary (ends at "config" or end)
    let dig_end = find_pattern(dig_data, b"\"config\"").unwrap_or(dig_data.len());
    let dig_section = &dig_data[..dig_end];

    let dig_type = extract_json_string(dig_section, b"\"type\"")?;
    let digest_type_pbkdf2 = dig_type == b"pbkdf2";

    let hash = extract_json_string(dig_section, b"\"hash\"").unwrap_or(b"sha256");
    let hash_sha256 = hash == b"sha256";

    let iterations = extract_json_number(dig_section, b"\"iterations\"").unwrap_or(0) as u32;

    // Decode base64 salt
    let salt_b64 = extract_json_string(dig_section, b"\"salt\"")?;
    let mut salt = [0u8; 32];
    let salt_len = base64_decode(salt_b64, &mut salt);

    // Decode base64 digest
    let digest_b64 = extract_json_string(dig_section, b"\"digest\"")?;
    let mut digest = [0u8; 32];
    let digest_len = base64_decode(digest_b64, &mut digest);

    Some(Luks2Digest {
        digest_type_pbkdf2,
        hash_sha256,
        iterations,
        salt,
        salt_len,
        digest,
        digest_len,
    })
}

/// Attempt LUKS1 decryption and return the detected inner format.
///
/// This implements the full LUKS1 decryption pipeline:
/// 1. Find first active key slot
/// 2. PBKDF2 key derivation with slot parameters
/// 3. Read encrypted key material from disk
/// 4. AES-XTS decrypt key material
/// 5. AFsplitter merge to recover candidate master key
/// 6. Verify master key against mk_digest
/// 7. Decrypt first payload sector with verified master key
/// 8. Detect inner format from decrypted data
///
/// Returns (inner_format, inner_virtual_size) or None if decryption fails.
unsafe fn try_luks1_decrypt(
    header: &[u8],
    config: &InfoConfig,
    call_table: &CallTable,
    input_sector_size: usize,
) -> Option<(ImageFormat, u64)> {
    if !config.has_passphrase() {
        return None;
    }

    if header.len() < LUKS_V1_HEADER_SIZE {
        return None;
    }

    // Verify this is LUKS v1
    let version =
        u16::from_be_bytes([header[LUKS_VERSION_OFFSET], header[LUKS_VERSION_OFFSET + 1]]);
    if version != 1 {
        (call_table.debug_print)(b"luks: not v1, skipping decrypt\n\0".as_ptr());
        return None;
    }

    // Check cipher is aes and mode is xts-plain64
    let cipher = cstr_from_header(header, LUKS_CIPHER_NAME_OFFSET, 32);
    let mode = cstr_from_header(header, LUKS_CIPHER_MODE_OFFSET, 32);
    let hash = cstr_from_header(header, LUKS_HASH_SPEC_OFFSET, 32);

    if cipher != "aes" {
        (call_table.debug_print)(b"luks: unsupported cipher\n\0".as_ptr());
        return None;
    }
    if mode != "xts-plain64" {
        (call_table.debug_print)(b"luks: unsupported mode\n\0".as_ptr());
        return None;
    }

    let key_bytes = u32::from_be_bytes([
        header[LUKS_KEY_BYTES_OFFSET],
        header[LUKS_KEY_BYTES_OFFSET + 1],
        header[LUKS_KEY_BYTES_OFFSET + 2],
        header[LUKS_KEY_BYTES_OFFSET + 3],
    ]) as usize;

    let payload_offset = u32::from_be_bytes([
        header[LUKS_PAYLOAD_OFFSET_OFFSET],
        header[LUKS_PAYLOAD_OFFSET_OFFSET + 1],
        header[LUKS_PAYLOAD_OFFSET_OFFSET + 2],
        header[LUKS_PAYLOAD_OFFSET_OFFSET + 3],
    ]);

    // Validate key_bytes: AES-XTS uses 32 (AES-128) or 64 (AES-256) byte keys
    if key_bytes != 32 && key_bytes != 64 {
        (call_table.debug_print)(b"luks: unsupported key size\n\0".as_ptr());
        return None;
    }

    // Master key digest fields (for verification)
    let mut mk_digest = [0u8; 20];
    mk_digest.copy_from_slice(&header[LUKS_MK_DIGEST_OFFSET..LUKS_MK_DIGEST_OFFSET + 20]);

    let mut mk_digest_salt = [0u8; 32];
    mk_digest_salt
        .copy_from_slice(&header[LUKS_MK_DIGEST_SALT_OFFSET..LUKS_MK_DIGEST_SALT_OFFSET + 32]);

    let mk_digest_iterations = u32::from_be_bytes([
        header[LUKS_MK_DIGEST_ITER_OFFSET],
        header[LUKS_MK_DIGEST_ITER_OFFSET + 1],
        header[LUKS_MK_DIGEST_ITER_OFFSET + 2],
        header[LUKS_MK_DIGEST_ITER_OFFSET + 3],
    ]);

    // Find first active key slot
    let mut slot: Option<LuksKeySlot> = None;
    for i in 0..LUKS_NUM_KEY_SLOTS {
        let slot_base = LUKS_KEY_SLOT_BASE + i * LUKS_KEY_SLOT_SIZE;
        let state = u32::from_be_bytes([
            header[slot_base],
            header[slot_base + 1],
            header[slot_base + 2],
            header[slot_base + 3],
        ]);
        if state == LUKS_KEY_SLOT_ACTIVE {
            let iterations = u32::from_be_bytes([
                header[slot_base + LUKS_SLOT_ITERATIONS_OFFSET],
                header[slot_base + LUKS_SLOT_ITERATIONS_OFFSET + 1],
                header[slot_base + LUKS_SLOT_ITERATIONS_OFFSET + 2],
                header[slot_base + LUKS_SLOT_ITERATIONS_OFFSET + 3],
            ]);
            let mut salt = [0u8; 32];
            salt.copy_from_slice(
                &header[slot_base + LUKS_SLOT_SALT_OFFSET..slot_base + LUKS_SLOT_SALT_OFFSET + 32],
            );
            let km_offset = u32::from_be_bytes([
                header[slot_base + LUKS_SLOT_KEY_MATERIAL_OFFSET],
                header[slot_base + LUKS_SLOT_KEY_MATERIAL_OFFSET + 1],
                header[slot_base + LUKS_SLOT_KEY_MATERIAL_OFFSET + 2],
                header[slot_base + LUKS_SLOT_KEY_MATERIAL_OFFSET + 3],
            ]);
            let stripes = u32::from_be_bytes([
                header[slot_base + LUKS_SLOT_STRIPES_OFFSET],
                header[slot_base + LUKS_SLOT_STRIPES_OFFSET + 1],
                header[slot_base + LUKS_SLOT_STRIPES_OFFSET + 2],
                header[slot_base + LUKS_SLOT_STRIPES_OFFSET + 3],
            ]);
            slot = Some(LuksKeySlot {
                iterations,
                salt,
                key_material_offset: km_offset,
                stripes,
            });
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => {
            (call_table.debug_print)(b"luks: no active key slot\n\0".as_ptr());
            return None;
        }
    };

    (call_table.verbose_print)(b"luks: starting PBKDF2 key derivation\n\0".as_ptr());

    // Step 1: PBKDF2 to derive the split key from the passphrase
    let passphrase = config.passphrase_bytes();
    let mut derived_key = [0u8; 64]; // Max key_bytes is 64
    let dk = &mut derived_key[..key_bytes];

    if hash == "sha256" {
        pbkdf2::<Hmac<Sha256>>(passphrase, &slot.salt, slot.iterations, dk).unwrap_or_else(|_| {});
    } else if hash == "sha1" {
        pbkdf2::<Hmac<Sha1>>(passphrase, &slot.salt, slot.iterations, dk).unwrap_or_else(|_| {});
    } else {
        (call_table.debug_print)(b"luks: unsupported hash\n\0".as_ptr());
        return None;
    }

    (call_table.verbose_print)(b"luks: PBKDF2 complete, reading key material\n\0".as_ptr());

    // Step 2: Read encrypted key material from disk
    // Key material size = key_bytes * stripes (typically 64 * 4000 = 256000 bytes)
    let km_total_bytes = match (key_bytes).checked_mul(slot.stripes as usize) {
        Some(n) => n,
        None => {
            (call_table.debug_print)(b"luks: key material size overflow\n\0".as_ptr());
            return None;
        }
    };
    if km_total_bytes > SCRATCH_MEM_SIZE {
        (call_table.debug_print)(b"luks: key material exceeds scratch memory\n\0".as_ptr());
        return None;
    }

    // Use scratch memory for key material I/O buffer
    // Scratch memory starts at SCRATCH_MEM_BASE (0x300000)
    let km_buf = core::slice::from_raw_parts_mut(SCRATCH_MEM_BASE as *mut u8, km_total_bytes);

    // Read key material from disk in sector-sized chunks
    // Key material offset is in 512-byte sectors (LUKS v1 always uses 512-byte sectors)
    let km_byte_offset = slot.key_material_offset as u64 * 512;

    // Validate key material region fits within device capacity
    let cap = (call_table.get_input_capacity)(0) * input_sector_size as u64;
    if km_byte_offset + km_total_bytes as u64 > cap {
        (call_table.debug_print)(b"luks: key material offset exceeds device capacity\n\0".as_ptr());
        return None;
    }

    let km_start_sector = km_byte_offset / input_sector_size as u64;
    let km_end_byte = km_byte_offset + km_total_bytes as u64;
    let km_end_sector = (km_end_byte + input_sector_size as u64 - 1) / input_sector_size as u64;
    let km_sectors_needed = (km_end_sector - km_start_sector) as usize;

    let mut sector_buf = [0u8; MAX_SECTOR_SIZE];
    let mut km_pos = 0usize;

    for s in 0..km_sectors_needed {
        let sector_idx = km_start_sector + s as u64;
        if !(call_table.read_input_sector)(
            0,
            sector_idx,
            sector_buf.as_mut_ptr(),
            input_sector_size,
        ) {
            (call_table.debug_print)(b"luks: failed to read key material\n\0".as_ptr());
            return None;
        }

        let offset_in_sector = if s == 0 {
            (km_byte_offset % input_sector_size as u64) as usize
        } else {
            0
        };
        let available = input_sector_size - offset_in_sector;
        let to_copy = available.min(km_total_bytes - km_pos);
        km_buf[km_pos..km_pos + to_copy]
            .copy_from_slice(&sector_buf[offset_in_sector..offset_in_sector + to_copy]);
        km_pos += to_copy;

        if km_pos >= km_total_bytes {
            break;
        }
    }

    (call_table.verbose_print)(b"luks: decrypting key material with AES-XTS\n\0".as_ptr());

    // Step 3: AES-XTS decrypt the key material
    // LUKS XTS uses the derived key split in half: first half = data key, second half = tweak key
    // The sector size for XTS is 512 bytes (LUKS1 always uses 512-byte crypto sectors)
    let half = key_bytes / 2;
    if half == 16 {
        let cipher_1 = Aes128::new(GenericArray::from_slice(&dk[..16]));
        let cipher_2 = Aes128::new(GenericArray::from_slice(&dk[16..32]));
        let xts = xts_mode::Xts128::new(cipher_1, cipher_2);
        xts.decrypt_area(km_buf, 512, 0, xts_mode::get_tweak_default);
    } else if half == 32 {
        let cipher_1 = Aes256::new(GenericArray::from_slice(&dk[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&dk[32..64]));
        let xts = xts_mode::Xts128::new(cipher_1, cipher_2);
        xts.decrypt_area(km_buf, 512, 0, xts_mode::get_tweak_default);
    } else {
        (call_table.debug_print)(b"luks: unsupported key half size\n\0".as_ptr());
        return None;
    }

    (call_table.verbose_print)(b"luks: AFsplitter merge\n\0".as_ptr());

    // Step 4: AFsplitter merge to recover candidate master key
    // d[0] = stripe[0]
    // for i in 1..stripes-1: d[i] = hash(d[i-1]) XOR stripe[i]
    // master_key = d[stripes-1] XOR stripe[stripes-1]
    let stripes = slot.stripes as usize;
    let mut candidate = [0u8; 64]; // Max key_bytes
    let mk = &mut candidate[..key_bytes];

    // First stripe: copy directly
    mk.copy_from_slice(&km_buf[..key_bytes]);

    // Process remaining stripes
    for i in 1..stripes {
        // Hash the accumulator (diffuse function)
        af_diffuse(mk, key_bytes);

        // XOR with next stripe
        let stripe_offset = i * key_bytes;
        for j in 0..key_bytes {
            mk[j] ^= km_buf[stripe_offset + j];
        }
    }

    (call_table.verbose_print)(b"luks: verifying master key\n\0".as_ptr());

    // Step 5: Verify the master key against mk_digest
    // PBKDF2(candidate_key, mk_digest_salt, mk_digest_iterations) -> 20-byte digest
    let mut verify_digest = [0u8; 20];
    if hash == "sha256" {
        pbkdf2::<Hmac<Sha256>>(
            mk,
            &mk_digest_salt,
            mk_digest_iterations,
            &mut verify_digest,
        )
        .unwrap_or_else(|_| {});
    } else if hash == "sha1" {
        pbkdf2::<Hmac<Sha1>>(
            mk,
            &mk_digest_salt,
            mk_digest_iterations,
            &mut verify_digest,
        )
        .unwrap_or_else(|_| {});
    }

    if verify_digest != mk_digest {
        (call_table.debug_print)(b"luks: master key verification failed\n\0".as_ptr());
        return None;
    }

    (call_table.verbose_print)(b"luks: master key verified, decrypting payload\n\0".as_ptr());

    // Step 6: Decrypt first payload sector with the verified master key
    // Read the first sector at payload_offset (in 512-byte sectors)
    let payload_byte_offset = payload_offset as u64 * 512;
    let payload_sector = payload_byte_offset / input_sector_size as u64;

    let mut payload_buf = [0u8; MAX_SECTOR_SIZE];
    if !(call_table.read_input_sector)(
        0,
        payload_sector,
        payload_buf.as_mut_ptr(),
        input_sector_size,
    ) {
        (call_table.debug_print)(b"luks: failed to read payload sector\n\0".as_ptr());
        return None;
    }

    // Decrypt using the master key with AES-XTS
    // For payload decryption, the sector index is 0 (first logical sector)
    // and sector size is 512 bytes
    let payload_offset_in_sector = (payload_byte_offset % input_sector_size as u64) as usize;
    let decrypt_buf = &mut payload_buf[payload_offset_in_sector..payload_offset_in_sector + 512];

    if half == 16 {
        let cipher_1 = Aes128::new(GenericArray::from_slice(&mk[..16]));
        let cipher_2 = Aes128::new(GenericArray::from_slice(&mk[16..32]));
        let xts = xts_mode::Xts128::new(cipher_1, cipher_2);
        xts.decrypt_area(decrypt_buf, 512, 0, xts_mode::get_tweak_default);
    } else if half == 32 {
        let cipher_1 = Aes256::new(GenericArray::from_slice(&mk[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&mk[32..64]));
        let xts = xts_mode::Xts128::new(cipher_1, cipher_2);
        xts.decrypt_area(decrypt_buf, 512, 0, xts_mode::get_tweak_default);
    }

    (call_table.verbose_print)(b"luks: detecting inner format\n\0".as_ptr());

    // Step 7: Detect inner format from decrypted data
    // Use extra_detail=true so LUKS-within-LUKS would be detected
    let inner_format = detect_format_from_header(decrypt_buf, 512, true);

    // Extract inner virtual size from the decrypted header where possible
    let inner_virtual_size = match inner_format {
        ImageFormat::Qcow2 => {
            // QCOW2: virtual_size at offset 24 (big-endian u64)
            if decrypt_buf.len() >= 32 {
                u64::from_be_bytes([
                    decrypt_buf[24],
                    decrypt_buf[25],
                    decrypt_buf[26],
                    decrypt_buf[27],
                    decrypt_buf[28],
                    decrypt_buf[29],
                    decrypt_buf[30],
                    decrypt_buf[31],
                ])
            } else {
                0
            }
        }
        ImageFormat::Raw => {
            // Raw: inner size = device bytes - payload offset bytes
            let cap_sectors = (call_table.get_input_capacity)(0);
            let cap_bytes = cap_sectors * input_sector_size as u64;
            let payload_bytes = payload_offset as u64 * 512;
            if cap_bytes > payload_bytes {
                cap_bytes - payload_bytes
            } else {
                0
            }
        }
        _ => 0,
    };

    Some((inner_format, inner_virtual_size))
}

/// AFsplitter diffuse function: hash each key_bytes-length block.
///
/// LUKS1 AFsplitter uses SHA-1 for diffusion (per the LUKS1 spec),
/// regardless of the hash spec used for PBKDF2. This processes the
/// data in SHA-1-digest-sized (20-byte) chunks.
fn af_diffuse(data: &mut [u8], key_bytes: usize) {
    let digest_size = 20; // SHA-1 output size
    let full_blocks = key_bytes / digest_size;
    let remainder = key_bytes % digest_size;

    // Process full blocks
    for i in 0..full_blocks {
        let offset = i * digest_size;
        let block_num = (i as u32).to_be_bytes();

        let mut hasher = Sha1::new();
        hasher.update(&block_num);
        hasher.update(&data[offset..offset + digest_size]);
        let hash_result = hasher.finalize();
        data[offset..offset + digest_size].copy_from_slice(&hash_result);
    }

    // Process remainder
    if remainder > 0 {
        let offset = full_blocks * digest_size;
        let block_num = (full_blocks as u32).to_be_bytes();

        let mut hasher = Sha1::new();
        hasher.update(&block_num);
        hasher.update(&data[offset..offset + remainder]);
        let hash_result = hasher.finalize();
        data[offset..offset + remainder].copy_from_slice(&hash_result[..remainder]);
    }
}

/// AFsplitter diffuse function using SHA-256 (for LUKS v2).
///
/// LUKS v2 AF typically uses SHA-256 for diffusion, with 32-byte
/// digest chunks instead of SHA-1's 20-byte chunks.
fn af_diffuse_sha256(data: &mut [u8], key_bytes: usize) {
    let digest_size = 32; // SHA-256 output size
    let full_blocks = key_bytes / digest_size;
    let remainder = key_bytes % digest_size;

    for i in 0..full_blocks {
        let offset = i * digest_size;
        let block_num = (i as u32).to_be_bytes();

        let mut hasher = Sha256::new();
        hasher.update(&block_num);
        hasher.update(&data[offset..offset + digest_size]);
        let hash_result = hasher.finalize();
        data[offset..offset + digest_size].copy_from_slice(&hash_result);
    }

    if remainder > 0 {
        let offset = full_blocks * digest_size;
        let block_num = (full_blocks as u32).to_be_bytes();

        let mut hasher = Sha256::new();
        hasher.update(&block_num);
        hasher.update(&data[offset..offset + remainder]);
        let hash_result = hasher.finalize();
        data[offset..offset + remainder].copy_from_slice(&hash_result[..remainder]);
    }
}

/// Attempt LUKS2 decryption with Argon2id KDF.
///
/// Pipeline:
/// 1. Parse keyslot and digest parameters from JSON
/// 2. Argon2id key derivation (requires extra guest memory)
/// 3. Read encrypted key material from disk
/// 4. AES-XTS decrypt key material
/// 5. AFsplitter merge (SHA-256) to recover candidate master key
/// 6. Verify master key via PBKDF2 digest
/// 7. Decrypt first payload sector with verified master key
/// 8. Detect inner format from decrypted data
///
/// Returns (inner_format, inner_virtual_size) or None if decryption fails.
unsafe fn try_luks2_decrypt(
    buffer: &[u8],
    luks_info: &LuksInfo,
    config: &InfoConfig,
    call_table: &CallTable,
    input_sector_size: usize,
) -> Option<(ImageFormat, u64)> {
    if !config.has_passphrase() {
        return None;
    }

    // Check that Argon2 memory is available
    if config.argon2_mem_size == 0 {
        (call_table.verbose_print)(
            b"luks2: skipping decryption (no --max-guest-memory)\n\0".as_ptr(),
        );
        return None;
    }

    // Get JSON data — either from the buffer (large sectors) or read from disk
    let json: &[u8] = if input_sector_size > LUKS2_BINARY_HEADER_SIZE
        && buffer.len() > LUKS2_BINARY_HEADER_SIZE
    {
        let json_data = &buffer[LUKS2_BINARY_HEADER_SIZE..];
        let json_len = json_data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(json_data.len());
        &json_data[..json_len]
    } else {
        // Read JSON from disk into scratch memory (will be reused later for key material)
        let json_buf =
            core::slice::from_raw_parts_mut(SCRATCH_MEM_BASE as *mut u8, LUKS2_JSON_SCAN_SIZE);
        let json_start_sector = LUKS2_BINARY_HEADER_SIZE / input_sector_size;
        let sectors_to_read = LUKS2_JSON_SCAN_SIZE / input_sector_size;
        let mut json_bytes_read = 0usize;
        for i in 0..sectors_to_read {
            let sector = (json_start_sector + i) as u64;
            let offset = i * input_sector_size;
            if !(call_table.read_input_sector)(
                0,
                sector,
                json_buf[offset..].as_mut_ptr(),
                input_sector_size,
            ) {
                break;
            }
            json_bytes_read = offset + input_sector_size;
        }
        if json_bytes_read == 0 {
            (call_table.debug_print)(b"luks2: failed to read JSON area\n\0".as_ptr());
            return None;
        }
        let json_len = json_buf[..json_bytes_read]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(json_bytes_read);
        &json_buf[..json_len]
    };

    // Parse keyslot parameters from JSON
    let slot = match parse_luks2_keyslot(json) {
        Some(s) => s,
        None => {
            (call_table.debug_print)(b"luks2: failed to parse keyslot JSON\n\0".as_ptr());
            return None;
        }
    };

    // Parse digest parameters
    let digest_params = match parse_luks2_digest(json) {
        Some(d) => d,
        None => {
            (call_table.debug_print)(b"luks2: failed to parse digest JSON\n\0".as_ptr());
            return None;
        }
    };

    let payload_offset_sectors = luks_info.payload_offset;

    let key_bytes = slot.key_size as usize;
    if key_bytes != 32 && key_bytes != 64 {
        (call_table.debug_print)(b"luks2: unsupported key size\n\0".as_ptr());
        return None;
    }

    // Verify we have enough Argon2 memory
    let needed_kib = slot.kdf_memory as u64;
    let available_kib = config.argon2_mem_size / 1024;
    if needed_kib > available_kib {
        (call_table.debug_print)(b"luks2: insufficient Argon2 memory\n\0".as_ptr());
        return None;
    }

    (call_table.verbose_print)(b"luks2: starting Argon2id key derivation\n\0".as_ptr());

    // Step 1: Argon2id key derivation
    let passphrase = config.passphrase_bytes();
    let mut derived_key = [0u8; 64];
    let dk = &mut derived_key[..key_bytes];

    // Construct Argon2id parameters
    let params = match argon2::Params::new(slot.kdf_memory, slot.kdf_time, slot.kdf_cpus, None) {
        Ok(p) => p,
        Err(_) => {
            (call_table.debug_print)(b"luks2: invalid Argon2 params\n\0".as_ptr());
            return None;
        }
    };

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    // Construct memory blocks from ARGON2_MEM_BASE
    let num_blocks = (slot.kdf_memory as usize * 1024) / 1024; // memory in KiB = number of 1KiB blocks
    let memory_ptr = ARGON2_MEM_BASE as *mut argon2::Block;
    let memory_blocks = core::slice::from_raw_parts_mut(memory_ptr, num_blocks);

    // Zero the memory blocks before use
    for block in memory_blocks.iter_mut() {
        *block = argon2::Block::default();
    }

    if argon2
        .hash_password_into_with_memory(
            passphrase,
            &slot.kdf_salt[..slot.kdf_salt_len],
            dk,
            memory_blocks,
        )
        .is_err()
    {
        (call_table.debug_print)(b"luks2: Argon2id derivation failed\n\0".as_ptr());
        return None;
    }

    (call_table.verbose_print)(b"luks2: Argon2id complete, reading key material\n\0".as_ptr());

    // Step 2: Read encrypted key material from disk
    let km_total_bytes = (key_bytes as u64)
        .checked_mul(slot.af_stripes as u64)
        .unwrap_or(0) as usize;
    if km_total_bytes == 0 || km_total_bytes > SCRATCH_MEM_SIZE {
        (call_table.debug_print)(b"luks2: key material size invalid\n\0".as_ptr());
        return None;
    }

    let km_buf = core::slice::from_raw_parts_mut(SCRATCH_MEM_BASE as *mut u8, km_total_bytes);

    // Key material offset is in bytes for LUKS v2
    let km_byte_offset = slot.area_offset;

    let cap = (call_table.get_input_capacity)(0) * input_sector_size as u64;
    if km_byte_offset + km_total_bytes as u64 > cap {
        (call_table.debug_print)(
            b"luks2: key material offset exceeds device capacity\n\0".as_ptr(),
        );
        return None;
    }

    let km_start_sector = km_byte_offset / input_sector_size as u64;
    let km_end_byte = km_byte_offset + km_total_bytes as u64;
    let km_end_sector = (km_end_byte + input_sector_size as u64 - 1) / input_sector_size as u64;
    let km_sectors_needed = (km_end_sector - km_start_sector) as usize;

    let mut sector_buf = [0u8; MAX_SECTOR_SIZE];
    let mut km_pos = 0usize;

    for s in 0..km_sectors_needed {
        let sector_idx = km_start_sector + s as u64;
        if !(call_table.read_input_sector)(
            0,
            sector_idx,
            sector_buf.as_mut_ptr(),
            input_sector_size,
        ) {
            (call_table.debug_print)(b"luks2: failed to read key material\n\0".as_ptr());
            return None;
        }

        let offset_in_sector = if s == 0 {
            (km_byte_offset % input_sector_size as u64) as usize
        } else {
            0
        };
        let available = input_sector_size - offset_in_sector;
        let to_copy = available.min(km_total_bytes - km_pos);
        km_buf[km_pos..km_pos + to_copy]
            .copy_from_slice(&sector_buf[offset_in_sector..offset_in_sector + to_copy]);
        km_pos += to_copy;

        if km_pos >= km_total_bytes {
            break;
        }
    }

    (call_table.verbose_print)(b"luks2: decrypting key material with AES-XTS\n\0".as_ptr());

    // Step 3: AES-XTS decrypt the key material
    let half = key_bytes / 2;
    if half == 16 {
        let cipher_1 = Aes128::new(GenericArray::from_slice(&dk[..16]));
        let cipher_2 = Aes128::new(GenericArray::from_slice(&dk[16..32]));
        let xts = xts_mode::Xts128::new(cipher_1, cipher_2);
        xts.decrypt_area(km_buf, 512, 0, xts_mode::get_tweak_default);
    } else if half == 32 {
        let cipher_1 = Aes256::new(GenericArray::from_slice(&dk[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&dk[32..64]));
        let xts = xts_mode::Xts128::new(cipher_1, cipher_2);
        xts.decrypt_area(km_buf, 512, 0, xts_mode::get_tweak_default);
    } else {
        (call_table.debug_print)(b"luks2: unsupported key half size\n\0".as_ptr());
        return None;
    }

    (call_table.verbose_print)(b"luks2: AFsplitter merge\n\0".as_ptr());

    // Step 4: AFsplitter merge
    let stripes = slot.af_stripes as usize;
    let mut candidate = [0u8; 64];
    let mk = &mut candidate[..key_bytes];

    mk.copy_from_slice(&km_buf[..key_bytes]);

    for i in 1..stripes {
        if slot.af_hash_sha256 {
            af_diffuse_sha256(mk, key_bytes);
        } else {
            af_diffuse(mk, key_bytes);
        }

        let stripe_offset = i * key_bytes;
        for j in 0..key_bytes {
            mk[j] ^= km_buf[stripe_offset + j];
        }
    }

    (call_table.verbose_print)(b"luks2: verifying master key\n\0".as_ptr());

    // Step 5: Verify master key against digest
    if digest_params.digest_type_pbkdf2 && digest_params.iterations > 0 {
        let mut verify_digest = [0u8; 32];
        let verify_len = digest_params.digest_len.min(32);

        if digest_params.hash_sha256 {
            pbkdf2::<Hmac<Sha256>>(
                mk,
                &digest_params.salt[..digest_params.salt_len],
                digest_params.iterations,
                &mut verify_digest[..verify_len],
            )
            .unwrap_or_else(|_| {});
        } else {
            // SHA-1 fallback
            let mut verify_20 = [0u8; 20];
            let vlen = verify_len.min(20);
            pbkdf2::<Hmac<Sha1>>(
                mk,
                &digest_params.salt[..digest_params.salt_len],
                digest_params.iterations,
                &mut verify_20[..vlen],
            )
            .unwrap_or_else(|_| {});
            verify_digest[..vlen].copy_from_slice(&verify_20[..vlen]);
        }

        if verify_digest[..digest_params.digest_len]
            != digest_params.digest[..digest_params.digest_len]
        {
            (call_table.debug_print)(b"luks2: master key verification failed\n\0".as_ptr());
            return None;
        }
    }

    (call_table.verbose_print)(b"luks2: master key verified, decrypting payload\n\0".as_ptr());

    // Step 6: Decrypt first payload sector
    // LUKS v2 payload_offset is in 512-byte sectors (already converted from JSON bytes)
    let payload_byte_offset = payload_offset_sectors as u64 * 512;
    let payload_sector = payload_byte_offset / input_sector_size as u64;

    let mut payload_buf = [0u8; MAX_SECTOR_SIZE];
    if !(call_table.read_input_sector)(
        0,
        payload_sector,
        payload_buf.as_mut_ptr(),
        input_sector_size,
    ) {
        (call_table.debug_print)(b"luks2: failed to read payload sector\n\0".as_ptr());
        return None;
    }

    // Decrypt using the master key with AES-XTS
    let payload_offset_in_sector = (payload_byte_offset % input_sector_size as u64) as usize;
    let decrypt_buf = &mut payload_buf[payload_offset_in_sector..payload_offset_in_sector + 512];

    if half == 16 {
        let cipher_1 = Aes128::new(GenericArray::from_slice(&mk[..16]));
        let cipher_2 = Aes128::new(GenericArray::from_slice(&mk[16..32]));
        let xts = xts_mode::Xts128::new(cipher_1, cipher_2);
        xts.decrypt_area(decrypt_buf, 512, 0, xts_mode::get_tweak_default);
    } else if half == 32 {
        let cipher_1 = Aes256::new(GenericArray::from_slice(&mk[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&mk[32..64]));
        let xts = xts_mode::Xts128::new(cipher_1, cipher_2);
        xts.decrypt_area(decrypt_buf, 512, 0, xts_mode::get_tweak_default);
    }

    (call_table.verbose_print)(b"luks2: detecting inner format\n\0".as_ptr());

    // Step 7: Detect inner format
    let inner_format = detect_format_from_header(decrypt_buf, 512, true);

    let inner_virtual_size = match inner_format {
        ImageFormat::Qcow2 => {
            if decrypt_buf.len() >= 32 {
                u64::from_be_bytes([
                    decrypt_buf[24],
                    decrypt_buf[25],
                    decrypt_buf[26],
                    decrypt_buf[27],
                    decrypt_buf[28],
                    decrypt_buf[29],
                    decrypt_buf[30],
                    decrypt_buf[31],
                ])
            } else {
                0
            }
        }
        ImageFormat::Raw => {
            let cap_sectors = (call_table.get_input_capacity)(0);
            let cap_bytes = cap_sectors * input_sector_size as u64;
            let payload_bytes = payload_offset_sectors as u64 * 512;
            if cap_bytes > payload_bytes {
                cap_bytes - payload_bytes
            } else {
                0
            }
        }
        _ => 0,
    };

    Some((inner_format, inner_virtual_size))
}

/// Extract a null-terminated string from a fixed-size header field.
fn cstr_from_header(header: &[u8], offset: usize, max_len: usize) -> &str {
    let field = &header[offset..offset + max_len];
    let end = field.iter().position(|&b| b == 0).unwrap_or(max_len);
    core::str::from_utf8(&field[..end]).unwrap_or("")
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
