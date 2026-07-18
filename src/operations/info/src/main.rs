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
        detect_dmg_koly_offset, detect_format_from_header, detect_iso_at_offset, detect_vhd_footer,
        dmg_sector_count, BOCHS_VERSION_2, BOCHS_VERSION_OFFSET, DMG_KOLY_MAGIC,
        DMG_KOLY_TRAILER_LEN, ISO_MAGIC_BYTE_OFFSET, PARALLELS_MAGIC_V1, VDI_SIGNATURE_OFFSET,
        VHD_COOKIE,
    },
    validate_call_table, CallTable, ImageFormat, InfoConfig, InfoResult, LuksInfo, Qcow2Info,
    VdiInfo, VmdkInfo, ARGON2_MEM_BASE, CALL_TABLE_ADDR, MAX_SECTOR_SIZE, SCRATCH_MEM_BASE,
    SCRATCH_MEM_SIZE,
};

// Argon2 Block type needed for memory allocation
use argon2;

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

// Parallels format offsets (detect-and-info only; parse mirrors
// qemu block/parallels.c). The 16-byte magic and LE u32 version @16
// are validated by the shared detector; here we only read the size.
const PARALLELS_NB_SECTORS_OFFSET: usize = 36; // LE u64 nb_sectors (unaligned)

// Bochs format offsets (detect-and-info only; parse mirrors
// qemu block/bochs.c). BOCHS_VERSION_OFFSET (@64) is shared.
const BOCHS_DISK_SIZE_V1_OFFSET: usize = 84; // LE u64 disk size (HEADER_V1)
const BOCHS_DISK_SIZE_V2_OFFSET: usize = 88; // LE u64 disk size (HEADER_VERSION)

// cloop format offsets and bounds (detect-and-info only; parse and
// open-time bounds mirror qemu block/cloop.c).
const CLOOP_BLOCK_SIZE_OFFSET: usize = 128; // BE u32 block_size
const CLOOP_N_BLOCKS_OFFSET: usize = 132; // BE u32 n_blocks
const CLOOP_MAX_BLOCK_SIZE: u32 = 64 * 1024 * 1024; // qemu MAX_BLOCK_SIZE (64 MiB)
const CLOOP_MAX_N_BLOCKS: u32 = (u32::MAX - 1) / 8; // qemu offsets-array bound

// DMG SectorCount is BE u64 at koly+0x1ec; ×512 gives virtual size.
const DMG_SECTOR_SIZE: u64 = 512;

// Note: ISO_MAGIC_BYTE_OFFSET and ISO_MAGIC are in shared::format_detection

// LUKS constants from the luks crate
use luks::{
    copy_null_padded, LUKS2_BINARY_HEADER_SIZE, LUKS2_JSON_SCAN_SIZE, LUKS2_UUID_OFFSET,
    LUKS_CIPHER_MODE_OFFSET, LUKS_CIPHER_NAME_OFFSET, LUKS_HASH_SPEC_OFFSET, LUKS_KEY_BYTES_OFFSET,
    LUKS_KEY_SLOT_ACTIVE, LUKS_KEY_SLOT_BASE, LUKS_KEY_SLOT_SIZE, LUKS_NUM_KEY_SLOTS,
    LUKS_PAYLOAD_OFFSET_OFFSET, LUKS_UUID_OFFSET, LUKS_V1_HEADER_SIZE, LUKS_VERSION_OFFSET,
};

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

    // If still no format detected, try DMG koly-trailer detection.
    //
    // Unlike ISO, DMG detection is NOT quirk-gated: the koly trailer is
    // structural content (same stance as ISO's content probe, but always
    // on). Surfacing "this raw-looking file is actually a DMG container"
    // is exactly the safety fact instar exists to report, so it runs even
    // under --unsafe-quirks. See `probe_dmg_trailer` for the file-length
    // recovery that makes this work under any sector size.
    let mut dmg_sector_count_val: Option<u64> = None;
    if format == ImageFormat::Raw && input_capacity > 0 {
        (call_table.verbose_print)(b"info: checking DMG koly trailer\n\0".as_ptr());
        if let Some(sc) = probe_dmg_trailer(call_table, input_capacity, input_sector_size) {
            format = ImageFormat::Dmg;
            dmg_sector_count_val = Some(sc);
            (call_table.verbose_print)(b"info: detected DMG koly trailer\n\0".as_ptr());
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
        ImageFormat::VmdkDescriptor => {
            // VMDK monolithicFlat: the descriptor file itself is
            // ASCII text pointing at a separate flat extent. Parse
            // the text in-guest (the VMM refuses to do format
            // parsing on untrusted bytes — architecture principle)
            // and report a `vmdk` result with the extent's virtual
            // size and the descriptor-level metadata.
            let mut vmdk_info = VmdkInfo::new();

            // `buffer` already holds the first input sector.
            // Descriptors emitted by qemu-img are well under 512
            // bytes, so a single sector covers the extent line.
            // Parse legacy fields (CID, parentCID, createType).
            vmdk::parse_descriptor(&buffer, buffer.len(), &mut vmdk_info);

            // Parse the extent line to recover the virtual size.
            // Failure here means the descriptor was malformed — the
            // VMM would already have rejected it on the host, but
            // we double-check so untrusted input never escapes as
            // "virtual_size = 0".
            if let Ok(text) = core::str::from_utf8(&buffer) {
                if let Ok(extents) = vmdk::parse_descriptor_extents(text) {
                    // Sum all extent sizes for total virtual size
                    // (single-extent for monolithicFlat, N extents
                    // for twoGbMaxExtentFlat).
                    let mut total: u64 = 0;
                    for i in 0..extents.len() {
                        if let Some(extent) = extents.get(i) {
                            total = total.saturating_add(extent.size_sectors.saturating_mul(512));
                        }
                    }
                    result.virtual_size = total;
                }
            }

            (call_table.send_info_result_vmdk)(
                format_str,
                result.version,
                result.virtual_size,
                result.actual_size,
                result.cluster_size,
                result.flags,
                b"\0".as_ptr(),
                b"\0".as_ptr(),
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
        ImageFormat::Parallels => {
            if detailed {
                parse_parallels_header(&buffer, &mut result);
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
        ImageFormat::Bochs => {
            if detailed {
                parse_bochs_header(&buffer, &mut result);
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
        ImageFormat::Cloop => {
            if detailed {
                parse_cloop_header(&buffer, &mut result);
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
        ImageFormat::Dmg => {
            // SectorCount was validated during the koly-trailer probe
            // above; virtual size = SectorCount × 512 (checked).
            if detailed {
                if let Some(sc) = dmg_sector_count_val {
                    result.virtual_size = sc.checked_mul(DMG_SECTOR_SIZE).unwrap_or(0);
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
        // VMDK monolithicFlat descriptor — reported as "vmdk" to
        // match qemu-img info output. Full descriptor-specific
        // info reporting (createType, extent filename) is handled
        // in Phase 22c.
        ImageFormat::VmdkDescriptor => b"vmdk\0".as_ptr(),
        // Detection and info-name only (format-coverage phase 1,
        // step 2a); dispatch/size parsing for these formats lands
        // in step 3a. Names match qemu-img's format_name strings.
        ImageFormat::Parallels => b"parallels\0".as_ptr(),
        ImageFormat::Bochs => b"bochs\0".as_ptr(),
        ImageFormat::Cloop => b"cloop\0".as_ptr(),
        ImageFormat::Dmg => b"dmg\0".as_ptr(),
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

    // Virtual disk size (little-endian u64 at offset 368).
    //
    // qemu's `vdi_open` rounds an odd `disk_size` up to the next 512-byte
    // multiple in memory rather than rejecting it (VBoxManage-created images
    // can write non-512-aligned sizes). We mirror that so info output stays
    // byte-identical to qemu-img. Checked arithmetic; on the (impossible for
    // a real header) overflow near u64::MAX, fall back to the raw value.
    let raw_disk_size = u64::from_le_bytes([
        buffer[VDI_DISK_SIZE_OFFSET],
        buffer[VDI_DISK_SIZE_OFFSET + 1],
        buffer[VDI_DISK_SIZE_OFFSET + 2],
        buffer[VDI_DISK_SIZE_OFFSET + 3],
        buffer[VDI_DISK_SIZE_OFFSET + 4],
        buffer[VDI_DISK_SIZE_OFFSET + 5],
        buffer[VDI_DISK_SIZE_OFFSET + 6],
        buffer[VDI_DISK_SIZE_OFFSET + 7],
    ]);
    result.virtual_size = raw_disk_size
        .checked_add(511)
        .map(|v| v & !511u64)
        .unwrap_or(raw_disk_size);

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

/// Parse a Parallels header and populate the virtual size.
///
/// Mirrors qemu block/parallels.c: `nb_sectors` is a LE u64 at offset
/// 36 (unaligned) and the virtual size is `nb_sectors × 512`. The
/// legacy `WithoutFreeSpace` magic stored `nb_sectors` in a 32-bit
/// field, so qemu masks it to the low 32 bits; the extended
/// `WithouFreSpacExt` magic uses the full 64-bit value. Detection has
/// already confirmed one of those two magics and version 2.
fn parse_parallels_header(buffer: &[u8], result: &mut InfoResult) {
    if buffer.len() < PARALLELS_NB_SECTORS_OFFSET + 8 {
        return;
    }

    let mut nb_sectors = u64::from_le_bytes([
        buffer[PARALLELS_NB_SECTORS_OFFSET],
        buffer[PARALLELS_NB_SECTORS_OFFSET + 1],
        buffer[PARALLELS_NB_SECTORS_OFFSET + 2],
        buffer[PARALLELS_NB_SECTORS_OFFSET + 3],
        buffer[PARALLELS_NB_SECTORS_OFFSET + 4],
        buffer[PARALLELS_NB_SECTORS_OFFSET + 5],
        buffer[PARALLELS_NB_SECTORS_OFFSET + 6],
        buffer[PARALLELS_NB_SECTORS_OFFSET + 7],
    ]);

    // Legacy WithoutFreeSpace: nb_sectors is only 32 bits wide.
    if buffer[0..16] == PARALLELS_MAGIC_V1 {
        nb_sectors &= 0xffff_ffff;
    }

    result.virtual_size = nb_sectors.saturating_mul(512);
}

/// Parse a Bochs growing-disk header and populate the virtual size.
///
/// Mirrors qemu block/bochs.c: the on-disk byte size is a LE u64 at
/// offset 88 for HEADER_VERSION (0x00020000) and at offset 84 for the
/// older HEADER_V1 (0x00010000). qemu computes `total_sectors =
/// disk_size / 512`, so the reported virtual size is
/// `(disk_size / 512) × 512` (truncating). Detection has already
/// confirmed the magics and a recognised version.
fn parse_bochs_header(buffer: &[u8], result: &mut InfoResult) {
    if buffer.len() < BOCHS_DISK_SIZE_V2_OFFSET + 8 {
        return;
    }

    let version = u32::from_le_bytes([
        buffer[BOCHS_VERSION_OFFSET],
        buffer[BOCHS_VERSION_OFFSET + 1],
        buffer[BOCHS_VERSION_OFFSET + 2],
        buffer[BOCHS_VERSION_OFFSET + 3],
    ]);

    let disk_offset = if version == BOCHS_VERSION_2 {
        BOCHS_DISK_SIZE_V2_OFFSET
    } else {
        BOCHS_DISK_SIZE_V1_OFFSET
    };

    let disk_size = u64::from_le_bytes([
        buffer[disk_offset],
        buffer[disk_offset + 1],
        buffer[disk_offset + 2],
        buffer[disk_offset + 3],
        buffer[disk_offset + 4],
        buffer[disk_offset + 5],
        buffer[disk_offset + 6],
        buffer[disk_offset + 7],
    ]);

    // Truncate to whole 512-byte sectors, matching qemu's total_sectors.
    result.virtual_size = (disk_size / 512) * 512;
}

/// Parse a cloop header and populate the virtual size.
///
/// Mirrors qemu block/cloop.c: `block_size` is a BE u32 at offset 128
/// and `n_blocks` a BE u32 at offset 132; virtual size is
/// `n_blocks × block_size`. qemu's open-time sanity checks are applied
/// here as parse-failure conditions (leaving virtual size 0, the same
/// outcome as any other detect-only parse failure): `block_size` must
/// be non-zero, a multiple of 512, and <= 64 MiB, and `n_blocks` must
/// not exceed `(u32::MAX - 1) / 8`.
fn parse_cloop_header(buffer: &[u8], result: &mut InfoResult) {
    if buffer.len() < CLOOP_N_BLOCKS_OFFSET + 4 {
        return;
    }

    let block_size = u32::from_be_bytes([
        buffer[CLOOP_BLOCK_SIZE_OFFSET],
        buffer[CLOOP_BLOCK_SIZE_OFFSET + 1],
        buffer[CLOOP_BLOCK_SIZE_OFFSET + 2],
        buffer[CLOOP_BLOCK_SIZE_OFFSET + 3],
    ]);
    let n_blocks = u32::from_be_bytes([
        buffer[CLOOP_N_BLOCKS_OFFSET],
        buffer[CLOOP_N_BLOCKS_OFFSET + 1],
        buffer[CLOOP_N_BLOCKS_OFFSET + 2],
        buffer[CLOOP_N_BLOCKS_OFFSET + 3],
    ]);

    if block_size == 0 || block_size % 512 != 0 || block_size > CLOOP_MAX_BLOCK_SIZE {
        return;
    }
    if n_blocks > CLOOP_MAX_N_BLOCKS {
        return;
    }

    result.virtual_size = (n_blocks as u64)
        .checked_mul(block_size as u64)
        .unwrap_or(0);
}

/// Probe the input's tail for a DMG koly trailer, returning its
/// SectorCount if a valid trailer is found.
///
/// # Why this is not a simple "read the last sector" probe
///
/// A DMG koly trailer is the file's final 512 bytes, and qemu locates
/// it by scanning the file's last 1024 bytes (`dmg_find_koly_offset`).
/// The obvious mirror — read the last device sector and hand it plus the
/// device capacity to the shared helpers — does not work here, because
/// the guest never sees the true file length. The host builds the virtio
/// device with `capacity = div_ceil(file_size, sector_size)` (see
/// `VirtioBlockDevice::new`), so `input_capacity * input_sector_size`
/// only gives `round_up(file_size, sector_size)`. With the default 64 KiB
/// sector size that padding can be tens of kilobytes — far more than
/// qemu's 511-byte trailing-padding tolerance — and reads past EOF
/// zero-fill (`BackingStore::read_at`), so the real koly ends up buried
/// mid-buffer with a large zero tail after it, nowhere near the
/// capacity-derived window. (Fixed-VHD footer detection sidesteps this
/// only because a VHD's data area is sector-aligned, so its footer
/// happens to start at a sector boundary; a DMG's koly is not aligned.)
///
/// # How the real file length is recovered
///
/// Because the koly is the file's final 512 bytes and everything after
/// it in the device buffer is zero-fill, the *last* `koly` magic in the
/// read tail marks the real trailer, and therefore the real file length
/// is `last_koly_offset + 512`. Once that length is known, the tail is
/// sliced to end exactly at it so the shared helper's
/// `buffer_base = len - buffer.len()` maps correctly, reproducing qemu's
/// `[len-1023, len-512]` window semantics and its SectorCount validation
/// (top-bit-set rejected). The last two sectors are read so a koly that
/// straddles the final sector boundary (file length just over a sector
/// multiple) is still fully covered.
///
/// Runs `#[inline(never)]` with its own large tail buffer so `_start`'s
/// stack frame stays small (guest codegen is sensitive to oversized
/// inlined frames under opt-level=z + LTO).
#[inline(never)]
unsafe fn probe_dmg_trailer(
    call_table: &CallTable,
    input_capacity: u64,
    input_sector_size: usize,
) -> Option<u64> {
    if input_capacity == 0 {
        return None;
    }

    // Read the last one or two device sectors into a contiguous buffer.
    let mut tail = [0u8; 2 * MAX_SECTOR_SIZE];
    let sectors_to_read = if input_capacity >= 2 { 2 } else { 1 };
    let base_sector = input_capacity - sectors_to_read;
    let base = base_sector * input_sector_size as u64; // device offset of tail[0]
    let mut tail_len = 0usize;
    for i in 0..sectors_to_read {
        let sector = base_sector + i;
        let off = i as usize * input_sector_size;
        if !(call_table.read_input_sector)(0, sector, tail[off..].as_mut_ptr(), input_sector_size) {
            return None;
        }
        tail_len = off + input_sector_size;
    }
    let tail = &tail[..tail_len];

    // Find the LAST koly magic in the read tail (the real trailer; see
    // the doc comment above).
    let mut koly_idx: Option<usize> = None;
    let mut i = 0usize;
    while i + DMG_KOLY_MAGIC.len() <= tail_len {
        if tail[i..i + DMG_KOLY_MAGIC.len()] == DMG_KOLY_MAGIC {
            koly_idx = Some(i);
        }
        i += 1;
    }
    let idx = koly_idx?;

    // The 512-byte koly block must be fully present in the read tail.
    if idx + DMG_KOLY_TRAILER_LEN > tail_len {
        return None;
    }

    // koly is the file's final 512 bytes → recover the true file length.
    let koly_abs = base + idx as u64;
    let real_len = koly_abs.checked_add(DMG_KOLY_TRAILER_LEN as u64)?;

    // Re-validate through the shared helpers with the recovered length.
    // Slicing to end exactly at real_len makes buffer_base map back to
    // `base`, so the helper's window scan is qemu-faithful.
    let slice = &tail[..idx + DMG_KOLY_TRAILER_LEN];
    let koly_off = detect_dmg_koly_offset(slice, real_len as usize)?;
    dmg_sector_count(slice, real_len as usize, koly_off)
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
                luks::parse_v2_json_metadata(
                    &json_data[..json_len],
                    &mut luks_info.cipher,
                    &mut luks_info.cipher_mode,
                    &mut luks_info.hash,
                    &mut luks_info.payload_offset,
                    &mut luks_info.master_key_length,
                    &mut luks_info.active_key_slots,
                );
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
                    luks::parse_v2_json_metadata(
                        &json_data[..json_len],
                        &mut luks_info.cipher,
                        &mut luks_info.cipher_mode,
                        &mut luks_info.hash,
                        &mut luks_info.payload_offset,
                        &mut luks_info.master_key_length,
                        &mut luks_info.active_key_slots,
                    );
                }
            }
        }
    }
}

/// Attempt LUKS1 decryption and return the detected inner format.
///
/// Uses the luks crate for header parsing, key derivation, and verification.
/// The I/O (reading key material and payload from disk) remains here.
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

    // Parse LUKS v1 header using the luks crate
    let parsed = match luks::parse_v1_header(header) {
        Some(h) => h,
        None => {
            (call_table.debug_print)(b"luks: failed to parse v1 header\n\0".as_ptr());
            return None;
        }
    };

    if !luks::v1_is_aes_xts(&parsed) {
        (call_table.debug_print)(b"luks: unsupported cipher/mode\n\0".as_ptr());
        return None;
    }

    let key_bytes = parsed.key_bytes as usize;
    if key_bytes != 32 && key_bytes != 64 {
        (call_table.debug_print)(b"luks: unsupported key size\n\0".as_ptr());
        return None;
    }

    let slot_idx = match luks::find_active_v1_slot(&parsed) {
        Some(i) => i,
        None => {
            (call_table.debug_print)(b"luks: no active key slot\n\0".as_ptr());
            return None;
        }
    };

    (call_table.verbose_print)(b"luks: starting PBKDF2 key derivation\n\0".as_ptr());

    // Read encrypted key material from disk
    let (km_byte_offset, km_total_bytes) =
        match luks::v1_key_material_region(&parsed.slots[slot_idx], parsed.key_bytes) {
            Some(v) => v,
            None => {
                (call_table.debug_print)(b"luks: key material size overflow\n\0".as_ptr());
                return None;
            }
        };

    if km_total_bytes > SCRATCH_MEM_SIZE {
        (call_table.debug_print)(b"luks: key material exceeds scratch memory\n\0".as_ptr());
        return None;
    }

    let cap = (call_table.get_input_capacity)(0) * input_sector_size as u64;
    if km_byte_offset + km_total_bytes as u64 > cap {
        (call_table.debug_print)(b"luks: key material offset exceeds device capacity\n\0".as_ptr());
        return None;
    }

    let km_buf = core::slice::from_raw_parts_mut(SCRATCH_MEM_BASE as *mut u8, km_total_bytes);
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

    (call_table.verbose_print)(b"luks: deriving master key via luks crate\n\0".as_ptr());

    // Derive master key using the luks crate (PBKDF2 + AES-XTS + AFsplit + verify)
    let passphrase = config.passphrase_bytes();
    let derived = match luks::derive_v1_master_key(&parsed, passphrase, km_buf) {
        Some(d) => d,
        None => {
            (call_table.debug_print)(b"luks: master key verification failed\n\0".as_ptr());
            return None;
        }
    };

    (call_table.verbose_print)(b"luks: master key verified, decrypting payload\n\0".as_ptr());

    // Decrypt first payload sector with the verified master key
    let payload_byte_offset = parsed.payload_offset as u64 * 512;
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

    let payload_offset_in_sector = (payload_byte_offset % input_sector_size as u64) as usize;
    let decrypt_buf = &mut payload_buf[payload_offset_in_sector..payload_offset_in_sector + 512];

    luks::aes_xts_decrypt(decrypt_buf, &derived.key[..derived.key_len], 0);

    (call_table.verbose_print)(b"luks: detecting inner format\n\0".as_ptr());

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
            let payload_bytes = parsed.payload_offset as u64 * 512;
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

// AFsplitter diffuse functions are now in the luks crate:
// luks::af_diffuse_sha1() and luks::af_diffuse_sha256()

/// Attempt LUKS2 decryption with Argon2id KDF.
///
/// Uses the luks crate for JSON parsing, key derivation, and verification.
/// The I/O (reading key material and payload from disk) remains here.
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

    // Parse keyslot and digest parameters using the luks crate
    let slot = match luks::parse_v2_keyslot(json) {
        Some(s) => s,
        None => {
            (call_table.debug_print)(b"luks2: failed to parse keyslot JSON\n\0".as_ptr());
            return None;
        }
    };

    let digest_params = match luks::parse_v2_digest(json) {
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

    (call_table.verbose_print)(b"luks2: reading key material\n\0".as_ptr());

    // Read encrypted key material from disk
    let km_total_bytes = (key_bytes as u64)
        .checked_mul(slot.af_stripes as u64)
        .unwrap_or(0) as usize;
    if km_total_bytes == 0 || km_total_bytes > SCRATCH_MEM_SIZE {
        (call_table.debug_print)(b"luks2: key material size invalid\n\0".as_ptr());
        return None;
    }

    let km_buf = core::slice::from_raw_parts_mut(SCRATCH_MEM_BASE as *mut u8, km_total_bytes);

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

    (call_table.verbose_print)(b"luks2: deriving master key via luks crate\n\0".as_ptr());

    // Derive master key using luks crate (Argon2id + AES-XTS + AFsplit + verify)
    let num_blocks = (slot.kdf_memory as usize * 1024) / 1024;
    let memory_ptr = ARGON2_MEM_BASE as *mut argon2::Block;
    let memory_blocks = core::slice::from_raw_parts_mut(memory_ptr, num_blocks);

    let passphrase = config.passphrase_bytes();
    let derived = match luks::derive_v2_master_key(
        &slot,
        &digest_params,
        passphrase,
        km_buf,
        memory_blocks,
    ) {
        Some(d) => d,
        None => {
            (call_table.debug_print)(b"luks2: master key derivation failed\n\0".as_ptr());
            return None;
        }
    };

    (call_table.verbose_print)(b"luks2: master key verified, decrypting payload\n\0".as_ptr());

    // Decrypt first payload sector
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

    let payload_offset_in_sector = (payload_byte_offset % input_sector_size as u64) as usize;
    let decrypt_buf = &mut payload_buf[payload_offset_in_sector..payload_offset_in_sector + 512];

    luks::aes_xts_decrypt(decrypt_buf, &derived.key[..derived.key_len], 0);

    (call_table.verbose_print)(b"luks2: detecting inner format\n\0".as_ptr());

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

// Unit tests for the detect-only format size parsers (format-coverage
// phase 1, step 3a). Byte-array fixtures mirror the VDI/QED style used
// elsewhere and the real instar-testdata images (parallels-v{1,2},
// empty.bochs, simple-pattern.cloop, dmg-simple).
//
// NOTE ON EXECUTION: the info operation is a `#![no_std] #![no_main]`
// guest binary, so `cargo test -p info` cannot build the standard test
// harness (no `main`), and `make test-rust` deliberately `--exclude`s
// `info` for that reason. These tests therefore document and pin the
// parser behaviour but are not run by the current CI harness; the
// exhaustively-run detection/koly coverage lives in the shared
// `format_detection` tests. They are compiled out of every production
// build (`cfg(test)` is false), so they cannot affect `make instar`.
#[cfg(test)]
mod tests {
    use super::*;
    use shared::format_detection::{
        DMG_KOLY_MAGIC, DMG_KOLY_SECTOR_COUNT_OFFSET, PARALLELS_MAGIC_V2,
    };

    // ------------------------------------------------------------------
    // Parallels
    // ------------------------------------------------------------------

    fn parallels_header(magic: &[u8; 16], nb_sectors: u64) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..16].copy_from_slice(magic);
        // version 2 (LE u32 @16), as required by detection.
        buf[16..20].copy_from_slice(&2u32.to_le_bytes());
        buf[PARALLELS_NB_SECTORS_OFFSET..PARALLELS_NB_SECTORS_OFFSET + 8]
            .copy_from_slice(&nb_sectors.to_le_bytes());
        buf
    }

    #[test]
    fn parallels_v1_fixture_size() {
        // instar-testdata parallels-v1: nb_sectors = 4096 → 2 MiB.
        let buf = parallels_header(&PARALLELS_MAGIC_V1, 4096);
        let mut result = InfoResult::new();
        parse_parallels_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 2_097_152);
    }

    #[test]
    fn parallels_v2_fixture_size() {
        // instar-testdata parallels-v2: nb_sectors = 4096 → 2 MiB.
        let buf = parallels_header(&PARALLELS_MAGIC_V2, 4096);
        let mut result = InfoResult::new();
        parse_parallels_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 2_097_152);
    }

    #[test]
    fn parallels_v1_masks_high_bits() {
        // WithoutFreeSpace stores nb_sectors in 32 bits: the high half
        // must be masked away before multiplying by 512.
        let nb = 0x0000_0001_0000_1000u64; // low 32 bits = 0x1000 = 4096
        let buf = parallels_header(&PARALLELS_MAGIC_V1, nb);
        let mut result = InfoResult::new();
        parse_parallels_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 4096 * 512);
    }

    #[test]
    fn parallels_v2_uses_full_64_bits() {
        // WithouFreSpacExt uses the full 64-bit nb_sectors (no masking).
        let nb = 0x0000_0001_0000_1000u64;
        let buf = parallels_header(&PARALLELS_MAGIC_V2, nb);
        let mut result = InfoResult::new();
        parse_parallels_header(&buf, &mut result);
        assert_eq!(result.virtual_size, nb * 512);
    }

    #[test]
    fn parallels_short_buffer_leaves_zero() {
        let full = parallels_header(&PARALLELS_MAGIC_V1, 4096);
        let mut result = InfoResult::new();
        parse_parallels_header(&full[..PARALLELS_NB_SECTORS_OFFSET + 7], &mut result);
        assert_eq!(result.virtual_size, 0);
    }

    // ------------------------------------------------------------------
    // Bochs
    // ------------------------------------------------------------------

    fn bochs_header(version: u32, disk_offset: usize, disk_size: u64) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[BOCHS_VERSION_OFFSET..BOCHS_VERSION_OFFSET + 4].copy_from_slice(&version.to_le_bytes());
        buf[disk_offset..disk_offset + 8].copy_from_slice(&disk_size.to_le_bytes());
        buf
    }

    #[test]
    fn bochs_v2_fixture_size() {
        // instar-testdata empty.bochs: version 2, disk @88 = 1032192.
        let buf = bochs_header(BOCHS_VERSION_2, BOCHS_DISK_SIZE_V2_OFFSET, 1_032_192);
        let mut result = InfoResult::new();
        parse_bochs_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 1_032_192);
    }

    #[test]
    fn bochs_v1_reads_offset_84() {
        let buf = bochs_header(0x0001_0000, BOCHS_DISK_SIZE_V1_OFFSET, 1_048_576);
        let mut result = InfoResult::new();
        parse_bochs_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 1_048_576);
    }

    #[test]
    fn bochs_truncates_to_whole_sectors() {
        // 1024 + 100 bytes: qemu computes total_sectors = disk / 512,
        // so the odd 100 bytes are dropped.
        let buf = bochs_header(BOCHS_VERSION_2, BOCHS_DISK_SIZE_V2_OFFSET, 1124);
        let mut result = InfoResult::new();
        parse_bochs_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 1024);
    }

    // ------------------------------------------------------------------
    // cloop
    // ------------------------------------------------------------------

    fn cloop_header(block_size: u32, n_blocks: u32) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[CLOOP_BLOCK_SIZE_OFFSET..CLOOP_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&block_size.to_be_bytes());
        buf[CLOOP_N_BLOCKS_OFFSET..CLOOP_N_BLOCKS_OFFSET + 4]
            .copy_from_slice(&n_blocks.to_be_bytes());
        buf
    }

    #[test]
    fn cloop_fixture_size() {
        // instar-testdata simple-pattern.cloop: block_size 65536,
        // n_blocks 16 → 1 MiB.
        let buf = cloop_header(65536, 16);
        let mut result = InfoResult::new();
        parse_cloop_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 1_048_576);
    }

    #[test]
    fn cloop_zero_block_size_fails() {
        let buf = cloop_header(0, 16);
        let mut result = InfoResult::new();
        parse_cloop_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 0);
    }

    #[test]
    fn cloop_non_multiple_of_512_fails() {
        let buf = cloop_header(1000, 16);
        let mut result = InfoResult::new();
        parse_cloop_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 0);
    }

    #[test]
    fn cloop_block_size_over_64mib_fails() {
        let buf = cloop_header(CLOOP_MAX_BLOCK_SIZE + 512, 16);
        let mut result = InfoResult::new();
        parse_cloop_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 0);
    }

    #[test]
    fn cloop_max_block_size_ok() {
        let buf = cloop_header(CLOOP_MAX_BLOCK_SIZE, 1);
        let mut result = InfoResult::new();
        parse_cloop_header(&buf, &mut result);
        assert_eq!(result.virtual_size, CLOOP_MAX_BLOCK_SIZE as u64);
    }

    #[test]
    fn cloop_n_blocks_over_bound_fails() {
        let buf = cloop_header(65536, CLOOP_MAX_N_BLOCKS + 1);
        let mut result = InfoResult::new();
        parse_cloop_header(&buf, &mut result);
        assert_eq!(result.virtual_size, 0);
    }

    #[test]
    fn cloop_short_buffer_leaves_zero() {
        let full = cloop_header(65536, 16);
        let mut result = InfoResult::new();
        parse_cloop_header(&full[..CLOOP_N_BLOCKS_OFFSET + 3], &mut result);
        assert_eq!(result.virtual_size, 0);
    }

    // ------------------------------------------------------------------
    // DMG (trailer helpers + ×512, as the dispatch arm computes it)
    // ------------------------------------------------------------------

    /// Reproduce the guest's DMG size path: locate koly in the tail,
    /// read SectorCount, multiply by 512. Mirrors the dispatch arm.
    fn dmg_virtual_size(tail: &[u8], file_len: usize) -> Option<u64> {
        let koly = detect_dmg_koly_offset(tail, file_len)?;
        let sc = dmg_sector_count(tail, file_len, koly)?;
        Some(sc.saturating_mul(DMG_SECTOR_SIZE))
    }

    #[test]
    fn dmg_fixture_style_size() {
        // dmg-simple carries SectorCount = 8192 → 4 MiB. Emulate a file
        // whose koly trailer sits at the very end, with 512-byte-sector
        // padding (file_len rounded up to the device capacity).
        let file_len = 2048usize;
        let mut tail = [0u8; 1024]; // last two 512-byte sectors
        let koly_off = file_len - DMG_SECTOR_SIZE as usize; // 1536
        let idx = koly_off - (file_len - tail.len());
        tail[idx..idx + 4].copy_from_slice(&DMG_KOLY_MAGIC);
        let sc_idx = idx + DMG_KOLY_SECTOR_COUNT_OFFSET;
        tail[sc_idx..sc_idx + 8].copy_from_slice(&8192u64.to_be_bytes());
        assert_eq!(dmg_virtual_size(&tail, file_len), Some(4_194_304));
    }

    #[test]
    fn dmg_top_bit_sector_count_rejected() {
        // A negative (top-bit-set) SectorCount must yield no size (the
        // probe leaves the format Raw).
        let file_len = 2048usize;
        let mut tail = [0u8; 1024];
        let koly_off = file_len - DMG_SECTOR_SIZE as usize;
        let idx = koly_off - (file_len - tail.len());
        tail[idx..idx + 4].copy_from_slice(&DMG_KOLY_MAGIC);
        let sc_idx = idx + DMG_KOLY_SECTOR_COUNT_OFFSET;
        tail[sc_idx..sc_idx + 8].copy_from_slice(&0x8000_0000_0000_0001u64.to_be_bytes());
        assert_eq!(dmg_virtual_size(&tail, file_len), None);
    }

    // ------------------------------------------------------------------
    // VDI (disk_size round-up to 512, qemu vdi_open parity)
    // ------------------------------------------------------------------

    /// Minimal 512-byte VDI header carrying only the fields the parser
    /// reads: version, image_type, disk_size, block_size, block counts.
    fn vdi_header(disk_size: u64) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[VDI_VERSION_OFFSET..VDI_VERSION_OFFSET + 4]
            .copy_from_slice(&0x0001_0001u32.to_le_bytes());
        buf[VDI_IMAGE_TYPE_OFFSET..VDI_IMAGE_TYPE_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[VDI_DISK_SIZE_OFFSET..VDI_DISK_SIZE_OFFSET + 8]
            .copy_from_slice(&disk_size.to_le_bytes());
        buf[VDI_BLOCK_SIZE_OFFSET..VDI_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&1_048_576u32.to_le_bytes());
        buf
    }

    #[test]
    fn vdi_odd_disk_size_rounds_up_to_512() {
        // qemu vdi_open rounds an odd disk_size up to the next 512-byte
        // multiple in memory (12801 → 13312); info must report the rounded
        // value to stay byte-identical to qemu-img.
        let buf = vdi_header(12801);
        let mut result = InfoResult::new();
        let mut vdi_info = VdiInfo::new();
        parse_vdi_header(&buf, &mut result, &mut vdi_info);
        assert_eq!(result.virtual_size, 13312);
    }

    #[test]
    fn vdi_aligned_disk_size_unchanged() {
        // An already-512-aligned disk_size (the common qemu-created case,
        // e.g. vdi-simple at 10 MiB) is reported verbatim.
        let buf = vdi_header(10 * 1024 * 1024);
        let mut result = InfoResult::new();
        let mut vdi_info = VdiInfo::new();
        parse_vdi_header(&buf, &mut result, &mut vdi_info);
        assert_eq!(result.virtual_size, 10 * 1024 * 1024);
    }

    #[test]
    fn vdi_exact_512_multiple_unchanged() {
        // Boundary: a value that is already a multiple of 512 must not be
        // bumped to the next multiple.
        let buf = vdi_header(13312);
        let mut result = InfoResult::new();
        let mut vdi_info = VdiInfo::new();
        parse_vdi_header(&buf, &mut result, &mut vdi_info);
        assert_eq!(result.virtual_size, 13312);
    }
}
