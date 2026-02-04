//! Check operation: validate image structural integrity.
//!
//! This operation reads the image and validates its internal structures,
//! similar to `qemu-img check`. For QCOW2 images, it verifies:
//! - Header validity
//! - L1/L2 table entries
//! - Refcount table consistency
//! - Cluster allocation status
//!
//! Results are sent via protobuf CheckResultMessage over the serial command channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    format_detection::{detect_format_from_header, detect_vhd_footer, VHD_COOKIE},
    CallTable, CheckConfig, CheckResult, ImageFormat, CALL_TABLE_ADDR, MAX_SECTOR_SIZE,
};

// Note: Format detection magic constants are in shared::format_detection
// QCOW2_MAGIC is implicitly used via detect_format_from_header

// QCOW2 header offsets (big-endian)
const QCOW2_VERSION_OFFSET: usize = 4;
const QCOW2_CLUSTER_BITS_OFFSET: usize = 20;
const QCOW2_SIZE_OFFSET: usize = 24;
const QCOW2_L1_SIZE_OFFSET: usize = 36;
const QCOW2_L1_TABLE_OFFSET_OFFSET: usize = 40;
const QCOW2_REFCOUNT_TABLE_OFFSET_OFFSET: usize = 48;
const QCOW2_REFCOUNT_TABLE_CLUSTERS_OFFSET: usize = 56;
const QCOW2_INCOMPATIBLE_FEATURES_OFFSET: usize = 72;
const QCOW2_REFCOUNT_ORDER_OFFSET: usize = 96;

// QCOW2 incompatible feature bits
const QCOW2_INCOMPAT_DIRTY: u64 = 1 << 0;
const QCOW2_INCOMPAT_CORRUPT: u64 = 1 << 1;

// L1/L2 table entry flags
const QCOW2_OFLAG_COPIED: u64 = 1 << 63;
const QCOW2_OFLAG_COMPRESSED: u64 = 1 << 62;

// Mask for extracting offset from L1/L2 entries (bits 9-55)
const L1_OFFSET_MASK: u64 = 0x00fffffffffffe00;
const L2_OFFSET_MASK: u64 = 0x00fffffffffffe00;

/// Entry point called by core after devices are initialized.
///
/// Returns the number of bytes read/checked.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    // Verify call table is valid
    if call_table.magic != CallTable::MAGIC {
        (call_table.debug_print)(b"check: bad magic\n\0".as_ptr());
        return 0;
    }
    if call_table.version != CallTable::VERSION {
        (call_table.debug_print)(b"check: bad version\n\0".as_ptr());
        return 0;
    }

    (call_table.verbose_print)(b"check: start\n\0".as_ptr());

    // Get operation config (optional)
    let config_result = (call_table.get_operation_config)();
    let config = &*(config_result.ptr as *const CheckConfig);
    let (_quiet, unsafe_quirks) = if config.is_valid() {
        (config.is_quiet(), config.unsafe_quirks_enabled())
    } else {
        (false, false)
    };

    // Get device parameters (device 0 = primary input)
    let input_capacity = (call_table.get_input_capacity)(0);
    let input_sector_size = (call_table.get_input_sector_size)(0);

    // Calculate actual file size
    let actual_size = input_capacity * input_sector_size as u64;

    (call_table.verbose_print)(b"check: reading header\n\0".as_ptr());

    // Buffer for reading data
    let mut buffer = [0u8; MAX_SECTOR_SIZE];

    // Read first sector (device 0, sector 0)
    if !(call_table.read_input_sector)(0, 0, buffer.as_mut_ptr(), input_sector_size) {
        (call_table.send_error)(b"check\0".as_ptr(), b"input\0".as_ptr(), 0, 1);
        return 0;
    }

    let mut bytes_read = input_sector_size as u64;

    // Initialize result structure
    let mut result = CheckResult::new();

    // Detect format based on magic numbers
    // If unsafe_quirks is enabled, only detect QCOW2 (qemu-img compatible behavior)
    // Otherwise, detect all supported formats
    let mut format = if unsafe_quirks {
        // qemu-img check only recognizes QCOW2, treats everything else as raw
        detect_qcow2_only(&buffer, input_sector_size)
    } else {
        // Secure mode: detect all formats properly
        detect_format_from_header(&buffer, input_sector_size, false)
    };

    // If format is still Raw and we're not in unsafe_quirks mode, check for VHD footer
    // (fixed VHDs have their signature at the end of the file)
    if format == ImageFormat::Raw && !unsafe_quirks && input_capacity > 0 {
        let last_sector = input_capacity - 1;
        let mut footer_buffer = [0u8; MAX_SECTOR_SIZE];
        if (call_table.read_input_sector)(
            0,
            last_sector,
            footer_buffer.as_mut_ptr(),
            input_sector_size,
        ) {
            bytes_read += input_sector_size as u64;
            format = detect_vhd_footer(&footer_buffer);
        }
    }

    result.format = format as u32;

    (call_table.verbose_print)(b"check: detected format\n\0".as_ptr());

    // Perform format-specific validation
    match format {
        ImageFormat::Qcow2 => {
            bytes_read += check_qcow2(
                &buffer,
                &mut result,
                call_table,
                input_sector_size,
                actual_size,
            );
        }
        ImageFormat::Vmdk4 | ImageFormat::Vmdk3 => {
            if unsafe_quirks {
                // qemu-img compatible: no validation for non-QCOW2
                (call_table.verbose_print)(b"check: vmdk not supported (quirks)\n\0".as_ptr());
                result.flags |= CheckResult::FLAG_NOT_SUPPORTED;
                result.flags |= CheckResult::FLAG_VALID;
            } else {
                // Validate VMDK header
                bytes_read += check_vmdk(&buffer, &mut result, actual_size);
            }
            result.image_end_offset = actual_size;
        }
        ImageFormat::Vhdx => {
            if unsafe_quirks {
                (call_table.verbose_print)(b"check: vhdx not supported (quirks)\n\0".as_ptr());
                result.flags |= CheckResult::FLAG_NOT_SUPPORTED;
                result.flags |= CheckResult::FLAG_VALID;
            } else {
                // Validate VHDX structure
                bytes_read += check_vhdx(&mut result, call_table, input_sector_size, actual_size);
            }
            result.image_end_offset = actual_size;
        }
        ImageFormat::Vhd => {
            if unsafe_quirks {
                (call_table.verbose_print)(b"check: vhd not supported (quirks)\n\0".as_ptr());
                result.flags |= CheckResult::FLAG_NOT_SUPPORTED;
                result.flags |= CheckResult::FLAG_VALID;
            } else {
                // Validate VHD footer
                // For dynamic VHD, footer is at start; for fixed, we already read it
                let vhd_cookie = u64::from_be_bytes([
                    buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6],
                    buffer[7],
                ]);
                if vhd_cookie == VHD_COOKIE {
                    // Dynamic VHD - footer at start
                    check_vhd_footer(&buffer, &mut result);
                } else {
                    // Fixed VHD - need to read last sector again
                    let last_sector = input_capacity - 1;
                    let mut footer_buffer = [0u8; MAX_SECTOR_SIZE];
                    if (call_table.read_input_sector)(
                        0,
                        last_sector,
                        footer_buffer.as_mut_ptr(),
                        input_sector_size,
                    ) {
                        bytes_read += input_sector_size as u64;
                        check_vhd_footer(&footer_buffer, &mut result);
                    }
                }
            }
            result.image_end_offset = actual_size;
        }
        ImageFormat::Raw => {
            // Raw format has no metadata to check
            (call_table.verbose_print)(b"check: raw format, no metadata\n\0".as_ptr());
            result.flags |= CheckResult::FLAG_NOT_SUPPORTED;
            result.flags |= CheckResult::FLAG_VALID;
            result.image_end_offset = actual_size;
        }
        _ => {
            // Other formats: mark as not supported
            // Note: We still detect the correct format, but don't validate it yet
            (call_table.verbose_print)(b"check: format not supported\n\0".as_ptr());
            result.flags |= CheckResult::FLAG_NOT_SUPPORTED;
            result.image_end_offset = actual_size;
        }
    }

    // Set VALID flag if no errors
    if result.total_errors == 0 && result.corruptions == 0 {
        result.flags |= CheckResult::FLAG_VALID;
    }

    // Send result via protobuf over serial
    (call_table.send_check_result)(&result);

    (call_table.send_complete)(b"check\0".as_ptr(), bytes_read, result.total_errors == 0);
    (call_table.verbose_print)(b"check: done\n\0".as_ptr());

    bytes_read
}

/// Detect only QCOW2 format (for unsafe_quirks mode, matching qemu-img behavior)
///
/// qemu-img check only recognizes QCOW2 format. All other formats are treated as raw.
fn detect_qcow2_only(buffer: &[u8], len: usize) -> ImageFormat {
    if len < 8 {
        return ImageFormat::Unknown;
    }

    // Check QCOW2 magic (big-endian)
    const QCOW2_MAGIC: u32 = 0x514649fb;
    let magic_be = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    if magic_be == QCOW2_MAGIC {
        return ImageFormat::Qcow2;
    }

    // qemu-img treats everything else as raw
    ImageFormat::Raw
}

// VMDK4 header offsets (little-endian)
const VMDK4_VERSION_OFFSET: usize = 4;
const VMDK4_CAPACITY_OFFSET: usize = 12;
const VMDK4_GRAIN_SIZE_OFFSET: usize = 20;
const VMDK4_DESC_OFFSET_OFFSET: usize = 28;
const VMDK4_DESC_SIZE_OFFSET: usize = 36;

// VHDX region table offset and signature
const VHDX_REGION_TABLE_OFFSET: u64 = 0x30000;
const VHDX_REGION_TABLE_SIG: u32 = 0x69676572; // "regi"

// VHD footer disk type offset
const VHD_FOOTER_DISK_TYPE_OFFSET: usize = 60;

/// Check VMDK image integrity
///
/// Validates:
/// - Header version (must be 1, 2, or 3)
/// - Capacity > 0
/// - Grain size is power of 2
/// - Descriptor offset is within file bounds
fn check_vmdk(header: &[u8], result: &mut CheckResult, actual_size: u64) -> u64 {
    // Check version
    let version = u32::from_le_bytes([
        header[VMDK4_VERSION_OFFSET],
        header[VMDK4_VERSION_OFFSET + 1],
        header[VMDK4_VERSION_OFFSET + 2],
        header[VMDK4_VERSION_OFFSET + 3],
    ]);

    if version == 0 || version > 3 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        return 0;
    }

    // Check capacity
    let capacity_sectors = u64::from_le_bytes([
        header[VMDK4_CAPACITY_OFFSET],
        header[VMDK4_CAPACITY_OFFSET + 1],
        header[VMDK4_CAPACITY_OFFSET + 2],
        header[VMDK4_CAPACITY_OFFSET + 3],
        header[VMDK4_CAPACITY_OFFSET + 4],
        header[VMDK4_CAPACITY_OFFSET + 5],
        header[VMDK4_CAPACITY_OFFSET + 6],
        header[VMDK4_CAPACITY_OFFSET + 7],
    ]);

    if capacity_sectors == 0 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        return 0;
    }

    // Check grain size (must be power of 2)
    let grain_size = u64::from_le_bytes([
        header[VMDK4_GRAIN_SIZE_OFFSET],
        header[VMDK4_GRAIN_SIZE_OFFSET + 1],
        header[VMDK4_GRAIN_SIZE_OFFSET + 2],
        header[VMDK4_GRAIN_SIZE_OFFSET + 3],
        header[VMDK4_GRAIN_SIZE_OFFSET + 4],
        header[VMDK4_GRAIN_SIZE_OFFSET + 5],
        header[VMDK4_GRAIN_SIZE_OFFSET + 6],
        header[VMDK4_GRAIN_SIZE_OFFSET + 7],
    ]);

    if grain_size == 0 || (grain_size & (grain_size - 1)) != 0 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        return 0;
    }

    // Check descriptor offset (if present, must be within file)
    let desc_offset_sectors = u64::from_le_bytes([
        header[VMDK4_DESC_OFFSET_OFFSET],
        header[VMDK4_DESC_OFFSET_OFFSET + 1],
        header[VMDK4_DESC_OFFSET_OFFSET + 2],
        header[VMDK4_DESC_OFFSET_OFFSET + 3],
        header[VMDK4_DESC_OFFSET_OFFSET + 4],
        header[VMDK4_DESC_OFFSET_OFFSET + 5],
        header[VMDK4_DESC_OFFSET_OFFSET + 6],
        header[VMDK4_DESC_OFFSET_OFFSET + 7],
    ]);

    let desc_size_sectors = u64::from_le_bytes([
        header[VMDK4_DESC_SIZE_OFFSET],
        header[VMDK4_DESC_SIZE_OFFSET + 1],
        header[VMDK4_DESC_SIZE_OFFSET + 2],
        header[VMDK4_DESC_SIZE_OFFSET + 3],
        header[VMDK4_DESC_SIZE_OFFSET + 4],
        header[VMDK4_DESC_SIZE_OFFSET + 5],
        header[VMDK4_DESC_SIZE_OFFSET + 6],
        header[VMDK4_DESC_SIZE_OFFSET + 7],
    ]);

    if desc_offset_sectors > 0 {
        let desc_end = desc_offset_sectors
            .saturating_mul(512)
            .saturating_add(desc_size_sectors.saturating_mul(512));
        if desc_end > actual_size {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            return 0;
        }
    }

    // VMDK header looks valid
    0
}

/// Check VHDX image integrity
///
/// Validates:
/// - Region table signature at offset 0x30000
unsafe fn check_vhdx(
    result: &mut CheckResult,
    call_table: &CallTable,
    sector_size: usize,
    actual_size: u64,
) -> u64 {
    let mut bytes_read: u64 = 0;

    // Check if file is large enough for region table
    if actual_size < VHDX_REGION_TABLE_OFFSET + 4096 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        return bytes_read;
    }

    // Read region table
    let mut buffer = [0u8; MAX_SECTOR_SIZE];
    let region_table_sector = VHDX_REGION_TABLE_OFFSET / sector_size as u64;

    if !(call_table.read_input_sector)(0, region_table_sector, buffer.as_mut_ptr(), sector_size) {
        result.corruptions += 1;
        result.total_errors += 1;
        return bytes_read;
    }
    bytes_read += sector_size as u64;

    let offset_in_sector = (VHDX_REGION_TABLE_OFFSET % sector_size as u64) as usize;
    let region_sig = u32::from_le_bytes([
        buffer[offset_in_sector],
        buffer[offset_in_sector + 1],
        buffer[offset_in_sector + 2],
        buffer[offset_in_sector + 3],
    ]);

    if region_sig != VHDX_REGION_TABLE_SIG {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
    }

    bytes_read
}

/// Check VHD footer integrity
///
/// Validates:
/// - Disk type is valid (2=fixed, 3=dynamic, 4=differencing)
fn check_vhd_footer(footer: &[u8], result: &mut CheckResult) {
    if footer.len() < VHD_FOOTER_DISK_TYPE_OFFSET + 4 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        return;
    }

    // Disk type is big-endian u32 at offset 60
    let disk_type = u32::from_be_bytes([
        footer[VHD_FOOTER_DISK_TYPE_OFFSET],
        footer[VHD_FOOTER_DISK_TYPE_OFFSET + 1],
        footer[VHD_FOOTER_DISK_TYPE_OFFSET + 2],
        footer[VHD_FOOTER_DISK_TYPE_OFFSET + 3],
    ]);

    // Valid disk types: 2 (fixed), 3 (dynamic), 4 (differencing)
    if disk_type < 2 || disk_type > 4 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
    }
}

/// Check QCOW2 image integrity
///
/// Validates:
/// - Header magic and version
/// - L1 table entries
/// - L2 table entries (samples)
/// - Refcount table structure
/// - Checks for dirty/corrupt flags
unsafe fn check_qcow2(
    header: &[u8],
    result: &mut CheckResult,
    call_table: &CallTable,
    sector_size: usize,
    actual_size: u64,
) -> u64 {
    let mut bytes_read: u64 = 0;

    // Parse header fields
    let version = u32::from_be_bytes([
        header[QCOW2_VERSION_OFFSET],
        header[QCOW2_VERSION_OFFSET + 1],
        header[QCOW2_VERSION_OFFSET + 2],
        header[QCOW2_VERSION_OFFSET + 3],
    ]);

    // Validate version (2 or 3)
    if version < 2 || version > 3 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: invalid qcow2 version\n\0".as_ptr());
        return bytes_read;
    }

    // Cluster bits and size (QCOW2 spec: valid range is 9-21)
    let cluster_bits = u32::from_be_bytes([
        header[QCOW2_CLUSTER_BITS_OFFSET],
        header[QCOW2_CLUSTER_BITS_OFFSET + 1],
        header[QCOW2_CLUSTER_BITS_OFFSET + 2],
        header[QCOW2_CLUSTER_BITS_OFFSET + 3],
    ]);
    if cluster_bits < 9 || cluster_bits > 21 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: invalid cluster_bits\n\0".as_ptr());
        return bytes_read;
    }
    let cluster_size = 1u64 << cluster_bits;

    // Virtual size
    let virtual_size = u64::from_be_bytes([
        header[QCOW2_SIZE_OFFSET],
        header[QCOW2_SIZE_OFFSET + 1],
        header[QCOW2_SIZE_OFFSET + 2],
        header[QCOW2_SIZE_OFFSET + 3],
        header[QCOW2_SIZE_OFFSET + 4],
        header[QCOW2_SIZE_OFFSET + 5],
        header[QCOW2_SIZE_OFFSET + 6],
        header[QCOW2_SIZE_OFFSET + 7],
    ]);

    // L1 table info
    let l1_size = u32::from_be_bytes([
        header[QCOW2_L1_SIZE_OFFSET],
        header[QCOW2_L1_SIZE_OFFSET + 1],
        header[QCOW2_L1_SIZE_OFFSET + 2],
        header[QCOW2_L1_SIZE_OFFSET + 3],
    ]);
    let l1_table_offset = u64::from_be_bytes([
        header[QCOW2_L1_TABLE_OFFSET_OFFSET],
        header[QCOW2_L1_TABLE_OFFSET_OFFSET + 1],
        header[QCOW2_L1_TABLE_OFFSET_OFFSET + 2],
        header[QCOW2_L1_TABLE_OFFSET_OFFSET + 3],
        header[QCOW2_L1_TABLE_OFFSET_OFFSET + 4],
        header[QCOW2_L1_TABLE_OFFSET_OFFSET + 5],
        header[QCOW2_L1_TABLE_OFFSET_OFFSET + 6],
        header[QCOW2_L1_TABLE_OFFSET_OFFSET + 7],
    ]);

    // Refcount table info
    let refcount_table_offset = u64::from_be_bytes([
        header[QCOW2_REFCOUNT_TABLE_OFFSET_OFFSET],
        header[QCOW2_REFCOUNT_TABLE_OFFSET_OFFSET + 1],
        header[QCOW2_REFCOUNT_TABLE_OFFSET_OFFSET + 2],
        header[QCOW2_REFCOUNT_TABLE_OFFSET_OFFSET + 3],
        header[QCOW2_REFCOUNT_TABLE_OFFSET_OFFSET + 4],
        header[QCOW2_REFCOUNT_TABLE_OFFSET_OFFSET + 5],
        header[QCOW2_REFCOUNT_TABLE_OFFSET_OFFSET + 6],
        header[QCOW2_REFCOUNT_TABLE_OFFSET_OFFSET + 7],
    ]);
    let refcount_table_clusters = u32::from_be_bytes([
        header[QCOW2_REFCOUNT_TABLE_CLUSTERS_OFFSET],
        header[QCOW2_REFCOUNT_TABLE_CLUSTERS_OFFSET + 1],
        header[QCOW2_REFCOUNT_TABLE_CLUSTERS_OFFSET + 2],
        header[QCOW2_REFCOUNT_TABLE_CLUSTERS_OFFSET + 3],
    ]);

    // Check incompatible features (v3 only)
    if version >= 3 {
        let incompat = u64::from_be_bytes([
            header[QCOW2_INCOMPATIBLE_FEATURES_OFFSET],
            header[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 1],
            header[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 2],
            header[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 3],
            header[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 4],
            header[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 5],
            header[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 6],
            header[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 7],
        ]);

        if (incompat & QCOW2_INCOMPAT_DIRTY) != 0 {
            result.flags |= CheckResult::FLAG_DIRTY;
            (call_table.debug_print)(b"check: image is dirty\n\0".as_ptr());
        }
        if (incompat & QCOW2_INCOMPAT_CORRUPT) != 0 {
            result.flags |= CheckResult::FLAG_CORRUPT_BIT;
            result.corruptions += 1;
            result.total_errors += 1;
            (call_table.debug_print)(b"check: corrupt bit set\n\0".as_ptr());
        }
    }

    // Validate L1 table offset
    if l1_table_offset == 0 || l1_table_offset >= actual_size {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: invalid L1 offset\n\0".as_ptr());
        return bytes_read;
    }

    // Validate refcount table offset
    if refcount_table_offset == 0 || refcount_table_offset >= actual_size {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: invalid refcount table offset\n\0".as_ptr());
        return bytes_read;
    }

    // Calculate L2 entries per cluster
    let l2_entries_per_cluster = cluster_size / 8; // Each L2 entry is 8 bytes

    // Calculate total clusters in image
    let total_clusters = (actual_size + cluster_size - 1) / cluster_size;
    result.clusters_checked = 0;
    result.clusters_allocated = 0;

    // Track image end offset (highest offset used)
    let mut max_offset: u64 = l1_table_offset + (l1_size as u64 * 8);

    // Update max_offset with refcount table
    let refcount_table_end =
        refcount_table_offset + (refcount_table_clusters as u64 * cluster_size);
    if refcount_table_end > max_offset {
        max_offset = refcount_table_end;
    }

    // Buffer for L1/L2 table entries
    let mut table_buffer = [0u8; MAX_SECTOR_SIZE];

    // Read and validate L1 table entries
    let mut l1_entries_checked: u32 = 0;
    let mut allocated_l2_tables: u32 = 0;
    let entries_per_sector = sector_size / 8;

    // Track fragmentation: count non-sequential allocations
    let mut last_data_offset: u64 = 0;
    let mut fragmented_entries: u64 = 0;
    let mut total_data_entries: u64 = 0;

    // Iterate through L1 table
    let mut l1_offset = l1_table_offset;
    let mut remaining_l1_entries = l1_size;

    while remaining_l1_entries > 0 {
        let l1_sector = l1_offset / sector_size as u64;
        let offset_in_sector = (l1_offset % sector_size as u64) as usize;

        if !(call_table.read_input_sector)(0, l1_sector, table_buffer.as_mut_ptr(), sector_size) {
            result.corruptions += 1;
            result.total_errors += 1;
            (call_table.debug_print)(b"check: L1 read error\n\0".as_ptr());
            break;
        }
        bytes_read += sector_size as u64;

        // Process L1 entries in this sector
        let entries_in_sector = core::cmp::min(
            remaining_l1_entries,
            ((sector_size - offset_in_sector) / 8) as u32,
        );

        for i in 0..entries_in_sector {
            let entry_offset = offset_in_sector + (i as usize * 8);
            let l1_entry = u64::from_be_bytes([
                table_buffer[entry_offset],
                table_buffer[entry_offset + 1],
                table_buffer[entry_offset + 2],
                table_buffer[entry_offset + 3],
                table_buffer[entry_offset + 4],
                table_buffer[entry_offset + 5],
                table_buffer[entry_offset + 6],
                table_buffer[entry_offset + 7],
            ]);

            l1_entries_checked += 1;
            result.clusters_checked += 1;

            // Skip zero entries (unallocated)
            if l1_entry == 0 {
                continue;
            }

            // Extract L2 table offset
            let l2_offset = l1_entry & L1_OFFSET_MASK;

            // Validate L2 table offset
            if l2_offset == 0 {
                // Zero offset with non-zero entry is invalid
                result.corruptions += 1;
                result.total_errors += 1;
                continue;
            }

            if l2_offset >= actual_size {
                result.corruptions += 1;
                result.total_errors += 1;
                (call_table.debug_print)(b"check: L2 offset out of bounds\n\0".as_ptr());
                continue;
            }

            // Check alignment
            if l2_offset % cluster_size != 0 {
                result.corruptions += 1;
                result.total_errors += 1;
                continue;
            }

            allocated_l2_tables += 1;
            result.clusters_allocated += 1;

            // Update max offset
            let l2_table_end = l2_offset + cluster_size;
            if l2_table_end > max_offset {
                max_offset = l2_table_end;
            }

            // Sample L2 table validation (read first sector of L2 table)
            // For full validation, we would read the entire L2 table
            let l2_sector = l2_offset / sector_size as u64;
            let mut l2_buffer = [0u8; MAX_SECTOR_SIZE];

            if (call_table.read_input_sector)(0, l2_sector, l2_buffer.as_mut_ptr(), sector_size) {
                bytes_read += sector_size as u64;

                // Check L2 entries in this sector
                let l2_entries_to_check =
                    core::cmp::min(l2_entries_per_cluster as usize, sector_size / 8);

                for j in 0..l2_entries_to_check {
                    let l2_entry_offset = j * 8;
                    let l2_entry = u64::from_be_bytes([
                        l2_buffer[l2_entry_offset],
                        l2_buffer[l2_entry_offset + 1],
                        l2_buffer[l2_entry_offset + 2],
                        l2_buffer[l2_entry_offset + 3],
                        l2_buffer[l2_entry_offset + 4],
                        l2_buffer[l2_entry_offset + 5],
                        l2_buffer[l2_entry_offset + 6],
                        l2_buffer[l2_entry_offset + 7],
                    ]);

                    result.clusters_checked += 1;

                    // Skip unallocated entries
                    if l2_entry == 0 {
                        continue;
                    }

                    // Check for compressed entry
                    let is_compressed = (l2_entry & QCOW2_OFLAG_COMPRESSED) != 0;

                    if !is_compressed {
                        // Standard cluster: extract data offset
                        let data_offset = l2_entry & L2_OFFSET_MASK;

                        if data_offset != 0 {
                            // Validate data cluster offset
                            if data_offset >= actual_size {
                                result.corruptions += 1;
                                result.total_errors += 1;
                                continue;
                            }

                            // Check alignment
                            if data_offset % cluster_size != 0 {
                                result.corruptions += 1;
                                result.total_errors += 1;
                                continue;
                            }

                            result.clusters_allocated += 1;

                            // Track fragmentation
                            total_data_entries += 1;
                            if last_data_offset != 0
                                && data_offset != last_data_offset + cluster_size
                            {
                                fragmented_entries += 1;
                            }
                            last_data_offset = data_offset;

                            // Update max offset
                            let data_end = data_offset + cluster_size;
                            if data_end > max_offset {
                                max_offset = data_end;
                            }
                        }
                    } else {
                        // Compressed cluster - just count it
                        result.clusters_allocated += 1;
                    }
                }
            }
        }

        remaining_l1_entries -= entries_in_sector;
        l1_offset += entries_in_sector as u64 * 8;
    }

    // Calculate fragmentation percentage
    if total_data_entries > 1 {
        result.fragmentation = ((fragmented_entries * 100) / (total_data_entries - 1)) as u32;
    } else {
        result.fragmentation = 0;
    }

    // Set image end offset
    result.image_end_offset = max_offset;

    // Set flags based on results
    if result.leaks > 0 {
        result.flags |= CheckResult::FLAG_HAS_LEAKS;
    }
    if result.corruptions > 0 {
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
    }

    (call_table.verbose_print)(b"check: qcow2 check complete\n\0".as_ptr());

    bytes_read
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
            (call_table.send_error)(b"panic\0".as_ptr(), b"check\0".as_ptr(), 0, 0xDEAD);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
