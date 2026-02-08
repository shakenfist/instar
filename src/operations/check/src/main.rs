//! Check operation: validate image structural integrity.
//!
//! This operation reads the image and validates its internal structures,
//! similar to `qemu-img check`. For QCOW2 images, it verifies:
//! - Header validity (version, cluster_bits, virtual_size)
//! - L1 table entries (offset bounds, alignment)
//! - L2 table entries (full validation across all sectors)
//! - Overlap detection (two L2 entries referencing same host cluster)
//! - Refcount validation (referenced clusters must have refcount > 0)
//! - Leak detection (clusters with refcount > 0 but no reference)
//! - Refcount table and block structure validation
//! - Dirty/corrupt incompatible feature flags (v3 only)
//!
//! Results are sent via protobuf CheckResultMessage over the serial
//! command channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    format_detection::{detect_format_from_header, detect_vhd_footer, QCOW2_MAGIC, VHD_COOKIE},
    CallTable, CheckConfig, CheckResult, ImageFormat, CALL_TABLE_ADDR, MAX_SECTOR_SIZE,
    SCRATCH_MEM_BASE, SCRATCH_MEM_SIZE,
};

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

// L2 table entry flags
const QCOW2_OFLAG_COMPRESSED: u64 = 1 << 62;

// Mask for extracting offset from L1/L2 entries (bits 9-55)
const L1_OFFSET_MASK: u64 = 0x00fffffffffffe00;
const L2_OFFSET_MASK: u64 = 0x00fffffffffffe00;

/// Result of a bitmap_set operation.
enum BitmapSetResult {
    /// Bit was not previously set (no overlap).
    NewBit,
    /// Bit was already set — overlap detected.
    AlreadySet,
    /// Cluster index exceeds bitmap capacity; overlap status unknown.
    BeyondCapacity,
}

/// Set a bit in the overlap-detection bitmap.
///
/// The bitmap lives in scratch memory and tracks which host clusters
/// have been referenced. Each bit corresponds to one host cluster.
///
/// Returns a `BitmapSetResult` distinguishing between "newly set",
/// "already set (overlap)", and "beyond bitmap capacity".
///
/// Safety: callers gate on `can_track` before calling, so
/// `BeyondCapacity` should never be reached in practice. It exists
/// as a defensive measure to prevent silent false-negatives if
/// the call-site guards are ever changed.
unsafe fn bitmap_set(bitmap: *mut u8, bitmap_size: usize, cluster_idx: u64) -> BitmapSetResult {
    let byte_idx = (cluster_idx / 8) as usize;
    let bit_mask = 1u8 << (cluster_idx % 8) as u8;
    if byte_idx >= bitmap_size {
        return BitmapSetResult::BeyondCapacity;
    }
    let byte_ptr = bitmap.add(byte_idx);
    let was_set = (*byte_ptr & bit_mask) != 0;
    *byte_ptr |= bit_mask;
    if was_set {
        BitmapSetResult::AlreadySet
    } else {
        BitmapSetResult::NewBit
    }
}

/// Test whether a bit is set in the overlap-detection bitmap.
///
/// Returns `false` for indices beyond bitmap capacity. This is safe
/// because callers only invoke this when `can_track` is true, which
/// guarantees all valid cluster indices fit within the bitmap.
unsafe fn bitmap_test(bitmap: *const u8, bitmap_size: usize, cluster_idx: u64) -> bool {
    let byte_idx = (cluster_idx / 8) as usize;
    let bit_mask = 1u8 << (cluster_idx % 8) as u8;
    if byte_idx >= bitmap_size {
        return false;
    }
    (*bitmap.add(byte_idx) & bit_mask) != 0
}

/// Read a big-endian u64 from a specific byte offset within the
/// image, using a sector-level cache to minimize I/O.
///
/// `cached_sector` / `cached_buffer` provide a one-sector cache.
/// Set `cached_sector` to `u64::MAX` to invalidate the cache.
unsafe fn read_u64_be_cached(
    call_table: &CallTable,
    byte_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    cached_sector: &mut u64,
    cached_buffer: &mut [u8; MAX_SECTOR_SIZE],
    bytes_read: &mut u64,
) -> Option<u64> {
    let sector = byte_offset / sector_size as u64;
    let off = (byte_offset % sector_size as u64) as usize;
    if off + 8 > sector_size {
        return None; // Entry spans sector boundary
    }
    if sector >= input_capacity {
        return None;
    }
    if *cached_sector != sector {
        if !(call_table.read_input_sector)(0, sector, cached_buffer.as_mut_ptr(), sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;
        *cached_sector = sector;
    }
    Some(u64::from_be_bytes([
        cached_buffer[off],
        cached_buffer[off + 1],
        cached_buffer[off + 2],
        cached_buffer[off + 3],
        cached_buffer[off + 4],
        cached_buffer[off + 5],
        cached_buffer[off + 6],
        cached_buffer[off + 7],
    ]))
}

/// Read a 16-bit big-endian refcount entry from a specific byte
/// offset, using a sector-level cache.
unsafe fn read_u16_be_cached(
    call_table: &CallTable,
    byte_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    cached_sector: &mut u64,
    cached_buffer: &mut [u8; MAX_SECTOR_SIZE],
    bytes_read: &mut u64,
) -> Option<u16> {
    let sector = byte_offset / sector_size as u64;
    let off = (byte_offset % sector_size as u64) as usize;
    if off + 2 > sector_size {
        return None;
    }
    if sector >= input_capacity {
        return None;
    }
    if *cached_sector != sector {
        if !(call_table.read_input_sector)(0, sector, cached_buffer.as_mut_ptr(), sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;
        *cached_sector = sector;
    }
    Some(u16::from_be_bytes([
        cached_buffer[off],
        cached_buffer[off + 1],
    ]))
}

/// Look up the refcount for a host cluster.
///
/// Returns `Some(refcount)` on success, `None` on I/O error.
/// A refcount of 0 means the cluster is not allocated.
unsafe fn lookup_refcount(
    call_table: &CallTable,
    refcount_table_offset: u64,
    refcount_bits: u32,
    cluster_size: u64,
    sector_size: usize,
    input_capacity: u64,
    host_offset: u64,
    reftable_cached_sector: &mut u64,
    reftable_cached_buffer: &mut [u8; MAX_SECTOR_SIZE],
    refblock_cached_sector: &mut u64,
    refblock_cached_buffer: &mut [u8; MAX_SECTOR_SIZE],
    bytes_read: &mut u64,
) -> Option<u64> {
    let cluster_index = host_offset / cluster_size;
    let entries_per_block = (cluster_size * 8) / refcount_bits as u64;
    let refblock_index = cluster_index / entries_per_block;

    // Read refcount table entry (big-endian u64 pointer to
    // refcount block)
    let reftable_byte_off = refblock_index
        .checked_mul(8)
        .and_then(|v| refcount_table_offset.checked_add(v))?;
    let refblock_offset = read_u64_be_cached(
        call_table,
        reftable_byte_off,
        sector_size,
        input_capacity,
        reftable_cached_sector,
        reftable_cached_buffer,
        bytes_read,
    )?;

    if refblock_offset == 0 {
        return Some(0); // Block not allocated = refcount 0
    }

    // Read the individual refcount entry from the block
    let entry_in_block = cluster_index % entries_per_block;
    // Currently only 16-bit refcounts are supported (the
    // overwhelmingly common case). Other widths are treated as
    // I/O errors to avoid silent misinterpretation.
    if refcount_bits == 16 {
        let entry_byte_off = entry_in_block
            .checked_mul(2)
            .and_then(|v| refblock_offset.checked_add(v))?;
        let rc = read_u16_be_cached(
            call_table,
            entry_byte_off,
            sector_size,
            input_capacity,
            refblock_cached_sector,
            refblock_cached_buffer,
            bytes_read,
        )?;
        Some(rc as u64)
    } else {
        // Unsupported refcount width - skip validation rather
        // than risk misreading entries
        None
    }
}

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
    // Quiet mode is handled on the VMM side (suppressing output);
    // the guest operation only needs the unsafe_quirks flag.
    let unsafe_quirks = if config.is_valid() {
        config.unsafe_quirks_enabled()
    } else {
        false
    };

    // Get device parameters (device 0 = primary input)
    let input_capacity = (call_table.get_input_capacity)(0);
    let input_sector_size = (call_table.get_input_sector_size)(0);

    // Calculate actual file size
    let actual_size = input_capacity.saturating_mul(input_sector_size as u64);

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

    // Check QCOW2 magic (big-endian) - use shared constant
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
        // Use checked arithmetic to detect overflow from malicious values
        let desc_end = desc_offset_sectors.checked_mul(512).and_then(|off| {
            desc_size_sectors
                .checked_mul(512)
                .and_then(|sz| off.checked_add(sz))
        });

        match desc_end {
            None => {
                // Overflow in offset calculation indicates corruption
                result.corruptions += 1;
                result.total_errors += 1;
                result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
                return 0;
            }
            Some(end) if end > actual_size => {
                result.corruptions += 1;
                result.total_errors += 1;
                result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
                return 0;
            }
            Some(_) => {} // Valid offset within bounds
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
    let input_capacity = (call_table.get_input_capacity)(0);

    // Validate sector is within file bounds before reading
    if region_table_sector >= input_capacity {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        return bytes_read;
    }

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
///
/// # Buffer requirements
///
/// The footer buffer must be at least 64 bytes (VHD_FOOTER_DISK_TYPE_OFFSET + 4).
/// Callers pass sector-sized buffers (minimum 512 bytes per sector_size validation),
/// so this is always satisfied in practice.
///
/// # Safety invariants
///
/// This function uses defense-in-depth for buffer size validation:
/// - A `debug_assert!` catches programming errors during development
/// - A runtime check handles undersized buffers gracefully in release builds,
///   treating them as corrupted rather than panicking
///
/// The invariant is maintained by callers (`check_vhd`) which read full sectors
/// into `MAX_SECTOR_SIZE` buffers before passing them here.
fn check_vhd_footer(footer: &[u8], result: &mut CheckResult) {
    // Minimum buffer size: disk_type field at offset 60 + 4 bytes = 64 bytes.
    // This is always satisfied since callers use sector-sized buffers (min 512 bytes).
    debug_assert!(
        footer.len() >= VHD_FOOTER_DISK_TYPE_OFFSET + 4,
        "VHD footer buffer too small: {} < {}",
        footer.len(),
        VHD_FOOTER_DISK_TYPE_OFFSET + 4
    );

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
/// - Header magic, version, and cluster_bits range
/// - L1 table entries (offset bounds and cluster alignment)
/// - L2 table entries (full validation, all sectors)
/// - Overlap detection (duplicate host cluster references)
/// - Refcount validation (referenced clusters have refcount > 0)
/// - Leak detection (refcount > 0 but no reference)
/// - Dirty/corrupt incompatible feature flags (v3 only)
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
    let _virtual_size = u64::from_be_bytes([
        header[QCOW2_SIZE_OFFSET],
        header[QCOW2_SIZE_OFFSET + 1],
        header[QCOW2_SIZE_OFFSET + 2],
        header[QCOW2_SIZE_OFFSET + 3],
        header[QCOW2_SIZE_OFFSET + 4],
        header[QCOW2_SIZE_OFFSET + 5],
        header[QCOW2_SIZE_OFFSET + 6],
        header[QCOW2_SIZE_OFFSET + 7],
    ]);

    // Refcount bits: v2 always 16-bit, v3 reads refcount_order
    let refcount_bits: u32 = if version >= 3 {
        let refcount_order = u32::from_be_bytes([
            header[QCOW2_REFCOUNT_ORDER_OFFSET],
            header[QCOW2_REFCOUNT_ORDER_OFFSET + 1],
            header[QCOW2_REFCOUNT_ORDER_OFFSET + 2],
            header[QCOW2_REFCOUNT_ORDER_OFFSET + 3],
        ]);
        if refcount_order > 6 {
            // refcount_order > 6 means refcount_bits > 64 which
            // is invalid
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: invalid refcount_order\n\0".as_ptr());
            return bytes_read;
        }
        1u32 << refcount_order
    } else {
        16 // v2 always uses 16-bit refcounts
    };

    if refcount_bits != 16 {
        (call_table.debug_print)(
            b"check: refcount_bits != 16, skipping refcount/leak validation\n\0".as_ptr(),
        );
    }

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

    // Validate l1_size
    const MAX_L1_ENTRIES: u32 = 16 * 1024 * 1024;
    let l1_table_size_bytes = (l1_size as u64).saturating_mul(8);
    if l1_size > MAX_L1_ENTRIES || l1_table_size_bytes > actual_size {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: l1_size exceeds bounds\n\0".as_ptr());
        return bytes_read;
    }

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
    let l2_entries_per_cluster = cluster_size / 8;

    // Number of sectors needed to read one full L2 table
    let sectors_per_l2 = ((cluster_size as usize) + sector_size - 1) / sector_size;

    result.clusters_checked = 0;
    result.clusters_allocated = 0;

    // Track image end offset (highest offset used)
    let mut max_offset: u64 = match l1_table_offset.checked_add((l1_size as u64).saturating_mul(8))
    {
        Some(v) => v,
        None => {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: L1 table end overflow\n\0".as_ptr());
            return bytes_read;
        }
    };

    // Update max_offset with refcount table
    let refcount_table_size = (refcount_table_clusters as u64).saturating_mul(cluster_size);
    if let Some(rte) = refcount_table_offset.checked_add(refcount_table_size) {
        if rte > max_offset {
            max_offset = rte;
        }
    } else {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: refcount table end overflow\n\0".as_ptr());
        return bytes_read;
    }

    // ---- Initialize overlap-detection bitmap ----
    let bitmap_size = SCRATCH_MEM_SIZE;
    let bitmap = SCRATCH_MEM_BASE as *mut u8;
    // Zero the bitmap
    core::ptr::write_bytes(bitmap, 0, bitmap_size);

    let max_trackable = (bitmap_size as u64) * 8;
    let total_host_clusters = (actual_size + cluster_size - 1) / cluster_size;
    let can_track = total_host_clusters <= max_trackable;

    (call_table.verbose_print)(b"check: bitmap initialized\n\0".as_ptr());

    // ---- Mark metadata clusters in bitmap ----
    // Header cluster (cluster 0)
    if can_track {
        bitmap_set(bitmap, bitmap_size, 0);
    }
    // L1 table clusters
    if can_track {
        let l1_start_cluster = l1_table_offset / cluster_size;
        let l1_clusters = (l1_table_size_bytes + cluster_size - 1) / cluster_size;
        for c in 0..l1_clusters {
            bitmap_set(bitmap, bitmap_size, l1_start_cluster + c);
        }
    }
    // Refcount table clusters
    if can_track {
        let rt_start_cluster = refcount_table_offset / cluster_size;
        for c in 0..(refcount_table_clusters as u64) {
            bitmap_set(bitmap, bitmap_size, rt_start_cluster + c);
        }
    }

    // ---- Refcount cache buffers ----
    let mut reftable_cached_sector: u64 = u64::MAX;
    let mut reftable_cached_buffer = [0u8; MAX_SECTOR_SIZE];
    let mut refblock_cached_sector: u64 = u64::MAX;
    let mut refblock_cached_buffer = [0u8; MAX_SECTOR_SIZE];

    // Buffer for L1 table entries
    let mut table_buffer = [0u8; MAX_SECTOR_SIZE];

    // Track fragmentation
    let mut last_data_offset: u64 = 0;
    let mut fragmented_entries: u64 = 0;
    let mut total_data_entries: u64 = 0;

    // Iterate through L1 table
    let mut l1_offset = l1_table_offset;
    let mut remaining_l1_entries = l1_size;
    let input_capacity = actual_size / sector_size as u64;

    while remaining_l1_entries > 0 {
        let l1_sector = l1_offset / sector_size as u64;
        let offset_in_sector = (l1_offset % sector_size as u64) as usize;

        if l1_sector >= input_capacity {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: L1 sector out of bounds\n\0".as_ptr());
            break;
        }

        if !(call_table.read_input_sector)(0, l1_sector, table_buffer.as_mut_ptr(), sector_size) {
            result.corruptions += 1;
            result.total_errors += 1;
            (call_table.debug_print)(b"check: L1 read error\n\0".as_ptr());
            break;
        }
        bytes_read += sector_size as u64;

        let entries_in_sector = core::cmp::min(
            remaining_l1_entries,
            ((sector_size - offset_in_sector) / 8) as u32,
        );

        for i in 0..entries_in_sector {
            let eo = offset_in_sector + (i as usize * 8);
            let l1_entry = u64::from_be_bytes([
                table_buffer[eo],
                table_buffer[eo + 1],
                table_buffer[eo + 2],
                table_buffer[eo + 3],
                table_buffer[eo + 4],
                table_buffer[eo + 5],
                table_buffer[eo + 6],
                table_buffer[eo + 7],
            ]);

            result.clusters_checked += 1;

            if l1_entry == 0 {
                continue;
            }

            let l2_offset = l1_entry & L1_OFFSET_MASK;

            if l2_offset == 0 {
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

            if l2_offset % cluster_size != 0 {
                result.corruptions += 1;
                result.total_errors += 1;
                continue;
            }

            result.clusters_allocated += 1;

            // Overlap check for L2 table cluster
            if can_track {
                let l2_cidx = l2_offset / cluster_size;
                if matches!(
                    bitmap_set(bitmap, bitmap_size, l2_cidx),
                    BitmapSetResult::AlreadySet
                ) {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    (call_table.debug_print)(b"check: L2 table cluster overlap\n\0".as_ptr());
                }
            }

            // Refcount check for L2 table cluster
            if let Some(rc) = lookup_refcount(
                call_table,
                refcount_table_offset,
                refcount_bits,
                cluster_size,
                sector_size,
                input_capacity,
                l2_offset,
                &mut reftable_cached_sector,
                &mut reftable_cached_buffer,
                &mut refblock_cached_sector,
                &mut refblock_cached_buffer,
                &mut bytes_read,
            ) {
                if rc == 0 {
                    result.refcount_errors += 1;
                    result.total_errors += 1;
                }
                // Mark refcount block cluster in bitmap too
                let entries_per_block = (cluster_size * 8) / refcount_bits as u64;
                let rb_idx = (l2_offset / cluster_size) / entries_per_block;
                let rb_byte_off = refcount_table_offset + rb_idx * 8;
                if let Some(rb_off) = read_u64_be_cached(
                    call_table,
                    rb_byte_off,
                    sector_size,
                    input_capacity,
                    &mut reftable_cached_sector,
                    &mut reftable_cached_buffer,
                    &mut bytes_read,
                ) {
                    if rb_off != 0 && can_track {
                        bitmap_set(bitmap, bitmap_size, rb_off / cluster_size);
                    }
                }
            }

            // Update max offset
            if let Some(l2e) = l2_offset.checked_add(cluster_size) {
                if l2e > max_offset {
                    max_offset = l2e;
                }
            } else {
                result.corruptions += 1;
                result.total_errors += 1;
                continue;
            }

            // ---- Full L2 table validation ----
            let l2_base_sector = l2_offset / sector_size as u64;
            let mut l2_buffer = [0u8; MAX_SECTOR_SIZE];
            let mut l2_entries_remaining = l2_entries_per_cluster;

            for s in 0..sectors_per_l2 {
                let l2_sector = l2_base_sector + s as u64;
                if l2_sector >= input_capacity {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    (call_table.debug_print)(b"check: L2 sector OOB\n\0".as_ptr());
                    break;
                }

                if !(call_table.read_input_sector)(
                    0,
                    l2_sector,
                    l2_buffer.as_mut_ptr(),
                    sector_size,
                ) {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    break;
                }
                bytes_read += sector_size as u64;

                let entries_this_sector =
                    core::cmp::min(l2_entries_remaining, (sector_size / 8) as u64);

                for j in 0..entries_this_sector as usize {
                    let off = j * 8;
                    let l2e = u64::from_be_bytes([
                        l2_buffer[off],
                        l2_buffer[off + 1],
                        l2_buffer[off + 2],
                        l2_buffer[off + 3],
                        l2_buffer[off + 4],
                        l2_buffer[off + 5],
                        l2_buffer[off + 6],
                        l2_buffer[off + 7],
                    ]);

                    result.clusters_checked += 1;

                    if l2e == 0 {
                        continue;
                    }

                    let compressed = (l2e & QCOW2_OFLAG_COMPRESSED) != 0;

                    if !compressed {
                        let data_off = l2e & L2_OFFSET_MASK;
                        if data_off == 0 {
                            continue;
                        }

                        if data_off >= actual_size {
                            result.corruptions += 1;
                            result.total_errors += 1;
                            continue;
                        }

                        if data_off % cluster_size != 0 {
                            result.corruptions += 1;
                            result.total_errors += 1;
                            continue;
                        }

                        result.clusters_allocated += 1;

                        // Overlap detection
                        if can_track {
                            let cidx = data_off / cluster_size;
                            if matches!(
                                bitmap_set(bitmap, bitmap_size, cidx),
                                BitmapSetResult::AlreadySet
                            ) {
                                result.corruptions += 1;
                                result.total_errors += 1;
                                (call_table.debug_print)(b"check: overlap\n\0".as_ptr());
                            }
                        }

                        // Refcount validation
                        if let Some(rc) = lookup_refcount(
                            call_table,
                            refcount_table_offset,
                            refcount_bits,
                            cluster_size,
                            sector_size,
                            input_capacity,
                            data_off,
                            &mut reftable_cached_sector,
                            &mut reftable_cached_buffer,
                            &mut refblock_cached_sector,
                            &mut refblock_cached_buffer,
                            &mut bytes_read,
                        ) {
                            if rc == 0 {
                                result.refcount_errors += 1;
                                result.total_errors += 1;
                            }
                        }

                        // Fragmentation tracking
                        total_data_entries += 1;
                        if last_data_offset != 0 {
                            if let Some(exp) = last_data_offset.checked_add(cluster_size) {
                                if data_off != exp {
                                    fragmented_entries += 1;
                                }
                            } else {
                                fragmented_entries += 1;
                            }
                        }
                        last_data_offset = data_off;

                        // Update max offset
                        if let Some(de) = data_off.checked_add(cluster_size) {
                            if de > max_offset {
                                max_offset = de;
                            }
                        } else {
                            result.corruptions += 1;
                            result.total_errors += 1;
                        }
                    } else {
                        // Compressed cluster
                        result.clusters_allocated += 1;
                    }
                }

                l2_entries_remaining -= entries_this_sector;
            }
        }

        remaining_l1_entries -= entries_in_sector;
        l1_offset += entries_in_sector as u64 * 8;
    }

    (call_table.verbose_print)(b"check: L1/L2 walk complete\n\0".as_ptr());

    // ---- Leak detection: scan refcount blocks ----
    if can_track && refcount_bits == 16 {
        (call_table.verbose_print)(b"check: scanning refcounts for leaks\n\0".as_ptr());

        let entries_per_block = (cluster_size * 8) / refcount_bits as u64;
        let reftable_entries = {
            let raw = (refcount_table_clusters as u64).saturating_mul(cluster_size / 8);
            let max_entries = actual_size / 8;
            core::cmp::min(raw, max_entries)
        };
        let mut leak_scan_buffer = [0u8; MAX_SECTOR_SIZE];

        // First pass: mark all refcount block clusters in the bitmap
        // before scanning entries, so that refcount blocks covering
        // other refcount blocks are not falsely reported as leaks.
        for rt_idx in 0..reftable_entries {
            let rt_byte_off = match rt_idx
                .checked_mul(8)
                .and_then(|v| refcount_table_offset.checked_add(v))
            {
                Some(off) => off,
                None => break,
            };
            if rt_byte_off + 8 > actual_size {
                break;
            }
            let refblock_off = match read_u64_be_cached(
                call_table,
                rt_byte_off,
                sector_size,
                input_capacity,
                &mut reftable_cached_sector,
                &mut reftable_cached_buffer,
                &mut bytes_read,
            ) {
                Some(v) => v,
                None => break,
            };

            if refblock_off != 0 {
                bitmap_set(bitmap, bitmap_size, refblock_off / cluster_size);
            }
        }

        // Second pass: scan individual refcount entries for leaks.
        for rt_idx in 0..reftable_entries {
            // Read refcount table entry
            let rt_byte_off = match rt_idx
                .checked_mul(8)
                .and_then(|v| refcount_table_offset.checked_add(v))
            {
                Some(off) => off,
                None => break,
            };
            if rt_byte_off + 8 > actual_size {
                break;
            }
            let refblock_off = match read_u64_be_cached(
                call_table,
                rt_byte_off,
                sector_size,
                input_capacity,
                &mut reftable_cached_sector,
                &mut reftable_cached_buffer,
                &mut bytes_read,
            ) {
                Some(v) => v,
                None => break,
            };

            if refblock_off == 0 {
                continue;
            }

            // Read each sector of this refcount block
            let refblock_base_sector = refblock_off / sector_size as u64;
            let sectors_per_block = ((cluster_size as usize) + sector_size - 1) / sector_size;
            let mut entries_remaining = entries_per_block;

            for s in 0..sectors_per_block {
                let sec = refblock_base_sector + s as u64;
                if sec >= input_capacity {
                    break;
                }
                if !(call_table.read_input_sector)(
                    0,
                    sec,
                    leak_scan_buffer.as_mut_ptr(),
                    sector_size,
                ) {
                    break;
                }
                bytes_read += sector_size as u64;

                let entries_this = core::cmp::min(entries_remaining, (sector_size / 2) as u64);

                for e in 0..entries_this as usize {
                    let off = e * 2;
                    let rc = u16::from_be_bytes([leak_scan_buffer[off], leak_scan_buffer[off + 1]]);

                    if rc > 0 {
                        let cidx = rt_idx * entries_per_block
                            + (s as u64) * ((sector_size / 2) as u64)
                            + e as u64;
                        if !bitmap_test(bitmap, bitmap_size, cidx) {
                            result.leaks += 1;
                            result.total_errors += 1;
                        }
                    }
                }

                entries_remaining -= entries_this;
            }
        }

        (call_table.verbose_print)(b"check: leak scan complete\n\0".as_ptr());
    } else if refcount_bits != 16 {
        (call_table.verbose_print)(
            b"check: skipping leak scan (non-16-bit refcounts)\n\0".as_ptr(),
        );
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
    if result.refcount_errors > 0 {
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
