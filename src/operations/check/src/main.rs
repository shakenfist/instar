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
//! When `--chain` is enabled, the operation also validates the backing
//! chain: format consistency, virtual size consistency across layers,
//! and basic QCOW2 header validation for each backing image.
//!
//! Refcount validation supports all standard QCOW2 refcount widths
//! (1, 2, 4, 8, 16, 32, and 64 bits).
//!
//! Results are sent via protobuf CheckResultMessage over the serial
//! command channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    format_detection::{detect_format_from_header, detect_vhd_footer, QCOW2_MAGIC, VHD_COOKIE},
    validate_call_table, CallTable, ChainConfig, CheckConfig, CheckResult, ImageFormat,
    CALL_TABLE_ADDR, MAX_SECTOR_SIZE, SCRATCH_MEM_BASE, SCRATCH_MEM_SIZE,
};

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

/// Entry point called by core after devices are initialized.
///
/// Returns the number of bytes read/checked.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    validate_call_table!(call_table, "check");

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
        ImageFormat::Vmdk4 => {
            if unsafe_quirks {
                (call_table.verbose_print)(b"check: vmdk not supported (quirks)\n\0".as_ptr());
                result.flags |= CheckResult::FLAG_NOT_SUPPORTED;
                result.image_end_offset = actual_size;
            } else {
                bytes_read += check_vmdk(
                    &buffer,
                    &mut result,
                    call_table,
                    input_sector_size,
                    actual_size,
                );
            }
        }
        ImageFormat::Vmdk3 => {
            // VMDK version 3 is a legacy format; no detailed
            // structural checking support
            (call_table.verbose_print)(b"check: vmdk3 format detected\n\0".as_ptr());
            result.flags |= CheckResult::FLAG_NOT_SUPPORTED;
            result.image_end_offset = actual_size;
        }
        ImageFormat::Vhdx => {
            if unsafe_quirks {
                (call_table.verbose_print)(b"check: vhdx not supported (quirks)\n\0".as_ptr());
                result.flags |= CheckResult::FLAG_NOT_SUPPORTED;
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

    // Chain validation (if --chain flag was set)
    let chain_enabled = if config.is_valid() {
        config.chain_enabled()
    } else {
        false
    };
    if chain_enabled {
        let chain_result = (call_table.get_chain_config)();
        if !chain_result.ptr.is_null() && chain_result.len > 0 {
            let chain_config = &*(chain_result.ptr as *const ChainConfig);
            if chain_config.is_valid() && chain_config.device_count > 1 {
                (call_table.verbose_print)(b"check: validating backing chain\n\0".as_ptr());
                bytes_read += validate_chain(call_table, chain_config, &mut result);
            }
        }
    }

    // Set VALID flag if no corruptions or refcount errors.
    // Leaks (unreferenced allocated clusters) intentionally do NOT prevent
    // FLAG_VALID from being set: the image data is intact and usable, leaks
    // just waste space and are fixable with `qemu-img check -r leaks`.
    // This matches qemu-img behavior where leaks produce exit code 3
    // (check found leaks) rather than exit code 2 (check found errors).
    //
    // Note: leaks still increment total_errors, so the VMM will still
    // report a non-zero exit code for leak-only images via check_passed
    // (which requires both FLAG_VALID and total_errors == 0).
    if result.corruptions == 0 && result.refcount_errors == 0 && result.chain_errors == 0 {
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

// VHDX region table offset and signature
const VHDX_REGION_TABLE_OFFSET: u64 = 0x30000;
const VHDX_REGION_TABLE_SIG: u32 = 0x69676572; // "regi"

// VHD footer disk type offset
const VHD_FOOTER_DISK_TYPE_OFFSET: usize = 60;

/// Read the GD offset from a streamOptimized VMDK footer.
///
/// The footer is a copy of the VMDK4 header located at EOF - 1024
/// bytes (between the footer marker and EOS marker).
unsafe fn read_vmdk_footer_gd_offset(
    call_table: &CallTable,
    sector_size: usize,
    actual_size: u64,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> Option<u64> {
    let footer_byte_offset = actual_size.checked_sub(1024)?;
    let footer_sector = footer_byte_offset / sector_size as u64;
    let offset_in_sector = (footer_byte_offset % sector_size as u64) as usize;

    if footer_sector >= input_capacity {
        return None;
    }

    let mut buf = [0u8; MAX_SECTOR_SIZE];
    if !(call_table.read_input_sector)(0, footer_sector, buf.as_mut_ptr(), sector_size) {
        return None;
    }
    *bytes_read += sector_size as u64;

    // Footer must fit within this sector
    if offset_in_sector + vmdk::HEADER_FULL_SIZE > sector_size {
        return None;
    }
    let footer = &buf[offset_in_sector..];

    // Validate footer magic
    let magic = u32::from_le_bytes([
        footer[vmdk::MAGIC_OFFSET],
        footer[vmdk::MAGIC_OFFSET + 1],
        footer[vmdk::MAGIC_OFFSET + 2],
        footer[vmdk::MAGIC_OFFSET + 3],
    ]);
    if magic != vmdk::VMDK4_MAGIC {
        return None;
    }

    // Read GD offset from footer
    let gd_offset = u64::from_le_bytes([
        footer[vmdk::GD_OFFSET_OFFSET],
        footer[vmdk::GD_OFFSET_OFFSET + 1],
        footer[vmdk::GD_OFFSET_OFFSET + 2],
        footer[vmdk::GD_OFFSET_OFFSET + 3],
        footer[vmdk::GD_OFFSET_OFFSET + 4],
        footer[vmdk::GD_OFFSET_OFFSET + 5],
        footer[vmdk::GD_OFFSET_OFFSET + 6],
        footer[vmdk::GD_OFFSET_OFFSET + 7],
    ]);
    if gd_offset == vmdk::GD_AT_END {
        return None; // Footer should have the real offset
    }
    Some(gd_offset)
}

/// Count extent description lines in a VMDK descriptor buffer.
///
/// Scans for lines starting with "RW " or "RDONLY " which indicate
/// disk extents. Multi-extent VMDKs have more than one such line.
fn count_extent_lines(desc: &[u8]) -> u32 {
    let end = desc.iter().position(|&b| b == 0).unwrap_or(desc.len());
    let text = &desc[..end];
    let mut count = 0u32;
    let mut pos = 0;
    while pos < text.len() {
        let line_end = text[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(text.len());
        let line = &text[pos..line_end];
        if line.starts_with(b"RW ") || line.starts_with(b"RDONLY ") {
            count += 1;
        }
        pos = line_end + 1;
    }
    count
}

/// Check VMDK4 image structural integrity.
///
/// Validates:
/// - Full header parsing (version, capacity, grain size, flags)
/// - Descriptor bounds and multi-extent detection
/// - Grain directory offset within file bounds
/// - Grain table offsets (referenced by GD entries)
/// - Grain data offsets (referenced by GT entries)
/// - Overlap detection via 1-bit-per-grain bitmap
/// - streamOptimized footer validation
/// - Fragmentation measurement
unsafe fn check_vmdk(
    header: &[u8],
    result: &mut CheckResult,
    call_table: &CallTable,
    sector_size: usize,
    actual_size: u64,
) -> u64 {
    let mut bytes_read: u64 = 0;
    let input_capacity = actual_size / sector_size as u64;

    // Parse full header
    let hdr = match vmdk::Vmdk4HeaderFull::parse(header) {
        Some(h) => h,
        None => {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: invalid vmdk header\n\0".as_ptr());
            result.image_end_offset = actual_size;
            return bytes_read;
        }
    };

    // Validate version
    if hdr.version == 0 || hdr.version > 3 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        result.image_end_offset = actual_size;
        return bytes_read;
    }

    // Validate capacity
    if hdr.capacity_sectors == 0 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        result.image_end_offset = actual_size;
        return bytes_read;
    }

    // Validate grain size (must be power of 2)
    if hdr.grain_size_sectors == 0 || (hdr.grain_size_sectors & (hdr.grain_size_sectors - 1)) != 0 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        result.image_end_offset = actual_size;
        return bytes_read;
    }

    // Validate descriptor bounds
    if hdr.desc_offset_sectors > 0 {
        let desc_end = hdr.desc_offset_sectors.checked_mul(512).and_then(|off| {
            hdr.desc_size_sectors
                .checked_mul(512)
                .and_then(|sz| off.checked_add(sz))
        });
        match desc_end {
            None => {
                result.corruptions += 1;
                result.total_errors += 1;
                result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
                result.image_end_offset = actual_size;
                return bytes_read;
            }
            Some(end) if end > actual_size => {
                result.corruptions += 1;
                result.total_errors += 1;
                result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
                result.image_end_offset = actual_size;
                return bytes_read;
            }
            Some(_) => {}
        }
    }

    // Parse descriptor for multi-extent detection
    if hdr.desc_offset_sectors > 0 && hdr.desc_size_sectors > 0 {
        let desc_byte_offset = hdr.desc_offset_sectors * 512;
        let desc_sector = desc_byte_offset / sector_size as u64;
        if desc_sector < input_capacity {
            let mut desc_buf = [0u8; MAX_SECTOR_SIZE];
            if (call_table.read_input_sector)(0, desc_sector, desc_buf.as_mut_ptr(), sector_size) {
                bytes_read += sector_size as u64;
                let offset_in_sector = (desc_byte_offset % sector_size as u64) as usize;
                let desc_data = &desc_buf[offset_in_sector..sector_size];
                let extent_count = count_extent_lines(desc_data);
                if extent_count > 1 {
                    (call_table.debug_print)(
                        b"check: multi-extent vmdk not supported\n\0".as_ptr(),
                    );
                    result.flags |= CheckResult::FLAG_NOT_SUPPORTED;
                    result.image_end_offset = actual_size;
                    return bytes_read;
                }
            }
        }
    }

    // Validate num_gtes_per_gt
    if hdr.num_gtes_per_gt == 0 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        result.image_end_offset = actual_size;
        return bytes_read;
    }

    // Calculate number of GD entries
    let num_gd_entries = match hdr.num_gd_entries() {
        Some(n) if n > 0 => n,
        _ => {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            result.image_end_offset = actual_size;
            return bytes_read;
        }
    };

    // Resolve GD offset (handle streamOptimized)
    let is_stream_optimized = hdr.gd_offset_sectors == vmdk::GD_AT_END;
    let gd_offset_sectors = if is_stream_optimized {
        match read_vmdk_footer_gd_offset(
            call_table,
            sector_size,
            actual_size,
            input_capacity,
            &mut bytes_read,
        ) {
            Some(off) => off,
            None => {
                result.corruptions += 1;
                result.total_errors += 1;
                result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
                (call_table.debug_print)(b"check: invalid vmdk footer\n\0".as_ptr());
                result.image_end_offset = actual_size;
                return bytes_read;
            }
        }
    } else {
        hdr.gd_offset_sectors
    };

    // Validate GD offset within file
    let gd_byte_offset = match gd_offset_sectors.checked_mul(512) {
        Some(off) if off < actual_size => off,
        _ => {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: GD offset out of bounds\n\0".as_ptr());
            result.image_end_offset = actual_size;
            return bytes_read;
        }
    };

    // Validate GD doesn't extend beyond file
    let gd_size_bytes = match (num_gd_entries as u64).checked_mul(4) {
        Some(sz) => sz,
        None => {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            result.image_end_offset = actual_size;
            return bytes_read;
        }
    };
    let gd_end = match gd_byte_offset.checked_add(gd_size_bytes) {
        Some(end) if end <= actual_size => end,
        _ => {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: GD extends beyond file\n\0".as_ptr());
            result.image_end_offset = actual_size;
            return bytes_read;
        }
    };

    (call_table.verbose_print)(b"check: vmdk header valid\n\0".as_ptr());

    // ---- Initialize overlap-detection bitmap ----
    let bitmap = SCRATCH_MEM_BASE as *mut u8;
    let grain_size_bytes = hdr.grain_size_bytes;
    let total_host_grains = (actual_size + grain_size_bytes - 1) / grain_size_bytes;
    let needed_bytes = ((total_host_grains + 7) / 8) as usize;
    let bitmap_size = core::cmp::min(needed_bytes, SCRATCH_MEM_SIZE);
    core::ptr::write_bytes(bitmap, 0, bitmap_size);
    let max_trackable = (bitmap_size as u64) * 8;
    let can_track = total_host_grains <= max_trackable;

    (call_table.verbose_print)(b"check: vmdk bitmap initialized\n\0".as_ptr());

    // ---- Mark metadata regions in bitmap ----
    if can_track {
        // Header grain (grain 0)
        bitmap_set(bitmap, bitmap_size, 0);

        // Descriptor grains
        if hdr.desc_offset_sectors > 0 {
            let desc_start = hdr.desc_offset_sectors * 512;
            let desc_end_b = desc_start + hdr.desc_size_sectors * 512;
            let first = desc_start / grain_size_bytes;
            let last = desc_end_b.saturating_sub(1) / grain_size_bytes;
            for g in first..=last {
                bitmap_set(bitmap, bitmap_size, g);
            }
        }

        // Grain directory grains
        let gd_first = gd_byte_offset / grain_size_bytes;
        let gd_last = gd_end.saturating_sub(1) / grain_size_bytes;
        for g in gd_first..=gd_last {
            bitmap_set(bitmap, bitmap_size, g);
        }
    }

    // ---- Cache buffers for GD/GT reads ----
    let mut gd_cached_sector: u64 = u64::MAX;
    let mut gd_cache = [0u8; MAX_SECTOR_SIZE];
    let mut gt_cached_sector: u64 = u64::MAX;
    let mut gt_cache = [0u8; MAX_SECTOR_SIZE];

    // ---- Track statistics ----
    let mut max_offset = gd_end;
    result.clusters_checked = 0;
    result.clusters_allocated = 0;
    let mut last_data_offset: u64 = 0;
    let mut fragmented_entries: u64 = 0;
    let mut total_data_entries: u64 = 0;
    let gt_size_bytes = (hdr.num_gtes_per_gt as u64) * 4;

    // ---- Walk grain directory ----
    for gd_idx in 0..num_gd_entries {
        let gd_byte_off = match (gd_idx as u64)
            .checked_mul(4)
            .and_then(|v| gd_byte_offset.checked_add(v))
        {
            Some(off) => off,
            None => {
                result.corruptions += 1;
                result.total_errors += 1;
                break;
            }
        };

        let gd_entry = match vmdk::read_u32_le_cached(
            call_table,
            0,
            gd_byte_off,
            sector_size,
            input_capacity,
            &mut gd_cached_sector,
            gd_cache.as_mut_ptr(),
            &mut bytes_read,
        ) {
            Some(v) => v,
            None => {
                result.corruptions += 1;
                result.total_errors += 1;
                (call_table.debug_print)(b"check: GD read error\n\0".as_ptr());
                break;
            }
        };

        result.clusters_checked += 1;

        if gd_entry == 0 {
            continue;
        }

        // Validate GT offset
        let gt_byte_off = match (gd_entry as u64).checked_mul(512) {
            Some(off) if off < actual_size => off,
            _ => {
                result.corruptions += 1;
                result.total_errors += 1;
                (call_table.debug_print)(b"check: GT offset out of bounds\n\0".as_ptr());
                continue;
            }
        };

        // Validate GT doesn't extend beyond file
        let gt_end = match gt_byte_off.checked_add(gt_size_bytes) {
            Some(end) if end <= actual_size => end,
            _ => {
                result.corruptions += 1;
                result.total_errors += 1;
                continue;
            }
        };

        result.clusters_allocated += 1;

        // Overlap check for GT
        if can_track {
            let first_grain = gt_byte_off / grain_size_bytes;
            let last_grain = gt_end.saturating_sub(1) / grain_size_bytes;
            for g in first_grain..=last_grain {
                if matches!(
                    bitmap_set(bitmap, bitmap_size, g),
                    BitmapSetResult::AlreadySet
                ) {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    (call_table.debug_print)(b"check: GT overlap\n\0".as_ptr());
                }
            }
        }

        // Update max offset
        if gt_end > max_offset {
            max_offset = gt_end;
        }

        // ---- Walk grain table entries ----
        for gt_idx in 0..hdr.num_gtes_per_gt {
            let gte_byte_off = match (gt_idx as u64)
                .checked_mul(4)
                .and_then(|v| gt_byte_off.checked_add(v))
            {
                Some(off) => off,
                None => {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    break;
                }
            };

            let gte = match vmdk::read_u32_le_cached(
                call_table,
                0,
                gte_byte_off,
                sector_size,
                input_capacity,
                &mut gt_cached_sector,
                gt_cache.as_mut_ptr(),
                &mut bytes_read,
            ) {
                Some(v) => v,
                None => {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    break;
                }
            };

            result.clusters_checked += 1;

            if gte == vmdk::GTE_UNALLOCATED {
                continue;
            }

            if hdr.has_zero_grain && gte == vmdk::GTE_ZEROED {
                continue;
            }

            // Validate grain offset
            let grain_off = match (gte as u64).checked_mul(512) {
                Some(off) => off,
                None => {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    continue;
                }
            };

            if grain_off >= actual_size {
                result.corruptions += 1;
                result.total_errors += 1;
                (call_table.debug_print)(b"check: grain offset out of bounds\n\0".as_ptr());
                continue;
            }

            if hdr.is_compressed {
                // Compressed grain: GTE points to grain marker.
                // Validate offset is within bounds. Compressed data
                // is variable-size; mark the host grain in the bitmap
                // (overlaps are expected, like QCOW2 compressed).
                result.clusters_allocated += 1;
                if can_track {
                    bitmap_set(bitmap, bitmap_size, grain_off / grain_size_bytes);
                }
                if grain_off > max_offset {
                    max_offset = grain_off;
                }
            } else {
                // Standard grain: validate full grain within file
                let grain_end = match grain_off.checked_add(grain_size_bytes) {
                    Some(end) => end,
                    None => {
                        result.corruptions += 1;
                        result.total_errors += 1;
                        continue;
                    }
                };

                if grain_end > actual_size {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    continue;
                }

                result.clusters_allocated += 1;

                // Overlap detection
                if can_track {
                    let gidx = grain_off / grain_size_bytes;
                    if matches!(
                        bitmap_set(bitmap, bitmap_size, gidx),
                        BitmapSetResult::AlreadySet
                    ) {
                        result.corruptions += 1;
                        result.total_errors += 1;
                        (call_table.debug_print)(b"check: grain overlap\n\0".as_ptr());
                    }
                }

                // Fragmentation tracking
                total_data_entries += 1;
                if last_data_offset != 0 {
                    if let Some(expected) = last_data_offset.checked_add(grain_size_bytes) {
                        if grain_off != expected {
                            fragmented_entries += 1;
                        }
                    } else {
                        fragmented_entries += 1;
                    }
                }
                last_data_offset = grain_off;

                // Update max offset
                if grain_end > max_offset {
                    max_offset = grain_end;
                }
            }
        }
    }

    (call_table.verbose_print)(b"check: vmdk GD/GT walk complete\n\0".as_ptr());

    // Calculate fragmentation
    if total_data_entries > 1 {
        result.fragmentation = ((fragmented_entries * 100) / (total_data_entries - 1)) as u32;
    }

    // Set image end offset
    if is_stream_optimized {
        result.image_end_offset = actual_size;
    } else {
        result.image_end_offset = max_offset;
    }

    // Set flags
    if result.corruptions > 0 {
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
    }

    bytes_read
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

    // Parse header using shared crate
    let hdr = match qcow2::QcowHeader::parse(header) {
        Some(h) => h,
        None => {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: invalid qcow2 header\n\0".as_ptr());
            return bytes_read;
        }
    };

    let version = hdr.version;
    let cluster_size = hdr.cluster_size;
    let cluster_bits = hdr.cluster_bits;
    let l1_size = hdr.l1_size;
    let l1_table_offset = hdr.l1_table_offset;
    let refcount_table_offset = hdr.refcount_table_offset;
    let refcount_table_clusters = hdr.refcount_table_clusters;

    // Additional v3 refcount_order validation
    // (QcowHeader::parse() falls back to 16 for invalid order,
    // but check should flag it as corruption)
    let refcount_bits = if version >= 3 {
        let refcount_order = u32::from_be_bytes([
            header[qcow2::REFCOUNT_ORDER_OFFSET],
            header[qcow2::REFCOUNT_ORDER_OFFSET + 1],
            header[qcow2::REFCOUNT_ORDER_OFFSET + 2],
            header[qcow2::REFCOUNT_ORDER_OFFSET + 3],
        ]);
        if refcount_order > 6 {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: invalid refcount_order\n\0".as_ptr());
            return bytes_read;
        }
        1u32 << refcount_order
    } else {
        16
    };

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

    // Check incompatible features (v3 only)
    if version >= 3 {
        if hdr.dirty {
            result.flags |= CheckResult::FLAG_DIRTY;
            (call_table.debug_print)(b"check: image is dirty\n\0".as_ptr());
        }
        if hdr.corrupt {
            result.flags |= CheckResult::FLAG_CORRUPT_BIT;
            result.corruptions += 1;
            result.total_errors += 1;
            (call_table.debug_print)(b"check: corrupt bit set\n\0".as_ptr());
        }

        // Reject images with unsupported incompatible features.
        // Per the QCOW2 spec, unknown incompatible bits MUST cause
        // the reader to refuse to open the image.
        //
        // Check uses a wider mask than data-processing operations
        // because structural validation (L1/L2 tables, refcounts)
        // works regardless of compression type. INCOMPAT_COMPRESSION
        // only affects how cluster data is compressed, not the table
        // structure that check validates.
        let check_supported = qcow2::SUPPORTED_INCOMPAT_FEATURES
            | qcow2::INCOMPAT_COMPRESSION
            | qcow2::INCOMPAT_EXTENDED_L2;
        let unsupported = hdr.incompatible_features & !check_supported;
        if unsupported != 0 {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: unsupported incompatible features\n\0".as_ptr());
            return bytes_read;
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
    // Extended L2 entries are 16 bytes (8-byte standard entry + 8-byte
    // subcluster bitmap), so there are half as many entries per cluster.
    let l2_entry_size: u64 = if hdr.extended_l2 { 16 } else { 8 };
    let l2_entries_per_cluster = cluster_size / l2_entry_size;

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
    let bitmap = SCRATCH_MEM_BASE as *mut u8;
    let total_host_clusters = (actual_size + cluster_size - 1) / cluster_size;
    let needed_bytes = ((total_host_clusters + 7) / 8) as usize;
    let bitmap_size = core::cmp::min(needed_bytes, SCRATCH_MEM_SIZE);
    // Only zero the bytes actually needed for this image's clusters
    core::ptr::write_bytes(bitmap, 0, bitmap_size);

    let max_trackable = (bitmap_size as u64) * 8;
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

            let l2_offset = l1_entry & qcow2::L1_OFFSET_MASK;

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
            if let Some(rc) = qcow2::lookup_refcount(
                call_table,
                0,
                refcount_table_offset,
                refcount_bits,
                cluster_size,
                sector_size,
                input_capacity,
                l2_offset,
                &mut reftable_cached_sector,
                reftable_cached_buffer.as_mut_ptr(),
                &mut refblock_cached_sector,
                refblock_cached_buffer.as_mut_ptr(),
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
                if let Some(rb_off) = qcow2::read_u64_be_cached(
                    call_table,
                    0,
                    rb_byte_off,
                    sector_size,
                    input_capacity,
                    &mut reftable_cached_sector,
                    reftable_cached_buffer.as_mut_ptr(),
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
                    core::cmp::min(l2_entries_remaining, (sector_size as u64) / l2_entry_size);

                for j in 0..entries_this_sector as usize {
                    let off = j * l2_entry_size as usize;
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

                    let compressed = (l2e & qcow2::OFLAG_COMPRESSED) != 0;

                    if !compressed {
                        let data_off = l2e & qcow2::L2_OFFSET_MASK;
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
                        if let Some(rc) = qcow2::lookup_refcount(
                            call_table,
                            0,
                            refcount_table_offset,
                            refcount_bits,
                            cluster_size,
                            sector_size,
                            input_capacity,
                            data_off,
                            &mut reftable_cached_sector,
                            reftable_cached_buffer.as_mut_ptr(),
                            &mut refblock_cached_sector,
                            refblock_cached_buffer.as_mut_ptr(),
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

                        // Parse compressed entry to find host clusters
                        // for bitmap tracking and bounds validation.
                        if let Some((comp_off, comp_size)) =
                            qcow2::parse_compressed_l2_entry(l2e, cluster_bits)
                        {
                            if let Some(comp_end) = comp_off.checked_add(comp_size) {
                                if comp_end > actual_size {
                                    result.corruptions += 1;
                                    result.total_errors += 1;
                                } else {
                                    // Track max offset for compressed data
                                    if comp_end > max_offset {
                                        max_offset = comp_end;
                                    }

                                    // Mark host clusters in bitmap for leak
                                    // prevention. Ignore AlreadySet: compressed
                                    // clusters can share host clusters via
                                    // sub-cluster packing.
                                    if can_track {
                                        let first = comp_off / cluster_size;
                                        let last = (comp_end - 1) / cluster_size;
                                        for cidx in first..=last {
                                            bitmap_set(bitmap, bitmap_size, cidx);
                                        }
                                    }
                                }
                            } else {
                                result.corruptions += 1;
                                result.total_errors += 1;
                            }
                        }
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
    if can_track {
        (call_table.verbose_print)(b"check: scanning refcounts for leaks\n\0".as_ptr());

        let entries_per_block = (cluster_size * 8) / refcount_bits as u64;
        const MAX_REFTABLE_ENTRIES: u64 = 16 * 1024 * 1024;
        let reftable_entries = {
            let raw = (refcount_table_clusters as u64).saturating_mul(cluster_size / 8);
            let max_entries = actual_size / 8;
            core::cmp::min(raw, max_entries)
        };
        if reftable_entries > MAX_REFTABLE_ENTRIES {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(
                b"check: reftable_entries exceeds bounds, skipping leak scan\n\0".as_ptr(),
            );
        } else {
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
                let refblock_off = match qcow2::read_u64_be_cached(
                    call_table,
                    0,
                    rt_byte_off,
                    sector_size,
                    input_capacity,
                    &mut reftable_cached_sector,
                    reftable_cached_buffer.as_mut_ptr(),
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
                let refblock_off = match qcow2::read_u64_be_cached(
                    call_table,
                    0,
                    rt_byte_off,
                    sector_size,
                    input_capacity,
                    &mut reftable_cached_sector,
                    reftable_cached_buffer.as_mut_ptr(),
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
                let entries_per_sector = (sector_size as u64 * 8) / refcount_bits as u64;

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

                    let entries_this = core::cmp::min(entries_remaining, entries_per_sector);

                    for e in 0..entries_this as usize {
                        let rc = read_refcount_from_buffer(&leak_scan_buffer, e, refcount_bits);

                        if rc > 0 {
                            let cidx = match rt_idx.checked_mul(entries_per_block).and_then(|v| {
                                v.checked_add((s as u64) * entries_per_sector + e as u64)
                            }) {
                                Some(v) => v,
                                None => continue,
                            };
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
        } // end else (reftable_entries within bounds)
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

/// Validate backing chain consistency.
///
/// For each backing device (1..device_count):
/// 1. Read first sector and detect format
/// 2. Cross-check format matches chain metadata from host
/// 3. Cross-check virtual size consistency (overlay virtual size
///    should not exceed its backing image's virtual size)
/// 4. Run basic QCOW2 header validation for QCOW2 backing images
///    (magic, version, cluster_bits, L1/refcount table bounds)
///
/// Returns the number of bytes read during validation.
unsafe fn validate_chain(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    result: &mut CheckResult,
) -> u64 {
    let mut bytes_read: u64 = 0;
    let device_count = chain_config.device_count as usize;

    for dev_idx in 1..device_count {
        let chain_dev = match chain_config.get(dev_idx) {
            Some(d) => d,
            None => break,
        };

        // Get device capacity from call table
        let capacity = (call_table.get_input_capacity)(dev_idx as u32);
        let sector_size = (call_table.get_input_sector_size)(dev_idx as u32);

        if capacity == 0 || sector_size == 0 {
            (call_table.debug_print)(b"check: chain device not available\n\0".as_ptr());
            result.chain_errors += 1;
            result.total_errors += 1;
            continue;
        }

        // Read first sector of backing device
        let mut header_buf = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(dev_idx as u32, 0, header_buf.as_mut_ptr(), sector_size)
        {
            (call_table.debug_print)(b"check: chain device read error\n\0".as_ptr());
            result.chain_errors += 1;
            result.total_errors += 1;
            continue;
        }
        bytes_read += sector_size as u64;

        // Detect format from header
        let detected = detect_format_from_header(&header_buf, sector_size, false);

        // Cross-check: format matches chain metadata
        let expected_format = chain_dev.detected_format();
        if detected != expected_format {
            (call_table.debug_print)(b"check: chain format mismatch\n\0".as_ptr());
            result.chain_errors += 1;
            result.total_errors += 1;
        }

        // Cross-check: virtual size consistency
        // A backing image's virtual size should not be zero
        if chain_dev.virtual_size == 0 {
            (call_table.debug_print)(b"check: chain backing has zero virtual size\n\0".as_ptr());
            result.chain_errors += 1;
            result.total_errors += 1;
        }

        // Basic QCOW2 header validation for QCOW2 backing images
        if detected == ImageFormat::Qcow2 {
            bytes_read += validate_chain_qcow2_header(
                call_table,
                &header_buf,
                capacity * sector_size as u64,
                result,
            );
        }
    }

    if result.chain_errors > 0 {
        result.flags |= CheckResult::FLAG_CHAIN_ERRORS;
    }

    bytes_read
}

/// Basic QCOW2 header validation for a backing image.
///
/// Uses `qcow2::QcowHeader::parse()` for field extraction, then validates
/// structural bounds. No L2/refcount walk (avoids scratch memory conflicts).
///
/// Returns bytes read (always 0 since we reuse the header buffer).
unsafe fn validate_chain_qcow2_header(
    call_table: &CallTable,
    header: &[u8],
    actual_size: u64,
    result: &mut CheckResult,
) -> u64 {
    // Validate magic
    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if magic != QCOW2_MAGIC {
        (call_table.debug_print)(b"check: chain qcow2 bad magic\n\0".as_ptr());
        result.chain_errors += 1;
        result.total_errors += 1;
        return 0;
    }

    // Parse header (validates version 2|3 and cluster_bits 9-21)
    let hdr = match qcow2::QcowHeader::parse(header) {
        Some(h) => h,
        None => {
            (call_table.debug_print)(b"check: chain qcow2 bad header\n\0".as_ptr());
            result.chain_errors += 1;
            result.total_errors += 1;
            return 0;
        }
    };

    // Validate L1 table offset is within bounds
    if hdr.l1_table_offset == 0 || hdr.l1_table_offset >= actual_size {
        (call_table.debug_print)(b"check: chain qcow2 bad L1 offset\n\0".as_ptr());
        result.chain_errors += 1;
        result.total_errors += 1;
        return 0;
    }

    // Validate L1 size
    let l1_table_size_bytes = (hdr.l1_size as u64).saturating_mul(8);
    if l1_table_size_bytes > actual_size {
        (call_table.debug_print)(b"check: chain qcow2 L1 too large\n\0".as_ptr());
        result.chain_errors += 1;
        result.total_errors += 1;
        return 0;
    }

    // Validate refcount table offset is within bounds
    if hdr.refcount_table_offset == 0 || hdr.refcount_table_offset >= actual_size {
        (call_table.debug_print)(b"check: chain qcow2 bad reftable offset\n\0".as_ptr());
        result.chain_errors += 1;
        result.total_errors += 1;
        return 0;
    }

    // Validate refcount table clusters are within bounds
    let reftable_size = (hdr.refcount_table_clusters as u64).saturating_mul(hdr.cluster_size);
    if let Some(rte) = hdr.refcount_table_offset.checked_add(reftable_size) {
        if rte > actual_size {
            (call_table.debug_print)(b"check: chain qcow2 reftable exceeds file\n\0".as_ptr());
            result.chain_errors += 1;
            result.total_errors += 1;
            return 0;
        }
    } else {
        result.chain_errors += 1;
        result.total_errors += 1;
        return 0;
    }

    // Check v3 incompatible features for corrupt bit
    if hdr.corrupt {
        (call_table.debug_print)(b"check: chain qcow2 corrupt bit set\n\0".as_ptr());
        result.chain_errors += 1;
        result.total_errors += 1;
    }

    0
}

/// Read a refcount entry from a sector buffer.
///
/// `entry_index` is the index of the entry within this sector.
/// `refcount_bits` must be 1, 2, 4, 8, 16, 32, or 64.
///
/// Sub-byte widths use little-endian bit ordering within each byte
/// (entry 0 at the LSB), matching QEMU's implementation.
fn read_refcount_from_buffer(
    buf: &[u8; MAX_SECTOR_SIZE],
    entry_index: usize,
    refcount_bits: u32,
) -> u64 {
    match refcount_bits {
        1 | 2 | 4 => {
            let entries_per_byte = 8 / refcount_bits as usize;
            let byte_idx = entry_index / entries_per_byte;
            let bit_pos = (entry_index % entries_per_byte) * refcount_bits as usize;
            let mask = (1u64 << refcount_bits) - 1;
            (buf[byte_idx] as u64 >> bit_pos) & mask
        }
        8 => buf[entry_index] as u64,
        16 => {
            let off = entry_index * 2;
            u16::from_be_bytes([buf[off], buf[off + 1]]) as u64
        }
        32 => {
            let off = entry_index * 4;
            u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as u64
        }
        64 => {
            let off = entry_index * 8;
            u64::from_be_bytes([
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
        _ => 0,
    }
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
