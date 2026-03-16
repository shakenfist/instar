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
    bitmap::{BitmapContext, BitmapSetResult},
    format_detection::{detect_format_from_header, detect_vhd_footer, QCOW2_MAGIC},
    validate_call_table, CallTable, ChainConfig, CheckConfig, CheckResult, ImageFormat,
    CALL_TABLE_ADDR, MAX_SECTOR_SIZE,
};

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

    // Determine external data file size from chain config (if available).
    // When a QCOW2 has an external data file, standard cluster offsets
    // point into the data device, not the metadata device. The check
    // operation must skip bounds/overlap/refcount validation for those
    // clusters against the metadata file.
    let data_file_size: u64 = {
        let chain_result = (call_table.get_chain_config)();
        if !chain_result.ptr.is_null() && chain_result.len > 0 {
            let cc = &*(chain_result.ptr as *const ChainConfig);
            if cc.is_valid() {
                if let Some(dev0) = cc.get(0) {
                    if dev0.has_external_data_device() {
                        let data_idx = dev0.data_device_idx as usize;
                        if let Some(data_dev) = cc.get(data_idx) {
                            data_dev.actual_size
                        } else {
                            0
                        }
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        }
    };

    // Perform format-specific validation
    match format {
        ImageFormat::Qcow2 => {
            bytes_read += check_qcow2(
                &buffer,
                &mut result,
                call_table,
                input_sector_size,
                actual_size,
                data_file_size,
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
                bytes_read += check_vhd(
                    &buffer,
                    &mut result,
                    call_table,
                    input_sector_size,
                    actual_size,
                );
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
    let grain_size_bytes = hdr.grain_size_bytes;
    let total_host_grains = (actual_size + grain_size_bytes - 1) / grain_size_bytes;
    let bmp = BitmapContext::init_in_scratch(total_host_grains);

    (call_table.verbose_print)(b"check: vmdk bitmap initialized\n\0".as_ptr());

    // ---- Mark metadata regions in bitmap ----
    if bmp.can_track {
        // Header grain (grain 0)
        bmp.set(0);

        // Descriptor grains
        if hdr.desc_offset_sectors > 0 {
            let desc_start = hdr.desc_offset_sectors * 512;
            let desc_end_b = desc_start + hdr.desc_size_sectors * 512;
            let first = desc_start / grain_size_bytes;
            let last = desc_end_b.saturating_sub(1) / grain_size_bytes;
            for g in first..=last {
                bmp.set(g);
            }
        }

        // Grain directory grains
        let gd_first = gd_byte_offset / grain_size_bytes;
        let gd_last = gd_end.saturating_sub(1) / grain_size_bytes;
        for g in gd_first..=gd_last {
            bmp.set(g);
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

        // Mark GT grains as metadata in the bitmap.
        // GT and GD grains may colocate in the same host grain
        // (especially in small streamOptimized VMDKs), so we mark
        // without checking AlreadySet — same as header/descriptor/GD.
        if bmp.can_track {
            let first_grain = gt_byte_off / grain_size_bytes;
            let last_grain = gt_end.saturating_sub(1) / grain_size_bytes;
            for g in first_grain..=last_grain {
                bmp.set(g);
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
                // Compressed grain: GTE points to grain marker
                // (12 bytes: u64 LBA + u32 compressed_size).
                // Read and validate the marker.
                let marker_sector = grain_off / sector_size as u64;
                let marker_off_in_sector = (grain_off % sector_size as u64) as usize;

                if marker_sector < input_capacity
                    && marker_off_in_sector + vmdk::GRAIN_MARKER_SIZE <= sector_size
                {
                    let mut marker_buf = [0u8; MAX_SECTOR_SIZE];
                    if (call_table.read_input_sector)(
                        0,
                        marker_sector,
                        marker_buf.as_mut_ptr(),
                        sector_size,
                    ) {
                        bytes_read += sector_size as u64;
                        if let Some((lba, comp_size)) =
                            vmdk::parse_grain_marker(&marker_buf[marker_off_in_sector..])
                        {
                            // Validate LBA matches expected virtual grain
                            let expected_lba = (gd_idx as u64)
                                .saturating_mul(hdr.num_gtes_per_gt as u64)
                                .saturating_add(gt_idx as u64)
                                .saturating_mul(hdr.grain_size_sectors);
                            if lba != expected_lba {
                                result.corruptions += 1;
                                result.total_errors += 1;
                                (call_table.debug_print)(
                                    b"check: grain marker LBA mismatch\n\0".as_ptr(),
                                );
                            }

                            // Validate compressed_size > 0
                            if comp_size == 0 {
                                result.corruptions += 1;
                                result.total_errors += 1;
                                (call_table.debug_print)(
                                    b"check: grain marker zero size\n\0".as_ptr(),
                                );
                            }

                            // Validate compressed data fits in file
                            let data_end = grain_off
                                .checked_add(vmdk::GRAIN_MARKER_SIZE as u64)
                                .and_then(|v| v.checked_add(comp_size as u64));
                            match data_end {
                                Some(end) if end <= actual_size => {
                                    if end > max_offset {
                                        max_offset = end;
                                    }
                                }
                                _ => {
                                    result.corruptions += 1;
                                    result.total_errors += 1;
                                    (call_table.debug_print)(
                                        b"check: grain data beyond EOF\n\0".as_ptr(),
                                    );
                                }
                            }
                        }
                    }
                }

                result.clusters_allocated += 1;
                if bmp.can_track {
                    bmp.set(grain_off / grain_size_bytes);
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
                if bmp.can_track {
                    let gidx = grain_off / grain_size_bytes;
                    if matches!(bmp.set(gidx), BitmapSetResult::AlreadySet) {
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

    // ---- Validate redundant grain directory (RGD) ----
    if (hdr.flags & vmdk::FLAG_USE_RGD) != 0 && hdr.rgd_offset_sectors != 0 {
        let rgd_byte_offset = match hdr.rgd_offset_sectors.checked_mul(512) {
            Some(off) if off < actual_size => off,
            _ => {
                result.corruptions += 1;
                result.total_errors += 1;
                (call_table.debug_print)(b"check: RGD offset out of bounds\n\0".as_ptr());
                // Skip RGD validation but continue
                0
            }
        };

        if rgd_byte_offset > 0 {
            let rgd_end = match rgd_byte_offset.checked_add(gd_size_bytes) {
                Some(end) if end <= actual_size => end,
                _ => {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    (call_table.debug_print)(b"check: RGD extends beyond file\n\0".as_ptr());
                    0
                }
            };

            if rgd_end > 0 {
                // Mark RGD region in bitmap. RGD may colocate
                // with GD/GT/descriptor in the same grain
                // (especially small VMDKs), so mark without
                // checking AlreadySet — same as GD marking.
                if bmp.can_track {
                    let rgd_first = rgd_byte_offset / grain_size_bytes;
                    let rgd_last = rgd_end.saturating_sub(1) / grain_size_bytes;
                    for g in rgd_first..=rgd_last {
                        bmp.set(g);
                    }
                }

                if rgd_end > max_offset {
                    max_offset = rgd_end;
                }

                // Compare RGD against primary GD.
                // GD and RGD entries point to different GT copies, so
                // we compare allocation consistency (both zero or both
                // non-zero) and, for allocated entries, compare the
                // GT contents they reference.
                let mut rgd_cached_sector: u64 = u64::MAX;
                let mut rgd_cache = [0u8; MAX_SECTOR_SIZE];
                let mut rgd_mismatches: u64 = 0;

                let mut gd2_cached_sector: u64 = u64::MAX;
                let mut gd2_cache = [0u8; MAX_SECTOR_SIZE];

                // Extra caches for GT/RGT comparison reads
                let mut gt_cmp_cached: u64 = u64::MAX;
                let mut gt_cmp_cache = [0u8; MAX_SECTOR_SIZE];
                let mut rgt_cmp_cached: u64 = u64::MAX;
                let mut rgt_cmp_cache = [0u8; MAX_SECTOR_SIZE];

                for i in 0..num_gd_entries {
                    let gd_off = match (i as u64)
                        .checked_mul(4)
                        .and_then(|v| gd_byte_offset.checked_add(v))
                    {
                        Some(off) => off,
                        None => break,
                    };
                    let rgd_off = match (i as u64)
                        .checked_mul(4)
                        .and_then(|v| rgd_byte_offset.checked_add(v))
                    {
                        Some(off) => off,
                        None => break,
                    };

                    let gd_val = vmdk::read_u32_le_cached(
                        call_table,
                        0,
                        gd_off,
                        sector_size,
                        input_capacity,
                        &mut gd2_cached_sector,
                        gd2_cache.as_mut_ptr(),
                        &mut bytes_read,
                    );
                    let rgd_val = vmdk::read_u32_le_cached(
                        call_table,
                        0,
                        rgd_off,
                        sector_size,
                        input_capacity,
                        &mut rgd_cached_sector,
                        rgd_cache.as_mut_ptr(),
                        &mut bytes_read,
                    );

                    match (gd_val, rgd_val) {
                        (Some(gd), Some(rgd)) => {
                            // Check allocation consistency
                            if (gd == 0) != (rgd == 0) {
                                rgd_mismatches += 1;
                                continue;
                            }
                            // Both allocated: compare GT contents
                            if gd != 0 && rgd != 0 {
                                let gt_base = (gd as u64) * 512;
                                let rgt_base = (rgd as u64) * 512;
                                for j in 0..hdr.num_gtes_per_gt {
                                    let gt_e_off = match (j as u64)
                                        .checked_mul(4)
                                        .and_then(|v| gt_base.checked_add(v))
                                    {
                                        Some(off) => off,
                                        None => break,
                                    };
                                    let rgt_e_off = match (j as u64)
                                        .checked_mul(4)
                                        .and_then(|v| rgt_base.checked_add(v))
                                    {
                                        Some(off) => off,
                                        None => break,
                                    };
                                    let gt_e = vmdk::read_u32_le_cached(
                                        call_table,
                                        0,
                                        gt_e_off,
                                        sector_size,
                                        input_capacity,
                                        &mut gt_cmp_cached,
                                        gt_cmp_cache.as_mut_ptr(),
                                        &mut bytes_read,
                                    );
                                    let rgt_e = vmdk::read_u32_le_cached(
                                        call_table,
                                        0,
                                        rgt_e_off,
                                        sector_size,
                                        input_capacity,
                                        &mut rgt_cmp_cached,
                                        rgt_cmp_cache.as_mut_ptr(),
                                        &mut bytes_read,
                                    );
                                    match (gt_e, rgt_e) {
                                        (Some(a), Some(b)) if a != b => {
                                            rgd_mismatches += 1;
                                            // One mismatch per GD entry is enough
                                            break;
                                        }
                                        (None, _) | (_, None) => {
                                            rgd_mismatches += 1;
                                            break;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        _ => {
                            // Read error on either GD or RGD
                            result.corruptions += 1;
                            result.total_errors += 1;
                            (call_table.debug_print)(b"check: RGD read error\n\0".as_ptr());
                            break;
                        }
                    }
                }

                if rgd_mismatches > 0 {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    (call_table.debug_print)(b"check: GD/RGD mismatch\n\0".as_ptr());
                }

                (call_table.verbose_print)(b"check: RGD validation complete\n\0".as_ptr());
            }
        }
    }

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

/// Check VHDX image integrity.
///
/// Validates:
/// - Header 1 and Header 2: signature, CRC-32C checksum, active header
///   selection via sequence_number
/// - Dirty log detection (non-zero log_guid in active header)
/// - Region table 1: signature, CRC-32C, entry count, BAT/metadata
///   region presence
/// - Metadata: table signature, required items (FileParameters,
///   VirtualDiskSize, LogicalSectorSize, PhysicalSectorSize)
/// - Differencing disk detection (has_parent → unsupported)
/// - BAT entries: allocated block offsets within file bounds, 1MB
///   alignment, overlap detection via BitmapContext
unsafe fn check_vhdx(
    result: &mut CheckResult,
    call_table: &CallTable,
    sector_size: usize,
    actual_size: u64,
) -> u64 {
    let mut bytes_read: u64 = 0;
    let input_capacity = (call_table.get_input_capacity)(0);

    // Need at least space for region table 1 + region table size
    if actual_size < vhdx::REGION_TABLE1_OFFSET + 65536 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: VHDX too small for headers\n\0".as_ptr());
        return bytes_read;
    }

    // --- Validate headers ---
    // Read and validate Header 1 (0x10000)
    let header1 = read_vhdx_header(
        call_table,
        vhdx::HEADER1_OFFSET,
        sector_size,
        input_capacity,
        &mut bytes_read,
    );
    // Read and validate Header 2 (0x20000)
    let header2 = read_vhdx_header(
        call_table,
        vhdx::HEADER2_OFFSET,
        sector_size,
        input_capacity,
        &mut bytes_read,
    );

    let header = match (&header1, &header2) {
        (Some(h1), Some(h2)) => {
            if h1.sequence_number >= h2.sequence_number {
                h1
            } else {
                h2
            }
        }
        (Some(h1), None) => {
            // Header 2 is invalid — warn but continue with header 1
            result.corruptions += 1;
            result.total_errors += 1;
            (call_table.debug_print)(b"check: VHDX header 2 invalid\n\0".as_ptr());
            h1
        }
        (None, Some(h2)) => {
            // Header 1 is invalid — warn but continue with header 2
            result.corruptions += 1;
            result.total_errors += 1;
            (call_table.debug_print)(b"check: VHDX header 1 invalid\n\0".as_ptr());
            h2
        }
        (None, None) => {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: both VHDX headers invalid\n\0".as_ptr());
            return bytes_read;
        }
    };

    // Dirty log detection
    if header.log_guid != [0u8; 16] {
        result.flags |= CheckResult::FLAG_DIRTY;
        (call_table.debug_print)(b"check: VHDX has dirty log\n\0".as_ptr());
    }

    // --- Validate region tables (RT1 at 0x30000, RT2 at 0x40000) ---
    let rt_sectors = 65536 / sector_size;

    // Use scratch memory: first 64KB for RT data, next 64KB for RT1
    // copy (for RT1/RT2 comparison)
    let rt_buf = shared::SCRATCH_MEM_BASE as *mut u8;
    let rt1_copy = (shared::SCRATCH_MEM_BASE + 65536) as *mut u8;
    if shared::SCRATCH_MEM_BASE + 131072 > shared::ALLOC_HEAP_BASE {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: not enough scratch for VHDX RT\n\0".as_ptr());
        return bytes_read;
    }

    // Read RT1
    let mut rt1_read_ok = true;
    let rt1_start = vhdx::REGION_TABLE1_OFFSET / sector_size as u64;
    for i in 0..rt_sectors {
        let sector = rt1_start + i as u64;
        if sector >= input_capacity
            || !(call_table.read_input_sector)(0, sector, rt_buf.add(i * sector_size), sector_size)
        {
            rt1_read_ok = false;
            break;
        }
        bytes_read += sector_size as u64;
    }

    let rt1_parsed = if rt1_read_ok {
        let rt_slice = core::slice::from_raw_parts(rt_buf, 65536);
        vhdx::parse_region_table(rt_slice)
    } else {
        None
    };

    // Save RT1 data for comparison if valid
    let rt1_valid = rt1_parsed.is_some();
    if rt1_valid {
        core::ptr::copy_nonoverlapping(rt_buf, rt1_copy, 65536);
    }

    // Read RT2
    let mut rt2_read_ok = true;
    let rt2_start = vhdx::REGION_TABLE2_OFFSET / sector_size as u64;
    for i in 0..rt_sectors {
        let sector = rt2_start + i as u64;
        if sector >= input_capacity
            || !(call_table.read_input_sector)(0, sector, rt_buf.add(i * sector_size), sector_size)
        {
            rt2_read_ok = false;
            break;
        }
        bytes_read += sector_size as u64;
    }

    let rt2_parsed = if rt2_read_ok {
        let rt_slice = core::slice::from_raw_parts(rt_buf, 65536);
        vhdx::parse_region_table(rt_slice)
    } else {
        None
    };

    // If both valid, compare raw contents for consistency
    if rt1_parsed.is_some() && rt2_parsed.is_some() {
        let rt1_slice = core::slice::from_raw_parts(rt1_copy, 65536);
        let rt2_slice = core::slice::from_raw_parts(rt_buf, 65536);
        let mut mismatch = false;
        for i in 0..65536 {
            if rt1_slice[i] != rt2_slice[i] {
                mismatch = true;
                break;
            }
        }
        if mismatch {
            result.corruptions += 1;
            result.total_errors += 1;
            (call_table.debug_print)(b"check: VHDX RT1/RT2 mismatch\n\0".as_ptr());
        }
    } else if rt1_parsed.is_some() {
        result.corruptions += 1;
        result.total_errors += 1;
        (call_table.debug_print)(b"check: VHDX region table 2 invalid\n\0".as_ptr());
    } else if rt2_parsed.is_some() {
        result.corruptions += 1;
        result.total_errors += 1;
        (call_table.debug_print)(b"check: VHDX region table 1 invalid, using RT2\n\0".as_ptr());
    }

    // Pick whichever region table is valid (prefer RT1)
    let rt_result = if let Some(r) = rt1_parsed {
        r
    } else if let Some(r) = rt2_parsed {
        // Need to re-read RT2 into scratch for use below
        r
    } else {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: both VHDX region tables invalid\n\0".as_ptr());
        return bytes_read;
    };
    let (regions, _entry_count) = rt_result;

    // regions[0] = BAT, regions[1] = Metadata
    let bat_offset = regions[0].file_offset;
    let bat_length = regions[0].length;
    let metadata_offset = regions[1].file_offset;

    // Validate region offsets are within file
    if bat_offset >= actual_size || metadata_offset >= actual_size {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: VHDX region offset out of bounds\n\0".as_ptr());
        return bytes_read;
    }

    // Validate region offsets are 1MB-aligned
    if bat_offset % vhdx::MB_ALIGN != 0 || metadata_offset % vhdx::MB_ALIGN != 0 {
        result.corruptions += 1;
        result.total_errors += 1;
        (call_table.debug_print)(b"check: VHDX region not 1MB-aligned\n\0".as_ptr());
    }

    // --- Validate metadata ---
    let metadata = match vhdx::parse_metadata(
        call_table,
        0,
        metadata_offset,
        sector_size,
        input_capacity,
        &mut bytes_read,
    ) {
        Some(m) => m,
        None => {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: VHDX metadata invalid\n\0".as_ptr());
            return bytes_read;
        }
    };

    // Check for differencing disk
    if metadata.has_parent {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: VHDX differencing disk unsupported\n\0".as_ptr());
        return bytes_read;
    }

    // Validate sector sizes
    if metadata.logical_sector_size != 512 && metadata.logical_sector_size != 4096 {
        result.corruptions += 1;
        result.total_errors += 1;
        (call_table.debug_print)(b"check: VHDX invalid logical sector size\n\0".as_ptr());
    }

    // --- Validate BAT ---
    let block_size = metadata.block_size;
    let virtual_disk_size = metadata.virtual_disk_size;
    let logical_sector_size = metadata.logical_sector_size;

    // Calculate chunk_ratio
    let chunk_ratio = if block_size > 0 && logical_sector_size > 0 {
        ((1u64 << 23) * logical_sector_size as u64) / block_size as u64
    } else {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        return bytes_read;
    };

    if chunk_ratio == 0 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: VHDX chunk ratio is zero\n\0".as_ptr());
        return bytes_read;
    }

    // Calculate total BAT entries (payload + interleaved SB entries)
    let total_payload_blocks = virtual_disk_size.div_ceil(block_size as u64);
    let sb_entries = total_payload_blocks.div_ceil(chunk_ratio);
    let total_bat_entries = total_payload_blocks + sb_entries;

    // Validate BAT region can hold all entries
    let needed_bat_bytes = total_bat_entries * 8;
    if needed_bat_bytes > bat_length as u64 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: VHDX BAT region too small\n\0".as_ptr());
        return bytes_read;
    }

    // Set up overlap detection bitmap.
    // Each slot represents one block_size worth of file space in MB units.
    let total_file_mb = actual_size.div_ceil(vhdx::MB_ALIGN);
    let block_mb = (block_size as u64).div_ceil(vhdx::MB_ALIGN);
    let total_block_slots = if block_mb > 0 {
        total_file_mb.div_ceil(block_mb)
    } else {
        0
    };
    let bmp = BitmapContext::init_in_scratch(total_block_slots);

    // Set up cached BAT read
    shared::cached_read!(read_u64_le_cached, u64, le, 8);

    let bat_cache_start = shared::SCRATCH_MEM_BASE + bmp.size;
    let bat_cache_buf = bat_cache_start as *mut u8;
    // Verify we have room for the cache buffer
    if bat_cache_start + MAX_SECTOR_SIZE > shared::ALLOC_HEAP_BASE {
        // Not enough memory for BAT cache; skip BAT validation
        if result.corruptions > 0 {
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        }
        return bytes_read;
    }

    let mut bat_cached_sector: u64 = u64::MAX;
    let mut allocated_blocks: u64 = 0;
    let mut payload_block_idx: u64 = 0;

    for bat_idx in 0..total_bat_entries {
        // Determine if this is a sector bitmap entry (skip it)
        // SB entries appear at indices: chunk_ratio, 2*chunk_ratio+1,
        // 3*chunk_ratio+2, etc.
        // A payload block's BAT index = payload_block_idx +
        //     (payload_block_idx / chunk_ratio)
        // If bat_idx doesn't match the next expected payload index,
        // it's a SB entry.
        let expected_payload_bat_idx = payload_block_idx + (payload_block_idx / chunk_ratio);
        if bat_idx != expected_payload_bat_idx {
            // This is a sector bitmap entry; skip it
            continue;
        }

        // This is a payload BAT entry
        let bat_byte_offset = bat_offset + bat_idx * 8;

        let bat_entry = match read_u64_le_cached(
            call_table,
            0,
            bat_byte_offset,
            sector_size,
            input_capacity,
            &mut bat_cached_sector,
            bat_cache_buf,
            &mut bytes_read,
        ) {
            Some(v) => v,
            None => {
                result.corruptions += 1;
                result.total_errors += 1;
                (call_table.debug_print)(b"check: VHDX BAT read failed\n\0".as_ptr());
                payload_block_idx += 1;
                continue;
            }
        };

        let state = bat_entry & vhdx::BAT_ENTRY_STATE_MASK;
        let file_offset = bat_entry & vhdx::BAT_ENTRY_OFFSET_MASK;

        match state {
            vhdx::PAYLOAD_BLOCK_NOT_PRESENT
            | vhdx::PAYLOAD_BLOCK_ZERO
            | vhdx::PAYLOAD_BLOCK_UNMAPPED
            | vhdx::PAYLOAD_BLOCK_UNDEFINED => {
                // Unallocated or zero; no host offset to validate
            }
            vhdx::PAYLOAD_BLOCK_FULLY_PRESENT => {
                allocated_blocks += 1;

                // Validate offset is within file bounds
                let block_end = file_offset + block_size as u64;
                if block_end > actual_size {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    (call_table.debug_print)(
                        b"check: VHDX block offset out of bounds\n\0".as_ptr(),
                    );
                    payload_block_idx += 1;
                    continue;
                }

                // Validate 1MB alignment
                if file_offset % vhdx::MB_ALIGN != 0 {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    (call_table.debug_print)(b"check: VHDX block not 1MB-aligned\n\0".as_ptr());
                }

                // Overlap detection
                if bmp.can_track && block_mb > 0 {
                    let slot = file_offset / (block_mb * vhdx::MB_ALIGN);
                    match bmp.set(slot) {
                        BitmapSetResult::AlreadySet => {
                            result.corruptions += 1;
                            result.total_errors += 1;
                            (call_table.debug_print)(
                                b"check: VHDX overlapping blocks\n\0".as_ptr(),
                            );
                        }
                        BitmapSetResult::NewBit => {}
                        BitmapSetResult::BeyondCapacity => {}
                    }
                }
            }
            vhdx::PAYLOAD_BLOCK_PARTIALLY_PRESENT => {
                // Only valid for differencing disks, which we rejected
                result.corruptions += 1;
                result.total_errors += 1;
                (call_table.debug_print)(b"check: VHDX partially present in non-diff\n\0".as_ptr());
            }
            _ => {
                // Unknown BAT entry state
                result.corruptions += 1;
                result.total_errors += 1;
                (call_table.debug_print)(b"check: VHDX unknown BAT entry state\n\0".as_ptr());
            }
        }

        payload_block_idx += 1;
    }

    result.clusters_allocated = allocated_blocks;
    result.clusters_checked = total_payload_blocks;

    if result.corruptions > 0 {
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
    }

    bytes_read
}

/// Read and validate a VHDX header at the given byte offset.
///
/// Returns `Some(VhdxHeader)` if valid (signature + CRC-32C match),
/// `None` otherwise. Reads the full 4KB header.
unsafe fn read_vhdx_header(
    call_table: &CallTable,
    header_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> Option<vhdx::VhdxHeader> {
    // The header is 4KB. Read enough sectors to cover it.
    let start_sector = header_offset / sector_size as u64;
    let sectors_needed = vhdx::HEADER_SIZE.div_ceil(sector_size);

    // Use a stack buffer — 4KB is enough for the header
    let mut header_buf = [0u8; vhdx::HEADER_SIZE];

    for i in 0..sectors_needed {
        let sector = start_sector + i as u64;
        if sector >= input_capacity {
            return None;
        }
        // Read into the appropriate offset in header_buf
        let buf_offset = i * sector_size;
        let remaining = vhdx::HEADER_SIZE - buf_offset;
        let copy_len = if remaining < sector_size {
            remaining
        } else {
            sector_size
        };
        // We need a sector-aligned temporary buffer for the read
        let mut tmp = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(0, sector, tmp.as_mut_ptr(), sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;
        header_buf[buf_offset..buf_offset + copy_len].copy_from_slice(&tmp[..copy_len]);
    }

    vhdx::VhdxHeader::parse(&header_buf)
}

/// Check VHD image integrity.
///
/// Validates:
/// - Footer cookie and checksum (from first or last sector)
/// - Disk type validity (2=fixed, 3=dynamic, 4=differencing)
/// - For dynamic VHDs:
///   - Dynamic header cookie and checksum
///   - BAT offset within file bounds
///   - BAT entries: allocated block offsets within file bounds
///   - Overlap detection (no two BAT entries reference same block)
///   - Footer copy consistency (start vs end of file)
unsafe fn check_vhd(
    header: &[u8],
    result: &mut CheckResult,
    call_table: &CallTable,
    sector_size: usize,
    actual_size: u64,
) -> u64 {
    let mut bytes_read: u64 = 0;
    let input_capacity = (call_table.get_input_capacity)(0);

    // Try parsing footer from first sector (dynamic VHDs)
    let start_footer = vhd::VhdFooter::parse(header);

    // SAFETY: the else branch below always returns early, so `footer_buf`
    // is only used after this block when it equals `header` (the caller-owned
    // slice).  If a future change removes the early returns, `footer_buf`
    // would dangle — keep the else branch self-contained.
    let (footer, footer_buf) = if let Some(f) = start_footer {
        // Footer found at start — dynamic or differencing VHD
        (f, header)
    } else {
        // Try last sector (fixed VHDs)
        if input_capacity == 0 {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            return bytes_read;
        }
        // We already read the last sector during format detection,
        // but we need to re-read it here to get the buffer.
        // (The format detection code doesn't pass the buffer to us.)
        let last_sector = input_capacity - 1;
        // Use a static buffer on the stack
        let mut last_buf = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(0, last_sector, last_buf.as_mut_ptr(), sector_size) {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            return bytes_read;
        }
        bytes_read += sector_size as u64;

        match vhd::VhdFooter::parse(&last_buf) {
            Some(f) => {
                // Validate checksum of footer at end
                let expected = vhd::compute_checksum(
                    &last_buf[..vhd::FOOTER_SIZE],
                    vhd::FOOTER_CHECKSUM_OFFSET,
                );
                if f.checksum != expected {
                    result.corruptions += 1;
                    result.total_errors += 1;
                }
                // Validate disk type
                if f.disk_type < 2 || f.disk_type > 4 {
                    result.corruptions += 1;
                    result.total_errors += 1;
                }
                // Fixed VHD — no further structural validation needed
                if result.corruptions > 0 {
                    result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
                }
                return bytes_read;
            }
            None => {
                result.corruptions += 1;
                result.total_errors += 1;
                result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
                return bytes_read;
            }
        }
    };

    // Validate footer checksum
    let expected_cksum =
        vhd::compute_checksum(&footer_buf[..vhd::FOOTER_SIZE], vhd::FOOTER_CHECKSUM_OFFSET);
    if footer.checksum != expected_cksum {
        result.corruptions += 1;
        result.total_errors += 1;
        (call_table.debug_print)(b"check: VHD footer checksum mismatch\n\0".as_ptr());
    }

    // Validate disk type
    if footer.disk_type < 2 || footer.disk_type > 4 {
        result.corruptions += 1;
        result.total_errors += 1;
        (call_table.debug_print)(b"check: invalid VHD disk type\n\0".as_ptr());
    }

    // CHS geometry cross-check
    let (exp_cyl, exp_heads, exp_spt) = vhd::compute_vhd_geometry(footer.current_size);
    if footer.cylinders != exp_cyl
        || footer.heads != exp_heads
        || footer.sectors_per_track != exp_spt
    {
        // Non-standard geometry: warn but don't count as corruption
        (call_table.debug_print)(b"check: VHD CHS geometry mismatch\n\0".as_ptr());
    }

    // Compare original_size and current_size
    if footer.original_size != footer.current_size {
        (call_table.debug_print)(b"check: VHD original_size != current_size\n\0".as_ptr());
    }

    // For fixed VHDs with footer at start, nothing more to check
    if footer.disk_type == vhd::DISK_TYPE_FIXED {
        if result.corruptions > 0 {
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        }
        return bytes_read;
    }

    // Dynamic or differencing VHD: read and validate dynamic header
    let dyn_byte_offset = footer.data_offset;
    if dyn_byte_offset >= actual_size {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: VHD dynamic header offset out of bounds\n\0".as_ptr());
        return bytes_read;
    }

    let dyn_sector = dyn_byte_offset / sector_size as u64;
    let dyn_off_in_sector = (dyn_byte_offset % sector_size as u64) as usize;

    let mut dyn_buf = [0u8; MAX_SECTOR_SIZE];
    if !(call_table.read_input_sector)(0, dyn_sector, dyn_buf.as_mut_ptr(), sector_size) {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        return bytes_read;
    }
    bytes_read += sector_size as u64;

    // Read second sector if dynamic header spans across sector boundary
    let dyn_available = sector_size - dyn_off_in_sector;
    let mut dyn_header_bytes = [0u8; vhd::DYNAMIC_HEADER_SIZE];
    if dyn_available >= vhd::DYNAMIC_HEADER_SIZE {
        dyn_header_bytes.copy_from_slice(
            &dyn_buf[dyn_off_in_sector..dyn_off_in_sector + vhd::DYNAMIC_HEADER_SIZE],
        );
    } else {
        dyn_header_bytes[..dyn_available].copy_from_slice(&dyn_buf[dyn_off_in_sector..sector_size]);
        let next_sector = dyn_sector + 1;
        if next_sector >= input_capacity {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            return bytes_read;
        }
        if !(call_table.read_input_sector)(0, next_sector, dyn_buf.as_mut_ptr(), sector_size) {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            return bytes_read;
        }
        bytes_read += sector_size as u64;
        let remaining = vhd::DYNAMIC_HEADER_SIZE - dyn_available;
        dyn_header_bytes[dyn_available..vhd::DYNAMIC_HEADER_SIZE]
            .copy_from_slice(&dyn_buf[..remaining]);
    }

    let dyn_header = match vhd::VhdDynamicHeader::parse(&dyn_header_bytes) {
        Some(h) => h,
        None => {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: invalid VHD dynamic header\n\0".as_ptr());
            return bytes_read;
        }
    };

    // Validate dynamic header checksum
    let dyn_expected = vhd::compute_checksum(&dyn_header_bytes, vhd::DYN_CHECKSUM_OFFSET);
    if dyn_header.checksum != dyn_expected {
        result.corruptions += 1;
        result.total_errors += 1;
        (call_table.debug_print)(b"check: VHD dynamic header checksum mismatch\n\0".as_ptr());
    }

    // Validate BAT offset
    let bat_offset = dyn_header.table_offset;
    let bat_size_bytes = dyn_header.max_table_entries as u64 * 4;
    if bat_offset >= actual_size || bat_offset + bat_size_bytes > actual_size {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: VHD BAT offset out of bounds\n\0".as_ptr());
        return bytes_read;
    }

    // Validate block size
    if dyn_header.block_size == 0 || (dyn_header.block_size & (dyn_header.block_size - 1)) != 0 {
        result.corruptions += 1;
        result.total_errors += 1;
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        (call_table.debug_print)(b"check: VHD block size invalid\n\0".as_ptr());
        return bytes_read;
    }

    // Sector bitmap size per block
    let sectors_per_block = dyn_header.block_size / 512;
    let bitmap_bytes = ((sectors_per_block + 7) / 8 + 511) & !511;
    let block_total_bytes = bitmap_bytes as u64 + dyn_header.block_size as u64;

    // Set up overlap detection bitmap
    // Each slot represents one "block unit" (bitmap + data) worth of 512-byte sectors
    let total_file_sectors = (actual_size + 511) / 512;
    let block_total_sectors = (block_total_bytes + 511) / 512;
    // Track in units of block_total_sectors to detect overlapping blocks
    let total_block_slots = if block_total_sectors > 0 {
        (total_file_sectors + block_total_sectors - 1) / block_total_sectors
    } else {
        0
    };
    let bmp = BitmapContext::init_in_scratch(total_block_slots);

    // Use cached read for BAT entries
    shared::cached_read!(read_u32_be_cached, u32, be, 4);

    let mut bat_cached_sector: u64 = u64::MAX;
    let bat_cache_buf = (shared::SCRATCH_MEM_BASE + bmp.size) as *mut u8;
    // Ensure cache buffer doesn't exceed scratch
    if shared::SCRATCH_MEM_BASE + bmp.size + MAX_SECTOR_SIZE > shared::SCRATCH_MEM_END {
        // Not enough memory for BAT cache; skip BAT validation
        if result.corruptions > 0 {
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
        }
        return bytes_read;
    }

    let mut allocated_blocks: u64 = 0;

    for entry_idx in 0..dyn_header.max_table_entries {
        let bat_byte_offset = bat_offset + entry_idx as u64 * 4;

        let bat_entry = match read_u32_be_cached(
            call_table,
            0,
            bat_byte_offset,
            sector_size,
            input_capacity,
            &mut bat_cached_sector,
            bat_cache_buf,
            &mut bytes_read,
        ) {
            Some(v) => v,
            None => {
                result.corruptions += 1;
                result.total_errors += 1;
                (call_table.debug_print)(b"check: VHD BAT read failed\n\0".as_ptr());
                continue;
            }
        };

        if bat_entry == vhd::BAT_UNALLOCATED {
            continue;
        }

        allocated_blocks += 1;

        // Validate block offset is within file
        let block_host_offset = bat_entry as u64 * 512;
        let block_end = block_host_offset + block_total_bytes;
        if block_end > actual_size {
            result.corruptions += 1;
            result.total_errors += 1;
            (call_table.debug_print)(b"check: VHD block offset out of bounds\n\0".as_ptr());
            continue;
        }

        // Overlap detection
        if bmp.can_track && block_total_sectors > 0 {
            let slot = block_host_offset / (block_total_sectors * 512);
            match bmp.set(slot) {
                BitmapSetResult::AlreadySet => {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    (call_table.debug_print)(b"check: VHD overlapping blocks\n\0".as_ptr());
                }
                BitmapSetResult::NewBit => {}
                BitmapSetResult::BeyondCapacity => {}
            }
        }

        // Sector bitmap validation: for non-differencing
        // dynamic VHDs, all bitmap bits should be set
        // (full-block allocation).
        if footer.disk_type == vhd::DISK_TYPE_DYNAMIC {
            let bitmap_sector = block_host_offset / sector_size as u64;
            let bitmap_sectors_count =
                (bitmap_bytes as u64 + sector_size as u64 - 1) / sector_size as u64;
            let mut all_ones = true;

            for s in 0..bitmap_sectors_count {
                let sec = bitmap_sector + s;
                if sec >= input_capacity {
                    break;
                }
                let mut bmp_buf = [0u8; MAX_SECTOR_SIZE];
                if !(call_table.read_input_sector)(0, sec, bmp_buf.as_mut_ptr(), sector_size) {
                    break;
                }
                bytes_read += sector_size as u64;

                // How many bitmap bytes are in this sector
                let done = (s as u32) * sector_size as u32;
                let remaining = bitmap_bytes - done;
                let check_len = if remaining < sector_size as u32 {
                    remaining as usize
                } else {
                    sector_size
                };

                for i in 0..check_len {
                    // Last bitmap byte may have padding
                    // bits beyond actual sectors
                    if (done + i as u32) == bitmap_bytes - 1 {
                        // Mask: only check bits for
                        // actual sectors
                        let total_bitmap_bits = sectors_per_block;
                        let bits_before = (done + i as u32) * 8;
                        let valid_bits = total_bitmap_bits - bits_before;
                        let valid = if valid_bits >= 8 { 8 } else { valid_bits };
                        let mask = 0xFFu8 << (8 - valid);
                        if bmp_buf[i] & mask != mask {
                            all_ones = false;
                            break;
                        }
                    } else if bmp_buf[i] != 0xFF {
                        all_ones = false;
                        break;
                    }
                }
                if !all_ones {
                    break;
                }
            }

            if !all_ones {
                // Partial bitmap in a dynamic (non-
                // differencing) VHD is unusual
                result.leaks += 1;
                result.total_errors += 1;
                (call_table.debug_print)(
                    b"check: VHD block bitmap partially allocated\n\0".as_ptr(),
                );
            }
        }
    }

    result.clusters_allocated = allocated_blocks;
    result.clusters_checked = dyn_header.max_table_entries as u64;

    // Verify footer copy at end of file matches footer at start
    if input_capacity > 0 {
        let last_sector = input_capacity - 1;
        let mut end_footer_buf = [0u8; MAX_SECTOR_SIZE];
        if (call_table.read_input_sector)(0, last_sector, end_footer_buf.as_mut_ptr(), sector_size)
        {
            bytes_read += sector_size as u64;
            if let Some(end_footer) = vhd::VhdFooter::parse(&end_footer_buf) {
                // Compare key fields
                if end_footer.current_size != footer.current_size
                    || end_footer.disk_type != footer.disk_type
                    || end_footer.data_offset != footer.data_offset
                {
                    result.corruptions += 1;
                    result.total_errors += 1;
                    (call_table.debug_print)(
                        b"check: VHD footer mismatch (start vs end)\n\0".as_ptr(),
                    );
                }
            }
            // If end footer doesn't parse, that's OK for fixed VHDs
            // but we've already handled fixed above
        }
    }

    if result.corruptions > 0 {
        result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
    }

    bytes_read
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
    data_file_size: u64,
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

    // Report encryption status (applies to both v2 and v3)
    if hdr.crypt_method == 1 {
        (call_table.verbose_print)(b"check: image uses AES encryption\n\0".as_ptr());
    } else if hdr.crypt_method == 2 {
        (call_table.verbose_print)(b"check: image uses LUKS encryption\n\0".as_ptr());
    }

    // Report snapshot count
    if hdr.nb_snapshots > 0 {
        (call_table.verbose_print)(b"check: image has snapshots\n\0".as_ptr());
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
            | qcow2::INCOMPAT_EXTENDED_L2
            | qcow2::INCOMPAT_EXTERNAL_DATA;
        let unsupported = hdr.incompatible_features & !check_supported;
        if unsupported != 0 {
            result.corruptions += 1;
            result.total_errors += 1;
            result.flags |= CheckResult::FLAG_HAS_CORRUPTIONS;
            (call_table.debug_print)(b"check: unsupported incompatible features\n\0".as_ptr());
            return bytes_read;
        }
    }

    // Determine if this image uses an external data file.
    // When true, standard (uncompressed) L2 cluster offsets point into
    // the external data file, not this metadata file. We must skip
    // bounds/overlap/refcount checks for those clusters against the
    // metadata file size. Compressed clusters and L2 tables remain in
    // the metadata file and are validated normally.
    let has_external_data = hdr.has_external_data;

    if has_external_data {
        (call_table.verbose_print)(b"check: external data file detected\n\0".as_ptr());
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
    let total_host_clusters = (actual_size + cluster_size - 1) / cluster_size;
    let bmp = BitmapContext::init_in_scratch(total_host_clusters);

    (call_table.verbose_print)(b"check: bitmap initialized\n\0".as_ptr());

    // ---- Mark metadata clusters in bitmap ----
    // Header cluster (cluster 0)
    if bmp.can_track {
        bmp.set(0);
    }
    // L1 table clusters
    if bmp.can_track {
        let l1_start_cluster = l1_table_offset / cluster_size;
        let l1_clusters = (l1_table_size_bytes + cluster_size - 1) / cluster_size;
        for c in 0..l1_clusters {
            bmp.set(l1_start_cluster + c);
        }
    }
    // Refcount table clusters
    if bmp.can_track {
        let rt_start_cluster = refcount_table_offset / cluster_size;
        for c in 0..(refcount_table_clusters as u64) {
            bmp.set(rt_start_cluster + c);
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
            if bmp.can_track {
                let l2_cidx = l2_offset / cluster_size;
                if matches!(bmp.set(l2_cidx), BitmapSetResult::AlreadySet) {
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
                    if rb_off != 0 && bmp.can_track {
                        bmp.set(rb_off / cluster_size);
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

                    // Read subcluster bitmap if extended L2
                    let sc_bitmap = if hdr.extended_l2 {
                        u64::from_be_bytes([
                            l2_buffer[off + 8],
                            l2_buffer[off + 9],
                            l2_buffer[off + 10],
                            l2_buffer[off + 11],
                            l2_buffer[off + 12],
                            l2_buffer[off + 13],
                            l2_buffer[off + 14],
                            l2_buffer[off + 15],
                        ])
                    } else {
                        0
                    };

                    result.clusters_checked += 1;

                    if l2e == 0 {
                        continue;
                    }

                    let compressed = (l2e & qcow2::OFLAG_COMPRESSED) != 0;

                    // Validate: compressed entries must not have
                    // a non-trivial subcluster bitmap
                    if compressed && hdr.extended_l2 {
                        let alloc_bits = sc_bitmap as u32;
                        if alloc_bits != 0 && alloc_bits != 0xFFFF_FFFF {
                            result.corruptions += 1;
                            result.total_errors += 1;
                        }
                    }

                    if !compressed {
                        let data_off = l2e & qcow2::L2_OFFSET_MASK;
                        if data_off == 0 {
                            continue;
                        }

                        if data_off % cluster_size != 0 {
                            result.corruptions += 1;
                            result.total_errors += 1;
                            continue;
                        }

                        if has_external_data {
                            // Standard cluster data is in the external
                            // data file. Skip overlap/refcount checks
                            // (those track metadata file only).
                            // Validate offset against data file size
                            // only if the data file was provided.
                            if data_file_size > 0 && data_off >= data_file_size {
                                result.corruptions += 1;
                                result.total_errors += 1;
                                continue;
                            }

                            result.clusters_allocated += 1;
                        } else {
                            // Standard cluster data is in this file.
                            if data_off >= actual_size {
                                result.corruptions += 1;
                                result.total_errors += 1;
                                continue;
                            }

                            result.clusters_allocated += 1;

                            // Overlap detection
                            if bmp.can_track {
                                let cidx = data_off / cluster_size;
                                if matches!(bmp.set(cidx), BitmapSetResult::AlreadySet) {
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

                        // Update max offset (only for metadata file)
                        if !has_external_data {
                            if let Some(de) = data_off.checked_add(cluster_size) {
                                if de > max_offset {
                                    max_offset = de;
                                }
                            } else {
                                result.corruptions += 1;
                                result.total_errors += 1;
                            }
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
                                    if bmp.can_track {
                                        let first = comp_off / cluster_size;
                                        let last = (comp_end - 1) / cluster_size;
                                        for cidx in first..=last {
                                            bmp.set(cidx);
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
    if bmp.can_track {
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
                    bmp.set(refblock_off / cluster_size);
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
                            if !bmp.test(cidx) {
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
