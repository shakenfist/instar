//! Compare operation: format-aware image data comparison.
//!
//! This operation reads two images (device 0 and device 1) and compares
//! their virtual content, reporting whether they are logically identical.
//! If they differ, it reports the byte offset of the first mismatch.
//!
//! Supports raw-vs-raw, QCOW2-vs-raw, and QCOW2-vs-QCOW2 comparison.
//! For QCOW2 images, performs L1/L2 table lookup and decompresses
//! compressed clusters using miniz_oxide (deflate).
//!
//! Results are sent via protobuf CompareResultMessage over the serial
//! command channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    CallTable, ChainConfig, CompareConfig, CompareResult, ImageFormat, CALL_TABLE_ADDR,
    CHAIN_CONFIG_ADDR, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
};

// QCOW2 header offsets (big-endian)
const QCOW2_VERSION_OFFSET: usize = 4;
const QCOW2_CLUSTER_BITS_OFFSET: usize = 20;
const QCOW2_SIZE_OFFSET: usize = 24;
const QCOW2_L1_SIZE_OFFSET: usize = 36;
const QCOW2_L1_TABLE_OFFSET_OFFSET: usize = 40;

// L2 table entry flags
const QCOW_OFLAG_COMPRESSED: u64 = 1 << 62;
// Mask for extracting offset from L1/L2 entries (bits 9-55)
const L2_OFFSET_MASK: u64 = 0x00fffffffffffe00;

// Scratch memory layout for compare operation.
// Each buffer is MAX_SECTOR_SIZE (64KB) in size.
const BUF_DEV0_L1_CACHE: usize = SCRATCH_MEM_BASE;
const BUF_DEV0_L2_CACHE: usize = BUF_DEV0_L1_CACHE + MAX_SECTOR_SIZE;
const BUF_DEV1_L1_CACHE: usize = BUF_DEV0_L2_CACHE + MAX_SECTOR_SIZE;
const BUF_DEV1_L2_CACHE: usize = BUF_DEV1_L1_CACHE + MAX_SECTOR_SIZE;
const BUF_CLUSTER_READ: usize = BUF_DEV1_L2_CACHE + MAX_SECTOR_SIZE;
const BUF_DECOMPRESS_OUT: usize = BUF_CLUSTER_READ + MAX_SECTOR_SIZE;
const BUF_COMPRESSED_IN: usize = BUF_DECOMPRESS_OUT + MAX_SECTOR_SIZE;
const BUF_COMPARE_1: usize = BUF_COMPRESSED_IN + MAX_SECTOR_SIZE;
const BUF_COMPARE_2: usize = BUF_COMPARE_1 + MAX_SECTOR_SIZE;

/// State for reading QCOW2 virtual content from a device.
struct Qcow2State {
    device_idx: u32,
    cluster_size: u64,
    cluster_bits: u32,
    l1_size: u32,
    l1_table_offset: u64,
    // Sector cache tracking for L1 table reads
    l1_cached_sector: u64,
    l1_cache_buf: *mut u8,
    // Sector cache tracking for L2 table reads
    l2_cached_sector: u64,
    l2_cache_buf: *mut u8,
}

/// Describes the format and key parameters for one device.
struct DeviceInfo {
    format: ImageFormat,
    virtual_size: u64,
    cluster_size: u64,
}

/// Result of looking up a virtual offset in QCOW2 L1/L2 tables.
enum ClusterLookup {
    /// Cluster is unallocated (reads as zeros)
    Unallocated,
    /// Standard cluster at given host byte offset
    Standard(u64),
    /// Compressed cluster: raw L2 entry for offset/size parsing
    Compressed(u64),
}

/// Read a big-endian u64 from a specific byte offset within a device,
/// using a sector-level cache to minimize I/O.
///
/// The cache buffers live in scratch memory at the addresses stored
/// in `cached_sector` / `cache_buf`.
unsafe fn read_u64_be_cached(
    call_table: &CallTable,
    device_idx: u32,
    byte_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    cached_sector: &mut u64,
    cache_buf: *mut u8,
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
        if !(call_table.read_input_sector)(device_idx, sector, cache_buf, sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;
        *cached_sector = sector;
    }
    let p = cache_buf.add(off);
    Some(u64::from_be_bytes([
        *p,
        *p.add(1),
        *p.add(2),
        *p.add(3),
        *p.add(4),
        *p.add(5),
        *p.add(6),
        *p.add(7),
    ]))
}

/// Read a big-endian u32 from a specific byte offset within a device,
/// using a sector-level cache to minimize I/O.
unsafe fn read_u32_be_cached(
    call_table: &CallTable,
    device_idx: u32,
    byte_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    cached_sector: &mut u64,
    cache_buf: *mut u8,
    bytes_read: &mut u64,
) -> Option<u32> {
    let sector = byte_offset / sector_size as u64;
    let off = (byte_offset % sector_size as u64) as usize;
    if off + 4 > sector_size {
        return None;
    }
    if sector >= input_capacity {
        return None;
    }
    if *cached_sector != sector {
        if !(call_table.read_input_sector)(device_idx, sector, cache_buf, sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;
        *cached_sector = sector;
    }
    let p = cache_buf.add(off);
    Some(u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]))
}

/// Initialize QCOW2 state by reading the header from the device.
unsafe fn init_qcow2_state(
    call_table: &CallTable,
    device_idx: u32,
    sector_size: usize,
    input_capacity: u64,
    l1_cache_buf: *mut u8,
    l2_cache_buf: *mut u8,
    bytes_read: &mut u64,
) -> Option<Qcow2State> {
    let mut state = Qcow2State {
        device_idx,
        cluster_size: 0,
        cluster_bits: 0,
        l1_size: 0,
        l1_table_offset: 0,
        l1_cached_sector: u64::MAX,
        l1_cache_buf,
        l2_cached_sector: u64::MAX,
        l2_cache_buf,
    };

    // Read version (must be 2 or 3)
    let version = read_u32_be_cached(
        call_table,
        device_idx,
        QCOW2_VERSION_OFFSET as u64,
        sector_size,
        input_capacity,
        &mut state.l1_cached_sector,
        state.l1_cache_buf,
        bytes_read,
    )?;
    if version != 2 && version != 3 {
        return None;
    }

    // Read cluster_bits
    let cluster_bits = read_u32_be_cached(
        call_table,
        device_idx,
        QCOW2_CLUSTER_BITS_OFFSET as u64,
        sector_size,
        input_capacity,
        &mut state.l1_cached_sector,
        state.l1_cache_buf,
        bytes_read,
    )?;
    if cluster_bits < 9 || cluster_bits > 21 {
        return None;
    }
    let cluster_size = 1u64 << cluster_bits;
    // Reject clusters larger than our scratch buffers (MAX_SECTOR_SIZE = 64 KiB).
    // The QCOW2 spec allows cluster_bits up to 21 (2 MiB), but our fixed-size
    // comparison and decompression buffers cannot handle clusters that large.
    if cluster_size > MAX_SECTOR_SIZE as u64 {
        return None;
    }
    state.cluster_bits = cluster_bits;
    state.cluster_size = cluster_size;

    // Read virtual size (not used directly but validates header)
    let _virtual_size = read_u64_be_cached(
        call_table,
        device_idx,
        QCOW2_SIZE_OFFSET as u64,
        sector_size,
        input_capacity,
        &mut state.l1_cached_sector,
        state.l1_cache_buf,
        bytes_read,
    )?;

    // Read L1 table size
    let l1_size = read_u32_be_cached(
        call_table,
        device_idx,
        QCOW2_L1_SIZE_OFFSET as u64,
        sector_size,
        input_capacity,
        &mut state.l1_cached_sector,
        state.l1_cache_buf,
        bytes_read,
    )?;
    state.l1_size = l1_size;

    // Read L1 table offset
    let l1_table_offset = read_u64_be_cached(
        call_table,
        device_idx,
        QCOW2_L1_TABLE_OFFSET_OFFSET as u64,
        sector_size,
        input_capacity,
        &mut state.l1_cached_sector,
        state.l1_cache_buf,
        bytes_read,
    )?;
    state.l1_table_offset = l1_table_offset;

    // Invalidate cache since we'll be reading L1/L2 tables from
    // different parts of the file
    state.l1_cached_sector = u64::MAX;
    state.l2_cached_sector = u64::MAX;

    Some(state)
}

/// Look up the host cluster for a given virtual offset in a QCOW2 image.
unsafe fn qcow2_cluster_lookup(
    call_table: &CallTable,
    state: &mut Qcow2State,
    virtual_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> Option<ClusterLookup> {
    let cluster_size = state.cluster_size;
    let entries_per_l2 = cluster_size / 8; // Each L2 entry is 8 bytes

    // Calculate L1 and L2 indices
    let l2_coverage = cluster_size * entries_per_l2;
    let l1_index = virtual_offset / l2_coverage;
    let l2_index = (virtual_offset / cluster_size) % entries_per_l2;

    // Bounds check L1 index
    if l1_index >= state.l1_size as u64 {
        return Some(ClusterLookup::Unallocated);
    }

    // Read L1 entry
    let l1_byte_offset = state.l1_table_offset + l1_index * 8;
    let l1_entry = read_u64_be_cached(
        call_table,
        state.device_idx,
        l1_byte_offset,
        sector_size,
        input_capacity,
        &mut state.l1_cached_sector,
        state.l1_cache_buf,
        bytes_read,
    )?;

    // L1 entry of 0 means unallocated
    let l2_table_offset = l1_entry & L2_OFFSET_MASK;
    if l2_table_offset == 0 {
        return Some(ClusterLookup::Unallocated);
    }

    // Read L2 entry
    let l2_byte_offset = l2_table_offset + l2_index * 8;
    let l2_entry = read_u64_be_cached(
        call_table,
        state.device_idx,
        l2_byte_offset,
        sector_size,
        input_capacity,
        &mut state.l2_cached_sector,
        state.l2_cache_buf,
        bytes_read,
    )?;

    // Decode L2 entry
    if l2_entry == 0 {
        Some(ClusterLookup::Unallocated)
    } else if (l2_entry & QCOW_OFLAG_COMPRESSED) != 0 {
        Some(ClusterLookup::Compressed(l2_entry))
    } else {
        // Standard cluster: extract host offset
        let host_offset = l2_entry & L2_OFFSET_MASK;
        if host_offset == 0 {
            // Zero cluster (preallocated but zero-filled)
            Some(ClusterLookup::Unallocated)
        } else {
            Some(ClusterLookup::Standard(host_offset))
        }
    }
}

/// Read a standard (uncompressed) cluster's data from a device into
/// the provided buffer, reading sector by sector.
unsafe fn read_cluster_sectors(
    call_table: &CallTable,
    device_idx: u32,
    host_offset: u64,
    buf: *mut u8,
    cluster_size: u64,
    sector_size: usize,
    bytes_read: &mut u64,
) -> bool {
    let first_sector = host_offset / sector_size as u64;
    let sectors_per_cluster = cluster_size / sector_size as u64;

    for i in 0..sectors_per_cluster {
        let sector = first_sector + i;
        let buf_offset = (i as usize) * sector_size;
        if !(call_table.read_input_sector)(device_idx, sector, buf.add(buf_offset), sector_size) {
            return false;
        }
        *bytes_read += sector_size as u64;
    }
    true
}

/// Read and decompress a compressed QCOW2 cluster.
///
/// Parses the compressed L2 entry to extract offset and size,
/// reads the compressed data, and inflates using miniz_oxide.
unsafe fn read_compressed_cluster(
    call_table: &CallTable,
    device_idx: u32,
    l2_entry: u64,
    cluster_bits: u32,
    out_buf: *mut u8,
    cluster_size: u64,
    sector_size: usize,
    _compressed_buf: *mut u8,
    bytes_read: &mut u64,
) -> bool {
    // Parse compressed L2 entry format:
    // csize_shift = 62 - (cluster_bits - 8)
    // offset_mask = (1 << csize_shift) - 1
    // compressed_offset = l2_entry & offset_mask
    // nb_sectors = ((l2_entry >> csize_shift) & csize_mask) + 1
    // compressed_size = nb_sectors * 512 - (compressed_offset & 511)
    let csize_shift = 62 - (cluster_bits as u64 - 8);
    let csize_mask = (1u64 << (cluster_bits as u64 - 8)) - 1;
    let offset_mask = (1u64 << csize_shift) - 1;

    let compressed_offset = l2_entry & offset_mask;
    let nb_sectors = ((l2_entry >> csize_shift) & csize_mask) + 1;
    let compressed_size = nb_sectors * 512 - (compressed_offset & 511);

    if compressed_size == 0 || compressed_size > MAX_SECTOR_SIZE as u64 {
        return false;
    }

    // Read compressed data sector by sector
    let first_sector = compressed_offset / sector_size as u64;
    // Calculate how many sectors we need to read to cover compressed data.
    // The compressed data starts at compressed_offset and is compressed_size bytes.
    let data_end = compressed_offset + compressed_size;
    let last_sector = (data_end + sector_size as u64 - 1) / sector_size as u64;
    let sectors_to_read = last_sector - first_sector;

    // Ensure total read fits within BUF_CLUSTER_READ (MAX_SECTOR_SIZE bytes)
    if sectors_to_read * sector_size as u64 > MAX_SECTOR_SIZE as u64 {
        return false;
    }

    // Read all needed sectors into compressed_buf
    // We need to handle the case where compressed data spans multiple sectors
    // and doesn't start at a sector boundary.
    let read_buf = BUF_CLUSTER_READ as *mut u8;
    for i in 0..sectors_to_read {
        let sector = first_sector + i;
        let buf_offset = (i as usize) * sector_size;
        if !(call_table.read_input_sector)(
            device_idx,
            sector,
            read_buf.add(buf_offset),
            sector_size,
        ) {
            return false;
        }
        *bytes_read += sector_size as u64;
    }

    // Extract the compressed data from within the read buffer
    let start_within_buf = (compressed_offset % sector_size as u64) as usize;
    let compressed_data = read_buf.add(start_within_buf);

    // Decompress using miniz_oxide raw deflate
    let compressed_slice = core::slice::from_raw_parts(compressed_data, compressed_size as usize);
    let out_slice = core::slice::from_raw_parts_mut(out_buf, cluster_size as usize);

    // Use miniz_oxide's low-level decompress API for no_std
    let mut decomp = miniz_oxide::inflate::core::DecompressorOxide::new();
    let (_status, _in_consumed, out_produced) = miniz_oxide::inflate::core::decompress(
        &mut decomp,
        compressed_slice,
        out_slice,
        0,
        miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );

    // Check that we produced exactly one cluster of output
    if out_produced != cluster_size as usize {
        // Try again without ZLIB header (raw deflate) since QCOW2
        // compression stores raw deflate data wrapped in a zlib stream
        let mut decomp2 = miniz_oxide::inflate::core::DecompressorOxide::new();
        let (_status2, _in2, out2) = miniz_oxide::inflate::core::decompress(
            &mut decomp2,
            compressed_slice,
            out_slice,
            0,
            miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        if out2 != cluster_size as usize {
            return false;
        }
    }

    true
}

/// Read one cluster's worth of virtual data from a device.
///
/// For raw devices: reads sectors directly from the file.
/// For QCOW2 devices: performs L1/L2 lookup, then reads or decompresses.
/// For unallocated clusters: fills buffer with zeros.
unsafe fn read_virtual_cluster(
    call_table: &CallTable,
    device_idx: u32,
    virtual_offset: u64,
    buf: *mut u8,
    cluster_size: u64,
    sector_size: usize,
    format: ImageFormat,
    qcow2_state: Option<&mut Qcow2State>,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> bool {
    match format {
        ImageFormat::Raw => {
            // Raw: read sectors directly, treating virtual offset as physical
            let first_sector = virtual_offset / sector_size as u64;
            let sectors_per_cluster = cluster_size / sector_size as u64;

            for i in 0..sectors_per_cluster {
                let sector = first_sector + i;
                if sector >= input_capacity {
                    // Beyond file: fill remainder with zeros
                    let remaining = ((sectors_per_cluster - i) as usize) * sector_size;
                    let dest = buf.add((i as usize) * sector_size);
                    core::ptr::write_bytes(dest, 0, remaining);
                    break;
                }
                let buf_offset = (i as usize) * sector_size;
                if !(call_table.read_input_sector)(
                    device_idx,
                    sector,
                    buf.add(buf_offset),
                    sector_size,
                ) {
                    return false;
                }
                *bytes_read += sector_size as u64;
            }
            true
        }
        ImageFormat::Qcow2 => {
            let state = match qcow2_state {
                Some(s) => s,
                None => return false,
            };

            match qcow2_cluster_lookup(
                call_table,
                state,
                virtual_offset,
                sector_size,
                input_capacity,
                bytes_read,
            ) {
                Some(ClusterLookup::Unallocated) => {
                    // Unallocated: fill with zeros
                    core::ptr::write_bytes(buf, 0, cluster_size as usize);
                    true
                }
                Some(ClusterLookup::Standard(host_offset)) => read_cluster_sectors(
                    call_table,
                    device_idx,
                    host_offset,
                    buf,
                    cluster_size,
                    sector_size,
                    bytes_read,
                ),
                Some(ClusterLookup::Compressed(l2_entry)) => read_compressed_cluster(
                    call_table,
                    device_idx,
                    l2_entry,
                    state.cluster_bits,
                    buf,
                    cluster_size,
                    sector_size,
                    BUF_COMPRESSED_IN as *mut u8,
                    bytes_read,
                ),
                None => false,
            }
        }
        _ => {
            // Unknown or unsupported format: treat as raw
            // (read sectors directly, same as Raw path above)
            let first_sector = virtual_offset / sector_size as u64;
            let sectors_per_cluster = cluster_size / sector_size as u64;

            for i in 0..sectors_per_cluster {
                let sector = first_sector + i;
                if sector >= input_capacity {
                    let remaining = ((sectors_per_cluster - i) as usize) * sector_size;
                    let dest = buf.add((i as usize) * sector_size);
                    core::ptr::write_bytes(dest, 0, remaining);
                    break;
                }
                let buf_offset = (i as usize) * sector_size;
                if !(call_table.read_input_sector)(
                    device_idx,
                    sector,
                    buf.add(buf_offset),
                    sector_size,
                ) {
                    return false;
                }
                *bytes_read += sector_size as u64;
            }
            true
        }
    }
}

/// Entry point called by core after devices are initialized.
///
/// Returns the number of bytes read during comparison.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    // Verify call table is valid
    if call_table.magic != CallTable::MAGIC {
        (call_table.debug_print)(b"compare: bad magic\n\0".as_ptr());
        return 0;
    }
    if call_table.version != CallTable::VERSION {
        (call_table.debug_print)(b"compare: bad version\n\0".as_ptr());
        return 0;
    }

    (call_table.verbose_print)(b"compare: start\n\0".as_ptr());

    // Get operation config
    let config_ptr = OPERATION_CONFIG_ADDR as *const CompareConfig;
    let config = &*config_ptr;
    let _strict = if config.is_valid() {
        config.is_strict()
    } else {
        false
    };

    // Read ChainConfig to learn format and virtual size for each device
    let chain_config = &*(CHAIN_CONFIG_ADDR as *const ChainConfig);
    let has_chain_config =
        chain_config.magic == ChainConfig::MAGIC && chain_config.device_count >= 2;

    // Get device parameters
    let cap1 = (call_table.get_input_capacity)(0);
    let cap2 = (call_table.get_input_capacity)(1);
    let sector_size1 = (call_table.get_input_sector_size)(0);
    let sector_size2 = (call_table.get_input_sector_size)(1);

    (call_table.verbose_print)(b"compare: got capacities\n\0".as_ptr());

    // Both devices must use the same sector size
    if sector_size1 != sector_size2 {
        (call_table.debug_print)(b"compare: sector size mismatch\n\0".as_ptr());
        let mut result = CompareResult::new();
        result.identical = 0;
        result.flags |= CompareResult::FLAG_SIZE_MISMATCH;
        (call_table.send_compare_result)(&result);
        (call_table.send_complete)(b"compare\0".as_ptr(), 0, false);
        return 0;
    }

    let sector_size = sector_size1;
    let mut bytes_read: u64 = 0;

    // Determine format and virtual size for each device
    let (dev0_info, dev1_info) = if has_chain_config {
        let d0 = &chain_config.devices[0];
        let d1 = &chain_config.devices[1];
        (
            DeviceInfo {
                format: d0.detected_format(),
                virtual_size: d0.virtual_size,
                cluster_size: if d0.cluster_size > 0 {
                    d0.cluster_size as u64
                } else {
                    sector_size as u64
                },
            },
            DeviceInfo {
                format: d1.detected_format(),
                virtual_size: d1.virtual_size,
                cluster_size: if d1.cluster_size > 0 {
                    d1.cluster_size as u64
                } else {
                    sector_size as u64
                },
            },
        )
    } else {
        // No chain config: treat both as raw, use physical capacity
        (
            DeviceInfo {
                format: ImageFormat::Raw,
                virtual_size: cap1 * sector_size as u64,
                cluster_size: sector_size as u64,
            },
            DeviceInfo {
                format: ImageFormat::Raw,
                virtual_size: cap2 * sector_size as u64,
                cluster_size: sector_size as u64,
            },
        )
    };

    (call_table.verbose_print)(b"compare: determined formats\n\0".as_ptr());

    // Initialize QCOW2 state if needed
    let mut qcow2_state0: Option<Qcow2State> = None;
    let mut qcow2_state1: Option<Qcow2State> = None;

    if matches!(dev0_info.format, ImageFormat::Qcow2) {
        qcow2_state0 = init_qcow2_state(
            call_table,
            0,
            sector_size,
            cap1,
            BUF_DEV0_L1_CACHE as *mut u8,
            BUF_DEV0_L2_CACHE as *mut u8,
            &mut bytes_read,
        );
        if qcow2_state0.is_none() {
            (call_table.debug_print)(b"compare: failed to init qcow2 state for dev0\n\0".as_ptr());
            let result = CompareResult::new();
            (call_table.send_compare_result)(&result);
            (call_table.send_complete)(b"compare\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }
        (call_table.verbose_print)(b"compare: initialized qcow2 state for dev0\n\0".as_ptr());
    }

    if matches!(dev1_info.format, ImageFormat::Qcow2) {
        qcow2_state1 = init_qcow2_state(
            call_table,
            1,
            sector_size,
            cap2,
            BUF_DEV1_L1_CACHE as *mut u8,
            BUF_DEV1_L2_CACHE as *mut u8,
            &mut bytes_read,
        );
        if qcow2_state1.is_none() {
            (call_table.debug_print)(b"compare: failed to init qcow2 state for dev1\n\0".as_ptr());
            let result = CompareResult::new();
            (call_table.send_compare_result)(&result);
            (call_table.send_complete)(b"compare\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }
        (call_table.verbose_print)(b"compare: initialized qcow2 state for dev1\n\0".as_ptr());
    }

    // Initialize result
    let mut result = CompareResult::new();

    // Use virtual sizes for comparison
    let vsize1 = dev0_info.virtual_size;
    let vsize2 = dev1_info.virtual_size;
    let sizes_differ = vsize1 != vsize2;

    if sizes_differ {
        result.flags |= CompareResult::FLAG_SIZE_MISMATCH;
    }

    // Use the larger cluster size as the comparison chunk size.
    // Both must be a power of 2 so max works correctly.
    let mut chunk_size = if dev0_info.cluster_size > dev1_info.cluster_size {
        dev0_info.cluster_size
    } else {
        dev1_info.cluster_size
    };

    // Clamp to buffer size: BUF_COMPARE_1/BUF_COMPARE_2 are MAX_SECTOR_SIZE each.
    if chunk_size > MAX_SECTOR_SIZE as u64 {
        chunk_size = MAX_SECTOR_SIZE as u64;
    }

    // Compare virtual content up to the minimum virtual size
    let min_vsize = if vsize1 < vsize2 { vsize1 } else { vsize2 };
    let compare_size = min_vsize;

    let buf1 = BUF_COMPARE_1 as *mut u8;
    let buf2 = BUF_COMPARE_2 as *mut u8;

    (call_table.verbose_print)(b"compare: comparing virtual content\n\0".as_ptr());

    let mut mismatch_found = false;
    let mut virtual_offset: u64 = 0;

    while virtual_offset < min_vsize {
        // How many bytes to compare in this iteration
        let remaining = min_vsize - virtual_offset;
        let this_chunk = if remaining < chunk_size {
            remaining
        } else {
            chunk_size
        };

        // Read virtual data from device 0
        if !read_virtual_cluster(
            call_table,
            0,
            virtual_offset,
            buf1,
            this_chunk,
            sector_size,
            dev0_info.format,
            qcow2_state0.as_mut(),
            cap1,
            &mut bytes_read,
        ) {
            (call_table.send_error)(
                b"compare\0".as_ptr(),
                b"input0\0".as_ptr(),
                virtual_offset / sector_size as u64,
                1,
            );
            result.total_bytes_compared = virtual_offset;
            (call_table.send_compare_result)(&result);
            (call_table.send_complete)(b"compare\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }

        // Read virtual data from device 1
        if !read_virtual_cluster(
            call_table,
            1,
            virtual_offset,
            buf2,
            this_chunk,
            sector_size,
            dev1_info.format,
            qcow2_state1.as_mut(),
            cap2,
            &mut bytes_read,
        ) {
            (call_table.send_error)(
                b"compare\0".as_ptr(),
                b"input1\0".as_ptr(),
                virtual_offset / sector_size as u64,
                1,
            );
            result.total_bytes_compared = virtual_offset;
            (call_table.send_compare_result)(&result);
            (call_table.send_complete)(b"compare\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }

        // Compare the chunk byte by byte to find exact mismatch offset
        let mut i: usize = 0;
        while i < this_chunk as usize {
            if *buf1.add(i) != *buf2.add(i) {
                let mismatch_offset = virtual_offset + i as u64;
                result.identical = 0;
                result.first_mismatch_offset = mismatch_offset;
                result.total_bytes_compared = compare_size;
                mismatch_found = true;
                break;
            }
            i += 1;
        }

        if mismatch_found {
            break;
        }

        virtual_offset += this_chunk;
    }

    if !mismatch_found {
        if sizes_differ {
            // Content within the common range matches, but sizes differ.
            // Check if the extra virtual data in the larger image is all zeros.
            // qemu-img treats as identical when the extra data is zeros.
            let (extra_device, extra_cap, extra_format, extra_vsize) = if vsize1 > vsize2 {
                (0u32, cap1, dev0_info.format, vsize1)
            } else {
                (1u32, cap2, dev1_info.format, vsize2)
            };

            (call_table.verbose_print)(
                b"compare: checking extra virtual data for zeros\n\0".as_ptr(),
            );

            let mut extra_nonzero = false;
            let mut extra_mismatch_byte: u64 = 0;
            let mut extra_offset = min_vsize;

            while extra_offset < extra_vsize {
                let remaining = extra_vsize - extra_offset;
                let this_chunk = if remaining < chunk_size {
                    remaining
                } else {
                    chunk_size
                };

                // Use appropriate state for reading
                let extra_qcow2 = if extra_device == 0 {
                    qcow2_state0.as_mut()
                } else {
                    qcow2_state1.as_mut()
                };

                if !read_virtual_cluster(
                    call_table,
                    extra_device,
                    extra_offset,
                    buf1,
                    this_chunk,
                    sector_size,
                    extra_format,
                    extra_qcow2,
                    extra_cap,
                    &mut bytes_read,
                ) {
                    // I/O error: treat as mismatch
                    extra_nonzero = true;
                    extra_mismatch_byte = extra_offset;
                    break;
                }

                let mut i: usize = 0;
                while i < this_chunk as usize {
                    if *buf1.add(i) != 0 {
                        extra_nonzero = true;
                        extra_mismatch_byte = extra_offset + i as u64;
                        break;
                    }
                    i += 1;
                }
                if extra_nonzero {
                    break;
                }
                extra_offset += this_chunk;
            }

            if extra_nonzero {
                result.identical = 0;
                result.first_mismatch_offset = extra_mismatch_byte;
            } else {
                result.identical = 1;
            }
        } else {
            // Same virtual size, all content matches
            result.identical = 1;
        }
    }

    result.total_bytes_compared = compare_size;

    (call_table.verbose_print)(b"compare: sending result\n\0".as_ptr());

    // Send result
    (call_table.send_compare_result)(&result);

    let success = result.identical != 0;
    (call_table.send_complete)(b"compare\0".as_ptr(), bytes_read, success);
    (call_table.verbose_print)(b"compare: done\n\0".as_ptr());

    bytes_read
}

/// Get the call table from the fixed address.
unsafe fn get_call_table() -> &'static CallTable {
    &*(CALL_TABLE_ADDR as *const CallTable)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        let call_table = get_call_table();
        if call_table.magic == CallTable::MAGIC {
            (call_table.send_error)(b"panic\0".as_ptr(), b"compare\0".as_ptr(), 0, 0xDEAD);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
