//! Compare operation: format-aware image data comparison with backing chain support.
//!
//! This operation reads two images and compares their virtual content, reporting
//! whether they are logically identical. If they differ, it reports the byte
//! offset of the first mismatch.
//!
//! Each image may have a backing chain (e.g., QCOW2 overlay -> base). When a
//! cluster is unallocated in the top image, the operation walks the backing
//! chain to find the data, just like a VM would see.
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
    CHAIN_CONFIG_ADDR, MAX_CHAIN_DEVICES, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
    SCRATCH_MEM_END,
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
// Fixed buffers (3 × MAX_SECTOR_SIZE = 192KB):
const BUF_COMPARE_1: usize = SCRATCH_MEM_BASE;
const BUF_COMPARE_2: usize = BUF_COMPARE_1 + MAX_SECTOR_SIZE;
const BUF_COMPRESSED_IN: usize = BUF_COMPARE_2 + MAX_SECTOR_SIZE;

// Dynamic region: L1/L2 caches for QCOW2 devices (2 × MAX_SECTOR_SIZE per device)
const DYNAMIC_BUFS_START: usize = BUF_COMPRESSED_IN + MAX_SECTOR_SIZE;
const _: () = assert!(
    DYNAMIC_BUFS_START + MAX_CHAIN_DEVICES * 2 * MAX_SECTOR_SIZE <= SCRATCH_MEM_END,
    "Scratch memory too small for MAX_CHAIN_DEVICES L1/L2 caches"
);

/// Get the L1 cache buffer address for a given device index.
fn dev_l1_cache(dev_idx: usize) -> *mut u8 {
    (DYNAMIC_BUFS_START + dev_idx * 2 * MAX_SECTOR_SIZE) as *mut u8
}

/// Get the L2 cache buffer address for a given device index.
fn dev_l2_cache(dev_idx: usize) -> *mut u8 {
    (DYNAMIC_BUFS_START + (dev_idx * 2 + 1) * MAX_SECTOR_SIZE) as *mut u8
}

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

/// Describes the format and key parameters for one image (top of its chain).
struct DeviceInfo {
    virtual_size: u64,
    cluster_size: u64,
}

/// Result of looking up a virtual offset in QCOW2 L1/L2 tables.
enum ClusterLookup {
    /// Cluster is unallocated (reads as zeros, or from backing)
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

    // Validate L1 table offset: must be non-zero and the entire L1 table
    // (l1_table_offset + l1_size * 8) must fit within the input device.
    let actual_size = input_capacity.saturating_mul(sector_size as u64);
    if l1_table_offset == 0 || l1_table_offset >= actual_size {
        return None;
    }
    let l1_table_end = l1_table_offset.checked_add((l1_size as u64).saturating_mul(8))?;
    if l1_table_end > actual_size {
        return None;
    }

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

    // Read L1 entry (use checked arithmetic to prevent overflow)
    let l1_byte_offset = state
        .l1_table_offset
        .checked_add(l1_index.checked_mul(8)?)?;
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

    // Validate L2 table offset against device capacity
    let actual_size = input_capacity.checked_mul(sector_size as u64)?;
    if l2_table_offset >= actual_size {
        return None;
    }

    // Read L2 entry (use checked arithmetic to prevent overflow)
    let l2_byte_offset = l2_table_offset.checked_add(l2_index.checked_mul(8)?)?;
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
    compressed_buf: *mut u8,
    input_capacity: u64,
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
    let nb_sectors_bytes = match nb_sectors.checked_mul(512) {
        Some(v) => v,
        None => return false,
    };
    let offset_remainder = compressed_offset & 511;
    if nb_sectors_bytes < offset_remainder {
        return false;
    }
    let compressed_size = nb_sectors_bytes - offset_remainder;

    if compressed_size == 0 || compressed_size > MAX_SECTOR_SIZE as u64 {
        return false;
    }

    // Validate compressed data range against device capacity
    let data_end = compressed_offset + compressed_size;
    let device_size = input_capacity.saturating_mul(sector_size as u64);
    if data_end > device_size {
        return false;
    }

    // Read compressed data sector by sector
    let first_sector = compressed_offset / sector_size as u64;
    let last_sector = (data_end + sector_size as u64 - 1) / sector_size as u64;
    let sectors_to_read = last_sector - first_sector;

    // Ensure total read fits within the compressed buffer (MAX_SECTOR_SIZE bytes)
    if sectors_to_read * sector_size as u64 > MAX_SECTOR_SIZE as u64 {
        return false;
    }

    // Read all needed sectors into compressed_buf
    // We need to handle the case where compressed data spans multiple sectors
    // and doesn't start at a sector boundary.
    let read_buf = compressed_buf;
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

    // Defense-in-depth: verify the compressed slice lies within the read data
    let total_read = (sectors_to_read as usize) * sector_size;
    if start_within_buf + compressed_size as usize > total_read {
        return false;
    }

    let compressed_data = read_buf.add(start_within_buf);

    // Decompress using miniz_oxide raw deflate
    let compressed_slice = core::slice::from_raw_parts(compressed_data, compressed_size as usize);
    let out_slice = core::slice::from_raw_parts_mut(out_buf, cluster_size as usize);

    // Use miniz_oxide's low-level decompress API for no_std
    use miniz_oxide::inflate::core::inflate_flags;
    use miniz_oxide::inflate::TINFLStatus;

    let mut decomp = miniz_oxide::inflate::core::DecompressorOxide::new();
    let (status, _in_consumed, out_produced) = miniz_oxide::inflate::core::decompress(
        &mut decomp,
        compressed_slice,
        out_slice,
        0,
        inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );

    // Check that decompression succeeded and produced exactly one cluster.
    // Only Done is acceptable — HasMoreOutput means the data decompresses to
    // more than cluster_size bytes, indicating a corrupt or malicious image.
    if status != TINFLStatus::Done || out_produced != cluster_size as usize {
        // Try again without ZLIB header (raw deflate) since QCOW2
        // compression stores raw deflate data wrapped in a zlib stream
        let mut decomp2 = miniz_oxide::inflate::core::DecompressorOxide::new();
        let (status2, _in2, out2) = miniz_oxide::inflate::core::decompress(
            &mut decomp2,
            compressed_slice,
            out_slice,
            0,
            inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        if status2 != TINFLStatus::Done || out2 != cluster_size as usize {
            return false;
        }
    }

    true
}

/// Read raw sectors from a device for a given virtual offset range.
unsafe fn read_raw_sectors(
    call_table: &CallTable,
    device_idx: u32,
    virtual_offset: u64,
    buf: *mut u8,
    chunk_size: u64,
    sector_size: usize,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> bool {
    let first_sector = virtual_offset / sector_size as u64;
    let sectors_per_cluster = chunk_size / sector_size as u64;

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
        if !(call_table.read_input_sector)(device_idx, sector, buf.add(buf_offset), sector_size) {
            return false;
        }
        *bytes_read += sector_size as u64;
    }
    true
}

/// Read one cluster's worth of virtual data by walking a backing chain.
///
/// For each device in the chain (starting from the top):
/// - QCOW2: perform L1/L2 lookup. If unallocated, try next device.
/// - Raw/other: read sectors directly (always the base of the chain).
/// If all devices have the cluster unallocated, fills with zeros.
unsafe fn read_chain_virtual_cluster(
    call_table: &CallTable,
    chain_start: usize,
    chain_len: usize,
    virtual_offset: u64,
    buf: *mut u8,
    chunk_size: u64,
    sector_size: usize,
    chain_config: &ChainConfig,
    qcow2_states: &mut [Option<Qcow2State>; MAX_CHAIN_DEVICES],
    bytes_read: &mut u64,
) -> bool {
    for dev_offset in 0..chain_len {
        let dev_idx = chain_start + dev_offset;
        let format = chain_config.devices[dev_idx].detected_format();
        let cap = (call_table.get_input_capacity)(dev_idx as u32);

        match format {
            ImageFormat::Qcow2 => {
                let state = match &mut qcow2_states[dev_idx] {
                    Some(s) => s,
                    None => return false,
                };

                // Always use the actual QCOW2 cluster size for reading/decompressing.
                // The caller may pass a smaller chunk_size for the final partial chunk,
                // but QCOW2 clusters must be read in full (decompression expects exactly
                // one cluster). The caller limits how many bytes are compared afterward.
                let qcow2_cluster_size = state.cluster_size;
                debug_assert!(qcow2_cluster_size <= MAX_SECTOR_SIZE as u64);

                match qcow2_cluster_lookup(
                    call_table,
                    state,
                    virtual_offset,
                    sector_size,
                    cap,
                    bytes_read,
                ) {
                    Some(ClusterLookup::Unallocated) => {
                        // Not in this device, try next in chain
                        continue;
                    }
                    Some(ClusterLookup::Standard(host_offset)) => {
                        return read_cluster_sectors(
                            call_table,
                            dev_idx as u32,
                            host_offset,
                            buf,
                            qcow2_cluster_size,
                            sector_size,
                            bytes_read,
                        );
                    }
                    Some(ClusterLookup::Compressed(l2_entry)) => {
                        return read_compressed_cluster(
                            call_table,
                            dev_idx as u32,
                            l2_entry,
                            state.cluster_bits,
                            buf,
                            qcow2_cluster_size,
                            sector_size,
                            BUF_COMPRESSED_IN as *mut u8,
                            cap,
                            bytes_read,
                        );
                    }
                    None => return false,
                }
            }
            _ => {
                // Raw/unknown: read sectors directly (base of chain)
                return read_raw_sectors(
                    call_table,
                    dev_idx as u32,
                    virtual_offset,
                    buf,
                    chunk_size,
                    sector_size,
                    cap,
                    bytes_read,
                );
            }
        }
    }
    // All devices in chain had unallocated: fill with zeros
    core::ptr::write_bytes(buf, 0, chunk_size as usize);
    true
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

    // Get operation config (includes chain boundary fields)
    let config_ptr = OPERATION_CONFIG_ADDR as *const CompareConfig;
    let config = &*config_ptr;
    let _strict = if config.is_valid() {
        config.is_strict()
    } else {
        false
    };

    // Read chain boundary fields from CompareConfig
    let image1_device_count = if config.is_valid() {
        config.image1_device_count() as usize
    } else {
        1
    };
    let image2_device_count = if config.is_valid() {
        config.image2_device_count() as usize
    } else {
        1
    };
    let image2_start = image1_device_count;
    let total_devices = image1_device_count + image2_device_count;

    // Bounds-check total_devices against the fixed-size arrays it will index
    if total_devices > MAX_CHAIN_DEVICES {
        (call_table.debug_print)(b"compare: total devices exceeds max\n\0".as_ptr());
        let result = CompareResult::new();
        (call_table.send_compare_result)(&result);
        (call_table.send_complete)(b"compare\0".as_ptr(), 0, false);
        return 0;
    }

    // Read ChainConfig to learn format and virtual size for each device.
    // In compare, device_count is the total across both chains (always >= 2),
    // so we use is_valid() which checks magic and device_count > 0.
    let chain_config = &*(CHAIN_CONFIG_ADDR as *const ChainConfig);
    if !chain_config.is_valid() {
        // The compare operation requires a valid ChainConfig to determine
        // each device's format (QCOW2 vs raw). Without it, the comparison
        // loop would read from uninitialized memory. The VMM always writes
        // a ChainConfig for compare, so this is a defensive guard.
        (call_table.debug_print)(b"compare: missing chain config\n\0".as_ptr());
        let result = CompareResult::new();
        (call_table.send_compare_result)(&result);
        (call_table.send_complete)(b"compare\0".as_ptr(), 0, false);
        return 0;
    }

    // Verify all devices have consistent sector size
    let sector_size = (call_table.get_input_sector_size)(0);
    for dev_idx in 1..total_devices {
        let dev_sector_size = (call_table.get_input_sector_size)(dev_idx as u32);
        if dev_sector_size != sector_size {
            (call_table.debug_print)(b"compare: sector size mismatch\n\0".as_ptr());
            let mut result = CompareResult::new();
            result.identical = 0;
            result.flags |= CompareResult::FLAG_SIZE_MISMATCH;
            (call_table.send_compare_result)(&result);
            (call_table.send_complete)(b"compare\0".as_ptr(), 0, false);
            return 0;
        }
    }

    let mut bytes_read: u64 = 0;

    (call_table.verbose_print)(b"compare: got capacities\n\0".as_ptr());

    // Determine virtual size and cluster size for each image (from top of chain)
    let d0 = &chain_config.devices[0];
    let d1 = &chain_config.devices[image2_start];
    let (dev0_info, dev1_info) = (
        DeviceInfo {
            virtual_size: d0.virtual_size,
            cluster_size: if d0.cluster_size > 0 {
                d0.cluster_size as u64
            } else {
                sector_size as u64
            },
        },
        DeviceInfo {
            virtual_size: d1.virtual_size,
            cluster_size: if d1.cluster_size > 0 {
                d1.cluster_size as u64
            } else {
                sector_size as u64
            },
        },
    );

    (call_table.verbose_print)(b"compare: determined formats\n\0".as_ptr());

    // Initialize QCOW2 state for all QCOW2 devices across both chains
    let mut qcow2_states: [Option<Qcow2State>; MAX_CHAIN_DEVICES] = Default::default();

    for dev_idx in 0..total_devices {
        let dev_info = &chain_config.devices[dev_idx];
        if matches!(dev_info.detected_format(), ImageFormat::Qcow2) {
            let cap = (call_table.get_input_capacity)(dev_idx as u32);
            qcow2_states[dev_idx] = init_qcow2_state(
                call_table,
                dev_idx as u32,
                sector_size,
                cap,
                dev_l1_cache(dev_idx),
                dev_l2_cache(dev_idx),
                &mut bytes_read,
            );
            if qcow2_states[dev_idx].is_none() {
                (call_table.debug_print)(b"compare: failed to init qcow2 state\n\0".as_ptr());
                let result = CompareResult::new();
                (call_table.send_compare_result)(&result);
                (call_table.send_complete)(b"compare\0".as_ptr(), bytes_read, false);
                return bytes_read;
            }
        }
    }

    (call_table.verbose_print)(b"compare: initialized device states\n\0".as_ptr());

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

        // Read virtual data from image1's chain
        if !read_chain_virtual_cluster(
            call_table,
            0,
            image1_device_count,
            virtual_offset,
            buf1,
            this_chunk,
            sector_size,
            chain_config,
            &mut qcow2_states,
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

        // Read virtual data from image2's chain
        if !read_chain_virtual_cluster(
            call_table,
            image2_start,
            image2_device_count,
            virtual_offset,
            buf2,
            this_chunk,
            sector_size,
            chain_config,
            &mut qcow2_states,
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
            let (extra_chain_start, extra_chain_len, extra_vsize) = if vsize1 > vsize2 {
                (0usize, image1_device_count, vsize1)
            } else {
                (image2_start, image2_device_count, vsize2)
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

                if !read_chain_virtual_cluster(
                    call_table,
                    extra_chain_start,
                    extra_chain_len,
                    extra_offset,
                    buf1,
                    this_chunk,
                    sector_size,
                    chain_config,
                    &mut qcow2_states,
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
