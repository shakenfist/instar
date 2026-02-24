//! Convert operation: read from any supported input format and write
//! to raw or QCOW2 output.
//!
//! Reads virtual content from an input image that may have a QCOW2
//! backing chain, and writes it to an output device in the requested
//! format. Compressed and standard clusters are handled transparently
//! via the shared qcow2 crate's chain-walking reader.
//!
//! Progress is reported via send_progress() and completion via
//! send_complete(). No special result message is needed (matching
//! qemu-img convert which produces no stdout on success).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

// 256KB bump allocator for miniz_oxide compression and ruzstd
// ZSTD decoding. Reset HEAP_POS to 0 between operations.
shared::bump_allocator!(256 * 1024);

use shared::{
    is_all_zeros_ptr, should_report_progress, validate_call_table, verify_sector_sizes, CallTable,
    ChainConfig, ConvertConfig, ImageFormat, CALL_TABLE_ADDR, CHAIN_CONFIG_ADDR,
    COMPRESSED_BUF_SIZE, MAX_CHAIN_DEVICES, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR,
    SCRATCH_MEM_BASE, SCRATCH_MEM_END,
};

// ================================================================
// Scratch memory layout
// ================================================================
// Fixed buffers (used by both raw and QCOW2 output paths):
//   BUF_DATA         (64KB): input/output data buffer
//   BUF_COMPRESSED_IN (128KB): compressed input data (also
//                     reused as compressed output buffer)
//
// Additional fixed buffers for QCOW2 output (unused by raw path,
// but always reserved to keep the layout consistent):
//   BUF_L2_OUT   (64KB): current output L2 table being built
//   BUF_HEADER   (64KB): header cluster buffer
//   BUF_REFCOUNT (64KB): refcount block buffer
//
// Dynamic region: L1/L2 caches for input QCOW2 devices
//   (2 × MAX_SECTOR_SIZE per device)
//
// After dynamic caches: output L1 table (QCOW2 path only,
//   size computed at runtime)
//
// For compressed QCOW2 output (after L1 table):
//   Refcount array: u16 per host cluster, remaining scratch

const BUF_DATA: usize = SCRATCH_MEM_BASE;
const BUF_COMPRESSED_IN: usize = BUF_DATA + MAX_SECTOR_SIZE;
const BUF_L2_OUT: usize = BUF_COMPRESSED_IN + COMPRESSED_BUF_SIZE;
const BUF_HEADER: usize = BUF_L2_OUT + MAX_SECTOR_SIZE;
const BUF_REFCOUNT: usize = BUF_HEADER + MAX_SECTOR_SIZE;
const DYNAMIC_BUFS_START: usize = BUF_REFCOUNT + MAX_SECTOR_SIZE;

const _: () = assert!(
    DYNAMIC_BUFS_START + MAX_CHAIN_DEVICES * 2 * MAX_SECTOR_SIZE <= SCRATCH_MEM_END,
    "Scratch memory too small for MAX_CHAIN_DEVICES L1/L2 caches"
);

/// Entry point called by core after devices are initialized.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    validate_call_table!(call_table, "convert");

    (call_table.verbose_print)(b"convert: start\n\0".as_ptr());

    // Read ConvertConfig
    let config_ptr = OPERATION_CONFIG_ADDR as *const ConvertConfig;
    let config = &*config_ptr;

    let (input_device_count, skip_zeros) = if config.is_valid() {
        (
            config.input_device_count() as usize,
            config.should_skip_zeros(),
        )
    } else {
        (1, false)
    };

    if input_device_count < 1 || input_device_count > MAX_CHAIN_DEVICES {
        (call_table.debug_print)(b"convert: invalid device count\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
        return 0;
    }

    // Read ChainConfig
    let chain_config = &*(CHAIN_CONFIG_ADDR as *const ChainConfig);
    if !chain_config.is_valid() {
        (call_table.debug_print)(b"convert: missing chain config\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
        return 0;
    }

    // Verify input sector sizes are consistent
    let sector_size = match verify_sector_sizes(call_table, input_device_count) {
        Some(ss) => ss,
        None => {
            (call_table.debug_print)(b"convert: sector size mismatch\n\0".as_ptr());
            (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
            return 0;
        }
    };

    let mut bytes_read: u64 = 0;

    // Get virtual size from top-of-chain device
    let top_dev = &chain_config.devices[0];
    let virtual_size = top_dev.virtual_size;
    if virtual_size == 0 {
        (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
        return 0;
    }

    (call_table.verbose_print)(b"convert: initializing qcow2 states\n\0".as_ptr());

    // Initialize QCOW2 state for each QCOW2 input device
    let mut qcow2_states: [Option<qcow2::Qcow2State>; MAX_CHAIN_DEVICES] = Default::default();

    if !qcow2::init_chain_qcow2_states(
        call_table,
        chain_config,
        &mut qcow2_states,
        input_device_count,
        sector_size,
        DYNAMIC_BUFS_START,
        &mut bytes_read,
    ) {
        (call_table.debug_print)(b"convert: failed to init qcow2\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
        return bytes_read;
    }

    // Reject QCOW2 images with unsupported incompatible features
    for state in qcow2_states.iter().flatten() {
        let unsupported = state.unsupported_incompat_features(qcow2::SUPPORTED_INCOMPAT_FEATURES);
        if unsupported != 0 {
            (call_table.debug_print)(b"convert: unsupported incompatible features\n\0".as_ptr());
            (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }
    }

    // Dispatch based on target format
    let target = config.target_format();
    match target {
        ImageFormat::Qcow2 => {
            if config.should_compress() {
                convert_to_qcow2_compressed(
                    call_table,
                    config,
                    chain_config,
                    &mut qcow2_states,
                    input_device_count,
                    virtual_size,
                    sector_size,
                    skip_zeros,
                    &mut bytes_read,
                )
            } else {
                convert_to_qcow2(
                    call_table,
                    config,
                    chain_config,
                    &mut qcow2_states,
                    input_device_count,
                    virtual_size,
                    sector_size,
                    skip_zeros,
                    &mut bytes_read,
                )
            }
        }
        _ => convert_to_raw(
            call_table,
            chain_config,
            &mut qcow2_states,
            input_device_count,
            virtual_size,
            sector_size,
            skip_zeros,
            &mut bytes_read,
        ),
    }
}

// ================================================================
// Raw output path (existing Phase 3 logic)
// ================================================================

unsafe fn convert_to_raw(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    qcow2_states: &mut [Option<qcow2::Qcow2State>; MAX_CHAIN_DEVICES],
    input_device_count: usize,
    virtual_size: u64,
    sector_size: usize,
    skip_zeros: bool,
    bytes_read: &mut u64,
) -> u64 {
    let output_sector_size = (call_table.get_output_sector_size)();
    let output_capacity = (call_table.get_output_capacity)();
    let progress_interval = (call_table.get_progress_interval)();

    let top_dev = &chain_config.devices[0];
    let cluster_size = if top_dev.cluster_size > 0 {
        top_dev.cluster_size as u64
    } else {
        sector_size as u64
    };

    let chunk_size = if cluster_size > MAX_SECTOR_SIZE as u64 {
        MAX_SECTOR_SIZE as u64
    } else {
        cluster_size
    };

    if chunk_size < output_sector_size as u64 {
        (call_table.debug_print)(b"convert: chunk < output sector size\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
        return 0;
    }

    (call_table.verbose_print)(b"convert: starting raw conversion\n\0".as_ptr());

    let buf = BUF_DATA as *mut u8;
    let mut virtual_offset: u64 = 0;
    let mut last_percent: u32 = 0;
    let mut chunks_done: u64 = 0;
    let total_chunks = (virtual_size + chunk_size - 1) / chunk_size;

    while virtual_offset < virtual_size {
        let remaining = virtual_size - virtual_offset;
        let this_chunk = if remaining < chunk_size {
            remaining
        } else {
            chunk_size
        };

        // Reset bump allocator before ZSTD decompression
        HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

        if !qcow2::read_chain_virtual_cluster(
            call_table,
            0,
            input_device_count,
            virtual_offset,
            buf,
            this_chunk,
            sector_size,
            chain_config,
            qcow2_states,
            BUF_COMPRESSED_IN as *mut u8,
            bytes_read,
        ) {
            (call_table.send_error)(
                b"convert\0".as_ptr(),
                b"input\0".as_ptr(),
                virtual_offset / sector_size as u64,
                1,
            );
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }

        if skip_zeros && is_all_zeros_ptr(buf, this_chunk as usize) {
            virtual_offset += this_chunk;
            chunks_done += 1;
            let percent = (chunks_done * 100 / total_chunks) as u32;
            if should_report_progress(progress_interval, percent, last_percent, chunks_done) {
                (call_table.send_progress)(
                    b"convert\0".as_ptr(),
                    chunks_done,
                    total_chunks,
                    percent,
                );
                last_percent = percent;
            }
            continue;
        }

        let output_first_sector = virtual_offset / output_sector_size as u64;
        let sectors_per_chunk =
            (this_chunk + output_sector_size as u64 - 1) / output_sector_size as u64;

        for i in 0..sectors_per_chunk {
            let output_sector = output_first_sector + i;
            if output_sector >= output_capacity {
                break;
            }
            let offset = (i as usize) * output_sector_size;
            if !(call_table.write_output_sector)(output_sector, buf.add(offset), output_sector_size)
            {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    output_sector,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }
        }

        virtual_offset += this_chunk;
        chunks_done += 1;

        let percent = (chunks_done * 100 / total_chunks) as u32;
        if should_report_progress(progress_interval, percent, last_percent, chunks_done) {
            (call_table.send_progress)(b"convert\0".as_ptr(), chunks_done, total_chunks, percent);
            last_percent = percent;
        }
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, true);
    (call_table.verbose_print)(b"convert: done\n\0".as_ptr());
    *bytes_read
}

// ================================================================
// QCOW2 output path
// ================================================================

/// Write a cluster-sized buffer to the output device at the given
/// byte offset. Returns false on I/O error.
unsafe fn write_cluster_to_output(
    call_table: &CallTable,
    buf: *const u8,
    byte_offset: u64,
    cluster_size: u64,
    output_sector_size: usize,
    output_capacity: u64,
) -> bool {
    write_bytes_to_output(
        call_table,
        buf,
        byte_offset,
        cluster_size,
        output_sector_size,
        output_capacity,
    )
}

/// Write an arbitrary number of bytes to the output device at the
/// given byte offset. byte_count is rounded up to the output
/// sector size for the final sector write. Returns false on I/O
/// error.
unsafe fn write_bytes_to_output(
    call_table: &CallTable,
    buf: *const u8,
    byte_offset: u64,
    byte_count: u64,
    output_sector_size: usize,
    output_capacity: u64,
) -> bool {
    let first_sector = byte_offset / output_sector_size as u64;
    let sectors = (byte_count + output_sector_size as u64 - 1) / output_sector_size as u64;
    for i in 0..sectors {
        let sector = first_sector + i;
        if sector >= output_capacity {
            return false;
        }
        if !(call_table.write_output_sector)(
            sector,
            buf.add(i as usize * output_sector_size),
            output_sector_size,
        ) {
            return false;
        }
    }
    true
}

/// Calculate refcount table layout. Returns
/// (reftable_clusters, refblock_count, total_clusters).
fn calculate_refcount_layout(used_clusters: u64, cluster_size: u64) -> (u64, u64, u64) {
    // 16-bit refcounts: entries per refcount block
    let entries_per_refblock = cluster_size / 2;

    // Iterate: metadata size depends on total clusters,
    // which includes the metadata itself.
    let mut reftable_clusters: u64 = 1;
    let mut refblock_count: u64 = 1;

    for _ in 0..10 {
        let total = used_clusters + reftable_clusters + refblock_count;
        let new_refblock_count = (total + entries_per_refblock - 1) / entries_per_refblock;
        // Each reftable entry is 8 bytes (u64 offset)
        let reftable_entries = new_refblock_count;
        let new_reftable_clusters = (reftable_entries * 8 + cluster_size - 1) / cluster_size;
        if new_refblock_count == refblock_count && new_reftable_clusters == reftable_clusters {
            break;
        }
        refblock_count = new_refblock_count;
        reftable_clusters = new_reftable_clusters;
    }

    let total = used_clusters + reftable_clusters + refblock_count;
    (reftable_clusters, refblock_count, total)
}

/// Write the QCOW2 v3 header at cluster 0.
unsafe fn write_qcow2_header(
    call_table: &CallTable,
    cluster_bits: u32,
    cluster_size: u64,
    virtual_size: u64,
    l1_size: u32,
    l1_offset: u64,
    reftable_offset: u64,
    reftable_clusters: u64,
    output_sector_size: usize,
    output_capacity: u64,
) -> bool {
    let buf_hdr = BUF_HEADER as *mut u8;
    core::ptr::write_bytes(buf_hdr, 0, cluster_size as usize);
    let hdr = core::slice::from_raw_parts_mut(buf_hdr, cluster_size as usize);

    qcow2::write_be_u32(hdr, 0, qcow2::QCOW2_MAGIC);
    qcow2::write_be_u32(hdr, 4, qcow2::QCOW2_VERSION_3);
    // backing_file_offset (8) and backing_file_size (16) = 0
    qcow2::write_be_u32(hdr, 20, cluster_bits);
    qcow2::write_be_u64(hdr, 24, virtual_size);
    // crypt_method (32) = 0
    qcow2::write_be_u32(hdr, 36, l1_size);
    qcow2::write_be_u64(hdr, 40, l1_offset);
    qcow2::write_be_u64(hdr, 48, reftable_offset);
    qcow2::write_be_u32(hdr, 56, reftable_clusters as u32);
    // nb_snapshots (60) = 0, snapshots_offset (64) = 0
    // incompatible_features (72) = 0
    // compatible_features (80) = 0
    // autoclear_features (88) = 0
    qcow2::write_be_u32(hdr, 96, qcow2::QCOW2_DEFAULT_REFCOUNT_ORDER); // refcount_order
    qcow2::write_be_u32(hdr, 100, qcow2::QCOW2_HEADER_LENGTH_V3); // header_length

    write_cluster_to_output(
        call_table,
        buf_hdr,
        0,
        cluster_size,
        output_sector_size,
        output_capacity,
    )
}

// ================================================================
// Shared QCOW2 output helpers
// ================================================================

/// Computed layout parameters for QCOW2 output. Used by both
/// uncompressed and compressed paths to avoid duplicating the
/// initialization logic.
struct Qcow2OutputLayout {
    cluster_bits: u32,
    cluster_size: u64,
    entries_per_l2: u32,
    l1_size: u32,
    l1_buf: *mut u8,
    l1_clusters: u64,
    l1_write_bytes: usize,
    /// First byte after the L1 buffer in scratch memory.
    l1_buf_end: usize,
    total_virtual_clusters: u64,
    output_sector_size: usize,
    output_capacity: u64,
    progress_interval: u32,
}

/// Compute QCOW2 output layout from config. Returns None and
/// sends an error if the L1 table doesn't fit in scratch memory.
unsafe fn init_qcow2_output_layout(
    call_table: &CallTable,
    config: &ConvertConfig,
    input_device_count: usize,
    virtual_size: u64,
    bytes_read: &mut u64,
) -> Option<Qcow2OutputLayout> {
    let output_sector_size = (call_table.get_output_sector_size)();
    let output_capacity = (call_table.get_output_capacity)();
    let progress_interval = (call_table.get_progress_interval)();

    let cluster_bits = config.output_cluster_bits();
    let cluster_size = 1u64 << cluster_bits;
    let entries_per_l2 = (cluster_size / 8) as u32;
    let l2_coverage = cluster_size * entries_per_l2 as u64;
    let l1_size = ((virtual_size + l2_coverage - 1) / l2_coverage) as u32;

    let l1_buf_addr = DYNAMIC_BUFS_START + input_device_count * 2 * MAX_SECTOR_SIZE;
    let l1_size_bytes = l1_size as usize * 8;
    let l1_clusters = ((l1_size_bytes as u64 + cluster_size - 1) / cluster_size).max(1);
    let l1_write_bytes = l1_clusters as usize * cluster_size as usize;

    if l1_buf_addr + l1_write_bytes > SCRATCH_MEM_END {
        (call_table.debug_print)(b"convert: L1 too large for scratch\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return None;
    }

    let l1_buf = l1_buf_addr as *mut u8;
    core::ptr::write_bytes(l1_buf, 0, l1_write_bytes);

    let total_virtual_clusters = (virtual_size + cluster_size - 1) / cluster_size;

    Some(Qcow2OutputLayout {
        cluster_bits,
        cluster_size,
        entries_per_l2,
        l1_size,
        l1_buf,
        l1_clusters,
        l1_write_bytes,
        l1_buf_end: l1_buf_addr + l1_write_bytes,
        total_virtual_clusters,
        output_sector_size,
        output_capacity,
        progress_interval,
    })
}

/// Write QCOW2 metadata: L1 table, refcount structures, and
/// header. Used by both uncompressed and compressed paths.
///
/// `data_end_offset` is the byte offset where data ends and
/// metadata begins (must be cluster-aligned).
///
/// When `refcount_array` is Some, refcount values are read from
/// the tracked array (compressed path). When None, all clusters
/// get refcount=1 (uncompressed path where every cluster is
/// allocated exactly once).
///
/// Returns true on success.
#[allow(clippy::too_many_arguments)]
unsafe fn write_qcow2_metadata(
    call_table: &CallTable,
    layout: &Qcow2OutputLayout,
    virtual_size: u64,
    data_end_offset: u64,
    refcount_array: Option<(*mut u16, usize)>,
    bytes_read: &mut u64,
) -> bool {
    let cs = layout.cluster_size;
    let oss = layout.output_sector_size;
    let oc = layout.output_capacity;

    // L1 table
    let l1_offset = data_end_offset;
    for c in 0..layout.l1_clusters {
        let off = l1_offset + c * cs;
        let ptr = layout.l1_buf.add(c as usize * cs as usize);
        if !write_cluster_to_output(call_table, ptr, off, cs, oss, oc) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return false;
        }
        if let Some((arr, max)) = refcount_array {
            inc_refcount(arr, off / cs, max);
        }
    }

    let clusters_before_refcount = if refcount_array.is_some() {
        // Compressed: also track header cluster
        let (arr, max) = refcount_array.unwrap();
        inc_refcount(arr, 0, max);
        (l1_offset + layout.l1_clusters * cs) / cs
    } else {
        // Uncompressed: simple cluster count
        data_end_offset / cs + layout.l1_clusters
    };

    // Refcount structures
    let (reftable_clusters, refblock_count, total_clusters) =
        calculate_refcount_layout(clusters_before_refcount, cs);

    let reftable_offset = clusters_before_refcount * cs;
    let refblock_base_offset = reftable_offset + reftable_clusters * cs;
    let entries_per_refblock = cs / 2;

    // Track refcounts for reftable/refblock clusters
    if let Some((arr, max)) = refcount_array {
        for c in clusters_before_refcount..total_clusters {
            inc_refcount(arr, c, max);
        }
    }

    // Write refcount blocks
    let buf_rc = BUF_REFCOUNT as *mut u8;
    for rb in 0..refblock_count {
        core::ptr::write_bytes(buf_rc, 0, cs as usize);
        let rc_slice = core::slice::from_raw_parts_mut(buf_rc, cs as usize);

        let first_in_block = rb * entries_per_refblock;
        let entries = core::cmp::min(
            entries_per_refblock,
            total_clusters.saturating_sub(first_in_block),
        );
        for e in 0..entries {
            let refcount = if let Some((arr, max)) = refcount_array {
                let idx = (first_in_block + e) as usize;
                if idx < max {
                    core::ptr::read(arr.add(idx))
                } else {
                    1
                }
            } else {
                1
            };
            qcow2::write_be_u16(rc_slice, e as usize * 2, refcount);
        }

        let rb_offset = refblock_base_offset + rb * cs;
        if !write_cluster_to_output(call_table, buf_rc, rb_offset, cs, oss, oc) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return false;
        }
    }

    // Write refcount table
    if !write_refcount_table(
        call_table,
        cs,
        reftable_offset,
        reftable_clusters,
        refblock_base_offset,
        refblock_count,
        oss,
        oc,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return false;
    }

    // Write header
    if !write_qcow2_header(
        call_table,
        layout.cluster_bits,
        cs,
        virtual_size,
        layout.l1_size,
        l1_offset,
        reftable_offset,
        reftable_clusters,
        oss,
        oc,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return false;
    }

    true
}

// ================================================================
// Uncompressed QCOW2 output (Phase 4)
// ================================================================

#[allow(clippy::too_many_arguments)]
unsafe fn convert_to_qcow2(
    call_table: &CallTable,
    config: &ConvertConfig,
    chain_config: &ChainConfig,
    qcow2_states: &mut [Option<qcow2::Qcow2State>; MAX_CHAIN_DEVICES],
    input_device_count: usize,
    virtual_size: u64,
    sector_size: usize,
    skip_zeros: bool,
    bytes_read: &mut u64,
) -> u64 {
    let layout = match init_qcow2_output_layout(
        call_table,
        config,
        input_device_count,
        virtual_size,
        bytes_read,
    ) {
        Some(l) => l,
        None => return *bytes_read,
    };

    let buf_data = BUF_DATA as *mut u8;
    let buf_l2 = BUF_L2_OUT as *mut u8;

    (call_table.verbose_print)(b"convert: starting qcow2 conversion\n\0".as_ptr());

    // Linear cluster allocator. Cluster 0 is the header.
    let mut next_free: u64 = 1;

    let mut clusters_done: u64 = 0;
    let mut last_percent: u32 = 0;

    // Process each L2 range
    for l1_idx in 0..layout.l1_size {
        // Zero the L2 buffer
        core::ptr::write_bytes(buf_l2, 0, layout.cluster_size as usize);

        let mut l2_allocated = false;
        let mut l2_cluster: u64 = 0;

        let first_vc = l1_idx as u64 * layout.entries_per_l2 as u64;
        let last_vc = core::cmp::min(
            first_vc + layout.entries_per_l2 as u64,
            layout.total_virtual_clusters,
        );

        for vc in first_vc..last_vc {
            let virtual_offset = vc * layout.cluster_size;
            let remaining = virtual_size - virtual_offset;
            let this_chunk = core::cmp::min(remaining, layout.cluster_size);

            // Reset bump allocator before ZSTD decompression
            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            // Read input data
            if !qcow2::read_chain_virtual_cluster(
                call_table,
                0,
                input_device_count,
                virtual_offset,
                buf_data,
                this_chunk,
                sector_size,
                chain_config,
                qcow2_states,
                BUF_COMPRESSED_IN as *mut u8,
                bytes_read,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"input\0".as_ptr(),
                    virtual_offset / sector_size as u64,
                    1,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Skip zero clusters when configured
            if skip_zeros && is_all_zeros_ptr(buf_data, this_chunk as usize) {
                clusters_done += 1;
                let pct = (clusters_done * 100 / layout.total_virtual_clusters) as u32;
                if should_report_progress(
                    layout.progress_interval,
                    pct,
                    last_percent,
                    clusters_done,
                ) {
                    (call_table.send_progress)(
                        b"convert\0".as_ptr(),
                        clusters_done,
                        layout.total_virtual_clusters,
                        pct,
                    );
                    last_percent = pct;
                }
                continue;
            }

            // Allocate L2 table on first non-zero cluster
            if !l2_allocated {
                l2_cluster = next_free;
                next_free += 1;
                l2_allocated = true;
            }

            // Allocate data cluster
            let data_cluster = next_free;
            next_free += 1;
            let data_offset = data_cluster * layout.cluster_size;

            // Zero-pad if this is a partial final cluster
            if this_chunk < layout.cluster_size {
                core::ptr::write_bytes(
                    buf_data.add(this_chunk as usize),
                    0,
                    (layout.cluster_size - this_chunk) as usize,
                );
            }

            // Write data cluster to output
            if !write_cluster_to_output(
                call_table,
                buf_data,
                data_offset,
                layout.cluster_size,
                layout.output_sector_size,
                layout.output_capacity,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    data_offset / layout.output_sector_size as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Set L2 entry: standard cluster at data_offset
            // OFLAG_COPIED (bit 63) must be set when refcount=1
            let l2_entry_idx = (vc - first_vc) as usize;
            let l2_slice = core::slice::from_raw_parts_mut(buf_l2, layout.cluster_size as usize);
            qcow2::write_be_u64(l2_slice, l2_entry_idx * 8, data_offset | (1u64 << 63));

            clusters_done += 1;
            let pct = (clusters_done * 100 / layout.total_virtual_clusters) as u32;
            if should_report_progress(layout.progress_interval, pct, last_percent, clusters_done) {
                (call_table.send_progress)(
                    b"convert\0".as_ptr(),
                    clusters_done,
                    layout.total_virtual_clusters,
                    pct,
                );
                last_percent = pct;
            }
        }

        // Flush L2 table if any data was written
        if l2_allocated {
            let l2_offset = l2_cluster * layout.cluster_size;
            if !write_cluster_to_output(
                call_table,
                buf_l2,
                l2_offset,
                layout.cluster_size,
                layout.output_sector_size,
                layout.output_capacity,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    l2_offset / layout.output_sector_size as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Record L2 offset in L1 table
            // OFLAG_COPIED (bit 63) must be set when refcount=1
            let l1_slice = core::slice::from_raw_parts_mut(layout.l1_buf, layout.l1_write_bytes);
            qcow2::write_be_u64(l1_slice, l1_idx as usize * 8, l2_offset | (1u64 << 63));
        }
    }

    // -- Write metadata at end --
    let data_end_offset = next_free * layout.cluster_size;
    if !write_qcow2_metadata(
        call_table,
        &layout,
        virtual_size,
        data_end_offset,
        None,
        bytes_read,
    ) {
        return *bytes_read;
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, true);
    (call_table.verbose_print)(b"convert: done\n\0".as_ptr());
    *bytes_read
}

/// Write the refcount table (array of u64 offsets to refcount
/// blocks).
unsafe fn write_refcount_table(
    call_table: &CallTable,
    cluster_size: u64,
    reftable_offset: u64,
    reftable_clusters: u64,
    refblock_base_offset: u64,
    refblock_count: u64,
    output_sector_size: usize,
    output_capacity: u64,
) -> bool {
    let buf_rc = BUF_REFCOUNT as *mut u8;
    for rt_cluster in 0..reftable_clusters {
        core::ptr::write_bytes(buf_rc, 0, cluster_size as usize);
        let rt_slice = core::slice::from_raw_parts_mut(buf_rc, cluster_size as usize);

        let entries_per_rt_cluster = cluster_size / 8;
        let first_entry = rt_cluster * entries_per_rt_cluster;
        let count = core::cmp::min(
            entries_per_rt_cluster,
            refblock_count.saturating_sub(first_entry),
        );
        for e in 0..count {
            let rb_idx = first_entry + e;
            let rb_off = refblock_base_offset + rb_idx * cluster_size;
            qcow2::write_be_u64(rt_slice, e as usize * 8, rb_off);
        }

        let rt_off = reftable_offset + rt_cluster * cluster_size;
        if !write_cluster_to_output(
            call_table,
            buf_rc,
            rt_off,
            cluster_size,
            output_sector_size,
            output_capacity,
        ) {
            return false;
        }
    }
    true
}

// ================================================================
// Compressed QCOW2 output (Phase 5)
// ================================================================

/// Increment the refcount for a host cluster in the tracking
/// array. Silently caps at u16::MAX if it would overflow.
#[inline]
unsafe fn inc_refcount(refcount_array: *mut u16, host_cluster: u64, max_entries: usize) {
    let idx = host_cluster as usize;
    if idx < max_entries {
        let ptr = refcount_array.add(idx);
        let val = core::ptr::read(ptr);
        if val < u16::MAX {
            core::ptr::write(ptr, val + 1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn convert_to_qcow2_compressed(
    call_table: &CallTable,
    config: &ConvertConfig,
    chain_config: &ChainConfig,
    qcow2_states: &mut [Option<qcow2::Qcow2State>; MAX_CHAIN_DEVICES],
    input_device_count: usize,
    virtual_size: u64,
    sector_size: usize,
    skip_zeros: bool,
    bytes_read: &mut u64,
) -> u64 {
    let layout = match init_qcow2_output_layout(
        call_table,
        config,
        input_device_count,
        virtual_size,
        bytes_read,
    ) {
        Some(l) => l,
        None => return *bytes_read,
    };

    // CompressorOxide state follows L1 table (too large for
    // 64KB guest stack at ~200KB). Align to 8 bytes.
    let compressor_addr = (layout.l1_buf_end + 7) & !7;
    let compressor_size = qcow2::COMPRESSOR_STATE_SIZE;

    // Refcount tracking array follows compressor state
    let refcount_array_addr = (compressor_addr + compressor_size + 1) & !1;
    let refcount_array_bytes = SCRATCH_MEM_END - refcount_array_addr;
    let max_refcount_entries = refcount_array_bytes / 2;

    if refcount_array_addr >= SCRATCH_MEM_END || max_refcount_entries < 64 {
        (call_table.debug_print)(b"convert: no room for refcount array\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    let buf_data = BUF_DATA as *mut u8;
    let buf_l2 = BUF_L2_OUT as *mut u8;
    // Reuse BUF_COMPRESSED_IN for compressed output (it's free
    // after read_chain_virtual_cluster returns).
    let buf_compressed_out = BUF_COMPRESSED_IN as *mut u8;
    let compressor_mem = compressor_addr as *mut u8;
    let refcount_array = refcount_array_addr as *mut u16;

    // Zero refcount array
    core::ptr::write_bytes(refcount_array as *mut u8, 0, max_refcount_entries * 2);

    (call_table.verbose_print)(b"convert: starting compressed qcow2\n\0".as_ptr());

    // Byte-level write position. Cluster 0 is reserved for
    // the header (written last).
    let mut write_pos: u64 = layout.cluster_size;

    let mut clusters_done: u64 = 0;
    let mut last_percent: u32 = 0;

    // Process each L2 range
    for l1_idx in 0..layout.l1_size {
        core::ptr::write_bytes(buf_l2, 0, layout.cluster_size as usize);
        let mut l2_has_data = false;

        let first_vc = l1_idx as u64 * layout.entries_per_l2 as u64;
        let last_vc = core::cmp::min(
            first_vc + layout.entries_per_l2 as u64,
            layout.total_virtual_clusters,
        );

        for vc in first_vc..last_vc {
            let virtual_offset = vc * layout.cluster_size;
            let remaining = virtual_size - virtual_offset;
            let this_chunk = core::cmp::min(remaining, layout.cluster_size);

            // Reset bump allocator before ZSTD decompression
            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            // Read input data
            if !qcow2::read_chain_virtual_cluster(
                call_table,
                0,
                input_device_count,
                virtual_offset,
                buf_data,
                this_chunk,
                sector_size,
                chain_config,
                qcow2_states,
                BUF_COMPRESSED_IN as *mut u8,
                bytes_read,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"input\0".as_ptr(),
                    virtual_offset / sector_size as u64,
                    1,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Skip zero clusters
            if skip_zeros && is_all_zeros_ptr(buf_data, this_chunk as usize) {
                clusters_done += 1;
                let pct = (clusters_done * 100 / layout.total_virtual_clusters) as u32;
                if should_report_progress(
                    layout.progress_interval,
                    pct,
                    last_percent,
                    clusters_done,
                ) {
                    (call_table.send_progress)(
                        b"convert\0".as_ptr(),
                        clusters_done,
                        layout.total_virtual_clusters,
                        pct,
                    );
                    last_percent = pct;
                }
                continue;
            }

            // Zero-pad partial final cluster
            if this_chunk < layout.cluster_size {
                core::ptr::write_bytes(
                    buf_data.add(this_chunk as usize),
                    0,
                    (layout.cluster_size - this_chunk) as usize,
                );
            }

            // Reset bump allocator before each compression
            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            // Compress the cluster
            let compressed_len = qcow2::compress_cluster_zlib(
                compressor_mem,
                buf_data,
                layout.cluster_size as usize,
                buf_compressed_out,
                layout.cluster_size as usize,
            );

            let l2_entry_idx = (vc - first_vc) as usize;
            let l2_slice = core::slice::from_raw_parts_mut(buf_l2, layout.cluster_size as usize);

            if compressed_len > 0 {
                // Compression succeeded: write packed at
                // sector-aligned position.
                let padded = ((compressed_len as u64) + 511) & !511;

                // Zero tail of compressed buffer for clean
                // sector writes
                if compressed_len < padded as usize {
                    core::ptr::write_bytes(
                        buf_compressed_out.add(compressed_len),
                        0,
                        padded as usize - compressed_len,
                    );
                }

                if !write_bytes_to_output(
                    call_table,
                    buf_compressed_out,
                    write_pos,
                    padded,
                    layout.output_sector_size,
                    layout.output_capacity,
                ) {
                    (call_table.send_error)(
                        b"convert\0".as_ptr(),
                        b"output\0".as_ptr(),
                        write_pos / layout.output_sector_size as u64,
                        2,
                    );
                    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                    return *bytes_read;
                }

                // Compressed L2 entry
                let l2_entry = qcow2::encode_compressed_l2_entry(
                    write_pos,
                    compressed_len as u64,
                    layout.cluster_bits,
                );
                qcow2::write_be_u64(l2_slice, l2_entry_idx * 8, l2_entry);

                // Track refcounts for touched host clusters
                let first_host = write_pos / layout.cluster_size;
                let last_host = (write_pos + padded - 1) / layout.cluster_size;
                for h in first_host..=last_host {
                    inc_refcount(refcount_array, h, max_refcount_entries);
                }

                write_pos += padded;
            } else {
                // Compression didn't help: write uncompressed
                // at cluster-aligned offset.
                write_pos = (write_pos + layout.cluster_size - 1) & !(layout.cluster_size - 1);

                if !write_cluster_to_output(
                    call_table,
                    buf_data,
                    write_pos,
                    layout.cluster_size,
                    layout.output_sector_size,
                    layout.output_capacity,
                ) {
                    (call_table.send_error)(
                        b"convert\0".as_ptr(),
                        b"output\0".as_ptr(),
                        write_pos / layout.output_sector_size as u64,
                        2,
                    );
                    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                    return *bytes_read;
                }

                // Standard L2 entry with OFLAG_COPIED
                qcow2::write_be_u64(l2_slice, l2_entry_idx * 8, write_pos | (1u64 << 63));

                inc_refcount(
                    refcount_array,
                    write_pos / layout.cluster_size,
                    max_refcount_entries,
                );

                write_pos += layout.cluster_size;
            }

            l2_has_data = true;
            clusters_done += 1;
            let pct = (clusters_done * 100 / layout.total_virtual_clusters) as u32;
            if should_report_progress(layout.progress_interval, pct, last_percent, clusters_done) {
                (call_table.send_progress)(
                    b"convert\0".as_ptr(),
                    clusters_done,
                    layout.total_virtual_clusters,
                    pct,
                );
                last_percent = pct;
            }
        }

        // Flush L2 table if any data was written
        if l2_has_data {
            // Pad to cluster boundary
            write_pos = (write_pos + layout.cluster_size - 1) & !(layout.cluster_size - 1);

            if !write_cluster_to_output(
                call_table,
                buf_l2,
                write_pos,
                layout.cluster_size,
                layout.output_sector_size,
                layout.output_capacity,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    write_pos / layout.output_sector_size as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Refcount for L2 cluster
            inc_refcount(
                refcount_array,
                write_pos / layout.cluster_size,
                max_refcount_entries,
            );

            // Record L2 offset in L1 table (OFLAG_COPIED)
            let l1_slice = core::slice::from_raw_parts_mut(layout.l1_buf, layout.l1_write_bytes);
            qcow2::write_be_u64(l1_slice, l1_idx as usize * 8, write_pos | (1u64 << 63));

            write_pos += layout.cluster_size;
        }
    }

    // -- Write metadata at end --
    // write_pos should already be cluster-aligned here.
    if !write_qcow2_metadata(
        call_table,
        &layout,
        virtual_size,
        write_pos,
        Some((refcount_array, max_refcount_entries)),
        bytes_read,
    ) {
        return *bytes_read;
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, true);
    (call_table.verbose_print)(b"convert: done\n\0".as_ptr());
    *bytes_read
}

// ================================================================
// Utility
// ================================================================

/// Get the call table from the fixed address.
unsafe fn get_call_table() -> &'static CallTable {
    &*(CALL_TABLE_ADDR as *const CallTable)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        let call_table = get_call_table();
        if call_table.magic == CallTable::MAGIC {
            (call_table.send_error)(b"panic\0".as_ptr(), b"convert\0".as_ptr(), 0, 0xDEAD);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
