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

use core::panic::PanicInfo;

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
//   BUF_COMPRESSED_IN (128KB): compressed input data
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

    // Dispatch based on target format
    let target = config.target_format();
    match target {
        ImageFormat::Qcow2 => convert_to_qcow2(
            call_table,
            config,
            chain_config,
            &mut qcow2_states,
            input_device_count,
            virtual_size,
            sector_size,
            skip_zeros,
            &mut bytes_read,
        ),
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
    let first_sector = byte_offset / output_sector_size as u64;
    let sectors = cluster_size / output_sector_size as u64;
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
/// All allocated clusters get refcount=1.
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
    let output_sector_size = (call_table.get_output_sector_size)();
    let output_capacity = (call_table.get_output_capacity)();
    let progress_interval = (call_table.get_progress_interval)();

    let cluster_bits = config.output_cluster_bits();
    let cluster_size = 1u64 << cluster_bits;
    let entries_per_l2 = (cluster_size / 8) as u32;
    let l2_coverage = cluster_size * entries_per_l2 as u64;
    let l1_size = ((virtual_size + l2_coverage - 1) / l2_coverage) as u32;

    // Output L1 table lives in scratch after input device caches
    let l1_buf_addr = DYNAMIC_BUFS_START + input_device_count * 2 * MAX_SECTOR_SIZE;
    let l1_size_bytes = l1_size as usize * 8;
    // Round up to whole clusters for writing
    let l1_clusters = ((l1_size_bytes as u64 + cluster_size - 1) / cluster_size).max(1);
    let l1_write_bytes = l1_clusters as usize * cluster_size as usize;

    if l1_buf_addr + l1_write_bytes > SCRATCH_MEM_END {
        (call_table.debug_print)(b"convert: L1 too large for scratch\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    let l1_buf = l1_buf_addr as *mut u8;
    let buf_data = BUF_DATA as *mut u8;
    let buf_l2 = BUF_L2_OUT as *mut u8;

    // Zero the L1 table
    core::ptr::write_bytes(l1_buf, 0, l1_write_bytes);

    (call_table.verbose_print)(b"convert: starting qcow2 conversion\n\0".as_ptr());

    // Linear cluster allocator. Cluster 0 is the header.
    let mut next_free: u64 = 1;

    let total_virtual_clusters = (virtual_size + cluster_size - 1) / cluster_size;
    let mut clusters_done: u64 = 0;
    let mut last_percent: u32 = 0;

    // Process each L2 range
    for l1_idx in 0..l1_size {
        // Zero the L2 buffer
        core::ptr::write_bytes(buf_l2, 0, cluster_size as usize);

        let mut l2_allocated = false;
        let mut l2_cluster: u64 = 0;

        let first_vc = l1_idx as u64 * entries_per_l2 as u64;
        let last_vc = core::cmp::min(first_vc + entries_per_l2 as u64, total_virtual_clusters);

        for vc in first_vc..last_vc {
            let virtual_offset = vc * cluster_size;
            let remaining = virtual_size - virtual_offset;
            let this_chunk = core::cmp::min(remaining, cluster_size);

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
                let pct = (clusters_done * 100 / total_virtual_clusters) as u32;
                if should_report_progress(progress_interval, pct, last_percent, clusters_done) {
                    (call_table.send_progress)(
                        b"convert\0".as_ptr(),
                        clusters_done,
                        total_virtual_clusters,
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
            let data_offset = data_cluster * cluster_size;

            // Zero-pad if this is a partial final cluster
            if this_chunk < cluster_size {
                core::ptr::write_bytes(
                    buf_data.add(this_chunk as usize),
                    0,
                    (cluster_size - this_chunk) as usize,
                );
            }

            // Write data cluster to output
            if !write_cluster_to_output(
                call_table,
                buf_data,
                data_offset,
                cluster_size,
                output_sector_size,
                output_capacity,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    data_offset / output_sector_size as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Set L2 entry: standard cluster at data_offset
            // OFLAG_COPIED (bit 63) must be set when refcount=1
            let l2_entry_idx = (vc - first_vc) as usize;
            let l2_slice = core::slice::from_raw_parts_mut(buf_l2, cluster_size as usize);
            qcow2::write_be_u64(l2_slice, l2_entry_idx * 8, data_offset | (1u64 << 63));

            clusters_done += 1;
            let pct = (clusters_done * 100 / total_virtual_clusters) as u32;
            if should_report_progress(progress_interval, pct, last_percent, clusters_done) {
                (call_table.send_progress)(
                    b"convert\0".as_ptr(),
                    clusters_done,
                    total_virtual_clusters,
                    pct,
                );
                last_percent = pct;
            }
        }

        // Flush L2 table if any data was written
        if l2_allocated {
            let l2_offset = l2_cluster * cluster_size;
            if !write_cluster_to_output(
                call_table,
                buf_l2,
                l2_offset,
                cluster_size,
                output_sector_size,
                output_capacity,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    l2_offset / output_sector_size as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Record L2 offset in L1 table
            // OFLAG_COPIED (bit 63) must be set when refcount=1
            let l1_slice = core::slice::from_raw_parts_mut(l1_buf, l1_write_bytes);
            qcow2::write_be_u64(l1_slice, l1_idx as usize * 8, l2_offset | (1u64 << 63));
        }
    }

    // -- Write metadata at end --

    // L1 table
    let l1_offset = next_free * cluster_size;
    let clusters_before_refcount = next_free + l1_clusters;

    for c in 0..l1_clusters {
        let off = l1_offset + c * cluster_size;
        let ptr = l1_buf.add(c as usize * cluster_size as usize);
        if !write_cluster_to_output(
            call_table,
            ptr,
            off,
            cluster_size,
            output_sector_size,
            output_capacity,
        ) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }
    }

    // Refcount structures
    let (reftable_clusters, refblock_count, total_clusters) =
        calculate_refcount_layout(clusters_before_refcount, cluster_size);

    let reftable_offset = clusters_before_refcount * cluster_size;
    let refblock_base_offset = reftable_offset + reftable_clusters * cluster_size;
    let entries_per_refblock = cluster_size / 2;

    // Write refcount blocks: every cluster 0..total_clusters
    // has refcount=1 (all allocated contiguously).
    let buf_rc = BUF_REFCOUNT as *mut u8;
    for rb in 0..refblock_count {
        core::ptr::write_bytes(buf_rc, 0, cluster_size as usize);
        let rc_slice = core::slice::from_raw_parts_mut(buf_rc, cluster_size as usize);

        let first_cluster_in_block = rb * entries_per_refblock;
        let entries = core::cmp::min(
            entries_per_refblock,
            total_clusters.saturating_sub(first_cluster_in_block),
        );
        for e in 0..entries {
            qcow2::write_be_u16(rc_slice, e as usize * 2, 1);
        }

        let rb_offset = refblock_base_offset + rb * cluster_size;
        if !write_cluster_to_output(
            call_table,
            buf_rc,
            rb_offset,
            cluster_size,
            output_sector_size,
            output_capacity,
        ) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }
    }

    // Write refcount table: array of u64 offsets to refcount
    // blocks. Reuse BUF_REFCOUNT buffer (one cluster at a time).
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
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }
    }

    // Write QCOW2 v3 header at cluster 0
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
    qcow2::write_be_u32(hdr, 96, qcow2::QCOW2_DEFAULT_REFCOUNT_ORDER);
    qcow2::write_be_u32(hdr, 100, qcow2::QCOW2_HEADER_LENGTH_V3);

    if !write_cluster_to_output(
        call_table,
        buf_hdr,
        0,
        cluster_size,
        output_sector_size,
        output_capacity,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
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
