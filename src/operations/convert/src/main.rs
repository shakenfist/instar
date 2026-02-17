//! Convert operation: flatten a QCOW2 image (with backing chain) to raw.
//!
//! Reads virtual content from an input image that may have a QCOW2
//! backing chain, and writes it sequentially to a raw output device.
//! Compressed and standard clusters are handled transparently via the
//! shared qcow2 crate's chain-walking reader.
//!
//! Progress is reported via send_progress() and completion via
//! send_complete(). No special result message is needed (matching
//! qemu-img convert which produces no stdout on success).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    is_all_zeros_ptr, l1_cache_addr, l2_cache_addr, should_report_progress, CallTable, ChainConfig,
    ConvertConfig, ImageFormat, CALL_TABLE_ADDR, CHAIN_CONFIG_ADDR, COMPRESSED_BUF_SIZE,
    MAX_CHAIN_DEVICES, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE, SCRATCH_MEM_END,
};

// Scratch memory layout for convert operation.
// Fixed buffers:
//   BUF_OUTPUT (MAX_SECTOR_SIZE = 64KB): cluster data read from input
//   BUF_COMPRESSED_IN (COMPRESSED_BUF_SIZE = 128KB): compressed data
//     may straddle a sector boundary, so needs room for 2 sectors
const BUF_OUTPUT: usize = SCRATCH_MEM_BASE;
const BUF_COMPRESSED_IN: usize = BUF_OUTPUT + MAX_SECTOR_SIZE;

// Dynamic region: L1/L2 caches for QCOW2 devices (2 × MAX_SECTOR_SIZE per device)
const DYNAMIC_BUFS_START: usize = BUF_COMPRESSED_IN + COMPRESSED_BUF_SIZE;
const _: () = assert!(
    DYNAMIC_BUFS_START + MAX_CHAIN_DEVICES * 2 * MAX_SECTOR_SIZE <= SCRATCH_MEM_END,
    "Scratch memory too small for MAX_CHAIN_DEVICES L1/L2 caches"
);

/// Entry point called by core after devices are initialized.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    // Verify call table is valid
    if call_table.magic != CallTable::MAGIC {
        (call_table.debug_print)(b"convert: bad magic\n\0".as_ptr());
        return 0;
    }
    if call_table.version != CallTable::VERSION {
        (call_table.debug_print)(b"convert: bad version\n\0".as_ptr());
        return 0;
    }

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
    let sector_size = (call_table.get_input_sector_size)(0);
    for dev_idx in 1..input_device_count {
        let dev_sector_size = (call_table.get_input_sector_size)(dev_idx as u32);
        if dev_sector_size != sector_size {
            (call_table.debug_print)(b"convert: sector size mismatch\n\0".as_ptr());
            (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
            return 0;
        }
    }

    let output_sector_size = (call_table.get_output_sector_size)();
    let output_capacity = (call_table.get_output_capacity)();
    let progress_interval = (call_table.get_progress_interval)();

    let mut bytes_read: u64 = 0;

    // Get virtual size from top-of-chain device
    let top_dev = &chain_config.devices[0];
    let virtual_size = top_dev.virtual_size;
    let cluster_size = if top_dev.cluster_size > 0 {
        top_dev.cluster_size as u64
    } else {
        sector_size as u64
    };

    // Clamp chunk size to buffer size
    let chunk_size = if cluster_size > MAX_SECTOR_SIZE as u64 {
        MAX_SECTOR_SIZE as u64
    } else {
        cluster_size
    };

    (call_table.verbose_print)(b"convert: initializing qcow2 states\n\0".as_ptr());

    // Initialize QCOW2 state for each QCOW2 device in the chain
    let mut qcow2_states: [Option<qcow2::Qcow2State>; MAX_CHAIN_DEVICES] = Default::default();

    for dev_idx in 0..input_device_count {
        let dev_info = &chain_config.devices[dev_idx];
        if matches!(dev_info.detected_format(), ImageFormat::Qcow2) {
            let cap = (call_table.get_input_capacity)(dev_idx as u32);
            qcow2_states[dev_idx] = qcow2::Qcow2State::init(
                call_table,
                dev_idx as u32,
                sector_size,
                cap,
                l1_cache_addr(DYNAMIC_BUFS_START, dev_idx),
                l2_cache_addr(DYNAMIC_BUFS_START, dev_idx),
                &mut bytes_read,
            );
            if qcow2_states[dev_idx].is_none() {
                (call_table.debug_print)(b"convert: failed to init qcow2\n\0".as_ptr());
                (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                return bytes_read;
            }
        }
    }

    (call_table.verbose_print)(b"convert: starting conversion\n\0".as_ptr());

    let buf = BUF_OUTPUT as *mut u8;
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

        // Read virtual data from input chain
        if !qcow2::read_chain_virtual_cluster(
            call_table,
            0,
            input_device_count,
            virtual_offset,
            buf,
            this_chunk,
            sector_size,
            chain_config,
            &mut qcow2_states,
            BUF_COMPRESSED_IN as *mut u8,
            &mut bytes_read,
        ) {
            (call_table.send_error)(
                b"convert\0".as_ptr(),
                b"input\0".as_ptr(),
                virtual_offset / sector_size as u64,
                1,
            );
            (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }

        // Skip zero-filled chunks if configured
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

        // Write to output device sector by sector
        let output_first_sector = virtual_offset / output_sector_size as u64;
        let sectors_per_chunk = this_chunk / output_sector_size as u64;

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
                (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                return bytes_read;
            }
        }

        virtual_offset += this_chunk;
        chunks_done += 1;

        // Progress reporting
        let percent = (chunks_done * 100 / total_chunks) as u32;
        if should_report_progress(progress_interval, percent, last_percent, chunks_done) {
            (call_table.send_progress)(b"convert\0".as_ptr(), chunks_done, total_chunks, percent);
            last_percent = percent;
        }
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, true);
    (call_table.verbose_print)(b"convert: done\n\0".as_ptr());

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
            (call_table.send_error)(b"panic\0".as_ptr(), b"convert\0".as_ptr(), 0, 0xDEAD);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
