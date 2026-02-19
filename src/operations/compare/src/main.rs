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
    validate_call_table, verify_sector_sizes, CallTable, ChainConfig, CompareConfig, CompareResult,
    ImageFormat, CALL_TABLE_ADDR, CHAIN_CONFIG_ADDR, COMPRESSED_BUF_SIZE, MAX_CHAIN_DEVICES,
    MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE, SCRATCH_MEM_END,
};

// Scratch memory layout for compare operation.
// Fixed buffers:
//   BUF_COMPARE_1 (64KB): first image cluster data
//   BUF_COMPARE_2 (64KB): second image cluster data
//   BUF_COMPRESSED_IN (128KB): compressed data may straddle a sector boundary
const BUF_COMPARE_1: usize = SCRATCH_MEM_BASE;
const BUF_COMPARE_2: usize = BUF_COMPARE_1 + MAX_SECTOR_SIZE;
const BUF_COMPRESSED_IN: usize = BUF_COMPARE_2 + MAX_SECTOR_SIZE;

// Dynamic region: L1/L2 caches for QCOW2 devices (2 × MAX_SECTOR_SIZE per device)
const DYNAMIC_BUFS_START: usize = BUF_COMPRESSED_IN + COMPRESSED_BUF_SIZE;
const _: () = assert!(
    DYNAMIC_BUFS_START + MAX_CHAIN_DEVICES * 2 * MAX_SECTOR_SIZE <= SCRATCH_MEM_END,
    "Scratch memory too small for MAX_CHAIN_DEVICES L1/L2 caches"
);

/// Describes the format and key parameters for one image (top of its chain).
struct DeviceInfo {
    virtual_size: u64,
    cluster_size: u64,
}

/// Entry point called by core after devices are initialized.
///
/// Returns the number of bytes read during comparison.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    validate_call_table!(call_table, "compare");

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

    // Each chain must have at least one device (the top image itself)
    if image1_device_count < 1 || image2_device_count < 1 {
        (call_table.debug_print)(b"compare: each chain must have >= 1 device\n\0".as_ptr());
        let result = CompareResult::new();
        (call_table.send_compare_result)(&result);
        (call_table.send_complete)(b"compare\0".as_ptr(), 0, false);
        return 0;
    }

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

    // Cross-check: CompareConfig device counts must match ChainConfig
    if chain_config.device_count as usize != total_devices {
        (call_table.debug_print)(
            b"compare: chain_config.device_count != total_devices\n\0".as_ptr(),
        );
        let result = CompareResult::new();
        (call_table.send_compare_result)(&result);
        (call_table.send_complete)(b"compare\0".as_ptr(), 0, false);
        return 0;
    }

    // Verify all devices have consistent sector size
    let sector_size = match verify_sector_sizes(call_table, total_devices) {
        Some(ss) => ss,
        None => {
            (call_table.debug_print)(b"compare: sector size mismatch\n\0".as_ptr());
            let mut result = CompareResult::new();
            result.identical = 0;
            result.flags |= CompareResult::FLAG_SIZE_MISMATCH;
            (call_table.send_compare_result)(&result);
            (call_table.send_complete)(b"compare\0".as_ptr(), 0, false);
            return 0;
        }
    };

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
    let mut qcow2_states: [Option<qcow2::Qcow2State>; MAX_CHAIN_DEVICES] = Default::default();

    if !qcow2::init_chain_qcow2_states(
        call_table,
        chain_config,
        &mut qcow2_states,
        total_devices,
        sector_size,
        DYNAMIC_BUFS_START,
        &mut bytes_read,
    ) {
        (call_table.debug_print)(b"compare: failed to init qcow2 state\n\0".as_ptr());
        let result = CompareResult::new();
        (call_table.send_compare_result)(&result);
        (call_table.send_complete)(b"compare\0".as_ptr(), bytes_read, false);
        return bytes_read;
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
        if !qcow2::read_chain_virtual_cluster(
            call_table,
            0,
            image1_device_count,
            virtual_offset,
            buf1,
            this_chunk,
            sector_size,
            chain_config,
            &mut qcow2_states,
            BUF_COMPRESSED_IN as *mut u8,
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
        if !qcow2::read_chain_virtual_cluster(
            call_table,
            image2_start,
            image2_device_count,
            virtual_offset,
            buf2,
            this_chunk,
            sector_size,
            chain_config,
            &mut qcow2_states,
            BUF_COMPRESSED_IN as *mut u8,
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

                if !qcow2::read_chain_virtual_cluster(
                    call_table,
                    extra_chain_start,
                    extra_chain_len,
                    extra_offset,
                    buf1,
                    this_chunk,
                    sector_size,
                    chain_config,
                    &mut qcow2_states,
                    BUF_COMPRESSED_IN as *mut u8,
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
