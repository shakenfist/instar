//! Compare operation: sector-by-sector image data comparison.
//!
//! This operation reads two images (device 0 and device 1) and compares
//! them sector by sector, reporting whether they are logically identical.
//! If they differ, it reports the byte offset of the first mismatch.
//!
//! Phase 2a supports raw-vs-raw comparison only. Future phases will add
//! format-aware comparison (QCOW2 cluster reading, decompression, etc.).
//!
//! Results are sent via protobuf CompareResultMessage over the serial
//! command channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    CallTable, CompareConfig, CompareResult, CALL_TABLE_ADDR, MAX_SECTOR_SIZE,
    OPERATION_CONFIG_ADDR,
};

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
    // Strict mode is handled by the VMM; reserved for future guest-side use
    let _strict = if config.is_valid() {
        config.is_strict()
    } else {
        false
    };

    // Get device parameters for both images
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

    // Initialize result
    let mut result = CompareResult::new();

    // Check for size differences
    let sizes_differ = cap1 != cap2;

    if sizes_differ {
        result.flags |= CompareResult::FLAG_SIZE_MISMATCH;
    }

    // Compare sectors up to the minimum of the two capacities
    let min_sectors = if cap1 < cap2 { cap1 } else { cap2 };
    let compare_size = min_sectors.saturating_mul(sector_size as u64);

    // Allocate buffers for reading sectors from each device
    let mut buf1 = [0u8; MAX_SECTOR_SIZE];
    let mut buf2 = [0u8; MAX_SECTOR_SIZE];

    (call_table.verbose_print)(b"compare: comparing sectors\n\0".as_ptr());

    let mut mismatch_found = false;

    for sector in 0..min_sectors {
        // Read sector from device 0
        if !(call_table.read_input_sector)(0, sector, buf1.as_mut_ptr(), sector_size) {
            (call_table.send_error)(b"compare\0".as_ptr(), b"input0\0".as_ptr(), sector, 1);
            result.total_bytes_compared = bytes_read;
            (call_table.send_compare_result)(&result);
            (call_table.send_complete)(b"compare\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }
        bytes_read += sector_size as u64;

        // Read sector from device 1
        if !(call_table.read_input_sector)(1, sector, buf2.as_mut_ptr(), sector_size) {
            (call_table.send_error)(b"compare\0".as_ptr(), b"input1\0".as_ptr(), sector, 1);
            result.total_bytes_compared = bytes_read;
            (call_table.send_compare_result)(&result);
            (call_table.send_complete)(b"compare\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }
        bytes_read += sector_size as u64;

        // Compare the sector contents byte by byte to find exact offset
        let mut i = 0;
        while i < sector_size {
            if buf1[i] != buf2[i] {
                let mismatch_offset = sector * sector_size as u64 + i as u64;
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
    }

    if !mismatch_found {
        if sizes_differ {
            // Content within the common range matches, but sizes differ.
            // Check if the extra sectors in the larger image are all zeros.
            // qemu-img treats as identical when the extra data is zeros
            // (non-strict mode).
            let (extra_device, extra_start, extra_end) = if cap1 > cap2 {
                (0u32, min_sectors, cap1)
            } else {
                (1u32, min_sectors, cap2)
            };

            (call_table.verbose_print)(b"compare: checking extra sectors for zeros\n\0".as_ptr());

            let mut extra_nonzero = false;
            let mut extra_mismatch_byte: u64 = 0;
            let mut sector = extra_start;
            while sector < extra_end {
                if !(call_table.read_input_sector)(
                    extra_device,
                    sector,
                    buf1.as_mut_ptr(),
                    sector_size,
                ) {
                    // I/O error reading extra sectors: treat as mismatch
                    extra_nonzero = true;
                    extra_mismatch_byte = sector * sector_size as u64;
                    break;
                }
                bytes_read += sector_size as u64;

                let mut i = 0;
                while i < sector_size {
                    if buf1[i] != 0 {
                        extra_nonzero = true;
                        extra_mismatch_byte = sector * sector_size as u64 + i as u64;
                        break;
                    }
                    i += 1;
                }
                if extra_nonzero {
                    break;
                }
                sector += 1;
            }

            if extra_nonzero {
                // Extra data is non-zero: images differ
                result.identical = 0;
                result.first_mismatch_offset = extra_mismatch_byte;
            } else {
                // Extra data is all zeros: logically identical
                result.identical = 1;
            }
        } else {
            // Same size, all sectors match
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
