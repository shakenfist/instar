//! Copy operation: read from input device, write to output device.
//!
//! This operation reads sectors from the input virtio-block device
//! and writes them to the output device, translating sector sizes
//! as needed.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{CallTable, CopyConfig, CALL_TABLE_ADDR, MAX_SECTOR_SIZE};

/// Entry point called by core after devices are initialized.
///
/// Returns the number of bytes processed.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    // Verify call table is valid
    if call_table.magic != CallTable::MAGIC {
        (call_table.debug_print)(b"copy: bad magic\n\0".as_ptr());
        return 0;
    }
    if call_table.version != CallTable::VERSION {
        (call_table.debug_print)(b"copy: bad version\n\0".as_ptr());
        return 0;
    }

    (call_table.verbose_print)(b"copy: start\n\0".as_ptr());

    // Get operation config
    let config_result = (call_table.get_operation_config)();
    let config = &*(config_result.ptr as *const CopyConfig);

    // Validate config and extract parameters
    let (cfg_start, cfg_count, skip_zeros) = if config.is_valid() {
        (call_table.verbose_print)(b"copy: config ok\n\0".as_ptr());
        (
            config.start_sector,
            config.sector_count,
            config.should_skip_zeros(),
        )
    } else {
        (call_table.verbose_print)(b"copy: no config\n\0".as_ptr());
        (0, 0, false) // Default: copy all, no skip zeros
    };

    // Get device parameters (device 0 = primary input)
    let input_capacity = (call_table.get_input_capacity)(0);
    let output_capacity = (call_table.get_output_capacity)();
    let input_sector_size = (call_table.get_input_sector_size)(0);
    let output_sector_size = (call_table.get_output_sector_size)();
    let progress_interval = (call_table.get_progress_interval)();

    // Calculate sectors to copy based on config
    let start_sector = cfg_start;
    let end_sector = if cfg_count == 0 {
        input_capacity // Copy all remaining
    } else {
        let end = start_sector + cfg_count;
        if end > input_capacity {
            input_capacity
        } else {
            end
        }
    };
    let sectors_to_copy = end_sector.saturating_sub(start_sector);

    // Calculate total bytes to copy (limited by both devices and config)
    let input_bytes = sectors_to_copy * input_sector_size as u64;
    let output_bytes = output_capacity * output_sector_size as u64;
    let total_bytes = if input_bytes < output_bytes {
        input_bytes
    } else {
        output_bytes
    };

    // Total sectors for progress reporting (reserved for future use)
    let _total_sectors = if input_sector_size >= output_sector_size {
        sectors_to_copy
    } else {
        total_bytes / input_sector_size as u64
    };

    (call_table.verbose_print)(b"copy: copying\n\0".as_ptr());

    if skip_zeros {
        (call_table.verbose_print)(b"copy: skip zeros enabled\n\0".as_ptr());
    }

    // Buffer for sector data
    let mut buffer = [0u8; MAX_SECTOR_SIZE];

    // Track progress
    let mut bytes_copied: u64 = 0;
    let mut last_percent: u32 = 0;

    // Copy sectors using larger sector size for efficiency
    if input_sector_size >= output_sector_size {
        // Read large input sectors, write multiple output sectors
        let ratio = input_sector_size / output_sector_size;
        (call_table.verbose_print)(b"copy: input sectors >= output\n\0".as_ptr());

        for input_sector in start_sector..end_sector {
            // Read one input sector
            if !(call_table.read_input_sector)(
                0,
                input_sector,
                buffer.as_mut_ptr(),
                input_sector_size,
            ) {
                (call_table.send_error)(b"copy\0".as_ptr(), b"input\0".as_ptr(), input_sector, 1);
                return bytes_copied;
            }

            // Skip all-zero sectors if configured
            if skip_zeros && is_all_zeros(&buffer, input_sector_size) {
                bytes_copied += input_sector_size as u64;
                // Still report progress for skipped sectors
                let sectors_done = input_sector - start_sector + 1;
                let percent = (sectors_done * 100 / sectors_to_copy) as u32;
                if should_report_progress(progress_interval, percent, last_percent, sectors_done) {
                    (call_table.send_progress)(
                        b"copy\0".as_ptr(),
                        sectors_done,
                        sectors_to_copy,
                        percent,
                    );
                    last_percent = percent;
                }
                continue;
            }

            // Write multiple output sectors
            let base_output_sector = input_sector * ratio as u64;
            for i in 0..ratio {
                let output_sector = base_output_sector + i as u64;
                if output_sector >= output_capacity {
                    break;
                }

                let offset = i * output_sector_size;
                if !(call_table.write_output_sector)(
                    output_sector,
                    buffer.as_ptr().add(offset),
                    output_sector_size,
                ) {
                    (call_table.send_error)(
                        b"copy\0".as_ptr(),
                        b"output\0".as_ptr(),
                        output_sector,
                        2,
                    );
                    return bytes_copied;
                }
            }

            bytes_copied += input_sector_size as u64;

            // Progress reporting
            let sectors_done = input_sector - start_sector + 1;
            let percent = (sectors_done * 100 / sectors_to_copy) as u32;
            if should_report_progress(progress_interval, percent, last_percent, sectors_done) {
                (call_table.send_progress)(
                    b"copy\0".as_ptr(),
                    sectors_done,
                    sectors_to_copy,
                    percent,
                );
                last_percent = percent;
            }
        }
    } else {
        // Read multiple input sectors to fill one output sector
        let ratio = output_sector_size / input_sector_size;
        let output_sectors_to_copy = sectors_to_copy / ratio as u64;
        let start_output_sector = start_sector / ratio as u64;
        (call_table.verbose_print)(b"copy: input sectors < output\n\0".as_ptr());

        for i in 0..output_sectors_to_copy {
            let output_sector = start_output_sector + i;
            // Read multiple input sectors
            let base_input_sector = output_sector * ratio as u64;
            for j in 0..ratio {
                let input_sector = base_input_sector + j as u64;
                if input_sector >= end_sector {
                    // Zero-fill remainder
                    let offset = j * input_sector_size;
                    for k in offset..output_sector_size {
                        buffer[k] = 0;
                    }
                    break;
                }

                let offset = j * input_sector_size;
                if !(call_table.read_input_sector)(
                    0,
                    input_sector,
                    buffer.as_mut_ptr().add(offset),
                    input_sector_size,
                ) {
                    (call_table.send_error)(
                        b"copy\0".as_ptr(),
                        b"input\0".as_ptr(),
                        input_sector,
                        1,
                    );
                    return bytes_copied;
                }
            }

            // Skip all-zero sectors if configured
            if skip_zeros && is_all_zeros(&buffer, output_sector_size) {
                bytes_copied += output_sector_size as u64;
                // Still report progress for skipped sectors
                let percent = ((i + 1) * 100 / output_sectors_to_copy) as u32;
                if should_report_progress(progress_interval, percent, last_percent, i) {
                    (call_table.send_progress)(
                        b"copy\0".as_ptr(),
                        i + 1,
                        output_sectors_to_copy,
                        percent,
                    );
                    last_percent = percent;
                }
                continue;
            }

            // Write one output sector
            if !(call_table.write_output_sector)(output_sector, buffer.as_ptr(), output_sector_size)
            {
                (call_table.send_error)(b"copy\0".as_ptr(), b"output\0".as_ptr(), output_sector, 2);
                return bytes_copied;
            }

            bytes_copied += output_sector_size as u64;

            // Progress reporting
            let percent = ((i + 1) * 100 / output_sectors_to_copy) as u32;
            if should_report_progress(progress_interval, percent, last_percent, i) {
                (call_table.send_progress)(
                    b"copy\0".as_ptr(),
                    i + 1,
                    output_sectors_to_copy,
                    percent,
                );
                last_percent = percent;
            }
        }
    }

    (call_table.send_complete)(b"copy\0".as_ptr(), bytes_copied, true);
    (call_table.verbose_print)(b"copy: done\n\0".as_ptr());

    bytes_copied
}

/// Get the call table from the fixed address
unsafe fn get_call_table() -> &'static CallTable {
    &*(CALL_TABLE_ADDR as *const CallTable)
}

/// Determine if progress should be reported
fn should_report_progress(interval: u32, percent: u32, last_percent: u32, sector: u64) -> bool {
    match interval {
        0 => sector % 10 == 9, // Every 10 sectors
        100 => false,          // Never
        n => percent >= last_percent + n && percent > last_percent,
    }
}

/// Check if a buffer contains only zeros
fn is_all_zeros(buffer: &[u8], len: usize) -> bool {
    for i in 0..len {
        if buffer[i] != 0 {
            return false;
        }
    }
    true
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        let call_table = get_call_table();
        if call_table.magic == CallTable::MAGIC {
            (call_table.send_error)(b"panic\0".as_ptr(), b"copy\0".as_ptr(), 0, 0xDEAD);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
