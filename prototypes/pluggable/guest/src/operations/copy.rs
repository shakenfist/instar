//! Copy operation: transfers data from input to output device.
//!
//! This operation reads all sectors from the input device and writes them
//! to the output device, handling sector size translation when the devices
//! have different sector sizes.

use crate::infra::mem::MAX_SECTOR_SIZE;
use crate::infra::{debug_print, send_error, send_progress, DeviceConfig, VirtioBlock};
use crate::operations::{GuestOperation, OperationResult};

/// Copy operation implementation
pub struct CopyOperation;

impl GuestOperation for CopyOperation {
    fn name(&self) -> &'static str {
        "copy"
    }

    fn execute(
        &self,
        input: &mut VirtioBlock,
        output: &mut VirtioBlock,
        config: &DeviceConfig,
    ) -> OperationResult {
        let input_sector_size = config.input_sector_size;
        let output_sector_size = config.output_sector_size;

        // Use input capacity as the source of truth for total bytes
        let total_input_sectors = input.capacity();

        // Allocate buffers
        let mut input_buffer = [0u8; MAX_SECTOR_SIZE];
        let mut output_buffer = [0u8; MAX_SECTOR_SIZE];

        let mut bytes_copied = 0u64;
        let mut errors = 0u64;
        let mut input_sector = 0u64;
        let mut output_sector = 0u64;
        let mut output_buffer_pos = 0usize;

        // Progress tracking
        let progress_percent = config.progress_percent;
        let mut last_reported_percent: u32 = 0;

        debug_print("guest: copy\n");

        // Simple copy loop that handles sector size translation
        while input_sector < total_input_sectors {
            // Read from input
            if !input.read_sector(input_sector, &mut input_buffer) {
                send_error("read", "input", input_sector, 1);
                errors += 1;
                input_sector += 1;
                continue;
            }

            // Copy data to output buffer
            let bytes_read = input_sector_size;
            let mut src_pos = 0usize;

            while src_pos < bytes_read {
                let space_in_output = output_sector_size - output_buffer_pos;
                let bytes_to_copy = core::cmp::min(bytes_read - src_pos, space_in_output);

                // Copy bytes
                for i in 0..bytes_to_copy {
                    output_buffer[output_buffer_pos + i] = input_buffer[src_pos + i];
                }

                output_buffer_pos += bytes_to_copy;
                src_pos += bytes_to_copy;

                // If output buffer is full, write it
                if output_buffer_pos >= output_sector_size {
                    if !output.write_sector(output_sector, &output_buffer) {
                        send_error("write", "output", output_sector, 1);
                        errors += 1;
                    } else {
                        bytes_copied += output_sector_size as u64;
                    }
                    output_sector += 1;
                    output_buffer_pos = 0;
                }
            }

            input_sector += 1;

            // Progress reporting based on configuration
            // progress_percent: 0=every 10 sectors, 1-99=every N%, 100=none
            let current_percent = if total_input_sectors > 0 {
                (input_sector * 100 / total_input_sectors) as u32
            } else {
                100
            };

            let should_report = match progress_percent {
                0 => {
                    // Legacy: every 10 sectors or last sector
                    input_sector % 10 == 0 || input_sector == total_input_sectors
                }
                100 => {
                    // No progress updates
                    false
                }
                interval => {
                    // Report when crossing a percentage threshold
                    let threshold = (current_percent / interval) * interval;
                    if threshold > last_reported_percent || input_sector == total_input_sectors {
                        last_reported_percent = threshold;
                        true
                    } else {
                        false
                    }
                }
            };

            if should_report {
                send_progress("copy", input_sector, total_input_sectors, current_percent);
            }
        }

        // Flush any remaining data in output buffer (partial sector)
        if output_buffer_pos > 0 {
            // Pad with zeros
            for i in output_buffer_pos..output_sector_size {
                output_buffer[i] = 0;
            }
            if !output.write_sector(output_sector, &output_buffer) {
                send_error("write", "output", output_sector, 1);
                errors += 1;
            } else {
                bytes_copied += output_buffer_pos as u64;
            }
        }

        OperationResult {
            bytes_processed: bytes_copied,
            success: errors == 0,
        }
    }
}
