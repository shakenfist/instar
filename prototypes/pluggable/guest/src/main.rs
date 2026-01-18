//! Bare-metal guest with pluggable operations.
//!
//! This guest provides a framework for running different operations inside
//! a minimal KVM virtual machine. The core handles device initialization
//! and communication, while operations implement specific functionality.
//!
//! # Architecture
//!
//! ```text
//! +------------------+
//! |     main.rs      |  Entry point, device setup, operation dispatch
//! +------------------+
//!          |
//!          v
//! +------------------+
//! |      infra/      |  Infrastructure: virtio, serial, memory layout
//! +------------------+
//!          |
//!          v
//! +------------------+
//! |   operations/    |  Pluggable operations: copy, info, transcode...
//! +------------------+
//! ```
//!
//! # Adding a new operation
//!
//! 1. Add a variant to `Operation` enum in `infra/serial.rs`
//! 2. Create the operation module in `operations/`
//! 3. Implement `GuestOperation` trait
//! 4. Register in `operations/mod.rs` dispatcher

#![no_std]
#![no_main]

mod infra;
mod operations;

use ::core::arch::asm;
use ::core::panic::PanicInfo;

use crate::infra::{
    debug_print, read_config, send_complete, send_error, send_init, DeviceConfig, VirtioBlock,
    INPUT_MMIO_BASE, INPUT_VQ_BASE, OUTPUT_MMIO_BASE, OUTPUT_VQ_BASE,
};
use crate::operations::run_operation;

/// Entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    debug_print("guest: start\n");

    // Read configuration from VMM over serial
    let config: DeviceConfig = read_config();
    debug_print("guest: config\n");

    // Report configuration
    send_init("config", "input", config.input_sector_size as u64);
    send_init("config", "output", config.output_sector_size as u64);
    send_init("config", "progress", config.progress_percent as u64);

    // Initialize input device with configured sector size
    let mut input = match VirtioBlock::init(
        INPUT_MMIO_BASE,
        INPUT_VQ_BASE,
        config.input_sector_size,
        "input",
    ) {
        Some(dev) => dev,
        None => {
            send_complete("init", 0, false);
            halt();
        }
    };

    // Initialize output device with configured sector size
    let mut output = match VirtioBlock::init(
        OUTPUT_MMIO_BASE,
        OUTPUT_VQ_BASE,
        config.output_sector_size,
        "output",
    ) {
        Some(dev) => dev,
        None => {
            send_complete("init", 0, false);
            halt();
        }
    };

    // Run the configured operation
    let result = run_operation(&mut input, &mut output, &config);

    // Report completion
    let op_name = match config.operation {
        crate::infra::Operation::Copy => "copy",
        crate::infra::Operation::Info => "info",
    };
    send_complete(op_name, result.bytes_processed, result.success);

    debug_print("guest: done\n");
    halt();
}

/// Halt the CPU
fn halt() -> ! {
    unsafe {
        asm!("hlt", options(nomem, nostack));
    }
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    send_error("panic", "guest", 0, 0xDEAD);
    halt();
}
