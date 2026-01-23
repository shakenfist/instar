//! Core guest binary for pluggable2 prototype.
//!
//! This binary handles:
//! - Device initialization (virtio-block input/output)
//! - Call table setup for operations
//! - Jumping to the operation binary
//!
//! The operation binary is loaded by the VMM at OPERATION_LOAD_ADDR and
//! called after devices are initialized.

#![no_std]
#![no_main]

mod serial;
mod virtio;

use core::arch::asm;
use core::panic::PanicInfo;
use core::ptr::write_volatile;

use shared::{
    CallTable, CALL_TABLE_ADDR, OPERATION_CONFIG_ADDR, OPERATION_CONFIG_MAX_SIZE,
    OPERATION_LOAD_ADDR,
};

use crate::serial::{
    debug_print, read_config, send_complete, send_error, send_init, send_progress, DeviceConfig,
};
use crate::virtio::VirtioBlock;

// Memory layout constants
const INPUT_MMIO_BASE: usize = 0x10000000;
const OUTPUT_MMIO_BASE: usize = 0x10001000;
const INPUT_VQ_BASE: usize = 0x100000;
const OUTPUT_VQ_BASE: usize = 0x110000;

// Global device state (accessed by call table functions)
// Using static mut because we need mutable access from extern "C" functions
static mut INPUT_DEVICE: Option<VirtioBlock> = None;
static mut OUTPUT_DEVICE: Option<VirtioBlock> = None;
static mut CONFIG: Option<DeviceConfig> = None;

/// Entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    debug_print("core: start\n");

    // Read configuration from VMM over serial
    let config = read_config();
    debug_print("core: config\n");

    // Report configuration
    send_init("config", "input", config.input_sector_size as u64);
    send_init("config", "output", config.output_sector_size as u64);
    send_init("config", "progress", config.progress_percent as u64);

    // Initialize input device
    let input = match VirtioBlock::init(
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

    // Initialize output device
    let output = match VirtioBlock::init(
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

    // Store devices and config in globals for call table access
    unsafe {
        INPUT_DEVICE = Some(input);
        OUTPUT_DEVICE = Some(output);
        CONFIG = Some(config);
    }

    // Set up call table
    debug_print("core: call_table\n");
    setup_call_table();

    // Jump to operation
    debug_print("core: jump\n");
    let bytes_processed = unsafe { call_operation() };

    // Report completion
    send_complete("operation", bytes_processed, bytes_processed > 0);

    debug_print("core: done\n");
    halt();
}

/// Set up the call table at the fixed address
fn setup_call_table() {
    let call_table = CallTable {
        magic: CallTable::MAGIC,
        version: CallTable::VERSION,
        read_input_sector: ct_read_input_sector,
        write_output_sector: ct_write_output_sector,
        get_input_capacity: ct_get_input_capacity,
        get_output_capacity: ct_get_output_capacity,
        get_input_sector_size: ct_get_input_sector_size,
        get_output_sector_size: ct_get_output_sector_size,
        get_progress_interval: ct_get_progress_interval,
        send_progress: ct_send_progress,
        send_error: ct_send_error,
        send_complete: ct_send_complete,
        debug_print: ct_debug_print,
        get_operation_config: ct_get_operation_config,
    };

    unsafe {
        let ptr = CALL_TABLE_ADDR as *mut CallTable;
        write_volatile(ptr, call_table);
    }
}

/// Call the operation at OPERATION_LOAD_ADDR
unsafe fn call_operation() -> u64 {
    let entry: shared::OperationEntry = core::mem::transmute(OPERATION_LOAD_ADDR as *const ());
    entry()
}

// ============================================================================
// Call table function implementations
// These are extern "C" functions that the operation binary calls
// ============================================================================

unsafe extern "C" fn ct_read_input_sector(sector: u64, buffer: *mut u8, len: usize) -> bool {
    if let Some(ref mut dev) = INPUT_DEVICE {
        let slice = core::slice::from_raw_parts_mut(buffer, len);
        dev.read_sector(sector, slice)
    } else {
        false
    }
}

unsafe extern "C" fn ct_write_output_sector(sector: u64, buffer: *const u8, len: usize) -> bool {
    if let Some(ref mut dev) = OUTPUT_DEVICE {
        let slice = core::slice::from_raw_parts(buffer, len);
        dev.write_sector(sector, slice)
    } else {
        false
    }
}

unsafe extern "C" fn ct_get_input_capacity() -> u64 {
    INPUT_DEVICE.as_ref().map(|d| d.capacity()).unwrap_or(0)
}

unsafe extern "C" fn ct_get_output_capacity() -> u64 {
    OUTPUT_DEVICE.as_ref().map(|d| d.capacity()).unwrap_or(0)
}

unsafe extern "C" fn ct_get_input_sector_size() -> usize {
    INPUT_DEVICE
        .as_ref()
        .map(|d| d.sector_size())
        .unwrap_or(512)
}

unsafe extern "C" fn ct_get_output_sector_size() -> usize {
    OUTPUT_DEVICE
        .as_ref()
        .map(|d| d.sector_size())
        .unwrap_or(512)
}

unsafe extern "C" fn ct_get_progress_interval() -> u32 {
    CONFIG.as_ref().map(|c| c.progress_percent).unwrap_or(10)
}

unsafe extern "C" fn ct_send_progress(op: *const u8, current: u64, total: u64, percent: u32) {
    let op_str = cstr_to_str(op);
    send_progress(op_str, current, total, percent);
}

unsafe extern "C" fn ct_send_error(op: *const u8, dev: *const u8, sector: u64, status: u32) {
    let op_str = cstr_to_str(op);
    let dev_str = cstr_to_str(dev);
    send_error(op_str, dev_str, sector, status);
}

unsafe extern "C" fn ct_send_complete(op: *const u8, bytes: u64, success: bool) {
    let op_str = cstr_to_str(op);
    send_complete(op_str, bytes, success);
}

unsafe extern "C" fn ct_debug_print(s: *const u8) {
    let str = cstr_to_str(s);
    debug_print(str);
}

/// Get operation-specific configuration.
/// The VMM writes the config to OPERATION_CONFIG_ADDR before starting the guest.
/// Returns ConfigResult - operations interpret the bytes according to their format.
unsafe extern "C" fn ct_get_operation_config() -> shared::ConfigResult {
    // The config is at a fixed address, written by the VMM
    // We return the address and max size - the operation validates the magic
    shared::ConfigResult {
        ptr: OPERATION_CONFIG_ADDR as *const u8,
        len: OPERATION_CONFIG_MAX_SIZE,
    }
}

/// Convert null-terminated C string to &str
unsafe fn cstr_to_str(ptr: *const u8) -> &'static str {
    if ptr.is_null() {
        return "";
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(ptr, len);
    core::str::from_utf8_unchecked(slice)
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
    send_error("panic", "core", 0, 0xDEAD);
    halt();
}
