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
use core::cell::UnsafeCell;
use core::panic::PanicInfo;
use core::ptr::write_volatile;

use shared::{
    CallTable, ChainConfig, CheckResult, CompareResult, Qcow2Info, VdiInfo, VmdkInfo,
    CALL_TABLE_ADDR, CHAIN_CONFIG_ADDR, CHAIN_CONFIG_MAX_SIZE, OPERATION_CONFIG_ADDR,
    OPERATION_CONFIG_MAX_SIZE, OPERATION_LOAD_ADDR,
};

use crate::serial::{
    debug_print, read_config, send_check_result, send_compare_result, send_complete, send_error,
    send_info_result, send_info_result_qcow2, send_info_result_vdi, send_info_result_vmdk,
    send_init, send_progress, DeviceConfig,
};
use crate::virtio::VirtioBlock;

// Memory layout constants
// Base addresses for device MMIO and virtqueues (must match VMM)
const MMIO_BASE_START: usize = 0x10000000;
const MMIO_SIZE: usize = 0x1000; // 4KB per device
const VQ_BASE_START: usize = 0x100000; // 1MB
const VQ_SIZE_PER_DEVICE: usize = 0x10000; // 64KB per device

// Maximum number of input devices (backing chain depth)
const MAX_INPUT_DEVICES: usize = 16;

/// Calculate MMIO base address for device at given index.
#[inline]
const fn device_mmio_base(device_index: usize) -> usize {
    MMIO_BASE_START + (device_index * MMIO_SIZE)
}

/// Calculate virtqueue base address for device at given index.
#[inline]
const fn device_vq_base(device_index: usize) -> usize {
    VQ_BASE_START + (device_index * VQ_SIZE_PER_DEVICE)
}

// Legacy constants for backward compatibility
const INPUT_MMIO_BASE: usize = MMIO_BASE_START; // device 0
const OUTPUT_MMIO_BASE: usize = MMIO_BASE_START + MMIO_SIZE; // device 1
const INPUT_VQ_BASE: usize = VQ_BASE_START; // device 0
const OUTPUT_VQ_BASE: usize = VQ_BASE_START + VQ_SIZE_PER_DEVICE; // device 1

/// A cell for single-threaded static mutable state.
///
/// This is a wrapper around `UnsafeCell` that implements `Sync`, making it
/// usable in static variables. This is safe because:
///
/// 1. The guest runs on a single vCPU (no concurrent access possible)
/// 2. All access is through the call table functions (no re-entrancy)
/// 3. Initialization happens once in `_start()` before any other access
///
/// # Safety
///
/// This type must only be used in single-threaded contexts. Using it in
/// multi-threaded code will cause data races (undefined behavior).
struct SingleThreadCell<T>(UnsafeCell<T>);

impl<T> SingleThreadCell<T> {
    const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// Get a mutable reference to the inner value.
    ///
    /// # Safety
    ///
    /// Caller must ensure no other references to the value exist.
    /// This is guaranteed in single-threaded code.
    #[allow(clippy::mut_from_ref)]
    unsafe fn get_mut(&self) -> &mut T {
        &mut *self.0.get()
    }

    /// Get a shared reference to the inner value.
    ///
    /// # Safety
    ///
    /// Caller must ensure no mutable references to the value exist.
    unsafe fn get(&self) -> &T {
        &*self.0.get()
    }
}

// SAFETY: This is only safe because the guest is single-threaded.
// The guest runs on exactly one vCPU with no possibility of concurrent access.
unsafe impl<T> Sync for SingleThreadCell<T> {}

// Global device state (accessed by call table functions).
// Using SingleThreadCell because we need interior mutability from extern "C" functions.
// SAFETY: Guest runs on a single vCPU - no concurrent access is possible.

/// Array of input devices (for backing chain support).
/// Device 0 = primary/top image, devices 1..N = backing files.
/// Legacy single-device functions (ct_read_input_sector, etc.) use index 0.
static INPUT_DEVICES: SingleThreadCell<[Option<VirtioBlock>; MAX_INPUT_DEVICES]> =
    SingleThreadCell::new([const { None }; MAX_INPUT_DEVICES]);

/// Number of active input devices.
static INPUT_DEVICE_COUNT: SingleThreadCell<usize> = SingleThreadCell::new(0);

static OUTPUT_DEVICE: SingleThreadCell<Option<VirtioBlock>> = SingleThreadCell::new(None);
static CONFIG: SingleThreadCell<Option<DeviceConfig>> = SingleThreadCell::new(None);

/// Entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    debug_print("core: start\n");

    // Read configuration from VMM over serial
    let config = read_config();
    debug_print("core: config\n");

    // Report configuration
    send_init("config", "input", config.input_sector_size as u64);
    if config.has_output_device {
        send_init("config", "output", config.output_sector_size as u64);
    }
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

    // Initialize output device (only if configured)
    let output = if config.has_output_device {
        match VirtioBlock::init(
            OUTPUT_MMIO_BASE,
            OUTPUT_VQ_BASE,
            config.output_sector_size,
            "output",
        ) {
            Some(dev) => Some(dev),
            None => {
                send_complete("init", 0, false);
                halt();
            }
        }
    } else {
        None
    };

    // Store devices and config in globals for call table access.
    // SAFETY: Single-threaded guest, no concurrent access possible.
    unsafe {
        // Store input device in the device array at index 0
        let devices = INPUT_DEVICES.get_mut();
        devices[0] = Some(input);
        let mut active_count: usize = 1;

        // Initialize additional input devices for backing chain
        for i in 1..config.input_device_count {
            let sector_size = config.extra_input_sector_sizes[i - 1];
            if sector_size == 0 {
                break;
            }
            let mmio = device_mmio_base(i);
            let vq = device_vq_base(i);
            match VirtioBlock::init(mmio, vq, sector_size, "chain") {
                Some(dev) => {
                    devices[i] = Some(dev);
                    active_count += 1;
                }
                None => {
                    debug_print("core: chain device init failed\n");
                    break;
                }
            }
        }
        *INPUT_DEVICE_COUNT.get_mut() = active_count;

        *OUTPUT_DEVICE.get_mut() = output;
        *CONFIG.get_mut() = Some(config.clone());
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

// Verbose flag bit position in operation config flags (bit 31, consistent across all configs)
const CONFIG_FLAG_VERBOSE_BIT: u32 = 1 << 31;

/// Set up the call table at the fixed address
fn setup_call_table() {
    // Read the operation config flags to determine if verbose mode is enabled.
    // The config layout is: magic (u32), flags (u32), ...
    // The verbose flag bit position is consistent across all operation configs.
    let verbose = unsafe {
        let flags_ptr = (OPERATION_CONFIG_ADDR + 4) as *const u32;
        let flags = core::ptr::read_volatile(flags_ptr);
        (flags & CONFIG_FLAG_VERBOSE_BIT) != 0
    };

    // Use actual debug_print for verbose_print when verbose is enabled,
    // otherwise use a no-op to avoid serial I/O overhead.
    let verbose_print_fn = if verbose {
        ct_debug_print
    } else {
        ct_silent_print
    };

    let call_table = CallTable {
        magic: CallTable::MAGIC,
        version: CallTable::VERSION,
        get_input_device_count: ct_get_input_device_count,
        read_input_sector: ct_read_input_sector,
        get_input_capacity: ct_get_input_capacity,
        get_input_sector_size: ct_get_input_sector_size,
        write_output_sector: ct_write_output_sector,
        get_output_capacity: ct_get_output_capacity,
        get_output_sector_size: ct_get_output_sector_size,
        get_progress_interval: ct_get_progress_interval,
        send_progress: ct_send_progress,
        send_error: ct_send_error,
        send_complete: ct_send_complete,
        debug_print: ct_debug_print,
        verbose_print: verbose_print_fn,
        get_operation_config: ct_get_operation_config,
        get_chain_config: ct_get_chain_config,
        send_info_result: ct_send_info_result,
        send_info_result_qcow2: ct_send_info_result_qcow2,
        send_info_result_vmdk: ct_send_info_result_vmdk,
        send_info_result_vdi: ct_send_info_result_vdi,
        send_check_result: ct_send_check_result,
        send_compare_result: ct_send_compare_result,
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

/// Get the number of input devices available.
unsafe extern "C" fn ct_get_input_device_count() -> u32 {
    *INPUT_DEVICE_COUNT.get() as u32
}

/// Read a sector from a specific input device.
/// Args: device index (0 = top/primary), sector number, buffer pointer, buffer length
unsafe extern "C" fn ct_read_input_sector(
    device_index: u32,
    sector: u64,
    buffer: *mut u8,
    len: usize,
) -> bool {
    let index = device_index as usize;
    let devices = INPUT_DEVICES.get_mut();
    if index < *INPUT_DEVICE_COUNT.get() {
        if let Some(ref mut dev) = devices[index] {
            let slice = core::slice::from_raw_parts_mut(buffer, len);
            return dev.read_sector(sector, slice);
        }
    }
    false
}

/// Get capacity in sectors for a specific input device.
/// Args: device index (0 = top/primary)
/// Returns: capacity in sectors, or 0 if device index invalid
unsafe extern "C" fn ct_get_input_capacity(device_index: u32) -> u64 {
    let index = device_index as usize;
    let devices = INPUT_DEVICES.get();
    if index < *INPUT_DEVICE_COUNT.get() {
        if let Some(ref dev) = devices[index] {
            return dev.capacity();
        }
    }
    0
}

/// Get sector size in bytes for a specific input device.
/// Args: device index (0 = top/primary)
/// Returns: sector size in bytes, or 0 if device index invalid
unsafe extern "C" fn ct_get_input_sector_size(device_index: u32) -> usize {
    let index = device_index as usize;
    let devices = INPUT_DEVICES.get();
    if index < *INPUT_DEVICE_COUNT.get() {
        if let Some(ref dev) = devices[index] {
            return dev.sector_size();
        }
    }
    0
}

// ============================================================================
// Output device functions (single device)
// ============================================================================

unsafe extern "C" fn ct_write_output_sector(sector: u64, buffer: *const u8, len: usize) -> bool {
    if let Some(ref mut dev) = *OUTPUT_DEVICE.get_mut() {
        let slice = core::slice::from_raw_parts(buffer, len);
        dev.write_sector(sector, slice)
    } else {
        false
    }
}

unsafe extern "C" fn ct_get_output_capacity() -> u64 {
    OUTPUT_DEVICE
        .get()
        .as_ref()
        .map(|d| d.capacity())
        .unwrap_or(0)
}

unsafe extern "C" fn ct_get_output_sector_size() -> usize {
    OUTPUT_DEVICE
        .get()
        .as_ref()
        .map(|d| d.sector_size())
        .unwrap_or(512)
}

// ============================================================================
// Progress and messaging functions
// ============================================================================

unsafe extern "C" fn ct_get_progress_interval() -> u32 {
    CONFIG
        .get()
        .as_ref()
        .map(|c| c.progress_percent)
        .unwrap_or(10)
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

/// No-op print function used for verbose_print when verbose mode is disabled.
/// This avoids serial I/O overhead when debug output is not needed.
#[allow(unused_variables)]
unsafe extern "C" fn ct_silent_print(s: *const u8) {
    // Do nothing - verbose output disabled
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

/// Get chain configuration (metadata about backing chain devices).
/// The VMM writes the config to CHAIN_CONFIG_ADDR before starting the guest.
/// Returns ConfigResult - len=0 if no chain config is available (magic invalid).
unsafe extern "C" fn ct_get_chain_config() -> shared::ConfigResult {
    // Check if chain config is valid by reading the magic
    let chain_config = &*(CHAIN_CONFIG_ADDR as *const ChainConfig);
    if chain_config.magic == ChainConfig::MAGIC {
        shared::ConfigResult {
            ptr: CHAIN_CONFIG_ADDR as *const u8,
            len: CHAIN_CONFIG_MAX_SIZE,
        }
    } else {
        // No valid chain config - return empty result
        shared::ConfigResult {
            ptr: core::ptr::null(),
            len: 0,
        }
    }
}

/// Send info result message.
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn ct_send_info_result(
    format: *const u8,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: *const u8,
    external_data_file: *const u8,
) {
    let format_str = cstr_to_str(format);
    let backing_str = cstr_to_str(backing_file);
    let external_str = cstr_to_str(external_data_file);
    send_info_result(
        format_str,
        version,
        virtual_size,
        actual_size,
        cluster_size,
        flags,
        backing_str,
        external_str,
    );
}

/// Send info result message with QCOW2-specific information.
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn ct_send_info_result_qcow2(
    format: *const u8,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: *const u8,
    external_data_file: *const u8,
    qcow2_info: *const Qcow2Info,
) {
    let format_str = cstr_to_str(format);
    let backing_str = cstr_to_str(backing_file);
    let external_str = cstr_to_str(external_data_file);

    // Use default if null pointer
    let qcow2_data = if qcow2_info.is_null() {
        Qcow2Info::new()
    } else {
        *qcow2_info
    };

    send_info_result_qcow2(
        format_str,
        version,
        virtual_size,
        actual_size,
        cluster_size,
        flags,
        backing_str,
        external_str,
        &qcow2_data,
    );
}

/// Send info result message with VMDK-specific information.
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn ct_send_info_result_vmdk(
    format: *const u8,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: *const u8,
    external_data_file: *const u8,
    vmdk_info: *const VmdkInfo,
) {
    let format_str = cstr_to_str(format);
    let backing_str = cstr_to_str(backing_file);
    let external_str = cstr_to_str(external_data_file);

    // Use default if null pointer
    let vmdk_data = if vmdk_info.is_null() {
        VmdkInfo::new()
    } else {
        *vmdk_info
    };

    send_info_result_vmdk(
        format_str,
        version,
        virtual_size,
        actual_size,
        cluster_size,
        flags,
        backing_str,
        external_str,
        &vmdk_data,
    );
}

/// Send info result message with VDI-specific information.
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn ct_send_info_result_vdi(
    format: *const u8,
    version: u32,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
    backing_file: *const u8,
    external_data_file: *const u8,
    vdi_info: *const VdiInfo,
) {
    let format_str = cstr_to_str(format);
    let backing_str = cstr_to_str(backing_file);
    let external_str = cstr_to_str(external_data_file);

    // Use default if null pointer
    let vdi_data = if vdi_info.is_null() {
        VdiInfo::new()
    } else {
        *vdi_info
    };

    send_info_result_vdi(
        format_str,
        version,
        virtual_size,
        actual_size,
        cluster_size,
        flags,
        backing_str,
        external_str,
        &vdi_data,
    );
}

/// Send check result message.
unsafe extern "C" fn ct_send_check_result(result: *const CheckResult) {
    if !result.is_null() {
        send_check_result(&*result);
    }
}

/// Send compare result message.
unsafe extern "C" fn ct_send_compare_result(result: *const CompareResult) {
    if !result.is_null() {
        send_compare_result(&*result);
    }
}

/// Convert null-terminated C string to &str.
///
/// # Safety
///
/// The caller must ensure:
/// - `ptr` points to valid memory (or is null)
/// - The memory remains valid for the returned lifetime
///
/// This function validates UTF-8 and returns an empty string if validation
/// fails or if the string exceeds MAX_CSTR_LEN bytes.
unsafe fn cstr_to_str(ptr: *const u8) -> &'static str {
    // Maximum length to prevent unbounded reads on unterminated strings
    const MAX_CSTR_LEN: usize = 4096;

    if ptr.is_null() {
        return "";
    }

    // Find null terminator with length limit
    let mut len = 0;
    while len < MAX_CSTR_LEN && *ptr.add(len) != 0 {
        len += 1;
    }

    // If we hit the limit without finding null, return empty (unterminated string)
    if len == MAX_CSTR_LEN && *ptr.add(len) != 0 {
        return "";
    }

    let slice = core::slice::from_raw_parts(ptr, len);

    // Validate UTF-8 instead of assuming it's valid
    match core::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => "", // Return empty string for invalid UTF-8
    }
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
