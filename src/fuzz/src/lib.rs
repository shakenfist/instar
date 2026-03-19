//! Fuzz harness support for imago parser crates.
//!
//! Provides a mock CallTable backed by fuzzer input, allowing
//! coverage-guided fuzzing of the no_std parser crates without
//! the full VMM/KVM stack.

use std::cell::RefCell;

thread_local! {
    static FUZZ_DATA: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

const SECTOR_SIZE: usize = 512;

/// Store fuzz input for the current iteration.
///
/// Must be called before `build_call_table()` or `input_capacity()`.
pub fn set_fuzz_input(data: &[u8]) {
    FUZZ_DATA.with(|f| {
        let mut input = f.borrow_mut();
        input.clear();
        input.extend_from_slice(data);
    });
}

/// Return the fuzz input size in sectors (rounded up).
pub fn input_capacity() -> u64 {
    FUZZ_DATA.with(|f| {
        let data = f.borrow();
        (data.len() as u64 + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64
    })
}

/// Return the raw fuzz input size in bytes.
pub fn input_size_bytes() -> u64 {
    FUZZ_DATA.with(|f| f.borrow().len() as u64)
}

/// Build a CallTable with mock function pointers backed by the
/// thread-local fuzz input.
pub fn build_call_table() -> shared::CallTable {
    shared::CallTable {
        magic: shared::CallTable::MAGIC,
        version: shared::CallTable::VERSION,
        get_input_device_count: mock_get_input_device_count,
        read_input_sector: mock_read_input_sector,
        get_input_capacity: mock_get_input_capacity,
        get_input_sector_size: mock_get_input_sector_size,
        write_output_sector: mock_write_output_sector,
        get_output_capacity: mock_get_output_capacity,
        get_output_sector_size: mock_get_output_sector_size,
        get_progress_interval: mock_get_progress_interval,
        send_progress: mock_send_progress,
        send_error: mock_send_error,
        send_complete: mock_send_complete,
        debug_print: mock_debug_print,
        verbose_print: mock_verbose_print,
        get_operation_config: mock_get_operation_config,
        get_chain_config: mock_get_chain_config,
        send_info_result: mock_send_info_result,
        send_info_result_qcow2: mock_send_info_result_qcow2,
        send_info_result_vmdk: mock_send_info_result_vmdk,
        send_info_result_vdi: mock_send_info_result_vdi,
        send_info_result_luks: mock_send_info_result_luks,
        send_check_result: mock_send_check_result,
        send_compare_result: mock_send_compare_result,
    }
}

// ---------------------------------------------------------------------------
// Mock function pointer implementations
// ---------------------------------------------------------------------------

unsafe extern "C" fn mock_get_input_device_count() -> u32 {
    1
}

unsafe extern "C" fn mock_read_input_sector(
    _device_idx: u32,
    sector: u64,
    buffer: *mut u8,
    len: usize,
) -> bool {
    FUZZ_DATA.with(|f| {
        let data = f.borrow();
        let sector_usize = sector as usize;
        let offset = match sector_usize.checked_mul(len) {
            Some(o) => o,
            None => {
                std::ptr::write_bytes(buffer, 0, len);
                return false;
            }
        };
        if offset >= data.len() {
            std::ptr::write_bytes(buffer, 0, len);
            return false;
        }
        let available = data.len() - offset;
        let copy_len = available.min(len);
        std::ptr::copy_nonoverlapping(data.as_ptr().add(offset), buffer, copy_len);
        if copy_len < len {
            std::ptr::write_bytes(buffer.add(copy_len), 0, len - copy_len);
        }
        true
    })
}

unsafe extern "C" fn mock_get_input_capacity(_device_idx: u32) -> u64 {
    FUZZ_DATA.with(|f| {
        let data = f.borrow();
        (data.len() as u64 + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64
    })
}

unsafe extern "C" fn mock_get_input_sector_size(_device_idx: u32) -> usize {
    SECTOR_SIZE
}

unsafe extern "C" fn mock_write_output_sector(
    _sector: u64,
    _buffer: *const u8,
    _len: usize,
) -> bool {
    true
}

unsafe extern "C" fn mock_get_output_capacity() -> u64 {
    0
}

unsafe extern "C" fn mock_get_output_sector_size() -> usize {
    SECTOR_SIZE
}

unsafe extern "C" fn mock_get_progress_interval() -> u32 {
    100 // suppress progress
}

unsafe extern "C" fn mock_send_progress(
    _op: *const u8,
    _current: u64,
    _total: u64,
    _percent: u32,
) {
}

unsafe extern "C" fn mock_send_error(
    _op: *const u8,
    _device: *const u8,
    _sector: u64,
    _status: u32,
) {
}

unsafe extern "C" fn mock_send_complete(_op: *const u8, _bytes: u64, _success: bool) {}

unsafe extern "C" fn mock_debug_print(_msg: *const u8) {}

unsafe extern "C" fn mock_verbose_print(_msg: *const u8) {}

unsafe extern "C" fn mock_get_operation_config() -> shared::ConfigResult {
    shared::ConfigResult {
        ptr: std::ptr::null(),
        len: 0,
    }
}

unsafe extern "C" fn mock_get_chain_config() -> shared::ConfigResult {
    shared::ConfigResult {
        ptr: std::ptr::null(),
        len: 0,
    }
}

unsafe extern "C" fn mock_send_info_result(
    _format: *const u8,
    _version: u32,
    _virtual_size: u64,
    _actual_size: u64,
    _cluster_size: u32,
    _flags: u32,
    _backing_file: *const u8,
    _external_data_file: *const u8,
) {
}

unsafe extern "C" fn mock_send_info_result_qcow2(
    _format: *const u8,
    _version: u32,
    _virtual_size: u64,
    _actual_size: u64,
    _cluster_size: u32,
    _flags: u32,
    _backing_file: *const u8,
    _external_data_file: *const u8,
    _qcow2_info: *const shared::Qcow2Info,
) {
}

unsafe extern "C" fn mock_send_info_result_vmdk(
    _format: *const u8,
    _version: u32,
    _virtual_size: u64,
    _actual_size: u64,
    _cluster_size: u32,
    _flags: u32,
    _backing_file: *const u8,
    _external_data_file: *const u8,
    _vmdk_info: *const shared::VmdkInfo,
) {
}

unsafe extern "C" fn mock_send_info_result_vdi(
    _format: *const u8,
    _version: u32,
    _virtual_size: u64,
    _actual_size: u64,
    _cluster_size: u32,
    _flags: u32,
    _backing_file: *const u8,
    _external_data_file: *const u8,
    _vdi_info: *const shared::VdiInfo,
) {
}

unsafe extern "C" fn mock_send_info_result_luks(
    _format: *const u8,
    _version: u32,
    _virtual_size: u64,
    _actual_size: u64,
    _cluster_size: u32,
    _flags: u32,
    _backing_file: *const u8,
    _external_data_file: *const u8,
    _luks_info: *const shared::LuksInfo,
) {
}

unsafe extern "C" fn mock_send_check_result(_result: *const shared::CheckResult) {}

unsafe extern "C" fn mock_send_compare_result(_result: *const shared::CompareResult) {}
