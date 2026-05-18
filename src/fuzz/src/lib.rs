//! Fuzz harness support for instar parser crates.
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

/// Extract a u64 offset from bytes 512..520 of the fuzz input.
///
/// Many fuzz targets use a fixed set of lookup offsets plus one
/// derived from the fuzz input for deeper exploration. This helper
/// extracts that dynamic offset from a consistent location (the
/// first byte past the first sector).
pub fn extract_fuzz_offset(data: &[u8]) -> Option<u64> {
    if data.len() < 520 {
        return None;
    }
    Some(u64::from_le_bytes([
        data[512], data[513], data[514], data[515],
        data[516], data[517], data[518], data[519],
    ]))
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
        send_measure_result: mock_send_measure_result,
        send_create_result: mock_send_create_result,
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

unsafe extern "C" fn mock_send_measure_result(_result: *const shared::MeasureResult) {}

unsafe extern "C" fn mock_send_create_result(_result: *const shared::CreateResult) {}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- extract_fuzz_offset --

    #[test]
    fn extract_fuzz_offset_too_short() {
        assert_eq!(extract_fuzz_offset(&[0u8; 519]), None);
        assert_eq!(extract_fuzz_offset(&[]), None);
    }

    #[test]
    fn extract_fuzz_offset_exact_size() {
        let mut data = vec![0u8; 520];
        data[512..520].copy_from_slice(&42u64.to_le_bytes());
        assert_eq!(extract_fuzz_offset(&data), Some(42));
    }

    #[test]
    fn extract_fuzz_offset_large_value() {
        let mut data = vec![0u8; 1024];
        data[512..520].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(extract_fuzz_offset(&data), Some(u64::MAX));
    }

    // -- set_fuzz_input / input_capacity / input_size_bytes --

    #[test]
    fn empty_input() {
        set_fuzz_input(&[]);
        assert_eq!(input_capacity(), 0);
        assert_eq!(input_size_bytes(), 0);
    }

    #[test]
    fn input_one_byte() {
        set_fuzz_input(&[0xAA]);
        assert_eq!(input_capacity(), 1); // rounds up to 1 sector
        assert_eq!(input_size_bytes(), 1);
    }

    #[test]
    fn input_exact_sector() {
        set_fuzz_input(&[0u8; 512]);
        assert_eq!(input_capacity(), 1);
        assert_eq!(input_size_bytes(), 512);
    }

    #[test]
    fn input_sector_plus_one() {
        set_fuzz_input(&[0u8; 513]);
        assert_eq!(input_capacity(), 2);
        assert_eq!(input_size_bytes(), 513);
    }

    #[test]
    fn input_replaces_previous() {
        set_fuzz_input(&[0u8; 1024]);
        assert_eq!(input_capacity(), 2);
        set_fuzz_input(&[0u8; 512]);
        assert_eq!(input_capacity(), 1);
    }

    // -- build_call_table --

    #[test]
    fn call_table_has_correct_magic_and_version() {
        let ct = build_call_table();
        assert_eq!(ct.magic, shared::CallTable::MAGIC);
        assert_eq!(ct.version, shared::CallTable::VERSION);
    }

    // -- mock_read_input_sector --

    /// Helper: read a sector via the mock and return (success, buffer).
    fn read_sector(sector: u64, len: usize) -> (bool, Vec<u8>) {
        let mut buf = vec![0xFFu8; len];
        let ok = unsafe {
            mock_read_input_sector(0, sector, buf.as_mut_ptr(), len)
        };
        (ok, buf)
    }

    #[test]
    fn read_sector_within_bounds() {
        let data: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        set_fuzz_input(&data);

        let (ok, buf) = read_sector(0, 512);
        assert!(ok);
        assert_eq!(buf, data);
    }

    #[test]
    fn read_sector_beyond_eof_returns_false() {
        set_fuzz_input(&[0u8; 512]);

        let (ok, buf) = read_sector(1, 512);
        assert!(!ok);
        assert!(buf.iter().all(|&b| b == 0), "out-of-bounds read should zero-fill");
    }

    #[test]
    fn read_partial_last_sector_zero_pads() {
        // 600 bytes = 1 full sector + 88 bytes into second sector
        let mut data = vec![0u8; 600];
        data[512..600].fill(0xAB);
        set_fuzz_input(&data);

        // Sector 1 starts at byte 512. Only 88 bytes available,
        // rest should be zero-padded. Returns true (sector starts
        // within bounds).
        let (ok, buf) = read_sector(1, 512);
        assert!(ok);
        assert_eq!(&buf[..88], &[0xAB; 88]);
        assert!(buf[88..].iter().all(|&b| b == 0), "remainder should be zero");
    }

    #[test]
    fn read_empty_input_returns_false() {
        set_fuzz_input(&[]);

        let (ok, buf) = read_sector(0, 512);
        assert!(!ok);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn read_very_large_sector_number_returns_false() {
        set_fuzz_input(&[0u8; 512]);

        let (ok, buf) = read_sector(u64::MAX, 512);
        assert!(!ok);
        assert!(buf.iter().all(|&b| b == 0));
    }

    // -- mock_get_input_capacity / mock_get_input_sector_size --

    #[test]
    fn mock_capacity_matches_public_fn() {
        set_fuzz_input(&[0u8; 1500]);
        let expected = input_capacity();
        let got = unsafe { mock_get_input_capacity(0) };
        assert_eq!(got, expected);
    }

    #[test]
    fn mock_sector_size_is_512() {
        let got = unsafe { mock_get_input_sector_size(0) };
        assert_eq!(got, 512);
    }

    // -- mock_get_input_device_count --

    #[test]
    fn device_count_is_one() {
        let got = unsafe { mock_get_input_device_count() };
        assert_eq!(got, 1);
    }

    // -- mock_write_output_sector --

    #[test]
    fn write_output_always_succeeds() {
        let buf = [0u8; 512];
        let ok = unsafe {
            mock_write_output_sector(0, buf.as_ptr(), buf.len())
        };
        assert!(ok);
    }

    // -- config mocks return empty --

    #[test]
    fn operation_config_is_empty() {
        let cfg = unsafe { mock_get_operation_config() };
        assert!(cfg.ptr.is_null());
        assert_eq!(cfg.len, 0);
    }

    #[test]
    fn chain_config_is_empty() {
        let cfg = unsafe { mock_get_chain_config() };
        assert!(cfg.ptr.is_null());
        assert_eq!(cfg.len, 0);
    }
}
