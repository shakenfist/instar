//! Fuzz harness support for instar parser crates.
//!
//! Provides a mock CallTable backed by fuzzer input, allowing
//! coverage-guided fuzzing of the no_std parser crates without
//! the full VMM/KVM stack.

use std::cell::RefCell;

thread_local! {
    static FUZZ_DATA: RefCell<Vec<u8>> = RefCell::new(Vec::new());

    /// Per-device buffers for the opt-in multi-device mode.
    ///
    /// Empty is the only state the single-device targets ever see, and
    /// every device mock below tests it first and falls through to
    /// `FUZZ_DATA` unchanged. A target that never calls
    /// [`set_fuzz_devices`] therefore cannot tell this list exists:
    /// that is what keeps one input device, backed by the single
    /// buffer, the default for the targets that assume it.
    static FUZZ_DEVICES: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
}

const SECTOR_SIZE: usize = 512;

/// A buffer of `len` bytes, measured in whole sectors (rounded up).
fn sectors_for(len: usize) -> u64 {
    (len as u64 + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64
}

/// Store fuzz input for the current iteration.
///
/// Must be called before `build_call_table()` or `input_capacity()`.
///
/// This installs single-device mode: one input device, backed by
/// `data`. Any per-device buffers a previous iteration installed with
/// [`set_fuzz_devices`] are dropped, so what the mocks answer depends
/// on this iteration's calls and not on the iteration before it. A
/// target that wants both calls them in this order.
pub fn set_fuzz_input(data: &[u8]) {
    FUZZ_DEVICES.with(|d| d.borrow_mut().clear());
    FUZZ_DATA.with(|f| {
        let mut input = f.borrow_mut();
        input.clear();
        input.extend_from_slice(data);
    });
}

/// Store one buffer per input device for the current iteration,
/// turning on multi-device mode.
///
/// `devices[0]` is device 0, and so on: the indices are the call
/// table's `device_idx`, which for a backing chain means device 0 is
/// the top image and each following device sits behind it. Reads of a
/// device index past the end of `devices` fail the way a read past the
/// end of a device's bytes does — zero-filled buffer, `false` return —
/// rather than aliasing another device's bytes.
///
/// Opt-in on purpose. Every other target is written against one input
/// device holding the whole fuzz input, and a target that silently
/// became two-device would still pass while reaching less code than
/// it did before. Passing an empty slice returns the mocks to that
/// single-device default.
pub fn set_fuzz_devices(devices: &[&[u8]]) {
    FUZZ_DEVICES.with(|d| {
        let mut installed = d.borrow_mut();
        installed.clear();
        installed.extend(devices.iter().map(|dev| dev.to_vec()));
    });
}

/// Return the fuzz input size in sectors (rounded up).
pub fn input_capacity() -> u64 {
    FUZZ_DATA.with(|f| sectors_for(f.borrow().len()))
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
        read_output_sector: mock_read_output_sector,
        send_resize_result: mock_send_resize_result,
        send_rebase_result: mock_send_rebase_result,
        send_commit_result: mock_send_commit_result,
        write_input_sector: mock_write_input_sector,
        send_map_extent: mock_send_map_extent,
        send_map_result: mock_send_map_result,
        send_snapshot_entry: mock_send_snapshot_entry,
        send_snapshot_result: mock_send_snapshot_result,
        fsync_input: mock_fsync_input,
        send_amend_result: mock_send_amend_result,
        send_bitmap_result: mock_send_bitmap_result,
        send_bench_start: mock_send_bench_start,
        send_bench_result: mock_send_bench_result,
    }
}

// ---------------------------------------------------------------------------
// Mock function pointer implementations
// ---------------------------------------------------------------------------

unsafe extern "C" fn mock_get_input_device_count() -> u32 {
    FUZZ_DEVICES.with(|d| {
        let count = d.borrow().len();
        if count == 0 {
            1
        } else {
            count as u32
        }
    })
}

/// Serve one sector-sized read out of `data`.
///
/// The whole of the read mock's behaviour, in one place, so the
/// single-device and multi-device paths cannot drift: both hand it a
/// `&[u8]` and nothing else. Lifting it out of
/// `mock_read_input_sector` is the only change the single-device path
/// has seen — the body below is the one that was inline there.
///
/// # Safety
///
/// `buffer` must point to at least `len` writable bytes.
unsafe fn serve_sector(data: &[u8], sector: u64, buffer: *mut u8, len: usize) -> bool {
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
}

unsafe extern "C" fn mock_read_input_sector(
    device_idx: u32,
    sector: u64,
    buffer: *mut u8,
    len: usize,
) -> bool {
    FUZZ_DEVICES.with(|d| {
        let devices = d.borrow();
        if devices.is_empty() {
            return FUZZ_DATA.with(|f| serve_sector(&f.borrow(), sector, buffer, len));
        }
        match devices.get(device_idx as usize) {
            Some(device) => serve_sector(device, sector, buffer, len),
            // A device index the harness never installed holds no
            // bytes at all, which is a harder failure than reading
            // past the end of one that does. Answering with another
            // device's bytes would be the worst possible mock for a
            // chain reader, whose whole job is to attribute data to
            // the right device.
            None => {
                std::ptr::write_bytes(buffer, 0, len);
                false
            }
        }
    })
}

unsafe extern "C" fn mock_get_input_capacity(device_idx: u32) -> u64 {
    FUZZ_DEVICES.with(|d| {
        let devices = d.borrow();
        if devices.is_empty() {
            return FUZZ_DATA.with(|f| sectors_for(f.borrow().len()));
        }
        // Zero sectors for an uninstalled index, matching the read
        // mock's refusal for the same index.
        devices
            .get(device_idx as usize)
            .map_or(0, |device| sectors_for(device.len()))
    })
}

// Every device reads in 512-byte sectors, in both modes: the sector
// size is a property of the mock rather than of the buffer behind a
// device, so there is nothing per-device to answer. The same goes for
// `mock_write_input_sector` and `mock_fsync_input` below, which refuse
// and succeed respectively whatever device they are asked about.
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

unsafe extern "C" fn mock_read_output_sector(
    _sector: u64,
    _buffer: *mut u8,
    _len: usize,
) -> bool {
    false
}

unsafe extern "C" fn mock_send_resize_result(_result: *const shared::ResizeResult) {}

unsafe extern "C" fn mock_send_rebase_result(_result: *const shared::RebaseResult) {}

unsafe extern "C" fn mock_send_commit_result(_result: *const shared::CommitResult) {}

unsafe extern "C" fn mock_write_input_sector(
    _device_idx: u32,
    _sector: u64,
    _buffer: *const u8,
    _len: usize,
) -> bool {
    false
}

unsafe extern "C" fn mock_send_map_extent(_record: *const shared::MapExtentRecord) {}

unsafe extern "C" fn mock_send_map_result(_result: *const shared::MapResult) {}

unsafe extern "C" fn mock_send_snapshot_entry(_record: *const shared::SnapshotEntryRecord) {}

unsafe extern "C" fn mock_send_snapshot_result(_result: *const shared::SnapshotResult) {}

unsafe extern "C" fn mock_fsync_input(_device_idx: u32) -> bool {
    true
}

unsafe extern "C" fn mock_send_amend_result(_result: *const shared::AmendResult) {}

unsafe extern "C" fn mock_send_bitmap_result(_result: *const shared::BitmapResult) {}

unsafe extern "C" fn mock_send_bench_start() {}

unsafe extern "C" fn mock_send_bench_result(_result: *const shared::BenchResult) {}

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

    // -- set_fuzz_devices --

    /// Helper: read a sector of a given device via the mock and return
    /// (success, buffer).
    fn read_device_sector(device_idx: u32, sector: u64, len: usize) -> (bool, Vec<u8>) {
        let mut buf = vec![0xFFu8; len];
        let ok = unsafe { mock_read_input_sector(device_idx, sector, buf.as_mut_ptr(), len) };
        (ok, buf)
    }

    /// The default every target that never calls `set_fuzz_devices`
    /// gets: one device, the single buffer, whatever index is asked
    /// about. Asserted for a non-zero index too, because the old mock
    /// ignored the index entirely and a per-device lookup is the one
    /// way that could have changed.
    #[test]
    fn devices_default_to_the_single_buffer() {
        let data: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        set_fuzz_input(&data);

        assert_eq!(unsafe { mock_get_input_device_count() }, 1);
        assert_eq!(unsafe { mock_get_input_capacity(0) }, 1);
        assert_eq!(unsafe { mock_get_input_capacity(7) }, 1);

        let (ok, buf) = read_device_sector(0, 0, 512);
        assert!(ok);
        assert_eq!(buf, data);

        let (ok, buf) = read_device_sector(7, 0, 512);
        assert!(
            ok,
            "a non-zero device index must still read the single buffer"
        );
        assert_eq!(buf, data);
    }

    #[test]
    fn devices_are_served_per_index() {
        let child = vec![0xC1u8; 512];
        let parent = vec![0xA2u8; 1024];
        set_fuzz_devices(&[&child, &parent]);

        assert_eq!(unsafe { mock_get_input_device_count() }, 2);
        assert_eq!(unsafe { mock_get_input_capacity(0) }, 1);
        assert_eq!(unsafe { mock_get_input_capacity(1) }, 2);

        let (ok, buf) = read_device_sector(0, 0, 512);
        assert!(ok);
        assert!(
            buf.iter().all(|&b| b == 0xC1),
            "device 0 served other bytes"
        );

        let (ok, buf) = read_device_sector(1, 1, 512);
        assert!(ok);
        assert!(
            buf.iter().all(|&b| b == 0xA2),
            "device 1 served other bytes"
        );

        // Device 0 ends after one sector; device 1 does not. Each
        // device's end is its own.
        let (ok, buf) = read_device_sector(0, 1, 512);
        assert!(!ok, "device 0's second sector does not exist");
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn uninstalled_device_index_refuses() {
        let only = vec![0xABu8; 512];
        set_fuzz_devices(&[&only]);

        assert_eq!(unsafe { mock_get_input_device_count() }, 1);
        assert_eq!(unsafe { mock_get_input_capacity(1) }, 0);

        let (ok, buf) = read_device_sector(1, 0, 512);
        assert!(!ok, "a device index that was never installed must refuse");
        assert!(buf.iter().all(|&b| b == 0), "a refused read must zero-fill");
    }

    #[test]
    fn empty_device_list_restores_the_default() {
        set_fuzz_devices(&[&[0u8; 512][..], &[0u8; 512][..]]);
        assert_eq!(unsafe { mock_get_input_device_count() }, 2);

        set_fuzz_devices(&[]);
        assert_eq!(unsafe { mock_get_input_device_count() }, 1);
    }

    #[test]
    fn set_fuzz_input_turns_multi_device_mode_off() {
        set_fuzz_devices(&[&[0xAAu8; 512][..], &[0xBBu8; 512][..]]);
        assert_eq!(unsafe { mock_get_input_device_count() }, 2);

        let single = vec![0x5Au8; 512];
        set_fuzz_input(&single);
        assert_eq!(unsafe { mock_get_input_device_count() }, 1);
        let (ok, buf) = read_device_sector(1, 0, 512);
        assert!(
            ok,
            "after set_fuzz_input every index reads the single buffer"
        );
        assert_eq!(buf, single);
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
