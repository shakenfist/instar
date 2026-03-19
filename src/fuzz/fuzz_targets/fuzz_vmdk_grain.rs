#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }

    imago_fuzz::set_fuzz_input(data);
    let call_table = imago_fuzz::build_call_table();
    let sector_size = 512;
    let input_capacity = imago_fuzz::input_capacity();
    let actual_file_size = imago_fuzz::input_size_bytes();

    let mut bytes_read = 0u64;
    let mut gd_cache = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut gt_cache = vec![0u8; shared::MAX_SECTOR_SIZE];

    unsafe {
        let state = vmdk::VmdkState::init(
            &call_table,
            0,
            sector_size,
            input_capacity,
            actual_file_size,
            gd_cache.as_mut_ptr(),
            gt_cache.as_mut_ptr(),
            &mut bytes_read,
        );

        if let Some(mut state) = state {
            // Fixed offsets
            for offset in [0u64, 65536, 1 << 20, 1 << 30] {
                let _ = state.grain_lookup(
                    &call_table,
                    offset,
                    sector_size,
                    input_capacity,
                    &mut bytes_read,
                );
            }

            // Fuzz-derived offset
            if data.len() >= 520 {
                let dynamic_offset = u64::from_le_bytes([
                    data[512], data[513], data[514], data[515],
                    data[516], data[517], data[518], data[519],
                ]);
                let _ = state.grain_lookup(
                    &call_table,
                    dynamic_offset,
                    sector_size,
                    input_capacity,
                    &mut bytes_read,
                );
            }
        }
    }
});
