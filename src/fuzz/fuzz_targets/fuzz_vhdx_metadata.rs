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

    let mut bytes_read = 0u64;
    let mut bat_cache = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut data_cache = vec![0u8; shared::MAX_SECTOR_SIZE];

    unsafe {
        // Full state init exercises header parsing, region table,
        // and metadata parsing via CallTable I/O
        let state = vhdx::VhdxState::init(
            &call_table,
            0,
            sector_size,
            input_capacity,
            bat_cache.as_mut_ptr(),
            data_cache.as_mut_ptr(),
            &mut bytes_read,
        );

        if let Some(mut state) = state {
            // Block lookups exercise BAT reading
            for offset in [0u64, 0x400000, 0x4000000, 0x40000000] {
                let _ = state.block_lookup(
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
                let _ = state.block_lookup(
                    &call_table,
                    dynamic_offset,
                    sector_size,
                    input_capacity,
                    &mut bytes_read,
                );
            }
        }

        // Also exercise standalone metadata parsing at various offsets
        // (metadata table can appear at different locations in VHDX)
        for metadata_offset in [0u64, 0x10000, 0x30000] {
            let _ = vhdx::parse_metadata(
                &call_table,
                0,
                metadata_offset,
                sector_size,
                input_capacity,
                &mut bytes_read,
            );
        }
    }
});
