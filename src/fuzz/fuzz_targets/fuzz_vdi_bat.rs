#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }

    instar_fuzz::set_fuzz_input(data);
    let call_table = instar_fuzz::build_call_table();
    let sector_size = 512;
    let input_capacity = instar_fuzz::input_capacity();

    let mut bytes_read = 0u64;
    let mut bmap_cache = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut data_cache = vec![0u8; shared::MAX_SECTOR_SIZE];

    unsafe {
        let state = vdi::VdiState::init(
            &call_table,
            0,
            sector_size,
            input_capacity,
            bmap_cache.as_mut_ptr(),
            data_cache.as_mut_ptr(),
            &mut bytes_read,
        );

        if let Some(mut state) = state {
            let offset_data = state.offset_data;

            // Fixed offsets spanning different blocks.
            for offset in [0u64, 0x200000, 0x1000000, 0x10000000] {
                if let Some(vdi::VdiBlockLookup::Allocated { host_byte_offset }) = state
                    .block_lookup(&call_table, offset, sector_size, input_capacity, &mut bytes_read)
                {
                    assert!(host_byte_offset >= offset_data);
                }
            }

            // Fuzz-derived offset.
            if let Some(dynamic_offset) = instar_fuzz::extract_fuzz_offset(data) {
                if let Some(vdi::VdiBlockLookup::Allocated { host_byte_offset }) = state
                    .block_lookup(
                        &call_table,
                        dynamic_offset,
                        sector_size,
                        input_capacity,
                        &mut bytes_read,
                    )
                {
                    assert!(host_byte_offset >= offset_data);
                }
            }
        }
    }
});
