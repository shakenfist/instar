#![no_main]
use libfuzzer_sys::fuzz_target;

// The mock read_input_sector serves fuzz input bytes verbatim starting at
// sector 0, so the header (and therefore the magic at byte 0) is driven
// directly by the fuzz corpus. Both Parallels magics (v1 "WithoutFreeSpace"
// and ext "WithouFreSpacExt") are 16-byte prefixes of the same input the
// mutator/coverage feedback controls, so both off_multiplier paths (1 for
// v1, tracks for ext) are reachable without any special-cased seeding --
// this mirrors how fuzz_vdi_bat reaches VdiState::init.
fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }

    instar_fuzz::set_fuzz_input(data);
    let call_table = instar_fuzz::build_call_table();
    let sector_size = 512;
    let input_capacity = instar_fuzz::input_capacity();

    let mut bytes_read = 0u64;
    let mut bat_cache_buf = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut data_cache_buf = vec![0u8; shared::MAX_SECTOR_SIZE];

    unsafe {
        let state = parallels::ParallelsState::init(
            &call_table,
            0,
            sector_size,
            input_capacity,
            bat_cache_buf.as_mut_ptr(),
            data_cache_buf.as_mut_ptr(),
            &mut bytes_read,
        );

        if let Some(mut state) = state {
            let cluster_size = state.cluster_size;

            // Fixed offsets spanning different clusters, including the
            // sentinel (BAT value 0 / beyond bat_entries) path.
            for offset in [0u64, 0x200000, 0x1000000, 0x10000000] {
                if let Some(lookup) =
                    state.block_lookup(&call_table, offset, sector_size, input_capacity, &mut bytes_read)
                {
                    check_lookup(lookup, offset, cluster_size);
                }
            }

            // Fuzz-derived offset for deeper exploration.
            if let Some(dynamic_offset) = instar_fuzz::extract_fuzz_offset(data) {
                if let Some(lookup) = state.block_lookup(
                    &call_table,
                    dynamic_offset,
                    sector_size,
                    input_capacity,
                    &mut bytes_read,
                ) {
                    check_lookup(lookup, dynamic_offset, cluster_size);
                }
            }
        }
    }
});

/// Assert the invariant a legal `block_lookup` result must satisfy,
/// regardless of which sentinel/allocated path was taken: an `Allocated`
/// result's host offset is built from a nonzero BAT entry (>= 1) times a
/// nonzero off_multiplier (>= 1) times 512, plus the in-cluster offset --
/// so it can never be less than one sector (512) plus that in-cluster
/// remainder. `Unallocated` carries no host offset to check.
fn check_lookup(lookup: parallels::ParallelsBlockLookup, virtual_offset: u64, cluster_size: u64) {
    if let parallels::ParallelsBlockLookup::Allocated { host_byte_offset } = lookup {
        let offset_in_cluster = virtual_offset % cluster_size;
        assert!(host_byte_offset >= 512 + offset_in_cluster);
    }
}
