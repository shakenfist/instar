#![no_main]
use libfuzzer_sys::fuzz_target;

// The mock read_input_sector serves fuzz input bytes verbatim starting at
// sector 0, so the header (bytes 0..48, including l1_table_offset at byte
// 40) is driven directly by the fuzz corpus, and so is every byte the L1
// and L2 tables are read from -- Qcow1State::init/block_lookup never
// validate l1_table_offset, so the mutator/coverage feedback can freely
// walk it anywhere in the input, including on top of other L1/L2 entries.
// In particular, L2 entries are plain 8-byte big-endian words read straight
// out of the fuzz bytes, so bit 63 (QCOW1_OFLAG_COMPRESSED) is naturally
// reachable by ordinary bit mutation of any such 8-byte span -- both the
// Allocated and Compressed decode paths are exercised without any special
// seeding, mirroring how fuzz_parallels_bat reaches both off_multiplier
// paths.
fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }

    instar_fuzz::set_fuzz_input(data);
    let call_table = instar_fuzz::build_call_table();
    let sector_size = 512;
    let input_capacity = instar_fuzz::input_capacity();

    let mut bytes_read = 0u64;
    let mut l1_cache_buf = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut l2_cache_buf = vec![0u8; shared::MAX_SECTOR_SIZE];

    unsafe {
        let state = qcow1::Qcow1State::init(
            &call_table,
            0,
            sector_size,
            input_capacity,
            l1_cache_buf.as_mut_ptr(),
            l2_cache_buf.as_mut_ptr(),
            &mut bytes_read,
        );

        // init returns None for a malformed header, an encrypted image, or
        // overflowing L1-region arithmetic -- skip the iteration cleanly,
        // same as fuzz_parallels_bat.
        let Some(mut state) = state else {
            return;
        };

        let cluster_size = state.cluster_size;
        let cluster_bits = state.cluster_bits;
        let virtual_size = state.virtual_size;

        // Fixed offsets: start of image, a cluster boundary, mid-cluster,
        // and near the end of the declared virtual size.
        let offsets = [
            0u64,
            cluster_size,
            cluster_size.saturating_add(cluster_size / 2),
            virtual_size.saturating_sub(1),
        ];

        for &offset in offsets.iter() {
            if let Some(lookup) =
                state.block_lookup(&call_table, offset, sector_size, input_capacity, &mut bytes_read)
            {
                check_lookup(lookup, offset, cluster_size, cluster_bits);
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
                check_lookup(lookup, dynamic_offset, cluster_size, cluster_bits);
            }
        }
    }
});

/// Assert the invariants a legal `block_lookup` result must satisfy,
/// regardless of which path was taken.
///
/// `Unallocated` carries no host offset to check (and, unlike VDI/
/// Parallels, does not itself mean "zero-fill" -- the chain reader
/// descends to a backing file if one exists -- so there is nothing further
/// to assert at this layer).
///
/// `Allocated`: the host offset is `entry + offset_in_cluster` computed via
/// `checked_add` inside the crate, so a `Some` result guarantees the
/// addition did not wrap; re-derive `offset_in_cluster` here and confirm
/// the returned offset is never less than it (i.e. it really is
/// `entry + offset_in_cluster` for some `entry >= 0`, not a wrapped value).
///
/// `Compressed`: `csize` must be strictly less than `cluster_size` (the
/// crate masks it with `cluster_size - 1`) and `host_offset` must fit the
/// `63 - cluster_bits`-bit mask the crate derives it with.
fn check_lookup(lookup: qcow1::Qcow1BlockLookup, virtual_offset: u64, cluster_size: u64, cluster_bits: u8) {
    match lookup {
        qcow1::Qcow1BlockLookup::Unallocated => {}
        qcow1::Qcow1BlockLookup::Allocated(host_byte_offset) => {
            let offset_in_cluster = virtual_offset % cluster_size;
            assert!(host_byte_offset >= offset_in_cluster);
        }
        qcow1::Qcow1BlockLookup::Compressed { host_offset, csize } => {
            assert!((csize as u64) < cluster_size);
            let shift = 63u32 - cluster_bits as u32;
            let max_host_offset = (1u64 << shift) - 1;
            assert!(host_offset <= max_host_offset);
        }
    }
}
