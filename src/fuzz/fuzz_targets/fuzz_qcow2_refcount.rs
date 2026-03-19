#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }

    // Parse the header from the buffer to get refcount table params
    let header = match qcow2::QcowHeader::parse(data) {
        Some(h) => h,
        None => return,
    };

    imago_fuzz::set_fuzz_input(data);
    let call_table = imago_fuzz::build_call_table();
    let sector_size = 512;
    let input_capacity = imago_fuzz::input_capacity();

    let mut bytes_read = 0u64;
    let mut rt_cache = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut rb_cache = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut rt_sector = u64::MAX;
    let mut rb_sector = u64::MAX;

    unsafe {
        // Try refcount lookups at various host offsets
        for host_offset in [0u64, header.cluster_size, header.cluster_size * 2, header.cluster_size * 100] {
            let _ = qcow2::lookup_refcount(
                &call_table,
                0,
                header.refcount_table_offset,
                header.refcount_bits,
                header.cluster_size,
                sector_size,
                input_capacity,
                host_offset,
                &mut rt_sector,
                rt_cache.as_mut_ptr(),
                &mut rb_sector,
                rb_cache.as_mut_ptr(),
                &mut bytes_read,
            );
        }

        // Fuzz-derived host offset
        if data.len() >= 520 {
            let dynamic_offset = u64::from_le_bytes([
                data[512], data[513], data[514], data[515],
                data[516], data[517], data[518], data[519],
            ]);
            let _ = qcow2::lookup_refcount(
                &call_table,
                0,
                header.refcount_table_offset,
                header.refcount_bits,
                header.cluster_size,
                sector_size,
                input_capacity,
                dynamic_offset,
                &mut rt_sector,
                rt_cache.as_mut_ptr(),
                &mut rb_sector,
                rb_cache.as_mut_ptr(),
                &mut bytes_read,
            );
        }
    }
});
