#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    instar_fuzz::set_fuzz_input(data);
    let call_table = instar_fuzz::build_call_table();
    let sector_size = 512;
    let input_capacity = instar_fuzz::input_capacity();

    // Extract l2_entry from first 8 bytes and force compressed flag
    let l2_entry = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]) | (1u64 << 62);

    // Try multiple cluster sizes to exercise different code paths
    for cluster_bits in [12u32, 16, 20] {
        let cluster_size = 1u64 << cluster_bits;
        let mut out_buf = vec![0u8; cluster_size as usize];
        let mut compressed_buf = vec![0u8; shared::COMPRESSED_BUF_SIZE];
        let mut bytes_read = 0u64;

        unsafe {
            // Zlib decompression path
            let _ = qcow2::read_compressed_cluster(
                &call_table,
                0,
                l2_entry,
                cluster_bits,
                out_buf.as_mut_ptr(),
                cluster_size,
                sector_size,
                compressed_buf.as_mut_ptr(),
                input_capacity,
                &mut bytes_read,
            );
        }
    }
});
