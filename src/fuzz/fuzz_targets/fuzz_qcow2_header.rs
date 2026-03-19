#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(header) = qcow2::QcowHeader::parse(data) {
        // Exercise header extension parsing
        let _ = qcow2::parse_header_extensions(data, &header);

        // Exercise derived methods
        let _ = header.qemu_disk_size();
        let _ = header.compat_str();
        let _ = header.compat_value();

        // Exercise pure L2 entry parsing with header-derived cluster_bits
        let _ = qcow2::parse_compressed_l2_entry(0, header.cluster_bits);
        if data.len() >= 113 {
            let l2_val = u64::from_le_bytes([
                data[105], data[106], data[107], data[108],
                data[109], data[110], data[111], data[112],
            ]);
            let _ = qcow2::parse_compressed_l2_entry(l2_val, header.cluster_bits);
        }
    }
});
