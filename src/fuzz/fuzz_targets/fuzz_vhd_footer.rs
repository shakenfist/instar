#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Footer parsing (validates cookie, extracts fields)
    if let Some(_footer) = vhd::VhdFooter::parse(data) {
        // Footer is valid, try dynamic header from offset 512
        if data.len() >= 1536 {
            let _ = vhd::VhdDynamicHeader::parse(&data[512..]);
        }
    }

    // Dynamic header parsing standalone
    let _ = vhd::VhdDynamicHeader::parse(data);

    // Checksum computation (used for footer validation)
    if data.len() >= 68 {
        let _ = vhd::compute_checksum(data, 64);
    }
    if data.len() >= 512 {
        let _ = vhd::compute_checksum(data, 64);
    }

    // CHS geometry calculation from arbitrary size
    if data.len() >= 8 {
        let size = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        let _ = vhd::compute_vhd_geometry(size);
    }
});
