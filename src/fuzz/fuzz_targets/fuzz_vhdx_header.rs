#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Header parsing (validates signature, CRC-32C)
    let _ = vhdx::VhdxHeader::parse(data);

    // Region table parsing (validates CRC-32C, extracts entries)
    let _ = vhdx::parse_region_table(data);

    // CRC-32C computation on arbitrary data
    if data.len() >= 8 {
        let _ = vhdx::compute_crc32c(data, 4);
    }
});
