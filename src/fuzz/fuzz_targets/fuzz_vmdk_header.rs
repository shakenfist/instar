#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Basic header (44 bytes)
    let _ = vmdk::Vmdk4Header::parse(data);

    // Full header with grain directory fields (79+ bytes)
    if let Some(full) = vmdk::Vmdk4HeaderFull::parse(data) {
        let _ = full.num_gd_entries();
    }

    // Text descriptor parsing (handles key=value pairs, extent lines)
    let mut vmdk_info = shared::VmdkInfo::default();
    vmdk::parse_descriptor(data, data.len(), &mut vmdk_info);

    // Hex value parsing (used for CID fields in descriptors)
    let _ = vmdk::parse_hex_value(data);
});
