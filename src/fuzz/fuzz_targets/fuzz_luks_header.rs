#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Version detection
    let _ = luks::get_version(data);

    // LUKS v1 header parsing
    if let Some(header) = luks::parse_v1_header(data) {
        let _ = luks::find_active_v1_slot(&header);
        let _ = luks::v1_is_aes_xts(&header);
        let _ = luks::v1_hash_spec(&header);
        let _ = luks::v1_active_slot_count(&header);

        // Key slot region calculation
        for i in 0..8 {
            let _ = luks::v1_key_material_region(&header.slots[i], header.key_bytes);
        }
    }

    // LUKS v2 JSON parsing (independent of v1 header)
    let _ = luks::parse_v2_keyslot(data);
    let _ = luks::parse_v2_digest(data);

    // JSON utility functions
    let _ = luks::find_pattern(data, b"\"type\"");
    let _ = luks::extract_json_string(data, b"\"type\"");
    let _ = luks::extract_json_number(data, b"\"iterations\"");
    let _ = luks::parse_ascii_u64(data);

    // Base64 decode
    if !data.is_empty() {
        let mut output = vec![0u8; data.len()];
        let _ = luks::base64_decode(data, &mut output);
    }
});
