#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise header-based format detection
    let _ = shared::format_detection::detect_format_from_header(data, data.len(), true);
    let _ = shared::format_detection::detect_format_from_header(data, data.len(), false);

    // Exercise VHD footer detection (footer at end of file)
    let _ = shared::format_detection::detect_vhd_footer(data);

    // Exercise ISO detection at standard offset
    if data.len() > shared::format_detection::ISO_MAGIC_BYTE_OFFSET + 5 {
        let _ = shared::format_detection::detect_iso_at_offset(
            data,
            shared::format_detection::ISO_MAGIC_BYTE_OFFSET,
        );
    }
});
