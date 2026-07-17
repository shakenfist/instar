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

    // Exercise DMG koly trailer detection. `data` itself stands in for
    // the tail buffer a real caller would read (up to the last 1024
    // bytes of the file); derive a plausible file length from the
    // fuzz input so the window math ([len-1023, len-512]) is fuzzed
    // too, not just a fixed length. Cover both "buffer is the whole
    // file" (len == data.len()) and "buffer is a suffix of a larger
    // file" (len derived from the input bytes themselves) shapes.
    let _ = shared::format_detection::detect_dmg_koly_offset(data, data.len());
    if data.len() >= 8 {
        let len_bytes: [u8; 8] = [
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ];
        // Bias the derived length toward data.len()'s neighbourhood so
        // the buffer/len relationship stays plausible while still
        // exercising both underflow-guard paths and in-window matches.
        let synthetic_len = data.len().wrapping_add(u64::from_le_bytes(len_bytes) as usize % 4096);
        if let Some(koly_offset) =
            shared::format_detection::detect_dmg_koly_offset(data, synthetic_len)
        {
            let _ = shared::format_detection::dmg_sector_count(data, synthetic_len, koly_offset);
        }
        // Also probe with an offset that was not necessarily found by
        // the scan, to exercise dmg_sector_count's own bounds checks
        // independently of detect_dmg_koly_offset's window logic.
        let _ = shared::format_detection::dmg_sector_count(
            data,
            synthetic_len,
            u64::from_le_bytes(len_bytes) as usize,
        );
    }
});
