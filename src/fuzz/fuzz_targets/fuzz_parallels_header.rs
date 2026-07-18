#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Header parsing (validates magic, version, tracks, catalog size,
    // ext_off).
    if let Some(header) = parallels::ParallelsHeader::parse(data) {
        // Touch every field so the optimizer can't drop the parse, and
        // assert the invariants ParallelsHeader::parse must have enforced.
        assert_ne!(header.tracks, 0);
        assert!(header.tracks <= parallels::PARALLELS_TRACKS_MAX);
        assert!(header.bat_entries <= parallels::PARALLELS_BAT_ENTRIES_MAX);
        assert_eq!(header.cluster_size, header.tracks as u64 * 512);
        assert!(header.off_multiplier == 1 || header.off_multiplier == header.tracks);
        assert!(header.virtual_size.is_multiple_of(512));

        let _ = header.is_v1;
        let _ = header.inuse;
        let _ = header.data_off;
        let _ = header.is_dirty();
    }
});
