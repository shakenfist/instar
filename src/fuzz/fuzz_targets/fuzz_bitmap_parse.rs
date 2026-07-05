//! Coverage-guided fuzzing for the Phase-1 qcow2 persistent-dirty-
//! bitmap parsers (`src/crates/qcow2/src/bitmap.rs`).
//!
//! The bitmap directory / table / extension bytes are the highest
//! attacker-controlled surface in the whole `bitmap` feature: they are
//! parsed verbatim from a hostile image. Phase 1 wrote every parser
//! panic-free by construction (length-guarded reads,
//! `checked_*`/saturating arithmetic). This target is the adversarial
//! validation that the discipline held — the **only** oracle is
//! panic-freedom (plus a handful of trivially-safe round-trip /
//! consistency asserts).
//!
//! Raw-bytes parser archetype (like `fuzz_qcow2_header`): feed the same
//! `&[u8]` to every pure parser, then drive the streaming enumerator
//! `for_each_bitmap_entry` through the mock CallTable (like
//! `fuzz_qcow2_l1l2`).

#![no_main]
use libfuzzer_sys::fuzz_target;

use qcow2::bitmap::{
    bitmap_bytes_needed, bitmap_table_size_entries, decode_bitmap_table_entry, default_granularity,
    for_each_bitmap_entry, granularity_bits_valid, parse_bitmap_dir_entry, parse_bitmaps_extension,
    serialize_bitmap_dir_entry, validate_bitmap_table_entry,
};

/// Largest possible serialized directory entry: `round_up(24 + 1023, 8)`.
const MAX_DIR_ENTRY: usize = 1048;

fuzz_target!(|data: &[u8]| {
    // ------------------------------------------------------------------
    // 1. Bitmaps header extension.
    // ------------------------------------------------------------------
    let _ = parse_bitmaps_extension(data);

    // ------------------------------------------------------------------
    // 2. A single directory entry, with a serialize -> re-parse round
    //    trip on success (parse guarantees name_size in 1..=1023 and
    //    extra_data == 0, so serialize into a MAX_DIR_ENTRY scratch
    //    always fits and must reproduce an equal entry).
    // ------------------------------------------------------------------
    if let Some((entry, size)) = parse_bitmap_dir_entry(data) {
        let mut scratch = [0u8; MAX_DIR_ENTRY];
        let written = serialize_bitmap_dir_entry(&entry, &mut scratch)
            .expect("a parsed entry must re-serialize into MAX_DIR_ENTRY");
        assert_eq!(written, size, "serialized size disagrees with parsed size");
        let (reparsed, reparsed_size) =
            parse_bitmap_dir_entry(&scratch).expect("round-trip entry must re-parse");
        assert_eq!(reparsed_size, size, "re-parsed size differs");
        assert_eq!(reparsed, entry, "serialize/parse round trip is not identity");
    }

    // ------------------------------------------------------------------
    // 3. Bitmap-table entry decode/validate on the first 8 bytes, plus
    //    a fuzz-derived word. decode() succeeds exactly when validate()
    //    accepts.
    // ------------------------------------------------------------------
    let check_table_word = |raw: u64| {
        let valid = validate_bitmap_table_entry(raw);
        let decoded = decode_bitmap_table_entry(raw);
        assert_eq!(
            valid,
            decoded.is_some(),
            "validate/decode disagree for raw table word {raw:#018x}",
        );
    };
    if data.len() >= 8 {
        check_table_word(u64::from_le_bytes(data[0..8].try_into().unwrap()));
        check_table_word(u64::from_be_bytes(data[0..8].try_into().unwrap()));
    }

    // ------------------------------------------------------------------
    // 4. Geometry helpers with values derived from the bytes. All are
    //    documented panic-free (0-guards + saturating math); exercise
    //    the guards and the extreme inputs.
    // ------------------------------------------------------------------
    if data.len() >= 11 {
        let vsize = u64::from_le_bytes(data[0..8].try_into().unwrap());
        // Shift amounts kept < 64 so `1 << n` is itself well-defined;
        // the helpers guard the resulting values internally.
        let cluster_size = 1u64 << (data[8] % 40);
        let granularity = 1u64 << (data[9] % 40);
        let _ = default_granularity(cluster_size);
        let _ = default_granularity(0);
        let bn = bitmap_bytes_needed(vsize, granularity);
        let _ = bitmap_bytes_needed(vsize, 0);
        let _ = bitmap_bytes_needed(u64::MAX, granularity.max(1));
        let _ = bitmap_table_size_entries(bn, cluster_size);
        let _ = bitmap_table_size_entries(bn, 0);
        let _ = granularity_bits_valid(data[10]);
    }

    // ------------------------------------------------------------------
    // 5. Streaming directory enumerator via the mock CallTable. The
    //    loop is bounded by `nb_bitmaps` (kept small); the reader pulls
    //    from the fuzz input, so entries are parsed out of hostile
    //    bytes exactly as the guest would. Oracle: no panic.
    // ------------------------------------------------------------------
    if data.len() >= 16 {
        instar_fuzz::set_fuzz_input(data);
        let call_table = instar_fuzz::build_call_table();
        let input_capacity = instar_fuzz::input_capacity();
        let sector_size = 512usize;

        let mut cache_buf = vec![0u8; shared::MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;

        // Bounded, fuzz-derived directory parameters. `nb_bitmaps` caps
        // the iteration count; the offset/size point into the fuzz data
        // so real entries get parsed.
        let nb_bitmaps = (data[8] as u32) % 64;
        let dir_offset = (u64::from_le_bytes(data[0..8].try_into().unwrap()))
            % (data.len() as u64 + 1);
        let dir_size = (u64::from_le_bytes(data[8..16].try_into().unwrap()))
            % (data.len() as u64 * 2 + 1);

        unsafe {
            let _ = for_each_bitmap_entry(
                &call_table,
                0,
                nb_bitmaps,
                dir_offset,
                dir_size,
                sector_size,
                input_capacity,
                cache_buf.as_mut_ptr(),
                &mut bytes_read,
                |_entry| true,
            );
        }
    }
});
