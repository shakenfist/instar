//! Coverage-guided fuzzing for the snapshot-table parsing
//! surface: the qcow2 crate's streaming snapshot parser
//! (`for_each_snapshot_entry` + `snapshot_entry_to_record`) and
//! the snapshot crate's pure table readers
//! (`snapshot_table_byte_len` / `snapshot_table_entry_bounds` /
//! `find_snapshot_in_table`). This is the code that faces
//! untrusted snapshot-table bytes in every list / create /
//! delete / apply invocation.
//!
//! Mock-CallTable archetype (like `fuzz_qcow2_l1l2`): the fuzz
//! input *is* the device. Input layout:
//!
//! ```text
//!   0..512:   device sector 0 (qcow2 header candidate)
//!   512..520: snapshots_offset for the header-independent
//!             variant (LE u64; same window extract_fuzz_offset
//!             reads)
//!   520..524: nb_snapshots for the header-independent variant
//!             (LE u32, clamped to 4096)
//!   524..528: pure-reader window start (LE u32, mod input len)
//!   528..530: pure-reader nb_snapshots (LE u16, clamped 4096)
//!   530:      visitor early-stop count (0 = never stop)
//!   531:      find needle length (clamped to 64)
//!   532..540: find needle source offset (LE u64, mod input len)
//! ```
//!
//! Three drives per input:
//!
//! 1. Sector 0 through the mock device -> `QcowHeader::parse`;
//!    on success, `for_each_snapshot_entry` with the header's
//!    `nb_snapshots` (clamped) / `snapshots_offset`.
//! 2. A header-independent `for_each_snapshot_entry` with
//!    fuzz-derived `nb_snapshots` / `snapshots_offset`, plus a
//!    fuzz-chosen early-stop count (bypasses header validation
//!    to hit the entry parser harder).
//! 3. The pure table readers over a fuzz-selected window of the
//!    raw input, with coherence asserts between
//!    `snapshot_table_byte_len`, `snapshot_table_entry_bounds`
//!    and `find_snapshot_in_table`.
//!
//! Iteration counts are clamped (`nb.min(4096)`) so a claimed
//! 65536-entry table cannot blow the per-exec time budget, and
//! the per-index bounds sweep is capped at the first 64 indices
//! plus the last (the bounds walk is O(index), so a full sweep
//! would be O(nb^2)).
//!
//! Semantic oracle (asserted on success; errors are silently
//! ignored — panic and ASAN are the base oracle):
//!
//! * Visitor entries respect their buffers per the documented
//!   parser contract: id is copied to at most 63 bytes and the
//!   remainder of the 64-byte buffer is zero (null-terminated);
//!   name is copied to at most 255 bytes with the same rule for
//!   its 256-byte buffer. NOTE: the phase plan's literal
//!   `id_len as usize <= entry.id.len()` does NOT hold —
//!   `SnapshotEntry::id_len` stores the raw on-disk u16
//!   (`raw.id_str_size`, up to 65535) while only
//!   `min(id_len, 63)` bytes are copied; the provable contract
//!   is the copy clamp + null sentinel asserted here.
//! * `snapshot_entry_to_record` clamps the wire lens to the
//!   32/256-byte wire buffers, with the documented
//!   `min(entry.*_len, buffer)` and disk_size-substitution
//!   rules.
//! * If `snapshot_table_byte_len` accepts (window, nb): the
//!   length is within the window; every entry's bounds resolve
//!   and lie within the claimed length; index nb errors
//!   `InvalidConfig`; the claimed length equals the end of the
//!   last entry's bounds.
//! * Any `FoundSnapshot` from `find_snapshot_in_table` has an
//!   in-range index and `l1_table_offset` / `l1_size` equal to
//!   the values decoded from the bounds-located raw entry.

#![no_main]
use libfuzzer_sys::fuzz_target;

use snapshot::table::{
    find_snapshot_in_table, snapshot_table_byte_len, snapshot_table_entry_bounds, MatchMode,
};
use snapshot::SnapshotError;

/// Control block starts after the device's first sector.
const CTRL: usize = 512;
/// Minimum input: one device sector + the 32-byte control block.
const MIN_LEN: usize = CTRL + 32;

/// Clamp for both `for_each_snapshot_entry` iteration counts and
/// the pure-reader nb (open question 4 in the phase plan).
const MAX_NB: u32 = 4096;

/// Per-entry semantic checks for the streaming parser's output.
///
/// Contracts from `qcow2::for_each_snapshot_entry` /
/// `SnapshotEntry` doc comments: id is "null-terminated, max 63
/// chars" in a 64-byte buffer, name is "null-terminated, max 255
/// chars" in a 256-byte buffer; the entry starts zeroed and only
/// the clamped prefix is overwritten, so everything past the
/// copied prefix must still be zero.
fn check_entry(entry: &qcow2::SnapshotEntry, header_virtual_size: u64) {
    let id_copy = (entry.id_len as usize).min(63);
    assert!(
        entry.id[id_copy..].iter().all(|&b| b == 0),
        "snapshot parse: id bytes past the copied prefix ({} of {}) must be zero",
        id_copy,
        entry.id_len,
    );
    let name_copy = (entry.name_len as usize).min(255);
    assert!(
        entry.name[name_copy..].iter().all(|&b| b == 0),
        "snapshot parse: name bytes past the copied prefix ({} of {}) must be zero",
        name_copy,
        entry.name_len,
    );

    // Wire-record conversion: lens must respect the 32/256 wire
    // buffers with the documented clamp, and the disk_size
    // substitution rule must hold.
    let rec = qcow2::snapshot_entry_to_record(entry, header_virtual_size);
    assert!(
        rec.id_len as usize <= 32,
        "snapshot parse: wire id_len {} exceeds the 32-byte buffer",
        rec.id_len,
    );
    assert!(
        rec.name_len as usize <= 256,
        "snapshot parse: wire name_len {} exceeds the 256-byte buffer",
        rec.name_len,
    );
    assert_eq!(
        rec.id_len as usize,
        (entry.id_len as usize).min(32),
        "snapshot parse: wire id_len must be the documented clamp",
    );
    assert_eq!(
        rec.name_len as usize,
        (entry.name_len as usize).min(256),
        "snapshot parse: wire name_len must be the documented clamp",
    );
    let expect_disk = if entry.disk_size == 0 {
        header_virtual_size
    } else {
        entry.disk_size
    };
    assert_eq!(
        rec.disk_size, expect_disk,
        "snapshot parse: disk_size substitution rule violated",
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN_LEN {
        return;
    }

    instar_fuzz::set_fuzz_input(data);
    let call_table = instar_fuzz::build_call_table();
    let sector_size = 512usize;
    let input_capacity = instar_fuzz::input_capacity();
    let mut bytes_read = 0u64;
    let mut cache_buf = vec![0u8; shared::MAX_SECTOR_SIZE];

    // ------------------------------------------------------------------
    // Drive 1: header-led streaming parse.
    // ------------------------------------------------------------------
    let mut sector0 = [0u8; 512];
    let read_ok =
        unsafe { (call_table.read_input_sector)(0, 0, sector0.as_mut_ptr(), sector_size) };
    if read_ok {
        if let Some(header) = qcow2::QcowHeader::parse(&sector0) {
            let nb = header.nb_snapshots.min(MAX_NB);
            unsafe {
                let _ = qcow2::for_each_snapshot_entry(
                    &call_table,
                    0,
                    nb,
                    header.snapshots_offset,
                    sector_size,
                    input_capacity,
                    cache_buf.as_mut_ptr(),
                    &mut bytes_read,
                    |entry| {
                        check_entry(entry, header.virtual_size);
                        true
                    },
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Drive 2: header-independent streaming parse with a
    // fuzz-chosen early stop.
    // ------------------------------------------------------------------
    let snaps_off = u64::from_le_bytes(data[CTRL..CTRL + 8].try_into().unwrap());
    let nb2 = u32::from_le_bytes(data[CTRL + 8..CTRL + 12].try_into().unwrap()).min(MAX_NB);
    let stop_after = data[CTRL + 18] as u32;
    let mut seen = 0u32;
    unsafe {
        let _ = qcow2::for_each_snapshot_entry(
            &call_table,
            0,
            nb2,
            snaps_off,
            sector_size,
            input_capacity,
            cache_buf.as_mut_ptr(),
            &mut bytes_read,
            |entry| {
                check_entry(entry, 1 << 30);
                seen += 1;
                // Early-stop exercise: stop after the fuzz-chosen
                // count (0 means never stop early).
                stop_after == 0 || seen < stop_after
            },
        );
    }

    // ------------------------------------------------------------------
    // Drive 3: pure table readers over a fuzz-selected window.
    // ------------------------------------------------------------------
    let win_start =
        u32::from_le_bytes(data[CTRL + 12..CTRL + 16].try_into().unwrap()) as usize % data.len();
    let window = &data[win_start..];
    let nb_pure =
        u16::from_le_bytes(data[CTRL + 16..CTRL + 18].try_into().unwrap()) as u32;
    let nb_pure = nb_pure.min(MAX_NB);
    let needle_len = (data[CTRL + 19] as usize).min(64);
    let needle_off =
        u64::from_le_bytes(data[CTRL + 20..CTRL + 28].try_into().unwrap()) as usize % data.len();
    let needle_end = (needle_off + needle_len).min(data.len());
    let needle = &data[needle_off..needle_end];

    if let Ok(total) = snapshot_table_byte_len(window, nb_pure) {
        // The walk bounds every entry within the table slice, so
        // the total cannot escape the window.
        assert!(
            total <= window.len(),
            "snapshot parse: byte_len {} escapes the {}-byte window",
            total,
            window.len(),
        );

        // Per-index bounds: byte_len succeeding means the same
        // walk succeeds for every prefix, and each entry lies
        // within the claimed length. The bounds walk is O(index),
        // so sweep only the first 64 indices plus the last to
        // keep the per-exec cost O(nb).
        let mut probe_last = 0usize;
        for i in (0..nb_pure.min(64)).chain(nb_pure.checked_sub(1)) {
            let (start, len) = snapshot_table_entry_bounds(window, nb_pure, i)
                .expect("snapshot parse: entry bounds must resolve when byte_len succeeded");
            assert!(
                start + len <= total,
                "snapshot parse: entry {} ({}..{}) escapes the claimed length {}",
                i,
                start,
                start + len,
                total,
            );
            if i == nb_pure - 1 {
                probe_last = start + len;
            }
        }
        if nb_pure > 0 {
            // Coherence: the claimed length is exactly the end of
            // the last entry's bounds.
            assert_eq!(
                probe_last, total,
                "snapshot parse: byte_len {} != end of last entry's bounds {}",
                total, probe_last,
            );
        }
        // Index >= nb errors InvalidConfig per the documented
        // contract.
        assert!(
            matches!(
                snapshot_table_entry_bounds(window, nb_pure, nb_pure),
                Err(SnapshotError::InvalidConfig)
            ),
            "snapshot parse: index == nb must error InvalidConfig",
        );

        // find_snapshot_in_table in both MatchModes: any match
        // must be in range and carry the fields decoded from the
        // bounds-located raw entry (l1_table_offset at +0,
        // l1_size at +8, both big-endian — the read oracle).
        for mode in [MatchMode::IdThenName, MatchMode::NameOnly] {
            if let Ok(Some(found)) =
                find_snapshot_in_table(window, total, nb_pure, needle, mode)
            {
                assert!(
                    found.index < nb_pure,
                    "snapshot parse: found index {} out of range {}",
                    found.index,
                    nb_pure,
                );
                let (start, _len) =
                    snapshot_table_entry_bounds(window, nb_pure, found.index)
                        .expect("snapshot parse: found entry's bounds must resolve");
                let l1_off =
                    u64::from_be_bytes(window[start..start + 8].try_into().unwrap());
                let l1_size =
                    u32::from_be_bytes(window[start + 8..start + 12].try_into().unwrap());
                assert_eq!(
                    found.l1_table_offset, l1_off,
                    "snapshot parse: found l1_table_offset disagrees with the raw entry",
                );
                assert_eq!(
                    found.l1_size, l1_size,
                    "snapshot parse: found l1_size disagrees with the raw entry",
                );
            }
        }
    }
});
