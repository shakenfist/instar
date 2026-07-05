//! Single-action, public-API round-trips for the `bitmap` crate.
//!
//! Each test builds a [`Fixture`](common::Fixture) (directory +
//! refcount-block buffers + geometry), applies exactly one action
//! through the crate's public `action_*` surface (via the `apply_*`
//! helpers), re-parses the resulting directory, and asserts the
//! directory *and* refcount effects. Refcount deltas are asserted
//! precisely; error / no-op cases snapshot the refblocks before the
//! action and assert they are byte-identical afterwards.
//!
//! These validate the crate through its **public** surface (the
//! `tests/` crate sees only `pub` items) and pin named round-trips —
//! notably the empty-bitmap representation — that the inline unit
//! tests exercise only against private helpers.

mod common;

use bitmap::BitmapError;
use common::*;

/// The default granularity used across the suite: `2^16` = 64 KiB/bit.
const GRAN_64K: u8 = 16;
/// An explicit 128 KiB/bit granularity: `2^17`.
const GRAN_128K: u8 = 17;

// ============================================================================
// add
// ============================================================================

#[test]
fn add_to_empty_fixture() {
    let mut f = Fixture::empty();
    let mut cursor = fresh_cursor();

    let outcome = apply_add(&mut f, &mut cursor, b"backup", GRAN_64K).expect("add");

    // Directory now holds exactly one enabled entry with the right
    // name and granularity.
    assert_eq!(outcome.new_nb_bitmaps, 1);
    let entries = parse_entries(&f.dir, f.nb_bitmaps);
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.name, b"backup");
    assert_eq!(e.granularity_bits, GRAN_64K);
    assert!(e.enabled);
    assert!(!e.in_use);

    // Empty-bitmap representation: exactly `num_table_clusters_to_zero`
    // table clusters allocated, and NO data clusters (the crate does
    // not allocate data on add — the table is all-zero).
    let expected_clusters = table_cluster_count(e.table_size, f.geom.cluster_size);
    assert_eq!(outcome.num_table_clusters_to_zero as u64, expected_clusters);
    // First free cluster after the metadata prefix is METADATA_CLUSTERS.
    let table_offset = METADATA_CLUSTERS * f.geom.cluster_size;
    assert_eq!(e.table_offset, table_offset);
    assert_eq!(outcome.table_clusters_to_zero[0], table_offset);

    // The allocated table cluster is now refcount 1; the next cluster
    // (a would-be data cluster) is untouched at 0.
    assert_eq!(refcount_at(&f.refblocks, &f.geom, table_offset), 1);
    assert_eq!(
        refcount_at(&f.refblocks, &f.geom, table_offset + f.geom.cluster_size),
        0
    );

    // add never signals a table-walk / zero-table to the guest.
    assert_eq!(outcome.freed_table_offset, 0);
    assert!(!outcome.zero_freed_table);
    assert!(outcome.extension_now_present);
}

#[test]
fn add_with_explicit_granularity() {
    let mut f = Fixture::empty();
    let mut cursor = fresh_cursor();

    apply_add(&mut f, &mut cursor, b"fine", GRAN_128K).expect("add");

    let entries = parse_entries(&f.dir, f.nb_bitmaps);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].granularity_bits, GRAN_128K);
}

#[test]
fn add_duplicate_name_is_bitmap_exists_no_mutation() {
    let mut f = Fixture::with_bitmaps(&[(b"dup", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    let before = f.refblocks.clone();
    let before_dir = f.dir.clone();
    let mut cursor = fresh_cursor();

    assert_eq!(
        apply_add(&mut f, &mut cursor, b"dup", GRAN_64K),
        Err(BitmapError::BitmapExists)
    );
    // Refblocks and directory untouched (validate-before-mutate).
    assert_eq!(f.refblocks, before);
    assert_eq!(f.dir, before_dir);
    assert_eq!(cursor, fresh_cursor());
}

#[test]
fn add_out_of_range_granularity_is_granularity_range_no_mutation() {
    for bad in [8u8, 32u8] {
        let mut f = Fixture::empty();
        let before = f.refblocks.clone();
        let mut cursor = fresh_cursor();
        assert_eq!(
            apply_add(&mut f, &mut cursor, b"n", bad),
            Err(BitmapError::GranularityRange)
        );
        assert_eq!(f.refblocks, before);
        assert!(f.dir.is_empty());
        assert_eq!(f.nb_bitmaps, 0);
    }
}

// ============================================================================
// remove
// ============================================================================

#[test]
fn remove_existing_frees_table_and_compacts() {
    let mut f = Fixture::with_bitmaps(&[(b"gone", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    let table_offset = METADATA_CLUSTERS * f.geom.cluster_size;
    assert_eq!(refcount_at(&f.refblocks, &f.geom, table_offset), 1);

    let outcome = apply_remove(&mut f, b"gone").expect("remove");

    // Entry gone, count decremented.
    assert_eq!(outcome.new_nb_bitmaps, 0);
    assert_eq!(f.nb_bitmaps, 0);
    assert!(parse_entries(&f.dir, f.nb_bitmaps).is_empty());

    // The removed bitmap's table cluster is now free.
    assert_eq!(refcount_at(&f.refblocks, &f.geom, table_offset), 0);

    // The guest is told where the on-disk table is so it can walk and
    // free the data clusters this crate cannot see.
    assert_eq!(outcome.freed_table_offset, table_offset);
    assert_eq!(
        outcome.freed_table_size,
        table_entries_for(&f.geom, GRAN_64K)
    );
    assert!(!outcome.zero_freed_table);

    // Removing the last bitmap drops the extension.
    assert!(!outcome.extension_now_present);
}

#[test]
fn remove_one_of_two_keeps_sibling() {
    let mut f = Fixture::with_bitmaps(&[
        (b"keep", GRAN_64K, true, false, METADATA_CLUSTERS),
        (b"drop", GRAN_64K, true, false, METADATA_CLUSTERS + 1),
    ]);
    let keep_off = METADATA_CLUSTERS * f.geom.cluster_size;
    let drop_off = (METADATA_CLUSTERS + 1) * f.geom.cluster_size;

    let outcome = apply_remove(&mut f, b"drop").expect("remove");

    assert_eq!(outcome.new_nb_bitmaps, 1);
    assert!(outcome.extension_now_present);
    // Only "keep" remains; its table cluster is intact, "drop"'s freed.
    let entries = parse_entries(&f.dir, f.nb_bitmaps);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"keep");
    assert_eq!(refcount_at(&f.refblocks, &f.geom, keep_off), 1);
    assert_eq!(refcount_at(&f.refblocks, &f.geom, drop_off), 0);
}

#[test]
fn remove_missing_is_not_found_no_mutation() {
    let mut f = Fixture::with_bitmaps(&[(b"present", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    let before = f.refblocks.clone();
    let before_dir = f.dir.clone();

    assert_eq!(
        apply_remove(&mut f, b"absent"),
        Err(BitmapError::BitmapNotFound)
    );
    assert_eq!(f.refblocks, before);
    assert_eq!(f.dir, before_dir);
    assert_eq!(f.nb_bitmaps, 1);
}

// ============================================================================
// clear
// ============================================================================

#[test]
fn clear_existing_keeps_entry_and_signals_guest() {
    let mut f = Fixture::with_bitmaps(&[(b"c", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    let before_dir = f.dir.clone();
    let before_rb = f.refblocks.clone();
    let before = parse_entries(&f.dir, f.nb_bitmaps);
    let table_offset = METADATA_CLUSTERS * f.geom.cluster_size;

    let outcome = apply_clear(&mut f, b"c").expect("clear");

    // Directory entry is byte-identical (name/granularity/flags/table
    // pointer all unchanged), count unchanged.
    assert_eq!(f.dir, before_dir);
    assert_eq!(outcome.new_nb_bitmaps, 1);
    assert_eq!(parse_entries(&f.dir, f.nb_bitmaps), before);

    // The guest is asked to free the data clusters and zero the table
    // (leaving it allocated) — clear touches no refcounts here.
    assert!(outcome.zero_freed_table);
    assert_eq!(outcome.freed_table_offset, table_offset);
    assert_eq!(
        outcome.freed_table_size,
        table_entries_for(&f.geom, GRAN_64K)
    );
    assert_eq!(f.refblocks, before_rb);
    assert_eq!(refcount_at(&f.refblocks, &f.geom, table_offset), 1);
    assert!(outcome.extension_now_present);
}

#[test]
fn clear_missing_is_not_found() {
    let mut f = Fixture::with_bitmaps(&[(b"c", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    let before = f.refblocks.clone();
    assert_eq!(
        apply_clear(&mut f, b"nope"),
        Err(BitmapError::BitmapNotFound)
    );
    assert_eq!(f.refblocks, before);
}

#[test]
fn clear_in_use_is_refused_no_mutation() {
    let mut f = Fixture::with_bitmaps(&[(b"c", GRAN_64K, false, true, METADATA_CLUSTERS)]);
    let before = f.refblocks.clone();
    let before_dir = f.dir.clone();
    assert_eq!(apply_clear(&mut f, b"c"), Err(BitmapError::BitmapInUse));
    assert_eq!(f.refblocks, before);
    assert_eq!(f.dir, before_dir);
}

// ============================================================================
// enable / disable
// ============================================================================

#[test]
fn enable_disabled_flips_only_auto_flag() {
    let mut f = Fixture::with_bitmaps(&[(b"a", GRAN_64K, false, false, METADATA_CLUSTERS)]);
    let mut before = parse_entries(&f.dir, f.nb_bitmaps);
    assert!(!before[0].enabled);

    let outcome = apply_enable(&mut f, b"a").expect("enable");
    assert_eq!(outcome.new_nb_bitmaps, 1);

    let after = parse_entries(&f.dir, f.nb_bitmaps);
    // Everything identical except the enabled flag, which is now set.
    before[0].enabled = true;
    assert_eq!(after, before);
}

#[test]
fn disable_enabled_flips_only_auto_flag() {
    let mut f = Fixture::with_bitmaps(&[(b"a", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    let mut before = parse_entries(&f.dir, f.nb_bitmaps);
    assert!(before[0].enabled);

    apply_disable(&mut f, b"a").expect("disable");

    let after = parse_entries(&f.dir, f.nb_bitmaps);
    before[0].enabled = false;
    assert_eq!(after, before);
}

#[test]
fn enable_already_enabled_is_idempotent() {
    let mut f = Fixture::with_bitmaps(&[(b"a", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    let before = parse_entries(&f.dir, f.nb_bitmaps);
    apply_enable(&mut f, b"a").expect("enable");
    // Still enabled, entry otherwise identical.
    assert_eq!(parse_entries(&f.dir, f.nb_bitmaps), before);
    assert!(parse_entries(&f.dir, f.nb_bitmaps)[0].enabled);
}

#[test]
fn enable_disable_missing_is_not_found() {
    let mut f = Fixture::with_bitmaps(&[(b"a", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    assert_eq!(
        apply_enable(&mut f, b"nope"),
        Err(BitmapError::BitmapNotFound)
    );
    assert_eq!(
        apply_disable(&mut f, b"nope"),
        Err(BitmapError::BitmapNotFound)
    );
}

#[test]
fn enable_disable_in_use_is_refused() {
    let mut f = Fixture::with_bitmaps(&[(b"a", GRAN_64K, false, true, METADATA_CLUSTERS)]);
    let before_dir = f.dir.clone();
    assert_eq!(apply_enable(&mut f, b"a"), Err(BitmapError::BitmapInUse));
    assert_eq!(apply_disable(&mut f, b"a"), Err(BitmapError::BitmapInUse));
    assert_eq!(f.dir, before_dir);
}
