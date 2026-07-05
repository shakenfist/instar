//! Multi-action, public-API sequences for the `bitmap` crate.
//!
//! Where [`round_trip`](../round_trip.rs) pins single actions, this
//! suite drives the guest's *ordered action list* through the public
//! `apply_*` helpers (the double-buffered directory the Phase-4 guest
//! stages), asserting the running directory state **and** a
//! refcount-conservation check after every step (Open question 3).
//!
//! # Refcount-conservation approach
//!
//! The crate cannot observe the whole qcow2 structure (that is
//! `qemu-img check`, Phase 7), but it *can* observe the staged refcount
//! blocks. So after each step we snapshot the refblocks, apply one
//! action, and assert — via [`assert_refblocks_delta`] — that **only**
//! the clusters we expect changed refcount (to the expected values) and
//! **every other cluster is byte-for-byte unchanged**. Steps that must
//! not touch refcounts at all (`enable`/`disable`, `clear` of an empty
//! bitmap) assert the before/after refblock buffers are byte-identical.
//! A whole sequence's net delta is the sum of its per-step deltas: the
//! empty→empty round-trip (add then remove) additionally asserts the
//! final refblocks equal the very-first snapshot.

mod common;

use bitmap::action::BitmapGeometry;
use common::*;

/// The default granularity used across the suite: `2^16` = 64 KiB/bit.
const GRAN_64K: u8 = 16;

/// How many leading clusters [`assert_refblocks_delta`] scans when
/// diffing two refblock snapshots. The toy layout occupies clusters
/// `0..METADATA_CLUSTERS` (8) and hands out table clusters just above
/// that, so 64 clusters covers every cluster any sequence here touches
/// with generous headroom.
const SCAN_CLUSTERS: u64 = 64;

/// Assert that exactly the clusters in `expected_changes` changed
/// refcount between the `before` and `after` refblock snapshots, each to
/// its listed new refcount, and that **no other** cluster in the scanned
/// range changed.
///
/// `expected_changes` is a list of `(host_offset, new_refcount)`. This
/// is the crate-observable slice of the refcount-conservation invariant:
/// after an action, only the clusters that action allocates or frees may
/// change, and they must land on the expected values.
fn assert_refblocks_delta(
    before: &[u8],
    after: &[u8],
    expected_changes: &[(u64, u64)],
    geom: &BitmapGeometry,
) {
    let mut matched = 0usize;
    for cluster in 0..SCAN_CLUSTERS {
        let host = geom.host_refblocks_start + cluster * geom.cluster_size;
        let b = refcount_at(before, geom, host);
        let a = refcount_at(after, geom, host);
        match expected_changes.iter().find(|&&(off, _)| off == host) {
            Some(&(_, want)) => {
                assert_eq!(
                    a, want,
                    "cluster at host {host:#x} should have refcount {want}, got {a}"
                );
                assert_ne!(
                    b, a,
                    "cluster at host {host:#x} was listed as changed but did not change (still {b})"
                );
                matched += 1;
            }
            None => {
                assert_eq!(
                    a, b,
                    "unlisted cluster at host {host:#x} changed refcount {b} -> {a}"
                );
            }
        }
    }
    assert_eq!(
        matched,
        expected_changes.len(),
        "some expected changes fell outside the scanned cluster range"
    );
}

/// The host offset of the `n`-th toy cluster.
fn cluster_off(n: u64) -> u64 {
    n * CLUSTER_SIZE
}

// ============================================================================
// 1. add(a) -> disable(a)
// ============================================================================

#[test]
fn add_then_disable_keeps_disabled_entry_and_table() {
    let mut f = Fixture::empty();
    let mut cursor = fresh_cursor();
    let a_tbl = cluster_off(METADATA_CLUSTERS);

    // add(a): the sole table cluster (the first free one) goes 0 -> 1.
    let before = f.refblocks.clone();
    apply_add(&mut f, &mut cursor, b"a", GRAN_64K).expect("add a");
    assert_refblocks_delta(&before, &f.refblocks, &[(a_tbl, 1)], &f.geom);
    let entries = parse_entries(&f.dir, f.nb_bitmaps);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"a");
    assert!(entries[0].enabled);
    assert_eq!(entries[0].table_offset, a_tbl);

    // disable(a): a pure AUTO flag flip — no refcount change at all.
    let before = f.refblocks.clone();
    apply_disable(&mut f, b"a").expect("disable a");
    assert_eq!(f.refblocks, before, "disable must not touch the refblocks");
    assert_refblocks_delta(&before, &f.refblocks, &[], &f.geom);

    // Final: one entry 'a', now disabled, its table cluster still 1.
    assert_eq!(f.nb_bitmaps, 1);
    let entries = parse_entries(&f.dir, f.nb_bitmaps);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"a");
    assert!(!entries[0].enabled);
    assert_eq!(refcount_at(&f.refblocks, &f.geom, a_tbl), 1);
}

// ============================================================================
// 2. add(a) -> add(b) -> remove(a)
// ============================================================================

#[test]
fn add_a_add_b_remove_a_leaves_only_b() {
    let mut f = Fixture::empty();
    let mut cursor = fresh_cursor();
    let a_tbl = cluster_off(METADATA_CLUSTERS);
    let b_tbl = cluster_off(METADATA_CLUSTERS + 1);

    // add(a): a's table cluster 0 -> 1.
    let before = f.refblocks.clone();
    apply_add(&mut f, &mut cursor, b"a", GRAN_64K).expect("add a");
    assert_refblocks_delta(&before, &f.refblocks, &[(a_tbl, 1)], &f.geom);
    assert_eq!(f.nb_bitmaps, 1);

    // add(b): the cursor advances, so b's table cluster is the next free
    // one; b's table cluster 0 -> 1.
    let before = f.refblocks.clone();
    apply_add(&mut f, &mut cursor, b"b", GRAN_64K).expect("add b");
    assert_refblocks_delta(&before, &f.refblocks, &[(b_tbl, 1)], &f.geom);
    assert_eq!(f.nb_bitmaps, 2);
    let entries = parse_entries(&f.dir, f.nb_bitmaps);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, b"a");
    assert_eq!(entries[1].name, b"b");

    // remove(a): a's table cluster 1 -> 0; b's untouched.
    let before = f.refblocks.clone();
    let outcome = apply_remove(&mut f, b"a").expect("remove a");
    assert_refblocks_delta(&before, &f.refblocks, &[(a_tbl, 0)], &f.geom);
    assert_eq!(outcome.freed_table_offset, a_tbl);

    // Final: only 'b', still enabled; a's cluster freed, b's still 1.
    assert_eq!(f.nb_bitmaps, 1);
    let entries = parse_entries(&f.dir, f.nb_bitmaps);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"b");
    assert!(entries[0].enabled);
    assert_eq!(refcount_at(&f.refblocks, &f.geom, a_tbl), 0);
    assert_eq!(refcount_at(&f.refblocks, &f.geom, b_tbl), 1);
}

// ============================================================================
// 3. add(a) -> clear(a)
// ============================================================================

#[test]
fn add_then_clear_keeps_entry_and_frees_no_refcounts() {
    let mut f = Fixture::empty();
    let mut cursor = fresh_cursor();
    let a_tbl = cluster_off(METADATA_CLUSTERS);

    let before = f.refblocks.clone();
    apply_add(&mut f, &mut cursor, b"a", GRAN_64K).expect("add a");
    assert_refblocks_delta(&before, &f.refblocks, &[(a_tbl, 1)], &f.geom);
    let after_add = parse_entries(&f.dir, f.nb_bitmaps);

    // clear(a): the crate frees the (guest-owned) data clusters and asks
    // the guest to zero the table; a freshly-added bitmap has no data
    // clusters, so the refblocks are untouched here.
    let before = f.refblocks.clone();
    let outcome = apply_clear(&mut f, b"a").expect("clear a");
    assert_eq!(f.refblocks, before, "clear must not touch the refblocks");
    assert_refblocks_delta(&before, &f.refblocks, &[], &f.geom);
    assert!(outcome.zero_freed_table);
    assert_eq!(outcome.freed_table_offset, a_tbl);

    // Final: 'a' present and unchanged in the directory; nb == 1; its
    // table cluster still allocated (refcount 1).
    assert_eq!(f.nb_bitmaps, 1);
    assert_eq!(parse_entries(&f.dir, f.nb_bitmaps), after_add);
    assert_eq!(refcount_at(&f.refblocks, &f.geom, a_tbl), 1);
}

// ============================================================================
// 4. enable -> disable -> enable (pre-existing bitmap; flags only)
// ============================================================================

#[test]
fn enable_disable_enable_toggles_only_the_flag() {
    // Start from a pre-existing, disabled bitmap.
    let mut f = Fixture::with_bitmaps(&[(b"a", GRAN_64K, false, false, METADATA_CLUSTERS)]);
    let a_tbl = cluster_off(METADATA_CLUSTERS);
    assert!(!parse_entries(&f.dir, f.nb_bitmaps)[0].enabled);

    // Each step flips only the AUTO flag; none touches the refblocks.
    for (step, enable) in [("enable", true), ("disable", false), ("enable", true)] {
        let before = f.refblocks.clone();
        if enable {
            apply_enable(&mut f, b"a").expect(step);
        } else {
            apply_disable(&mut f, b"a").expect(step);
        }
        assert_eq!(f.refblocks, before, "{step} must not touch the refblocks");
        assert_refblocks_delta(&before, &f.refblocks, &[], &f.geom);
        assert_eq!(parse_entries(&f.dir, f.nb_bitmaps)[0].enabled, enable);
    }

    // Final: enabled, table cluster still allocated, count unchanged.
    assert_eq!(f.nb_bitmaps, 1);
    assert!(parse_entries(&f.dir, f.nb_bitmaps)[0].enabled);
    assert_eq!(refcount_at(&f.refblocks, &f.geom, a_tbl), 1);
}

// ============================================================================
// 5. add(a) -> add(b) -> disable(a) -> remove(b)
// ============================================================================

#[test]
fn add_a_add_b_disable_a_remove_b() {
    let mut f = Fixture::empty();
    let mut cursor = fresh_cursor();
    let a_tbl = cluster_off(METADATA_CLUSTERS);
    let b_tbl = cluster_off(METADATA_CLUSTERS + 1);

    // add(a): a's table cluster 0 -> 1.
    let before = f.refblocks.clone();
    apply_add(&mut f, &mut cursor, b"a", GRAN_64K).expect("add a");
    assert_refblocks_delta(&before, &f.refblocks, &[(a_tbl, 1)], &f.geom);

    // add(b): b's table cluster 0 -> 1.
    let before = f.refblocks.clone();
    apply_add(&mut f, &mut cursor, b"b", GRAN_64K).expect("add b");
    assert_refblocks_delta(&before, &f.refblocks, &[(b_tbl, 1)], &f.geom);
    assert_eq!(f.nb_bitmaps, 2);

    // disable(a): flag flip only, no refcount change.
    let before = f.refblocks.clone();
    apply_disable(&mut f, b"a").expect("disable a");
    assert_eq!(f.refblocks, before, "disable must not touch the refblocks");
    assert_refblocks_delta(&before, &f.refblocks, &[], &f.geom);
    let entries = parse_entries(&f.dir, f.nb_bitmaps);
    assert!(!entries[0].enabled); // a disabled
    assert!(entries[1].enabled); // b still enabled

    // remove(b): b's table cluster 1 -> 0; a's untouched.
    let before = f.refblocks.clone();
    apply_remove(&mut f, b"b").expect("remove b");
    assert_refblocks_delta(&before, &f.refblocks, &[(b_tbl, 0)], &f.geom);

    // Final: 'a' present and disabled; b removed; a's cluster still 1.
    assert_eq!(f.nb_bitmaps, 1);
    let entries = parse_entries(&f.dir, f.nb_bitmaps);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"a");
    assert!(!entries[0].enabled);
    assert_eq!(refcount_at(&f.refblocks, &f.geom, a_tbl), 1);
    assert_eq!(refcount_at(&f.refblocks, &f.geom, b_tbl), 0);
}

// ============================================================================
// 6. add(a) -> remove(a): empty -> empty (net-zero refcount)
// ============================================================================

#[test]
fn add_then_remove_returns_to_empty_with_net_zero_refcount() {
    let mut f = Fixture::empty();
    let mut cursor = fresh_cursor();
    let a_tbl = cluster_off(METADATA_CLUSTERS);

    // Snapshot the pristine (no-bitmaps) refblocks to compare against at
    // the very end: the whole sequence must net to zero refcount change.
    let start = f.refblocks.clone();

    // add(a): a's table cluster 0 -> 1.
    apply_add(&mut f, &mut cursor, b"a", GRAN_64K).expect("add a");
    assert_refblocks_delta(&start, &f.refblocks, &[(a_tbl, 1)], &f.geom);
    assert_eq!(f.nb_bitmaps, 1);

    // remove(a): a's table cluster 1 -> 0.
    let before = f.refblocks.clone();
    let outcome = apply_remove(&mut f, b"a").expect("remove a");
    assert_refblocks_delta(&before, &f.refblocks, &[(a_tbl, 0)], &f.geom);

    // Final: back to an empty image. Directory empty, extension dropped,
    // and the refblocks are byte-identical to the pristine snapshot
    // (allocate-then-free nets to zero).
    assert_eq!(f.nb_bitmaps, 0);
    assert!(parse_entries(&f.dir, f.nb_bitmaps).is_empty());
    assert!(!outcome.extension_now_present);
    assert_eq!(
        f.refblocks, start,
        "add-then-remove must net to zero refcount change"
    );
    assert_eq!(refcount_at(&f.refblocks, &f.geom, a_tbl), 0);
}
