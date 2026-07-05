//! Public-API exercise of the `bitmap` crate's **pure** merge surface.
//!
//! `merge` OR-s a source bitmap's set bits into a destination bitmap.
//! The *data-cluster orchestration* (reading/OR-ing/allocating data
//! clusters) is Phase-4 guest code that performs I/O and is untestable
//! here (Open question 4) — the bits-set round-trip is a Phase-7
//! integration test. This file therefore covers only the crate's pure,
//! public functions:
//!
//! - [`merge_validate`](bitmap::merge::merge_validate) — the six
//!   validation outcomes, driven off a real staged directory built with
//!   the shared [`Fixture`](common::Fixture) toolkit.
//! - [`merge_cluster_action`](bitmap::merge::merge_cluster_action) — the
//!   full `(source, dest)` truth table, with raw table words built via
//!   [`encode_bitmap_table_entry`], plus the reserved-word reject.
//! - [`or_bitmap_data`](bitmap::merge::or_bitmap_data) — bytewise OR and
//!   the length-mismatch reject.

mod common;

use common::*;

use bitmap::merge::{merge_cluster_action, merge_validate, or_bitmap_data, MergeClusterAction};
use bitmap::BitmapError;
use qcow2::bitmap::{
    decode_bitmap_table_entry, encode_bitmap_table_entry, BitmapTableEntry,
    BME_TABLE_ENTRY_RESERVED_MASK,
};

/// The default granularity used across the suite: `2^16` = 64 KiB/bit.
const GRAN_64K: u8 = 16;
/// An explicit 128 KiB/bit granularity: `2^17`.
const GRAN_128K: u8 = 17;

// ============================================================================
// merge_validate
// ============================================================================

#[test]
fn validate_two_compatible_bitmaps_is_ok() {
    let f = Fixture::with_bitmaps(&[
        (b"dst", GRAN_64K, true, false, METADATA_CLUSTERS),
        (b"src", GRAN_64K, true, false, METADATA_CLUSTERS + 1),
    ]);

    let spec = merge_validate(&f.dir, f.nb_bitmaps, b"dst", b"src", &f.geom).expect("validate");
    assert!(!spec.self_merge);
    assert_eq!(spec.granularity_bits, GRAN_64K);
    assert_eq!(spec.table_size, table_entries_for(&f.geom, GRAN_64K));
    assert_eq!(
        spec.dest.entry.bitmap_table_offset,
        METADATA_CLUSTERS * f.geom.cluster_size
    );
    assert_eq!(
        spec.source.entry.bitmap_table_offset,
        (METADATA_CLUSTERS + 1) * f.geom.cluster_size
    );
}

#[test]
fn validate_missing_dest_is_not_found() {
    let f = Fixture::with_bitmaps(&[(b"src", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    assert_eq!(
        merge_validate(&f.dir, f.nb_bitmaps, b"dst", b"src", &f.geom),
        Err(BitmapError::BitmapNotFound)
    );
}

#[test]
fn validate_missing_source_is_merge_source_not_found() {
    let f = Fixture::with_bitmaps(&[(b"dst", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    assert_eq!(
        merge_validate(&f.dir, f.nb_bitmaps, b"dst", b"src", &f.geom),
        Err(BitmapError::MergeSourceNotFound)
    );
}

#[test]
fn validate_in_use_dest_is_refused() {
    let f = Fixture::with_bitmaps(&[
        (b"dst", GRAN_64K, false, true, METADATA_CLUSTERS),
        (b"src", GRAN_64K, true, false, METADATA_CLUSTERS + 1),
    ]);
    assert_eq!(
        merge_validate(&f.dir, f.nb_bitmaps, b"dst", b"src", &f.geom),
        Err(BitmapError::BitmapInUse)
    );
}

#[test]
fn validate_in_use_source_is_refused() {
    let f = Fixture::with_bitmaps(&[
        (b"dst", GRAN_64K, true, false, METADATA_CLUSTERS),
        (b"src", GRAN_64K, false, true, METADATA_CLUSTERS + 1),
    ]);
    assert_eq!(
        merge_validate(&f.dir, f.nb_bitmaps, b"dst", b"src", &f.geom),
        Err(BitmapError::BitmapInUse)
    );
}

#[test]
fn validate_granularity_mismatch_is_incompatible() {
    let f = Fixture::with_bitmaps(&[
        (b"dst", GRAN_64K, true, false, METADATA_CLUSTERS),
        (b"src", GRAN_128K, true, false, METADATA_CLUSTERS + 1),
    ]);
    assert_eq!(
        merge_validate(&f.dir, f.nb_bitmaps, b"dst", b"src", &f.geom),
        Err(BitmapError::IncompatibleMerge)
    );
}

#[test]
fn validate_self_merge_is_ok_and_flagged() {
    let f = Fixture::with_bitmaps(&[(b"same", GRAN_64K, true, false, METADATA_CLUSTERS)]);
    let spec = merge_validate(&f.dir, f.nb_bitmaps, b"same", b"same", &f.geom).expect("validate");
    assert!(spec.self_merge);
    assert_eq!(
        spec.dest.entry.bitmap_table_offset,
        spec.source.entry.bitmap_table_offset
    );
}

// ============================================================================
// merge_cluster_action truth table
// ============================================================================

/// Raw table word for an all-zeroes entry.
fn zeroes() -> u64 {
    encode_bitmap_table_entry(&BitmapTableEntry::AllZeroes)
}
/// Raw table word for an all-ones entry.
fn ones() -> u64 {
    encode_bitmap_table_entry(&BitmapTableEntry::AllOnes)
}
/// Raw table word for an allocated entry at `off`.
fn alloc(off: u64) -> u64 {
    encode_bitmap_table_entry(&BitmapTableEntry::Allocated(off))
}

#[test]
fn cluster_action_full_truth_table() {
    use MergeClusterAction::*;
    let src_off = 0x20000u64;
    let dst_off = 0x30000u64;

    // Sanity: the raw words we build round-trip through the decoder to
    // the states we intend (so the truth-table rows are meaningful).
    assert_eq!(
        decode_bitmap_table_entry(zeroes()),
        Some(BitmapTableEntry::AllZeroes)
    );
    assert_eq!(
        decode_bitmap_table_entry(ones()),
        Some(BitmapTableEntry::AllOnes)
    );
    assert_eq!(
        decode_bitmap_table_entry(alloc(src_off)),
        Some(BitmapTableEntry::Allocated(src_off))
    );

    // source AllZeroes -> always Skip (contributes no set bits).
    assert_eq!(merge_cluster_action(zeroes(), zeroes()).unwrap(), Skip);
    assert_eq!(merge_cluster_action(zeroes(), ones()).unwrap(), Skip);
    assert_eq!(
        merge_cluster_action(zeroes(), alloc(dst_off)).unwrap(),
        Skip
    );

    // dest AllOnes -> always Skip (already fully set).
    assert_eq!(merge_cluster_action(ones(), ones()).unwrap(), Skip);
    assert_eq!(merge_cluster_action(alloc(src_off), ones()).unwrap(), Skip);

    // source AllOnes into a non-all-ones dest -> CopyAllOnes.
    assert_eq!(merge_cluster_action(ones(), zeroes()).unwrap(), CopyAllOnes);
    assert_eq!(
        merge_cluster_action(ones(), alloc(dst_off)).unwrap(),
        CopyAllOnes
    );

    // source Allocated into all-zeroes dest -> AllocDestFromSource.
    assert_eq!(
        merge_cluster_action(alloc(src_off), zeroes()).unwrap(),
        AllocDestFromSource
    );

    // both Allocated -> OrIntoExisting.
    assert_eq!(
        merge_cluster_action(alloc(src_off), alloc(dst_off)).unwrap(),
        OrIntoExisting
    );
}

#[test]
fn cluster_action_rejects_reserved_word() {
    // A word with reserved bits set is not a valid table entry.
    let bad = BME_TABLE_ENTRY_RESERVED_MASK & 0xff00_0000_0000_0000;
    assert_ne!(bad, 0);
    assert!(decode_bitmap_table_entry(bad).is_none());

    // Rejected in either the source or the destination position.
    assert_eq!(
        merge_cluster_action(bad, zeroes()),
        Err(BitmapError::ParseFailed)
    );
    assert_eq!(
        merge_cluster_action(zeroes(), bad),
        Err(BitmapError::ParseFailed)
    );
}

// ============================================================================
// or_bitmap_data
// ============================================================================

#[test]
fn or_data_disjoint_and_overlapping() {
    // Disjoint bits: the OR is the union.
    let mut dst = [0b0000_1111u8, 0b1010_1010, 0x00];
    let src = [0b1111_0000u8, 0b0101_0101, 0xFF];
    or_bitmap_data(&mut dst, &src).expect("or");
    assert_eq!(dst, [0xFF, 0xFF, 0xFF]);

    // Overlapping bits: shared bits stay set, extras are added, and a
    // second OR is idempotent.
    let mut dst = [0b1100_0011u8, 0x0F];
    let src = [0b1010_0001u8, 0xF0];
    or_bitmap_data(&mut dst, &src).expect("or");
    assert_eq!(dst, [0b1110_0011, 0xFF]);
    let snapshot = dst;
    or_bitmap_data(&mut dst, &src).expect("or again");
    assert_eq!(dst, snapshot, "OR must be idempotent");
}

#[test]
fn or_data_length_mismatch_is_internal_overflow() {
    // Shorter src.
    let mut dst = [0u8; 4];
    let src = [0xFFu8; 3];
    assert_eq!(
        or_bitmap_data(&mut dst, &src),
        Err(BitmapError::InternalOverflow)
    );
    assert_eq!(dst, [0u8; 4], "no partial OR on a length mismatch");

    // Longer src.
    let mut dst = [0u8; 2];
    let src = [0xFFu8; 3];
    assert_eq!(
        or_bitmap_data(&mut dst, &src),
        Err(BitmapError::InternalOverflow)
    );
    assert_eq!(dst, [0u8; 2]);
}
