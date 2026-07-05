//! Same-image `merge`: the pure, testable crate-side pieces.
//!
//! `merge` OR-s a *source* bitmap's set bits into a *destination*
//! bitmap. Doing so requires READING the on-disk bitmap **data**
//! clusters of both bitmaps and WRITING the destination's data
//! clusters — I/O this pure `no_std` crate cannot perform. So, exactly
//! like the `remove`/`clear` data-cluster split in
//! [`crate::action`], the work is split across the crate/guest
//! boundary:
//!
//! - **This crate** owns the pure logic: validating the two bitmaps
//!   ([`merge_validate`]), deciding what to do for each source
//!   bitmap-table entry given the matching destination entry
//!   ([`merge_cluster_action`]), and OR-ing one data cluster into
//!   another ([`or_bitmap_data`]).
//! - **The Phase-4 guest** owns the orchestration: walking the two
//!   on-disk bitmap tables, reading/writing the data clusters,
//!   allocating destination data clusters, rewriting the destination
//!   bitmap table + refcounts, and re-serializing the directory. None
//!   of that lives here.
//!
//! See the "3d design decisions" note in
//! `docs/plans/PLAN-bitmap-phase-03-planner.md` for the crate/guest
//! contract and the [`MergeClusterAction`] truth table.
//!
//! # Same-image only (Open question 5)
//!
//! v1 merges a source and destination that live in the **same** qcow2
//! image (they therefore share `virtual_size` and cluster geometry).
//! Cross-file `-b` merge is deferred (the ABI has no source-file
//! field; Phase 5 rejects `-b` with `ERROR_UNSUPPORTED_ACTION`).

use crate::directory::{find_bitmap, FoundBitmap};
use crate::BitmapError;
use qcow2::bitmap::{decode_bitmap_table_entry, BitmapTableEntry};

use crate::action::BitmapGeometry;

/// The validated inputs a same-image `merge` needs, computed purely
/// from the two directory entries.
///
/// Both bitmaps have been located, are consistent (`in_use` clear),
/// and have equal geometry (equal `granularity_bits` ⇒ equal
/// bit-count ⇒ equal `bitmap_table_size`, since both are in the same
/// image with the same `virtual_size`). The guest uses the two
/// [`FoundBitmap`]s' on-disk table offsets/sizes to walk both tables,
/// pairing entry `i` of the source with entry `i` of the destination.
///
/// Small and `Copy`; carries no heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeSpec {
    /// The destination bitmap (the one that gains bits).
    pub dest: FoundBitmap,
    /// The source bitmap (read-only for the merge).
    pub source: FoundBitmap,
    /// The (equal) bitmap-table entry count of both bitmaps. The guest
    /// walks entries `0..table_size` of each on-disk table.
    pub table_size: u32,
    /// The (equal) granularity bits of both bitmaps.
    pub granularity_bits: u8,
    /// `true` when `source_name == dest_name`: merging a bitmap into
    /// itself is a no-op (OR-ing a set of bits into itself changes
    /// nothing), matching qemu. The guest may short-circuit; the
    /// `dest`/`source` fields are equal in this case.
    pub self_merge: bool,
}

/// Validate a same-image `merge` and compute its [`MergeSpec`].
///
/// Performs no I/O and no mutation — it only reads the staged
/// directory bytes. On any failure it returns the error without side
/// effects.
///
/// Validation, in order:
/// - The **destination** must exist ([`BitmapError::BitmapNotFound`]).
/// - The **source** must exist ([`BitmapError::MergeSourceNotFound`]).
/// - **Neither** bitmap may be `in_use` ([`BitmapError::BitmapInUse`]):
///   qemu refuses to merge to/from an inconsistent bitmap. Checked for
///   the destination first, then the source.
/// - The two bitmaps must have **equal `granularity_bits`**
///   ([`BitmapError::IncompatibleMerge`]). qemu requires compatible
///   (equal) granularity to merge; since both bitmaps live in the same
///   image (equal `virtual_size`), equal granularity implies an equal
///   bit-count and therefore an equal `bitmap_table_size`. The equal
///   table size is additionally asserted defensively (also
///   [`BitmapError::IncompatibleMerge`] if it somehow differs).
///
/// **Self-merge** (`source_name == dest_name`) is *allowed* and
/// resolves to a no-op: OR-ing a bitmap's bits into itself changes
/// nothing. It still passes every check above (a bitmap is trivially
/// geometry-compatible with itself and, being a legal merge target, is
/// not `in_use`). The returned spec carries `self_merge = true` so the
/// guest can skip the (pointless) table walk. This matches qemu, whose
/// `qemu-img bitmap --merge X --add-to X` is a no-op.
pub fn merge_validate(
    dir: &[u8],
    nb_bitmaps: u32,
    dest_name: &[u8],
    source_name: &[u8],
    _geom: &BitmapGeometry,
) -> Result<MergeSpec, BitmapError> {
    let dest = find_bitmap(dir, nb_bitmaps, dest_name)?.ok_or(BitmapError::BitmapNotFound)?;
    let source =
        find_bitmap(dir, nb_bitmaps, source_name)?.ok_or(BitmapError::MergeSourceNotFound)?;

    // Neither bitmap may be inconsistent. Check dest then source.
    if dest.entry.is_in_use() {
        return Err(BitmapError::BitmapInUse);
    }
    if source.entry.is_in_use() {
        return Err(BitmapError::BitmapInUse);
    }

    // Equal granularity is required to merge. Equal granularity over an
    // equal virtual size implies an equal bit-count and thus an equal
    // bitmap-table size; verify the table size too (defensive).
    if dest.entry.granularity_bits != source.entry.granularity_bits {
        return Err(BitmapError::IncompatibleMerge);
    }
    if dest.entry.bitmap_table_size != source.entry.bitmap_table_size {
        return Err(BitmapError::IncompatibleMerge);
    }

    let self_merge = dest_name == source_name;

    Ok(MergeSpec {
        dest,
        source,
        table_size: dest.entry.bitmap_table_size,
        granularity_bits: dest.entry.granularity_bits,
        self_merge,
    })
}

/// Byte-wise OR one bitmap DATA cluster into another: `dst[i] |=
/// src[i]`.
///
/// The guest calls this after reading a source data cluster and the
/// matching destination data cluster into scratch; the result is
/// written back to the destination cluster.
///
/// `dst` and `src` must have **equal length** (both a whole bitmap
/// data cluster — one qcow2 cluster). An unequal length is a staging
/// bug and is rejected with [`BitmapError::InternalOverflow`] rather
/// than silently OR-ing a prefix. Panic-free.
pub fn or_bitmap_data(dst: &mut [u8], src: &[u8]) -> Result<(), BitmapError> {
    if dst.len() != src.len() {
        return Err(BitmapError::InternalOverflow);
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d |= *s;
    }
    Ok(())
}

/// What the guest must do for one source/destination bitmap-table
/// entry pair during a merge.
///
/// The bitmap table maps each data cluster of the bitmap to one of
/// three states (Phase 1 [`BitmapTableEntry`]): `AllZeroes` (implicit
/// zero bits, unallocated), `AllOnes` (implicit one bits,
/// unallocated), or `Allocated(offset)` (a real data cluster). A merge
/// OR-s the source's bits into the destination's, per table index.
///
/// # Truth table (source × destination)
///
/// | source \ dest | AllZeroes            | AllOnes | Allocated          |
/// |---------------|----------------------|---------|--------------------|
/// | **AllZeroes** | Skip                 | Skip    | Skip               |
/// | **AllOnes**   | CopyAllOnes          | Skip    | CopyAllOnes        |
/// | **Allocated** | AllocDestFromSource  | Skip    | OrIntoExisting     |
///
/// Rationale:
/// - Source `AllZeroes` contributes no set bits, so the destination is
///   unchanged regardless of its state → [`Skip`](Self::Skip).
/// - Destination `AllOnes` already has every bit set, so OR-ing
///   anything in leaves it all-ones → [`Skip`](Self::Skip) (covers the
///   "source all-ones/allocated + dest all-ones" cases the prompt
///   flagged: the dest table entry already encodes all-ones, so
///   nothing to write and no data cluster to touch).
/// - Source `AllOnes` into a non-all-ones destination sets every bit:
///   the destination's table entry becomes the all-ones flag and any
///   previously-allocated dest data cluster is freed →
///   [`CopyAllOnes`](Self::CopyAllOnes) (this is where the "source
///   all-ones + dest allocated ⇒ dest becomes all-ones, free its data
///   cluster" case folds — the variant's doc records that the guest
///   frees a formerly-allocated dest cluster).
/// - Source `Allocated` into an all-zero destination: the destination
///   gains real bits where it had none, so the guest allocates a fresh
///   dest data cluster and copies the source bits in →
///   [`AllocDestFromSource`](Self::AllocDestFromSource).
/// - Source `Allocated` into an allocated destination: both hold real
///   data; OR the source into the existing dest cluster →
///   [`OrIntoExisting`](Self::OrIntoExisting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeClusterAction {
    /// Nothing to merge for this index: either the source cluster is
    /// all-zeroes (no set bits to contribute) or the destination is
    /// already all-ones (cannot gain more bits). The destination table
    /// entry and data cluster are left untouched.
    Skip,
    /// The destination becomes all-ones for this index: the guest sets
    /// the destination table entry's all-ones flag and, if the
    /// destination previously had an `Allocated` data cluster, frees
    /// that cluster (it is no longer referenced). No data cluster is
    /// read or written.
    CopyAllOnes,
    /// Both source and destination have allocated data clusters: the
    /// guest reads both into scratch, OR-s them with
    /// [`or_bitmap_data`], and writes the result back to the
    /// destination's existing data cluster. The destination table
    /// entry is unchanged.
    OrIntoExisting,
    /// The source has an allocated data cluster and the destination is
    /// all-zeroes: the guest allocates a fresh destination data
    /// cluster, copies the source cluster's bits into it (equivalently
    /// zero-fills then OR-s), writes it, and points the destination
    /// table entry at the new cluster.
    AllocDestFromSource,
}

/// Decide the [`MergeClusterAction`] for one source/destination
/// bitmap-table entry pair.
///
/// `source_entry` and `dest_entry` are the raw big-endian table words
/// (as read from the on-disk bitmap tables), decoded via Phase 1's
/// [`decode_bitmap_table_entry`]. A raw word that fails validation
/// (reserved bits set, or offset + all-ones flag both present) yields
/// [`BitmapError::ParseFailed`] — the guest must not act on a
/// malformed table.
///
/// Pure, panic-free, no I/O. See the [`MergeClusterAction`] truth
/// table for the full disposition.
pub fn merge_cluster_action(
    source_entry: u64,
    dest_entry: u64,
) -> Result<MergeClusterAction, BitmapError> {
    let source = decode_bitmap_table_entry(source_entry).ok_or(BitmapError::ParseFailed)?;
    let dest = decode_bitmap_table_entry(dest_entry).ok_or(BitmapError::ParseFailed)?;

    Ok(match (source, dest) {
        // Source contributes no bits: destination unchanged.
        (BitmapTableEntry::AllZeroes, _) => MergeClusterAction::Skip,
        // Destination already all-ones: cannot gain bits.
        (_, BitmapTableEntry::AllOnes) => MergeClusterAction::Skip,
        // Source all-ones into a non-all-ones destination: dest -> all-ones.
        (BitmapTableEntry::AllOnes, _) => MergeClusterAction::CopyAllOnes,
        // Source has data, destination all-zeroes: alloc + copy.
        (BitmapTableEntry::Allocated(_), BitmapTableEntry::AllZeroes) => {
            MergeClusterAction::AllocDestFromSource
        }
        // Both allocated: OR source into existing dest cluster.
        (BitmapTableEntry::Allocated(_), BitmapTableEntry::Allocated(_)) => {
            MergeClusterAction::OrIntoExisting
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qcow2::bitmap::{
        encode_bitmap_table_entry, serialize_bitmap_dir_entry, BitmapDirEntry, BME_FLAG_AUTO,
        BME_FLAG_IN_USE, BME_TABLE_ENTRY_RESERVED_MASK, BT_DIRTY_TRACKING_BITMAP,
    };
    use std::vec::Vec;

    const CLUSTER_SIZE: u64 = 65536;

    fn geom() -> BitmapGeometry {
        BitmapGeometry {
            cluster_size: CLUSTER_SIZE,
            cluster_bits: 16,
            refcount_bits: 16,
            virtual_size: 1 << 30,
            refblock_count: 1,
            host_refblocks_start: 0,
        }
    }

    fn dir_entry(
        name: &[u8],
        flags: u32,
        granularity_bits: u8,
        off: u64,
        size: u32,
    ) -> BitmapDirEntry {
        let mut e = BitmapDirEntry::zeroed();
        e.bitmap_table_offset = off;
        e.bitmap_table_size = size;
        e.flags = flags;
        e.bitmap_type = BT_DIRTY_TRACKING_BITMAP;
        e.granularity_bits = granularity_bits;
        e.name_size = name.len() as u16;
        e.name[..name.len()].copy_from_slice(name);
        e
    }

    fn build_dir(entries: &[BitmapDirEntry]) -> Vec<u8> {
        let mut dir = Vec::new();
        let mut scratch = [0u8; 1200];
        for e in entries {
            let n = serialize_bitmap_dir_entry(e, &mut scratch).unwrap();
            dir.extend_from_slice(&scratch[..n]);
        }
        dir
    }

    // -------------------- merge_validate --------------------

    #[test]
    fn validate_ok_equal_granularity() {
        let d = dir_entry(b"dst", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let s = dir_entry(b"src", BME_FLAG_AUTO, 16, 5 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[d, s]);
        let spec = merge_validate(&dir, 2, b"dst", b"src", &geom()).unwrap();
        assert_eq!(spec.table_size, 1);
        assert_eq!(spec.granularity_bits, 16);
        assert!(!spec.self_merge);
        assert_eq!(spec.dest.entry.bitmap_table_offset, 4 * CLUSTER_SIZE);
        assert_eq!(spec.source.entry.bitmap_table_offset, 5 * CLUSTER_SIZE);
    }

    #[test]
    fn validate_dest_absent_is_not_found() {
        let s = dir_entry(b"src", BME_FLAG_AUTO, 16, 5 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[s]);
        assert_eq!(
            merge_validate(&dir, 1, b"dst", b"src", &geom()),
            Err(BitmapError::BitmapNotFound)
        );
    }

    #[test]
    fn validate_source_absent_is_merge_source_not_found() {
        let d = dir_entry(b"dst", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[d]);
        assert_eq!(
            merge_validate(&dir, 1, b"dst", b"src", &geom()),
            Err(BitmapError::MergeSourceNotFound)
        );
    }

    #[test]
    fn validate_dest_in_use_is_refused() {
        let d = dir_entry(b"dst", BME_FLAG_IN_USE, 16, 4 * CLUSTER_SIZE, 1);
        let s = dir_entry(b"src", BME_FLAG_AUTO, 16, 5 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[d, s]);
        assert_eq!(
            merge_validate(&dir, 2, b"dst", b"src", &geom()),
            Err(BitmapError::BitmapInUse)
        );
    }

    #[test]
    fn validate_source_in_use_is_refused() {
        let d = dir_entry(b"dst", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let s = dir_entry(b"src", BME_FLAG_IN_USE, 16, 5 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[d, s]);
        assert_eq!(
            merge_validate(&dir, 2, b"dst", b"src", &geom()),
            Err(BitmapError::BitmapInUse)
        );
    }

    #[test]
    fn validate_granularity_mismatch_is_incompatible() {
        let d = dir_entry(b"dst", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let s = dir_entry(b"src", BME_FLAG_AUTO, 17, 5 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[d, s]);
        assert_eq!(
            merge_validate(&dir, 2, b"dst", b"src", &geom()),
            Err(BitmapError::IncompatibleMerge)
        );
    }

    #[test]
    fn validate_table_size_mismatch_is_incompatible() {
        // Equal granularity but (defensively) unequal table size.
        let d = dir_entry(b"dst", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let s = dir_entry(b"src", BME_FLAG_AUTO, 16, 5 * CLUSTER_SIZE, 2);
        let dir = build_dir(&[d, s]);
        assert_eq!(
            merge_validate(&dir, 2, b"dst", b"src", &geom()),
            Err(BitmapError::IncompatibleMerge)
        );
    }

    #[test]
    fn validate_self_merge_is_ok_noop() {
        let d = dir_entry(b"same", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[d]);
        let spec = merge_validate(&dir, 1, b"same", b"same", &geom()).unwrap();
        assert!(spec.self_merge);
        assert_eq!(spec.dest.entry.bitmap_table_offset, 4 * CLUSTER_SIZE);
        assert_eq!(
            spec.source.entry.bitmap_table_offset,
            spec.dest.entry.bitmap_table_offset
        );
    }

    // -------------------- or_bitmap_data --------------------

    #[test]
    fn or_data_ors_bytewise() {
        let mut dst = [0b0000_1111u8, 0b1010_1010, 0x00];
        let src = [0b1111_0000u8, 0b0101_0101, 0xFF];
        or_bitmap_data(&mut dst, &src).unwrap();
        assert_eq!(dst, [0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn or_data_preserves_existing_and_is_idempotent() {
        let mut dst = [0b1100_0000u8, 0x00];
        let src = [0b0000_0011u8, 0x00];
        or_bitmap_data(&mut dst, &src).unwrap();
        assert_eq!(dst, [0b1100_0011, 0x00]);
        // OR-ing again changes nothing.
        or_bitmap_data(&mut dst, &src).unwrap();
        assert_eq!(dst, [0b1100_0011, 0x00]);
    }

    #[test]
    fn or_data_length_mismatch_is_rejected() {
        let mut dst = [0u8; 4];
        let src = [0u8; 3];
        assert_eq!(
            or_bitmap_data(&mut dst, &src),
            Err(BitmapError::InternalOverflow)
        );
        // Longer src is equally rejected (no partial OR).
        let mut dst2 = [0u8; 2];
        let src2 = [0xFFu8; 3];
        assert_eq!(
            or_bitmap_data(&mut dst2, &src2),
            Err(BitmapError::InternalOverflow)
        );
        assert_eq!(dst2, [0u8; 2]);
    }

    // -------------------- merge_cluster_action --------------------

    // Raw encodings for the three states.
    fn zeroes() -> u64 {
        encode_bitmap_table_entry(&BitmapTableEntry::AllZeroes)
    }
    fn ones() -> u64 {
        encode_bitmap_table_entry(&BitmapTableEntry::AllOnes)
    }
    fn alloc(off: u64) -> u64 {
        encode_bitmap_table_entry(&BitmapTableEntry::Allocated(off))
    }

    #[test]
    fn cluster_action_truth_table() {
        use MergeClusterAction::*;
        let a = 0x20000u64; // a valid cluster-aligned offset
        let b = 0x30000u64;
        // source \ dest = AllZeroes, AllOnes, Allocated
        // source AllZeroes -> always Skip.
        assert_eq!(merge_cluster_action(zeroes(), zeroes()).unwrap(), Skip);
        assert_eq!(merge_cluster_action(zeroes(), ones()).unwrap(), Skip);
        assert_eq!(merge_cluster_action(zeroes(), alloc(b)).unwrap(), Skip);
        // source AllOnes.
        assert_eq!(merge_cluster_action(ones(), zeroes()).unwrap(), CopyAllOnes);
        assert_eq!(merge_cluster_action(ones(), ones()).unwrap(), Skip);
        assert_eq!(merge_cluster_action(ones(), alloc(b)).unwrap(), CopyAllOnes);
        // source Allocated.
        assert_eq!(
            merge_cluster_action(alloc(a), zeroes()).unwrap(),
            AllocDestFromSource
        );
        assert_eq!(merge_cluster_action(alloc(a), ones()).unwrap(), Skip);
        assert_eq!(
            merge_cluster_action(alloc(a), alloc(b)).unwrap(),
            OrIntoExisting
        );
    }

    #[test]
    fn cluster_action_rejects_invalid_raw() {
        // A reserved bit set makes the entry invalid.
        let bad = BME_TABLE_ENTRY_RESERVED_MASK & 0xff00_0000_0000_0000;
        assert!(bad != 0);
        assert_eq!(
            merge_cluster_action(bad, zeroes()),
            Err(BitmapError::ParseFailed)
        );
        // Invalid destination entry is equally rejected.
        assert_eq!(
            merge_cluster_action(zeroes(), bad),
            Err(BitmapError::ParseFailed)
        );
    }
}
