//! qcow2 repair planners.
//!
//! The leak-reclamation planner (phase 2,
//! [`reclaim_leaks_in_refblock`]) lives here, alongside the
//! `use` surface the phase 3 refcount-rebuild + COPIED-reconciliation
//! planner will draw on. The imports are declared once, up front, so
//! they are reviewed before the planners that consume them land.
//!
//! The reused building blocks:
//! - From `snapshot::qcow2`: the refcount accessors and the
//!   L1/L2 visitors that drive both repair tiers.
//! - From `qcow2`: the on-disk flag/mask constants the planners
//!   decode L1/L2 entries with.
//! - From the crate root: [`RepairError`](crate::RepairError) for
//!   `?`-propagation and [`RepairCounters`](crate::RepairCounters)
//!   for the return tally.

// The refcount accessors and arithmetic are used by the phase-2
// leak planner and the phase-3 counting/correction primitives
// below. `update_copied_flags_for_l1` is the snapshot COPIED
// reconciler that `reconcile_copied_flags_for_l1` wraps. The
// explicit `SnapshotError` match in `account_reference_in_map`
// translates the overflow variant itself rather than via the
// generic `From`.
use snapshot::qcow2::{
    check_refcount_after_addend, read_refcount_in_block, set_refcount_in_block,
    update_copied_flags_for_l1,
};
use snapshot::SnapshotError;

// Phase-4 imports: the metadata-walk orchestration will consume the
// L1/L2 cluster visitor and decode L1/L2 entries with the on-disk
// flag/mask constants. The phase-3 planners reuse the snapshot
// COPIED reconciler, which already decodes those flags internally,
// so these stay unused for now. Gated to keep the module
// warning-clean; phase 4 drops the gate as it wires up the walk.
#[allow(unused_imports)]
use qcow2::{L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COMPRESSED, OFLAG_COPIED};
#[allow(unused_imports)]
use snapshot::qcow2::for_each_cluster_in_l1;

use crate::RepairError;

/// Reclaim leaked clusters within one staged refcount block.
///
/// `refblock` is a contiguous slice whose byte 0 is the first
/// refcount entry of the block (the caller stages a whole refblock
/// and, for sub-sector starts, passes the aligned subslice). For
/// each of the `entries_in_block` entries, reads the stored
/// refcount; for an entry with refcount > 0 that the
/// `is_referenced` predicate reports unreferenced, sets it to 0.
/// Returns the number of entries reclaimed.
///
/// Entries with refcount 0 are skipped without consulting the
/// predicate (a free cluster cannot leak). An entry the predicate
/// reports *referenced* is never modified, regardless of its stored
/// refcount — the safe tier never lowers a live cluster's refcount,
/// even when it is over-counted; correcting an over-count needs a
/// per-cluster recount and is phase 3's lossy concern.
///
/// `is_referenced` takes the **local** entry index within this
/// block; the guest (phase 4) maps it to a global cluster index and
/// tests its reference bitmap, keeping this planner ignorant of
/// global cluster-index math.
///
/// Errors from the reused snapshot refcount primitives (an
/// out-of-range `local_idx` against an under-sized slice, or an
/// unsupported width) propagate as [`RepairError`] via the crate's
/// `From<snapshot::SnapshotError>` bridge.
pub fn reclaim_leaks_in_refblock(
    refblock: &mut [u8],
    entries_in_block: u64,
    refcount_bits: u32,
    mut is_referenced: impl FnMut(u64) -> bool,
) -> Result<u32, RepairError> {
    let mut reclaimed: u32 = 0;
    for local_idx in 0..entries_in_block {
        let rc = read_refcount_in_block(refblock, local_idx, refcount_bits)?;
        if rc > 0 && !is_referenced(local_idx) {
            set_refcount_in_block(refblock, local_idx, refcount_bits, 0)?;
            reclaimed += 1;
        }
    }
    Ok(reclaimed)
}

/// Accumulate a single reference to `cluster_index` into the staged
/// computed-refcount map.
///
/// `map` is the caller-staged computed-refcount structure — a second
/// refcount array held in guest memory, interpreted at the image's
/// `refcount_bits` width, mirroring qemu's in-memory `refcount_table`
/// during `qcow2_check_refcounts`. The guest (phase 4) zeroes it,
/// then calls this once per discovered reference to every cluster
/// (active L1 -> L2s, each snapshot L1 -> L2s, the refcount table +
/// blocks, the snapshot table, and the header/L1/refcount clusters
/// themselves). The accumulated map is the *computed* refcount that
/// [`correct_refcounts_in_refblock`] then reconciles the on-disk
/// refblocks against.
///
/// Reads the current computed count, adds 1 via the overflow-checked
/// [`check_refcount_after_addend`], and writes it back.
///
/// A positive overflow — a cluster referenced more times than the
/// configured width can store — is genuine unrepairable corruption
/// (the refcount order is too small for the image's true reference
/// graph, and widening it is out of scope). It is translated
/// **explicitly** to [`RepairError::AmbiguousCorruption`], not via
/// the crate's generic `From<snapshot::SnapshotError>` (which maps
/// `RefcountOverflow` to `MisalignedAccess` — the wrong semantics
/// here: this is a real on-disk condition, not a slice-misuse bug).
///
/// An out-of-range `cluster_index` against the `map` slice (the
/// guest mis-sized the computed map for the image's cluster count)
/// surfaces [`RepairError::MisalignedAccess`] via the `?` on the
/// read/set, matching the bounded-map refuse-don't-partial policy.
pub fn account_reference_in_map(
    map: &mut [u8],
    cluster_index: u64,
    refcount_bits: u32,
) -> Result<(), RepairError> {
    let cur = read_refcount_in_block(map, cluster_index, refcount_bits)?;
    // A positive overflow is a reference count that exceeds the
    // width: refuse rather than guess (see the doc comment).
    // Translated explicitly, not through the generic `From` (which
    // maps `RefcountOverflow` to `MisalignedAccess`).
    match check_refcount_after_addend(cur, 1, refcount_bits) {
        Ok(n) => set_refcount_in_block(map, cluster_index, refcount_bits, n)?,
        Err(SnapshotError::RefcountOverflow { .. }) => {
            return Err(RepairError::AmbiguousCorruption)
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// The direction a single refcount entry was corrected in.
///
/// Returned conceptually per entry by [`correct_refcounts_in_refblock`]'s
/// comparison; the public surface aggregates these into a
/// [`RefcountFixTally`]. `Unchanged` means the stored value already
/// matched the computed value. `Raised` is the **dangerous**
/// direction made safe — an under-counted (possibly stored-0)
/// cluster brought up to its true reference count. `Lowered`
/// trims an over-counted but still-referenced cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefcountFix {
    /// Stored refcount already equalled the computed value.
    Unchanged,
    /// Stored refcount was below the computed value and was raised.
    Raised {
        /// The stored value before correction.
        from: u64,
        /// The computed value written.
        to: u64,
    },
    /// Stored refcount was above the computed value (but still > 0)
    /// and was lowered.
    Lowered {
        /// The stored value before correction.
        from: u64,
        /// The computed value written.
        to: u64,
    },
}

/// Per-refblock tally of refcount corrections, by direction.
///
/// The guest (phase 4) folds these into
/// [`RepairCounters`](crate::RepairCounters): `freed` maps to
/// `leaks`, and `raised + lowered` to `refcounts`. `freed` is
/// counted separately from `lowered` because a lowering-to-zero is a
/// leak discovered by the recount (the cluster is referenced zero
/// times) rather than by phase 2's boolean predicate, and the guest
/// reports it under the leak counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RefcountFixTally {
    /// Entries raised toward a higher computed reference count
    /// (the under-count fix; the dangerous direction made safe).
    pub raised: u32,
    /// Entries lowered to a smaller but still non-zero computed
    /// count (an over-counted live cluster trimmed).
    pub lowered: u32,
    /// Entries lowered to zero — a leak found by the recount.
    pub freed: u32,
}

/// Correct one staged refcount block against the computed-refcount
/// map, in both directions.
///
/// For each of the `entries_in_block` entries, `computed_for(local_idx)`
/// supplies the true reference count from the
/// [`account_reference_in_map`]-built map. Where the stored refcount
/// differs from the computed value the stored value is overwritten
/// with the computed one and the direction tallied:
///
/// - computed > stored -> `raised` (under-count, the dangerous case,
///   including the stored-0 referenced cluster the boolean detector
///   flags as a refcount error: it is raised to its *true*
///   multi-reference count, never a naive 1);
/// - computed < stored and computed > 0 -> `lowered` (over-counted
///   live cluster);
/// - computed == 0 -> `freed` (a leak the recount found).
///
/// `computed_for` returning `None` marks an entry outside the walk's
/// covered range; it is skipped and left byte-identical (no read, no
/// write), so a partial map never zeroes uncovered entries.
///
/// This **generalises** phase 2's [`reclaim_leaks_in_refblock`]: a
/// leak is simply `computed == 0`. Both coexist — the safe (`leaks`)
/// tier uses the cheap boolean predicate with no count-map memory,
/// the lossy (`all`) tier uses this count-driven correction, exactly
/// `qemu-img -r leaks` versus `-r all`.
///
/// Errors from the reused snapshot refcount primitives (an
/// out-of-range `local_idx` against an under-sized `refblock`, or an
/// unsupported width) propagate as [`RepairError`].
pub fn correct_refcounts_in_refblock(
    refblock: &mut [u8],
    entries_in_block: u64,
    refcount_bits: u32,
    mut computed_for: impl FnMut(u64) -> Option<u64>,
) -> Result<RefcountFixTally, RepairError> {
    let mut tally = RefcountFixTally::default();
    for local_idx in 0..entries_in_block {
        let Some(want) = computed_for(local_idx) else {
            continue;
        };
        let have = read_refcount_in_block(refblock, local_idx, refcount_bits)?;
        if want != have {
            set_refcount_in_block(refblock, local_idx, refcount_bits, want)?;
            if want > have {
                tally.raised += 1;
            } else if want > 0 {
                tally.lowered += 1;
            } else {
                tally.freed += 1;
            }
        }
    }
    Ok(tally)
}

/// Reconcile the [`OFLAG_COPIED`] flag on every L1 and L2 entry
/// reachable from `l1_bytes` against the corrected on-disk
/// refcounts.
///
/// A thin wrapper over [`snapshot::qcow2::update_copied_flags_for_l1`]:
/// it forwards the staged L1 bytes, `cluster_bits`, the
/// `l2_for_index` / `refcount_for_cluster` closures, and the
/// `extended_l2` flag unchanged, and maps the returned
/// `SnapshotError` to [`RepairError`] via the crate's `From` bridge,
/// keeping the `check` crate the single home for repair entry points
/// with one error type for phase 4.
///
/// The COPIED rule — set iff the referenced cluster's refcount == 1,
/// for both the L1 entry (keyed on the L2-table cluster's refcount)
/// and each L2 entry (keyed on the data cluster's refcount) — lives
/// in the already-tested snapshot reconciler and is **not**
/// reimplemented here. The guest (phase 4) backs `refcount_for_cluster`
/// with the **corrected** on-disk refcounts, so reconciliation runs
/// after [`correct_refcounts_in_refblock`].
///
/// Returns the number of L1 + L2 entries whose COPIED flag was
/// rewritten.
pub fn reconcile_copied_flags_for_l1<'l2, L2MF, RCF>(
    l1_bytes: &mut [u8],
    cluster_bits: u32,
    l2_for_index: L2MF,
    refcount_for_cluster: RCF,
    extended_l2: bool,
) -> Result<u32, RepairError>
where
    L2MF: FnMut(u32) -> Option<&'l2 mut [u8]>,
    RCF: FnMut(u64) -> Option<u64>,
{
    let rewrites = update_copied_flags_for_l1(
        l1_bytes,
        cluster_bits,
        l2_for_index,
        refcount_for_cluster,
        extended_l2,
    )?;
    Ok(rewrites)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snapshot::qcow2::{read_refcount_in_block, set_refcount_in_block};

    /// (a) An all-zero block with an always-referenced predicate
    /// reclaims nothing and leaves the buffer untouched. (The
    /// predicate is never consulted because every entry is rc==0,
    /// but even if it were, "referenced" would not reclaim.)
    #[test]
    fn all_zero_block_reclaims_nothing() {
        let mut block = [0u8; 8];
        let before = block;
        let reclaimed = reclaim_leaks_in_refblock(&mut block, 8, 8, |_| true).unwrap();
        assert_eq!(reclaimed, 0);
        assert_eq!(block, before);
    }

    /// (b) A mixed block: rc>0 referenced, rc>0 unreferenced, and
    /// rc==0 entries. Only the unreferenced rc>0 entries become 0;
    /// referenced and already-zero entries are untouched; the count
    /// is correct. 8-bit width, one entry per byte.
    ///
    /// Layout (index -> refcount): 0:1 1:0 2:2 3:0 4:5 5:1 6:0 7:9
    /// Referenced: 0, 2, 7. Unreferenced rc>0 (leaks): 4, 5.
    #[test]
    fn mixed_block_reclaims_only_unreferenced_nonzero() {
        let mut block = [1u8, 0, 2, 0, 5, 1, 0, 9];
        let referenced = |idx: u64| matches!(idx, 0 | 2 | 7);
        let reclaimed = reclaim_leaks_in_refblock(&mut block, 8, 8, referenced).unwrap();
        assert_eq!(reclaimed, 2);
        // Referenced entries keep their original (possibly >1) value;
        // already-zero entries stay zero; leaks become zero.
        assert_eq!(block, [1u8, 0, 2, 0, 0, 0, 0, 9]);
    }

    /// (c) A referenced entry with rc==3 is left at 3: the safe tier
    /// never lowers a live cluster's refcount, even when it is
    /// over-counted relative to its (boolean) referenced state.
    #[test]
    fn referenced_high_refcount_is_not_lowered() {
        let mut block = [3u8, 0, 0, 0];
        let reclaimed = reclaim_leaks_in_refblock(&mut block, 4, 8, |idx| idx == 0).unwrap();
        assert_eq!(reclaimed, 0);
        assert_eq!(block, [3u8, 0, 0, 0]);
    }

    /// (d) Idempotence: a second call over the already-reclaimed
    /// buffer reclaims 0 and leaves the buffer byte-identical.
    #[test]
    fn second_call_is_idempotent() {
        let mut block = [1u8, 0, 2, 0, 5, 1, 0, 9];
        let referenced = |idx: u64| matches!(idx, 0 | 2 | 7);
        let first = reclaim_leaks_in_refblock(&mut block, 8, 8, referenced).unwrap();
        assert_eq!(first, 2);
        let after_first = block;
        let second = reclaim_leaks_in_refblock(&mut block, 8, 8, referenced).unwrap();
        assert_eq!(second, 0);
        assert_eq!(block, after_first);
    }

    /// (e) `is_referenced` is never consulted for rc==0 entries. The
    /// predicate panics if asked about any of the zero indices; if
    /// the contract held, those indices are never passed in.
    #[test]
    fn predicate_not_consulted_for_zero_entries() {
        // Indices 1, 3, 6 are rc==0 and must never reach the closure.
        let mut block = [1u8, 0, 2, 0, 5, 1, 0, 9];
        let mut seen = [false; 8];
        {
            let predicate = |idx: u64| -> bool {
                assert!(
                    !matches!(idx, 1 | 3 | 6),
                    "is_referenced consulted for rc==0 entry {idx}"
                );
                seen[idx as usize] = true;
                // Report everything referenced so nothing is zeroed,
                // keeping the focus on which indices are queried.
                true
            };
            reclaim_leaks_in_refblock(&mut block, 8, 8, predicate).unwrap();
        }
        // Exactly the rc>0 indices were queried; the rc==0 ones were
        // not (the assert above would have fired otherwise).
        assert_eq!(seen, [true, false, true, false, true, true, false, true]);
    }

    /// (f) 1-bit sub-byte neighbour preservation. All eight entries
    /// share byte 0; LSB-first, entry i is bit i. Set bits 2, 3, 4
    /// (entries 2, 3, 4 each rc==1): 0b0001_1100 == 0x1C. Entry 3 is
    /// the leak; entries 2 and 4 are referenced. After reclaim only
    /// bit 3 clears: 0b0001_0100 == 0x14.
    #[test]
    fn subbyte_1bit_neighbour_preservation() {
        let mut block = [0x1Cu8];
        // Confirm the hand-built layout reads back as intended.
        assert_eq!(read_refcount_in_block(&block, 2, 1).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 3, 1).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 4, 1).unwrap(), 1);
        // Only entry 3 is unreferenced.
        let referenced = |idx: u64| idx != 3;
        let reclaimed = reclaim_leaks_in_refblock(&mut block, 8, 1, referenced).unwrap();
        assert_eq!(reclaimed, 1);
        assert_eq!(block, [0x14u8]);
        // Neighbours bit-for-bit intact; the leak is cleared.
        assert_eq!(read_refcount_in_block(&block, 2, 1).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 3, 1).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&block, 4, 1).unwrap(), 1);
    }

    /// (f) 2-bit sub-byte neighbour preservation. Four entries share
    /// byte 0; LSB-first, entry i occupies bits [2*i, 2*i+1]. Build
    /// entry0=2 (0b10), entry1=3 (0b11), entry2=1 (0b01), entry3=0:
    /// 0b00_01_11_10 == 0x1E. Entry 1 (rc==3) is the leak; entries 0
    /// and 2 are referenced non-zero neighbours. Clearing entry 1
    /// gives 0b00_01_00_10 == 0x12.
    #[test]
    fn subbyte_2bit_neighbour_preservation() {
        let mut block = [0x1Eu8];
        assert_eq!(read_refcount_in_block(&block, 0, 2).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&block, 1, 2).unwrap(), 3);
        assert_eq!(read_refcount_in_block(&block, 2, 2).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 3, 2).unwrap(), 0);
        // Only entry 1 is unreferenced; entry 3 is rc==0 so the
        // predicate is not consulted for it.
        let referenced = |idx: u64| idx != 1;
        let reclaimed = reclaim_leaks_in_refblock(&mut block, 4, 2, referenced).unwrap();
        assert_eq!(reclaimed, 1);
        assert_eq!(block, [0x12u8]);
        assert_eq!(read_refcount_in_block(&block, 0, 2).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&block, 1, 2).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&block, 2, 2).unwrap(), 1);
    }

    /// (f) 4-bit sub-byte neighbour preservation. Two entries share
    /// byte 0; entry 0 is the low nibble, entry 1 the high nibble.
    /// Build entry0=5 (0x5), entry1=0xA: byte == 0xA5. Entry 0 is
    /// the leak; entry 1 is a referenced non-zero neighbour.
    /// Clearing entry 0 gives 0xA0.
    #[test]
    fn subbyte_4bit_neighbour_preservation() {
        let mut block = [0xA5u8];
        assert_eq!(read_refcount_in_block(&block, 0, 4).unwrap(), 5);
        assert_eq!(read_refcount_in_block(&block, 1, 4).unwrap(), 0xA);
        let referenced = |idx: u64| idx != 0;
        let reclaimed = reclaim_leaks_in_refblock(&mut block, 2, 4, referenced).unwrap();
        assert_eq!(reclaimed, 1);
        assert_eq!(block, [0xA0u8]);
        assert_eq!(read_refcount_in_block(&block, 0, 4).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&block, 1, 4).unwrap(), 0xA);
    }

    /// (g) 16-bit standard width happy path (the qemu-img default).
    /// Big-endian, two bytes per entry. Entry 0 = 0x0001 (leak),
    /// entry 1 = 0x0002 (referenced), entry 2 = 0x0000.
    #[test]
    fn width_16bit_happy_path() {
        let mut block = [0x00, 0x01, 0x00, 0x02, 0x00, 0x00];
        let referenced = |idx: u64| idx == 1;
        let reclaimed = reclaim_leaks_in_refblock(&mut block, 3, 16, referenced).unwrap();
        assert_eq!(reclaimed, 1);
        assert_eq!(block, [0x00, 0x00, 0x00, 0x02, 0x00, 0x00]);
        assert_eq!(read_refcount_in_block(&block, 0, 16).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&block, 1, 16).unwrap(), 2);
    }

    /// (h) 32-bit width. Big-endian, four bytes per entry. Entry 0 =
    /// 0x0000_0007 (leak), entry 1 = 0x0000_0001 (referenced).
    #[test]
    fn width_32bit() {
        let mut block = [0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01];
        let referenced = |idx: u64| idx == 1;
        let reclaimed = reclaim_leaks_in_refblock(&mut block, 2, 32, referenced).unwrap();
        assert_eq!(reclaimed, 1);
        assert_eq!(read_refcount_in_block(&block, 0, 32).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&block, 1, 32).unwrap(), 1);
        assert_eq!(block, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    }

    /// (h) 64-bit width. Big-endian, eight bytes per entry. Entry 0
    /// = 0x0000_0000_0000_00FF (leak), entry 1 = 0x0000_0000_0000_0001
    /// (referenced).
    #[test]
    fn width_64bit() {
        let mut block = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, // entry 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // entry 1
        ];
        let referenced = |idx: u64| idx == 1;
        let reclaimed = reclaim_leaks_in_refblock(&mut block, 2, 64, referenced).unwrap();
        assert_eq!(reclaimed, 1);
        assert_eq!(read_refcount_in_block(&block, 0, 64).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&block, 1, 64).unwrap(), 1);
        let mut expected = [0u8; 16];
        // entry 0 zeroed, entry 1 keeps its 0x01 in the last byte.
        set_refcount_in_block(&mut expected, 1, 64, 1).unwrap();
        assert_eq!(block, expected);
    }

    /// (i) An under-sized `refblock` slice for the given
    /// `entries_in_block` surfaces `RepairError::MisalignedAccess`
    /// via the `?`-propagated read/set. Here `entries_in_block` is 4
    /// but the slice holds room for only 2 16-bit entries, so the
    /// read of entry 2 runs past the end.
    #[test]
    fn undersized_slice_is_misaligned_access() {
        // The slice holds room for only 2 entries at 16-bit, but
        // `entries_in_block` is 4, so the read of entry 2 runs past
        // the end. Mark entry 0 as a leak so the function does real
        // work before reaching the out-of-range index; the read of
        // entry 2 must error regardless.
        let mut block = [0u8; 4];
        block[1] = 1; // entry 0 (big-endian) = 0x0001.
        let err = reclaim_leaks_in_refblock(&mut block, 4, 16, |_| false).unwrap_err();
        assert_eq!(err, RepairError::MisalignedAccess);
    }

    /// (i, companion) An unsupported refcount width surfaces
    /// `RepairError::Unsupported` via the same `?` bridge — the read
    /// of entry 0 returns `SnapshotError::Unsupported`.
    #[test]
    fn unsupported_width_is_unsupported() {
        let mut block = [0u8; 8];
        let err = reclaim_leaks_in_refblock(&mut block, 1, 3, |_| false).unwrap_err();
        assert_eq!(err, RepairError::Unsupported);
    }

    // ============================================================
    // Phase 3a: account_reference_in_map + correct_refcounts_in_refblock
    // ============================================================

    /// (3a-1) Repeated accounting accumulates: three references to
    /// cluster 2 leave its computed count at 3, and an untouched
    /// neighbour stays 0. 8-bit width, one entry per byte.
    #[test]
    fn account_accumulates_across_repeated_calls() {
        let mut map = [0u8; 8];
        account_reference_in_map(&mut map, 2, 8).unwrap();
        account_reference_in_map(&mut map, 2, 8).unwrap();
        account_reference_in_map(&mut map, 2, 8).unwrap();
        assert_eq!(read_refcount_in_block(&map, 2, 8).unwrap(), 3);
        // Untouched neighbours stay zero.
        assert_eq!(read_refcount_in_block(&map, 1, 8).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&map, 3, 8).unwrap(), 0);
    }

    /// (3a-2) Accounting also accumulates at a sub-byte width
    /// without disturbing a packed neighbour. 2-bit: seed entry 0 to
    /// its max (3) so its byte is non-zero, then account entry 1
    /// twice -> 2; entry 0 must remain 3.
    #[test]
    fn account_accumulates_subbyte_preserving_neighbour() {
        let mut map = [0u8; 1];
        set_refcount_in_block(&mut map, 0, 2, 3).unwrap();
        account_reference_in_map(&mut map, 1, 2).unwrap();
        account_reference_in_map(&mut map, 1, 2).unwrap();
        assert_eq!(read_refcount_in_block(&map, 1, 2).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&map, 0, 2).unwrap(), 3);
    }

    /// (3a-3) 1-bit counting overflow: a 1-bit entry maxes at 1, so
    /// accounting an already-1 entry overflows. Returns
    /// AmbiguousCorruption (NOT MisalignedAccess) and leaves the
    /// byte untouched.
    #[test]
    fn account_overflow_1bit_is_ambiguous() {
        let mut map = [0u8; 1];
        set_refcount_in_block(&mut map, 0, 1, 1).unwrap();
        let before = map;
        let err = account_reference_in_map(&mut map, 0, 1).unwrap_err();
        assert_eq!(err, RepairError::AmbiguousCorruption);
        assert_eq!(map, before);
    }

    /// (3a-3) 2-bit counting overflow: max is 3; seed to 3 then
    /// account once more -> AmbiguousCorruption.
    #[test]
    fn account_overflow_2bit_is_ambiguous() {
        let mut map = [0u8; 1];
        set_refcount_in_block(&mut map, 0, 2, 3).unwrap();
        let err = account_reference_in_map(&mut map, 0, 2).unwrap_err();
        assert_eq!(err, RepairError::AmbiguousCorruption);
    }

    /// (3a-3) 4-bit counting overflow: max is 0xF; seed to 0xF then
    /// account once more -> AmbiguousCorruption.
    #[test]
    fn account_overflow_4bit_is_ambiguous() {
        let mut map = [0u8; 1];
        set_refcount_in_block(&mut map, 0, 4, 0xF).unwrap();
        let err = account_reference_in_map(&mut map, 0, 4).unwrap_err();
        assert_eq!(err, RepairError::AmbiguousCorruption);
    }

    /// (3a-3) 8-bit counting overflow: max is 0xFF; seed to 0xFF
    /// then account once more -> AmbiguousCorruption.
    #[test]
    fn account_overflow_8bit_is_ambiguous() {
        let mut map = [0xFFu8; 1];
        let err = account_reference_in_map(&mut map, 0, 8).unwrap_err();
        assert_eq!(err, RepairError::AmbiguousCorruption);
    }

    /// (3a-3) 16-bit counting overflow: max is 0xFFFF; seed the
    /// two-byte big-endian entry to 0xFFFF then account once more ->
    /// AmbiguousCorruption. (The width's canonical overflow case.)
    #[test]
    fn account_overflow_16bit_is_ambiguous() {
        let mut map = [0xFFu8, 0xFF];
        assert_eq!(read_refcount_in_block(&map, 0, 16).unwrap(), 0xFFFF);
        let err = account_reference_in_map(&mut map, 0, 16).unwrap_err();
        assert_eq!(err, RepairError::AmbiguousCorruption);
    }

    /// (3a-3) 32-bit counting overflow: max is 0xFFFF_FFFF; seed to
    /// max then account once more -> AmbiguousCorruption.
    #[test]
    fn account_overflow_32bit_is_ambiguous() {
        let mut map = [0xFFu8; 4];
        assert_eq!(read_refcount_in_block(&map, 0, 32).unwrap(), 0xFFFF_FFFF);
        let err = account_reference_in_map(&mut map, 0, 32).unwrap_err();
        assert_eq!(err, RepairError::AmbiguousCorruption);
    }

    /// (3a-3) 64-bit counting overflow: max is u64::MAX; seed all
    /// eight bytes to 0xFF then account once more -> the checked add
    /// itself overflows -> AmbiguousCorruption.
    #[test]
    fn account_overflow_64bit_is_ambiguous() {
        let mut map = [0xFFu8; 8];
        assert_eq!(read_refcount_in_block(&map, 0, 64).unwrap(), u64::MAX);
        let err = account_reference_in_map(&mut map, 0, 64).unwrap_err();
        assert_eq!(err, RepairError::AmbiguousCorruption);
    }

    /// (3a-4) An out-of-range `cluster_index` against the map slice
    /// surfaces MisalignedAccess via the `?` on the read.
    #[test]
    fn account_out_of_range_is_misaligned() {
        let mut map = [0u8; 4];
        // 8-bit, 4 bytes -> indices 0..3 valid; index 4 is past end.
        let err = account_reference_in_map(&mut map, 4, 8).unwrap_err();
        assert_eq!(err, RepairError::MisalignedAccess);
    }

    /// (3a-5) `correct_refcounts_in_refblock` raises 0->2: tally
    /// raised=1, all else 0; stored entry becomes 2.
    #[test]
    fn correct_raises_zero_to_two() {
        let mut block = [0u8; 4];
        let tally = correct_refcounts_in_refblock(&mut block, 4, 8, |idx| {
            if idx == 0 {
                Some(2)
            } else {
                Some(0)
            }
        })
        .unwrap();
        assert_eq!(
            tally,
            RefcountFixTally {
                raised: 1,
                lowered: 0,
                freed: 0
            }
        );
        assert_eq!(read_refcount_in_block(&block, 0, 8).unwrap(), 2);
    }

    /// (3a-5) The dangerous referenced-but-stored-0 case: a cluster
    /// shared across snapshots whose stored refcount is 0 is raised
    /// to its true multi-reference computed value (3), never a naive
    /// 1. Tally raised=1; stored becomes 3.
    #[test]
    fn correct_raises_stored_zero_to_multi_reference() {
        let mut block = [0u8; 4];
        let tally = correct_refcounts_in_refblock(&mut block, 4, 8, |idx| {
            if idx == 0 {
                Some(3)
            } else {
                Some(0)
            }
        })
        .unwrap();
        assert_eq!(
            tally,
            RefcountFixTally {
                raised: 1,
                lowered: 0,
                freed: 0
            }
        );
        assert_eq!(read_refcount_in_block(&block, 0, 8).unwrap(), 3);
    }

    /// (3a-5) Lowers 5->2 (over-counted live cluster): tally
    /// lowered=1; stored becomes 2.
    #[test]
    fn correct_lowers_five_to_two() {
        let mut block = [5u8, 0, 0, 0];
        let tally = correct_refcounts_in_refblock(&mut block, 4, 8, |idx| {
            if idx == 0 {
                Some(2)
            } else {
                Some(0)
            }
        })
        .unwrap();
        assert_eq!(
            tally,
            RefcountFixTally {
                raised: 0,
                lowered: 1,
                freed: 0
            }
        );
        assert_eq!(read_refcount_in_block(&block, 0, 8).unwrap(), 2);
    }

    /// (3a-5) Frees 3->0 (a leak found by the recount): tally
    /// freed=1, NOT lowered; stored becomes 0.
    #[test]
    fn correct_frees_three_to_zero() {
        let mut block = [3u8, 0, 0, 0];
        let tally = correct_refcounts_in_refblock(&mut block, 4, 8, |idx| {
            if idx == 0 {
                Some(0)
            } else {
                Some(0)
            }
        })
        .unwrap();
        assert_eq!(
            tally,
            RefcountFixTally {
                raised: 0,
                lowered: 0,
                freed: 1
            }
        );
        assert_eq!(read_refcount_in_block(&block, 0, 8).unwrap(), 0);
    }

    /// (3a-5) Equal entries are Unchanged: every stored value already
    /// matches the computed value, tally is all-zero and the buffer
    /// is byte-identical.
    #[test]
    fn correct_equal_entries_unchanged() {
        let mut block = [1u8, 2, 3, 4];
        let before = block;
        // Computed value equals the stored value for every entry
        // (entry idx holds idx+1), so nothing is rewritten.
        let tally = correct_refcounts_in_refblock(&mut block, 4, 8, |idx| Some(idx + 1)).unwrap();
        assert_eq!(tally, RefcountFixTally::default());
        assert_eq!(block, before);
    }

    /// (3a-5, combined) A mixed block exercising all three
    /// directions plus an Unchanged entry in one pass. Entries:
    /// 0: 0->2 raised, 1: 5->2 lowered, 2: 3->0 freed, 3: 4 stays 4.
    #[test]
    fn correct_mixed_all_directions() {
        let mut block = [0u8, 5, 3, 4];
        let tally = correct_refcounts_in_refblock(&mut block, 4, 8, |idx| {
            Some(match idx {
                0 => 2,
                1 => 2,
                2 => 0,
                _ => 4,
            })
        })
        .unwrap();
        assert_eq!(
            tally,
            RefcountFixTally {
                raised: 1,
                lowered: 1,
                freed: 1
            }
        );
        assert_eq!(block, [2u8, 2, 0, 4]);
    }

    /// (3a-6) `computed_for` returning None skips an entry, leaving
    /// it byte-identical and not counting it. Here entry 1 is
    /// outside the walk's covered range (None) and its stored 9 must
    /// survive untouched, while entry 0 is raised 0->1.
    #[test]
    fn correct_none_skips_entry_byte_identical() {
        let mut block = [0u8, 9, 0, 0];
        let tally = correct_refcounts_in_refblock(&mut block, 4, 8, |idx| match idx {
            0 => Some(1),
            1 => None,
            _ => Some(0),
        })
        .unwrap();
        assert_eq!(
            tally,
            RefcountFixTally {
                raised: 1,
                lowered: 0,
                freed: 0
            }
        );
        // Entry 1 (None) left byte-identical at 9.
        assert_eq!(block, [1u8, 9, 0, 0]);
    }

    /// (3a-7) An out-of-range `local_idx` in correction surfaces
    /// MisalignedAccess via the `?` on the read. `entries_in_block`
    /// is 4 but the slice holds room for only two 16-bit entries.
    #[test]
    fn correct_out_of_range_local_idx_is_misaligned() {
        let mut block = [0u8; 4];
        let err = correct_refcounts_in_refblock(&mut block, 4, 16, |_| Some(1)).unwrap_err();
        assert_eq!(err, RepairError::MisalignedAccess);
    }

    /// (3a-8) Correction across every supported width. For each of
    /// 1/2/4/8/16/32/64 bits, raising entry 0 from 0 to 1 yields
    /// raised=1 and reads back as 1.
    #[test]
    fn correct_all_widths_raise_to_one() {
        for bits in [1u32, 2, 4, 8, 16, 32, 64] {
            let mut block = [0u8; 8];
            let tally = correct_refcounts_in_refblock(&mut block, 1, bits, |_| Some(1)).unwrap();
            assert_eq!(
                tally,
                RefcountFixTally {
                    raised: 1,
                    lowered: 0,
                    freed: 0
                },
                "width {bits}"
            );
            assert_eq!(
                read_refcount_in_block(&block, 0, bits).unwrap(),
                1,
                "width {bits}"
            );
        }
    }

    /// (3a-9) 1-bit sub-byte neighbour preservation under
    /// correction. Eight entries share byte 0, LSB-first (entry i is
    /// bit i). Seed bits 2 and 4 set (entries 2,4 == 1): 0b0001_0100
    /// == 0x14. Correct ONLY entry 3 from 0 to 1 -> bit 3 set:
    /// 0b0001_1100 == 0x1C. Neighbours 2 and 4 must stay 1.
    #[test]
    fn correct_subbyte_1bit_preserves_neighbours() {
        let mut block = [0x14u8];
        assert_eq!(read_refcount_in_block(&block, 2, 1).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 4, 1).unwrap(), 1);
        let tally =
            correct_refcounts_in_refblock(
                &mut block,
                8,
                1,
                |idx| {
                    if idx == 3 {
                        Some(1)
                    } else {
                        None
                    }
                },
            )
            .unwrap();
        assert_eq!(
            tally,
            RefcountFixTally {
                raised: 1,
                lowered: 0,
                freed: 0
            }
        );
        assert_eq!(block, [0x1Cu8]);
        // Neighbours bit-for-bit intact.
        assert_eq!(read_refcount_in_block(&block, 2, 1).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 3, 1).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 4, 1).unwrap(), 1);
    }

    /// (3a-9) 2-bit sub-byte neighbour preservation. Four entries
    /// share byte 0, LSB-first (entry i occupies bits [2i, 2i+1]).
    /// Seed entry0=2 (0b10), entry2=1 (0b01), entry3=3 (0b11),
    /// entry1=0: 0b11_01_00_10 == 0xD2. Correct ONLY entry 1 from 0
    /// to 3 -> 0b11_01_11_10 == 0xDE. Entries 0/2/3 must survive.
    #[test]
    fn correct_subbyte_2bit_preserves_neighbours() {
        let mut block = [0xD2u8];
        assert_eq!(read_refcount_in_block(&block, 0, 2).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&block, 1, 2).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&block, 2, 2).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 3, 2).unwrap(), 3);
        let tally =
            correct_refcounts_in_refblock(
                &mut block,
                4,
                2,
                |idx| {
                    if idx == 1 {
                        Some(3)
                    } else {
                        None
                    }
                },
            )
            .unwrap();
        assert_eq!(
            tally,
            RefcountFixTally {
                raised: 1,
                lowered: 0,
                freed: 0
            }
        );
        assert_eq!(block, [0xDEu8]);
        assert_eq!(read_refcount_in_block(&block, 0, 2).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&block, 2, 2).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 3, 2).unwrap(), 3);
    }

    /// (3a-9) 4-bit sub-byte neighbour preservation. Two entries
    /// share byte 0: entry 0 is the low nibble, entry 1 the high
    /// nibble. Seed entry0=0, entry1=0xA -> byte 0xA0. Correct ONLY
    /// entry 0 from 0 to 5 -> 0xA5. The high-nibble neighbour 0xA
    /// must survive.
    #[test]
    fn correct_subbyte_4bit_preserves_neighbours() {
        let mut block = [0xA0u8];
        assert_eq!(read_refcount_in_block(&block, 0, 4).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&block, 1, 4).unwrap(), 0xA);
        let tally =
            correct_refcounts_in_refblock(
                &mut block,
                2,
                4,
                |idx| {
                    if idx == 0 {
                        Some(5)
                    } else {
                        None
                    }
                },
            )
            .unwrap();
        assert_eq!(
            tally,
            RefcountFixTally {
                raised: 1,
                lowered: 0,
                freed: 0
            }
        );
        assert_eq!(block, [0xA5u8]);
        assert_eq!(read_refcount_in_block(&block, 0, 4).unwrap(), 5);
        assert_eq!(read_refcount_in_block(&block, 1, 4).unwrap(), 0xA);
    }

    // ============================================================
    // Phase 3b: reconcile_copied_flags_for_l1
    // ============================================================
    //
    // Mirrors the snapshot crate's own update_copied_flags_for_l1
    // fixtures: L1 entries are 8-byte big-endian (offset in
    // L1_OFFSET_MASK, COPIED in bit 63); L2 entries are 8 bytes
    // (standard) or 16 bytes (extended L2, the second 8 bytes being
    // the subcluster bitmap). Real mutable L2 buffers are threaded
    // through the 'l2 lifetime with a raw-pointer reborrow, the same
    // pattern the snapshot tests and the phase-4 guest use.

    /// (3b-1) COPIED is SET on an L1 entry whose L2-table cluster has
    /// refcount == 1. The L2 closure returns None, so the walk errors
    /// with MisalignedAccess *after* the L1 rewrite — we assert the
    /// L1 entry was updated first (mirrors the snapshot crate's
    /// copied_flags_set_when_refcount_one).
    #[test]
    fn reconcile_sets_copied_on_l1_when_refcount_one() {
        let mut l1 = [0u8; 8];
        let l1_entry = 0x4000u64 & L1_OFFSET_MASK; // no COPIED yet
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let rc = |off: u64| -> Option<u64> { Some(if off == 0x4000 { 1 } else { 0 }) };
        let r = reconcile_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| -> Option<&'static mut [u8]> { None },
            rc,
            false,
        );
        assert_eq!(r, Err(RepairError::MisalignedAccess));
        let v = u64::from_be_bytes(l1[0..8].try_into().unwrap());
        assert_eq!(v & OFLAG_COPIED, OFLAG_COPIED);
    }

    /// (3b-2) COPIED is SET on an L2 entry whose data cluster has
    /// refcount == 1. One L1 entry -> L2 at 0x4000 (rc 1, COPIED
    /// already set so it contributes no rewrite); the single L2 data
    /// cluster at 0x10_0000 has rc 1 and no COPIED, so it is set.
    /// Only the L2 entry changes, so the rewrite count is 1.
    #[test]
    fn reconcile_sets_copied_on_l2_when_refcount_one() {
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64 & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let mut l2 = [0u8; 8];
        l2[0..8].copy_from_slice(&0x10_0000u64.to_be_bytes()); // no COPIED
        let rc = |off: u64| -> Option<u64> {
            Some(match off {
                0x4000 => 1,
                0x10_0000 => 1,
                _ => 0,
            })
        };
        let ptr = l2.as_mut_ptr();
        let len = l2.len();
        let r = reconcile_copied_flags_for_l1(
            &mut l1,
            12,
            // SAFETY: the walker visits each L1 index once, so a
            // single live reborrow exists at a time.
            |_idx| Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) }),
            rc,
            false,
        )
        .unwrap();
        assert_eq!(r, 1);
        assert_eq!(
            u64::from_be_bytes(l2[0..8].try_into().unwrap()),
            0x10_0000 | OFLAG_COPIED
        );
    }

    /// (3b-3) COPIED is CLEARED on a shared (refcount > 1) L2 data
    /// cluster. The L2 entry has COPIED set but its cluster's
    /// refcount is 2, so it is cleared (1 rewrite). The L1 entry
    /// (rc 1, COPIED already set) is unchanged.
    #[test]
    fn reconcile_clears_copied_when_shared() {
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64 & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let mut l2 = [0u8; 8];
        l2[0..8].copy_from_slice(&(0x10_0000u64 | OFLAG_COPIED).to_be_bytes());
        let rc = |off: u64| -> Option<u64> {
            Some(match off {
                0x4000 => 1,
                0x10_0000 => 2,
                _ => 0,
            })
        };
        let ptr = l2.as_mut_ptr();
        let len = l2.len();
        let r = reconcile_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) }),
            rc,
            false,
        )
        .unwrap();
        assert_eq!(r, 1);
        assert_eq!(u64::from_be_bytes(l2[0..8].try_into().unwrap()), 0x10_0000);
    }

    /// (3b-4) Extended L2 (16-byte entries): the COPIED flag in the
    /// first 8 bytes is set when refcount == 1, and the second
    /// 8-byte subcluster bitmap half is preserved bit-for-bit. The
    /// L2 data cluster at 0x10_0000 has rc 1; its bitmap is a
    /// recognisable sentinel.
    #[test]
    fn reconcile_extended_l2_preserves_subcluster_bitmap() {
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64 & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let mut l2 = [0u8; 16];
        l2[0..8].copy_from_slice(&0x10_0000u64.to_be_bytes()); // no COPIED yet
        l2[8..16].copy_from_slice(&0xDEAD_BEEF_CAFE_F00Du64.to_be_bytes()); // bitmap
        let rc = |off: u64| -> Option<u64> {
            Some(match off {
                0x4000 => 1,
                0x10_0000 => 1,
                _ => 0,
            })
        };
        let ptr = l2.as_mut_ptr();
        let len = l2.len();
        let r = reconcile_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) }),
            rc,
            true,
        )
        .unwrap();
        assert_eq!(r, 1);
        // COPIED set on the entry's first 8 bytes.
        assert_eq!(
            u64::from_be_bytes(l2[0..8].try_into().unwrap()),
            0x10_0000 | OFLAG_COPIED
        );
        // Subcluster bitmap half untouched.
        assert_eq!(
            u64::from_be_bytes(l2[8..16].try_into().unwrap()),
            0xDEAD_BEEF_CAFE_F00D
        );
    }

    /// (3b-5) Standard-L2 happy path with refcount > 1 on a 16-byte
    /// region treated as TWO 8-byte standard entries (extended_l2
    /// false), confirming the 8-byte stride. Entry 0 (rc 2, COPIED
    /// set) cleared; entry 1 (rc 1, no COPIED) set. Two rewrites.
    #[test]
    fn reconcile_standard_l2_two_entries_both_directions() {
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64 & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let mut l2 = [0u8; 16];
        l2[0..8].copy_from_slice(&(0x10_0000u64 | OFLAG_COPIED).to_be_bytes());
        l2[8..16].copy_from_slice(&0x10_1000u64.to_be_bytes());
        let rc = |off: u64| -> Option<u64> {
            Some(match off {
                0x4000 => 1,
                0x10_0000 => 2,
                0x10_1000 => 1,
                _ => 0,
            })
        };
        let ptr = l2.as_mut_ptr();
        let len = l2.len();
        let r = reconcile_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) }),
            rc,
            false,
        )
        .unwrap();
        assert_eq!(r, 2);
        assert_eq!(u64::from_be_bytes(l2[0..8].try_into().unwrap()), 0x10_0000);
        assert_eq!(
            u64::from_be_bytes(l2[8..16].try_into().unwrap()),
            0x10_1000 | OFLAG_COPIED
        );
    }

    /// (3b-6) Idempotence: after a first reconciliation brings the
    /// flags into agreement, a second call rewrites 0 and leaves the
    /// buffers byte-identical.
    #[test]
    fn reconcile_is_idempotent() {
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64 & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let mut l2 = [0u8; 8];
        l2[0..8].copy_from_slice(&0x10_0000u64.to_be_bytes()); // no COPIED yet
        let rc = |off: u64| -> Option<u64> {
            Some(match off {
                0x4000 => 1,
                0x10_0000 => 1,
                _ => 0,
            })
        };
        let ptr = l2.as_mut_ptr();
        let len = l2.len();
        let first = reconcile_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) }),
            rc,
            false,
        )
        .unwrap();
        assert_eq!(first, 1);
        let l1_after = l1;
        let l2_after = l2;
        let second = reconcile_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) }),
            rc,
            false,
        )
        .unwrap();
        assert_eq!(second, 0);
        assert_eq!(l1, l1_after);
        assert_eq!(l2, l2_after);
    }

    /// (3b-7) A `refcount_for_cluster` that returns None for a
    /// needed cluster surfaces the snapshot crate's error mapped to
    /// RepairError (MisalignedAccess via the From bridge). Here the
    /// allocated L1 entry's own L2-table cluster has no refcount.
    #[test]
    fn reconcile_missing_refcount_surfaces_repair_error() {
        let mut l1 = [0u8; 8];
        let l1_entry = 0x4000u64 & L1_OFFSET_MASK;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let rc = |_off: u64| -> Option<u64> { None };
        let r = reconcile_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| -> Option<&'static mut [u8]> { None },
            rc,
            false,
        );
        assert_eq!(r, Err(RepairError::MisalignedAccess));
    }

    /// (3b-8) Zero `cluster_bits` is rejected by the snapshot
    /// reconciler (InvalidConfig) and mapped to RepairError::ParseFailed
    /// via the From bridge — confirms error translation, not just
    /// the happy path.
    #[test]
    fn reconcile_zero_cluster_bits_maps_to_parse_failed() {
        let mut l1 = [0u8; 8];
        let rc = |_off: u64| -> Option<u64> { Some(1) };
        let r = reconcile_copied_flags_for_l1(
            &mut l1,
            0,
            |_idx| -> Option<&'static mut [u8]> { None },
            rc,
            false,
        );
        assert_eq!(r, Err(RepairError::ParseFailed));
    }
}
