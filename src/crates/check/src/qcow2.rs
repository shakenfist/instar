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

// Phase-3 imports: the COPIED-reconciliation / refcount-rebuild
// planner consumes the L1/L2 visitors and the on-disk flag/mask
// constants. Gated to keep the module warning-clean until phase 3
// adds the planner that uses them; remove the gate then.
#[allow(unused_imports)]
use qcow2::{L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COMPRESSED, OFLAG_COPIED};
#[allow(unused_imports)]
use snapshot::qcow2::{for_each_cluster_in_l1, update_copied_flags_for_l1};

// The refcount accessors are used by the phase-2 planner below.
use snapshot::qcow2::{read_refcount_in_block, set_refcount_in_block};

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
}
