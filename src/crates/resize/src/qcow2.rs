//! QCOW2-specific resize planning.
//!
//! Phase 2 of `PLAN-resize.md`. The public entry point is
//! [`plan_resize_qcow2`](super::plan_resize_qcow2) in the crate
//! root; this module hosts the helpers that decide which growth
//! flavour applies and (in steps 2b/2c) assemble the patch list.

// Steps 2b/2c wire these helpers into the public entry point;
// phase 2a ships them with unit-test coverage only.
#![allow(dead_code)]

/// Classification of a qcow2 grow request, decided up-front from
/// the existing and target layouts.
///
/// The three flavours have progressively more invasive patch
/// lists. [`Qcow2GrowAction::HeaderOnly`] emits a single header
/// rewrite; [`Qcow2GrowAction::L1Grow`] additionally appends a
/// new L1 region and updates the refcount entries that cover it;
/// [`Qcow2GrowAction::L1AndRefcountGrow`] runs the full algorithm
/// including new refcount blocks and (optionally) a relocated
/// refcount table.
///
/// `NoOp` is also represented for parity with the action enum
/// even though the public planner short-circuits before reaching
/// `decide_action` for `new == current`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Qcow2GrowAction {
    /// new_virtual_size fits inside the existing L1's L2
    /// coverage and the refcount table already covers every
    /// cluster the resize will allocate. Only `header.size`
    /// changes.
    HeaderOnly,
    /// `target_l1_entries > current_l1_entries`, but the existing
    /// refcount blocks still cover every newly-allocated cluster.
    /// Append the new L1 region; patch refcount entries for it in
    /// existing blocks.
    L1Grow,
    /// `target_l1_entries > current_l1_entries` AND the refcount
    /// table either needs more blocks or a larger table itself.
    /// The full algorithm.
    L1AndRefcountGrow,
}

/// Decide which growth flavour applies, given the current and
/// target geometry.
///
/// All inputs are scalars read straight off the parsed header or
/// out of a freshly-computed `Qcow2Layout`. Pure function; no
/// I/O.
pub(crate) fn decide_action(
    current_l1_entries: u32,
    current_refcount_table_clusters: u32,
    current_refcount_block_count: u64,
    target_l1_entries: u32,
    target_refcount_table_clusters: u64,
    target_refcount_block_count: u64,
) -> Qcow2GrowAction {
    let l1_grows = target_l1_entries > current_l1_entries;
    let refcount_grows = target_refcount_block_count > current_refcount_block_count
        || target_refcount_table_clusters > current_refcount_table_clusters as u64;
    match (l1_grows, refcount_grows) {
        (false, false) => Qcow2GrowAction::HeaderOnly,
        (true, false) => Qcow2GrowAction::L1Grow,
        (true, true) | (false, true) => Qcow2GrowAction::L1AndRefcountGrow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_only_when_nothing_grows() {
        // Existing L1 has slack for a much bigger virtual size;
        // the refcount table likewise already covers everything.
        // Arg order: (current_l1, current_rt_clusters,
        // current_rb_count, target_l1, target_rt_clusters,
        // target_rb_count).
        let action = decide_action(16, 1, 1, 16, 1, 1);
        assert_eq!(action, Qcow2GrowAction::HeaderOnly);
    }

    #[test]
    fn l1_grow_when_only_l1_extends() {
        let action = decide_action(1, 1, 1, 4, 1, 1);
        assert_eq!(action, Qcow2GrowAction::L1Grow);
    }

    #[test]
    fn l1_and_refcount_grow_when_both_extend() {
        let action = decide_action(1, 1, 1, 4, 1, 2);
        assert_eq!(action, Qcow2GrowAction::L1AndRefcountGrow);
    }

    #[test]
    fn refcount_table_growth_alone_still_uses_full_algorithm() {
        // L1 stays, refcount table itself grew (more blocks
        // appended pushed the table past its current clusters).
        let action = decide_action(16, 1, 1, 16, 2, 2);
        assert_eq!(action, Qcow2GrowAction::L1AndRefcountGrow);
    }

    #[test]
    fn refcount_block_growth_without_table_grow_uses_full_algorithm() {
        // New blocks appended but the existing table still has
        // enough entries to hold their pointers.
        let action = decide_action(16, 2, 1, 16, 2, 3);
        assert_eq!(action, Qcow2GrowAction::L1AndRefcountGrow);
    }
}
