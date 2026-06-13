//! qcow2 repair planners (scaffold).
//!
//! Phase 1 is an empty stub: it declares the `use` surface the
//! phase 2-3 planners will draw on so the imports are reviewed
//! once, up front. The leak-reclamation planner (phase 2) and the
//! refcount-rebuild + COPIED-reconciliation planner (phase 3) land
//! their functions here.
//!
//! The reused building blocks:
//! - From `snapshot::qcow2`: the refcount accessors and the
//!   L1/L2 visitors that drive both repair tiers.
//! - From `qcow2`: the on-disk flag/mask constants the planners
//!   decode L1/L2 entries with.
//! - From the crate root: [`RepairError`](crate::RepairError) for
//!   `?`-propagation and [`RepairCounters`](crate::RepairCounters)
//!   for the return tally.

// These imports are intentionally unused in the phase 1 scaffold;
// the planners that consume them arrive in phases 2-3. Gated to
// keep the stub warning-clean without suppressing dead-code
// warnings crate-wide.
#[allow(unused_imports)]
use qcow2::{L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COMPRESSED, OFLAG_COPIED};
#[allow(unused_imports)]
use snapshot::qcow2::{
    for_each_cluster_in_l1, read_refcount_in_block, set_refcount_in_block,
    update_copied_flags_for_l1,
};

#[allow(unused_imports)]
use crate::{RepairCounters, RepairError};

#[cfg(test)]
mod tests {}
