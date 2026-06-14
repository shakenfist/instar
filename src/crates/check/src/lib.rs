//! Pure planner crate for `qcow2 check --repair`.
//!
//! This crate is the per-operation home for the byte-level repair
//! planners that the `check` guest binary (phase 4) will compose
//! into in-place patch sequences. It is parallel to `snapshot` /
//! `commit` / `rebase`: pure functions over caller-staged slices,
//! no I/O, no allocator. It reuses `snapshot`'s hardened
//! refcount/L1/L2 primitives (`set_refcount_in_block`,
//! `for_each_cluster_in_l1`, `update_copied_flags_for_l1`, ...)
//! rather than re-deriving refcount-width arithmetic.
//!
//! Phase 1 ships only the stable public type surface that phases
//! 2-3 consume; the planners themselves live in [`qcow2`] and are
//! added later. The types are fixed now to avoid churning the
//! planner signatures across phases.

#![no_std]

pub mod qcow2;

/// Which repair tier a planner is operating in.
///
/// Mirrors `qemu-img check -r leaks|all`. Decoded by the guest
/// (phase 4) from [`shared::CheckConfig`]'s
/// [`FLAG_REPAIR`](shared::CheckConfig::FLAG_REPAIR) /
/// [`FLAG_REPAIR_ALL`](shared::CheckConfig::FLAG_REPAIR_ALL) bits
/// and threaded into the planner entry points so each planner
/// knows whether it may take the lossy `All` actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairTier {
    /// The safe, lossless tier: reclaim allocated-but-unreferenced
    /// clusters only (phase 2).
    Leaks,
    /// The lossy tier: the leaks tier plus refcount-structure
    /// rebuild, COPIED reconciliation, and `corrupt`-bit clearing
    /// (phase 3).
    All,
}

/// Errors returned by the repair planners.
///
/// An internal planner type, not a wire type: the guest (phase 4)
/// translates a hard failure into a `send_error` call and a
/// partial repair into
/// [`CheckResult::FLAG_REPAIR_INCOMPLETE`](shared::CheckResult::FLAG_REPAIR_INCOMPLETE),
/// rather than mapping these 1:1 to wire codes. The
/// [`From<snapshot::SnapshotError>`] impl lets the planners
/// `?`-propagate errors from the reused snapshot primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairError {
    /// Every existing refcount block is full and v1 does not grow
    /// the refcount table — the inherited refuse-don't-guess
    /// boundary from the snapshot allocator. Reported, never
    /// worked around.
    RefcountExhausted,
    /// A corruption whose correct fix is not mechanically
    /// determined by the rest of the metadata (e.g. a
    /// refcount-table entry pointing outside the file, an L1 entry
    /// whose L2 cluster overlaps the refcount structures). The
    /// safety model refuses rather than fabricating a fix.
    AmbiguousCorruption,
    /// The image uses a feature or refcount width this crate does
    /// not yet repair.
    Unsupported,
    /// A staged-slice index was out of range — a planner bug or a
    /// truncated buffer, not a repairable on-disk condition.
    MisalignedAccess,
    /// A format-specific parse of the staged metadata failed.
    ParseFailed,
}

impl From<snapshot::SnapshotError> for RepairError {
    fn from(err: snapshot::SnapshotError) -> Self {
        use snapshot::SnapshotError as S;
        match err {
            // The allocator's no-grow boundary maps straight
            // across; both crates treat it as refuse-don't-guess.
            S::RefcountExhausted => RepairError::RefcountExhausted,

            // Width/feature limits in the reused primitives.
            S::Unsupported | S::UnsupportedFormat | S::UnsupportedFeature => {
                RepairError::Unsupported
            }

            // Staged-slice misuse / arithmetic overflow on a
            // refcount entry: a sub-sector access problem, not a
            // repairable on-disk condition.
            S::MisalignedAccess | S::RefcountOverflow { .. } => RepairError::MisalignedAccess,

            // Everything else surfaces from parsing or
            // reconciling the staged metadata and has no
            // mechanically-determined fix at this layer, so it
            // collapses to a parse failure for the planners. The
            // snapshot-table-shaped variants (NotFound,
            // DuplicateName, SnapshotTableFull, L1SizeMismatch)
            // cannot arise from the refcount/L1/L2 primitives
            // repair calls, but are mapped for exhaustiveness.
            S::ParseFailed
            | S::InvalidUtf8
            | S::InvalidConfig
            | S::Io
            | S::AllocationFailed
            | S::NotFound
            | S::DuplicateName
            | S::SnapshotTableFull
            | S::L1SizeMismatch => RepairError::ParseFailed,
        }
    }
}

/// The repair-outcome tally a planner returns.
///
/// The guest (phase 4) folds these into the
/// [`CheckResult`](shared::CheckResult) wire struct's
/// `repaired_leaks` / `repaired_refcounts` / `repaired_corruptions`
/// counters and sets
/// [`FLAG_REPAIR_INCOMPLETE`](shared::CheckResult::FLAG_REPAIR_INCOMPLETE)
/// from [`incomplete`](Self::incomplete).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RepairCounters {
    /// Leaked clusters reclaimed (the safe tier's only output).
    pub leaks: u32,
    /// Refcount inconsistencies corrected.
    pub refcounts: u32,
    /// Corruptions resolved.
    pub corruptions: u32,
    /// True when repair made progress but could not fully clean
    /// the image (a refuse-don't-guess boundary or
    /// `RefcountExhausted` was hit).
    pub incomplete: bool,
}
