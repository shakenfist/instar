//! Pure planner crate for qcow2 snapshot mutator primitives.
//!
//! This crate is the per-operation home for the byte-level
//! mutators that the snapshot create / delete / apply guest
//! binaries (phases 6-8) compose into per-mode patch lists.
//! It is parallel to `commit` and `rebase`: pure functions over
//! caller-staged slices, no I/O, no allocator.
//!
//! The crate's eight public functions live in [`qcow2`]:
//!
//! - [`qcow2::read_refcount_in_block`] / [`qcow2::set_refcount_in_block`]
//!   — scalar refcount accessors for every supported width.
//! - [`qcow2::check_refcount_after_addend`] — overflow-safe
//!   arithmetic check used by the two-pass refcount mutator.
//! - [`qcow2::alloc_cluster_in_refblocks`] — cursor-driven linear
//!   scan over staged refcount blocks; claims the first zero
//!   entry and returns the host byte offset of the new cluster.
//! - [`qcow2::rewrite_l1_entry_copied_flag`] /
//!   [`qcow2::rewrite_l2_entry_copied_flag`] — flip
//!   `OFLAG_COPIED` on L1 / L2 entries (standard or extended-L2).
//! - [`qcow2::for_each_cluster_in_l1`] — visitor that walks the
//!   L1 -> L2 chain, classifying each allocated cluster.
//! - [`qcow2::update_snapshot_refcount`] — two-pass refcount
//!   mutator (dry-run reads only, apply pass mutates).
//! - [`qcow2::precheck_snapshot_refcount`] — the dry-run pass
//!   alone, read-only, for callers that must validate before any
//!   disk write but apply after a commit point (delete, phase 7).
//! - [`qcow2::update_copied_flags_for_l1`] — rewrites COPIED
//!   flags on L1 and L2 entries based on current refcount.
//!
//! The crate is `no_std` and performs no I/O. Mutators operate
//! on slices in place. (A speculative `SnapshotPatch` /
//! `SnapshotPlan` patch-list API existed through phase 13 but
//! was never adopted — the guest binaries went with direct
//! write-groups in phase 6 — and was removed in phase 14.)

#![no_std]
#![allow(clippy::too_many_arguments)]

pub mod qcow2;
pub mod table;

use shared::SnapshotResult;

/// Errors returned by the snapshot mutator primitives.
///
/// The first 13 variants map 1:1 to the [`SnapshotResult::ERROR_*`]
/// wire codes from phase 1; the trailing two variants
/// ([`Self::MisalignedAccess`] and [`Self::Unsupported`]) are
/// planner-internal misuse codes that the phase 6-8 guest
/// binaries translate to the closest matching wire code via
/// the [`From<SnapshotError> for u32`] impl below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    /// The image is not a qcow2 v2 / v3. Maps to
    /// [`SnapshotResult::ERROR_UNSUPPORTED_FORMAT`] (1).
    UnsupportedFormat,
    /// The format is supported but a sub-feature isn't (e.g.
    /// external-data-file, LUKS). Maps to
    /// [`SnapshotResult::ERROR_UNSUPPORTED_FEATURE`] (2).
    UnsupportedFeature,
    /// The named snapshot was not found. Maps to
    /// [`SnapshotResult::ERROR_NOT_FOUND`] (3).
    NotFound,
    /// A snapshot with the same name already exists. Maps to
    /// [`SnapshotResult::ERROR_DUPLICATE_NAME`] (4).
    DuplicateName,
    /// A refcount entry would overflow the configured width.
    /// `at_host_offset` carries the host byte offset of the
    /// cluster whose refcount was about to overflow, so the
    /// caller can report it. Maps to
    /// [`SnapshotResult::ERROR_REFCOUNT_OVERFLOW`] (5).
    RefcountOverflow {
        /// Host byte offset of the cluster whose refcount
        /// would have overflowed.
        at_host_offset: u64,
    },
    /// The allocator could not find a free cluster. Maps to
    /// [`SnapshotResult::ERROR_ALLOCATION_FAILED`] (6).
    AllocationFailed,
    /// Every existing refcount block is full and v1 does not
    /// grow the refcount table. Maps to
    /// [`SnapshotResult::ERROR_ALLOCATION_FAILED`] (6) on the
    /// wire — only the planner distinguishes the cause.
    RefcountExhausted,
    /// The snapshot table is at its bounded capacity. Maps to
    /// [`SnapshotResult::ERROR_SNAPSHOT_TABLE_FULL`] (7).
    SnapshotTableFull,
    /// Generic I/O failure surfaced by upper layers. Maps to
    /// [`SnapshotResult::ERROR_IO`] (8).
    Io,
    /// The snapshot's L1 size disagrees with the active L1's
    /// size. Maps to
    /// [`SnapshotResult::ERROR_L1_SIZE_MISMATCH`] (9).
    L1SizeMismatch,
    /// A snapshot's name or id failed UTF-8 decoding. Maps to
    /// [`SnapshotResult::ERROR_INVALID_UTF8`] (10).
    InvalidUtf8,
    /// Caller-supplied configuration was invalid. Maps to
    /// [`SnapshotResult::ERROR_INVALID_CONFIG`] (11).
    InvalidConfig,
    /// A format-specific parser failed. Maps to
    /// [`SnapshotResult::ERROR_PARSE_FAILED`] (12).
    ParseFailed,
    /// Caller passed an index out of range for the staged
    /// slice. Indicates a planner bug, not a wire condition;
    /// translated to [`SnapshotResult::ERROR_PARSE_FAILED`]
    /// (12) on the wire.
    MisalignedAccess,
    /// Caller asked for a refcount width or other feature this
    /// crate does not yet support (e.g. non-16-bit refcounts
    /// in [`qcow2::alloc_cluster_in_refblocks`]). Translated to
    /// [`SnapshotResult::ERROR_UNSUPPORTED_FEATURE`] (2) on the
    /// wire.
    Unsupported,
}

impl From<SnapshotError> for u32 {
    fn from(err: SnapshotError) -> u32 {
        match err {
            SnapshotError::UnsupportedFormat => SnapshotResult::ERROR_UNSUPPORTED_FORMAT,
            SnapshotError::UnsupportedFeature => SnapshotResult::ERROR_UNSUPPORTED_FEATURE,
            SnapshotError::NotFound => SnapshotResult::ERROR_NOT_FOUND,
            SnapshotError::DuplicateName => SnapshotResult::ERROR_DUPLICATE_NAME,
            SnapshotError::RefcountOverflow { .. } => SnapshotResult::ERROR_REFCOUNT_OVERFLOW,
            SnapshotError::AllocationFailed => SnapshotResult::ERROR_ALLOCATION_FAILED,
            SnapshotError::RefcountExhausted => SnapshotResult::ERROR_ALLOCATION_FAILED,
            SnapshotError::SnapshotTableFull => SnapshotResult::ERROR_SNAPSHOT_TABLE_FULL,
            SnapshotError::Io => SnapshotResult::ERROR_IO,
            SnapshotError::L1SizeMismatch => SnapshotResult::ERROR_L1_SIZE_MISMATCH,
            SnapshotError::InvalidUtf8 => SnapshotResult::ERROR_INVALID_UTF8,
            SnapshotError::InvalidConfig => SnapshotResult::ERROR_INVALID_CONFIG,
            SnapshotError::ParseFailed => SnapshotResult::ERROR_PARSE_FAILED,
            SnapshotError::MisalignedAccess => SnapshotResult::ERROR_PARSE_FAILED,
            SnapshotError::Unsupported => SnapshotResult::ERROR_UNSUPPORTED_FEATURE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_to_wire_code_mapping() {
        assert_eq!(u32::from(SnapshotError::UnsupportedFormat), 1);
        assert_eq!(u32::from(SnapshotError::UnsupportedFeature), 2);
        assert_eq!(u32::from(SnapshotError::NotFound), 3);
        assert_eq!(u32::from(SnapshotError::DuplicateName), 4);
        assert_eq!(
            u32::from(SnapshotError::RefcountOverflow { at_host_offset: 0 }),
            5
        );
        assert_eq!(u32::from(SnapshotError::AllocationFailed), 6);
        assert_eq!(u32::from(SnapshotError::RefcountExhausted), 6);
        assert_eq!(u32::from(SnapshotError::SnapshotTableFull), 7);
        assert_eq!(u32::from(SnapshotError::Io), 8);
        assert_eq!(u32::from(SnapshotError::L1SizeMismatch), 9);
        assert_eq!(u32::from(SnapshotError::InvalidUtf8), 10);
        assert_eq!(u32::from(SnapshotError::InvalidConfig), 11);
        assert_eq!(u32::from(SnapshotError::ParseFailed), 12);
        assert_eq!(u32::from(SnapshotError::MisalignedAccess), 12);
        assert_eq!(u32::from(SnapshotError::Unsupported), 2);
    }
}
