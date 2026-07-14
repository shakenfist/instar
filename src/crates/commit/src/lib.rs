//! Validation and geometry planning for committing overlay
//! clusters into a backing image.
//!
//! Given the parsed headers of the overlay and the backing, the
//! `plan_commit_*` functions in this crate validate the pair
//! (LUKS / external-data-file refusal, virtual-size
//! compatibility, geometry sanity) and return a per-format
//! *context* of the geometry the guest threads through its
//! per-cluster commit loop. Unlike rebase (where unsafe mode
//! could pre-compute a complete patch list), commit is always
//! data-aware: every commit reads overlay cluster data and
//! writes it into the backing.
//!
//! For qcow2, the backing-side write composition (cluster
//! allocation, refblock staging and dirty tracking, the L2/L1
//! /refcount flush) moved to `crates/qcow2-write` +
//! `crates/qcow2-write-exec` in phase 4 of
//! `PLAN-qcow2-write-infrastructure`; [`plan_commit_qcow2`]
//! keeps the overlay-side and cross-image validation plus the
//! overlay geometry the clear pass needs. The vmdk path
//! ([`plan_commit_vmdk`], [`allocate_backing_grain_vmdk`])
//! still owns its backing-side allocator and scratch staging.
//!
//! This crate is `no_std` and performs no I/O. The vmdk
//! planner's scratch buffer is caller-supplied; its returned
//! context borrows from that scratch.

#![no_std]
#![allow(clippy::too_many_arguments)]

mod qcow2;
mod vmdk;

/// Errors returned by the `plan_commit_*` family of functions.
///
/// Each variant maps to a distinct
/// [`shared::CommitResult::ERROR_*`] wire code via the
/// `map_commit_error` helper in `src/operations/commit/src/main.rs`
/// (phase 7 step 7c). Wire codes 0..=13 are append-only and
/// stable; phase 7 step 7a appended codes 8..=13 to cover the
/// planner-internal variants below that didn't have a phase-1
/// wire equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitError {
    /// The overlay or backing is not a format this crate
    /// supports (qcow2 v2/v3 or vmdk monolithicSparse). Maps to
    /// `CommitResult::ERROR_UNSUPPORTED_FORMAT` (1).
    UnsupportedFormat,
    /// The format is supported but the subformat isn't (e.g.
    /// vmdk twoGbMaxExtent overlay). Maps to
    /// `CommitResult::ERROR_UNSUPPORTED_FORMAT` (1) on the
    /// wire — only the planner distinguishes.
    UnsupportedSubformat,
    /// The overlay is a qcow2 image with the external-data-file
    /// incompatible feature set. Maps to
    /// `CommitResult::ERROR_EXTERNAL_DATA_FILE` (3).
    ExternalDataFile,
    /// The overlay or backing is LUKS-wrapped. Maps to
    /// `CommitResult::ERROR_LUKS_UNSUPPORTED` (4).
    LuksUnsupported,
    /// The backing's virtual size is smaller than the
    /// overlay's. Maps to
    /// `CommitResult::ERROR_OVERLAY_LARGER_THAN_BACKING` (6).
    OverlayLargerThanBacking,
    /// The backing's virtual size is smaller than the highest
    /// cluster the overlay has allocated. Maps to
    /// `CommitResult::ERROR_BACKING_TOO_SMALL` (5). Distinct
    /// from [`Self::OverlayLargerThanBacking`] because some
    /// overlays declare a larger virtual size than they have
    /// allocated.
    BackingTooSmall,
    /// The overlay's or backing's header changed during
    /// planning, or one of its internal invariants is broken.
    /// Maps to `CommitResult::ERROR_HEADER_MISMATCH` (7).
    HeaderMismatch,
    /// The overlay's metadata is internally inconsistent. Maps
    /// to `CommitResult::ERROR_OVERLAY_CORRUPT` (8).
    OverlayCorrupt,
    /// The backing's metadata is internally inconsistent. Maps
    /// to `CommitResult::ERROR_BACKING_CORRUPT` (9).
    BackingCorrupt,
    /// The caller-supplied scratch buffer is too small for the
    /// requested layout. Maps to
    /// `CommitResult::ERROR_SCRATCH_TOO_SMALL` (10).
    ScratchTooSmall,
    /// Backing allocator: every existing refcount block is
    /// full and v1 does not yet append new ones. Maps to
    /// `CommitResult::ERROR_REFCOUNT_EXHAUSTED` (11).
    RefcountExhausted,
    /// A format-specific parser failed to interpret the staged
    /// header bytes. Maps to
    /// `CommitResult::ERROR_PARSE_FAILED` (12).
    ParseFailed,
    /// An internal size or offset computation overflowed. Maps
    /// to `CommitResult::ERROR_INTERNAL_OVERFLOW` (13).
    Overflow,
}

// Re-export the per-format opts, contexts, and allocator
// helpers so downstream callers see a flat API surface.
pub use qcow2::{
    overlay_l2_byte_offset_qcow2, overlay_refcount_byte_offset_qcow2, plan_commit_qcow2,
    Qcow2CommitContext, Qcow2CommitOpts,
};
pub use vmdk::{
    allocate_backing_grain_vmdk, overlay_gte_byte_offset_vmdk, plan_commit_vmdk,
    BackingGrainAllocationState, VmdkCommitContext, VmdkCommitOpts,
};
