//! Plan in-place metadata mutations to commit overlay
//! clusters into a backing image.
//!
//! Given the parsed headers of the overlay and the backing,
//! and the host-pre-staged refcount blocks of the backing, the
//! `plan_commit_*` functions in this crate return a per-format
//! *context* the guest threads through a per-cluster commit
//! loop. Unlike rebase (where unsafe mode could pre-compute a
//! complete patch list), commit is always data-aware: every
//! commit reads overlay cluster data and writes it into the
//! backing. There is no `Unsafe` mode and the planner returns
//! the context directly rather than an `Output` enum.
//!
//! Workflow:
//!
//! 1. The host pre-probes the overlay and backing headers and
//!    pre-reads the backing's refcount table + every refcount
//!    block it points at into a buffer it hands to the planner
//!    via `Qcow2CommitOpts` / `VmdkCommitOpts`.
//! 2. The planner validates inputs (LUKS / external-data-file
//!    refusal, virtual-size compatibility, geometry sanity),
//!    copies the backing's refcount blocks into scratch, and
//!    returns a `*CommitContext` borrowing into scratch.
//! 3. The guest iterates the overlay's allocated clusters,
//!    calling [`allocate_backing_cluster_qcow2`] (or the vmdk
//!    analogue) when the backing doesn't already have a
//!    cluster at the matching guest offset. The pure allocator
//!    mutates the staged refcount blocks; the guest emits the
//!    data write, the backing L2 update, and finally the
//!    overlay-clear writes (zero the L2 entry, zero the
//!    refcount entry on the overlay).
//! 4. After the comparison loop the guest flushes the dirty
//!    refcount blocks back to the backing.
//!
//! This crate is `no_std` and performs no I/O. Scratch buffers
//! are caller-supplied; returned contexts borrow from the
//! scratch buffer.

#![no_std]
#![allow(clippy::too_many_arguments)]

mod qcow2;
mod vmdk;

/// Errors returned by the `plan_commit_*` family of functions.
///
/// Mirrors the [`shared::CommitResult::ERROR_*`] numeric codes
/// where applicable; phase 7 (the commit guest binary) maps
/// variants to those codes when reporting back to the host.
/// Additional variants describe planner-internal conditions
/// that don't have a corresponding wire-level error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitError {
    /// The overlay or backing is not a format this crate
    /// supports (qcow2 v2/v3 or vmdk monolithicSparse).
    UnsupportedFormat,
    /// The format is supported but the subformat isn't (e.g.
    /// vmdk twoGbMaxExtent overlay).
    UnsupportedSubformat,
    /// The overlay is a qcow2 image with the external-data-file
    /// incompatible feature set. Commit refuses to match
    /// qemu-img.
    ExternalDataFile,
    /// The overlay or backing is LUKS-wrapped. v1 of commit
    /// refuses; a future plan can lift this.
    LuksUnsupported,
    /// The backing's virtual size is smaller than the
    /// overlay's. Commit refuses to truncate guest data.
    OverlayLargerThanBacking,
    /// The backing's virtual size is smaller than the highest
    /// cluster the overlay has allocated. Distinct from
    /// [`Self::OverlayLargerThanBacking`] because some overlays
    /// declare a larger virtual size than they have allocated.
    BackingTooSmall,
    /// The overlay's or backing's header changed during
    /// planning, or one of its internal invariants is broken.
    HeaderMismatch,
    /// The overlay's metadata is internally inconsistent.
    OverlayCorrupt,
    /// The backing's metadata is internally inconsistent.
    BackingCorrupt,
    /// The caller-supplied scratch buffer is too small for the
    /// requested layout.
    ScratchTooSmall,
    /// Backing allocator: every existing refcount block is
    /// full and v1 does not yet append new ones.
    RefcountExhausted,
    /// A format-specific parser failed to interpret the staged
    /// header bytes.
    ParseFailed,
    /// An internal size or offset computation overflowed.
    Overflow,
}

/// A single byte-level operation against either the backing
/// or the overlay.
///
/// Commit emits patches sparingly — the bulk of the work is
/// runtime data writes the guest issues directly. The
/// [`CommitPatch::Write`] variant is the only shape currently
/// in use; an `Append` variant is intentionally absent because
/// commit never grows the backing past its existing EOF in v1.
#[derive(Debug, Clone, Copy)]
pub enum CommitPatch<'a> {
    /// Overwrite an existing byte range. The patch carries no
    /// indication of which file it targets; the guest knows
    /// based on which slot it pulls the patch from.
    Write {
        /// Absolute byte offset within the target file.
        byte_offset: u64,
        /// Bytes to write.
        bytes: &'a [u8],
    },
}

impl<'a> CommitPatch<'a> {
    /// Empty placeholder used as the default array element when
    /// building a [`CommitPlan`].
    pub const EMPTY: CommitPatch<'static> = CommitPatch::Write {
        byte_offset: 0,
        bytes: &[],
    };

    /// Byte offset where this patch starts in its target file.
    pub fn byte_offset(&self) -> u64 {
        match self {
            CommitPatch::Write { byte_offset, .. } => *byte_offset,
        }
    }

    /// Number of bytes this patch touches.
    pub fn len(&self) -> usize {
        match self {
            CommitPatch::Write { bytes, .. } => bytes.len(),
        }
    }

    /// True if the patch is a no-op (zero-length write).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Maximum number of patch entries a [`CommitPlan`] can hold.
///
/// 16 is generous; the planner currently emits zero patches.
/// The plan storage exists for the dry-run / preview shape
/// flagged in the phase plan's open question 2.
pub const MAX_COMMIT_PATCHES: usize = 16;

/// A bounded collection of [`CommitPatch`] entries.
///
/// Mirrors [`rebase::RebasePlan`] in shape; commit's planner
/// returns an empty plan today, but the type exists so the
/// dry-run / preview surface can populate it without an ABI
/// break.
#[derive(Debug, Clone, Copy)]
pub struct CommitPlan<'a> {
    /// File size the backing should end up at after applying
    /// every patch. Equals the backing's pre-commit file size
    /// for v1 (no growth).
    pub total_file_size: u64,
    /// Number of populated entries in `patches_storage`.
    patch_count: u16,
    /// Inline storage; only `..patch_count` is valid.
    patches_storage: [CommitPatch<'a>; MAX_COMMIT_PATCHES],
}

impl<'a> CommitPlan<'a> {
    /// Construct an empty plan for the given target file size.
    pub const fn new(total_file_size: u64) -> Self {
        CommitPlan {
            total_file_size,
            patch_count: 0,
            patches_storage: [CommitPatch::EMPTY; MAX_COMMIT_PATCHES],
        }
    }

    /// Ordered list of patches to apply.
    pub fn patches(&self) -> &[CommitPatch<'a>] {
        &self.patches_storage[..self.patch_count as usize]
    }

    /// Append a patch to the plan. Returns
    /// [`CommitError::ScratchTooSmall`] if the plan's storage
    /// is full.
    pub fn push(&mut self, patch: CommitPatch<'a>) -> Result<(), CommitError> {
        let idx = self.patch_count as usize;
        if idx >= MAX_COMMIT_PATCHES {
            return Err(CommitError::ScratchTooSmall);
        }
        self.patches_storage[idx] = patch;
        self.patch_count += 1;
        Ok(())
    }
}

// Re-export the per-format opts, contexts, and allocator
// helpers so downstream callers see a flat API surface.
pub use qcow2::{
    allocate_backing_cluster_qcow2, overlay_l2_byte_offset_qcow2,
    overlay_refcount_byte_offset_qcow2, plan_commit_qcow2, BackingAllocationState,
    Qcow2CommitContext, Qcow2CommitOpts,
};
pub use vmdk::{
    allocate_backing_grain_vmdk, overlay_gte_byte_offset_vmdk, plan_commit_vmdk,
    BackingGrainAllocationState, VmdkCommitContext, VmdkCommitOpts,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_methods_match_variant() {
        let p = CommitPatch::Write {
            byte_offset: 0x1000,
            bytes: &[1, 2, 3, 4],
        };
        assert_eq!(p.byte_offset(), 0x1000);
        assert_eq!(p.len(), 4);
        assert!(!p.is_empty());

        let empty = CommitPatch::EMPTY;
        assert!(empty.is_empty());
    }

    #[test]
    fn plan_push_respects_bound() {
        let mut plan = CommitPlan::new(1024);
        for i in 0..MAX_COMMIT_PATCHES {
            let r = plan.push(CommitPatch::Write {
                byte_offset: i as u64,
                bytes: &[],
            });
            assert!(r.is_ok(), "push at i={i} must succeed within bound");
        }
        let overflow = plan.push(CommitPatch::EMPTY);
        assert_eq!(overflow, Err(CommitError::ScratchTooSmall));
        assert_eq!(plan.patches().len(), MAX_COMMIT_PATCHES);
    }
}
