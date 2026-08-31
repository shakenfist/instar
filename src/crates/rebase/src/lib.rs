//! Plan in-place metadata mutations to rebase disk images.
//!
//! Given the parsed header of an existing overlay image, the
//! parsed header of a new backing image, and the requested mode
//! (`-u` unsafe or default safe), the `plan_rebase_*` functions
//! in this crate return per-format outputs that describe what
//! the guest must do to make the overlay reference the new
//! backing.
//!
//! Unlike [`resize`](../../resize/), which can fully pre-compute
//! its patch list because every mutation is metadata-only,
//! rebase's safe mode is the first instar operation where the
//! planner *cannot* enumerate the work statically. Data
//! comparison between the old and new backing chains is
//! inherently a runtime operation. The split is:
//!
//! - **Unsafe mode**: the planner returns a [`RebasePlan`] of
//!   byte-level patches the guest applies in order. No runtime
//!   decisions.
//! - **Safe mode**: the planner returns a per-format *context*
//!   plus a deferred-apply metadata patch. The guest drives the
//!   per-cluster comparison loop; once the loop completes, it
//!   applies the deferred metadata patch (typically the qcow2
//!   header rewrite or the vmdk descriptor rewrite).
//!
//! For qcow2 safe mode the write composition (cluster
//! allocation, refcount staging, L2/L1 patching) lives in
//! `crates/qcow2-write` + `crates/qcow2-write-exec` since
//! phase 5 of `PLAN-qcow2-write-infrastructure`; the qcow2
//! safe context is plain overlay geometry. The vmdk safe
//! context still carries the in-crate grain allocator's staged
//! state.
//!
//! This crate is `no_std` and performs no I/O. Scratch buffers
//! are caller-supplied; returned plans and contexts borrow from
//! the scratch buffer.

#![no_std]
#![allow(clippy::too_many_arguments)]

mod qcow2;
mod vmdk;

/// Errors returned by the `plan_rebase_*` family of functions.
///
/// Mirrors the [`shared::RebaseResult::ERROR_*`] numeric codes
/// where applicable; phase 3 (the rebase guest binary) maps
/// variants to those codes when reporting back to the host.
/// Additional variants describe planner-internal conditions
/// that don't have a corresponding wire-level error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebaseError {
    /// The overlay or new backing is not a format this crate
    /// supports (qcow2 v2/v3 or vmdk monolithicSparse). Maps to
    /// `RebaseResult::ERROR_UNSUPPORTED_FORMAT`.
    UnsupportedFormat,
    /// The format is supported but the subformat isn't (e.g.
    /// vmdk twoGbMaxExtent overlay). Maps to
    /// `RebaseResult::ERROR_UNSUPPORTED_FORMAT` on the wire —
    /// only the planner distinguishes.
    UnsupportedSubformat,
    /// The new backing's virtual size is smaller than the
    /// overlay's, or its format is otherwise incompatible.
    /// Maps to `RebaseResult::ERROR_NEW_BACKING_INCOMPATIBLE`.
    NewBackingIncompatible,
    /// The overlay is a qcow2 image with the external-data-file
    /// incompatible feature set. Rebase refuses to match
    /// qemu-img. Maps to
    /// `RebaseResult::ERROR_EXTERNAL_DATA_FILE`.
    ExternalDataFile,
    /// The overlay or new backing is LUKS-wrapped. v1 of rebase
    /// refuses; a future plan can lift this. Maps to
    /// `RebaseResult::ERROR_LUKS_UNSUPPORTED`.
    LuksUnsupported,
    /// The old or new chain exceeds [`shared::MAX_CHAIN_DEVICES`].
    /// Maps to `RebaseResult::ERROR_CHAIN_DEPTH`.
    ChainDepth,
    /// The overlay's header changed during planning, or one of
    /// its internal invariants is broken (e.g. backing-file
    /// offset doesn't fall inside the first cluster). Maps to
    /// `RebaseResult::ERROR_HEADER_MISMATCH`.
    HeaderMismatch,
    /// The supplied new-backing-path is longer than the format's
    /// cap (1024 bytes for qcow2; matches `CreateConfig`). Maps
    /// to `RebaseResult::ERROR_BACKING_PATH_TOO_LONG`.
    BackingPathTooLong,
    /// The caller-supplied scratch buffer is too small for the
    /// requested layout. Maps to
    /// `RebaseResult::ERROR_SCRATCH_TOO_SMALL`.
    ScratchTooSmall,
    /// The overlay's metadata is internally inconsistent in a
    /// way the planner can detect without I/O (e.g. negative
    /// cluster index after decoding a header field). Maps to
    /// `RebaseResult::ERROR_OVERLAY_CORRUPT`.
    OverlayCorrupt,
    /// Safe-mode allocator: every existing refcount block (qcow2)
    /// or grain table (vmdk) is full and v1 does not yet append
    /// new ones. The user can fall back to `-u` mode or run
    /// `qemu-img rebase`. Maps to
    /// `RebaseResult::ERROR_REFCOUNT_EXHAUSTED`.
    RefcountExhausted,
    /// The vmdk descriptor slot is too small to hold the
    /// new-backing-reference text. Maps to
    /// `RebaseResult::ERROR_DESCRIPTOR_TOO_LARGE`.
    DescriptorTooLarge,
    /// An internal size or offset computation overflowed, or a
    /// planner tried to push a patch whose byte range falls
    /// outside the plan's target file. Maps to
    /// `RebaseResult::ERROR_INTERNAL_OVERFLOW`.
    Overflow,
    /// A format-specific parser failed to interpret the staged
    /// header bytes. Indicates either a corrupted image or a
    /// host bug. Maps to `RebaseResult::ERROR_PARSE_FAILED`.
    ParseFailed,
}

/// Mode selector for the rebase planners.
///
/// Carried in the per-format opts so callers can dispatch
/// through a single entry point per format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebaseMode {
    /// `-u` metadata-only mode. The planner emits a complete
    /// patch list; no runtime data comparison.
    Unsafe,
    /// Default mode. The planner emits a context the guest
    /// drives at runtime against the input chains.
    Safe,
}

/// A single byte-level operation against the overlay being
/// rebased.
///
/// Patches are emitted by a planner (unsafe mode) or by the
/// guest after consulting the planner's context (safe mode)
/// and applied **in order**. Ordering matters for crash
/// safety: refcount and L2 writes must precede the header
/// rewrite that brings the new backing reference into effect.
///
/// Rebase intentionally does not carry a `ZeroFill` variant
/// (cf. [`resize::ResizePatch::ZeroFill`]); the patches it
/// emits are bounded in size by the new-backing path string
/// and a handful of metadata fields.
#[derive(Debug, Clone, Copy)]
pub enum RebasePatch<'a> {
    /// Overwrite an existing byte range. Used for header field
    /// rewrites, in-place backing-path slot updates, refcount
    /// decrements, and L2 entry updates.
    Write {
        /// Absolute byte offset within the overlay file.
        byte_offset: u64,
        /// Bytes to write.
        bytes: &'a [u8],
    },
    /// Extend the overlay file by writing new bytes starting at
    /// `byte_offset`. `byte_offset` must equal the file size at
    /// the moment the patch is applied. Used by the path-
    /// relocation path when the new backing path doesn't fit
    /// the existing slot.
    Append {
        /// Absolute byte offset within the overlay file
        /// (== current EOF).
        byte_offset: u64,
        /// Bytes to write.
        bytes: &'a [u8],
    },
}

impl<'a> RebasePatch<'a> {
    /// Empty placeholder used as the default array element when
    /// building a [`RebasePlan`].
    pub const EMPTY: RebasePatch<'static> = RebasePatch::Write {
        byte_offset: 0,
        bytes: &[],
    };

    /// Byte offset where this patch starts in the overlay.
    pub fn byte_offset(&self) -> u64 {
        match self {
            RebasePatch::Write { byte_offset, .. } | RebasePatch::Append { byte_offset, .. } => {
                *byte_offset
            }
        }
    }

    /// Number of bytes this patch touches.
    pub fn len(&self) -> usize {
        match self {
            RebasePatch::Write { bytes, .. } | RebasePatch::Append { bytes, .. } => bytes.len(),
        }
    }

    /// True if the patch is a no-op (zero-length write).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Maximum number of patch entries a [`RebasePlan`] can hold.
///
/// Unsafe-mode rebase emits at most: one header-field patch,
/// one backing-path patch (or one Append when relocating), one
/// optional refcount-block patch, one optional backing-format
/// header-extension patch. Safe-mode rebase emits patches
/// indirectly through the guest's runtime loop; this constant
/// only bounds the unsafe-mode plan storage. 16 is generous.
pub const MAX_REBASE_PATCHES: usize = 16;

/// A complete in-place mutation plan for unsafe-mode rebase.
///
/// Mirrors [`resize::ResizePlan`]: patches stored inline as a
/// fixed-size array so the whole value is `Copy` and no
/// separate patches buffer is required.
#[derive(Debug, Clone, Copy)]
pub struct RebasePlan<'a> {
    /// File size the host should `ftruncate` to after applying
    /// every patch. For rebase this is typically unchanged
    /// from the pre-rebase file size; the path-relocation path
    /// grows it by a cluster.
    pub total_file_size: u64,
    /// Number of populated entries in `patches_storage`.
    patch_count: u16,
    /// Inline storage; only `..patch_count` is valid.
    patches_storage: [RebasePatch<'a>; MAX_REBASE_PATCHES],
}

impl<'a> RebasePlan<'a> {
    /// Construct an empty plan for the given target file size.
    pub const fn new(total_file_size: u64) -> Self {
        RebasePlan {
            total_file_size,
            patch_count: 0,
            patches_storage: [RebasePatch::EMPTY; MAX_REBASE_PATCHES],
        }
    }

    /// Ordered list of patches to apply.
    pub fn patches(&self) -> &[RebasePatch<'a>] {
        &self.patches_storage[..self.patch_count as usize]
    }

    /// Append a patch to the plan. Returns
    /// [`RebaseError::ScratchTooSmall`] if the plan's storage
    /// is full, or [`RebaseError::Overflow`] if the patch's
    /// byte range does not fit inside `total_file_size`.
    ///
    /// The range check is the single choke point that makes an
    /// out-of-file write unrepresentable: `patches_storage` is
    /// private, so every patch any planner emits — qcow2 or
    /// vmdk, present or future — passes through here. Both
    /// planners derive patch offsets from untrusted image
    /// metadata, and issue #485 was exactly such an offset
    /// escaping into a plan the guest would then have applied
    /// past the end of the device. Formats bound their own
    /// fields more tightly (see the qcow2 planner's
    /// first-cluster rule for the backing-path slot); this is
    /// the backstop underneath them, and it is what the fuzz
    /// harness's invariants 3 and 4 assert.
    ///
    /// `Append` is held to the same bound: `total_file_size` is
    /// the file size *after* the whole plan is applied, so a
    /// patch appending beyond it would still be a write past
    /// the final EOF.
    pub fn push(&mut self, patch: RebasePatch<'a>) -> Result<(), RebaseError> {
        let idx = self.patch_count as usize;
        if idx >= MAX_REBASE_PATCHES {
            return Err(RebaseError::ScratchTooSmall);
        }
        let (byte_offset, len) = match &patch {
            RebasePatch::Write { byte_offset, bytes }
            | RebasePatch::Append { byte_offset, bytes } => (*byte_offset, bytes.len()),
        };
        let end = byte_offset
            .checked_add(len as u64)
            .ok_or(RebaseError::Overflow)?;
        if end > self.total_file_size {
            return Err(RebaseError::Overflow);
        }
        self.patches_storage[idx] = patch;
        self.patch_count += 1;
        Ok(())
    }
}

// Re-export the per-format opts, outputs, and (vmdk-side)
// allocator helpers so downstream callers see a flat API
// surface.
pub use qcow2::{plan_rebase_qcow2, Qcow2RebaseOpts, Qcow2RebaseOutput, RebaseQcow2SafeContext};
pub use vmdk::{
    allocate_overlay_grain_vmdk, plan_rebase_vmdk, GrainAllocationState, RebaseVmdkSafeContext,
    VmdkRebaseOpts, VmdkRebaseOutput,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_methods_match_variant() {
        let p = RebasePatch::Write {
            byte_offset: 0x1000,
            bytes: &[1, 2, 3, 4],
        };
        assert_eq!(p.byte_offset(), 0x1000);
        assert_eq!(p.len(), 4);
        assert!(!p.is_empty());

        let empty = RebasePatch::EMPTY;
        assert!(empty.is_empty());
    }

    #[test]
    fn plan_push_respects_bound() {
        let mut plan = RebasePlan::new(1024);
        for i in 0..MAX_REBASE_PATCHES {
            let r = plan.push(RebasePatch::Write {
                byte_offset: i as u64,
                bytes: &[],
            });
            assert!(r.is_ok(), "push at i={i} must succeed within bound");
        }
        let overflow = plan.push(RebasePatch::EMPTY);
        assert_eq!(overflow, Err(RebaseError::ScratchTooSmall));
        assert_eq!(plan.patches().len(), MAX_REBASE_PATCHES);
    }

    /// The plan-level backstop for issue #485: no planner can
    /// place a patch that runs past the target file size, and a
    /// rejected patch is not stored.
    #[test]
    fn plan_push_rejects_patch_past_total_file_size() {
        let bytes = [0u8; 8];

        let mut plan = RebasePlan::new(1024);
        assert_eq!(
            plan.push(RebasePatch::Write {
                byte_offset: 1020,
                bytes: &bytes,
            }),
            Err(RebaseError::Overflow)
        );
        assert_eq!(plan.patches().len(), 0);

        // Ending exactly at total_file_size is legal.
        assert!(plan
            .push(RebasePatch::Write {
                byte_offset: 1016,
                bytes: &bytes,
            })
            .is_ok());
        assert_eq!(plan.patches().len(), 1);

        // Appends are held to the same final-EOF bound.
        assert_eq!(
            plan.push(RebasePatch::Append {
                byte_offset: 1024,
                bytes: &bytes,
            }),
            Err(RebaseError::Overflow)
        );

        // An offset whose end overflows u64 is caught before the
        // comparison, not wrapped into an accepted range.
        assert_eq!(
            plan.push(RebasePatch::Write {
                byte_offset: u64::MAX - 4,
                bytes: &bytes,
            }),
            Err(RebaseError::Overflow)
        );
        assert_eq!(plan.patches().len(), 1);
    }
}
