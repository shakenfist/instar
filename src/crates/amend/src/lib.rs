//! Plan in-place qcow2 amend (header) mutations.
//!
//! Given the first header cluster of an existing qcow2 image and
//! the requested option changes (compat version up/down, lazy
//! refcounts on/off), [`plan_amend_qcow2`] returns an
//! [`AmendPlan`] describing the action ([`AmendAction::NoOp`] or
//! [`AmendAction::Amended`]), the resulting version / lazy state,
//! and the byte-level header patch(es) to apply — or an
//! [`AmendError`] mapping to a [`shared::AmendResult::ERROR_*`]
//! wire code.
//!
//! This crate is `no_std` and performs no I/O. The scratch buffer
//! is caller-supplied; returned patches borrow from it. The
//! planner is the correctness core of amend: it owns every
//! refusal decision and the byte-exact header rewrite. Phase 3
//! (the guest op) reads the cluster, calls this planner, applies
//! the patches, and reports the result.
//!
//! Unlike [`qcow2::create::build_header`] — which always emits a
//! fresh v3 header and cannot preserve arbitrary existing
//! extensions — amend must preserve the image's existing
//! extension bytes verbatim and target either version, so it
//! carries its own copy-and-adjust header serializer (see
//! [`qcow2::plan_amend_qcow2`]'s rebuild path).

#![no_std]

mod qcow2;

/// Errors returned by [`plan_amend_qcow2`].
///
/// Each variant maps 1:1 to a [`shared::AmendResult::ERROR_*`]
/// wire code via [`AmendError::error_code`]. Phase 3 (the amend
/// guest binary) reports that code back to the host.
///
/// Note: `ERROR_HEADER_MISMATCH (6)` and `ERROR_WRITE_FAILED
/// (10)` have no variant here — they are guest-side concerns (the
/// host/guest cross-check and the device write), surfaced in
/// phase 3, not by the pure planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmendError {
    /// Input is not qcow2 / nonsensical. Maps to
    /// `AmendResult::ERROR_UNSUPPORTED_FORMAT` (1).
    UnsupportedFormat,
    /// An unrecognised / unsupported option reached the planner.
    /// Maps to `AmendResult::ERROR_INVALID_OPTION` (2).
    InvalidOption,
    /// `compat=0.10` refused because a v3 incompatible feature is
    /// set. Maps to `AmendResult::ERROR_DOWNGRADE_BLOCKED_FEATURE`
    /// (3).
    DowngradeBlockedFeature,
    /// `compat=0.10` refused because `refcount_bits != 16`. Maps
    /// to `AmendResult::ERROR_DOWNGRADE_REFCOUNT_WIDTH` (4).
    DowngradeRefcountWidth,
    /// `lazy_refcounts=on` requested against a v2 target. Maps to
    /// `AmendResult::ERROR_LAZY_REQUIRES_V3` (5).
    LazyRequiresV3,
    /// `QcowHeader::parse` failed on the staged header. Maps to
    /// `AmendResult::ERROR_PARSE_FAILED` (7).
    ParseFailed,
    /// `INCOMPAT_DIRTY`/`INCOMPAT_CORRUPT` is set; refuse to amend
    /// an image another writer may hold open. Maps to
    /// `AmendResult::ERROR_DIRTY` (8).
    Dirty,
    /// A version change would have to relocate header extensions /
    /// the backing string past the cluster end. Maps to
    /// `AmendResult::ERROR_EXTENSION_RELOCATION_UNSUPPORTED` (9).
    ExtensionRelocationUnsupported,
    /// The caller-supplied scratch buffer is too small. Maps to
    /// `AmendResult::ERROR_SCRATCH_TOO_SMALL` (11).
    ScratchTooSmall,
    /// An internal size or offset computation overflowed. Maps to
    /// `AmendResult::ERROR_INTERNAL_OVERFLOW` (12).
    Overflow,
}

impl AmendError {
    /// The [`shared::AmendResult::ERROR_*`] wire code for this
    /// variant.
    pub fn error_code(&self) -> u32 {
        use shared::AmendResult as R;
        match self {
            AmendError::UnsupportedFormat => R::ERROR_UNSUPPORTED_FORMAT,
            AmendError::InvalidOption => R::ERROR_INVALID_OPTION,
            AmendError::DowngradeBlockedFeature => R::ERROR_DOWNGRADE_BLOCKED_FEATURE,
            AmendError::DowngradeRefcountWidth => R::ERROR_DOWNGRADE_REFCOUNT_WIDTH,
            AmendError::LazyRequiresV3 => R::ERROR_LAZY_REQUIRES_V3,
            AmendError::ParseFailed => R::ERROR_PARSE_FAILED,
            AmendError::Dirty => R::ERROR_DIRTY,
            AmendError::ExtensionRelocationUnsupported => R::ERROR_EXTENSION_RELOCATION_UNSUPPORTED,
            AmendError::ScratchTooSmall => R::ERROR_SCRATCH_TOO_SMALL,
            AmendError::Overflow => R::ERROR_INTERNAL_OVERFLOW,
        }
    }
}

/// A single byte-level operation against the image being amended.
///
/// Patches are emitted by [`plan_amend_qcow2`] and applied **in
/// order** by the guest. Amend touches only the first header
/// cluster: either a single 8-byte selective write (lazy toggle)
/// or a full single-cluster header rewrite (version change).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmendPatch<'a> {
    /// Overwrite an existing byte range in the header cluster.
    Write {
        /// Absolute byte offset within the image file.
        byte_offset: u64,
        /// Bytes to write.
        bytes: &'a [u8],
    },
}

impl<'a> AmendPatch<'a> {
    /// Empty placeholder used as the default array element when
    /// building an [`AmendPlan`].
    pub const EMPTY: AmendPatch<'static> = AmendPatch::Write {
        byte_offset: 0,
        bytes: &[],
    };

    /// Byte offset where this patch starts in the image.
    pub fn byte_offset(&self) -> u64 {
        match self {
            AmendPatch::Write { byte_offset, .. } => *byte_offset,
        }
    }

    /// Number of bytes this patch touches.
    pub fn len(&self) -> usize {
        match self {
            AmendPatch::Write { bytes, .. } => bytes.len(),
        }
    }

    /// True if the patch is a no-op (zero-length write).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Maximum number of patch entries an [`AmendPlan`] can hold.
///
/// Amend emits at most one patch today (a single lazy-toggle
/// write or a single full-cluster rewrite); 2 leaves headroom.
pub const MAX_AMEND_PATCHES: usize = 2;

/// The action [`plan_amend_qcow2`] decided on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmendAction {
    /// The requested options already matched the header; nothing
    /// to rewrite (zero patches).
    NoOp,
    /// The header is (or would be) rewritten by the emitted
    /// patches.
    Amended,
}

/// A complete amend plan.
///
/// Mirrors [`rebase::RebasePlan`]: patches stored inline as a
/// fixed-size array so the whole value is `Copy`.
#[derive(Clone, Copy)]
pub struct AmendPlan<'a> {
    /// The action decided on.
    pub action: AmendAction,
    /// qcow2 version (2 or 3) after the amend completes.
    pub resulting_version: u32,
    /// Lazy-refcounts state after the amend completes.
    pub resulting_lazy_refcounts: bool,
    /// Number of populated entries in `patches_storage`.
    patch_count: u8,
    /// Inline storage; only `..patch_count` is valid.
    patches_storage: [AmendPatch<'a>; MAX_AMEND_PATCHES],
}

impl<'a> AmendPlan<'a> {
    /// Construct an empty plan with the given resulting state.
    pub const fn new(
        action: AmendAction,
        resulting_version: u32,
        resulting_lazy_refcounts: bool,
    ) -> Self {
        AmendPlan {
            action,
            resulting_version,
            resulting_lazy_refcounts,
            patch_count: 0,
            patches_storage: [AmendPatch::EMPTY; MAX_AMEND_PATCHES],
        }
    }

    /// Ordered list of patches to apply.
    pub fn patches(&self) -> &[AmendPatch<'a>] {
        &self.patches_storage[..self.patch_count as usize]
    }

    /// Append a patch to the plan. Returns
    /// [`AmendError::ScratchTooSmall`] if the plan's storage is
    /// full.
    pub fn push(&mut self, patch: AmendPatch<'a>) -> Result<(), AmendError> {
        let idx = self.patch_count as usize;
        if idx >= MAX_AMEND_PATCHES {
            return Err(AmendError::ScratchTooSmall);
        }
        self.patches_storage[idx] = patch;
        self.patch_count += 1;
        Ok(())
    }
}

/// Options for [`plan_amend_qcow2`].
///
/// The planner derives the current version / lazy / features
/// entirely from `header_cluster`; host-probed cross-check fields
/// are validated by the guest (phase 3), keeping the planner pure
/// and unit-testable.
pub struct Qcow2AmendOpts<'a> {
    /// The whole first cluster of the image.
    pub header_cluster: &'a [u8],
    /// Cluster size in bytes.
    pub cluster_size: u32,
    /// True if the compat (version) target was specified.
    pub set_compat: bool,
    /// Target version: v3 if true, v2 if false. Meaningful only
    /// when `set_compat`.
    pub target_v3: bool,
    /// True if the lazy-refcounts target was specified.
    pub set_lazy: bool,
    /// Target lazy state. Meaningful only when `set_lazy`.
    pub lazy_on: bool,
}

pub use qcow2::plan_amend_qcow2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_match_wire() {
        use shared::AmendResult as R;
        assert_eq!(
            AmendError::UnsupportedFormat.error_code(),
            R::ERROR_UNSUPPORTED_FORMAT
        );
        assert_eq!(
            AmendError::InvalidOption.error_code(),
            R::ERROR_INVALID_OPTION
        );
        assert_eq!(
            AmendError::DowngradeBlockedFeature.error_code(),
            R::ERROR_DOWNGRADE_BLOCKED_FEATURE
        );
        assert_eq!(
            AmendError::DowngradeRefcountWidth.error_code(),
            R::ERROR_DOWNGRADE_REFCOUNT_WIDTH
        );
        assert_eq!(
            AmendError::LazyRequiresV3.error_code(),
            R::ERROR_LAZY_REQUIRES_V3
        );
        assert_eq!(AmendError::ParseFailed.error_code(), R::ERROR_PARSE_FAILED);
        assert_eq!(AmendError::Dirty.error_code(), R::ERROR_DIRTY);
        assert_eq!(
            AmendError::ExtensionRelocationUnsupported.error_code(),
            R::ERROR_EXTENSION_RELOCATION_UNSUPPORTED
        );
        assert_eq!(
            AmendError::ScratchTooSmall.error_code(),
            R::ERROR_SCRATCH_TOO_SMALL
        );
        assert_eq!(
            AmendError::Overflow.error_code(),
            R::ERROR_INTERNAL_OVERFLOW
        );
    }

    #[test]
    fn plan_push_respects_bound() {
        let mut plan = AmendPlan::new(AmendAction::Amended, 3, false);
        for i in 0..MAX_AMEND_PATCHES {
            let r = plan.push(AmendPatch::Write {
                byte_offset: i as u64,
                bytes: &[],
            });
            assert!(r.is_ok(), "push at i={i} must succeed within bound");
        }
        let overflow = plan.push(AmendPatch::EMPTY);
        assert_eq!(overflow, Err(AmendError::ScratchTooSmall));
        assert_eq!(plan.patches().len(), MAX_AMEND_PATCHES);
    }
}
