//! vmdk monolithicSparse rebase planner.
//!
//! Step 2a ships the public surface and a stubbed entry point
//! that returns [`RebaseError::UnsupportedFormat`]. Step 2d
//! fills in unsafe mode; step 2e fills in safe mode plus the
//! grain allocator.

use crate::{RebaseError, RebaseMode, RebasePatch, RebasePlan};

/// Options for [`plan_rebase_vmdk`].
///
/// The host populates this from the parsed overlay header,
/// the existing descriptor bytes, the new backing's CID (read
/// from its own descriptor on the host side), and the
/// `RebaseConfig` the guest reads at runtime.
#[derive(Debug, Clone, Copy)]
pub struct VmdkRebaseOpts<'a> {
    /// Rebase mode.
    pub mode: RebaseMode,
    /// Overlay's virtual size in bytes.
    pub overlay_virtual_size: u64,
    /// Overlay's existing descriptor bytes (the planner
    /// rewrites this slot).
    pub overlay_descriptor: &'a [u8],
    /// Overlay's existing descriptor size in bytes (the slot
    /// the rewrite must fit into).
    pub overlay_descriptor_size: u32,
    /// Byte offset of the descriptor within the overlay file.
    pub overlay_descriptor_offset: u64,
    /// New backing's virtual size. Used for compatibility
    /// checking.
    pub new_backing_virtual_size: u64,
    /// New backing path string. Written into the rewritten
    /// descriptor's `parentFileNameHint=` line.
    pub new_backing_path: &'a [u8],
    /// New parent CID. The host reads this from the new
    /// backing's own descriptor before populating the opts.
    pub new_parent_cid: u32,
    /// Detach flag: `new_backing_path` is empty and the
    /// overlay becomes standalone.
    pub detach: bool,
}

/// Output of [`plan_rebase_vmdk`].
///
/// Unsafe mode returns a complete plan. Safe mode returns a
/// context the guest drives at runtime plus a deferred-apply
/// descriptor patch.
///
/// Same size asymmetry as [`crate::Qcow2RebaseOutput`]; see
/// that type's docs for the rationale.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy)]
pub enum VmdkRebaseOutput<'a> {
    /// Unsafe-mode (`-u`) output: a complete patch list ready
    /// to apply.
    Unsafe { plan: RebasePlan<'a> },
    /// Safe-mode output: a context the guest drives plus the
    /// final descriptor rewrite to apply once the comparison
    /// loop completes.
    Safe {
        context: RebaseVmdkSafeContext<'a>,
        descriptor_patch: RebasePatch<'a>,
    },
}

/// Context carried by the guest across safe-mode rebase's
/// per-grain comparison loop.
///
/// Step 2e fills in the field set; step 2a defines the type
/// so callers can match on [`VmdkRebaseOutput::Safe`] without
/// changing later.
#[derive(Debug, Clone, Copy)]
pub struct RebaseVmdkSafeContext<'a> {
    /// Overlay grain size in sectors (echoed from opts).
    pub overlay_grain_size_sectors: u32,
    /// Total guest grains the comparison loop iterates over.
    pub overlay_grain_count: u64,
    /// Reserved for step 2e: scratch slice carrying the
    /// staged grain-directory bytes. Empty in step 2a.
    pub grain_directory: &'a [u8],
}

/// Allocator state threaded through repeated calls to
/// [`allocate_overlay_grain_vmdk`].
#[derive(Debug, Clone, Copy, Default)]
pub struct GrainAllocationState {
    /// Grain-directory entry index where the next free-grain
    /// scan resumes.
    pub next_gde_index: u32,
    /// Grain-table entry index within the current grain table
    /// where the scan resumes.
    pub next_gte_index: u32,
    /// Number of grains allocated so far.
    pub allocated: u64,
}

/// Plan a vmdk monolithicSparse rebase.
///
/// Step 2a stub: returns [`RebaseError::UnsupportedFormat`]
/// unconditionally. Steps 2d and 2e replace this with the real
/// implementation.
pub fn plan_rebase_vmdk<'a>(
    _opts: &VmdkRebaseOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<VmdkRebaseOutput<'a>, RebaseError> {
    Err(RebaseError::UnsupportedFormat)
}

/// Allocate a single fresh grain in the overlay.
///
/// Step 2a stub: returns [`RebaseError::UnsupportedFormat`].
/// Step 2e fills in the scan logic for vmdk's two-level grain
/// directory layout.
pub fn allocate_overlay_grain_vmdk(
    _context: &mut RebaseVmdkSafeContext<'_>,
    _state: &mut GrainAllocationState,
) -> Result<u64, RebaseError> {
    Err(RebaseError::UnsupportedFormat)
}
