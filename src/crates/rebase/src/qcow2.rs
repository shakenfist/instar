//! qcow2 rebase planner.
//!
//! Step 2a ships the public surface and a stubbed entry point
//! that returns [`RebaseError::UnsupportedFormat`]. Step 2c
//! fills in safe-mode planning + allocation, and step 2b
//! finishes unsafe mode (which depends on the allocator for
//! long-path relocation).

use crate::{RebaseError, RebaseMode, RebasePatch, RebasePlan};

/// Options for [`plan_rebase_qcow2`].
///
/// The host populates this from the parsed overlay header, the
/// parsed new-backing header, and the `RebaseConfig` the guest
/// reads at runtime. Borrows are bound to the staging buffers
/// the host provides; the planner does not store anything
/// outside `scratch`.
///
/// Most fields are placeholders in step 2a and will be
/// populated as step 2b / 2c fill in the implementation. They
/// are declared here so callers can construct opts at the
/// right shape from the start.
#[derive(Debug, Clone, Copy)]
pub struct Qcow2RebaseOpts<'a> {
    /// Rebase mode.
    pub mode: RebaseMode,
    /// Overlay's cluster size in bytes (from the parsed
    /// header).
    pub overlay_cluster_size: u32,
    /// Overlay's virtual size in bytes.
    pub overlay_virtual_size: u64,
    /// Overlay's current header bytes, including any
    /// extensions. Read by the planner to compute the rewrite
    /// patch.
    pub overlay_header: &'a [u8],
    /// New backing file's virtual size. Used for
    /// compatibility checking only — the planner does not
    /// validate the backing's full metadata.
    pub new_backing_virtual_size: u64,
    /// New backing path string. The planner writes this into
    /// the overlay header (or into a freshly relocated cluster
    /// if it doesn't fit the existing slot).
    pub new_backing_path: &'a [u8],
    /// Detach flag: `new_backing_path` is empty and the
    /// overlay becomes standalone.
    pub detach: bool,
}

/// Output of [`plan_rebase_qcow2`].
///
/// Unsafe mode returns a complete plan. Safe mode returns a
/// context the guest drives at runtime plus a deferred-apply
/// header patch.
///
/// The `Unsafe` variant carries a [`RebasePlan`] (~530 bytes
/// of inline patch storage) while `Safe` is much smaller.
/// The size asymmetry is intentional — both modes share one
/// entry point so the guest's match is exhaustive — and is
/// suppressed with `allow(clippy::large_enum_variant)` to
/// match the resize crate's `ResizePlan` storage shape.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy)]
pub enum Qcow2RebaseOutput<'a> {
    /// Unsafe-mode (`-u`) output: a complete patch list ready
    /// to apply.
    Unsafe { plan: RebasePlan<'a> },
    /// Safe-mode output: a context the guest drives plus the
    /// final header rewrite to apply once the comparison loop
    /// completes.
    Safe {
        context: RebaseQcow2SafeContext<'a>,
        header_patch: RebasePatch<'a>,
    },
}

/// Context carried by the guest across safe-mode rebase's
/// per-cluster comparison loop.
///
/// All fields except scratch slices are populated by the
/// planner. The guest mutates the scratch-slice contents (the
/// staged refcount-block bytes) via the allocator helper. Once
/// the comparison loop completes, the guest is responsible for
/// flushing dirty refcount-block bytes back to the overlay
/// before applying the final header patch.
///
/// Step 2c fills in the field set; step 2a defines the type
/// so callers can match on [`Qcow2RebaseOutput::Safe`] without
/// changing later.
#[derive(Debug, Clone, Copy)]
pub struct RebaseQcow2SafeContext<'a> {
    /// Overlay cluster size in bytes (echoed from opts for
    /// convenience).
    pub overlay_cluster_size: u32,
    /// Total guest clusters the comparison loop iterates over
    /// (`overlay_virtual_size / cluster_size`).
    pub overlay_cluster_count: u64,
    /// Reserved for step 2c: scratch slice carrying the
    /// staged refcount-block bytes. Empty in step 2a.
    pub refcount_blocks: &'a [u8],
}

/// Allocator state threaded through repeated calls to
/// [`allocate_overlay_cluster_qcow2`].
///
/// The guest constructs this at the start of the comparison
/// loop and mutates it through subsequent calls; the planner
/// does not retain a reference.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllocationState {
    /// Refcount entry index where the next free-cluster scan
    /// resumes.
    pub next_scan_index: u64,
    /// Number of clusters allocated so far.
    pub allocated: u64,
}

/// Plan a qcow2 rebase.
///
/// Step 2a stub: returns [`RebaseError::UnsupportedFormat`]
/// unconditionally. Steps 2b and 2c replace this with the real
/// implementation.
pub fn plan_rebase_qcow2<'a>(
    _opts: &Qcow2RebaseOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<Qcow2RebaseOutput<'a>, RebaseError> {
    Err(RebaseError::UnsupportedFormat)
}

/// Allocate a single fresh cluster in the overlay.
///
/// Pure function: scans the staged refcount-block bytes in
/// `context.refcount_blocks` starting from
/// `state.next_scan_index`, finds the next entry whose
/// refcount is zero, bumps it to one (in place; the slice
/// must be mutable in the caller, even though it's `&[u8]`
/// here for the type-only stub), and returns the host byte
/// offset of the claimed cluster.
///
/// Step 2a stub: returns [`RebaseError::UnsupportedFormat`].
/// Step 2c fills in the actual scan/bump logic and changes
/// the slice mutability accordingly.
pub fn allocate_overlay_cluster_qcow2(
    _context: &mut RebaseQcow2SafeContext<'_>,
    _state: &mut AllocationState,
) -> Result<u64, RebaseError> {
    Err(RebaseError::UnsupportedFormat)
}
