//! qcow2 commit planner.
//!
//! Step 6a ships scaffolding only: the type surface and a
//! stub [`plan_commit_qcow2`] that returns
//! [`CommitError::UnsupportedFormat`]. Step 6b fills in the
//! validation, the backing allocator, and the geometry
//! decoder helpers the guest binary needs.

use crate::CommitError;

/// Options for [`plan_commit_qcow2`].
///
/// Borrows are bound to the lifetime of the caller's staging
/// data. The planner does not retain anything outside
/// `scratch`; lifetimes on the output are bound to `scratch`,
/// not to the opts.
#[derive(Debug, Clone, Copy)]
pub struct Qcow2CommitOpts<'a> {
    /// Overlay's current header bytes (at least 105 bytes for
    /// v2 / 4 KiB for v3 with extensions). The planner re-
    /// parses the header internally to avoid trusting host-
    /// pre-probed fields.
    pub overlay_header: &'a [u8],
    /// Overlay's current file size in bytes.
    pub overlay_file_size: u64,
    /// Backing's current header bytes.
    pub backing_header: &'a [u8],
    /// Backing's current file size in bytes (also the anchor
    /// the allocator uses for the "no growth in v1" invariant).
    pub backing_file_size: u64,
    /// Backing's refcount-table bytes (an array of u64 BE
    /// entries pointing at refcount blocks). Used to validate
    /// the host-supplied refblock_host_offsets array.
    pub backing_refcount_table: &'a [u8],
    /// Host byte offsets of each backing refcount block.
    /// Length must equal `backing_refblock_count`. The
    /// allocator mutates the staged refcount-block bytes; the
    /// guest uses these offsets to flush dirty blocks back to
    /// the backing.
    pub backing_refblock_host_offsets: &'a [u64],
    /// Concatenated backing refcount-block bytes
    /// (`backing_refblock_count * cluster_size` bytes). The
    /// planner copies these into scratch for the allocator to
    /// mutate.
    pub backing_refcount_blocks: &'a [u8],
    /// Number of refcount blocks present in
    /// `backing_refcount_blocks`.
    pub backing_refblock_count: u32,
}

/// Context carried by the guest across the commit
/// per-cluster loop.
///
/// All numeric fields are populated by the planner. The two
/// slice fields are views into the caller's scratch buffer
/// that the allocator mutates as it claims clusters. The
/// guest is responsible for flushing the dirty refcount-block
/// bytes back to the backing once the commit loop completes
/// (it knows where each block lives via the
/// `backing_refblock_host_offsets` it passed in via opts).
#[derive(Debug)]
pub struct Qcow2CommitContext<'a> {
    /// Overlay cluster size in bytes (echoed from the parsed
    /// overlay header).
    pub overlay_cluster_size: u32,
    /// Total guest clusters the commit loop iterates over
    /// (`overlay.virtual_size / cluster_size`, rounded up).
    pub overlay_cluster_count: u64,
    /// Overlay L1 table offset in the overlay file.
    pub overlay_l1_table_offset: u64,
    /// Overlay L1 size in entries.
    pub overlay_l1_size: u32,
    /// Overlay refcount-table offset (used by the overlay-
    /// clear pass to compute which refcount block + entry
    /// corresponds to a given host offset).
    pub overlay_refcount_table_offset: u64,
    /// Overlay refcount-table size in clusters.
    pub overlay_refcount_table_clusters: u32,
    /// Overlay refcount entry width in bits. v1 supports 16
    /// only on both sides.
    pub overlay_refcount_bits: u32,
    /// Backing cluster size in bytes.
    pub backing_cluster_size: u32,
    /// Backing total guest clusters
    /// (`backing.virtual_size / cluster_size`, rounded up).
    pub backing_cluster_count: u64,
    /// Backing L1 table offset.
    pub backing_l1_table_offset: u64,
    /// Backing L1 size in entries.
    pub backing_l1_size: u32,
    /// Backing refcount entry width in bits. v1 supports 16.
    pub backing_refcount_bits: u32,
    /// Refcount entries per backing refcount block.
    pub backing_entries_per_refblock: u64,
    /// Number of refcount blocks present in
    /// `backing_refblocks`.
    pub backing_refblock_count: u32,
    /// Staged backing refcount-block bytes, mutated in place
    /// by the allocator.
    pub backing_refblocks: &'a mut [u8],
    /// Echoed from opts so the guest can flush dirty blocks
    /// back without re-parsing the refcount table.
    pub backing_refblock_host_offsets: &'a [u64],
    /// Per-refblock dirty bitmap; bit `i` is set if the
    /// allocator has modified refblock `i`. Length is
    /// `(backing_refblock_count + 7) / 8`.
    pub backing_dirty: &'a mut [u8],
}

/// Allocator state threaded through repeated calls to
/// [`allocate_backing_cluster_qcow2`].
///
/// The guest constructs this at the start of the commit loop
/// and mutates it through subsequent calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct BackingAllocationState {
    /// Refblock index where the next scan resumes.
    pub next_refblock: u32,
    /// Entry index within the current refblock where the next
    /// scan resumes.
    pub next_entry_in_refblock: u64,
    /// Total clusters allocated so far in the backing.
    pub allocated: u64,
}

/// Plan a qcow2 commit.
///
/// Step 6a stub: returns `UnsupportedFormat`. Step 6b fills
/// this in.
pub fn plan_commit_qcow2<'a>(
    _opts: &Qcow2CommitOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<Qcow2CommitContext<'a>, CommitError> {
    Err(CommitError::UnsupportedFormat)
}

/// Allocate a single fresh cluster in the backing.
///
/// Step 6a stub: returns `UnsupportedFormat`. Step 6b fills
/// this in.
pub fn allocate_backing_cluster_qcow2(
    _context: &mut Qcow2CommitContext<'_>,
    _state: &mut BackingAllocationState,
) -> Result<u64, CommitError> {
    Err(CommitError::UnsupportedFormat)
}

/// Compute the disk byte offset of the L2 entry covering a
/// given guest cluster on the overlay.
///
/// Step 6a stub: returns 0. Step 6b implements the lookup
/// against the staged L1 table the guest has read.
pub fn overlay_l2_byte_offset_qcow2(
    _context: &Qcow2CommitContext<'_>,
    _overlay_l1_entry: u64,
    _l2_idx_in_table: u64,
) -> u64 {
    0
}

/// Compute the disk byte offset of the refcount entry for a
/// given overlay host offset.
///
/// Step 6a stub: returns `(0, 0)`. Step 6b implements.
pub fn overlay_refcount_byte_offset_qcow2(
    _context: &Qcow2CommitContext<'_>,
    _overlay_host_offset: u64,
) -> (u64, u8) {
    (0, 0)
}
