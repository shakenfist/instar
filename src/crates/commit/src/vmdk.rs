//! vmdk monolithicSparse commit planner.
//!
//! Step 6a ships scaffolding only: the type surface and a
//! stub [`plan_commit_vmdk`] that returns
//! [`CommitError::UnsupportedFormat`]. Step 6c fills in the
//! validation, the grain allocator, and the geometry decoder
//! helpers the guest binary needs.

use crate::CommitError;

/// Options for [`plan_commit_vmdk`].
#[derive(Debug, Clone, Copy)]
pub struct VmdkCommitOpts<'a> {
    /// Overlay's binary header (first sector).
    pub overlay_header: &'a [u8],
    /// Overlay's descriptor bytes
    /// (`desc_size_sectors * 512`).
    pub overlay_descriptor: &'a [u8],
    /// Overlay grain size in sectors.
    pub overlay_grain_size_sectors: u32,
    /// Grain table entries per GT on the overlay.
    pub overlay_num_gtes_per_gt: u32,
    /// Number of GD entries on the overlay.
    pub overlay_num_gd_entries: u32,
    /// Overlay's grain directory offset in sectors.
    pub overlay_gd_offset_sectors: u64,
    /// Staged overlay grain-directory bytes.
    pub overlay_grain_directory: &'a [u8],
    /// Concatenated overlay grain-table bytes (one block per
    /// allocated GT).
    pub overlay_grain_tables: &'a [u8],
    /// Per-allocated-GT host sectors (length =
    /// overlay_allocated_gt_count).
    pub overlay_allocated_gt_host_sectors: &'a [u64],
    /// Number of allocated GTs staged.
    pub overlay_allocated_gt_count: u32,
    /// Overlay's virtual size in bytes.
    pub overlay_virtual_size: u64,
    /// Overlay's current file size.
    pub overlay_file_size: u64,

    /// Backing's binary header.
    pub backing_header: &'a [u8],
    /// Backing's descriptor bytes.
    pub backing_descriptor: &'a [u8],
    /// Backing's grain size in sectors.
    pub backing_grain_size_sectors: u32,
    /// Grain table entries per GT on the backing.
    pub backing_num_gtes_per_gt: u32,
    /// Number of GD entries on the backing.
    pub backing_num_gd_entries: u32,
    /// Backing's grain directory offset in sectors.
    pub backing_gd_offset_sectors: u64,
    /// Staged backing grain-directory bytes.
    pub backing_grain_directory: &'a [u8],
    /// Concatenated backing grain-table bytes.
    pub backing_grain_tables: &'a [u8],
    /// Per-allocated-GT host sectors for the backing.
    pub backing_allocated_gt_host_sectors: &'a [u64],
    /// Number of allocated GTs in the backing.
    pub backing_allocated_gt_count: u32,
    /// Backing's virtual size.
    pub backing_virtual_size: u64,
    /// Backing's current file size — anchor for the grain
    /// allocator's EOF cursor.
    pub backing_file_size: u64,
}

/// Context carried by the guest across the vmdk commit loop.
#[derive(Debug)]
pub struct VmdkCommitContext<'a> {
    /// Overlay grain size in sectors.
    pub overlay_grain_size_sectors: u32,
    /// Total grains the commit loop iterates over
    /// (`overlay_virtual_size / grain_size_bytes`, rounded up).
    pub overlay_grain_count: u64,
    /// Echoed `overlay_num_gtes_per_gt`.
    pub overlay_num_gtes_per_gt: u32,
    /// Number of GD entries on the overlay.
    pub overlay_num_gd_entries: u32,
    /// Overlay GD offset (sectors).
    pub overlay_gd_offset_sectors: u64,
    /// Backing grain size in sectors.
    pub backing_grain_size_sectors: u32,
    /// Backing num GTEs per GT.
    pub backing_num_gtes_per_gt: u32,
    /// Backing num GD entries.
    pub backing_num_gd_entries: u32,
    /// Backing GD offset (sectors).
    pub backing_gd_offset_sectors: u64,
    /// Number of staged backing GTs.
    pub backing_allocated_gt_count: u32,
    /// Staged backing GD bytes; the GD-extension follow-up
    /// flagged in the phase plan would let the allocator
    /// flip a GDE here.
    pub backing_grain_directory: &'a mut [u8],
    /// Concatenated backing GT bytes; the allocator updates
    /// the matching entry when the guest writes the
    /// allocator's returned host offset into the GT.
    pub backing_grain_tables: &'a mut [u8],
    /// Per-GT host sectors for the backing.
    pub backing_gt_host_sectors: &'a [u64],
    /// Per-GT dirty bitmap; bit `i` set means GT `i` was
    /// mutated and the guest must flush it.
    pub backing_gt_dirty: &'a mut [u8],
    /// Whether the staged backing GD bytes are dirty
    /// (GD extension follow-up).
    pub backing_gd_dirty: &'a mut [u8],
    /// Backing's current file size — start point for the EOF
    /// cursor.
    pub backing_file_size: u64,
}

/// Allocator state threaded through repeated calls to
/// [`allocate_backing_grain_vmdk`].
#[derive(Debug, Clone, Copy, Default)]
pub struct BackingGrainAllocationState {
    /// Next host sector the allocator will hand out.
    pub next_grain_sector: u64,
    /// Total grains allocated so far in the backing.
    pub allocated: u64,
}

impl BackingGrainAllocationState {
    /// Construct an allocator state anchored at the backing's
    /// current EOF (rounded up to a grain boundary).
    pub fn at_eof(backing_file_size: u64, grain_size_sectors: u32) -> Result<Self, CommitError> {
        if grain_size_sectors == 0 {
            return Err(CommitError::BackingCorrupt);
        }
        let grain_bytes = (grain_size_sectors as u64)
            .checked_mul(512)
            .ok_or(CommitError::Overflow)?;
        let rounded = if backing_file_size.is_multiple_of(grain_bytes) {
            backing_file_size
        } else {
            backing_file_size
                .checked_add(grain_bytes - (backing_file_size % grain_bytes))
                .ok_or(CommitError::Overflow)?
        };
        Ok(Self {
            next_grain_sector: rounded / 512,
            allocated: 0,
        })
    }
}

/// Plan a vmdk commit.
///
/// Step 6a stub: returns `UnsupportedFormat`. Step 6c fills
/// this in.
pub fn plan_commit_vmdk<'a>(
    _opts: &VmdkCommitOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<VmdkCommitContext<'a>, CommitError> {
    Err(CommitError::UnsupportedFormat)
}

/// Allocate a single fresh grain in the backing.
///
/// Step 6a stub: returns `UnsupportedFormat`. Step 6c fills
/// this in.
pub fn allocate_backing_grain_vmdk(
    _context: &mut VmdkCommitContext<'_>,
    _state: &mut BackingGrainAllocationState,
) -> Result<u64, CommitError> {
    Err(CommitError::UnsupportedFormat)
}

/// Compute the disk byte offset of a given GTE on the
/// overlay's grain table at `gt_host_sector`.
///
/// Step 6a stub: returns 0. Step 6c implements.
pub fn overlay_gte_byte_offset_vmdk(
    _context: &VmdkCommitContext<'_>,
    _gt_host_sector: u64,
    _gte_idx_in_gt: u32,
) -> u64 {
    0
}
