//! vmdk monolithicSparse commit planner.
//!
//! Stages the backing's grain directory + grain tables into
//! scratch and returns a [`VmdkCommitContext`] the guest
//! threads through a per-grain commit loop. The pure allocator
//! [`allocate_backing_grain_vmdk`] is a cursor bump anchored on
//! the backing's current EOF — vmdk's allocation model is
//! append-only, so commit gets new grains by extending the
//! backing past its existing data.
//!
//! v1 only allocates grains in GTs the backing already has.
//! Allocating a fresh GT (and bumping the backing's GD entry)
//! when the covering GDE is zero on the backing is a follow-up
//! tracked under "Future work" in
//! `PLAN-rebase-commit-phase-06-commit-planners.md`.

use vmdk::{Vmdk4HeaderFull, FLAG_COMPRESSED};

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
    /// `overlay_allocated_gt_count`).
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
    pub overlay_grain_size_sectors: u32,
    /// Total grains the commit loop iterates over
    /// (`overlay_virtual_size / grain_size_bytes`, rounded up).
    pub overlay_grain_count: u64,
    pub overlay_num_gtes_per_gt: u32,
    pub overlay_num_gd_entries: u32,
    pub overlay_gd_offset_sectors: u64,
    pub backing_grain_size_sectors: u32,
    pub backing_num_gtes_per_gt: u32,
    pub backing_num_gd_entries: u32,
    pub backing_gd_offset_sectors: u64,
    pub backing_allocated_gt_count: u32,
    /// Staged backing GD bytes; the GD-extension follow-up
    /// flagged in the phase plan would let the allocator
    /// flip a GDE here.
    pub backing_grain_directory: &'a mut [u8],
    /// Concatenated backing GT bytes; the guest updates the
    /// matching entry after [`allocate_backing_grain_vmdk`]
    /// returns a host offset.
    pub backing_grain_tables: &'a mut [u8],
    /// Per-GT host sectors for the backing.
    pub backing_gt_host_sectors: &'a [u64],
    /// Per-GT dirty bitmap; bit `i` set means GT `i` was
    /// mutated and the guest must flush it.
    pub backing_gt_dirty: &'a mut [u8],
    /// Single-byte GD dirty flag (non-zero = guest must
    /// flush the GD). v1 of the allocator never sets this;
    /// reserved for the GT-extension follow-up.
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

/// Plan a vmdk monolithicSparse commit.
///
/// Validates compatibility, stages the backing's GD + allocated
/// GTs into scratch, and returns a [`VmdkCommitContext`]
/// borrowing into scratch. The guest drives the per-grain
/// commit loop itself — the planner emits no patches.
pub fn plan_commit_vmdk<'a>(
    opts: &VmdkCommitOpts<'a>,
    scratch: &'a mut [u8],
) -> Result<VmdkCommitContext<'a>, CommitError> {
    // ----- Parse + validate both headers --------------------
    let overlay = Vmdk4HeaderFull::parse(opts.overlay_header).ok_or(CommitError::ParseFailed)?;
    let backing = Vmdk4HeaderFull::parse(opts.backing_header).ok_or(CommitError::ParseFailed)?;

    if (overlay.flags & FLAG_COMPRESSED) != 0 {
        return Err(CommitError::UnsupportedSubformat);
    }
    if (backing.flags & FLAG_COMPRESSED) != 0 {
        return Err(CommitError::UnsupportedSubformat);
    }

    if opts.overlay_grain_size_sectors == 0
        || opts.overlay_num_gtes_per_gt == 0
        || opts.overlay_num_gd_entries == 0
    {
        return Err(CommitError::OverlayCorrupt);
    }
    if opts.backing_grain_size_sectors == 0
        || opts.backing_num_gtes_per_gt == 0
        || opts.backing_num_gd_entries == 0
    {
        return Err(CommitError::BackingCorrupt);
    }

    if backing.virtual_size < overlay.virtual_size
        || opts.backing_virtual_size < opts.overlay_virtual_size
    {
        return Err(CommitError::OverlayLargerThanBacking);
    }

    // ----- Validate the staged overlay metadata lengths -----
    let overlay_allocated = opts.overlay_allocated_gt_count as usize;
    if opts.overlay_allocated_gt_host_sectors.len() != overlay_allocated {
        return Err(CommitError::HeaderMismatch);
    }
    let overlay_gt_size_bytes = (opts.overlay_num_gtes_per_gt as usize)
        .checked_mul(4)
        .ok_or(CommitError::Overflow)?;
    let overlay_gts_total_bytes = overlay_allocated
        .checked_mul(overlay_gt_size_bytes)
        .ok_or(CommitError::Overflow)?;
    if opts.overlay_grain_tables.len() < overlay_gts_total_bytes {
        return Err(CommitError::HeaderMismatch);
    }
    let overlay_gd_bytes = (opts.overlay_num_gd_entries as usize)
        .checked_mul(4)
        .ok_or(CommitError::Overflow)?;
    if opts.overlay_grain_directory.len() < overlay_gd_bytes {
        return Err(CommitError::HeaderMismatch);
    }

    // ----- Validate the staged backing metadata lengths -----
    let backing_allocated = opts.backing_allocated_gt_count as usize;
    if opts.backing_allocated_gt_host_sectors.len() != backing_allocated {
        return Err(CommitError::HeaderMismatch);
    }
    let backing_gt_size_bytes = (opts.backing_num_gtes_per_gt as usize)
        .checked_mul(4)
        .ok_or(CommitError::Overflow)?;
    let backing_gts_total_bytes = backing_allocated
        .checked_mul(backing_gt_size_bytes)
        .ok_or(CommitError::Overflow)?;
    if opts.backing_grain_tables.len() < backing_gts_total_bytes {
        return Err(CommitError::HeaderMismatch);
    }
    let backing_gd_bytes = (opts.backing_num_gd_entries as usize)
        .checked_mul(4)
        .ok_or(CommitError::Overflow)?;
    if opts.backing_grain_directory.len() < backing_gd_bytes {
        return Err(CommitError::HeaderMismatch);
    }

    // ----- Carve scratch (backing side only) ---------------
    let gt_dirty_bytes = backing_allocated.div_ceil(8);
    let gd_dirty_bytes = 1usize;
    let need = backing_gd_bytes
        .checked_add(backing_gts_total_bytes)
        .and_then(|v| v.checked_add(gt_dirty_bytes))
        .and_then(|v| v.checked_add(gd_dirty_bytes))
        .ok_or(CommitError::Overflow)?;
    if scratch.len() < need {
        return Err(CommitError::ScratchTooSmall);
    }

    let (gd_buf, rest) = scratch.split_at_mut(backing_gd_bytes);
    let (gt_buf, rest) = rest.split_at_mut(backing_gts_total_bytes);
    let (gt_dirty_buf, rest) = rest.split_at_mut(gt_dirty_bytes);
    let (gd_dirty_buf, _rest) = rest.split_at_mut(gd_dirty_bytes);

    gd_buf.copy_from_slice(&opts.backing_grain_directory[..backing_gd_bytes]);
    if backing_gts_total_bytes > 0 {
        gt_buf.copy_from_slice(&opts.backing_grain_tables[..backing_gts_total_bytes]);
    }
    for b in gt_dirty_buf.iter_mut() {
        *b = 0;
    }
    gd_dirty_buf[0] = 0;

    let overlay_grain_size_bytes = (opts.overlay_grain_size_sectors as u64)
        .checked_mul(512)
        .ok_or(CommitError::Overflow)?;
    if overlay_grain_size_bytes == 0 {
        return Err(CommitError::OverlayCorrupt);
    }
    let overlay_grain_count = opts.overlay_virtual_size.div_ceil(overlay_grain_size_bytes);

    Ok(VmdkCommitContext {
        overlay_grain_size_sectors: opts.overlay_grain_size_sectors,
        overlay_grain_count,
        overlay_num_gtes_per_gt: opts.overlay_num_gtes_per_gt,
        overlay_num_gd_entries: opts.overlay_num_gd_entries,
        overlay_gd_offset_sectors: opts.overlay_gd_offset_sectors,
        backing_grain_size_sectors: opts.backing_grain_size_sectors,
        backing_num_gtes_per_gt: opts.backing_num_gtes_per_gt,
        backing_num_gd_entries: opts.backing_num_gd_entries,
        backing_gd_offset_sectors: opts.backing_gd_offset_sectors,
        backing_allocated_gt_count: opts.backing_allocated_gt_count,
        backing_grain_directory: gd_buf,
        backing_grain_tables: gt_buf,
        backing_gt_host_sectors: opts.backing_allocated_gt_host_sectors,
        backing_gt_dirty: gt_dirty_buf,
        backing_gd_dirty: gd_dirty_buf,
        backing_file_size: opts.backing_file_size,
    })
}

/// Allocate a single fresh grain in the backing.
///
/// Returns the host byte offset where the new grain will
/// live. The caller is responsible for:
///
/// 1. Writing the grain's data to the returned offset.
/// 2. Updating the appropriate GTE in
///    [`VmdkCommitContext::backing_grain_tables`] to point at
///    `host_byte / 512` (LE u32 sector pointer).
/// 3. Marking the containing backing GT dirty via
///    [`VmdkCommitContext::backing_gt_dirty`].
///
/// Pure: this function only inspects
/// `context.backing_grain_size_sectors` and advances the
/// allocator cursor. v1 does not extend the backing's GD or
/// allocate new GTs — if the caller encounters a backing GDE
/// of zero it must skip the grain rather than calling this
/// allocator. The GD-extension follow-up is tracked under
/// "Future work" in the phase plan.
pub fn allocate_backing_grain_vmdk(
    context: &mut VmdkCommitContext<'_>,
    state: &mut BackingGrainAllocationState,
) -> Result<u64, CommitError> {
    let grain_sectors = context.backing_grain_size_sectors as u64;
    if grain_sectors == 0 {
        return Err(CommitError::BackingCorrupt);
    }
    let host_sector = state.next_grain_sector;
    let host_byte = host_sector.checked_mul(512).ok_or(CommitError::Overflow)?;
    let next = host_sector
        .checked_add(grain_sectors)
        .ok_or(CommitError::Overflow)?;
    state.next_grain_sector = next;
    state.allocated = state
        .allocated
        .checked_add(1)
        .ok_or(CommitError::Overflow)?;
    Ok(host_byte)
}

/// Compute the disk byte offset of a given GTE within a grain
/// table at the given host sector.
///
/// Pure function: `gt_host_sector * 512 + gte_idx_in_gt * 4`.
/// Works for both the overlay's GTs (read by the guest at
/// commit time) and the backing's GTs (looked up from the
/// staged GD).
pub fn overlay_gte_byte_offset_vmdk(gt_host_sector: u64, gte_idx_in_gt: u32) -> u64 {
    gt_host_sector * 512 + (gte_idx_in_gt as u64) * 4
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const VMDK_MAGIC: u32 = 0x564d_444b; // "VMDK"

    /// Build a minimal Vmdk4 binary header.
    fn make_header(virtual_size_sectors: u64) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[0..4].copy_from_slice(&VMDK_MAGIC.to_le_bytes());
        h[4..8].copy_from_slice(&3u32.to_le_bytes()); // version
        h[8..12].copy_from_slice(&0u32.to_le_bytes()); // flags
        h[12..20].copy_from_slice(&virtual_size_sectors.to_le_bytes()); // capacity
        h[20..28].copy_from_slice(&128u64.to_le_bytes()); // grain_size_sectors = 64K
        h[28..36].copy_from_slice(&1u64.to_le_bytes()); // desc_offset_sectors
        h[36..44].copy_from_slice(&20u64.to_le_bytes()); // desc_size_sectors
        h[44..48].copy_from_slice(&512u32.to_le_bytes()); // num_gtes_per_gt
        h[48..56].copy_from_slice(&0u64.to_le_bytes()); // rgd_offset
        h[56..64].copy_from_slice(&21u64.to_le_bytes()); // gd_offset_sectors
        h[64..72].copy_from_slice(&21u64.to_le_bytes()); // overhead_sectors
        h
    }

    fn baseline_opts<'a>(
        overlay_hdr: &'a [u8],
        backing_hdr: &'a [u8],
        gd: &'a [u8],
        gt: &'a [u8],
        gt_hosts: &'a [u64],
        num_gd_entries: u32,
        num_gtes_per_gt: u32,
        virtual_size: u64,
    ) -> VmdkCommitOpts<'a> {
        VmdkCommitOpts {
            overlay_header: overlay_hdr,
            overlay_descriptor: &[],
            overlay_grain_size_sectors: 128,
            overlay_num_gtes_per_gt: num_gtes_per_gt,
            overlay_num_gd_entries: num_gd_entries,
            overlay_gd_offset_sectors: 21,
            overlay_grain_directory: gd,
            overlay_grain_tables: gt,
            overlay_allocated_gt_host_sectors: gt_hosts,
            overlay_allocated_gt_count: gt_hosts.len() as u32,
            overlay_virtual_size: virtual_size,
            overlay_file_size: virtual_size,
            backing_header: backing_hdr,
            backing_descriptor: &[],
            backing_grain_size_sectors: 128,
            backing_num_gtes_per_gt: num_gtes_per_gt,
            backing_num_gd_entries: num_gd_entries,
            backing_gd_offset_sectors: 21,
            backing_grain_directory: gd,
            backing_grain_tables: gt,
            backing_allocated_gt_host_sectors: gt_hosts,
            backing_allocated_gt_count: gt_hosts.len() as u32,
            backing_virtual_size: virtual_size,
            backing_file_size: virtual_size,
        }
    }

    #[test]
    fn plan_populates_geometry() {
        let virtual_sectors = (64 * 1024 * 1024u64) / 512;
        let oh = make_header(virtual_sectors);
        let bh = make_header(virtual_sectors);
        let gd = [0u8; 4]; // 1 GD entry × 4 bytes
        let gt = [0u8; 2048]; // 1 GT × 512 GTEs × 4 bytes
        let gt_hosts = [4096u64];
        let mut scratch = [0u8; 8192];
        let opts = baseline_opts(&oh, &bh, &gd, &gt, &gt_hosts, 1, 512, 64 * 1024 * 1024);
        let ctx = plan_commit_vmdk(&opts, &mut scratch).expect("plan ok");
        assert_eq!(ctx.overlay_grain_size_sectors, 128);
        assert_eq!(ctx.backing_grain_size_sectors, 128);
        assert_eq!(ctx.overlay_grain_count, (64 * 1024 * 1024) / (128 * 512));
        assert_eq!(ctx.backing_allocated_gt_count, 1);
        assert_eq!(ctx.backing_grain_directory.len(), 4);
        assert_eq!(ctx.backing_grain_tables.len(), 2048);
        assert_eq!(ctx.backing_gt_dirty.len(), 1);
        assert_eq!(ctx.backing_gd_dirty.len(), 1);
        assert_eq!(ctx.backing_gd_dirty[0], 0);
    }

    #[test]
    fn rejects_backing_smaller_than_overlay() {
        let oh = make_header(128 * 1024);
        let bh = make_header(64 * 1024);
        let gd = [0u8; 4];
        let gt = [0u8; 2048];
        let gt_hosts = [4096u64];
        let mut scratch = [0u8; 8192];
        let opts = VmdkCommitOpts {
            overlay_virtual_size: 64 * 1024 * 1024,
            backing_virtual_size: 32 * 1024 * 1024,
            ..baseline_opts(&oh, &bh, &gd, &gt, &gt_hosts, 1, 512, 64 * 1024 * 1024)
        };
        let r = plan_commit_vmdk(&opts, &mut scratch);
        assert_eq!(r.err(), Some(CommitError::OverlayLargerThanBacking));
    }

    #[test]
    fn allocator_lands_at_eof_and_advances() {
        let virtual_sectors = (64 * 1024 * 1024u64) / 512;
        let oh = make_header(virtual_sectors);
        let bh = make_header(virtual_sectors);
        let gd = [0u8; 4];
        let gt = [0u8; 2048];
        let gt_hosts = [4096u64];
        let mut scratch = [0u8; 8192];
        let file_size_at_plan: u64 = 21 * 512 + 4 + 2048; // header + desc + gd + gt
        let opts = VmdkCommitOpts {
            backing_file_size: file_size_at_plan,
            ..baseline_opts(&oh, &bh, &gd, &gt, &gt_hosts, 1, 512, 64 * 1024 * 1024)
        };
        let mut ctx = plan_commit_vmdk(&opts, &mut scratch).expect("plan ok");
        let mut state =
            BackingGrainAllocationState::at_eof(file_size_at_plan, ctx.backing_grain_size_sectors)
                .expect("init");
        let a = allocate_backing_grain_vmdk(&mut ctx, &mut state).expect("alloc a");
        let b = allocate_backing_grain_vmdk(&mut ctx, &mut state).expect("alloc b");
        let grain_bytes = (ctx.backing_grain_size_sectors as u64) * 512;
        assert!(a >= file_size_at_plan);
        assert!(a.is_multiple_of(grain_bytes));
        assert_eq!(b, a + grain_bytes);
        assert_eq!(state.allocated, 2);
    }

    #[test]
    fn allocator_rejects_zero_grain_size() {
        let virtual_sectors = (64 * 1024 * 1024u64) / 512;
        let oh = make_header(virtual_sectors);
        let bh = make_header(virtual_sectors);
        let gd = [0u8; 4];
        let gt = [0u8; 2048];
        let gt_hosts = [4096u64];
        let mut scratch = [0u8; 8192];
        let opts = baseline_opts(&oh, &bh, &gd, &gt, &gt_hosts, 1, 512, 64 * 1024 * 1024);
        let mut ctx = plan_commit_vmdk(&opts, &mut scratch).expect("plan ok");
        ctx.backing_grain_size_sectors = 0;
        let mut state = BackingGrainAllocationState::default();
        let r = allocate_backing_grain_vmdk(&mut ctx, &mut state);
        assert_eq!(r.err(), Some(CommitError::BackingCorrupt));
    }

    #[test]
    fn at_eof_aligns_to_grain_boundary() {
        // file size midway through a grain; expect rounding up.
        let st = BackingGrainAllocationState::at_eof(0x1100, 128).expect("ok");
        // grain_bytes = 128 * 512 = 0x10000. Next aligned >=
        // 0x1100 is 0x10000.
        assert_eq!(st.next_grain_sector * 512, 0x10000);
    }

    #[test]
    fn overlay_gte_byte_offset_is_pure() {
        // GT at sector 100, entry 3 -> 100*512 + 3*4 = 51212
        assert_eq!(overlay_gte_byte_offset_vmdk(100, 3), 100 * 512 + 12);
    }
}
