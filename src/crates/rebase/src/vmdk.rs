//! vmdk monolithicSparse rebase planner.
//!
//! - **Unsafe mode** (step 2d) emits a descriptor rewrite that
//!   substitutes `parentCID=` and `parentFileNameHint=` while
//!   preserving every other descriptor line.
//! - **Safe mode** (step 2e) emits a [`RebaseVmdkSafeContext`]
//!   that carries the staged grain-directory and grain-table
//!   bytes (mutated by the allocator as the guest decides to
//!   copy a grain), plus the same descriptor rewrite as a
//!   deferred-apply metadata patch.
//!
//! vmdk's allocation model is append-only: every newly claimed
//! grain lives at a fresh host sector beyond the file's current
//! EOF. The allocator therefore tracks a `next_grain_sector`
//! cursor instead of scanning a refcount space. The "free GTE"
//! invariant the brief calls out is the *caller's* job: the
//! guest iterates GTEs in the staged grain-tables, only invokes
//! [`allocate_overlay_grain_vmdk`] when it encounters a slot
//! that needs a copy, and writes the returned host offset back
//! into the GTE itself.

use crate::{RebaseError, RebaseMode, RebasePatch, RebasePlan};

/// Maximum bytes the descriptor rewriter will emit. Keeps the
/// scratch carve-out bounded and matches the typical 10 KiB
/// descriptor slot vmdk monolithicSparse uses.
pub const MAX_DESCRIPTOR_REWRITE_LEN: usize = 64 * 1024;

/// Options for [`plan_rebase_vmdk`].
///
/// The first block of fields is required in both modes. The
/// `safe_*` block is consulted only when `mode ==
/// RebaseMode::Safe`; unsafe-mode callers can leave those
/// fields at their default-ish values (zero / empty slices).
#[derive(Debug, Clone, Copy)]
pub struct VmdkRebaseOpts<'a> {
    /// Rebase mode.
    pub mode: RebaseMode,
    /// Overlay's virtual size in bytes.
    pub overlay_virtual_size: u64,
    /// Overlay's existing descriptor bytes (the planner
    /// rewrites this slot).
    pub overlay_descriptor: &'a [u8],
    /// Overlay's existing descriptor slot size in bytes.
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
    /// Ignored when `detach` is set.
    pub new_parent_cid: u32,
    /// Detach flag: emit `parentCID=ffffffff` and an empty
    /// `parentFileNameHint=` line, matching qemu-img's detach
    /// convention.
    pub detach: bool,
    /// Overlay grain size in sectors (echoed from the parsed
    /// binary header). Safe mode only.
    pub overlay_grain_size_sectors: u32,
    /// Number of GTEs per GT (echoed from the parsed header;
    /// almost always 512). Safe mode only.
    pub num_gtes_per_gt: u32,
    /// Number of GD entries required to cover the overlay's
    /// virtual size. Safe mode only.
    pub num_gd_entries: u32,
    /// Sector offset of the grain directory in the overlay
    /// file. Safe mode only.
    pub gd_offset_sectors: u64,
    /// Overlay file size in bytes at planning time. The
    /// allocator's `next_grain_sector` cursor is initialised
    /// to this value (rounded up to a grain boundary) so new
    /// grains land beyond the current EOF.
    pub overlay_file_size: u64,
    /// Existing grain-directory bytes (LE u32 per slot; a
    /// zero entry means the corresponding GT is unallocated).
    /// Safe mode only.
    pub overlay_grain_directory: &'a [u8],
    /// Concatenated grain-table bytes, one block per entry in
    /// [`Self::allocated_gt_host_sectors`]. Each block is
    /// `num_gtes_per_gt * 4` bytes of LE u32 grain pointers.
    /// Safe mode only.
    pub overlay_grain_tables: &'a [u8],
    /// Host sector offsets of each allocated GT in the overlay
    /// file. Length must equal `allocated_gt_count`. Safe mode
    /// only.
    pub allocated_gt_host_sectors: &'a [u64],
    /// Number of allocated GTs whose bytes were supplied in
    /// `overlay_grain_tables`. Safe mode only.
    pub allocated_gt_count: u32,
}

impl<'a> VmdkRebaseOpts<'a> {
    /// Build an opts value with the safe-mode fields zeroed
    /// out. Convenient for unsafe-mode callers; the safe-mode
    /// planner returns
    /// [`RebaseError::OverlayCorrupt`] if invoked against the
    /// resulting opts.
    pub fn unsafe_only(
        overlay_virtual_size: u64,
        overlay_descriptor: &'a [u8],
        overlay_descriptor_size: u32,
        overlay_descriptor_offset: u64,
        new_backing_virtual_size: u64,
        new_backing_path: &'a [u8],
        new_parent_cid: u32,
        detach: bool,
    ) -> Self {
        VmdkRebaseOpts {
            mode: RebaseMode::Unsafe,
            overlay_virtual_size,
            overlay_descriptor,
            overlay_descriptor_size,
            overlay_descriptor_offset,
            new_backing_virtual_size,
            new_backing_path,
            new_parent_cid,
            detach,
            overlay_grain_size_sectors: 0,
            num_gtes_per_gt: 0,
            num_gd_entries: 0,
            gd_offset_sectors: 0,
            overlay_file_size: 0,
            overlay_grain_directory: &[],
            overlay_grain_tables: &[],
            allocated_gt_host_sectors: &[],
            allocated_gt_count: 0,
        }
    }
}

/// Output of [`plan_rebase_vmdk`].
///
/// Not `Copy` — the safe-mode context carries `&mut` borrows
/// into scratch. The size asymmetry between the two variants
/// is unrelated; it is suppressed with
/// `allow(large_enum_variant)`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum VmdkRebaseOutput<'a> {
    /// Unsafe-mode (`-u`) output.
    Unsafe { plan: RebasePlan<'a> },
    /// Safe-mode output: a runtime context the guest threads
    /// through the per-grain comparison loop plus a deferred
    /// descriptor rewrite to apply once the loop completes.
    Safe {
        context: RebaseVmdkSafeContext<'a>,
        deferred_metadata: RebasePlan<'a>,
    },
}

/// Context carried by the guest across safe-mode rebase's
/// per-grain comparison loop.
///
/// All numeric fields are populated by the planner. The
/// `grain_directory`, `grain_tables`, `gt_dirty`, and
/// `gd_dirty` slices are views into the caller's scratch
/// buffer that the guest mutates as it allocates grains and
/// updates GTEs. Once the comparison loop completes, the
/// guest flushes:
///
/// - Each dirty GT's bytes back to its host sector
///   (`gt_host_sectors[i]` for the *i*th GT in
///   `grain_tables`).
/// - The full GD if `gd_dirty[0]` is non-zero (only happens
///   when a fresh GT is referenced — not yet implemented in
///   v1; the allocator only fills slots in already-allocated
///   GTs).
/// - The deferred descriptor patch (last, after every other
///   mutation has been written).
#[derive(Debug)]
pub struct RebaseVmdkSafeContext<'a> {
    /// Overlay grain size in sectors.
    pub overlay_grain_size_sectors: u32,
    /// Total guest grains the comparison loop iterates
    /// (`overlay.virtual_size` rounded up to a grain).
    pub overlay_grain_count: u64,
    /// Number of GTEs per GT.
    pub num_gtes_per_gt: u32,
    /// Number of GD entries needed for the virtual size.
    pub num_gd_entries: u32,
    /// Sector offset of the GD in the overlay file.
    pub gd_offset_sectors: u64,
    /// Number of GTs whose bytes are staged in
    /// `grain_tables`. The `i`th GT's bytes live at
    /// `grain_tables[i * gt_size_bytes .. (i + 1) *
    /// gt_size_bytes]`, where `gt_size_bytes =
    /// num_gtes_per_gt * 4`.
    pub allocated_gt_count: u32,
    /// Staged grain-directory bytes (mutated when the guest
    /// references a fresh GT; v1 leaves this untouched).
    pub grain_directory: &'a mut [u8],
    /// Staged grain-table bytes, concatenated in the same
    /// order as `gt_host_sectors`. The guest writes new grain
    /// pointers here as it allocates.
    pub grain_tables: &'a mut [u8],
    /// Host sector offsets of each allocated GT.
    pub gt_host_sectors: &'a [u64],
    /// Per-GT dirty bitmap; bit `i` is set when GT `i` has
    /// been modified by an allocation. Length is
    /// `(allocated_gt_count + 7) / 8`.
    pub gt_dirty: &'a mut [u8],
    /// Single-byte GD dirty flag (non-zero = guest must flush
    /// the GD). v1 of the allocator never sets this; reserved
    /// for the GT-extension follow-up.
    pub gd_dirty: &'a mut [u8],
}

/// Allocator state threaded through repeated calls to
/// [`allocate_overlay_grain_vmdk`].
///
/// The guest constructs this at the start of the comparison
/// loop. The initial `next_grain_sector` should be the
/// overlay's current EOF in sectors, rounded up to a multiple
/// of `overlay_grain_size_sectors` so the first grain lands
/// on a grain boundary.
#[derive(Debug, Clone, Copy, Default)]
pub struct GrainAllocationState {
    /// Next host sector to claim.
    pub next_grain_sector: u64,
    /// Total grains allocated so far.
    pub allocated: u64,
}

impl GrainAllocationState {
    /// Construct an allocator state that places new grains
    /// starting at the next grain-aligned sector at or after
    /// `overlay_file_size` bytes.
    pub fn at_eof(overlay_file_size: u64, grain_size_sectors: u32) -> Option<Self> {
        if grain_size_sectors == 0 {
            return None;
        }
        let gs = grain_size_sectors as u64;
        let sector = overlay_file_size.checked_div(512)?;
        let aligned = sector.checked_add(gs.checked_sub(1)?)? / gs * gs;
        Some(GrainAllocationState {
            next_grain_sector: aligned,
            allocated: 0,
        })
    }
}

/// Allocate a single fresh grain in the overlay.
///
/// Returns the host byte offset where the new grain will
/// live. The caller is responsible for:
///
/// 1. Writing the grain's data to the returned offset.
/// 2. Updating the GTE in [`RebaseVmdkSafeContext::grain_tables`]
///    to point at `host_byte / 512` (LE u32 sector pointer).
/// 3. Marking the containing GT dirty via
///    [`RebaseVmdkSafeContext::gt_dirty`].
///
/// Pure: this function only inspects
/// `context.overlay_grain_size_sectors` and advances the
/// allocator cursor. v1 does not extend the GD or allocate
/// new GTs — if the caller encounters an unallocated GD slot
/// (GDE == 0) it must skip the grain rather than calling
/// this allocator, falling back to `-u` mode for that case.
pub fn allocate_overlay_grain_vmdk(
    context: &mut RebaseVmdkSafeContext<'_>,
    state: &mut GrainAllocationState,
) -> Result<u64, RebaseError> {
    let grain_sectors = context.overlay_grain_size_sectors as u64;
    if grain_sectors == 0 {
        return Err(RebaseError::OverlayCorrupt);
    }
    let host_sector = state.next_grain_sector;
    let host_byte = host_sector.checked_mul(512).ok_or(RebaseError::Overflow)?;
    let next = host_sector
        .checked_add(grain_sectors)
        .ok_or(RebaseError::Overflow)?;
    state.next_grain_sector = next;
    state.allocated = state
        .allocated
        .checked_add(1)
        .ok_or(RebaseError::Overflow)?;
    Ok(host_byte)
}

/// Plan a vmdk monolithicSparse rebase.
pub fn plan_rebase_vmdk<'a>(
    opts: &VmdkRebaseOpts<'a>,
    scratch: &'a mut [u8],
) -> Result<VmdkRebaseOutput<'a>, RebaseError> {
    if opts.detach && !opts.new_backing_path.is_empty() {
        return Err(RebaseError::HeaderMismatch);
    }
    if opts.new_backing_path.len() > MAX_DESCRIPTOR_REWRITE_LEN {
        return Err(RebaseError::BackingPathTooLong);
    }
    if !opts.detach && opts.new_backing_virtual_size < opts.overlay_virtual_size {
        return Err(RebaseError::NewBackingIncompatible);
    }

    match opts.mode {
        RebaseMode::Unsafe => plan_vmdk_unsafe(opts, scratch),
        RebaseMode::Safe => plan_vmdk_safe(opts, scratch),
    }
}

fn plan_vmdk_unsafe<'a>(
    opts: &VmdkRebaseOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<VmdkRebaseOutput<'a>, RebaseError> {
    let slot_size = opts.overlay_descriptor_size as usize;
    if scratch.len() < slot_size {
        return Err(RebaseError::ScratchTooSmall);
    }

    let written = rewrite_descriptor(
        opts.overlay_descriptor,
        opts.new_backing_path,
        opts.new_parent_cid,
        opts.detach,
        &mut scratch[..slot_size],
    )?;
    // Zero-pad the rest of the slot so the patch covers the
    // full descriptor region (qemu-img's parsers stop at the
    // first NUL, so this matches its in-memory model).
    for b in scratch[written..slot_size].iter_mut() {
        *b = 0;
    }

    // The descriptor rewrite mutates an existing region in
    // place; the file size doesn't change. Match the qcow2
    // unsafe planner (line 411) which initialises
    // `RebasePlan::new(opts.overlay_file_size)`. Earlier this
    // function used `RebasePlan::new(0)`, which left callers
    // (and the phase-10 fuzz harness) with no way to bound
    // the patch's range — the bug surfaced on the very first
    // fuzz run.
    let patch_bytes: &'a [u8] = &scratch[..slot_size];
    let mut plan = RebasePlan::new(opts.overlay_file_size);
    plan.push(RebasePatch::Write {
        byte_offset: opts.overlay_descriptor_offset,
        bytes: patch_bytes,
    })?;

    Ok(VmdkRebaseOutput::Unsafe { plan })
}

fn plan_vmdk_safe<'a>(
    opts: &VmdkRebaseOpts<'a>,
    scratch: &'a mut [u8],
) -> Result<VmdkRebaseOutput<'a>, RebaseError> {
    if opts.overlay_grain_size_sectors == 0 || opts.num_gtes_per_gt == 0 {
        return Err(RebaseError::OverlayCorrupt);
    }
    if opts.num_gd_entries == 0 {
        return Err(RebaseError::OverlayCorrupt);
    }

    let allocated_gt_count = opts.allocated_gt_count as usize;
    if opts.allocated_gt_host_sectors.len() != allocated_gt_count {
        return Err(RebaseError::HeaderMismatch);
    }
    let gt_size_bytes = (opts.num_gtes_per_gt as usize)
        .checked_mul(4)
        .ok_or(RebaseError::Overflow)?;
    let gts_total_bytes = allocated_gt_count
        .checked_mul(gt_size_bytes)
        .ok_or(RebaseError::Overflow)?;
    if opts.overlay_grain_tables.len() < gts_total_bytes {
        return Err(RebaseError::HeaderMismatch);
    }
    let gd_bytes = (opts.num_gd_entries as usize)
        .checked_mul(4)
        .ok_or(RebaseError::Overflow)?;
    if opts.overlay_grain_directory.len() < gd_bytes {
        return Err(RebaseError::HeaderMismatch);
    }

    let descriptor_slot = opts.overlay_descriptor_size as usize;
    let gt_dirty_bytes = allocated_gt_count.div_ceil(8);
    let gd_dirty_bytes = 1usize;
    let need = descriptor_slot
        .checked_add(gd_bytes)
        .and_then(|v| v.checked_add(gts_total_bytes))
        .and_then(|v| v.checked_add(gt_dirty_bytes))
        .and_then(|v| v.checked_add(gd_dirty_bytes))
        .ok_or(RebaseError::Overflow)?;
    if scratch.len() < need {
        return Err(RebaseError::ScratchTooSmall);
    }

    let (desc_buf, rest) = scratch.split_at_mut(descriptor_slot);
    let (gd_buf, rest) = rest.split_at_mut(gd_bytes);
    let (gt_buf, rest) = rest.split_at_mut(gts_total_bytes);
    let (gt_dirty_buf, rest) = rest.split_at_mut(gt_dirty_bytes);
    let (gd_dirty_buf, _rest) = rest.split_at_mut(gd_dirty_bytes);

    gd_buf.copy_from_slice(&opts.overlay_grain_directory[..gd_bytes]);
    if gts_total_bytes > 0 {
        gt_buf.copy_from_slice(&opts.overlay_grain_tables[..gts_total_bytes]);
    }
    for b in gt_dirty_buf.iter_mut() {
        *b = 0;
    }
    gd_dirty_buf[0] = 0;

    // Deferred descriptor rewrite — same shape as unsafe mode.
    let written = rewrite_descriptor(
        opts.overlay_descriptor,
        opts.new_backing_path,
        opts.new_parent_cid,
        opts.detach,
        desc_buf,
    )?;
    for b in desc_buf[written..].iter_mut() {
        *b = 0;
    }
    let patch_bytes: &'a [u8] = desc_buf;

    let mut plan = RebasePlan::new(opts.overlay_file_size);
    plan.push(RebasePatch::Write {
        byte_offset: opts.overlay_descriptor_offset,
        bytes: patch_bytes,
    })?;

    let grain_size_bytes = (opts.overlay_grain_size_sectors as u64)
        .checked_mul(512)
        .ok_or(RebaseError::Overflow)?;
    if grain_size_bytes == 0 {
        return Err(RebaseError::OverlayCorrupt);
    }
    let overlay_grain_count = opts.overlay_virtual_size.div_ceil(grain_size_bytes);

    let context = RebaseVmdkSafeContext {
        overlay_grain_size_sectors: opts.overlay_grain_size_sectors,
        overlay_grain_count,
        num_gtes_per_gt: opts.num_gtes_per_gt,
        num_gd_entries: opts.num_gd_entries,
        gd_offset_sectors: opts.gd_offset_sectors,
        allocated_gt_count: opts.allocated_gt_count,
        grain_directory: gd_buf,
        grain_tables: gt_buf,
        gt_host_sectors: opts.allocated_gt_host_sectors,
        gt_dirty: gt_dirty_buf,
        gd_dirty: gd_dirty_buf,
    };

    Ok(VmdkRebaseOutput::Safe {
        context,
        deferred_metadata: plan,
    })
}

/// Rewrite a vmdk descriptor with new `parentCID=` and
/// `parentFileNameHint=` values.
///
/// Walks the source descriptor line-by-line. Lines starting
/// with `parentCID=` and `parentFileNameHint=` are replaced;
/// other lines are copied verbatim. If neither line was
/// present in the source, the replacements are appended after
/// the `CID=` line (or at the top if even that's missing).
///
/// Returns the number of bytes written to `dest`, or
/// [`RebaseError::DescriptorTooLarge`] if the rewrite would
/// exceed the destination slot.
fn rewrite_descriptor(
    source: &[u8],
    new_path: &[u8],
    new_parent_cid: u32,
    detach: bool,
    dest: &mut [u8],
) -> Result<usize, RebaseError> {
    // Trim source at first NUL to match the parser's
    // conventions.
    let source_end = source.iter().position(|&b| b == 0).unwrap_or(source.len());
    let source = &source[..source_end];

    let mut pos = 0usize;
    let mut saw_parent_cid = false;
    let mut saw_parent_hint = false;

    let cid_value = if detach { 0xffff_ffff } else { new_parent_cid };

    let mut line_start = 0usize;
    while line_start < source.len() {
        let line_end = source[line_start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| line_start + p)
            .unwrap_or(source.len());
        let line = &source[line_start..line_end];

        if line.starts_with(b"parentCID=") {
            pos = write_parent_cid_line(dest, pos, cid_value)?;
            saw_parent_cid = true;
        } else if line.starts_with(b"parentFileNameHint=") {
            pos = write_parent_hint_line(dest, pos, new_path, detach)?;
            saw_parent_hint = true;
        } else {
            pos = copy_line(dest, pos, line)?;
        }

        if line_end < source.len() {
            // Preserve the newline.
            pos = put_byte(dest, pos, b'\n')?;
        }

        // Insert missing parent lines right after the first
        // `CID=` line, matching the descriptor layout
        // create::build_vmdk_descriptor_with_backing emits.
        if line.starts_with(b"CID=") && !saw_parent_cid {
            pos = write_parent_cid_line(dest, pos, cid_value)?;
            pos = put_byte(dest, pos, b'\n')?;
            saw_parent_cid = true;
        }

        line_start = line_end + 1;
    }

    // If the source had no CID line at all, the parent lines
    // weren't inserted above; append them at the end so the
    // descriptor still parses.
    if !saw_parent_cid {
        pos = write_parent_cid_line(dest, pos, cid_value)?;
        pos = put_byte(dest, pos, b'\n')?;
    }
    if !saw_parent_hint {
        pos = write_parent_hint_line(dest, pos, new_path, detach)?;
        pos = put_byte(dest, pos, b'\n')?;
    }

    Ok(pos)
}

fn put_byte(dest: &mut [u8], pos: usize, b: u8) -> Result<usize, RebaseError> {
    if pos >= dest.len() {
        return Err(RebaseError::DescriptorTooLarge);
    }
    dest[pos] = b;
    Ok(pos + 1)
}

fn copy_line(dest: &mut [u8], pos: usize, line: &[u8]) -> Result<usize, RebaseError> {
    let end = pos.checked_add(line.len()).ok_or(RebaseError::Overflow)?;
    if end > dest.len() {
        return Err(RebaseError::DescriptorTooLarge);
    }
    dest[pos..end].copy_from_slice(line);
    Ok(end)
}

fn write_parent_cid_line(
    dest: &mut [u8],
    pos: usize,
    parent_cid: u32,
) -> Result<usize, RebaseError> {
    let mut pos = copy_line(dest, pos, b"parentCID=")?;
    let mut buf = [0u8; 8];
    let hex = format_u32_hex8(parent_cid, &mut buf);
    pos = copy_line(dest, pos, hex)?;
    Ok(pos)
}

fn write_parent_hint_line(
    dest: &mut [u8],
    pos: usize,
    path: &[u8],
    detach: bool,
) -> Result<usize, RebaseError> {
    let mut pos = copy_line(dest, pos, b"parentFileNameHint=\"")?;
    if !detach {
        pos = copy_line(dest, pos, path)?;
    }
    pos = copy_line(dest, pos, b"\"")?;
    Ok(pos)
}

/// Format a u32 as a fixed-width 8-character lowercase hex
/// string (matches qemu-img's parentCID format).
fn format_u32_hex8(val: u32, buf: &mut [u8; 8]) -> &[u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, slot) in buf.iter_mut().enumerate() {
        let nibble = (val >> ((7 - i) * 4)) & 0xf;
        *slot = HEX[nibble as usize];
    }
    &buf[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DESCRIPTOR: &[u8] = b"# Disk DescriptorFile\n\
        version=1\n\
        CID=fffffffe\n\
        parentCID=ffffffff\n\
        createType=\"monolithicSparse\"\n\
        parentFileNameHint=\"old.vmdk\"\n\
        \n\
        # Extent description\n\
        RW 2097152 SPARSE \"output.vmdk\"\n\
        \n\
        # The Disk Data Base\n\
        #DDB\n";

    fn unsafe_opts<'a>(
        descriptor: &'a [u8],
        new_path: &'a [u8],
        cid: u32,
        detach: bool,
    ) -> VmdkRebaseOpts<'a> {
        VmdkRebaseOpts::unsafe_only(
            1024 * 1024 * 1024,
            descriptor,
            1024,
            512,
            if detach { 0 } else { 1024 * 1024 * 1024 },
            new_path,
            cid,
            detach,
        )
    }

    #[test]
    fn rewrites_parent_cid_and_hint() {
        let mut dest = [0u8; 4096];
        let n = rewrite_descriptor(
            SAMPLE_DESCRIPTOR,
            b"new.vmdk",
            0x1234_5678,
            false,
            &mut dest,
        )
        .unwrap();
        let out = core::str::from_utf8(&dest[..n]).unwrap();
        assert!(out.contains("parentCID=12345678"));
        assert!(out.contains("parentFileNameHint=\"new.vmdk\""));
        // Other lines preserved.
        assert!(out.contains("CID=fffffffe"));
        assert!(out.contains("createType=\"monolithicSparse\""));
        assert!(out.contains("RW 2097152 SPARSE \"output.vmdk\""));
        // No leftover old path.
        assert!(!out.contains("old.vmdk"));
    }

    #[test]
    fn detach_uses_sentinel_and_empty_path() {
        let mut dest = [0u8; 4096];
        let n = rewrite_descriptor(SAMPLE_DESCRIPTOR, b"", 0, true, &mut dest).unwrap();
        let out = core::str::from_utf8(&dest[..n]).unwrap();
        assert!(out.contains("parentCID=ffffffff"));
        assert!(out.contains("parentFileNameHint=\"\""));
    }

    #[test]
    fn inserts_missing_lines_after_cid() {
        // Descriptor without parentCID or parentFileNameHint;
        // rewriter should insert them after CID=.
        let src =
            b"# Disk DescriptorFile\nversion=1\nCID=fffffffe\ncreateType=\"monolithicSparse\"\n";
        let mut dest = [0u8; 4096];
        let n = rewrite_descriptor(src, b"new.vmdk", 0xabcd_1234, false, &mut dest).unwrap();
        let out = core::str::from_utf8(&dest[..n]).unwrap();
        assert!(out.contains("CID=fffffffe"));
        assert!(out.contains("parentCID=abcd1234"));
        assert!(out.contains("parentFileNameHint=\"new.vmdk\""));
    }

    #[test]
    fn rejects_when_dest_too_small() {
        let mut tiny = [0u8; 32];
        let r = rewrite_descriptor(SAMPLE_DESCRIPTOR, b"new.vmdk", 0, false, &mut tiny);
        assert_eq!(r.err(), Some(RebaseError::DescriptorTooLarge));
    }

    #[test]
    fn unsafe_mode_plan_emits_descriptor_rewrite() {
        let mut scratch = [0u8; 4096];
        let opts = unsafe_opts(SAMPLE_DESCRIPTOR, b"new.vmdk", 0xc0de_f00d, false);
        let out = plan_rebase_vmdk(&opts, &mut scratch).unwrap();
        match out {
            VmdkRebaseOutput::Unsafe { plan } => {
                let patches = plan.patches();
                assert_eq!(patches.len(), 1);
                match patches[0] {
                    RebasePatch::Write { byte_offset, bytes } => {
                        assert_eq!(byte_offset, 512);
                        assert_eq!(bytes.len(), 1024);
                        // Decode the rewritten descriptor.
                        let text = core::str::from_utf8(bytes).unwrap();
                        assert!(text.contains("parentCID=c0def00d"));
                        assert!(text.contains("parentFileNameHint=\"new.vmdk\""));
                    }
                    _ => panic!("expected Write"),
                }
            }
            _ => panic!("expected Unsafe variant"),
        }
    }

    #[test]
    fn rejects_smaller_new_backing() {
        let mut scratch = [0u8; 4096];
        let mut opts = unsafe_opts(SAMPLE_DESCRIPTOR, b"new.vmdk", 0, false);
        opts.overlay_virtual_size = 4 * 1024 * 1024;
        opts.new_backing_virtual_size = 1024 * 1024; // smaller
        let r = plan_rebase_vmdk(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::NewBackingIncompatible));
    }

    // -----------------------------------------------------------------------
    // Safe-mode planner + allocator tests (step 2e).
    // -----------------------------------------------------------------------

    /// Build a safe-mode opts value with a single allocated GT
    /// whose every GTE is unallocated (zeroed). 64 KiB grain
    /// size; 512 GTEs per GT; one GD entry pointing at the
    /// allocated GT.
    fn safe_opts<'a>(
        descriptor: &'a [u8],
        new_path: &'a [u8],
        gd: &'a [u8],
        gts: &'a [u8],
        gt_host_sectors: &'a [u64],
        allocated_gt_count: u32,
        overlay_file_size: u64,
        overlay_virtual_size: u64,
    ) -> VmdkRebaseOpts<'a> {
        VmdkRebaseOpts {
            mode: RebaseMode::Safe,
            overlay_virtual_size,
            overlay_descriptor: descriptor,
            overlay_descriptor_size: 1024,
            overlay_descriptor_offset: 512,
            new_backing_virtual_size: overlay_virtual_size,
            new_backing_path: new_path,
            new_parent_cid: 0xabcd_1234,
            detach: false,
            overlay_grain_size_sectors: 128, // 64 KiB grain
            num_gtes_per_gt: 512,
            num_gd_entries: 1,
            gd_offset_sectors: 21,
            overlay_file_size,
            overlay_grain_directory: gd,
            overlay_grain_tables: gts,
            allocated_gt_host_sectors: gt_host_sectors,
            allocated_gt_count,
        }
    }

    #[test]
    fn safe_mode_plan_emits_deferred_descriptor_and_context() {
        let mut gd = [0u8; 4];
        // GD entry 0 points to GT at sector 22 (just after GD).
        gd[..4].copy_from_slice(&22u32.to_le_bytes());
        let gts = [0u8; 512 * 4]; // empty GT, no grains allocated yet
        let gt_host_sectors = [22u64];

        let mut scratch = [0u8; 8192];
        let opts = safe_opts(
            SAMPLE_DESCRIPTOR,
            b"new.vmdk",
            &gd,
            &gts,
            &gt_host_sectors,
            1,
            1 << 20,
            64 * 1024 * 1024,
        );
        let out = plan_rebase_vmdk(&opts, &mut scratch).expect("plan succeeds");
        match out {
            VmdkRebaseOutput::Safe {
                context,
                deferred_metadata,
            } => {
                assert_eq!(context.overlay_grain_size_sectors, 128);
                assert_eq!(context.num_gtes_per_gt, 512);
                assert_eq!(context.allocated_gt_count, 1);
                assert_eq!(context.grain_tables.len(), 512 * 4);
                assert_eq!(context.grain_directory.len(), 4);

                let patches = deferred_metadata.patches();
                assert_eq!(patches.len(), 1);
                match patches[0] {
                    RebasePatch::Write { byte_offset, bytes } => {
                        assert_eq!(byte_offset, 512);
                        assert_eq!(bytes.len(), 1024);
                        let text = core::str::from_utf8(bytes).unwrap();
                        assert!(text.contains("parentCID=abcd1234"));
                        assert!(text.contains("parentFileNameHint=\"new.vmdk\""));
                    }
                    _ => panic!("expected Write"),
                }
            }
            _ => panic!("expected Safe variant"),
        }
    }

    #[test]
    fn safe_mode_detach_preserves_descriptor_semantic() {
        let gd = [0u8; 4];
        let gts = [0u8; 512 * 4];
        let gt_host_sectors: [u64; 0] = [];

        let mut scratch = [0u8; 8192];
        let mut opts = safe_opts(
            SAMPLE_DESCRIPTOR,
            b"",
            &gd,
            &gts,
            &gt_host_sectors,
            0,
            1 << 20,
            64 * 1024 * 1024,
        );
        opts.detach = true;
        opts.new_backing_virtual_size = 0;
        let out = plan_rebase_vmdk(&opts, &mut scratch).expect("plan succeeds");
        match out {
            VmdkRebaseOutput::Safe {
                deferred_metadata, ..
            } => {
                let patches = deferred_metadata.patches();
                assert_eq!(patches.len(), 1);
                let RebasePatch::Write { bytes, .. } = patches[0] else {
                    panic!("expected Write")
                };
                let text = core::str::from_utf8(bytes).unwrap();
                assert!(text.contains("parentCID=ffffffff"));
                assert!(text.contains("parentFileNameHint=\"\""));
            }
            _ => panic!("expected Safe variant"),
        }
    }

    #[test]
    fn safe_mode_rejects_mismatched_gt_count() {
        let gd = [0u8; 4];
        let gts = [0u8; 512 * 4];
        // Mismatch: claim 1 GT but supply 2 host sectors.
        let gt_host_sectors = [22u64, 100u64];

        let mut scratch = [0u8; 8192];
        let opts = safe_opts(
            SAMPLE_DESCRIPTOR,
            b"new.vmdk",
            &gd,
            &gts,
            &gt_host_sectors,
            1,
            1 << 20,
            64 * 1024 * 1024,
        );
        let r = plan_rebase_vmdk(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::HeaderMismatch));
    }

    #[test]
    fn safe_mode_rejects_short_gt_bytes() {
        let gd = [0u8; 4];
        // Only 256 entries supplied for a 512-GTE GT.
        let gts = [0u8; 256 * 4];
        let gt_host_sectors = [22u64];

        let mut scratch = [0u8; 8192];
        let opts = safe_opts(
            SAMPLE_DESCRIPTOR,
            b"new.vmdk",
            &gd,
            &gts,
            &gt_host_sectors,
            1,
            1 << 20,
            64 * 1024 * 1024,
        );
        let r = plan_rebase_vmdk(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::HeaderMismatch));
    }

    #[test]
    fn safe_mode_rejects_zero_geometry() {
        let gd = [0u8; 4];
        let gts = [0u8; 512 * 4];
        let gt_host_sectors = [22u64];

        let mut scratch = [0u8; 8192];
        let mut opts = safe_opts(
            SAMPLE_DESCRIPTOR,
            b"new.vmdk",
            &gd,
            &gts,
            &gt_host_sectors,
            1,
            1 << 20,
            64 * 1024 * 1024,
        );
        opts.overlay_grain_size_sectors = 0;
        let r = plan_rebase_vmdk(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::OverlayCorrupt));
    }

    #[test]
    fn allocator_claims_grain_at_eof() {
        let mut gd = [0u8; 4];
        gd[..4].copy_from_slice(&22u32.to_le_bytes());
        let gts = [0u8; 512 * 4];
        let gt_host_sectors = [22u64];

        let mut scratch = [0u8; 8192];
        // Overlay file size = 1 MiB = 2048 sectors. Grain size
        // = 128 sectors. Allocator should start at sector 2048.
        let opts = safe_opts(
            SAMPLE_DESCRIPTOR,
            b"new.vmdk",
            &gd,
            &gts,
            &gt_host_sectors,
            1,
            1 << 20,
            64 * 1024 * 1024,
        );
        let out = plan_rebase_vmdk(&opts, &mut scratch).expect("plan");
        let (mut ctx, _plan) = match out {
            VmdkRebaseOutput::Safe {
                context,
                deferred_metadata,
            } => (context, deferred_metadata),
            _ => panic!("expected Safe"),
        };

        let mut state =
            GrainAllocationState::at_eof(1 << 20, ctx.overlay_grain_size_sectors).expect("init");
        assert_eq!(state.next_grain_sector, 2048);

        let off = allocate_overlay_grain_vmdk(&mut ctx, &mut state).expect("alloc");
        // Sector 2048 * 512 = byte 1 MiB.
        assert_eq!(off, 1 << 20);
        assert_eq!(state.allocated, 1);
        // Cursor advanced by 128 sectors.
        assert_eq!(state.next_grain_sector, 2048 + 128);

        let off2 = allocate_overlay_grain_vmdk(&mut ctx, &mut state).expect("alloc2");
        assert_eq!(off2, (2048 + 128) * 512);
        assert_eq!(state.allocated, 2);
    }

    #[test]
    fn allocator_aligns_eof_up_to_grain_boundary() {
        // File size = 1 MiB + 1 sector (= sector 2049). Grain
        // size 128 sectors should round the cursor up to 2176.
        let s = GrainAllocationState::at_eof((1 << 20) + 512, 128).expect("init");
        assert_eq!(s.next_grain_sector, 2176);
    }

    #[test]
    fn allocator_rejects_zero_grain_size() {
        let mut gd = [0u8; 4];
        let gts = [0u8; 512 * 4];
        let gt_host_sectors = [22u64];
        let mut gt_dirty = [0u8; 1];
        let mut gd_dirty = [0u8; 1];
        let mut ctx = RebaseVmdkSafeContext {
            overlay_grain_size_sectors: 0,
            overlay_grain_count: 0,
            num_gtes_per_gt: 512,
            num_gd_entries: 1,
            gd_offset_sectors: 21,
            allocated_gt_count: 1,
            grain_directory: &mut gd,
            grain_tables: &mut [0u8; 0][..],
            gt_host_sectors: &gt_host_sectors,
            gt_dirty: &mut gt_dirty,
            gd_dirty: &mut gd_dirty,
        };
        let _ = gts; // silence unused-warning when slices recreate
        let mut state = GrainAllocationState::default();
        let r = allocate_overlay_grain_vmdk(&mut ctx, &mut state);
        assert_eq!(r.err(), Some(RebaseError::OverlayCorrupt));
    }
}
