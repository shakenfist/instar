//! VMDK-specific resize planning.
//!
//! Phase 6 of `PLAN-resize.md`. The public entry point
//! [`plan_resize_vmdk`](super::plan_resize_vmdk) in the crate
//! root dispatches into [`plan_grow`] here, which classifies the
//! request and emits the patch list. Phase 6 supports
//! `MonolithicSparse` only; other subformats are rejected with
//! [`ResizeError::UnsupportedSubformat`].

use core::fmt::Write;

use shared::{le_u64, VmdkInfo};
use vmdk::{
    build_sparse_header, parse_descriptor, parse_descriptor_extents, ExtentKind, CAPACITY_OFFSET,
};

use crate::{
    Preallocation, ResizeAction, ResizeError, ResizePatch, ResizePlan, VmdkResizeOpts,
    VmdkSubformat,
};

/// Classification of a VMDK monolithicSparse grow request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VmdkGrowAction {
    /// New `num_gd_entries` fits in the existing GD region;
    /// only header.capacity + descriptor's extent line change.
    MetadataOnly,
    /// New `num_gd_entries` exceeds the existing GD region's
    /// capacity; relocate the GD to end of file.
    GdGrowRelocate,
}

const SECTOR: u64 = 512;
const HEADER_SECTOR_BYTES: usize = 512;
const GD_ENTRY_BYTES: u32 = 4;
/// Number of GD entries that fit in one 512-byte sector.
const ENTRIES_PER_SECTOR: u32 = SECTOR as u32 / GD_ENTRY_BYTES;

/// Permitted grain-size range (in bytes) — matches the create
/// crate's validation.
const MIN_GRAIN_BYTES: u32 = 4096;
const MAX_GRAIN_BYTES: u32 = 65536;

/// Top-level entry point.
pub(crate) fn plan_grow<'a>(
    opts: &VmdkResizeOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    if opts.new_virtual_size == 0 {
        return Err(ResizeError::InvalidNewVirtualSize);
    }
    if !matches!(opts.subformat, VmdkSubformat::MonolithicSparse) {
        return Err(ResizeError::UnsupportedSubformat);
    }
    if opts.preallocation == Preallocation::Metadata {
        return Err(ResizeError::PreallocationUnsupported);
    }
    if !is_valid_grain_size(opts.grain_size) {
        return Err(ResizeError::InvalidNewVirtualSize);
    }
    if opts.new_virtual_size < opts.current_virtual_size {
        if !opts.allow_shrink {
            return Err(ResizeError::ShrinkWithoutFlag);
        }
        return Err(ResizeError::UnsupportedShrink);
    }
    if opts.new_virtual_size == opts.current_virtual_size {
        return Ok(ResizePlan::new(ResizeAction::NoOp, opts.current_file_size));
    }

    // Parse the existing header (we only need a handful of
    // fields, all known LE offsets).
    if opts.existing_header.len() < HEADER_SECTOR_BYTES {
        return Err(ResizeError::ParseFailed);
    }
    let header_capacity_sectors = le_u64(opts.existing_header, CAPACITY_OFFSET);
    if header_capacity_sectors * SECTOR != opts.current_virtual_size {
        return Err(ResizeError::HeaderMismatch);
    }

    // Parse the existing descriptor: CID / parentCID /
    // createType + the extent line's filename.
    let mut info = VmdkInfo::new();
    parse_descriptor(
        opts.existing_descriptor,
        opts.existing_descriptor.len(),
        &mut info,
    );
    if info.create_type_str() != "monolithicSparse" {
        return Err(ResizeError::UnsupportedSubformat);
    }
    let (filename, _current_extent_sectors) = parse_existing_extent_line(opts.existing_descriptor)?;

    // Compute new capacity, rounded up to a grain boundary.
    let grain_bytes = opts.grain_size as u64;
    let new_capacity_bytes = opts.new_virtual_size.div_ceil(grain_bytes) * grain_bytes;
    let new_capacity_sectors = new_capacity_bytes / SECTOR;

    // Compute new num_gd_entries.  Each GT covers
    // (num_gtes_per_gt * grain_size_sectors) sectors of virtual
    // space; num_gtes_per_gt lives at offset 44 in the header
    // (NUM_GTES_PER_GT_OFFSET).
    let grain_size_sectors = grain_bytes / SECTOR;
    let num_gtes_per_gt = u32::from_le_bytes([
        opts.existing_header[44],
        opts.existing_header[45],
        opts.existing_header[46],
        opts.existing_header[47],
    ]);
    if num_gtes_per_gt == 0 {
        return Err(ResizeError::ParseFailed);
    }
    let sectors_per_gt = (num_gtes_per_gt as u64) * grain_size_sectors;
    let new_num_gd_entries: u32 = new_capacity_sectors
        .div_ceil(sectors_per_gt)
        .try_into()
        .map_err(|_| ResizeError::Overflow)?;

    let action = decide_action(opts.current_gd_sectors, new_num_gd_entries);

    match action {
        VmdkGrowAction::MetadataOnly => {
            plan_metadata_only(opts, &info, filename, new_capacity_sectors, scratch)
        }
        VmdkGrowAction::GdGrowRelocate => plan_gd_grow_relocate(
            opts,
            &info,
            filename,
            new_capacity_sectors,
            new_num_gd_entries,
            num_gtes_per_gt,
            grain_size_sectors,
            scratch,
        ),
    }
}

/// Decide whether the new GD entry count fits in the existing
/// region or needs relocation.
pub(crate) fn decide_action(current_gd_sectors: u32, new_num_gd_entries: u32) -> VmdkGrowAction {
    let capacity_entries = current_gd_sectors * ENTRIES_PER_SECTOR;
    if new_num_gd_entries <= capacity_entries {
        VmdkGrowAction::MetadataOnly
    } else {
        VmdkGrowAction::GdGrowRelocate
    }
}

fn is_valid_grain_size(grain_bytes: u32) -> bool {
    (MIN_GRAIN_BYTES..=MAX_GRAIN_BYTES).contains(&grain_bytes) && grain_bytes.is_power_of_two()
}

/// Extract the (filename, size_sectors) from the first extent
/// line of an existing descriptor.
fn parse_existing_extent_line(descriptor_bytes: &[u8]) -> Result<(&[u8], u64), ResizeError> {
    // The descriptor is null-terminated within its region.
    let end = descriptor_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(descriptor_bytes.len());
    let text =
        core::str::from_utf8(&descriptor_bytes[..end]).map_err(|_| ResizeError::ParseFailed)?;
    let extents = parse_descriptor_extents(text).map_err(|_| ResizeError::ParseFailed)?;
    if extents.is_empty() {
        return Err(ResizeError::ParseFailed);
    }
    let first = extents.get(0).ok_or(ResizeError::ParseFailed)?;
    if first.kind != ExtentKind::Sparse {
        return Err(ResizeError::UnsupportedSubformat);
    }
    // Map the &str filename back to the corresponding slice in
    // the original descriptor bytes (preserves byte-exact
    // contents through the rewrite).
    let filename_bytes = first.filename.as_bytes();
    let filename_in_desc = locate_subslice(descriptor_bytes, filename_bytes)
        .map(|off| &descriptor_bytes[off..off + filename_bytes.len()])
        .unwrap_or(filename_bytes);
    Ok((filename_in_desc, first.size_sectors))
}

/// Find the byte offset of `needle` within `haystack`, if any.
fn locate_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ============================================================================
// MetadataOnly
// ============================================================================

fn plan_metadata_only<'a>(
    opts: &VmdkResizeOpts<'_>,
    info: &VmdkInfo,
    filename: &[u8],
    new_capacity_sectors: u64,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    // Scratch layout: 8-byte capacity LE + descriptor bytes
    // (`desc_size_sectors * 512`).
    let desc_size_sectors = read_le_u64(opts.existing_header, 36)?;
    let desc_region_bytes = (desc_size_sectors * SECTOR) as usize;
    let cap_off = 0usize;
    let cap_end = 8;
    let desc_off = cap_end;
    let desc_end = desc_off + desc_region_bytes;
    if desc_end > scratch.len() {
        return Err(ResizeError::ScratchTooSmall);
    }

    {
        let (cap_buf, desc_buf) = scratch[..desc_end].split_at_mut(cap_end);
        cap_buf.copy_from_slice(&new_capacity_sectors.to_le_bytes());
        desc_buf.fill(0);
        let written = format_monolithic_sparse_descriptor(
            desc_buf,
            info.cid,
            info.parent_cid,
            filename,
            new_capacity_sectors,
        )?;
        // Verify the descriptor fit; format_*_descriptor
        // already errors on overflow.
        debug_assert!(written <= desc_buf.len());
    }

    let desc_file_off = read_le_u64(opts.existing_header, 28)? * SECTOR; // descriptor_offset_sectors

    let mut plan = ResizePlan::new(ResizeAction::Grow, opts.current_file_size);
    plan.push(ResizePatch::Write {
        byte_offset: desc_file_off,
        bytes: &scratch[desc_off..desc_end],
    })?;
    // Header capacity write last (the "atomic commit" for VMDK).
    plan.push(ResizePatch::Write {
        byte_offset: CAPACITY_OFFSET as u64,
        bytes: &scratch[cap_off..cap_end],
    })?;
    Ok(plan)
}

// ============================================================================
// GdGrowRelocate
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn plan_gd_grow_relocate<'a>(
    opts: &VmdkResizeOpts<'_>,
    info: &VmdkInfo,
    filename: &[u8],
    new_capacity_sectors: u64,
    new_num_gd_entries: u32,
    num_gtes_per_gt: u32,
    grain_size_sectors: u64,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    let new_gd_bytes = (new_num_gd_entries as u64) * GD_ENTRY_BYTES as u64;
    let new_gd_sectors = new_gd_bytes.div_ceil(SECTOR);
    let new_gd_region_bytes = new_gd_sectors * SECTOR;

    let new_gd_offset_sectors = opts.current_file_size / SECTOR;
    let total_file_size = opts.current_file_size + new_gd_region_bytes;

    let desc_size_sectors = read_le_u64(opts.existing_header, 36)?;
    let desc_region_bytes = (desc_size_sectors * SECTOR) as usize;
    let _ = num_gtes_per_gt; // already captured in the new header below
    let _ = grain_size_sectors;

    // Scratch layout: new header (512) + new descriptor +
    // new GD region.
    let header_off = 0usize;
    let header_end = HEADER_SECTOR_BYTES;
    let desc_off = header_end;
    let desc_end = desc_off + desc_region_bytes;
    let gd_off = desc_end;
    let gd_end = gd_off + new_gd_region_bytes as usize;
    if gd_end > scratch.len() {
        return Err(ResizeError::ScratchTooSmall);
    }

    {
        let (header_buf, after_header) = scratch[..gd_end].split_at_mut(HEADER_SECTOR_BYTES);
        let (desc_buf, gd_buf) = after_header.split_at_mut(desc_region_bytes);

        // Rebuild the header with the new capacity AND the new
        // GD offset; everything else preserved from the
        // existing image.
        header_buf.fill(0);
        let overhead_sectors = read_le_u64(opts.existing_header, 64)?;
        build_sparse_header(
            header_buf,
            new_capacity_sectors,
            grain_size_sectors,
            num_gtes_per_gt,
            new_gd_offset_sectors,
            overhead_sectors,
        );

        // New descriptor with preserved CID / parentCID +
        // updated capacity.
        desc_buf.fill(0);
        format_monolithic_sparse_descriptor(
            desc_buf,
            info.cid,
            info.parent_cid,
            filename,
            new_capacity_sectors,
        )?;

        // New GD region: copy existing entries + zero pad.
        gd_buf.fill(0);
        let existing_gd_bytes = (opts.current_num_gd_entries as usize) * GD_ENTRY_BYTES as usize;
        let copy_len = opts
            .existing_gd
            .len()
            .min(existing_gd_bytes)
            .min(gd_buf.len());
        gd_buf[..copy_len].copy_from_slice(&opts.existing_gd[..copy_len]);
    }

    let desc_file_off = read_le_u64(opts.existing_header, 28)? * SECTOR;

    let mut plan = ResizePlan::new(ResizeAction::Grow, total_file_size);
    // Phase A — prepare:
    plan.push(ResizePatch::Append {
        byte_offset: opts.current_file_size,
        bytes: &scratch[gd_off..gd_end],
    })?;
    plan.push(ResizePatch::Write {
        byte_offset: desc_file_off,
        bytes: &scratch[desc_off..desc_end],
    })?;
    // Phase B — commit (header points at the new GD region and
    // carries the new capacity):
    plan.push(ResizePatch::Write {
        byte_offset: 0,
        bytes: &scratch[header_off..header_end],
    })?;
    Ok(plan)
}

// ============================================================================
// Descriptor formatter
// ============================================================================

/// Emit a monolithicSparse descriptor into `buf`. Returns the
/// number of bytes written (excluding the zero-pad tail).
///
/// The trailing bytes past the formatted text remain whatever
/// the caller left them (the caller zero-fills before calling).
fn format_monolithic_sparse_descriptor(
    buf: &mut [u8],
    cid: u32,
    parent_cid: u32,
    filename: &[u8],
    capacity_sectors: u64,
) -> Result<usize, ResizeError> {
    let mut writer = BufWriter::new(buf);
    let filename_str = core::str::from_utf8(filename).map_err(|_| ResizeError::ParseFailed)?;
    writer
        .write_str("# Disk DescriptorFile\nversion=1\n")
        .map_err(|_| ResizeError::ScratchTooSmall)?;
    write!(writer, "CID={:08x}\nparentCID={:08x}\n", cid, parent_cid)
        .map_err(|_| ResizeError::ScratchTooSmall)?;
    writer
        .write_str("createType=\"monolithicSparse\"\n\n# Extent description\n")
        .map_err(|_| ResizeError::ScratchTooSmall)?;
    write!(
        writer,
        "RW {} SPARSE \"{}\"\n\n# The disk Data Base\n#DDB\n\n",
        capacity_sectors, filename_str
    )
    .map_err(|_| ResizeError::ScratchTooSmall)?;
    Ok(writer.pos)
}

/// Tiny `&mut [u8]` adapter that implements `core::fmt::Write`.
struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl core::fmt::Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let end = self.pos.checked_add(bytes.len()).ok_or(core::fmt::Error)?;
        if end > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }
}

/// Helper: read a u64 LE at `off` with bounds-checking via
/// ResizeError instead of panic.
fn read_le_u64(buf: &[u8], off: usize) -> Result<u64, ResizeError> {
    if off + 8 > buf.len() {
        return Err(ResizeError::ParseFailed);
    }
    Ok(le_u64(buf, off))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grain_size_validation() {
        assert!(is_valid_grain_size(4096));
        assert!(is_valid_grain_size(8192));
        assert!(is_valid_grain_size(65536));
        assert!(!is_valid_grain_size(0));
        assert!(!is_valid_grain_size(2048));
        assert!(!is_valid_grain_size(131072));
        assert!(!is_valid_grain_size(8000));
    }

    #[test]
    fn decide_action_metadata_only() {
        // 1 GD sector holds 128 entries; 100 entries fit.
        assert_eq!(decide_action(1, 100), VmdkGrowAction::MetadataOnly);
        // Exactly the capacity: also fits.
        assert_eq!(decide_action(1, 128), VmdkGrowAction::MetadataOnly);
    }

    #[test]
    fn decide_action_relocate() {
        // 1 sector caps at 128 entries; 129 needs relocate.
        assert_eq!(decide_action(1, 129), VmdkGrowAction::GdGrowRelocate);
    }

    #[test]
    fn descriptor_formatter_round_trips_cid_and_size() {
        let mut buf = [0u8; 1024];
        let written = format_monolithic_sparse_descriptor(
            &mut buf,
            0xdead_beef,
            0xffff_ffff,
            b"foo.vmdk",
            2_097_152,
        )
        .unwrap();
        let s = core::str::from_utf8(&buf[..written]).unwrap();
        assert!(s.contains("CID=deadbeef"));
        assert!(s.contains("parentCID=ffffffff"));
        assert!(s.contains("createType=\"monolithicSparse\""));
        assert!(s.contains("RW 2097152 SPARSE \"foo.vmdk\""));
    }

    #[test]
    fn descriptor_formatter_errors_when_buf_too_small() {
        let mut buf = [0u8; 32];
        let err = format_monolithic_sparse_descriptor(&mut buf, 0, 0xffff_ffff, b"foo.vmdk", 1_000)
            .unwrap_err();
        assert_eq!(err, ResizeError::ScratchTooSmall);
    }
}
