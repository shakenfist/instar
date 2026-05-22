//! VHD-specific resize planning.
//!
//! Phase 4 of `PLAN-resize.md`. The public entry point
//! [`plan_resize_vhd`](super::plan_resize_vhd) in the crate root
//! dispatches into [`plan_grow`] here, which classifies the
//! request into a [`VhdGrowAction`] and emits the patch list in
//! the documented crash-safety order.

use shared::be_u32;
use vhd::{
    build_dynamic_header, build_footer, VhdDynamicHeader, VhdFooter, BAT_UNALLOCATED,
    DISK_TYPE_DIFFERENCING, DISK_TYPE_DYNAMIC, DISK_TYPE_FIXED, DYNAMIC_HEADER_SIZE, FOOTER_SIZE,
};

use crate::{
    Preallocation, ResizeAction, ResizeError, ResizePatch, ResizePlan, VhdResizeOpts, VhdSubformat,
};

/// Classification of a dynamic VHD grow request.
///
/// (Fixed-VHD grow is dispatched directly from `plan_grow` via
/// the subformat match; the enum covers the dynamic branch only,
/// where the in-place-vs-relocate decision depends on BAT
/// allocation state.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VhdGrowAction {
    /// Dynamic VHD: extend BAT in place (existing BAT region has
    /// slack before the first allocated block / tail footer).
    DynamicGrowInPlace,
    /// Dynamic VHD: relocate BAT to end of file (existing BAT
    /// region collides with allocated blocks).
    DynamicGrowRelocate,
}

/// Top-level entry point: validate, classify, dispatch.
pub(crate) fn plan_grow<'a>(
    opts: &VhdResizeOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    if opts.new_virtual_size == 0 {
        return Err(ResizeError::InvalidNewVirtualSize);
    }
    validate_disk_type(opts.disk_type)?;
    if opts.preallocation == Preallocation::Metadata {
        // VHD has no qcow2-style L2 metadata-mode prealloc;
        // reject.
        return Err(ResizeError::PreallocationUnsupported);
    }
    if opts.new_virtual_size < opts.current_virtual_size {
        if !opts.allow_shrink {
            return Err(ResizeError::ShrinkWithoutFlag);
        }
        // Phase 4 ships grow only; shrink is deferred.
        return Err(ResizeError::UnsupportedShrink);
    }
    if opts.new_virtual_size == opts.current_virtual_size {
        return Ok(ResizePlan::new(ResizeAction::NoOp, opts.current_file_size));
    }

    // Cross-check the host's current_virtual_size against the
    // existing footer's current_size field.
    let parsed_footer = VhdFooter::parse(opts.existing_footer).ok_or(ResizeError::ParseFailed)?;
    if parsed_footer.current_size != opts.current_virtual_size {
        return Err(ResizeError::HeaderMismatch);
    }

    match opts.subformat {
        VhdSubformat::Fixed => plan_fixed_grow(opts, &parsed_footer, scratch),
        VhdSubformat::Dynamic => {
            let parsed_dyn = VhdDynamicHeader::parse(opts.existing_dynamic_header)
                .ok_or(ResizeError::ParseFailed)?;
            let action = decide_dynamic_action(opts, &parsed_dyn);
            match action {
                VhdGrowAction::DynamicGrowInPlace => {
                    plan_dynamic_grow_in_place(opts, &parsed_footer, &parsed_dyn, scratch)
                }
                VhdGrowAction::DynamicGrowRelocate => {
                    plan_dynamic_grow_relocate(opts, &parsed_footer, &parsed_dyn, scratch)
                }
            }
        }
    }
}

fn validate_disk_type(disk_type: u32) -> Result<(), ResizeError> {
    match disk_type {
        DISK_TYPE_FIXED | DISK_TYPE_DYNAMIC => Ok(()),
        DISK_TYPE_DIFFERENCING => Err(ResizeError::UnsupportedSubformat),
        _ => Err(ResizeError::UnsupportedFormat),
    }
}

/// Decide between in-place and relocate for a dynamic VHD grow.
///
/// In-place requires the new BAT's tail end to land at or before
/// the first allocated block (or, if no blocks are allocated, at
/// or before the tail footer position).
pub(crate) fn decide_dynamic_action(
    opts: &VhdResizeOpts<'_>,
    parsed_dyn: &VhdDynamicHeader,
) -> VhdGrowAction {
    let new_max_entries = compute_new_max_entries(opts.new_virtual_size, parsed_dyn.block_size);
    let new_bat_size_bytes = (new_max_entries as u64) * 4;
    let new_bat_end = parsed_dyn.table_offset + new_bat_size_bytes;

    let first_block_offset = first_allocated_block_offset(opts.existing_bat, parsed_dyn.block_size);
    let ceiling = first_block_offset.unwrap_or(opts.current_file_size.saturating_sub(512));

    if new_bat_end <= ceiling {
        VhdGrowAction::DynamicGrowInPlace
    } else {
        VhdGrowAction::DynamicGrowRelocate
    }
}

fn compute_new_max_entries(new_virtual_size: u64, block_size: u32) -> u32 {
    let block_size = block_size as u64;
    new_virtual_size.div_ceil(block_size) as u32
}

/// Walk the BAT and return the smallest non-`BAT_UNALLOCATED`
/// block's host byte offset. None if every entry is unallocated.
fn first_allocated_block_offset(bat_bytes: &[u8], block_size: u32) -> Option<u64> {
    let mut min: Option<u64> = None;
    for chunk in bat_bytes.chunks_exact(4) {
        let entry = be_u32(chunk, 0);
        if entry == BAT_UNALLOCATED {
            continue;
        }
        // Entries are sector offsets (512-byte units); the bitmap
        // for each block occupies one sector, followed by the
        // block payload. Just take the sector-offset value as
        // the lower bound for "where the block lives".
        let _ = block_size;
        let off = (entry as u64) * 512;
        min = Some(match min {
            Some(m) => m.min(off),
            None => off,
        });
    }
    min
}

// ============================================================================
// FixedGrow
// ============================================================================

fn plan_fixed_grow<'a>(
    opts: &VhdResizeOpts<'_>,
    parsed_footer: &VhdFooter,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    // Scratch layout: 512 bytes for the new footer + 512 zero
    // bytes for the old-footer-position write.
    if scratch.len() < 2 * FOOTER_SIZE {
        return Err(ResizeError::ScratchTooSmall);
    }
    let (footer_buf, rest) = scratch.split_at_mut(FOOTER_SIZE);
    let (zero_buf, _) = rest.split_at_mut(FOOTER_SIZE);

    // Build the new footer with updated current_size + CHS +
    // checksum; UUID preserved.
    build_footer(
        footer_buf,
        opts.new_virtual_size,
        DISK_TYPE_FIXED,
        0xFFFF_FFFF_FFFF_FFFF, // data_offset = sentinel for fixed
        &parsed_footer.uuid,
    );
    zero_buf.fill(0);

    let total_file_size = opts.new_virtual_size + FOOTER_SIZE as u64;
    let mut plan = ResizePlan::new(ResizeAction::Grow, total_file_size);

    // Phase A (prepare): write the new footer at new EOF. This
    // is intentionally before the old-footer zero patch — see
    // the phase plan's rationale: a crash after this patch but
    // before the next leaves the file with two valid footers,
    // the last of which (at new EOF) is the one parsers use.
    plan.push(ResizePatch::Write {
        byte_offset: opts.new_virtual_size,
        bytes: footer_buf,
    })?;
    // Phase B (commit): zero the old footer's bytes so they
    // can't be misread as a footer in the future.
    plan.push(ResizePatch::Write {
        byte_offset: opts.current_virtual_size,
        bytes: zero_buf,
    })?;

    Ok(plan)
}

// ============================================================================
// DynamicGrow shared helpers
// ============================================================================

fn build_bat_extension(
    buf: &mut [u8],
    old_max_entries: u32,
    new_max_entries: u32,
) -> Result<usize, ResizeError> {
    let extension_entries = new_max_entries.saturating_sub(old_max_entries) as usize;
    let bytes = extension_entries * 4;
    if buf.len() < bytes {
        return Err(ResizeError::ScratchTooSmall);
    }
    for chunk in buf[..bytes].chunks_exact_mut(4) {
        chunk[0] = 0xFF;
        chunk[1] = 0xFF;
        chunk[2] = 0xFF;
        chunk[3] = 0xFF;
    }
    Ok(bytes)
}

// ============================================================================
// DynamicGrowInPlace
// ============================================================================

fn plan_dynamic_grow_in_place<'a>(
    opts: &VhdResizeOpts<'_>,
    parsed_footer: &VhdFooter,
    parsed_dyn: &VhdDynamicHeader,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    let new_max_entries = compute_new_max_entries(opts.new_virtual_size, parsed_dyn.block_size);

    // Scratch layout: head footer (512) + dynamic header (1024)
    // + tail footer (512) + BAT extension bytes.
    let head_end = FOOTER_SIZE;
    let dyn_end = head_end + DYNAMIC_HEADER_SIZE;
    let tail_end = dyn_end + FOOTER_SIZE;
    let bat_ext_off = tail_end;
    if bat_ext_off > scratch.len() {
        return Err(ResizeError::ScratchTooSmall);
    }
    let (fixed_region, bat_region) = scratch.split_at_mut(bat_ext_off);
    let bat_ext_bytes =
        build_bat_extension(bat_region, parsed_dyn.max_table_entries, new_max_entries)?;

    // Build the four fixed-size buffers in scratch.
    // SAFETY: head_off / dyn_off / tail_off carve disjoint
    // regions of `fixed_region`.
    let (head_buf, rest) = fixed_region.split_at_mut(head_end);
    let (dyn_buf, tail_buf) = rest.split_at_mut(DYNAMIC_HEADER_SIZE);

    // Dynamic VHDs have data_offset = 512 (points at the dynamic
    // header).
    let data_offset = 512u64;
    build_footer(
        head_buf,
        opts.new_virtual_size,
        DISK_TYPE_DYNAMIC,
        data_offset,
        &parsed_footer.uuid,
    );
    build_footer(
        tail_buf,
        opts.new_virtual_size,
        DISK_TYPE_DYNAMIC,
        data_offset,
        &parsed_footer.uuid,
    );
    build_dynamic_header(
        dyn_buf,
        parsed_dyn.table_offset,
        new_max_entries,
        parsed_dyn.block_size,
    );

    let bat_extension_start = parsed_dyn.table_offset + (parsed_dyn.max_table_entries as u64) * 4;
    let total_file_size = opts.current_file_size;
    let tail_footer_offset = total_file_size - FOOTER_SIZE as u64;

    let mut plan = ResizePlan::new(ResizeAction::Grow, total_file_size);

    // Phase A — prepare:
    if bat_ext_bytes > 0 {
        plan.push(ResizePatch::Write {
            byte_offset: bat_extension_start,
            bytes: &bat_region[..bat_ext_bytes],
        })?;
    }
    plan.push(ResizePatch::Write {
        byte_offset: 512,
        bytes: dyn_buf,
    })?;
    plan.push(ResizePatch::Write {
        byte_offset: tail_footer_offset,
        bytes: tail_buf,
    })?;
    // Phase B — commit:
    plan.push(ResizePatch::Write {
        byte_offset: 0,
        bytes: head_buf,
    })?;

    Ok(plan)
}

// ============================================================================
// DynamicGrowRelocate
// ============================================================================

fn plan_dynamic_grow_relocate<'a>(
    opts: &VhdResizeOpts<'_>,
    parsed_footer: &VhdFooter,
    parsed_dyn: &VhdDynamicHeader,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    let new_max_entries = compute_new_max_entries(opts.new_virtual_size, parsed_dyn.block_size);
    let new_bat_size_bytes = (new_max_entries as u64) * 4;

    // Layout the new BAT region at the current tail footer
    // position (the existing data shifts the tail footer up by
    // new_bat_size_bytes).
    let new_bat_offset = opts.current_file_size - FOOTER_SIZE as u64;
    let total_file_size = new_bat_offset + new_bat_size_bytes + FOOTER_SIZE as u64;
    let new_tail_footer_offset = total_file_size - FOOTER_SIZE as u64;

    // Scratch layout: head footer + dynamic header + tail
    // footer + new BAT region.
    let head_end = FOOTER_SIZE;
    let dyn_end = head_end + DYNAMIC_HEADER_SIZE;
    let tail_end = dyn_end + FOOTER_SIZE;
    let bat_off = tail_end;
    let bat_end = bat_off + new_bat_size_bytes as usize;
    if bat_end > scratch.len() {
        return Err(ResizeError::ScratchTooSmall);
    }

    // Build all four scratch regions in one scope; the
    // mutable-borrow chain dies at the end of the block and
    // we re-borrow immutably to assemble the plan.
    {
        let (head_buf, after_head) = scratch[..bat_end].split_at_mut(head_end);
        let (dyn_buf, after_dyn) = after_head.split_at_mut(DYNAMIC_HEADER_SIZE);
        let (tail_buf, bat_buf) = after_dyn.split_at_mut(FOOTER_SIZE);

        let data_offset = 512u64;
        build_footer(
            head_buf,
            opts.new_virtual_size,
            DISK_TYPE_DYNAMIC,
            data_offset,
            &parsed_footer.uuid,
        );
        build_footer(
            tail_buf,
            opts.new_virtual_size,
            DISK_TYPE_DYNAMIC,
            data_offset,
            &parsed_footer.uuid,
        );
        build_dynamic_header(
            dyn_buf,
            new_bat_offset,
            new_max_entries,
            parsed_dyn.block_size,
        );
        // Build the new BAT region: copy existing entries +
        // fill new entries with BAT_UNALLOCATED.
        bat_buf.fill(0);
        let old_bat_bytes = (parsed_dyn.max_table_entries as usize) * 4;
        let copy_len = opts
            .existing_bat
            .len()
            .min(old_bat_bytes)
            .min(bat_buf.len());
        bat_buf[..copy_len].copy_from_slice(&opts.existing_bat[..copy_len]);
        for chunk in bat_buf[copy_len..].chunks_exact_mut(4) {
            chunk[0] = 0xFF;
            chunk[1] = 0xFF;
            chunk[2] = 0xFF;
            chunk[3] = 0xFF;
        }
    }

    let mut plan = ResizePlan::new(ResizeAction::Grow, total_file_size);

    // Phase A — prepare:
    //   1. Append the new BAT region at the old tail-footer
    //      position. (The old tail footer's bytes are
    //      overwritten by the new BAT; the new tail footer
    //      lives further along.)
    plan.push(ResizePatch::Append {
        byte_offset: new_bat_offset,
        bytes: &scratch[bat_off..bat_end],
    })?;
    //   2. Write the new dynamic header (now pointing at the
    //      new BAT).
    plan.push(ResizePatch::Write {
        byte_offset: 512,
        bytes: &scratch[head_end..dyn_end],
    })?;
    //   3. Write the new tail footer at its new position.
    plan.push(ResizePatch::Write {
        byte_offset: new_tail_footer_offset,
        bytes: &scratch[dyn_end..tail_end],
    })?;
    // Phase B — commit:
    plan.push(ResizePatch::Write {
        byte_offset: 0,
        bytes: &scratch[..head_end],
    })?;

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_disk_type_accepts_known() {
        assert!(validate_disk_type(DISK_TYPE_FIXED).is_ok());
        assert!(validate_disk_type(DISK_TYPE_DYNAMIC).is_ok());
    }

    #[test]
    fn validate_disk_type_rejects_differencing() {
        assert_eq!(
            validate_disk_type(DISK_TYPE_DIFFERENCING),
            Err(ResizeError::UnsupportedSubformat)
        );
    }

    #[test]
    fn validate_disk_type_rejects_unknown() {
        assert_eq!(validate_disk_type(0), Err(ResizeError::UnsupportedFormat));
        assert_eq!(validate_disk_type(99), Err(ResizeError::UnsupportedFormat));
    }

    #[test]
    fn compute_new_max_entries_rounds_up() {
        // 1 GiB / 2 MiB = 512 entries exactly.
        assert_eq!(compute_new_max_entries(1 << 30, 2 * 1024 * 1024), 512);
        // 1 GiB + 1 byte → 513 entries (round up).
        assert_eq!(compute_new_max_entries((1 << 30) + 1, 2 * 1024 * 1024), 513);
    }

    #[test]
    fn first_allocated_block_offset_finds_min() {
        // Construct a BAT with: unallocated, allocated at sector
        // 100, unallocated, allocated at sector 50.
        let mut bat = [0xFFu8; 16];
        bat[4] = 0;
        bat[5] = 0;
        bat[6] = 0;
        bat[7] = 100;
        bat[12] = 0;
        bat[13] = 0;
        bat[14] = 0;
        bat[15] = 50;
        assert_eq!(
            first_allocated_block_offset(&bat, 2 * 1024 * 1024),
            Some(50 * 512)
        );
    }

    #[test]
    fn first_allocated_block_offset_all_unallocated() {
        let bat = [0xFFu8; 16];
        assert_eq!(first_allocated_block_offset(&bat, 2 * 1024 * 1024), None);
    }
}
