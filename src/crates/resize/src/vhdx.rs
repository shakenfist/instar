//! VHDX-specific resize planning.
//!
//! Phase 5 of `PLAN-resize.md`. The public entry point
//! [`plan_resize_vhdx`](super::plan_resize_vhdx) in the crate
//! root dispatches into [`plan_grow`] here, which classifies the
//! request and emits the patch list in the documented
//! crash-safety order (prepare → inactive-header-commit →
//! active-header-redundancy).

use vhdx::{
    build_header, build_metadata, build_region_table, calculate_bat_layout, HEADER1_OFFSET,
    HEADER2_OFFSET, HEADER_SIZE, REGION_TABLE1_OFFSET, REGION_TABLE2_OFFSET,
};

use crate::{Preallocation, ResizeAction, ResizeError, ResizePatch, ResizePlan, VhdxResizeOpts};

/// Classification of a VHDX dynamic grow request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VhdxGrowAction {
    /// Virtual size grew but the existing BAT can still hold
    /// every entry; only `VirtualDiskSize` + the headers change.
    MetadataAndHeaders,
    /// Virtual size grew enough that the BAT needs more entries
    /// than fit in the current region; relocate the BAT to end
    /// of file and update both region-table copies.
    BatGrowRelocate,
}

/// Region table size in bytes (one full 64 KiB sector-region).
const REGION_TABLE_REGION_SIZE: usize = 64 * 1024;
/// Byte offset within the metadata region where the
/// `VirtualDiskSize` u64 lives.
const VIRTUAL_DISK_SIZE_ITEM_OFFSET: u64 = 0x10008;
/// 1-MiB alignment for the BAT region (matches `plan_vhdx`).
const ONE_MIB: u64 = 1 << 20;

/// Minimum / maximum allowed VHDX block sizes (power-of-two).
const MIN_BLOCK_SIZE: u32 = 1 << 20; // 1 MiB
const MAX_BLOCK_SIZE: u32 = 256 << 20; // 256 MiB

/// Top-level entry point.
pub(crate) fn plan_grow<'a>(
    opts: &VhdxResizeOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    if opts.new_virtual_size == 0 {
        return Err(ResizeError::InvalidNewVirtualSize);
    }
    if !is_valid_block_size(opts.block_size) {
        return Err(ResizeError::InvalidNewVirtualSize);
    }
    if opts.preallocation == Preallocation::Metadata {
        return Err(ResizeError::PreallocationUnsupported);
    }
    if opts.has_parent {
        return Err(ResizeError::UnsupportedSubformat);
    }
    if !is_clean_log(opts.existing_active_header) {
        return Err(ResizeError::RequiresCheckFirst);
    }
    if !is_valid_active_header_offset(opts.current_active_header_offset) {
        return Err(ResizeError::HeaderMismatch);
    }
    if opts.new_virtual_size < opts.current_virtual_size {
        if !opts.allow_shrink {
            return Err(ResizeError::ShrinkWithoutFlag);
        }
        // qemu has no upstream VHDX shrink; we don't either.
        return Err(ResizeError::UnsupportedShrink);
    }
    if opts.new_virtual_size == opts.current_virtual_size {
        return Ok(ResizePlan::new(ResizeAction::NoOp, opts.current_file_size));
    }

    let (target_total_bat_entries, _chunk_ratio, _payload_blocks) = calculate_bat_layout(
        opts.new_virtual_size,
        opts.block_size,
        opts.logical_sector_size,
    )
    .ok_or(ResizeError::InvalidNewVirtualSize)?;

    let action = decide_action(opts.current_total_bat_entries, target_total_bat_entries);
    match action {
        VhdxGrowAction::MetadataAndHeaders => plan_metadata_and_headers(opts, scratch),
        VhdxGrowAction::BatGrowRelocate => {
            plan_bat_grow_relocate(opts, target_total_bat_entries, scratch)
        }
    }
}

/// Decide between the two grow flavours.
pub(crate) fn decide_action(
    current_total_bat_entries: u32,
    target_total_bat_entries: u32,
) -> VhdxGrowAction {
    if target_total_bat_entries <= current_total_bat_entries {
        VhdxGrowAction::MetadataAndHeaders
    } else {
        VhdxGrowAction::BatGrowRelocate
    }
}

fn is_valid_block_size(block_size: u32) -> bool {
    (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size) && block_size.is_power_of_two()
}

fn is_valid_active_header_offset(offset: u64) -> bool {
    offset == HEADER1_OFFSET || offset == HEADER2_OFFSET
}

/// Check that the active header's `log_guid` is all-zero
/// (clean image, no pending log entries to replay).
fn is_clean_log(header_bytes: &[u8]) -> bool {
    // log_guid lives at offset 48 in the header (per the parser
    // constants in the vhdx crate). 16 zero bytes = clean.
    if header_bytes.len() < 64 {
        return false;
    }
    header_bytes[48..64].iter().all(|&b| b == 0)
}

/// Identify the file offset of the *inactive* header — the one
/// the planner writes first (with `seq + 1`) to make it active.
fn inactive_header_offset(active_offset: u64) -> u64 {
    if active_offset == HEADER1_OFFSET {
        HEADER2_OFFSET
    } else {
        HEADER1_OFFSET
    }
}

// ============================================================================
// MetadataAndHeaders
// ============================================================================

fn plan_metadata_and_headers<'a>(
    opts: &VhdxResizeOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    // Scratch layout:
    //   [0..HEADER_SIZE)         — inactive header at seq + 1
    //   [HEADER_SIZE..2*HEADER_SIZE)
    //                            — formerly-active header at seq + 2
    //   [..+8)                   — VirtualDiskSize bytes
    let inactive_off = 0usize;
    let inactive_end = HEADER_SIZE;
    let active_off = inactive_end;
    let active_end = active_off + HEADER_SIZE;
    let vds_off = active_end;
    let vds_end = vds_off + 8;
    if vds_end > scratch.len() {
        return Err(ResizeError::ScratchTooSmall);
    }

    {
        let (inactive_buf, after_inactive) = scratch[..vds_end].split_at_mut(HEADER_SIZE);
        let (active_buf, vds_buf) = after_inactive.split_at_mut(HEADER_SIZE);

        // build_header writes 4096 bytes; the surrounding 64 KiB
        // header region's other bytes (4096..65536) are
        // already zero in the existing file and remain zero.
        build_header(inactive_buf, opts.current_sequence_number + 1);
        build_header(active_buf, opts.current_sequence_number + 2);
        vds_buf.copy_from_slice(&opts.new_virtual_size.to_le_bytes());
    }

    let inactive_offset = inactive_header_offset(opts.current_active_header_offset);
    let vds_file_off = opts.current_metadata_offset + VIRTUAL_DISK_SIZE_ITEM_OFFSET;

    let mut plan = ResizePlan::new(ResizeAction::Grow, opts.current_file_size);

    // Phase A — prepare:
    plan.push(ResizePatch::Write {
        byte_offset: vds_file_off,
        bytes: &scratch[vds_off..vds_end],
    })?;
    // Phase B — commit (write the inactive header with the
    // higher seq):
    plan.push(ResizePatch::Write {
        byte_offset: inactive_offset,
        bytes: &scratch[inactive_off..inactive_end],
    })?;
    // Phase C — redundancy (bring the previously-active header
    // back up to date with a yet-higher seq):
    plan.push(ResizePatch::Write {
        byte_offset: opts.current_active_header_offset,
        bytes: &scratch[active_off..active_end],
    })?;

    Ok(plan)
}

// ============================================================================
// BatGrowRelocate
// ============================================================================

fn plan_bat_grow_relocate<'a>(
    opts: &VhdxResizeOpts<'_>,
    target_total_bat_entries: u32,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    // Compute new BAT region size in bytes, rounded up to 1 MiB
    // (matching the create crate's BAT-region alignment).
    let new_bat_size_bytes_raw = (target_total_bat_entries as u64) * 8;
    let new_bat_size_bytes = new_bat_size_bytes_raw.div_ceil(ONE_MIB) * ONE_MIB;

    // New BAT lives at the current EOF.
    let new_bat_offset = opts.current_file_size;
    let total_file_size = new_bat_offset + new_bat_size_bytes;

    // The metadata region stays where it is; only the BAT
    // region in the region table changes its file_offset /
    // length.
    let new_metadata_offset = opts.current_metadata_offset;
    let new_metadata_length = opts.current_metadata_length;

    // Scratch layout:
    //   [0..HEADER_SIZE)                 — inactive header (seq+1)
    //   [..2*HEADER_SIZE)                — active header (seq+2)
    //   [..+REGION_TABLE_REGION_SIZE)    — new region table copy 1
    //   [..+REGION_TABLE_REGION_SIZE)    — new region table copy 2
    //   [..+8)                           — VirtualDiskSize bytes
    //   [..+new_bat_size_bytes)          — new BAT region
    let inactive_off = 0usize;
    let inactive_end = HEADER_SIZE;
    let active_off = inactive_end;
    let active_end = active_off + HEADER_SIZE;
    let rt1_off = active_end;
    let rt1_end = rt1_off + REGION_TABLE_REGION_SIZE;
    let rt2_off = rt1_end;
    let rt2_end = rt2_off + REGION_TABLE_REGION_SIZE;
    let vds_off = rt2_end;
    let vds_end = vds_off + 8;
    let bat_off = vds_end;
    let bat_end = bat_off + new_bat_size_bytes as usize;
    if bat_end > scratch.len() {
        return Err(ResizeError::ScratchTooSmall);
    }

    {
        let (inactive_buf, after_inactive) = scratch[..bat_end].split_at_mut(HEADER_SIZE);
        let (active_buf, after_active) = after_inactive.split_at_mut(HEADER_SIZE);
        let (rt1_buf, after_rt1) = after_active.split_at_mut(REGION_TABLE_REGION_SIZE);
        let (rt2_buf, after_rt2) = after_rt1.split_at_mut(REGION_TABLE_REGION_SIZE);
        let (vds_buf, bat_buf) = after_rt2.split_at_mut(8);

        build_header(inactive_buf, opts.current_sequence_number + 1);
        build_header(active_buf, opts.current_sequence_number + 2);

        let new_bat_length: u32 = new_bat_size_bytes
            .try_into()
            .map_err(|_| ResizeError::Overflow)?;
        build_region_table(
            rt1_buf,
            new_bat_offset,
            new_bat_length,
            new_metadata_offset,
            new_metadata_length,
        );
        build_region_table(
            rt2_buf,
            new_bat_offset,
            new_bat_length,
            new_metadata_offset,
            new_metadata_length,
        );

        vds_buf.copy_from_slice(&opts.new_virtual_size.to_le_bytes());

        // BAT: copy existing + zero-fill rest. The new entries
        // default to PAYLOAD_BLOCK_NOT_PRESENT (state=0, offset=0)
        // which is exactly what zero bytes encode for an
        // 8-byte BAT entry.
        bat_buf.fill(0);
        let copy_len = opts.existing_bat.len().min(bat_buf.len());
        bat_buf[..copy_len].copy_from_slice(&opts.existing_bat[..copy_len]);
    }

    let inactive_offset = inactive_header_offset(opts.current_active_header_offset);
    let vds_file_off = opts.current_metadata_offset + VIRTUAL_DISK_SIZE_ITEM_OFFSET;

    let mut plan = ResizePlan::new(ResizeAction::Grow, total_file_size);

    // Phase A — prepare:
    plan.push(ResizePatch::Append {
        byte_offset: new_bat_offset,
        bytes: &scratch[bat_off..bat_end],
    })?;
    plan.push(ResizePatch::Write {
        byte_offset: vds_file_off,
        bytes: &scratch[vds_off..vds_end],
    })?;
    plan.push(ResizePatch::Write {
        byte_offset: REGION_TABLE1_OFFSET,
        bytes: &scratch[rt1_off..rt1_end],
    })?;
    plan.push(ResizePatch::Write {
        byte_offset: REGION_TABLE2_OFFSET,
        bytes: &scratch[rt2_off..rt2_end],
    })?;
    // Phase B — commit:
    plan.push(ResizePatch::Write {
        byte_offset: inactive_offset,
        bytes: &scratch[inactive_off..inactive_end],
    })?;
    // Phase C — redundancy:
    plan.push(ResizePatch::Write {
        byte_offset: opts.current_active_header_offset,
        bytes: &scratch[active_off..active_end],
    })?;

    // Silence "unused" warnings — these helpers belong to the
    // module's public surface even if not all callers are wired
    // up yet.
    let _ = build_metadata;

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_size_validation() {
        assert!(is_valid_block_size(1 << 20)); // 1 MiB
        assert!(is_valid_block_size(2 << 20)); // 2 MiB
        assert!(is_valid_block_size(32 << 20)); // 32 MiB (default)
        assert!(is_valid_block_size(256 << 20)); // 256 MiB max
        assert!(!is_valid_block_size(0));
        assert!(!is_valid_block_size(512 << 20)); // > max
        assert!(!is_valid_block_size((1 << 20) + 1)); // not power of two
    }

    #[test]
    fn inactive_header_picks_the_other_one() {
        assert_eq!(inactive_header_offset(HEADER1_OFFSET), HEADER2_OFFSET);
        assert_eq!(inactive_header_offset(HEADER2_OFFSET), HEADER1_OFFSET);
    }

    #[test]
    fn decide_action_metadata_only() {
        // Current image holds 128 BAT entries; target needs 64.
        assert_eq!(decide_action(128, 64), VhdxGrowAction::MetadataAndHeaders);
        // Same → metadata-only.
        assert_eq!(decide_action(128, 128), VhdxGrowAction::MetadataAndHeaders);
    }

    #[test]
    fn decide_action_bat_grow() {
        assert_eq!(decide_action(64, 128), VhdxGrowAction::BatGrowRelocate);
    }

    #[test]
    fn is_clean_log_zero_guid_is_clean() {
        let mut hdr = [0u8; 64];
        assert!(is_clean_log(&hdr));
        hdr[48] = 1;
        assert!(!is_clean_log(&hdr));
    }

    #[test]
    fn is_clean_log_too_short_is_dirty() {
        let hdr = [0u8; 32];
        assert!(!is_clean_log(&hdr));
    }
}
