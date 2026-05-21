//! QCOW2-specific resize planning.
//!
//! Phase 2 of `PLAN-resize.md`. The public entry point
//! [`plan_resize_qcow2`](super::plan_resize_qcow2) in the crate
//! root dispatches into [`plan_grow`] here, which decides on a
//! [`Qcow2GrowAction`] and emits a [`ResizePlan`] of patches in
//! the documented crash-safety order (prepare → header → cleanup).

// Step 2c wires the L1AndRefcountGrow path and Preallocation::Metadata
// support; until then the helpers that only those paths need are
// dead-code-flagged below at their definitions.

// build_l1_table / build_refcount_block / build_refcount_table
// land as imports in step 2c when the L1AndRefcountGrow path
// needs them.
use qcow2::create::{
    build_header, compute_layout, BuildHeaderOptions, Preallocation as Qcow2CreatePreallocation,
    Qcow2CreateError, Qcow2Layout,
};
use shared::{be_u64, write_be_u64};

use crate::{Preallocation, Qcow2ResizeOpts, ResizeAction, ResizeError, ResizePatch, ResizePlan};

/// Classification of a qcow2 grow request, decided up-front from
/// the existing and target layouts.
///
/// The three flavours have progressively more invasive patch
/// lists. [`Qcow2GrowAction::HeaderOnly`] emits a single header
/// rewrite; [`Qcow2GrowAction::L1Grow`] additionally appends a
/// new L1 region and updates the refcount entries that cover it;
/// [`Qcow2GrowAction::L1AndRefcountGrow`] runs the full algorithm
/// including new refcount blocks and (optionally) a relocated
/// refcount table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Qcow2GrowAction {
    HeaderOnly,
    L1Grow,
    L1AndRefcountGrow,
}

/// Decide which growth flavour applies, given the current and
/// target geometry. Pure scalar function; no I/O.
pub(crate) fn decide_action(
    current_l1_entries: u32,
    current_refcount_table_clusters: u32,
    current_refcount_block_count: u64,
    target_l1_entries: u32,
    target_refcount_table_clusters: u64,
    target_refcount_block_count: u64,
) -> Qcow2GrowAction {
    let l1_grows = target_l1_entries > current_l1_entries;
    let refcount_grows = target_refcount_block_count > current_refcount_block_count
        || target_refcount_table_clusters > current_refcount_table_clusters as u64;
    match (l1_grows, refcount_grows) {
        (false, false) => Qcow2GrowAction::HeaderOnly,
        (true, false) => Qcow2GrowAction::L1Grow,
        (true, true) | (false, true) => Qcow2GrowAction::L1AndRefcountGrow,
    }
}

/// Plan a qcow2 resize.
///
/// Phase 2b implements the HeaderOnly and L1Grow flavours;
/// L1AndRefcountGrow returns [`ResizeError::ScratchTooSmall`]
/// until step 2c lands the full algorithm.
pub(crate) fn plan_grow<'a>(
    opts: &Qcow2ResizeOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    if opts.new_virtual_size == 0 {
        return Err(ResizeError::InvalidNewVirtualSize);
    }
    if opts.new_virtual_size < opts.current_virtual_size {
        if !opts.allow_shrink {
            return Err(ResizeError::ShrinkWithoutFlag);
        }
        // Phase 3 lands the shrink planner.
        return Err(ResizeError::UnsupportedShrink);
    }
    if opts.new_virtual_size == opts.current_virtual_size {
        return Ok(ResizePlan::new(ResizeAction::NoOp, opts.current_file_size));
    }
    validate_incompat(opts.current_incompatible_features)?;
    if opts.preallocation == Preallocation::Metadata {
        // 2c lifts this gate after the metadata layer lands.
        return Err(ResizeError::PreallocationUnsupported);
    }
    if opts.extended_l2 && opts.preallocation != Preallocation::Off {
        return Err(ResizeError::PreallocationUnsupported);
    }

    let cluster_bits = cluster_bits_from(opts.cluster_size)?;
    if !opts
        .current_file_size
        .is_multiple_of(opts.cluster_size as u64)
    {
        // The file should be cluster-aligned for any qcow2 we'd
        // be willing to resize. Misalignment indicates either
        // host bug or pathological image.
        return Err(ResizeError::HeaderMismatch);
    }

    // Target layout is for sizing only (l1_entries needed,
    // refcount-table sizing). Offsets in the resize layout are
    // computed below from current_file_size and the
    // "always append" strategy.
    let target_layout = compute_layout(
        opts.new_virtual_size,
        cluster_bits,
        opts.refcount_bits as u32,
        opts.extended_l2,
        Qcow2CreatePreallocation::Off,
    )
    .map_err(map_qcow2_create_err)?;

    // How many refcount blocks does the existing image actually
    // have? Count non-zero entries in the refcount table.
    let existing_block_count = count_existing_refcount_blocks(opts.existing_refcount_table_bytes);

    let action = decide_action(
        opts.current_l1_entries,
        opts.current_refcount_table_clusters,
        existing_block_count,
        target_layout.l1_entries,
        target_layout.refcount_table_clusters,
        target_layout.refcount_block_count,
    );

    match action {
        Qcow2GrowAction::HeaderOnly => plan_header_only(opts, scratch),
        Qcow2GrowAction::L1Grow => plan_l1_grow(opts, &target_layout, scratch),
        Qcow2GrowAction::L1AndRefcountGrow => {
            // Phase 2c lands this. Surfacing ScratchTooSmall vs a
            // dedicated "not-yet-implemented" error keeps the
            // error enum minimal; the test matrix exercises both
            // paths once 2c lifts the gate.
            Err(ResizeError::ScratchTooSmall)
        }
    }
}

/// HeaderOnly path: the existing L1 already addresses the new
/// virtual size, and the existing refcount table already covers
/// every cluster the resize will allocate (which is none, since
/// no metadata is appended). Just rewrite the header with the
/// new `size` field.
///
/// The patch list is exactly one [`ResizePatch::Write`] at offset
/// 0 covering one cluster of header bytes.
fn plan_header_only<'a>(
    opts: &Qcow2ResizeOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    let cluster_size = opts.cluster_size as usize;
    if scratch.len() < cluster_size {
        return Err(ResizeError::ScratchTooSmall);
    }
    let (header_buf, _rest) = scratch.split_at_mut(cluster_size);

    // Synthesise a layout that reflects the existing geometry
    // with only the virtual_size updated. The fields build_header
    // reads: cluster_bits, virtual_size, l1_entries, l1_offset,
    // refcount_table_offset, refcount_table_clusters,
    // extended_l2, cluster_size.
    let layout = synthetic_current_layout(opts, opts.new_virtual_size);

    let header_bytes = build_header(
        header_buf,
        &BuildHeaderOptions {
            layout: &layout,
            backing_file: opts.backing_file,
            backing_format: opts.backing_format,
            lazy_refcounts: opts.lazy_refcounts,
            luks_header: None,
        },
    )
    .map_err(map_qcow2_create_err)?;

    let mut plan = ResizePlan::new(ResizeAction::Grow, opts.current_file_size);
    plan.push(ResizePatch::Write {
        byte_offset: 0,
        bytes: header_bytes,
    })?;
    Ok(plan)
}

/// L1Grow path: the L1 table must grow; the existing refcount
/// blocks still cover every newly-allocated cluster. The new L1
/// region is appended at `current_file_size`; refcount entries
/// for it are patched in existing refcount blocks; old-L1
/// refcount entries are decremented as cleanup after the header
/// rewrite.
///
/// Patch sequence:
///   1. Append: new L1 region (existing entries + zero tail)
///   2. Write: each affected refcount block (increment-only state)
///   3. Write: new header (points at new L1) — atomic commit
///   4. Write: refcount decrements for old-L1 clusters (cleanup)
///
/// For the rare edge case where an existing refcount block holds
/// both increment (new-L1) and decrement (old-L1) entries (small
/// images where new and old L1 share a block), the planner emits
/// TWO patches for that block: one in phase 2 with only the
/// increment applied, one in phase 4 with both applied. This keeps
/// the crash-safety invariant intact at the cost of one extra
/// write per overlapping block.
fn plan_l1_grow<'a>(
    opts: &Qcow2ResizeOpts<'_>,
    target_layout: &Qcow2Layout,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    let cluster_size = opts.cluster_size as u64;
    let cluster_size_us = opts.cluster_size as usize;
    let new_l1_entries = target_layout.l1_entries;
    let new_l1_size_bytes = (new_l1_entries as u64) * 8;
    let new_l1_clusters = new_l1_size_bytes.div_ceil(cluster_size).max(1);
    let new_l1_region_bytes = new_l1_clusters * cluster_size;

    let new_l1_first_cluster = opts.current_file_size / cluster_size;
    let new_l1_last_cluster = new_l1_first_cluster + new_l1_clusters - 1;

    let old_l1_first_cluster = opts.current_l1_table_offset / cluster_size;
    let old_l1_size_bytes = (opts.current_l1_entries as u64) * 8;
    let old_l1_clusters = old_l1_size_bytes.div_ceil(cluster_size).max(1);
    let old_l1_last_cluster = old_l1_first_cluster + old_l1_clusters - 1;

    let entries_per_refblock: u64 = (cluster_size * 8) / opts.refcount_bits as u64;

    // Carve scratch:
    //   [0..cluster_size)                       — new header
    //   [cluster_size..cluster_size + new_l1_region_bytes)
    //                                           — new L1 region
    //   then per-block staging slots: each "increment-only" block
    //   followed by its (optional) "increment+decrement" block.
    let header_off = 0usize;
    let header_end = cluster_size_us;
    let l1_off = header_end;
    let l1_end = l1_off + new_l1_region_bytes as usize;
    if l1_end > scratch.len() {
        return Err(ResizeError::ScratchTooSmall);
    }

    // Build new L1 region: copy old entries + zero pad.
    {
        let l1_buf = &mut scratch[l1_off..l1_end];
        l1_buf.fill(0);
        let old_l1_actual = opts.existing_l1_bytes.len().min(old_l1_size_bytes as usize);
        l1_buf[..old_l1_actual].copy_from_slice(&opts.existing_l1_bytes[..old_l1_actual]);
    }

    // Stage every distinct refcount block we need to touch.
    // Worst case for L1Grow at typical sizes: 1-2 blocks for the
    // increment side, 1 for the decrement side. The increment
    // and decrement side may refer to the same block (overlap);
    // in that case we stage it twice — once for the
    // increment-only intermediate state, once for the final
    // state.
    const MAX_BLOCKS_TOUCHED: usize = 16;
    let mut blocks: [BlockSlot; MAX_BLOCKS_TOUCHED] = [BlockSlot::EMPTY; MAX_BLOCKS_TOUCHED];
    let mut blocks_count: usize = 0;
    let mut next_staging = l1_end;

    // Register increment patches.
    for c in new_l1_first_cluster..=new_l1_last_cluster {
        let block_idx = c / entries_per_refblock;
        let local_idx = c % entries_per_refblock;
        stage_increment(
            opts,
            scratch,
            block_idx,
            local_idx,
            &mut blocks,
            &mut blocks_count,
            &mut next_staging,
            cluster_size_us,
            MAX_BLOCKS_TOUCHED,
        )?;
    }

    // Register decrement patches.
    for c in old_l1_first_cluster..=old_l1_last_cluster {
        let block_idx = c / entries_per_refblock;
        let local_idx = c % entries_per_refblock;
        stage_decrement(
            opts,
            scratch,
            block_idx,
            local_idx,
            &mut blocks,
            &mut blocks_count,
            &mut next_staging,
            cluster_size_us,
            MAX_BLOCKS_TOUCHED,
        )?;
    }

    // Build the new header bytes (the final "prepare" patch).
    let header_layout = synthetic_layout_after_l1_grow(
        opts,
        opts.new_virtual_size,
        new_l1_entries,
        opts.current_file_size,
    );
    let header_bytes_len = {
        let header_buf = &mut scratch[header_off..header_end];
        build_header(
            header_buf,
            &BuildHeaderOptions {
                layout: &header_layout,
                backing_file: opts.backing_file,
                backing_format: opts.backing_format,
                lazy_refcounts: opts.lazy_refcounts,
                luks_header: None,
            },
        )
        .map_err(map_qcow2_create_err)?
        .len()
    };

    // Assemble the plan in crash-safe order. Scratch slices are
    // non-overlapping by construction.
    let total_file_size = opts.current_file_size + new_l1_region_bytes;
    let mut plan = ResizePlan::new(ResizeAction::Grow, total_file_size);

    // Phase A — prepare:
    plan.push(ResizePatch::Append {
        byte_offset: opts.current_file_size,
        bytes: &scratch[l1_off..l1_end],
    })?;
    for slot in blocks.iter().take(blocks_count) {
        if !slot.has_increment {
            continue;
        }
        // The "increment_off" slot holds the block with only the
        // increment applied (the intermediate state visible until
        // the header rewrites).
        let block_offset =
            block_offset_in_file(opts.existing_refcount_table_bytes, slot.block_idx)?;
        plan.push(ResizePatch::Write {
            byte_offset: block_offset,
            bytes: &scratch[slot.increment_off..slot.increment_off + cluster_size_us],
        })?;
    }

    // Phase B — header rewrite (the atomic commit).
    plan.push(ResizePatch::Write {
        byte_offset: 0,
        bytes: &scratch[header_off..header_off + header_bytes_len],
    })?;

    // Phase C — cleanup decrements.
    for slot in blocks.iter().take(blocks_count) {
        if !slot.has_decrement {
            continue;
        }
        let block_offset =
            block_offset_in_file(opts.existing_refcount_table_bytes, slot.block_idx)?;
        plan.push(ResizePatch::Write {
            byte_offset: block_offset,
            bytes: &scratch[slot.final_off..slot.final_off + cluster_size_us],
        })?;
    }

    Ok(plan)
}

/// A per-block staging record. `increment_off` is the scratch
/// offset for the intermediate state with only the increment
/// applied (used by phase-A patches). `final_off` is the scratch
/// offset for the final state with both increment and decrement
/// applied (used by phase-C patches). They are the same offset
/// if the block has only one of the two; distinct offsets if
/// the block has both (the rare overlap case).
#[derive(Clone, Copy)]
struct BlockSlot {
    block_idx: u64,
    increment_off: usize,
    final_off: usize,
    has_increment: bool,
    has_decrement: bool,
}

impl BlockSlot {
    const EMPTY: BlockSlot = BlockSlot {
        block_idx: 0,
        increment_off: 0,
        final_off: 0,
        has_increment: false,
        has_decrement: false,
    };
}

/// Find an existing block slot by index. Returns the array
/// position if present.
fn find_block_slot(blocks: &[BlockSlot], count: usize, idx: u64) -> Option<usize> {
    blocks
        .iter()
        .take(count)
        .position(|slot| slot.block_idx == idx)
}

#[allow(clippy::too_many_arguments)]
fn stage_increment(
    opts: &Qcow2ResizeOpts<'_>,
    scratch: &mut [u8],
    block_idx: u64,
    local_idx: u64,
    blocks: &mut [BlockSlot],
    blocks_count: &mut usize,
    next_staging: &mut usize,
    cluster_size: usize,
    max_blocks: usize,
) -> Result<(), ResizeError> {
    let pos = find_block_slot(blocks, *blocks_count, block_idx);
    match pos {
        Some(i) if blocks[i].has_increment => {
            // Already staged; just patch the entry.
            let off = blocks[i].increment_off;
            set_refcount(
                &mut scratch[off..off + cluster_size],
                local_idx,
                opts.refcount_bits,
                1,
            )?;
            // Also reflect into final state if present.
            if blocks[i].has_decrement {
                let foff = blocks[i].final_off;
                set_refcount(
                    &mut scratch[foff..foff + cluster_size],
                    local_idx,
                    opts.refcount_bits,
                    1,
                )?;
            }
            Ok(())
        }
        Some(i) => {
            // Decrement-only slot already exists; promote to also
            // have increment. The decrement slot's bytes become
            // the FINAL state; we need a separate INCREMENT-only
            // staging area for the intermediate state.
            let inc_off = allocate_staging(next_staging, scratch.len(), cluster_size)?;
            ensure_block_staged(opts, block_idx, scratch, inc_off, cluster_size)?;
            set_refcount(
                &mut scratch[inc_off..inc_off + cluster_size],
                local_idx,
                opts.refcount_bits,
                1,
            )?;
            // Also apply the increment to the final-state slot.
            let foff = blocks[i].final_off;
            set_refcount(
                &mut scratch[foff..foff + cluster_size],
                local_idx,
                opts.refcount_bits,
                1,
            )?;
            blocks[i].increment_off = inc_off;
            blocks[i].has_increment = true;
            Ok(())
        }
        None => {
            // First touch of this block — it'll only have an
            // increment for now. increment_off and final_off
            // share storage; promotion to "has_decrement" later
            // doesn't need a second slot because the final state
            // is the same as the increment-only state in
            // increment-first ordering. (If a decrement later
            // lands on this block, we promote by allocating a
            // separate final-state slot via stage_decrement.)
            if *blocks_count >= max_blocks {
                return Err(ResizeError::ScratchTooSmall);
            }
            let off = allocate_staging(next_staging, scratch.len(), cluster_size)?;
            ensure_block_staged(opts, block_idx, scratch, off, cluster_size)?;
            set_refcount(
                &mut scratch[off..off + cluster_size],
                local_idx,
                opts.refcount_bits,
                1,
            )?;
            blocks[*blocks_count] = BlockSlot {
                block_idx,
                increment_off: off,
                final_off: off,
                has_increment: true,
                has_decrement: false,
            };
            *blocks_count += 1;
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_decrement(
    opts: &Qcow2ResizeOpts<'_>,
    scratch: &mut [u8],
    block_idx: u64,
    local_idx: u64,
    blocks: &mut [BlockSlot],
    blocks_count: &mut usize,
    next_staging: &mut usize,
    cluster_size: usize,
    max_blocks: usize,
) -> Result<(), ResizeError> {
    let pos = find_block_slot(blocks, *blocks_count, block_idx);
    match pos {
        Some(i) if blocks[i].has_decrement => {
            // Already promoted; just patch the entry.
            let foff = blocks[i].final_off;
            set_refcount(
                &mut scratch[foff..foff + cluster_size],
                local_idx,
                opts.refcount_bits,
                0,
            )?;
            Ok(())
        }
        Some(i) => {
            // Increment-only slot exists; allocate a separate
            // final-state slot, copy the current increment-only
            // bytes into it, then apply the decrement.
            let foff = allocate_staging(next_staging, scratch.len(), cluster_size)?;
            let inc_off = blocks[i].increment_off;
            // SAFETY: split_at_mut so both slices coexist.
            let (a, b) = scratch.split_at_mut(foff.max(inc_off));
            let (src, dst) = if inc_off < foff {
                (&a[inc_off..inc_off + cluster_size], &mut b[..cluster_size])
            } else {
                (&b[..cluster_size], &mut a[foff..foff + cluster_size])
            };
            dst.copy_from_slice(src);
            set_refcount(
                &mut scratch[foff..foff + cluster_size],
                local_idx,
                opts.refcount_bits,
                0,
            )?;
            blocks[i].final_off = foff;
            blocks[i].has_decrement = true;
            Ok(())
        }
        None => {
            if *blocks_count >= max_blocks {
                return Err(ResizeError::ScratchTooSmall);
            }
            let off = allocate_staging(next_staging, scratch.len(), cluster_size)?;
            ensure_block_staged(opts, block_idx, scratch, off, cluster_size)?;
            set_refcount(
                &mut scratch[off..off + cluster_size],
                local_idx,
                opts.refcount_bits,
                0,
            )?;
            blocks[*blocks_count] = BlockSlot {
                block_idx,
                increment_off: off,
                final_off: off,
                has_increment: false,
                has_decrement: true,
            };
            *blocks_count += 1;
            Ok(())
        }
    }
}

fn allocate_staging(
    next_staging: &mut usize,
    scratch_len: usize,
    cluster_size: usize,
) -> Result<usize, ResizeError> {
    let off = *next_staging;
    let end = off + cluster_size;
    if end > scratch_len {
        return Err(ResizeError::ScratchTooSmall);
    }
    *next_staging = end;
    Ok(off)
}

// ============================================================================
// Helpers
// ============================================================================

/// Reject incompatible-features bits the resize planner can't
/// handle.
fn validate_incompat(features: u64) -> Result<(), ResizeError> {
    use qcow2::{
        INCOMPAT_COMPRESSION, INCOMPAT_CORRUPT, INCOMPAT_DIRTY, INCOMPAT_EXTENDED_L2,
        INCOMPAT_EXTERNAL_DATA,
    };
    const KNOWN: u64 = INCOMPAT_DIRTY
        | INCOMPAT_CORRUPT
        | INCOMPAT_EXTERNAL_DATA
        | INCOMPAT_COMPRESSION
        | INCOMPAT_EXTENDED_L2;
    if features & !KNOWN != 0 {
        return Err(ResizeError::UnsupportedFormat);
    }
    if features & (INCOMPAT_EXTERNAL_DATA | INCOMPAT_COMPRESSION) != 0 {
        return Err(ResizeError::UnsupportedFormat);
    }
    if features & (INCOMPAT_DIRTY | INCOMPAT_CORRUPT) != 0 {
        return Err(ResizeError::RequiresCheckFirst);
    }
    Ok(())
}

/// Compute `cluster_bits` from `cluster_size`, validating that
/// cluster_size is a power of two in the qcow2-permitted range.
fn cluster_bits_from(cluster_size: u32) -> Result<u32, ResizeError> {
    if cluster_size == 0 || !cluster_size.is_power_of_two() {
        return Err(ResizeError::InvalidNewVirtualSize);
    }
    let bits = cluster_size.trailing_zeros();
    if !(9..=21).contains(&bits) {
        return Err(ResizeError::InvalidNewVirtualSize);
    }
    Ok(bits)
}

/// Map qcow2 builder errors into resize errors.
fn map_qcow2_create_err(e: Qcow2CreateError) -> ResizeError {
    match e {
        Qcow2CreateError::InvalidVirtualSize => ResizeError::InvalidNewVirtualSize,
        Qcow2CreateError::InvalidClusterBits | Qcow2CreateError::InvalidRefcountBits => {
            ResizeError::InvalidNewVirtualSize
        }
        Qcow2CreateError::Overflow => ResizeError::Overflow,
        Qcow2CreateError::BufferTooSmall => ResizeError::ScratchTooSmall,
        Qcow2CreateError::BackingMetadataTooLarge => ResizeError::ScratchTooSmall,
        Qcow2CreateError::PreallocationUnsupported => ResizeError::PreallocationUnsupported,
    }
}

/// Count the number of refcount blocks the existing image
/// actually has, by counting non-zero entries in the refcount
/// table.
fn count_existing_refcount_blocks(refcount_table_bytes: &[u8]) -> u64 {
    let mut count = 0u64;
    let mut i = 0;
    while i + 8 <= refcount_table_bytes.len() {
        let entry = be_u64(refcount_table_bytes, i);
        if entry != 0 {
            count += 1;
        }
        i += 8;
    }
    count
}

/// Synthesise a `Qcow2Layout` reflecting the current image's
/// geometry, with `virtual_size` set to a (possibly-new) value.
/// Used by HeaderOnly to rewrite the header without changing L1
/// or refcount-table fields.
fn synthetic_current_layout(opts: &Qcow2ResizeOpts<'_>, new_virtual_size: u64) -> Qcow2Layout {
    let cluster_bits =
        cluster_bits_from(opts.cluster_size).expect("validated upstream by plan_grow");
    let cluster_size = opts.cluster_size as u64;
    let l1_size_bytes = (opts.current_l1_entries as u64) * 8;
    let l1_clusters = l1_size_bytes.div_ceil(cluster_size).max(1);
    Qcow2Layout {
        cluster_bits,
        cluster_size,
        virtual_size: new_virtual_size,
        refcount_bits: opts.refcount_bits as u32,
        extended_l2: opts.extended_l2,
        preallocation: Qcow2CreatePreallocation::Off,
        l1_entries: opts.current_l1_entries,
        l1_size_bytes,
        l1_clusters,
        l1_offset: opts.current_l1_table_offset,
        refcount_table_offset: opts.current_refcount_table_offset,
        refcount_table_clusters: opts.current_refcount_table_clusters as u64,
        refcount_block_count: 0, // build_header doesn't read this
        refcount_blocks_base_offset: 0,
        l2_clusters: 0,
        l2_base_offset: 0,
        data_clusters: 0,
        data_base_offset: 0,
        total_clusters: 0,
        total_file_size: 0,
    }
}

/// Synthesise a `Qcow2Layout` reflecting the post-L1-grow
/// geometry: same refcount-table location as the existing image,
/// new L1 at the end of the pre-resize file.
fn synthetic_layout_after_l1_grow(
    opts: &Qcow2ResizeOpts<'_>,
    new_virtual_size: u64,
    new_l1_entries: u32,
    new_l1_offset: u64,
) -> Qcow2Layout {
    let cluster_bits =
        cluster_bits_from(opts.cluster_size).expect("validated upstream by plan_grow");
    let cluster_size = opts.cluster_size as u64;
    let l1_size_bytes = (new_l1_entries as u64) * 8;
    let l1_clusters = l1_size_bytes.div_ceil(cluster_size).max(1);
    Qcow2Layout {
        cluster_bits,
        cluster_size,
        virtual_size: new_virtual_size,
        refcount_bits: opts.refcount_bits as u32,
        extended_l2: opts.extended_l2,
        preallocation: Qcow2CreatePreallocation::Off,
        l1_entries: new_l1_entries,
        l1_size_bytes,
        l1_clusters,
        l1_offset: new_l1_offset,
        refcount_table_offset: opts.current_refcount_table_offset,
        refcount_table_clusters: opts.current_refcount_table_clusters as u64,
        refcount_block_count: 0,
        refcount_blocks_base_offset: 0,
        l2_clusters: 0,
        l2_base_offset: 0,
        data_clusters: 0,
        data_base_offset: 0,
        total_clusters: 0,
        total_file_size: 0,
    }
}

/// Stage an existing refcount block in `scratch[off..off + cluster_size]`
/// by copying from `opts.existing_refcount_block_bytes` if the
/// guest staged it, or zero-filling if the block is one the guest
/// didn't stage (which is an error if the planner is going to
/// patch it — return ScratchTooSmall to signal "guest must
/// stage more blocks").
fn ensure_block_staged(
    opts: &Qcow2ResizeOpts<'_>,
    block_idx: u64,
    scratch: &mut [u8],
    off: usize,
    cluster_size: usize,
) -> Result<(), ResizeError> {
    for (i, &staged_idx) in opts.existing_refcount_block_indices.iter().enumerate() {
        if staged_idx == block_idx {
            let src_off = i * cluster_size;
            let src_end = src_off + cluster_size;
            if src_end > opts.existing_refcount_block_bytes.len() {
                return Err(ResizeError::ScratchTooSmall);
            }
            scratch[off..off + cluster_size]
                .copy_from_slice(&opts.existing_refcount_block_bytes[src_off..src_end]);
            return Ok(());
        }
    }
    // Block not staged. The guest's pre-pass should have caught
    // this; surface as ScratchTooSmall so the host can retry
    // with a wider stage list.
    Err(ResizeError::ScratchTooSmall)
}

/// Read the file offset of refcount block `idx` from the existing
/// refcount table.
fn block_offset_in_file(refcount_table_bytes: &[u8], idx: u64) -> Result<u64, ResizeError> {
    let off = (idx as usize) * 8;
    if off + 8 > refcount_table_bytes.len() {
        return Err(ResizeError::ScratchTooSmall);
    }
    let entry = be_u64(refcount_table_bytes, off);
    if entry == 0 {
        // The planner requested a refcount block that the
        // refcount table doesn't actually point at. Surface as
        // a header mismatch (the guest's pre-pass should have
        // computed which blocks exist).
        return Err(ResizeError::HeaderMismatch);
    }
    Ok(entry)
}

/// Set the entry at index `local_idx` within a refcount block to
/// `value` (currently only 0 or 1 are used). Handles every
/// permitted refcount width.
fn set_refcount(
    block: &mut [u8],
    local_idx: u64,
    refcount_bits: u8,
    value: u64,
) -> Result<(), ResizeError> {
    match refcount_bits {
        1 => {
            let byte = (local_idx / 8) as usize;
            let bit = 7 - (local_idx % 8) as u32;
            if value == 0 {
                block[byte] &= !(1 << bit);
            } else {
                block[byte] |= 1 << bit;
            }
        }
        2 => {
            let byte = (local_idx / 4) as usize;
            let shift = 6 - 2 * (local_idx % 4) as u32;
            let mask = 0b11u8 << shift;
            block[byte] = (block[byte] & !mask) | (((value as u8) & 0b11) << shift);
        }
        4 => {
            let byte = (local_idx / 2) as usize;
            let shift = if local_idx.is_multiple_of(2) { 4 } else { 0 };
            let mask = 0b1111u8 << shift;
            block[byte] = (block[byte] & !mask) | (((value as u8) & 0b1111) << shift);
        }
        8 => {
            let byte = local_idx as usize;
            block[byte] = value as u8;
        }
        16 => {
            let off = (local_idx as usize) * 2;
            block[off] = (value >> 8) as u8;
            block[off + 1] = value as u8;
        }
        32 => {
            let off = (local_idx as usize) * 4;
            for i in 0..4 {
                block[off + i] = (value >> ((3 - i) * 8)) as u8;
            }
        }
        64 => {
            let off = (local_idx as usize) * 8;
            write_be_u64(block, off, value);
        }
        _ => return Err(ResizeError::InvalidNewVirtualSize),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_only_when_nothing_grows() {
        // Existing L1 has slack for a much bigger virtual size;
        // the refcount table likewise already covers everything.
        // Arg order: (current_l1, current_rt_clusters,
        // current_rb_count, target_l1, target_rt_clusters,
        // target_rb_count).
        let action = decide_action(16, 1, 1, 16, 1, 1);
        assert_eq!(action, Qcow2GrowAction::HeaderOnly);
    }

    #[test]
    fn l1_grow_when_only_l1_extends() {
        let action = decide_action(1, 1, 1, 4, 1, 1);
        assert_eq!(action, Qcow2GrowAction::L1Grow);
    }

    #[test]
    fn l1_and_refcount_grow_when_both_extend() {
        let action = decide_action(1, 1, 1, 4, 1, 2);
        assert_eq!(action, Qcow2GrowAction::L1AndRefcountGrow);
    }

    #[test]
    fn refcount_table_growth_alone_still_uses_full_algorithm() {
        let action = decide_action(16, 1, 1, 16, 2, 2);
        assert_eq!(action, Qcow2GrowAction::L1AndRefcountGrow);
    }

    #[test]
    fn refcount_block_growth_without_table_grow_uses_full_algorithm() {
        let action = decide_action(16, 2, 1, 16, 2, 3);
        assert_eq!(action, Qcow2GrowAction::L1AndRefcountGrow);
    }

    #[test]
    fn cluster_bits_from_valid() {
        assert_eq!(cluster_bits_from(512).unwrap(), 9);
        assert_eq!(cluster_bits_from(65536).unwrap(), 16);
        assert_eq!(cluster_bits_from(2 * 1024 * 1024).unwrap(), 21);
    }

    #[test]
    fn cluster_bits_from_invalid() {
        assert!(cluster_bits_from(0).is_err());
        assert!(cluster_bits_from(513).is_err()); // not power of 2
        assert!(cluster_bits_from(256).is_err()); // below min
        assert!(cluster_bits_from(4 * 1024 * 1024).is_err()); // above max
    }

    #[test]
    fn validate_incompat_clean() {
        assert!(validate_incompat(0).is_ok());
        // EXTENDED_L2 alone is acceptable; the planner handles
        // it.
        assert!(validate_incompat(qcow2::INCOMPAT_EXTENDED_L2).is_ok());
    }

    #[test]
    fn validate_incompat_rejects_external_data() {
        assert_eq!(
            validate_incompat(qcow2::INCOMPAT_EXTERNAL_DATA),
            Err(ResizeError::UnsupportedFormat)
        );
    }

    #[test]
    fn validate_incompat_rejects_compression() {
        assert_eq!(
            validate_incompat(qcow2::INCOMPAT_COMPRESSION),
            Err(ResizeError::UnsupportedFormat)
        );
    }

    #[test]
    fn validate_incompat_rejects_dirty() {
        assert_eq!(
            validate_incompat(qcow2::INCOMPAT_DIRTY),
            Err(ResizeError::RequiresCheckFirst)
        );
    }

    #[test]
    fn validate_incompat_rejects_corrupt() {
        assert_eq!(
            validate_incompat(qcow2::INCOMPAT_CORRUPT),
            Err(ResizeError::RequiresCheckFirst)
        );
    }

    #[test]
    fn validate_incompat_rejects_unknown() {
        // Bit 5 isn't defined yet.
        assert_eq!(
            validate_incompat(1 << 5),
            Err(ResizeError::UnsupportedFormat)
        );
    }

    #[test]
    fn count_existing_refcount_blocks_walks_table() {
        // 4 entries: 2 nonzero pointers and 2 zeros.
        let mut bytes = [0u8; 32];
        write_be_u64(&mut bytes, 0, 0x10000);
        write_be_u64(&mut bytes, 8, 0);
        write_be_u64(&mut bytes, 16, 0x20000);
        write_be_u64(&mut bytes, 24, 0);
        assert_eq!(count_existing_refcount_blocks(&bytes), 2);
    }

    #[test]
    fn set_refcount_16bit() {
        let mut block = [0u8; 16];
        set_refcount(&mut block, 0, 16, 1).unwrap();
        set_refcount(&mut block, 3, 16, 1).unwrap();
        assert_eq!(&block[0..2], &[0x00, 0x01]);
        assert_eq!(&block[6..8], &[0x00, 0x01]);
        // Decrement to 0.
        set_refcount(&mut block, 0, 16, 0).unwrap();
        assert_eq!(&block[0..2], &[0x00, 0x00]);
    }
}
