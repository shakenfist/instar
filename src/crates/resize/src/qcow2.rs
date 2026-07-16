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

use crate::{
    Preallocation, Qcow2GrowAction, Qcow2GrowQueryResult, Qcow2ResizeGrowQuery, Qcow2ResizeOpts,
    ResizeAction, ResizeError, ResizePatch, ResizePlan, QCOW2_MAX_REQUIRED_BLOCKS,
};

// Qcow2GrowAction is now defined in lib.rs (public) so the guest
// pre-pass can dispatch on the flavour returned by
// `compute_qcow2_grow_query`.  See lib.rs for the variant docs.

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

/// Compute the actual refcount-block and refcount-table requirements
/// for a resize-by-append (the strategy both L1Grow and
/// L1AndRefcountGrow follow). Returns
/// `(block_count, table_clusters, new_total_clusters)`.
///
/// `compute_layout` models a *compact fresh build* at the target
/// virtual size, so it under-counts refcount requirements for the
/// append strategy: a resize appends new L1 / RT / RB regions at
/// the existing EOF and leaves the old L1 in place (decremented to
/// refcount 0, but still occupying clusters). So the post-resize
/// file is larger than a fresh image of the same virtual size and
/// may need more RBs (and occasionally a bigger RT) to refcount
/// itself.
///
/// Fixed-point iterates because each added RB / RT cluster grows
/// the file, which in turn may require another RB. Bounded by the
/// post-resize cluster count, so it terminates after a handful of
/// iterations.
pub(crate) fn compute_append_requirements(
    current_file_size: u64,
    cluster_size: u64,
    refcount_bits: u8,
    target_l1_clusters: u64,
    current_refcount_table_clusters: u64,
    existing_block_count: u64,
) -> (u64, u64, u64) {
    let entries_per_refblock: u64 = (cluster_size * 8) / refcount_bits as u64;
    let new_l1_size_bytes = target_l1_clusters * cluster_size;
    let current_rt_clusters = current_refcount_table_clusters.max(1);

    let mut block_count = existing_block_count.max(1);
    let mut table_clusters = current_rt_clusters;
    loop {
        let table_grows = table_clusters > current_rt_clusters;
        let new_table_bytes = if table_grows {
            table_clusters * cluster_size
        } else {
            0
        };
        let new_blocks_delta = block_count.saturating_sub(existing_block_count);
        let new_blocks_bytes = new_blocks_delta * cluster_size;
        let total_file_size =
            current_file_size + new_l1_size_bytes + new_table_bytes + new_blocks_bytes;
        let new_total_clusters = total_file_size / cluster_size;

        let needed_block_count = new_total_clusters
            .div_ceil(entries_per_refblock)
            .max(existing_block_count.max(1));
        let needed_table_clusters = (needed_block_count * 8)
            .div_ceil(cluster_size)
            .max(current_rt_clusters);

        if needed_block_count == block_count && needed_table_clusters == table_clusters {
            return (block_count, table_clusters, new_total_clusters);
        }
        block_count = needed_block_count;
        table_clusters = needed_table_clusters;
    }
}

// ----------------------------------------------------------------
// Targeted refcount-block pre-pass query (followup-01).
// ----------------------------------------------------------------

/// Implementation of [`crate::compute_qcow2_grow_query`].  Mirrors
/// the input-validation gates of [`plan_grow`] and emits the
/// pre-classification (action + required block indices) the guest
/// needs to stage exactly the right slice of refcount-block bytes
/// before invoking [`plan_resize_qcow2`].
pub(crate) fn compute_grow_query(
    q: &Qcow2ResizeGrowQuery<'_>,
) -> Result<Qcow2GrowQueryResult, ResizeError> {
    if q.new_virtual_size == 0 {
        return Err(ResizeError::InvalidNewVirtualSize);
    }
    validate_incompat(q.current_incompatible_features)?;
    validate_no_bitmaps(q.current_autoclear_features)?;
    if q.new_virtual_size < q.current_virtual_size {
        if !q.allow_shrink {
            return Err(ResizeError::ShrinkWithoutFlag);
        }
        // This helper is grow-only; shrink uses a different
        // (L2-table) staging strategy.  Caller must dispatch.
        return Err(ResizeError::UnsupportedShrink);
    }
    if q.preallocation == Preallocation::Metadata {
        return Err(ResizeError::PreallocationUnsupported);
    }
    if q.extended_l2 && q.preallocation != Preallocation::Off {
        return Err(ResizeError::PreallocationUnsupported);
    }

    let cluster_bits = cluster_bits_from(q.cluster_size)?;
    let cluster_size = q.cluster_size as u64;
    // qemu-img truncates a fresh image at the exact end of its L1
    // table, so a valid qcow2's file size need not be cluster-
    // aligned (issue #373). Appended regions start at the next
    // cluster boundary — where qemu's own allocator would place
    // them — so enumerate blocks from the aligned-up size, matching
    // the planner's placement.
    let q = &Qcow2ResizeGrowQuery {
        current_file_size: q
            .current_file_size
            .checked_next_multiple_of(cluster_size)
            .ok_or(ResizeError::HeaderMismatch)?,
        ..*q
    };

    // No-change: empty plan, no blocks to stage.
    if q.new_virtual_size == q.current_virtual_size {
        return Ok(Qcow2GrowQueryResult {
            action: Qcow2GrowAction::HeaderOnly,
            required_blocks: [0; QCOW2_MAX_REQUIRED_BLOCKS],
            required_blocks_len: 0,
        });
    }

    // Run compute_layout for the *target* geometry so we can
    // decide_action identically to plan_grow.
    let target_layout = compute_layout(
        q.new_virtual_size,
        cluster_bits,
        q.refcount_bits as u32,
        q.extended_l2,
        Qcow2CreatePreallocation::Off,
    )
    .map_err(map_qcow2_create_err)?;

    let existing_block_count = count_existing_refcount_blocks(q.existing_refcount_table_bytes);

    // Use append-aware RB/RT counts (not target_layout's fresh-build
    // counts) when L1 grows — the appended L1 region can spill into
    // refcount-block territory that a compact fresh build would not
    // have needed, forcing L1AndRefcountGrow.
    let l1_grows = target_layout.l1_entries > q.current_l1_entries;
    let (effective_block_count, effective_table_clusters) = if l1_grows {
        let target_l1_clusters = ((target_layout.l1_entries as u64) * 8)
            .div_ceil(cluster_size)
            .max(1);
        let (bc, tc, _) = compute_append_requirements(
            q.current_file_size,
            cluster_size,
            q.refcount_bits,
            target_l1_clusters,
            q.current_refcount_table_clusters as u64,
            existing_block_count,
        );
        (bc, tc)
    } else {
        (
            target_layout.refcount_block_count,
            target_layout.refcount_table_clusters,
        )
    };

    let action = decide_action(
        q.current_l1_entries,
        q.current_refcount_table_clusters,
        existing_block_count,
        target_layout.l1_entries,
        effective_table_clusters,
        effective_block_count,
    );

    // Enumerate cluster ranges per flavour and dedupe to distinct
    // block indices.
    let mut required = RequiredBlocks::new();
    let entries_per_refblock: u64 = (cluster_size * 8) / q.refcount_bits as u64;
    debug_assert!(entries_per_refblock > 0);

    match action {
        Qcow2GrowAction::HeaderOnly => {
            // Nothing to stage.
        }
        Qcow2GrowAction::L1Grow => {
            add_l1_growth_blocks(&mut required, q, &target_layout, entries_per_refblock)?;
        }
        Qcow2GrowAction::L1AndRefcountGrow => {
            add_l1_and_refcount_growth_blocks(
                &mut required,
                q,
                &target_layout,
                existing_block_count,
                entries_per_refblock,
            )?;
        }
    }

    Ok(Qcow2GrowQueryResult {
        action,
        required_blocks: required.storage,
        required_blocks_len: required.len,
    })
}

/// Small helper struct for de-duplicating block indices into a
/// fixed-size array.
struct RequiredBlocks {
    storage: [u64; QCOW2_MAX_REQUIRED_BLOCKS],
    len: usize,
}

impl RequiredBlocks {
    fn new() -> Self {
        Self {
            storage: [0; QCOW2_MAX_REQUIRED_BLOCKS],
            len: 0,
        }
    }

    /// Add `block_idx` if it isn't already present.  Returns
    /// `ScratchTooSmall` if the array is full — that's the
    /// "planner needs more blocks than the helper budgeted for"
    /// signal, and means [`QCOW2_MAX_REQUIRED_BLOCKS`] needs
    /// raising rather than that the caller did anything wrong.
    fn add(&mut self, block_idx: u64) -> Result<(), ResizeError> {
        for i in 0..self.len {
            if self.storage[i] == block_idx {
                return Ok(());
            }
        }
        if self.len >= QCOW2_MAX_REQUIRED_BLOCKS {
            return Err(ResizeError::ScratchTooSmall);
        }
        self.storage[self.len] = block_idx;
        self.len += 1;
        Ok(())
    }
}

/// Identify blocks the L1Grow flavour touches: new L1 region
/// clusters (increment side) plus old L1 region clusters
/// (decrement side).
fn add_l1_growth_blocks(
    required: &mut RequiredBlocks,
    q: &Qcow2ResizeGrowQuery<'_>,
    target_layout: &Qcow2Layout,
    entries_per_refblock: u64,
) -> Result<(), ResizeError> {
    let cluster_size = q.cluster_size as u64;

    let new_l1_size_bytes = (target_layout.l1_entries as u64) * 8;
    let new_l1_clusters = new_l1_size_bytes.div_ceil(cluster_size).max(1);
    let new_l1_first_cluster = q.current_file_size / cluster_size;
    let new_l1_last_cluster = new_l1_first_cluster + new_l1_clusters - 1;

    let old_l1_first_cluster = q.current_l1_table_offset / cluster_size;
    let old_l1_size_bytes = (q.current_l1_entries as u64) * 8;
    let old_l1_clusters = old_l1_size_bytes.div_ceil(cluster_size).max(1);
    let old_l1_last_cluster = old_l1_first_cluster + old_l1_clusters - 1;

    for c in new_l1_first_cluster..=new_l1_last_cluster {
        required.add(c / entries_per_refblock)?;
    }
    for c in old_l1_first_cluster..=old_l1_last_cluster {
        required.add(c / entries_per_refblock)?;
    }
    Ok(())
}

/// Identify blocks the L1AndRefcountGrow flavour touches.
///
/// The flavour appends a new L1 region, optionally a relocated
/// refcount table, and one or more new refcount blocks (all at
/// EOF).  Existing refcount blocks need staging only when:
///
/// - they contain the "overlap" clusters — the trailing slice
///   of the new appended region that still falls within an
///   already-existing refcount block (the last existing block
///   may be partially populated), AND
/// - they contain the "cleanup" clusters — the old L1 region
///   and (if the table relocates) the old refcount table.
///
/// New refcount blocks beyond `existing_block_count` are
/// constructed from scratch by the planner — no existing
/// block-bytes to stage for those.
fn add_l1_and_refcount_growth_blocks(
    required: &mut RequiredBlocks,
    q: &Qcow2ResizeGrowQuery<'_>,
    target_layout: &Qcow2Layout,
    existing_block_count: u64,
    entries_per_refblock: u64,
) -> Result<(), ResizeError> {
    let cluster_size = q.cluster_size as u64;

    let new_l1_size_bytes = (target_layout.l1_entries as u64) * 8;
    let new_l1_clusters = new_l1_size_bytes.div_ceil(cluster_size).max(1);
    let new_l1_offset = q.current_file_size;

    // Mirror plan_l1_and_refcount_grow's append-aware sizing.
    let current_rt_clusters = q.current_refcount_table_clusters as u64;
    let (effective_block_count, effective_table_clusters, _) = compute_append_requirements(
        q.current_file_size,
        cluster_size,
        q.refcount_bits,
        new_l1_clusters,
        current_rt_clusters,
        existing_block_count,
    );
    let table_relocates = effective_table_clusters > current_rt_clusters;

    let new_refcount_table_offset = new_l1_offset + new_l1_clusters * cluster_size;
    let new_refcount_table_size = if table_relocates {
        effective_table_clusters * cluster_size
    } else {
        0
    };
    let new_refcount_blocks_offset = new_refcount_table_offset + new_refcount_table_size;
    let new_block_count_delta = effective_block_count.saturating_sub(existing_block_count);
    let new_refcount_blocks_size = new_block_count_delta * cluster_size;
    let total_file_size = new_refcount_blocks_offset + new_refcount_blocks_size;
    let new_total_clusters = total_file_size / cluster_size;

    // Overlap range: clusters in [pre_resize_cluster_count,
    // min(existing_block_coverage, new_total_clusters)) live in
    // existing refcount blocks that need staging.  Beyond
    // existing_block_coverage the planner writes brand-new
    // refcount blocks, so no existing block to stage.
    let pre_resize_cluster_count = q.current_file_size / cluster_size;
    let existing_block_coverage = existing_block_count * entries_per_refblock;
    let overlap_last_excl = existing_block_coverage.min(new_total_clusters);
    let mut c = pre_resize_cluster_count;
    while c < overlap_last_excl {
        required.add(c / entries_per_refblock)?;
        c += 1;
    }

    // Cleanup: old L1 region.
    let old_l1_first = q.current_l1_table_offset / cluster_size;
    let old_l1_clusters = ((q.current_l1_entries as u64) * 8)
        .div_ceil(cluster_size)
        .max(1);
    let old_l1_last_excl = old_l1_first + old_l1_clusters;
    for c in old_l1_first..old_l1_last_excl {
        required.add(c / entries_per_refblock)?;
    }

    // Cleanup: old refcount table (only if relocated).
    if table_relocates {
        let old_rt_first = q.current_refcount_table_offset / cluster_size;
        let old_rt_last_excl = old_rt_first + q.current_refcount_table_clusters as u64;
        for c in old_rt_first..old_rt_last_excl {
            required.add(c / entries_per_refblock)?;
        }
    }

    Ok(())
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
    validate_incompat(opts.current_incompatible_features)?;
    validate_no_bitmaps(opts.current_autoclear_features)?;
    if opts.new_virtual_size < opts.current_virtual_size {
        if !opts.allow_shrink {
            return Err(ResizeError::ShrinkWithoutFlag);
        }
        return plan_shrink(opts, scratch);
    }
    if opts.new_virtual_size == opts.current_virtual_size {
        return Ok(ResizePlan::new(ResizeAction::NoOp, opts.current_file_size));
    }
    if opts.preallocation == Preallocation::Metadata {
        // 2c lifts this gate after the metadata layer lands.
        return Err(ResizeError::PreallocationUnsupported);
    }
    if opts.extended_l2 && opts.preallocation != Preallocation::Off {
        return Err(ResizeError::PreallocationUnsupported);
    }

    let cluster_bits = cluster_bits_from(opts.cluster_size)?;
    // qemu-img truncates a fresh image at the exact end of its L1
    // table, so a valid qcow2's file size need not be cluster-
    // aligned (issue #373). Appended regions start at the next
    // cluster boundary — where qemu's own allocator would place
    // them — so size and plan the appending flavours from the
    // aligned-up file size. HeaderOnly keeps the true size: it
    // appends nothing and must not extend the file.
    let aligned_opts = &Qcow2ResizeOpts {
        current_file_size: opts
            .current_file_size
            .checked_next_multiple_of(opts.cluster_size as u64)
            .ok_or(ResizeError::HeaderMismatch)?,
        ..*opts
    };

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

    // Use append-aware RB/RT counts (not target_layout's fresh-build
    // counts) when L1 grows — see compute_append_requirements.
    let l1_grows = target_layout.l1_entries > opts.current_l1_entries;
    let (effective_block_count, effective_table_clusters) = if l1_grows {
        let target_l1_clusters = ((target_layout.l1_entries as u64) * 8)
            .div_ceil(opts.cluster_size as u64)
            .max(1);
        let (bc, tc, _) = compute_append_requirements(
            aligned_opts.current_file_size,
            opts.cluster_size as u64,
            opts.refcount_bits,
            target_l1_clusters,
            opts.current_refcount_table_clusters as u64,
            existing_block_count,
        );
        (bc, tc)
    } else {
        (
            target_layout.refcount_block_count,
            target_layout.refcount_table_clusters,
        )
    };

    let action = decide_action(
        opts.current_l1_entries,
        opts.current_refcount_table_clusters,
        existing_block_count,
        target_layout.l1_entries,
        effective_table_clusters,
        effective_block_count,
    );

    match action {
        Qcow2GrowAction::HeaderOnly => plan_header_only(opts, scratch),
        Qcow2GrowAction::L1Grow => plan_l1_grow(aligned_opts, &target_layout, scratch),
        Qcow2GrowAction::L1AndRefcountGrow => {
            plan_l1_and_refcount_grow(aligned_opts, &target_layout, existing_block_count, scratch)
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

/// L1AndRefcountGrow path: the full algorithm. The L1 grows AND
/// the refcount table needs more blocks (or possibly a larger
/// table itself; we always relocate when it grows).
///
/// File layout after the resize (appended in this order):
///   [current EOF .. ] new L1 region
///   [..] new refcount-table region (only if the table grows)
///   [..] new refcount blocks
///
/// Patch sequence (crash-safe ordering):
///   Phase A (prepare):
///     1. Append new L1 region
///     2. Append new refcount-table region (if relocated)
///     3. Append new refcount blocks (pre-populated with
///        refcount=1 for every cluster in the post-resize image)
///     4. Write existing refcount blocks that need entry-level
///        patching (for the rare case where the new clusters
///        overlap an existing block's coverage range)
///   Phase B (commit):
///     5. Write new header
///   Phase C (cleanup):
///     6. Write decrements for old L1 region's refcount entries
///     7. Write decrements for old refcount-table's refcount
///        entries (if relocated)
///
/// Preallocation::Metadata is rejected by the upstream gate in
/// plan_grow; integrating it into this path is deferred.
fn plan_l1_and_refcount_grow<'a>(
    opts: &Qcow2ResizeOpts<'_>,
    target_layout: &Qcow2Layout,
    existing_block_count: u64,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    let cluster_size = opts.cluster_size as u64;
    let cluster_size_us = opts.cluster_size as usize;
    let entries_per_refblock: u64 = (cluster_size * 8) / opts.refcount_bits as u64;

    let new_l1_entries = target_layout.l1_entries;
    let new_l1_clusters = ((new_l1_entries as u64) * 8).div_ceil(cluster_size).max(1);
    let new_l1_size_bytes = new_l1_clusters * cluster_size;

    // Derive refcount-block/table requirements for the resize-by-
    // append strategy. target_layout models a *fresh compact build*
    // which under-counts the append strategy's needs (the old L1
    // region stays in place, growing the post-resize file).
    let current_rt_clusters = opts.current_refcount_table_clusters as u64;
    let (effective_block_count, effective_table_clusters, _new_total_clusters_est) =
        compute_append_requirements(
            opts.current_file_size,
            cluster_size,
            opts.refcount_bits,
            new_l1_clusters,
            current_rt_clusters,
            existing_block_count,
        );
    let new_block_count_delta = effective_block_count.saturating_sub(existing_block_count);
    let table_relocates = effective_table_clusters > current_rt_clusters;
    // The existing RT also needs a Write patch when it stays in
    // place but new RBs are added — the new RT entries pointing at
    // the new blocks must be persisted before the header commit.
    let table_updates_in_place = !table_relocates && new_block_count_delta > 0;

    // File layout post-resize.
    let new_l1_offset = opts.current_file_size;
    let new_refcount_table_offset = new_l1_offset + new_l1_size_bytes;
    let new_refcount_table_size_bytes = if table_relocates {
        effective_table_clusters * cluster_size
    } else {
        0
    };
    let new_refcount_blocks_offset = new_refcount_table_offset + new_refcount_table_size_bytes;
    let new_refcount_blocks_size_bytes = new_block_count_delta * cluster_size;
    let total_file_size = new_refcount_blocks_offset + new_refcount_blocks_size_bytes;
    let new_total_clusters = total_file_size / cluster_size;

    let effective_table_offset = if table_relocates {
        new_refcount_table_offset
    } else {
        opts.current_refcount_table_offset
    };

    // Carve scratch: header (1 cluster) + new L1 + RT staging
    // (sized to the effective table when there's any RT patch) +
    // new RBs + per-existing-block staging slots.
    let rt_staging_bytes = if table_relocates || table_updates_in_place {
        effective_table_clusters * cluster_size
    } else {
        0
    };
    let header_off = 0usize;
    let header_end = cluster_size_us;
    let l1_off = header_end;
    let l1_end = l1_off + new_l1_size_bytes as usize;
    let table_off = l1_end;
    let table_end = table_off + rt_staging_bytes as usize;
    let blocks_off = table_end;
    let blocks_end = blocks_off + new_refcount_blocks_size_bytes as usize;
    if blocks_end > scratch.len() {
        return Err(ResizeError::ScratchTooSmall);
    }

    // Build new L1 region (existing entries + zero pad).
    {
        let l1_buf = &mut scratch[l1_off..l1_end];
        l1_buf.fill(0);
        let old_l1_size_bytes = (opts.current_l1_entries as u64) * 8;
        let copy_len = opts.existing_l1_bytes.len().min(old_l1_size_bytes as usize);
        l1_buf[..copy_len].copy_from_slice(&opts.existing_l1_bytes[..copy_len]);
    }

    // Build the RT region — used by either the relocated Append
    // (table_relocates) or the in-place Write (table_updates_in_place).
    // Both flavours need the existing entries plus the new ones
    // pointing at the newly-appended refcount blocks.
    if table_relocates || table_updates_in_place {
        let table_buf = &mut scratch[table_off..table_end];
        table_buf.fill(0);
        let copy_len = opts
            .existing_refcount_table_bytes
            .len()
            .min(table_buf.len());
        table_buf[..copy_len].copy_from_slice(&opts.existing_refcount_table_bytes[..copy_len]);
        for i in 0..new_block_count_delta {
            let entry_idx = (existing_block_count + i) as usize;
            let entry_off = entry_idx * 8;
            if entry_off + 8 > table_buf.len() {
                return Err(ResizeError::ScratchTooSmall);
            }
            let block_file_offset = new_refcount_blocks_offset + i * cluster_size;
            write_be_u64(table_buf, entry_off, block_file_offset);
        }
    }

    // Build new refcount blocks: refcount=1 for every cluster in
    // [first_covered..new_total_clusters), 0 elsewhere. This
    // covers the post-resize image's new region (clusters >=
    // current_file_size / cluster_size).
    {
        let blocks_buf = &mut scratch[blocks_off..blocks_end];
        blocks_buf.fill(0);
        for i in 0..new_block_count_delta {
            let block_idx_in_table = existing_block_count + i;
            let block_buf = &mut blocks_buf
                [(i as usize) * cluster_size_us..((i as usize) + 1) * cluster_size_us];
            let first_cluster = block_idx_in_table * entries_per_refblock;
            for j in 0..entries_per_refblock {
                let cluster_idx = first_cluster + j;
                if cluster_idx < new_total_clusters {
                    set_refcount(block_buf, j, opts.refcount_bits, 1)?;
                }
            }
        }
    }

    // Build the new header (last "prepare"-ordered patch).
    let header_layout = Qcow2Layout {
        cluster_bits: cluster_bits_from(opts.cluster_size).expect("validated upstream"),
        cluster_size,
        virtual_size: opts.new_virtual_size,
        refcount_bits: opts.refcount_bits as u32,
        extended_l2: opts.extended_l2,
        preallocation: Qcow2CreatePreallocation::Off,
        l1_entries: new_l1_entries,
        l1_size_bytes: (new_l1_entries as u64) * 8,
        l1_clusters: new_l1_clusters,
        l1_offset: new_l1_offset,
        refcount_table_offset: effective_table_offset,
        refcount_table_clusters: effective_table_clusters,
        refcount_block_count: 0,
        refcount_blocks_base_offset: 0,
        l2_clusters: 0,
        l2_base_offset: 0,
        data_clusters: 0,
        data_base_offset: 0,
        total_clusters: 0,
        total_file_size: 0,
    };
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

    // === Stage overlap and cleanup work BEFORE assembling
    // patches (the assembly takes immutable borrows on scratch
    // that would otherwise conflict). ===
    const MAX_OVERLAP_BLOCKS: usize = 4;
    let mut overlap_slots: [(u64, usize); MAX_OVERLAP_BLOCKS] = [(0, 0); MAX_OVERLAP_BLOCKS];
    let mut overlap_count: usize = 0;
    const MAX_CLEANUP_BLOCKS: usize = 8;
    let mut cleanup_slots: [(u64, usize); MAX_CLEANUP_BLOCKS] = [(0, 0); MAX_CLEANUP_BLOCKS];
    let mut cleanup_count: usize = 0;
    let mut next_staging = blocks_end;

    // Overlap: existing blocks that hold entries for newly-
    // allocated clusters (the last existing block may not be
    // full).
    let pre_resize_cluster_count = opts.current_file_size / cluster_size;
    let existing_block_coverage = existing_block_count * entries_per_refblock;
    let overlap_first = pre_resize_cluster_count;
    let overlap_last_excl = existing_block_coverage.min(new_total_clusters);

    let mut c = overlap_first;
    while c < overlap_last_excl {
        let block_idx = c / entries_per_refblock;
        let local_idx = c % entries_per_refblock;
        let off = if let Some(pos) = overlap_slots
            .iter()
            .take(overlap_count)
            .position(|(idx, _)| *idx == block_idx)
        {
            overlap_slots[pos].1
        } else {
            if overlap_count >= MAX_OVERLAP_BLOCKS {
                return Err(ResizeError::ScratchTooSmall);
            }
            let new_off = allocate_staging(&mut next_staging, scratch.len(), cluster_size_us)?;
            ensure_block_staged(opts, block_idx, scratch, new_off, cluster_size_us)?;
            overlap_slots[overlap_count] = (block_idx, new_off);
            overlap_count += 1;
            new_off
        };
        set_refcount(
            &mut scratch[off..off + cluster_size_us],
            local_idx,
            opts.refcount_bits,
            1,
        )?;
        c += 1;
    }

    // Cleanup: old L1 region clusters, plus old refcount table
    // clusters if the table relocated.
    let old_l1_first = opts.current_l1_table_offset / cluster_size;
    let old_l1_clusters = ((opts.current_l1_entries as u64) * 8)
        .div_ceil(cluster_size)
        .max(1);
    let old_l1_last_excl = old_l1_first + old_l1_clusters;
    for c in old_l1_first..old_l1_last_excl {
        stage_cleanup_decrement(
            opts,
            scratch,
            c,
            entries_per_refblock,
            &mut cleanup_slots,
            &mut cleanup_count,
            MAX_CLEANUP_BLOCKS,
            &mut next_staging,
            cluster_size_us,
            &overlap_slots,
            overlap_count,
        )?;
    }
    if table_relocates {
        let old_rt_first = opts.current_refcount_table_offset / cluster_size;
        let old_rt_last_excl = old_rt_first + opts.current_refcount_table_clusters as u64;
        for c in old_rt_first..old_rt_last_excl {
            stage_cleanup_decrement(
                opts,
                scratch,
                c,
                entries_per_refblock,
                &mut cleanup_slots,
                &mut cleanup_count,
                MAX_CLEANUP_BLOCKS,
                &mut next_staging,
                cluster_size_us,
                &overlap_slots,
                overlap_count,
            )?;
        }
    }

    // === Assemble the plan in crash-safe order. ===
    let mut plan = ResizePlan::new(ResizeAction::Grow, total_file_size);

    // Phase A — prepare (1-3): appends.
    plan.push(ResizePatch::Append {
        byte_offset: new_l1_offset,
        bytes: &scratch[l1_off..l1_end],
    })?;
    if table_relocates {
        plan.push(ResizePatch::Append {
            byte_offset: new_refcount_table_offset,
            bytes: &scratch[table_off..table_end],
        })?;
    }
    if new_block_count_delta > 0 {
        plan.push(ResizePatch::Append {
            byte_offset: new_refcount_blocks_offset,
            bytes: &scratch[blocks_off..blocks_end],
        })?;
    }
    // In-place RT update: when the table stays at its existing
    // location but new RB entries were added, write the updated
    // table back to its existing offset (before the header commit,
    // so a crash mid-flight still leaves a consistent RT once the
    // header is rewritten).
    if table_updates_in_place {
        plan.push(ResizePatch::Write {
            byte_offset: opts.current_refcount_table_offset,
            bytes: &scratch[table_off..table_end],
        })?;
    }

    // Phase A (4): overlap patches.
    for slot in overlap_slots.iter().take(overlap_count) {
        let block_file_off = block_offset_in_file(opts.existing_refcount_table_bytes, slot.0)?;
        plan.push(ResizePatch::Write {
            byte_offset: block_file_off,
            bytes: &scratch[slot.1..slot.1 + cluster_size_us],
        })?;
    }

    // Phase B — header rewrite (atomic commit).
    plan.push(ResizePatch::Write {
        byte_offset: 0,
        bytes: &scratch[header_off..header_off + header_bytes_len],
    })?;

    // Phase C — cleanup decrements.
    for slot in cleanup_slots.iter().take(cleanup_count) {
        let block_file_off = block_offset_in_file(opts.existing_refcount_table_bytes, slot.0)?;
        plan.push(ResizePatch::Write {
            byte_offset: block_file_off,
            bytes: &scratch[slot.1..slot.1 + cluster_size_us],
        })?;
    }

    Ok(plan)
}

#[allow(clippy::too_many_arguments)]
fn stage_cleanup_decrement(
    opts: &Qcow2ResizeOpts<'_>,
    scratch: &mut [u8],
    cluster_idx: u64,
    entries_per_refblock: u64,
    cleanup_slots: &mut [(u64, usize); 8],
    cleanup_count: &mut usize,
    max_blocks: usize,
    next_staging: &mut usize,
    cluster_size_us: usize,
    overlap_slots: &[(u64, usize)],
    overlap_count: usize,
) -> Result<(), ResizeError> {
    let block_idx = cluster_idx / entries_per_refblock;
    let local_idx = cluster_idx % entries_per_refblock;
    let off = if let Some(pos) = cleanup_slots
        .iter()
        .take(*cleanup_count)
        .position(|(idx, _)| *idx == block_idx)
    {
        cleanup_slots[pos].1
    } else {
        if *cleanup_count >= max_blocks {
            return Err(ResizeError::ScratchTooSmall);
        }
        let new_off = allocate_staging(next_staging, scratch.len(), cluster_size_us)?;
        // Seed the cleanup slot from the overlap slot if it exists
        // — the Phase C write is the FINAL state and must include
        // any Phase A increments to the same block. Without this,
        // the cleanup write overwrites the overlap write because
        // they target the same file offset.
        if let Some(pos) = overlap_slots
            .iter()
            .take(overlap_count)
            .position(|(idx, _)| *idx == block_idx)
        {
            let src_off = overlap_slots[pos].1;
            scratch.copy_within(src_off..src_off + cluster_size_us, new_off);
        } else {
            ensure_block_staged(opts, block_idx, scratch, new_off, cluster_size_us)?;
        }
        cleanup_slots[*cleanup_count] = (block_idx, new_off);
        *cleanup_count += 1;
        new_off
    };
    set_refcount(
        &mut scratch[off..off + cluster_size_us],
        local_idx,
        opts.refcount_bits,
        0,
    )?;
    Ok(())
}

/// Shrink planner: walk L1/L2 to identify clusters above
/// `new_virtual_size`, zero their L2 entries and L1 entries
/// (where the entire L2 coverage is above the boundary),
/// decrement refcounts to 0, and rewrite the header. No file
/// truncation; matches qemu's behaviour.
///
/// Patch sequence (crash-safe ordering — prepare → header,
/// no cleanup phase because no metadata is relocated):
///   1. Write: straddling L2 table (if any) with entries above
///      the boundary zeroed
///   2. Write: existing L1 region with discarded entries zeroed
///   3. Write: each modified existing refcount block (entries
///      decremented to 0 for discarded data clusters and the
///      L2-table clusters they referenced)
///   4. Write: new header (header.size = new_virtual_size)
fn plan_shrink<'a>(
    opts: &Qcow2ResizeOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    let cluster_size = opts.cluster_size as u64;
    let cluster_size_us = opts.cluster_size as usize;
    let cluster_bits = cluster_bits_from(opts.cluster_size)?;

    // Round down to cluster boundary per the phase plan's
    // open question 1.
    let new_virtual_size = (opts.new_virtual_size / cluster_size) * cluster_size;
    if new_virtual_size < cluster_size {
        // Minimum one cluster of virtual size; smaller asks
        // are rejected.
        return Err(ResizeError::InvalidNewVirtualSize);
    }

    let l2_entry_size: u64 = if opts.extended_l2 { 16 } else { 8 };
    let entries_per_l2: u64 = cluster_size / l2_entry_size;
    let l2_coverage: u64 = cluster_size * entries_per_l2;
    let entries_per_refblock: u64 = (cluster_size * 8) / opts.refcount_bits as u64;

    // L1 entries fully above the new size.
    let first_discarded_l1_idx = new_virtual_size.div_ceil(l2_coverage) as u32;
    // The L1 entry whose coverage range straddles the boundary
    // (if any). When new_virtual_size is an exact multiple of
    // l2_coverage, no straddling case.
    let straddle_l1_idx: Option<u32> = if new_virtual_size.is_multiple_of(l2_coverage) {
        None
    } else {
        Some((new_virtual_size / l2_coverage) as u32)
    };

    // Carve scratch:
    //   [0..cluster_size)                — new header
    //   [cluster_size..+l1_region_bytes) — rewritten L1 region
    //   [..+cluster_size)                — straddling L2 staging
    //   [..]                             — refcount-block staging
    let old_l1_size_bytes = (opts.current_l1_entries as u64) * 8;
    let old_l1_clusters = old_l1_size_bytes.div_ceil(cluster_size).max(1);
    let l1_region_bytes = old_l1_clusters * cluster_size;

    let header_off = 0usize;
    let header_end = cluster_size_us;
    let l1_off = header_end;
    let l1_end = l1_off + l1_region_bytes as usize;
    let straddle_l2_off = l1_end;
    let straddle_l2_end = straddle_l2_off + cluster_size_us;
    if straddle_l2_end > scratch.len() {
        return Err(ResizeError::ScratchTooSmall);
    }
    let mut next_staging = straddle_l2_end;

    // Build the new L1 region: copy existing + zero discarded
    // L1 entries (we mark them zero up-front; the walk loop
    // below validates that the L2 walk doesn't reveal allocated
    // data the user didn't authorise to drop).
    {
        let l1_buf = &mut scratch[l1_off..l1_end];
        l1_buf.fill(0);
        let copy_len = opts.existing_l1_bytes.len().min(old_l1_size_bytes as usize);
        l1_buf[..copy_len].copy_from_slice(&opts.existing_l1_bytes[..copy_len]);
    }

    // Track existing refcount blocks we need to patch (decrement
    // entries to 0 for each discarded data/L2 cluster). Up to
    // MAX_DISCARD_REFBLOCKS distinct blocks; if exceeded return
    // ScratchTooSmall.
    const MAX_DISCARD_REFBLOCKS: usize = 64;
    let mut refblock_slots: [(u64, usize); MAX_DISCARD_REFBLOCKS] = [(0, 0); MAX_DISCARD_REFBLOCKS];
    let mut refblock_count: usize = 0;

    let mut decrement_cluster = |scratch: &mut [u8],
                                 next_staging: &mut usize,
                                 refblock_slots: &mut [(u64, usize); MAX_DISCARD_REFBLOCKS],
                                 refblock_count: &mut usize,
                                 host_offset: u64|
     -> Result<(), ResizeError> {
        let cluster_idx = host_offset / cluster_size;
        let block_idx = cluster_idx / entries_per_refblock;
        let local_idx = cluster_idx % entries_per_refblock;
        let off = if let Some(pos) = refblock_slots
            .iter()
            .take(*refblock_count)
            .position(|(idx, _)| *idx == block_idx)
        {
            refblock_slots[pos].1
        } else {
            if *refblock_count >= MAX_DISCARD_REFBLOCKS {
                return Err(ResizeError::ScratchTooSmall);
            }
            let new_off = allocate_staging(next_staging, scratch.len(), cluster_size_us)?;
            ensure_block_staged(opts, block_idx, scratch, new_off, cluster_size_us)?;
            refblock_slots[*refblock_count] = (block_idx, new_off);
            *refblock_count += 1;
            new_off
        };
        set_refcount(
            &mut scratch[off..off + cluster_size_us],
            local_idx,
            opts.refcount_bits,
            0,
        )?;
        Ok(())
    };

    // 1. Walk L1 entries fully above new_virtual_size.
    for i in first_discarded_l1_idx..opts.current_l1_entries {
        let l1_entry = be_u64(opts.existing_l1_bytes, (i as usize) * 8);
        if l1_entry == 0 {
            continue;
        }
        let l2_host = l1_entry & qcow2::L2_OFFSET_MASK;
        // Walk the L2 table; for each non-zero data entry,
        // decrement (or reject without --shrink).
        let l2_bytes = lookup_l2(opts, i, cluster_size_us)?;
        walk_l2_for_discard(
            opts,
            l2_bytes,
            None, // discard all entries
            scratch,
            &mut next_staging,
            &mut refblock_slots,
            &mut refblock_count,
            &mut decrement_cluster,
            l2_entry_size,
        )?;
        // Decrement the L2 table cluster itself.
        decrement_cluster(
            scratch,
            &mut next_staging,
            &mut refblock_slots,
            &mut refblock_count,
            l2_host,
        )?;
        // Zero the L1 entry in the rewritten L1 region.
        let l1_buf = &mut scratch[l1_off..l1_end];
        let off = (i as usize) * 8;
        write_be_u64(l1_buf, off, 0);
    }

    // 2. Handle the straddling L1 entry (if any).
    let mut straddle_emit = false;
    if let Some(i) = straddle_l1_idx {
        let l1_entry = be_u64(opts.existing_l1_bytes, (i as usize) * 8);
        if l1_entry != 0 {
            let l2_bytes = lookup_l2(opts, i, cluster_size_us)?;
            // Stage the L2 table; zero the entries whose guest
            // offset is >= new_virtual_size, decrement the
            // referenced data clusters.
            let base_virtual = (i as u64) * l2_coverage;
            // Copy l2_bytes into staging, then mutate.
            scratch[straddle_l2_off..straddle_l2_end].copy_from_slice(l2_bytes);
            let entries = entries_per_l2 as usize;
            for j in 0..entries {
                let entry_off = j * l2_entry_size as usize;
                let l2e = be_u64(l2_bytes, entry_off);
                let v_start = base_virtual + (j as u64) * cluster_size;
                if v_start < new_virtual_size {
                    continue;
                }
                if l2e == 0 {
                    // Already unallocated; nothing to do beyond
                    // ensuring the entry stays zero.
                    if l2_entry_size == 16 {
                        let staged = &mut scratch[straddle_l2_off..straddle_l2_end];
                        write_be_u64(staged, entry_off, 0);
                        write_be_u64(staged, entry_off + 8, 0);
                    } else {
                        let staged = &mut scratch[straddle_l2_off..straddle_l2_end];
                        write_be_u64(staged, entry_off, 0);
                    }
                    straddle_emit = true;
                    continue;
                }
                // Allocated cluster above the boundary — discard.
                let data_host = l2e & qcow2::L2_OFFSET_MASK;
                decrement_cluster(
                    scratch,
                    &mut next_staging,
                    &mut refblock_slots,
                    &mut refblock_count,
                    data_host,
                )?;
                // Zero the L2 entry in staging.
                let staged = &mut scratch[straddle_l2_off..straddle_l2_end];
                write_be_u64(staged, entry_off, 0);
                if l2_entry_size == 16 {
                    write_be_u64(staged, entry_off + 8, 0);
                }
                straddle_emit = true;
            }
        }
    }

    // 3. Build the new header.
    let header_layout = Qcow2Layout {
        cluster_bits,
        cluster_size,
        virtual_size: new_virtual_size,
        refcount_bits: opts.refcount_bits as u32,
        extended_l2: opts.extended_l2,
        preallocation: Qcow2CreatePreallocation::Off,
        l1_entries: opts.current_l1_entries,
        l1_size_bytes: old_l1_size_bytes,
        l1_clusters: old_l1_clusters,
        l1_offset: opts.current_l1_table_offset,
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
    };
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

    // 4. Assemble the plan in crash-safe order.
    let mut plan = ResizePlan::new(ResizeAction::Shrink, opts.current_file_size);

    // Phase A — prepare:
    if straddle_emit {
        if let Some(i) = straddle_l1_idx {
            let l1_entry = be_u64(opts.existing_l1_bytes, (i as usize) * 8);
            let l2_host = l1_entry & qcow2::L2_OFFSET_MASK;
            plan.push(ResizePatch::Write {
                byte_offset: l2_host,
                bytes: &scratch[straddle_l2_off..straddle_l2_end],
            })?;
        }
    }
    // L1 region rewrite (with discarded entries zeroed). Always
    // emit even if no L1 entries were zeroed, to keep the patch
    // sequence uniform — qemu's check tolerates a no-op rewrite.
    // Actually skip it if nothing changed: the straddle-only
    // case doesn't touch L1.
    let l1_changed = first_discarded_l1_idx < opts.current_l1_entries
        && (first_discarded_l1_idx..opts.current_l1_entries)
            .any(|i| be_u64(opts.existing_l1_bytes, (i as usize) * 8) != 0);
    if l1_changed {
        plan.push(ResizePatch::Write {
            byte_offset: opts.current_l1_table_offset,
            bytes: &scratch[l1_off..l1_end],
        })?;
    }
    // Refcount-block patches (each modified block, with all
    // relevant entries decremented to 0).
    for slot in refblock_slots.iter().take(refblock_count) {
        let block_file_off = block_offset_in_file(opts.existing_refcount_table_bytes, slot.0)?;
        plan.push(ResizePatch::Write {
            byte_offset: block_file_off,
            bytes: &scratch[slot.1..slot.1 + cluster_size_us],
        })?;
    }

    // Phase B — header rewrite (atomic commit).
    plan.push(ResizePatch::Write {
        byte_offset: 0,
        bytes: &scratch[header_off..header_off + header_bytes_len],
    })?;

    Ok(plan)
}

/// Walk an L2 table, decrementing refcounts for non-zero entries
/// in the discard range. With `boundary == None` (fully-discarded
/// L1 entry), every non-zero entry is decremented. With
/// `boundary == Some((base_virtual, new_virtual_size))`
/// (straddling case), only entries whose guest offset is
/// `>= new_virtual_size` are decremented.
///
/// Returns `ShrinkBelowAllocated` if `!opts.allow_shrink` and any
/// entry in the discard range is allocated. Otherwise updates
/// refblock_slots in place via the `decrement` closure.
#[allow(clippy::too_many_arguments)]
fn walk_l2_for_discard(
    opts: &Qcow2ResizeOpts<'_>,
    l2_bytes: &[u8],
    boundary: Option<(u64, u64)>, // (base_virtual, new_virtual_size)
    scratch: &mut [u8],
    next_staging: &mut usize,
    refblock_slots: &mut [(u64, usize); 64],
    refblock_count: &mut usize,
    decrement: &mut impl FnMut(
        &mut [u8],
        &mut usize,
        &mut [(u64, usize); 64],
        &mut usize,
        u64,
    ) -> Result<(), ResizeError>,
    l2_entry_size: u64,
) -> Result<(), ResizeError> {
    let cluster_size = opts.cluster_size as u64;
    let entries = (opts.cluster_size as u64 / l2_entry_size) as usize;
    for j in 0..entries {
        let entry_off = j * l2_entry_size as usize;
        if entry_off + 8 > l2_bytes.len() {
            return Err(ResizeError::ScratchTooSmall);
        }
        let l2e = be_u64(l2_bytes, entry_off);
        if l2e == 0 {
            continue;
        }
        if let Some((base_virtual, new_virtual_size)) = boundary {
            let v = base_virtual + (j as u64) * cluster_size;
            if v < new_virtual_size {
                continue;
            }
        }
        if !opts.allow_shrink {
            return Err(ResizeError::ShrinkBelowAllocated);
        }
        let data_host = l2e & qcow2::L2_OFFSET_MASK;
        decrement(
            scratch,
            next_staging,
            refblock_slots,
            refblock_count,
            data_host,
        )?;
    }
    Ok(())
}

/// Look up an L2 table in the staged snapshot. Returns the
/// `cluster_size` bytes for L2 index `l1_index`, or
/// `ScratchTooSmall` if the guest did not stage it.
fn lookup_l2<'a>(
    opts: &'a Qcow2ResizeOpts<'_>,
    l1_index: u32,
    cluster_size: usize,
) -> Result<&'a [u8], ResizeError> {
    for (i, &idx) in opts.existing_l2_indices.iter().enumerate() {
        if idx == l1_index {
            let off = i * cluster_size;
            let end = off + cluster_size;
            if end > opts.existing_l2_bytes.len() {
                return Err(ResizeError::ScratchTooSmall);
            }
            return Ok(&opts.existing_l2_bytes[off..end]);
        }
    }
    Err(ResizeError::ScratchTooSmall)
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

/// Reject images carrying persistent dirty bitmaps. resize would
/// discard them (build_header drops unknown extensions + zeroes
/// autoclear), so refuse rather than silently lose data — matching
/// snapshot's posture.
fn validate_no_bitmaps(autoclear_features: u64) -> Result<(), ResizeError> {
    if autoclear_features & qcow2::bitmap::AUTOCLEAR_BITMAPS_BIT != 0 {
        return Err(ResizeError::BitmapsPresent);
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

/// Set the entry at index `local_idx` within a refcount block
/// to `value` (currently only 0 or 1 are used). Handles every
/// permitted refcount width.
///
/// **Phase 5 of PLAN-snapshot lifted the bit-level body** into
/// the new `snapshot` crate as `set_refcount_in_block`. This
/// thin wrapper keeps the resize-side signature
/// (`refcount_bits: u8`, [`ResizeError`] return type) so the
/// 14 existing call sites compile unchanged. The new home is
/// authoritative; do not edit the bit-level logic here.
fn set_refcount(
    block: &mut [u8],
    local_idx: u64,
    refcount_bits: u8,
    value: u64,
) -> Result<(), ResizeError> {
    // The new home returns a richer `SnapshotError`; resize
    // pre-lift returned `InvalidNewVirtualSize` for any failure
    // mode (only unsupported widths could fail in practice).
    // Collapse all snapshot errors to that same code so the 14
    // call sites observe identical behaviour.
    snapshot::qcow2::set_refcount_in_block(block, local_idx, refcount_bits as u32, value)
        .map_err(|_| ResizeError::InvalidNewVirtualSize)
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

    // ------------------------------------------------------------------
    // compute_grow_query unit tests (followup-01).
    // ------------------------------------------------------------------

    /// Build a `Qcow2ResizeGrowQuery` for a small synthetic qcow2
    /// at the given cluster size and current virtual size.  The
    /// refcount-table bytes are sized to match what `compute_layout`
    /// would produce for `current_virtual_size`, and densely-packed
    /// (one entry per existing refcount block).
    fn make_query<'a>(
        rt_bytes_buf: &'a mut [u8],
        cluster_size: u32,
        current_virtual_size: u64,
        new_virtual_size: u64,
    ) -> Qcow2ResizeGrowQuery<'a> {
        let cluster_bits = cluster_bits_from(cluster_size).unwrap();
        let layout = compute_layout(
            current_virtual_size,
            cluster_bits,
            16,
            false,
            Qcow2CreatePreallocation::Off,
        )
        .unwrap();

        // Populate the refcount-table buffer densely up to
        // `layout.refcount_block_count` entries.
        let cs = cluster_size as u64;
        let blocks_base = layout
            .refcount_table_offset
            .saturating_add(layout.refcount_table_clusters * cs);
        for i in 0..layout.refcount_block_count {
            let entry_off = (i as usize) * 8;
            if entry_off + 8 > rt_bytes_buf.len() {
                break;
            }
            write_be_u64(rt_bytes_buf, entry_off, blocks_base + i * cs);
        }

        let total_file_size = layout.total_file_size;
        Qcow2ResizeGrowQuery {
            cluster_size,
            refcount_bits: 16,
            extended_l2: false,
            current_virtual_size,
            new_virtual_size,
            current_file_size: total_file_size,
            current_l1_entries: layout.l1_entries,
            current_l1_table_offset: layout.l1_offset,
            current_refcount_table_offset: layout.refcount_table_offset,
            current_refcount_table_clusters: layout.refcount_table_clusters as u32,
            current_incompatible_features: 0,
            current_autoclear_features: 0,
            preallocation: Preallocation::Off,
            allow_shrink: false,
            existing_refcount_table_bytes: rt_bytes_buf,
        }
    }

    #[test]
    fn compute_grow_query_header_only_at_default_cluster() {
        // Tiny grow within the same L1 region — HeaderOnly path.
        let mut rt = [0u8; 8192];
        let q = make_query(&mut rt, 65536, 1 << 20, 4 << 20);
        let r = compute_grow_query(&q).unwrap();
        assert_eq!(r.action, Qcow2GrowAction::HeaderOnly);
        assert_eq!(r.required_blocks_len, 0);
    }

    #[test]
    fn validate_no_bitmaps_accepts_clear() {
        assert_eq!(validate_no_bitmaps(0), Ok(()));
        // Other autoclear bits (unknown to us) do not trip the gate;
        // only the bitmaps bit does.
        assert_eq!(validate_no_bitmaps(1 << 3), Ok(()));
    }

    #[test]
    fn validate_no_bitmaps_rejects_bitmaps_bit() {
        assert_eq!(
            validate_no_bitmaps(qcow2::bitmap::AUTOCLEAR_BITMAPS_BIT),
            Err(ResizeError::BitmapsPresent)
        );
        // Set alongside other bits, still rejected.
        assert_eq!(
            validate_no_bitmaps(qcow2::bitmap::AUTOCLEAR_BITMAPS_BIT | (1 << 5)),
            Err(ResizeError::BitmapsPresent)
        );
    }

    #[test]
    fn compute_grow_query_refuses_bitmaps() {
        // A grow that would otherwise be a plain HeaderOnly path, but
        // the autoclear bitmaps bit is set — must refuse rather than
        // silently drop the on-disk bitmaps.
        let mut rt = [0u8; 8192];
        let mut q = make_query(&mut rt, 65536, 1 << 20, 4 << 20);
        q.current_autoclear_features = qcow2::bitmap::AUTOCLEAR_BITMAPS_BIT;
        assert_eq!(
            compute_grow_query(&q).unwrap_err(),
            ResizeError::BitmapsPresent
        );
    }

    #[test]
    fn compute_grow_query_l1_grow_at_default_cluster() {
        // Grow from 1 MiB to 64 MiB at default 64K cluster.
        // current L1: 1 entry (covers one L2 of 64K * 8K = 512 MiB).
        // Actually with one L1 entry covering 512 MiB, 64 MiB stays
        // HeaderOnly.  Force L1Grow by jumping into a regime where
        // multiple L1 entries are needed.  At 4 KiB cluster, one L1
        // entry covers cluster_size * cluster_size/8 = 2 MiB; so
        // 1 MiB -> 64 MiB does grow the L1.
        let mut rt = [0u8; 8192];
        let q = make_query(&mut rt, 4096, 1 << 20, 64 << 20);
        let r = compute_grow_query(&q).unwrap();
        assert_eq!(r.action, Qcow2GrowAction::L1Grow);
        // Must demand at least one block (the one covering the new
        // L1 region, appended at EOF), plus the one covering the
        // old L1 region.  Distinct count is typically 1-2.
        assert!(
            r.required_blocks_len >= 1 && r.required_blocks_len <= 4,
            "L1Grow required_blocks_len out of bounds: {}",
            r.required_blocks_len
        );
    }

    #[test]
    fn compute_grow_query_handles_large_virtual_size() {
        // 500 GiB -> 1 TiB at default cluster.  Pre-followup this
        // would blow EXISTING_STATE_LIMIT; the targeted helper must
        // return a bounded block set regardless of image size.
        let mut rt = [0u8; 8192];
        let q = make_query(&mut rt, 65536, 500u64 << 30, 1024u64 << 30);
        let r = compute_grow_query(&q).unwrap();
        assert!(
            r.required_blocks_len <= QCOW2_MAX_REQUIRED_BLOCKS,
            "required_blocks_len ({}) exceeds MAX_REQUIRED_BLOCKS ({})",
            r.required_blocks_len,
            QCOW2_MAX_REQUIRED_BLOCKS,
        );
        // 1 TiB grow at 64K cluster needs L1+refcount table growth.
        assert!(matches!(
            r.action,
            Qcow2GrowAction::L1Grow | Qcow2GrowAction::L1AndRefcountGrow
        ));
    }

    #[test]
    fn compute_grow_query_rejects_zero_size() {
        let mut rt = [0u8; 8192];
        let mut q = make_query(&mut rt, 65536, 1 << 20, 4 << 20);
        q.new_virtual_size = 0;
        assert_eq!(
            compute_grow_query(&q).unwrap_err(),
            ResizeError::InvalidNewVirtualSize
        );
    }

    #[test]
    fn compute_grow_query_rejects_shrink_without_flag() {
        let mut rt = [0u8; 8192];
        let mut q = make_query(&mut rt, 65536, 4 << 20, 1 << 20);
        q.allow_shrink = false;
        assert_eq!(
            compute_grow_query(&q).unwrap_err(),
            ResizeError::ShrinkWithoutFlag
        );
    }

    #[test]
    fn compute_grow_query_rejects_shrink_with_flag() {
        // Helper is grow-only; shrink uses different staging.
        let mut rt = [0u8; 8192];
        let mut q = make_query(&mut rt, 65536, 4 << 20, 1 << 20);
        q.allow_shrink = true;
        assert_eq!(
            compute_grow_query(&q).unwrap_err(),
            ResizeError::UnsupportedShrink
        );
    }

    #[test]
    fn compute_grow_query_rejects_metadata_preallocation() {
        let mut rt = [0u8; 8192];
        let mut q = make_query(&mut rt, 65536, 1 << 20, 4 << 20);
        q.preallocation = Preallocation::Metadata;
        assert_eq!(
            compute_grow_query(&q).unwrap_err(),
            ResizeError::PreallocationUnsupported
        );
    }

    #[test]
    fn compute_grow_query_no_op_returns_empty_blocks() {
        let mut rt = [0u8; 8192];
        let q = make_query(&mut rt, 65536, 4 << 20, 4 << 20);
        let r = compute_grow_query(&q).unwrap();
        assert_eq!(r.action, Qcow2GrowAction::HeaderOnly);
        assert_eq!(r.required_blocks_len, 0);
    }

    #[test]
    fn required_blocks_dedupes() {
        let mut r = RequiredBlocks::new();
        r.add(7).unwrap();
        r.add(3).unwrap();
        r.add(7).unwrap();
        r.add(3).unwrap();
        r.add(11).unwrap();
        assert_eq!(r.len, 3);
        assert_eq!(&r.storage[..3], &[7, 3, 11]);
    }

    #[test]
    fn required_blocks_overflow_returns_scratch_too_small() {
        let mut r = RequiredBlocks::new();
        for i in 0..QCOW2_MAX_REQUIRED_BLOCKS as u64 {
            r.add(i).unwrap();
        }
        assert_eq!(r.add(99).unwrap_err(), ResizeError::ScratchTooSmall);
    }
}
