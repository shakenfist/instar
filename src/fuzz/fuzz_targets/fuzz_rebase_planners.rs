//! Coverage-guided fuzzing for the `crates/rebase/` planners.
//!
//! Decodes a 32-byte structured header into a `(format_selector,
//! mode_selector, opts, synthetic existing-state slices)` tuple
//! and dispatches to one of the two `plan_rebase_*` functions
//! (`plan_rebase_qcow2`, `plan_rebase_vmdk`). On every successful
//! return, asserts plan-level invariants:
//!
//!   1. `RebasePlan::patches().len() <= MAX_REBASE_PATCHES` (16).
//!   2. Every patch's `byte_offset + len` doesn't overflow u64.
//!   3. Every `Write` patch's range lies within
//!      `plan.total_file_size`.
//!   4. `Append`s end at or below `plan.total_file_size`.
//!   5. No two `Write` patches overlap.
//!
//! For safe-mode `RebaseQcow2SafeContext`:
//!
//!   6. `dirty.len() == (refblock_count + 7) / 8`.
//!   7. `refblocks.len() == refblock_count * cluster_size`.
//!   8. `entries_per_refblock == cluster_size * 8 / refcount_bits`.
//!
//! For safe-mode `RebaseVmdkSafeContext`:
//!
//!   9. `gt_dirty.len() == (allocated_gt_count + 7) / 8`.
//!  10. `grain_tables.len() == allocated_gt_count *
//!      num_gtes_per_gt * 4`.
//!
//! Errors (`RebaseError::*`) are silently ignored — libFuzzer's
//! only oracle is panic.

#![no_main]
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;

use rebase::{
    plan_rebase_qcow2, plan_rebase_vmdk, MAX_REBASE_PATCHES, Qcow2RebaseOpts,
    Qcow2RebaseOutput, RebaseMode, RebasePatch, RebasePlan, RebaseQcow2SafeContext,
    RebaseVmdkSafeContext, VmdkRebaseOpts, VmdkRebaseOutput,
};

const HEADER_BYTES: usize = 32;

/// Scratch buffer size. Sized generously to cover both formats'
/// worst case in v1: qcow2 stages up to
/// `MAX_REBASE_PATCHES * cluster_size` for relocations plus the
/// safe-mode refcount-block staging (capped at ~32 KiB per block
/// times a handful of blocks); vmdk safe-mode stages GT bytes
/// for every allocated GT plus the dirty bitmap. 8 MiB is
/// well over the v1 ceiling and keeps the harness's allocator
/// quiet.
const SCRATCH_BYTES: usize = 8 * 1024 * 1024;

thread_local! {
    /// Reusable scratch buffer for `plan_rebase_*`. The shared
    /// buffer is reset between invocations via `borrow_mut`.
    static SCRATCH: RefCell<Vec<u8>> = RefCell::new(vec![0u8; SCRATCH_BYTES]);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_BYTES {
        return;
    }

    // ------------------------------------------------------------------
    // Decode the structured header.
    // ------------------------------------------------------------------
    let format_sel = data[0] & 0b1;
    let mode_sel = (data[0] >> 1) & 0b1;
    let mode = if mode_sel == 0 {
        RebaseMode::Unsafe
    } else {
        RebaseMode::Safe
    };
    let flags = data[1];
    let detach = (flags & 0b0000_0001) != 0;

    let refblock_count = (data[2] as u32) & 0b1111;
    let allocated_gt_count = (data[3] as u32) & 0b1111;

    let cluster_size = match data[4] & 0b111 {
        0 => 512u32,
        1 => 1024,
        2 => 4096,
        3 => 16 * 1024,
        4 => 65536,
        5 => 128 * 1024,
        6 => 1024 * 1024,
        _ => 2 * 1024 * 1024,
    };
    let num_gtes_per_gt = match data[5] & 0b11 {
        0 => 128u32,
        1 => 256,
        2 => 512,
        _ => 1024,
    };

    // Clamp the u64 size fields to a realistic envelope (48 bits
    // = 256 TiB). The same pattern as `fuzz_resize_planners`.
    //
    // `overlay_file_size` is floored at 8 MiB so the synthesised
    // `overlay_descriptor_offset` (`file_size - 64 KiB`) lands at
    // a plausible position — the planner unconditionally emits a
    // descriptor patch, so passing a file_size smaller than the
    // descriptor slot is nonsensical and would only exercise the
    // arithmetic-saturation path. The resize harness floors
    // `current_file_size` at 8 MiB for the equivalent reason.
    const SIZE_MASK: u64 = (1 << 48) - 1;
    let overlay_file_size =
        (u64::from_le_bytes(data[8..16].try_into().unwrap()) & SIZE_MASK)
            .max(8 * 1024 * 1024);
    let new_backing_virtual_size =
        u64::from_le_bytes(data[16..24].try_into().unwrap()) & SIZE_MASK;
    let overlay_virtual_size =
        u64::from_le_bytes(data[24..32].try_into().unwrap()) & SIZE_MASK;

    // ------------------------------------------------------------------
    // Carve the post-header pool into per-format slices.
    // ------------------------------------------------------------------
    let pool = &data[HEADER_BYTES..];

    let slice = |start: usize, max_len: usize| -> &[u8] {
        if start >= pool.len() {
            &[]
        } else {
            let end = (start + max_len).min(pool.len());
            &pool[start..end]
        }
    };

    // Synthesised ascending sequences for the host-offset
    // arrays. The planner returns ScratchTooSmall or
    // HeaderMismatch if these don't line up with the staged
    // refcount blocks; either outcome is silently ignored.
    let small_refblock_host_offsets: [u64; 16] = [
        0x1_0000, 0x2_0000, 0x3_0000, 0x4_0000,
        0x5_0000, 0x6_0000, 0x7_0000, 0x8_0000,
        0x9_0000, 0xa_0000, 0xb_0000, 0xc_0000,
        0xd_0000, 0xe_0000, 0xf_0000, 0x10_0000,
    ];
    let refblock_host_offsets =
        &small_refblock_host_offsets[..(refblock_count as usize).min(16)];

    let small_gt_host_sectors: [u64; 16] = [
        0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700, 0x800,
        0x900, 0xa00, 0xb00, 0xc00, 0xd00, 0xe00, 0xf00, 0x1000,
    ];
    let gt_host_sectors =
        &small_gt_host_sectors[..(allocated_gt_count as usize).min(16)];

    // New-backing path string carved from the pool tail. The
    // planner rejects oversized paths with BackingPathTooLong.
    let new_backing_path: &[u8] = if detach {
        &[]
    } else {
        slice(60 * 1024, 256)
    };

    // ------------------------------------------------------------------
    // Dispatch on format_sel.
    // ------------------------------------------------------------------
    SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();

        match format_sel {
            0 => {
                // qcow2.
                let opts = Qcow2RebaseOpts {
                    mode,
                    overlay_header: slice(0, 4096),
                    overlay_file_size,
                    refcount_table: slice(4096, 4096),
                    refblock_host_offsets,
                    refcount_blocks: slice(8192, 32 * 1024),
                    refblock_count,
                    new_backing_virtual_size,
                    new_backing_path,
                    detach,
                };
                if let Ok(output) = plan_rebase_qcow2(&opts, &mut scratch) {
                    match output {
                        Qcow2RebaseOutput::Unsafe { plan } => {
                            assert_plan_invariants(&plan, "qcow2 unsafe");
                        }
                        Qcow2RebaseOutput::Safe {
                            context,
                            deferred_metadata,
                        } => {
                            assert_plan_invariants(
                                &deferred_metadata,
                                "qcow2 safe (deferred)",
                            );
                            assert_qcow2_safe_context(&context);
                        }
                    }
                }
            }
            _ => {
                // vmdk.
                let opts = VmdkRebaseOpts {
                    mode,
                    overlay_virtual_size,
                    overlay_descriptor: slice(0, 10 * 1024),
                    overlay_descriptor_size:
                        u32::from_le_bytes(data[4..8].try_into().unwrap())
                            .min(64 * 1024),
                    overlay_descriptor_offset:
                        overlay_file_size.saturating_sub(64 * 1024),
                    new_backing_virtual_size,
                    new_backing_path,
                    new_parent_cid:
                        u32::from_le_bytes(data[4..8].try_into().unwrap()),
                    detach,
                    overlay_grain_size_sectors: (cluster_size / 512).max(1),
                    num_gtes_per_gt,
                    num_gd_entries: refblock_count.max(1),
                    gd_offset_sectors: 1,
                    overlay_file_size,
                    overlay_grain_directory: slice(11 * 1024, 4 * 1024),
                    overlay_grain_tables: slice(16 * 1024, 32 * 1024),
                    allocated_gt_host_sectors: gt_host_sectors,
                    allocated_gt_count,
                };
                if let Ok(output) = plan_rebase_vmdk(&opts, &mut scratch) {
                    match output {
                        VmdkRebaseOutput::Unsafe { plan } => {
                            assert_plan_invariants(&plan, "vmdk unsafe");
                        }
                        VmdkRebaseOutput::Safe {
                            context,
                            deferred_metadata,
                        } => {
                            assert_plan_invariants(
                                &deferred_metadata,
                                "vmdk safe (deferred)",
                            );
                            assert_vmdk_safe_context(&context);
                        }
                    }
                }
            }
        }
    });
});

/// Plan-level invariants. Panicking on violation triggers
/// libFuzzer to record the input as a crash.
fn assert_plan_invariants(plan: &RebasePlan<'_>, label: &str) {
    let patches = plan.patches();

    // Invariant 1: patch count bound.
    assert!(
        patches.len() <= MAX_REBASE_PATCHES,
        "{}: patch count {} > MAX_REBASE_PATCHES ({})",
        label,
        patches.len(),
        MAX_REBASE_PATCHES,
    );

    let total = plan.total_file_size;

    // Invariants 2-4: per-patch bounds.
    for (i, p) in patches.iter().enumerate() {
        let off = p.byte_offset();
        let len = p.len() as u64;
        let end = off.checked_add(len).unwrap_or_else(|| {
            panic!(
                "{}: patch {} offset {} + len {} overflows u64",
                label, i, off, len
            )
        });
        match p {
            RebasePatch::Write { .. } => {
                assert!(
                    end <= total,
                    "{}: Write patch {} ({}..{}) exceeds \
                     total_file_size ({})",
                    label, i, off, end, total,
                );
            }
            RebasePatch::Append { .. } => {
                assert!(
                    end <= total,
                    "{}: Append patch {} ({}..{}) exceeds \
                     total_file_size ({})",
                    label, i, off, end, total,
                );
            }
        }
    }

    // Invariant 5: no two Write patches overlap.
    let mut writes: Vec<(u64, u64)> = patches
        .iter()
        .filter_map(|p| match p {
            RebasePatch::Write { byte_offset, bytes } => {
                Some((*byte_offset, *byte_offset + bytes.len() as u64))
            }
            _ => None,
        })
        .collect();
    writes.sort_by_key(|(off, _)| *off);
    for w in writes.windows(2) {
        let (off_a, end_a) = w[0];
        let (off_b, end_b) = w[1];
        assert!(
            end_a <= off_b,
            "{}: overlapping Write patches: ({}..{}) and ({}..{})",
            label, off_a, end_a, off_b, end_b,
        );
    }
}

/// Safe-mode qcow2 context invariants.
fn assert_qcow2_safe_context(ctx: &RebaseQcow2SafeContext<'_>) {
    let expected_dirty_len = ((ctx.refblock_count as usize) + 7) / 8;
    assert_eq!(
        ctx.dirty.len(),
        expected_dirty_len,
        "qcow2 safe: dirty.len() {} != (refblock_count {} + 7) / 8 = {}",
        ctx.dirty.len(),
        ctx.refblock_count,
        expected_dirty_len,
    );

    let expected_refblocks_len =
        (ctx.refblock_count as usize) * (ctx.overlay_cluster_size as usize);
    assert_eq!(
        ctx.refblocks.len(),
        expected_refblocks_len,
        "qcow2 safe: refblocks.len() {} != refblock_count {} * \
         cluster_size {} = {}",
        ctx.refblocks.len(),
        ctx.refblock_count,
        ctx.overlay_cluster_size,
        expected_refblocks_len,
    );

    if ctx.refcount_bits > 0 {
        let expected_epr =
            (ctx.overlay_cluster_size as u64) * 8 / (ctx.refcount_bits as u64);
        assert_eq!(
            ctx.entries_per_refblock,
            expected_epr,
            "qcow2 safe: entries_per_refblock {} != cluster_size {} * \
             8 / refcount_bits {} = {}",
            ctx.entries_per_refblock,
            ctx.overlay_cluster_size,
            ctx.refcount_bits,
            expected_epr,
        );
    }
}

/// Safe-mode vmdk context invariants.
fn assert_vmdk_safe_context(ctx: &RebaseVmdkSafeContext<'_>) {
    let expected_dirty_len = ((ctx.allocated_gt_count as usize) + 7) / 8;
    assert_eq!(
        ctx.gt_dirty.len(),
        expected_dirty_len,
        "vmdk safe: gt_dirty.len() {} != (allocated_gt_count {} + 7) / 8 = {}",
        ctx.gt_dirty.len(),
        ctx.allocated_gt_count,
        expected_dirty_len,
    );

    let expected_tables_len =
        (ctx.allocated_gt_count as usize) * (ctx.num_gtes_per_gt as usize) * 4;
    assert_eq!(
        ctx.grain_tables.len(),
        expected_tables_len,
        "vmdk safe: grain_tables.len() {} != allocated_gt_count {} * \
         num_gtes_per_gt {} * 4 = {}",
        ctx.grain_tables.len(),
        ctx.allocated_gt_count,
        ctx.num_gtes_per_gt,
        expected_tables_len,
    );
}
