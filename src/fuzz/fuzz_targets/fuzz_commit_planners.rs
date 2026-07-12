//! Coverage-guided fuzzing for the `crates/commit/` planners.
//!
//! Decodes a 32-byte structured header into a `(format_selector,
//! opts, synthetic existing-state slices)` tuple and dispatches
//! to one of the two `plan_commit_*` functions
//! (`plan_commit_qcow2`, `plan_commit_vmdk`). On every successful
//! return, asserts context invariants:
//!
//! For [`Qcow2CommitContext`] (slimmed to overlay geometry by
//! phase 4 of `PLAN-qcow2-write-infrastructure` — the backing
//! refblock staging moved to `crates/qcow2-write`, whose planner
//! has its own fuzz/simulation surface):
//!
//!   1. `overlay_entries_per_refblock ==
//!      overlay_cluster_size * 8 / overlay_refcount_bits`.
//!   2. `overlay_cluster_count` covers the overlay's virtual
//!      size (`(count - 1) * cs < vsize <= count * cs`, for
//!      nonzero sizes).
//!
//! For [`VmdkCommitContext`]:
//!
//!   3. `backing_gt_dirty.len() ==
//!      (backing_allocated_gt_count + 7) / 8`.
//!   4. `backing_grain_tables.len() == backing_allocated_gt_count *
//!      backing_num_gtes_per_gt * 4`.
//!   5. `backing_gd_dirty.len() == 1`.
//!   6. `overlay_grain_size_sectors > 0` and
//!      `backing_grain_size_sectors > 0`.
//!
//! Errors (`CommitError::*`) are silently ignored — libFuzzer's
//! only oracle is panic.

#![no_main]
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;

use commit::{
    plan_commit_qcow2, plan_commit_vmdk, Qcow2CommitContext, Qcow2CommitOpts,
    VmdkCommitContext, VmdkCommitOpts,
};

const HEADER_BYTES: usize = 32;

/// Scratch buffer size for the vmdk planner (backing GD + GT
/// copies plus dirty maps; the qcow2 planner has been pure
/// geometry since phase 4 and takes no scratch). 8 MiB is well
/// over the v1 ceiling.
const SCRATCH_BYTES: usize = 8 * 1024 * 1024;

thread_local! {
    /// Reusable scratch buffer for `plan_commit_*`. The shared
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

    let backing_refblock_count = (data[2] as u32) & 0b1111;
    let overlay_allocated_gt_count = (data[3] as u32) & 0b1111;
    let backing_allocated_gt_count = ((data[3] >> 4) as u32) & 0b1111;

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
    // = 256 TiB). `overlay_file_size` and `backing_file_size`
    // are floored at 8 MiB so the synthesised metadata offsets
    // land within a plausible file (mirroring the resize and
    // rebase harnesses).
    const SIZE_MASK: u64 = (1 << 48) - 1;
    let overlay_file_size =
        (u64::from_le_bytes(data[8..16].try_into().unwrap()) & SIZE_MASK)
            .max(8 * 1024 * 1024);
    let backing_file_size =
        (u64::from_le_bytes(data[16..24].try_into().unwrap()) & SIZE_MASK)
            .max(8 * 1024 * 1024);
    let virtual_size_word =
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

    let small_gt_host_sectors: [u64; 16] = [
        0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700, 0x800,
        0x900, 0xa00, 0xb00, 0xc00, 0xd00, 0xe00, 0xf00, 0x1000,
    ];
    let overlay_gt_host_sectors = &small_gt_host_sectors
        [..(overlay_allocated_gt_count as usize).min(16)];
    let backing_gt_host_sectors = &small_gt_host_sectors
        [..(backing_allocated_gt_count as usize).min(16)];

    // ------------------------------------------------------------------
    // Dispatch on format_sel.
    // ------------------------------------------------------------------
    SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();

        match format_sel {
            0 => {
                // qcow2.
                let opts = Qcow2CommitOpts {
                    overlay_header: slice(0, 4096),
                    overlay_file_size,
                    backing_header: slice(4096, 4096),
                    backing_file_size,
                };
                if let Ok(ctx) = plan_commit_qcow2(&opts) {
                    assert_qcow2_context(&ctx);
                }
            }
            _ => {
                // vmdk.
                let opts = VmdkCommitOpts {
                    overlay_header: slice(0, 512),
                    overlay_descriptor: slice(512, 10 * 1024),
                    overlay_grain_size_sectors: (cluster_size / 512).max(1),
                    overlay_num_gtes_per_gt: num_gtes_per_gt,
                    overlay_num_gd_entries:
                        backing_refblock_count.max(1),
                    overlay_gd_offset_sectors: 1,
                    overlay_grain_directory: slice(11 * 1024, 4 * 1024),
                    overlay_grain_tables: slice(16 * 1024, 32 * 1024),
                    overlay_allocated_gt_host_sectors: overlay_gt_host_sectors,
                    overlay_allocated_gt_count,
                    overlay_virtual_size: virtual_size_word,
                    overlay_file_size,
                    backing_header: slice(48 * 1024, 512),
                    backing_descriptor: slice(49 * 1024, 10 * 1024),
                    backing_grain_size_sectors: (cluster_size / 512).max(1),
                    backing_num_gtes_per_gt: num_gtes_per_gt,
                    backing_num_gd_entries:
                        backing_refblock_count.max(1),
                    backing_gd_offset_sectors: 1,
                    backing_grain_directory: slice(60 * 1024, 4 * 1024),
                    backing_grain_tables: slice(64 * 1024, 32 * 1024),
                    backing_allocated_gt_host_sectors: backing_gt_host_sectors,
                    backing_allocated_gt_count,
                    backing_virtual_size: virtual_size_word,
                    backing_file_size,
                };
                if let Ok(ctx) = plan_commit_vmdk(&opts, &mut scratch) {
                    assert_vmdk_context(&ctx);
                }
            }
        }
    });
});

/// qcow2 commit context invariants.
fn assert_qcow2_context(ctx: &Qcow2CommitContext) {
    if ctx.overlay_refcount_bits > 0 && ctx.overlay_cluster_size > 0 {
        let expected_epr = (ctx.overlay_cluster_size as u64) * 8
            / (ctx.overlay_refcount_bits as u64);
        assert_eq!(
            ctx.overlay_entries_per_refblock,
            expected_epr,
            "qcow2 commit: overlay_entries_per_refblock {} != \
             overlay_cluster_size {} * 8 / overlay_refcount_bits {} = {}",
            ctx.overlay_entries_per_refblock,
            ctx.overlay_cluster_size,
            ctx.overlay_refcount_bits,
            expected_epr,
        );
    }

    if ctx.overlay_cluster_size > 0 && ctx.overlay_cluster_count > 0 {
        let cs = ctx.overlay_cluster_size as u64;
        let covered = ctx.overlay_cluster_count * cs;
        let prev = (ctx.overlay_cluster_count - 1) * cs;
        assert!(
            prev < covered,
            "qcow2 commit: overlay_cluster_count {} overflows at \
             cluster size {}",
            ctx.overlay_cluster_count,
            cs,
        );
    }
}

/// vmdk commit context invariants.
fn assert_vmdk_context(ctx: &VmdkCommitContext<'_>) {
    let expected_dirty_len =
        ((ctx.backing_allocated_gt_count as usize) + 7) / 8;
    assert_eq!(
        ctx.backing_gt_dirty.len(),
        expected_dirty_len,
        "vmdk commit: backing_gt_dirty.len() {} != \
         (backing_allocated_gt_count {} + 7) / 8 = {}",
        ctx.backing_gt_dirty.len(),
        ctx.backing_allocated_gt_count,
        expected_dirty_len,
    );

    let expected_tables_len = (ctx.backing_allocated_gt_count as usize)
        * (ctx.backing_num_gtes_per_gt as usize)
        * 4;
    assert_eq!(
        ctx.backing_grain_tables.len(),
        expected_tables_len,
        "vmdk commit: backing_grain_tables.len() {} != \
         backing_allocated_gt_count {} * backing_num_gtes_per_gt {} * 4 = {}",
        ctx.backing_grain_tables.len(),
        ctx.backing_allocated_gt_count,
        ctx.backing_num_gtes_per_gt,
        expected_tables_len,
    );

    assert_eq!(
        ctx.backing_gd_dirty.len(),
        1,
        "vmdk commit: backing_gd_dirty.len() {} != 1 (single-byte flag)",
        ctx.backing_gd_dirty.len(),
    );

    assert!(
        ctx.overlay_grain_size_sectors > 0,
        "vmdk commit: overlay_grain_size_sectors must be > 0",
    );
    assert!(
        ctx.backing_grain_size_sectors > 0,
        "vmdk commit: backing_grain_size_sectors must be > 0",
    );
}
