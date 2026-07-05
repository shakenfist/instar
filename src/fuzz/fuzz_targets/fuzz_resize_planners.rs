//! Coverage-guided fuzzing for the `crates/resize/` planners.
//!
//! Decodes a 32-byte structured header into a `(format_selector,
//! opts, synthetic existing-state slices)` tuple and dispatches to
//! one of the five `plan_resize_*` functions (`plan_resize_raw`,
//! `plan_resize_qcow2`, `plan_resize_vmdk`, `plan_resize_vhd`,
//! `plan_resize_vhdx`). On every successful return, asserts plan-
//! level invariants:
//!
//!   1. `patches().len() <= MAX_RESIZE_PATCHES` (128).
//!   2. Every patch's `byte_offset + len` doesn't overflow u64.
//!   3. Every `Write` / `ZeroFill` ends within `total_file_size`.
//!   4. `Append`s end at or below `total_file_size` (the final EOF).
//!   5. No two `Write` patches overlap.
//!
//! Errors (`InvalidNewVirtualSize`, `ShrinkWithoutFlag`,
//! `UnsupportedFormat`, `ScratchTooSmall`, etc.) are silently
//! ignored — libFuzzer's only oracle is panic.
//!
//! No re-parse round-trip: resize mutates an existing image, so a
//! faithful reparse would require reconstructing a complete input
//! image from fuzzer-synthetic existing-state bytes. Phase 11's
//! consistency suite (`TestResizeConsistency` +
//! `TestResizeBaselineMatrix`) cross-checks the planner+guest pair
//! against real images. This target's contract is narrower:
//! no panics, no integer overflows, no overlapping writes, no
//! patch counts above the bound.

#![no_main]
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;

use resize::{
    plan_resize_qcow2, plan_resize_raw, plan_resize_vhd, plan_resize_vhdx,
    plan_resize_vmdk, Preallocation, Qcow2ResizeOpts, RawResizeOpts, ResizePatch,
    ResizePlan, VhdResizeOpts, VhdSubformat, VhdxResizeOpts, VmdkResizeOpts,
    VmdkSubformat, MAX_RESIZE_PATCHES, QCOW2_MAX_RESIZE_SCRATCH,
};

const HEADER_BYTES: usize = 32;

thread_local! {
    /// Reusable scratch buffer for plan_resize_*. Sized to the
    /// largest per-format worst case (qcow2 = 32 MiB) so every
    /// dispatch can share the allocation.
    static SCRATCH: RefCell<Vec<u8>> =
        RefCell::new(vec![0u8; QCOW2_MAX_RESIZE_SCRATCH]);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_BYTES {
        return;
    }

    // ------------------------------------------------------------------
    // Decode the structured header.
    // ------------------------------------------------------------------
    let format_sel = data[0] % 5;
    let flags = data[1];
    let allow_shrink = flags & 0b0000_0001 != 0;
    let extended_l2 = flags & 0b0000_0010 != 0;
    let lazy_refcounts = flags & 0b0000_0100 != 0;
    let has_backing = flags & 0b0000_1000 != 0;
    let prealloc_sel = (flags >> 4) & 0b11;

    let refcount_bits = match data[2] % 8 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        5 => 32,
        6 => 64,
        _ => 0xff, // invalid — exercises the InvalidOption path
    };

    let vmdk_sub = match data[3] % 5 {
        1 => VmdkSubformat::StreamOptimized,
        2 => VmdkSubformat::MonolithicFlat,
        3 => VmdkSubformat::TwoGbMaxExtentSparse,
        4 => VmdkSubformat::TwoGbMaxExtentFlat,
        _ => VmdkSubformat::MonolithicSparse,
    };
    let vhd_sub = if data[3] & 0b0001_0000 != 0 {
        VhdSubformat::Fixed
    } else {
        VhdSubformat::Dynamic
    };

    let unit_size = u32::from_le_bytes(data[4..8].try_into().unwrap());

    // Clamp the three u64 size fields to a realistic envelope.
    //
    // The host VMM constructs these from `stat()` on a real file
    // (`current_file_size`) and from parsed header bytes
    // (`current_virtual_size` / `new_virtual_size`). Real images
    // top out around 100 TiB for the largest deployments.
    //
    // Per-format clamp because the planners have different
    // robustness profiles:
    //
    // * **qcow2** is robust against large sizes after followup-01
    //   (the targeted refcount-block pre-pass bounded the staging
    //   regardless of image size).  Use 48 bits = 256 TiB to
    //   exercise the new code path at cloud-disk scale.
    // * **vmdk / vhd / vhdx** still have the phase-12 planner-
    //   input-validation gap (returning Ok with corrupt
    //   total_file_size when the host passes mutually
    //   inconsistent values).  Keep the 40-bit / 1 TiB clamp
    //   until those planners are hardened (master-plan Future
    //   work).
    //
    // The qcow2 branch is selected by `format_sel == 1`.
    const SIZE_MASK_TIGHT: u64 = (1 << 40) - 1;
    const SIZE_MASK_QCOW2: u64 = (1 << 48) - 1;
    let size_mask = if format_sel == 1 {
        SIZE_MASK_QCOW2
    } else {
        SIZE_MASK_TIGHT
    };
    let current_virtual_size =
        u64::from_le_bytes(data[8..16].try_into().unwrap()) & size_mask;
    let new_virtual_size =
        u64::from_le_bytes(data[16..24].try_into().unwrap()) & size_mask;
    // current_file_size floored at 8 MiB: the hardcoded VHDX
    // metadata/BAT offsets the harness passes (2 / 3 MiB) must
    // land within the file. The floor reflects what a real VHDX
    // actually looks like — even a 1 MiB image has its 1 MiB
    // metadata region past the headers + log.
    let current_file_size =
        (u64::from_le_bytes(data[24..32].try_into().unwrap()) & size_mask)
            .max(8 * 1024 * 1024);

    let preallocation = match prealloc_sel {
        1 => Preallocation::Metadata,
        2 => Preallocation::Falloc,
        3 => Preallocation::Full,
        _ => Preallocation::Off,
    };

    // ------------------------------------------------------------------
    // Carve the post-header pool into per-format slices. The pool
    // shrinks gracefully when data is short; planners are
    // responsible for returning errors rather than panicking on
    // empty or undersized inputs.
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

    // Indices arrays: synthesised ascending sequences. The planner
    // is documented to return ScratchTooSmall if it references an
    // index whose corresponding block isn't staged, so providing a
    // tiny ascending sequence is sufficient — we're not trying to
    // make the planner *succeed*, only to make it explore reachable
    // states without panicking.
    let small_indices_u32: [u32; 4] = [0, 1, 2, 3];
    let small_indices_u64: [u64; 4] = [0, 1, 2, 3];

    // ------------------------------------------------------------------
    // Construct optional backing-file reference.
    // ------------------------------------------------------------------
    let backing_path: &[u8] = if has_backing {
        // Drop into the pool past the existing-state slices to find
        // some bytes; small fixed window is fine because backing
        // paths are short.
        slice(60 * 1024, 256)
    } else {
        &[]
    };
    let backing_file = if has_backing { Some(backing_path) } else { None };

    // ------------------------------------------------------------------
    // Dispatch on format_sel.
    // ------------------------------------------------------------------
    SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();

        match format_sel {
            0 => {
                // Raw: trivial, no slices needed.
                let opts = RawResizeOpts {
                    current_virtual_size,
                    new_virtual_size,
                    preallocation,
                };
                if let Ok(plan) = plan_resize_raw(&opts) {
                    assert_invariants(&plan, "raw");
                }
            }
            1 => {
                // QCOW2: four byte slices + two indices slices.
                let opts = Qcow2ResizeOpts {
                    current_virtual_size,
                    new_virtual_size,
                    cluster_size: unit_size,
                    refcount_bits,
                    extended_l2,
                    preallocation,
                    allow_shrink,
                    existing_l1_bytes: slice(0, 4096),
                    existing_refcount_table_bytes: slice(4096, 4096),
                    existing_refcount_block_bytes: slice(8192, 32 * 1024),
                    existing_refcount_block_indices: &small_indices_u64,
                    current_file_size,
                    current_l1_entries: u32::from_le_bytes(
                        data[24..28].try_into().unwrap(),
                    ),
                    current_l1_table_offset: current_file_size
                        .wrapping_sub(8192),
                    current_refcount_table_offset: current_file_size
                        .wrapping_sub(4096),
                    current_refcount_table_clusters: 1,
                    current_incompatible_features: u64::from_le_bytes(
                        data[16..24].try_into().unwrap(),
                    ),
                    // Drive the qcow2 bitmaps autoclear bit (bit 0) from a
                    // free flag bit so the fuzzer exercises resize's
                    // refuse-bitmap-bearing-images gate.
                    current_autoclear_features: ((flags >> 6) & 1) as u64,
                    backing_file,
                    backing_format: None,
                    lazy_refcounts,
                    existing_l2_bytes: slice(40 * 1024, 16 * 1024),
                    existing_l2_indices: &small_indices_u32,
                };
                if let Ok(plan) = plan_resize_qcow2(&opts, &mut scratch) {
                    assert_invariants(&plan, "qcow2");
                }
            }
            2 => {
                // VMDK: three byte slices.
                let opts = VmdkResizeOpts {
                    current_virtual_size,
                    new_virtual_size,
                    grain_size: unit_size,
                    subformat: vmdk_sub,
                    allow_shrink,
                    preallocation,
                    existing_header: slice(0, 512),
                    existing_descriptor: slice(512, 10 * 1024),
                    existing_gd: slice(11 * 1024, 16 * 1024),
                    current_num_gd_entries: u32::from_le_bytes(
                        data[4..8].try_into().unwrap(),
                    )
                    .min(4096),
                    current_gd_sectors: 1,
                    current_file_size,
                };
                if let Ok(plan) = plan_resize_vmdk(&opts, &mut scratch) {
                    assert_invariants(&plan, "vmdk");
                }
            }
            3 => {
                // VHD: three byte slices + a few numeric fields.
                let opts = VhdResizeOpts {
                    current_virtual_size,
                    new_virtual_size,
                    block_size: unit_size,
                    subformat: vhd_sub,
                    allow_shrink,
                    preallocation,
                    existing_footer: slice(0, 512),
                    existing_dynamic_header: slice(512, 1024),
                    existing_bat: slice(1536, 32 * 1024),
                    current_file_size,
                    disk_type: data[3] as u32 % 5,
                    current_table_offset: 1024,
                    current_max_table_entries: u32::from_le_bytes(
                        data[4..8].try_into().unwrap(),
                    )
                    .min(1 << 20),
                };
                if let Ok(plan) = plan_resize_vhd(&opts, &mut scratch) {
                    assert_invariants(&plan, "vhd");
                }
            }
            _ => {
                // VHDX: header + region table + BAT.
                let opts = VhdxResizeOpts {
                    current_virtual_size,
                    new_virtual_size,
                    block_size: unit_size,
                    preallocation,
                    allow_shrink,
                    existing_active_header: slice(0, 4096),
                    current_active_header_offset: 0x10000,
                    current_sequence_number: u64::from_le_bytes(
                        data[8..16].try_into().unwrap(),
                    ),
                    existing_region_table: slice(4096, 64 * 1024),
                    existing_bat: slice(64 * 1024 + 4096, 32 * 1024),
                    current_bat_offset: 3 * 1024 * 1024,
                    current_bat_length: u32::from_le_bytes(
                        data[4..8].try_into().unwrap(),
                    )
                    .min(32 * 1024),
                    current_total_bat_entries: u32::from_le_bytes(
                        data[4..8].try_into().unwrap(),
                    )
                    .min(4096),
                    current_metadata_offset: 2 * 1024 * 1024,
                    current_metadata_length: 1024 * 1024,
                    logical_sector_size: 512,
                    physical_sector_size: 4096,
                    has_parent: flags & 0b1000_0000 != 0,
                    current_file_size,
                };
                if let Ok(plan) = plan_resize_vhdx(&opts, &mut scratch) {
                    assert_invariants(&plan, "vhdx");
                }
            }
        }
    });
});

/// Plan-level invariants. Panicking on violation triggers libFuzzer
/// to record the input as a crash.
fn assert_invariants(plan: &ResizePlan<'_>, label: &str) {
    let patches = plan.patches();

    // Invariant 1: patch count bound.
    assert!(
        patches.len() <= MAX_RESIZE_PATCHES,
        "{}: patch count {} > MAX_RESIZE_PATCHES ({})",
        label,
        patches.len(),
        MAX_RESIZE_PATCHES,
    );

    let total = plan.total_file_size;

    // Invariants 2-4: per-patch bounds.
    for (i, p) in patches.iter().enumerate() {
        let off = p.byte_offset();
        let len = p.len();
        let end = off.checked_add(len).unwrap_or_else(|| {
            panic!("{}: patch {} offset {} + len {} overflows u64", label, i, off, len)
        });
        match p {
            ResizePatch::Write { .. } | ResizePatch::ZeroFill { .. } => {
                assert!(
                    end <= total,
                    "{}: patch {} ({}..{}) exceeds total_file_size ({})",
                    label, i, off, end, total,
                );
            }
            ResizePatch::Append { .. } => {
                // Appends define the file's growing EOF; after the
                // plan finishes the final EOF is total_file_size,
                // so any individual append's end must still be
                // within that bound.
                assert!(
                    end <= total,
                    "{}: append {} ({}..{}) exceeds total_file_size ({})",
                    label, i, off, end, total,
                );
            }
        }
    }

    // Invariant 5: no two Write patches overlap (Appends and
    // ZeroFills can legitimately co-exist at the same offset in
    // some planner expressions; Writes are unambiguously a bug).
    let mut writes: Vec<(u64, u64)> = patches
        .iter()
        .filter_map(|p| match p {
            ResizePatch::Write { byte_offset, bytes } => {
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
