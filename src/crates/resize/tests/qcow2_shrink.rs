//! End-to-end integration tests for the qcow2 shrink planner.
//!
//! Each test builds a starting qcow2 image via crates/create,
//! optionally writes a known cluster (by directly manipulating
//! L2 / refcount bytes — phase 3 ships before the write
//! operation, so we forge allocations by hand for the tests
//! that need them), calls `plan_resize_qcow2` with
//! `allow_shrink: true`, applies the patch list against the
//! starting bytes, then re-parses with `qcow2::QcowHeader::parse`
//! and asserts the expected post-resize geometry.

use create::{plan_qcow2, MetadataPlan, Qcow2CreateOpts};
use qcow2::QcowHeader;
use resize::{
    plan_resize_qcow2, Preallocation, Qcow2ResizeOpts, ResizeAction, ResizeError, ResizePatch,
    ResizePlan, QCOW2_MAX_RESIZE_SCRATCH,
};
use shared::{be_u64, write_be_u64};

// ---------------------------------------------------------------------------
// Helpers (mirror tests/qcow2_grow.rs)
// ---------------------------------------------------------------------------

fn materialise_create(plan: &MetadataPlan<'_>) -> Vec<u8> {
    let mut buf = vec![0u8; plan.minimum_file_size as usize];
    for w in plan.writes() {
        let start = w.byte_offset as usize;
        let end = start + w.bytes.len();
        buf[start..end].copy_from_slice(w.bytes);
    }
    buf
}

fn apply_resize(file: &mut Vec<u8>, plan: &ResizePlan<'_>) {
    if file.len() < plan.total_file_size as usize {
        file.resize(plan.total_file_size as usize, 0);
    }
    for patch in plan.patches() {
        match patch {
            ResizePatch::Write { byte_offset, bytes }
            | ResizePatch::Append { byte_offset, bytes } => {
                let start = *byte_offset as usize;
                let end = start + bytes.len();
                if end > file.len() {
                    file.resize(end, 0);
                }
                file[start..end].copy_from_slice(bytes);
            }
            ResizePatch::ZeroFill { byte_offset, len } => {
                let start = *byte_offset as usize;
                let end = start + *len as usize;
                if end > file.len() {
                    file.resize(end, 0);
                }
                file[start..end].fill(0);
            }
        }
    }
    if file.len() != plan.total_file_size as usize {
        file.resize(plan.total_file_size as usize, 0);
    }
}

fn build_starting_image(virtual_size: u64, cluster_size: u32) -> (Vec<u8>, QcowHeader) {
    let opts = Qcow2CreateOpts {
        virtual_size,
        cluster_size,
        refcount_bits: 16,
        extended_l2: false,
        lazy_refcounts: false,
        compat_v3: true,
        backing: None,
        preallocation: qcow2::create::Preallocation::Off,
    };
    let mut scratch = vec![0u8; create::QCOW2_MAX_METADATA_SCRATCH];
    let plan = plan_qcow2(&opts, &mut scratch).expect("create plan");
    let bytes = materialise_create(&plan);
    let parsed = QcowHeader::parse(&bytes).expect("parse starting");
    (bytes, parsed)
}

/// Allocate one data cluster at the end of `bytes` and point
/// L2[l2_index] within L1[l1_index]'s L2 table at it. If
/// L1[l1_index] is currently zero, also allocate an L2 cluster
/// and point L1 at it. Increment refcount entries for any
/// newly-allocated clusters. Returns the host offset of the
/// allocated data cluster.
///
/// This is a deliberately ugly test-only forging helper — phase 3
/// ships before the write operation, so we build "allocated"
/// images by hand to exercise the shrink planner's discard
/// path.
fn forge_allocated_cluster(
    bytes: &mut Vec<u8>,
    header: &QcowHeader,
    l1_index: u32,
    l2_index: u32,
) -> u64 {
    let cluster_size = header.cluster_size;
    let cluster_size_us = cluster_size as usize;

    // Step 1: locate (or allocate) the L2 table for L1[l1_index].
    let l1_off = header.l1_table_offset as usize + (l1_index as usize) * 8;
    let l1_entry = be_u64(bytes, l1_off);
    let l2_host = if l1_entry == 0 {
        // Append an L2 cluster.
        let off = bytes.len() as u64;
        bytes.extend_from_slice(&vec![0u8; cluster_size_us]);
        // Point L1[i] at it with OFLAG_COPIED.
        write_be_u64(bytes, l1_off, off | (1u64 << 63));
        // Increment refcount for the L2 cluster.
        bump_refcount(bytes, header, off);
        off
    } else {
        l1_entry & qcow2::L2_OFFSET_MASK
    };

    // Step 2: allocate a data cluster.
    let data_host = bytes.len() as u64;
    bytes.extend_from_slice(&vec![0xAB; cluster_size_us]);

    // Step 3: point L2[l2_index] at it with OFLAG_COPIED.
    let l2_entry_off = l2_host as usize + (l2_index as usize) * 8;
    write_be_u64(bytes, l2_entry_off, data_host | (1u64 << 63));

    // Step 4: bump refcount for the new data cluster.
    bump_refcount(bytes, header, data_host);

    data_host
}

/// Set the refcount entry for `cluster_host_offset` to 1 in the
/// refcount block that covers it.
fn bump_refcount(bytes: &mut [u8], header: &QcowHeader, cluster_host_offset: u64) {
    let cluster_size = header.cluster_size;
    let entries_per_refblock = (cluster_size * 8) / header.refcount_bits as u64;
    let cluster_idx = cluster_host_offset / cluster_size;
    let block_idx = cluster_idx / entries_per_refblock;
    let local_idx = (cluster_idx % entries_per_refblock) as usize;

    let rt_entry_off = header.refcount_table_offset as usize + (block_idx as usize) * 8;
    let block_offset = be_u64(bytes, rt_entry_off);
    if block_offset == 0 {
        panic!(
            "refcount block {} not allocated; forging needs a fully-formed image",
            block_idx
        );
    }
    // Assume 16-bit refcounts (default; what build_starting_image uses).
    let entry_off = block_offset as usize + local_idx * 2;
    bytes[entry_off] = 0x00;
    bytes[entry_off + 1] = 0x01;
}

fn opts_from_image<'a>(
    bytes: &'a [u8],
    header: &QcowHeader,
    new_virtual_size: u64,
    allow_shrink: bool,
    stage_l2_for_l1_indices: &[u32],
) -> Qcow2ResizeOpts<'a> {
    let cluster_size = header.cluster_size as u32;
    let l1_size_bytes = (header.l1_size as usize) * 8;
    let existing_l1_bytes =
        &bytes[header.l1_table_offset as usize..header.l1_table_offset as usize + l1_size_bytes];
    let rt_size_bytes = (header.refcount_table_clusters as usize) * (cluster_size as usize);
    let existing_refcount_table_bytes = &bytes[header.refcount_table_offset as usize
        ..header.refcount_table_offset as usize + rt_size_bytes];

    // Stage every existing refcount block (simpler for tests).
    let mut block_indices: Vec<u64> = Vec::new();
    let mut block_bytes: Vec<u8> = Vec::new();
    let mut i = 0;
    while i + 8 <= existing_refcount_table_bytes.len() {
        let entry = be_u64(existing_refcount_table_bytes, i);
        if entry != 0 {
            let idx = (i / 8) as u64;
            block_indices.push(idx);
            let off = entry as usize;
            block_bytes.extend_from_slice(&bytes[off..off + cluster_size as usize]);
        }
        i += 8;
    }
    let block_indices: &'static [u64] = Box::leak(block_indices.into_boxed_slice());
    let block_bytes: &'static [u8] = Box::leak(block_bytes.into_boxed_slice());

    // Stage the requested L2 tables.
    let mut l2_indices: Vec<u32> = Vec::new();
    let mut l2_bytes_buf: Vec<u8> = Vec::new();
    for &l1_idx in stage_l2_for_l1_indices {
        let l1_entry = be_u64(existing_l1_bytes, (l1_idx as usize) * 8);
        if l1_entry == 0 {
            continue;
        }
        let l2_host = (l1_entry & qcow2::L2_OFFSET_MASK) as usize;
        l2_indices.push(l1_idx);
        l2_bytes_buf.extend_from_slice(&bytes[l2_host..l2_host + cluster_size as usize]);
    }
    let l2_indices: &'static [u32] = Box::leak(l2_indices.into_boxed_slice());
    let l2_bytes: &'static [u8] = Box::leak(l2_bytes_buf.into_boxed_slice());

    Qcow2ResizeOpts {
        current_virtual_size: header.virtual_size,
        new_virtual_size,
        cluster_size,
        refcount_bits: header.refcount_bits as u8,
        extended_l2: header.extended_l2,
        preallocation: Preallocation::Off,
        allow_shrink,
        existing_l1_bytes,
        existing_refcount_table_bytes,
        existing_refcount_block_bytes: block_bytes,
        existing_refcount_block_indices: block_indices,
        current_file_size: bytes.len() as u64,
        current_l1_entries: header.l1_size,
        current_l1_table_offset: header.l1_table_offset,
        current_refcount_table_offset: header.refcount_table_offset,
        current_refcount_table_clusters: header.refcount_table_clusters,
        current_incompatible_features: header.incompatible_features,
        current_autoclear_features: 0,
        backing_file: None,
        backing_format: None,
        lazy_refcounts: header.lazy_refcounts,
        existing_l2_bytes: l2_bytes,
        existing_l2_indices: l2_indices,
    }
}

// ---------------------------------------------------------------------------
// Positive paths
// ---------------------------------------------------------------------------

#[test]
fn shrink_within_single_l2_entry() {
    // 64 MiB → 32 MiB at default cluster: both fit inside L1[0]'s
    // L2 coverage (512 MiB). L1[0] is zero in a fresh image →
    // no L2 to walk, just rewrite header.
    let (bytes, header) = build_starting_image(64 << 20, 65536);
    let opts = opts_from_image(&bytes, &header, 32 << 20, true, &[]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("shrink plan");
    assert_eq!(plan.action, ResizeAction::Shrink);

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);
    let parsed = QcowHeader::parse(&file).expect("re-parse");
    assert_eq!(parsed.virtual_size, 32 << 20);
}

#[test]
fn shrink_preserves_sub_byte_refcount_width() {
    // Regression for instar #365: the shrink path rebuilds the qcow2
    // header via crates/qcow2::build_header. That writer used to hardcode
    // refcount_order=4, so shrinking a refcount_bits=1/2/4 image produced a
    // header that claimed 16-bit refcounts over sub-byte-packed blocks
    // (qemu-img check ERRORs, exit 0). The rebuilt header must declare the
    // source image's actual refcount width.
    for rb in [1u8, 2, 4] {
        let opts = Qcow2CreateOpts {
            virtual_size: 64 << 20,
            cluster_size: 65536,
            refcount_bits: rb,
            extended_l2: false,
            lazy_refcounts: false,
            compat_v3: true,
            backing: None,
            preallocation: qcow2::create::Preallocation::Off,
        };
        let mut cscratch = vec![0u8; create::QCOW2_MAX_METADATA_SCRATCH];
        let bytes = materialise_create(&plan_qcow2(&opts, &mut cscratch).expect("create plan"));
        let header = QcowHeader::parse(&bytes).expect("parse starting");
        assert_eq!(header.refcount_bits, rb as u32, "starting image width");

        let ropts = opts_from_image(&bytes, &header, 32 << 20, true, &[]);
        let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
        let plan = plan_resize_qcow2(&ropts, &mut scratch).expect("shrink plan");
        assert_eq!(plan.action, ResizeAction::Shrink);

        let mut file = bytes.clone();
        apply_resize(&mut file, &plan);
        let parsed = QcowHeader::parse(&file).expect("re-parse");
        assert_eq!(parsed.virtual_size, 32 << 20);
        // The rebuilt header must keep the sub-byte width, not revert to 16.
        assert_eq!(
            parsed.refcount_bits, rb as u32,
            "shrunk image refcount width"
        );
    }
}

#[test]
fn shrink_drops_multiple_l1_entries() {
    // 4 GiB → 1 GiB at default cluster: L1 entries 2..=7 are
    // fully above the boundary, L1[1] straddles. Fresh image
    // has all L1 entries zero so the walk just zeros the L1
    // tail and rewrites the header.
    let (bytes, header) = build_starting_image(4u64 << 30, 65536);
    let opts = opts_from_image(&bytes, &header, 1u64 << 30, true, &[]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("shrink plan");
    assert_eq!(plan.action, ResizeAction::Shrink);

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);
    let parsed = QcowHeader::parse(&file).expect("re-parse");
    assert_eq!(parsed.virtual_size, 1u64 << 30);
}

#[test]
fn shrink_to_cluster_boundary_no_straddle() {
    // 2 GiB → 512 MiB at default cluster: 512 MiB is the exact
    // L1[1] boundary, so no straddling case — just discard
    // L1[1..3].
    let (bytes, header) = build_starting_image(2u64 << 30, 65536);
    let opts = opts_from_image(&bytes, &header, 512 << 20, true, &[]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("shrink plan");
    assert_eq!(plan.action, ResizeAction::Shrink);

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);
    let parsed = QcowHeader::parse(&file).expect("re-parse");
    assert_eq!(parsed.virtual_size, 512 << 20);
}

#[test]
fn shrink_rounds_down_to_cluster_boundary() {
    // Ask for 32 MiB + 1 byte; planner rounds down to 32 MiB.
    let (bytes, header) = build_starting_image(64 << 20, 65536);
    let opts = opts_from_image(&bytes, &header, (32 << 20) + 1, true, &[]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("shrink plan");

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);
    let parsed = QcowHeader::parse(&file).expect("re-parse");
    assert_eq!(parsed.virtual_size, 32 << 20);
}

#[test]
fn shrink_with_allocated_cluster_below_boundary() {
    // Allocate a data cluster at L1[0] / L2[5] (guest offset
    // 5 * 64K = 320K, well below 32 MiB). Shrink from 64 MiB to
    // 32 MiB. The cluster should survive — its guest offset is
    // < new_virtual_size, so it's not discarded.
    let (mut bytes, header) = build_starting_image(64 << 20, 65536);
    let data_host = forge_allocated_cluster(&mut bytes, &header, 0, 5);

    // L1[0] is now non-zero; stage its L2.
    let opts = opts_from_image(&bytes, &header, 32 << 20, true, &[0]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("shrink plan");

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);

    // Walk the post-resize L1/L2 and confirm the data cluster
    // is still referenced.
    let parsed = QcowHeader::parse(&file).expect("re-parse");
    assert_eq!(parsed.virtual_size, 32 << 20);
    let l1_entry = be_u64(&file, parsed.l1_table_offset as usize + 0);
    let l2_host = l1_entry & qcow2::L2_OFFSET_MASK;
    let l2_entry = be_u64(&file, l2_host as usize + 5 * 8);
    assert_eq!(l2_entry & qcow2::L2_OFFSET_MASK, data_host);
}

#[test]
fn shrink_discards_cluster_above_boundary() {
    // Allocate a data cluster at L1[1] / L2[0] (guest offset
    // 512 MiB, which is above a 256 MiB shrink target).
    let (mut bytes, header) = build_starting_image(1u64 << 30, 65536);
    let _data_host = forge_allocated_cluster(&mut bytes, &header, 1, 0);

    let opts = opts_from_image(&bytes, &header, 256 << 20, true, &[1]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("shrink plan");

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);

    // The L1[1] entry should now be zero (its whole coverage is
    // above the boundary).
    let parsed = QcowHeader::parse(&file).expect("re-parse");
    assert_eq!(parsed.virtual_size, 256 << 20);
    let l1_entry = be_u64(&file, parsed.l1_table_offset as usize + 8);
    assert_eq!(l1_entry, 0, "L1[1] should be zeroed");
}

// ---------------------------------------------------------------------------
// Negative paths
// ---------------------------------------------------------------------------

#[test]
fn shrink_without_flag_when_clusters_above_size() {
    // Forge an allocated cluster above the shrink boundary, then
    // attempt without --shrink → ShrinkBelowAllocated.
    let (mut bytes, header) = build_starting_image(1u64 << 30, 65536);
    forge_allocated_cluster(&mut bytes, &header, 1, 0);
    let opts = opts_from_image(&bytes, &header, 256 << 20, false, &[1]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    // Without --shrink, the planner rejects up-front based on
    // the size delta; it doesn't even walk to find allocated
    // entries. The user gets ShrinkWithoutFlag in that case
    // (matching qemu's two-stage error).
    assert_eq!(
        plan_resize_qcow2(&opts, &mut scratch).unwrap_err(),
        ResizeError::ShrinkWithoutFlag
    );
}

#[test]
fn shrink_with_flag_proceeds_even_with_allocated_cluster() {
    let (mut bytes, header) = build_starting_image(1u64 << 30, 65536);
    forge_allocated_cluster(&mut bytes, &header, 1, 0);
    let opts = opts_from_image(&bytes, &header, 256 << 20, true, &[1]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("shrink with --shrink");
    assert_eq!(plan.action, ResizeAction::Shrink);
}

#[test]
fn shrink_below_minimum_cluster_rejected() {
    let (bytes, header) = build_starting_image(64 << 20, 65536);
    // Ask for 1 byte → rounds down to 0 → reject.
    let opts = opts_from_image(&bytes, &header, 1, true, &[]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    assert_eq!(
        plan_resize_qcow2(&opts, &mut scratch).unwrap_err(),
        ResizeError::InvalidNewVirtualSize
    );
}

#[test]
fn missing_l2_in_staging_returns_scratch_too_small() {
    // L1[1] is non-zero (forged); we shrink so the L2 walk
    // would need it, but the opts don't stage it.
    let (mut bytes, header) = build_starting_image(1u64 << 30, 65536);
    forge_allocated_cluster(&mut bytes, &header, 1, 0);
    let opts = opts_from_image(&bytes, &header, 256 << 20, true, &[]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    assert_eq!(
        plan_resize_qcow2(&opts, &mut scratch).unwrap_err(),
        ResizeError::ScratchTooSmall
    );
}

// ---------------------------------------------------------------------------
// Crash-safety invariant
// ---------------------------------------------------------------------------

#[test]
fn shrink_patches_have_no_cleanup_phase() {
    // The shrink planner emits patches in prepare → header
    // order; there are no Append patches and no Writes after
    // the header rewrite.
    let (mut bytes, header) = build_starting_image(1u64 << 30, 65536);
    forge_allocated_cluster(&mut bytes, &header, 1, 0);
    let opts = opts_from_image(&bytes, &header, 256 << 20, true, &[1]);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("plan");

    let patches = plan.patches();
    let header_idx = patches
        .iter()
        .position(|p| matches!(p, ResizePatch::Write { byte_offset: 0, .. }))
        .expect("header rewrite present");
    // Header is the LAST patch.
    assert_eq!(
        header_idx,
        patches.len() - 1,
        "shrink has no cleanup phase; header should be the final patch"
    );
    // No Appends in shrink.
    for p in patches {
        assert!(
            !matches!(p, ResizePatch::Append { .. }),
            "shrink shouldn't emit Append patches"
        );
    }
}
