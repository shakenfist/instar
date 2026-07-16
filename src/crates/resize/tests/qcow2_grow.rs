//! End-to-end integration tests for the qcow2 grow planner.
//!
//! Each test builds a starting qcow2 image bytes via
//! `crates/create`, populates a `Qcow2ResizeOpts` from the
//! parsed header, calls `plan_resize_qcow2`, applies the patch
//! list onto the starting bytes, then parses the result with
//! `qcow2::QcowHeader::parse` and asserts the expected
//! post-resize geometry.

use create::{plan_qcow2, MetadataPlan, Qcow2CreateOpts};
use qcow2::QcowHeader;
use resize::{
    plan_resize_qcow2, Preallocation, Qcow2ResizeOpts, ResizeAction, ResizeError, ResizePatch,
    ResizePlan, QCOW2_MAX_RESIZE_SCRATCH,
};
use shared::be_u64;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Materialise a `MetadataPlan` (from crates/create) into a
/// contiguous byte buffer sized to `minimum_file_size`.
fn materialise_create(plan: &MetadataPlan<'_>) -> Vec<u8> {
    let mut buf = vec![0u8; plan.minimum_file_size as usize];
    for w in plan.writes() {
        let start = w.byte_offset as usize;
        let end = start + w.bytes.len();
        buf[start..end].copy_from_slice(w.bytes);
    }
    buf
}

/// Apply a `ResizePlan` to an existing byte buffer. The buffer
/// is extended to `plan.total_file_size` if necessary; patches
/// are applied in order.
fn apply_resize(file: &mut Vec<u8>, plan: &ResizePlan<'_>) {
    if file.len() < plan.total_file_size as usize {
        file.resize(plan.total_file_size as usize, 0);
    }
    for patch in plan.patches() {
        match patch {
            ResizePatch::Write { byte_offset, bytes } => {
                let start = *byte_offset as usize;
                let end = start + bytes.len();
                if end > file.len() {
                    file.resize(end, 0);
                }
                file[start..end].copy_from_slice(bytes);
            }
            ResizePatch::Append { byte_offset, bytes } => {
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

/// Build a starting qcow2 image with the given virtual size and
/// cluster size; return the bytes plus the parsed header.
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

/// Populate a `Qcow2ResizeOpts` from a starting image's bytes
/// and header.
fn opts_from_image<'a>(
    bytes: &'a [u8],
    header: &QcowHeader,
    new_virtual_size: u64,
    preallocation: Preallocation,
    allow_shrink: bool,
) -> Qcow2ResizeOpts<'a> {
    let cluster_size = header.cluster_size as u32;
    let l1_size_bytes = (header.l1_size as usize) * 8;
    let existing_l1_bytes =
        &bytes[header.l1_table_offset as usize..header.l1_table_offset as usize + l1_size_bytes];
    let rt_size_bytes = (header.refcount_table_clusters as usize) * (cluster_size as usize);
    let existing_refcount_table_bytes = &bytes[header.refcount_table_offset as usize
        ..header.refcount_table_offset as usize + rt_size_bytes];

    // Stage every existing refcount block (small count for our
    // test images; in production the guest stages selectively).
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
    // Leak the heap allocations into a static-ish lifetime by
    // using a Box::leak; that's fine for tests.
    let block_indices: &'static [u64] = Box::leak(block_indices.into_boxed_slice());
    let block_bytes: &'static [u8] = Box::leak(block_bytes.into_boxed_slice());

    Qcow2ResizeOpts {
        current_virtual_size: header.virtual_size,
        new_virtual_size,
        cluster_size,
        refcount_bits: header.refcount_bits as u8,
        extended_l2: header.extended_l2,
        preallocation,
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
        existing_l2_bytes: &[],
        existing_l2_indices: &[],
    }
}

/// Helper that does the whole round-trip: build → opts → plan →
/// apply → re-parse.
fn round_trip(
    start_virtual_size: u64,
    new_virtual_size: u64,
    cluster_size: u32,
) -> (QcowHeader, ResizeAction, Vec<u8>) {
    let (mut bytes, header) = build_starting_image(start_virtual_size, cluster_size);
    let opts = opts_from_image(&bytes, &header, new_virtual_size, Preallocation::Off, false);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("resize plan");
    let action = plan.action;
    apply_resize(&mut bytes, &plan);
    let parsed = QcowHeader::parse(&bytes).expect("re-parse after resize");
    (parsed, action, bytes)
}

// ---------------------------------------------------------------------------
// Positive paths
// ---------------------------------------------------------------------------

#[test]
fn grow_header_only_when_l1_has_slack() {
    // Default cluster 64 KiB with default refcount bits 16. A
    // 1 MiB image's L1 already addresses 512 MiB (one L1 entry
    // covers cluster_size * entries_per_l2 = 64K * 8K = 512 MiB).
    // Growing to 64 MiB stays within that L1 entry.
    let (parsed, action, _) = round_trip(1 << 20, 64 << 20, 65536);
    assert_eq!(action, ResizeAction::Grow);
    assert_eq!(parsed.virtual_size, 64 << 20);
}

#[test]
fn grow_l1_extends_within_existing_refcount_table() {
    // Default cluster, grow from 1 GiB to 16 GiB. 1 GiB / 512 MiB
    // = 2 L1 entries; 16 GiB / 512 MiB = 32 L1 entries. L1 grows
    // from 16 bytes to 256 bytes (both still fit in one cluster).
    // The refcount table at default cluster covers many MiB of
    // file, so no new refcount blocks needed.
    let (parsed, action, _) = round_trip(1 << 30, 16 << 30, 65536);
    assert_eq!(action, ResizeAction::Grow);
    assert_eq!(parsed.virtual_size, 16 << 30);
    assert!(parsed.l1_size >= 32);
}

#[test]
fn grow_l1_and_refcount_table_extension() {
    // Small cluster + large grow forces the refcount-table
    // extension path. cluster_size=512 has tiny L2 coverage so
    // the L1 grows steeply; the file grows past one refcount-
    // block's coverage.
    let (parsed, action, _) = round_trip(1 << 25, 1 << 28, 512);
    assert_eq!(action, ResizeAction::Grow);
    assert_eq!(parsed.virtual_size, 1 << 28);
}

#[test]
fn grow_l1_spillover_into_new_refcount_block() {
    // Regression: differential fuzz iter 66 (seed 4165940029).
    //
    // 256 MiB at cluster_size=512: the fresh-build refcount layout
    // for the target (257 MiB) still only needs one refcount block,
    // so the old `decide_action` chose L1Grow. But L1Grow appends a
    // 129-cluster L1 region at EOF (cluster 131 onwards), which
    // crosses the existing block's 256-cluster coverage and demands
    // a second refcount block. The planner then asked for a refcount
    // block whose RT entry was zero, surfacing as HeaderMismatch.
    //
    // After the append-aware action decision, this scenario must
    // pick L1AndRefcountGrow and produce a valid resize plan.
    let (parsed, action, _) = round_trip(256 << 20, (256 << 20) + (1 << 20), 512);
    assert_eq!(action, ResizeAction::Grow);
    assert_eq!(parsed.virtual_size, (256 << 20) + (1 << 20));
}

#[test]
fn grow_l1_spillover_updates_existing_rt_in_place() {
    // Same shape as the regression above. The refcount table only
    // has 1 cluster (64 entries) which is plenty for the 2 RBs we
    // now need — so the table does not relocate, but its new entry
    // for the second RB must still be written. Verify by parsing
    // the resulting image and confirming RT entry [1] points to a
    // valid in-file refcount block.
    let (parsed, _action, bytes) = round_trip(256 << 20, (256 << 20) + (1 << 20), 512);
    assert_eq!(parsed.refcount_table_clusters, 1);
    let rt_off = parsed.refcount_table_offset as usize;
    let entry0 = be_u64(&bytes, rt_off);
    let entry1 = be_u64(&bytes, rt_off + 8);
    assert_ne!(entry0, 0, "RT entry 0 should still point at block 0");
    assert_ne!(entry1, 0, "RT entry 1 must point at the new block");
    assert!(
        (entry1 as usize) < bytes.len(),
        "RT entry 1 must point inside the file (off=0x{:x}, len={})",
        entry1,
        bytes.len()
    );
}

#[test]
fn grow_l1_spillover_refcounts_are_consistent() {
    // Verify the post-resize image's refcount blocks correctly
    // refcount every cluster the new L1 region occupies and clear
    // the refcount on the old L1 region. Mirrors `qemu-img check`.
    let (parsed, _action, bytes) = round_trip(256 << 20, (256 << 20) + (1 << 20), 512);
    let cluster_size = parsed.cluster_size;
    let rb_entries = cluster_size * 8 / parsed.refcount_bits as u64;
    let rt_off = parsed.refcount_table_offset as usize;
    let rt_bytes =
        &bytes[rt_off..rt_off + parsed.refcount_table_clusters as usize * cluster_size as usize];

    // Walk every cluster, look up its refcount, and check that
    // metadata clusters (header / L1 / RT / RBs) and L2 entries
    // referenced by L1 are all refcount>=1, while old-L1 clusters
    // we deliberately dropped are 0.
    let refcount_of = |cluster: u64| -> u64 {
        let block_idx = cluster / rb_entries;
        let local_idx = cluster % rb_entries;
        let rb_off = be_u64(rt_bytes, (block_idx * 8) as usize);
        if rb_off == 0 {
            return 0;
        }
        let entry_off = rb_off as usize + (local_idx as usize) * 2;
        u16::from_be_bytes([bytes[entry_off], bytes[entry_off + 1]]) as u64
    };

    let header_cluster = 0;
    assert!(refcount_of(header_cluster) >= 1, "header cluster");

    let new_l1_first = parsed.l1_table_offset / cluster_size;
    let new_l1_size_bytes = (parsed.l1_size as u64) * 8;
    let new_l1_clusters = new_l1_size_bytes.div_ceil(cluster_size);
    for c in new_l1_first..new_l1_first + new_l1_clusters {
        assert!(
            refcount_of(c) >= 1,
            "new L1 cluster {c} must be refcounted (got {})",
            refcount_of(c)
        );
    }

    let rt_cluster_first = parsed.refcount_table_offset / cluster_size;
    for c in rt_cluster_first..rt_cluster_first + parsed.refcount_table_clusters as u64 {
        assert!(refcount_of(c) >= 1, "RT cluster {c}");
    }

    // Old L1 region: clusters 1..=128 in this scenario. Iterate
    // until we hit the new L1's first cluster.
    for c in 1..new_l1_first {
        // Skip any cluster that's actually a referenced RB.
        let mut is_rb = false;
        for i in 0..parsed.refcount_table_clusters as u64 * (cluster_size / 8) {
            let rb_off = be_u64(rt_bytes, (i * 8) as usize);
            if rb_off != 0 && rb_off / cluster_size == c {
                is_rb = true;
                break;
            }
        }
        if is_rb {
            continue;
        }
        // Skip RT clusters.
        if c >= rt_cluster_first && c < rt_cluster_first + parsed.refcount_table_clusters as u64 {
            continue;
        }
        assert_eq!(
            refcount_of(c),
            0,
            "old-L1 cluster {c} must be decremented to 0 (got {})",
            refcount_of(c)
        );
    }
}

#[test]
fn noop_when_sizes_equal() {
    let (bytes, header) = build_starting_image(1 << 20, 65536);
    let opts = opts_from_image(&bytes, &header, 1 << 20, Preallocation::Off, false);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("plan");
    assert_eq!(plan.action, ResizeAction::NoOp);
    assert_eq!(plan.patches().len(), 0);
}

// ---------------------------------------------------------------------------
// Crash-safety ordering invariant
// ---------------------------------------------------------------------------

#[test]
fn patches_partition_prepare_header_cleanup() {
    // For L1Grow: prepare-phase patches come before the header
    // rewrite; cleanup-phase patches come after.
    let (bytes, header) = build_starting_image(1 << 25, 65536);
    let opts = opts_from_image(&bytes, &header, 1 << 32, Preallocation::Off, false);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("plan");

    let patches = plan.patches();
    // The header rewrite is a Write at offset 0. Find it.
    let header_idx = patches
        .iter()
        .position(|p| matches!(p, ResizePatch::Write { byte_offset: 0, .. }))
        .expect("header rewrite present");

    // Before the header rewrite: only Appends (new regions) and
    // Writes targeting non-zero offsets (existing refcount-block
    // patches). No second Write at offset 0.
    for p in &patches[..header_idx] {
        match p {
            ResizePatch::Append { .. } => {}
            ResizePatch::Write { byte_offset, .. } => {
                assert_ne!(*byte_offset, 0, "second header write in prepare phase");
            }
            ResizePatch::ZeroFill { .. } => {}
        }
    }
    // After the header rewrite: only Writes (refcount-decrement
    // cleanups). No further Appends or ZeroFills.
    for p in &patches[header_idx + 1..] {
        assert!(
            matches!(p, ResizePatch::Write { .. }),
            "cleanup patch is a Write, got {:?}",
            p
        );
    }
}

// ---------------------------------------------------------------------------
// Negative paths
// ---------------------------------------------------------------------------

#[test]
fn rejects_shrink_without_flag() {
    let (bytes, header) = build_starting_image(1 << 30, 65536);
    let opts = opts_from_image(&bytes, &header, 1 << 28, Preallocation::Off, false);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    assert_eq!(
        plan_resize_qcow2(&opts, &mut scratch).unwrap_err(),
        ResizeError::ShrinkWithoutFlag
    );
}

#[test]
fn rejects_zero_new_virtual_size() {
    let (bytes, header) = build_starting_image(1 << 20, 65536);
    let opts = opts_from_image(&bytes, &header, 0, Preallocation::Off, false);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    assert_eq!(
        plan_resize_qcow2(&opts, &mut scratch).unwrap_err(),
        ResizeError::InvalidNewVirtualSize
    );
}

#[test]
fn rejects_preallocation_metadata_pending_followup() {
    let (bytes, header) = build_starting_image(1 << 25, 65536);
    let opts = opts_from_image(&bytes, &header, 1 << 27, Preallocation::Metadata, false);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    assert_eq!(
        plan_resize_qcow2(&opts, &mut scratch).unwrap_err(),
        ResizeError::PreallocationUnsupported
    );
}

#[test]
fn rejects_external_data_incompat_bit() {
    let (bytes, header) = build_starting_image(1 << 20, 65536);
    let mut opts = opts_from_image(&bytes, &header, 2 << 20, Preallocation::Off, false);
    opts.current_incompatible_features = qcow2::INCOMPAT_EXTERNAL_DATA;
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    assert_eq!(
        plan_resize_qcow2(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedFormat
    );
}

#[test]
fn rejects_dirty_image() {
    let (bytes, header) = build_starting_image(1 << 20, 65536);
    let mut opts = opts_from_image(&bytes, &header, 2 << 20, Preallocation::Off, false);
    opts.current_incompatible_features = qcow2::INCOMPAT_DIRTY;
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    assert_eq!(
        plan_resize_qcow2(&opts, &mut scratch).unwrap_err(),
        ResizeError::RequiresCheckFirst
    );
}

#[test]
fn rejects_image_with_persistent_bitmaps() {
    // An otherwise-plannable grow, but the qcow2 bitmaps autoclear
    // bit is set. resize rebuilds the header cluster and would drop
    // the bitmaps extension, so plan_grow must refuse instead.
    let (bytes, header) = build_starting_image(1 << 20, 65536);
    let mut opts = opts_from_image(&bytes, &header, 2 << 20, Preallocation::Off, false);
    opts.current_autoclear_features = qcow2::bitmap::AUTOCLEAR_BITMAPS_BIT;
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    assert_eq!(
        plan_resize_qcow2(&opts, &mut scratch).unwrap_err(),
        ResizeError::BitmapsPresent
    );
}

// ---------------------------------------------------------------------------
// Unaligned file sizes (issue #373)
// ---------------------------------------------------------------------------

/// Give an image qemu-img's on-disk size property: qemu truncates a
/// fresh image at the exact end of its trailing L1 table, so the file
/// size is usually NOT a multiple of `cluster_size` (e.g. 196616
/// bytes for `qemu-img create -o cluster_size=65536 f.qcow2 1M`).
/// instar-created fixtures order their regions differently (the L1 is
/// not the trailing region), so rather than truncating real metadata
/// this helper appends a short zero tail past the last full cluster —
/// the same "EOF mid-cluster, no metadata beyond it" shape. The
/// end-to-end qemu-created-image coverage lives in
/// tests/test_resize.py (TestResizeQemuCreatedImages).
fn with_unaligned_tail(mut bytes: Vec<u8>, cluster_size: u32) -> Vec<u8> {
    assert_eq!(bytes.len() % cluster_size as usize, 0);
    bytes.extend_from_slice(&[0u8; 8]);
    bytes
}

#[test]
fn grow_header_only_on_unaligned_file_keeps_file_size() {
    // Issue #373: growing 1M -> 64M at the default 64K cluster is
    // HeaderOnly (the single L1 entry covers 512 MiB) and must
    // succeed on a cluster-unaligned file — the pre-fix planner
    // refused every unaligned file with HeaderMismatch — without
    // extending it: nothing is appended.
    let (bytes, header) = build_starting_image(1 << 20, 65536);
    let bytes = with_unaligned_tail(bytes, 65536);
    let mut file = bytes.clone();
    let opts = opts_from_image(&bytes, &header, 64 << 20, Preallocation::Off, false);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("unaligned HeaderOnly grow");
    assert_eq!(plan.action, ResizeAction::Grow);
    assert_eq!(
        plan.total_file_size,
        bytes.len() as u64,
        "HeaderOnly must not extend the file"
    );
    apply_resize(&mut file, &plan);
    let parsed = QcowHeader::parse(&file).expect("re-parse");
    assert_eq!(parsed.virtual_size, 64 << 20);
}

#[test]
fn grow_l1_on_unaligned_file_appends_at_cluster_boundary() {
    // Issue #373's failing cs=512 leg (1M -> 64M): the L1 append on
    // an unaligned file must land on the next cluster boundary — not
    // at the unaligned EOF, and not refuse with HeaderMismatch.
    let (bytes, header) = build_starting_image(1 << 20, 512);
    let bytes = with_unaligned_tail(bytes, 512);
    let unaligned_len = bytes.len() as u64;
    let mut file = bytes.clone();
    let opts = opts_from_image(&bytes, &header, 64 << 20, Preallocation::Off, false);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("unaligned L1 grow");
    assert_eq!(plan.action, ResizeAction::Grow);
    assert_eq!(
        plan.total_file_size % 512,
        0,
        "post-grow file must be cluster-aligned"
    );
    apply_resize(&mut file, &plan);
    let parsed = QcowHeader::parse(&file).expect("re-parse");
    assert_eq!(parsed.virtual_size, 64 << 20);
    assert_eq!(
        parsed.l1_table_offset % 512,
        0,
        "appended L1 must start on a cluster boundary"
    );
    assert!(
        parsed.l1_table_offset >= unaligned_len,
        "appended L1 must not overlap the pre-resize file"
    );
}

#[test]
fn grow_matrix_on_unaligned_files_matches_issue_373() {
    // The issue's grow matrix, on unaligned-EOF fixtures: every leg
    // must plan successfully and re-parse with the target virtual
    // size and cluster-aligned metadata offsets.
    let cases: [(u64, u64, u32); 9] = [
        (4 << 20, 8 << 20, 512),
        (1 << 20, 64 << 20, 512),
        (4 << 20, 8 << 20, 4096),
        (1 << 20, 64 << 20, 4096),
        (64 << 20, 256 << 20, 4096),
        (4 << 20, 8 << 20, 65536),
        (1 << 20, 64 << 20, 65536),
        (64 << 20, 256 << 20, 65536),
        (4 << 20, 8 << 20, 1048576),
    ];
    for &(start, target, cs) in &cases {
        let (bytes, header) = build_starting_image(start, cs);
        let bytes = with_unaligned_tail(bytes, cs);
        let mut file = bytes.clone();
        let opts = opts_from_image(&bytes, &header, target, Preallocation::Off, false);
        let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
        let plan = plan_resize_qcow2(&opts, &mut scratch)
            .unwrap_or_else(|e| panic!("{}->{} cs={}: {:?}", start, target, cs, e));
        apply_resize(&mut file, &plan);
        let parsed = QcowHeader::parse(&file).expect("re-parse");
        assert_eq!(parsed.virtual_size, target, "cs={}", cs);
        assert_eq!(parsed.l1_table_offset % cs as u64, 0, "cs={}", cs);
        assert_eq!(parsed.refcount_table_offset % cs as u64, 0, "cs={}", cs);
    }
}
