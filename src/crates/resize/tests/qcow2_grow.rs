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
        backing_file: None,
        backing_format: None,
        lazy_refcounts: header.lazy_refcounts,
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
fn rejects_shrink_with_flag_pending_phase_3() {
    let (bytes, header) = build_starting_image(1 << 30, 65536);
    let opts = opts_from_image(&bytes, &header, 1 << 28, Preallocation::Off, true);
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    // Phase 3 lands the real shrink implementation; for now we
    // return UnsupportedShrink so the host can render a
    // "shrink not yet supported" message.
    assert_eq!(
        plan_resize_qcow2(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedShrink
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
