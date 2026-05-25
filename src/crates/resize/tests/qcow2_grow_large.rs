//! Large-image qcow2 grow tests (followup-01).
//!
//! These exercise the targeted refcount-block pre-pass at image
//! sizes that the previous "stage every non-zero refcount block"
//! approach could not handle (image-size ceiling at default
//! 64 KiB cluster was ~128 GiB).
//!
//! The tests run end-to-end through the planner with **only the
//! blocks `compute_qcow2_grow_query` identifies** staged in
//! `existing_refcount_block_bytes`.  If the planner returns
//! `ScratchTooSmall` the pre-pass under-staged for a flavour;
//! that's the regression the suite catches.
//!
//! Image sizes up to 1 TiB are handled in memory because
//! `Preallocation::Off` means a 1 TiB qcow2's *file* size is
//! just metadata (~hundreds of KiB), not the virtual size.

use create::{plan_qcow2, MetadataPlan, Qcow2CreateOpts};
use qcow2::QcowHeader;
use resize::{
    compute_qcow2_grow_query, plan_resize_qcow2, Preallocation, Qcow2GrowAction,
    Qcow2ResizeGrowQuery, Qcow2ResizeOpts, ResizeAction, ResizePatch, QCOW2_MAX_RESIZE_SCRATCH,
};
use shared::be_u64;

// ---------------------------------------------------------------------------
// Helpers (smaller mirrors of qcow2_grow.rs's helpers — kept inline
// to avoid a shared-test-helpers module that the workspace doesn't
// have wiring for yet)
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

fn apply_resize(file: &mut Vec<u8>, plan: &resize::ResizePlan<'_>) {
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
                if start > file.len() {
                    file.resize(start, 0);
                }
                let end = start + bytes.len();
                if end > file.len() {
                    file.resize(end, 0);
                }
                file[start..end].copy_from_slice(bytes);
            }
            ResizePatch::ZeroFill { byte_offset, len } => {
                let start = *byte_offset as usize;
                let end = start + (*len as usize);
                if end > file.len() {
                    file.resize(end, 0);
                }
                file[start..end].fill(0);
            }
        }
    }
    if file.len() > plan.total_file_size as usize {
        file.truncate(plan.total_file_size as usize);
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

/// Build a `Qcow2ResizeOpts` that stages **only** the refcount
/// blocks `compute_qcow2_grow_query` identifies — the precise
/// scenario the production guest pre-pass produces.
fn opts_with_targeted_blocks<'a>(
    bytes: &'a [u8],
    header: &QcowHeader,
    new_virtual_size: u64,
    indices_buf: &'a mut Vec<u64>,
    bytes_buf: &'a mut Vec<u8>,
) -> Qcow2ResizeOpts<'a> {
    let cluster_size = header.cluster_size as u32;
    let l1_size_bytes = (header.l1_size as usize) * 8;
    let existing_l1_bytes =
        &bytes[header.l1_table_offset as usize..header.l1_table_offset as usize + l1_size_bytes];
    let rt_size_bytes = (header.refcount_table_clusters as usize) * (cluster_size as usize);
    let existing_refcount_table_bytes = &bytes[header.refcount_table_offset as usize
        ..header.refcount_table_offset as usize + rt_size_bytes];

    // Ask the helper which blocks the planner will need.
    let query = Qcow2ResizeGrowQuery {
        cluster_size,
        refcount_bits: header.refcount_bits as u8,
        extended_l2: header.extended_l2,
        current_virtual_size: header.virtual_size,
        new_virtual_size,
        current_file_size: bytes.len() as u64,
        current_l1_entries: header.l1_size,
        current_l1_table_offset: header.l1_table_offset,
        current_refcount_table_offset: header.refcount_table_offset,
        current_refcount_table_clusters: header.refcount_table_clusters,
        current_incompatible_features: header.incompatible_features,
        preallocation: Preallocation::Off,
        allow_shrink: false,
        existing_refcount_table_bytes,
    };
    let qres = compute_qcow2_grow_query(&query).expect("grow query");

    // Stage exactly those blocks (mirroring the production guest).
    indices_buf.clear();
    bytes_buf.clear();
    for i in 0..qres.required_blocks_len {
        let block_idx = qres.required_blocks[i];
        let entry_off = (block_idx as usize) * 8;
        let block_file_off = be_u64(existing_refcount_table_bytes, entry_off) as usize;
        indices_buf.push(block_idx);
        bytes_buf.extend_from_slice(&bytes[block_file_off..block_file_off + cluster_size as usize]);
    }

    Qcow2ResizeOpts {
        current_virtual_size: header.virtual_size,
        new_virtual_size,
        cluster_size,
        refcount_bits: header.refcount_bits as u8,
        extended_l2: header.extended_l2,
        preallocation: Preallocation::Off,
        allow_shrink: false,
        existing_l1_bytes,
        existing_refcount_table_bytes,
        existing_refcount_block_bytes: bytes_buf.as_slice(),
        existing_refcount_block_indices: indices_buf.as_slice(),
        current_file_size: bytes.len() as u64,
        current_l1_entries: header.l1_size,
        current_l1_table_offset: header.l1_table_offset,
        current_refcount_table_offset: header.refcount_table_offset,
        current_refcount_table_clusters: header.refcount_table_clusters,
        current_incompatible_features: header.incompatible_features,
        backing_file: None,
        backing_format: None,
        lazy_refcounts: header.lazy_refcounts,
        existing_l2_bytes: &[],
        existing_l2_indices: &[],
    }
}

/// Full round-trip: build → query → targeted-stage → plan →
/// apply → re-parse.  Returns the post-resize header.
fn targeted_round_trip(
    start_virtual_size: u64,
    new_virtual_size: u64,
    cluster_size: u32,
) -> (QcowHeader, ResizeAction, Qcow2GrowAction) {
    let (mut bytes, header) = build_starting_image(start_virtual_size, cluster_size);

    // Also capture the action the helper picked, for the assertion.
    let cs = cluster_size;
    let rt_off = header.refcount_table_offset as usize;
    let rt_size = (header.refcount_table_clusters as usize) * (cs as usize);
    let q_for_action = Qcow2ResizeGrowQuery {
        cluster_size: cs,
        refcount_bits: header.refcount_bits as u8,
        extended_l2: header.extended_l2,
        current_virtual_size: header.virtual_size,
        new_virtual_size,
        current_file_size: bytes.len() as u64,
        current_l1_entries: header.l1_size,
        current_l1_table_offset: header.l1_table_offset,
        current_refcount_table_offset: header.refcount_table_offset,
        current_refcount_table_clusters: header.refcount_table_clusters,
        current_incompatible_features: header.incompatible_features,
        preallocation: Preallocation::Off,
        allow_shrink: false,
        existing_refcount_table_bytes: &bytes[rt_off..rt_off + rt_size],
    };
    let grow_action = compute_qcow2_grow_query(&q_for_action).unwrap().action;

    let mut indices: Vec<u64> = Vec::new();
    let mut block_bytes: Vec<u8> = Vec::new();
    let opts = opts_with_targeted_blocks(
        &bytes,
        &header,
        new_virtual_size,
        &mut indices,
        &mut block_bytes,
    );
    let mut scratch = vec![0u8; QCOW2_MAX_RESIZE_SCRATCH];
    let plan = plan_resize_qcow2(&opts, &mut scratch).expect("resize plan");
    let action = plan.action;
    apply_resize(&mut bytes, &plan);
    let parsed = QcowHeader::parse(&bytes).expect("re-parse after resize");
    (parsed, action, grow_action)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn grow_64_to_128_gib_at_default_cluster() {
    // 64 GiB -> 128 GiB.  Sits inside the OLD ~128 GiB ceiling
    // boundary; confirms the targeted pre-pass handles cases the
    // stage-all approach could already handle.
    let (parsed, action, grow_action) = targeted_round_trip(64u64 << 30, 128u64 << 30, 65536);
    assert_eq!(action, ResizeAction::Grow);
    assert_eq!(parsed.virtual_size, 128u64 << 30);
    // 64 GiB at default cluster has L1 size 16 entries (1 cluster);
    // 128 GiB needs 32 entries (still 1 cluster). HeaderOnly is the
    // likely action (L1 already fits).
    assert!(matches!(
        grow_action,
        Qcow2GrowAction::HeaderOnly | Qcow2GrowAction::L1Grow | Qcow2GrowAction::L1AndRefcountGrow
    ));
}

#[test]
fn grow_200_to_256_gib_at_default_cluster() {
    // 200 GiB -> 256 GiB.  Sits in the regime the OLD pre-pass
    // could not handle: 200 GiB / 2 GiB per block = 100 blocks
    // existing, well past the 4 MiB / 64 KiB = 64-block cap.  The
    // targeted pre-pass stages O(1) blocks and the planner
    // succeeds.
    let (parsed, action, _) = targeted_round_trip(200u64 << 30, 256u64 << 30, 65536);
    assert_eq!(action, ResizeAction::Grow);
    assert_eq!(parsed.virtual_size, 256u64 << 30);
}

#[test]
fn grow_500_gib_to_1_tib_at_default_cluster() {
    // 500 GiB -> 1 TiB.  Well past the old ceiling.
    let (parsed, action, _) = targeted_round_trip(500u64 << 30, 1024u64 << 30, 65536);
    assert_eq!(action, ResizeAction::Grow);
    assert_eq!(parsed.virtual_size, 1024u64 << 30);
}

#[test]
fn grow_1_tib_to_2_tib_at_default_cluster() {
    // 1 TiB -> 2 TiB.  An order of magnitude past the old ceiling.
    // Demonstrates the bound is now "what the filesystem can hold",
    // not "what fits in 4 MiB of refcount-block staging".
    let (parsed, action, _) = targeted_round_trip(1024u64 << 30, 2048u64 << 30, 65536);
    assert_eq!(action, ResizeAction::Grow);
    assert_eq!(parsed.virtual_size, 2048u64 << 30);
}

#[test]
fn grow_8_gib_to_16_gib_at_4k_cluster() {
    // Small cluster, modest grow.  At 4 KiB cluster the ceiling
    // was tighter (~8 GiB); this grow exercises the boundary
    // crossing.
    let (parsed, action, _) = targeted_round_trip(8u64 << 30, 16u64 << 30, 4096);
    assert_eq!(action, ResizeAction::Grow);
    assert_eq!(parsed.virtual_size, 16u64 << 30);
}
