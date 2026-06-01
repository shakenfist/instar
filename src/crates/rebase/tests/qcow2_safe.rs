//! End-to-end integration tests for the qcow2 safe-mode rebase
//! planner.
//!
//! Safe mode's contract is split across the planner (which
//! stages the refcount-block region the guest mutates) and the
//! guest-side comparison loop (not exercised in unit tests).
//! These integration tests cover what the planner can deliver
//! end-to-end:
//!
//! - Smoke: build an overlay via `create`, stage its refcount
//!   block in opts, plan a rebase, assert the context's claims
//!   line up with the parsed header and the deferred metadata
//!   patch lands the new backing pointer.
//! - Allocator: drive `allocate_overlay_cluster_qcow2` against
//!   the staged refblocks to claim two clusters in a row, assert
//!   the host offsets line up with the cluster geometry.

mod common;

use common::materialise_create;
use create::{plan_qcow2, BackingRef, Qcow2CreateOpts, QCOW2_MAX_METADATA_SCRATCH};
use qcow2::QcowHeader;
use rebase::{
    allocate_overlay_cluster_qcow2, plan_rebase_qcow2, AllocationState, Qcow2RebaseOpts,
    Qcow2RebaseOutput, RebaseMode,
};
use shared::{be_u64, ImageFormat};

const CLUSTER_SIZE: u32 = 65536;
const VIRTUAL_SIZE: u64 = 1 << 20;

/// Build an overlay qcow2 with the given backing path, returning
/// the bytes plus the parsed header.
fn build_overlay(backing_path: &[u8]) -> (Vec<u8>, QcowHeader) {
    let opts = Qcow2CreateOpts {
        virtual_size: VIRTUAL_SIZE,
        cluster_size: CLUSTER_SIZE,
        refcount_bits: 16,
        extended_l2: false,
        lazy_refcounts: false,
        compat_v3: true,
        backing: Some(BackingRef {
            path: backing_path,
            format: Some(ImageFormat::Qcow2),
        }),
        preallocation: qcow2::create::Preallocation::Off,
    };
    let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
    let plan = plan_qcow2(&opts, &mut scratch).expect("create plan");
    let bytes = materialise_create(&plan);
    let header = QcowHeader::parse(&bytes).expect("parse overlay");
    (bytes, header)
}

/// Extract the single refcount block referenced by the freshly
/// created overlay's refcount table.
fn stage_refblocks(bytes: &[u8], header: &QcowHeader) -> (Vec<u64>, Vec<u8>, u32) {
    let cluster_size = header.cluster_size as usize;
    let rt_size_bytes = (header.refcount_table_clusters as usize) * cluster_size;
    let rt = &bytes[header.refcount_table_offset as usize
        ..header.refcount_table_offset as usize + rt_size_bytes];
    let mut host_offsets = Vec::new();
    let mut block_bytes = Vec::new();
    let mut i = 0;
    while i + 8 <= rt.len() {
        let entry = be_u64(rt, i);
        if entry != 0 {
            host_offsets.push(entry);
            block_bytes.extend_from_slice(&bytes[entry as usize..entry as usize + cluster_size]);
        }
        i += 8;
    }
    let count = host_offsets.len() as u32;
    (host_offsets, block_bytes, count)
}

#[test]
fn safe_mode_context_matches_overlay_geometry() {
    let (bytes, header) = build_overlay(b"old.qcow2");
    let (host_offsets, block_bytes, count) = stage_refblocks(&bytes, &header);
    let new_path = b"new.qcow2";

    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Safe,
        overlay_header: &bytes[..4096],
        overlay_file_size: bytes.len() as u64,
        refcount_table: &bytes[header.refcount_table_offset as usize
            ..header.refcount_table_offset as usize
                + (header.refcount_table_clusters as usize) * (header.cluster_size as usize)],
        refblock_host_offsets: &host_offsets,
        refcount_blocks: &block_bytes,
        refblock_count: count,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: new_path,
        detach: false,
    };
    let mut scratch = vec![0u8; 1024 * 1024];
    let out = plan_rebase_qcow2(&opts, &mut scratch).expect("rebase plan");
    let (context, deferred) = match out {
        Qcow2RebaseOutput::Safe {
            context,
            deferred_metadata,
        } => (context, deferred_metadata),
        Qcow2RebaseOutput::Unsafe { .. } => panic!("expected Safe"),
    };

    assert_eq!(context.overlay_cluster_size, header.cluster_size as u32);
    assert_eq!(
        context.overlay_cluster_count,
        header.virtual_size.div_ceil(header.cluster_size),
    );
    assert_eq!(context.overlay_l1_table_offset, header.l1_table_offset);
    assert_eq!(context.overlay_l1_size, header.l1_size);
    assert_eq!(context.refcount_bits, 16);
    assert_eq!(context.refblock_count, count);

    // Deferred metadata: path bytes, then header field rewrite.
    let patches = deferred.patches();
    assert_eq!(patches.len(), 2);
}

#[test]
fn safe_mode_allocator_claims_clusters_in_order() {
    let (bytes, header) = build_overlay(b"old.qcow2");
    let (host_offsets, block_bytes, count) = stage_refblocks(&bytes, &header);
    let cluster_size = header.cluster_size as u32;

    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Safe,
        overlay_header: &bytes[..4096],
        overlay_file_size: bytes.len() as u64,
        refcount_table: &bytes[header.refcount_table_offset as usize
            ..header.refcount_table_offset as usize
                + (header.refcount_table_clusters as usize) * (header.cluster_size as usize)],
        refblock_host_offsets: &host_offsets,
        refcount_blocks: &block_bytes,
        refblock_count: count,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: b"new.qcow2",
        detach: false,
    };
    let mut scratch = vec![0u8; 1024 * 1024];
    let out = plan_rebase_qcow2(&opts, &mut scratch).expect("rebase plan");
    let Qcow2RebaseOutput::Safe { mut context, .. } = out else {
        panic!("expected Safe");
    };

    // Find the first free entry index in the staged refblock so
    // we know what host offsets to expect back.
    let first_free_entry = (0..context.entries_per_refblock as usize)
        .find(|i| {
            let off = i * 2;
            context.refblocks[off] == 0 && context.refblocks[off + 1] == 0
        })
        .expect("at least one free refcount entry in the staged block");

    let mut state = AllocationState::default();
    let a = allocate_overlay_cluster_qcow2(&mut context, &mut state).expect("alloc 1");
    let b = allocate_overlay_cluster_qcow2(&mut context, &mut state).expect("alloc 2");
    assert_eq!(a, (first_free_entry as u64) * cluster_size as u64);
    assert_eq!(b, ((first_free_entry + 1) as u64) * cluster_size as u64);
    assert_eq!(state.allocated, 2);
    // First refblock is dirty.
    assert!(context.dirty[0] & 1 != 0);
}
