//! End-to-end integration tests for the qcow2 commit planner.
//!
//! Each test builds a backing + overlay via `create::plan_qcow2`,
//! materialises their bytes, stages the backing's refcount table
//! and refcount blocks, calls `plan_commit_qcow2`, and asserts
//! the returned context's geometry matches the parsed headers.
//! The allocator is exercised against the staged refblocks; the
//! per-cluster commit loop itself is the phase 7 guest binary's
//! responsibility.

mod common;

use commit::{
    allocate_backing_cluster_qcow2, plan_commit_qcow2, BackingAllocationState, CommitError,
    Qcow2CommitOpts,
};
use common::materialise_create;
use create::{plan_qcow2, BackingRef, Qcow2CreateOpts, QCOW2_MAX_METADATA_SCRATCH};
use qcow2::QcowHeader;
use shared::{be_u64, ImageFormat};

const CLUSTER_SIZE: u32 = 65536;
const VIRTUAL_SIZE: u64 = 1 << 20;

/// Build a standalone qcow2 backing image. Returns the bytes
/// and the parsed header.
fn build_backing(virtual_size: u64) -> (Vec<u8>, QcowHeader) {
    let opts = Qcow2CreateOpts {
        virtual_size,
        cluster_size: CLUSTER_SIZE,
        refcount_bits: 16,
        extended_l2: false,
        lazy_refcounts: false,
        compat_v3: true,
        backing: None,
        preallocation: qcow2::create::Preallocation::Off,
    };
    let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
    let plan = plan_qcow2(&opts, &mut scratch).expect("backing plan");
    let bytes = materialise_create(&plan);
    let header = QcowHeader::parse(&bytes).expect("parse backing");
    (bytes, header)
}

/// Build a qcow2 overlay backed by `backing_path`.
fn build_overlay(backing_path: &[u8], virtual_size: u64) -> (Vec<u8>, QcowHeader) {
    let opts = Qcow2CreateOpts {
        virtual_size,
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
    let plan = plan_qcow2(&opts, &mut scratch).expect("overlay plan");
    let bytes = materialise_create(&plan);
    let header = QcowHeader::parse(&bytes).expect("parse overlay");
    (bytes, header)
}

/// Extract the refcount blocks referenced by an image's refcount
/// table, returning `(host_offsets, block_bytes, count)`.
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
fn plan_populates_geometry_for_real_images() {
    let (backing_bytes, backing_header) = build_backing(VIRTUAL_SIZE);
    let (overlay_bytes, overlay_header) = build_overlay(b"base.qcow2", VIRTUAL_SIZE);
    let (host_offsets, block_bytes, count) = stage_refblocks(&backing_bytes, &backing_header);

    let backing_rt_off = backing_header.refcount_table_offset as usize;
    let backing_rt_len =
        (backing_header.refcount_table_clusters as usize) * (backing_header.cluster_size as usize);
    let opts = Qcow2CommitOpts {
        overlay_header: &overlay_bytes[..4096],
        overlay_file_size: overlay_bytes.len() as u64,
        backing_header: &backing_bytes[..4096],
        backing_file_size: backing_bytes.len() as u64,
        backing_refcount_table: &backing_bytes[backing_rt_off..backing_rt_off + backing_rt_len],
        backing_refblock_host_offsets: &host_offsets,
        backing_refcount_blocks: &block_bytes,
        backing_refblock_count: count,
    };
    let mut scratch = vec![0u8; 1024 * 1024];
    let ctx = plan_commit_qcow2(&opts, &mut scratch).expect("plan");

    assert_eq!(ctx.overlay_cluster_size, overlay_header.cluster_size as u32);
    assert_eq!(ctx.backing_cluster_size, backing_header.cluster_size as u32);
    assert_eq!(
        ctx.overlay_cluster_count,
        overlay_header
            .virtual_size
            .div_ceil(overlay_header.cluster_size),
    );
    assert_eq!(ctx.overlay_l1_table_offset, overlay_header.l1_table_offset);
    assert_eq!(ctx.backing_l1_table_offset, backing_header.l1_table_offset);
    assert_eq!(ctx.backing_refcount_bits, 16);
    assert_eq!(ctx.backing_refblock_count, count);
}

#[test]
fn allocator_claims_clusters_in_order() {
    let (backing_bytes, backing_header) = build_backing(VIRTUAL_SIZE);
    let (overlay_bytes, _) = build_overlay(b"base.qcow2", VIRTUAL_SIZE);
    let (host_offsets, block_bytes, count) = stage_refblocks(&backing_bytes, &backing_header);
    let cluster_size = backing_header.cluster_size as u32;

    let backing_rt_off = backing_header.refcount_table_offset as usize;
    let backing_rt_len =
        (backing_header.refcount_table_clusters as usize) * (backing_header.cluster_size as usize);
    let opts = Qcow2CommitOpts {
        overlay_header: &overlay_bytes[..4096],
        overlay_file_size: overlay_bytes.len() as u64,
        backing_header: &backing_bytes[..4096],
        backing_file_size: backing_bytes.len() as u64,
        backing_refcount_table: &backing_bytes[backing_rt_off..backing_rt_off + backing_rt_len],
        backing_refblock_host_offsets: &host_offsets,
        backing_refcount_blocks: &block_bytes,
        backing_refblock_count: count,
    };
    let mut scratch = vec![0u8; 1024 * 1024];
    let mut ctx = plan_commit_qcow2(&opts, &mut scratch).expect("plan");

    // Find the first free entry index in the staged backing
    // refblock so we know what host offsets to expect back.
    let first_free_entry = (0..ctx.backing_entries_per_refblock as usize)
        .find(|i| {
            let off = i * 2;
            ctx.backing_refblocks[off] == 0 && ctx.backing_refblocks[off + 1] == 0
        })
        .expect("at least one free refcount entry in the backing's staged block");

    let mut state = BackingAllocationState::default();
    let a = allocate_backing_cluster_qcow2(&mut ctx, &mut state).expect("alloc 1");
    let b = allocate_backing_cluster_qcow2(&mut ctx, &mut state).expect("alloc 2");
    assert_eq!(a, (first_free_entry as u64) * cluster_size as u64);
    assert_eq!(b, ((first_free_entry + 1) as u64) * cluster_size as u64);
    assert_eq!(state.allocated, 2);
    // First refblock is dirty.
    assert!(ctx.backing_dirty[0] & 1 != 0);
}

#[test]
fn rejects_backing_smaller_than_overlay() {
    let (backing_bytes, backing_header) = build_backing(VIRTUAL_SIZE);
    let (overlay_bytes, _) = build_overlay(b"base.qcow2", 2 * VIRTUAL_SIZE);
    let (host_offsets, block_bytes, count) = stage_refblocks(&backing_bytes, &backing_header);

    let opts = Qcow2CommitOpts {
        overlay_header: &overlay_bytes[..4096],
        overlay_file_size: overlay_bytes.len() as u64,
        backing_header: &backing_bytes[..4096],
        backing_file_size: backing_bytes.len() as u64,
        backing_refcount_table: &[],
        backing_refblock_host_offsets: &host_offsets,
        backing_refcount_blocks: &block_bytes,
        backing_refblock_count: count,
    };
    let mut scratch = vec![0u8; 1024 * 1024];
    let err = plan_commit_qcow2(&opts, &mut scratch).expect_err("expected rejection");
    assert_eq!(err, CommitError::OverlayLargerThanBacking);
}

#[test]
fn rejects_mismatched_refblock_counts() {
    let (backing_bytes, backing_header) = build_backing(VIRTUAL_SIZE);
    let (overlay_bytes, _) = build_overlay(b"base.qcow2", VIRTUAL_SIZE);
    let (host_offsets, block_bytes, _count) = stage_refblocks(&backing_bytes, &backing_header);

    let opts = Qcow2CommitOpts {
        overlay_header: &overlay_bytes[..4096],
        overlay_file_size: overlay_bytes.len() as u64,
        backing_header: &backing_bytes[..4096],
        backing_file_size: backing_bytes.len() as u64,
        backing_refcount_table: &[],
        backing_refblock_host_offsets: &host_offsets,
        backing_refcount_blocks: &block_bytes,
        // Claim a higher refblock count than the offsets array
        // provides — the planner must reject.
        backing_refblock_count: (host_offsets.len() as u32) + 1,
    };
    let mut scratch = vec![0u8; 1024 * 1024];
    let err = plan_commit_qcow2(&opts, &mut scratch).expect_err("expected rejection");
    assert_eq!(err, CommitError::HeaderMismatch);
}
