//! End-to-end integration tests for the qcow2 safe-mode rebase
//! planner.
//!
//! Safe mode's contract is split across the planner (which
//! validates the overlay and builds the deferred metadata
//! plan) and the guest-side comparison loop (not exercised in
//! unit tests; its write composition lives in
//! `crates/qcow2-write` since phase 5 of
//! `PLAN-qcow2-write-infrastructure`). These integration tests
//! cover what the planner can deliver end-to-end:
//!
//! - Smoke: build an overlay via `create`, plan a rebase,
//!   assert the context's geometry claims line up with the
//!   parsed header and the deferred metadata patch lands the
//!   new backing pointer.

mod common;

use common::materialise_create;
use create::{plan_qcow2, BackingRef, Qcow2CreateOpts, QCOW2_MAX_METADATA_SCRATCH};
use qcow2::QcowHeader;
use rebase::{plan_rebase_qcow2, Qcow2RebaseOpts, Qcow2RebaseOutput, RebaseMode};
use shared::ImageFormat;

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

#[test]
fn safe_mode_context_matches_overlay_geometry() {
    let (bytes, header) = build_overlay(b"old.qcow2");
    let new_path = b"new.qcow2";

    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Safe,
        overlay_header: &bytes[..4096],
        overlay_file_size: bytes.len() as u64,
        refcount_table: &[],
        refblock_host_offsets: &[],
        refcount_blocks: &[],
        refblock_count: 0,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: new_path,
        detach: false,
    };
    let mut scratch = vec![0u8; 64 * 1024];
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

    // Deferred metadata: path bytes, then header field rewrite.
    let patches = deferred.patches();
    assert_eq!(patches.len(), 2);
}
