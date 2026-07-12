//! End-to-end integration tests for the qcow2 commit planner.
//!
//! Each test builds a backing + overlay via `create::plan_qcow2`,
//! materialises their bytes, calls `plan_commit_qcow2`, and
//! asserts the returned context's geometry matches the parsed
//! headers. The per-cluster commit loop and the backing-side
//! write composition are exercised by `crates/qcow2-write` /
//! `crates/qcow2-write-exec` and the phase 7 guest binary's
//! integration tests.

mod common;

use commit::{plan_commit_qcow2, CommitError, Qcow2CommitOpts};
use common::materialise_create;
use create::{plan_qcow2, BackingRef, Qcow2CreateOpts, QCOW2_MAX_METADATA_SCRATCH};
use qcow2::QcowHeader;
use shared::ImageFormat;

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

#[test]
fn plan_populates_geometry_for_real_images() {
    let (backing_bytes, _backing_header) = build_backing(VIRTUAL_SIZE);
    let (overlay_bytes, overlay_header) = build_overlay(b"base.qcow2", VIRTUAL_SIZE);

    let opts = Qcow2CommitOpts {
        overlay_header: &overlay_bytes[..4096],
        overlay_file_size: overlay_bytes.len() as u64,
        backing_header: &backing_bytes[..4096],
        backing_file_size: backing_bytes.len() as u64,
    };
    let ctx = plan_commit_qcow2(&opts).expect("plan");

    assert_eq!(ctx.overlay_cluster_size, overlay_header.cluster_size as u32);
    assert_eq!(
        ctx.overlay_cluster_count,
        overlay_header
            .virtual_size
            .div_ceil(overlay_header.cluster_size),
    );
    assert_eq!(ctx.overlay_l1_table_offset, overlay_header.l1_table_offset);
    assert_eq!(ctx.overlay_l1_size, overlay_header.l1_size);
    assert_eq!(
        ctx.overlay_refcount_table_offset,
        overlay_header.refcount_table_offset
    );
    assert_eq!(ctx.overlay_refcount_bits, 16);
    assert_eq!(
        ctx.overlay_entries_per_refblock,
        overlay_header.cluster_size * 8 / 16
    );
}

#[test]
fn rejects_backing_smaller_than_overlay() {
    let (backing_bytes, _) = build_backing(VIRTUAL_SIZE);
    let (overlay_bytes, _) = build_overlay(b"base.qcow2", 2 * VIRTUAL_SIZE);

    let opts = Qcow2CommitOpts {
        overlay_header: &overlay_bytes[..4096],
        overlay_file_size: overlay_bytes.len() as u64,
        backing_header: &backing_bytes[..4096],
        backing_file_size: backing_bytes.len() as u64,
    };
    let err = plan_commit_qcow2(&opts).expect_err("expected rejection");
    assert_eq!(err, CommitError::OverlayLargerThanBacking);
}
