//! End-to-end integration tests for the qcow2 unsafe-mode
//! rebase planner.
//!
//! Each test builds a starting qcow2 image bytes via
//! `crates/create` (with the original backing reference baked
//! in), populates a `Qcow2RebaseOpts`, calls
//! `plan_rebase_qcow2`, applies the patch list onto the
//! starting bytes, then parses the result with
//! `qcow2::QcowHeader::parse` and asserts the backing
//! reference now matches the rebased target.

mod common;

use common::{apply_rebase, materialise_create};
use create::{plan_qcow2, BackingRef, Qcow2CreateOpts, QCOW2_MAX_METADATA_SCRATCH};
use qcow2::QcowHeader;
use rebase::{plan_rebase_qcow2, Qcow2RebaseOpts, Qcow2RebaseOutput, RebaseError, RebaseMode};
use shared::ImageFormat;

const CLUSTER_SIZE: u32 = 65536;
const VIRTUAL_SIZE: u64 = 1 << 20;

fn build_overlay(backing_path: &[u8]) -> Vec<u8> {
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
    materialise_create(&plan)
}

fn parsed_path<'a>(bytes: &'a [u8], header: &QcowHeader) -> &'a [u8] {
    let off = header.backing_file_offset as usize;
    let len = header.backing_file_size as usize;
    &bytes[off..off + len]
}

#[test]
fn rebase_replaces_backing_path_in_place() {
    let original_path = b"old.qcow2";
    let new_path = b"new.qcow2"; // same length, fits existing slot
    let mut bytes = build_overlay(original_path);
    let header = QcowHeader::parse(&bytes).expect("parse pre");
    assert_eq!(parsed_path(&bytes, &header), original_path);
    let backing_slot_size = header.backing_file_size;

    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Unsafe,
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
    let plan = match out {
        Qcow2RebaseOutput::Unsafe { plan } => plan,
        Qcow2RebaseOutput::Safe { .. } => panic!("expected Unsafe"),
    };
    apply_rebase(&mut bytes, &plan);

    let header_post = QcowHeader::parse(&bytes).expect("parse post");
    assert_eq!(parsed_path(&bytes, &header_post), new_path);
    // Backing-file slot size shrinks to the new path's length;
    // the existing slot capacity (backing_file_size_max) is
    // preserved implicitly by leaving the trailing bytes
    // untouched.
    assert_eq!(header_post.backing_file_size, new_path.len() as u32);
    // The slot we wrote into is the same offset.
    assert_eq!(header_post.backing_file_offset, header.backing_file_offset);
    // Slot capacity hint comes from the original create.
    assert!(
        header_post.backing_file_size <= backing_slot_size,
        "rewritten size should fit in original slot",
    );
}

#[test]
fn detach_clears_backing_pointer() {
    let mut bytes = build_overlay(b"old.qcow2");
    let header_pre = QcowHeader::parse(&bytes).expect("parse pre");
    assert!(header_pre.backing_file_offset != 0);

    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Unsafe,
        overlay_header: &bytes[..4096],
        overlay_file_size: bytes.len() as u64,
        refcount_table: &[],
        refblock_host_offsets: &[],
        refcount_blocks: &[],
        refblock_count: 0,
        new_backing_virtual_size: 0,
        new_backing_path: b"",
        detach: true,
    };
    let mut scratch = vec![0u8; 64 * 1024];
    let out = plan_rebase_qcow2(&opts, &mut scratch).expect("rebase plan");
    let plan = match out {
        Qcow2RebaseOutput::Unsafe { plan } => plan,
        Qcow2RebaseOutput::Safe { .. } => panic!("expected Unsafe"),
    };
    apply_rebase(&mut bytes, &plan);

    let header_post = QcowHeader::parse(&bytes).expect("parse post");
    assert_eq!(header_post.backing_file_offset, 0);
    assert_eq!(header_post.backing_file_size, 0);
}

#[test]
fn rebase_rejects_long_path_relocation() {
    // The original slot was sized to the original path's
    // length; supplying a longer path forces relocation, which
    // the v1 planner doesn't implement. Expect
    // `BackingPathTooLong`.
    let bytes = build_overlay(b"short.qcow2");
    let long_path = b"a-much-longer-backing-name.qcow2";

    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Unsafe,
        overlay_header: &bytes[..4096],
        overlay_file_size: bytes.len() as u64,
        refcount_table: &[],
        refblock_host_offsets: &[],
        refcount_blocks: &[],
        refblock_count: 0,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: long_path,
        detach: false,
    };
    let mut scratch = vec![0u8; 64 * 1024];
    let err = plan_rebase_qcow2(&opts, &mut scratch).expect_err("expected rejection");
    assert_eq!(err, RebaseError::BackingPathTooLong);
}
