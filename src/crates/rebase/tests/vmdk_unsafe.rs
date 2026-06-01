//! End-to-end integration tests for the vmdk monolithicSparse
//! unsafe-mode rebase planner.
//!
//! Build a starting vmdk image via `crates/create` with an
//! initial backing reference, plan a rebase to a new backing
//! path, apply the patches, then verify the descriptor's
//! `parentFileNameHint=` and `parentCID=` lines reflect the
//! rebase target.

mod common;

use common::{apply_rebase, materialise_create};
use create::{plan_vmdk, BackingRef, VmdkCreateOpts, VmdkSubformat, VMDK_MAX_METADATA_SCRATCH};
use rebase::{plan_rebase_vmdk, VmdkRebaseOpts, VmdkRebaseOutput};
use shared::ImageFormat;
use vmdk::{Vmdk4HeaderFull, DESC_SECTORS};

const VIRTUAL_SIZE: u64 = 64 * 1024 * 1024;
const GRAIN_SIZE: u32 = 65536;

fn build_overlay(backing_path: &[u8], parent_cid: u32) -> (Vec<u8>, Vmdk4HeaderFull) {
    let opts = VmdkCreateOpts {
        virtual_size: VIRTUAL_SIZE,
        subformat: VmdkSubformat::MonolithicSparse,
        grain_size: GRAIN_SIZE,
        backing: Some(BackingRef {
            path: backing_path,
            format: Some(ImageFormat::Vmdk4),
        }),
        parent_cid: Some(parent_cid),
    };
    let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
    let plan = plan_vmdk(&opts, &mut scratch).expect("create plan");
    let bytes = materialise_create(&plan);
    let header = Vmdk4HeaderFull::parse(&bytes).expect("parse overlay");
    (bytes, header)
}

fn descriptor_bytes<'a>(file: &'a [u8], header: &Vmdk4HeaderFull) -> &'a [u8] {
    let off = (header.desc_offset_sectors * 512) as usize;
    let len = (header.desc_size_sectors * 512) as usize;
    &file[off..off + len]
}

#[test]
fn rebase_rewrites_descriptor_with_new_parent() {
    let (mut bytes, header) = build_overlay(b"old.vmdk", 0xdead_beef);
    let original_desc = descriptor_bytes(&bytes, &header).to_vec();
    assert!(original_desc.windows(8).any(|w| w == b"old.vmdk"));
    assert!(original_desc
        .windows(b"parentCID=deadbeef".len())
        .any(|w| w == b"parentCID=deadbeef"));

    let descriptor = descriptor_bytes(&bytes, &header).to_vec();
    let opts = VmdkRebaseOpts::unsafe_only(
        VIRTUAL_SIZE,
        &descriptor,
        (header.desc_size_sectors * 512) as u32,
        header.desc_offset_sectors * 512,
        VIRTUAL_SIZE,
        b"new.vmdk",
        0xc0de_f00d,
        false,
    );
    let mut scratch = vec![0u8; 64 * 1024];
    let out = plan_rebase_vmdk(&opts, &mut scratch).expect("rebase plan");
    let plan = match out {
        VmdkRebaseOutput::Unsafe { plan } => plan,
        VmdkRebaseOutput::Safe { .. } => panic!("expected Unsafe"),
    };
    apply_rebase(&mut bytes, &plan);

    let header_post = Vmdk4HeaderFull::parse(&bytes).expect("parse post");
    let post_desc = descriptor_bytes(&bytes, &header_post);
    let text = std::str::from_utf8(post_desc)
        .unwrap_or("")
        .trim_end_matches('\0');
    assert!(
        text.contains("parentFileNameHint=\"new.vmdk\""),
        "descriptor missing new hint: {text}",
    );
    assert!(
        text.contains("parentCID=c0def00d"),
        "descriptor missing new parentCID: {text}",
    );
    assert!(!text.contains("old.vmdk"), "stale path lingered: {text}");
    // Descriptor sits in the same DESC_SECTORS region.
    assert_eq!(header_post.desc_offset_sectors, 1);
    assert_eq!(header_post.desc_size_sectors, DESC_SECTORS);
}

#[test]
fn rebase_detach_clears_parent_hint() {
    let (mut bytes, header) = build_overlay(b"old.vmdk", 0xdead_beef);

    let descriptor = descriptor_bytes(&bytes, &header).to_vec();
    let opts = VmdkRebaseOpts::unsafe_only(
        VIRTUAL_SIZE,
        &descriptor,
        (header.desc_size_sectors * 512) as u32,
        header.desc_offset_sectors * 512,
        0,
        b"",
        0,
        true,
    );
    let mut scratch = vec![0u8; 64 * 1024];
    let out = plan_rebase_vmdk(&opts, &mut scratch).expect("rebase plan");
    let VmdkRebaseOutput::Unsafe { plan } = out else {
        panic!("expected Unsafe");
    };
    apply_rebase(&mut bytes, &plan);

    let header_post = Vmdk4HeaderFull::parse(&bytes).expect("parse post");
    let post_desc = descriptor_bytes(&bytes, &header_post);
    let text = std::str::from_utf8(post_desc)
        .unwrap_or("")
        .trim_end_matches('\0');
    assert!(
        text.contains("parentCID=ffffffff"),
        "detach missing sentinel parentCID: {text}",
    );
    assert!(
        text.contains("parentFileNameHint=\"\""),
        "detach left a non-empty hint: {text}",
    );
}
