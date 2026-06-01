//! End-to-end integration tests for the vmdk monolithicSparse
//! safe-mode rebase planner (step 2e).
//!
//! Safe-mode vmdk rebase requires the host to stage the existing
//! grain directory and any already-allocated grain tables. A
//! freshly-created vmdk has no allocated grain tables (the GD
//! is all zeros), so these tests synthesise a one-GT setup by
//! hand: we extend the overlay bytes with a 512-GTE grain
//! table, point GD entry 0 at it, and exercise the planner +
//! allocator against that shape.

mod common;

use common::materialise_create;
use create::{plan_vmdk, BackingRef, VmdkCreateOpts, VmdkSubformat, VMDK_MAX_METADATA_SCRATCH};
use rebase::{
    allocate_overlay_grain_vmdk, plan_rebase_vmdk, GrainAllocationState, RebaseMode,
    VmdkRebaseOpts, VmdkRebaseOutput,
};
use shared::ImageFormat;
use vmdk::Vmdk4HeaderFull;

const VIRTUAL_SIZE: u64 = 64 * 1024 * 1024;
const GRAIN_SIZE: u32 = 65536;
const GRAIN_SIZE_SECTORS: u32 = GRAIN_SIZE / 512;
const GTES_PER_GT: u32 = 512;

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

/// Append a 512-GTE all-zero grain table to `bytes` and point
/// GD entry 0 at it. Returns the GT's host sector offset, the
/// extracted GD bytes, and the GT bytes (both safe to pass as
/// borrowed slices to the planner).
fn install_empty_gt(bytes: &mut Vec<u8>, header: &Vmdk4HeaderFull) -> (u64, Vec<u8>, Vec<u8>) {
    let gt_size_bytes = (GTES_PER_GT as usize) * 4;
    let gt_sector = (bytes.len() as u64) / 512;
    // Extend file to host the GT.
    bytes.resize(bytes.len() + gt_size_bytes, 0u8);
    // Point GD entry 0 at gt_sector (LE u32 sector pointer).
    let gd_off = (header.gd_offset_sectors * 512) as usize;
    bytes[gd_off..gd_off + 4].copy_from_slice(&(gt_sector as u32).to_le_bytes());

    let num_gd_entries = header.num_gd_entries().expect("num_gd_entries");
    let gd_bytes_len = (num_gd_entries as usize) * 4;
    let gd_bytes = bytes[gd_off..gd_off + gd_bytes_len].to_vec();
    let gt_bytes = vec![0u8; gt_size_bytes];
    (gt_sector, gd_bytes, gt_bytes)
}

#[test]
fn safe_mode_smoke_emits_deferred_descriptor() {
    let (mut bytes, header) = build_overlay(b"old.vmdk", 0xdead_beef);
    let (gt_sector, gd_bytes, gt_bytes) = install_empty_gt(&mut bytes, &header);
    let descriptor = descriptor_bytes(&bytes, &header).to_vec();
    let num_gd_entries = header.num_gd_entries().expect("num_gd_entries");
    let gt_host_sectors = vec![gt_sector];

    let opts = VmdkRebaseOpts {
        mode: RebaseMode::Safe,
        overlay_virtual_size: VIRTUAL_SIZE,
        overlay_descriptor: &descriptor,
        overlay_descriptor_size: (header.desc_size_sectors * 512) as u32,
        overlay_descriptor_offset: header.desc_offset_sectors * 512,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: b"new.vmdk",
        new_parent_cid: 0xc0de_f00d,
        detach: false,
        overlay_grain_size_sectors: GRAIN_SIZE_SECTORS,
        num_gtes_per_gt: GTES_PER_GT,
        num_gd_entries,
        gd_offset_sectors: header.gd_offset_sectors,
        overlay_file_size: bytes.len() as u64,
        overlay_grain_directory: &gd_bytes,
        overlay_grain_tables: &gt_bytes,
        allocated_gt_host_sectors: &gt_host_sectors,
        allocated_gt_count: 1,
    };
    let mut scratch = vec![0u8; 256 * 1024];
    let out = plan_rebase_vmdk(&opts, &mut scratch).expect("rebase plan");
    let (context, deferred) = match out {
        VmdkRebaseOutput::Safe {
            context,
            deferred_metadata,
        } => (context, deferred_metadata),
        VmdkRebaseOutput::Unsafe { .. } => panic!("expected Safe"),
    };

    assert_eq!(context.overlay_grain_size_sectors, GRAIN_SIZE_SECTORS);
    assert_eq!(context.num_gtes_per_gt, GTES_PER_GT);
    assert_eq!(context.allocated_gt_count, 1);
    assert_eq!(context.grain_tables.len(), (GTES_PER_GT as usize) * 4);
    assert_eq!(context.grain_directory.len(), (num_gd_entries as usize) * 4);
    // The staged GD slot 0 still points at our installed GT.
    let gd_entry0 = u32::from_le_bytes([
        context.grain_directory[0],
        context.grain_directory[1],
        context.grain_directory[2],
        context.grain_directory[3],
    ]);
    assert_eq!(u64::from(gd_entry0), gt_sector);

    // Deferred metadata patch: descriptor rewrite.
    let patches = deferred.patches();
    assert_eq!(patches.len(), 1);
    let rebase::RebasePatch::Write { byte_offset, bytes } = patches[0] else {
        panic!("expected Write");
    };
    assert_eq!(byte_offset, header.desc_offset_sectors * 512);
    let text = std::str::from_utf8(bytes)
        .unwrap_or("")
        .trim_end_matches('\0');
    assert!(text.contains("parentFileNameHint=\"new.vmdk\""));
    assert!(text.contains("parentCID=c0def00d"));
}

#[test]
fn safe_mode_allocator_lands_at_eof_and_advances_by_grain() {
    let (mut bytes, header) = build_overlay(b"old.vmdk", 0xdead_beef);
    let (gt_sector, gd_bytes, gt_bytes) = install_empty_gt(&mut bytes, &header);
    let file_size_at_plan = bytes.len() as u64;
    let descriptor = descriptor_bytes(&bytes, &header).to_vec();
    let num_gd_entries = header.num_gd_entries().expect("num_gd_entries");
    let gt_host_sectors = vec![gt_sector];

    let opts = VmdkRebaseOpts {
        mode: RebaseMode::Safe,
        overlay_virtual_size: VIRTUAL_SIZE,
        overlay_descriptor: &descriptor,
        overlay_descriptor_size: (header.desc_size_sectors * 512) as u32,
        overlay_descriptor_offset: header.desc_offset_sectors * 512,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: b"new.vmdk",
        new_parent_cid: 0xc0de_f00d,
        detach: false,
        overlay_grain_size_sectors: GRAIN_SIZE_SECTORS,
        num_gtes_per_gt: GTES_PER_GT,
        num_gd_entries,
        gd_offset_sectors: header.gd_offset_sectors,
        overlay_file_size: file_size_at_plan,
        overlay_grain_directory: &gd_bytes,
        overlay_grain_tables: &gt_bytes,
        allocated_gt_host_sectors: &gt_host_sectors,
        allocated_gt_count: 1,
    };
    let mut scratch = vec![0u8; 256 * 1024];
    let out = plan_rebase_vmdk(&opts, &mut scratch).expect("rebase plan");
    let VmdkRebaseOutput::Safe { mut context, .. } = out else {
        panic!("expected Safe");
    };

    let mut state = GrainAllocationState::at_eof(file_size_at_plan, GRAIN_SIZE_SECTORS)
        .expect("init allocator");
    let a = allocate_overlay_grain_vmdk(&mut context, &mut state).expect("alloc 1");
    let b = allocate_overlay_grain_vmdk(&mut context, &mut state).expect("alloc 2");
    let grain_bytes = (GRAIN_SIZE_SECTORS as u64) * 512;
    // First grain at or above EOF, aligned to a grain boundary.
    assert!(a >= file_size_at_plan);
    assert_eq!(a % grain_bytes, 0);
    // Second grain follows immediately.
    assert_eq!(b, a + grain_bytes);
    assert_eq!(state.allocated, 2);
}
