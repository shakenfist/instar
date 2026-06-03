//! End-to-end integration tests for the vmdk monolithicSparse
//! commit planner.
//!
//! Each test builds a backing + overlay via `create::plan_vmdk`,
//! materialises their bytes, and (because a freshly-created
//! vmdk has no allocated grain tables — the GD is all zeros)
//! synthesises a one-GT setup by extending the file with a
//! 512-GTE grain table and pointing GD entry 0 at it. The
//! planner is then exercised against that shape; the grain
//! allocator is driven a couple of times to confirm the EOF
//! cursor advances by `backing_grain_size_sectors`.

mod common;

use commit::{
    allocate_backing_grain_vmdk, plan_commit_vmdk, BackingGrainAllocationState, CommitError,
    VmdkCommitOpts,
};
use common::materialise_create;
use create::{plan_vmdk, VmdkCreateOpts, VmdkSubformat, VMDK_MAX_METADATA_SCRATCH};
use vmdk::Vmdk4HeaderFull;

const VIRTUAL_SIZE: u64 = 64 * 1024 * 1024;
const GRAIN_SIZE: u32 = 65536;
const GRAIN_SIZE_SECTORS: u32 = GRAIN_SIZE / 512;
const GTES_PER_GT: u32 = 512;

fn build_image(virtual_size: u64) -> (Vec<u8>, Vmdk4HeaderFull) {
    let opts = VmdkCreateOpts {
        virtual_size,
        subformat: VmdkSubformat::MonolithicSparse,
        grain_size: GRAIN_SIZE,
        backing: None,
        parent_cid: None,
    };
    let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
    let plan = plan_vmdk(&opts, &mut scratch).expect("create plan");
    let bytes = materialise_create(&plan);
    let header = Vmdk4HeaderFull::parse(&bytes).expect("parse header");
    (bytes, header)
}

fn descriptor_bytes<'a>(file: &'a [u8], header: &Vmdk4HeaderFull) -> &'a [u8] {
    let off = (header.desc_offset_sectors * 512) as usize;
    let len = (header.desc_size_sectors * 512) as usize;
    &file[off..off + len]
}

/// Append a 512-GTE all-zero grain table to `bytes` and point
/// GD entry 0 at it. Returns the GT's host sector offset, the
/// extracted GD bytes, and the GT bytes.
fn install_empty_gt(bytes: &mut Vec<u8>, header: &Vmdk4HeaderFull) -> (u64, Vec<u8>, Vec<u8>) {
    let gt_size_bytes = (GTES_PER_GT as usize) * 4;
    let gt_sector = (bytes.len() as u64) / 512;
    bytes.resize(bytes.len() + gt_size_bytes, 0u8);
    let gd_off = (header.gd_offset_sectors * 512) as usize;
    bytes[gd_off..gd_off + 4].copy_from_slice(&(gt_sector as u32).to_le_bytes());

    let num_gd_entries = header.num_gd_entries().expect("num_gd_entries");
    let gd_bytes_len = (num_gd_entries as usize) * 4;
    let gd_bytes = bytes[gd_off..gd_off + gd_bytes_len].to_vec();
    let gt_bytes = vec![0u8; gt_size_bytes];
    (gt_sector, gd_bytes, gt_bytes)
}

#[test]
fn plan_populates_geometry_for_real_images() {
    let (mut overlay_bytes, overlay_header) = build_image(VIRTUAL_SIZE);
    let (mut backing_bytes, backing_header) = build_image(VIRTUAL_SIZE);
    let (overlay_gt_sector, overlay_gd_bytes, overlay_gt_bytes) =
        install_empty_gt(&mut overlay_bytes, &overlay_header);
    let (backing_gt_sector, backing_gd_bytes, backing_gt_bytes) =
        install_empty_gt(&mut backing_bytes, &backing_header);
    let overlay_descriptor = descriptor_bytes(&overlay_bytes, &overlay_header).to_vec();
    let backing_descriptor = descriptor_bytes(&backing_bytes, &backing_header).to_vec();
    let num_gd_entries = overlay_header.num_gd_entries().expect("num_gd_entries");
    let overlay_gt_hosts = vec![overlay_gt_sector];
    let backing_gt_hosts = vec![backing_gt_sector];

    let opts = VmdkCommitOpts {
        overlay_header: &overlay_bytes[..512],
        overlay_descriptor: &overlay_descriptor,
        overlay_grain_size_sectors: GRAIN_SIZE_SECTORS,
        overlay_num_gtes_per_gt: GTES_PER_GT,
        overlay_num_gd_entries: num_gd_entries,
        overlay_gd_offset_sectors: overlay_header.gd_offset_sectors,
        overlay_grain_directory: &overlay_gd_bytes,
        overlay_grain_tables: &overlay_gt_bytes,
        overlay_allocated_gt_host_sectors: &overlay_gt_hosts,
        overlay_allocated_gt_count: 1,
        overlay_virtual_size: VIRTUAL_SIZE,
        overlay_file_size: overlay_bytes.len() as u64,
        backing_header: &backing_bytes[..512],
        backing_descriptor: &backing_descriptor,
        backing_grain_size_sectors: GRAIN_SIZE_SECTORS,
        backing_num_gtes_per_gt: GTES_PER_GT,
        backing_num_gd_entries: num_gd_entries,
        backing_gd_offset_sectors: backing_header.gd_offset_sectors,
        backing_grain_directory: &backing_gd_bytes,
        backing_grain_tables: &backing_gt_bytes,
        backing_allocated_gt_host_sectors: &backing_gt_hosts,
        backing_allocated_gt_count: 1,
        backing_virtual_size: VIRTUAL_SIZE,
        backing_file_size: backing_bytes.len() as u64,
    };
    let mut scratch = vec![0u8; 256 * 1024];
    let ctx = plan_commit_vmdk(&opts, &mut scratch).expect("plan");

    assert_eq!(ctx.overlay_grain_size_sectors, GRAIN_SIZE_SECTORS);
    assert_eq!(ctx.backing_grain_size_sectors, GRAIN_SIZE_SECTORS);
    assert_eq!(ctx.overlay_num_gtes_per_gt, GTES_PER_GT);
    assert_eq!(ctx.backing_num_gtes_per_gt, GTES_PER_GT);
    assert_eq!(ctx.backing_allocated_gt_count, 1);
    assert_eq!(ctx.backing_grain_tables.len(), (GTES_PER_GT as usize) * 4);
    assert_eq!(
        ctx.backing_grain_directory.len(),
        (num_gd_entries as usize) * 4
    );
    // The staged backing GD slot 0 still points at our
    // installed GT.
    let gd_entry0 = u32::from_le_bytes([
        ctx.backing_grain_directory[0],
        ctx.backing_grain_directory[1],
        ctx.backing_grain_directory[2],
        ctx.backing_grain_directory[3],
    ]);
    assert_eq!(u64::from(gd_entry0), backing_gt_sector);
}

#[test]
fn allocator_lands_at_backing_eof_and_advances_by_grain() {
    let (mut overlay_bytes, overlay_header) = build_image(VIRTUAL_SIZE);
    let (mut backing_bytes, backing_header) = build_image(VIRTUAL_SIZE);
    let (overlay_gt_sector, overlay_gd_bytes, overlay_gt_bytes) =
        install_empty_gt(&mut overlay_bytes, &overlay_header);
    let (backing_gt_sector, backing_gd_bytes, backing_gt_bytes) =
        install_empty_gt(&mut backing_bytes, &backing_header);
    let backing_file_size_at_plan = backing_bytes.len() as u64;
    let overlay_descriptor = descriptor_bytes(&overlay_bytes, &overlay_header).to_vec();
    let backing_descriptor = descriptor_bytes(&backing_bytes, &backing_header).to_vec();
    let num_gd_entries = overlay_header.num_gd_entries().expect("num_gd_entries");
    let overlay_gt_hosts = vec![overlay_gt_sector];
    let backing_gt_hosts = vec![backing_gt_sector];

    let opts = VmdkCommitOpts {
        overlay_header: &overlay_bytes[..512],
        overlay_descriptor: &overlay_descriptor,
        overlay_grain_size_sectors: GRAIN_SIZE_SECTORS,
        overlay_num_gtes_per_gt: GTES_PER_GT,
        overlay_num_gd_entries: num_gd_entries,
        overlay_gd_offset_sectors: overlay_header.gd_offset_sectors,
        overlay_grain_directory: &overlay_gd_bytes,
        overlay_grain_tables: &overlay_gt_bytes,
        overlay_allocated_gt_host_sectors: &overlay_gt_hosts,
        overlay_allocated_gt_count: 1,
        overlay_virtual_size: VIRTUAL_SIZE,
        overlay_file_size: overlay_bytes.len() as u64,
        backing_header: &backing_bytes[..512],
        backing_descriptor: &backing_descriptor,
        backing_grain_size_sectors: GRAIN_SIZE_SECTORS,
        backing_num_gtes_per_gt: GTES_PER_GT,
        backing_num_gd_entries: num_gd_entries,
        backing_gd_offset_sectors: backing_header.gd_offset_sectors,
        backing_grain_directory: &backing_gd_bytes,
        backing_grain_tables: &backing_gt_bytes,
        backing_allocated_gt_host_sectors: &backing_gt_hosts,
        backing_allocated_gt_count: 1,
        backing_virtual_size: VIRTUAL_SIZE,
        backing_file_size: backing_file_size_at_plan,
    };
    let mut scratch = vec![0u8; 256 * 1024];
    let mut ctx = plan_commit_vmdk(&opts, &mut scratch).expect("plan");

    let mut state =
        BackingGrainAllocationState::at_eof(backing_file_size_at_plan, GRAIN_SIZE_SECTORS)
            .expect("init allocator");
    let a = allocate_backing_grain_vmdk(&mut ctx, &mut state).expect("alloc 1");
    let b = allocate_backing_grain_vmdk(&mut ctx, &mut state).expect("alloc 2");
    let grain_bytes = (GRAIN_SIZE_SECTORS as u64) * 512;
    assert!(a >= backing_file_size_at_plan);
    assert_eq!(a % grain_bytes, 0);
    assert_eq!(b, a + grain_bytes);
    assert_eq!(state.allocated, 2);
}

#[test]
fn rejects_backing_smaller_than_overlay() {
    let (mut overlay_bytes, overlay_header) = build_image(VIRTUAL_SIZE);
    let (mut backing_bytes, backing_header) = build_image(VIRTUAL_SIZE / 2);
    let (overlay_gt_sector, overlay_gd_bytes, overlay_gt_bytes) =
        install_empty_gt(&mut overlay_bytes, &overlay_header);
    let (backing_gt_sector, backing_gd_bytes, backing_gt_bytes) =
        install_empty_gt(&mut backing_bytes, &backing_header);
    let overlay_descriptor = descriptor_bytes(&overlay_bytes, &overlay_header).to_vec();
    let backing_descriptor = descriptor_bytes(&backing_bytes, &backing_header).to_vec();
    let overlay_num_gd_entries = overlay_header.num_gd_entries().expect("num_gd_entries");
    let backing_num_gd_entries = backing_header.num_gd_entries().expect("num_gd_entries");
    let overlay_gt_hosts = vec![overlay_gt_sector];
    let backing_gt_hosts = vec![backing_gt_sector];

    let opts = VmdkCommitOpts {
        overlay_header: &overlay_bytes[..512],
        overlay_descriptor: &overlay_descriptor,
        overlay_grain_size_sectors: GRAIN_SIZE_SECTORS,
        overlay_num_gtes_per_gt: GTES_PER_GT,
        overlay_num_gd_entries,
        overlay_gd_offset_sectors: overlay_header.gd_offset_sectors,
        overlay_grain_directory: &overlay_gd_bytes,
        overlay_grain_tables: &overlay_gt_bytes,
        overlay_allocated_gt_host_sectors: &overlay_gt_hosts,
        overlay_allocated_gt_count: 1,
        overlay_virtual_size: VIRTUAL_SIZE,
        overlay_file_size: overlay_bytes.len() as u64,
        backing_header: &backing_bytes[..512],
        backing_descriptor: &backing_descriptor,
        backing_grain_size_sectors: GRAIN_SIZE_SECTORS,
        backing_num_gtes_per_gt: GTES_PER_GT,
        backing_num_gd_entries,
        backing_gd_offset_sectors: backing_header.gd_offset_sectors,
        backing_grain_directory: &backing_gd_bytes,
        backing_grain_tables: &backing_gt_bytes,
        backing_allocated_gt_host_sectors: &backing_gt_hosts,
        backing_allocated_gt_count: 1,
        backing_virtual_size: VIRTUAL_SIZE / 2,
        backing_file_size: backing_bytes.len() as u64,
    };
    let mut scratch = vec![0u8; 256 * 1024];
    let err = plan_commit_vmdk(&opts, &mut scratch).expect_err("expected rejection");
    assert_eq!(err, CommitError::OverlayLargerThanBacking);
}
