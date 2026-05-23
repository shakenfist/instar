//! End-to-end integration tests for the VMDK monolithicSparse
//! grow planner.
//!
//! Each test builds a starting VMDK via `crates/create::plan_vmdk`,
//! populates `VmdkResizeOpts` from the parsed header / descriptor /
//! GD, calls `plan_resize_vmdk`, applies the patches, and re-parses
//! to verify the post-resize state.

use create::{plan_vmdk, MetadataPlan, VmdkCreateOpts};
use resize::{
    plan_resize_vmdk, Preallocation, ResizeAction, ResizeError, ResizePatch, ResizePlan,
    VmdkResizeOpts, VmdkSubformat, QCOW2_MAX_RESIZE_SCRATCH,
};
use shared::{le_u64, VmdkInfo};
use vmdk::{parse_descriptor, parse_descriptor_extents, Vmdk4HeaderFull};

const VMDK_SCRATCH: usize = QCOW2_MAX_RESIZE_SCRATCH;

// ---------------------------------------------------------------------------
// Helpers
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

fn apply_resize(file: &mut Vec<u8>, plan: &ResizePlan<'_>) {
    if file.len() < plan.total_file_size as usize {
        file.resize(plan.total_file_size as usize, 0);
    }
    for patch in plan.patches() {
        match patch {
            ResizePatch::Write { byte_offset, bytes }
            | ResizePatch::Append { byte_offset, bytes } => {
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

fn build_starting_vmdk(virtual_size: u64, grain_size: u32) -> Vec<u8> {
    let opts = VmdkCreateOpts {
        virtual_size,
        subformat: create::VmdkSubformat::MonolithicSparse,
        grain_size,
        backing: None,
        parent_cid: None,
    };
    let mut scratch = vec![0u8; create::VMDK_MAX_METADATA_SCRATCH];
    let plan = plan_vmdk(&opts, &mut scratch).expect("create vmdk plan");
    materialise_create(&plan)
}

/// Populate `VmdkResizeOpts` from a starting image.
fn opts_from_image<'a>(
    bytes: &'a [u8],
    new_virtual_size: u64,
    allow_shrink: bool,
) -> VmdkResizeOpts<'a> {
    let header = Vmdk4HeaderFull::parse(&bytes[..512]).expect("parse header");

    let desc_off = (header.desc_offset_sectors * 512) as usize;
    let desc_len = (header.desc_size_sectors * 512) as usize;
    let existing_descriptor = &bytes[desc_off..desc_off + desc_len];

    let grain_size_bytes = (header.grain_size_sectors * 512) as u32;
    let num_gtes_per_gt = header.num_gtes_per_gt;
    let sectors_per_gt = (num_gtes_per_gt as u64) * header.grain_size_sectors;
    let num_gd_entries = header.capacity_sectors.div_ceil(sectors_per_gt) as u32;
    let gd_off = (header.gd_offset_sectors * 512) as usize;
    let gd_bytes = (num_gd_entries as usize) * 4;
    let gd_sectors = (gd_bytes.div_ceil(512)) as u32;
    let existing_gd = &bytes[gd_off..gd_off + gd_bytes.min(bytes.len() - gd_off)];

    VmdkResizeOpts {
        current_virtual_size: header.capacity_sectors * 512,
        new_virtual_size,
        grain_size: grain_size_bytes,
        subformat: VmdkSubformat::MonolithicSparse,
        allow_shrink,
        preallocation: Preallocation::Off,
        existing_header: &bytes[..512],
        existing_descriptor,
        existing_gd,
        current_num_gd_entries: num_gd_entries,
        current_gd_sectors: gd_sectors,
        current_file_size: bytes.len() as u64,
    }
}

/// Parse the post-resize file: return (header.capacity_sectors,
/// extent-line size_sectors, cid, parent_cid, filename).
fn read_post_resize<'a>(bytes: &'a [u8]) -> (u64, u64, u32, u32, String) {
    let header = Vmdk4HeaderFull::parse(&bytes[..512]).expect("re-parse header");

    let desc_off = (header.desc_offset_sectors * 512) as usize;
    let desc_len = (header.desc_size_sectors * 512) as usize;
    let desc = &bytes[desc_off..desc_off + desc_len];

    let mut info = VmdkInfo::new();
    parse_descriptor(desc, desc.len(), &mut info);

    let end = desc.iter().position(|&b| b == 0).unwrap_or(desc.len());
    let text = core::str::from_utf8(&desc[..end]).expect("descriptor utf8");
    let extents = parse_descriptor_extents(text).expect("extents");
    let first = extents.get(0).unwrap();
    let filename = first.filename.to_owned();

    (
        header.capacity_sectors,
        first.size_sectors,
        info.cid,
        info.parent_cid,
        filename,
    )
}

// ---------------------------------------------------------------------------
// Positive paths
// ---------------------------------------------------------------------------

#[test]
fn metadata_only_grow_when_gd_has_slack() {
    // 1 GiB → 4 GiB at default 64 KiB grain. num_gtes_per_gt =
    // 512, grain_size_sectors = 128 → one GT covers 32 MiB,
    // so num_gd_entries = 128 for 4 GiB; 1 GD sector holds
    // 128 entries → MetadataOnly fires.
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let opts = opts_from_image(&bytes, 4u64 << 30, false);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    let plan = plan_resize_vmdk(&opts, &mut scratch).expect("plan");
    assert_eq!(plan.action, ResizeAction::Grow);
    // 2 patches: descriptor + header capacity.
    assert_eq!(plan.patches().len(), 2);

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);
    let (cap, ext_size, _cid, _pcid, _name) = read_post_resize(&file);
    assert_eq!(cap, (4u64 << 30) / 512);
    assert_eq!(ext_size, cap);
}

#[test]
fn gd_grow_relocate_when_entries_exceed_slack() {
    // Smaller grain pushes the GD entries past the 1-sector
    // ceiling.  grain=4 KiB, num_gtes_per_gt=512 → sectors_per_gt
    // = 512 * 8 = 4096 (2 MiB virtual coverage per GT).  A
    // 128 MiB image needs 64 GD entries — fits in 1 sector
    // (128 entries / sector).  Grow to 4 GiB needs 2048 entries
    // = 16 sectors → relocate.
    let bytes = build_starting_vmdk(128 << 20, 4096);
    let starting_size = bytes.len();
    let opts = opts_from_image(&bytes, 4u64 << 30, false);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    let plan = plan_resize_vmdk(&opts, &mut scratch).expect("plan");
    assert_eq!(plan.action, ResizeAction::Grow);
    assert!(
        plan.total_file_size > starting_size as u64,
        "relocate should grow the file"
    );
    // First patch must be the new-GD Append.
    assert!(matches!(plan.patches()[0], ResizePatch::Append { .. }));

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);
    let (cap, _, _, _, _) = read_post_resize(&file);
    assert_eq!(cap, (4u64 << 30) / 512);
}

#[test]
fn noop_when_sizes_equal() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let opts = opts_from_image(&bytes, 1u64 << 30, false);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    let plan = plan_resize_vmdk(&opts, &mut scratch).expect("plan");
    assert_eq!(plan.action, ResizeAction::NoOp);
    assert_eq!(plan.patches().len(), 0);
}

#[test]
fn metadata_only_preserves_cid_and_parent_cid() {
    // Read the starting CID / parentCID so we can verify they
    // survive the resize.
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let (_, _, starting_cid, starting_pcid, _) = read_post_resize(&bytes);

    let opts = opts_from_image(&bytes, 2u64 << 30, false);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    let plan = plan_resize_vmdk(&opts, &mut scratch).expect("plan");

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);
    let (_, _, post_cid, post_pcid, _) = read_post_resize(&file);
    assert_eq!(post_cid, starting_cid, "CID should survive resize");
    assert_eq!(post_pcid, starting_pcid, "parentCID should survive resize");
}

#[test]
fn metadata_only_preserves_filename() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let (_, _, _, _, starting_name) = read_post_resize(&bytes);

    let opts = opts_from_image(&bytes, 2u64 << 30, false);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    let plan = plan_resize_vmdk(&opts, &mut scratch).expect("plan");

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);
    let (_, _, _, _, post_name) = read_post_resize(&file);
    assert_eq!(post_name, starting_name);
}

#[test]
fn header_capacity_field_updated() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let opts = opts_from_image(&bytes, 8u64 << 30, false);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    let plan = plan_resize_vmdk(&opts, &mut scratch).expect("plan");

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);

    // Direct read of the binary capacity field.
    let cap = le_u64(&file, 12);
    assert_eq!(cap, (8u64 << 30) / 512);
}

// ---------------------------------------------------------------------------
// Crash-safety ordering
// ---------------------------------------------------------------------------

#[test]
fn header_capacity_write_is_last_for_metadata_only() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let opts = opts_from_image(&bytes, 2u64 << 30, false);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    let plan = plan_resize_vmdk(&opts, &mut scratch).expect("plan");

    // The 8-byte Write at offset 12 (capacity) must be the
    // LAST patch — VMDK's atomic-commit point.
    let n = plan.patches().len();
    if let ResizePatch::Write { byte_offset, .. } = plan.patches()[n - 1] {
        assert_eq!(byte_offset, 12);
    } else {
        panic!("last patch must be a Write");
    }
}

// ---------------------------------------------------------------------------
// Negative paths
// ---------------------------------------------------------------------------

#[test]
fn rejects_shrink_without_flag() {
    let bytes = build_starting_vmdk(2u64 << 30, 65536);
    let opts = opts_from_image(&bytes, 1u64 << 30, false);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    assert_eq!(
        plan_resize_vmdk(&opts, &mut scratch).unwrap_err(),
        ResizeError::ShrinkWithoutFlag
    );
}

#[test]
fn rejects_shrink_with_flag() {
    let bytes = build_starting_vmdk(2u64 << 30, 65536);
    let opts = opts_from_image(&bytes, 1u64 << 30, true);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    assert_eq!(
        plan_resize_vmdk(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedShrink
    );
}

#[test]
fn rejects_stream_optimized_subformat() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.subformat = VmdkSubformat::StreamOptimized;
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    assert_eq!(
        plan_resize_vmdk(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedSubformat
    );
}

#[test]
fn rejects_monolithic_flat_subformat() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.subformat = VmdkSubformat::MonolithicFlat;
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    assert_eq!(
        plan_resize_vmdk(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedSubformat
    );
}

#[test]
fn rejects_two_gb_max_extent_subformats() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    opts.subformat = VmdkSubformat::TwoGbMaxExtentSparse;
    assert_eq!(
        plan_resize_vmdk(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedSubformat
    );
    opts.subformat = VmdkSubformat::TwoGbMaxExtentFlat;
    assert_eq!(
        plan_resize_vmdk(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedSubformat
    );
}

#[test]
fn rejects_zero_new_virtual_size() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let opts = opts_from_image(&bytes, 0, false);
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    assert_eq!(
        plan_resize_vmdk(&opts, &mut scratch).unwrap_err(),
        ResizeError::InvalidNewVirtualSize
    );
}

#[test]
fn rejects_preallocation_metadata() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.preallocation = Preallocation::Metadata;
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    assert_eq!(
        plan_resize_vmdk(&opts, &mut scratch).unwrap_err(),
        ResizeError::PreallocationUnsupported
    );
}

#[test]
fn rejects_invalid_grain_size() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.grain_size = 5000; // not power-of-two, out of range
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    assert_eq!(
        plan_resize_vmdk(&opts, &mut scratch).unwrap_err(),
        ResizeError::InvalidNewVirtualSize
    );
}

#[test]
fn rejects_invalid_existing_header() {
    let bytes = build_starting_vmdk(1u64 << 30, 65536);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    // Truncate the header — planner needs at least 512 bytes.
    opts.existing_header = &[];
    let mut scratch = vec![0u8; VMDK_SCRATCH];
    assert_eq!(
        plan_resize_vmdk(&opts, &mut scratch).unwrap_err(),
        ResizeError::ParseFailed
    );
}
