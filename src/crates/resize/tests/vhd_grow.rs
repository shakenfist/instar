//! End-to-end integration tests for the VHD grow planner.
//!
//! Each test builds a starting VHD via `crates/create::plan_vhd`,
//! populates `VhdResizeOpts` from the parsed footer / dynamic
//! header / BAT, calls `plan_resize_vhd`, applies the patches,
//! and re-parses the result to verify the post-resize geometry.

use create::{plan_vhd, MetadataPlan, VhdCreateOpts};
use resize::{
    plan_resize_vhd, Preallocation, ResizeAction, ResizeError, ResizePatch, ResizePlan,
    VhdResizeOpts, VhdSubformat, QCOW2_MAX_RESIZE_SCRATCH,
};
use shared::write_be_u32;
use vhd::{
    VhdDynamicHeader, VhdFooter, DISK_TYPE_DIFFERENCING, DISK_TYPE_DYNAMIC, DISK_TYPE_FIXED,
    FOOTER_SIZE,
};

// Use a vhd-specific scratch since the planner's worst case is
// dominated by the BAT region; QCOW2_MAX_RESIZE_SCRATCH (32 MiB)
// is comfortable but VHD's bound is much smaller — see
// VHD_MAX_RESIZE_SCRATCH in the resize crate.
const VHD_SCRATCH: usize = QCOW2_MAX_RESIZE_SCRATCH;

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

/// Build a starting VHD image (fixed or dynamic) at the given
/// virtual size and block size.
fn build_starting_vhd(
    virtual_size: u64,
    subformat: create::VhdSubformat,
    block_size: u32,
) -> Vec<u8> {
    let opts = VhdCreateOpts {
        virtual_size,
        subformat,
        block_size,
        backing: None,
    };
    let mut scratch = vec![0u8; create::VHD_MAX_METADATA_SCRATCH];
    let plan = plan_vhd(&opts, &mut scratch).expect("create vhd plan");
    let mut bytes = materialise_create(&plan);
    // For fixed VHDs the data region between header bytes and
    // the tail footer is implicit — extend the buffer so the
    // tail footer ends up at virtual_size + 512.
    if matches!(subformat, create::VhdSubformat::Fixed) {
        // Fixed plan emits the footer at plan.minimum_file_size
        // - 512 already; the buffer is sized to fit it.
        bytes.resize(plan.minimum_file_size as usize, 0);
    }
    bytes
}

/// Build `VhdResizeOpts` from a starting image. For the dynamic
/// subformat, parses the dynamic header and BAT out of the
/// bytes; for fixed, leaves those fields as `&[]`.
fn opts_from_image<'a>(
    bytes: &'a [u8],
    subformat: VhdSubformat,
    new_virtual_size: u64,
    allow_shrink: bool,
) -> VhdResizeOpts<'a> {
    let footer_off = bytes.len() - FOOTER_SIZE;
    let footer = VhdFooter::parse(&bytes[footer_off..]).expect("parse tail footer");
    // For dynamic VHDs the head footer at offset 0 is what we
    // actually want to read; verify it matches.
    let (
        existing_footer,
        existing_dyn,
        existing_bat,
        current_table_offset,
        current_max_entries,
        block_size,
    ) = match subformat {
        VhdSubformat::Fixed => (
            &bytes[footer_off..footer_off + FOOTER_SIZE],
            &bytes[..0],
            &bytes[..0],
            0u64,
            0u32,
            0u32,
        ),
        VhdSubformat::Dynamic => {
            let head_footer = &bytes[..FOOTER_SIZE];
            let dyn_hdr_bytes = &bytes[FOOTER_SIZE..FOOTER_SIZE + 1024];
            let dyn_hdr = VhdDynamicHeader::parse(dyn_hdr_bytes).expect("parse dyn hdr");
            let bat_off = dyn_hdr.table_offset as usize;
            let bat_len = (dyn_hdr.max_table_entries as usize) * 4;
            let bat_aligned = bat_len.next_multiple_of(512);
            let bat = &bytes[bat_off..bat_off + bat_aligned.min(bytes.len() - bat_off)];
            (
                head_footer,
                dyn_hdr_bytes,
                bat,
                dyn_hdr.table_offset,
                dyn_hdr.max_table_entries,
                dyn_hdr.block_size,
            )
        }
    };

    VhdResizeOpts {
        current_virtual_size: footer.current_size,
        new_virtual_size,
        block_size,
        subformat,
        allow_shrink,
        preallocation: Preallocation::Off,
        existing_footer,
        existing_dynamic_header: existing_dyn,
        existing_bat,
        current_file_size: bytes.len() as u64,
        disk_type: footer.disk_type,
        current_table_offset,
        current_max_table_entries: current_max_entries,
    }
}

// ---------------------------------------------------------------------------
// Positive paths
// ---------------------------------------------------------------------------

#[test]
fn fixed_grow_small() {
    let bytes = build_starting_vhd(16 << 20, create::VhdSubformat::Fixed, 0);
    let starting_size = bytes.len();
    let opts = opts_from_image(&bytes, VhdSubformat::Fixed, 64 << 20, false);
    let mut scratch = vec![0u8; VHD_SCRATCH];
    let plan = plan_resize_vhd(&opts, &mut scratch).expect("resize plan");

    assert_eq!(plan.action, ResizeAction::Grow);
    assert_eq!(plan.total_file_size, (64u64 << 20) + 512);
    assert_eq!(plan.patches().len(), 2);

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);
    let new_footer = VhdFooter::parse(&file[file.len() - FOOTER_SIZE..]).expect("re-parse");
    assert_eq!(new_footer.current_size, 64 << 20);
    assert_eq!(new_footer.disk_type, DISK_TYPE_FIXED);

    // The OLD footer position should now be zeroed in the data
    // region. The OLD position was (starting_size - 512).
    let old_footer_pos = starting_size - 512;
    assert_eq!(
        &file[old_footer_pos..old_footer_pos + 512],
        &[0u8; 512],
        "old footer should be zeroed"
    );
}

#[test]
fn fixed_grow_preserves_uuid() {
    let bytes = build_starting_vhd(16 << 20, create::VhdSubformat::Fixed, 0);
    let starting_footer = VhdFooter::parse(&bytes[bytes.len() - FOOTER_SIZE..]).unwrap();
    let starting_uuid = starting_footer.uuid;

    let opts = opts_from_image(&bytes, VhdSubformat::Fixed, 64 << 20, false);
    let mut scratch = vec![0u8; VHD_SCRATCH];
    let plan = plan_resize_vhd(&opts, &mut scratch).expect("plan");

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);
    let new_footer = VhdFooter::parse(&file[file.len() - FOOTER_SIZE..]).unwrap();
    assert_eq!(new_footer.uuid, starting_uuid);
}

#[test]
fn dynamic_grow_with_no_blocks_allocated() {
    // A freshly-created dynamic VHD has no slack between the
    // BAT and the tail footer, so this grow naturally takes the
    // Relocate path even with zero allocated blocks. The
    // resulting image is still parseable and reports the new
    // geometry. (In-place coverage requires forging an image
    // with explicit BAT padding — see open question 4 in the
    // phase plan.)
    let bytes = build_starting_vhd(1u64 << 30, create::VhdSubformat::Dynamic, 2 * 1024 * 1024);
    let opts = opts_from_image(&bytes, VhdSubformat::Dynamic, 2u64 << 30, false);
    let mut scratch = vec![0u8; VHD_SCRATCH];
    let plan = plan_resize_vhd(&opts, &mut scratch).expect("plan");

    assert_eq!(plan.action, ResizeAction::Grow);

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);

    let head_footer = VhdFooter::parse(&file[..FOOTER_SIZE]).expect("head footer");
    assert_eq!(head_footer.current_size, 2u64 << 30);
    assert_eq!(head_footer.disk_type, DISK_TYPE_DYNAMIC);

    let dyn_hdr = VhdDynamicHeader::parse(&file[FOOTER_SIZE..FOOTER_SIZE + 1024]).expect("dyn hdr");
    assert_eq!(dyn_hdr.max_table_entries, 1024); // 2 GiB / 2 MiB

    let tail_footer = VhdFooter::parse(&file[file.len() - FOOTER_SIZE..]).expect("tail footer");
    assert_eq!(tail_footer.current_size, 2u64 << 30);
}

#[test]
fn dynamic_grow_relocate_when_blocks_block_the_bat() {
    let mut bytes = build_starting_vhd(16 << 20, create::VhdSubformat::Dynamic, 2 * 1024 * 1024);
    // Forge an allocated block: take the first BAT entry's
    // slot and set it to a low sector number so the BAT
    // extension will collide with it. We need to write a real
    // block bitmap and payload too, otherwise the parser would
    // detect inconsistency — but for the planner test, just
    // the BAT entry is enough.
    let dyn_hdr =
        VhdDynamicHeader::parse(&bytes[FOOTER_SIZE..FOOTER_SIZE + 1024]).expect("dyn hdr");
    let bat_off = dyn_hdr.table_offset as usize;
    // Point BAT[0] at sector 4 (offset 2048 = 4 * 512) — well
    // below where the extended BAT would land. The new
    // virtual size of 1 GiB needs 512 entries (2048 bytes BAT)
    // so the BAT extension lands at table_offset + 2048; our
    // forged block at offset 2048 is right above that, forcing
    // relocate.
    write_be_u32(&mut bytes, bat_off, 4);

    let opts = opts_from_image(&bytes, VhdSubformat::Dynamic, 1u64 << 30, false);
    let mut scratch = vec![0u8; VHD_SCRATCH];
    let plan = plan_resize_vhd(&opts, &mut scratch).expect("plan");

    assert_eq!(plan.action, ResizeAction::Grow);
    // Relocate: file size grew by new BAT size + 0 (tail
    // footer moves but counts once).
    assert!(
        plan.total_file_size > bytes.len() as u64,
        "relocate should grow the file"
    );

    // First patch should be an Append (the new BAT region).
    assert!(matches!(plan.patches()[0], ResizePatch::Append { .. }));
}

#[test]
fn noop_when_sizes_equal() {
    let bytes = build_starting_vhd(16 << 20, create::VhdSubformat::Fixed, 0);
    let opts = opts_from_image(&bytes, VhdSubformat::Fixed, 16 << 20, false);
    let mut scratch = vec![0u8; VHD_SCRATCH];
    let plan = plan_resize_vhd(&opts, &mut scratch).expect("plan");
    assert_eq!(plan.action, ResizeAction::NoOp);
    assert_eq!(plan.patches().len(), 0);
}

// ---------------------------------------------------------------------------
// Crash-safety ordering
// ---------------------------------------------------------------------------

#[test]
fn dynamic_grow_in_place_head_footer_is_last_patch() {
    let bytes = build_starting_vhd(1u64 << 30, create::VhdSubformat::Dynamic, 2 * 1024 * 1024);
    let opts = opts_from_image(&bytes, VhdSubformat::Dynamic, 2u64 << 30, false);
    let mut scratch = vec![0u8; VHD_SCRATCH];
    let plan = plan_resize_vhd(&opts, &mut scratch).expect("plan");

    // The head footer Write at offset 0 should be the LAST patch.
    let head_idx = plan
        .patches()
        .iter()
        .position(|p| matches!(p, ResizePatch::Write { byte_offset: 0, .. }))
        .expect("head footer rewrite present");
    assert_eq!(
        head_idx,
        plan.patches().len() - 1,
        "head footer rewrite must be the last patch (atomic commit)"
    );
}

// ---------------------------------------------------------------------------
// Negative paths
// ---------------------------------------------------------------------------

#[test]
fn rejects_shrink_without_flag() {
    let bytes = build_starting_vhd(64 << 20, create::VhdSubformat::Fixed, 0);
    let opts = opts_from_image(&bytes, VhdSubformat::Fixed, 32 << 20, false);
    let mut scratch = vec![0u8; VHD_SCRATCH];
    assert_eq!(
        plan_resize_vhd(&opts, &mut scratch).unwrap_err(),
        ResizeError::ShrinkWithoutFlag
    );
}

#[test]
fn rejects_shrink_with_flag_pending_future_work() {
    let bytes = build_starting_vhd(64 << 20, create::VhdSubformat::Fixed, 0);
    let opts = opts_from_image(&bytes, VhdSubformat::Fixed, 32 << 20, true);
    let mut scratch = vec![0u8; VHD_SCRATCH];
    assert_eq!(
        plan_resize_vhd(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedShrink
    );
}

#[test]
fn rejects_differencing_subformat() {
    let bytes = build_starting_vhd(16 << 20, create::VhdSubformat::Fixed, 0);
    let mut opts = opts_from_image(&bytes, VhdSubformat::Fixed, 32 << 20, false);
    opts.disk_type = DISK_TYPE_DIFFERENCING;
    let mut scratch = vec![0u8; VHD_SCRATCH];
    assert_eq!(
        plan_resize_vhd(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedSubformat
    );
}

#[test]
fn rejects_zero_new_virtual_size() {
    let bytes = build_starting_vhd(16 << 20, create::VhdSubformat::Fixed, 0);
    let opts = opts_from_image(&bytes, VhdSubformat::Fixed, 0, false);
    let mut scratch = vec![0u8; VHD_SCRATCH];
    assert_eq!(
        plan_resize_vhd(&opts, &mut scratch).unwrap_err(),
        ResizeError::InvalidNewVirtualSize
    );
}

#[test]
fn rejects_preallocation_metadata() {
    let bytes = build_starting_vhd(16 << 20, create::VhdSubformat::Fixed, 0);
    let mut opts = opts_from_image(&bytes, VhdSubformat::Fixed, 32 << 20, false);
    opts.preallocation = Preallocation::Metadata;
    let mut scratch = vec![0u8; VHD_SCRATCH];
    assert_eq!(
        plan_resize_vhd(&opts, &mut scratch).unwrap_err(),
        ResizeError::PreallocationUnsupported
    );
}
