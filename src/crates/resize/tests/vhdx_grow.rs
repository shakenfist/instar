//! End-to-end integration tests for the VHDX grow planner.
//!
//! Each test builds a starting VHDX via `crates/create::plan_vhdx`,
//! populates `VhdxResizeOpts` from the parsed headers / region
//! table / metadata / BAT, calls `plan_resize_vhdx`, applies the
//! patches, and re-parses the result to verify the post-resize
//! state.

use create::{plan_vhdx, MetadataPlan, VhdxCreateOpts};
use resize::{
    plan_resize_vhdx, Preallocation, ResizeAction, ResizeError, ResizePatch, ResizePlan,
    VhdxResizeOpts, QCOW2_MAX_RESIZE_SCRATCH,
};
use shared::{le_u32, le_u64, write_le_u32, write_le_u64};
use vhdx::{
    parse_metadata_region, parse_region_table, VhdxHeader, HEADER1_OFFSET, HEADER2_OFFSET,
    REGION_TABLE1_OFFSET,
};

const VHDX_SCRATCH: usize = QCOW2_MAX_RESIZE_SCRATCH;

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

fn build_starting_vhdx(virtual_size: u64, block_size: u32) -> Vec<u8> {
    let opts = VhdxCreateOpts {
        virtual_size,
        block_size,
        backing: None,
        parent_data_write_guid: [0u8; 16],
    };
    let mut scratch = vec![0u8; create::VHDX_MAX_METADATA_SCRATCH];
    let plan = plan_vhdx(&opts, &mut scratch).expect("create vhdx plan");
    materialise_create(&plan)
}

/// Inspect a starting VHDX and produce a populated
/// `VhdxResizeOpts` pointing at the correct regions.
fn opts_from_image<'a>(
    bytes: &'a [u8],
    new_virtual_size: u64,
    allow_shrink: bool,
) -> VhdxResizeOpts<'a> {
    let header1 = VhdxHeader::parse(&bytes[HEADER1_OFFSET as usize..]).expect("header 1");
    let header2 = VhdxHeader::parse(&bytes[HEADER2_OFFSET as usize..]).expect("header 2");
    let (active_offset, active_header) = if header1.sequence_number >= header2.sequence_number {
        (HEADER1_OFFSET, header1)
    } else {
        (HEADER2_OFFSET, header2)
    };
    let existing_active_header = &bytes[active_offset as usize..active_offset as usize + 4096];

    let region_table_bytes = &bytes[REGION_TABLE1_OFFSET as usize..];
    let (entries, _count) = parse_region_table(region_table_bytes).expect("region table");

    // Entries[0] = BAT, Entries[1] = Metadata per parse_region_table's ordering.
    let bat_entry = &entries[0];
    let metadata_entry = &entries[1];

    let existing_bat = &bytes[bat_entry.file_offset as usize
        ..bat_entry.file_offset as usize + bat_entry.length as usize];

    // For the resize crate's test purposes, derive the current
    // total_bat_entries from the BAT region's byte length:
    // each entry is 8 bytes.
    let current_total_bat_entries = (bat_entry.length / 8) as u32;

    let metadata = parse_metadata_region(
        &bytes[metadata_entry.file_offset as usize
            ..metadata_entry.file_offset as usize + metadata_entry.length as usize],
    )
    .expect("metadata region");

    VhdxResizeOpts {
        current_virtual_size: metadata.virtual_disk_size,
        new_virtual_size,
        block_size: metadata.block_size,
        preallocation: Preallocation::Off,
        allow_shrink,
        existing_active_header,
        current_active_header_offset: active_offset,
        current_sequence_number: active_header.sequence_number,
        existing_region_table: &bytes
            [REGION_TABLE1_OFFSET as usize..REGION_TABLE1_OFFSET as usize + 64 * 1024],
        existing_bat,
        current_bat_offset: bat_entry.file_offset,
        current_bat_length: bat_entry.length,
        current_total_bat_entries,
        current_metadata_offset: metadata_entry.file_offset,
        current_metadata_length: metadata_entry.length,
        virtual_disk_size_item_offset: metadata.virtual_disk_size_offset,
        logical_sector_size: metadata.logical_sector_size,
        physical_sector_size: metadata.physical_sector_size,
        has_parent: metadata.has_parent,
        current_file_size: bytes.len() as u64,
    }
}

// ---------------------------------------------------------------------------
// Positive paths
// ---------------------------------------------------------------------------

#[test]
fn metadata_only_grow_when_bat_fits() {
    // 1 GiB → 2 GiB at default 32 MiB block_size. The default
    // BAT region (1 MiB) holds many more entries than needed
    // for 2 GiB, so MetadataAndHeaders fires.
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let opts = opts_from_image(&bytes, 2u64 << 30, false);
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    let plan = plan_resize_vhdx(&opts, &mut scratch).expect("plan");
    assert_eq!(plan.action, ResizeAction::Grow);

    // Three patches: VDS + inactive header + active header.
    assert_eq!(plan.patches().len(), 3);

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);

    // Re-parse both headers.
    let header1 = VhdxHeader::parse(&file[HEADER1_OFFSET as usize..]).expect("header 1");
    let header2 = VhdxHeader::parse(&file[HEADER2_OFFSET as usize..]).expect("header 2");
    let max_seq = header1.sequence_number.max(header2.sequence_number);

    // Both headers should be > the original max (which was 2).
    assert!(max_seq > 2);

    // VirtualDiskSize updated.
    let region_table = parse_region_table(&file[REGION_TABLE1_OFFSET as usize..]).expect("rt");
    let metadata = &region_table.0[1];
    let metadata_bytes = &file
        [metadata.file_offset as usize..metadata.file_offset as usize + metadata.length as usize];
    let post = parse_metadata_region(metadata_bytes).expect("metadata");
    assert_eq!(post.virtual_disk_size, 2u64 << 30);
}

/// The metadata region of an image, as a mutable slice.
fn metadata_region_mut(bytes: &mut [u8]) -> &mut [u8] {
    let (entries, _count) =
        parse_region_table(&bytes[REGION_TABLE1_OFFSET as usize..]).expect("region table");
    let start = entries[1].file_offset as usize;
    let end = start + entries[1].length as usize;
    &mut bytes[start..end]
}

/// Metadata table entry 1 is Virtual Disk Size in the layout
/// `vhdx::build_metadata` writes.
const VDS_TABLE_ENTRY: usize = 32 + 32;

#[test]
fn writes_virtual_disk_size_where_the_metadata_table_puts_it() {
    // SPEC(VHDX) fixes no position for metadata items. Move the
    // Virtual Disk Size item and leave a decoy at the offset instar's
    // own writer uses: resize must follow the table to the real one
    // and leave the decoy alone.
    let mut bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let region = metadata_region_mut(&mut bytes);
    write_le_u32(region, VDS_TABLE_ENTRY + 16, 0x10100);
    write_le_u64(region, 0x10100, 1u64 << 30);
    write_le_u64(region, 0x10008, 0xdead_beef);

    let opts = opts_from_image(&bytes, 2u64 << 30, false);
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    let plan = plan_resize_vhdx(&opts, &mut scratch).expect("plan");
    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);

    let region = metadata_region_mut(&mut file);
    assert_eq!(le_u64(region, 0x10100), 2u64 << 30);
    assert_eq!(le_u64(region, 0x10008), 0xdead_beef);
}

#[test]
fn rejects_virtual_disk_size_item_outside_the_metadata_region() {
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.virtual_disk_size_item_offset = opts.current_metadata_length - 4;
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    assert_eq!(
        plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
        ResizeError::HeaderMismatch
    );
}

#[test]
fn noop_when_sizes_equal() {
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let opts = opts_from_image(&bytes, 1u64 << 30, false);
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    let plan = plan_resize_vhdx(&opts, &mut scratch).expect("plan");
    assert_eq!(plan.action, ResizeAction::NoOp);
    assert_eq!(plan.patches().len(), 0);
}

#[test]
fn header_sequence_numbers_bump_correctly() {
    // Pre-resize: header1 seq=1, header2 seq=2 (per plan_vhdx).
    // After resize: inactive (header1) should be seq=3,
    // formerly-active (header2) should be seq=4.
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let opts = opts_from_image(&bytes, 2u64 << 30, false);
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    let plan = plan_resize_vhdx(&opts, &mut scratch).expect("plan");

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);

    let header1 = VhdxHeader::parse(&file[HEADER1_OFFSET as usize..]).expect("h1");
    let header2 = VhdxHeader::parse(&file[HEADER2_OFFSET as usize..]).expect("h2");
    // The new active header is whichever has the higher seq;
    // both must be higher than 2 (the original max).
    assert!(header1.sequence_number > 2);
    assert!(header2.sequence_number > 2);
    // They differ by 1 (one is +1, one is +2 from the original).
    let diff = header1.sequence_number.abs_diff(header2.sequence_number);
    assert_eq!(diff, 1);
}

#[test]
fn header_log_guid_stays_zero() {
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let opts = opts_from_image(&bytes, 2u64 << 30, false);
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    let plan = plan_resize_vhdx(&opts, &mut scratch).expect("plan");

    let mut file = bytes.clone();
    apply_resize(&mut file, &plan);

    let header1 = VhdxHeader::parse(&file[HEADER1_OFFSET as usize..]).expect("h1");
    let header2 = VhdxHeader::parse(&file[HEADER2_OFFSET as usize..]).expect("h2");
    assert_eq!(header1.log_guid, [0u8; 16]);
    assert_eq!(header2.log_guid, [0u8; 16]);
}

// ---------------------------------------------------------------------------
// Crash-safety ordering
// ---------------------------------------------------------------------------

#[test]
fn header_commit_then_redundancy_order() {
    // The two header writes must be the LAST two patches, in
    // the order: inactive (commit) → active (redundancy).
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let opts = opts_from_image(&bytes, 2u64 << 30, false);
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    let plan = plan_resize_vhdx(&opts, &mut scratch).expect("plan");

    let patches = plan.patches();
    let n = patches.len();
    // Last patch is a Write at the active header's offset.
    if let ResizePatch::Write { byte_offset, .. } = patches[n - 1] {
        assert_eq!(byte_offset, opts.current_active_header_offset);
    } else {
        panic!("last patch must be a Write");
    }
    // Second-to-last is the inactive header.
    let inactive_offset = if opts.current_active_header_offset == HEADER1_OFFSET {
        HEADER2_OFFSET
    } else {
        HEADER1_OFFSET
    };
    if let ResizePatch::Write { byte_offset, .. } = patches[n - 2] {
        assert_eq!(byte_offset, inactive_offset);
    } else {
        panic!("second-to-last patch must be a Write");
    }
}

// ---------------------------------------------------------------------------
// Negative paths
// ---------------------------------------------------------------------------

#[test]
fn rejects_shrink_without_flag() {
    let bytes = build_starting_vhdx(2u64 << 30, 32 * 1024 * 1024);
    let opts = opts_from_image(&bytes, 1u64 << 30, false);
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    assert_eq!(
        plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
        ResizeError::ShrinkWithoutFlag
    );
}

#[test]
fn rejects_shrink_with_flag() {
    let bytes = build_starting_vhdx(2u64 << 30, 32 * 1024 * 1024);
    let opts = opts_from_image(&bytes, 1u64 << 30, true);
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    assert_eq!(
        plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedShrink
    );
}

#[test]
fn rejects_differencing_image() {
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.has_parent = true;
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    assert_eq!(
        plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedSubformat
    );
}

#[test]
fn rejects_an_image_whose_metadata_says_it_has_a_parent() {
    // Unlike `rejects_differencing_image`, which sets the option
    // directly, this sets the File Parameters HasParent bit in the
    // image and lets the metadata parser carry it to the planner.
    let mut bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let region = metadata_region_mut(&mut bytes);
    // File Parameters is item 0 at 0x10000; flags follow block size.
    let flags = le_u32(region, 0x10004);
    write_le_u32(region, 0x10004, flags | 2);

    let opts = opts_from_image(&bytes, 2u64 << 30, false);
    assert!(opts.has_parent);
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    assert_eq!(
        plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedSubformat
    );
}

#[test]
fn rejects_zero_new_virtual_size() {
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let opts = opts_from_image(&bytes, 0, false);
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    assert_eq!(
        plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
        ResizeError::InvalidNewVirtualSize
    );
}

#[test]
fn rejects_preallocation_metadata() {
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.preallocation = Preallocation::Metadata;
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    assert_eq!(
        plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
        ResizeError::PreallocationUnsupported
    );
}

#[test]
fn rejects_invalid_block_size() {
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.block_size = 12345; // not power-of-two, out of range
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    assert_eq!(
        plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
        ResizeError::InvalidNewVirtualSize
    );
}

#[test]
fn rejects_dirty_log_guid() {
    // Forge a non-zero log_guid in our copy of the active header
    // and pass it through opts; the planner should reject.
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    // Build a tampered active header copy with a non-zero
    // log_guid at offset 48.
    let header1_bytes = &bytes[HEADER1_OFFSET as usize..HEADER1_OFFSET as usize + 4096];
    let mut tampered = header1_bytes.to_vec();
    tampered[48] = 1;
    // Need to re-route opts to point at our tampered slice; the
    // existing_active_header is just a borrow, so leak a stable
    // boxed slice for the test's lifetime.
    let tampered_static: &'static [u8] = Box::leak(tampered.into_boxed_slice());

    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.existing_active_header = tampered_static;
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    assert_eq!(
        plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
        ResizeError::RequiresCheckFirst
    );
}

#[test]
fn rejects_sequence_number_near_u64_max() {
    // The two grow flavours write header copies at
    // current_sequence_number + 1 and + 2. A sequence number within 2 of
    // u64::MAX overflows those increments — the fuzz_resize_planners panic at
    // vhdx.rs:248 (instar #354, #360). The planner must reject it rather than
    // overflow. u64::MAX - 2 is the largest value that stays in range.
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let mut scratch = vec![0u8; VHDX_SCRATCH];

    for seq in [u64::MAX, u64::MAX - 1] {
        let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
        opts.current_sequence_number = seq;
        assert_eq!(
            plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
            ResizeError::Overflow,
            "sequence number {seq} must be rejected",
        );
    }

    // The largest in-range value (its + 2 increment is exactly u64::MAX) is
    // still accepted — the guard is not over-broad.
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.current_sequence_number = u64::MAX - 2;
    assert!(plan_resize_vhdx(&opts, &mut scratch).is_ok());
}

#[test]
fn rejects_invalid_active_header_offset() {
    let bytes = build_starting_vhdx(1u64 << 30, 32 * 1024 * 1024);
    let mut opts = opts_from_image(&bytes, 2u64 << 30, false);
    opts.current_active_header_offset = 0xDEADBEEF;
    let mut scratch = vec![0u8; VHDX_SCRATCH];
    assert_eq!(
        plan_resize_vhdx(&opts, &mut scratch).unwrap_err(),
        ResizeError::HeaderMismatch
    );
}

// Suppress unused-import warning when not all helpers are
// referenced by every test.
#[allow(dead_code)]
fn _force_use_of_helpers() {
    let mut buf = [0u8; 8];
    write_le_u64(&mut buf, 0, 0);
}
