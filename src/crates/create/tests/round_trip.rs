//! End-to-end round-trip integration tests for every `plan_*`
//! function in `crates/create`.
//!
//! Sweeps a representative option matrix per format, materialises
//! each plan into a contiguous byte buffer, parses it back with the
//! matching parser crate, and asserts that the format-specific
//! identifying fields (virtual_size, cluster/grain/block size,
//! version, backing reference where applicable) round-trip exactly.
//!
//! Also asserts the structural invariants every plan must satisfy:
//!
//! * `total_metadata_bytes == sum(writes[*].bytes.len())`
//! * `minimum_file_size == max(byte_offset + bytes.len())`
//! * No two writes overlap (sorted by `byte_offset`).
//!
//! These complement the per-planner unit tests in `lib.rs` by
//! exercising the matrix breadth in one place; if a single planner
//! regresses on its option surface this file catches it.

use create::{
    plan_qcow2, plan_vhd, plan_vhdx, plan_vmdk, BackingRef, CreateError, MetadataPlan,
    MetadataWrite, Qcow2CreateOpts, VhdCreateOpts, VhdSubformat, VhdxCreateOpts, VmdkCreateOpts,
    VmdkSubformat, MAX_BACKING_FILE_LEN, QCOW2_MAX_METADATA_SCRATCH, VHDX_MAX_METADATA_SCRATCH,
    VHD_MAX_METADATA_SCRATCH, VMDK_MAX_METADATA_SCRATCH,
};
use shared::ImageFormat;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn materialise(plan: &MetadataPlan<'_>) -> Vec<u8> {
    let mut buf = vec![0u8; plan.minimum_file_size as usize];
    for w in plan.writes() {
        let start = w.byte_offset as usize;
        let end = start + w.bytes.len();
        buf[start..end].copy_from_slice(w.bytes);
    }
    buf
}

fn assert_plan_invariants(plan: &MetadataPlan<'_>) {
    // Sum of write lengths matches total_metadata_bytes.
    let sum: u64 = plan.writes().iter().map(|w| w.bytes.len() as u64).sum();
    assert_eq!(plan.total_metadata_bytes, sum, "total_metadata_bytes");

    // minimum_file_size is the max end-offset.
    let max_end: u64 = plan
        .writes()
        .iter()
        .map(|w| w.byte_offset + w.bytes.len() as u64)
        .max()
        .unwrap_or(0);
    assert_eq!(plan.minimum_file_size, max_end, "minimum_file_size");

    // No writes overlap.
    let mut sorted: Vec<&MetadataWrite<'_>> = plan.writes().iter().collect();
    sorted.sort_by_key(|w| w.byte_offset);
    for pair in sorted.windows(2) {
        let prev = pair[0];
        let next = pair[1];
        assert!(
            prev.byte_offset + prev.bytes.len() as u64 <= next.byte_offset,
            "overlap: {}+{} > {}",
            prev.byte_offset,
            prev.bytes.len(),
            next.byte_offset,
        );
    }
}

// ---------------------------------------------------------------------------
// qcow2 sweep
// ---------------------------------------------------------------------------

#[test]
fn sweep_qcow2() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30, 1 << 35, 1 << 40];
    let cluster_sizes: &[u32] = &[512, 4096, 65536, 1 << 20, 2 << 20];
    let mut cases = 0;
    let mut skipped = 0;

    for &virtual_size in sizes {
        for &cluster_size in cluster_sizes {
            for extended_l2 in [false, true] {
                let opts = Qcow2CreateOpts {
                    virtual_size,
                    cluster_size,
                    refcount_bits: 16,
                    extended_l2,
                    lazy_refcounts: false,
                    compat_v3: true,
                    backing: None,
                    preallocation: qcow2::create::Preallocation::Off,
                };
                let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
                let scratch_len = scratch.len();
                let plan = match plan_qcow2(&opts, &mut scratch) {
                    Ok(p) => p,
                    Err(create::CreateError::InvalidVirtualSize) => {
                        // Combination exceeds QCOW2_MAX_L1_SIZE — expected
                        // for very small clusters at very large virtual
                        // sizes. Not a regression.
                        skipped += 1;
                        continue;
                    }
                    Err(e) => panic!(
                        "plan_qcow2 failed for virtual_size={}, cluster_size={}, extended_l2={}, scratch_len={}: {:?}",
                        virtual_size, cluster_size, extended_l2, scratch_len, e
                    ),
                };
                assert_plan_invariants(&plan);
                let bytes = materialise(&plan);
                let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse");
                assert_eq!(parsed.virtual_size, virtual_size);
                assert_eq!(parsed.cluster_size, cluster_size as u64);
                assert_eq!(parsed.extended_l2, extended_l2);
                cases += 1;
            }
        }
    }

    // Plus one backing-file case.
    let opts = Qcow2CreateOpts {
        virtual_size: 1 << 30,
        cluster_size: 65536,
        refcount_bits: 16,
        extended_l2: false,
        lazy_refcounts: true,
        compat_v3: true,
        backing: Some(BackingRef {
            path: b"backing.qcow2",
            format: Some(ImageFormat::Qcow2),
        }),
        preallocation: qcow2::create::Preallocation::Off,
    };
    let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
    let plan = plan_qcow2(&opts, &mut scratch).expect("plan");
    assert_plan_invariants(&plan);
    let bytes = materialise(&plan);
    let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse");
    assert_eq!(parsed.virtual_size, 1 << 30);
    assert!(parsed.lazy_refcounts);
    assert_eq!(parsed.backing_file_size as usize, b"backing.qcow2".len());
    cases += 1;

    // Preallocation::Metadata case (PR #298 review item #5).
    // The matrix above only exercises Preallocation::Off; Metadata /
    // Falloc / Full share the same metadata layout but populate L1
    // and refcount differently and reserve space for the L2 region
    // emitted by the guest (outside the plan). The minimum_file_size
    // override (layout.total_file_size, not max write end) is what
    // makes the host extend the file to cover the data region, so
    // assert_plan_invariants's strict minimum_file_size == max_end
    // rule doesn't apply here — verify the relaxed invariants inline.
    let opts = Qcow2CreateOpts {
        virtual_size: 1 << 26, // 64 MiB
        cluster_size: 65536,
        refcount_bits: 16,
        extended_l2: false,
        lazy_refcounts: false,
        compat_v3: true,
        backing: None,
        preallocation: qcow2::create::Preallocation::Metadata,
    };
    let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
    let plan = plan_qcow2(&opts, &mut scratch).expect("plan for metadata mode");
    let sum: u64 = plan.writes().iter().map(|w| w.bytes.len() as u64).sum();
    assert_eq!(
        plan.total_metadata_bytes, sum,
        "Preallocation::Metadata total_metadata_bytes"
    );
    let max_end: u64 = plan
        .writes()
        .iter()
        .map(|w| w.byte_offset + w.bytes.len() as u64)
        .max()
        .unwrap_or(0);
    assert!(
        plan.minimum_file_size >= max_end,
        "Preallocation::Metadata minimum_file_size {} should cover the \
         max write end {}",
        plan.minimum_file_size,
        max_end
    );
    assert!(
        plan.minimum_file_size >= 1 << 26,
        "Preallocation::Metadata minimum_file_size {} should cover the \
         64 MiB data region",
        plan.minimum_file_size
    );
    // Re-parse the header (sector 0) — the writes for the header /
    // L1 / refcount cluster all live within plan.writes(), so the
    // materialise sized at minimum_file_size still captures them.
    let bytes = materialise(&plan);
    let parsed = qcow2::QcowHeader::parse(&bytes).expect("metadata mode parse");
    assert_eq!(parsed.virtual_size, 1 << 26);
    cases += 1;

    // cases counts: matrix-success + 2 (trailing backing-file + Metadata cases).
    // skipped counts: matrix-skip (combinations beyond format limits).
    assert_eq!(cases + skipped, sizes.len() * cluster_sizes.len() * 2 + 2);
    // We should have covered at least the realistic combinations.
    assert!(cases > 30, "sweep covered only {} cases", cases);
}

// ---------------------------------------------------------------------------
// vmdk sweep
// ---------------------------------------------------------------------------

#[test]
fn sweep_vmdk() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30, 1 << 32];
    let grain_sizes: &[u32] = &[4096, 16384, 65536];
    let mut cases = 0;

    for &virtual_size in sizes {
        for &grain_size in grain_sizes {
            for subformat in [
                VmdkSubformat::MonolithicSparse,
                VmdkSubformat::StreamOptimized,
            ] {
                let opts = VmdkCreateOpts {
                    virtual_size,
                    subformat,
                    grain_size,
                    backing: None,
                    parent_cid: None,
                };
                let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
                let plan = plan_vmdk(&opts, &mut scratch).expect("plan");
                assert_plan_invariants(&plan);
                let bytes = materialise(&plan);
                let parsed = vmdk::Vmdk4Header::parse(&bytes).expect("parse");
                assert_eq!(parsed.virtual_size, virtual_size);
                assert_eq!(parsed.cluster_size, grain_size);
                cases += 1;
            }
        }
    }

    // Plus a monolithicSparse-with-backing case.
    let opts = VmdkCreateOpts {
        virtual_size: 1 << 30,
        subformat: VmdkSubformat::MonolithicSparse,
        grain_size: 65536,
        backing: Some(BackingRef {
            path: b"parent.vmdk",
            format: Some(ImageFormat::Vmdk4),
        }),
        parent_cid: Some(0x12345678),
    };
    let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
    let plan = plan_vmdk(&opts, &mut scratch).expect("plan");
    assert_plan_invariants(&plan);
    let bytes = materialise(&plan);
    let desc = &bytes[512..512 + (vmdk::DESC_SECTORS * 512) as usize];
    let needle = b"parentFileNameHint=\"parent.vmdk\"";
    assert!(desc.windows(needle.len()).any(|w| w == needle));
    cases += 1;

    assert_eq!(cases, sizes.len() * grain_sizes.len() * 2 + 1);
}

// ---------------------------------------------------------------------------
// vhd sweep
// ---------------------------------------------------------------------------

#[test]
fn sweep_vhd_dynamic() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30, 1 << 32];
    let block_sizes: &[u32] = &[512 * 1024, 2 * 1024 * 1024, 32 * 1024 * 1024];
    let mut cases = 0;

    for &virtual_size in sizes {
        for &block_size in block_sizes {
            let opts = VhdCreateOpts {
                virtual_size,
                subformat: VhdSubformat::Dynamic,
                block_size,
                backing: None,
                parent_unique_id: [0; 16],
                parent_timestamp: 0,
            };
            let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
            let plan = plan_vhd(&opts, &mut scratch).expect("plan");
            assert_plan_invariants(&plan);
            let bytes = materialise(&plan);
            let footer = vhd::VhdFooter::parse(&bytes[bytes.len() - 512..]).expect("parse footer");
            assert_eq!(footer.current_size, virtual_size);
            assert_eq!(footer.disk_type, vhd::DISK_TYPE_DYNAMIC);
            cases += 1;
        }
    }

    assert_eq!(cases, sizes.len() * block_sizes.len());
}

#[test]
fn sweep_vhd_fixed() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30];
    let mut cases = 0;

    for &virtual_size in sizes {
        let opts = VhdCreateOpts {
            virtual_size,
            subformat: VhdSubformat::Fixed,
            block_size: 0,
            backing: None,
            parent_unique_id: [0; 16],
            parent_timestamp: 0,
        };
        let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
        let plan = plan_vhd(&opts, &mut scratch).expect("plan");
        assert_plan_invariants(&plan);
        let bytes = materialise(&plan);
        assert_eq!(bytes.len() as u64, virtual_size + 512);
        let footer = vhd::VhdFooter::parse(&bytes[bytes.len() - 512..]).expect("parse footer");
        assert_eq!(footer.current_size, virtual_size);
        assert_eq!(footer.disk_type, vhd::DISK_TYPE_FIXED);
        cases += 1;
    }

    assert_eq!(cases, sizes.len());
}

// ---------------------------------------------------------------------------
// vhdx sweep
// ---------------------------------------------------------------------------

#[test]
fn sweep_vhdx_dynamic() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30, 1 << 32];
    let block_sizes: &[u32] = &[1024 * 1024, 16 * 1024 * 1024, 32 * 1024 * 1024];
    let mut cases = 0;

    for &virtual_size in sizes {
        for &block_size in block_sizes {
            let opts = VhdxCreateOpts {
                virtual_size,
                block_size,
                backing: None,
            };
            let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
            let plan = plan_vhdx(&opts, &mut scratch).expect("plan");
            assert_plan_invariants(&plan);
            let bytes = materialise(&plan);

            let sig = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            assert_eq!(sig, vhdx::FILE_IDENTIFIER_SIGNATURE);

            let h1 = &bytes
                [vhdx::HEADER1_OFFSET as usize..vhdx::HEADER1_OFFSET as usize + vhdx::HEADER_SIZE];
            vhdx::VhdxHeader::parse(h1).expect("parse header 1");

            let rt = &bytes
                [vhdx::REGION_TABLE1_OFFSET as usize..vhdx::REGION_TABLE1_OFFSET as usize + 65536];
            vhdx::parse_region_table(rt).expect("parse region table");

            cases += 1;
        }
    }

    assert_eq!(cases, sizes.len() * block_sizes.len());
}

// ---------------------------------------------------------------------------
// vhd differencing child (phase 5)
// ---------------------------------------------------------------------------
//
// Everything below covers `plan_vhd` with a backing reference — the
// differencing emitter added by
// docs/plans/PLAN-differencing-phase-05-vhd-emitter.md. The per-field
// raw-byte assertions for the `crates/vhd` builders live in that crate's
// own unit tests; what these add is that `plan_vhd` calls them with the
// right arguments, in the right layout, and surfaces their refusals.

/// A parent identity the planner cannot derive and must copy verbatim.
/// Deliberately neither all-zero nor a valid-looking UUID: a builder that
/// byte-swapped it, reformatted it, or wrote its own would fail.
const DIFF_PARENT_ID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

/// Distinct from every other u32 in the header, and with four different
/// bytes, so a little-endian write or a write to a neighbouring field is
/// visible.
const DIFF_PARENT_TIMESTAMP: u32 = 0x1A2B_3C4D;

/// A relative parent path: relative selects the `W2ru` platform code.
const DIFF_PARENT_PATH: &str = "parent.vhd";

/// Absolute file offsets of a differencing child's metadata, per decision
/// 1 of the phase plan. Written as literals rather than derived from the
/// planner, so a layout change has to edit them.
const DIFF_HEAD_FOOTER_OFF: usize = 0;
const DIFF_DYN_HEADER_OFF: usize = 512;
const DIFF_LOCATOR_DATA_OFF: usize = 1536;
const DIFF_BAT_OFF: u64 = 2048;

fn diff_opts(path: &str) -> VhdCreateOpts<'_> {
    VhdCreateOpts {
        virtual_size: 1 << 30,
        subformat: VhdSubformat::Dynamic,
        block_size: 2 * 1024 * 1024,
        backing: Some(BackingRef {
            path: path.as_bytes(),
            format: Some(ImageFormat::Vhd),
        }),
        parent_unique_id: DIFF_PARENT_ID,
        parent_timestamp: DIFF_PARENT_TIMESTAMP,
    }
}

/// The 1024 bytes of the dynamic header, as they lie in the image.
fn dyn_header(bytes: &[u8]) -> &[u8] {
    &bytes[DIFF_DYN_HEADER_OFF..DIFF_DYN_HEADER_OFF + 1024]
}

/// The bounds a reader of this image would supply: its real length, and
/// the dynamic header at the footer's `data_offset`.
fn diff_bounds(bytes: &[u8]) -> vhd::VhdImageBounds {
    vhd::VhdImageBounds {
        image_len: bytes.len() as u64,
        header_offset: DIFF_DYN_HEADER_OFF as u64,
    }
}

/// Build a differencing child for `path` and return its bytes.
fn materialise_differencing(path: &str) -> Vec<u8> {
    let opts = diff_opts(path);
    let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
    let plan = plan_vhd(&opts, &mut scratch).expect("differencing plan");
    assert_plan_invariants(&plan);
    materialise(&plan)
}

/// The load-bearing test of phase 5: lay a differencing plan's writes into
/// a buffer and read every parent-bearing structure back with the phase 3
/// parser.
///
/// It is *necessary and not sufficient* — emitter and parser share their
/// offset constants, so this alone could pass with both halves wrong in
/// the same direction. Two things make it more than a tautology. The
/// endianness assertions below check the raw bytes against a hand-written
/// expectation rather than against the parser, and the
/// `defect == None` assertion exercises `locator_defect`, whose four
/// placement rules are facts about the *layout* that no emitter constant
/// encodes. `vhd_differencing_locator_misplacement_is_detected` is the
/// negative control for the latter.
#[test]
fn vhd_differencing_round_trips_through_the_parser() {
    let bytes = materialise_differencing(DIFF_PARENT_PATH);

    // --- layout (decision 1) -------------------------------------------
    //
    // Asserted through the plan rather than only through the parser,
    // because the locator data region is new file real estate and its
    // offset is what the four placement rules are about.
    let opts = diff_opts(DIFF_PARENT_PATH);
    let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
    let plan = plan_vhd(&opts, &mut scratch).expect("differencing plan");
    let offsets: Vec<(u64, usize)> = plan
        .writes()
        .iter()
        .map(|w| (w.byte_offset, w.bytes.len()))
        .collect();
    assert_eq!(
        offsets,
        vec![
            (0, 512),     // head footer copy
            (512, 1024),  // dynamic header
            (1536, 512),  // parent locator platform data
            (2048, 2048), // BAT: 1 GiB / 2 MiB = 512 entries
            (4096, 512),  // tail footer
        ],
        "differencing layout",
    );
    drop(plan);

    // --- both footers ---------------------------------------------------
    let head = vhd::VhdFooter::parse(&bytes[DIFF_HEAD_FOOTER_OFF..DIFF_HEAD_FOOTER_OFF + 512])
        .expect("parse head footer");
    let tail = vhd::VhdFooter::parse(&bytes[bytes.len() - 512..]).expect("parse tail footer");
    assert_eq!(vhd::DISK_TYPE_DIFFERENCING, 4);
    assert_eq!(head.disk_type, vhd::DISK_TYPE_DIFFERENCING);
    assert_eq!(tail.disk_type, vhd::DISK_TYPE_DIFFERENCING);
    // The copy really is a copy: a child whose two footers disagree about
    // its disk type is a child qemu and Hyper-V read differently.
    assert_eq!(
        &bytes[..512],
        &bytes[bytes.len() - 512..],
        "footer copy differs from the tail footer",
    );

    // --- dynamic header --------------------------------------------------
    let dh = vhd::VhdDynamicHeader::parse(dyn_header(&bytes)).expect("parse dynamic header");
    assert_eq!(
        dh.table_offset, DIFF_BAT_OFF,
        "a differencing child's BAT moves to 2048 to make room for the locator data",
    );
    assert_eq!(dh.max_table_entries, 512);
    assert_eq!(dh.block_size, 2 * 1024 * 1024);

    // --- the parent fields ----------------------------------------------
    let bounds = diff_bounds(&bytes);
    let info = vhd::VhdParentInfo::parse(dyn_header(&bytes), &bounds).expect("parse parent info");
    assert_eq!(info.unique_id, DIFF_PARENT_ID);
    assert_eq!(info.timestamp, DIFF_PARENT_TIMESTAMP);

    let mut name = [0u8; vhd::MAX_PARENT_NAME_UTF8];
    let n = info.decode_name(&mut name).expect("decode parent name");
    assert_eq!(&name[..n], DIFF_PARENT_PATH.as_bytes());

    // --- the selected locator --------------------------------------------
    let window = vhd::VhdImageWindow {
        file_offset: 0,
        bytes: &bytes,
    };
    match info.locators.preferred_locator(Some(&window)) {
        vhd::PreferredLocator::Found { slot, demoted_from } => {
            assert_eq!(slot, 0, "the one populated entry is slot 0");
            assert_eq!(demoted_from, None);
        }
        other => panic!("no locator selected: {other:?}"),
    }

    let entry = info.locators.entries[0];
    // `defect == None` is the assertion that carries this test: it proves
    // the platform data overlaps neither footer nor the dynamic header,
    // lies inside the image, and is no longer than its declared space.
    assert_eq!(entry.defect, None);
    assert_eq!(entry.platform(), vhd::VhdPlatform::W2ru);
    // Decision 4: a byte count, not the sector count SPEC(VHD) implies.
    assert_eq!(entry.platform_data_space, 512);
    assert_eq!(
        entry.platform_data_length,
        (DIFF_PARENT_PATH.len() * 2) as u32,
        "an all-BMP path is two bytes per character, with no terminator",
    );
    assert_eq!(entry.reserved, 0);
    assert_eq!(entry.platform_data_offset, DIFF_LOCATOR_DATA_OFF as u64);

    // Slots 2..8 (one-based) are untouched.
    for slot in 1..vhd::PARENT_LOCATOR_COUNT {
        assert_eq!(
            info.locators.entries[slot],
            vhd::VhdParentLocator::EMPTY,
            "slot {slot} should be all zero",
        );
    }

    let mut path = [0u8; 64];
    let n = entry
        .decode_path(&window, &mut path)
        .expect("decode locator path");
    assert_eq!(&path[..n], DIFF_PARENT_PATH.as_bytes());

    // --- the two endiannesses, against raw bytes --------------------------
    //
    // The single most valuable assertion here. The parent unicode name is
    // UTF-16 BIG endian and the locator platform data is UTF-16 LITTLE
    // endian, 1024 bytes apart in the same image, and an emitter that used
    // one encoder for both would still round-trip through instar's own
    // parser if the parser were wrong in the same direction. These compare
    // against bytes written out by hand.
    let name_field = DIFF_DYN_HEADER_OFF + 64;
    assert_eq!(
        &bytes[name_field..name_field + 6],
        // 'p' 'a' 'r', high byte first.
        &[0x00, b'p', 0x00, b'a', 0x00, b'r'],
        "the parent unicode name must be UTF-16 big endian",
    );
    assert_eq!(
        &bytes[DIFF_LOCATOR_DATA_OFF..DIFF_LOCATOR_DATA_OFF + 6],
        // The same three characters, low byte first.
        &[b'p', 0x00, b'a', 0x00, b'r', 0x00],
        "the locator platform data must be UTF-16 little endian",
    );

    // The locator data region is one sector, and the bytes past the path
    // are zero padding rather than anything left over.
    assert!(
        bytes[DIFF_LOCATOR_DATA_OFF + DIFF_PARENT_PATH.len() * 2..DIFF_BAT_OFF as usize]
            .iter()
            .all(|&b| b == 0),
        "the tail of the locator sector is not zero padded",
    );

    // The BAT is still entirely unallocated, at its new offset.
    let bat = &bytes[DIFF_BAT_OFF as usize..DIFF_BAT_OFF as usize + 2048];
    assert!(bat.iter().all(|&b| b == 0xFF), "BAT is not all-unallocated");
}

/// The negative control for `defect == None`.
///
/// Without this, the positive assertion above is close to vacuous: it
/// would pass just as happily if `locator_defect` never returned a defect
/// at all. This takes the same emitted bytes, moves only the locator's
/// `platform_data_offset` from 1536 to 512 — inside the dynamic header,
/// which is the placement decision 1 rejected — and asserts the parser
/// notices.
#[test]
fn vhd_differencing_locator_misplacement_is_detected() {
    let mut bytes = materialise_differencing(DIFF_PARENT_PATH);
    let bounds = diff_bounds(&bytes);

    // Before: sound.
    let info = vhd::VhdParentInfo::parse(dyn_header(&bytes), &bounds).expect("parse parent info");
    assert_eq!(info.locators.entries[0].defect, None);
    assert_eq!(info.locators.entries[0].platform_data_offset, 1536);

    // `platform_data_offset` is the big-endian u64 at +16 of the entry at
    // header offset +576. Nothing else about the image changes: the
    // platform data is still where it was, the name field still decodes,
    // and the only difference is a locator that now points into the
    // 1024-byte dynamic header.
    let field = DIFF_DYN_HEADER_OFF + 576 + 16;
    bytes[field..field + 8].copy_from_slice(&512u64.to_be_bytes());

    let info = vhd::VhdParentInfo::parse(dyn_header(&bytes), &bounds).expect("parse parent info");
    let entry = info.locators.entries[0];
    assert_eq!(
        entry.defect,
        Some(vhd::VhdLocatorDefect::OverlapsHeader),
        "a locator pointing into the dynamic header must be refused",
    );
    // And a defective entry is not a candidate, so nothing is selected.
    assert!(matches!(
        info.locators.preferred_locator(Some(&vhd::VhdImageWindow {
            file_offset: 0,
            bytes: &bytes,
        })),
        vhd::PreferredLocator::NotFound,
    ));
}

/// The platform code is chosen from the path the user typed, and is four
/// ASCII bytes in file order.
///
/// Asserted against the raw bytes rather than through
/// [`vhd::VhdPlatform::from_code`], because both sides of that comparison
/// would be byte-swapped together if the emitter wrote the code as a
/// little-endian u32.
#[test]
fn vhd_differencing_platform_code_follows_the_path() {
    let code_off = DIFF_DYN_HEADER_OFF + 576;

    let relative = materialise_differencing("parent.vhd");
    assert_eq!(&relative[code_off..code_off + 4], b"W2ru");
    // Not byte-swapped: a u32 0x57327275 written little-endian gives this.
    assert_ne!(&relative[code_off..code_off + 4], b"ur2W");

    let absolute = materialise_differencing("/srv/images/parent.vhd");
    assert_eq!(&absolute[code_off..code_off + 4], b"W2ku");
    assert_ne!(&absolute[code_off..code_off + 4], b"uk2W");

    // A relative path that merely contains a slash is still relative.
    let nested = materialise_differencing("images/parent.vhd");
    assert_eq!(&nested[code_off..code_off + 4], b"W2ru");
}

/// The 255-UTF-16-code-unit cap, as `plan_vhd` surfaces it.
///
/// The boundary itself is `crates/vhd`'s and is tested there against the
/// builder. What this adds is that `plan_vhd` neither re-derives the limit
/// nor swallows the refusal: an over-length parent path comes back as
/// [`CreateError::ParentNameTooLong`] and not as `BackingFileTooLong`,
/// whose host message names a 1024-byte limit that has nothing to do with
/// the 512-byte field that actually overflowed.
#[test]
fn vhd_differencing_parent_name_length_boundary() {
    // 255 code units is 510 bytes, leaving the last code unit of the
    // 512-byte field zero so a terminating NUL stays inside it.
    let fits = "a".repeat(255);
    let bytes = materialise_differencing(&fits);
    let bounds = diff_bounds(&bytes);
    let info = vhd::VhdParentInfo::parse(dyn_header(&bytes), &bounds).expect("parse parent info");
    let mut name = [0u8; vhd::MAX_PARENT_NAME_UTF8];
    let n = info.decode_name(&mut name).expect("decode parent name");
    assert_eq!(&name[..n], fits.as_bytes());
    assert_eq!(info.locators.entries[0].platform_data_length, 510);

    // 256 would fill all 512 bytes with no terminator — libvhdi then reads
    // past the field into the locator table and appends a stray character
    // to the parent filename it reports.
    let over = "a".repeat(256);
    let opts = diff_opts(&over);
    let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
    assert_eq!(
        plan_vhd(&opts, &mut scratch).err(),
        Some(CreateError::ParentNameTooLong),
    );
}

/// A character outside the BMP costs two UTF-16 code units, so the cap is
/// reached after 127 of them and not after 255.
///
/// 128 of them is 512 UTF-8 bytes — comfortably under
/// `MAX_BACKING_FILE_LEN`, and under any byte-based guess at the parent
/// name limit — but 256 code units, which does not fit. A limit estimated
/// from the UTF-8 length rather than counted during encoding gets this
/// wrong in one direction or the other.
#[test]
fn vhd_differencing_non_bmp_characters_cost_two_code_units() {
    let fits = "\u{1F600}".repeat(127);
    assert_eq!(fits.len(), 508);
    let bytes = materialise_differencing(&fits);
    let bounds = diff_bounds(&bytes);
    let info = vhd::VhdParentInfo::parse(dyn_header(&bytes), &bounds).expect("parse parent info");
    let mut name = [0u8; vhd::MAX_PARENT_NAME_UTF8];
    let n = info.decode_name(&mut name).expect("decode parent name");
    assert_eq!(&name[..n], fits.as_bytes());
    // 127 surrogate pairs is 254 code units, 508 bytes: one code unit of
    // headroom is unavoidable because 255 is odd.
    assert_eq!(info.locators.entries[0].platform_data_length, 508);

    let over = "\u{1F600}".repeat(128);
    assert_eq!(over.len(), 512);
    let opts = diff_opts(&over);
    let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
    assert_eq!(
        plan_vhd(&opts, &mut scratch).err(),
        Some(CreateError::ParentNameTooLong),
    );
}

/// The last two bytes of the 512-byte parent unicode name field are always
/// zero, whatever the path — asserted directly rather than inferred from
/// the 255-code-unit cap.
///
/// This is the byte libvhdi reads if it looks for a terminator past the
/// end of a full field, so it is worth checking at the longest path the
/// emitter accepts as well as at ordinary ones.
#[test]
fn vhd_differencing_parent_name_field_always_ends_in_a_nul() {
    let last = DIFF_DYN_HEADER_OFF + 64 + 512 - 2;
    for path in [
        "p.vhd".to_string(),
        "parent.vhd".to_string(),
        "/srv/images/parent.vhd".to_string(),
        "a".repeat(255),
        "\u{1F600}".repeat(127),
    ] {
        let bytes = materialise_differencing(&path);
        assert_eq!(
            &bytes[last..last + 2],
            &[0u8, 0u8],
            "parent name field not NUL-terminated for {path:?}",
        );
    }
}

/// Decision 5: a differencing VHD is Dynamic-only. `disk_type = 4` means
/// "the BAT says which blocks are mine", and a fixed VHD has neither a BAT
/// nor a dynamic header to hold the parent locators.
#[test]
fn vhd_fixed_with_backing_is_refused() {
    let opts = VhdCreateOpts {
        virtual_size: 1 << 20,
        subformat: VhdSubformat::Fixed,
        block_size: 0,
        backing: Some(BackingRef {
            path: b"parent.vhd",
            format: Some(ImageFormat::Vhd),
        }),
        parent_unique_id: DIFF_PARENT_ID,
        parent_timestamp: DIFF_PARENT_TIMESTAMP,
    };
    let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
    assert_eq!(
        plan_vhd(&opts, &mut scratch).err(),
        Some(CreateError::BackingFileUnsupported),
    );
}

// ---------------------------------------------------------------------------
// vhd non-differencing golden
// ---------------------------------------------------------------------------

/// FNV-1a 64, so a write's whole content is pinned by one constant without
/// committing tens of kilobytes of hex. Implemented here rather than
/// pulled in as a dependency: the golden is only meaningful if the hash
/// never changes, and an inlined eight-line function cannot be bumped by a
/// `cargo update`.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn summarise_plan(label: &str, plan: &MetadataPlan<'_>, out: &mut String) {
    use std::fmt::Write;
    writeln!(
        out,
        "{label} min={} meta={} writes={}",
        plan.minimum_file_size,
        plan.total_metadata_bytes,
        plan.writes().len()
    )
    .unwrap();
    for (i, w) in plan.writes().iter().enumerate() {
        writeln!(
            out,
            "  w{i} off={} len={} h={:016x}",
            w.byte_offset,
            w.bytes.len(),
            fnv1a64(w.bytes)
        )
        .unwrap();
    }
}

/// Every byte `plan_vhd` emits for a non-differencing VHD, as it was on
/// `develop` at `f981374` — the commit this phase branched from, before
/// the differencing emitter existed.
///
/// **How these constants were obtained, and why they mean what they say.**
/// They are not a transcription of the current tree's behaviour. A
/// detached worktree was created at `f981374`, a throwaway integration
/// test was added there that built exactly the option matrix below and
/// wrote this summary out, and `make test-rust` was run in that worktree.
/// The text is its output, pasted here unedited. So this constant is
/// `develop`'s output by construction, and the assertion below is a real
/// comparison between two revisions rather than a restatement of one.
///
/// What it protects is the risk named in the phase plan: the locator data
/// region sits between the dynamic header and the BAT, so moving the BAT
/// unconditionally instead of only for a differencing child is a
/// one-character mistake that silently changes the bytes of every
/// `create -f vpc` invocation — including the ones `tests/test_create.py`
/// compares against qemu-img, where the failure would look like a qemu
/// disagreement rather than like this. The `off=` columns for `w2` and
/// `w3` are where that shows up: the BAT stays at 1536.
///
/// If a deliberate change to the non-differencing layout is ever made,
/// regenerate this the same way — from the revision being compared
/// against, not from the tree being changed.
const GOLDEN_VHD_NO_BACKING: &str = "\
dyn vsize=1048576 bsize=524288 min=2560 meta=2560 writes=4
  w0 off=0 len=512 h=648bbf3bb2203d41
  w1 off=512 len=1024 h=596fd2569ac18420
  w2 off=1536 len=512 h=d4dd49c3f3e3ba9d
  w3 off=2048 len=512 h=648bbf3bb2203d41
dyn vsize=1048576 bsize=2097152 min=2560 meta=2560 writes=4
  w0 off=0 len=512 h=648bbf3bb2203d41
  w1 off=512 len=1024 h=6f9a786e96d83b2c
  w2 off=1536 len=512 h=e0304207e28618c1
  w3 off=2048 len=512 h=648bbf3bb2203d41
dyn vsize=1048576 bsize=33554432 min=2560 meta=2560 writes=4
  w0 off=0 len=512 h=648bbf3bb2203d41
  w1 off=512 len=1024 h=f359ddfa4f3f94ec
  w2 off=1536 len=512 h=e0304207e28618c1
  w3 off=2048 len=512 h=648bbf3bb2203d41
dyn vsize=33554432 bsize=524288 min=2560 meta=2560 writes=4
  w0 off=0 len=512 h=b3f3d7e0d1e1bedc
  w1 off=512 len=1024 h=da68ecc8bdfff974
  w2 off=1536 len=512 h=70f2d3fff53e1425
  w3 off=2048 len=512 h=b3f3d7e0d1e1bedc
dyn vsize=33554432 bsize=2097152 min=2560 meta=2560 writes=4
  w0 off=0 len=512 h=b3f3d7e0d1e1bedc
  w1 off=512 len=1024 h=dfd38eed3d7e93c4
  w2 off=1536 len=512 h=98cd8be1666f50e5
  w3 off=2048 len=512 h=b3f3d7e0d1e1bedc
dyn vsize=33554432 bsize=33554432 min=2560 meta=2560 writes=4
  w0 off=0 len=512 h=b3f3d7e0d1e1bedc
  w1 off=512 len=1024 h=f359ddfa4f3f94ec
  w2 off=1536 len=512 h=e0304207e28618c1
  w3 off=2048 len=512 h=b3f3d7e0d1e1bedc
dyn vsize=1073741824 bsize=524288 min=10240 meta=10240 writes=4
  w0 off=0 len=512 h=de8ba96e91643020
  w1 off=512 len=1024 h=19157299ea048bf4
  w2 off=1536 len=8192 h=9c50825ef0adc325
  w3 off=9728 len=512 h=de8ba96e91643020
dyn vsize=1073741824 bsize=2097152 min=4096 meta=4096 writes=4
  w0 off=0 len=512 h=de8ba96e91643020
  w1 off=512 len=1024 h=8d1d929af69ec708
  w2 off=1536 len=2048 h=f024277fb3c50b25
  w3 off=3584 len=512 h=de8ba96e91643020
dyn vsize=1073741824 bsize=33554432 min=2560 meta=2560 writes=4
  w0 off=0 len=512 h=de8ba96e91643020
  w1 off=512 len=1024 h=df8d7bdecb480758
  w2 off=1536 len=512 h=f657619b0c4f98a5
  w3 off=2048 len=512 h=de8ba96e91643020
dyn vsize=4294967296 bsize=524288 min=34816 meta=34816 writes=4
  w0 off=0 len=512 h=89a9906da3171a26
  w1 off=512 len=1024 h=f5f00d92f8655bb4
  w2 off=1536 len=32768 h=9111afa91650a325
  w3 off=34304 len=512 h=89a9906da3171a26
dyn vsize=4294967296 bsize=2097152 min=10240 meta=10240 writes=4
  w0 off=0 len=512 h=89a9906da3171a26
  w1 off=512 len=1024 h=d304663790958754
  w2 off=1536 len=8192 h=9c50825ef0adc325
  w3 off=9728 len=512 h=89a9906da3171a26
dyn vsize=4294967296 bsize=33554432 min=2560 meta=2560 writes=4
  w0 off=0 len=512 h=89a9906da3171a26
  w1 off=512 len=1024 h=c6c270d5d1a9b318
  w2 off=1536 len=512 h=be78bcdbd952dd25
  w3 off=2048 len=512 h=89a9906da3171a26
fix vsize=1048576 min=1049088 meta=512 writes=1
  w0 off=1048576 len=512 h=cf83137f0cf84c99
fix vsize=33554432 min=33554944 meta=512 writes=1
  w0 off=33554432 len=512 h=e7fda2413134a9f8
fix vsize=1073741824 min=1073742336 meta=512 writes=1
  w0 off=1073741824 len=512 h=ec2eedb5a85d9e18
";

/// A non-differencing VHD is byte-identical to what `develop` at
/// `f981374` produced for the same options.
///
/// See [`GOLDEN_VHD_NO_BACKING`] for how the expected text was produced
/// and why it is a cross-revision comparison rather than a snapshot of the
/// current tree.
#[test]
fn vhd_non_differencing_output_matches_develop() {
    let mut out = String::new();

    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30, 1 << 32];
    let block_sizes: &[u32] = &[512 * 1024, 2 * 1024 * 1024, 32 * 1024 * 1024];
    for &virtual_size in sizes {
        for &block_size in block_sizes {
            let opts = VhdCreateOpts {
                virtual_size,
                subformat: VhdSubformat::Dynamic,
                block_size,
                backing: None,
                // The parent identity is read only when `backing` is
                // `Some`, so these must not reach the image. If they ever
                // do, the w1 hashes move.
                parent_unique_id: DIFF_PARENT_ID,
                parent_timestamp: DIFF_PARENT_TIMESTAMP,
            };
            let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
            let plan = plan_vhd(&opts, &mut scratch).expect("plan");
            summarise_plan(
                &format!("dyn vsize={virtual_size} bsize={block_size}"),
                &plan,
                &mut out,
            );
        }
    }

    for &virtual_size in &[1u64 << 20, 1 << 25, 1 << 30] {
        let opts = VhdCreateOpts {
            virtual_size,
            subformat: VhdSubformat::Fixed,
            block_size: 0,
            backing: None,
            parent_unique_id: DIFF_PARENT_ID,
            parent_timestamp: DIFF_PARENT_TIMESTAMP,
        };
        let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
        let plan = plan_vhd(&opts, &mut scratch).expect("plan");
        summarise_plan(&format!("fix vsize={virtual_size}"), &plan, &mut out);
    }

    // Line by line first: the whole-string comparison below is what the
    // test is, but its failure output is one escaped 4 KiB line, and the
    // interesting difference is almost always a single `off=` column.
    for (i, (got, want)) in out.lines().zip(GOLDEN_VHD_NO_BACKING.lines()).enumerate() {
        assert_eq!(got, want, "golden line {} differs", i + 1);
    }
    assert_eq!(
        out.lines().count(),
        GOLDEN_VHD_NO_BACKING.lines().count(),
        "golden line count differs",
    );
    assert_eq!(out, GOLDEN_VHD_NO_BACKING);
}

/// The differencing layout, swept across geometries rather than pinned at
/// one.
///
/// Every other differencing test runs through `materialise_differencing`,
/// which fixes 1 GiB / 2 MiB. That is fine for the field encodings, which
/// do not depend on geometry, and useless for the layout rules, which do:
/// the locator region sits between two structures whose sizes change with
/// the image. The interesting extreme is the smallest image, where the BAT
/// is a single sector and the tail footer lands at 2560 — the case closest
/// to `locator_defect`'s `OverlapsFooter` rule, which no fixed-geometry
/// test can approach. `assert_plan_invariants` also does real work here,
/// because it is the overlap check.
#[test]
fn vhd_differencing_layout_holds_across_geometries() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30, 1 << 32];
    let block_sizes: &[u32] = &[512 * 1024, 2 * 1024 * 1024, 32 * 1024 * 1024];
    let path = "parent.vhd";

    for &virtual_size in sizes {
        for &block_size in block_sizes {
            let opts = VhdCreateOpts {
                virtual_size,
                block_size,
                ..diff_opts(path)
            };
            let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
            let plan = plan_vhd(&opts, &mut scratch)
                .unwrap_or_else(|e| panic!("vsize={virtual_size} bsize={block_size}: {e:?}"));
            assert_plan_invariants(&plan);

            let writes = plan.writes();
            assert_eq!(writes.len(), 5, "vsize={virtual_size} bsize={block_size}");
            assert_eq!(
                (writes[2].byte_offset, writes[2].bytes.len()),
                (DIFF_LOCATOR_DATA_OFF as u64, 512),
                "locator region moved: vsize={virtual_size} bsize={block_size}"
            );
            assert_eq!(
                writes[3].byte_offset, DIFF_BAT_OFF,
                "BAT moved: vsize={virtual_size} bsize={block_size}"
            );

            // The tail footer is the structure the locator region gets
            // closest to on a small image; prove the parser is content
            // with the placement at every geometry, not just the roomy
            // one.
            let bytes = materialise(&plan);
            let bounds = diff_bounds(&bytes);
            let info =
                vhd::VhdParentInfo::parse(dyn_header(&bytes), &bounds).expect("parent info parses");
            let entry = info.locators.entries[0];
            assert_eq!(
                entry.defect, None,
                "locator defective at vsize={virtual_size} bsize={block_size}"
            );
            assert_eq!(entry.platform_data_offset, DIFF_LOCATOR_DATA_OFF as u64);
            assert_eq!(entry.platform_data_space, 512);
        }
    }
}

/// An empty backing path is refused rather than emitted.
///
/// Found in review. `MAX_BACKING_FILE_LEN` bounded the top end and
/// nothing bounded the bottom, so `BackingRef { path: b"", .. }` planned
/// a `disk_type = 4` image whose locator carried
/// `platform_data_length == 0` — which this crate's own parser calls
/// `VhdLocatorDefect::EmptyData`. `fuzz_create_emitters` reached it and
/// none of its oracles looked at locator defects, so it passed silently.
#[test]
fn vhd_differencing_refuses_an_empty_parent_path() {
    let opts = VhdCreateOpts {
        backing: Some(BackingRef {
            path: b"",
            format: Some(ImageFormat::Vhd),
        }),
        ..diff_opts("unused")
    };
    let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
    assert_eq!(
        plan_vhd(&opts, &mut scratch).unwrap_err(),
        CreateError::BackingFileUnsupported
    );
}

/// A backing path over `MAX_BACKING_FILE_LEN` is `BackingFileTooLong`,
/// not `ParentNameTooLong`.
///
/// The two limits are different facts — 1024 UTF-8 bytes the call table
/// accepts, versus 255 UTF-16 code units the VHD field holds — and they
/// have different host messages. A path over both must report the one the
/// generic check owns, so the boundary between them stays visible.
#[test]
fn vhd_differencing_distinguishes_the_two_length_limits() {
    let long = "a".repeat(MAX_BACKING_FILE_LEN + 1);
    let opts = VhdCreateOpts {
        backing: Some(BackingRef {
            path: long.as_bytes(),
            format: Some(ImageFormat::Vhd),
        }),
        ..diff_opts("unused")
    };
    let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
    assert_eq!(
        plan_vhd(&opts, &mut scratch).unwrap_err(),
        CreateError::BackingFileTooLong
    );
}

/// A backing path that is not valid UTF-8 cannot reach a UTF-16 field.
///
/// Unreachable from the CLI — the VMM's backing argument is a `String`,
/// so clap refuses non-UTF-8 first — but `fuzz_create_emitters` feeds
/// arbitrary bytes, and a lossy transcode here would name a different
/// file.
#[test]
fn vhd_differencing_refuses_a_non_utf8_parent_path() {
    let opts = VhdCreateOpts {
        backing: Some(BackingRef {
            path: &[0x66, 0x6f, 0xff, 0x6f],
            format: Some(ImageFormat::Vhd),
        }),
        ..diff_opts("unused")
    };
    let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
    assert_eq!(
        plan_vhd(&opts, &mut scratch).unwrap_err(),
        CreateError::BackingFileUnsupported
    );
}
