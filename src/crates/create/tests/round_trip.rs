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
                parent_data_write_guid: [0u8; 16],
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

/// [`DIFF_PARENT_PATH`] as the **locator** carries it.
///
/// `W2ru` is a Windows-defined platform code, so a relative path is
/// emitted in the Windows convention the measured Hyper-V fixtures use:
/// separators flipped and a leading `.\`
/// ([PLAN-differencing.md](docs/plans/PLAN-differencing.md)). The parent
/// unicode name field 1024 bytes earlier keeps [`DIFF_PARENT_PATH`]
/// itself — the tests below assert both, because the two fields
/// deliberately disagree now.
const DIFF_PARENT_PATH_EMITTED: &str = r".\parent.vhd";

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
        (DIFF_PARENT_PATH_EMITTED.len() * 2) as u32,
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
    assert_eq!(&path[..n], DIFF_PARENT_PATH_EMITTED.as_bytes());

    // --- the two endiannesses, against raw bytes --------------------------
    //
    // The single most valuable assertion here. The parent unicode name is
    // UTF-16 BIG endian and the locator platform data is UTF-16 LITTLE
    // endian, 1024 bytes apart in the same image, and an emitter that used
    // one encoder for both would still round-trip through instar's own
    // parser if the parser were wrong in the same direction. These compare
    // against bytes written out by hand.
    //
    // The two fields also carry *different paths* now: the name field is
    // the path as typed and the locator is the Windows rendering, so the
    // first characters differ as well as their byte order.
    let name_field = DIFF_DYN_HEADER_OFF + 64;
    assert_eq!(
        &bytes[name_field..name_field + 6],
        // 'p' 'a' 'r', high byte first — the typed path, not `.\p`.
        &[0x00, b'p', 0x00, b'a', 0x00, b'r'],
        "the parent unicode name must be UTF-16 big endian, and as typed",
    );
    assert_eq!(
        &bytes[DIFF_LOCATOR_DATA_OFF..DIFF_LOCATOR_DATA_OFF + 6],
        // '.' '\' 'p', low byte first.
        &[b'.', 0x00, b'\\', 0x00, b'p', 0x00],
        "the locator platform data must be UTF-16 little endian",
    );

    // The locator data region is one sector, and the bytes past the path
    // are zero padding rather than anything left over.
    assert!(
        bytes[DIFF_LOCATOR_DATA_OFF + DIFF_PARENT_PATH_EMITTED.len() * 2..DIFF_BAT_OFF as usize]
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

/// The locator path of a materialised differencing child, decoded.
fn locator_path(bytes: &[u8]) -> Vec<u8> {
    let bounds = diff_bounds(bytes);
    let info = vhd::VhdParentInfo::parse(dyn_header(bytes), &bounds).expect("parse parent info");
    let window = vhd::VhdImageWindow {
        file_offset: 0,
        bytes,
    };
    let mut out = [0u8; vhd::MAX_PARENT_NAME_UTF8];
    let n = info.locators.entries[0]
        .decode_path(&window, &mut out)
        .expect("decode locator path");
    out[..n].to_vec()
}

/// The parent unicode name of a materialised differencing child, decoded.
fn parent_unicode_name(bytes: &[u8]) -> Vec<u8> {
    let bounds = diff_bounds(bytes);
    let info = vhd::VhdParentInfo::parse(dyn_header(bytes), &bounds).expect("parse parent info");
    let mut out = [0u8; vhd::MAX_PARENT_NAME_UTF8];
    let n = info.decode_name(&mut out).expect("decode parent name");
    out[..n].to_vec()
}

/// The path *bytes* the `W2ru` locator carries, for every shape of
/// relative input — and the `W2ku` one, which is not normalised.
///
/// `W2ru` is a Windows-defined platform code, so a relative path goes
/// out in the Windows convention the phase 3 Hyper-V fixtures use: `/`
/// becomes `\` and the result is prefixed `.\`, with a leading `./`
/// replaced by that prefix rather than doubled. A POSIX-absolute path
/// has no honest `W2ku` rendering, so it keeps its bytes — see
/// [PLAN-differencing.md](docs/plans/PLAN-differencing.md).
///
/// Every case also asserts the parent unicode name is untouched. That
/// field is the one qemu's `block/vpc.c` and libvhdi actually resolve a
/// parent through, and normalising it would break both oracles; an
/// emitter that normalised once and used the result for both fields
/// would pass every locator assertion here.
#[test]
fn vhd_differencing_relative_locator_paths_are_windows_rendered() {
    for (typed, emitted) in [
        ("parent.vhd", r".\parent.vhd"),
        ("./parent.vhd", r".\parent.vhd"),
        ("sub/dir/parent.vhd", r".\sub\dir\parent.vhd"),
        ("../parent.vhd", r".\..\parent.vhd"),
        ("./sub/parent.vhd", r".\sub\parent.vhd"),
        // Absolute: verbatim, forward slashes and all.
        ("/srv/images/parent.vhd", "/srv/images/parent.vhd"),
        ("/parent.vhd", "/parent.vhd"),
    ] {
        let bytes = materialise_differencing(typed);
        assert_eq!(
            locator_path(&bytes),
            emitted.as_bytes(),
            "locator path for {typed:?}",
        );
        assert_eq!(
            parent_unicode_name(&bytes),
            typed.as_bytes(),
            "the parent unicode name must stay as typed for {typed:?}",
        );
    }
}

/// The length cap on a *relative* parent path, as `plan_vhd` surfaces it.
///
/// The boundary itself is `crates/vhd`'s and is tested there against the
/// builder. What this adds is that `plan_vhd` neither re-derives the limit
/// nor swallows the refusal: an over-length parent path comes back as
/// [`CreateError::ParentNameTooLong`] and not as `BackingFileTooLong`,
/// whose host message names a 1024-byte limit that has nothing to do with
/// the 512-byte field that actually overflowed.
///
/// # Why the boundary is 254 and not 255
///
/// Two fields carry the path and they now hold different strings, so
/// there are two caps and the smaller one binds:
///
/// * the parent unicode name field takes the path **as typed** and stops
///   at 255 UTF-16 code units, leaving a terminating NUL inside its 512
///   bytes;
/// * the locator platform data takes the path **normalised** — two code
///   units longer for a bare relative name — into a one-sector region,
///   which holds 256 code units and needs no terminator because
///   `platform_data_length` delimits it.
///
/// So a relative path of 254 typed code units emits a 256-code-unit
/// locator that exactly fills the sector, and 255 no longer fits.
/// [`vhd_differencing_absolute_path_length_boundary`] is the same
/// boundary for an absolute path, which is not normalised and so still
/// stops at the name field's 255.
#[test]
fn vhd_differencing_parent_name_length_boundary() {
    // 254 typed code units, `.\` and 508 bytes in the name field; 256
    // code units and all 512 bytes of the locator sector.
    let fits = "a".repeat(254);
    let bytes = materialise_differencing(&fits);
    let bounds = diff_bounds(&bytes);
    let info = vhd::VhdParentInfo::parse(dyn_header(&bytes), &bounds).expect("parse parent info");
    let mut name = [0u8; vhd::MAX_PARENT_NAME_UTF8];
    let n = info.decode_name(&mut name).expect("decode parent name");
    assert_eq!(&name[..n], fits.as_bytes(), "the name field is as typed");
    assert_eq!(info.locators.entries[0].platform_data_length, 512);
    // A full sector is still a sound entry: the locator's length is
    // declared, not terminated, and 512 is exactly its declared space.
    assert_eq!(info.locators.entries[0].platform_data_space, 512);
    assert_eq!(info.locators.entries[0].defect, None);

    // 255 fits the name field and overflows the locator sector once
    // normalised. It is the same condition — a path too long for the
    // format's parent path fields — so it is the same error.
    let over = "a".repeat(255);
    let opts = diff_opts(&over);
    let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
    assert_eq!(
        plan_vhd(&opts, &mut scratch).err(),
        Some(CreateError::ParentNameTooLong),
    );
}

/// An absolute path is emitted verbatim, so its cap is the parent
/// unicode name field's 255 UTF-16 code units, unchanged.
///
/// The companion to [`vhd_differencing_parent_name_length_boundary`]:
/// the two limits differ by exactly the two code units normalisation
/// adds, and a test that only exercised the relative case could not tell
/// a changed limit from a changed normalisation.
#[test]
fn vhd_differencing_absolute_path_length_boundary() {
    // 255 code units is 510 bytes, leaving the last code unit of the
    // 512-byte name field zero so a terminating NUL stays inside it.
    let fits = format!("/{}", "a".repeat(254));
    assert_eq!(fits.len(), 255);
    let bytes = materialise_differencing(&fits);
    let bounds = diff_bounds(&bytes);
    let info = vhd::VhdParentInfo::parse(dyn_header(&bytes), &bounds).expect("parse parent info");
    let mut name = [0u8; vhd::MAX_PARENT_NAME_UTF8];
    let n = info.decode_name(&mut name).expect("decode parent name");
    assert_eq!(&name[..n], fits.as_bytes());
    assert_eq!(info.locators.entries[0].platform_data_length, 510);

    // 256 would fill all 512 bytes of the name field with no terminator
    // — libvhdi then reads past the field into the locator table and
    // appends a stray character to the parent filename it reports.
    let over = format!("/{}", "a".repeat(255));
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
    // 127 surrogate pairs is 254 code units in the name field. The
    // locator carries `.\` as well, so it is 256 code units and 512
    // bytes — the odd code unit the name field leaves spare is exactly
    // what the two-character prefix needs, which is why 127 is still the
    // largest emoji count that fits.
    assert_eq!(info.locators.entries[0].platform_data_length, 512);

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
        // The longest relative path the emitter now accepts (the
        // locator's 256 code units less the two `.\` adds), and the
        // longest absolute one (the name field's own 255).
        "a".repeat(254),
        format!("/{}", "a".repeat(254)),
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

// ---------------------------------------------------------------------------
// vhdx differencing child
// ---------------------------------------------------------------------------
//
// Everything below covers `plan_vhdx` with a backing reference. The
// per-field raw-byte assertions for `vhdx::build_parent_locator` live in
// that crate's own unit tests; what these add is that `plan_vhdx` calls
// it with the right arguments, that the metadata table it leaves behind
// describes the item it actually wrote, and that a non-differencing image
// is untouched by any of it.

/// The parent `DataWriteGuid` measured from a real Hyper-V parent in
/// `docs/plans/PLAN-differencing-phase-01-pin.md`, whose child's
/// `parent_linkage` was measured to be [`VHDX_PARENT_LINKAGE`].
///
/// Used here rather than an invented constant because the bytes_le
/// rendering reorders the first eight bytes, and a renderer that read
/// them in stored order would still produce a plausible-looking GUID.
/// Only the measured pair catches that.
const VHDX_PARENT_DATA_WRITE_GUID: [u8; 16] = [
    0x92, 0x4d, 0x8d, 0xf8, 0xcc, 0x6f, 0x8d, 0x40, 0x9b, 0xef, 0x9b, 0x7c, 0x89, 0xf1, 0x5c, 0x89,
];

/// The braced rendering of [`VHDX_PARENT_DATA_WRITE_GUID`], as measured
/// from the child Hyper-V wrote for that parent.
const VHDX_PARENT_LINKAGE: &[u8] = b"{f88d4d92-6fcc-408d-9bef-9b7c89f15c89}";

/// A relative parent path: relative selects `relative_path`.
const VHDX_PARENT_PATH: &str = "parent.vhdx";

/// [`VHDX_PARENT_PATH`] as the `relative_path` value carries it.
///
/// `relative_path` is as Windows-defined as VHD's `W2ru`, so a relative
/// path is emitted in the Windows convention the measured Hyper-V
/// fixtures use — see
/// [PLAN-differencing.md](docs/plans/PLAN-differencing.md).
const VHDX_PARENT_PATH_EMITTED: &str = r".\parent.vhdx";

/// The item's exact length for [`VHDX_PARENT_PATH`] under
/// `relative_path`, written out as the sum decision 5 of the phase plan
/// gives: 148 fixed bytes (20 header, two 12-byte entries, a 28-byte
/// `parent_linkage` key and a 76-byte linkage value) plus the key and
/// the *emitted* value, which is two code units longer than the typed
/// one. Spelled as arithmetic rather than as `200` so that a changed
/// layout has to be argued with rather than re-measured.
const VHDX_LOCATOR_ITEM_LEN: u32 = 148 + 2 * 13 + 2 * 13;

fn vhdx_diff_opts(path: &str) -> VhdxCreateOpts<'_> {
    VhdxCreateOpts {
        virtual_size: 1 << 30,
        block_size: 32 * 1024 * 1024,
        backing: Some(BackingRef {
            path: path.as_bytes(),
            format: Some(ImageFormat::Vhdx),
        }),
        parent_data_write_guid: VHDX_PARENT_DATA_WRITE_GUID,
    }
}

/// A materialised VHDX, plus the two things the file's own region table
/// says about where its regions live.
struct LaidOutVhdx {
    bytes: Vec<u8>,
    /// `(byte_offset, len)` for every write the plan pushed.
    writes: Vec<(u64, u64)>,
    metadata_off: usize,
    metadata_len: usize,
    bat_off: usize,
    bat_len: usize,
}

impl LaidOutVhdx {
    /// The metadata region, starting at the metadata table signature —
    /// the frame every offset in this section is relative to.
    fn metadata(&self) -> &[u8] {
        &self.bytes[self.metadata_off..self.metadata_off + self.metadata_len]
    }
}

/// Plan, check the structural invariants, lay the writes into a buffer,
/// and read the region table back to find out where the regions are.
///
/// The region offsets are taken from the emitted region table rather
/// than recomputed here, so a test asserting something "at metadata +
/// 0x10028" is asserting it at the offset a reader would actually go to.
fn lay_out_vhdx(opts: &VhdxCreateOpts<'_>) -> LaidOutVhdx {
    let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
    let plan = plan_vhdx(opts, &mut scratch).expect("vhdx plan");
    assert_plan_invariants(&plan);
    let writes: Vec<(u64, u64)> = plan
        .writes()
        .iter()
        .map(|w| (w.byte_offset, w.bytes.len() as u64))
        .collect();
    let bytes = materialise(&plan);

    let rt_start = vhdx::REGION_TABLE1_OFFSET as usize;
    let (regions, _entry_count) =
        vhdx::parse_region_table(&bytes[rt_start..rt_start + 65536]).expect("parse region table");

    LaidOutVhdx {
        metadata_off: regions[1].file_offset as usize,
        metadata_len: regions[1].length as usize,
        bat_off: regions[0].file_offset as usize,
        bat_len: regions[0].length as usize,
        writes,
        bytes,
    }
}

/// One metadata table entry, read field by field out of the region.
#[derive(Clone, Copy, Debug)]
struct MetadataTableEntry {
    item_id: [u8; 16],
    offset: u32,
    length: u32,
    flags: u32,
    reserved2: u32,
}

/// Walk the metadata table by hand: a 32-byte header whose LE u16 at
/// offset 10 is the entry count, then that many 32-byte entries.
///
/// Deliberately not `vhdx::parse_metadata`, which wants a call table and
/// a device to read through and which only looks at the items it needs.
/// A hand walk is what a foreign reader does, and it is the only way to
/// see the entries the emitter wrote as *entries* rather than as the
/// four values instar's own consumer extracts.
fn walk_metadata_table(region: &[u8]) -> Vec<MetadataTableEntry> {
    assert_eq!(
        u64::from_le_bytes(region[..8].try_into().unwrap()),
        vhdx::METADATA_TABLE_SIGNATURE,
        "metadata table signature",
    );
    let count = u16::from_le_bytes(region[10..12].try_into().unwrap()) as usize;
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let e = vhdx::METADATA_TABLE_HEADER_SIZE + i * vhdx::METADATA_TABLE_ENTRY_SIZE;
        let mut item_id = [0u8; 16];
        item_id.copy_from_slice(&region[e..e + 16]);
        entries.push(MetadataTableEntry {
            item_id,
            offset: u32::from_le_bytes(region[e + 16..e + 20].try_into().unwrap()),
            length: u32::from_le_bytes(region[e + 20..e + 24].try_into().unwrap()),
            flags: u32::from_le_bytes(region[e + 24..e + 28].try_into().unwrap()),
            reserved2: u32::from_le_bytes(region[e + 28..e + 32].try_into().unwrap()),
        });
    }
    entries
}

/// The parent locator table entry, and the bytes it *declares*.
///
/// The item is sliced at the entry's own `Offset` and `Length`, never at
/// `vhdx::PARENT_LOCATOR_ITEM_OFFSET`. That is the whole point of going
/// through the table: an entry that points somewhere the item is not is
/// a broken image, and a test that reached past the entry to the
/// emitter's own constant would read the item back perfectly while the
/// entry lied about it.
fn locator_entry_and_item(region: &[u8]) -> (MetadataTableEntry, &[u8]) {
    let entries = walk_metadata_table(region);
    let entry = *entries
        .iter()
        .find(|e| e.item_id == vhdx::PARENT_LOCATOR_GUID)
        .expect("a parent locator entry in the metadata table");
    let start = entry.offset as usize;
    let end = start + entry.length as usize;
    assert!(end <= region.len(), "locator item runs past the region");
    (entry, &region[start..end])
}

/// Every pair of declared item ranges that overlaps.
///
/// SPEC(VHDX) 2.6.1.2 forbids overlapping metadata items, and nothing in
/// this tree checks it — `vhdx::parse_metadata` reads each item at the
/// offset its entry gives and never compares two of them. So this is the
/// check that makes the placement assertions non-vacuous, and it is the
/// control `vhdx_differencing_locator_misplacement_is_detected` trips.
fn overlapping_item_ranges(entries: &[MetadataTableEntry]) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    for (i, a) in entries.iter().enumerate() {
        for (j, b) in entries.iter().enumerate().skip(i + 1) {
            let a_end = a.offset as u64 + a.length as u64;
            let b_end = b.offset as u64 + b.length as u64;
            if (a.offset as u64) < b_end && (b.offset as u64) < a_end {
                found.push((i, j));
            }
        }
    }
    found
}

/// The load-bearing test: lay a differencing plan's writes into a
/// buffer, walk the metadata table the way a foreign reader would, and
/// read the item the table points at back with this tree's own parser.
///
/// It is *necessary and not sufficient* — emitter and parser share their
/// offset constants, so this alone could pass with both halves wrong in
/// the same direction. Three things make it more than a tautology. The
/// table walk here is hand-written against SPEC(VHDX) 2.6.1.2's layout
/// rather than shared with the emitter; the item is sliced at the offset
/// and length the *entry* declares, so the entry and the item are pinned
/// to each other; and `parent_linkage` is compared against a string
/// measured from Hyper-V, not against anything this tree renders.
#[test]
fn vhdx_differencing_round_trips_through_the_parser() {
    let laid = lay_out_vhdx(&vhdx_diff_opts(VHDX_PARENT_PATH));
    let region = laid.metadata();

    // --- the table ------------------------------------------------------
    let entries = walk_metadata_table(region);
    assert_eq!(entries.len(), 6, "five built-in items plus the locator");
    assert!(
        overlapping_item_ranges(&entries).is_empty(),
        "metadata items must not overlap: {:?}",
        entries,
    );

    let (entry, item) = locator_entry_and_item(region);
    assert_eq!(
        entry.offset,
        vhdx::PARENT_LOCATOR_ITEM_OFFSET,
        "the locator item goes immediately above the five built-in items",
    );
    assert_eq!(entry.offset, 0x10028, "and that address is 0x10028");
    assert_eq!(entry.length, VHDX_LOCATOR_ITEM_LEN, "item length");
    assert_eq!(entry.flags, 0x0000_0004, "IsRequired, and nothing else");
    assert_eq!(entry.reserved2, 0);
    // The locator is the *last* entry: appending must not have displaced
    // an item `build_metadata` wrote.
    assert_eq!(entries[5].item_id, vhdx::PARENT_LOCATOR_GUID);

    // --- File Parameters ------------------------------------------------
    //
    // Read straight out of the region rather than through the table, so
    // that a locator written over the top of File Parameters could not
    // pass by having moved the entry too.
    let fp_flags = u32::from_le_bytes(region[0x10004..0x10008].try_into().unwrap());
    assert_eq!(fp_flags, 0x0000_0002, "HasParent");

    // --- the item -------------------------------------------------------
    let locator = vhdx::parse_parent_locator(item).expect("parse parent locator");
    assert_eq!(locator.defect, None, "emitted item must be defect-free");
    assert!(locator.is_vhdx_locator_type());
    assert_eq!(locator.reserved, 0);
    assert_eq!(locator.key_value_count, 2);
    assert_eq!(locator.entries().len(), 2);
    for e in locator.entries() {
        assert_eq!(e.defect, None, "entry {:?} has a defect", e.key());
    }

    assert_eq!(locator.parent_linkage(), Some(VHDX_PARENT_LINKAGE));
    assert!(locator.linkage_matches(VHDX_PARENT_LINKAGE));
    assert_eq!(
        locator.preferred_path(),
        Some(VHDX_PARENT_PATH_EMITTED.as_bytes()),
        "preferred_path is the caller's path, in the Windows convention \
         `relative_path` is defined in",
    );

    // The strings are UTF-16 *little* endian with no terminator — the
    // opposite endianness to VHD's parent name field. Checked against a
    // hand-built expectation rather than through the parser, which would
    // byte-swap in sympathy with an emitter that got this wrong.
    let linkage = locator
        .entries()
        .iter()
        .find(|e| e.key() == b"parent_linkage")
        .expect("parent_linkage entry");
    let want: Vec<u8> = VHDX_PARENT_LINKAGE.iter().flat_map(|&c| [c, 0u8]).collect();
    let start = linkage.value_offset as usize;
    assert_eq!(&item[start..start + want.len()], &want[..]);
    assert_eq!(linkage.value_length as usize, want.len());
    // Not big endian: the first code unit is '{' then a zero pad.
    assert_eq!(&item[start..start + 2], b"{\0");
}

/// The negative control for the placement assertions above, and an
/// honest record of which half of the check actually does the work.
///
/// The same emitted bytes are taken and only the locator's placement is
/// changed: the item is moved down to `0x10000`, where the five items
/// `build_metadata` wrote already live, and the table entry is updated
/// to point at it. SPEC(VHDX) 2.6.1.2 forbids exactly that.
///
/// **The table walk catches it; the parser does not, and cannot.**
/// `vhdx::parse_parent_locator` is handed the item's own bytes and
/// nothing else — every offset it reads is item-relative — so it has no
/// way to know where in the region those bytes came from or what else is
/// there. `vhdx::parse_metadata` does see the whole region, and does not
/// check for overlap either. That is a real gap in this tree's reader
/// rather than something this test papers over: an image whose items
/// overlap is read back as sound, and the item that wins is whichever
/// one was written last. It is recorded here so that a later phase
/// adding an overlap check knows the check was missing, not forgotten.
#[test]
fn vhdx_differencing_locator_misplacement_is_detected() {
    let laid = lay_out_vhdx(&vhdx_diff_opts(VHDX_PARENT_PATH));
    let mut region = laid.metadata().to_vec();

    // Before: sound, and the item sits above the built-in items.
    assert!(overlapping_item_ranges(&walk_metadata_table(&region)).is_empty());

    let (entry, item) = locator_entry_and_item(&region);
    let item = item.to_vec();
    assert_eq!(entry.offset, vhdx::PARENT_LOCATOR_ITEM_OFFSET);

    // Move it on top of the built-in items, entry and body together, so
    // that the image is internally consistent and only its *placement*
    // is wrong. The entry's Offset is the LE u32 at +16 of entry index
    // five.
    let dst = vhdx::METADATA_ITEMS_MIN_OFFSET as usize;
    region[dst..dst + item.len()].copy_from_slice(&item);
    let e = vhdx::METADATA_TABLE_HEADER_SIZE + 5 * vhdx::METADATA_TABLE_ENTRY_SIZE;
    region[e + 16..e + 20].copy_from_slice(&(dst as u32).to_le_bytes());

    // The table walk fires: the locator now overlaps all five.
    let entries = walk_metadata_table(&region);
    let overlaps = overlapping_item_ranges(&entries);
    assert_eq!(
        overlaps.len(),
        5,
        "a locator at 0x10000 overlaps every built-in item: {:?}",
        overlaps,
    );
    assert!(overlaps.iter().all(|&(_, j)| j == 5));

    // The parser does not, per this test's doc comment. Asserted rather
    // than only described, so that the claim is checked.
    let (moved_entry, moved_item) = locator_entry_and_item(&region);
    assert_eq!(moved_entry.offset, dst as u32);
    let locator = vhdx::parse_parent_locator(moved_item).expect("parse parent locator");
    assert_eq!(
        locator.defect, None,
        "parse_parent_locator sees only item-relative offsets, so a \
         misplaced item still reads as sound",
    );
    assert_eq!(locator.parent_linkage(), Some(VHDX_PARENT_LINKAGE));
}

/// The path key is chosen from the path the user typed, exactly one path
/// key is written, and the key decides the value's bytes.
///
/// A relative path goes out in the Windows convention `relative_path` is
/// defined in — `/` to `\`, leading `.\`, a leading `./` replaced rather
/// than doubled — matching the phase 3 Hyper-V fixtures. A
/// POSIX-absolute path has no honest `absolute_win32_path` rendering and
/// keeps its bytes; see
/// [PLAN-differencing.md](docs/plans/PLAN-differencing.md).
///
/// Checked against the raw UTF-16LE key bytes as well as through the
/// parser: `preferred_path` prefers `relative_path`, so a emitter that
/// wrote both keys would satisfy the parser-side assertions alone.
#[test]
fn vhdx_differencing_path_key_follows_the_path() {
    for (path, emitted, want_key, absolute) in [
        (
            "parent.vhdx",
            r".\parent.vhdx",
            &b"relative_path"[..],
            false,
        ),
        (
            "./parent.vhdx",
            r".\parent.vhdx",
            &b"relative_path"[..],
            false,
        ),
        (
            "../parent.vhdx",
            r".\..\parent.vhdx",
            &b"relative_path"[..],
            false,
        ),
        (
            "images/parent.vhdx",
            r".\images\parent.vhdx",
            &b"relative_path"[..],
            false,
        ),
        (
            "sub/dir/parent.vhdx",
            r".\sub\dir\parent.vhdx",
            &b"relative_path"[..],
            false,
        ),
        (
            "/srv/images/parent.vhdx",
            "/srv/images/parent.vhdx",
            &b"absolute_win32_path"[..],
            true,
        ),
    ] {
        let laid = lay_out_vhdx(&vhdx_diff_opts(path));
        let region = laid.metadata();
        let (_entry, item) = locator_entry_and_item(region);
        let locator = vhdx::parse_parent_locator(item).expect("parse parent locator");
        assert_eq!(locator.defect, None, "{path}");

        // Exactly two entries: parent_linkage and one path key.
        assert_eq!(locator.entries().len(), 2, "{path}");
        let keys: Vec<&[u8]> = locator.entries().iter().map(|e| e.key()).collect();
        assert_eq!(keys, vec![&b"parent_linkage"[..], want_key], "{path}");

        if absolute {
            assert_eq!(locator.relative_path(), None, "{path}");
            assert_eq!(
                locator.absolute_win32_path(),
                Some(emitted.as_bytes()),
                "{path}",
            );
        } else {
            assert_eq!(locator.relative_path(), Some(emitted.as_bytes()), "{path}");
            assert_eq!(locator.absolute_win32_path(), None, "{path}");
        }
        assert_eq!(locator.volume_path(), None, "instar never writes it");
        assert_eq!(locator.preferred_path(), Some(emitted.as_bytes()), "{path}");

        // And the same, from the raw bytes at the offset the entry
        // declares, so the key is not merely what the parser decoded.
        let path_entry = locator.entries()[1];
        let key_start = path_entry.key_offset as usize;
        let raw: Vec<u8> = want_key.iter().flat_map(|&c| [c, 0u8]).collect();
        assert_eq!(
            &item[key_start..key_start + raw.len()],
            &raw[..],
            "{path}: raw key bytes",
        );
        assert_eq!(path_entry.key_length as usize, raw.len(), "{path}");
    }
}

/// The 260-UTF-16-code-unit cap, as `plan_vhdx` surfaces it.
///
/// The boundary itself belongs to `vhdx::build_parent_locator` and is
/// tested there. What this adds is that `plan_vhdx` neither re-derives
/// the limit nor swallows the refusal: an over-length path comes back as
/// [`CreateError::ParentNameTooLong`] and not as `BackingFileTooLong`,
/// whose host message names a 1024-byte limit that has nothing to do
/// with the value field that actually overflowed. 261 bytes is well
/// under `MAX_BACKING_FILE_LEN`, so the length check it passes on the
/// way is real.
///
/// # Why the relative boundary is 258 and not 260
///
/// The cap is 260 code units on the string that is **emitted**, and a
/// relative path is emitted two code units longer than it was typed. So
/// 258 typed characters fill the field exactly and 259 overflow it —
/// which is the whole point of normalising before the length check
/// rather than after. `vhdx_differencing_absolute_path_length_boundary`
/// pins the unnormalised case at the unchanged 260.
#[test]
fn vhdx_differencing_parent_path_length_boundary() {
    let fits = "a".repeat(258);
    assert!(fits.len() < MAX_BACKING_FILE_LEN);
    let laid = lay_out_vhdx(&vhdx_diff_opts(&fits));
    let (entry, item) = locator_entry_and_item(laid.metadata());
    let locator = vhdx::parse_parent_locator(item).expect("parse parent locator");
    assert_eq!(locator.defect, None);
    let emitted = format!(r".\{fits}");
    assert_eq!(locator.relative_path(), Some(emitted.as_bytes()));
    assert_eq!(entry.length, 148 + 2 * 13 + 2 * 260);

    let over = "a".repeat(259);
    assert!(over.len() < MAX_BACKING_FILE_LEN);
    let opts = vhdx_diff_opts(&over);
    let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
    assert_eq!(
        plan_vhdx(&opts, &mut scratch).unwrap_err(),
        CreateError::ParentNameTooLong,
    );
}

/// An absolute path is emitted verbatim, so its cap is
/// `vhdx::build_parent_locator`'s unchanged 260 UTF-16 code units.
///
/// The companion to [`vhdx_differencing_parent_path_length_boundary`]:
/// the two limits differ by exactly the two code units normalisation
/// adds, and a test that only exercised the relative case could not tell
/// a changed limit from a changed normalisation.
#[test]
fn vhdx_differencing_absolute_path_length_boundary() {
    let fits = format!("/{}", "a".repeat(259));
    assert_eq!(fits.len(), 260);
    let laid = lay_out_vhdx(&vhdx_diff_opts(&fits));
    let (entry, item) = locator_entry_and_item(laid.metadata());
    let locator = vhdx::parse_parent_locator(item).expect("parse parent locator");
    assert_eq!(locator.defect, None);
    assert_eq!(locator.absolute_win32_path(), Some(fits.as_bytes()));
    assert_eq!(entry.length, 148 + 2 * 19 + 2 * 260);

    let over = format!("/{}", "a".repeat(260));
    let opts = vhdx_diff_opts(&over);
    let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
    assert_eq!(
        plan_vhdx(&opts, &mut scratch).unwrap_err(),
        CreateError::ParentNameTooLong,
    );
}

/// A differencing child's BAT region is a hole, and the plan says so by
/// containing no write for it at all.
///
/// Zero is `PAYLOAD_BLOCK_NOT_PRESENT` for every payload entry and
/// `SB_BLOCK_NOT_PRESENT` for every sector-bitmap entry, which is what
/// SPEC(VHDX) 2.5.1.1 says a child with no blocks of its own should say.
/// So the correct emitter does nothing here — and "we did nothing and it
/// is correct" is indistinguishable from "we forgot" unless a test
/// states which one it is. Swept across geometries because the BAT's
/// size, and so the metadata region's offset, moves with them.
#[test]
fn vhdx_differencing_bat_region_is_untouched() {
    for &virtual_size in &[1u64 << 20, 1 << 30, 1 << 32, 1 << 40] {
        for &block_size in &[1024u32 * 1024, 32 * 1024 * 1024, 256 * 1024 * 1024] {
            let opts = VhdxCreateOpts {
                virtual_size,
                block_size,
                ..vhdx_diff_opts(VHDX_PARENT_PATH)
            };
            let laid = lay_out_vhdx(&opts);
            let label = format!("vsize={virtual_size} bsize={block_size}");

            // No write touches the BAT region.
            let bat_start = laid.bat_off as u64;
            let bat_end = bat_start + laid.bat_len as u64;
            for &(off, len) in &laid.writes {
                assert!(
                    off + len <= bat_start || off >= bat_end,
                    "{label}: a write at {off}+{len} lands in the BAT region \
                     [{bat_start}, {bat_end})",
                );
            }

            // And the bytes there are zero, which is what a plan with no
            // write for the region leaves behind.
            assert!(
                laid.bytes[laid.bat_off..laid.bat_off + laid.bat_len]
                    .iter()
                    .all(|&b| b == 0),
                "{label}: BAT region is not all zero",
            );

            // The locator still landed, so this is a differencing child
            // and not an accidentally plain image.
            let (entry, _item) = locator_entry_and_item(laid.metadata());
            assert_eq!(entry.offset, vhdx::PARENT_LOCATOR_ITEM_OFFSET, "{label}");
        }
    }
}

/// Without a backing reference the metadata region is what it always
/// was: five entries, no locator, and the File Parameters `HasParent`
/// bit clear.
///
/// The byte-for-byte case is
/// [`vhdx_non_differencing_output_matches_develop`]; this one names the
/// three facts that matter, so a failure says which one moved.
#[test]
fn vhdx_non_differencing_metadata_is_unchanged() {
    let opts = VhdxCreateOpts {
        virtual_size: 1 << 30,
        block_size: 32 * 1024 * 1024,
        backing: None,
        // Read only when `backing` is `Some`. If it ever leaks into a
        // plain image, the golden test's w5 hashes move too.
        parent_data_write_guid: VHDX_PARENT_DATA_WRITE_GUID,
    };
    let laid = lay_out_vhdx(&opts);
    let region = laid.metadata();

    let entries = walk_metadata_table(region);
    assert_eq!(entries.len(), 5);
    assert!(entries
        .iter()
        .all(|e| e.item_id != vhdx::PARENT_LOCATOR_GUID));

    let fp_flags = u32::from_le_bytes(region[0x10004..0x10008].try_into().unwrap());
    assert_eq!(fp_flags, 0x0000_0000, "HasParent must be clear");

    // Nothing was written where the locator would have gone.
    let at = vhdx::PARENT_LOCATOR_ITEM_OFFSET as usize;
    assert!(
        region[at..at + 256].iter().all(|&b| b == 0),
        "bytes above the built-in items must stay zero",
    );
}

/// Every byte `plan_vhdx` emits for a non-differencing VHDX, as it was
/// on `develop` at `9a80776` — the commit this phase branched from,
/// before the differencing emitter existed.
///
/// **How these constants were obtained, and why they mean what they
/// say.** They are not a transcription of the current tree's behaviour.
/// A detached worktree was created at `9a80776`, a throwaway integration
/// test was added there that built exactly the option matrix below and
/// wrote this summary to a file, and `make test-rust` was run in that
/// worktree. The text is that file's contents, pasted here unedited. So
/// this constant is `develop`'s output by construction, and the
/// assertion below is a real comparison between two revisions rather
/// than a restatement of one.
///
/// **What it covers, and what it does not.** Each line pins a write's
/// offset, its length, and an FNV-1a-64 hash of every byte in it — so
/// any change to a header, the region table or the metadata region's
/// million bytes moves a hash, including a locator item accidentally
/// appended to an image with no parent, or a `HasParent` bit set from a
/// stale flag. It does not describe *what* changed: a moved hash says
/// only that the write differs, and the tests above are what say which
/// field. Writes the plan does not contain are invisible to it, which is
/// why [`vhdx_differencing_bat_region_is_untouched`] checks the BAT
/// separately.
///
/// If a deliberate change to the non-differencing layout is ever made,
/// regenerate this the same way — from the revision being compared
/// against, not from the tree being changed.
const GOLDEN_VHDX_NO_BACKING: &str = "\
vhdx vsize=1048576 bsize=1048576 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=f453e6adb1c76eb7
vhdx vsize=1048576 bsize=33554432 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=a45cd5f5e059c5b7
vhdx vsize=1048576 bsize=268435456 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=773dcb7b76224c97
vhdx vsize=1073741824 bsize=1048576 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=a7b7f7b24fef2bf7
vhdx vsize=1073741824 bsize=33554432 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=2f3d8d61f724b177
vhdx vsize=1073741824 bsize=268435456 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=4ada37caddcbc7d7
vhdx vsize=4294967296 bsize=1048576 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=da3222834184bf4b
vhdx vsize=4294967296 bsize=33554432 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=469ada16440e3f83
vhdx vsize=4294967296 bsize=268435456 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=18c37434941d7f2b
vhdx vsize=1099511627776 bsize=1048576 min=12582912 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=42e5e0b0ed731f4c
  w4 off=262144 len=65536 h=42e5e0b0ed731f4c
  w5 off=11534336 len=1048576 h=50b5dbdb4cf425b7
vhdx vsize=1099511627776 bsize=33554432 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=00becb237b867cb7
vhdx vsize=1099511627776 bsize=268435456 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=25cd95f303fcd318
  w4 off=262144 len=65536 h=25cd95f303fcd318
  w5 off=3145728 len=1048576 h=d39fc0a9114f0397
";

/// A non-differencing VHDX is byte-identical to what `develop` at
/// `9a80776` produced for the same options.
///
/// See [`GOLDEN_VHDX_NO_BACKING`] for how the expected text was produced
/// and for what the hashes do and do not cover.
#[test]
fn vhdx_non_differencing_output_matches_develop() {
    let mut out = String::new();

    let sizes: &[u64] = &[1 << 20, 1 << 30, 1 << 32, 1 << 40];
    let block_sizes: &[u32] = &[1024 * 1024, 32 * 1024 * 1024, 256 * 1024 * 1024];
    for &virtual_size in sizes {
        for &block_size in block_sizes {
            let opts = VhdxCreateOpts {
                virtual_size,
                block_size,
                backing: None,
                // Read only when `backing` is `Some`, so this must not
                // reach the image. If it ever does, the w5 hashes move.
                parent_data_write_guid: VHDX_PARENT_DATA_WRITE_GUID,
            };
            let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
            let plan = plan_vhdx(&opts, &mut scratch).expect("plan");
            summarise_plan(
                &format!("vhdx vsize={virtual_size} bsize={block_size}"),
                &plan,
                &mut out,
            );
        }
    }

    // Line by line first: the whole-string comparison below is what the
    // test is, but its failure output is one escaped block of text, and
    // the interesting difference is almost always a single `h=` column.
    for (i, (got, want)) in out.lines().zip(GOLDEN_VHDX_NO_BACKING.lines()).enumerate() {
        assert_eq!(got, want, "golden line {} differs", i + 1);
    }
    assert_eq!(
        out.lines().count(),
        GOLDEN_VHDX_NO_BACKING.lines().count(),
        "golden line count differs",
    );
    assert_eq!(out, GOLDEN_VHDX_NO_BACKING);
}
