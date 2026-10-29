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
    plan_qcow2, plan_vhd, plan_vhdx, plan_vmdk, BackingRef, CreateError, FixedVhdxPlan,
    MetadataPlan, MetadataWrite, Qcow2CreateOpts, VhdCreateOpts, VhdSubformat, VhdxCreateOpts,
    VhdxSubformat, VmdkCreateOpts, VmdkSubformat, MAX_BACKING_FILE_LEN, QCOW2_MAX_METADATA_SCRATCH,
    VHDX_MAX_METADATA_SCRATCH, VHD_MAX_METADATA_SCRATCH, VMDK_MAX_METADATA_SCRATCH,
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
                subformat: VhdxSubformat::Dynamic,
                block_state_zero: true,
                backing: None,
                parent_data_write_guid: [0u8; 16],
            };
            let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
            let plan = plan_vhdx(&opts, &mut scratch).expect("plan").metadata;
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
// vhd differencing child
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

/// Absolute file offsets of a differencing child's metadata. The locator
/// data takes the one sector between the dynamic header and the BAT —
/// where both measured Hyper-V images put it, and where `locator_defect`
/// accepts it — so the BAT moves from 1536 to 2048 for a child only.
/// Written as literals rather than derived from the planner, so a layout
/// change has to edit them.
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

/// The load-bearing test of the differencing VHD emitter: lay a
/// differencing plan's writes into a buffer and read every parent-bearing
/// structure back with `crates/vhd`'s parser.
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

    // --- layout ---------------------------------------------------------
    //
    // The locator data goes in its own sector between the dynamic header
    // and the BAT, the one placement `locator_defect`'s four rules (no
    // overlap with the head footer or the dynamic header, inside the
    // image, length within the declared space) all accept. Asserted
    // through the plan rather than only through the parser, because the
    // locator data region is new file real estate and its offset is what
    // those rules are about.
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
    // A byte count, not the sector count SPEC(VHD) implies: the sector
    // reading is arithmetically impossible on both measured Hyper-V
    // images, and nothing downstream would catch a wrong `1` here.
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
/// which is a placement the emitter must never use — and asserts the
/// parser notices.
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
/// out in the Windows convention the Hyper-V-made differencing fixtures
/// use: `/` becomes `\` and the result is prefixed `.\`, with a leading
/// `./` replaced by that prefix rather than doubled. A POSIX-absolute path
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

/// A differencing VHD is Dynamic-only. `disk_type = 4` means
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
/// `develop` at `f981374` — the last commit before the differencing
/// emitter existed.
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
/// What it protects against: the locator data region sits between the
/// dynamic header and the BAT, so moving the BAT unconditionally instead
/// of only for a differencing child is a one-character mistake that
/// silently changes the bytes of every `create -f vpc` invocation —
/// including the ones `tests/test_create.py` compares against qemu-img,
/// where the failure would look like a qemu disagreement rather than like
/// this. The `off=` columns for `w2` and `w3` are where that shows up: the
/// BAT stays at 1536.
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
/// `relative_path`, written out as the sum of the item layout (one item,
/// two entries, keys before values, no padding): 148 fixed bytes (20
/// header, two 12-byte entries, a 28-byte `parent_linkage` key and a
/// 76-byte linkage value) plus the key and the *emitted* value, which is
/// two code units longer than the typed one. Spelled as arithmetic rather
/// than as `200` so that a changed layout has to be argued with rather
/// than re-measured.
const VHDX_LOCATOR_ITEM_LEN: u32 = 148 + 2 * 13 + 2 * 13;

fn vhdx_diff_opts(path: &str) -> VhdxCreateOpts<'_> {
    VhdxCreateOpts {
        virtual_size: 1 << 30,
        block_size: 32 * 1024 * 1024,
        subformat: VhdxSubformat::Dynamic,
        block_state_zero: true,
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
    let plan = plan_vhdx(opts, &mut scratch).expect("vhdx plan").metadata;
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
/// one was written last. It is recorded here so that whoever adds an
/// overlap check later knows the check was missing, not forgotten.
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
/// than doubled — matching the Hyper-V-made differencing fixtures. A
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

/// Logical sectors a chunk group spans, and so the BAT entry count one
/// group occupies, written out from the format's own definitions rather
/// than taken from the crate whose sizing is under test here.
fn chunk_ratio_of(block_size: u32, logical_sector_size: u32) -> u64 {
    (1u64 << 23) * u64::from(logical_sector_size) / u64::from(block_size)
}

/// A differencing child's BAT region holds every entry of every chunk
/// group its virtual disk reaches into, bitmap entries included.
///
/// A group's sector bitmap entry is the **last** of the group's
/// `chunk_ratio + 1` entries, so it sits past the last payload entry
/// the virtual disk defines whenever the disk stops part way through a
/// group — which is every geometry whose block count is not an exact
/// multiple of `chunk_ratio`. An emitter that sized the region by the
/// no-parent rule (one entry per payload block, plus the bitmap entry
/// of every group but the last) leaves those bitmap entries outside
/// the region the region table declares, and a reader that honours the
/// declaration cannot reach them: the child's own sectors become
/// unresolvable.
///
/// Swept across both the block-size range and both logical sector
/// sizes `init` accepts, because `chunk_ratio` is a function of both
/// and it is `chunk_ratio` that decides how far the two rules diverge.
/// The virtual sizes deliberately include ones that are *not* a whole
/// number of groups: at an exact multiple the two rules differ only by
/// the last group's bitmap entry, which the 1 MiB region rounding
/// usually absorbs.
#[test]
fn vhdx_differencing_bat_region_holds_every_padded_entry() {
    const LOGICAL_SECTOR_SIZE: u32 = 512;
    for &block_size in &[1024u32 * 1024, 4 * 1024 * 1024, 32 * 1024 * 1024] {
        let chunk_ratio = chunk_ratio_of(block_size, LOGICAL_SECTOR_SIZE);
        for &blocks in &[1u64, 3, chunk_ratio - 1, chunk_ratio, chunk_ratio + 1] {
            let virtual_size = blocks * u64::from(block_size);
            let opts = VhdxCreateOpts {
                virtual_size,
                block_size,
                ..vhdx_diff_opts(VHDX_PARENT_PATH)
            };
            let laid = lay_out_vhdx(&opts);
            let label = format!("bsize={block_size} blocks={blocks}");

            // The region table's own declaration, not the planner's
            // intermediate: this is what a foreign reader sees.
            let declared_entries = laid.bat_len as u64 / 8;
            let groups = blocks.div_ceil(chunk_ratio);
            let padded = groups * (chunk_ratio + 1);
            assert!(
                declared_entries >= padded,
                "{label}: the BAT region declares {declared_entries} entries, \
                 short of the {padded} a differencing BAT of this geometry has",
            );

            // And specifically: the last payload block's group bitmap
            // entry is inside the declaration.
            let last_group = (blocks - 1) / chunk_ratio;
            let last_sb_index = last_group * (chunk_ratio + 1) + chunk_ratio;
            assert!(
                last_sb_index < declared_entries,
                "{label}: the last group's bitmap entry is at BAT index \
                 {last_sb_index}, outside the declared {declared_entries}",
            );
        }
    }
}

/// The geometry at which the no-parent rule's shortfall is not absorbed
/// by the 1 MiB region rounding, with the numbers written out.
///
/// Everywhere else the shortfall — at most `chunk_ratio` entries —
/// disappears into the padding `round_up(entries * 8, 1 MiB)` adds, so a
/// sweep of convenient sizes cannot tell a correctly sized region from a
/// short one. Here it can: 126 977 blocks of 1 MiB need 127 008 entries
/// by the no-parent rule (126 977 + 126 976 / 4096), which is 1 016 064
/// bytes and rounds to exactly one 1 MiB region holding 131 072 entries,
/// while the differencing rule needs 131 104 — 32 entries more than that
/// region can hold. The last
/// group's bitmap entry is at BAT index 131 103, inside the padded count
/// and outside the rounded no-parent one.
///
/// This is the case `VhdxState::init`'s `min(padded, region_entries)`
/// cap would otherwise truncate, making instar unable to resolve the
/// sector bitmaps of an image instar itself wrote.
#[test]
fn vhdx_differencing_bat_region_covers_the_last_group_bitmap() {
    const BLOCK_SIZE: u32 = 1024 * 1024;
    const BLOCKS: u64 = 126_977;
    let virtual_size = BLOCKS * u64::from(BLOCK_SIZE);

    let child = lay_out_vhdx(&VhdxCreateOpts {
        virtual_size,
        block_size: BLOCK_SIZE,
        ..vhdx_diff_opts(VHDX_PARENT_PATH)
    });
    assert_eq!(child.bat_len, 2 * 1024 * 1024);
    let declared_entries = child.bat_len as u64 / 8;
    assert_eq!(declared_entries, 262_144);

    // What `init` bounds a sector bitmap lookup by, built the way
    // `init` builds it: the padded count, capped by the declaration.
    let chunk_ratio = chunk_ratio_of(BLOCK_SIZE, 512);
    assert_eq!(chunk_ratio, 4096);
    let padded = BLOCKS.div_ceil(chunk_ratio) * (chunk_ratio + 1);
    assert_eq!(padded, 131_104);
    let bound = padded.min(declared_entries);
    assert_eq!(bound, 131_104);
    assert_eq!(
        vhdx::sb_bat_index(BLOCKS - 1, chunk_ratio as u32),
        Some(131_103)
    );
    assert!(131_103 < bound);

    // The same disk with no parent keeps the shorter region, so this
    // test is measuring the rule and not the geometry.
    let plain = lay_out_vhdx(&VhdxCreateOpts {
        virtual_size,
        block_size: BLOCK_SIZE,
        subformat: VhdxSubformat::Dynamic,
        block_state_zero: true,
        backing: None,
        parent_data_write_guid: [0u8; 16],
    });
    assert_eq!(plain.bat_len, 1024 * 1024);
    assert!(131_103 >= plain.bat_len as u64 / 8);

    // And the child's metadata region moved with its BAT, so the file
    // the planner describes is self-consistent rather than overlapping.
    assert_eq!(child.metadata_off, child.bat_off + child.bat_len);
    assert_eq!(plain.metadata_off, plain.bat_off + plain.bat_len);
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
        subformat: VhdxSubformat::Dynamic,
        block_state_zero: true,
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

/// Every byte `plan_vhdx` emits for a non-differencing VHDX: as it was
/// on `develop` at `9a80776` — the last commit before the
/// differencing emitter existed — apart from the region tables and the
/// metadata region, which have since been changed on purpose to
/// qemu-img's structure.
///
/// **How these constants were obtained, and why they mean what they
/// say.** They are not a transcription of the current tree's behaviour.
/// A detached worktree was created at `9a80776`, a throwaway integration
/// test was added there that built exactly the option matrix below and
/// wrote this summary to a file, and `make test-rust` was run in that
/// worktree. The text is that file's contents, pasted here unedited. So
/// this constant was `develop`'s output by construction, and the
/// assertion below a real comparison between two revisions rather than
/// a restatement of one.
///
/// **The one deliberate change since.** The region tables (`w3`, `w4`)
/// and the metadata region (`w5`) now carry qemu-img's structure:
/// Required clear on both region entries, qemu's metadata item order
/// and flags, and a 512-byte physical sector size. Their hashes were
/// regenerated from the tree that made that change, the same throwaway
/// way, and taken only after checking that nothing else moved: every
/// offset, length, count and the `w0` to `w2` hashes of every line are
/// still the `9a80776` values. So those columns remain a comparison
/// with `develop`, and the three moved hashes are a pin on the new
/// structure, whose fields the `vhdx` crate's builder tests compare
/// with qemu-img's field by field.
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
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=8f92a034531d7359
vhdx vsize=1048576 bsize=33554432 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=e3552ce725e31499
vhdx vsize=1048576 bsize=268435456 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=6451739a0a569b59
vhdx vsize=1073741824 bsize=1048576 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=758dd78d44a0e7d9
vhdx vsize=1073741824 bsize=33554432 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=5d3d8d7490602a99
vhdx vsize=1073741824 bsize=268435456 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=06bd2dbffc3082d9
vhdx vsize=4294967296 bsize=1048576 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=a38b5f2efdb2edb9
vhdx vsize=4294967296 bsize=33554432 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=8ce74db5139895f9
vhdx vsize=4294967296 bsize=268435456 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=784a3294b4ec15b9
vhdx vsize=1099511627776 bsize=1048576 min=12582912 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=c39db0e458e61cb4
  w4 off=262144 len=65536 h=c39db0e458e61cb4
  w5 off=11534336 len=1048576 h=5010c8c652d96a79
vhdx vsize=1099511627776 bsize=33554432 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=53e1f058082afab9
vhdx vsize=1099511627776 bsize=268435456 min=4194304 meta=1191936 writes=6
  w0 off=0 len=4096 h=1537a6cf8f243b0a
  w1 off=65536 len=4096 h=615e69c3d445c125
  w2 off=131072 len=4096 h=db3b58eb855205b3
  w3 off=196608 len=65536 h=df9c730238ed4888
  w4 off=262144 len=65536 h=df9c730238ed4888
  w5 off=3145728 len=1048576 h=24cf9c2c0a129279
";

/// A non-differencing VHDX is byte-identical to what `develop` at
/// `9a80776` produced for the same options, apart from the region
/// tables and metadata region that now follow qemu-img.
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
                subformat: VhdxSubformat::Dynamic,
                // What the create op passes. Read only for a fixed
                // image, so it must not reach this one; if it ever
                // does, a hash moves.
                block_state_zero: true,
                backing: None,
                // Read only when `backing` is `Some`, so this must not
                // reach the image. If it ever does, the w5 hashes move.
                parent_data_write_guid: VHDX_PARENT_DATA_WRITE_GUID,
            };
            let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
            let plan = plan_vhdx(&opts, &mut scratch).expect("plan");
            assert!(plan.fixed.is_none(), "a dynamic image has no fixed plan");
            let plan = plan.metadata;
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

// ---------------------------------------------------------------------------
// vhdx fixed
// ---------------------------------------------------------------------------
//
// A fixed VHDX is the plan's metadata writes, a BAT the caller streams
// through `vhdx::fill_fixed_bat`, and a file extended to the plan's
// length. Everything below builds images that way, as a guest would, and
// compares them field by field with what `qemu-img create -f vhdx -o
// subformat=fixed` writes. The expected values are copied from
// `tests/golden/qemu-create-pins.json`, whose every pinned qemu build
// agrees on them, and each table row names the pin case it came from.
// The crate tests cannot read that file (the container mounts only this
// repository, and the workspace has no JSON parser), so a change to the
// pins has to be copied here by hand.

const MIB: u64 = 1024 * 1024;

/// What a BAT index is, by the rule the comparator in
/// `tests/helpers/vhdx_structure.py` applies: padding past the entry
/// count, the last index of each group of `chunk_ratio + 1` a sector
/// bitmap slot, and every other index a payload block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BatKind {
    Payload,
    SectorBitmap,
    Padding,
}
use BatKind::{Padding, Payload, SectorBitmap};

/// One BAT run as the pin file records it: `count` entries of one kind
/// and state from index `start`, entry `start + k` at file offset
/// `offset + k * stride`. A run of one entry has stride 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PinRun {
    start: u64,
    count: u64,
    kind: BatKind,
    state: u64,
    offset: u64,
    stride: u64,
}

const fn run(
    start: u64,
    count: u64,
    kind: BatKind,
    state: u64,
    offset: u64,
    stride: u64,
) -> PinRun {
    PinRun {
        start,
        count,
        kind,
        state,
        offset,
        stride,
    }
}

/// One `vhdx-fixed-*` pin case: the options it was created with and
/// every per-case field the comparator compares. The fields every case
/// shares are the `PIN_*` constants below.
struct FixedPin {
    case: &'static str,
    virtual_size: u64,
    /// The `block_size` option, 0 when the case gave none.
    block_size: u32,
    /// The `block_state_zero` option: off for a `-bsz-off` case.
    block_state_zero: bool,
    file_length: u64,
    recorded_virtual_size: u64,
    recorded_block_size: u32,
    chunk_ratio: u64,
    bat_entry_count: u64,
    /// `repeated` occurs `repeat` times, each repeat `index_step`
    /// entries and `offset_step` bytes after the last (the pin file's
    /// `repeat`, `index_step` and first `offset_steps`), and `bat`
    /// follows the repeats.
    repeat: u64,
    index_step: u64,
    offset_step: u64,
    repeated: &'static [PinRun],
    bat: &'static [PinRun],
}

/// The ten small fixed pin cases, small enough to materialise whole:
/// the largest file is 73 MiB.
const FIXED_PINS: &[FixedPin] = &[
    FixedPin {
        case: "vhdx-fixed-16M",
        virtual_size: 16 * MIB,
        block_size: 0,
        block_state_zero: true,
        file_length: 25165824,
        recorded_virtual_size: 16777216,
        recorded_block_size: 8388608,
        chunk_ratio: 512,
        bat_entry_count: 2,
        repeat: 0,
        index_step: 0,
        offset_step: 0,
        repeated: &[],
        bat: &[
            run(0, 2, Payload, 2, 0, 0),
            run(2, 131070, Padding, 0, 0, 0),
        ],
    },
    FixedPin {
        case: "vhdx-fixed-16M-bsz-off",
        virtual_size: 16 * MIB,
        block_size: 0,
        block_state_zero: false,
        file_length: 25165824,
        recorded_virtual_size: 16777216,
        recorded_block_size: 8388608,
        chunk_ratio: 512,
        bat_entry_count: 2,
        repeat: 0,
        index_step: 0,
        offset_step: 0,
        repeated: &[],
        bat: &[
            run(0, 2, Payload, 6, 8388608, 8388608),
            run(2, 131070, Padding, 0, 0, 0),
        ],
    },
    FixedPin {
        // 17 MiB ends 1 MiB into its third 8 MiB block: the third entry
        // still names a whole block, and the file ends inside it.
        case: "vhdx-fixed-17M",
        virtual_size: 17 * MIB,
        block_size: 0,
        block_state_zero: true,
        file_length: 26214400,
        recorded_virtual_size: 17825792,
        recorded_block_size: 8388608,
        chunk_ratio: 512,
        bat_entry_count: 3,
        repeat: 0,
        index_step: 0,
        offset_step: 0,
        repeated: &[],
        bat: &[
            run(0, 3, Payload, 2, 0, 0),
            run(3, 131069, Padding, 0, 0, 0),
        ],
    },
    FixedPin {
        case: "vhdx-fixed-17M-bsz-off",
        virtual_size: 17 * MIB,
        block_size: 0,
        block_state_zero: false,
        file_length: 26214400,
        recorded_virtual_size: 17825792,
        recorded_block_size: 8388608,
        chunk_ratio: 512,
        bat_entry_count: 3,
        repeat: 0,
        index_step: 0,
        offset_step: 0,
        repeated: &[],
        bat: &[
            run(0, 3, Payload, 6, 8388608, 8388608),
            run(3, 131069, Padding, 0, 0, 0),
        ],
    },
    FixedPin {
        case: "vhdx-fixed-64M",
        virtual_size: 64 * MIB,
        block_size: 0,
        block_state_zero: true,
        file_length: 75497472,
        recorded_virtual_size: 67108864,
        recorded_block_size: 8388608,
        chunk_ratio: 512,
        bat_entry_count: 8,
        repeat: 0,
        index_step: 0,
        offset_step: 0,
        repeated: &[],
        bat: &[
            run(0, 8, Payload, 2, 0, 0),
            run(8, 131064, Padding, 0, 0, 0),
        ],
    },
    FixedPin {
        case: "vhdx-fixed-64M-bsz-off",
        virtual_size: 64 * MIB,
        block_size: 0,
        block_state_zero: false,
        file_length: 75497472,
        recorded_virtual_size: 67108864,
        recorded_block_size: 8388608,
        chunk_ratio: 512,
        bat_entry_count: 8,
        repeat: 0,
        index_step: 0,
        offset_step: 0,
        repeated: &[],
        bat: &[
            run(0, 8, Payload, 6, 8388608, 8388608),
            run(8, 131064, Padding, 0, 0, 0),
        ],
    },
    FixedPin {
        case: "vhdx-fixed-65M",
        virtual_size: 65 * MIB,
        block_size: 0,
        block_state_zero: true,
        file_length: 76546048,
        recorded_virtual_size: 68157440,
        recorded_block_size: 8388608,
        chunk_ratio: 512,
        bat_entry_count: 9,
        repeat: 0,
        index_step: 0,
        offset_step: 0,
        repeated: &[],
        bat: &[
            run(0, 9, Payload, 2, 0, 0),
            run(9, 131063, Padding, 0, 0, 0),
        ],
    },
    FixedPin {
        case: "vhdx-fixed-65M-bsz-off",
        virtual_size: 65 * MIB,
        block_size: 0,
        block_state_zero: false,
        file_length: 76546048,
        recorded_virtual_size: 68157440,
        recorded_block_size: 8388608,
        chunk_ratio: 512,
        bat_entry_count: 9,
        repeat: 0,
        index_step: 0,
        offset_step: 0,
        repeated: &[],
        bat: &[
            run(0, 9, Payload, 6, 8388608, 8388608),
            run(9, 131063, Padding, 0, 0, 0),
        ],
    },
    FixedPin {
        case: "vhdx-fixed-64M-block-1M",
        virtual_size: 64 * MIB,
        block_size: 1048576,
        block_state_zero: true,
        file_length: 75497472,
        recorded_virtual_size: 67108864,
        recorded_block_size: 1048576,
        chunk_ratio: 4096,
        bat_entry_count: 64,
        repeat: 0,
        index_step: 0,
        offset_step: 0,
        repeated: &[],
        bat: &[
            run(0, 64, Payload, 2, 0, 0),
            run(64, 131008, Padding, 0, 0, 0),
        ],
    },
    FixedPin {
        case: "vhdx-fixed-64M-block-1M-bsz-off",
        virtual_size: 64 * MIB,
        block_size: 1048576,
        block_state_zero: false,
        file_length: 75497472,
        recorded_virtual_size: 67108864,
        recorded_block_size: 1048576,
        chunk_ratio: 4096,
        bat_entry_count: 64,
        repeat: 0,
        index_step: 0,
        offset_step: 0,
        repeated: &[],
        bat: &[
            run(0, 64, Payload, 6, 8388608, 1048576),
            run(64, 131008, Padding, 0, 0, 0),
        ],
    },
];

/// `vhdx-fixed-131041M-block-1M-bsz-off`: a 128 GiB file, so it is
/// checked with only its structure in memory and the data region left
/// as the hole a sparse file would hold. 131041 blocks of 1 MiB are 31
/// whole groups of 4096 payload entries, each followed by a sector
/// bitmap slot, then 4065 entries that fill the region's last entry
/// exactly, with no padding.
const FIXED_PIN_131041M: FixedPin = FixedPin {
    case: "vhdx-fixed-131041M-block-1M-bsz-off",
    virtual_size: 131041 * MIB,
    block_size: 1048576,
    block_state_zero: false,
    file_length: 137414836224,
    recorded_virtual_size: 137406447616,
    recorded_block_size: 1048576,
    chunk_ratio: 4096,
    bat_entry_count: 131072,
    repeat: 31,
    index_step: 4097,
    offset_step: 4294967296,
    repeated: &[
        run(0, 4096, Payload, 6, 8388608, 1048576),
        run(4096, 1, SectorBitmap, 0, 0, 0),
    ],
    bat: &[run(127007, 4065, Payload, 6, 133152374784, 1048576)],
};

/// Region table entries, identical in both tables of every fixed pin
/// case: `(region GUID, offset, length, Required)`.
const PIN_REGIONS: [(&str, u64, u32, u32); 2] = [
    ("2DC27766-F623-4200-9D64-115E9BFD4A08", 2097152, 1048576, 0),
    ("8B7CA206-4790-4B9A-B8FE-575F050F886E", 3145728, 1048576, 0),
];

/// The log region every fixed pin case declares: `(offset, length)`.
const PIN_LOG: (u64, u32) = (1048576, 1048576);

/// The metadata table of every fixed pin case, in table order:
/// `(item GUID, offset in the region, length, flags)`. File Parameters
/// is IsRequired (4), the other four IsRequired | IsVirtualDisk (6).
const PIN_METADATA_ITEMS: [(&str, u32, u32, u32); 5] = [
    ("CAA16737-FA36-4D43-B3B6-33F0AA44E76B", 65536, 8, 4), // file_parameters
    ("2FA54224-CD1B-4876-B211-5DBED83BF4B8", 65544, 8, 6), // virtual_disk_size
    ("BECA12AB-B2E6-4523-93EF-C309E000C746", 65552, 16, 6), // page83
    ("8141BF1D-A96F-4709-BA47-F233A8FAAB5F", 65568, 4, 6), // logical_sector_size
    ("CDA348C7-445D-4471-9CC9-E9885251C556", 65572, 4, 6), // physical_sector_size
];

/// Logical and physical sector size of every fixed pin case.
const PIN_SECTOR_SIZES: (u32, u32) = (512, 512);

/// `bat_capacity` of every fixed pin case: a 1 MiB BAT region.
const PIN_BAT_CAPACITY: u64 = 131072;

/// A GUID's text form as the bytes VHDX stores it: the first three
/// groups little-endian, the last two in order. Written out here rather
/// than taken from the `vhdx` crate, whose item GUIDs are what is under
/// test.
fn guid_bytes_le(text: &str) -> [u8; 16] {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    assert_eq!(hex.len(), 32, "{text}");
    let mut raw = [0u8; 16];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    raw[0..4].reverse();
    raw[4..6].reverse();
    raw[6..8].reverse();
    raw
}

/// A pin's BAT as one run per range, in index order: the repeats
/// unrolled, then the rest.
fn expand_pin_runs(pin: &FixedPin) -> Vec<PinRun> {
    let mut runs = Vec::new();
    for r in 0..pin.repeat {
        for run in pin.repeated {
            runs.push(PinRun {
                start: run.start + r * pin.index_step,
                offset: if run.state == 0 {
                    run.offset
                } else {
                    run.offset + r * pin.offset_step
                },
                ..*run
            });
        }
    }
    runs.extend_from_slice(pin.bat);
    runs
}

/// Run-length encode a BAT region the way the comparator does
/// (`_parse_bat` in `tests/helpers/vhdx_structure.py`), so the result
/// compares with a pin's runs directly. The state is bits 0-2 and the
/// file offset bits 20-63, SPEC(VHDX) 2.5.1.
fn bat_runs(bat: &[u8], entry_count: u64, chunk_ratio: u64) -> Vec<PinRun> {
    let mut runs: Vec<PinRun> = Vec::new();
    for (index, raw) in bat.chunks_exact(8).enumerate() {
        let index = index as u64;
        let value = u64::from_le_bytes(raw.try_into().unwrap());
        let kind = if index >= entry_count {
            Padding
        } else if (index + 1) % (chunk_ratio + 1) == 0 {
            SectorBitmap
        } else {
            Payload
        };
        let state = value & 0x7;
        let offset = value & 0xFFFF_FFFF_FFF0_0000;
        if let Some(current) = runs.last_mut() {
            if current.kind == kind && current.state == state {
                if current.count == 1 {
                    current.stride = offset.wrapping_sub(current.offset);
                    current.count = 2;
                    continue;
                }
                if offset
                    == current
                        .offset
                        .wrapping_add(current.count.wrapping_mul(current.stride))
                {
                    current.count += 1;
                    continue;
                }
            }
        }
        runs.push(run(index, 1, kind, state, offset, 0));
    }
    runs
}

/// The first byte at which two images differ, for a failure message
/// that does not print 73 MiB of bytes.
fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .or_else(|| (a.len() != b.len()).then_some(a.len().min(b.len())))
}

/// Stream the first `upto` bytes of a fixed image's BAT into `image`
/// through a buffer of `buf_len` bytes, as a guest with one reusable
/// buffer would: fill it from the plan's layout, write it at the BAT
/// offset plus its first entry's index times 8, and advance.
fn stream_fixed_bat(image: &mut [u8], fixed: &FixedVhdxPlan, buf_len: usize, upto: u64) {
    assert_eq!(buf_len % 8, 0);
    let mut buf = vec![0xAAu8; buf_len];
    let mut done = 0u64;
    while done < upto {
        let n = (upto - done).min(buf_len as u64) as usize;
        vhdx::fill_fixed_bat(&fixed.layout, fixed.state, done / 8, &mut buf[..n])
            .expect("fill a buffer of the BAT");
        let at = (fixed.layout.bat_offset + done) as usize;
        image[at..at + n].copy_from_slice(&buf[..n]);
        done += n as u64;
    }
}

// A device for `vhdx::VhdxState` to read, as the guest's readers do. The
// image is held per test thread, and a sector past its end but inside
// the declared capacity reads as zeros, which is what a sparse file's
// hole reads as: that lets a 128 GiB fixed image be read back with only
// its structure in memory.
std::thread_local! {
    static DEVICE: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

unsafe extern "C" fn device_read_sector(
    _device: u32,
    sector: u64,
    buf: *mut u8,
    sector_size: usize,
) -> bool {
    DEVICE.with(|device| {
        let device = device.borrow();
        let start = sector as usize * sector_size;
        // SAFETY: the reader passes a buffer of at least `sector_size`
        // bytes, which is its contract with the call table.
        let out = unsafe { std::slice::from_raw_parts_mut(buf, sector_size) };
        out.fill(0);
        if start < device.len() {
            let end = (start + sector_size).min(device.len());
            out[..end - start].copy_from_slice(&device[start..end]);
        }
        true
    })
}

/// A `CallTable` whose only working entry reads [`DEVICE`]. Every other
/// entry is a stub the VHDX reader never calls. A copy of the `vhdx`
/// crate's test stub, because `shared` has no test-support surface to
/// share one from.
fn device_call_table() -> shared::CallTable {
    unsafe extern "C" fn s_get_dev_count() -> u32 {
        1
    }
    unsafe extern "C" fn s_in_cap(_: u32) -> u64 {
        0
    }
    unsafe extern "C" fn s_in_secsz(_: u32) -> usize {
        512
    }
    unsafe extern "C" fn s_write_out(_: u64, _: *const u8, _: usize) -> bool {
        false
    }
    unsafe extern "C" fn s_out_cap() -> u64 {
        0
    }
    unsafe extern "C" fn s_out_secsz() -> usize {
        512
    }
    unsafe extern "C" fn s_prog_int() -> u32 {
        100
    }
    unsafe extern "C" fn s_send_prog(_: *const u8, _: u64, _: u64, _: u32) {}
    unsafe extern "C" fn s_send_err(_: *const u8, _: *const u8, _: u64, _: u32) {}
    unsafe extern "C" fn s_send_complete(_: *const u8, _: u64, _: bool) {}
    unsafe extern "C" fn s_dbg(_: *const u8) {}
    unsafe extern "C" fn s_verb(_: *const u8) {}
    unsafe extern "C" fn s_get_op_cfg() -> shared::ConfigResult {
        shared::ConfigResult {
            ptr: core::ptr::null(),
            len: 0,
        }
    }
    unsafe extern "C" fn s_get_chain_cfg() -> shared::ConfigResult {
        shared::ConfigResult {
            ptr: core::ptr::null(),
            len: 0,
        }
    }
    unsafe extern "C" fn s_send_info(
        _: *const u8,
        _: u32,
        _: u64,
        _: u64,
        _: u32,
        _: u32,
        _: *const u8,
        _: *const u8,
    ) {
    }
    unsafe extern "C" fn s_send_info_q(
        _: *const u8,
        _: u32,
        _: u64,
        _: u64,
        _: u32,
        _: u32,
        _: *const u8,
        _: *const u8,
        _: *const shared::Qcow2Info,
    ) {
    }
    unsafe extern "C" fn s_send_info_v(
        _: *const u8,
        _: u32,
        _: u64,
        _: u64,
        _: u32,
        _: u32,
        _: *const u8,
        _: *const u8,
        _: *const shared::VmdkInfo,
    ) {
    }
    unsafe extern "C" fn s_send_info_vdi(
        _: *const u8,
        _: u32,
        _: u64,
        _: u64,
        _: u32,
        _: u32,
        _: *const u8,
        _: *const u8,
        _: *const shared::VdiInfo,
    ) {
    }
    unsafe extern "C" fn s_send_info_l(
        _: *const u8,
        _: u32,
        _: u64,
        _: u64,
        _: u32,
        _: u32,
        _: *const u8,
        _: *const u8,
        _: *const shared::LuksInfo,
    ) {
    }
    unsafe extern "C" fn s_send_check(_: *const shared::CheckResult) {}
    unsafe extern "C" fn s_send_compare(_: *const shared::CompareResult) {}
    unsafe extern "C" fn s_send_measure(_: *const shared::MeasureResult) {}
    unsafe extern "C" fn s_send_create(_: *const shared::CreateResult) {}
    unsafe extern "C" fn s_read_out(_: u64, _: *mut u8, _: usize) -> bool {
        false
    }
    unsafe extern "C" fn s_send_resize(_: *const shared::ResizeResult) {}
    unsafe extern "C" fn s_send_rebase(_: *const shared::RebaseResult) {}
    unsafe extern "C" fn s_send_commit(_: *const shared::CommitResult) {}
    unsafe extern "C" fn s_write_in(_: u32, _: u64, _: *const u8, _: usize) -> bool {
        false
    }
    unsafe extern "C" fn s_send_map_ex(_: *const shared::MapExtentRecord) {}
    unsafe extern "C" fn s_send_map_res(_: *const shared::MapResult) {}
    unsafe extern "C" fn s_send_snap_ent(_: *const shared::SnapshotEntryRecord) {}
    unsafe extern "C" fn s_send_snap_res(_: *const shared::SnapshotResult) {}
    unsafe extern "C" fn s_fsync_in(_: u32) -> bool {
        true
    }
    unsafe extern "C" fn s_send_amend(_: *const shared::AmendResult) {}
    unsafe extern "C" fn s_send_bitmap(_: *const shared::BitmapResult) {}
    unsafe extern "C" fn s_send_bench_start() {}
    unsafe extern "C" fn s_send_bench_result(_: *const shared::BenchResult) {}
    shared::CallTable {
        magic: shared::CallTable::MAGIC,
        version: shared::CallTable::VERSION,
        get_input_device_count: s_get_dev_count,
        read_input_sector: device_read_sector,
        get_input_capacity: s_in_cap,
        get_input_sector_size: s_in_secsz,
        write_output_sector: s_write_out,
        get_output_capacity: s_out_cap,
        get_output_sector_size: s_out_secsz,
        get_progress_interval: s_prog_int,
        send_progress: s_send_prog,
        send_error: s_send_err,
        send_complete: s_send_complete,
        debug_print: s_dbg,
        verbose_print: s_verb,
        get_operation_config: s_get_op_cfg,
        get_chain_config: s_get_chain_cfg,
        send_info_result: s_send_info,
        send_info_result_qcow2: s_send_info_q,
        send_info_result_vmdk: s_send_info_v,
        send_info_result_vdi: s_send_info_vdi,
        send_info_result_luks: s_send_info_l,
        send_check_result: s_send_check,
        send_compare_result: s_send_compare,
        send_measure_result: s_send_measure,
        send_create_result: s_send_create,
        read_output_sector: s_read_out,
        send_resize_result: s_send_resize,
        send_rebase_result: s_send_rebase,
        send_commit_result: s_send_commit,
        write_input_sector: s_write_in,
        send_map_extent: s_send_map_ex,
        send_map_result: s_send_map_res,
        send_snapshot_entry: s_send_snap_ent,
        send_snapshot_result: s_send_snap_res,
        fsync_input: s_fsync_in,
        send_amend_result: s_send_amend,
        send_bitmap_result: s_send_bitmap,
        send_bench_start: s_send_bench_start,
        send_bench_result: s_send_bench_result,
    }
}

/// The bytes of the plan's write at `offset`, read from the write itself
/// rather than from a materialised image: at 64 TiB the metadata region
/// ends 516 MiB into the file.
fn write_at<'a>(plan: &MetadataPlan<'a>, offset: u64) -> &'a [u8] {
    plan.writes()
        .iter()
        .find(|w| w.byte_offset == offset)
        .unwrap_or_else(|| panic!("no write at {offset}"))
        .bytes
}

/// Plan a pin case's image.
fn plan_fixed_pin<'a>(pin: &FixedPin, scratch: &'a mut [u8]) -> (MetadataPlan<'a>, FixedVhdxPlan) {
    let opts = VhdxCreateOpts {
        virtual_size: pin.virtual_size,
        block_size: pin.block_size,
        subformat: VhdxSubformat::Fixed,
        block_state_zero: pin.block_state_zero,
        backing: None,
        parent_data_write_guid: [0u8; 16],
    };
    let plan = plan_vhdx(&opts, scratch).expect(pin.case);
    let fixed = plan.fixed.expect("a fixed image has a fixed plan");
    assert_plan_invariants(&plan.metadata);
    (plan.metadata, fixed)
}

/// Check the plan's own numbers against the pin, before any image is
/// built: the BAT bytes it asks the caller to stream, the length it asks
/// the file to reach, and that its metadata writes end where the
/// metadata region ends, as a dynamic plan's do.
fn check_fixed_plan(pin: &FixedPin, metadata: &MetadataPlan<'_>, fixed: &FixedVhdxPlan) {
    let case = pin.case;
    assert_eq!(
        fixed.layout.bat_entries as u64, pin.bat_entry_count,
        "{case}"
    );
    assert_eq!(
        fixed.bat_bytes,
        fixed.layout.bat_entries as u64 * 8,
        "{case}"
    );
    assert_eq!(fixed.bat_bytes, pin.bat_entry_count * 8, "{case}");
    assert_eq!(fixed.file_length, pin.file_length, "{case}");
    assert_eq!(fixed.file_length, fixed.layout.fixed_file_length, "{case}");
    let (_, metadata_offset, metadata_len, _) = PIN_REGIONS[1];
    assert_eq!(
        metadata.minimum_file_size,
        metadata_offset + u64::from(metadata_len),
        "{case}: the metadata writes end at the end of the metadata region",
    );
    assert_eq!(
        metadata.minimum_file_size, fixed.layout.data_start,
        "{case}"
    );
}

/// Read a fixed image back, structure by structure, and compare every
/// field the comparator compares with the pin. `image` holds the file
/// from offset 0, and `file_length` is the file's length, which may run
/// past `image` into a hole.
fn check_fixed_image(pin: &FixedPin, image: &[u8], file_length: u64) {
    let case = pin.case;
    assert_eq!(file_length, pin.file_length, "{case}: file length");

    // File identifier, and both headers with the log they declare.
    let sig = u64::from_le_bytes(image[..8].try_into().unwrap());
    assert_eq!(sig, vhdx::FILE_IDENTIFIER_SIGNATURE, "{case}");
    let header_at = |offset: u64| {
        vhdx::VhdxHeader::parse(&image[offset as usize..offset as usize + vhdx::HEADER_SIZE])
            .expect("parse header")
    };
    let (h1, h2) = (
        header_at(vhdx::HEADER1_OFFSET),
        header_at(vhdx::HEADER2_OFFSET),
    );
    let active = if h1.sequence_number >= h2.sequence_number {
        h1
    } else {
        h2
    };
    assert_eq!(
        (active.log_offset, active.log_length),
        PIN_LOG,
        "{case}: log"
    );

    // Both region tables, which must agree byte for byte.
    let table_at = |offset: u64| &image[offset as usize..offset as usize + 65536];
    let rt1 = table_at(vhdx::REGION_TABLE1_OFFSET);
    assert!(
        rt1 == table_at(vhdx::REGION_TABLE2_OFFSET),
        "{case}: region tables disagree"
    );
    let (entries, count) = vhdx::parse_region_table(rt1).expect("parse region table");
    assert_eq!(count, 2, "{case}: region table entry count");
    for (entry, (guid, offset, length, required)) in entries.iter().zip(PIN_REGIONS) {
        assert_eq!(entry.guid, guid_bytes_le(guid), "{case}");
        assert_eq!(
            (entry.file_offset, entry.length, entry.required),
            (offset, length, required),
            "{case}: region {guid}",
        );
    }
    let [bat, metadata] = entries;

    // The metadata table, entry by entry, and the values its items hold.
    let region = &image[metadata.file_offset as usize..][..metadata.length as usize];
    let table = walk_metadata_table(region);
    assert_eq!(
        table.len(),
        PIN_METADATA_ITEMS.len(),
        "{case}: metadata items"
    );
    for (entry, (guid, offset, length, flags)) in table.iter().zip(PIN_METADATA_ITEMS) {
        assert_eq!(entry.item_id, guid_bytes_le(guid), "{case}: item order");
        assert_eq!(
            (entry.offset, entry.length, entry.flags),
            (offset, length, flags),
            "{case}: metadata item {guid}",
        );
    }
    let items = vhdx::parse_metadata_region(region).expect("parse metadata region");
    assert_eq!(items.block_size, pin.recorded_block_size, "{case}");
    assert_eq!(items.virtual_disk_size, pin.recorded_virtual_size, "{case}");
    assert_eq!(
        (items.logical_sector_size, items.physical_sector_size),
        PIN_SECTOR_SIZES,
        "{case}: sector sizes",
    );
    assert!(
        items.leave_blocks_allocated,
        "{case}: LeaveBlocksAllocated must be set on a fixed image",
    );
    assert!(!items.has_parent, "{case}: HasParent");

    // The BAT as runs, padding and sector bitmap slots included.
    let bat_bytes = &image[bat.file_offset as usize..][..bat.length as usize];
    assert_eq!(
        bat_bytes.len() as u64 / 8,
        PIN_BAT_CAPACITY,
        "{case}: BAT capacity"
    );
    assert_eq!(
        bat_runs(bat_bytes, pin.bat_entry_count, pin.chunk_ratio),
        expand_pin_runs(pin),
        "{case}: BAT runs",
    );

    // And through the reader the operations use: every payload block's
    // lookup must land where the pin's run says it is.
    let call_table = device_call_table();
    let mut bat_cache = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut data_cache = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut bytes_read = 0u64;
    let capacity = file_length / 512;
    DEVICE.with(|device| device.replace(image.to_vec()));
    // SAFETY: both cache buffers are MAX_SECTOR_SIZE bytes and outlive
    // the state, and the call table's reader serves DEVICE.
    let mut state = unsafe {
        vhdx::VhdxState::init(
            &call_table,
            0,
            512,
            capacity,
            bat_cache.as_mut_ptr(),
            data_cache.as_mut_ptr(),
            &mut bytes_read,
        )
    }
    .expect("the reader opens the image");
    assert_eq!(state.block_size, pin.recorded_block_size, "{case}");
    assert_eq!(state.virtual_disk_size, pin.recorded_virtual_size, "{case}");
    assert_eq!(state.logical_sector_size, PIN_SECTOR_SIZES.0, "{case}");
    assert_eq!(u64::from(state.chunk_ratio), pin.chunk_ratio, "{case}");
    assert_eq!(
        u64::from(state.total_bat_entries),
        pin.bat_entry_count,
        "{case}"
    );
    assert_eq!(state.bat_offset, PIN_REGIONS[0].1, "{case}");
    assert!(!state.has_parent, "{case}");

    let block_size = u64::from(pin.recorded_block_size);
    let mut lookup = |virtual_offset: u64| {
        // SAFETY: as for `init` above.
        unsafe { state.block_lookup(&call_table, virtual_offset, 512, capacity, &mut bytes_read) }
    };
    let mut block = 0u64;
    for run in expand_pin_runs(pin).iter().filter(|r| r.kind == Payload) {
        for k in 0..run.count {
            let first = block * block_size;
            let last = (first + block_size).min(pin.recorded_virtual_size) - 1;
            for virtual_offset in [first, last] {
                let got = lookup(virtual_offset);
                match run.state {
                    2 => assert!(
                        matches!(got, Some(vhdx::VhdxBlockLookup::Zero)),
                        "{case}: block {block} at {virtual_offset}: {got:?}",
                    ),
                    6 => {
                        let want = run.offset + k * run.stride + (virtual_offset - first);
                        assert!(
                            matches!(
                                got,
                                Some(vhdx::VhdxBlockLookup::Present { host_byte_offset })
                                    if host_byte_offset == want
                            ),
                            "{case}: block {block} at {virtual_offset}: {got:?}, want {want}",
                        );
                    }
                    other => panic!("{case}: the pin has a payload run in state {other}"),
                }
            }
            block += 1;
        }
    }
    assert_eq!(
        block,
        pin.recorded_virtual_size.div_ceil(block_size),
        "{case}: payload blocks the reader was asked about",
    );
    DEVICE.with(|device| device.take());
}

/// Every small fixed pin case, built as a guest would build it and read
/// back field by field.
///
/// The BAT is streamed into an image already extended to the plan's
/// file length three ways: the whole region through a 512-byte buffer,
/// the whole region through a 64 KiB one, and only the entries'
/// `bat_bytes` through 64 KiB, leaving the padding as the hole the plan
/// says it may stay. All three files must be identical, which catches an
/// entry lost or doubled at a buffer edge, where one whole-region fill
/// could not. Each file is then compared with the pin.
#[test]
fn vhdx_fixed_round_trips_match_qemu_pins() {
    for pin in FIXED_PINS {
        let case = pin.case;
        let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
        let (metadata, fixed) = plan_fixed_pin(pin, &mut scratch);
        check_fixed_plan(pin, &metadata, &fixed);

        let mut base = materialise(&metadata);
        base.resize(fixed.file_length as usize, 0);
        let region = u64::from(fixed.layout.bat_region_len);

        let mut small = base.clone();
        stream_fixed_bat(&mut small, &fixed, 512, region);
        let mut large = base.clone();
        stream_fixed_bat(&mut large, &fixed, 64 * 1024, region);
        assert_eq!(
            first_difference(&small, &large),
            None,
            "{case}: 512-byte and 64 KiB buffers wrote different files",
        );
        drop(large);
        let mut entries_only = base;
        stream_fixed_bat(&mut entries_only, &fixed, 64 * 1024, fixed.bat_bytes);
        assert_eq!(
            first_difference(&small, &entries_only),
            None,
            "{case}: leaving the padding as a hole wrote a different file",
        );
        drop(entries_only);

        check_fixed_image(pin, &small, small.len() as u64);
    }
}

/// `vhdx-fixed-131041M-block-1M-bsz-off`, whose BAT has a sector bitmap
/// slot after every 4096 entries and ends exactly at the region's last
/// entry. Only the structure is materialised: the data region of a
/// 128 GiB file is a hole, and the reader is told the file's real
/// length.
#[test]
fn vhdx_fixed_131041m_round_trip_matches_its_qemu_pin() {
    let pin = &FIXED_PIN_131041M;
    let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
    let (metadata, fixed) = plan_fixed_pin(pin, &mut scratch);
    check_fixed_plan(pin, &metadata, &fixed);

    let mut small = materialise(&metadata);
    let region = u64::from(fixed.layout.bat_region_len);
    stream_fixed_bat(&mut small, &fixed, 512, region);
    let mut large = materialise(&metadata);
    stream_fixed_bat(&mut large, &fixed, 64 * 1024, region);
    assert_eq!(
        first_difference(&small, &large),
        None,
        "buffer sizes disagree"
    );

    check_fixed_image(pin, &small, fixed.file_length);
}

/// The two geometries too large to pin: 2 TiB and 64 TiB at 1 MiB
/// blocks, where the BAT region grows past 1 MiB and moves the metadata
/// region and qemu's data start with it. The values are the ones the
/// `vhdx` crate's filler tests carry: 2 TiB's 24 MiB data start was
/// measured with qemu-img 10.0.13, and 64 TiB's 520 MiB is computed
/// from qemu's rule. What this adds is that the plan hands the caller
/// that same layout, and that its metadata writes end where the moved
/// metadata region does. The entries are sampled at the edges of the
/// first group and the last, not streamed.
#[test]
fn vhdx_fixed_plan_at_the_largest_geometries() {
    // (virtual size, BAT entries, BAT region length, fixed data start,
    // file length, index of the last group's first entry)
    let cases: [(u64, u64, u32, u64, u64, u64); 2] = [
        (
            2 * 1024 * 1024 * MIB,
            2097663,
            17825792,
            25165824,
            2199048421376,
            2093567,
        ),
        (
            64 * 1024 * 1024 * MIB,
            67125247,
            537919488,
            545259520,
            70369289437184,
            67121151,
        ),
    ];
    for (virtual_size, entries, region_len, data_start, file_length, last_group) in cases {
        let opts = VhdxCreateOpts {
            virtual_size,
            block_size: 1024 * 1024,
            subformat: VhdxSubformat::Fixed,
            block_state_zero: false,
            backing: None,
            parent_data_write_guid: [0u8; 16],
        };
        let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
        let plan = plan_vhdx(&opts, &mut scratch).expect("plan");
        assert_plan_invariants(&plan.metadata);
        let fixed = plan.fixed.expect("fixed plan");
        let label = format!("vsize={virtual_size}");
        assert_eq!(fixed.layout.bat_entries as u64, entries, "{label}");
        assert_eq!(fixed.bat_bytes, entries * 8, "{label}");
        assert_eq!(fixed.layout.bat_region_len, region_len, "{label}");
        assert_eq!(fixed.layout.fixed_data_start, data_start, "{label}");
        assert_eq!(fixed.file_length, file_length, "{label}");
        let metadata_end = 2 * MIB + u64::from(region_len) + MIB;
        assert_eq!(plan.metadata.minimum_file_size, metadata_end, "{label}");

        // The emitted region table declares the BAT the filler sizes.
        let rt = write_at(&plan.metadata, vhdx::REGION_TABLE1_OFFSET);
        let ([bat, metadata], _) = vhdx::parse_region_table(rt).expect("parse region table");
        assert_eq!(
            (bat.file_offset, bat.length),
            (2 * MIB, region_len),
            "{label}"
        );
        assert_eq!(
            metadata.file_offset,
            2 * MIB + u64::from(region_len),
            "{label}"
        );

        let entry_at = |index: u64| {
            let mut out = [0u8; 8];
            vhdx::fill_fixed_bat(&fixed.layout, fixed.state, index, &mut out).expect("fill");
            u64::from_le_bytes(out)
        };
        let present = |block: u64| (data_start + block * MIB) | 6;
        assert_eq!(entry_at(0), present(0), "{label}: first entry");
        assert_eq!(
            entry_at(4095),
            present(4095),
            "{label}: end of the first group"
        );
        assert_eq!(entry_at(4096), 0, "{label}: the first sector bitmap slot");
        assert_eq!(
            entry_at(4097),
            present(4096),
            "{label}: start of the second group"
        );
        let last_group_block = last_group - last_group / 4097;
        assert_eq!(entry_at(last_group), present(last_group_block), "{label}");
        assert_eq!(
            entry_at(entries - 1),
            present(virtual_size / MIB - 1),
            "{label}: the last entry is the last block",
        );
        assert_eq!(entry_at(entries), 0, "{label}: the first padding entry");
    }
}

/// A fixed plan's metadata writes are a dynamic plan's with one bit
/// changed, File Parameters `LeaveBlocksAllocated`, and the dynamic
/// plan's is clear. The writes are compared byte for byte, so the bit
/// cannot be set on both, cleared on both, or joined by any other
/// difference. `block_state_zero` reaches neither: it chooses the state
/// of BAT entries the caller streams, not anything the writes hold.
#[test]
fn vhdx_fixed_metadata_differs_from_dynamic_only_in_leave_blocks_allocated() {
    let mut geometries: Vec<(u64, u32)> = FIXED_PINS
        .iter()
        .chain([&FIXED_PIN_131041M])
        .map(|pin| (pin.virtual_size, pin.block_size))
        .collect();
    geometries.extend([
        (1 << 40, 32 * 1024 * 1024),
        (vhdx::MAX_VIRTUAL_SIZE, 1024 * 1024),
    ]);

    for (virtual_size, block_size) in geometries {
        let label = format!("vsize={virtual_size} bsize={block_size}");
        let opts = |subformat, block_state_zero| VhdxCreateOpts {
            virtual_size,
            block_size,
            subformat,
            block_state_zero,
            backing: None,
            parent_data_write_guid: [0u8; 16],
        };
        let mut dynamic_scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
        let dynamic = plan_vhdx(&opts(VhdxSubformat::Dynamic, true), &mut dynamic_scratch)
            .expect("dynamic plan");
        assert!(dynamic.fixed.is_none(), "{label}");
        let dynamic = dynamic.metadata;

        for (subformat, block_state_zero) in [
            (VhdxSubformat::Dynamic, false),
            (VhdxSubformat::Fixed, true),
            (VhdxSubformat::Fixed, false),
        ] {
            let label = format!("{label} {subformat:?} block_state_zero={block_state_zero}");
            let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
            let other = plan_vhdx(&opts(subformat, block_state_zero), &mut scratch)
                .expect("plan")
                .metadata;
            assert_eq!(
                other.minimum_file_size, dynamic.minimum_file_size,
                "{label}"
            );
            assert_eq!(
                other.total_metadata_bytes, dynamic.total_metadata_bytes,
                "{label}"
            );
            assert_eq!(other.writes().len(), dynamic.writes().len(), "{label}");

            let mut differences = Vec::new();
            for (want, got) in dynamic.writes().iter().zip(other.writes()) {
                assert_eq!(want.byte_offset, got.byte_offset, "{label}");
                assert_eq!(want.bytes.len(), got.bytes.len(), "{label}");
                for (i, (a, b)) in want.bytes.iter().zip(got.bytes).enumerate() {
                    if a != b {
                        differences.push((want.byte_offset + i as u64, *a, *b));
                    }
                }
            }

            if subformat == VhdxSubformat::Dynamic {
                assert_eq!(differences, [], "{label}");
                continue;
            }
            // The File Parameters item's flags word, found through the
            // dynamic plan's own region table and metadata table.
            let rt = write_at(&dynamic, vhdx::REGION_TABLE1_OFFSET);
            let ([_, metadata], _) = vhdx::parse_region_table(rt).expect("parse region table");
            let region = write_at(&dynamic, metadata.file_offset);
            let file_parameters = walk_metadata_table(region)
                .into_iter()
                .find(|e| e.item_id == guid_bytes_le(PIN_METADATA_ITEMS[0].0))
                .expect("a File Parameters item");
            let flags_at = metadata.file_offset + u64::from(file_parameters.offset) + 4;
            assert_eq!(
                differences,
                [(flags_at, 0x00, 0x01)],
                "{label}: the only difference is LeaveBlocksAllocated, clear for \
                 dynamic and set for fixed",
            );
        }
    }
}
