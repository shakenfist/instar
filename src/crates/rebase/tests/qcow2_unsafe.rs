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
use qcow2::{parse_header_extensions, QcowHeader};
use rebase::{plan_rebase_qcow2, Qcow2RebaseOpts, Qcow2RebaseOutput, RebaseError, RebaseMode};
use shared::{BackingFormat, ImageFormat};

const CLUSTER_SIZE: u32 = 65536;
const VIRTUAL_SIZE: u64 = 1 << 20;

fn build_overlay(backing_path: &[u8]) -> Vec<u8> {
    build_overlay_recording(backing_path, ImageFormat::Qcow2)
}

fn build_overlay_recording(backing_path: &[u8], format: ImageFormat) -> Vec<u8> {
    build_overlay_with(backing_path, Some(format))
}

fn build_overlay_with(backing_path: &[u8], format: Option<ImageFormat>) -> Vec<u8> {
    let opts = Qcow2CreateOpts {
        virtual_size: VIRTUAL_SIZE,
        cluster_size: CLUSTER_SIZE,
        refcount_bits: 16,
        extended_l2: false,
        lazy_refcounts: false,
        compat_v3: true,
        backing: Some(BackingRef {
            path: backing_path,
            format,
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
        new_backing_format_name: b"",
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
        new_backing_format_name: b"",
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
        new_backing_format_name: b"",
    };
    let mut scratch = vec![0u8; 64 * 1024];
    let err = plan_rebase_qcow2(&opts, &mut scratch).expect_err("expected rejection");
    assert_eq!(err, RebaseError::BackingPathTooLong);
}

// ---------------------------------------------------------------------
// The recorded backing format
// ---------------------------------------------------------------------
//
// `build_overlay` bakes a `qcow2` backing-format extension into
// every fixture here, so each of these starts from an overlay
// that records `qcow2` and is rebased onto something else.

#[test]
fn rebase_records_the_new_backing_format() {
    // The defect this closes: the overlay went on recording
    // `qcow2` after being rebased onto a raw backing, and a
    // reader that trusts the field refuses such an overlay
    // outright ("Image is not in qcow2 format").
    let mut bytes = build_overlay(b"old.qcow2");
    let header = QcowHeader::parse(&bytes).expect("parse pre");
    assert_eq!(
        parse_header_extensions(&bytes, &header).backing_format,
        BackingFormat::Qcow2
    );

    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Unsafe,
        overlay_header: &bytes[..4096],
        overlay_file_size: bytes.len() as u64,
        refcount_table: &[],
        refblock_host_offsets: &[],
        refcount_blocks: &[],
        refblock_count: 0,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: b"new.raw00",
        detach: false,
        new_backing_format_name: b"raw",
    };
    // Dirty scratch, because the guest's is: `PLANNER_SCRATCH` is a
    // fixed region of guest memory that previous work has written to,
    // never a fresh zeroed allocation. A zero-filled buffer here made
    // the record's padding look right whether the planner wrote it or
    // not, which is what the mutation check for that line caught.
    let mut scratch = vec![0xccu8; 64 * 1024];
    let out = plan_rebase_qcow2(&opts, &mut scratch).expect("rebase plan");
    let plan = match out {
        Qcow2RebaseOutput::Unsafe { plan } => plan,
        Qcow2RebaseOutput::Safe { .. } => panic!("expected Unsafe"),
    };
    apply_rebase(&mut bytes, &plan);

    let header_post = QcowHeader::parse(&bytes).expect("parse post");
    let exts_post = parse_header_extensions(&bytes, &header_post);
    assert_eq!(exts_post.backing_format, BackingFormat::Raw);
    assert_eq!(exts_post.backing_format_len, 3);
    // The name is rewritten out to its padded width, so no byte
    // of `qcow2` survives inside the `raw` record -- the two
    // trailing bytes of the old name sat where the padding now
    // is, and a reader honouring a longer length would read
    // `raw` plus whatever was left.
    let data = exts_post.backing_format_offset;
    assert_eq!(&bytes[data..data + 8], b"raw\0\0\0\0\0");
    // The record keeps its padded width, so every extension
    // behind it stays where it was. The bitmaps/feature-table
    // records that follow are what would be lost if it moved,
    // and the walk below reaching the same backing-file pointer
    // is what proves the chain still parses.
    assert_eq!(parsed_path(&bytes, &header_post), b"new.raw00");
}

#[test]
fn a_caller_with_no_format_to_state_leaves_the_record_alone() {
    // Empty is "I do not know", not "raw". Writing a guess here
    // would be worse than the stale value: the stale value is at
    // least what the previous backing was.
    let mut bytes = build_overlay(b"old.qcow2");
    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Unsafe,
        overlay_header: &bytes[..4096],
        overlay_file_size: bytes.len() as u64,
        refcount_table: &[],
        refblock_host_offsets: &[],
        refcount_blocks: &[],
        refblock_count: 0,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: b"new.qcow2",
        detach: false,
        new_backing_format_name: b"",
    };
    let mut scratch = vec![0u8; 64 * 1024];
    let out = plan_rebase_qcow2(&opts, &mut scratch).expect("rebase plan");
    let plan = match out {
        Qcow2RebaseOutput::Unsafe { plan } => plan,
        Qcow2RebaseOutput::Safe { .. } => panic!("expected Unsafe"),
    };
    apply_rebase(&mut bytes, &plan);
    let header_post = QcowHeader::parse(&bytes).expect("parse post");
    assert_eq!(
        parse_header_extensions(&bytes, &header_post).backing_format,
        BackingFormat::Qcow2
    );
}

#[test]
fn an_overlay_that_records_no_format_keeps_recording_none() {
    // `qemu-img create -b` without `-F` writes no backing-format
    // extension at all. There is no slot to rewrite, and adding one
    // would move every extension behind it, so the record stays
    // absent: the planner writes the path and the header fields and
    // nothing else. This branch writes nothing, so only a test tells
    // "left alone on purpose" from "the record lookup broke".
    let mut bytes = build_overlay_with(b"old.qcow2", None);
    let header = QcowHeader::parse(&bytes).expect("parse pre");
    let exts = parse_header_extensions(&bytes, &header);
    assert_eq!(exts.backing_format, BackingFormat::None);
    assert_eq!(exts.backing_format_offset, 0);
    // Everything between the fixed header and the backing path is
    // the extension area; none of it may change.
    let ext_area = header.header_length as usize..header.backing_file_offset as usize;
    let before = bytes[ext_area.clone()].to_vec();

    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Unsafe,
        overlay_header: &bytes[..4096],
        overlay_file_size: bytes.len() as u64,
        refcount_table: &[],
        refblock_host_offsets: &[],
        refcount_blocks: &[],
        refblock_count: 0,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: b"new.raw00",
        detach: false,
        new_backing_format_name: b"raw",
    };
    let mut scratch = vec![0xccu8; 64 * 1024];
    let out = plan_rebase_qcow2(&opts, &mut scratch).expect("rebase plan");
    let plan = match out {
        Qcow2RebaseOutput::Unsafe { plan } => plan,
        Qcow2RebaseOutput::Safe { .. } => panic!("expected Unsafe"),
    };
    apply_rebase(&mut bytes, &plan);

    let header_post = QcowHeader::parse(&bytes).expect("parse post");
    assert_eq!(parsed_path(&bytes, &header_post), b"new.raw00");
    assert_eq!(
        parse_header_extensions(&bytes, &header_post).backing_format,
        BackingFormat::None
    );
    assert_eq!(&bytes[ext_area], &before[..]);
}

#[test]
fn a_name_that_would_move_the_extensions_is_refused() {
    // `parallels` is nine bytes, so its record would pad to 16
    // where `qcow2` pads to 8: recording it in place would move
    // every extension behind it. A rebase onto a Parallels backing
    // reaches this without `-F`, since discovery names the format;
    // the alternative to refusing is a corrupt extension chain, and
    // the alternative to recording is a stale `qcow2` record.
    let bytes = build_overlay(b"old.qcow2");
    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Unsafe,
        overlay_header: &bytes[..4096],
        overlay_file_size: bytes.len() as u64,
        refcount_table: &[],
        refblock_host_offsets: &[],
        refcount_blocks: &[],
        refblock_count: 0,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: b"new.qcow2",
        detach: false,
        new_backing_format_name: b"parallels",
    };
    let mut scratch = vec![0u8; 64 * 1024];
    assert_eq!(
        plan_rebase_qcow2(&opts, &mut scratch).err(),
        Some(RebaseError::BackingFormatSlotWidth)
    );
}

#[test]
fn the_widest_name_is_rewritten_in_its_own_slot() {
    // `parallels` pads to 16, the one name that does not fit an
    // 8-byte slot, and it is what `BACKING_FORMAT_REWRITE_MAX` is
    // sized for. An overlay that already records it -- `qemu-img
    // create -F parallels` writes one -- can still be rebased onto
    // another Parallels backing; it is a width *change* that is
    // refused, which the second half pins.
    for (name, expected) in [
        // `BackingFormat` has no Parallels member, so the parsed enum
        // says only "not one we know"; the bytes are the real check.
        (&b"parallels"[..], Ok(BackingFormat::Unknown)),
        (&b"raw"[..], Err(RebaseError::BackingFormatSlotWidth)),
    ] {
        let mut bytes = build_overlay_recording(b"old.hdd", ImageFormat::Parallels);
        let header = QcowHeader::parse(&bytes).expect("parse pre");
        assert_eq!(
            parse_header_extensions(&bytes, &header).backing_format_len,
            9
        );
        let header_bytes = bytes[..4096].to_vec();
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Unsafe,
            overlay_header: &header_bytes,
            overlay_file_size: bytes.len() as u64,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: VIRTUAL_SIZE,
            new_backing_path: b"new.hdd",
            detach: false,
            new_backing_format_name: name,
        };
        let mut scratch = vec![0xccu8; 64 * 1024];
        match (plan_rebase_qcow2(&opts, &mut scratch), expected) {
            (Ok(Qcow2RebaseOutput::Unsafe { plan }), Ok(format)) => {
                apply_rebase(&mut bytes, &plan);
                let header_post = QcowHeader::parse(&bytes).expect("parse post");
                let exts = parse_header_extensions(&bytes, &header_post);
                assert_eq!(exts.backing_format, format);
                assert_eq!(exts.backing_format_len, 9);
                let data = exts.backing_format_offset;
                assert_eq!(&bytes[data..data + 16], b"parallels\0\0\0\0\0\0\0");
                assert_eq!(parsed_path(&bytes, &header_post), b"new.hdd");
            }
            (Err(e), Err(want)) => assert_eq!(e, want),
            (got, want) => panic!("{name:?}: got {:?}, want {want:?}", got.err()),
        }
    }
}

#[test]
fn a_backing_name_overlapping_the_format_record_is_refused() {
    // `compute_path_target` bounds the path bytes to "after the
    // fixed header, inside the first cluster" and deliberately does
    // not walk the extensions, so a header that aims its backing
    // name at the format record passes that bound. Both writes are
    // then planned over the same bytes, and the record patch is
    // pushed last: without a disjointness check it would silently
    // overwrite the path the plan had just written. No header qemu
    // or instar writes looks like this -- the name goes down after
    // the extension chain -- so refusing costs nothing a real image
    // needs.
    let mut bytes = build_overlay(b"old.qcow2");
    let header = QcowHeader::parse(&bytes).expect("parse");
    let exts = parse_header_extensions(&bytes, &header);
    assert!(
        exts.backing_format_offset != 0,
        "the fixture must record a backing format"
    );
    // The record's length word, which is where the patch starts.
    let aimed = exts.backing_format_offset as u64 - 4;
    bytes[8..16].copy_from_slice(&aimed.to_be_bytes());
    bytes[16..20].copy_from_slice(&9u32.to_be_bytes());

    let header_bytes = bytes[..4096].to_vec();
    let opts = Qcow2RebaseOpts {
        mode: RebaseMode::Unsafe,
        overlay_header: &header_bytes,
        overlay_file_size: bytes.len() as u64,
        refcount_table: &[],
        refblock_host_offsets: &[],
        refcount_blocks: &[],
        refblock_count: 0,
        new_backing_virtual_size: VIRTUAL_SIZE,
        new_backing_path: b"new.qcow2",
        detach: false,
        new_backing_format_name: b"raw",
    };
    let mut scratch = vec![0xccu8; 64 * 1024];
    assert_eq!(
        plan_rebase_qcow2(&opts, &mut scratch).err(),
        Some(RebaseError::HeaderMismatch)
    );
}

#[test]
fn a_detach_does_not_touch_the_recorded_format() {
    // There is no backing left to describe, and qemu-img leaves
    // the record alone too.
    let mut bytes = build_overlay(b"old.qcow2");
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
        new_backing_format_name: b"raw",
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
    assert_eq!(
        parse_header_extensions(&bytes, &header_post).backing_format,
        BackingFormat::Qcow2
    );
}
