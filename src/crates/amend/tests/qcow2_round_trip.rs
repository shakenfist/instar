//! Apply-then-reparse round-trip integration tests for the qcow2
//! amend planner.
//!
//! Each test builds a header buffer (v3 via `create`, v2
//! hand-crafted), calls `plan_amend_qcow2`, applies the emitted
//! patches with `apply_amend`, re-parses with `QcowHeader::parse`
//! (and `parse_header_extensions` where extensions are involved),
//! and asserts the resulting header invariants. Where phase 2's
//! inline unit tests assert "the planner emits these bytes", this
//! suite asserts "after applying those bytes and re-parsing, the
//! header is correct and self-consistent" across every transition,
//! including compound (down-then-up, lazy on-then-off) sequences.

mod common;

use amend::{plan_amend_qcow2, AmendAction, AmendError, Qcow2AmendOpts};
use common::{apply_amend, build_v3, make_v2_header, put_backing_format_ext};
use qcow2::{
    parse_header_extensions, QcowHeader, COMPAT_LAZY_REFCOUNTS, EXT_BACKING_FORMAT,
    HEADER_LENGTH_OFFSET, INCOMPATIBLE_FEATURES_OFFSET, INCOMPAT_COMPRESSION, INCOMPAT_DIRTY,
    REFCOUNT_ORDER_OFFSET,
};
use shared::{be_u32, be_u64, BackingFormat};

const CLUSTER: u32 = 65536;
const VSIZE: u64 = 1 << 20;

/// Build amend opts whose `header_cluster` is the first cluster of
/// `bytes`.
fn opts<'a>(
    bytes: &'a [u8],
    set_compat: bool,
    target_v3: bool,
    set_lazy: bool,
    lazy_on: bool,
) -> Qcow2AmendOpts<'a> {
    Qcow2AmendOpts {
        header_cluster: &bytes[..CLUSTER as usize],
        cluster_size: CLUSTER,
        set_compat,
        target_v3,
        set_lazy,
        lazy_on,
    }
}

// ---------------------------------------------------------------------------
// Case 1: lazy toggle (same version), exact-byte round-trip
// ---------------------------------------------------------------------------

#[test]
fn lazy_off_on_off_exact_byte_cycle() {
    // A non-lazy v3 image. Toggle lazy on, then off, then on, then
    // off again, applying each amend onto the running buffer. The
    // lazy bit must toggle cleanly and the non-lazy state must match
    // the original header cluster byte-for-byte.
    let mut bytes = build_v3(VSIZE, CLUSTER, false, None);
    let original = bytes.clone();

    // --- amend lazy on ---
    {
        let mut scratch = vec![0u8; CLUSTER as usize];
        let plan = plan_amend_qcow2(&opts(&bytes, false, false, true, true), &mut scratch)
            .expect("lazy on");
        assert_eq!(plan.action, AmendAction::Amended);
        assert!(plan.resulting_lazy_refcounts);
        apply_amend(&mut bytes, &plan);
    }
    let parsed = QcowHeader::parse(&bytes).expect("parse after on");
    assert_eq!(parsed.version, 3);
    assert!(parsed.lazy_refcounts, "lazy must be on after lazy_on");

    // --- amend lazy off (first off) ---
    {
        let mut scratch = vec![0u8; CLUSTER as usize];
        let plan = plan_amend_qcow2(&opts(&bytes, false, false, true, false), &mut scratch)
            .expect("lazy off");
        assert!(!plan.resulting_lazy_refcounts);
        apply_amend(&mut bytes, &plan);
    }
    assert!(!QcowHeader::parse(&bytes).unwrap().lazy_refcounts);
    let after_first_off = bytes.clone();
    // Same-version lazy toggle only touches compatible_features, so
    // the non-lazy buffer must equal the original exactly.
    assert_eq!(
        after_first_off, original,
        "first lazy-off must restore the exact original header cluster"
    );

    // --- amend lazy on again ---
    {
        let mut scratch = vec![0u8; CLUSTER as usize];
        let plan = plan_amend_qcow2(&opts(&bytes, false, false, true, true), &mut scratch)
            .expect("lazy on 2");
        apply_amend(&mut bytes, &plan);
    }
    assert!(QcowHeader::parse(&bytes).unwrap().lazy_refcounts);

    // --- amend lazy off again ---
    {
        let mut scratch = vec![0u8; CLUSTER as usize];
        let plan = plan_amend_qcow2(&opts(&bytes, false, false, true, false), &mut scratch)
            .expect("lazy off 2");
        apply_amend(&mut bytes, &plan);
    }
    assert!(!QcowHeader::parse(&bytes).unwrap().lazy_refcounts);
    // Toggling off -> on -> off returns to the exact bytes after the
    // first off (== the original).
    assert_eq!(
        bytes, after_first_off,
        "off->on->off must return to the post-first-off buffer"
    );
    assert_eq!(bytes, original, "and thus to the original bytes");
}

// ---------------------------------------------------------------------------
// Case 2: no-op / idempotency
// ---------------------------------------------------------------------------

#[test]
fn noop_amend_v3_to_compat_1_1() {
    // Amend a v3 image to compat=1.1 (its current version): NoOp,
    // zero patches, bytes unchanged.
    let mut bytes = build_v3(VSIZE, CLUSTER, false, None);
    let original = bytes.clone();
    let mut scratch = vec![0u8; CLUSTER as usize];
    let plan =
        plan_amend_qcow2(&opts(&bytes, true, true, false, false), &mut scratch).expect("noop");
    assert_eq!(plan.action, AmendAction::NoOp);
    assert_eq!(plan.patches().len(), 0);
    apply_amend(&mut bytes, &plan);
    assert_eq!(bytes, original, "no-op must not change any bytes");
}

#[test]
fn noop_lazy_off_on_non_lazy_v3() {
    // Amend lazy_refcounts=off on a non-lazy v3 image: NoOp.
    let mut bytes = build_v3(VSIZE, CLUSTER, false, None);
    let original = bytes.clone();
    let mut scratch = vec![0u8; CLUSTER as usize];
    let plan =
        plan_amend_qcow2(&opts(&bytes, false, false, true, false), &mut scratch).expect("noop");
    assert_eq!(plan.action, AmendAction::NoOp);
    assert_eq!(plan.patches().len(), 0);
    apply_amend(&mut bytes, &plan);
    assert_eq!(bytes, original);
}

// ---------------------------------------------------------------------------
// Case 3a: upgrade v2 -> v3, no extensions
// ---------------------------------------------------------------------------

#[test]
fn upgrade_v2_to_v3_no_ext() {
    let mut bytes = make_v2_header(CLUSTER as usize, VSIZE);
    let mut scratch = vec![0u8; CLUSTER as usize];
    let plan =
        plan_amend_qcow2(&opts(&bytes, true, true, false, false), &mut scratch).expect("upgrade");
    assert_eq!(plan.action, AmendAction::Amended);
    assert_eq!(plan.resulting_version, 3);
    apply_amend(&mut bytes, &plan);

    let parsed = QcowHeader::parse(&bytes).expect("parse after upgrade");
    assert_eq!(parsed.version, 3);
    // header_length == 104 (read raw at offset 100).
    assert_eq!(be_u32(&bytes, HEADER_LENGTH_OFFSET), 104);
    // refcount_order == 4 (offset 96) => 16-bit refcounts.
    assert_eq!(be_u32(&bytes, REFCOUNT_ORDER_OFFSET), 4);
    assert_eq!(parsed.refcount_bits, 16);
    assert_eq!(parsed.incompatible_features, 0);
    assert_eq!(parsed.compatible_features, 0);
    // Structural fields preserved.
    assert_eq!(parsed.virtual_size, VSIZE);
    assert_eq!(parsed.cluster_size, CLUSTER as u64);
}

// ---------------------------------------------------------------------------
// Case 4a: downgrade v3 -> v2, no extensions
// ---------------------------------------------------------------------------

#[test]
fn downgrade_v3_to_v2_no_ext() {
    let mut bytes = build_v3(VSIZE, CLUSTER, false, None);
    let mut scratch = vec![0u8; CLUSTER as usize];
    let plan = plan_amend_qcow2(&opts(&bytes, true, false, false, false), &mut scratch)
        .expect("downgrade");
    assert_eq!(plan.action, AmendAction::Amended);
    assert_eq!(plan.resulting_version, 2);
    apply_amend(&mut bytes, &plan);

    let parsed = QcowHeader::parse(&bytes).expect("parse after downgrade");
    assert_eq!(parsed.version, 2);
    assert!(!parsed.lazy_refcounts);
    assert_eq!(parsed.virtual_size, VSIZE);
    assert_eq!(parsed.cluster_size, CLUSTER as u64);
    // v2 refcounts are always 16-bit.
    assert_eq!(parsed.refcount_bits, 16);
}

// ---------------------------------------------------------------------------
// Case 3b: upgrade v2 -> v3 with a backing-format extension at 72
// ---------------------------------------------------------------------------

#[test]
fn upgrade_v2_to_v3_with_backing_ext() {
    let backing = b"base.qcow2";
    let mut bytes = make_v2_header(CLUSTER as usize, VSIZE);
    // ext at 72; EXT_END at 88; backing string at 96.
    let meaningful_end = put_backing_format_ext(&mut bytes, 72, backing);
    assert_eq!(meaningful_end, 96 + backing.len());
    let v2_backing_off = be_u64(&bytes, 8);
    assert_eq!(v2_backing_off, 96);

    let mut scratch = vec![0u8; CLUSTER as usize];
    let plan =
        plan_amend_qcow2(&opts(&bytes, true, true, false, false), &mut scratch).expect("upgrade");
    apply_amend(&mut bytes, &plan);

    let parsed = QcowHeader::parse(&bytes).expect("parse after upgrade");
    assert_eq!(parsed.version, 3);
    assert_eq!(be_u32(&bytes, HEADER_LENGTH_OFFSET), 104);

    // The backing-format ext relocated from 72 to 104 (delta +32).
    let exts = parse_header_extensions(&bytes, &parsed);
    assert_eq!(exts.backing_format, BackingFormat::Qcow2);
    // The ext now lives at >= 104 (the v3 boundary).
    assert_eq!(be_u32(&bytes, 104), EXT_BACKING_FORMAT);

    // backing_file_offset bumped +32 vs the v2 value (96 -> 128).
    assert_eq!(parsed.backing_file_offset, v2_backing_off + 32);
    assert_eq!(parsed.backing_file_size as usize, backing.len());

    // The backing string bytes are intact at the relocated offset.
    let off = parsed.backing_file_offset as usize;
    assert_eq!(&bytes[off..off + backing.len()], backing);
}

// ---------------------------------------------------------------------------
// Case 3c: upgrade v2 -> v3 with lazy_refcounts=on in the same amend
// ---------------------------------------------------------------------------

#[test]
fn upgrade_v2_to_v3_with_lazy() {
    let mut bytes = make_v2_header(CLUSTER as usize, VSIZE);
    let mut scratch = vec![0u8; CLUSTER as usize];
    // set_compat + target_v3 + set_lazy + lazy_on.
    let plan = plan_amend_qcow2(&opts(&bytes, true, true, true, true), &mut scratch)
        .expect("upgrade+lazy");
    assert_eq!(plan.resulting_version, 3);
    assert!(plan.resulting_lazy_refcounts);
    apply_amend(&mut bytes, &plan);

    let parsed = QcowHeader::parse(&bytes).expect("parse");
    assert_eq!(parsed.version, 3);
    assert!(parsed.lazy_refcounts);
    assert_ne!(
        parsed.compatible_features & COMPAT_LAZY_REFCOUNTS,
        0,
        "compatible_features must carry COMPAT_LAZY_REFCOUNTS"
    );
}

// ---------------------------------------------------------------------------
// Case 4b: downgrade v3 -> v2 with an extension + backing
// ---------------------------------------------------------------------------

#[test]
fn downgrade_v3_to_v2_with_backing_ext() {
    // build a v3 image with a backing reference via `create`.
    let backing = b"base.qcow2";
    let mut bytes = build_v3(VSIZE, CLUSTER, false, Some(backing));

    let before = QcowHeader::parse(&bytes).expect("parse v3");
    assert_eq!(before.version, 3);
    let exts_before = parse_header_extensions(&bytes, &before);
    assert_eq!(
        exts_before.backing_format,
        BackingFormat::Qcow2,
        "v3 fixture must carry a qcow2 backing-format ext"
    );
    let v3_backing_off = before.backing_file_offset;
    let v3_ext_start = be_u32(&bytes, HEADER_LENGTH_OFFSET) as usize;

    let mut scratch = vec![0u8; CLUSTER as usize];
    let plan = plan_amend_qcow2(&opts(&bytes, true, false, false, false), &mut scratch)
        .expect("downgrade");
    apply_amend(&mut bytes, &plan);

    let parsed = QcowHeader::parse(&bytes).expect("parse after downgrade");
    assert_eq!(parsed.version, 2);

    // The backing-format ext survived, relocated to the v2 boundary
    // (offset 72). v2 has no header_length field; the ext chain
    // starts at 72.
    assert_eq!(be_u32(&bytes, 72), EXT_BACKING_FORMAT);

    // backing_file_offset bumped by the negative delta (72 - v3_ext_start).
    let delta: i64 = 72 - v3_ext_start as i64;
    assert_eq!(
        parsed.backing_file_offset as i64,
        v3_backing_off as i64 + delta,
        "backing_file_offset must shift by the relocation delta"
    );
    assert_eq!(parsed.backing_file_size as usize, backing.len());
    let off = parsed.backing_file_offset as usize;
    assert_eq!(&bytes[off..off + backing.len()], backing);

    // Bytes beyond the relocated tail are zeroed. The relocated tail
    // (ext chain + backing string) ends at backing_file_offset +
    // backing_file_size; everything from there up to (and past) the
    // old v3 extension area must be zero. Bound the scan generously
    // beyond the old extension start, staying within the cluster.
    let tail_end = off + backing.len();
    let scan_end = (v3_ext_start + 64).min(bytes.len());
    assert!(
        scan_end > tail_end,
        "scan window must extend past the relocated tail"
    );
    assert!(
        bytes[tail_end..scan_end].iter().all(|&b| b == 0),
        "freed region beyond the relocated tail must be zeroed"
    );
}

// ---------------------------------------------------------------------------
// Case 5: compound round-trips (assert parsed invariants, not bytes)
// ---------------------------------------------------------------------------

#[test]
fn compound_v2_to_v3_to_v2() {
    let backing = b"base.qcow2";
    let mut bytes = make_v2_header(CLUSTER as usize, VSIZE);
    put_backing_format_ext(&mut bytes, 72, backing);

    // --- upgrade v2 -> v3 ---
    {
        let mut scratch = vec![0u8; CLUSTER as usize];
        let plan = plan_amend_qcow2(&opts(&bytes, true, true, false, false), &mut scratch)
            .expect("upgrade");
        apply_amend(&mut bytes, &plan);
    }
    let mid = QcowHeader::parse(&bytes).expect("parse v3");
    assert_eq!(mid.version, 3);
    assert_eq!(
        parse_header_extensions(&bytes, &mid).backing_format,
        BackingFormat::Qcow2
    );

    // --- downgrade v3 -> v2 ---
    {
        let mut scratch = vec![0u8; CLUSTER as usize];
        let plan = plan_amend_qcow2(&opts(&bytes, true, false, false, false), &mut scratch)
            .expect("downgrade");
        apply_amend(&mut bytes, &plan);
    }
    let parsed = QcowHeader::parse(&bytes).expect("parse v2");
    // Assert parsed invariants (not raw bytes — see plan open Q2).
    assert_eq!(parsed.version, 2);
    assert_eq!(parsed.virtual_size, VSIZE);
    assert_eq!(parsed.cluster_size, CLUSTER as u64);
    assert_eq!(parsed.refcount_bits, 16);
    // The backing reference survives the two-way conversion.
    assert_eq!(be_u32(&bytes, 72), EXT_BACKING_FORMAT);
    assert_eq!(parsed.backing_file_size as usize, backing.len());
    let off = parsed.backing_file_offset as usize;
    assert_eq!(&bytes[off..off + backing.len()], backing);
}

#[test]
fn compound_v3_to_v2_to_v3() {
    // v3 with no v3-only incompatible features and no lazy.
    let mut bytes = build_v3(VSIZE, CLUSTER, false, None);

    // --- downgrade v3 -> v2 ---
    {
        let mut scratch = vec![0u8; CLUSTER as usize];
        let plan = plan_amend_qcow2(&opts(&bytes, true, false, false, false), &mut scratch)
            .expect("downgrade");
        apply_amend(&mut bytes, &plan);
    }
    let mid = QcowHeader::parse(&bytes).expect("parse v2");
    assert_eq!(mid.version, 2);
    assert!(!mid.lazy_refcounts, "lazy must be false at the v2 step");

    // --- upgrade v2 -> v3 ---
    {
        let mut scratch = vec![0u8; CLUSTER as usize];
        let plan = plan_amend_qcow2(&opts(&bytes, true, true, false, false), &mut scratch)
            .expect("upgrade");
        apply_amend(&mut bytes, &plan);
    }
    let parsed = QcowHeader::parse(&bytes).expect("parse v3");
    assert_eq!(parsed.version, 3);
    assert_eq!(parsed.virtual_size, VSIZE);
    assert_eq!(parsed.cluster_size, CLUSTER as u64);
    assert!(!parsed.lazy_refcounts, "lazy false throughout");
}

// ---------------------------------------------------------------------------
// Case 6: suite-level refusal assertions (planner returns Err, no apply)
// ---------------------------------------------------------------------------

#[test]
fn refuse_downgrade_with_incompat_bit() {
    // Hand-set an incompatible feature bit in a v3 header, then try
    // to downgrade -> DowngradeBlockedFeature.
    let mut bytes = build_v3(VSIZE, CLUSTER, false, None);
    let incompat = be_u64(&bytes, INCOMPATIBLE_FEATURES_OFFSET) | INCOMPAT_COMPRESSION;
    bytes[INCOMPATIBLE_FEATURES_OFFSET..INCOMPATIBLE_FEATURES_OFFSET + 8]
        .copy_from_slice(&incompat.to_be_bytes());
    let mut scratch = vec![0u8; CLUSTER as usize];
    assert_eq!(
        plan_amend_qcow2(&opts(&bytes, true, false, false, false), &mut scratch).err(),
        Some(AmendError::DowngradeBlockedFeature)
    );
}

#[test]
fn refuse_downgrade_with_refcount_width() {
    // v3 with refcount_order != 4 (e.g. 6 = 64-bit). Downgrade ->
    // DowngradeRefcountWidth.
    let mut bytes = build_v3(VSIZE, CLUSTER, false, None);
    bytes[REFCOUNT_ORDER_OFFSET..REFCOUNT_ORDER_OFFSET + 4].copy_from_slice(&6u32.to_be_bytes());
    let mut scratch = vec![0u8; CLUSTER as usize];
    assert_eq!(
        plan_amend_qcow2(&opts(&bytes, true, false, false, false), &mut scratch).err(),
        Some(AmendError::DowngradeRefcountWidth)
    );
}

#[test]
fn refuse_lazy_on_against_v2() {
    // lazy_refcounts=on against a v2 image, no compat change ->
    // LazyRequiresV3.
    let bytes = make_v2_header(CLUSTER as usize, VSIZE);
    let mut scratch = vec![0u8; CLUSTER as usize];
    assert_eq!(
        plan_amend_qcow2(&opts(&bytes, false, false, true, true), &mut scratch).err(),
        Some(AmendError::LazyRequiresV3)
    );
}

#[test]
fn refuse_dirty_image() {
    // A v3 image with INCOMPAT_DIRTY set -> Dirty.
    let mut bytes = build_v3(VSIZE, CLUSTER, false, None);
    let incompat = be_u64(&bytes, INCOMPATIBLE_FEATURES_OFFSET) | INCOMPAT_DIRTY;
    bytes[INCOMPATIBLE_FEATURES_OFFSET..INCOMPATIBLE_FEATURES_OFFSET + 8]
        .copy_from_slice(&incompat.to_be_bytes());
    let mut scratch = vec![0u8; CLUSTER as usize];
    assert_eq!(
        plan_amend_qcow2(&opts(&bytes, true, false, false, false), &mut scratch).err(),
        Some(AmendError::Dirty)
    );
}
