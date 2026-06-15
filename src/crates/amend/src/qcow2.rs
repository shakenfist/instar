//! qcow2 amend planner.
//!
//! [`plan_amend_qcow2`] parses the first header cluster, runs the
//! full decision/validation matrix, and emits the byte-level
//! header patch(es) needed to realise the requested compat /
//! lazy-refcounts changes:
//!
//! - **No-op** (target == current for both version and lazy): zero
//!   patches, [`AmendAction::NoOp`].
//! - **Same-version lazy toggle**: one selective 8-byte write of
//!   the new `compatible_features` word at offset 80.
//! - **Version change (up or down)**: one full single-cluster
//!   header rewrite produced by a copy-and-adjust serializer that
//!   preserves the fixed-header fields 0..72, sets the
//!   version/feature/refcount_order/header_length fields for the
//!   target, relocates the existing extension area + backing
//!   string to the new fixed-header boundary, and bumps
//!   `backing_file_offset` by the shift.
//!
//! The serializer never mutates the source cluster in place: it
//! builds the target into a zeroed region of `scratch` by copying
//! from the source, so writing the v3 fixed fields into 72..104
//! cannot clobber source extensions that still need relocating.

use qcow2::{
    header_extension_area_end, QcowHeader, AUTOCLEAR_FEATURES_OFFSET, BACKING_FILE_OFFSET_OFFSET,
    COMPATIBLE_FEATURES_OFFSET, COMPAT_LAZY_REFCOUNTS, HEADER_LENGTH_OFFSET,
    INCOMPATIBLE_FEATURES_OFFSET, REFCOUNT_ORDER_OFFSET, V2_HEADER_EXTENSION_OFFSET,
    VERSION_OFFSET,
};
use shared::{be_u32, write_be_u32, write_be_u64};

use crate::{AmendAction, AmendError, AmendPatch, AmendPlan, Qcow2AmendOpts};

/// The v3 fixed-header length amend writes on upgrade (the minimum
/// valid v3 header: no `compression_type` field, extensions
/// immediately after). qemu writes 112 + a feature-name-table
/// extension; amend stays minimal — `qemu-img info`/`check`/
/// `compare` do not observe `header_length` or the feature-name
/// table, so the result stays info-equivalent.
const DST_FIXED_LEN_V3: usize = 104;
/// The v2 fixed-header length (extensions begin immediately at 72).
const DST_FIXED_LEN_V2: usize = V2_HEADER_EXTENSION_OFFSET; // 72

/// Plan a qcow2 amend.
///
/// Parses the header cluster, runs the refusal/no-op matrix, and
/// emits patch(es). Returns an [`AmendError`] on any refusal.
pub fn plan_amend_qcow2<'a>(
    opts: &Qcow2AmendOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<AmendPlan<'a>, AmendError> {
    let cluster_size = opts.cluster_size as usize;
    if cluster_size == 0 || opts.header_cluster.len() < cluster_size {
        return Err(AmendError::UnsupportedFormat);
    }

    let header = QcowHeader::parse(opts.header_cluster).ok_or(AmendError::ParseFailed)?;

    // Refuse any amend of an image another writer may hold open, or
    // one flagged corrupt.
    if header.dirty || header.corrupt {
        return Err(AmendError::Dirty);
    }

    // Compute the targets.
    let target_version: u32 = if opts.set_compat {
        if opts.target_v3 {
            3
        } else {
            2
        }
    } else {
        header.version
    };
    let mut target_lazy: bool = if opts.set_lazy {
        opts.lazy_on
    } else {
        header.lazy_refcounts
    };

    // v2 has no compatible_features word, so it cannot carry lazy
    // refcounts. An *explicit* `lazy_refcounts=on` request against a
    // v2 target (image already v2, or being downgraded to v2) is a
    // refusal. Lazy that is only `true` because it was inherited from
    // a v3 source being downgraded is NOT a refusal: the downgrade
    // gate below silently clears it, matching `qemu-img amend
    // -o compat=0.10` on a lazy image.
    if opts.set_lazy && opts.lazy_on && target_version == 2 {
        return Err(AmendError::LazyRequiresV3);
    }

    // Downgrade gate: v3 source -> v2 target.
    if header.version == 3 && target_version == 2 {
        if header.incompatible_features != 0 {
            // Any incompatible bit (dirty/corrupt/external_data/
            // compression/extended_l2) blocks the downgrade.
            return Err(AmendError::DowngradeBlockedFeature);
        }
        if header.refcount_bits != 16 {
            return Err(AmendError::DowngradeRefcountWidth);
        }
        // Lazy is a compatible feature that simply ceases to exist
        // on v2; downgrade silently clears it.
        target_lazy = false;
    }

    // No-op: nothing changes.
    if target_version == header.version && target_lazy == header.lazy_refcounts {
        return Ok(AmendPlan::new(
            AmendAction::NoOp,
            target_version,
            target_lazy,
        ));
    }

    // Same-version lazy change: one selective 8-byte write of the
    // new compatible_features word. Only reachable for v3 (a v2
    // same-version lazy-on was rejected above; lazy-off on v2 is a
    // no-op since v2 has no lazy bit).
    if target_version == header.version {
        let new_compat = if target_lazy {
            header.compatible_features | COMPAT_LAZY_REFCOUNTS
        } else {
            header.compatible_features & !COMPAT_LAZY_REFCOUNTS
        };
        if scratch.len() < 8 {
            return Err(AmendError::ScratchTooSmall);
        }
        write_be_u64(scratch, 0, new_compat);
        let bytes: &'a [u8] = &scratch[0..8];
        let mut plan = AmendPlan::new(AmendAction::Amended, target_version, target_lazy);
        plan.push(AmendPatch::Write {
            byte_offset: COMPATIBLE_FEATURES_OFFSET as u64,
            bytes,
        })?;
        return Ok(plan);
    }

    // Cross-version full rebuild.
    rebuild_cross_version(opts, &header, target_version, target_lazy, scratch)
}

/// Build the target header cluster for a version change and emit a
/// single full-cluster `Write { byte_offset: 0, .. }`.
fn rebuild_cross_version<'a>(
    opts: &Qcow2AmendOpts<'_>,
    header: &QcowHeader,
    target_version: u32,
    target_lazy: bool,
    scratch: &'a mut [u8],
) -> Result<AmendPlan<'a>, AmendError> {
    let cluster_size = opts.cluster_size as usize;
    let src = opts.header_cluster;

    // Source extension start: v2 fixes it at 72; v3 reads the
    // header_length field (112 in modern qemu, sometimes 104).
    let src_ext_start: usize = if header.version == 2 {
        V2_HEADER_EXTENSION_OFFSET
    } else {
        be_u32(src, HEADER_LENGTH_OFFSET) as usize
    };
    if src_ext_start > cluster_size || src_ext_start < 72 {
        return Err(AmendError::ParseFailed);
    }

    let dst_fixed_len: usize = if target_version == 3 {
        DST_FIXED_LEN_V3
    } else {
        DST_FIXED_LEN_V2
    };

    let delta: i64 = dst_fixed_len as i64 - src_ext_start as i64;

    // Find the end of the relocatable tail: the extension chain
    // plus (further out) the backing-file string.
    let backing_off = header.backing_file_offset;
    let backing_size = header.backing_file_size as u64;
    let backing_end = backing_off
        .checked_add(backing_size)
        .ok_or(AmendError::Overflow)?;

    let meaningful_end: usize = match header_extension_area_end(src, src_ext_start) {
        Some(ext_end) => {
            // Take the farther of the extension-chain end and the
            // backing-string end (the backing string lives after the
            // chain, sometimes far out).
            let m = core::cmp::max(ext_end as u64, backing_end);
            if m > cluster_size as u64 {
                return Err(AmendError::ExtensionRelocationUnsupported);
            }
            m as usize
        }
        None => {
            // No well-formed EXT_END terminator within the cluster.
            // Defensive: per fixtures qemu always terminates the
            // chain, so this is malformed. If there is no backing
            // file, treat the tail as empty (nothing to relocate);
            // otherwise we cannot safely bound the relocation.
            if backing_size == 0 {
                src_ext_start
            } else {
                return Err(AmendError::ExtensionRelocationUnsupported);
            }
        }
    };

    if meaningful_end < src_ext_start {
        return Err(AmendError::ExtensionRelocationUnsupported);
    }

    // Would the shifted tail run past the cluster end?
    let shifted_end = meaningful_end as i64 + delta;
    if shifted_end < 0 || shifted_end as u64 > cluster_size as u64 {
        return Err(AmendError::ExtensionRelocationUnsupported);
    }

    // Build into scratch. Must hold a full cluster.
    if scratch.len() < cluster_size {
        return Err(AmendError::ScratchTooSmall);
    }
    let dst = &mut scratch[..cluster_size];
    for b in dst.iter_mut() {
        *b = 0;
    }

    // Copy the fixed header 0..72 verbatim from the source.
    dst[..72].copy_from_slice(&src[..72]);

    // Set the target version.
    write_be_u32(dst, VERSION_OFFSET, target_version);

    if target_version == 3 {
        // Write the v3 fixed feature/refcount words. An upgrade from
        // v2 carries no incompatible features; a v3->v3 path never
        // reaches this rebuild (handled as same-version above), so
        // zeroing incompatible_features here is correct for the only
        // caller (v2 -> v3).
        write_be_u64(dst, INCOMPATIBLE_FEATURES_OFFSET, 0);
        write_be_u64(
            dst,
            COMPATIBLE_FEATURES_OFFSET,
            if target_lazy {
                COMPAT_LAZY_REFCOUNTS
            } else {
                0
            },
        );
        write_be_u64(dst, AUTOCLEAR_FEATURES_OFFSET, 0);
        write_be_u32(
            dst,
            REFCOUNT_ORDER_OFFSET,
            header.refcount_bits.trailing_zeros(),
        );
        write_be_u32(dst, HEADER_LENGTH_OFFSET, DST_FIXED_LEN_V3 as u32);
    }
    // For target v2: leave 72.. as the relocated extension area; do
    // not write any feature words (they do not exist on v2).

    // Copy the relocatable tail from the source into the destination
    // at the new fixed-header boundary.
    let tail_len = meaningful_end - src_ext_start;
    dst[dst_fixed_len..dst_fixed_len + tail_len]
        .copy_from_slice(&src[src_ext_start..meaningful_end]);

    // Bump backing_file_offset by the shift (only if there is one).
    if header.backing_file_size > 0 {
        let new_backing = (header.backing_file_offset as i64 + delta) as u64;
        write_be_u64(dst, BACKING_FILE_OFFSET_OFFSET, new_backing);
    }

    let bytes: &'a [u8] = &scratch[..cluster_size];
    let mut plan = AmendPlan::new(AmendAction::Amended, target_version, target_lazy);
    plan.push(AmendPatch::Write {
        byte_offset: 0,
        bytes,
    })?;
    Ok(plan)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use qcow2::{
        EXT_BACKING_FORMAT, INCOMPAT_COMPRESSION, INCOMPAT_CORRUPT, INCOMPAT_DIRTY,
        INCOMPAT_EXTERNAL_DATA, QCOW2_MAGIC,
    };

    const CLUSTER: usize = 65536;

    /// Build a header cluster.
    ///
    /// `version` (2 or 3), `refcount_order` (only meaningful for v3,
    /// e.g. 4 = 16-bit), `header_length` (the v3 header_length field;
    /// ignored for v2 which fixes extensions at 72),
    /// `incompatible`/`compatible` feature words (v3 only),
    /// `backing_file_offset`/`backing_file_size`.
    #[allow(clippy::too_many_arguments)]
    fn make_header(
        version: u32,
        refcount_order: u32,
        header_length: u32,
        incompatible: u64,
        compatible: u64,
        backing_file_offset: u64,
        backing_file_size: u32,
    ) -> [u8; CLUSTER] {
        let mut h = [0u8; CLUSTER];
        h[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
        h[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&version.to_be_bytes());
        h[8..16].copy_from_slice(&backing_file_offset.to_be_bytes());
        h[16..20].copy_from_slice(&backing_file_size.to_be_bytes());
        // cluster_bits = 16
        h[20..24].copy_from_slice(&16u32.to_be_bytes());
        // virtual_size = 1 MiB
        h[24..32].copy_from_slice(&(1u64 << 20).to_be_bytes());
        // l1_size = 1
        h[36..40].copy_from_slice(&1u32.to_be_bytes());
        // l1_table_offset = cluster 2
        h[40..48].copy_from_slice(&(2u64 * CLUSTER as u64).to_be_bytes());
        // refcount_table_offset = cluster 1
        h[48..56].copy_from_slice(&(CLUSTER as u64).to_be_bytes());
        // refcount_table_clusters = 1
        h[56..60].copy_from_slice(&1u32.to_be_bytes());
        if version >= 3 {
            h[INCOMPATIBLE_FEATURES_OFFSET..INCOMPATIBLE_FEATURES_OFFSET + 8]
                .copy_from_slice(&incompatible.to_be_bytes());
            h[COMPATIBLE_FEATURES_OFFSET..COMPATIBLE_FEATURES_OFFSET + 8]
                .copy_from_slice(&compatible.to_be_bytes());
            h[REFCOUNT_ORDER_OFFSET..REFCOUNT_ORDER_OFFSET + 4]
                .copy_from_slice(&refcount_order.to_be_bytes());
            h[HEADER_LENGTH_OFFSET..HEADER_LENGTH_OFFSET + 4]
                .copy_from_slice(&header_length.to_be_bytes());
        }
        h
    }

    /// Write a backing-format extension at `off` ("qcow2", len 5),
    /// followed by an EXT_END record. Returns the offset just past
    /// EXT_END.
    fn put_backing_format_ext(h: &mut [u8], off: usize) -> usize {
        h[off..off + 4].copy_from_slice(&EXT_BACKING_FORMAT.to_be_bytes());
        h[off + 4..off + 8].copy_from_slice(&5u32.to_be_bytes());
        h[off + 8..off + 13].copy_from_slice(b"qcow2");
        // padded body = 8 bytes; EXT_END header at off + 16.
        let ext_end = off + 16;
        // EXT_END (type 0, len 0) — already zeros. End is +8.
        ext_end + 8
    }

    fn v2_opts<'a>(h: &'a [u8], target_v3: bool) -> Qcow2AmendOpts<'a> {
        Qcow2AmendOpts {
            header_cluster: h,
            cluster_size: CLUSTER as u32,
            set_compat: true,
            target_v3,
            set_lazy: false,
            lazy_on: false,
        }
    }

    // ---- Refusal matrix --------------------------------------------------

    #[test]
    fn refuses_dirty() {
        let h = make_header(3, 4, 104, INCOMPAT_DIRTY, 0, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = Qcow2AmendOpts {
            header_cluster: &h,
            cluster_size: CLUSTER as u32,
            set_compat: false,
            target_v3: false,
            set_lazy: true,
            lazy_on: false,
        };
        assert_eq!(
            plan_amend_qcow2(&opts, &mut scratch).err(),
            Some(AmendError::Dirty)
        );
    }

    #[test]
    fn refuses_corrupt() {
        let h = make_header(3, 4, 104, INCOMPAT_CORRUPT, 0, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = Qcow2AmendOpts {
            header_cluster: &h,
            cluster_size: CLUSTER as u32,
            set_compat: true,
            target_v3: false,
            set_lazy: false,
            lazy_on: false,
        };
        assert_eq!(
            plan_amend_qcow2(&opts, &mut scratch).err(),
            Some(AmendError::Dirty)
        );
    }

    #[test]
    fn refuses_lazy_on_against_v2() {
        // v2 image, request lazy on, no version change.
        let h = make_header(2, 0, 0, 0, 0, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = Qcow2AmendOpts {
            header_cluster: &h,
            cluster_size: CLUSTER as u32,
            set_compat: false,
            target_v3: false,
            set_lazy: true,
            lazy_on: true,
        };
        assert_eq!(
            plan_amend_qcow2(&opts, &mut scratch).err(),
            Some(AmendError::LazyRequiresV3)
        );
    }

    #[test]
    fn refuses_lazy_on_while_downgrading() {
        // v3 -> v2 downgrade with lazy on requested.
        let h = make_header(3, 4, 104, 0, 0, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = Qcow2AmendOpts {
            header_cluster: &h,
            cluster_size: CLUSTER as u32,
            set_compat: true,
            target_v3: false,
            set_lazy: true,
            lazy_on: true,
        };
        assert_eq!(
            plan_amend_qcow2(&opts, &mut scratch).err(),
            Some(AmendError::LazyRequiresV3)
        );
    }

    #[test]
    fn refuses_downgrade_with_incompat_bit() {
        for bit in [
            INCOMPAT_EXTERNAL_DATA,
            INCOMPAT_COMPRESSION,
            1u64 << 4, // extended_l2
        ] {
            let h = make_header(3, 4, 104, bit, 0, 0, 0);
            let mut scratch = [0u8; CLUSTER];
            let opts = v2_opts(&h, false);
            assert_eq!(
                plan_amend_qcow2(&opts, &mut scratch).err(),
                Some(AmendError::DowngradeBlockedFeature),
                "bit {bit:#x} must block downgrade"
            );
        }
    }

    #[test]
    fn refuses_downgrade_refcount_width() {
        // v3 with 64-bit refcounts (refcount_order = 6).
        let h = make_header(3, 6, 104, 0, 0, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = v2_opts(&h, false);
        assert_eq!(
            plan_amend_qcow2(&opts, &mut scratch).err(),
            Some(AmendError::DowngradeRefcountWidth)
        );
    }

    // ---- No-op -----------------------------------------------------------

    #[test]
    fn noop_v3_same_lazy() {
        let h = make_header(3, 4, 104, 0, 0, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = Qcow2AmendOpts {
            header_cluster: &h,
            cluster_size: CLUSTER as u32,
            set_compat: true,
            target_v3: true,
            set_lazy: true,
            lazy_on: false,
        };
        let plan = plan_amend_qcow2(&opts, &mut scratch).expect("ok");
        assert_eq!(plan.action, AmendAction::NoOp);
        assert_eq!(plan.resulting_version, 3);
        assert!(!plan.resulting_lazy_refcounts);
        assert_eq!(plan.patches().len(), 0);
    }

    #[test]
    fn noop_v2_to_v2() {
        let h = make_header(2, 0, 0, 0, 0, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = v2_opts(&h, false);
        let plan = plan_amend_qcow2(&opts, &mut scratch).expect("ok");
        assert_eq!(plan.action, AmendAction::NoOp);
        assert_eq!(plan.resulting_version, 2);
        assert!(!plan.resulting_lazy_refcounts);
        assert_eq!(plan.patches().len(), 0);
    }

    // ---- Same-version lazy toggle ----------------------------------------

    #[test]
    fn lazy_on_v3_emits_compat_patch() {
        let h = make_header(3, 4, 104, 0, 0, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = Qcow2AmendOpts {
            header_cluster: &h,
            cluster_size: CLUSTER as u32,
            set_compat: false,
            target_v3: false,
            set_lazy: true,
            lazy_on: true,
        };
        let plan = plan_amend_qcow2(&opts, &mut scratch).expect("ok");
        assert_eq!(plan.action, AmendAction::Amended);
        assert_eq!(plan.resulting_version, 3);
        assert!(plan.resulting_lazy_refcounts);
        let patches = plan.patches();
        assert_eq!(patches.len(), 1);
        match patches[0] {
            AmendPatch::Write { byte_offset, bytes } => {
                assert_eq!(byte_offset, COMPATIBLE_FEATURES_OFFSET as u64);
                assert_eq!(bytes.len(), 8);
                assert_eq!(
                    u64::from_be_bytes(bytes.try_into().unwrap()),
                    COMPAT_LAZY_REFCOUNTS
                );
            }
        }
    }

    #[test]
    fn lazy_off_v3_emits_compat_patch() {
        // v3 image already lazy; clear it.
        let h = make_header(3, 4, 104, 0, COMPAT_LAZY_REFCOUNTS, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = Qcow2AmendOpts {
            header_cluster: &h,
            cluster_size: CLUSTER as u32,
            set_compat: false,
            target_v3: false,
            set_lazy: true,
            lazy_on: false,
        };
        let plan = plan_amend_qcow2(&opts, &mut scratch).expect("ok");
        assert_eq!(plan.action, AmendAction::Amended);
        assert!(!plan.resulting_lazy_refcounts);
        let patches = plan.patches();
        assert_eq!(patches.len(), 1);
        match patches[0] {
            AmendPatch::Write { byte_offset, bytes } => {
                assert_eq!(byte_offset, 80);
                assert_eq!(u64::from_be_bytes(bytes.try_into().unwrap()), 0);
            }
        }
    }

    // ---- Cross-version rebuild: upgrade ----------------------------------

    #[test]
    fn upgrade_no_ext() {
        // v2 plain (no extensions, no backing). Upgrade -> v3.
        let h = make_header(2, 0, 0, 0, 0, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = v2_opts(&h, true);
        let plan = plan_amend_qcow2(&opts, &mut scratch).expect("ok");
        assert_eq!(plan.action, AmendAction::Amended);
        assert_eq!(plan.resulting_version, 3);
        assert!(!plan.resulting_lazy_refcounts);
        let patches = plan.patches();
        assert_eq!(patches.len(), 1);
        let AmendPatch::Write { byte_offset, bytes } = patches[0];
        assert_eq!(byte_offset, 0);
        assert_eq!(bytes.len(), CLUSTER);
        // version = 3
        assert_eq!(u32::from_be_bytes(bytes[4..8].try_into().unwrap()), 3);
        // incompatible_features = 0
        assert_eq!(u64::from_be_bytes(bytes[72..80].try_into().unwrap()), 0);
        // compatible_features = 0 (no lazy requested)
        assert_eq!(u64::from_be_bytes(bytes[80..88].try_into().unwrap()), 0);
        // autoclear = 0
        assert_eq!(u64::from_be_bytes(bytes[88..96].try_into().unwrap()), 0);
        // refcount_order = 4 (16-bit)
        assert_eq!(u32::from_be_bytes(bytes[96..100].try_into().unwrap()), 4);
        // header_length = 104
        assert_eq!(u32::from_be_bytes(bytes[100..104].try_into().unwrap()), 104);
        // backing_file_offset untouched (== 0)
        assert_eq!(u64::from_be_bytes(bytes[8..16].try_into().unwrap()), 0);
    }

    #[test]
    fn upgrade_with_lazy_sets_compat_bit() {
        let h = make_header(2, 0, 0, 0, 0, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = Qcow2AmendOpts {
            header_cluster: &h,
            cluster_size: CLUSTER as u32,
            set_compat: true,
            target_v3: true,
            set_lazy: true,
            lazy_on: true,
        };
        let plan = plan_amend_qcow2(&opts, &mut scratch).expect("ok");
        assert!(plan.resulting_lazy_refcounts);
        let AmendPatch::Write { bytes, .. } = plan.patches()[0];
        assert_eq!(
            u64::from_be_bytes(bytes[80..88].try_into().unwrap()),
            COMPAT_LAZY_REFCOUNTS
        );
    }

    #[test]
    fn upgrade_with_backing_ext() {
        // v2 with a backing-format ext at 72, then EXT_END, then a
        // backing string. Mirrors the qemu fixture: ext at 72,
        // EXT_END at 0x58, backing string at offset 96
        // (backing_file_offset = 0x60), size 10. On upgrade the
        // 72..106 region relocates to 104 (+32), backing_file_offset
        // 96 -> 128.
        let mut h = make_header(2, 0, 0, 0, 0, 0x60, 10);
        let ext_end = put_backing_format_ext(&mut h, 72);
        // ext_end is offset just past EXT_END = 72 + 16 + 8 = 96.
        assert_eq!(ext_end, 96);
        // backing string at 96, 10 bytes.
        h[96..106].copy_from_slice(b"base.qcow2");

        let mut scratch = [0u8; CLUSTER];
        let opts = v2_opts(&h, true);
        let plan = plan_amend_qcow2(&opts, &mut scratch).expect("ok");
        let AmendPatch::Write { byte_offset, bytes } = plan.patches()[0];
        assert_eq!(byte_offset, 0);
        // version = 3, header_length = 104.
        assert_eq!(u32::from_be_bytes(bytes[4..8].try_into().unwrap()), 3);
        assert_eq!(u32::from_be_bytes(bytes[100..104].try_into().unwrap()), 104);
        // The backing-format ext relocated to offset 104.
        assert_eq!(
            u32::from_be_bytes(bytes[104..108].try_into().unwrap()),
            EXT_BACKING_FORMAT
        );
        assert_eq!(u32::from_be_bytes(bytes[108..112].try_into().unwrap()), 5);
        assert_eq!(&bytes[112..117], b"qcow2");
        // EXT_END preserved (relocated from 88 to 120).
        assert_eq!(u32::from_be_bytes(bytes[120..124].try_into().unwrap()), 0);
        // backing string relocated to 128 (96 + 32).
        assert_eq!(&bytes[128..138], b"base.qcow2");
        // backing_file_offset bumped +32: 0x60 -> 0x80 = 128.
        assert_eq!(u64::from_be_bytes(bytes[8..16].try_into().unwrap()), 128);
    }

    // ---- Cross-version rebuild: downgrade --------------------------------

    #[test]
    fn downgrade_no_incompat() {
        // v3 plain, header_length = 112, with a feature-name-table-
        // style extension at 112 (use a backing-format ext as a
        // stand-in opaque ext) then EXT_END. No backing file.
        // Downgrade -> v2; ext relocates to 72; tail beyond
        // meaningful_end zeroed.
        let mut h = make_header(3, 4, 112, 0, 0, 0, 0);
        let ext_end = put_backing_format_ext(&mut h, 112);
        assert_eq!(ext_end, 112 + 24);
        let mut scratch = [0u8; CLUSTER];
        let opts = v2_opts(&h, false);
        let plan = plan_amend_qcow2(&opts, &mut scratch).expect("ok");
        assert_eq!(plan.resulting_version, 2);
        assert!(!plan.resulting_lazy_refcounts);
        let AmendPatch::Write { byte_offset, bytes } = plan.patches()[0];
        assert_eq!(byte_offset, 0);
        // version = 2
        assert_eq!(u32::from_be_bytes(bytes[4..8].try_into().unwrap()), 2);
        // ext relocated to 72.
        assert_eq!(
            u32::from_be_bytes(bytes[72..76].try_into().unwrap()),
            EXT_BACKING_FORMAT
        );
        assert_eq!(u32::from_be_bytes(bytes[76..80].try_into().unwrap()), 5);
        assert_eq!(&bytes[80..85], b"qcow2");
        // EXT_END relocated from 128 to 88.
        assert_eq!(u32::from_be_bytes(bytes[88..92].try_into().unwrap()), 0);
        // Tail beyond the relocated area is zeroed (delta = 72-112 =
        // -40; meaningful_end = 136; shifted_end = 96). Bytes from 96
        // on must be zero.
        assert!(bytes[96..200].iter().all(|&b| b == 0));
    }

    #[test]
    fn downgrade_with_backing() {
        // v3 with header_length = 112, backing-format ext at 112,
        // EXT_END, and a backing string far out at offset 200 (size
        // 10). meaningful_end = 210. Downgrade delta = -40: ext to
        // 72, backing string to 160, backing_file_offset 200 -> 160.
        let mut h = make_header(3, 4, 112, 0, 0, 200, 10);
        put_backing_format_ext(&mut h, 112);
        h[200..210].copy_from_slice(b"base.qcow2");
        let mut scratch = [0u8; CLUSTER];
        let opts = v2_opts(&h, false);
        let plan = plan_amend_qcow2(&opts, &mut scratch).expect("ok");
        let AmendPatch::Write { bytes, .. } = plan.patches()[0];
        assert_eq!(u32::from_be_bytes(bytes[4..8].try_into().unwrap()), 2);
        // ext at 72.
        assert_eq!(
            u32::from_be_bytes(bytes[72..76].try_into().unwrap()),
            EXT_BACKING_FORMAT
        );
        // backing string relocated to 160 (200 - 40).
        assert_eq!(&bytes[160..170], b"base.qcow2");
        // backing_file_offset bumped -40: 200 -> 160.
        assert_eq!(u64::from_be_bytes(bytes[8..16].try_into().unwrap()), 160);
    }

    #[test]
    fn downgrade_clears_inherited_lazy_without_explicit_flag() {
        // Regression: a v3 image with lazy_refcounts=on, downgraded
        // with NO explicit lazy flag (set_lazy=false), must succeed
        // and silently clear lazy -- NOT be refused with
        // LazyRequiresV3. (qemu-img amend -o compat=0.10 on a lazy
        // image clears the bit.)
        let h = make_header(3, 4, 104, 0, COMPAT_LAZY_REFCOUNTS, 0, 0);
        let mut scratch = [0u8; CLUSTER];
        let opts = v2_opts(&h, false); // set_compat, target v2, set_lazy=false
        let plan = plan_amend_qcow2(&opts, &mut scratch).expect("downgrade succeeds");
        assert_eq!(plan.action, AmendAction::Amended);
        assert_eq!(plan.resulting_version, 2);
        assert!(!plan.resulting_lazy_refcounts);
        let AmendPatch::Write { byte_offset, bytes } = plan.patches()[0];
        assert_eq!(byte_offset, 0);
        assert_eq!(u32::from_be_bytes(bytes[4..8].try_into().unwrap()), 2);
    }

    // ---- Overflow refusal ------------------------------------------------

    #[test]
    fn upgrade_overflow_refused() {
        // Tiny cluster where the +32 upgrade shift pushes the
        // meaningful tail past the cluster end. Use cluster_size that
        // is barely big enough to parse (>= 105) but where
        // meaningful_end + 32 > cluster_size. Build a v2 with a
        // backing string ending right at the cluster end.
        let cluster: usize = 512; // cluster_bits unaffected; we set size explicitly
        let mut h = [0u8; CLUSTER];
        h[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
        h[4..8].copy_from_slice(&2u32.to_be_bytes());
        h[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits = 16
        h[24..32].copy_from_slice(&(1u64 << 20).to_be_bytes());
        h[36..40].copy_from_slice(&1u32.to_be_bytes());
        // backing string spanning right up to cluster end (512).
        // backing_file_offset = 500, size = 12 -> meaningful_end = 512.
        h[8..16].copy_from_slice(&500u64.to_be_bytes());
        h[16..20].copy_from_slice(&12u32.to_be_bytes());
        // EXT_END at 72 immediately (no extensions); ext_end = 80.
        // meaningful_end = max(80, 512) = 512. +32 = 544 > 512.
        let mut scratch = [0u8; CLUSTER];
        let opts = Qcow2AmendOpts {
            header_cluster: &h,
            cluster_size: cluster as u32,
            set_compat: true,
            target_v3: true,
            set_lazy: false,
            lazy_on: false,
        };
        assert_eq!(
            plan_amend_qcow2(&opts, &mut scratch).err(),
            Some(AmendError::ExtensionRelocationUnsupported)
        );
    }
}
