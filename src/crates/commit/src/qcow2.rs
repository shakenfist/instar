//! qcow2 commit planner: overlay-side and cross-image
//! validation plus the geometry the guest's commit loop needs.
//!
//! Phase 4 of `PLAN-qcow2-write-infrastructure` moved the
//! backing-side write composition (allocation, refblock
//! staging, dirty tracking) into `crates/qcow2-write` +
//! `crates/qcow2-write-exec`; what remains here is the
//! cross-image validation gate and the overlay geometry the
//! guest threads through the per-cluster loop and the
//! overlay-clear pass.
//!
//! Refcount-width coverage in v1: only `refcount_bits == 16`
//! (qemu-img's default) on both the overlay and the backing.
//! Other widths return [`CommitError::UnsupportedFormat`]. The
//! bit-packing reference for the future widths is
//! `qcow2::lookup_refcount` in `src/crates/qcow2/src/lib.rs`.

use qcow2::{QcowHeader, INCOMPAT_CORRUPT, INCOMPAT_DIRTY, INCOMPAT_EXTERNAL_DATA, L1_OFFSET_MASK};

use crate::CommitError;

/// Options for [`plan_commit_qcow2`].
#[derive(Debug, Clone, Copy)]
pub struct Qcow2CommitOpts<'a> {
    /// Overlay's current header bytes (at least 105 bytes for
    /// v2 / 4 KiB for v3 with extensions).
    pub overlay_header: &'a [u8],
    /// Overlay's current file size in bytes.
    pub overlay_file_size: u64,
    /// Backing's current header bytes.
    pub backing_header: &'a [u8],
    /// Backing's current file size in bytes.
    pub backing_file_size: u64,
}

/// Geometry the guest threads through a qcow2 commit loop and
/// the overlay-clear pass. Backing-side write state lives in
/// `qcow2_write::WriteState` since phase 4.
#[derive(Debug, Clone, Copy)]
pub struct Qcow2CommitContext {
    pub overlay_cluster_size: u32,
    pub overlay_cluster_count: u64,
    pub overlay_l1_table_offset: u64,
    pub overlay_l1_size: u32,
    pub overlay_refcount_table_offset: u64,
    pub overlay_refcount_table_clusters: u32,
    pub overlay_refcount_bits: u32,
    pub overlay_entries_per_refblock: u64,
}

/// Plan a qcow2 commit.
///
/// Validates compatibility between the overlay and the backing
/// (LUKS / external-data-file refusal, dirty/corrupt bits,
/// virtual-size compatibility, refcount width, geometry sanity)
/// and returns the overlay geometry as a [`Qcow2CommitContext`].
/// The guest drives the per-cluster commit loop itself; the
/// backing-side envelope (feature bits, snapshots) is gated
/// separately by `qcow2_write::check_envelope`.
pub fn plan_commit_qcow2(opts: &Qcow2CommitOpts<'_>) -> Result<Qcow2CommitContext, CommitError> {
    // ----- Parse + validate the overlay header --------------
    let overlay = QcowHeader::parse(opts.overlay_header).ok_or(CommitError::ParseFailed)?;
    if overlay.dirty || overlay.corrupt {
        return Err(CommitError::OverlayCorrupt);
    }
    if overlay.has_external_data || (overlay.incompatible_features & INCOMPAT_EXTERNAL_DATA) != 0 {
        return Err(CommitError::ExternalDataFile);
    }
    if (overlay.incompatible_features & (INCOMPAT_DIRTY | INCOMPAT_CORRUPT)) != 0 {
        return Err(CommitError::OverlayCorrupt);
    }
    if overlay.crypt_method != 0 {
        return Err(CommitError::LuksUnsupported);
    }

    // ----- Parse + validate the backing header --------------
    let backing = QcowHeader::parse(opts.backing_header).ok_or(CommitError::ParseFailed)?;
    if backing.dirty || backing.corrupt {
        return Err(CommitError::BackingCorrupt);
    }
    if backing.has_external_data || (backing.incompatible_features & INCOMPAT_EXTERNAL_DATA) != 0 {
        return Err(CommitError::ExternalDataFile);
    }
    if (backing.incompatible_features & (INCOMPAT_DIRTY | INCOMPAT_CORRUPT)) != 0 {
        return Err(CommitError::BackingCorrupt);
    }
    if backing.crypt_method != 0 {
        return Err(CommitError::LuksUnsupported);
    }

    // ----- Cross-image checks ------------------------------
    if backing.virtual_size < overlay.virtual_size {
        return Err(CommitError::OverlayLargerThanBacking);
    }
    if overlay.refcount_bits != 16 || backing.refcount_bits != 16 {
        return Err(CommitError::UnsupportedFormat);
    }
    if overlay.cluster_size == 0 {
        return Err(CommitError::OverlayCorrupt);
    }
    if backing.cluster_size == 0 {
        return Err(CommitError::BackingCorrupt);
    }

    let overlay_cluster_size = overlay.cluster_size;
    let overlay_entries_per_refblock = (overlay_cluster_size * 8) / overlay.refcount_bits as u64;
    let overlay_cluster_count = overlay.virtual_size.div_ceil(overlay_cluster_size);

    Ok(Qcow2CommitContext {
        overlay_cluster_size: overlay_cluster_size as u32,
        overlay_cluster_count,
        overlay_l1_table_offset: overlay.l1_table_offset,
        overlay_l1_size: overlay.l1_size,
        overlay_refcount_table_offset: overlay.refcount_table_offset,
        overlay_refcount_table_clusters: overlay.refcount_table_clusters,
        overlay_refcount_bits: overlay.refcount_bits,
        overlay_entries_per_refblock,
    })
}

/// Compute the disk byte offset of the L2 entry covering a
/// guest cluster.
///
/// Pure function: takes the raw L1 entry value (the guest
/// reads it from disk) and the index of the L2 entry within
/// that L2 table. Returns the disk offset of the L2 entry
/// itself.
///
/// The L1 entry's high bits encode flags (`OFLAG_COPIED`); the
/// L2 table offset lives in bits 9..55, exposed via
/// `qcow2::L1_OFFSET_MASK`. For a zero L1 entry the returned
/// offset is meaningless; the guest must check
/// `l1_entry & L1_OFFSET_MASK == 0` first and skip the
/// cluster.
pub fn overlay_l2_byte_offset_qcow2(overlay_l1_entry: u64, l2_idx_in_table: u32) -> u64 {
    (overlay_l1_entry & L1_OFFSET_MASK) + (l2_idx_in_table as u64) * 8
}

/// Compute the disk byte offset of the refcount entry for a
/// given host offset on the overlay.
///
/// Returns `(byte_offset, bit_in_byte)`. For
/// `refcount_bits == 16` the byte offset addresses two bytes
/// holding the BE-encoded entry and `bit_in_byte` is always
/// zero; the signature anticipates the 1/2/4-bit follow-up.
///
/// `overlay_refblock_host_offset` is the host byte offset of
/// the overlay's refcount block that covers the given host
/// offset; the guest reads this from its own staged copy of
/// the overlay's refcount table (the planner does not stage
/// the overlay's refcount table — only the backing's).
pub fn overlay_refcount_byte_offset_qcow2(
    overlay_refblock_host_offset: u64,
    entry_idx_in_refblock: u64,
) -> (u64, u8) {
    // v1: 16-bit width only. Entry width follow-up will
    // generalise this to (byte_offset = refblock + entry *
    // bits/8, bit = (entry * bits) % 8).
    (overlay_refblock_host_offset + entry_idx_in_refblock * 2, 0)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal v3 qcow2 header buffer for tests.
    /// `cluster_bits = 16` (64 KB clusters), `refcount_bits =
    /// 16`, `virtual_size` configurable.
    fn make_header(virtual_size: u64) -> [u8; 4096] {
        let mut h = [0u8; 4096];
        h[0..4].copy_from_slice(&qcow2::QCOW2_MAGIC.to_be_bytes());
        h[4..8].copy_from_slice(&3u32.to_be_bytes());
        h[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits
        h[24..32].copy_from_slice(&virtual_size.to_be_bytes());
        h[36..40].copy_from_slice(&1u32.to_be_bytes()); // l1_size
        h[40..48].copy_from_slice(&(2u64 * 65536).to_be_bytes()); // l1_table_offset
        h[48..56].copy_from_slice(&65536u64.to_be_bytes()); // refcount_table_offset
        h[56..60].copy_from_slice(&1u32.to_be_bytes()); // refcount_table_clusters
        h[96..100].copy_from_slice(&4u32.to_be_bytes()); // refcount_order = 4 (16-bit)
        h[100..104].copy_from_slice(&104u32.to_be_bytes()); // header_length
        h
    }

    fn make_header_with_external_data() -> [u8; 4096] {
        let mut h = make_header(1 << 20);
        h[72..80].copy_from_slice(&INCOMPAT_EXTERNAL_DATA.to_be_bytes());
        h
    }

    fn make_header_with_crypt() -> [u8; 4096] {
        let mut h = make_header(1 << 20);
        h[32..36].copy_from_slice(&1u32.to_be_bytes()); // crypt_method = AES
        h
    }

    fn baseline_opts<'a>(overlay_hdr: &'a [u8], backing_hdr: &'a [u8]) -> Qcow2CommitOpts<'a> {
        Qcow2CommitOpts {
            overlay_header: overlay_hdr,
            overlay_file_size: 1 << 20,
            backing_header: backing_hdr,
            backing_file_size: 1 << 20,
        }
    }

    #[test]
    fn rejects_external_data_overlay() {
        let oh = make_header_with_external_data();
        let bh = make_header(1 << 20);
        let r = plan_commit_qcow2(&baseline_opts(&oh, &bh));
        assert_eq!(r.err(), Some(CommitError::ExternalDataFile));
    }

    #[test]
    fn rejects_external_data_backing() {
        let oh = make_header(1 << 20);
        let bh = make_header_with_external_data();
        let r = plan_commit_qcow2(&baseline_opts(&oh, &bh));
        assert_eq!(r.err(), Some(CommitError::ExternalDataFile));
    }

    #[test]
    fn rejects_encrypted_overlay() {
        let oh = make_header_with_crypt();
        let bh = make_header(1 << 20);
        let r = plan_commit_qcow2(&baseline_opts(&oh, &bh));
        assert_eq!(r.err(), Some(CommitError::LuksUnsupported));
    }

    #[test]
    fn rejects_backing_smaller_than_overlay() {
        let oh = make_header(2 << 20);
        let bh = make_header(1 << 20);
        let r = plan_commit_qcow2(&baseline_opts(&oh, &bh));
        assert_eq!(r.err(), Some(CommitError::OverlayLargerThanBacking));
    }

    #[test]
    fn plan_populates_geometry() {
        let oh = make_header(1 << 20);
        let bh = make_header(1 << 20);
        let ctx = plan_commit_qcow2(&baseline_opts(&oh, &bh)).expect("plan ok");
        assert_eq!(ctx.overlay_cluster_size, 65536);
        assert_eq!(ctx.overlay_cluster_count, (1u64 << 20) / 65536);
        assert_eq!(ctx.overlay_l1_size, 1);
        assert_eq!(ctx.overlay_l1_table_offset, 2 * 65536);
        assert_eq!(ctx.overlay_refcount_table_offset, 65536);
        assert_eq!(ctx.overlay_refcount_table_clusters, 1);
        assert_eq!(ctx.overlay_refcount_bits, 16);
        // 64 KiB clusters, 16-bit entries.
        assert_eq!(ctx.overlay_entries_per_refblock, 65536 * 8 / 16);
    }

    #[test]
    fn overlay_l2_byte_offset_decodes_l1_entry() {
        // L2 table at host offset 0x20000 (cluster 2 with
        // 64 KB clusters) with OFLAG_COPIED set.
        let l1_entry = 0x20000u64 | (1u64 << 63);
        let off = overlay_l2_byte_offset_qcow2(l1_entry, 5);
        assert_eq!(off, 0x20000 + 5 * 8);
    }

    #[test]
    fn overlay_refcount_byte_offset_16bit() {
        let (off, bit) = overlay_refcount_byte_offset_qcow2(0x10000, 7);
        assert_eq!(off, 0x10000 + 7 * 2);
        assert_eq!(bit, 0);
    }
}
