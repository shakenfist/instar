//! qcow2 commit planner.
//!
//! Stages the backing's refcount blocks into scratch, validates
//! that the overlay and backing geometries are compatible, and
//! returns a [`Qcow2CommitContext`] the guest threads through a
//! per-cluster commit loop. The pure allocator
//! [`allocate_backing_cluster_qcow2`] hands out fresh backing
//! host offsets as the guest decides to copy clusters.
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
    /// Backing's current file size in bytes (the allocator
    /// does not grow it in v1).
    pub backing_file_size: u64,
    /// Backing's refcount-table bytes (an array of u64 BE
    /// entries pointing at refcount blocks). The planner only
    /// uses these to validate the host-supplied
    /// `backing_refblock_host_offsets`; the allocator works
    /// against the staged refblock bytes directly.
    pub backing_refcount_table: &'a [u8],
    /// Host byte offsets of each backing refcount block.
    /// Length must equal `backing_refblock_count`.
    pub backing_refblock_host_offsets: &'a [u64],
    /// Concatenated backing refcount-block bytes.
    pub backing_refcount_blocks: &'a [u8],
    /// Number of refcount blocks present in
    /// `backing_refcount_blocks`.
    pub backing_refblock_count: u32,
}

/// Context the guest threads through a qcow2 commit loop.
#[derive(Debug)]
pub struct Qcow2CommitContext<'a> {
    pub overlay_cluster_size: u32,
    pub overlay_cluster_count: u64,
    pub overlay_l1_table_offset: u64,
    pub overlay_l1_size: u32,
    pub overlay_refcount_table_offset: u64,
    pub overlay_refcount_table_clusters: u32,
    pub overlay_refcount_bits: u32,
    pub overlay_entries_per_refblock: u64,
    pub backing_cluster_size: u32,
    pub backing_cluster_count: u64,
    pub backing_l1_table_offset: u64,
    pub backing_l1_size: u32,
    pub backing_refcount_bits: u32,
    pub backing_entries_per_refblock: u64,
    pub backing_refblock_count: u32,
    /// Staged backing refcount-block bytes, mutated in place
    /// by [`allocate_backing_cluster_qcow2`].
    pub backing_refblocks: &'a mut [u8],
    /// Echoed from opts so the guest can flush dirty blocks
    /// back without re-parsing the refcount table.
    pub backing_refblock_host_offsets: &'a [u64],
    /// Per-refblock dirty bitmap; bit `i` is set if the
    /// allocator has modified refblock `i`. Length is
    /// `(backing_refblock_count + 7) / 8`.
    pub backing_dirty: &'a mut [u8],
}

/// Allocator state threaded through repeated calls to
/// [`allocate_backing_cluster_qcow2`].
#[derive(Debug, Clone, Copy, Default)]
pub struct BackingAllocationState {
    /// Refblock index where the next scan resumes.
    pub next_refblock: u32,
    /// Entry index within the current refblock where the next
    /// scan resumes.
    pub next_entry_in_refblock: u64,
    /// Total clusters allocated so far in the backing.
    pub allocated: u64,
}

/// Plan a qcow2 commit.
///
/// Validates compatibility between the overlay and the backing,
/// stages the backing's refcount blocks into scratch, and
/// returns a [`Qcow2CommitContext`] borrowing into scratch. The
/// guest drives the per-cluster commit loop itself; the
/// planner does not pre-compute any patches.
pub fn plan_commit_qcow2<'a>(
    opts: &Qcow2CommitOpts<'a>,
    scratch: &'a mut [u8],
) -> Result<Qcow2CommitContext<'a>, CommitError> {
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

    let backing_cluster_size = backing.cluster_size;
    let backing_entries_per_refblock = (backing_cluster_size * 8) / backing.refcount_bits as u64;
    let overlay_cluster_size = overlay.cluster_size;
    let overlay_entries_per_refblock = (overlay_cluster_size * 8) / overlay.refcount_bits as u64;

    // ----- Validate the host-supplied backing-refblock buffers
    let refblock_count = opts.backing_refblock_count as usize;
    let refblocks_size_bytes = refblock_count
        .checked_mul(backing_cluster_size as usize)
        .ok_or(CommitError::Overflow)?;
    if opts.backing_refcount_blocks.len() < refblocks_size_bytes {
        return Err(CommitError::HeaderMismatch);
    }
    if opts.backing_refblock_host_offsets.len() != refblock_count {
        return Err(CommitError::HeaderMismatch);
    }

    // ----- Carve scratch -----------------------------------
    let dirty_bytes = refblock_count.div_ceil(8);
    let need = dirty_bytes
        .checked_add(refblocks_size_bytes)
        .ok_or(CommitError::Overflow)?;
    if scratch.len() < need {
        return Err(CommitError::ScratchTooSmall);
    }

    let (dirty_buf, rest) = scratch.split_at_mut(dirty_bytes);
    let (refblocks_buf, _rest) = rest.split_at_mut(refblocks_size_bytes);

    refblocks_buf.copy_from_slice(&opts.backing_refcount_blocks[..refblocks_size_bytes]);
    for b in dirty_buf.iter_mut() {
        *b = 0;
    }

    let overlay_cluster_count = overlay.virtual_size.div_ceil(overlay_cluster_size);
    let backing_cluster_count = backing.virtual_size.div_ceil(backing_cluster_size);

    Ok(Qcow2CommitContext {
        overlay_cluster_size: overlay_cluster_size as u32,
        overlay_cluster_count,
        overlay_l1_table_offset: overlay.l1_table_offset,
        overlay_l1_size: overlay.l1_size,
        overlay_refcount_table_offset: overlay.refcount_table_offset,
        overlay_refcount_table_clusters: overlay.refcount_table_clusters,
        overlay_refcount_bits: overlay.refcount_bits,
        overlay_entries_per_refblock,
        backing_cluster_size: backing_cluster_size as u32,
        backing_cluster_count,
        backing_l1_table_offset: backing.l1_table_offset,
        backing_l1_size: backing.l1_size,
        backing_refcount_bits: backing.refcount_bits,
        backing_entries_per_refblock,
        backing_refblock_count: opts.backing_refblock_count,
        backing_refblocks: refblocks_buf,
        backing_refblock_host_offsets: opts.backing_refblock_host_offsets,
        backing_dirty: dirty_buf,
    })
}

/// Allocate a single fresh cluster in the backing.
///
/// Pure function: scans the staged backing refcount-block
/// bytes starting from `state.next_refblock` /
/// `state.next_entry_in_refblock`, finds the next entry
/// whose refcount is zero, bumps it to one, marks the
/// containing refblock dirty, and returns the host byte
/// offset of the claimed cluster.
///
/// v1 supports `context.backing_refcount_bits == 16` only.
/// Returns [`CommitError::UnsupportedFormat`] for other widths
/// and [`CommitError::RefcountExhausted`] when every existing
/// block is full.
pub fn allocate_backing_cluster_qcow2(
    context: &mut Qcow2CommitContext<'_>,
    state: &mut BackingAllocationState,
) -> Result<u64, CommitError> {
    if context.backing_refcount_bits != 16 {
        return Err(CommitError::UnsupportedFormat);
    }
    let cluster_size = context.backing_cluster_size as u64;
    let entries_per_refblock = context.backing_entries_per_refblock;
    let bytes_per_refblock = cluster_size as usize;

    while state.next_refblock < context.backing_refblock_count {
        let refblock_idx = state.next_refblock as usize;
        let refblock_byte_offset = refblock_idx
            .checked_mul(bytes_per_refblock)
            .ok_or(CommitError::Overflow)?;
        let refblock = context
            .backing_refblocks
            .get_mut(refblock_byte_offset..refblock_byte_offset + bytes_per_refblock)
            .ok_or(CommitError::BackingCorrupt)?;

        while state.next_entry_in_refblock < entries_per_refblock {
            let entry_idx = state.next_entry_in_refblock as usize;
            let byte_off = entry_idx * 2; // 16-bit entries
            if byte_off + 2 > refblock.len() {
                break;
            }
            let raw = u16::from_be_bytes([refblock[byte_off], refblock[byte_off + 1]]);
            if raw == 0 {
                // Claim it.
                let one = 1u16.to_be_bytes();
                refblock[byte_off] = one[0];
                refblock[byte_off + 1] = one[1];

                // Mark refblock dirty.
                let dirty_byte = refblock_idx / 8;
                let dirty_bit = refblock_idx % 8;
                if let Some(b) = context.backing_dirty.get_mut(dirty_byte) {
                    *b |= 1u8 << dirty_bit;
                }

                let cluster_index = (state.next_refblock as u64)
                    .checked_mul(entries_per_refblock)
                    .and_then(|v| v.checked_add(state.next_entry_in_refblock))
                    .ok_or(CommitError::Overflow)?;
                let host_offset = cluster_index
                    .checked_mul(cluster_size)
                    .ok_or(CommitError::Overflow)?;

                state.next_entry_in_refblock += 1;
                state.allocated += 1;
                return Ok(host_offset);
            }
            state.next_entry_in_refblock += 1;
        }

        state.next_refblock += 1;
        state.next_entry_in_refblock = 0;
    }

    Err(CommitError::RefcountExhausted)
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

    fn baseline_opts<'a>(
        overlay_hdr: &'a [u8],
        backing_hdr: &'a [u8],
        refblocks: &'a [u8],
        offsets: &'a [u64],
        count: u32,
    ) -> Qcow2CommitOpts<'a> {
        Qcow2CommitOpts {
            overlay_header: overlay_hdr,
            overlay_file_size: 1 << 20,
            backing_header: backing_hdr,
            backing_file_size: 1 << 20,
            backing_refcount_table: &[],
            backing_refblock_host_offsets: offsets,
            backing_refcount_blocks: refblocks,
            backing_refblock_count: count,
        }
    }

    #[test]
    fn rejects_external_data_overlay() {
        let oh = make_header_with_external_data();
        let bh = make_header(1 << 20);
        let mut scratch = [0u8; 65536 * 2];
        let one_block = [0u8; 65536];
        let offsets = [65536u64];
        let opts = baseline_opts(&oh, &bh, &one_block, &offsets, 1);
        let r = plan_commit_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(CommitError::ExternalDataFile));
    }

    #[test]
    fn rejects_external_data_backing() {
        let oh = make_header(1 << 20);
        let bh = make_header_with_external_data();
        let mut scratch = [0u8; 65536 * 2];
        let one_block = [0u8; 65536];
        let offsets = [65536u64];
        let opts = baseline_opts(&oh, &bh, &one_block, &offsets, 1);
        let r = plan_commit_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(CommitError::ExternalDataFile));
    }

    #[test]
    fn rejects_encrypted_overlay() {
        let oh = make_header_with_crypt();
        let bh = make_header(1 << 20);
        let mut scratch = [0u8; 65536 * 2];
        let one_block = [0u8; 65536];
        let offsets = [65536u64];
        let opts = baseline_opts(&oh, &bh, &one_block, &offsets, 1);
        let r = plan_commit_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(CommitError::LuksUnsupported));
    }

    #[test]
    fn rejects_backing_smaller_than_overlay() {
        let oh = make_header(2 << 20);
        let bh = make_header(1 << 20);
        let mut scratch = [0u8; 65536 * 2];
        let one_block = [0u8; 65536];
        let offsets = [65536u64];
        let opts = baseline_opts(&oh, &bh, &one_block, &offsets, 1);
        let r = plan_commit_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(CommitError::OverlayLargerThanBacking));
    }

    #[test]
    fn plan_populates_geometry() {
        let oh = make_header(1 << 20);
        let bh = make_header(1 << 20);
        let mut scratch = [0u8; 65536 * 2];
        let one_block = [0u8; 65536];
        let offsets = [65536u64];
        let opts = baseline_opts(&oh, &bh, &one_block, &offsets, 1);
        let ctx = plan_commit_qcow2(&opts, &mut scratch).expect("plan ok");
        assert_eq!(ctx.overlay_cluster_size, 65536);
        assert_eq!(ctx.backing_cluster_size, 65536);
        assert_eq!(ctx.overlay_cluster_count, (1u64 << 20) / 65536);
        assert_eq!(ctx.backing_refblock_count, 1);
        assert_eq!(ctx.backing_refblocks.len(), 65536);
        assert_eq!(ctx.backing_dirty.len(), 1);
        assert_eq!(ctx.backing_dirty[0], 0);
    }

    #[test]
    fn allocator_claims_first_free_cluster() {
        let oh = make_header(1 << 20);
        let bh = make_header(1 << 20);
        let mut scratch = [0u8; 65536 * 2];
        // Mark entries 0..3 already-allocated in the backing's
        // staged refblock.
        let mut one_block = [0u8; 65536];
        let one = 1u16.to_be_bytes();
        one_block[0..2].copy_from_slice(&one);
        one_block[2..4].copy_from_slice(&one);
        one_block[4..6].copy_from_slice(&one);
        let offsets = [65536u64];
        let opts = baseline_opts(&oh, &bh, &one_block, &offsets, 1);

        let mut ctx = plan_commit_qcow2(&opts, &mut scratch).expect("plan ok");
        let mut state = BackingAllocationState::default();
        let off = allocate_backing_cluster_qcow2(&mut ctx, &mut state).expect("alloc");
        // Cluster 3 -> offset 3 * 65536 = 196608.
        assert_eq!(off, 3 * 65536);
        assert_eq!(state.allocated, 1);
        let raw = u16::from_be_bytes([ctx.backing_refblocks[6], ctx.backing_refblocks[7]]);
        assert_eq!(raw, 1);
        assert_eq!(ctx.backing_dirty[0] & 1, 1);
    }

    #[test]
    fn allocator_advances_across_calls() {
        let oh = make_header(1 << 20);
        let bh = make_header(1 << 20);
        let mut scratch = [0u8; 65536 * 2];
        let one_block = [0u8; 65536];
        let offsets = [65536u64];
        let opts = baseline_opts(&oh, &bh, &one_block, &offsets, 1);

        let mut ctx = plan_commit_qcow2(&opts, &mut scratch).expect("plan ok");
        let mut state = BackingAllocationState::default();
        let a = allocate_backing_cluster_qcow2(&mut ctx, &mut state).unwrap();
        let b = allocate_backing_cluster_qcow2(&mut ctx, &mut state).unwrap();
        let c = allocate_backing_cluster_qcow2(&mut ctx, &mut state).unwrap();
        assert_eq!(a, 0);
        assert_eq!(b, 65536);
        assert_eq!(c, 2 * 65536);
        assert_eq!(state.allocated, 3);
    }

    #[test]
    fn allocator_exhausted_when_full() {
        let _oh = make_header(1 << 20);
        let _bh = make_header(1 << 20);
        let mut scratch = [0u8; 32];
        let mut tiny_block = [0u8; 8]; // 4 × 16-bit entries
        for chunk in tiny_block.chunks_mut(2) {
            chunk.copy_from_slice(&1u16.to_be_bytes());
        }
        let offsets = [65536u64];
        // Override cluster size by hand-crafting a small
        // refblock — we can't get plan_commit_qcow2 to give us
        // a 4-entry block, so build the context manually for
        // this allocator test.
        let mut refblocks = tiny_block;
        let mut dirty = [0u8; 1];
        let mut ctx = Qcow2CommitContext {
            overlay_cluster_size: 8,
            overlay_cluster_count: 1,
            overlay_l1_table_offset: 0,
            overlay_l1_size: 0,
            overlay_refcount_table_offset: 0,
            overlay_refcount_table_clusters: 0,
            overlay_refcount_bits: 16,
            overlay_entries_per_refblock: 4,
            backing_cluster_size: 8,
            backing_cluster_count: 1,
            backing_l1_table_offset: 0,
            backing_l1_size: 0,
            backing_refcount_bits: 16,
            backing_entries_per_refblock: 4,
            backing_refblock_count: 1,
            backing_refblocks: &mut refblocks,
            backing_refblock_host_offsets: &offsets,
            backing_dirty: &mut dirty,
        };
        let mut state = BackingAllocationState::default();
        let r = allocate_backing_cluster_qcow2(&mut ctx, &mut state);
        assert_eq!(r.err(), Some(CommitError::RefcountExhausted));
        let _ = &mut scratch;
    }

    #[test]
    fn allocator_rejects_non_16bit_widths() {
        let offsets = [65536u64];
        let mut refblocks = [0u8; 64];
        let mut dirty = [0u8; 1];
        let mut ctx = Qcow2CommitContext {
            overlay_cluster_size: 64,
            overlay_cluster_count: 1,
            overlay_l1_table_offset: 0,
            overlay_l1_size: 0,
            overlay_refcount_table_offset: 0,
            overlay_refcount_table_clusters: 0,
            overlay_refcount_bits: 32,
            overlay_entries_per_refblock: 16,
            backing_cluster_size: 64,
            backing_cluster_count: 1,
            backing_l1_table_offset: 0,
            backing_l1_size: 0,
            backing_refcount_bits: 32,
            backing_entries_per_refblock: 16,
            backing_refblock_count: 1,
            backing_refblocks: &mut refblocks,
            backing_refblock_host_offsets: &offsets,
            backing_dirty: &mut dirty,
        };
        let mut state = BackingAllocationState::default();
        let r = allocate_backing_cluster_qcow2(&mut ctx, &mut state);
        assert_eq!(r.err(), Some(CommitError::UnsupportedFormat));
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
