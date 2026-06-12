//! qcow2 snapshot mutator primitives.
//!
//! Pure functions over caller-staged byte slices. No I/O. The
//! phase 5 mission is to land the eight building blocks the
//! phase 6-8 per-mode planners will compose:
//!
//! 1. [`read_refcount_in_block`] — scalar refcount read.
//! 2. [`set_refcount_in_block`] — scalar refcount write (lifted
//!    from `resize::qcow2::set_refcount`).
//! 3. [`check_refcount_after_addend`] — overflow-safe addend.
//! 4. [`alloc_cluster_in_refblocks`] + [`AllocCursor`] —
//!    cursor-driven linear-scan allocator over staged refcount
//!    blocks.
//! 5. [`rewrite_l1_entry_copied_flag`] — set/clear
//!    `OFLAG_COPIED` on one L1 entry.
//! 6. [`rewrite_l2_entry_copied_flag`] — same for L2 (standard
//!    or extended-L2 stride).
//! 7. [`for_each_cluster_in_l1`] + [`L1ClusterRef`] — visitor
//!    over the L1 -> L2 chain.
//! 8. [`update_snapshot_refcount`] + [`SnapshotRefcountOp`] —
//!    two-pass refcount mutator (dry-run reads only, apply
//!    pass mutates).
//! 9. [`update_copied_flags_for_l1`] — walks the L1, rewriting
//!    COPIED flags on L1 and L2 entries based on current
//!    refcount.
//!
//! Refcount-width coverage: [`read_refcount_in_block`] and
//! [`set_refcount_in_block`] support every spec-permitted width
//! (1, 2, 4, 8, 16, 32, 64). The allocator
//! [`alloc_cluster_in_refblocks`] supports `refcount_bits ==
//! 16` only in v1 (the qemu-img default and the only width the
//! sister `commit` crate's allocator handles).

use qcow2::{L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COMPRESSED, OFLAG_COPIED};

use crate::SnapshotError;

// ---------------------------------------------------------------------------
// Scalar refcount accessors
// ---------------------------------------------------------------------------

/// Read the refcount entry at index `local_idx` within a
/// refcount block.
///
/// Mirrors the bit-packing of [`set_refcount_in_block`] exactly
/// so set -> read round trips. Returns
/// [`SnapshotError::MisalignedAccess`] if the entry extends past
/// the end of `block`, and [`SnapshotError::Unsupported`] for
/// any width not in the qcow2 spec set
/// `{1, 2, 4, 8, 16, 32, 64}`.
pub fn read_refcount_in_block(
    block: &[u8],
    local_idx: u64,
    refcount_bits: u32,
) -> Result<u64, SnapshotError> {
    match refcount_bits {
        // Sub-byte widths are LSB-first within each byte: entry 0
        // occupies the LOWEST bits of byte 0, matching qemu's
        // get_refcount_ro0/ro1/ro2 in block/qcow2-refcount.c
        // (`>> (index % 8)`, `>> (2 * (index % 4))`,
        // `>> (4 * (index % 2))`). These paths were MSB-first
        // until the PLAN-snapshot pre-push audit caught the
        // divergence from qemu and from qcow2::lookup_refcount;
        // the MSB-first order corrupted refcount_bits 1/2/4
        // images in `resize --shrink`, which delegates here.
        1 => {
            let byte = (local_idx / 8) as usize;
            if byte >= block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            let bit = (local_idx % 8) as u32;
            Ok(((block[byte] >> bit) & 0b1) as u64)
        }
        2 => {
            let byte = (local_idx / 4) as usize;
            if byte >= block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            let shift = 2 * (local_idx % 4) as u32;
            Ok(((block[byte] >> shift) & 0b11) as u64)
        }
        4 => {
            let byte = (local_idx / 2) as usize;
            if byte >= block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            let shift = if local_idx.is_multiple_of(2) { 0 } else { 4 };
            Ok(((block[byte] >> shift) & 0b1111) as u64)
        }
        8 => {
            let byte = local_idx as usize;
            if byte >= block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            Ok(block[byte] as u64)
        }
        16 => {
            let off = (local_idx as usize) * 2;
            if off + 2 > block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            Ok(u16::from_be_bytes([block[off], block[off + 1]]) as u64)
        }
        32 => {
            let off = (local_idx as usize) * 4;
            if off + 4 > block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            Ok(
                u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]])
                    as u64,
            )
        }
        64 => {
            let off = (local_idx as usize) * 8;
            if off + 8 > block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            Ok(u64::from_be_bytes([
                block[off],
                block[off + 1],
                block[off + 2],
                block[off + 3],
                block[off + 4],
                block[off + 5],
                block[off + 6],
                block[off + 7],
            ]))
        }
        _ => Err(SnapshotError::Unsupported),
    }
}

/// Set the refcount entry at index `local_idx` within a
/// refcount block to `value`.
///
/// Lifted from `resize::qcow2::set_refcount` (the resize crate
/// now delegates here via a thin wrapper). The byte-and-wider
/// widths are preserved byte-for-byte from the original; the
/// sub-byte widths (1/2/4) were corrected to qemu's LSB-first
/// packing during the PLAN-snapshot pre-push audit — the
/// original MSB-first order corrupted sub-byte-width images in
/// `resize --shrink` (see the ordering note on
/// [`read_refcount_in_block`]). The signature widens
/// `refcount_bits` from `u8` to `u32` to match the rest of the
/// snapshot crate's API; resize bridges the type difference via
/// a thin wrapper.
///
/// Returns [`SnapshotError::MisalignedAccess`] if the entry
/// extends past the end of `block` or
/// [`SnapshotError::Unsupported`] for unsupported widths.
pub fn set_refcount_in_block(
    block: &mut [u8],
    local_idx: u64,
    refcount_bits: u32,
    value: u64,
) -> Result<(), SnapshotError> {
    match refcount_bits {
        // Sub-byte widths are LSB-first within each byte, matching
        // qemu's set_refcount_ro0/ro1/ro2 — see the ordering note
        // on read_refcount_in_block above.
        1 => {
            let byte = (local_idx / 8) as usize;
            if byte >= block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            let bit = (local_idx % 8) as u32;
            if value == 0 {
                block[byte] &= !(1 << bit);
            } else {
                block[byte] |= 1 << bit;
            }
        }
        2 => {
            let byte = (local_idx / 4) as usize;
            if byte >= block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            let shift = 2 * (local_idx % 4) as u32;
            let mask = 0b11u8 << shift;
            block[byte] = (block[byte] & !mask) | (((value as u8) & 0b11) << shift);
        }
        4 => {
            let byte = (local_idx / 2) as usize;
            if byte >= block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            let shift = if local_idx.is_multiple_of(2) { 0 } else { 4 };
            let mask = 0b1111u8 << shift;
            block[byte] = (block[byte] & !mask) | (((value as u8) & 0b1111) << shift);
        }
        8 => {
            let byte = local_idx as usize;
            if byte >= block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            block[byte] = value as u8;
        }
        16 => {
            let off = (local_idx as usize) * 2;
            if off + 2 > block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            block[off] = (value >> 8) as u8;
            block[off + 1] = value as u8;
        }
        32 => {
            let off = (local_idx as usize) * 4;
            if off + 4 > block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            for i in 0..4 {
                block[off + i] = (value >> ((3 - i) * 8)) as u8;
            }
        }
        64 => {
            let off = (local_idx as usize) * 8;
            if off + 8 > block.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            for i in 0..8 {
                block[off + i] = (value >> ((7 - i) * 8)) as u8;
            }
        }
        _ => return Err(SnapshotError::Unsupported),
    }
    Ok(())
}

/// Compute `current + addend`, returning the new value or an
/// error if the result would overflow the configured refcount
/// width (positive addend) or underflow below zero (negative
/// addend — defensive; should never happen if the caller paired
/// inc/dec correctly).
///
/// For `refcount_bits >= 64` the max is `u64::MAX`; below that
/// the max is `(1u64 << refcount_bits) - 1`. `refcount_bits ==
/// 0` is rejected as [`SnapshotError::Unsupported`].
pub fn check_refcount_after_addend(
    current: u64,
    addend: i32,
    refcount_bits: u32,
) -> Result<u64, SnapshotError> {
    if refcount_bits == 0 {
        return Err(SnapshotError::Unsupported);
    }
    let max = if refcount_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << refcount_bits) - 1
    };
    if addend >= 0 {
        let inc = addend as u64;
        let new_val = current
            .checked_add(inc)
            .ok_or(SnapshotError::RefcountOverflow { at_host_offset: 0 })?;
        if new_val > max {
            return Err(SnapshotError::RefcountOverflow { at_host_offset: 0 });
        }
        Ok(new_val)
    } else {
        let dec = addend.unsigned_abs() as u64;
        if dec > current {
            // Underflow — caller bookkeeping error. Map to
            // ParseFailed (planner-internal misuse code).
            return Err(SnapshotError::ParseFailed);
        }
        Ok(current - dec)
    }
}

// ---------------------------------------------------------------------------
// Cluster allocator (refblock linear scan)
// ---------------------------------------------------------------------------

/// Allocator state threaded through repeated calls to
/// [`alloc_cluster_in_refblocks`].
///
/// Mirrors `commit::BackingAllocationState`. The cursor records
/// where the next scan resumes; callers may reset it to zero to
/// rescan from the start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocCursor {
    /// Refblock index where the next scan resumes.
    pub next_refblock: u64,
    /// Entry index within the current refblock where the next
    /// scan resumes.
    pub next_entry_in_refblock: u64,
    /// Total clusters allocated so far via this cursor.
    pub allocated: u64,
}

/// Allocate a single fresh cluster from the staged refcount
/// blocks.
///
/// Thin wrapper over [`alloc_contiguous_clusters_in_refblocks`]
/// with `count == 1`. See that function for the scan / cursor
/// semantics and the `refcount_bits == 16` v1 restriction.
pub fn alloc_cluster_in_refblocks(
    blocks: &mut [u8],
    cluster_size: u64,
    refcount_bits: u32,
    refblock_count: u64,
    host_refblocks_start: u64,
    cursor: &mut AllocCursor,
) -> Result<u64, SnapshotError> {
    alloc_contiguous_clusters_in_refblocks(
        blocks,
        cluster_size,
        refcount_bits,
        refblock_count,
        host_refblocks_start,
        1,
        cursor,
    )
}

/// Allocate `count` *consecutive* fresh clusters from the staged
/// refcount blocks (first-fit) and return the host byte offset of
/// the first.
///
/// Pure function: scans the concatenated `blocks` byte buffer
/// starting from `cursor.next_refblock` /
/// `cursor.next_entry_in_refblock` for the first run of `count`
/// consecutive cluster indices whose refcounts are all zero. The
/// run is allowed to span refblock boundaries (refblock coverage
/// is contiguous over consecutive cluster indices). Every claimed
/// entry is set to 1; the cursor is advanced past the run.
/// `host_refblocks_start` is added to the first cluster's index ×
/// `cluster_size` so callers can describe a virtual offset basis
/// independent of where the refblocks physically live.
///
/// `count == 0` is rejected as [`SnapshotError::InvalidConfig`]
/// (a zero-cluster allocation has no host offset to return; the
/// MODE_CREATE caller handles the `l1_size == 0` case separately).
///
/// v1 supports `refcount_bits == 16` only (matches the sister
/// `commit` crate's allocator scope). Other widths return
/// [`SnapshotError::Unsupported`].
///
/// Returns [`SnapshotError::RefcountExhausted`] if no run of
/// `count` consecutive free clusters exists. Refcount-table growth
/// is a separate concern (see open question 7 in the phase plan).
pub fn alloc_contiguous_clusters_in_refblocks(
    blocks: &mut [u8],
    cluster_size: u64,
    refcount_bits: u32,
    refblock_count: u64,
    host_refblocks_start: u64,
    count: u64,
    cursor: &mut AllocCursor,
) -> Result<u64, SnapshotError> {
    if refcount_bits != 16 {
        return Err(SnapshotError::Unsupported);
    }
    if cluster_size == 0 {
        return Err(SnapshotError::InvalidConfig);
    }
    if count == 0 {
        return Err(SnapshotError::InvalidConfig);
    }
    let entries_per_refblock = (cluster_size * 8) / refcount_bits as u64;
    if entries_per_refblock == 0 {
        return Err(SnapshotError::InvalidConfig);
    }
    let bytes_per_refblock = cluster_size as usize;
    let total_entries = refblock_count
        .checked_mul(entries_per_refblock)
        .ok_or(SnapshotError::ParseFailed)?;

    // Linear index over the flattened cluster space, resuming from
    // the cursor. `read_entry` maps a flat cluster index to its
    // refcount within `blocks` (bounds-checked).
    let read_entry = |blocks: &[u8], cluster_index: u64| -> Result<u64, SnapshotError> {
        let refblock_idx = cluster_index / entries_per_refblock;
        let entry_idx = cluster_index % entries_per_refblock;
        let refblock_byte_off = (refblock_idx as usize)
            .checked_mul(bytes_per_refblock)
            .ok_or(SnapshotError::ParseFailed)?;
        let refblock_end = refblock_byte_off
            .checked_add(bytes_per_refblock)
            .ok_or(SnapshotError::ParseFailed)?;
        if refblock_end > blocks.len() {
            return Err(SnapshotError::MisalignedAccess);
        }
        read_refcount_in_block(
            &blocks[refblock_byte_off..refblock_end],
            entry_idx,
            refcount_bits,
        )
    };

    let mut start = cursor
        .next_refblock
        .checked_mul(entries_per_refblock)
        .and_then(|v| v.checked_add(cursor.next_entry_in_refblock))
        .ok_or(SnapshotError::ParseFailed)?;

    while start + count <= total_entries {
        // Scan `count` consecutive entries from `start`.
        let mut all_free = true;
        let mut probe = start;
        while probe < start + count {
            if read_entry(blocks, probe)? != 0 {
                all_free = false;
                break;
            }
            probe += 1;
        }
        if all_free {
            // Claim every entry in the run.
            for cluster_index in start..start + count {
                let refblock_idx = cluster_index / entries_per_refblock;
                let entry_idx = cluster_index % entries_per_refblock;
                let refblock_byte_off = (refblock_idx as usize) * bytes_per_refblock;
                let refblock =
                    &mut blocks[refblock_byte_off..refblock_byte_off + bytes_per_refblock];
                set_refcount_in_block(refblock, entry_idx, refcount_bits, 1)?;
            }
            let next = start + count;
            cursor.next_refblock = next / entries_per_refblock;
            cursor.next_entry_in_refblock = next % entries_per_refblock;
            cursor.allocated += count;
            let host_offset = start
                .checked_mul(cluster_size)
                .and_then(|v| v.checked_add(host_refblocks_start))
                .ok_or(SnapshotError::ParseFailed)?;
            return Ok(host_offset);
        }
        // Resume scanning just past the occupied entry at `probe`.
        start = probe + 1;
    }

    Err(SnapshotError::RefcountExhausted)
}

// ---------------------------------------------------------------------------
// L1 / L2 COPIED flag rewrites
// ---------------------------------------------------------------------------

/// Set or clear [`OFLAG_COPIED`] on one L1 entry.
///
/// L1 entries are big-endian u64 values; the COPIED flag is
/// bit 63, the L2 table offset is in bits 9..55
/// (mask [`L1_OFFSET_MASK`]). This helper preserves every bit
/// outside bit 63.
///
/// Returns [`SnapshotError::MisalignedAccess`] if the entry
/// extends past the end of `l1_bytes`.
pub fn rewrite_l1_entry_copied_flag(
    l1_bytes: &mut [u8],
    entry_idx: u32,
    set: bool,
) -> Result<(), SnapshotError> {
    let off = (entry_idx as usize)
        .checked_mul(8)
        .ok_or(SnapshotError::MisalignedAccess)?;
    if off
        .checked_add(8)
        .map(|end| end > l1_bytes.len())
        .unwrap_or(true)
    {
        return Err(SnapshotError::MisalignedAccess);
    }
    let mut entry = u64::from_be_bytes([
        l1_bytes[off],
        l1_bytes[off + 1],
        l1_bytes[off + 2],
        l1_bytes[off + 3],
        l1_bytes[off + 4],
        l1_bytes[off + 5],
        l1_bytes[off + 6],
        l1_bytes[off + 7],
    ]);
    if set {
        entry |= OFLAG_COPIED;
    } else {
        entry &= !OFLAG_COPIED;
    }
    let be = entry.to_be_bytes();
    l1_bytes[off..off + 8].copy_from_slice(&be);
    Ok(())
}

/// Set or clear [`OFLAG_COPIED`] on one L2 entry.
///
/// Standard L2 entries are 8 bytes (one big-endian u64);
/// extended-L2 entries are 16 bytes (a big-endian u64
/// type-and-offset half followed by an 8-byte subcluster
/// bitmap). The COPIED flag is bit 63 of the type-and-offset
/// half in both cases; the subcluster bitmap is untouched.
///
/// Returns [`SnapshotError::MisalignedAccess`] if the entry
/// extends past the end of `l2_bytes`.
pub fn rewrite_l2_entry_copied_flag(
    l2_bytes: &mut [u8],
    entry_idx: u32,
    set: bool,
    extended_l2: bool,
) -> Result<(), SnapshotError> {
    let stride = if extended_l2 { 16usize } else { 8usize };
    let off = (entry_idx as usize)
        .checked_mul(stride)
        .ok_or(SnapshotError::MisalignedAccess)?;
    if off
        .checked_add(stride)
        .map(|end| end > l2_bytes.len())
        .unwrap_or(true)
    {
        return Err(SnapshotError::MisalignedAccess);
    }
    let mut entry = u64::from_be_bytes([
        l2_bytes[off],
        l2_bytes[off + 1],
        l2_bytes[off + 2],
        l2_bytes[off + 3],
        l2_bytes[off + 4],
        l2_bytes[off + 5],
        l2_bytes[off + 6],
        l2_bytes[off + 7],
    ]);
    if set {
        entry |= OFLAG_COPIED;
    } else {
        entry &= !OFLAG_COPIED;
    }
    let be = entry.to_be_bytes();
    l2_bytes[off..off + 8].copy_from_slice(&be);
    // Subcluster bitmap (bytes off+8..off+16) is intentionally
    // untouched for extended-L2.
    Ok(())
}

// ---------------------------------------------------------------------------
// L1 / L2 visitor
// ---------------------------------------------------------------------------

/// Per-cluster reference produced by [`for_each_cluster_in_l1`].
///
/// Carries enough context for the visitor to find the cluster
/// in the staged metadata buffers and to bump the appropriate
/// refcount. The `classification` field captures whether the
/// cluster is a Standard data cluster or a Compressed payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L1ClusterRef {
    /// Index of the L1 entry that reached this cluster.
    pub l1_idx: u32,
    /// Index of the L2 entry that reached this cluster.
    pub l2_idx: u32,
    /// Host byte offset of the data cluster (or compressed
    /// payload start).
    pub host_offset: u64,
    /// Classification of the L2 entry.
    pub classification: L2Classification,
}

/// Lightweight classifier for L2 entries used by the snapshot
/// visitor. Captures the distinctions the snapshot refcount /
/// COPIED-flag walks care about; the richer `MapExtent` from
/// the `qcow2` crate is overkill for refcount bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2Classification {
    /// Standard data cluster pointed at by an L2 entry.
    Standard,
    /// Compressed payload; the L2 entry's
    /// type-and-offset half encodes a byte-granular start
    /// and a length, but for refcount bookkeeping only the
    /// host offset of the containing cluster is needed.
    Compressed,
}

/// Visit every allocated cluster reachable from an L1 table.
///
/// Iterates `l1_bytes` (big-endian u64 entries), masks out
/// [`OFLAG_COPIED`] / [`OFLAG_COMPRESSED`] / extended-L2 flag
/// bits via [`L1_OFFSET_MASK`] to find the L2 table offset, and
/// calls `l2_for_index` to retrieve the staged L2 bytes. For
/// each L2 entry, classifies it; allocated entries (Standard
/// or Compressed) build a [`L1ClusterRef`] and invoke `visit`.
/// Unallocated L1 entries (entry value zero after masking) and
/// unallocated L2 entries are skipped (open question 8).
///
/// Returning `false` from the visitor stops the walk; the
/// function returns `Ok(())` either way.
///
/// Returns [`SnapshotError::MisalignedAccess`] if `l2_for_index`
/// returns `None` for an allocated L1 entry (the caller is
/// supposed to have staged every L2 the L1 references).
pub fn for_each_cluster_in_l1<'l2, L2F, VisitF>(
    l1_bytes: &[u8],
    cluster_bits: u32,
    mut l2_for_index: L2F,
    extended_l2: bool,
    mut visit: VisitF,
) -> Result<(), SnapshotError>
where
    L2F: FnMut(u32) -> Option<&'l2 [u8]>,
    VisitF: FnMut(L1ClusterRef) -> bool,
{
    // Reject silly cluster_bits early; the L2 stride math
    // assumes cluster_bits >= 9 (the qcow2 minimum 512-byte
    // cluster), but we only really need a non-zero value here.
    if cluster_bits == 0 {
        return Err(SnapshotError::InvalidConfig);
    }
    let l2_entry_stride = if extended_l2 { 16usize } else { 8usize };

    let l1_entries = l1_bytes.len() / 8;
    for l1_idx in 0..l1_entries {
        let off = l1_idx * 8;
        let raw = u64::from_be_bytes([
            l1_bytes[off],
            l1_bytes[off + 1],
            l1_bytes[off + 2],
            l1_bytes[off + 3],
            l1_bytes[off + 4],
            l1_bytes[off + 5],
            l1_bytes[off + 6],
            l1_bytes[off + 7],
        ]);
        let l2_table_offset = raw & L1_OFFSET_MASK;
        if l2_table_offset == 0 {
            // Unallocated L1 entry: skip.
            continue;
        }

        let l2_bytes = match l2_for_index(l1_idx as u32) {
            Some(b) => b,
            None => return Err(SnapshotError::MisalignedAccess),
        };

        let l2_entries = l2_bytes.len() / l2_entry_stride;
        for l2_idx in 0..l2_entries {
            let eoff = l2_idx * l2_entry_stride;
            if eoff + 8 > l2_bytes.len() {
                break;
            }
            let l2_entry = u64::from_be_bytes([
                l2_bytes[eoff],
                l2_bytes[eoff + 1],
                l2_bytes[eoff + 2],
                l2_bytes[eoff + 3],
                l2_bytes[eoff + 4],
                l2_bytes[eoff + 5],
                l2_bytes[eoff + 6],
                l2_bytes[eoff + 7],
            ]);
            let masked = l2_entry & !OFLAG_COPIED;
            if masked == 0 {
                // Unallocated L2 entry: skip.
                continue;
            }
            let (classification, host_offset) = if (l2_entry & OFLAG_COMPRESSED) != 0 {
                // Compressed: low bits encode (offset, length).
                // For refcount bookkeeping, derive the host
                // offset of the containing cluster by clearing
                // the low cluster_bits bits.
                let raw_off = l2_entry & !(OFLAG_COMPRESSED | OFLAG_COPIED);
                let cluster_mask = !((1u64 << cluster_bits) - 1);
                (L2Classification::Compressed, raw_off & cluster_mask)
            } else {
                let host_offset = l2_entry & L2_OFFSET_MASK;
                if host_offset == 0 {
                    // Truly unallocated (only COPIED flag set,
                    // no offset). Skip.
                    continue;
                }
                (L2Classification::Standard, host_offset)
            };

            let cont = visit(L1ClusterRef {
                l1_idx: l1_idx as u32,
                l2_idx: l2_idx as u32,
                host_offset,
                classification,
            });
            if !cont {
                return Ok(());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Composed mutators: refcount adjust + COPIED-flag rewrite
// ---------------------------------------------------------------------------

/// Per-mode argument bundle for [`update_snapshot_refcount`].
#[derive(Debug, Clone, Copy)]
pub enum SnapshotRefcountOp<'a> {
    /// `-c` (create): increment refcount on every cluster
    /// reachable from `snapshot_l1`. The new snapshot now
    /// references the same clusters as the active L1.
    IncrementForCreate {
        /// L1 bytes whose reachable clusters get their refcount
        /// incremented.
        snapshot_l1: &'a [u8],
    },
    /// `-d` (delete): decrement refcount on every cluster
    /// reachable from `snapshot_l1`.
    DecrementForDelete {
        /// L1 bytes whose reachable clusters get their refcount
        /// decremented.
        snapshot_l1: &'a [u8],
    },
    /// `-a` (apply / goto): decrement on `from_l1` (the
    /// outgoing active L1, becomes a snapshot) and increment on
    /// `to_l1` (the target snapshot's L1, becomes the new
    /// active). Dry-run checks both; apply mutates both.
    SwapForApply {
        /// Outgoing active L1; its clusters get their refcount
        /// decremented.
        from_l1: &'a [u8],
        /// Incoming target L1; its clusters get their refcount
        /// incremented.
        to_l1: &'a [u8],
    },
}

/// Two-pass refcount mutator.
///
/// **Pass 1 (dry-run)** walks the relevant L1(s) and, for every
/// allocated cluster, reads the current refcount and runs
/// [`check_refcount_after_addend`]. If any check fails, the
/// function returns the error *before* mutating any refblock
/// byte. The dry-run pass guarantees byte-identity of
/// `refblocks` on failure.
///
/// **Pass 2 (apply)** walks the same L1(s) again and applies
/// each new value via [`set_refcount_in_block`].
///
/// Callers that need the validation *without* the paired apply
/// (e.g. MODE_DELETE's pre-write validation, which must run
/// before any disk write while the apply must run after the
/// commit-point header write) use the standalone
/// [`precheck_snapshot_refcount`], which runs exactly this
/// function's pass 1 against an immutable `refblocks`.
///
/// **L2-table coverage.** Both passes adjust the refcount of
/// every reachable *data* cluster **and** of each **L2 table
/// cluster** — once per non-zero L1 entry, after that entry's L2
/// data clusters, exactly as qemu's
/// `qcow2_update_snapshot_refcount` in `block/qcow2-refcount.c`
/// does (qemu calls `qcow2_update_cluster_refcount(l2_offset >>
/// cluster_bits, ...)` once per L1 entry). The L2-table bump is
/// mandatory for create: after a create the active L1 and the
/// snapshot's L1 copy share the same physical L2 tables, so the
/// L2 cluster's refcount must reach 2 for a later guest write to
/// trigger the L2 COW instead of silently mutating the
/// snapshot's L2 in place.
///
/// **L1-cluster exclusion.** Neither pass touches the L1 table's
/// own clusters — qemu's function doesn't either; the *caller*
/// owns L1-cluster refcounts (create allocates the snapshot's L1
/// copy at refcount 1; delete frees the snapshot's L1
/// explicitly).
///
/// `l2_for_index` returns the staged L2 bytes for a given L1
/// index; `refblock_byte_offset_for_cluster` maps a cluster's
/// host offset to `(refblock_byte_offset_within_blocks,
/// entry_local_idx)` — it is called for L2-table clusters with
/// the same mapping as for data clusters.
pub fn update_snapshot_refcount<'l2, L2F, RBF>(
    op: SnapshotRefcountOp<'_>,
    refblocks: &mut [u8],
    cluster_bits: u32,
    refcount_bits: u32,
    extended_l2: bool,
    mut l2_for_index: L2F,
    mut refblock_byte_offset_for_cluster: RBF,
) -> Result<(), SnapshotError>
where
    L2F: FnMut(u32) -> Option<&'l2 [u8]>,
    RBF: FnMut(u64) -> Option<(usize, u64)>,
{
    // Pass 1 (dry-run): walk relevant L1(s), check overflow.
    match op {
        SnapshotRefcountOp::IncrementForCreate { snapshot_l1 } => {
            dry_run_refcount_pass(
                snapshot_l1,
                1,
                refblocks,
                cluster_bits,
                refcount_bits,
                extended_l2,
                &mut l2_for_index,
                &mut refblock_byte_offset_for_cluster,
            )?;
        }
        SnapshotRefcountOp::DecrementForDelete { snapshot_l1 } => {
            dry_run_refcount_pass(
                snapshot_l1,
                -1,
                refblocks,
                cluster_bits,
                refcount_bits,
                extended_l2,
                &mut l2_for_index,
                &mut refblock_byte_offset_for_cluster,
            )?;
        }
        SnapshotRefcountOp::SwapForApply { from_l1, to_l1 } => {
            // Check each side in isolation against its own
            // addend so a shared cluster at the max ref doesn't
            // spuriously fail (dec to max-1 = ok, inc back to
            // max = ok independently).
            dry_run_refcount_pass(
                from_l1,
                -1,
                refblocks,
                cluster_bits,
                refcount_bits,
                extended_l2,
                &mut l2_for_index,
                &mut refblock_byte_offset_for_cluster,
            )?;
            dry_run_refcount_pass(
                to_l1,
                1,
                refblocks,
                cluster_bits,
                refcount_bits,
                extended_l2,
                &mut l2_for_index,
                &mut refblock_byte_offset_for_cluster,
            )?;
        }
    }

    // Pass 2 (apply): same walks, now mutating refblocks.
    match op {
        SnapshotRefcountOp::IncrementForCreate { snapshot_l1 } => apply_refcount_pass(
            snapshot_l1,
            1,
            refblocks,
            cluster_bits,
            refcount_bits,
            extended_l2,
            &mut l2_for_index,
            &mut refblock_byte_offset_for_cluster,
        ),
        SnapshotRefcountOp::DecrementForDelete { snapshot_l1 } => apply_refcount_pass(
            snapshot_l1,
            -1,
            refblocks,
            cluster_bits,
            refcount_bits,
            extended_l2,
            &mut l2_for_index,
            &mut refblock_byte_offset_for_cluster,
        ),
        SnapshotRefcountOp::SwapForApply { from_l1, to_l1 } => {
            apply_refcount_pass(
                from_l1,
                -1,
                refblocks,
                cluster_bits,
                refcount_bits,
                extended_l2,
                &mut l2_for_index,
                &mut refblock_byte_offset_for_cluster,
            )?;
            apply_refcount_pass(
                to_l1,
                1,
                refblocks,
                cluster_bits,
                refcount_bits,
                extended_l2,
                &mut l2_for_index,
                &mut refblock_byte_offset_for_cluster,
            )
        }
    }
}

/// Read-only refcount pre-validation: run
/// [`update_snapshot_refcount`]'s dry-run pass (pass 1) for `op`
/// without the paired apply pass.
///
/// Walks the relevant L1(s) and, for every reachable data cluster
/// **and** every L2 table cluster (the same coverage as
/// [`update_snapshot_refcount`]), reads the current refcount from
/// `refblocks` and runs [`check_refcount_after_addend`] with the
/// op's addend(s). `refblocks` is immutable — the borrow makes the
/// no-mutation guarantee structural.
///
/// MODE_DELETE (phase 7) calls this *before any disk write* so a
/// corrupt image (a chain cluster whose decrement would
/// underflow) fails with the file untouched; the later full
/// [`update_snapshot_refcount`] call's internal dry-run is then a
/// redundant-but-free second check. [`SnapshotRefcountOp::
/// SwapForApply`] prechecks both sides (decrement on `from_l1`,
/// increment on `to_l1`), each against the *current* refcounts —
/// the same independent-side semantics as the paired mutator's
/// pass 1.
///
/// Errors are those of the dry-run pass:
/// [`SnapshotError::RefcountOverflow`] (with the offending
/// cluster's host offset), [`SnapshotError::ParseFailed`] for a
/// decrement underflow, and [`SnapshotError::MisalignedAccess`]
/// for staging gaps.
pub fn precheck_snapshot_refcount<'l2, L2F, RBF>(
    op: SnapshotRefcountOp<'_>,
    refblocks: &[u8],
    cluster_bits: u32,
    refcount_bits: u32,
    extended_l2: bool,
    mut l2_for_index: L2F,
    mut refblock_byte_offset_for_cluster: RBF,
) -> Result<(), SnapshotError>
where
    L2F: FnMut(u32) -> Option<&'l2 [u8]>,
    RBF: FnMut(u64) -> Option<(usize, u64)>,
{
    match op {
        SnapshotRefcountOp::IncrementForCreate { snapshot_l1 } => dry_run_refcount_pass(
            snapshot_l1,
            1,
            refblocks,
            cluster_bits,
            refcount_bits,
            extended_l2,
            &mut l2_for_index,
            &mut refblock_byte_offset_for_cluster,
        ),
        SnapshotRefcountOp::DecrementForDelete { snapshot_l1 } => dry_run_refcount_pass(
            snapshot_l1,
            -1,
            refblocks,
            cluster_bits,
            refcount_bits,
            extended_l2,
            &mut l2_for_index,
            &mut refblock_byte_offset_for_cluster,
        ),
        SnapshotRefcountOp::SwapForApply { from_l1, to_l1 } => {
            dry_run_refcount_pass(
                from_l1,
                -1,
                refblocks,
                cluster_bits,
                refcount_bits,
                extended_l2,
                &mut l2_for_index,
                &mut refblock_byte_offset_for_cluster,
            )?;
            dry_run_refcount_pass(
                to_l1,
                1,
                refblocks,
                cluster_bits,
                refcount_bits,
                extended_l2,
                &mut l2_for_index,
                &mut refblock_byte_offset_for_cluster,
            )
        }
    }
}

/// Inline walk used by [`update_snapshot_refcount`]'s dry-run
/// pass: same shape as [`for_each_cluster_in_l1`] but with the
/// refcount-check logic baked in. Lives as a free function (not
/// a closure) so the borrow checker can resolve the two
/// generic-closure captures cleanly.
fn dry_run_refcount_pass<'l2, L2F, RBF>(
    l1_bytes: &[u8],
    addend: i32,
    refblocks: &[u8],
    cluster_bits: u32,
    refcount_bits: u32,
    extended_l2: bool,
    l2_for_index: &mut L2F,
    refblock_byte_offset_for_cluster: &mut RBF,
) -> Result<(), SnapshotError>
where
    L2F: FnMut(u32) -> Option<&'l2 [u8]>,
    RBF: FnMut(u64) -> Option<(usize, u64)>,
{
    if cluster_bits == 0 {
        return Err(SnapshotError::InvalidConfig);
    }
    let l2_entry_stride = if extended_l2 { 16usize } else { 8usize };
    let bytes_per_refblock = 1usize << cluster_bits;

    let l1_entries = l1_bytes.len() / 8;
    for l1_idx in 0..l1_entries {
        let off = l1_idx * 8;
        let raw = u64::from_be_bytes([
            l1_bytes[off],
            l1_bytes[off + 1],
            l1_bytes[off + 2],
            l1_bytes[off + 3],
            l1_bytes[off + 4],
            l1_bytes[off + 5],
            l1_bytes[off + 6],
            l1_bytes[off + 7],
        ]);
        if (raw & L1_OFFSET_MASK) == 0 {
            continue;
        }
        let l2_bytes = match l2_for_index(l1_idx as u32) {
            Some(b) => b,
            None => return Err(SnapshotError::MisalignedAccess),
        };
        let l2_entries = l2_bytes.len() / l2_entry_stride;
        for l2_idx in 0..l2_entries {
            let eoff = l2_idx * l2_entry_stride;
            if eoff + 8 > l2_bytes.len() {
                break;
            }
            let l2_entry = u64::from_be_bytes([
                l2_bytes[eoff],
                l2_bytes[eoff + 1],
                l2_bytes[eoff + 2],
                l2_bytes[eoff + 3],
                l2_bytes[eoff + 4],
                l2_bytes[eoff + 5],
                l2_bytes[eoff + 6],
                l2_bytes[eoff + 7],
            ]);
            if (l2_entry & !OFLAG_COPIED) == 0 {
                continue;
            }
            let host_offset = if (l2_entry & OFLAG_COMPRESSED) != 0 {
                let raw_off = l2_entry & !(OFLAG_COMPRESSED | OFLAG_COPIED);
                let cluster_mask = !((1u64 << cluster_bits) - 1);
                raw_off & cluster_mask
            } else {
                let v = l2_entry & L2_OFFSET_MASK;
                if v == 0 {
                    continue;
                }
                v
            };

            let (rb_off, local_idx) = match refblock_byte_offset_for_cluster(host_offset) {
                Some(t) => t,
                None => return Err(SnapshotError::MisalignedAccess),
            };
            let end = rb_off
                .checked_add(bytes_per_refblock)
                .ok_or(SnapshotError::MisalignedAccess)?;
            if end > refblocks.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            let refblock = &refblocks[rb_off..end];
            let current = read_refcount_in_block(refblock, local_idx, refcount_bits)?;
            match check_refcount_after_addend(current, addend, refcount_bits) {
                Ok(_) => {}
                Err(SnapshotError::RefcountOverflow { .. }) => {
                    return Err(SnapshotError::RefcountOverflow {
                        at_host_offset: host_offset,
                    });
                }
                Err(e) => return Err(e),
            }
        }

        // The L2 table cluster itself. qemu's
        // `qcow2_update_snapshot_refcount` adjusts the L2 table
        // cluster's refcount once per non-zero L1 entry (it calls
        // `qcow2_update_cluster_refcount(l2_offset >> cluster_bits,
        // ...)` after the per-entry loop). Check it for overflow
        // here so the dry-run aborts before any mutation if the L2
        // table cluster is already at the refcount cap.
        let l2_table_offset = raw & L1_OFFSET_MASK;
        let (rb_off, local_idx) = match refblock_byte_offset_for_cluster(l2_table_offset) {
            Some(t) => t,
            None => return Err(SnapshotError::MisalignedAccess),
        };
        let end = rb_off
            .checked_add(bytes_per_refblock)
            .ok_or(SnapshotError::MisalignedAccess)?;
        if end > refblocks.len() {
            return Err(SnapshotError::MisalignedAccess);
        }
        let refblock = &refblocks[rb_off..end];
        let current = read_refcount_in_block(refblock, local_idx, refcount_bits)?;
        match check_refcount_after_addend(current, addend, refcount_bits) {
            Ok(_) => {}
            Err(SnapshotError::RefcountOverflow { .. }) => {
                return Err(SnapshotError::RefcountOverflow {
                    at_host_offset: l2_table_offset,
                });
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Inline walk used by [`update_snapshot_refcount`]'s apply
/// pass. Mutates `refblocks` in place; assumes the dry-run
/// pass already validated overflow.
fn apply_refcount_pass<'l2, L2F, RBF>(
    l1_bytes: &[u8],
    addend: i32,
    refblocks: &mut [u8],
    cluster_bits: u32,
    refcount_bits: u32,
    extended_l2: bool,
    l2_for_index: &mut L2F,
    refblock_byte_offset_for_cluster: &mut RBF,
) -> Result<(), SnapshotError>
where
    L2F: FnMut(u32) -> Option<&'l2 [u8]>,
    RBF: FnMut(u64) -> Option<(usize, u64)>,
{
    if cluster_bits == 0 {
        return Err(SnapshotError::InvalidConfig);
    }
    let l2_entry_stride = if extended_l2 { 16usize } else { 8usize };
    let bytes_per_refblock = 1usize << cluster_bits;

    let l1_entries = l1_bytes.len() / 8;
    for l1_idx in 0..l1_entries {
        let off = l1_idx * 8;
        let raw = u64::from_be_bytes([
            l1_bytes[off],
            l1_bytes[off + 1],
            l1_bytes[off + 2],
            l1_bytes[off + 3],
            l1_bytes[off + 4],
            l1_bytes[off + 5],
            l1_bytes[off + 6],
            l1_bytes[off + 7],
        ]);
        if (raw & L1_OFFSET_MASK) == 0 {
            continue;
        }
        let l2_bytes = match l2_for_index(l1_idx as u32) {
            Some(b) => b,
            None => return Err(SnapshotError::MisalignedAccess),
        };
        let l2_entries = l2_bytes.len() / l2_entry_stride;
        for l2_idx in 0..l2_entries {
            let eoff = l2_idx * l2_entry_stride;
            if eoff + 8 > l2_bytes.len() {
                break;
            }
            let l2_entry = u64::from_be_bytes([
                l2_bytes[eoff],
                l2_bytes[eoff + 1],
                l2_bytes[eoff + 2],
                l2_bytes[eoff + 3],
                l2_bytes[eoff + 4],
                l2_bytes[eoff + 5],
                l2_bytes[eoff + 6],
                l2_bytes[eoff + 7],
            ]);
            if (l2_entry & !OFLAG_COPIED) == 0 {
                continue;
            }
            let host_offset = if (l2_entry & OFLAG_COMPRESSED) != 0 {
                let raw_off = l2_entry & !(OFLAG_COMPRESSED | OFLAG_COPIED);
                let cluster_mask = !((1u64 << cluster_bits) - 1);
                raw_off & cluster_mask
            } else {
                let v = l2_entry & L2_OFFSET_MASK;
                if v == 0 {
                    continue;
                }
                v
            };

            let (rb_off, local_idx) = match refblock_byte_offset_for_cluster(host_offset) {
                Some(t) => t,
                None => return Err(SnapshotError::MisalignedAccess),
            };
            let end = rb_off
                .checked_add(bytes_per_refblock)
                .ok_or(SnapshotError::MisalignedAccess)?;
            if end > refblocks.len() {
                return Err(SnapshotError::MisalignedAccess);
            }
            let refblock = &mut refblocks[rb_off..end];
            let current = read_refcount_in_block(refblock, local_idx, refcount_bits)?;
            let new_val = check_refcount_after_addend(current, addend, refcount_bits)?;
            set_refcount_in_block(refblock, local_idx, refcount_bits, new_val)?;
        }

        // The L2 table cluster itself — bumped once per non-zero
        // L1 entry, matching qemu's `qcow2_update_snapshot_refcount`
        // (see the dry-run pass for the qemu cross-reference). The
        // dry-run already validated this cluster's overflow.
        let l2_table_offset = raw & L1_OFFSET_MASK;
        let (rb_off, local_idx) = match refblock_byte_offset_for_cluster(l2_table_offset) {
            Some(t) => t,
            None => return Err(SnapshotError::MisalignedAccess),
        };
        let end = rb_off
            .checked_add(bytes_per_refblock)
            .ok_or(SnapshotError::MisalignedAccess)?;
        if end > refblocks.len() {
            return Err(SnapshotError::MisalignedAccess);
        }
        let refblock = &mut refblocks[rb_off..end];
        let current = read_refcount_in_block(refblock, local_idx, refcount_bits)?;
        let new_val = check_refcount_after_addend(current, addend, refcount_bits)?;
        set_refcount_in_block(refblock, local_idx, refcount_bits, new_val)?;
    }
    Ok(())
}

/// Rewrite the [`OFLAG_COPIED`] flag on every L1 and L2 entry
/// reachable from `l1_bytes`, based on the current refcount of
/// the targeted cluster.
///
/// For each L1 entry the L1 cluster's own host offset is looked
/// up via `refcount_for_cluster`; if its refcount is 1 the
/// COPIED flag is set, else cleared. The L2 cluster bytes
/// (via `l2_for_index`) are then walked and each L2 entry's
/// COPIED flag rewritten similarly.
///
/// Entries that reference no cluster are **scrubbed**, not
/// skipped (phase 8b): qemu's `qcow2_update_snapshot_refcount`
/// strips `QCOW_OFLAG_COPIED` before classifying and assigns
/// `refcount = 0` to `QCOW2_CLUSTER_ZERO_PLAIN` (standard L2
/// only: zero bit set, offset 0 — with subclusters the zero
/// status lives in the bitmap and `qcow2_get_cluster_type`
/// skips the zero branch) and `QCOW2_CLUSTER_UNALLOCATED`
/// (offset 0), so a stale COPIED bit on such an entry is
/// actively cleared. Both classifications reduce to "offset
/// masks to 0 and not compressed", and both get the same
/// treatment: clear a set COPIED bit and count the rewrite.
/// The extended-L2 subcluster bitmap is untouched.
///
/// Returns the count of entries (L1 + L2 combined) actually
/// rewritten.
pub fn update_copied_flags_for_l1<'l2, L2MF, RCF>(
    l1_bytes: &mut [u8],
    cluster_bits: u32,
    mut l2_for_index: L2MF,
    mut refcount_for_cluster: RCF,
    extended_l2: bool,
) -> Result<u32, SnapshotError>
where
    L2MF: FnMut(u32) -> Option<&'l2 mut [u8]>,
    RCF: FnMut(u64) -> Option<u64>,
{
    if cluster_bits == 0 {
        return Err(SnapshotError::InvalidConfig);
    }
    let l2_entry_stride = if extended_l2 { 16usize } else { 8usize };
    let mut rewrites: u32 = 0;

    let l1_entries = l1_bytes.len() / 8;
    for l1_idx in 0..l1_entries {
        let off = l1_idx * 8;
        let raw = u64::from_be_bytes([
            l1_bytes[off],
            l1_bytes[off + 1],
            l1_bytes[off + 2],
            l1_bytes[off + 3],
            l1_bytes[off + 4],
            l1_bytes[off + 5],
            l1_bytes[off + 6],
            l1_bytes[off + 7],
        ]);
        let l2_table_offset = raw & L1_OFFSET_MASK;
        if l2_table_offset == 0 {
            continue;
        }

        // L1 entry: rewrite COPIED based on the L1 cluster's
        // own refcount.
        let l1_rc = match refcount_for_cluster(l2_table_offset) {
            Some(v) => v,
            None => return Err(SnapshotError::MisalignedAccess),
        };
        let want_l1_copied = l1_rc == 1;
        let has_l1_copied = (raw & OFLAG_COPIED) != 0;
        if want_l1_copied != has_l1_copied {
            rewrite_l1_entry_copied_flag(l1_bytes, l1_idx as u32, want_l1_copied)?;
            rewrites = rewrites.saturating_add(1);
        }

        // L2 entries: rewrite COPIED based on each data
        // cluster's refcount.
        let l2_bytes = match l2_for_index(l1_idx as u32) {
            Some(b) => b,
            None => return Err(SnapshotError::MisalignedAccess),
        };

        let l2_count = l2_bytes.len() / l2_entry_stride;
        for l2_idx in 0..l2_count {
            let eoff = l2_idx * l2_entry_stride;
            if eoff + 8 > l2_bytes.len() {
                break;
            }
            let l2_entry = u64::from_be_bytes([
                l2_bytes[eoff],
                l2_bytes[eoff + 1],
                l2_bytes[eoff + 2],
                l2_bytes[eoff + 3],
                l2_bytes[eoff + 4],
                l2_bytes[eoff + 5],
                l2_bytes[eoff + 6],
                l2_bytes[eoff + 7],
            ]);
            let host_offset = if (l2_entry & OFLAG_COMPRESSED) != 0 {
                let raw_off = l2_entry & !(OFLAG_COMPRESSED | OFLAG_COPIED);
                let cluster_mask = !((1u64 << cluster_bits) - 1);
                raw_off & cluster_mask
            } else {
                let v = l2_entry & L2_OFFSET_MASK;
                if v == 0 {
                    // UNALLOCATED or ZERO_PLAIN: qemu treats the
                    // refcount as 0, so COPIED can never be
                    // legitimately set — scrub a stale bit
                    // (phase 8b; see the doc comment).
                    if (l2_entry & OFLAG_COPIED) != 0 {
                        rewrite_l2_entry_copied_flag(l2_bytes, l2_idx as u32, false, extended_l2)?;
                        rewrites = rewrites.saturating_add(1);
                    }
                    continue;
                }
                v
            };
            let rc = match refcount_for_cluster(host_offset) {
                Some(v) => v,
                None => return Err(SnapshotError::MisalignedAccess),
            };
            let want = rc == 1;
            let has = (l2_entry & OFLAG_COPIED) != 0;
            if want != has {
                rewrite_l2_entry_copied_flag(l2_bytes, l2_idx as u32, want, extended_l2)?;
                rewrites = rewrites.saturating_add(1);
            }
        }
    }
    Ok(rewrites)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------- read_refcount_in_block --------------------

    #[test]
    fn read_refcount_16bit_basic() {
        let mut block = [0u8; 32];
        block[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        block[6..8].copy_from_slice(&0x1234u16.to_be_bytes());
        assert_eq!(read_refcount_in_block(&block, 0, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 3, 16).unwrap(), 0x1234);
    }

    #[test]
    fn read_refcount_8bit() {
        let block = [0x00u8, 0x05, 0xff, 0x2a];
        assert_eq!(read_refcount_in_block(&block, 0, 8).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&block, 1, 8).unwrap(), 5);
        assert_eq!(read_refcount_in_block(&block, 2, 8).unwrap(), 0xff);
        assert_eq!(read_refcount_in_block(&block, 3, 8).unwrap(), 0x2a);
    }

    #[test]
    fn read_refcount_32_64_bit() {
        let mut block = [0u8; 16];
        block[0..4].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        block[4..8].copy_from_slice(&0x9abc_def0u32.to_be_bytes());
        assert_eq!(read_refcount_in_block(&block, 0, 32).unwrap(), 0x1234_5678);
        assert_eq!(read_refcount_in_block(&block, 1, 32).unwrap(), 0x9abc_def0);

        let mut block2 = [0u8; 16];
        block2[0..8].copy_from_slice(&0xdead_beef_cafe_babeu64.to_be_bytes());
        assert_eq!(
            read_refcount_in_block(&block2, 0, 64).unwrap(),
            0xdead_beef_cafe_babe
        );
    }

    #[test]
    fn read_refcount_out_of_range_errors() {
        let block = [0u8; 4];
        assert_eq!(
            read_refcount_in_block(&block, 4, 8),
            Err(SnapshotError::MisalignedAccess)
        );
        assert_eq!(
            read_refcount_in_block(&block, 2, 16),
            Err(SnapshotError::MisalignedAccess)
        );
        assert_eq!(
            read_refcount_in_block(&block, 1, 32),
            Err(SnapshotError::MisalignedAccess)
        );
        assert_eq!(
            read_refcount_in_block(&block, 0, 64),
            Err(SnapshotError::MisalignedAccess)
        );
    }

    #[test]
    fn read_refcount_unsupported_widths() {
        let block = [0xffu8; 8];
        for bits in [0u32, 3, 5, 7, 128] {
            assert_eq!(
                read_refcount_in_block(&block, 0, bits),
                Err(SnapshotError::Unsupported)
            );
        }
    }

    // -------------------- set_refcount_in_block --------------------

    #[test]
    fn set_refcount_16bit_round_trip() {
        let mut block = [0u8; 32];
        set_refcount_in_block(&mut block, 0, 16, 1).unwrap();
        set_refcount_in_block(&mut block, 3, 16, 0x1234).unwrap();
        assert_eq!(read_refcount_in_block(&block, 0, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 3, 16).unwrap(), 0x1234);
        assert_eq!(&block[0..2], &[0x00, 0x01]);
        assert_eq!(&block[6..8], &[0x12, 0x34]);

        set_refcount_in_block(&mut block, 0, 16, 0).unwrap();
        assert_eq!(&block[0..2], &[0x00, 0x00]);
    }

    #[test]
    fn set_refcount_8bit_round_trip() {
        let mut block = [0u8; 8];
        for i in 0..8u64 {
            set_refcount_in_block(&mut block, i, 8, i + 1).unwrap();
        }
        for i in 0..8u64 {
            assert_eq!(read_refcount_in_block(&block, i, 8).unwrap(), i + 1);
        }
    }

    #[test]
    fn set_refcount_1bit_round_trip() {
        // Use the round-trip via read_refcount_in_block (the
        // pair is internally consistent).
        let mut block = [0u8; 4];
        for i in [0u64, 3, 7, 8, 15] {
            set_refcount_in_block(&mut block, i, 1, 1).unwrap();
        }
        for i in [0u64, 3, 7, 8, 15] {
            assert_eq!(read_refcount_in_block(&block, i, 1).unwrap(), 1);
        }
        for i in [1u64, 2, 4, 5, 6, 9, 10, 11, 12, 13, 14] {
            assert_eq!(read_refcount_in_block(&block, i, 1).unwrap(), 0);
        }
    }

    #[test]
    fn set_refcount_2bit_4bit_round_trip() {
        let mut block = [0u8; 8];
        for i in 0..16u64 {
            set_refcount_in_block(&mut block, i, 2, (i & 0b11) as u64).unwrap();
        }
        for i in 0..16u64 {
            assert_eq!(
                read_refcount_in_block(&block, i, 2).unwrap(),
                (i & 0b11) as u64
            );
        }

        let mut block2 = [0u8; 4];
        for i in 0..8u64 {
            set_refcount_in_block(&mut block2, i, 4, (i & 0b1111) as u64).unwrap();
        }
        for i in 0..8u64 {
            assert_eq!(
                read_refcount_in_block(&block2, i, 4).unwrap(),
                (i & 0b1111) as u64
            );
        }
    }

    #[test]
    fn sub_byte_widths_are_lsb_first_like_qemu() {
        // Round-trip tests pass under EITHER bit order (set and
        // read mirror each other), which is how an MSB-first bug
        // survived until the PLAN-snapshot pre-push audit. This
        // test pins the on-disk layout byte-exactly against
        // qemu's get/set_refcount_ro0/ro1/ro2
        // (block/qcow2-refcount.c): entry 0 occupies the LOWEST
        // bits of byte 0.
        //
        // Width 1: qemu reads `(byte >> (index % 8)) & 1`.
        let block = [0b0000_0010u8];
        assert_eq!(read_refcount_in_block(&block, 0, 1).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&block, 1, 1).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 7, 1).unwrap(), 0);

        // Width 2: qemu reads `(byte >> (2 * (index % 4))) & 3`.
        // 0x39 = 0b00_11_10_01 -> indices 0..3 read 1, 2, 3, 0.
        let block = [0x39u8];
        for (idx, want) in [(0u64, 1u64), (1, 2), (2, 3), (3, 0)] {
            assert_eq!(read_refcount_in_block(&block, idx, 2).unwrap(), want);
        }

        // Width 4: qemu reads `(byte >> (4 * (index % 2))) & 0xf`.
        // 0x21 -> index 0 (low nibble) reads 1, index 1 reads 2.
        let block = [0x21u8];
        assert_eq!(read_refcount_in_block(&block, 0, 4).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&block, 1, 4).unwrap(), 2);

        // Set side: writing entry 0 must land in the LOW bits.
        let mut block = [0u8];
        set_refcount_in_block(&mut block, 0, 4, 0xf).unwrap();
        assert_eq!(block[0], 0x0f);
        let mut block = [0u8];
        set_refcount_in_block(&mut block, 0, 2, 0b11).unwrap();
        assert_eq!(block[0], 0b0000_0011);
        let mut block = [0u8];
        set_refcount_in_block(&mut block, 0, 1, 1).unwrap();
        assert_eq!(block[0], 0b0000_0001);
    }

    #[test]
    fn set_refcount_32_64_bit_round_trip() {
        let mut block = [0u8; 16];
        set_refcount_in_block(&mut block, 0, 32, 0x1234_5678).unwrap();
        set_refcount_in_block(&mut block, 1, 32, 0x9abc_def0).unwrap();
        assert_eq!(read_refcount_in_block(&block, 0, 32).unwrap(), 0x1234_5678);
        assert_eq!(read_refcount_in_block(&block, 1, 32).unwrap(), 0x9abc_def0);

        let mut block2 = [0u8; 16];
        set_refcount_in_block(&mut block2, 0, 64, 0xdead_beef_cafe_babe).unwrap();
        assert_eq!(
            read_refcount_in_block(&block2, 0, 64).unwrap(),
            0xdead_beef_cafe_babe
        );
    }

    #[test]
    fn set_refcount_out_of_range_errors() {
        let mut block = [0u8; 4];
        assert_eq!(
            set_refcount_in_block(&mut block, 4, 8, 1),
            Err(SnapshotError::MisalignedAccess)
        );
        assert_eq!(
            set_refcount_in_block(&mut block, 2, 16, 1),
            Err(SnapshotError::MisalignedAccess)
        );
        assert_eq!(
            set_refcount_in_block(&mut block, 1, 32, 1),
            Err(SnapshotError::MisalignedAccess)
        );
        assert_eq!(
            set_refcount_in_block(&mut block, 0, 64, 1),
            Err(SnapshotError::MisalignedAccess)
        );
    }

    #[test]
    fn set_refcount_unsupported_widths() {
        let mut block = [0u8; 8];
        for bits in [0u32, 3, 5, 7, 128] {
            assert_eq!(
                set_refcount_in_block(&mut block, 0, bits, 1),
                Err(SnapshotError::Unsupported)
            );
        }
    }

    // -------------------- check_refcount_after_addend --------------------

    #[test]
    fn check_addend_basic() {
        assert_eq!(check_refcount_after_addend(0, 0, 16).unwrap(), 0);
        assert_eq!(check_refcount_after_addend(1, 0, 16).unwrap(), 1);
        assert_eq!(check_refcount_after_addend(0, 1, 16).unwrap(), 1);
        assert_eq!(check_refcount_after_addend(1, 1, 16).unwrap(), 2);
        assert_eq!(check_refcount_after_addend(1, -1, 16).unwrap(), 0);
    }

    #[test]
    fn check_addend_max_value_no_inc() {
        let max_16 = 0xffffu64;
        assert_eq!(check_refcount_after_addend(max_16, 0, 16).unwrap(), max_16);
        assert!(matches!(
            check_refcount_after_addend(max_16, 1, 16),
            Err(SnapshotError::RefcountOverflow { .. })
        ));
        let max_8 = 0xffu64;
        assert!(matches!(
            check_refcount_after_addend(max_8, 1, 8),
            Err(SnapshotError::RefcountOverflow { .. })
        ));
    }

    #[test]
    fn check_addend_underflow_errors() {
        assert_eq!(
            check_refcount_after_addend(0, -1, 16),
            Err(SnapshotError::ParseFailed)
        );
        assert_eq!(
            check_refcount_after_addend(5, -10, 16),
            Err(SnapshotError::ParseFailed)
        );
    }

    #[test]
    fn check_addend_64bit_uses_u64_max() {
        // For 64-bit width, max == u64::MAX.
        assert_eq!(
            check_refcount_after_addend(u64::MAX, 0, 64).unwrap(),
            u64::MAX
        );
        assert!(matches!(
            check_refcount_after_addend(u64::MAX, 1, 64),
            Err(SnapshotError::RefcountOverflow { .. })
        ));
    }

    #[test]
    fn check_addend_rejects_zero_width() {
        assert_eq!(
            check_refcount_after_addend(0, 0, 0),
            Err(SnapshotError::Unsupported)
        );
    }

    // -------------------- alloc_cluster_in_refblocks --------------------

    #[test]
    fn alloc_first_zero_entry() {
        // Single refblock, 16-bit refcounts, cluster_size = 512.
        let mut blocks = [0u8; 512];
        let mut cursor = AllocCursor::default();
        let off = alloc_cluster_in_refblocks(&mut blocks, 512, 16, 1, 0, &mut cursor).unwrap();
        assert_eq!(off, 0);
        // First entry is now 1.
        assert_eq!(&blocks[0..2], &[0x00, 0x01]);
        assert_eq!(cursor.allocated, 1);
        assert_eq!(cursor.next_entry_in_refblock, 1);
        assert_eq!(cursor.next_refblock, 0);
    }

    #[test]
    fn alloc_successive_entries() {
        let mut blocks = [0u8; 512];
        let mut cursor = AllocCursor::default();
        let o0 = alloc_cluster_in_refblocks(&mut blocks, 512, 16, 1, 0, &mut cursor).unwrap();
        let o1 = alloc_cluster_in_refblocks(&mut blocks, 512, 16, 1, 0, &mut cursor).unwrap();
        let o2 = alloc_cluster_in_refblocks(&mut blocks, 512, 16, 1, 0, &mut cursor).unwrap();
        assert_eq!(o0, 0);
        assert_eq!(o1, 512);
        assert_eq!(o2, 1024);
        assert_eq!(cursor.allocated, 3);
        assert_eq!(cursor.next_entry_in_refblock, 3);
    }

    #[test]
    fn alloc_skips_non_zero_entry() {
        let mut blocks = [0u8; 512];
        // Mark entries 0..2 as already used.
        blocks[0..2].copy_from_slice(&1u16.to_be_bytes());
        blocks[2..4].copy_from_slice(&1u16.to_be_bytes());
        let mut cursor = AllocCursor::default();
        let off = alloc_cluster_in_refblocks(&mut blocks, 512, 16, 1, 0, &mut cursor).unwrap();
        // Should land on entry 2 (host offset = 2 * 512).
        assert_eq!(off, 1024);
        assert_eq!(cursor.next_entry_in_refblock, 3);
    }

    #[test]
    fn alloc_full_block_returns_exhausted() {
        let mut blocks = [0xffu8; 512];
        let mut cursor = AllocCursor::default();
        assert_eq!(
            alloc_cluster_in_refblocks(&mut blocks, 512, 16, 1, 0, &mut cursor),
            Err(SnapshotError::RefcountExhausted)
        );
    }

    #[test]
    fn alloc_with_cursor_past_end() {
        let mut blocks = [0u8; 512];
        let mut cursor = AllocCursor {
            next_refblock: 1,
            next_entry_in_refblock: 0,
            allocated: 0,
        };
        assert_eq!(
            alloc_cluster_in_refblocks(&mut blocks, 512, 16, 1, 0, &mut cursor),
            Err(SnapshotError::RefcountExhausted)
        );
    }

    #[test]
    fn alloc_unsupported_width() {
        let mut blocks = [0u8; 512];
        let mut cursor = AllocCursor::default();
        assert_eq!(
            alloc_cluster_in_refblocks(&mut blocks, 512, 8, 1, 0, &mut cursor),
            Err(SnapshotError::Unsupported)
        );
    }

    #[test]
    fn alloc_host_refblocks_start_offsets_result() {
        let mut blocks = [0u8; 512];
        let mut cursor = AllocCursor::default();
        let off =
            alloc_cluster_in_refblocks(&mut blocks, 512, 16, 1, 0x1_0000, &mut cursor).unwrap();
        assert_eq!(off, 0x1_0000);
        let off2 =
            alloc_cluster_in_refblocks(&mut blocks, 512, 16, 1, 0x1_0000, &mut cursor).unwrap();
        assert_eq!(off2, 0x1_0000 + 512);
    }

    #[test]
    fn alloc_crosses_refblock_boundary() {
        // Two 512-byte refblocks. First fully used, second empty.
        let mut blocks = [0u8; 1024];
        for i in 0..512 {
            blocks[i] = 0xff;
        }
        let mut cursor = AllocCursor::default();
        let off = alloc_cluster_in_refblocks(&mut blocks, 512, 16, 2, 0, &mut cursor).unwrap();
        // entries_per_refblock = 512 * 8 / 16 = 256; first
        // alloc in second block lands at cluster index 256.
        assert_eq!(off, 256 * 512);
        assert_eq!(cursor.next_refblock, 1);
    }

    #[test]
    fn alloc_zero_cluster_size_rejected() {
        let mut blocks = [0u8; 16];
        let mut cursor = AllocCursor::default();
        assert_eq!(
            alloc_cluster_in_refblocks(&mut blocks, 0, 16, 1, 0, &mut cursor),
            Err(SnapshotError::InvalidConfig)
        );
    }

    // ---------------- alloc_contiguous_clusters_in_refblocks ----------------

    #[test]
    fn alloc_contiguous_happy_path() {
        // One refblock, all free; ask for 3 consecutive clusters.
        let mut blocks = [0u8; 512];
        let mut cursor = AllocCursor::default();
        let off =
            alloc_contiguous_clusters_in_refblocks(&mut blocks, 512, 16, 1, 0, 3, &mut cursor)
                .unwrap();
        assert_eq!(off, 0);
        // Entries 0, 1, 2 all set to 1.
        assert_eq!(read_refcount_in_block(&blocks, 0, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&blocks, 1, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&blocks, 2, 16).unwrap(), 1);
        // Entry 3 still free.
        assert_eq!(read_refcount_in_block(&blocks, 3, 16).unwrap(), 0);
        assert_eq!(cursor.allocated, 3);
        assert_eq!(cursor.next_entry_in_refblock, 3);
    }

    #[test]
    fn alloc_contiguous_spans_refblock_boundary() {
        // Two 512-byte refblocks. entries_per_refblock = 256.
        // Occupy the last entry of refblock 0 (entry 255) so a
        // 3-cluster run can't fit ending in block 0; the run lands
        // at the start of block 1.
        let mut blocks = [0u8; 1024];
        // Fill block 0 entirely so first-fit must move to block 1.
        for b in blocks.iter_mut().take(512) {
            *b = 0xff;
        }
        let mut cursor = AllocCursor::default();
        let off =
            alloc_contiguous_clusters_in_refblocks(&mut blocks, 512, 16, 2, 0, 3, &mut cursor)
                .unwrap();
        // First free run starts at cluster index 256 (block 1).
        assert_eq!(off, 256 * 512);
        assert_eq!(read_refcount_in_block(&blocks[512..], 0, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&blocks[512..], 1, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&blocks[512..], 2, 16).unwrap(), 1);
    }

    #[test]
    fn alloc_contiguous_run_crosses_boundary_between_blocks() {
        // entries_per_refblock = 256. Occupy entries 0..254 of
        // block 0 (leaving entry 255 free) so a 3-run must span the
        // block 0 / block 1 boundary: clusters 255, 256, 257.
        let mut blocks = [0u8; 1024];
        for i in 0..255u64 {
            set_refcount_in_block(&mut blocks[..512], i, 16, 1).unwrap();
        }
        let mut cursor = AllocCursor::default();
        let off =
            alloc_contiguous_clusters_in_refblocks(&mut blocks, 512, 16, 2, 0, 3, &mut cursor)
                .unwrap();
        assert_eq!(off, 255 * 512);
        // Cluster 255 (block 0, entry 255) and 256/257 (block 1).
        assert_eq!(read_refcount_in_block(&blocks[..512], 255, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&blocks[512..], 0, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&blocks[512..], 1, 16).unwrap(), 1);
    }

    #[test]
    fn alloc_contiguous_skips_hole_smaller_than_count() {
        // Free run of 2 at entries 0..2, then entry 2 occupied,
        // then a run of >=3 from entry 3. Asking for 3 must skip
        // the 2-cluster hole and land at entry 3.
        let mut blocks = [0u8; 512];
        set_refcount_in_block(&mut blocks, 2, 16, 1).unwrap();
        let mut cursor = AllocCursor::default();
        let off =
            alloc_contiguous_clusters_in_refblocks(&mut blocks, 512, 16, 1, 0, 3, &mut cursor)
                .unwrap();
        assert_eq!(off, 3 * 512);
        assert_eq!(read_refcount_in_block(&blocks, 3, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&blocks, 4, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&blocks, 5, 16).unwrap(), 1);
        // Entry 0/1 (the too-small hole) left untouched.
        assert_eq!(read_refcount_in_block(&blocks, 0, 16).unwrap(), 0);
        assert_eq!(read_refcount_in_block(&blocks, 1, 16).unwrap(), 0);
    }

    #[test]
    fn alloc_contiguous_exhausted() {
        // Only 2 free entries at the end; asking for 3 fails.
        let mut blocks = [0u8; 512]; // 256 entries
        for i in 0..254u64 {
            set_refcount_in_block(&mut blocks, i, 16, 1).unwrap();
        }
        let mut cursor = AllocCursor::default();
        assert_eq!(
            alloc_contiguous_clusters_in_refblocks(&mut blocks, 512, 16, 1, 0, 3, &mut cursor),
            Err(SnapshotError::RefcountExhausted)
        );
    }

    #[test]
    fn alloc_contiguous_cursor_reuse_across_calls() {
        let mut blocks = [0u8; 512];
        let mut cursor = AllocCursor::default();
        let o0 = alloc_contiguous_clusters_in_refblocks(&mut blocks, 512, 16, 1, 0, 2, &mut cursor)
            .unwrap();
        let o1 = alloc_contiguous_clusters_in_refblocks(&mut blocks, 512, 16, 1, 0, 2, &mut cursor)
            .unwrap();
        assert_eq!(o0, 0);
        assert_eq!(o1, 2 * 512);
        assert_eq!(cursor.allocated, 4);
        assert_eq!(cursor.next_entry_in_refblock, 4);
    }

    #[test]
    fn alloc_contiguous_count_zero_rejected() {
        let mut blocks = [0u8; 512];
        let mut cursor = AllocCursor::default();
        assert_eq!(
            alloc_contiguous_clusters_in_refblocks(&mut blocks, 512, 16, 1, 0, 0, &mut cursor),
            Err(SnapshotError::InvalidConfig)
        );
    }

    #[test]
    fn alloc_single_wrapper_matches_contiguous_count_one() {
        // The thin wrapper must behave exactly like count == 1.
        let mut a = [0u8; 512];
        let mut b = [0u8; 512];
        let mut ca = AllocCursor::default();
        let mut cb = AllocCursor::default();
        let oa = alloc_cluster_in_refblocks(&mut a, 512, 16, 1, 0, &mut ca).unwrap();
        let ob = alloc_contiguous_clusters_in_refblocks(&mut b, 512, 16, 1, 0, 1, &mut cb).unwrap();
        assert_eq!(oa, ob);
        assert_eq!(a, b);
        assert_eq!(ca, cb);
    }

    // -------------------- rewrite_l1_entry_copied_flag --------------------

    fn make_l1_entry(offset: u64, copied: bool) -> [u8; 8] {
        let mut v = offset & L1_OFFSET_MASK;
        if copied {
            v |= OFLAG_COPIED;
        }
        v.to_be_bytes()
    }

    #[test]
    fn l1_rewrite_sets_copied() {
        let mut l1 = [0u8; 16];
        l1[0..8].copy_from_slice(&make_l1_entry(0x10_0000, false));
        rewrite_l1_entry_copied_flag(&mut l1, 0, true).unwrap();
        let v = u64::from_be_bytes([l1[0], l1[1], l1[2], l1[3], l1[4], l1[5], l1[6], l1[7]]);
        assert_eq!(v & OFLAG_COPIED, OFLAG_COPIED);
        assert_eq!(v & L1_OFFSET_MASK, 0x10_0000);
    }

    #[test]
    fn l1_rewrite_clears_copied() {
        let mut l1 = [0u8; 16];
        l1[0..8].copy_from_slice(&make_l1_entry(0x20_0000, true));
        rewrite_l1_entry_copied_flag(&mut l1, 0, false).unwrap();
        let v = u64::from_be_bytes([l1[0], l1[1], l1[2], l1[3], l1[4], l1[5], l1[6], l1[7]]);
        assert_eq!(v & OFLAG_COPIED, 0);
        assert_eq!(v & L1_OFFSET_MASK, 0x20_0000);
    }

    #[test]
    fn l1_rewrite_idempotent() {
        let mut l1 = [0u8; 8];
        l1.copy_from_slice(&make_l1_entry(0x4000, false));
        rewrite_l1_entry_copied_flag(&mut l1, 0, true).unwrap();
        let snap1 = l1;
        rewrite_l1_entry_copied_flag(&mut l1, 0, true).unwrap();
        assert_eq!(l1, snap1);
        rewrite_l1_entry_copied_flag(&mut l1, 0, false).unwrap();
        let snap2 = l1;
        rewrite_l1_entry_copied_flag(&mut l1, 0, false).unwrap();
        assert_eq!(l1, snap2);
    }

    #[test]
    fn l1_rewrite_out_of_range_errors() {
        let mut l1 = [0u8; 8];
        assert_eq!(
            rewrite_l1_entry_copied_flag(&mut l1, 1, true),
            Err(SnapshotError::MisalignedAccess)
        );
    }

    // -------------------- rewrite_l2_entry_copied_flag --------------------

    #[test]
    fn l2_standard_rewrite_sets_clears() {
        let mut l2 = [0u8; 16];
        l2[0..8].copy_from_slice(&0x0010_0000u64.to_be_bytes());
        rewrite_l2_entry_copied_flag(&mut l2, 0, true, false).unwrap();
        let v = u64::from_be_bytes([l2[0], l2[1], l2[2], l2[3], l2[4], l2[5], l2[6], l2[7]]);
        assert_eq!(v & OFLAG_COPIED, OFLAG_COPIED);
        assert_eq!(v & L2_OFFSET_MASK, 0x10_0000);

        rewrite_l2_entry_copied_flag(&mut l2, 0, false, false).unwrap();
        let v2 = u64::from_be_bytes([l2[0], l2[1], l2[2], l2[3], l2[4], l2[5], l2[6], l2[7]]);
        assert_eq!(v2 & OFLAG_COPIED, 0);
    }

    #[test]
    fn l2_standard_rewrite_uses_8byte_stride() {
        let mut l2 = [0u8; 16];
        l2[0..8].copy_from_slice(&0x0010_0000u64.to_be_bytes());
        l2[8..16].copy_from_slice(&0x0020_0000u64.to_be_bytes());
        rewrite_l2_entry_copied_flag(&mut l2, 1, true, false).unwrap();
        // entry 1 at byte 8.
        let v0 = u64::from_be_bytes([l2[0], l2[1], l2[2], l2[3], l2[4], l2[5], l2[6], l2[7]]);
        let v1 = u64::from_be_bytes([l2[8], l2[9], l2[10], l2[11], l2[12], l2[13], l2[14], l2[15]]);
        assert_eq!(v0 & OFLAG_COPIED, 0);
        assert_eq!(v1 & OFLAG_COPIED, OFLAG_COPIED);
    }

    #[test]
    fn l2_extended_rewrite_uses_16byte_stride() {
        let mut l2 = [0u8; 48];
        // Three extended entries at offsets 0, 16, 32.
        l2[0..8].copy_from_slice(&0x0030_0000u64.to_be_bytes());
        l2[8..16].copy_from_slice(&0xdead_beef_cafe_babeu64.to_be_bytes());
        l2[16..24].copy_from_slice(&0x0040_0000u64.to_be_bytes());
        l2[24..32].copy_from_slice(&0xfeed_face_0123_4567u64.to_be_bytes());

        rewrite_l2_entry_copied_flag(&mut l2, 1, true, true).unwrap();
        // entry 1 = bytes 16..24 (offset half), subcluster
        // bitmap bytes 24..32 must be untouched.
        let v0 = u64::from_be_bytes([l2[0], l2[1], l2[2], l2[3], l2[4], l2[5], l2[6], l2[7]]);
        let sc0 =
            u64::from_be_bytes([l2[8], l2[9], l2[10], l2[11], l2[12], l2[13], l2[14], l2[15]]);
        let v1 = u64::from_be_bytes([
            l2[16], l2[17], l2[18], l2[19], l2[20], l2[21], l2[22], l2[23],
        ]);
        let sc1 = u64::from_be_bytes([
            l2[24], l2[25], l2[26], l2[27], l2[28], l2[29], l2[30], l2[31],
        ]);
        assert_eq!(v0 & OFLAG_COPIED, 0);
        assert_eq!(sc0, 0xdead_beef_cafe_babe);
        assert_eq!(v1 & OFLAG_COPIED, OFLAG_COPIED);
        // Critical: subcluster bitmap bit-for-bit untouched.
        assert_eq!(sc1, 0xfeed_face_0123_4567);
    }

    #[test]
    fn l2_extended_rewrite_entry_0_untouched_by_entry_1() {
        // Specifically guard against the dominant
        // 8-vs-16-byte stride bug.
        let mut l2 = [0u8; 48];
        l2[0..8].copy_from_slice(&0x0030_0000u64.to_be_bytes());
        let orig_first = l2;
        rewrite_l2_entry_copied_flag(&mut l2, 1, true, true).unwrap();
        // First 16 bytes (entry 0 offset half + subcluster
        // bitmap) must be exactly as they were.
        assert_eq!(&l2[0..16], &orig_first[0..16]);
    }

    #[test]
    fn l2_extended_rewrite_preserves_subcluster_bitmap_when_clearing() {
        let mut l2 = [0u8; 32];
        l2[0..8].copy_from_slice(&((0x0050_0000u64) | OFLAG_COPIED).to_be_bytes());
        l2[8..16].copy_from_slice(&0xa5a5_a5a5_a5a5_a5a5u64.to_be_bytes());
        rewrite_l2_entry_copied_flag(&mut l2, 0, false, true).unwrap();
        let sc = u64::from_be_bytes([l2[8], l2[9], l2[10], l2[11], l2[12], l2[13], l2[14], l2[15]]);
        assert_eq!(sc, 0xa5a5_a5a5_a5a5_a5a5);
    }

    #[test]
    fn l2_rewrite_out_of_range_errors() {
        let mut l2 = [0u8; 8];
        assert_eq!(
            rewrite_l2_entry_copied_flag(&mut l2, 1, true, false),
            Err(SnapshotError::MisalignedAccess)
        );
        let mut l2_ext = [0u8; 8];
        assert_eq!(
            rewrite_l2_entry_copied_flag(&mut l2_ext, 0, true, true),
            Err(SnapshotError::MisalignedAccess)
        );
    }

    // -------------------- for_each_cluster_in_l1 --------------------

    /// Build a 1-entry L1 pointing at an L2 cluster at `0x4000`.
    /// `l2_bytes` is the L2 table the visitor will hand back via
    /// `l2_for_index`.
    fn l1_pointing_to(host_l2_offset: u64, copied: bool) -> [u8; 8] {
        let mut v = host_l2_offset & L1_OFFSET_MASK;
        if copied {
            v |= OFLAG_COPIED;
        }
        v.to_be_bytes()
    }

    // For test fixtures we need static L2 byte buffers because
    // the for_each_cluster_in_l1 closure signature takes
    // `Option<&'static [u8]>`. We use a couple of `static`s and
    // hand them out per the l1_idx requested.
    static L2_FIXTURE_STANDARD: [u8; 32] = {
        let mut b = [0u8; 32];
        // Two entries: entry 0 = standard at 0x10_0000,
        // entry 1 = standard at 0x20_0000.
        let e0 = (0x10_0000u64 | OFLAG_COPIED).to_be_bytes();
        let e1 = 0x20_0000u64.to_be_bytes();
        let mut i = 0;
        while i < 8 {
            b[i] = e0[i];
            b[8 + i] = e1[i];
            i += 1;
        }
        b
    };

    static L2_FIXTURE_WITH_UNALLOC: [u8; 32] = {
        let mut b = [0u8; 32];
        // Entry 0 = 0 (unalloc), entry 1 = standard.
        let e1 = 0x30_0000u64.to_be_bytes();
        let mut i = 0;
        while i < 8 {
            b[8 + i] = e1[i];
            i += 1;
        }
        b
    };

    #[test]
    fn visitor_walks_two_entries() {
        let l1 = l1_pointing_to(0x4000, true);
        let mut seen: [Option<L1ClusterRef>; 4] = [None; 4];
        let mut count = 0usize;
        for_each_cluster_in_l1(
            &l1,
            16,
            |_idx| Some(&L2_FIXTURE_STANDARD[..]),
            false,
            |cref| {
                seen[count] = Some(cref);
                count += 1;
                true
            },
        )
        .unwrap();
        assert_eq!(count, 2);
        let c0 = seen[0].unwrap();
        let c1 = seen[1].unwrap();
        assert_eq!(c0.l1_idx, 0);
        assert_eq!(c0.l2_idx, 0);
        assert_eq!(c0.host_offset, 0x10_0000);
        assert_eq!(c0.classification, L2Classification::Standard);
        assert_eq!(c1.l1_idx, 0);
        assert_eq!(c1.l2_idx, 1);
        assert_eq!(c1.host_offset, 0x20_0000);
    }

    #[test]
    fn visitor_skips_unalloc_l1() {
        // L1 entry zero -> visitor never invoked.
        let l1 = [0u8; 8];
        let mut count = 0usize;
        for_each_cluster_in_l1(
            &l1,
            16,
            |_idx| Some(&L2_FIXTURE_STANDARD[..]),
            false,
            |_cref| {
                count += 1;
                true
            },
        )
        .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn visitor_skips_unalloc_l2() {
        let l1 = l1_pointing_to(0x4000, true);
        let mut count = 0usize;
        let mut last_offset = 0u64;
        for_each_cluster_in_l1(
            &l1,
            16,
            |_idx| Some(&L2_FIXTURE_WITH_UNALLOC[..]),
            false,
            |cref| {
                count += 1;
                last_offset = cref.host_offset;
                true
            },
        )
        .unwrap();
        // Only the second entry (0x30_0000) was allocated.
        assert_eq!(count, 1);
        assert_eq!(last_offset, 0x30_0000);
    }

    #[test]
    fn visitor_missing_l2_errors() {
        let l1 = l1_pointing_to(0x4000, true);
        let err = for_each_cluster_in_l1(&l1, 16, |_idx| None, false, |_cref| true);
        assert_eq!(err, Err(SnapshotError::MisalignedAccess));
    }

    #[test]
    fn visitor_early_stop() {
        let l1 = l1_pointing_to(0x4000, true);
        let mut count = 0usize;
        for_each_cluster_in_l1(
            &l1,
            16,
            |_idx| Some(&L2_FIXTURE_STANDARD[..]),
            false,
            |_cref| {
                count += 1;
                false
            },
        )
        .unwrap();
        // Visitor returned false on the first call -> only one
        // invocation.
        assert_eq!(count, 1);
    }

    static L2_FIXTURE_EXTENDED: [u8; 64] = {
        let mut b = [0u8; 64];
        // Two extended entries: entry 0 at bytes 0..16,
        // entry 1 at bytes 16..32; cleared at 32..64.
        let e0 = 0x10_0000u64.to_be_bytes();
        let sc0 = 0xa5a5_0000_0000_0000u64.to_be_bytes();
        let e1 = 0x20_0000u64.to_be_bytes();
        let mut i = 0;
        while i < 8 {
            b[i] = e0[i];
            b[8 + i] = sc0[i];
            b[16 + i] = e1[i];
            i += 1;
        }
        b
    };

    #[test]
    fn visitor_extended_l2_uses_16byte_stride() {
        let l1 = l1_pointing_to(0x4000, true);
        let mut offsets: [u64; 8] = [0; 8];
        let mut count = 0usize;
        for_each_cluster_in_l1(
            &l1,
            16,
            |_idx| Some(&L2_FIXTURE_EXTENDED[..]),
            true,
            |cref| {
                if count < offsets.len() {
                    offsets[count] = cref.host_offset;
                }
                count += 1;
                true
            },
        )
        .unwrap();
        // 64-byte L2 / 16-byte stride = 4 entries; two allocated
        // (entry 0 and entry 1), the rest unalloc -> skip.
        assert_eq!(count, 2);
        assert_eq!(offsets[0], 0x10_0000);
        assert_eq!(offsets[1], 0x20_0000);
    }

    static L2_FIXTURE_COMPRESSED: [u8; 32] = {
        let mut b = [0u8; 32];
        // Entry 0 = compressed with payload offset 0x10_0000
        // (cluster-aligned in the test fixture). Entry 1 unalloc.
        let e0 = (OFLAG_COMPRESSED | 0x10_0000u64).to_be_bytes();
        let mut i = 0;
        while i < 8 {
            b[i] = e0[i];
            i += 1;
        }
        b
    };

    #[test]
    fn visitor_classifies_compressed() {
        let l1 = l1_pointing_to(0x4000, true);
        let mut count = 0usize;
        let mut cls = L2Classification::Standard;
        let mut offset = 0u64;
        for_each_cluster_in_l1(
            &l1,
            16,
            |_idx| Some(&L2_FIXTURE_COMPRESSED[..]),
            false,
            |cref| {
                cls = cref.classification;
                offset = cref.host_offset;
                count += 1;
                true
            },
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(cls, L2Classification::Compressed);
        assert_eq!(offset, 0x10_0000);
    }

    // -------------------- update_snapshot_refcount --------------------

    // Static L2 backing the snapshot-refcount tests: 4 entries,
    // all allocated as standard clusters at increasing offsets
    // 0x10_0000, 0x10_1000, 0x10_2000, 0x10_3000. Cluster_bits
    // = 12 (4 KiB clusters) for tests.
    static REFC_L2: [u8; 32] = {
        let mut b = [0u8; 32];
        let mut i = 0;
        while i < 4 {
            let e = (0x10_0000u64 + (i as u64) * 0x1000).to_be_bytes();
            let mut j = 0;
            while j < 8 {
                b[i * 8 + j] = e[j];
                j += 1;
            }
            i += 1;
        }
        b
    };

    /// Build an L1 with one entry pointing at a fake L2 host
    /// offset. The visitor closure picks REFC_L2.
    fn refc_l1() -> [u8; 8] {
        l1_pointing_to(0x4000, true)
    }

    /// 4 KiB cluster_bits = 12, so bytes_per_refblock = 4096.
    /// refcount_bits = 16, so entries_per_refblock = 4096*8/16
    /// = 2048. We map cluster host_offset / 0x1000 ->
    /// (refblock_byte_off=0, entry_idx = (offset / 0x1000)).
    fn refblock_lookup(host_offset: u64) -> Option<(usize, u64)> {
        let entry_idx = host_offset / 0x1000;
        Some((0, entry_idx))
    }

    #[test]
    fn refcount_increment_basic() {
        let mut refblocks = [0u8; 4096];
        // Set initial refcounts of the four target clusters to
        // 1, 1, 2, 1.
        set_refcount_in_block(&mut refblocks, 0x100, 16, 1).unwrap(); // entry idx 256
        set_refcount_in_block(&mut refblocks, 0x101, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x102, 16, 2).unwrap();
        set_refcount_in_block(&mut refblocks, 0x103, 16, 1).unwrap();
        // The L2 table cluster lives at host offset 0x4000 (entry
        // idx 0x4 under refblock_lookup); seed it at 1 so the
        // create bump takes it to 2.
        set_refcount_in_block(&mut refblocks, 0x4, 16, 1).unwrap();

        let l1 = refc_l1();
        update_snapshot_refcount(
            SnapshotRefcountOp::IncrementForCreate { snapshot_l1: &l1 },
            &mut refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        )
        .unwrap();

        assert_eq!(read_refcount_in_block(&refblocks, 0x100, 16).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&refblocks, 0x101, 16).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&refblocks, 0x102, 16).unwrap(), 3);
        assert_eq!(read_refcount_in_block(&refblocks, 0x103, 16).unwrap(), 2);
        // The L2 table cluster is now counted by the create: its
        // refcount went 1 -> 2 (active L1 + snapshot L1 copy share
        // this physical L2 table). qemu's
        // qcow2_update_snapshot_refcount bumps it once per L1 entry.
        assert_eq!(read_refcount_in_block(&refblocks, 0x4, 16).unwrap(), 2);
    }

    #[test]
    fn refcount_decrement_basic() {
        let mut refblocks = [0u8; 4096];
        // Initial refcounts 2, 2, 3, 2.
        set_refcount_in_block(&mut refblocks, 0x100, 16, 2).unwrap();
        set_refcount_in_block(&mut refblocks, 0x101, 16, 2).unwrap();
        set_refcount_in_block(&mut refblocks, 0x102, 16, 3).unwrap();
        set_refcount_in_block(&mut refblocks, 0x103, 16, 2).unwrap();
        // The L2 table cluster (host 0x4000 -> entry idx 0x4) is
        // shared by two L1s before the delete; seed it at 2 so the
        // decrement takes it to 1.
        set_refcount_in_block(&mut refblocks, 0x4, 16, 2).unwrap();

        let l1 = refc_l1();
        update_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete { snapshot_l1: &l1 },
            &mut refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        )
        .unwrap();

        assert_eq!(read_refcount_in_block(&refblocks, 0x100, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&refblocks, 0x101, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&refblocks, 0x102, 16).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&refblocks, 0x103, 16).unwrap(), 1);
        // The L2 table cluster is now counted by the delete: its
        // refcount went 2 -> 1 (only the active L1 still references
        // it once the snapshot is gone).
        assert_eq!(read_refcount_in_block(&refblocks, 0x4, 16).unwrap(), 1);
    }

    #[test]
    fn refcount_dry_run_aborts_on_overflow_without_mutation() {
        let mut refblocks = [0u8; 4096];
        // Cluster at host offset 0x10_2000 (entry idx 0x102) has
        // refcount at max for 16-bit. The increment will overflow.
        set_refcount_in_block(&mut refblocks, 0x100, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x101, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x102, 16, 0xffff).unwrap();
        set_refcount_in_block(&mut refblocks, 0x103, 16, 1).unwrap();

        let snapshot = refblocks; // copy for byte-identity comparison
        let l1 = refc_l1();
        let err = update_snapshot_refcount(
            SnapshotRefcountOp::IncrementForCreate { snapshot_l1: &l1 },
            &mut refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        );
        match err {
            Err(SnapshotError::RefcountOverflow { at_host_offset }) => {
                assert_eq!(at_host_offset, 0x10_2000);
            }
            other => panic!("expected RefcountOverflow, got {other:?}"),
        }
        // Byte-identity: dry-run must not have mutated refblocks.
        assert_eq!(refblocks, snapshot);
    }

    #[test]
    fn refcount_swap_for_apply() {
        let mut refblocks = [0u8; 4096];
        // Active L1 (from_l1) reaches clusters at host offsets
        // 0x10_0000 and 0x10_1000; target snapshot L1 (to_l1)
        // reaches 0x10_2000 and 0x10_3000. No overlap.
        set_refcount_in_block(&mut refblocks, 0x100, 16, 2).unwrap();
        set_refcount_in_block(&mut refblocks, 0x101, 16, 2).unwrap();
        set_refcount_in_block(&mut refblocks, 0x102, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x103, 16, 1).unwrap();
        // The two sides reach distinct L2 table clusters: from_l1's
        // L2 at host 0x4000 (entry 0x4), to_l1's at 0x5000 (entry
        // 0x5). The apply decrements from's L2 table and increments
        // to's, exactly as it does for the data clusters.
        set_refcount_in_block(&mut refblocks, 0x4, 16, 2).unwrap();
        set_refcount_in_block(&mut refblocks, 0x5, 16, 1).unwrap();

        static FROM_L2: [u8; 16] = {
            let mut b = [0u8; 16];
            let e0 = 0x10_0000u64.to_be_bytes();
            let e1 = 0x10_1000u64.to_be_bytes();
            let mut i = 0;
            while i < 8 {
                b[i] = e0[i];
                b[8 + i] = e1[i];
                i += 1;
            }
            b
        };
        static TO_L2: [u8; 16] = {
            let mut b = [0u8; 16];
            let e0 = 0x10_2000u64.to_be_bytes();
            let e1 = 0x10_3000u64.to_be_bytes();
            let mut i = 0;
            while i < 8 {
                b[i] = e0[i];
                b[8 + i] = e1[i];
                i += 1;
            }
            b
        };
        let from_l1 = l1_pointing_to(0x4000, true);
        let to_l1 = l1_pointing_to(0x5000, true);

        // SnapshotRefcountOp::SwapForApply calls the closure
        // four times: dry-run(from), dry-run(to), apply(from),
        // apply(to). Hand back FROM_L2 on even calls (0, 2)
        // and TO_L2 on odd calls (1, 3).
        let mut walk_count = 0u32;
        update_snapshot_refcount(
            SnapshotRefcountOp::SwapForApply {
                from_l1: &from_l1,
                to_l1: &to_l1,
            },
            &mut refblocks,
            12,
            16,
            false,
            |idx| {
                if idx != 0 {
                    return None;
                }
                let l2: &'static [u8] = if walk_count.is_multiple_of(2) {
                    &FROM_L2[..]
                } else {
                    &TO_L2[..]
                };
                walk_count += 1;
                Some(l2)
            },
            refblock_lookup,
        )
        .unwrap();

        // from_l1 clusters decremented: 0x100 / 0x101 go 2 -> 1.
        // to_l1 clusters incremented: 0x102 / 0x103 go 1 -> 2.
        assert_eq!(read_refcount_in_block(&refblocks, 0x100, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&refblocks, 0x101, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&refblocks, 0x102, 16).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&refblocks, 0x103, 16).unwrap(), 2);
        // The per-side L2 table clusters move with their side: from's
        // L2 table (0x4) decremented 2 -> 1, to's L2 table (0x5)
        // incremented 1 -> 2.
        assert_eq!(read_refcount_in_block(&refblocks, 0x4, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&refblocks, 0x5, 16).unwrap(), 2);
    }

    #[test]
    fn refcount_underflow_in_dry_run() {
        let mut refblocks = [0u8; 4096];
        // Cluster at 0x10_0000 has refcount 0; decrement
        // underflows.
        set_refcount_in_block(&mut refblocks, 0x100, 16, 0).unwrap();
        set_refcount_in_block(&mut refblocks, 0x101, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x102, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x103, 16, 1).unwrap();

        let snapshot = refblocks;
        let l1 = refc_l1();
        let err = update_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete { snapshot_l1: &l1 },
            &mut refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        );
        assert_eq!(err, Err(SnapshotError::ParseFailed));
        // Byte-identity.
        assert_eq!(refblocks, snapshot);
    }

    // ---- L2-table refcount coverage (phase 6b, open question 2) ----
    //
    // These tests pin the phase-6 extension: update_snapshot_refcount
    // must adjust each L2 table cluster's refcount once per non-zero
    // L1 entry, mirroring qemu's qcow2_update_snapshot_refcount.

    /// An L2 table with a single allocated data cluster at
    /// host 0x10_0000 (entry idx 0x100 under refblock_lookup).
    static L2_ONE_DATA: [u8; 32] = {
        let mut b = [0u8; 32];
        let e = 0x10_0000u64.to_be_bytes();
        let mut j = 0;
        while j < 8 {
            b[j] = e[j];
            j += 1;
        }
        b
    };

    /// An empty L2 table (no allocated data clusters). Used to prove
    /// the L2-table cluster itself is still counted even when it has
    /// no data entries.
    static L2_EMPTY: [u8; 32] = [0u8; 32];

    #[test]
    fn l2_table_increment_bumps_only_l2_cluster_when_data_empty() {
        // L1 has one entry pointing at an L2 table at host 0x4000
        // (entry idx 0x4). The L2 table is empty, so the only
        // refcount that should change is the L2 table cluster's.
        let mut refblocks = [0u8; 4096];
        set_refcount_in_block(&mut refblocks, 0x4, 16, 1).unwrap();
        let l1 = l1_pointing_to(0x4000, true);
        update_snapshot_refcount(
            SnapshotRefcountOp::IncrementForCreate { snapshot_l1: &l1 },
            &mut refblocks,
            12,
            16,
            false,
            |_idx| Some(&L2_EMPTY[..]),
            refblock_lookup,
        )
        .unwrap();
        // L2 table cluster bumped exactly once: 1 -> 2.
        assert_eq!(read_refcount_in_block(&refblocks, 0x4, 16).unwrap(), 2);
    }

    #[test]
    fn l2_table_two_l1_entries_bump_both_l2_clusters() {
        // Two L1 entries pointing at two distinct L2 tables at host
        // 0x4000 (idx 0x4) and 0x6000 (idx 0x6). Each L2 table
        // cluster must be bumped exactly once.
        let mut l1 = [0u8; 16];
        l1[0..8].copy_from_slice(&l1_pointing_to(0x4000, true));
        l1[8..16].copy_from_slice(&l1_pointing_to(0x6000, true));
        let mut refblocks = [0u8; 4096];
        set_refcount_in_block(&mut refblocks, 0x4, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x6, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x100, 16, 1).unwrap();
        update_snapshot_refcount(
            SnapshotRefcountOp::IncrementForCreate { snapshot_l1: &l1 },
            &mut refblocks,
            12,
            16,
            false,
            // Both L1 entries hand back the same one-data-cluster L2
            // fixture; the data cluster (0x100) is therefore bumped
            // twice, while each L2 table cluster is bumped once.
            |_idx| Some(&L2_ONE_DATA[..]),
            refblock_lookup,
        )
        .unwrap();
        assert_eq!(read_refcount_in_block(&refblocks, 0x4, 16).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&refblocks, 0x6, 16).unwrap(), 2);
        // Shared data cluster reached from both L2s: bumped twice.
        assert_eq!(read_refcount_in_block(&refblocks, 0x100, 16).unwrap(), 3);
    }

    #[test]
    fn l2_table_unallocated_l1_entry_contributes_no_bump() {
        // L1 entry 0 is unallocated (zero); entry 1 points at an L2
        // table at host 0x4000 (idx 0x4). Only one L2-table bump.
        let mut l1 = [0u8; 16];
        // entry 0 left zero
        l1[8..16].copy_from_slice(&l1_pointing_to(0x4000, true));
        let mut refblocks = [0u8; 4096];
        set_refcount_in_block(&mut refblocks, 0x4, 16, 1).unwrap();
        let mut l2_calls = 0u32;
        update_snapshot_refcount(
            SnapshotRefcountOp::IncrementForCreate { snapshot_l1: &l1 },
            &mut refblocks,
            12,
            16,
            false,
            |idx| {
                // The closure must only be asked for the allocated
                // entry (index 1), never index 0.
                assert_eq!(idx, 1, "unallocated L1 entry 0 must be skipped");
                l2_calls += 1;
                Some(&L2_EMPTY[..])
            },
            refblock_lookup,
        )
        .unwrap();
        assert_eq!(read_refcount_in_block(&refblocks, 0x4, 16).unwrap(), 2);
        // l2_for_index called once per pass (dry-run + apply) for
        // the single allocated entry.
        assert_eq!(l2_calls, 2);
    }

    #[test]
    fn l2_table_dry_run_overflow_on_l2_cluster_leaves_refblocks_untouched() {
        // The L2 table cluster (host 0x4000 -> entry 0x4) is already
        // at the 16-bit max; the create's L2-table bump would
        // overflow. The data clusters are fine, so the overflow is
        // detected on the L2 table cluster specifically. Byte-
        // identity must hold (the dry-run mutates nothing).
        let mut refblocks = [0u8; 4096];
        set_refcount_in_block(&mut refblocks, 0x100, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x101, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x102, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x103, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x4, 16, 0xffff).unwrap();

        let snapshot = refblocks; // byte-identity reference
        let l1 = refc_l1();
        let err = update_snapshot_refcount(
            SnapshotRefcountOp::IncrementForCreate { snapshot_l1: &l1 },
            &mut refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        );
        match err {
            Err(SnapshotError::RefcountOverflow { at_host_offset }) => {
                // The overflow is reported against the L2 table
                // cluster's host offset, not a data cluster.
                assert_eq!(at_host_offset, 0x4000);
            }
            other => panic!("expected RefcountOverflow on the L2 cluster, got {other:?}"),
        }
        assert_eq!(refblocks, snapshot);
    }

    #[test]
    fn l2_table_swap_with_shared_l2_nets_to_zero() {
        // Degenerate apply where from_l1 and to_l1 reach the *same*
        // L2 table cluster (host 0x4000 -> entry 0x4). The
        // decrement on the from side and the increment on the to
        // side must net to zero for that shared L2 table cluster.
        let mut refblocks = [0u8; 4096];
        // Shared L2 table cluster starts at 2.
        set_refcount_in_block(&mut refblocks, 0x4, 16, 2).unwrap();
        // Shared single data cluster 0x100 starts at 2 too.
        set_refcount_in_block(&mut refblocks, 0x100, 16, 2).unwrap();

        let from_l1 = l1_pointing_to(0x4000, true);
        let to_l1 = l1_pointing_to(0x4000, true);
        update_snapshot_refcount(
            SnapshotRefcountOp::SwapForApply {
                from_l1: &from_l1,
                to_l1: &to_l1,
            },
            &mut refblocks,
            12,
            16,
            false,
            |_idx| Some(&L2_ONE_DATA[..]),
            refblock_lookup,
        )
        .unwrap();
        // dec then inc on the same clusters: net zero.
        assert_eq!(read_refcount_in_block(&refblocks, 0x4, 16).unwrap(), 2);
        assert_eq!(read_refcount_in_block(&refblocks, 0x100, 16).unwrap(), 2);
    }

    // -------------------- precheck_snapshot_refcount --------------------

    #[test]
    fn precheck_healthy_decrement_passes_and_mutates_nothing() {
        let mut refblocks = [0u8; 4096];
        for idx in [0x100u64, 0x101, 0x102, 0x103] {
            set_refcount_in_block(&mut refblocks, idx, 16, 2).unwrap();
        }
        set_refcount_in_block(&mut refblocks, 0x4, 16, 2).unwrap();
        let snapshot = refblocks; // byte-identity reference
        let l1 = refc_l1();
        precheck_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete { snapshot_l1: &l1 },
            &refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        )
        .unwrap();
        // Provably untouched on success too.
        assert_eq!(refblocks, snapshot);
    }

    #[test]
    fn precheck_detects_data_cluster_underflow() {
        let mut refblocks = [0u8; 4096];
        // Data cluster 0x10_1000 (entry 0x101) has refcount 0; the
        // decrement underflows -> ParseFailed.
        set_refcount_in_block(&mut refblocks, 0x100, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x102, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x103, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x4, 16, 1).unwrap();
        let snapshot = refblocks;
        let l1 = refc_l1();
        let err = precheck_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete { snapshot_l1: &l1 },
            &refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        );
        assert_eq!(err, Err(SnapshotError::ParseFailed));
        assert_eq!(refblocks, snapshot);
    }

    #[test]
    fn precheck_detects_l2_table_cluster_underflow() {
        let mut refblocks = [0u8; 4096];
        // All data clusters healthy; the L2 table cluster itself
        // (host 0x4000 -> entry 0x4) is 0, so the L2-table-cluster
        // coverage must catch the underflow.
        for idx in [0x100u64, 0x101, 0x102, 0x103] {
            set_refcount_in_block(&mut refblocks, idx, 16, 1).unwrap();
        }
        let snapshot = refblocks;
        let l1 = refc_l1();
        let err = precheck_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete { snapshot_l1: &l1 },
            &refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        );
        assert_eq!(err, Err(SnapshotError::ParseFailed));
        assert_eq!(refblocks, snapshot);
    }

    #[test]
    fn precheck_detects_increment_overflow_with_offset() {
        let mut refblocks = [0u8; 4096];
        set_refcount_in_block(&mut refblocks, 0x100, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x101, 16, 0xffff).unwrap();
        set_refcount_in_block(&mut refblocks, 0x102, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x103, 16, 1).unwrap();
        set_refcount_in_block(&mut refblocks, 0x4, 16, 1).unwrap();
        let l1 = refc_l1();
        let err = precheck_snapshot_refcount(
            SnapshotRefcountOp::IncrementForCreate { snapshot_l1: &l1 },
            &refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        );
        match err {
            Err(SnapshotError::RefcountOverflow { at_host_offset }) => {
                assert_eq!(at_host_offset, 0x10_1000);
            }
            other => panic!("expected RefcountOverflow, got {other:?}"),
        }
    }

    #[test]
    fn precheck_swap_checks_decrement_side() {
        let mut refblocks = [0u8; 4096];
        // from_l1's data cluster 0x10_0000 has refcount 0 ->
        // underflow on the decrement side.
        set_refcount_in_block(&mut refblocks, 0x4, 16, 1).unwrap();
        let from_l1 = l1_pointing_to(0x4000, true);
        let to_l1 = [0u8; 8]; // empty
        let err = precheck_snapshot_refcount(
            SnapshotRefcountOp::SwapForApply {
                from_l1: &from_l1,
                to_l1: &to_l1,
            },
            &refblocks,
            12,
            16,
            false,
            |_idx| Some(&L2_ONE_DATA[..]),
            refblock_lookup,
        );
        assert_eq!(err, Err(SnapshotError::ParseFailed));
    }

    #[test]
    fn precheck_swap_checks_increment_side() {
        let mut refblocks = [0u8; 4096];
        // to_l1's data cluster 0x10_0000 is at the 16-bit max ->
        // overflow on the increment side.
        set_refcount_in_block(&mut refblocks, 0x100, 16, 0xffff).unwrap();
        set_refcount_in_block(&mut refblocks, 0x4, 16, 1).unwrap();
        let from_l1 = [0u8; 8]; // empty
        let to_l1 = l1_pointing_to(0x4000, true);
        let err = precheck_snapshot_refcount(
            SnapshotRefcountOp::SwapForApply {
                from_l1: &from_l1,
                to_l1: &to_l1,
            },
            &refblocks,
            12,
            16,
            false,
            |_idx| Some(&L2_ONE_DATA[..]),
            refblock_lookup,
        );
        match err {
            Err(SnapshotError::RefcountOverflow { at_host_offset }) => {
                assert_eq!(at_host_offset, 0x10_0000);
            }
            other => panic!("expected RefcountOverflow, got {other:?}"),
        }
    }

    #[test]
    fn precheck_swap_healthy_both_sides_passes() {
        let mut refblocks = [0u8; 4096];
        set_refcount_in_block(&mut refblocks, 0x100, 16, 2).unwrap();
        set_refcount_in_block(&mut refblocks, 0x4, 16, 2).unwrap();
        let snapshot = refblocks;
        let from_l1 = l1_pointing_to(0x4000, true);
        let to_l1 = l1_pointing_to(0x4000, true);
        precheck_snapshot_refcount(
            SnapshotRefcountOp::SwapForApply {
                from_l1: &from_l1,
                to_l1: &to_l1,
            },
            &refblocks,
            12,
            16,
            false,
            |_idx| Some(&L2_ONE_DATA[..]),
            refblock_lookup,
        )
        .unwrap();
        assert_eq!(refblocks, snapshot);
    }

    #[test]
    fn precheck_matches_paired_mutator_dry_run() {
        // The precheck must agree with update_snapshot_refcount's
        // built-in pass 1: where the precheck passes, the paired
        // mutator applies cleanly.
        let mut refblocks = [0u8; 4096];
        for idx in [0x100u64, 0x101, 0x102, 0x103] {
            set_refcount_in_block(&mut refblocks, idx, 16, 2).unwrap();
        }
        set_refcount_in_block(&mut refblocks, 0x4, 16, 2).unwrap();
        let l1 = refc_l1();
        precheck_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete { snapshot_l1: &l1 },
            &refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        )
        .unwrap();
        update_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete { snapshot_l1: &l1 },
            &mut refblocks,
            12,
            16,
            false,
            |_idx| Some(&REFC_L2[..]),
            refblock_lookup,
        )
        .unwrap();
        assert_eq!(read_refcount_in_block(&refblocks, 0x100, 16).unwrap(), 1);
        assert_eq!(read_refcount_in_block(&refblocks, 0x4, 16).unwrap(), 1);
    }

    // -------------------- update_copied_flags_for_l1 --------------------

    static COPIED_TEST_L2: [u8; 16] = {
        let mut b = [0u8; 16];
        // Two entries: 0x10_0000 (no COPIED), 0x10_1000 (with COPIED).
        let e0 = 0x10_0000u64.to_be_bytes();
        let e1 = (0x10_1000u64 | OFLAG_COPIED).to_be_bytes();
        let mut i = 0;
        while i < 8 {
            b[i] = e0[i];
            b[8 + i] = e1[i];
            i += 1;
        }
        b
    };

    // Mutable copies for tests (each test reinitialises).
    fn copied_test_l2_buf() -> [u8; 16] {
        let mut b = [0u8; 16];
        let e0 = 0x10_0000u64.to_be_bytes();
        let e1 = (0x10_1000u64 | OFLAG_COPIED).to_be_bytes();
        b[0..8].copy_from_slice(&e0);
        b[8..16].copy_from_slice(&e1);
        b
    }

    #[test]
    fn copied_flags_set_when_refcount_one() {
        let _ = COPIED_TEST_L2; // keep the static referenced for clippy
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64) & L1_OFFSET_MASK; // no copied yet
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let l2 = copied_test_l2_buf();

        // refcount_for_cluster: L2 at 0x4000 -> 1; data
        // clusters 0x10_0000 -> 1, 0x10_1000 -> 2.
        let rc = |host_off: u64| -> Option<u64> {
            Some(match host_off {
                0x4000 => 1,
                0x10_0000 => 1,
                0x10_1000 => 2,
                _ => 0,
            })
        };

        // For static lifetime closure, we use leak-by-static.
        // The simplest approach is to splice the mutable
        // l2 buffer through unsafe transmute — but no_std and
        // no unsafe. Instead, use a non-static mutable
        // reference path via a wrapping function that
        // captures a static raw pointer; since the tests run
        // with std, we can use a Mutex<Vec<u8>>... but no_std
        // crate. So inline the L2 mutation logic by passing
        // a closure that returns `None` and exercise only the
        // L1-side rewrite here.

        // L1-side test: refcount=1 -> set COPIED on L1 entry 0.
        let rewrites = update_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| -> Option<&'static mut [u8]> { None },
            rc,
            false,
        );
        // We'll get MisalignedAccess after the L1 update
        // because l2_for_index returned None for an
        // allocated L1 entry. That's fine — we just want to
        // verify the L1 was updated first.
        assert_eq!(rewrites, Err(SnapshotError::MisalignedAccess));
        let v = u64::from_be_bytes([l1[0], l1[1], l1[2], l1[3], l1[4], l1[5], l1[6], l1[7]]);
        assert_eq!(v & OFLAG_COPIED, OFLAG_COPIED);

        let _ = &l2;
    }

    #[test]
    fn copied_flags_clear_when_refcount_above_one() {
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64 & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());

        let rc = |_off: u64| -> Option<u64> { Some(5) };

        let _ = update_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| -> Option<&'static mut [u8]> { None },
            rc,
            false,
        );
        let v = u64::from_be_bytes([l1[0], l1[1], l1[2], l1[3], l1[4], l1[5], l1[6], l1[7]]);
        assert_eq!(v & OFLAG_COPIED, 0);
    }

    #[test]
    fn copied_flags_idempotent_on_l1() {
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64 & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let rc = |_off: u64| -> Option<u64> { Some(1) };
        let _ = update_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| -> Option<&'static mut [u8]> { None },
            rc,
            false,
        );
        let after_first = l1;
        let _ = update_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| -> Option<&'static mut [u8]> { None },
            rc,
            false,
        );
        assert_eq!(l1, after_first);
    }

    #[test]
    fn copied_flags_returns_count_zero_when_no_change_needed() {
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64 & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let rc = |_off: u64| -> Option<u64> { Some(1) };
        // L2 returns Some(empty slice) so the walk doesn't
        // error on the missing L2.
        let rewrites = update_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| -> Option<&'static mut [u8]> { Some(&mut []) },
            rc,
            false,
        )
        .unwrap();
        // No L1 rewrite (already has the right state), no L2
        // entries to walk.
        assert_eq!(rewrites, 0);
    }

    #[test]
    fn copied_flags_skip_unallocated_l1_entries() {
        // L1 entry zero -> the closure must not be invoked.
        let mut l1 = [0u8; 8];
        let rc = |_off: u64| -> Option<u64> {
            panic!("refcount_for_cluster should not be invoked for unalloc L1")
        };
        let r = update_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| -> Option<&'static mut [u8]> { None },
            rc,
            false,
        )
        .unwrap();
        assert_eq!(r, 0);
    }

    #[test]
    fn copied_flags_missing_refcount_errors() {
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64) & L1_OFFSET_MASK;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let rc = |_off: u64| -> Option<u64> { None };
        let r = update_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| -> Option<&'static mut [u8]> { None },
            rc,
            false,
        );
        assert_eq!(r, Err(SnapshotError::MisalignedAccess));
    }

    #[test]
    fn copied_flags_returns_count_one_when_l1_rewritten() {
        let mut l1 = [0u8; 8];
        // L1 entry has COPIED but real refcount is 5; expect
        // one rewrite (the L1 entry) and no L2 work.
        let l1_entry = ((0x4000u64) & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let rc = |_off: u64| -> Option<u64> { Some(5) };
        let r = update_copied_flags_for_l1(
            &mut l1,
            12,
            |_idx| -> Option<&'static mut [u8]> { Some(&mut []) },
            rc,
            false,
        )
        .unwrap();
        assert_eq!(r, 1);
        let v = u64::from_be_bytes([l1[0], l1[1], l1[2], l1[3], l1[4], l1[5], l1[6], l1[7]]);
        assert_eq!(v & OFLAG_COPIED, 0);
    }

    #[test]
    fn copied_flags_zero_cluster_bits_rejected() {
        let mut l1 = [0u8; 8];
        let rc = |_off: u64| -> Option<u64> { Some(1) };
        let r = update_copied_flags_for_l1(
            &mut l1,
            0,
            |_idx| -> Option<&'static mut [u8]> { None },
            rc,
            false,
        );
        assert_eq!(r, Err(SnapshotError::InvalidConfig));
    }

    // ---------------- phase 8b: stale-COPIED scrub ----------------
    //
    // qemu's qcow2_update_snapshot_refcount strips COPIED before
    // classifying; ZERO_PLAIN / UNALLOCATED entries get
    // refcount = 0, so a stale COPIED bit is cleared on every
    // walk. These tests pin the mirrored behaviour. Real mutable
    // L2 buffers are threaded through the 'l2 lifetime with a raw
    // pointer reborrow, the same pattern the guest binary uses.

    /// Run the walker over one L1 entry (-> L2 at 0x4000, rc 1,
    /// COPIED already set so the L1 contributes no rewrite) and
    /// the given L2 buffer. Returns the rewrite count.
    fn run_flags_over_l2(l2: &mut [u8], extended_l2: bool, rc_data: u64) -> u32 {
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64 & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let rc = move |off: u64| -> Option<u64> {
            Some(match off {
                0x4000 => 1,
                _ => rc_data,
            })
        };
        let ptr = l2.as_mut_ptr();
        let len = l2.len();
        update_copied_flags_for_l1(
            &mut l1,
            12,
            // SAFETY: the walker visits each L1 index once, so a
            // single live reborrow of the buffer exists at a time.
            |_idx| Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) }),
            rc,
            extended_l2,
        )
        .unwrap()
    }

    #[test]
    fn scrub_clears_stale_copied_on_zero_plain_standard() {
        // ZERO_PLAIN: zero bit (bit 0) set, offset 0, stale
        // COPIED. The scrub clears COPIED, preserves the zero
        // bit, and counts one rewrite.
        let mut l2 = [0u8; 16];
        l2[0..8].copy_from_slice(&(OFLAG_COPIED | 1u64).to_be_bytes());
        l2[8..16].copy_from_slice(&1u64.to_be_bytes()); // clean zero-plain
        let rewrites = run_flags_over_l2(&mut l2, false, 0);
        assert_eq!(rewrites, 1);
        assert_eq!(u64::from_be_bytes(l2[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_be_bytes(l2[8..16].try_into().unwrap()), 1);
    }

    #[test]
    fn scrub_clears_stale_copied_on_unallocated_standard() {
        // UNALLOCATED with only COPIED set: scrubbed to all-zero.
        let mut l2 = [0u8; 16];
        l2[0..8].copy_from_slice(&OFLAG_COPIED.to_be_bytes());
        // Entry 1 fully zero: untouched, no rewrite counted.
        let rewrites = run_flags_over_l2(&mut l2, false, 0);
        assert_eq!(rewrites, 1);
        assert_eq!(u64::from_be_bytes(l2[0..8].try_into().unwrap()), 0);
        assert_eq!(u64::from_be_bytes(l2[8..16].try_into().unwrap()), 0);
    }

    #[test]
    fn scrub_clean_unallocated_entries_untouched() {
        // No stale flags anywhere: zero rewrites, bytes identical.
        let mut l2 = [0u8; 24];
        l2[0..8].copy_from_slice(&0u64.to_be_bytes());
        l2[8..16].copy_from_slice(&1u64.to_be_bytes()); // zero-plain, clean
        l2[16..24].copy_from_slice(&0u64.to_be_bytes());
        let before = l2;
        let rewrites = run_flags_over_l2(&mut l2, false, 0);
        assert_eq!(rewrites, 0);
        assert_eq!(l2, before);
    }

    #[test]
    fn scrub_clears_stale_copied_on_extended_l2_offset_zero() {
        // Extended L2: 16-byte entries. An offset-0 entry with a
        // stale COPIED (with subclusters this is UNALLOCATED —
        // qcow2_get_cluster_type skips the zero branch — but the
        // scrub result is the same). The subcluster bitmap must
        // be untouched.
        let mut l2 = [0u8; 32];
        l2[0..8].copy_from_slice(&OFLAG_COPIED.to_be_bytes());
        l2[8..16].copy_from_slice(&0xDEAD_BEEF_CAFE_F00Du64.to_be_bytes());
        // Entry 1: bit 0 set + COPIED, offset 0 (UNALLOCATED under
        // extended L2): scrubbed too, bitmap untouched.
        l2[16..24].copy_from_slice(&(OFLAG_COPIED | 1u64).to_be_bytes());
        l2[24..32].copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_be_bytes());
        let rewrites = run_flags_over_l2(&mut l2, true, 0);
        assert_eq!(rewrites, 2);
        assert_eq!(u64::from_be_bytes(l2[0..8].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_be_bytes(l2[8..16].try_into().unwrap()),
            0xDEAD_BEEF_CAFE_F00D
        );
        assert_eq!(u64::from_be_bytes(l2[16..24].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_be_bytes(l2[24..32].try_into().unwrap()),
            0x0123_4567_89AB_CDEF
        );
    }

    #[test]
    fn scrub_does_not_consult_refcounts_for_scrubbed_entries() {
        // qemu assigns refcount = 0 without a refcount lookup for
        // ZERO_PLAIN / UNALLOCATED; the walker must not call
        // refcount_for_cluster for them (only for the L1's own
        // L2 cluster here).
        let mut l1 = [0u8; 8];
        let l1_entry = (0x4000u64 & L1_OFFSET_MASK) | OFLAG_COPIED;
        l1.copy_from_slice(&l1_entry.to_be_bytes());
        let mut l2 = [0u8; 16];
        l2[0..8].copy_from_slice(&(OFLAG_COPIED | 1u64).to_be_bytes());
        l2[8..16].copy_from_slice(&OFLAG_COPIED.to_be_bytes());
        let rc = |off: u64| -> Option<u64> {
            assert_eq!(off, 0x4000, "data refcount consulted for an empty entry");
            Some(1)
        };
        let ptr = l2.as_mut_ptr();
        let len = l2.len();
        let rewrites = update_copied_flags_for_l1(
            &mut l1,
            12,
            // SAFETY: single L1 index, single live reborrow.
            |_idx| Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) }),
            rc,
            false,
        )
        .unwrap();
        assert_eq!(rewrites, 2);
    }

    #[test]
    fn scrub_mixed_with_allocated_entries() {
        // Allocated entries keep the refcount-driven behaviour
        // (rc 2 -> COPIED cleared; rc 1 via a second run -> set),
        // while the stale zero-plain neighbour is scrubbed in the
        // same pass.
        let mut l2 = [0u8; 24];
        l2[0..8].copy_from_slice(&(0x10_0000u64 | OFLAG_COPIED).to_be_bytes());
        l2[8..16].copy_from_slice(&(OFLAG_COPIED | 1u64).to_be_bytes());
        l2[16..24].copy_from_slice(&0x10_1000u64.to_be_bytes());
        let rewrites = run_flags_over_l2(&mut l2, false, 2);
        // Entry 0: rc 2, COPIED cleared (1 rewrite). Entry 1:
        // scrubbed (1 rewrite). Entry 2: rc 2, COPIED already
        // clear (no rewrite).
        assert_eq!(rewrites, 2);
        assert_eq!(u64::from_be_bytes(l2[0..8].try_into().unwrap()), 0x10_0000);
        assert_eq!(u64::from_be_bytes(l2[8..16].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_be_bytes(l2[16..24].try_into().unwrap()),
            0x10_1000
        );
    }

    #[test]
    fn scrub_allocated_refcount_one_still_sets_copied() {
        // Regression guard for the allocated path: rc 1 sets
        // COPIED exactly as before the scrub change.
        let mut l2 = [0u8; 16];
        l2[0..8].copy_from_slice(&0x10_0000u64.to_be_bytes());
        l2[8..16].copy_from_slice(&(OFLAG_COPIED | 1u64).to_be_bytes());
        let rewrites = run_flags_over_l2(&mut l2, false, 1);
        assert_eq!(rewrites, 2);
        assert_eq!(
            u64::from_be_bytes(l2[0..8].try_into().unwrap()),
            0x10_0000 | OFLAG_COPIED
        );
        assert_eq!(u64::from_be_bytes(l2[8..16].try_into().unwrap()), 1);
    }

    #[test]
    fn scrub_is_idempotent() {
        let mut l2 = [0u8; 16];
        l2[0..8].copy_from_slice(&(OFLAG_COPIED | 1u64).to_be_bytes());
        l2[8..16].copy_from_slice(&OFLAG_COPIED.to_be_bytes());
        let first = run_flags_over_l2(&mut l2, false, 0);
        assert_eq!(first, 2);
        let after_first = l2;
        let second = run_flags_over_l2(&mut l2, false, 0);
        assert_eq!(second, 0);
        assert_eq!(l2, after_first);
    }
}
