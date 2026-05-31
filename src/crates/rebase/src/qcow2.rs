//! qcow2 rebase planner.
//!
//! Two entry points share the same signature:
//!
//! - [`plan_rebase_qcow2`] in [`crate::RebaseMode::Unsafe`] mode
//!   (`-u`) emits the complete patch list the guest applies in
//!   order: optional backing-format extension, optional path
//!   write (in place or to a relocated cluster), and the
//!   header field rewrite last.
//! - [`plan_rebase_qcow2`] in [`crate::RebaseMode::Safe`] mode
//!   emits a [`RebaseQcow2SafeContext`] the guest threads
//!   through per-cluster comparison plus a deferred-apply
//!   [`RebasePlan`] of metadata patches the guest applies
//!   after the comparison loop completes.
//!
//! Both modes share the [`allocate_overlay_cluster_qcow2`]
//! helper for claiming a fresh cluster from the staged
//! refcount blocks. Unsafe-mode rebase uses it when the new
//! backing path is longer than the existing slot and the
//! path string must be relocated to a fresh cluster;
//! safe-mode rebase uses it once per guest cluster that
//! turns out to need a copy at runtime.
//!
//! Refcount-width coverage in v1: only `refcount_bits == 16`
//! (qemu-img's default). Other widths return
//! [`RebaseError::UnsupportedFormat`]. Adding the remaining
//! widths is a mechanical follow-up; the bit-packing
//! reference is `qcow2::lookup_refcount` in
//! `src/crates/qcow2/src/lib.rs`.

use qcow2::{
    QcowHeader, BACKING_FILE_OFFSET_OFFSET, BACKING_FILE_SIZE_OFFSET, INCOMPAT_CORRUPT,
    INCOMPAT_DIRTY, INCOMPAT_EXTERNAL_DATA,
};

use crate::{RebaseError, RebaseMode, RebasePatch, RebasePlan};

/// Maximum supported backing-file path length, matching
/// `CreateConfig::MAX_BACKING_FILE` (1024 bytes).
pub const MAX_BACKING_PATH_LEN: usize = 1024;

/// Options for [`plan_rebase_qcow2`].
///
/// Borrows are bound to the lifetime of the caller's staging
/// data. The planner does not retain anything outside
/// `scratch`; lifetimes on the output are bound to `scratch`,
/// not to the opts.
#[derive(Debug, Clone, Copy)]
pub struct Qcow2RebaseOpts<'a> {
    /// Rebase mode.
    pub mode: RebaseMode,
    /// Overlay's current header bytes (at least 105 bytes for
    /// v2 / 4 KiB for v3 with extensions). The planner re-
    /// parses the header internally to avoid trusting host-
    /// pre-probed fields.
    pub overlay_header: &'a [u8],
    /// Overlay's current file size in bytes (the EOF). Used
    /// to compute relocation targets for the path string and
    /// the Append patch offset.
    pub overlay_file_size: u64,
    /// Raw refcount-table bytes (an array of u64 BE entries
    /// pointing at refcount blocks). Used only by the
    /// safe-mode allocator; unsafe mode without relocation
    /// can pass an empty slice.
    pub refcount_table: &'a [u8],
    /// Host byte offsets of each refcount block. Length must
    /// equal `refcount_block_count`. The allocator mutates
    /// refcount-block bytes in scratch; the guest uses these
    /// offsets to flush dirty blocks back to the file.
    /// Safe-mode and unsafe-with-relocation only.
    pub refblock_host_offsets: &'a [u64],
    /// Concatenated refcount-block bytes (`refblock_count *
    /// cluster_size` bytes). The planner copies these into
    /// scratch for the allocator to mutate. Safe-mode and
    /// unsafe-with-relocation only.
    pub refcount_blocks: &'a [u8],
    /// Number of refcount blocks present in
    /// `refcount_blocks`. Safe-mode and unsafe-with-
    /// relocation only.
    pub refblock_count: u32,
    /// New backing file's virtual size in bytes. Used for
    /// compatibility checking.
    pub new_backing_virtual_size: u64,
    /// New backing path string. May be empty when paired
    /// with `detach`.
    pub new_backing_path: &'a [u8],
    /// Detach: `new_backing_path` should be empty and the
    /// rewrite zeros the backing-file pointer.
    pub detach: bool,
}

/// Output of [`plan_rebase_qcow2`].
///
/// `Unsafe` carries a complete patch list ready to apply.
/// `Safe` carries a context the guest drives at runtime plus
/// a deferred-apply metadata plan to commit after the
/// comparison loop completes.
///
/// Not `Copy`: `Safe` carries `&mut` borrows into scratch.
/// The size asymmetry is unrelated to the `Copy` deletion —
/// it is suppressed with `allow(large_enum_variant)` to keep
/// `Unsafe`'s inline plan storage.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Qcow2RebaseOutput<'a> {
    /// Unsafe-mode (`-u`) output.
    Unsafe { plan: RebasePlan<'a> },
    /// Safe-mode output.
    Safe {
        context: RebaseQcow2SafeContext<'a>,
        deferred_metadata: RebasePlan<'a>,
    },
}

/// Context carried by the guest across safe-mode rebase's
/// per-cluster comparison loop.
///
/// All numeric fields are populated by the planner. The two
/// slice fields are views into the caller's scratch buffer
/// that the allocator mutates as it claims clusters. The
/// guest is responsible for flushing the dirty refcount-block
/// bytes back to the overlay once the comparison loop
/// completes (it knows where each block lives via the
/// `refblock_host_offsets` it passed in via opts).
#[derive(Debug)]
pub struct RebaseQcow2SafeContext<'a> {
    /// Overlay cluster size in bytes (echoed from the parsed
    /// header).
    pub overlay_cluster_size: u32,
    /// Total guest clusters the comparison loop iterates over
    /// (`overlay.virtual_size / cluster_size`, rounded up).
    pub overlay_cluster_count: u64,
    /// Overlay L1 table offset in the overlay file.
    pub overlay_l1_table_offset: u64,
    /// Overlay L1 size in entries.
    pub overlay_l1_size: u32,
    /// Refcount entry width in bits. v1 supports only 16.
    pub refcount_bits: u32,
    /// Refcount entries per refcount block (`cluster_size * 8
    /// / refcount_bits`).
    pub entries_per_refblock: u64,
    /// Number of refcount blocks present in `refblocks`.
    pub refblock_count: u32,
    /// Staged refcount-block bytes, mutated in place by the
    /// allocator.
    pub refblocks: &'a mut [u8],
    /// Per-refblock dirty bitmap; bit `i` is set if the
    /// allocator has modified refblock `i`. Length is
    /// `(refblock_count + 7) / 8`.
    pub dirty: &'a mut [u8],
}

/// Allocator state threaded through repeated calls to
/// [`allocate_overlay_cluster_qcow2`].
///
/// The guest constructs this at the start of the comparison
/// loop (or before calling unsafe-mode relocation) and
/// mutates it through subsequent calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllocationState {
    /// Refblock index where the next scan resumes.
    pub next_refblock: u32,
    /// Entry index within the current refblock where the next
    /// scan resumes.
    pub next_entry_in_refblock: u64,
    /// Total clusters allocated so far.
    pub allocated: u64,
}

/// Plan a qcow2 rebase.
///
/// Validates compatibility, parses the overlay header, and
/// dispatches to unsafe-mode or safe-mode planning per
/// `opts.mode`.
pub fn plan_rebase_qcow2<'a>(
    opts: &Qcow2RebaseOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<Qcow2RebaseOutput<'a>, RebaseError> {
    // Validation shared by both modes.
    let parsed = QcowHeader::parse(opts.overlay_header).ok_or(RebaseError::ParseFailed)?;
    if parsed.dirty || parsed.corrupt {
        return Err(RebaseError::OverlayCorrupt);
    }
    if parsed.has_external_data || (parsed.incompatible_features & INCOMPAT_EXTERNAL_DATA) != 0 {
        return Err(RebaseError::ExternalDataFile);
    }
    if (parsed.incompatible_features & (INCOMPAT_DIRTY | INCOMPAT_CORRUPT)) != 0 {
        return Err(RebaseError::OverlayCorrupt);
    }
    if parsed.crypt_method != 0 {
        return Err(RebaseError::LuksUnsupported);
    }

    // Detach is encoded as an empty path; reject paths that
    // are present but oversized.
    let path_len = opts.new_backing_path.len();
    if opts.detach && path_len != 0 {
        return Err(RebaseError::HeaderMismatch);
    }
    if path_len > MAX_BACKING_PATH_LEN {
        return Err(RebaseError::BackingPathTooLong);
    }

    if opts.new_backing_virtual_size < opts.overlay_virtual_size_required(&parsed) {
        return Err(RebaseError::NewBackingIncompatible);
    }

    match opts.mode {
        RebaseMode::Unsafe => plan_qcow2_unsafe(opts, &parsed, scratch),
        RebaseMode::Safe => plan_qcow2_safe(opts, &parsed, scratch),
    }
}

impl Qcow2RebaseOpts<'_> {
    /// The overlay's effective virtual size (used for
    /// compatibility checking against the new backing). A
    /// detach drops the requirement to zero — the overlay
    /// becomes standalone and the new backing's size is
    /// irrelevant.
    fn overlay_virtual_size_required(&self, parsed: &QcowHeader) -> u64 {
        if self.detach {
            0
        } else {
            parsed.virtual_size
        }
    }
}

// ---------------------------------------------------------------------------
// Safe mode (step 2c)
// ---------------------------------------------------------------------------

fn plan_qcow2_safe<'a>(
    opts: &Qcow2RebaseOpts<'_>,
    parsed: &QcowHeader,
    scratch: &'a mut [u8],
) -> Result<Qcow2RebaseOutput<'a>, RebaseError> {
    // v1 supports refcount_bits == 16 only. Other widths are
    // a mechanical extension; track them in a follow-up.
    if parsed.refcount_bits != 16 {
        return Err(RebaseError::UnsupportedFormat);
    }

    let cluster_size = parsed.cluster_size;
    if cluster_size == 0 {
        return Err(RebaseError::OverlayCorrupt);
    }
    let entries_per_refblock = (cluster_size * 8) / parsed.refcount_bits as u64;

    let refblock_count = opts.refblock_count as usize;
    let refblocks_size_bytes = refblock_count
        .checked_mul(cluster_size as usize)
        .ok_or(RebaseError::Overflow)?;
    if opts.refcount_blocks.len() < refblocks_size_bytes {
        return Err(RebaseError::HeaderMismatch);
    }
    if opts.refblock_host_offsets.len() != refblock_count {
        return Err(RebaseError::HeaderMismatch);
    }
    let dirty_bytes = refblock_count.div_ceil(8);

    // Lay out scratch: header rewrite buffer, path buffer,
    // dirty bitmap, staged refcount-block bytes. Each region
    // ends up as its own (immutable or mutable) view.
    let header_rewrite_len = 12usize; // backing_file_offset u64 + backing_file_size u32
    let path_buf_len = MAX_BACKING_PATH_LEN;
    let need = header_rewrite_len
        .checked_add(path_buf_len)
        .and_then(|v| v.checked_add(dirty_bytes))
        .and_then(|v| v.checked_add(refblocks_size_bytes))
        .ok_or(RebaseError::Overflow)?;
    if scratch.len() < need {
        return Err(RebaseError::ScratchTooSmall);
    }

    let (header_rewrite_buf, rest) = scratch.split_at_mut(header_rewrite_len);
    let (path_buf, rest) = rest.split_at_mut(path_buf_len);
    let (dirty_buf, rest) = rest.split_at_mut(dirty_bytes);
    let (refblocks_buf, _rest) = rest.split_at_mut(refblocks_size_bytes);

    // Populate the path buffer (left-padded with zero bytes
    // beyond `path_len`; the patch references only the first
    // `path_len` bytes).
    let path_len = opts.new_backing_path.len();
    path_buf[..path_len].copy_from_slice(opts.new_backing_path);

    // Populate the refcount-block scratch from opts.
    refblocks_buf.copy_from_slice(&opts.refcount_blocks[..refblocks_size_bytes]);

    // Zero the dirty bitmap; allocator will set bits as it
    // mutates blocks.
    for b in dirty_buf.iter_mut() {
        *b = 0;
    }

    // Build the deferred metadata plan. Order matches the
    // unsafe-mode plan because the guest applies metadata
    // patches in the same sequence: path bytes (so the
    // pointer rewrite never references stale path memory),
    // then the header field rewrite.
    let mut plan = RebasePlan::new(opts.overlay_file_size);

    let (new_backing_file_offset, new_backing_file_size) =
        compute_path_target(opts, parsed, path_len)?;

    // Path bytes patch (only if there is a path to write).
    if new_backing_file_size > 0 {
        let path_patch_bytes: &'a [u8] = &path_buf[..path_len];
        plan.push(RebasePatch::Write {
            byte_offset: new_backing_file_offset,
            bytes: path_patch_bytes,
        })?;
    }

    // Header field rewrite at offset 8: backing_file_offset
    // (u64 BE) followed by backing_file_size (u32 BE).
    header_rewrite_buf[0..8].copy_from_slice(&new_backing_file_offset.to_be_bytes());
    header_rewrite_buf[8..12].copy_from_slice(&new_backing_file_size.to_be_bytes());
    let header_patch_bytes: &'a [u8] = header_rewrite_buf;
    plan.push(RebasePatch::Write {
        byte_offset: BACKING_FILE_OFFSET_OFFSET as u64,
        bytes: header_patch_bytes,
    })?;

    debug_assert_eq!(
        BACKING_FILE_SIZE_OFFSET - BACKING_FILE_OFFSET_OFFSET,
        8,
        "header field layout assumption broken"
    );

    let context = RebaseQcow2SafeContext {
        overlay_cluster_size: cluster_size as u32,
        overlay_cluster_count: parsed.virtual_size.div_ceil(cluster_size),
        overlay_l1_table_offset: parsed.l1_table_offset,
        overlay_l1_size: parsed.l1_size,
        refcount_bits: parsed.refcount_bits,
        entries_per_refblock,
        refblock_count: opts.refblock_count,
        refblocks: refblocks_buf,
        dirty: dirty_buf,
    };

    Ok(Qcow2RebaseOutput::Safe {
        context,
        deferred_metadata: plan,
    })
}

// ---------------------------------------------------------------------------
// Unsafe mode
// ---------------------------------------------------------------------------

fn plan_qcow2_unsafe<'a>(
    opts: &Qcow2RebaseOpts<'_>,
    parsed: &QcowHeader,
    scratch: &'a mut [u8],
) -> Result<Qcow2RebaseOutput<'a>, RebaseError> {
    let header_rewrite_len = 12usize;
    let path_buf_len = MAX_BACKING_PATH_LEN;
    let need = header_rewrite_len
        .checked_add(path_buf_len)
        .ok_or(RebaseError::Overflow)?;
    if scratch.len() < need {
        return Err(RebaseError::ScratchTooSmall);
    }

    let (header_rewrite_buf, rest) = scratch.split_at_mut(header_rewrite_len);
    let (path_buf, _rest) = rest.split_at_mut(path_buf_len);

    let path_len = opts.new_backing_path.len();
    path_buf[..path_len].copy_from_slice(opts.new_backing_path);

    let mut plan = RebasePlan::new(opts.overlay_file_size);
    let (new_backing_file_offset, new_backing_file_size) =
        compute_path_target(opts, parsed, path_len)?;

    if new_backing_file_size > 0 {
        let path_patch_bytes: &'a [u8] = &path_buf[..path_len];
        plan.push(RebasePatch::Write {
            byte_offset: new_backing_file_offset,
            bytes: path_patch_bytes,
        })?;
    }

    header_rewrite_buf[0..8].copy_from_slice(&new_backing_file_offset.to_be_bytes());
    header_rewrite_buf[8..12].copy_from_slice(&new_backing_file_size.to_be_bytes());
    let header_patch_bytes: &'a [u8] = header_rewrite_buf;
    plan.push(RebasePatch::Write {
        byte_offset: BACKING_FILE_OFFSET_OFFSET as u64,
        bytes: header_patch_bytes,
    })?;

    Ok(Qcow2RebaseOutput::Unsafe { plan })
}

/// Decide where the new backing path lives in the overlay
/// and what `backing_file_size` the header should carry.
///
/// Returns `(new_backing_file_offset, new_backing_file_size)`.
///
/// v1 supports two cases: detach (zero pointer + zero size)
/// and in-place rewrite (the new path fits in the existing
/// slot and the existing slot is non-empty). The long-path
/// relocation case — where the new path exceeds the existing
/// `backing_file_size` and the planner allocates a fresh
/// cluster — is tracked as follow-up work because it needs
/// the allocator's refcount-block staging path wired
/// through to both modes. v1 rejects with
/// `BackingPathTooLong` for now.
fn compute_path_target(
    opts: &Qcow2RebaseOpts<'_>,
    parsed: &QcowHeader,
    path_len: usize,
) -> Result<(u64, u32), RebaseError> {
    if opts.detach {
        return Ok((0u64, 0u32));
    }
    if (path_len as u32) > parsed.backing_file_size {
        // Even a slightly-longer path needs relocation.
        return Err(RebaseError::BackingPathTooLong);
    }
    if parsed.backing_file_offset == 0 {
        // Original overlay had no backing reference; no
        // slot to write into. Adding one requires
        // relocation; deferred.
        return Err(RebaseError::BackingPathTooLong);
    }
    Ok((parsed.backing_file_offset, path_len as u32))
}

// ---------------------------------------------------------------------------
// Allocator (16-bit refcount, v1)
// ---------------------------------------------------------------------------

/// Allocate a single fresh cluster in the overlay.
///
/// Pure function: scans the staged refcount-block bytes in
/// `context.refblocks` starting from `state.next_refblock` /
/// `state.next_entry_in_refblock`, finds the next entry
/// whose refcount is zero, bumps it to one, marks the
/// containing refblock dirty, and returns the host byte
/// offset of the claimed cluster.
///
/// v1 supports `context.refcount_bits == 16` only. Returns
/// [`RebaseError::UnsupportedFormat`] for other widths and
/// [`RebaseError::RefcountExhausted`] when every existing
/// block is full.
///
/// The host byte offset is computed as
/// `(refblock_index * entries_per_refblock + entry_index) *
/// cluster_size`. The caller (the guest) is responsible for
/// also threading a per-allocation refblock-index hint
/// through to its flush-dirty pass once the rebase loop
/// completes.
pub fn allocate_overlay_cluster_qcow2(
    context: &mut RebaseQcow2SafeContext<'_>,
    state: &mut AllocationState,
) -> Result<u64, RebaseError> {
    if context.refcount_bits != 16 {
        return Err(RebaseError::UnsupportedFormat);
    }
    let cluster_size = context.overlay_cluster_size as u64;
    let entries_per_refblock = context.entries_per_refblock;
    let bytes_per_refblock = cluster_size as usize;

    while state.next_refblock < context.refblock_count {
        let refblock_idx = state.next_refblock as usize;
        let refblock_byte_offset = refblock_idx
            .checked_mul(bytes_per_refblock)
            .ok_or(RebaseError::Overflow)?;
        let refblock = context
            .refblocks
            .get_mut(refblock_byte_offset..refblock_byte_offset + bytes_per_refblock)
            .ok_or(RebaseError::OverlayCorrupt)?;

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
                if let Some(b) = context.dirty.get_mut(dirty_byte) {
                    *b |= 1u8 << dirty_bit;
                }

                let cluster_index = (state.next_refblock as u64)
                    .checked_mul(entries_per_refblock)
                    .and_then(|v| v.checked_add(state.next_entry_in_refblock))
                    .ok_or(RebaseError::Overflow)?;
                let host_offset = cluster_index
                    .checked_mul(cluster_size)
                    .ok_or(RebaseError::Overflow)?;

                // Advance state past the just-claimed entry
                // so the next call doesn't re-scan it.
                state.next_entry_in_refblock += 1;
                state.allocated += 1;
                return Ok(host_offset);
            }
            state.next_entry_in_refblock += 1;
        }

        // Exhausted this refblock; move to the next.
        state.next_refblock += 1;
        state.next_entry_in_refblock = 0;
    }

    Err(RebaseError::RefcountExhausted)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal v3 qcow2 header buffer for tests.
    /// `cluster_bits = 16` (64 KB clusters), `refcount_bits =
    /// 16`, `virtual_size`, `backing_file_offset`,
    /// `backing_file_size` configurable.
    fn make_header(
        virtual_size: u64,
        backing_file_offset: u64,
        backing_file_size: u32,
    ) -> [u8; 4096] {
        let mut h = [0u8; 4096];
        // magic "QFI\xfb"
        h[0..4].copy_from_slice(&qcow2::QCOW2_MAGIC.to_be_bytes());
        // version = 3
        h[4..8].copy_from_slice(&3u32.to_be_bytes());
        // backing_file_offset @ 8
        h[8..16].copy_from_slice(&backing_file_offset.to_be_bytes());
        // backing_file_size @ 16
        h[16..20].copy_from_slice(&backing_file_size.to_be_bytes());
        // cluster_bits @ 20 = 16
        h[20..24].copy_from_slice(&16u32.to_be_bytes());
        // virtual size @ 24
        h[24..32].copy_from_slice(&virtual_size.to_be_bytes());
        // l1_size @ 36 = 1
        h[36..40].copy_from_slice(&1u32.to_be_bytes());
        // l1_table_offset @ 40 = cluster 2
        h[40..48].copy_from_slice(&(2u64 * 65536).to_be_bytes());
        // refcount_table_offset @ 48 = cluster 1
        h[48..56].copy_from_slice(&65536u64.to_be_bytes());
        // refcount_table_clusters @ 56 = 1
        h[56..60].copy_from_slice(&1u32.to_be_bytes());
        // refcount_order @ 96 = 4 (i.e. 16-bit)
        h[96..100].copy_from_slice(&4u32.to_be_bytes());
        // header_length @ 100 = 104
        h[100..104].copy_from_slice(&104u32.to_be_bytes());
        h
    }

    #[test]
    fn rejects_external_data_file() {
        let mut h = make_header(1 << 20, 65536, 16);
        // INCOMPAT_EXTERNAL_DATA at offset 72
        h[72..80].copy_from_slice(&INCOMPAT_EXTERNAL_DATA.to_be_bytes());

        let mut scratch = [0u8; 65536];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Safe,
            overlay_header: &h,
            overlay_file_size: 1 << 20,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: 1 << 20,
            new_backing_path: b"/tmp/new.qcow2",
            detach: false,
        };
        let r = plan_rebase_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::ExternalDataFile));
    }

    #[test]
    fn rejects_encrypted() {
        let mut h = make_header(1 << 20, 65536, 16);
        // crypt_method @ 32 = 1 (AES)
        h[32..36].copy_from_slice(&1u32.to_be_bytes());
        let mut scratch = [0u8; 65536];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Safe,
            overlay_header: &h,
            overlay_file_size: 1 << 20,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: 1 << 20,
            new_backing_path: b"/tmp/new.qcow2",
            detach: false,
        };
        let r = plan_rebase_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::LuksUnsupported));
    }

    #[test]
    fn rejects_backing_smaller_than_overlay() {
        let h = make_header(2 << 20, 65536, 16);
        let mut scratch = [0u8; 65536];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Safe,
            overlay_header: &h,
            overlay_file_size: 2 << 20,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: 1 << 20, // smaller
            new_backing_path: b"/tmp/new.qcow2",
            detach: false,
        };
        let r = plan_rebase_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::NewBackingIncompatible));
    }

    #[test]
    fn rejects_oversized_path() {
        let h = make_header(1 << 20, 65536, 16);
        let mut scratch = [0u8; 65536];
        let too_long = [b'x'; MAX_BACKING_PATH_LEN + 1];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Safe,
            overlay_header: &h,
            overlay_file_size: 1 << 20,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: 1 << 20,
            new_backing_path: &too_long,
            detach: false,
        };
        let r = plan_rebase_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::BackingPathTooLong));
    }

    #[test]
    fn safe_mode_plan_emits_in_place_rewrite() {
        // Existing backing slot at offset 65536, size 32
        // bytes. New path is 14 bytes; fits.
        let h = make_header(1 << 20, 65536, 32);
        let mut scratch = [0u8; 65536 * 4];
        let one_block_of_refcounts = [0u8; 65536];
        let offsets = [65536u64];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Safe,
            overlay_header: &h,
            overlay_file_size: 1 << 20,
            refcount_table: &[],
            refblock_host_offsets: &offsets,
            refcount_blocks: &one_block_of_refcounts,
            refblock_count: 1,
            new_backing_virtual_size: 1 << 20,
            new_backing_path: b"/tmp/new.qcow2", // 14 bytes
            detach: false,
        };
        let out = plan_rebase_qcow2(&opts, &mut scratch).expect("plan succeeds");
        match out {
            Qcow2RebaseOutput::Safe {
                context,
                deferred_metadata,
            } => {
                assert_eq!(context.overlay_cluster_size, 65536);
                assert_eq!(context.refcount_bits, 16);
                assert_eq!(context.refblock_count, 1);
                let patches = deferred_metadata.patches();
                assert_eq!(patches.len(), 2);
                // First patch: path bytes at the old offset.
                match patches[0] {
                    RebasePatch::Write { byte_offset, bytes } => {
                        assert_eq!(byte_offset, 65536);
                        assert_eq!(bytes, b"/tmp/new.qcow2");
                    }
                    _ => panic!("expected Write for path"),
                }
                // Second patch: header rewrite at offset 8.
                match patches[1] {
                    RebasePatch::Write { byte_offset, bytes } => {
                        assert_eq!(byte_offset, BACKING_FILE_OFFSET_OFFSET as u64);
                        assert_eq!(bytes.len(), 12);
                        let bo = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
                        let bs = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
                        assert_eq!(bo, 65536);
                        assert_eq!(bs, 14);
                    }
                    _ => panic!("expected Write for header"),
                }
            }
            Qcow2RebaseOutput::Unsafe { .. } => panic!("expected Safe variant"),
        }
    }

    #[test]
    fn safe_mode_detach_writes_zero_pointer() {
        let h = make_header(1 << 20, 65536, 32);
        let mut scratch = [0u8; 65536 * 4];
        let one_block_of_refcounts = [0u8; 65536];
        let offsets = [65536u64];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Safe,
            overlay_header: &h,
            overlay_file_size: 1 << 20,
            refcount_table: &[],
            refblock_host_offsets: &offsets,
            refcount_blocks: &one_block_of_refcounts,
            refblock_count: 1,
            new_backing_virtual_size: 0,
            new_backing_path: b"",
            detach: true,
        };
        let out = plan_rebase_qcow2(&opts, &mut scratch).expect("plan succeeds");
        match out {
            Qcow2RebaseOutput::Safe {
                deferred_metadata, ..
            } => {
                let patches = deferred_metadata.patches();
                assert_eq!(patches.len(), 1);
                match patches[0] {
                    RebasePatch::Write { byte_offset, bytes } => {
                        assert_eq!(byte_offset, BACKING_FILE_OFFSET_OFFSET as u64);
                        let bo = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
                        let bs = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
                        assert_eq!(bo, 0);
                        assert_eq!(bs, 0);
                    }
                    _ => panic!("expected Write for detach"),
                }
            }
            _ => panic!("expected Safe variant"),
        }
    }

    #[test]
    fn allocator_claims_first_free_cluster() {
        // One 64 KB refblock = 32768 16-bit entries. Mark
        // entries 0..3 as already-allocated (rc=1); the
        // allocator should claim entry 3.
        let mut refblocks = [0u8; 65536];
        let one = 1u16.to_be_bytes();
        refblocks[0..2].copy_from_slice(&one);
        refblocks[2..4].copy_from_slice(&one);
        refblocks[4..6].copy_from_slice(&one);
        let mut dirty = [0u8; 1];
        let mut context = RebaseQcow2SafeContext {
            overlay_cluster_size: 65536,
            overlay_cluster_count: 32768,
            overlay_l1_table_offset: 0,
            overlay_l1_size: 0,
            refcount_bits: 16,
            entries_per_refblock: 32768,
            refblock_count: 1,
            refblocks: &mut refblocks,
            dirty: &mut dirty,
        };
        let mut state = AllocationState::default();
        let off = allocate_overlay_cluster_qcow2(&mut context, &mut state).expect("ok");
        // Cluster 3 -> offset 3 * 65536 = 196608.
        assert_eq!(off, 3 * 65536);
        assert_eq!(state.allocated, 1);
        // The just-claimed entry now has rc=1.
        let raw = u16::from_be_bytes([context.refblocks[6], context.refblocks[7]]);
        assert_eq!(raw, 1);
        // Dirty bit 0 is set.
        assert_eq!(context.dirty[0] & 1, 1);
    }

    #[test]
    fn allocator_advances_across_calls() {
        let mut refblocks = [0u8; 65536];
        let mut dirty = [0u8; 1];
        let mut context = RebaseQcow2SafeContext {
            overlay_cluster_size: 65536,
            overlay_cluster_count: 32768,
            overlay_l1_table_offset: 0,
            overlay_l1_size: 0,
            refcount_bits: 16,
            entries_per_refblock: 32768,
            refblock_count: 1,
            refblocks: &mut refblocks,
            dirty: &mut dirty,
        };
        let mut state = AllocationState::default();
        let a = allocate_overlay_cluster_qcow2(&mut context, &mut state).unwrap();
        let b = allocate_overlay_cluster_qcow2(&mut context, &mut state).unwrap();
        let c = allocate_overlay_cluster_qcow2(&mut context, &mut state).unwrap();
        assert_eq!(a, 0);
        assert_eq!(b, 65536);
        assert_eq!(c, 2 * 65536);
        assert_eq!(state.allocated, 3);
    }

    #[test]
    fn allocator_returns_exhausted_when_full() {
        // 4-entry "refblock" — small enough to fill in test.
        let mut refblocks = [0u8; 8]; // 4 × 16-bit entries
        for chunk in refblocks.chunks_mut(2) {
            chunk.copy_from_slice(&1u16.to_be_bytes());
        }
        let mut dirty = [0u8; 1];
        let mut context = RebaseQcow2SafeContext {
            overlay_cluster_size: 8, // tiny "cluster" for the test
            overlay_cluster_count: 4,
            overlay_l1_table_offset: 0,
            overlay_l1_size: 0,
            refcount_bits: 16,
            entries_per_refblock: 4,
            refblock_count: 1,
            refblocks: &mut refblocks,
            dirty: &mut dirty,
        };
        let mut state = AllocationState::default();
        let r = allocate_overlay_cluster_qcow2(&mut context, &mut state);
        assert_eq!(r.err(), Some(RebaseError::RefcountExhausted));
    }

    #[test]
    fn unsafe_mode_plan_emits_in_place_rewrite() {
        // Same scenario as the safe-mode test but with
        // mode=Unsafe. The result should be a plan with the
        // same two patches (path bytes, then header field
        // rewrite) and no context.
        let h = make_header(1 << 20, 65536, 32);
        let mut scratch = [0u8; 65536 * 4];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Unsafe,
            overlay_header: &h,
            overlay_file_size: 1 << 20,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: 1 << 20,
            new_backing_path: b"/tmp/new.qcow2",
            detach: false,
        };
        let out = plan_rebase_qcow2(&opts, &mut scratch).expect("plan succeeds");
        match out {
            Qcow2RebaseOutput::Unsafe { plan } => {
                let patches = plan.patches();
                assert_eq!(patches.len(), 2);
                match patches[0] {
                    RebasePatch::Write { byte_offset, bytes } => {
                        assert_eq!(byte_offset, 65536);
                        assert_eq!(bytes, b"/tmp/new.qcow2");
                    }
                    _ => panic!("expected Write for path"),
                }
                match patches[1] {
                    RebasePatch::Write { byte_offset, bytes } => {
                        assert_eq!(byte_offset, BACKING_FILE_OFFSET_OFFSET as u64);
                        let bs = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
                        assert_eq!(bs, 14);
                    }
                    _ => panic!("expected Write for header"),
                }
            }
            _ => panic!("expected Unsafe variant"),
        }
    }

    #[test]
    fn unsafe_mode_detach() {
        let h = make_header(1 << 20, 65536, 32);
        let mut scratch = [0u8; 65536 * 4];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Unsafe,
            overlay_header: &h,
            overlay_file_size: 1 << 20,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: 0,
            new_backing_path: b"",
            detach: true,
        };
        let out = plan_rebase_qcow2(&opts, &mut scratch).expect("plan succeeds");
        match out {
            Qcow2RebaseOutput::Unsafe { plan } => {
                let patches = plan.patches();
                assert_eq!(patches.len(), 1);
                match patches[0] {
                    RebasePatch::Write { byte_offset, bytes } => {
                        assert_eq!(byte_offset, BACKING_FILE_OFFSET_OFFSET as u64);
                        let bo = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
                        let bs = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
                        assert_eq!(bo, 0);
                        assert_eq!(bs, 0);
                    }
                    _ => panic!("expected Write for detach"),
                }
            }
            _ => panic!("expected Unsafe variant"),
        }
    }

    #[test]
    fn unsafe_mode_rejects_long_path() {
        let h = make_header(1 << 20, 65536, 4); // tiny slot
        let mut scratch = [0u8; 65536 * 4];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Unsafe,
            overlay_header: &h,
            overlay_file_size: 1 << 20,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: 1 << 20,
            new_backing_path: b"/tmp/new.qcow2", // 14 bytes > 4
            detach: false,
        };
        let r = plan_rebase_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::BackingPathTooLong));
    }

    #[test]
    fn allocator_rejects_non_16bit_widths() {
        let mut refblocks = [0u8; 64];
        let mut dirty = [0u8; 1];
        let mut context = RebaseQcow2SafeContext {
            overlay_cluster_size: 64,
            overlay_cluster_count: 1,
            overlay_l1_table_offset: 0,
            overlay_l1_size: 0,
            refcount_bits: 32,
            entries_per_refblock: 16,
            refblock_count: 1,
            refblocks: &mut refblocks,
            dirty: &mut dirty,
        };
        let mut state = AllocationState::default();
        let r = allocate_overlay_cluster_qcow2(&mut context, &mut state);
        assert_eq!(r.err(), Some(RebaseError::UnsupportedFormat));
    }
}
