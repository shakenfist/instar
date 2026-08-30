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
//!   emits a [`RebaseQcow2SafeContext`] (overlay geometry the
//!   guest threads through the per-cluster comparison loop)
//!   plus a deferred-apply [`RebasePlan`] of metadata patches
//!   the guest applies after the comparison loop completes.
//!
//! Phase 5 of `PLAN-qcow2-write-infrastructure` moved the
//! safe-mode write composition (cluster allocation, refblock
//! staging, dirty tracking) into `crates/qcow2-write` +
//! `crates/qcow2-write-exec`; the old
//! `allocate_overlay_cluster_qcow2` helper, its
//! `AllocationState`, and the context's staged refblock copy
//! and dirty bitmap are gone. What remains here is the shared
//! validation, the deferred header/backing-path metadata plan,
//! and the overlay geometry.
//!
//! Refcount-width coverage in v1: only `refcount_bits == 16`
//! (qemu-img's default). Other widths return
//! [`RebaseError::UnsupportedFormat`].

use qcow2::{
    QcowHeader, BACKING_FILE_OFFSET_OFFSET, BACKING_FILE_SIZE_OFFSET, INCOMPAT_CORRUPT,
    INCOMPAT_DIRTY, INCOMPAT_EXTERNAL_DATA, QCOW2_HEADER_LENGTH_V3, V2_HEADER_EXTENSION_OFFSET,
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
    /// pointing at refcount blocks). Retained for API
    /// stability; unconsumed since phase 5 of
    /// `PLAN-qcow2-write-infrastructure` moved safe-mode
    /// allocation into `crates/qcow2-write`. Pass an empty
    /// slice.
    pub refcount_table: &'a [u8],
    /// Host byte offsets of each refcount block. Retained for
    /// API stability; unconsumed since phase 5. Pass an empty
    /// slice.
    pub refblock_host_offsets: &'a [u64],
    /// Concatenated refcount-block bytes. Retained for API
    /// stability; unconsumed since phase 5. Pass an empty
    /// slice.
    pub refcount_blocks: &'a [u8],
    /// Number of refcount blocks present in
    /// `refcount_blocks`. Retained for API stability;
    /// unconsumed since phase 5. Pass zero.
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
/// `Safe` carries the overlay geometry the guest drives at
/// runtime plus a deferred-apply metadata plan to commit after
/// the comparison loop completes.
///
/// The size asymmetry between the two variants is suppressed
/// with `allow(large_enum_variant)` to keep the inline plan
/// storage.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Qcow2RebaseOutput<'a> {
    /// Unsafe-mode (`-u`) output.
    Unsafe { plan: RebasePlan<'a> },
    /// Safe-mode output.
    Safe {
        context: RebaseQcow2SafeContext,
        deferred_metadata: RebasePlan<'a>,
    },
}

/// Overlay geometry carried by the guest across safe-mode
/// rebase's per-cluster comparison loop.
///
/// Phase 5 of `PLAN-qcow2-write-infrastructure` reduced this
/// to plain geometry: the staged refcount-block copy and the
/// dirty bitmap the old in-crate allocator mutated moved into
/// `qcow2_write::WriteState` and the guest's own staging
/// carve.
#[derive(Debug, Clone, Copy)]
pub struct RebaseQcow2SafeContext {
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

    // Both modes rewrite the header's backing-file pointer at
    // bytes 8..20, so an overlay too short to hold the fixed
    // header has no slot for that patch either.
    if opts.overlay_file_size < (BACKING_FILE_SIZE_OFFSET + 4) as u64 {
        return Err(RebaseError::OverlayCorrupt);
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

    // Lay out scratch: header rewrite buffer, path buffer.
    // (The staged refcount-block copy and dirty bitmap the
    // old in-crate allocator carved here moved into the
    // guest's qcow2-write staging in phase 5.)
    let header_rewrite_len = 12usize; // backing_file_offset u64 + backing_file_size u32
    let path_buf_len = MAX_BACKING_PATH_LEN;
    let need = header_rewrite_len
        .checked_add(path_buf_len)
        .ok_or(RebaseError::Overflow)?;
    if scratch.len() < need {
        return Err(RebaseError::ScratchTooSmall);
    }

    let (header_rewrite_buf, rest) = scratch.split_at_mut(header_rewrite_len);
    let (path_buf, _rest) = rest.split_at_mut(path_buf_len);

    // Populate the path buffer (left-padded with zero bytes
    // beyond `path_len`; the patch references only the first
    // `path_len` bytes).
    let path_len = opts.new_backing_path.len();
    path_buf[..path_len].copy_from_slice(opts.new_backing_path);

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
///
/// The in-place case additionally requires the existing slot
/// to be a region the overlay actually has: inside the file
/// and clear of the fixed header. A header describing anything
/// else is rejected with `HeaderMismatch`.
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

    // `backing_file_offset` and `backing_file_size` are raw
    // header fields and `QcowHeader::parse` range-checks
    // neither. The slot they describe is only writable if it is
    // a real region of the overlay that starts after the fixed
    // header — the plan rewrites bytes 8..20 itself, and path
    // bytes landing anywhere in the header would corrupt the
    // image. An overlay claiming an offset past EOF otherwise
    // makes the planner emit a Write patch outside the file
    // (issue #485).
    let header_end = if parsed.version >= 3 {
        QCOW2_HEADER_LENGTH_V3 as u64
    } else {
        V2_HEADER_EXTENSION_OFFSET as u64
    };
    let slot_end = parsed
        .backing_file_offset
        .checked_add(u64::from(parsed.backing_file_size))
        .ok_or(RebaseError::HeaderMismatch)?;
    if parsed.backing_file_offset < header_end || slot_end > opts.overlay_file_size {
        return Err(RebaseError::HeaderMismatch);
    }

    Ok((parsed.backing_file_offset, path_len as u32))
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
                assert_eq!(context.overlay_cluster_count, (1 << 20) / 65536);
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

    /// Regression for issue #485: a fuzzed overlay header
    /// whose `backing_file_offset` points far beyond EOF made
    /// the planner emit a Write patch outside the file.
    #[test]
    fn rejects_backing_slot_past_eof() {
        // Offset from the crash: 70267192421360547, with a
        // 256-byte declared slot and an 8 MiB overlay.
        let h = make_header(1 << 20, 70_267_192_421_360_547, 256);
        let mut scratch = [0u8; 65536 * 4];
        let path = [b'x'; 256];
        for mode in [RebaseMode::Unsafe, RebaseMode::Safe] {
            let opts = Qcow2RebaseOpts {
                mode,
                overlay_header: &h,
                overlay_file_size: 8 * 1024 * 1024,
                refcount_table: &[],
                refblock_host_offsets: &[],
                refcount_blocks: &[],
                refblock_count: 0,
                new_backing_virtual_size: 1 << 20,
                new_backing_path: &path,
                detach: false,
            };
            let r = plan_rebase_qcow2(&opts, &mut scratch);
            assert_eq!(r.err(), Some(RebaseError::HeaderMismatch));
        }
    }

    /// A slot whose end overflows u64 is a corrupt header, not
    /// an arithmetic surprise.
    #[test]
    fn rejects_backing_slot_offset_overflow() {
        let h = make_header(1 << 20, u64::MAX - 4, 16);
        let mut scratch = [0u8; 65536 * 4];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Unsafe,
            overlay_header: &h,
            overlay_file_size: 8 * 1024 * 1024,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: 1 << 20,
            new_backing_path: b"/tmp/new.qcow2",
            detach: false,
        };
        let r = plan_rebase_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::HeaderMismatch));
    }

    /// A slot inside the fixed header would have the path
    /// bytes clobber the header — including the very fields
    /// the plan's second patch rewrites.
    #[test]
    fn rejects_backing_slot_inside_header() {
        let h = make_header(1 << 20, 8, 64);
        let mut scratch = [0u8; 65536 * 4];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Unsafe,
            overlay_header: &h,
            overlay_file_size: 8 * 1024 * 1024,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: 1 << 20,
            new_backing_path: b"/tmp/new.qcow2",
            detach: false,
        };
        let r = plan_rebase_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::HeaderMismatch));
    }

    /// An overlay shorter than the fixed header cannot hold
    /// the backing-pointer rewrite either.
    #[test]
    fn rejects_overlay_shorter_than_header_fields() {
        let h = make_header(1 << 20, 65536, 32);
        let mut scratch = [0u8; 65536 * 4];
        let opts = Qcow2RebaseOpts {
            mode: RebaseMode::Unsafe,
            overlay_header: &h,
            overlay_file_size: 16,
            refcount_table: &[],
            refblock_host_offsets: &[],
            refcount_blocks: &[],
            refblock_count: 0,
            new_backing_virtual_size: 1 << 20,
            new_backing_path: b"/tmp/new.qcow2",
            detach: false,
        };
        let r = plan_rebase_qcow2(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::OverlayCorrupt));
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
}
