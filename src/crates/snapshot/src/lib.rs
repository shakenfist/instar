//! Pure planner crate for qcow2 snapshot mutator primitives.
//!
//! This crate is the per-operation home for the byte-level
//! mutators that the snapshot create / delete / apply guest
//! binaries (phases 6-8) compose into per-mode patch lists.
//! It is parallel to `commit` and `rebase`: pure functions over
//! caller-staged slices, no I/O, no allocator.
//!
//! The crate's eight public functions live in [`qcow2`]:
//!
//! - [`qcow2::read_refcount_in_block`] / [`qcow2::set_refcount_in_block`]
//!   — scalar refcount accessors for every supported width.
//! - [`qcow2::check_refcount_after_addend`] — overflow-safe
//!   arithmetic check used by the two-pass refcount mutator.
//! - [`qcow2::alloc_cluster_in_refblocks`] — cursor-driven linear
//!   scan over staged refcount blocks; claims the first zero
//!   entry and returns the host byte offset of the new cluster.
//! - [`qcow2::rewrite_l1_entry_copied_flag`] /
//!   [`qcow2::rewrite_l2_entry_copied_flag`] — flip
//!   `OFLAG_COPIED` on L1 / L2 entries (standard or extended-L2).
//! - [`qcow2::for_each_cluster_in_l1`] — visitor that walks the
//!   L1 -> L2 chain, classifying each allocated cluster.
//! - [`qcow2::update_snapshot_refcount`] — two-pass refcount
//!   mutator (dry-run reads only, apply pass mutates).
//! - [`qcow2::update_copied_flags_for_l1`] — rewrites COPIED
//!   flags on L1 and L2 entries based on current refcount.
//!
//! The crate is `no_std` and performs no I/O. Mutators operate
//! on slices in place; [`SnapshotPatch`] / [`SnapshotPlan`] exist
//! so phases 6-8 can emit patches from real planners without an
//! ABI break.

#![no_std]
#![allow(clippy::too_many_arguments)]

pub mod qcow2;
pub mod table;

use shared::SnapshotResult;

/// Errors returned by the snapshot mutator primitives.
///
/// The first 13 variants map 1:1 to the [`SnapshotResult::ERROR_*`]
/// wire codes from phase 1; the trailing two variants
/// ([`Self::MisalignedAccess`] and [`Self::Unsupported`]) are
/// planner-internal misuse codes that the phase 6-8 guest
/// binaries translate to the closest matching wire code via
/// the [`From<SnapshotError> for u32`] impl below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    /// The image is not a qcow2 v2 / v3. Maps to
    /// [`SnapshotResult::ERROR_UNSUPPORTED_FORMAT`] (1).
    UnsupportedFormat,
    /// The format is supported but a sub-feature isn't (e.g.
    /// external-data-file, LUKS). Maps to
    /// [`SnapshotResult::ERROR_UNSUPPORTED_FEATURE`] (2).
    UnsupportedFeature,
    /// The named snapshot was not found. Maps to
    /// [`SnapshotResult::ERROR_NOT_FOUND`] (3).
    NotFound,
    /// A snapshot with the same name already exists. Maps to
    /// [`SnapshotResult::ERROR_DUPLICATE_NAME`] (4).
    DuplicateName,
    /// A refcount entry would overflow the configured width.
    /// `at_host_offset` carries the host byte offset of the
    /// cluster whose refcount was about to overflow, so the
    /// caller can report it. Maps to
    /// [`SnapshotResult::ERROR_REFCOUNT_OVERFLOW`] (5).
    RefcountOverflow {
        /// Host byte offset of the cluster whose refcount
        /// would have overflowed.
        at_host_offset: u64,
    },
    /// The allocator could not find a free cluster. Maps to
    /// [`SnapshotResult::ERROR_ALLOCATION_FAILED`] (6).
    AllocationFailed,
    /// Every existing refcount block is full and v1 does not
    /// grow the refcount table. Maps to
    /// [`SnapshotResult::ERROR_ALLOCATION_FAILED`] (6) on the
    /// wire — only the planner distinguishes the cause.
    RefcountExhausted,
    /// The snapshot table is at its bounded capacity. Maps to
    /// [`SnapshotResult::ERROR_SNAPSHOT_TABLE_FULL`] (7).
    SnapshotTableFull,
    /// Generic I/O failure surfaced by upper layers. Maps to
    /// [`SnapshotResult::ERROR_IO`] (8).
    Io,
    /// The snapshot's L1 size disagrees with the active L1's
    /// size. Maps to
    /// [`SnapshotResult::ERROR_L1_SIZE_MISMATCH`] (9).
    L1SizeMismatch,
    /// A snapshot's name or id failed UTF-8 decoding. Maps to
    /// [`SnapshotResult::ERROR_INVALID_UTF8`] (10).
    InvalidUtf8,
    /// Caller-supplied configuration was invalid. Maps to
    /// [`SnapshotResult::ERROR_INVALID_CONFIG`] (11).
    InvalidConfig,
    /// A format-specific parser failed. Maps to
    /// [`SnapshotResult::ERROR_PARSE_FAILED`] (12).
    ParseFailed,
    /// Caller passed an index out of range for the staged
    /// slice. Indicates a planner bug, not a wire condition;
    /// translated to [`SnapshotResult::ERROR_PARSE_FAILED`]
    /// (12) on the wire.
    MisalignedAccess,
    /// Caller asked for a refcount width or other feature this
    /// crate does not yet support (e.g. non-16-bit refcounts
    /// in [`qcow2::alloc_cluster_in_refblocks`]). Translated to
    /// [`SnapshotResult::ERROR_UNSUPPORTED_FEATURE`] (2) on the
    /// wire.
    Unsupported,
}

impl From<SnapshotError> for u32 {
    fn from(err: SnapshotError) -> u32 {
        match err {
            SnapshotError::UnsupportedFormat => SnapshotResult::ERROR_UNSUPPORTED_FORMAT,
            SnapshotError::UnsupportedFeature => SnapshotResult::ERROR_UNSUPPORTED_FEATURE,
            SnapshotError::NotFound => SnapshotResult::ERROR_NOT_FOUND,
            SnapshotError::DuplicateName => SnapshotResult::ERROR_DUPLICATE_NAME,
            SnapshotError::RefcountOverflow { .. } => SnapshotResult::ERROR_REFCOUNT_OVERFLOW,
            SnapshotError::AllocationFailed => SnapshotResult::ERROR_ALLOCATION_FAILED,
            SnapshotError::RefcountExhausted => SnapshotResult::ERROR_ALLOCATION_FAILED,
            SnapshotError::SnapshotTableFull => SnapshotResult::ERROR_SNAPSHOT_TABLE_FULL,
            SnapshotError::Io => SnapshotResult::ERROR_IO,
            SnapshotError::L1SizeMismatch => SnapshotResult::ERROR_L1_SIZE_MISMATCH,
            SnapshotError::InvalidUtf8 => SnapshotResult::ERROR_INVALID_UTF8,
            SnapshotError::InvalidConfig => SnapshotResult::ERROR_INVALID_CONFIG,
            SnapshotError::ParseFailed => SnapshotResult::ERROR_PARSE_FAILED,
            SnapshotError::MisalignedAccess => SnapshotResult::ERROR_PARSE_FAILED,
            SnapshotError::Unsupported => SnapshotResult::ERROR_UNSUPPORTED_FEATURE,
        }
    }
}

/// A single byte-level operation against the qcow2 file.
///
/// Snapshot v1 only emits [`SnapshotPatch::Write`]; an `Append`
/// variant is intentionally absent because the bounded
/// `MAX_SNAPSHOTS = 16` cap from phase 2 prevents the snapshot
/// table from spilling beyond its initial cluster.
#[derive(Debug, Clone, Copy)]
pub enum SnapshotPatch<'a> {
    /// Overwrite an existing byte range. The patch carries no
    /// indication of which file it targets; the guest knows
    /// based on which slot it pulls the patch from.
    Write {
        /// Absolute byte offset within the target file.
        byte_offset: u64,
        /// Bytes to write.
        bytes: &'a [u8],
    },
}

impl<'a> SnapshotPatch<'a> {
    /// Empty placeholder used as the default array element when
    /// building a [`SnapshotPlan`].
    pub const EMPTY: SnapshotPatch<'static> = SnapshotPatch::Write {
        byte_offset: 0,
        bytes: &[],
    };

    /// Byte offset where this patch starts in its target file.
    pub fn byte_offset(&self) -> u64 {
        match self {
            SnapshotPatch::Write { byte_offset, .. } => *byte_offset,
        }
    }

    /// Number of bytes this patch touches.
    pub fn len(&self) -> usize {
        match self {
            SnapshotPatch::Write { bytes, .. } => bytes.len(),
        }
    }

    /// True if the patch is a no-op (zero-length write).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Maximum number of patch entries a [`SnapshotPlan`] can hold.
///
/// 64 is conservative headroom for phases 6-8. A snapshot
/// create / delete / apply realistically tops out at ~30
/// patches: header rewrite, snapshot-table entry rewrite,
/// per-modified-refblock writeback, per-modified-L2 writeback,
/// new-L1 cluster allocation. The constant lives here so the
/// type surface is stable for phases 6-8.
pub const MAX_SNAPSHOT_PATCHES: usize = 64;

/// A bounded collection of [`SnapshotPatch`] entries.
///
/// Mirrors `CommitPlan` / `RebasePlan` in shape; phase 5 does
/// not emit patches (mutators operate in place) but the type
/// exists so the phases 6-8 planners can populate it without
/// an ABI break.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotPlan<'a> {
    /// File size the qcow2 image should end up at after applying
    /// every patch. Equals the pre-snapshot file size for v1 (no
    /// growth — open question 3 in phase plan).
    pub total_file_size: u64,
    /// Number of populated entries in `patches_storage`.
    patch_count: u16,
    /// Inline storage; only `..patch_count` is valid.
    patches_storage: [SnapshotPatch<'a>; MAX_SNAPSHOT_PATCHES],
}

impl<'a> SnapshotPlan<'a> {
    /// Construct an empty plan for the given target file size.
    pub const fn new(total_file_size: u64) -> Self {
        SnapshotPlan {
            total_file_size,
            patch_count: 0,
            patches_storage: [SnapshotPatch::EMPTY; MAX_SNAPSHOT_PATCHES],
        }
    }

    /// Ordered list of patches to apply.
    pub fn patches(&self) -> &[SnapshotPatch<'a>] {
        &self.patches_storage[..self.patch_count as usize]
    }

    /// Append a patch to the plan. Returns
    /// [`SnapshotError::SnapshotTableFull`] if the plan's
    /// storage is full.
    pub fn push(&mut self, patch: SnapshotPatch<'a>) -> Result<(), SnapshotError> {
        let idx = self.patch_count as usize;
        if idx >= MAX_SNAPSHOT_PATCHES {
            return Err(SnapshotError::SnapshotTableFull);
        }
        self.patches_storage[idx] = patch;
        self.patch_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_methods_match_variant() {
        let p = SnapshotPatch::Write {
            byte_offset: 0x2000,
            bytes: &[7, 8, 9],
        };
        assert_eq!(p.byte_offset(), 0x2000);
        assert_eq!(p.len(), 3);
        assert!(!p.is_empty());

        let empty = SnapshotPatch::EMPTY;
        assert!(empty.is_empty());
        assert_eq!(empty.byte_offset(), 0);
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn plan_push_respects_bound() {
        let mut plan = SnapshotPlan::new(4096);
        for i in 0..MAX_SNAPSHOT_PATCHES {
            let r = plan.push(SnapshotPatch::Write {
                byte_offset: i as u64,
                bytes: &[],
            });
            assert!(r.is_ok(), "push at i={i} must succeed within bound");
        }
        let overflow = plan.push(SnapshotPatch::EMPTY);
        assert_eq!(overflow, Err(SnapshotError::SnapshotTableFull));
        assert_eq!(plan.patches().len(), MAX_SNAPSHOT_PATCHES);
    }

    #[test]
    fn plan_new_starts_empty() {
        let plan = SnapshotPlan::new(8192);
        assert_eq!(plan.total_file_size, 8192);
        assert_eq!(plan.patches().len(), 0);
    }

    #[test]
    fn error_to_wire_code_mapping() {
        assert_eq!(u32::from(SnapshotError::UnsupportedFormat), 1);
        assert_eq!(u32::from(SnapshotError::UnsupportedFeature), 2);
        assert_eq!(u32::from(SnapshotError::NotFound), 3);
        assert_eq!(u32::from(SnapshotError::DuplicateName), 4);
        assert_eq!(
            u32::from(SnapshotError::RefcountOverflow { at_host_offset: 0 }),
            5
        );
        assert_eq!(u32::from(SnapshotError::AllocationFailed), 6);
        assert_eq!(u32::from(SnapshotError::RefcountExhausted), 6);
        assert_eq!(u32::from(SnapshotError::SnapshotTableFull), 7);
        assert_eq!(u32::from(SnapshotError::Io), 8);
        assert_eq!(u32::from(SnapshotError::L1SizeMismatch), 9);
        assert_eq!(u32::from(SnapshotError::InvalidUtf8), 10);
        assert_eq!(u32::from(SnapshotError::InvalidConfig), 11);
        assert_eq!(u32::from(SnapshotError::ParseFailed), 12);
        assert_eq!(u32::from(SnapshotError::MisalignedAccess), 12);
        assert_eq!(u32::from(SnapshotError::Unsupported), 2);
    }
}
