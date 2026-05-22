//! Plan in-place metadata mutations to resize disk images.
//!
//! Given the parsed header of an existing image and
//! `(new_virtual_size, options, preallocation)`, the
//! `plan_resize_*` functions in this crate return a [`ResizePlan`]
//! — an ordered, bounded sequence of [`ResizePatch`] operations
//! (in-place writes, file-extending appends, zero-fills) that
//! together implement the resize.
//!
//! This crate is `no_std` and performs no I/O. Scratch buffers
//! are caller-supplied; the returned [`ResizePlan`] borrows from
//! the scratch buffer.
//!
//! This phase ships scaffolding only: the type surface and
//! stubbed planners that return [`ResizeError::UnsupportedFormat`].
//! Later phases (2 = qcow2 grow, 3 = qcow2 shrink, 4 = vhd, 5 =
//! vhdx, 6 = vmdk) fill in the per-format implementations.

#![no_std]

mod qcow2;
mod vhd;
mod vhdx;

/// Errors returned by the `plan_resize_*` family of functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeError {
    /// New virtual size is zero, misaligned, or exceeds the
    /// format's maximum addressable range.
    InvalidNewVirtualSize,
    /// Caller asked to shrink but did not pass the equivalent of
    /// `qemu-img resize --shrink`.
    ShrinkWithoutFlag,
    /// Caller asked to shrink past data that is still allocated
    /// in the image (qcow2 shrink only; other formats reject
    /// shrink unconditionally with `UnsupportedShrink`).
    ShrinkBelowAllocated,
    /// The source format is not supported by this version of
    /// `instar resize` (QED, LUKS, encrypted qcow2, ...).
    UnsupportedFormat,
    /// The format is supported but the subformat isn't (multi-
    /// file VMDK, fixed VHDX, ...).
    UnsupportedSubformat,
    /// The format is supported but shrinking it isn't (vmdk /
    /// vhd / vhdx in v1). qemu-img-compatible: the corresponding
    /// `qemu-img resize` invocations fail too.
    UnsupportedShrink,
    /// An internal size computation overflowed.
    Overflow,
    /// The caller-supplied scratch buffer is too small for the
    /// requested layout.
    ScratchTooSmall,
    /// The requested preallocation mode isn't supported for the
    /// target format/subformat (e.g. `metadata` on vmdk).
    PreallocationUnsupported,
    /// The image is marked dirty or corrupt (qcow2's
    /// `INCOMPAT_DIRTY` / `INCOMPAT_CORRUPT` bits). Resize refuses
    /// to operate on it until the user runs `instar check` and
    /// resolves the inconsistency.
    RequiresCheckFirst,
    /// The opts the planner received describe a geometry that
    /// doesn't agree with what the host pre-populated in
    /// `ResizeConfig.current_virtual_size`. Either the file
    /// changed between the host's pre-probe and the guest's
    /// read, or a host bug. The guest surfaces this so the host
    /// can render a specific diagnostic.
    HeaderMismatch,
    /// A format-specific parser (`vhd::VhdFooter::parse`,
    /// `vhd::VhdDynamicHeader::parse`, etc.) failed to interpret
    /// the existing metadata the host staged into the opts.
    /// Indicates either a corrupted image or a host bug.
    ParseFailed,
}

/// What the resize will do to the file. Carried in [`ResizePlan`]
/// so the host can render the right success line and so the
/// post-pass `set_len` knows whether to grow or shrink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeAction {
    /// New virtual size > current virtual size.
    Grow,
    /// New virtual size < current virtual size.
    Shrink,
    /// New == current. The plan is empty; the host should print
    /// "Image resized." and exit zero, matching qemu-img's
    /// behaviour for a no-op resize.
    NoOp,
}

/// A single byte-level operation against the file being resized.
///
/// Patches are emitted by a planner and applied **in order** by
/// the guest. Ordering is load-bearing for crash safety on some
/// formats (qcow2's refcount-then-data-then-header sequence;
/// vhdx's two-header sequence-number dance). Planners must not
/// reorder patches; the guest must not reorder patches.
#[derive(Debug, Clone, Copy)]
pub enum ResizePatch<'a> {
    /// Overwrite an existing byte range. Used for header
    /// rewrites, footer copy updates, in-place L1/BAT entry
    /// updates, and refcount decrements.
    Write {
        /// Absolute byte offset within the file.
        byte_offset: u64,
        /// Bytes to write.
        bytes: &'a [u8],
    },
    /// Extend the file by writing new bytes starting at
    /// `byte_offset`. `byte_offset` must equal the file size at
    /// the moment the patch is applied — the guest cannot skip
    /// forward and leave a hole. Used for appending new L1
    /// regions, refcount blocks, BAT extensions, and new
    /// metadata regions.
    Append {
        /// Absolute byte offset within the file (== current EOF).
        byte_offset: u64,
        /// Bytes to write.
        bytes: &'a [u8],
    },
    /// Zero `len` bytes at `byte_offset`. Equivalent to `Write`
    /// with a zero buffer of size `len`, but lets the planner
    /// declare large zero regions without paying for the staging
    /// buffer. The guest implementation writes `ceil(len /
    /// sector_size)` zero sectors via `write_output_sector`.
    ZeroFill {
        /// Absolute byte offset within the file.
        byte_offset: u64,
        /// Number of zero bytes to write.
        len: u64,
    },
}

/// Maximum number of patch entries a [`ResizePlan`] can hold.
///
/// QCOW2 grow at small cluster sizes with a refcount-table
/// extension is the dominant case: a header rewrite plus an L1
/// append plus ~32 refcount-block appends plus old-L1 refcount
/// decrements plus new L1-table refcount increments. 128 is
/// conservative; phase 2 either confirms this is sufficient or
/// raises the bound.
pub const MAX_RESIZE_PATCHES: usize = 128;

/// A complete in-place mutation plan.
///
/// The plan stores its patches inline as a fixed-size array so
/// the whole value is `Copy` and the guest does not need to pass
/// a separate patches buffer alongside the byte scratch. Only
/// the first [`ResizePlan::patches`]`().len()` entries are
/// populated.
#[derive(Debug, Clone, Copy)]
pub struct ResizePlan<'a> {
    /// File size the host should `ftruncate` to after applying
    /// every patch. For `Shrink` this may be smaller than the
    /// pre-resize file size; for `Grow` larger; for `NoOp`
    /// unchanged from the pre-resize file size.
    pub total_file_size: u64,
    /// What this plan does at a high level.
    pub action: ResizeAction,
    /// Number of populated entries in `patches_storage`.
    patch_count: u16,
    /// Inline storage; only `..patch_count` is valid.
    patches_storage: [ResizePatch<'a>; MAX_RESIZE_PATCHES],
}

impl<'a> ResizePlan<'a> {
    /// Construct an empty plan for the given action and target
    /// file size. Push patches into it with [`Self::push`].
    pub const fn new(action: ResizeAction, total_file_size: u64) -> Self {
        ResizePlan {
            total_file_size,
            action,
            patch_count: 0,
            patches_storage: [ResizePatch::EMPTY; MAX_RESIZE_PATCHES],
        }
    }

    /// Ordered list of patches to apply.
    pub fn patches(&self) -> &[ResizePatch<'a>] {
        &self.patches_storage[..self.patch_count as usize]
    }

    /// Append a patch to the plan. Returns
    /// [`ResizeError::ScratchTooSmall`] if the plan's storage is
    /// full — this indicates either a planner bug or a format
    /// pathologically large in the way that motivated the
    /// [`MAX_RESIZE_PATCHES`] bound; if you hit it legitimately,
    /// raise the constant.
    pub fn push(&mut self, patch: ResizePatch<'a>) -> Result<(), ResizeError> {
        let idx = self.patch_count as usize;
        if idx >= MAX_RESIZE_PATCHES {
            return Err(ResizeError::ScratchTooSmall);
        }
        self.patches_storage[idx] = patch;
        self.patch_count += 1;
        Ok(())
    }
}

impl<'a> ResizePatch<'a> {
    /// Empty placeholder used as the default array element when
    /// building a [`ResizePlan`].
    pub const EMPTY: ResizePatch<'static> = ResizePatch::Write {
        byte_offset: 0,
        bytes: &[],
    };

    /// Byte offset where this patch starts in the file.
    pub fn byte_offset(&self) -> u64 {
        match self {
            ResizePatch::Write { byte_offset, .. }
            | ResizePatch::Append { byte_offset, .. }
            | ResizePatch::ZeroFill { byte_offset, .. } => *byte_offset,
        }
    }

    /// Length of the range covered by this patch, in bytes.
    pub fn len(&self) -> u64 {
        match self {
            ResizePatch::Write { bytes, .. } | ResizePatch::Append { bytes, .. } => {
                bytes.len() as u64
            }
            ResizePatch::ZeroFill { len, .. } => *len,
        }
    }

    /// True if this patch covers zero bytes. Trivial helper.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Preallocation mode for newly-added regions.
///
/// Layout numerically matches `shared::ResizeConfig::PREALLOC_*`
/// (and, for consistency, `shared::CreateConfig::PREALLOC_*`).
/// Forward-compat tripwire: phase 1d asserts the variant count
/// is exactly four.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Preallocation {
    /// Metadata only; the new region is sparse.
    Off = 0,
    /// Pre-populate format metadata (qcow2 L2 / vhdx BAT entries)
    /// pointing at zero clusters in the new region; the host
    /// does not extend the data region itself.
    Metadata = 1,
    /// Reserve disk blocks for the new region via
    /// `posix_fallocate` without writing.
    Falloc = 2,
    /// Reserve disk blocks for the new region and zero them.
    Full = 3,
}

/// VMDK subformat identifiers. Variants outside the v1 supported
/// set still appear in the enum so the host CLI can map qemu-
/// img's subformat string to a variant and emit
/// [`ResizeError::UnsupportedSubformat`] rather than treating it
/// as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmdkSubformat {
    MonolithicSparse,
    StreamOptimized,
    MonolithicFlat,
    TwoGbMaxExtentSparse,
    TwoGbMaxExtentFlat,
}

/// VHD subformat identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdSubformat {
    Dynamic,
    Fixed,
}

/// Options for [`plan_resize_raw`].
///
/// Raw has no metadata; the host's post-pass `set_len` does the
/// work. The planner only classifies the action and reports the
/// new file size.
#[derive(Debug, Clone, Copy)]
pub struct RawResizeOpts {
    /// Current virtual size in bytes (== current file size for
    /// raw).
    pub current_virtual_size: u64,
    /// Requested new virtual size in bytes.
    pub new_virtual_size: u64,
    /// Preallocation for the newly-added region (`Grow` only).
    /// Phase 1's planner does not consume this; phase 9's host-
    /// side preallocation pass reads it from the config.
    pub preallocation: Preallocation,
}

/// Options for [`plan_resize_qcow2`].
#[derive(Debug, Clone, Copy)]
pub struct Qcow2ResizeOpts<'a> {
    /// Current virtual size in bytes (from the existing header's
    /// `size` field).
    pub current_virtual_size: u64,
    /// Requested new virtual size in bytes.
    pub new_virtual_size: u64,
    /// Cluster size in bytes (from the existing header; the
    /// guest cross-checks against the parsed value).
    pub cluster_size: u32,
    /// Refcount entry width in bits (from the existing header).
    pub refcount_bits: u8,
    /// True if the existing image uses 16-byte extended L2
    /// entries.
    pub extended_l2: bool,
    /// Preallocation mode for the new range.
    pub preallocation: Preallocation,
    /// True iff the host CLI passed `--shrink`.
    pub allow_shrink: bool,
    /// Read-only view of the existing image's L1 table. The guest
    /// reads `current_l1_entries * 8` bytes starting at
    /// `current_l1_table_offset` into scratch before calling the
    /// planner; the planner copies these bytes verbatim into the
    /// new L1 region.
    pub existing_l1_bytes: &'a [u8],
    /// Read-only view of the existing image's refcount table.
    /// The guest reads `current_refcount_table_clusters *
    /// cluster_size` bytes starting at
    /// `current_refcount_table_offset` into scratch before calling
    /// the planner; the planner walks it to find the offsets of
    /// existing refcount blocks (so the new refcount table can
    /// preserve pointers to unchanged blocks).
    pub existing_refcount_table_bytes: &'a [u8],
    /// Read-only snapshot of the *existing* refcount blocks that
    /// the planner needs to patch (those that span the new L1
    /// region's first cluster, new refcount-block clusters, etc).
    /// The guest does a pre-pass to identify which blocks the
    /// planner will modify and stages only those here; if the
    /// planner needs a block that wasn't staged it returns
    /// [`ResizeError::ScratchTooSmall`].
    ///
    /// Storage is a flat concatenation of cluster-sized blocks in
    /// `existing_refcount_block_indices` order.
    pub existing_refcount_block_bytes: &'a [u8],
    /// The refcount-table indices of the blocks staged in
    /// `existing_refcount_block_bytes`, in the same order.
    /// `block i` lives in
    /// `&existing_refcount_block_bytes[i * cluster_size..(i + 1) *
    /// cluster_size]`.
    pub existing_refcount_block_indices: &'a [u64],
    /// Current file size in bytes (pre-resize EOF). The planner
    /// places appended regions at this offset.
    pub current_file_size: u64,
    /// Current `header.l1_size` (entries, not bytes).
    pub current_l1_entries: u32,
    /// Current `header.l1_table_offset`.
    pub current_l1_table_offset: u64,
    /// Current `header.refcount_table_offset`.
    pub current_refcount_table_offset: u64,
    /// Current `header.refcount_table_clusters`.
    pub current_refcount_table_clusters: u32,
    /// Current `header.incompatible_features`. The planner rejects
    /// `INCOMPAT_EXTERNAL_DATA` / `INCOMPAT_COMPRESSION` and any
    /// unknown bits with [`ResizeError::UnsupportedFormat`]; it
    /// rejects `INCOMPAT_DIRTY` / `INCOMPAT_CORRUPT` with
    /// [`ResizeError::RequiresCheckFirst`].
    pub current_incompatible_features: u64,
    /// Optional backing-file path bytes (from the existing
    /// header). Copied verbatim into the new header so the
    /// backing-file reference survives the rewrite.
    pub backing_file: Option<&'a [u8]>,
    /// Optional backing-format hint (from the existing header's
    /// EXT_BACKING_FORMAT extension).
    pub backing_format: Option<&'a [u8]>,
    /// Whether the existing header has the `lazy_refcounts`
    /// compatible feature bit set.
    pub lazy_refcounts: bool,
    /// Read-only snapshots of L2 tables the shrink planner
    /// needs to walk. The guest's pre-pass identifies which
    /// L2 tables cover virtual addresses in
    /// `[new_virtual_size, current_virtual_size)` and stages
    /// them here as a flat concatenation of cluster-sized
    /// blocks in `existing_l2_indices` order. If the planner
    /// needs an L2 table not present here it returns
    /// [`ResizeError::ScratchTooSmall`].
    pub existing_l2_bytes: &'a [u8],
    /// L1 indices of the L2 tables staged in
    /// `existing_l2_bytes`, in the same order. Table `i` lives
    /// in `&existing_l2_bytes[i * cluster_size..(i + 1) *
    /// cluster_size]`.
    pub existing_l2_indices: &'a [u32],
}

/// Options for [`plan_resize_vmdk`].
#[derive(Debug, Clone, Copy)]
pub struct VmdkResizeOpts {
    /// Current virtual size in bytes.
    pub current_virtual_size: u64,
    /// Requested new virtual size in bytes.
    pub new_virtual_size: u64,
    /// Grain size in bytes (from the existing header).
    pub grain_size: u32,
    /// Subformat of the existing image.
    pub subformat: VmdkSubformat,
    /// True iff the host CLI passed `--shrink`. v1 rejects vmdk
    /// shrink unconditionally with [`ResizeError::UnsupportedShrink`].
    pub allow_shrink: bool,
    /// Preallocation mode for the new range.
    pub preallocation: Preallocation,
}

/// Options for [`plan_resize_vhd`].
#[derive(Debug, Clone, Copy)]
pub struct VhdResizeOpts<'a> {
    /// Current virtual size in bytes.
    pub current_virtual_size: u64,
    /// Requested new virtual size in bytes.
    pub new_virtual_size: u64,
    /// Block size in bytes (from the existing dynamic header;
    /// unused for `Fixed`).
    pub block_size: u32,
    /// Subformat of the existing image.
    pub subformat: VhdSubformat,
    /// True iff the host CLI passed `--shrink`. v1 rejects vhd
    /// shrink unconditionally with [`ResizeError::UnsupportedShrink`].
    pub allow_shrink: bool,
    /// Preallocation mode for the new range.
    pub preallocation: Preallocation,
    /// Existing footer bytes (512). For dynamic VHDs this is
    /// the head footer at offset 0. The planner reads
    /// `disk_type`, `current_size`, and `uuid` from here so the
    /// rewritten footers preserve disk identity.
    pub existing_footer: &'a [u8],
    /// Existing dynamic header bytes (1024). Only meaningful
    /// for dynamic; `&[]` for fixed.
    pub existing_dynamic_header: &'a [u8],
    /// Existing BAT bytes (only meaningful for dynamic). The
    /// planner walks these to decide whether the new BAT fits
    /// in place or must be relocated.
    pub existing_bat: &'a [u8],
    /// Current file size in bytes (pre-resize EOF). The
    /// relocate path uses this to compute where the new BAT
    /// region lands.
    pub current_file_size: u64,
    /// Disk type from the existing footer
    /// (`DISK_TYPE_FIXED` / `DYNAMIC` / `DIFFERENCING`). The
    /// planner rejects differencing with
    /// [`ResizeError::UnsupportedSubformat`].
    pub disk_type: u32,
    /// Current dynamic header's `table_offset`. 0 for fixed.
    pub current_table_offset: u64,
    /// Current dynamic header's `max_table_entries`. 0 for
    /// fixed.
    pub current_max_table_entries: u32,
}

/// Options for [`plan_resize_vhdx`].
#[derive(Debug, Clone, Copy)]
pub struct VhdxResizeOpts<'a> {
    /// Current virtual size in bytes (from the
    /// `VirtualDiskSize` metadata entry).
    pub current_virtual_size: u64,
    /// Requested new virtual size in bytes.
    pub new_virtual_size: u64,
    /// Block size in bytes (from the `FileParameters` metadata
    /// entry).
    pub block_size: u32,
    /// Preallocation mode for the new range.
    pub preallocation: Preallocation,
    /// True iff the host CLI passed `--shrink`. VHDX shrink is
    /// rejected unconditionally with
    /// [`ResizeError::UnsupportedShrink`] (no qemu upstream
    /// implementation to mirror) but the flag is carried for
    /// host-side diagnostics.
    pub allow_shrink: bool,
    /// Existing bytes of the *active* header (4 KiB).  The
    /// guest's pre-pass selects whichever header has the
    /// higher `sequence_number` and stages it here.  Used to
    /// read `sequence_number` and `log_guid`.
    pub existing_active_header: &'a [u8],
    /// File offset of the active header: either `0x10000` or
    /// `0x20000`.  The planner writes the *other* header first
    /// with `sequence_number + 1` so it becomes active.
    pub current_active_header_offset: u64,
    /// Current `sequence_number` of the active header.
    pub current_sequence_number: u64,
    /// Existing region table bytes (64 KiB).  Either copy is
    /// fine — they're identical when consistent.
    pub existing_region_table: &'a [u8],
    /// Existing BAT bytes (`current_total_bat_entries * 8`).
    /// The planner walks these to preserve allocated-block
    /// references when relocating.
    pub existing_bat: &'a [u8],
    /// Current BAT region's file offset (from the region
    /// table).
    pub current_bat_offset: u64,
    /// Current BAT region's length in bytes (from the region
    /// table).
    pub current_bat_length: u32,
    /// Current `total_bat_entries` (computed by the parser at
    /// init time via `calculate_bat_layout`).
    pub current_total_bat_entries: u32,
    /// Current metadata region's file offset.
    pub current_metadata_offset: u64,
    /// Current metadata region's length (typically 1 MiB).
    pub current_metadata_length: u32,
    /// `logical_sector_size` from the existing metadata.
    pub logical_sector_size: u32,
    /// `physical_sector_size` from the existing metadata.
    pub physical_sector_size: u32,
    /// Whether the existing image has a parent (differencing
    /// disk).  Resize rejects differencing with
    /// [`ResizeError::UnsupportedSubformat`].
    pub has_parent: bool,
    /// Current file size in bytes (pre-resize EOF).  The
    /// relocate path appends a new BAT region here.
    pub current_file_size: u64,
}

// ============================================================================
// Worst-case scratch buffer sizes
// ============================================================================
//
// Each per-format planner takes a caller-supplied scratch buffer
// large enough to stage its append/write payloads. These
// constants give the guest binary (phase 7) a static upper bound
// per format. They are conservative for phase 1 and will be
// tightened as each format's planner lands.

/// Worst-case scratch buffer size for [`plan_resize_qcow2`].
// TODO(phase-2): tighten once the qcow2 grow planner lands.
pub const QCOW2_MAX_RESIZE_SCRATCH: usize = 32 * 1024 * 1024;

/// Worst-case scratch buffer size for [`plan_resize_vmdk`].
// TODO(phase-6): tighten once the vmdk planner lands.
pub const VMDK_MAX_RESIZE_SCRATCH: usize = 4 * 1024 * 1024;

/// Worst-case scratch buffer size for [`plan_resize_vhd`].
// TODO(phase-4): tighten once the vhd planner lands.
pub const VHD_MAX_RESIZE_SCRATCH: usize = 4 * 1024 * 1024;

/// Worst-case scratch buffer size for [`plan_resize_vhdx`].
// TODO(phase-5): tighten once the vhdx planner lands.
pub const VHDX_MAX_RESIZE_SCRATCH: usize = 8 * 1024 * 1024;

// ============================================================================
// Planner functions
// ============================================================================
//
// Phase 1 stubs every planner to `UnsupportedFormat`. Phase 1c
// upgrades `plan_resize_raw` to a real implementation. Phases
// 2–6 fill in the per-format planners.

/// Plan a resize of a raw image.
///
/// Raw resize is metadata-free: the host's post-pass `set_len`
/// extends or truncates the file. The planner classifies the
/// action and reports the target file size; the patches list is
/// always empty.
///
/// Raw resize does **not** require `--shrink`: `qemu-img resize
/// -f raw IMAGE SMALLER` succeeds without `--shrink` because the
/// host-side `ftruncate` is the user's deliberate choice and
/// there is no metadata to consult. The planner therefore
/// ignores any `allow_shrink` signal from the host CLI on the
/// raw path.
pub fn plan_resize_raw(opts: &RawResizeOpts) -> Result<ResizePlan<'static>, ResizeError> {
    if opts.new_virtual_size == 0 {
        return Err(ResizeError::InvalidNewVirtualSize);
    }
    let action = if opts.new_virtual_size == opts.current_virtual_size {
        ResizeAction::NoOp
    } else if opts.new_virtual_size > opts.current_virtual_size {
        ResizeAction::Grow
    } else {
        ResizeAction::Shrink
    };
    Ok(ResizePlan::new(action, opts.new_virtual_size))
}

/// Plan a resize of a qcow2 image.
///
/// Phase 2 implements the grow planner (HeaderOnly and L1Grow
/// flavours; L1AndRefcountGrow lands in step 2c and
/// `Preallocation::Metadata` likewise). Phase 3 will land the
/// shrink planner.
pub fn plan_resize_qcow2<'a>(
    opts: &Qcow2ResizeOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    qcow2::plan_grow(opts, scratch)
}

/// Plan a resize of a vmdk image.
///
/// Phase 1 stub. Phase 6 lands monolithicSparse grow; other
/// subformats remain unsupported.
pub fn plan_resize_vmdk<'a>(
    _opts: &VmdkResizeOpts,
    _scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    Err(ResizeError::UnsupportedFormat)
}

/// Plan a resize of a vhd image.
///
/// Phase 4 lands fixed and dynamic grow; shrink is deferred.
pub fn plan_resize_vhd<'a>(
    opts: &VhdResizeOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    vhd::plan_grow(opts, scratch)
}

/// Plan a resize of a vhdx image.
///
/// Phase 5 lands the dynamic grow planner; shrink is not
/// supported by qemu upstream and the planner rejects it.
pub fn plan_resize_vhdx<'a>(
    opts: &VhdxResizeOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    vhdx::plan_grow(opts, scratch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_opts(current: u64, new: u64) -> RawResizeOpts {
        RawResizeOpts {
            current_virtual_size: current,
            new_virtual_size: new,
            preallocation: Preallocation::Off,
        }
    }

    #[test]
    fn raw_noop_when_sizes_equal() {
        let plan = plan_resize_raw(&raw_opts(1 << 20, 1 << 20)).unwrap();
        assert_eq!(plan.action, ResizeAction::NoOp);
        assert_eq!(plan.total_file_size, 1 << 20);
        assert_eq!(plan.patches().len(), 0);
    }

    #[test]
    fn raw_grow_when_new_larger() {
        let plan = plan_resize_raw(&raw_opts(1 << 20, 2 << 20)).unwrap();
        assert_eq!(plan.action, ResizeAction::Grow);
        assert_eq!(plan.total_file_size, 2 << 20);
        assert_eq!(plan.patches().len(), 0);
    }

    #[test]
    fn raw_shrink_when_new_smaller_no_flag_needed() {
        // Raw resize matches qemu-img: --shrink is not required
        // for raw because there is no metadata to consult.
        let plan = plan_resize_raw(&raw_opts(2 << 20, 1 << 20)).unwrap();
        assert_eq!(plan.action, ResizeAction::Shrink);
        assert_eq!(plan.total_file_size, 1 << 20);
        assert_eq!(plan.patches().len(), 0);
    }

    #[test]
    fn raw_zero_size_rejected() {
        let err = plan_resize_raw(&raw_opts(1 << 20, 0)).unwrap_err();
        assert_eq!(err, ResizeError::InvalidNewVirtualSize);
    }

    #[test]
    fn plan_push_increments_count_and_keeps_total_file_size() {
        let mut plan = ResizePlan::new(ResizeAction::Grow, 2 << 20);
        assert_eq!(plan.patches().len(), 0);
        plan.push(ResizePatch::Write {
            byte_offset: 0,
            bytes: &[0xAB; 8],
        })
        .unwrap();
        assert_eq!(plan.patches().len(), 1);
        // total_file_size is set at construction and is not
        // touched by push — it describes the post-resize EOF the
        // host should set_len to, not the cumulative bytes
        // written by the patches.
        assert_eq!(plan.total_file_size, 2 << 20);
    }

    #[test]
    fn plan_push_returns_scratch_too_small_when_full() {
        let mut plan = ResizePlan::new(ResizeAction::Grow, 0);
        for _ in 0..MAX_RESIZE_PATCHES {
            plan.push(ResizePatch::Write {
                byte_offset: 0,
                bytes: &[],
            })
            .unwrap();
        }
        let err = plan
            .push(ResizePatch::Write {
                byte_offset: 0,
                bytes: &[],
            })
            .unwrap_err();
        assert_eq!(err, ResizeError::ScratchTooSmall);
    }

    #[test]
    fn patch_byte_offset_and_len_per_variant() {
        let w = ResizePatch::Write {
            byte_offset: 100,
            bytes: &[0; 16],
        };
        assert_eq!(w.byte_offset(), 100);
        assert_eq!(w.len(), 16);

        let a = ResizePatch::Append {
            byte_offset: 200,
            bytes: &[0; 4],
        };
        assert_eq!(a.byte_offset(), 200);
        assert_eq!(a.len(), 4);

        let z = ResizePatch::ZeroFill {
            byte_offset: 300,
            len: 4096,
        };
        assert_eq!(z.byte_offset(), 300);
        assert_eq!(z.len(), 4096);
    }

    #[test]
    fn patch_is_empty() {
        assert!(ResizePatch::EMPTY.is_empty());
        assert!(!ResizePatch::Write {
            byte_offset: 0,
            bytes: &[1],
        }
        .is_empty());
    }

    #[test]
    fn non_raw_planners_stub_to_unsupported() {
        // qcow2 is no longer stubbed (phase 2b lands the grow
        // planner); see crates/resize/src/qcow2.rs tests and the
        // tests/qcow2_grow.rs integration suite (phase 2d) for
        // qcow2 coverage. The remaining three formats are still
        // stubbed pending phases 4-6.
        let mut scratch = [0u8; 64];

        let vmdk_opts = VmdkResizeOpts {
            current_virtual_size: 1 << 20,
            new_virtual_size: 2 << 20,
            grain_size: 65536,
            subformat: VmdkSubformat::MonolithicSparse,
            allow_shrink: false,
            preallocation: Preallocation::Off,
        };
        assert_eq!(
            plan_resize_vmdk(&vmdk_opts, &mut scratch).unwrap_err(),
            ResizeError::UnsupportedFormat
        );

        // VHD is no longer a stub (phase 4 ships the grow
        // planner); coverage moves to tests/vhd_grow.rs.

        // VHDX is no longer a stub (phase 5 ships the grow
        // planner); coverage moves to tests/vhdx_grow.rs.
    }
}
