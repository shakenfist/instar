//! Build empty disk image metadata layouts.
//!
//! Given `(target_format, virtual_size, options, optional backing
//! reference)`, the `plan_*` functions in this crate return a
//! [`MetadataPlan`] — a bounded sequence of `(byte_offset, &[u8])`
//! writes that constitute a valid empty image in the requested
//! format.
//!
//! This phase ships scaffolding only: the type surface and stubbed
//! planners that return [`CreateError::ScratchTooSmall`]. Later
//! phase-1 steps fill in the per-format implementations.
//!
//! This crate is `no_std` and performs no I/O. Scratch buffers are
//! caller-supplied; the returned [`MetadataPlan`] borrows from the
//! scratch buffer.

#![no_std]

use shared::ImageFormat;

/// Maximum length, in bytes, of a backing file path accepted by any
/// `plan_*` function. Matches the call-table struct's
/// `backing_file` field size so the host CLI and guest planner agree.
pub const MAX_BACKING_FILE_LEN: usize = 1024;

// Worst-case scratch sizes for each format. These are conservative
// placeholders for the phase-1a scaffold; phase-1c..1f tighten them
// once the planners' real memory requirements are known.

/// Worst-case scratch buffer size required by [`plan_qcow2`].
// TODO(phase-1c): tighten
pub const QCOW2_MAX_METADATA_SCRATCH: usize = 4 * 1024 * 1024;

/// Worst-case scratch buffer size required by [`plan_vmdk`].
// TODO(phase-1d): tighten
pub const VMDK_MAX_METADATA_SCRATCH: usize = 4 * 1024 * 1024;

/// Worst-case scratch buffer size required by [`plan_vhd`].
// TODO(phase-1e): tighten
pub const VHD_MAX_METADATA_SCRATCH: usize = 4 * 1024 * 1024;

/// Worst-case scratch buffer size required by [`plan_vhdx`].
// TODO(phase-1f): tighten
pub const VHDX_MAX_METADATA_SCRATCH: usize = 4 * 1024 * 1024;

/// Errors returned by the `plan_*` family of functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateError {
    /// Virtual size is zero, misaligned, or exceeds the format's
    /// maximum.
    InvalidVirtualSize,
    /// Cluster size is out of range or not a power of two.
    InvalidClusterSize,
    /// Block size is out of range or not a power of two.
    InvalidBlockSize,
    /// Grain size is out of range or not a power of two.
    InvalidGrainSize,
    /// Subformat is unknown, or known but not yet supported.
    InvalidSubformat,
    /// Backing-file path exceeds [`MAX_BACKING_FILE_LEN`].
    BackingFileTooLong,
    /// The target format does not support backing files.
    BackingFileUnsupported,
    /// An internal size computation overflowed.
    Overflow,
    /// The caller-supplied scratch buffer is too small for the
    /// requested layout. The required size is bounded above by the
    /// per-format `*_MAX_METADATA_SCRATCH` constant.
    ScratchTooSmall,
}

/// A reference to a backing image that the new image should chain to.
///
/// `path` holds the bytes the user typed (e.g. on the command line);
/// they are written verbatim into the new image's metadata. `format`
/// is an optional hint that some formats (qcow2) embed alongside the
/// path.
#[derive(Debug, Clone, Copy)]
pub struct BackingRef<'a> {
    /// Backing file path, as bytes; written verbatim.
    pub path: &'a [u8],
    /// Optional format hint for the backing file.
    pub format: Option<ImageFormat>,
}

/// One contiguous write of metadata bytes at a known file offset.
#[derive(Debug, Clone, Copy)]
pub struct MetadataWrite<'a> {
    /// Absolute byte offset within the new image file.
    pub byte_offset: u64,
    /// Bytes to write at `byte_offset`.
    pub bytes: &'a [u8],
}

/// A complete empty-image metadata layout.
///
/// `writes` is an ordered list of contiguous byte regions to write to
/// the new file. `total_metadata_bytes` is the sum of
/// `writes[*].bytes.len()`. `minimum_file_size` is the smallest file
/// size that contains every write's byte range (the maximum of
/// `byte_offset + bytes.len()` across all writes); the caller may
/// need to extend the file past this for preallocation in later
/// phases.
#[derive(Debug, Clone, Copy)]
pub struct MetadataPlan<'a> {
    /// Sum of all `writes[*].bytes.len()`.
    pub total_metadata_bytes: u64,
    /// Smallest file size that contains every write.
    pub minimum_file_size: u64,
    /// Ordered list of writes that, applied together, form a valid
    /// empty image in the requested format.
    pub writes: &'a [MetadataWrite<'a>],
}

/// Options for [`plan_qcow2`].
#[derive(Debug, Clone, Copy)]
pub struct Qcow2CreateOpts<'a> {
    /// Logical (virtual) size of the resulting image, in bytes.
    pub virtual_size: u64,
    /// Cluster size in bytes. Must be a power of two in
    /// `512..=2 MiB`.
    pub cluster_size: u32,
    /// Refcount entry width in bits. Must be one of
    /// `{1, 2, 4, 8, 16, 32, 64}`.
    pub refcount_bits: u8,
    /// Whether to enable extended L2 entries (qcow2 v3 feature).
    pub extended_l2: bool,
    /// Whether to enable the lazy-refcounts feature.
    pub lazy_refcounts: bool,
    /// Emit a v3-compat header (vs. the newest supported version).
    pub compat_v3: bool,
    /// Optional backing image to chain to.
    pub backing: Option<BackingRef<'a>>,
    // preallocation handled by phase 6; phase 1 supports `off` only.
}

/// VMDK subformat selector.
///
/// Phase 1 ships [`MonolithicSparse`](VmdkSubformat::MonolithicSparse)
/// and [`StreamOptimized`](VmdkSubformat::StreamOptimized). The
/// remaining variants are listed so phase-4's `-o subformat=...`
/// option parser can return a clear "not yet supported" error
/// instead of an "unknown subformat" one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmdkSubformat {
    /// Single sparse extent (supported).
    MonolithicSparse,
    /// Single stream-optimised extent (supported).
    StreamOptimized,
    /// Single flat extent (not yet supported).
    MonolithicFlat,
    /// Multi-extent sparse, 2 GiB cap (not yet supported).
    TwoGbMaxExtentSparse,
    /// Multi-extent flat, 2 GiB cap (not yet supported).
    TwoGbMaxExtentFlat,
}

/// Options for [`plan_vmdk`].
#[derive(Debug, Clone, Copy)]
pub struct VmdkCreateOpts<'a> {
    /// Logical (virtual) size of the resulting image, in bytes.
    pub virtual_size: u64,
    /// Subformat to emit.
    pub subformat: VmdkSubformat,
    /// Grain size in bytes. Must be a power of two in `4 KiB..=64 KiB`.
    pub grain_size: u32,
    /// Optional backing image to chain to.
    pub backing: Option<BackingRef<'a>>,
}

/// VHD subformat selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdSubformat {
    /// Dynamic (sparse) VHD.
    Dynamic,
    /// Fixed (fully-allocated) VHD.
    Fixed,
}

/// Options for [`plan_vhd`].
#[derive(Debug, Clone, Copy)]
pub struct VhdCreateOpts<'a> {
    /// Logical (virtual) size of the resulting image, in bytes.
    pub virtual_size: u64,
    /// Subformat to emit.
    pub subformat: VhdSubformat,
    /// Block size in bytes. Must be a power of two in
    /// `512 KiB..=256 MiB`.
    pub block_size: u32,
    /// Optional backing image to chain to.
    pub backing: Option<BackingRef<'a>>,
}

/// Options for [`plan_vhdx`].
#[derive(Debug, Clone, Copy)]
pub struct VhdxCreateOpts<'a> {
    /// Logical (virtual) size of the resulting image, in bytes.
    pub virtual_size: u64,
    /// Block size in bytes. Must be a power of two in
    /// `1 MiB..=256 MiB`.
    pub block_size: u32,
    /// Optional backing image to chain to.
    pub backing: Option<BackingRef<'a>>,
}

/// Build a metadata plan for a qcow2 image.
///
/// Stub: returns [`CreateError::ScratchTooSmall`] until phase-1c.
pub fn plan_qcow2<'a>(
    _opts: &Qcow2CreateOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<MetadataPlan<'a>, CreateError> {
    Err(CreateError::ScratchTooSmall)
}

/// Build a metadata plan for a VMDK image.
///
/// Stub: returns [`CreateError::ScratchTooSmall`] until phase-1d.
pub fn plan_vmdk<'a>(
    _opts: &VmdkCreateOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<MetadataPlan<'a>, CreateError> {
    Err(CreateError::ScratchTooSmall)
}

/// Build a metadata plan for a VHD image.
///
/// Stub: returns [`CreateError::ScratchTooSmall`] until phase-1e.
pub fn plan_vhd<'a>(
    _opts: &VhdCreateOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<MetadataPlan<'a>, CreateError> {
    Err(CreateError::ScratchTooSmall)
}

/// Build a metadata plan for a VHDX image.
///
/// Stub: returns [`CreateError::ScratchTooSmall`] until phase-1f.
pub fn plan_vhdx<'a>(
    _opts: &VhdxCreateOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<MetadataPlan<'a>, CreateError> {
    Err(CreateError::ScratchTooSmall)
}
