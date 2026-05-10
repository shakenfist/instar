//! Pre-calculate disk image file size for given format options.
//!
//! Each `measure_<fmt>` function answers: "if I ask instar to write
//! `allocated_bytes` of allocated data into a fresh `<fmt>` image of
//! virtual size `virtual_size` with options `opts`, how large will the
//! resulting file be?"
//!
//! Two values are returned per call:
//! - `required`: the expected size when instar's sparse writer skips holes
//!   (i.e. only allocated extents are written).
//! - `fully_allocated`: the expected size if every cluster/grain/block in
//!   the virtual address range were written.
//!
//! This is a pure, `no_std` library crate. It performs no I/O.

#![no_std]

/// Summary of source-side allocation as seen by a parser.
///
/// Phase 2 produces this from a parsed source image; phase 1 only
/// consumes it as input to the measure functions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocationSummary {
    /// Total addressable size of the source image in bytes.
    pub virtual_size: u64,
    /// Bytes that the source has marked as allocated (whether or not they
    /// contain non-zero data). For raw input this equals `virtual_size`.
    /// For sparse inputs it may be less.
    pub allocated_bytes: u64,
}

/// The measured output sizes for a target format.
///
/// Returned by every `measure_<fmt>` function on success.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MeasureOutput {
    /// Expected file size when only allocated extents are written (sparse
    /// writer skips holes, matching instar's `convert` behaviour).
    pub required: u64,
    /// Expected file size when every cluster/grain/block in the virtual
    /// range is written (no holes).
    pub fully_allocated: u64,
}

/// Errors returned by the measure functions.
///
/// - `Overflow`: an intermediate or final value exceeds `u64::MAX`.
/// - `InvalidOption`: an option value is outside the permitted set
///   (e.g. `cluster_size` not a power of two, `refcount_bits` not in
///   `{1,2,4,8,16,32,64}`, `grain_size` < 4 KiB, `block_size` out of
///   range).
/// - `InvalidSize`: `virtual_size` or `allocated_bytes` is outside the
///   range accepted by the target format (e.g. qcow2 caps at 2^63).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeasureError {
    /// An arithmetic overflow occurred during size calculation.
    Overflow,
    /// A format option value is invalid or unsupported.
    InvalidOption,
    /// The virtual size or allocated bytes is out of range for the format.
    InvalidSize,
}

/// Convenience alias for the result type returned by all measure functions.
pub type MeasureResult = core::result::Result<MeasureOutput, MeasureError>;

// ---------------------------------------------------------------------------
// Shared option enums
// ---------------------------------------------------------------------------

/// Preallocation mode for qcow2 images.
///
/// Controls how much of the image is materialised on disk at creation time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preallocation {
    /// Sparse output; holes are not written (default).
    Off,
    /// Metadata only: all L2 tables and refcount structures are written so
    /// that every cluster has a refcount entry, but data clusters are not
    /// written. Matches `qemu-img`'s `preallocation=metadata` behaviour.
    Metadata,
    /// All clusters are allocated using `fallocate(2)` (or equivalent).
    /// `required` equals `fully_allocated`.
    Falloc,
    /// All clusters are fully zeroed. `required` equals `fully_allocated`.
    Full,
}

/// VMDK sub-format selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmdkSubformat {
    /// Monolithic sparse extent with a grain directory and grain tables.
    MonolithicSparse,
    /// Stream-optimised VMDK (compressed, with per-grain markers).
    StreamOptimized,
    /// Monolithic flat (raw) extent with a text descriptor.
    MonolithicFlat,
}

/// VHD sub-format selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VhdSubformat {
    /// Dynamic VHD: block allocation table grows on demand.
    Dynamic,
    /// Fixed VHD: all data blocks are pre-allocated.
    Fixed,
}

// ---------------------------------------------------------------------------
// Raw
// ---------------------------------------------------------------------------

/// Measure a raw output image.
///
/// For raw images `required` and `fully_allocated` are both equal to
/// `virtual_size`; there is no format overhead.
pub fn measure_raw(_virtual_size: u64) -> MeasureResult {
    unimplemented!("step 1b")
}

// ---------------------------------------------------------------------------
// qcow2
// ---------------------------------------------------------------------------

/// Options for a qcow2 output image.
#[derive(Clone, Copy, Debug)]
pub struct Qcow2Opts {
    /// Cluster size in bytes. Must be a power of two in `[512, 2 MiB]`.
    /// Default: 65536.
    pub cluster_size: u32,
    /// Refcount entry width in bits. Must be one of `{1,2,4,8,16,32,64}`.
    /// Default: 16.
    pub refcount_bits: u8,
    /// Use extended L2 entries (64-bit data + 64-bit subcluster bitmap per
    /// entry). Requires `compat_v3 = true`. Default: false.
    pub extended_l2: bool,
    /// Enable lazy refcount updates. Does not affect image size; accepted
    /// and ignored. Default: false.
    pub lazy_refcounts: bool,
    /// Produce a qcow2 v3 (compat 1.1) image. `false` selects v2.
    /// `extended_l2 = true` requires `compat_v3 = true`. Default: true.
    pub compat_v3: bool,
    /// Enable compressed clusters. Does not affect the `required` bound
    /// (incompressible data is the worst case, matching `qemu-img`).
    /// Default: false.
    pub compress: bool,
    /// Preallocation mode. Default: `Preallocation::Off`.
    pub preallocation: Preallocation,
    /// Additional bytes consumed by a LUKS-in-qcow2 header
    /// (`crypt_method=2`). When `Some(n)`, `round_up(n, cluster_size)` is
    /// added to both `required` and `fully_allocated`. Default: `None`.
    pub luks_header_overhead: Option<u64>,
}

impl Default for Qcow2Opts {
    fn default() -> Self {
        Self {
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            lazy_refcounts: false,
            compat_v3: true,
            compress: false,
            preallocation: Preallocation::Off,
            luks_header_overhead: None,
        }
    }
}

/// Measure a qcow2 output image.
///
/// Implements the same fixed-point refcount layout algorithm used by
/// `qemu-img measure -O qcow2`. The formula is sourced from
/// `calculate_refcount_layout()` and `init_qcow2_output_layout()` in
/// `src/operations/convert/src/main.rs`.
pub fn measure_qcow2(_s: &AllocationSummary, _opts: &Qcow2Opts) -> MeasureResult {
    unimplemented!("step 1c")
}

// ---------------------------------------------------------------------------
// VMDK
// ---------------------------------------------------------------------------

/// Options for a VMDK output image.
#[derive(Clone, Copy, Debug)]
pub struct VmdkOpts {
    /// VMDK sub-format. Default: `VmdkSubformat::MonolithicSparse`.
    pub subformat: VmdkSubformat,
    /// Grain size in bytes. Must be a power of two in `[4096, 65536]`.
    /// Default: 65536.
    pub grain_size: u32,
}

impl Default for VmdkOpts {
    fn default() -> Self {
        Self {
            subformat: VmdkSubformat::MonolithicSparse,
            grain_size: 65536,
        }
    }
}

/// Measure a VMDK output image.
///
/// Supports `MonolithicSparse`, `StreamOptimized`, and `MonolithicFlat`
/// sub-formats. Constants are sourced from the `vmdk` crate.
pub fn measure_vmdk(_s: &AllocationSummary, _opts: &VmdkOpts) -> MeasureResult {
    unimplemented!("step 1d")
}

// ---------------------------------------------------------------------------
// VHD
// ---------------------------------------------------------------------------

/// Options for a VHD output image.
#[derive(Clone, Copy, Debug)]
pub struct VhdOpts {
    /// VHD sub-format. Default: `VhdSubformat::Dynamic`.
    pub subformat: VhdSubformat,
    /// Block size in bytes. Must be a power of two in `[512 KiB, 2 GiB]`.
    /// Ignored for `Fixed` images. Default: 2 MiB.
    pub block_size: u32,
}

impl Default for VhdOpts {
    fn default() -> Self {
        Self {
            subformat: VhdSubformat::Dynamic,
            block_size: 2 * 1024 * 1024,
        }
    }
}

/// Measure a VHD output image.
///
/// Supports `Dynamic` and `Fixed` sub-formats. Constants (`FOOTER_SIZE`,
/// `DYNAMIC_HEADER_SIZE`) are sourced from the `vhd` crate.
pub fn measure_vhd(_s: &AllocationSummary, _opts: &VhdOpts) -> MeasureResult {
    unimplemented!("step 1e")
}

// ---------------------------------------------------------------------------
// VHDX
// ---------------------------------------------------------------------------

/// Options for a VHDX output image.
#[derive(Clone, Copy, Debug)]
pub struct VhdxOpts {
    /// Block size in bytes. Must be a power of two in `[1 MiB, 256 MiB]`.
    /// Default: 32 MiB.
    pub block_size: u32,
}

impl Default for VhdxOpts {
    fn default() -> Self {
        Self {
            block_size: 32 * 1024 * 1024,
        }
    }
}

/// Measure a VHDX output image.
///
/// Uses `vhdx::calculate_bat_layout()` directly for the BAT entry count
/// rather than re-deriving the chunk-ratio formula. Constants (`MB_ALIGN`,
/// `HEADER_SIZE`) are sourced from the `vhdx` crate.
pub fn measure_vhdx(_s: &AllocationSummary, _opts: &VhdxOpts) -> MeasureResult {
    unimplemented!("step 1f")
}
