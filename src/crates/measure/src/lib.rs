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
pub fn measure_raw(virtual_size: u64) -> MeasureResult {
    Ok(MeasureOutput {
        required: virtual_size,
        fully_allocated: virtual_size,
    })
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
/// `src/operations/convert/src/main.rs`, with two adjustments to match
/// `qemu-img`'s own `qcow2_measure` (verified against `qemu-img 10.0.8`
/// fixture rows in this crate's tests):
///
/// 1. The L2 table is sized to cover the full virtual range, not just
///    `allocated_bytes`. qemu-img writes one L2 cluster per L1 entry
///    that the virtual size requires, regardless of which clusters are
///    actually allocated. This means `l2_clusters_required ==
///    l2_clusters_full == l1_entries`.
/// 2. The refcount table is sized as if every data cluster in the
///    virtual range were allocated. This is because the refcount table
///    must be large enough to track every cluster the image could ever
///    contain. The same refcount layout is then used for both
///    `required` (which excludes unallocated data clusters) and
///    `fully_allocated`.
///
/// As a consequence, `Preallocation::Metadata` and
/// `Preallocation::Off` produce identical results for qcow2 — every
/// metadata cluster is already counted in `required` under `Off`.
/// `Falloc` and `Full` set `required = fully_allocated`.
pub fn measure_qcow2(s: &AllocationSummary, opts: &Qcow2Opts) -> MeasureResult {
    // ---- Validate options. -------------------------------------------------
    if opts.cluster_size < 512
        || opts.cluster_size > 2 * 1024 * 1024
        || !opts.cluster_size.is_power_of_two()
    {
        return Err(MeasureError::InvalidOption);
    }
    match opts.refcount_bits {
        1 | 2 | 4 | 8 | 16 | 32 | 64 => {}
        _ => return Err(MeasureError::InvalidOption),
    }
    if opts.extended_l2 && !opts.compat_v3 {
        return Err(MeasureError::InvalidOption);
    }

    // ---- Validate sizes. ---------------------------------------------------
    // qcow2 caps virtual_size at 2^63.
    if s.virtual_size > (1u64 << 63) {
        return Err(MeasureError::InvalidSize);
    }
    if s.allocated_bytes > s.virtual_size {
        return Err(MeasureError::InvalidSize);
    }

    let cluster_size = opts.cluster_size as u64;
    let l2_entry_size: u64 = if opts.extended_l2 { 16 } else { 8 };
    let entries_per_l2 = cluster_size / l2_entry_size;
    let l2_coverage = cluster_size
        .checked_mul(entries_per_l2)
        .ok_or(MeasureError::Overflow)?;

    // ---- L1 table. ---------------------------------------------------------
    let l1_entries = if s.virtual_size == 0 {
        0
    } else {
        ceil_div(s.virtual_size, l2_coverage)
    };
    let l1_size_bytes = l1_entries.checked_mul(8).ok_or(MeasureError::Overflow)?;
    let l1_clusters = if l1_entries == 0 {
        0
    } else {
        ceil_div(l1_size_bytes, cluster_size)
    };

    // ---- L2 cluster counts. ------------------------------------------------
    // qemu-img sizes L2 tables to cover the full virtual range regardless of
    // which clusters carry data. This is the contiguous-from-zero assumption
    // that qemu-img documents in `qcow2_measure`.
    let l2_clusters_full = l1_entries;
    let l2_clusters_required = l2_clusters_full;

    // ---- Data cluster counts. ---------------------------------------------
    let data_clusters_required = ceil_div(s.allocated_bytes, cluster_size);
    let data_clusters_full = if s.virtual_size == 0 {
        0
    } else {
        ceil_div(s.virtual_size, cluster_size)
    };

    // ---- LUKS header overhead. --------------------------------------------
    let luks_clusters = match opts.luks_header_overhead {
        Some(n) if n > 0 => ceil_div(n, cluster_size),
        _ => 0,
    };

    // ---- Refcount layout sized for the FULLY-ALLOCATED image. -------------
    // qemu-img sizes the refcount table for the worst case (every data cluster
    // tracked) and uses that same layout in `required`.
    let used_clusters_full = checked_sum(&[
        1, // header
        l1_clusters,
        l2_clusters_full,
        data_clusters_full,
        luks_clusters,
    ])?;
    let (reftable_clusters, refblock_count, _total_full_via_helper) =
        calculate_refcount_layout(used_clusters_full, cluster_size, opts.refcount_bits)?;

    // ---- Final cluster counts. --------------------------------------------
    let required_clusters = checked_sum(&[
        1,
        l1_clusters,
        l2_clusters_required,
        luks_clusters,
        data_clusters_required,
        reftable_clusters,
        refblock_count,
    ])?;
    let full_clusters = checked_sum(&[
        1,
        l1_clusters,
        l2_clusters_full,
        luks_clusters,
        data_clusters_full,
        reftable_clusters,
        refblock_count,
    ])?;

    let mut required = required_clusters
        .checked_mul(cluster_size)
        .ok_or(MeasureError::Overflow)?;
    let fully_allocated = full_clusters
        .checked_mul(cluster_size)
        .ok_or(MeasureError::Overflow)?;

    // ---- Apply preallocation. ---------------------------------------------
    match opts.preallocation {
        Preallocation::Off => {}
        Preallocation::Metadata => {
            // All metadata is already in `required` (l2_clusters_required ==
            // l2_clusters_full and the refcount table is sized for the full
            // image), so Metadata is a no-op vs Off. Matches qemu-img.
        }
        Preallocation::Falloc | Preallocation::Full => {
            required = fully_allocated;
        }
    }

    // `compress` and `lazy_refcounts` are accepted for option-surface parity
    // with qemu-img but do not affect the size bound.
    let _ = (opts.compress, opts.lazy_refcounts);

    Ok(MeasureOutput {
        required,
        fully_allocated,
    })
}

/// Ceiling division for `u64`. Caller guarantees `b > 0`.
#[inline]
fn ceil_div(a: u64, b: u64) -> u64 {
    // Saturating add prevents overflow when `a` is very close to `u64::MAX`;
    // callers feed only validated, in-range values so this branch is mostly
    // defensive against fuzzing.
    a.saturating_add(b - 1) / b
}

/// Sum a slice of `u64`s with overflow checking.
fn checked_sum(parts: &[u64]) -> Result<u64, MeasureError> {
    let mut total: u64 = 0;
    for p in parts {
        total = total.checked_add(*p).ok_or(MeasureError::Overflow)?;
    }
    Ok(total)
}

/// Compute the qcow2 refcount table layout via fixed-point iteration.
///
/// Returns `(reftable_clusters, refblock_count, total_clusters)` where
/// `total_clusters = used_clusters + reftable_clusters + refblock_count`.
///
/// Generalised from `convert::calculate_refcount_layout` (which hard-coded
/// 16-bit refcounts) to support any width in `{1,2,4,8,16,32,64}`. The fixed
/// point converges in ≤4 iterations on real images; the 16-iteration cap is a
/// fuzz-safety net.
fn calculate_refcount_layout(
    used_clusters: u64,
    cluster_size: u64,
    refcount_bits: u8,
) -> Result<(u64, u64, u64), MeasureError> {
    // entries_per_refblock = bits_per_cluster / refcount_bits
    let bits_per_cluster = cluster_size.checked_mul(8).ok_or(MeasureError::Overflow)?;
    let entries_per_refblock = bits_per_cluster / refcount_bits as u64;
    if entries_per_refblock == 0 {
        return Err(MeasureError::InvalidOption);
    }

    let mut reftable_clusters: u64 = 1;
    let mut refblock_count: u64 = 1;
    let mut converged = false;

    for _ in 0..16 {
        let total = used_clusters
            .checked_add(reftable_clusters)
            .ok_or(MeasureError::Overflow)?
            .checked_add(refblock_count)
            .ok_or(MeasureError::Overflow)?;
        let new_refblock_count = ceil_div(total, entries_per_refblock);
        let new_reftable_bytes = new_refblock_count
            .checked_mul(8)
            .ok_or(MeasureError::Overflow)?;
        let new_reftable_clusters = ceil_div(new_reftable_bytes, cluster_size);
        if new_refblock_count == refblock_count && new_reftable_clusters == reftable_clusters {
            converged = true;
            break;
        }
        refblock_count = new_refblock_count;
        reftable_clusters = new_reftable_clusters;
    }

    if !converged {
        return Err(MeasureError::Overflow);
    }

    let total = used_clusters
        .checked_add(reftable_clusters)
        .ok_or(MeasureError::Overflow)?
        .checked_add(refblock_count)
        .ok_or(MeasureError::Overflow)?;
    Ok((reftable_clusters, refblock_count, total))
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
///
/// # Formula sources
///
/// - `vmdk::DEFAULT_NUM_GTES_PER_GT` (= 512) — grain table entries per GT.
/// - `vmdk::DESC_SECTORS` (= 20) — descriptor sectors reserved after the
///   512-byte binary header. Sourced from `src/crates/vmdk/src/lib.rs`.
/// - `vmdk::GRAIN_MARKER_SIZE` (= 12) — per-grain marker header for
///   `StreamOptimized`. Sourced from `src/crates/vmdk/src/lib.rs`.
/// - `vmdk::METADATA_MARKER_SIZE` (= 512) — metadata marker sector size.
/// - `shared::MAX_SECTOR_SIZE` (= 65536) — alignment boundary used by the
///   `StreamOptimized` writer to pad before the footer tail. Sourced from
///   `src/operations/convert/src/main.rs:convert_to_vmdk_compressed`.
///
/// # MonolithicSparse layout (sourced from `init_vmdk_output_layout` /
/// `convert_to_vmdk` in `src/operations/convert/src/main.rs`)
///
/// ```text
/// header (512) | descriptor (DESC_SECTORS×512) | grain data | GTs | GD
/// ```
///
/// GTs are allocated interleaved with grain data in the actual writer
/// (one GT per GD entry that has ≥ 1 grain), but for measurement purposes we
/// conservatively count `num_gd_entries` GTs in both `required` and
/// `fully_allocated`. This is a strict upper bound for `required` (the real
/// writer skips GTs for GD entries with no allocated grains), which ensures
/// `measure_vmdk` is always ≥ the actual writer output size.
///
/// # StreamOptimized layout (sourced from `convert_to_vmdk_compressed`)
///
/// ```text
/// header (512) | descriptor (DESC_SECTORS×512)
/// | [grain_marker(12) + compressed_data, padded to 512] × allocated_grains
/// | [GT_marker(512) + GT_data(padded to 512)] × num_gd_entries
/// | GD_marker(512) + GD_data(padded to 512, min 512)
/// | padding to MAX_SECTOR_SIZE boundary
/// | footer_marker(512) + footer(512) + EOS(512)
/// ```
///
/// Compressed size is bounded by `grain_size` (incompressible worst case),
/// so each grain costs `grain_size + 512` bytes after the 12-byte marker
/// bleeds into an additional 512-byte sector.
///
/// # MonolithicFlat layout
///
/// Two-file layout in the VMDK spec: a text descriptor file + a flat extent
/// file. For measurement purposes we report `descriptor + extent` summed
/// together so that both `required` and `fully_allocated` represent the total
/// disk consumption. The descriptor is bounded to 1 sector (512 bytes); in
/// practice it is smaller, making this a safe upper bound.
pub fn measure_vmdk(s: &AllocationSummary, opts: &VmdkOpts) -> MeasureResult {
    // ---- Validate options. -------------------------------------------------
    let grain_size = opts.grain_size as u64;
    if !(4096..=65536).contains(&grain_size) || !opts.grain_size.is_power_of_two() {
        return Err(MeasureError::InvalidOption);
    }

    // ---- Validate sizes. ---------------------------------------------------
    if s.allocated_bytes > s.virtual_size {
        return Err(MeasureError::InvalidSize);
    }

    match opts.subformat {
        VmdkSubformat::MonolithicSparse | VmdkSubformat::StreamOptimized => {
            measure_vmdk_sparse_or_stream(s, opts, grain_size)
        }
        VmdkSubformat::MonolithicFlat => measure_vmdk_flat(s),
    }
}

/// Internal helper for `MonolithicSparse` and `StreamOptimized`.
fn measure_vmdk_sparse_or_stream(
    s: &AllocationSummary,
    opts: &VmdkOpts,
    grain_size: u64,
) -> MeasureResult {
    // Constants from the vmdk crate.
    // vmdk::DEFAULT_NUM_GTES_PER_GT = 512  (grain table entries per GT)
    // vmdk::DESC_SECTORS = 20              (descriptor sectors, verified in
    //                                      src/crates/vmdk/src/lib.rs:103)
    let gtes_per_gt = vmdk::DEFAULT_NUM_GTES_PER_GT as u64;
    let gt_bytes = gtes_per_gt.checked_mul(4).ok_or(MeasureError::Overflow)?; // = 2048

    // ---- Grain/directory geometry. -----------------------------------------
    let capacity_sectors = ceil_div(s.virtual_size, 512);
    let grain_size_sectors = grain_size / 512; // grain_size is ≥ 4096, always > 0
    let total_grains = ceil_div(capacity_sectors, grain_size_sectors);
    let num_gd_entries = ceil_div(total_grains, gtes_per_gt);
    let gd_bytes = num_gd_entries
        .checked_mul(4)
        .ok_or(MeasureError::Overflow)?;

    // ---- Allocated grain counts. -------------------------------------------
    let allocated_grains_required = ceil_div(s.allocated_bytes, grain_size);
    let allocated_grains_full = total_grains;

    // ---- Per-sub-format calculation. ----------------------------------------
    match opts.subformat {
        VmdkSubformat::MonolithicSparse => measure_vmdk_monolithic_sparse(
            grain_size,
            allocated_grains_required,
            allocated_grains_full,
            num_gd_entries,
            gt_bytes,
            gd_bytes,
        ),
        VmdkSubformat::StreamOptimized => measure_vmdk_stream_optimized(
            grain_size,
            allocated_grains_required,
            allocated_grains_full,
            num_gd_entries,
            gt_bytes,
            gd_bytes,
        ),
        VmdkSubformat::MonolithicFlat => unreachable!(),
    }
}

/// Compute grain-data-start offset (= header + descriptor, aligned to 512).
///
/// header = 512 bytes
/// descriptor = vmdk::DESC_SECTORS × 512 bytes
///
/// With output_sector_size = 512 (the on-disk grain alignment used for
/// measure purposes), the result is exactly 512 + DESC_SECTORS * 512.
#[inline]
fn vmdk_grain_data_start() -> Result<u64, MeasureError> {
    // 512 (header) + DESC_SECTORS * 512 (descriptor)
    // vmdk::DESC_SECTORS = 20, so this is 512 + 10240 = 10752.
    let desc_bytes = vmdk::DESC_SECTORS
        .checked_mul(512)
        .ok_or(MeasureError::Overflow)?;
    let start = 512u64
        .checked_add(desc_bytes)
        .ok_or(MeasureError::Overflow)?;
    Ok(start)
}

/// MonolithicSparse size calculation.
///
/// Layout: header | descriptor | [GT | grains]* | GD
///
/// For measurement, all `num_gd_entries` GTs are counted even for
/// `required`, providing a safe upper bound.
fn measure_vmdk_monolithic_sparse(
    grain_size: u64,
    allocated_grains_required: u64,
    allocated_grains_full: u64,
    num_gd_entries: u64,
    gt_bytes: u64,
    gd_bytes: u64,
) -> MeasureResult {
    let grain_data_start = vmdk_grain_data_start()?;

    // GT overhead: each GT is padded to 512 bytes.
    // round_up(gt_bytes=2048, 512) = 2048
    let gt_padded = round_up_u64(gt_bytes, 512)?;
    let all_gts = num_gd_entries
        .checked_mul(gt_padded)
        .ok_or(MeasureError::Overflow)?;

    // GD overhead: padded to 512 bytes, minimum 512.
    let gd_padded = round_up_u64(gd_bytes, 512)?.max(512);

    // required
    let grains_bytes_required = allocated_grains_required
        .checked_mul(grain_size)
        .ok_or(MeasureError::Overflow)?;
    let required = checked_sum(&[grain_data_start, grains_bytes_required, all_gts, gd_padded])?;

    // fully_allocated
    let grains_bytes_full = allocated_grains_full
        .checked_mul(grain_size)
        .ok_or(MeasureError::Overflow)?;
    let fully_allocated = checked_sum(&[grain_data_start, grains_bytes_full, all_gts, gd_padded])?;

    Ok(MeasureOutput {
        required,
        fully_allocated,
    })
}

/// StreamOptimized size calculation.
///
/// Layout: header | descriptor
///         | [grain_marker(12) + compressed_data, padded to 512] × grains
///         | [GT_marker(512) + GT_data(padded to 512)] × num_gd_entries
///         | GD_marker(512) + GD_data(padded to 512, min 512)
///         | padding to MAX_SECTOR_SIZE
///         | footer_marker(512) + footer(512) + EOS(512)
///
/// Compressed size is bounded by grain_size (incompressible worst case),
/// so each grain marker + data costs:
///   round_up(12 + grain_size, 512) = grain_size + 512
/// (the 12-byte preamble causes one extra 512-byte sector to be consumed).
///
/// The padding before the footer tail (3 × 512 = 1536 bytes) aligns the
/// total file to a `MAX_SECTOR_SIZE` (65536-byte) boundary. This matches
/// `convert_to_vmdk_compressed` in `src/operations/convert/src/main.rs`
/// (lines 3561-3579).
fn measure_vmdk_stream_optimized(
    grain_size: u64,
    allocated_grains_required: u64,
    allocated_grains_full: u64,
    num_gd_entries: u64,
    gt_bytes: u64,
    gd_bytes: u64,
) -> MeasureResult {
    let grain_data_start = vmdk_grain_data_start()?;

    // Each grain: marker_preamble (12 bytes) + compressed_data, padded to 512.
    // Worst case (incompressible): round_up(12 + grain_size, 512) = grain_size + 512
    // because grain_size is already a multiple of 512 and 12 > 0 pushes into
    // the next sector.
    let per_grain_cost = grain_size.checked_add(512).ok_or(MeasureError::Overflow)?;

    // GT overhead: GT marker (512) + GT data padded to 512.
    // round_up(gt_bytes=2048, 512) = 2048
    let gt_padded = round_up_u64(gt_bytes, 512)?;
    // 512-byte GT marker per GD entry that has grain data; conservatively
    // count all num_gd_entries (upper bound).
    let gt_marker_cost = 512u64;
    let per_gt_cost = gt_marker_cost
        .checked_add(gt_padded)
        .ok_or(MeasureError::Overflow)?;
    let all_gts_cost = num_gd_entries
        .checked_mul(per_gt_cost)
        .ok_or(MeasureError::Overflow)?;

    // GD overhead: GD marker (512) + GD data padded to 512, minimum 512.
    let gd_data_padded = round_up_u64(gd_bytes, 512)?.max(512);
    let gd_cost = 512u64
        .checked_add(gd_data_padded)
        .ok_or(MeasureError::Overflow)?;

    // Footer tail: footer_marker(512) + footer(512) + EOS(512) = 1536 bytes.
    // The writer pads (write_pos + 1536) to a MAX_SECTOR_SIZE boundary.
    // MAX_SECTOR_SIZE = 65536, sourced from shared::MAX_SECTOR_SIZE.
    let footer_tail: u64 = 3 * 512;
    let max_sector_size: u64 = shared::MAX_SECTOR_SIZE as u64;

    // required
    let grains_cost_required = allocated_grains_required
        .checked_mul(per_grain_cost)
        .ok_or(MeasureError::Overflow)?;
    let pre_footer_required = checked_sum(&[
        grain_data_start,
        grains_cost_required,
        all_gts_cost,
        gd_cost,
    ])?;
    let required = round_up_u64(
        pre_footer_required
            .checked_add(footer_tail)
            .ok_or(MeasureError::Overflow)?,
        max_sector_size,
    )?;

    // fully_allocated
    let grains_cost_full = allocated_grains_full
        .checked_mul(per_grain_cost)
        .ok_or(MeasureError::Overflow)?;
    let pre_footer_full =
        checked_sum(&[grain_data_start, grains_cost_full, all_gts_cost, gd_cost])?;
    let fully_allocated = round_up_u64(
        pre_footer_full
            .checked_add(footer_tail)
            .ok_or(MeasureError::Overflow)?,
        max_sector_size,
    )?;

    Ok(MeasureOutput {
        required,
        fully_allocated,
    })
}

/// MonolithicFlat size calculation.
///
/// Two-file layout (descriptor + extent), but for measurement we report the
/// sum of both files so the result is the total disk consumption. The
/// descriptor is bounded to 1 sector (512 bytes) — an upper bound since in
/// practice the descriptor is a short text file smaller than one sector.
/// The extent is exactly `virtual_size` bytes (flat, no overhead).
///
/// For flat VMDK, `required == fully_allocated` regardless of allocation
/// because the extent is always a dense file equal to `virtual_size`.
fn measure_vmdk_flat(s: &AllocationSummary) -> MeasureResult {
    // descriptor_size = 512 bytes (one sector, upper bound)
    // extent_size = virtual_size (flat / dense, no sparseness)
    let total = 512u64
        .checked_add(s.virtual_size)
        .ok_or(MeasureError::Overflow)?;
    Ok(MeasureOutput {
        required: total,
        fully_allocated: total,
    })
}

/// Round `a` up to the nearest multiple of `b`. Caller guarantees `b > 0`.
#[inline]
fn round_up_u64(a: u64, b: u64) -> Result<u64, MeasureError> {
    if b == 0 {
        return Err(MeasureError::Overflow);
    }
    if a == 0 {
        return Ok(0);
    }
    let remainder = a % b;
    if remainder == 0 {
        Ok(a)
    } else {
        a.checked_add(b - remainder).ok_or(MeasureError::Overflow)
    }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_zero() {
        assert_eq!(
            measure_raw(0),
            Ok(MeasureOutput {
                required: 0,
                fully_allocated: 0
            })
        );
    }

    #[test]
    fn raw_one_byte() {
        assert_eq!(
            measure_raw(1),
            Ok(MeasureOutput {
                required: 1,
                fully_allocated: 1
            })
        );
    }

    #[test]
    fn raw_511_bytes() {
        // raw has no sector rounding; 511 bytes in → 511 bytes out
        assert_eq!(
            measure_raw(511),
            Ok(MeasureOutput {
                required: 511,
                fully_allocated: 511
            })
        );
    }

    #[test]
    fn raw_one_sector() {
        assert_eq!(
            measure_raw(512),
            Ok(MeasureOutput {
                required: 512,
                fully_allocated: 512
            })
        );
    }

    #[test]
    fn raw_one_mib() {
        assert_eq!(
            measure_raw(1024 * 1024),
            Ok(MeasureOutput {
                required: 1_048_576,
                fully_allocated: 1_048_576
            }),
        );
    }

    #[test]
    fn raw_max_u64() {
        // u64::MAX as a virtual_size is hypothetical (qemu-img measure --size
        // 18446744073709551615 -O raw errors at the CLI level), but raw output
        // cannot overflow: both fields simply equal the input.
        assert_eq!(
            measure_raw(u64::MAX),
            Ok(MeasureOutput {
                required: u64::MAX,
                fully_allocated: u64::MAX
            }),
        );
    }

    // -----------------------------------------------------------------------
    // qcow2 fixture table
    //
    // All `expected_*` numbers are sourced from `qemu-img 10.0.8` running on
    // the dev host on 2026-05-10 unless explicitly marked `formula-derived`.
    // qemu-img invocation:
    //   qemu-img measure --output=json --size <SIZE> -O qcow2 -o <OPTS>
    // qemu-img only emits the empty-image case in `--size` mode (i.e. it
    // computes `required` for `allocated_bytes == 0` and `fully-allocated`
    // for `allocated_bytes == virtual_size`). Rows with partial allocation
    // therefore use `formula-derived` numbers and exist to exercise the
    // arithmetic paths that qemu-img cannot directly verify.
    // -----------------------------------------------------------------------

    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    #[derive(Clone, Copy)]
    struct Q2Case {
        name: &'static str,
        virtual_size: u64,
        allocated_bytes: u64,
        cluster_size: u32,
        refcount_bits: u8,
        extended_l2: bool,
        compat_v3: bool,
        preallocation: Preallocation,
        expected_required: u64,
        expected_full: u64,
    }

    const QCOW2_CASES: &[Q2Case] = &[
        // --- Empty images, default refcount_bits=16, default cluster_size sweep
        // (qemu-img sourced) ---
        Q2Case {
            name: "1M empty cs=512",
            virtual_size: MIB,
            allocated_bytes: 0,
            cluster_size: 512,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 22528,
            expected_full: 1071104,
        },
        Q2Case {
            name: "1M empty cs=4K",
            virtual_size: MIB,
            allocated_bytes: 0,
            cluster_size: 4096,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 20480,
            expected_full: 1069056,
        },
        Q2Case {
            name: "1M empty cs=64K",
            virtual_size: MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 327680,
            expected_full: 1376256,
        },
        Q2Case {
            name: "1M empty cs=2M",
            virtual_size: MIB,
            allocated_bytes: 0,
            cluster_size: 2 * 1024 * 1024,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 10485760,
            expected_full: 12582912,
        },
        Q2Case {
            name: "64M empty cs=512",
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
            cluster_size: 512,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 1337856,
            expected_full: 68446720,
        },
        Q2Case {
            name: "64M empty cs=4K",
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
            cluster_size: 4096,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 180224,
            expected_full: 67289088,
        },
        Q2Case {
            name: "64M empty cs=64K",
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 327680,
            expected_full: 67436544,
        },
        Q2Case {
            name: "64M empty cs=2M",
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
            cluster_size: 2 * 1024 * 1024,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 10485760,
            expected_full: 77594624,
        },
        Q2Case {
            name: "1G empty cs=512",
            virtual_size: GIB,
            allocated_bytes: 0,
            cluster_size: 512,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 21385216,
            expected_full: 1095127040,
        },
        Q2Case {
            name: "1G empty cs=4K",
            virtual_size: GIB,
            allocated_bytes: 0,
            cluster_size: 4096,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 2637824,
            expected_full: 1076379648,
        },
        Q2Case {
            name: "1G empty cs=64K",
            virtual_size: GIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 393216,
            expected_full: 1074135040,
        },
        Q2Case {
            name: "1G empty cs=2M",
            virtual_size: GIB,
            allocated_bytes: 0,
            cluster_size: 2 * 1024 * 1024,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 10485760,
            expected_full: 1084227584,
        },
        Q2Case {
            name: "1T empty cs=4K",
            virtual_size: TIB,
            allocated_bytes: 0,
            cluster_size: 4096,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 2690920448,
            expected_full: 1102202548224,
        },
        Q2Case {
            name: "1T empty cs=64K",
            virtual_size: TIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 168034304,
            expected_full: 1099679662080,
        },
        Q2Case {
            name: "1T empty cs=2M",
            virtual_size: TIB,
            allocated_bytes: 0,
            cluster_size: 2 * 1024 * 1024,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 12582912,
            expected_full: 1099524210688,
        },
        // --- refcount_bits=1 (3 rows, qemu-img sourced) ---
        Q2Case {
            name: "1M empty cs=64K rb=1",
            virtual_size: MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 1,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 327680,
            expected_full: 1376256,
        },
        Q2Case {
            name: "1G empty cs=64K rb=1",
            virtual_size: GIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 1,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 393216,
            expected_full: 1074135040,
        },
        Q2Case {
            name: "1T empty cs=64K rb=1",
            virtual_size: TIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 1,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 136577024,
            expected_full: 1099648204800,
        },
        // --- refcount_bits=64 (3 rows, qemu-img sourced) ---
        Q2Case {
            name: "1M empty cs=64K rb=64",
            virtual_size: MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 64,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 327680,
            expected_full: 1376256,
        },
        Q2Case {
            name: "1G empty cs=64K rb=64",
            virtual_size: GIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 64,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 524288,
            expected_full: 1074266112,
        },
        Q2Case {
            name: "1T empty cs=64K rb=64",
            virtual_size: TIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 64,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 268697600,
            expected_full: 1099780325376,
        },
        // --- extended_l2=on (3 rows, qemu-img sourced; cs>=64K required) ---
        Q2Case {
            name: "1M empty cs=64K ext_l2",
            virtual_size: MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: true,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 327680,
            expected_full: 1376256,
        },
        Q2Case {
            name: "64M empty cs=64K ext_l2",
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: true,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 327680,
            expected_full: 67436544,
        },
        Q2Case {
            name: "1G empty cs=64K ext_l2",
            virtual_size: GIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: true,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 524288,
            expected_full: 1074266112,
        },
        // --- compat=0.10 (qcow2 v2; 3 rows, qemu-img sourced — sizes match
        // v3 because qemu-img does not factor compat into measure) ---
        Q2Case {
            name: "1M empty cs=64K v2",
            virtual_size: MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: false,
            preallocation: Preallocation::Off,
            expected_required: 327680,
            expected_full: 1376256,
        },
        Q2Case {
            name: "64M empty cs=64K v2",
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: false,
            preallocation: Preallocation::Off,
            expected_required: 327680,
            expected_full: 67436544,
        },
        Q2Case {
            name: "1G empty cs=64K v2",
            virtual_size: GIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: false,
            preallocation: Preallocation::Off,
            expected_required: 393216,
            expected_full: 1074135040,
        },
        // --- preallocation=metadata (3 rows, qemu-img sourced; identical to
        // Off because all metadata is already counted in `required`) ---
        Q2Case {
            name: "1M empty cs=64K prealloc=metadata",
            virtual_size: MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Metadata,
            expected_required: 327680,
            expected_full: 1376256,
        },
        Q2Case {
            name: "64M empty cs=64K prealloc=metadata",
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Metadata,
            expected_required: 327680,
            expected_full: 67436544,
        },
        Q2Case {
            name: "1G empty cs=64K prealloc=metadata",
            virtual_size: GIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Metadata,
            expected_required: 393216,
            expected_full: 1074135040,
        },
        // --- preallocation=falloc/full (qemu-img sourced) ---
        Q2Case {
            name: "64M empty cs=64K prealloc=falloc",
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Falloc,
            expected_required: 67436544,
            expected_full: 67436544,
        },
        Q2Case {
            name: "64M empty cs=64K prealloc=full",
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Full,
            expected_required: 67436544,
            expected_full: 67436544,
        },
        // --- Fully-allocated rows (allocated_bytes == virtual_size,
        // qemu-img sourced; `required == fully_allocated` by construction) ---
        Q2Case {
            name: "64M full cs=64K",
            virtual_size: 64 * MIB,
            allocated_bytes: 64 * MIB,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 67436544,
            expected_full: 67436544,
        },
        Q2Case {
            name: "1G full cs=64K",
            virtual_size: GIB,
            allocated_bytes: GIB,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 1074135040,
            expected_full: 1074135040,
        },
        // --- Partial allocation (formula-derived; qemu-img --size only
        // emits the empty-image case) ---
        Q2Case {
            name: "64M alloc=16M cs=64K (formula-derived)",
            virtual_size: 64 * MIB,
            allocated_bytes: 16 * MIB,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 17104896,
            expected_full: 67436544,
        },
        Q2Case {
            name: "1G alloc=256M cs=64K (formula-derived)",
            virtual_size: GIB,
            allocated_bytes: 256 * MIB,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 268828672,
            expected_full: 1074135040,
        },
        Q2Case {
            name: "1G alloc=512M cs=64K (formula-derived)",
            virtual_size: GIB,
            allocated_bytes: 512 * MIB,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 537264128,
            expected_full: 1074135040,
        },
        Q2Case {
            name: "1G alloc=512M cs=4K (formula-derived)",
            virtual_size: GIB,
            allocated_bytes: 512 * MIB,
            cluster_size: 4096,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 539508736,
            expected_full: 1076379648,
        },
        Q2Case {
            name: "1M alloc=512K cs=4K (formula-derived)",
            virtual_size: MIB,
            allocated_bytes: 512 * KIB,
            cluster_size: 4096,
            refcount_bits: 16,
            extended_l2: false,
            compat_v3: true,
            preallocation: Preallocation::Off,
            expected_required: 544768,
            expected_full: 1069056,
        },
    ];

    #[test]
    fn qcow2_fixture_table() {
        for c in QCOW2_CASES {
            let s = AllocationSummary {
                virtual_size: c.virtual_size,
                allocated_bytes: c.allocated_bytes,
            };
            let opts = Qcow2Opts {
                cluster_size: c.cluster_size,
                refcount_bits: c.refcount_bits,
                extended_l2: c.extended_l2,
                compat_v3: c.compat_v3,
                preallocation: c.preallocation,
                ..Qcow2Opts::default()
            };
            let m =
                measure_qcow2(&s, &opts).unwrap_or_else(|e| panic!("{}: error {:?}", c.name, e));
            assert_eq!(
                m.required, c.expected_required,
                "{}: required got {} expected {}",
                c.name, m.required, c.expected_required
            );
            assert_eq!(
                m.fully_allocated, c.expected_full,
                "{}: fully_allocated got {} expected {}",
                c.name, m.fully_allocated, c.expected_full
            );
            assert!(
                m.required <= m.fully_allocated,
                "{}: required > fully_allocated",
                c.name
            );
        }
    }

    #[test]
    fn qcow2_fixture_count() {
        // Pin the row count so that accidental table truncations show up
        // as a test failure instead of a silent regression.
        assert!(
            QCOW2_CASES.len() >= 30,
            "fixture table should have at least 30 rows, got {}",
            QCOW2_CASES.len()
        );
    }

    // --- Option validation ---------------------------------------------------

    #[test]
    fn qcow2_invalid_cluster_size_not_power_of_two() {
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts {
            cluster_size: 1023,
            ..Qcow2Opts::default()
        };
        assert_eq!(measure_qcow2(&s, &opts), Err(MeasureError::InvalidOption));
    }

    #[test]
    fn qcow2_invalid_cluster_size_too_small() {
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts {
            cluster_size: 256,
            ..Qcow2Opts::default()
        };
        assert_eq!(measure_qcow2(&s, &opts), Err(MeasureError::InvalidOption));
    }

    #[test]
    fn qcow2_invalid_cluster_size_too_large() {
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts {
            cluster_size: 4 * 1024 * 1024,
            ..Qcow2Opts::default()
        };
        assert_eq!(measure_qcow2(&s, &opts), Err(MeasureError::InvalidOption));
    }

    #[test]
    fn qcow2_invalid_refcount_bits() {
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts {
            refcount_bits: 3,
            ..Qcow2Opts::default()
        };
        assert_eq!(measure_qcow2(&s, &opts), Err(MeasureError::InvalidOption));
    }

    #[test]
    fn qcow2_invalid_refcount_bits_zero() {
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts {
            refcount_bits: 0,
            ..Qcow2Opts::default()
        };
        assert_eq!(measure_qcow2(&s, &opts), Err(MeasureError::InvalidOption));
    }

    #[test]
    fn qcow2_extended_l2_requires_v3() {
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts {
            extended_l2: true,
            compat_v3: false,
            ..Qcow2Opts::default()
        };
        assert_eq!(measure_qcow2(&s, &opts), Err(MeasureError::InvalidOption));
    }

    #[test]
    fn qcow2_virtual_size_above_2_pow_63() {
        let s = AllocationSummary {
            virtual_size: (1u64 << 63) + 1,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts::default();
        assert_eq!(measure_qcow2(&s, &opts), Err(MeasureError::InvalidSize));
    }

    #[test]
    fn qcow2_virtual_size_at_cap_does_not_error_immediately() {
        // 2^63 itself is permitted by the size validator (it is the cap).
        // The actual measurement may overflow downstream depending on
        // cluster_size; here we only confirm that the size check itself
        // does not reject it.
        let s = AllocationSummary {
            virtual_size: 1u64 << 63,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts::default();
        // The default 64 KiB cluster yields a manageable total here.
        let m = measure_qcow2(&s, &opts).expect("2^63 with cs=64K should compute");
        assert!(m.fully_allocated >= s.virtual_size);
    }

    #[test]
    fn qcow2_allocated_above_virtual() {
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: MIB + 1,
        };
        let opts = Qcow2Opts::default();
        assert_eq!(measure_qcow2(&s, &opts), Err(MeasureError::InvalidSize));
    }

    #[test]
    fn qcow2_overflow_above_u64_max() {
        // virtual_size = u64::MAX is well above the 2^63 qcow2 cap; the
        // size validator rejects it before any arithmetic runs. This is
        // the documented behaviour: qcow2 caps at 2^63 and reports
        // `InvalidSize` rather than `Overflow` for inputs above that cap.
        let s = AllocationSummary {
            virtual_size: u64::MAX,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts {
            cluster_size: 512,
            ..Qcow2Opts::default()
        };
        assert_eq!(measure_qcow2(&s, &opts), Err(MeasureError::InvalidSize));
    }

    #[test]
    fn qcow2_max_virtual_size_with_small_cluster() {
        // 2^63 with cs=512 sits at the upper end of valid inputs. The
        // arithmetic must complete without overflow because every
        // intermediate is bounded by the 2^63 cap.
        let s = AllocationSummary {
            virtual_size: 1u64 << 63,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts {
            cluster_size: 512,
            ..Qcow2Opts::default()
        };
        let m = measure_qcow2(&s, &opts).expect("2^63 with cs=512 must compute");
        // Sanity: fully_allocated must cover the virtual range plus all
        // metadata.
        assert!(m.fully_allocated >= s.virtual_size);
        assert!(m.required <= m.fully_allocated);
    }

    #[test]
    fn qcow2_zero_virtual_size() {
        // Empty virtual range: no L1, no L2, no data; just header + minimal
        // refcount table.
        let s = AllocationSummary {
            virtual_size: 0,
            allocated_bytes: 0,
        };
        let opts = Qcow2Opts::default();
        let m = measure_qcow2(&s, &opts).expect("zero-virtual-size must compute");
        // header(1) + refblock(1) + reftable(1) = 3 clusters at default 64 KiB.
        assert_eq!(m.required, 3 * 65536);
        assert_eq!(m.fully_allocated, 3 * 65536);
    }

    #[test]
    fn qcow2_luks_header_overhead() {
        // 1 MiB LUKS header. Cluster size 64 KiB, so the LUKS header
        // occupies 16 additional clusters added to both required and
        // fully_allocated. Compare to the no-LUKS baseline for 64M empty.
        let s = AllocationSummary {
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
        };
        let baseline_opts = Qcow2Opts::default();
        let baseline = measure_qcow2(&s, &baseline_opts).unwrap();

        let luks_opts = Qcow2Opts {
            luks_header_overhead: Some(MIB),
            ..Qcow2Opts::default()
        };
        let luks = measure_qcow2(&s, &luks_opts).unwrap();
        assert_eq!(
            luks.required,
            baseline.required + 16 * 65536,
            "LUKS adds 16 clusters to required"
        );
        assert_eq!(
            luks.fully_allocated,
            baseline.fully_allocated + 16 * 65536,
            "LUKS adds 16 clusters to fully_allocated"
        );
    }

    #[test]
    fn qcow2_luks_header_partial_cluster() {
        // 100 KiB rounds up to 2 * 64 KiB clusters.
        let s = AllocationSummary {
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
        };
        let baseline = measure_qcow2(&s, &Qcow2Opts::default()).unwrap();
        let opts = Qcow2Opts {
            luks_header_overhead: Some(100 * KIB),
            ..Qcow2Opts::default()
        };
        let with_luks = measure_qcow2(&s, &opts).unwrap();
        assert_eq!(with_luks.required, baseline.required + 2 * 65536);
    }

    #[test]
    fn qcow2_luks_header_zero_is_noop() {
        // `Some(0)` is treated like `None` — no LUKS clusters added.
        let s = AllocationSummary {
            virtual_size: 64 * MIB,
            allocated_bytes: 0,
        };
        let baseline = measure_qcow2(&s, &Qcow2Opts::default()).unwrap();
        let opts = Qcow2Opts {
            luks_header_overhead: Some(0),
            ..Qcow2Opts::default()
        };
        let with_luks = measure_qcow2(&s, &opts).unwrap();
        assert_eq!(with_luks, baseline);
    }

    #[test]
    fn qcow2_compress_does_not_alter_size() {
        let s = AllocationSummary {
            virtual_size: 64 * MIB,
            allocated_bytes: 16 * MIB,
        };
        let off = Qcow2Opts::default();
        let on = Qcow2Opts {
            compress: true,
            ..Qcow2Opts::default()
        };
        assert_eq!(measure_qcow2(&s, &off), measure_qcow2(&s, &on));
    }

    #[test]
    fn qcow2_lazy_refcounts_does_not_alter_size() {
        let s = AllocationSummary {
            virtual_size: 64 * MIB,
            allocated_bytes: 16 * MIB,
        };
        let off = Qcow2Opts::default();
        let on = Qcow2Opts {
            lazy_refcounts: true,
            ..Qcow2Opts::default()
        };
        assert_eq!(measure_qcow2(&s, &off), measure_qcow2(&s, &on));
    }

    #[test]
    fn qcow2_metadata_equals_off_for_empty() {
        // Metadata preallocation is a no-op vs Off because all metadata
        // clusters are already in `required` (qemu-img semantics).
        let s = AllocationSummary {
            virtual_size: GIB,
            allocated_bytes: 0,
        };
        let off = Qcow2Opts::default();
        let meta = Qcow2Opts {
            preallocation: Preallocation::Metadata,
            ..Qcow2Opts::default()
        };
        assert_eq!(measure_qcow2(&s, &off), measure_qcow2(&s, &meta));
    }

    #[test]
    fn qcow2_falloc_equals_full_required_equals_fully_allocated() {
        let s = AllocationSummary {
            virtual_size: GIB,
            allocated_bytes: 256 * MIB,
        };
        let falloc = Qcow2Opts {
            preallocation: Preallocation::Falloc,
            ..Qcow2Opts::default()
        };
        let full = Qcow2Opts {
            preallocation: Preallocation::Full,
            ..Qcow2Opts::default()
        };
        let m_falloc = measure_qcow2(&s, &falloc).unwrap();
        let m_full = measure_qcow2(&s, &full).unwrap();
        assert_eq!(m_falloc, m_full);
        assert_eq!(m_falloc.required, m_falloc.fully_allocated);
    }

    // -----------------------------------------------------------------------
    // VMDK tests
    //
    // All expected values are formula-derived (qemu-img does not support
    // `measure -O vmdk`). See `measure_vmdk` doc-comment for the formula.
    //
    // Constants used throughout:
    //   DESC_SECTORS = 20  → descriptor = 20 × 512 = 10240 bytes
    //   header = 512 bytes
    //   grain_data_start = 512 + 10240 = 10752 bytes
    //   gtes_per_gt = 512
    //   gt_bytes = 512 × 4 = 2048 bytes; round_up(2048, 512) = 2048
    //
    // -----------------------------------------------------------------------

    // --- MonolithicSparse cases ---

    #[test]
    fn vmdk_mono_sparse_1m_64k_empty() {
        // MonolithicSparse, 1M virtual, 64K grain, empty (allocated=0).
        //
        // capacity_sectors = ceil(1M / 512) = 2048
        // grain_size_sectors = 65536 / 512 = 128
        // total_grains = ceil(2048 / 128) = 16
        // num_gd_entries = ceil(16 / 512) = 1
        // gd_bytes = 1×4 = 4; round_up(4, 512) = 512
        // allocated_grains_required = ceil(0 / 65536) = 0
        //
        // required = 10752 + 0×65536 + 1×2048 + 512
        //          = 10752 + 2048 + 512 = 13312
        //
        // allocated_grains_full = 16
        // fully_allocated = 10752 + 16×65536 + 1×2048 + 512
        //                 = 10752 + 1048576 + 2048 + 512 = 1061888
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::MonolithicSparse,
            grain_size: 65536,
        };
        let m = measure_vmdk(&s, &opts).unwrap();
        assert_eq!(m.required, 13312, "required");
        assert_eq!(m.fully_allocated, 1061888, "fully_allocated");
    }

    #[test]
    fn vmdk_mono_sparse_1g_64k_empty() {
        // MonolithicSparse, 1G virtual, 64K grain, empty (allocated=0).
        //
        // capacity_sectors = ceil(1G / 512) = 2097152
        // grain_size_sectors = 128
        // total_grains = ceil(2097152 / 128) = 16384
        // num_gd_entries = ceil(16384 / 512) = 32
        // gd_bytes = 32×4 = 128; round_up(128, 512) = 512
        // allocated_grains_required = 0
        //
        // required = 10752 + 0 + 32×2048 + 512
        //          = 10752 + 65536 + 512 = 76800
        //
        // allocated_grains_full = 16384
        // fully_allocated = 10752 + 16384×65536 + 32×2048 + 512
        //                 = 10752 + 1073741824 + 65536 + 512 = 1073818624
        let s = AllocationSummary {
            virtual_size: GIB,
            allocated_bytes: 0,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::MonolithicSparse,
            grain_size: 65536,
        };
        let m = measure_vmdk(&s, &opts).unwrap();
        assert_eq!(m.required, 76800, "required");
        assert_eq!(m.fully_allocated, 1073818624, "fully_allocated");
    }

    #[test]
    fn vmdk_mono_sparse_1g_4k_full() {
        // MonolithicSparse, 1G virtual, 4K grain, fully allocated.
        //
        // capacity_sectors = 2097152
        // grain_size_sectors = 4096 / 512 = 8
        // total_grains = ceil(2097152 / 8) = 262144
        // num_gd_entries = ceil(262144 / 512) = 512
        // gd_bytes = 512×4 = 2048; round_up(2048, 512) = 2048
        // allocated_grains_required = ceil(1G / 4096) = 262144
        //
        // required = 10752 + 262144×4096 + 512×2048 + 2048
        //          = 10752 + 1073741824 + 1048576 + 2048 = 1074803200
        // fully_allocated = required (all grains allocated)
        let s = AllocationSummary {
            virtual_size: GIB,
            allocated_bytes: GIB,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::MonolithicSparse,
            grain_size: 4096,
        };
        let m = measure_vmdk(&s, &opts).unwrap();
        assert_eq!(m.required, 1074803200, "required");
        assert_eq!(m.fully_allocated, 1074803200, "fully_allocated");
        assert_eq!(m.required, m.fully_allocated);
    }

    // --- StreamOptimized cases ---
    //
    // Per-grain cost (worst-case incompressible):
    //   round_up(GRAIN_MARKER_SIZE(12) + grain_size, 512) = grain_size + 512
    //   (because grain_size is ≥ 512 and a multiple of 512, so the 12-byte
    //   preamble pushes into an extra sector)
    //
    // Per-GT cost: GT_marker(512) + round_up(gt_bytes=2048, 512) = 512+2048 = 2560
    //
    // GD cost: GD_marker(512) + max(round_up(gd_bytes, 512), 512)
    //
    // Total = round_up(grain_data_start + grains_cost + all_gts_cost + gd_cost
    //                  + 1536 [footer tail], 65536 [MAX_SECTOR_SIZE])

    #[test]
    fn vmdk_stream_optimized_1m_64k_empty() {
        // StreamOptimized, 1M virtual, 64K grain, empty (allocated=0).
        //
        // grain_data_start = 10752
        // num_gd_entries = 1; gd_bytes=4; round_up(4,512)=512
        // grains_cost = 0×(65536+512) = 0
        // all_gts_cost = 1×(512+2048) = 2560
        // gd_cost = 512 + 512 = 1024
        //
        // pre_footer = 10752 + 0 + 2560 + 1024 = 14336
        // total = round_up(14336 + 1536, 65536) = round_up(15872, 65536) = 65536
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::StreamOptimized,
            grain_size: 65536,
        };
        let m = measure_vmdk(&s, &opts).unwrap();
        assert_eq!(m.required, 65536, "required");
        // fully_allocated:
        // allocated_grains_full = 16
        // grains_cost_full = 16×(65536+512) = 16×66048 = 1056768
        // pre_footer_full = 10752 + 1056768 + 2560 + 1024 = 1071104
        // total_full = round_up(1071104+1536, 65536) = round_up(1072640, 65536)
        //   1072640 / 65536 = 16.366... → ceil = 17 → 17×65536 = 1114112
        assert_eq!(m.fully_allocated, 1114112, "fully_allocated");
    }

    #[test]
    fn vmdk_stream_optimized_1g_64k_partial() {
        // StreamOptimized, 1G virtual, 64K grain, partial (allocated=512K).
        //
        // grain_data_start = 10752
        // capacity_sectors = 2097152; total_grains = 16384
        // num_gd_entries = 32; gd_bytes=128; round_up(128,512)=512
        // allocated_grains_required = ceil(512K / 64K) = 8
        // grains_cost_required = 8×(65536+512) = 8×66048 = 528384
        // all_gts_cost = 32×(512+2048) = 32×2560 = 81920
        // gd_cost = 512 + 512 = 1024
        //
        // pre_footer_required = 10752 + 528384 + 81920 + 1024 = 622080
        // required = round_up(622080+1536, 65536) = round_up(623616, 65536)
        //   623616 / 65536 = 9.51... → ceil = 10 → 10×65536 = 655360
        //
        // allocated_grains_full = 16384
        // grains_cost_full = 16384×(65536+512) = 16384×66048 = 1082130432
        // pre_footer_full = 10752 + 1082130432 + 81920 + 1024 = 1082224128
        // fully_allocated = round_up(1082224128+1536, 65536)
        //   = round_up(1082225664, 65536)
        //   1082225664 / 65536 = 16513.0... let's check: 16513×65536 = ?
        //   16000×65536 = 1048576000; 513×65536 = 33619968
        //   16513×65536 = 1048576000+33619968 = 1082195968 ≠ 1082225664
        //   1082225664 / 65536 = 16513.49... → ceil = 16514
        //   16514×65536 = 1082195968 + 65536 = 1082261504
        let s = AllocationSummary {
            virtual_size: GIB,
            allocated_bytes: 512 * KIB,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::StreamOptimized,
            grain_size: 65536,
        };
        let m = measure_vmdk(&s, &opts).unwrap();
        assert_eq!(m.required, 655360, "required");
        assert_eq!(m.fully_allocated, 1082261504, "fully_allocated");
    }

    #[test]
    fn vmdk_stream_optimized_1g_4k_full() {
        // StreamOptimized, 1G virtual, 4K grain, fully allocated.
        //
        // grain_data_start = 10752
        // capacity_sectors = 2097152
        // grain_size_sectors = 8; total_grains = 262144
        // num_gd_entries = 512; gd_bytes=2048; round_up(2048,512)=2048
        // allocated_grains = 262144 (full)
        // grains_cost = 262144×(4096+512) = 262144×4608 = 1207959552
        // all_gts_cost = 512×(512+2048) = 512×2560 = 1310720
        // gd_cost = 512 + 2048 = 2560
        //
        // pre_footer = 10752 + 1207959552 + 1310720 + 2560 = 1209283584
        // total = round_up(1209283584+1536, 65536) = round_up(1209285120, 65536)
        //   1209285120 / 65536 = ?
        //   65536 × 18452 = 65536 × 18000 + 65536 × 452
        //                 = 1179648000 + 29622272 = 1209270272
        //   1209270272 < 1209285120 → need 18453
        //   18453 × 65536 = 1209270272 + 65536 = 1209335808
        //   1209335808 >= 1209285120+1536=1209286656 ✓
        let s = AllocationSummary {
            virtual_size: GIB,
            allocated_bytes: GIB,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::StreamOptimized,
            grain_size: 4096,
        };
        let m = measure_vmdk(&s, &opts).unwrap();
        assert_eq!(m.required, 1209335808, "required");
        assert_eq!(m.fully_allocated, 1209335808, "fully_allocated");
        assert_eq!(m.required, m.fully_allocated);
    }

    // --- MonolithicFlat cases ---

    #[test]
    fn vmdk_mono_flat_1m() {
        // MonolithicFlat, 1M virtual (grain_size irrelevant for flat).
        //
        // required = descriptor(512) + virtual_size(1M)
        //          = 512 + 1048576 = 1049088
        // fully_allocated = required (flat is always dense)
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::MonolithicFlat,
            grain_size: 65536,
        };
        let m = measure_vmdk(&s, &opts).unwrap();
        assert_eq!(m.required, 1049088);
        assert_eq!(m.fully_allocated, 1049088);
        assert_eq!(m.required, m.fully_allocated);
    }

    #[test]
    fn vmdk_mono_flat_1g() {
        // MonolithicFlat, 1G virtual.
        //
        // required = 512 + 1G = 512 + 1073741824 = 1073742336
        let s = AllocationSummary {
            virtual_size: GIB,
            allocated_bytes: GIB,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::MonolithicFlat,
            grain_size: 65536,
        };
        let m = measure_vmdk(&s, &opts).unwrap();
        assert_eq!(m.required, 1073742336);
        assert_eq!(m.fully_allocated, 1073742336);
    }

    #[test]
    fn vmdk_mono_flat_64m() {
        // MonolithicFlat, 64M virtual, 4K grain (grain_size irrelevant).
        //
        // required = 512 + 64M = 512 + 67108864 = 67109376
        let s = AllocationSummary {
            virtual_size: 64 * MIB,
            allocated_bytes: 32 * MIB,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::MonolithicFlat,
            grain_size: 4096,
        };
        let m = measure_vmdk(&s, &opts).unwrap();
        assert_eq!(m.required, 67109376);
        assert_eq!(m.fully_allocated, 67109376);
    }

    // --- VMDK option validation tests ---

    #[test]
    fn vmdk_grain_size_8192_is_valid() {
        // 8192 is in [4096, 65536] and is a power of two — must succeed.
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::MonolithicSparse,
            grain_size: 8192,
        };
        assert!(measure_vmdk(&s, &opts).is_ok());
    }

    #[test]
    fn vmdk_grain_size_2048_is_invalid() {
        // 2048 < 4096 — below the floor.
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::MonolithicSparse,
            grain_size: 2048,
        };
        assert_eq!(measure_vmdk(&s, &opts), Err(MeasureError::InvalidOption));
    }

    #[test]
    fn vmdk_grain_size_131072_is_invalid() {
        // 131072 > 65536 — above the ceiling.
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::MonolithicSparse,
            grain_size: 131072,
        };
        assert_eq!(measure_vmdk(&s, &opts), Err(MeasureError::InvalidOption));
    }

    #[test]
    fn vmdk_grain_size_12288_is_invalid() {
        // 12288 is in [4096, 65536] but is NOT a power of two.
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: 0,
        };
        let opts = VmdkOpts {
            subformat: VmdkSubformat::MonolithicSparse,
            grain_size: 12288,
        };
        assert_eq!(measure_vmdk(&s, &opts), Err(MeasureError::InvalidOption));
    }

    #[test]
    fn vmdk_allocated_above_virtual_is_invalid() {
        let s = AllocationSummary {
            virtual_size: MIB,
            allocated_bytes: MIB + 1,
        };
        let opts = VmdkOpts::default();
        assert_eq!(measure_vmdk(&s, &opts), Err(MeasureError::InvalidSize));
    }

    // --- VMDK invariant checks ---

    #[test]
    fn vmdk_invariant_required_le_fully_allocated() {
        // For all subformats and a spread of sizes/allocations,
        // required <= fully_allocated must hold.
        let sizes = [MIB, 64 * MIB, GIB];
        let grains = [4096u32, 8192, 16384, 32768, 65536];
        let subformats = [
            VmdkSubformat::MonolithicSparse,
            VmdkSubformat::StreamOptimized,
            VmdkSubformat::MonolithicFlat,
        ];
        for &vs in &sizes {
            for &gs in &grains {
                for &sf in &subformats {
                    let s = AllocationSummary {
                        virtual_size: vs,
                        allocated_bytes: vs / 2,
                    };
                    let opts = VmdkOpts {
                        subformat: sf,
                        grain_size: gs,
                    };
                    let m = measure_vmdk(&s, &opts)
                        .unwrap_or_else(|e| panic!("vmdk invariant vs={vs} gs={gs}: {e:?}"));
                    assert!(
                        m.required <= m.fully_allocated,
                        "required > fully_allocated: vs={vs} gs={gs}"
                    );
                    assert!(
                        m.fully_allocated >= vs,
                        "fully_allocated < virtual_size: vs={vs} gs={gs}"
                    );
                }
            }
        }
    }
}
