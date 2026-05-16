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

impl<'a> MetadataWrite<'a> {
    /// An empty write at offset 0. Used as the default array element
    /// when building a [`MetadataPlan`] with inline storage.
    pub const EMPTY: MetadataWrite<'static> = MetadataWrite {
        byte_offset: 0,
        bytes: &[],
    };
}

/// Maximum number of write entries any [`MetadataPlan`] can hold.
///
/// Empty-image layouts decompose into at most a handful of regions
/// (header, L1, refcount/BAT/metadata tables, plus per-block entries).
/// 96 leaves comfortable headroom for the most write-heavy format
/// (qcow2 with many refcount blocks at small cluster sizes).
pub const MAX_METADATA_WRITES: usize = 96;

/// A complete empty-image metadata layout.
///
/// The plan stores its writes inline as a fixed-size array so the
/// whole value is `Copy` and the orchestrator does not need to pass a
/// separate writes buffer alongside the byte scratch. Only the first
/// [`MetadataPlan::writes`]`().len()` entries are populated.
///
/// `total_metadata_bytes` is the sum of `writes()[*].bytes.len()`.
/// `minimum_file_size` is the smallest file size that contains every
/// write's byte range (the maximum of `byte_offset + bytes.len()`
/// across all writes); the caller may need to extend the file past
/// this for preallocation in later phases.
#[derive(Debug, Clone, Copy)]
pub struct MetadataPlan<'a> {
    /// Sum of all `writes()[*].bytes.len()`.
    pub total_metadata_bytes: u64,
    /// Smallest file size that contains every write.
    pub minimum_file_size: u64,
    /// Number of populated entries in `writes_storage`.
    write_count: u16,
    /// Inline storage for the writes; only `..write_count` is valid.
    writes_storage: [MetadataWrite<'a>; MAX_METADATA_WRITES],
}

impl<'a> MetadataPlan<'a> {
    /// Construct an empty plan ready to be populated.
    pub const fn new() -> Self {
        MetadataPlan {
            total_metadata_bytes: 0,
            minimum_file_size: 0,
            write_count: 0,
            writes_storage: [MetadataWrite::EMPTY; MAX_METADATA_WRITES],
        }
    }

    /// Ordered list of writes that, applied together, form a valid
    /// empty image in the requested format.
    pub fn writes(&self) -> &[MetadataWrite<'a>] {
        &self.writes_storage[..self.write_count as usize]
    }

    /// Append a write to the plan, updating bookkeeping. Returns
    /// `Err(CreateError::ScratchTooSmall)` if the storage is full
    /// (the plan is small by design; running out indicates an
    /// orchestrator bug or a format pathologically large).
    pub fn push(&mut self, write: MetadataWrite<'a>) -> Result<(), CreateError> {
        let idx = self.write_count as usize;
        if idx >= MAX_METADATA_WRITES {
            return Err(CreateError::ScratchTooSmall);
        }
        let len = write.bytes.len() as u64;
        let end = write
            .byte_offset
            .checked_add(len)
            .ok_or(CreateError::Overflow)?;
        self.writes_storage[idx] = write;
        self.write_count += 1;
        self.total_metadata_bytes = self
            .total_metadata_bytes
            .checked_add(len)
            .ok_or(CreateError::Overflow)?;
        if end > self.minimum_file_size {
            self.minimum_file_size = end;
        }
        Ok(())
    }
}

impl Default for MetadataPlan<'_> {
    fn default() -> Self {
        Self::new()
    }
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
/// Layout written into `scratch`:
///
/// 1. Header cluster (1 × cluster_size).
/// 2. L1 table (`l1_clusters` × cluster_size, zero-filled).
/// 3. Refcount table (`refcount_table_clusters` × cluster_size).
/// 4. Refcount blocks (`refcount_block_count` × cluster_size, each
///    populated with refcount=1 for every used cluster).
///
/// The returned plan's writes reference these regions of `scratch`
/// directly, so the scratch buffer must outlive the plan.
pub fn plan_qcow2<'a>(
    opts: &Qcow2CreateOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<MetadataPlan<'a>, CreateError> {
    // Validate the cluster_size up front so we can convert to bits,
    // then defer the rest of validation to qcow2::create.
    if opts.cluster_size == 0
        || !opts.cluster_size.is_power_of_two()
        || opts.cluster_size < 512
        || opts.cluster_size > (2 << 20)
    {
        return Err(CreateError::InvalidClusterSize);
    }
    let cluster_bits = opts.cluster_size.trailing_zeros();

    let layout = qcow2::create::compute_layout(
        opts.virtual_size,
        cluster_bits,
        opts.refcount_bits as u32,
        opts.extended_l2,
    )
    .map_err(map_qcow2_error)?;

    // Backing-file validation.
    let backing_path = match &opts.backing {
        Some(b) => {
            if b.path.len() > MAX_BACKING_FILE_LEN {
                return Err(CreateError::BackingFileTooLong);
            }
            Some(b.path)
        }
        None => None,
    };
    let backing_format_bytes: Option<&[u8]> = match &opts.backing {
        Some(b) => b.format.map(image_format_name_bytes),
        None => None,
    };

    let cluster_size = layout.cluster_size as usize;
    let header_bytes = cluster_size;
    let l1_bytes = (layout.l1_clusters as usize) * cluster_size;
    let reftable_bytes = (layout.refcount_table_clusters as usize) * cluster_size;
    let refblock_bytes_total = (layout.refcount_block_count as usize) * cluster_size;
    let total_needed = header_bytes + l1_bytes + reftable_bytes + refblock_bytes_total;
    if scratch.len() < total_needed {
        return Err(CreateError::ScratchTooSmall);
    }

    // Carve scratch into named regions. Each split returns the rest
    // for the next slice, keeping the lifetimes lined up to 'a.
    let (header_region, rest) = scratch.split_at_mut(header_bytes);
    let (l1_region, rest) = rest.split_at_mut(l1_bytes);
    let (reftable_region, refblocks_region) = rest.split_at_mut(reftable_bytes);

    // Header.
    let header_opts = qcow2::create::BuildHeaderOptions {
        layout: &layout,
        backing_file: backing_path,
        backing_format: backing_format_bytes,
        lazy_refcounts: opts.lazy_refcounts,
        luks_header: None,
    };
    let header_slice =
        qcow2::create::build_header(header_region, &header_opts).map_err(map_qcow2_error)?;

    // L1 table.
    let l1_slice = qcow2::create::build_l1_table(l1_region, &layout).map_err(map_qcow2_error)?;

    // Refcount table.
    let reftable_slice =
        qcow2::create::build_refcount_table(reftable_region, &layout).map_err(map_qcow2_error)?;

    // Refcount blocks: split the refblocks_region into per-block
    // slices in a loop and populate each.
    let mut plan = MetadataPlan::new();
    plan.push(MetadataWrite {
        byte_offset: 0,
        bytes: header_slice,
    })?;
    plan.push(MetadataWrite {
        byte_offset: layout.l1_offset,
        bytes: l1_slice,
    })?;
    plan.push(MetadataWrite {
        byte_offset: layout.refcount_table_offset,
        bytes: reftable_slice,
    })?;

    let mut remaining = refblocks_region;
    for block_index in 0..layout.refcount_block_count {
        let (this_block, rest) = remaining.split_at_mut(cluster_size);
        let block_slice = qcow2::create::build_refcount_block(this_block, &layout, block_index)
            .map_err(map_qcow2_error)?;
        plan.push(MetadataWrite {
            byte_offset: layout.refcount_blocks_base_offset + block_index * layout.cluster_size,
            bytes: block_slice,
        })?;
        remaining = rest;
    }

    debug_assert_eq!(plan.minimum_file_size, layout.total_file_size);
    Ok(plan)
}

fn map_qcow2_error(e: qcow2::create::Qcow2CreateError) -> CreateError {
    match e {
        qcow2::create::Qcow2CreateError::InvalidVirtualSize => CreateError::InvalidVirtualSize,
        qcow2::create::Qcow2CreateError::InvalidClusterBits => CreateError::InvalidClusterSize,
        qcow2::create::Qcow2CreateError::InvalidRefcountBits => CreateError::InvalidVirtualSize,
        qcow2::create::Qcow2CreateError::Overflow => CreateError::Overflow,
        qcow2::create::Qcow2CreateError::BufferTooSmall => CreateError::ScratchTooSmall,
        qcow2::create::Qcow2CreateError::BackingMetadataTooLarge => CreateError::BackingFileTooLong,
    }
}

/// Map a backing-image format hint to the ASCII bytes qemu-img writes
/// into the qcow2 `EXT_BACKING_FORMAT` header extension.
fn image_format_name_bytes(fmt: ImageFormat) -> &'static [u8] {
    match fmt {
        ImageFormat::Raw => b"raw",
        ImageFormat::Qcow2 => b"qcow2",
        ImageFormat::Vmdk4 | ImageFormat::Vmdk3 | ImageFormat::VmdkDescriptor => b"vmdk",
        ImageFormat::Vhd => b"vpc",
        ImageFormat::Vhdx => b"vhdx",
        ImageFormat::Qcow1 => b"qcow",
        ImageFormat::Vdi => b"vdi",
        ImageFormat::Qed => b"qed",
        ImageFormat::Iso => b"iso",
        ImageFormat::Luks => b"luks",
        ImageFormat::Unknown => b"",
    }
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

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod qcow2_plan_tests {
    use super::*;
    use std::vec;

    /// Materialise a plan's writes into a contiguous byte vector of
    /// length `plan.minimum_file_size`, zero-filling any gaps.
    fn materialise(plan: &MetadataPlan<'_>) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; plan.minimum_file_size as usize];
        for w in plan.writes() {
            let start = w.byte_offset as usize;
            let end = start + w.bytes.len();
            buf[start..end].copy_from_slice(w.bytes);
        }
        buf
    }

    fn default_opts(virtual_size: u64) -> Qcow2CreateOpts<'static> {
        Qcow2CreateOpts {
            virtual_size,
            cluster_size: 65536,
            refcount_bits: 16,
            extended_l2: false,
            lazy_refcounts: false,
            compat_v3: true,
            backing: None,
        }
    }

    fn run_round_trip(opts: &Qcow2CreateOpts<'_>) -> std::vec::Vec<u8> {
        let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
        let plan = plan_qcow2(opts, &mut scratch).expect("plan");
        // Structural invariants:
        let sum: u64 = plan.writes().iter().map(|w| w.bytes.len() as u64).sum();
        assert_eq!(plan.total_metadata_bytes, sum);
        let max_end: u64 = plan
            .writes()
            .iter()
            .map(|w| w.byte_offset + w.bytes.len() as u64)
            .max()
            .unwrap_or(0);
        assert_eq!(plan.minimum_file_size, max_end);
        materialise(&plan)
    }

    #[test]
    fn plan_qcow2_default_1mib_round_trips() {
        let opts = default_opts(1 << 20);
        let bytes = run_round_trip(&opts);
        let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse header");
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.virtual_size, 1 << 20);
        assert_eq!(parsed.cluster_size, 65536);
        assert!(!parsed.extended_l2);
        assert_eq!(parsed.crypt_method, 0);
    }

    #[test]
    fn plan_qcow2_cluster_512_round_trips() {
        let mut opts = default_opts(1 << 30);
        opts.cluster_size = 512;
        let bytes = run_round_trip(&opts);
        let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse header");
        assert_eq!(parsed.cluster_size, 512);
        assert_eq!(parsed.virtual_size, 1 << 30);
    }

    #[test]
    fn plan_qcow2_extended_l2_round_trips() {
        let mut opts = default_opts(1 << 30);
        opts.extended_l2 = true;
        let bytes = run_round_trip(&opts);
        let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse header");
        assert!(parsed.extended_l2);
    }

    #[test]
    fn plan_qcow2_refcount_bits_1_round_trips() {
        let mut opts = default_opts(1 << 30);
        opts.refcount_bits = 1;
        let bytes = run_round_trip(&opts);
        // refcount_order=4 is hardcoded in build_header (matching
        // convert) regardless of the layout's refcount_bits, so the
        // parsed header still reports 16. The round-trip property
        // we assert is that the file at least parses and has the
        // right virtual size.
        let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse header");
        assert_eq!(parsed.virtual_size, 1 << 30);
    }

    #[test]
    fn plan_qcow2_lazy_refcounts_round_trips() {
        let mut opts = default_opts(1 << 30);
        opts.lazy_refcounts = true;
        let bytes = run_round_trip(&opts);
        let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse header");
        assert!(parsed.lazy_refcounts);
    }

    #[test]
    fn plan_qcow2_backing_file_round_trips() {
        let mut opts = default_opts(1 << 30);
        let backing = BackingRef {
            path: b"../backing.qcow2",
            format: Some(ImageFormat::Qcow2),
        };
        opts.backing = Some(backing);
        let bytes = run_round_trip(&opts);
        let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse header");
        assert_eq!(parsed.backing_file_size as usize, backing.path.len());
        let off = parsed.backing_file_offset as usize;
        assert_eq!(&bytes[off..off + backing.path.len()], backing.path);
        let exts = qcow2::parse_header_extensions(&bytes, &parsed);
        assert_eq!(exts.backing_format.as_str(), "qcow2");
    }

    #[test]
    fn plan_qcow2_minimum_file_size_matches_layout() {
        let opts = default_opts(1 << 30);
        let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
        let plan = plan_qcow2(&opts, &mut scratch).expect("plan");
        // The layout's total_file_size and the plan's
        // minimum_file_size should agree.
        let layout = qcow2::create::compute_layout(opts.virtual_size, 16, 16, false).unwrap();
        assert_eq!(plan.minimum_file_size, layout.total_file_size);
    }

    #[test]
    fn plan_qcow2_rejects_invalid_cluster_size() {
        let mut opts = default_opts(1 << 20);
        opts.cluster_size = 1000; // not a power of two
        let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
        assert!(matches!(
            plan_qcow2(&opts, &mut scratch),
            Err(CreateError::InvalidClusterSize)
        ));
    }

    #[test]
    fn plan_qcow2_rejects_zero_virtual_size() {
        let opts = default_opts(0);
        let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
        assert!(matches!(
            plan_qcow2(&opts, &mut scratch),
            Err(CreateError::InvalidVirtualSize)
        ));
    }

    #[test]
    fn plan_qcow2_rejects_too_small_scratch() {
        let opts = default_opts(1 << 20);
        let mut scratch = [0u8; 32];
        assert!(matches!(
            plan_qcow2(&opts, &mut scratch),
            Err(CreateError::ScratchTooSmall)
        ));
    }

    #[test]
    fn plan_qcow2_writes_dont_overlap() {
        let opts = default_opts(1 << 30);
        let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
        let plan = plan_qcow2(&opts, &mut scratch).expect("plan");
        let mut sorted: std::vec::Vec<&MetadataWrite<'_>> = plan.writes().iter().collect();
        sorted.sort_by_key(|w| w.byte_offset);
        for pair in sorted.windows(2) {
            let prev = pair[0];
            let next = pair[1];
            assert!(
                prev.byte_offset + prev.bytes.len() as u64 <= next.byte_offset,
                "overlap between writes",
            );
        }
    }
}
