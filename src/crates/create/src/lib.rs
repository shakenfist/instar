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
///
/// The dominant term is the L1 table for sparse layouts: at
/// `cluster_size=512` with `extended_l2=true` (16-byte L2 entries),
/// L2 coverage drops to 16 KiB and L1 grows toward 16 MiB long
/// before hitting the `QCOW2_MAX_L1_SIZE` cap. 32 MiB covers every
/// option combination within the supported virtual-size range; the
/// guest binary (phase 2) only needs to allocate this once.
pub const QCOW2_MAX_METADATA_SCRATCH: usize = 32 * 1024 * 1024;

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
    /// The requested preallocation mode isn't supported for this
    /// option combination (e.g. metadata-mode + extended_l2; or
    /// any preallocation other than `Off` for a target format
    /// whose phase-6 emitter doesn't yet populate metadata for
    /// the data region).
    PreallocationUnsupported,
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
    /// Preallocation mode (phase 6). `Off` (default) emits header +
    /// L1 (empty) + refcount only. `Metadata` / `Falloc` / `Full`
    /// populate L1 + L2 + refcount for the full virtual range; the
    /// host applies the matching post-pass (truncate / fallocate /
    /// zero-write) after `plan_qcow2`'s metadata bytes have been
    /// written.
    pub preallocation: qcow2::create::Preallocation,
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
    /// When the backing is a VMDK, the parent's `CID` value to write
    /// into the new descriptor's `parentCID=` line. `None` falls back
    /// to a fixed sentinel (`0xdeadbeef`) — used when the backing
    /// isn't a VMDK or the caller couldn't extract the CID (e.g.
    /// parent descriptor unreadable). Phase 5b wires this through
    /// from the create guest's
    /// [`vmdk::read_and_parse_descriptor`] call.
    pub parent_cid: Option<u32>,
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
        opts.preallocation,
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

    // Refcount blocks are laid out back-to-back at
    // `refcount_blocks_base_offset` and each is one cluster long.
    // Build each in place and emit a single coalesced write covering
    // all of them — keeping them as one entry stops MetadataPlan's
    // inline write storage from filling up on sparse images with
    // many refcount blocks (the contiguous-region count can reach
    // 100+ at small cluster sizes with extended_l2).
    let refblocks_total_bytes = (layout.refcount_block_count as usize) * cluster_size;
    let refblocks_combined = &mut refblocks_region[..refblocks_total_bytes];
    for block_index in 0..layout.refcount_block_count {
        let start = (block_index as usize) * cluster_size;
        let end = start + cluster_size;
        qcow2::create::build_refcount_block(
            &mut refblocks_combined[start..end],
            &layout,
            block_index,
        )
        .map_err(map_qcow2_error)?;
    }
    plan.push(MetadataWrite {
        byte_offset: layout.refcount_blocks_base_offset,
        bytes: refblocks_combined,
    })?;

    // In Off mode the pushes above reach total_file_size already.
    // In non-Off modes L2 tables + the data region come after the
    // refcount blocks but are *not* emitted in the plan (the guest
    // streams L2 tables outside the inline-writes array because
    // they can sum to far more than the plan's storage; the host
    // then extends the file via fill_zeros / posix_fallocate to
    // cover the data region). Override minimum_file_size so the
    // host sees the eventual on-disk size.
    if opts.preallocation.populates_data_metadata() {
        plan.minimum_file_size = layout.total_file_size;
    } else {
        debug_assert_eq!(plan.minimum_file_size, layout.total_file_size);
    }
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
        qcow2::create::Qcow2CreateError::PreallocationUnsupported => {
            CreateError::PreallocationUnsupported
        }
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

/// Build a metadata plan for a VMDK image (monolithicSparse or
/// streamOptimized).
///
/// Layout written into `scratch`:
///
/// 1. Binary header (1 sector).
/// 2. Descriptor text (DESC_SECTORS sectors, zero-padded).
/// 3. Grain directory (rounded up to a sector, all zero entries for
///    an empty image).
/// 4. For `StreamOptimized` only: an end-of-stream marker (1 sector).
pub fn plan_vmdk<'a>(
    opts: &VmdkCreateOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<MetadataPlan<'a>, CreateError> {
    // Subformat support check.
    let stream_optimized = match opts.subformat {
        VmdkSubformat::MonolithicSparse => false,
        VmdkSubformat::StreamOptimized => true,
        VmdkSubformat::MonolithicFlat
        | VmdkSubformat::TwoGbMaxExtentSparse
        | VmdkSubformat::TwoGbMaxExtentFlat => return Err(CreateError::InvalidSubformat),
    };

    if opts.virtual_size == 0 {
        return Err(CreateError::InvalidVirtualSize);
    }
    if opts.grain_size == 0
        || !opts.grain_size.is_power_of_two()
        || opts.grain_size < 4096
        || opts.grain_size > 65536
    {
        return Err(CreateError::InvalidGrainSize);
    }

    let backing_path = match &opts.backing {
        Some(b) => {
            if b.path.len() > MAX_BACKING_FILE_LEN {
                return Err(CreateError::BackingFileTooLong);
            }
            Some(b.path)
        }
        None => None,
    };

    const SECTOR: u64 = 512;
    let grain_size_sectors: u64 = opts.grain_size as u64 / SECTOR;
    let gtes_per_gt: u32 = vmdk::DEFAULT_NUM_GTES_PER_GT;

    // Capacity (round up virtual_size to grain boundary, then to sector).
    // `div_ceil(_, grain) * grain` can exceed u64::MAX when virtual_size is
    // close to u64::MAX (e.g. fuzzer-generated inputs). Surface as Overflow
    // rather than panicking under overflow-checks=on.
    let grain_size_bytes = opts.grain_size as u64;
    let capacity_bytes = opts
        .virtual_size
        .div_ceil(grain_size_bytes)
        .checked_mul(grain_size_bytes)
        .ok_or(CreateError::Overflow)?;
    let capacity_sectors = capacity_bytes / SECTOR;

    // GD entries cover the full virtual size. The GD is a flat u32 array
    // in the on-disk header, so the entry count must fit in u32; reject
    // pathological virtual_size values rather than silently truncating
    // (which would produce a smaller GD than the address space requires
    // and corrupt the emitted image).
    let sectors_per_gt = gtes_per_gt as u64 * grain_size_sectors;
    let num_gd_entries: u32 = u32::try_from(capacity_sectors.div_ceil(sectors_per_gt))
        .map_err(|_| CreateError::Overflow)?;
    let gd_bytes: usize = num_gd_entries as usize * 4;
    let gd_sectors: u64 = (gd_bytes as u64).div_ceil(SECTOR);

    // Layout:
    //   sector 0:                              header (1)
    //   sector 1..=DESC_SECTORS:               descriptor
    //   sector DESC_SECTORS+1 ..:              GD (gd_sectors)
    //   sector DESC_SECTORS+1+gd_sectors ..:   EOS marker (StreamOptimized only)
    let header_sector: u64 = 0;
    let desc_sector: u64 = 1;
    let gd_sector: u64 = 1 + vmdk::DESC_SECTORS;
    let eos_sector: u64 = gd_sector + gd_sectors;

    let total_sectors: u64 = if stream_optimized {
        eos_sector + 1
    } else {
        gd_sector + gd_sectors
    };
    let total_bytes: usize = (total_sectors * SECTOR) as usize;
    if scratch.len() < total_bytes {
        return Err(CreateError::ScratchTooSmall);
    }

    let (header_region, rest) = scratch.split_at_mut(SECTOR as usize);
    let (desc_region, rest) = rest.split_at_mut((vmdk::DESC_SECTORS * SECTOR) as usize);
    let (gd_region, rest) = rest.split_at_mut((gd_sectors * SECTOR) as usize);

    // Header.
    header_region.fill(0);
    if stream_optimized {
        vmdk::build_streamoptimized_header(
            header_region,
            capacity_sectors,
            grain_size_sectors,
            gtes_per_gt,
            gd_sector,
            gd_sector + gd_sectors,
        );
    } else {
        vmdk::build_sparse_header(
            header_region,
            capacity_sectors,
            grain_size_sectors,
            gtes_per_gt,
            gd_sector,
            gd_sector + gd_sectors,
        );
    }

    // Descriptor: vmdk::build_descriptor for no-backing case, or a
    // locally-built variant for the backing case (the stock builder
    // hardcodes parentCID=ffffffff and has no slot for
    // parentFileNameHint).
    desc_region.fill(0);
    let _desc_len = if let Some(path) = backing_path {
        build_vmdk_descriptor_with_backing(
            desc_region,
            capacity_sectors,
            stream_optimized,
            path,
            opts.parent_cid,
        )
    } else if stream_optimized {
        vmdk::build_streamoptimized_descriptor(desc_region, 0, capacity_sectors)
    } else {
        vmdk::build_descriptor(desc_region, 0, capacity_sectors)
    };

    // Grain directory (all zero entries — no GTs allocated yet).
    gd_region.fill(0);

    let mut plan = MetadataPlan::new();
    plan.push(MetadataWrite {
        byte_offset: header_sector * SECTOR,
        bytes: &header_region[..SECTOR as usize],
    })?;
    plan.push(MetadataWrite {
        byte_offset: desc_sector * SECTOR,
        bytes: desc_region,
    })?;
    plan.push(MetadataWrite {
        byte_offset: gd_sector * SECTOR,
        bytes: gd_region,
    })?;

    if stream_optimized {
        let (eos_region, _) = rest.split_at_mut(SECTOR as usize);
        eos_region.fill(0);
        vmdk::build_metadata_marker(eos_region, 0, vmdk::MARKER_EOS);
        plan.push(MetadataWrite {
            byte_offset: eos_sector * SECTOR,
            bytes: eos_region,
        })?;
    }

    Ok(plan)
}

/// Build a monolithicSparse or streamOptimized descriptor with a
/// `parentFileNameHint` line populated. Returns the byte length
/// written. We re-implement rather than call `vmdk::build_descriptor`
/// because the stock builder hardcodes parentCID=FFFFFFFF and has no
/// hook for the parent filename.
///
/// `parent_cid` carries the parent's `CID` value when the caller
/// could extract it (vmdk-from-vmdk path; phase 5b wires this via
/// `vmdk::read_and_parse_descriptor`). `None` falls back to the
/// fixed sentinel `0xdeadbeef` — used when the backing is non-vmdk
/// (no CID concept) or descriptor extraction fails.
fn build_vmdk_descriptor_with_backing(
    buf: &mut [u8],
    capacity_sectors: u64,
    stream_optimized: bool,
    parent_path: &[u8],
    parent_cid: Option<u32>,
) -> usize {
    let mut pos: usize = 0;
    let mut put = |bytes: &[u8], pos: &mut usize| {
        let end = *pos + bytes.len();
        if end <= buf.len() {
            buf[*pos..end].copy_from_slice(bytes);
        }
        *pos = end;
    };

    put(b"# Disk DescriptorFile\n", &mut pos);
    put(b"version=1\n", &mut pos);
    put(b"CID=fffffffe\n", &mut pos);
    // parentCID line: use the real value when supplied, fall back
    // to a fixed sentinel otherwise.
    let parent_cid_val = parent_cid.unwrap_or(0xdead_beef);
    let mut cid_buf = [0u8; 16];
    let cid_hex = format_u32_hex8(parent_cid_val, &mut cid_buf);
    put(b"parentCID=", &mut pos);
    put(cid_hex, &mut pos);
    put(b"\n", &mut pos);
    if stream_optimized {
        put(b"createType=\"streamOptimized\"\n", &mut pos);
    } else {
        put(b"createType=\"monolithicSparse\"\n", &mut pos);
    }
    put(b"parentFileNameHint=\"", &mut pos);
    put(parent_path, &mut pos);
    put(b"\"\n\n", &mut pos);
    put(b"# Extent description\n", &mut pos);
    put(b"RW ", &mut pos);

    // Decimal capacity_sectors.
    let mut num_buf = [0u8; 20];
    let num_str = format_u64_decimal(capacity_sectors, &mut num_buf);
    put(num_str, &mut pos);

    put(b" SPARSE \"output.vmdk\"\n\n", &mut pos);
    put(b"# The Disk Data Base\n", &mut pos);
    put(b"#DDB\n", &mut pos);

    pos
}

/// Format a u32 as a fixed-width 8-character lowercase hex string
/// (matches qemu-img's parentCID format). The output buffer must
/// be at least 8 bytes.
fn format_u32_hex8(val: u32, buf: &mut [u8; 16]) -> &[u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, slot) in buf.iter_mut().take(8).enumerate() {
        let nibble = (val >> ((7 - i) * 4)) & 0xf;
        *slot = HEX[nibble as usize];
    }
    &buf[..8]
}

fn format_u64_decimal(mut val: u64, buf: &mut [u8; 20]) -> &[u8] {
    if val == 0 {
        buf[19] = b'0';
        return &buf[19..20];
    }
    let mut pos = 20;
    while val > 0 {
        pos -= 1;
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    &buf[pos..20]
}

/// Build a metadata plan for a VHD image (Dynamic or Fixed).
///
/// Dynamic layout:
///
///   bytes 0..512:                  head footer copy
///   bytes 512..1536:               dynamic header
///   bytes 1536..1536+bat_padded:   BAT (entries = 0xFFFF_FFFF)
///   bytes total-512..total:        tail footer
///
/// Fixed layout: phase 1 emits only the footer at byte
/// `virtual_size`. The data region is left as a sparse hole; phase 6
/// handles `preallocation=full` by writing zeros.
pub fn plan_vhd<'a>(
    opts: &VhdCreateOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<MetadataPlan<'a>, CreateError> {
    // The largest virtual size VHD can represent, matching qemu's
    // `block/vpc.c` `VHD_MAX_SECTORS` (0xFF000000 sectors = 2040 GiB):
    // `qemu-img create -f vpc` accepts exactly this size and rejects one
    // sector more. The check sits before the subformat split so it covers
    // both Fixed and Dynamic. Without it the Fixed branch places the footer
    // at byte_offset == virtual_size, so a virtual_size near u64::MAX makes
    // `total_metadata_bytes + minimum_file_size` overflow u64 (the Dynamic
    // branch was already protected, incidentally, by its u32 BAT-entry count
    // overflowing first).
    const VHD_MAX_VIRTUAL_SIZE: u64 = 0xFF00_0000 * 512;

    if opts.virtual_size == 0 || opts.virtual_size > VHD_MAX_VIRTUAL_SIZE {
        return Err(CreateError::InvalidVirtualSize);
    }
    if opts.backing.is_some() {
        // Differencing VHD (DISK_TYPE_DIFFERENCING + parent locators)
        // is deferred — too complex for phase 1.
        return Err(CreateError::BackingFileUnsupported);
    }

    const SECTOR: u64 = 512;
    const FOOTER_BYTES: usize = vhd::FOOTER_SIZE;
    const DYN_HEADER_BYTES: usize = vhd::DYNAMIC_HEADER_SIZE;
    const UUID_ZERO: [u8; 16] = [0; 16];

    match opts.subformat {
        VhdSubformat::Dynamic => {
            if opts.block_size == 0
                || !opts.block_size.is_power_of_two()
                || opts.block_size < 512 * 1024
                || opts.block_size > 256 * 1024 * 1024
            {
                return Err(CreateError::InvalidBlockSize);
            }
            let block_size = opts.block_size as u64;
            // BAT entries are u32-indexed in the on-disk dynamic header; a
            // u64 → u32 truncation here would emit a smaller BAT than the
            // virtual address space requires. Reject overflow with a
            // clear error rather than silently corrupting the image.
            let max_table_entries: u32 = u32::try_from(opts.virtual_size.div_ceil(block_size))
                .map_err(|_| CreateError::Overflow)?;
            let bat_bytes: u64 = max_table_entries as u64 * 4;
            let bat_padded: u64 = bat_bytes.div_ceil(SECTOR) * SECTOR;

            let head_footer_off: u64 = 0;
            let dyn_header_off: u64 = SECTOR; // sector 1
            let bat_off: u64 = SECTOR + DYN_HEADER_BYTES as u64;
            let tail_footer_off: u64 = bat_off + bat_padded;
            let total_file_size: u64 = tail_footer_off + FOOTER_BYTES as u64;

            let total_bytes_needed: usize =
                FOOTER_BYTES * 2 + DYN_HEADER_BYTES + bat_padded as usize;
            if scratch.len() < total_bytes_needed {
                return Err(CreateError::ScratchTooSmall);
            }

            let (head_footer_region, rest) = scratch.split_at_mut(FOOTER_BYTES);
            let (dyn_header_region, rest) = rest.split_at_mut(DYN_HEADER_BYTES);
            let (bat_region, rest) = rest.split_at_mut(bat_padded as usize);
            let (tail_footer_region, _) = rest.split_at_mut(FOOTER_BYTES);

            head_footer_region.fill(0);
            vhd::build_footer(
                head_footer_region,
                opts.virtual_size,
                vhd::DISK_TYPE_DYNAMIC,
                dyn_header_off,
                &UUID_ZERO,
            );

            dyn_header_region.fill(0);
            vhd::build_dynamic_header(
                dyn_header_region,
                bat_off,
                max_table_entries,
                opts.block_size,
            );

            // BAT: meaningful entries are 0xFF, padding is zero.
            bat_region[..bat_bytes as usize].fill(0xFF);
            bat_region[bat_bytes as usize..bat_padded as usize].fill(0);

            tail_footer_region.fill(0);
            vhd::build_footer(
                tail_footer_region,
                opts.virtual_size,
                vhd::DISK_TYPE_DYNAMIC,
                dyn_header_off,
                &UUID_ZERO,
            );

            let mut plan = MetadataPlan::new();
            plan.push(MetadataWrite {
                byte_offset: head_footer_off,
                bytes: head_footer_region,
            })?;
            plan.push(MetadataWrite {
                byte_offset: dyn_header_off,
                bytes: dyn_header_region,
            })?;
            plan.push(MetadataWrite {
                byte_offset: bat_off,
                bytes: bat_region,
            })?;
            plan.push(MetadataWrite {
                byte_offset: tail_footer_off,
                bytes: tail_footer_region,
            })?;
            debug_assert_eq!(plan.minimum_file_size, total_file_size);
            Ok(plan)
        }
        VhdSubformat::Fixed => {
            if scratch.len() < FOOTER_BYTES {
                return Err(CreateError::ScratchTooSmall);
            }
            let (footer_region, _) = scratch.split_at_mut(FOOTER_BYTES);
            footer_region.fill(0);
            vhd::build_footer(
                footer_region,
                opts.virtual_size,
                vhd::DISK_TYPE_FIXED,
                0xFFFF_FFFF_FFFF_FFFF,
                &UUID_ZERO,
            );
            let mut plan = MetadataPlan::new();
            plan.push(MetadataWrite {
                byte_offset: opts.virtual_size,
                bytes: footer_region,
            })?;
            Ok(plan)
        }
    }
}

/// Build a metadata plan for an empty Dynamic VHDX image.
///
/// Layout (all offsets MB-aligned per the VHDX spec):
///
///   bytes 0..0x10000:                file identifier
///   bytes 0x10000..0x11000:          header 1
///   bytes 0x20000..0x21000:          header 2
///   bytes 0x30000..0x40000:          region table 1
///   bytes 0x40000..0x50000:          region table 2
///   bytes 0x100000..0x200000:        log region (sparse zero hole)
///   bytes 0x200000..bat_end:         BAT region (sparse zero hole)
///   bytes bat_end..bat_end+0x100000: metadata region
///
/// The log region and BAT region are left as sparse zero holes —
/// reading zeros from a hole is equivalent to `PAYLOAD_BLOCK_NOT_PRESENT`
/// (state 0) for every BAT entry, and the log region is unused for a
/// freshly-created clean image. minimum_file_size extends to the end
/// of the metadata region.
pub fn plan_vhdx<'a>(
    opts: &VhdxCreateOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<MetadataPlan<'a>, CreateError> {
    if opts.virtual_size == 0 {
        return Err(CreateError::InvalidVirtualSize);
    }
    if opts.block_size == 0
        || !opts.block_size.is_power_of_two()
        || opts.block_size < 1024 * 1024
        || opts.block_size > 256 * 1024 * 1024
    {
        return Err(CreateError::InvalidBlockSize);
    }
    if opts.backing.is_some() {
        // VHDX parent locators are deferred — too complex for phase 1.
        return Err(CreateError::BackingFileUnsupported);
    }

    const LOGICAL_SECTOR_SIZE: u32 = 512;
    const PHYSICAL_SECTOR_SIZE: u32 = 4096;
    const FILE_ID_LEN: usize = 4096;
    const REGION_TABLE_LEN: usize = 65536;
    const METADATA_REGION_LEN: usize = 1024 * 1024;

    let (total_bat_entries, _chunk_ratio, _payload_blocks) =
        vhdx::calculate_bat_layout(opts.virtual_size, opts.block_size, LOGICAL_SECTOR_SIZE)
            .ok_or(CreateError::Overflow)?;
    let bat_size_bytes: u64 = total_bat_entries as u64 * 8;
    let bat_region_size: u64 = bat_size_bytes.div_ceil(vhdx::MB_ALIGN) * vhdx::MB_ALIGN;

    let file_id_off: u64 = 0;
    let header1_off: u64 = vhdx::HEADER1_OFFSET;
    let header2_off: u64 = vhdx::HEADER2_OFFSET;
    let rt1_off: u64 = vhdx::REGION_TABLE1_OFFSET;
    let rt2_off: u64 = vhdx::REGION_TABLE2_OFFSET;
    let bat_off: u64 = 0x20_0000;
    let metadata_off: u64 = bat_off + bat_region_size;
    let total_file_size: u64 = metadata_off + METADATA_REGION_LEN as u64;

    let total_scratch_needed: usize = FILE_ID_LEN
        + vhdx::HEADER_SIZE
        + vhdx::HEADER_SIZE
        + REGION_TABLE_LEN
        + METADATA_REGION_LEN;
    if scratch.len() < total_scratch_needed {
        return Err(CreateError::ScratchTooSmall);
    }

    let (file_id_region, rest) = scratch.split_at_mut(FILE_ID_LEN);
    let (header1_region, rest) = rest.split_at_mut(vhdx::HEADER_SIZE);
    let (header2_region, rest) = rest.split_at_mut(vhdx::HEADER_SIZE);
    let (rt_region, rest) = rest.split_at_mut(REGION_TABLE_LEN);
    let (metadata_region, _) = rest.split_at_mut(METADATA_REGION_LEN);

    file_id_region.fill(0);
    vhdx::build_file_identifier(file_id_region);

    header1_region.fill(0);
    vhdx::build_header(header1_region, 1);
    header2_region.fill(0);
    vhdx::build_header(header2_region, 2);

    rt_region.fill(0);
    vhdx::build_region_table(
        rt_region,
        bat_off,
        bat_region_size as u32,
        metadata_off,
        METADATA_REGION_LEN as u32,
    );

    metadata_region.fill(0);
    vhdx::build_metadata(
        metadata_region,
        opts.block_size,
        opts.virtual_size,
        LOGICAL_SECTOR_SIZE,
        PHYSICAL_SECTOR_SIZE,
        false,
    );

    // Region table is identical at both offsets, so both writes
    // reference the same slice.
    let rt_slice: &[u8] = rt_region;

    let mut plan = MetadataPlan::new();
    plan.push(MetadataWrite {
        byte_offset: file_id_off,
        bytes: file_id_region,
    })?;
    plan.push(MetadataWrite {
        byte_offset: header1_off,
        bytes: header1_region,
    })?;
    plan.push(MetadataWrite {
        byte_offset: header2_off,
        bytes: header2_region,
    })?;
    plan.push(MetadataWrite {
        byte_offset: rt1_off,
        bytes: rt_slice,
    })?;
    plan.push(MetadataWrite {
        byte_offset: rt2_off,
        bytes: rt_slice,
    })?;
    plan.push(MetadataWrite {
        byte_offset: metadata_off,
        bytes: metadata_region,
    })?;
    debug_assert_eq!(plan.minimum_file_size, total_file_size);
    Ok(plan)
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
            preallocation: qcow2::create::Preallocation::Off,
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
        // build_header now derives refcount_order from refcount_bits, so the
        // header's declared width matches the 1-bit-packed refcount blocks
        // (previously it hardcoded refcount_order=4 and corrupted sub-byte
        // images — instar #365).
        let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse header");
        assert_eq!(parsed.virtual_size, 1 << 30);
        assert_eq!(parsed.refcount_bits, 1);
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
        let layout = qcow2::create::compute_layout(
            opts.virtual_size,
            16,
            16,
            false,
            qcow2::create::Preallocation::Off,
        )
        .unwrap();
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
    fn plan_qcow2_handles_many_refcount_blocks() {
        // virtual_size=32 GiB with cluster_size=512 and extended_l2
        // forces ~130 refcount blocks. They must coalesce into a
        // single MetadataWrite so the plan's inline write storage
        // doesn't overflow.
        let opts = Qcow2CreateOpts {
            virtual_size: 1u64 << 35,
            cluster_size: 512,
            refcount_bits: 16,
            extended_l2: true,
            lazy_refcounts: false,
            compat_v3: true,
            backing: None,
            preallocation: qcow2::create::Preallocation::Off,
        };
        let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
        let plan = plan_qcow2(&opts, &mut scratch).expect("plan");
        // Header + L1 + reftable + one coalesced refblocks region = 4.
        assert_eq!(plan.writes().len(), 4);
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

#[cfg(test)]
mod vmdk_plan_tests {
    use super::*;
    use std::vec;

    fn materialise(plan: &MetadataPlan<'_>) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; plan.minimum_file_size as usize];
        for w in plan.writes() {
            let start = w.byte_offset as usize;
            let end = start + w.bytes.len();
            buf[start..end].copy_from_slice(w.bytes);
        }
        buf
    }

    fn default_opts(virtual_size: u64) -> VmdkCreateOpts<'static> {
        VmdkCreateOpts {
            virtual_size,
            subformat: VmdkSubformat::MonolithicSparse,
            grain_size: 65536,
            backing: None,
            parent_cid: None,
        }
    }

    fn run(opts: &VmdkCreateOpts<'_>) -> std::vec::Vec<u8> {
        let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
        let plan = plan_vmdk(opts, &mut scratch).expect("plan");
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
    fn plan_vmdk_monolithic_sparse_1mib_round_trips() {
        let opts = default_opts(1 << 20);
        let bytes = run(&opts);
        let parsed = vmdk::Vmdk4Header::parse(&bytes).expect("parse header");
        assert_eq!(parsed.virtual_size, 1 << 20);
        assert_eq!(parsed.grain_size_sectors * 512, 65536);
    }

    #[test]
    fn plan_vmdk_monolithic_sparse_1gib_grain_4k() {
        let mut opts = default_opts(1 << 30);
        opts.grain_size = 4096;
        let bytes = run(&opts);
        let parsed = vmdk::Vmdk4Header::parse(&bytes).expect("parse header");
        assert_eq!(parsed.virtual_size, 1 << 30);
        assert_eq!(parsed.cluster_size, 4096);
    }

    #[test]
    fn plan_vmdk_stream_optimized_round_trips() {
        let mut opts = default_opts(1 << 20);
        opts.subformat = VmdkSubformat::StreamOptimized;
        let bytes = run(&opts);
        let parsed = vmdk::Vmdk4Header::parse(&bytes).expect("parse header");
        assert_eq!(parsed.virtual_size, 1 << 20);
        assert_eq!(parsed.version, 3);
    }

    #[test]
    fn plan_vmdk_with_backing_embeds_path_in_descriptor() {
        let mut opts = default_opts(1 << 20);
        let path = b"../parent.vmdk";
        opts.backing = Some(BackingRef {
            path,
            format: Some(ImageFormat::Vmdk4),
        });
        let bytes = run(&opts);
        // Locate the descriptor (starts at sector 1).
        let desc = &bytes[512..512 + (vmdk::DESC_SECTORS * 512) as usize];
        let needle = b"parentFileNameHint=\"../parent.vmdk\"";
        assert!(
            desc.windows(needle.len()).any(|w| w == needle),
            "descriptor missing parentFileNameHint",
        );
    }

    #[test]
    fn plan_vmdk_rejects_deferred_subformat() {
        let mut opts = default_opts(1 << 20);
        opts.subformat = VmdkSubformat::MonolithicFlat;
        let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
        assert!(matches!(
            plan_vmdk(&opts, &mut scratch),
            Err(CreateError::InvalidSubformat)
        ));
    }

    #[test]
    fn plan_vmdk_rejects_bad_grain_size() {
        let mut opts = default_opts(1 << 20);
        opts.grain_size = 1000; // not power of two
        let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
        assert!(matches!(
            plan_vmdk(&opts, &mut scratch),
            Err(CreateError::InvalidGrainSize)
        ));
    }

    #[test]
    fn plan_vmdk_rejects_capacity_overflow() {
        // virtual_size = u64::MAX with the largest valid grain rounds up
        // past u64::MAX in the capacity computation. Must return Overflow,
        // not panic. Regression test for coverage-fuzz panics at lib.rs:526
        // (github.com/shakenfist/instar issues #309, #314, #318, #322,
        // #328, #331, #339).
        let mut opts = default_opts(u64::MAX);
        opts.grain_size = 65536;
        let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
        assert!(matches!(
            plan_vmdk(&opts, &mut scratch),
            Err(CreateError::Overflow)
        ));
    }

    #[test]
    fn plan_vmdk_writes_dont_overlap() {
        let opts = default_opts(1 << 30);
        let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
        let plan = plan_vmdk(&opts, &mut scratch).expect("plan");
        let mut sorted: std::vec::Vec<&MetadataWrite<'_>> = plan.writes().iter().collect();
        sorted.sort_by_key(|w| w.byte_offset);
        for pair in sorted.windows(2) {
            let prev = pair[0];
            let next = pair[1];
            assert!(prev.byte_offset + prev.bytes.len() as u64 <= next.byte_offset);
        }
    }
}

#[cfg(test)]
mod vhd_plan_tests {
    use super::*;
    use std::vec;

    fn materialise(plan: &MetadataPlan<'_>) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; plan.minimum_file_size as usize];
        for w in plan.writes() {
            let start = w.byte_offset as usize;
            let end = start + w.bytes.len();
            buf[start..end].copy_from_slice(w.bytes);
        }
        buf
    }

    fn default_dynamic(virtual_size: u64) -> VhdCreateOpts<'static> {
        VhdCreateOpts {
            virtual_size,
            subformat: VhdSubformat::Dynamic,
            block_size: 2 * 1024 * 1024, // 2 MiB
            backing: None,
        }
    }

    fn default_fixed(virtual_size: u64) -> VhdCreateOpts<'static> {
        VhdCreateOpts {
            virtual_size,
            subformat: VhdSubformat::Fixed,
            block_size: 0,
            backing: None,
        }
    }

    fn run(opts: &VhdCreateOpts<'_>) -> std::vec::Vec<u8> {
        let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
        let plan = plan_vhd(opts, &mut scratch).expect("plan");
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
    fn plan_vhd_dynamic_1mib_round_trips() {
        let opts = default_dynamic(1 << 20);
        let bytes = run(&opts);
        // Tail footer should parse.
        let footer = vhd::VhdFooter::parse(&bytes[bytes.len() - 512..]).expect("parse footer");
        assert_eq!(footer.current_size, 1 << 20);
        assert_eq!(footer.disk_type, vhd::DISK_TYPE_DYNAMIC);
    }

    #[test]
    fn plan_vhd_dynamic_1gib_round_trips() {
        let opts = default_dynamic(1 << 30);
        let bytes = run(&opts);
        let footer = vhd::VhdFooter::parse(&bytes[bytes.len() - 512..]).expect("parse footer");
        assert_eq!(footer.current_size, 1 << 30);
        // Head copy should also parse identically.
        let head = vhd::VhdFooter::parse(&bytes[..512]).expect("parse head footer");
        assert_eq!(head.current_size, 1 << 30);
        assert_eq!(head.disk_type, vhd::DISK_TYPE_DYNAMIC);
    }

    #[test]
    fn plan_vhd_fixed_round_trips() {
        let opts = default_fixed(1 << 20);
        let bytes = run(&opts);
        // File size should be virtual_size + 512.
        assert_eq!(bytes.len() as u64, (1 << 20) + 512);
        let footer = vhd::VhdFooter::parse(&bytes[bytes.len() - 512..]).expect("parse footer");
        assert_eq!(footer.current_size, 1 << 20);
        assert_eq!(footer.disk_type, vhd::DISK_TYPE_FIXED);
    }

    #[test]
    fn plan_vhd_dynamic_bat_all_unallocated() {
        let opts = default_dynamic(1 << 20);
        let bytes = run(&opts);
        // BAT begins at offset 1536 (sector 3).
        let bat_start = 1536;
        // virtual_size 1 MiB / block_size 2 MiB = 1 entry
        let entry = u32::from_be_bytes([
            bytes[bat_start],
            bytes[bat_start + 1],
            bytes[bat_start + 2],
            bytes[bat_start + 3],
        ]);
        assert_eq!(entry, 0xFFFF_FFFF);
    }

    #[test]
    fn plan_vhd_rejects_backing() {
        let mut opts = default_dynamic(1 << 20);
        opts.backing = Some(BackingRef {
            path: b"parent.vhd",
            format: Some(ImageFormat::Vhd),
        });
        let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
        assert!(matches!(
            plan_vhd(&opts, &mut scratch),
            Err(CreateError::BackingFileUnsupported)
        ));
    }

    #[test]
    fn plan_vhd_rejects_bad_block_size() {
        let mut opts = default_dynamic(1 << 20);
        opts.block_size = 1000;
        let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
        assert!(matches!(
            plan_vhd(&opts, &mut scratch),
            Err(CreateError::InvalidBlockSize)
        ));
    }

    #[test]
    fn plan_vhd_rejects_oversize_virtual_size() {
        // VHD tops out at 0xFF000000 sectors (2040 GiB): `qemu-img create
        // -f vpc` accepts exactly this and rejects one sector more. Without
        // the cap, a Fixed VHD places its footer at byte_offset ==
        // virtual_size, so a virtual_size near u64::MAX makes
        // total_metadata_bytes + minimum_file_size overflow u64 — the
        // fuzz_create_emitters invariant-3 panic (instar #353 #355 #357 #361
        // #362 #363 #367). The cap sits before the subformat split, so it
        // rejects oversize inputs for both Fixed and Dynamic before any
        // subformat-specific work runs.
        const VHD_MAX: u64 = 0xFF00_0000 * 512;
        let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];

        // The boundary value is accepted for Fixed (it needs only a footer's
        // worth of scratch, so no materialisation is required to confirm).
        let plan = plan_vhd(&default_fixed(VHD_MAX), &mut scratch).expect("max is accepted");
        assert!(plan
            .total_metadata_bytes
            .checked_add(plan.minimum_file_size)
            .is_some());

        // One sector past the cap is rejected for both subformats.
        for opts in [default_fixed(VHD_MAX + 512), default_dynamic(VHD_MAX + 512)] {
            assert!(matches!(
                plan_vhd(&opts, &mut scratch),
                Err(CreateError::InvalidVirtualSize)
            ));
        }

        // The exact fuzz reproducer virtual_sizes are all rejected rather
        // than producing a plan that trips invariant 3.
        for vsize in [
            0xffff_ffff_ffff_fd80u64, // #367
            0xffff_ffff_ffff_fd00,    // #363 / #362
            0xffff_ffff_ffff_fdff,    // #361 / #357
            0xffff_ffff_ffff_fdc1,    // #355
            0xffff_ffff_ffff_fc02,    // #353
        ] {
            assert!(matches!(
                plan_vhd(&default_fixed(vsize), &mut scratch),
                Err(CreateError::InvalidVirtualSize)
            ));
        }
    }

    #[test]
    fn plan_vhd_writes_dont_overlap() {
        let opts = default_dynamic(1 << 30);
        let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
        let plan = plan_vhd(&opts, &mut scratch).expect("plan");
        let mut sorted: std::vec::Vec<&MetadataWrite<'_>> = plan.writes().iter().collect();
        sorted.sort_by_key(|w| w.byte_offset);
        for pair in sorted.windows(2) {
            let prev = pair[0];
            let next = pair[1];
            assert!(prev.byte_offset + prev.bytes.len() as u64 <= next.byte_offset);
        }
    }
}

#[cfg(test)]
mod vhdx_plan_tests {
    use super::*;
    use std::vec;

    fn materialise(plan: &MetadataPlan<'_>) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; plan.minimum_file_size as usize];
        for w in plan.writes() {
            let start = w.byte_offset as usize;
            let end = start + w.bytes.len();
            buf[start..end].copy_from_slice(w.bytes);
        }
        buf
    }

    fn default_opts(virtual_size: u64) -> VhdxCreateOpts<'static> {
        VhdxCreateOpts {
            virtual_size,
            block_size: 32 * 1024 * 1024,
            backing: None,
        }
    }

    fn run(opts: &VhdxCreateOpts<'_>) -> std::vec::Vec<u8> {
        let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
        let plan = plan_vhdx(opts, &mut scratch).expect("plan");
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
    fn plan_vhdx_dynamic_1mib_round_trips() {
        let opts = default_opts(1 << 20);
        let bytes = run(&opts);
        // File identifier signature at offset 0.
        let sig = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(sig, vhdx::FILE_IDENTIFIER_SIGNATURE);
        // Header 1 parses.
        let h1 = &bytes
            [vhdx::HEADER1_OFFSET as usize..vhdx::HEADER1_OFFSET as usize + vhdx::HEADER_SIZE];
        let hdr = vhdx::VhdxHeader::parse(h1).expect("parse header 1");
        assert_eq!(hdr.sequence_number, 1);
        // Header 2 has sequence 2.
        let h2 = &bytes
            [vhdx::HEADER2_OFFSET as usize..vhdx::HEADER2_OFFSET as usize + vhdx::HEADER_SIZE];
        let hdr2 = vhdx::VhdxHeader::parse(h2).expect("parse header 2");
        assert_eq!(hdr2.sequence_number, 2);
    }

    #[test]
    fn plan_vhdx_region_table_points_at_bat_and_metadata() {
        let opts = default_opts(1 << 30);
        let bytes = run(&opts);
        let rt = &bytes
            [vhdx::REGION_TABLE1_OFFSET as usize..vhdx::REGION_TABLE1_OFFSET as usize + 65536];
        let (entries, _count) = vhdx::parse_region_table(rt).expect("parse region table");
        // One BAT entry, one metadata entry — in some order.
        let mut have_bat = false;
        let mut have_meta = false;
        for e in &entries {
            if e.file_offset == 0x20_0000 {
                have_bat = true;
            }
            if e.file_offset > 0x20_0000 && e.length == 1024 * 1024 {
                have_meta = true;
            }
        }
        assert!(have_bat, "no BAT region pointer");
        assert!(have_meta, "no metadata region pointer");
    }

    #[test]
    fn plan_vhdx_region_table_duplicated() {
        let opts = default_opts(1 << 20);
        let bytes = run(&opts);
        let rt1 = &bytes
            [vhdx::REGION_TABLE1_OFFSET as usize..vhdx::REGION_TABLE1_OFFSET as usize + 65536];
        let rt2 = &bytes
            [vhdx::REGION_TABLE2_OFFSET as usize..vhdx::REGION_TABLE2_OFFSET as usize + 65536];
        assert_eq!(rt1, rt2);
    }

    #[test]
    fn plan_vhdx_rejects_backing() {
        let mut opts = default_opts(1 << 20);
        opts.backing = Some(BackingRef {
            path: b"parent.vhdx",
            format: Some(ImageFormat::Vhdx),
        });
        let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
        assert!(matches!(
            plan_vhdx(&opts, &mut scratch),
            Err(CreateError::BackingFileUnsupported)
        ));
    }

    #[test]
    fn plan_vhdx_rejects_bad_block_size() {
        let mut opts = default_opts(1 << 20);
        opts.block_size = 1000;
        let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
        assert!(matches!(
            plan_vhdx(&opts, &mut scratch),
            Err(CreateError::InvalidBlockSize)
        ));
    }

    #[test]
    fn plan_vhdx_writes_dont_overlap() {
        let opts = default_opts(1 << 30);
        let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
        let plan = plan_vhdx(&opts, &mut scratch).expect("plan");
        let mut sorted: std::vec::Vec<&MetadataWrite<'_>> = plan.writes().iter().collect();
        sorted.sort_by_key(|w| w.byte_offset);
        for pair in sorted.windows(2) {
            let prev = pair[0];
            let next = pair[1];
            assert!(prev.byte_offset + prev.bytes.len() as u64 <= next.byte_offset);
        }
    }
}
