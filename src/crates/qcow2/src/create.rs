//! Pure builders for an empty QCOW2 image's on-disk metadata.
//!
//! These helpers complement the parser in `lib.rs`: given options and
//! a layout, they populate caller-supplied byte buffers with the bytes
//! that constitute a valid empty QCOW2 image. They perform no I/O and
//! make no allocations.
//!
//! The shapes mirror the writer functions in
//! `src/operations/convert/src/main.rs` (`write_qcow2_header`,
//! `write_qcow2_metadata`, `write_refcount_table`,
//! `calculate_refcount_layout`) but are control-inverted: each builder
//! takes a `&mut [u8]` buffer and returns a populated `&[u8]` rather
//! than calling back into a write-sector function.
//!
//! The convert operation continues to use its private copies; this
//! module is consumed by `crates/create` and (later) by a refactored
//! convert.

#[cfg(test)]
extern crate std;

use shared::{write_be_u32, write_be_u64};

use crate::{
    EXT_BACKING_FORMAT, EXT_END, INCOMPAT_EXTENDED_L2, OFLAG_COPIED, QCOW2_HEADER_LENGTH_V3,
    QCOW2_MAGIC, QCOW2_VERSION_3,
};

/// Preallocation mode for a qcow2 image being emitted.
///
/// `Off` produces the minimal empty image: header + L1 (empty) +
/// refcount tables. Reads of any virtual cluster return zero via
/// qcow2's read-as-zero default.
///
/// `Metadata` / `Falloc` / `Full` all share the same on-disk
/// metadata shape: L1 entries point at populated L2 tables, L2
/// entries point at sequentially-laid-out data clusters, and the
/// refcount blocks cover every used cluster (metadata + data).
/// The three variants differ only in how the *host* treats the
/// data region after the guest finishes:
///   - `Metadata` — file is extended via `ftruncate`; data region
///     is sparse (FS-dependent zero-fill on read).
///   - `Falloc` — host calls `posix_fallocate` on the data region
///     so blocks are reserved.
///   - `Full` — host writes zeros across the data region.
///
/// From the qcow2 emitter's perspective the three variants are
/// indistinguishable; the host applies the appropriate
/// preallocation post-pass. Encoding all four here keeps the
/// shape symmetric with `crates/measure::Preallocation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Preallocation {
    #[default]
    Off,
    Metadata,
    Falloc,
    Full,
}

impl Preallocation {
    /// True when the layout should populate L1 + L2 + refcount for
    /// the full virtual range. All non-`Off` modes share the same
    /// emitted metadata; the host distinguishes them in its
    /// post-pass.
    pub fn populates_data_metadata(self) -> bool {
        !matches!(self, Preallocation::Off)
    }
}

/// Cap on `cluster_bits` (matches the parser's accept range).
const MIN_CLUSTER_BITS: u32 = 9;
const MAX_CLUSTER_BITS: u32 = 21;

/// Maximum number of fixed-point iterations when sizing the refcount
/// table. Convert uses 10; we use 16 for headroom — every realistic
/// case converges in 2-3 iterations.
const REFCOUNT_FIXED_POINT_ITERATIONS: u32 = 16;

/// Length in bytes of the EXT_END terminator marker (type:u32 +
/// length:u32, no data).
const EXT_END_LEN: usize = 8;

/// Errors returned by the create builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qcow2CreateError {
    /// `virtual_size` is zero or so large that intermediate computations
    /// overflow.
    InvalidVirtualSize,
    /// `cluster_bits` is outside the permitted 9..=21 range.
    InvalidClusterBits,
    /// `refcount_bits` is not one of {1, 2, 4, 8, 16, 32, 64}.
    InvalidRefcountBits,
    /// A size or offset computation overflowed `u64`.
    Overflow,
    /// The caller-supplied buffer is smaller than the populated region
    /// requires.
    BufferTooSmall,
    /// Backing-file metadata (path + extensions) does not fit in the
    /// header cluster.
    BackingMetadataTooLarge,
    /// Preallocation is requested but the option combination is
    /// not supported (e.g. metadata-mode + extended_l2 — the
    /// subcluster bitmap layout adds complexity phase 6 doesn't
    /// implement).
    PreallocationUnsupported,
}

/// Computed layout for a QCOW2 image being emitted.
///
/// Every offset and size is derived from
/// `(virtual_size, cluster_bits, refcount_bits, extended_l2,
/// preallocation)`. In `Preallocation::Off` mode the data region
/// is absent (`data_clusters == 0`); in any other mode the layout
/// covers L2 tables and data clusters too.
///
/// File layout (in cluster order):
///
///   * Cluster 0: header
///   * Clusters 1..1+l1_clusters: L1 table
///   * Refcount table (`refcount_table_clusters` clusters)
///   * Refcount blocks (`refcount_block_count` clusters)
///   * **Non-Off only**: L2 tables (`l2_clusters` clusters, one per
///     L1 entry)
///   * **Non-Off only**: data region (`data_clusters` clusters,
///     `virtual_size / cluster_size` rounded up)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qcow2Layout {
    /// `1u64 << cluster_bits`.
    pub cluster_bits: u32,
    /// Cluster size in bytes.
    pub cluster_size: u64,
    /// Virtual disk size in bytes (echoed back from input).
    pub virtual_size: u64,
    /// Refcount entry width in bits.
    pub refcount_bits: u32,
    /// Whether extended L2 entries (16-byte) are in use (sets
    /// INCOMPAT_EXTENDED_L2 and uses a 16-byte L2 entry size).
    pub extended_l2: bool,
    /// Preallocation mode the layout was computed for.
    pub preallocation: Preallocation,
    /// Number of L1 entries needed to cover `virtual_size`.
    pub l1_entries: u32,
    /// `l1_entries * 8`, the on-disk size of the L1 table in bytes.
    pub l1_size_bytes: u64,
    /// `ceil(l1_size_bytes / cluster_size).max(1)`.
    pub l1_clusters: u64,
    /// Byte offset of the L1 table. Always `cluster_size` (the header
    /// cluster is index 0, the L1 table starts at cluster 1).
    pub l1_offset: u64,
    /// Byte offset of the refcount table.
    pub refcount_table_offset: u64,
    /// Number of clusters the refcount table occupies.
    pub refcount_table_clusters: u64,
    /// Number of refcount blocks the refcount table references.
    pub refcount_block_count: u64,
    /// Byte offset of the first refcount block. Successive blocks are
    /// laid out contiguously at this offset + (i * cluster_size).
    pub refcount_blocks_base_offset: u64,
    /// Number of L2-table clusters (one per L1 entry in non-Off
    /// modes; 0 in Off mode).
    pub l2_clusters: u64,
    /// Byte offset of the first L2 table. Successive L2 tables are
    /// at offset `l2_base_offset + l1_index * cluster_size`. Only
    /// meaningful when `l2_clusters > 0`.
    pub l2_base_offset: u64,
    /// Number of data clusters (`virtual_size / cluster_size` rounded
    /// up in non-Off modes; 0 in Off mode).
    pub data_clusters: u64,
    /// Byte offset of the first data cluster. Only meaningful when
    /// `data_clusters > 0`.
    pub data_base_offset: u64,
    /// Total number of clusters in the image (header + L1 +
    /// reftable + refblocks + l2 + data).
    pub total_clusters: u64,
    /// Total file size in bytes (`total_clusters * cluster_size`).
    pub total_file_size: u64,
}

/// Compute the layout for an image with the given parameters.
///
/// `Preallocation::Off` produces a layout that covers header + L1 +
/// refcount only (no L2 tables, no data region). Any other mode
/// extends the layout to include L2 tables (one per L1 entry) and
/// the data region (virtual_size rounded up to cluster boundary).
///
/// Combining `Preallocation::Metadata`/`Falloc`/`Full` with
/// `extended_l2` returns `PreallocationUnsupported` because
/// populating extended-L2 subcluster bitmaps for the full virtual
/// range is non-trivial (every subcluster has to be marked
/// allocated) and the combination is rare in practice.
pub fn compute_layout(
    virtual_size: u64,
    cluster_bits: u32,
    refcount_bits: u32,
    extended_l2: bool,
    preallocation: Preallocation,
) -> Result<Qcow2Layout, Qcow2CreateError> {
    if virtual_size == 0 {
        return Err(Qcow2CreateError::InvalidVirtualSize);
    }
    if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
        return Err(Qcow2CreateError::InvalidClusterBits);
    }
    if !matches!(refcount_bits, 1 | 2 | 4 | 8 | 16 | 32 | 64) {
        return Err(Qcow2CreateError::InvalidRefcountBits);
    }
    if extended_l2 && preallocation.populates_data_metadata() {
        return Err(Qcow2CreateError::PreallocationUnsupported);
    }

    let cluster_size: u64 = 1u64 << cluster_bits;
    let l2_entry_size: u64 = if extended_l2 { 16 } else { 8 };
    let entries_per_l2: u64 = cluster_size / l2_entry_size;
    let l2_coverage: u64 = cluster_size
        .checked_mul(entries_per_l2)
        .ok_or(Qcow2CreateError::Overflow)?;
    let l1_entries_u64: u64 = virtual_size
        .checked_add(l2_coverage - 1)
        .ok_or(Qcow2CreateError::Overflow)?
        / l2_coverage;
    if l1_entries_u64 > crate::QCOW2_MAX_L1_SIZE_ENTRIES as u64 {
        return Err(Qcow2CreateError::InvalidVirtualSize);
    }
    let l1_entries: u32 = l1_entries_u64 as u32;
    let l1_size_bytes: u64 = (l1_entries as u64)
        .checked_mul(8)
        .ok_or(Qcow2CreateError::Overflow)?;
    let l1_clusters: u64 = l1_size_bytes.div_ceil(cluster_size).max(1);

    // Header is cluster 0, L1 starts at cluster 1.
    let l1_offset: u64 = cluster_size;

    // Non-Off modes pre-allocate L2 tables (one per L1 entry) and
    // the data region (virtual_size rounded up to cluster). They
    // sit *after* the refcount metadata in the file so the
    // refcount layout can be computed once and used to derive the
    // L2/data base offsets.
    let (l2_clusters, data_clusters): (u64, u64) = if preallocation.populates_data_metadata() {
        let data = virtual_size.div_ceil(cluster_size);
        (l1_entries as u64, data)
    } else {
        (0, 0)
    };

    // Clusters covered by refcount blocks: header + L1 + reftable +
    // refblocks + L2 + data. Refcount's fixed-point iteration
    // includes itself.
    let used_clusters_before_refcount: u64 = 1u64 + l1_clusters + l2_clusters + data_clusters;

    // refcount blocks pack `cluster_size * 8 / refcount_bits` entries
    // each; refcount table entries are 8 bytes (u64 offset).
    let entries_per_refblock: u64 = (cluster_size * 8) / refcount_bits as u64;
    let mut reftable_clusters: u64 = 1;
    let mut refblock_count: u64 = 1;
    for _ in 0..REFCOUNT_FIXED_POINT_ITERATIONS {
        let total = used_clusters_before_refcount + reftable_clusters + refblock_count;
        let new_refblock_count = total.div_ceil(entries_per_refblock);
        let reftable_entries = new_refblock_count;
        let new_reftable_clusters = (reftable_entries * 8).div_ceil(cluster_size);
        if new_refblock_count == refblock_count && new_reftable_clusters == reftable_clusters {
            break;
        }
        refblock_count = new_refblock_count;
        reftable_clusters = new_reftable_clusters;
    }

    let refcount_table_offset: u64 = (1u64 + l1_clusters) * cluster_size;
    let refcount_blocks_base_offset: u64 = refcount_table_offset + reftable_clusters * cluster_size;
    let l2_base_offset: u64 = refcount_blocks_base_offset + refblock_count * cluster_size;
    let data_base_offset: u64 = l2_base_offset + l2_clusters * cluster_size;
    let total_clusters: u64 =
        1u64 + l1_clusters + reftable_clusters + refblock_count + l2_clusters + data_clusters;
    let total_file_size: u64 = total_clusters * cluster_size;

    Ok(Qcow2Layout {
        cluster_bits,
        cluster_size,
        virtual_size,
        refcount_bits,
        extended_l2,
        preallocation,
        l1_entries,
        l1_size_bytes,
        l1_clusters,
        l1_offset,
        refcount_table_offset,
        refcount_table_clusters: reftable_clusters,
        refcount_block_count: refblock_count,
        refcount_blocks_base_offset,
        l2_clusters,
        l2_base_offset,
        data_clusters,
        data_base_offset,
        total_clusters,
        total_file_size,
    })
}

/// Options for [`build_header`].
#[derive(Debug, Clone, Copy)]
pub struct BuildHeaderOptions<'a> {
    /// Layout produced by [`compute_layout`].
    pub layout: &'a Qcow2Layout,
    /// Optional backing-file path bytes (written verbatim into the
    /// header cluster after the extensions block).
    pub backing_file: Option<&'a [u8]>,
    /// Optional backing-format hint (ASCII format name; written as
    /// the data of an `EXT_BACKING_FORMAT` header extension).
    pub backing_format: Option<&'a [u8]>,
    /// Set the COMPAT_LAZY_REFCOUNTS bit (`compatible_features`).
    pub lazy_refcounts: bool,
    /// Optional LUKS header pointer extension data: `(offset, length)`
    /// describing where the LUKS blob lives in the file. Phase 1's
    /// `crates/create` orchestrator always passes `None`; the parameter
    /// exists so a future encrypted-create phase can wire LUKS support
    /// without redesigning the API.
    pub luks_header: Option<(u64, u64)>,
}

/// Populate `buf` with a v3 QCOW2 header (and any header extensions
/// + backing-file path), returning the populated slice.
///
/// `buf` must be at least one cluster long (`layout.cluster_size`).
/// The function zero-fills the buffer up to `cluster_size`, writes the
/// fixed header at offset 0, lays out extensions (and the LUKS header
/// pointer, if any), writes the backing-file path after the
/// extensions, and fills in the header's `backing_file_offset` /
/// `backing_file_size` fields.
pub fn build_header<'a>(
    buf: &'a mut [u8],
    opts: &BuildHeaderOptions<'_>,
) -> Result<&'a [u8], Qcow2CreateError> {
    let cluster_size = opts.layout.cluster_size as usize;
    if buf.len() < cluster_size {
        return Err(Qcow2CreateError::BufferTooSmall);
    }
    let hdr = &mut buf[..cluster_size];
    hdr.fill(0);

    // Fixed v3 header.
    write_be_u32(hdr, 0, QCOW2_MAGIC);
    write_be_u32(hdr, 4, QCOW2_VERSION_3);
    // backing_file_offset (8) and backing_file_size (16) filled in below.
    write_be_u32(hdr, 20, opts.layout.cluster_bits);
    write_be_u64(hdr, 24, opts.layout.virtual_size);
    let crypt_method: u32 = if opts.luks_header.is_some() { 2 } else { 0 };
    write_be_u32(hdr, 32, crypt_method);
    write_be_u32(hdr, 36, opts.layout.l1_entries);
    write_be_u64(hdr, 40, opts.layout.l1_offset);
    write_be_u64(hdr, 48, opts.layout.refcount_table_offset);
    write_be_u32(hdr, 56, opts.layout.refcount_table_clusters as u32);
    // nb_snapshots (60) = 0, snapshots_offset (64) = 0.
    let incompat: u64 = if opts.layout.extended_l2 {
        INCOMPAT_EXTENDED_L2
    } else {
        0
    };
    write_be_u64(hdr, 72, incompat);
    // compatible_features
    let compat: u64 = if opts.lazy_refcounts {
        crate::COMPAT_LAZY_REFCOUNTS
    } else {
        0
    };
    write_be_u64(hdr, 80, compat);
    // autoclear_features (88) = 0
    // refcount_order: log2(refcount_bits). refcount_bits is a validated
    // power of two in {1,2,4,8,16,32,64} (compute_layout for create; 1 <<
    // refcount_order from the parsed source header for resize/snapshot
    // rebuilds), so trailing_zeros() yields the order directly. Deriving it
    // here — rather than hardcoding the 16-bit default — keeps the header's
    // declared width consistent with how the refcount blocks are actually
    // packed; a mismatch made qemu read sub-byte refcounts as 16-bit and
    // corrupted 1/2/4-bit images (instar #365).
    write_be_u32(hdr, 96, opts.layout.refcount_bits.trailing_zeros());
    write_be_u32(hdr, 100, QCOW2_HEADER_LENGTH_V3);

    // Lay out header extensions starting at offset 104.
    let mut ext_off = QCOW2_HEADER_LENGTH_V3 as usize;

    if let Some(fmt) = opts.backing_format {
        let padded = (fmt.len() + 7) & !7;
        if ext_off + 8 + padded > cluster_size {
            return Err(Qcow2CreateError::BackingMetadataTooLarge);
        }
        write_be_u32(hdr, ext_off, EXT_BACKING_FORMAT);
        write_be_u32(hdr, ext_off + 4, fmt.len() as u32);
        hdr[ext_off + 8..ext_off + 8 + fmt.len()].copy_from_slice(fmt);
        // Padding bytes are already zero.
        ext_off += 8 + padded;
    }

    if let Some((luks_off, luks_len)) = opts.luks_header {
        if ext_off + 8 + 16 > cluster_size {
            return Err(Qcow2CreateError::BackingMetadataTooLarge);
        }
        write_be_u32(hdr, ext_off, crate::EXT_ENCRYPT_HEADER);
        write_be_u32(hdr, ext_off + 4, 16);
        write_be_u64(hdr, ext_off + 8, luks_off);
        write_be_u64(hdr, ext_off + 16, luks_len);
        ext_off += 8 + 16;
    }

    // EXT_END terminator.
    if ext_off + EXT_END_LEN > cluster_size {
        return Err(Qcow2CreateError::BackingMetadataTooLarge);
    }
    write_be_u32(hdr, ext_off, EXT_END);
    write_be_u32(hdr, ext_off + 4, 0);
    ext_off += EXT_END_LEN;

    // Backing-file path (after extensions).
    if let Some(path) = opts.backing_file {
        if ext_off + path.len() > cluster_size {
            return Err(Qcow2CreateError::BackingMetadataTooLarge);
        }
        hdr[ext_off..ext_off + path.len()].copy_from_slice(path);
        write_be_u64(hdr, 8, ext_off as u64);
        write_be_u32(hdr, 16, path.len() as u32);
    }

    Ok(hdr)
}

/// Populate `buf` with the L1 table, returning the populated slice.
///
/// `buf` must be at least `layout.l1_clusters * layout.cluster_size`
/// bytes. In `Preallocation::Off` mode every L1 entry is zero (no L2
/// tables exist). In any other mode each L1 entry points at the
/// corresponding L2 table offset with `OFLAG_COPIED` set (preallocated
/// L2 tables have refcount=1 so writes can modify in place).
pub fn build_l1_table<'a>(
    buf: &'a mut [u8],
    layout: &Qcow2Layout,
) -> Result<&'a [u8], Qcow2CreateError> {
    let needed = (layout.l1_clusters * layout.cluster_size) as usize;
    if buf.len() < needed {
        return Err(Qcow2CreateError::BufferTooSmall);
    }
    let slice = &mut buf[..needed];
    slice.fill(0);

    if layout.preallocation.populates_data_metadata() {
        // Populate one entry per L1 slot, each pointing at the
        // matching L2 table offset with OFLAG_COPIED set.
        for i in 0..layout.l1_entries as u64 {
            let l2_offset = layout.l2_base_offset + i * layout.cluster_size;
            let entry = l2_offset | OFLAG_COPIED;
            let off = (i as usize) * 8;
            write_be_u64(slice, off, entry);
        }
    }
    Ok(slice)
}

/// Populate `buf` with one L2 table for the given L1 index, returning
/// the populated cluster-sized slice.
///
/// Only meaningful when `layout.preallocation.populates_data_metadata()`
/// is true. Each L2 entry points at a sequentially-laid-out data
/// cluster offset with `OFLAG_COPIED` set. Entries past the virtual
/// range (the last L2 table may have unused tail entries) stay zero.
///
/// Phase 6 rejects `extended_l2 + preallocation != Off` in
/// `compute_layout` so this function only needs to handle the
/// 8-byte L2 entry layout.
pub fn build_l2_table<'a>(
    buf: &'a mut [u8],
    layout: &Qcow2Layout,
    l1_index: u64,
) -> Result<&'a [u8], Qcow2CreateError> {
    let needed = layout.cluster_size as usize;
    if buf.len() < needed {
        return Err(Qcow2CreateError::BufferTooSmall);
    }
    let slice = &mut buf[..needed];
    slice.fill(0);

    if !layout.preallocation.populates_data_metadata() {
        // Caller asked for an L2 table in Off mode — shouldn't
        // happen via the documented API surface but return an
        // empty cluster so misuse fails closed instead of writing
        // garbage entries.
        return Ok(slice);
    }
    if layout.extended_l2 {
        // Defence in depth — compute_layout already rejected this
        // combination; reaching here means the caller built a
        // layout struct by hand.
        return Err(Qcow2CreateError::PreallocationUnsupported);
    }
    if l1_index >= layout.l1_entries as u64 {
        return Ok(slice);
    }

    // L2 entry size is 8 bytes (extended_l2 is rejected above).
    let entries_per_l2: u64 = layout.cluster_size / 8;
    let first_virtual_cluster = l1_index * entries_per_l2;
    let mut entries_in_table = entries_per_l2;
    if first_virtual_cluster >= layout.data_clusters {
        return Ok(slice);
    }
    let remaining = layout.data_clusters - first_virtual_cluster;
    if remaining < entries_in_table {
        entries_in_table = remaining;
    }

    for local in 0..entries_in_table {
        let data_offset =
            layout.data_base_offset + (first_virtual_cluster + local) * layout.cluster_size;
        let entry = data_offset | OFLAG_COPIED;
        write_be_u64(slice, (local as usize) * 8, entry);
    }

    Ok(slice)
}

/// Populate `buf` with the refcount table — one entry per refcount
/// block, each entry a u64 byte-offset into the file pointing at the
/// corresponding refcount block. Returns the populated slice
/// (`layout.refcount_table_clusters * layout.cluster_size` bytes).
pub fn build_refcount_table<'a>(
    buf: &'a mut [u8],
    layout: &Qcow2Layout,
) -> Result<&'a [u8], Qcow2CreateError> {
    let needed = (layout.refcount_table_clusters * layout.cluster_size) as usize;
    if buf.len() < needed {
        return Err(Qcow2CreateError::BufferTooSmall);
    }
    let slice = &mut buf[..needed];
    slice.fill(0);
    for i in 0..layout.refcount_block_count {
        let entry_off = (i as usize) * 8;
        let block_off = layout.refcount_blocks_base_offset + i * layout.cluster_size;
        write_be_u64(slice, entry_off, block_off);
    }
    Ok(slice)
}

/// Populate `buf` with one refcount block.
///
/// Each block holds `(cluster_size * 8) / refcount_bits` entries.
/// `block_index` is in `0..layout.refcount_block_count`. For an empty
/// image every cluster in `0..layout.total_clusters` has refcount=1;
/// entries past `total_clusters` are zero.
pub fn build_refcount_block<'a>(
    buf: &'a mut [u8],
    layout: &Qcow2Layout,
    block_index: u64,
) -> Result<&'a [u8], Qcow2CreateError> {
    let needed = layout.cluster_size as usize;
    if buf.len() < needed {
        return Err(Qcow2CreateError::BufferTooSmall);
    }
    let slice = &mut buf[..needed];
    slice.fill(0);

    let entries_per_block: u64 = (layout.cluster_size * 8) / layout.refcount_bits as u64;
    let first_entry = block_index * entries_per_block;
    let mut entries_in_block = entries_per_block;
    if first_entry >= layout.total_clusters {
        return Ok(slice);
    }
    let remaining = layout.total_clusters - first_entry;
    if remaining < entries_in_block {
        entries_in_block = remaining;
    }

    for local in 0..entries_in_block {
        set_refcount_to_one(slice, local, layout.refcount_bits);
    }

    Ok(slice)
}

/// Set entry `idx` within a refcount block to value `1`. Handles all
/// permitted refcount widths.
fn set_refcount_to_one(block: &mut [u8], idx: u64, refcount_bits: u32) {
    match refcount_bits {
        1 => {
            // 8 entries per byte; LSB-first packing within byte (entry 0 in
            // the lowest bit), matching qemu's set_refcount_ro0 and the
            // shared snapshot::qcow2 accessors. See instar #365.
            let byte = (idx / 8) as usize;
            let bit = (idx % 8) as u32;
            block[byte] |= 1 << bit;
        }
        2 => {
            // 4 entries per byte; LSB-first 2-bit slots.
            let byte = (idx / 4) as usize;
            let shift = 2 * (idx % 4) as u32;
            block[byte] |= 0b01 << shift;
        }
        4 => {
            // 2 entries per byte; LSB-first nibbles (entry 0 in the low
            // nibble).
            let byte = (idx / 2) as usize;
            let shift = if idx.is_multiple_of(2) { 0 } else { 4 };
            block[byte] |= 0b0001 << shift;
        }
        8 => {
            block[idx as usize] = 1;
        }
        16 => {
            let off = (idx as usize) * 2;
            write_be_u16_local(&mut block[off..off + 2], 1);
        }
        32 => {
            let off = (idx as usize) * 4;
            write_be_u32(block, off, 1);
        }
        64 => {
            let off = (idx as usize) * 8;
            write_be_u64(block, off, 1);
        }
        _ => unreachable!("refcount_bits validated by compute_layout"),
    }
}

/// Tiny local helper to write a big-endian u16. The `shared` crate
/// exposes `write_be_u16` but it takes an `&mut [u8]` and an offset;
/// here we want to write into a 2-byte sub-slice directly.
fn write_be_u16_local(buf: &mut [u8], val: u16) {
    buf[0] = (val >> 8) as u8;
    buf[1] = val as u8;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    /// Mirror convert's `calculate_refcount_layout` exactly so we can
    /// cross-check `compute_layout`'s refcount sizing against the
    /// reference path. Hardcoded to 16-bit refcounts to match convert.
    fn convert_calculate_refcount_layout(used_clusters: u64, cluster_size: u64) -> (u64, u64, u64) {
        let entries_per_refblock = cluster_size / 2;
        let mut reftable_clusters: u64 = 1;
        let mut refblock_count: u64 = 1;
        for _ in 0..10 {
            let total = used_clusters + reftable_clusters + refblock_count;
            let new_refblock_count = (total + entries_per_refblock - 1) / entries_per_refblock;
            let reftable_entries = new_refblock_count;
            let new_reftable_clusters = (reftable_entries * 8 + cluster_size - 1) / cluster_size;
            if new_refblock_count == refblock_count && new_reftable_clusters == reftable_clusters {
                break;
            }
            refblock_count = new_refblock_count;
            reftable_clusters = new_reftable_clusters;
        }
        let total = used_clusters + reftable_clusters + refblock_count;
        (reftable_clusters, refblock_count, total)
    }

    fn assert_layout_matches_convert(virtual_size: u64, cluster_bits: u32, extended_l2: bool) {
        let layout = compute_layout(
            virtual_size,
            cluster_bits,
            16,
            extended_l2,
            Preallocation::Off,
        )
        .unwrap();
        let cluster_size = 1u64 << cluster_bits;
        let l2_entry_size: u64 = if extended_l2 { 16 } else { 8 };
        let entries_per_l2 = cluster_size / l2_entry_size;
        let l2_coverage = cluster_size * entries_per_l2;
        let l1_size = ((virtual_size + l2_coverage - 1) / l2_coverage) as u32;
        let l1_size_bytes = l1_size as u64 * 8;
        let l1_clusters = ((l1_size_bytes + cluster_size - 1) / cluster_size).max(1);
        let used_before = 1 + l1_clusters;
        let (reftable, refblocks, total) =
            convert_calculate_refcount_layout(used_before, cluster_size);

        assert_eq!(layout.cluster_size, cluster_size);
        assert_eq!(layout.l1_entries, l1_size);
        assert_eq!(layout.l1_size_bytes, l1_size_bytes);
        assert_eq!(layout.l1_clusters, l1_clusters);
        assert_eq!(layout.refcount_table_clusters, reftable);
        assert_eq!(layout.refcount_block_count, refblocks);
        assert_eq!(layout.total_clusters, total);
        assert_eq!(layout.total_file_size, total * cluster_size);
        assert_eq!(layout.l1_offset, cluster_size);
        assert_eq!(layout.refcount_table_offset, used_before * cluster_size);
        assert_eq!(
            layout.refcount_blocks_base_offset,
            (used_before + reftable) * cluster_size,
        );
    }

    #[test]
    fn layout_1mib_default_matches_convert() {
        assert_layout_matches_convert(1 << 20, 16, false);
    }

    #[test]
    fn layout_1gib_default_matches_convert() {
        assert_layout_matches_convert(1 << 30, 16, false);
    }

    #[test]
    fn layout_1tib_default_matches_convert() {
        assert_layout_matches_convert(1 << 40, 16, false);
    }

    #[test]
    fn layout_1gib_extended_l2_matches_convert() {
        assert_layout_matches_convert(1 << 30, 16, true);
    }

    #[test]
    fn layout_1gib_cluster_512_matches_convert() {
        assert_layout_matches_convert(1 << 30, 9, false);
    }

    #[test]
    fn invalid_virtual_size_zero_rejected() {
        assert_eq!(
            compute_layout(0, 16, 16, false, Preallocation::Off),
            Err(Qcow2CreateError::InvalidVirtualSize),
        );
    }

    #[test]
    fn invalid_cluster_bits_rejected() {
        assert_eq!(
            compute_layout(1 << 20, 8, 16, false, Preallocation::Off),
            Err(Qcow2CreateError::InvalidClusterBits),
        );
        assert_eq!(
            compute_layout(1 << 20, 22, 16, false, Preallocation::Off),
            Err(Qcow2CreateError::InvalidClusterBits),
        );
    }

    #[test]
    fn invalid_refcount_bits_rejected() {
        assert_eq!(
            compute_layout(1 << 20, 16, 3, false, Preallocation::Off),
            Err(Qcow2CreateError::InvalidRefcountBits),
        );
    }

    #[test]
    fn over_huge_virtual_size_rejected() {
        // virtual_size that would require more than QCOW2_MAX_L1_SIZE_ENTRIES
        // L1 entries should be rejected.
        let bits = 16u32; // 64 KiB clusters
        let cluster_size = 1u64 << bits;
        let l2_coverage = cluster_size * (cluster_size / 8);
        let too_many_l1 = (crate::QCOW2_MAX_L1_SIZE_ENTRIES as u64 + 1) * l2_coverage;
        assert_eq!(
            compute_layout(too_many_l1, bits, 16, false, Preallocation::Off),
            Err(Qcow2CreateError::InvalidVirtualSize),
        );
    }

    #[test]
    fn header_refcount_order_tracks_refcount_bits() {
        // build_header must write refcount_order = log2(refcount_bits) for
        // every valid width, not a hardcoded 16-bit default — otherwise the
        // declared width disagrees with the packed refcount blocks and qemu
        // misreads sub-byte images (instar #365).
        for (bits, order) in [
            (1u32, 0u32),
            (2, 1),
            (4, 2),
            (8, 3),
            (16, 4),
            (32, 5),
            (64, 6),
        ] {
            let layout = compute_layout(1 << 30, 16, bits, false, Preallocation::Off).unwrap();
            let cs = layout.cluster_size as usize;
            let mut buf = vec![0u8; cs];
            let opts = BuildHeaderOptions {
                layout: &layout,
                backing_file: None,
                backing_format: None,
                lazy_refcounts: false,
                luks_header: None,
            };
            let hdr = build_header(&mut buf, &opts).unwrap();
            // refcount_order is the big-endian u32 at offset 96.
            let written = u32::from_be_bytes([hdr[96], hdr[97], hdr[98], hdr[99]]);
            assert_eq!(written, order, "refcount_bits {bits} -> order {order}");
            assert_eq!(
                crate::QcowHeader::parse(hdr).unwrap().refcount_bits,
                bits,
                "parsed refcount_bits for width {bits}",
            );
        }
    }

    #[test]
    fn header_round_trips_through_parser() {
        let layout = compute_layout(1 << 30, 16, 16, false, Preallocation::Off).unwrap();
        let cluster_size = layout.cluster_size as usize;
        let mut buf = [0u8; 1 << 16]; // 64 KiB
        let opts = BuildHeaderOptions {
            layout: &layout,
            backing_file: None,
            backing_format: None,
            lazy_refcounts: false,
            luks_header: None,
        };
        let hdr = build_header(&mut buf[..cluster_size], &opts).unwrap();
        let parsed = crate::QcowHeader::parse(hdr).expect("parse");
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.cluster_bits, 16);
        assert_eq!(parsed.cluster_size, 1 << 16);
        assert_eq!(parsed.virtual_size, 1 << 30);
        assert_eq!(parsed.l1_size, layout.l1_entries);
        assert_eq!(parsed.l1_table_offset, layout.l1_offset);
        assert_eq!(parsed.refcount_table_offset, layout.refcount_table_offset);
        assert_eq!(
            parsed.refcount_table_clusters,
            layout.refcount_table_clusters as u32,
        );
        assert_eq!(parsed.refcount_bits, 16);
        assert!(!parsed.extended_l2);
        assert!(!parsed.lazy_refcounts);
        assert_eq!(parsed.crypt_method, 0);
        assert_eq!(parsed.backing_file_offset, 0);
        assert_eq!(parsed.backing_file_size, 0);
    }

    #[test]
    fn header_with_extended_l2_sets_incompat_bit() {
        let layout = compute_layout(1 << 30, 16, 16, true, Preallocation::Off).unwrap();
        let cluster_size = layout.cluster_size as usize;
        let mut buf = [0u8; 1 << 16];
        let opts = BuildHeaderOptions {
            layout: &layout,
            backing_file: None,
            backing_format: None,
            lazy_refcounts: false,
            luks_header: None,
        };
        let hdr = build_header(&mut buf[..cluster_size], &opts).unwrap();
        let parsed = crate::QcowHeader::parse(hdr).expect("parse");
        assert!(parsed.extended_l2);
        assert_eq!(
            parsed.incompatible_features & INCOMPAT_EXTENDED_L2,
            INCOMPAT_EXTENDED_L2
        );
    }

    #[test]
    fn header_with_lazy_refcounts_sets_compat_bit() {
        let layout = compute_layout(1 << 30, 16, 16, false, Preallocation::Off).unwrap();
        let cluster_size = layout.cluster_size as usize;
        let mut buf = [0u8; 1 << 16];
        let opts = BuildHeaderOptions {
            layout: &layout,
            backing_file: None,
            backing_format: None,
            lazy_refcounts: true,
            luks_header: None,
        };
        let hdr = build_header(&mut buf[..cluster_size], &opts).unwrap();
        let parsed = crate::QcowHeader::parse(hdr).expect("parse");
        assert!(parsed.lazy_refcounts);
    }

    #[test]
    fn header_with_backing_file_round_trips() {
        let layout = compute_layout(1 << 30, 16, 16, false, Preallocation::Off).unwrap();
        let cluster_size = layout.cluster_size as usize;
        let mut buf = [0u8; 1 << 16];
        let path = b"backing.qcow2";
        let fmt = b"qcow2";
        let opts = BuildHeaderOptions {
            layout: &layout,
            backing_file: Some(path),
            backing_format: Some(fmt),
            lazy_refcounts: false,
            luks_header: None,
        };
        let hdr = build_header(&mut buf[..cluster_size], &opts).unwrap();
        let parsed = crate::QcowHeader::parse(hdr).expect("parse");
        assert_eq!(parsed.backing_file_size as usize, path.len());
        let off = parsed.backing_file_offset as usize;
        assert_eq!(&hdr[off..off + path.len()], path);
        let exts = crate::parse_header_extensions(hdr, &parsed);
        assert_eq!(exts.backing_format.as_str(), "qcow2");
    }

    #[test]
    fn l1_table_is_zero_filled() {
        let layout = compute_layout(1 << 30, 16, 16, false, Preallocation::Off).unwrap();
        let needed = (layout.l1_clusters * layout.cluster_size) as usize;
        let mut buf = vec![0xffu8; needed];
        let l1 = build_l1_table(&mut buf, &layout).unwrap();
        assert!(l1.iter().all(|&b| b == 0));
    }

    #[test]
    fn refcount_table_points_at_blocks() {
        let layout = compute_layout(1 << 30, 16, 16, false, Preallocation::Off).unwrap();
        let cs = layout.cluster_size as usize;
        let mut buf = vec![0u8; cs * layout.refcount_table_clusters as usize];
        let rt = build_refcount_table(&mut buf, &layout).unwrap();
        for i in 0..layout.refcount_block_count {
            let off = (i as usize) * 8;
            let val = shared::be_u64(rt, off);
            let expected = layout.refcount_blocks_base_offset + i * layout.cluster_size;
            assert_eq!(val, expected, "refcount table entry {} mismatch", i);
        }
    }

    #[test]
    fn refcount_block_marks_all_used_clusters_16bit() {
        let layout = compute_layout(1 << 20, 16, 16, false, Preallocation::Off).unwrap();
        let cs = layout.cluster_size as usize;
        let mut buf = vec![0u8; cs];
        let rb = build_refcount_block(&mut buf, &layout, 0).unwrap();
        for i in 0..layout.total_clusters as usize {
            let off = i * 2;
            let val = shared::be_u16(rb, off);
            assert_eq!(val, 1, "cluster {} refcount mismatch", i);
        }
        let off_after = (layout.total_clusters as usize) * 2;
        if off_after < rb.len() {
            assert_eq!(shared::be_u16(rb, off_after), 0);
        }
    }

    #[test]
    fn refcount_block_marks_all_used_clusters_8bit() {
        let layout = compute_layout(1 << 20, 16, 8, false, Preallocation::Off).unwrap();
        let cs = layout.cluster_size as usize;
        let mut buf = vec![0u8; cs];
        let rb = build_refcount_block(&mut buf, &layout, 0).unwrap();
        for i in 0..layout.total_clusters as usize {
            assert_eq!(rb[i], 1);
        }
        if (layout.total_clusters as usize) < rb.len() {
            assert_eq!(rb[layout.total_clusters as usize], 0);
        }
    }

    #[test]
    fn refcount_block_marks_all_used_clusters_1bit() {
        // Sub-byte refcounts are LSB-first within each byte (entry 0 in the
        // lowest bit), matching qemu's set_refcount_ro0. A byte-exact check
        // pins the ordering so it can't silently flip back to the MSB-first
        // packing that corrupted sub-byte images (instar #365).
        let layout = compute_layout(1 << 20, 16, 1, false, Preallocation::Off).unwrap();
        let cs = layout.cluster_size as usize;
        let mut buf = vec![0u8; cs];
        let rb = build_refcount_block(&mut buf, &layout, 0).unwrap();
        for i in 0..layout.total_clusters as usize {
            let byte = i / 8;
            let bit = i % 8; // LSB-first
            assert!(rb[byte] & (1u8 << bit) != 0, "cluster {} bit unset", i);
        }
        // The N used clusters occupy the N lowest bits of the block: full
        // 0xFF bytes followed by a partial low-bit-filled byte.
        let used = layout.total_clusters as usize;
        for (b, byte) in rb.iter().enumerate() {
            let expected: u8 = if (b + 1) * 8 <= used {
                0xFF
            } else if b * 8 >= used {
                0x00
            } else {
                (1u8 << (used - b * 8)) - 1
            };
            assert_eq!(*byte, expected, "refblock byte {b} mismatch");
        }
    }

    #[test]
    fn refcount_block_sub_byte_widths_are_lsb_first() {
        // 2- and 4-bit widths pack entry 0 in the lowest bits too. Every
        // used cluster has refcount 1, so the low slots read back as 1.
        for &bits in &[2u32, 4u32] {
            let layout = compute_layout(1 << 20, 16, bits, false, Preallocation::Off).unwrap();
            let cs = layout.cluster_size as usize;
            let mut buf = vec![0u8; cs];
            let rb = build_refcount_block(&mut buf, &layout, 0).unwrap();
            let entries_per_byte = (8 / bits) as u64;
            let mask = (1u8 << bits) - 1;
            for i in 0..layout.total_clusters {
                let byte = (i / entries_per_byte) as usize;
                let shift = (bits as u64 * (i % entries_per_byte)) as u32;
                let val = (rb[byte] >> shift) & mask;
                assert_eq!(val, 1, "width {bits}: cluster {i} refcount {val} != 1");
            }
        }
    }

    #[test]
    fn build_with_too_small_buffer_errors() {
        let layout = compute_layout(1 << 20, 16, 16, false, Preallocation::Off).unwrap();
        let mut buf = [0u8; 32];
        let opts = BuildHeaderOptions {
            layout: &layout,
            backing_file: None,
            backing_format: None,
            lazy_refcounts: false,
            luks_header: None,
        };
        assert_eq!(
            build_header(&mut buf, &opts),
            Err(Qcow2CreateError::BufferTooSmall),
        );
    }

    // ---- Preallocation (metadata mode) tests -----------------

    #[test]
    fn metadata_mode_layout_grows_to_cover_data_region() {
        // 1 GiB virtual + default 64 KiB clusters: 16384 data clusters
        // + L2 tables (2 L1 entries → 2 L2 clusters, since
        // L2 coverage = 64K * 8K = 512 MiB and 1 GiB / 512 MiB = 2)
        // + header + L1 + refcount.
        let layout = compute_layout(1 << 30, 16, 16, false, Preallocation::Metadata).unwrap();
        assert_eq!(layout.preallocation, Preallocation::Metadata);
        assert_eq!(layout.l1_entries, 2);
        assert_eq!(layout.l2_clusters, 2);
        assert_eq!(layout.data_clusters, 16384);
        // total_file_size should cover the data region: well over
        // 1 GiB (1 GiB data + a few hundred KiB of metadata).
        assert!(layout.total_file_size >= (1u64 << 30));
        // l2_base_offset comes after the refcount blocks; data_base
        // comes after L2 tables.
        assert!(layout.l2_base_offset > layout.refcount_blocks_base_offset);
        assert_eq!(
            layout.data_base_offset,
            layout.l2_base_offset + layout.l2_clusters * layout.cluster_size,
        );
    }

    #[test]
    fn metadata_mode_off_keeps_existing_layout() {
        // Sanity: existing Off-mode layouts are unaffected by the
        // phase-6 extension.
        let off = compute_layout(1 << 30, 16, 16, false, Preallocation::Off).unwrap();
        assert_eq!(off.l2_clusters, 0);
        assert_eq!(off.data_clusters, 0);
        // total_file_size still tiny (~256 KiB for 1 GiB virtual).
        assert!(off.total_file_size < (1u64 << 20));
    }

    #[test]
    fn metadata_mode_with_extended_l2_rejected() {
        let err = compute_layout(1 << 30, 16, 16, true, Preallocation::Metadata).unwrap_err();
        assert_eq!(err, Qcow2CreateError::PreallocationUnsupported);
    }

    #[test]
    fn metadata_mode_l1_table_points_at_l2_tables() {
        let layout = compute_layout(1 << 30, 16, 16, false, Preallocation::Metadata).unwrap();
        let cs = layout.cluster_size as usize;
        let mut buf = vec![0u8; cs];
        let l1 = build_l1_table(&mut buf, &layout).unwrap();
        for i in 0..layout.l1_entries as u64 {
            let val = shared::be_u64(l1, (i as usize) * 8);
            let l2_off = layout.l2_base_offset + i * layout.cluster_size;
            let expected = l2_off | OFLAG_COPIED;
            assert_eq!(val, expected, "L1 entry {} mismatch", i);
        }
    }

    #[test]
    fn metadata_mode_l2_table_points_at_data_clusters() {
        let layout = compute_layout(1 << 30, 16, 16, false, Preallocation::Metadata).unwrap();
        let cs = layout.cluster_size as usize;
        let mut buf = vec![0u8; cs];
        let entries_per_l2 = layout.cluster_size / 8;
        // Check the first L2 table.
        let l2 = build_l2_table(&mut buf, &layout, 0).unwrap();
        for i in 0..entries_per_l2.min(layout.data_clusters) {
            let val = shared::be_u64(l2, (i as usize) * 8);
            let data_off = layout.data_base_offset + i * layout.cluster_size;
            assert_eq!(val, data_off | OFLAG_COPIED, "L2 entry {} mismatch", i);
        }
    }

    #[test]
    fn metadata_mode_l2_tail_entries_zero_when_below_full() {
        // virtual_size = 1 MiB at 64 KiB clusters = 16 data clusters,
        // far less than entries_per_l2 (8192). The single L2 table's
        // tail entries (16..8192) should be zero.
        let layout = compute_layout(1 << 20, 16, 16, false, Preallocation::Metadata).unwrap();
        assert_eq!(layout.l1_entries, 1);
        assert_eq!(layout.data_clusters, 16);
        let cs = layout.cluster_size as usize;
        let mut buf = vec![0u8; cs];
        let l2 = build_l2_table(&mut buf, &layout, 0).unwrap();
        for i in 16..32 {
            assert_eq!(
                shared::be_u64(l2, i * 8),
                0,
                "L2 entry {} should be zero (past data range)",
                i,
            );
        }
    }

    #[test]
    fn metadata_mode_refcount_block_covers_data_region() {
        // Refcount blocks in metadata mode mark every cluster up to
        // total_clusters (which now includes L2 + data).
        let layout = compute_layout(1 << 20, 16, 16, false, Preallocation::Metadata).unwrap();
        let cs = layout.cluster_size as usize;
        let mut buf = vec![0u8; cs];
        let rb = build_refcount_block(&mut buf, &layout, 0).unwrap();
        // total_clusters includes header + L1 + reftable + refblocks
        // + L2 + data; every entry up to total_clusters should be 1.
        for i in 0..layout.total_clusters as usize {
            let off = i * 2;
            let val = shared::be_u16(rb, off);
            assert_eq!(val, 1, "cluster {} refcount mismatch", i);
        }
    }
}
