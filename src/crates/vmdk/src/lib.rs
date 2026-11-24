//! VMDK (VMware Virtual Machine Disk) format parsing.
//!
//! Provides VMDK4 binary header parsing, text descriptor parsing,
//! and grain directory/table reading for monolithicSparse and
//! streamOptimized images.

#![no_std]
// Guest crate I/O uses function pointers (no closures/trait objects in
// no_std), so cached-read helpers inherently need many parameters.
#![allow(clippy::too_many_arguments)]

use shared::{
    le_u16, le_u32, le_u64, write_le_u16, write_le_u32, write_le_u64, AllocationSummary, CallTable,
    MapExtent, MapExtentCoalescer, MapExtentState, VmdkInfo, MAX_SECTOR_SIZE,
};

// ============================================================================
// VMDK4 binary header offsets (all little-endian)
// ============================================================================

pub const MAGIC_OFFSET: usize = 0;
pub const VERSION_OFFSET: usize = 4;
pub const FLAGS_OFFSET: usize = 8;
pub const CAPACITY_OFFSET: usize = 12;
pub const GRAIN_SIZE_OFFSET: usize = 20;
pub const DESC_OFFSET_OFFSET: usize = 28;
pub const DESC_SIZE_OFFSET: usize = 36;
pub const NUM_GTES_PER_GT_OFFSET: usize = 44;
pub const RGD_OFFSET_OFFSET: usize = 48;
pub const GD_OFFSET_OFFSET: usize = 56;
pub const OVERHEAD_OFFSET: usize = 64;
pub const COMPRESS_ALGORITHM_OFFSET: usize = 77;

/// Minimum header size for basic parsing (through desc_size).
pub const HEADER_MIN_SIZE: usize = 44;

/// Full header size for grain table operations (through
/// compressAlgorithm).
pub const HEADER_FULL_SIZE: usize = 79;

// ============================================================================
// VMDK4 header flag constants
// ============================================================================

/// Newline detection enabled.
pub const FLAG_VALID_NEW_LINE: u32 = 1 << 0;
/// Redundant grain directory present.
pub const FLAG_USE_RGD: u32 = 1 << 1;
/// GTE value 1 means zeroed grain.
pub const FLAG_ZERO_GRAIN: u32 = 1 << 2;
/// Compression enabled.
pub const FLAG_COMPRESSED: u32 = 1 << 16;
/// Grain markers present (streamOptimized).
pub const FLAG_MARKER: u32 = 1 << 17;

// ============================================================================
// Special values
// ============================================================================

/// Grain directory offset indicating GD is at end of file
/// (streamOptimized).
pub const GD_AT_END: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Grain table entry marker for an explicit zero grain, as written
/// by qemu-img for monolithicSparse output (VMDK spec / qemu-img
/// block/vmdk.c). Distinct from `GTE_UNALLOCATED` (0) — the grain
/// exists on disk but contains all zeros.
pub const ZERO_GRAIN_MARKER: u32 = 0xFFFF_FFFE;

/// Grain table entry: not allocated.
pub const GTE_UNALLOCATED: u32 = 0;
/// Grain table entry: zeroed grain (only valid when FLAG_ZERO_GRAIN
/// is set).
pub const GTE_ZEROED: u32 = 1;

/// DEFLATE compression algorithm.
pub const COMPRESS_DEFLATE: u16 = 1;

/// Default number of grain table entries per grain table.
pub const DEFAULT_NUM_GTES_PER_GT: u32 = 512;

/// Grain marker header size in bytes (u64 lba + u32 size).
pub const GRAIN_MARKER_SIZE: usize = 12;

/// VMDK4 magic number.
pub const VMDK4_MAGIC: u32 = 0x564D_444B;

/// The sector a sparse VMDK counts in, whatever the sector size of the
/// device it is read from: its header is one of these, and every
/// offset and capacity in it is a number of them.
const VMDK_SECTOR: u64 = 512;

// ============================================================================
// Metadata marker types (streamOptimized)
// ============================================================================

/// End-of-stream marker type.
pub const MARKER_EOS: u32 = 0;
/// Grain table marker type.
pub const MARKER_GT: u32 = 1;
/// Grain directory marker type.
pub const MARKER_GD: u32 = 2;
/// Footer marker type.
pub const MARKER_FOOTER: u32 = 3;

/// Size of a metadata marker (one sector).
pub const METADATA_MARKER_SIZE: usize = 512;

// ============================================================================
// Header and descriptor builders (VMDK output)
// ============================================================================

/// Number of descriptor sectors (512-byte) reserved in the output.
pub const DESC_SECTORS: u64 = 20;

/// Build a monolithicSparse VMDK4 header in `buf`.
///
/// Fills the first 512 bytes with the binary header fields.
/// `buf` must be at least 512 bytes and should be pre-zeroed.
pub fn build_sparse_header(
    buf: &mut [u8],
    capacity_sectors: u64,
    grain_size_sectors: u64,
    num_gtes_per_gt: u32,
    gd_offset_sectors: u64,
    overhead_sectors: u64,
) {
    write_le_u32(buf, MAGIC_OFFSET, VMDK4_MAGIC);
    write_le_u32(buf, VERSION_OFFSET, 1);
    write_le_u32(buf, FLAGS_OFFSET, FLAG_VALID_NEW_LINE);
    write_le_u64(buf, CAPACITY_OFFSET, capacity_sectors);
    write_le_u64(buf, GRAIN_SIZE_OFFSET, grain_size_sectors);
    write_le_u64(buf, DESC_OFFSET_OFFSET, 1); // Descriptor at sector 1
    write_le_u64(buf, DESC_SIZE_OFFSET, DESC_SECTORS);
    write_le_u32(buf, NUM_GTES_PER_GT_OFFSET, num_gtes_per_gt);
    write_le_u64(buf, RGD_OFFSET_OFFSET, 0); // No redundant GD
    write_le_u64(buf, GD_OFFSET_OFFSET, gd_offset_sectors);
    write_le_u64(buf, OVERHEAD_OFFSET, overhead_sectors);
    // Newline detection bytes (for FLAG_VALID_NEW_LINE)
    buf[73] = b'\n';
    buf[74] = b' ';
    buf[75] = b'\r';
    buf[76] = b'\n';
    // compressAlgorithm = 0 (uncompressed) - already zero
}

/// Build a streamOptimized VMDK4 header in `buf`.
///
/// Similar to `build_sparse_header` but sets compression flags
/// and uses `GD_AT_END` as the GD offset (the real offset is
/// stored in the footer).
/// `buf` must be at least 512 bytes and should be pre-zeroed.
pub fn build_streamoptimized_header(
    buf: &mut [u8],
    capacity_sectors: u64,
    grain_size_sectors: u64,
    num_gtes_per_gt: u32,
    gd_offset_sectors: u64,
    overhead_sectors: u64,
) {
    write_le_u32(buf, MAGIC_OFFSET, VMDK4_MAGIC);
    write_le_u32(buf, VERSION_OFFSET, 3);
    write_le_u32(
        buf,
        FLAGS_OFFSET,
        FLAG_VALID_NEW_LINE | FLAG_COMPRESSED | FLAG_MARKER | FLAG_ZERO_GRAIN,
    );
    write_le_u64(buf, CAPACITY_OFFSET, capacity_sectors);
    write_le_u64(buf, GRAIN_SIZE_OFFSET, grain_size_sectors);
    write_le_u64(buf, DESC_OFFSET_OFFSET, 1); // Descriptor at sector 1
    write_le_u64(buf, DESC_SIZE_OFFSET, DESC_SECTORS);
    write_le_u32(buf, NUM_GTES_PER_GT_OFFSET, num_gtes_per_gt);
    write_le_u64(buf, RGD_OFFSET_OFFSET, 0); // No redundant GD
    write_le_u64(buf, GD_OFFSET_OFFSET, gd_offset_sectors);
    write_le_u64(buf, OVERHEAD_OFFSET, overhead_sectors);
    // Newline detection bytes (for FLAG_VALID_NEW_LINE)
    buf[73] = b'\n';
    buf[74] = b' ';
    buf[75] = b'\r';
    buf[76] = b'\n';
    write_le_u16(buf, COMPRESS_ALGORITHM_OFFSET, COMPRESS_DEFLATE);
}

/// Build a streamOptimized descriptor into `buf` starting at
/// `offset`. Returns the number of bytes written.
pub fn build_streamoptimized_descriptor(
    buf: &mut [u8],
    offset: usize,
    capacity_sectors: u64,
) -> usize {
    let mut pos = offset;

    let mut put = |bytes: &[u8]| {
        let end = pos + bytes.len();
        if end <= buf.len() {
            buf[pos..end].copy_from_slice(bytes);
        }
        pos = end;
    };

    put(b"# Disk DescriptorFile\n");
    put(b"version=1\n");
    put(b"CID=fffffffe\n");
    put(b"parentCID=ffffffff\n");
    put(b"createType=\"streamOptimized\"\n\n");
    put(b"# Extent description\n");
    put(b"RW ");

    let mut num_buf = [0u8; 20];
    let num_str = format_u64(capacity_sectors, &mut num_buf);
    put(num_str);

    put(b" SPARSE \"output.vmdk\"\n\n");
    put(b"# The Disk Data Base\n");
    put(b"#DDB\n");

    pos - offset
}

/// Build a monolithicSparse descriptor into `buf` starting at
/// `offset`. Returns the number of bytes written.
///
/// The descriptor contains the minimum fields needed for
/// interoperability: version, CID, parentCID, createType, and
/// an extent description.
pub fn build_descriptor(buf: &mut [u8], offset: usize, capacity_sectors: u64) -> usize {
    // We build the descriptor as a byte string to avoid
    // alloc (this is no_std code). Format capacity as decimal.
    let mut pos = offset;

    // Helper: copy bytes into buf
    let mut put = |bytes: &[u8]| {
        let end = pos + bytes.len();
        if end <= buf.len() {
            buf[pos..end].copy_from_slice(bytes);
        }
        pos = end;
    };

    put(b"# Disk DescriptorFile\n");
    put(b"version=1\n");
    put(b"CID=fffffffe\n");
    put(b"parentCID=ffffffff\n");
    put(b"createType=\"monolithicSparse\"\n\n");
    put(b"# Extent description\n");
    put(b"RW ");

    // Format capacity_sectors as decimal
    let mut num_buf = [0u8; 20]; // Max u64 decimal = 20 digits
    let num_str = format_u64(capacity_sectors, &mut num_buf);
    put(num_str);

    put(b" SPARSE \"output.vmdk\"\n\n");
    put(b"# The Disk Data Base\n");
    put(b"#DDB\n");

    pos - offset
}

/// Build a monolithicFlat descriptor into `buf` starting at
/// `offset`. Returns the number of bytes written.
///
/// `flat_filename` is the bare filename of the flat extent file
/// (e.g. `b"output-flat.vmdk"`). The descriptor is written as
/// pure ASCII text — no binary header is needed for flat images.
pub fn build_flat_descriptor(
    buf: &mut [u8],
    offset: usize,
    capacity_sectors: u64,
    flat_filename: &[u8],
) -> usize {
    let mut pos = offset;

    let mut put = |bytes: &[u8]| {
        let end = pos + bytes.len();
        if end <= buf.len() {
            buf[pos..end].copy_from_slice(bytes);
        }
        pos = end;
    };

    put(b"# Disk DescriptorFile\n");
    put(b"version=1\n");
    put(b"CID=fffffffe\n");
    put(b"parentCID=ffffffff\n");
    put(b"createType=\"monolithicFlat\"\n\n");
    put(b"# Extent description\n");
    put(b"RW ");

    let mut num_buf = [0u8; 20];
    let num_str = format_u64(capacity_sectors, &mut num_buf);
    put(num_str);

    put(b" FLAT \"");
    put(flat_filename);
    put(b"\" 0\n\n");
    put(b"# The Disk Data Base\n");
    put(b"#DDB\n");

    pos - offset
}

/// Sectors in every extent of a split VMDK except possibly the last:
/// 2 GiB, which is the size qemu cuts a `twoGbMaxExtent` image at.
pub const SPLIT_EXTENT_SECTORS: u64 = 4_194_304;

/// Heads in the CHS geometry qemu writes for a split VMDK. It is a
/// constant whatever the size of the disk.
pub const SPLIT_HEADS: u32 = 16;

/// Sectors per track in the CHS geometry qemu writes for a split VMDK.
/// Also a constant whatever the size of the disk.
pub const SPLIT_SECTORS_PER_TRACK: u32 = 63;

/// Which of the two split subformats a descriptor describes. They share
/// a layout rule and differ only in how each extent is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitKind {
    /// `twoGbMaxExtentSparse`: every extent is a sparse VMDK4 file.
    Sparse,
    /// `twoGbMaxExtentFlat`: every extent is a raw file.
    Flat,
}

/// How a split VMDK of a given virtual size is cut into extents, and
/// the CHS geometry its descriptor records.
///
/// Everything here is a pure function of the virtual size, so no caller
/// supplies `cylinders` or an extent size and two callers cannot derive
/// them differently. Use `split_layout` to build one, and
/// `sectors_of_extent` rather than re-deriving the short last extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitLayout {
    /// The virtual size in 512-byte sectors, rounded up.
    pub total_sectors: u64,
    /// Number of extent files. Zero only for a zero-byte disk.
    pub extent_count: u64,
    /// Sectors in the final extent: `SPLIT_EXTENT_SECTORS` when the size
    /// is an exact multiple of it, never a zero-length trailing extent.
    pub last_extent_sectors: u64,
    /// `total_sectors / (heads * sectors)`, truncating. Deliberately not
    /// clamped to the 65535 a real CHS geometry allows, because qemu
    /// does not: its 33 GiB split image records 68656.
    pub cylinders: u64,
    /// Always `SPLIT_HEADS`.
    pub heads: u32,
    /// Always `SPLIT_SECTORS_PER_TRACK`.
    pub sectors: u32,
    /// The subformat this layout is for.
    pub kind: SplitKind,
}

impl SplitLayout {
    /// The sector count of extent `index` (zero-based): a full extent
    /// for every one but the last, the remainder for the last, and zero
    /// for an index past the end.
    pub fn sectors_of_extent(&self, index: u64) -> u64 {
        if index >= self.extent_count {
            0
        } else if index + 1 == self.extent_count {
            // index < extent_count, so index + 1 cannot overflow.
            self.last_extent_sectors
        } else {
            SPLIT_EXTENT_SECTORS
        }
    }
}

/// Work out the extent layout and CHS geometry for a split VMDK of
/// `virtual_size_bytes`.
///
/// A size that is not a multiple of 512 is rounded up to the next
/// sector, and a size of zero gives zero extents and zero cylinders. No
/// pinned qemu case covers either: both are this function's own choice
/// of the least surprising answer. All arithmetic is overflow-free for
/// any `u64`, since the largest sector count is 2^55.
pub fn split_layout(virtual_size_bytes: u64, kind: SplitKind) -> SplitLayout {
    let total_sectors = virtual_size_bytes.div_ceil(VMDK_SECTOR);
    let extent_count = total_sectors.div_ceil(SPLIT_EXTENT_SECTORS);
    let remainder = total_sectors % SPLIT_EXTENT_SECTORS;
    let last_extent_sectors = if extent_count == 0 {
        0
    } else if remainder == 0 {
        SPLIT_EXTENT_SECTORS
    } else {
        remainder
    };
    let cylinders = total_sectors / (SPLIT_HEADS as u64 * SPLIT_SECTORS_PER_TRACK as u64);

    SplitLayout {
        total_sectors,
        extent_count,
        last_extent_sectors,
        cylinders,
        heads: SPLIT_HEADS,
        sectors: SPLIT_SECTORS_PER_TRACK,
        kind,
    }
}

/// Format a u64 as a decimal string in a fixed buffer.
/// Returns a slice of the formatted digits.
fn format_u64(mut val: u64, buf: &mut [u8; 20]) -> &[u8] {
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

/// Format `val` in decimal, left-padded with zeros to at least `min_width`
/// digits, in a fixed buffer. Returns a slice of the formatted digits.
///
/// The width is a floor, not a cap: a value with more digits than
/// `min_width` is written in full, which is what qemu does for the
/// thousandth extent of a split image (`image-s1000.vmdk`). A
/// `min_width` over 20 is treated as 20.
fn format_u64_padded(mut val: u64, min_width: usize, buf: &mut [u8; 20]) -> &[u8] {
    let width = if min_width > 20 { 20 } else { min_width };
    let mut pos = 20;
    while val > 0 {
        pos -= 1;
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    while 20 - pos < width {
        pos -= 1;
        buf[pos] = b'0';
    }
    if pos == 20 {
        pos = 19;
        buf[pos] = b'0';
    }
    &buf[pos..20]
}

/// Build a `twoGbMaxExtentSparse` or `twoGbMaxExtentFlat` descriptor into
/// `buf` starting at `offset`. Returns the number of bytes the descriptor
/// needs.
///
/// Like the other descriptor builders this has `snprintf` semantics: the
/// cursor advances past the end of the buffer but bytes are copied only
/// when they fit, so the return value is the full length whatever buffer
/// was given. Call it once with an empty slice to measure, allocate, and
/// call it again to write. That matters more here than for the
/// single-extent descriptors, because the length grows with the number of
/// extents and is not bounded by a constant.
///
/// Extent files are named `<prefix>-s<NNN><postfix>` for a sparse layout
/// and `<prefix>-f<NNN><postfix>` for a flat one, where `NNN` is the
/// one-based extent number zero-padded to at least three digits. `prefix`
/// is the base name without extension (e.g. `b"image"`) and `postfix` is
/// the extension including its dot (e.g. `b".vmdk"`). The geometry is
/// taken from `layout`, and the `CID` is a fixed value rather than the
/// random one qemu writes, so output is reproducible.
pub fn build_split_descriptor(
    buf: &mut [u8],
    offset: usize,
    layout: &SplitLayout,
    prefix: &[u8],
    postfix: &[u8],
) -> usize {
    let mut pos = offset;

    let mut put = |bytes: &[u8]| {
        let end = pos.saturating_add(bytes.len());
        if let Some(dst) = buf.get_mut(pos..end) {
            dst.copy_from_slice(bytes);
        }
        pos = end;
    };

    let (create_type, keyword, tag, start): (&[u8], &[u8], &[u8], &[u8]) = match layout.kind {
        SplitKind::Sparse => (b"twoGbMaxExtentSparse", b" SPARSE \"", b"-s", b"\"\n"),
        SplitKind::Flat => (b"twoGbMaxExtentFlat", b" FLAT \"", b"-f", b"\" 0\n"),
    };

    put(b"# Disk DescriptorFile\n");
    put(b"version=1\n");
    put(b"CID=fffffffe\n");
    put(b"parentCID=ffffffff\n");
    put(b"createType=\"");
    put(create_type);
    put(b"\"\n\n");
    put(b"# Extent description\n");

    let mut num_buf = [0u8; 20];
    let mut index = 0u64;
    while index < layout.extent_count {
        put(b"RW ");
        put(format_u64(layout.sectors_of_extent(index), &mut num_buf));
        put(keyword);
        put(prefix);
        put(tag);
        // index < extent_count <= 2^33, so index + 1 cannot overflow.
        put(format_u64_padded(index + 1, 3, &mut num_buf));
        put(postfix);
        put(start);
        index += 1;
    }

    put(b"\n# The Disk Data Base\n");
    put(b"#DDB\n\n");
    put(b"ddb.virtualHWVersion = \"4\"\n");
    put(b"ddb.geometry.cylinders = \"");
    put(format_u64(layout.cylinders, &mut num_buf));
    put(b"\"\n");
    put(b"ddb.geometry.heads = \"");
    put(format_u64(layout.heads as u64, &mut num_buf));
    put(b"\"\n");
    put(b"ddb.geometry.sectors = \"");
    put(format_u64(layout.sectors as u64, &mut num_buf));
    put(b"\"\n");
    put(b"ddb.adapterType = \"ide\"\n");
    put(b"ddb.toolsVersion = \"2147483647\"\n");

    pos.saturating_sub(offset)
}

/// Build a metadata marker into a 512-byte buffer.
///
/// Used in streamOptimized VMDK output. Each metadata section
/// (GT, GD, footer) is preceded by a sector-sized marker.
///
/// `buf` must be at least 512 bytes and should be pre-zeroed.
/// `num_sectors` is the number of data sectors that follow.
/// `marker_type` is one of MARKER_GT, MARKER_GD, MARKER_FOOTER,
/// or MARKER_EOS.
pub fn build_metadata_marker(buf: &mut [u8], num_sectors: u64, marker_type: u32) {
    write_le_u64(buf, 0, num_sectors);
    write_le_u32(buf, 8, 0); // size (unused for metadata markers)
    write_le_u32(buf, 12, marker_type);
}

// ============================================================================
// Basic header parsing (used by info operation)
// ============================================================================

/// Parsed VMDK4 binary header fields (basic subset).
///
/// This struct parses the minimum fields needed for format detection
/// and metadata reporting. For grain table operations, use
/// [`Vmdk4HeaderFull`].
pub struct Vmdk4Header {
    pub version: u32,
    pub capacity_sectors: u64,
    pub virtual_size: u64,
    pub grain_size_sectors: u64,
    pub cluster_size: u32,
    pub desc_offset_sectors: u64,
    pub desc_size_sectors: u64,
}

impl Vmdk4Header {
    /// Parse a VMDK4 binary header from raw bytes.
    ///
    /// `header` must contain at least 44 bytes (through desc_size
    /// field). Returns `None` if the buffer is too small.
    pub fn parse(header: &[u8]) -> Option<Self> {
        if header.len() < HEADER_MIN_SIZE {
            return None;
        }

        let version = le_u32(header, VERSION_OFFSET);
        let capacity_sectors = le_u64(header, CAPACITY_OFFSET);
        let grain_size_sectors = le_u64(header, GRAIN_SIZE_OFFSET);
        let desc_offset_sectors = le_u64(header, DESC_OFFSET_OFFSET);
        let desc_size_sectors = le_u64(header, DESC_SIZE_OFFSET);

        let virtual_size = capacity_sectors.checked_mul(512)?;
        let cluster_size = u32::try_from(grain_size_sectors.checked_mul(512)?).ok()?;

        Some(Vmdk4Header {
            version,
            capacity_sectors,
            virtual_size,
            grain_size_sectors,
            cluster_size,
            desc_offset_sectors,
            desc_size_sectors,
        })
    }
}

// ============================================================================
// Full header parsing (for grain table operations)
// ============================================================================

/// Fully parsed VMDK4 binary header including grain directory/table
/// fields.
pub struct Vmdk4HeaderFull {
    pub version: u32,
    pub flags: u32,
    pub capacity_sectors: u64,
    pub virtual_size: u64,
    pub grain_size_sectors: u64,
    pub grain_size_bytes: u64,
    pub desc_offset_sectors: u64,
    pub desc_size_sectors: u64,
    pub num_gtes_per_gt: u32,
    pub rgd_offset_sectors: u64,
    pub gd_offset_sectors: u64,
    pub overhead_sectors: u64,
    pub compress_algorithm: u16,
    pub has_zero_grain: bool,
    pub is_compressed: bool,
}

impl Vmdk4HeaderFull {
    /// Parse a full VMDK4 binary header from raw bytes.
    ///
    /// `header` must contain at least [`HEADER_FULL_SIZE`] bytes.
    /// Returns `None` if the buffer is too small or fields overflow.
    pub fn parse(header: &[u8]) -> Option<Self> {
        if header.len() < HEADER_FULL_SIZE {
            return None;
        }

        let version = le_u32(header, VERSION_OFFSET);
        let flags = le_u32(header, FLAGS_OFFSET);
        let capacity_sectors = le_u64(header, CAPACITY_OFFSET);
        let grain_size_sectors = le_u64(header, GRAIN_SIZE_OFFSET);
        let desc_offset_sectors = le_u64(header, DESC_OFFSET_OFFSET);
        let desc_size_sectors = le_u64(header, DESC_SIZE_OFFSET);
        let num_gtes_per_gt = le_u32(header, NUM_GTES_PER_GT_OFFSET);
        let rgd_offset_sectors = le_u64(header, RGD_OFFSET_OFFSET);
        let gd_offset_sectors = le_u64(header, GD_OFFSET_OFFSET);
        let overhead_sectors = le_u64(header, OVERHEAD_OFFSET);
        let compress_algorithm = le_u16(header, COMPRESS_ALGORITHM_OFFSET);

        let virtual_size = capacity_sectors.checked_mul(512)?;
        let grain_size_bytes = grain_size_sectors.checked_mul(512)?;

        let has_zero_grain = (flags & FLAG_ZERO_GRAIN) != 0;
        let is_compressed = (flags & FLAG_COMPRESSED) != 0;

        Some(Vmdk4HeaderFull {
            version,
            flags,
            capacity_sectors,
            virtual_size,
            grain_size_sectors,
            grain_size_bytes,
            desc_offset_sectors,
            desc_size_sectors,
            num_gtes_per_gt,
            rgd_offset_sectors,
            gd_offset_sectors,
            overhead_sectors,
            compress_algorithm,
            has_zero_grain,
            is_compressed,
        })
    }

    /// Calculate the number of grain directory entries needed to cover
    /// the full virtual disk capacity.
    pub fn num_gd_entries(&self) -> Option<u32> {
        if self.grain_size_sectors == 0 || self.num_gtes_per_gt == 0 {
            return None;
        }
        // Sectors covered by one grain table
        let sectors_per_gt = (self.num_gtes_per_gt as u64).checked_mul(self.grain_size_sectors)?;
        // Round up: ceil(capacity / sectors_per_gt)
        let count = self.capacity_sectors.checked_add(sectors_per_gt - 1)? / sectors_per_gt;
        u32::try_from(count).ok()
    }
}

// ============================================================================
// Grain lookup result
// ============================================================================

/// Result of looking up a virtual offset in the VMDK grain tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrainLookup {
    /// The grain is not allocated (reads as zeros or from backing).
    Unallocated,
    /// The grain is explicitly zeroed (FLAG_ZERO_GRAIN, GTE == 1).
    Zeroed,
    /// Standard (uncompressed) grain at the given host byte offset.
    Standard(u64),
    /// Compressed grain: the GTE value is the sector offset to the
    /// grain marker.
    Compressed(u64),
}

// ============================================================================
// Allocation-counting pure helpers
// ============================================================================

/// Count non-zero entries in a VMDK grain-directory byte slice.
///
/// Each entry is a little-endian u32 grain-table sector pointer.
/// A zero entry indicates the GT is unallocated. Returns the
/// count of populated GTs.
///
/// `gd_bytes` may have a trailing partial entry; incomplete u32
/// entries at the tail are ignored.
pub fn count_populated_gd_entries(gd_bytes: &[u8]) -> u64 {
    gd_bytes
        .chunks_exact(4)
        .filter(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) != 0)
        .count() as u64
}

/// Count allocated entries in a VMDK grain-table byte slice.
///
/// Each entry is a little-endian u32 grain sector pointer. Entries
/// that are 0 or `ZERO_GRAIN_MARKER` (0xFFFFFFFE — an explicit
/// zero-grain marker used by qemu-img for monolithicSparse output)
/// count as unallocated. Any other value indicates an allocated grain.
///
/// `gt_bytes` may have a trailing partial entry; incomplete u32
/// entries at the tail are ignored.
pub fn count_allocated_in_gt(gt_bytes: &[u8]) -> u64 {
    gt_bytes
        .chunks_exact(4)
        .filter(|c| {
            let v = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            v != 0 && v != ZERO_GRAIN_MARKER
        })
        .count() as u64
}

/// Classify one VMDK grain-table entry into a single `MapExtent`.
///
/// Mirrors `VmdkState::grain_lookup`'s decision tree, augmented with
/// the explicit `ZERO_GRAIN_MARKER` (0xFFFF_FFFE) sentinel that
/// `count_allocated_in_gt` already treats as unallocated-but-zero
/// (used by qemu-img for monolithicSparse output to mark
/// explicit-zero grains).
///
/// - `entry == 0` (`GTE_UNALLOCATED`): `Hole`.
/// - `entry == GTE_ZEROED` (`1`), when `has_zero_grain` is set:
///   `ZeroAllocated`. (FLAG_ZERO_GRAIN is on header; without it the
///   `1` is technically a malformed grain pointer — fall through to
///   the Data path. Mirrors `grain_lookup`'s feature gate.)
/// - `entry == ZERO_GRAIN_MARKER` (`0xFFFF_FFFE`): `ZeroAllocated`.
/// - Otherwise: `Data { file_offset: (entry as u64) * 512 }`. For
///   compressed (streamOptimized) VMDKs this is the marker offset
///   (12-byte grain header + compressed payload), matching
///   `grain_lookup`'s compressed-path semantics. For standard VMDKs
///   it is the grain data offset.
///
/// `grain_size_bytes` is the extent's length; `virtual_offset` is
/// the virtual address of the grain's first byte. The caller is
/// responsible for clamping `length` against virtual_size if the
/// grain straddles end-of-image.
pub fn classify_vmdk_gt_entry(
    entry: u32,
    virtual_offset: u64,
    grain_size_bytes: u64,
    has_zero_grain: bool,
) -> MapExtent {
    let state = if entry == GTE_UNALLOCATED {
        MapExtentState::Hole
    } else if (has_zero_grain && entry == GTE_ZEROED) || entry == ZERO_GRAIN_MARKER {
        MapExtentState::ZeroAllocated
    } else {
        MapExtentState::Data {
            file_offset: (entry as u64).saturating_mul(512),
        }
    };
    MapExtent {
        start: virtual_offset,
        length: grain_size_bytes,
        state,
    }
}

// ============================================================================
// VMDK state for grain table I/O
// ============================================================================

/// Runtime state for reading VMDK grain tables from a device.
///
/// Analogous to `qcow2::Qcow2State`. Maintains sector caches for
/// the grain directory and grain table reads.
pub struct VmdkState {
    pub device_idx: u32,
    pub grain_size_sectors: u64,
    pub grain_size_bytes: u64,
    pub num_gtes_per_gt: u32,
    pub gd_offset_sectors: u64,
    pub num_gd_entries: u32,
    pub capacity_sectors: u64,
    pub has_zero_grain: bool,
    pub is_compressed: bool,
    /// Byte offset within the device at which this image's file
    /// begins: zero for an image that is the whole device, and
    /// wherever its file was laid for one extent of a multi-extent
    /// descriptor. Every offset a sparse image holds -- its grain
    /// directory's, each grain table's, each grain's -- counts sectors
    /// from the start of its own file, so each one is read at this
    /// plus that.
    pub base_offset: u64,
    /// Byte offset within the device at which this image's file ends,
    /// or `u64::MAX` for an image that is the whole device, which ends
    /// where the device does. Nothing the image points at is read past
    /// it. For an extent the bytes that follow are the next extent's
    /// file, and an entry pointing there would otherwise be served
    /// that file's header and tables as this one's data.
    pub image_end: u64,
    // Sector cache for grain directory reads
    pub gd_cached_sector: u64,
    pub gd_cache_buf: *mut u8,
    // Sector cache for grain table reads
    pub gt_cached_sector: u64,
    pub gt_cache_buf: *mut u8,
}

impl VmdkState {
    /// Initialize VMDK state by reading the header from a device.
    ///
    /// Reads and validates the full header, sets up cache pointers.
    /// For streamOptimized images (`gd_offset == GD_AT_END`), reads
    /// the footer to find the real GD offset.
    ///
    /// Returns `None` if the header is invalid, I/O fails, or the
    /// image is not a supported monolithic VMDK.
    ///
    /// # Safety
    ///
    /// `gd_cache_buf` and `gt_cache_buf` must each point to at least
    /// `MAX_SECTOR_SIZE` writable bytes. `call_table` must be valid.
    pub unsafe fn init(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        actual_file_size: u64,
        gd_cache_buf: *mut u8,
        gt_cache_buf: *mut u8,
        bytes_read: &mut u64,
    ) -> Option<Self> {
        Self::init_image(
            call_table,
            device_idx,
            sector_size,
            input_capacity,
            None,
            actual_file_size,
            gd_cache_buf,
            gt_cache_buf,
            bytes_read,
        )
    }

    /// Initialize VMDK state for a sparse image that begins partway
    /// through a device: one extent of a multi-extent descriptor, whose
    /// files the host lays end to end as a single device.
    ///
    /// `base_offset` is the byte offset within the device at which the
    /// extent's file begins, and `file_length` the length of that file.
    /// Each extent is a sparse image in its own right, covering only its
    /// own span, so its header is read at `base_offset` and everything
    /// the header and tables point at is found relative to it. The
    /// state [`Self::init`] builds assumes its image starts at device
    /// offset zero, which is true of exactly one extent.
    ///
    /// Stricter than [`Self::init`] in four ways, each because the
    /// image is not alone on its device:
    ///
    /// * The header must carry the VMDK4 magic. A whole device reaches
    ///   `init` only after format detection found the magic there; an
    ///   extent reaches this because a descriptor's extent line called
    ///   its file sparse, and nothing has looked at the file.
    /// * `base_offset` must be a multiple of 512. Sparse VMDK counts in
    ///   512-byte sectors from the start of the file, so only then do
    ///   the header and every table entry sit whole inside one device
    ///   sector, whatever the device's sector size.
    /// * The header, the grain directory, each grain table entry and
    ///   each grain must lie inside the file. Past its end is the next
    ///   extent's file, not the end of the device.
    /// * A compressed image is refused. A compressed grain's length is
    ///   stated only by the marker in front of it, so nothing here can
    ///   hold it to the file. qemu compresses only the stream-optimised
    ///   subformat, which is a single file, so the extents of the split
    ///   subformats it writes are never compressed; it would read one
    ///   that was, and this does not.
    ///
    /// Returns `None` on any of those, or where `init` would.
    ///
    /// # Safety
    ///
    /// `gd_cache_buf` and `gt_cache_buf` must each point to at least
    /// `MAX_SECTOR_SIZE` writable bytes. `call_table` must be valid.
    pub unsafe fn init_at(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        base_offset: u64,
        file_length: u64,
        gd_cache_buf: *mut u8,
        gt_cache_buf: *mut u8,
        bytes_read: &mut u64,
    ) -> Option<Self> {
        let state = Self::init_image(
            call_table,
            device_idx,
            sector_size,
            input_capacity,
            Some(base_offset),
            file_length,
            gd_cache_buf,
            gt_cache_buf,
            bytes_read,
        )?;
        if state.is_compressed {
            return None;
        }
        Some(state)
    }

    /// Whether this state was read from the image whose file occupies
    /// `file_length` bytes of the device from `base_offset`.
    ///
    /// A device holding several extents keeps the state of one at a
    /// time, and this is how a reader tells whether the one it holds is
    /// the one it wants: a state is a parse of the bytes in a range, so
    /// it serves whichever extent occupies exactly that range.
    pub fn is_image_at(&self, base_offset: u64, file_length: u64) -> bool {
        self.base_offset == base_offset
            && base_offset.checked_add(file_length) == Some(self.image_end)
    }

    /// Where byte `file_offset` of this image's own file sits in the
    /// device, or `None` if that is past the addressable range.
    #[inline]
    fn device_offset(&self, file_offset: u64) -> Option<u64> {
        self.base_offset.checked_add(file_offset)
    }

    /// The body of [`Self::init`] and [`Self::init_at`].
    ///
    /// `extent_base` is `None` for an image that is the whole device
    /// and the offset its file begins at otherwise. `file_size` is the
    /// length of the image's own file either way: the footer of a
    /// stream-optimised image is found from it.
    ///
    /// # Safety
    ///
    /// As [`Self::init`].
    unsafe fn init_image(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        extent_base: Option<u64>,
        file_size: u64,
        gd_cache_buf: *mut u8,
        gt_cache_buf: *mut u8,
        bytes_read: &mut u64,
    ) -> Option<Self> {
        // Where the image's file sits in the device, and where its
        // 512-byte header is: the device sector holding it and the
        // header's offset within that sector. An image that is the
        // whole device has its header at the start of sector 0. An
        // extent's base is a multiple of 512, so its header starts on a
        // 512-byte boundary of some device sector and, a device sector
        // being a multiple of 512 itself, ends inside the same one; a
        // sector size that would break that is refused rather than
        // read across.
        let (base_offset, image_end, header_sector, header_at) = match extent_base {
            Some(base) => {
                let ssz = sector_size as u64;
                if sector_size == 0 || sector_size > MAX_SECTOR_SIZE {
                    return None;
                }
                if !base.is_multiple_of(VMDK_SECTOR) || file_size < VMDK_SECTOR {
                    return None;
                }
                let header_at = (base % ssz) as usize;
                if header_at + VMDK_SECTOR as usize > sector_size {
                    return None;
                }
                (base, base.checked_add(file_size)?, base / ssz, header_at)
            }
            None => (0, u64::MAX, 0, 0),
        };

        let mut header_buf = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(
            device_idx,
            header_sector,
            header_buf.as_mut_ptr(),
            sector_size,
        ) {
            return None;
        }
        *bytes_read += sector_size as u64;
        let header_bytes = &header_buf[header_at..];

        if extent_base.is_some() && le_u32(header_bytes, MAGIC_OFFSET) != VMDK4_MAGIC {
            return None;
        }

        let header = Vmdk4HeaderFull::parse(header_bytes)?;

        // Validate basic fields
        if header.version == 0 || header.version > 3 {
            return None;
        }
        if header.capacity_sectors == 0 {
            return None;
        }
        if header.grain_size_sectors == 0
            || (header.grain_size_sectors & (header.grain_size_sectors - 1)) != 0
        {
            return None; // Must be power of 2
        }
        if header.num_gtes_per_gt == 0 {
            return None;
        }

        let num_gd_entries = header.num_gd_entries()?;
        if num_gd_entries == 0 {
            return None;
        }

        // Resolve GD offset
        let gd_offset_sectors = if header.gd_offset_sectors == GD_AT_END {
            // streamOptimized: read footer from end of file.
            // Footer is at (EOF - 3 sectors) in 512-byte sector
            // units, but we use the device's sector size.
            Self::read_footer_gd_offset(
                call_table,
                device_idx,
                sector_size,
                input_capacity,
                base_offset,
                file_size,
                bytes_read,
            )?
        } else {
            header.gd_offset_sectors
        };

        // Validate GD offset. The grain directory has to be inside the
        // device and, for an extent, inside the extent's own file: the
        // nearer of the two ends is the limit.
        let actual_size = input_capacity.checked_mul(sector_size as u64)?;
        let limit = actual_size.min(image_end);
        let gd_byte_offset = base_offset.checked_add(gd_offset_sectors.checked_mul(512)?)?;
        if gd_byte_offset >= limit {
            return None;
        }
        // Validate GD doesn't extend beyond file
        let gd_size_bytes = (num_gd_entries as u64).checked_mul(4)?;
        let gd_end = gd_byte_offset.checked_add(gd_size_bytes)?;
        if gd_end > limit {
            return None;
        }

        Some(VmdkState {
            device_idx,
            grain_size_sectors: header.grain_size_sectors,
            grain_size_bytes: header.grain_size_bytes,
            num_gtes_per_gt: header.num_gtes_per_gt,
            gd_offset_sectors,
            num_gd_entries,
            capacity_sectors: header.capacity_sectors,
            has_zero_grain: header.has_zero_grain,
            is_compressed: header.is_compressed,
            base_offset,
            image_end,
            gd_cached_sector: u64::MAX,
            gd_cache_buf,
            gt_cached_sector: u64::MAX,
            gt_cache_buf,
        })
    }

    /// Read the footer of a streamOptimized VMDK to find the real GD
    /// offset.
    ///
    /// The footer is a copy of the VMDK4 header located 1536 bytes
    /// before EOF (3 x 512-byte sectors). Its `gd_offset` field
    /// contains the actual grain directory location.
    ///
    /// `base_offset` is where the image's file begins in the device:
    /// the end of file the footer is counted back from is the file's
    /// own, `actual_file_size` bytes on from there.
    unsafe fn read_footer_gd_offset(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        base_offset: u64,
        actual_file_size: u64,
        bytes_read: &mut u64,
    ) -> Option<u64> {
        // Footer is at EOF - 1024 bytes (the middle of the last 3
        // 512-byte sectors: footer_marker | footer_header | eos).
        // We must use the actual file size here, not capacity *
        // sector_size, because when the file size doesn't evenly
        // divide the sector size the capacity is rounded up and
        // the calculated offset would land in zero-padded space
        // beyond the real file data.
        let footer_byte_offset = base_offset.checked_add(actual_file_size.checked_sub(1024)?)?;
        let footer_sector = footer_byte_offset / sector_size as u64;
        let offset_in_sector = (footer_byte_offset % sector_size as u64) as usize;

        if footer_sector >= input_capacity {
            return None;
        }

        let mut buf = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(device_idx, footer_sector, buf.as_mut_ptr(), sector_size)
        {
            return None;
        }
        *bytes_read += sector_size as u64;

        // Validate footer magic
        if offset_in_sector + HEADER_FULL_SIZE > sector_size {
            // Footer spans sector boundary; need to read next sector
            // too. For simplicity, require footer fits in one sector.
            // With 512-byte sectors this is always true. With larger
            // sectors, the footer header (512 bytes) will always fit
            // within a single sector.
            return None;
        }
        let footer = &buf[offset_in_sector..];
        let magic = le_u32(footer, MAGIC_OFFSET);
        if magic != VMDK4_MAGIC {
            return None;
        }

        // Read the real GD offset from the footer header
        if footer.len() < GD_OFFSET_OFFSET + 8 {
            return None;
        }
        let gd_offset = le_u64(footer, GD_OFFSET_OFFSET);
        if gd_offset == GD_AT_END {
            return None; // Footer should have the real offset
        }
        Some(gd_offset)
    }

    /// Look up the host location for a given virtual byte offset.
    ///
    /// Performs two-level address translation through the grain
    /// directory (L1) and grain table (L2). Returns the grain type
    /// or `None` on I/O error.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. Cache buffers must still be valid.
    pub unsafe fn grain_lookup(
        &mut self,
        call_table: &CallTable,
        virtual_offset: u64,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<GrainLookup> {
        // Calculate virtual sector and indices
        let virtual_sector = virtual_offset / 512;

        // Sectors covered by one grain table
        let sectors_per_gt = (self.num_gtes_per_gt as u64).checked_mul(self.grain_size_sectors)?;

        // L1 index (which grain table)
        let gd_index = virtual_sector / sectors_per_gt;

        // L2 index (which entry within the grain table)
        let gt_index = (virtual_sector / self.grain_size_sectors) % self.num_gtes_per_gt as u64;

        // Bounds check GD index
        if gd_index >= self.num_gd_entries as u64 {
            return Some(GrainLookup::Unallocated);
        }

        // Read GD entry (u32 LE, sector offset to grain table)
        let gd_byte_offset = self.device_offset(
            self.gd_offset_sectors
                .checked_mul(512)?
                .checked_add(gd_index.checked_mul(4)?)?,
        )?;
        let gd_entry = read_u32_le_cached(
            call_table,
            self.device_idx,
            gd_byte_offset,
            sector_size,
            input_capacity,
            &mut self.gd_cached_sector,
            self.gd_cache_buf,
            bytes_read,
        )?;

        if gd_entry == 0 {
            return Some(GrainLookup::Unallocated);
        }

        // Read GT entry (u32 LE, sector offset to grain data)
        let gt_byte_offset = self.device_offset(
            (gd_entry as u64)
                .checked_mul(512)?
                .checked_add(gt_index.checked_mul(4)?)?,
        )?;

        // Validate GT offset within file
        let actual_size = input_capacity.checked_mul(sector_size as u64)?;
        if gt_byte_offset >= actual_size {
            return None;
        }
        // And, for an extent, within the extent's own file. Never true
        // of an image that is the whole device, whose end is the
        // device's and was checked just above.
        if gt_byte_offset.saturating_add(4) > self.image_end {
            return None;
        }

        let gte = read_u32_le_cached(
            call_table,
            self.device_idx,
            gt_byte_offset,
            sector_size,
            input_capacity,
            &mut self.gt_cached_sector,
            self.gt_cache_buf,
            bytes_read,
        )?;

        if gte == GTE_UNALLOCATED {
            return Some(GrainLookup::Unallocated);
        }

        if self.has_zero_grain && gte == GTE_ZEROED {
            return Some(GrainLookup::Zeroed);
        }

        // Either way the GTE counts sectors from the start of the
        // image's own file, and what is returned is where that is in
        // the device, which is what the caller reads.
        if self.is_compressed {
            // For compressed images, the GTE is the sector offset
            // to the grain marker (12-byte header + compressed data).
            // Only an image that is the whole device is compressed
            // (`init_at` refuses one), so there is no file end short of
            // the device's to hold the grain to.
            let marker_byte_offset = self.device_offset((gte as u64).checked_mul(512)?)?;
            Some(GrainLookup::Compressed(marker_byte_offset))
        } else {
            // Standard grain: GTE is sector offset to grain data.
            let host_byte_offset = self.device_offset((gte as u64).checked_mul(512)?)?;
            // An extent's grain is the extent's own bytes or it is not
            // read: past the end of its file is the next extent's.
            if host_byte_offset.saturating_add(self.grain_size_bytes) > self.image_end {
                return None;
            }
            Some(GrainLookup::Standard(host_byte_offset))
        }
    }

    /// Walk the grain directory and per-GD-entry grain tables, and
    /// produce an `AllocationSummary`.
    ///
    /// `virtual_size = capacity_sectors * 512`. `allocated_bytes` is
    /// the number of allocated grains across all populated grain tables,
    /// multiplied by `grain_size_bytes`.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. `gd_cache_buf` and `gt_cache_buf`
    /// must still be valid and each point to at least `MAX_SECTOR_SIZE`
    /// writable bytes.
    pub unsafe fn scan_allocation(
        &mut self,
        call_table: &CallTable,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<AllocationSummary> {
        let virtual_size = self.capacity_sectors.checked_mul(512)?;

        // The grain table for one GD entry is num_gtes_per_gt u32-LE
        // entries, i.e. num_gtes_per_gt * 4 bytes.
        let gt_size_bytes = (self.num_gtes_per_gt as u64).checked_mul(4)?;

        let mut allocated_grains: u64 = 0;

        for gd_index in 0..self.num_gd_entries as u64 {
            // Compute byte offset of this GD entry.
            let gd_byte_offset = self.device_offset(
                self.gd_offset_sectors
                    .checked_mul(512)?
                    .checked_add(gd_index.checked_mul(4)?)?,
            )?;

            let gd_entry = read_u32_le_cached(
                call_table,
                self.device_idx,
                gd_byte_offset,
                sector_size,
                input_capacity,
                &mut self.gd_cached_sector,
                self.gd_cache_buf,
                bytes_read,
            )?;

            if gd_entry == 0 {
                // GT is unallocated; all grains in it are unallocated.
                continue;
            }

            // The GT starts gd_entry * 512 bytes into the image's file.
            let gt_start_byte = self.device_offset((gd_entry as u64).checked_mul(512)?)?;
            let gt_end_byte = gt_start_byte.checked_add(gt_size_bytes)?;
            if gt_end_byte > self.image_end {
                return None;
            }

            // Walk the GT in MAX_SECTOR_SIZE-sized chunks.
            let gt_start_sector = gt_start_byte / sector_size as u64;
            let gt_end_sector =
                gt_end_byte.checked_add(sector_size as u64 - 1)? / sector_size as u64;

            let mut gt_bytes_consumed: u64 = 0;

            let mut sector = gt_start_sector;
            while sector < gt_end_sector {
                if sector >= input_capacity {
                    return None;
                }
                if !(call_table.read_input_sector)(
                    self.device_idx,
                    sector,
                    self.gt_cache_buf,
                    sector_size,
                ) {
                    return None;
                }
                *bytes_read += sector_size as u64;
                self.gt_cached_sector = sector;

                let sector_byte_start = sector * sector_size as u64;
                let buf_start = if sector_byte_start < gt_start_byte {
                    (gt_start_byte - sector_byte_start) as usize
                } else {
                    0
                };
                let buf_end =
                    sector_size.min((gt_end_byte.saturating_sub(sector_byte_start)) as usize);
                if buf_end <= buf_start {
                    sector += 1;
                    continue;
                }

                let chunk = core::slice::from_raw_parts(
                    self.gt_cache_buf.add(buf_start),
                    buf_end - buf_start,
                );

                // Clamp to the meaningful GT bytes (ignore sector padding).
                let meaningful_len =
                    (gt_size_bytes - gt_bytes_consumed).min((buf_end - buf_start) as u64) as usize;
                let meaningful = &chunk[..meaningful_len];

                allocated_grains += count_allocated_in_gt(meaningful);
                gt_bytes_consumed += meaningful_len as u64;

                sector += 1;
            }
        }

        // AllocationSummary::clamp keeps `allocated_bytes <=
        // virtual_size` even when the last allocated grain extends
        // past the declared virtual size. Mirrors the qcow2 allocation
        // scan's out-of-bounds skip: the measure path and
        // `fuzz_measure_scan` depend on `allocated_bytes <=
        // virtual_size`.
        let allocated_bytes = allocated_grains.saturating_mul(self.grain_size_bytes);
        Some(AllocationSummary::clamp(
            virtual_size,
            allocated_bytes,
            // TODO(#286): populate from target_unit_size when this
            // scanner is converted to target-aware accounting.
            0,
        ))
    }

    /// Walk the grain directory and per-GD-entry grain tables, and
    /// emit a coalesced `MapExtent` stream covering
    /// `[0, virtual_size)`.
    ///
    /// Single-extent monolithicSparse / monolithicFlat /
    /// streamOptimized only — multi-extent descriptor-driven layouts
    /// are not propagated here (the parser returns the top extent
    /// only, matching `scan_allocation`'s posture). Multi-extent
    /// sources never reach this walker in the map op: `VmdkState::init`
    /// handles only single-extent binary headers, so they fail init.
    ///
    /// The walker mirrors `scan_allocation` for sector reading and
    /// GD/GT traversal but classifies each GT entry via
    /// [`classify_vmdk_gt_entry`] and pushes the result through a
    /// `MapExtentCoalescer`. The coalescer persists across GT
    /// boundaries so adjacent Data grains with contiguous file
    /// offsets collapse into one extent.
    ///
    /// GD entries that are zero emit one `Hole` per GT-coverage
    /// range. A trailing `Hole` covers any virtual range past the
    /// last walked grain up to `virtual_size`.
    ///
    /// A `Data` extent's `file_offset` is an offset into the image's
    /// own file, as the grain table states it, whatever
    /// [`Self::base_offset`] is: it names where the data is in the
    /// file a user can open, not where the host laid that file in the
    /// device.
    ///
    /// Returns `Some(())` on success (including early termination);
    /// `None` on I/O failure.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. `gd_cache_buf` and `gt_cache_buf`
    /// must still each point to at least `MAX_SECTOR_SIZE` writable
    /// bytes.
    pub unsafe fn map_extents<F: FnMut(MapExtent) -> bool>(
        &mut self,
        call_table: &CallTable,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
        emit: &mut F,
    ) -> Option<()> {
        let virtual_size = self.capacity_sectors.checked_mul(512)?;
        if virtual_size == 0 {
            return Some(());
        }

        let grain_size_bytes = self.grain_size_bytes;
        let has_zero_grain = self.has_zero_grain;
        let gt_size_bytes = (self.num_gtes_per_gt as u64).checked_mul(4)?;
        let gt_coverage = (self.num_gtes_per_gt as u64).checked_mul(grain_size_bytes)?;

        let mut coalescer = MapExtentCoalescer::new(emit);
        let mut next_unwalked: u64 = 0;

        'gd_loop: for gd_index in 0..self.num_gd_entries as u64 {
            let gd_byte_offset = self.device_offset(
                self.gd_offset_sectors
                    .checked_mul(512)?
                    .checked_add(gd_index.checked_mul(4)?)?,
            )?;
            let gd_entry = read_u32_le_cached(
                call_table,
                self.device_idx,
                gd_byte_offset,
                sector_size,
                input_capacity,
                &mut self.gd_cached_sector,
                self.gd_cache_buf,
                bytes_read,
            )?;

            let gd_virtual_start = gd_index.saturating_mul(gt_coverage);
            if gd_virtual_start >= virtual_size {
                continue;
            }
            let gd_remaining = virtual_size - gd_virtual_start;
            let gd_visible_span = gt_coverage.min(gd_remaining);

            if gd_entry == 0 {
                let cont = coalescer.push(MapExtent {
                    start: gd_virtual_start,
                    length: gd_visible_span,
                    state: MapExtentState::Hole,
                });
                next_unwalked = gd_virtual_start.saturating_add(gd_visible_span);
                if !cont {
                    break 'gd_loop;
                }
                continue;
            }

            let gt_start_byte = self.device_offset((gd_entry as u64).checked_mul(512)?)?;
            let gt_end_byte = gt_start_byte.checked_add(gt_size_bytes)?;
            if gt_end_byte > self.image_end {
                return None;
            }
            let gt_start_sector = gt_start_byte / sector_size as u64;
            let gt_end_sector =
                gt_end_byte.checked_add(sector_size as u64 - 1)? / sector_size as u64;

            let mut gt_bytes_consumed: u64 = 0;
            let mut sector = gt_start_sector;
            while sector < gt_end_sector {
                if sector >= input_capacity {
                    return None;
                }
                if !(call_table.read_input_sector)(
                    self.device_idx,
                    sector,
                    self.gt_cache_buf,
                    sector_size,
                ) {
                    return None;
                }
                *bytes_read += sector_size as u64;
                self.gt_cached_sector = sector;

                let sector_byte_start = sector * sector_size as u64;
                let buf_start = if sector_byte_start < gt_start_byte {
                    (gt_start_byte - sector_byte_start) as usize
                } else {
                    0
                };
                let buf_end =
                    sector_size.min((gt_end_byte.saturating_sub(sector_byte_start)) as usize);
                if buf_end <= buf_start {
                    sector += 1;
                    continue;
                }
                let chunk = core::slice::from_raw_parts(
                    self.gt_cache_buf.add(buf_start),
                    buf_end - buf_start,
                );
                let meaningful_len =
                    (gt_size_bytes - gt_bytes_consumed).min((buf_end - buf_start) as u64) as usize;
                let meaningful = &chunk[..meaningful_len];

                let chunk_entry_count = (meaningful_len as u64) / 4;
                let base_entry_index = gt_bytes_consumed / 4;

                for k in 0..chunk_entry_count {
                    let off = (k as usize) * 4;
                    let entry = u32::from_le_bytes([
                        meaningful[off],
                        meaningful[off + 1],
                        meaningful[off + 2],
                        meaningful[off + 3],
                    ]);
                    let global_idx = base_entry_index + k;
                    let grain_virt = gd_virtual_start
                        .saturating_add(global_idx.saturating_mul(grain_size_bytes));
                    if grain_virt >= virtual_size {
                        break;
                    }
                    let grain_visible = grain_size_bytes.min(virtual_size - grain_virt);

                    let mut ext =
                        classify_vmdk_gt_entry(entry, grain_virt, grain_size_bytes, has_zero_grain);
                    if ext.length > grain_visible {
                        ext.length = grain_visible;
                    }
                    let cont = coalescer.push(ext);
                    next_unwalked = grain_virt.saturating_add(grain_visible);
                    if !cont {
                        break 'gd_loop;
                    }
                }

                gt_bytes_consumed += meaningful_len as u64;
                sector += 1;
            }
        }

        if next_unwalked < virtual_size {
            let _ = coalescer.push(MapExtent {
                start: next_unwalked,
                length: virtual_size - next_unwalked,
                state: MapExtentState::Hole,
            });
        }
        let _ = coalescer.finish();
        Some(())
    }
}

// ============================================================================
// Compressed grain reading (streamOptimized VMDK)
// ============================================================================

/// Read and decompress a compressed grain from a streamOptimized VMDK.
///
/// The grain marker is 12 bytes at `marker_byte_offset`:
/// - u64 LE: uncompressed LBA (sector number)
/// - u32 LE: compressed data size in bytes
///
/// Immediately after the marker is the DEFLATE-compressed grain data.
/// Decompression uses miniz_oxide (tries zlib-wrapped first, then raw
/// DEFLATE).
///
/// # Safety
///
/// `out_buf` must point to at least `grain_size_bytes` writable bytes.
/// `compressed_buf` must point to at least `compressed_buf_size`
/// writable bytes. `call_table` must be valid.
#[cfg(feature = "decompress")]
pub unsafe fn read_compressed_grain(
    call_table: &CallTable,
    device_idx: u32,
    marker_byte_offset: u64,
    grain_size_bytes: u64,
    out_buf: *mut u8,
    sector_size: usize,
    compressed_buf: *mut u8,
    compressed_buf_size: usize,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> bool {
    // Read the sector containing the grain marker header.
    let first_sector = marker_byte_offset / sector_size as u64;
    let marker_off = (marker_byte_offset % sector_size as u64) as usize;

    if first_sector >= input_capacity {
        return false;
    }

    // Read first sector
    if !(call_table.read_input_sector)(device_idx, first_sector, compressed_buf, sector_size) {
        return false;
    }
    *bytes_read += sector_size as u64;

    // Marker must fit within this sector (12 bytes)
    if marker_off + GRAIN_MARKER_SIZE > sector_size {
        return false;
    }

    // Parse compressed_size from the marker (offset 8, u32 LE)
    let marker_ptr = compressed_buf.add(marker_off);
    let compressed_size = u32::from_le_bytes([
        *marker_ptr.add(8),
        *marker_ptr.add(9),
        *marker_ptr.add(10),
        *marker_ptr.add(11),
    ]) as usize;

    if compressed_size == 0 {
        // Empty grain: fill with zeros
        core::ptr::write_bytes(out_buf, 0, grain_size_bytes as usize);
        return true;
    }

    // Validate compressed data fits in our buffer
    let total_needed = GRAIN_MARKER_SIZE + compressed_size;
    if total_needed > compressed_buf_size {
        return false;
    }

    // Calculate how many sectors we need in total
    let total_byte_end = marker_byte_offset + total_needed as u64;
    let last_sector = total_byte_end.div_ceil(sector_size as u64);
    let sectors_to_read = last_sector - first_sector;

    if sectors_to_read * sector_size as u64 > compressed_buf_size as u64 {
        return false;
    }

    // Read remaining sectors (first one already read)
    for i in 1..sectors_to_read {
        let sector = first_sector + i;
        if sector >= input_capacity {
            return false;
        }
        let buf_offset = (i as usize) * sector_size;
        if !(call_table.read_input_sector)(
            device_idx,
            sector,
            compressed_buf.add(buf_offset),
            sector_size,
        ) {
            return false;
        }
        *bytes_read += sector_size as u64;
    }

    // Decompress: compressed data starts after the 12-byte marker
    let data_offset = marker_off + GRAIN_MARKER_SIZE;
    let compressed_slice =
        core::slice::from_raw_parts(compressed_buf.add(data_offset), compressed_size);
    let out_slice = core::slice::from_raw_parts_mut(out_buf, grain_size_bytes as usize);

    use miniz_oxide::inflate::core::inflate_flags;
    use miniz_oxide::inflate::TINFLStatus;

    // Try zlib-wrapped DEFLATE first (standard for VMDK)
    let mut decomp = miniz_oxide::inflate::core::DecompressorOxide::new();
    let (status, _in_consumed, out_produced) = miniz_oxide::inflate::core::decompress(
        &mut decomp,
        compressed_slice,
        out_slice,
        0,
        inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );

    if status == TINFLStatus::Done && out_produced == grain_size_bytes as usize {
        return true;
    }

    // Fall back to raw DEFLATE (no zlib header)
    let mut decomp2 = miniz_oxide::inflate::core::DecompressorOxide::new();
    let (status2, _in2, out2) = miniz_oxide::inflate::core::decompress(
        &mut decomp2,
        compressed_slice,
        out_slice,
        0,
        inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );

    status2 == TINFLStatus::Done && out2 == grain_size_bytes as usize
}

// ============================================================================
// Cached sector read helper (generated by shared::cached_read! macro)
// ============================================================================

shared::cached_read!(read_u32_le_cached, u32, le, 4);

// ============================================================================
// Descriptor parsing (used by info operation)
// ============================================================================

/// Read and parse the VMDK descriptor from the image.
///
/// Uses the descriptor offset/size from the binary header to read the
/// descriptor text and parse CID, parentCID, and createType fields.
///
/// # Safety
///
/// `call_table` must point to a valid initialized call table.
pub unsafe fn read_and_parse_descriptor(
    call_table: &CallTable,
    device_idx: u32,
    header: &Vmdk4Header,
    vmdk_info: &mut VmdkInfo,
) {
    if header.desc_offset_sectors == 0 || header.desc_size_sectors == 0 {
        return;
    }

    let input_sector_size = (call_table.get_input_sector_size)(device_idx);
    let desc_byte_offset = match header.desc_offset_sectors.checked_mul(512) {
        Some(v) => v,
        None => return,
    };
    let desc_sector = desc_byte_offset / input_sector_size as u64;
    let offset_within_sector = (desc_byte_offset % input_sector_size as u64) as usize;

    let mut desc_buffer = [0u8; MAX_SECTOR_SIZE];

    if (call_table.read_input_sector)(
        device_idx,
        desc_sector,
        desc_buffer.as_mut_ptr(),
        input_sector_size,
    ) {
        let desc_data = &desc_buffer[offset_within_sector..input_sector_size];
        parse_descriptor(desc_data, desc_data.len(), vmdk_info);
    }
}

/// Parse VMDK descriptor text to extract CID, parentCID, and
/// createType.
pub fn parse_descriptor(buffer: &[u8], len: usize, vmdk_info: &mut VmdkInfo) {
    let end = buffer[..len].iter().position(|&b| b == 0).unwrap_or(len);
    let text = &buffer[..end];

    let mut pos = 0;
    while pos < text.len() {
        let line_end = text[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(text.len());

        let line = &text[pos..line_end];

        if line.starts_with(b"CID=") {
            if let Some(cid) = parse_hex_value(&line[4..]) {
                vmdk_info.cid = cid;
            }
        } else if line.starts_with(b"parentCID=") {
            if let Some(parent_cid) = parse_hex_value(&line[10..]) {
                vmdk_info.parent_cid = parent_cid;
            }
        } else if line.starts_with(b"createType=") {
            let value_start = 12; // After 'createType="'
            if line.len() > value_start && line[11] == b'"' {
                if let Some(quote_end) = line[value_start..].iter().position(|&b| b == b'"') {
                    vmdk_info.set_create_type(&line[value_start..value_start + quote_end]);
                }
            }
        }

        pos = line_end + 1;
    }
}

/// Parse a hexadecimal value from a byte slice (no 0x prefix).
pub fn parse_hex_value(bytes: &[u8]) -> Option<u32> {
    let mut value: u32 = 0;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            b' ' | b'\r' | b'\n' | 0 => break,
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit as u32)?;
    }
    Some(value)
}

// ============================================================================
// Descriptor extent parsing
// ============================================================================
//
// A VMDK text descriptor contains one or more extent lines of the form:
//
//     RW 20971520 FLAT "foo-flat.vmdk" 0
//
// Fields, in order:
//   1. access    — RW, RDONLY, or NOACCESS
//   2. size      — extent size in sectors (decimal)
//   3. kind      — FLAT, SPARSE, ZERO, VMFS, VMFSSPARSE
//   4. filename  — quoted backing file (absent for ZERO extents)
//   5. offset    — starting sector within the backing file (decimal,
//                  optional; defaults to 0)
//
// The parser below is strict: any field it cannot positionally
// identify is an error. It only parses what monolithicFlat and
// monolithicSparse descriptors actually emit.

/// Maximum number of extent lines accepted in a descriptor.
///
/// This is the chain config's extent table size and not a number of
/// its own: the two bound the same thing, and whichever is smaller is
/// the one a user meets, so a descriptor this crate accepts is one the
/// guest can be told about. At qemu's 2 GiB default extent size it
/// covers a 128 GiB image. The largest in the corpus is 100 GiB in 26
/// extents of 3.96 GiB each; the same image written with qemu's
/// default would need 50.
pub const MAX_EXTENTS: usize = shared::MAX_CHAIN_EXTENTS;

/// Access mode declared on an extent line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentAccess {
    Rw,
    RdOnly,
    NoAccess,
}

/// Storage kind declared on an extent line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentKind {
    /// Raw sector data (monolithicFlat, twoGbMaxExtentFlat).
    Flat,
    /// Sparse grain-indexed extent (monolithicSparse).
    Sparse,
    /// Zero-filled extent (no backing file).
    Zero,
    /// VMFS-backed flat extent.
    Vmfs,
    /// VMFS-backed sparse extent.
    VmfsSparse,
}

/// A single parsed extent line.
#[derive(Clone, Copy, Debug)]
pub struct VmdkExtent<'a> {
    pub access: ExtentAccess,
    pub size_sectors: u64,
    pub kind: ExtentKind,
    /// Filename as it appears in the descriptor (unquoted). Empty for
    /// `ZERO` extents, which have no backing file.
    pub filename: &'a str,
    pub offset_sectors: u64,
}

/// Errors returned by [`parse_descriptor_extents`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentParseError {
    /// No extent lines were found in the descriptor text.
    NoExtents,
    /// The descriptor contains more than [`MAX_EXTENTS`] extents.
    TooManyExtents,
    /// An extent line is missing a required field.
    MissingField,
    /// The access mode token is not RW/RDONLY/NOACCESS.
    UnknownAccess,
    /// The extent kind token is unknown or unsupported.
    UnknownKind,
    /// A numeric field (size or offset) could not be parsed.
    InvalidNumber,
    /// The filename field is not a double-quoted string.
    UnquotedFilename,
    /// A non-ZERO extent has no filename.
    MissingFilename,
}

/// Fixed-capacity result of parsing a descriptor's extent lines.
///
/// Borrows filename slices directly from the input descriptor text —
/// the lifetime `'a` is tied to that input. Avoids an `alloc`
/// dependency in the `vmdk` crate so guest binaries stay lean.
pub struct ParsedExtents<'a> {
    count: usize,
    extents: [Option<VmdkExtent<'a>>; MAX_EXTENTS],
}

impl<'a> ParsedExtents<'a> {
    const EMPTY: Option<VmdkExtent<'a>> = None;

    /// Construct an empty collection.
    pub const fn new() -> Self {
        Self {
            count: 0,
            extents: [Self::EMPTY; MAX_EXTENTS],
        }
    }

    /// Number of parsed extents.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether no extents were parsed.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get extent by index.
    pub fn get(&self, idx: usize) -> Option<&VmdkExtent<'a>> {
        if idx < self.count {
            self.extents[idx].as_ref()
        } else {
            None
        }
    }

    /// Iterate over the parsed extents in descriptor order.
    pub fn iter(&self) -> impl Iterator<Item = &VmdkExtent<'a>> {
        self.extents[..self.count].iter().filter_map(|o| o.as_ref())
    }
}

impl Default for ParsedExtents<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse extent lines out of a VMDK descriptor's text.
///
/// Walks the descriptor line-by-line; any line whose first whitespace-
/// separated token is `RW`, `RDONLY`, or `NOACCESS` is treated as an
/// extent line and fully parsed. All other lines (comments, key=value
/// pairs, DDB entries) are ignored.
///
/// Returns `NoExtents` if no extent lines were found — an empty
/// descriptor is never valid for monolithicFlat.
pub fn parse_descriptor_extents(text: &str) -> Result<ParsedExtents<'_>, ExtentParseError> {
    let mut out = ParsedExtents::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Peek at the first token to decide whether this is an
        // extent line. Non-extent lines (ddb.*, version=, CID=, etc.)
        // are silently ignored.
        let first = match trimmed.split_ascii_whitespace().next() {
            Some(t) => t,
            None => continue,
        };
        if !matches!(first, "RW" | "RDONLY" | "NOACCESS") {
            continue;
        }

        if out.count >= MAX_EXTENTS {
            return Err(ExtentParseError::TooManyExtents);
        }

        let extent = parse_extent_line(trimmed)?;
        out.extents[out.count] = Some(extent);
        out.count += 1;
    }

    if out.count == 0 {
        return Err(ExtentParseError::NoExtents);
    }

    Ok(out)
}

/// Parse a single extent line into a [`VmdkExtent`].
///
/// Exposed for callers that already have a single line in hand
/// (e.g., iterator-style consumers). Returns an error for any
/// positional field that cannot be parsed.
pub fn parse_extent_line(line: &str) -> Result<VmdkExtent<'_>, ExtentParseError> {
    // Access token.
    let (access_tok, rest) = split_token(line).ok_or(ExtentParseError::MissingField)?;
    let access = match access_tok {
        "RW" => ExtentAccess::Rw,
        "RDONLY" => ExtentAccess::RdOnly,
        "NOACCESS" => ExtentAccess::NoAccess,
        _ => return Err(ExtentParseError::UnknownAccess),
    };

    // Size token (sectors).
    let (size_tok, rest) = split_token(rest).ok_or(ExtentParseError::MissingField)?;
    let size_sectors: u64 = parse_decimal_u64(size_tok)?;

    // Kind token.
    let (kind_tok, rest) = split_token(rest).ok_or(ExtentParseError::MissingField)?;
    let kind = match kind_tok {
        "FLAT" => ExtentKind::Flat,
        "SPARSE" => ExtentKind::Sparse,
        "ZERO" => ExtentKind::Zero,
        "VMFS" => ExtentKind::Vmfs,
        "VMFSSPARSE" => ExtentKind::VmfsSparse,
        _ => return Err(ExtentParseError::UnknownKind),
    };

    // Filename (quoted). ZERO extents are allowed to omit the filename
    // entirely.
    let rest = rest.trim_start();
    let (filename, rest_after_name) = if rest.is_empty() {
        if kind == ExtentKind::Zero {
            ("", rest)
        } else {
            return Err(ExtentParseError::MissingFilename);
        }
    } else if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped
            .find('"')
            .ok_or(ExtentParseError::UnquotedFilename)?;
        (&stripped[..end], &stripped[end + 1..])
    } else {
        return Err(ExtentParseError::UnquotedFilename);
    };

    if kind != ExtentKind::Zero && filename.is_empty() {
        return Err(ExtentParseError::MissingFilename);
    }

    // Optional starting-sector offset inside the backing file.
    // Whitespace + decimal; absence means 0.
    let offset_sectors = {
        let tail = rest_after_name.trim_start();
        if tail.is_empty() {
            0
        } else {
            let (off_tok, tail_after) = split_token(tail).ok_or(ExtentParseError::MissingField)?;
            // Reject unknown trailing garbage.
            if !tail_after.trim().is_empty() {
                return Err(ExtentParseError::MissingField);
            }
            parse_decimal_u64(off_tok)?
        }
    };

    Ok(VmdkExtent {
        access,
        size_sectors,
        kind,
        filename,
        offset_sectors,
    })
}

/// Split off the first whitespace-delimited token from `s`.
/// Returns `(token, rest)` where `rest` has leading whitespace
/// intact (the caller trims as needed).
fn split_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    match s.find(|c: char| c.is_ascii_whitespace()) {
        Some(i) => Some((&s[..i], &s[i..])),
        None => Some((s, "")),
    }
}

/// Parse an ASCII decimal `u64`. Empty strings and any non-digit byte
/// are errors.
fn parse_decimal_u64(s: &str) -> Result<u64, ExtentParseError> {
    if s.is_empty() {
        return Err(ExtentParseError::InvalidNumber);
    }
    let mut out: u64 = 0;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return Err(ExtentParseError::InvalidNumber);
        }
        out = out
            .checked_mul(10)
            .and_then(|v| v.checked_add((b - b'0') as u64))
            .ok_or(ExtentParseError::InvalidNumber)?;
    }
    Ok(out)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use shared::VmdkInfo;

    // ====================================================================
    // parse_hex_value tests
    // ====================================================================

    #[test]
    fn hex_simple_values() {
        assert_eq!(parse_hex_value(b"0"), Some(0));
        assert_eq!(parse_hex_value(b"1"), Some(1));
        assert_eq!(parse_hex_value(b"a"), Some(10));
        assert_eq!(parse_hex_value(b"ff"), Some(255));
        assert_eq!(parse_hex_value(b"FF"), Some(255));
        assert_eq!(parse_hex_value(b"fffffffe"), Some(0xFFFFFFFE));
    }

    #[test]
    fn hex_empty_input() {
        assert_eq!(parse_hex_value(b""), Some(0));
    }

    #[test]
    fn hex_invalid_chars() {
        assert_eq!(parse_hex_value(b"xyz"), None);
        assert_eq!(parse_hex_value(b"0g"), None);
    }

    #[test]
    fn hex_overflow() {
        assert_eq!(parse_hex_value(b"ffffffff"), Some(u32::MAX));
        assert_eq!(parse_hex_value(b"100000000"), None);
    }

    #[test]
    fn hex_stops_at_whitespace_and_null() {
        assert_eq!(parse_hex_value(b"ff "), Some(255));
        assert_eq!(parse_hex_value(b"ff\r"), Some(255));
        assert_eq!(parse_hex_value(b"ff\n"), Some(255));
        assert_eq!(parse_hex_value(b"ff\0"), Some(255));
    }

    // ====================================================================
    // Vmdk4Header::parse tests (basic header)
    // ====================================================================

    /// Build a minimal 44-byte VMDK4 header buffer.
    fn make_vmdk4_header(
        version: u32,
        capacity: u64,
        grain_size: u64,
        desc_offset: u64,
        desc_size: u64,
    ) -> [u8; 44] {
        let mut buf = [0u8; 44];
        buf[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&version.to_le_bytes());
        buf[CAPACITY_OFFSET..CAPACITY_OFFSET + 8].copy_from_slice(&capacity.to_le_bytes());
        buf[GRAIN_SIZE_OFFSET..GRAIN_SIZE_OFFSET + 8].copy_from_slice(&grain_size.to_le_bytes());
        buf[DESC_OFFSET_OFFSET..DESC_OFFSET_OFFSET + 8].copy_from_slice(&desc_offset.to_le_bytes());
        buf[DESC_SIZE_OFFSET..DESC_SIZE_OFFSET + 8].copy_from_slice(&desc_size.to_le_bytes());
        buf
    }

    #[test]
    fn vmdk4_parse_valid() {
        let buf = make_vmdk4_header(1, 2097152, 128, 1, 20);
        let hdr = Vmdk4Header::parse(&buf).unwrap();
        assert_eq!(hdr.version, 1);
        assert_eq!(hdr.capacity_sectors, 2097152);
        assert_eq!(hdr.virtual_size, 2097152 * 512);
        assert_eq!(hdr.grain_size_sectors, 128);
        assert_eq!(hdr.cluster_size, 128 * 512);
        assert_eq!(hdr.desc_offset_sectors, 1);
        assert_eq!(hdr.desc_size_sectors, 20);
    }

    #[test]
    fn vmdk4_parse_short_buffer() {
        assert!(Vmdk4Header::parse(&[0u8; 43]).is_none());
        assert!(Vmdk4Header::parse(&[]).is_none());
    }

    #[test]
    fn vmdk4_parse_capacity_overflow() {
        let buf = make_vmdk4_header(1, u64::MAX, 128, 0, 0);
        assert!(Vmdk4Header::parse(&buf).is_none());
    }

    #[test]
    fn vmdk4_parse_grain_size_overflow() {
        let huge_grain = (u32::MAX as u64) + 1;
        let buf = make_vmdk4_header(1, 2048, huge_grain, 0, 0);
        assert!(Vmdk4Header::parse(&buf).is_none());
    }

    // ====================================================================
    // Vmdk4HeaderFull::parse tests
    // ====================================================================

    /// Build a full VMDK4 header buffer (at least 79 bytes).
    fn make_full_header(
        version: u32,
        flags: u32,
        capacity: u64,
        grain_size: u64,
        desc_offset: u64,
        desc_size: u64,
        num_gtes: u32,
        rgd_offset: u64,
        gd_offset: u64,
        overhead: u64,
        compress_alg: u16,
    ) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[MAGIC_OFFSET..MAGIC_OFFSET + 4].copy_from_slice(&VMDK4_MAGIC.to_le_bytes());
        buf[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&version.to_le_bytes());
        buf[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());
        buf[CAPACITY_OFFSET..CAPACITY_OFFSET + 8].copy_from_slice(&capacity.to_le_bytes());
        buf[GRAIN_SIZE_OFFSET..GRAIN_SIZE_OFFSET + 8].copy_from_slice(&grain_size.to_le_bytes());
        buf[DESC_OFFSET_OFFSET..DESC_OFFSET_OFFSET + 8].copy_from_slice(&desc_offset.to_le_bytes());
        buf[DESC_SIZE_OFFSET..DESC_SIZE_OFFSET + 8].copy_from_slice(&desc_size.to_le_bytes());
        buf[NUM_GTES_PER_GT_OFFSET..NUM_GTES_PER_GT_OFFSET + 4]
            .copy_from_slice(&num_gtes.to_le_bytes());
        buf[RGD_OFFSET_OFFSET..RGD_OFFSET_OFFSET + 8].copy_from_slice(&rgd_offset.to_le_bytes());
        buf[GD_OFFSET_OFFSET..GD_OFFSET_OFFSET + 8].copy_from_slice(&gd_offset.to_le_bytes());
        buf[OVERHEAD_OFFSET..OVERHEAD_OFFSET + 8].copy_from_slice(&overhead.to_le_bytes());
        buf[COMPRESS_ALGORITHM_OFFSET..COMPRESS_ALGORITHM_OFFSET + 2]
            .copy_from_slice(&compress_alg.to_le_bytes());
        buf
    }

    #[test]
    fn full_header_parse_monolithic_sparse() {
        // 1GB disk, 64KB grains, 512 GTEs, GD at sector 100
        let buf = make_full_header(
            1,       // version
            0,       // flags (no compression, no zero grain)
            2097152, // capacity: 1GB in sectors
            128,     // grain_size: 64KB in sectors
            1,       // desc_offset
            20,      // desc_size
            512,     // num_gtes_per_gt
            0,       // rgd_offset (none)
            100,     // gd_offset
            200,     // overhead
            0,       // compress_algorithm (none)
        );
        let hdr = Vmdk4HeaderFull::parse(&buf).unwrap();
        assert_eq!(hdr.version, 1);
        assert_eq!(hdr.flags, 0);
        assert_eq!(hdr.capacity_sectors, 2097152);
        assert_eq!(hdr.virtual_size, 2097152 * 512);
        assert_eq!(hdr.grain_size_sectors, 128);
        assert_eq!(hdr.grain_size_bytes, 128 * 512);
        assert_eq!(hdr.num_gtes_per_gt, 512);
        assert_eq!(hdr.gd_offset_sectors, 100);
        assert_eq!(hdr.overhead_sectors, 200);
        assert!(!hdr.has_zero_grain);
        assert!(!hdr.is_compressed);
    }

    #[test]
    fn full_header_parse_stream_optimized() {
        let buf = make_full_header(
            3,
            FLAG_COMPRESSED | FLAG_MARKER | FLAG_ZERO_GRAIN,
            2097152,
            128,
            1,
            20,
            512,
            0,
            GD_AT_END,
            200,
            COMPRESS_DEFLATE,
        );
        let hdr = Vmdk4HeaderFull::parse(&buf).unwrap();
        assert_eq!(hdr.version, 3);
        assert!(hdr.has_zero_grain);
        assert!(hdr.is_compressed);
        assert_eq!(hdr.compress_algorithm, COMPRESS_DEFLATE);
        assert_eq!(hdr.gd_offset_sectors, GD_AT_END);
    }

    #[test]
    fn full_header_parse_short_buffer() {
        assert!(Vmdk4HeaderFull::parse(&[0u8; 78]).is_none());
        assert!(Vmdk4HeaderFull::parse(&[0u8; 0]).is_none());
    }

    #[test]
    fn full_header_parse_capacity_overflow() {
        let buf = make_full_header(1, 0, u64::MAX, 128, 0, 0, 512, 0, 100, 0, 0);
        assert!(Vmdk4HeaderFull::parse(&buf).is_none());
    }

    // ====================================================================
    // num_gd_entries tests
    // ====================================================================

    #[test]
    fn gd_entries_exact_division() {
        // 1GB disk, 128 sectors/grain, 512 gtes = 65536 sectors/GT
        // 2097152 / 65536 = 32 GD entries exactly
        let buf = make_full_header(1, 0, 2097152, 128, 1, 20, 512, 0, 100, 0, 0);
        let hdr = Vmdk4HeaderFull::parse(&buf).unwrap();
        assert_eq!(hdr.num_gd_entries(), Some(32));
    }

    #[test]
    fn gd_entries_with_remainder() {
        // 2097153 sectors / 65536 = 32.00001... -> 33 GD entries
        let buf = make_full_header(1, 0, 2097153, 128, 1, 20, 512, 0, 100, 0, 0);
        let hdr = Vmdk4HeaderFull::parse(&buf).unwrap();
        assert_eq!(hdr.num_gd_entries(), Some(33));
    }

    #[test]
    fn gd_entries_zero_grain_size() {
        let mut buf = make_full_header(1, 0, 2097152, 0, 1, 20, 512, 0, 100, 0, 0);
        // grain_size of 0 fails Vmdk4HeaderFull::parse (checked_mul
        // returns 0, which is fine, but power-of-2 check fails in
        // init). Test via direct construction.
        buf[GRAIN_SIZE_OFFSET..GRAIN_SIZE_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        // parse returns None because 0 * 512 = 0 grain_size_bytes
        // which is valid but num_gd_entries would need grain_size > 0
        // The parse itself won't fail (0*512=0 is valid), so test
        // num_gd_entries on a manually constructed header.
        let hdr = Vmdk4HeaderFull {
            version: 1,
            flags: 0,
            capacity_sectors: 2097152,
            virtual_size: 2097152 * 512,
            grain_size_sectors: 0,
            grain_size_bytes: 0,
            desc_offset_sectors: 1,
            desc_size_sectors: 20,
            num_gtes_per_gt: 512,
            rgd_offset_sectors: 0,
            gd_offset_sectors: 100,
            overhead_sectors: 0,
            compress_algorithm: 0,
            has_zero_grain: false,
            is_compressed: false,
        };
        assert_eq!(hdr.num_gd_entries(), None);
    }

    #[test]
    fn gd_entries_zero_gtes_per_gt() {
        let hdr = Vmdk4HeaderFull {
            version: 1,
            flags: 0,
            capacity_sectors: 2097152,
            virtual_size: 2097152 * 512,
            grain_size_sectors: 128,
            grain_size_bytes: 128 * 512,
            desc_offset_sectors: 1,
            desc_size_sectors: 20,
            num_gtes_per_gt: 0,
            rgd_offset_sectors: 0,
            gd_offset_sectors: 100,
            overhead_sectors: 0,
            compress_algorithm: 0,
            has_zero_grain: false,
            is_compressed: false,
        };
        assert_eq!(hdr.num_gd_entries(), None);
    }

    // ====================================================================
    // parse_descriptor tests
    // ====================================================================

    #[test]
    fn descriptor_parses_cid_and_parent_cid() {
        let desc = b"CID=fffffffe\nparentCID=12345678\n";
        let mut info = VmdkInfo::new();
        parse_descriptor(desc, desc.len(), &mut info);
        assert_eq!(info.cid, 0xFFFFFFFE);
        assert_eq!(info.parent_cid, 0x12345678);
    }

    #[test]
    fn descriptor_parses_create_type() {
        let desc = b"createType=\"monolithicSparse\"\n";
        let mut info = VmdkInfo::new();
        parse_descriptor(desc, desc.len(), &mut info);
        assert_eq!(info.create_type_str(), "monolithicSparse");
    }

    #[test]
    fn descriptor_handles_null_terminated_buffer() {
        let mut buf = [0u8; 64];
        let text = b"CID=abcd\n";
        buf[..text.len()].copy_from_slice(text);
        let mut info = VmdkInfo::new();
        parse_descriptor(&buf, buf.len(), &mut info);
        assert_eq!(info.cid, 0xABCD);
    }

    #[test]
    fn descriptor_ignores_unknown_lines() {
        let desc = b"version=1\nCID=1\nsomething=else\n";
        let mut info = VmdkInfo::new();
        parse_descriptor(desc, desc.len(), &mut info);
        assert_eq!(info.cid, 1);
        assert_eq!(info.parent_cid, 0xFFFFFFFF);
    }

    // ====================================================================
    // parse_descriptor_extents tests
    // ====================================================================

    /// Canonical monolithicFlat descriptor emitted by qemu-img.
    const FLAT_DESCRIPTOR: &str = "\
# Disk DescriptorFile
version=1
CID=abcdef01
parentCID=ffffffff
createType=\"monolithicFlat\"

# Extent description
RW 20971520 FLAT \"test-flat.vmdk\" 0

# The Disk Data Base
#DDB

ddb.adapterType = \"ide\"
ddb.geometry.sectors = \"63\"
ddb.geometry.heads = \"16\"
ddb.geometry.cylinders = \"20805\"
";

    /// Canonical monolithicSparse descriptor.
    const SPARSE_DESCRIPTOR: &str = "\
# Disk DescriptorFile
version=1
CID=12345678
parentCID=ffffffff
createType=\"monolithicSparse\"

# Extent description
RW 2097152 SPARSE \"test.vmdk\"

# The Disk Data Base
#DDB
ddb.geometry.sectors = \"63\"
";

    /// twoGbMaxExtentFlat descriptor (three extents).
    const MULTI_FLAT_DESCRIPTOR: &str = "\
# Disk DescriptorFile
version=1
CID=deadbeef
parentCID=ffffffff
createType=\"twoGbMaxExtentFlat\"

# Extent description
RW 4194304 FLAT \"disk-f001.vmdk\" 0
RW 4194304 FLAT \"disk-f002.vmdk\" 0
RW 2097152 FLAT \"disk-f003.vmdk\" 0
";

    #[test]
    fn extents_parse_monolithic_flat() {
        let parsed = parse_descriptor_extents(FLAT_DESCRIPTOR).unwrap();
        assert_eq!(parsed.len(), 1);
        let e = parsed.get(0).unwrap();
        assert_eq!(e.access, ExtentAccess::Rw);
        assert_eq!(e.size_sectors, 20971520);
        assert_eq!(e.kind, ExtentKind::Flat);
        assert_eq!(e.filename, "test-flat.vmdk");
        assert_eq!(e.offset_sectors, 0);
    }

    #[test]
    fn extents_parse_monolithic_sparse() {
        let parsed = parse_descriptor_extents(SPARSE_DESCRIPTOR).unwrap();
        assert_eq!(parsed.len(), 1);
        let e = parsed.get(0).unwrap();
        assert_eq!(e.kind, ExtentKind::Sparse);
        assert_eq!(e.filename, "test.vmdk");
        // Offset is absent (monolithicSparse omits the trailing 0).
        assert_eq!(e.offset_sectors, 0);
    }

    #[test]
    fn extents_parse_two_gb_max_extent_flat() {
        let parsed = parse_descriptor_extents(MULTI_FLAT_DESCRIPTOR).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed.get(0).unwrap().filename, "disk-f001.vmdk");
        assert_eq!(parsed.get(1).unwrap().filename, "disk-f002.vmdk");
        assert_eq!(parsed.get(2).unwrap().filename, "disk-f003.vmdk");
        for i in 0..3 {
            assert_eq!(parsed.get(i).unwrap().kind, ExtentKind::Flat);
        }
    }

    #[test]
    fn extents_iter_returns_all_extents() {
        let parsed = parse_descriptor_extents(MULTI_FLAT_DESCRIPTOR).unwrap();
        let names: heapless_collect::Names = heapless_collect::Names::collect(&parsed);
        assert_eq!(
            names.as_slice(),
            &["disk-f001.vmdk", "disk-f002.vmdk", "disk-f003.vmdk"]
        );
    }

    #[test]
    fn extents_zero_kind_allows_missing_filename() {
        let desc = "# Disk DescriptorFile\nRW 1024 ZERO\n";
        let parsed = parse_descriptor_extents(desc).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.get(0).unwrap().kind, ExtentKind::Zero);
        assert_eq!(parsed.get(0).unwrap().filename, "");
    }

    #[test]
    fn extents_reject_unknown_kind() {
        let desc = "RW 1024 BOGUS \"file.vmdk\"\n";
        assert!(matches!(
            parse_descriptor_extents(desc),
            Err(ExtentParseError::UnknownKind)
        ));
    }

    #[test]
    fn extents_reject_unknown_access() {
        let desc = "XYZ 1024 FLAT \"file.vmdk\" 0\n";
        // XYZ isn't one of our recognized leading tokens, so the line
        // is skipped entirely and we see NoExtents instead.
        assert!(matches!(
            parse_descriptor_extents(desc),
            Err(ExtentParseError::NoExtents)
        ));
    }

    #[test]
    fn extents_reject_unquoted_filename() {
        let desc = "RW 1024 FLAT file.vmdk 0\n";
        assert!(matches!(
            parse_descriptor_extents(desc),
            Err(ExtentParseError::UnquotedFilename)
        ));
    }

    #[test]
    fn extents_reject_missing_quote_close() {
        let desc = "RW 1024 FLAT \"file.vmdk\n";
        assert!(matches!(
            parse_descriptor_extents(desc),
            Err(ExtentParseError::UnquotedFilename)
        ));
    }

    #[test]
    fn extents_reject_missing_filename_on_non_zero_kind() {
        let desc = "RW 1024 FLAT\n";
        assert!(matches!(
            parse_descriptor_extents(desc),
            Err(ExtentParseError::MissingFilename)
        ));
    }

    #[test]
    fn extents_reject_negative_or_nondecimal_size() {
        let desc = "RW -1024 FLAT \"file.vmdk\" 0\n";
        assert!(matches!(
            parse_descriptor_extents(desc),
            Err(ExtentParseError::InvalidNumber)
        ));
    }

    #[test]
    fn extents_reject_trailing_garbage_after_offset() {
        let desc = "RW 1024 FLAT \"file.vmdk\" 0 extra-token\n";
        assert!(matches!(
            parse_descriptor_extents(desc),
            Err(ExtentParseError::MissingField)
        ));
    }

    #[test]
    fn extents_reject_empty_descriptor() {
        assert!(matches!(
            parse_descriptor_extents(""),
            Err(ExtentParseError::NoExtents)
        ));
        assert!(matches!(
            parse_descriptor_extents("# just a comment\nversion=1\n"),
            Err(ExtentParseError::NoExtents)
        ));
    }

    #[test]
    fn extents_cap_at_max_extents() {
        // Build MAX_EXTENTS + 1 identical extent lines in a fixed-size
        // buffer to avoid depending on `alloc` in the test harness.
        const LINE: &[u8] = b"RW 1024 FLAT \"f.vmdk\" 0\n";
        const LINES: usize = MAX_EXTENTS + 1;
        let mut buf = [0u8; LINE.len() * LINES];
        for i in 0..LINES {
            let off = i * LINE.len();
            buf[off..off + LINE.len()].copy_from_slice(LINE);
        }
        let desc = core::str::from_utf8(&buf).unwrap();
        assert!(matches!(
            parse_descriptor_extents(desc),
            Err(ExtentParseError::TooManyExtents)
        ));
    }

    #[test]
    fn extents_ignore_comments_and_blank_lines() {
        let desc = "\n\n# comment\n\nRW 10 FLAT \"a.vmdk\" 0\n# another\nRW 20 FLAT \"b.vmdk\" 0\n";
        let parsed = parse_descriptor_extents(desc).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get(0).unwrap().size_sectors, 10);
        assert_eq!(parsed.get(1).unwrap().size_sectors, 20);
    }

    // ====================================================================
    // count_populated_gd_entries tests
    // ====================================================================

    #[test]
    fn gd_empty_slice_returns_zero() {
        assert_eq!(count_populated_gd_entries(&[]), 0);
    }

    #[test]
    fn gd_three_of_eight_populated() {
        // Build 8 u32-LE entries: entries 1, 4, 7 are non-zero.
        let mut buf = [0u8; 32];
        let set = |buf: &mut [u8; 32], idx: usize, val: u32| {
            buf[idx * 4..idx * 4 + 4].copy_from_slice(&val.to_le_bytes());
        };
        set(&mut buf, 1, 0x0000_0080);
        set(&mut buf, 4, 0x0000_1000);
        set(&mut buf, 7, 0xFFFF_FFFD);
        assert_eq!(count_populated_gd_entries(&buf), 3);
    }

    #[test]
    fn gd_trailing_partial_entry_is_ignored() {
        // 5 bytes: one complete u32-LE entry (non-zero) + 1 byte tail.
        let mut buf = [0u8; 5];
        buf[0..4].copy_from_slice(&42u32.to_le_bytes());
        buf[4] = 0xFF; // partial — should be dropped
        assert_eq!(count_populated_gd_entries(&buf), 1);
    }

    // ====================================================================
    // count_allocated_in_gt tests
    // ====================================================================

    #[test]
    fn gt_all_zeros_returns_zero() {
        let buf = [0u8; 16]; // 4 entries, all zero
        assert_eq!(count_allocated_in_gt(&buf), 0);
    }

    #[test]
    fn gt_all_allocated_returns_entry_count() {
        // 4 non-zero, non-marker entries
        let mut buf = [0u8; 16];
        for (i, val) in [0x0000_0002u32, 0x0000_0100, 0x0000_1000, 0x00FF_0000]
            .iter()
            .enumerate()
        {
            buf[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
        }
        assert_eq!(count_allocated_in_gt(&buf), 4);
    }

    #[test]
    fn gt_zero_grain_marker_excluded() {
        // Mix: 0, ZERO_GRAIN_MARKER, and two allocated entries.
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        buf[4..8].copy_from_slice(&ZERO_GRAIN_MARKER.to_le_bytes());
        buf[8..12].copy_from_slice(&0x0000_0010u32.to_le_bytes());
        buf[12..16].copy_from_slice(&0x0000_0020u32.to_le_bytes());
        assert_eq!(count_allocated_in_gt(&buf), 2);
    }

    #[test]
    fn gt_pure_zero_grain_marker_entries_return_zero() {
        // All four entries are ZERO_GRAIN_MARKER — none are allocated.
        let mut buf = [0u8; 16];
        for i in 0..4 {
            buf[i * 4..i * 4 + 4].copy_from_slice(&ZERO_GRAIN_MARKER.to_le_bytes());
        }
        assert_eq!(count_allocated_in_gt(&buf), 0);
    }

    #[test]
    fn gt_adversarial_5_byte_tail_is_dropped() {
        // 1 complete non-zero entry (4 bytes) + 1 byte tail; tail must
        // be ignored, count must be 1.
        let mut buf = [0u8; 5];
        buf[0..4].copy_from_slice(&0x0000_00FFu32.to_le_bytes());
        buf[4] = 0xAB; // partial — should be dropped
        assert_eq!(count_allocated_in_gt(&buf), 1);
    }

    #[test]
    fn gt_large_every_seventh_allocated() {
        // 512 entries (2048 bytes), every 7th is allocated.
        let mut buf = [0u8; 512 * 4];
        let mut expected: u64 = 0;
        for i in 0..512usize {
            let val: u32 = if i % 7 == 0 { (i as u32) + 2 } else { 0 };
            buf[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
            if val != 0 {
                expected += 1;
            }
        }
        assert_eq!(count_allocated_in_gt(&buf), expected);
    }

    // ====================================================================
    // classify_vmdk_gt_entry tests
    // ====================================================================

    #[test]
    fn classify_vmdk_unallocated_is_hole() {
        let e = classify_vmdk_gt_entry(GTE_UNALLOCATED, 0, 65536, true);
        assert_eq!(e.state, MapExtentState::Hole);
        assert_eq!(e.length, 65536);
    }

    #[test]
    fn classify_vmdk_zeroed_with_flag_is_zero_alloc() {
        let e = classify_vmdk_gt_entry(GTE_ZEROED, 0, 65536, true);
        assert_eq!(e.state, MapExtentState::ZeroAllocated);
    }

    #[test]
    fn classify_vmdk_zeroed_without_flag_is_data() {
        // Without has_zero_grain set, GTE value 1 is just a (very
        // low) sector pointer — emit as Data.
        let e = classify_vmdk_gt_entry(GTE_ZEROED, 0, 65536, false);
        assert_eq!(e.state, MapExtentState::Data { file_offset: 512 });
    }

    #[test]
    fn classify_vmdk_zero_grain_marker_is_zero_alloc() {
        let e = classify_vmdk_gt_entry(ZERO_GRAIN_MARKER, 0, 65536, false);
        assert_eq!(e.state, MapExtentState::ZeroAllocated);
    }

    #[test]
    fn classify_vmdk_normal_is_data() {
        // entry = 0x100 sectors → file_offset = 0x100 * 512.
        let e = classify_vmdk_gt_entry(0x100, 65536, 65536, false);
        assert_eq!(e.start, 65536);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 0x100 * 512,
            }
        );
    }

    #[test]
    fn classify_vmdk_large_sector_offset() {
        // Ensure (entry as u64) * 512 doesn't lose precision for
        // max-u32 entries.
        let e = classify_vmdk_gt_entry(0x7FFF_FFFF, 0, 65536, false);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 0x7FFF_FFFFu64 * 512
            }
        );
    }

    #[test]
    fn classify_vmdk_grain_size_512() {
        // Smallest sensible grain size (1 sector).
        let e = classify_vmdk_gt_entry(0x10, 0, 512, false);
        assert_eq!(e.length, 512);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 0x10 * 512
            }
        );
    }

    #[test]
    fn classify_vmdk_zero_grain_marker_overrides_has_zero_grain() {
        // ZERO_GRAIN_MARKER must produce ZeroAllocated regardless
        // of whether has_zero_grain is set.
        let with_flag = classify_vmdk_gt_entry(ZERO_GRAIN_MARKER, 0, 65536, true);
        let without_flag = classify_vmdk_gt_entry(ZERO_GRAIN_MARKER, 0, 65536, false);
        assert_eq!(with_flag.state, MapExtentState::ZeroAllocated);
        assert_eq!(without_flag.state, MapExtentState::ZeroAllocated);
    }

    // ====================================================================
    // split_layout tests
    // ====================================================================

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    /// Assert extent count, last-extent sectors and cylinders for a size.
    fn check_layout(bytes: u64, count: u64, last: u64, cyl: u64) {
        let l = split_layout(bytes, SplitKind::Sparse);
        assert_eq!(l.total_sectors, bytes / 512, "total_sectors for {bytes}");
        assert_eq!(l.extent_count, count, "extent_count for {bytes}");
        assert_eq!(
            l.last_extent_sectors, last,
            "last_extent_sectors for {bytes}"
        );
        assert_eq!(l.cylinders, cyl, "cylinders for {bytes}");
        assert_eq!(l.heads, 16);
        assert_eq!(l.sectors, 63);
    }

    #[test]
    fn split_layout_matches_every_pinned_size() {
        // vmdk-multi-sparse-1M
        check_layout(MIB, 1, 2048, 2);
        // vmdk-multi-sparse-2G: exactly one full extent, not two.
        check_layout(2 * GIB, 1, 4_194_304, 4161);
        // vmdk-multi-sparse-2049M
        check_layout(2049 * MIB, 2, 2048, 4163);
        // vmdk-multi-sparse-4G
        check_layout(4 * GIB, 2, 4_194_304, 8322);
        // vmdk-multi-sparse-5G
        check_layout(5 * GIB, 3, 2_097_152, 10402);
        // vmdk-multi-sparse-21G
        check_layout(21 * GIB, 11, 2_097_152, 43690);
    }

    #[test]
    fn split_layout_does_not_clamp_cylinders() {
        // custom/format-coverage/vmdk-split-sparse-33g.vmdk records
        // ddb.geometry.cylinders = "68656", past the 16-bit 65535.
        check_layout(33 * GIB, 17, 2_097_152, 68656);
    }

    #[test]
    fn split_layout_kind_is_carried_through() {
        assert_eq!(split_layout(MIB, SplitKind::Flat).kind, SplitKind::Flat);
        assert_eq!(split_layout(MIB, SplitKind::Sparse).kind, SplitKind::Sparse);
    }

    #[test]
    fn split_layout_sectors_of_extent() {
        let l = split_layout(5 * GIB, SplitKind::Flat);
        assert_eq!(l.sectors_of_extent(0), 4_194_304);
        assert_eq!(l.sectors_of_extent(1), 4_194_304);
        assert_eq!(l.sectors_of_extent(2), 2_097_152);
        assert_eq!(l.sectors_of_extent(3), 0);
        assert_eq!(l.sectors_of_extent(u64::MAX), 0);
        let whole = split_layout(4 * GIB, SplitKind::Flat);
        assert_eq!(whole.sectors_of_extent(1), 4_194_304);
        assert_eq!(whole.sectors_of_extent(2), 0);
    }

    #[test]
    fn split_layout_extent_sectors_sum_to_total() {
        for bytes in [MIB, 2 * GIB, 2049 * MIB, 5 * GIB, 33 * GIB] {
            let l = split_layout(bytes, SplitKind::Sparse);
            let mut sum = 0u64;
            for i in 0..l.extent_count {
                sum += l.sectors_of_extent(i);
            }
            assert_eq!(sum, l.total_sectors, "extents of {bytes}");
        }
    }

    #[test]
    fn split_layout_zero_size() {
        // No pin covers a zero-byte disk. Chosen answer: no extents, no
        // sectors, no cylinders, and every extent index is out of range.
        let l = split_layout(0, SplitKind::Sparse);
        assert_eq!(l.total_sectors, 0);
        assert_eq!(l.extent_count, 0);
        assert_eq!(l.last_extent_sectors, 0);
        assert_eq!(l.cylinders, 0);
        assert_eq!(l.sectors_of_extent(0), 0);
    }

    #[test]
    fn split_layout_rounds_unaligned_size_up() {
        // No pin covers a size that is not a multiple of 512. Chosen
        // answer: round up to the next sector, as for the other builders.
        let l = split_layout(MIB + 1, SplitKind::Sparse);
        assert_eq!(l.total_sectors, 2049);
        assert_eq!(l.extent_count, 1);
        assert_eq!(l.last_extent_sectors, 2049);
        // One byte over a full extent spills a one-sector extent.
        let l = split_layout(2 * GIB + 1, SplitKind::Sparse);
        assert_eq!(l.extent_count, 2);
        assert_eq!(l.last_extent_sectors, 1);
    }

    #[test]
    fn split_layout_u64_max_does_not_overflow() {
        let l = split_layout(u64::MAX, SplitKind::Flat);
        assert_eq!(l.total_sectors, 1u64 << 55);
        assert_eq!(l.extent_count, 1u64 << 33);
        assert_eq!(l.last_extent_sectors, SPLIT_EXTENT_SECTORS);
        assert_eq!(
            l.sectors_of_extent(l.extent_count - 1),
            SPLIT_EXTENT_SECTORS
        );
    }

    // ====================================================================
    // build_split_descriptor mechanics tests
    // ====================================================================

    /// Large enough for the descriptor of a 1000-extent image.
    const DESC_BUF: usize = 65536;

    fn split_len(extents: u64, kind: SplitKind) -> usize {
        let layout = split_layout(extents * SPLIT_EXTENT_SECTORS * 512, kind);
        assert_eq!(layout.extent_count, extents);
        build_split_descriptor(&mut [], 0, &layout, b"image", b".vmdk")
    }

    #[test]
    fn split_descriptor_measured_length_equals_written_length() {
        for kind in [SplitKind::Sparse, SplitKind::Flat] {
            for extents in [1u64, 2, 17, 1000] {
                let layout = split_layout(extents * SPLIT_EXTENT_SECTORS * 512, kind);
                let measured = build_split_descriptor(&mut [], 0, &layout, b"image", b".vmdk");
                assert!(measured < DESC_BUF);
                let mut buf = [0u8; DESC_BUF];
                let written = build_split_descriptor(&mut buf, 0, &layout, b"image", b".vmdk");
                assert_eq!(measured, written, "{extents} extents, {kind:?}");
                assert_eq!(buf[written - 1], b'\n');
                assert_eq!(buf[written], 0, "wrote past the reported length");
            }
        }
        assert!(split_len(1000, SplitKind::Sparse) > split_len(17, SplitKind::Sparse));
    }

    #[test]
    fn split_descriptor_short_buffer_returns_needed_length() {
        let layout = split_layout(5 * GIB, SplitKind::Sparse);
        let mut full = [0u8; 4096];
        let need = build_split_descriptor(&mut full, 0, &layout, b"image", b".vmdk");
        assert!(need < full.len());

        let mut short = [0xAAu8; 4096];
        let got = build_split_descriptor(&mut short[..need - 1], 0, &layout, b"image", b".vmdk");
        assert_eq!(got, need);
        // The final write does not fit, so it is skipped entirely and the
        // buffer is left holding a prefix of the full output.
        let copied = need - 1 - b"ddb.toolsVersion = \"2147483647\"\n".len();
        assert_eq!(short[..copied], full[..copied]);
        assert_eq!(short[need - 1], 0xAA);
    }

    #[test]
    fn split_descriptor_empty_buffer_writes_nothing() {
        let layout = split_layout(5 * GIB, SplitKind::Flat);
        let need = build_split_descriptor(&mut [], 0, &layout, b"image", b".vmdk");
        assert!(need > 0);
        // An offset past the end of the buffer is measured, not a panic.
        let mut buf = [0x55u8; 8];
        let got = build_split_descriptor(&mut buf, 1 << 20, &layout, b"image", b".vmdk");
        assert_eq!(got, need);
        assert_eq!(buf, [0x55u8; 8]);
    }

    #[test]
    fn split_descriptor_sparse_5g_text() {
        let want = b"# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n\
createType=\"twoGbMaxExtentSparse\"\n\n# Extent description\n\
RW 4194304 SPARSE \"image-s001.vmdk\"\nRW 4194304 SPARSE \"image-s002.vmdk\"\n\
RW 2097152 SPARSE \"image-s003.vmdk\"\n\n# The Disk Data Base\n#DDB\n\n\
ddb.virtualHWVersion = \"4\"\nddb.geometry.cylinders = \"10402\"\n\
ddb.geometry.heads = \"16\"\nddb.geometry.sectors = \"63\"\n\
ddb.adapterType = \"ide\"\nddb.toolsVersion = \"2147483647\"\n";
        let layout = split_layout(5 * GIB, SplitKind::Sparse);
        let mut buf = [0u8; 2048];
        let n = build_split_descriptor(&mut buf, 0, &layout, b"image", b".vmdk");
        assert_eq!(&buf[..n], &want[..]);
    }

    #[test]
    fn split_descriptor_index_padding_is_a_floor() {
        let layout = split_layout(1000 * SPLIT_EXTENT_SECTORS * 512, SplitKind::Sparse);
        let mut buf = [0u8; DESC_BUF];
        let n = build_split_descriptor(&mut buf, 0, &layout, b"image", b".vmdk");
        let text = &buf[..n];
        let has = |needle: &[u8]| text.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"\"image-s999.vmdk\""));
        assert!(has(b"\"image-s1000.vmdk\""));
    }

    // ====================================================================
    // split descriptor parity with qemu
    // ====================================================================
    //
    // The descriptors below are what `qemu-img create -f vmdk -o
    // subformat=twoGbMaxExtentSparse|twoGbMaxExtentFlat` writes, copied from
    // `tests/golden/qemu-create-pins.json`: the 6.2.0-to-10.2.0 version group,
    // with the CID written as `fffffffe` and the extent names filled in from the
    // stem `image`. Every pinned qemu build in that range agrees on them, and
    // each constant names the pin case it came from. The crate tests cannot
    // read that file (the container mounts only this repository, and the
    // workspace has no JSON parser), so a change to the pins has to be copied
    // here by hand; `tests/test_vmdk_split_descriptor_pins.py` guards the copy.
    //
    // The literals keep the shape of `FLAT_DESCRIPTOR` above (real newlines,
    // every line at column zero) so that the guard can find them as text.

    /// Pin case `vmdk-multi-sparse-1M`.
    const PIN_SPARSE_1M: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentSparse\"

# Extent description
RW 2048 SPARSE \"image-s001.vmdk\"

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"2\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-sparse-2G`.
    const PIN_SPARSE_2G: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentSparse\"

# Extent description
RW 4194304 SPARSE \"image-s001.vmdk\"

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"4161\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-sparse-2049M`.
    const PIN_SPARSE_2049M: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentSparse\"

# Extent description
RW 4194304 SPARSE \"image-s001.vmdk\"
RW 2048 SPARSE \"image-s002.vmdk\"

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"4163\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-sparse-4G`.
    const PIN_SPARSE_4G: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentSparse\"

# Extent description
RW 4194304 SPARSE \"image-s001.vmdk\"
RW 4194304 SPARSE \"image-s002.vmdk\"

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"8322\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-sparse-5G`.
    const PIN_SPARSE_5G: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentSparse\"

# Extent description
RW 4194304 SPARSE \"image-s001.vmdk\"
RW 4194304 SPARSE \"image-s002.vmdk\"
RW 2097152 SPARSE \"image-s003.vmdk\"

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"10402\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-sparse-21G`.
    const PIN_SPARSE_21G: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentSparse\"

# Extent description
RW 4194304 SPARSE \"image-s001.vmdk\"
RW 4194304 SPARSE \"image-s002.vmdk\"
RW 4194304 SPARSE \"image-s003.vmdk\"
RW 4194304 SPARSE \"image-s004.vmdk\"
RW 4194304 SPARSE \"image-s005.vmdk\"
RW 4194304 SPARSE \"image-s006.vmdk\"
RW 4194304 SPARSE \"image-s007.vmdk\"
RW 4194304 SPARSE \"image-s008.vmdk\"
RW 4194304 SPARSE \"image-s009.vmdk\"
RW 4194304 SPARSE \"image-s010.vmdk\"
RW 2097152 SPARSE \"image-s011.vmdk\"

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"43690\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-flat-1M`.
    const PIN_FLAT_1M: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentFlat\"

# Extent description
RW 2048 FLAT \"image-f001.vmdk\" 0

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"2\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-flat-2G`.
    const PIN_FLAT_2G: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentFlat\"

# Extent description
RW 4194304 FLAT \"image-f001.vmdk\" 0

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"4161\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-flat-2049M`.
    const PIN_FLAT_2049M: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentFlat\"

# Extent description
RW 4194304 FLAT \"image-f001.vmdk\" 0
RW 2048 FLAT \"image-f002.vmdk\" 0

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"4163\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-flat-4G`.
    const PIN_FLAT_4G: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentFlat\"

# Extent description
RW 4194304 FLAT \"image-f001.vmdk\" 0
RW 4194304 FLAT \"image-f002.vmdk\" 0

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"8322\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-flat-5G`.
    const PIN_FLAT_5G: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentFlat\"

# Extent description
RW 4194304 FLAT \"image-f001.vmdk\" 0
RW 4194304 FLAT \"image-f002.vmdk\" 0
RW 2097152 FLAT \"image-f003.vmdk\" 0

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"10402\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Pin case `vmdk-multi-flat-21G`.
    const PIN_FLAT_21G: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentFlat\"

# Extent description
RW 4194304 FLAT \"image-f001.vmdk\" 0
RW 4194304 FLAT \"image-f002.vmdk\" 0
RW 4194304 FLAT \"image-f003.vmdk\" 0
RW 4194304 FLAT \"image-f004.vmdk\" 0
RW 4194304 FLAT \"image-f005.vmdk\" 0
RW 4194304 FLAT \"image-f006.vmdk\" 0
RW 4194304 FLAT \"image-f007.vmdk\" 0
RW 4194304 FLAT \"image-f008.vmdk\" 0
RW 4194304 FLAT \"image-f009.vmdk\" 0
RW 4194304 FLAT \"image-f010.vmdk\" 0
RW 2097152 FLAT \"image-f011.vmdk\" 0

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"43690\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// The descriptor of `custom/format-coverage/vmdk-split-sparse-33g.vmdk` in
    /// instar-testdata, written by qemu-img with its `CID=` line replaced.
    const QEMU_SPLIT_SPARSE_33G: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentSparse\"

# Extent description
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s001.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s002.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s003.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s004.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s005.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s006.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s007.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s008.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s009.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s010.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s011.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s012.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s013.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s014.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s015.vmdk\"
RW 4194304 SPARSE \"vmdk-split-sparse-33g-s016.vmdk\"
RW 2097152 SPARSE \"vmdk-split-sparse-33g-s017.vmdk\"

# The Disk Data Base
#DDB

ddb.virtualHWVersion = \"4\"
ddb.geometry.cylinders = \"68656\"
ddb.geometry.heads = \"16\"
ddb.geometry.sectors = \"63\"
ddb.adapterType = \"ide\"
ddb.toolsVersion = \"2147483647\"
";

    /// Parity table: (pin case, virtual size in bytes, kind, expected text).
    ///
    /// The two existing-extent cases deliberately share the plain 5 GiB
    /// text: a file already sitting where an extent goes does not change
    /// what qemu writes in the descriptor. That the two pinned descriptors
    /// really are identical is checked where the pin file can be read, in
    /// `tests/test_vmdk_split_descriptor_pins.py`; asserting it here would
    /// only compare a constant with itself.
    fn pin_table() -> [(&'static str, u64, SplitKind, &'static str); 14] {
        [
            (
                "vmdk-multi-sparse-1M",
                1048576,
                SplitKind::Sparse,
                PIN_SPARSE_1M,
            ),
            (
                "vmdk-multi-sparse-2G",
                2147483648,
                SplitKind::Sparse,
                PIN_SPARSE_2G,
            ),
            (
                "vmdk-multi-sparse-2049M",
                2148532224,
                SplitKind::Sparse,
                PIN_SPARSE_2049M,
            ),
            (
                "vmdk-multi-sparse-4G",
                4294967296,
                SplitKind::Sparse,
                PIN_SPARSE_4G,
            ),
            (
                "vmdk-multi-sparse-5G",
                5368709120,
                SplitKind::Sparse,
                PIN_SPARSE_5G,
            ),
            (
                "vmdk-multi-sparse-21G",
                22548578304,
                SplitKind::Sparse,
                PIN_SPARSE_21G,
            ),
            (
                "vmdk-multi-sparse-5G-existing-extent",
                5368709120,
                SplitKind::Sparse,
                PIN_SPARSE_5G,
            ),
            ("vmdk-multi-flat-1M", 1048576, SplitKind::Flat, PIN_FLAT_1M),
            (
                "vmdk-multi-flat-2G",
                2147483648,
                SplitKind::Flat,
                PIN_FLAT_2G,
            ),
            (
                "vmdk-multi-flat-2049M",
                2148532224,
                SplitKind::Flat,
                PIN_FLAT_2049M,
            ),
            (
                "vmdk-multi-flat-4G",
                4294967296,
                SplitKind::Flat,
                PIN_FLAT_4G,
            ),
            (
                "vmdk-multi-flat-5G",
                5368709120,
                SplitKind::Flat,
                PIN_FLAT_5G,
            ),
            (
                "vmdk-multi-flat-21G",
                22548578304,
                SplitKind::Flat,
                PIN_FLAT_21G,
            ),
            (
                "vmdk-multi-flat-5G-existing-extent",
                5368709120,
                SplitKind::Flat,
                PIN_FLAT_5G,
            ),
        ]
    }

    #[test]
    fn split_descriptor_matches_every_pinned_qemu_descriptor() {
        for (case, bytes, kind, want) in pin_table() {
            let layout = split_layout(bytes, kind);
            let mut buf = [0u8; 4096];
            let n = build_split_descriptor(&mut buf, 0, &layout, b"image", b".vmdk");
            assert!(n <= buf.len(), "{case}: descriptor needs {n} bytes");
            assert_eq!(
                core::str::from_utf8(&buf[..n]).unwrap(),
                want,
                "descriptor differs from qemu's for pin case {case}"
            );
        }
    }

    #[test]
    fn split_descriptor_matches_qemu_written_33g_fixture() {
        // Seventeen extents and 68656 cylinders: past both the sixteen-extent
        // and the 65535-cylinder points a smaller case cannot reach.
        let layout = split_layout(33 * GIB, SplitKind::Sparse);
        let mut buf = [0u8; 4096];
        let n = build_split_descriptor(&mut buf, 0, &layout, b"vmdk-split-sparse-33g", b".vmdk");
        assert!(n <= buf.len());
        assert_eq!(
            core::str::from_utf8(&buf[..n]).unwrap(),
            QEMU_SPLIT_SPARSE_33G
        );
    }

    /// Build `<stem><letter><NNN>.vmdk` for a 1-based extent index below 1000.
    fn extent_name<'a>(out: &'a mut [u8; 64], stem: &[u8], letter: u8, index: usize) -> &'a str {
        let mut n = 0;
        for part in [
            stem,
            &[
                b'-',
                letter,
                b'0' + (index / 100) as u8,
                b'0' + (index / 10 % 10) as u8,
                b'0' + (index % 10) as u8,
            ][..],
            b".vmdk",
        ] {
            out[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        core::str::from_utf8(&out[..n]).unwrap()
    }

    /// Emit a descriptor, parse it back, and check every extent against the
    /// shape qemu pins for the size: all extents 4194304 sectors except the
    /// last, which holds `last` sectors.
    fn check_round_trip(bytes: u64, kind: SplitKind, stem: &[u8], count: usize, last: u64) {
        let layout = split_layout(bytes, kind);
        let mut buf = [0u8; 4096];
        let n = build_split_descriptor(&mut buf, 0, &layout, stem, b".vmdk");
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        let parsed = parse_descriptor_extents(text).unwrap();
        assert_eq!(parsed.len(), count);
        let (want_kind, letter) = match kind {
            SplitKind::Sparse => (ExtentKind::Sparse, b's'),
            SplitKind::Flat => (ExtentKind::Flat, b'f'),
        };
        for i in 0..count {
            let e = parsed.get(i).unwrap();
            let mut name = [0u8; 64];
            assert_eq!(e.filename, extent_name(&mut name, stem, letter, i + 1));
            assert_eq!(e.kind, want_kind, "extent {i}");
            assert_eq!(e.access, ExtentAccess::Rw, "extent {i}");
            assert_eq!(e.offset_sectors, 0, "extent {i}");
            let sectors = if i + 1 == count { last } else { 4194304 };
            assert_eq!(e.size_sectors, sectors, "extent {i}");
        }
    }

    #[test]
    fn split_descriptor_round_trips_through_the_extent_parser() {
        // 5 GiB: three extents, the last half-sized (pin case
        // vmdk-multi-sparse-5G / vmdk-multi-flat-5G).
        check_round_trip(5 * GIB, SplitKind::Sparse, b"image", 3, 2097152);
        check_round_trip(5 * GIB, SplitKind::Flat, b"image", 3, 2097152);
        // 21 GiB: eleven extents (pin case vmdk-multi-*-21G).
        check_round_trip(21 * GIB, SplitKind::Sparse, b"image", 11, 2097152);
        check_round_trip(21 * GIB, SplitKind::Flat, b"image", 11, 2097152);
        // 1 MiB: one extent holding 2048 sectors (pin case vmdk-multi-*-1M).
        check_round_trip(MIB, SplitKind::Sparse, b"image", 1, 2048);
        // 33 GiB: seventeen extents (vmdk-split-sparse-33g.vmdk).
        check_round_trip(
            33 * GIB,
            SplitKind::Sparse,
            b"vmdk-split-sparse-33g",
            17,
            2097152,
        );
    }
}

#[cfg(test)]
mod heapless_collect {
    //! Minimal fixed-capacity collector for iterator tests, to avoid
    //! pulling `alloc` into the crate for the sake of one assertion.
    use super::ParsedExtents;

    pub struct Names {
        buf: [&'static str; 8],
        len: usize,
    }

    impl Names {
        pub fn collect(parsed: &ParsedExtents<'static>) -> Self {
            let mut out = Names {
                buf: [""; 8],
                len: 0,
            };
            for e in parsed.iter() {
                out.buf[out.len] = e.filename;
                out.len += 1;
            }
            out
        }

        pub fn as_slice(&self) -> &[&'static str] {
            &self.buf[..self.len]
        }
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod extent_tests {
    //! `VmdkState` over a sparse image that does not start its device:
    //! one extent of a multi-extent descriptor, whose files the host
    //! lays end to end as one device.
    //!
    //! Each test puts the image under test somewhere other than device
    //! offset zero, and usually puts a different image at zero, so a
    //! read that forgets the base lands on the wrong image's header,
    //! tables or grains instead of failing.
    use super::*;
    use std::sync::Mutex;

    // The `read_input_sector` callback is an `extern "C" fn` and can
    // only close over `'static` state, so the mock device lives in a
    // global buffer guarded by a lock that serializes the tests.
    const MOCK_LEN: usize = 4 * MAX_SECTOR_SIZE;
    static MOCK_LOCK: Mutex<()> = Mutex::new(());
    static mut MOCK_IMAGE: [u8; MOCK_LEN] = [0u8; MOCK_LEN];
    static mut GD_CACHE: [u8; MAX_SECTOR_SIZE] = [0u8; MAX_SECTOR_SIZE];
    static mut GT_CACHE: [u8; MAX_SECTOR_SIZE] = [0u8; MAX_SECTOR_SIZE];

    unsafe extern "C" fn mock_read_input_sector(
        _device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        let start = match (sector as usize).checked_mul(sector_size) {
            Some(s) => s,
            None => return false,
        };
        if start + sector_size > MOCK_LEN {
            return false;
        }
        let src = core::ptr::addr_of!(MOCK_IMAGE) as *const u8;
        core::ptr::copy_nonoverlapping(src.add(start), out_buf, sector_size);
        true
    }

    fn stub_call_table() -> shared::CallTable {
        unsafe extern "C" fn s_dev_count() -> u32 {
            1
        }
        unsafe extern "C" fn s_in_cap(_: u32) -> u64 {
            (MOCK_LEN / 512) as u64
        }
        unsafe extern "C" fn s_in_secsz(_: u32) -> usize {
            512
        }
        unsafe extern "C" fn s_write_out(_: u64, _: *const u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_out_cap() -> u64 {
            0
        }
        unsafe extern "C" fn s_out_secsz() -> usize {
            512
        }
        unsafe extern "C" fn s_prog_int() -> u32 {
            100
        }
        unsafe extern "C" fn s_send_prog(_: *const u8, _: u64, _: u64, _: u32) {}
        unsafe extern "C" fn s_send_err(_: *const u8, _: *const u8, _: u64, _: u32) {}
        unsafe extern "C" fn s_send_complete(_: *const u8, _: u64, _: bool) {}
        unsafe extern "C" fn s_dbg(_: *const u8) {}
        unsafe extern "C" fn s_verb(_: *const u8) {}
        unsafe extern "C" fn s_get_op_cfg() -> shared::ConfigResult {
            shared::ConfigResult {
                ptr: core::ptr::null(),
                len: 0,
            }
        }
        unsafe extern "C" fn s_get_chain_cfg() -> shared::ConfigResult {
            shared::ConfigResult {
                ptr: core::ptr::null(),
                len: 0,
            }
        }
        unsafe extern "C" fn s_send_info(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
        ) {
        }
        unsafe extern "C" fn s_send_info_q(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::Qcow2Info,
        ) {
        }
        unsafe extern "C" fn s_send_info_v(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::VmdkInfo,
        ) {
        }
        unsafe extern "C" fn s_send_info_vdi(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::VdiInfo,
        ) {
        }
        unsafe extern "C" fn s_send_info_l(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::LuksInfo,
        ) {
        }
        unsafe extern "C" fn s_send_check(_: *const shared::CheckResult) {}
        unsafe extern "C" fn s_send_compare(_: *const shared::CompareResult) {}
        unsafe extern "C" fn s_send_measure(_: *const shared::MeasureResult) {}
        unsafe extern "C" fn s_send_create(_: *const shared::CreateResult) {}
        unsafe extern "C" fn s_read_out(_: u64, _: *mut u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_send_resize(_: *const shared::ResizeResult) {}
        unsafe extern "C" fn s_send_rebase(_: *const shared::RebaseResult) {}
        unsafe extern "C" fn s_send_commit(_: *const shared::CommitResult) {}
        unsafe extern "C" fn s_write_in(_: u32, _: u64, _: *const u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_send_map_ex(_: *const shared::MapExtentRecord) {}
        unsafe extern "C" fn s_send_map_res(_: *const shared::MapResult) {}
        unsafe extern "C" fn s_send_snap_ent(_: *const shared::SnapshotEntryRecord) {}
        unsafe extern "C" fn s_send_snap_res(_: *const shared::SnapshotResult) {}
        unsafe extern "C" fn s_fsync_in(_: u32) -> bool {
            true
        }
        unsafe extern "C" fn s_send_amend(_: *const shared::AmendResult) {}
        unsafe extern "C" fn s_send_bitmap(_: *const shared::BitmapResult) {}
        unsafe extern "C" fn s_send_bench_start() {}
        unsafe extern "C" fn s_send_bench_result(_: *const shared::BenchResult) {}
        shared::CallTable {
            magic: shared::CallTable::MAGIC,
            version: shared::CallTable::VERSION,
            get_input_device_count: s_dev_count,
            read_input_sector: mock_read_input_sector,
            get_input_capacity: s_in_cap,
            get_input_sector_size: s_in_secsz,
            write_output_sector: s_write_out,
            get_output_capacity: s_out_cap,
            get_output_sector_size: s_out_secsz,
            get_progress_interval: s_prog_int,
            send_progress: s_send_prog,
            send_error: s_send_err,
            send_complete: s_send_complete,
            debug_print: s_dbg,
            verbose_print: s_verb,
            get_operation_config: s_get_op_cfg,
            get_chain_config: s_get_chain_cfg,
            send_info_result: s_send_info,
            send_info_result_qcow2: s_send_info_q,
            send_info_result_vmdk: s_send_info_v,
            send_info_result_vdi: s_send_info_vdi,
            send_info_result_luks: s_send_info_l,
            send_check_result: s_send_check,
            send_compare_result: s_send_compare,
            send_measure_result: s_send_measure,
            send_create_result: s_send_create,
            read_output_sector: s_read_out,
            send_resize_result: s_send_resize,
            send_rebase_result: s_send_rebase,
            send_commit_result: s_send_commit,
            write_input_sector: s_write_in,
            send_map_extent: s_send_map_ex,
            send_map_result: s_send_map_res,
            send_snapshot_entry: s_send_snap_ent,
            send_snapshot_result: s_send_snap_res,
            fsync_input: s_fsync_in,
            send_amend_result: s_send_amend,
            send_bitmap_result: s_send_bitmap,
            send_bench_start: s_send_bench_start,
            send_bench_result: s_send_bench_result,
        }
    }

    // ====================================================================
    // A small sparse image
    // ====================================================================

    /// 4096-byte grains, four to a grain table.
    const GRAIN_SECTORS: u64 = 8;
    const GRAIN_BYTES: u64 = GRAIN_SECTORS * 512;
    const GTES_PER_GT: u32 = 4;
    /// Bytes of virtual disk one grain table covers.
    const GT_SPAN: u64 = GTES_PER_GT as u64 * GRAIN_BYTES;
    /// The file, in its own 512-byte sectors: the header, the grain
    /// directory, room for two grain tables, then eight grains.
    const GD_SECTOR: u64 = 1;
    const GT_SECTOR: [u32; 2] = [2, 3];
    const FIRST_GRAIN: u32 = 8;
    const IMAGE_SECTORS: u64 = FIRST_GRAIN as u64 + 8 * GRAIN_SECTORS;
    const IMAGE_LEN: u64 = IMAGE_SECTORS * 512;

    /// What a test image's header and tables say.
    #[derive(Clone, Copy)]
    struct Image {
        capacity_sectors: u64,
        flags: u32,
        /// The header's grain directory offset, in sectors.
        gd_offset: u64,
        /// Grain directory entries: the sector of each grain table.
        gd: [u32; 2],
        /// The grain tables, as sectors within the image's own file.
        gts: [[u32; 4]; 2],
    }

    /// An image of two grain tables, every grain allocated in file
    /// order.
    fn full_image() -> Image {
        let grain = |n: u32| FIRST_GRAIN + n * GRAIN_SECTORS as u32;
        Image {
            capacity_sectors: 2 * GT_SPAN / 512,
            flags: FLAG_VALID_NEW_LINE,
            gd_offset: GD_SECTOR,
            gd: GT_SECTOR,
            gts: [
                [grain(0), grain(1), grain(2), grain(3)],
                [grain(4), grain(5), grain(6), grain(7)],
            ],
        }
    }

    /// Write `image` into the mock device with its file starting at
    /// `base`.
    unsafe fn put_image(base: usize, image: &Image) {
        let dev = core::ptr::addr_of_mut!(MOCK_IMAGE) as *mut u8;
        let file = core::slice::from_raw_parts_mut(dev.add(base), IMAGE_LEN as usize);
        file.fill(0);
        build_sparse_header(
            file,
            image.capacity_sectors,
            GRAIN_SECTORS,
            GTES_PER_GT,
            image.gd_offset,
            FIRST_GRAIN as u64,
        );
        write_le_u32(file, FLAGS_OFFSET, image.flags);
        for (i, &entry) in image.gd.iter().enumerate() {
            write_le_u32(file, GD_SECTOR as usize * 512 + i * 4, entry);
        }
        for (table, entries) in image.gts.iter().enumerate() {
            for (i, &entry) in entries.iter().enumerate() {
                write_le_u32(file, GT_SECTOR[table] as usize * 512 + i * 4, entry);
            }
        }
    }

    /// Fill the mock device with a byte no table holds and put each
    /// image at its base. The guard holds the device for the test.
    fn install(images: &[(u64, Image)]) -> std::sync::MutexGuard<'static, ()> {
        let guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let dev = core::ptr::addr_of_mut!(MOCK_IMAGE) as *mut u8;
            core::ptr::write_bytes(dev, 0xEE, MOCK_LEN);
            for (base, image) in images {
                put_image(*base as usize, image);
            }
        }
        guard
    }

    fn caches() -> (*mut u8, *mut u8) {
        (
            core::ptr::addr_of_mut!(GD_CACHE) as *mut u8,
            core::ptr::addr_of_mut!(GT_CACHE) as *mut u8,
        )
    }

    /// The state of the image whose file is `len` bytes at `base`.
    fn state_at(base: u64, len: u64, sector_size: usize) -> Option<VmdkState> {
        let (gd, gt) = caches();
        let mut bytes_read = 0u64;
        unsafe {
            VmdkState::init_at(
                &stub_call_table(),
                0,
                sector_size,
                (MOCK_LEN / sector_size) as u64,
                base,
                len,
                gd,
                gt,
                &mut bytes_read,
            )
        }
    }

    /// The state of the image that is the whole device.
    fn whole_device_state(sector_size: usize) -> Option<VmdkState> {
        let (gd, gt) = caches();
        let mut bytes_read = 0u64;
        unsafe {
            VmdkState::init(
                &stub_call_table(),
                0,
                sector_size,
                (MOCK_LEN / sector_size) as u64,
                MOCK_LEN as u64,
                gd,
                gt,
                &mut bytes_read,
            )
        }
    }

    fn lookup(
        state: &mut VmdkState,
        virtual_offset: u64,
        sector_size: usize,
    ) -> Option<GrainLookup> {
        let mut bytes_read = 0u64;
        unsafe {
            state.grain_lookup(
                &stub_call_table(),
                virtual_offset,
                sector_size,
                (MOCK_LEN / sector_size) as u64,
                &mut bytes_read,
            )
        }
    }

    /// Where a second extent sits when the first is one test image
    /// long.
    const SECOND: u64 = IMAGE_LEN;

    // ====================================================================
    // The header
    // ====================================================================

    #[test]
    fn init_at_reads_the_header_where_the_extent_begins() {
        // Two images with different capacities. The one at the base is
        // the extent; the one at zero is what a read that forgets the
        // base finds.
        let first = full_image();
        let second = Image {
            capacity_sectors: GT_SPAN / 512,
            ..full_image()
        };
        let _guard = install(&[(0, first), (SECOND, second)]);

        let state = state_at(SECOND, IMAGE_LEN, 512).expect("the second extent");
        assert_eq!(state.capacity_sectors, second.capacity_sectors);
        assert_eq!(state.num_gd_entries, 1);
        assert_eq!(state.base_offset, SECOND);
        assert_eq!(state.image_end, SECOND + IMAGE_LEN);

        // The image that is the whole device is unchanged: it starts
        // at zero and ends where the device does.
        let state = whole_device_state(512).expect("the whole device");
        assert_eq!(state.capacity_sectors, first.capacity_sectors);
        assert_eq!(state.base_offset, 0);
        assert_eq!(state.image_end, u64::MAX);
    }

    #[test]
    fn init_at_reads_a_header_that_does_not_start_a_device_sector() {
        // A device sector larger than 512 bytes: an extent's base is a
        // multiple of 512 but need not be a multiple of the device's
        // sector, so its header starts partway into one.
        let image = Image {
            capacity_sectors: GT_SPAN / 512,
            ..full_image()
        };
        let base = SECOND + 512;
        for sector_size in [4096usize, MAX_SECTOR_SIZE] {
            assert_ne!(base % sector_size as u64, 0, "the harness must misalign");
            let _guard = install(&[(0, full_image()), (base, image)]);
            let mut state = state_at(base, IMAGE_LEN, sector_size)
                .unwrap_or_else(|| panic!("sector size {sector_size}"));
            assert_eq!(state.capacity_sectors, image.capacity_sectors);
            assert_eq!(
                lookup(&mut state, GRAIN_BYTES, sector_size),
                Some(GrainLookup::Standard(base + image.gts[0][1] as u64 * 512)),
                "sector size {sector_size}"
            );
        }
    }

    #[test]
    fn init_at_refuses_a_base_that_is_not_on_a_vmdk_sector() {
        // A sound image, put where a sparse image cannot be read from.
        // With 512-byte device sectors its header would straddle two
        // of them. With larger ones it would fit inside one, and so
        // would every table entry, so only the rule refuses it.
        for sector_size in [512usize, 4096] {
            let _guard = install(&[(SECOND + 256, full_image())]);
            assert!(
                state_at(SECOND + 256, IMAGE_LEN, sector_size).is_none(),
                "sector size {sector_size}"
            );
        }
        // The control: the same image one whole sector along.
        for sector_size in [512usize, 4096] {
            let _guard = install(&[(SECOND + 512, full_image())]);
            assert!(
                state_at(SECOND + 512, IMAGE_LEN, sector_size).is_some(),
                "sector size {sector_size}"
            );
        }
    }

    #[test]
    fn init_at_refuses_a_file_that_is_not_a_sparse_image() {
        // An extent is called sparse by its descriptor, and nothing has
        // looked at the file. Flat data that happens to parse as a
        // header is not one.
        let _guard = install(&[(SECOND, full_image())]);
        assert!(state_at(SECOND, IMAGE_LEN, 512).is_some(), "the control");
        unsafe {
            let dev = core::ptr::addr_of_mut!(MOCK_IMAGE) as *mut u8;
            *dev.add(SECOND as usize) ^= 0xFF;
        }
        assert!(state_at(SECOND, IMAGE_LEN, 512).is_none());
    }

    #[test]
    fn init_at_refuses_a_file_too_short_to_hold_a_header() {
        let _guard = install(&[(SECOND, full_image())]);
        assert!(state_at(SECOND, 511, 512).is_none());
        assert!(state_at(SECOND, 0, 512).is_none());
    }

    #[test]
    fn init_at_refuses_a_compressed_image() {
        let compressed = Image {
            flags: FLAG_VALID_NEW_LINE | FLAG_COMPRESSED | FLAG_MARKER,
            ..full_image()
        };
        let _guard = install(&[(0, compressed), (SECOND, compressed)]);
        assert!(state_at(SECOND, IMAGE_LEN, 512).is_none());
        // Refused for being an extent, not for being compressed: the
        // same image as a whole device still initialises.
        let state = whole_device_state(512).expect("a compressed whole device");
        assert!(state.is_compressed);
    }

    #[test]
    fn init_at_holds_the_grain_directory_to_the_extents_file() {
        // Two grain directory entries end 520 bytes into the file. A
        // file that long holds them; one byte shorter does not, though
        // the device goes on for a long way after it.
        let _guard = install(&[(SECOND, full_image())]);
        assert!(state_at(SECOND, GD_SECTOR * 512 + 8, 512).is_some());
        assert!(state_at(SECOND, GD_SECTOR * 512 + 7, 512).is_none());
        // A directory that starts past the end of the file.
        assert!(state_at(SECOND, GD_SECTOR * 512, 512).is_none());
    }

    #[test]
    fn init_at_finds_a_footer_from_the_end_of_the_extents_file() {
        // The header says the grain directory's offset is in the
        // footer, 1024 bytes before the end of the file. The file's end
        // is the extent's, not the device's, and not what the end would
        // be were the file at offset zero.
        let footed = Image {
            gd_offset: GD_AT_END,
            ..full_image()
        };
        let _guard = install(&[(SECOND, footed)]);
        unsafe {
            let dev = core::ptr::addr_of_mut!(MOCK_IMAGE) as *mut u8;
            let device = core::slice::from_raw_parts_mut(dev, MOCK_LEN);
            // The real footer: a header copy naming the directory.
            let footer_at = (SECOND + IMAGE_LEN - 1024) as usize;
            write_le_u32(device, footer_at + MAGIC_OFFSET, VMDK4_MAGIC);
            write_le_u64(device, footer_at + GD_OFFSET_OFFSET, GD_SECTOR);
            // A decoy where the footer would be for a file at zero.
            let decoy_at = (IMAGE_LEN - 1024) as usize;
            write_le_u32(device, decoy_at + MAGIC_OFFSET, VMDK4_MAGIC);
            write_le_u64(device, decoy_at + GD_OFFSET_OFFSET, 5);
        }
        let state = state_at(SECOND, IMAGE_LEN, 512).expect("a footed extent");
        assert_eq!(state.gd_offset_sectors, GD_SECTOR);
    }

    // ====================================================================
    // Lookups
    // ====================================================================

    /// An extent with one of each kind of grain, behind a first image
    /// whose directory and tables say something different at every
    /// index: a different table for the first directory entry, no
    /// table at all for the second, and a different number of grains,
    /// so that neither a lookup nor a count comes out the same from
    /// the wrong image's metadata.
    fn mixed_pair() -> (Image, Image) {
        let first = Image {
            gd: [GT_SECTOR[1], 0],
            gts: [[40, 48, 56, 64], [16, 24, 32, 0]],
            ..full_image()
        };
        let second = Image {
            flags: FLAG_VALID_NEW_LINE | FLAG_ZERO_GRAIN,
            gts: [[8, 0, GTE_ZEROED, 24], [0, 32, 0, 0]],
            ..full_image()
        };
        (first, second)
    }

    #[test]
    fn grain_lookup_reads_an_extents_tables_from_its_base() {
        let (first, second) = mixed_pair();
        let _guard = install(&[(0, first), (SECOND, second)]);
        let mut state = state_at(SECOND, IMAGE_LEN, 512).expect("the second extent");

        // The grain's place is given in the device: the extent's base
        // plus the sector its own table names.
        let at = |sector: u64| Some(GrainLookup::Standard(SECOND + sector * 512));
        assert_eq!(lookup(&mut state, 0, 512), at(8));
        assert_eq!(lookup(&mut state, 100, 512), at(8), "inside the grain");
        assert_eq!(
            lookup(&mut state, GRAIN_BYTES, 512),
            Some(GrainLookup::Unallocated)
        );
        assert_eq!(
            lookup(&mut state, 2 * GRAIN_BYTES, 512),
            Some(GrainLookup::Zeroed)
        );
        assert_eq!(lookup(&mut state, 3 * GRAIN_BYTES, 512), at(24));
        // The second grain table.
        assert_eq!(
            lookup(&mut state, GT_SPAN, 512),
            Some(GrainLookup::Unallocated)
        );
        assert_eq!(lookup(&mut state, GT_SPAN + GRAIN_BYTES, 512), at(32));
        // Past the capacity there is no directory entry to read.
        assert_eq!(
            lookup(&mut state, 2 * GT_SPAN, 512),
            Some(GrainLookup::Unallocated)
        );
    }

    #[test]
    fn grain_lookup_of_a_whole_device_is_counted_from_zero() {
        let (first, _) = mixed_pair();
        let _guard = install(&[(0, first)]);
        let mut state = whole_device_state(512).expect("the whole device");
        // The first directory entry names the second table's sector,
        // and the second names no table.
        assert_eq!(
            lookup(&mut state, 0, 512),
            Some(GrainLookup::Standard(16 * 512))
        );
        assert_eq!(
            lookup(&mut state, GRAIN_BYTES, 512),
            Some(GrainLookup::Standard(24 * 512))
        );
        assert_eq!(
            lookup(&mut state, GT_SPAN, 512),
            Some(GrainLookup::Unallocated)
        );
    }

    #[test]
    fn grain_lookup_holds_a_grain_to_the_extents_file() {
        // What follows the extent in the device is the next extent's
        // file. A grain reaching into it is not this extent's data.
        let last_whole = (IMAGE_SECTORS - GRAIN_SECTORS) as u32;
        let image = Image {
            gts: [[last_whole, last_whole + 1, 8, 8], [8, 8, 8, 8]],
            ..full_image()
        };
        let _guard = install(&[(0, image), (SECOND, image), (2 * SECOND, full_image())]);

        let mut state = state_at(SECOND, IMAGE_LEN, 512).expect("the second extent");
        assert_eq!(
            lookup(&mut state, 0, 512),
            Some(GrainLookup::Standard(SECOND + last_whole as u64 * 512)),
            "a grain ending where the file ends is the extent's"
        );
        assert_eq!(
            lookup(&mut state, GRAIN_BYTES, 512),
            None,
            "a grain ending one sector past the file is not"
        );

        // The same tables in an image that is the whole device point
        // inside the device, and are read as they always were.
        let mut state = whole_device_state(512).expect("the whole device");
        assert_eq!(
            lookup(&mut state, GRAIN_BYTES, 512),
            Some(GrainLookup::Standard((last_whole as u64 + 1) * 512))
        );
    }

    #[test]
    fn grain_lookup_holds_a_grain_table_to_the_extents_file() {
        // The second directory entry names the sector after the file's
        // last: in the device that is the start of the next extent's
        // file. What is there reads as a grain table entry naming the
        // extent's own first grain, so a lookup that followed the
        // pointer would come back with an answer.
        let image = Image {
            gd: [GT_SECTOR[0], IMAGE_SECTORS as u32],
            ..full_image()
        };
        let _guard = install(&[(0, image), (SECOND, image)]);
        unsafe {
            let dev = core::ptr::addr_of_mut!(MOCK_IMAGE) as *mut u8;
            let device = core::slice::from_raw_parts_mut(dev, MOCK_LEN);
            write_le_u32(device, 2 * SECOND as usize, FIRST_GRAIN);
        }

        let mut state = state_at(SECOND, IMAGE_LEN, 512).expect("the second extent");
        assert!(lookup(&mut state, 0, 512).is_some(), "the control");
        assert_eq!(lookup(&mut state, GT_SPAN, 512), None);

        // A whole device has no such end short of its own.
        let mut state = whole_device_state(512).expect("the whole device");
        assert!(lookup(&mut state, GT_SPAN, 512).is_some());
    }

    // ====================================================================
    // The walks
    // ====================================================================

    fn allocation_of(state: &mut VmdkState) -> Option<AllocationSummary> {
        let mut bytes_read = 0u64;
        unsafe {
            state.scan_allocation(
                &stub_call_table(),
                512,
                (MOCK_LEN / 512) as u64,
                &mut bytes_read,
            )
        }
    }

    /// The first eight extents `map_extents` emits.
    fn map_of(state: &mut VmdkState) -> ([Option<MapExtent>; 8], usize) {
        let mut out = [None; 8];
        let mut count = 0usize;
        let mut bytes_read = 0u64;
        let walked = unsafe {
            state.map_extents(
                &stub_call_table(),
                512,
                (MOCK_LEN / 512) as u64,
                &mut bytes_read,
                &mut |extent| {
                    if count < out.len() {
                        out[count] = Some(extent);
                    }
                    count += 1;
                    true
                },
            )
        };
        assert!(walked.is_some(), "the walk must not fail");
        (out, count)
    }

    #[test]
    fn the_walks_read_an_extents_tables_from_its_base() {
        let (first, second) = mixed_pair();

        // What the second image says when it is the whole device.
        let (alone_allocation, alone_map) = {
            let _guard = install(&[(0, second)]);
            let mut state = whole_device_state(512).expect("alone");
            (allocation_of(&mut state), map_of(&mut state))
        };
        // And what the first says, which is what a walk that forgets
        // the base would report for the second.
        let first_allocation = {
            let _guard = install(&[(0, first)]);
            let mut state = whole_device_state(512).expect("the first alone");
            allocation_of(&mut state)
        };
        let alone = alone_allocation.expect("the scan must not fail");
        // Three data grains and the zeroed one, which the scan counts.
        assert_eq!(alone.allocated_bytes, 4 * GRAIN_BYTES);
        assert_ne!(
            first_allocation.map(|a| a.allocated_bytes),
            Some(alone.allocated_bytes),
            "the two images must differ for the test to mean anything"
        );

        let _guard = install(&[(0, first), (SECOND, second)]);
        let mut state = state_at(SECOND, IMAGE_LEN, 512).expect("the second extent");
        let based = allocation_of(&mut state).expect("the scan must not fail");
        assert_eq!(based.allocated_bytes, alone.allocated_bytes);
        assert_eq!(based.virtual_size, alone.virtual_size);

        // The map is the same too, down to each data extent's offset,
        // which is an offset into the extent's own file and so does not
        // move with the base.
        let based_map = map_of(&mut state);
        assert_eq!(based_map.1, alone_map.1);
        assert_eq!(based_map.0, alone_map.0);
        assert_eq!(
            based_map.0[0],
            Some(MapExtent {
                start: 0,
                length: GRAIN_BYTES,
                state: MapExtentState::Data {
                    file_offset: 8 * 512
                },
            })
        );
    }

    #[test]
    fn the_walks_hold_a_grain_table_to_the_extents_file() {
        let image = Image {
            gd: [GT_SECTOR[0], IMAGE_SECTORS as u32],
            ..full_image()
        };
        let _guard = install(&[(0, image), (SECOND, image), (2 * SECOND, full_image())]);
        let mut state = state_at(SECOND, IMAGE_LEN, 512).expect("the second extent");
        assert!(allocation_of(&mut state).is_none());
        let mut bytes_read = 0u64;
        let walked = unsafe {
            state.map_extents(
                &stub_call_table(),
                512,
                (MOCK_LEN / 512) as u64,
                &mut bytes_read,
                &mut |_| true,
            )
        };
        assert!(walked.is_none());
    }

    // ====================================================================
    // Which extent a state belongs to
    // ====================================================================

    #[test]
    fn is_image_at_names_the_range_the_state_was_read_from() {
        let _guard = install(&[(0, full_image()), (SECOND, full_image())]);
        let state = state_at(SECOND, IMAGE_LEN, 512).expect("the second extent");
        assert!(state.is_image_at(SECOND, IMAGE_LEN));
        assert!(!state.is_image_at(0, IMAGE_LEN), "another base");
        assert!(
            !state.is_image_at(SECOND, IMAGE_LEN - 512),
            "another length"
        );
        assert!(
            !state.is_image_at(SECOND, u64::MAX),
            "a length that overflows"
        );

        // The first extent starts at zero, as a whole device does, but
        // its state is still its own.
        let state = state_at(0, IMAGE_LEN, 512).expect("the first extent");
        assert!(state.is_image_at(0, IMAGE_LEN));
        assert!(!state.is_image_at(SECOND, IMAGE_LEN));
    }
}
