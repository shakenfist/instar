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
    le_u16, le_u32, le_u64, write_le_u16, write_le_u32, write_le_u64, CallTable, VmdkInfo,
    MAX_SECTOR_SIZE,
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
        // Read first sector (contains the 512-byte VMDK4 header)
        let mut header_buf = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(device_idx, 0, header_buf.as_mut_ptr(), sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;

        let header = Vmdk4HeaderFull::parse(&header_buf)?;

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
                actual_file_size,
                bytes_read,
            )?
        } else {
            header.gd_offset_sectors
        };

        // Validate GD offset
        let actual_size = input_capacity.checked_mul(sector_size as u64)?;
        let gd_byte_offset = gd_offset_sectors.checked_mul(512)?;
        if gd_byte_offset >= actual_size {
            return None;
        }
        // Validate GD doesn't extend beyond file
        let gd_size_bytes = (num_gd_entries as u64).checked_mul(4)?;
        let gd_end = gd_byte_offset.checked_add(gd_size_bytes)?;
        if gd_end > actual_size {
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
    unsafe fn read_footer_gd_offset(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
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
        let footer_byte_offset = actual_file_size.checked_sub(1024)?;
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
        let gd_byte_offset = self
            .gd_offset_sectors
            .checked_mul(512)?
            .checked_add(gd_index.checked_mul(4)?)?;
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
        let gt_byte_offset = (gd_entry as u64)
            .checked_mul(512)?
            .checked_add(gt_index.checked_mul(4)?)?;

        // Validate GT offset within file
        let actual_size = input_capacity.checked_mul(sector_size as u64)?;
        if gt_byte_offset >= actual_size {
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

        if self.is_compressed {
            // For compressed images, the GTE is the sector offset
            // to the grain marker (12-byte header + compressed data).
            let marker_byte_offset = (gte as u64).checked_mul(512)?;
            Some(GrainLookup::Compressed(marker_byte_offset))
        } else {
            // Standard grain: GTE is sector offset to grain data.
            let host_byte_offset = (gte as u64).checked_mul(512)?;
            Some(GrainLookup::Standard(host_byte_offset))
        }
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
/// Real-world monolithicFlat uses a single extent;
/// twoGbMaxExtentFlat caps at ~1TB/2GB extents per file so this
/// limit comfortably covers any legitimate descriptor.
pub const MAX_EXTENTS: usize = 32;

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
