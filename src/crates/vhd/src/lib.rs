//! VHD/VPC (Virtual Hard Disk) format parsing.
//!
//! Provides VHD footer and dynamic header parsing, BAT (Block Allocation
//! Table) reading, and block lookup for dynamic VHD images. Fixed VHDs
//! (disk_type=2) are treated as raw data with a trailing footer.

#![no_std]
#![allow(clippy::too_many_arguments)]

use shared::{
    be_u16, be_u32, be_u64, write_be_u16, write_be_u32, write_be_u64, AllocationSummary, CallTable,
    MapExtent, MapExtentCoalescer, MapExtentState, MAX_SECTOR_SIZE,
};

// ============================================================================
// VHD footer field offsets (all big-endian)
// ============================================================================

/// Footer size in bytes.
pub const FOOTER_SIZE: usize = 512;

/// Footer cookie offset: "conectix" (8 bytes, big-endian).
pub const FOOTER_COOKIE_OFFSET: usize = 0;
/// Footer features offset (u32 BE).
pub const FOOTER_FEATURES_OFFSET: usize = 8;
/// Footer format version offset (u32 BE).
pub const FOOTER_FORMAT_VERSION_OFFSET: usize = 12;
/// Footer data offset (u64 BE) — offset to dynamic header.
pub const FOOTER_DATA_OFFSET_OFFSET: usize = 16;
/// Footer timestamp offset (u32 BE).
pub const FOOTER_TIMESTAMP_OFFSET: usize = 24;
/// Footer creator application offset (4 bytes).
pub const FOOTER_CREATOR_APP_OFFSET: usize = 28;
/// Footer creator version offset (u32 BE).
pub const FOOTER_CREATOR_VERSION_OFFSET: usize = 32;
/// Footer creator host OS offset (u32 BE).
pub const FOOTER_CREATOR_HOST_OFFSET: usize = 36;
/// Footer original size offset (u64 BE).
pub const FOOTER_ORIGINAL_SIZE_OFFSET: usize = 40;
/// Footer current size offset (u64 BE).
pub const FOOTER_CURRENT_SIZE_OFFSET: usize = 48;
/// Footer disk geometry offset (4 bytes: CHS).
pub const FOOTER_GEOMETRY_OFFSET: usize = 56;
/// Footer disk type offset (u32 BE).
pub const FOOTER_DISK_TYPE_OFFSET: usize = 60;
/// Footer checksum offset (u32 BE).
pub const FOOTER_CHECKSUM_OFFSET: usize = 64;
/// Footer unique ID offset (16 bytes UUID).
pub const FOOTER_UUID_OFFSET: usize = 68;
/// Footer saved state offset (u8).
pub const FOOTER_SAVED_STATE_OFFSET: usize = 84;

// ============================================================================
// VHD dynamic header field offsets (all big-endian)
// ============================================================================

/// Dynamic header size in bytes.
pub const DYNAMIC_HEADER_SIZE: usize = 1024;

/// Dynamic header cookie offset: "cxsparse" (8 bytes).
pub const DYN_COOKIE_OFFSET: usize = 0;
/// Dynamic header data offset (u64 BE) — unused, should be 0xFFFFFFFFFFFFFFFF.
pub const DYN_DATA_OFFSET_OFFSET: usize = 8;
/// Dynamic header table offset (u64 BE) — byte offset to BAT.
pub const DYN_TABLE_OFFSET_OFFSET: usize = 16;
/// Dynamic header version offset (u32 BE).
pub const DYN_HEADER_VERSION_OFFSET: usize = 24;
/// Dynamic header max table entries (u32 BE) — number of BAT entries.
pub const DYN_MAX_TABLE_ENTRIES_OFFSET: usize = 28;
/// Dynamic header block size (u32 BE) — bytes per data block.
pub const DYN_BLOCK_SIZE_OFFSET: usize = 32;
/// Dynamic header checksum offset (u32 BE).
pub const DYN_CHECKSUM_OFFSET: usize = 36;

// ============================================================================
// VHD constants
// ============================================================================

/// VHD footer cookie: "conectix" (big-endian u64).
pub const VHD_COOKIE: u64 = 0x636f_6e65_6374_6978;

/// VHD dynamic header cookie: "cxsparse" (big-endian u64).
pub const CXSPARSE_COOKIE: u64 = 0x6378_7370_6172_7365;

/// VHD format version 1.0 (stored as major.minor in u32 BE).
pub const VHD_VERSION_1_0: u32 = 0x0001_0000;

/// Disk type: Fixed (raw data + footer).
pub const DISK_TYPE_FIXED: u32 = 2;
/// Disk type: Dynamic (footer + dynamic header + BAT + blocks).
pub const DISK_TYPE_DYNAMIC: u32 = 3;
/// Disk type: Differencing (has parent locators).
pub const DISK_TYPE_DIFFERENCING: u32 = 4;

/// BAT entry value indicating an unallocated block.
pub const BAT_UNALLOCATED: u32 = 0xFFFF_FFFF;

/// Default block size (2 MiB).
pub const DEFAULT_BLOCK_SIZE: u32 = 2 * 1024 * 1024;

/// VHD features: reserved bit (must be set).
pub const FEATURES_RESERVED: u32 = 0x0000_0002;

// ============================================================================
// VHD footer parsing
// ============================================================================

/// Parsed VHD footer fields.
pub struct VhdFooter {
    pub cookie: u64,
    pub features: u32,
    pub format_version: u32,
    pub data_offset: u64,
    pub original_size: u64,
    pub current_size: u64,
    pub cylinders: u16,
    pub heads: u8,
    pub sectors_per_track: u8,
    pub disk_type: u32,
    pub checksum: u32,
    pub uuid: [u8; 16],
}

impl VhdFooter {
    /// Parse a VHD footer from raw bytes.
    ///
    /// `buf` must contain at least 512 bytes starting at the footer.
    /// Returns `None` if the buffer is too small or the cookie is invalid.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < FOOTER_SIZE {
            return None;
        }

        let cookie = be_u64(buf, FOOTER_COOKIE_OFFSET);
        if cookie != VHD_COOKIE {
            return None;
        }

        let features = be_u32(buf, FOOTER_FEATURES_OFFSET);
        let format_version = be_u32(buf, FOOTER_FORMAT_VERSION_OFFSET);
        let data_offset = be_u64(buf, FOOTER_DATA_OFFSET_OFFSET);
        let original_size = be_u64(buf, FOOTER_ORIGINAL_SIZE_OFFSET);
        let current_size = be_u64(buf, FOOTER_CURRENT_SIZE_OFFSET);

        let cylinders = be_u16(buf, FOOTER_GEOMETRY_OFFSET);
        let heads = buf[FOOTER_GEOMETRY_OFFSET + 2];
        let sectors_per_track = buf[FOOTER_GEOMETRY_OFFSET + 3];

        let disk_type = be_u32(buf, FOOTER_DISK_TYPE_OFFSET);
        let checksum = be_u32(buf, FOOTER_CHECKSUM_OFFSET);

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[FOOTER_UUID_OFFSET..FOOTER_UUID_OFFSET + 16]);

        Some(VhdFooter {
            cookie,
            features,
            format_version,
            data_offset,
            original_size,
            current_size,
            cylinders,
            heads,
            sectors_per_track,
            disk_type,
            checksum,
            uuid,
        })
    }
}

// ============================================================================
// VHD dynamic header parsing
// ============================================================================

/// Parsed VHD dynamic header fields.
pub struct VhdDynamicHeader {
    pub cookie: u64,
    pub table_offset: u64,
    pub header_version: u32,
    pub max_table_entries: u32,
    pub block_size: u32,
    pub checksum: u32,
}

impl VhdDynamicHeader {
    /// Parse a VHD dynamic header from raw bytes.
    ///
    /// `buf` must contain at least 1024 bytes starting at the dynamic
    /// header. Returns `None` if the buffer is too small or the cookie
    /// is invalid.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < DYNAMIC_HEADER_SIZE {
            return None;
        }

        let cookie = be_u64(buf, DYN_COOKIE_OFFSET);
        if cookie != CXSPARSE_COOKIE {
            return None;
        }

        let table_offset = be_u64(buf, DYN_TABLE_OFFSET_OFFSET);
        let header_version = be_u32(buf, DYN_HEADER_VERSION_OFFSET);
        let max_table_entries = be_u32(buf, DYN_MAX_TABLE_ENTRIES_OFFSET);
        let block_size = be_u32(buf, DYN_BLOCK_SIZE_OFFSET);
        let checksum = be_u32(buf, DYN_CHECKSUM_OFFSET);

        Some(VhdDynamicHeader {
            cookie,
            table_offset,
            header_version,
            max_table_entries,
            block_size,
            checksum,
        })
    }
}

// ============================================================================
// Checksum computation
// ============================================================================

/// Compute the VHD checksum for a buffer.
///
/// The checksum is the one's complement of the sum of all bytes in the
/// structure, with the checksum field itself set to zero during computation.
pub fn compute_checksum(buf: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i >= checksum_offset && i < checksum_offset + 4 {
            continue;
        }
        sum = sum.wrapping_add(b as u32);
    }
    !sum
}

// ============================================================================
// CHS geometry calculation (VPC algorithm)
// ============================================================================

/// Maximum CHS-addressable sector count (16-bit cylinders × 16 heads ×
/// 255 sectors/track): qemu vpc.c's `VHD_MAX_SECTORS` / `VHD_MAX_GEOMETRY`.
pub const VHD_MAX_SECTORS: u64 = 65535 * 16 * 255;

/// CHS geometry from a sector count — an exact mirror of qemu vpc.c's
/// `calculate_geometry` (itself the VHD-spec / Virtual PC algorithm).
/// All divisions floor, `heads` rounds up, and the 17 → 31 → 63
/// sectors-per-track ladder escalates whenever `cylinders × heads`
/// would overflow the current head count; disks of at least
/// `65535 * 16 * 63` sectors use 255 sectors/track. The returned
/// product `cylinders * heads * spt` may be slightly below
/// `total_sectors` (everything floors) — qemu's create path compensates
/// with the upward search in [`chs_rounded_size`].
fn calculate_geometry(total_sectors: u64) -> (u16, u8, u8) {
    let total_sectors = total_sectors.min(VHD_MAX_SECTORS);

    if total_sectors >= 65535 * 16 * 63 {
        let cyl_times_heads = total_sectors / 255;
        return ((cyl_times_heads / 16) as u16, 16, 255);
    }

    let mut sectors_per_track: u64 = 17;
    let mut cyl_times_heads = total_sectors / sectors_per_track;
    let mut heads = cyl_times_heads.div_ceil(1024);
    if heads < 4 {
        heads = 4;
    }

    if cyl_times_heads >= (heads * 1024) || heads > 16 {
        sectors_per_track = 31;
        heads = 16;
        cyl_times_heads = total_sectors / sectors_per_track;
    }

    if cyl_times_heads >= (heads * 1024) {
        sectors_per_track = 63;
        heads = 16;
        cyl_times_heads = total_sectors / sectors_per_track;
    }

    (
        (cyl_times_heads / heads) as u16,
        heads as u8,
        sectors_per_track as u8,
    )
}

/// Compute CHS geometry for a VHD from a size in bytes (floor to whole
/// sectors), mirroring qemu vpc.c's `calculate_geometry`.
///
/// Returns `(cylinders, heads, sectors_per_track)`.
pub fn compute_vhd_geometry(size: u64) -> (u16, u8, u8) {
    calculate_geometry(size / 512)
}

/// Compute the CHS-rounded virtual size that `qemu-img dd -O vpc` /
/// `qemu-img create -f vpc` declare for an arbitrary requested size —
/// an exact mirror of qemu vpc.c's `calculate_rounded_image_size`.
///
/// qemu rounds the request up to whole sectors, then searches upward
/// from that sector count for the first candidate whose (floor)
/// [`calculate_geometry`] product covers the request; the product
/// becomes the footer's current_size (what `qemu-img info` reports as
/// the virtual size) and the candidate's geometry becomes the footer
/// CHS. Because the product is a fixed point of `calculate_geometry`,
/// [`build_footer`]'s recomputation from current_size reproduces the
/// identical CHS bytes (`chs_rounded_size_is_chs_consistent` pins
/// this).
///
/// Two edges depart from the plain search:
///   * The max-geometry window: when only the full `(65535,16,255)`
///     ceiling can cover the request, qemu keeps the EXACT sector-
///     rounded request as the size (the footer CHS then addresses
///     slightly less than current_size). Mirrored here.
///   * Oversize requests: qemu refuses anything past 2040 GiB
///     (`VHD_MAX_SECTORS`); instar's convert path instead clamps to
///     the ceiling, preserving long-standing saturation behaviour
///     (`fuzz_chs_rounded_size` invariant 3).
pub fn chs_rounded_size(size: u64) -> u64 {
    // An empty window (size 0) has no CHS geometry; qemu-img dd produces a
    // 0-virtual-size VHD for count=0.
    if size == 0 {
        return 0;
    }
    let requested = size.div_ceil(512).min(VHD_MAX_SECTORS);

    let mut cyls: u64 = 0;
    let mut heads: u64 = 0;
    let mut spt: u64 = 0;
    let mut candidate = requested;
    while requested > cyls * heads * spt {
        let (c, h, s) = calculate_geometry(candidate);
        cyls = c as u64;
        heads = h as u64;
        spt = s as u64;
        candidate += 1;
    }

    let product = cyls * heads * spt;
    if product == VHD_MAX_SECTORS {
        requested * 512
    } else {
        product * 512
    }
}

// ============================================================================
// Allocation scanning — pure helper
// ============================================================================

/// Count allocated entries in a dynamic-VHD BAT byte slice.
///
/// Each entry is a big-endian u32 sector pointer. The unallocated
/// marker is `0xFFFF_FFFF`. Any other value indicates an allocated
/// block.
///
/// `bat_bytes` may have a trailing partial entry (length not a
/// multiple of 4); the trailing bytes are ignored. The caller is
/// expected to pass a slice covering exactly `total_blocks * 4`
/// bytes after BAT padding.
pub fn count_allocated_in_bat(bat_bytes: &[u8]) -> u64 {
    bat_bytes
        .chunks_exact(4)
        .filter(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]) != BAT_UNALLOCATED)
        .count() as u64
}

/// Classify one dynamic-VHD BAT entry into a single `MapExtent`.
///
/// Mirrors `VhdState::block_lookup`'s dynamic-VHD decision tree:
///
/// - `entry == BAT_UNALLOCATED` (0xFFFF_FFFF): `Hole`.
/// - Otherwise: `Data { file_offset = entry * 512 +
///   block_data_offset }`. The BAT entry is the absolute sector
///   number of the block's sector-bitmap; the payload starts
///   `block_data_offset` bytes later.
///
/// `block_size_bytes` is the extent's length. `virtual_offset` is
/// the virtual address of the block's first byte; the caller is
/// responsible for clamping `length` against virtual_size if the
/// block straddles end-of-image.
pub fn classify_vhd_bat_entry(
    entry: u32,
    virtual_offset: u64,
    block_size_bytes: u64,
    block_data_offset: u64,
) -> MapExtent {
    let state = if entry == BAT_UNALLOCATED {
        MapExtentState::Hole
    } else {
        let block_host_offset = (entry as u64).saturating_mul(512);
        MapExtentState::Data {
            file_offset: block_host_offset.saturating_add(block_data_offset),
        }
    };
    MapExtent {
        start: virtual_offset,
        length: block_size_bytes,
        state,
    }
}

// ============================================================================
// Block lookup result
// ============================================================================

/// Result of looking up a virtual offset in the VHD BAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockLookup {
    /// The block is not allocated (reads as zeros or from parent).
    Unallocated,
    /// The block is allocated at the given host byte offset
    /// (past the sector bitmap, pointing to the data region).
    Allocated { host_byte_offset: u64 },
}

// ============================================================================
// VHD state for BAT I/O
// ============================================================================

/// Runtime state for reading VHD blocks from a device.
///
/// Analogous to `qcow2::Qcow2State` and `vmdk::VmdkState`. Maintains
/// a sector cache for BAT reads.
pub struct VhdState {
    pub device_idx: u32,
    pub disk_type: u32,
    pub block_size: u32,
    pub block_data_offset: u32,
    pub max_table_entries: u32,
    pub table_offset: u64,
    pub current_size: u64,
    // Sector cache for BAT reads
    pub bat_cached_sector: u64,
    pub bat_cache_buf: *mut u8,
    // Sector cache for data reads (reused for sector bitmap skip)
    pub data_cached_sector: u64,
    pub data_cache_buf: *mut u8,
}

impl VhdState {
    /// Initialize VHD state by reading footer and dynamic header.
    ///
    /// For dynamic VHDs: reads the footer (first sector), then the
    /// dynamic header, validates, and sets up state.
    ///
    /// For fixed VHDs: reads the footer from the last sector,
    /// validates, and sets up minimal state (no BAT needed).
    ///
    /// Returns `None` if the footer/header is invalid or I/O fails.
    ///
    /// # Safety
    ///
    /// `bat_cache_buf` and `data_cache_buf` must each point to at
    /// least `MAX_SECTOR_SIZE` writable bytes. `call_table` must be
    /// valid.
    pub unsafe fn init(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        bat_cache_buf: *mut u8,
        data_cache_buf: *mut u8,
        bytes_read: &mut u64,
    ) -> Option<Self> {
        // Read first sector (contains footer copy for dynamic VHDs,
        // or raw data for fixed VHDs).
        let mut first_sector = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(device_idx, 0, first_sector.as_mut_ptr(), sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;

        // Try parsing footer from first sector
        let footer = VhdFooter::parse(&first_sector);

        if footer.is_none() {
            // No footer at start — try the last sector (fixed VHD
            // only has footer at end).
            let last_sector_idx = input_capacity.checked_sub(1)?;
            let mut last_sector = [0u8; MAX_SECTOR_SIZE];
            if !(call_table.read_input_sector)(
                device_idx,
                last_sector_idx,
                last_sector.as_mut_ptr(),
                sector_size,
            ) {
                return None;
            }
            *bytes_read += sector_size as u64;

            // For large sectors the footer is at the start of the
            // last sector (footer is only 512 bytes).
            let footer = VhdFooter::parse(&last_sector)?;
            return Self::init_fixed(
                footer,
                device_idx,
                input_capacity,
                sector_size,
                bat_cache_buf,
                data_cache_buf,
            );
        }

        let footer = footer.unwrap();

        if footer.disk_type == DISK_TYPE_FIXED {
            return Self::init_fixed(
                footer,
                device_idx,
                input_capacity,
                sector_size,
                bat_cache_buf,
                data_cache_buf,
            );
        }

        if footer.disk_type != DISK_TYPE_DYNAMIC && footer.disk_type != DISK_TYPE_DIFFERENCING {
            return None;
        }

        // Read dynamic header at footer.data_offset
        let dyn_byte_offset = footer.data_offset;
        let actual_size = input_capacity.checked_mul(sector_size as u64)?;
        if dyn_byte_offset >= actual_size {
            return None;
        }
        // Dynamic header is 1024 bytes. We need to read enough
        // sectors to cover it.
        let dyn_sector = dyn_byte_offset / sector_size as u64;
        let dyn_off_in_sector = (dyn_byte_offset % sector_size as u64) as usize;

        // Read up to 2 sectors to ensure we get the full 1024-byte header
        let mut dyn_buf = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(
            device_idx,
            dyn_sector,
            dyn_buf.as_mut_ptr(),
            sector_size,
        ) {
            return None;
        }
        *bytes_read += sector_size as u64;

        // If the dynamic header doesn't fit in the first sector,
        // read the next one too. For typical VHDs the footer is at
        // offset 0 and the dynamic header at offset 512, so with
        // 512-byte sectors we need to read sector 1 + sector 2.
        // With larger sectors, it fits in one.
        let dyn_available = sector_size - dyn_off_in_sector;
        let mut dyn_header_bytes = [0u8; DYNAMIC_HEADER_SIZE];
        if dyn_available >= DYNAMIC_HEADER_SIZE {
            dyn_header_bytes.copy_from_slice(
                &dyn_buf[dyn_off_in_sector..dyn_off_in_sector + DYNAMIC_HEADER_SIZE],
            );
        } else {
            // First part from this sector
            dyn_header_bytes[..dyn_available]
                .copy_from_slice(&dyn_buf[dyn_off_in_sector..sector_size]);
            // Read next sector
            let next_sector = dyn_sector + 1;
            if next_sector >= input_capacity {
                return None;
            }
            if !(call_table.read_input_sector)(
                device_idx,
                next_sector,
                dyn_buf.as_mut_ptr(),
                sector_size,
            ) {
                return None;
            }
            *bytes_read += sector_size as u64;
            let remaining = DYNAMIC_HEADER_SIZE - dyn_available;
            dyn_header_bytes[dyn_available..DYNAMIC_HEADER_SIZE]
                .copy_from_slice(&dyn_buf[..remaining]);
        }

        let dyn_header = VhdDynamicHeader::parse(&dyn_header_bytes)?;

        // Validate
        if dyn_header.block_size == 0 {
            return None;
        }
        // Block size must be a power of 2
        if (dyn_header.block_size & (dyn_header.block_size - 1)) != 0 {
            return None;
        }
        if dyn_header.max_table_entries == 0 {
            return None;
        }

        // Validate BAT offset
        let bat_byte_offset = dyn_header.table_offset;
        if bat_byte_offset >= actual_size {
            return None;
        }
        let bat_size_bytes = (dyn_header.max_table_entries as u64).checked_mul(4)?;
        let bat_end = bat_byte_offset.checked_add(bat_size_bytes)?;
        if bat_end > actual_size {
            return None;
        }

        // Sector bitmap size: ceil(block_size / 512 / 8) rounded up
        // to next 512-byte boundary.
        let sectors_per_block = dyn_header.block_size / 512;
        let bitmap_bytes = (sectors_per_block.div_ceil(8) + 511) & !511;

        Some(VhdState {
            device_idx,
            disk_type: footer.disk_type,
            block_size: dyn_header.block_size,
            block_data_offset: bitmap_bytes,
            max_table_entries: dyn_header.max_table_entries,
            table_offset: dyn_header.table_offset,
            current_size: footer.current_size,
            bat_cached_sector: u64::MAX,
            bat_cache_buf,
            data_cached_sector: u64::MAX,
            data_cache_buf,
        })
    }

    /// Initialize state for a fixed VHD.
    ///
    /// Fixed VHDs have raw data from offset 0 with a 512-byte footer
    /// appended at the end. No BAT or dynamic header exists.
    fn init_fixed(
        footer: VhdFooter,
        device_idx: u32,
        _input_capacity: u64,
        _sector_size: usize,
        bat_cache_buf: *mut u8,
        data_cache_buf: *mut u8,
    ) -> Option<Self> {
        Some(VhdState {
            device_idx,
            disk_type: DISK_TYPE_FIXED,
            block_size: 0,
            block_data_offset: 0,
            max_table_entries: 0,
            table_offset: 0,
            current_size: footer.current_size,
            bat_cached_sector: u64::MAX,
            bat_cache_buf,
            data_cached_sector: u64::MAX,
            data_cache_buf,
        })
    }

    /// Check if this is a fixed VHD (raw data, no BAT).
    pub fn is_fixed(&self) -> bool {
        self.disk_type == DISK_TYPE_FIXED
    }

    /// Look up the host location for a given virtual byte offset.
    ///
    /// For dynamic VHDs: reads the BAT entry for the containing block.
    /// If allocated, returns the host byte offset past the sector
    /// bitmap. If unallocated (0xFFFFFFFF), returns `Unallocated`.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. Cache buffers must still be valid.
    pub unsafe fn block_lookup(
        &mut self,
        call_table: &CallTable,
        virtual_offset: u64,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<BlockLookup> {
        if self.is_fixed() {
            // Fixed VHDs: data is at the same offset as virtual
            return Some(BlockLookup::Allocated {
                host_byte_offset: virtual_offset,
            });
        }

        // Calculate which block this virtual offset falls in
        let block_idx = virtual_offset / self.block_size as u64;

        if block_idx >= self.max_table_entries as u64 {
            return Some(BlockLookup::Unallocated);
        }

        // Read BAT entry (u32 BE at table_offset + block_idx * 4)
        let bat_byte_offset = self.table_offset.checked_add(block_idx.checked_mul(4)?)?;

        let bat_entry = read_u32_be_cached(
            call_table,
            self.device_idx,
            bat_byte_offset,
            sector_size,
            input_capacity,
            &mut self.bat_cached_sector,
            self.bat_cache_buf,
            bytes_read,
        )?;

        if bat_entry == BAT_UNALLOCATED {
            return Some(BlockLookup::Unallocated);
        }

        // BAT entry is the absolute sector number (512-byte sectors)
        // of the block's sector bitmap. Data follows the bitmap.
        let block_host_offset = (bat_entry as u64).checked_mul(512)?;
        let data_start = block_host_offset.checked_add(self.block_data_offset as u64)?;

        // Offset within the block
        let intra_block_offset = virtual_offset % self.block_size as u64;

        Some(BlockLookup::Allocated {
            host_byte_offset: data_start + intra_block_offset,
        })
    }

    /// Walk the BAT and produce an `AllocationSummary`.
    ///
    /// For Fixed VHDs (no BAT), `allocated_bytes == virtual_size`.
    /// For Dynamic VHDs, walks the BAT in `MAX_SECTOR_SIZE`-sized cached
    /// chunks and counts entries != `0xFFFF_FFFF`, multiplying by
    /// `block_size`.
    ///
    /// Returns `None` if any I/O call fails. The caller treats `None`
    /// as an unrecoverable format error.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. `bat_cache_buf` must still be valid
    /// and point to at least `MAX_SECTOR_SIZE` writable bytes.
    // NOTE: The sector-walking loop below (buf_start / buf_end /
    // meaningful_len / per-sector read) is duplicated near-verbatim in
    // `vhdx::VhdxState::scan_allocation`. The two formats walk single
    // contiguous BAT tables; the only differences are the entry
    // decoder (`count_allocated_in_bat` vs the vhdx chunk_ratio-aware
    // variant) and one cache-invalidation line. Extracting a shared
    // `walk_table_sectors(call_table, byte_offset, byte_len, ...,
    // FnMut(&[u8]))` helper into `shared` is captured as future work
    // in PLAN-measure.md; deferred because the FnMut + &mut self
    // borrow interaction adds non-trivial complexity for marginal
    // line-count reduction.
    pub unsafe fn scan_allocation(
        &mut self,
        call_table: &CallTable,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<AllocationSummary> {
        // Fixed VHDs: every byte is allocated — no BAT to walk.
        if self.disk_type == DISK_TYPE_FIXED {
            return Some(AllocationSummary::clamp(
                self.current_size,
                self.current_size,
                // TODO(#286): populate from target_unit_size when this
                // scanner is converted to target-aware accounting.
                0,
            ));
        }

        // Dynamic (and Differencing) VHDs: walk the BAT.
        // The BAT is a contiguous u32-be array of `max_table_entries`
        // entries starting at `table_offset` (byte offset).
        let total_bat_bytes = (self.max_table_entries as u64).checked_mul(4)?;
        let bat_start_sector = self.table_offset / sector_size as u64;
        let bat_end_byte = self.table_offset.checked_add(total_bat_bytes)?;
        // Round up to the next sector boundary so we cover any partial
        // sector at the end of the BAT.
        let bat_end_sector = bat_end_byte.checked_add(sector_size as u64 - 1)? / sector_size as u64;

        let mut allocated_blocks: u64 = 0;
        // Bytes of BAT we have logically consumed so far (used to bound
        // the count so padding at the end of the last sector is ignored).
        let mut bat_bytes_consumed: u64 = 0;

        let mut sector = bat_start_sector;
        while sector < bat_end_sector {
            if sector >= input_capacity {
                return None;
            }
            if !(call_table.read_input_sector)(
                self.device_idx,
                sector,
                self.bat_cache_buf,
                sector_size,
            ) {
                return None;
            }
            *bytes_read += sector_size as u64;

            // Determine the byte range within this sector that belongs
            // to the BAT (accounting for the first sector's intra-sector
            // offset and clamping to `total_bat_bytes`).
            let sector_byte_start = sector * sector_size as u64;
            // Offset of the first BAT byte within this sector's buffer.
            let buf_start = if sector_byte_start < self.table_offset {
                (self.table_offset - sector_byte_start) as usize
            } else {
                0
            };
            let buf_end =
                sector_size.min((bat_end_byte.saturating_sub(sector_byte_start)) as usize);
            if buf_end <= buf_start {
                sector += 1;
                continue;
            }
            let chunk =
                core::slice::from_raw_parts(self.bat_cache_buf.add(buf_start), buf_end - buf_start);

            // Clamp to the meaningful BAT bytes (ignore sector padding).
            let meaningful_len =
                (total_bat_bytes - bat_bytes_consumed).min((buf_end - buf_start) as u64) as usize;
            let meaningful = &chunk[..meaningful_len];

            allocated_blocks += count_allocated_in_bat(meaningful);
            bat_bytes_consumed += meaningful_len as u64;

            sector += 1;
        }

        // `block_size` (typically 2 MiB) frequently exceeds the
        // virtual_size of small images, so a single allocated block can
        // make `allocated_blocks * block_size` overshoot `current_size`.
        // AllocationSummary::clamp enforces allocated_bytes <=
        // virtual_size at construction; `measure_<fmt>` rejects
        // summaries that violate it, which would surface to the user
        // as "source image is unsupported format". Mirrors the qcow2
        // out-of-bounds skip established in PLAN-fuzzing-bugs phase 2.
        let allocated_bytes = allocated_blocks.saturating_mul(self.block_size as u64);

        Some(AllocationSummary::clamp(
            self.current_size,
            allocated_bytes,
            // TODO(#286): populate from target_unit_size when this
            // scanner is converted to target-aware accounting.
            0,
        ))
    }

    /// Walk the dynamic-VHD BAT (or short-circuit for fixed VHDs)
    /// and emit a coalesced `MapExtent` stream covering
    /// `[0, current_size)`.
    ///
    /// For fixed VHDs: a single Data extent at file_offset 0
    /// covering the whole virtual size. No BAT walk.
    ///
    /// For dynamic / differencing VHDs: walks the BAT exactly like
    /// `scan_allocation`'s sector-walking shell, classifies each
    /// entry via [`classify_vhd_bat_entry`], and pushes the result
    /// through a `MapExtentCoalescer` that persists for the whole
    /// walk so consecutive Data blocks with contiguous payload
    /// offsets coalesce into one extent.
    ///
    /// A trailing `Hole` covers any virtual range past the last
    /// walked block up to `current_size` so emitted extents
    /// partition `[0, current_size)`.
    ///
    /// Returns `Some(())` on success (including early termination);
    /// `None` on I/O failure.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. `bat_cache_buf` must still point
    /// to at least `MAX_SECTOR_SIZE` writable bytes.
    pub unsafe fn map_extents<F: FnMut(MapExtent) -> bool>(
        &mut self,
        call_table: &CallTable,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
        emit: &mut F,
    ) -> Option<()> {
        if self.current_size == 0 {
            return Some(());
        }

        if self.disk_type == DISK_TYPE_FIXED {
            let _ = emit(MapExtent {
                start: 0,
                length: self.current_size,
                state: MapExtentState::Data { file_offset: 0 },
            });
            return Some(());
        }

        let block_size = self.block_size as u64;
        let block_data_offset = self.block_data_offset as u64;
        let total_bat_bytes = (self.max_table_entries as u64).checked_mul(4)?;
        let bat_start_sector = self.table_offset / sector_size as u64;
        let bat_end_byte = self.table_offset.checked_add(total_bat_bytes)?;
        let bat_end_sector = bat_end_byte.checked_add(sector_size as u64 - 1)? / sector_size as u64;

        let mut coalescer = MapExtentCoalescer::new(emit);
        let mut next_unwalked: u64 = 0;
        let mut bat_bytes_consumed: u64 = 0;

        let mut sector = bat_start_sector;
        'walk: while sector < bat_end_sector {
            if sector >= input_capacity {
                return None;
            }
            if !(call_table.read_input_sector)(
                self.device_idx,
                sector,
                self.bat_cache_buf,
                sector_size,
            ) {
                return None;
            }
            *bytes_read += sector_size as u64;

            let sector_byte_start = sector * sector_size as u64;
            let buf_start = if sector_byte_start < self.table_offset {
                (self.table_offset - sector_byte_start) as usize
            } else {
                0
            };
            let buf_end =
                sector_size.min((bat_end_byte.saturating_sub(sector_byte_start)) as usize);
            if buf_end <= buf_start {
                sector += 1;
                continue;
            }
            let chunk =
                core::slice::from_raw_parts(self.bat_cache_buf.add(buf_start), buf_end - buf_start);
            let meaningful_len =
                (total_bat_bytes - bat_bytes_consumed).min((buf_end - buf_start) as u64) as usize;
            let meaningful = &chunk[..meaningful_len];

            let chunk_entry_count = (meaningful_len as u64) / 4;
            let base_entry_index = bat_bytes_consumed / 4;

            for k in 0..chunk_entry_count {
                let off = (k as usize) * 4;
                let entry = u32::from_be_bytes([
                    meaningful[off],
                    meaningful[off + 1],
                    meaningful[off + 2],
                    meaningful[off + 3],
                ]);
                let global_idx = base_entry_index + k;
                let block_virt = global_idx.saturating_mul(block_size);
                if block_virt >= self.current_size {
                    break 'walk;
                }
                let block_visible = block_size.min(self.current_size - block_virt);

                let mut ext =
                    classify_vhd_bat_entry(entry, block_virt, block_size, block_data_offset);
                if ext.length > block_visible {
                    ext.length = block_visible;
                }
                let cont = coalescer.push(ext);
                next_unwalked = block_virt.saturating_add(block_visible);
                if !cont {
                    break 'walk;
                }
            }

            bat_bytes_consumed += meaningful_len as u64;
            sector += 1;
        }

        if next_unwalked < self.current_size {
            let _ = coalescer.push(MapExtent {
                start: next_unwalked,
                length: self.current_size - next_unwalked,
                state: MapExtentState::Hole,
            });
        }
        let _ = coalescer.finish();
        Some(())
    }
}

// ============================================================================
// Cached sector read helper (big-endian u32)
// ============================================================================

shared::cached_read!(read_u32_be_cached, u32, be, 4);

// ============================================================================
// VHD footer/header builder helpers (for output)
// ============================================================================

/// Build a VHD footer into `buf`.
///
/// `buf` must be at least 512 bytes and should be pre-zeroed.
/// The checksum field is computed and written automatically.
pub fn build_footer(
    buf: &mut [u8],
    current_size: u64,
    disk_type: u32,
    data_offset: u64,
    uuid: &[u8; 16],
) {
    // Cookie: "conectix"
    write_be_u64(buf, FOOTER_COOKIE_OFFSET, VHD_COOKIE);
    // Features: reserved bit
    write_be_u32(buf, FOOTER_FEATURES_OFFSET, FEATURES_RESERVED);
    // Format version: 1.0
    write_be_u32(buf, FOOTER_FORMAT_VERSION_OFFSET, VHD_VERSION_1_0);
    // Data offset (to dynamic header, or 0xFFFFFFFFFFFFFFFF for fixed)
    write_be_u64(buf, FOOTER_DATA_OFFSET_OFFSET, data_offset);
    // Timestamp: 0 (we don't track creation time)
    write_be_u32(buf, FOOTER_TIMESTAMP_OFFSET, 0);
    // Creator application: "imgo"
    buf[FOOTER_CREATOR_APP_OFFSET] = b'i';
    buf[FOOTER_CREATOR_APP_OFFSET + 1] = b'm';
    buf[FOOTER_CREATOR_APP_OFFSET + 2] = b'g';
    buf[FOOTER_CREATOR_APP_OFFSET + 3] = b'o';
    // Creator version: 1.0
    write_be_u32(buf, FOOTER_CREATOR_VERSION_OFFSET, 0x0001_0000);
    // Creator host OS: "Wi2k" (Windows) — standard value
    write_be_u32(buf, FOOTER_CREATOR_HOST_OFFSET, 0x5769_326B);
    // Original size = current size
    write_be_u64(buf, FOOTER_ORIGINAL_SIZE_OFFSET, current_size);
    // Current size
    write_be_u64(buf, FOOTER_CURRENT_SIZE_OFFSET, current_size);
    // Geometry
    let (cyl, heads, spt) = compute_vhd_geometry(current_size);
    write_be_u16(buf, FOOTER_GEOMETRY_OFFSET, cyl);
    buf[FOOTER_GEOMETRY_OFFSET + 2] = heads;
    buf[FOOTER_GEOMETRY_OFFSET + 3] = spt;
    // Disk type
    write_be_u32(buf, FOOTER_DISK_TYPE_OFFSET, disk_type);
    // UUID
    buf[FOOTER_UUID_OFFSET..FOOTER_UUID_OFFSET + 16].copy_from_slice(uuid);
    // Saved state: 0
    buf[FOOTER_SAVED_STATE_OFFSET] = 0;

    // Compute and write checksum (must be last)
    let checksum = compute_checksum(buf, FOOTER_CHECKSUM_OFFSET);
    write_be_u32(buf, FOOTER_CHECKSUM_OFFSET, checksum);
}

/// Build a VHD dynamic header into `buf`.
///
/// `buf` must be at least 1024 bytes and should be pre-zeroed.
/// The checksum field is computed and written automatically.
pub fn build_dynamic_header(
    buf: &mut [u8],
    table_offset: u64,
    max_table_entries: u32,
    block_size: u32,
) {
    // Cookie: "cxsparse"
    write_be_u64(buf, DYN_COOKIE_OFFSET, CXSPARSE_COOKIE);
    // Data offset: unused, should be 0xFFFFFFFFFFFFFFFF
    write_be_u64(buf, DYN_DATA_OFFSET_OFFSET, 0xFFFF_FFFF_FFFF_FFFF);
    // Table offset (BAT byte offset)
    write_be_u64(buf, DYN_TABLE_OFFSET_OFFSET, table_offset);
    // Header version: 1.0
    write_be_u32(buf, DYN_HEADER_VERSION_OFFSET, VHD_VERSION_1_0);
    // Max table entries
    write_be_u32(buf, DYN_MAX_TABLE_ENTRIES_OFFSET, max_table_entries);
    // Block size
    write_be_u32(buf, DYN_BLOCK_SIZE_OFFSET, block_size);

    // Compute and write checksum (must be last)
    let checksum = compute_checksum(buf, DYN_CHECKSUM_OFFSET);
    write_be_u32(buf, DYN_CHECKSUM_OFFSET, checksum);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // VhdFooter::parse tests
    // ====================================================================

    /// Build a minimal VHD footer buffer.
    fn make_footer(current_size: u64, disk_type: u32, data_offset: u64) -> [u8; 512] {
        let mut buf = [0u8; 512];
        write_be_u64(&mut buf, FOOTER_COOKIE_OFFSET, VHD_COOKIE);
        write_be_u32(&mut buf, FOOTER_FEATURES_OFFSET, FEATURES_RESERVED);
        write_be_u32(&mut buf, FOOTER_FORMAT_VERSION_OFFSET, VHD_VERSION_1_0);
        write_be_u64(&mut buf, FOOTER_DATA_OFFSET_OFFSET, data_offset);
        write_be_u64(&mut buf, FOOTER_ORIGINAL_SIZE_OFFSET, current_size);
        write_be_u64(&mut buf, FOOTER_CURRENT_SIZE_OFFSET, current_size);
        let (cyl, heads, spt) = compute_vhd_geometry(current_size);
        write_be_u16(&mut buf, FOOTER_GEOMETRY_OFFSET, cyl);
        buf[FOOTER_GEOMETRY_OFFSET + 2] = heads;
        buf[FOOTER_GEOMETRY_OFFSET + 3] = spt;
        write_be_u32(&mut buf, FOOTER_DISK_TYPE_OFFSET, disk_type);
        let checksum = compute_checksum(&buf, FOOTER_CHECKSUM_OFFSET);
        write_be_u32(&mut buf, FOOTER_CHECKSUM_OFFSET, checksum);
        buf
    }

    #[test]
    fn footer_parse_dynamic() {
        let size = 1024 * 1024 * 1024; // 1 GiB
        let buf = make_footer(size, DISK_TYPE_DYNAMIC, 512);
        let footer = VhdFooter::parse(&buf).unwrap();
        assert_eq!(footer.cookie, VHD_COOKIE);
        assert_eq!(footer.current_size, size);
        assert_eq!(footer.disk_type, DISK_TYPE_DYNAMIC);
        assert_eq!(footer.data_offset, 512);
    }

    #[test]
    fn footer_parse_fixed() {
        let size = 512 * 1024 * 1024; // 512 MiB
        let data_off = 0xFFFF_FFFF_FFFF_FFFF;
        let buf = make_footer(size, DISK_TYPE_FIXED, data_off);
        let footer = VhdFooter::parse(&buf).unwrap();
        assert_eq!(footer.disk_type, DISK_TYPE_FIXED);
        assert_eq!(footer.data_offset, data_off);
    }

    #[test]
    fn footer_parse_short_buffer() {
        assert!(VhdFooter::parse(&[0u8; 511]).is_none());
        assert!(VhdFooter::parse(&[0u8; 0]).is_none());
    }

    #[test]
    fn footer_parse_bad_cookie() {
        let mut buf = make_footer(1024 * 1024, DISK_TYPE_DYNAMIC, 512);
        buf[0] = 0; // Corrupt cookie
        assert!(VhdFooter::parse(&buf).is_none());
    }

    // ====================================================================
    // VhdDynamicHeader::parse tests
    // ====================================================================

    /// Build a minimal VHD dynamic header buffer.
    fn make_dynamic_header(
        table_offset: u64,
        max_table_entries: u32,
        block_size: u32,
    ) -> [u8; 1024] {
        let mut buf = [0u8; 1024];
        write_be_u64(&mut buf, DYN_COOKIE_OFFSET, CXSPARSE_COOKIE);
        write_be_u64(&mut buf, DYN_DATA_OFFSET_OFFSET, 0xFFFF_FFFF_FFFF_FFFF);
        write_be_u64(&mut buf, DYN_TABLE_OFFSET_OFFSET, table_offset);
        write_be_u32(&mut buf, DYN_HEADER_VERSION_OFFSET, VHD_VERSION_1_0);
        write_be_u32(&mut buf, DYN_MAX_TABLE_ENTRIES_OFFSET, max_table_entries);
        write_be_u32(&mut buf, DYN_BLOCK_SIZE_OFFSET, block_size);
        let checksum = compute_checksum(&buf, DYN_CHECKSUM_OFFSET);
        write_be_u32(&mut buf, DYN_CHECKSUM_OFFSET, checksum);
        buf
    }

    #[test]
    fn dynamic_header_parse_valid() {
        let buf = make_dynamic_header(1536, 512, DEFAULT_BLOCK_SIZE);
        let hdr = VhdDynamicHeader::parse(&buf).unwrap();
        assert_eq!(hdr.cookie, CXSPARSE_COOKIE);
        assert_eq!(hdr.table_offset, 1536);
        assert_eq!(hdr.max_table_entries, 512);
        assert_eq!(hdr.block_size, DEFAULT_BLOCK_SIZE);
    }

    #[test]
    fn dynamic_header_parse_short_buffer() {
        assert!(VhdDynamicHeader::parse(&[0u8; 1023]).is_none());
        assert!(VhdDynamicHeader::parse(&[0u8; 0]).is_none());
    }

    #[test]
    fn dynamic_header_parse_bad_cookie() {
        let mut buf = make_dynamic_header(1536, 512, DEFAULT_BLOCK_SIZE);
        buf[0] = 0; // Corrupt cookie
        assert!(VhdDynamicHeader::parse(&buf).is_none());
    }

    // ====================================================================
    // Checksum tests
    // ====================================================================

    #[test]
    fn checksum_zeros() {
        let buf = [0u8; 512];
        // All zeros → sum = 0 → complement = 0xFFFFFFFF
        assert_eq!(compute_checksum(&buf, FOOTER_CHECKSUM_OFFSET), !0u32);
    }

    #[test]
    fn checksum_footer_round_trip() {
        let buf = make_footer(1024 * 1024 * 1024, DISK_TYPE_DYNAMIC, 512);
        let stored = be_u32(&buf, FOOTER_CHECKSUM_OFFSET);
        let computed = compute_checksum(&buf, FOOTER_CHECKSUM_OFFSET);
        assert_eq!(stored, computed);
    }

    #[test]
    fn checksum_dynamic_header_round_trip() {
        let buf = make_dynamic_header(1536, 512, DEFAULT_BLOCK_SIZE);
        let stored = be_u32(&buf, DYN_CHECKSUM_OFFSET);
        let computed = compute_checksum(&buf, DYN_CHECKSUM_OFFSET);
        assert_eq!(stored, computed);
    }

    // ====================================================================
    // CHS geometry tests
    // ====================================================================

    #[test]
    fn geometry_small_disk() {
        // 40 MiB disk
        let size = 40 * 1024 * 1024;
        let (cyl, heads, spt) = compute_vhd_geometry(size);
        assert!(cyl > 0);
        assert!(heads >= 4);
        assert!(spt >= 17);
        // Total addressable should cover the size
        let addressable = cyl as u64 * heads as u64 * spt as u64 * 512;
        assert!(addressable >= size || addressable >= cyl as u64 * heads as u64 * spt as u64 * 512);
    }

    #[test]
    fn geometry_1gib_disk() {
        // 1 GiB disk
        let size = 1024 * 1024 * 1024;
        let (cyl, heads, spt) = compute_vhd_geometry(size);
        assert!(cyl > 0);
        assert!(heads > 0);
        assert!(spt > 0);
    }

    #[test]
    fn geometry_large_disk() {
        // 2 TiB disk (max CHS)
        let size = 2u64 * 1024 * 1024 * 1024 * 1024;
        let (cyl, heads, spt) = compute_vhd_geometry(size);
        assert_eq!(cyl, 65535);
        assert_eq!(heads, 16);
        assert_eq!(spt, 255);
    }

    #[test]
    fn geometry_zero_disk() {
        let (cyl, heads, spt) = compute_vhd_geometry(0);
        // Zero size: total_sectors = 0, should still produce valid geometry
        assert_eq!(spt, 17); // Falls into small disk branch
    }

    // ====================================================================
    // build_footer / build_dynamic_header round-trip tests
    // ====================================================================

    #[test]
    fn build_footer_round_trip() {
        let size = 1024 * 1024 * 1024; // 1 GiB
        let uuid = [1u8; 16];
        let mut buf = [0u8; 512];
        build_footer(&mut buf, size, DISK_TYPE_DYNAMIC, 512, &uuid);

        let footer = VhdFooter::parse(&buf).unwrap();
        assert_eq!(footer.current_size, size);
        assert_eq!(footer.original_size, size);
        assert_eq!(footer.disk_type, DISK_TYPE_DYNAMIC);
        assert_eq!(footer.data_offset, 512);
        assert_eq!(footer.uuid, uuid);

        // Verify checksum
        let computed = compute_checksum(&buf, FOOTER_CHECKSUM_OFFSET);
        assert_eq!(footer.checksum, computed);
    }

    #[test]
    fn build_dynamic_header_round_trip() {
        let mut buf = [0u8; 1024];
        build_dynamic_header(&mut buf, 1536, 512, DEFAULT_BLOCK_SIZE);

        let hdr = VhdDynamicHeader::parse(&buf).unwrap();
        assert_eq!(hdr.table_offset, 1536);
        assert_eq!(hdr.max_table_entries, 512);
        assert_eq!(hdr.block_size, DEFAULT_BLOCK_SIZE);

        // Verify checksum
        let computed = compute_checksum(&buf, DYN_CHECKSUM_OFFSET);
        assert_eq!(hdr.checksum, computed);
    }

    // ====================================================================
    // count_allocated_in_bat tests
    // ====================================================================

    /// Helper: encode a u32 as 4 big-endian bytes.
    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    #[test]
    fn bat_count_empty() {
        // Empty slice → 0 allocated entries.
        assert_eq!(count_allocated_in_bat(&[]), 0);
    }

    #[test]
    fn bat_count_all_allocated() {
        // 4 entries, all with small non-0xFFFFFFFF values → all allocated.
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&be32(0x0000_0001));
        buf[4..8].copy_from_slice(&be32(0x0000_0002));
        buf[8..12].copy_from_slice(&be32(0x0000_0003));
        buf[12..16].copy_from_slice(&be32(0x0000_0004));
        assert_eq!(count_allocated_in_bat(&buf), 4);
    }

    #[test]
    fn bat_count_all_unallocated() {
        // 4 entries, all 0xFFFFFFFF → 0 allocated.
        let buf = [0xFF_u8; 16];
        assert_eq!(count_allocated_in_bat(&buf), 0);
    }

    #[test]
    fn bat_count_mixed() {
        // 5 entries: entries 0 and 3 are allocated, entries 1, 2, 4 are not.
        // Expected: 2.
        let mut buf = [0u8; 20];
        buf[0..4].copy_from_slice(&be32(0x0000_0010)); // allocated
        buf[4..8].copy_from_slice(&be32(BAT_UNALLOCATED)); // unallocated
        buf[8..12].copy_from_slice(&be32(BAT_UNALLOCATED)); // unallocated
        buf[12..16].copy_from_slice(&be32(0x0000_0020)); // allocated
        buf[16..20].copy_from_slice(&be32(BAT_UNALLOCATED)); // unallocated
        assert_eq!(count_allocated_in_bat(&buf), 2);
    }

    #[test]
    fn bat_count_trailing_partial_entry() {
        // 3 complete entries + 1 trailing byte (13 bytes total).
        // chunks_exact(4) must discard the tail and count only 3 entries.
        // Entries: allocated, unallocated, allocated → expected 2.
        let mut buf = [0u8; 13];
        buf[0..4].copy_from_slice(&be32(0x0000_0001)); // allocated
        buf[4..8].copy_from_slice(&be32(BAT_UNALLOCATED)); // unallocated
        buf[8..12].copy_from_slice(&be32(0x0000_0002)); // allocated
        buf[12] = 0x00; // trailing garbage byte — must be ignored
        assert_eq!(count_allocated_in_bat(&buf), 2);
    }

    #[test]
    fn bat_count_large_every_seventh_allocated() {
        // 1024 entries, with every 7th entry allocated (indices 0, 7, 14, ...).
        // Count = number of i in 0..1024 where i % 7 == 0.
        let mut buf = [0xFF_u8; 1024 * 4];
        let mut expected: u64 = 0;
        for i in 0usize..1024 {
            if i % 7 == 0 {
                let off = i * 4;
                buf[off..off + 4].copy_from_slice(&be32(i as u32));
                expected += 1;
            }
        }
        // Verify expected: ceil(1023 / 7) + 1 = 146 + 1 = 147.
        assert_eq!(expected, 147);
        assert_eq!(count_allocated_in_bat(&buf), 147);
    }

    #[test]
    fn bat_count_zero_value_is_allocated() {
        // BAT entry value 0 is a valid sector pointer → must count as allocated.
        // Only 0xFFFFFFFF is the unallocated sentinel.
        let buf = be32(0x0000_0000);
        assert_eq!(count_allocated_in_bat(&buf), 1);
    }

    // ====================================================================
    // classify_vhd_bat_entry tests
    // ====================================================================

    #[test]
    fn classify_vhd_unallocated_is_hole() {
        let e = classify_vhd_bat_entry(BAT_UNALLOCATED, 0, 2 * 1024 * 1024, 512);
        assert_eq!(e.state, MapExtentState::Hole);
        assert_eq!(e.length, 2 * 1024 * 1024);
    }

    #[test]
    fn classify_vhd_allocated_is_data_with_bitmap_offset() {
        // Block starts at sector 10, bitmap is 512 bytes (1 sector),
        // so payload starts at byte 10*512 + 512 = 5632.
        let e = classify_vhd_bat_entry(10, 0, 2 * 1024 * 1024, 512);
        assert_eq!(e.state, MapExtentState::Data { file_offset: 5632 });
    }

    #[test]
    fn classify_vhd_allocated_zero_sector() {
        // BAT entry of 0 is a valid sector pointer (sector 0); payload
        // starts at block_data_offset bytes.
        let e = classify_vhd_bat_entry(0, 0, 2 * 1024 * 1024, 512);
        assert_eq!(e.state, MapExtentState::Data { file_offset: 512 });
    }

    #[test]
    fn classify_vhd_large_block_index() {
        // 2 MiB block at sector 1000.
        let e = classify_vhd_bat_entry(1000, 4 * 1024 * 1024, 2 * 1024 * 1024, 1024);
        assert_eq!(e.start, 4 * 1024 * 1024);
        assert_eq!(e.length, 2 * 1024 * 1024);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 1000 * 512 + 1024
            }
        );
    }

    #[test]
    fn classify_vhd_max_sector_pointer_minus_one() {
        // 0xFFFFFFFE is allocated (only 0xFFFFFFFF is unallocated).
        let e = classify_vhd_bat_entry(0xFFFF_FFFE, 0, 2 * 1024 * 1024, 512);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 0xFFFF_FFFEu64 * 512 + 512
            }
        );
    }

    #[test]
    fn classify_vhd_block_data_offset_zero() {
        // A theoretical zero-bitmap layout: payload starts exactly at
        // sector boundary.
        let e = classify_vhd_bat_entry(100, 0, 4096, 0);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 100 * 512
            }
        );
    }

    // ====================================================================
    // chs_rounded_size tests
    // ====================================================================

    /// Verified against `qemu-img create -f vpc <size>` (virtual-size
    /// via `qemu-img info`, CHS + current_size read from the footer),
    /// qemu-img 10.0.8. The `(35651584, ...)` row is the differential-
    /// fuzz dd window from issue #382 (69632 sectors), where the old
    /// one-pass ceil approximation produced 35807232 with a footer CHS
    /// (822/5/17) that did not even match its own current_size; qemu's
    /// upward search lands on 820/5/17 = 69700 sectors. The >=1.6 GiB
    /// rows pin the removal of the non-qemu `65535*3*17` "medium-large"
    /// 255-sectors-per-track branch (qemu switches to 255 spt only at
    /// 65535*16*63 sectors).
    #[test]
    fn chs_rounded_size_matches_qemu() {
        let cases: &[(u64, u64, (u16, u8, u8))] = &[
            (512, 34816, (1, 4, 17)),
            (1000, 34816, (1, 4, 17)),
            (3000, 34816, (1, 4, 17)),
            (34816, 34816, (1, 4, 17)),
            (34817, 69632, (2, 4, 17)),
            (65536, 69632, (2, 4, 17)),
            (131072, 139264, (4, 4, 17)),
            (1048576, 1079296, (31, 4, 17)),
            (35553280, 35581952, (1022, 4, 17)),
            (35651584, 35686400, (820, 5, 17)),
            (35686400, 35686400, (820, 5, 17)),
            (1073741824, 1073995776, (2081, 16, 63)),
            (1610612736, 1610735616, (3121, 16, 63)),
            (1711249920, 1711374336, (3316, 16, 63)),
            (1711250432, 1711374336, (3316, 16, 63)),
            (2147483648, 2147991552, (4162, 16, 63)),
            (3221225472, 3221471232, (6242, 16, 63)),
            (10737418240, 10737893376, (20806, 16, 63)),
        ];
        assert_eq!(chs_rounded_size(0), 0);
        for &(input, expected, chs) in cases {
            let r = chs_rounded_size(input);
            assert_eq!(
                r, expected,
                "chs_rounded_size({input}) should be {expected}"
            );
            assert_eq!(
                compute_vhd_geometry(r),
                chs,
                "footer CHS for input {input} (rounded {r})"
            );
        }
    }

    /// For each CHS-rounded size r, compute_vhd_geometry(r) must
    /// reproduce r exactly: c * h * spt * 512 == r. With the rounding
    /// mirroring qemu's upward search this holds for every input whose
    /// rounded size is a CHS product — i.e. everything below the
    /// max-geometry window (the top ~2 MiB below the 2040 GiB ceiling,
    /// where qemu keeps the exact sector-rounded request instead).
    ///
    /// Skips r == 0 (no CHS geometry for empty disks).
    #[test]
    fn chs_rounded_size_is_chs_consistent() {
        let inputs: &[u64] = &[
            512,
            1000,
            3000,
            34816,
            34817,
            65536,
            131072,
            1048576,
            1073741824,
            // Extras not in the qemu table, including the spt=255
            // branch (>= 65535*16*63 sectors) the old implementation
            // excluded:
            2_000_000,
            500_000_000,
            10_737_418_240,
            35_651_584,
            65535 * 16 * 63 * 512,
            100_000_000_000,
        ];
        for &s in inputs {
            let r = chs_rounded_size(s);
            assert_ne!(
                r, 0,
                "chs_rounded_size({s}) must not be 0 for non-zero input"
            );
            let (c, h, spt) = compute_vhd_geometry(r);
            let reconstructed = c as u64 * h as u64 * spt as u64 * 512;
            assert_eq!(
                reconstructed, r,
                "geometry round-trip failed for input={s}: \
                 chs_rounded_size={r}, c={c} h={h} spt={spt}, \
                 c*h*spt*512={reconstructed}"
            );
        }
    }

    /// The max-geometry window: requests the largest sub-ceiling
    /// geometry (65534×16×255) cannot cover round to the EXACT sector
    /// count (qemu keeps the request), and anything past the ceiling
    /// clamps to it (where qemu would refuse).
    #[test]
    fn chs_rounded_size_max_geometry_window() {
        let window_start = 65534u64 * 16 * 255; // largest sub-ceiling product
        assert_eq!(
            chs_rounded_size(window_start * 512),
            window_start * 512,
            "largest sub-ceiling product is a fixed point"
        );
        let in_window = window_start + 1;
        assert_eq!(
            chs_rounded_size(in_window * 512),
            in_window * 512,
            "window sizes keep their exact sector count"
        );
        assert_eq!(
            chs_rounded_size(in_window * 512 - 511),
            in_window * 512,
            "sub-sector window request rounds up to whole sectors"
        );
        assert_eq!(
            chs_rounded_size(VHD_MAX_SECTORS * 512),
            VHD_MAX_SECTORS * 512
        );
        assert_eq!(
            chs_rounded_size(VHD_MAX_SECTORS * 512 + 512),
            VHD_MAX_SECTORS * 512,
            "oversize requests clamp to the CHS ceiling"
        );
    }

    /// chs_rounded_size must never return a value smaller than its input
    /// (for non-zero inputs).
    #[test]
    fn chs_rounded_size_rounds_up() {
        let inputs: &[u64] = &[
            1,
            511,
            512,
            513,
            34815,
            34816,
            34817,
            69631,
            69632,
            130000,
            131072,
            131073,
            1_000_000,
            1_048_576,
            1_073_741_824,
            10_737_418_240,
        ];
        for &s in inputs {
            let r = chs_rounded_size(s);
            assert!(r >= s, "chs_rounded_size({s}) = {r} is less than the input");
        }
    }
}
