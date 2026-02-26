//! Shared QCOW2 format parsing for bare-metal guest operations.
//!
//! This crate provides the canonical implementation of QCOW2 header parsing,
//! L1/L2 cluster lookup, refcount table reading, and compressed cluster
//! decompression. All guest operations (info, check, compare, convert)
//! depend on this crate rather than maintaining their own copies.
//!
//! All code is `no_std` compatible for bare-metal KVM guest execution.

#![no_std]
// Guest crate I/O uses function pointers (no closures/trait objects in
// no_std), so cached-read helpers inherently need many parameters.
#![allow(clippy::too_many_arguments)]

#[cfg(feature = "decompress-zstd")]
extern crate alloc;

#[cfg(any(
    feature = "decompress",
    feature = "decompress-zstd",
    feature = "vmdk-decompress"
))]
use shared::COMPRESSED_BUF_SIZE;
use shared::{
    l1_cache_addr, l2_cache_addr, BackingFormat, CallTable, ChainConfig, ImageFormat,
    MAX_CHAIN_DEVICES, MAX_CLUSTER_SIZE, MAX_SECTOR_SIZE,
};
#[cfg(feature = "vmdk-input")]
use vmdk::{GrainLookup, VmdkState};

// ============================================================================
// QCOW2 Header Constants
// ============================================================================

// Header field offsets (all values are big-endian in the on-disk format)
pub const VERSION_OFFSET: usize = 4;
pub const BACKING_FILE_OFFSET_OFFSET: usize = 8;
pub const BACKING_FILE_SIZE_OFFSET: usize = 16;
pub const CLUSTER_BITS_OFFSET: usize = 20;
pub const SIZE_OFFSET: usize = 24;
pub const CRYPT_METHOD_OFFSET: usize = 32;
pub const L1_SIZE_OFFSET: usize = 36;
pub const L1_TABLE_OFFSET_OFFSET: usize = 40;
pub const REFCOUNT_TABLE_OFFSET_OFFSET: usize = 48;
pub const REFCOUNT_TABLE_CLUSTERS_OFFSET: usize = 56;
pub const INCOMPATIBLE_FEATURES_OFFSET: usize = 72;
pub const COMPATIBLE_FEATURES_OFFSET: usize = 80;
pub const REFCOUNT_ORDER_OFFSET: usize = 96;
pub const HEADER_LENGTH_OFFSET: usize = 100;
pub const COMPRESSION_TYPE_OFFSET: usize = 104;

// Header extension type IDs
pub const EXT_BACKING_FORMAT: u32 = 0xE2792ACA;
pub const EXT_END: u32 = 0x00000000;
/// Start of header extensions in v2 (fixed 72-byte header)
pub const V2_HEADER_EXTENSION_OFFSET: usize = 72;

// Incompatible feature bits
pub const INCOMPAT_DIRTY: u64 = 1 << 0;
pub const INCOMPAT_CORRUPT: u64 = 1 << 1;
pub const INCOMPAT_EXTERNAL_DATA: u64 = 1 << 2;
pub const INCOMPAT_COMPRESSION: u64 = 1 << 3;
pub const INCOMPAT_EXTENDED_L2: u64 = 1 << 4;

// Compatible feature bits
pub const COMPAT_LAZY_REFCOUNTS: u64 = 1 << 0;

/// Bitmask of incompatible features that this implementation supports.
///
/// Operations should reject images with unsupported incompatible features
/// (per the QCOW2 spec, unknown incompatible bits MUST cause rejection).
///
/// - Bit 0 (dirty): handled (informational, data still readable)
/// - Bit 1 (corrupt): handled (informational, data still readable)
/// - Bit 2 (external_data): NOT supported (data in separate file)
/// - Bit 3 (compression): conditionally supported (see below)
/// - Bit 4 (extended_l2): supported (16-byte L2 entries; subcluster
///   bitmap is ignored, treating the cluster as fully allocated)
///
/// When the `decompress-zstd` feature is enabled, bit 3 is included
/// because ZSTD decompression is available. Otherwise only zlib
/// (compression_type=0) works, and bit 3 is not needed since zlib
/// images don't set it.
#[cfg(not(feature = "decompress-zstd"))]
pub const SUPPORTED_INCOMPAT_FEATURES: u64 =
    INCOMPAT_DIRTY | INCOMPAT_CORRUPT | INCOMPAT_EXTENDED_L2;

#[cfg(feature = "decompress-zstd")]
pub const SUPPORTED_INCOMPAT_FEATURES: u64 =
    INCOMPAT_DIRTY | INCOMPAT_CORRUPT | INCOMPAT_COMPRESSION | INCOMPAT_EXTENDED_L2;

// L1/L2 entry masks and flags
/// Bit 62 set indicates a compressed cluster in an L2 entry
pub const OFLAG_COMPRESSED: u64 = 1 << 62;
/// Mask for extracting offset from L1/L2 entries (bits 9-55)
pub const L1_OFFSET_MASK: u64 = 0x00fffffffffffe00;
/// Mask for extracting offset from L2 entries (bits 9-55)
pub const L2_OFFSET_MASK: u64 = 0x00fffffffffffe00;

// ============================================================================
// QCOW2 construction constants (for writing new images)
// ============================================================================

/// QCOW2 magic number (big-endian on disk: 0x51 0x46 0x49 0xfb)
pub const QCOW2_MAGIC: u32 = 0x514649fb;
/// QCOW2 version 3
pub const QCOW2_VERSION_3: u32 = 3;
/// V3 header length in bytes
pub const QCOW2_HEADER_LENGTH_V3: u32 = 104;
/// Default refcount order (4 = 16-bit refcounts)
pub const QCOW2_DEFAULT_REFCOUNT_ORDER: u32 = 4;

/// Offset of nb_snapshots field in the header
pub const NB_SNAPSHOTS_OFFSET: usize = 60;
/// Offset of snapshots_offset field in the header
pub const SNAPSHOTS_OFFSET_OFFSET: usize = 64;
/// Offset of autoclear_features field in the v3 header
pub const AUTOCLEAR_FEATURES_OFFSET: usize = 88;

// ============================================================================
// Byte-order helpers
// ============================================================================

/// Read a big-endian u32 from a byte slice at the given offset.
#[inline]
pub fn be_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read a big-endian u64 from a byte slice at the given offset.
#[inline]
pub fn be_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Write a big-endian u16 to a byte slice at the given offset.
#[inline]
pub fn write_be_u16(buf: &mut [u8], off: usize, val: u16) {
    let bytes = val.to_be_bytes();
    buf[off..off + 2].copy_from_slice(&bytes);
}

/// Write a big-endian u32 to a byte slice at the given offset.
#[inline]
pub fn write_be_u32(buf: &mut [u8], off: usize, val: u32) {
    let bytes = val.to_be_bytes();
    buf[off..off + 4].copy_from_slice(&bytes);
}

/// Write a big-endian u64 to a byte slice at the given offset.
#[inline]
pub fn write_be_u64(buf: &mut [u8], off: usize, val: u64) {
    let bytes = val.to_be_bytes();
    buf[off..off + 8].copy_from_slice(&bytes);
}

// ============================================================================
// Compression support (writing compressed QCOW2 clusters)
// ============================================================================

/// Encode a compressed L2 entry for a compressed cluster.
///
/// The entry encodes the byte offset and the number of 512-byte
/// sectors occupied by the compressed data, using the QCOW2
/// compressed cluster format:
///   - Bit 62: OFLAG_COMPRESSED
///   - Bits (62-(cluster_bits-8)) to 61: nb_sectors - 1
///   - Bits 0 to (62-(cluster_bits-8)-1): host byte offset
pub fn encode_compressed_l2_entry(
    host_offset: u64,
    compressed_bytes: u64,
    cluster_bits: u32,
) -> u64 {
    let csize_shift = 62 - (cluster_bits as u64 - 8);
    let offset_mask = (1u64 << csize_shift) - 1;
    let nb_sectors = (compressed_bytes + 511) / 512;
    OFLAG_COMPRESSED | ((nb_sectors - 1) << csize_shift) | (host_offset & offset_mask)
}

/// Size in bytes of the compressor state (CompressorOxide).
///
/// Callers must provide at least this many bytes of scratch memory
/// to [`compress_cluster_zlib`]. The compressor is too large for the
/// guest stack (~200KB), so it must be placed in scratch memory.
#[cfg(feature = "compress")]
pub const COMPRESSOR_STATE_SIZE: usize = {
    // CompressorOxide contains large hash tables and buffers.
    // We compute the size at compile time.
    core::mem::size_of::<miniz_oxide::deflate::core::CompressorOxide>()
};

/// Compress a cluster using zlib (deflate with zlib header).
///
/// Compresses `input_len` bytes from `input` into `output`, which
/// must have capacity for at least `output_capacity` bytes.
///
/// `compressor_mem` must point to at least [`COMPRESSOR_STATE_SIZE`]
/// bytes of writable memory (scratch memory, NOT the stack).
///
/// Returns the number of compressed bytes produced, or 0 on failure
/// or if the compressed output would not be smaller than the input.
///
/// # Safety
///
/// `input` must point to at least `input_len` readable bytes.
/// `output` must point to at least `output_capacity` writable bytes.
/// `compressor_mem` must point to at least `COMPRESSOR_STATE_SIZE`
/// writable bytes aligned to 8.
#[cfg(feature = "compress")]
pub unsafe fn compress_cluster_zlib(
    compressor_mem: *mut u8,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_capacity: usize,
) -> usize {
    use miniz_oxide::deflate::core::{
        compress, create_comp_flags_from_zip_params, CompressorOxide, TDEFLFlush, TDEFLStatus,
    };

    let in_slice = core::slice::from_raw_parts(input, input_len);
    let out_slice = core::slice::from_raw_parts_mut(output, output_capacity);

    // Compression level 6 (default, same as qemu-img), raw deflate.
    // QCOW2 compression type 0 ("zlib") is actually raw deflate
    // without a zlib wrapper header. qemu uses inflateInit2(-12)
    // for decompression, so we must NOT write the zlib header.
    // window_bits <= 0 omits the header.
    let flags = create_comp_flags_from_zip_params(6, -15, 0);

    // Initialize CompressorOxide at the provided scratch address.
    // This avoids placing it on the stack (it's ~200KB, guest
    // stack is only 64KB). With LTO the compiler should construct
    // directly at the target address via return-value optimization.
    let compressor = compressor_mem as *mut CompressorOxide;
    core::ptr::write(compressor, CompressorOxide::new(flags));

    let (status, _in_consumed, out_produced) =
        compress(&mut *compressor, in_slice, out_slice, TDEFLFlush::Finish);

    if status != TDEFLStatus::Done {
        return 0;
    }

    // Don't use compressed form if it's not smaller
    if out_produced >= input_len {
        return 0;
    }

    out_produced
}

/// Compress data with raw DEFLATE, always returning the compressed
/// size. Unlike `compress_cluster_zlib`, this returns the compressed
/// output even if it is larger than the input. Returns 0 only on
/// actual compression error.
///
/// Used by VMDK streamOptimized output where all non-zero grains
/// must be stored as compressed data with a grain marker.
///
/// # Safety
/// Same requirements as `compress_cluster_zlib`.
#[cfg(feature = "compress")]
pub unsafe fn compress_deflate_raw(
    compressor_mem: *mut u8,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_capacity: usize,
) -> usize {
    use miniz_oxide::deflate::core::{
        compress, create_comp_flags_from_zip_params, CompressorOxide, TDEFLFlush, TDEFLStatus,
    };

    let in_slice = core::slice::from_raw_parts(input, input_len);
    let out_slice = core::slice::from_raw_parts_mut(output, output_capacity);

    let flags = create_comp_flags_from_zip_params(6, -15, 0);
    let compressor = compressor_mem as *mut CompressorOxide;
    core::ptr::write(compressor, CompressorOxide::new(flags));

    let (status, _in_consumed, out_produced) =
        compress(&mut *compressor, in_slice, out_slice, TDEFLFlush::Finish);

    if status != TDEFLStatus::Done {
        return 0;
    }

    out_produced
}

// ============================================================================
// Parsed QCOW2 Header
// ============================================================================

/// Parsed QCOW2 header fields.
///
/// Created by [`QcowHeader::parse()`] from the raw bytes of the first sector.
/// Contains all header fields that any operation might need. Individual
/// operations pick the fields they require.
pub struct QcowHeader {
    pub version: u32,
    pub cluster_bits: u32,
    pub cluster_size: u64,
    pub virtual_size: u64,
    pub l1_size: u32,
    pub l1_table_offset: u64,
    pub backing_file_offset: u64,
    pub backing_file_size: u32,
    pub crypt_method: u32,
    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,
    /// Derived from `refcount_order`: `1 << refcount_order` for valid values
    /// (0..=6), or 16 as a fallback for invalid values (>6). For v2 headers,
    /// this is always 16. Note: invalid `refcount_order` values silently fall
    /// back to 16-bit refcounts. Callers that need to detect invalid
    /// `refcount_order` should re-check the raw header bytes.
    pub refcount_bits: u32,
    pub incompatible_features: u64,
    pub compatible_features: u64,
    pub compression_type: u8,
    // Derived flags
    pub dirty: bool,
    pub corrupt: bool,
    pub has_external_data: bool,
    pub extended_l2: bool,
    pub lazy_refcounts: bool,
}

impl QcowHeader {
    /// Parse a QCOW2 header from raw bytes.
    ///
    /// `header` must contain at least the first sector of the image
    /// (minimum 512 bytes). Returns `None` if the buffer is too small
    /// or the version/cluster_bits are out of range.
    ///
    /// This function performs no I/O - it only reads from the provided
    /// byte slice. Multi-sector operations like backing file path
    /// extraction and header extension parsing are separate functions.
    pub fn parse(header: &[u8]) -> Option<Self> {
        // Minimum header size: need at least through compression_type (offset 104+1)
        if header.len() < 105 {
            return None;
        }

        let version = be_u32(header, VERSION_OFFSET);
        if version != 2 && version != 3 {
            return None;
        }

        let cluster_bits = be_u32(header, CLUSTER_BITS_OFFSET);
        if !(9..=21).contains(&cluster_bits) {
            return None;
        }
        let cluster_size = 1u64 << cluster_bits;

        let virtual_size = be_u64(header, SIZE_OFFSET);
        let l1_size = be_u32(header, L1_SIZE_OFFSET);
        let l1_table_offset = be_u64(header, L1_TABLE_OFFSET_OFFSET);
        let backing_file_offset = be_u64(header, BACKING_FILE_OFFSET_OFFSET);
        let backing_file_size = be_u32(header, BACKING_FILE_SIZE_OFFSET);
        let crypt_method = be_u32(header, CRYPT_METHOD_OFFSET);
        let refcount_table_offset = be_u64(header, REFCOUNT_TABLE_OFFSET_OFFSET);
        let refcount_table_clusters = be_u32(header, REFCOUNT_TABLE_CLUSTERS_OFFSET);

        // v3 specific fields
        let (refcount_bits, incompatible_features, compatible_features, compression_type) =
            if version >= 3 {
                let refcount_order = be_u32(header, REFCOUNT_ORDER_OFFSET);
                let rb = if refcount_order <= 6 {
                    1u32 << refcount_order
                } else {
                    16 // Fallback for invalid order
                };
                let incompat = be_u64(header, INCOMPATIBLE_FEATURES_OFFSET);
                let compat = be_u64(header, COMPATIBLE_FEATURES_OFFSET);
                let ct = header[COMPRESSION_TYPE_OFFSET];
                (rb, incompat, compat, ct)
            } else {
                (16, 0, 0, 0)
            };

        Some(QcowHeader {
            version,
            cluster_bits,
            cluster_size,
            virtual_size,
            l1_size,
            l1_table_offset,
            backing_file_offset,
            backing_file_size,
            crypt_method,
            refcount_table_offset,
            refcount_table_clusters,
            refcount_bits,
            incompatible_features,
            compatible_features,
            compression_type,
            dirty: (incompatible_features & INCOMPAT_DIRTY) != 0,
            corrupt: (incompatible_features & INCOMPAT_CORRUPT) != 0,
            has_external_data: (incompatible_features & INCOMPAT_EXTERNAL_DATA) != 0,
            extended_l2: (incompatible_features & INCOMPAT_EXTENDED_L2) != 0,
            lazy_refcounts: (compatible_features & COMPAT_LAZY_REFCOUNTS) != 0,
        })
    }

    /// Calculate qemu-style actual disk size (highest metadata offset
    /// rounded up to 512-byte sector boundary).
    ///
    /// Uses saturating arithmetic because both `l1_table_offset` and
    /// `l1_size` come from the untrusted on-disk header.
    pub fn qemu_disk_size(&self) -> u64 {
        let l1_table_end = self
            .l1_table_offset
            .saturating_add((self.l1_size as u64).saturating_mul(8));
        ((l1_table_end.saturating_add(511)) / 512).saturating_mul(512)
    }

    /// Get compat string: "0.10" for v2, "1.1" for v3+.
    pub fn compat_str(&self) -> &'static str {
        if self.version >= 3 {
            "1.1"
        } else {
            "0.10"
        }
    }

    /// Get compat numeric value: 0 for v2, 1 for v3+.
    pub fn compat_value(&self) -> u8 {
        if self.version >= 3 {
            1
        } else {
            0
        }
    }
}

/// Parse QCOW2 header extensions from a header buffer.
///
/// Looks for the backing format extension (`EXT_BACKING_FORMAT`) and
/// returns it. Only applicable to v3+ headers (v2 has no extensions
/// at the standard offsets).
///
/// `header` is the same buffer passed to `QcowHeader::parse()`.
/// `parsed` is the parsed header (needed for version check).
pub fn parse_header_extensions(header: &[u8], parsed: &QcowHeader) -> BackingFormat {
    if parsed.version < 3 {
        return BackingFormat::None;
    }
    if header.len() < HEADER_LENGTH_OFFSET + 4 {
        return BackingFormat::None;
    }

    let header_length = be_u32(header, HEADER_LENGTH_OFFSET) as usize;
    let mut ext_offset = header_length;

    while ext_offset + 8 <= header.len() {
        let ext_type = be_u32(header, ext_offset);
        let ext_len = be_u32(header, ext_offset + 4) as usize;

        if ext_type == EXT_END {
            break;
        }

        if ext_offset + 8 + ext_len > header.len() {
            break;
        }

        if ext_type == EXT_BACKING_FORMAT && ext_len > 0 {
            let format_bytes = &header[ext_offset + 8..ext_offset + 8 + ext_len];
            return BackingFormat::from_bytes(format_bytes);
        }

        // Move to next extension (data padded to 8-byte boundary)
        let padded_len = (ext_len + 7) & !7;
        ext_offset += 8 + padded_len;
    }

    BackingFormat::None
}

/// Read the backing file path from a QCOW2 image.
///
/// Uses the `backing_file_offset` and `backing_file_size` from the
/// parsed header to read the path string from the image. Handles
/// multi-sector spanning.
///
/// # Safety
///
/// `call_table` must point to a valid initialized call table.
/// `out_buf` must be at least `max_len + 1` bytes.
pub unsafe fn read_backing_file(
    call_table: &CallTable,
    device_idx: u32,
    header: &QcowHeader,
    out_buf: &mut [u8],
    sector_size: usize,
    input_capacity: u64,
) -> usize {
    if header.backing_file_offset == 0 || header.backing_file_size == 0 {
        return 0;
    }

    let max_len = out_buf.len().saturating_sub(1); // Reserve space for null
    let read_size = core::cmp::min(header.backing_file_size as usize, max_len);

    let backing_sector = header.backing_file_offset / sector_size as u64;
    let offset_in_sector = (header.backing_file_offset % sector_size as u64) as usize;

    // Validate backing sector is within device bounds
    if backing_sector >= input_capacity {
        return 0;
    }

    let mut sector_buf = [0u8; MAX_SECTOR_SIZE];

    if !(call_table.read_input_sector)(
        device_idx,
        backing_sector,
        sector_buf.as_mut_ptr(),
        sector_size,
    ) {
        return 0;
    }

    let bytes_in_first_sector = core::cmp::min(read_size, sector_size - offset_in_sector);
    out_buf[..bytes_in_first_sector]
        .copy_from_slice(&sector_buf[offset_in_sector..offset_in_sector + bytes_in_first_sector]);

    let mut bytes_read = bytes_in_first_sector;
    let mut current_sector = backing_sector + 1;

    while bytes_read < read_size {
        if current_sector >= input_capacity {
            break;
        }
        if !(call_table.read_input_sector)(
            device_idx,
            current_sector,
            sector_buf.as_mut_ptr(),
            sector_size,
        ) {
            break;
        }
        let bytes_to_copy = core::cmp::min(read_size - bytes_read, sector_size);
        out_buf[bytes_read..bytes_read + bytes_to_copy]
            .copy_from_slice(&sector_buf[..bytes_to_copy]);
        bytes_read += bytes_to_copy;
        current_sector += 1;
    }

    // Null terminate
    out_buf[bytes_read] = 0;
    bytes_read
}

// ============================================================================
// Sector-cached I/O helpers
// ============================================================================

/// Read a big-endian u64 from a specific byte offset within a device,
/// using a one-sector cache to minimize I/O.
///
/// # Safety
///
/// `cache_buf` must point to at least `MAX_SECTOR_SIZE` writable bytes.
/// `call_table` must point to a valid initialized call table.
pub unsafe fn read_u64_be_cached(
    call_table: &CallTable,
    device_idx: u32,
    byte_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    cached_sector: &mut u64,
    cache_buf: *mut u8,
    bytes_read: &mut u64,
) -> Option<u64> {
    let sector = byte_offset / sector_size as u64;
    let off = (byte_offset % sector_size as u64) as usize;
    if off + 8 > sector_size {
        return None; // Entry spans sector boundary
    }
    if sector >= input_capacity {
        return None;
    }
    if *cached_sector != sector {
        if !(call_table.read_input_sector)(device_idx, sector, cache_buf, sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;
        *cached_sector = sector;
    }
    let p = cache_buf.add(off);
    Some(u64::from_be_bytes([
        *p,
        *p.add(1),
        *p.add(2),
        *p.add(3),
        *p.add(4),
        *p.add(5),
        *p.add(6),
        *p.add(7),
    ]))
}

/// Read a big-endian u32 from a specific byte offset within a device,
/// using a one-sector cache to minimize I/O.
///
/// # Safety
///
/// `cache_buf` must point to at least `MAX_SECTOR_SIZE` writable bytes.
/// `call_table` must point to a valid initialized call table.
pub unsafe fn read_u32_be_cached(
    call_table: &CallTable,
    device_idx: u32,
    byte_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    cached_sector: &mut u64,
    cache_buf: *mut u8,
    bytes_read: &mut u64,
) -> Option<u32> {
    let sector = byte_offset / sector_size as u64;
    let off = (byte_offset % sector_size as u64) as usize;
    if off + 4 > sector_size {
        return None;
    }
    if sector >= input_capacity {
        return None;
    }
    if *cached_sector != sector {
        if !(call_table.read_input_sector)(device_idx, sector, cache_buf, sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;
        *cached_sector = sector;
    }
    let p = cache_buf.add(off);
    Some(u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]))
}

/// Read a single byte from a specific byte offset within a device,
/// using a one-sector cache to minimize I/O.
///
/// Used for sub-byte and 8-bit refcount entry reading.
///
/// # Safety
///
/// `cache_buf` must point to at least `MAX_SECTOR_SIZE` writable bytes.
/// `call_table` must point to a valid initialized call table.
pub unsafe fn read_u8_cached(
    call_table: &CallTable,
    device_idx: u32,
    byte_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    cached_sector: &mut u64,
    cache_buf: *mut u8,
    bytes_read: &mut u64,
) -> Option<u8> {
    let sector = byte_offset / sector_size as u64;
    let off = (byte_offset % sector_size as u64) as usize;
    if off + 1 > sector_size {
        return None;
    }
    if sector >= input_capacity {
        return None;
    }
    if *cached_sector != sector {
        if !(call_table.read_input_sector)(device_idx, sector, cache_buf, sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;
        *cached_sector = sector;
    }
    Some(*cache_buf.add(off))
}

/// Read a big-endian u16 from a specific byte offset within a device,
/// using a one-sector cache to minimize I/O.
///
/// Used primarily for 16-bit refcount entry reading.
///
/// # Safety
///
/// `cache_buf` must point to at least `MAX_SECTOR_SIZE` writable bytes.
/// `call_table` must point to a valid initialized call table.
pub unsafe fn read_u16_be_cached(
    call_table: &CallTable,
    device_idx: u32,
    byte_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    cached_sector: &mut u64,
    cache_buf: *mut u8,
    bytes_read: &mut u64,
) -> Option<u16> {
    let sector = byte_offset / sector_size as u64;
    let off = (byte_offset % sector_size as u64) as usize;
    if off + 2 > sector_size {
        return None;
    }
    if sector >= input_capacity {
        return None;
    }
    if *cached_sector != sector {
        if !(call_table.read_input_sector)(device_idx, sector, cache_buf, sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;
        *cached_sector = sector;
    }
    let p = cache_buf.add(off);
    Some(u16::from_be_bytes([*p, *p.add(1)]))
}

// ============================================================================
// L1/L2 Cluster Lookup
// ============================================================================

/// Result of looking up a virtual offset in QCOW2 L1/L2 tables.
pub enum ClusterLookup {
    /// Cluster is unallocated (reads as zeros, or from backing)
    Unallocated,
    /// Standard cluster at given host byte offset
    Standard(u64),
    /// Compressed cluster: raw L2 entry for offset/size parsing
    Compressed(u64),
}

/// State for reading QCOW2 virtual content from a device.
///
/// Bundles the parsed header fields needed for L1/L2 lookup together
/// with per-device sector caches. Create with [`Qcow2State::init()`].
pub struct Qcow2State {
    pub device_idx: u32,
    pub cluster_size: u64,
    pub cluster_bits: u32,
    pub l1_size: u32,
    pub l1_table_offset: u64,
    /// Raw incompatible_features from the v3 header (0 for v2).
    pub incompatible_features: u64,
    /// Compression type from the v3 header (0=zlib, 1=zstd).
    pub compression_type: u8,
    /// True when INCOMPAT_EXTENDED_L2 (bit 4) is set.
    pub extended_l2: bool,
    // Sector cache tracking for L1 table reads
    pub l1_cached_sector: u64,
    pub l1_cache_buf: *mut u8,
    // Sector cache tracking for L2 table reads
    pub l2_cached_sector: u64,
    pub l2_cache_buf: *mut u8,
}

impl Qcow2State {
    /// Return the bitmask of incompatible features that are set but
    /// not in `supported_mask`. Returns 0 if all set features are
    /// supported.
    pub fn unsupported_incompat_features(&self, supported_mask: u64) -> u64 {
        self.incompatible_features & !supported_mask
    }

    /// Initialize QCOW2 state by reading the header from a device.
    ///
    /// Reads version, cluster_bits, L1 table size/offset, and v3
    /// feature fields from the device header and validates them.
    /// Returns `None` if the header is invalid or I/O fails.
    ///
    /// Rejects clusters larger than `MAX_CLUSTER_SIZE` (2 MiB). Large
    /// clusters are read in `MAX_SECTOR_SIZE`-sized chunks by callers.
    ///
    /// # Safety
    ///
    /// `l1_cache_buf` and `l2_cache_buf` must each point to at least
    /// `MAX_SECTOR_SIZE` writable bytes. `call_table` must be valid.
    pub unsafe fn init(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        l1_cache_buf: *mut u8,
        l2_cache_buf: *mut u8,
        bytes_read: &mut u64,
    ) -> Option<Qcow2State> {
        let mut state = Qcow2State {
            device_idx,
            cluster_size: 0,
            cluster_bits: 0,
            l1_size: 0,
            l1_table_offset: 0,
            incompatible_features: 0,
            compression_type: 0,
            extended_l2: false,
            l1_cached_sector: u64::MAX,
            l1_cache_buf,
            l2_cached_sector: u64::MAX,
            l2_cache_buf,
        };

        // Read version (must be 2 or 3)
        let version = read_u32_be_cached(
            call_table,
            device_idx,
            VERSION_OFFSET as u64,
            sector_size,
            input_capacity,
            &mut state.l1_cached_sector,
            state.l1_cache_buf,
            bytes_read,
        )?;
        if version != 2 && version != 3 {
            return None;
        }

        // Read cluster_bits
        let cluster_bits = read_u32_be_cached(
            call_table,
            device_idx,
            CLUSTER_BITS_OFFSET as u64,
            sector_size,
            input_capacity,
            &mut state.l1_cached_sector,
            state.l1_cache_buf,
            bytes_read,
        )?;
        if !(9..=21).contains(&cluster_bits) {
            return None;
        }
        let cluster_size = 1u64 << cluster_bits;
        // Reject clusters larger than our maximum supported size
        if cluster_size > MAX_CLUSTER_SIZE as u64 {
            return None;
        }
        state.cluster_bits = cluster_bits;
        state.cluster_size = cluster_size;

        // Read virtual size (validates header readability)
        let _virtual_size = read_u64_be_cached(
            call_table,
            device_idx,
            SIZE_OFFSET as u64,
            sector_size,
            input_capacity,
            &mut state.l1_cached_sector,
            state.l1_cache_buf,
            bytes_read,
        )?;

        // Read v3 feature fields (incompatible_features at offset 72,
        // compression_type at offset 104). For v2, these default to 0.
        if version >= 3 {
            state.incompatible_features = read_u64_be_cached(
                call_table,
                device_idx,
                INCOMPATIBLE_FEATURES_OFFSET as u64,
                sector_size,
                input_capacity,
                &mut state.l1_cached_sector,
                state.l1_cache_buf,
                bytes_read,
            )?;
            state.extended_l2 = (state.incompatible_features & INCOMPAT_EXTENDED_L2) != 0;

            // compression_type is a single byte at offset 104.
            // Read the containing u32 at offset 104 and take the
            // high byte (big-endian: byte at offset 104 is bits
            // 31-24 of the u32 at 104).
            let ct_word = read_u32_be_cached(
                call_table,
                device_idx,
                COMPRESSION_TYPE_OFFSET as u64,
                sector_size,
                input_capacity,
                &mut state.l1_cached_sector,
                state.l1_cache_buf,
                bytes_read,
            )?;
            state.compression_type = (ct_word >> 24) as u8;
        }

        // Read L1 table size
        let l1_size = read_u32_be_cached(
            call_table,
            device_idx,
            L1_SIZE_OFFSET as u64,
            sector_size,
            input_capacity,
            &mut state.l1_cached_sector,
            state.l1_cache_buf,
            bytes_read,
        )?;
        state.l1_size = l1_size;

        // Read L1 table offset
        let l1_table_offset = read_u64_be_cached(
            call_table,
            device_idx,
            L1_TABLE_OFFSET_OFFSET as u64,
            sector_size,
            input_capacity,
            &mut state.l1_cached_sector,
            state.l1_cache_buf,
            bytes_read,
        )?;

        // Validate L1 table bounds
        let actual_size = input_capacity.saturating_mul(sector_size as u64);
        if l1_table_offset == 0 || l1_table_offset >= actual_size {
            return None;
        }
        let l1_table_end = l1_table_offset.checked_add((l1_size as u64).saturating_mul(8))?;
        if l1_table_end > actual_size {
            return None;
        }

        state.l1_table_offset = l1_table_offset;

        // Invalidate cache for subsequent L1/L2 reads
        state.l1_cached_sector = u64::MAX;
        state.l2_cached_sector = u64::MAX;

        Some(state)
    }

    /// Look up the host cluster for a given virtual offset.
    ///
    /// Returns the cluster type (unallocated, standard, or compressed)
    /// or `None` on I/O error.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. Cache buffers must still be valid.
    pub unsafe fn cluster_lookup(
        &mut self,
        call_table: &CallTable,
        virtual_offset: u64,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<ClusterLookup> {
        let cluster_size = self.cluster_size;
        let entry_size: u64 = if self.extended_l2 { 16 } else { 8 };
        let entries_per_l2 = cluster_size / entry_size;

        // Calculate L1 and L2 indices
        let l2_coverage = cluster_size * entries_per_l2;
        let l1_index = virtual_offset / l2_coverage;
        let l2_index = (virtual_offset / cluster_size) % entries_per_l2;

        // Bounds check L1 index
        if l1_index >= self.l1_size as u64 {
            return Some(ClusterLookup::Unallocated);
        }

        // Read L1 entry
        let l1_byte_offset = self.l1_table_offset.checked_add(l1_index.checked_mul(8)?)?;
        let l1_entry = read_u64_be_cached(
            call_table,
            self.device_idx,
            l1_byte_offset,
            sector_size,
            input_capacity,
            &mut self.l1_cached_sector,
            self.l1_cache_buf,
            bytes_read,
        )?;

        // L1 entry of 0 means unallocated
        let l2_table_offset = l1_entry & L2_OFFSET_MASK;
        if l2_table_offset == 0 {
            return Some(ClusterLookup::Unallocated);
        }

        // Validate L2 table offset against device capacity
        let actual_size = input_capacity.checked_mul(sector_size as u64)?;
        if l2_table_offset >= actual_size {
            return None;
        }

        // Read L2 entry (first 8 bytes of each entry, whether 8 or 16 bytes)
        let l2_byte_offset = l2_table_offset.checked_add(l2_index.checked_mul(entry_size)?)?;
        let l2_entry = read_u64_be_cached(
            call_table,
            self.device_idx,
            l2_byte_offset,
            sector_size,
            input_capacity,
            &mut self.l2_cached_sector,
            self.l2_cache_buf,
            bytes_read,
        )?;

        // Decode L2 entry
        if l2_entry == 0 {
            Some(ClusterLookup::Unallocated)
        } else if (l2_entry & OFLAG_COMPRESSED) != 0 {
            Some(ClusterLookup::Compressed(l2_entry))
        } else {
            let host_offset = l2_entry & L2_OFFSET_MASK;
            if host_offset == 0 {
                // Zero cluster (preallocated but zero-filled)
                Some(ClusterLookup::Unallocated)
            } else {
                Some(ClusterLookup::Standard(host_offset))
            }
        }
    }
}

// ============================================================================
// Cluster data reading
// ============================================================================

/// Read a standard (uncompressed) cluster's data sector by sector.
///
/// # Safety
///
/// `buf` must point to at least `cluster_size` writable bytes.
/// `call_table` must be valid.
pub unsafe fn read_cluster_sectors(
    call_table: &CallTable,
    device_idx: u32,
    host_offset: u64,
    buf: *mut u8,
    cluster_size: u64,
    sector_size: usize,
    bytes_read: &mut u64,
) -> bool {
    let first_sector = host_offset / sector_size as u64;
    // Ensure at least one sector is read when cluster_size < sector_size.
    // The caller's buffer is always >= MAX_SECTOR_SIZE.
    let read_size = if cluster_size < sector_size as u64 {
        sector_size as u64
    } else {
        cluster_size
    };
    let sectors_per_cluster = read_size / sector_size as u64;

    for i in 0..sectors_per_cluster {
        let sector = first_sector + i;
        let buf_offset = (i as usize) * sector_size;
        if !(call_table.read_input_sector)(device_idx, sector, buf.add(buf_offset), sector_size) {
            return false;
        }
        *bytes_read += sector_size as u64;
    }
    true
}

/// Parse a compressed L2 entry and return the host byte offset and
/// compressed byte size without performing any I/O.
///
/// Returns `Some((host_offset, compressed_bytes))` on success, or
/// `None` if the entry fields are inconsistent.
pub fn parse_compressed_l2_entry(l2_entry: u64, cluster_bits: u32) -> Option<(u64, u64)> {
    let csize_shift = 62 - (cluster_bits as u64 - 8);
    let csize_mask = (1u64 << (cluster_bits as u64 - 8)) - 1;
    let offset_mask = (1u64 << csize_shift) - 1;

    let compressed_offset = l2_entry & offset_mask;
    let nb_sectors = ((l2_entry >> csize_shift) & csize_mask) + 1;
    let nb_sectors_bytes = nb_sectors.checked_mul(512)?;
    let offset_remainder = compressed_offset & 511;
    if nb_sectors_bytes < offset_remainder {
        return None;
    }
    let compressed_size = nb_sectors_bytes - offset_remainder;
    if compressed_size == 0 {
        return None;
    }

    Some((compressed_offset, compressed_size))
}

/// This is the common prefix shared by both zlib and ZSTD decompression
/// paths: L2 entry parsing, bounds validation, and sector-by-sector I/O.
///
/// # Safety
///
/// `compressed_buf` must point to at least `COMPRESSED_BUF_SIZE` writable bytes.
/// `call_table` must be valid.
#[cfg(any(feature = "decompress", feature = "decompress-zstd"))]
unsafe fn read_compressed_data(
    call_table: &CallTable,
    device_idx: u32,
    l2_entry: u64,
    cluster_bits: u32,
    sector_size: usize,
    compressed_buf: *mut u8,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> Option<(*const u8, usize)> {
    // Parse compressed L2 entry format
    let csize_shift = 62 - (cluster_bits as u64 - 8);
    let csize_mask = (1u64 << (cluster_bits as u64 - 8)) - 1;
    let offset_mask = (1u64 << csize_shift) - 1;

    let compressed_offset = l2_entry & offset_mask;
    let nb_sectors = ((l2_entry >> csize_shift) & csize_mask) + 1;
    let nb_sectors_bytes = nb_sectors.checked_mul(512)?;
    let offset_remainder = compressed_offset & 511;
    if nb_sectors_bytes < offset_remainder {
        return None;
    }
    let compressed_size = nb_sectors_bytes - offset_remainder;

    if compressed_size == 0 || compressed_size > COMPRESSED_BUF_SIZE as u64 {
        return None;
    }

    // Validate compressed data range against device capacity
    let data_end = compressed_offset.checked_add(compressed_size)?;
    let device_size = input_capacity.saturating_mul(sector_size as u64);
    if data_end > device_size {
        return None;
    }

    // Read compressed data sector by sector
    let first_sector = compressed_offset / sector_size as u64;
    let last_sector = (data_end + sector_size as u64 - 1) / sector_size as u64;
    let sectors_to_read = last_sector - first_sector;

    if sectors_to_read * sector_size as u64 > COMPRESSED_BUF_SIZE as u64 {
        return None;
    }

    let read_buf = compressed_buf;
    for i in 0..sectors_to_read {
        let sector = first_sector + i;
        let buf_offset = (i as usize) * sector_size;
        if !(call_table.read_input_sector)(
            device_idx,
            sector,
            read_buf.add(buf_offset),
            sector_size,
        ) {
            return None;
        }
        *bytes_read += sector_size as u64;
    }

    // Extract compressed data from within the read buffer
    let start_within_buf = (compressed_offset % sector_size as u64) as usize;
    let total_read = (sectors_to_read as usize) * sector_size;
    if start_within_buf + compressed_size as usize > total_read {
        return None;
    }

    Some((
        read_buf.add(start_within_buf) as *const u8,
        compressed_size as usize,
    ))
}

/// Read and decompress a zlib-compressed QCOW2 cluster.
///
/// Parses the compressed L2 entry to extract offset and size,
/// reads the compressed data, and inflates using miniz_oxide.
///
/// # Safety
///
/// `out_buf` must point to at least `cluster_size` writable bytes.
/// `compressed_buf` must point to at least `COMPRESSED_BUF_SIZE` writable bytes
/// (used as scratch for decompressing compressed clusters).
/// `call_table` must be valid.
#[cfg(feature = "decompress")]
pub unsafe fn read_compressed_cluster(
    call_table: &CallTable,
    device_idx: u32,
    l2_entry: u64,
    cluster_bits: u32,
    out_buf: *mut u8,
    cluster_size: u64,
    sector_size: usize,
    compressed_buf: *mut u8,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> bool {
    let (compressed_data, compressed_len) = match read_compressed_data(
        call_table,
        device_idx,
        l2_entry,
        cluster_bits,
        sector_size,
        compressed_buf,
        input_capacity,
        bytes_read,
    ) {
        Some(v) => v,
        None => return false,
    };

    let compressed_slice = core::slice::from_raw_parts(compressed_data, compressed_len);
    let out_slice = core::slice::from_raw_parts_mut(out_buf, cluster_size as usize);

    // Decompress using miniz_oxide
    use miniz_oxide::inflate::core::inflate_flags;
    use miniz_oxide::inflate::TINFLStatus;

    let mut decomp = miniz_oxide::inflate::core::DecompressorOxide::new();
    let (status, _in_consumed, out_produced) = miniz_oxide::inflate::core::decompress(
        &mut decomp,
        compressed_slice,
        out_slice,
        0,
        inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );

    if status != TINFLStatus::Done || out_produced != cluster_size as usize {
        // Try raw deflate (without zlib header)
        let mut decomp2 = miniz_oxide::inflate::core::DecompressorOxide::new();
        let (status2, _in2, out2) = miniz_oxide::inflate::core::decompress(
            &mut decomp2,
            compressed_slice,
            out_slice,
            0,
            inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        if status2 != TINFLStatus::Done || out2 != cluster_size as usize {
            return false;
        }
    }

    true
}

/// Read and decompress a ZSTD-compressed QCOW2 cluster.
///
/// Same interface as [`read_compressed_cluster`] but uses ruzstd
/// for decompression instead of miniz_oxide. Used for QCOW2 v3
/// images with `compression_type=1` (ZSTD).
///
/// The caller MUST reset the bump allocator before calling this
/// function, as ruzstd allocates internally via `alloc`.
///
/// # Safety
///
/// Same requirements as [`read_compressed_cluster`].
#[cfg(feature = "decompress-zstd")]
pub unsafe fn read_compressed_cluster_zstd(
    call_table: &CallTable,
    device_idx: u32,
    l2_entry: u64,
    cluster_bits: u32,
    out_buf: *mut u8,
    cluster_size: u64,
    sector_size: usize,
    compressed_buf: *mut u8,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> bool {
    let (compressed_data, compressed_len) = match read_compressed_data(
        call_table,
        device_idx,
        l2_entry,
        cluster_bits,
        sector_size,
        compressed_buf,
        input_capacity,
        bytes_read,
    ) {
        Some(v) => v,
        None => return false,
    };

    let compressed_slice = core::slice::from_raw_parts(compressed_data, compressed_len);
    let out_slice = core::slice::from_raw_parts_mut(out_buf, cluster_size as usize);

    // Decompress using ruzstd (ZSTD)
    let mut decoder = match ruzstd::decoding::StreamingDecoder::new(compressed_slice) {
        Ok(d) => d,
        Err(_) => return false,
    };

    match ruzstd::io::Read::read_exact(&mut decoder, out_slice) {
        Ok(()) => true,
        Err(_) => false,
    }
}

// ============================================================================
// Refcount table lookup
// ============================================================================

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal QCOW2 header buffer (≥105 bytes).
    /// Fields default to valid v3, cluster_bits=16, virtual_size=1GiB.
    fn make_qcow2_header() -> [u8; 512] {
        let mut buf = [0u8; 512];
        // version = 3
        buf[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&3u32.to_be_bytes());
        // cluster_bits = 16 (64 KiB clusters)
        buf[CLUSTER_BITS_OFFSET..CLUSTER_BITS_OFFSET + 4].copy_from_slice(&16u32.to_be_bytes());
        // virtual_size = 1 GiB
        let vsize: u64 = 1 << 30;
        buf[SIZE_OFFSET..SIZE_OFFSET + 8].copy_from_slice(&vsize.to_be_bytes());
        // l1_size = 256
        buf[L1_SIZE_OFFSET..L1_SIZE_OFFSET + 4].copy_from_slice(&256u32.to_be_bytes());
        // l1_table_offset = 0x30000
        buf[L1_TABLE_OFFSET_OFFSET..L1_TABLE_OFFSET_OFFSET + 8]
            .copy_from_slice(&0x30000u64.to_be_bytes());
        // refcount_table_offset = 0x10000
        buf[REFCOUNT_TABLE_OFFSET_OFFSET..REFCOUNT_TABLE_OFFSET_OFFSET + 8]
            .copy_from_slice(&0x10000u64.to_be_bytes());
        // refcount_table_clusters = 1
        buf[REFCOUNT_TABLE_CLUSTERS_OFFSET..REFCOUNT_TABLE_CLUSTERS_OFFSET + 4]
            .copy_from_slice(&1u32.to_be_bytes());
        // refcount_order = 4 (16-bit refcounts)
        buf[REFCOUNT_ORDER_OFFSET..REFCOUNT_ORDER_OFFSET + 4].copy_from_slice(&4u32.to_be_bytes());
        // header_length = 112
        buf[HEADER_LENGTH_OFFSET..HEADER_LENGTH_OFFSET + 4].copy_from_slice(&112u32.to_be_bytes());
        buf
    }

    // ---- QcowHeader::parse ----

    #[test]
    fn parse_valid_v3_header() {
        let buf = make_qcow2_header();
        let hdr = QcowHeader::parse(&buf).unwrap();
        assert_eq!(hdr.version, 3);
        assert_eq!(hdr.cluster_bits, 16);
        assert_eq!(hdr.cluster_size, 1 << 16);
        assert_eq!(hdr.virtual_size, 1 << 30);
        assert_eq!(hdr.l1_size, 256);
        assert_eq!(hdr.l1_table_offset, 0x30000);
        assert_eq!(hdr.refcount_bits, 16);
    }

    #[test]
    fn parse_valid_v2_header() {
        let mut buf = make_qcow2_header();
        buf[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&2u32.to_be_bytes());
        let hdr = QcowHeader::parse(&buf).unwrap();
        assert_eq!(hdr.version, 2);
        // v2 defaults
        assert_eq!(hdr.refcount_bits, 16);
        assert_eq!(hdr.incompatible_features, 0);
        assert_eq!(hdr.compatible_features, 0);
        assert_eq!(hdr.compression_type, 0);
    }

    #[test]
    fn parse_invalid_version() {
        let mut buf = make_qcow2_header();
        buf[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&1u32.to_be_bytes());
        assert!(QcowHeader::parse(&buf).is_none());

        buf[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&4u32.to_be_bytes());
        assert!(QcowHeader::parse(&buf).is_none());
    }

    #[test]
    fn parse_cluster_bits_out_of_range() {
        let mut buf = make_qcow2_header();
        // Too small
        buf[CLUSTER_BITS_OFFSET..CLUSTER_BITS_OFFSET + 4].copy_from_slice(&8u32.to_be_bytes());
        assert!(QcowHeader::parse(&buf).is_none());

        // Too large
        buf[CLUSTER_BITS_OFFSET..CLUSTER_BITS_OFFSET + 4].copy_from_slice(&22u32.to_be_bytes());
        assert!(QcowHeader::parse(&buf).is_none());
    }

    #[test]
    fn parse_cluster_bits_boundary() {
        let mut buf = make_qcow2_header();
        // Minimum valid: 9
        buf[CLUSTER_BITS_OFFSET..CLUSTER_BITS_OFFSET + 4].copy_from_slice(&9u32.to_be_bytes());
        let hdr = QcowHeader::parse(&buf).unwrap();
        assert_eq!(hdr.cluster_size, 512);

        // Maximum valid: 21
        buf[CLUSTER_BITS_OFFSET..CLUSTER_BITS_OFFSET + 4].copy_from_slice(&21u32.to_be_bytes());
        let hdr = QcowHeader::parse(&buf).unwrap();
        assert_eq!(hdr.cluster_size, 1 << 21);
    }

    #[test]
    fn parse_buffer_too_short() {
        // 104 bytes = one less than minimum
        let buf = [0u8; 104];
        assert!(QcowHeader::parse(&buf).is_none());
    }

    #[test]
    fn parse_exactly_minimum_size() {
        let full = make_qcow2_header();
        let buf = &full[..105];
        let hdr = QcowHeader::parse(buf).unwrap();
        assert_eq!(hdr.version, 3);
    }

    // ---- Feature flags ----

    #[test]
    fn parse_feature_flags() {
        let mut buf = make_qcow2_header();
        let incompat = INCOMPAT_DIRTY | INCOMPAT_CORRUPT | INCOMPAT_EXTENDED_L2;
        buf[INCOMPATIBLE_FEATURES_OFFSET..INCOMPATIBLE_FEATURES_OFFSET + 8]
            .copy_from_slice(&incompat.to_be_bytes());
        let compat = COMPAT_LAZY_REFCOUNTS;
        buf[COMPATIBLE_FEATURES_OFFSET..COMPATIBLE_FEATURES_OFFSET + 8]
            .copy_from_slice(&compat.to_be_bytes());

        let hdr = QcowHeader::parse(&buf).unwrap();
        assert!(hdr.dirty);
        assert!(hdr.corrupt);
        assert!(hdr.extended_l2);
        assert!(!hdr.has_external_data);
        assert!(hdr.lazy_refcounts);
    }

    // ---- qemu_disk_size ----

    #[test]
    fn qemu_disk_size_normal() {
        let buf = make_qcow2_header();
        let hdr = QcowHeader::parse(&buf).unwrap();
        // l1_table_offset=0x30000, l1_size=256 → end = 0x30000 + 256*8 = 0x30800
        // rounded up to 512: 0x30800 (already aligned)
        assert_eq!(hdr.qemu_disk_size(), 0x30800);
    }

    #[test]
    fn qemu_disk_size_saturates_on_overflow() {
        let mut buf = make_qcow2_header();
        // Set l1_table_offset to near u64::MAX
        buf[L1_TABLE_OFFSET_OFFSET..L1_TABLE_OFFSET_OFFSET + 8]
            .copy_from_slice(&(u64::MAX - 100).to_be_bytes());
        buf[L1_SIZE_OFFSET..L1_SIZE_OFFSET + 4].copy_from_slice(&1000u32.to_be_bytes());

        let hdr = QcowHeader::parse(&buf).unwrap();
        // Should saturate, not panic
        let size = hdr.qemu_disk_size();
        assert!(size <= u64::MAX);
    }

    // ---- compat helpers ----

    #[test]
    fn compat_str_and_value() {
        let buf = make_qcow2_header();
        let hdr = QcowHeader::parse(&buf).unwrap();
        assert_eq!(hdr.compat_str(), "1.1");
        assert_eq!(hdr.compat_value(), 1);

        let mut v2buf = make_qcow2_header();
        v2buf[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&2u32.to_be_bytes());
        let hdr2 = QcowHeader::parse(&v2buf).unwrap();
        assert_eq!(hdr2.compat_str(), "0.10");
        assert_eq!(hdr2.compat_value(), 0);
    }

    // ---- parse_header_extensions ----

    #[test]
    fn header_extensions_v2_returns_none() {
        let mut buf = make_qcow2_header();
        buf[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&2u32.to_be_bytes());
        let hdr = QcowHeader::parse(&buf).unwrap();
        assert_eq!(parse_header_extensions(&buf, &hdr), BackingFormat::None);
    }

    #[test]
    fn header_extensions_with_backing_format() {
        let mut buf = make_qcow2_header();
        let hdr = QcowHeader::parse(&buf).unwrap();
        // header_length=112, so extensions start at offset 112
        let ext_off = 112;
        // Extension type = EXT_BACKING_FORMAT
        buf[ext_off..ext_off + 4].copy_from_slice(&EXT_BACKING_FORMAT.to_be_bytes());
        // Extension length = 5 ("qcow2")
        buf[ext_off + 4..ext_off + 8].copy_from_slice(&5u32.to_be_bytes());
        // Extension data
        buf[ext_off + 8..ext_off + 13].copy_from_slice(b"qcow2");
        // End extension after padding (5 padded to 8)
        let next = ext_off + 8 + 8;
        buf[next..next + 4].copy_from_slice(&EXT_END.to_be_bytes());

        assert_eq!(parse_header_extensions(&buf, &hdr), BackingFormat::Qcow2);
    }

    #[test]
    fn header_extensions_empty_returns_none() {
        let mut buf = make_qcow2_header();
        let hdr = QcowHeader::parse(&buf).unwrap();
        // Place end-of-extensions immediately
        let ext_off = 112;
        buf[ext_off..ext_off + 4].copy_from_slice(&EXT_END.to_be_bytes());

        assert_eq!(parse_header_extensions(&buf, &hdr), BackingFormat::None);
    }
}

/// Look up the refcount for a host cluster via two-level table indirection.
///
/// Returns `Some(refcount)` on success, `None` on I/O error or unsupported
/// refcount width. A refcount of 0 means the cluster is not allocated.
///
/// Supports all standard QCOW2 refcount widths: 1, 2, 4, 8, 16, 32,
/// and 64 bits. Sub-byte widths (1, 2, 4) use little-endian bit
/// ordering within each byte, matching QEMU's implementation.
///
/// # Safety
///
/// Cache buffers must each point to at least `MAX_SECTOR_SIZE` writable bytes.
/// `call_table` must be valid.
pub unsafe fn lookup_refcount(
    call_table: &CallTable,
    device_idx: u32,
    refcount_table_offset: u64,
    refcount_bits: u32,
    cluster_size: u64,
    sector_size: usize,
    input_capacity: u64,
    host_offset: u64,
    reftable_cached_sector: &mut u64,
    reftable_cache_buf: *mut u8,
    refblock_cached_sector: &mut u64,
    refblock_cache_buf: *mut u8,
    bytes_read: &mut u64,
) -> Option<u64> {
    let cluster_index = host_offset / cluster_size;
    let entries_per_block = (cluster_size * 8) / refcount_bits as u64;
    let refblock_index = cluster_index / entries_per_block;

    // Read refcount table entry (big-endian u64 pointer to refcount block)
    let reftable_byte_off = refblock_index
        .checked_mul(8)
        .and_then(|v| refcount_table_offset.checked_add(v))?;
    let refblock_offset = read_u64_be_cached(
        call_table,
        device_idx,
        reftable_byte_off,
        sector_size,
        input_capacity,
        reftable_cached_sector,
        reftable_cache_buf,
        bytes_read,
    )?;

    if refblock_offset == 0 {
        return Some(0); // Block not allocated = refcount 0
    }

    // Read the individual refcount entry from the block.
    // Sub-byte widths use little-endian bit order within each byte
    // (entry 0 occupies the LSB), matching QEMU's get_refcount_ro*
    // functions.
    let entry_in_block = cluster_index % entries_per_block;
    match refcount_bits {
        1 | 2 | 4 => {
            // Sub-byte: multiple entries packed per byte
            let entries_per_byte = 8 / refcount_bits as u64;
            let byte_in_block = entry_in_block / entries_per_byte;
            let entry_byte_off = refblock_offset.checked_add(byte_in_block)?;
            let raw_byte = read_u8_cached(
                call_table,
                device_idx,
                entry_byte_off,
                sector_size,
                input_capacity,
                refblock_cached_sector,
                refblock_cache_buf,
                bytes_read,
            )?;
            // Little-endian bit order: entry 0 at LSB
            let bit_pos = (entry_in_block % entries_per_byte) * refcount_bits as u64;
            let mask = (1u64 << refcount_bits) - 1;
            Some((raw_byte as u64 >> bit_pos) & mask)
        }
        8 => {
            let entry_byte_off = refblock_offset.checked_add(entry_in_block)?;
            let rc = read_u8_cached(
                call_table,
                device_idx,
                entry_byte_off,
                sector_size,
                input_capacity,
                refblock_cached_sector,
                refblock_cache_buf,
                bytes_read,
            )?;
            Some(rc as u64)
        }
        16 => {
            let entry_byte_off = entry_in_block
                .checked_mul(2)
                .and_then(|v| refblock_offset.checked_add(v))?;
            let rc = read_u16_be_cached(
                call_table,
                device_idx,
                entry_byte_off,
                sector_size,
                input_capacity,
                refblock_cached_sector,
                refblock_cache_buf,
                bytes_read,
            )?;
            Some(rc as u64)
        }
        32 => {
            let entry_byte_off = entry_in_block
                .checked_mul(4)
                .and_then(|v| refblock_offset.checked_add(v))?;
            let rc = read_u32_be_cached(
                call_table,
                device_idx,
                entry_byte_off,
                sector_size,
                input_capacity,
                refblock_cached_sector,
                refblock_cache_buf,
                bytes_read,
            )?;
            Some(rc as u64)
        }
        64 => {
            let entry_byte_off = entry_in_block
                .checked_mul(8)
                .and_then(|v| refblock_offset.checked_add(v))?;
            let rc = read_u64_be_cached(
                call_table,
                device_idx,
                entry_byte_off,
                sector_size,
                input_capacity,
                refblock_cached_sector,
                refblock_cache_buf,
                bytes_read,
            )?;
            Some(rc)
        }
        _ => None, // Unsupported refcount width
    }
}

// ============================================================================
// Chain-walking cluster reading
// ============================================================================

/// Read raw sectors from a device for a given virtual offset range.
///
/// Reads `chunk_size / sector_size` consecutive sectors starting at
/// `virtual_offset`. If the device is smaller than the requested range,
/// the remainder is zero-filled.
///
/// # Safety
///
/// `buf` must point to at least `chunk_size` writable bytes.
/// `call_table` must be valid.
pub unsafe fn read_raw_sectors(
    call_table: &CallTable,
    device_idx: u32,
    virtual_offset: u64,
    buf: *mut u8,
    chunk_size: u64,
    sector_size: usize,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> bool {
    let first_sector = virtual_offset / sector_size as u64;
    // Ensure at least one sector is read when chunk_size < sector_size.
    // The caller's buffer is always >= MAX_SECTOR_SIZE.
    let read_size = if chunk_size < sector_size as u64 {
        sector_size as u64
    } else {
        chunk_size
    };
    let sectors_per_chunk = read_size / sector_size as u64;

    for i in 0..sectors_per_chunk {
        let sector = first_sector + i;
        if sector >= input_capacity {
            // Beyond file: fill remainder with zeros
            let remaining = ((sectors_per_chunk - i) as usize) * sector_size;
            let dest = buf.add((i as usize) * sector_size);
            core::ptr::write_bytes(dest, 0, remaining);
            break;
        }
        let buf_offset = (i as usize) * sector_size;
        if !(call_table.read_input_sector)(device_idx, sector, buf.add(buf_offset), sector_size) {
            return false;
        }
        *bytes_read += sector_size as u64;
    }
    true
}

/// Read one cluster's worth of virtual data by walking a backing chain.
///
/// For each device in the chain (starting from the top):
/// - QCOW2: perform L1/L2 lookup. If unallocated, try next device.
/// - VMDK (with `vmdk-input` feature): perform GD/GT grain lookup.
///   If unallocated, try next device.
/// - Raw/other: read sectors directly (base of chain).
///
/// If all devices have the cluster unallocated, fills with zeros.
///
/// # Safety
///
/// `buf` must point to at least `chunk_size` writable bytes.
/// `compressed_buf` must point to at least `COMPRESSED_BUF_SIZE` writable
/// bytes (used as scratch for decompressing compressed clusters).
/// `call_table` must be valid.
#[allow(unused_variables)]
pub unsafe fn read_chain_virtual_cluster(
    call_table: &CallTable,
    chain_start: usize,
    chain_len: usize,
    virtual_offset: u64,
    buf: *mut u8,
    chunk_size: u64,
    sector_size: usize,
    chain_config: &ChainConfig,
    chain_states: &mut ChainStates,
    compressed_buf: *mut u8,
    bytes_read: &mut u64,
) -> bool {
    for dev_offset in 0..chain_len {
        let dev_idx = chain_start + dev_offset;
        let format = chain_config.devices[dev_idx].detected_format();
        let cap = (call_table.get_input_capacity)(dev_idx as u32);

        match format {
            ImageFormat::Qcow2 => {
                let state = match &mut chain_states.qcow2_states[dev_idx] {
                    Some(s) => s,
                    None => return false,
                };

                let qcow2_cluster_size = state.cluster_size;

                // Capture fields before mutable borrow in cluster_lookup
                let compression_type = state.compression_type;
                let cluster_bits = state.cluster_bits;

                match state.cluster_lookup(call_table, virtual_offset, sector_size, cap, bytes_read)
                {
                    Some(ClusterLookup::Unallocated) => {
                        continue;
                    }
                    Some(ClusterLookup::Standard(host_offset)) => {
                        // For large clusters (> chunk_size), calculate
                        // the intra-cluster offset to read only the
                        // requested chunk rather than the full cluster.
                        let intra_offset = virtual_offset % qcow2_cluster_size;
                        let read_offset = host_offset + intra_offset;
                        let read_size = if chunk_size < qcow2_cluster_size {
                            chunk_size
                        } else {
                            qcow2_cluster_size
                        };
                        return read_cluster_sectors(
                            call_table,
                            dev_idx as u32,
                            read_offset,
                            buf,
                            read_size,
                            sector_size,
                            bytes_read,
                        );
                    }
                    #[cfg(feature = "decompress")]
                    Some(ClusterLookup::Compressed(l2_entry)) => {
                        // Compressed clusters with large cluster sizes
                        // can't be decompressed into chunk-sized buffers.
                        if qcow2_cluster_size > MAX_SECTOR_SIZE as u64 {
                            return false;
                        }
                        // Dispatch based on compression type:
                        // 0 = zlib (deflate), 1 = zstd
                        #[cfg(feature = "decompress-zstd")]
                        if compression_type == 1 {
                            return read_compressed_cluster_zstd(
                                call_table,
                                dev_idx as u32,
                                l2_entry,
                                cluster_bits,
                                buf,
                                qcow2_cluster_size,
                                sector_size,
                                compressed_buf,
                                cap,
                                bytes_read,
                            );
                        }
                        if compression_type != 0 {
                            return false;
                        }
                        return read_compressed_cluster(
                            call_table,
                            dev_idx as u32,
                            l2_entry,
                            cluster_bits,
                            buf,
                            qcow2_cluster_size,
                            sector_size,
                            compressed_buf,
                            cap,
                            bytes_read,
                        );
                    }
                    #[cfg(not(feature = "decompress"))]
                    Some(ClusterLookup::Compressed(_)) => {
                        return false;
                    }
                    None => return false,
                }
            }
            #[cfg(feature = "vmdk-input")]
            ImageFormat::Vmdk4 => {
                let state = match &mut chain_states.vmdk_states[dev_idx] {
                    Some(s) => s,
                    None => return false,
                };

                let grain_size_bytes = state.grain_size_bytes;

                match state.grain_lookup(call_table, virtual_offset, sector_size, cap, bytes_read) {
                    Some(GrainLookup::Unallocated) => {
                        continue;
                    }
                    Some(GrainLookup::Zeroed) => {
                        core::ptr::write_bytes(buf, 0, chunk_size as usize);
                        return true;
                    }
                    Some(GrainLookup::Standard(host_offset)) => {
                        // Handle intra-grain offset for large grains
                        let intra_offset = virtual_offset % grain_size_bytes;
                        let read_offset = host_offset + intra_offset;
                        let grain_remaining = grain_size_bytes - intra_offset;
                        let read_size = if chunk_size < grain_remaining {
                            chunk_size
                        } else {
                            grain_remaining
                        };
                        return read_cluster_sectors(
                            call_table,
                            dev_idx as u32,
                            read_offset,
                            buf,
                            read_size,
                            sector_size,
                            bytes_read,
                        );
                    }
                    #[cfg(feature = "vmdk-decompress")]
                    Some(GrainLookup::Compressed(marker_offset)) => {
                        // Compressed grains can't decompress into
                        // a buffer smaller than the grain.
                        if grain_size_bytes > MAX_SECTOR_SIZE as u64 {
                            return false;
                        }
                        return vmdk::read_compressed_grain(
                            call_table,
                            dev_idx as u32,
                            marker_offset,
                            grain_size_bytes,
                            buf,
                            sector_size,
                            compressed_buf,
                            COMPRESSED_BUF_SIZE,
                            cap,
                            bytes_read,
                        );
                    }
                    #[cfg(not(feature = "vmdk-decompress"))]
                    Some(GrainLookup::Compressed(_)) => {
                        return false;
                    }
                    None => return false,
                }
            }
            _ => {
                return read_raw_sectors(
                    call_table,
                    dev_idx as u32,
                    virtual_offset,
                    buf,
                    chunk_size,
                    sector_size,
                    cap,
                    bytes_read,
                );
            }
        }
    }
    // All devices in chain had unallocated: fill with zeros
    core::ptr::write_bytes(buf, 0, chunk_size as usize);
    true
}

/// Initialize QCOW2 state for each QCOW2 device in a chain.
///
/// Iterates over `device_count` devices, initializing a `Qcow2State` for
/// each one whose format is QCOW2. Returns `true` on success, or `false`
/// if any QCOW2 device fails to initialize.
///
/// # Safety
///
/// Caller must ensure `call_table` is a valid initialized `CallTable`,
/// `chain_config` describes the attached devices, `device_count` does not
/// exceed `MAX_CHAIN_DEVICES`, and the memory regions at
/// `dynamic_bufs_start` are large enough for L1/L2 caches.
pub unsafe fn init_chain_qcow2_states(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    qcow2_states: &mut [Option<Qcow2State>; MAX_CHAIN_DEVICES],
    device_count: usize,
    sector_size: usize,
    dynamic_bufs_start: usize,
    bytes_read: &mut u64,
) -> bool {
    for (dev_idx, state) in qcow2_states.iter_mut().enumerate().take(device_count) {
        let dev_info = &chain_config.devices[dev_idx];
        if matches!(dev_info.detected_format(), ImageFormat::Qcow2) {
            let cap = (call_table.get_input_capacity)(dev_idx as u32);
            *state = Qcow2State::init(
                call_table,
                dev_idx as u32,
                sector_size,
                cap,
                l1_cache_addr(dynamic_bufs_start, dev_idx),
                l2_cache_addr(dynamic_bufs_start, dev_idx),
                bytes_read,
            );
            if state.is_none() {
                return false;
            }
        }
    }
    true
}

// ============================================================================
// ChainStates: unified state container for multi-format chain reading
// ============================================================================

/// Bundled state for all format-specific chain readers.
///
/// Holds per-device state arrays for each supported input format.
/// VMDK state is feature-gated to avoid binary bloat when not needed.
/// Each device in a chain uses at most one format's state slot.
#[derive(Default)]
pub struct ChainStates {
    pub qcow2_states: [Option<Qcow2State>; MAX_CHAIN_DEVICES],
    #[cfg(feature = "vmdk-input")]
    pub vmdk_states: [Option<VmdkState>; MAX_CHAIN_DEVICES],
}

/// Initialize format-specific state for all devices in a chain.
///
/// Initializes QCOW2 state for QCOW2 devices, and (when the
/// `vmdk-input` feature is enabled) VMDK state for VMDK4 devices.
/// Each device reuses the same per-device cache memory region
/// (2 × MAX_SECTOR_SIZE), since a device is never both QCOW2 and VMDK.
///
/// Returns `true` on success, `false` if any device fails to
/// initialize.
///
/// # Safety
///
/// Same requirements as `init_chain_qcow2_states`: valid `call_table`,
/// valid `chain_config`, `device_count <= MAX_CHAIN_DEVICES`, and
/// sufficient memory at `dynamic_bufs_start`.
pub unsafe fn init_chain_states(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    chain_states: &mut ChainStates,
    device_count: usize,
    sector_size: usize,
    dynamic_bufs_start: usize,
    bytes_read: &mut u64,
) -> bool {
    for dev_idx in 0..device_count {
        let dev_info = &chain_config.devices[dev_idx];
        let format = dev_info.detected_format();
        let cap = (call_table.get_input_capacity)(dev_idx as u32);

        match format {
            ImageFormat::Qcow2 => {
                chain_states.qcow2_states[dev_idx] = Qcow2State::init(
                    call_table,
                    dev_idx as u32,
                    sector_size,
                    cap,
                    l1_cache_addr(dynamic_bufs_start, dev_idx),
                    l2_cache_addr(dynamic_bufs_start, dev_idx),
                    bytes_read,
                );
                if chain_states.qcow2_states[dev_idx].is_none() {
                    return false;
                }
            }
            #[cfg(feature = "vmdk-input")]
            ImageFormat::Vmdk4 => {
                // Reuse the same cache slots: L1→GD, L2→GT
                chain_states.vmdk_states[dev_idx] = VmdkState::init(
                    call_table,
                    dev_idx as u32,
                    sector_size,
                    cap,
                    l1_cache_addr(dynamic_bufs_start, dev_idx),
                    l2_cache_addr(dynamic_bufs_start, dev_idx),
                    bytes_read,
                );
                if chain_states.vmdk_states[dev_idx].is_none() {
                    return false;
                }
            }
            _ => {} // Raw and other formats need no per-device state
        }
    }
    true
}
