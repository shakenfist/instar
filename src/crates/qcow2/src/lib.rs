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

pub mod bitmap;

#[cfg(feature = "create")]
pub mod create;

#[cfg(any(
    feature = "decompress",
    feature = "decompress-zstd",
    feature = "vmdk-decompress"
))]
use shared::COMPRESSED_BUF_SIZE;
use shared::{
    be_u32, be_u64, l1_cache_addr, l2_cache_addr, AllocationSummary, BackingFormat, CallTable,
    ChainConfig, ImageFormat, MapExtent, MapExtentCoalescer, MapExtentState, MAX_CHAIN_DEVICES,
    MAX_CLUSTER_SIZE, MAX_SECTOR_SIZE,
};
#[cfg(feature = "vhd-input")]
use vhd::{BlockLookup, VhdState};
#[cfg(feature = "vhdx-input")]
use vhdx::{VhdxBlockLookup, VhdxState};
#[cfg(feature = "vmdk-input")]
use vmdk::{GrainLookup, VmdkState};

// Re-export the DMG scratch-layout constants so the chain-discovery
// consumers (convert / compare / bench / rebase) can reserve the
// per-device DMG scratch in their own memory maps without depending on
// the `dmg` crate directly. See `init_chain_states` for how the region is
// carved.
#[cfg(feature = "dmg-input")]
pub use dmg::{DmgRefusal, DmgState, DMG_REQUIRED_SCRATCH, DMG_TABLE_REGION};

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
pub const EXT_EXTERNAL_DATA_FILE: u32 = 0x44415441; // "DATA"
pub const EXT_ENCRYPT_HEADER: u32 = 0x0537BE77; // Full disk encryption header pointer (crypt_method=2)
/// Persistent dirty bitmaps header extension (24-byte body).
/// Parsed by [`bitmap::parse_bitmaps_extension`].
pub const EXT_BITMAPS: u32 = 0x23852875;
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
/// - Bit 2 (external_data): supported (data in separate device via
///   ChainDeviceInfo.data_device_idx; VMM validates and opens the
///   data file as a separate virtio-block device)
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
    INCOMPAT_DIRTY | INCOMPAT_CORRUPT | INCOMPAT_EXTERNAL_DATA | INCOMPAT_EXTENDED_L2;

#[cfg(feature = "decompress-zstd")]
pub const SUPPORTED_INCOMPAT_FEATURES: u64 = INCOMPAT_DIRTY
    | INCOMPAT_CORRUPT
    | INCOMPAT_EXTERNAL_DATA
    | INCOMPAT_COMPRESSION
    | INCOMPAT_EXTENDED_L2;

// L1/L2 entry masks and flags
/// Bit 0 set on a standard (non-extended) L2 entry marks the cluster
/// as reading all zeroes, per the qcow2 spec's standard cluster
/// descriptor ("Bit 0: If set, the cluster reads as all zeros. The
/// host cluster offset ... may be used to describe a preallocated
/// zero cluster"). This holds regardless of the host-offset field:
/// `host_offset == 0` is `QCOW2_CLUSTER_ZERO_PLAIN`, `host_offset !=
/// 0` is `QCOW2_CLUSTER_ZERO_ALLOC`; both read as zeros. Only defined
/// for standard L2 entries — extended-L2 zero status lives in the
/// per-subcluster zero bitmap, not this bit.
pub const QCOW_OFLAG_ZERO: u64 = 1;
/// Bit 62 set indicates a compressed cluster in an L2 entry
pub const OFLAG_COMPRESSED: u64 = 1 << 62;
/// Bit 63 set indicates the cluster (L2 table for an L1 entry, or
/// data cluster for an L2 entry) has refcount == 1, so writes can
/// modify it in place rather than copy-on-write. Set by the
/// preallocation modes (`metadata` / `falloc` / `full`) during
/// create — every preallocated cluster starts with refcount=1.
pub const OFLAG_COPIED: u64 = 1 << 63;
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

/// Maximum sane `l1_size` (in u64 entries). Matches qemu's
/// `QCOW_MAX_L1_SIZE = 32 MiB` (= 4 Mi × 8 bytes/entry). Any
/// header reporting more is either corrupt or hostile; reject
/// it in `QcowHeader::parse` so downstream `scan_allocation`
/// loops are bounded by construction.
pub const QCOW2_MAX_L1_SIZE_ENTRIES: u32 = 4 * 1024 * 1024;

/// Offset of nb_snapshots field in the header
pub const NB_SNAPSHOTS_OFFSET: usize = 60;
/// Offset of snapshots_offset field in the header
pub const SNAPSHOTS_OFFSET_OFFSET: usize = 64;
/// Offset of autoclear_features field in the v3 header
pub const AUTOCLEAR_FEATURES_OFFSET: usize = 88;

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
    let nb_sectors = compressed_bytes.div_ceil(512);
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
    /// Number of snapshots in the snapshot table
    pub nb_snapshots: u32,
    /// Byte offset of the snapshot table in the file
    pub snapshots_offset: u64,
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
        // Reject grossly oversized L1 tables. Matches qemu's
        // QCOW_MAX_L1_SIZE absolute cap. An untrusted image cannot
        // force the scan_allocation / cluster_lookup loops to walk
        // an unbounded L1 region.
        if l1_size > QCOW2_MAX_L1_SIZE_ENTRIES {
            return None;
        }
        let l1_table_offset = be_u64(header, L1_TABLE_OFFSET_OFFSET);
        let backing_file_offset = be_u64(header, BACKING_FILE_OFFSET_OFFSET);
        let backing_file_size = be_u32(header, BACKING_FILE_SIZE_OFFSET);
        let crypt_method = be_u32(header, CRYPT_METHOD_OFFSET);
        let refcount_table_offset = be_u64(header, REFCOUNT_TABLE_OFFSET_OFFSET);
        let refcount_table_clusters = be_u32(header, REFCOUNT_TABLE_CLUSTERS_OFFSET);
        let nb_snapshots = be_u32(header, NB_SNAPSHOTS_OFFSET);
        let snapshots_offset = be_u64(header, SNAPSHOTS_OFFSET_OFFSET);

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

        // Reject images whose virtual size cannot be addressed by a
        // legal L1 table. qemu's qcow2 open computes
        // `size_to_l1(virtual_size)` — the number of L1 entries needed
        // to map the whole image — and refuses to open when it exceeds
        // the addressable maximum ("Image is too large"). Each L1 entry
        // maps one L2 table, which covers `cluster_size * entries_per_l2`
        // bytes (8-byte L2 entries, or 16-byte with the extended-L2
        // feature). A virtual size demanding more than
        // QCOW2_MAX_L1_SIZE_ENTRIES L1 entries is unrepresentable: no
        // valid `l1_size` could reference it, and downstream consumers
        // re-expanding `cluster_count * cluster_size` would overflow u64
        // (issue #438 — a rebase overlay with virtual_size ≈ u64::MAX).
        let l2_entry_size = if incompatible_features & INCOMPAT_EXTENDED_L2 != 0 {
            16u64
        } else {
            8u64
        };
        let l2_coverage = cluster_size * (cluster_size / l2_entry_size);
        if virtual_size.div_ceil(l2_coverage) > QCOW2_MAX_L1_SIZE_ENTRIES as u64 {
            return None;
        }

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
            nb_snapshots,
            snapshots_offset,
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

/// Results from parsing QCOW2 v3 header extensions.
#[derive(Debug, PartialEq)]
pub struct HeaderExtensionResults {
    /// Backing format from EXT_BACKING_FORMAT extension.
    pub backing_format: BackingFormat,
    /// Byte offset of the data file name within the header buffer
    /// (0 if no DATA extension found).
    pub data_file_name_offset: usize,
    /// Length of the data file name in bytes (0 if absent).
    pub data_file_name_len: usize,
    /// Byte offset of the LUKS header data within the QCOW2 file
    /// (0 if no encryption header pointer extension found). Present when
    /// crypt_method=2. The extension 0x0537BE77 contains a pointer
    /// (offset + length) to the actual LUKS header stored elsewhere in the file.
    pub luks_header_offset: u64,
    /// Length of the LUKS header data in bytes (0 if absent).
    pub luks_header_len: u64,
    /// True when a usable persistent-dirty-bitmaps extension is present:
    /// the `EXT_BITMAPS` (`0x23852875`) extension parsed successfully AND
    /// the header's autoclear bitmaps bit (bit 0) is set.
    pub bitmaps_present: bool,
    /// True when the bitmaps extension parsed but the header's autoclear
    /// bitmaps bit is clear — the header advertises bitmaps that the
    /// autoclear bit marks as stale/inconsistent. Callers must treat such
    /// bitmaps as absent (only `--remove` is permitted by qemu).
    pub bitmaps_inconsistent: bool,
    /// `nb_bitmaps` from the bitmaps extension (0 if absent/unparsed).
    pub bitmap_nb_bitmaps: u32,
    /// `bitmap_directory_size` from the bitmaps extension (0 if absent).
    pub bitmap_directory_size: u64,
    /// `bitmap_directory_offset` from the bitmaps extension (0 if absent).
    pub bitmap_directory_offset: u64,
}

/// Parse QCOW2 header extensions from a header buffer.
///
/// Walks all v3+ header extensions and returns the backing format
/// and external data file name location (if present). Only applicable
/// to v3+ headers (v2 has no extensions at the standard offsets).
///
/// `header` is the same buffer passed to `QcowHeader::parse()`.
/// `parsed` is the parsed header (needed for version check).
pub fn parse_header_extensions(header: &[u8], parsed: &QcowHeader) -> HeaderExtensionResults {
    let mut result = HeaderExtensionResults {
        backing_format: BackingFormat::None,
        data_file_name_offset: 0,
        data_file_name_len: 0,
        luks_header_offset: 0,
        luks_header_len: 0,
        bitmaps_present: false,
        bitmaps_inconsistent: false,
        bitmap_nb_bitmaps: 0,
        bitmap_directory_size: 0,
        bitmap_directory_offset: 0,
    };

    if parsed.version < 3 {
        return result;
    }
    if header.len() < HEADER_LENGTH_OFFSET + 4 {
        return result;
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
            result.backing_format = BackingFormat::from_bytes(format_bytes);
        } else if ext_type == EXT_EXTERNAL_DATA_FILE && ext_len > 0 {
            result.data_file_name_offset = ext_offset + 8;
            result.data_file_name_len = ext_len;
        } else if ext_type == EXT_ENCRYPT_HEADER && ext_len >= 16 {
            // Extension data is a pointer: offset (u64 BE) + length (u64 BE)
            let data_start = ext_offset + 8;
            result.luks_header_offset = be_u64(header, data_start);
            result.luks_header_len = be_u64(header, data_start + 8);
        } else if ext_type == EXT_BITMAPS {
            // Parse the 24-byte bitmaps extension body. The loop has already
            // bounds-checked `ext_offset + 8 + ext_len <= header.len()`.
            let body = &header[ext_offset + 8..ext_offset + 8 + ext_len];
            if let Some(ext) = bitmap::parse_bitmaps_extension(body) {
                result.bitmap_nb_bitmaps = ext.nb_bitmaps;
                result.bitmap_directory_size = ext.bitmap_directory_size;
                result.bitmap_directory_offset = ext.bitmap_directory_offset;
                // The bitmaps extension is consistency-guarded by autoclear
                // bit 0: it is usable only if that bit is set. Length-guard
                // before reading the autoclear word.
                let bit_set = if header.len() >= AUTOCLEAR_FEATURES_OFFSET + 8 {
                    be_u64(header, AUTOCLEAR_FEATURES_OFFSET) & bitmap::AUTOCLEAR_BITMAPS_BIT != 0
                } else {
                    false
                };
                if bit_set {
                    result.bitmaps_present = true;
                    result.bitmaps_inconsistent = false;
                } else {
                    // Header advertises bitmaps but the autoclear bit is
                    // clear: treat as inconsistent/absent.
                    result.bitmaps_present = false;
                    result.bitmaps_inconsistent = true;
                }
            }
            // parse_bitmaps_extension returning None ⇒ leave defaults
            // (no usable bitmaps).
        }

        // Move to next extension (data padded to 8-byte boundary)
        let padded_len = (ext_len + 7) & !7;
        ext_offset += 8 + padded_len;
    }

    result
}

/// Walk the header-extension chain and return the offset just past
/// the terminating `EXT_END` record.
///
/// Unlike [`parse_header_extensions`], this is **version-agnostic**:
/// it walks `(type:u32 BE, len:u32 BE)` records from `start`,
/// advancing by `8 + align8(len)` per record, and stops *after* the
/// `EXT_END` (type == 0) record, returning the offset just past its
/// 8-byte header. The amend planner uses this to size the
/// "meaningful tail" (extension chain + backing string) that a
/// version change must relocate, for either a v2 source (extensions
/// at offset 72) or a v3 source (extensions at `header_length`).
///
/// Returns `None` if any record header or body would read out of
/// bounds, or if no `EXT_END` is found within the cluster.
pub fn header_extension_area_end(cluster: &[u8], start: usize) -> Option<usize> {
    let mut off = start;
    loop {
        // Need the 8-byte (type, len) record header.
        if off.checked_add(8)? > cluster.len() {
            return None;
        }
        let ext_type = be_u32(cluster, off);
        let ext_len = be_u32(cluster, off + 4) as usize;

        if ext_type == EXT_END {
            // Stop after the EXT_END record (its body is ignored).
            return Some(off + 8);
        }

        // Validate the (padded) body stays in bounds before advancing.
        let padded_len = (ext_len + 7) & !7;
        let next = off.checked_add(8)?.checked_add(padded_len)?;
        if next > cluster.len() {
            return None;
        }
        off = next;
    }
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
// Snapshot table parsing
// ============================================================================

/// Maximum number of snapshots we will parse via the bounded
/// `parse_snapshot_table` path (memory constraint).
///
/// The streaming `for_each_snapshot_entry` API has no in-memory cap
/// and is bounded only by the qcow2 header's `nb_snapshots` field.
pub const MAX_SNAPSHOTS: usize = 16;

/// Maximum size of a single snapshot's extra-data section, in bytes.
///
/// Mirrors qemu's `QCOW_MAX_SNAPSHOT_EXTRA_DATA` cap from
/// `block/qcow2-snapshot.c`. Entries whose `extra_data_size` exceeds
/// this value are rejected by the per-entry parser.
pub const QCOW_MAX_SNAPSHOT_EXTRA_DATA: u32 = 1024;

/// Parsed snapshot table entry.
///
/// The first set of fields mirrors what `qemu-img snapshot -l`
/// surfaces from the on-disk 40-byte header. The trailing fields
/// (after `vm_state_size`) carry the v3 extra-data progressive-
/// reveal values; see `parse_snapshot_extra_data` for the fallback
/// rules.
#[derive(Clone, Copy)]
pub struct SnapshotEntry {
    /// Byte offset of this snapshot's L1 table
    pub l1_table_offset: u64,
    /// Number of entries in this snapshot's L1 table
    pub l1_size: u32,
    /// Snapshot ID string length
    pub id_len: u16,
    /// Snapshot name string length
    pub name_len: u16,
    /// Snapshot ID (null-terminated, max 63 chars)
    pub id: [u8; 64],
    /// Snapshot name (null-terminated, max 255 chars).
    ///
    /// Widened from 64 to 256 bytes so the parser can hold any name
    /// that qemu-img can create (qemu caps creation at 255 bytes).
    /// The wire record's `name` field is also 256 bytes, so no
    /// truncation occurs on the list path for any qemu-reachable name.
    pub name: [u8; 256],
    /// Creation timestamp (seconds since epoch)
    pub date_sec: u32,
    /// VM state size in bytes (legacy 32-bit field).
    pub vm_state_size: u32,
    /// Subsecond component of the snapshot creation date
    /// (nanoseconds).
    pub date_nsec: u32,
    /// VM clock at snapshot creation (nanoseconds).
    pub vm_clock_nsec: u64,
    /// 64-bit VM state size from qcow2 v3 extra-data (offset 0).
    ///
    /// Equals `vm_state_size as u64` when the v3 extra-data is not
    /// present (`extra_data_size < 8`).
    pub vm_state_size_large: u64,
    /// Virtual disk size at snapshot creation, from qcow2 v3 extra-
    /// data (offset 8).
    ///
    /// `0` is a sentinel meaning "not present in extra-data"; the
    /// planner converter `snapshot_entry_to_record` substitutes the
    /// active image's virtual size from the qcow2 header.
    pub disk_size: u64,
    /// qemu record/replay icount, from qcow2 v3 extra-data
    /// (offset 16).
    ///
    /// [`ICOUNT_ABSENT`](Self::ICOUNT_ABSENT) (`u64::MAX`) is the
    /// sentinel for "not present" — matches qemu's
    /// `qcow2_snapshot.icount = -1`.
    pub icount: u64,
    /// Length of the source extra-data section, reported for
    /// forward-compat diagnostics.
    pub extra_data_size: u32,
}

impl SnapshotEntry {
    /// Sentinel indicating no qemu record/replay icount is present
    /// on the source snapshot. Mirrors qemu's
    /// `qcow2_snapshot.icount = -1` and matches
    /// `shared::SnapshotEntryRecord::ICOUNT_ABSENT`.
    pub const ICOUNT_ABSENT: u64 = u64::MAX;

    const fn zeroed() -> Self {
        Self {
            l1_table_offset: 0,
            l1_size: 0,
            id_len: 0,
            name_len: 0,
            id: [0; 64],
            name: [0; 256],
            date_sec: 0,
            vm_state_size: 0,
            date_nsec: 0,
            vm_clock_nsec: 0,
            vm_state_size_large: 0,
            disk_size: 0,
            icount: Self::ICOUNT_ABSENT,
            extra_data_size: 0,
        }
    }
}

/// Result of parsing the snapshot table.
pub struct SnapshotTable {
    /// Number of valid entries
    pub count: usize,
    /// Parsed entries (up to MAX_SNAPSHOTS)
    pub entries: [SnapshotEntry; MAX_SNAPSHOTS],
}

impl SnapshotTable {
    const fn empty() -> Self {
        Self {
            count: 0,
            entries: [
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
                SnapshotEntry::zeroed(),
            ],
        }
    }
}

/// Raw on-disk snapshot header fields, decoded from a 40-byte
/// in-memory slice.
///
/// Private intermediate; not exposed in the public surface. The
/// streaming parser uses this together with `SnapshotExtraData` to
/// assemble a `SnapshotEntry`.
struct SnapshotHeaderRaw {
    l1_table_offset: u64,
    l1_size: u32,
    id_str_size: u16,
    name_size: u16,
    date_sec: u32,
    date_nsec: u32,
    vm_clock_nsec: u64,
    vm_state_size: u32,
    extra_data_size: u32,
}

/// Decoded snapshot v3 extra-data fields, with qemu's progressive-
/// reveal fallback rules applied.
///
/// Private intermediate; not exposed in the public surface.
struct SnapshotExtraData {
    /// 64-bit VM state size (extra-data offset 0). Equals
    /// `vm_state_size as u64` when `extra_data_size < 8`.
    vm_state_size_large: u64,
    /// Virtual disk size at snapshot creation (extra-data offset 8).
    /// `0` sentinel when `extra_data_size < 16`.
    disk_size: u64,
    /// qemu record/replay icount (extra-data offset 16). `u64::MAX`
    /// sentinel when `extra_data_size < 24`.
    icount: u64,
}

/// Parse the fixed 40-byte snapshot header from an in-memory slice.
///
/// Returns `None` if the buffer is shorter than 40 bytes. All fields
/// are big-endian on disk; see the qcow2 spec §4.2 "Snapshots" and
/// `block/qcow2-snapshot.c::qcow2_read_snapshots` in qemu.
fn parse_snapshot_header_bytes(buf: &[u8]) -> Option<SnapshotHeaderRaw> {
    if buf.len() < 40 {
        return None;
    }
    // Offsets per the qcow2 snapshot header layout:
    //   0-7:   l1_table_offset (u64 BE)
    //   8-11:  l1_size (u32 BE)
    //   12-13: id_str_size (u16 BE)
    //   14-15: name_size (u16 BE)
    //   16-19: date_sec (u32 BE)
    //   20-23: date_nsec (u32 BE)
    //   24-31: vm_clock_nsec (u64 BE)
    //   32-35: vm_state_size (u32 BE)
    //   36-39: extra_data_size (u32 BE)
    let l1_table_offset = u64::from_be_bytes(buf[0..8].try_into().ok()?);
    let l1_size = u32::from_be_bytes(buf[8..12].try_into().ok()?);
    let id_str_size = u16::from_be_bytes(buf[12..14].try_into().ok()?);
    let name_size = u16::from_be_bytes(buf[14..16].try_into().ok()?);
    let date_sec = u32::from_be_bytes(buf[16..20].try_into().ok()?);
    let date_nsec = u32::from_be_bytes(buf[20..24].try_into().ok()?);
    let vm_clock_nsec = u64::from_be_bytes(buf[24..32].try_into().ok()?);
    let vm_state_size = u32::from_be_bytes(buf[32..36].try_into().ok()?);
    let extra_data_size = u32::from_be_bytes(buf[36..40].try_into().ok()?);
    Some(SnapshotHeaderRaw {
        l1_table_offset,
        l1_size,
        id_str_size,
        name_size,
        date_sec,
        date_nsec,
        vm_clock_nsec,
        vm_state_size,
        extra_data_size,
    })
}

/// Apply qemu's progressive-reveal extra-data rules to the in-memory
/// extra-data slice.
///
/// Per `block/qcow2-snapshot.c::qcow2_read_snapshots`:
/// - `extra_data_size >= 8`: read 64-bit `vm_state_size_large`.
/// - `extra_data_size >= 16`: read `disk_size`. Otherwise `0`
///   sentinel meaning "fall back to the active header's virtual
///   size" — resolved by the planner converter.
/// - `extra_data_size >= 24`: read `icount`. Otherwise
///   `u64::MAX` (matches qemu's `sn->icount = -1`).
///
/// Truncated buffers (slice shorter than the field offset would
/// require) fall back to the same sentinels, so a partial read
/// still produces a consistent result.
fn parse_snapshot_extra_data(buf: &[u8], extra_data_size: u32) -> SnapshotExtraData {
    let mut out = SnapshotExtraData {
        vm_state_size_large: 0,
        disk_size: 0,
        icount: u64::MAX,
    };
    // Refuse oversized extra-data per qemu's `QCOW_MAX_SNAPSHOT_EXTRA_DATA`.
    if extra_data_size > QCOW_MAX_SNAPSHOT_EXTRA_DATA {
        return out;
    }
    if extra_data_size >= 8 {
        if let Some(slice) = buf.get(0..8) {
            if let Ok(arr) = slice.try_into() {
                out.vm_state_size_large = u64::from_be_bytes(arr);
            }
        }
    }
    if extra_data_size >= 16 {
        if let Some(slice) = buf.get(8..16) {
            if let Ok(arr) = slice.try_into() {
                out.disk_size = u64::from_be_bytes(arr);
            }
        }
    }
    if extra_data_size >= 24 {
        if let Some(slice) = buf.get(16..24) {
            if let Ok(arr) = slice.try_into() {
                out.icount = u64::from_be_bytes(arr);
            }
        }
    }
    out
}

/// Read `len` consecutive bytes from `offset` into `out`, using
/// the sector-cache helper byte-by-byte. Stops on the first read
/// failure and returns `false`; otherwise returns `true`.
///
/// # Safety
///
/// Same contract as the cached-read helpers: `call_table` must be
/// valid, `cache_buf` must point to at least `sector_size`
/// writable bytes.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn read_bytes_cached(
    call_table: &CallTable,
    device_idx: u32,
    offset: u64,
    len: usize,
    sector_size: usize,
    input_capacity: u64,
    cached_sector: &mut u64,
    cache_buf: *mut u8,
    bytes_read: &mut u64,
    out: &mut [u8],
) -> bool {
    let n = len.min(out.len());
    for (j, slot) in out.iter_mut().take(n).enumerate() {
        match read_u8_cached(
            call_table,
            device_idx,
            offset + j as u64,
            sector_size,
            input_capacity,
            cached_sector,
            cache_buf,
            bytes_read,
        ) {
            Some(b) => *slot = b,
            None => return false,
        }
    }
    true
}

/// Stream snapshot entries one at a time through a caller-supplied
/// callback.
///
/// Bounded only by `nb_snapshots` from the qcow2 header (which the
/// spec caps at 65536). No in-memory snapshot array: the single
/// in-flight `SnapshotEntry` lives on this function's stack frame.
///
/// The callback returns `true` to continue iterating or `false` to
/// stop early. This function returns `true` if the full table was
/// visited and `false` if the callback stopped early or a read
/// error / oversized-extra-data condition aborted the loop.
///
/// `bytes_read` is updated cumulatively across all sector reads.
///
/// # Safety
///
/// `call_table` must be valid. `cache_buf` must point to at least
/// `MAX_SECTOR_SIZE` writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe fn for_each_snapshot_entry(
    call_table: &CallTable,
    device_idx: u32,
    nb_snapshots: u32,
    snapshots_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    cache_buf: *mut u8,
    bytes_read: &mut u64,
    mut callback: impl FnMut(&SnapshotEntry) -> bool,
) -> bool {
    let mut offset = snapshots_offset;
    let mut cached_sector = u64::MAX;
    // Scratch buffer for the 40-byte header + a clamped extra-data
    // section. We only need to inspect the first 24 bytes of extra-
    // data (icount lives at offset 16); anything beyond is ignored.
    let mut header_buf = [0u8; 40];
    let mut extra_buf = [0u8; 24];

    for _ in 0..nb_snapshots {
        // Read the fixed 40-byte snapshot header.
        if !read_bytes_cached(
            call_table,
            device_idx,
            offset,
            40,
            sector_size,
            input_capacity,
            &mut cached_sector,
            cache_buf,
            bytes_read,
            &mut header_buf,
        ) {
            return false;
        }
        let raw = match parse_snapshot_header_bytes(&header_buf) {
            Some(r) => r,
            None => return false,
        };
        // Reject oversized extra-data per qemu's cap.
        if raw.extra_data_size > QCOW_MAX_SNAPSHOT_EXTRA_DATA {
            return false;
        }

        // Read up to 24 bytes of extra-data (anything beyond is
        // ignored for parsing — we still skip the full
        // `extra_data_size` when advancing).
        let extra_read = (raw.extra_data_size as usize).min(extra_buf.len());
        // Zero the buffer first so a short extra_data_size leaves
        // tail bytes as zero rather than carrying stale data.
        for b in extra_buf.iter_mut() {
            *b = 0;
        }
        if extra_read > 0
            && !read_bytes_cached(
                call_table,
                device_idx,
                offset + 40,
                extra_read,
                sector_size,
                input_capacity,
                &mut cached_sector,
                cache_buf,
                bytes_read,
                &mut extra_buf[..extra_read],
            )
        {
            return false;
        }
        let extra = parse_snapshot_extra_data(&extra_buf[..extra_read], raw.extra_data_size);

        // Build the entry. Id/name strings are read directly into
        // the entry buffers, truncated at 63 bytes (the historical
        // limit; longer names are silently dropped — see
        // `snapshot_entry_to_record` for the wire-record path).
        let mut entry = SnapshotEntry::zeroed();
        entry.l1_table_offset = raw.l1_table_offset;
        entry.l1_size = raw.l1_size;
        entry.id_len = raw.id_str_size;
        entry.name_len = raw.name_size;
        entry.date_sec = raw.date_sec;
        entry.date_nsec = raw.date_nsec;
        entry.vm_clock_nsec = raw.vm_clock_nsec;
        entry.vm_state_size = raw.vm_state_size;
        entry.extra_data_size = raw.extra_data_size;
        entry.vm_state_size_large = if raw.extra_data_size >= 8 {
            extra.vm_state_size_large
        } else {
            raw.vm_state_size as u64
        };
        entry.disk_size = extra.disk_size;
        entry.icount = extra.icount;

        let id_start = offset + 40 + raw.extra_data_size as u64;
        let id_copy_len = (raw.id_str_size as usize).min(63);
        if id_copy_len > 0
            && !read_bytes_cached(
                call_table,
                device_idx,
                id_start,
                id_copy_len,
                sector_size,
                input_capacity,
                &mut cached_sector,
                cache_buf,
                bytes_read,
                &mut entry.id[..id_copy_len],
            )
        {
            return false;
        }
        // entry.id[id_copy_len] is already zero from `zeroed()`.

        let name_start = id_start + raw.id_str_size as u64;
        // Cap at 255: the name buffer is [u8; 256] with the last byte
        // reserved as null sentinel, matching the wire record's 256-byte
        // name field.  qemu-img caps creation at 255 bytes, so this is
        // lossless for every name qemu-img can produce.
        let name_copy_len = (raw.name_size as usize).min(255);
        if name_copy_len > 0
            && !read_bytes_cached(
                call_table,
                device_idx,
                name_start,
                name_copy_len,
                sector_size,
                input_capacity,
                &mut cached_sector,
                cache_buf,
                bytes_read,
                &mut entry.name[..name_copy_len],
            )
        {
            return false;
        }

        if !callback(&entry) {
            return false;
        }

        // Advance to the next entry: 40-byte header + extra_data +
        // id + name, rounded up to the 8-byte boundary.
        let entry_size =
            40 + raw.extra_data_size as u64 + raw.id_str_size as u64 + raw.name_size as u64;
        offset += (entry_size + 7) & !7;
    }
    true
}

/// Parse the QCOW2 snapshot table from disk.
///
/// Reads variable-length snapshot entries starting at
/// `snapshots_offset`. Bounded at [`MAX_SNAPSHOTS`] (16) entries —
/// use [`for_each_snapshot_entry`] for the streaming, uncapped
/// variant.
///
/// This is a thin wrapper over [`for_each_snapshot_entry`] that
/// stops once the bounded array is full; the public signature and
/// behaviour are unchanged.
///
/// # Safety
///
/// `call_table` must be valid. `cache_buf` must point to at least
/// `MAX_SECTOR_SIZE` writable bytes.
pub unsafe fn parse_snapshot_table(
    call_table: &CallTable,
    device_idx: u32,
    nb_snapshots: u32,
    snapshots_offset: u64,
    sector_size: usize,
    input_capacity: u64,
    cache_buf: *mut u8,
    bytes_read: &mut u64,
) -> SnapshotTable {
    let mut table = SnapshotTable::empty();
    let bounded = nb_snapshots.min(MAX_SNAPSHOTS as u32);
    for_each_snapshot_entry(
        call_table,
        device_idx,
        bounded,
        snapshots_offset,
        sector_size,
        input_capacity,
        cache_buf,
        bytes_read,
        |entry| {
            if table.count >= MAX_SNAPSHOTS {
                return false;
            }
            table.entries[table.count] = *entry;
            table.count += 1;
            true
        },
    );
    table
}

/// Find a snapshot by ID or name string.
///
/// Two full passes over the table, matching qemu's
/// `find_snapshot_by_id_or_name` (the resolver behind both
/// `qemu-img snapshot -a` and `qemu-img convert -l`): the first
/// pass compares every entry's **ID**; only if no ID matched does
/// the second pass compare every entry's **name**. A *later*
/// entry matching by ID therefore beats an *earlier* entry
/// matching by name — on a table with `id=1 name="2"` and
/// `id=2 name="x"`, the needle `2` resolves to ID 2, not to the
/// snapshot named "2". (The earlier per-entry id-or-name walk
/// returned the first hit of either kind, which diverged from
/// qemu on exactly such collision tables; fixed in PLAN-snapshot
/// phase 14, probe 1.)
///
/// Returns the index into `SnapshotTable::entries` if found.
pub fn find_snapshot(table: &SnapshotTable, needle: &[u8]) -> Option<usize> {
    // Pass 1: IDs only, over the whole table.
    for i in 0..table.count {
        let entry = &table.entries[i];
        let id_len = entry.id_len as usize;
        if id_len == needle.len() && entry.id[..id_len] == *needle {
            return Some(i);
        }
    }
    // Pass 2: names only, over the whole table.
    for i in 0..table.count {
        let entry = &table.entries[i];
        let name_len = entry.name_len as usize;
        if name_len == needle.len() && entry.name[..name_len] == *needle {
            return Some(i);
        }
    }
    None
}

/// Convert a parsed [`SnapshotEntry`] into the wire-FFI
/// [`shared::SnapshotEntryRecord`] representation.
///
/// `header_virtual_size` is the active image's virtual size from
/// the qcow2 header; it is substituted for `entry.disk_size` when
/// the source extra-data did not carry a `disk_size` (qcow2 v2 or
/// short v3, the parser stored `0` as the sentinel).
///
/// `date_sec` is split into `date_sec_hi` / `date_sec_lo` to match
/// the on-disk and wire layout. The parser stores the assembled
/// u32 in `entry.date_sec`; the converter places it in
/// `date_sec_lo` with `date_sec_hi = 0` (Unix time fits in u32
/// until 2106; the wire layout reserves the upper half for the
/// post-2106 future).
///
/// id/name are silently truncated to the wire-record buffer sizes
/// (32 bytes for id, 256 for name) and the `_len` fields reflect the
/// truncated length. In practice `SnapshotEntry::name` is 256 bytes
/// (parser cap 255), so no truncation occurs for any name qemu-img
/// can produce (qemu caps creation at 255 bytes). The clamp is
/// retained as a depth-defence against pathological callers.
pub fn snapshot_entry_to_record(
    entry: &SnapshotEntry,
    header_virtual_size: u64,
) -> shared::SnapshotEntryRecord {
    // Clamp len against both the parser's source buffer and the wire
    // record's destination buffer (32 bytes for id, 256 for name).
    // The parser caps id at 63 bytes ([u8;64]) and name at 255 bytes
    // ([u8;256]), so in practice id_len <= 63 and name_len <= 255 —
    // but defend in depth against any future caller that bypasses the
    // parser.
    let id_len = (entry.id_len as usize).min(entry.id.len()).min(32);
    let name_len = (entry.name_len as usize).min(entry.name.len()).min(256);
    let mut id = [0u8; 32];
    let mut name = [0u8; 256];
    id[..id_len].copy_from_slice(&entry.id[..id_len]);
    name[..name_len].copy_from_slice(&entry.name[..name_len]);

    let disk_size = if entry.disk_size == 0 {
        header_virtual_size
    } else {
        entry.disk_size
    };

    shared::SnapshotEntryRecord {
        magic: shared::SnapshotEntryRecord::MAGIC,
        date_sec_hi: 0,
        date_sec_lo: entry.date_sec,
        date_nsec: entry.date_nsec,
        vm_clock_nsec: entry.vm_clock_nsec,
        vm_state_size_large: entry.vm_state_size_large,
        disk_size,
        icount: entry.icount,
        l1_table_offset: entry.l1_table_offset,
        l1_size: entry.l1_size,
        extra_data_size: entry.extra_data_size,
        id_len: id_len as u32,
        name_len: name_len as u32,
        id,
        name,
        _reserved: [0; 32],
    }
}

// ============================================================================
// Sector-cached I/O helpers (generated by shared::cached_read! macro)
// ============================================================================

shared::cached_read!(read_u64_be_cached, u64, be, 8);
shared::cached_read!(read_u32_be_cached, u32, be, 4);
shared::cached_read!(read_u16_be_cached, u16, be, 2);
shared::cached_read!(read_u8_cached, u8, be, 1);

// ============================================================================
// L1/L2 Cluster Lookup
// ============================================================================

/// Result of looking up a virtual offset in QCOW2 L1/L2 tables.
pub enum ClusterLookup {
    /// Cluster is unallocated (reads as zeros, or from backing)
    Unallocated,
    /// Classic (non-extended) L2 entry with the qcow2 v3 all-zeroes
    /// flag (`QCOW_OFLAG_ZERO`, bit 0) set. The cluster reads as all
    /// zeros regardless of the host-offset field; the chain reader
    /// must zero-fill it and must NOT fall through to a backing layer
    /// (unlike `Unallocated`) nor read the host offset (unlike
    /// `Standard`). The extended-L2 equivalent is expressed through
    /// `StandardSubclusters`' zero bitmap.
    Zero,
    /// Standard cluster at given host byte offset
    Standard(u64),
    /// Standard cluster with extended L2 subcluster bitmap.
    /// (host_offset, subcluster_bitmap)
    /// Bitmap bits 0-31 = allocation, bits 32-63 = zero.
    StandardSubclusters(u64, u64),
    /// Compressed cluster: raw L2 entry for offset/size parsing
    Compressed(u64),
}

// ============================================================================
// Extended L2 subcluster bitmap validation
// ============================================================================

/// Verdict for an extended-L2 entry's subcluster bitmap.
/// `Ok` means the bitmap is self-consistent per the QCOW2 spec.
/// Other variants identify which invariant failed so callers
/// can log specifically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubclusterBitmapStatus {
    /// Bitmap is consistent.
    Ok,
    /// Compressed entry but bitmap is non-zero (spec reserves 0).
    /// We also accept the legacy QEMU pattern alloc_bits=0xFFFF_FFFF
    /// with zero_bits=0; anything else is flagged.
    CompressedNonZero,
    /// `alloc_bits & zero_bits != 0` — subcluster simultaneously
    /// allocated and all-zero without a host cluster.
    AllocAndZeroOverlap,
    /// `host_offset == 0 && alloc_bits != 0` — bitmap claims
    /// subclusters are allocated but no host cluster to hold them.
    AllocWithoutHost,
    /// `host_offset != 0 && alloc_bits == 0 && zero_bits == 0` —
    /// host cluster allocated but no subcluster references it.
    HostWithoutRef,
}

/// Validate an extended-L2 entry's subcluster bitmap against the
/// QCOW2 spec's invalid-combination rules.
///
/// `compressed` must be the result of `(l2e & OFLAG_COMPRESSED) != 0`.
/// `host_offset` is `l2e & L2_OFFSET_MASK` for standard entries
/// (ignored for compressed).
///
/// For compressed entries the spec requires `sc_bitmap == 0`; we
/// also accept `alloc_bits == 0xFFFF_FFFF && zero_bits == 0` for
/// compatibility with images produced by older QEMU versions.
///
/// For standard (non-compressed) entries the following are invalid:
/// - I1: `alloc_bits & zero_bits != 0`
/// - I2: `host_offset == 0 && alloc_bits != 0`
/// - I3: `host_offset != 0 && alloc_bits == 0 && zero_bits == 0`
pub fn validate_subcluster_bitmap(
    compressed: bool,
    host_offset: u64,
    sc_bitmap: u64,
) -> SubclusterBitmapStatus {
    let alloc_bits = sc_bitmap as u32;
    let zero_bits = (sc_bitmap >> 32) as u32;

    if compressed {
        // Spec says bitmap must be 0 for compressed entries.
        // Accept alloc_bits == 0xFFFF_FFFF with zero_bits == 0
        // for compatibility with older QEMU versions.
        if sc_bitmap == 0 || (alloc_bits == 0xFFFF_FFFF && zero_bits == 0) {
            return SubclusterBitmapStatus::Ok;
        }
        return SubclusterBitmapStatus::CompressedNonZero;
    }

    // I1: subcluster simultaneously allocated and all-zero
    if alloc_bits & zero_bits != 0 {
        return SubclusterBitmapStatus::AllocAndZeroOverlap;
    }

    // I2: bitmap claims allocated subclusters but no host cluster
    if host_offset == 0 && alloc_bits != 0 {
        return SubclusterBitmapStatus::AllocWithoutHost;
    }

    // I3: host cluster allocated but no subcluster references it
    if host_offset != 0 && alloc_bits == 0 && zero_bits == 0 {
        return SubclusterBitmapStatus::HostWithoutRef;
    }

    SubclusterBitmapStatus::Ok
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
    /// Encryption method from the header (0=none, 1=AES-128-CBC, 2=LUKS).
    pub crypt_method: u32,
    /// Byte offset of the LUKS header extension data within the QCOW2 file.
    /// Only valid when crypt_method=2. The extension contains the full LUKS
    /// binary header and key material areas.
    pub luks_ext_offset: u64,
    /// Length of the LUKS header extension in bytes.
    pub luks_ext_len: u64,
    /// True when INCOMPAT_EXTENDED_L2 (bit 4) is set.
    pub extended_l2: bool,
    // Sector cache tracking for L1 table reads
    pub l1_cached_sector: u64,
    pub l1_cache_buf: *mut u8,
    // Sector cache tracking for L2 table reads
    pub l2_cached_sector: u64,
    pub l2_cache_buf: *mut u8,
}

// ============================================================================
// Pure allocation-counting helpers (no I/O, no_std)
// ============================================================================

/// Count allocated source bytes in a standard (non-extended-L2) L2 table
/// byte slice. Each entry is an 8-byte big-endian u64.
///
/// Counting rules (mirroring `Qcow2State::cluster_lookup` for the
/// non-extended-L2 case):
/// - `entry == 0` → unallocated (counts as 0).
/// - `entry != 0` → allocated (counts as `cluster_size`, whether the
///   entry is a standard or compressed cluster; the measure semantics
///   are "is there data here", not "how many host bytes does it cost").
///
/// `l2_bytes` may have a trailing partial entry; incomplete 8-byte
/// entries at the tail are ignored. `cluster_size == 0` defensively
/// returns 0 (the parser rejects such images in `Qcow2State::init`).
pub fn count_allocated_in_l2_standard(l2_bytes: &[u8], cluster_size: u64) -> u64 {
    if cluster_size == 0 {
        return 0;
    }
    let allocated = l2_bytes
        .chunks_exact(8)
        .filter(|c| u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]) != 0)
        .count() as u64;
    allocated.saturating_mul(cluster_size)
}

/// Per-scan tracker for "number of target-aligned units touched by
/// allocated source data". Walk the source in virtual-offset order
/// and call [`TargetUnitTracker::observe_allocated`] once per
/// allocated source extent; the running count is in
/// [`TargetUnitTracker::target_units_with_data`].
///
/// `target_unit_size == 0` disables tracking — every method is a
/// no-op and the count stays at zero (the legacy
/// `ceil(allocated_bytes / target_unit_size)` fallback in
/// `measure_qcow2` etc. is used in that case). See bug #286.
pub struct TargetUnitTracker {
    pub target_unit_size: u64,
    /// Index of the last target unit seen, or `u64::MAX` if none yet.
    pub last_unit_idx: u64,
    pub target_units_with_data: u64,
}

impl TargetUnitTracker {
    pub fn new(target_unit_size: u64) -> Self {
        Self {
            target_unit_size,
            last_unit_idx: u64::MAX,
            target_units_with_data: 0,
        }
    }

    /// Note that the byte range `[virtual_offset, virtual_offset+len)`
    /// contains allocated source data. Adds the count of target units
    /// that range covers but which haven't been seen before. Caller
    /// must walk the source in non-decreasing virtual-offset order.
    pub fn observe_allocated(&mut self, virtual_offset: u64, len: u64) {
        if self.target_unit_size == 0 || len == 0 {
            return;
        }
        let unit = self.target_unit_size;
        let first = virtual_offset / unit;
        let last = virtual_offset.saturating_add(len - 1) / unit;
        let new_units = if self.last_unit_idx == u64::MAX || first > self.last_unit_idx {
            last - first + 1
        } else {
            last.saturating_sub(self.last_unit_idx)
        };
        self.target_units_with_data = self.target_units_with_data.saturating_add(new_units);
        if last > self.last_unit_idx || self.last_unit_idx == u64::MAX {
            self.last_unit_idx = last;
        }
    }
}

/// Like [`count_allocated_in_l2_standard`] but also feeds each
/// allocated entry's virtual range into `tracker`, so the scan can
/// count target units touched without a second pass.
///
/// `base_virtual_offset` is the virtual address covered by the first
/// entry in `l2_bytes`. `virtual_size` is the image's declared
/// virtual size; entries whose covered virtual range starts at or
/// past `virtual_size` are parsed but not counted (see "out-of-bounds
/// L2 entries" below).
///
/// # Out-of-bounds L2 entries
///
/// The qcow2 spec lets the L1 table cover more virtual address space
/// than the image's declared `size` (an L1 entry's coverage is
/// `cluster_size * entries_per_l2`, which is rarely an exact
/// divisor of `size`). On-disk L2 entries past `size` are legal —
/// they parse cleanly — but they describe clusters with no
/// guest-visible meaning. Counting them inflates `allocated_bytes`
/// past `virtual_size`, which breaks the invariant
/// `allocated_bytes <= virtual_size` that the measure path and
/// `fuzz_measure_scan` both depend on.
///
/// Per `docs/qcow2/parsing.md`: allocated_bytes never exceeds
/// virtual_size; entries beyond virtual_size are parsed but not
/// counted. Last-cluster contributions are capped at
/// `virtual_size - cluster_start` so a cluster that straddles
/// `virtual_size` still contributes its in-bounds portion.
pub fn walk_l2_standard(
    l2_bytes: &[u8],
    cluster_size: u64,
    base_virtual_offset: u64,
    virtual_size: u64,
    tracker: &mut TargetUnitTracker,
) -> u64 {
    if cluster_size == 0 {
        return 0;
    }
    let mut allocated_bytes: u64 = 0;
    for (i, chunk) in l2_bytes.chunks_exact(8).enumerate() {
        let entry = u64::from_be_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        if entry == 0 {
            continue;
        }
        let v = base_virtual_offset.saturating_add((i as u64).saturating_mul(cluster_size));
        if v >= virtual_size {
            // OOB: cluster starts at or past virtual_size; no
            // guest-visible bytes here. See doc comment.
            continue;
        }
        let cluster_contrib = cluster_size.min(virtual_size - v);
        allocated_bytes = allocated_bytes.saturating_add(cluster_contrib);
        tracker.observe_allocated(v, cluster_contrib);
    }
    allocated_bytes
}

/// Count allocated source bytes in an extended-L2 (16-byte entry) L2
/// table byte slice. Each entry is two big-endian u64s: `l2_entry`
/// followed by `sc_bitmap`.
///
/// Subcluster bitmap layout (32 subclusters per cluster):
/// - `alloc_bits = sc_bitmap as u32`
/// - `zero_bits  = (sc_bitmap >> 32) as u32`
///
/// Counting rules (mirroring `Qcow2State::cluster_lookup` for the
/// extended-L2 case):
/// - `l2_entry == 0` and `(sc_bitmap >> 32) == 0` → unallocated (0).
/// - `l2_entry == 0` with any `zero_bits` set → logically zero (0).
/// - `l2_entry & OFLAG_COMPRESSED != 0` → allocated, counts as
///   `cluster_size` (compressed clusters carry one full cluster's
///   worth of decompressed data; see PLAN open-question 1).
/// - `l2_entry != 0` (standard, non-compressed):
///     - `alloc_bits == 0xFFFF_FFFF && zero_bits == 0` → counts as
///       `cluster_size` (whole cluster allocated, matches
///       `ClusterLookup::Standard`).
///     - otherwise → counts as
///       `popcount(alloc_bits) * (cluster_size / 32)`.
///
/// `l2_bytes` may have a trailing partial entry; incomplete 16-byte
/// pairs at the tail are ignored. `cluster_size == 0` defensively
/// returns 0 (the parser rejects such images in `Qcow2State::init`).
///
/// `base_virtual_offset` is the virtual address covered by the first
/// pair in `l2_bytes`; entries with `cluster_start >= virtual_size`
/// are skipped. See [`walk_l2_standard`] for the rationale on
/// out-of-bounds L2 entries.
pub fn count_allocated_in_l2_extended(
    l2_bytes: &[u8],
    cluster_size: u64,
    base_virtual_offset: u64,
    virtual_size: u64,
) -> u64 {
    if cluster_size == 0 {
        return 0;
    }
    let subcluster_size = cluster_size / 32;
    let mut total: u64 = 0;
    for (i, chunk) in l2_bytes.chunks_exact(16).enumerate() {
        let l2_entry = u64::from_be_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        let sc_bitmap = u64::from_be_bytes([
            chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15],
        ]);

        if l2_entry == 0 {
            // l2_entry==0 is unallocated regardless of zero_bits — zero
            // subclusters consume no source bytes (logically zero).
            continue;
        }

        let cluster_start =
            base_virtual_offset.saturating_add((i as u64).saturating_mul(cluster_size));
        if cluster_start >= virtual_size {
            // OOB: cluster starts at or past virtual_size; no
            // guest-visible bytes here. See `walk_l2_standard`.
            continue;
        }
        let cluster_cap = cluster_size.min(virtual_size - cluster_start);

        if (l2_entry & OFLAG_COMPRESSED) != 0 {
            // Compressed cluster counts as one full cluster's worth.
            total = total.saturating_add(cluster_cap);
            continue;
        }

        let alloc_bits = sc_bitmap as u32;
        let zero_bits = (sc_bitmap >> 32) as u32;
        let raw_contrib = if alloc_bits == 0xFFFF_FFFF && zero_bits == 0 {
            cluster_size
        } else {
            let popcount = alloc_bits.count_ones() as u64;
            popcount.saturating_mul(subcluster_size)
        };
        total = total.saturating_add(raw_contrib.min(cluster_cap));
    }
    total
}

/// Classify one standard-L2 entry into a single `MapExtent`.
///
/// The classification mirrors `Qcow2State::cluster_lookup`'s
/// standard-L2 decision tree exactly:
///
/// - `entry == 0` → `Hole`.
/// - `entry & OFLAG_COMPRESSED != 0` → `Data { file_offset:
///   entry & L2_OFFSET_MASK }`. For map's purposes the compressed
///   cluster occupies one cluster's worth of virtual space at the
///   masked file offset; the embedded length-in-sectors field is
///   not extracted (map only reports file_offset, not file_length).
/// - `entry & QCOW_OFLAG_ZERO != 0` (bit 0) → `ZeroAllocated`. The
///   qcow2 v3 all-zeroes flag on a standard L2 entry reads as zeros
///   regardless of the host-offset field (`host_offset == 0` is
///   `ZERO_PLAIN`, `host_offset != 0` is `ZERO_ALLOC`); qemu-img map
///   reports both as `present: true, zero: true, data: false`. This
///   mirrors `cluster_lookup`'s `ClusterLookup::Zero` verdict.
/// - Otherwise, `host_offset = entry & L2_OFFSET_MASK`:
///   - `host_offset == 0` → `Hole` (matches cluster_lookup's
///     "host_offset == 0 && !extended_l2 → Unallocated" path).
///   - `host_offset != 0` → `Data { file_offset: host_offset }`.
///
/// `cluster_size` is the extent's length. `virtual_offset` is the
/// virtual address of the cluster's first byte; the caller is
/// responsible for clamping `length` against virtual_size if the
/// cluster straddles end-of-image.
pub fn classify_qcow2_l2_standard(entry: u64, virtual_offset: u64, cluster_size: u64) -> MapExtent {
    if entry == 0 {
        return MapExtent {
            start: virtual_offset,
            length: cluster_size,
            state: MapExtentState::Hole,
        };
    }
    if (entry & OFLAG_COMPRESSED) != 0 {
        let file_offset = entry & L2_OFFSET_MASK;
        return MapExtent {
            start: virtual_offset,
            length: cluster_size,
            state: MapExtentState::Data { file_offset },
        };
    }
    if (entry & QCOW_OFLAG_ZERO) != 0 {
        // qcow2 v3 all-zeroes flag (bit 0): reads as zeros regardless
        // of the host-offset field (ZERO_PLAIN / ZERO_ALLOC).
        return MapExtent {
            start: virtual_offset,
            length: cluster_size,
            state: MapExtentState::ZeroAllocated,
        };
    }
    let host_offset = entry & L2_OFFSET_MASK;
    if host_offset == 0 {
        return MapExtent {
            start: virtual_offset,
            length: cluster_size,
            state: MapExtentState::Hole,
        };
    }
    MapExtent {
        start: virtual_offset,
        length: cluster_size,
        state: MapExtentState::Data {
            file_offset: host_offset,
        },
    }
}

/// Classify one extended-L2 entry by pushing 1-32 subcluster
/// `MapExtent`s through the supplied coalescer.
///
/// Each cluster has 32 subclusters of size `cluster_size / 32`.
/// The 64-bit `sc_bitmap` packs the per-subcluster state as two
/// 32-bit words: `alloc_bits = sc_bitmap as u32` and
/// `zero_bits = (sc_bitmap >> 32) as u32`. Per cluster_lookup
/// extended-L2 decision tree:
///
/// - `l2_entry == 0`, `zero_bits == 0`: 32× `Hole`. Coalesces to
///   one extent.
/// - `l2_entry == 0`, `zero_bits != 0`: per-subcluster: if
///   `zero_bits[i]` set → `ZeroAllocated`, else → `Hole`.
/// - `l2_entry & OFLAG_COMPRESSED != 0`: 32× `Data { file_offset
///   = (l2_entry & L2_OFFSET_MASK) + i * subcluster_size }`.
///   (Compressed clusters do not technically have one host offset
///   per subcluster, but emitting them as a Data sequence that
///   coalesces into one cluster-wide extent matches the qemu-img
///   map output.)
/// - `l2_entry != 0`, `alloc_bits == 0xFFFF_FFFF`, `zero_bits ==
///   0`: 32× `Data` with contiguous file offsets (collapses).
/// - Otherwise: per-subcluster (alloc[i], zero[i]) →
///   (0,0)=`Hole`, (0,1)=`ZeroAllocated`, (1,0)=`Data { offset
///   = host_offset + i * subcluster_size }`, (1,1)=`ZeroAllocated`
///   (zero wins; sc_bitmap_invalid rejects this combo, but treat
///   defensively as zero for forward compatibility).
///
/// The caller is responsible for clamping `cluster_length` to
/// virtual_size if the cluster straddles end-of-image. Returns
/// `false` if the coalescer signalled abort.
pub fn classify_qcow2_l2_extended<F: FnMut(MapExtent) -> bool>(
    l2_entry: u64,
    sc_bitmap: u64,
    virtual_offset: u64,
    cluster_size: u64,
    cluster_length: u64,
    sink: &mut MapExtentCoalescer<'_, F>,
) -> bool {
    if cluster_size == 0 || cluster_length == 0 {
        return true;
    }
    let subcluster_size = cluster_size / 32;
    if subcluster_size == 0 {
        return true;
    }
    let alloc_bits = sc_bitmap as u32;
    let zero_bits = (sc_bitmap >> 32) as u32;
    let host_offset = l2_entry & L2_OFFSET_MASK;
    let is_compressed = (l2_entry & OFLAG_COMPRESSED) != 0;

    // Per-subcluster emission. The coalescer merges
    // adjacent same-state subclusters back into one extent.
    let mut sub_virt = virtual_offset;
    let mut consumed: u64 = 0;
    for i in 0..32u32 {
        // Clamp the final subcluster against the cluster's
        // remaining length so the emitted run never exceeds the
        // cluster's effective span (caller-supplied
        // `cluster_length` accounts for end-of-image clamping).
        let remaining = cluster_length.saturating_sub(consumed);
        if remaining == 0 {
            break;
        }
        let sub_len = subcluster_size.min(remaining);

        let state = if is_compressed {
            // All 32 subclusters point into the same compressed
            // payload; emit each at host_offset + i * subcluster_size
            // so the coalescer collapses them into one cluster-wide
            // Data extent.
            MapExtentState::Data {
                file_offset: host_offset.saturating_add((i as u64).saturating_mul(subcluster_size)),
            }
        } else if l2_entry == 0 {
            if (zero_bits >> i) & 1 != 0 {
                MapExtentState::ZeroAllocated
            } else {
                MapExtentState::Hole
            }
        } else {
            let a = (alloc_bits >> i) & 1 != 0;
            let z = (zero_bits >> i) & 1 != 0;
            match (a, z) {
                (false, false) => MapExtentState::Hole,
                (_, true) => MapExtentState::ZeroAllocated,
                (true, false) => {
                    if host_offset == 0 {
                        MapExtentState::Hole
                    } else {
                        MapExtentState::Data {
                            file_offset: host_offset
                                .saturating_add((i as u64).saturating_mul(subcluster_size)),
                        }
                    }
                }
            }
        };

        let cont = sink.push(MapExtent {
            start: sub_virt,
            length: sub_len,
            state,
        });
        if !cont {
            return false;
        }
        sub_virt = sub_virt.saturating_add(sub_len);
        consumed = consumed.saturating_add(sub_len);
    }
    true
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
            crypt_method: 0,
            luks_ext_offset: 0,
            luks_ext_len: 0,
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

        // Read crypt_method (offset 32, 4 bytes)
        state.crypt_method = read_u32_be_cached(
            call_table,
            device_idx,
            CRYPT_METHOD_OFFSET as u64,
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

            // If crypt_method=2, scan header extensions to find the LUKS
            // header extension offset. Extensions start at header_length.
            if state.crypt_method == 2 {
                let header_length = read_u32_be_cached(
                    call_table,
                    device_idx,
                    HEADER_LENGTH_OFFSET as u64,
                    sector_size,
                    input_capacity,
                    &mut state.l1_cached_sector,
                    state.l1_cache_buf,
                    bytes_read,
                )? as u64;

                let mut ext_off = header_length;
                // Scan up to 1MB of extensions (generous upper bound)
                while ext_off + 8 < 1024 * 1024 {
                    let ext_type = read_u32_be_cached(
                        call_table,
                        device_idx,
                        ext_off,
                        sector_size,
                        input_capacity,
                        &mut state.l1_cached_sector,
                        state.l1_cache_buf,
                        bytes_read,
                    );
                    let ext_type = match ext_type {
                        Some(v) => v,
                        None => break,
                    };
                    let ext_len = read_u32_be_cached(
                        call_table,
                        device_idx,
                        ext_off + 4,
                        sector_size,
                        input_capacity,
                        &mut state.l1_cached_sector,
                        state.l1_cache_buf,
                        bytes_read,
                    );
                    let ext_len = match ext_len {
                        Some(v) => v as u64,
                        None => break,
                    };

                    if ext_type == EXT_END {
                        break;
                    }
                    if ext_type == EXT_ENCRYPT_HEADER && ext_len >= 16 {
                        // Extension data is a pointer: offset (u64 BE) + length (u64 BE)
                        // pointing to the actual LUKS header elsewhere in the file.
                        let ptr_off = ext_off + 8;
                        let hi = read_u32_be_cached(
                            call_table,
                            device_idx,
                            ptr_off,
                            sector_size,
                            input_capacity,
                            &mut state.l1_cached_sector,
                            state.l1_cache_buf,
                            bytes_read,
                        );
                        let lo = read_u32_be_cached(
                            call_table,
                            device_idx,
                            ptr_off + 4,
                            sector_size,
                            input_capacity,
                            &mut state.l1_cached_sector,
                            state.l1_cache_buf,
                            bytes_read,
                        );
                        if let (Some(h), Some(l)) = (hi, lo) {
                            state.luks_ext_offset = ((h as u64) << 32) | (l as u64);
                        }
                        let hi2 = read_u32_be_cached(
                            call_table,
                            device_idx,
                            ptr_off + 8,
                            sector_size,
                            input_capacity,
                            &mut state.l1_cached_sector,
                            state.l1_cache_buf,
                            bytes_read,
                        );
                        let lo2 = read_u32_be_cached(
                            call_table,
                            device_idx,
                            ptr_off + 12,
                            sector_size,
                            input_capacity,
                            &mut state.l1_cached_sector,
                            state.l1_cache_buf,
                            bytes_read,
                        );
                        if let (Some(h), Some(l)) = (hi2, lo2) {
                            state.luks_ext_len = ((h as u64) << 32) | (l as u64);
                        }
                        break;
                    }
                    // Move to next (8-byte aligned)
                    ext_off += 8 + ((ext_len + 7) & !7);
                }
            }
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

        // Read L2 entry (first 8 bytes of each 8- or 16-byte entry)
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

        // For extended L2, read the subcluster bitmap (second 8 bytes)
        let bitmap = if self.extended_l2 {
            read_u64_be_cached(
                call_table,
                self.device_idx,
                l2_byte_offset + 8,
                sector_size,
                input_capacity,
                &mut self.l2_cached_sector,
                self.l2_cache_buf,
                bytes_read,
            )
            .unwrap_or(0)
        } else {
            0
        };

        // Decode L2 entry
        if l2_entry == 0 {
            if self.extended_l2 && (bitmap >> 32) != 0 {
                // l2_entry is 0 but bitmap has zero bits set (zero-plain subclusters)
                Some(ClusterLookup::StandardSubclusters(0, bitmap))
            } else {
                Some(ClusterLookup::Unallocated)
            }
        } else if (l2_entry & OFLAG_COMPRESSED) != 0 {
            Some(ClusterLookup::Compressed(l2_entry))
        } else if !self.extended_l2 {
            // Classic (non-extended) L2 entry. Bit 0 (QCOW_OFLAG_ZERO)
            // wins over the host-offset field: a set zero flag means the
            // cluster reads as all zeros whether host_offset is 0
            // (ZERO_PLAIN) or not (ZERO_ALLOC). Test it before the
            // host_offset==0 → Unallocated fallback so a zero-flag entry
            // is never mis-routed to Unallocated or Standard.
            if (l2_entry & QCOW_OFLAG_ZERO) != 0 {
                Some(ClusterLookup::Zero)
            } else {
                let host_offset = l2_entry & L2_OFFSET_MASK;
                if host_offset == 0 {
                    Some(ClusterLookup::Unallocated)
                } else {
                    Some(ClusterLookup::Standard(host_offset))
                }
            }
        } else {
            // Extended L2: zero status is carried by the subcluster
            // zero bitmap, not bit 0 of the entry.
            let host_offset = l2_entry & L2_OFFSET_MASK;
            let alloc_bits = bitmap as u32;
            let zero_bits = (bitmap >> 32) as u32;
            if alloc_bits == 0xFFFF_FFFF && zero_bits == 0 {
                // All subclusters allocated, none zeroed — same as Standard
                Some(ClusterLookup::Standard(host_offset))
            } else {
                Some(ClusterLookup::StandardSubclusters(host_offset, bitmap))
            }
        }
    }

    /// Walk the L1 / L2 tables and produce an `AllocationSummary` for
    /// the active image.
    ///
    /// Reports allocations in the top layer only; backing-chain
    /// composition (shadowing across layers) is the caller's
    /// responsibility (see phase 3 host code in `PLAN-measure.md`).
    ///
    /// `virtual_size` must be supplied by the caller because
    /// `Qcow2State` does not store it.
    ///
    /// For each non-zero L1 entry, the L2 table at the masked host
    /// offset is read in `MAX_SECTOR_SIZE`-aligned chunks and counted
    /// via `count_allocated_in_l2_standard` or
    /// `count_allocated_in_l2_extended` depending on
    /// `self.extended_l2`. The per-chunk byte slice is always an
    /// entry-aligned multiple (8 divides every sector size we
    /// support, and 16 divides `MAX_SECTOR_SIZE = 65536`), so the
    /// pure helpers always see whole entries.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. `l1_cache_buf` and `l2_cache_buf`
    /// must still be valid and each point to at least
    /// `MAX_SECTOR_SIZE` writable bytes.
    pub unsafe fn scan_allocation(
        &mut self,
        call_table: &CallTable,
        sector_size: usize,
        input_capacity: u64,
        virtual_size: u64,
        target_unit_size: u64,
        bytes_read: &mut u64,
    ) -> Option<AllocationSummary> {
        let cluster_size = self.cluster_size;
        let extended_l2 = self.extended_l2;
        let l1_size = self.l1_size as u64;
        let l1_table_offset = self.l1_table_offset;

        let mut allocated_bytes: u64 = 0;
        // Target-unit tracker. Only meaningful for the standard-L2
        // walk path; extended L2 leaves the tracker untouched and
        // `target_units_with_data` ends up at 0, which makes
        // `measure_*` fall back to the legacy approximation. See
        // bug #286 for the standard-L2 fix; extended-L2 target-aware
        // accounting is tracked as follow-up.
        let mut tracker = TargetUnitTracker::new(if extended_l2 { 0 } else { target_unit_size });
        // Virtual address covered by one L2 table (entries_per_l2 *
        // cluster_size). Bytes 0..l2_coverage of the source virtual
        // address space map to L1 entry 0, l2_coverage..2*l2_coverage
        // to L1 entry 1, and so on.
        let entries_per_l2: u64 = cluster_size / if extended_l2 { 16 } else { 8 };
        let l2_coverage = cluster_size.checked_mul(entries_per_l2)?;

        for l1_index in 0..l1_size {
            let l1_byte_offset = l1_table_offset.checked_add(l1_index.checked_mul(8)?)?;
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

            let l2_table_offset = l1_entry & L2_OFFSET_MASK;
            if l2_table_offset == 0 {
                // L2 table not allocated; all clusters in its
                // coverage range are unallocated.
                continue;
            }

            // Walk the L2 table (cluster_size bytes) in sector-sized
            // chunks. The L2 cache is per-sector, so invalidate it
            // before each new L2 so the cached_sector tracker doesn't
            // serve a stale sector from a previous L2.
            self.l2_cached_sector = u64::MAX;

            // Reject obviously-invalid L2 offsets up front: an L2
            // table that starts past the end of the device cannot
            // possibly hold valid entries. The sector-level capacity
            // check inside the read loop also catches OOB reads,
            // but short-circuiting here avoids computing very large
            // sector counts for adversarial L1 entries (mirrors the
            // pattern in `cluster_lookup`).
            let device_byte_capacity = input_capacity.checked_mul(sector_size as u64)?;
            if l2_table_offset >= device_byte_capacity {
                return None;
            }
            let l2_end_byte = l2_table_offset.checked_add(cluster_size)?;
            let l2_start_sector = l2_table_offset / sector_size as u64;
            let l2_end_sector =
                l2_end_byte.checked_add(sector_size as u64 - 1)? / sector_size as u64;

            let mut l2_bytes_consumed: u64 = 0;

            let mut sector = l2_start_sector;
            while sector < l2_end_sector {
                if sector >= input_capacity {
                    return None;
                }
                if !(call_table.read_input_sector)(
                    self.device_idx,
                    sector,
                    self.l2_cache_buf,
                    sector_size,
                ) {
                    return None;
                }
                *bytes_read += sector_size as u64;
                self.l2_cached_sector = sector;

                let sector_byte_start = sector * sector_size as u64;
                let buf_start = if sector_byte_start < l2_table_offset {
                    (l2_table_offset - sector_byte_start) as usize
                } else {
                    0
                };
                let buf_end =
                    sector_size.min((l2_end_byte.saturating_sub(sector_byte_start)) as usize);
                if buf_end <= buf_start {
                    sector += 1;
                    continue;
                }

                let chunk = core::slice::from_raw_parts(
                    self.l2_cache_buf.add(buf_start),
                    buf_end - buf_start,
                );

                // Clamp to the L2 table's remaining meaningful bytes
                // (ignore any sector-padding tail at the end).
                let meaningful_len =
                    (cluster_size - l2_bytes_consumed).min((buf_end - buf_start) as u64) as usize;
                let meaningful = &chunk[..meaningful_len];

                // Virtual offset covered by the first entry of `meaningful`:
                // each L1 entry maps a contiguous `l2_coverage` range, and
                // within that range, the n-th 8-byte L2 entry covers
                // `n * cluster_size` of virtual space. `l2_bytes_consumed`
                // counts the L2-table bytes we've already walked, so its
                // entry-stride equivalent times `cluster_size` is the
                // offset of the first entry in this chunk.
                let entry_size_bytes: u64 = if extended_l2 { 16 } else { 8 };
                let base_virtual_offset = l1_index.saturating_mul(l2_coverage).saturating_add(
                    (l2_bytes_consumed / entry_size_bytes).saturating_mul(cluster_size),
                );

                allocated_bytes = allocated_bytes.saturating_add(if extended_l2 {
                    count_allocated_in_l2_extended(
                        meaningful,
                        cluster_size,
                        base_virtual_offset,
                        virtual_size,
                    )
                } else {
                    walk_l2_standard(
                        meaningful,
                        cluster_size,
                        base_virtual_offset,
                        virtual_size,
                        &mut tracker,
                    )
                });

                l2_bytes_consumed += meaningful_len as u64;
                sector += 1;
            }
        }

        // walk_l2_standard / count_allocated_in_l2_extended already skip
        // out-of-bounds L2 entries, so `allocated_bytes` is naturally
        // bounded — `clamp` here is defensive and reasserts the
        // AllocationSummary invariant at the scanner's return site.
        Some(AllocationSummary::clamp(
            virtual_size,
            allocated_bytes,
            tracker.target_units_with_data,
        ))
    }

    /// Walk the L1 / L2 tables and emit a coalesced `MapExtent`
    /// stream covering `[0, virtual_size)`.
    ///
    /// Reports the active layer only; backing-chain composition is
    /// the caller's responsibility (deferred — see PLAN-map.md).
    ///
    /// The walker mirrors `Qcow2State::scan_allocation` for sector
    /// reading and L1/L2 traversal but classifies each L2 entry via
    /// [`classify_qcow2_l2_standard`] or
    /// [`classify_qcow2_l2_extended`] and pushes the result through a
    /// `MapExtentCoalescer` wrapping the caller's `emit` callback.
    /// The coalescer persists across L2-table boundaries so a Data
    /// run spanning two L2 tables with contiguous file offsets
    /// collapses into one extent.
    ///
    /// L1 entries that are zero or whose L2 table offset is zero
    /// emit one `Hole` for the entire L2-coverage range (clamped
    /// against virtual_size). A trailing `Hole` is pushed for any
    /// virtual range past the last walked L1 entry up to
    /// `virtual_size`, so the emitted extents partition
    /// `[0, virtual_size)`.
    ///
    /// Returns `Some(())` on a successful walk (including early
    /// termination via `emit` returning `false`). Returns `None` on
    /// an I/O failure or adversarial L2 offset, matching
    /// `scan_allocation`'s convention.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. `l1_cache_buf` and `l2_cache_buf`
    /// must still point to at least `MAX_SECTOR_SIZE` writable bytes.
    pub unsafe fn map_extents<F: FnMut(MapExtent) -> bool>(
        &mut self,
        call_table: &CallTable,
        sector_size: usize,
        input_capacity: u64,
        virtual_size: u64,
        bytes_read: &mut u64,
        emit: &mut F,
    ) -> Option<()> {
        if virtual_size == 0 {
            return Some(());
        }

        let cluster_size = self.cluster_size;
        let extended_l2 = self.extended_l2;
        let l1_size = self.l1_size as u64;
        let l1_table_offset = self.l1_table_offset;

        let entry_size_bytes: u64 = if extended_l2 { 16 } else { 8 };
        let entries_per_l2: u64 = cluster_size / entry_size_bytes;
        let l2_coverage = cluster_size.checked_mul(entries_per_l2)?;

        let mut coalescer = MapExtentCoalescer::new(emit);
        // Virtual offset of the next byte we still need to cover.
        // Used to emit Hole records for unwalked L2 tables and to
        // detect the trailing hole at end-of-image.
        let mut next_unwalked: u64 = 0;

        'l1_loop: for l1_index in 0..l1_size {
            let l1_byte_offset = l1_table_offset.checked_add(l1_index.checked_mul(8)?)?;
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

            let l1_virtual_start = (l1_index).saturating_mul(l2_coverage);
            if l1_virtual_start >= virtual_size {
                // L1 entries past virtual_size cover no
                // guest-visible bytes; nothing to emit.
                continue;
            }
            let l1_remaining = virtual_size - l1_virtual_start;
            let l1_visible_span = l2_coverage.min(l1_remaining);

            let l2_table_offset = l1_entry & L2_OFFSET_MASK;
            if l2_table_offset == 0 {
                // Entire L2 coverage range is unallocated. Push one
                // Hole for the visible portion; the coalescer merges
                // it with adjacent same-state extents.
                let cont = coalescer.push(MapExtent {
                    start: l1_virtual_start,
                    length: l1_visible_span,
                    state: MapExtentState::Hole,
                });
                next_unwalked = l1_virtual_start.saturating_add(l1_visible_span);
                if !cont {
                    break 'l1_loop;
                }
                continue;
            }

            // Invalidate L2 cache before each new L2 (matches the
            // pattern in scan_allocation).
            self.l2_cached_sector = u64::MAX;

            // Reject obviously-invalid L2 offsets up front (mirrors
            // scan_allocation's defence).
            let device_byte_capacity = input_capacity.checked_mul(sector_size as u64)?;
            if l2_table_offset >= device_byte_capacity {
                return None;
            }
            let l2_end_byte = l2_table_offset.checked_add(cluster_size)?;
            let l2_start_sector = l2_table_offset / sector_size as u64;
            let l2_end_sector =
                l2_end_byte.checked_add(sector_size as u64 - 1)? / sector_size as u64;

            let mut l2_bytes_consumed: u64 = 0;

            let mut sector = l2_start_sector;
            while sector < l2_end_sector {
                if sector >= input_capacity {
                    return None;
                }
                if !(call_table.read_input_sector)(
                    self.device_idx,
                    sector,
                    self.l2_cache_buf,
                    sector_size,
                ) {
                    return None;
                }
                *bytes_read += sector_size as u64;
                self.l2_cached_sector = sector;

                let sector_byte_start = sector * sector_size as u64;
                let buf_start = if sector_byte_start < l2_table_offset {
                    (l2_table_offset - sector_byte_start) as usize
                } else {
                    0
                };
                let buf_end =
                    sector_size.min((l2_end_byte.saturating_sub(sector_byte_start)) as usize);
                if buf_end <= buf_start {
                    sector += 1;
                    continue;
                }

                let chunk = core::slice::from_raw_parts(
                    self.l2_cache_buf.add(buf_start),
                    buf_end - buf_start,
                );

                let meaningful_len =
                    (cluster_size - l2_bytes_consumed).min((buf_end - buf_start) as u64) as usize;
                let meaningful = &chunk[..meaningful_len];

                // Walk the entries in this chunk in virtual-offset
                // order. Each entry covers `cluster_size` of virtual
                // space; for extended L2 it occupies 16 bytes of L2
                // table, for standard L2 8 bytes.
                let chunk_entry_count = (meaningful_len as u64) / entry_size_bytes;
                let base_entry_index = l2_bytes_consumed / entry_size_bytes;

                for k in 0..chunk_entry_count {
                    let entry_byte_offset = (k as usize) * (entry_size_bytes as usize);
                    let l2_entry = u64::from_be_bytes([
                        meaningful[entry_byte_offset],
                        meaningful[entry_byte_offset + 1],
                        meaningful[entry_byte_offset + 2],
                        meaningful[entry_byte_offset + 3],
                        meaningful[entry_byte_offset + 4],
                        meaningful[entry_byte_offset + 5],
                        meaningful[entry_byte_offset + 6],
                        meaningful[entry_byte_offset + 7],
                    ]);
                    let global_entry_idx = base_entry_index + k;
                    let cluster_virt = l1_virtual_start
                        .saturating_add(global_entry_idx.saturating_mul(cluster_size));
                    if cluster_virt >= virtual_size {
                        // OOB cluster: don't emit; subsequent
                        // entries are also OOB so we can break.
                        break;
                    }
                    let cluster_visible = cluster_size.min(virtual_size - cluster_virt);

                    let cont = if extended_l2 {
                        let sc_bitmap = u64::from_be_bytes([
                            meaningful[entry_byte_offset + 8],
                            meaningful[entry_byte_offset + 9],
                            meaningful[entry_byte_offset + 10],
                            meaningful[entry_byte_offset + 11],
                            meaningful[entry_byte_offset + 12],
                            meaningful[entry_byte_offset + 13],
                            meaningful[entry_byte_offset + 14],
                            meaningful[entry_byte_offset + 15],
                        ]);
                        classify_qcow2_l2_extended(
                            l2_entry,
                            sc_bitmap,
                            cluster_virt,
                            cluster_size,
                            cluster_visible,
                            &mut coalescer,
                        )
                    } else {
                        let mut ext =
                            classify_qcow2_l2_standard(l2_entry, cluster_virt, cluster_size);
                        // Clamp to virtual_size for end-of-image
                        // clusters.
                        if ext.length > cluster_visible {
                            ext.length = cluster_visible;
                        }
                        coalescer.push(ext)
                    };

                    next_unwalked = cluster_virt.saturating_add(cluster_visible);

                    if !cont {
                        // Abort the entire walk; the coalescer has
                        // already noted the abort and any further
                        // push/finish call will short-circuit.
                        break 'l1_loop;
                    }
                }

                l2_bytes_consumed += meaningful_len as u64;
                sector += 1;
            }
        }

        // Trailing hole: any virtual range past the last walked
        // cluster up to virtual_size must be emitted so the output
        // partitions [0, virtual_size).
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
// Cluster data reading
// ============================================================================

/// Read `cluster_size` bytes starting at the byte offset `host_offset`,
/// byte-accurately.
///
/// Neither `host_offset` nor `cluster_size` need be a multiple of
/// `sector_size`: the covering boundary sectors are read through a stack
/// scratch and only the requested byte run is copied into `buf`, while full
/// interior sectors are read straight in. This lets callers request an
/// arbitrary sub-sector window (as a non-cluster-aligned `dd` window does).
///
/// When `host_offset` is sector-aligned and `cluster_size` is a multiple of
/// `sector_size`, the original whole-sector-into-`buf` fast path runs and is
/// byte-identical to before, so whole-image convert is unaffected.
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
    let ssz = sector_size as u64;
    let first_sector = host_offset / ssz;
    let offset_in_sector = (host_offset % ssz) as usize;

    // Fast path: sector-aligned start and a whole number of sectors. This is
    // the whole-image convert path and must stay byte-identical.
    if offset_in_sector == 0 && cluster_size >= ssz && cluster_size.is_multiple_of(ssz) {
        let sectors_per_cluster = cluster_size / ssz;
        for i in 0..sectors_per_cluster {
            let sector = first_sector + i;
            let buf_offset = (i as usize) * sector_size;
            if !(call_table.read_input_sector)(device_idx, sector, buf.add(buf_offset), sector_size)
            {
                return false;
            }
            *bytes_read += ssz;
        }
        return true;
    }

    // Byte-accurate path. Walk the covering sectors, reading boundary
    // (partial) sectors through a scratch and copying only the requested
    // bytes; full interior sectors read straight into `buf`.
    let mut sector = first_sector;
    let mut produced: u64 = 0;
    let mut sector_off = offset_in_sector as u64;
    let mut scratch = [0u8; MAX_SECTOR_SIZE];

    while produced < cluster_size {
        let avail = ssz - sector_off;
        let want = core::cmp::min(avail, cluster_size - produced);

        if sector_off == 0 && want == ssz {
            if !(call_table.read_input_sector)(
                device_idx,
                sector,
                buf.add(produced as usize),
                sector_size,
            ) {
                return false;
            }
        } else {
            if !(call_table.read_input_sector)(
                device_idx,
                sector,
                scratch.as_mut_ptr(),
                sector_size,
            ) {
                return false;
            }
            core::ptr::copy_nonoverlapping(
                scratch.as_ptr().add(sector_off as usize),
                buf.add(produced as usize),
                want as usize,
            );
        }

        *bytes_read += ssz;
        produced += want;
        sector += 1;
        sector_off = 0;
    }
    true
}

/// Read data starting at an arbitrary byte offset that may not be
/// sector-aligned.
///
/// VHD data blocks are addressed in 512-byte sectors, but the device
/// sector size may be larger (e.g. 65536 bytes). When the data start
/// offset falls inside a sector, this function reads the first sector
/// into `scratch` and copies the relevant tail, then reads the
/// remaining sectors directly into `buf`.
///
/// `scratch` is a caller-provided buffer used for partial-sector reads
/// so that `buf` is not overwritten beyond `chunk_size` bytes.
///
/// # Safety
///
/// `buf` must point to at least `max(chunk_size, sector_size)` writable
/// bytes.  `scratch` must point to at least `sector_size` writable bytes.
/// `call_table` must be valid.
#[cfg(any(
    feature = "vhd-input",
    feature = "vdi-input",
    feature = "parallels-input",
    feature = "qcow1-input",
    feature = "dmg-input"
))]
unsafe fn read_offset_sectors(
    call_table: &CallTable,
    device_idx: u32,
    host_offset: u64,
    buf: *mut u8,
    chunk_size: u64,
    sector_size: usize,
    scratch: *mut u8,
    bytes_read: &mut u64,
) -> bool {
    let first_sector = host_offset / sector_size as u64;
    let off_in_sector = (host_offset % sector_size as u64) as usize;
    let first_useful = sector_size - off_in_sector;
    if !(call_table.read_input_sector)(device_idx, first_sector, scratch, sector_size) {
        return false;
    }
    *bytes_read += sector_size as u64;
    let first_copy = if (chunk_size as usize) < first_useful {
        chunk_size as usize
    } else {
        first_useful
    };
    core::ptr::copy_nonoverlapping(scratch.add(off_in_sector), buf, first_copy);

    if chunk_size as usize <= first_useful {
        return true;
    }

    // Read remaining full sectors directly into buf
    let mut buf_pos = first_copy;
    let mut sector = first_sector + 1;
    let mut remaining = chunk_size as usize - first_copy;

    while remaining > 0 {
        let copy_len = if remaining < sector_size {
            // Last partial sector: read into scratch, copy
            if !(call_table.read_input_sector)(device_idx, sector, scratch, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(scratch, buf.add(buf_pos), remaining);
            *bytes_read += sector_size as u64;
            break;
        } else {
            sector_size
        };
        if !(call_table.read_input_sector)(device_idx, sector, buf.add(buf_pos), sector_size) {
            return false;
        }
        *bytes_read += sector_size as u64;
        buf_pos += copy_len;
        sector += 1;
        remaining -= copy_len;
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
    let last_sector = data_end.div_ceil(sector_size as u64);
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
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_area_end_empty_region() {
        // EXT_END immediately at `start`: a zeroed cluster reads
        // (type=0, len=0) and stops right after the 8-byte header.
        let cluster = [0u8; 256];
        assert_eq!(header_extension_area_end(&cluster, 72), Some(80));
    }

    #[test]
    fn ext_area_end_one_backing_format_ext() {
        // One backing-format extension (type 0xE2792ACA, len 5 =
        // "qcow2"), then EXT_END.
        let mut cluster = [0u8; 256];
        let start = 72usize;
        // ext header: type + len
        cluster[start..start + 4].copy_from_slice(&EXT_BACKING_FORMAT.to_be_bytes());
        cluster[start + 4..start + 8].copy_from_slice(&5u32.to_be_bytes());
        cluster[start + 8..start + 13].copy_from_slice(b"qcow2");
        // padded body len = 8, so EXT_END at start + 8 + 8 = 88.
        // EXT_END is already zeros; its header is at 88, end = 96.
        assert_eq!(
            header_extension_area_end(&cluster, start),
            Some(start + 16 + 8)
        );
    }

    #[test]
    fn ext_area_end_truncated_chain_is_none() {
        // A non-EXT_END record whose body runs past the buffer end,
        // and no EXT_END terminator -> None.
        let mut cluster = [0u8; 24];
        cluster[0..4].copy_from_slice(&EXT_BACKING_FORMAT.to_be_bytes());
        // len = 100 (way past the 24-byte buffer).
        cluster[4..8].copy_from_slice(&100u32.to_be_bytes());
        assert_eq!(header_extension_area_end(&cluster, 0), None);
    }

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
    fn parse_rejects_oversized_l1() {
        // Header claims l1_size = 4 * 1024 * 1024 + 1 entries, exceeding
        // the absolute QCOW2_MAX_L1_SIZE_ENTRIES cap.
        let mut buf = make_qcow2_header();
        let bad_l1 = QCOW2_MAX_L1_SIZE_ENTRIES + 1;
        buf[L1_SIZE_OFFSET..L1_SIZE_OFFSET + 4].copy_from_slice(&bad_l1.to_be_bytes());
        assert!(QcowHeader::parse(&buf).is_none());
    }

    #[test]
    fn parse_rejects_unaddressable_virtual_size() {
        // A near-u64::MAX virtual size cannot be mapped by any legal L1
        // table (qemu refuses such an image as "too large"). Regression
        // for issue #438: a safe-mode rebase overlay with this header
        // drove `cluster_count * cluster_size` past u64::MAX. Uses the
        // exact geometry from the fuzz reproducer (1 KiB clusters).
        let mut buf = make_qcow2_header();
        buf[CLUSTER_BITS_OFFSET..CLUSTER_BITS_OFFSET + 4].copy_from_slice(&10u32.to_be_bytes());
        buf[SIZE_OFFSET..SIZE_OFFSET + 8].copy_from_slice(&0xffff_ffff_ffff_ff35u64.to_be_bytes());
        assert!(QcowHeader::parse(&buf).is_none());
    }

    #[test]
    fn parse_accepts_max_addressable_virtual_size() {
        // Boundary: the largest virtual size whose L1 requirement is
        // exactly QCOW2_MAX_L1_SIZE_ENTRIES is accepted, and its cluster
        // extent stays within u64.
        let mut buf = make_qcow2_header();
        let cluster_size = 1u64 << 16; // matches make_qcow2_header cluster_bits
        let l2_coverage = cluster_size * (cluster_size / 8);
        let vsize = QCOW2_MAX_L1_SIZE_ENTRIES as u64 * l2_coverage;
        buf[SIZE_OFFSET..SIZE_OFFSET + 8].copy_from_slice(&vsize.to_be_bytes());
        let hdr = QcowHeader::parse(&buf).unwrap();
        assert_eq!(hdr.virtual_size, vsize);
        assert!(hdr
            .virtual_size
            .div_ceil(hdr.cluster_size)
            .checked_mul(hdr.cluster_size)
            .is_some());
    }

    #[test]
    fn parse_accepts_l1_at_cap() {
        // Boundary: exactly QCOW2_MAX_L1_SIZE_ENTRIES is accepted.
        let mut buf = make_qcow2_header();
        buf[L1_SIZE_OFFSET..L1_SIZE_OFFSET + 4]
            .copy_from_slice(&QCOW2_MAX_L1_SIZE_ENTRIES.to_be_bytes());
        let hdr = QcowHeader::parse(&buf).unwrap();
        assert_eq!(hdr.l1_size, QCOW2_MAX_L1_SIZE_ENTRIES);
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
        assert_eq!(
            parse_header_extensions(&buf, &hdr).backing_format,
            BackingFormat::None,
        );
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

        let result = parse_header_extensions(&buf, &hdr);
        assert_eq!(result.backing_format, BackingFormat::Qcow2);
        assert_eq!(result.data_file_name_len, 0);
    }

    #[test]
    fn header_extensions_empty_returns_none() {
        let mut buf = make_qcow2_header();
        let hdr = QcowHeader::parse(&buf).unwrap();
        // Place end-of-extensions immediately
        let ext_off = 112;
        buf[ext_off..ext_off + 4].copy_from_slice(&EXT_END.to_be_bytes());

        assert_eq!(
            parse_header_extensions(&buf, &hdr).backing_format,
            BackingFormat::None,
        );
    }

    // ---- parse_header_extensions: bitmaps ----

    /// Write a 24-byte EXT_BITMAPS body at `off` and an EXT_END terminator
    /// after its (already-8-byte-aligned) padding. Returns nothing; mutates
    /// `buf` in place.
    fn poke_bitmaps_extension(
        buf: &mut [u8; 512],
        off: usize,
        nb_bitmaps: u32,
        dir_size: u64,
        dir_offset: u64,
    ) {
        buf[off..off + 4].copy_from_slice(&EXT_BITMAPS.to_be_bytes());
        buf[off + 4..off + 8].copy_from_slice(&24u32.to_be_bytes());
        let body = off + 8;
        buf[body..body + 4].copy_from_slice(&nb_bitmaps.to_be_bytes());
        // reserved @body+4 left zero
        buf[body + 8..body + 16].copy_from_slice(&dir_size.to_be_bytes());
        buf[body + 16..body + 24].copy_from_slice(&dir_offset.to_be_bytes());
        // 24 is already a multiple of 8: EXT_END follows immediately.
        let next = body + 24;
        buf[next..next + 4].copy_from_slice(&EXT_END.to_be_bytes());
    }

    #[test]
    fn header_extensions_bitmaps_present_when_autoclear_set() {
        let mut buf = make_qcow2_header();
        // Autoclear bit 0 set ⇒ bitmaps are consistent/usable.
        buf[AUTOCLEAR_FEATURES_OFFSET..AUTOCLEAR_FEATURES_OFFSET + 8]
            .copy_from_slice(&1u64.to_be_bytes());
        // header_length=112, so extensions start at offset 112.
        poke_bitmaps_extension(&mut buf, 112, 3, 2048, 0x50000);

        let hdr = QcowHeader::parse(&buf).unwrap();
        let result = parse_header_extensions(&buf, &hdr);
        assert!(result.bitmaps_present);
        assert!(!result.bitmaps_inconsistent);
        assert_eq!(result.bitmap_nb_bitmaps, 3);
        assert_eq!(result.bitmap_directory_size, 2048);
        assert_eq!(result.bitmap_directory_offset, 0x50000);
    }

    #[test]
    fn header_extensions_bitmaps_inconsistent_when_autoclear_clear() {
        let mut buf = make_qcow2_header();
        // Autoclear bit 0 left clear ⇒ extension present but stale.
        poke_bitmaps_extension(&mut buf, 112, 3, 2048, 0x50000);

        let hdr = QcowHeader::parse(&buf).unwrap();
        let result = parse_header_extensions(&buf, &hdr);
        assert!(!result.bitmaps_present);
        assert!(result.bitmaps_inconsistent);
        // The parsed offsets are still recorded for diagnostics.
        assert_eq!(result.bitmap_nb_bitmaps, 3);
        assert_eq!(result.bitmap_directory_size, 2048);
        assert_eq!(result.bitmap_directory_offset, 0x50000);
    }

    #[test]
    fn header_extensions_no_bitmaps_extension() {
        let mut buf = make_qcow2_header();
        // Set the autoclear bit, but provide no bitmaps extension.
        buf[AUTOCLEAR_FEATURES_OFFSET..AUTOCLEAR_FEATURES_OFFSET + 8]
            .copy_from_slice(&1u64.to_be_bytes());
        let ext_off = 112;
        buf[ext_off..ext_off + 4].copy_from_slice(&EXT_END.to_be_bytes());

        let hdr = QcowHeader::parse(&buf).unwrap();
        let result = parse_header_extensions(&buf, &hdr);
        assert!(!result.bitmaps_present);
        assert!(!result.bitmaps_inconsistent);
        assert_eq!(result.bitmap_nb_bitmaps, 0);
        assert_eq!(result.bitmap_directory_size, 0);
        assert_eq!(result.bitmap_directory_offset, 0);
    }

    // ---- validate_subcluster_bitmap ----

    #[test]
    fn sc_bitmap_ok_all_allocated() {
        // All 32 subclusters allocated, none zeroed, host != 0
        let bitmap: u64 = 0x00000000_FFFFFFFF;
        assert_eq!(
            validate_subcluster_bitmap(false, 0x10000, bitmap),
            SubclusterBitmapStatus::Ok,
        );
    }

    #[test]
    fn sc_bitmap_ok_all_zero_plain() {
        // All 32 subclusters zero-plain (l2e == 0, host == 0)
        let bitmap: u64 = 0xFFFFFFFF_00000000;
        assert_eq!(
            validate_subcluster_bitmap(false, 0, bitmap),
            SubclusterBitmapStatus::Ok,
        );
    }

    #[test]
    fn sc_bitmap_ok_mixed_alloc_zero() {
        // First 16 subclusters allocated, next 8 zero, last 8 unallocated
        // alloc_bits = 0x0000FFFF, zero_bits = 0x00FF0000
        let alloc_bits: u64 = 0x0000FFFF;
        let zero_bits: u64 = 0x00FF0000;
        let bitmap = (zero_bits << 32) | alloc_bits;
        assert_eq!(
            validate_subcluster_bitmap(false, 0x10000, bitmap),
            SubclusterBitmapStatus::Ok,
        );
    }

    #[test]
    fn sc_bitmap_ok_all_unallocated() {
        // l2e == 0, bitmap == 0 → unallocated (not reached via validator
        // in practice, but should be Ok)
        assert_eq!(
            validate_subcluster_bitmap(false, 0, 0),
            SubclusterBitmapStatus::Ok,
        );
    }

    #[test]
    fn sc_bitmap_ok_host_with_zero_only() {
        // Host cluster present, all subclusters are zero-plain
        // (data was written then zeroed; host not yet freed)
        let bitmap: u64 = 0xFFFFFFFF_00000000;
        assert_eq!(
            validate_subcluster_bitmap(false, 0x10000, bitmap),
            SubclusterBitmapStatus::Ok,
        );
    }

    #[test]
    fn sc_bitmap_ok_compressed_zero() {
        // Compressed entry with bitmap == 0 (spec-compliant)
        assert_eq!(
            validate_subcluster_bitmap(true, 0, 0),
            SubclusterBitmapStatus::Ok,
        );
    }

    #[test]
    fn sc_bitmap_ok_compressed_legacy_qemu() {
        // Compressed entry with alloc_bits == 0xFFFF_FFFF, zero_bits == 0
        // (legacy QEMU pattern, accepted for compatibility)
        let bitmap: u64 = 0x00000000_FFFFFFFF;
        assert_eq!(
            validate_subcluster_bitmap(true, 0, bitmap),
            SubclusterBitmapStatus::Ok,
        );
    }

    #[test]
    fn sc_bitmap_err_alloc_and_zero_overlap() {
        // I1: subcluster 0 is both allocated and zero
        let bitmap: u64 = (1u64 << 32) | 1; // zero_bits bit 0 + alloc_bits bit 0
        assert_eq!(
            validate_subcluster_bitmap(false, 0x10000, bitmap),
            SubclusterBitmapStatus::AllocAndZeroOverlap,
        );
    }

    #[test]
    fn sc_bitmap_err_alloc_and_zero_overlap_no_host() {
        // I5/I1: l2e == 0, subcluster simultaneously alloc+zero
        let bitmap: u64 = (1u64 << 32) | 1;
        assert_eq!(
            validate_subcluster_bitmap(false, 0, bitmap),
            SubclusterBitmapStatus::AllocAndZeroOverlap,
        );
    }

    #[test]
    fn sc_bitmap_err_alloc_without_host() {
        // I2: alloc bits set but host_offset == 0
        let bitmap: u64 = 0x0000FFFF;
        assert_eq!(
            validate_subcluster_bitmap(false, 0, bitmap),
            SubclusterBitmapStatus::AllocWithoutHost,
        );
    }

    #[test]
    fn sc_bitmap_err_host_without_ref() {
        // I3: host cluster present but both bitmap halves are 0
        assert_eq!(
            validate_subcluster_bitmap(false, 0x10000, 0),
            SubclusterBitmapStatus::HostWithoutRef,
        );
    }

    #[test]
    fn sc_bitmap_err_compressed_nonzero() {
        // C1: compressed entry with a partial alloc bitmap
        let bitmap: u64 = 0x0000000F;
        assert_eq!(
            validate_subcluster_bitmap(true, 0, bitmap),
            SubclusterBitmapStatus::CompressedNonZero,
        );
    }

    #[test]
    fn sc_bitmap_err_compressed_zero_bits_set() {
        // C1: compressed entry with zero_bits set (even though alloc_bits == 0)
        let bitmap: u64 = 0x00010000_00000000;
        assert_eq!(
            validate_subcluster_bitmap(true, 0, bitmap),
            SubclusterBitmapStatus::CompressedNonZero,
        );
    }

    #[test]
    fn sc_bitmap_err_compressed_legacy_plus_zero_bits() {
        // C1: compressed entry with legacy alloc pattern BUT
        // also has zero_bits set — should be flagged
        let bitmap: u64 = 0x00010000_FFFFFFFF;
        assert_eq!(
            validate_subcluster_bitmap(true, 0, bitmap),
            SubclusterBitmapStatus::CompressedNonZero,
        );
    }

    // ---- count_allocated_in_l2_standard ----

    /// Write a u64-be entry into `buf` at entry index `i`.
    fn put_std_entry(buf: &mut [u8], i: usize, entry: u64) {
        buf[i * 8..i * 8 + 8].copy_from_slice(&entry.to_be_bytes());
    }

    /// Write an extended-L2 pair (l2_entry, sc_bitmap) at index `i`.
    fn put_ext_entry(buf: &mut [u8], i: usize, l2_entry: u64, sc_bitmap: u64) {
        buf[i * 16..i * 16 + 8].copy_from_slice(&l2_entry.to_be_bytes());
        buf[i * 16 + 8..i * 16 + 16].copy_from_slice(&sc_bitmap.to_be_bytes());
    }

    #[test]
    fn count_l2_standard_empty_slice() {
        assert_eq!(count_allocated_in_l2_standard(&[], 65536), 0);
    }

    #[test]
    fn count_l2_standard_all_zero_entries() {
        let buf = [0u8; 64]; // 8 entries, all zero
        assert_eq!(count_allocated_in_l2_standard(&buf, 65536), 0);
    }

    #[test]
    fn count_l2_standard_three_of_four_allocated() {
        // cluster_size = 64 KiB; 3 of 4 entries allocated → 3 * 65536.
        let mut buf = [0u8; 32];
        put_std_entry(&mut buf, 0, 0x50000);
        put_std_entry(&mut buf, 1, 0);
        put_std_entry(&mut buf, 2, 0x60000);
        put_std_entry(&mut buf, 3, 0x70000);
        assert_eq!(count_allocated_in_l2_standard(&buf, 65536), 3 * 65536);
    }

    #[test]
    fn count_l2_standard_compressed_entry_counts_as_allocated() {
        // OFLAG_COMPRESSED set; the standard helper treats any non-zero
        // entry as allocated (mirrors `cluster_lookup`'s Compressed
        // branch, which is also "data here").
        let mut buf = [0u8; 8];
        put_std_entry(&mut buf, 0, OFLAG_COMPRESSED | 0xDEAD);
        assert_eq!(count_allocated_in_l2_standard(&buf, 65536), 65536);
    }

    #[test]
    fn count_l2_standard_cluster_size_512() {
        // Boundary: small but legal cluster_size. 1 entry × 512.
        let mut buf = [0u8; 8];
        put_std_entry(&mut buf, 0, 0x1000);
        assert_eq!(count_allocated_in_l2_standard(&buf, 512), 512);
    }

    #[test]
    fn count_l2_standard_cluster_size_2mib() {
        // Boundary: maximum cluster_size, single allocated entry.
        let mut buf = [0u8; 8];
        put_std_entry(&mut buf, 0, 0x80000);
        assert_eq!(
            count_allocated_in_l2_standard(&buf, 2 * 1024 * 1024),
            2 * 1024 * 1024,
        );
    }

    #[test]
    fn count_l2_standard_trailing_partial_entry_ignored() {
        // 1 complete 8-byte entry (allocated) + 1 zero entry +
        // 1 byte tail — the tail must be ignored.
        let mut buf = [0u8; 17];
        put_std_entry(&mut buf, 0, 0x1234);
        // entry 1 stays zero
        buf[16] = 0xAB; // partial tail — must be dropped
        assert_eq!(count_allocated_in_l2_standard(&buf, 65536), 65536);
    }

    #[test]
    fn count_l2_standard_zero_cluster_size_defensive() {
        let mut buf = [0u8; 16];
        put_std_entry(&mut buf, 0, 0x1234);
        put_std_entry(&mut buf, 1, 0x5678);
        assert_eq!(count_allocated_in_l2_standard(&buf, 0), 0);
    }

    // ---- count_allocated_in_l2_extended ----

    #[test]
    fn count_l2_extended_empty_slice() {
        assert_eq!(count_allocated_in_l2_extended(&[], 65536, 0, u64::MAX), 0);
    }

    #[test]
    fn count_l2_extended_all_zero_entries() {
        // 3 pairs, all l2_entry=0, sc_bitmap=0 → unallocated.
        let buf = [0u8; 48];
        assert_eq!(count_allocated_in_l2_extended(&buf, 65536, 0, u64::MAX), 0);
    }

    #[test]
    fn count_l2_extended_zero_entry_with_all_zero_subclusters() {
        // l2_entry=0, alloc_bits=0, zero_bits=0xFFFF_FFFF → all
        // explicit zero subclusters. Source-byte count is 0 (logically
        // zero, no host bytes).
        let bitmap: u64 = (0xFFFF_FFFFu64) << 32;
        let mut buf = [0u8; 16];
        put_ext_entry(&mut buf, 0, 0, bitmap);
        assert_eq!(count_allocated_in_l2_extended(&buf, 65536, 0, u64::MAX), 0);
    }

    #[test]
    fn count_l2_extended_full_subcluster_alloc_counts_as_cluster() {
        // alloc_bits = 0xFFFF_FFFF, zero_bits = 0 → whole cluster.
        let bitmap: u64 = 0x0000_0000_FFFF_FFFF;
        let mut buf = [0u8; 16];
        put_ext_entry(&mut buf, 0, 0x50000, bitmap);
        assert_eq!(
            count_allocated_in_l2_extended(&buf, 65536, 0, u64::MAX),
            65536
        );
    }

    #[test]
    fn count_l2_extended_partial_subcluster_alloc() {
        // alloc_bits = 0x0000_00FF (8 subclusters set) with
        // cluster_size = 65536 → subcluster_size = 2048. Expected:
        // 8 * 2048 = 16384.
        let bitmap: u64 = 0x0000_0000_0000_00FF;
        let mut buf = [0u8; 16];
        put_ext_entry(&mut buf, 0, 0x50000, bitmap);
        assert_eq!(
            count_allocated_in_l2_extended(&buf, 65536, 0, u64::MAX),
            8 * 2048
        );
    }

    #[test]
    fn count_l2_extended_compressed_entry_counts_as_cluster() {
        // OFLAG_COMPRESSED set → counts as full cluster regardless of
        // bitmap (compressed entries carry whole-cluster data).
        let mut buf = [0u8; 16];
        put_ext_entry(&mut buf, 0, OFLAG_COMPRESSED | 0xDEAD, 0);
        assert_eq!(
            count_allocated_in_l2_extended(&buf, 65536, 0, u64::MAX),
            65536
        );
    }

    #[test]
    fn count_l2_extended_mixed_entries() {
        // Four entries: unallocated, fully allocated, partial (4 sc),
        // compressed.
        let full: u64 = 0x0000_0000_FFFF_FFFF;
        let partial: u64 = 0x0000_0000_0000_000F; // 4 subclusters
        let mut buf = [0u8; 64];
        put_ext_entry(&mut buf, 0, 0, 0);
        put_ext_entry(&mut buf, 1, 0x10000, full);
        put_ext_entry(&mut buf, 2, 0x20000, partial);
        put_ext_entry(&mut buf, 3, OFLAG_COMPRESSED | 0xCAFE, 0);
        // 0 + 65536 + (4 * 2048) + 65536 = 139264.
        assert_eq!(
            count_allocated_in_l2_extended(&buf, 65536, 0, u64::MAX),
            65536 + 4 * 2048 + 65536,
        );
    }

    #[test]
    fn count_l2_extended_partial_with_cluster_size_2mib() {
        // 2 MiB cluster, subcluster_size = 65536. alloc_bits with 16
        // bits set → 16 * 65536 = 1 MiB.
        let bitmap: u64 = 0x0000_0000_0000_FFFF;
        let mut buf = [0u8; 16];
        put_ext_entry(&mut buf, 0, 0x100000, bitmap);
        assert_eq!(
            count_allocated_in_l2_extended(&buf, 2 * 1024 * 1024, 0, u64::MAX),
            16 * 65536,
        );
    }

    #[test]
    fn count_l2_extended_trailing_partial_pair_ignored() {
        // One complete 16-byte pair (fully allocated) plus a 2-byte
        // tail — the tail must be ignored.
        let full: u64 = 0x0000_0000_FFFF_FFFF;
        let mut buf = [0u8; 18];
        put_ext_entry(&mut buf, 0, 0x50000, full);
        buf[16] = 0xAB; // partial tail
        buf[17] = 0xCD;
        assert_eq!(
            count_allocated_in_l2_extended(&buf, 65536, 0, u64::MAX),
            65536
        );
    }

    #[test]
    fn count_l2_extended_zero_cluster_size_defensive() {
        let full: u64 = 0x0000_0000_FFFF_FFFF;
        let mut buf = [0u8; 16];
        put_ext_entry(&mut buf, 0, 0x50000, full);
        assert_eq!(count_allocated_in_l2_extended(&buf, 0, 0, u64::MAX), 0);
    }

    #[test]
    fn count_l2_extended_zero_entry_with_partial_zero_bits() {
        // l2_entry == 0 with some zero_bits set (and alloc_bits == 0):
        // matches the "StandardSubclusters(0, bitmap)" cluster_lookup
        // branch — but logically zero, so 0 source bytes.
        let bitmap: u64 = 0x0000_FFFF_0000_0000; // 16 zero subclusters
        let mut buf = [0u8; 16];
        put_ext_entry(&mut buf, 0, 0, bitmap);
        assert_eq!(count_allocated_in_l2_extended(&buf, 65536, 0, u64::MAX), 0);
    }

    // ---- TargetUnitTracker / walk_l2_standard (bug #286) ----

    #[test]
    fn tracker_disabled_when_unit_size_zero() {
        let mut t = TargetUnitTracker::new(0);
        t.observe_allocated(0, 4096);
        t.observe_allocated(4096, 4096);
        assert_eq!(t.target_units_with_data, 0);
    }

    #[test]
    fn tracker_counts_distinct_target_units() {
        // Two source clusters at offsets 8192 and 65536, target 64K.
        // Reproduces the qcow2-source half of the seed-37 failure
        // described in issue #286: each falls in a different target
        // cluster, so the count is 2 (not the 1 you would get from
        // ceil_div(8192, 65536)).
        let mut t = TargetUnitTracker::new(65536);
        t.observe_allocated(8192, 4096);
        t.observe_allocated(65536, 4096);
        assert_eq!(t.target_units_with_data, 2);
    }

    #[test]
    fn tracker_does_not_double_count_within_one_target_unit() {
        // Two adjacent 4K source clusters in the same 64K target unit.
        let mut t = TargetUnitTracker::new(65536);
        t.observe_allocated(0, 4096);
        t.observe_allocated(4096, 4096);
        assert_eq!(t.target_units_with_data, 1);
    }

    #[test]
    fn tracker_counts_partial_overlap_into_next_target_unit() {
        // One large source extent that straddles a target boundary.
        let mut t = TargetUnitTracker::new(65536);
        t.observe_allocated(60000, 10000); // crosses 65536
        assert_eq!(t.target_units_with_data, 2);
    }

    #[test]
    fn tracker_handles_target_smaller_than_source() {
        // Target unit smaller than source: each 64K source cluster
        // spans 16 target 4K units.
        let mut t = TargetUnitTracker::new(4096);
        t.observe_allocated(0, 65536);
        assert_eq!(t.target_units_with_data, 16);
    }

    #[test]
    fn walk_l2_standard_records_target_units() {
        // L2 with 3 non-zero entries at index 0, 16, 17 (cluster_size 4K,
        // target unit 64K → entry 0 → unit 0; entries 16,17 → unit 1).
        let mut buf = [0u8; 64 * 8];
        put_std_entry(&mut buf, 0, 0x1);
        put_std_entry(&mut buf, 16, 0x2);
        put_std_entry(&mut buf, 17, 0x3);
        let mut t = TargetUnitTracker::new(65536);
        let allocated = walk_l2_standard(&buf, 4096, 0, u64::MAX, &mut t);
        assert_eq!(allocated, 3 * 4096);
        // Entry 0 covers virtual [0, 4096) → unit 0.
        // Entry 16 covers virtual [65536, 69632) → unit 1.
        // Entry 17 covers virtual [69632, 73728) → unit 1 (same as prev).
        assert_eq!(t.target_units_with_data, 2);
    }

    #[test]
    fn walk_l2_standard_with_base_offset() {
        // Same buffer but starting at an L1-offset of 1 GiB. The base
        // offset must shift the per-entry virtual ranges.
        let mut buf = [0u8; 8 * 8];
        put_std_entry(&mut buf, 0, 0x1);
        let mut t = TargetUnitTracker::new(65536);
        let _ = walk_l2_standard(&buf, 4096, 1 << 30, u64::MAX, &mut t);
        // After the call, last_unit_idx should reflect the high offset.
        assert_eq!(t.last_unit_idx, (1u64 << 30) / 65536);
    }

    // ---- OOB L2 entry skipping ----
    // qcow2 L1 table coverage often exceeds virtual_size; on-disk L2
    // entries past virtual_size are legal but describe clusters with
    // no guest-visible meaning. The walkers must skip them so the
    // invariants allocated_bytes <= virtual_size and
    // target_units_with_data <= virtual_size.div_ceil(target_unit)
    // hold. Regression for github.com/shakenfist/instar issues #292,
    // #295, #297, #304, #308, #313, #317, #321, #330, #338.

    #[test]
    fn walk_l2_standard_skips_entries_past_virtual_size() {
        // 4 non-zero entries, cluster 4K. virtual_size = 8K → only the
        // first two entries are in-bounds.
        let mut buf = [0u8; 4 * 8];
        put_std_entry(&mut buf, 0, 0x1);
        put_std_entry(&mut buf, 1, 0x2);
        put_std_entry(&mut buf, 2, 0x3);
        put_std_entry(&mut buf, 3, 0x4);
        let mut t = TargetUnitTracker::new(0);
        let allocated = walk_l2_standard(&buf, 4096, 0, 8192, &mut t);
        assert_eq!(allocated, 2 * 4096);
    }

    #[test]
    fn walk_l2_standard_caps_straddling_last_cluster() {
        // virtual_size = 6000; the second 4K cluster (at offset 4096)
        // straddles virtual_size. In-bounds portion = 6000 - 4096 = 1904.
        let mut buf = [0u8; 4 * 8];
        put_std_entry(&mut buf, 0, 0x1);
        put_std_entry(&mut buf, 1, 0x2);
        let mut t = TargetUnitTracker::new(0);
        let allocated = walk_l2_standard(&buf, 4096, 0, 6000, &mut t);
        assert_eq!(allocated, 4096 + 1904);
    }

    #[test]
    fn walk_l2_standard_oob_keeps_target_units_within_cap() {
        // The bug-286 invariant: target_units_with_data must not exceed
        // virtual_size.div_ceil(target_unit_size). With OOB entries the
        // pre-fix code would inflate this; the fix keeps it bounded.
        let mut buf = [0u8; 4 * 8];
        for i in 0..4 {
            put_std_entry(&mut buf, i, 0x1);
        }
        let virtual_size: u64 = 8192;
        let target_unit: u64 = 4096;
        let mut t = TargetUnitTracker::new(target_unit);
        let _ = walk_l2_standard(&buf, 4096, 0, virtual_size, &mut t);
        let cap = virtual_size.div_ceil(target_unit);
        assert!(
            t.target_units_with_data <= cap,
            "target_units_with_data {} > cap {}",
            t.target_units_with_data,
            cap,
        );
    }

    #[test]
    fn count_l2_extended_skips_entries_past_virtual_size() {
        // Two pairs, both fully allocated. virtual_size = cluster_size so
        // only the first is in-bounds.
        let full: u64 = 0x0000_0000_FFFF_FFFF;
        let mut buf = [0u8; 32];
        put_ext_entry(&mut buf, 0, 0x10000, full);
        put_ext_entry(&mut buf, 1, 0x20000, full);
        assert_eq!(count_allocated_in_l2_extended(&buf, 65536, 0, 65536), 65536,);
    }

    #[test]
    fn count_l2_extended_caps_straddling_last_cluster() {
        // One fully-allocated extended-L2 entry, virtual_size = 30000.
        // Contribution capped at 30000 - 0 = 30000 (not the full 65536).
        let full: u64 = 0x0000_0000_FFFF_FFFF;
        let mut buf = [0u8; 16];
        put_ext_entry(&mut buf, 0, 0x10000, full);
        assert_eq!(count_allocated_in_l2_extended(&buf, 65536, 0, 30000), 30000,);
    }

    // ====================================================================
    // classify_qcow2_l2_standard tests
    // ====================================================================

    #[test]
    fn classify_standard_zero_is_hole() {
        let e = classify_qcow2_l2_standard(0, 0, 65536);
        assert_eq!(e.start, 0);
        assert_eq!(e.length, 65536);
        assert_eq!(e.state, MapExtentState::Hole);
    }

    #[test]
    fn classify_standard_normal_is_data() {
        // host_offset = 0x50000, no flag bits.
        let e = classify_qcow2_l2_standard(0x0005_0000, 0, 65536);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 0x0005_0000
            }
        );
    }

    #[test]
    fn classify_standard_compressed_is_data() {
        // OFLAG_COMPRESSED set; offset bits in L2_OFFSET_MASK range.
        let entry = OFLAG_COMPRESSED | 0x0001_2000;
        let e = classify_qcow2_l2_standard(entry, 65536, 65536);
        assert_eq!(e.start, 65536);
        assert_eq!(e.length, 65536);
        // file_offset masked with L2_OFFSET_MASK.
        let want_off = entry & L2_OFFSET_MASK;
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: want_off
            }
        );
    }

    #[test]
    fn classify_standard_oflag_copied_only_is_hole() {
        // OFLAG_COPIED is bit 63; on its own with no offset the
        // entry is non-zero but host_offset is 0 — treat as Hole
        // to match cluster_lookup's "host_offset == 0 →
        // Unallocated" path.
        let e = classify_qcow2_l2_standard(OFLAG_COPIED, 0, 65536);
        assert_eq!(e.state, MapExtentState::Hole);
    }

    #[test]
    fn classify_standard_oflag_copied_with_offset_is_data() {
        let entry = OFLAG_COPIED | 0x0001_0000;
        let e = classify_qcow2_l2_standard(entry, 0, 65536);
        assert_eq!(
            e.state,
            MapExtentState::Data {
                file_offset: 0x0001_0000
            }
        );
    }

    // ====================================================================
    // classify_qcow2_l2_extended tests
    // ====================================================================

    fn extract_extents(
        l2_entry: u64,
        sc_bitmap: u64,
        virtual_offset: u64,
        cluster_size: u64,
        cluster_visible: u64,
    ) -> ([MapExtent; 40], usize) {
        let mut buf = [MapExtent {
            start: 0,
            length: 0,
            state: MapExtentState::Hole,
        }; 40];
        let mut count = 0usize;
        let mut emit = |e: MapExtent| -> bool {
            assert!(count < buf.len(), "extract_extents overflowed buffer");
            buf[count] = e;
            count += 1;
            true
        };
        {
            let mut sink = MapExtentCoalescer::new(&mut emit);
            assert!(classify_qcow2_l2_extended(
                l2_entry,
                sc_bitmap,
                virtual_offset,
                cluster_size,
                cluster_visible,
                &mut sink,
            ));
            assert!(sink.finish());
        }
        (buf, count)
    }

    #[test]
    fn classify_extended_zero_entry_no_zero_bits_is_one_hole() {
        // l2_entry == 0, zero_bits == 0 → 32 Hole subclusters
        // that coalesce into one cluster-wide Hole.
        let (buf, count) = extract_extents(0, 0, 0, 65536, 65536);
        assert_eq!(count, 1);
        assert_eq!(buf[0].state, MapExtentState::Hole);
        assert_eq!(buf[0].length, 65536);
    }

    #[test]
    fn classify_extended_zero_entry_all_zero_bits_is_one_zero_alloc() {
        // l2_entry == 0, zero_bits == 0xFFFFFFFF → 32 ZeroAllocated
        // subclusters that coalesce.
        let bitmap: u64 = 0xFFFF_FFFFu64 << 32;
        let (buf, count) = extract_extents(0, bitmap, 0, 65536, 65536);
        assert_eq!(count, 1);
        assert_eq!(buf[0].state, MapExtentState::ZeroAllocated);
        assert_eq!(buf[0].length, 65536);
    }

    #[test]
    fn classify_extended_full_alloc_is_one_data() {
        // alloc_bits == 0xFFFFFFFF, zero_bits == 0, host_offset
        // non-zero. Each subcluster gets file_offset host + i*sc;
        // coalesces into one Data extent at host_offset.
        let bitmap: u64 = 0xFFFF_FFFF;
        let host_offset: u64 = 0x10_0000;
        let (buf, count) = extract_extents(host_offset, bitmap, 0, 65536, 65536);
        assert_eq!(count, 1);
        assert_eq!(buf[0].length, 65536);
        assert_eq!(
            buf[0].state,
            MapExtentState::Data {
                file_offset: host_offset
            }
        );
    }

    #[test]
    fn classify_extended_compressed_is_one_data() {
        // OFLAG_COMPRESSED set: emit Data for every subcluster with
        // file_offset = host + i*sc; coalesces to one extent at the
        // host offset.
        let host_offset: u64 = 0x4000;
        let entry = OFLAG_COMPRESSED | host_offset;
        let (buf, count) = extract_extents(entry, 0, 0, 65536, 65536);
        assert_eq!(count, 1);
        assert_eq!(buf[0].length, 65536);
        assert_eq!(
            buf[0].state,
            MapExtentState::Data {
                file_offset: host_offset
            }
        );
    }

    #[test]
    fn classify_extended_checkerboard_alloc_keeps_split() {
        // alloc_bits = 0xAAAAAAAA (every other subcluster
        // allocated), zero_bits = 0. Result: 32 separate extents
        // alternating Hole / Data. The coalescer cannot merge them
        // because the states differ.
        let alloc: u64 = 0xAAAA_AAAA;
        let host_offset: u64 = 0x1_0000_0000;
        let (buf, count) = extract_extents(host_offset, alloc, 0, 65536, 65536);
        assert_eq!(count, 32);
        // Even-index subclusters are Hole (low bits = 0).
        assert_eq!(buf[0].state, MapExtentState::Hole);
        // Odd-index are Data.
        match buf[1].state {
            MapExtentState::Data { file_offset } => {
                assert_eq!(file_offset, host_offset + 2048);
            }
            other => panic!("expected Data, got {:?}", other),
        }
    }

    #[test]
    fn classify_extended_one_alloc_amid_holes() {
        // alloc_bits = 1 (subcluster 0 only), zero_bits = 0.
        // 1 Data extent then 1 Hole extent (31 subclusters worth
        // of Hole, coalesced).
        let alloc: u64 = 1;
        let host_offset: u64 = 0x8000;
        let (buf, count) = extract_extents(host_offset, alloc, 0, 65536, 65536);
        assert_eq!(count, 2);
        assert_eq!(
            buf[0].state,
            MapExtentState::Data {
                file_offset: host_offset
            }
        );
        assert_eq!(buf[0].length, 2048);
        assert_eq!(buf[1].state, MapExtentState::Hole);
        assert_eq!(buf[1].length, 2048 * 31);
    }

    #[test]
    fn classify_extended_alloc_plus_zero_subcluster_is_zero_alloc() {
        // Subcluster 0 has both alloc and zero set: zero wins
        // (defensive against sc_bitmap validator I1).
        let bitmap: u64 = (1u64 << 32) | 1;
        let (buf, count) = extract_extents(0x1_0000, bitmap, 0, 65536, 65536);
        // Subcluster 0: ZeroAllocated. Subclusters 1..32: Hole
        // (l2_entry != 0 path: alloc=0, zero=0 → Hole).
        assert_eq!(count, 2);
        assert_eq!(buf[0].state, MapExtentState::ZeroAllocated);
        assert_eq!(buf[0].length, 2048);
        assert_eq!(buf[1].state, MapExtentState::Hole);
    }

    #[test]
    fn classify_extended_clamps_to_cluster_visible() {
        // Fully-allocated cluster but virtual_size cuts it at half
        // the cluster size; emitted length must match
        // cluster_visible, not cluster_size.
        let bitmap: u64 = 0xFFFF_FFFF;
        let (buf, count) = extract_extents(0x1_0000, bitmap, 0, 65536, 32768);
        // We've asked for half the cluster.
        let total_len: u64 = buf[..count].iter().map(|e| e.length).sum();
        assert_eq!(total_len, 32768);
    }

    // ====================================================================
    // Smoke-test that the new helpers are wired correctly via the
    // module's public API. Full Qcow2State::map_extents end-to-end
    // coverage lives in the phase 6 integration tests against real
    // testdata.
    // ====================================================================

    #[test]
    fn classify_standard_compressed_offset_masked() {
        // Make sure high garbage bits don't leak into file_offset.
        let entry = OFLAG_COMPRESSED | OFLAG_COPIED | 0x0007_0000;
        let e = classify_qcow2_l2_standard(entry, 0, 65536);
        let want = entry & L2_OFFSET_MASK;
        assert_eq!(e.state, MapExtentState::Data { file_offset: want });
    }

    // ----------------------------------------------------------------
    // Snapshot table parser tests (PLAN-snapshot phase 2)
    // ----------------------------------------------------------------

    /// Build a 40-byte snapshot header with the given fields.
    #[allow(clippy::too_many_arguments)]
    fn make_snapshot_header(
        l1_table_offset: u64,
        l1_size: u32,
        id_str_size: u16,
        name_size: u16,
        date_sec: u32,
        date_nsec: u32,
        vm_clock_nsec: u64,
        vm_state_size: u32,
        extra_data_size: u32,
    ) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..8].copy_from_slice(&l1_table_offset.to_be_bytes());
        buf[8..12].copy_from_slice(&l1_size.to_be_bytes());
        buf[12..14].copy_from_slice(&id_str_size.to_be_bytes());
        buf[14..16].copy_from_slice(&name_size.to_be_bytes());
        buf[16..20].copy_from_slice(&date_sec.to_be_bytes());
        buf[20..24].copy_from_slice(&date_nsec.to_be_bytes());
        buf[24..32].copy_from_slice(&vm_clock_nsec.to_be_bytes());
        buf[32..36].copy_from_slice(&vm_state_size.to_be_bytes());
        buf[36..40].copy_from_slice(&extra_data_size.to_be_bytes());
        buf
    }

    #[test]
    fn snapshot_header_happy_path() {
        let buf = make_snapshot_header(
            0x4000,
            64,
            3,
            5,
            0x6000_0001,
            0x0a0b_0c0d,
            0x1122_3344_5566_7788,
            0xdead_beef,
            16,
        );
        let raw = parse_snapshot_header_bytes(&buf).expect("header parses");
        assert_eq!(raw.l1_table_offset, 0x4000);
        assert_eq!(raw.l1_size, 64);
        assert_eq!(raw.id_str_size, 3);
        assert_eq!(raw.name_size, 5);
        assert_eq!(raw.date_sec, 0x6000_0001);
        assert_eq!(raw.date_nsec, 0x0a0b_0c0d);
        assert_eq!(raw.vm_clock_nsec, 0x1122_3344_5566_7788);
        assert_eq!(raw.vm_state_size, 0xdead_beef);
        assert_eq!(raw.extra_data_size, 16);
    }

    #[test]
    fn snapshot_header_rejects_short() {
        let buf = [0u8; 39];
        assert!(parse_snapshot_header_bytes(&buf).is_none());
        let buf2 = [0u8; 0];
        assert!(parse_snapshot_header_bytes(&buf2).is_none());
    }

    #[test]
    fn snapshot_extra_data_v2_fallback() {
        // extra_data_size == 0 → all sentinels.
        let extra = parse_snapshot_extra_data(&[], 0);
        assert_eq!(extra.vm_state_size_large, 0);
        assert_eq!(extra.disk_size, 0);
        assert_eq!(extra.icount, u64::MAX);
    }

    #[test]
    fn snapshot_extra_data_v3_8() {
        // extra_data_size == 8 → vm_state_size_large only.
        let mut buf = [0u8; 8];
        buf[0..8].copy_from_slice(&0x1234_5678_9abc_def0u64.to_be_bytes());
        let extra = parse_snapshot_extra_data(&buf, 8);
        assert_eq!(extra.vm_state_size_large, 0x1234_5678_9abc_def0);
        assert_eq!(extra.disk_size, 0);
        assert_eq!(extra.icount, u64::MAX);
    }

    #[test]
    fn snapshot_extra_data_v3_16() {
        // extra_data_size == 16 → vm_state_size_large + disk_size.
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&100u64.to_be_bytes());
        buf[8..16].copy_from_slice(&(1u64 << 30).to_be_bytes());
        let extra = parse_snapshot_extra_data(&buf, 16);
        assert_eq!(extra.vm_state_size_large, 100);
        assert_eq!(extra.disk_size, 1u64 << 30);
        assert_eq!(extra.icount, u64::MAX);
    }

    #[test]
    fn snapshot_extra_data_v3_24() {
        // extra_data_size == 24 → all three populated.
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&100u64.to_be_bytes());
        buf[8..16].copy_from_slice(&(1u64 << 30).to_be_bytes());
        buf[16..24].copy_from_slice(&42u64.to_be_bytes());
        let extra = parse_snapshot_extra_data(&buf, 24);
        assert_eq!(extra.vm_state_size_large, 100);
        assert_eq!(extra.disk_size, 1u64 << 30);
        assert_eq!(extra.icount, 42);
    }

    #[test]
    fn snapshot_extra_data_oversized_rejected() {
        // extra_data_size > QCOW_MAX_SNAPSHOT_EXTRA_DATA → all sentinels,
        // trailing data ignored.
        let buf = [0xffu8; 32];
        let extra = parse_snapshot_extra_data(&buf, QCOW_MAX_SNAPSHOT_EXTRA_DATA + 1);
        assert_eq!(extra.vm_state_size_large, 0);
        assert_eq!(extra.disk_size, 0);
        assert_eq!(extra.icount, u64::MAX);
    }

    #[test]
    fn snapshot_extra_data_truncated_buffer() {
        // extra_data_size claims 24 but buffer only carries 12 bytes;
        // we get the first field, then sentinels for the rest.
        let mut buf = [0u8; 12];
        buf[0..8].copy_from_slice(&77u64.to_be_bytes());
        let extra = parse_snapshot_extra_data(&buf, 24);
        assert_eq!(extra.vm_state_size_large, 77);
        // buf[8..16] is partial — try_into() fails, falls back to 0.
        assert_eq!(extra.disk_size, 0);
        assert_eq!(extra.icount, u64::MAX);
    }

    #[test]
    fn snapshot_entry_to_record_v2_fallback() {
        // entry.disk_size == 0 (v2 sentinel) → record.disk_size =
        // header_virtual_size.
        let entry = SnapshotEntry::zeroed();
        let rec = snapshot_entry_to_record(&entry, 4096);
        assert_eq!(rec.disk_size, 4096);
    }

    #[test]
    fn snapshot_entry_to_record_happy_path() {
        let mut entry = SnapshotEntry::zeroed();
        entry.l1_table_offset = 0x5000;
        entry.l1_size = 16;
        entry.id_len = 3;
        entry.name_len = 5;
        entry.id[..3].copy_from_slice(b"42\0");
        entry.name[..5].copy_from_slice(b"hello");
        entry.date_sec = 1_700_000_000;
        entry.date_nsec = 12345;
        entry.vm_clock_nsec = 0xdead_beef_cafe_babe;
        entry.vm_state_size = 0;
        entry.vm_state_size_large = 256 * 1024;
        entry.disk_size = 1u64 << 30;
        entry.icount = 99;
        entry.extra_data_size = 24;
        let rec = snapshot_entry_to_record(&entry, 0);
        assert_eq!(rec.magic, shared::SnapshotEntryRecord::MAGIC);
        assert_eq!(rec.date_sec_hi, 0);
        assert_eq!(rec.date_sec_lo, 1_700_000_000);
        assert_eq!(rec.date_nsec, 12345);
        assert_eq!(rec.vm_clock_nsec, 0xdead_beef_cafe_babe);
        assert_eq!(rec.vm_state_size_large, 256 * 1024);
        assert_eq!(rec.disk_size, 1u64 << 30);
        assert_eq!(rec.icount, 99);
        assert_eq!(rec.l1_table_offset, 0x5000);
        assert_eq!(rec.l1_size, 16);
        assert_eq!(rec.extra_data_size, 24);
        assert_eq!(rec.id_len, 3);
        assert_eq!(rec.name_len, 5);
        assert_eq!(&rec.id[..3], b"42\0");
        assert_eq!(&rec.name[..5], b"hello");
        // Bytes past the populated tail are zero.
        assert!(rec.id[3..].iter().all(|&b| b == 0));
        assert!(rec.name[5..].iter().all(|&b| b == 0));
        assert!(rec._reserved.iter().all(|&b| b == 0));
    }

    #[test]
    fn snapshot_entry_to_record_long_name_truncates_to_wire_buffer() {
        // `SnapshotEntry::name` is now [u8; 256] (parser cap 255), matching
        // the wire record's destination buffer exactly.  With name_len = 300
        // (set directly, bypassing the parser's own truncation), the
        // converter must clamp against both the source buffer (256) and the
        // destination buffer (256).  The resulting wire name_len is therefore
        // 256 (source-buffer-bounded), not 300 (raw entry value).
        // Previously the source buffer was [u8; 64] and the expected result
        // was 64 — that cap was the bug fixed here; this test is deliberately
        // updated to reflect the widened buffer, not blind re-snapshotted.
        let mut entry = SnapshotEntry::zeroed();
        entry.name_len = 300;
        for (i, b) in entry.name.iter_mut().enumerate() {
            *b = (i as u8) | 0x80;
        }
        let rec = snapshot_entry_to_record(&entry, 0);
        // Source buffer is 256 bytes; dest buffer is also 256 bytes.
        assert_eq!(rec.name_len, 256);
        // All 256 source bytes land verbatim in the wire buffer.
        for (i, &b) in rec.name.iter().enumerate() {
            assert_eq!(b, (i as u8) | 0x80);
        }
    }

    #[test]
    fn snapshot_entry_to_record_long_id_truncates_to_wire_buffer() {
        // Wire record's id buffer is 32; internal is 64. A 40-byte id
        // (forced by setting id_len = 40) truncates to 32 on the wire.
        let mut entry = SnapshotEntry::zeroed();
        entry.id_len = 40;
        for (i, b) in entry.id.iter_mut().enumerate() {
            *b = (i as u8) | 0x40;
        }
        let rec = snapshot_entry_to_record(&entry, 0);
        // wire id_len is min(40, 32) = 32.
        assert_eq!(rec.id_len, 32);
        for (i, &b) in rec.id.iter().enumerate() {
            assert_eq!(b, (i as u8) | 0x40);
        }
    }

    // ---- 200-byte name round-trip tests (longname fix) -----------

    /// Build a 200-byte cyclic (a-z) name pattern into `out`.
    fn make_200_byte_name(out: &mut [u8; 200]) {
        for (i, b) in out.iter_mut().enumerate() {
            *b = b'a' + (i as u8 % 26);
        }
    }

    /// Build the bytes for a single snapshot entry with a 200-byte name.
    /// Returns the raw bytes to place in the fixture buffer and the
    /// expected post-padding byte length.
    fn longname_200_entry_bytes() -> ([u8; 512], usize) {
        let mut name = [0u8; 200];
        make_200_byte_name(&mut name);
        let id = b"1";
        let mut buf = [0u8; 512];
        let end = write_entry(&mut buf, 0, id, &name);
        (buf, end)
    }

    #[test]
    fn for_each_snapshot_entry_200_byte_name_round_trip() {
        // A 200-byte snapshot name must survive the streaming parser
        // with all 200 bytes intact and name_len == 200.
        let _guard = STREAMING_LOCK.lock().unwrap();
        unsafe {
            let (entry_bytes, _end) = longname_200_entry_bytes();
            let buf = &raw mut STREAMING_FIXTURE.buf;
            for b in (*buf).iter_mut() {
                *b = 0;
            }
            (&mut (*buf))[..entry_bytes.len()].copy_from_slice(&entry_bytes);
            let ct = make_streaming_call_table();
            let mut cache = [0u8; 512];
            let mut bytes = 0u64;
            let mut captured: Option<SnapshotEntry> = None;
            let done = for_each_snapshot_entry(
                &ct,
                0,
                1,
                0,
                512,
                8,
                cache.as_mut_ptr(),
                &mut bytes,
                |e| {
                    captured = Some(*e);
                    true
                },
            );
            assert!(done, "for_each_snapshot_entry should complete");
            let e = captured.expect("callback must have fired");
            assert_eq!(e.name_len, 200, "name_len must be 200");
            // Check all 200 bytes are the correct cyclic pattern.
            let mut expected = [0u8; 200];
            make_200_byte_name(&mut expected);
            assert_eq!(&e.name[..200], &expected[..]);
            // Bytes past name_len must be zero (zeroed() guarantee).
            assert!(
                e.name[200..].iter().all(|&b| b == 0),
                "bytes past name_len must be zero"
            );
        }
    }

    #[test]
    fn snapshot_entry_to_record_200_byte_name_round_trip() {
        // A 200-byte name that came through the parser must arrive on
        // the wire with all 200 bytes intact.
        let mut entry = SnapshotEntry::zeroed();
        entry.name_len = 200;
        let mut expected = [0u8; 200];
        make_200_byte_name(&mut expected);
        entry.name[..200].copy_from_slice(&expected);
        let rec = snapshot_entry_to_record(&entry, 4096);
        assert_eq!(rec.name_len, 200);
        assert_eq!(&rec.name[..200], &expected[..]);
        assert!(rec.name[200..].iter().all(|&b| b == 0));
    }

    #[test]
    fn snapshot_entry_to_record_255_byte_name_boundary() {
        // 255 bytes is the maximum qemu-img can create.  All 255 bytes
        // must pass through the converter without truncation.
        let mut entry = SnapshotEntry::zeroed();
        entry.name_len = 255;
        // Fill with a recognisable pattern.
        let mut expected = [0u8; 255];
        for (i, b) in expected.iter_mut().enumerate() {
            *b = (i as u8) | 0xA0;
        }
        entry.name[..255].copy_from_slice(&expected);
        let rec = snapshot_entry_to_record(&entry, 0);
        assert_eq!(rec.name_len, 255);
        assert_eq!(&rec.name[..255], &expected[..]);
        assert_eq!(rec.name[255], 0);
    }

    #[test]
    fn snapshot_entry_to_record_256_byte_name_over_limit_truncation_pin() {
        // name_len = 256 is unreachable via qemu-img (which caps
        // creation at 255), but if a caller forces it the converter
        // must clamp to the source buffer size (256) AND the
        // destination buffer size (256).  Both are 256, so the wire
        // name_len must be 256 — all 256 bytes land intact.
        // (A name_len > 256 would be clamped to 256 by entry.name.len().)
        let mut entry = SnapshotEntry::zeroed();
        entry.name_len = 257; // beyond any on-disk possibility
        for (i, b) in entry.name.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x20);
        }
        let rec = snapshot_entry_to_record(&entry, 0);
        // min(257, 256 [src], 256 [dst]) = 256
        assert_eq!(rec.name_len, 256);
        for (i, &b) in rec.name.iter().enumerate() {
            assert_eq!(b, (i as u8).wrapping_add(0x20));
        }
    }

    // ---- end 200-byte name round-trip tests ----------------------

    #[test]
    fn snapshot_entry_icount_absent_matches_shared() {
        assert_eq!(
            SnapshotEntry::ICOUNT_ABSENT,
            shared::SnapshotEntryRecord::ICOUNT_ABSENT
        );
        assert_eq!(SnapshotEntry::ICOUNT_ABSENT, u64::MAX);
    }

    #[test]
    fn snapshot_entry_size_tripwire() {
        // Tripwire: if SnapshotEntry's size drifts, the bounded
        // SnapshotTable's stack footprint changes and callers
        // (convert) need re-validation.  Adjust this number
        // intentionally when adding/resizing fields, after auditing
        // callers.
        //
        // Current shape: u64 + u32 + u16 + u16 + [u8;64] + [u8;256] +
        // u32 + u32 + u32 + u64 + u64 + u64 + u64 + u32
        // = 8 + 4 + 2 + 2 + 64 + 256 + 4 + 4 + 4 + 8 + 8 + 8 + 8 + 4
        // = 384 bytes (plus any Rust padding).
        //
        // `name` was widened from [u8;64] to [u8;256] when fixing the
        // list-mode 63-byte truncation bug.  The 16-entry SnapshotTable
        // grows by 16×192 = 3072 bytes (from ~3 KiB to ~6 KiB), well
        // within the 4 MiB guest stack budget.  The convert caller
        // (src/operations/convert/src/main.rs:413) allocates this as a
        // local variable; stack headroom remains ample (>2×).
        let s = core::mem::size_of::<SnapshotEntry>();
        // Sanity bounds: must fit below 512 bytes so the bounded
        // 16-entry SnapshotTable stays in the low-kilobyte range.
        assert!(
            s >= 376 && s <= 512,
            "SnapshotEntry size unexpected: {} bytes",
            s
        );
    }

    // ---- Streaming parser fixture ---------------------------------

    /// A self-contained streaming snapshot fixture in memory.
    ///
    /// Builds a small qcow2-style snapshot table in a fixed buffer
    /// and installs a `CallTable` whose `read_input_sector` services
    /// reads from the buffer, so streaming-parser tests (e.g. the
    /// 200-byte-name round trip above) can exercise
    /// `for_each_snapshot_entry` without a real device.
    struct StreamingFixture {
        // Static-sized buffer big enough for a few small entries.
        buf: [u8; 4096],
    }

    // Serialize tests that touch the shared `STREAMING_FIXTURE`
    // global. The streaming `read_input_sector` callback can only
    // close over `'static` state because it is an `extern "C" fn`,
    // hence the global buffer + lock.
    static STREAMING_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut STREAMING_FIXTURE: StreamingFixture = StreamingFixture { buf: [0u8; 4096] };

    unsafe extern "C" fn streaming_read_sector(
        _device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        let start = (sector as usize).saturating_mul(sector_size);
        if start + sector_size > 4096 {
            return false;
        }
        let fixture_ptr = core::ptr::addr_of!(STREAMING_FIXTURE.buf) as *const u8;
        core::ptr::copy_nonoverlapping(fixture_ptr.add(start), out_buf, sector_size);
        true
    }

    /// Write one snapshot entry into the fixture buffer at `offset`
    /// with the given id/name and return the post-entry offset.
    fn write_entry(buf: &mut [u8], offset: usize, id: &[u8], name: &[u8]) -> usize {
        // Use minimal-but-valid v3 extra-data (24 bytes carrying
        // vm_state_size_large=0, disk_size=0, icount=ABSENT).
        let id_str_size = id.len() as u16;
        let name_size = name.len() as u16;
        let extra_data_size: u32 = 24;
        let header = make_snapshot_header(
            0x4000,
            16,
            id_str_size,
            name_size,
            0,
            0,
            0,
            0,
            extra_data_size,
        );
        buf[offset..offset + 40].copy_from_slice(&header);
        // 24-byte extra-data carrying icount=ABSENT (u64::MAX).
        let extra_start = offset + 40;
        buf[extra_start..extra_start + 8].fill(0);
        buf[extra_start + 8..extra_start + 16].fill(0);
        buf[extra_start + 16..extra_start + 24].copy_from_slice(&u64::MAX.to_be_bytes());
        let id_start = extra_start + 24;
        buf[id_start..id_start + id.len()].copy_from_slice(id);
        let name_start = id_start + id.len();
        buf[name_start..name_start + name.len()].copy_from_slice(name);
        let raw_end = name_start + name.len();
        // Round up to 8-byte boundary.
        (raw_end + 7) & !7
    }

    /// Build a CallTable with every function pointer set to a
    /// trivially-correct stub. Only `read_input_sector` is
    /// overwritten by callers as needed.
    fn stub_call_table() -> shared::CallTable {
        unsafe extern "C" fn s_get_dev_count() -> u32 {
            1
        }
        unsafe extern "C" fn s_read_in(_: u32, _: u64, _: *mut u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_in_cap(_: u32) -> u64 {
            8
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
            get_input_device_count: s_get_dev_count,
            read_input_sector: s_read_in,
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

    /// Make a CallTable with `read_input_sector` set to the
    /// streaming fixture's reader.
    fn make_streaming_call_table() -> shared::CallTable {
        shared::CallTable {
            read_input_sector: streaming_read_sector,
            ..stub_call_table()
        }
    }

    // ---- find_snapshot (two-pass ID-then-name) tests ---------------

    /// Build an in-memory `SnapshotTable` from (id, name) pairs.
    fn table_with(entries: &[(&[u8], &[u8])]) -> SnapshotTable {
        let mut table = SnapshotTable::empty();
        for (id, name) in entries {
            let mut e = SnapshotEntry::zeroed();
            e.id_len = id.len() as u16;
            e.id[..id.len()].copy_from_slice(id);
            e.name_len = name.len() as u16;
            e.name[..name.len()].copy_from_slice(name);
            table.entries[table.count] = e;
            table.count += 1;
        }
        table
    }

    #[test]
    fn find_snapshot_later_id_beats_earlier_name() {
        // The probe-1 collision shape: `id=1 name="2"` then
        // `id=2 name="x"`. qemu's two-full-pass matcher resolves
        // the needle "2" to ID 2 (index 1), not to the earlier
        // entry *named* "2" (index 0). The pre-fix per-entry walk
        // returned index 0 here.
        let table = table_with(&[(b"1", b"2"), (b"2", b"x")]);
        assert_eq!(find_snapshot(&table, b"2"), Some(1));
        // The mirrored collision: a later entry's NAME does not
        // outrank an earlier entry's ID either — "1" is an ID hit
        // on the first pass.
        let table = table_with(&[(b"1", b"x"), (b"2", b"1")]);
        assert_eq!(find_snapshot(&table, b"1"), Some(0));
    }

    #[test]
    fn find_snapshot_name_only_fallback() {
        // No ID matches the needle, so the second (name) pass
        // resolves it — including a needle that looks numeric.
        let table = table_with(&[(b"1", b"alpha"), (b"2", b"beta")]);
        assert_eq!(find_snapshot(&table, b"beta"), Some(1));
        let table = table_with(&[(b"1", b"7"), (b"2", b"x")]);
        assert_eq!(find_snapshot(&table, b"7"), Some(0));
    }

    #[test]
    fn find_snapshot_not_found() {
        let table = table_with(&[(b"1", b"alpha")]);
        assert_eq!(find_snapshot(&table, b"missing"), None);
        // Prefix of a name is not an exact-length match.
        assert_eq!(find_snapshot(&table, b"alph"), None);
        // Empty table.
        let table = table_with(&[]);
        assert_eq!(find_snapshot(&table, b"1"), None);
    }

    // ---- Byte-accurate read primitives (read_raw_sectors /
    //      read_cluster_sectors) -------------------------------------
    //
    // Phase 3 rewrote these two shared read primitives to serve
    // arbitrary sub-sector byte ranges, keeping a sector-aligned fast
    // path byte-identical and adding a byte-accurate scratch-and-copy
    // path for unaligned / partial windows. These tests pin both paths
    // to a deterministic, position-dependent device pattern so any
    // regression (e.g. dropping a partial tail, or mis-offsetting into
    // a multi-sector cluster) fails fast without KVM or testdata.

    /// Sector size used by the read-primitive tests. Small so cases are
    /// easy to reason about by hand.
    const READ_TEST_SSZ: usize = 512;

    /// Deterministic, position-dependent device byte at absolute offset
    /// `o`. 251 is prime and < 256, so the pattern has period 251 (not a
    /// multiple of the 512-byte sector size); a sector- or
    /// cluster-misaligned copy therefore cannot accidentally match.
    fn read_test_pattern_byte(o: u64) -> u8 {
        (o % 251) as u8
    }

    /// Device capacity, in `READ_TEST_SSZ` sectors, that the read-test
    /// `read_input_sector` mock serves. Set per-test under the lock.
    static mut READ_TEST_CAPACITY_SECTORS: u64 = 0;

    /// Serialize tests that touch the `READ_TEST_CAPACITY_SECTORS`
    /// global. The mock callback is an `extern "C" fn` and can only
    /// close over `'static` state, hence the global + lock (mirrors the
    /// `STREAMING_FIXTURE` / `STREAMING_LOCK` pattern above).
    static READ_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Mock `read_input_sector`: fills `out_buf` with the device pattern
    /// for `[sector*sector_size, (sector+1)*sector_size)`. Returns false
    /// for any sector at/beyond the configured capacity, so a caller
    /// reading past the end (which it must avoid by zero-filling itself)
    /// would surface as a failure rather than fabricated bytes.
    unsafe extern "C" fn read_test_sector(
        _device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        if sector >= READ_TEST_CAPACITY_SECTORS {
            return false;
        }
        let base = sector * sector_size as u64;
        for i in 0..sector_size {
            *out_buf.add(i) = read_test_pattern_byte(base + i as u64);
        }
        true
    }

    fn read_test_call_table() -> shared::CallTable {
        shared::CallTable {
            read_input_sector: read_test_sector,
            ..stub_call_table()
        }
    }

    /// The reference bytes a correct read of `[offset, offset+len)`
    /// must produce: the device pattern where the range lies within
    /// `capacity_sectors * READ_TEST_SSZ`, and zero past the device end.
    fn read_test_expected(offset: u64, len: usize, capacity_sectors: u64) -> std::vec::Vec<u8> {
        let capacity = capacity_sectors * READ_TEST_SSZ as u64;
        let mut out = std::vec::Vec::with_capacity(len);
        for i in 0..len as u64 {
            let abs = offset + i;
            if abs < capacity {
                out.push(read_test_pattern_byte(abs));
            } else {
                out.push(0);
            }
        }
        out
    }

    /// Drive `read_raw_sectors` for `[virtual_offset, virtual_offset +
    /// chunk_size)` against a device of `capacity_sectors` and assert
    /// every returned byte equals the reference pattern (zero past end).
    /// Also asserts `bytes_read` advanced by a whole number of sectors.
    fn check_read_raw(virtual_offset: u64, chunk_size: u64, capacity_sectors: u64) {
        let _guard = READ_TEST_LOCK.lock().unwrap();
        unsafe {
            READ_TEST_CAPACITY_SECTORS = capacity_sectors;
        }
        let call_table = read_test_call_table();

        // Buffer must hold at least max(chunk_size, sector_size) bytes
        // per the safety contract; pad generously and sentinel it.
        let buf_len = core::cmp::max(chunk_size as usize, READ_TEST_SSZ) + 64;
        let mut buf = std::vec![0xAAu8; buf_len];
        let mut bytes_read: u64 = 0;

        let ok = unsafe {
            read_raw_sectors(
                &call_table,
                0,
                virtual_offset,
                buf.as_mut_ptr(),
                chunk_size,
                READ_TEST_SSZ,
                capacity_sectors,
                &mut bytes_read,
            )
        };
        assert!(ok, "read_raw_sectors returned false");

        let expected = read_test_expected(virtual_offset, chunk_size as usize, capacity_sectors);
        assert_eq!(
            &buf[..chunk_size as usize],
            &expected[..],
            "read_raw_sectors bytes mismatch at offset={virtual_offset} len={chunk_size}"
        );
        // Device I/O happens in whole sectors only.
        assert!(
            bytes_read.is_multiple_of(READ_TEST_SSZ as u64),
            "bytes_read {bytes_read} not a sector multiple"
        );
        // Bytes past the requested range must be untouched.
        assert!(
            buf[chunk_size as usize..].iter().all(|&b| b == 0xAA),
            "read_raw_sectors wrote past the requested range"
        );
    }

    /// Drive `read_cluster_sectors` for `[host_offset, host_offset +
    /// cluster_size)` and assert every returned byte equals the
    /// reference pattern. `read_cluster_sectors` has no past-capacity
    /// handling of its own (callers only pass in-range host offsets),
    /// so the device is sized to cover the whole range here.
    fn check_read_cluster(host_offset: u64, cluster_size: u64, capacity_sectors: u64) {
        let _guard = READ_TEST_LOCK.lock().unwrap();
        unsafe {
            READ_TEST_CAPACITY_SECTORS = capacity_sectors;
        }
        let call_table = read_test_call_table();

        let buf_len = core::cmp::max(cluster_size as usize, READ_TEST_SSZ) + 64;
        let mut buf = std::vec![0xAAu8; buf_len];
        let mut bytes_read: u64 = 0;

        let ok = unsafe {
            read_cluster_sectors(
                &call_table,
                0,
                host_offset,
                buf.as_mut_ptr(),
                cluster_size,
                READ_TEST_SSZ,
                &mut bytes_read,
            )
        };
        assert!(ok, "read_cluster_sectors returned false");

        let expected = read_test_expected(host_offset, cluster_size as usize, capacity_sectors);
        assert_eq!(
            &buf[..cluster_size as usize],
            &expected[..],
            "read_cluster_sectors bytes mismatch at host_offset={host_offset} len={cluster_size}"
        );
        assert!(
            bytes_read.is_multiple_of(READ_TEST_SSZ as u64),
            "bytes_read {bytes_read} not a sector multiple"
        );
        assert!(
            buf[cluster_size as usize..].iter().all(|&b| b == 0xAA),
            "read_cluster_sectors wrote past the requested range"
        );
    }

    // -- read_raw_sectors --------------------------------------------

    #[test]
    fn read_raw_aligned_fast_path() {
        // Offset and length both sector multiples: the fast path reads
        // whole sectors straight into buf. Multi-sector read starting
        // mid-device.
        check_read_raw(2 * 512, 4 * 512, 32);
    }

    #[test]
    fn read_raw_sub_sector_start() {
        // Offset 600 = sector 1 + 88 bytes in. Exercises the partial
        // head-sector scratch-and-copy.
        check_read_raw(600, 512, 32);
    }

    #[test]
    fn read_raw_sub_sector_length_tail() {
        // Sector-aligned start, length not a sector multiple. Dropping
        // the partial tail was the phase-3 bug; len=300 and len=1000
        // both leave a non-zero tail that must be copied.
        check_read_raw(0, 300, 32);
        check_read_raw(512, 1000, 32);
    }

    #[test]
    fn read_raw_full_span() {
        // [600, 2100): partial head sector (600..1024), full interior
        // sector (1024..1536, 1536..2048), partial tail sector
        // (2048..2100) — all in one read.
        check_read_raw(600, 1500, 32);
    }

    #[test]
    fn read_raw_past_capacity_fast_path() {
        // Aligned read whose range runs off the end of an 8-sector
        // (4096-byte) device: sectors 6,7 are real, 8,9 are past end
        // and must zero-fill. Hits the fast path's `sector >= capacity`
        // branch.
        check_read_raw(6 * 512, 4 * 512, 8);
    }

    #[test]
    fn read_raw_past_capacity_byte_accurate() {
        // Unaligned read straddling the device end (8 sectors = 4096
        // bytes): starts at 3800 (in sector 7), runs to 4400 — past the
        // 4096-byte capacity. In-range bytes match the pattern; the
        // remainder zero-fills via the byte-accurate path.
        check_read_raw(3800, 600, 8);
    }

    // -- read_cluster_sectors ----------------------------------------

    #[test]
    fn read_cluster_aligned_fast_path() {
        // Sector-aligned host_offset, cluster_size a sector multiple:
        // the fast path reads whole sectors straight into buf.
        check_read_cluster(3 * 512, 4 * 512, 32);
    }

    #[test]
    fn read_cluster_sub_sector_size() {
        // cluster_size < sector_size: a single partial-sector read
        // copying just the cluster's bytes from the right offset.
        check_read_cluster(0, 200, 32);
        // ...and a sub-sector cluster that also starts partway in.
        check_read_cluster(700, 200, 32);
    }

    #[test]
    fn read_cluster_unaligned_host_offset_multi_sector() {
        // Non-sector-aligned host_offset into a multi-sector cluster —
        // the latent bug phase 3 fixed. host_offset 600 (sector 1 + 88)
        // with a 1536-byte (3-sector) cluster spans a partial head, a
        // full interior sector, and a partial tail. Assert exact bytes.
        check_read_cluster(600, 1536, 32);
    }

    // ====================================================================
    // #432: classic (non-extended) L2 zero-flag (QCOW_OFLAG_ZERO, bit 0)
    // ====================================================================
    //
    // A classic v3 L2 entry with bit 0 set reads as all zeros regardless
    // of its host-offset field. Before the 7z fix cluster_lookup ignored
    // the bit, so a host==0 zero-flag entry was mis-classified as
    // Unallocated (fell through to backing) and a host!=0 one as
    // Standard (read stale host bytes). These tests exercise both.

    // Byte size of the in-memory qcow2 image the #432 mock serves.
    const Z432_IMG_LEN: usize = 8192;

    // Serialize tests touching the Z432 globals (extern "C" callbacks can
    // only close over 'static state; mirrors the READ_TEST_LOCK pattern).
    static Z432_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static mut Z432_IMG: [u8; Z432_IMG_LEN] = [0u8; Z432_IMG_LEN];
    static mut Z432_CAP_SECTORS: u64 = 0;

    // Sector size and cluster geometry the #432 fixture uses.
    const Z432_SSZ: usize = 512;

    unsafe extern "C" fn z432_read_sector(
        _device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        let start = (sector as usize).saturating_mul(sector_size);
        if start + sector_size > Z432_IMG_LEN {
            return false;
        }
        let base = core::ptr::addr_of!(Z432_IMG) as *const u8;
        core::ptr::copy_nonoverlapping(base.add(start), out_buf, sector_size);
        true
    }

    unsafe extern "C" fn z432_capacity(_device_idx: u32) -> u64 {
        Z432_CAP_SECTORS
    }

    fn z432_call_table() -> shared::CallTable {
        shared::CallTable {
            read_input_sector: z432_read_sector,
            get_input_capacity: z432_capacity,
            ..stub_call_table()
        }
    }

    /// Build the in-memory classic-L2 fixture into `Z432_IMG` and set the
    /// served capacity. Layout (cluster_size = 512, 8-byte entries):
    ///   - L1 table at 512: L1[0] → L2 table at 1024.
    ///   - L2 table at 1024:
    ///       [0] @1024 = QCOW_OFLAG_ZERO           → host==0 zero-flag.
    ///       [1] @1032 = 2048 | COPIED | ZERO      → host!=0 zero-flag.
    ///       [2] @1040 = 2048 | COPIED             → plain Standard guard.
    ///   - Data region at host offset 2048 filled with 0xDD, so a stale
    ///     Standard read of the zero-flag entry [1] would return 0xDD.
    unsafe fn z432_build_image() {
        let mut img = [0u8; Z432_IMG_LEN];
        let mut put = |off: usize, v: u64| {
            img[off..off + 8].copy_from_slice(&v.to_be_bytes());
        };
        put(512, 1024 | OFLAG_COPIED);
        put(1024, QCOW_OFLAG_ZERO);
        put(1032, 2048 | OFLAG_COPIED | QCOW_OFLAG_ZERO);
        put(1040, 2048 | OFLAG_COPIED);
        for b in img[2048..2560].iter_mut() {
            *b = 0xDD;
        }
        let dst = core::ptr::addr_of_mut!(Z432_IMG) as *mut u8;
        core::ptr::copy_nonoverlapping(img.as_ptr(), dst, Z432_IMG_LEN);
        Z432_CAP_SECTORS = (Z432_IMG_LEN / Z432_SSZ) as u64;
    }

    /// Construct a `Qcow2State` matching the #432 fixture geometry. The
    /// caller owns the two cache buffers (each ≥ MAX_SECTOR_SIZE).
    fn z432_state(l1_cache: &mut [u8], l2_cache: &mut [u8]) -> Qcow2State {
        Qcow2State {
            device_idx: 0,
            cluster_size: Z432_SSZ as u64,
            cluster_bits: 9,
            l1_size: 1,
            l1_table_offset: 512,
            incompatible_features: 0,
            compression_type: 0,
            crypt_method: 0,
            luks_ext_offset: 0,
            luks_ext_len: 0,
            extended_l2: false,
            l1_cached_sector: u64::MAX,
            l1_cache_buf: l1_cache.as_mut_ptr(),
            l2_cached_sector: u64::MAX,
            l2_cache_buf: l2_cache.as_mut_ptr(),
        }
    }

    #[test]
    fn classic_zero_flag_cluster_lookup_returns_zero() {
        let _guard = Z432_LOCK.lock().unwrap();
        unsafe {
            z432_build_image();
        }
        let call_table = z432_call_table();
        let mut l1_cache = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut l2_cache = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut state = z432_state(&mut l1_cache, &mut l2_cache);
        let cap = (Z432_IMG_LEN / Z432_SSZ) as u64;
        let mut bytes_read = 0u64;

        // vo=0 → L2[0], host==0 zero-flag → Zero (was Unallocated pre-fix).
        let a = unsafe { state.cluster_lookup(&call_table, 0, Z432_SSZ, cap, &mut bytes_read) };
        assert!(
            matches!(a, Some(ClusterLookup::Zero)),
            "host==0 zero-flag must resolve to Zero, got a non-Zero verdict"
        );

        // vo=512 → L2[1], host!=0 zero-flag → Zero (was Standard pre-fix).
        let b = unsafe { state.cluster_lookup(&call_table, 512, Z432_SSZ, cap, &mut bytes_read) };
        assert!(
            matches!(b, Some(ClusterLookup::Zero)),
            "host!=0 zero-flag must resolve to Zero, got a non-Zero verdict"
        );

        // vo=1024 → L2[2], no zero-flag → Standard (guard against
        // over-broadening the new branch).
        let c = unsafe { state.cluster_lookup(&call_table, 1024, Z432_SSZ, cap, &mut bytes_read) };
        assert!(
            matches!(c, Some(ClusterLookup::Standard(2048))),
            "plain allocated entry must stay Standard(2048)"
        );
    }

    #[test]
    fn classic_zero_flag_chain_read_is_all_zero() {
        let _guard = Z432_LOCK.lock().unwrap();
        unsafe {
            z432_build_image();
        }
        let call_table = z432_call_table();
        let mut l1_cache = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut l2_cache = std::vec![0u8; MAX_SECTOR_SIZE];
        let state = z432_state(&mut l1_cache, &mut l2_cache);

        let mut chain_states = ChainStates::default();
        chain_states.qcow2_states[0] = Some(state);

        let mut chain_config = ChainConfig::new();
        chain_config.magic = ChainConfig::MAGIC;
        chain_config.version = ChainConfig::VERSION;
        chain_config.device_count = 1;
        chain_config.devices[0].format = ImageFormat::Qcow2 as u32;
        chain_config.devices[0].cluster_size = Z432_SSZ as u32;
        chain_config.devices[0].data_device_idx = 0;

        let mut compressed_buf = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut staging_buf = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut staging_cluster_offset = u64::MAX;

        // Read both zero-flag clusters through the single-device chain. A
        // correct read yields all zeros; pre-fix the host!=0 entry (vo=512)
        // returned the stale 0xDD host bytes.
        for vo in [0u64, 512u64] {
            let mut buf = std::vec![0xAAu8; Z432_SSZ];
            let mut bytes_read = 0u64;
            let ok = unsafe {
                read_chain_virtual_cluster(
                    &call_table,
                    0,
                    1,
                    vo,
                    buf.as_mut_ptr(),
                    Z432_SSZ as u64,
                    Z432_SSZ,
                    &chain_config,
                    &mut chain_states,
                    compressed_buf.as_mut_ptr(),
                    staging_buf.as_mut_ptr(),
                    &mut staging_cluster_offset,
                    None,
                    None,
                    0,
                    &mut bytes_read,
                )
            };
            assert!(ok, "read_chain_virtual_cluster returned false at vo={vo}");
            assert!(
                buf.iter().all(|&b| b == 0),
                "zero-flag cluster at vo={vo} must read as all zeros, got {:02x?}",
                &buf[..16]
            );
        }
    }

    #[test]
    fn classify_standard_zero_flag_host_zero_is_zeroallocated() {
        // QCOW_OFLAG_ZERO with host_offset == 0 (ZERO_PLAIN).
        let e = classify_qcow2_l2_standard(QCOW_OFLAG_ZERO, 0, 65536);
        assert_eq!(e.state, MapExtentState::ZeroAllocated);
    }

    #[test]
    fn classify_standard_zero_flag_host_nonzero_is_zeroallocated() {
        // QCOW_OFLAG_ZERO with a host offset set (ZERO_ALLOC); the zero
        // flag wins over the Data classification the offset would imply.
        let entry = 0x0005_0000 | OFLAG_COPIED | QCOW_OFLAG_ZERO;
        let e = classify_qcow2_l2_standard(entry, 0, 65536);
        assert_eq!(e.state, MapExtentState::ZeroAllocated);
    }

    // ====================================================================
    // VDI chain-reader arm (read_chain_virtual_cluster ImageFormat::Vdi)
    // ====================================================================
    //
    // These exercise the guest-side arm added for VDI input: hole /
    // discarded blocks read as zeros, allocated blocks map through the
    // non-identity block map (offset_data 1024 forces the unaligned
    // read path), and reads at or past the device capacity zero-fill
    // rather than error (qemu's no-EOF-validation semantics), including
    // a straddle that zero-fills only the truncated tail.
    //
    // The mock serves a synthetic VDI image from a heap buffer via a
    // raw pointer + capacity in a `static mut`, guarded by a lock that
    // serializes these tests (the `read_input_sector` callback is an
    // `extern "C" fn` and can only close over `'static` state — same
    // pattern as `READ_TEST_*` above).

    #[cfg(feature = "vdi-input")]
    static VDI_MOCK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[cfg(feature = "vdi-input")]
    static mut VDI_MOCK_PTR: *const u8 = core::ptr::null();
    #[cfg(feature = "vdi-input")]
    static mut VDI_MOCK_CAP_SECTORS: u64 = 0;

    /// Guest sector size for the VDI arm tests. 4096 is NOT a divisor of
    /// offset_data (1024), so an allocated read takes the unaligned path.
    #[cfg(feature = "vdi-input")]
    const VDI_TEST_SSZ: usize = 4096;

    /// Deterministic device byte at absolute offset `o`; period 251 so a
    /// misaligned copy cannot accidentally match.
    #[cfg(feature = "vdi-input")]
    fn vdi_pattern_byte(o: u64) -> u8 {
        (o % 251) as u8
    }

    /// Mock `read_input_sector`: copies `sector_size` bytes from the mock
    /// image. Returns false for any sector at/beyond the configured
    /// capacity, so a read the arm fails to clamp would surface as an
    /// error rather than fabricated bytes.
    #[cfg(feature = "vdi-input")]
    unsafe extern "C" fn vdi_mock_read_sector(
        _device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        if sector >= VDI_MOCK_CAP_SECTORS {
            return false;
        }
        let start = match (sector as usize).checked_mul(sector_size) {
            Some(s) => s,
            None => return false,
        };
        core::ptr::copy_nonoverlapping(VDI_MOCK_PTR.add(start), out_buf, sector_size);
        true
    }

    #[cfg(feature = "vdi-input")]
    unsafe extern "C" fn vdi_mock_capacity(_device_idx: u32) -> u64 {
        VDI_MOCK_CAP_SECTORS
    }

    #[cfg(feature = "vdi-input")]
    fn vdi_call_table() -> shared::CallTable {
        shared::CallTable {
            read_input_sector: vdi_mock_read_sector,
            get_input_capacity: vdi_mock_capacity,
            ..stub_call_table()
        }
    }

    /// Build a minimal valid 512-byte VDI header (all UUIDs zero).
    #[cfg(feature = "vdi-input")]
    fn build_vdi_header(
        offset_bmap: u32,
        offset_data: u32,
        disk_size: u64,
        blocks_in_image: u32,
    ) -> [u8; 512] {
        use shared::{write_le_u32, write_le_u64};
        let mut buf = [0u8; 512];
        write_le_u32(&mut buf, vdi::SIGNATURE_OFFSET, vdi::VDI_SIGNATURE);
        write_le_u32(&mut buf, vdi::VERSION_OFFSET, vdi::VDI_VERSION_1_1);
        write_le_u32(&mut buf, vdi::IMAGE_TYPE_OFFSET, 1);
        write_le_u32(&mut buf, vdi::OFFSET_BMAP_OFFSET, offset_bmap);
        write_le_u32(&mut buf, vdi::OFFSET_DATA_OFFSET, offset_data);
        write_le_u32(&mut buf, vdi::SECTOR_SIZE_OFFSET, vdi::VDI_SECTOR_SIZE);
        write_le_u64(&mut buf, vdi::DISK_SIZE_OFFSET, disk_size);
        write_le_u32(&mut buf, vdi::BLOCK_SIZE_OFFSET, vdi::VDI_BLOCK_SIZE);
        write_le_u32(&mut buf, vdi::BLOCKS_IN_IMAGE_OFFSET, blocks_in_image);
        buf
    }

    /// Install a synthetic VDI image (pattern everywhere, then the header
    /// at 0 and the LE u32 block map at `offset_bmap`), init a
    /// [`vdi::VdiState`], and read one chunk through
    /// [`read_chain_virtual_cluster`] as a single-device chain. Returns
    /// the produced bytes.
    #[cfg(feature = "vdi-input")]
    fn run_vdi_chain_read(
        header: &[u8; 512],
        offset_bmap: usize,
        bmap: &[u32],
        cap_sectors: u64,
        virtual_offset: u64,
        chunk_size: u64,
    ) -> std::vec::Vec<u8> {
        let _guard = VDI_MOCK_LOCK.lock().unwrap();

        let len = cap_sectors as usize * VDI_TEST_SSZ;
        let mut image = std::vec![0u8; len];
        for (i, b) in image.iter_mut().enumerate() {
            *b = vdi_pattern_byte(i as u64);
        }
        image[..512].copy_from_slice(header);
        for (i, &entry) in bmap.iter().enumerate() {
            let off = offset_bmap + i * 4;
            image[off..off + 4].copy_from_slice(&entry.to_le_bytes());
        }

        unsafe {
            VDI_MOCK_PTR = image.as_ptr();
            VDI_MOCK_CAP_SECTORS = cap_sectors;
        }
        let call_table = vdi_call_table();

        let mut bmap_cache = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut data_cache = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let state = unsafe {
            vdi::VdiState::init(
                &call_table,
                0,
                VDI_TEST_SSZ,
                cap_sectors,
                bmap_cache.as_mut_ptr(),
                data_cache.as_mut_ptr(),
                &mut bytes_read,
            )
        }
        .expect("VdiState::init should succeed for a valid header");

        let mut chain_states = ChainStates::default();
        chain_states.vdi_states[0] = Some(state);

        let mut chain_config = ChainConfig::new();
        chain_config.magic = ChainConfig::MAGIC;
        chain_config.version = ChainConfig::VERSION;
        chain_config.device_count = 1;
        chain_config.devices[0].format = ImageFormat::Vdi as u32;
        chain_config.devices[0].cluster_size = VDI_TEST_SSZ as u32;
        chain_config.devices[0].data_device_idx = 0;

        let mut compressed_buf = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut staging_buf = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut staging_cluster_offset = u64::MAX;

        let mut out = std::vec![0xAAu8; chunk_size as usize];
        let ok = unsafe {
            read_chain_virtual_cluster(
                &call_table,
                0,
                1,
                virtual_offset,
                out.as_mut_ptr(),
                chunk_size,
                VDI_TEST_SSZ,
                &chain_config,
                &mut chain_states,
                compressed_buf.as_mut_ptr(),
                staging_buf.as_mut_ptr(),
                &mut staging_cluster_offset,
                None,
                None,
                0,
                &mut bytes_read,
            )
        };
        // Drop the dangling global before `image` is freed.
        unsafe {
            VDI_MOCK_PTR = core::ptr::null();
        }
        assert!(ok, "read_chain_virtual_cluster returned false");
        out
    }

    #[cfg(feature = "vdi-input")]
    #[test]
    fn vdi_arm_unallocated_block_reads_zeros() {
        // Dynamic bmap with holes: block 1 is allocated (entry 0), the
        // rest are unallocated. Reading the hole at block 0 yields zeros.
        let block = vdi::VDI_BLOCK_SIZE as u64;
        let header = build_vdi_header(512, 1024, 4 * block, 4);
        let bmap = [
            vdi::VDI_BLOCK_UNALLOCATED,
            0,
            vdi::VDI_BLOCK_UNALLOCATED,
            vdi::VDI_BLOCK_UNALLOCATED,
        ];
        let out = run_vdi_chain_read(&header, 512, &bmap, 2, 0, VDI_TEST_SSZ as u64);
        assert!(
            out.iter().all(|&b| b == 0),
            "unallocated VDI block must read as zeros, got {:02x?}",
            &out[..16]
        );
    }

    #[cfg(feature = "vdi-input")]
    #[test]
    fn vdi_arm_discarded_block_reads_zeros() {
        // A discarded sentinel (0xfffffffe) reads as zeros, exactly like
        // an unallocated block.
        let block = vdi::VDI_BLOCK_SIZE as u64;
        let header = build_vdi_header(512, 1024, 4 * block, 4);
        let bmap = [
            vdi::VDI_BLOCK_DISCARDED,
            vdi::VDI_BLOCK_UNALLOCATED,
            vdi::VDI_BLOCK_UNALLOCATED,
            vdi::VDI_BLOCK_UNALLOCATED,
        ];
        let out = run_vdi_chain_read(&header, 512, &bmap, 2, 0, VDI_TEST_SSZ as u64);
        assert!(
            out.iter().all(|&b| b == 0),
            "discarded VDI block must read as zeros, got {:02x?}",
            &out[..16]
        );
    }

    #[cfg(feature = "vdi-input")]
    #[test]
    fn vdi_arm_allocated_nonidentity_unaligned_reads_data() {
        // Non-identity block map: block index 1 maps to allocation entry
        // 0 (host = offset_data + 0 = 1024). offset_data 1024 is not
        // aligned to the 4096-byte guest sector, so the unaligned read
        // path is exercised. The returned bytes must equal the device
        // pattern at host offset 1024.
        let block = vdi::VDI_BLOCK_SIZE as u64;
        let header = build_vdi_header(512, 1024, 4 * block, 4);
        let bmap = [
            vdi::VDI_BLOCK_UNALLOCATED,
            0,
            vdi::VDI_BLOCK_DISCARDED,
            vdi::VDI_BLOCK_UNALLOCATED,
        ];
        let chunk = VDI_TEST_SSZ as u64;
        // block 1: virtual offset 1 MiB, intra-block offset 0.
        let out = run_vdi_chain_read(&header, 512, &bmap, 2, block, chunk);
        let expected: std::vec::Vec<u8> = (0..chunk).map(|i| vdi_pattern_byte(1024 + i)).collect();
        assert_eq!(
            out, expected,
            "allocated VDI block must return device data via the unaligned path"
        );
    }

    #[cfg(feature = "vdi-input")]
    #[test]
    fn vdi_arm_allocated_past_capacity_zero_fills() {
        // An allocated entry whose host offset lands far past the device
        // capacity must zero-fill the whole block, not error — qemu never
        // validates VDI file length.
        let block = vdi::VDI_BLOCK_SIZE as u64;
        let header = build_vdi_header(512, 1024, 4 * block, 4);
        // entry 100 → host = 1024 + 100 MiB, far past the 2-sector cap.
        let bmap = [
            100,
            vdi::VDI_BLOCK_UNALLOCATED,
            vdi::VDI_BLOCK_UNALLOCATED,
            vdi::VDI_BLOCK_UNALLOCATED,
        ];
        let out = run_vdi_chain_read(&header, 512, &bmap, 2, 0, VDI_TEST_SSZ as u64);
        assert!(
            out.iter().all(|&b| b == 0),
            "past-capacity VDI block must zero-fill, got {:02x?}",
            &out[..16]
        );
    }

    #[cfg(feature = "vdi-input")]
    #[test]
    fn vdi_arm_allocated_straddle_zero_fills_tail() {
        // An allocated block that starts in-file but whose read runs off
        // the end of the device: the in-capacity prefix returns device
        // data, and only the truncated tail zero-fills.
        let block = vdi::VDI_BLOCK_SIZE as u64;
        let header = build_vdi_header(512, 1024, 4 * block, 4);
        let bmap = [
            0,
            vdi::VDI_BLOCK_UNALLOCATED,
            vdi::VDI_BLOCK_UNALLOCATED,
            vdi::VDI_BLOCK_UNALLOCATED,
        ];
        // Capacity 2 sectors = 8192 bytes. Block 0 → host 1024; a 8192-byte
        // read runs to 9216, past the 8192-byte end. Prefix length is
        // 8192 - 1024 = 7168 device bytes; the remaining 1024 bytes zero.
        let cap_sectors = 2u64;
        let chunk = 2 * VDI_TEST_SSZ as u64; // 8192
        let out = run_vdi_chain_read(&header, 512, &bmap, cap_sectors, 0, chunk);
        let cap_bytes = cap_sectors * VDI_TEST_SSZ as u64;
        let prefix = (cap_bytes - 1024) as usize; // 7168
        let expected: std::vec::Vec<u8> = (0..chunk)
            .map(|i| {
                if (i as usize) < prefix {
                    vdi_pattern_byte(1024 + i)
                } else {
                    0
                }
            })
            .collect();
        assert_eq!(
            out, expected,
            "straddling VDI read must return the in-file prefix and zero the truncated tail"
        );
    }

    // ====================================================================
    // Parallels chain-reader arm (read_chain_virtual_cluster
    // ImageFormat::Parallels)
    // ====================================================================
    //
    // These exercise the guest-side arm added for Parallels input. Unlike
    // the VDI/VHD arms, this arm walks the chunk one parallels cluster at a
    // time: adjacent clusters are non-contiguous on the host and, while
    // `convert`/`dd` clamp a chunk to the top device's cluster boundary,
    // `compare` uses the LARGER of the two chains' cluster sizes (capped at
    // MAX_SECTOR_SIZE) and `bench`/`rebase` use their qcow2 cluster size, so
    // a 65536-byte chunk can span sixteen 4 KiB parallels clusters. The
    // `..._small_cluster_multi_cluster_span` test is that chunk-boundary
    // pin (ChainDeviceInfo.cluster_size = 4096). Both magics are driven
    // through the arm to prove the per-magic off_multiplier decodes to
    // identical bytes; holes read as zeros; past-capacity and straddling
    // reads zero-fill without error (qemu's no-file-length-validation
    // semantics).
    //
    // Same `'static`-mock pattern as the VDI arm tests above.

    #[cfg(feature = "parallels-input")]
    static PLS_MOCK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[cfg(feature = "parallels-input")]
    static mut PLS_MOCK_PTR: *const u8 = core::ptr::null();
    #[cfg(feature = "parallels-input")]
    static mut PLS_MOCK_CAP_SECTORS: u64 = 0;
    #[cfg(feature = "parallels-input")]
    static mut PLS_MOCK_SSZ: usize = 512;

    /// Deterministic device byte at absolute offset `o`; period 251 so a
    /// misaligned copy cannot accidentally match.
    #[cfg(feature = "parallels-input")]
    fn pls_pattern_byte(o: u64) -> u8 {
        (o % 251) as u8
    }

    /// Mock `read_input_sector`: copies `sector_size` bytes from the mock
    /// image. Returns false for any sector at/beyond the configured
    /// capacity, so a read the arm fails to clamp surfaces as an error
    /// rather than fabricated bytes.
    #[cfg(feature = "parallels-input")]
    unsafe extern "C" fn pls_mock_read_sector(
        _device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        if sector >= PLS_MOCK_CAP_SECTORS {
            return false;
        }
        let start = match (sector as usize).checked_mul(sector_size) {
            Some(s) => s,
            None => return false,
        };
        core::ptr::copy_nonoverlapping(PLS_MOCK_PTR.add(start), out_buf, sector_size);
        true
    }

    #[cfg(feature = "parallels-input")]
    unsafe extern "C" fn pls_mock_capacity(_device_idx: u32) -> u64 {
        PLS_MOCK_CAP_SECTORS
    }

    #[cfg(feature = "parallels-input")]
    unsafe extern "C" fn pls_mock_ssz(_device_idx: u32) -> usize {
        PLS_MOCK_SSZ
    }

    #[cfg(feature = "parallels-input")]
    fn pls_call_table() -> shared::CallTable {
        shared::CallTable {
            read_input_sector: pls_mock_read_sector,
            get_input_capacity: pls_mock_capacity,
            get_input_sector_size: pls_mock_ssz,
            ..stub_call_table()
        }
    }

    /// Build a minimal valid Parallels header (64 bytes) inside a 512-byte
    /// sector: only the fields the reader consumes are set.
    #[cfg(feature = "parallels-input")]
    fn build_pls_header(
        magic: [u8; 16],
        tracks: u32,
        bat_entries: u32,
        nb_sectors: u64,
    ) -> [u8; 512] {
        use shared::{write_le_u32, write_le_u64};
        let mut buf = [0u8; 512];
        buf[..16].copy_from_slice(&magic);
        write_le_u32(
            &mut buf,
            parallels::VERSION_OFFSET,
            shared::format_detection::PARALLELS_VERSION,
        );
        write_le_u32(&mut buf, parallels::TRACKS_OFFSET, tracks);
        write_le_u32(&mut buf, parallels::BAT_ENTRIES_OFFSET, bat_entries);
        write_le_u64(&mut buf, parallels::NB_SECTORS_OFFSET, nb_sectors);
        buf
    }

    /// Install a synthetic Parallels image (pattern everywhere, then the
    /// header at 0 and the LE u32 BAT at [`parallels::HEADER_SIZE`]), init a
    /// [`parallels::ParallelsState`], and read one chunk through
    /// [`read_chain_virtual_cluster`] as a single-device chain. The chain's
    /// `ChainDeviceInfo.cluster_size` is set to `info_cluster_size` (pass 0
    /// to model the pre-info-plumbing state — the arm must still be correct,
    /// since its cluster boundary comes from the header-derived
    /// `state.cluster_size`, not from the chunk). Returns the produced bytes.
    #[cfg(feature = "parallels-input")]
    fn run_pls_chain_read(
        header: &[u8; 512],
        bat: &[u32],
        cap_sectors: u64,
        sector_size: usize,
        info_cluster_size: u32,
        virtual_offset: u64,
        chunk_size: u64,
    ) -> std::vec::Vec<u8> {
        let _guard = PLS_MOCK_LOCK.lock().unwrap();

        let len = cap_sectors as usize * sector_size;
        let mut image = std::vec![0u8; len];
        for (i, b) in image.iter_mut().enumerate() {
            *b = pls_pattern_byte(i as u64);
        }
        image[..512].copy_from_slice(header);
        for (i, &entry) in bat.iter().enumerate() {
            let off = parallels::HEADER_SIZE + i * 4;
            image[off..off + 4].copy_from_slice(&entry.to_le_bytes());
        }

        unsafe {
            PLS_MOCK_PTR = image.as_ptr();
            PLS_MOCK_CAP_SECTORS = cap_sectors;
            PLS_MOCK_SSZ = sector_size;
        }
        let call_table = pls_call_table();

        let mut bat_cache = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut data_cache = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let state = unsafe {
            parallels::ParallelsState::init(
                &call_table,
                0,
                sector_size,
                cap_sectors,
                bat_cache.as_mut_ptr(),
                data_cache.as_mut_ptr(),
                &mut bytes_read,
            )
        }
        .expect("ParallelsState::init should succeed for a valid header");

        let mut chain_states = ChainStates::default();
        chain_states.parallels_states[0] = Some(state);

        let mut chain_config = ChainConfig::new();
        chain_config.magic = ChainConfig::MAGIC;
        chain_config.version = ChainConfig::VERSION;
        chain_config.device_count = 1;
        chain_config.devices[0].format = ImageFormat::Parallels as u32;
        chain_config.devices[0].cluster_size = info_cluster_size;
        chain_config.devices[0].data_device_idx = 0;

        let mut compressed_buf = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut staging_buf = std::vec![0u8; MAX_SECTOR_SIZE];
        let mut staging_cluster_offset = u64::MAX;

        let mut out = std::vec![0xAAu8; chunk_size as usize];
        let ok = unsafe {
            read_chain_virtual_cluster(
                &call_table,
                0,
                1,
                virtual_offset,
                out.as_mut_ptr(),
                chunk_size,
                sector_size,
                &chain_config,
                &mut chain_states,
                compressed_buf.as_mut_ptr(),
                staging_buf.as_mut_ptr(),
                &mut staging_cluster_offset,
                None,
                None,
                0,
                &mut bytes_read,
            )
        };
        // Drop the dangling global before `image` is freed.
        unsafe {
            PLS_MOCK_PTR = core::ptr::null();
        }
        assert!(ok, "read_chain_virtual_cluster returned false");
        out
    }

    #[cfg(feature = "parallels-input")]
    #[test]
    fn pls_arm_hole_reads_zeros() {
        // BAT value 0 → unallocated cluster; a parallels image has no lower
        // device, so the arm zero-fills in place.
        let header = build_pls_header(shared::format_detection::PARALLELS_MAGIC_V2, 128, 4, 4096);
        let out = run_pls_chain_read(&header, &[0, 0, 0, 0], 2, 4096, 65536, 0, 4096);
        assert!(
            out.iter().all(|&b| b == 0),
            "unallocated parallels cluster must read as zeros, got {:02x?}",
            &out[..16]
        );
    }

    #[cfg(feature = "parallels-input")]
    #[test]
    fn pls_arm_both_magics_identical_reads() {
        // The per-magic gotcha, through the arm: with tracks=128 the v1 BAT
        // `[0x80, 0x100]` (sector numbers, off_multiplier 1) and the ext BAT
        // `[1, 2]` (cluster indices, off_multiplier tracks) both decode
        // cluster 0 to host 0x10000. A full-cluster (65536) read must return
        // the identical device bytes under either magic.
        let expect: std::vec::Vec<u8> = (0..65536u64)
            .map(|i| pls_pattern_byte(0x10000 + i))
            .collect();

        let v1 = build_pls_header(shared::format_detection::PARALLELS_MAGIC_V1, 128, 2, 4096);
        let out_v1 = run_pls_chain_read(&v1, &[0x80, 0x100], 48, 4096, 65536, 0, 65536);
        assert_eq!(out_v1, expect, "v1 magic (sector-valued BAT)");

        let ext = build_pls_header(shared::format_detection::PARALLELS_MAGIC_V2, 128, 2, 4096);
        let out_ext = run_pls_chain_read(&ext, &[1, 2], 48, 4096, 65536, 0, 65536);
        assert_eq!(out_ext, expect, "ext magic (cluster-valued BAT)");

        assert_eq!(out_v1, out_ext, "both magics must produce identical reads");
    }

    #[cfg(feature = "parallels-input")]
    #[test]
    fn pls_arm_non_contiguous_bat_multi_cluster_chunk() {
        // ext magic, tracks=128: BAT [0, 2, 0, 1] — a hole, a non-identity
        // allocation (cluster 1 → entry 2 → host 0x20000), a second hole,
        // then cluster 3 → entry 1 → host 0x10000. A single 4-cluster chunk
        // (262144 bytes) crosses three cluster boundaries and must decode
        // each cluster independently.
        let header = build_pls_header(shared::format_detection::PARALLELS_MAGIC_V2, 128, 4, 16384);
        let out = run_pls_chain_read(&header, &[0, 2, 0, 1], 48, 4096, 65536, 0, 4 * 65536);
        let cl = 65536usize;
        assert!(out[..cl].iter().all(|&b| b == 0), "cluster 0 hole");
        let want1: std::vec::Vec<u8> = (0..cl as u64)
            .map(|i| pls_pattern_byte(0x20000 + i))
            .collect();
        assert_eq!(out[cl..2 * cl], want1[..], "cluster 1 → host 0x20000");
        assert!(
            out[2 * cl..3 * cl].iter().all(|&b| b == 0),
            "cluster 2 hole"
        );
        let want3: std::vec::Vec<u8> = (0..cl as u64)
            .map(|i| pls_pattern_byte(0x10000 + i))
            .collect();
        assert_eq!(out[3 * cl..4 * cl], want3[..], "cluster 3 → host 0x10000");
    }

    #[cfg(feature = "parallels-input")]
    #[test]
    fn pls_arm_unaligned_data_offset() {
        // Parallels data offsets are 512-aligned but not necessarily aligned
        // to the guest's virtio sector. v1 magic (off_multiplier 1), a BAT
        // value of 3 → host = 3 * 512 = 1536, which is not a multiple of the
        // 4096-byte guest sector, so the arm takes the unaligned read path.
        let header = build_pls_header(shared::format_detection::PARALLELS_MAGIC_V1, 8, 1, 8);
        let out = run_pls_chain_read(&header, &[3], 2, 4096, 4096, 0, 4096);
        let want: std::vec::Vec<u8> = (0..4096u64).map(|i| pls_pattern_byte(1536 + i)).collect();
        assert_eq!(
            out, want,
            "unaligned parallels data offset must read device data via the unaligned path"
        );
    }

    #[cfg(feature = "parallels-input")]
    #[test]
    fn pls_arm_allocated_past_capacity_zero_fills() {
        // ext magic, BAT entry 100 → host = 100 * 128 * 512 = 0x640000, far
        // past the 2-sector capacity. qemu never validates parallels file
        // length, so the whole cluster zero-fills rather than erroring.
        let header = build_pls_header(shared::format_detection::PARALLELS_MAGIC_V2, 128, 4, 4096);
        let out = run_pls_chain_read(&header, &[100, 0, 0, 0], 2, 4096, 65536, 0, 4096);
        assert!(
            out.iter().all(|&b| b == 0),
            "past-capacity parallels cluster must zero-fill, got {:02x?}",
            &out[..16]
        );
    }

    #[cfg(feature = "parallels-input")]
    #[test]
    fn pls_arm_allocated_straddle_zero_fills_tail() {
        // An allocated cluster that starts in-file but whose read runs off
        // the device end: the in-capacity prefix returns device data and
        // only the truncated tail zero-fills. sector_size 512 lets the
        // capacity land mid-cluster. ext magic, tracks=8 (4 KiB cluster),
        // BAT [1] → host = 1 * 8 * 512 = 4096. Capacity 13 sectors = 6656
        // bytes: a 4096-byte cluster read from 4096 has 2560 in-file bytes
        // then 1536 zero.
        let header = build_pls_header(shared::format_detection::PARALLELS_MAGIC_V2, 8, 1, 16);
        let out = run_pls_chain_read(&header, &[1], 13, 512, 4096, 0, 4096);
        let prefix = 2560usize; // 6656 - 4096
        let want: std::vec::Vec<u8> = (0..4096u64)
            .map(|i| {
                if (i as usize) < prefix {
                    pls_pattern_byte(4096 + i)
                } else {
                    0
                }
            })
            .collect();
        assert_eq!(
            out, want,
            "straddling parallels read must return the in-file prefix and zero the truncated tail"
        );
    }

    #[cfg(feature = "parallels-input")]
    #[test]
    fn pls_arm_small_cluster_multi_cluster_span() {
        // THE CHUNK-BOUNDARY PIN. tracks=8 → 4 KiB clusters, and a 65536-byte
        // chunk (as `compare`/`bench`/`rebase` can hand the arm) spans
        // sixteen of them. ChainDeviceInfo.cluster_size is 4096, but the arm
        // relies on the header-derived cluster size to walk cluster-by-cluster
        // through the scattered ext BAT. Every cluster — hole or allocated —
        // must decode independently.
        let header = build_pls_header(shared::format_detection::PARALLELS_MAGIC_V2, 8, 16, 128);
        // ext off_multiplier=tracks: entry e → host = e * 4096 (= sector e).
        let bat = [0u32, 5, 0, 3, 7, 0, 0, 2, 0, 9, 0, 0, 0, 0, 0, 11];
        let out = run_pls_chain_read(&header, &bat, 16, 4096, 4096, 0, 65536);
        let cl = 4096usize;
        for (i, &entry) in bat.iter().enumerate() {
            let region = &out[i * cl..(i + 1) * cl];
            if entry == 0 {
                assert!(
                    region.iter().all(|&b| b == 0),
                    "cluster {i} hole must be zero"
                );
            } else {
                let base = entry as u64 * 4096;
                let want: std::vec::Vec<u8> =
                    (0..cl as u64).map(|j| pls_pattern_byte(base + j)).collect();
                assert_eq!(region, &want[..], "cluster {i} → host {base:#x}");
            }
        }
    }

    #[cfg(feature = "parallels-input")]
    #[test]
    fn pls_arm_chunk_starting_at_cluster_boundary() {
        // A chunk that begins partway into the image at a cluster boundary
        // (as `compare` produces once virtual_offset advances) and spans a
        // hole→allocated boundary. tracks=8, ext BAT [0,1,0,3]; read the two
        // clusters 2 and 3 starting at virtual offset 8192: cluster 2 is a
        // hole, cluster 3 → entry 3 → host 0x3000.
        let header = build_pls_header(shared::format_detection::PARALLELS_MAGIC_V2, 8, 4, 32);
        let out = run_pls_chain_read(&header, &[0, 1, 0, 3], 4, 4096, 4096, 8192, 8192);
        let cl = 4096usize;
        assert!(out[..cl].iter().all(|&b| b == 0), "cluster 2 hole");
        let want: std::vec::Vec<u8> = (0..cl as u64)
            .map(|j| pls_pattern_byte(3 * 4096 + j))
            .collect();
        assert_eq!(out[cl..2 * cl], want[..], "cluster 3 → host 0x3000");
    }

    // ====================================================================
    // QCOW1 chain-reader arm (feature = "qcow1-input")
    // ====================================================================
    //
    // These exercise the guest-side arm added for QCOW1 input. It combines
    // three precedents: the Parallels per-cluster walk (qcow1 clusters can be
    // 512 B, smaller than any chunk); the Qcow2 arm's BACKING FALL-THROUGH (an
    // unallocated cluster descends to the next chain device via recursion into
    // `read_chain_virtual_cluster` for its own sub-span — NOT zero-fill — with
    // zeros only at the bottom of the chain); and the Vdi/Parallels
    // capacity-clamped zero-fill for past-EOF/straddle. Unlike the
    // single-device vdi/pls mocks, the mock here dispatches on `device_idx` so
    // a multi-device chain (qcow1 overlay over a raw backing) can be modelled.

    #[cfg(feature = "qcow1-input")]
    const Q1_MAX_DEVS: usize = 3;
    #[cfg(feature = "qcow1-input")]
    static Q1_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[cfg(feature = "qcow1-input")]
    static mut Q1_IMAGES: [*const u8; Q1_MAX_DEVS] = [core::ptr::null(); Q1_MAX_DEVS];
    #[cfg(feature = "qcow1-input")]
    static mut Q1_LENS: [usize; Q1_MAX_DEVS] = [0; Q1_MAX_DEVS];
    #[cfg(feature = "qcow1-input")]
    static mut Q1_SSZ: usize = 512;

    /// Overlay device byte at absolute host offset `o`.
    #[cfg(feature = "qcow1-input")]
    fn q1_overlay_byte(o: u64) -> u8 {
        (o % 251) as u8
    }
    /// Backing device byte at virtual offset `o`; a distinct period and a +1
    /// bias so a wrong-device read cannot silently match the overlay pattern.
    #[cfg(feature = "qcow1-input")]
    fn q1_backing_byte(o: u64) -> u8 {
        ((o % 241) as u8).wrapping_add(1)
    }

    /// Per-device mock: fails any sector at/beyond the device length so a read
    /// the arm fails to clamp surfaces as an error, not fabricated bytes.
    #[cfg(feature = "qcow1-input")]
    unsafe extern "C" fn q1_read_sector(
        device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        let d = device_idx as usize;
        if d >= Q1_MAX_DEVS {
            return false;
        }
        let imgs = core::ptr::addr_of!(Q1_IMAGES) as *const *const u8;
        let lens = core::ptr::addr_of!(Q1_LENS) as *const usize;
        let ptr = *imgs.add(d);
        let len = *lens.add(d);
        if ptr.is_null() {
            return false;
        }
        let start = match (sector as usize).checked_mul(sector_size) {
            Some(s) => s,
            None => return false,
        };
        if start + sector_size > len {
            return false;
        }
        core::ptr::copy_nonoverlapping(ptr.add(start), out_buf, sector_size);
        true
    }

    #[cfg(feature = "qcow1-input")]
    unsafe extern "C" fn q1_capacity(device_idx: u32) -> u64 {
        let d = device_idx as usize;
        if d >= Q1_MAX_DEVS {
            return 0;
        }
        let lens = core::ptr::addr_of!(Q1_LENS) as *const usize;
        (*lens.add(d) / Q1_SSZ) as u64
    }

    #[cfg(feature = "qcow1-input")]
    unsafe extern "C" fn q1_ssz(_device_idx: u32) -> usize {
        Q1_SSZ
    }

    #[cfg(feature = "qcow1-input")]
    fn q1_call_table() -> shared::CallTable {
        shared::CallTable {
            read_input_sector: q1_read_sector,
            get_input_capacity: q1_capacity,
            get_input_sector_size: q1_ssz,
            ..stub_call_table()
        }
    }

    #[cfg(feature = "qcow1-input")]
    struct Q1Spec {
        cluster_bits: u8,
        l2_bits: u8,
        virtual_size: u64,
        crypt_method: u32,
    }

    #[cfg(feature = "qcow1-input")]
    fn build_q1_header_bytes(spec: &Q1Spec, l1_table_offset: u64) -> [u8; 512] {
        use shared::{write_be_u32, write_be_u64};
        let mut buf = [0u8; 512];
        write_be_u32(
            &mut buf,
            qcow1::MAGIC_OFFSET,
            shared::format_detection::QCOW2_MAGIC,
        );
        write_be_u32(&mut buf, qcow1::VERSION_OFFSET, qcow1::QCOW1_VERSION);
        write_be_u64(&mut buf, qcow1::SIZE_OFFSET, spec.virtual_size);
        buf[qcow1::CLUSTER_BITS_OFFSET] = spec.cluster_bits;
        buf[qcow1::L2_BITS_OFFSET] = spec.l2_bits;
        write_be_u32(&mut buf, qcow1::CRYPT_METHOD_OFFSET, spec.crypt_method);
        write_be_u64(&mut buf, qcow1::L1_TABLE_OFFSET_OFFSET, l1_table_offset);
        buf
    }

    #[cfg(feature = "qcow1-input")]
    fn q1_put_u64(img: &mut [u8], byte_off: usize, val: u64) {
        img[byte_off..byte_off + 8].copy_from_slice(&val.to_be_bytes());
    }

    /// Build a single-L1-entry qcow1 overlay image: header at 0, L1[0] pointing
    /// at `l2_table_offset`, the given `l2_values` (l2_index → raw u64 entry),
    /// and each `(host, len)` in `data_fills` filled with the overlay pattern.
    /// Everything else is zero, so any L2 index not listed reads as a hole.
    #[cfg(feature = "qcow1-input")]
    #[allow(clippy::too_many_arguments)]
    fn build_q1_overlay(
        cluster_bits: u8,
        l2_bits: u8,
        virtual_size: u64,
        total_len: usize,
        crypt_method: u32,
        l1_table_offset: u64,
        l2_table_offset: u64,
        l2_values: &[(u64, u64)],
        data_fills: &[(u64, u64)],
    ) -> std::vec::Vec<u8> {
        let mut img = std::vec![0u8; total_len];
        let hdr = build_q1_header_bytes(
            &Q1Spec {
                cluster_bits,
                l2_bits,
                virtual_size,
                crypt_method,
            },
            l1_table_offset,
        );
        img[..512].copy_from_slice(&hdr);
        q1_put_u64(&mut img, l1_table_offset as usize, l2_table_offset);
        for &(idx, val) in l2_values {
            q1_put_u64(&mut img, (l2_table_offset + idx * 8) as usize, val);
        }
        for &(host, len) in data_fills {
            for i in 0..len {
                img[(host + i) as usize] = q1_overlay_byte(host + i);
            }
        }
        img
    }

    /// A device in the mock chain: its raw bytes and its detected format.
    #[cfg(feature = "qcow1-input")]
    struct Q1Device {
        bytes: std::vec::Vec<u8>,
        format: ImageFormat,
    }

    /// Init per-device qcow1 state, wire a `ChainConfig`, and read one span
    /// through [`read_chain_virtual_cluster`] over the whole chain. Returns the
    /// produced bytes. The ChainDeviceInfo cluster_size is populated from the
    /// header (the arm ignores it — its boundary is the header-derived
    /// `state.cluster_size`).
    #[cfg(feature = "qcow1-input")]
    fn run_q1_chain_read(
        devices: &[Q1Device],
        sector_size: usize,
        virtual_offset: u64,
        chunk_size: u64,
    ) -> std::vec::Vec<u8> {
        let _guard = Q1_LOCK.lock().unwrap();
        assert!(devices.len() <= Q1_MAX_DEVS);

        unsafe {
            Q1_SSZ = sector_size;
            let imgs = core::ptr::addr_of_mut!(Q1_IMAGES) as *mut *const u8;
            let lens = core::ptr::addr_of_mut!(Q1_LENS) as *mut usize;
            for i in 0..Q1_MAX_DEVS {
                if i < devices.len() {
                    *imgs.add(i) = devices[i].bytes.as_ptr();
                    *lens.add(i) = devices[i].bytes.len();
                } else {
                    *imgs.add(i) = core::ptr::null();
                    *lens.add(i) = 0;
                }
            }
        }
        let call_table = q1_call_table();

        // Two cache buffers (L1 + L2) per device, kept alive for the read.
        let mut caches: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
        for _ in 0..devices.len() {
            caches.push(std::vec![0u8; MAX_SECTOR_SIZE]);
            caches.push(std::vec![0u8; MAX_SECTOR_SIZE]);
        }

        let mut chain_states = ChainStates::default();
        let mut chain_config = ChainConfig::new();
        chain_config.magic = ChainConfig::MAGIC;
        chain_config.version = ChainConfig::VERSION;
        chain_config.device_count = devices.len() as u32;

        let mut bytes_read = 0u64;
        for (i, d) in devices.iter().enumerate() {
            chain_config.devices[i].format = d.format as u32;
            chain_config.devices[i].data_device_idx = 0;
            let cap = unsafe { (call_table.get_input_capacity)(i as u32) };
            if matches!(d.format, ImageFormat::Qcow1) {
                let l1 = caches[i * 2].as_mut_ptr();
                let l2 = caches[i * 2 + 1].as_mut_ptr();
                chain_states.qcow1_states[i] = unsafe {
                    qcow1::Qcow1State::init(
                        &call_table,
                        i as u32,
                        sector_size,
                        cap,
                        l1,
                        l2,
                        &mut bytes_read,
                    )
                };
                let cs = chain_states.qcow1_states[i]
                    .as_ref()
                    .expect("Qcow1State::init should succeed for a valid header")
                    .cluster_size;
                chain_config.devices[i].cluster_size = cs as u32;
            }
        }

        let mut compressed_buf = std::vec![0u8; COMPRESSED_BUF_SIZE];
        let mut staging_buf = std::vec![0u8; MAX_CLUSTER_SIZE];
        let mut staging_cluster_offset = u64::MAX;

        let mut out = std::vec![0xAAu8; chunk_size as usize];
        let ok = unsafe {
            read_chain_virtual_cluster(
                &call_table,
                0,
                devices.len(),
                virtual_offset,
                out.as_mut_ptr(),
                chunk_size,
                sector_size,
                &chain_config,
                &mut chain_states,
                compressed_buf.as_mut_ptr(),
                staging_buf.as_mut_ptr(),
                &mut staging_cluster_offset,
                None,
                None,
                0,
                &mut bytes_read,
            )
        };
        unsafe {
            let imgs = core::ptr::addr_of_mut!(Q1_IMAGES) as *mut *const u8;
            for i in 0..Q1_MAX_DEVS {
                *imgs.add(i) = core::ptr::null();
            }
        }
        assert!(ok, "read_chain_virtual_cluster returned false");
        out
    }

    // (a) An unallocated overlay cluster descends to the backing device.
    #[cfg(feature = "qcow1-input")]
    #[test]
    fn q1_arm_unallocated_descends_to_backing() {
        // Overlay: 4 KiB clusters, cluster 0 is a hole (no L2 value). Backing:
        // a raw device whose byte at virtual offset v is q1_backing_byte(v).
        let overlay = build_q1_overlay(12, 9, 64 * 1024, 64 * 1024, 0, 0x200, 0x400, &[], &[]);
        let mut backing = std::vec![0u8; 64 * 1024];
        for (i, b) in backing.iter_mut().enumerate() {
            *b = q1_backing_byte(i as u64);
        }
        let devices = [
            Q1Device {
                bytes: overlay,
                format: ImageFormat::Qcow1,
            },
            Q1Device {
                bytes: backing,
                format: ImageFormat::Raw,
            },
        ];
        let out = run_q1_chain_read(&devices, 512, 0, 4096);
        let want: std::vec::Vec<u8> = (0..4096u64).map(q1_backing_byte).collect();
        assert_eq!(
            out, want,
            "unallocated qcow1 cluster must read through to the backing device"
        );
    }

    // (b) One chunk with interleaved allocated + unallocated clusters: the
    // allocated sub-spans come from the overlay, the holes from the backing.
    #[cfg(feature = "qcow1-input")]
    #[test]
    fn q1_arm_mixed_chunk_allocated_and_backing() {
        // Overlay: cluster 0 → host 0x2000, cluster 1 hole, cluster 2 → host
        // 0x3000, cluster 3 hole. A single 4-cluster (16384-byte) chunk mixes
        // allocated (overlay) and unallocated (backing) sub-spans.
        let overlay = build_q1_overlay(
            12,
            9,
            64 * 1024,
            64 * 1024,
            0,
            0x200,
            0x400,
            &[(0, 0x2000), (2, 0x3000)],
            &[(0x2000, 4096), (0x3000, 4096)],
        );
        let mut backing = std::vec![0u8; 64 * 1024];
        for (i, b) in backing.iter_mut().enumerate() {
            *b = q1_backing_byte(i as u64);
        }
        let devices = [
            Q1Device {
                bytes: overlay,
                format: ImageFormat::Qcow1,
            },
            Q1Device {
                bytes: backing,
                format: ImageFormat::Raw,
            },
        ];
        let out = run_q1_chain_read(&devices, 512, 0, 4 * 4096);
        let cl = 4096usize;
        // Cluster 0: overlay @ host 0x2000.
        let w0: std::vec::Vec<u8> = (0..cl as u64)
            .map(|i| q1_overlay_byte(0x2000 + i))
            .collect();
        assert_eq!(out[..cl], w0[..], "cluster 0 from overlay");
        // Cluster 1: hole → backing @ virtual 4096.
        let w1: std::vec::Vec<u8> = (0..cl as u64).map(|i| q1_backing_byte(4096 + i)).collect();
        assert_eq!(out[cl..2 * cl], w1[..], "cluster 1 from backing");
        // Cluster 2: overlay @ host 0x3000.
        let w2: std::vec::Vec<u8> = (0..cl as u64)
            .map(|i| q1_overlay_byte(0x3000 + i))
            .collect();
        assert_eq!(out[2 * cl..3 * cl], w2[..], "cluster 2 from overlay");
        // Cluster 3: hole → backing @ virtual 12288.
        let w3: std::vec::Vec<u8> = (0..cl as u64).map(|i| q1_backing_byte(12288 + i)).collect();
        assert_eq!(out[3 * cl..4 * cl], w3[..], "cluster 3 from backing");
    }

    // (c) A compressed (raw-DEFLATE) cluster inflates end-to-end, including a
    // windowed sub-cluster read.
    #[cfg(feature = "qcow1-input")]
    #[test]
    fn q1_arm_compressed_cluster_end_to_end() {
        // A compressible-but-position-sensitive 4 KiB plaintext.
        let plaintext: std::vec::Vec<u8> = (0..4096u64).map(|i| ((i >> 2) & 0x3f) as u8).collect();
        // Raw DEFLATE (no zlib header) — exactly what qcow1 stores.
        let blob = miniz_oxide::deflate::compress_to_vec(&plaintext, 6);
        assert!(
            blob.len() < 4096,
            "compressed blob must fit the csize field (< cluster_size), got {}",
            blob.len()
        );
        // Place the blob at an UNALIGNED host offset to exercise the
        // byte-accurate read; encode the compressed L2 entry.
        let host = 0x2003u64;
        let shift = 63 - 12u32; // 51
        let entry = (1u64 << 63) | ((blob.len() as u64) << shift) | host;

        let mut overlay = build_q1_overlay(
            12,
            9,
            64 * 1024,
            64 * 1024,
            0,
            0x200,
            0x400,
            &[(0, entry)],
            &[],
        );
        overlay[host as usize..host as usize + blob.len()].copy_from_slice(&blob);

        // Full-cluster read.
        let devices = [Q1Device {
            bytes: overlay,
            format: ImageFormat::Qcow1,
        }];
        let out = run_q1_chain_read(&devices, 512, 0, 4096);
        assert_eq!(
            out, plaintext,
            "compressed cluster must inflate to plaintext"
        );

        // Windowed read: 1024 bytes starting 100 into the cluster copies the
        // matching slice of the inflated cluster.
        let overlay2 = {
            let mut o = build_q1_overlay(
                12,
                9,
                64 * 1024,
                64 * 1024,
                0,
                0x200,
                0x400,
                &[(0, entry)],
                &[],
            );
            o[host as usize..host as usize + blob.len()].copy_from_slice(&blob);
            o
        };
        let devices2 = [Q1Device {
            bytes: overlay2,
            format: ImageFormat::Qcow1,
        }];
        let out2 = run_q1_chain_read(&devices2, 512, 100, 1024);
        assert_eq!(
            out2[..],
            plaintext[100..1124],
            "windowed compressed read must copy the right sub-span"
        );
    }

    // (d) A 512-byte-cluster walk across a chunk with scattered allocations and
    // holes (no backing → holes read as zeros).
    #[cfg(feature = "qcow1-input")]
    #[test]
    fn q1_arm_small_cluster_walk() {
        // cluster_bits=9 (512-byte clusters), l2_bits=12 (4096 entries).
        // Clusters 0,2,5 allocated (data past the 32 KiB L2 table); the rest
        // are holes. A 4096-byte chunk spans eight 512-byte clusters.
        let overlay = build_q1_overlay(
            9,
            12,
            16 * 1024,
            64 * 1024,
            0,
            0x200,
            0x400,
            &[(0, 0x9000), (2, 0x9200), (5, 0x9400)],
            &[(0x9000, 512), (0x9200, 512), (0x9400, 512)],
        );
        let devices = [Q1Device {
            bytes: overlay,
            format: ImageFormat::Qcow1,
        }];
        let out = run_q1_chain_read(&devices, 512, 0, 4096);
        let cl = 512usize;
        let alloc: [(usize, u64); 3] = [(0, 0x9000), (2, 0x9200), (5, 0x9400)];
        for c in 0..8usize {
            let region = &out[c * cl..(c + 1) * cl];
            if let Some(&(_, host)) = alloc.iter().find(|&&(idx, _)| idx == c) {
                let want: std::vec::Vec<u8> =
                    (0..cl as u64).map(|j| q1_overlay_byte(host + j)).collect();
                assert_eq!(region, &want[..], "cluster {c} → host {host:#x}");
            } else {
                assert!(
                    region.iter().all(|&b| b == 0),
                    "cluster {c} hole must be zero"
                );
            }
        }
    }

    // (e) An allocated cluster whose host offset is past capacity zero-fills.
    #[cfg(feature = "qcow1-input")]
    #[test]
    fn q1_arm_allocated_past_capacity_zero_fills() {
        // L2[0] points 1 MiB into a 64 KiB device: qemu never validates file
        // length, so the whole cluster zero-fills rather than erroring.
        let overlay = build_q1_overlay(
            12,
            9,
            64 * 1024,
            64 * 1024,
            0,
            0x200,
            0x400,
            &[(0, 0x100000)],
            &[],
        );
        let devices = [Q1Device {
            bytes: overlay,
            format: ImageFormat::Qcow1,
        }];
        let out = run_q1_chain_read(&devices, 512, 0, 4096);
        assert!(
            out.iter().all(|&b| b == 0),
            "past-capacity qcow1 cluster must zero-fill, got {:02x?}",
            &out[..16]
        );
    }

    // (f) A straddling allocated cluster returns the in-file prefix and zero
    // fills the truncated tail.
    #[cfg(feature = "qcow1-input")]
    #[test]
    fn q1_arm_allocated_straddle_zero_fills_tail() {
        // L2[0] → host 8192. Device length 10752 (21 × 512) so a 4096-byte
        // cluster read from 8192 has 2560 in-file bytes then 1536 zero.
        let total_len = 21 * 512usize; // 10752
        let overlay = build_q1_overlay(
            12,
            9,
            64 * 1024,
            total_len,
            0,
            0x200,
            0x400,
            &[(0, 8192)],
            &[(8192, 2560)],
        );
        let devices = [Q1Device {
            bytes: overlay,
            format: ImageFormat::Qcow1,
        }];
        let out = run_q1_chain_read(&devices, 512, 0, 4096);
        let prefix = 2560usize;
        let want: std::vec::Vec<u8> = (0..4096u64)
            .map(|i| {
                if (i as usize) < prefix {
                    q1_overlay_byte(8192 + i)
                } else {
                    0
                }
            })
            .collect();
        assert_eq!(
            out, want,
            "straddling qcow1 read must return the in-file prefix and zero the tail"
        );
    }

    // (g) With no backing device, an unallocated cluster reads as zeros.
    #[cfg(feature = "qcow1-input")]
    #[test]
    fn q1_arm_no_backing_unallocated_reads_zeros() {
        let overlay = build_q1_overlay(12, 9, 64 * 1024, 64 * 1024, 0, 0x200, 0x400, &[], &[]);
        let devices = [Q1Device {
            bytes: overlay,
            format: ImageFormat::Qcow1,
        }];
        let out = run_q1_chain_read(&devices, 512, 0, 4096);
        assert!(
            out.iter().all(|&b| b == 0),
            "bottom-of-chain unallocated qcow1 cluster must read as zeros"
        );
    }

    // (h) An encrypted image fails chain init (and the op therefore fails
    // cleanly) — the reader-level crypt refusal propagates like the other arms.
    #[cfg(feature = "qcow1-input")]
    #[test]
    fn q1_arm_encrypted_init_fails_cleanly() {
        let _guard = Q1_LOCK.lock().unwrap();
        let mut img = std::vec![0u8; 64 * 1024];
        let hdr = build_q1_header_bytes(
            &Q1Spec {
                cluster_bits: 12,
                l2_bits: 9,
                virtual_size: 64 * 1024,
                crypt_method: 1, // AES: parses (for info) but init refuses.
            },
            0x200,
        );
        img[..512].copy_from_slice(&hdr);

        unsafe {
            Q1_SSZ = 512;
            let imgs = core::ptr::addr_of_mut!(Q1_IMAGES) as *mut *const u8;
            let lens = core::ptr::addr_of_mut!(Q1_LENS) as *mut usize;
            *imgs = img.as_ptr();
            *lens = img.len();
        }
        let call_table = q1_call_table();

        let mut chain_states = ChainStates::default();
        let mut chain_config = ChainConfig::new();
        chain_config.magic = ChainConfig::MAGIC;
        chain_config.version = ChainConfig::VERSION;
        chain_config.device_count = 1;
        chain_config.devices[0].format = ImageFormat::Qcow1 as u32;

        let mut cache = std::vec![0u8; 2 * MAX_SECTOR_SIZE];
        let dynamic_bufs_start = cache.as_mut_ptr() as usize;
        let mut bytes_read = 0u64;
        let ok = unsafe {
            init_chain_states(
                &call_table,
                &chain_config,
                &mut chain_states,
                1,
                512,
                dynamic_bufs_start,
                // No DMG device in this chain; the DMG scratch args are
                // unused (0/0 is fine — the DMG arm is never reached).
                0,
                0,
                &mut bytes_read,
            )
        };
        unsafe {
            let imgs = core::ptr::addr_of_mut!(Q1_IMAGES) as *mut *const u8;
            *imgs = core::ptr::null();
        }
        assert!(!ok, "encrypted qcow1 must fail chain init");
        assert!(
            chain_states.qcow1_states[0].is_none(),
            "no state should be recorded for the refused encrypted device"
        );
    }

    // ========================================================================
    // DMG chain-reader arm (read_chain_virtual_cluster ImageFormat::Dmg)
    //
    // Synthetic UDIF images ([data fork][xml plist w/ one mish][koly]) are
    // served through a zero-padded mock device (a real virtio device
    // rounds capacity up to a sector, reading zeros past the file tail).
    // data_fork_offset / mish out_offset / data_offset are all 0, so a
    // chunk's effective host offset equals its raw comp_offset.
    // ========================================================================

    #[cfg(feature = "dmg-input")]
    const DMG_MOCK_LEN: usize = 4 * 1024 * 1024;
    #[cfg(feature = "dmg-input")]
    static DMG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[cfg(feature = "dmg-input")]
    static mut DMG_IMAGE: [u8; DMG_MOCK_LEN] = [0u8; DMG_MOCK_LEN];
    #[cfg(feature = "dmg-input")]
    static mut DMG_CAP: u64 = 0;
    #[cfg(feature = "dmg-input")]
    static mut DMG_SSZ: usize = 512;
    // Captured debug_print message (typed refusal string), null-stripped.
    #[cfg(feature = "dmg-input")]
    static mut DMG_DBG_BUF: [u8; 128] = [0u8; 128];
    #[cfg(feature = "dmg-input")]
    static mut DMG_DBG_LEN: usize = 0;

    #[cfg(feature = "dmg-input")]
    unsafe extern "C" fn dmg_read_sector(
        _device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        if sector >= DMG_CAP {
            return false;
        }
        let start = match (sector as usize).checked_mul(sector_size) {
            Some(s) => s,
            None => return false,
        };
        if start + sector_size > DMG_MOCK_LEN {
            return false;
        }
        let src = core::ptr::addr_of!(DMG_IMAGE) as *const u8;
        core::ptr::copy_nonoverlapping(src.add(start), out_buf, sector_size);
        true
    }

    #[cfg(feature = "dmg-input")]
    unsafe extern "C" fn dmg_capacity(_device_idx: u32) -> u64 {
        DMG_CAP
    }

    #[cfg(feature = "dmg-input")]
    unsafe extern "C" fn dmg_ssz(_device_idx: u32) -> usize {
        DMG_SSZ
    }

    #[cfg(feature = "dmg-input")]
    unsafe extern "C" fn dmg_dbg(msg: *const u8) {
        let mut n = 0usize;
        while n < 127 && *msg.add(n) != 0 {
            n += 1;
        }
        let dst = core::ptr::addr_of_mut!(DMG_DBG_BUF) as *mut u8;
        core::ptr::copy_nonoverlapping(msg, dst, n);
        DMG_DBG_LEN = n;
    }

    #[cfg(feature = "dmg-input")]
    fn dmg_call_table() -> shared::CallTable {
        shared::CallTable {
            read_input_sector: dmg_read_sector,
            get_input_capacity: dmg_capacity,
            get_input_sector_size: dmg_ssz,
            debug_print: dmg_dbg,
            ..stub_call_table()
        }
    }

    /// Install an image into the zero-padded mock; return its capacity in
    /// sectors. Caller holds DMG_LOCK.
    #[cfg(feature = "dmg-input")]
    fn install_dmg(image: &[u8], sector_size: usize) -> u64 {
        assert!(image.len() <= DMG_MOCK_LEN, "image too big for mock");
        unsafe {
            let img = core::ptr::addr_of_mut!(DMG_IMAGE) as *mut u8;
            core::ptr::write_bytes(img, 0, DMG_MOCK_LEN);
            core::ptr::copy_nonoverlapping(image.as_ptr(), img, image.len());
            DMG_CAP = image.len().div_ceil(sector_size) as u64;
            DMG_SSZ = sector_size;
            DMG_CAP
        }
    }

    #[cfg(feature = "dmg-input")]
    fn dmg_b64(data: &[u8]) -> std::string::String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = std::string::String::new();
        for c in data.chunks(3) {
            let b0 = c[0] as u32;
            let b1 = if c.len() > 1 { c[1] as u32 } else { 0 };
            let b2 = if c.len() > 2 { c[2] as u32 } else { 0 };
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(A[((n >> 18) & 63) as usize] as char);
            out.push(A[((n >> 12) & 63) as usize] as char);
            out.push(if c.len() > 1 {
                A[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if c.len() > 2 {
                A[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    /// One synthetic mish chunk entry.
    #[cfg(feature = "dmg-input")]
    #[derive(Clone, Copy)]
    struct DChunk {
        ctype: u32,
        sector: u64,
        sector_count: u64,
        comp_offset: u64,
        comp_len: u64,
    }

    #[cfg(feature = "dmg-input")]
    fn build_mish(chunks: &[DChunk]) -> std::vec::Vec<u8> {
        use shared::{write_be_u32, write_be_u64};
        let mut b = std::vec![0u8; dmg::MISH_HEADER_LEN + chunks.len() * dmg::MISH_ENTRY_LEN];
        write_be_u32(&mut b, 0, dmg::MISH_MAGIC);
        // out_offset @8 and data_offset @0x18 both left 0.
        let mut off = dmg::MISH_HEADER_LEN;
        for c in chunks {
            write_be_u32(&mut b, off, c.ctype);
            write_be_u64(&mut b, off + 8, c.sector);
            write_be_u64(&mut b, off + 0x10, c.sector_count);
            write_be_u64(&mut b, off + 0x18, c.comp_offset);
            write_be_u64(&mut b, off + 0x20, c.comp_len);
            off += dmg::MISH_ENTRY_LEN;
        }
        b
    }

    #[cfg(feature = "dmg-input")]
    fn build_koly(xml_offset: u64, xml_length: u64, sector_count: u64) -> [u8; 512] {
        use shared::write_be_u64;
        let mut b = [0u8; 512];
        b[0..4].copy_from_slice(b"koly");
        // data_fork_offset @0x18 = 0; rsrc @0x28/0x30 = 0.
        write_be_u64(&mut b, 0xd8, xml_offset);
        write_be_u64(&mut b, 0xe0, xml_length);
        write_be_u64(&mut b, 0x1ec, sector_count);
        b
    }

    /// Assemble `[data_fork][<data>base64(mish)</data> plist][koly]`.
    #[cfg(feature = "dmg-input")]
    fn assemble_dmg(data_fork: &[u8], mish: &[u8], koly_sector_count: u64) -> std::vec::Vec<u8> {
        let mut xml = std::string::String::from("<plist><dict><key>blkx</key><array><data>");
        xml.push_str(&dmg_b64(mish));
        xml.push_str("</data></array></dict></plist>");
        let xb = xml.as_bytes();
        let xml_offset = data_fork.len();
        let koly_offset = xml_offset + xb.len();
        let total = koly_offset + 512;
        let mut img = std::vec![0u8; total];
        img[..data_fork.len()].copy_from_slice(data_fork);
        img[xml_offset..xml_offset + xb.len()].copy_from_slice(xb);
        let koly = build_koly(xml_offset as u64, xb.len() as u64, koly_sector_count);
        img[koly_offset..koly_offset + 512].copy_from_slice(&koly);
        img
    }

    /// Init a `DmgState` from `image`, wire a one-device chain, and read one
    /// span through `read_chain_virtual_cluster`. Returns (ok, produced,
    /// bytes_read). The output buffer is pre-poisoned with 0xAA so EIO-parity
    /// tests can assert the arm did NOT zero-fill on failure.
    #[cfg(feature = "dmg-input")]
    fn run_dmg_read(
        image: &[u8],
        sector_size: usize,
        voff: u64,
        chunk: u64,
    ) -> (bool, std::vec::Vec<u8>) {
        let _g = DMG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cap = install_dmg(image, sector_size);
        let ct = dmg_call_table();
        let mut scratch = std::vec![0u8; dmg::DMG_REQUIRED_SCRATCH];
        let mut br = 0u64;
        let state = unsafe {
            dmg::DmgState::init(
                &ct,
                0,
                sector_size,
                cap,
                scratch.as_mut_ptr(),
                scratch.len(),
                &mut br,
            )
        }
        .expect("DmgState::init should succeed for a valid image");
        let mut cs = ChainStates::default();
        cs.dmg_states[0] = Some(state);
        let mut cc = ChainConfig::new();
        cc.magic = ChainConfig::MAGIC;
        cc.version = ChainConfig::VERSION;
        cc.device_count = 1;
        cc.devices[0].format = ImageFormat::Dmg as u32;
        let mut comp = std::vec![0u8; COMPRESSED_BUF_SIZE];
        let mut stg = std::vec![0u8; MAX_CLUSTER_SIZE];
        let mut sco = u64::MAX;
        let mut out = std::vec![0xAAu8; chunk as usize];
        let ok = unsafe {
            read_chain_virtual_cluster(
                &ct,
                0,
                1,
                voff,
                out.as_mut_ptr(),
                chunk,
                sector_size,
                &cc,
                &mut cs,
                comp.as_mut_ptr(),
                stg.as_mut_ptr(),
                &mut sco,
                None,
                None,
                0,
                &mut br,
            )
        };
        // `scratch` must outlive the read (state.table_ptr borrows it).
        let _ = &scratch;
        (ok, out)
    }

    // (a) A single chunk-spanning read walks zero + raw + zlib chunks.
    #[cfg(feature = "dmg-input")]
    #[test]
    fn dmg_arm_mixed_zero_raw_zlib_walk() {
        // Data fork: raw bytes at 0x1000, a zlib blob at 0x2000.
        let raw: std::vec::Vec<u8> = (0..512u32).map(|i| (i * 7 + 3) as u8).collect();
        let plain: std::vec::Vec<u8> = (0..1024u32).map(|i| (i ^ 0x5a) as u8).collect();
        let blob = miniz_oxide::deflate::compress_to_vec_zlib(&plain, 6);
        let mut fork = std::vec![0u8; 0x4000];
        fork[0x1000..0x1000 + raw.len()].copy_from_slice(&raw);
        fork[0x2000..0x2000 + blob.len()].copy_from_slice(&blob);
        // sector0: zero (1 sector); sector1: raw (1); sectors 2-3: zlib (2).
        let mish = build_mish(&[
            DChunk {
                ctype: dmg::CHUNK_ZERO,
                sector: 0,
                sector_count: 1,
                comp_offset: 0,
                comp_len: 0,
            },
            DChunk {
                ctype: dmg::CHUNK_RAW,
                sector: 1,
                sector_count: 1,
                comp_offset: 0x1000,
                comp_len: 512,
            },
            DChunk {
                ctype: dmg::CHUNK_ZLIB,
                sector: 2,
                sector_count: 2,
                comp_offset: 0x2000,
                comp_len: blob.len() as u64,
            },
        ]);
        let img = assemble_dmg(&fork, &mish, 4);
        let (ok, out) = run_dmg_read(&img, 512, 0, 4 * 512);
        assert!(ok, "mixed walk read must succeed");
        assert!(out[..512].iter().all(|&b| b == 0), "sector 0 zero chunk");
        assert_eq!(out[512..1024], raw[..], "sector 1 raw chunk");
        assert_eq!(out[1024..2048], plain[..], "sectors 2-3 zlib chunk");
    }

    // (b) A large zlib chunk is inflated ONCE and cached across two reads.
    #[cfg(feature = "dmg-input")]
    #[test]
    fn dmg_arm_zlib_chunk_cached_across_reads() {
        let plain: std::vec::Vec<u8> = (0..4096u32).map(|i| ((i >> 1) ^ i) as u8).collect();
        let blob = miniz_oxide::deflate::compress_to_vec_zlib(&plain, 6);
        let mut fork = std::vec![0u8; 0x4000];
        fork[0x1000..0x1000 + blob.len()].copy_from_slice(&blob);
        // One 8-sector (4096-byte) zlib chunk.
        let mish = build_mish(&[DChunk {
            ctype: dmg::CHUNK_ZLIB,
            sector: 0,
            sector_count: 8,
            comp_offset: 0x1000,
            comp_len: blob.len() as u64,
        }]);
        let img = assemble_dmg(&fork, &mish, 8);

        let _g = DMG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cap = install_dmg(&img, 512);
        let ct = dmg_call_table();
        let mut scratch = std::vec![0u8; dmg::DMG_REQUIRED_SCRATCH];
        let mut br = 0u64;
        let state = unsafe {
            dmg::DmgState::init(
                &ct,
                0,
                512,
                cap,
                scratch.as_mut_ptr(),
                scratch.len(),
                &mut br,
            )
        }
        .expect("init");
        let mut cs = ChainStates::default();
        cs.dmg_states[0] = Some(state);
        let mut cc = ChainConfig::new();
        cc.magic = ChainConfig::MAGIC;
        cc.version = ChainConfig::VERSION;
        cc.device_count = 1;
        cc.devices[0].format = ImageFormat::Dmg as u32;
        let mut comp = std::vec![0u8; COMPRESSED_BUF_SIZE];
        let mut stg = std::vec![0u8; MAX_CLUSTER_SIZE];
        let mut sco = u64::MAX;

        // First read: sectors 0-1 (bytes 0..1024). Inflates the chunk.
        let mut o1 = std::vec![0u8; 1024];
        let br_before_1 = br;
        let ok1 = unsafe {
            read_chain_virtual_cluster(
                &ct,
                0,
                1,
                0,
                o1.as_mut_ptr(),
                1024,
                512,
                &cc,
                &mut cs,
                comp.as_mut_ptr(),
                stg.as_mut_ptr(),
                &mut sco,
                None,
                None,
                0,
                &mut br,
            )
        };
        let first_read_bytes = br - br_before_1;
        // Second read: sectors 4-5 (bytes 2048..3072) of the SAME chunk. Cache
        // hit => NO further device reads (no re-inflation).
        let mut o2 = std::vec![0u8; 1024];
        let br_before_2 = br;
        let ok2 = unsafe {
            read_chain_virtual_cluster(
                &ct,
                0,
                1,
                2048,
                o2.as_mut_ptr(),
                1024,
                512,
                &cc,
                &mut cs,
                comp.as_mut_ptr(),
                stg.as_mut_ptr(),
                &mut sco,
                None,
                None,
                0,
                &mut br,
            )
        };
        let second_read_bytes = br - br_before_2;
        let _ = &scratch;

        assert!(ok1 && ok2, "both cached reads must succeed");
        assert_eq!(o1[..], plain[0..1024], "first window");
        assert_eq!(o2[..], plain[2048..3072], "second window");
        assert!(
            first_read_bytes > 0,
            "first read must fetch the compressed bytes"
        );
        assert_eq!(
            second_read_bytes, 0,
            "second read within the cached chunk must NOT re-fetch/re-inflate"
        );
    }

    // (c) A raw span whose bytes lie past capacity FAILS (EIO parity) — it
    // must NOT zero-fill (the poisoned 0xAA buffer must survive).
    #[cfg(feature = "dmg-input")]
    #[test]
    fn dmg_arm_raw_truncated_is_eio_not_zerofill() {
        let fork = std::vec![0u8; 0x1000];
        // Raw chunk whose comp_offset points far past the file/capacity.
        let mish = build_mish(&[DChunk {
            ctype: dmg::CHUNK_RAW,
            sector: 0,
            sector_count: 1,
            comp_offset: 8 * 1024 * 1024, // well past cap
            comp_len: 512,
        }]);
        let img = assemble_dmg(&fork, &mish, 1);
        let (ok, out) = run_dmg_read(&img, 512, 0, 512);
        assert!(!ok, "raw span past capacity must return false (EIO parity)");
        assert!(
            out.iter().all(|&b| b == 0xAA),
            "EIO parity: buffer must NOT be zero-filled on a truncated raw read"
        );
    }

    // (d) A gap between chunks FAILS (EIO parity), never zero-fills.
    #[cfg(feature = "dmg-input")]
    #[test]
    fn dmg_arm_interior_gap_is_eio() {
        let fork = std::vec![0u8; 0x2000];
        // Chunks at sector 0 and sector 3 leave sectors 1-2 uncovered.
        let mish = build_mish(&[
            DChunk {
                ctype: dmg::CHUNK_ZERO,
                sector: 0,
                sector_count: 1,
                comp_offset: 0,
                comp_len: 0,
            },
            DChunk {
                ctype: dmg::CHUNK_ZERO,
                sector: 3,
                sector_count: 1,
                comp_offset: 0,
                comp_len: 0,
            },
        ]);
        let img = assemble_dmg(&fork, &mish, 4);
        let (ok, out) = run_dmg_read(&img, 512, 0, 4 * 512);
        assert!(!ok, "a gap between chunks must return false (EIO parity)");
        // The pre-gap sector 0 zero chunk may have been written; the gap
        // sector triggers the failure. The key invariant is `ok == false`.
        let _ = out;
    }

    // (e) The koly-SectorCount tail (virtual size > mish coverage) FAILS.
    #[cfg(feature = "dmg-input")]
    #[test]
    fn dmg_arm_tail_gap_is_eio() {
        let fork = std::vec![0u8; 0x2000];
        // Coverage is sectors 0-1, but the koly claims 4 sectors.
        let mish = build_mish(&[DChunk {
            ctype: dmg::CHUNK_ZERO,
            sector: 0,
            sector_count: 2,
            comp_offset: 0,
            comp_len: 0,
        }]);
        let img = assemble_dmg(&fork, &mish, 4);
        // Read sectors 2-3 (the koly-wins tail beyond coverage).
        let (ok, _out) = run_dmg_read(&img, 512, 2 * 512, 2 * 512);
        assert!(
            !ok,
            "the koly-SectorCount tail must return false (EIO parity)"
        );
    }

    /// Run `init_chain_states` over `formats` and capture the last typed
    /// refusal message. Returns (ok, captured_message).
    #[cfg(feature = "dmg-input")]
    fn run_dmg_init(
        images: &[&[u8]],
        formats: &[ImageFormat],
        dmg_scratch_len: usize,
    ) -> (bool, std::string::String) {
        // For a single-image chain the mock serves device 0; multi-device
        // init tests below reuse one image for every DMG slot.
        let _g = DMG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cap = install_dmg(images[0], 512);
        let ct = dmg_call_table();
        unsafe { DMG_DBG_LEN = 0 };

        let mut cs = ChainStates::default();
        let mut cc = ChainConfig::new();
        cc.magic = ChainConfig::MAGIC;
        cc.version = ChainConfig::VERSION;
        cc.device_count = formats.len() as u32;
        for (i, f) in formats.iter().enumerate() {
            cc.devices[i].format = *f as u32;
        }
        // Caches for any non-DMG device (unused by the DMG arm).
        let mut caches = std::vec![0u8; 2 * MAX_SECTOR_SIZE * MAX_CHAIN_DEVICES];
        // DMG scratch, sized by the caller to exercise the slot cap.
        let mut dmg_scratch = std::vec![0u8; dmg_scratch_len.max(1)];
        let _ = cap;
        let mut br = 0u64;
        let ok = unsafe {
            init_chain_states(
                &ct,
                &cc,
                &mut cs,
                formats.len(),
                512,
                caches.as_mut_ptr() as usize,
                dmg_scratch.as_mut_ptr() as usize,
                dmg_scratch_len,
                &mut br,
            )
        };
        let msg = unsafe {
            let n = DMG_DBG_LEN;
            let src = core::ptr::addr_of!(DMG_DBG_BUF) as *const u8;
            let slice = core::slice::from_raw_parts(src, n);
            std::string::String::from_utf8_lossy(slice).into_owned()
        };
        let _ = (&caches, &dmg_scratch);
        (ok, msg)
    }

    // (f) An empty parsed chunk table refuses at init with the typed message.
    #[cfg(feature = "dmg-input")]
    #[test]
    fn dmg_arm_empty_table_refusal_propagates() {
        // A well-formed <data> block whose mish magic is corrupt => zero
        // parsed chunks => EmptyChunkTable (the qemu-segfault case).
        let mut mish = build_mish(&[DChunk {
            ctype: dmg::CHUNK_ZERO,
            sector: 0,
            sector_count: 1,
            comp_offset: 0,
            comp_len: 0,
        }]);
        mish[0] ^= 0xff; // break the mish magic
        let img = assemble_dmg(&std::vec![0u8; 0x1000], &mish, 1);
        let (ok, msg) = run_dmg_init(&[&img], &[ImageFormat::Dmg], dmg::DMG_REQUIRED_SCRATCH);
        assert!(!ok, "empty chunk table must refuse at init");
        assert_eq!(msg, "dmg: empty chunk table\n");
    }

    // (g) An unsupported codec refuses at init with the code-naming message.
    #[cfg(feature = "dmg-input")]
    #[test]
    fn dmg_arm_codec_refusal_propagates() {
        let mish = build_mish(&[DChunk {
            ctype: dmg::CHUNK_BZIP2, // 0x80000006
            sector: 0,
            sector_count: 1,
            comp_offset: 0x1000,
            comp_len: 16,
        }]);
        let img = assemble_dmg(&std::vec![0u8; 0x2000], &mish, 1);
        let (ok, msg) = run_dmg_init(&[&img], &[ImageFormat::Dmg], dmg::DMG_REQUIRED_SCRATCH);
        assert!(!ok, "unsupported codec must refuse at init");
        assert_eq!(msg, "dmg: unsupported chunk codec 0x80000006\n");
    }

    // (h) Two DMG devices both init when the reserved region holds two slots
    // (the compare dmg-vs-dmg case); a single-slot region refuses the second
    // with the typed over-cap message.
    #[cfg(feature = "dmg-input")]
    #[test]
    fn dmg_arm_multi_device_slots_and_overcap() {
        let mish = build_mish(&[DChunk {
            ctype: dmg::CHUNK_ZERO,
            sector: 0,
            sector_count: 1,
            comp_offset: 0,
            comp_len: 0,
        }]);
        let img = assemble_dmg(&std::vec![0u8; 0x1000], &mish, 1);

        // Two slots reserved => both DMG devices init successfully.
        let two_slots = dmg::DMG_TABLE_REGION + dmg::DMG_REQUIRED_SCRATCH;
        let (ok2, _m2) = run_dmg_init(&[&img], &[ImageFormat::Dmg, ImageFormat::Dmg], two_slots);
        assert!(ok2, "two DMG devices must init with a two-slot region");

        // One slot reserved => the second DMG device refuses, typed.
        let (ok1, m1) = run_dmg_init(
            &[&img],
            &[ImageFormat::Dmg, ImageFormat::Dmg],
            dmg::DMG_REQUIRED_SCRATCH,
        );
        assert!(
            !ok1,
            "a second DMG must refuse when only one slot is reserved"
        );
        assert_eq!(m1, "dmg: too many dmg devices for scratch\n");
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

/// Read exactly `[virtual_offset, virtual_offset + chunk_size)` bytes from a
/// device into `buf`, byte-accurately.
///
/// `virtual_offset` and `chunk_size` need not be multiples of `sector_size`.
/// The device is read in whole `sector_size` units (the only granularity the
/// call table exposes); when the requested range starts partway into a sector
/// or ends partway into one, the covering boundary sectors are read into a
/// stack scratch and only the requested bytes are copied out, so callers may
/// pass an arbitrary sub-sector window (as `dd skip=`/`count=` does). Any part
/// of the range at or beyond the device capacity is zero-filled.
///
/// Aligned reads (sector-aligned `virtual_offset`, `chunk_size` a multiple of
/// `sector_size`) take the original whole-sector-into-`buf` fast path and are
/// byte-identical to before, so whole-image convert is unaffected.
///
/// # Safety
///
/// `buf` must point to at least `max(chunk_size, sector_size)` writable bytes.
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
    let ssz = sector_size as u64;
    let offset_in_sector = (virtual_offset % ssz) as usize;

    // Fast path: the requested range is sector-aligned at both ends, so every
    // sector can be read straight into `buf`. This is the whole-image convert
    // path and must stay byte-identical to the original implementation.
    if offset_in_sector == 0 && chunk_size.is_multiple_of(ssz) {
        let first_sector = virtual_offset / ssz;
        // Ensure at least one sector is read when chunk_size < sector_size.
        // The caller's buffer is always >= MAX_SECTOR_SIZE.
        let read_size = if chunk_size < ssz { ssz } else { chunk_size };
        let sectors_per_chunk = read_size / ssz;

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
            if !(call_table.read_input_sector)(device_idx, sector, buf.add(buf_offset), sector_size)
            {
                return false;
            }
            *bytes_read += ssz;
        }
        return true;
    }

    // Byte-accurate path for a sub-sector window. Walk the covering sectors,
    // reading boundary (partial) sectors through a scratch and copying only
    // the requested bytes, and full interior sectors straight into `buf`.
    let mut sector = virtual_offset / ssz;
    let mut produced: u64 = 0; // bytes written into buf so far
    let mut sector_off = offset_in_sector as u64; // offset into the current sector
    let mut scratch = [0u8; MAX_SECTOR_SIZE];

    while produced < chunk_size {
        // Number of bytes this sector contributes to the output range.
        let avail = ssz - sector_off;
        let want = core::cmp::min(avail, chunk_size - produced);

        if sector >= input_capacity {
            // Past the end of the device: zero-fill the rest of the range.
            core::ptr::write_bytes(
                buf.add(produced as usize),
                0,
                (chunk_size - produced) as usize,
            );
            break;
        }

        if sector_off == 0 && want == ssz {
            // Whole sector lands entirely in the output; read straight in.
            if !(call_table.read_input_sector)(
                device_idx,
                sector,
                buf.add(produced as usize),
                sector_size,
            ) {
                return false;
            }
        } else {
            // Partial sector: read into scratch, copy the wanted byte run.
            if !(call_table.read_input_sector)(
                device_idx,
                sector,
                scratch.as_mut_ptr(),
                sector_size,
            ) {
                return false;
            }
            core::ptr::copy_nonoverlapping(
                scratch.as_ptr().add(sector_off as usize),
                buf.add(produced as usize),
                want as usize,
            );
        }

        *bytes_read += ssz;
        produced += want;
        sector += 1;
        sector_off = 0;
    }
    true
}

/// Decrypt a buffer of QCOW2 data encrypted with legacy AES-128-CBC
/// (crypt_method=1).
///
/// Each 512-byte sector is encrypted independently with AES-128-CBC.
/// The IV for each sector is the virtual sector number (virtual byte
/// offset / 512) as a little-endian u64, zero-padded to 16 bytes.
///
/// # Safety
///
/// `buf` must point to at least `len` writable bytes. `len` must be
/// a multiple of 512. `virtual_offset` is the guest-visible byte offset
/// of the start of the data (used to compute sector-based IVs).
#[cfg(feature = "aes-decrypt")]
pub unsafe fn decrypt_cluster_aes_cbc(
    buf: *mut u8,
    len: u64,
    virtual_offset: u64,
    aes_key: &[u8; 16],
) {
    use aes::cipher::{Array, BlockCipherDecrypt, KeyInit};
    use aes::Aes128;

    let cipher = Aes128::new(aes_key.into());
    let sector_size: u64 = 512;
    let block_size: usize = 16;
    let num_sectors = len / sector_size;

    for i in 0..num_sectors {
        let sector_offset = (i * sector_size) as usize;

        // IV: virtual sector number as LE u64, zero-padded to 16 bytes
        let virt_sector = (virtual_offset + i * sector_size) / sector_size;
        let mut prev = [0u8; 16];
        prev[..8].copy_from_slice(&virt_sector.to_le_bytes());

        // CBC decryption: for each 16-byte block, decrypt then XOR with
        // the previous ciphertext block (or IV for the first block).
        let blocks_per_sector = sector_size as usize / block_size;
        for j in 0..blocks_per_sector {
            let block_off = sector_offset + j * block_size;
            let block_ptr = buf.add(block_off);

            // Save ciphertext before decryption (needed for next block's XOR)
            let mut ct = [0u8; 16];
            core::ptr::copy_nonoverlapping(block_ptr, ct.as_mut_ptr(), 16);

            // Decrypt the block in-place
            let block = &mut *(block_ptr as *mut Array<u8, aes::cipher::consts::U16>);
            cipher.decrypt_block(block);

            // XOR with previous ciphertext (or IV)
            for k in 0..16 {
                *block_ptr.add(k) ^= prev[k];
            }
            prev = ct;
        }
    }
}

/// Decrypt a buffer of QCOW2 data encrypted with LUKS AES-XTS
/// (crypt_method=2).
///
/// Each sector (default 512 bytes) is encrypted independently with AES-XTS.
/// The tweak for each sector is its virtual sector number (PLAIN64 IV mode):
/// sector_num = virtual_byte_offset / luks_sector_size.
///
/// # Safety
///
/// `buf` must point to at least `len` writable bytes. `len` must be
/// a multiple of `luks_sector_size`. `virtual_offset` is the guest-visible
/// byte offset of the start of the data.
/// `luks_key` must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS).
#[cfg(feature = "luks-decrypt")]
pub unsafe fn decrypt_cluster_aes_xts(
    buf: *mut u8,
    len: u64,
    virtual_offset: u64,
    luks_key: &[u8],
    luks_sector_size: u64,
) {
    use aes::cipher::{Array, KeyInit};
    use aes::{Aes128, Aes256};

    let data = core::slice::from_raw_parts_mut(buf, len as usize);
    let first_sector = virtual_offset / luks_sector_size;
    let half = luks_key.len() / 2;

    if half == 16 {
        let c1 = Aes128::new(<&Array<u8, _>>::try_from(&luks_key[..16]).unwrap());
        let c2 = Aes128::new(<&Array<u8, _>>::try_from(&luks_key[16..32]).unwrap());
        let xts = xts_mode::Xts128::<Aes128>::new(c1, c2);
        xts.decrypt_area(
            data,
            luks_sector_size as usize,
            first_sector as u128,
            xts_mode::get_tweak_default,
        );
    } else if half == 32 {
        let c1 = Aes256::new(<&Array<u8, _>>::try_from(&luks_key[..32]).unwrap());
        let c2 = Aes256::new(<&Array<u8, _>>::try_from(&luks_key[32..64]).unwrap());
        let xts = xts_mode::Xts128::<Aes256>::new(c1, c2);
        xts.decrypt_area(
            data,
            luks_sector_size as usize,
            first_sector as u128,
            xts_mode::get_tweak_default,
        );
    }
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
/// `staging_buf` must point to at least `MAX_CLUSTER_SIZE` writable bytes
/// (used for decompressing clusters larger than `chunk_size`).
/// `staging_cluster_offset` tracks which cluster is cached in `staging_buf`
/// (set to `u64::MAX` to invalidate).
/// `aes_key` is `Some(&key)` to decrypt AES-128-CBC encrypted clusters
/// (crypt_method=1), or `None` for unencrypted images.
/// `luks_key` is `Some(key_bytes)` to decrypt LUKS AES-XTS encrypted
/// clusters (crypt_method=2). Key length determines cipher:
/// 32 bytes = AES-128-XTS, 64 bytes = AES-256-XTS.
/// `luks_sector_size` is the LUKS sector size for XTS (typically 512).
/// `call_table` must be valid.
#[allow(unused_variables)]
#[allow(clippy::only_used_in_recursion)]
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
    staging_buf: *mut u8,
    staging_cluster_offset: &mut u64,
    aes_key: Option<&[u8; 16]>,
    luks_key: Option<&[u8]>,
    luks_sector_size: u64,
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
                let crypt_method = state.crypt_method;

                match state.cluster_lookup(call_table, virtual_offset, sector_size, cap, bytes_read)
                {
                    Some(ClusterLookup::Unallocated) => {
                        continue;
                    }
                    Some(ClusterLookup::Zero) => {
                        // Classic qcow2 v3 all-zeroes cluster (L2 bit 0):
                        // reads as zeros regardless of host offset. Zero-fill
                        // this chunk and stop — do NOT fall through to a
                        // backing layer, and do NOT read the host offset.
                        core::ptr::write_bytes(buf, 0, chunk_size as usize);
                        return true;
                    }
                    Some(ClusterLookup::StandardSubclusters(host_offset, bitmap)) => {
                        let alloc_bits = bitmap as u32;
                        let zero_bits = (bitmap >> 32) as u32;

                        let intra_offset = virtual_offset % qcow2_cluster_size;
                        let read_size = if chunk_size < qcow2_cluster_size {
                            chunk_size
                        } else {
                            qcow2_cluster_size
                        };

                        // Per-subcluster handling for mixed allocation
                        let sc_size = qcow2_cluster_size / 32;
                        let sc_start = intra_offset / sc_size;
                        let sc_count = read_size / sc_size;
                        let read_dev = chain_config.devices[dev_idx].data_device_idx;
                        let read_dev = if read_dev != 0 {
                            read_dev
                        } else {
                            dev_idx as u32
                        };

                        // When sector_size <= subcluster_size, we can
                        // read only the allocated subcluster runs and
                        // skip I/O for zero/unallocated ranges. When
                        // sector_size > subcluster_size, we must read
                        // the full chunk first (a per-subcluster read
                        // would read an entire sector for each 2 KB
                        // subcluster, wasting I/O or overrunning the
                        // buffer).
                        if sector_size as u64 <= sc_size {
                            // ---- NARROW I/O PATH ----
                            // Read only allocated runs; zero-fill and
                            // backing-chain-recurse the rest.
                            let mut i = 0u64;
                            while i < sc_count {
                                let sc_idx = (sc_start + i) as u32;
                                let is_zero = (zero_bits >> sc_idx) & 1 != 0;
                                let is_alloc = (alloc_bits >> sc_idx) & 1 != 0;

                                if is_zero || (!is_alloc && host_offset == 0) {
                                    // ZERO RUN: coalesce contiguous zero subclusters
                                    let run_start = i;
                                    let mut run_len = 1u64;
                                    while i + run_len < sc_count {
                                        let next = (sc_start + i + run_len) as u32;
                                        let nz = (zero_bits >> next) & 1 != 0;
                                        let na = (alloc_bits >> next) & 1 != 0;
                                        if nz || (!na && host_offset == 0) {
                                            run_len += 1;
                                        } else {
                                            break;
                                        }
                                    }
                                    core::ptr::write_bytes(
                                        buf.add((run_start * sc_size) as usize),
                                        0,
                                        (run_len * sc_size) as usize,
                                    );
                                    i += run_len;
                                } else if is_alloc {
                                    // ALLOC RUN: coalesce contiguous allocated subclusters
                                    let run_start = i;
                                    let mut run_len = 1u64;
                                    while i + run_len < sc_count {
                                        let next = (sc_start + i + run_len) as u32;
                                        let nz = (zero_bits >> next) & 1 != 0;
                                        let na = (alloc_bits >> next) & 1 != 0;
                                        if na && !nz {
                                            run_len += 1;
                                        } else {
                                            break;
                                        }
                                    }

                                    let run_buf_off = (run_start * sc_size) as usize;
                                    let run_host = host_offset + (sc_start + run_start) * sc_size;
                                    let run_bytes = run_len * sc_size;

                                    if host_offset != 0 {
                                        if !read_cluster_sectors(
                                            call_table,
                                            read_dev,
                                            run_host,
                                            buf.add(run_buf_off),
                                            run_bytes,
                                            sector_size,
                                            bytes_read,
                                        ) {
                                            return false;
                                        }
                                        #[cfg(feature = "aes-decrypt")]
                                        if crypt_method == 1 {
                                            if let Some(key) = aes_key {
                                                let virt = virtual_offset + run_start * sc_size;
                                                decrypt_cluster_aes_cbc(
                                                    buf.add(run_buf_off),
                                                    run_bytes,
                                                    virt,
                                                    key,
                                                );
                                            }
                                        }
                                        #[cfg(feature = "luks-decrypt")]
                                        if crypt_method == 2 {
                                            if let Some(key) = luks_key {
                                                decrypt_cluster_aes_xts(
                                                    buf.add(run_buf_off),
                                                    run_bytes,
                                                    run_host,
                                                    key,
                                                    luks_sector_size,
                                                );
                                            }
                                        }
                                    } else {
                                        // host_offset == 0 but alloc set:
                                        // malformed (I2), zero-fill defensively
                                        core::ptr::write_bytes(
                                            buf.add(run_buf_off),
                                            0,
                                            run_bytes as usize,
                                        );
                                    }
                                    i += run_len;
                                } else {
                                    // UNALLOC: recurse into backing chain
                                    let buf_off = (i * sc_size) as usize;
                                    let remaining = chain_len - dev_offset - 1;
                                    if remaining > 0 {
                                        if !read_chain_virtual_cluster(
                                            call_table,
                                            chain_start + dev_offset + 1,
                                            remaining,
                                            virtual_offset + i * sc_size,
                                            buf.add(buf_off),
                                            sc_size,
                                            sector_size,
                                            chain_config,
                                            chain_states,
                                            compressed_buf,
                                            staging_buf,
                                            staging_cluster_offset,
                                            aes_key,
                                            luks_key,
                                            luks_sector_size,
                                            bytes_read,
                                        ) {
                                            return false;
                                        }
                                    } else {
                                        // Bottom of chain: zero
                                        core::ptr::write_bytes(
                                            buf.add(buf_off),
                                            0,
                                            sc_size as usize,
                                        );
                                    }
                                    i += 1;
                                }
                            }
                        } else {
                            // ---- WIDE I/O PATH ----
                            // Sector is larger than a subcluster; read the
                            // full chunk, decrypt, then selectively overwrite.
                            if host_offset != 0 {
                                let read_offset = host_offset + intra_offset;
                                if !read_cluster_sectors(
                                    call_table,
                                    read_dev,
                                    read_offset,
                                    buf,
                                    read_size,
                                    sector_size,
                                    bytes_read,
                                ) {
                                    return false;
                                }
                                #[cfg(feature = "aes-decrypt")]
                                if crypt_method == 1 {
                                    if let Some(key) = aes_key {
                                        decrypt_cluster_aes_cbc(
                                            buf,
                                            read_size,
                                            virtual_offset,
                                            key,
                                        );
                                    }
                                }
                                #[cfg(feature = "luks-decrypt")]
                                if crypt_method == 2 {
                                    if let Some(key) = luks_key {
                                        decrypt_cluster_aes_xts(
                                            buf,
                                            read_size,
                                            host_offset + intra_offset,
                                            key,
                                            luks_sector_size,
                                        );
                                    }
                                }
                            }

                            // Selectively fill non-allocated subclusters:
                            // zero subclusters get zeroed, unallocated
                            // subclusters come from backing chain or zero
                            // at bottom of chain.
                            for i in 0..sc_count {
                                let sc_idx = (sc_start + i) as u32;
                                let is_zero = (zero_bits >> sc_idx) & 1 != 0;
                                let is_alloc = (alloc_bits >> sc_idx) & 1 != 0;
                                let buf_off = (i * sc_size) as usize;

                                if is_zero || (!is_alloc && host_offset == 0) {
                                    core::ptr::write_bytes(buf.add(buf_off), 0, sc_size as usize);
                                } else if !is_alloc {
                                    let remaining = chain_len - dev_offset - 1;
                                    if remaining > 0 {
                                        if !read_chain_virtual_cluster(
                                            call_table,
                                            chain_start + dev_offset + 1,
                                            remaining,
                                            virtual_offset + i * sc_size,
                                            buf.add(buf_off),
                                            sc_size,
                                            sector_size,
                                            chain_config,
                                            chain_states,
                                            compressed_buf,
                                            staging_buf,
                                            staging_cluster_offset,
                                            aes_key,
                                            luks_key,
                                            luks_sector_size,
                                            bytes_read,
                                        ) {
                                            return false;
                                        }
                                    } else {
                                        core::ptr::write_bytes(
                                            buf.add(buf_off),
                                            0,
                                            sc_size as usize,
                                        );
                                    }
                                }
                                // Allocated subclusters: already read above
                            }
                        }
                        return true;
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
                        // If this device has an external data file, read
                        // standard clusters from the data device instead.
                        // Compressed clusters stay on the metadata device.
                        let read_dev = chain_config.devices[dev_idx].data_device_idx;
                        let read_dev = if read_dev != 0 {
                            read_dev
                        } else {
                            dev_idx as u32
                        };
                        if !read_cluster_sectors(
                            call_table,
                            read_dev,
                            read_offset,
                            buf,
                            read_size,
                            sector_size,
                            bytes_read,
                        ) {
                            return false;
                        }
                        // Decrypt AES-128-CBC encrypted clusters
                        #[cfg(feature = "aes-decrypt")]
                        if crypt_method == 1 {
                            if let Some(key) = aes_key {
                                decrypt_cluster_aes_cbc(buf, read_size, virtual_offset, key);
                            }
                        }
                        // Decrypt LUKS AES-XTS encrypted clusters.
                        // IV is based on the physical byte offset within
                        // the QCOW2 file (host offset), not the virtual
                        // guest offset. Each sector's IV = physical_byte_offset / sector_size.
                        #[cfg(feature = "luks-decrypt")]
                        if crypt_method == 2 {
                            if let Some(key) = luks_key {
                                decrypt_cluster_aes_xts(
                                    buf,
                                    read_size,
                                    read_offset,
                                    key,
                                    luks_sector_size,
                                );
                            }
                        }
                        return true;
                    }
                    #[cfg(feature = "decompress")]
                    Some(ClusterLookup::Compressed(l2_entry)) => {
                        // For clusters that fit in the output buffer,
                        // decompress directly (fast path).
                        if qcow2_cluster_size <= chunk_size {
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

                        // Large cluster: decompress into staging buffer,
                        // then copy the requested chunk.
                        if qcow2_cluster_size > MAX_CLUSTER_SIZE as u64 {
                            return false;
                        }
                        let cluster_base = virtual_offset & !(qcow2_cluster_size - 1);
                        if *staging_cluster_offset != cluster_base {
                            // Decompress full cluster into staging buffer
                            #[cfg(feature = "decompress-zstd")]
                            if compression_type == 1 {
                                if !read_compressed_cluster_zstd(
                                    call_table,
                                    dev_idx as u32,
                                    l2_entry,
                                    cluster_bits,
                                    staging_buf,
                                    qcow2_cluster_size,
                                    sector_size,
                                    compressed_buf,
                                    cap,
                                    bytes_read,
                                ) {
                                    return false;
                                }
                                *staging_cluster_offset = cluster_base;
                                let intra = (virtual_offset - cluster_base) as usize;
                                core::ptr::copy_nonoverlapping(
                                    staging_buf.add(intra),
                                    buf,
                                    chunk_size as usize,
                                );
                                return true;
                            }
                            if compression_type != 0 {
                                return false;
                            }
                            if !read_compressed_cluster(
                                call_table,
                                dev_idx as u32,
                                l2_entry,
                                cluster_bits,
                                staging_buf,
                                qcow2_cluster_size,
                                sector_size,
                                compressed_buf,
                                cap,
                                bytes_read,
                            ) {
                                return false;
                            }
                            *staging_cluster_offset = cluster_base;
                        }
                        let intra = (virtual_offset - cluster_base) as usize;
                        core::ptr::copy_nonoverlapping(
                            staging_buf.add(intra),
                            buf,
                            chunk_size as usize,
                        );
                        return true;
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
                        // For grains that fit in the output buffer,
                        // decompress directly (fast path).
                        if grain_size_bytes <= chunk_size {
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

                        // Large grain: decompress into staging buffer,
                        // then copy the requested chunk.
                        if grain_size_bytes > MAX_CLUSTER_SIZE as u64 {
                            return false;
                        }
                        let grain_base = virtual_offset & !(grain_size_bytes - 1);
                        if *staging_cluster_offset != grain_base {
                            if !vmdk::read_compressed_grain(
                                call_table,
                                dev_idx as u32,
                                marker_offset,
                                grain_size_bytes,
                                staging_buf,
                                sector_size,
                                compressed_buf,
                                COMPRESSED_BUF_SIZE,
                                cap,
                                bytes_read,
                            ) {
                                return false;
                            }
                            *staging_cluster_offset = grain_base;
                        }
                        let intra = (virtual_offset - grain_base) as usize;
                        core::ptr::copy_nonoverlapping(
                            staging_buf.add(intra),
                            buf,
                            chunk_size as usize,
                        );
                        return true;
                    }
                    #[cfg(not(feature = "vmdk-decompress"))]
                    Some(GrainLookup::Compressed(_)) => {
                        return false;
                    }
                    None => return false,
                }
            }
            #[cfg(feature = "vhd-input")]
            ImageFormat::Vhd => {
                let state = match &mut chain_states.vhd_states[dev_idx] {
                    Some(s) => s,
                    None => return false,
                };

                if state.is_fixed() {
                    // Fixed VHD: raw data from offset 0, read directly
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

                match state.block_lookup(call_table, virtual_offset, sector_size, cap, bytes_read) {
                    Some(BlockLookup::Unallocated) => {
                        continue;
                    }
                    Some(BlockLookup::Allocated { host_byte_offset }) => {
                        // host_byte_offset already includes the
                        // intra-block offset from block_lookup().
                        // VHD data may start mid-sector when the
                        // device sector size is larger than 512
                        // bytes (the bitmap + data layout uses
                        // 512-byte sector addressing).
                        let intra_sector = (host_byte_offset % sector_size as u64) as usize;
                        if intra_sector == 0 {
                            return read_cluster_sectors(
                                call_table,
                                dev_idx as u32,
                                host_byte_offset,
                                buf,
                                chunk_size,
                                sector_size,
                                bytes_read,
                            );
                        }
                        // Sub-sector offset: read each sector and
                        // copy the relevant portion into buf.
                        return read_offset_sectors(
                            call_table,
                            dev_idx as u32,
                            host_byte_offset,
                            buf,
                            chunk_size,
                            sector_size,
                            compressed_buf,
                            bytes_read,
                        );
                    }
                    None => return false,
                }
            }
            #[cfg(feature = "vhdx-input")]
            ImageFormat::Vhdx => {
                let state = match &mut chain_states.vhdx_states[dev_idx] {
                    Some(s) => s,
                    None => return false,
                };
                match state.block_lookup(call_table, virtual_offset, sector_size, cap, bytes_read) {
                    Some(VhdxBlockLookup::NotPresent) | Some(VhdxBlockLookup::Zero) => {
                        continue;
                    }
                    Some(VhdxBlockLookup::Present { host_byte_offset }) => {
                        return read_cluster_sectors(
                            call_table,
                            dev_idx as u32,
                            host_byte_offset,
                            buf,
                            chunk_size,
                            sector_size,
                            bytes_read,
                        );
                    }
                    None => return false,
                }
            }
            #[cfg(feature = "vdi-input")]
            ImageFormat::Vdi => {
                let state = match &mut chain_states.vdi_states[dev_idx] {
                    Some(s) => s,
                    None => return false,
                };

                match state.block_lookup(call_table, virtual_offset, sector_size, cap, bytes_read) {
                    Some(vdi::VdiBlockLookup::Unallocated) => {
                        // A VDI can never have a lower device (non-null
                        // link/parent UUIDs are refused at parse), so fall
                        // through to the chain loop's zero-fill tail.
                        continue;
                    }
                    Some(vdi::VdiBlockLookup::Allocated { host_byte_offset }) => {
                        // qemu never validates VDI file length: any portion
                        // of an allocated read at or past the device
                        // capacity zero-fills rather than erroring, including
                        // the straddle case (block starts in-file, data
                        // truncated mid-read). `cap` is in sectors.
                        let cap_bytes = cap.saturating_mul(sector_size as u64);
                        if host_byte_offset >= cap_bytes {
                            core::ptr::write_bytes(buf, 0, chunk_size as usize);
                            return true;
                        }
                        let avail = cap_bytes - host_byte_offset;
                        let read_len = if chunk_size < avail {
                            chunk_size
                        } else {
                            avail
                        };
                        // Zero the past-capacity tail first so a straddling
                        // read leaves only the in-file prefix populated.
                        if read_len < chunk_size {
                            core::ptr::write_bytes(
                                buf.add(read_len as usize),
                                0,
                                (chunk_size - read_len) as usize,
                            );
                        }
                        // offset_data is typically 1024 — NOT sector-aligned
                        // to the guest's virtio sector — so the unaligned
                        // path is the common case.
                        let intra_sector = (host_byte_offset % sector_size as u64) as usize;
                        if intra_sector == 0 {
                            return read_cluster_sectors(
                                call_table,
                                dev_idx as u32,
                                host_byte_offset,
                                buf,
                                read_len,
                                sector_size,
                                bytes_read,
                            );
                        }
                        return read_offset_sectors(
                            call_table,
                            dev_idx as u32,
                            host_byte_offset,
                            buf,
                            read_len,
                            sector_size,
                            compressed_buf,
                            bytes_read,
                        );
                    }
                    None => return false,
                }
            }
            #[cfg(feature = "parallels-input")]
            ImageFormat::Parallels => {
                let state = match &mut chain_states.parallels_states[dev_idx] {
                    Some(s) => s,
                    None => return false,
                };

                // Unlike the VDI/VHD arms, this chunk is NOT guaranteed to lie
                // within a single device cluster. `convert`/`dd` clamp each
                // chunk to the top device's own cluster boundary, but `compare`
                // uses the LARGER of the two chains' cluster sizes (capped at
                // MAX_SECTOR_SIZE) and `bench`/`rebase` use their qcow2 cluster
                // size — so a small (e.g. 4 KiB) parallels cluster can be
                // spanned by a chunk up to 65536 bytes. Adjacent parallels
                // clusters are non-contiguous on the host, so we walk the chunk
                // one parallels cluster at a time and resolve each sub-span
                // through its own BAT lookup. This also stays correct if
                // ChainDeviceInfo.cluster_size is 0 (as it is before the info
                // op is taught to report it), since the boundary comes from the
                // header-derived `state.cluster_size`, never from the chunk.
                //
                // A parallels image can never have a lower device in the chain
                // (instar builds 1-device chains for parallels), so an
                // unallocated cluster reads as zeros directly here rather than
                // `continue`-ing to a lower layer; a fully-unallocated chunk is
                // byte-identical to what the chain's zero-fill tail would emit.
                let cluster_size = state.cluster_size;
                let cap_bytes = cap.saturating_mul(sector_size as u64);
                let mut done = 0u64;
                while done < chunk_size {
                    let cur_virtual = virtual_offset + done;
                    let offset_in_cluster = cur_virtual % cluster_size;
                    let to_cluster_end = cluster_size - offset_in_cluster;
                    let remaining = chunk_size - done;
                    let span = if remaining < to_cluster_end {
                        remaining
                    } else {
                        to_cluster_end
                    };
                    let dst = buf.add(done as usize);

                    match state.block_lookup(call_table, cur_virtual, sector_size, cap, bytes_read)
                    {
                        Some(parallels::ParallelsBlockLookup::Unallocated) => {
                            // BAT value 0 or beyond BAT coverage: zeros.
                            core::ptr::write_bytes(dst, 0, span as usize);
                        }
                        Some(parallels::ParallelsBlockLookup::Allocated { host_byte_offset }) => {
                            // qemu never validates parallels file length: any
                            // portion of an allocated read at or past the device
                            // capacity zero-fills rather than erroring,
                            // including the straddle case (cluster starts
                            // in-file, data truncated mid-read). `cap` is in
                            // sectors.
                            if host_byte_offset >= cap_bytes {
                                core::ptr::write_bytes(dst, 0, span as usize);
                            } else {
                                let avail = cap_bytes - host_byte_offset;
                                let read_len = if span < avail { span } else { avail };
                                // Zero the past-capacity tail first so a
                                // straddling read leaves only the in-file
                                // prefix populated.
                                if read_len < span {
                                    core::ptr::write_bytes(
                                        dst.add(read_len as usize),
                                        0,
                                        (span - read_len) as usize,
                                    );
                                }
                                // Parallels data offsets are 512-aligned (BAT
                                // values scale by 512) but not necessarily
                                // aligned to the guest's virtio sector, so the
                                // unaligned path is reachable just as for VDI.
                                let intra_sector = (host_byte_offset % sector_size as u64) as usize;
                                let ok = if intra_sector == 0 {
                                    read_cluster_sectors(
                                        call_table,
                                        dev_idx as u32,
                                        host_byte_offset,
                                        dst,
                                        read_len,
                                        sector_size,
                                        bytes_read,
                                    )
                                } else {
                                    read_offset_sectors(
                                        call_table,
                                        dev_idx as u32,
                                        host_byte_offset,
                                        dst,
                                        read_len,
                                        sector_size,
                                        compressed_buf,
                                        bytes_read,
                                    )
                                };
                                if !ok {
                                    return false;
                                }
                            }
                        }
                        None => return false,
                    }

                    done += span;
                }
                return true;
            }
            #[cfg(feature = "qcow1-input")]
            ImageFormat::Qcow1 => {
                // QCOW1 combines three precedents:
                //   * a PER-CLUSTER WALK (like the Parallels arm): qcow1
                //     clusters go down to 512 bytes, far smaller than a chunk,
                //     and adjacent clusters are non-contiguous on the host, so
                //     the chunk is resolved one header-derived cluster at a
                //     time (never from ChainDeviceInfo.cluster_size).
                //   * BACKING FALL-THROUGH (like the Qcow2 arm): an
                //     unallocated qcow1 cluster must descend to the next chain
                //     device, NOT zero-fill. The Qcow2 arm signals a
                //     whole-chunk hole with `continue` (retry the same span on
                //     the next device) and a sub-span hole (mixed
                //     subclusters) by RECURSING into
                //     `read_chain_virtual_cluster` at `chain_start +
                //     dev_offset + 1` for just that sub-span, zero-filling only
                //     at the bottom of the chain. Because this walk resolves
                //     one cluster at a time inside a single chunk — where
                //     allocated and unallocated clusters can be interleaved —
                //     we mirror the Qcow2 sub-span mechanism: each unallocated
                //     cluster recurses into the remaining lower chain for its
                //     own span while allocated/compressed clusters are served
                //     from this device. A `continue` would wrongly re-resolve
                //     the whole chunk (including already-filled allocated
                //     clusters) on the next device, so it is not used here.
                //   * CAPACITY-CLAMPED ZERO-FILL (like the Vdi/Parallels arms)
                //     for allocated-but-past-EOF and straddling reads (qemu
                //     never validates qcow1 file length and zero-fills every
                //     truncation shape on every version).
                let cluster_size = match &chain_states.qcow1_states[dev_idx] {
                    Some(s) => s.cluster_size,
                    None => return false,
                };
                let cap_bytes = cap.saturating_mul(sector_size as u64);
                let mut done = 0u64;
                while done < chunk_size {
                    let cur_virtual = virtual_offset + done;
                    let offset_in_cluster = cur_virtual % cluster_size;
                    let to_cluster_end = cluster_size - offset_in_cluster;
                    let remaining = chunk_size - done;
                    let span = if remaining < to_cluster_end {
                        remaining
                    } else {
                        to_cluster_end
                    };
                    let dst = buf.add(done as usize);

                    // Look up this cluster with a short-lived borrow so the
                    // Unallocated arm below can re-borrow `chain_states` for
                    // the backing recursion (block_lookup returns a Copy enum,
                    // ending the borrow before the match body runs).
                    let lookup = match &mut chain_states.qcow1_states[dev_idx] {
                        Some(s) => {
                            s.block_lookup(call_table, cur_virtual, sector_size, cap, bytes_read)
                        }
                        None => return false,
                    };

                    match lookup {
                        Some(qcow1::Qcow1BlockLookup::Unallocated) => {
                            // Defer this sub-span to the next device in the
                            // chain; zeros only if this is the bottom device.
                            let lower = chain_len - dev_offset - 1;
                            if lower > 0 {
                                if !read_chain_virtual_cluster(
                                    call_table,
                                    chain_start + dev_offset + 1,
                                    lower,
                                    cur_virtual,
                                    dst,
                                    span,
                                    sector_size,
                                    chain_config,
                                    chain_states,
                                    compressed_buf,
                                    staging_buf,
                                    staging_cluster_offset,
                                    aes_key,
                                    luks_key,
                                    luks_sector_size,
                                    bytes_read,
                                ) {
                                    return false;
                                }
                            } else {
                                core::ptr::write_bytes(dst, 0, span as usize);
                            }
                        }
                        Some(qcow1::Qcow1BlockLookup::Allocated(host_byte_offset)) => {
                            // Uncompressed L2 entries are absolute host byte
                            // offsets. qemu never validates file length: a read
                            // at or past capacity zero-fills, and a straddling
                            // read returns the in-file prefix then zero-fills
                            // the truncated tail. `cap` is in sectors.
                            if host_byte_offset >= cap_bytes {
                                core::ptr::write_bytes(dst, 0, span as usize);
                            } else {
                                let avail = cap_bytes - host_byte_offset;
                                let read_len = if span < avail { span } else { avail };
                                if read_len < span {
                                    core::ptr::write_bytes(
                                        dst.add(read_len as usize),
                                        0,
                                        (span - read_len) as usize,
                                    );
                                }
                                // qcow1 cluster offsets are not necessarily
                                // aligned to the guest's virtio sector, so the
                                // unaligned path is reachable just as for VDI.
                                let intra_sector = (host_byte_offset % sector_size as u64) as usize;
                                let ok = if intra_sector == 0 {
                                    read_cluster_sectors(
                                        call_table,
                                        dev_idx as u32,
                                        host_byte_offset,
                                        dst,
                                        read_len,
                                        sector_size,
                                        bytes_read,
                                    )
                                } else {
                                    read_offset_sectors(
                                        call_table,
                                        dev_idx as u32,
                                        host_byte_offset,
                                        dst,
                                        read_len,
                                        sector_size,
                                        compressed_buf,
                                        bytes_read,
                                    )
                                };
                                if !ok {
                                    return false;
                                }
                            }
                        }
                        Some(qcow1::Qcow1BlockLookup::Compressed { host_offset, csize }) => {
                            // Read `csize` bytes of raw-DEFLATE data from the
                            // possibly-unaligned host offset into compressed_buf
                            // (COMPRESSED_BUF_SIZE >> qcow1's 64 KiB max
                            // cluster), zero-filling any tail past capacity like
                            // qemu (it reads what's there and inflates the rest
                            // from zeroes). read_cluster_sectors' byte-accurate
                            // path handles the unaligned start.
                            if host_offset >= cap_bytes {
                                core::ptr::write_bytes(compressed_buf, 0, csize);
                            } else {
                                let avail = cap_bytes - host_offset;
                                let read_len = if (csize as u64) < avail {
                                    csize as u64
                                } else {
                                    avail
                                };
                                if (read_len as usize) < csize {
                                    core::ptr::write_bytes(
                                        compressed_buf.add(read_len as usize),
                                        0,
                                        csize - read_len as usize,
                                    );
                                }
                                if read_len > 0
                                    && !read_cluster_sectors(
                                        call_table,
                                        dev_idx as u32,
                                        host_offset,
                                        compressed_buf,
                                        read_len,
                                        sector_size,
                                        bytes_read,
                                    )
                                {
                                    return false;
                                }
                            }

                            // Inflate exactly cluster_size bytes into
                            // staging_buf (MAX_CLUSTER_SIZE), then copy the
                            // requested span. qcow1 clusters are RAW DEFLATE:
                            // miniz WITHOUT TINFL_FLAG_PARSE_ZLIB_HEADER (no
                            // qcow2 zlib-first two-try). We clobber staging_buf,
                            // so invalidate the qcow2/vmdk large-cluster staging
                            // cache to keep a later backing read honest.
                            let comp_slice =
                                core::slice::from_raw_parts(compressed_buf as *const u8, csize);
                            let out_slice =
                                core::slice::from_raw_parts_mut(staging_buf, cluster_size as usize);
                            use miniz_oxide::inflate::core::inflate_flags;
                            use miniz_oxide::inflate::TINFLStatus;
                            let mut decomp = miniz_oxide::inflate::core::DecompressorOxide::new();
                            let (status, _in_consumed, out_produced) =
                                miniz_oxide::inflate::core::decompress(
                                    &mut decomp,
                                    comp_slice,
                                    out_slice,
                                    0,
                                    inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
                                );
                            *staging_cluster_offset = u64::MAX;
                            if status != TINFLStatus::Done || out_produced != cluster_size as usize
                            {
                                return false;
                            }
                            core::ptr::copy_nonoverlapping(
                                staging_buf.add(offset_in_cluster as usize),
                                dst,
                                span as usize,
                            );
                        }
                        None => return false,
                    }

                    done += span;
                }
                return true;
            }
            #[cfg(feature = "dmg-input")]
            ImageFormat::Dmg => {
                // ================= EIO PARITY (READ THIS) =================
                // This arm INVERTS the phase 2-4 zero-fill posture. Unlike
                // the VDI / Parallels / VHD / qcow1 arms, DMG reads ERROR
                // where those formats zero-fill. qemu's block/dmg.c short-
                // preads a truncated data fork and treats a gap (a sector
                // covered by no chunk: a hole between chunks, a dropped
                // unsupported-codec chunk, or the koly-SectorCount tail
                // beyond mish coverage) as a hard I/O error — convert exits
                // non-zero. We mirror that exactly: any span whose bytes
                // the device cannot supply, and any Gap, returns `false`
                // here — NEVER a zero-fill. Only genuine zero/ignore chunks
                // write zeros. DMG has no backing file, so there is no
                // chain descent from this arm.
                let state = match &chain_states.dmg_states[dev_idx] {
                    Some(s) => s,
                    None => return false,
                };
                let cap_bytes = cap.saturating_mul(sector_size as u64);
                let mut done = 0u64;
                while done < chunk_size {
                    let cur_virtual = virtual_offset + done;
                    // DMG virtual sectors are always 512 bytes; the koly
                    // SectorCount and every chunk boundary are in those
                    // units. `intra` is a sub-512 remainder (virtually
                    // always 0, since chunk reads are >= sector_size).
                    let cur_sector = cur_virtual / dmg::SECTOR_BYTES;
                    let intra = cur_virtual % dmg::SECTOR_BYTES;
                    let dst = buf.add(done as usize);
                    let remaining = chunk_size - done;

                    match state.chunk_lookup(cur_sector) {
                        dmg::DmgLookup::Zero { span_sectors } => {
                            let span_bytes = span_sectors
                                .saturating_mul(dmg::SECTOR_BYTES)
                                .saturating_sub(intra);
                            let span = if remaining < span_bytes {
                                remaining
                            } else {
                                span_bytes
                            };
                            core::ptr::write_bytes(dst, 0, span as usize);
                            done += span;
                        }
                        dmg::DmgLookup::Raw {
                            host_offset,
                            span_sectors,
                        } => {
                            let span_bytes = span_sectors
                                .saturating_mul(dmg::SECTOR_BYTES)
                                .saturating_sub(intra);
                            let span = if remaining < span_bytes {
                                remaining
                            } else {
                                span_bytes
                            };
                            // `host_offset` is already advanced to
                            // cur_sector's start; add the sub-512 remainder
                            // for a (rare) unaligned start.
                            let read_at = host_offset.saturating_add(intra);
                            // EIO PARITY: any needed byte at/past capacity
                            // fails the read (qemu short-pread -> EIO). NOT
                            // a zero-fill.
                            let end = read_at.saturating_add(span);
                            if read_at >= cap_bytes || end > cap_bytes {
                                return false;
                            }
                            let intra_sector = (read_at % sector_size as u64) as usize;
                            let ok = if intra_sector == 0 {
                                read_cluster_sectors(
                                    call_table,
                                    dev_idx as u32,
                                    read_at,
                                    dst,
                                    span,
                                    sector_size,
                                    bytes_read,
                                )
                            } else {
                                read_offset_sectors(
                                    call_table,
                                    dev_idx as u32,
                                    read_at,
                                    dst,
                                    span,
                                    sector_size,
                                    compressed_buf,
                                    bytes_read,
                                )
                            };
                            if !ok {
                                return false;
                            }
                            done += span;
                        }
                        dmg::DmgLookup::Zlib {
                            host_offset,
                            comp_len,
                            chunk_first_sector,
                            chunk_sector_count,
                        } => {
                            // Staging cache key: the chunk's host comp
                            // offset, TAGGED with bit 63. The qcow2/vmdk
                            // arms key `staging_cluster_offset` by a
                            // *virtual* cluster/grain base, which is always
                            // < 2^63 (bit 63 clear); file offsets are also
                            // < 2^63, so OR-ing bit 63 yields a key that can
                            // never alias a qcow2/vmdk key. This makes a
                            // DMG-backing-under-qcow2 chain share the one
                            // staging buffer safely, and lets consecutive
                            // read calls landing in the same (large) DMG
                            // chunk skip re-inflation — qemu caches exactly
                            // one decompressed chunk the same way.
                            let cache_key = host_offset | (1u64 << 63);
                            if *staging_cluster_offset != cache_key {
                                let uncompressed = match chunk_sector_count
                                    .checked_mul(dmg::SECTOR_BYTES)
                                    .filter(|&n| n as usize <= MAX_CLUSTER_SIZE)
                                {
                                    Some(n) => n,
                                    None => return false,
                                };
                                // EIO PARITY: the whole compressed chunk
                                // must lie in-file. A truncated data fork
                                // fails — we do NOT inflate from fabricated
                                // zero bytes (the qcow1 arm's posture).
                                let comp_end = host_offset.saturating_add(comp_len);
                                if comp_len as usize > COMPRESSED_BUF_SIZE
                                    || host_offset >= cap_bytes
                                    || comp_end > cap_bytes
                                {
                                    return false;
                                }
                                // Byte-accurate read of comp_len bytes (the
                                // comp offset may be unaligned) into
                                // compressed_buf.
                                if comp_len > 0
                                    && !read_cluster_sectors(
                                        call_table,
                                        dev_idx as u32,
                                        host_offset,
                                        compressed_buf,
                                        comp_len,
                                        sector_size,
                                        bytes_read,
                                    )
                                {
                                    return false;
                                }
                                // Inflate ZLIB-WRAPPED: UDZO chunks carry
                                // the 0x78 zlib header, so we use the
                                // qcow2-style first-try flags
                                // (TINFL_FLAG_PARSE_ZLIB_HEADER), NOT
                                // qcow1's raw-DEFLATE-only call. Require
                                // Done status AND an exactly-sized output.
                                let comp_slice = core::slice::from_raw_parts(
                                    compressed_buf as *const u8,
                                    comp_len as usize,
                                );
                                let out_slice = core::slice::from_raw_parts_mut(
                                    staging_buf,
                                    uncompressed as usize,
                                );
                                use miniz_oxide::inflate::core::inflate_flags;
                                use miniz_oxide::inflate::TINFLStatus;
                                let mut decomp =
                                    miniz_oxide::inflate::core::DecompressorOxide::new();
                                let (status, _in_consumed, out_produced) =
                                    miniz_oxide::inflate::core::decompress(
                                        &mut decomp,
                                        comp_slice,
                                        out_slice,
                                        0,
                                        inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
                                            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
                                    );
                                if status != TINFLStatus::Done
                                    || out_produced != uncompressed as usize
                                {
                                    // staging_buf is now clobbered; drop the
                                    // stale cache marker.
                                    *staging_cluster_offset = u64::MAX;
                                    return false;
                                }
                                *staging_cluster_offset = cache_key;
                            }
                            // Serve from the offset within the cached
                            // inflated chunk.
                            let chunk_base_bytes =
                                chunk_first_sector.saturating_mul(dmg::SECTOR_BYTES);
                            let within = cur_virtual.saturating_sub(chunk_base_bytes);
                            let chunk_bytes = chunk_sector_count.saturating_mul(dmg::SECTOR_BYTES);
                            let span_bytes = chunk_bytes.saturating_sub(within);
                            let span = if remaining < span_bytes {
                                remaining
                            } else {
                                span_bytes
                            };
                            core::ptr::copy_nonoverlapping(
                                staging_buf.add(within as usize),
                                dst,
                                span as usize,
                            );
                            done += span;
                        }
                        dmg::DmgLookup::Gap { span_sectors } => {
                            // EIO PARITY: a hole between chunks, a dropped
                            // (unsupported-codec) chunk, or the
                            // koly-SectorCount tail is a hard I/O error in
                            // qemu — NOT a zero-fill.
                            let _ = span_sectors;
                            return false;
                        }
                    }
                }
                return true;
            }
            ImageFormat::VmdkDescriptor => {
                // A VMDK flat descriptor holds no content of its
                // own; the flat extent(s) live on data device(s)
                // wired up by the VMM. Walk consecutive data
                // devices starting at data_device_idx, using each
                // device's virtual_size (= extent size from
                // descriptor) to map the virtual offset to the
                // correct extent and offset within it.
                let first_data_dev = chain_config.devices[dev_idx].data_device_idx;
                if first_data_dev == 0 {
                    return false;
                }

                // Walk data devices to find which extent holds
                // the requested virtual offset.
                let mut remaining = virtual_offset;
                let mut d = first_data_dev;
                while (d as usize) < chain_config.device_count as usize {
                    let ext_size = chain_config.devices[d as usize].virtual_size;
                    if ext_size == 0 {
                        break; // End of data devices
                    }
                    if remaining < ext_size {
                        let data_cap = (call_table.get_input_capacity)(d);
                        return read_raw_sectors(
                            call_table,
                            d,
                            remaining,
                            buf,
                            chunk_size,
                            sector_size,
                            data_cap,
                            bytes_read,
                        );
                    }
                    remaining -= ext_size;
                    d += 1;
                }
                // Offset beyond all extents: zeros
                core::ptr::write_bytes(buf, 0, chunk_size as usize);
                return true;
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

/// Read an arbitrary virtual byte range, filling the FULL `len` bytes.
///
/// [`read_chain_virtual_cluster`] only fills up to one input cluster per
/// call (its `chunk_size` is clamped to the qcow2 cluster size for qcow2
/// inputs), so a caller that hands it a span larger than the input
/// cluster — e.g. a VMDK 64 KiB grain or a VHD/VHDX block read from a
/// qcow2 with 512-byte clusters — would otherwise get only the first
/// cluster filled and stale/zero bytes after it. The qcow2 output path
/// loops in `min(input_cluster, output_cluster)` steps to avoid this;
/// this wrapper centralises that loop so the VMDK/VHD/VHDX writers can
/// request a whole grain/block and get every byte.
///
/// # Safety
///
/// `len` may be any size; it is filled exactly. `buf` must point to at
/// least `len` writable bytes. All other arguments match
/// [`read_chain_virtual_cluster`]; see its `# Safety` notes for the
/// `compressed_buf`/`staging_buf` sizing and `call_table` validity
/// requirements.
#[allow(clippy::too_many_arguments)]
pub unsafe fn read_chain_virtual_range(
    call_table: &CallTable,
    chain_start: usize,
    chain_len: usize,
    virtual_offset: u64,
    buf: *mut u8,
    len: u64,
    sector_size: usize,
    chain_config: &ChainConfig,
    chain_states: &mut ChainStates,
    compressed_buf: *mut u8,
    staging_buf: *mut u8,
    staging_cluster_offset: &mut u64,
    aes_key: Option<&[u8; 16]>,
    luks_key: Option<&[u8]>,
    luks_sector_size: u64,
    bytes_read: &mut u64,
) -> bool {
    // Per-call read granularity: the top device's cluster size bounds how
    // much read_chain_virtual_cluster fills in one call. Raw inputs report
    // cluster_size 0 and read the full span in one go, so fall back to
    // `len` in that case (a single iteration).
    let input_cluster_size = {
        let top = &chain_config.devices[chain_start];
        if top.cluster_size > 0 {
            top.cluster_size as u64
        } else {
            len
        }
    };
    let step = core::cmp::min(input_cluster_size, len).max(1);

    let mut filled: u64 = 0;
    while filled < len {
        // read_chain_virtual_cluster reads from `intra = vo % cluster` up to
        // `min(piece, cluster)` bytes, so a piece must never straddle a
        // cluster boundary or the tail of the cluster would be skipped. Cap
        // each piece at the remainder of the current input cluster.
        let abs = virtual_offset + filled;
        let to_cluster_end = input_cluster_size - (abs % input_cluster_size);
        let piece = core::cmp::min(core::cmp::min(step, len - filled), to_cluster_end);
        if !read_chain_virtual_cluster(
            call_table,
            chain_start,
            chain_len,
            virtual_offset + filled,
            buf.add(filled as usize),
            piece,
            sector_size,
            chain_config,
            chain_states,
            compressed_buf,
            staging_buf,
            staging_cluster_offset,
            aes_key,
            luks_key,
            luks_sector_size,
            bytes_read,
        ) {
            return false;
        }
        filled += piece;
    }
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
/// VMDK and VHD state is feature-gated to avoid binary bloat when
/// not needed. Each device in a chain uses at most one format's
/// state slot.
#[derive(Default)]
pub struct ChainStates {
    pub qcow2_states: [Option<Qcow2State>; MAX_CHAIN_DEVICES],
    #[cfg(feature = "vmdk-input")]
    pub vmdk_states: [Option<VmdkState>; MAX_CHAIN_DEVICES],
    #[cfg(feature = "vhd-input")]
    pub vhd_states: [Option<VhdState>; MAX_CHAIN_DEVICES],
    #[cfg(feature = "vhdx-input")]
    pub vhdx_states: [Option<VhdxState>; MAX_CHAIN_DEVICES],
    #[cfg(feature = "vdi-input")]
    pub vdi_states: [Option<vdi::VdiState>; MAX_CHAIN_DEVICES],
    #[cfg(feature = "parallels-input")]
    pub parallels_states: [Option<parallels::ParallelsState>; MAX_CHAIN_DEVICES],
    #[cfg(feature = "qcow1-input")]
    pub qcow1_states: [Option<qcow1::Qcow1State>; MAX_CHAIN_DEVICES],
    #[cfg(feature = "dmg-input")]
    pub dmg_states: [Option<dmg::DmgState>; MAX_CHAIN_DEVICES],
}

/// Initialize format-specific state for all devices in a chain.
///
/// Initializes QCOW2 state for QCOW2 devices, and (when the
/// respective features are enabled) VMDK state for VMDK4 devices
/// and VHD state for VHD devices. Each device reuses the same
/// per-device cache memory region (2 × MAX_SECTOR_SIZE), since a
/// device is never more than one format.
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
    dmg_scratch_base: usize,
    dmg_scratch_len: usize,
    bytes_read: &mut u64,
) -> bool {
    // The DMG chunk table needs a persistent, per-device home in guest
    // scratch (unlike every other format, whose per-device state is a
    // fixed-size cache that fits in the shared L1/L2 cache slots). The
    // caller hands us a `[dmg_scratch_base, +dmg_scratch_len)` region it
    // has reserved; we carve one `DMG_REQUIRED_SCRATCH`-sized slot per DMG
    // device out of it, contiguously. Only the first `DMG_TABLE_REGION`
    // bytes of each slot must survive `DmgState::init`; the 2 MiB staging
    // suffix is transient (see the crate's scratch-layout docs and the
    // per-consumer memory maps). A chain can legitimately hold more than
    // one DMG (e.g. `compare` reads two independent chains, each possibly
    // a DMG), so we allocate slots sequentially and refuse cleanly if the
    // reserved region cannot hold another.
    #[cfg(not(feature = "dmg-input"))]
    let _ = (dmg_scratch_base, dmg_scratch_len);
    #[cfg(feature = "dmg-input")]
    let mut dmg_slot: usize = 0;
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
                    dev_info.actual_size,
                    l1_cache_addr(dynamic_bufs_start, dev_idx),
                    l2_cache_addr(dynamic_bufs_start, dev_idx),
                    bytes_read,
                );
                if chain_states.vmdk_states[dev_idx].is_none() {
                    return false;
                }
            }
            #[cfg(feature = "vhd-input")]
            ImageFormat::Vhd => {
                // Reuse the same cache slots: L1→BAT, L2→data
                chain_states.vhd_states[dev_idx] = VhdState::init(
                    call_table,
                    dev_idx as u32,
                    sector_size,
                    cap,
                    l1_cache_addr(dynamic_bufs_start, dev_idx),
                    l2_cache_addr(dynamic_bufs_start, dev_idx),
                    bytes_read,
                );
                if chain_states.vhd_states[dev_idx].is_none() {
                    return false;
                }
            }
            #[cfg(feature = "vhdx-input")]
            ImageFormat::Vhdx => {
                // Reuse the same cache slots: L1→BAT, L2→data
                chain_states.vhdx_states[dev_idx] = VhdxState::init(
                    call_table,
                    dev_idx as u32,
                    sector_size,
                    cap,
                    l1_cache_addr(dynamic_bufs_start, dev_idx),
                    l2_cache_addr(dynamic_bufs_start, dev_idx),
                    bytes_read,
                );
                if chain_states.vhdx_states[dev_idx].is_none() {
                    return false;
                }
            }
            #[cfg(feature = "vdi-input")]
            ImageFormat::Vdi => {
                // Reuse the same cache slots: L1→block map, L2→data
                chain_states.vdi_states[dev_idx] = vdi::VdiState::init(
                    call_table,
                    dev_idx as u32,
                    sector_size,
                    cap,
                    l1_cache_addr(dynamic_bufs_start, dev_idx),
                    l2_cache_addr(dynamic_bufs_start, dev_idx),
                    bytes_read,
                );
                if chain_states.vdi_states[dev_idx].is_none() {
                    return false;
                }
            }
            #[cfg(feature = "parallels-input")]
            ImageFormat::Parallels => {
                // Reuse the same cache slots: L1→BAT, L2→(unused parity buf)
                chain_states.parallels_states[dev_idx] = parallels::ParallelsState::init(
                    call_table,
                    dev_idx as u32,
                    sector_size,
                    cap,
                    l1_cache_addr(dynamic_bufs_start, dev_idx),
                    l2_cache_addr(dynamic_bufs_start, dev_idx),
                    bytes_read,
                );
                if chain_states.parallels_states[dev_idx].is_none() {
                    return false;
                }
            }
            #[cfg(feature = "qcow1-input")]
            ImageFormat::Qcow1 => {
                // Reuse the same cache slots: L1→L1 table, L2→L2 table. Init
                // failure — a malformed header, a failed header-sector read,
                // or the reader-level encryption refusal (crypt_method != 0) —
                // propagates as `false` exactly like the Vdi/Parallels arms.
                chain_states.qcow1_states[dev_idx] = qcow1::Qcow1State::init(
                    call_table,
                    dev_idx as u32,
                    sector_size,
                    cap,
                    l1_cache_addr(dynamic_bufs_start, dev_idx),
                    l2_cache_addr(dynamic_bufs_start, dev_idx),
                    bytes_read,
                );
                if chain_states.qcow1_states[dev_idx].is_none() {
                    return false;
                }
            }
            #[cfg(feature = "dmg-input")]
            ImageFormat::Dmg => {
                // Carve the next contiguous DMG slot out of the caller's
                // reserved region. `DmgState::init` stages the full
                // DMG_REQUIRED_SCRATCH (~3.25 MiB: 1.25 MiB persistent
                // table + 2 MiB transient plist/decode) at `slot_base`,
                // and retains only the first DMG_TABLE_REGION bytes. Slots
                // are laid out `DMG_TABLE_REGION` apart, so slot N+1's
                // table reuses slot N's transient — safe because init runs
                // sequentially (slot N has returned before slot N+1
                // begins), and every earlier slot's persistent table sits
                // below where the current slot writes.
                let slot_base = dmg_scratch_base + dmg_slot * dmg::DMG_TABLE_REGION;
                if slot_base
                    .checked_add(dmg::DMG_REQUIRED_SCRATCH)
                    .map(|end| end > dmg_scratch_base + dmg_scratch_len)
                    .unwrap_or(true)
                {
                    // More DMG devices than the reserved region can hold.
                    let msg: &[u8] = b"dmg: too many dmg devices for scratch\n\0";
                    (call_table.debug_print)(msg.as_ptr());
                    return false;
                }
                match dmg::DmgState::init(
                    call_table,
                    dev_idx as u32,
                    sector_size,
                    cap,
                    slot_base as *mut u8,
                    dmg::DMG_REQUIRED_SCRATCH,
                    bytes_read,
                ) {
                    Ok(state) => {
                        chain_states.dmg_states[dev_idx] = Some(state);
                        dmg_slot += 1;
                    }
                    Err(refusal) => {
                        // Emit the typed, stable message so malformed
                        // fixtures can pin the exact reason (5c/5d rely on
                        // these strings verbatim).
                        dmg_debug_print_refusal(call_table, refusal);
                        return false;
                    }
                }
            }
            _ => {} // Raw and other formats need no per-device state
        }
    }
    true
}

/// Emit the stable, typed `dmg:`-prefixed refusal string for a
/// [`dmg::DmgRefusal`] via the call table's `debug_print`. These strings
/// are the `expected_error` contract for the malformed DMG fixtures, so
/// they must stay stable. [`dmg::DmgRefusal::UnsupportedCodec`] carries the
/// raw chunk-type code, which is rendered as `0x`-prefixed lowercase hex
/// into a fixed stack buffer.
#[cfg(feature = "dmg-input")]
fn dmg_debug_print_refusal(call_table: &CallTable, refusal: dmg::DmgRefusal) {
    use dmg::DmgRefusal;
    let msg: &[u8] = match refusal {
        DmgRefusal::ScratchTooSmall => b"dmg: scratch region too small\n\0",
        DmgRefusal::TrailerNotFound => b"dmg: koly trailer not found\n\0",
        DmgRefusal::KolyRead => b"dmg: koly trailer read failed\n\0",
        DmgRefusal::KolyFieldOutOfRange => b"dmg: koly field out of range\n\0",
        DmgRefusal::BadDataForkOffset => b"dmg: bad data fork offset\n\0",
        DmgRefusal::BadRsrcForkRegion => b"dmg: bad resource fork region\n\0",
        DmgRefusal::BadXmlRegion => b"dmg: bad xml region\n\0",
        DmgRefusal::NegativeSectorCount => b"dmg: negative sector count\n\0",
        DmgRefusal::NoChunkSource => b"dmg: no chunk source\n\0",
        DmgRefusal::RegionTooLarge => b"dmg: metadata region too large\n\0",
        DmgRefusal::RegionReadFailed => b"dmg: metadata region read failed\n\0",
        DmgRefusal::MalformedXml => b"dmg: malformed xml\n\0",
        DmgRefusal::RsrcForkMalformed => b"dmg: malformed resource fork\n\0",
        DmgRefusal::QemuSectorCountTooLarge => b"dmg: chunk sector count exceeds max (131072)\n\0",
        DmgRefusal::QemuChunkLengthTooLarge => b"dmg: chunk length exceeds max (67108864)\n\0",
        DmgRefusal::ChunkTableTooLarge => b"dmg: chunk table too large\n\0",
        DmgRefusal::StagedSectorCountTooLarge => b"dmg: chunk exceeds staging cap\n\0",
        DmgRefusal::StagedChunkLengthTooLarge => b"dmg: compressed chunk exceeds buffer\n\0",
        DmgRefusal::EmptyChunkTable => b"dmg: empty chunk table\n\0",
        DmgRefusal::UnsortedOrOverlapping => b"dmg: unsorted or overlapping chunk table\n\0",
        DmgRefusal::ArithmeticOverflow => b"dmg: arithmetic overflow\n\0",
        DmgRefusal::UnsupportedCodec(code) => {
            // "dmg: unsupported chunk codec 0x________\n\0"
            let mut buf = *b"dmg: unsupported chunk codec 0x00000000\n\0";
            const HEX: &[u8; 16] = b"0123456789abcdef";
            // The eight hex digits start right after the "0x" (index 31).
            for i in 0..8 {
                let nibble = ((code >> ((7 - i) * 4)) & 0xf) as usize;
                buf[31 + i] = HEX[nibble];
            }
            unsafe { (call_table.debug_print)(buf.as_ptr()) };
            return;
        }
    };
    unsafe { (call_table.debug_print)(msg.as_ptr()) };
}
