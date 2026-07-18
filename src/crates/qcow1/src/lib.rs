//! QCOW1 ("qcow" v1, qemu's original deprecated format) parsing.
//!
//! Provides QCOW1 header parsing and two-level (L1/L2) block-lookup for the
//! convert / compare / dd read path. Mirrors qemu's `block/qcow.c`
//! read-only open-time validation (`qcow_open`) and the `get_cluster_offset`
//! lookup semantics exactly: the header is validated with the same
//! magic/version/cluster_bits/l2_bits/size/crypt/backing checks qemu applies
//! on the RO path, `l1_table_offset` is deliberately NOT validated (qemu
//! tolerates 0 / unaligned / past-EOF and zero-fills later reads), and
//! lookups never reject host offsets past end-of-file — qemu performs no
//! file-length check and zero-fills past-EOF reads, so that classification
//! is left to the chain reader.
//!
//! Two QCOW1-specific deltas from the vdi/parallels precedent:
//!
//! * **Unallocated means "defer to the backing file"** — unlike VDI and
//!   Parallels (which can never have a lower device in the chain and so
//!   zero-fill), an unallocated QCOW1 cluster must fall through to the next
//!   device in the backing chain (zeros only if there is none). The lookup
//!   result merely reports [`Qcow1BlockLookup::Unallocated`]; the chain
//!   reader decides between backing-descent and zero-fill.
//! * A [`Qcow1BlockLookup::Compressed`] result that the other formats lack:
//!   L2 entries with bit 63 set describe a byte-packed compressed cluster.
//!
//! `parse` stays lenient on encryption (`crypt_method == 1`/AES parses so
//! `info` can report the metadata); the reader-level [`Qcow1State::init`]
//! refuses any non-zero `crypt_method`, matching keyless qemu's refusal of
//! encrypted data reads.

#![no_std]
#![allow(clippy::too_many_arguments)]

use shared::{be_u32, be_u64, CallTable, MAX_SECTOR_SIZE};

// The QCOW1 magic is identical to the QCOW2 magic (`QFI\xfb`); only the
// version field distinguishes the two formats. Reuse the shared constant
// rather than redefining it. Detection performs the same magic+version
// split (`shared::format_detection::detect_format_from_header` +
// `QCOW_VERSION_1`); this parser re-validates both.
use shared::format_detection::QCOW2_MAGIC;

// ============================================================================
// QCOW1 header field offsets (all big-endian)
// ============================================================================

/// Header size in bytes.
pub const HEADER_SIZE: usize = 48;

/// Magic offset (u32 BE): `QFI\xfb` (`0x514649fb`), same as qcow2.
pub const MAGIC_OFFSET: usize = 0;
/// Version offset (u32 BE): must be 1.
pub const VERSION_OFFSET: usize = 4;
/// Backing-file name offset (u64 BE): file offset of the backing file name.
pub const BACKING_FILE_OFFSET_OFFSET: usize = 8;
/// Backing-file name length offset (u32 BE): `> 1023` refused.
pub const BACKING_FILE_SIZE_OFFSET: usize = 16;
/// Modification-time offset (u32 BE): ignored (always 0 on create).
pub const MTIME_OFFSET: usize = 20;
/// Virtual size offset (u64 BE): virtual disk size in bytes.
pub const SIZE_OFFSET: usize = 24;
/// Cluster-bits offset (u8): accepted range [9, 16].
pub const CLUSTER_BITS_OFFSET: usize = 32;
/// L2-bits offset (u8): accepted range [6, 13].
pub const L2_BITS_OFFSET: usize = 33;
/// Padding offset (u16): unused.
pub const PADDING_OFFSET: usize = 34;
/// Crypt-method offset (u32 BE): 0=none, 1=AES, `>= 2` refused.
pub const CRYPT_METHOD_OFFSET: usize = 36;
/// L1-table offset (u64 BE): **never validated** (0 / unaligned / past-EOF
/// all tolerated at open; reads later zero-fill).
pub const L1_TABLE_OFFSET_OFFSET: usize = 40;

// ============================================================================
// QCOW1 constants
// ============================================================================

/// Mandatory version for the qcow (v1) driver.
pub const QCOW1_VERSION: u32 = 1;

/// Minimum accepted `cluster_bits` (512-byte clusters).
pub const QCOW1_CLUSTER_BITS_MIN: u8 = 9;
/// Maximum accepted `cluster_bits` (64 KiB clusters).
pub const QCOW1_CLUSTER_BITS_MAX: u8 = 16;
/// Minimum accepted `l2_bits`. qemu writes the check as `l2_bits < 9 - 3`
/// (bytes = entries << 3), i.e. `l2_bits >= 6`.
pub const QCOW1_L2_BITS_MIN: u8 = 6;
/// Maximum accepted `l2_bits`. qemu writes the check as `l2_bits > 16 - 3`,
/// i.e. `l2_bits <= 13`.
pub const QCOW1_L2_BITS_MAX: u8 = 13;

/// `crypt_method == 1`: AES-128-CBC. Parses (for `info`); refused at reader
/// init. Anything `>= 2` is refused at parse.
pub const QCOW1_CRYPT_AES: u32 = 1;

/// Maximum backing-file name length qemu will open.
pub const QCOW1_BACKING_FILE_SIZE_MAX: u32 = 1023;

/// L2-entry flag (bit 63): the cluster is compressed (byte-packed).
pub const QCOW1_OFLAG_COMPRESSED: u64 = 1u64 << 63;

/// The "Image too large" L1-size cap from `qcow_open` (qemu `block/qcow.c`
/// v7.0.0:247): `l1_size > INT_MAX / sizeof(uint64_t)` is refused. With
/// `INT_MAX == 2_147_483_647` and `sizeof(uint64_t) == 8` this is
/// `268_435_455` (`0x0fff_ffff`). See [`compute_l1_size`] for the full
/// arithmetic; step 4d pins the empirical boundary against real qemu.
pub const QCOW1_L1_SIZE_MAX: u64 = (i32::MAX as u64) / 8;

// ============================================================================
// "Image too large" L1-size arithmetic (single documented source of truth)
// ============================================================================

/// Compute the L1-table entry count for a virtual `size`, refusing the
/// "Image too large" cases exactly as qemu `qcow_open` does
/// (`block/qcow.c` v7.0.0:239-253):
///
/// ```c
/// shift = s->cluster_bits + s->l2_bits;
/// if (header.size > UINT64_MAX - (1LL << shift)) {          // line 241
///     error_setg(errp, "Image too large");                  // (overflow guard)
/// } else {
///     uint64_t l1_size = (header.size + (1LL << shift) - 1) >> shift;  // 246
///     if (l1_size > INT_MAX / sizeof(uint64_t)) {           // line 247
///         error_setg(errp, "Image too large");
///     }
///     s->l1_size = l1_size;
/// }
/// ```
///
/// `shift = cluster_bits + l2_bits` is at most `16 + 13 = 29` given the
/// validated bit ranges, so `1 << shift` never overflows. `l1_size` is
/// `ceil(size / 2^shift)`. Returns `None` for either "Image too large"
/// refusal, otherwise the entry count.
fn compute_l1_size(size: u64, cluster_bits: u8, l2_bits: u8) -> Option<u64> {
    let shift = (cluster_bits as u32).checked_add(l2_bits as u32)?;
    // 1 << shift. shift <= 29 here, but keep it checked for panic-freedom.
    let span = 1u64.checked_shl(shift)?;
    // Overflow guard: the rounding add below must not wrap (qemu line 241).
    if size > u64::MAX - span {
        return None;
    }
    // l1_size = ceil(size / span) = (size + span - 1) >> shift (qemu line 246).
    let l1_size = size.checked_add(span - 1)?.checked_shr(shift)?;
    // The INT_MAX/8 cap (qemu line 247).
    if l1_size > QCOW1_L1_SIZE_MAX {
        return None;
    }
    Some(l1_size)
}

// ============================================================================
// QCOW1 header parsing
// ============================================================================

/// Parsed QCOW1 header fields the read path needs.
///
/// All sizes are in bytes. `virtual_size` is the raw header `size` verbatim
/// (no rounding). `l1_size` is the derived entry count from
/// [`compute_l1_size`].
pub struct Qcow1Header {
    /// Bits per cluster (`cluster_size == 1 << cluster_bits`), in [9, 16].
    pub cluster_bits: u8,
    /// Bits per L2 table (`l2_size == 1 << l2_bits`), in [6, 13].
    pub l2_bits: u8,
    /// Cluster size in bytes (`1 << cluster_bits`).
    pub cluster_size: u64,
    /// L2 entries per table (`1 << l2_bits`).
    pub l2_size: u64,
    /// Virtual disk size in bytes, stored verbatim (no rounding).
    pub virtual_size: u64,
    /// L1-table entry count (`ceil(virtual_size / 2^(cluster_bits+l2_bits))`).
    pub l1_size: u64,
    /// File byte offset of the L1 table (deliberately unvalidated).
    pub l1_table_offset: u64,
    /// File byte offset of the backing-file name (0 == none).
    pub backing_file_offset: u64,
    /// Backing-file name length in bytes (`<= 1023`).
    pub backing_file_size: u32,
    /// Encryption method: 0=none, 1=AES. Stored verbatim; the reader refuses
    /// non-zero at init.
    pub crypt_method: u32,
}

impl Qcow1Header {
    /// Parse and validate a QCOW1 header from raw bytes.
    ///
    /// Enforces qemu `qcow_open`'s read-only open-time checks with the same
    /// limits (`block/qcow.c`): magic `0x514649fb` AND version 1;
    /// `cluster_bits` in [9, 16]; `l2_bits` in [6, 13]; `size >= 2`; the
    /// "Image too large" L1-size bound (see [`compute_l1_size`]);
    /// `crypt_method <= 1` (`>= 2` is "invalid encryption method");
    /// `backing_file_size <= 1023`.
    ///
    /// `crypt_method == 1` (AES) PARSES successfully — `info` needs the
    /// metadata; the reader refuses it at [`Qcow1State::init`].
    /// `l1_table_offset` is deliberately NOT validated: qemu tolerates 0,
    /// unaligned, and past-EOF values at open and zero-fills later reads.
    /// `mtime` and `padding` are ignored.
    ///
    /// Returns `None` if the buffer is too small or any check fails
    /// (including arithmetic overflow of the derived sizes).
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }

        let magic = be_u32(buf, MAGIC_OFFSET);
        if magic != QCOW2_MAGIC {
            return None;
        }

        let version = be_u32(buf, VERSION_OFFSET);
        if version != QCOW1_VERSION {
            return None;
        }

        let size = be_u64(buf, SIZE_OFFSET);
        if size <= 1 {
            return None;
        }

        let cluster_bits_raw = buf[CLUSTER_BITS_OFFSET];
        if !(QCOW1_CLUSTER_BITS_MIN..=QCOW1_CLUSTER_BITS_MAX).contains(&cluster_bits_raw) {
            return None;
        }

        let l2_bits_raw = buf[L2_BITS_OFFSET];
        if !(QCOW1_L2_BITS_MIN..=QCOW1_L2_BITS_MAX).contains(&l2_bits_raw) {
            return None;
        }

        let crypt_method = be_u32(buf, CRYPT_METHOD_OFFSET);
        // qemu: crypt_method 0 (none) and 1 (AES) accepted at open; anything
        // else is "invalid encryption method in qcow header".
        if crypt_method > QCOW1_CRYPT_AES {
            return None;
        }

        let backing_file_size = be_u32(buf, BACKING_FILE_SIZE_OFFSET);
        if backing_file_size > QCOW1_BACKING_FILE_SIZE_MAX {
            return None;
        }

        // The "Image too large" L1-size bound, derived from qcow_open.
        let l1_size = compute_l1_size(size, cluster_bits_raw, l2_bits_raw)?;

        // cluster_size = 1 << cluster_bits, l2_size = 1 << l2_bits. Both
        // shifts are bounded by the validated ranges (<= 16 and <= 13) and
        // cannot overflow, but stay checked for panic-freedom idiom.
        let cluster_size = 1u64.checked_shl(cluster_bits_raw as u32)?;
        let l2_size = 1u64.checked_shl(l2_bits_raw as u32)?;

        let l1_table_offset = be_u64(buf, L1_TABLE_OFFSET_OFFSET);
        let backing_file_offset = be_u64(buf, BACKING_FILE_OFFSET_OFFSET);

        Some(Qcow1Header {
            cluster_bits: cluster_bits_raw,
            l2_bits: l2_bits_raw,
            cluster_size,
            l2_size,
            virtual_size: size,
            l1_size,
            l1_table_offset,
            backing_file_offset,
            backing_file_size,
            crypt_method,
        })
    }

    /// True if the image declares AES encryption (`crypt_method != 0`).
    /// Informational for `info`; the reader refuses these at init.
    pub fn is_encrypted(&self) -> bool {
        self.crypt_method != 0
    }
}

// ============================================================================
// Block lookup result
// ============================================================================

/// Result of looking up a virtual offset in the QCOW1 two-level table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qcow1BlockLookup {
    /// The cluster is not allocated (L1 index out of range, L1 entry 0, or
    /// L2 entry 0). Unlike VDI/Parallels, this means **defer to the backing
    /// file**: the chain reader descends to the next device (zeros only if
    /// there is none). This lookup result does not itself decide that.
    Unallocated,
    /// The cluster is allocated uncompressed at the given absolute host byte
    /// offset (the L2 entry is the cluster's file offset plus the in-cluster
    /// offset).
    Allocated(u64),
    /// The cluster is compressed (L2 entry bit 63 set). `host_offset` is the
    /// byte offset of the compressed data (may be byte-unaligned); `csize`
    /// is its length in BYTES. The data is raw DEFLATE (no zlib wrapper).
    Compressed { host_offset: u64, csize: usize },
}

// ============================================================================
// QCOW1 state for L1/L2 table I/O
// ============================================================================

/// Runtime state for reading QCOW1 clusters from a device.
///
/// Analogous to `parallels::ParallelsState`. Maintains two independent
/// sector caches — one for L1-table reads, one for L2-table reads — so the
/// two-level walk does not thrash a single cache. The init signature mirrors
/// [`parallels::ParallelsState::init`]'s two-cache-buffer shape.
pub struct Qcow1State {
    pub device_idx: u32,
    pub cluster_bits: u8,
    pub l2_bits: u8,
    pub cluster_size: u64,
    pub l2_size: u64,
    pub l1_size: u64,
    pub l1_table_offset: u64,
    pub virtual_size: u64,
    pub crypt_method: u32,
    // Sector cache for L1-table reads.
    pub l1_cached_sector: u64,
    pub l1_cache_buf: *mut u8,
    // Sector cache for L2-table reads.
    pub l2_cached_sector: u64,
    pub l2_cache_buf: *mut u8,
}

impl Qcow1State {
    /// Initialize QCOW1 state by reading and validating the header.
    ///
    /// Reads the first sector (the 48-byte header lives at offset 0),
    /// validates it via [`Qcow1Header::parse`], and refuses any image with
    /// a non-zero `crypt_method` — the reader-level encryption refusal
    /// (parse stays lenient so `info` can report AES metadata; keyless qemu
    /// likewise refuses encrypted data reads). Per qemu, the L1 table is NOT
    /// required to fit within `input_capacity` — file length is never
    /// validated.
    ///
    /// Returns `None` if the header is invalid, the header sector read
    /// fails, the image is encrypted, or L1-region addressing would
    /// overflow — the same `Option`-`None` failure shape
    /// `ParallelsState::init` uses.
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
    ) -> Option<Self> {
        let _ = input_capacity;

        let mut header_sector = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(device_idx, 0, header_sector.as_mut_ptr(), sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;

        let header = Qcow1Header::parse(&header_sector)?;

        // Reader-level encryption refusal (parse stays lenient for info).
        if header.crypt_method != 0 {
            return None;
        }

        // Ensure the L1 region (l1_table_offset + entries*8, rounded up to a
        // sector boundary) is arithmetically sound. This does NOT require
        // the region to lie within the file — qemu never checks, and
        // l1_table_offset itself is deliberately unvalidated.
        let l1_bytes = header.l1_size.checked_mul(8)?;
        let l1_end = header.l1_table_offset.checked_add(l1_bytes)?;
        l1_end.checked_add(sector_size as u64 - 1)?;

        Some(Qcow1State {
            device_idx,
            cluster_bits: header.cluster_bits,
            l2_bits: header.l2_bits,
            cluster_size: header.cluster_size,
            l2_size: header.l2_size,
            l1_size: header.l1_size,
            l1_table_offset: header.l1_table_offset,
            virtual_size: header.virtual_size,
            crypt_method: header.crypt_method,
            l1_cached_sector: u64::MAX,
            l1_cache_buf,
            l2_cached_sector: u64::MAX,
            l2_cache_buf,
        })
    }

    /// Look up the host location for a given virtual byte offset.
    ///
    /// Performs the two-level QCOW1 walk (qemu `get_cluster_offset`):
    /// `l1_index = offset >> (l2_bits + cluster_bits)`;
    /// `l2_index = (offset >> cluster_bits) & (l2_size - 1)`. Both L1 and L2
    /// entries are u64 big-endian, read via the shared cached-sector helper.
    ///
    /// An L1 index at or beyond `l1_size`, an L1 entry of 0, or an L2 entry
    /// of 0 all map to [`Qcow1BlockLookup::Unallocated`] (the chain reader
    /// then descends to the backing file). An L2 entry with bit 63 set is
    /// [`Qcow1BlockLookup::Compressed`]; otherwise the entry is the absolute
    /// host byte offset of the cluster and the result is
    /// [`Qcow1BlockLookup::Allocated`] at that offset plus the in-cluster
    /// offset. Host offsets past `input_capacity` are NOT rejected — the
    /// caller zero-fills past-EOF reads.
    ///
    /// Returns `None` only if an L1/L2 sector read itself fails or offset
    /// arithmetic overflows.
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
    ) -> Option<Qcow1BlockLookup> {
        let l1_shift = (self.l2_bits as u32).checked_add(self.cluster_bits as u32)?;
        let l1_index = virtual_offset.checked_shr(l1_shift)?;
        if l1_index >= self.l1_size {
            return Some(Qcow1BlockLookup::Unallocated);
        }

        // L1 entry: the byte offset of the L2 table (0 == unallocated).
        let l1_entry_offset = self.l1_table_offset.checked_add(l1_index.checked_mul(8)?)?;
        let l2_table_offset = read_u64_be_cached(
            call_table,
            self.device_idx,
            l1_entry_offset,
            sector_size,
            input_capacity,
            &mut self.l1_cached_sector,
            self.l1_cache_buf,
            bytes_read,
        )?;
        if l2_table_offset == 0 {
            return Some(Qcow1BlockLookup::Unallocated);
        }

        // L2 entry.
        let l2_index = virtual_offset.checked_shr(self.cluster_bits as u32)? & (self.l2_size - 1);
        let l2_entry_offset = l2_table_offset.checked_add(l2_index.checked_mul(8)?)?;
        let entry = read_u64_be_cached(
            call_table,
            self.device_idx,
            l2_entry_offset,
            sector_size,
            input_capacity,
            &mut self.l2_cached_sector,
            self.l2_cache_buf,
            bytes_read,
        )?;
        if entry == 0 {
            return Some(Qcow1BlockLookup::Unallocated);
        }

        if entry & QCOW1_OFLAG_COMPRESSED != 0 {
            // Compressed cluster (qemu decompress_cluster, block/qcow.c:595-597):
            //   coffset = entry & cluster_offset_mask; where
            //     cluster_offset_mask = (1 << (63 - cluster_bits)) - 1
            //   csize   = (entry >> (63 - cluster_bits)) & (cluster_size - 1)
            // The raw `entry >> (63 - cluster_bits)` shift still carries bit
            // 63 into the csize field; the `& (cluster_size - 1)` mask
            // (cluster_size == 1 << cluster_bits) removes it. host_offset may
            // be byte-unaligned; csize is in BYTES.
            let cb = self.cluster_bits as u32;
            let shift = 63u32.checked_sub(cb)?;
            let offset_mask = 1u64.checked_shl(shift)?.checked_sub(1)?;
            let host_offset = entry & offset_mask;
            let csize_mask = self.cluster_size.checked_sub(1)?;
            let csize = (entry.checked_shr(shift)? & csize_mask) as usize;
            return Some(Qcow1BlockLookup::Compressed { host_offset, csize });
        }

        // Uncompressed: the entry is the absolute file byte offset of the
        // cluster (qcow1 has no other flag bits on uncompressed entries).
        let offset_in_cluster = virtual_offset % self.cluster_size;
        let host_byte_offset = entry.checked_add(offset_in_cluster)?;
        Some(Qcow1BlockLookup::Allocated(host_byte_offset))
    }
}

// ============================================================================
// Cached sector read helper (big-endian u64)
// ============================================================================

shared::cached_read!(read_u64_be_cached, u64, be, 8);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use shared::{write_be_u32, write_be_u64};
    use std::sync::Mutex;

    // ====================================================================
    // Header builder
    // ====================================================================

    /// Fields for building a synthetic, otherwise-valid QCOW1 header. Every
    /// field defaults to a value that passes validation; individual tests
    /// mutate the one field under test.
    struct HeaderSpec {
        magic: u32,
        version: u32,
        backing_file_offset: u64,
        backing_file_size: u32,
        mtime: u32,
        size: u64,
        cluster_bits: u8,
        l2_bits: u8,
        crypt_method: u32,
        l1_table_offset: u64,
    }

    impl Default for HeaderSpec {
        fn default() -> Self {
            // qemu-img create -f qcow defaults: cluster_bits=12, l2_bits=9,
            // 1 MiB virtual, unencrypted, no backing file. l1_table_offset
            // placed after the header for a plausible layout.
            HeaderSpec {
                magic: QCOW2_MAGIC,
                version: QCOW1_VERSION,
                backing_file_offset: 0,
                backing_file_size: 0,
                mtime: 0,
                size: 1024 * 1024,
                cluster_bits: 12,
                l2_bits: 9,
                crypt_method: 0,
                l1_table_offset: 512,
            }
        }
    }

    fn build_header(spec: &HeaderSpec) -> [u8; 512] {
        let mut buf = [0u8; 512];
        write_be_u32(&mut buf, MAGIC_OFFSET, spec.magic);
        write_be_u32(&mut buf, VERSION_OFFSET, spec.version);
        write_be_u64(
            &mut buf,
            BACKING_FILE_OFFSET_OFFSET,
            spec.backing_file_offset,
        );
        write_be_u32(&mut buf, BACKING_FILE_SIZE_OFFSET, spec.backing_file_size);
        write_be_u32(&mut buf, MTIME_OFFSET, spec.mtime);
        write_be_u64(&mut buf, SIZE_OFFSET, spec.size);
        buf[CLUSTER_BITS_OFFSET] = spec.cluster_bits;
        buf[L2_BITS_OFFSET] = spec.l2_bits;
        write_be_u32(&mut buf, CRYPT_METHOD_OFFSET, spec.crypt_method);
        write_be_u64(&mut buf, L1_TABLE_OFFSET_OFFSET, spec.l1_table_offset);
        buf
    }

    // ====================================================================
    // compute_l1_size — the "Image too large" arithmetic
    // ====================================================================

    #[test]
    fn compute_l1_size_examples() {
        // shift = cluster_bits + l2_bits = 12 + 9 = 21, span = 2 MiB.
        // 1 MiB image → ceil(1 MiB / 2 MiB) = 1 entry.
        assert_eq!(compute_l1_size(1024 * 1024, 12, 9), Some(1));
        // Exactly one span → 1 entry; one byte over → 2 entries.
        assert_eq!(compute_l1_size(2 * 1024 * 1024, 12, 9), Some(1));
        assert_eq!(compute_l1_size(2 * 1024 * 1024 + 1, 12, 9), Some(2));
        // size == 2 (the minimum) → 1 entry.
        assert_eq!(compute_l1_size(2, 12, 9), Some(1));
    }

    #[test]
    fn compute_l1_size_boundary() {
        // The cap is l1_size <= INT_MAX/8 = 268_435_455. l1_size =
        // ceil(size / 2^shift), so the largest accepted size is exactly
        // QCOW1_L1_SIZE_MAX * 2^shift (that yields l1_size == the cap), and
        // one byte more rounds up past it. Use the smallest valid shift
        // (cluster_bits=9, l2_bits=6 → shift=15, span=32768) so the boundary
        // sizes stay well within u64.
        let span = 1u64 << 15;
        let max_ok_size = QCOW1_L1_SIZE_MAX * span;
        assert_eq!(compute_l1_size(max_ok_size, 9, 6), Some(QCOW1_L1_SIZE_MAX));
        // One byte over the exact-multiple boundary rounds up to cap+1.
        assert_eq!(compute_l1_size(max_ok_size + 1, 9, 6), None);
    }

    #[test]
    fn compute_l1_size_overflow_guard() {
        // qemu's first "Image too large" branch: size > UINT64_MAX - span.
        // With shift=15, span=32768; a size in the top span-window must be
        // refused by the overflow guard, not wrap.
        assert_eq!(compute_l1_size(u64::MAX, 9, 6), None);
        assert_eq!(compute_l1_size(u64::MAX - 10, 9, 6), None);
    }

    // ====================================================================
    // Qcow1Header::parse — acceptance and per-rule rejection
    // ====================================================================

    #[test]
    fn parse_valid_header() {
        let hdr = Qcow1Header::parse(&build_header(&HeaderSpec::default())).unwrap();
        assert_eq!(hdr.cluster_bits, 12);
        assert_eq!(hdr.l2_bits, 9);
        assert_eq!(hdr.cluster_size, 4096);
        assert_eq!(hdr.l2_size, 512);
        assert_eq!(hdr.virtual_size, 1024 * 1024);
        assert_eq!(hdr.l1_table_offset, 512);
        assert_eq!(hdr.crypt_method, 0);
        assert!(!hdr.is_encrypted());
        // ceil(1 MiB / 2^21) = 1.
        assert_eq!(hdr.l1_size, 1);
    }

    #[test]
    fn parse_short_buffer() {
        assert!(Qcow1Header::parse(&[0u8; 47]).is_none());
        assert!(Qcow1Header::parse(&[0u8; 0]).is_none());
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let spec = HeaderSpec {
            magic: 0xdead_beef,
            ..HeaderSpec::default()
        };
        assert!(Qcow1Header::parse(&build_header(&spec)).is_none());
        // A 3-byte "QFI" prefix must NOT be accepted as the 4-byte magic;
        // only the full 0x514649fb passes.
        assert!(Qcow1Header::parse(&build_header(&HeaderSpec::default())).is_some());
    }

    #[test]
    fn parse_version_boundaries() {
        // Only version 1 is accepted (0 and 2 refused).
        for (version, ok) in [(0u32, false), (1, true), (2, false)] {
            let spec = HeaderSpec {
                version,
                ..HeaderSpec::default()
            };
            assert_eq!(
                Qcow1Header::parse(&build_header(&spec)).is_some(),
                ok,
                "version {version}"
            );
        }
    }

    #[test]
    fn parse_cluster_bits_boundaries() {
        // 8 rejected; 9 and 16 accepted; 17 rejected.
        for (cluster_bits, ok) in [(8u8, false), (9, true), (16, true), (17, false)] {
            let spec = HeaderSpec {
                cluster_bits,
                ..HeaderSpec::default()
            };
            assert_eq!(
                Qcow1Header::parse(&build_header(&spec)).is_some(),
                ok,
                "cluster_bits {cluster_bits}"
            );
        }
    }

    #[test]
    fn parse_l2_bits_boundaries() {
        // 5 rejected; 6 and 13 accepted; 14 rejected.
        for (l2_bits, ok) in [(5u8, false), (6, true), (13, true), (14, false)] {
            let spec = HeaderSpec {
                l2_bits,
                ..HeaderSpec::default()
            };
            assert_eq!(
                Qcow1Header::parse(&build_header(&spec)).is_some(),
                ok,
                "l2_bits {l2_bits}"
            );
        }
    }

    #[test]
    fn parse_size_boundaries() {
        // size 0 and 1 rejected ("Image size is too small"); 2 accepted.
        for (size, ok) in [(0u64, false), (1, false), (2, true)] {
            let spec = HeaderSpec {
                size,
                ..HeaderSpec::default()
            };
            assert_eq!(
                Qcow1Header::parse(&build_header(&spec)).is_some(),
                ok,
                "size {size}"
            );
        }
    }

    #[test]
    fn parse_size_verbatim_no_rounding() {
        // An odd size is stored verbatim (unlike VDI, which rounds up).
        let spec = HeaderSpec {
            size: 1_048_577,
            ..HeaderSpec::default()
        };
        let hdr = Qcow1Header::parse(&build_header(&spec)).unwrap();
        assert_eq!(hdr.virtual_size, 1_048_577);
    }

    #[test]
    fn parse_crypt_method_boundaries() {
        // 0 (none) and 1 (AES) PARSE; 2 refused ("invalid encryption
        // method"). crypt_method==1 must parse so info can report it.
        for (crypt_method, ok) in [(0u32, true), (1, true), (2, false)] {
            let spec = HeaderSpec {
                crypt_method,
                ..HeaderSpec::default()
            };
            let parsed = Qcow1Header::parse(&build_header(&spec));
            assert_eq!(parsed.is_some(), ok, "crypt_method {crypt_method}");
            if crypt_method == 1 {
                let hdr = parsed.unwrap();
                assert_eq!(hdr.crypt_method, 1);
                assert!(hdr.is_encrypted());
            }
        }
    }

    #[test]
    fn parse_backing_file_size_boundary() {
        // 1023 accepted; 1024 refused ("Backing file name too long").
        let ok = HeaderSpec {
            backing_file_size: 1023,
            backing_file_offset: 4096,
            ..HeaderSpec::default()
        };
        let hdr = Qcow1Header::parse(&build_header(&ok)).unwrap();
        assert_eq!(hdr.backing_file_size, 1023);
        assert_eq!(hdr.backing_file_offset, 4096);

        let too_long = HeaderSpec {
            backing_file_size: 1024,
            ..HeaderSpec::default()
        };
        assert!(Qcow1Header::parse(&build_header(&too_long)).is_none());
    }

    #[test]
    fn parse_huge_size_boundary() {
        // The "Image too large" boundary at the header level, mirroring
        // compute_l1_size_boundary. cluster_bits=9, l2_bits=6 → shift=15.
        let span = 1u64 << 15;
        let max_ok = QCOW1_L1_SIZE_MAX * span;
        let ok = HeaderSpec {
            size: max_ok,
            cluster_bits: 9,
            l2_bits: 6,
            ..HeaderSpec::default()
        };
        let hdr = Qcow1Header::parse(&build_header(&ok)).unwrap();
        assert_eq!(hdr.l1_size, QCOW1_L1_SIZE_MAX);

        let too_big = HeaderSpec {
            size: max_ok + 1,
            cluster_bits: 9,
            l2_bits: 6,
            ..HeaderSpec::default()
        };
        assert!(Qcow1Header::parse(&build_header(&too_big)).is_none());
    }

    #[test]
    fn parse_ignores_mtime() {
        // mtime is unused; any value must be harmless.
        let spec = HeaderSpec {
            mtime: 0xdead_beef,
            ..HeaderSpec::default()
        };
        assert!(Qcow1Header::parse(&build_header(&spec)).is_some());
    }

    #[test]
    fn parse_tolerates_any_l1_table_offset() {
        // l1_table_offset is deliberately unvalidated: 0, unaligned, and
        // absurdly-past-EOF values all parse.
        for l1_table_offset in [0u64, 1, 7, 0xffff_ffff_ffff_f000] {
            let spec = HeaderSpec {
                l1_table_offset,
                ..HeaderSpec::default()
            };
            let hdr = Qcow1Header::parse(&build_header(&spec)).unwrap();
            assert_eq!(hdr.l1_table_offset, l1_table_offset);
        }
    }

    // ====================================================================
    // Compressed-entry decode (pure, no I/O)
    // ====================================================================

    #[test]
    fn compressed_entry_decode_example() {
        // The plan's empirically-verified example: entry 0x81d0000000002000
        // at cluster_bits=12 → host_offset 0x2000, csize 58. Exercised
        // through block_lookup via the mock image below; here we verify the
        // bit math directly against the qcow.c decompress_cluster formula.
        let entry = 0x81d0_0000_0000_2000u64;
        let cb = 12u32;
        let shift = 63 - cb; // 51
        let host_offset = entry & ((1u64 << shift) - 1);
        let csize = (entry >> shift) & ((1u64 << cb) - 1);
        assert_eq!(host_offset, 0x2000);
        assert_eq!(csize, 58);
    }

    // ====================================================================
    // Mock CallTable backed by an in-memory image
    // ====================================================================

    // The `read_input_sector` callback is an `extern "C" fn` and can only
    // close over `'static` state, so the mock image lives in a global buffer
    // guarded by a lock that serializes the table tests.
    const MOCK_LEN: usize = 64 * 1024;
    static MOCK_LOCK: Mutex<()> = Mutex::new(());
    static mut MOCK_IMAGE: [u8; MOCK_LEN] = [0u8; MOCK_LEN];

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

    /// One u64 BE entry to install at a byte offset in the mock image.
    struct Entry {
        byte_offset: usize,
        value: u64,
    }

    /// Install `header` at offset 0 and each `entry` (u64 BE) at its byte
    /// offset in the mock image, zeroing the rest. Returns a guard holding
    /// the lock for the duration of the test.
    fn install_image(header: &[u8; 512], entries: &[Entry]) -> std::sync::MutexGuard<'static, ()> {
        let guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let img = core::ptr::addr_of_mut!(MOCK_IMAGE) as *mut u8;
            core::ptr::write_bytes(img, 0, MOCK_LEN);
            core::ptr::copy_nonoverlapping(header.as_ptr(), img, 512);
            for e in entries {
                let bytes = e.value.to_be_bytes();
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), img.add(e.byte_offset), 8);
            }
        }
        guard
    }

    unsafe fn init_state(
        ct: &shared::CallTable,
        l1_buf: &mut [u8; MAX_SECTOR_SIZE],
        l2_buf: &mut [u8; MAX_SECTOR_SIZE],
        bytes_read: &mut u64,
    ) -> Option<Qcow1State> {
        Qcow1State::init(
            ct,
            0,
            512,
            (MOCK_LEN / 512) as u64,
            l1_buf.as_mut_ptr(),
            l2_buf.as_mut_ptr(),
            bytes_read,
        )
    }

    // ====================================================================
    // Qcow1State::init + block_lookup against the mock image
    // ====================================================================

    #[test]
    fn init_rejects_malformed_header() {
        let _guard = {
            let bad = HeaderSpec {
                magic: 0,
                ..HeaderSpec::default()
            };
            install_image(&build_header(&bad), &[])
        };
        let ct = stub_call_table();
        let mut l1_buf = [0u8; MAX_SECTOR_SIZE];
        let mut l2_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let state = unsafe { init_state(&ct, &mut l1_buf, &mut l2_buf, &mut bytes_read) };
        assert!(state.is_none());
    }

    #[test]
    fn init_refuses_encrypted_but_parse_accepts() {
        // crypt_method=1 parses (info needs the metadata) but the reader
        // refuses it at init.
        let spec = HeaderSpec {
            crypt_method: 1,
            ..HeaderSpec::default()
        };
        assert!(Qcow1Header::parse(&build_header(&spec)).is_some());

        let _guard = install_image(&build_header(&spec), &[]);
        let ct = stub_call_table();
        let mut l1_buf = [0u8; MAX_SECTOR_SIZE];
        let mut l2_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let state = unsafe { init_state(&ct, &mut l1_buf, &mut l2_buf, &mut bytes_read) };
        assert!(state.is_none());
    }

    /// The plan's populated-image lookup example: cluster_bits=12 (4 KiB
    /// clusters), l2_bits=9 (512 entries per L2 table). The single L1 table
    /// lives at l1_table_offset; l1[0] = 0x1000 points to an L2 table whose
    /// entries 0..15 are 0x2000, 0x3000, ... 0x11000. Each maps a 4 KiB
    /// guest cluster to the corresponding absolute host byte offset.
    #[test]
    fn block_lookup_populated_image() {
        let l1_table_offset = 0x800u64; // 2 KiB
        let l2_table_offset = 0x1000u64;
        let spec = HeaderSpec {
            cluster_bits: 12,
            l2_bits: 9,
            // 16 clusters * 4 KiB = 64 KiB virtual; shift = 21, span = 2 MiB
            // so l1_size = 1 (one L1 entry covers the whole image).
            size: 64 * 1024,
            l1_table_offset,
            ..HeaderSpec::default()
        };

        let mut entries = std::vec::Vec::new();
        // L1[0] -> L2 table at 0x1000.
        entries.push(Entry {
            byte_offset: l1_table_offset as usize,
            value: l2_table_offset,
        });
        // L2[0..15] = 0x2000, 0x3000, ... 0x11000.
        for i in 0..16u64 {
            entries.push(Entry {
                byte_offset: (l2_table_offset + i * 8) as usize,
                value: 0x2000 + i * 0x1000,
            });
        }
        let _guard = install_image(&build_header(&spec), &entries);

        let ct = stub_call_table();
        let mut l1_buf = [0u8; MAX_SECTOR_SIZE];
        let mut l2_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;
        let cluster = 4096u64;

        let mut state =
            unsafe { init_state(&ct, &mut l1_buf, &mut l2_buf, &mut bytes_read) }.unwrap();
        assert_eq!(state.l1_size, 1);

        for i in 0..16u64 {
            let l = unsafe { state.block_lookup(&ct, i * cluster, 512, cap, &mut bytes_read) };
            assert_eq!(
                l,
                Some(Qcow1BlockLookup::Allocated(0x2000 + i * 0x1000)),
                "cluster {i}"
            );
        }

        // In-cluster offset is added to the absolute host offset.
        let off = 0x123u64;
        let l = unsafe { state.block_lookup(&ct, cluster + off, 512, cap, &mut bytes_read) };
        assert_eq!(l, Some(Qcow1BlockLookup::Allocated(0x3000 + off)));
    }

    #[test]
    fn block_lookup_unallocated_l1_and_l2_and_out_of_range() {
        let l1_table_offset = 0x800u64;
        let l2_table_offset = 0x1000u64;
        let spec = HeaderSpec {
            cluster_bits: 12,
            l2_bits: 9,
            size: 64 * 1024,
            l1_table_offset,
            ..HeaderSpec::default()
        };
        // L1[0] -> L2 table; within it, cluster 0 is a hole (entry 0),
        // cluster 1 is allocated at 0x5000.
        let entries = [
            Entry {
                byte_offset: l1_table_offset as usize,
                value: l2_table_offset,
            },
            Entry {
                byte_offset: (l2_table_offset + 8) as usize,
                value: 0x5000,
            },
        ];
        let _guard = install_image(&build_header(&spec), &entries);

        let ct = stub_call_table();
        let mut l1_buf = [0u8; MAX_SECTOR_SIZE];
        let mut l2_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;
        let cluster = 4096u64;

        let mut state =
            unsafe { init_state(&ct, &mut l1_buf, &mut l2_buf, &mut bytes_read) }.unwrap();

        // Cluster 0 → L2 entry 0 → unallocated (defer to backing).
        let l0 = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert_eq!(l0, Some(Qcow1BlockLookup::Unallocated));

        // Cluster 1 → allocated at 0x5000.
        let l1 = unsafe { state.block_lookup(&ct, cluster, 512, cap, &mut bytes_read) };
        assert_eq!(l1, Some(Qcow1BlockLookup::Allocated(0x5000)));

        // An offset whose L1 index is >= l1_size (1) is out of range → the
        // whole image is only one L1 entry wide (2 MiB); an offset at 2 MiB
        // lands in L1 index 1 → unallocated.
        let past = unsafe { state.block_lookup(&ct, 2 * 1024 * 1024, 512, cap, &mut bytes_read) };
        assert_eq!(past, Some(Qcow1BlockLookup::Unallocated));
    }

    #[test]
    fn block_lookup_unallocated_when_l1_entry_zero() {
        // L1 table present but L1[0] == 0 → the L2 table is absent, so the
        // cluster is unallocated regardless of what lies at offset 0.
        let l1_table_offset = 0x800u64;
        let spec = HeaderSpec {
            cluster_bits: 12,
            l2_bits: 9,
            size: 64 * 1024,
            l1_table_offset,
            ..HeaderSpec::default()
        };
        // No entries → L1[0] reads as 0.
        let _guard = install_image(&build_header(&spec), &[]);

        let ct = stub_call_table();
        let mut l1_buf = [0u8; MAX_SECTOR_SIZE];
        let mut l2_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;

        let mut state =
            unsafe { init_state(&ct, &mut l1_buf, &mut l2_buf, &mut bytes_read) }.unwrap();

        let l = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert_eq!(l, Some(Qcow1BlockLookup::Unallocated));
    }

    #[test]
    fn block_lookup_compressed_entry() {
        // The plan's empirical compressed entry through the full walk:
        // L2 entry 0x81d0000000002000 at cluster_bits=12 → host_offset
        // 0x2000, csize 58.
        let l1_table_offset = 0x800u64;
        let l2_table_offset = 0x1000u64;
        let spec = HeaderSpec {
            cluster_bits: 12,
            l2_bits: 9,
            size: 64 * 1024,
            l1_table_offset,
            ..HeaderSpec::default()
        };
        let entries = [
            Entry {
                byte_offset: l1_table_offset as usize,
                value: l2_table_offset,
            },
            Entry {
                byte_offset: l2_table_offset as usize,
                value: 0x81d0_0000_0000_2000,
            },
        ];
        let _guard = install_image(&build_header(&spec), &entries);

        let ct = stub_call_table();
        let mut l1_buf = [0u8; MAX_SECTOR_SIZE];
        let mut l2_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;

        let mut state =
            unsafe { init_state(&ct, &mut l1_buf, &mut l2_buf, &mut bytes_read) }.unwrap();

        let l = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert_eq!(
            l,
            Some(Qcow1BlockLookup::Compressed {
                host_offset: 0x2000,
                csize: 58,
            })
        );
    }

    #[test]
    fn block_lookup_allows_past_eof_host_offset() {
        // An allocated entry whose host offset lands past the mock image
        // length must NOT be rejected — past-EOF classification is the
        // caller's job (qemu zero-fills). The L1/L2 entries themselves live
        // in-range and read fine.
        let l1_table_offset = 0x800u64;
        let l2_table_offset = 0x1000u64;
        let spec = HeaderSpec {
            cluster_bits: 12,
            l2_bits: 9,
            size: 64 * 1024,
            l1_table_offset,
            ..HeaderSpec::default()
        };
        let far = 0x0010_0000_0000u64; // 1 TiB, far past the 64 KiB mock.
        let entries = [
            Entry {
                byte_offset: l1_table_offset as usize,
                value: l2_table_offset,
            },
            Entry {
                byte_offset: l2_table_offset as usize,
                value: far,
            },
        ];
        let _guard = install_image(&build_header(&spec), &entries);

        let ct = stub_call_table();
        let mut l1_buf = [0u8; MAX_SECTOR_SIZE];
        let mut l2_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;

        let mut state =
            unsafe { init_state(&ct, &mut l1_buf, &mut l2_buf, &mut bytes_read) }.unwrap();

        let l = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert_eq!(l, Some(Qcow1BlockLookup::Allocated(far)));
    }

    #[test]
    fn block_lookup_fails_when_l2_table_unreadable() {
        // L1[0] points the L2 table past the mock capacity; the L2 sector
        // read then fails and the lookup surfaces None (the 4b reader arm
        // maps that policy — 4a mirrors the parallels None-on-read-failure
        // shape).
        let l1_table_offset = 0x800u64;
        let l2_table_offset = (MOCK_LEN as u64) + 512; // past EOF
        let spec = HeaderSpec {
            cluster_bits: 12,
            l2_bits: 9,
            size: 64 * 1024,
            l1_table_offset,
            ..HeaderSpec::default()
        };
        let entries = [Entry {
            byte_offset: l1_table_offset as usize,
            value: l2_table_offset,
        }];
        let _guard = install_image(&build_header(&spec), &entries);

        let ct = stub_call_table();
        let mut l1_buf = [0u8; MAX_SECTOR_SIZE];
        let mut l2_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;

        let mut state =
            unsafe { init_state(&ct, &mut l1_buf, &mut l2_buf, &mut bytes_read) }.unwrap();

        let l = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert!(l.is_none());
    }

    #[test]
    fn block_lookup_small_cluster_walk() {
        // create-with-backing uses cluster_bits=9 (512-byte clusters),
        // l2_bits=12 (4096 entries). Exercise the small-cluster L2 index
        // math: with cluster_bits=9, l2_index = (offset >> 9) & 4095.
        let l1_table_offset = 0x800u64;
        let l2_table_offset = 0x1000u64;
        let spec = HeaderSpec {
            cluster_bits: 9,
            l2_bits: 12,
            // shift = 9 + 12 = 21, span = 2 MiB, so one L1 entry.
            size: 2 * 1024 * 1024,
            l1_table_offset,
            ..HeaderSpec::default()
        };
        // Cluster 3 (offset 3*512) → L2 index 3 → host 0x9000.
        let entries = [
            Entry {
                byte_offset: l1_table_offset as usize,
                value: l2_table_offset,
            },
            Entry {
                byte_offset: (l2_table_offset + 3 * 8) as usize,
                value: 0x9000,
            },
        ];
        let _guard = install_image(&build_header(&spec), &entries);

        let ct = stub_call_table();
        let mut l1_buf = [0u8; MAX_SECTOR_SIZE];
        let mut l2_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;

        let mut state =
            unsafe { init_state(&ct, &mut l1_buf, &mut l2_buf, &mut bytes_read) }.unwrap();
        assert_eq!(state.cluster_size, 512);
        assert_eq!(state.l2_size, 4096);

        // Cluster 0 (offset 0) → L2 entry 0 → unallocated.
        let l0 = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert_eq!(l0, Some(Qcow1BlockLookup::Unallocated));

        // Cluster 3 (offset 1536) → host 0x9000, plus in-cluster offset.
        let off = 0x40u64;
        let l3 = unsafe { state.block_lookup(&ct, 3 * 512 + off, 512, cap, &mut bytes_read) };
        assert_eq!(l3, Some(Qcow1BlockLookup::Allocated(0x9000 + off)));
    }
}
