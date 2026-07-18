//! Parallels (`WithoutFreeSpace`) format parsing.
//!
//! Provides Parallels header parsing and block-allocation-table (BAT)
//! lookup for the convert / compare / dd read path. Mirrors qemu's
//! `block/parallels.c` read-only open-time validation and read semantics
//! exactly: the header is validated with the same magic/version/tracks/
//! catalog checks qemu applies on the RO path, `inuse`-dirty images are
//! accepted (qemu opens them read-only), `data_off` is parsed but never
//! used by reads, and BAT lookups never reject host offsets past
//! end-of-file — qemu performs no file-length or BAT-vs-`nb_sectors`
//! consistency check and zero-fills past-EOF reads, so that
//! classification is left to the chain reader.
//!
//! One deliberate divergence from qemu: an image with a non-zero
//! `ext_off` (a format-extension pointer, used for dirty bitmaps) is
//! refused at parse time. qemu would parse the extension on the RO path;
//! instar refuses until a real need appears (see `parse`).

#![no_std]
#![allow(clippy::too_many_arguments)]

use shared::{le_u32, le_u64, CallTable, MAX_SECTOR_SIZE};

// The two magic strings and the mandatory version live in the shared
// format-detection module (they are also used by format detection); reuse
// them rather than redefining. `PARALLELS_MAGIC_V2` in `shared` is the
// extended ("WithouFreSpacExt") magic — this crate uses the "v1"/"ext"
// terminology from qemu, where "ext" == shared's V2.
use shared::format_detection::{
    PARALLELS_MAGIC_V1, PARALLELS_MAGIC_V2 as PARALLELS_MAGIC_EXT, PARALLELS_VERSION,
};

// ============================================================================
// Parallels header field offsets (all little-endian)
// ============================================================================

/// Header size in bytes. The BAT (u32 LE entries) begins immediately at
/// this offset.
pub const HEADER_SIZE: usize = 64;

/// Magic offset (16 bytes): `WithoutFreeSpace` (v1) or `WithouFreSpacExt`
/// (ext), not NUL-terminated.
pub const MAGIC_OFFSET: usize = 0;
/// Version offset (u32 LE): must be 2.
pub const VERSION_OFFSET: usize = 16;
/// Heads offset (u32 LE): geometry, unused by the reader.
pub const HEADS_OFFSET: usize = 20;
/// Cylinders offset (u32 LE): geometry, unused by the reader.
pub const CYLINDERS_OFFSET: usize = 24;
/// Tracks offset (u32 LE): sectors per cluster; `cluster_size = tracks << 9`.
pub const TRACKS_OFFSET: usize = 28;
/// BAT entry count offset (u32 LE).
pub const BAT_ENTRIES_OFFSET: usize = 32;
/// Virtual size in sectors offset (u64 LE, UNALIGNED at 36): under the v1
/// magic only the low 32 bits are honoured, under the ext magic all 64.
pub const NB_SECTORS_OFFSET: usize = 36;
/// In-use flag offset (u32 LE): `0x746f6e59` = opened-dirty. Stored but
/// never gated on — dirty images are readable read-only.
pub const INUSE_OFFSET: usize = 44;
/// Data offset (u32 LE, in sectors): the write-path allocation frontier;
/// irrelevant to reads (parsed but unused).
pub const DATA_OFF_OFFSET: usize = 48;
/// Flags offset (u32 LE): unused by the reader.
pub const FLAGS_OFFSET: usize = 52;
/// Format-extension offset (u64 LE, in sectors): 0 = none. A non-zero
/// value is refused (see `parse`).
pub const EXT_OFF_OFFSET: usize = 56;

// ============================================================================
// Parallels constants
// ============================================================================

/// Maximum `tracks` (sectors per cluster) qemu will open: `INT32_MAX / 513`.
/// Anything larger is "Invalid image: Too big cluster".
pub const PARALLELS_TRACKS_MAX: u32 = 4_185_446;

/// Maximum BAT entry count qemu will open: `INT_MAX / 4`. Anything larger
/// is "Catalog too large".
pub const PARALLELS_BAT_ENTRIES_MAX: u32 = 0x3fff_ffff;

/// `inuse` sentinel for an image opened dirty (`"Yno t"` little-endian).
/// Read-only opens succeed regardless; the reader stores this but never
/// refuses on it.
pub const PARALLELS_INUSE_DIRTY: u32 = 0x746f_6e59;

/// Number of bytes per sector, the unit `off_multiplier` and BAT values
/// are scaled by.
pub const SECTOR_BYTES: u64 = 512;

// ============================================================================
// Parallels header parsing
// ============================================================================

/// Parsed Parallels header fields the read path needs.
///
/// `off_multiplier` and `virtual_size` already fold in the per-magic
/// behaviour (see [`ParallelsHeader::parse`]); all sizes are in bytes.
pub struct ParallelsHeader {
    /// True for the `WithoutFreeSpace` (v1) magic, false for the
    /// `WithouFreSpacExt` (ext) magic. Discriminates the two decode
    /// behaviours below.
    pub is_v1: bool,
    /// Sectors per cluster (`tracks`).
    pub tracks: u32,
    /// BAT entry count.
    pub bat_entries: u32,
    /// Cluster size in bytes (`tracks << 9`).
    pub cluster_size: u64,
    /// Virtual disk size in bytes (`nb_sectors * 512`), with `nb_sectors`
    /// masked to its low 32 bits under the v1 magic.
    pub virtual_size: u64,
    /// BAT-value multiplier: 1 under the v1 magic (BAT values are sector
    /// numbers), `tracks` under the ext magic (BAT values are cluster
    /// indices).
    pub off_multiplier: u32,
    /// In-use (dirty) flag, stored verbatim; never gated on.
    pub inuse: u32,
    /// Data offset in sectors, parsed but unused by reads (write-path
    /// allocation frontier only).
    pub data_off: u32,
}

impl ParallelsHeader {
    /// Parse and validate a Parallels header from raw bytes.
    ///
    /// Enforces qemu `parallels_open`'s read-only open-time checks with
    /// the same limits: the magic must be one of the two known strings AND
    /// the version must be 2; `tracks` must be non-zero and at most
    /// [`PARALLELS_TRACKS_MAX`]; `bat_entries` must be at most
    /// [`PARALLELS_BAT_ENTRIES_MAX`]. Additionally, a non-zero `ext_off`
    /// is refused — a deliberate, documented divergence from qemu, which
    /// parses the format extension on the RO path (dirty bitmaps); instar
    /// refuses until a real need appears, since no shipped or creatable
    /// fixture sets it and silently ignoring it risks misreading images
    /// whose extensions matter.
    ///
    /// `inuse`-dirty images are accepted (qemu opens them RO); `data_off`
    /// is parsed but never used; there is NO `data_off` validation and NO
    /// BAT-vs-`nb_sectors` consistency check. Returns `None` if the buffer
    /// is too small or any check fails (including arithmetic overflow of
    /// the derived sizes).
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }

        let magic = &buf[MAGIC_OFFSET..MAGIC_OFFSET + 16];
        let is_v1 = magic == PARALLELS_MAGIC_V1;
        let is_ext = magic == PARALLELS_MAGIC_EXT;
        if !is_v1 && !is_ext {
            return None;
        }

        let version = le_u32(buf, VERSION_OFFSET);
        if version != PARALLELS_VERSION {
            return None;
        }

        let tracks = le_u32(buf, TRACKS_OFFSET);
        if tracks == 0 {
            return None;
        }
        if tracks > PARALLELS_TRACKS_MAX {
            return None;
        }

        let bat_entries = le_u32(buf, BAT_ENTRIES_OFFSET);
        if bat_entries > PARALLELS_BAT_ENTRIES_MAX {
            return None;
        }

        // Deliberate divergence from qemu: refuse format extensions
        // (ext_off in sectors, 0 == none) rather than parse them RO.
        let ext_off = le_u64(buf, EXT_OFF_OFFSET);
        if ext_off != 0 {
            return None;
        }

        // nb_sectors is masked to its low 32 bits under the v1 magic and
        // used at full width under the ext magic (byte-verified: the same
        // field reads 2 MiB under v1 and 2 TiB under ext).
        let raw_nb_sectors = le_u64(buf, NB_SECTORS_OFFSET);
        let nb_sectors = if is_v1 {
            raw_nb_sectors & 0xffff_ffff
        } else {
            raw_nb_sectors
        };
        let virtual_size = nb_sectors.checked_mul(SECTOR_BYTES)?;

        // cluster_size = tracks << 9. The tracks cap above guarantees this
        // cannot overflow, but keep it checked for idiom parity.
        let cluster_size = (tracks as u64).checked_mul(SECTOR_BYTES)?;

        // BAT values are sector numbers under v1 (multiplier 1) and cluster
        // indices under ext (multiplier tracks).
        let off_multiplier = if is_v1 { 1 } else { tracks };

        let inuse = le_u32(buf, INUSE_OFFSET);
        let data_off = le_u32(buf, DATA_OFF_OFFSET);

        Some(ParallelsHeader {
            is_v1,
            tracks,
            bat_entries,
            cluster_size,
            virtual_size,
            off_multiplier,
            inuse,
            data_off,
        })
    }

    /// True if the image was left opened-dirty. Informational only: the
    /// read path treats dirty and clean images identically (qemu opens
    /// dirty images read-only).
    pub fn is_dirty(&self) -> bool {
        self.inuse == PARALLELS_INUSE_DIRTY
    }
}

// ============================================================================
// Block lookup result
// ============================================================================

/// Result of looking up a virtual offset in the Parallels BAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParallelsBlockLookup {
    /// The cluster is not allocated (BAT value 0, or the offset is beyond
    /// BAT coverage); reads as zeros. A Parallels image can never have a
    /// lower device in the chain, so the caller zero-fills.
    Unallocated,
    /// The cluster is allocated at the given host byte offset.
    Allocated { host_byte_offset: u64 },
}

// ============================================================================
// Parallels state for BAT I/O
// ============================================================================

/// Runtime state for reading Parallels clusters from a device.
///
/// Analogous to `vdi::VdiState`. Maintains a sector cache for BAT reads;
/// the second cache buffer mirrors the VDI/VHD state layout for a uniform
/// init signature and is unused by the BAT walk.
pub struct ParallelsState {
    pub device_idx: u32,
    pub cluster_size: u64,
    pub bat_entries: u32,
    pub off_multiplier: u64,
    pub virtual_size: u64,
    // Sector cache for BAT reads.
    pub bat_cached_sector: u64,
    pub bat_cache_buf: *mut u8,
    // Second cache buffer, held for init-signature parity with VdiState.
    pub data_cached_sector: u64,
    pub data_cache_buf: *mut u8,
}

impl ParallelsState {
    /// Initialize Parallels state by reading and validating the header.
    ///
    /// Reads the first sector (the 64-byte header lives at offset 0),
    /// validates it via [`ParallelsHeader::parse`], and checks that the
    /// BAT region address arithmetic is sound (no overflow). Per qemu, the
    /// BAT is NOT required to fit within `input_capacity` — file length is
    /// never validated.
    ///
    /// Returns `None` if the header is invalid, the header sector read
    /// fails, or BAT region addressing would overflow.
    ///
    /// # Safety
    ///
    /// `bat_cache_buf` and `data_cache_buf` must each point to at least
    /// `MAX_SECTOR_SIZE` writable bytes. `call_table` must be valid.
    pub unsafe fn init(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        bat_cache_buf: *mut u8,
        data_cache_buf: *mut u8,
        bytes_read: &mut u64,
    ) -> Option<Self> {
        let _ = input_capacity;

        let mut header_sector = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(device_idx, 0, header_sector.as_mut_ptr(), sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;

        let header = ParallelsHeader::parse(&header_sector)?;

        // Ensure the BAT region (64 + entries*4, rounded up to a sector
        // boundary) is arithmetically sound. This does NOT require the
        // region to lie within the file — qemu never checks.
        let bat_bytes = (header.bat_entries as u64).checked_mul(4)?;
        let bat_end = (HEADER_SIZE as u64).checked_add(bat_bytes)?;
        bat_end.checked_add(sector_size as u64 - 1)?;

        Some(ParallelsState {
            device_idx,
            cluster_size: header.cluster_size,
            bat_entries: header.bat_entries,
            off_multiplier: header.off_multiplier as u64,
            virtual_size: header.virtual_size,
            bat_cached_sector: u64::MAX,
            bat_cache_buf,
            data_cached_sector: u64::MAX,
            data_cache_buf,
        })
    }

    /// Look up the host location for a given virtual byte offset.
    ///
    /// Reads the BAT entry for the containing cluster. A cluster index at
    /// or beyond `bat_entries`, or a BAT value of 0, maps to
    /// [`ParallelsBlockLookup::Unallocated`]; any other value `v` gives
    /// host offset `v * off_multiplier * 512 + offset_in_cluster`
    /// (`off_multiplier` folds in the per-magic sector-vs-cluster
    /// distinction). Host offsets past `input_capacity` are NOT rejected —
    /// the caller zero-fills past-EOF reads.
    ///
    /// Returns `None` only if the BAT sector read itself fails or offset
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
    ) -> Option<ParallelsBlockLookup> {
        let cluster_idx = virtual_offset / self.cluster_size;

        if cluster_idx >= self.bat_entries as u64 {
            return Some(ParallelsBlockLookup::Unallocated);
        }

        let entry_offset = (HEADER_SIZE as u64).checked_add(cluster_idx.checked_mul(4)?)?;

        let entry = read_u32_le_cached(
            call_table,
            self.device_idx,
            entry_offset,
            sector_size,
            input_capacity,
            &mut self.bat_cached_sector,
            self.bat_cache_buf,
            bytes_read,
        )?;

        if entry == 0 {
            return Some(ParallelsBlockLookup::Unallocated);
        }

        let offset_in_cluster = virtual_offset % self.cluster_size;
        let host_byte_offset = (entry as u64)
            .checked_mul(self.off_multiplier)?
            .checked_mul(SECTOR_BYTES)?
            .checked_add(offset_in_cluster)?;

        Some(ParallelsBlockLookup::Allocated { host_byte_offset })
    }
}

// ============================================================================
// Cached sector read helper (little-endian u32)
// ============================================================================

shared::cached_read!(read_u32_le_cached, u32, le, 4);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use shared::{write_le_u32, write_le_u64};
    use std::sync::Mutex;

    // ====================================================================
    // Header builder
    // ====================================================================

    /// Fields for building a synthetic, otherwise-valid Parallels header.
    /// Every field defaults to a value that passes validation; individual
    /// tests mutate the one field under test.
    struct HeaderSpec {
        magic: [u8; 16],
        version: u32,
        tracks: u32,
        bat_entries: u32,
        nb_sectors: u64,
        inuse: u32,
        data_off: u32,
        ext_off: u64,
    }

    impl Default for HeaderSpec {
        fn default() -> Self {
            // ext magic, tracks=128 (64 KiB clusters), 4 BAT entries,
            // 2 MiB virtual (4096 sectors): a minimal valid header.
            HeaderSpec {
                magic: PARALLELS_MAGIC_EXT,
                version: PARALLELS_VERSION,
                tracks: 128,
                bat_entries: 4,
                nb_sectors: 4096,
                inuse: 0,
                data_off: 0,
                ext_off: 0,
            }
        }
    }

    fn build_header(spec: &HeaderSpec) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[MAGIC_OFFSET..MAGIC_OFFSET + 16].copy_from_slice(&spec.magic);
        write_le_u32(&mut buf, VERSION_OFFSET, spec.version);
        write_le_u32(&mut buf, TRACKS_OFFSET, spec.tracks);
        write_le_u32(&mut buf, BAT_ENTRIES_OFFSET, spec.bat_entries);
        write_le_u64(&mut buf, NB_SECTORS_OFFSET, spec.nb_sectors);
        write_le_u32(&mut buf, INUSE_OFFSET, spec.inuse);
        write_le_u32(&mut buf, DATA_OFF_OFFSET, spec.data_off);
        write_le_u64(&mut buf, EXT_OFF_OFFSET, spec.ext_off);
        buf
    }

    // ====================================================================
    // ParallelsHeader::parse — acceptance and per-rule rejection
    // ====================================================================

    #[test]
    fn parse_valid_ext_header() {
        let buf = build_header(&HeaderSpec::default());
        let hdr = ParallelsHeader::parse(&buf).unwrap();
        assert!(!hdr.is_v1);
        assert_eq!(hdr.tracks, 128);
        assert_eq!(hdr.bat_entries, 4);
        assert_eq!(hdr.cluster_size, 65536);
        assert_eq!(hdr.virtual_size, 2 * 1024 * 1024);
        // ext magic: BAT values are cluster indices, multiplier == tracks.
        assert_eq!(hdr.off_multiplier, 128);
    }

    #[test]
    fn parse_valid_v1_header() {
        let spec = HeaderSpec {
            magic: PARALLELS_MAGIC_V1,
            ..HeaderSpec::default()
        };
        let hdr = ParallelsHeader::parse(&build_header(&spec)).unwrap();
        assert!(hdr.is_v1);
        // v1 magic: BAT values are sector numbers, multiplier == 1.
        assert_eq!(hdr.off_multiplier, 1);
    }

    #[test]
    fn parse_accepts_both_magics_rejects_garbage() {
        for magic in [PARALLELS_MAGIC_V1, PARALLELS_MAGIC_EXT] {
            let spec = HeaderSpec {
                magic,
                ..HeaderSpec::default()
            };
            assert!(ParallelsHeader::parse(&build_header(&spec)).is_some());
        }
        let spec = HeaderSpec {
            magic: *b"NotAParallels!!!",
            ..HeaderSpec::default()
        };
        assert!(ParallelsHeader::parse(&build_header(&spec)).is_none());
    }

    #[test]
    fn parse_short_buffer() {
        assert!(ParallelsHeader::parse(&[0u8; 63]).is_none());
        assert!(ParallelsHeader::parse(&[0u8; 0]).is_none());
    }

    #[test]
    fn parse_version_boundaries() {
        // Only version 2 is accepted.
        for (version, ok) in [(1u32, false), (2, true), (3, false)] {
            let spec = HeaderSpec {
                version,
                ..HeaderSpec::default()
            };
            assert_eq!(
                ParallelsHeader::parse(&build_header(&spec)).is_some(),
                ok,
                "version {version}"
            );
        }
    }

    #[test]
    fn parse_tracks_boundaries() {
        // 0 rejected; 1 and the max accepted; one past the max rejected.
        for (tracks, ok) in [
            (0u32, false),
            (1, true),
            (PARALLELS_TRACKS_MAX, true),
            (PARALLELS_TRACKS_MAX + 1, false),
        ] {
            let spec = HeaderSpec {
                tracks,
                ..HeaderSpec::default()
            };
            assert_eq!(
                ParallelsHeader::parse(&build_header(&spec)).is_some(),
                ok,
                "tracks {tracks}"
            );
        }
    }

    #[test]
    fn parse_bat_entries_boundaries() {
        // At the max accepted; one past it rejected.
        let at_max = HeaderSpec {
            bat_entries: PARALLELS_BAT_ENTRIES_MAX,
            ..HeaderSpec::default()
        };
        assert!(ParallelsHeader::parse(&build_header(&at_max)).is_some());

        let over_max = HeaderSpec {
            bat_entries: PARALLELS_BAT_ENTRIES_MAX + 1,
            ..HeaderSpec::default()
        };
        assert!(ParallelsHeader::parse(&build_header(&over_max)).is_none());
    }

    #[test]
    fn parse_ext_off_zero_accepted_nonzero_refused() {
        let zero = HeaderSpec {
            ext_off: 0,
            ..HeaderSpec::default()
        };
        assert!(ParallelsHeader::parse(&build_header(&zero)).is_some());

        // Deliberate divergence from qemu, which parses the extension RO.
        let nonzero = HeaderSpec {
            ext_off: 1,
            ..HeaderSpec::default()
        };
        assert!(ParallelsHeader::parse(&build_header(&nonzero)).is_none());
    }

    #[test]
    fn parse_accepts_inuse_dirty() {
        // A dirty image opens read-only in qemu; parse must not refuse it.
        let spec = HeaderSpec {
            inuse: PARALLELS_INUSE_DIRTY,
            ..HeaderSpec::default()
        };
        let hdr = ParallelsHeader::parse(&build_header(&spec)).unwrap();
        assert_eq!(hdr.inuse, PARALLELS_INUSE_DIRTY);
        assert!(hdr.is_dirty());
    }

    #[test]
    fn parse_ignores_data_off_garbage() {
        // data_off is the write-path frontier; any value must be harmless.
        let spec = HeaderSpec {
            data_off: 0xdead_beef,
            ..HeaderSpec::default()
        };
        let hdr = ParallelsHeader::parse(&build_header(&spec)).unwrap();
        assert_eq!(hdr.data_off, 0xdead_beef);
    }

    #[test]
    fn parse_nb_sectors_masking_by_magic() {
        // The plan's verified case: nb_sectors = 0x1_0000_1000 reads as
        // 2 MiB under the v1 magic (masked to the low 32 bits = 0x1000
        // sectors) and 2 TiB under the ext magic (full 64 bits).
        let nb_sectors = 0x1_0000_1000u64;

        let v1 = HeaderSpec {
            magic: PARALLELS_MAGIC_V1,
            nb_sectors,
            ..HeaderSpec::default()
        };
        let hdr_v1 = ParallelsHeader::parse(&build_header(&v1)).unwrap();
        assert_eq!(hdr_v1.virtual_size, 2 * 1024 * 1024);

        let ext = HeaderSpec {
            magic: PARALLELS_MAGIC_EXT,
            nb_sectors,
            ..HeaderSpec::default()
        };
        let hdr_ext = ParallelsHeader::parse(&build_header(&ext)).unwrap();
        // Full 64-bit width: 0x1_0000_1000 sectors * 512 ≈ 2 TiB (exactly
        // 2 TiB + 2 MiB, since the low 0x1000 sectors are no longer masked
        // away as they are under v1).
        assert_eq!(hdr_ext.virtual_size, nb_sectors * 512);
        assert_eq!(
            hdr_ext.virtual_size,
            2 * 1024 * 1024 * 1024 * 1024 + 2 * 1024 * 1024
        );
    }

    #[test]
    fn parse_rejects_virtual_size_overflow() {
        // Under the ext magic nb_sectors is used at full width; a value
        // whose byte size overflows u64 must be refused, not truncated.
        let spec = HeaderSpec {
            magic: PARALLELS_MAGIC_EXT,
            nb_sectors: u64::MAX,
            ..HeaderSpec::default()
        };
        assert!(ParallelsHeader::parse(&build_header(&spec)).is_none());
    }

    #[test]
    fn parse_cluster_size_math() {
        // cluster_size = tracks << 9.
        for (tracks, cluster_size) in [(128u32, 65536u64), (2048, 1024 * 1024), (8, 4096)] {
            let spec = HeaderSpec {
                tracks,
                ..HeaderSpec::default()
            };
            let hdr = ParallelsHeader::parse(&build_header(&spec)).unwrap();
            assert_eq!(hdr.cluster_size, cluster_size, "tracks {tracks}");
        }
        // The tracks cap is what guards cluster_size against overflow: any
        // value large enough to overflow tracks << 9 is refused by the
        // tracks-limit check before cluster_size is ever computed.
        let overflow = HeaderSpec {
            tracks: PARALLELS_TRACKS_MAX + 1,
            ..HeaderSpec::default()
        };
        assert!(ParallelsHeader::parse(&build_header(&overflow)).is_none());
    }

    // ====================================================================
    // Mock CallTable backed by an in-memory image
    // ====================================================================

    // The `read_input_sector` callback is an `extern "C" fn` and can only
    // close over `'static` state, so the mock image lives in a global
    // buffer guarded by a lock that serializes the BAT tests.
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

    /// Install `header` at offset 0 and `bat` (u32 LE entries) at offset
    /// [`HEADER_SIZE`] in the mock image, zeroing the rest. Returns a guard
    /// holding the lock for the duration of the test.
    fn install_image(header: &[u8; 512], bat: &[u32]) -> std::sync::MutexGuard<'static, ()> {
        let guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let img = core::ptr::addr_of_mut!(MOCK_IMAGE) as *mut u8;
            core::ptr::write_bytes(img, 0, MOCK_LEN);
            core::ptr::copy_nonoverlapping(header.as_ptr(), img, 512);
            for (i, &entry) in bat.iter().enumerate() {
                let off = HEADER_SIZE + i * 4;
                let bytes = entry.to_le_bytes();
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), img.add(off), 4);
            }
        }
        guard
    }

    /// Init a `ParallelsState` from the mock image (caller must hold the
    /// lock via `install_image`).
    unsafe fn init_state(
        ct: &shared::CallTable,
        bat_buf: &mut [u8; MAX_SECTOR_SIZE],
        data_buf: &mut [u8; MAX_SECTOR_SIZE],
        bytes_read: &mut u64,
    ) -> Option<ParallelsState> {
        ParallelsState::init(
            ct,
            0,
            512,
            (MOCK_LEN / 512) as u64,
            bat_buf.as_mut_ptr(),
            data_buf.as_mut_ptr(),
            bytes_read,
        )
    }

    // ====================================================================
    // ParallelsState::init + block_lookup against the mock image
    // ====================================================================

    #[test]
    fn init_rejects_malformed_header() {
        let _guard = {
            let bad = HeaderSpec {
                magic: [0u8; 16],
                ..HeaderSpec::default()
            };
            install_image(&build_header(&bad), &[])
        };
        let ct = stub_call_table();
        let mut bat_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let state = unsafe { init_state(&ct, &mut bat_buf, &mut data_buf, &mut bytes_read) };
        assert!(state.is_none());
    }

    /// The per-magic BAT decoding equivalence — the phase's central
    /// gotcha. With tracks=128, the v1 BAT `[0x80,0x100,0x180,0x200]`
    /// (sector numbers) and the ext BAT `[1,2,3,4]` (cluster indices) must
    /// decode to the identical host offsets 0x10000/0x20000/0x30000/
    /// 0x40000 at in-cluster offset 0 (the empirical fixture values).
    #[test]
    fn block_lookup_per_magic_equivalence() {
        let expected = [0x10000u64, 0x20000, 0x30000, 0x40000];
        // v1: BAT values are sector numbers (multiplier 1).
        // ext: BAT values are cluster indices (multiplier tracks=128).
        let cases: [([u8; 16], [u32; 4]); 2] = [
            (PARALLELS_MAGIC_V1, [0x80, 0x100, 0x180, 0x200]),
            (PARALLELS_MAGIC_EXT, [1, 2, 3, 4]),
        ];

        for (magic, bat) in cases {
            let spec = HeaderSpec {
                magic,
                tracks: 128,
                bat_entries: 4,
                ..HeaderSpec::default()
            };
            let _guard = install_image(&build_header(&spec), &bat);

            let ct = stub_call_table();
            let mut bat_buf = [0u8; MAX_SECTOR_SIZE];
            let mut data_buf = [0u8; MAX_SECTOR_SIZE];
            let mut bytes_read = 0u64;
            let cap = (MOCK_LEN / 512) as u64;
            let cluster = 65536u64;

            let mut state =
                unsafe { init_state(&ct, &mut bat_buf, &mut data_buf, &mut bytes_read) }.unwrap();

            for (i, &want) in expected.iter().enumerate() {
                let virtual_offset = i as u64 * cluster;
                let l =
                    unsafe { state.block_lookup(&ct, virtual_offset, 512, cap, &mut bytes_read) };
                assert_eq!(
                    l,
                    Some(ParallelsBlockLookup::Allocated {
                        host_byte_offset: want,
                    }),
                    "magic {magic:?} cluster {i}"
                );
            }
        }
    }

    #[test]
    fn block_lookup_sentinel_and_non_contiguous() {
        // ext magic, tracks=128: BAT [0, 2, 0, 1] — a hole, then a
        // non-identity allocation order (cluster 1 → entry 2 → 0x20000,
        // cluster 3 → entry 1 → 0x10000), with cluster 2 a second hole.
        let spec = HeaderSpec {
            tracks: 128,
            bat_entries: 4,
            ..HeaderSpec::default()
        };
        let bat = [0u32, 2, 0, 1];
        let _guard = install_image(&build_header(&spec), &bat);

        let ct = stub_call_table();
        let mut bat_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;
        let cluster = 65536u64;

        let mut state =
            unsafe { init_state(&ct, &mut bat_buf, &mut data_buf, &mut bytes_read) }.unwrap();

        // Cluster 0 → BAT value 0 → unallocated.
        let l0 = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert_eq!(l0, Some(ParallelsBlockLookup::Unallocated));

        // Cluster 1 → entry 2 → 2 * 128 * 512 = 0x20000, plus in-cluster
        // offset 0x1234.
        let off = 0x1234u64;
        let l1 = unsafe { state.block_lookup(&ct, cluster + off, 512, cap, &mut bytes_read) };
        assert_eq!(
            l1,
            Some(ParallelsBlockLookup::Allocated {
                host_byte_offset: 0x20000 + off,
            })
        );

        // Cluster 2 → BAT value 0 → unallocated.
        let l2 = unsafe { state.block_lookup(&ct, 2 * cluster, 512, cap, &mut bytes_read) };
        assert_eq!(l2, Some(ParallelsBlockLookup::Unallocated));

        // Cluster 3 → entry 1 → 0x10000.
        let l3 = unsafe { state.block_lookup(&ct, 3 * cluster, 512, cap, &mut bytes_read) };
        assert_eq!(
            l3,
            Some(ParallelsBlockLookup::Allocated {
                host_byte_offset: 0x10000,
            })
        );
    }

    #[test]
    fn block_lookup_cluster_idx_beyond_bat() {
        // A virtual offset in a cluster at or beyond bat_entries is not
        // covered by the BAT, so it reads as zeros.
        let spec = HeaderSpec {
            tracks: 128,
            bat_entries: 4,
            ..HeaderSpec::default()
        };
        let _guard = install_image(&build_header(&spec), &[1, 2, 3, 4]);

        let ct = stub_call_table();
        let mut bat_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;
        let cluster = 65536u64;

        let mut state =
            unsafe { init_state(&ct, &mut bat_buf, &mut data_buf, &mut bytes_read) }.unwrap();

        // Cluster index 4 == bat_entries → beyond coverage.
        let l = unsafe { state.block_lookup(&ct, 4 * cluster, 512, cap, &mut bytes_read) };
        assert_eq!(l, Some(ParallelsBlockLookup::Unallocated));
    }

    #[test]
    fn block_lookup_allows_past_eof_host_offset() {
        // An allocated entry whose host offset lands past the mock image
        // length must NOT be rejected — past-EOF classification is the
        // caller's job. ext magic, entry 100 → 100 * 128 * 512 = 0x640000,
        // far past the 64 KiB mock capacity. The BAT entry itself lives in
        // sector 0 and reads fine.
        let spec = HeaderSpec {
            tracks: 128,
            bat_entries: 4,
            ..HeaderSpec::default()
        };
        let _guard = install_image(&build_header(&spec), &[100, 0, 0, 0]);

        let ct = stub_call_table();
        let mut bat_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;

        let mut state =
            unsafe { init_state(&ct, &mut bat_buf, &mut data_buf, &mut bytes_read) }.unwrap();

        let l = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert_eq!(
            l,
            Some(ParallelsBlockLookup::Allocated {
                host_byte_offset: 100 * 128 * 512,
            })
        );
    }

    #[test]
    fn block_lookup_fails_when_bat_sector_unreadable() {
        // A small cluster size (tracks=8 → 4 KiB) drives the cluster index
        // high enough that its BAT entry lands in a sector past the mock
        // capacity; the cached BAT read then fails and the lookup surfaces
        // that as None. bat_entries is large so the index is in range.
        let spec = HeaderSpec {
            tracks: 8,
            bat_entries: PARALLELS_BAT_ENTRIES_MAX,
            ..HeaderSpec::default()
        };
        let _guard = install_image(&build_header(&spec), &[]);

        let ct = stub_call_table();
        let mut bat_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;
        let cluster = 4096u64;

        let mut state =
            unsafe { init_state(&ct, &mut bat_buf, &mut data_buf, &mut bytes_read) }.unwrap();

        // Choose cluster_idx so the BAT entry offset (64 + idx*4) lands at
        // or past MOCK_LEN (65536): idx = (65536 - 64) / 4 = 16368.
        let cluster_idx = 16368u64;
        assert!(cluster_idx < state.bat_entries as u64);
        let virtual_offset = cluster_idx * cluster;
        let l = unsafe { state.block_lookup(&ct, virtual_offset, 512, cap, &mut bytes_read) };
        assert!(l.is_none());
    }

    #[test]
    fn block_lookup_small_cluster_scattered() {
        // Small-cluster (tracks=8 → 4 KiB) image with a scattered ext BAT
        // pins small-cluster decoding. entry v → v * 8 * 512 = v * 4096.
        let spec = HeaderSpec {
            tracks: 8,
            bat_entries: 4,
            ..HeaderSpec::default()
        };
        let bat = [0u32, 5, 0, 3];
        let _guard = install_image(&build_header(&spec), &bat);

        let ct = stub_call_table();
        let mut bat_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;
        let cluster = 4096u64;

        let mut state =
            unsafe { init_state(&ct, &mut bat_buf, &mut data_buf, &mut bytes_read) }.unwrap();

        let l0 = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert_eq!(l0, Some(ParallelsBlockLookup::Unallocated));

        let l1 = unsafe { state.block_lookup(&ct, cluster, 512, cap, &mut bytes_read) };
        assert_eq!(
            l1,
            Some(ParallelsBlockLookup::Allocated {
                host_byte_offset: 5 * cluster,
            })
        );

        let l3 = unsafe { state.block_lookup(&ct, 3 * cluster, 512, cap, &mut bytes_read) };
        assert_eq!(
            l3,
            Some(ParallelsBlockLookup::Allocated {
                host_byte_offset: 3 * cluster,
            })
        );
    }
}
