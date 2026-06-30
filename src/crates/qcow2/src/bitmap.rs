//! QCOW2 persistent dirty-bitmap structures.
//!
//! This module holds the `no_std`, panic-free parsers, encoders, geometry
//! helpers, and the streaming directory enumerator for the qcow2
//! persistent-dirty-bitmap on-disk format (the `0x23852875` bitmaps header
//! extension, the bitmap directory, the bitmap table, and the bitmap-data
//! geometry).
//!
//! This is **entirely unrelated** to the extended-L2 *subcluster* bitmap code
//! (`SubclusterBitmapStatus` / `validate_subcluster_bitmap` in `lib.rs`) and to
//! the overlap-detection bitmap in the `shared` crate. Do not confuse them.
//!
//! All parsing here runs on attacker-controlled header bytes (the crate is
//! fuzzed), so every read is length-guarded before calling the `shared::be_*`
//! helpers (which do not bounds-check), and all arithmetic is
//! `checked_*`/saturating.

use shared::be_u32;

// Re-export the extension type ID so the constant has a single source of
// truth in `lib.rs` while remaining reachable as `bitmap::EXT_BITMAPS`.
pub use crate::EXT_BITMAPS;

// ============================================================================
// Constants
// ============================================================================

/// Autoclear feature bit guarding bitmap consistency (`autoclear_features`
/// bit 0). Set ⇔ the bitmaps extension is valid; if the extension is present
/// but this bit is clear, the bitmaps are treated as inconsistent/absent.
pub const AUTOCLEAR_BITMAPS_BIT: u64 = 1 << 0;

/// Directory-entry flag: the bitmap is `in_use` (was being written when the
/// image was last closed uncleanly) — inconsistent; only `--remove` is allowed.
pub const BME_FLAG_IN_USE: u32 = 1 << 0;
/// Directory-entry flag: the bitmap is `auto` (i.e. enabled — auto-tracks
/// writes).
pub const BME_FLAG_AUTO: u32 = 1 << 1;
/// Directory-entry flag (spec only): `extra_data_compatible`. qemu's
/// `check_dir_entry` rejects it (treats bits 2..=31 as reserved).
pub const BME_FLAG_EXTRA_DATA_COMPATIBLE: u32 = 1 << 2;
/// Mask of reserved directory-entry flag bits (bits 2..=31): any set ⇒ reject,
/// matching qemu's `check_dir_entry`.
pub const BME_RESERVED_FLAGS: u32 = 0xFFFF_FFFC;

/// The only valid bitmap `type`: a dirty-tracking bitmap.
pub const BT_DIRTY_TRACKING_BITMAP: u8 = 1;

/// Minimum permitted `granularity_bits` (512 bytes/bit).
pub const BME_MIN_GRANULARITY_BITS: u8 = 9;
/// Maximum permitted `granularity_bits` (2 GiB/bit).
pub const BME_MAX_GRANULARITY_BITS: u8 = 31;
/// Maximum bitmap-name length in bytes (not NUL-terminated on disk).
pub const BME_MAX_NAME_SIZE: usize = 1023;

/// Maximum number of bitmaps in one image.
pub const QCOW2_MAX_BITMAPS: u32 = 65535;
/// Maximum total size of the bitmap directory in bytes.
pub const QCOW2_MAX_BITMAP_DIRECTORY_SIZE: u64 = 1024 * 65535;

/// Maximum size, in bytes, of a single bitmap table (qemu `BME_MAX_TABLE_SIZE`).
pub const BME_MAX_TABLE_SIZE: u64 = 0x8000000;
/// Maximum physical size of a serialized bitmap, in bytes (512 MiB)
/// (qemu `BME_MAX_PHYS_SIZE`).
pub const BME_MAX_PHYS_SIZE: u64 = 0x20000000;

/// Mask for the host cluster offset within a bitmap-table entry (bits 9-55).
pub const BME_TABLE_ENTRY_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
/// Mask of reserved bits within a bitmap-table entry (must be zero).
pub const BME_TABLE_ENTRY_RESERVED_MASK: u64 = 0xff00_0000_0000_01fe;
/// Bitmap-table entry flag: with a zero offset, marks an all-ones cluster.
pub const BME_TABLE_ENTRY_FLAG_ALL_ONES: u64 = 1 << 0;

// ============================================================================
// Bitmaps header extension
// ============================================================================

/// Parsed contents of the 24-byte `EXT_BITMAPS` (`0x23852875`) header
/// extension body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapsExtension {
    /// Number of bitmaps in the directory.
    pub nb_bitmaps: u32,
    /// Total size of the bitmap directory in bytes.
    pub bitmap_directory_size: u64,
    /// File offset of the bitmap directory (cluster-aligned on disk; only an
    /// 8-byte alignment check is performed here — see below).
    pub bitmap_directory_offset: u64,
}

/// Parse the 24-byte bitmaps-extension body.
///
/// Body layout (all big-endian):
/// - `nb_bitmaps`             u32 @0
/// - `reserved`               u32 @4  (parsed-but-ignored; qemu does not hard-
///   require it to be zero)
/// - `bitmap_directory_size`  u64 @8
/// - `bitmap_directory_offset` u64 @16
///
/// Returns `None` (no usable bitmaps) when:
/// - `data.len() < 24`,
/// - `nb_bitmaps == 0` or `nb_bitmaps > QCOW2_MAX_BITMAPS`,
/// - `bitmap_directory_size > QCOW2_MAX_BITMAP_DIRECTORY_SIZE`,
/// - `bitmap_directory_offset == 0` or is not 8-byte aligned.
///
/// **Note:** this function does not know the image's `cluster_size`, so it can
/// only enforce the minimal 8-byte alignment of the directory offset. The full
/// cluster-alignment check (`offset % cluster_size == 0`) requires
/// `cluster_size` and is the caller's/planner's responsibility.
pub fn parse_bitmaps_extension(data: &[u8]) -> Option<BitmapsExtension> {
    if data.len() < 24 {
        return None;
    }

    let nb_bitmaps = be_u32(data, 0);
    // reserved @4 is parsed-but-ignored (qemu does not hard-require 0).
    let bitmap_directory_size = be_u64_at(data, 8)?;
    let bitmap_directory_offset = be_u64_at(data, 16)?;

    if nb_bitmaps == 0 || nb_bitmaps > QCOW2_MAX_BITMAPS {
        return None;
    }
    if bitmap_directory_size > QCOW2_MAX_BITMAP_DIRECTORY_SIZE {
        return None;
    }
    // Minimal sane offset check: non-zero and 8-byte aligned. Cluster-alignment
    // validation needs cluster_size and is the caller's job.
    if bitmap_directory_offset == 0 || bitmap_directory_offset % 8 != 0 {
        return None;
    }

    Some(BitmapsExtension {
        nb_bitmaps,
        bitmap_directory_size,
        bitmap_directory_offset,
    })
}

/// Length-guarded big-endian u64 read. Returns `None` if the 8-byte read would
/// run past the end of `buf` (the `shared::be_u64` helper panics on OOB).
#[inline]
fn be_u64_at(buf: &[u8], off: usize) -> Option<u64> {
    if off.checked_add(8)? > buf.len() {
        return None;
    }
    Some(shared::be_u64(buf, off))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid 24-byte bitmaps-extension body.
    fn make_ext_body(nb_bitmaps: u32, dir_size: u64, dir_offset: u64) -> [u8; 24] {
        let mut body = [0u8; 24];
        body[0..4].copy_from_slice(&nb_bitmaps.to_be_bytes());
        // reserved @4 left zero
        body[8..16].copy_from_slice(&dir_size.to_be_bytes());
        body[16..24].copy_from_slice(&dir_offset.to_be_bytes());
        body
    }

    #[test]
    fn parse_valid_body() {
        let body = make_ext_body(2, 1024, 0x40000);
        let ext = parse_bitmaps_extension(&body).unwrap();
        assert_eq!(ext.nb_bitmaps, 2);
        assert_eq!(ext.bitmap_directory_size, 1024);
        assert_eq!(ext.bitmap_directory_offset, 0x40000);
    }

    #[test]
    fn parse_ignores_reserved_field() {
        let mut body = make_ext_body(1, 512, 0x10000);
        // Set the reserved word to a non-zero value; it must be ignored.
        body[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        assert!(parse_bitmaps_extension(&body).is_some());
    }

    #[test]
    fn parse_rejects_nb_bitmaps_zero() {
        let body = make_ext_body(0, 1024, 0x40000);
        assert!(parse_bitmaps_extension(&body).is_none());
    }

    #[test]
    fn parse_rejects_nb_bitmaps_over_max() {
        let body = make_ext_body(QCOW2_MAX_BITMAPS + 1, 1024, 0x40000);
        assert!(parse_bitmaps_extension(&body).is_none());
    }

    #[test]
    fn parse_accepts_nb_bitmaps_at_max() {
        let body = make_ext_body(QCOW2_MAX_BITMAPS, 1024, 0x40000);
        assert!(parse_bitmaps_extension(&body).is_some());
    }

    #[test]
    fn parse_rejects_dir_size_over_max() {
        let body = make_ext_body(1, QCOW2_MAX_BITMAP_DIRECTORY_SIZE + 1, 0x40000);
        assert!(parse_bitmaps_extension(&body).is_none());
    }

    #[test]
    fn parse_accepts_dir_size_at_max() {
        let body = make_ext_body(1, QCOW2_MAX_BITMAP_DIRECTORY_SIZE, 0x40000);
        assert!(parse_bitmaps_extension(&body).is_some());
    }

    #[test]
    fn parse_rejects_truncated_body() {
        let body = make_ext_body(1, 1024, 0x40000);
        assert!(parse_bitmaps_extension(&body[..23]).is_none());
        assert!(parse_bitmaps_extension(&[]).is_none());
    }

    #[test]
    fn parse_rejects_misaligned_offset() {
        // Offset not 8-byte aligned.
        let body = make_ext_body(1, 1024, 0x40001);
        assert!(parse_bitmaps_extension(&body).is_none());
    }

    #[test]
    fn parse_rejects_zero_offset() {
        let body = make_ext_body(1, 1024, 0);
        assert!(parse_bitmaps_extension(&body).is_none());
    }
}
