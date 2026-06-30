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

use shared::{be_u16, be_u32, write_be_u16, write_be_u32, write_be_u64};

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

/// Length-guarded big-endian u32 read. Returns `None` if the 4-byte read would
/// run past the end of `buf`.
#[inline]
fn be_u32_at(buf: &[u8], off: usize) -> Option<u32> {
    if off.checked_add(4)? > buf.len() {
        return None;
    }
    Some(be_u32(buf, off))
}

/// Length-guarded big-endian u16 read. Returns `None` if the 2-byte read would
/// run past the end of `buf`.
#[inline]
fn be_u16_at(buf: &[u8], off: usize) -> Option<u16> {
    if off.checked_add(2)? > buf.len() {
        return None;
    }
    Some(be_u16(buf, off))
}

// ============================================================================
// Bitmap directory entry
// ============================================================================

/// Capacity of the inline bitmap-name buffer. The on-disk `name_size` is
/// constrained to `BME_MAX_NAME_SIZE` (1023), so 1024 leaves headroom for an
/// (unused) NUL while keeping the entry one stack-resident record.
pub const BITMAP_NAME_CAPACITY: usize = 1024;

/// A parsed (or to-be-serialized) bitmap directory entry.
///
/// The 24-byte fixed head matches the qcow2 on-disk layout; the name is held
/// inline in a fixed-capacity buffer so that a single in-flight entry needs no
/// heap (mirroring `SnapshotEntry` in `lib.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapDirEntry {
    /// File offset of this bitmap's table (the array of table entries).
    pub bitmap_table_offset: u64,
    /// Number of entries in the bitmap table.
    pub bitmap_table_size: u32,
    /// Directory-entry flags (`BME_FLAG_*`).
    pub flags: u32,
    /// Bitmap type (must be `BT_DIRTY_TRACKING_BITMAP`).
    pub bitmap_type: u8,
    /// Granularity in bits: granularity (bytes/bit) is `1 << granularity_bits`.
    pub granularity_bits: u8,
    /// On-disk byte length of the (non-NUL-terminated) name.
    pub name_size: u16,
    /// Size of the extra-data blob (always 0 for the bitmaps qemu writes).
    pub extra_data_size: u32,
    /// Inline name buffer; only `name_size` bytes are valid.
    pub name: [u8; BITMAP_NAME_CAPACITY],
}

impl BitmapDirEntry {
    /// A fully-zeroed entry (no heap), for callers/enumerators that build a
    /// default before parsing into it. Mirrors `SnapshotEntry::zeroed`.
    pub const fn zeroed() -> Self {
        Self {
            bitmap_table_offset: 0,
            bitmap_table_size: 0,
            flags: 0,
            bitmap_type: 0,
            granularity_bits: 0,
            name_size: 0,
            extra_data_size: 0,
            name: [0; BITMAP_NAME_CAPACITY],
        }
    }

    /// True if the bitmap is enabled (`auto` flag set).
    pub fn is_enabled(&self) -> bool {
        self.flags & BME_FLAG_AUTO != 0
    }

    /// True if the bitmap is marked `in_use` (image was closed uncleanly while
    /// the bitmap was being written — inconsistent).
    pub fn is_in_use(&self) -> bool {
        self.flags & BME_FLAG_IN_USE != 0
    }

    /// Granularity in bytes/bit: `1 << granularity_bits`. `granularity_bits` is
    /// validated `<= 31` on parse, but a bounded shift is used here so this can
    /// never panic even on a hand-built entry with an out-of-range value.
    pub fn granularity(&self) -> u64 {
        if self.granularity_bits >= 64 {
            0
        } else {
            1u64 << self.granularity_bits
        }
    }

    /// The valid bytes of the bitmap name (not NUL-terminated).
    pub fn name_bytes(&self) -> &[u8] {
        let len = (self.name_size as usize).min(BITMAP_NAME_CAPACITY);
        &self.name[..len]
    }
}

/// Round `value` up to a multiple of 8 using checked arithmetic. Returns `None`
/// on overflow.
#[inline]
fn round_up_8(value: u64) -> Option<u64> {
    Some(value.checked_add(7)? & !7u64)
}

/// Parse a single bitmap directory entry from `buf` (which begins at the entry).
///
/// The 24-byte fixed head (all big-endian):
/// - `bitmap_table_offset`  u64 @0
/// - `bitmap_table_size`    u32 @8
/// - `flags`                u32 @12
/// - `bitmap_type`          u8  @16
/// - `granularity_bits`     u8  @17
/// - `name_size`            u16 @18
/// - `extra_data_size`      u32 @20
///
/// followed by `extra_data` (`extra_data_size` bytes) then the name
/// (`name_size` bytes), the whole entry padded up to a multiple of 8.
///
/// Validation mirrors qemu's `check_dir_entry` exactly: reject reserved flag
/// bits, a non-dirty-tracking type, any extra data, and an out-of-range name
/// size. **Granularity range is intentionally NOT checked here** — qemu
/// validates it in a separate layer (`bitmap_list_load` → `check_constraints`),
/// not in `check_dir_entry`. Callers that need it use
/// [`granularity_bits_valid`]. Returns `(entry, entry_size)` on success.
pub fn parse_bitmap_dir_entry(buf: &[u8]) -> Option<(BitmapDirEntry, usize)> {
    // Fixed head must be present.
    if buf.len() < 24 {
        return None;
    }

    let bitmap_table_offset = be_u64_at(buf, 0)?;
    let bitmap_table_size = be_u32_at(buf, 8)?;
    let flags = be_u32_at(buf, 12)?;
    let bitmap_type = buf[16];
    let granularity_bits = buf[17];
    let name_size = be_u16_at(buf, 18)?;
    let extra_data_size = be_u32_at(buf, 20)?;

    // qemu check_dir_entry validation.
    if flags & BME_RESERVED_FLAGS != 0 {
        return None;
    }
    if bitmap_type != BT_DIRTY_TRACKING_BITMAP {
        return None;
    }
    if extra_data_size != 0 {
        return None;
    }
    if name_size == 0 || name_size as usize > BME_MAX_NAME_SIZE {
        return None;
    }

    // entry_size = round_up(24 + extra_data_size + name_size, 8), checked.
    let raw_size = 24u64
        .checked_add(extra_data_size as u64)?
        .checked_add(name_size as u64)?;
    let entry_size = round_up_8(raw_size)?;
    let entry_size_usize: usize = entry_size.try_into().ok()?;
    if buf.len() < entry_size_usize {
        return None;
    }

    // Name sits at 24 + extra_data_size, length name_size.
    let name_off = 24usize.checked_add(extra_data_size as usize)?;
    let name_end = name_off.checked_add(name_size as usize)?;
    if name_end > buf.len() {
        return None;
    }

    let mut entry = BitmapDirEntry::zeroed();
    entry.bitmap_table_offset = bitmap_table_offset;
    entry.bitmap_table_size = bitmap_table_size;
    entry.flags = flags;
    entry.bitmap_type = bitmap_type;
    entry.granularity_bits = granularity_bits;
    entry.name_size = name_size;
    entry.extra_data_size = extra_data_size;
    entry.name[..name_size as usize].copy_from_slice(&buf[name_off..name_end]);

    Some((entry, entry_size_usize))
}

/// Serialize a bitmap directory entry into `out`. Inverse of
/// [`parse_bitmap_dir_entry`]: writes the 24-byte big-endian head, the name at
/// `24 + extra_data_size`, and zero-fills the padding up to `entry_size`
/// (`round_up(24 + extra_data_size + name_size, 8)`). Returns `entry_size` on
/// success, or `None` if `out` is too small or arithmetic overflows.
pub fn serialize_bitmap_dir_entry(entry: &BitmapDirEntry, out: &mut [u8]) -> Option<usize> {
    let name_size = entry.name_size as usize;
    if name_size > BME_MAX_NAME_SIZE || name_size > BITMAP_NAME_CAPACITY {
        return None;
    }

    let raw_size = 24u64
        .checked_add(entry.extra_data_size as u64)?
        .checked_add(entry.name_size as u64)?;
    let entry_size = round_up_8(raw_size)?;
    let entry_size_usize: usize = entry_size.try_into().ok()?;
    if out.len() < entry_size_usize {
        return None;
    }

    // 24-byte head.
    write_be_u64(out, 0, entry.bitmap_table_offset);
    write_be_u32(out, 8, entry.bitmap_table_size);
    write_be_u32(out, 12, entry.flags);
    out[16] = entry.bitmap_type;
    out[17] = entry.granularity_bits;
    write_be_u16(out, 18, entry.name_size);
    write_be_u32(out, 20, entry.extra_data_size);

    // Name at 24 + extra_data_size.
    let name_off = 24usize.checked_add(entry.extra_data_size as usize)?;
    let name_end = name_off.checked_add(name_size)?;
    if name_end > entry_size_usize {
        return None;
    }
    out[name_off..name_end].copy_from_slice(&entry.name[..name_size]);

    // Zero the padding (and any extra-data gap) up to entry_size. Anything
    // between the head and the name (the extra-data region) and between the
    // name and entry_size is zeroed.
    for b in out[24..name_off].iter_mut() {
        *b = 0;
    }
    for b in out[name_end..entry_size_usize].iter_mut() {
        *b = 0;
    }

    Some(entry_size_usize)
}

// ============================================================================
// Bitmap table entry
// ============================================================================

/// A decoded bitmap-table entry.
///
/// Each entry describes one cluster of serialized bitmap data:
/// - `AllZeroes`: the cluster is implicitly all zero bits (not allocated).
/// - `AllOnes`: the cluster is implicitly all one bits (not allocated).
/// - `Allocated(offset)`: the host file offset (bits 9-55, cluster-aligned) of
///   the cluster holding the bitmap data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitmapTableEntry {
    /// Implicitly all-zero cluster.
    AllZeroes,
    /// Implicitly all-one cluster.
    AllOnes,
    /// Allocated cluster at the given host offset.
    Allocated(u64),
}

/// Validate a raw bitmap-table entry word.
///
/// Returns `false` if any reserved bit is set, or if the entry both carries a
/// non-zero offset and has the all-ones flag bit set (an allocated cluster
/// cannot also be the all-ones sentinel).
pub fn validate_bitmap_table_entry(raw: u64) -> bool {
    if raw & BME_TABLE_ENTRY_RESERVED_MASK != 0 {
        return false;
    }
    let offset = raw & BME_TABLE_ENTRY_OFFSET_MASK;
    if offset != 0 && raw & BME_TABLE_ENTRY_FLAG_ALL_ONES != 0 {
        return false;
    }
    true
}

/// Decode a raw bitmap-table entry word into a [`BitmapTableEntry`]. Returns
/// `None` if the raw word fails [`validate_bitmap_table_entry`].
pub fn decode_bitmap_table_entry(raw: u64) -> Option<BitmapTableEntry> {
    if !validate_bitmap_table_entry(raw) {
        return None;
    }
    let offset = raw & BME_TABLE_ENTRY_OFFSET_MASK;
    if offset != 0 {
        Some(BitmapTableEntry::Allocated(offset))
    } else if raw & BME_TABLE_ENTRY_FLAG_ALL_ONES != 0 {
        Some(BitmapTableEntry::AllOnes)
    } else {
        Some(BitmapTableEntry::AllZeroes)
    }
}

/// Encode a [`BitmapTableEntry`] into its raw on-disk word. The offset of an
/// `Allocated` entry is masked to the offset bits (it is cluster-aligned and in
/// range by construction).
pub fn encode_bitmap_table_entry(entry: &BitmapTableEntry) -> u64 {
    match entry {
        BitmapTableEntry::AllZeroes => 0,
        BitmapTableEntry::AllOnes => BME_TABLE_ENTRY_FLAG_ALL_ONES,
        BitmapTableEntry::Allocated(off) => off & BME_TABLE_ENTRY_OFFSET_MASK,
    }
}

// ============================================================================
// Geometry + validation helpers
// ============================================================================

/// Divide `a` by `b`, rounding up. Guards `b == 0` (returns 0) and uses
/// saturating addition so it cannot panic on `u64::MAX`-scale inputs.
#[inline]
fn div_round_up(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    a.saturating_add(b - 1) / b
}

/// Default bitmap granularity for a given cluster size, matching qemu's
/// `bdrv_get_default_bitmap_granularity`: `min(65536, max(4096, cluster_size))`.
pub fn default_granularity(cluster_size: u64) -> u64 {
    cluster_size.clamp(4096, 65536)
}

/// True if `bits` is a valid `granularity_bits` value
/// (`BME_MIN_GRANULARITY_BITS..=BME_MAX_GRANULARITY_BITS`, i.e. 9..=31).
pub fn granularity_bits_valid(bits: u8) -> bool {
    (BME_MIN_GRANULARITY_BITS..=BME_MAX_GRANULARITY_BITS).contains(&bits)
}

/// Number of bytes needed to hold a serialized bitmap covering `virtual_size`
/// bytes at the given `granularity`, matching qemu's `get_bitmap_bytes_needed`:
/// `div_round_up(div_round_up(virtual_size, granularity), 8)`. Guards
/// `granularity == 0` (returns 0) and uses saturating math so `u64::MAX`
/// inputs cannot panic.
pub fn bitmap_bytes_needed(virtual_size: u64, granularity: u64) -> u64 {
    if granularity == 0 {
        return 0;
    }
    let bits = div_round_up(virtual_size, granularity);
    div_round_up(bits, 8)
}

/// Number of bitmap-table entries (one per data cluster) needed to hold
/// `serialized_bytes` of bitmap data, matching qemu's `size_to_clusters`:
/// `div_round_up(serialized_bytes, cluster_size)`. Guards `cluster_size == 0`
/// (returns 0).
pub fn bitmap_table_size_entries(serialized_bytes: u64, cluster_size: u64) -> u64 {
    if cluster_size == 0 {
        return 0;
    }
    div_round_up(serialized_bytes, cluster_size)
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

    // ------------------------------------------------------------------------
    // Directory-entry codec
    // ------------------------------------------------------------------------

    /// Build a directory entry into a buffer large enough for it. Returns the
    /// buffer and the entry_size. `extra_data_size` is honored for the head but
    /// no extra-data bytes are written (callers use 0).
    fn make_dir_entry(
        table_offset: u64,
        table_size: u32,
        flags: u32,
        bitmap_type: u8,
        granularity_bits: u8,
        name: &[u8],
        extra_data_size: u32,
    ) -> ([u8; 2048], usize) {
        let mut buf = [0u8; 2048];
        buf[0..8].copy_from_slice(&table_offset.to_be_bytes());
        buf[8..12].copy_from_slice(&table_size.to_be_bytes());
        buf[12..16].copy_from_slice(&flags.to_be_bytes());
        buf[16] = bitmap_type;
        buf[17] = granularity_bits;
        buf[18..20].copy_from_slice(&(name.len() as u16).to_be_bytes());
        buf[20..24].copy_from_slice(&extra_data_size.to_be_bytes());
        let name_off = 24 + extra_data_size as usize;
        buf[name_off..name_off + name.len()].copy_from_slice(name);
        let raw = 24 + extra_data_size as usize + name.len();
        let entry_size = (raw + 7) & !7usize;
        (buf, entry_size)
    }

    #[test]
    fn dir_entry_round_trip_various() {
        // (name, flags, granularity_bits)
        let cases: &[(&[u8], u32, u8)] = &[
            (b"node0", BME_FLAG_AUTO, 16),
            (b"bitmap-with-a-longer-name", 0, 9),
            (b"x", BME_FLAG_AUTO | BME_FLAG_IN_USE, 31),
            (b"aligned8", BME_FLAG_AUTO, 12), // name len 8 -> head+name = 32, already aligned
        ];
        for &(name, flags, gbits) in cases {
            let (buf, entry_size) = make_dir_entry(0x5000, 7, flags, 1, gbits, name, 0);
            let (entry, parsed_size) = parse_bitmap_dir_entry(&buf).expect("parse");
            assert_eq!(parsed_size, entry_size);
            assert_eq!(entry.bitmap_table_offset, 0x5000);
            assert_eq!(entry.bitmap_table_size, 7);
            assert_eq!(entry.name_bytes(), name);
            assert_eq!(entry.granularity_bits, gbits);
            assert_eq!(entry.granularity(), 1u64 << gbits);
            assert_eq!(entry.is_enabled(), flags & BME_FLAG_AUTO != 0);
            assert_eq!(entry.is_in_use(), flags & BME_FLAG_IN_USE != 0);

            // serialize -> parse again
            let mut out = [0xAAu8; 2048];
            let written = serialize_bitmap_dir_entry(&entry, &mut out).expect("serialize");
            assert_eq!(written, entry_size);
            // padding must be zeroed
            let raw = 24 + name.len();
            for &b in &out[raw..entry_size] {
                assert_eq!(b, 0, "padding byte must be zero");
            }
            let (entry2, size2) = parse_bitmap_dir_entry(&out).expect("reparse");
            assert_eq!(size2, entry_size);
            assert_eq!(entry2, entry);
        }
    }

    #[test]
    fn dir_entry_padding_alignment() {
        // name len 5 -> raw 29 -> round_up 32; name len 8 -> raw 32 -> 32;
        // name len 9 -> raw 33 -> 40.
        let nm = [b'a'; 16];
        for (name_len, expected) in &[(5usize, 32usize), (8, 32), (9, 40)] {
            let (buf, entry_size) = make_dir_entry(0, 1, 0, 1, 16, &nm[..*name_len], 0);
            assert_eq!(entry_size, *expected);
            let (_, parsed_size) = parse_bitmap_dir_entry(&buf).unwrap();
            assert_eq!(parsed_size, *expected);
        }
    }

    #[test]
    fn dir_entry_rejects_reserved_flag() {
        let (buf, _) = make_dir_entry(0, 1, BME_FLAG_EXTRA_DATA_COMPATIBLE, 1, 16, b"n", 0);
        assert!(parse_bitmap_dir_entry(&buf).is_none());
    }

    #[test]
    fn dir_entry_rejects_bad_type() {
        let (buf, _) = make_dir_entry(0, 1, 0, 2, 16, b"n", 0);
        assert!(parse_bitmap_dir_entry(&buf).is_none());
        let (buf0, _) = make_dir_entry(0, 1, 0, 0, 16, b"n", 0);
        assert!(parse_bitmap_dir_entry(&buf0).is_none());
    }

    #[test]
    fn dir_entry_rejects_extra_data() {
        let (buf, _) = make_dir_entry(0, 1, 0, 1, 16, b"n", 8);
        assert!(parse_bitmap_dir_entry(&buf).is_none());
    }

    #[test]
    fn dir_entry_rejects_name_size_zero() {
        let (buf, _) = make_dir_entry(0, 1, 0, 1, 16, b"", 0);
        assert!(parse_bitmap_dir_entry(&buf).is_none());
    }

    #[test]
    fn dir_entry_rejects_name_too_long() {
        // name_size = 1024 (> BME_MAX_NAME_SIZE 1023).
        let mut buf = [0u8; 2048];
        buf[16] = 1; // type
        buf[17] = 16; // granularity
        buf[18..20].copy_from_slice(&1024u16.to_be_bytes());
        assert!(parse_bitmap_dir_entry(&buf).is_none());
        // name_size = 1023 must be accepted (when the buffer fits).
        buf[18..20].copy_from_slice(&1023u16.to_be_bytes());
        assert!(parse_bitmap_dir_entry(&buf).is_some());
    }

    #[test]
    fn dir_entry_rejects_truncated() {
        // Head shorter than 24 bytes.
        let (buf, _) = make_dir_entry(0, 1, 0, 1, 16, b"name", 0);
        assert!(parse_bitmap_dir_entry(&buf[..23]).is_none());
        // entry_size > buf.len(): valid head but the name+padding don't fit.
        let (full, entry_size) = make_dir_entry(0, 1, 0, 1, 16, b"name", 0);
        assert!(parse_bitmap_dir_entry(&full[..entry_size - 1]).is_none());
    }

    #[test]
    fn serialize_rejects_small_out() {
        let (buf, entry_size) = make_dir_entry(0, 1, 0, 1, 16, b"hello", 0);
        let (entry, _) = parse_bitmap_dir_entry(&buf).unwrap();
        let mut out = [0u8; 2048];
        assert!(serialize_bitmap_dir_entry(&entry, &mut out[..entry_size - 1]).is_none());
        assert!(serialize_bitmap_dir_entry(&entry, &mut out[..entry_size]).is_some());
    }

    // ------------------------------------------------------------------------
    // Table-entry codec
    // ------------------------------------------------------------------------

    #[test]
    fn table_entry_all_zeroes() {
        assert!(validate_bitmap_table_entry(0));
        assert_eq!(
            decode_bitmap_table_entry(0),
            Some(BitmapTableEntry::AllZeroes)
        );
        assert_eq!(encode_bitmap_table_entry(&BitmapTableEntry::AllZeroes), 0);
    }

    #[test]
    fn table_entry_all_ones() {
        let raw = BME_TABLE_ENTRY_FLAG_ALL_ONES;
        assert!(validate_bitmap_table_entry(raw));
        assert_eq!(
            decode_bitmap_table_entry(raw),
            Some(BitmapTableEntry::AllOnes)
        );
        assert_eq!(encode_bitmap_table_entry(&BitmapTableEntry::AllOnes), raw);
    }

    #[test]
    fn table_entry_allocated() {
        // A cluster-aligned offset within the offset mask (bits 9-55).
        let off = 0x40000u64;
        assert_eq!(off & BME_TABLE_ENTRY_OFFSET_MASK, off);
        assert!(validate_bitmap_table_entry(off));
        assert_eq!(
            decode_bitmap_table_entry(off),
            Some(BitmapTableEntry::Allocated(off))
        );
        assert_eq!(
            encode_bitmap_table_entry(&BitmapTableEntry::Allocated(off)),
            off
        );
    }

    #[test]
    fn table_entry_round_trip() {
        for e in &[
            BitmapTableEntry::AllZeroes,
            BitmapTableEntry::AllOnes,
            BitmapTableEntry::Allocated(0x200),
            BitmapTableEntry::Allocated(0x00ff_ffff_ffff_fe00),
        ] {
            let raw = encode_bitmap_table_entry(e);
            assert_eq!(decode_bitmap_table_entry(raw).as_ref(), Some(e));
        }
    }

    #[test]
    fn table_entry_rejects_reserved_bit() {
        // A reserved bit in the high byte.
        let raw = 1u64 << 56;
        assert!(!validate_bitmap_table_entry(raw));
        assert!(decode_bitmap_table_entry(raw).is_none());
        // A reserved bit in bits 1-8.
        let raw2 = 1u64 << 1;
        assert!(!validate_bitmap_table_entry(raw2));
        assert!(decode_bitmap_table_entry(raw2).is_none());
    }

    #[test]
    fn table_entry_rejects_offset_and_all_ones() {
        let raw = 0x40000u64 | BME_TABLE_ENTRY_FLAG_ALL_ONES;
        assert!(!validate_bitmap_table_entry(raw));
        assert!(decode_bitmap_table_entry(raw).is_none());
    }

    // ------------------------------------------------------------------------
    // Geometry helpers
    // ------------------------------------------------------------------------

    #[test]
    fn default_granularity_cases() {
        assert_eq!(default_granularity(512), 4096);
        assert_eq!(default_granularity(4096), 4096);
        assert_eq!(default_granularity(65536), 65536);
        assert_eq!(default_granularity(2 * 1024 * 1024), 65536);
    }

    #[test]
    fn bitmap_bytes_needed_cases() {
        // 1 MiB at 64 KiB granularity: 16 bits -> 2 bytes.
        assert_eq!(bitmap_bytes_needed(1024 * 1024, 65536), 2);
        // 8 * 65536 bytes at 65536 granularity: 8 bits -> 1 byte.
        assert_eq!(bitmap_bytes_needed(8 * 65536, 65536), 1);
        // 9 * 65536 bytes -> 9 bits -> 2 bytes.
        assert_eq!(bitmap_bytes_needed(9 * 65536, 65536), 2);
        // Non-multiple virtual size rounds the bit count up.
        assert_eq!(bitmap_bytes_needed(65536 + 1, 65536), 1); // 2 bits -> 1 byte
                                                              // granularity 0 -> 0 (guard).
        assert_eq!(bitmap_bytes_needed(1024, 0), 0);
    }

    #[test]
    fn bitmap_bytes_needed_no_panic_on_max() {
        // Must not panic on u64::MAX virtual size.
        let _ = bitmap_bytes_needed(u64::MAX, 512);
        let _ = bitmap_bytes_needed(u64::MAX, 1);
    }

    #[test]
    fn granularity_bits_valid_boundaries() {
        assert!(!granularity_bits_valid(8));
        assert!(granularity_bits_valid(9));
        assert!(granularity_bits_valid(31));
        assert!(!granularity_bits_valid(32));
    }

    #[test]
    fn table_size_entries_cases() {
        assert_eq!(bitmap_table_size_entries(0, 65536), 0);
        assert_eq!(bitmap_table_size_entries(1, 65536), 1);
        assert_eq!(bitmap_table_size_entries(65536, 65536), 1);
        assert_eq!(bitmap_table_size_entries(65537, 65536), 2);
        assert_eq!(bitmap_table_size_entries(100, 0), 0); // guard
    }
}
