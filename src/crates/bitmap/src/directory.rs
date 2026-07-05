//! Directory-level byte helpers for the qcow2 bitmaps directory.
//!
//! Templated on `snapshot::table`, these functions locate, build,
//! and rewrite bitmap directory entries and serialize the bitmaps
//! extension body, reusing the Phase 1 entry codec in
//! [`qcow2::bitmap`]. They are `no_std`, panic-free, and
//! bounds-checked.
//!
//! The bitmap directory is a sequence of variable-length entries
//! packed back-to-back. Each entry occupies
//! `round_up(24 + extra_data_size + name_size, 8)` bytes
//! (`extra_data_size` is always 0 for the entries qemu — and this
//! crate — write), so entries are self-aligning: the packed layout
//! is already 8-aligned per entry, unlike the snapshot table where
//! the *next* entry's start must be re-aligned. The walk therefore
//! reuses [`qcow2::bitmap::parse_bitmap_dir_entry`], which returns
//! the entry **and** its total (padded) size, rather than
//! recomputing the size by hand.
//!
//! The on-disk directory-entry layout (big-endian) is the read
//! oracle in [`qcow2::bitmap::parse_bitmap_dir_entry`]:
//!
//! ```text
//!   0-7:   bitmap_table_offset (u64)
//!   8-11:  bitmap_table_size   (u32)
//!   12-15: flags               (u32)
//!   16:    bitmap_type         (u8)
//!   17:    granularity_bits    (u8)
//!   18-19: name_size           (u16)
//!   20-23: extra_data_size     (u32)
//! ```
//!
//! followed by `extra_data_size` bytes of extra data (0 here) and
//! `name_size` name bytes, the whole entry zero-padded up to a
//! multiple of 8.

use crate::BitmapError;
use qcow2::bitmap::{parse_bitmap_dir_entry, serialize_bitmap_dir_entry, BitmapDirEntry};

/// A bitmap located by [`find_bitmap`]: its table index, the parsed
/// directory entry, and its byte position within the raw directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundBitmap {
    /// Table index of the matched entry (0-based walk order).
    pub index: u32,
    /// The parsed directory entry.
    pub entry: BitmapDirEntry,
    /// Byte offset of the entry's start within the raw directory.
    pub byte_offset: usize,
    /// Total (padded) byte length of the entry
    /// (`round_up(24 + extra_data_size + name_size, 8)`).
    pub entry_size: usize,
}

/// Walk the raw on-disk bitmap directory `dir` for `nb_bitmaps`
/// entries and return the total byte length up to the end of the
/// last entry.
///
/// Each entry is self-aligning (its own size is a multiple of 8),
/// so entries are packed back-to-back and the returned length is
/// the sum of the entry sizes. Reuses
/// [`qcow2::bitmap::parse_bitmap_dir_entry`] (which returns the
/// entry's total size) rather than recomputing sizes by hand.
///
/// Mirrors `snapshot::table::snapshot_table_byte_len`. Returns
/// [`BitmapError::ParseFailed`] if any entry fails to parse or the
/// walk would escape `dir`.
pub fn directory_byte_len(dir: &[u8], nb_bitmaps: u32) -> Result<usize, BitmapError> {
    let mut offset: usize = 0;
    for _ in 0..nb_bitmaps {
        let rest = dir.get(offset..).ok_or(BitmapError::ParseFailed)?;
        let (_entry, entry_size) = parse_bitmap_dir_entry(rest).ok_or(BitmapError::ParseFailed)?;
        offset = offset
            .checked_add(entry_size)
            .ok_or(BitmapError::ParseFailed)?;
    }
    Ok(offset)
}

/// Return the `(start_offset, entry_size)` of raw entry `index`
/// within `dir`, walking entries exactly like
/// [`directory_byte_len`].
///
/// Mirrors `snapshot::table::snapshot_table_entry_bounds`. Returns
/// [`BitmapError::BitmapNotFound`] if `index >= nb_bitmaps`
/// (index out of range), or [`BitmapError::ParseFailed`] if the
/// walk would escape `dir`.
pub fn entry_bounds(
    dir: &[u8],
    nb_bitmaps: u32,
    index: u32,
) -> Result<(usize, usize), BitmapError> {
    if index >= nb_bitmaps {
        return Err(BitmapError::BitmapNotFound);
    }
    let mut offset: usize = 0;
    for i in 0..=index {
        let rest = dir.get(offset..).ok_or(BitmapError::ParseFailed)?;
        let (_entry, entry_size) = parse_bitmap_dir_entry(rest).ok_or(BitmapError::ParseFailed)?;
        if i == index {
            return Ok((offset, entry_size));
        }
        offset = offset
            .checked_add(entry_size)
            .ok_or(BitmapError::ParseFailed)?;
    }
    // Unreachable: the loop returns at i == index.
    Err(BitmapError::ParseFailed)
}

/// Find the first bitmap in `dir` whose name equals `name`.
///
/// Bitmap names are unique per image, so the first match is the
/// only match. Compares the full on-disk name bytes
/// ([`BitmapDirEntry::name_bytes`]).
///
/// Returns `Ok(None)` when nothing matches, or
/// [`BitmapError::ParseFailed`] if the entry walk escapes `dir`.
pub fn find_bitmap(
    dir: &[u8],
    nb_bitmaps: u32,
    name: &[u8],
) -> Result<Option<FoundBitmap>, BitmapError> {
    let mut offset: usize = 0;
    for i in 0..nb_bitmaps {
        let rest = dir.get(offset..).ok_or(BitmapError::ParseFailed)?;
        let (entry, entry_size) = parse_bitmap_dir_entry(rest).ok_or(BitmapError::ParseFailed)?;
        if entry.name_bytes() == name {
            return Ok(Some(FoundBitmap {
                index: i,
                entry,
                byte_offset: offset,
                entry_size,
            }));
        }
        offset = offset
            .checked_add(entry_size)
            .ok_or(BitmapError::ParseFailed)?;
    }
    Ok(None)
}

/// Build the new bitmap directory into `out`: the old entries copied
/// verbatim, then the serialized `new_entry` appended. Returns the
/// total byte length.
///
/// Each existing entry is already 8-aligned (its size is a multiple
/// of 8), so `old_dir[..old_len]` is copied verbatim with no
/// alignment gap, and the new entry — itself 8-aligned by
/// [`qcow2::bitmap::serialize_bitmap_dir_entry`] — is appended
/// directly at `old_len`.
///
/// Mirrors `snapshot::table::build_snapshot_table` (minus the
/// re-alignment, which the self-aligning bitmap entries make
/// unnecessary). `old_len` is the exact length of the existing
/// entries (from [`directory_byte_len`]).
///
/// The caller guarantees name uniqueness and count limits (that is
/// `action.rs`'s job); this function only bounds-checks buffers.
/// Returns [`BitmapError::InternalOverflow`] if `old_len` exceeds
/// `old_dir` or an offset computation overflows,
/// [`BitmapError::ScratchTooSmall`] if `out` is too small, and
/// [`BitmapError::ParseFailed`] if the new entry fails to serialize.
pub fn build_directory_with_added(
    old_dir: &[u8],
    old_len: usize,
    _nb_bitmaps: u32,
    new_entry: &BitmapDirEntry,
    out: &mut [u8],
) -> Result<usize, BitmapError> {
    if old_len > old_dir.len() {
        return Err(BitmapError::InternalOverflow);
    }
    if out.len() < old_len {
        return Err(BitmapError::ScratchTooSmall);
    }
    // Verbatim copy of the old entries (already 8-aligned per entry).
    out[..old_len].copy_from_slice(&old_dir[..old_len]);
    // Append the serialized new entry at old_len.
    let appended = serialize_bitmap_dir_entry(new_entry, &mut out[old_len..])
        .ok_or(BitmapError::ParseFailed)?;
    old_len
        .checked_add(appended)
        .ok_or(BitmapError::InternalOverflow)
}

/// Build the compacted bitmap directory into `out`: every entry of
/// the old directory except `remove_index` copied verbatim, packed
/// back-to-back. Returns the total byte length.
///
/// Each surviving entry is already 8-aligned, so survivors are
/// copied verbatim with no re-alignment (the removed entry's slot
/// simply vanishes and later entries shift down). Removing the sole
/// entry yields length 0.
///
/// Mirrors `snapshot::table::build_snapshot_table_without` (minus
/// the re-alignment). `old_len` is the exact length of the existing
/// entries (from [`directory_byte_len`]).
///
/// Returns [`BitmapError::BitmapNotFound`] if
/// `remove_index >= nb_bitmaps`, [`BitmapError::InternalOverflow`]
/// if `old_len` exceeds `old_dir` or an offset overflows,
/// [`BitmapError::ScratchTooSmall`] if `out` is too small, and
/// [`BitmapError::ParseFailed`] if the walk escapes the directory.
pub fn build_directory_without(
    old_dir: &[u8],
    old_len: usize,
    nb_bitmaps: u32,
    remove_index: u32,
    out: &mut [u8],
) -> Result<usize, BitmapError> {
    if remove_index >= nb_bitmaps {
        return Err(BitmapError::BitmapNotFound);
    }
    if old_len > old_dir.len() {
        return Err(BitmapError::InternalOverflow);
    }
    let dir = &old_dir[..old_len];
    let mut in_offset: usize = 0;
    let mut out_offset: usize = 0;
    for i in 0..nb_bitmaps {
        let rest = dir.get(in_offset..).ok_or(BitmapError::ParseFailed)?;
        let (_entry, entry_size) = parse_bitmap_dir_entry(rest).ok_or(BitmapError::ParseFailed)?;
        let end_in = in_offset
            .checked_add(entry_size)
            .ok_or(BitmapError::InternalOverflow)?;
        if i != remove_index {
            let end_out = out_offset
                .checked_add(entry_size)
                .ok_or(BitmapError::InternalOverflow)?;
            if end_out > out.len() {
                return Err(BitmapError::ScratchTooSmall);
            }
            out[out_offset..end_out].copy_from_slice(&dir[in_offset..end_in]);
            out_offset = end_out;
        }
        in_offset = end_in;
    }
    Ok(out_offset)
}

/// Build the bitmap directory into `out` with entry `index`
/// rewritten to `replacement`, every other entry copied verbatim.
/// Returns the total byte length (equal to `old_len`).
///
/// Used by enable/disable (flip the `BME_FLAG_AUTO` flag) and clear
/// (reset the bitmap-table pointer/size). The `replacement` MUST
/// have the same name — and thus the same serialized entry size —
/// as the entry it replaces: enable/disable/clear only change flags
/// or table fields, never the name. If the replacement's serialized
/// size differs from the original entry's size, this returns
/// [`BitmapError::InternalOverflow`] (a defensive guard — callers do
/// not change the name).
///
/// Returns [`BitmapError::BitmapNotFound`] if `index >= nb_bitmaps`,
/// [`BitmapError::InternalOverflow`] if `old_len` exceeds `old_dir`,
/// an offset overflows, or the replacement's size differs,
/// [`BitmapError::ScratchTooSmall`] if `out` is too small, and
/// [`BitmapError::ParseFailed`] if the walk escapes the directory or
/// the replacement fails to serialize.
pub fn build_directory_replacing(
    old_dir: &[u8],
    old_len: usize,
    nb_bitmaps: u32,
    index: u32,
    replacement: &BitmapDirEntry,
    out: &mut [u8],
) -> Result<usize, BitmapError> {
    if index >= nb_bitmaps {
        return Err(BitmapError::BitmapNotFound);
    }
    if old_len > old_dir.len() {
        return Err(BitmapError::InternalOverflow);
    }
    let dir = &old_dir[..old_len];
    let mut in_offset: usize = 0;
    let mut out_offset: usize = 0;
    for i in 0..nb_bitmaps {
        let rest = dir.get(in_offset..).ok_or(BitmapError::ParseFailed)?;
        let (_entry, entry_size) = parse_bitmap_dir_entry(rest).ok_or(BitmapError::ParseFailed)?;
        let end_in = in_offset
            .checked_add(entry_size)
            .ok_or(BitmapError::InternalOverflow)?;
        let end_out = out_offset
            .checked_add(entry_size)
            .ok_or(BitmapError::InternalOverflow)?;
        if end_out > out.len() {
            return Err(BitmapError::ScratchTooSmall);
        }
        if i == index {
            // Serialize the replacement into a bounded stack scratch
            // first so a size mismatch is diagnosed cleanly (as
            // InternalOverflow) rather than manifesting as a
            // short-buffer ParseFailed when the replacement is larger
            // than the entry it replaces. The replacement MUST have
            // the same name — and thus the same serialized size — as
            // the original entry (enable/disable/clear never change
            // the name). The max entry size is
            // round_up(24 + 1023, 8) = 1048 bytes.
            let mut scratch = [0u8; 1048];
            let written = serialize_bitmap_dir_entry(replacement, &mut scratch)
                .ok_or(BitmapError::ParseFailed)?;
            if written != entry_size {
                return Err(BitmapError::InternalOverflow);
            }
            out[out_offset..end_out].copy_from_slice(&scratch[..written]);
        } else {
            out[out_offset..end_out].copy_from_slice(&dir[in_offset..end_in]);
        }
        in_offset = end_in;
        out_offset = end_out;
    }
    Ok(out_offset)
}

/// Serialize the 24-byte bitmaps header-extension body into `out`,
/// returning 24.
///
/// Body layout (all big-endian), the inverse of
/// [`qcow2::bitmap::parse_bitmaps_extension`]:
///
/// ```text
///   0-3:   nb_bitmaps             (u32)
///   4-7:   reserved               (u32, zero)
///   8-15:  bitmap_directory_size  (u64)
///   16-23: bitmap_directory_offset (u64)
/// ```
///
/// Returns [`BitmapError::ScratchTooSmall`] if `out.len() < 24`.
pub fn serialize_bitmaps_extension(
    nb_bitmaps: u32,
    bitmap_directory_size: u64,
    bitmap_directory_offset: u64,
    out: &mut [u8],
) -> Result<usize, BitmapError> {
    if out.len() < 24 {
        return Err(BitmapError::ScratchTooSmall);
    }
    shared::write_be_u32(out, 0, nb_bitmaps);
    shared::write_be_u32(out, 4, 0);
    shared::write_be_u64(out, 8, bitmap_directory_size);
    shared::write_be_u64(out, 16, bitmap_directory_offset);
    Ok(24)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qcow2::bitmap::{parse_bitmaps_extension, BME_FLAG_AUTO, BT_DIRTY_TRACKING_BITMAP};
    use std::vec::Vec;

    /// Build a `BitmapDirEntry` fixture with the given fields.
    fn dir_entry(
        name: &[u8],
        flags: u32,
        granularity_bits: u8,
        table_offset: u64,
        table_size: u32,
    ) -> BitmapDirEntry {
        let mut e = BitmapDirEntry::zeroed();
        e.bitmap_table_offset = table_offset;
        e.bitmap_table_size = table_size;
        e.flags = flags;
        e.bitmap_type = BT_DIRTY_TRACKING_BITMAP;
        e.granularity_bits = granularity_bits;
        e.name_size = name.len() as u16;
        e.extra_data_size = 0;
        e.name[..name.len()].copy_from_slice(name);
        e
    }

    /// Serialize a slice of entries into a contiguous directory Vec.
    fn build_dir(entries: &[BitmapDirEntry]) -> Vec<u8> {
        let mut dir = Vec::new();
        let mut scratch = [0u8; 1200];
        for e in entries {
            let n = serialize_bitmap_dir_entry(e, &mut scratch).expect("serialize");
            dir.extend_from_slice(&scratch[..n]);
        }
        dir
    }

    /// The expected padded size of an entry with the given name.
    fn entry_size_of(name_len: usize) -> usize {
        (24 + name_len + 7) & !7
    }

    // A varied 3-entry fixture: distinct names (lengths chosen so
    // entry sizes are NOT all equal), flags, granularities, table
    // pointers.
    fn three_entries() -> [BitmapDirEntry; 3] {
        [
            dir_entry(b"alpha", BME_FLAG_AUTO, 16, 0x10000, 1), // 24+5 -> 32
            dir_entry(b"a-much-longer-bitmap-name", 0, 12, 0x20000, 2), // 24+25=49 -> 56
            dir_entry(b"g", BME_FLAG_AUTO, 9, 0x30000, 3),      // 24+1 -> 32
        ]
    }

    // -------------------- directory_byte_len --------------------

    #[test]
    fn byte_len_zero_entries() {
        assert_eq!(directory_byte_len(&[], 0).unwrap(), 0);
    }

    #[test]
    fn byte_len_single_entry() {
        let dir = build_dir(&[dir_entry(b"only", BME_FLAG_AUTO, 16, 0x1000, 1)]);
        assert_eq!(dir.len(), entry_size_of(4)); // 24+4 -> 32
        assert_eq!(directory_byte_len(&dir, 1).unwrap(), dir.len());
    }

    #[test]
    fn byte_len_three_entries() {
        let dir = build_dir(&three_entries());
        let expected = entry_size_of(5) + entry_size_of(25) + entry_size_of(1);
        assert_eq!(dir.len(), expected);
        assert_eq!(directory_byte_len(&dir, 3).unwrap(), expected);
    }

    #[test]
    fn byte_len_truncated_is_parse_failed() {
        let dir = build_dir(&three_entries());
        // Truncate mid-directory so the last entry cannot parse.
        assert_eq!(
            directory_byte_len(&dir[..dir.len() - 4], 3),
            Err(BitmapError::ParseFailed)
        );
        // Claim more entries than the buffer holds.
        assert_eq!(directory_byte_len(&dir, 4), Err(BitmapError::ParseFailed));
    }

    // -------------------- entry_bounds --------------------

    #[test]
    fn entry_bounds_first_middle_last() {
        let dir = build_dir(&three_entries());
        let s0 = entry_size_of(5);
        let s1 = entry_size_of(25);
        let s2 = entry_size_of(1);
        assert_eq!(entry_bounds(&dir, 3, 0).unwrap(), (0, s0));
        assert_eq!(entry_bounds(&dir, 3, 1).unwrap(), (s0, s1));
        assert_eq!(entry_bounds(&dir, 3, 2).unwrap(), (s0 + s1, s2));
    }

    #[test]
    fn entry_bounds_out_of_range() {
        let dir = build_dir(&three_entries());
        assert_eq!(entry_bounds(&dir, 3, 3), Err(BitmapError::BitmapNotFound));
        assert_eq!(entry_bounds(&[], 0, 0), Err(BitmapError::BitmapNotFound));
    }

    #[test]
    fn entry_bounds_truncated_is_parse_failed() {
        let dir = build_dir(&three_entries());
        // Ask for entry 2 in a buffer truncated before it.
        assert_eq!(
            entry_bounds(&dir[..entry_size_of(5) + 4], 3, 2),
            Err(BitmapError::ParseFailed)
        );
    }

    // -------------------- find_bitmap --------------------

    #[test]
    fn find_present_returns_index_offset_entry() {
        let dir = build_dir(&three_entries());
        let f = find_bitmap(&dir, 3, b"a-much-longer-bitmap-name")
            .unwrap()
            .unwrap();
        assert_eq!(f.index, 1);
        assert_eq!(f.byte_offset, entry_size_of(5));
        assert_eq!(f.entry_size, entry_size_of(25));
        assert_eq!(f.entry.name_bytes(), b"a-much-longer-bitmap-name");
        assert_eq!(f.entry.bitmap_table_offset, 0x20000);
        assert_eq!(f.entry.granularity_bits, 12);
        assert!(!f.entry.is_enabled());
    }

    #[test]
    fn find_first_and_last() {
        let dir = build_dir(&three_entries());
        let f0 = find_bitmap(&dir, 3, b"alpha").unwrap().unwrap();
        assert_eq!(f0.index, 0);
        assert_eq!(f0.byte_offset, 0);
        let f2 = find_bitmap(&dir, 3, b"g").unwrap().unwrap();
        assert_eq!(f2.index, 2);
        assert_eq!(f2.byte_offset, entry_size_of(5) + entry_size_of(25));
    }

    #[test]
    fn find_absent_is_none() {
        let dir = build_dir(&three_entries());
        assert_eq!(find_bitmap(&dir, 3, b"nosuch").unwrap(), None);
        // A prefix of a real name must not match (full-name compare).
        assert_eq!(find_bitmap(&dir, 3, b"alph").unwrap(), None);
    }

    #[test]
    fn find_in_empty_directory() {
        assert_eq!(find_bitmap(&[], 0, b"x").unwrap(), None);
    }

    #[test]
    fn find_truncated_is_parse_failed() {
        let dir = build_dir(&three_entries());
        // Search for the last name in a truncated buffer: the walk
        // escapes before reaching it.
        assert_eq!(
            find_bitmap(&dir[..entry_size_of(5) + 4], 3, b"g"),
            Err(BitmapError::ParseFailed)
        );
    }

    // -------------------- build_directory_with_added --------------------

    #[test]
    fn add_appends_and_preserves_old_bytes() {
        let old_entries = three_entries();
        let old = build_dir(&old_entries);
        let old_len = old.len();
        let new = dir_entry(b"new-bitmap", BME_FLAG_AUTO, 16, 0x40000, 4);
        let mut out = [0u8; 512];
        let total = build_directory_with_added(&old, old_len, 3, &new, &mut out).unwrap();
        assert_eq!(total, old_len + entry_size_of(10)); // 24+10 -> 40
                                                        // Old bytes verbatim.
        assert_eq!(&out[..old_len], &old[..]);
        // The full result re-walks as a 4-entry directory.
        assert_eq!(directory_byte_len(&out[..total], 4).unwrap(), total);
        // The appended entry parses back correctly.
        let f = find_bitmap(&out[..total], 4, b"new-bitmap")
            .unwrap()
            .unwrap();
        assert_eq!(f.index, 3);
        assert_eq!(f.entry.bitmap_table_offset, 0x40000);
        assert_eq!(f.entry.granularity_bits, 16);
        assert!(f.entry.is_enabled());
    }

    #[test]
    fn add_to_empty_directory() {
        let new = dir_entry(b"first", BME_FLAG_AUTO, 16, 0x1000, 1);
        let mut out = [0u8; 128];
        let total = build_directory_with_added(&[], 0, 0, &new, &mut out).unwrap();
        assert_eq!(total, entry_size_of(5));
        let f = find_bitmap(&out[..total], 1, b"first").unwrap().unwrap();
        assert_eq!(f.index, 0);
    }

    #[test]
    fn add_rejects_small_out() {
        let old = build_dir(&three_entries());
        let old_len = old.len();
        let new = dir_entry(b"new-bitmap", BME_FLAG_AUTO, 16, 0x40000, 4);
        // Big enough for the old bytes but not the appended entry.
        let mut out = std::vec![0u8; old_len + 8];
        assert_eq!(
            build_directory_with_added(&old, old_len, 3, &new, &mut out),
            Err(BitmapError::ParseFailed)
        );
        // Not even big enough for the old bytes.
        let mut tiny = [0u8; 16];
        assert_eq!(
            build_directory_with_added(&old, old_len, 3, &new, &mut tiny),
            Err(BitmapError::ScratchTooSmall)
        );
    }

    #[test]
    fn add_rejects_old_len_beyond_slice() {
        let old = build_dir(&three_entries());
        let new = dir_entry(b"x", BME_FLAG_AUTO, 16, 0x40000, 4);
        let mut out = [0u8; 512];
        assert_eq!(
            build_directory_with_added(&old, old.len() + 1, 3, &new, &mut out),
            Err(BitmapError::InternalOverflow)
        );
    }

    // -------------------- build_directory_without --------------------

    /// Parse every entry's name out of a directory, in order.
    fn names_of(dir: &[u8], nb: u32) -> Vec<Vec<u8>> {
        let mut names = Vec::new();
        let mut off = 0usize;
        for _ in 0..nb {
            let (e, sz) = parse_bitmap_dir_entry(&dir[off..]).unwrap();
            names.push(e.name_bytes().to_vec());
            off += sz;
        }
        names
    }

    #[test]
    fn without_first_compacts() {
        let old = build_dir(&three_entries());
        let old_len = old.len();
        let mut out = [0xEEu8; 512];
        let total = build_directory_without(&old, old_len, 3, 0, &mut out).unwrap();
        assert_eq!(total, entry_size_of(25) + entry_size_of(1));
        assert_eq!(directory_byte_len(&out[..total], 2).unwrap(), total);
        assert_eq!(
            names_of(&out[..total], 2),
            std::vec![b"a-much-longer-bitmap-name".to_vec(), b"g".to_vec()]
        );
    }

    #[test]
    fn without_middle_compacts() {
        let old = build_dir(&three_entries());
        let old_len = old.len();
        let mut out = [0xEEu8; 512];
        let total = build_directory_without(&old, old_len, 3, 1, &mut out).unwrap();
        assert_eq!(total, entry_size_of(5) + entry_size_of(1));
        assert_eq!(
            names_of(&out[..total], 2),
            std::vec![b"alpha".to_vec(), b"g".to_vec()]
        );
        // The surviving first entry is byte-identical to the original.
        assert_eq!(&out[..entry_size_of(5)], &old[..entry_size_of(5)]);
    }

    #[test]
    fn without_last_is_prefix() {
        let old = build_dir(&three_entries());
        let old_len = old.len();
        let mut out = [0xEEu8; 512];
        let total = build_directory_without(&old, old_len, 3, 2, &mut out).unwrap();
        let prefix = entry_size_of(5) + entry_size_of(25);
        assert_eq!(total, prefix);
        // Removing the last entry leaves the old prefix verbatim.
        assert_eq!(&out[..total], &old[..prefix]);
        assert_eq!(
            names_of(&out[..total], 2),
            std::vec![b"alpha".to_vec(), b"a-much-longer-bitmap-name".to_vec()]
        );
    }

    #[test]
    fn without_sole_entry_yields_zero() {
        let old = build_dir(&[dir_entry(b"only", BME_FLAG_AUTO, 16, 0x1000, 1)]);
        let mut out = [0xEEu8; 64];
        assert_eq!(
            build_directory_without(&old, old.len(), 1, 0, &mut out).unwrap(),
            0
        );
    }

    #[test]
    fn without_rejects_bad_args() {
        let old = build_dir(&three_entries());
        let old_len = old.len();
        let mut out = [0u8; 512];
        assert_eq!(
            build_directory_without(&old, old_len, 3, 3, &mut out),
            Err(BitmapError::BitmapNotFound)
        );
        assert_eq!(
            build_directory_without(&old, old.len() + 1, 3, 0, &mut out),
            Err(BitmapError::InternalOverflow)
        );
        let mut tiny = [0u8; 16];
        assert_eq!(
            build_directory_without(&old, old_len, 3, 0, &mut tiny),
            Err(BitmapError::ScratchTooSmall)
        );
    }

    #[test]
    fn without_truncated_is_parse_failed() {
        let old = build_dir(&three_entries());
        // old_len claims the whole dir but the slice is truncated.
        let short = &old[..entry_size_of(5) + 4];
        let mut out = [0u8; 512];
        assert_eq!(
            build_directory_without(short, short.len(), 3, 0, &mut out),
            Err(BitmapError::ParseFailed)
        );
    }

    // -------------------- build_directory_replacing --------------------

    #[test]
    fn replacing_flips_auto_flag_only() {
        let entries = three_entries();
        let old = build_dir(&entries);
        let old_len = old.len();
        // Replace entry 1 (currently disabled) with an enabled copy.
        let mut repl = entries[1];
        repl.flags |= BME_FLAG_AUTO;
        let mut out = [0u8; 512];
        let total = build_directory_replacing(&old, old_len, 3, 1, &repl, &mut out).unwrap();
        // Length unchanged.
        assert_eq!(total, old_len);
        // Entries 0 and 2 are byte-identical to the originals.
        let s0 = entry_size_of(5);
        let s1 = entry_size_of(25);
        assert_eq!(&out[..s0], &old[..s0]);
        assert_eq!(&out[s0 + s1..total], &old[s0 + s1..old_len]);
        // Entry 1 now has the auto flag; nothing else changed.
        let f = find_bitmap(&out[..total], 3, b"a-much-longer-bitmap-name")
            .unwrap()
            .unwrap();
        assert_eq!(f.index, 1);
        assert!(f.entry.is_enabled());
        assert_eq!(f.entry.bitmap_table_offset, 0x20000);
        assert_eq!(f.entry.granularity_bits, 12);
        // The other entries' enabled state is unchanged.
        assert!(find_bitmap(&out[..total], 3, b"alpha")
            .unwrap()
            .unwrap()
            .entry
            .is_enabled());
        assert!(find_bitmap(&out[..total], 3, b"g")
            .unwrap()
            .unwrap()
            .entry
            .is_enabled());
    }

    #[test]
    fn replacing_disable_round_trips_enable() {
        let entries = three_entries();
        let old = build_dir(&entries);
        let old_len = old.len();
        // Entry 0 is enabled; disable it (clear auto).
        let mut repl = entries[0];
        repl.flags &= !BME_FLAG_AUTO;
        let mut out = [0u8; 512];
        let total = build_directory_replacing(&old, old_len, 3, 0, &repl, &mut out).unwrap();
        assert_eq!(total, old_len);
        let f = find_bitmap(&out[..total], 3, b"alpha").unwrap().unwrap();
        assert!(!f.entry.is_enabled());
    }

    #[test]
    fn replacing_resets_table_pointer() {
        // clear's use: same name, table pointer/size reset to zero.
        let entries = three_entries();
        let old = build_dir(&entries);
        let old_len = old.len();
        let mut repl = entries[1];
        repl.bitmap_table_offset = 0;
        repl.bitmap_table_size = 0;
        let mut out = [0u8; 512];
        let total = build_directory_replacing(&old, old_len, 3, 1, &repl, &mut out).unwrap();
        assert_eq!(total, old_len);
        let f = find_bitmap(&out[..total], 3, b"a-much-longer-bitmap-name")
            .unwrap()
            .unwrap();
        assert_eq!(f.entry.bitmap_table_offset, 0);
        assert_eq!(f.entry.bitmap_table_size, 0);
    }

    #[test]
    fn replacing_size_mismatch_is_internal_overflow() {
        // A replacement with a different-length name serializes to a
        // different size and must be rejected.
        let entries = three_entries();
        let old = build_dir(&entries);
        let old_len = old.len();
        // Replace entry 0 ("alpha", size 32) with a longer name that
        // rounds up to a larger entry.
        let repl = dir_entry(
            b"a-name-that-is-clearly-longer",
            BME_FLAG_AUTO,
            16,
            0x10000,
            1,
        );
        let mut out = [0u8; 512];
        assert_eq!(
            build_directory_replacing(&old, old_len, 3, 0, &repl, &mut out),
            Err(BitmapError::InternalOverflow)
        );
    }

    #[test]
    fn replacing_rejects_bad_args() {
        let entries = three_entries();
        let old = build_dir(&entries);
        let old_len = old.len();
        let repl = entries[0];
        let mut out = [0u8; 512];
        assert_eq!(
            build_directory_replacing(&old, old_len, 3, 3, &repl, &mut out),
            Err(BitmapError::BitmapNotFound)
        );
        assert_eq!(
            build_directory_replacing(&old, old.len() + 1, 3, 0, &repl, &mut out),
            Err(BitmapError::InternalOverflow)
        );
        // out too small to hold even the first (replaced) entry copy.
        let mut tiny = [0u8; 16];
        assert_eq!(
            build_directory_replacing(&old, old_len, 3, 0, &repl, &mut tiny),
            Err(BitmapError::ScratchTooSmall)
        );
    }

    // -------------------- serialize_bitmaps_extension --------------------

    #[test]
    fn extension_round_trips_through_parser() {
        let mut out = [0u8; 24];
        let n = serialize_bitmaps_extension(2, 1024, 0x40000, &mut out).unwrap();
        assert_eq!(n, 24);
        let ext = parse_bitmaps_extension(&out).unwrap();
        assert_eq!(ext.nb_bitmaps, 2);
        assert_eq!(ext.bitmap_directory_size, 1024);
        assert_eq!(ext.bitmap_directory_offset, 0x40000);
    }

    #[test]
    fn extension_reserved_word_is_zero() {
        let mut out = [0xFFu8; 24];
        serialize_bitmaps_extension(1, 512, 0x10000, &mut out).unwrap();
        assert_eq!(&out[4..8], &[0, 0, 0, 0]);
    }

    #[test]
    fn extension_rejects_small_out() {
        let mut out = [0u8; 23];
        assert_eq!(
            serialize_bitmaps_extension(1, 512, 0x10000, &mut out),
            Err(BitmapError::ScratchTooSmall)
        );
    }

    #[test]
    fn extension_round_trips_larger_out() {
        // A larger buffer: only the first 24 bytes are the body.
        let mut out = [0u8; 64];
        let n = serialize_bitmaps_extension(5, 0x2000, 0x8_0000, &mut out).unwrap();
        assert_eq!(n, 24);
        let ext = parse_bitmaps_extension(&out[..24]).unwrap();
        assert_eq!(ext.nb_bitmaps, 5);
        assert_eq!(ext.bitmap_directory_size, 0x2000);
        assert_eq!(ext.bitmap_directory_offset, 0x8_0000);
    }
}
