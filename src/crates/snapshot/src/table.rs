//! Snapshot-table serialisation helpers for MODE_CREATE.
//!
//! Pure functions over caller-staged byte slices — no I/O. These
//! compose the on-disk snapshot table that the phase 6 create
//! guest binary writes to a freshly allocated region:
//!
//! - [`NewSnapshotEntry`] + [`serialize_snapshot_entry`] emit one
//!   new entry (40-byte header + 24-byte extra data + id + name),
//!   matching `qcow2_write_snapshots` in
//!   `block/qcow2-snapshot.c` from qemu 10.0.x.
//! - [`snapshot_table_byte_len`] walks the raw old table to find
//!   its exact byte length so the guest can stage / copy / free it.
//! - [`snapshot_table_entry_bounds`] returns one raw entry's
//!   (start offset, unpadded length) for MODE_DELETE's
//!   find-by-name walk and compaction maths (phase 7).
//! - [`build_snapshot_table`] copies the old entries verbatim and
//!   8-aligns the new entry after them.
//! - [`build_snapshot_table_without`] copies every entry except
//!   one verbatim, re-aligning survivors — MODE_DELETE's table
//!   compaction (phase 7), matching `qcow2_write_snapshots`'
//!   full-table rewrite after the in-memory `memmove`.
//! - [`parse_decimal_id`] / [`format_decimal_u64`] implement
//!   qemu's `find_new_snapshot_id` ID arithmetic (strtoul-style
//!   parse, `%lu`-style render).
//!
//! The on-disk snapshot header layout (big-endian) is the read
//! oracle in `qcow2::parse_snapshot_header_bytes`:
//!
//! ```text
//!   0-7:   l1_table_offset (u64)
//!   8-11:  l1_size         (u32)
//!   12-13: id_str_size     (u16)
//!   14-15: name_size       (u16)
//!   16-19: date_sec        (u32)
//!   20-23: date_nsec       (u32)
//!   24-31: vm_clock_nsec   (u64)
//!   32-35: vm_state_size   (u32)
//!   36-39: extra_data_size (u32)
//! ```
//!
//! followed by `extra_data_size` bytes of extra data (the first
//! 24 of which are `vm_state_size_large` / `disk_size` / `icount`,
//! each a big-endian u64), then the id string, then the name
//! string.

use crate::SnapshotError;

/// Fixed on-disk snapshot header size, in bytes.
pub const SNAPSHOT_HEADER_SIZE: usize = 40;

/// qemu's `QCowSnapshotExtraData` size (three big-endian u64s:
/// `vm_state_size_large`, `disk_size`, `icount`). qemu always
/// writes at least this much extra data
/// (`MAX(sizeof(extra), sn->extra_data_size)`); a fresh entry uses
/// exactly this.
pub const SNAPSHOT_EXTRA_DATA_SIZE: usize = 24;

/// A new snapshot-table entry to serialise.
///
/// Field order mirrors `qcow2::parse_snapshot_header_bytes` (the
/// read oracle) plus the three extra-data u64s. `id` and `name`
/// are the raw UTF-8 bytes (no nul terminator); their lengths are
/// taken from the slice lengths and written into `id_str_size` /
/// `name_size`.
#[derive(Debug, Clone, Copy)]
pub struct NewSnapshotEntry<'a> {
    /// Host byte offset of this snapshot's L1 table copy.
    pub l1_table_offset: u64,
    /// Number of entries in this snapshot's L1 table.
    pub l1_size: u32,
    /// Snapshot ID bytes (decimal string; no nul).
    pub id: &'a [u8],
    /// Snapshot name bytes (UTF-8; no nul).
    pub name: &'a [u8],
    /// Creation timestamp seconds (host wall clock).
    pub date_sec: u32,
    /// Creation timestamp sub-second nanoseconds.
    pub date_nsec: u32,
    /// VM clock at creation (nanoseconds). Zero for `qemu-img`.
    pub vm_clock_nsec: u64,
    /// Legacy 32-bit VM state size. Zero for `qemu-img`.
    pub vm_state_size: u32,
    /// 64-bit VM state size (extra-data offset 0). Zero for
    /// `qemu-img`.
    pub vm_state_size_large: u64,
    /// Virtual disk size at creation (extra-data offset 8). Equals
    /// the image's virtual size.
    pub disk_size: u64,
    /// qemu record/replay icount (extra-data offset 16). `0` for
    /// `qemu-img` (it memsets the whole `QEMUSnapshotInfo`, so
    /// icount is 0, not the `u64::MAX` "absent" sentinel — see
    /// phase plan fact 4).
    pub icount: u64,
}

/// Serialise one [`NewSnapshotEntry`] into `out`, returning the
/// unpadded byte length written
/// (`40 + 24 + id.len() + name.len()`).
///
/// Emits the 40-byte big-endian header (with `extra_data_size =
/// 24`), the 24-byte extra data, the id bytes, then the name
/// bytes. No trailing pad — the caller 8-aligns the *next* entry,
/// exactly like `qcow2_write_snapshots`.
///
/// Returns [`SnapshotError::MisalignedAccess`] if `out` is too
/// small, or [`SnapshotError::InvalidConfig`] if `id` / `name`
/// exceed the on-disk `u16` length field.
pub fn serialize_snapshot_entry(
    e: &NewSnapshotEntry<'_>,
    out: &mut [u8],
) -> Result<usize, SnapshotError> {
    if e.id.len() > u16::MAX as usize || e.name.len() > u16::MAX as usize {
        return Err(SnapshotError::InvalidConfig);
    }
    let total = SNAPSHOT_HEADER_SIZE + SNAPSHOT_EXTRA_DATA_SIZE + e.id.len() + e.name.len();
    if out.len() < total {
        return Err(SnapshotError::MisalignedAccess);
    }

    // 40-byte header.
    out[0..8].copy_from_slice(&e.l1_table_offset.to_be_bytes());
    out[8..12].copy_from_slice(&e.l1_size.to_be_bytes());
    out[12..14].copy_from_slice(&(e.id.len() as u16).to_be_bytes());
    out[14..16].copy_from_slice(&(e.name.len() as u16).to_be_bytes());
    out[16..20].copy_from_slice(&e.date_sec.to_be_bytes());
    out[20..24].copy_from_slice(&e.date_nsec.to_be_bytes());
    out[24..32].copy_from_slice(&e.vm_clock_nsec.to_be_bytes());
    out[32..36].copy_from_slice(&e.vm_state_size.to_be_bytes());
    out[36..40].copy_from_slice(&(SNAPSHOT_EXTRA_DATA_SIZE as u32).to_be_bytes());

    // 24-byte extra data.
    out[40..48].copy_from_slice(&e.vm_state_size_large.to_be_bytes());
    out[48..56].copy_from_slice(&e.disk_size.to_be_bytes());
    out[56..64].copy_from_slice(&e.icount.to_be_bytes());

    // id then name.
    let id_start = SNAPSHOT_HEADER_SIZE + SNAPSHOT_EXTRA_DATA_SIZE;
    out[id_start..id_start + e.id.len()].copy_from_slice(e.id);
    let name_start = id_start + e.id.len();
    out[name_start..name_start + e.name.len()].copy_from_slice(e.name);

    Ok(total)
}

/// Compute the bounds of the raw entry starting at (or after, once
/// 8-aligned) `offset` within `table`. Returns the entry's
/// `(aligned_start, unpadded_len)`.
///
/// Shared walk core for [`snapshot_table_byte_len`] and
/// [`snapshot_table_entry_bounds`]: 8-align the start, read the
/// 40-byte header's `extra_data_size` / `id_str_size` /
/// `name_size`, and advance by `40 + extra + id + name`. Returns
/// [`SnapshotError::ParseFailed`] if the entry would escape
/// `table`.
fn entry_bounds_at(table: &[u8], offset: usize) -> Result<(usize, usize), SnapshotError> {
    // 8-align the entry start.
    let start = round_up_8(offset).ok_or(SnapshotError::ParseFailed)?;
    let header_end = start
        .checked_add(SNAPSHOT_HEADER_SIZE)
        .ok_or(SnapshotError::ParseFailed)?;
    if header_end > table.len() {
        return Err(SnapshotError::ParseFailed);
    }
    let extra_data_size = u32::from_be_bytes([
        table[start + 36],
        table[start + 37],
        table[start + 38],
        table[start + 39],
    ]) as usize;
    let id_str_size = u16::from_be_bytes([table[start + 12], table[start + 13]]) as usize;
    let name_size = u16::from_be_bytes([table[start + 14], table[start + 15]]) as usize;
    let entry_len = SNAPSHOT_HEADER_SIZE
        .checked_add(extra_data_size)
        .and_then(|v| v.checked_add(id_str_size))
        .and_then(|v| v.checked_add(name_size))
        .ok_or(SnapshotError::ParseFailed)?;
    let entry_end = start
        .checked_add(entry_len)
        .ok_or(SnapshotError::ParseFailed)?;
    if entry_end > table.len() {
        return Err(SnapshotError::ParseFailed);
    }
    Ok((start, entry_len))
}

/// Walk the raw on-disk snapshot table `table` for `nb_snapshots`
/// entries and return the total byte length up to the unpadded end
/// of the last entry.
///
/// Entries start at 8-aligned offsets. Each entry advances by
/// `40 + extra_data_size + id_str_size + name_size`, and the
/// *next* entry's start is rounded up to the next 8-byte boundary.
/// The returned length is the end of the last entry **without** a
/// trailing pad, matching what `qemu-img` writes (phase plan
/// fact 4).
///
/// Walks raw headers directly so it is independent of the bounded
/// parser's 63-char id/name truncation. Returns
/// [`SnapshotError::ParseFailed`] if a walk would escape `table`.
pub fn snapshot_table_byte_len(table: &[u8], nb_snapshots: u32) -> Result<usize, SnapshotError> {
    let mut offset: usize = 0;
    for _ in 0..nb_snapshots {
        let (start, len) = entry_bounds_at(table, offset)?;
        offset = start + len;
    }
    Ok(offset)
}

/// Return the `(start_offset, unpadded_length)` of raw entry
/// `index` within `table`, walking entries exactly like
/// [`snapshot_table_byte_len`].
///
/// MODE_DELETE (phase 7) uses this to find the matched entry's raw
/// bytes (the find-by-name walk compares the full on-disk name,
/// independent of the bounded parser's 63-char truncation) and to
/// compute the compaction copy ranges.
///
/// Returns [`SnapshotError::InvalidConfig`] if
/// `index >= nb_snapshots`, or [`SnapshotError::ParseFailed`] if
/// the walk would escape `table`.
pub fn snapshot_table_entry_bounds(
    table: &[u8],
    nb_snapshots: u32,
    index: u32,
) -> Result<(usize, usize), SnapshotError> {
    if index >= nb_snapshots {
        return Err(SnapshotError::InvalidConfig);
    }
    let mut offset: usize = 0;
    for i in 0..=index {
        let (start, len) = entry_bounds_at(table, offset)?;
        if i == index {
            return Ok((start, len));
        }
        offset = start + len;
    }
    // Unreachable: the loop returns at i == index.
    Err(SnapshotError::ParseFailed)
}

/// Build the new snapshot table into `out`: the old entries copied
/// verbatim, zero-padded to the next 8-byte boundary, then the
/// already-serialised `new_entry` appended. Returns the total
/// byte length (unpadded after the new entry, matching qemu).
///
/// `old_len` is the exact byte length of the old table (from
/// [`snapshot_table_byte_len`]); `old_table[..old_len]` is copied
/// verbatim so any unknown trailing extra data on the old entries
/// is preserved. The gap bytes between the verbatim copy and the
/// 8-aligned append are zeroed.
///
/// Returns [`SnapshotError::MisalignedAccess`] if `out` is too
/// small or `old_len` exceeds `old_table`.
pub fn build_snapshot_table(
    old_table: &[u8],
    old_len: usize,
    new_entry: &[u8],
    out: &mut [u8],
) -> Result<usize, SnapshotError> {
    if old_len > old_table.len() {
        return Err(SnapshotError::MisalignedAccess);
    }
    let aligned = round_up_8(old_len).ok_or(SnapshotError::ParseFailed)?;
    let total = aligned
        .checked_add(new_entry.len())
        .ok_or(SnapshotError::ParseFailed)?;
    if out.len() < total {
        return Err(SnapshotError::MisalignedAccess);
    }
    // Verbatim copy of the old entries.
    out[..old_len].copy_from_slice(&old_table[..old_len]);
    // Zero the alignment gap.
    for b in out.iter_mut().take(aligned).skip(old_len) {
        *b = 0;
    }
    // Append the new entry.
    out[aligned..total].copy_from_slice(new_entry);
    Ok(total)
}

/// Build the compacted snapshot table into `out`: every entry of
/// the old table except `remove_index` copied verbatim, each
/// surviving entry starting at the next 8-aligned output offset
/// with the alignment gaps zeroed. Returns the total byte length
/// (unpadded after the last surviving entry, matching qemu).
///
/// This is MODE_DELETE's table compaction (phase 7, open
/// question 5): a verbatim per-entry copy preserves unknown
/// trailing extra data byte-for-byte, exactly what the
/// byte-identity matrix against `qemu-img snapshot -d` requires.
/// Removing the sole remaining entry yields length 0 (the caller
/// then writes header `nb_snapshots = 0, snapshots_offset = 0`
/// and allocates no table — phase plan fact 3).
///
/// `old_len` is the exact byte length of the old table (from
/// [`snapshot_table_byte_len`]); only `old_table[..old_len]` is
/// walked. Returns [`SnapshotError::InvalidConfig`] if
/// `remove_index >= nb_snapshots`,
/// [`SnapshotError::MisalignedAccess`] if `old_len` exceeds
/// `old_table` or `out` is too small, and
/// [`SnapshotError::ParseFailed`] if the walk escapes the table.
pub fn build_snapshot_table_without(
    old_table: &[u8],
    old_len: usize,
    nb_snapshots: u32,
    remove_index: u32,
    out: &mut [u8],
) -> Result<usize, SnapshotError> {
    if remove_index >= nb_snapshots {
        return Err(SnapshotError::InvalidConfig);
    }
    if old_len > old_table.len() {
        return Err(SnapshotError::MisalignedAccess);
    }
    let table = &old_table[..old_len];
    let mut in_offset: usize = 0;
    let mut out_offset: usize = 0;
    for i in 0..nb_snapshots {
        let (start, len) = entry_bounds_at(table, in_offset)?;
        in_offset = start + len;
        if i == remove_index {
            continue;
        }
        // 8-align the surviving entry's output start, zeroing the
        // alignment gap.
        let aligned = round_up_8(out_offset).ok_or(SnapshotError::ParseFailed)?;
        let end = aligned.checked_add(len).ok_or(SnapshotError::ParseFailed)?;
        if end > out.len() {
            return Err(SnapshotError::MisalignedAccess);
        }
        for b in out.iter_mut().take(aligned).skip(out_offset) {
            *b = 0;
        }
        out[aligned..end].copy_from_slice(&table[start..start + len]);
        out_offset = end;
    }
    Ok(out_offset)
}

/// Parse the leading decimal digits of `id`, strtoul-style.
///
/// Mirrors qemu's `find_new_snapshot_id`, which calls
/// `strtoul(sn->id_str, NULL, 10)`: leading decimal digits are
/// parsed; a non-numeric ID (or an empty one) yields 0, and
/// trailing non-digits are ignored. So `"abc"` parses as 0 (it is
/// then treated as id_max contribution 0) and `"3x"` parses as 3.
///
/// Returns `None` only on arithmetic overflow of the accumulated
/// value (a u64 cannot overflow from a realistic id string, but
/// the bound is defensive against adversarial input). An empty or
/// fully non-numeric id returns `Some(0)`.
pub fn parse_decimal_id(id: &[u8]) -> Option<u64> {
    let mut value: u64 = 0;
    let mut saw_digit = false;
    for &b in id {
        if b.is_ascii_digit() {
            saw_digit = true;
            value = value.checked_mul(10)?.checked_add((b - b'0') as u64)?;
        } else {
            // strtoul stops at the first non-digit.
            break;
        }
    }
    let _ = saw_digit;
    Some(value)
}

/// Render `v` as a decimal ASCII string into `out`, returning the
/// number of bytes written. Mirrors qemu's `snprintf(..., "%lu",
/// id_max + 1)`. `out` must be at least 20 bytes (the widest u64
/// decimal). Returns 0 if `out` is too small.
pub fn format_decimal_u64(v: u64, out: &mut [u8]) -> usize {
    // u64::MAX is 20 decimal digits.
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    let mut value = v;
    if value == 0 {
        tmp[0] = b'0';
        n = 1;
    } else {
        while value > 0 {
            tmp[n] = b'0' + (value % 10) as u8;
            value /= 10;
            n += 1;
        }
    }
    if out.len() < n {
        return 0;
    }
    // tmp holds the digits least-significant-first; reverse into out.
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
}

/// Round `v` up to the next multiple of 8, returning `None` on
/// overflow.
fn round_up_8(v: usize) -> Option<usize> {
    v.checked_add(7).map(|x| x & !7)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qcow2::OFLAG_COPIED;

    // -------------------- serialize_snapshot_entry --------------------

    fn sample_entry<'a>(id: &'a [u8], name: &'a [u8]) -> NewSnapshotEntry<'a> {
        NewSnapshotEntry {
            l1_table_offset: 0x4_0000,
            l1_size: 3,
            id,
            name,
            date_sec: 0x1122_3344,
            date_nsec: 1_000,
            vm_clock_nsec: 0,
            vm_state_size: 0,
            vm_state_size_large: 0,
            disk_size: 0x0400_0000, // 64 MiB
            icount: 0,
        }
    }

    #[test]
    fn serialize_lengths_and_no_trailing_pad() {
        let e = sample_entry(b"1", b"snap1");
        let mut out = [0u8; 128];
        let n = serialize_snapshot_entry(&e, &mut out).unwrap();
        // 40 header + 24 extra + 1 id + 5 name = 70, no pad.
        assert_eq!(n, 70);
    }

    #[test]
    fn serialize_round_trips_through_parser() {
        // The on-disk bytes must decode through the same path the
        // streaming list parser uses. We reproduce the header /
        // extra-data decode inline (matching
        // qcow2::parse_snapshot_header_bytes) and assert equality.
        let e = sample_entry(b"7", b"my-snapshot");
        let mut out = [0u8; 128];
        let n = serialize_snapshot_entry(&e, &mut out).unwrap();
        let buf = &out[..n];

        assert_eq!(
            u64::from_be_bytes(buf[0..8].try_into().unwrap()),
            e.l1_table_offset
        );
        assert_eq!(
            u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            e.l1_size
        );
        assert_eq!(
            u16::from_be_bytes(buf[12..14].try_into().unwrap()),
            e.id.len() as u16
        );
        assert_eq!(
            u16::from_be_bytes(buf[14..16].try_into().unwrap()),
            e.name.len() as u16
        );
        assert_eq!(
            u32::from_be_bytes(buf[16..20].try_into().unwrap()),
            e.date_sec
        );
        assert_eq!(
            u32::from_be_bytes(buf[20..24].try_into().unwrap()),
            e.date_nsec
        );
        assert_eq!(
            u64::from_be_bytes(buf[24..32].try_into().unwrap()),
            e.vm_clock_nsec
        );
        assert_eq!(
            u32::from_be_bytes(buf[32..36].try_into().unwrap()),
            e.vm_state_size
        );
        assert_eq!(u32::from_be_bytes(buf[36..40].try_into().unwrap()), 24);
        // extra data
        assert_eq!(
            u64::from_be_bytes(buf[40..48].try_into().unwrap()),
            e.vm_state_size_large
        );
        assert_eq!(
            u64::from_be_bytes(buf[48..56].try_into().unwrap()),
            e.disk_size
        );
        assert_eq!(
            u64::from_be_bytes(buf[56..64].try_into().unwrap()),
            e.icount
        );
        // id then name
        assert_eq!(&buf[64..64 + e.id.len()], e.id);
        assert_eq!(&buf[64 + e.id.len()..], e.name);
    }

    #[test]
    fn serialize_icount_is_zero_not_absent_sentinel() {
        // Phase plan fact 4: qemu-img writes icount = 0, not the
        // u64::MAX "absent" sentinel the read side uses.
        let e = sample_entry(b"1", b"x");
        let mut out = [0u8; 128];
        let n = serialize_snapshot_entry(&e, &mut out).unwrap();
        assert_eq!(u64::from_be_bytes(out[56..64].try_into().unwrap()), 0);
        assert_ne!(
            u64::from_be_bytes(out[56..64].try_into().unwrap()),
            u64::MAX
        );
        let _ = n;
    }

    #[test]
    fn serialize_rejects_small_out() {
        let e = sample_entry(b"1", b"snap1");
        let mut out = [0u8; 16];
        assert_eq!(
            serialize_snapshot_entry(&e, &mut out),
            Err(SnapshotError::MisalignedAccess)
        );
    }

    #[test]
    fn serialize_empty_id_and_name() {
        let e = sample_entry(b"", b"");
        let mut out = [0u8; 128];
        let n = serialize_snapshot_entry(&e, &mut out).unwrap();
        assert_eq!(n, 64);
    }

    // -------------------- snapshot_table_byte_len --------------------

    /// Hand-build a snapshot table into `buf` with the given
    /// (id, name, extra_data_size) entries, each 8-aligned. Returns
    /// the unpadded total length (end of the last entry).
    fn build_raw_table(buf: &mut [u8], entries: &[(&[u8], &[u8], usize)]) -> usize {
        let mut pos = 0usize;
        for (id, name, extra) in entries.iter().copied() {
            // 8-align the entry start.
            while pos % 8 != 0 {
                buf[pos] = 0;
                pos += 1;
            }
            // 40-byte header.
            buf[pos + 8..pos + 12].copy_from_slice(&3u32.to_be_bytes()); // l1_size
            buf[pos + 12..pos + 14].copy_from_slice(&(id.len() as u16).to_be_bytes());
            buf[pos + 14..pos + 16].copy_from_slice(&(name.len() as u16).to_be_bytes());
            buf[pos + 36..pos + 40].copy_from_slice(&(extra as u32).to_be_bytes());
            pos += 40;
            // Arbitrary extra data.
            for b in buf.iter_mut().skip(pos).take(extra) {
                *b = 0xAB;
            }
            pos += extra;
            buf[pos..pos + id.len()].copy_from_slice(id);
            pos += id.len();
            buf[pos..pos + name.len()].copy_from_slice(name);
            pos += name.len();
        }
        pos
    }

    #[test]
    fn table_byte_len_two_entries() {
        let mut raw = [0u8; 256];
        let total = build_raw_table(&mut raw, &[(b"1", b"snap1", 24), (b"2", b"snap2", 24)]);
        assert_eq!(snapshot_table_byte_len(&raw[..total], 2).unwrap(), total);
    }

    #[test]
    fn table_byte_len_with_oversized_unknown_extra() {
        // An old entry with extra_data_size = 40 (16 bytes of
        // unknown extra beyond the standard 24) must be measured
        // by its stored extra_data_size, not the standard 24.
        let mut raw = [0u8; 256];
        let total = build_raw_table(&mut raw, &[(b"1", b"a", 40), (b"2", b"b", 24)]);
        assert_eq!(snapshot_table_byte_len(&raw[..total], 2).unwrap(), total);
    }

    #[test]
    fn table_byte_len_single_entry_unpadded() {
        let mut raw = [0u8; 128];
        let total = build_raw_table(&mut raw, &[(b"1", b"snap1", 24)]);
        // 40 + 24 + 1 + 5 = 70.
        assert_eq!(total, 70);
        assert_eq!(snapshot_table_byte_len(&raw[..total], 1).unwrap(), 70);
    }

    #[test]
    fn table_byte_len_zero_snapshots() {
        assert_eq!(snapshot_table_byte_len(&[], 0).unwrap(), 0);
    }

    #[test]
    fn table_byte_len_escape_errors() {
        // A header claiming a huge name that escapes the buffer.
        let mut raw = [0u8; 40];
        raw[14..16].copy_from_slice(&0xFFFFu16.to_be_bytes());
        raw[36..40].copy_from_slice(&24u32.to_be_bytes());
        assert_eq!(
            snapshot_table_byte_len(&raw, 1),
            Err(SnapshotError::ParseFailed)
        );
    }

    // -------------------- build_snapshot_table --------------------

    #[test]
    fn build_preserves_old_bytes_and_aligns_append() {
        // Old table: one entry of length 70 (not 8-aligned).
        let mut old = [0u8; 128];
        let old_len = build_raw_table(&mut old, &[(b"1", b"snap1", 24)]);
        assert_eq!(old_len, 70);
        let new_entry = b"NEWENTRYBYTES";
        let mut out = [0u8; 256];
        let total = build_snapshot_table(&old[..old_len], old_len, new_entry, &mut out).unwrap();
        // 70 rounds up to 72, then 13 bytes of new entry.
        assert_eq!(total, 72 + new_entry.len());
        // Old bytes verbatim.
        assert_eq!(&out[..old_len], &old[..old_len]);
        // Gap zeroed.
        assert_eq!(&out[70..72], &[0, 0]);
        // New entry appended at the 8-aligned offset.
        assert_eq!(&out[72..72 + new_entry.len()], new_entry);
    }

    #[test]
    fn build_preserves_unknown_extra_data_verbatim() {
        // Old entry carries unknown extra data (extra_data_size =
        // 40); build must copy it byte-for-byte.
        let mut old = [0u8; 128];
        let old_len = build_raw_table(&mut old, &[(b"9", b"x", 40)]);
        let new_entry = b"NN";
        let mut out = [0u8; 256];
        build_snapshot_table(&old[..old_len], old_len, new_entry, &mut out).unwrap();
        assert_eq!(&out[..old_len], &old[..old_len]);
    }

    #[test]
    fn build_empty_old_table() {
        // First snapshot: old table is empty (nb_snapshots == 0).
        let new_entry = b"FIRSTENTRY";
        let mut out = [0u8; 64];
        let total = build_snapshot_table(&[], 0, new_entry, &mut out).unwrap();
        assert_eq!(total, new_entry.len());
        assert_eq!(&out[..total], new_entry);
    }

    #[test]
    fn build_rejects_small_out() {
        let new_entry = [0u8; 32];
        let mut out = [0u8; 8];
        assert_eq!(
            build_snapshot_table(&[], 0, &new_entry, &mut out),
            Err(SnapshotError::MisalignedAccess)
        );
    }

    // -------------------- decimal helpers --------------------

    #[test]
    fn parse_decimal_id_cases() {
        assert_eq!(parse_decimal_id(b"0"), Some(0));
        assert_eq!(parse_decimal_id(b"1"), Some(1));
        assert_eq!(parse_decimal_id(b"123"), Some(123));
        // strtoul: non-numeric lead -> 0.
        assert_eq!(parse_decimal_id(b"abc"), Some(0));
        // strtoul: trailing non-digits ignored.
        assert_eq!(parse_decimal_id(b"3x"), Some(3));
        // empty -> 0.
        assert_eq!(parse_decimal_id(b""), Some(0));
        // max u64.
        assert_eq!(parse_decimal_id(b"18446744073709551615"), Some(u64::MAX));
    }

    #[test]
    fn parse_decimal_id_overflow_is_none() {
        // One past u64::MAX overflows the accumulator.
        assert_eq!(parse_decimal_id(b"18446744073709551616"), None);
    }

    #[test]
    fn format_decimal_u64_cases() {
        let mut out = [0u8; 20];
        let n = format_decimal_u64(0, &mut out);
        assert_eq!(&out[..n], b"0");
        let n = format_decimal_u64(1, &mut out);
        assert_eq!(&out[..n], b"1");
        let n = format_decimal_u64(123, &mut out);
        assert_eq!(&out[..n], b"123");
        let n = format_decimal_u64(u64::MAX, &mut out);
        assert_eq!(&out[..n], b"18446744073709551615");
    }

    #[test]
    fn format_decimal_u64_round_trips_parse() {
        for v in [0u64, 1, 2, 9, 10, 99, 100, 65535, 1_000_000, u64::MAX] {
            let mut out = [0u8; 20];
            let n = format_decimal_u64(v, &mut out);
            assert_eq!(parse_decimal_id(&out[..n]), Some(v));
        }
    }

    #[test]
    fn format_decimal_u64_too_small_returns_zero() {
        let mut out = [0u8; 2];
        assert_eq!(format_decimal_u64(123, &mut out), 0);
    }

    // -------------------- snapshot_table_entry_bounds --------------------

    /// The 3-entry mixed-length table used by the bounds / build
    /// tests: id/name lengths chosen so entry lengths are NOT
    /// multiples of 8 (the alignment maths must be exercised) and
    /// the middle entry carries unknown trailing extra data.
    fn mixed_table(buf: &mut [u8]) -> usize {
        build_raw_table(
            buf,
            &[
                (b"1", b"alpha", 24),   // 40+24+1+5 = 70
                (b"22", b"beta", 40),   // 40+40+2+4 = 86 (unknown extra)
                (b"3", b"gamma-x", 24), // 40+24+1+7 = 72
            ],
        )
    }

    #[test]
    fn entry_bounds_first_middle_last() {
        let mut raw = [0u8; 512];
        let total = mixed_table(&mut raw);
        let t = &raw[..total];
        // Entry 0 at 0, len 70. Entry 1 at 72 (70 aligned), len 86.
        // Entry 2 at 160 (158 aligned), len 72.
        assert_eq!(snapshot_table_entry_bounds(t, 3, 0).unwrap(), (0, 70));
        assert_eq!(snapshot_table_entry_bounds(t, 3, 1).unwrap(), (72, 86));
        assert_eq!(snapshot_table_entry_bounds(t, 3, 2).unwrap(), (160, 72));
        // Cross-check against the total walk.
        assert_eq!(snapshot_table_byte_len(t, 3).unwrap(), 160 + 72);
        assert_eq!(total, 232);
    }

    #[test]
    fn entry_bounds_recovers_name_bytes() {
        // The bounds plus the in-entry header offsets recover the
        // exact name bytes — the delete find-by-name path.
        let mut raw = [0u8; 512];
        let total = mixed_table(&mut raw);
        let t = &raw[..total];
        let (start, _len) = snapshot_table_entry_bounds(t, 3, 1).unwrap();
        let extra = u32::from_be_bytes(t[start + 36..start + 40].try_into().unwrap()) as usize;
        let id_size = u16::from_be_bytes(t[start + 12..start + 14].try_into().unwrap()) as usize;
        let name_size = u16::from_be_bytes(t[start + 14..start + 16].try_into().unwrap()) as usize;
        let name_start = start + 40 + extra + id_size;
        assert_eq!(&t[name_start..name_start + name_size], b"beta");
    }

    #[test]
    fn entry_bounds_index_out_of_range() {
        let mut raw = [0u8; 512];
        let total = mixed_table(&mut raw);
        assert_eq!(
            snapshot_table_entry_bounds(&raw[..total], 3, 3),
            Err(SnapshotError::InvalidConfig)
        );
        assert_eq!(
            snapshot_table_entry_bounds(&[], 0, 0),
            Err(SnapshotError::InvalidConfig)
        );
    }

    #[test]
    fn entry_bounds_escape_errors() {
        // Entry 1's header lies past the truncated buffer.
        let mut raw = [0u8; 512];
        let _ = mixed_table(&mut raw);
        assert_eq!(
            snapshot_table_entry_bounds(&raw[..80], 3, 1),
            Err(SnapshotError::ParseFailed)
        );
        // A header claiming a huge name escapes for index 0.
        let mut bad = [0u8; 40];
        bad[14..16].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert_eq!(
            snapshot_table_entry_bounds(&bad, 1, 0),
            Err(SnapshotError::ParseFailed)
        );
    }

    // -------------------- build_snapshot_table_without --------------------

    /// Helper: bounds of each entry of `table` as (start, len).
    fn all_bounds(table: &[u8], nb: u32) -> [(usize, usize); 3] {
        let mut out = [(0usize, 0usize); 3];
        for (i, slot) in out.iter_mut().enumerate().take(nb as usize) {
            *slot = snapshot_table_entry_bounds(table, nb, i as u32).unwrap();
        }
        out
    }

    #[test]
    fn build_without_first_preserves_survivors() {
        let mut raw = [0u8; 512];
        let total = mixed_table(&mut raw);
        let t = &raw[..total];
        let b = all_bounds(t, 3);
        let mut out = [0xEEu8; 512];
        let new_len = build_snapshot_table_without(t, total, 3, 0, &mut out).unwrap();
        // Survivors: entry 1 (len 86) at 0, entry 2 (len 72) at 88.
        assert_eq!(new_len, 88 + 72);
        assert_eq!(&out[..86], &t[b[1].0..b[1].0 + b[1].1]);
        // Alignment gap zeroed.
        assert_eq!(&out[86..88], &[0, 0]);
        assert_eq!(&out[88..88 + 72], &t[b[2].0..b[2].0 + b[2].1]);
        // The new table re-walks cleanly as a 2-entry table.
        assert_eq!(
            snapshot_table_byte_len(&out[..new_len], 2).unwrap(),
            new_len
        );
    }

    #[test]
    fn build_without_middle_preserves_survivors() {
        // Removing the middle (unknown-extra) entry: survivors 0
        // and 2 are copied verbatim. (The unknown-extra entry's own
        // verbatim preservation as a survivor is pinned by
        // build_without_first_preserves_survivors above.)
        let mut raw = [0u8; 512];
        let total = mixed_table(&mut raw);
        let t = &raw[..total];
        let b = all_bounds(t, 3);
        let mut out = [0xEEu8; 512];
        let new_len = build_snapshot_table_without(t, total, 3, 1, &mut out).unwrap();
        // Survivors: entry 0 (len 70) at 0, entry 2 (len 72) at 72.
        assert_eq!(new_len, 72 + 72);
        assert_eq!(&out[..70], &t[b[0].0..b[0].0 + b[0].1]);
        assert_eq!(&out[70..72], &[0, 0]);
        assert_eq!(&out[72..72 + 72], &t[b[2].0..b[2].0 + b[2].1]);
    }

    #[test]
    fn build_without_last_is_prefix() {
        // Removing the last entry leaves the old table's prefix
        // byte-for-byte (no re-alignment changes for survivors).
        let mut raw = [0u8; 512];
        let total = mixed_table(&mut raw);
        let t = &raw[..total];
        let b = all_bounds(t, 3);
        let mut out = [0xEEu8; 512];
        let new_len = build_snapshot_table_without(t, total, 3, 2, &mut out).unwrap();
        // Survivors end at entry 1's unpadded end: 72 + 86 = 158.
        assert_eq!(new_len, b[1].0 + b[1].1);
        assert_eq!(&out[..new_len], &t[..new_len]);
    }

    #[test]
    fn build_without_realigns_after_odd_length_removal() {
        // Entry 0's length (70) is not a multiple of 8; removing it
        // shifts entry 1 from input offset 72 to output offset 0,
        // and entry 2 from 160 to 88 — both 8-aligned.
        let mut raw = [0u8; 512];
        let total = mixed_table(&mut raw);
        let t = &raw[..total];
        let mut out = [0u8; 512];
        let new_len = build_snapshot_table_without(t, total, 3, 0, &mut out).unwrap();
        let (s1, _) = snapshot_table_entry_bounds(&out[..new_len], 2, 0).unwrap();
        let (s2, _) = snapshot_table_entry_bounds(&out[..new_len], 2, 1).unwrap();
        assert_eq!(s1 % 8, 0);
        assert_eq!(s2 % 8, 0);
    }

    #[test]
    fn build_without_sole_entry_yields_zero() {
        let mut raw = [0u8; 128];
        let total = build_raw_table(&mut raw, &[(b"1", b"only", 24)]);
        let mut out = [0xEEu8; 64];
        assert_eq!(
            build_snapshot_table_without(&raw[..total], total, 1, 0, &mut out).unwrap(),
            0
        );
    }

    #[test]
    fn build_without_rejects_bad_args() {
        let mut raw = [0u8; 512];
        let total = mixed_table(&mut raw);
        let mut out = [0u8; 512];
        // remove_index out of range.
        assert_eq!(
            build_snapshot_table_without(&raw[..total], total, 3, 3, &mut out),
            Err(SnapshotError::InvalidConfig)
        );
        // old_len beyond the slice.
        assert_eq!(
            build_snapshot_table_without(&raw[..100], 200, 3, 0, &mut out),
            Err(SnapshotError::MisalignedAccess)
        );
        // out too small for the survivors.
        let mut tiny = [0u8; 16];
        assert_eq!(
            build_snapshot_table_without(&raw[..total], total, 3, 0, &mut tiny),
            Err(SnapshotError::MisalignedAccess)
        );
    }

    #[test]
    fn build_without_malformed_table_errors() {
        // A truncated table (entry 1 escapes) fails ParseFailed even
        // when removing entry 0.
        let mut raw = [0u8; 512];
        let _ = mixed_table(&mut raw);
        let mut out = [0u8; 512];
        assert_eq!(
            build_snapshot_table_without(&raw[..80], 80, 3, 0, &mut out),
            Err(SnapshotError::ParseFailed)
        );
    }

    // Keep the OFLAG_COPIED import meaningful: a serialized entry's
    // l1_table_offset must not carry the COPIED flag (it is a raw
    // host offset, not an L1 entry).
    #[test]
    fn serialize_l1_offset_has_no_copied_flag() {
        let e = sample_entry(b"1", b"x");
        let mut out = [0u8; 128];
        serialize_snapshot_entry(&e, &mut out).unwrap();
        let stored = u64::from_be_bytes(out[0..8].try_into().unwrap());
        assert_eq!(stored & OFLAG_COPIED, 0);
    }
}
