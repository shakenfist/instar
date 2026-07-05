//! Per-action logic for the bitmap subcommand.
//!
//! Each action (`add`, `remove`, `clear`, `enable`, `disable`, and —
//! in 3d — same-image `merge`) is a pure validate-then-mutate function
//! over caller-staged slices (directory bytes, refcount-block bytes)
//! plus scalar geometry, reusing `snapshot::qcow2` for allocation and
//! refcount arithmetic. They are `no_std` and perform no I/O.
//!
//! # Double-buffered directory (Open question 2)
//!
//! The Phase-4 guest stages the existing directory bytes and the
//! refcount blocks once, then applies the ordered action list one
//! action at a time, **double-buffering** the directory: each action
//! reads `old_dir` and writes a fresh `out_dir`, and the guest swaps
//! the two scratch buffers so the just-written `out_dir` becomes the
//! next action's `old_dir`. This keeps every action pure (verbatim
//! copy + edit, mirroring `snapshot::table::build_*`) and means the
//! guest only needs two directory scratch buffers of the worst-case
//! directory size. The refcount blocks (`refblocks: &mut [u8]`) and
//! the [`AllocCursor`] are threaded across all actions and mutated in
//! place.
//!
//! # Validate-before-mutate
//!
//! Every action validates all preconditions before touching
//! `refblocks` or allocating. A refused action therefore leaves
//! `refblocks` and the caller's cursor byte-identical (the `out_dir`
//! buffer is scratch and its contents are unspecified on error).
//!
//! # What the crate can and cannot do (remove / clear)
//!
//! This crate performs no I/O, so it cannot read a bitmap's on-disk
//! **bitmap table** (the array of table entries that point at the
//! bitmap's data clusters). It therefore cannot know which data
//! clusters a bitmap owns. For `remove` and `clear` it does what it
//! *can* compute directly from the directory entry — free the
//! **table clusters** (whose host offset and length are recorded in
//! the entry) — and reports the table's location
//! ([`ActionOutcome::freed_table_offset`] /
//! [`ActionOutcome::freed_table_size`]) so the Phase-4 guest can walk
//! the on-disk table itself and free the data clusters (and, for
//! `clear`, zero the table clusters back to an all-zero empty table).
//! See the "3c design decisions" note in
//! `docs/plans/PLAN-bitmap-phase-03-planner.md`.

use crate::directory::{
    build_directory_replacing, build_directory_with_added, build_directory_without,
    directory_byte_len, find_bitmap,
};
use crate::BitmapError;
use qcow2::bitmap::{
    bitmap_bytes_needed, bitmap_table_size_entries, granularity_bits_valid, BitmapDirEntry,
    BME_FLAG_AUTO, BME_MAX_NAME_SIZE, BT_DIRTY_TRACKING_BITMAP, QCOW2_MAX_BITMAPS,
};
use snapshot::qcow2::{alloc_contiguous_clusters_in_refblocks, set_refcount_in_block, AllocCursor};
use snapshot::SnapshotError;

/// The qcow2 refcount width v1 supports (the qemu-img default and the
/// only width `snapshot::qcow2`'s allocator handles).
const SUPPORTED_REFCOUNT_BITS: u32 = 16;

/// Up to this many cluster host-offsets the guest must zero-fill on
/// disk after an `add`. A bitmap table for a realistic image is a
/// single cluster; eight is generous headroom.
pub const MAX_TABLE_CLUSTERS: usize = 8;

/// Scalar geometry threaded through every action.
///
/// Describes the qcow2 image and the layout of the caller-staged
/// refcount blocks, mirroring the parameters
/// [`alloc_contiguous_clusters_in_refblocks`] takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapGeometry {
    /// Cluster size in bytes (also the byte length of one staged
    /// refcount block).
    pub cluster_size: u64,
    /// `log2(cluster_size)`.
    pub cluster_bits: u32,
    /// qcow2 refcount width in bits. Must be 16 in v1 (else the
    /// action is refused with
    /// [`BitmapError::UnsupportedRefcountWidth`]).
    pub refcount_bits: u32,
    /// The image's virtual (guest) size in bytes.
    pub virtual_size: u64,
    /// Number of refcount blocks staged in `refblocks` (its byte
    /// length is `refblock_count * cluster_size`).
    pub refblock_count: u64,
    /// Host byte offset that staged-refblock cluster index 0 maps to.
    /// Added to `cluster_index * cluster_size` to form a host offset.
    pub host_refblocks_start: u64,
}

/// What an action changed, so the Phase-4 guest knows what to write /
/// zero on disk and how the bitmaps extension must change.
///
/// Small and `Copy`; carries no heap. The `table_clusters_to_zero`
/// list is a fixed [`MAX_TABLE_CLUSTERS`]-slot array whose first
/// `num_table_clusters_to_zero` entries are valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionOutcome {
    /// Number of bytes written into `out_dir` (the new directory
    /// length). Zero when the last bitmap was removed.
    pub new_dir_len: usize,
    /// The bitmaps count after the action (for the bitmaps extension
    /// body the guest rewrites).
    pub new_nb_bitmaps: u32,
    /// `false` only when the last bitmap was removed and the bitmaps
    /// extension (and autoclear bit) must be dropped; `true`
    /// otherwise.
    pub extension_now_present: bool,
    /// Host offsets of newly-allocated bitmap-table clusters the guest
    /// must zero-fill on disk (an `add` allocates an all-zero table).
    /// Only the first `num_table_clusters_to_zero` entries are valid.
    pub table_clusters_to_zero: [u64; MAX_TABLE_CLUSTERS],
    /// Number of valid entries in `table_clusters_to_zero`.
    pub num_table_clusters_to_zero: usize,
    /// For `remove`/`clear`: host offset of the removed/cleared
    /// bitmap's on-disk table, so the guest can walk it and free the
    /// data clusters this crate cannot see. Zero when there is no such
    /// table to walk (add/enable/disable, or a bitmap whose
    /// `bitmap_table_size` is 0).
    pub freed_table_offset: u64,
    /// Number of entries in the on-disk table at
    /// [`freed_table_offset`](Self::freed_table_offset) the guest must
    /// walk. Zero when there is nothing to walk.
    pub freed_table_size: u32,
    /// For `clear`: the guest must, after freeing the data clusters,
    /// zero the table clusters at
    /// [`freed_table_offset`](Self::freed_table_offset) (leaving the
    /// table allocated but all-zero, an empty bitmap). `false` for
    /// every other action. (`remove` frees the table clusters here, so
    /// it does not ask the guest to zero them.)
    pub zero_freed_table: bool,
}

impl ActionOutcome {
    /// A zeroed outcome, refined by each action before it returns.
    const fn empty() -> Self {
        Self {
            new_dir_len: 0,
            new_nb_bitmaps: 0,
            extension_now_present: true,
            table_clusters_to_zero: [0; MAX_TABLE_CLUSTERS],
            num_table_clusters_to_zero: 0,
            freed_table_offset: 0,
            freed_table_size: 0,
            zero_freed_table: false,
        }
    }
}

/// Map a `snapshot::qcow2` allocator/refcount error to the matching
/// [`BitmapError`].
///
/// The allocator's 16-bit-only gate becomes
/// [`BitmapError::UnsupportedRefcountWidth`]; a full refcount tree
/// becomes [`BitmapError::NoSpace`] (v1 does not grow the refcount
/// table); a zero-cluster / bad-geometry `InvalidConfig` and any
/// bounds error become [`BitmapError::InternalOverflow`]; everything
/// else becomes [`BitmapError::ParseFailed`].
fn map_alloc_err(err: SnapshotError) -> BitmapError {
    match err {
        SnapshotError::Unsupported => BitmapError::UnsupportedRefcountWidth,
        SnapshotError::RefcountExhausted | SnapshotError::AllocationFailed => BitmapError::NoSpace,
        SnapshotError::InvalidConfig | SnapshotError::MisalignedAccess => {
            BitmapError::InternalOverflow
        }
        _ => BitmapError::ParseFailed,
    }
}

/// Number of refcount entries per staged refcount block, or an error
/// on bad geometry.
fn entries_per_refblock(geom: &BitmapGeometry) -> Result<u64, BitmapError> {
    if geom.cluster_size == 0 || geom.refcount_bits == 0 {
        return Err(BitmapError::InternalOverflow);
    }
    geom.cluster_size
        .checked_mul(8)
        .map(|bits| bits / geom.refcount_bits as u64)
        .filter(|&e| e != 0)
        .ok_or(BitmapError::InternalOverflow)
}

/// Map a host byte offset (a cluster start) to the staged refblock
/// slot's byte range and the entry index within that block.
///
/// Mirrors `snapshot`'s guest-op `rb_lookup`
/// (`src/operations/snapshot/src/main.rs`): refblocks are contiguous
/// from cluster index 0, so `rb_slot = cluster_index /
/// entries_per_refblock` and `entry_local = cluster_index %
/// entries_per_refblock`. Returns the `(start, end)` byte range of the
/// refblock within `refblocks` and the local entry index.
///
/// Returns [`BitmapError::InternalOverflow`] if the offset is not
/// cluster-aligned relative to `host_refblocks_start`, or maps outside
/// the staged blocks, or any arithmetic overflows.
fn refblock_byte_range_for_cluster(
    host_offset: u64,
    geom: &BitmapGeometry,
) -> Result<(usize, usize, u64), BitmapError> {
    let epr = entries_per_refblock(geom)?;
    let rel = host_offset
        .checked_sub(geom.host_refblocks_start)
        .ok_or(BitmapError::InternalOverflow)?;
    if rel % geom.cluster_size != 0 {
        return Err(BitmapError::InternalOverflow);
    }
    let cluster_index = rel / geom.cluster_size;
    let rb_slot = cluster_index / epr;
    let entry_local = cluster_index % epr;
    if rb_slot >= geom.refblock_count {
        return Err(BitmapError::InternalOverflow);
    }
    let start = (rb_slot as usize)
        .checked_mul(geom.cluster_size as usize)
        .ok_or(BitmapError::InternalOverflow)?;
    let end = start
        .checked_add(geom.cluster_size as usize)
        .ok_or(BitmapError::InternalOverflow)?;
    Ok((start, end, entry_local))
}

/// Set the refcount of the cluster at `host_offset` to `value` in the
/// staged refblocks (used to free a cluster: `value == 0`).
fn set_cluster_refcount(
    refblocks: &mut [u8],
    host_offset: u64,
    value: u64,
    geom: &BitmapGeometry,
) -> Result<(), BitmapError> {
    let (start, end, entry_local) = refblock_byte_range_for_cluster(host_offset, geom)?;
    let block = refblocks
        .get_mut(start..end)
        .ok_or(BitmapError::InternalOverflow)?;
    set_refcount_in_block(block, entry_local, geom.refcount_bits, value).map_err(map_alloc_err)
}

/// Read the refcount of the cluster at `host_offset` from the staged
/// refblocks.
///
/// The read companion to [`set_cluster_refcount`]; the actions
/// themselves only need the write path (freeing table clusters), so
/// this is currently exercised only by the crate's tests. Gated
/// `#[cfg(test)]` so it does not read as dead code until the Phase-4
/// guest (which will want to inspect refcounts) links against it.
#[cfg(test)]
fn read_cluster_refcount(
    refblocks: &[u8],
    host_offset: u64,
    geom: &BitmapGeometry,
) -> Result<u64, BitmapError> {
    let (start, end, entry_local) = refblock_byte_range_for_cluster(host_offset, geom)?;
    let block = refblocks
        .get(start..end)
        .ok_or(BitmapError::InternalOverflow)?;
    snapshot::qcow2::read_refcount_in_block(block, entry_local, geom.refcount_bits)
        .map_err(map_alloc_err)
}

/// Number of clusters a bitmap table of `table_size` entries occupies:
/// `ceil(table_size * 8 / cluster_size)`.
fn table_cluster_count(table_size: u32, cluster_size: u64) -> Result<u64, BitmapError> {
    if cluster_size == 0 {
        return Err(BitmapError::InternalOverflow);
    }
    let bytes = (table_size as u64)
        .checked_mul(8)
        .ok_or(BitmapError::InternalOverflow)?;
    Ok(bytes.div_ceil(cluster_size))
}

/// `add` a new, enabled, empty bitmap.
///
/// Validates (no mutation on failure): `refcount_bits == 16`
/// ([`BitmapError::UnsupportedRefcountWidth`]); name length `1..=1023`
/// ([`BitmapError::NameTooLong`] — this covers both an empty name and
/// an over-long one, matching qemu's non-empty-name requirement);
/// `granularity_bits` in `9..=31` ([`BitmapError::GranularityRange`]);
/// the name is not already present ([`BitmapError::BitmapExists`]);
/// and `nb_bitmaps < 65535` ([`BitmapError::TooManyBitmaps`]).
///
/// Then allocates `ceil(table_bytes / cluster_size)` **table
/// clusters** for the new bitmap's all-zero table (an empty bitmap has
/// no data clusters — see master OQ8), records their host offsets in
/// [`ActionOutcome::table_clusters_to_zero`] (the guest zero-fills
/// them), builds the enabled directory entry, and appends it to
/// `out_dir` via
/// [`build_directory_with_added`](crate::directory::build_directory_with_added).
///
/// Validation runs entirely before the allocation, so a refused `add`
/// leaves `refblocks` and `cursor` untouched.
#[allow(clippy::too_many_arguments)]
pub fn action_add(
    old_dir: &[u8],
    old_len: usize,
    nb_bitmaps: u32,
    name: &[u8],
    granularity_bits: u8,
    refblocks: &mut [u8],
    cursor: &mut AllocCursor,
    geom: &BitmapGeometry,
    out_dir: &mut [u8],
) -> Result<ActionOutcome, BitmapError> {
    // ---- Validate (no mutation past this block on failure) ----
    if geom.refcount_bits != SUPPORTED_REFCOUNT_BITS {
        return Err(BitmapError::UnsupportedRefcountWidth);
    }
    // NameTooLong covers an invalid name *length*: empty or > 1023.
    if name.is_empty() || name.len() > BME_MAX_NAME_SIZE {
        return Err(BitmapError::NameTooLong);
    }
    if !granularity_bits_valid(granularity_bits) {
        return Err(BitmapError::GranularityRange);
    }
    // Check the count limit before walking the directory: an image
    // already at the maximum cannot gain a bitmap regardless of the
    // requested name, and this keeps the guard cheaply reachable
    // (find_bitmap would otherwise walk `nb_bitmaps` entries first).
    if nb_bitmaps >= QCOW2_MAX_BITMAPS {
        return Err(BitmapError::TooManyBitmaps);
    }
    if find_bitmap(old_dir, nb_bitmaps, name)?.is_some() {
        return Err(BitmapError::BitmapExists);
    }

    // ---- Compute the empty bitmap's table geometry ----
    let granularity = 1u64
        .checked_shl(granularity_bits as u32)
        .ok_or(BitmapError::InternalOverflow)?;
    let bytes_needed = bitmap_bytes_needed(geom.virtual_size, granularity);
    let table_entries = bitmap_table_size_entries(bytes_needed, geom.cluster_size);
    // A bitmap table always occupies at least one cluster.
    let table_clusters = table_cluster_count(table_entries as u32, geom.cluster_size)?.max(1);
    if table_clusters > MAX_TABLE_CLUSTERS as u64 {
        // Would not fit our fixed zero-list; refuse rather than
        // silently drop offsets. A single cluster covers realistic
        // images; more implies an implausible virtual size.
        return Err(BitmapError::NoSpace);
    }
    if table_entries > u32::MAX as u64 {
        return Err(BitmapError::InternalOverflow);
    }

    // ---- Allocate the table clusters (the first mutation) ----
    let table_offset = alloc_contiguous_clusters_in_refblocks(
        refblocks,
        geom.cluster_size,
        geom.refcount_bits,
        geom.refblock_count,
        geom.host_refblocks_start,
        table_clusters,
        cursor,
    )
    .map_err(map_alloc_err)?;

    // ---- Build the new directory entry (enabled, empty table) ----
    let mut entry = BitmapDirEntry::zeroed();
    entry.bitmap_table_offset = table_offset;
    entry.bitmap_table_size = table_entries as u32;
    entry.flags = BME_FLAG_AUTO;
    entry.bitmap_type = BT_DIRTY_TRACKING_BITMAP;
    entry.granularity_bits = granularity_bits;
    entry.name_size = name.len() as u16;
    entry.extra_data_size = 0;
    entry.name[..name.len()].copy_from_slice(name);

    let new_len = build_directory_with_added(old_dir, old_len, nb_bitmaps, &entry, out_dir)?;

    // ---- Report the newly-allocated table clusters to zero-fill ----
    let mut outcome = ActionOutcome::empty();
    outcome.new_dir_len = new_len;
    outcome.new_nb_bitmaps = nb_bitmaps + 1;
    outcome.extension_now_present = true;
    let n = table_clusters as usize;
    for (i, slot) in outcome.table_clusters_to_zero[..n].iter_mut().enumerate() {
        *slot = table_offset
            .checked_add((i as u64) * geom.cluster_size)
            .ok_or(BitmapError::InternalOverflow)?;
    }
    outcome.num_table_clusters_to_zero = n;
    Ok(outcome)
}

/// `remove` a bitmap.
///
/// Finds the bitmap ([`BitmapError::BitmapNotFound`] if absent).
/// **`remove` is the only action allowed on an `in_use` bitmap**, so
/// no in-use check. Frees the bitmap's **table clusters** (their host
/// offsets and count are known from the entry) by setting their
/// refcounts to zero, then compacts the directory into `out_dir` via
/// [`build_directory_without`](crate::directory::build_directory_without).
///
/// The bitmap's **data clusters** cannot be freed here (the crate
/// cannot read the on-disk table); the outcome carries
/// [`freed_table_offset`](ActionOutcome::freed_table_offset) /
/// [`freed_table_size`](ActionOutcome::freed_table_size) so the guest
/// walks the on-disk table and frees them.
///
/// The table-cluster free is validated first (every offset must map
/// into the staged refblocks) before any refcount is written, so a
/// refused remove leaves `refblocks` byte-identical.
pub fn action_remove(
    old_dir: &[u8],
    old_len: usize,
    nb_bitmaps: u32,
    name: &[u8],
    refblocks: &mut [u8],
    geom: &BitmapGeometry,
    out_dir: &mut [u8],
) -> Result<ActionOutcome, BitmapError> {
    if geom.refcount_bits != SUPPORTED_REFCOUNT_BITS {
        return Err(BitmapError::UnsupportedRefcountWidth);
    }
    let found = find_bitmap(old_dir, nb_bitmaps, name)?.ok_or(BitmapError::BitmapNotFound)?;
    let entry = found.entry;

    // Validate every table-cluster offset maps into the staged
    // refblocks BEFORE writing any refcount (validate-before-mutate).
    let table_clusters = table_cluster_count(entry.bitmap_table_size, geom.cluster_size)?;
    for i in 0..table_clusters {
        let host = entry
            .bitmap_table_offset
            .checked_add(i * geom.cluster_size)
            .ok_or(BitmapError::InternalOverflow)?;
        // Bounds-check only; do not mutate yet.
        let _ = refblock_byte_range_for_cluster(host, geom)?;
    }

    // Free the table clusters (refcount -> 0).
    for i in 0..table_clusters {
        let host = entry.bitmap_table_offset + i * geom.cluster_size;
        set_cluster_refcount(refblocks, host, 0, geom)?;
    }

    let new_len = build_directory_without(old_dir, old_len, nb_bitmaps, found.index, out_dir)?;
    let new_nb = nb_bitmaps - 1;

    let mut outcome = ActionOutcome::empty();
    outcome.new_dir_len = new_len;
    outcome.new_nb_bitmaps = new_nb;
    outcome.extension_now_present = new_nb != 0;
    outcome.freed_table_offset = entry.bitmap_table_offset;
    outcome.freed_table_size = entry.bitmap_table_size;
    outcome.zero_freed_table = false;
    Ok(outcome)
}

/// `clear` a bitmap back to the empty state.
///
/// Finds the bitmap ([`BitmapError::BitmapNotFound`] if absent) and
/// refuses an `in_use` one ([`BitmapError::BitmapInUse`]). Leaves the
/// directory entry **unchanged** (same name / granularity / flags /
/// table pointer + size) — `clear` changes the bitmap's on-disk table
/// *contents* (all entries -> all-zero) and frees its data clusters,
/// not the directory. `out_dir` therefore receives a verbatim copy of
/// the old directory.
///
/// As with `remove`, the crate cannot read the on-disk table, so it
/// signals the guest via the outcome: the guest walks the table at
/// [`freed_table_offset`](ActionOutcome::freed_table_offset) to free
/// the data clusters, then zeroes the table clusters
/// ([`zero_freed_table`](ActionOutcome::zero_freed_table) is `true`).
/// The table clusters stay allocated (an empty bitmap keeps its
/// all-zero table), so no refcount is changed here — `clear` performs
/// no refblock mutation, only validation.
pub fn action_clear(
    old_dir: &[u8],
    old_len: usize,
    nb_bitmaps: u32,
    name: &[u8],
    refblocks: &mut [u8],
    geom: &BitmapGeometry,
    out_dir: &mut [u8],
) -> Result<ActionOutcome, BitmapError> {
    if geom.refcount_bits != SUPPORTED_REFCOUNT_BITS {
        return Err(BitmapError::UnsupportedRefcountWidth);
    }
    let found = find_bitmap(old_dir, nb_bitmaps, name)?.ok_or(BitmapError::BitmapNotFound)?;
    if found.entry.is_in_use() {
        return Err(BitmapError::BitmapInUse);
    }
    let entry = found.entry;

    // Validate the table clusters map into the staged refblocks (so a
    // clear that could not later be completed is refused up front) —
    // but do NOT free them: clear keeps the table allocated.
    let table_clusters = table_cluster_count(entry.bitmap_table_size, geom.cluster_size)?;
    for i in 0..table_clusters {
        let host = entry
            .bitmap_table_offset
            .checked_add(i * geom.cluster_size)
            .ok_or(BitmapError::InternalOverflow)?;
        let _ = refblock_byte_range_for_cluster(host, geom)?;
    }

    // Directory entry is unchanged: verbatim copy old -> out.
    let expected = directory_byte_len(old_dir, nb_bitmaps)?;
    if old_len != expected {
        return Err(BitmapError::InternalOverflow);
    }
    if old_len > old_dir.len() {
        return Err(BitmapError::InternalOverflow);
    }
    let out = out_dir
        .get_mut(..old_len)
        .ok_or(BitmapError::ScratchTooSmall)?;
    out.copy_from_slice(&old_dir[..old_len]);
    // Touch refblocks read-only to prove the mapping (and to keep the
    // signature consistent); no mutation.
    let _ = refblocks;

    let mut outcome = ActionOutcome::empty();
    outcome.new_dir_len = old_len;
    outcome.new_nb_bitmaps = nb_bitmaps;
    outcome.extension_now_present = true;
    outcome.freed_table_offset = entry.bitmap_table_offset;
    outcome.freed_table_size = entry.bitmap_table_size;
    outcome.zero_freed_table = true;
    Ok(outcome)
}

/// `enable` a bitmap (set `BME_FLAG_AUTO`).
///
/// Finds the bitmap ([`BitmapError::BitmapNotFound`] if absent) and
/// refuses an `in_use` one ([`BitmapError::BitmapInUse`]). Rewrites
/// the entry with the `auto` flag set via
/// [`build_directory_replacing`](crate::directory::build_directory_replacing).
/// No allocation, no refblock change.
pub fn action_enable(
    old_dir: &[u8],
    old_len: usize,
    nb_bitmaps: u32,
    name: &[u8],
    out_dir: &mut [u8],
) -> Result<ActionOutcome, BitmapError> {
    set_auto_flag(old_dir, old_len, nb_bitmaps, name, true, out_dir)
}

/// `disable` a bitmap (clear `BME_FLAG_AUTO`).
///
/// Finds the bitmap ([`BitmapError::BitmapNotFound`] if absent) and
/// refuses an `in_use` one ([`BitmapError::BitmapInUse`]). Rewrites
/// the entry with the `auto` flag cleared via
/// [`build_directory_replacing`](crate::directory::build_directory_replacing).
/// No allocation, no refblock change.
pub fn action_disable(
    old_dir: &[u8],
    old_len: usize,
    nb_bitmaps: u32,
    name: &[u8],
    out_dir: &mut [u8],
) -> Result<ActionOutcome, BitmapError> {
    set_auto_flag(old_dir, old_len, nb_bitmaps, name, false, out_dir)
}

/// Shared implementation of enable/disable: flip only `BME_FLAG_AUTO`.
fn set_auto_flag(
    old_dir: &[u8],
    old_len: usize,
    nb_bitmaps: u32,
    name: &[u8],
    enable: bool,
    out_dir: &mut [u8],
) -> Result<ActionOutcome, BitmapError> {
    let found = find_bitmap(old_dir, nb_bitmaps, name)?.ok_or(BitmapError::BitmapNotFound)?;
    if found.entry.is_in_use() {
        return Err(BitmapError::BitmapInUse);
    }
    let mut replacement = found.entry;
    if enable {
        replacement.flags |= BME_FLAG_AUTO;
    } else {
        replacement.flags &= !BME_FLAG_AUTO;
    }
    let new_len = build_directory_replacing(
        old_dir,
        old_len,
        nb_bitmaps,
        found.index,
        &replacement,
        out_dir,
    )?;

    let mut outcome = ActionOutcome::empty();
    outcome.new_dir_len = new_len;
    outcome.new_nb_bitmaps = nb_bitmaps;
    outcome.extension_now_present = true;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qcow2::bitmap::{serialize_bitmap_dir_entry, BME_FLAG_IN_USE};
    use snapshot::qcow2::read_refcount_in_block;
    use std::vec;
    use std::vec::Vec;

    const CLUSTER_SIZE: u64 = 65536;
    const CLUSTER_BITS: u32 = 16;
    const REFCOUNT_BITS: u32 = 16;
    // 1 GiB virtual size: at granularity 2^16 = 65536 bytes/bit, that
    // is 16384 bits -> 2048 bytes -> a single table cluster.
    const VIRTUAL_SIZE: u64 = 1 << 30;

    /// entries_per_refblock = cluster_size * 8 / refcount_bits.
    const EPR: u64 = (CLUSTER_SIZE * 8) / REFCOUNT_BITS as u64; // 32768

    fn geom(refblock_count: u64) -> BitmapGeometry {
        BitmapGeometry {
            cluster_size: CLUSTER_SIZE,
            cluster_bits: CLUSTER_BITS,
            refcount_bits: REFCOUNT_BITS,
            virtual_size: VIRTUAL_SIZE,
            refblock_count,
            host_refblocks_start: 0,
        }
    }

    /// A staged refblock buffer of `refblock_count` blocks. The first
    /// `used_clusters` cluster entries are marked refcount 1 (the image
    /// header, refcount table, refblocks, L1, etc.); the rest are free.
    fn refblocks(refblock_count: u64, used_clusters: u64) -> Vec<u8> {
        let mut b = vec![0u8; (refblock_count * CLUSTER_SIZE) as usize];
        for c in 0..used_clusters {
            let rb_slot = (c / EPR) as usize;
            let entry = c % EPR;
            let base = rb_slot * CLUSTER_SIZE as usize;
            set_refcount_in_block(
                &mut b[base..base + CLUSTER_SIZE as usize],
                entry,
                REFCOUNT_BITS,
                1,
            )
            .unwrap();
        }
        b
    }

    fn refcount_at(refblocks: &[u8], cluster_index: u64) -> u64 {
        let rb_slot = (cluster_index / EPR) as usize;
        let entry = cluster_index % EPR;
        let base = rb_slot * CLUSTER_SIZE as usize;
        read_refcount_in_block(
            &refblocks[base..base + CLUSTER_SIZE as usize],
            entry,
            REFCOUNT_BITS,
        )
        .unwrap()
    }

    fn dir_entry(
        name: &[u8],
        flags: u32,
        granularity_bits: u8,
        off: u64,
        size: u32,
    ) -> BitmapDirEntry {
        let mut e = BitmapDirEntry::zeroed();
        e.bitmap_table_offset = off;
        e.bitmap_table_size = size;
        e.flags = flags;
        e.bitmap_type = BT_DIRTY_TRACKING_BITMAP;
        e.granularity_bits = granularity_bits;
        e.name_size = name.len() as u16;
        e.name[..name.len()].copy_from_slice(name);
        e
    }

    fn build_dir(entries: &[BitmapDirEntry]) -> Vec<u8> {
        let mut dir = Vec::new();
        let mut scratch = [0u8; 1200];
        for e in entries {
            let n = serialize_bitmap_dir_entry(e, &mut scratch).unwrap();
            dir.extend_from_slice(&scratch[..n]);
        }
        dir
    }

    // -------------------- refblock mapping helper --------------------

    #[test]
    fn refblock_mapping_first_block() {
        let g = geom(2);
        // cluster 0 -> slot 0, entry 0.
        let (s, e, idx) = refblock_byte_range_for_cluster(0, &g).unwrap();
        assert_eq!((s, e, idx), (0, CLUSTER_SIZE as usize, 0));
        // cluster 5 -> slot 0, entry 5.
        let (s, e, idx) = refblock_byte_range_for_cluster(5 * CLUSTER_SIZE, &g).unwrap();
        assert_eq!((s, e, idx), (0, CLUSTER_SIZE as usize, 5));
    }

    #[test]
    fn refblock_mapping_second_block() {
        let g = geom(2);
        // First cluster of the second refblock is cluster index EPR.
        let host = EPR * CLUSTER_SIZE;
        let (s, e, idx) = refblock_byte_range_for_cluster(host, &g).unwrap();
        assert_eq!(
            (s, e, idx),
            (CLUSTER_SIZE as usize, 2 * CLUSTER_SIZE as usize, 0)
        );
    }

    #[test]
    fn refblock_mapping_honours_host_start() {
        let mut g = geom(2);
        g.host_refblocks_start = 10 * CLUSTER_SIZE;
        // A host offset equal to the base maps to cluster 0.
        let (_, _, idx) = refblock_byte_range_for_cluster(10 * CLUSTER_SIZE, &g).unwrap();
        assert_eq!(idx, 0);
        // Below the base underflows -> error.
        assert_eq!(
            refblock_byte_range_for_cluster(0, &g),
            Err(BitmapError::InternalOverflow)
        );
    }

    #[test]
    fn refblock_mapping_rejects_misaligned_and_oob() {
        let g = geom(1);
        assert_eq!(
            refblock_byte_range_for_cluster(CLUSTER_SIZE / 2, &g),
            Err(BitmapError::InternalOverflow)
        );
        // Cluster index EPR is in the (nonexistent) second block.
        assert_eq!(
            refblock_byte_range_for_cluster(EPR * CLUSTER_SIZE, &g),
            Err(BitmapError::InternalOverflow)
        );
    }

    #[test]
    fn cluster_refcount_read_and_set_round_trip() {
        let g = geom(2);
        let mut rb = refblocks(2, 0);
        // Read back what set_cluster_refcount writes, across both blocks.
        for &cluster in &[0u64, 7, EPR, EPR + 3] {
            let host = cluster * CLUSTER_SIZE;
            assert_eq!(read_cluster_refcount(&rb, host, &g).unwrap(), 0);
            set_cluster_refcount(&mut rb, host, 1, &g).unwrap();
            assert_eq!(read_cluster_refcount(&rb, host, &g).unwrap(), 1);
            // Confirm against the raw fixture accessor.
            assert_eq!(refcount_at(&rb, cluster), 1);
            set_cluster_refcount(&mut rb, host, 0, &g).unwrap();
            assert_eq!(read_cluster_refcount(&rb, host, &g).unwrap(), 0);
        }
        // Out-of-range host offset is reported, not panicked.
        assert_eq!(
            read_cluster_refcount(&rb, 2 * EPR * CLUSTER_SIZE, &g),
            Err(BitmapError::InternalOverflow)
        );
    }

    #[test]
    fn table_cluster_count_rounds_up() {
        // 8192 entries * 8 = 65536 bytes = exactly one cluster.
        assert_eq!(table_cluster_count(8192, CLUSTER_SIZE).unwrap(), 1);
        // One more entry spills into a second cluster.
        assert_eq!(table_cluster_count(8193, CLUSTER_SIZE).unwrap(), 2);
        // Zero entries -> zero clusters (add clamps this to >=1 itself).
        assert_eq!(table_cluster_count(0, CLUSTER_SIZE).unwrap(), 0);
    }

    // -------------------- add --------------------

    #[test]
    fn add_allocates_one_table_cluster_and_appends_enabled_entry() {
        let g = geom(1);
        let used = 3; // clusters 0,1,2 occupied.
        let mut rb = refblocks(1, used);
        let before = rb.clone();
        let mut cursor = AllocCursor::default();
        let old_dir: [u8; 0] = [];
        let mut out = [0u8; 512];

        let outcome = action_add(
            &old_dir,
            0,
            0,
            b"backup",
            16,
            &mut rb,
            &mut cursor,
            &g,
            &mut out,
        )
        .unwrap();

        // One table cluster allocated at the first free cluster (index 3).
        assert_eq!(outcome.num_table_clusters_to_zero, 1);
        assert_eq!(outcome.table_clusters_to_zero[0], used * CLUSTER_SIZE);
        assert_eq!(refcount_at(&rb, used), 1);
        // No other refcounts changed except cluster `used`.
        let mut expect = before.clone();
        let base = 0usize;
        set_refcount_in_block(
            &mut expect[base..base + CLUSTER_SIZE as usize],
            used,
            REFCOUNT_BITS,
            1,
        )
        .unwrap();
        assert_eq!(rb, expect);

        assert_eq!(outcome.new_nb_bitmaps, 1);
        assert!(outcome.extension_now_present);
        assert_eq!(outcome.freed_table_offset, 0);
        assert!(!outcome.zero_freed_table);

        // The appended entry is enabled, correct name/granularity, and
        // its table_size is the empty-bitmap table entry count.
        let f = find_bitmap(&out[..outcome.new_dir_len], 1, b"backup")
            .unwrap()
            .unwrap();
        assert!(f.entry.is_enabled());
        assert!(!f.entry.is_in_use());
        assert_eq!(f.entry.granularity_bits, 16);
        assert_eq!(f.entry.bitmap_table_offset, used * CLUSTER_SIZE);
        // 1 GiB / 65536 bytes-per-bit / 8 = 2048 bytes -> 256 entries.
        let bytes = bitmap_bytes_needed(VIRTUAL_SIZE, 1 << 16);
        let entries = bitmap_table_size_entries(bytes, CLUSTER_SIZE);
        assert_eq!(f.entry.bitmap_table_size as u64, entries);
    }

    #[test]
    fn add_duplicate_is_bitmap_exists_no_mutation() {
        let g = geom(1);
        let existing = dir_entry(b"dup", BME_FLAG_AUTO, 16, CLUSTER_SIZE, 1);
        let dir = build_dir(&[existing]);
        let mut rb = refblocks(1, 4);
        let before = rb.clone();
        let mut cursor = AllocCursor::default();
        let before_cursor = cursor;
        let mut out = [0u8; 512];
        assert_eq!(
            action_add(
                &dir,
                dir.len(),
                1,
                b"dup",
                16,
                &mut rb,
                &mut cursor,
                &g,
                &mut out
            ),
            Err(BitmapError::BitmapExists)
        );
        assert_eq!(rb, before);
        assert_eq!(cursor, before_cursor);
    }

    #[test]
    fn add_bad_granularity_is_granularity_range_no_mutation() {
        let g = geom(1);
        let mut rb = refblocks(1, 4);
        let before = rb.clone();
        let mut cursor = AllocCursor::default();
        let mut out = [0u8; 512];
        for bad in [8u8, 32u8] {
            assert_eq!(
                action_add(&[], 0, 0, b"n", bad, &mut rb, &mut cursor, &g, &mut out),
                Err(BitmapError::GranularityRange)
            );
        }
        assert_eq!(rb, before);
        assert_eq!(cursor, AllocCursor::default());
    }

    #[test]
    fn add_name_too_long_and_empty() {
        let g = geom(1);
        let mut rb = refblocks(1, 4);
        let before = rb.clone();
        let mut cursor = AllocCursor::default();
        let mut out = [0u8; 2048];
        let long = [b'a'; 1024];
        assert_eq!(
            action_add(&[], 0, 0, &long, 16, &mut rb, &mut cursor, &g, &mut out),
            Err(BitmapError::NameTooLong)
        );
        assert_eq!(
            action_add(&[], 0, 0, b"", 16, &mut rb, &mut cursor, &g, &mut out),
            Err(BitmapError::NameTooLong)
        );
        assert_eq!(rb, before);
    }

    #[test]
    fn add_too_many_bitmaps() {
        let g = geom(1);
        let mut rb = refblocks(1, 4);
        let before = rb.clone();
        let mut cursor = AllocCursor::default();
        let mut out = [0u8; 512];
        // The count guard (`nb_bitmaps >= 65535`) runs before the
        // directory walk, so claiming the max over an empty directory
        // exercises it directly.
        assert_eq!(
            action_add(
                &[],
                0,
                QCOW2_MAX_BITMAPS,
                b"new",
                16,
                &mut rb,
                &mut cursor,
                &g,
                &mut out
            ),
            Err(BitmapError::TooManyBitmaps)
        );
        assert_eq!(rb, before);
    }

    #[test]
    fn add_non_16bit_refcount_is_unsupported() {
        let mut g = geom(1);
        g.refcount_bits = 32;
        let mut rb = refblocks(1, 4);
        let before = rb.clone();
        let mut cursor = AllocCursor::default();
        let mut out = [0u8; 512];
        assert_eq!(
            action_add(&[], 0, 0, b"n", 16, &mut rb, &mut cursor, &g, &mut out),
            Err(BitmapError::UnsupportedRefcountWidth)
        );
        assert_eq!(rb, before);
    }

    #[test]
    fn add_refblocks_full_is_no_space() {
        let g = geom(1);
        // Every cluster occupied.
        let mut rb = refblocks(1, EPR);
        let before = rb.clone();
        let mut cursor = AllocCursor::default();
        let mut out = [0u8; 512];
        assert_eq!(
            action_add(&[], 0, 0, b"n", 16, &mut rb, &mut cursor, &g, &mut out),
            Err(BitmapError::NoSpace)
        );
        assert_eq!(rb, before);
    }

    // -------------------- remove --------------------

    #[test]
    fn remove_frees_table_cluster_and_compacts() {
        let g = geom(1);
        // Two bitmaps; the second owns a table cluster at index 5.
        let e0 = dir_entry(b"keep", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let e1 = dir_entry(b"drop", BME_FLAG_AUTO, 16, 5 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[e0, e1]);
        // Mark clusters up to and including 5 as used.
        let mut rb = refblocks(1, 6);
        assert_eq!(refcount_at(&rb, 5), 1);
        let mut out = [0u8; 512];

        let outcome = action_remove(&dir, dir.len(), 2, b"drop", &mut rb, &g, &mut out).unwrap();

        // Cluster 5 (drop's table) freed; cluster 4 (keep's) intact.
        assert_eq!(refcount_at(&rb, 5), 0);
        assert_eq!(refcount_at(&rb, 4), 1);
        assert_eq!(outcome.new_nb_bitmaps, 1);
        assert!(outcome.extension_now_present);
        assert_eq!(outcome.freed_table_offset, 5 * CLUSTER_SIZE);
        assert_eq!(outcome.freed_table_size, 1);
        assert!(!outcome.zero_freed_table);
        // Directory now has only "keep".
        assert!(find_bitmap(&out[..outcome.new_dir_len], 1, b"keep")
            .unwrap()
            .is_some());
        assert!(find_bitmap(&out[..outcome.new_dir_len], 1, b"drop")
            .unwrap()
            .is_none());
    }

    #[test]
    fn remove_last_clears_extension() {
        let g = geom(1);
        let e = dir_entry(b"only", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[e]);
        let mut rb = refblocks(1, 5);
        let mut out = [0u8; 512];
        let outcome = action_remove(&dir, dir.len(), 1, b"only", &mut rb, &g, &mut out).unwrap();
        assert_eq!(outcome.new_nb_bitmaps, 0);
        assert!(!outcome.extension_now_present);
        assert_eq!(outcome.new_dir_len, 0);
        assert_eq!(refcount_at(&rb, 4), 0);
    }

    #[test]
    fn remove_absent_is_not_found_no_mutation() {
        let g = geom(1);
        let e = dir_entry(b"present", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[e]);
        let mut rb = refblocks(1, 5);
        let before = rb.clone();
        let mut out = [0u8; 512];
        assert_eq!(
            action_remove(&dir, dir.len(), 1, b"nope", &mut rb, &g, &mut out),
            Err(BitmapError::BitmapNotFound)
        );
        assert_eq!(rb, before);
    }

    #[test]
    fn remove_in_use_succeeds() {
        let g = geom(1);
        // in_use bitmap: remove is the only action allowed on it.
        let e = dir_entry(b"stale", BME_FLAG_IN_USE, 16, 4 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[e]);
        let mut rb = refblocks(1, 5);
        let mut out = [0u8; 512];
        let outcome = action_remove(&dir, dir.len(), 1, b"stale", &mut rb, &g, &mut out).unwrap();
        assert_eq!(outcome.new_nb_bitmaps, 0);
        assert_eq!(refcount_at(&rb, 4), 0);
    }

    // -------------------- clear --------------------

    #[test]
    fn clear_keeps_entry_and_signals_guest() {
        let g = geom(1);
        let e = dir_entry(b"c", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[e]);
        let mut rb = refblocks(1, 5);
        let before = rb.clone();
        let mut out = [0u8; 512];
        let outcome = action_clear(&dir, dir.len(), 1, b"c", &mut rb, &g, &mut out).unwrap();
        // Directory is byte-identical (entry unchanged).
        assert_eq!(&out[..outcome.new_dir_len], &dir[..]);
        assert_eq!(outcome.new_nb_bitmaps, 1);
        assert!(outcome.extension_now_present);
        assert_eq!(outcome.freed_table_offset, 4 * CLUSTER_SIZE);
        assert_eq!(outcome.freed_table_size, 1);
        assert!(outcome.zero_freed_table);
        // clear does not touch refcounts (table stays allocated).
        assert_eq!(rb, before);
        assert_eq!(refcount_at(&rb, 4), 1);
    }

    #[test]
    fn clear_absent_is_not_found() {
        let g = geom(1);
        let e = dir_entry(b"c", BME_FLAG_AUTO, 16, 4 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[e]);
        let mut rb = refblocks(1, 5);
        let mut out = [0u8; 512];
        assert_eq!(
            action_clear(&dir, dir.len(), 1, b"nope", &mut rb, &g, &mut out),
            Err(BitmapError::BitmapNotFound)
        );
    }

    #[test]
    fn clear_in_use_is_refused_no_mutation() {
        let g = geom(1);
        let e = dir_entry(b"c", BME_FLAG_IN_USE, 16, 4 * CLUSTER_SIZE, 1);
        let dir = build_dir(&[e]);
        let mut rb = refblocks(1, 5);
        let before = rb.clone();
        let mut out = [0u8; 512];
        assert_eq!(
            action_clear(&dir, dir.len(), 1, b"c", &mut rb, &g, &mut out),
            Err(BitmapError::BitmapInUse)
        );
        assert_eq!(rb, before);
    }

    // -------------------- enable / disable --------------------

    #[test]
    fn disable_clears_only_auto_flag() {
        let g = geom(1);
        let e0 = dir_entry(b"a", BME_FLAG_AUTO, 16, CLUSTER_SIZE, 1);
        let e1 = dir_entry(b"b", BME_FLAG_AUTO, 12, 2 * CLUSTER_SIZE, 2);
        let dir = build_dir(&[e0, e1]);
        let mut out = [0u8; 512];
        let outcome = action_disable(&dir, dir.len(), 2, b"a", &mut out).unwrap();
        let f = find_bitmap(&out[..outcome.new_dir_len], 2, b"a")
            .unwrap()
            .unwrap();
        assert!(!f.entry.is_enabled());
        assert_eq!(f.entry.bitmap_table_offset, CLUSTER_SIZE);
        assert_eq!(f.entry.granularity_bits, 16);
        // Sibling untouched, still enabled.
        assert!(find_bitmap(&out[..outcome.new_dir_len], 2, b"b")
            .unwrap()
            .unwrap()
            .entry
            .is_enabled());
        assert_eq!(outcome.new_nb_bitmaps, 2);
        let _ = &g;
    }

    #[test]
    fn enable_sets_auto_flag() {
        let e = dir_entry(b"a", 0, 16, CLUSTER_SIZE, 1);
        let dir = build_dir(&[e]);
        let mut out = [0u8; 512];
        let outcome = action_enable(&dir, dir.len(), 1, b"a", &mut out).unwrap();
        let f = find_bitmap(&out[..outcome.new_dir_len], 1, b"a")
            .unwrap()
            .unwrap();
        assert!(f.entry.is_enabled());
    }

    #[test]
    fn enable_disable_round_trip() {
        let e = dir_entry(b"a", BME_FLAG_AUTO, 16, CLUSTER_SIZE, 1);
        let dir = build_dir(&[e]);
        let mut buf_a = [0u8; 512];
        let o1 = action_disable(&dir, dir.len(), 1, b"a", &mut buf_a).unwrap();
        let n1 = o1.new_dir_len;
        let mut buf_b = [0u8; 512];
        let o2 = action_enable(&buf_a[..n1], n1, 1, b"a", &mut buf_b).unwrap();
        // Round-trips back to the original directory bytes.
        assert_eq!(&buf_b[..o2.new_dir_len], &dir[..]);
    }

    #[test]
    fn enable_absent_is_not_found() {
        let e = dir_entry(b"a", 0, 16, CLUSTER_SIZE, 1);
        let dir = build_dir(&[e]);
        let mut out = [0u8; 512];
        assert_eq!(
            action_enable(&dir, dir.len(), 1, b"nope", &mut out),
            Err(BitmapError::BitmapNotFound)
        );
        assert_eq!(
            action_disable(&dir, dir.len(), 1, b"nope", &mut out),
            Err(BitmapError::BitmapNotFound)
        );
    }

    #[test]
    fn enable_disable_refuse_in_use() {
        let e = dir_entry(b"a", BME_FLAG_IN_USE, 16, CLUSTER_SIZE, 1);
        let dir = build_dir(&[e]);
        let mut out = [0u8; 512];
        assert_eq!(
            action_enable(&dir, dir.len(), 1, b"a", &mut out),
            Err(BitmapError::BitmapInUse)
        );
        assert_eq!(
            action_disable(&dir, dir.len(), 1, b"a", &mut out),
            Err(BitmapError::BitmapInUse)
        );
    }
}
