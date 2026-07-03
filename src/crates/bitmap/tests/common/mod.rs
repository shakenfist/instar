//! Shared fixture + assertion toolkit for the `bitmap` crate's
//! integration (`tests/`) suite.
//!
//! Unlike the amend suite (whose fixtures are whole qcow2 images
//! replayed from an `AmendPlan`), the `bitmap` crate is an I/O-free,
//! in-place **slice mutator** over caller-staged buffers: the bitmap
//! **directory** bytes and the qcow2 **refcount block** bytes, plus
//! scalar geometry. So the fixtures here are exactly those buffers —
//! a [`Fixture`] carries them together with a [`BitmapGeometry`], and
//! the `apply_*` helpers drive the crate's public `action_*` functions
//! the way the Phase-4 guest does (double-buffering the directory).
//!
//! Everything here goes through the crate's **public API**; the point
//! of the `tests/` crate is that it sees only `pub` items.
//!
//! # Toy refcount layout (Open question 2)
//!
//! The refcount fixtures use a single, self-consistent toy layout so
//! that [`refcount_at`] assertions are meaningful and the first-fit
//! allocator has free clusters to hand out:
//!
//! - `cluster_size = 65536` (64 KiB), `cluster_bits = 16`.
//! - `refcount_bits = 16` (the only width the allocator handles).
//! - **One** refcount block (`refblock_count = 1`,
//!   `host_refblocks_start = 0`), so refblock index 0 covers host
//!   cluster 0 and the staged buffer is exactly one cluster long.
//! - `entries_per_refblock = cluster_size * 8 / refcount_bits =
//!   65536 * 8 / 16 = 32768` clusters — far more than any fixture
//!   needs.
//! - `virtual_size = 64 MiB`. At the default granularity
//!   `2^16 = 65536` bytes/bit that is `1024` bits -> `128` bytes ->
//!   a single-cluster bitmap table (the realistic case).
//! - The first [`METADATA_CLUSTERS`] clusters (`0..8`) are reserved at
//!   **refcount 1** as stand-in image metadata (header, refcount
//!   table, the refcount block itself, L1, ...), so the allocator's
//!   first-fit scan starts handing out free clusters at index 8. Any
//!   pre-existing bitmap-table cluster a fixture places (via
//!   [`Fixture::with_bitmaps`]) is *also* marked refcount 1 and sits
//!   at or above index 8, keeping the occupied region contiguous and
//!   the layout self-consistent.

#![allow(dead_code)]

use bitmap::action::{
    action_add, action_clear, action_disable, action_enable, action_remove, ActionOutcome,
    BitmapGeometry,
};
use bitmap::BitmapError;
use qcow2::bitmap::{
    bitmap_bytes_needed, bitmap_table_size_entries, serialize_bitmap_dir_entry, BitmapDirEntry,
    BME_FLAG_AUTO, BME_FLAG_IN_USE, BT_DIRTY_TRACKING_BITMAP,
};
use snapshot::qcow2::{read_refcount_in_block, set_refcount_in_block, AllocCursor};

/// Toy cluster size: 64 KiB.
pub const CLUSTER_SIZE: u64 = 65536;
/// `log2(CLUSTER_SIZE)`.
pub const CLUSTER_BITS: u32 = 16;
/// The only refcount width the allocator handles.
pub const REFCOUNT_BITS: u32 = 16;
/// Toy image virtual size: 64 MiB (a single-cluster bitmap table at
/// the default granularity).
pub const VIRTUAL_SIZE: u64 = 64 * 1024 * 1024;
/// Refcount entries per staged refcount block:
/// `CLUSTER_SIZE * 8 / REFCOUNT_BITS = 32768`.
pub const EPR: u64 = (CLUSTER_SIZE * 8) / REFCOUNT_BITS as u64;
/// Clusters reserved as stand-in image metadata (refcount 1). The
/// allocator begins handing out free clusters at this index.
pub const METADATA_CLUSTERS: u64 = 8;

/// The toy [`BitmapGeometry`]: one refcount block, base at host
/// offset 0 (so refblock cluster index 0 == host cluster 0).
pub fn geometry() -> BitmapGeometry {
    BitmapGeometry {
        cluster_size: CLUSTER_SIZE,
        cluster_bits: CLUSTER_BITS,
        refcount_bits: REFCOUNT_BITS,
        virtual_size: VIRTUAL_SIZE,
        refblock_count: 1,
        host_refblocks_start: 0,
    }
}

/// The caller-staged state the Phase-4 guest hands to the actions: the
/// bitmap directory bytes (exactly `nb_bitmaps` packed entries), the
/// refcount-block bytes, and the geometry.
pub struct Fixture {
    /// Packed bitmap directory entries; `dir.len()` is the exact
    /// directory byte length (the `old_len` the actions take).
    pub dir: Vec<u8>,
    /// Number of entries currently in `dir`.
    pub nb_bitmaps: u32,
    /// Staged refcount block buffer (`refblock_count * cluster_size`).
    pub refblocks: Vec<u8>,
    /// Scalar geometry threaded through every action.
    pub geom: BitmapGeometry,
}

impl Fixture {
    /// An empty image: no bitmaps, refblocks with clusters
    /// `0..METADATA_CLUSTERS` occupied and the rest free.
    pub fn empty() -> Self {
        Fixture {
            dir: Vec::new(),
            nb_bitmaps: 0,
            refblocks: build_refblocks(METADATA_CLUSTERS),
            geom: geometry(),
        }
    }

    /// An image pre-populated with bitmaps. Each tuple is
    /// `(name, granularity_bits, enabled, in_use, table_cluster_index)`:
    /// the entry's `bitmap_table_offset` is
    /// `table_cluster_index * CLUSTER_SIZE` and its
    /// `bitmap_table_size` is derived from the geometry; each of the
    /// entry's table clusters is marked occupied (refcount 1) in the
    /// refblocks so `remove`/`clear` can free/observe them.
    pub fn with_bitmaps(specs: &[(&[u8], u8, bool, bool, u64)]) -> Self {
        let geom = geometry();
        let mut refblocks = build_refblocks(METADATA_CLUSTERS);
        let mut dir = Vec::new();
        let mut scratch = [0u8; 1200];

        for &(name, granularity_bits, enabled, in_use, table_cluster) in specs {
            let table_entries = table_entries_for(&geom, granularity_bits);
            let table_offset = table_cluster * geom.cluster_size;

            let mut flags = 0u32;
            if enabled {
                flags |= BME_FLAG_AUTO;
            }
            if in_use {
                flags |= BME_FLAG_IN_USE;
            }

            let mut entry = BitmapDirEntry::zeroed();
            entry.bitmap_table_offset = table_offset;
            entry.bitmap_table_size = table_entries;
            entry.flags = flags;
            entry.bitmap_type = BT_DIRTY_TRACKING_BITMAP;
            entry.granularity_bits = granularity_bits;
            entry.name_size = name.len() as u16;
            entry.extra_data_size = 0;
            entry.name[..name.len()].copy_from_slice(name);

            let n = serialize_bitmap_dir_entry(&entry, &mut scratch).expect("serialize entry");
            dir.extend_from_slice(&scratch[..n]);

            // Mark every table cluster this entry owns as occupied.
            let clusters = table_cluster_count(table_entries, geom.cluster_size);
            for i in 0..clusters {
                set_cluster_refcount(&mut refblocks, table_cluster + i, 1);
            }
        }

        Fixture {
            dir,
            nb_bitmaps: specs.len() as u32,
            refblocks,
            geom,
        }
    }
}

/// A comparable, heap-backed view of a parsed directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEntry {
    pub name: Vec<u8>,
    pub granularity_bits: u8,
    pub enabled: bool,
    pub in_use: bool,
    pub table_offset: u64,
    pub table_size: u32,
}

/// Walk `dir` (exactly `nb_bitmaps` packed entries) into a comparable
/// [`ParsedEntry`] list, using the crate's public
/// [`parse_bitmap_dir_entry`](qcow2::bitmap::parse_bitmap_dir_entry).
pub fn parse_entries(dir: &[u8], nb_bitmaps: u32) -> Vec<ParsedEntry> {
    let mut out = Vec::new();
    let mut off = 0usize;
    for _ in 0..nb_bitmaps {
        let (entry, size) =
            qcow2::bitmap::parse_bitmap_dir_entry(&dir[off..]).expect("parse dir entry");
        out.push(ParsedEntry {
            name: entry.name_bytes().to_vec(),
            granularity_bits: entry.granularity_bits,
            enabled: entry.is_enabled(),
            in_use: entry.is_in_use(),
            table_offset: entry.bitmap_table_offset,
            table_size: entry.bitmap_table_size,
        });
        off += size;
    }
    out
}

/// Number of bitmap-table entries an empty bitmap of the given
/// granularity needs for the toy geometry.
pub fn table_entries_for(geom: &BitmapGeometry, granularity_bits: u8) -> u32 {
    let granularity = 1u64 << granularity_bits;
    let bytes = bitmap_bytes_needed(geom.virtual_size, granularity);
    bitmap_table_size_entries(bytes, geom.cluster_size) as u32
}

/// Number of clusters a bitmap table of `table_size` entries occupies:
/// `ceil(table_size * 8 / cluster_size)`. Mirrors the crate-private
/// `table_cluster_count`.
pub fn table_cluster_count(table_size: u32, cluster_size: u64) -> u64 {
    (table_size as u64 * 8).div_ceil(cluster_size)
}

/// A staged refcount block buffer of one block with clusters
/// `0..occupied` at refcount 1 and the rest free.
pub fn build_refblocks(occupied: u64) -> Vec<u8> {
    let mut b = vec![0u8; CLUSTER_SIZE as usize];
    for c in 0..occupied {
        set_cluster_refcount(&mut b, c, 1);
    }
    b
}

/// Set the refcount of `cluster_index` within a single-block refblock
/// buffer (the toy layout has one block based at cluster 0).
fn set_cluster_refcount(refblocks: &mut [u8], cluster_index: u64, value: u64) {
    let rb_slot = (cluster_index / EPR) as usize;
    let local = cluster_index % EPR;
    let base = rb_slot * CLUSTER_SIZE as usize;
    set_refcount_in_block(
        &mut refblocks[base..base + CLUSTER_SIZE as usize],
        local,
        REFCOUNT_BITS,
        value,
    )
    .expect("set refcount");
}

/// Read the refcount of the cluster at host byte `host_offset` from the
/// staged refblocks, mirroring the crate-private
/// `refblock_byte_range_for_cluster` mapping.
pub fn refcount_at(refblocks: &[u8], geom: &BitmapGeometry, host_offset: u64) -> u64 {
    let epr = (geom.cluster_size * 8) / geom.refcount_bits as u64;
    let rel = host_offset - geom.host_refblocks_start;
    assert_eq!(
        rel % geom.cluster_size,
        0,
        "host_offset not cluster-aligned"
    );
    let cluster_index = rel / geom.cluster_size;
    let rb_slot = (cluster_index / epr) as usize;
    let local = cluster_index % epr;
    let base = rb_slot * geom.cluster_size as usize;
    read_refcount_in_block(
        &refblocks[base..base + geom.cluster_size as usize],
        local,
        geom.refcount_bits,
    )
    .expect("read refcount")
}

/// A fresh allocator cursor.
pub fn fresh_cursor() -> AllocCursor {
    AllocCursor::default()
}

/// Scratch out-buffer big enough for any single action's rewritten
/// directory (old directory + one appended max-size entry).
fn out_buffer(old_len: usize) -> Vec<u8> {
    vec![0u8; old_len + 2048]
}

/// Apply `add` to `f` with a fresh out-buffer, swapping the rewritten
/// directory in (the double-buffer the guest does) on success.
pub fn apply_add(
    f: &mut Fixture,
    cursor: &mut AllocCursor,
    name: &[u8],
    granularity_bits: u8,
) -> Result<ActionOutcome, BitmapError> {
    let old_len = f.dir.len();
    let mut out = out_buffer(old_len);
    let outcome = action_add(
        &f.dir,
        old_len,
        f.nb_bitmaps,
        name,
        granularity_bits,
        &mut f.refblocks,
        cursor,
        &f.geom,
        &mut out,
    )?;
    out.truncate(outcome.new_dir_len);
    f.dir = out;
    f.nb_bitmaps = outcome.new_nb_bitmaps;
    Ok(outcome)
}

/// Apply `remove` to `f`, swapping the compacted directory in.
pub fn apply_remove(f: &mut Fixture, name: &[u8]) -> Result<ActionOutcome, BitmapError> {
    let old_len = f.dir.len();
    let mut out = out_buffer(old_len);
    let outcome = action_remove(
        &f.dir,
        old_len,
        f.nb_bitmaps,
        name,
        &mut f.refblocks,
        &f.geom,
        &mut out,
    )?;
    out.truncate(outcome.new_dir_len);
    f.dir = out;
    f.nb_bitmaps = outcome.new_nb_bitmaps;
    Ok(outcome)
}

/// Apply `clear` to `f` (directory unchanged; validation only).
pub fn apply_clear(f: &mut Fixture, name: &[u8]) -> Result<ActionOutcome, BitmapError> {
    let old_len = f.dir.len();
    let mut out = out_buffer(old_len);
    let outcome = action_clear(
        &f.dir,
        old_len,
        f.nb_bitmaps,
        name,
        &mut f.refblocks,
        &f.geom,
        &mut out,
    )?;
    out.truncate(outcome.new_dir_len);
    f.dir = out;
    f.nb_bitmaps = outcome.new_nb_bitmaps;
    Ok(outcome)
}

/// Apply `enable` to `f` (no refblocks/cursor/geom).
pub fn apply_enable(f: &mut Fixture, name: &[u8]) -> Result<ActionOutcome, BitmapError> {
    let old_len = f.dir.len();
    let mut out = out_buffer(old_len);
    let outcome = action_enable(&f.dir, old_len, f.nb_bitmaps, name, &mut out)?;
    out.truncate(outcome.new_dir_len);
    f.dir = out;
    f.nb_bitmaps = outcome.new_nb_bitmaps;
    Ok(outcome)
}

/// Apply `disable` to `f` (no refblocks/cursor/geom).
pub fn apply_disable(f: &mut Fixture, name: &[u8]) -> Result<ActionOutcome, BitmapError> {
    let old_len = f.dir.len();
    let mut out = out_buffer(old_len);
    let outcome = action_disable(&f.dir, old_len, f.nb_bitmaps, name, &mut out)?;
    out.truncate(outcome.new_dir_len);
    f.dir = out;
    f.nb_bitmaps = outcome.new_nb_bitmaps;
    Ok(outcome)
}
