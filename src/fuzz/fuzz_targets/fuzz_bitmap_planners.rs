//! Coverage-guided fuzzing for the Phase-3 bitmap planner crate
//! (`src/crates/bitmap/`): the per-action validate-then-mutate
//! functions, the directory builders they call, and the pure `merge`
//! helpers.
//!
//! Input-synthesis archetype (like `fuzz_snapshot_refcount`): decode a
//! structured prefix into a `cluster_size` + geometry, build a refblock
//! buffer with a marked metadata prefix (so the allocator can succeed),
//! synthesise a plausible bitmap directory from the fuzz pool (valid
//! entries the crate's walker accepts, so the interesting alloc/free/
//! rewrite paths get covered rather than bouncing off the parse-reject
//! guard), and dispatch one fuzz-chosen action. On `Ok` — mirroring
//! `fuzz_amend_planners::check_amend_invariants` — assert the
//! outcome invariants; on any input the base oracle is panic-freedom.
//!
//! ## Invariants asserted on `Ok`
//!
//!   1. `new_dir_len <= out_dir.len()` (the outcome never claims more
//!      bytes than the scratch it was handed).
//!   2. `num_table_clusters_to_zero <= MAX_TABLE_CLUSTERS`.
//!   3. Every `table_clusters_to_zero[i]` is cluster-aligned relative to
//!      `host_refblocks_start` (0 here) and maps to a cluster index
//!      strictly inside the staged refblocks (the allocator only claims
//!      clusters it can see).
//!   4. The re-parsed new directory is self-consistent:
//!      `directory_byte_len(new_dir, new_nb_bitmaps) == Ok(new_dir_len)`.
//!
//! The `merge` helpers (`merge_cluster_action`, `or_bitmap_data`) and
//! `serialize_bitmaps_extension` are folded in and exercised
//! panic-free, with a serialize -> parse round-trip check on the
//! extension body.

#![no_main]
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;

use bitmap::action::{
    action_add, action_clear, action_disable, action_enable, action_remove, ActionOutcome,
    BitmapGeometry, MAX_TABLE_CLUSTERS,
};
use bitmap::directory::{directory_byte_len, serialize_bitmaps_extension};
use bitmap::merge::{merge_cluster_action, or_bitmap_data};
use qcow2::bitmap::{
    parse_bitmaps_extension, serialize_bitmap_dir_entry, BitmapDirEntry, BME_FLAG_AUTO,
    BME_FLAG_IN_USE, BT_DIRTY_TRACKING_BITMAP,
};
use snapshot::qcow2::{set_refcount_in_block, AllocCursor};

/// Cluster sizes matching the other planner fuzzers (power-of-two,
/// `cluster_bits` = `trailing_zeros`).
const CLUSTER_SIZES: [u64; 5] = [512, 4096, 65536, 1 << 20, 1 << 21];

/// Fixed refcount width v1 supports.
const REFCOUNT_BITS: u32 = 16;

/// One refblock is staged (a realistic small image needs no more).
const REFBLOCK_COUNT: u64 = 1;

/// Structured-prefix length; the rest is the synthesis pool.
const HEADER_BYTES: usize = 40;

/// Max synthesised directory-entry name length (keeps entries small).
const MAX_ENTRY_NAME: usize = 32;

/// Max number of synthesised directory entries.
const MAX_ENTRIES: usize = 8;

/// Directory scratch: `MAX_ENTRIES` worst-case entries plus one
/// appended `add` entry (name up to 1023 -> 1048 bytes) and headroom.
const DIR_SCRATCH: usize = MAX_ENTRIES * (24 + MAX_ENTRY_NAME + 8) + 2048;

struct Scratch {
    /// One refblock (sized to the largest cluster).
    refblocks: Vec<u8>,
    /// The synthesised old directory.
    dir: Vec<u8>,
    /// The action's output directory.
    out_dir: Vec<u8>,
    /// OR-scratch for `or_bitmap_data`.
    or_dst: Vec<u8>,
    or_src: Vec<u8>,
    /// Synthesised entry names, so an action can target an existing one.
    names: [[u8; MAX_ENTRY_NAME]; MAX_ENTRIES],
    name_lens: [usize; MAX_ENTRIES],
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch {
        refblocks: vec![0u8; 1usize << 21],
        dir: vec![0u8; DIR_SCRATCH],
        out_dir: vec![0u8; DIR_SCRATCH],
        or_dst: vec![0u8; 256],
        or_src: vec![0u8; 256],
        names: [[0u8; MAX_ENTRY_NAME]; MAX_ENTRIES],
        name_lens: [0usize; MAX_ENTRIES],
    });
}

/// Fill `buf` cyclically from `pool` starting at `*cursor`, advancing
/// it. An empty pool leaves a fixed pattern.
fn fill_from_pool(buf: &mut [u8], pool: &[u8], cursor: &mut usize) {
    if pool.is_empty() {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        return;
    }
    for b in buf.iter_mut() {
        *b = pool[*cursor % pool.len()];
        *cursor += 1;
    }
}

/// Pull one byte from the pool (cyclically), or a fallback when empty.
fn pool_byte(pool: &[u8], cursor: &mut usize, fallback: u8) -> u8 {
    if pool.is_empty() {
        return fallback;
    }
    let b = pool[*cursor % pool.len()];
    *cursor += 1;
    b
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_BYTES {
        return;
    }

    // ------------------------------------------------------------------
    // Decode the structured prefix.
    // ------------------------------------------------------------------
    let cluster_size = CLUSTER_SIZES[data[0] as usize % CLUSTER_SIZES.len()];
    let cluster_bits = cluster_size.trailing_zeros();
    let action_sel = data[1] % 5;
    let n_entries = (data[2] as usize) % (MAX_ENTRIES + 1);
    let add_granularity_bits = data[3];
    let used_seed = data[4] as u64;
    let target_sel = data[5];
    let add_name_len = u16::from_le_bytes([data[6], data[7]]) as usize;
    let virtual_size = u64::from_le_bytes(data[8..16].try_into().unwrap()) % (16u64 << 30);
    let merge_a = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let merge_b = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let or_len = (data[32] as usize) % 256;
    let entry_variety = data[33];

    let entries_per_refblock = cluster_size * 8 / REFCOUNT_BITS as u64;
    let total_entries = REFBLOCK_COUNT * entries_per_refblock;

    let geom = BitmapGeometry {
        cluster_size,
        cluster_bits,
        refcount_bits: REFCOUNT_BITS,
        virtual_size,
        refblock_count: REFBLOCK_COUNT,
        host_refblocks_start: 0,
    };

    let pool = &data[HEADER_BYTES..];

    SCRATCH.with(|cell| {
        let s = &mut *cell.borrow_mut();
        let mut cursor = 0usize;

        // --------------------------------------------------------------
        // Refblock: mark a metadata prefix occupied (refcount 1) so the
        // allocator's first-fit scan has both used and free runs.
        // --------------------------------------------------------------
        {
            let rb = &mut s.refblocks[..cluster_size as usize];
            rb.fill(0);
            let used = used_seed % entries_per_refblock.min(128).max(1);
            for c in 0..used {
                // Single refblock: cluster index == entry index.
                let _ = set_refcount_in_block(rb, c, REFCOUNT_BITS, 1);
            }
        }

        // --------------------------------------------------------------
        // Synthesise `n_entries` valid, parseable directory entries.
        // Distinct first name byte => unique names; cluster-aligned
        // in-range table pointers => remove/clear can reach the free
        // path.
        // --------------------------------------------------------------
        let mut dir_len = 0usize;
        let mut built = 0usize;
        for i in 0..n_entries {
            let name_len = (1 + ((entry_variety as usize).wrapping_add(i) % MAX_ENTRY_NAME))
                .min(MAX_ENTRY_NAME);
            s.name_lens[i] = name_len;
            s.names[i][0] = i as u8;
            for j in 1..name_len {
                s.names[i][j] = pool_byte(pool, &mut cursor, (i + j) as u8);
            }

            let fb = pool_byte(pool, &mut cursor, i as u8);
            let mut flags = 0u32;
            if fb & 0b01 != 0 {
                flags |= BME_FLAG_AUTO;
            }
            if fb & 0b10 != 0 {
                flags |= BME_FLAG_IN_USE;
            }
            let gbits = 9 + ((fb >> 2) % 23); // 9..=31 (plausible)
            let table_index = (fb as u64) % total_entries.max(1);
            let table_size = (fb as u32) % 3; // 0..=2 table entries

            let mut entry = BitmapDirEntry::zeroed();
            entry.bitmap_table_offset = table_index * cluster_size;
            entry.bitmap_table_size = table_size;
            entry.flags = flags;
            entry.bitmap_type = BT_DIRTY_TRACKING_BITMAP;
            entry.granularity_bits = gbits;
            entry.name_size = name_len as u16;
            entry.extra_data_size = 0;
            let name = s.names[i];
            entry.name[..name_len].copy_from_slice(&name[..name_len]);

            match serialize_bitmap_dir_entry(&entry, &mut s.dir[dir_len..]) {
                Some(written) => {
                    dir_len += written;
                    built += 1;
                }
                None => break,
            }
        }
        let nb_bitmaps = built as u32;

        // --------------------------------------------------------------
        // Target name: an existing entry's name (found paths) or a fresh
        // fuzz name (not-found / add). Owned so it does not alias the
        // Scratch fields borrowed by the action call below.
        // --------------------------------------------------------------
        let target: Vec<u8> = if nb_bitmaps > 0 && target_sel & 0x80 != 0 {
            let idx = (target_sel as usize) % nb_bitmaps as usize;
            s.names[idx][..s.name_lens[idx]].to_vec()
        } else {
            let tl = 1 + (target_sel as usize) % MAX_ENTRY_NAME;
            let mut tb = vec![0u8; tl];
            fill_from_pool(&mut tb, pool, &mut cursor);
            tb
        };

        // add name: may be empty or over-long (exercises NameTooLong).
        let add_name_len = add_name_len.min(1100);
        let mut add_name = vec![0u8; add_name_len];
        fill_from_pool(&mut add_name, pool, &mut cursor);

        // --------------------------------------------------------------
        // Dispatch one action over disjoint-field borrows.
        // --------------------------------------------------------------
        let mut alloc_cursor = AllocCursor::default();
        let result = {
            let Scratch {
                refblocks,
                dir,
                out_dir,
                ..
            } = &mut *s;
            let rb = &mut refblocks[..cluster_size as usize];
            let old_dir = &dir[..dir_len];
            let out = &mut out_dir[..];
            match action_sel {
                0 => action_add(
                    old_dir,
                    dir_len,
                    nb_bitmaps,
                    &add_name,
                    add_granularity_bits,
                    rb,
                    &mut alloc_cursor,
                    &geom,
                    out,
                ),
                1 => action_remove(old_dir, dir_len, nb_bitmaps, &target, rb, &geom, out),
                2 => action_clear(old_dir, dir_len, nb_bitmaps, &target, rb, &geom, out),
                3 => action_enable(old_dir, dir_len, nb_bitmaps, &target, out),
                _ => action_disable(old_dir, dir_len, nb_bitmaps, &target, out),
            }
        };

        if let Ok(outcome) = result {
            check_outcome(&outcome, &s.out_dir, cluster_size, total_entries);
        }

        // --------------------------------------------------------------
        // merge helpers: purely functional, exercise panic-free.
        // --------------------------------------------------------------
        let _ = merge_cluster_action(merge_a, merge_b);
        let _ = merge_cluster_action(merge_b, merge_a);

        {
            let dst = &mut s.or_dst[..or_len];
            fill_from_pool(dst, pool, &mut cursor);
        }
        {
            let src = &mut s.or_src[..or_len];
            fill_from_pool(src, pool, &mut cursor);
        }
        {
            let (dst, src) = (&mut s.or_dst[..or_len], &s.or_src[..or_len]);
            or_bitmap_data(dst, src).expect("equal-length OR must succeed");
        }

        // --------------------------------------------------------------
        // Extension body round-trip (serialize -> parse identity on the
        // success path).
        // --------------------------------------------------------------
        let mut ext = [0u8; 24];
        let e_nb = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if serialize_bitmaps_extension(e_nb, merge_a, merge_b, &mut ext).is_ok() {
            if let Some(parsed) = parse_bitmaps_extension(&ext) {
                assert_eq!(parsed.nb_bitmaps, e_nb, "extension nb_bitmaps round-trip");
                assert_eq!(
                    parsed.bitmap_directory_size, merge_a,
                    "extension size round-trip",
                );
                assert_eq!(
                    parsed.bitmap_directory_offset, merge_b,
                    "extension offset round-trip",
                );
            }
        }
    });
});

/// The outcome invariants, asserted only on `Ok`.
fn check_outcome(
    outcome: &ActionOutcome,
    out_dir: &[u8],
    cluster_size: u64,
    total_entries: u64,
) {
    // 1. The claimed directory length fits the scratch it was written to.
    assert!(
        outcome.new_dir_len <= out_dir.len(),
        "new_dir_len {} exceeds out_dir capacity {}",
        outcome.new_dir_len,
        out_dir.len(),
    );

    // 2. The zero-list count is within the fixed array.
    assert!(
        outcome.num_table_clusters_to_zero <= MAX_TABLE_CLUSTERS,
        "num_table_clusters_to_zero {} > MAX_TABLE_CLUSTERS ({})",
        outcome.num_table_clusters_to_zero,
        MAX_TABLE_CLUSTERS,
    );

    // 3. Every reported table cluster is inside the staged refblocks
    //    (host_refblocks_start is 0 in this harness).
    for i in 0..outcome.num_table_clusters_to_zero {
        let off = outcome.table_clusters_to_zero[i];
        assert_eq!(
            off % cluster_size,
            0,
            "table cluster {i} offset {off} not cluster-aligned",
        );
        let cluster_index = off / cluster_size;
        assert!(
            cluster_index < total_entries,
            "table cluster {i} index {cluster_index} outside refblocks ({total_entries})",
        );
    }

    // 4. The re-parsed new directory is self-consistent: exactly
    //    `new_nb_bitmaps` entries occupy exactly `new_dir_len` bytes.
    assert_eq!(
        directory_byte_len(&out_dir[..outcome.new_dir_len], outcome.new_nb_bitmaps),
        Ok(outcome.new_dir_len),
        "new directory does not re-parse to new_nb_bitmaps entries / new_dir_len",
    );
}
