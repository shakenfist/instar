//! Coverage-guided fuzzing for the snapshot crate's mutator
//! primitives — the "no corruption regardless of input" surface
//! the master plan flags as the part needing care.
//!
//! Structured-header planner archetype (like
//! `fuzz_resize_planners`): decode a 32-byte header, synthesize
//! staged slices from the remaining input, dispatch one mutator
//! per exec via an op selector, and assert semantic invariants
//! on success — errors are silently ignored; panic (and ASAN)
//! is the base oracle, the asserts are the semantic oracle.
//!
//! Header layout (LE):
//!
//! ```text
//!   0:      op selector (% 7)
//!   1:      flags: bit0 extended_l2, bit1 set/clear for the
//!           flag helpers
//!   2:      refcount_bits selector (% 7 -> 1/2/4/8/16/32/64)
//!   3:      cluster_bits = 9 + (% 6)  (9..=14)
//!   4:      refblock_count = 1 + (% 4)
//!   5:      L1 entry count (% 65, 0..=64)
//!   6:      L2 slot length = (% 65) * 16  (0..=1024 bytes)
//!   7:      id length (% 65)
//!   8:      name length (raw u8, 0..=255)
//!   9:      allocator cluster count (% 18, 0..=17 incl. 0)
//!   10..12: flag-helper entry index (u16)
//!   12..20: L2-presence bitmask (u64)
//!   20..28: host_refblocks_start (u64, masked to 48 bits)
//!   28:     old-table entry count for the table op (% 4)
//!           and removal-index seed
//!   29:     allocator cursor refblock seed
//!   30..32: allocator cursor entry seed (u16)
//! ```
//!
//! The pool (bytes 32..) fills, in order: refblocks
//! (refblock_count x cluster_size), L1-A (n x 8), L1-B (n x 8,
//! the SwapForApply to-side), the L2 pool (n slots of the L2
//! slot length), id bytes, name bytes, and a 1 KiB old-table
//! window — each cyclically from the pool.
//!
//! ## The invariant set (phase 12 plan), re-derived
//!
//! 1. **Precheck never mutates.** `precheck_snapshot_refcount`
//!    takes `refblocks: &[u8]` ("the borrow makes the
//!    no-mutation guarantee structural", phase 7b); the
//!    byte-identity assert guards interior-mutability
//!    regressions and documents the contract.
//! 2. **Precheck-Ok implies apply-Ok** — *conditioned on the
//!    visited refcount-entry multiset being duplicate-free per
//!    walk side*. Derivation: the precheck is exactly
//!    `update_snapshot_refcount`'s pass 1 (phase 7b: it
//!    delegates to the same `dry_run_refcount_pass` dispatch),
//!    so precheck-Ok always implies the apply's own pass 1
//!    passes. Pass 2's only divergent error channel is
//!    value-dependent: every structural failure (staging gap,
//!    bounds, unsupported width) is deterministic and shared
//!    with pass 1, but pass 2 re-runs
//!    `check_refcount_after_addend` against values *mutated
//!    earlier in the same pass*. A cluster whose refcount entry
//!    is visited twice (two L2 entries resolving to the same
//!    entry — reachable because standard L2 offsets need not be
//!    cluster-aligned, compressed payloads share containing
//!    clusters, and an L2-table cluster can collide with a data
//!    cluster) can pass the per-visit dry-run check yet
//!    overflow (inc) or underflow (dec) on its second apply
//!    visit. Such staged state is a corrupt image by qcow2
//!    refcount semantics, not a planner bug, so the
//!    unconditional form of this invariant is FALSE and would
//!    burn the nightly lane with phantom crashes; the harness
//!    computes each side's visit multiset (replicating the
//!    crate's classification walk) and asserts only when it is
//!    duplicate-free. For SwapForApply, per-side freedom
//!    suffices: the dec side applies wholly before the inc
//!    side, so a cross-side shared cluster gives the inc check
//!    strictly more headroom than the dry-run validated.
//! 3. **Inc/dec round-trip identity**, asserted unconditionally
//!    on inc success. Derivation: both walks visit the same
//!    multiset (deterministic walk over identical staged
//!    state). If `IncrementForCreate` succeeded, every visited
//!    entry holds original + multiplicity. The paired
//!    `DecrementForDelete` must then succeed: its structural
//!    error paths already passed during the inc; its dry-run
//!    checks current >= 1 against post-inc values (>=
//!    multiplicity >= 1); its apply pass sees val + m - k >= 1
//!    at every visit. +1 then -1 per visit restores every entry
//!    exactly, and `set_refcount_in_block` masks sub-byte
//!    widths so co-resident bits are untouched — refblocks are
//!    byte-identical to the start state.
//! 4. **Flag-walker idempotence and containment** (phase 8b
//!    contract): on a successful `update_copied_flags_for_l1`,
//!    only bit 63 of each L1/L2 type-and-offset word may have
//!    changed (the dispatched helpers preserve every other bit)
//!    and extended-L2 bitmap halves are untouched; afterwards
//!    every allocated entry's COPIED bit equals
//!    `refcount_for_cluster(target) == 1` (for an L1 entry the
//!    target is its L2 table cluster) while offset-zero entries
//!    are scrubbed clear; a second run reports 0 rewrites and
//!    changes no byte (the walk re-derives the same `want` from
//!    unmodified refblocks and unmodified offsets, and `has`
//!    already equals `want` everywhere).
//! 5. **Allocator claims exactly what it says**: on success the
//!    `count` claimed entries read 0 in a pre-call snapshot and
//!    1 after, no other refblock byte changes (the claim loop
//!    writes value 1 to exactly the run's entries),
//!    `(offset - host_refblocks_start) / cluster_size` is the
//!    first claimed flat index, and the cursor lands just past
//!    the run (never backwards — the scan resumes at the
//!    cursor). `count == 0` errors `InvalidConfig` when
//!    `refcount_bits == 16` (the width gate precedes it; the
//!    cluster-size gate passes by construction). On
//!    `RefcountExhausted`, a verification scan from the
//!    cursor's flat start confirms no `count`-run of zeros
//!    exists: the crate's first-fit scan is exhaustive
//!    (skipping to one past the blocking occupied entry cannot
//!    skip a candidate run start, since any earlier start's
//!    window would contain that occupied entry).
//! 6. **Flag-helper containment**:
//!    `rewrite_l1_entry_copied_flag` /
//!    `rewrite_l2_entry_copied_flag` read the targeted 8-byte
//!    type-and-offset word, set or clear bit 63, and write the
//!    same word back; the bounds check precedes mutation, so on
//!    error nothing changes. Byte-compare the full buffer minus
//!    that bit.
//! 7. **Table round-trip coherence**: a serialized
//!    `NewSnapshotEntry` appended via `build_snapshot_table` to
//!    an old table accepted by `snapshot_table_byte_len` yields
//!    a table whose byte_len equals the returned length (the
//!    old entries re-walk byte-identically and the new entry
//!    starts at the walk's own 8-aligned offset), whose last
//!    entry's bounds recover the serialized bytes verbatim, and
//!    from which `build_snapshot_table_without` produces a
//!    table whose surviving entries are byte-identical (via
//!    bounds extraction) and whose byte_len re-parses at one
//!    fewer entry.
//!
//! (A phase 12 invariant 8 covered `SnapshotPlan::push`'s bound;
//! the never-adopted `SnapshotPlan` API and its op 7 were removed
//! in PLAN-snapshot phase 14.)

#![no_main]
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;

use snapshot::qcow2::{
    alloc_contiguous_clusters_in_refblocks, for_each_cluster_in_l1, precheck_snapshot_refcount,
    read_refcount_in_block, rewrite_l1_entry_copied_flag, rewrite_l2_entry_copied_flag,
    set_refcount_in_block, update_copied_flags_for_l1, update_snapshot_refcount, AllocCursor,
    SnapshotRefcountOp,
};
use snapshot::table::{
    build_snapshot_table, build_snapshot_table_without, serialize_snapshot_entry,
    snapshot_table_byte_len, snapshot_table_entry_bounds, NewSnapshotEntry,
};
use snapshot::SnapshotError;

const HEADER_BYTES: usize = 32;

/// Maximum staged sizes (cluster_bits <= 14, refblock_count <= 4,
/// L1 entries <= 64, L2 slot <= 1024 bytes).
const MAX_REFBLOCKS: usize = 4 * 16384;
const MAX_L1: usize = 64 * 8;
const MAX_L2_POOL: usize = 64 * 1024;
const OLD_TABLE_BYTES: usize = 1024;
/// Serialized new entry: 40 header + 24 extra + id(<=64) +
/// name(<=255).
const MAX_SER: usize = 40 + 24 + 64 + 255;
/// Combined table output: 8-aligned old table + new entry.
const MAX_TABLE_OUT: usize = OLD_TABLE_BYTES + 8 + MAX_SER;

struct Scratch {
    refblocks: Vec<u8>,
    refblocks_before: Vec<u8>,
    l1a: Vec<u8>,
    l1b: Vec<u8>,
    l2_pool: Vec<u8>,
    snap_a: Vec<u8>,
    snap_b: Vec<u8>,
    table_out: Vec<u8>,
    table_out2: Vec<u8>,
    visits: Vec<u64>,
}

thread_local! {
    /// Reusable staging buffers (resize-target pattern), sized to
    /// the worst case so every exec reuses the allocations.
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch {
        refblocks: vec![0u8; MAX_REFBLOCKS],
        refblocks_before: vec![0u8; MAX_REFBLOCKS],
        l1a: vec![0u8; MAX_L1],
        l1b: vec![0u8; MAX_L1],
        l2_pool: vec![0u8; MAX_L2_POOL],
        snap_a: vec![0u8; MAX_REFBLOCKS],
        snap_b: vec![0u8; MAX_L2_POOL],
        table_out: vec![0u8; MAX_TABLE_OUT],
        table_out2: vec![0u8; MAX_TABLE_OUT],
        visits: Vec::with_capacity(64 * 130),
    });
}

/// Fill `buf` cyclically from `pool` starting at `*cursor`,
/// advancing the cursor. An empty pool zero-fills.
fn fill_from_pool(buf: &mut [u8], pool: &[u8], cursor: &mut usize) {
    if pool.is_empty() {
        buf.fill(0);
        return;
    }
    for b in buf.iter_mut() {
        *b = pool[*cursor % pool.len()];
        *cursor += 1;
    }
}

/// Decoded header fields shared by the op handlers.
#[derive(Clone, Copy)]
struct Cfg {
    extended_l2: bool,
    helper_set: bool,
    refcount_bits: u32,
    cluster_bits: u32,
    cluster_size: usize,
    refblock_count: u64,
    entries_per_refblock: u64,
    l1_entries: usize,
    l2_slot_len: usize,
    presence: u64,
    host_start: u64,
}

impl Cfg {
    /// Canonical refblock mapping shared by every op: flat
    /// cluster index = host_offset >> cluster_bits, refblock =
    /// flat / entries_per_refblock (None past the staged
    /// refblocks), local entry = flat % entries_per_refblock.
    fn rbf(&self, host_offset: u64) -> Option<(usize, u64)> {
        let flat = host_offset >> self.cluster_bits;
        let rb_idx = flat / self.entries_per_refblock;
        if rb_idx >= self.refblock_count {
            return None;
        }
        Some((
            rb_idx as usize * self.cluster_size,
            flat % self.entries_per_refblock,
        ))
    }

    /// Immutable L2 lookup over a pool slice: slot `idx` when the
    /// presence bit is set, None otherwise (drives the
    /// MisalignedAccess staging-gap path).
    fn l2_slot<'p>(&self, pool: &'p [u8], idx: u32) -> Option<&'p [u8]> {
        if self.presence & (1u64 << (idx % 64)) == 0 {
            return None;
        }
        let start = idx as usize * self.l2_slot_len;
        pool.get(start..start + self.l2_slot_len)
    }

    /// Read the refcount for `flat` from concatenated refblocks.
    /// Panics on a staging bug (the harness sizes refblocks to
    /// cover every flat index below refblock_count * e_p_r).
    fn read_flat(&self, blocks: &[u8], flat: u64) -> u64 {
        let rb = (flat / self.entries_per_refblock) as usize * self.cluster_size;
        read_refcount_in_block(
            &blocks[rb..rb + self.cluster_size],
            flat % self.entries_per_refblock,
            self.refcount_bits,
        )
        .expect("staged refblocks cover every flat index")
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_BYTES {
        return;
    }

    // ------------------------------------------------------------------
    // Decode the structured header.
    // ------------------------------------------------------------------
    let op = data[0] % 7;
    let refcount_bits = match data[2] % 7 {
        0 => 1u32,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        5 => 32,
        _ => 64,
    };
    let cluster_bits = 9 + (data[3] % 6) as u32; // 9..=14
    let cluster_size = 1usize << cluster_bits;
    let cfg = Cfg {
        extended_l2: data[1] & 0b1 != 0,
        helper_set: data[1] & 0b10 != 0,
        refcount_bits,
        cluster_bits,
        cluster_size,
        refblock_count: 1 + (data[4] % 4) as u64,
        entries_per_refblock: (cluster_size as u64 * 8) / refcount_bits as u64,
        l1_entries: (data[5] % 65) as usize, // 0..=64
        l2_slot_len: (data[6] % 65) as usize * 16, // 0..=1024
        presence: u64::from_le_bytes(data[12..20].try_into().unwrap()),
        host_start: u64::from_le_bytes(data[20..28].try_into().unwrap()) & ((1 << 48) - 1),
    };
    let id_len = (data[7] % 65) as usize;
    let name_len = data[8] as usize;
    let alloc_count = (data[9] % 18) as u64; // 0..=17
    let helper_idx = u16::from_le_bytes(data[10..12].try_into().unwrap()) as u32;
    let nb_old = (data[28] % 4) as u32;
    let cursor_rb_seed = data[29] as u64;
    let cursor_entry_seed = u16::from_le_bytes(data[30..32].try_into().unwrap()) as u64;

    let pool = &data[HEADER_BYTES..];

    SCRATCH.with(|cell| {
        let s = &mut *cell.borrow_mut();

        // --------------------------------------------------------------
        // Synthesize the staged state from the pool.
        // --------------------------------------------------------------
        let rb_len = cfg.refblock_count as usize * cfg.cluster_size;
        let l1_len = cfg.l1_entries * 8;
        let l2_len = cfg.l1_entries * cfg.l2_slot_len;
        let mut cursor = 0usize;
        fill_from_pool(&mut s.refblocks[..rb_len], pool, &mut cursor);
        fill_from_pool(&mut s.l1a[..l1_len], pool, &mut cursor);
        fill_from_pool(&mut s.l1b[..l1_len], pool, &mut cursor);
        fill_from_pool(&mut s.l2_pool[..l2_len], pool, &mut cursor);
        let mut id_buf = [0u8; 64];
        let mut name_buf = [0u8; 255];
        fill_from_pool(&mut id_buf[..id_len], pool, &mut cursor);
        fill_from_pool(&mut name_buf[..name_len], pool, &mut cursor);
        let mut old_table = [0u8; OLD_TABLE_BYTES];
        fill_from_pool(&mut old_table, pool, &mut cursor);

        match op {
            0 | 1 | 2 => run_refcount_op(op, &cfg, s, rb_len, l1_len, l2_len),
            3 => run_flag_walker(&cfg, s, rb_len, l1_len, l2_len),
            4 => run_allocator(
                &cfg,
                s,
                rb_len,
                alloc_count,
                cursor_rb_seed,
                cursor_entry_seed,
            ),
            5 => run_flag_helpers(&cfg, s, l1_len, l2_len, helper_idx),
            _ => run_table_round_trip(
                &cfg,
                s,
                &old_table,
                nb_old,
                &id_buf[..id_len],
                &name_buf[..name_len],
                data,
            ),
        }
    });
});

// ---------------------------------------------------------------------------
// Ops 0..=2: refcount mutators (invariants 1, 2, 3).
// ---------------------------------------------------------------------------

fn run_refcount_op(
    op: u8,
    cfg: &Cfg,
    s: &mut Scratch,
    rb_len: usize,
    l1_len: usize,
    l2_len: usize,
) {
    let refblocks = &mut s.refblocks[..rb_len];
    let before = &mut s.refblocks_before[..rb_len];
    before.copy_from_slice(refblocks);

    let l1a = &s.l1a[..l1_len];
    let l1b = &s.l1b[..l1_len];
    let l2_pool = &s.l2_pool[..l2_len];
    let l2f = |idx: u32| cfg.l2_slot(l2_pool, idx);
    let rbf = |off: u64| cfg.rbf(off);
    let mk_op = || match op {
        0 => SnapshotRefcountOp::IncrementForCreate { snapshot_l1: l1a },
        1 => SnapshotRefcountOp::DecrementForDelete { snapshot_l1: l1a },
        _ => SnapshotRefcountOp::SwapForApply {
            from_l1: l1a,
            to_l1: l1b,
        },
    };

    let pre = precheck_snapshot_refcount(
        mk_op(),
        refblocks,
        cfg.cluster_bits,
        cfg.refcount_bits,
        cfg.extended_l2,
        l2f,
        rbf,
    );
    // Invariant 1: the precheck leaves refblocks byte-identical,
    // success or failure.
    assert_eq!(
        refblocks, before,
        "snapshot refcount: precheck mutated refblocks",
    );

    // Invariant-2 precondition: per-side duplicate-freedom of the
    // visited refcount-entry multiset (see module docs). The walk
    // replicates the crate's classification: for_each_cluster_in_l1
    // yields the data-cluster visits, and each non-zero L1 entry
    // contributes one L2-table-cluster visit.
    let visits = &mut s.visits;
    let mut side_dup_free = |l1: &[u8]| -> bool {
        visits.clear();
        let walked = for_each_cluster_in_l1(l1, cfg.cluster_bits, l2f, cfg.extended_l2, |r| {
            visits.push(r.host_offset >> cfg.cluster_bits);
            true
        });
        if walked.is_err() {
            // Staging gap: the precheck failed too, so invariant 2
            // is vacuous for this input.
            return false;
        }
        for chunk in l1.chunks_exact(8) {
            let raw = u64::from_be_bytes(chunk.try_into().unwrap());
            let l2_off = raw & qcow2::L1_OFFSET_MASK;
            if l2_off != 0 {
                visits.push(l2_off >> cfg.cluster_bits);
            }
        }
        visits.sort_unstable();
        visits.windows(2).all(|w| w[0] != w[1])
    };
    let dup_free = match op {
        2 => side_dup_free(l1a) && side_dup_free(l1b),
        _ => side_dup_free(l1a),
    };

    let upd = update_snapshot_refcount(
        mk_op(),
        refblocks,
        cfg.cluster_bits,
        cfg.refcount_bits,
        cfg.extended_l2,
        l2f,
        rbf,
    );
    // Invariant 2 (conditional form, see module docs).
    if pre.is_ok() && dup_free {
        assert!(
            upd.is_ok(),
            "snapshot refcount: precheck accepted but apply failed ({:?}) \
             on a duplicate-free visit set",
            upd,
        );
    }

    // Invariant 3: inc then dec restores byte-identity.
    if op == 0 && upd.is_ok() {
        let dec = update_snapshot_refcount(
            SnapshotRefcountOp::DecrementForDelete { snapshot_l1: l1a },
            refblocks,
            cfg.cluster_bits,
            cfg.refcount_bits,
            cfg.extended_l2,
            l2f,
            rbf,
        );
        assert!(
            dec.is_ok(),
            "snapshot refcount: decrement failed ({:?}) after a successful \
             increment over identical state",
            dec,
        );
        assert_eq!(
            refblocks, before,
            "snapshot refcount: inc/dec round trip is not byte-identical",
        );
    }
}

// ---------------------------------------------------------------------------
// Op 3: COPIED-flag walker (invariant 4).
// ---------------------------------------------------------------------------

fn run_flag_walker(cfg: &Cfg, s: &mut Scratch, rb_len: usize, l1_len: usize, l2_len: usize) {
    let stride = if cfg.extended_l2 { 16usize } else { 8usize };

    let l1_before = &mut s.snap_a[..l1_len];
    l1_before.copy_from_slice(&s.l1a[..l1_len]);
    let l2_before = &mut s.snap_b[..l2_len];
    l2_before.copy_from_slice(&s.l2_pool[..l2_len]);

    let r1 = walk_copied_flags(cfg, s, rb_len, l1_len, l2_len);
    if r1.is_err() {
        // Errors are silently ignored; a failed walk may have
        // partially rewritten flags, which is the documented
        // caller-visible behaviour (the guest aborts the op).
        return;
    }

    let refblocks = &s.refblocks[..rb_len];
    let rc = |host_offset: u64| -> Option<u64> {
        let (rb_off, local) = cfg.rbf(host_offset)?;
        read_refcount_in_block(
            &refblocks[rb_off..rb_off + cfg.cluster_size],
            local,
            cfg.refcount_bits,
        )
        .ok()
    };

    // Containment: only bit 63 of each 8-byte type-and-offset
    // word may differ; extended-L2 bitmap halves byte-identical.
    let l1 = &s.l1a[..l1_len];
    let l2_after = &s.l2_pool[..l2_len];
    let l1_before = &s.snap_a[..l1_len];
    let l2_before = &s.snap_b[..l2_len];
    for (i, (a, b)) in l1_before
        .chunks_exact(8)
        .zip(l1.chunks_exact(8))
        .enumerate()
    {
        let a = u64::from_be_bytes(a.try_into().unwrap());
        let b = u64::from_be_bytes(b.try_into().unwrap());
        assert_eq!(
            (a ^ b) & !qcow2::OFLAG_COPIED,
            0,
            "snapshot flags: L1 entry {i} changed outside bit 63",
        );
    }
    let mut off = 0usize;
    while off + stride <= l2_len {
        let a = u64::from_be_bytes(l2_before[off..off + 8].try_into().unwrap());
        let b = u64::from_be_bytes(l2_after[off..off + 8].try_into().unwrap());
        assert_eq!(
            (a ^ b) & !qcow2::OFLAG_COPIED,
            0,
            "snapshot flags: L2 word at {off} changed outside bit 63",
        );
        if cfg.extended_l2 {
            assert_eq!(
                &l2_before[off + 8..off + 16],
                &l2_after[off + 8..off + 16],
                "snapshot flags: extended-L2 bitmap half changed",
            );
        }
        off += stride;
    }
    assert_eq!(
        &l2_before[off..],
        &l2_after[off..],
        "snapshot flags: L2 tail bytes changed",
    );

    // Post-state: COPIED equals (refcount == 1) for every
    // allocated entry; offset-zero entries are scrubbed clear
    // (the phase 8b contract).
    for (i, chunk) in l1.chunks_exact(8).enumerate() {
        let raw = u64::from_be_bytes(chunk.try_into().unwrap());
        let l2_off = raw & qcow2::L1_OFFSET_MASK;
        if l2_off == 0 {
            continue;
        }
        let want = rc(l2_off) == Some(1);
        assert_eq!(
            raw & qcow2::OFLAG_COPIED != 0,
            want,
            "snapshot flags: L1 entry {i} COPIED disagrees with refcount",
        );
        let l2_slice = cfg
            .l2_slot(l2_after, i as u32)
            .expect("walker succeeded, so every allocated slot is present");
        for (j, e) in l2_slice.chunks_exact(stride).enumerate() {
            let e = u64::from_be_bytes(e[..8].try_into().unwrap());
            let masked = e & !qcow2::OFLAG_COPIED;
            if masked == 0 {
                assert_eq!(
                    e & qcow2::OFLAG_COPIED,
                    0,
                    "snapshot flags: scrubbed entry {j} kept COPIED",
                );
                continue;
            }
            let host = if e & qcow2::OFLAG_COMPRESSED != 0 {
                let raw_off = e & !(qcow2::OFLAG_COMPRESSED | qcow2::OFLAG_COPIED);
                raw_off & !((1u64 << cfg.cluster_bits) - 1)
            } else {
                let v = e & qcow2::L2_OFFSET_MASK;
                if v == 0 {
                    assert_eq!(
                        e & qcow2::OFLAG_COPIED,
                        0,
                        "snapshot flags: zero-offset entry {j} kept COPIED",
                    );
                    continue;
                }
                v
            };
            let want = rc(host) == Some(1);
            assert_eq!(
                e & qcow2::OFLAG_COPIED != 0,
                want,
                "snapshot flags: L2 entry {j} COPIED disagrees with refcount",
            );
        }
    }

    // Idempotence: a second run succeeds, rewrites nothing, and
    // changes no byte.
    let l1_snap = &mut s.snap_a[..l1_len];
    l1_snap.copy_from_slice(&s.l1a[..l1_len]);
    let l2_snap = &mut s.snap_b[..l2_len];
    l2_snap.copy_from_slice(&s.l2_pool[..l2_len]);
    let r2 = walk_copied_flags(cfg, s, rb_len, l1_len, l2_len);
    assert_eq!(
        r2,
        Ok(0),
        "snapshot flags: second walker run must succeed with 0 rewrites",
    );
    assert_eq!(
        &s.l1a[..l1_len],
        &s.snap_a[..l1_len],
        "snapshot flags: second walker run changed L1 bytes",
    );
    assert_eq!(
        &s.l2_pool[..l2_len],
        &s.snap_b[..l2_len],
        "snapshot flags: second walker run changed L2 bytes",
    );
}

/// One `update_copied_flags_for_l1` run over the scratch state.
///
/// The mutable L2 lookup uses the raw-pointer reborrow pattern
/// the crate's own tests and the guest binary use. SAFETY: the
/// walker visits each L1 index once per run (so one live
/// reborrow exists at a time), distinct indices map to disjoint
/// slots, and no other reference to `l2_pool` is live across the
/// call (the pointer is taken fresh per run).
fn walk_copied_flags(
    cfg: &Cfg,
    s: &mut Scratch,
    rb_len: usize,
    l1_len: usize,
    l2_len: usize,
) -> Result<u32, SnapshotError> {
    let refblocks = &s.refblocks[..rb_len];
    let rc = |host_offset: u64| -> Option<u64> {
        let (rb_off, local) = cfg.rbf(host_offset)?;
        read_refcount_in_block(
            &refblocks[rb_off..rb_off + cfg.cluster_size],
            local,
            cfg.refcount_bits,
        )
        .ok()
    };
    let l2_ptr = s.l2_pool.as_mut_ptr();
    let l2mf = |idx: u32| -> Option<&mut [u8]> {
        if cfg.presence & (1u64 << (idx % 64)) == 0 {
            return None;
        }
        let start = idx as usize * cfg.l2_slot_len;
        if start + cfg.l2_slot_len > l2_len {
            return None;
        }
        Some(unsafe { core::slice::from_raw_parts_mut(l2_ptr.add(start), cfg.l2_slot_len) })
    };
    update_copied_flags_for_l1(
        &mut s.l1a[..l1_len],
        cfg.cluster_bits,
        l2mf,
        rc,
        cfg.extended_l2,
    )
}

// ---------------------------------------------------------------------------
// Op 4: contiguous allocator (invariant 5).
// ---------------------------------------------------------------------------

fn run_allocator(
    cfg: &Cfg,
    s: &mut Scratch,
    rb_len: usize,
    alloc_count: u64,
    cursor_rb_seed: u64,
    cursor_entry_seed: u64,
) {
    let refblocks = &mut s.refblocks[..rb_len];
    let before = &mut s.refblocks_before[..rb_len];
    before.copy_from_slice(refblocks);

    let mut cursor = AllocCursor {
        next_refblock: cursor_rb_seed % (cfg.refblock_count + 1),
        next_entry_in_refblock: cursor_entry_seed % (cfg.entries_per_refblock + 1),
        allocated: 0,
    };
    let flat0 =
        cursor.next_refblock * cfg.entries_per_refblock + cursor.next_entry_in_refblock;
    let total_entries = cfg.refblock_count * cfg.entries_per_refblock;

    let res = alloc_contiguous_clusters_in_refblocks(
        refblocks,
        cfg.cluster_size as u64,
        cfg.refcount_bits,
        cfg.refblock_count,
        cfg.host_start,
        alloc_count,
        &mut cursor,
    );
    match res {
        Ok(offset) => {
            assert!(
                offset >= cfg.host_start,
                "snapshot alloc: returned offset below host_refblocks_start",
            );
            let first = (offset - cfg.host_start) / cfg.cluster_size as u64;
            assert!(
                first >= flat0,
                "snapshot alloc: claimed run starts before the cursor",
            );
            for k in 0..alloc_count {
                assert_eq!(
                    cfg.read_flat(before, first + k),
                    0,
                    "snapshot alloc: claimed entry {k} was not free",
                );
                assert_eq!(
                    cfg.read_flat(refblocks, first + k),
                    1,
                    "snapshot alloc: claimed entry {k} not set to 1",
                );
            }
            // No other byte changed: replay the claim on the
            // snapshot and compare whole buffers.
            for k in 0..alloc_count {
                let flat = first + k;
                let rb = (flat / cfg.entries_per_refblock) as usize * cfg.cluster_size;
                set_refcount_in_block(
                    &mut before[rb..rb + cfg.cluster_size],
                    flat % cfg.entries_per_refblock,
                    cfg.refcount_bits,
                    1,
                )
                .unwrap();
            }
            assert_eq!(
                refblocks, before,
                "snapshot alloc: bytes outside the claimed run changed",
            );
            // Cursor lands just past the run; never backwards.
            let flat_new =
                cursor.next_refblock * cfg.entries_per_refblock + cursor.next_entry_in_refblock;
            assert_eq!(
                flat_new,
                first + alloc_count,
                "snapshot alloc: cursor did not land just past the claimed run",
            );
            assert!(flat_new >= flat0, "snapshot alloc: cursor moved backwards");
            assert_eq!(cursor.allocated, alloc_count);
        }
        Err(SnapshotError::InvalidConfig) => {
            if cfg.refcount_bits == 16 {
                assert_eq!(
                    alloc_count, 0,
                    "snapshot alloc: InvalidConfig for a non-zero count with a \
                     valid width and cluster size",
                );
            }
        }
        Err(SnapshotError::RefcountExhausted) => {
            // Verification scan: no run of alloc_count consecutive
            // zero entries exists from the cursor's start position.
            assert!(alloc_count > 0, "count == 0 must error InvalidConfig first");
            let mut run = 0u64;
            let mut flat = flat0;
            while flat < total_entries {
                if cfg.read_flat(before, flat) == 0 {
                    run += 1;
                    assert!(
                        run < alloc_count,
                        "snapshot alloc: RefcountExhausted but a free run of \
                         {alloc_count} entries exists ending at flat index {flat}",
                    );
                } else {
                    run = 0;
                }
                flat += 1;
            }
        }
        Err(SnapshotError::Unsupported) => {
            assert_ne!(
                cfg.refcount_bits, 16,
                "snapshot alloc: Unsupported for the supported 16-bit width",
            );
        }
        Err(_) => {}
    }
}

// ---------------------------------------------------------------------------
// Op 5: flag-helper containment (invariant 6).
// ---------------------------------------------------------------------------

fn run_flag_helpers(cfg: &Cfg, s: &mut Scratch, l1_len: usize, l2_len: usize, helper_idx: u32) {
    {
        let l1 = &mut s.l1a[..l1_len];
        let before = &mut s.snap_a[..l1_len];
        before.copy_from_slice(l1);
        let r = rewrite_l1_entry_copied_flag(l1, helper_idx, cfg.helper_set);
        check_single_bit63_rewrite(
            before,
            l1,
            helper_idx as usize,
            8,
            r.is_ok(),
            cfg.helper_set,
            "L1",
        );
    }
    {
        let stride = if cfg.extended_l2 { 16usize } else { 8usize };
        let l2 = &mut s.l2_pool[..l2_len];
        let before = &mut s.snap_b[..l2_len];
        before.copy_from_slice(l2);
        let r = rewrite_l2_entry_copied_flag(l2, helper_idx, cfg.helper_set, cfg.extended_l2);
        check_single_bit63_rewrite(
            before,
            l2,
            helper_idx as usize,
            stride,
            r.is_ok(),
            cfg.helper_set,
            "L2",
        );
    }
}

/// Invariant 6 checker: after a flag-helper call, at most bit 63
/// of the targeted entry's type-and-offset word differs; on error
/// nothing differs; on success the bit equals `set`. Buffer
/// lengths are multiples of 8 by construction.
fn check_single_bit63_rewrite(
    before: &[u8],
    after: &[u8],
    entry_idx: usize,
    stride: usize,
    ok: bool,
    set: bool,
    label: &str,
) {
    let word_off = entry_idx.checked_mul(stride);
    for (off, (a, b)) in before
        .chunks_exact(8)
        .zip(after.chunks_exact(8))
        .enumerate()
        .map(|(i, ab)| (i * 8, ab))
    {
        let a = u64::from_be_bytes(a.try_into().unwrap());
        let b = u64::from_be_bytes(b.try_into().unwrap());
        if ok && Some(off) == word_off {
            assert_eq!(
                (a ^ b) & !qcow2::OFLAG_COPIED,
                0,
                "snapshot {label} helper: targeted word changed outside bit 63",
            );
            assert_eq!(
                b & qcow2::OFLAG_COPIED != 0,
                set,
                "snapshot {label} helper: COPIED bit does not match the request",
            );
        } else {
            assert_eq!(
                a, b,
                "snapshot {label} helper: untargeted word at byte {off} changed",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Op 6: table round-trip coherence (invariant 7).
// ---------------------------------------------------------------------------

fn run_table_round_trip(
    cfg: &Cfg,
    s: &mut Scratch,
    old_table: &[u8],
    nb_old: u32,
    id: &[u8],
    name: &[u8],
    data: &[u8],
) {
    let Ok(old_len) = snapshot_table_byte_len(old_table, nb_old) else {
        return;
    };

    let entry = NewSnapshotEntry {
        l1_table_offset: cfg.host_start,
        l1_size: cfg.l1_entries as u32,
        id,
        name,
        date_sec: u32::from_le_bytes(data[12..16].try_into().unwrap()),
        date_nsec: u32::from_le_bytes(data[16..20].try_into().unwrap()),
        vm_clock_nsec: u64::from_le_bytes(data[20..28].try_into().unwrap()),
        vm_state_size: 0,
        vm_state_size_large: 0,
        disk_size: 1 << 30,
        icount: 0,
    };
    let mut ser = [0u8; MAX_SER];
    let ser_len = serialize_snapshot_entry(&entry, &mut ser)
        .expect("serialize must fit the bounded id/name in MAX_SER");
    assert_eq!(ser_len, 40 + 24 + id.len() + name.len());

    let out = &mut s.table_out[..];
    let total = build_snapshot_table(old_table, old_len, &ser[..ser_len], out)
        .expect("build must fit: out is sized for the worst case");
    let aligned = (old_len + 7) & !7;
    assert_eq!(
        total,
        aligned + ser_len,
        "snapshot table: build returned an unexpected total",
    );

    let n_new = nb_old + 1;
    let combined = &out[..total];
    assert_eq!(
        snapshot_table_byte_len(combined, n_new),
        Ok(total),
        "snapshot table: combined table's byte_len disagrees with build",
    );
    let (ls, ll) = snapshot_table_entry_bounds(combined, n_new, n_new - 1)
        .expect("last entry's bounds must resolve");
    assert_eq!(ls, aligned, "snapshot table: appended entry misplaced");
    assert_eq!(ll, ser_len, "snapshot table: appended entry length wrong");
    assert_eq!(
        &combined[ls..ls + ll],
        &ser[..ser_len],
        "snapshot table: appended entry not recovered verbatim",
    );

    // Removal round-trip: survivors byte-identical, count drops
    // by one.
    let k = (data[28] as u32 / 4) % n_new;
    let out2 = &mut s.table_out2[..];
    let new_len = build_snapshot_table_without(combined, total, n_new, k, out2)
        .expect("removal must fit: out2 is sized for the worst case");
    let compacted = &out2[..new_len];
    assert_eq!(
        snapshot_table_byte_len(compacted, n_new - 1),
        Ok(new_len),
        "snapshot table: compacted table's byte_len disagrees",
    );
    let mut j = 0u32;
    for i in 0..n_new {
        if i == k {
            continue;
        }
        let (os, ol) = snapshot_table_entry_bounds(combined, n_new, i).unwrap();
        let (ns, nl) = snapshot_table_entry_bounds(compacted, n_new - 1, j).unwrap();
        assert_eq!(ol, nl, "snapshot table: survivor {i} changed length");
        assert_eq!(
            &combined[os..os + ol],
            &compacted[ns..ns + nl],
            "snapshot table: survivor {i} not byte-identical",
        );
        j += 1;
    }
}
