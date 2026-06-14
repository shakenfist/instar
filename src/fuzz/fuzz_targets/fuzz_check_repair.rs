//! Coverage-guided fuzzing for the qcow2 repair planners in
//! `crates/check/` — the "no corruption regardless of input"
//! surface the check-repair master plan (phase 9) flags for
//! fuzzing.
//!
//! Structured-header planner archetype (like
//! `fuzz_snapshot_refcount`): decode a 32-byte header, synthesize
//! staged slices from the remaining input, dispatch one planner
//! per exec via an op selector, and assert the planners'
//! documented contracts on success. Errors are silently ignored
//! (they are the documented refuse path); panic and ASAN are the
//! base oracle, the asserts are the semantic oracle.
//!
//! Header layout (LE):
//!
//! ```text
//!   0:      op selector (% 4)
//!   1:      flags: bit0 extended_l2 (op 3)
//!   2:      refcount_bits selector (% 7 -> 1/2/4/8/16/32/64)
//!   3:      cluster_bits = 9 + (% 6)  (9..=14)            (op 3)
//!   4:      block byte length = 1 + data[4]  (1..=256)    (ops 0-2);
//!           refblock_count = 1 + (% 4)                    (op 3)
//!   5:      entries_in_block (raw u8, 0..=255 — NOT clamped to the
//!           slice, so the MisalignedAccess bounds path is fuzzed)
//!   6:      L1 entry count (% 65, 0..=64)                 (op 3)
//!   7:      L2 slot length = (% 65) * 16  (0..=1024 bytes) (op 3)
//!   8..16:  reference/presence bitmask (u64): is_referenced for
//!           op 0, L2-slot presence for op 3
//!   16..24: computed-map driver (u64): per-entry computed value
//!           seed for op 2, target-index seed for op 1
//!   24..32: misc (u64): op-1 accumulate count seed, op-2 None-mask
//! ```
//!
//! The pool (bytes 32..) fills, in order: the op-0/1/2 block, then
//! (op 3) the refblocks, the L1 table, and the L2 pool — each
//! cyclically from the pool.
//!
//! ## Invariants (per the planner doc comments)
//!
//! Every op shares the base oracle — **no panic, no out-of-bounds
//! access, for every input** — enforced by libFuzzer + ASAN. The
//! per-op asserts fire only on the success path.
//!
//! 1. **`reclaim_leaks_in_refblock` (op 0).** On `Ok(n)`: the
//!    refblock equals a replay of the contract (rc>0 && !referenced
//!    -> 0, else untouched) byte-for-byte — the sub-byte masking
//!    test, since `set_refcount_in_block` must leave co-resident
//!    entries in the same byte intact at widths 1/2/4; `n` equals
//!    the replay's change count; a second call reclaims 0 and
//!    changes nothing (idempotence); and the doc's "this
//!    generalises reclaim" claim holds —
//!    `correct_refcounts_in_refblock` with `computed = referenced ?
//!    stored : 0` yields the identical buffer with `freed == n`,
//!    `raised == lowered == 0`.
//! 2. **`account_reference_in_map` (op 1).** On `Ok`: the target
//!    entry reads back `cur + 1`, every other byte unchanged; the
//!    pre-call value was below the width max. `AmbiguousCorruption`
//!    <=> an in-range target already at the width max (saturated),
//!    buffer byte-identical. `MisalignedAccess` <=> an out-of-range
//!    target, buffer byte-identical. `k` successive accounts raise
//!    an in-range entry by exactly `k`.
//! 3. **`correct_refcounts_in_refblock` (op 2).** On `Ok(tally)`:
//!    the refblock equals a replay (None -> skip/untouched, Some(w)
//!    -> write w) byte-for-byte; the tally's raised/lowered/freed
//!    match the replay; every covered entry's stored refcount
//!    equals its computed value (the computed values are masked to
//!    the width, so the read-back is exact); a second call with the
//!    same map yields an all-zero tally and changes nothing.
//! 4. **`reconcile_copied_flags_for_l1` (op 3).** A thin wrapper
//!    over `snapshot::qcow2::update_copied_flags_for_l1`: its
//!    result equals the direct call's result mapped through
//!    `RepairError::from` and it mutates the staged L1/L2 bytes
//!    identically (pass-through fidelity + the `From`-bridge
//!    surface); a second wrapper call reports 0 rewrites and
//!    changes nothing (idempotence). The walker's deep semantic
//!    invariants — COPIED <=> refcount == 1, offset-zero scrubbed,
//!    containment to bit 63 — are owned by `fuzz_snapshot_refcount`
//!    op 3 against the same primitive and are **not** re-derived
//!    here.

#![no_main]
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;

use check::qcow2::{
    account_reference_in_map, correct_refcounts_in_refblock, reclaim_leaks_in_refblock,
    reconcile_copied_flags_for_l1, RefcountFixTally,
};
use check::RepairError;
use snapshot::qcow2::{read_refcount_in_block, set_refcount_in_block, update_copied_flags_for_l1};

const HEADER_BYTES: usize = 32;

/// Max op-0/1/2 staged block: byte length is 1 + data[4], so
/// 1..=256.
const MAX_BLOCK: usize = 256;
/// Op-3 staged sizes (cluster_bits <= 14, refblock_count <= 4, L1
/// entries <= 64, L2 slot <= 1024 bytes).
const MAX_REFBLOCKS: usize = 4 * 16384;
const MAX_L1: usize = 64 * 8;
const MAX_L2_POOL: usize = 64 * 1024;

struct Scratch {
    /// Op-0/1/2 staged refblock / count-map and its copies.
    block: Vec<u8>,
    block_before: Vec<u8>,
    block_copy: Vec<u8>,
    /// Op-3 staged image fragment. The L1/L2 buffers are doubled
    /// so the wrapper and the direct call each mutate an
    /// independent copy of identical starting state.
    refblocks: Vec<u8>,
    l1a: Vec<u8>,
    l1b: Vec<u8>,
    l2a: Vec<u8>,
    l2b: Vec<u8>,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch {
        block: vec![0u8; MAX_BLOCK],
        block_before: vec![0u8; MAX_BLOCK],
        block_copy: vec![0u8; MAX_BLOCK],
        refblocks: vec![0u8; MAX_REFBLOCKS],
        l1a: vec![0u8; MAX_L1],
        l1b: vec![0u8; MAX_L1],
        l2a: vec![0u8; MAX_L2_POOL],
        l2b: vec![0u8; MAX_L2_POOL],
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

/// The width's maximum storable refcount.
fn width_max(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Mask a value into the refcount width, so a "computed" count is
/// always storable (a real computed refcount that exceeded the
/// width would be the overflow / AmbiguousCorruption case, not a
/// `correct_refcounts` input).
fn mask_to_width(v: u64, bits: u32) -> u64 {
    if bits >= 64 {
        v
    } else {
        v & ((1u64 << bits) - 1)
    }
}

/// Decode `data[2] % 7` into a qcow2 refcount width.
fn decode_refcount_bits(sel: u8) -> u32 {
    match sel % 7 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        5 => 32,
        _ => 64,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_BYTES {
        return;
    }

    let op = data[0] % 4;
    let refcount_bits = decode_refcount_bits(data[2]);
    let ref_mask = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let driver = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let misc = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let pool = &data[HEADER_BYTES..];

    SCRATCH.with(|cell| {
        let s = &mut *cell.borrow_mut();
        match op {
            0 => run_reclaim(s, pool, refcount_bits, data[4], data[5], ref_mask),
            1 => run_account(s, pool, refcount_bits, data[4], driver, misc),
            2 => run_correct(s, pool, refcount_bits, data[4], data[5], driver, misc),
            _ => run_reconcile(s, pool, refcount_bits, data),
        }
    });
});

/// is_referenced over the staged reference bitmask.
fn is_referenced(ref_mask: u64, idx: u64) -> bool {
    (ref_mask >> (idx % 64)) & 1 != 0
}

// ---------------------------------------------------------------------------
// Op 0: reclaim_leaks_in_refblock (invariant 1).
// ---------------------------------------------------------------------------

fn run_reclaim(
    s: &mut Scratch,
    pool: &[u8],
    bits: u32,
    len_seed: u8,
    entries_seed: u8,
    ref_mask: u64,
) {
    let block_len = 1 + len_seed as usize; // 1..=256
    let entries = entries_seed as u64; // 0..=255, unclamped
    let mut cursor = 0usize;
    fill_from_pool(&mut s.block[..block_len], pool, &mut cursor);
    // The pre-call original is kept in `block_before` for the whole
    // op (replay + cross-check both need it).
    s.block_before[..block_len].copy_from_slice(&s.block[..block_len]);

    let res = reclaim_leaks_in_refblock(&mut s.block[..block_len], entries, bits, |idx| {
        is_referenced(ref_mask, idx)
    });
    let Ok(n) = res else {
        return;
    };

    // Replay the contract on the pre-call copy: Ok implies every
    // entry in 0..entries was readable.
    {
        let before = &s.block_before[..block_len];
        let expected = &mut s.block_copy[..block_len];
        expected.copy_from_slice(before);
        let mut changed = 0u32;
        for idx in 0..entries {
            let rc = read_refcount_in_block(before, idx, bits)
                .expect("Ok reclaim implies every entry was readable");
            if rc > 0 && !is_referenced(ref_mask, idx) {
                set_refcount_in_block(expected, idx, bits, 0).unwrap();
                changed += 1;
            }
        }
        assert_eq!(n, changed, "reclaim: returned count disagrees with the replay");
    }
    assert_eq!(
        &s.block[..block_len],
        &s.block_copy[..block_len],
        "reclaim: result is not the byte-identical contract replay",
    );

    // Generalisation cross-check (the doc's "correct generalises
    // reclaim"): correcting the ORIGINAL with computed = referenced
    // ? stored : 0 reproduces the reclaim result exactly, with
    // freed == n and no raises/lowers. `refblocks` is unused by op 0,
    // so it doubles as the cross-check mutation target; the closure
    // reads `block_before` (disjoint field).
    {
        let before = &s.block_before[..block_len];
        let xref = &mut s.refblocks[..block_len];
        xref.copy_from_slice(before);
        let tally = correct_refcounts_in_refblock(xref, entries, bits, |idx| {
            if is_referenced(ref_mask, idx) {
                Some(read_refcount_in_block(before, idx, bits).expect("in range on the Ok path"))
            } else {
                Some(0)
            }
        })
        .expect("cross-check correction over readable entries must succeed");
        assert_eq!(tally.raised, 0, "reclaim cross-check: unexpected raise");
        assert_eq!(tally.lowered, 0, "reclaim cross-check: unexpected lower");
        assert_eq!(tally.freed, n, "reclaim cross-check: freed != reclaimed count");
    }
    assert_eq!(
        &s.refblocks[..block_len],
        &s.block[..block_len],
        "reclaim cross-check: correct(referenced?stored:0) != reclaim result",
    );

    // Idempotence: a second reclaim over the result reclaims nothing
    // and changes no byte. Snapshot the result into `block_copy`.
    s.block_copy[..block_len].copy_from_slice(&s.block[..block_len]);
    let n2 = reclaim_leaks_in_refblock(&mut s.block[..block_len], entries, bits, |idx| {
        is_referenced(ref_mask, idx)
    })
    .expect("second reclaim over a reclaimed buffer must succeed");
    assert_eq!(n2, 0, "reclaim: second call reclaimed more clusters");
    assert_eq!(
        &s.block[..block_len],
        &s.block_copy[..block_len],
        "reclaim: second call changed bytes",
    );
}

// ---------------------------------------------------------------------------
// Op 1: account_reference_in_map (invariant 2).
// ---------------------------------------------------------------------------

fn run_account(s: &mut Scratch, pool: &[u8], bits: u32, len_seed: u8, driver: u64, misc: u64) {
    let block_len = 1 + len_seed as usize; // 1..=256
    let mut cursor = 0usize;
    fill_from_pool(&mut s.block[..block_len], pool, &mut cursor);
    s.block_before[..block_len].copy_from_slice(&s.block[..block_len]);

    // Target index: mostly in range, sometimes just past capacity
    // so the MisalignedAccess path is reached.
    let capacity = (block_len as u64 * 8) / bits as u64;
    let target = driver % (capacity + 4);

    let before = &s.block_before[..block_len];
    let in_range = read_refcount_in_block(before, target, bits).is_ok();
    let maxv = width_max(bits);

    let res = account_reference_in_map(&mut s.block[..block_len], target, bits);
    match res {
        Ok(()) => {
            assert!(in_range, "account: Ok for an out-of-range target");
            let cur = read_refcount_in_block(before, target, bits).unwrap();
            assert!(cur < maxv, "account: Ok despite a saturated entry");
            // Containment: only the target entry incremented by 1.
            let expected = &mut s.block_copy[..block_len];
            expected.copy_from_slice(before);
            set_refcount_in_block(expected, target, bits, cur + 1).unwrap();
            assert_eq!(
                &s.block[..block_len],
                &s.block_copy[..block_len],
                "account: Ok changed more than the target entry by +1",
            );
        }
        Err(RepairError::AmbiguousCorruption) => {
            assert!(in_range, "account: AmbiguousCorruption for an out-of-range target");
            let cur = read_refcount_in_block(before, target, bits).unwrap();
            assert_eq!(cur, maxv, "account: AmbiguousCorruption for a non-saturated entry");
            assert_eq!(
                &s.block[..block_len],
                before,
                "account: AmbiguousCorruption mutated the map",
            );
        }
        Err(RepairError::MisalignedAccess) => {
            assert!(!in_range, "account: MisalignedAccess for an in-range target");
            assert_eq!(
                &s.block[..block_len],
                before,
                "account: MisalignedAccess mutated the map",
            );
        }
        Err(_) => {}
    }

    // Accumulation round-trip: only meaningful for an in-range,
    // non-saturated target (guaranteed by the Ok arm above).
    if in_range {
        let cur = read_refcount_in_block(before, target, bits).unwrap();
        let remaining = maxv - cur;
        if remaining >= 1 {
            let k = ((misc % 7) + 1).min(remaining); // 1..=7, capped
            let map2 = &mut s.block_copy[..block_len];
            map2.copy_from_slice(before);
            for _ in 0..k {
                account_reference_in_map(map2, target, bits)
                    .expect("account within headroom must succeed");
            }
            let got = read_refcount_in_block(map2, target, bits).unwrap();
            assert_eq!(got, cur + k, "account: {k} accounts did not raise by exactly k");
        }
    }
}

// ---------------------------------------------------------------------------
// Op 2: correct_refcounts_in_refblock (invariant 3).
// ---------------------------------------------------------------------------

/// The per-entry computed value: `None` (uncovered) when the
/// None-mask bit is set, else a width-masked seed.
fn computed_value(idx: u64, driver: u64, none_mask: u64, bits: u32) -> Option<u64> {
    if (none_mask >> (idx % 64)) & 1 != 0 {
        return None;
    }
    let seed = driver
        .wrapping_mul(idx.wrapping_add(1))
        ^ idx.rotate_left((idx % 64) as u32);
    Some(mask_to_width(seed, bits))
}

fn run_correct(
    s: &mut Scratch,
    pool: &[u8],
    bits: u32,
    len_seed: u8,
    entries_seed: u8,
    driver: u64,
    none_mask: u64,
) {
    let block_len = 1 + len_seed as usize;
    let entries = entries_seed as u64;
    let mut cursor = 0usize;
    fill_from_pool(&mut s.block[..block_len], pool, &mut cursor);
    s.block_before[..block_len].copy_from_slice(&s.block[..block_len]);

    let res = correct_refcounts_in_refblock(&mut s.block[..block_len], entries, bits, |idx| {
        computed_value(idx, driver, none_mask, bits)
    });
    let Ok(tally) = res else {
        return;
    };

    // Replay the contract on the pre-call copy.
    let before = &s.block_before[..block_len];
    let expected = &mut s.block_copy[..block_len];
    expected.copy_from_slice(before);
    let mut exp = RefcountFixTally::default();
    for idx in 0..entries {
        let Some(want) = computed_value(idx, driver, none_mask, bits) else {
            continue;
        };
        let have = read_refcount_in_block(before, idx, bits)
            .expect("Ok correct implies every covered entry was readable");
        if want != have {
            set_refcount_in_block(expected, idx, bits, want).unwrap();
            if want > have {
                exp.raised += 1;
            } else if want > 0 {
                exp.lowered += 1;
            } else {
                exp.freed += 1;
            }
        }
    }
    assert_eq!(
        &s.block[..block_len],
        &s.block_copy[..block_len],
        "correct: result is not the byte-identical contract replay",
    );
    assert_eq!(tally, exp, "correct: tally disagrees with the replay");

    // Post-state: every covered entry's stored refcount equals its
    // (width-masked) computed value.
    for idx in 0..entries {
        if let Some(want) = computed_value(idx, driver, none_mask, bits) {
            let got = read_refcount_in_block(&s.block[..block_len], idx, bits).unwrap();
            assert_eq!(got, want, "correct: covered entry {idx} != computed value");
        }
    }

    // Idempotence: a second correction with the same map is a no-op.
    s.block_before[..block_len].copy_from_slice(&s.block[..block_len]);
    let tally2 = correct_refcounts_in_refblock(&mut s.block[..block_len], entries, bits, |idx| {
        computed_value(idx, driver, none_mask, bits)
    })
    .expect("second correction over a corrected buffer must succeed");
    assert_eq!(
        tally2,
        RefcountFixTally::default(),
        "correct: second correction reported changes",
    );
    assert_eq!(
        &s.block[..block_len],
        &s.block_before[..block_len],
        "correct: second correction changed bytes",
    );
}

// ---------------------------------------------------------------------------
// Op 3: reconcile_copied_flags_for_l1 (invariant 4, thin wrapper).
// ---------------------------------------------------------------------------

fn run_reconcile(s: &mut Scratch, pool: &[u8], bits: u32, data: &[u8]) {
    let extended_l2 = data[1] & 0b1 != 0;
    let cluster_bits = 9 + (data[3] % 6) as u32; // 9..=14
    let cluster_size = 1usize << cluster_bits;
    let refblock_count = 1 + (data[4] % 4) as u64;
    let entries_per_refblock = (cluster_size as u64 * 8) / bits as u64;
    let l1_entries = (data[6] % 65) as usize; // 0..=64
    let l2_slot_len = (data[7] % 65) as usize * 16; // 0..=1024
    let presence = u64::from_le_bytes(data[8..16].try_into().unwrap());

    let rb_len = refblock_count as usize * cluster_size;
    let l1_len = l1_entries * 8;
    let l2_len = l1_entries * l2_slot_len;

    let mut cursor = 0usize;
    fill_from_pool(&mut s.refblocks[..rb_len], pool, &mut cursor);
    fill_from_pool(&mut s.l1a[..l1_len], pool, &mut cursor);
    s.l1b[..l1_len].copy_from_slice(&s.l1a[..l1_len]);
    fill_from_pool(&mut s.l2a[..l2_len], pool, &mut cursor);
    s.l2b[..l2_len].copy_from_slice(&s.l2a[..l2_len]);

    // Shared read-only refcount lookup over the staged refblocks.
    let refblocks = &s.refblocks[..rb_len];
    let rc = |host_offset: u64| -> Option<u64> {
        let flat = host_offset >> cluster_bits;
        let rb_idx = flat / entries_per_refblock;
        if rb_idx >= refblock_count {
            return None;
        }
        let rb_off = rb_idx as usize * cluster_size;
        read_refcount_in_block(
            &refblocks[rb_off..rb_off + cluster_size],
            flat % entries_per_refblock,
            bits,
        )
        .ok()
    };

    // Wrapper call over the a-set.
    let l2a_ptr = s.l2a.as_mut_ptr();
    let l2a_mf = |idx: u32| -> Option<&mut [u8]> {
        if presence & (1u64 << (idx % 64)) == 0 {
            return None;
        }
        let start = idx as usize * l2_slot_len;
        if l2_slot_len == 0 || start + l2_slot_len > l2_len {
            return None;
        }
        // SAFETY: mirrors the crate's own tests and the guest: the
        // walker visits each L1 index at most once per run, distinct
        // indices map to disjoint slots, and no other reference to
        // `l2a` is live across the call.
        Some(unsafe { core::slice::from_raw_parts_mut(l2a_ptr.add(start), l2_slot_len) })
    };
    let wres = reconcile_copied_flags_for_l1(
        &mut s.l1a[..l1_len],
        cluster_bits,
        l2a_mf,
        rc,
        extended_l2,
    );

    // Direct call over the b-set with identical starting state.
    let l2b_ptr = s.l2b.as_mut_ptr();
    let l2b_mf = |idx: u32| -> Option<&mut [u8]> {
        if presence & (1u64 << (idx % 64)) == 0 {
            return None;
        }
        let start = idx as usize * l2_slot_len;
        if l2_slot_len == 0 || start + l2_slot_len > l2_len {
            return None;
        }
        // SAFETY: as above, over the independent `l2b` buffer.
        Some(unsafe { core::slice::from_raw_parts_mut(l2b_ptr.add(start), l2_slot_len) })
    };
    let dres = update_copied_flags_for_l1(
        &mut s.l1b[..l1_len],
        cluster_bits,
        l2b_mf,
        rc,
        extended_l2,
    );

    // Pass-through fidelity: the wrapper's result equals the direct
    // result mapped through the From bridge, and both mutate the
    // staged bytes identically.
    assert_eq!(
        wres,
        dres.map_err(RepairError::from),
        "reconcile: wrapper result diverged from the direct call",
    );
    assert_eq!(
        &s.l1a[..l1_len],
        &s.l1b[..l1_len],
        "reconcile: wrapper mutated L1 differently from the direct call",
    );
    assert_eq!(
        &s.l2a[..l2_len],
        &s.l2b[..l2_len],
        "reconcile: wrapper mutated L2 differently from the direct call",
    );

    // Idempotence: a second wrapper run over the reconciled a-set
    // reports 0 rewrites and changes nothing.
    let Ok(_) = wres else {
        return;
    };
    s.l1b[..l1_len].copy_from_slice(&s.l1a[..l1_len]);
    s.l2b[..l2_len].copy_from_slice(&s.l2a[..l2_len]);
    let l2a_ptr = s.l2a.as_mut_ptr();
    let l2a_mf2 = |idx: u32| -> Option<&mut [u8]> {
        if presence & (1u64 << (idx % 64)) == 0 {
            return None;
        }
        let start = idx as usize * l2_slot_len;
        if l2_slot_len == 0 || start + l2_slot_len > l2_len {
            return None;
        }
        // SAFETY: as above.
        Some(unsafe { core::slice::from_raw_parts_mut(l2a_ptr.add(start), l2_slot_len) })
    };
    let refblocks = &s.refblocks[..rb_len];
    let rc2 = |host_offset: u64| -> Option<u64> {
        let flat = host_offset >> cluster_bits;
        let rb_idx = flat / entries_per_refblock;
        if rb_idx >= refblock_count {
            return None;
        }
        let rb_off = rb_idx as usize * cluster_size;
        read_refcount_in_block(
            &refblocks[rb_off..rb_off + cluster_size],
            flat % entries_per_refblock,
            bits,
        )
        .ok()
    };
    let r2 = reconcile_copied_flags_for_l1(
        &mut s.l1a[..l1_len],
        cluster_bits,
        l2a_mf2,
        rc2,
        extended_l2,
    );
    assert_eq!(r2, Ok(0), "reconcile: second run must report 0 rewrites");
    assert_eq!(
        &s.l1a[..l1_len],
        &s.l1b[..l1_len],
        "reconcile: second run changed L1 bytes",
    );
    assert_eq!(
        &s.l2a[..l2_len],
        &s.l2b[..l2_len],
        "reconcile: second run changed L2 bytes",
    );
}
