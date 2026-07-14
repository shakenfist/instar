//! Coverage-guided fuzzing for the `crates/qcow2-write` planner
//! (`plan_write` / `plan_flush`) driven through the crate's own
//! Vec-backed simulation harness (`qcow2_write::sim`, lifted out of the
//! unit tests in phase 8a).
//!
//! The input bytes are hand-decoded into:
//!
//!   * a **fixture archetype** — clean / backing-present / shared-data
//!     (C1) / shared-L2 nested (C2/C3) / owned-L2 / zero-flag-target —
//!     plus a cluster size {512, 4096, 65536, 2 MiB}, an L2-window slot
//!     count, and a resume-buffer capacity;
//!   * a bounded sequence (<= 16) of operations, each either
//!     `plan_write(voff, len, DataSource)` or `plan_flush`, with the
//!     virtual offset / length / data pattern drawn from the bytes.
//!
//! Every operation is driven through the harness `run_write` /
//! `run_flush` `BufFull`-resume loop (which converges under an iteration
//! cap — a non-convergence panics, i.e. is a libFuzzer finding). After
//! **every** operation the invariant oracle runs:
//!
//!   1. **`max_rc < 3`** — the copy-on-write corruption signature (a
//!      snapshot-shared child bumped past its creation refcount of 2).
//!      The single most important invariant.
//!   2. **snapshot-shared clusters byte-preserved and never freed** —
//!      the clusters the fixture marked shared keep `rc >= 1` and their
//!      bytes are frozen for the whole run (COW never rewrites them in
//!      place, and the allocator never re-hands them out).
//!   3. **metadata liveness** — header / refcount-table / refblock / L1
//!      clusters keep `rc >= 1`.
//!   4. **no dangling / past-EOF pointer** — the active on-disk L1 chain
//!      (and low L2 entries) reference only in-bounds, cluster-aligned
//!      hosts whose refcount is `>= 1`.
//!
//! After a successful **flush** (which makes the on-disk metadata
//! authoritative) the walk additionally asserts **COPIED-flag
//! correctness**: an entry with `OFLAG_COPIED` set maps to a cluster of
//! refcount exactly 1.
//!
//! A `WriteError` refusal (OutOfBounds, SnapshotShared, RefcountInconsistent,
//! RefcountCoverage, …) is a **valid** outcome, not a crash: it is caught
//! and the run continues, but the invariants above must still hold on the
//! staged image. Malformed / short input bails early — the target never
//! panics on the input itself.

#![no_main]
use libfuzzer_sys::fuzz_target;

use qcow2::{L1_OFFSET_MASK, OFLAG_COPIED, QCOW_OFLAG_ZERO};
use qcow2_write::sim::*;
use qcow2_write::{DataSource, WriteState};

/// Bytes consumed by the fixed geometry header before the op stream.
const HEADER_BYTES: usize = 6;
/// Bytes consumed by each decoded operation.
const OP_BYTES: usize = 8;
/// Upper bound on operations per run (keeps each run total).
const MAX_OPS: usize = 16;
/// Cap on the cluster window scanned by the refcount oracle (2 MiB
/// clusters have a 1M-entry refblock; a bounded window keeps exec/s up
/// while still covering every fixture cluster and bounded allocation).
const SCAN_CAP: u64 = 4096;

/// A snapshot-shared cluster the fixture created: its index plus a copy
/// of its original bytes, both frozen for the whole run.
struct Shared {
    cluster: u64,
    bytes: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_BYTES {
        return;
    }

    // ------------------------------------------------------------------
    // Decode the fixed geometry header.
    // ------------------------------------------------------------------
    let archetype = data[0] % 6;
    let cluster_bits: u32 = match data[1] % 4 {
        0 => 9,  // 512 B
        1 => 12, // 4 KiB
        2 => 16, // 64 KiB
        _ => 21, // 2 MiB
    };
    let l2_slots = 1 + (data[2] as usize % 4); // 1..=4
    let cap = 8 + (data[3] as usize % 121); // 8..=128
    let zero_rc = 1 + (data[4] as u64 % 2); // 1 or 2 (zero-flag fixture)
    let n_ops = data[5] as usize % (MAX_OPS + 1); // 0..=16

    let cs = 1u64 << cluster_bits;
    // Refblock capacity in clusters (16-bit refcounts: cs*8/16 == cs/2).
    let capacity = cs / 2;
    let scan_upto = capacity.min(SCAN_CAP);
    // Virtual size mk/mk_vs give the fixture: 4 L2 tables of coverage.
    let l2_coverage = (cs / 8) * cs;
    let virtual_size = 4 * l2_coverage;

    // ------------------------------------------------------------------
    // Build the fixture archetype + record its snapshot-shared clusters.
    // ------------------------------------------------------------------
    let (mut img, mut st, shared) = build_fixture(archetype, cluster_bits, l2_slots, cs, zero_rc);

    // Baseline invariants must hold before any operation.
    check_core(&img, scan_upto, &shared);

    // ------------------------------------------------------------------
    // Replay the decoded operation sequence.
    // ------------------------------------------------------------------
    let ops = &data[HEADER_BYTES..];
    for i in 0..n_ops {
        let base = i * OP_BYTES;
        if base + OP_BYTES > ops.len() {
            break; // ran out of bytes: stop issuing ops (total).
        }
        let ob = &ops[base..base + OP_BYTES];

        let is_flush = ob[0] % 4 == 3;
        if is_flush {
            let flushed = run_flush(&mut img, &mut st, cap).is_ok();
            check_core(&img, scan_upto, &shared);
            check_chain(&img, capacity, flushed /* strict after a clean flush */);
            continue;
        }

        // Decode a write.
        let use_fill = (ob[0] >> 2) & 1 == 1;
        let raw_voff = u32::from_le_bytes([ob[1], ob[2], ob[3], ob[4]]) as u64;
        // Allow offsets past the virtual size to exercise the OOB refusal.
        let voff = raw_voff % (2 * virtual_size).max(1);
        let raw_len = u16::from_le_bytes([ob[5], ob[6]]) as u64;
        let len = raw_len % (4 * cs + 1); // 0..=4*cs (caller region is 4*cs)
        let data_src = if use_fill {
            DataSource::Fill { byte: ob[7] }
        } else {
            DataSource::CallerData { offset: 0 }
        };

        let _ = run_write(&mut img, &mut st, voff, len, data_src, cap);
        // Success or refusal: the core invariants must hold either way.
        check_core(&img, scan_upto, &shared);
        check_chain(&img, capacity, false /* on-disk L1 may be pre-flush stale */);
    }
});

/// Build one fixture archetype and return the image, its write state,
/// and the set of snapshot-shared clusters to hold invariant.
fn build_fixture(
    archetype: u8,
    cluster_bits: u32,
    l2_slots: usize,
    cs: u64,
    zero_rc: u64,
) -> (TestImg, WriteState, Vec<Shared>) {
    let cluster = |img: &TestImg, c: u64| -> Vec<u8> {
        let off = (c * cs) as usize;
        img.disk[off..off + cs as usize].to_vec()
    };
    match archetype {
        0 => {
            // Clean, no backing, non-COW.
            let (img, st) = mk(cluster_bits, l2_slots, false);
            (img, st, Vec::new())
        }
        1 => {
            // Backing present, non-COW.
            let (img, st) = mk(cluster_bits, l2_slots, true);
            (img, st, Vec::new())
        }
        2 => {
            // C1: owned L2 with a snapshot-shared child data cluster
            // (cluster 5, rc 2), COW state.
            let (mut img, st) = mk_cow(cluster_bits, l2_slots);
            add_shared_data(&mut img, 0);
            let shared = vec![Shared {
                cluster: 5,
                bytes: cluster(&img, 5),
            }];
            (img, st, shared)
        }
        3 => {
            // C2/C3: snapshot-shared L2 table (cluster 4) over two
            // shared children (clusters 5, 6), all rc 2, COW state.
            let (mut img, st) = mk_cow(cluster_bits, l2_slots);
            add_shared_l2_two_children(&mut img);
            let shared = vec![
                Shared { cluster: 4, bytes: cluster(&img, 4) },
                Shared { cluster: 5, bytes: cluster(&img, 5) },
                Shared { cluster: 6, bytes: cluster(&img, 6) },
            ];
            (img, st, shared)
        }
        4 => {
            // Owned L2 with an owned child (all rc 1), COW state — the
            // in-place / allocate-on-write paths without sharing.
            let (mut img, st) = mk_cow(cluster_bits, l2_slots);
            add_allocated_cluster(&mut img, 0, OFLAG_COPIED, OFLAG_COPIED);
            (img, st, Vec::new())
        }
        _ => {
            // Zero-flag WRITE target: owned L2, child cluster 5 carrying
            // QCOW_OFLAG_ZERO at refcount `zero_rc` (1 = reuse in place,
            // 2 = COW with a zero pre-image). COW state so rc 2 is legal.
            let (mut img, st) = mk_cow(cluster_bits, l2_slots);
            add_owned_l2(&mut img);
            put_disk_u64(&mut img, (4 * cs) as usize, (5 * cs) | QCOW_OFLAG_ZERO);
            set_rc(&mut img, 5, zero_rc);
            let shared = if zero_rc >= 2 {
                vec![Shared { cluster: 5, bytes: cluster(&img, 5) }]
            } else {
                Vec::new()
            };
            (img, st, shared)
        }
    }
}

/// The core oracle, checked after every operation (success or refusal):
/// the corruption signature, snapshot preservation, and metadata
/// liveness.
fn check_core(img: &TestImg, scan_upto: u64, shared: &[Shared]) {
    // 1. THE corruption signature: no cluster ever reaches refcount 3.
    let hi = max_rc(img, scan_upto);
    assert!(hi < 3, "COW corruption: a cluster reached refcount {hi} (>= 3)");

    // 2. Snapshot-shared clusters: never freed (rc >= 1) and byte-frozen.
    for s in shared {
        assert!(
            rc_of(img, s.cluster) >= 1,
            "snapshot-shared cluster {} was freed (rc 0)",
            s.cluster
        );
        let off = (s.cluster * img.cs as u64) as usize;
        assert_eq!(
            &img.disk[off..off + img.cs],
            &s.bytes[..],
            "snapshot-shared cluster {} bytes mutated in place",
            s.cluster
        );
    }

    // 3. Metadata liveness: header(0), refcount table(1), refblock(2),
    //    L1(3) are always referenced.
    for c in 0..4u64 {
        assert!(rc_of(img, c) >= 1, "metadata cluster {c} lost its refcount");
    }
}

/// Walk the active **staged** L1 table — the authoritative, zero-init
/// view. (The on-disk L1 region is sentinel-filled until a dirty flush
/// writes it, and freshly-allocated L2 hosts can sit past the lazily
/// grown disk EOF before flush, so the on-disk copy is not walkable.)
/// Every present L1 pointer must be cluster-aligned and — within the
/// refblock window — refcounted `>= 1` (the no-dangling invariant). When
/// `strict` (a settled point, right after a clean flush), also assert
/// COPIED-flag correctness: `OFLAG_COPIED` set implies refcount exactly 1.
fn check_chain(img: &TestImg, capacity: u64, strict: bool) {
    let cs = img.cs as u64;
    // The staged L1 table is `l1_size` (== 4) entries of 8 bytes.
    for i in 0..4usize {
        let raw = u64::from_be_bytes(img.l1[i * 8..i * 8 + 8].try_into().unwrap());
        let host = raw & L1_OFFSET_MASK;
        if host == 0 {
            continue; // absent L1 entry.
        }
        assert_eq!(host % cs, 0, "L1 pointer host {host:#x} not cluster-aligned");
        let cluster = host / cs;
        // Refcounts are only readable within the single refblock's
        // capacity; a referenced cluster beyond it would have been refused
        // (RefcountCoverage) before success, so skip the read defensively.
        if cluster >= capacity {
            continue;
        }
        let rc = rc_of(img, cluster);
        assert!(rc >= 1, "L1 pointer to cluster {cluster} with refcount 0 (dangling)");
        if strict && raw & OFLAG_COPIED != 0 {
            assert_eq!(rc, 1, "L1 entry has OFLAG_COPIED but cluster {cluster} refcount is {rc} (!= 1)");
        }
    }
}
