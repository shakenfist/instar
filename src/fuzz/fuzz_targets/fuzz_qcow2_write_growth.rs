//! Coverage-guided fuzzing for `qcow2_write::growth::plan_refcount_growth`
//! — the pure saturating-arithmetic refcount-growth planner (bench's
//! preemptive growth pass).
//!
//! Decodes the geometry inputs from the fuzz bytes and asserts the
//! planner's contract on every accepted plan:
//!
//!   * **no panic / no arithmetic overflow** — the function is pure
//!     saturating u64 arithmetic (libFuzzer + the fuzzing profile's
//!     overflow / debug-assert checks are the oracle);
//!   * **self-coverage** — every new-structure cluster index
//!     (`structures_start + new_rt_clusters + new_refblocks`) is below
//!     the coverage the plan provides (`worst_end_clusters`), and
//!     `worst_end_clusters >= file_end + worst_case_new`;
//!   * **cap adherence** — an accepted plan never exceeds the staging
//!     caps;
//!   * **layout consistency** — `rt_start == structures_start` and
//!     `refblocks_start == structures_start + new_rt_clusters`.
//!
//! A `GrowthOverflow` refusal is a valid outcome, caught and ignored.
//!
//! **Realistic-envelope clamp.** Like the `crates/commit` and
//! `crates/resize` planner targets (which mask their u64 size fields to
//! a 48-bit envelope), this target clamps `file_end_clusters` and
//! `worst_case_new_clusters` to a 40-bit cluster envelope and ties
//! `entries_per_refblock` to a real 16-bit-refcount refblock
//! (`cluster_size / 2`, one of the four qcow2 cluster sizes). Raw u64
//! maxima describe geometries no real qcow2 file can have (e.g. a
//! `2^62`-cluster file is `2^71` bytes) and trip the planner's
//! deliberate *debug-only* non-convergence guard
//! (`debug_assert!` at `growth.rs`), which in release returns
//! `GrowthOverflow` gracefully — not a production-reachable path. The
//! clamp keeps the target on the arithmetic surface the guest actually
//! exercises. `populated_refblocks` is clamped within the caps to honour
//! the caller's "already within budget" contract for the no-growth
//! short-circuit (which, by design, precedes the cap checks).

#![no_main]
use libfuzzer_sys::fuzz_target;

use qcow2_write::growth::{plan_refcount_growth, GrowthCaps};

const NEEDED: usize = 8 * 6; // six 8-byte words.
/// Realistic cluster envelope for `file_end_clusters` and
/// `worst_case_new_clusters` (their sum drives the growth fixed point).
/// 27 bits keeps `base_end <= 2^28`, which converges in <= 6 rounds for
/// the worst real geometry (`epb == 256`) — comfortably inside the
/// planner's 8-round bound. At 512-byte clusters this is a 64 GiB file;
/// at 2 MiB clusters a 256 TiB file. Raw u64 maxima describe geometries
/// no real bench write produces (a `2^40`-cluster write footprint is
/// petabytes) and legitimately need more rounds than the planner's
/// *debug-only* non-convergence guard allows — in release that guard
/// returns `GrowthOverflow`, a graceful, non-production path.
const CLUSTER_ENVELOPE: u64 = (1 << 27) - 1;
/// A wider envelope for the refcount-table capacity (does not drive
/// non-convergence; kept sane rather than raw-u64).
const RT_ENVELOPE: u64 = (1 << 40) - 1;

fuzz_target!(|data: &[u8]| {
    if data.len() < NEEDED {
        return;
    }
    let w = |i: usize| u64::from_le_bytes(data[i * 8..i * 8 + 8].try_into().unwrap());

    // One of the four qcow2 envelope cluster sizes; 16-bit refcounts
    // give entries_per_refblock == cluster_size / 2 (always >= 256, so
    // the fixed point converges as documented).
    let cluster_size = match data[0] % 4 {
        0 => 512u64,
        1 => 4096,
        2 => 65536,
        _ => 2 * 1024 * 1024,
    };
    let entries_per_refblock = cluster_size / 2;

    // Staging caps: the guest budget, with the fuzzer able to shrink them
    // to exercise the refusal envelope.
    let caps = GrowthCaps {
        max_refblocks: 1 + (data[2] as u64 % 4096),
        max_refblock_clusters: 1 + (data[3] as u64 % 8192),
        max_rt_slots: 1 + (data[4] as u64 % 16384),
    };
    let min_cap = caps
        .max_refblocks
        .min(caps.max_refblock_clusters)
        .min(caps.max_rt_slots);

    let file_end_clusters = w(2) & CLUSTER_ENVELOPE;
    let worst_case_new_clusters = w(5) & CLUSTER_ENVELOPE;
    // The caller's contract: the already-staged prefix is within budget.
    let populated_refblocks = w(3) % (min_cap + 1);
    let rt_capacity_slots = w(4) & RT_ENVELOPE;

    let plan = plan_refcount_growth(
        entries_per_refblock,
        cluster_size,
        file_end_clusters,
        populated_refblocks,
        rt_capacity_slots,
        worst_case_new_clusters,
        &caps,
    );

    if let Ok(p) = plan {
        // Self-coverage: every new-structure cluster is covered.
        let top = p
            .structures_start
            .saturating_add(p.new_rt_clusters)
            .saturating_add(p.new_refblocks);
        assert!(
            top <= p.worst_end_clusters,
            "self-coverage violated: top {top} > worst_end {}",
            p.worst_end_clusters
        );
        let base_end = file_end_clusters.saturating_add(worst_case_new_clusters);
        assert!(
            p.worst_end_clusters >= base_end,
            "coverage {} below base_end {base_end}",
            p.worst_end_clusters
        );
        // Cap adherence. On the no-growth short-circuit (new_refblocks ==
        // 0) needed_slots == populated_refblocks, which we clamped within
        // the caps above; on the growth path the planner itself refuses
        // (GrowthOverflow) anything exceeding the caps — so any accepted
        // plan is within budget.
        assert!(p.needed_slots <= caps.max_refblocks, "needed_slots exceeds max_refblocks");
        assert!(
            p.needed_slots <= caps.max_refblock_clusters,
            "needed_slots exceeds max_refblock_clusters"
        );
        assert!(p.needed_slots <= caps.max_rt_slots, "needed_slots exceeds max_rt_slots");
        // Layout consistency.
        assert_eq!(p.rt_start, p.structures_start, "rt_start must equal structures_start");
        assert_eq!(
            p.refblocks_start,
            p.structures_start.saturating_add(p.new_rt_clusters),
            "refblocks_start must follow the relocated RT"
        );
    }
});
