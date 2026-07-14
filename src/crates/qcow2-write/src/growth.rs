//! Preemptive refcount-growth planning (pure arithmetic).
//!
//! Moved verbatim from `crates/bench` by phase 6 step 6a of
//! `docs/plans/PLAN-qcow2-write-infrastructure-phase-06-bench.md`
//! (settled decision 1), generalizing bench's growth planner
//! into this shared crate — the master plan's mission item 3
//! (`docs/plans/PLAN-qcow2-write-infrastructure.md`). The
//! algorithm, growth layout, and refusal envelope are specified
//! by `docs/plans/PLAN-bench-refcount-growth.md`.
//!
//! Like the rest of this crate the module is pure and I/O-free:
//! [`plan_refcount_growth`] is saturating `u64` arithmetic over
//! caller-supplied geometry and staging caps — no call-table
//! types and no guest addresses. The imperative growth
//! *execution* (write order, the data-first/fsync/header-flip
//! dance, freeing the old refcount table) stays with the
//! consumer (`src/operations/bench`), as does the schedule-
//! coupled worst-case bound: callers pass the computed
//! `worst_case_new_clusters` number across this boundary
//! (bench derives it via its `worst_case_touched`).

/// A refcount growth request that exceeds the guest's staging budget (or
/// carries degenerate geometry — `entries_per_refblock == 0` or
/// `cluster_size == 0`, which no parsed qcow2 header produces). The guest
/// op maps this to `BenchResult::ERROR_ALLOC_EXHAUSTED`, preserving the
/// refusal envelope described in
/// `docs/plans/PLAN-bench-refcount-growth.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrowthOverflow;

/// The guest's staging budget for refcount growth, in the units
/// [`plan_refcount_growth`] compares against: a slot-count cap
/// (`WRITE_MAX_REFBLOCKS`), a refblock-byte cap divided by the cluster
/// size (`WRITE_REFBLOCKS_LIMIT / cluster_size` — refblocks are one
/// cluster each), and a refcount-table-byte cap divided by 8
/// (`WRITE_RT_LIMIT / 8` — RT entries are 8 bytes each).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrowthCaps {
    /// Maximum refblock slots the guest can stage (`WRITE_MAX_REFBLOCKS`).
    pub max_refblocks: u64,
    /// Maximum staged refblock bytes, expressed in clusters:
    /// `max_refblock_bytes / cluster_size`.
    pub max_refblock_clusters: u64,
    /// Maximum staged refcount-table bytes, expressed in 8-byte slots:
    /// `max_rt_bytes / 8`.
    pub max_rt_slots: u64,
}

/// The preemptive refcount-growth plan for one bench write run, from
/// [`plan_refcount_growth`]. All cluster indices are host-file cluster
/// numbers; new structures are placed contiguously at the cluster-aligned
/// current file end (`docs/plans/PLAN-bench-refcount-growth.md`, "Growth
/// layout"):
///
/// ```text
/// [ existing file ... E ) [ new RT (only if relocating) ) [ new refblocks ... )
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefcountGrowthPlan {
    /// Total refblock slots the guest stages, including growth. On the
    /// no-growth path this is `populated_refblocks` (the staged set is
    /// unchanged); on the growth path it is the converged
    /// `ceil(worst_end / entries_per_refblock)`.
    pub needed_slots: u64,
    /// `needed_slots - populated_refblocks` (`0` = no growth).
    pub new_refblocks: u64,
    /// First cluster index of the new structures — the cluster-aligned
    /// current file end. Meaningful only when `new_refblocks > 0`.
    pub structures_start: u64,
    /// Clusters of relocated, enlarged refcount table (`0` = the RT
    /// stays in place and has enough slots).
    pub new_rt_clusters: u64,
    /// Where the relocated RT starts; `== structures_start`. Meaningful
    /// only when `new_rt_clusters > 0`.
    pub rt_start: u64,
    /// Where the new refblocks start:
    /// `structures_start + new_rt_clusters`.
    pub refblocks_start: u64,
    /// The coverage the plan provides, in clusters:
    /// `needed_slots * entries_per_refblock`. Always `>=
    /// file_end_clusters + worst_case_new_clusters`, and every
    /// new-structure cluster index is below it (self-coverage).
    pub worst_end_clusters: u64,
}

/// Bound on the fixed-point rounds in [`plan_refcount_growth`]. The
/// iteration converges in at most 3 rounds for any real qcow2 geometry
/// (`entries_per_refblock >= 256`, so each round's correction shrinks by
/// that factor); the bound exists so degenerate inputs (e.g.
/// `entries_per_refblock == 1`, where the correction never shrinks)
/// terminate with [`GrowthOverflow`] instead of looping.
const GROWTH_FIXED_POINT_ROUNDS: u32 = 8;

/// Plan the preemptive refcount growth for a bench write run (phase 01
/// of `docs/plans/PLAN-bench-refcount-growth.md`). Pure saturating u64
/// arithmetic; no I/O and no panics on any input.
///
/// Inputs:
/// - `entries_per_refblock`: refcount entries per refblock cluster
///   (`cluster_size / 2` for the 16-bit refcounts bench supports).
/// - `cluster_size`: bytes per cluster (passed explicitly rather than
///   derived from `entries_per_refblock`, so the arithmetic does not
///   hard-code the refcount width).
/// - `file_end_clusters`: current host file size in clusters, rounded up
///   — where new structures are placed.
/// - `populated_refblocks`: the gap-free contiguous prefix of populated
///   refblocks the guest stages (already within the staging caps by the
///   caller's contract).
/// - `rt_capacity_slots`: on-disk refcount-table capacity,
///   `refcount_table_clusters * cluster_size / 8`.
/// - `worst_case_new_clusters`: the worst-case allocation bound —
///   `data_clusters + l2_tables` from `crates/bench`'s
///   `worst_case_touched` (schedule-coupled, so it stays there).
/// - `caps`: the staging budget, see [`GrowthCaps`].
///
/// **No-growth short-circuit** (v1 fast path, coverage-based): when
/// `ceil((file_end_clusters + worst_case_new_clusters) /
/// entries_per_refblock) <= populated_refblocks`, the staged coverage
/// already suffices and the plan is `new_refblocks == 0 &&
/// new_rt_clusters == 0` — no growth and no new writes, even when the RT
/// has spare slots. The short-circuit precedes the cap checks (the
/// already-staged set is within budget by contract).
///
/// **Growth**: fixed-point iteration, because the new structures need
/// refcounts themselves. Starting from `end = file_end_clusters +
/// worst_case_new_clusters`, each round computes `needed_slots =
/// ceil(end / entries_per_refblock)`; if `needed_slots >
/// rt_capacity_slots` the RT is relocated and enlarged to
/// `new_rt_clusters = ceil(needed_slots * 8 / cluster_size)`; then `end`
/// is recomputed with the new structures included, until stable
/// (bounded by [`GROWTH_FIXED_POINT_ROUNDS`]).
///
/// **Refusal envelope** ([`GrowthOverflow`], mapped to
/// `ERROR_ALLOC_EXHAUSTED` by the guest): the converged `needed_slots`
/// exceeding any of the three caps, or — when relocating — the staged RT
/// image (`new_rt_clusters` whole clusters) exceeding the RT byte budget
/// `caps.max_rt_slots * 8`; that last check matters at large cluster
/// sizes, where one RT cluster alone can exceed the budget.
pub fn plan_refcount_growth(
    entries_per_refblock: u64,
    cluster_size: u64,
    file_end_clusters: u64,
    populated_refblocks: u64,
    rt_capacity_slots: u64,
    worst_case_new_clusters: u64,
    caps: &GrowthCaps,
) -> Result<RefcountGrowthPlan, GrowthOverflow> {
    if entries_per_refblock == 0 || cluster_size == 0 {
        return Err(GrowthOverflow);
    }
    let base_end = file_end_clusters.saturating_add(worst_case_new_clusters);
    let base_slots = base_end.div_ceil(entries_per_refblock);
    if base_slots <= populated_refblocks {
        // No-growth short-circuit: the staged coverage
        // (populated_refblocks * entries_per_refblock clusters) already
        // covers the worst case. Report that coverage unchanged.
        return Ok(RefcountGrowthPlan {
            needed_slots: populated_refblocks,
            new_refblocks: 0,
            structures_start: file_end_clusters,
            new_rt_clusters: 0,
            rt_start: file_end_clusters,
            refblocks_start: file_end_clusters,
            worst_end_clusters: populated_refblocks.saturating_mul(entries_per_refblock),
        });
    }

    // Fixed point: the new RT clusters and refblocks need refcount
    // coverage too, so they feed back into `end` until stable.
    let mut end = base_end;
    let mut needed_slots = 0u64;
    let mut new_refblocks = 0u64;
    let mut new_rt_clusters = 0u64;
    let mut converged = false;
    for _ in 0..GROWTH_FIXED_POINT_ROUNDS {
        needed_slots = end.div_ceil(entries_per_refblock);
        new_refblocks = needed_slots.saturating_sub(populated_refblocks);
        new_rt_clusters = if needed_slots > rt_capacity_slots {
            needed_slots.saturating_mul(8).div_ceil(cluster_size)
        } else {
            0
        };
        let next_end = base_end
            .saturating_add(new_rt_clusters)
            .saturating_add(new_refblocks);
        if next_end == end {
            converged = true;
            break;
        }
        end = next_end;
    }
    if !converged {
        // Unreachable for real geometry (see GROWTH_FIXED_POINT_ROUNDS);
        // refuse rather than panic or return an under-provisioned plan.
        debug_assert!(false, "refcount growth fixed point did not converge");
        return Err(GrowthOverflow);
    }

    // Staging caps (master plan refusal envelope): total staged slots,
    // staged refblock bytes (needed_slots clusters), staged RT slots,
    // and — when relocating — the staged RT image in whole clusters.
    if needed_slots > caps.max_refblocks
        || needed_slots > caps.max_refblock_clusters
        || needed_slots > caps.max_rt_slots
        || new_rt_clusters.saturating_mul(cluster_size) > caps.max_rt_slots.saturating_mul(8)
    {
        return Err(GrowthOverflow);
    }

    let structures_start = file_end_clusters;
    let refblocks_start = structures_start.saturating_add(new_rt_clusters);
    let worst_end_clusters = needed_slots.saturating_mul(entries_per_refblock);
    // Self-coverage: every new-structure cluster index is below the
    // coverage the plan provides (structures sit at [file_end, end) and
    // worst_end = ceil(end / epb) * epb >= end).
    debug_assert!(
        structures_start
            .saturating_add(new_rt_clusters)
            .saturating_add(new_refblocks)
            <= worst_end_clusters
    );
    debug_assert!(worst_end_clusters >= base_end);
    Ok(RefcountGrowthPlan {
        needed_slots,
        new_refblocks,
        structures_start,
        new_rt_clusters,
        rt_start: structures_start,
        refblocks_start,
        worst_end_clusters,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Unit tests for [`plan_refcount_growth`], relocated verbatim from
    //! `crates/bench` (phase 6 step 6a — see the module docs). Pure
    //! arithmetic — host-only, no KVM or testdata required.
    use super::*;

    const MIB: u64 = 1024 * 1024;

    /// The staging caps the guest will pass (master plan memory budget):
    /// WRITE_MAX_REFBLOCKS = 2048 slots, WRITE_REFBLOCKS_LIMIT = 2 MiB of
    /// refblock bytes, WRITE_RT_LIMIT = 64 KiB of RT bytes.
    fn guest_caps(cluster_size: u64) -> GrowthCaps {
        GrowthCaps {
            max_refblocks: 2048,
            max_refblock_clusters: (2 * MIB) / cluster_size,
            max_rt_slots: (64 * 1024) / 8,
        }
    }

    #[test]
    fn growth_no_growth_short_circuit() {
        // epb=256 (cs 512), file_end=100, worst_new=50: end = 150,
        // needed = ceil(150/256) = 1 <= populated 2 -> no growth, no
        // relocation, coverage = 2 * 256 = 512 clusters.
        let p = plan_refcount_growth(256, 512, 100, 2, 64, 50, &guest_caps(512)).unwrap();
        assert_eq!(p.needed_slots, 2);
        assert_eq!(p.new_refblocks, 0);
        assert_eq!(p.new_rt_clusters, 0);
        assert_eq!(p.structures_start, 100);
        assert_eq!(p.rt_start, 100);
        assert_eq!(p.refblocks_start, 100);
        assert_eq!(p.worst_end_clusters, 512);
    }

    #[test]
    fn growth_new_refblocks_no_relocation_512() {
        // epb=256 (cs 512), file_end=1000, populated=2 (coverage 512 <
        // 1000, staged prefix shorter than the file), rt_capacity=64,
        // worst_new=500. base_end = 1500.
        //   round 1: needed = ceil(1500/256) = 6; 6 <= 64 so no reloc;
        //            new_rb = 6-2 = 4; next_end = 1500 + 4 = 1504.
        //   round 2: needed = ceil(1504/256) = 6; next_end = 1504 stable.
        // Plan: 6 slots, 4 new refblocks at cluster 1000, RT in place,
        // coverage 6 * 256 = 1536 >= 1504.
        let p = plan_refcount_growth(256, 512, 1000, 2, 64, 500, &guest_caps(512)).unwrap();
        assert_eq!(p.needed_slots, 6);
        assert_eq!(p.new_refblocks, 4);
        assert_eq!(p.new_rt_clusters, 0);
        assert_eq!(p.structures_start, 1000);
        assert_eq!(p.refblocks_start, 1000);
        assert_eq!(p.worst_end_clusters, 1536);
    }

    #[test]
    fn growth_rt_relocation_512() {
        // epb=256 (cs 512), file_end=200, populated=1, rt_capacity=64
        // slots (a one-cluster RT at cs 512), worst_new=32768 (a full 16M
        // image of data clusters). base_end = 32968.
        //   round 1: needed = ceil(32968/256) = 129 > 64 -> relocate;
        //            rt = ceil(129*8/512) = ceil(1032/512) = 3;
        //            rb = 128; next_end = 32968 + 3 + 128 = 33099.
        //   round 2: needed = ceil(33099/256) = 130; rt = ceil(1040/512)
        //            = 3; rb = 129; next_end = 32968 + 3 + 129 = 33100.
        //   round 3: needed = ceil(33100/256) = 130; next_end = 33100
        //            stable (3 rounds, the documented worst case).
        // Coverage 130 * 256 = 33280 >= 33100.
        let p = plan_refcount_growth(256, 512, 200, 1, 64, 32768, &guest_caps(512)).unwrap();
        assert_eq!(p.needed_slots, 130);
        assert_eq!(p.new_refblocks, 129);
        assert_eq!(p.new_rt_clusters, 3);
        assert_eq!(p.structures_start, 200);
        assert_eq!(p.rt_start, 200);
        assert_eq!(p.refblocks_start, 203);
        assert_eq!(p.worst_end_clusters, 33280);
    }

    #[test]
    fn growth_rt_relocation_boundary() {
        // Relocation triggers strictly above rt_capacity_slots.
        // epb=256 (cs 512), file_end=0, populated=1, rt_capacity=4.
        // worst_new=1000: needed = ceil(1000/256) = 4 == capacity -> RT
        // stays; rb = 3; next_end = 1003; needed = ceil(1003/256) = 4
        // stable.
        let caps = guest_caps(512);
        let p = plan_refcount_growth(256, 512, 0, 1, 4, 1000, &caps).unwrap();
        assert_eq!(p.needed_slots, 4);
        assert_eq!(p.new_rt_clusters, 0);
        // worst_new=1030: needed = ceil(1030/256) = 5 > 4 -> relocate;
        // rt = ceil(5*8/512) = 1; rb = 4; next_end = 1030 + 1 + 4 = 1035;
        // needed = ceil(1035/256) = 5 stable. Coverage 5 * 256 = 1280.
        let p = plan_refcount_growth(256, 512, 0, 1, 4, 1030, &caps).unwrap();
        assert_eq!(p.needed_slots, 5);
        assert_eq!(p.new_refblocks, 4);
        assert_eq!(p.new_rt_clusters, 1);
        assert_eq!(p.rt_start, 0);
        assert_eq!(p.refblocks_start, 1);
        assert_eq!(p.worst_end_clusters, 1280);
    }

    #[test]
    fn growth_no_relocation_4096() {
        // epb=2048 (cs 4096), file_end=100, populated=1, rt_capacity=512
        // (one-cluster RT at cs 4096), worst_new=4104 (16M image: 4096
        // data clusters + 8 L2 tables). base_end = 4204.
        //   round 1: needed = ceil(4204/2048) = 3 <= 512; rb = 2;
        //            next_end = 4206.
        //   round 2: needed = ceil(4206/2048) = 3; next_end = 4206 stable.
        // Coverage 3 * 2048 = 6144.
        let p = plan_refcount_growth(2048, 4096, 100, 1, 512, 4104, &guest_caps(4096)).unwrap();
        assert_eq!(p.needed_slots, 3);
        assert_eq!(p.new_refblocks, 2);
        assert_eq!(p.new_rt_clusters, 0);
        assert_eq!(p.worst_end_clusters, 6144);
    }

    #[test]
    fn growth_single_new_refblock_65536() {
        // epb=32768 (cs 64K), file_end=32000, populated=1, rt_capacity=
        // 8192, worst_new=1000. base_end = 33000.
        //   round 1: needed = ceil(33000/32768) = 2; rb = 1; next = 33001.
        //   round 2: needed = ceil(33001/32768) = 2; next = 33001 stable.
        // Coverage 2 * 32768 = 65536.
        let p =
            plan_refcount_growth(32768, 65536, 32000, 1, 8192, 1000, &guest_caps(65536)).unwrap();
        assert_eq!(p.needed_slots, 2);
        assert_eq!(p.new_refblocks, 1);
        assert_eq!(p.new_rt_clusters, 0);
        assert_eq!(p.structures_start, 32000);
        assert_eq!(p.refblocks_start, 32000);
        assert_eq!(p.worst_end_clusters, 65536);
    }

    #[test]
    fn growth_matrix_hand_computed() {
        // Full-image worst cases for 4M/16M/64M images at 512/4096/65536
        // clusters: worst_new is the caller's worst-case allocation
        // bound (data cap + L2 cap under default wrapping params).
        // Bench derives it via its schedule-coupled `worst_case_touched`
        // — which stays in `crates/bench`, where
        // touched_wrap_whole_image_matrix pins exactly these data/L2
        // caps for these image/cs combos (the cross-check that lived in
        // this test before the phase-6 step-6a move). file_end=5
        // clusters, populated=1, rt_capacity = cs/8 (a one-cluster RT).
        //
        // Hand computations (epb = cs/2; base_end = 5 + worst_new):
        //  4M/512:   worst=8192+128=8320,  base_end=8325:
        //            needed=ceil(8325/256)=33 <= 64, rb=32, end=8357,
        //            needed=33 stable. worst_end=33*256=8448.
        //  4M/4096:  worst=1024+2=1026, base_end=1031:
        //            ceil(1031/2048)=1 <= populated -> no growth,
        //            worst_end=1*2048=2048.
        //  4M/64K:   worst=64+1=65, base_end=70: needed=1 -> no growth,
        //            worst_end=32768.
        //  16M/512:  worst=32768+512=33280, base_end=33285:
        //            r1 needed=ceil(33285/256)=131 > 64 -> reloc,
        //               rt=ceil(131*8/512)=3, rb=130, end=33285+133=33418;
        //            r2 needed=ceil(33418/256)=131, end=33418 stable.
        //            worst_end=131*256=33536.
        //  16M/4096: worst=4096+8=4104, base_end=4109:
        //            needed=ceil(4109/2048)=3, rb=2, end=4111, stable.
        //            worst_end=6144.
        //  16M/64K:  worst=256+1=257, base_end=262: needed=1 -> no
        //            growth, worst_end=32768.
        //  64M/512:  worst=131072+2048=133120, base_end=133125:
        //            r1 needed=ceil(133125/256)=521 -> reloc,
        //               rt=ceil(521*8/512)=9, rb=520, end=133654;
        //            r2 needed=ceil(133654/256)=523,
        //               rt=ceil(523*8/512)=9, rb=522, end=133656;
        //            r3 needed=ceil(133656/256)=523, end=133656 stable.
        //            worst_end=523*256=133888.
        //  64M/4096: worst=16384+32=16416, base_end=16421:
        //            needed=ceil(16421/2048)=9, rb=8, end=16429, stable.
        //            worst_end=9*2048=18432.
        //  64M/64K:  worst=1024+1=1025, base_end=1030: needed=1 -> no
        //            growth, worst_end=32768.
        let cases: [(u64, u64, u64, u64, u64, u64, u64); 9] = [
            // image, cs, worst_new, needed, new_rb, new_rt, worst_end
            (4 * MIB, 512, 8320, 33, 32, 0, 8448),
            (4 * MIB, 4096, 1026, 1, 0, 0, 2048),
            (4 * MIB, 65536, 65, 1, 0, 0, 32768),
            (16 * MIB, 512, 33280, 131, 130, 3, 33536),
            (16 * MIB, 4096, 4104, 3, 2, 0, 6144),
            (16 * MIB, 65536, 257, 1, 0, 0, 32768),
            (64 * MIB, 512, 133120, 523, 522, 9, 133888),
            (64 * MIB, 4096, 16416, 9, 8, 0, 18432),
            (64 * MIB, 65536, 1025, 1, 0, 0, 32768),
        ];
        for &(image, cs, worst_new, needed, new_rb, new_rt, worst_end) in &cases {
            let p =
                plan_refcount_growth(cs / 2, cs, 5, 1, cs / 8, worst_new, &guest_caps(cs)).unwrap();
            assert_eq!(
                (
                    p.needed_slots,
                    p.new_refblocks,
                    p.new_rt_clusters,
                    p.worst_end_clusters
                ),
                (needed, new_rb, new_rt, worst_end),
                "plan mismatch at image={} cs={}",
                image,
                cs
            );
        }
    }

    #[test]
    fn growth_staging_cap_slots_overflow() {
        // epb=256 (cs 512), file_end=10, populated=1, rt_capacity=8192
        // (already-huge RT, no relocation), worst_new=600000 (~293 MiB of
        // clusters, past the ~256 MiB refusal point at cs 512).
        //   base_end=600010; r1 needed=ceil(600010/256)=2344, rb=2343,
        //   end=602353; r2 needed=2353, rb=2352, end=602362;
        //   r3 needed=ceil(602362/256)=2353 stable.
        // Converged needed 2353 > max_refblocks 2048 -> overflow.
        assert_eq!(
            plan_refcount_growth(256, 512, 10, 1, 8192, 600000, &guest_caps(512)),
            Err(GrowthOverflow)
        );
    }

    #[test]
    fn growth_staging_cap_refblock_bytes_overflow() {
        // At cs 64K the binding cap is refblock bytes: 2 MiB / 64 KiB =
        // 32 staged refblock clusters. epb=32768, file_end=0,
        // populated=1, rt_capacity=8192, worst_new=1050000:
        //   needed = ceil(1050000/32768) = 33 (32*32768 = 1048576 <
        //   1050000); rb = 32; end = 1050032; needed = 33 stable.
        // 33 > 32 -> overflow with the real caps ...
        let caps = guest_caps(65536);
        assert_eq!(caps.max_refblock_clusters, 32);
        assert_eq!(
            plan_refcount_growth(32768, 65536, 0, 1, 8192, 1050000, &caps),
            Err(GrowthOverflow)
        );
        // ... and Ok once that one cap is lifted to 33, isolating it.
        let lifted = GrowthCaps {
            max_refblock_clusters: 33,
            ..caps
        };
        let p = plan_refcount_growth(32768, 65536, 0, 1, 8192, 1050000, &lifted).unwrap();
        assert_eq!(p.needed_slots, 33);
        assert_eq!(p.new_refblocks, 32);
    }

    #[test]
    fn growth_rt_staging_bytes_overflow_two_mib_clusters() {
        // At cs 2 MiB one relocated-RT cluster alone is 2 MiB — past the
        // 64 KiB RT staging budget — even though its slot *count* is
        // fine. epb=1048576, file_end=0, populated=1, rt_capacity=1,
        // worst_new=2000000: needed = ceil(2000000/1048576) = 2 > 1 ->
        // relocate; rt = ceil(2*8/2097152) = 1; rb = 1; end = 2000002;
        // needed = 2 stable. Caps (generous slot caps to isolate the RT
        // byte check): needed 2 passes all three slot caps, but
        // 1 * 2097152 > 8192 * 8 -> overflow.
        let caps = GrowthCaps {
            max_refblocks: 2048,
            max_refblock_clusters: 2048,
            max_rt_slots: 8192,
        };
        assert_eq!(
            plan_refcount_growth(1048576, 2097152, 0, 1, 1, 2000000, &caps),
            Err(GrowthOverflow)
        );
        // With rt_capacity=2 no relocation is needed and the same inputs
        // plan cleanly: rb = 1, RT in place.
        let p = plan_refcount_growth(1048576, 2097152, 0, 1, 2, 2000000, &caps).unwrap();
        assert_eq!(p.needed_slots, 2);
        assert_eq!(p.new_refblocks, 1);
        assert_eq!(p.new_rt_clusters, 0);
    }

    #[test]
    fn growth_zero_geometry_is_overflow() {
        // Degenerate geometry must refuse, not divide by zero.
        let caps = guest_caps(512);
        assert_eq!(
            plan_refcount_growth(0, 512, 0, 1, 64, 100, &caps),
            Err(GrowthOverflow)
        );
        assert_eq!(
            plan_refcount_growth(256, 0, 0, 1, 64, 100, &caps),
            Err(GrowthOverflow)
        );
    }

    #[test]
    fn growth_invariants_over_grid() {
        // The four phase-01 invariants, property-style over a seedless
        // parameter grid (worst_case_new_clusters iterated ascending so
        // monotonicity is checked pairwise):
        //   1. self-coverage: every new-structure cluster index is below
        //      needed_slots * epb;
        //   2. worst_end_clusters >= file_end + worst_new;
        //   3. coverage-based no-growth: ceil((file_end + worst_new)/epb)
        //      <= populated  <=>  new_refblocks == 0 (and then
        //      new_rt_clusters == 0 too);
        //   4. plans are monotone in worst_case_new_clusters (and Ok can
        //      never follow Err).
        for &epb in &[256u64, 2048, 32768] {
            let cs = epb * 2;
            let caps = guest_caps(cs);
            for &file_end in &[0u64, 1, 257, 5000] {
                for &populated in &[0u64, 1, 3] {
                    for &rt_cap in &[1u64, 64, 8192] {
                        let mut prev: Option<Result<RefcountGrowthPlan, GrowthOverflow>> = None;
                        for &wc in &[0u64, 1, 255, 256, 257, 1000, 10000, 100000, 600000] {
                            let r = plan_refcount_growth(
                                epb, cs, file_end, populated, rt_cap, wc, &caps,
                            );
                            let ctx = (epb, file_end, populated, rt_cap, wc);
                            if let Ok(p) = r {
                                // Invariant 1 (self-coverage) + layout.
                                assert!(
                                    p.structures_start + p.new_rt_clusters + p.new_refblocks
                                        <= p.worst_end_clusters,
                                    "self-coverage violated at {:?}",
                                    ctx
                                );
                                assert_eq!(p.structures_start, file_end);
                                assert_eq!(p.rt_start, p.structures_start);
                                assert_eq!(p.refblocks_start, p.rt_start + p.new_rt_clusters);
                                assert_eq!(
                                    p.new_refblocks,
                                    p.needed_slots - populated.min(p.needed_slots)
                                );
                                // Invariant 2 (coverage suffices).
                                assert!(
                                    p.worst_end_clusters >= file_end + wc,
                                    "coverage too small at {:?}",
                                    ctx
                                );
                                // Invariant 3 (no-growth is coverage-based).
                                if (file_end + wc).div_ceil(epb) <= populated {
                                    assert_eq!(p.new_refblocks, 0, "growth at {:?}", ctx);
                                    assert_eq!(p.new_rt_clusters, 0, "reloc at {:?}", ctx);
                                } else {
                                    assert!(p.new_refblocks > 0, "no growth at {:?}", ctx);
                                }
                            }
                            // Invariant 4 (monotone in worst_new).
                            if let Some(prev_r) = prev {
                                match (prev_r, r) {
                                    (Ok(a), Ok(b)) => {
                                        assert!(b.needed_slots >= a.needed_slots);
                                        assert!(b.new_refblocks >= a.new_refblocks);
                                        assert!(b.new_rt_clusters >= a.new_rt_clusters);
                                        assert!(b.worst_end_clusters >= a.worst_end_clusters);
                                    }
                                    (Err(_), Ok(_)) => {
                                        panic!("Err followed by Ok at {:?}", ctx)
                                    }
                                    _ => {}
                                }
                            }
                            prev = Some(r);
                        }
                    }
                }
            }
        }
    }
}
