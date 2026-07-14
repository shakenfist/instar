//! Compute the `bench` request schedule, transfer split, and flush cadence.
//!
//! This crate is `no_std` and performs no I/O — it is plain integer
//! arithmetic. It owns the exact upstream `qemu-img bench` parameter-
//! validation, offset-wrap, transfer-split, and flush-cadence semantics
//! so the math can be unit-tested and fuzzed independently of the vmm
//! binary.
//!
//! This phase implements only parameter validation ([`BenchParams`],
//! [`BenchParamError`]) and the defaults/bounds constants. The offset
//! schedule, transfer split, and flush cadence land in later phases of
//! `docs/plans/PLAN-bench-phase-01-crate.md`.

#![no_std]

/// Default request count (`-c`), matching `qemu-img bench`.
pub const DEFAULT_COUNT: u32 = 75000;

/// Default queue depth (`-d`), matching `qemu-img bench`.
pub const DEFAULT_DEPTH: u32 = 64;

/// Default buffer size in bytes (`-s`), matching `qemu-img bench`.
pub const DEFAULT_BUFSIZE: u64 = 4096;

/// The `INT_MAX` upper bound qemu (Debian 10.0.8 and master) enforces on
/// `count`, `depth`, `bufsize`, and `step`. Values above this bound are
/// rejected with qemu's "Invalid ... specified. Must be between 1 and
/// 2147483647." message family.
pub const QEMU_BENCH_ARG_MAX: u64 = 2_147_483_647;

/// The instar-only v1 cap on `-s` (`bufsize`). This is deliberately equal
/// to `shared::MAX_CLUSTER_SIZE` (2 MiB) — this crate is dependency-free
/// so it cannot reference `shared` directly; consumers assert the two
/// constants are equal at their boundary.
pub const BENCH_MAX_BUFSIZE: u64 = 2 * 1024 * 1024;

/// The fully-resolved parameters for one bench run, after host-side
/// parsing (size suffixes, etc. are a host concern — this crate deals
/// only in already-parsed numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchParams {
    /// Number of requests to issue (`-c`).
    pub count: u32,
    /// Queue depth (`-d`) — accepted, validated, and echoed in the
    /// header for output parity; it is not consumed by any function in
    /// this crate (v1 executes serially, see the master plan's OQ1).
    pub depth: u32,
    /// Bytes per request (`-s`).
    pub bufsize: u64,
    /// Byte offset advance per request (`-S`). `0` means "use
    /// `bufsize`" — see [`BenchParams::effective_step`].
    pub step: u64,
    /// The first request's byte offset (`-o`).
    pub offset: u64,
    /// Whether this is a write test (`-w`). Read test otherwise.
    pub is_write: bool,
    /// The byte pattern written on write tests (`--pattern`). Ignored
    /// (not an error) on read tests — see the non-check note on
    /// [`BenchParams::validate`].
    pub pattern: u8,
    /// Issue a flush every `flush_interval` completions
    /// (`--flush-interval`). `0` means never.
    pub flush_interval: u32,
    /// Skip draining in-flight requests before a scheduled flush
    /// (`--no-drain`). Valid (and irrelevant) even when
    /// `flush_interval` is `0`.
    pub no_drain: bool,
}

impl Default for BenchParams {
    /// qemu's own defaults: count 75000, depth 64, bufsize 4096, step 0
    /// (meaning "= bufsize"), offset 0, read test, pattern 0, no flush,
    /// draining enabled.
    fn default() -> Self {
        BenchParams {
            count: DEFAULT_COUNT,
            depth: DEFAULT_DEPTH,
            bufsize: DEFAULT_BUFSIZE,
            step: 0,
            offset: 0,
            is_write: false,
            pattern: 0,
            flush_interval: 0,
            no_drain: false,
        }
    }
}

impl BenchParams {
    /// The step actually used to advance the offset between requests.
    ///
    /// qemu computes `.step = step ?: bufsize` at parse time — a literal
    /// zero step is unobtainable once parsed, because `0` is defined to
    /// mean "use `bufsize`".
    pub fn effective_step(&self) -> u64 {
        if self.step == 0 {
            self.bufsize
        } else {
            self.step
        }
    }

    /// Validate these parameters against the Debian-10.0.8 (== master)
    /// `qemu-img bench` bounds, plus the single instar-only cap.
    ///
    /// Checks, in order:
    /// 1. `count < 1` — [`BenchParamError::CountOutOfRange`] (the `u32`
    ///    representation already caps the top of qemu's `[1,
    ///    2147483647]` range).
    /// 2. `depth < 1` — [`BenchParamError::DepthOutOfRange`].
    /// 3. `bufsize < 1 || bufsize > QEMU_BENCH_ARG_MAX` —
    ///    [`BenchParamError::BufsizeOutOfRange`]. This qemu-range check
    ///    runs *before* the instar cap check below, so an absurd
    ///    `-s 3G` (past `QEMU_BENCH_ARG_MAX`) gets qemu's own
    ///    out-of-range error rather than instar's cap error.
    /// 4. `bufsize > BENCH_MAX_BUFSIZE` —
    ///    [`BenchParamError::BufsizeAboveInstarCap`]. Anything in
    ///    `(BENCH_MAX_BUFSIZE, QEMU_BENCH_ARG_MAX]` reaches this check
    ///    (it already passed the qemu-range check) and gets instar's
    ///    cap error.
    /// 5. `step > QEMU_BENCH_ARG_MAX` — [`BenchParamError::StepOutOfRange`].
    ///    `step == 0` is always valid — it means "use `bufsize`".
    /// 6. `flush_interval != 0 && !is_write` —
    ///    [`BenchParamError::FlushRequiresWrite`].
    /// 7. `flush_interval != 0 && flush_interval < depth` —
    ///    [`BenchParamError::FlushIntervalSmallerThanDepth`]. Equality
    ///    (`flush_interval == depth`) is fine; qemu's check is
    ///    strictly-smaller.
    ///
    /// Deliberate non-checks (qemu parity, not oversights):
    /// - No pattern-without-write error: qemu silently ignores
    ///   `--pattern` on read tests.
    /// - No offset/image-size bounds check: qemu submits the request
    ///   and lets it fail at request time; that is a phase-3 (guest op)
    ///   concern, not this crate's.
    /// - `no_drain` without `flush_interval` is valid and irrelevant —
    ///   there is nothing to drain around if no flush is ever scheduled.
    /// - `pattern` needs no range check: it is a `u8`, so values above
    ///   `0xff` are unrepresentable in this type; the host CLI parser
    ///   owns that refusal before a `BenchParams` value can exist.
    /// - `offset`'s qemu-defined `[0, i64::MAX]` bound is owned by the
    ///   host parser (this field is `u64` here, wider than qemu's
    ///   `int64_t`, precisely so this crate does not need to re-derive
    ///   that bound).
    pub fn validate(&self) -> Result<(), BenchParamError> {
        if self.count < 1 {
            return Err(BenchParamError::CountOutOfRange);
        }
        if self.depth < 1 {
            return Err(BenchParamError::DepthOutOfRange);
        }
        if self.bufsize < 1 || self.bufsize > QEMU_BENCH_ARG_MAX {
            return Err(BenchParamError::BufsizeOutOfRange);
        }
        if self.bufsize > BENCH_MAX_BUFSIZE {
            return Err(BenchParamError::BufsizeAboveInstarCap);
        }
        if self.step > QEMU_BENCH_ARG_MAX {
            return Err(BenchParamError::StepOutOfRange);
        }
        if self.flush_interval != 0 && !self.is_write {
            return Err(BenchParamError::FlushRequiresWrite);
        }
        if self.flush_interval != 0 && self.flush_interval < self.depth {
            return Err(BenchParamError::FlushIntervalSmallerThanDepth);
        }
        Ok(())
    }
}

/// A `BenchParams` validation failure. The host (phase 4) maps each
/// variant to the captured qemu message text (step 1e); the
/// instar-only [`BenchParamError::BufsizeAboveInstarCap`] gets an
/// instar-worded "not yet supported above 2 MiB" message instead.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BenchParamError {
    /// `count < 1` (the `u32` representation already caps the top).
    CountOutOfRange,
    /// `depth < 1`.
    DepthOutOfRange,
    /// `bufsize < 1 || bufsize > QEMU_BENCH_ARG_MAX`.
    BufsizeOutOfRange,
    /// `step > QEMU_BENCH_ARG_MAX` (`step == 0` is valid — see
    /// [`BenchParams::effective_step`]).
    StepOutOfRange,
    /// `flush_interval != 0 && !is_write`.
    FlushRequiresWrite,
    /// `flush_interval != 0 && flush_interval < depth`. Equal is fine.
    FlushIntervalSmallerThanDepth,
    /// `bufsize > BENCH_MAX_BUFSIZE` — instar-only v1 cap, distinct
    /// from qemu's own (much larger) bound.
    BufsizeAboveInstarCap,
}

/// Advance one bench offset by `step`, wrapping with qemu master's fixed
/// rule.
///
/// qemu's submission loop advances the offset after each request and wraps
/// it so the *next* request stays in range. The Debian 10.0.8 (== master
/// at that tag) source wraps modulo the whole image size:
///
/// ```c
/// b->offset += b->step;
/// if (b->image_size == 0) {
///     b->offset = 0;
/// } else {
///     b->offset %= b->image_size;          /* 10.0.8 rule */
/// }
/// ```
///
/// That 10.0.8 rule can hand back an offset in `(image_size - bufsize,
/// image_size)`, so a wrapped request of `bufsize` bytes overruns EOF and
/// the whole run dies with `Failed request: Input/output error` (EIO).
/// qemu master fixed this in commit `ff2ab634` by wrapping modulo the
/// *usable* range `image_size - bufsize` instead, with a degenerate guard:
///
/// ```c
/// if (b->image_size <= b->bufsize) {
///     b->offset = 0;
/// } else {
///     b->offset %= b->image_size - b->bufsize;   /* master, ff2ab634 */
/// }
/// ```
///
/// instar adopts the **master rule** (master-plan OQ7); the 10.0.8
/// `% image_size` behaviour is recorded in phase 6's divergence registry.
/// The `image_size <= bufsize ⇒ 0` guard also subsumes qemu's separate
/// `image_size == 0` zero-guard: when `image_size == 0` it is `<= bufsize`
/// for any `bufsize >= 1`, so this single branch covers both. Wrapped
/// offsets land in `[0, image_size - bufsize)` and are deliberately *not*
/// aligned to anything — that matches qemu, which never rounds them.
///
/// Panic-free: `saturating_add` absorbs a `cur + step` overflow (an
/// out-of-range step is a validation concern, not this function's), and
/// the modulus divisor is guaranteed nonzero by the `<=` guard.
pub fn next_offset(cur: u64, step: u64, image_size: u64, bufsize: u64) -> u64 {
    let n = cur.saturating_add(step);
    if image_size <= bufsize {
        0
    } else {
        n % (image_size - bufsize)
    }
}

/// The sequence of byte offsets a bench run submits, one per request.
///
/// Yields exactly `count` offsets (`Iterator<Item = u64>`). The **first**
/// yielded offset is the *raw* `params.offset` — unwrapped, unclamped,
/// even when it lies past usable EOF. This mirrors qemu's submission loop,
/// where the wrap arithmetic applies only *after* the first offset is
/// captured:
///
/// ```c
/// int64_t offset = b->offset;   /* first request uses the raw -o offset */
/// b->offset += b->step;
/// b->offset %= ...;             /* wrap applies to the *next* request */
/// ```
///
/// A first request that overruns EOF is submitted anyway and fails at
/// request time (qemu's `Failed request: Input/output error`); catching
/// that is phase 3's concern, not this schedule's. Every subsequent offset
/// is [`next_offset`] applied to its predecessor with
/// [`BenchParams::effective_step`], so it lands in
/// `[0, image_size - bufsize)` (possibly unaligned — correct, not rounded).
pub struct OffsetSchedule {
    /// The offset to yield on the next call to `next`.
    next: u64,
    /// How many offsets remain to be yielded.
    remaining: u32,
    /// The resolved per-request advance (`effective_step`).
    step: u64,
    /// The image size in bytes, used by the wrap rule.
    image_size: u64,
    /// The request size in bytes, used by the wrap rule.
    bufsize: u64,
}

impl OffsetSchedule {
    /// Build the schedule for `params` against an image of `image_size`
    /// bytes. The first offset yielded is the raw `params.offset`; each
    /// following one advances by `params.effective_step()` under the
    /// master wrap rule.
    pub fn new(params: &BenchParams, image_size: u64) -> Self {
        OffsetSchedule {
            next: params.offset,
            remaining: params.count,
            step: params.effective_step(),
            image_size,
            bufsize: params.bufsize,
        }
    }
}

impl Iterator for OffsetSchedule {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if self.remaining == 0 {
            return None;
        }
        let cur = self.next;
        self.remaining -= 1;
        self.next = next_offset(cur, self.step, self.image_size, self.bufsize);
        Some(cur)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.remaining as usize;
        (n, Some(n))
    }
}

/// Split a single logical transfer `[offset, offset + len)` into a run of
/// contiguous chunks, each no larger than `max_transfer` bytes.
///
/// Yields `(chunk_offset, chunk_len)` pairs (`Iterator<Item = (u64, u64)>`)
/// in ascending offset order covering the whole range. Every chunk but the
/// last is exactly `max_transfer` bytes; the last carries the remainder.
/// This is how phase 3's guest loop turns a bench buffer larger than one
/// virtio transfer (the guest passes `shared::MAX_SECTOR_SIZE`, 64 KiB)
/// into a series of in-range transfers.
///
/// Edge cases: `len == 0` yields nothing (there is nothing to transfer);
/// `max_transfer == 0` yields nothing too — that is a defensive guard so a
/// zero cap can never divide-by-zero or loop forever. Real callers never
/// pass `max_transfer == 0`. Offsets are advanced with `saturating_add`, so
/// a range near `u64::MAX` cannot panic; the iterator still terminates
/// because `remaining` strictly decreases by each nonzero chunk.
pub struct TransferSplit {
    /// The offset of the next chunk to yield.
    offset: u64,
    /// Bytes still to be covered.
    remaining: u64,
    /// The per-chunk cap in bytes.
    max_transfer: u64,
}

impl TransferSplit {
    /// Split `[offset, offset + len)` into `<= max_transfer`-byte chunks.
    pub fn new(offset: u64, len: u64, max_transfer: u64) -> Self {
        TransferSplit {
            offset,
            remaining: len,
            max_transfer,
        }
    }
}

impl Iterator for TransferSplit {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<(u64, u64)> {
        if self.remaining == 0 || self.max_transfer == 0 {
            return None;
        }
        let chunk = if self.remaining < self.max_transfer {
            self.remaining
        } else {
            self.max_transfer
        };
        let cur = self.offset;
        self.offset = self.offset.saturating_add(chunk);
        self.remaining -= chunk;
        Some((cur, chunk))
    }
}

/// Whether a flush is issued *after* the `completed`-th request finishes.
///
/// Derived directly from qemu's `bench_cb` completion path (qemu-img.c,
/// v10.0.8 lines 4439–4505):
///
/// ```c
/// } else if (b->in_flight > 0) {
///     int remaining = b->n - b->in_flight;
///     b->n--;
///     b->in_flight--;
///     /* Time for flush? Drain queue if requested, then flush */
///     if (b->flush_interval && remaining % b->flush_interval == 0) {
///         if (!b->in_flight || !b->drain_on_flush) {
///             ... blk_aio_flush(b->blk, cb, b); ...
///         }
///         if (b->drain_on_flush) { return; }
///     }
/// }
/// ```
///
/// `remaining = b->n - b->in_flight` is computed *before* decrementing
/// both. `b->n` counts still-uncompleted requests (starts at `count`,
/// decremented at each completion). Under instar's serial execution
/// `in_flight == 1` at every completion, so when the `k`-th request of
/// `count` completes, `n = count - k + 1` and therefore
/// `remaining = n - 1 = count - k`. A flush fires iff
/// `flush_interval != 0 && (count - k) % flush_interval == 0`, for
/// `k ∈ 1..=count`. This includes a **trailing flush at `k == count`**
/// (`remaining == 0`, and `0 % x == 0`), which happens inside the timed
/// window.
///
/// Depth independence: at depth > 1 the flush *positions* shift to drain
/// boundaries, but the flush *count* is identical, because qemu enforces
/// `flush_interval >= depth` (a validated invariant), which makes
/// `remaining` land on each multiple of `flush_interval` exactly once. So
/// this serial formula is the correct v1 semantics for any accepted depth.
///
/// Panic-free: no division unless `flush_interval != 0`, and `completed`
/// is range-guarded (`1..=count`) so `count - completed` never underflows.
pub fn flush_after_completion(count: u32, completed: u32, flush_interval: u32) -> bool {
    flush_interval != 0
        && completed >= 1
        && completed <= count
        && (count - completed).is_multiple_of(flush_interval)
}

/// The total number of flushes a whole bench run issues.
///
/// Equal to the number of `k ∈ 1..=count` for which
/// [`flush_after_completion`] is true. Since a flush fires exactly when
/// `(count - k) % flush_interval == 0`, and `count - k` ranges over
/// `0..count` as `k` runs over `1..=count`, the count of multiples of
/// `flush_interval` in `[0, count)` is `(count - 1) / flush_interval + 1`
/// (integer division).
///
/// Panic-free: `flush_interval == 0` short-circuits to `0` (never divides
/// by zero), and `count == 0` short-circuits to `0` so the `count - 1`
/// never underflows. Validated params never pass `count == 0`, but the
/// function is sensible and total on all inputs.
pub fn total_flushes(count: u32, flush_interval: u32) -> u32 {
    if flush_interval == 0 || count == 0 {
        0
    } else {
        (count - 1) / flush_interval + 1
    }
}

/// Upper bounds on the distinct qcow2 structures one execution of a bench
/// write schedule can touch, from [`worst_case_touched`]. "Touch" means a
/// request's byte range overlaps the data cluster (so the guest op may
/// have to allocate it) or the L2 table mapping it (so that table may
/// have to be allocated). These are deliberate over-estimates: the growth
/// planner ([`plan_refcount_growth`]) pre-provisions refcount coverage
/// from them, and unused pre-grown refblocks are `qemu-img check`-clean
/// (empirical probe, `docs/plans/PLAN-bench-refcount-growth.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TouchedBound {
    /// Distinct data clusters any request's bytes can overlap.
    pub data_clusters: u64,
    /// Distinct L2 tables mapping those clusters.
    pub l2_tables: u64,
}

/// The number of `granule`-sized units the byte range `[start, end)`
/// overlaps: `(end-1)/granule - start/granule + 1`. Zero when the range
/// or the granule is empty (never divides by zero).
fn units_spanned(start: u64, end: u64, granule: u64) -> u64 {
    if granule == 0 || end <= start {
        0
    } else {
        ((end - 1) / granule) - (start / granule) + 1
    }
}

/// Upper-bound the distinct data clusters and L2 tables a whole bench
/// write schedule can touch (phase 01 of
/// `docs/plans/PLAN-bench-refcount-growth.md`).
///
/// Three bounds are combined with `min`, each independently sound:
///
/// 1. **Per-request straddle**: a `bufsize`-byte range overlaps at most
///    `bufsize/unit + 2` unit-sized regions (both ends unaligned), so
///    `count` requests touch at most `count * (bufsize/unit + 2)` units.
/// 2. **No-wrap span**: when no offset ever wraps, every request lies in
///    `[offset, offset + (count-1)*step + bufsize)` and the touched units
///    are at most the units that span overlaps. The master wrap rule
///    ([`next_offset`]) reduces each *subsequent* offset modulo
///    `image_size - bufsize`, and a cumulative offset **equal** to that
///    modulus wraps to 0 — so the no-wrap test must be strict:
///    `offset + (count-1)*step + bufsize < image_size`. (A `<=` test
///    would under-count the schedule whose last offset lands exactly on
///    the modulus and wraps to cluster 0; see the
///    `touched_wrap_boundary_equality_treated_as_wrap` test.) A
///    single-request schedule never wraps regardless — its raw first
///    offset is submitted unmodified.
/// 3. **Whole image**: at most `ceil(image_size/unit)` units exist.
///
/// The data unit is `cluster_size` bytes; the L2 unit is `l2_coverage =
/// cluster_size * (cluster_size/8)` bytes of virtual space per L2 table.
/// Saturating u64 arithmetic throughout: `image_size == 0`,
/// `cluster_size == 0`, or `count == 0` return zeroed bounds rather than
/// dividing, and a `cluster_size < 8` (no real qcow2 has one) makes
/// `l2_coverage` zero and yields zero L2 tables.
pub fn worst_case_touched(
    params: &BenchParams,
    image_size: u64,
    cluster_size: u64,
) -> TouchedBound {
    let count = params.count as u64;
    if image_size == 0 || cluster_size == 0 || count == 0 {
        return TouchedBound {
            data_clusters: 0,
            l2_tables: 0,
        };
    }
    let bufsize = params.bufsize;
    let step = params.effective_step();
    let l2_coverage = cluster_size.saturating_mul(cluster_size / 8);

    // Bound 1: per-request straddle.
    let mut data = count.saturating_mul((bufsize / cluster_size).saturating_add(2));
    let mut l2 = match bufsize.checked_div(l2_coverage) {
        Some(per_request) => count.saturating_mul(per_request.saturating_add(2)),
        None => 0,
    };

    // Bound 2: no-wrap span. `last_end` is the exclusive end of the last
    // request if no wrap happens; strict `<` (see doc above). Saturation
    // is conservative: a saturated sum compares `>= image_size` and is
    // treated as wrapping.
    let last_end = params
        .offset
        .saturating_add((count - 1).saturating_mul(step))
        .saturating_add(bufsize);
    if count == 1 || last_end < image_size {
        data = data.min(units_spanned(params.offset, last_end, cluster_size));
        if l2_coverage != 0 {
            l2 = l2.min(units_spanned(params.offset, last_end, l2_coverage));
        }
    }

    // Bound 3: the whole image.
    data = data.min(image_size.div_ceil(cluster_size));
    if l2_coverage != 0 {
        l2 = l2.min(image_size.div_ceil(l2_coverage));
    }
    TouchedBound {
        data_clusters: data,
        l2_tables: l2,
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for `BenchParams::validate` and `effective_step`.
    //!
    //! Pure arithmetic — host-only, no KVM or testdata required.
    use super::*;

    #[test]
    fn defaults_match_qemu() {
        let p = BenchParams::default();
        assert_eq!(p.count, 75000);
        assert_eq!(p.depth, 64);
        assert_eq!(p.bufsize, 4096);
        assert_eq!(p.step, 0);
        assert_eq!(p.offset, 0);
        assert!(!p.is_write);
        assert_eq!(p.pattern, 0);
        assert_eq!(p.flush_interval, 0);
        assert!(!p.no_drain);
        assert_eq!(p.effective_step(), p.bufsize);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn custom_step_passes_through() {
        let mut p = BenchParams::default();
        p.step = 8192;
        assert_eq!(p.effective_step(), 8192);
    }

    #[test]
    fn count_zero_rejected_one_accepted() {
        let mut p = BenchParams::default();
        p.count = 0;
        assert_eq!(p.validate(), Err(BenchParamError::CountOutOfRange));
        p.count = 1;
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn depth_zero_rejected_one_accepted() {
        let mut p = BenchParams::default();
        p.depth = 0;
        assert_eq!(p.validate(), Err(BenchParamError::DepthOutOfRange));
        p.depth = 1;
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn bufsize_zero_rejected() {
        let mut p = BenchParams::default();
        p.bufsize = 0;
        assert_eq!(p.validate(), Err(BenchParamError::BufsizeOutOfRange));
    }

    #[test]
    fn bufsize_one_accepted() {
        let mut p = BenchParams::default();
        p.bufsize = 1;
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn bufsize_qemu_arg_max_is_above_instar_cap() {
        // Within qemu's own range, but above the instar v1 cap: the
        // qemu-range check passes, so the instar-cap error fires.
        let mut p = BenchParams::default();
        p.bufsize = QEMU_BENCH_ARG_MAX;
        assert_eq!(p.validate(), Err(BenchParamError::BufsizeAboveInstarCap));
    }

    #[test]
    fn bufsize_above_qemu_arg_max_is_qemu_out_of_range() {
        // Past qemu's own bound: the qemu-range check fires first, even
        // though this value is also above the instar cap.
        let mut p = BenchParams::default();
        p.bufsize = QEMU_BENCH_ARG_MAX + 1;
        assert_eq!(p.validate(), Err(BenchParamError::BufsizeOutOfRange));
    }

    #[test]
    fn bufsize_at_instar_cap_accepted() {
        let mut p = BenchParams::default();
        p.bufsize = BENCH_MAX_BUFSIZE;
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn bufsize_above_instar_cap_rejected() {
        let mut p = BenchParams::default();
        p.bufsize = BENCH_MAX_BUFSIZE + 1;
        assert_eq!(p.validate(), Err(BenchParamError::BufsizeAboveInstarCap));
    }

    #[test]
    fn step_zero_is_valid() {
        let mut p = BenchParams::default();
        p.step = 0;
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn step_at_qemu_arg_max_is_valid() {
        let mut p = BenchParams::default();
        p.step = QEMU_BENCH_ARG_MAX;
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn step_above_qemu_arg_max_rejected() {
        let mut p = BenchParams::default();
        p.step = QEMU_BENCH_ARG_MAX + 1;
        assert_eq!(p.validate(), Err(BenchParamError::StepOutOfRange));
    }

    #[test]
    fn flush_interval_zero_always_valid_regardless_of_write() {
        let mut p = BenchParams::default();
        p.flush_interval = 0;
        p.is_write = false;
        assert_eq!(p.validate(), Ok(()));
        p.is_write = true;
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn flush_interval_without_write_rejected() {
        let mut p = BenchParams::default();
        p.flush_interval = 10;
        p.is_write = false;
        assert_eq!(p.validate(), Err(BenchParamError::FlushRequiresWrite));
    }

    #[test]
    fn flush_interval_smaller_than_depth_rejected_equal_accepted() {
        let mut p = BenchParams::default();
        p.is_write = true;
        p.depth = 50;
        p.flush_interval = 49;
        assert_eq!(
            p.validate(),
            Err(BenchParamError::FlushIntervalSmallerThanDepth)
        );
        p.flush_interval = 50;
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn no_drain_alone_is_valid() {
        let mut p = BenchParams::default();
        p.no_drain = true;
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn pattern_without_write_is_silently_ignored_not_an_error() {
        let mut p = BenchParams::default();
        p.is_write = false;
        p.pattern = 65;
        assert_eq!(p.validate(), Ok(()));
    }

    const MIB: u64 = 1024 * 1024;

    // ---- OffsetSchedule / next_offset ----

    #[test]
    fn default_schedule_first_offsets_and_length() {
        // Default params (step 0 => bufsize 4096) on a 1 MiB image: the
        // offsets march by 4096 with no wrap in sight.
        let mut p = BenchParams::default();
        p.count = 5;
        let offsets: [u64; 5] = {
            let mut it = OffsetSchedule::new(&p, MIB);
            [
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
            ]
        };
        assert_eq!(offsets, [0, 4096, 8192, 12288, 16384]);

        // Length is exactly `count`.
        assert_eq!(OffsetSchedule::new(&p, MIB).count(), 5);

        // The default (huge) count still starts 0, 4096, 8192, 12288.
        let full = BenchParams::default();
        let first4: [u64; 4] = {
            let mut it = OffsetSchedule::new(&full, MIB);
            [
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
            ]
        };
        assert_eq!(first4, [0, 4096, 8192, 12288]);
        assert_eq!(OffsetSchedule::new(&full, MIB).count(), full.count as usize);
    }

    #[test]
    fn wrap_case_that_eios_on_1008_wraps_within_usable_range() {
        // The exact case that EIOs on qemu 10.0.8: a 10240-byte image,
        // 4096-byte requests, step 4096. The usable wrap modulus is
        // image_size - bufsize = 6144.
        let mut p = BenchParams::default();
        p.bufsize = 4096;
        p.step = 4096;
        p.offset = 0;
        p.count = 5;
        let image_size = 10240;
        let v: [u64; 5] = {
            let mut it = OffsetSchedule::new(&p, image_size);
            [
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
            ]
        };
        // 0, then 4096, then (4096 + 4096) % 6144 = 8192 % 6144 = 2048.
        // On 10.0.8 the third offset would be 8192 (% image_size 10240),
        // and a 4096-byte read at 8192 overruns the 10240-byte image ->
        // EIO. The master rule keeps it at 2048, safely in range.
        assert_eq!(
            v[2], 2048,
            "master rule wraps to 2048, not 8192 as on 10.0.8"
        );
        assert_eq!(v, [0, 4096, 2048, 0, 4096]);
        // Every wrapped offset stays in [0, 6144).
        for &o in &v {
            assert!(o < image_size - p.bufsize);
        }
    }

    #[test]
    fn step_greater_than_image_size_still_wraps_into_range() {
        // image 1 MiB, step 3 MiB: subsequent offsets stay in
        // [0, image_size - bufsize).
        let mut p = BenchParams::default();
        p.bufsize = 4096;
        p.step = 3 * MIB;
        p.offset = 0;
        p.count = 6;
        let modulus = MIB - 4096;
        let it = OffsetSchedule::new(&p, MIB);
        for (i, o) in it.enumerate() {
            if i == 0 {
                assert_eq!(o, 0); // raw first offset
            } else {
                assert!(o < modulus, "offset {} not below modulus {}", o, modulus);
            }
        }
        // Spot-check the exact arithmetic: (0 + 3 MiB) % (1 MiB - 4096).
        assert_eq!(next_offset(0, 3 * MIB, MIB, 4096), (3 * MIB) % modulus);
    }

    #[test]
    fn offset_near_u64_max_with_large_step_saturates_no_panic() {
        // Raw first offset is returned unmodified even past any EOF, then
        // the advance saturates rather than overflowing.
        let mut p = BenchParams::default();
        p.bufsize = 4096;
        p.step = QEMU_BENCH_ARG_MAX; // a large-but-valid step
        p.offset = u64::MAX - 10;
        p.count = 3;
        let modulus = MIB - 4096;
        let v: [u64; 3] = {
            let mut it = OffsetSchedule::new(&p, MIB);
            [it.next().unwrap(), it.next().unwrap(), it.next().unwrap()]
        };
        // v[0] is the raw, unwrapped first offset.
        assert_eq!(v[0], u64::MAX - 10);
        // (u64::MAX - 10).saturating_add(step) = u64::MAX, then % modulus.
        let expected_second = u64::MAX % modulus;
        assert_eq!(v[1], expected_second);
        assert!(v[1] < modulus && v[2] < modulus);
        // Direct saturation check on next_offset itself.
        assert_eq!(
            next_offset(u64::MAX, u64::MAX, MIB, 4096),
            u64::MAX % modulus
        );
    }

    #[test]
    fn image_size_equal_to_and_below_bufsize_pins_to_zero() {
        // image_size == bufsize: degenerate, all *subsequent* offsets 0.
        let mut p = BenchParams::default();
        p.bufsize = 4096;
        p.step = 4096;
        p.offset = 12345; // raw first offset, unclamped
        p.count = 4;
        let v: [u64; 4] = {
            let mut it = OffsetSchedule::new(&p, 4096);
            [
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
            ]
        };
        assert_eq!(v, [12345, 0, 0, 0]);

        // image_size < bufsize: same pinning.
        let v2: [u64; 3] = {
            let mut it = OffsetSchedule::new(&p, 1024);
            [it.next().unwrap(), it.next().unwrap(), it.next().unwrap()]
        };
        assert_eq!(v2, [12345, 0, 0]);
    }

    #[test]
    fn image_size_zero_pins_subsequent_to_zero() {
        let mut p = BenchParams::default();
        p.bufsize = 4096;
        p.step = 4096;
        p.offset = 999;
        p.count = 3;
        let v: [u64; 3] = {
            let mut it = OffsetSchedule::new(&p, 0);
            [it.next().unwrap(), it.next().unwrap(), it.next().unwrap()]
        };
        assert_eq!(v, [999, 0, 0]);
        assert_eq!(next_offset(999, 4096, 0, 4096), 0);
    }

    #[test]
    fn unaligned_offset_and_odd_step_pass_through_unrounded() {
        // offset 1000, step 333 on a large image: values are pure
        // arithmetic, never rounded to any boundary.
        let mut p = BenchParams::default();
        p.bufsize = 4096;
        p.step = 333;
        p.offset = 1000;
        p.count = 4;
        let v: [u64; 4] = {
            let mut it = OffsetSchedule::new(&p, MIB);
            [
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
                it.next().unwrap(),
            ]
        };
        // 1000 (raw), 1000+333=1333, 1666, 1999 — all well below the
        // modulus so no wrap, and none aligned to 512/4096.
        assert_eq!(v, [1000, 1333, 1666, 1999]);
    }

    // ---- TransferSplit ----

    /// Assert the structural invariants of a [`TransferSplit`] run. Phase
    /// 7's fuzz target (`fuzz_bench_schedule`) reuses these exact
    /// invariants: the chunk lengths sum to `len`, each chunk is in
    /// `(0, max]`, and the chunks are contiguous and ascending from
    /// `offset`. `max == 0` and `len == 0` legitimately produce no chunks.
    fn assert_split_invariants(offset: u64, len: u64, max: u64) {
        let mut expected_offset = offset;
        let mut total: u64 = 0;
        let mut count = 0u64;
        for (o, l) in TransferSplit::new(offset, len, max) {
            assert!(l > 0, "chunk length must be positive");
            assert!(l <= max, "chunk length {} exceeds max {}", l, max);
            assert_eq!(o, expected_offset, "chunks must be contiguous ascending");
            expected_offset = expected_offset.saturating_add(l);
            total = total.saturating_add(l);
            count += 1;
        }
        if max == 0 {
            assert_eq!(count, 0, "max_transfer 0 must yield nothing");
        } else {
            assert_eq!(total, len, "chunk lengths must sum to len");
        }
    }

    #[test]
    fn split_single_chunk_when_len_below_max() {
        let chunks: [(u64, u64); 1] = {
            let mut it = TransferSplit::new(0, 4096, 65536);
            [it.next().unwrap()]
        };
        assert_eq!(chunks, [(0, 4096)]);
        assert!(TransferSplit::new(0, 4096, 65536).nth(1).is_none());
        assert_split_invariants(0, 4096, 65536);
    }

    #[test]
    fn split_two_mib_into_thirty_two_chunks() {
        let mut count = 0u64;
        for (i, (o, l)) in TransferSplit::new(0, 2 * MIB, 65536).enumerate() {
            assert_eq!(l, 65536);
            assert_eq!(o, i as u64 * 65536);
            count += 1;
        }
        assert_eq!(count, 32);
        assert_split_invariants(0, 2 * MIB, 65536);
    }

    #[test]
    fn split_remainder_chunk() {
        let chunks: [(u64, u64); 2] = {
            let mut it = TransferSplit::new(0, 102400, 65536);
            [it.next().unwrap(), it.next().unwrap()]
        };
        assert_eq!(chunks, [(0, 65536), (65536, 36864)]);
        assert!(TransferSplit::new(0, 102400, 65536).nth(2).is_none());
        assert_split_invariants(0, 102400, 65536);
    }

    #[test]
    fn split_len_zero_is_empty() {
        assert!(TransferSplit::new(0, 0, 65536).next().is_none());
        assert_split_invariants(0, 0, 65536);
    }

    #[test]
    fn split_max_transfer_zero_is_empty() {
        assert!(TransferSplit::new(0, 4096, 0).next().is_none());
        assert_split_invariants(0, 4096, 0);
    }

    #[test]
    fn split_near_u64_max_does_not_panic() {
        // A range near the top of the address space: offset saturates,
        // the iterator still terminates.
        assert_split_invariants(u64::MAX - 100000, 100000, 65536);
    }

    // ---- flush_after_completion / total_flushes ----

    /// Collect the completion indices `k ∈ 1..=count` at which a flush
    /// fires, for a given `(count, interval)`.
    fn flush_positions(count: u32, interval: u32) -> [u32; 8] {
        // Small fixed buffer is enough for the verification vectors.
        let mut out = [0u32; 8];
        let mut n = 0usize;
        for k in 1..=count {
            if flush_after_completion(count, k, interval) {
                out[n] = k;
                n += 1;
            }
        }
        out
    }

    #[test]
    fn vector_100_50() {
        // Flushes after k = 50, 100; total 2.
        assert!(flush_after_completion(100, 50, 50));
        assert!(flush_after_completion(100, 100, 50));
        assert_eq!(&flush_positions(100, 50)[..2], &[50, 100]);
        assert_eq!(
            (1..=100)
                .filter(|&k| flush_after_completion(100, k, 50))
                .count(),
            2
        );
        assert_eq!(total_flushes(100, 50), 2);
    }

    #[test]
    fn vector_101_50() {
        // Flushes after k = 1, 51, 101; total 3 — note the immediate flush
        // after the FIRST completion (remaining = 101 - 1 = 100, 100 % 50).
        assert!(flush_after_completion(101, 1, 50));
        assert!(flush_after_completion(101, 51, 50));
        assert!(flush_after_completion(101, 101, 50));
        assert_eq!(&flush_positions(101, 50)[..3], &[1, 51, 101]);
        assert_eq!(total_flushes(101, 50), 3);
    }

    #[test]
    fn vector_100_100() {
        // Single flush at k = 100; total 1.
        assert!(flush_after_completion(100, 100, 100));
        assert_eq!(&flush_positions(100, 100)[..1], &[100]);
        assert_eq!(total_flushes(100, 100), 1);
    }

    #[test]
    fn vector_75_25() {
        // Flushes after k = 25, 50, 75; total 3.
        assert_eq!(&flush_positions(75, 25)[..3], &[25, 50, 75]);
        assert_eq!(total_flushes(75, 25), 3);
    }

    #[test]
    fn vector_1_1() {
        // Single completion, single flush at k = 1; total 1.
        assert!(flush_after_completion(1, 1, 1));
        assert_eq!(&flush_positions(1, 1)[..1], &[1]);
        assert_eq!(total_flushes(1, 1), 1);
    }

    #[test]
    fn interval_zero_never_flushes() {
        for k in 1..=10 {
            assert!(!flush_after_completion(10, k, 0));
        }
        assert_eq!(total_flushes(10, 0), 0);
        assert_eq!(total_flushes(75000, 0), 0);
    }

    #[test]
    fn completed_zero_is_false() {
        assert!(!flush_after_completion(100, 0, 50));
    }

    #[test]
    fn completed_above_count_is_false() {
        assert!(!flush_after_completion(100, 101, 50));
        assert!(!flush_after_completion(100, 200, 1));
    }

    #[test]
    fn count_equal_interval_single_flush_at_count() {
        // count == interval: only k == count satisfies (count - k) % i == 0
        // within 1..=count (k < count gives remaining in 1..count, none a
        // multiple of interval == count).
        assert!(flush_after_completion(50, 50, 50));
        for k in 1..50 {
            assert!(!flush_after_completion(50, k, 50));
        }
        assert_eq!(total_flushes(50, 50), 1);
    }

    #[test]
    fn interval_greater_than_count_single_final_flush() {
        // interval > count: only k == count fires ((count - count) % i == 0);
        // total_flushes = (count - 1) / i + 1 == 1 since count - 1 < i.
        assert!(flush_after_completion(10, 10, 25));
        for k in 1..10 {
            assert!(!flush_after_completion(10, k, 25));
        }
        assert_eq!(total_flushes(10, 25), 1);
    }

    #[test]
    fn count_zero_no_panic() {
        assert_eq!(total_flushes(0, 50), 0);
        assert_eq!(total_flushes(0, 0), 0);
        assert!(!flush_after_completion(0, 0, 50));
        assert!(!flush_after_completion(0, 1, 50));
    }

    // ---- worst_case_touched ----

    /// Simulate a schedule with [`OffsetSchedule`] and count the distinct
    /// `granule`-sized units its requests' bytes overlap, clamped to the
    /// image (a request wholly past EOF fails and allocates nothing; a
    /// partial overrun is counted conservatively). Fixed bitset — the
    /// callers keep `ceil(image_size/granule) <= 4096`.
    fn simulated_distinct_units(params: &BenchParams, image_size: u64, granule: u64) -> u64 {
        let total = image_size.div_ceil(granule);
        assert!(total <= 4096, "test image too large for the bitset");
        let mut bits = [0u64; 64];
        let mut n = 0u64;
        for off in OffsetSchedule::new(params, image_size) {
            if off >= image_size {
                continue; // whole request past EOF: fails, allocates nothing
            }
            let end = off.saturating_add(params.bufsize).min(image_size);
            if end <= off {
                continue;
            }
            for u in (off / granule)..=((end - 1) / granule) {
                let (w, b) = ((u / 64) as usize, u % 64);
                if bits[w] & (1u64 << b) == 0 {
                    bits[w] |= 1u64 << b;
                    n += 1;
                }
            }
        }
        n
    }

    #[test]
    fn touched_zero_inputs_zeroed() {
        let zero = TouchedBound {
            data_clusters: 0,
            l2_tables: 0,
        };
        let p = BenchParams::default();
        assert_eq!(worst_case_touched(&p, 0, 512), zero);
        assert_eq!(worst_case_touched(&p, 16 * MIB, 0), zero);
        let mut p0 = BenchParams::default();
        p0.count = 0; // invalid (validate() rejects it) but must not divide/panic
        assert_eq!(worst_case_touched(&p0, 16 * MIB, 512), zero);
    }

    #[test]
    fn touched_no_wrap_span_bound_16m_512() {
        // 16M image, 512B clusters: 32768 data clusters total,
        // l2_coverage = 512 * 64 = 32768 bytes, 512 L2 tables total.
        // count=100, bufsize=4096, step=0 (eff 4096), offset=0:
        //   last_end = 0 + 99*4096 + 4096 = 409600 < 16777216 -> no wrap.
        //   per-request data:  100 * (4096/512 + 2) = 1000
        //   span data:         (409599/512) - 0 + 1 = 799 + 1 = 800  <- min
        //   image cap:         32768
        //   per-request L2:    100 * (4096/32768 + 2) = 200
        //   span L2:           (409599/32768) - 0 + 1 = 12 + 1 = 13  <- min
        //   image cap:         512
        let mut p = BenchParams::default();
        p.count = 100;
        let b = worst_case_touched(&p, 16 * MIB, 512);
        assert_eq!(b.data_clusters, 800);
        assert_eq!(b.l2_tables, 13);
    }

    #[test]
    fn touched_no_wrap_64m_65536() {
        // 64M image, 64K clusters: 1024 data clusters total,
        // l2_coverage = 65536 * 8192 = 512 MiB, 1 L2 table total.
        // count=1000, bufsize=65536, step=0 (eff 65536), offset=0:
        //   last_end = 999*65536 + 65536 = 65536000 < 67108864 -> no wrap.
        //   per-request data:  1000 * (65536/65536 + 2) = 3000
        //   span data:         (65535999/65536) - 0 + 1 = 999 + 1 = 1000 <- min
        //   image cap:         1024
        //   L2: per-request 1000*2 = 2000; span 1; cap 1 -> 1.
        let mut p = BenchParams::default();
        p.count = 1000;
        p.bufsize = 65536;
        let b = worst_case_touched(&p, 64 * MIB, 65536);
        assert_eq!(b.data_clusters, 1000);
        assert_eq!(b.l2_tables, 1);
    }

    #[test]
    fn touched_single_request_span_4m_512() {
        // 4M image, 512B clusters, one 4096-byte request at the very end
        // (offset 4194304 - 4096 = 4190208):
        //   span data: (4194303/512) - (4190208/512) + 1 = 8191 - 8184 + 1 = 8
        //   span L2 (l2_coverage 32768): (4194303/32768) - (4190208/32768) + 1
        //            = 127 - 127 + 1 = 1
        let mut p = BenchParams::default();
        p.count = 1;
        p.offset = 4 * MIB - 4096;
        let b = worst_case_touched(&p, 4 * MIB, 512);
        assert_eq!(b.data_clusters, 8);
        assert_eq!(b.l2_tables, 1);
    }

    #[test]
    fn touched_single_request_past_eof_is_bounded() {
        // count == 1 never wraps: the raw first offset is submitted as-is
        // even past EOF (and fails at request time). The span bound still
        // applies: an 8-cluster request, image cap 8192.
        let mut p = BenchParams::default();
        p.count = 1;
        p.offset = 10 * MIB; // beyond the 4M image
        let b = worst_case_touched(&p, 4 * MIB, 512);
        assert_eq!(b.data_clusters, 8);
    }

    #[test]
    fn touched_sparse_large_step_per_request_bound_64m_512() {
        // 64M image, 512B clusters, count=3, bufsize=512, step=1MiB,
        // offset=0: last_end = 2*1048576 + 512 = 2097664 < 67108864, no
        // wrap, but the requests are sparse so the per-request bound wins:
        //   per-request data:  3 * (512/512 + 2) = 9   <- min
        //   span data:         (2097663/512) - 0 + 1 = 4097
        //   per-request L2:    3 * (512/32768 + 2) = 6 <- min
        //   span L2:           (2097663/32768) - 0 + 1 = 64
        let mut p = BenchParams::default();
        p.count = 3;
        p.bufsize = 512;
        p.step = MIB;
        let b = worst_case_touched(&p, 64 * MIB, 512);
        assert_eq!(b.data_clusters, 9);
        assert_eq!(b.l2_tables, 6);
    }

    #[test]
    fn touched_wrap_boundary_equality_treated_as_wrap() {
        // Why the no-wrap test is strict (`<`, not `<=`): 1M image,
        // bufsize 4096, step 512, offset = (1M - 4096) - 512 = 1043968,
        // count 2. offset + 1*step + bufsize == 1048576 == image_size, so
        // a `<=` test would call this no-wrap and bound by the span
        // [1043968, 1048576) = clusters 2039..=2047 = 9 clusters. But the
        // second offset is (1043968 + 512) % (1048576 - 4096) =
        // 1044480 % 1044480 = 0 — it wraps to cluster 0, and the run
        // really touches 8 + 8 = 16 distinct clusters > 9. The strict
        // test falls back to min(per-request, image cap) =
        // min(2 * (4096/512 + 2), 2048) = 20 >= 16.
        let mut p = BenchParams::default();
        p.count = 2;
        p.step = 512;
        p.offset = MIB - 4096 - 512;
        let b = worst_case_touched(&p, MIB, 512);
        assert_eq!(b.data_clusters, 20);
        assert_eq!(simulated_distinct_units(&p, MIB, 512), 16);
    }

    #[test]
    fn touched_wrap_whole_image_matrix() {
        // Default params (count 75000, bufsize 4096, step -> 4096,
        // offset 0) wrap on every image here (75000 * 4096 bytes >> 64M),
        // so the whole-image caps win everywhere:
        //   data cap = image/cs; L2 cap = ceil(image / (cs * cs/8)).
        //   l2_coverage: 512 -> 32768 B; 4096 -> 2 MiB; 65536 -> 512 MiB.
        let cases: [(u64, u64, u64, u64); 9] = [
            (4 * MIB, 512, 8192, 128),     // ceil(4M/32K) = 128
            (4 * MIB, 4096, 1024, 2),      // ceil(4M/2M) = 2
            (4 * MIB, 65536, 64, 1),       // ceil(4M/512M) = 1
            (16 * MIB, 512, 32768, 512),   // ceil(16M/32K) = 512
            (16 * MIB, 4096, 4096, 8),     // ceil(16M/2M) = 8
            (16 * MIB, 65536, 256, 1),     // ceil(16M/512M) = 1
            (64 * MIB, 512, 131072, 2048), // ceil(64M/32K) = 2048
            (64 * MIB, 4096, 16384, 32),   // ceil(64M/2M) = 32
            (64 * MIB, 65536, 1024, 1),    // ceil(64M/512M) = 1
        ];
        let p = BenchParams::default();
        for &(image, cs, data, l2) in &cases {
            let b = worst_case_touched(&p, image, cs);
            assert_eq!(
                b.data_clusters, data,
                "data mismatch at image={} cs={}",
                image, cs
            );
            assert_eq!(b.l2_tables, l2, "l2 mismatch at image={} cs={}", image, cs);
        }
    }

    #[test]
    fn touched_tiny_cluster_l2_coverage_zero() {
        // cluster_size < 8 makes l2_coverage = cs * (cs/8) = 0 — not a
        // real qcow2 geometry, but must not divide by zero. L2 tables are
        // reported as 0; the data bound still works: count=10, bufsize=8,
        // step -> 8, offset=0, cs=4, image=1024:
        //   last_end = 9*8 + 8 = 80 < 1024 -> no wrap.
        //   per-request: 10 * (8/4 + 2) = 40; span (79/4) - 0 + 1 = 20;
        //   cap 256 -> 20.
        let mut p = BenchParams::default();
        p.count = 10;
        p.bufsize = 8;
        let b = worst_case_touched(&p, 1024, 4);
        assert_eq!(b.data_clusters, 20);
        assert_eq!(b.l2_tables, 0);
    }

    #[test]
    fn touched_bound_dominates_simulated_schedules() {
        // Property: the bound is never below the exact distinct-cluster
        // (and distinct-L2) count of a simulated run, across a grid of
        // offsets, steps, buffer sizes, counts, images, and cluster
        // sizes. Covers wrap, no-wrap, unaligned, and past-EOF cases.
        for &image_size in &[65536u64, 262144, MIB, MIB + 512] {
            for &cs in &[512u64, 4096] {
                let l2_coverage = cs * (cs / 8);
                for &count in &[1u32, 2, 7, 64] {
                    for &bufsize in &[512u64, 4096, 5000] {
                        for &step in &[0u64, 512, 4096, 65536, 1000000] {
                            for &offset in &[0u64, 511, 100000, 2 * MIB] {
                                let mut p = BenchParams::default();
                                p.count = count;
                                p.bufsize = bufsize;
                                p.step = step;
                                p.offset = offset;
                                let b = worst_case_touched(&p, image_size, cs);
                                let data = simulated_distinct_units(&p, image_size, cs);
                                assert!(
                                    data <= b.data_clusters,
                                    "data {} > bound {} at image={} cs={} c={} s={} st={} o={}",
                                    data,
                                    b.data_clusters,
                                    image_size,
                                    cs,
                                    count,
                                    bufsize,
                                    step,
                                    offset
                                );
                                let l2 = simulated_distinct_units(&p, image_size, l2_coverage);
                                assert!(
                                    l2 <= b.l2_tables,
                                    "l2 {} > bound {} at image={} cs={} c={} s={} st={} o={}",
                                    l2,
                                    b.l2_tables,
                                    image_size,
                                    cs,
                                    count,
                                    bufsize,
                                    step,
                                    offset
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn total_flushes_matches_per_completion_count() {
        // Property: total_flushes equals the number of completions at which
        // a flush fires, across a grid of small counts and intervals.
        for count in 1..=40u32 {
            for interval in 0..=45u32 {
                let by_loop = (1..=count)
                    .filter(|&k| flush_after_completion(count, k, interval))
                    .count() as u32;
                assert_eq!(
                    total_flushes(count, interval),
                    by_loop,
                    "mismatch at count={} interval={}",
                    count,
                    interval
                );
            }
        }
    }
}
