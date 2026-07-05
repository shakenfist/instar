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
}
