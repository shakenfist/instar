//! Coverage-guided fuzzing for the `bench` crate's schedule math: param
//! validation ([`bench::BenchParams::validate`]), offset advance
//! ([`bench::next_offset`], [`bench::OffsetSchedule`]), transfer
//! splitting ([`bench::TransferSplit`]), and flush cadence
//! ([`bench::flush_after_completion`], [`bench::total_flushes`]).
//!
//! Decodes the fuzzer bytes into a raw, DELIBERATELY UNCLAMPED header —
//! `crates/bench` is `no_std`, dependency-free, panic-free arithmetic and
//! is documented to accept any value of its scalar fields, so every byte
//! string of at least `HEADER_BYTES` is a legal input:
//!
//! ```text
//! count u32 | depth u32 | bufsize u64 | step u64 | offset u64 |
//! flush_interval u32 | flags u8 (bit0 is_write, bit1 no_drain) |
//! pattern u8 | image_size u64
//! ```
//!
//! Invariants asserted (libFuzzer's oracle is panic):
//!
//!   1. `validate()` never panics. When it returns an error, the
//!      returned variant is cross-checked against the exact predicate
//!      `BenchParams::validate`'s doc comment attributes to it (each
//!      variant maps 1:1 to a bound over the raw fields) — this catches
//!      a returned-error/field-state mismatch even though both sides
//!      read the same struct.
//!   2. `effective_step() == bufsize` iff `step == 0`, else `== step`.
//!   3. `next_offset` on the raw (unclamped) fields never panics, and
//!      its result is `< image_size - bufsize` when
//!      `image_size > bufsize`, else `0`.
//!   4. A CLAMPED copy of the params (count capped to 4096 for iteration
//!      cost; bufsize into `[1, BENCH_MAX_BUFSIZE]`; step capped to
//!      `QEMU_BENCH_ARG_MAX`) drives an `OffsetSchedule` that yields
//!      EXACTLY `count` offsets; the first equals the raw (unclamped)
//!      `offset`; every subsequent offset satisfies the §3 bound;
//!      `size_hint` is exact at every step.
//!   5. `TransferSplit` invariants, re-implemented verbatim from
//!      `crates/bench/src/lib.rs`'s private, test-only
//!      `assert_split_invariants` (its doc comment names this fuzz
//!      target as the intended second consumer, ~line 794): every chunk
//!      length is `> 0` and `<= max_transfer`, chunks are contiguous
//!      ascending from the start offset, zero chunks are yielded iff
//!      `max_transfer == 0`, and (when `max_transfer != 0`) the chunk
//!      lengths sum to exactly `len` (capped to 16 MiB here for fuzz
//!      iteration cost).
//!   6. Flush cadence: the count of `k in 1..=count` for which
//!      `flush_after_completion` fires equals `total_flushes`, for the
//!      clamped `count` and the raw (fuzzed) `flush_interval`; interval
//!      `0` forces both to `0`; `flush_after_completion` is false at
//!      `completed == 0` and at `completed == count + 1`.

#![no_main]
use libfuzzer_sys::fuzz_target;

use bench::{
    flush_after_completion, next_offset, total_flushes, BenchParamError, BenchParams,
    OffsetSchedule, TransferSplit, BENCH_MAX_BUFSIZE, QEMU_BENCH_ARG_MAX,
};

/// `count`(4) + `depth`(4) + `bufsize`(8) + `step`(8) + `offset`(8) +
/// `flush_interval`(4) + `flags`(1) + `pattern`(1) + `image_size`(8).
const HEADER_BYTES: usize = 46;

/// Fuzz-target-local cap on the `TransferSplit` `len` operand, purely for
/// iteration cost (16 MiB split into 1-byte chunks would still be a lot
/// of chunks, but is bounded rather than unbounded).
const MAX_SPLIT_LEN: u64 = 16 * 1024 * 1024;

/// Fuzz-target-local cap on the clamped `OffsetSchedule`/flush-cadence
/// `count`, so a single input cannot force an unbounded iteration.
const MAX_CLAMPED_COUNT: u32 = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_BYTES {
        return;
    }

    let count = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let depth = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let bufsize = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let step = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let offset = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let flush_interval = u32::from_le_bytes(data[32..36].try_into().unwrap());
    let flags = data[36];
    let pattern = data[37];
    let image_size = u64::from_le_bytes(data[38..46].try_into().unwrap());

    let is_write = flags & 0b01 != 0;
    let no_drain = flags & 0b10 != 0;

    let params = BenchParams {
        count,
        depth,
        bufsize,
        step,
        offset,
        is_write,
        pattern,
        flush_interval,
        no_drain,
    };

    // Invariant 1: validate() never panics; on error, the returned
    // variant is consistent with its documented predicate over the raw
    // fields.
    match params.validate() {
        Ok(()) => {}
        Err(BenchParamError::CountOutOfRange) => {
            assert!(params.count < 1, "CountOutOfRange but count={}", params.count);
        }
        Err(BenchParamError::DepthOutOfRange) => {
            assert!(params.depth < 1, "DepthOutOfRange but depth={}", params.depth);
        }
        Err(BenchParamError::BufsizeOutOfRange) => {
            assert!(
                params.bufsize < 1 || params.bufsize > QEMU_BENCH_ARG_MAX,
                "BufsizeOutOfRange but bufsize={} is within qemu's range",
                params.bufsize
            );
        }
        Err(BenchParamError::BufsizeAboveInstarCap) => {
            assert!(
                params.bufsize > BENCH_MAX_BUFSIZE,
                "BufsizeAboveInstarCap but bufsize={} <= cap {}",
                params.bufsize, BENCH_MAX_BUFSIZE
            );
        }
        Err(BenchParamError::StepOutOfRange) => {
            assert!(
                params.step > QEMU_BENCH_ARG_MAX,
                "StepOutOfRange but step={} <= {}",
                params.step, QEMU_BENCH_ARG_MAX
            );
        }
        Err(BenchParamError::FlushRequiresWrite) => {
            assert!(
                params.flush_interval != 0 && !params.is_write,
                "FlushRequiresWrite but flush_interval={} is_write={}",
                params.flush_interval, params.is_write
            );
        }
        Err(BenchParamError::FlushIntervalSmallerThanDepth) => {
            assert!(
                params.flush_interval != 0 && params.flush_interval < params.depth,
                "FlushIntervalSmallerThanDepth but flush_interval={} depth={}",
                params.flush_interval, params.depth
            );
        }
    }

    // Invariant 2: effective_step.
    let eff = params.effective_step();
    if params.step == 0 {
        assert_eq!(eff, params.bufsize, "effective_step must be bufsize when step==0");
    } else {
        assert_eq!(eff, params.step, "effective_step must be step when step!=0");
    }

    // Invariant 3: next_offset on the raw, unclamped fields.
    let n = next_offset(offset, step, image_size, bufsize);
    if image_size > bufsize {
        assert!(
            n < image_size - bufsize,
            "next_offset {} not below usable modulus {} (image_size={} bufsize={})",
            n,
            image_size - bufsize,
            image_size,
            bufsize
        );
    } else {
        assert_eq!(
            n, 0,
            "next_offset must pin to 0 when image_size <= bufsize (image_size={} bufsize={})",
            image_size, bufsize
        );
    }

    // Derive the clamped copy driving invariants 4-6 (count, bufsize,
    // step only — everything else stays at its raw fuzzed value).
    let clamped = BenchParams {
        count: count.min(MAX_CLAMPED_COUNT),
        depth,
        bufsize: bufsize.clamp(1, BENCH_MAX_BUFSIZE),
        step: step.min(QEMU_BENCH_ARG_MAX),
        offset,
        is_write,
        pattern,
        flush_interval,
        no_drain,
    };

    // Invariant 4: OffsetSchedule.
    let mut schedule = OffsetSchedule::new(&clamped, image_size);
    let mut yielded: u32 = 0;
    let mut first: Option<u64> = None;
    loop {
        let remaining = (clamped.count - yielded) as usize;
        assert_eq!(
            schedule.size_hint(),
            (remaining, Some(remaining)),
            "size_hint not exact at yielded={yielded}"
        );
        match schedule.next() {
            None => break,
            Some(o) => {
                if first.is_none() {
                    first = Some(o);
                } else if clamped.bufsize < image_size {
                    assert!(
                        o < image_size - clamped.bufsize,
                        "schedule offset {} not below usable modulus (image_size={} bufsize={})",
                        o,
                        image_size,
                        clamped.bufsize
                    );
                } else {
                    assert_eq!(o, 0, "schedule offset must pin to 0 past the first item");
                }
                yielded += 1;
            }
        }
    }
    assert_eq!(yielded, clamped.count, "OffsetSchedule must yield exactly count items");
    if let Some(f) = first {
        assert_eq!(f, offset, "first scheduled offset must be the raw, unwrapped offset");
    }

    // Invariant 5: TransferSplit, re-implementing
    // crates/bench/src/lib.rs's private `assert_split_invariants`
    // verbatim. `split_len` is the raw `image_size` capped for fuzz
    // iteration cost; `split_max` is the raw (unclamped) `bufsize` so the
    // `max_transfer == 0` degenerate case stays reachable.
    let split_offset = offset;
    let split_len = image_size.min(MAX_SPLIT_LEN);
    let split_max = bufsize;
    {
        let mut expected_offset = split_offset;
        let mut total: u64 = 0;
        let mut chunk_count: u64 = 0;
        for (o, l) in TransferSplit::new(split_offset, split_len, split_max) {
            assert!(l > 0, "chunk length must be positive");
            assert!(l <= split_max, "chunk length {l} exceeds max {split_max}");
            assert_eq!(o, expected_offset, "chunks must be contiguous ascending");
            expected_offset = expected_offset.saturating_add(l);
            total = total.saturating_add(l);
            chunk_count += 1;
        }
        if split_max == 0 {
            assert_eq!(chunk_count, 0, "max_transfer 0 must yield nothing");
        } else {
            assert_eq!(total, split_len, "chunk lengths must sum to len");
        }
    }

    // Invariant 6: flush cadence, clamped count + raw fuzzed interval.
    let flush_count = (1..=clamped.count)
        .filter(|k| flush_after_completion(clamped.count, *k, flush_interval))
        .count();
    assert_eq!(
        flush_count,
        total_flushes(clamped.count, flush_interval) as usize,
        "flush count mismatch (count={} interval={})",
        clamped.count,
        flush_interval
    );
    if flush_interval == 0 {
        assert_eq!(flush_count, 0, "interval 0 must never flush");
        assert_eq!(total_flushes(clamped.count, flush_interval), 0);
    }
    assert!(
        !flush_after_completion(clamped.count, 0, flush_interval),
        "completed==0 must never flush"
    );
    assert!(
        !flush_after_completion(clamped.count, clamped.count + 1, flush_interval),
        "completed==count+1 must never flush"
    );
});
