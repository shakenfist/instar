//! Coverage-guided fuzzing for `dd::compute_dd_window` (the dd
//! planner-equivalent extracted in phase 8a of PLAN-dd).
//!
//! Decodes the fuzzer bytes into the four window operands the host
//! derives from a `dd` invocation — `(virtual_size, bs, count_opt,
//! skip)` — and calls `compute_dd_window`. The inputs are fuzzed raw
//! (no clamping): `compute_dd_window` is documented to use saturating
//! arithmetic and to never reject an out-of-range window, so every
//! `u64` quadruple is a legal input and the result must satisfy the
//! window algebra below.
//!
//! Invariants asserted (libFuzzer's oracle is panic; these cheap
//! checks turn a silent algebra regression into a crash):
//!
//!   1. `w.start == skip.saturating_mul(bs)`.
//!   2. `w.end == match count { Some(c) => (c*bs).min(virtual_size),
//!      None => virtual_size }` (count clamps DOWN only, saturating).
//!   3. `w.out_vsize == w.end.saturating_sub(w.start)`.
//!   4. `w.out_vsize <= w.end` (output can never exceed the window
//!      end — a corollary of saturating_sub, but cheap to assert).
//!
//! No re-derivation round-trip is possible (the operands are not
//! recoverable from the window), so the contract is purely the
//! algebra above plus "no panic".

#![no_main]
use libfuzzer_sys::fuzz_target;

/// 32 bytes for four `u64` operands + 1 flag byte for count-present.
const HEADER_BYTES: usize = 33;

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_BYTES {
        return;
    }

    let virtual_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let bs = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let raw_count = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let skip = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let count = if data[32] & 1 != 0 { Some(raw_count) } else { None };

    let w = dd::compute_dd_window(virtual_size, bs, count, skip);

    // Invariant 1: window start.
    let expected_start = skip.saturating_mul(bs);
    assert_eq!(
        w.start, expected_start,
        "start mismatch: got {} expected {} (bs={bs} skip={skip})",
        w.start, expected_start
    );

    // Invariant 2: window end (count clamps DOWN only, saturating).
    let expected_end = match count {
        Some(c) => c.saturating_mul(bs).min(virtual_size),
        None => virtual_size,
    };
    assert_eq!(
        w.end, expected_end,
        "end mismatch: got {} expected {} \
         (virtual_size={virtual_size} bs={bs} count={count:?})",
        w.end, expected_end
    );

    // Invariant 3: output size is the saturating window length.
    let expected_vsize = w.end.saturating_sub(w.start);
    assert_eq!(
        w.out_vsize, expected_vsize,
        "out_vsize mismatch: got {} expected {} (start={} end={})",
        w.out_vsize, expected_vsize, w.start, w.end
    );

    // Invariant 4: output never exceeds the window end.
    assert!(
        w.out_vsize <= w.end,
        "out_vsize {} exceeds end {}",
        w.out_vsize, w.end
    );
});
