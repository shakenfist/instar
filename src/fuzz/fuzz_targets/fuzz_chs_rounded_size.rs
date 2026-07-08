//! Coverage-guided fuzzing for `vhd::chs_rounded_size` — the branchy
//! CHS round-up arithmetic `qemu-img dd -O vpc` uses to declare a
//! VHD's virtual size. The highest-value new dd fuzz target.
//!
//! Decodes a single `u64` size and calls `chs_rounded_size`, which
//! mirrors qemu vpc.c's `calculate_rounded_image_size` (the upward
//! search over floor `calculate_geometry` candidates — see the
//! function's doc comment). Invariants asserted (libFuzzer's oracle is
//! panic):
//!
//!   1. No panic / overflow (the function caps `total_sectors`, so
//!      `cylinders * heads * spt * 512` cannot overflow).
//!   2. `size == 0 ⇒ result == 0` (an empty window has no geometry).
//!   3. `size > 0 ⇒ result >= size` (rounds UP to a CHS boundary)
//!      EXCEPT above the CHS ceiling. VHD CHS geometry uses 16-bit
//!      cylinders, so it caps at `65535 * 16 * 255` sectors =
//!      `CHS_MAX_BYTES` (~127.5 GiB); qemu refuses larger requests,
//!      instar clamps them to the ceiling, so for
//!      `size > CHS_MAX_BYTES` the result is `CHS_MAX_BYTES` and is
//!      (correctly) SMALLER than the input. In that saturated region
//!      we assert `result == CHS_MAX_BYTES` instead of
//!      `result >= size`.
//!   4. `result` is a whole number of sectors (`result % 512 == 0`).
//!   5. CHS self-consistency. Below the max-geometry window the result
//!      is a `calculate_geometry` fixed point, so feeding it back
//!      through `compute_vhd_geometry` reconstructs it EXACTLY:
//!      `c * h * spt * 512 == result`. (The old one-pass ceil
//!      implementation violated exactness — e.g. `35_643_423` produced
//!      a size its own recomputed footer CHS could not address, the
//!      qemu divergence behind issue #382 — so this target's old form
//!      asserted only a one-cylinder bound. The qemu-mirror rewrite
//!      restores exactness.) Inside the max-geometry window — sector
//!      counts above the largest sub-ceiling product `65534*16*255`,
//!      where qemu keeps the exact sector-rounded request — we instead
//!      assert the result is exactly the sector-rounded (and ceiling-
//!      clamped) request.
//!   6. Idempotence: `chs_rounded_size(result) == result` everywhere
//!      (an already-rounded size never re-rounds), which is what lets
//!      `build_footer` recompute the footer CHS from current_size.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let size = u64::from_le_bytes(data[0..8].try_into().unwrap());

    // The CHS ceiling: 16-bit cylinders × 16 heads × 255 spt × 512.
    // chs_rounded_size clamps any larger request to this value.
    const CHS_MAX_BYTES: u64 = 65535 * 16 * 255 * 512;
    // The largest geometry product below the ceiling; sector counts
    // above it fall into the max-geometry window.
    const WINDOW_START_SECTORS: u64 = 65534 * 16 * 255;

    let result = vhd::chs_rounded_size(size);

    // Invariant 2: empty disk has no geometry.
    if size == 0 {
        assert_eq!(result, 0, "chs_rounded_size(0) must be 0, got {result}");
        return;
    }

    // Invariant 3: rounds UP, except above the CHS ceiling where the
    // geometry saturates and the result is (correctly) smaller.
    assert_ne!(result, 0, "chs_rounded_size({size}) must not be 0 for non-zero input");
    if size > CHS_MAX_BYTES {
        assert_eq!(
            result, CHS_MAX_BYTES,
            "chs_rounded_size({size}) past the CHS ceiling must saturate to \
             {CHS_MAX_BYTES}, got {result}"
        );
    } else {
        assert!(
            result >= size,
            "chs_rounded_size({size}) = {result} is less than the input"
        );
    }

    // Invariant 4: result is a whole number of sectors.
    assert!(
        result.is_multiple_of(512),
        "chs_rounded_size({size}) = {result} is not a sector multiple"
    );

    // Invariant 5: exact CHS reconstruction below the max-geometry
    // window; the exact sector-rounded request inside it.
    if result / 512 > WINDOW_START_SECTORS {
        let expected = size.div_ceil(512).min(65535 * 16 * 255) * 512;
        assert_eq!(
            result, expected,
            "max-geometry window must keep the sector-rounded request: \
             input={size}, result={result}, expected={expected}"
        );
    } else {
        let (c, h, spt) = vhd::compute_vhd_geometry(result);
        let reconstructed = c as u64 * h as u64 * spt as u64 * 512;
        assert_eq!(
            reconstructed, result,
            "geometry round-trip failed for input={size}: \
             chs_rounded_size={result}, c={c} h={h} spt={spt}, \
             c*h*spt*512={reconstructed}"
        );
    }

    // Invariant 6: idempotence.
    assert_eq!(
        vhd::chs_rounded_size(result),
        result,
        "chs_rounded_size must be idempotent on its own output ({size} -> {result})"
    );
});
