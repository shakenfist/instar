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
//!   2. `size == 0 ⇒ result == 0` (an empty window has no geometry),
//!      and the footer CHS for a zero size is `(0, 0, 0)` (what qemu
//!      writes for a count=0 dd).
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
//!   5. Footer-CHS self-consistency, via the SEARCH geometry
//!      (`chs_rounded_geometry` — the CHS qemu writes into the
//!      footer), NOT the floor geometry of the result. Below the
//!      max-geometry window the search geometry's product IS the
//!      result: `c * h * spt * 512 == result`. Inside the window —
//!      sector counts above the largest sub-ceiling product
//!      `65534*16*255`, where qemu keeps the exact sector-rounded
//!      request — the result is the sector-rounded (and ceiling-
//!      clamped) request and the search geometry is the full ceiling
//!      `(65535, 16, 255)`. This target's previous form asserted the
//!      floor `compute_vhd_geometry(result)` reconstructs the result,
//!      which is FALSE whenever the search's final candidate sits
//!      above a head-count boundary while its product sits below one
//!      (issue #413: input 53426191 rounds to 104363 sectors =
//!      877×7×17, but the floor geometry of 104363 is 1023×6×17 =
//!      104346).
//!   6. Footer reconstruction: `footer_geometry(result)` — what
//!      `build_footer` writes when given the rounded size, re-running
//!      the search on the result alone — equals
//!      `chs_rounded_geometry(size)`, the CHS qemu computed from the
//!      original request. This is what lets instar's dd path stamp
//!      `chs_rounded_size(out_vsize)` and still emit qemu's exact
//!      footer CHS bytes.
//!   7. Idempotence: `chs_rounded_size(result) == result` everywhere
//!      (an already-rounded size never re-rounds).

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
        assert_eq!(vhd::chs_rounded_geometry(0), (0, 0, 0));
        assert_eq!(vhd::footer_geometry(0), (0, 0, 0));
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

    // Invariant 5: the search geometry addresses the result exactly
    // below the max-geometry window; inside it the result is the exact
    // sector-rounded request and the geometry is the full ceiling.
    let (c, h, spt) = vhd::chs_rounded_geometry(size);
    let product = c as u64 * h as u64 * spt as u64 * 512;
    if result / 512 > WINDOW_START_SECTORS {
        let expected = size.div_ceil(512).min(65535 * 16 * 255) * 512;
        assert_eq!(
            result, expected,
            "max-geometry window must keep the sector-rounded request: \
             input={size}, result={result}, expected={expected}"
        );
        assert_eq!(
            (c, h, spt),
            (65535, 16, 255),
            "max-geometry window footer CHS must be the ceiling: \
             input={size}, got ({c},{h},{spt})"
        );
    } else {
        assert_eq!(
            product, result,
            "search geometry does not address the result for input={size}: \
             chs_rounded_size={result}, c={c} h={h} spt={spt}, \
             c*h*spt*512={product}"
        );
    }

    // Invariant 6: build_footer's recomputation from the rounded size
    // alone reproduces the CHS qemu derived from the original request.
    assert_eq!(
        vhd::footer_geometry(result),
        (c, h, spt),
        "footer_geometry({result}) must reproduce the search CHS \
         ({c},{h},{spt}) for input {size}"
    );

    // Invariant 7: idempotence.
    assert_eq!(
        vhd::chs_rounded_size(result),
        result,
        "chs_rounded_size must be idempotent on its own output ({size} -> {result})"
    );
});
