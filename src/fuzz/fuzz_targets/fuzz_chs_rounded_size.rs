//! Coverage-guided fuzzing for `vhd::chs_rounded_size` — the branchy
//! CHS round-up arithmetic `qemu-img dd -O vpc` uses to declare a
//! VHD's virtual size. The highest-value new dd fuzz target.
//!
//! Decodes a single `u64` size and calls `chs_rounded_size`.
//! Invariants asserted (libFuzzer's oracle is panic):
//!
//!   1. No panic / overflow (the function caps `total_sectors`, so
//!      `cylinders * heads * spt * 512` cannot overflow).
//!   2. `size == 0 ⇒ result == 0` (an empty window has no geometry).
//!   3. `size > 0 ⇒ result >= size` (rounds UP to a CHS boundary)
//!      EXCEPT above the CHS ceiling. VHD CHS geometry uses 16-bit
//!      cylinders, so it caps at `65535 * 16 * 255` sectors =
//!      `CHS_MAX_BYTES` (~127.5 GiB); both `chs_rounded_size` and
//!      qemu's VPC backend clamp any larger request to that ceiling,
//!      so for `size > CHS_MAX_BYTES` the result is `CHS_MAX_BYTES`
//!      and is (correctly) SMALLER than the input. In that saturated
//!      region we assert `result == CHS_MAX_BYTES` instead of
//!      `result >= size`. (The phase-5 `chs_rounded_size_rounds_up`
//!      unit test never reached this region — its largest input is
//!      10 GiB — so this fuzz target is what surfaces the ceiling.)
//!   4. `result` is a whole number of sectors (`result % 512 == 0`).
//!   5. CHS self-consistency (floor form). Feeding `result` back
//!      through `compute_vhd_geometry` yields a geometry whose product
//!      `c * h * spt * 512` is `<= result` and within ONE cylinder
//!      (`h * spt * 512`) of it. i.e. `result` is the geometry rounded
//!      UP to a whole cylinder, and the two functions agree to within
//!      one cylinder.
//!
//!      NOTE on why this is NOT the stricter exact-equality the
//!      phase-5 `chs_rounded_size_is_chs_consistent` test asserts:
//!      that unit test feeds a hand-picked allowlist of CHS-ALIGNED
//!      inputs. The exact round-trip `c*h*spt*512 == result` is NOT a
//!      universal property of `chs_rounded_size` — this fuzz target
//!      surfaced two counter-examples that prove it:
//!        * `size = 35_643_423` → `result = 35_807_232`, but
//!          `compute_vhd_geometry` floors `cyl_times_heads / heads`
//!          (4113 / 5 = 822, dropping a remainder of 3) giving
//!          `822*5*17*512 = 35_773_440 != result` — in the spt=17
//!          branch, not the spt=255 region.
//!        * near the `65535*16*63`-sector boundary,
//!          `compute_vhd_geometry` takes its max-geometry early return
//!          `(65535,16,255)` whose product (the full ceiling) EXCEEDS
//!          a `result` that `chs_rounded_size` produced in the spt=63
//!          branch.
//!      So exact equality would be a false positive; the floor +
//!      one-cylinder bound is the faithful invariant. The
//!      max-geometry early-return region (geom returns a fixed
//!      `(65535,16,255)` independent of `result`) is excluded — there
//!      `result` is not derived from that geometry.

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

    // Invariant 5: floor-form CHS self-consistency. Excludes the
    // max-geometry early-return region of compute_vhd_geometry
    // (total_sectors >= 65535*16*63), where it returns a fixed
    // (65535,16,255) independent of `result` and so cannot be expected
    // to reconstruct it.
    const GEOM_MAX_EARLY_SECTORS: u64 = 65535 * 16 * 63;
    if result / 512 < GEOM_MAX_EARLY_SECTORS {
        let (c, h, spt) = vhd::compute_vhd_geometry(result);
        let reconstructed = c as u64 * h as u64 * spt as u64 * 512;
        let cylinder = h as u64 * spt as u64 * 512;
        assert!(
            reconstructed <= result,
            "geometry over-reconstructs input={size}: \
             chs_rounded_size={result}, c={c} h={h} spt={spt}, \
             c*h*spt*512={reconstructed} > {result}"
        );
        assert!(
            result - reconstructed < cylinder,
            "geometry round-trip off by >=1 cylinder for input={size}: \
             chs_rounded_size={result}, c={c} h={h} spt={spt}, \
             c*h*spt*512={reconstructed}, cylinder={cylinder}"
        );
    }
});
