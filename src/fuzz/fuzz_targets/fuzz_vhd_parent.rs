//! Coverage-guided fuzzing of the VHD parent locator read path.
//!
//! Buffer-based on purpose: the parsers under test do no I/O by
//! construction (see the "Parent locators do no I/O" section of the `vhd`
//! module docs), so a mock `CallTable` would cost throughput for code that
//! never calls it.
//!
//! This target asserts invariants rather than merely the absence of a
//! panic. These are safe `no_std` parsers reading constant offsets inside
//! lengths already checked, so a panic-only target would very likely find
//! nothing and would then be indistinguishable from one that reaches
//! nothing at all. The interesting failures here are *policy* failures:
//! a defective entry winning selection, a disagreeing duplicate resolving
//! to a winner, an offset escaping the bounds it was validated against.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vhd::{
    AmbiguityReason, PreferredLocator, VhdImageBounds, VhdImageWindow, VhdParentInfo,
    VhdParentLocator, VhdParentLocatorTable, DYNAMIC_HEADER_SIZE, FOOTER_SIZE,
    MAX_PARENT_NAME_UTF8, PARENT_LOCATOR_COUNT,
};

/// A buffer far larger than the 512-byte UTF-16BE name field can ever
/// need. Decoding into both this and a [`MAX_PARENT_NAME_UTF8`] buffer is
/// how the target distinguishes "the name is undecodable" from "768 bytes
/// was not enough", which the crate documents as impossible.
const OVERSIZED_DST: usize = 4096;

/// Prefilled into every decode destination so a write past the returned
/// length is visible.
const SENTINEL: u8 = 0xA5;

fuzz_target!(|data: &[u8]| {
    if data.len() < DYNAMIC_HEADER_SIZE {
        return;
    }
    let header = &data[..DYNAMIC_HEADER_SIZE];
    let tail = &data[DYNAMIC_HEADER_SIZE..];

    let bounds = synth_bounds(tail);
    let window = synth_window(tail, &bounds);

    // A non-`cxsparse` or short buffer is a valid outcome, not a failure;
    // most of the corpus reaches here.
    let info = match VhdParentInfo::parse(header, &bounds) {
        Some(info) => info,
        None => return,
    };

    // Invariant 4: parsing is deterministic. Anything that depended on
    // uninitialised buffer contents would show up as a mismatch here.
    let again = VhdParentInfo::parse(header, &bounds)
        .expect("VhdParentInfo::parse accepted a header and then refused the same bytes");
    assert_eq!(info.unique_id, again.unique_id, "unique_id is not deterministic");
    assert_eq!(info.timestamp, again.timestamp, "timestamp is not deterministic");
    assert_eq!(
        info.name_utf16_be, again.name_utf16_be,
        "name_utf16_be is not deterministic"
    );
    assert_eq!(
        info.locators, again.locators,
        "the locator table is not deterministic"
    );

    for entry in info.locators.entries.iter() {
        check_entry(entry, &bounds, &window);
    }

    // Invariants 1 and 2, with and without platform data available. The
    // two windows differ in what they can reach, so they exercise both
    // the `ContentsDiffer` and `ContentsUnknown` arms.
    let blind = info.locators.preferred_locator(None);
    let sighted = info.locators.preferred_locator(Some(&window));
    check_preferred(&info.locators, blind, None);
    check_preferred(&info.locators, sighted, Some(&window));

    assert_eq!(
        blind,
        again.locators.preferred_locator(None),
        "preferred_locator is not deterministic"
    );
    assert_eq!(
        sighted,
        again.locators.preferred_locator(Some(&window)),
        "preferred_locator is not deterministic"
    );

    check_decode_name(&info);
});

/// Bounds derived from the input tail, so they vary with the corpus
/// rather than being a constant.
///
/// The arms are weighted towards the realistic layout — a 1024-byte
/// header at file offset 512 — because a wholly random `image_len` and
/// `header_offset` would make `locator_defect` refuse nearly everything
/// and the interesting selection rules would never run. The remaining
/// arms keep the degenerate shapes (a tiny image, a header at zero, an
/// image claiming the whole address space) reachable.
fn synth_bounds(tail: &[u8]) -> VhdImageBounds {
    let selector = byte_at(tail, 0);
    let raw = u64_at(tail, 1);

    let header_offset = match selector & 0x03 {
        0 | 1 => FOOTER_SIZE as u64,
        2 => 0,
        _ => raw,
    };
    let image_len = match (selector >> 2) & 0x03 {
        0 | 1 => 1024 * 1024 + FOOTER_SIZE as u64,
        2 => raw & 0xFFFF,
        _ => raw,
    };

    VhdImageBounds {
        image_len,
        header_offset,
    }
}

/// A window over the input tail, placed so that a locator pointing just
/// past the dynamic header — where instar and Hyper-V both put platform
/// data — resolves, while other arms keep unreachable windows in play.
fn synth_window<'a>(tail: &'a [u8], bounds: &VhdImageBounds) -> VhdImageWindow<'a> {
    let selector = byte_at(tail, 0) >> 4;
    let file_offset = match selector & 0x03 {
        0 | 1 => bounds
            .header_offset
            .saturating_add(DYNAMIC_HEADER_SIZE as u64),
        2 => 0,
        _ => u64_at(tail, 9),
    };
    VhdImageWindow {
        file_offset,
        bytes: tail,
    }
}

/// Invariant 5, plus the accessor walk.
///
/// Every offset and length reachable from a defect-free entry must lie
/// inside the `VhdImageBounds` it was parsed against and clear of the
/// structures `locator_defect` protects. Stated once at the boundary
/// rather than per rule: this is the property the whole defect machinery
/// exists to produce.
fn check_entry(entry: &VhdParentLocator, bounds: &VhdImageBounds, window: &VhdImageWindow<'_>) {
    let platform = entry.platform();
    let unused = entry.is_unused();
    assert_eq!(
        unused,
        platform == vhd::VhdPlatform::Unused,
        "is_unused disagrees with platform() for {:?}",
        entry.platform_code
    );
    assert_eq!(
        entry.is_candidate(),
        !unused && entry.defect.is_none() && platform.preference().is_some(),
        "is_candidate disagrees with its own definition for {:?}",
        entry.platform_code
    );

    let raw = entry.raw_path_bytes(window);

    // Driven for every entry, not only the sound ones, so the refusals
    // decode_path makes before it looks at any bytes are exercised too.
    let mut path = [SENTINEL; OVERSIZED_DST];
    match entry.decode_path(window, &mut path) {
        Ok(n) => {
            assert!(
                platform.is_utf16le_path(),
                "decode_path decoded a {platform:?} entry"
            );
            assert!(
                n <= path.len(),
                "decode_path returned {n} for a {}-byte buffer",
                path.len()
            );
            assert!(
                path[n..].iter().all(|&b| b == SENTINEL),
                "decode_path wrote past its return value"
            );
        }
        Err(vhd::VhdLocatorDefect::UnsupportedPlatformCode) => {
            // `locator_defect` never produces this variant and neither
            // does `raw_path_bytes`, so it can only have come from the
            // encoding check: the code is genuinely one this crate does
            // not decode.
            assert!(
                !platform.is_utf16le_path(),
                "decode_path refused {platform:?} as an unsupported platform code"
            );
        }
        Err(_) => {}
    }

    if let Some(defect) = entry.defect {
        assert_eq!(
            raw.err(),
            Some(defect),
            "a defective entry's raw_path_bytes did not report its defect"
        );
        // A defective entry keeps its raw fields, so nothing below applies.
        return;
    }
    if unused {
        assert!(raw.is_err(), "an unused slot yielded platform data");
        return;
    }

    let start = entry.platform_data_offset;
    let len = u64::from(entry.platform_data_length);
    assert!(len > 0, "a defect-free populated entry names zero bytes");
    assert!(
        entry.platform_data_length <= entry.platform_data_space,
        "platform_data_length {} exceeds platform_data_space {}",
        entry.platform_data_length,
        entry.platform_data_space
    );

    let end = start
        .checked_add(len)
        .expect("a defect-free entry's platform data range overflows u64");
    assert!(
        end <= bounds.image_len,
        "platform data [{start}, {end}) escapes an image of {} bytes",
        bounds.image_len
    );
    assert!(
        !overlaps(start, end, 0, FOOTER_SIZE as u64),
        "platform data [{start}, {end}) overlaps the leading footer"
    );
    if let Some(tail_start) = bounds.image_len.checked_sub(FOOTER_SIZE as u64) {
        assert!(
            !overlaps(start, end, tail_start, bounds.image_len),
            "platform data [{start}, {end}) overlaps the trailing footer"
        );
    }
    let header_end = bounds
        .header_offset
        .saturating_add(DYNAMIC_HEADER_SIZE as u64);
    assert!(
        !overlaps(start, end, bounds.header_offset, header_end),
        "platform data [{start}, {end}) overlaps the dynamic header"
    );

    if let Ok(bytes) = raw {
        // The trim at the first NUL code unit can only shorten it.
        assert!(
            bytes.len() as u64 <= len,
            "raw_path_bytes returned {} bytes for a {len}-byte range",
            bytes.len()
        );
    }
}

/// Invariants 1 and 2: `preferred_locator` never returns a defective
/// entry, and a duplicate platform code whose values disagree resolves to
/// ambiguous rather than to a winner.
fn check_preferred(
    table: &VhdParentLocatorTable,
    result: PreferredLocator,
    data: Option<&VhdImageWindow<'_>>,
) {
    let entries = &table.entries;
    match result {
        PreferredLocator::Found { slot, demoted_from } => {
            assert!(slot < PARENT_LOCATOR_COUNT, "winning slot {slot} is out of range");
            let winner = &entries[slot];

            // Invariant 1. This is what `locator_defect` exists to
            // guarantee; the crate tests it only for hand-built cases.
            assert!(
                winner.defect.is_none(),
                "preferred_locator selected slot {slot} carrying defect {:?}",
                winner.defect
            );
            assert!(!winner.is_unused(), "preferred_locator selected unused slot {slot}");
            let rank = winner
                .platform()
                .preference()
                .expect("preferred_locator selected a non-Windows platform code");

            for (i, entry) in entries.iter().enumerate() {
                if !entry.is_candidate() {
                    continue;
                }
                let other = entry
                    .platform()
                    .preference()
                    .expect("is_candidate proved the rank is Some");
                assert!(
                    other >= rank,
                    "candidate at slot {i} outranks the winner at slot {slot}"
                );
                if other == rank {
                    assert!(
                        i >= slot,
                        "slot {i} carries the winning code but slot {slot} was selected"
                    );
                }
                if other != rank || i == slot {
                    continue;
                }

                // Invariant 2: a second entry sharing the winning code
                // only ever loses when its contents provably agree. Equal
                // ranks mean equal codes, because `preference` maps the
                // four Windows codes to four distinct ranks.
                assert_eq!(
                    entry.platform_code, winner.platform_code,
                    "two platform codes share a preference rank"
                );
                let window = data.expect(
                    "preferred_locator(None) found a winner despite a duplicate winning code",
                );
                let mine = winner
                    .raw_path_bytes(window)
                    .expect("the winner's platform data became unreachable");
                let theirs = entry
                    .raw_path_bytes(window)
                    .expect("a losing duplicate's platform data became unreachable");
                assert_eq!(
                    mine, theirs,
                    "slots {slot} and {i} share a platform code and disagree, \
                     yet resolved to a winner"
                );
            }

            if let Some(demoted) = demoted_from {
                assert!(demoted < PARENT_LOCATOR_COUNT, "demoted_from {demoted} out of range");
                let entry = &entries[demoted];
                assert!(
                    entry.defect.is_some(),
                    "demoted_from names slot {demoted}, which carries no defect"
                );
                assert!(
                    matches!(entry.platform().preference(), Some(r) if r < rank),
                    "demoted_from names slot {demoted}, which does not outrank the winner"
                );
            }
        }
        PreferredLocator::Ambiguous {
            first,
            second,
            reason,
        } => {
            assert!(first < second, "ambiguity reported slots {first} and {second} out of order");
            assert!(second < PARENT_LOCATOR_COUNT, "ambiguous slot {second} is out of range");
            assert!(
                entries[first].is_candidate() && entries[second].is_candidate(),
                "ambiguity between slots {first} and {second}, at least one not a candidate"
            );
            assert_eq!(
                entries[first].platform_code, entries[second].platform_code,
                "ambiguity between slots carrying different platform codes"
            );
            match reason {
                AmbiguityReason::ContentsDiffer => {
                    let window =
                        data.expect("ContentsDiffer without a window: contents were never read");
                    let a = entries[first]
                        .raw_path_bytes(window)
                        .expect("ContentsDiffer on unreadable platform data");
                    let b = entries[second]
                        .raw_path_bytes(window)
                        .expect("ContentsDiffer on unreadable platform data");
                    assert_ne!(a, b, "ContentsDiffer reported for identical platform data");
                }
                AmbiguityReason::ContentsUnknown => {
                    if let Some(window) = data {
                        assert!(
                            entries[first].raw_path_bytes(window).is_err()
                                || entries[second].raw_path_bytes(window).is_err(),
                            "ContentsUnknown although both entries' platform data was readable"
                        );
                    }
                }
            }
        }
        PreferredLocator::NotFound => {
            for (i, entry) in entries.iter().enumerate() {
                assert!(
                    !entry.is_candidate(),
                    "NotFound although slot {i} is a candidate"
                );
            }
        }
    }
}

/// Invariant 3: `decode_name` returns `Some(n)` with `n <= dst.len()` and
/// writes nothing past `n`.
///
/// The crate documents a [`MAX_PARENT_NAME_UTF8`] buffer as one that "can
/// never be too small", but `decode_name` legitimately returns `None` for
/// an unpaired surrogate — refusing rather than substituting `U+FFFD` is
/// deliberate, so a caller cannot mistake a mangled name for a real one.
/// Those two outcomes are indistinguishable
/// from the `Option` alone, so the size claim is asserted by decoding the
/// same field into a buffer that is five times larger and requiring the
/// two calls to agree: a `None` that a bigger buffer turns into a `Some`
/// would be a buffer that was too small.
fn check_decode_name(info: &VhdParentInfo<'_>) {
    let mut dst = [SENTINEL; MAX_PARENT_NAME_UTF8];
    let mut oversized = [SENTINEL; OVERSIZED_DST];
    let n = info.decode_name(&mut dst);
    let m = info.decode_name(&mut oversized);

    assert_eq!(
        n, m,
        "decode_name into {} bytes disagreed with {} bytes: the documented worst case is wrong",
        MAX_PARENT_NAME_UTF8, OVERSIZED_DST
    );

    if let Some(n) = n {
        assert!(
            n <= dst.len(),
            "decode_name returned {n} for a {}-byte buffer",
            dst.len()
        );
        assert!(
            dst[n..].iter().all(|&b| b == SENTINEL),
            "decode_name wrote past its return value"
        );
        assert_eq!(
            &dst[..n],
            &oversized[..n],
            "decode_name produced different bytes for different buffer sizes"
        );
    }
}

/// Whether two half-open ranges intersect. Mirrors the crate-private
/// helper `locator_defect` uses, so the assertion is independent of it.
fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

/// The byte at `off`, or zero past the end.
fn byte_at(buf: &[u8], off: usize) -> u8 {
    buf.get(off).copied().unwrap_or(0)
}

/// Eight big-endian bytes at `off`, zero-padded past the end.
fn u64_at(buf: &[u8], off: usize) -> u64 {
    let mut out = 0u64;
    for i in 0..8 {
        out = (out << 8) | u64::from(byte_at(buf, off + i));
    }
    out
}
