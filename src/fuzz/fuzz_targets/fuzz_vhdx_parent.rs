//! Coverage-guided fuzzing of the VHDX parent locator item parser.
//!
//! Buffer-based on purpose, like `fuzz_vhd_parent`: `parse_parent_locator`
//! does no I/O by construction, taking the item's own bytes and nothing
//! else, so a mock `CallTable` would cost throughput for code that never
//! calls it.
//!
//! It is also the only way this path gets fuzzed at all. Driving it
//! through `parse_metadata` means first synthesising a region table, a
//! metadata table, and an item entry whose offset clears
//! `METADATA_ITEMS_MIN_OFFSET` (64 KiB) — three independent structures
//! that all have to line up before a single byte of the locator itself
//! is read. `fuzz_vhdx_metadata`, which does drive that whole path,
//! measured 0% region coverage on `parse_parent_locator` and every one
//! of its helpers after a 300-second run and 3.7M executions: libFuzzer
//! never stumbled onto a layout that satisfies all three preconditions
//! at once. Handing it the item bytes directly removes the precondition
//! and leaves only the parser itself on trial.
//!
//! Invariants asserted below, not just the absence of a panic — this is
//! a safe `no_std` parser reading `u32`/`u16` offsets behind
//! `checked_add` and an explicit bounds compare, so a panic-only target
//! would very likely find nothing. The interesting failures are the
//! same shape as the VHD side's: an offset escaping the bounds it was
//! checked against, a comparison that silently ignores case where the
//! spec requires it to, or a "this was declined" outcome that collapses
//! into the same `None` a truly absent value produces.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vhdx::{
    parse_parent_locator, VhdxParentLocator, VhdxParentLocatorDefect, VhdxParentLocatorEntry,
    VhdxParentLocatorState, MAX_PARENT_LOCATOR_ENTRIES, MAX_PARENT_LOCATOR_KEY_UTF8,
    MAX_PARENT_LOCATOR_VALUE_UTF8, PARENT_LOCATOR_ENTRY_SIZE, PARENT_LOCATOR_HEADER_SIZE,
    VHDX_PARENT_LOCATOR_TYPE_GUID,
};

fuzz_target!(|data: &[u8]| {
    // Too short to hold even the fixed header is a valid outcome, not a
    // failure; most of a random corpus lands here.
    let Some(locator) = parse_parent_locator(data) else {
        return;
    };

    // Invariant 3: parsing is deterministic. `parse_parent_locator`
    // takes no allocator and touches nothing but `data`, so anything
    // that depended on uninitialised state would show up as a mismatch
    // here.
    let again = parse_parent_locator(data)
        .expect("parse_parent_locator accepted an item and then refused the same bytes");
    assert_locators_match(&locator, &again, data.len());

    check_item_level(&locator, data);

    for entry in locator.entries() {
        check_entry_bounds(entry, data.len());
    }

    check_declined_distinguishable_from_absent(&locator);
    check_linkage(&locator);
    check_preferred_path(&locator);

    // `VhdxParentLocatorState::is_absent`/`parsed` are one-line wrappers
    // around the variant, reachable in practice only through
    // `parse_metadata`'s region/metadata-table synthesis — the same
    // precondition that keeps `parse_parent_locator` itself unreached
    // by `fuzz_vhdx_metadata`. Exercised directly here for the same
    // reason.
    let state = VhdxParentLocatorState::Parsed(locator);
    assert!(!state.is_absent(), "Parsed state reported is_absent()");
    assert!(state.parsed().is_some(), "Parsed state's parsed() returned None");

    assert!(
        VhdxParentLocatorState::Absent.is_absent(),
        "Absent state's is_absent() returned false"
    );
    assert!(
        VhdxParentLocatorState::Absent.parsed().is_none(),
        "Absent state's parsed() returned Some"
    );
});

/// Invariant 3, spelled out field by field because neither
/// `VhdxParentLocator` nor `VhdxParentLocatorEntry` derives `PartialEq`
/// — they carry fixed decode buffers that are compared through the
/// public accessors instead of the raw arrays.
fn assert_locators_match(a: &VhdxParentLocator, b: &VhdxParentLocator, item_len: usize) {
    assert_eq!(a.locator_type, b.locator_type, "locator_type is not deterministic");
    assert_eq!(a.reserved, b.reserved, "reserved is not deterministic");
    assert_eq!(
        a.key_value_count, b.key_value_count,
        "key_value_count is not deterministic"
    );
    assert_eq!(a.defect, b.defect, "item-level defect is not deterministic");
    assert_eq!(
        a.entries().len(),
        b.entries().len(),
        "entry count is not deterministic for a {item_len}-byte item"
    );
    for (i, (ea, eb)) in a.entries().iter().zip(b.entries().iter()).enumerate() {
        assert_eq!(ea.key_offset, eb.key_offset, "entry {i} key_offset is not deterministic");
        assert_eq!(
            ea.value_offset, eb.value_offset,
            "entry {i} value_offset is not deterministic"
        );
        assert_eq!(ea.key_length, eb.key_length, "entry {i} key_length is not deterministic");
        assert_eq!(
            ea.value_length, eb.value_length,
            "entry {i} value_length is not deterministic"
        );
        assert_eq!(ea.defect, eb.defect, "entry {i} defect is not deterministic");
        assert_eq!(ea.key(), eb.key(), "entry {i} decoded key is not deterministic");
        assert_eq!(ea.value(), eb.value(), "entry {i} decoded value is not deterministic");
    }
}

/// Invariant 2, plus the structural bounds `parse_parent_locator` itself
/// enforces on how many entries it can ever produce for a given item —
/// checked here independently of the parser's own arithmetic, the same
/// way `parent_locator_key_value_count_exceeds_item` and
/// `..._exceeds_capacity` check it by hand.
fn check_item_level(locator: &VhdxParentLocator, item: &[u8]) {
    // Invariant 2: is_vhdx_locator_type() agrees with the GUID actually
    // present in the item bytes, not merely with the field it copied
    // that GUID into.
    assert_eq!(
        locator.is_vhdx_locator_type(),
        item[..16] == VHDX_PARENT_LOCATOR_TYPE_GUID,
        "is_vhdx_locator_type disagrees with the GUID in the item bytes"
    );
    assert_eq!(
        &locator.locator_type[..],
        &item[..16],
        "locator_type does not match the item bytes"
    );

    // The item-level defect field is only ever set for one of these two
    // reasons; an entry-level defect never ends up here.
    assert!(
        matches!(
            locator.defect,
            None
                | Some(VhdxParentLocatorDefect::EntryCountExceedsItem)
                | Some(VhdxParentLocatorDefect::EntryCountExceedsCapacity)
        ),
        "unexpected item-level defect {:?}",
        locator.defect
    );

    let entries_that_fit = (item.len() - PARENT_LOCATOR_HEADER_SIZE) / PARENT_LOCATOR_ENTRY_SIZE;
    assert!(
        locator.entries().len() <= entries_that_fit,
        "{} entries retained but only {entries_that_fit} fit in a {}-byte item",
        locator.entries().len(),
        item.len()
    );
    assert!(
        locator.entries().len() <= MAX_PARENT_LOCATOR_ENTRIES,
        "{} entries retained, over the {MAX_PARENT_LOCATOR_ENTRIES}-entry parser bound",
        locator.entries().len()
    );
}

/// Invariant 1: every offset and length reachable from a parsed entry
/// lies inside the item it was parsed from, checked by index against
/// `item_len` rather than trusted from the parser's own bookkeeping.
///
/// `decode_entry_strings` resolves key bounds, then key length, then
/// key decoding, then value bounds, then value length, then value
/// decoding, returning on the first problem — so which of those steps
/// ran, and therefore which bounds were actually established, is
/// determined by which defect (if any) an entry carries. This mirrors
/// that order independently rather than re-deriving it from the parser.
fn check_entry_bounds(entry: &VhdxParentLocatorEntry, item_len: usize) {
    use VhdxParentLocatorDefect::{KeyOutOfBounds, KeyTooLong, KeyUndecodable, ValueOutOfBounds};

    let key_bounds_checked = entry.defect != Some(KeyOutOfBounds);
    if key_bounds_checked {
        let end = (entry.key_offset as usize).checked_add(entry.key_length as usize);
        assert!(
            matches!(end, Some(e) if e <= item_len),
            "entry key [{}, +{}) escapes the {item_len}-byte item, \
             defect {:?} rather than KeyOutOfBounds",
            entry.key_offset,
            entry.key_length,
            entry.defect,
        );
    } else {
        assert!(entry.key().is_empty(), "KeyOutOfBounds entry still produced a decoded key");
    }

    // Value bounds are only ever reached once the key resolved far
    // enough for decode_entry_strings to get past it.
    let value_bounds_checked = !matches!(
        entry.defect,
        Some(KeyOutOfBounds) | Some(KeyTooLong) | Some(KeyUndecodable) | Some(ValueOutOfBounds)
    );
    if value_bounds_checked {
        let end = (entry.value_offset as usize).checked_add(entry.value_length as usize);
        assert!(
            matches!(end, Some(e) if e <= item_len),
            "entry value [{}, +{}) escapes a {item_len}-byte item (defect: {:?})",
            entry.value_offset,
            entry.value_length,
            entry.defect,
        );
    }

    // A key/value that decode_entry_strings never reached, or that it
    // reached and rejected, never produces a non-empty decoded string —
    // key() and value() only hold what actually decoded.
    let key_decoded =
        !matches!(entry.defect, Some(KeyOutOfBounds) | Some(KeyTooLong) | Some(KeyUndecodable));
    if !key_decoded {
        assert!(
            entry.key().is_empty(),
            "entry.key() non-empty despite defect {:?}",
            entry.defect
        );
    }
    let value_decoded = matches!(entry.defect, None | Some(VhdxParentLocatorDefect::DuplicateKey));
    if !value_decoded {
        assert!(
            entry.value().is_empty(),
            "entry.value() non-empty despite defect {:?}",
            entry.defect
        );
    }

    assert!(entry.key().len() <= MAX_PARENT_LOCATOR_KEY_UTF8, "decoded key exceeds its own buffer");
    assert!(
        entry.value().len() <= MAX_PARENT_LOCATOR_VALUE_UTF8,
        "decoded value exceeds its own buffer"
    );
}

/// Invariant 4: an entry the parser declines is reported as declined,
/// not silently treated the same as a key the item never mentioned —
/// the same distinction `VhdxParentLocatorState::NotStaged` draws
/// against `::Absent` at the metadata-item level
/// (`parent_locator_declined_item_is_distinguishable_from_absent`), here
/// at the entry level.
///
/// A key that decoded is always findable — `find()` never degrades a
/// present-but-defective entry into the `None` a genuinely missing key
/// produces, which a probe key guaranteed not to appear in this image
/// demonstrates. Where the entry `find()` actually resolves to *is*
/// this one (i.e. it is the first entry carrying that key — a later
/// `DuplicateKey` entry resolves to the earlier, defect-free entry
/// instead, per `parent_locator_duplicate_key`), the defect it
/// carries survives the round trip through `find()`, and `value_of()`
/// — which exists to hand a caller a usable value — refuses it.
fn check_declined_distinguishable_from_absent(locator: &VhdxParentLocator) {
    // 0xFF, not a distinctive spelling. libFuzzer intercepts
    // memcmp-style comparisons and feeds the operands into its
    // auto-dictionary, so a merely improbable literal is exactly the
    // kind of constant it is built to learn -- and a match would fire an
    // assertion that says nothing about the parser. Keys come back as
    // UTF-8 written by `utf16_to_utf8`, whose widest lead byte is 0xF4
    // and whose continuation bytes are all 0x80..=0xBF, so a probe
    // carrying 0xFF cannot be matched however well the corpus is
    // mutated: this probe is absent by construction rather than by luck.
    let probe: &[u8] = b"\xffnever written\xff";
    assert!(locator.find(probe).is_none(), "find() matched a key that was never written");
    assert!(
        locator.value_of(probe).is_none(),
        "value_of() matched a key that was never written"
    );

    for (i, entry) in locator.entries().iter().enumerate() {
        let Some(defect) = entry.defect else { continue };
        if entry.key().is_empty() {
            // The key itself never decoded; nothing to look up it by.
            continue;
        }

        assert!(
            locator.find(entry.key()).is_some(),
            "a declined entry's own key is not findable via find() (defect: {defect:?})"
        );

        let first = locator
            .entries()
            .iter()
            .position(|e| !e.key().is_empty() && e.key() == entry.key())
            .expect("just proved this key is findable");
        if first == i {
            assert_eq!(
                locator.find(entry.key()).and_then(|e| e.defect),
                Some(defect),
                "find() lost this entry's own defect"
            );
            assert!(
                locator.value_of(entry.key()).is_none(),
                "value_of() returned a value for a defective entry"
            );
        }
    }
}

/// Invariant 5: `linkage_matches` compares case-insensitively, and a
/// missing `parent_linkage` matches nothing.
fn check_linkage(locator: &VhdxParentLocator) {
    match locator.parent_linkage() {
        None => {
            assert!(
                !locator.linkage_matches(b""),
                "linkage_matches matched with no linkage present"
            );
            assert!(
                !locator.linkage_matches(b"{00000000-0000-0000-0000-000000000000}"),
                "linkage_matches matched with no linkage present"
            );
        }
        Some(linkage) => {
            assert!(locator.linkage_matches(linkage), "linkage_matches did not match itself");

            let mut flipped = [0u8; MAX_PARENT_LOCATOR_VALUE_UTF8];
            let dst = &mut flipped[..linkage.len()];
            for (o, &b) in dst.iter_mut().zip(linkage.iter()) {
                *o = flip_ascii_case(b);
            }
            assert!(locator.linkage_matches(dst), "linkage_matches is not case-insensitive");

            // A value that cannot possibly be a case variant of the
            // real one -- shorter by a byte -- must not match.
            if !linkage.is_empty() {
                assert!(
                    !locator.linkage_matches(&linkage[..linkage.len() - 1]),
                    "linkage_matches matched a truncated value"
                );
            }
        }
    }
}

/// Exercises the three raw path accessors alongside `preferred_path`
/// and `preferred_path_with_convention`, and checks the preference
/// order `preferred_path_with_convention` documents: `relative_path`,
/// then `absolute_win32_path`, then `volume_path`, highest first —
/// the same order `preferred_path_prefers_relative_path` and
/// `preferred_path_falls_back_to_absolute_win32_path` each check for
/// one hand-built layout.
fn check_preferred_path(locator: &VhdxParentLocator) {
    let relative = locator.relative_path();
    let absolute = locator.absolute_win32_path();
    let volume = locator.volume_path();
    let preferred = locator.preferred_path();
    let with_convention = locator.preferred_path_with_convention();

    assert_eq!(
        preferred,
        with_convention.map(|(path, _)| path),
        "preferred_path disagrees with preferred_path_with_convention"
    );

    let expected = relative
        .map(|p| (p, true))
        .or_else(|| absolute.map(|p| (p, false)))
        .or_else(|| volume.map(|p| (p, false)));
    assert_eq!(
        with_convention, expected,
        "preferred_path_with_convention ignored the documented \
         relative > absolute_win32 > volume order"
    );
}

/// Flip the ASCII case of one byte, leaving anything else (digits,
/// hyphens, braces) unchanged.
fn flip_ascii_case(b: u8) -> u8 {
    if b.is_ascii_lowercase() {
        b.to_ascii_uppercase()
    } else if b.is_ascii_uppercase() {
        b.to_ascii_lowercase()
    } else {
        b
    }
}
