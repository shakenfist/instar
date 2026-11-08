//! Coverage-guided fuzzing of the fixed VHDX block allocation table
//! filler, `vhdx::fill_fixed_bat`.
//!
//! The filler is a pure function of a layout, a block state, a first
//! BAT index and an output buffer, so its input space is arbitrary
//! geometries crossed with arbitrary index ranges and buffer sizes.
//! That has nothing in common with the create-option bytes
//! `fuzz_create_emitters` decodes: that target reaches the filler only
//! through a layout a create plan produced, and only over the two
//! windows it places. This one reaches geometries no create plan
//! chooses, index ranges that start anywhere in the region, and the
//! buffer lengths -- zero, unaligned, past the region -- a planner
//! never asks for.
//!
//! A 26-byte structured header is decoded into a virtual size, a block
//! size, a block state, a first entry and an output length, the layout
//! is derived with `vhdx::layout` (never recomputed here: a harness
//! with its own geometry rules checks the filler against the wrong
//! image), and the filler is called. Asserted on success:
//!
//!   1. every entry in the buffer was written
//!   2. every entry is one the format defines
//!   3. a padding or sector-bitmap index is zero
//!   4. a payload entry carries the state the call asked for
//!   5. a payload entry's offset is a whole number of MiB
//!   6. payload offsets strictly increase with the index
//!   7. a payload offset is the one qemu's forward map gives it
//!   8. any partition of the index range into two calls writes the
//!      same bytes as one call
//!
//! and on failure:
//!
//!   9. the error is the one the inputs imply, and the buffer is
//!      untouched
//!
//! and over the layout itself, before the call, because invariant 3
//! classifies an index by the entry count the layout declares and so
//! cannot see that count being wrong:
//!
//!  10. the entry count is the one the layout's own block count and
//!      chunk ratio imply
//!
//! Nothing here may panic on any input, so every arithmetic step is
//! checked.

#![no_main]

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use vhdx::{
    BatFillError, FixedBlockState, VhdxLayout, BAT_ENTRY_OFFSET_MASK, BAT_ENTRY_STATE_MASK,
    MB_ALIGN, PAYLOAD_BLOCK_FULLY_PRESENT, PAYLOAD_BLOCK_ZERO,
};

/// Bytes of structured header the target decodes.
const HEADER_BYTES: usize = 26;

/// Bytes per BAT entry.
const ENTRY_LEN: usize = 8;

/// Most entries one call is asked for.
///
/// A fixed BAT runs to 513 MiB at the 64 TiB ceiling, so a target that
/// filled whole regions would spend every iteration in one geometry.
/// The bound is one more than the largest `chunk_ratio` a legal layout
/// produces (4096, at a 1 MiB block size), because the BAT repeats
/// every `chunk_ratio + 1` entries with the sector-bitmap slot last:
/// 4096 entries from index 0 stop one short of that slot, and 4097
/// reach it, so a single call can span a whole group and its slot at
/// every legal ratio.
const MAX_BUFFER_ENTRIES: u64 = 4097;

/// The largest `chunk_ratio` a legal layout produces: 8 MiB of sectors
/// per chunk at a 512-byte logical sector size divided by the smallest
/// 1 MiB block size (SPEC(VHDX) 3.4.1.2).
const MAX_CHUNK_RATIO: u64 = 4096;

/// The buffer bound's reason, checked at build time rather than left to
/// the comment above it: the BAT repeats every `chunk_ratio + 1`
/// entries with the sector-bitmap slot last, so spanning a whole group
/// and its slot from index 0 needs strictly more than `MAX_CHUNK_RATIO`
/// entries.
const _: () = assert!(MAX_BUFFER_ENTRIES > MAX_CHUNK_RATIO);

/// Bytes past the slice handed to the filler, left as the fill pattern
/// so a write past the end of the buffer is caught here rather than
/// relying on it happening to land in another allocation.
const GUARD_LEN: usize = ENTRY_LEN;

/// Most bytes a draw adds past a whole number of entries, to reach the
/// `UnalignedBuffer` path. The buffer has to hold those bytes as well
/// as the guard, or an unaligned draw indexes past the allocation and
/// the harness fails where the filler is blameless.
const MAX_SKEW: usize = ENTRY_LEN - 1;

/// What an unwritten byte holds. No entry the filler writes can equal
/// `FILL` repeated: every entry it writes is 0, `PAYLOAD_BLOCK_ZERO`,
/// or an offset with `PAYLOAD_BLOCK_FULLY_PRESENT` in its state field,
/// and `0xa5 & 0x07` is 5, which is none of those states.
const FILL: u8 = 0xa5;

thread_local! {
    /// The buffer one call fills, plus its guard.
    static SINGLE: RefCell<Vec<u8>> = RefCell::new(vec![
        FILL;
        MAX_BUFFER_ENTRIES as usize * ENTRY_LEN + MAX_SKEW + GUARD_LEN
    ]);

    /// The buffer the two partitioned calls fill between them.
    static PARTITIONED: RefCell<Vec<u8>> =
        RefCell::new(vec![FILL; MAX_BUFFER_ENTRIES as usize * ENTRY_LEN]);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_BYTES {
        return;
    }

    let virtual_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let block_size_raw = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let flags = data[12];
    let first_entry_raw = u64::from_le_bytes(data[13..21].try_into().unwrap());
    let buffer_entries_raw = u16::from_le_bytes(data[21..23].try_into().unwrap());
    let skew_sel = data[23];
    let split_raw = u16::from_le_bytes(data[24..26].try_into().unwrap());

    // Bit 1 steers the block size onto one of the nine powers of two
    // the metadata rule accepts (1 MiB to 256 MiB). Left raw, almost
    // every draw is refused by `layout` and the filler is never
    // reached; steered, the geometry varies and the invariants below
    // get exercised. Both paths are kept so the refusal is still fuzzed
    // -- and 0, which means "the default for this virtual size", is
    // only reachable through the raw path.
    let block_size = if flags & 2 != 0 {
        1u32 << (20 + block_size_raw % 9)
    } else {
        block_size_raw
    };
    let state = if flags & 1 != 0 {
        FixedBlockState::FullyPresent
    } else {
        FixedBlockState::Zero
    };

    // A fixed VHDX never has a parent -- it is the only kind qemu-img
    // creates, and the planner refuses a fixed image with a backing
    // file -- so the filler's entry rule is the no-parent one and the
    // layout must be derived the same way. A differencing layout here
    // would check the filler against a BAT it does not write.
    let Ok(layout) = vhdx::layout(virtual_size, block_size, false) else {
        return;
    };

    // Entries the BAT region holds, which is what the filler bounds
    // `first_entry` against -- not `bat_entries`, since the region is
    // rounded up to 1 MiB and the padding past the last entry is part
    // of it.
    let capacity = u64::from(layout.bat_region_len) / ENTRY_LEN as u64;

    // `layout` resolves `chunk_ratio` from the block size it has
    // already validated, and the largest block size it accepts
    // (256 MiB) still leaves a ratio of 16, so a zero ratio cannot come
    // out of it. The filler's `DegenerateChunkRatio` is therefore
    // unreachable from here, and the expected-error rule below relies on
    // that. What breaking this looks like: a layout whose BAT has no
    // group size, which no reader accepts and which would make every
    // index classification below meaningless.
    assert!(
        layout.chunk_ratio != 0,
        "layout({}, {}) declared a zero chunk ratio",
        virtual_size, block_size
    );

    // Invariant 10: the entry count is the one the layout's own block
    // count and chunk ratio imply.
    //
    // SPEC(VHDX) 2.5 for an image with no parent: one entry per payload
    // block, plus one sector-bitmap entry for each whole group of
    // `chunk_ratio` payload blocks that has another payload block after
    // it. Computed here rather than by calling the crate's counter, so
    // that a counter which is off by one is a divergence this target
    // can see rather than one it reproduces -- invariant 3 takes the
    // declared count as given when it decides which indices are
    // padding, so without this the two would agree with each other and
    // with nothing else. What breaking this looks like: a BAT one entry
    // longer than the region table declares, which a conforming reader
    // refuses outright, or one entry shorter, which loses the last
    // block.
    let payload_blocks = u64::from(layout.payload_blocks);
    let expected_entries = if payload_blocks == 0 {
        0
    } else {
        payload_blocks
            .checked_sub(1)
            .and_then(|n| n.checked_div(u64::from(layout.chunk_ratio)))
            .and_then(|bitmaps| payload_blocks.checked_add(bitmaps))
            .expect("expected BAT entry count overflows u64")
    };
    assert_eq!(
        u64::from(layout.bat_entries), expected_entries,
        "layout({}, {}) declares {} BAT entries, but {} payload blocks at a chunk ratio \
         of {} imply {}",
        virtual_size, block_size, layout.bat_entries, payload_blocks, layout.chunk_ratio,
        expected_entries
    );

    // Bit 2 folds the first entry into the region. Left raw it is
    // almost always past the region, which is worth fuzzing but reaches
    // none of the success invariants; folded, the whole range of legal
    // starts is reachable, mid-group starts included.
    let first_entry = if flags & 4 != 0 {
        first_entry_raw % (capacity + 1)
    } else {
        first_entry_raw
    };
    let entries = u64::from(buffer_entries_raw) % (MAX_BUFFER_ENTRIES + 1);
    // 1 to 7 bytes past a whole number of entries, which is the
    // `UnalignedBuffer` path; 0 for every aligned draw.
    let skew = usize::from(skew_sel % ENTRY_LEN as u8);
    let len = entries as usize * ENTRY_LEN + skew;
    // Where the two partitioned calls below divide the range, including
    // both ends: a partition that writes nothing in one of its halves
    // is as much a partition as any other.
    let split = u64::from(split_raw) % (entries + 1);

    // The error the inputs imply, in the order the filler decides them:
    // an unaligned length first, then a range whose end does not fit
    // u64, then a range that leaves the region. Anything else must
    // succeed, since a degenerate chunk ratio is ruled out above.
    let expected_error = if skew != 0 {
        Some(BatFillError::UnalignedBuffer)
    } else {
        match first_entry.checked_add(entries) {
            None => Some(BatFillError::Overflow),
            Some(end) if end > capacity => Some(BatFillError::PastRegion),
            Some(_) => None,
        }
    };

    SINGLE.with(|cell| {
        let mut buf = cell.borrow_mut();
        let slot = &mut buf[..len + GUARD_LEN];
        slot.fill(FILL);
        let result = vhdx::fill_fixed_bat(&layout, state, first_entry, &mut slot[..len]);

        // Invariant 9: the call refuses exactly what the inputs imply,
        // with a declared variant, and writes nothing when it refuses.
        //
        // The error is checked against the inputs rather than merely
        // matched against the enum, because "some error" is satisfied by
        // a filler that refuses everything. What breaking this looks
        // like: a bound that rejects a legal window, so a caller
        // streaming a BAT stops part way through and writes a region
        // the header already declares full length; or one that accepts
        // an illegal one, so the caller writes past the region and over
        // the metadata that follows it.
        assert_eq!(
            result.err(), expected_error,
            "fill_fixed_bat({} entries from {}, {} byte buffer, capacity {}) returned {:?}, \
             not {:?}",
            entries, first_entry, len, capacity, result.err(), expected_error
        );
        if expected_error.is_some() {
            // `fill_fixed_bat_errors_leave_the_buffer_untouched`
            // generalised: a caller that writes the buffer out anyway
            // after ignoring the error must not find half a BAT in it.
            assert!(
                slot.iter().all(|&b| b == FILL),
                "fill_fixed_bat wrote into the buffer before returning {:?}",
                expected_error
            );
            return;
        }

        // The guard sits past the slice the filler was given, so a
        // single byte written past the end shows here. It is part of
        // invariant 1: nothing outside the buffer is touched.
        assert!(
            slot[len..].iter().all(|&b| b == FILL),
            "fill_fixed_bat wrote past the end of a {}-byte buffer",
            len
        );

        assert_entries(&layout, state, first_entry, &slot[..len]);

        // Invariant 8: any partition of the index range into two calls
        // writes the same bytes as one call over the whole range.
        //
        // `fill_fixed_bat_is_the_same_through_any_buffer_size` pins this
        // for two layouts and two buffer sizes; here it is every
        // partition of an arbitrary range in an arbitrary geometry,
        // which is what a streaming caller actually does -- it advances
        // `first_entry` by whatever its buffer holds. What breaking this
        // looks like: an entry that depends on where the caller's buffer
        // happened to start rather than on its own index, so the same
        // BAT comes out differently through a 512-byte buffer and a
        // 64 KiB one and only one of them is the image qemu wrote.
        PARTITIONED.with(|other| {
            let mut part = other.borrow_mut();
            let head_len = split as usize * ENTRY_LEN;
            part[..len].fill(FILL);
            let (head, tail) = part[..len].split_at_mut(head_len);
            for (label, first, out) in [
                ("head", first_entry, head),
                ("tail", first_entry + split, tail),
            ] {
                vhdx::fill_fixed_bat(&layout, state, first, out).unwrap_or_else(|e| {
                    panic!(
                        "fill_fixed_bat refused the {} of a partition at {}: {:?}, \
                         though the whole range from {} succeeded",
                        label, split, e, first
                    )
                });
            }
            assert!(
                part[..len] == slot[..len],
                "fill_fixed_bat over {} entries from {} differs from the same range \
                 split at {}",
                entries, first_entry, split
            );
        });
    });
});

/// Invariants 1 to 7, over the entries one successful call wrote.
fn assert_entries(layout: &VhdxLayout, state: FixedBlockState, first_entry: u64, out: &[u8]) {
    let chunk_ratio = u64::from(layout.chunk_ratio);
    let group = chunk_ratio
        .checked_add(1)
        .expect("chunk ratio + 1 overflows u64");
    let bat_entries = u64::from(layout.bat_entries);
    let block_size = u64::from(layout.block_size);
    let mut previous_offset: Option<u64> = None;

    for (slot, index) in out.chunks_exact(ENTRY_LEN).zip(first_entry..) {
        let entry = u64::from_le_bytes(slot.try_into().expect("8-byte chunk"));

        // Invariant 1: every entry in the buffer was written.
        //
        // No entry the filler writes can be the fill pattern, so an
        // entry that still holds it was skipped. What breaking this
        // looks like: a BAT whose last entry, or whose entry at a group
        // boundary, holds whatever the caller's buffer held before --
        // which a reader decodes as a block at a garbage offset, not as
        // an absent one.
        assert_ne!(
            entry,
            u64::from_le_bytes([FILL; ENTRY_LEN]),
            "entry {} was not written",
            index
        );

        // Invariant 2: the entry is one the format defines.
        //
        // The filler writes three shapes and no others: an unused
        // entry, a ZERO payload entry, and a FULLY_PRESENT one naming
        // an offset. What breaking this looks like: a state field a
        // reader has no rule for -- PARTIALLY_PRESENT, say, which sends
        // it to a sector bitmap a fixed image never wrote.
        let state_field = entry & BAT_ENTRY_STATE_MASK;
        assert!(
            state_field == 0 || state_field == PAYLOAD_BLOCK_ZERO
                || state_field == PAYLOAD_BLOCK_FULLY_PRESENT,
            "entry {} ({:#x}) has state {}, which is none of 0, {} or {}",
            index, entry, state_field, PAYLOAD_BLOCK_ZERO, PAYLOAD_BLOCK_FULLY_PRESENT
        );

        // Invariant 3: a padding or sector-bitmap index is zero.
        //
        // Padding is past the last entry the image needs; a
        // sector-bitmap slot is the last index of each group of
        // `chunk_ratio + 1`, and an image with no parent never reads
        // one, so qemu leaves both at zero. What breaking this looks
        // like: an entry pointing at a sector bitmap block that was
        // never allocated, so a reader that does consult the bitmap
        // reads whatever is at that offset; or padding a reader takes
        // for a block the image does not have.
        let position_in_group = index.checked_rem(group).expect("group size is non-zero");
        if index >= bat_entries || position_in_group == chunk_ratio {
            let what = if index >= bat_entries {
                "padding past the entry count"
            } else {
                "a sector-bitmap slot"
            };
            assert_eq!(
                entry, 0,
                "entry {} is {} and is {:#x}, not zero",
                index, what, entry
            );
            continue;
        }

        let payload_block = index
            .checked_div(group)
            .and_then(|groups_before| index.checked_sub(groups_before))
            .expect("payload block number underflows");

        match state {
            FixedBlockState::Zero => {
                // Invariant 4, the `block_state_zero` half: the entry is
                // PAYLOAD_BLOCK_ZERO and names no offset. qemu forces
                // the offset to zero on a ZERO entry because Hyper-V
                // refuses one that names a file offset. What breaking
                // this looks like: an image Hyper-V will not open, for
                // a block that holds nothing.
                assert_eq!(
                    entry, PAYLOAD_BLOCK_ZERO,
                    "entry {} for payload block {} is {:#x}, not PAYLOAD_BLOCK_ZERO with a \
                     zero offset",
                    index, payload_block, entry
                );
                continue;
            }
            FixedBlockState::FullyPresent => {
                // Invariant 4: a payload entry carries the state the
                // call asked for. What breaking this looks like: a
                // fixed image whose blocks are all declared absent, so
                // every read returns zeros from a file that holds the
                // data.
                assert_eq!(
                    state_field, PAYLOAD_BLOCK_FULLY_PRESENT,
                    "entry {} for payload block {} has state {}, not \
                     PAYLOAD_BLOCK_FULLY_PRESENT",
                    index, payload_block, state_field
                );
            }
        }

        // Invariant 5: the offset the entry encodes is a whole number
        // of MiB.
        //
        // Asserted on the entry's bits above the state field rather
        // than on the decoded offset, because the offset field is
        // FileOffsetMB: the decode masks a misaligned low word away, so
        // the decoded value is aligned whatever was put in and only
        // these bits still show the mistake. What breaking this looks
        // like: an image whose blocks are all one sector away from
        // where their entries say, which reads as corruption rather
        // than as a bad offset.
        let encoded_offset = entry & !BAT_ENTRY_STATE_MASK;
        assert_eq!(
            encoded_offset % MB_ALIGN, 0,
            "entry {} ({:#x}) encodes offset {:#x}, not a whole number of MiB",
            index, entry, encoded_offset
        );

        // Invariant 6: payload offsets strictly increase with the
        // index. A fixed image's blocks are laid down in order from the
        // first, so two entries sharing an offset have two blocks on
        // top of each other and a descending pair has the file laid out
        // backwards.
        let offset = entry & BAT_ENTRY_OFFSET_MASK;
        if let Some(prev) = previous_offset {
            assert!(
                offset > prev,
                "entry {} for payload block {} has offset {}, not above the previous \
                 entry's {}",
                index, payload_block, offset, prev
            );
        }
        previous_offset = Some(offset);

        // Invariant 7: the offset is the one qemu's forward map gives
        // this block.
        //
        // qemu's fixed writer places payload block p at
        // `data_file_offset + p * block_size` and reaches it through BAT
        // index `p + p / chunk_ratio` (`vhdx_create_bat` and
        // `vhdx_block_translate`, `block/vhdx.c`, qemu 7.0.0). Inverted
        // here from the index, independently of the filler's own
        // arithmetic, so a map that is right about its shape and wrong
        // about which block an index belongs to is still caught. What
        // breaking this looks like: an image whose blocks are all
        // present and all in the wrong order, which reads as data from
        // somewhere else in the disk.
        let expected = payload_block
            .checked_mul(block_size)
            .and_then(|bytes| bytes.checked_add(layout.fixed_data_start))
            .expect("expected offset overflows u64");
        assert_eq!(
            offset, expected,
            "entry {} for payload block {} names offset {}, not {} ({} + {} * {})",
            index, payload_block, offset, expected, layout.fixed_data_start, payload_block,
            block_size
        );
    }
}
