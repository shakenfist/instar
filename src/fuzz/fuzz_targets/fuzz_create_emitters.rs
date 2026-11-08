//! Coverage-guided fuzzing for the `crates/create/` emitters.
//!
//! Decodes a 24-byte structured header into a `(format_selector,
//! virtual_size, options, backing)` tuple and dispatches to one of
//! the four `plan_*` functions (`plan_qcow2`, `plan_vmdk`,
//! `plan_vhd`, `plan_vhdx`). On every successful return, asserts a
//! set of structural invariants on the produced `MetadataPlan`:
//!
//!   1. total_metadata_bytes == sum of write byte lengths
//!   2. every write fits within plan.minimum_file_size
//!   3. total_metadata_bytes + minimum_file_size doesn't overflow
//!   4. write count <= MAX_METADATA_WRITES
//!   5. no two writes overlap
//!
//! A fixed VHDX plan carries a BAT the planner does not emit as a
//! write -- it can be 513 MiB at the 64 TiB ceiling, so the caller
//! streams it through `vhdx::fill_fixed_bat`. The harness streams a
//! bounded window of it and asserts five more invariants over the
//! entries (6 to 10); a dynamic plan carries no BAT and reaches none
//! of them.
//!
//! Errors (`InvalidVirtualSize`, `InvalidClusterSize`,
//! `InvalidBlockSize`, `InvalidGrainSize`, `InvalidSubformat`,
//! `BackingFileTooLong`, `BackingFileUnsupported`, `Overflow`,
//! `ScratchTooSmall`, `PreallocationUnsupported`) are silently
//! ignored; libFuzzer's only oracle is panic.
//!
//! A header re-parse round-trip is layered on top: when the
//! plan's `minimum_file_size` fits within `REPARSE_BUFFER_CAP`
//! (16 MiB), the harness assembles the emitted writes into a
//! contiguous buffer and re-parses the relevant header slice with
//! the matching parser crate (`qcow2::QcowHeader`, `vmdk::Vmdk4Header`,
//! `vhd::VhdFooter`, `vhdx::VhdxHeader`). Validates that:
//!   - the parser recognises the bytes the planner emitted
//!   - the parser-reported virtual_size / current_size matches
//!     the planner's input (where the header surfaces it).

#![no_main]
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;

use create::{
    plan_qcow2, plan_vhd, plan_vhdx, plan_vmdk, BackingRef, CreateError,
    FixedVhdxPlan, MetadataPlan, Qcow2CreateOpts, VhdCreateOpts, VhdSubformat, VhdxCreateOpts,
    VhdxSubformat, VmdkCreateOpts, VmdkSubformat, MAX_METADATA_WRITES, QCOW2_MAX_METADATA_SCRATCH,
};
use shared::ImageFormat;
use vhdx::{
    FixedBlockState, BAT_ENTRY_OFFSET_MASK, BAT_ENTRY_STATE_MASK, MB_ALIGN,
    PAYLOAD_BLOCK_FULLY_PRESENT, PAYLOAD_BLOCK_ZERO,
};

const HEADER_BYTES: usize = 24;

/// Maximum `plan.minimum_file_size` for which the harness assembles
/// the emitted writes and runs the re-parse round-trip. Above this
/// cap the re-parse step is skipped (the plan-level invariants
/// still hold). 16 MiB comfortably covers qcow2 / vmdk / vhd / vhdx
/// images up to ~1 GiB virtual; larger virtual_size values are
/// typically the fuzzer probing extreme inputs where re-parse
/// coverage saturates anyway.
const REPARSE_BUFFER_CAP: u64 = 16 * 1024 * 1024;

thread_local! {
    /// Reusable scratch buffer for plan_*. Sized to the largest
    /// per-format worst case (qcow2 = 32 MiB) so every plan_* call
    /// can share the same allocation.
    static SCRATCH: RefCell<Vec<u8>> =
        RefCell::new(vec![0u8; QCOW2_MAX_METADATA_SCRATCH]);

    /// Reusable buffer for re-parse assembly. Grown on demand up to
    /// `REPARSE_BUFFER_CAP`; cleared (not freed) between iterations.
    static REPARSE: RefCell<Vec<u8>> = RefCell::new(Vec::new());

    /// Reusable buffer for one window of a fixed image's BAT. Fixed
    /// to `BAT_WINDOW_ENTRIES` entries, which every legal BAT region
    /// holds, so it is never resized.
    static BAT_WINDOW: RefCell<Vec<u8>> =
        RefCell::new(vec![0u8; (BAT_WINDOW_ENTRIES * BAT_ENTRY_LEN) as usize]);
}

/// Bytes per BAT entry.
const BAT_ENTRY_LEN: u64 = 8;

/// BAT entries the harness fills and checks per window.
///
/// A fixed BAT runs to 513 MiB at the 64 TiB ceiling, so the harness
/// checks windows rather than the whole region. 8192 entries is chosen
/// to clear the largest `chunk_ratio` a legal layout produces (4096, at
/// a 1 MiB block size), so a window starting at entry 0 always contains
/// at least one sector-bitmap slot. It is also well inside the smallest
/// BAT region the layout ever declares -- 1 MiB, which is 131072
/// entries -- so a window never runs past the region.
const BAT_WINDOW_ENTRIES: u64 = 8192;

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_BYTES {
        return;
    }

    let target_sel = data[0] % 4;
    let rcb_sel = data[1] % 8;
    let flag_bits = data[2];
    let prealloc_sel = data[3] % 4;
    let vmdk_sub = data[4] % 5;
    let vhd_sub = data[5] % 2;
    let backing_flag = data[6];
    let backing_path_len_sel = data[7];
    let virtual_size = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let unit_size = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let parent_cid_raw = u32::from_le_bytes(data[20..24].try_into().unwrap());
    // Reuse the tail of the structured header as a VHD parent unique id;
    // the fuzz header has no dedicated field and adding one would shift
    // every existing corpus entry.
    let vhd_parent_id: [u8; 16] = data[8..24].try_into().unwrap();

    let refcount_bits: u8 = match rcb_sel {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        5 => 32,
        6 => 64,
        _ => 0xff, // invalid — exercises the InvalidOption path
    };
    let preallocation = match prealloc_sel {
        1 => qcow2::create::Preallocation::Metadata,
        2 => qcow2::create::Preallocation::Falloc,
        3 => qcow2::create::Preallocation::Full,
        _ => qcow2::create::Preallocation::Off,
    };
    let vmdk_subformat = match vmdk_sub {
        1 => VmdkSubformat::StreamOptimized,
        2 => VmdkSubformat::MonolithicFlat,
        3 => VmdkSubformat::TwoGbMaxExtentSparse,
        4 => VmdkSubformat::TwoGbMaxExtentFlat,
        _ => VmdkSubformat::MonolithicSparse,
    };
    let vhd_subformat = if vhd_sub == 1 {
        VhdSubformat::Fixed
    } else {
        VhdSubformat::Dynamic
    };
    // The VHDX subformat and `block_state_zero` ride in two spare bits
    // of `flag_bits` rather than in header bytes of their own: only the
    // qcow2 arm reads that byte and it reads bits 0 to 2, and adding a
    // 25th header byte would move where the backing path starts and so
    // change what every existing corpus entry means. The fuzzer flips
    // these bits as freely as any others, so nothing is lost by
    // sharing the byte.
    let vhdx_subformat = if flag_bits & 8 != 0 {
        VhdxSubformat::Fixed
    } else {
        VhdxSubformat::Dynamic
    };
    let vhdx_block_state_zero = flag_bits & 16 != 0;

    // Backing-path slice. The selector byte maps 0..=127 to 0..=127
    // bytes of path; 128 maps to MAX_BACKING_FILE_LEN (1024) to land
    // on the boundary; 129..=255 maps to 1025 to exercise the
    // BackingFileTooLong rejection.
    let backing_present = backing_flag & 1 != 0;
    let path_len = match backing_path_len_sel {
        0..=127 => backing_path_len_sel as usize,
        128 => 1024,
        _ => 1025,
    };
    let path_bytes_avail = data.len().saturating_sub(HEADER_BYTES);
    let path_len = path_len.min(path_bytes_avail);
    let backing_path = &data[HEADER_BYTES..HEADER_BYTES + path_len];

    let backing_format = if backing_flag & 2 != 0 {
        match (backing_flag >> 4) % 6 {
            0 => Some(ImageFormat::Raw),
            1 => Some(ImageFormat::Qcow2),
            2 => Some(ImageFormat::Vmdk4),
            3 => Some(ImageFormat::Vhd),
            4 => Some(ImageFormat::Vhdx),
            _ => None,
        }
    } else {
        None
    };
    let backing = if backing_present {
        Some(BackingRef { path: backing_path, format: backing_format })
    } else {
        None
    };

    SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        // What `plan_vhdx` returns beside the metadata writes, for a
        // fixed image: the layout, the block state and the file length
        // its BAT must be filled from. `None` for every other target
        // and for a dynamic VHDX.
        let mut fixed_vhdx: Option<FixedVhdxPlan> = None;
        let result: Result<MetadataPlan, CreateError> = match target_sel {
            0 => {
                let opts = Qcow2CreateOpts {
                    virtual_size,
                    cluster_size: unit_size,
                    refcount_bits,
                    extended_l2: flag_bits & 1 != 0,
                    lazy_refcounts: flag_bits & 2 != 0,
                    compat_v3: flag_bits & 4 != 0,
                    backing,
                    preallocation,
                };
                plan_qcow2(&opts, &mut scratch)
            }
            1 => {
                let parent_cid = if parent_cid_raw == 0 {
                    None
                } else {
                    Some(parent_cid_raw)
                };
                let opts = VmdkCreateOpts {
                    virtual_size,
                    subformat: vmdk_subformat,
                    grain_size: unit_size,
                    backing,
                    parent_cid,
                };
                plan_vmdk(&opts, &mut scratch)
            }
            2 => {
                let opts = VhdCreateOpts {
                    virtual_size,
                    subformat: vhd_subformat,
                    block_size: unit_size,
                    backing,
                    // Parent identity for a differencing child. Neither
                    // value affects the layout, but feeding structured
                    // bytes rather than a constant keeps the emitted
                    // header varying with the corpus.
                    parent_unique_id: vhd_parent_id,
                    parent_timestamp: parent_cid_raw,
                };
                plan_vhd(&opts, &mut scratch)
            }
            _ => {
                let opts = VhdxCreateOpts {
                    virtual_size,
                    block_size: unit_size,
                    // Both subformats, and both block states a fixed
                    // image can carry: `PAYLOAD_BLOCK_ZERO` entries
                    // with no offset when `block_state_zero` is on, and
                    // `PAYLOAD_BLOCK_FULLY_PRESENT` entries naming
                    // their block when it is off. A dynamic image
                    // ignores the flag and keeps its BAT a hole.
                    subformat: vhdx_subformat,
                    block_state_zero: vhdx_block_state_zero,
                    backing,
                    // Parent identity for a differencing child. It does
                    // not affect the layout, but feeding structured
                    // bytes rather than a constant keeps the emitted
                    // locator varying with the corpus — the same reason
                    // the VHD arm above feeds `vhd_parent_id`.
                    parent_data_write_guid: vhd_parent_id,
                };
                plan_vhdx(&opts, &mut scratch).map(|plan| {
                    fixed_vhdx = plan.fixed;
                    plan.metadata
                })
            }
        };

        if let Ok(plan) = result {
            assert_invariants(&plan, target_sel, fixed_vhdx.as_ref());
            if plan.minimum_file_size <= REPARSE_BUFFER_CAP {
                assert_reparse(&plan, target_sel, virtual_size);
            }
        }
    });
});

fn assert_invariants(
    plan: &MetadataPlan<'_>,
    target_sel: u8,
    fixed_vhdx: Option<&FixedVhdxPlan>,
) {
    // Invariant 1: bookkeeping consistency.
    let sum: u64 = plan.writes().iter().map(|w| w.bytes.len() as u64).sum();
    assert_eq!(
        plan.total_metadata_bytes, sum,
        "target {}: total_metadata_bytes ({}) != sum of write lengths ({})",
        target_sel, plan.total_metadata_bytes, sum
    );

    // Invariant 2: every write fits in minimum_file_size.
    for (i, w) in plan.writes().iter().enumerate() {
        let end = w
            .byte_offset
            .checked_add(w.bytes.len() as u64)
            .expect("write end overflows u64");
        assert!(
            end <= plan.minimum_file_size,
            "target {} write {}: end ({}) > minimum_file_size ({})",
            target_sel, i, end, plan.minimum_file_size
        );
    }

    // Invariant 3: total_metadata_bytes + minimum_file_size doesn't overflow.
    assert!(
        plan.total_metadata_bytes
            .checked_add(plan.minimum_file_size)
            .is_some(),
        "target {}: total + minimum_file_size overflows u64",
        target_sel
    );

    // Invariant 4: write count bound.
    assert!(
        plan.writes().len() <= MAX_METADATA_WRITES,
        "target {}: write count ({}) > MAX_METADATA_WRITES ({})",
        target_sel,
        plan.writes().len(),
        MAX_METADATA_WRITES
    );

    // Invariant 5: no two writes overlap.
    //
    // A plan whose regions overlap silently writes one structure over
    // another -- the failure mode a layout change introduces, where
    // every other invariant here still holds because the bookkeeping is
    // self-consistent. It matters most for the newest layout: a
    // differencing VHD inserts a locator region between the dynamic
    // header and the BAT, and getting that offset wrong lands it on one
    // of them.
    let mut spans: Vec<(u64, u64)> = plan
        .writes()
        .iter()
        .map(|w| (w.byte_offset, w.byte_offset + w.bytes.len() as u64))
        .collect();
    spans.sort_unstable();
    for pair in spans.windows(2) {
        assert!(
            pair[0].1 <= pair[1].0,
            "target {}: writes overlap -- [{}, {}) and [{}, {})",
            target_sel, pair[0].0, pair[0].1, pair[1].0, pair[1].1
        );
    }

    // Invariants 6 to 10 are about the BAT, which only a fixed VHDX
    // plan has. Every other plan -- including a dynamic VHDX, whose BAT
    // region stays a sparse hole the planner never writes -- returns
    // here.
    if let Some(fixed) = fixed_vhdx {
        assert_fixed_bat(fixed);
    }
}

/// Invariants 6 to 10: a fixed VHDX's block allocation table.
///
/// The BAT is not among the plan's writes, because at the 64 TiB
/// ceiling it is 513 MiB and the planner is given a bounded scratch
/// buffer. The caller streams it instead, through
/// `vhdx::fill_fixed_bat`, and that is what the harness does here: it
/// fills a window at entry 0 and a window straddling the last entry
/// the image needs, which between them cover the first sector-bitmap
/// slot, the smallest and largest payload offsets, and the boundary
/// where entries give way to padding.
fn assert_fixed_bat(fixed: &FixedVhdxPlan) {
    let layout = &fixed.layout;
    let payload_blocks = u64::from(layout.payload_blocks);
    let chunk_ratio = u64::from(layout.chunk_ratio);

    // Invariant 6: the entry count is the one the layout's own block
    // count and chunk ratio imply.
    //
    // SPEC(VHDX) 2.5 for an image with no parent -- the only kind a
    // fixed VHDX can be, since the planner refuses a fixed image with a
    // backing file: one entry per payload block, plus one sector-bitmap
    // entry for each whole group of `chunk_ratio` payload blocks that
    // has another payload block after it. Computed here from
    // `payload_blocks` and `chunk_ratio` rather than by calling the
    // crate's counter, so that a counter which is off by one is a
    // divergence the harness can see rather than one it reproduces.
    // What breaking this looks like: a BAT one entry longer than the
    // region table declares, which a conforming reader refuses
    // outright, or one entry shorter, which loses the last block.
    assert!(
        chunk_ratio != 0,
        "fixed vhdx: layout declares a zero chunk ratio, which no reader accepts"
    );
    let expected_entries = if payload_blocks == 0 {
        0
    } else {
        payload_blocks
            .checked_sub(1)
            .and_then(|n| n.checked_div(chunk_ratio))
            .and_then(|sb| payload_blocks.checked_add(sb))
            .expect("fixed vhdx: expected BAT entry count overflows u64")
    };
    assert_eq!(
        u64::from(layout.bat_entries), expected_entries,
        "fixed vhdx: layout declares {} BAT entries, but {} payload blocks at a \
         chunk ratio of {} imply {}",
        layout.bat_entries, payload_blocks, chunk_ratio, expected_entries
    );

    // The BAT region is never shorter than 1 MiB, so it always holds a
    // whole window; a layout that says otherwise is a layout bug and
    // the windows below would be the wrong thing to report it with.
    let capacity = u64::from(layout.bat_region_len) / BAT_ENTRY_LEN;
    assert!(
        capacity >= BAT_WINDOW_ENTRIES,
        "fixed vhdx: BAT region of {} bytes holds fewer than {} entries",
        layout.bat_region_len, BAT_WINDOW_ENTRIES
    );

    // Two windows: the start of the region, and one placed so that the
    // last entry the image needs falls in its middle. The second is the
    // only one that sees the entry-to-padding boundary, and for a BAT
    // shorter than half a window it is the first one again.
    let tail_start = u64::from(layout.bat_entries)
        .saturating_sub(BAT_WINDOW_ENTRIES / 2)
        .min(capacity - BAT_WINDOW_ENTRIES);
    assert_bat_window(fixed, 0);
    if tail_start != 0 {
        assert_bat_window(fixed, tail_start);
    }
}

/// Fill one window of a fixed image's BAT and check invariants 7 to 10
/// over its entries.
fn assert_bat_window(fixed: &FixedVhdxPlan, first_entry: u64) {
    let layout = &fixed.layout;
    let chunk_ratio = u64::from(layout.chunk_ratio);
    let group = chunk_ratio
        .checked_add(1)
        .expect("fixed vhdx: chunk ratio + 1 overflows u64");
    let bat_entries = u64::from(layout.bat_entries);

    BAT_WINDOW.with(|cell| {
        let mut buf = cell.borrow_mut();
        // The window was placed inside the region the layout declares
        // and the buffer is a whole number of entries, so every reason
        // the filler refuses has been ruled out; a refusal here means
        // the filler and the layout disagree about the region.
        vhdx::fill_fixed_bat(layout, fixed.state, first_entry, &mut buf).unwrap_or_else(|e| {
            panic!(
                "fixed vhdx: fill_fixed_bat refused {:?} for {} entries from {} in a \
                 {}-byte BAT region",
                e, BAT_WINDOW_ENTRIES, first_entry, layout.bat_region_len
            )
        });

        let mut previous_offset: Option<u64> = None;
        for (slot, index) in buf.chunks_exact(BAT_ENTRY_LEN as usize).zip(first_entry..) {
            let entry = u64::from_le_bytes(slot.try_into().expect("8-byte chunk"));
            if index >= bat_entries {
                // Padding past the last entry the image needs. qemu
                // leaves it zero and so does the filler, but the region
                // is allowed to be a hole, so there is nothing here the
                // harness can hold the filler to.
                continue;
            }
            let position_in_group = index
                .checked_rem(group)
                .expect("fixed vhdx: group size is non-zero");
            if position_in_group == chunk_ratio {
                // Invariant 10: a sector-bitmap slot is zero.
                //
                // An image with no parent never reads its sector
                // bitmaps, and qemu never writes them for a fixed
                // image: it fills the BAT one payload block at a time
                // and the slot after each group is simply skipped. What
                // breaking this looks like: an entry pointing at a
                // sector-bitmap block that was never allocated, so a
                // reader that does consult the bitmap reads whatever
                // happens to be at that offset.
                assert_eq!(
                    entry, 0,
                    "fixed vhdx: sector-bitmap slot at index {} is {:#x}, not zero",
                    index, entry
                );
                continue;
            }

            let payload_block = index
                .checked_div(group)
                .and_then(|groups_before| index.checked_sub(groups_before))
                .expect("fixed vhdx: payload block number underflows");
            let encoded_offset = entry & !BAT_ENTRY_STATE_MASK;
            let offset = entry & BAT_ENTRY_OFFSET_MASK;
            let state = entry & BAT_ENTRY_STATE_MASK;

            // Invariant 9: the offset an entry encodes is a whole
            // number of MiB.
            //
            // Asserted on the entry's bits rather than on the decoded
            // offset, because the offset field is FileOffsetMB: the
            // decode shifts a misaligned low word away, so the decoded
            // value is aligned whatever was put in and only the bits
            // between the state field and FileOffsetMB still show the
            // mistake. What breaking this looks like: an image whose
            // blocks are all one sector away from where their entries
            // say, which reads as corruption rather than as a bad
            // offset.
            assert_eq!(
                encoded_offset % MB_ALIGN, 0,
                "fixed vhdx: entry {} ({:#x}) encodes offset {:#x}, not a whole number of MiB",
                index, entry, encoded_offset
            );

            match fixed.state {
                FixedBlockState::Zero => {
                    // Invariant 7, the `block_state_zero` half: the
                    // entry is PAYLOAD_BLOCK_ZERO and names no offset.
                    // qemu forces the offset to zero on a ZERO entry
                    // because Hyper-V refuses one that names a file
                    // offset. What breaking this looks like: an image
                    // Hyper-V will not open, for a block that holds
                    // nothing.
                    assert_eq!(
                        entry, PAYLOAD_BLOCK_ZERO,
                        "fixed vhdx: entry {} for payload block {} is {:#x}, not \
                         PAYLOAD_BLOCK_ZERO with a zero offset",
                        index, payload_block, entry
                    );
                }
                FixedBlockState::FullyPresent => {
                    // Invariant 7: a payload entry is FULLY_PRESENT and
                    // its offset is inside the payload region -- at or
                    // after the first block's place, and before the
                    // length the file is extended to. The last block
                    // may extend past that length, which is why the
                    // bound is on the offset and not on its end: a
                    // virtual size that ends inside a block is not
                    // padded out.
                    //
                    // What breaking this looks like: a well-formed
                    // image whose blocks are somewhere other than where
                    // qemu puts them -- over the metadata region if the
                    // offset is too low, or past the end of the file if
                    // it is too high, which reads as zeros.
                    assert_eq!(
                        state, PAYLOAD_BLOCK_FULLY_PRESENT,
                        "fixed vhdx: entry {} for payload block {} has state {}, not \
                         PAYLOAD_BLOCK_FULLY_PRESENT",
                        index, payload_block, state
                    );
                    assert!(
                        offset >= layout.fixed_data_start && offset < fixed.file_length,
                        "fixed vhdx: entry {} for payload block {} has offset {}, outside \
                         the payload region [{}, {})",
                        index, payload_block, offset, layout.fixed_data_start,
                        fixed.file_length
                    );

                    // Invariant 8: offsets strictly increase with the
                    // index, within the window. A fixed image's blocks
                    // are laid down in order from the first, so two
                    // entries that share an offset have two blocks on
                    // top of each other and a descending pair has the
                    // file laid out backwards. Monotonicity across the
                    // whole BAT follows from each entry being a
                    // function of its index alone, which the filler's
                    // buffer-size independence pins; the harness checks
                    // it where it can see two entries at once.
                    if let Some(prev) = previous_offset {
                        assert!(
                            offset > prev,
                            "fixed vhdx: entry {} for payload block {} has offset {}, not \
                             above the previous entry's {}",
                            index, payload_block, offset, prev
                        );
                    }
                    previous_offset = Some(offset);
                }
            }
        }
    });
}

/// Each format rounds an arbitrary input virtual_size up to its
/// own alignment boundary (cluster_size / grain_size / sector /
/// block_size). The planner records the rounded value in the
/// header, so the re-parse must accept any rounded-up value
/// within a generous bound rather than demanding strict equality.
///
/// The largest legal block_size across all formats is 256 MiB
/// (vhd / vhdx); add a comfortable margin for any future
/// geometry-rounding to keep the assertion stable. A genuine
/// endianness / offset bug would produce a wildly mismatched
/// value (orders of magnitude off), so this loose bound still
/// catches the real failure modes.
const VIRTUAL_SIZE_ROUNDUP_BOUND: u64 = 512 * 1024 * 1024;

fn assert_virtual_size_rounded_up(label: &str, parsed: u64, requested: u64) {
    assert!(
        parsed >= requested,
        "{}: parsed virtual_size {} < requested {}",
        label, parsed, requested
    );
    assert!(
        parsed - requested < VIRTUAL_SIZE_ROUNDUP_BOUND,
        "{}: parsed virtual_size {} rounded up by {} bytes from {} \
         (exceeds {} bound)",
        label,
        parsed,
        parsed - requested,
        requested,
        VIRTUAL_SIZE_ROUNDUP_BOUND
    );
}

/// Header re-parse round-trip: assemble the emitted bytes into a
/// contiguous buffer and re-parse with the matching format's
/// first-stage parser. Not one of the numbered invariants -- it is a
/// second oracle over the same plan.
fn assert_reparse(plan: &MetadataPlan<'_>, target_sel: u8, virtual_size: u64) {
    let size = plan.minimum_file_size as usize;
    REPARSE.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        buf.resize(size, 0u8);
        for w in plan.writes() {
            let start = w.byte_offset as usize;
            let end = start + w.bytes.len();
            buf[start..end].copy_from_slice(w.bytes);
        }
        match target_sel {
            0 => {
                let header = qcow2::QcowHeader::parse(&buf[..size.min(512)])
                    .expect("qcow2 emitter produced unparseable header");
                assert_virtual_size_rounded_up(
                    "qcow2", header.virtual_size, virtual_size);
            }
            1 => {
                let header = vmdk::Vmdk4Header::parse(&buf[..size.min(512)])
                    .expect("vmdk emitter produced unparseable header");
                assert_virtual_size_rounded_up(
                    "vmdk", header.virtual_size, virtual_size);
            }
            2 => {
                // VHD footer lives in the last 512 bytes of the file.
                let footer = vhd::VhdFooter::parse(&buf[size - 512..])
                    .expect("vhd emitter produced unparseable footer");
                assert_virtual_size_rounded_up(
                    "vhd", footer.current_size, virtual_size);
            }
            _ => {
                // VHDX Header 1 lives at file offset 64 KiB; the parser
                // wants a 4 KiB window of context for the CRC validation.
                let hdr_start = 64 * 1024;
                let hdr_end = hdr_start + 4096;
                assert!(
                    hdr_end <= size,
                    "vhdx minimum_file_size ({}) below header end ({})",
                    size, hdr_end
                );
                vhdx::VhdxHeader::parse(&buf[hdr_start..hdr_end])
                    .expect("vhdx emitter produced unparseable header");
                // VHDX virtual_size lives in the metadata region, not the
                // header itself; deeper validation needs a CallTable walk
                // and is left to fuzz_vhdx_metadata.
            }
        }
    });
}
