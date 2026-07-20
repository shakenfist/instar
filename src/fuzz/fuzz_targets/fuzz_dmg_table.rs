#![no_main]
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;

// The mock read_input_sector serves fuzz input bytes verbatim as the DMG
// device content, so every byte the koly-trailer tail scan, XML/resource-
// fork region staging, lenient base64 decode, and mish chunk-table parse
// touch is driven directly by the fuzz corpus -- mirroring
// fuzz_qcow1_table's "raw bytes are the device" approach (this is the
// priority surface per PLAN-format-coverage-phase-05-dmg-read.md's
// Fuzzing section: "the plist scanner and lenient base64 are the juicy
// attack surface"). DmgState::init's path selection is
// `RsrcForkLength != 0 -> resource-fork path` else `XMLLength != 0 ->
// plist path`, and both koly fields (bytes 0x30 and 0xE0 of the located
// trailer) come straight from fuzz bytes, so ordinary mutation naturally
// reaches BOTH table-build paths without any special seeding -- the same
// "both paths reachable by construction" property fuzz_qcow1_table notes
// for the Allocated/Compressed L2 decode.
thread_local! {
    // DmgState::init's scratch requirement (DMG_REQUIRED_SCRATCH, ~3.25
    // MiB: the persistent ~1.25 MiB chunk table plus 1 MiB plist/rsrc-fork
    // staging plus 1 MiB base64 decode buffer) is too large to allocate
    // fresh every iteration without hurting exec/s -- reuse one buffer per
    // fuzzer thread, mirroring fuzz_amend_planners'/fuzz_resize_planners'
    // SCRATCH idiom for the same reason.
    static SCRATCH: RefCell<Vec<u8>> = RefCell::new(vec![0u8; dmg::DMG_REQUIRED_SCRATCH]);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }

    instar_fuzz::set_fuzz_input(data);
    let call_table = instar_fuzz::build_call_table();
    let sector_size = 512;
    let input_capacity = instar_fuzz::input_capacity();

    let mut bytes_read = 0u64;

    SCRATCH.with(|s| {
        let mut scratch = s.borrow_mut();

        unsafe {
            let state = dmg::DmgState::init(
                &call_table,
                0,
                sector_size,
                input_capacity,
                scratch.as_mut_ptr(),
                scratch.len(),
                &mut bytes_read,
            );

            // Err covers every refusal path (missing/invalid trailer,
            // region caps, malformed XML/resource-fork, qemu/instar
            // per-chunk caps, unsupported codecs, empty table,
            // unsorted/overlapping) -- all of these are the common,
            // expected outcome for random bytes and are fine to skip
            // cleanly, the same posture as fuzz_qcow1_table's
            // `let Some(state) = state else { return };` gate.
            let Ok(state) = state else {
                return;
            };

            let virtual_sectors = state.virtual_sectors;

            // Fixed sectors: start, mid, and near the declared virtual
            // end.
            let sectors = [0u64, virtual_sectors / 2, virtual_sectors.saturating_sub(1)];

            for &sector in sectors.iter() {
                check_lookup(state.chunk_lookup(sector));
            }

            // Fuzz-derived sector for deeper exploration, including well
            // past virtual_sectors, to exercise the Gap tail-clamp path.
            if let Some(dynamic_sector) = instar_fuzz::extract_fuzz_offset(data) {
                check_lookup(state.chunk_lookup(dynamic_sector));
            }
        }
    });
});

/// Assert the invariants a legal `chunk_lookup` result must satisfy,
/// regardless of which chunk kind (or gap) was hit.
///
/// `Zero`/`Raw` hits only occur when the binary search lands inside a
/// chunk whose `sector_count > 0` (see `DmgState::chunk_lookup`'s
/// `sector < end` guard), so `span_sectors` is guaranteed nonzero for
/// those two variants. `Gap` has no such guarantee -- a fuzz-derived
/// sector far past `virtual_sectors` legitimately yields a zero-length
/// gap (the tail-clamp path), so it is intentionally not asserted here.
fn check_lookup(lookup: dmg::DmgLookup) {
    match lookup {
        dmg::DmgLookup::Zero { span_sectors } => {
            assert!(span_sectors > 0);
        }
        dmg::DmgLookup::Raw {
            host_offset,
            span_sectors,
        } => {
            assert!(span_sectors > 0);
            // The reader arm walks the span byte-by-byte from
            // host_offset; the whole span's end must not overflow u64.
            let span_bytes = span_sectors
                .checked_mul(512)
                .expect("span_sectors * 512 must not overflow for a legal chunk");
            assert!(host_offset.checked_add(span_bytes).is_some());
        }
        dmg::DmgLookup::Zlib {
            host_offset,
            comp_len,
            chunk_sector_count,
            ..
        } => {
            assert!(chunk_sector_count > 0);
            // qemu's own per-chunk cap (DMG_LENGTHS_MAX), enforced at
            // parse_mish_block time -- every kept Zlib chunk satisfies it.
            assert!(comp_len <= dmg::DMG_LENGTHS_MAX);
            // instar's tighter staged-read caps: a chunk kept in the
            // table with kind == Zlib was already checked against
            // COMPRESSED_BUF_SIZE and DMG_MAX_STAGED_SECTOR_COUNT at
            // init time (parse_mish_block's StagedChunkLengthTooLarge /
            // StagedSectorCountTooLarge refusals), so both must hold
            // here too.
            assert!(comp_len <= shared::COMPRESSED_BUF_SIZE as u64);
            assert!(chunk_sector_count <= dmg::DMG_MAX_STAGED_SECTOR_COUNT);
            // The reader arm reads comp_len bytes starting at
            // host_offset; that read window must not overflow u64.
            assert!(host_offset.checked_add(comp_len).is_some());
        }
        dmg::DmgLookup::Gap { .. } => {}
    }
}
