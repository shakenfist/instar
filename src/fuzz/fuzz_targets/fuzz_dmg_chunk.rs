#![no_main]
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;

use shared::{write_be_u32, write_be_u64};

// Arm-level structured harness (companion to fuzz_dmg_table's fully-raw
// approach): a small fixed-size prefix picks a chunk-table SHAPE (path,
// chunk count, per-chunk type/gap/size), which is then encoded into a
// real, well-formed koly + plist(-or-resource-fork) + mish device image
// and parsed via DmgState::init -- mirroring fuzz_amend_planners' "decode
// a structured prefix, then stamp a mostly-valid structure from the
// remaining pool" idiom. Because the shape is constructed to be sorted,
// non-overlapping, and koly-consistent by construction, most inputs reach
// DmgState::init's Ok path, so libFuzzer's mutation budget goes toward
// exploring chunk_lookup's binary search -- exact chunk boundaries,
// adjacent chunks, and tail gaps -- far more densely than random raw
// bytes could reliably reach. fuzz_dmg_table already owns the
// koly/plist-scanner/lenient-base64 malformation surface; this target's
// job is lookup/binary-search edge coverage plus the instar-specific
// staging caps (DMG_MAX_STAGED_SECTOR_COUNT / COMPRESSED_BUF_SIZE), which
// the per-chunk size ranges below are centred on.
thread_local! {
    // See fuzz_dmg_table.rs for why this buffer is thread-local rather
    // than allocated per iteration.
    static SCRATCH: RefCell<Vec<u8>> = RefCell::new(vec![0u8; dmg::DMG_REQUIRED_SCRATCH]);
}

/// Number of chunk-table slots the structured prefix encodes.
const MAX_SLOTS: usize = 8;
/// Per-slot structured bytes: type selector, gap selector, sector-count
/// lo/hi (u16 LE), comp-len lo/hi (u16 LE).
const PER_SLOT: usize = 6;
/// path-selector byte + slot-count byte, then `MAX_SLOTS * PER_SLOT`.
const PREFIX_BYTES: usize = 2 + MAX_SLOTS * PER_SLOT;

fuzz_target!(|data: &[u8]| {
    if data.len() < PREFIX_BYTES {
        return;
    }

    let use_rsrc_fork = data[0] % 5 == 0; // ~20%, exercising both table paths
    let num_slots = 1 + (data[1] as usize % MAX_SLOTS);

    let mut next_sector = 0u64;
    let mut mish_entries: Vec<(u32, u64, u64, u64, u64)> = Vec::new();
    // (first_sector, sector_count) for chunks DmgState actually keeps --
    // used below to derive dense boundary-lookup sectors after init.
    let mut kept_chunks: Vec<(u64, u64)> = Vec::new();

    for i in 0..num_slots {
        let base = 2 + i * PER_SLOT;
        let slot = &data[base..base + PER_SLOT];
        let type_byte = slot[0];
        let gap_byte = slot[1];
        let size_u16 = u16::from_le_bytes([slot[2], slot[3]]);
        let complen_u16 = u16::from_le_bytes([slot[4], slot[5]]);

        // Gap before this chunk: mostly 0..2 (adjacency / exact-boundary
        // heavy) with an occasional larger gap for tail/mid-table Gap
        // coverage.
        let gap = if gap_byte >= 250 { 64 } else { (gap_byte % 3) as u64 };

        let kind_selector = type_byte % 8;
        let (kept, ctype) = match kind_selector {
            0 | 1 => (true, dmg::CHUNK_ZERO),
            2 => (true, dmg::CHUNK_IGNORE),
            3 | 4 => (true, dmg::CHUNK_RAW),
            5 | 6 => (true, dmg::CHUNK_ZLIB),
            // The remaining 1/8: comment, terminator, or an unsupported
            // codec (ADC) -- all dropped/refused without contributing a
            // kept chunk. An unsupported codec aborts the rest of init
            // (parse_mish_block returns Err on the first unsupported
            // entry it sees, per the crate docs) -- a real, useful
            // outcome to fuzz too, just not one this target walks
            // lookups after (state is simply None that iteration).
            _ => {
                let dropped = match (type_byte / 8) % 3 {
                    0 => dmg::CHUNK_COMMENT,
                    1 => dmg::CHUNK_TERMINATOR,
                    _ => dmg::CHUNK_ADC,
                };
                (false, dropped)
            }
        };

        if !kept {
            mish_entries.push((ctype, 0, 0, 0, 0));
            continue;
        }

        let is_zeroish = ctype == dmg::CHUNK_ZERO || ctype == dmg::CHUNK_IGNORE;
        // Sector count: dense around instar's DMG_MAX_STAGED_SECTOR_COUNT
        // (4096) for Raw/Zlib; zero/ignore are exempt from every cap, so
        // the same range just gives varied span widths for those.
        let sector_count = 1 + (size_u16 as u64 % 8192);
        // Compressed length: dense around COMPRESSED_BUF_SIZE (~2.06
        // MiB) for Raw/Zlib -- well under qemu's own 64 MiB cap (that
        // boundary is fuzz_dmg_table's job via raw bytes), so this
        // target concentrates on instar's tighter staging cap instead.
        let comp_len = if is_zeroish { 0 } else { complen_u16 as u64 * 40 };

        let first_sector = next_sector + gap;
        mish_entries.push((ctype, first_sector, sector_count, 0, comp_len));
        kept_chunks.push((first_sector, sector_count));
        next_sector = first_sector + sector_count;
    }

    // koly SectorCount: the mish coverage, plus an occasional tail gap
    // (dense Gap-at-end coverage) derived from a leftover fuzz byte.
    let tail_gap = data.get(PREFIX_BYTES).map(|b| (*b % 64) as u64).unwrap_or(0);
    let total_sectors = next_sector + tail_gap;

    let mish = build_mish(0, 0, &mish_entries);

    // ------------------------------------------------------------------
    // Assemble a real device image: [filler][xml-or-rsrc region][koly].
    // Any leftover fuzz bytes past the structured prefix become the
    // filler region's content -- the "rest is device content" split.
    // chunk_lookup never dereferences comp_offset/host_offset (that is
    // the reader arm's job, out of scope for this no_std crate), so the
    // filler bytes don't affect table shape; they just vary the bytes
    // preceding the region/koly, exercising the koly tail-scan window
    // over varied layouts.
    // ------------------------------------------------------------------
    let mut image: Vec<u8> = Vec::new();
    let filler_pool = data.get(PREFIX_BYTES..).unwrap_or(&[]);
    let mut filler: Vec<u8> = filler_pool.iter().copied().take(4096).collect();
    if filler.len() < 16 {
        filler.resize(16, 0);
    }
    image.extend_from_slice(&filler);

    let region_offset = image.len() as u64;
    let rsrc_fork_offset;
    let rsrc_fork_length;
    let xml_offset;
    let xml_length;
    if use_rsrc_fork {
        let mut r = Vec::new();
        r.extend_from_slice(&12u32.to_be_bytes()); // rsrc_data_offset
        r.extend_from_slice(&0u32.to_be_bytes()); // unused @4
        let count = 4 + mish.len();
        r.extend_from_slice(&(count as u32).to_be_bytes()); // @8 count
        r.extend_from_slice(&(mish.len() as u32).to_be_bytes()); // resource size
        r.extend_from_slice(&mish);
        rsrc_fork_offset = region_offset;
        rsrc_fork_length = r.len() as u64;
        xml_offset = 0;
        xml_length = 0;
        image.extend_from_slice(&r);
    } else {
        let mut x = Vec::new();
        x.extend_from_slice(b"<plist><data>");
        x.extend_from_slice(&base64_encode(&mish));
        x.extend_from_slice(b"</data></plist>");
        xml_offset = region_offset;
        xml_length = x.len() as u64;
        rsrc_fork_offset = 0;
        rsrc_fork_length = 0;
        image.extend_from_slice(&x);
    }

    let mut koly = [0u8; 512];
    koly[0..4].copy_from_slice(b"koly");
    write_be_u64(&mut koly, 0x18, 0); // DataForkOffset
    write_be_u64(&mut koly, 0x28, rsrc_fork_offset);
    write_be_u64(&mut koly, 0x30, rsrc_fork_length);
    write_be_u64(&mut koly, 0xd8, xml_offset);
    write_be_u64(&mut koly, 0xe0, xml_length);
    write_be_u64(&mut koly, 0x1ec, total_sectors);
    image.extend_from_slice(&koly);

    instar_fuzz::set_fuzz_input(&image);
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

            // A malformed shape (e.g. an unsupported-codec slot, or a
            // region that overflowed DMG_REGION_STAGE_CAP) is fine to
            // skip -- see the kind_selector comment above.
            let Ok(state) = state else {
                return;
            };

            // Dense boundary sweep: for every chunk we intended to keep,
            // sample just before it, at its start, mid-chunk, its last
            // sector, and just past its end (the adjacent chunk or a
            // gap) -- exactly the binary-search edges the plan calls
            // out.
            for &(start, count) in kept_chunks.iter() {
                let end = start + count;
                let mid = start + count / 2;
                for &sector in [start.saturating_sub(1), start, mid, end.saturating_sub(1), end].iter() {
                    check_lookup(state.chunk_lookup(sector));
                }
            }

            // The tail: sector 0, the last virtual sector, and one past
            // the koly-declared virtual end (the tail-gap path).
            let virtual_sectors = state.virtual_sectors;
            for &sector in [0u64, virtual_sectors.saturating_sub(1), virtual_sectors].iter() {
                check_lookup(state.chunk_lookup(sector));
            }
        }
    });
});

/// Build a 204-byte mish header (magic, out_offset, data_offset) followed
/// by 40-byte BE chunk entries. Mirrors `src/crates/dmg/src/tests.rs`'s
/// `build_mish` test helper (duplicated here rather than shared across
/// the crate boundary, since fuzz targets are independent binaries).
fn build_mish(out_offset: u64, data_offset: u64, entries: &[(u32, u64, u64, u64, u64)]) -> Vec<u8> {
    let mut b = vec![0u8; dmg::MISH_HEADER_LEN + entries.len() * dmg::MISH_ENTRY_LEN];
    write_be_u32(&mut b, 0, dmg::MISH_MAGIC);
    write_be_u64(&mut b, 8, out_offset);
    write_be_u64(&mut b, 0x18, data_offset);
    let mut off = dmg::MISH_HEADER_LEN;
    for &(ctype, sector, sector_count, comp_offset, comp_len) in entries {
        write_be_u32(&mut b, off, ctype);
        write_be_u64(&mut b, off + 8, sector);
        write_be_u64(&mut b, off + 0x10, sector_count);
        write_be_u64(&mut b, off + 0x18, comp_offset);
        write_be_u64(&mut b, off + 0x20, comp_len);
        off += dmg::MISH_ENTRY_LEN;
    }
    b
}

/// Standard base64 encoder (the crate's `glib_base64_decode` accepts the
/// standard alphabet, plus arbitrary junk between groups). Mirrors
/// `src/crates/dmg/src/tests.rs`'s `base64_encode` test helper.
fn base64_encode(data: &[u8]) -> Vec<u8> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((n >> 18) & 63) as usize]);
        out.push(ALPHA[((n >> 12) & 63) as usize]);
        out.push(if chunk.len() > 1 {
            ALPHA[((n >> 6) & 63) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 { ALPHA[(n & 63) as usize] } else { b'=' });
    }
    out
}

/// Assert the invariants a legal `chunk_lookup` result must satisfy,
/// regardless of which chunk kind (or gap) was hit. Identical to
/// fuzz_dmg_table's checker (duplicated -- fuzz targets are independent
/// binaries).
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
            assert!(comp_len <= dmg::DMG_LENGTHS_MAX);
            assert!(comp_len <= shared::COMPRESSED_BUF_SIZE as u64);
            assert!(chunk_sector_count <= dmg::DMG_MAX_STAGED_SECTOR_COUNT);
            assert!(host_offset.checked_add(comp_len).is_some());
        }
        dmg::DmgLookup::Gap { .. } => {}
    }
}
