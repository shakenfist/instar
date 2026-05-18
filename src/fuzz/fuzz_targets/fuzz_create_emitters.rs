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
//!
//! Errors (`InvalidVirtualSize`, `InvalidClusterSize`,
//! `InvalidBlockSize`, `InvalidGrainSize`, `InvalidSubformat`,
//! `BackingFileTooLong`, `BackingFileUnsupported`, `Overflow`,
//! `ScratchTooSmall`, `PreallocationUnsupported`) are silently
//! ignored; libFuzzer's only oracle is panic.
//!
//! Phase 9b layers a header re-parse round-trip on top: when the
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
    MetadataPlan, Qcow2CreateOpts, VhdCreateOpts, VhdSubformat, VhdxCreateOpts,
    VmdkCreateOpts, VmdkSubformat, MAX_METADATA_WRITES, QCOW2_MAX_METADATA_SCRATCH,
};
use shared::ImageFormat;

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
}

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
                };
                plan_vhd(&opts, &mut scratch)
            }
            _ => {
                let opts = VhdxCreateOpts {
                    virtual_size,
                    block_size: unit_size,
                    backing,
                };
                plan_vhdx(&opts, &mut scratch)
            }
        };

        if let Ok(plan) = result {
            assert_invariants(&plan, target_sel);
            if plan.minimum_file_size <= REPARSE_BUFFER_CAP {
                assert_reparse(&plan, target_sel, virtual_size);
            }
        }
    });
});

fn assert_invariants(plan: &MetadataPlan<'_>, target_sel: u8) {
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

/// Invariant 5: assemble the emitted bytes into a contiguous buffer
/// and re-parse with the matching format's first-stage parser.
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
