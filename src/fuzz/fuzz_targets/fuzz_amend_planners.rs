//! Coverage-guided fuzzing for the `crates/amend/` planner.
//!
//! Decodes a small fixed-size structured prefix into a
//! `(cluster_size, control-flags)` tuple, synthesises a header
//! cluster from the remaining fuzz bytes — stamping a valid qcow2
//! magic, a v2/v3 version, and a `cluster_bits` consistent with the
//! chosen `cluster_size` so the planner's `QcowHeader::parse`
//! frequently proceeds past `ParseFailed` into the interesting
//! compat / lazy / extension-relocation logic — and calls
//! `plan_amend_qcow2`. On every successful return, asserts plan-
//! level invariants:
//!
//!   1. `patches().len() <= MAX_AMEND_PATCHES` (2).
//!   2. Every patch's `byte_offset + len` doesn't overflow u64.
//!   3. Every `Write` ends within `cluster_size` — amend only ever
//!      rewrites the first header cluster.
//!   4. `resulting_version` is 2 or 3.
//!   5. No two `Write` patches overlap.
//!   6. A `NoOp` plan carries zero patches.
//!
//! Errors (`ParseFailed`, `Dirty`, `DowngradeBlockedFeature`,
//! `LazyRequiresV3`, `ExtensionRelocationUnsupported`,
//! `ScratchTooSmall`, …) are silently ignored — libFuzzer's only
//! oracle is panic.
//!
//! No re-parse round-trip: applying the patches and re-parsing the
//! resulting cluster is a stronger property covered by the phase-5
//! unit tests (`crates/amend/src/qcow2.rs`). This target's contract
//! is narrower: no panics, no integer overflows, no overlapping
//! writes, no out-of-cluster writes, no patch counts above the
//! bound.

#![no_main]
use libfuzzer_sys::fuzz_target;

use std::cell::RefCell;

use amend::{
    plan_amend_qcow2, AmendAction, AmendPatch, AmendPlan, Qcow2AmendOpts, MAX_AMEND_PATCHES,
};
use qcow2::{CLUSTER_BITS_OFFSET, QCOW2_MAGIC, VERSION_OFFSET};

/// Realistic cluster sizes (all have `cluster_bits` within the
/// 9..=21 range `QcowHeader::parse` accepts): 512 (bits 9), 4 KiB
/// (12), 64 KiB (16), 1 MiB (20).
const CLUSTER_SIZES: [u32; 4] = [512, 4096, 65536, 1 << 20];

/// Minimum prefix: byte 0 -> cluster_size, byte 1 -> flags, byte 2
/// -> version, then bytes 8.. are copied into the header cluster.
const PREFIX_BYTES: usize = 8;

thread_local! {
    /// Reusable scratch buffer for plan_amend_qcow2. Sized to the
    /// largest supported cluster (1 MiB) so the cross-version
    /// full-cluster rebuild always has room.
    static SCRATCH: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 1 << 20]);
}

fuzz_target!(|data: &[u8]| {
    if data.len() < PREFIX_BYTES {
        return;
    }

    // ------------------------------------------------------------------
    // Decode the structured prefix.
    // ------------------------------------------------------------------
    let cluster_size = CLUSTER_SIZES[data[0] as usize % CLUSTER_SIZES.len()];
    let cluster_bits = cluster_size.trailing_zeros();

    let flags = data[1];
    let set_compat = flags & 0b0000_0001 != 0;
    let target_v3 = flags & 0b0000_0010 != 0;
    let set_lazy = flags & 0b0000_0100 != 0;
    let lazy_on = flags & 0b0000_1000 != 0;

    // Stamp a v2 or v3 version so the parser reaches the version-
    // specific decision logic for both.
    let version: u32 = (data[2] as u32 % 2) + 2;

    // ------------------------------------------------------------------
    // Synthesise the header cluster.
    //
    // Start from the fuzz pool (so the fuzzer can explore malformed
    // extension areas, feature words, backing strings, etc.), then
    // stamp the minimal fields `QcowHeader::parse` gates on (magic,
    // version, cluster_bits) so a meaningful fraction of inputs
    // reach the planning logic rather than bailing at ParseFailed.
    // ------------------------------------------------------------------
    let mut header = vec![0u8; cluster_size as usize];
    let pool = &data[PREFIX_BYTES..];
    let copy_len = pool.len().min(header.len());
    header[..copy_len].copy_from_slice(&pool[..copy_len]);

    header[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
    header[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&version.to_be_bytes());
    header[CLUSTER_BITS_OFFSET..CLUSTER_BITS_OFFSET + 4]
        .copy_from_slice(&cluster_bits.to_be_bytes());

    let opts = Qcow2AmendOpts {
        header_cluster: &header,
        cluster_size,
        set_compat,
        target_v3,
        set_lazy,
        lazy_on,
    };

    SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        if let Ok(plan) = plan_amend_qcow2(&opts, &mut scratch) {
            check_amend_invariants(&plan, cluster_size);
        }
    });
});

/// Plan-level invariants. Panicking on violation triggers libFuzzer
/// to record the input as a crash.
fn check_amend_invariants(plan: &AmendPlan<'_>, cluster_size: u32) {
    let patches = plan.patches();

    // Invariant 1: patch count bound.
    assert!(
        patches.len() <= MAX_AMEND_PATCHES,
        "patch count {} > MAX_AMEND_PATCHES ({})",
        patches.len(),
        MAX_AMEND_PATCHES,
    );

    // Invariant 4: resulting version is 2 or 3.
    assert!(
        plan.resulting_version == 2 || plan.resulting_version == 3,
        "resulting_version {} not in {{2, 3}}",
        plan.resulting_version,
    );

    // Invariant 6: a no-op carries no patches.
    if plan.action == AmendAction::NoOp {
        assert!(
            patches.is_empty(),
            "NoOp plan carries {} patch(es)",
            patches.len(),
        );
    }

    let cluster_end = cluster_size as u64;

    // Invariants 2-3: per-patch overflow + within-cluster bounds.
    // Amend only ever rewrites the first header cluster, so every
    // emitted patch must land within `cluster_size`.
    for (i, p) in patches.iter().enumerate() {
        let off = p.byte_offset();
        let len = p.len() as u64;
        let end = off.checked_add(len).unwrap_or_else(|| {
            panic!("patch {i} offset {off} + len {len} overflows u64")
        });
        match p {
            AmendPatch::Write { .. } => {
                assert!(
                    end <= cluster_end,
                    "patch {i} ({off}..{end}) exceeds cluster_size ({cluster_end})",
                );
            }
        }
    }

    // Invariant 5: no two Write patches overlap (sort by offset,
    // mirror resize).
    let mut writes: Vec<(u64, u64)> = patches
        .iter()
        .filter_map(|p| match p {
            AmendPatch::Write { byte_offset, bytes } => {
                Some((*byte_offset, *byte_offset + bytes.len() as u64))
            }
        })
        .collect();
    writes.sort_by_key(|(off, _)| *off);
    for w in writes.windows(2) {
        let (off_a, end_a) = w[0];
        let (off_b, end_b) = w[1];
        assert!(
            end_a <= off_b,
            "overlapping Write patches: ({off_a}..{end_a}) and ({off_b}..{end_b})",
        );
    }
}
