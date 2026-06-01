//! Shared helpers for the rebase integration tests.
//!
//! Each test crate builds a starting image via `create::plan_*`,
//! materialises it into a contiguous byte buffer, calls the
//! relevant `plan_rebase_*` entry point, applies the resulting
//! patches in order, and re-parses the post-rebase header to
//! assert metadata. The functions here are the shared pieces:
//! materialisation and patch application.

#![allow(dead_code)] // Each test crate uses a subset.

use create::MetadataPlan;
use rebase::{RebasePatch, RebasePlan};

/// Materialise a `MetadataPlan` (from `crates/create`) into a
/// contiguous byte buffer sized to `minimum_file_size`.
pub fn materialise_create(plan: &MetadataPlan<'_>) -> Vec<u8> {
    let mut buf = vec![0u8; plan.minimum_file_size as usize];
    for w in plan.writes() {
        let start = w.byte_offset as usize;
        let end = start + w.bytes.len();
        buf[start..end].copy_from_slice(w.bytes);
    }
    buf
}

/// Apply a `RebasePlan` to a byte buffer. The buffer is extended
/// to `plan.total_file_size` (if non-zero) and to whatever each
/// patch demands; patches are applied in order.
pub fn apply_rebase(file: &mut Vec<u8>, plan: &RebasePlan<'_>) {
    if plan.total_file_size > file.len() as u64 {
        file.resize(plan.total_file_size as usize, 0);
    }
    for patch in plan.patches() {
        match patch {
            RebasePatch::Write { byte_offset, bytes } => {
                let start = *byte_offset as usize;
                let end = start + bytes.len();
                if end > file.len() {
                    file.resize(end, 0);
                }
                file[start..end].copy_from_slice(bytes);
            }
            RebasePatch::Append { byte_offset, bytes } => {
                let start = *byte_offset as usize;
                let end = start + bytes.len();
                if end > file.len() {
                    file.resize(end, 0);
                }
                file[start..end].copy_from_slice(bytes);
            }
        }
    }
}
