//! Shared helpers for the commit integration tests.
//!
//! Each test crate builds an overlay + a backing via
//! `create::plan_*`, materialises them into contiguous byte
//! buffers, and threads the staged metadata into the planner's
//! opts. The functions here are the shared pieces:
//! materialisation of a `MetadataPlan` into bytes.

#![allow(dead_code)] // Each test crate uses a subset.

use create::MetadataPlan;

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
