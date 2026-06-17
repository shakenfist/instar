//! Shared helpers for the `amend` integration round-trip suite.
//!
//! These build qcow2 header buffers (v3 via the `create` crate, v2
//! hand-crafted), apply an `AmendPlan`'s patches onto a byte buffer,
//! and synthesise the v2-with-backing-extension layout real qemu
//! emits — so the apply-then-reparse matrix in
//! `qcow2_round_trip.rs` can assert header invariants and extension
//! survival across every transition.

#![allow(dead_code)]

use create::{plan_qcow2, BackingRef, MetadataPlan, Qcow2CreateOpts, QCOW2_MAX_METADATA_SCRATCH};
use qcow2::{
    BACKING_FILE_OFFSET_OFFSET, BACKING_FILE_SIZE_OFFSET, CLUSTER_BITS_OFFSET, EXT_BACKING_FORMAT,
    EXT_END, L1_SIZE_OFFSET, L1_TABLE_OFFSET_OFFSET, QCOW2_MAGIC, REFCOUNT_TABLE_CLUSTERS_OFFSET,
    REFCOUNT_TABLE_OFFSET_OFFSET, SIZE_OFFSET, VERSION_OFFSET,
};
use shared::ImageFormat;

/// Materialise a `MetadataPlan` (from crates/create) into a
/// contiguous byte buffer sized to `minimum_file_size`.
fn materialise(plan: &MetadataPlan<'_>) -> Vec<u8> {
    let mut buf = vec![0u8; plan.minimum_file_size as usize];
    for w in plan.writes() {
        let start = w.byte_offset as usize;
        let end = start + w.bytes.len();
        buf[start..end].copy_from_slice(w.bytes);
    }
    buf
}

/// Apply an `AmendPlan` to an existing byte buffer. Each
/// `AmendPatch::Write` copies `bytes` to `file[byte_offset..]`,
/// resizing the buffer if the write would run past its end.
pub fn apply_amend(file: &mut Vec<u8>, plan: &amend::AmendPlan) {
    for patch in plan.patches() {
        match patch {
            amend::AmendPatch::Write { byte_offset, bytes } => {
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

/// Build a v3 qcow2 image via the `create` crate (mirrors
/// `resize/tests/qcow2_grow.rs::build_starting_image`).
///
/// `lazy` sets `compatible_features = COMPAT_LAZY_REFCOUNTS`; an
/// optional `backing` path adds a backing-file reference (format
/// qcow2). Returns the materialised bytes.
pub fn build_v3(
    virtual_size: u64,
    cluster_size: u32,
    lazy: bool,
    backing: Option<&[u8]>,
) -> Vec<u8> {
    let opts = Qcow2CreateOpts {
        virtual_size,
        cluster_size,
        refcount_bits: 16,
        extended_l2: false,
        lazy_refcounts: lazy,
        compat_v3: true,
        backing: backing.map(|path| BackingRef {
            path,
            format: Some(ImageFormat::Qcow2),
        }),
        preallocation: qcow2::create::Preallocation::Off,
    };
    let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
    let plan = plan_qcow2(&opts, &mut scratch).expect("create plan");
    materialise(&plan)
}

/// Hand-craft a minimal valid v2 qcow2 header cluster.
///
/// Mirrors phase 2's `make_header` (qcow2.rs) field layout but sizes
/// the buffer to a full `cluster_size` and computes `cluster_bits`
/// from `cluster_size`. Sets: magic, version=2, cluster_bits,
/// virtual_size, l1_size=1, l1_table_offset=2*cluster_size,
/// refcount_table_offset=cluster_size, refcount_table_clusters=1 —
/// all big-endian. No header extensions or backing reference.
pub fn make_v2_header(cluster_size: usize, virtual_size: u64) -> Vec<u8> {
    let mut h = vec![0u8; cluster_size];
    let cluster_bits = cluster_size.trailing_zeros();
    h[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
    h[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&2u32.to_be_bytes());
    h[CLUSTER_BITS_OFFSET..CLUSTER_BITS_OFFSET + 4].copy_from_slice(&cluster_bits.to_be_bytes());
    h[SIZE_OFFSET..SIZE_OFFSET + 8].copy_from_slice(&virtual_size.to_be_bytes());
    h[L1_SIZE_OFFSET..L1_SIZE_OFFSET + 4].copy_from_slice(&1u32.to_be_bytes());
    h[L1_TABLE_OFFSET_OFFSET..L1_TABLE_OFFSET_OFFSET + 8]
        .copy_from_slice(&(2u64 * cluster_size as u64).to_be_bytes());
    h[REFCOUNT_TABLE_OFFSET_OFFSET..REFCOUNT_TABLE_OFFSET_OFFSET + 8]
        .copy_from_slice(&(cluster_size as u64).to_be_bytes());
    h[REFCOUNT_TABLE_CLUSTERS_OFFSET..REFCOUNT_TABLE_CLUSTERS_OFFSET + 4]
        .copy_from_slice(&1u32.to_be_bytes());
    h
}

/// Write a backing-format extension at `at`, followed by `EXT_END`,
/// followed by the `backing_name` string; update the header's
/// `backing_file_offset`/`backing_file_size` to point at that string.
///
/// Layout written from `at` (mirrors phase 2's `put_backing_format_ext`
/// plus the explicit backing string the qemu fixture carries):
///   at      : EXT_BACKING_FORMAT type (u32 BE)
///   at + 4  : ext len = 5 (u32 BE)
///   at + 8  : "qcow2" (5 bytes; body padded to 8 -> at+8..at+16)
///   at + 16 : EXT_END (type 0, len 0 -> 8 bytes, ends at at+24)
///   at + 24 : backing_name string
///
/// Sets `backing_file_offset` (offset 8, u64 BE) to the backing
/// string offset (`at + 24`) and `backing_file_size` (offset 16,
/// u32 BE) to `backing_name.len()`. Returns the offset just past the
/// backing string (the meaningful end of the relocatable tail).
pub fn put_backing_format_ext(buf: &mut [u8], at: usize, backing_name: &[u8]) -> usize {
    buf[at..at + 4].copy_from_slice(&EXT_BACKING_FORMAT.to_be_bytes());
    buf[at + 4..at + 8].copy_from_slice(&5u32.to_be_bytes());
    buf[at + 8..at + 13].copy_from_slice(b"qcow2");
    // padded body = 8 bytes; EXT_END header at at + 16.
    let ext_end_at = at + 16;
    buf[ext_end_at..ext_end_at + 4].copy_from_slice(&EXT_END.to_be_bytes());
    // EXT_END len = 0 (already zero). EXT_END record ends at + 24.
    let backing_str_at = ext_end_at + 8;
    buf[backing_str_at..backing_str_at + backing_name.len()].copy_from_slice(backing_name);

    buf[BACKING_FILE_OFFSET_OFFSET..BACKING_FILE_OFFSET_OFFSET + 8]
        .copy_from_slice(&(backing_str_at as u64).to_be_bytes());
    buf[BACKING_FILE_SIZE_OFFSET..BACKING_FILE_SIZE_OFFSET + 4]
        .copy_from_slice(&(backing_name.len() as u32).to_be_bytes());

    backing_str_at + backing_name.len()
}
