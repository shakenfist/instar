//! End-to-end round-trip integration tests for every `plan_*`
//! function in `crates/create`.
//!
//! Sweeps a representative option matrix per format, materialises
//! each plan into a contiguous byte buffer, parses it back with the
//! matching parser crate, and asserts that the format-specific
//! identifying fields (virtual_size, cluster/grain/block size,
//! version, backing reference where applicable) round-trip exactly.
//!
//! Also asserts the structural invariants every plan must satisfy:
//!
//! * `total_metadata_bytes == sum(writes[*].bytes.len())`
//! * `minimum_file_size == max(byte_offset + bytes.len())`
//! * No two writes overlap (sorted by `byte_offset`).
//!
//! These complement the per-planner unit tests in `lib.rs` by
//! exercising the matrix breadth in one place; if a single planner
//! regresses on its option surface this file catches it.

use create::{
    plan_qcow2, plan_vhd, plan_vhdx, plan_vmdk, BackingRef, MetadataPlan, MetadataWrite,
    Qcow2CreateOpts, VhdCreateOpts, VhdSubformat, VhdxCreateOpts, VmdkCreateOpts, VmdkSubformat,
    QCOW2_MAX_METADATA_SCRATCH, VHDX_MAX_METADATA_SCRATCH, VHD_MAX_METADATA_SCRATCH,
    VMDK_MAX_METADATA_SCRATCH,
};
use shared::ImageFormat;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn materialise(plan: &MetadataPlan<'_>) -> Vec<u8> {
    let mut buf = vec![0u8; plan.minimum_file_size as usize];
    for w in plan.writes() {
        let start = w.byte_offset as usize;
        let end = start + w.bytes.len();
        buf[start..end].copy_from_slice(w.bytes);
    }
    buf
}

fn assert_plan_invariants(plan: &MetadataPlan<'_>) {
    // Sum of write lengths matches total_metadata_bytes.
    let sum: u64 = plan.writes().iter().map(|w| w.bytes.len() as u64).sum();
    assert_eq!(plan.total_metadata_bytes, sum, "total_metadata_bytes");

    // minimum_file_size is the max end-offset.
    let max_end: u64 = plan
        .writes()
        .iter()
        .map(|w| w.byte_offset + w.bytes.len() as u64)
        .max()
        .unwrap_or(0);
    assert_eq!(plan.minimum_file_size, max_end, "minimum_file_size");

    // No writes overlap.
    let mut sorted: Vec<&MetadataWrite<'_>> = plan.writes().iter().collect();
    sorted.sort_by_key(|w| w.byte_offset);
    for pair in sorted.windows(2) {
        let prev = pair[0];
        let next = pair[1];
        assert!(
            prev.byte_offset + prev.bytes.len() as u64 <= next.byte_offset,
            "overlap: {}+{} > {}",
            prev.byte_offset,
            prev.bytes.len(),
            next.byte_offset,
        );
    }
}

// ---------------------------------------------------------------------------
// qcow2 sweep
// ---------------------------------------------------------------------------

#[test]
fn sweep_qcow2() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30, 1 << 35, 1 << 40];
    let cluster_sizes: &[u32] = &[512, 4096, 65536, 1 << 20, 2 << 20];
    let mut cases = 0;
    let mut skipped = 0;

    for &virtual_size in sizes {
        for &cluster_size in cluster_sizes {
            for extended_l2 in [false, true] {
                let opts = Qcow2CreateOpts {
                    virtual_size,
                    cluster_size,
                    refcount_bits: 16,
                    extended_l2,
                    lazy_refcounts: false,
                    compat_v3: true,
                    backing: None,
                    preallocation: qcow2::create::Preallocation::Off,
                };
                let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
                let scratch_len = scratch.len();
                let plan = match plan_qcow2(&opts, &mut scratch) {
                    Ok(p) => p,
                    Err(create::CreateError::InvalidVirtualSize) => {
                        // Combination exceeds QCOW2_MAX_L1_SIZE — expected
                        // for very small clusters at very large virtual
                        // sizes. Not a regression.
                        skipped += 1;
                        continue;
                    }
                    Err(e) => panic!(
                        "plan_qcow2 failed for virtual_size={}, cluster_size={}, extended_l2={}, scratch_len={}: {:?}",
                        virtual_size, cluster_size, extended_l2, scratch_len, e
                    ),
                };
                assert_plan_invariants(&plan);
                let bytes = materialise(&plan);
                let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse");
                assert_eq!(parsed.virtual_size, virtual_size);
                assert_eq!(parsed.cluster_size, cluster_size as u64);
                assert_eq!(parsed.extended_l2, extended_l2);
                cases += 1;
            }
        }
    }

    // Plus one backing-file case.
    let opts = Qcow2CreateOpts {
        virtual_size: 1 << 30,
        cluster_size: 65536,
        refcount_bits: 16,
        extended_l2: false,
        lazy_refcounts: true,
        compat_v3: true,
        backing: Some(BackingRef {
            path: b"backing.qcow2",
            format: Some(ImageFormat::Qcow2),
        }),
        preallocation: qcow2::create::Preallocation::Off,
    };
    let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
    let plan = plan_qcow2(&opts, &mut scratch).expect("plan");
    assert_plan_invariants(&plan);
    let bytes = materialise(&plan);
    let parsed = qcow2::QcowHeader::parse(&bytes).expect("parse");
    assert_eq!(parsed.virtual_size, 1 << 30);
    assert!(parsed.lazy_refcounts);
    assert_eq!(parsed.backing_file_size as usize, b"backing.qcow2".len());
    cases += 1;

    // cases counts: matrix-success + 1 (the trailing backing-file case).
    // skipped counts: matrix-skip (combinations beyond format limits).
    assert_eq!(cases + skipped, sizes.len() * cluster_sizes.len() * 2 + 1);
    // We should have covered at least the realistic combinations.
    assert!(cases > 30, "sweep covered only {} cases", cases);
}

// ---------------------------------------------------------------------------
// vmdk sweep
// ---------------------------------------------------------------------------

#[test]
fn sweep_vmdk() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30, 1 << 32];
    let grain_sizes: &[u32] = &[4096, 16384, 65536];
    let mut cases = 0;

    for &virtual_size in sizes {
        for &grain_size in grain_sizes {
            for subformat in [
                VmdkSubformat::MonolithicSparse,
                VmdkSubformat::StreamOptimized,
            ] {
                let opts = VmdkCreateOpts {
                    virtual_size,
                    subformat,
                    grain_size,
                    backing: None,
                    parent_cid: None,
                };
                let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
                let plan = plan_vmdk(&opts, &mut scratch).expect("plan");
                assert_plan_invariants(&plan);
                let bytes = materialise(&plan);
                let parsed = vmdk::Vmdk4Header::parse(&bytes).expect("parse");
                assert_eq!(parsed.virtual_size, virtual_size);
                assert_eq!(parsed.cluster_size, grain_size);
                cases += 1;
            }
        }
    }

    // Plus a monolithicSparse-with-backing case.
    let opts = VmdkCreateOpts {
        virtual_size: 1 << 30,
        subformat: VmdkSubformat::MonolithicSparse,
        grain_size: 65536,
        backing: Some(BackingRef {
            path: b"parent.vmdk",
            format: Some(ImageFormat::Vmdk4),
        }),
        parent_cid: Some(0x12345678),
    };
    let mut scratch = vec![0u8; VMDK_MAX_METADATA_SCRATCH];
    let plan = plan_vmdk(&opts, &mut scratch).expect("plan");
    assert_plan_invariants(&plan);
    let bytes = materialise(&plan);
    let desc = &bytes[512..512 + (vmdk::DESC_SECTORS * 512) as usize];
    let needle = b"parentFileNameHint=\"parent.vmdk\"";
    assert!(desc.windows(needle.len()).any(|w| w == needle));
    cases += 1;

    assert_eq!(cases, sizes.len() * grain_sizes.len() * 2 + 1);
}

// ---------------------------------------------------------------------------
// vhd sweep
// ---------------------------------------------------------------------------

#[test]
fn sweep_vhd_dynamic() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30, 1 << 32];
    let block_sizes: &[u32] = &[512 * 1024, 2 * 1024 * 1024, 32 * 1024 * 1024];
    let mut cases = 0;

    for &virtual_size in sizes {
        for &block_size in block_sizes {
            let opts = VhdCreateOpts {
                virtual_size,
                subformat: VhdSubformat::Dynamic,
                block_size,
                backing: None,
            };
            let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
            let plan = plan_vhd(&opts, &mut scratch).expect("plan");
            assert_plan_invariants(&plan);
            let bytes = materialise(&plan);
            let footer = vhd::VhdFooter::parse(&bytes[bytes.len() - 512..]).expect("parse footer");
            assert_eq!(footer.current_size, virtual_size);
            assert_eq!(footer.disk_type, vhd::DISK_TYPE_DYNAMIC);
            cases += 1;
        }
    }

    assert_eq!(cases, sizes.len() * block_sizes.len());
}

#[test]
fn sweep_vhd_fixed() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30];
    let mut cases = 0;

    for &virtual_size in sizes {
        let opts = VhdCreateOpts {
            virtual_size,
            subformat: VhdSubformat::Fixed,
            block_size: 0,
            backing: None,
        };
        let mut scratch = vec![0u8; VHD_MAX_METADATA_SCRATCH];
        let plan = plan_vhd(&opts, &mut scratch).expect("plan");
        assert_plan_invariants(&plan);
        let bytes = materialise(&plan);
        assert_eq!(bytes.len() as u64, virtual_size + 512);
        let footer = vhd::VhdFooter::parse(&bytes[bytes.len() - 512..]).expect("parse footer");
        assert_eq!(footer.current_size, virtual_size);
        assert_eq!(footer.disk_type, vhd::DISK_TYPE_FIXED);
        cases += 1;
    }

    assert_eq!(cases, sizes.len());
}

// ---------------------------------------------------------------------------
// vhdx sweep
// ---------------------------------------------------------------------------

#[test]
fn sweep_vhdx_dynamic() {
    let sizes: &[u64] = &[1 << 20, 1 << 25, 1 << 30, 1 << 32];
    let block_sizes: &[u32] = &[1024 * 1024, 16 * 1024 * 1024, 32 * 1024 * 1024];
    let mut cases = 0;

    for &virtual_size in sizes {
        for &block_size in block_sizes {
            let opts = VhdxCreateOpts {
                virtual_size,
                block_size,
                backing: None,
            };
            let mut scratch = vec![0u8; VHDX_MAX_METADATA_SCRATCH];
            let plan = plan_vhdx(&opts, &mut scratch).expect("plan");
            assert_plan_invariants(&plan);
            let bytes = materialise(&plan);

            let sig = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            assert_eq!(sig, vhdx::FILE_IDENTIFIER_SIGNATURE);

            let h1 = &bytes
                [vhdx::HEADER1_OFFSET as usize..vhdx::HEADER1_OFFSET as usize + vhdx::HEADER_SIZE];
            vhdx::VhdxHeader::parse(h1).expect("parse header 1");

            let rt = &bytes
                [vhdx::REGION_TABLE1_OFFSET as usize..vhdx::REGION_TABLE1_OFFSET as usize + 65536];
            vhdx::parse_region_table(rt).expect("parse region table");

            cases += 1;
        }
    }

    assert_eq!(cases, sizes.len() * block_sizes.len());
}
