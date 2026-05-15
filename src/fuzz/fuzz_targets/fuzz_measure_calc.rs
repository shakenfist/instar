//! Coverage-guided fuzzing for the per-format `measure_<fmt>` calculator
//! functions in `crates/measure/`. The harness decodes 42 bytes of fuzz
//! input into a `(target_format, AllocationSummary, options)` tuple and
//! asserts:
//!   - required <= fully_allocated
//!   - fully_allocated >= virtual_size  (for raw output)
//!   - fully_allocated > 0  whenever virtual_size > 0 (non-raw target)
//!   - required + fully_allocated does not overflow u64
//!   - Preallocation::Falloc|Full -> required == fully_allocated  (qcow2)
//!
//! Errors (Overflow / InvalidOption / InvalidSize) are silently ignored;
//! libFuzzer's only oracle is panic.

#![no_main]
use libfuzzer_sys::fuzz_target;

use measure::{
    measure_qcow2, measure_raw, measure_vhd, measure_vhdx, measure_vmdk,
    AllocationSummary, MeasureOutput, Preallocation, Qcow2Opts, VhdOpts,
    VhdSubformat, VhdxOpts, VmdkOpts, VmdkSubformat,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 42 {
        return;
    }

    // Byte layout (see PLAN-measure-phase-08-fuzz-coverage.md):
    let target_sel   = data[0] % 5;
    let rcb_sel      = data[1] % 8;
    let flag_bits    = data[2];
    let prealloc_sel = data[3] % 4;
    let vmdk_sub     = data[4] % 3;
    let vhd_sub      = data[5] % 2;
    let virtual_size    = u64::from_le_bytes(data[6..14].try_into().unwrap());
    let allocated_bytes = u64::from_le_bytes(data[14..22].try_into().unwrap());
    let cluster_size    = u32::from_le_bytes(data[22..26].try_into().unwrap());
    let grain_size      = u32::from_le_bytes(data[26..30].try_into().unwrap());
    let block_size      = u32::from_le_bytes(data[30..34].try_into().unwrap());
    let luks_overhead   = u64::from_le_bytes(data[34..42].try_into().unwrap());

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
        1 => Preallocation::Metadata,
        2 => Preallocation::Falloc,
        3 => Preallocation::Full,
        _ => Preallocation::Off,
    };
    let vmdk_subformat = match vmdk_sub {
        1 => VmdkSubformat::StreamOptimized,
        2 => VmdkSubformat::MonolithicFlat,
        _ => VmdkSubformat::MonolithicSparse,
    };
    let vhd_subformat = match vhd_sub {
        1 => VhdSubformat::Fixed,
        _ => VhdSubformat::Dynamic,
    };

    let summary = AllocationSummary {
        virtual_size,
        allocated_bytes,
        target_units_with_data: 0,
    };
    let result: Option<MeasureOutput> = match target_sel {
        0 => measure_raw(virtual_size).ok(),
        1 => {
            let opts = Qcow2Opts {
                cluster_size,
                refcount_bits,
                extended_l2: flag_bits & 1 != 0,
                lazy_refcounts: flag_bits & 2 != 0,
                compat_v3: flag_bits & 4 != 0,
                compress: flag_bits & 8 != 0,
                preallocation,
                luks_header_overhead: if luks_overhead == 0 {
                    None
                } else {
                    Some(luks_overhead)
                },
            };
            measure_qcow2(&summary, &opts).ok()
        }
        2 => {
            let opts = VmdkOpts {
                subformat: vmdk_subformat,
                grain_size,
            };
            measure_vmdk(&summary, &opts).ok()
        }
        3 => {
            let opts = VhdOpts {
                subformat: vhd_subformat,
                block_size,
            };
            measure_vhd(&summary, &opts).ok()
        }
        _ => {
            let opts = VhdxOpts { block_size };
            measure_vhdx(&summary, &opts).ok()
        }
    };

    if let Some(m) = result {
        // Invariant 1: required <= fully_allocated.
        assert!(
            m.required <= m.fully_allocated,
            "required ({}) > fully_allocated ({}) for target {}",
            m.required,
            m.fully_allocated,
            target_sel
        );

        // Invariant 2: for raw output, fully_allocated covers the virtual range.
        if target_sel == 0 {
            assert!(
                m.fully_allocated >= virtual_size,
                "raw fully_allocated ({}) < virtual_size ({})",
                m.fully_allocated,
                virtual_size
            );
        }

        // Invariant 3: non-raw targets with non-zero virtual_size always have
        // at least header overhead, so fully_allocated > 0.
        if target_sel != 0 && virtual_size > 0 {
            assert!(
                m.fully_allocated > 0,
                "non-raw target {} with virtual_size {} has fully_allocated = 0",
                target_sel,
                virtual_size
            );
        }

        // Invariant 4: the two outputs don't overflow when summed.
        assert!(
            m.required.checked_add(m.fully_allocated).is_some(),
            "required + fully_allocated overflows u64"
        );

        // Invariant 5: qcow2 with Preallocation::Falloc|Full collapses
        // required onto fully_allocated.
        if target_sel == 1
            && matches!(preallocation, Preallocation::Falloc | Preallocation::Full)
        {
            assert_eq!(
                m.required,
                m.fully_allocated,
                "qcow2 with Falloc/Full preallocation: required {} != fully_allocated {}",
                m.required,
                m.fully_allocated
            );
        }
    }
});
