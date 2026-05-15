//! Coverage-guided fuzzing for the per-parser `scan_allocation` entry
//! points added in phase 2 of PLAN-measure.md. First byte selects the
//! format (qcow2/vmdk/vhd/vhdx); remaining bytes feed through the
//! existing instar_fuzz::build_call_table() mock to drive the cached
//! sector reader and into the metadata-walking scan path.
//!
//! Invariants asserted on Some(AllocationSummary) returns:
//!   - allocated_bytes <= virtual_size
//!
//! None returns are fine (parser rejected the image). raw is omitted
//! because raw::scan_allocation is a pure function exercised by
//! fuzz_measure_calc.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let format = data[0] % 4;
    // Pick a target unit size from a small set so the new bug-#286
    // target-aware scan path is exercised on every iteration. `0`
    // selects the legacy code path (no target-unit tracking).
    let target_unit_size: u64 = match data[1] & 0x3 {
        0 => 0,
        1 => 4096,
        2 => 65536,
        _ => 1 << 20,
    };
    let image_data = &data[2..];

    instar_fuzz::set_fuzz_input(image_data);
    let call_table = instar_fuzz::build_call_table();
    let sector_size = 512usize;
    let input_capacity = instar_fuzz::input_capacity();

    let mut cache_a = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut cache_b = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut bytes_read = 0u64;

    unsafe {
        match format {
            0 => {
                // qcow2: needs virtual_size from QcowHeader::parse
                if let Some(mut state) = qcow2::Qcow2State::init(
                    &call_table,
                    0,
                    sector_size,
                    input_capacity,
                    cache_a.as_mut_ptr(),
                    cache_b.as_mut_ptr(),
                    &mut bytes_read,
                ) {
                    // Recover virtual_size by re-reading the first sector
                    // and re-parsing the header. Matches the production
                    // measure operation's flow (src/operations/measure/).
                    let mut buf = vec![0u8; sector_size];
                    if (call_table.read_input_sector)(
                        0,
                        0,
                        buf.as_mut_ptr(),
                        sector_size,
                    ) {
                        if let Some(h) = qcow2::QcowHeader::parse(&buf) {
                            if let Some(s) = state.scan_allocation(
                                &call_table,
                                sector_size,
                                input_capacity,
                                h.virtual_size,
                                target_unit_size,
                                &mut bytes_read,
                            ) {
                                assert!(
                                    s.allocated_bytes <= s.virtual_size,
                                    "qcow2 allocated {} > virtual {}",
                                    s.allocated_bytes,
                                    s.virtual_size
                                );
                                // Bug #286 invariant: when target-unit
                                // tracking is enabled and any source data
                                // is allocated, the count must also fit
                                // within the target's view of virtual size.
                                if target_unit_size > 0 && s.virtual_size > 0 {
                                    let cap = s
                                        .virtual_size
                                        .div_ceil(target_unit_size);
                                    assert!(
                                        s.target_units_with_data <= cap,
                                        "qcow2 target_units {} > cap {}",
                                        s.target_units_with_data,
                                        cap
                                    );
                                }
                            }
                        }
                    }
                }
            }
            1 => {
                // vmdk: VmdkState::init also takes actual_file_size
                let actual_size =
                    (input_capacity as u64).saturating_mul(sector_size as u64);
                if let Some(mut state) = vmdk::VmdkState::init(
                    &call_table,
                    0,
                    sector_size,
                    input_capacity,
                    actual_size,
                    cache_a.as_mut_ptr(),
                    cache_b.as_mut_ptr(),
                    &mut bytes_read,
                ) {
                    if let Some(s) = state.scan_allocation(
                        &call_table,
                        sector_size,
                        input_capacity,
                        &mut bytes_read,
                    ) {
                        assert!(
                            s.allocated_bytes <= s.virtual_size,
                            "vmdk allocated {} > virtual {}",
                            s.allocated_bytes,
                            s.virtual_size
                        );
                    }
                }
            }
            2 => {
                // vhd
                if let Some(mut state) = vhd::VhdState::init(
                    &call_table,
                    0,
                    sector_size,
                    input_capacity,
                    cache_a.as_mut_ptr(),
                    cache_b.as_mut_ptr(),
                    &mut bytes_read,
                ) {
                    if let Some(s) = state.scan_allocation(
                        &call_table,
                        sector_size,
                        input_capacity,
                        &mut bytes_read,
                    ) {
                        assert!(
                            s.allocated_bytes <= s.virtual_size,
                            "vhd allocated {} > virtual {}",
                            s.allocated_bytes,
                            s.virtual_size
                        );
                    }
                }
            }
            _ => {
                // vhdx
                if let Some(mut state) = vhdx::VhdxState::init(
                    &call_table,
                    0,
                    sector_size,
                    input_capacity,
                    cache_a.as_mut_ptr(),
                    cache_b.as_mut_ptr(),
                    &mut bytes_read,
                ) {
                    if let Some(s) = state.scan_allocation(
                        &call_table,
                        sector_size,
                        input_capacity,
                        &mut bytes_read,
                    ) {
                        assert!(
                            s.allocated_bytes <= s.virtual_size,
                            "vhdx allocated {} > virtual {}",
                            s.allocated_bytes,
                            s.virtual_size
                        );
                    }
                }
            }
        }
    }
});
