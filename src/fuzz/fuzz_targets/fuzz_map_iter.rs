//! Coverage-guided fuzzing for the per-parser `map_extents` entry
//! points added in phase 1 of PLAN-map.md. First byte selects the
//! format (qcow2/vmdk/vhd/vhdx); remaining bytes feed through the
//! existing instar_fuzz::build_call_table() mock to drive the
//! cached sector reader and into the per-cluster extent emission
//! path.
//!
//! Invariants asserted when the walker returns Some(virtual_size):
//!   1. No zero-length extents.
//!   2. No start + length overflow.
//!   3. e[0].start == 0 and each e[i].start == prev_end (sorted,
//!      contiguous, no gaps, no overlaps).
//!   4. prev_end == virtual_size after the last extent.
//!   5. virtual_size == 0 ⇒ zero extents.
//!   6. virtual_size > 0 ⇒ at least one extent.
//!
//! File-offset overflow on Data extents (invariant 7 in the plan)
//! is deferred until compressed-cluster reporting lands properly —
//! in v1 compressed clusters legitimately reuse a file offset
//! across coalesced runs, so an offset+length overflow check would
//! produce false positives.
//!
//! None returns are fine (parser rejected the image, or I/O
//! through the mock returned false). raw is omitted because its
//! map_extents is a pure function of virtual_size with no on-disk
//! input surface — same omission as fuzz_measure_scan.

#![no_main]
use libfuzzer_sys::fuzz_target;
use shared::MapExtent;

// Generous cap on recorded extents. A 4 GiB qcow2 at 4 KiB
// clusters tops out at 1 M extents pre-coalesce; the fuzz mock's
// input_capacity is much smaller than that. Hitting the cap is
// itself surfaced as a failure — we don't want to silently
// truncate an unbounded-loop bug.
const EXTENT_CAP: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let format = data[0] % 4;
    let image_data = &data[1..];

    instar_fuzz::set_fuzz_input(image_data);
    let call_table = instar_fuzz::build_call_table();
    let sector_size = 512usize;
    let input_capacity = instar_fuzz::input_capacity();

    let mut cache_a = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut cache_b = vec![0u8; shared::MAX_SECTOR_SIZE];
    let mut bytes_read = 0u64;

    let mut extents: Vec<MapExtent> = Vec::with_capacity(1024);
    let mut hit_cap = false;
    let mut emit = |e: MapExtent| -> bool {
        if extents.len() >= EXTENT_CAP {
            hit_cap = true;
            return false;
        }
        extents.push(e);
        true
    };

    let virtual_size: Option<u64> = unsafe {
        match format {
            0 => qcow2_dispatch(
                &call_table,
                sector_size,
                input_capacity,
                cache_a.as_mut_ptr(),
                cache_b.as_mut_ptr(),
                &mut bytes_read,
                &mut emit,
            ),
            1 => vmdk_dispatch(
                &call_table,
                sector_size,
                input_capacity,
                cache_a.as_mut_ptr(),
                cache_b.as_mut_ptr(),
                &mut bytes_read,
                &mut emit,
            ),
            2 => vhd_dispatch(
                &call_table,
                sector_size,
                input_capacity,
                cache_a.as_mut_ptr(),
                cache_b.as_mut_ptr(),
                &mut bytes_read,
                &mut emit,
            ),
            _ => vhdx_dispatch(
                &call_table,
                sector_size,
                input_capacity,
                cache_a.as_mut_ptr(),
                cache_b.as_mut_ptr(),
                &mut bytes_read,
                &mut emit,
            ),
        }
    };

    let Some(virtual_size) = virtual_size else {
        return;
    };
    if hit_cap {
        panic!(
            "map_extents emitted >{} extents on {} bytes of input \
             — likely unbounded loop or pathological cluster size",
            EXTENT_CAP,
            image_data.len()
        );
    }
    assert_partition(&extents, virtual_size);
});

unsafe fn qcow2_dispatch<F: FnMut(MapExtent) -> bool>(
    call_table: &shared::CallTable,
    sector_size: usize,
    input_capacity: u64,
    cache_a: *mut u8,
    cache_b: *mut u8,
    bytes_read: &mut u64,
    emit: &mut F,
) -> Option<u64> {
    let mut state = qcow2::Qcow2State::init(
        call_table,
        0,
        sector_size,
        input_capacity,
        cache_a,
        cache_b,
        bytes_read,
    )?;
    // Qcow2State does not expose virtual_size directly; re-read
    // sector 0 and parse the header (same approach as
    // fuzz_measure_scan.rs:60-65).
    let mut buf = vec![0u8; sector_size];
    if !(call_table.read_input_sector)(0, 0, buf.as_mut_ptr(), sector_size) {
        return None;
    }
    let header = qcow2::QcowHeader::parse(&buf)?;
    state.map_extents(
        call_table,
        sector_size,
        input_capacity,
        header.virtual_size,
        bytes_read,
        emit,
    )?;
    Some(header.virtual_size)
}

unsafe fn vmdk_dispatch<F: FnMut(MapExtent) -> bool>(
    call_table: &shared::CallTable,
    sector_size: usize,
    input_capacity: u64,
    cache_a: *mut u8,
    cache_b: *mut u8,
    bytes_read: &mut u64,
    emit: &mut F,
) -> Option<u64> {
    let actual_size = input_capacity.saturating_mul(sector_size as u64);
    let mut state = vmdk::VmdkState::init(
        call_table,
        0,
        sector_size,
        input_capacity,
        actual_size,
        cache_a,
        cache_b,
        bytes_read,
    )?;
    let virtual_size = state.capacity_sectors.checked_mul(512)?;
    state.map_extents(
        call_table,
        sector_size,
        input_capacity,
        bytes_read,
        emit,
    )?;
    Some(virtual_size)
}

unsafe fn vhd_dispatch<F: FnMut(MapExtent) -> bool>(
    call_table: &shared::CallTable,
    sector_size: usize,
    input_capacity: u64,
    cache_a: *mut u8,
    cache_b: *mut u8,
    bytes_read: &mut u64,
    emit: &mut F,
) -> Option<u64> {
    let mut state = vhd::VhdState::init(
        call_table,
        0,
        sector_size,
        input_capacity,
        cache_a,
        cache_b,
        bytes_read,
    )?;
    let virtual_size = state.current_size;
    state.map_extents(
        call_table,
        sector_size,
        input_capacity,
        bytes_read,
        emit,
    )?;
    Some(virtual_size)
}

unsafe fn vhdx_dispatch<F: FnMut(MapExtent) -> bool>(
    call_table: &shared::CallTable,
    sector_size: usize,
    input_capacity: u64,
    cache_a: *mut u8,
    cache_b: *mut u8,
    bytes_read: &mut u64,
    emit: &mut F,
) -> Option<u64> {
    let mut state = vhdx::VhdxState::init(
        call_table,
        0,
        sector_size,
        input_capacity,
        cache_a,
        cache_b,
        bytes_read,
    )?;
    let virtual_size = state.virtual_disk_size;
    state.map_extents(
        call_table,
        sector_size,
        input_capacity,
        bytes_read,
        emit,
    )?;
    Some(virtual_size)
}

fn assert_partition(extents: &[MapExtent], virtual_size: u64) {
    if virtual_size == 0 {
        assert!(
            extents.is_empty(),
            "virtual_size=0 must emit zero extents, got {}",
            extents.len()
        );
        return;
    }
    assert!(
        !extents.is_empty(),
        "virtual_size={virtual_size} > 0 must emit at least one extent"
    );

    let mut prev_end: u64 = 0;
    for (i, e) in extents.iter().enumerate() {
        assert!(
            e.length > 0,
            "extent[{i}] has zero length (start={}, virtual_size={virtual_size})",
            e.start
        );
        let end = e.start.checked_add(e.length).unwrap_or_else(|| {
            panic!(
                "extent[{i}] start+length overflows: \
                 start={} length={} virtual_size={virtual_size}",
                e.start, e.length
            )
        });
        assert_eq!(
            e.start, prev_end,
            "extent[{i}] not contiguous: start={} prev_end={prev_end} \
             virtual_size={virtual_size}",
            e.start
        );
        assert!(
            end <= virtual_size,
            "extent[{i}] end={end} exceeds virtual_size={virtual_size} \
             (start={}, length={})",
            e.start,
            e.length
        );
        prev_end = end;
    }
    assert_eq!(
        prev_end, virtual_size,
        "partition does not close: last_end={prev_end} virtual_size={virtual_size}"
    );
}
