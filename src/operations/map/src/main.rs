//! Map operation: emit the allocation map for a source image.
//!
//! Reads `MapConfig` at `OPERATION_CONFIG_ADDR`. Detects the source
//! format on device 0 and dispatches to the matching parser's
//! `map_extents` walker, streaming one [`MapExtentRecord`] per
//! coalesced extent through the call table's `send_map_extent`
//! function pointer. After the walk completes (or aborts early
//! when the window is exhausted), the binary sends a single
//! [`MapResult`] summary via `send_map_result`.
//!
//! Out of scope (single-image v1 — chain composition is deferred):
//! - Sources with a backing file (qcow2 with `backing_file_offset
//!   != 0`).
//! - Sources with a parent (vhdx differencing — already rejected
//!   by `VhdxState::init`; vhd differencing — rejected here).
//! - Multi-extent VMDK descriptors (already filtered by
//!   `VmdkState::init`'s VMDK4 binary header parse).
//! - LUKS source decryption.
//! - Snapshot extraction.
//!
//! If the source format is unrecognised or has a backing reference
//! the result reports the matching `ERROR_*` code; the host
//! renderer in phase 4 will translate to a clear user-facing
//! message.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    format_detection::detect_format_from_header, validate_call_table, CallTable, ImageFormat,
    MapConfig, MapExtent, MapExtentRecord, MapExtentState, MapResult, CALL_TABLE_ADDR,
    MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
};

/// Scratch memory layout for map: one header buffer plus two
/// per-parser cache buffers (each `MAX_SECTOR_SIZE` bytes).
///
/// Parser cache requirements (same as `operations/measure`):
/// - qcow2: L1 + L2 cache (uses CACHE_A + CACHE_B).
/// - vmdk:  GD + GT cache (uses CACHE_A + CACHE_B).
/// - vhd:   BAT + data cache (uses CACHE_A + CACHE_B).
/// - vhdx:  BAT + data cache (uses CACHE_A + CACHE_B).
///
/// Only one parser runs per map invocation so reusing two buffers
/// across parsers is safe.
const HEADER_BUF: usize = SCRATCH_MEM_BASE;
const CACHE_BUF_A: usize = HEADER_BUF + MAX_SECTOR_SIZE;
const CACHE_BUF_B: usize = CACHE_BUF_A + MAX_SECTOR_SIZE;

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Encode a parser-facing `MapExtent` into the FFI
/// `MapExtentRecord` form sent across the call-table boundary.
///
/// `STATE_DATA` records carry a `file_offset` from the enum
/// payload; the other states leave `file_offset` zero.
fn encode_extent(e: MapExtent) -> MapExtentRecord {
    let (state, file_offset) = match e.state {
        MapExtentState::Hole => (MapExtentRecord::STATE_HOLE, 0),
        MapExtentState::ZeroAllocated => (MapExtentRecord::STATE_ZERO_ALLOCATED, 0),
        MapExtentState::Data { file_offset } => (MapExtentRecord::STATE_DATA, file_offset),
    };
    MapExtentRecord {
        magic: MapExtentRecord::MAGIC,
        state,
        start: e.start,
        length: e.length,
        file_offset,
        _reserved: [0; 16],
    }
}

/// Clip an extent against the half-open window
/// `[window_start, window_end)`. Returns `Some(clipped)` if the
/// extent overlaps the window; `None` if it lies entirely
/// outside. The clipped extent's `file_offset` (when `Data`) is
/// adjusted forward by the amount trimmed off the front.
fn clip_to_window(e: MapExtent, window_start: u64, window_end: u64) -> Option<MapExtent> {
    let e_end = e.start.saturating_add(e.length);
    if e_end <= window_start || e.start >= window_end {
        return None;
    }
    let new_start = e.start.max(window_start);
    let new_end = e_end.min(window_end);
    let front_trim = new_start - e.start;
    let new_length = new_end - new_start;
    let new_state = match e.state {
        MapExtentState::Data { file_offset } => MapExtentState::Data {
            file_offset: file_offset.saturating_add(front_trim),
        },
        other => other,
    };
    Some(MapExtent {
        start: new_start,
        length: new_length,
        state: new_state,
    })
}

/// Build a populated `MapResult` and send it via the call table,
/// then signal `send_complete`.
///
/// # Safety
///
/// `call_table` must be the validated initialised CallTable from
/// `_start`.
unsafe fn finish(
    call_table: &CallTable,
    source_format: u32,
    extents_emitted: u64,
    virtual_size: u64,
    error: u32,
    bytes_read: u64,
) -> u64 {
    let result = MapResult {
        magic: MapResult::MAGIC,
        source_format,
        extents_emitted,
        virtual_size,
        error,
        _reserved: 0,
    };
    (call_table.send_map_result)(&result);
    let success = error == MapResult::ERROR_OK;
    (call_table.send_complete)(b"map\0".as_ptr(), bytes_read, success);
    bytes_read
}

/// Entry point.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`MapConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - Initialised input device 0 and routed virtio-block I/O
///   through the call table.
///
/// These invariants hold by construction of the host-side VMM
/// (`src/vmm/src/main.rs::run_map` in phase 3); no other caller
/// is architecturally possible.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "map");

    (call_table.verbose_print)(b"map: start\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const MapConfig);
    let sector_size_ok = config.sector_size >= 512
        && config.sector_size as usize <= MAX_SECTOR_SIZE
        && config.sector_size.is_power_of_two();
    if !config.is_valid() || !sector_size_ok || config.input_device_count != 1 {
        return finish(
            call_table,
            ImageFormat::Unknown as u32,
            0,
            0,
            MapResult::ERROR_INVALID_OPTION,
            0,
        );
    }

    let sector_size = config.sector_size as usize;
    let mut bytes_read: u64 = 0;

    // Read first sector for format detection.
    let header_ptr = HEADER_BUF as *mut u8;
    if !(call_table.read_input_sector)(0, 0, header_ptr, sector_size) {
        return finish(
            call_table,
            ImageFormat::Unknown as u32,
            0,
            0,
            MapResult::ERROR_IO,
            bytes_read,
        );
    }
    bytes_read += sector_size as u64;

    let header = core::slice::from_raw_parts(header_ptr, sector_size);
    let format = detect_format_from_header(header, sector_size, false);
    let source_format_u32 = format as u32;
    let input_capacity = (call_table.get_input_capacity)(0);
    let cache_a = CACHE_BUF_A as *mut u8;
    let cache_b = CACHE_BUF_B as *mut u8;

    // Resolve virtual_size and refuse backing/parent sources
    // before starting the walk.
    let virtual_size: u64 = match format {
        ImageFormat::Raw => match input_capacity.checked_mul(sector_size as u64) {
            Some(v) => v,
            None => {
                return finish(
                    call_table,
                    source_format_u32,
                    0,
                    0,
                    MapResult::ERROR_INVALID_SOURCE,
                    bytes_read,
                );
            }
        },
        ImageFormat::Qcow2 => {
            // Parse the header from the sector we already read so
            // we can both recover virtual_size and check for a
            // backing-file reference before initialising state.
            let parsed = match qcow2::QcowHeader::parse(header) {
                Some(p) => p,
                None => {
                    return finish(
                        call_table,
                        source_format_u32,
                        0,
                        0,
                        MapResult::ERROR_INVALID_SOURCE,
                        bytes_read,
                    );
                }
            };
            if parsed.backing_file_offset != 0 && parsed.backing_file_size != 0 {
                return finish(
                    call_table,
                    source_format_u32,
                    0,
                    parsed.virtual_size,
                    MapResult::ERROR_HAS_BACKING,
                    bytes_read,
                );
            }
            parsed.virtual_size
        }
        ImageFormat::Vmdk4 | ImageFormat::Vmdk3 => {
            // VmdkState::init only handles single-extent VMDK4
            // binary headers; multi-extent descriptor layouts fail
            // init naturally. We don't need an additional refusal
            // step here.
            0 // resolved after init below
        }
        ImageFormat::Vhd => 0,  // resolved after init below
        ImageFormat::Vhdx => 0, // VhdxState::init already rejects differencing.
        _ => {
            return finish(
                call_table,
                source_format_u32,
                0,
                0,
                MapResult::ERROR_INVALID_SOURCE,
                bytes_read,
            );
        }
    };

    // Coalescer + counter live across the walker dispatch so the
    // `extents_emitted` counter survives the walk. The closure
    // captures `&mut extents_emitted` and the call table.
    let mut extents_emitted: u64 = 0;

    // Resolve the emission window. `max_length == 0` means "to
    // end of image". Clamp window_end against virtual_size so a
    // user-supplied overshoot silently bounds at the image end.
    let resolve_window = |vsize: u64| -> (u64, u64) {
        let win_end = if config.max_length == 0 {
            vsize
        } else {
            config
                .start_offset
                .saturating_add(config.max_length)
                .min(vsize)
        };
        let win_start = config.start_offset.min(vsize);
        (win_start, win_end)
    };

    // Dispatch on format. For raw we skip init entirely (the
    // raw walker is pure). For the others, we init state and
    // then map_extents through the closure.
    //
    // Window-abort invariant: each emit closure returns false
    // once `e.start + e.length >= win_end` to stop the walker
    // early. This relies on every per-format walker emitting
    // contiguous extents in virtual-offset order — a chain-aware
    // shadowing walker (future work) that skips already-covered
    // ranges would need a different abort condition, since an
    // extent past the window does not imply no further in-window
    // extents.
    let walk_err: u32 = match format {
        ImageFormat::Raw => {
            let (win_start, win_end) = resolve_window(virtual_size);
            let mut emit = |e: MapExtent| -> bool {
                if let Some(clipped) = clip_to_window(e, win_start, win_end) {
                    let record = encode_extent(clipped);
                    (call_table.send_map_extent)(&record);
                    extents_emitted += 1;
                }
                // Stop the walker once the current extent's
                // virtual start has passed the window end. The
                // walker itself emits one final trailing extent
                // for the post-window range; we drop it.
                e.start.saturating_add(e.length) < win_end
            };
            match raw::map_extents(virtual_size, &mut emit) {
                Some(()) => MapResult::ERROR_OK,
                None => MapResult::ERROR_IO,
            }
        }
        ImageFormat::Qcow2 => {
            let mut state = match qcow2::Qcow2State::init(
                call_table,
                0,
                sector_size,
                input_capacity,
                cache_a,
                cache_b,
                &mut bytes_read,
            ) {
                Some(s) => s,
                None => {
                    return finish(
                        call_table,
                        source_format_u32,
                        0,
                        virtual_size,
                        MapResult::ERROR_INVALID_SOURCE,
                        bytes_read,
                    );
                }
            };
            let (win_start, win_end) = resolve_window(virtual_size);
            let mut emit = |e: MapExtent| -> bool {
                if let Some(clipped) = clip_to_window(e, win_start, win_end) {
                    let record = encode_extent(clipped);
                    (call_table.send_map_extent)(&record);
                    extents_emitted += 1;
                }
                e.start.saturating_add(e.length) < win_end
            };
            match state.map_extents(
                call_table,
                sector_size,
                input_capacity,
                virtual_size,
                &mut bytes_read,
                &mut emit,
            ) {
                Some(()) => MapResult::ERROR_OK,
                None => MapResult::ERROR_IO,
            }
        }
        ImageFormat::Vmdk4 | ImageFormat::Vmdk3 => {
            let actual_file_size = match input_capacity.checked_mul(sector_size as u64) {
                Some(s) => s,
                None => {
                    return finish(
                        call_table,
                        source_format_u32,
                        0,
                        0,
                        MapResult::ERROR_INVALID_SOURCE,
                        bytes_read,
                    );
                }
            };
            let mut state = match vmdk::VmdkState::init(
                call_table,
                0,
                sector_size,
                input_capacity,
                actual_file_size,
                cache_a,
                cache_b,
                &mut bytes_read,
            ) {
                Some(s) => s,
                None => {
                    return finish(
                        call_table,
                        source_format_u32,
                        0,
                        0,
                        MapResult::ERROR_INVALID_SOURCE,
                        bytes_read,
                    );
                }
            };
            let vsize = match state.capacity_sectors.checked_mul(512) {
                Some(v) => v,
                None => {
                    return finish(
                        call_table,
                        source_format_u32,
                        0,
                        0,
                        MapResult::ERROR_INVALID_SOURCE,
                        bytes_read,
                    );
                }
            };
            let (win_start, win_end) = resolve_window(vsize);
            let mut emit = |e: MapExtent| -> bool {
                if let Some(clipped) = clip_to_window(e, win_start, win_end) {
                    let record = encode_extent(clipped);
                    (call_table.send_map_extent)(&record);
                    extents_emitted += 1;
                }
                e.start.saturating_add(e.length) < win_end
            };
            let res = match state.map_extents(
                call_table,
                sector_size,
                input_capacity,
                &mut bytes_read,
                &mut emit,
            ) {
                Some(()) => MapResult::ERROR_OK,
                None => MapResult::ERROR_IO,
            };
            return finish(
                call_table,
                source_format_u32,
                extents_emitted,
                vsize,
                res,
                bytes_read,
            );
        }
        ImageFormat::Vhd => {
            let mut state = match vhd::VhdState::init(
                call_table,
                0,
                sector_size,
                input_capacity,
                cache_a,
                cache_b,
                &mut bytes_read,
            ) {
                Some(s) => s,
                None => {
                    return finish(
                        call_table,
                        source_format_u32,
                        0,
                        0,
                        MapResult::ERROR_INVALID_SOURCE,
                        bytes_read,
                    );
                }
            };
            // Differencing VHDs: refuse explicitly. VhdState::init
            // accepts both Dynamic and Differencing; the chain
            // follow-up will lift this restriction.
            if state.disk_type == vhd::DISK_TYPE_DIFFERENCING {
                return finish(
                    call_table,
                    source_format_u32,
                    0,
                    state.current_size,
                    MapResult::ERROR_HAS_BACKING,
                    bytes_read,
                );
            }
            let vsize = state.current_size;
            let (win_start, win_end) = resolve_window(vsize);
            let mut emit = |e: MapExtent| -> bool {
                if let Some(clipped) = clip_to_window(e, win_start, win_end) {
                    let record = encode_extent(clipped);
                    (call_table.send_map_extent)(&record);
                    extents_emitted += 1;
                }
                e.start.saturating_add(e.length) < win_end
            };
            let res = match state.map_extents(
                call_table,
                sector_size,
                input_capacity,
                &mut bytes_read,
                &mut emit,
            ) {
                Some(()) => MapResult::ERROR_OK,
                None => MapResult::ERROR_IO,
            };
            return finish(
                call_table,
                source_format_u32,
                extents_emitted,
                vsize,
                res,
                bytes_read,
            );
        }
        ImageFormat::Vhdx => {
            let mut state = match vhdx::VhdxState::init(
                call_table,
                0,
                sector_size,
                input_capacity,
                cache_a,
                cache_b,
                &mut bytes_read,
            ) {
                Some(s) => s,
                None => {
                    return finish(
                        call_table,
                        source_format_u32,
                        0,
                        0,
                        MapResult::ERROR_INVALID_SOURCE,
                        bytes_read,
                    );
                }
            };
            let vsize = state.virtual_disk_size;
            let (win_start, win_end) = resolve_window(vsize);
            let mut emit = |e: MapExtent| -> bool {
                if let Some(clipped) = clip_to_window(e, win_start, win_end) {
                    let record = encode_extent(clipped);
                    (call_table.send_map_extent)(&record);
                    extents_emitted += 1;
                }
                e.start.saturating_add(e.length) < win_end
            };
            let res = match state.map_extents(
                call_table,
                sector_size,
                input_capacity,
                &mut bytes_read,
                &mut emit,
            ) {
                Some(()) => MapResult::ERROR_OK,
                None => MapResult::ERROR_IO,
            };
            return finish(
                call_table,
                source_format_u32,
                extents_emitted,
                vsize,
                res,
                bytes_read,
            );
        }
        _ => unreachable!("format dispatch already validated above"),
    };

    finish(
        call_table,
        source_format_u32,
        extents_emitted,
        virtual_size,
        walk_err,
        bytes_read,
    )
}
