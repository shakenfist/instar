//! Snapshot operation: list / apply / create / delete qcow2 internal snapshots.
//!
//! v1 (this phase) implements `MODE_LIST` end-to-end against qcow2
//! sources and stubs the mutating modes (`MODE_APPLY`, `MODE_CREATE`,
//! `MODE_DELETE`). Phases 6-8 of `PLAN-snapshot.md` replace each stub
//! with the real planner; this binary's stubs return
//! `ERROR_INVALID_CONFIG` and emit a verbose-trace marker so the
//! intent is unambiguous.
//!
//! Flow:
//! 1. Read [`SnapshotConfig`] at [`OPERATION_CONFIG_ADDR`] and
//!    validate magic + sector-size invariant.
//! 2. Read sector 0 from device 0 and run
//!    [`detect_format_from_header`].
//! 3. Refuse non-qcow2 sources with `ERROR_UNSUPPORTED_FORMAT`.
//! 4. Parse the qcow2 header (`QcowHeader::parse`) to recover
//!    `virtual_size`, `nb_snapshots`, `snapshots_offset`.
//! 5. Dispatch on `config.mode`:
//!    - `MODE_LIST` (0): stream snapshot entries via
//!      [`qcow2::for_each_snapshot_entry`] and convert each entry to
//!      a [`SnapshotEntryRecord`] with
//!      [`qcow2::snapshot_entry_to_record`]; send via
//!      `call_table.send_snapshot_entry`.
//!    - `MODE_APPLY` / `MODE_CREATE` / `MODE_DELETE` (1/2/3): stub
//!      returns `ERROR_INVALID_CONFIG` (see open question 3 in
//!      `PLAN-snapshot-phase-03-list-guest.md`).
//!    - Otherwise: `ERROR_INVALID_CONFIG` for the unknown mode.
//! 6. Build a [`SnapshotResult`] and emit it via
//!    `send_snapshot_result`, then signal `send_complete`.
//!
//! Out of scope for v1 (deferred to later phases):
//! - Real `MODE_APPLY` / `MODE_CREATE` / `MODE_DELETE` planners
//!   (phases 5-8).
//! - Incompatible-feature refusal for mutating modes (phases 6-8;
//!   `MODE_LIST` works on any qcow2 per the master plan).
//! - Non-qcow2 sources (qemu-img matches: `qemu-img snapshot`
//!   refuses everything but qcow2).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    format_detection::detect_format_from_header, validate_call_table, CallTable, ImageFormat,
    SnapshotConfig, SnapshotResult, CALL_TABLE_ADDR, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR,
    SCRATCH_MEM_BASE,
};

/// Scratch memory layout for snapshot. v1 (list mode) only touches
/// `HEADER_BUF` (qcow2 header sector) and `CACHE_BUF_A` (snapshot-
/// table sector cache used by `qcow2::for_each_snapshot_entry`).
///
/// `CACHE_BUF_B` / `_C` / `_D` are reserved for phases 5+ (the
/// mutating planners need L1 / L2 / refcount caches). They are
/// declared here so phases 5-8 extend without renumbering scratch
/// addresses. Each slot is `MAX_SECTOR_SIZE` bytes; the total
/// (5 × `MAX_SECTOR_SIZE` = 320 KiB) is well within
/// `SCRATCH_MEM_SIZE`.
const HEADER_BUF: usize = SCRATCH_MEM_BASE;
const CACHE_BUF_A: usize = HEADER_BUF + MAX_SECTOR_SIZE;
#[allow(dead_code)]
const CACHE_BUF_B: usize = CACHE_BUF_A + MAX_SECTOR_SIZE;
#[allow(dead_code)]
const CACHE_BUF_C: usize = CACHE_BUF_B + MAX_SECTOR_SIZE;
#[allow(dead_code)]
const CACHE_BUF_D: usize = CACHE_BUF_C + MAX_SECTOR_SIZE;

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Build a populated `SnapshotResult` and send it via the call
/// table, then signal `send_complete` so the host VMM knows the
/// guest has finished.
///
/// `mode` is the echo of `SnapshotConfig.mode`. `error` is one of
/// `SnapshotResult::ERROR_*`. `snapshots_emitted` is the number of
/// `send_snapshot_entry` calls the guest made (populated for
/// `MODE_LIST`; zero otherwise). `bytes_read` is accumulated across
/// every input-sector read.
///
/// # Safety
///
/// `call_table` must be the validated initialised CallTable from
/// `_start`.
unsafe fn finish(
    call_table: &CallTable,
    mode: u32,
    error: u32,
    snapshots_emitted: u32,
    bytes_read: u64,
) -> u64 {
    let result = SnapshotResult {
        magic: SnapshotResult::MAGIC,
        mode,
        error,
        _pad: 0,
        snapshots_emitted,
        assigned_id_len: 0,
        assigned_id: [0; 64],
        _reserved: [0; 96],
    };
    (call_table.send_snapshot_result)(&result);
    let success = error == SnapshotResult::ERROR_OK;
    (call_table.send_complete)(b"snapshot\0".as_ptr(), bytes_read, success);
    bytes_read
}

/// Entry point.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`SnapshotConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - Initialised input device 0 and routed virtio-block I/O
///   through the call table.
///
/// These invariants hold by construction of the host-side VMM;
/// phase 4 of `PLAN-snapshot.md` adds the host CLI dispatch that
/// wires the snapshot path.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "snapshot");

    (call_table.verbose_print)(b"snapshot: start\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const SnapshotConfig);
    let sector_size_ok = config.sector_size >= 512
        && config.sector_size as usize <= MAX_SECTOR_SIZE
        && config.sector_size.is_power_of_two();
    if !config.is_valid() || !sector_size_ok {
        return finish(
            call_table,
            config.mode,
            SnapshotResult::ERROR_INVALID_CONFIG,
            0,
            0,
        );
    }

    let sector_size = config.sector_size as usize;
    let mut bytes_read: u64 = 0;

    // Read first sector for format detection and qcow2 header parse.
    let header_ptr = HEADER_BUF as *mut u8;
    if !(call_table.read_input_sector)(0, 0, header_ptr, sector_size) {
        return finish(
            call_table,
            config.mode,
            SnapshotResult::ERROR_IO,
            0,
            bytes_read,
        );
    }
    bytes_read += sector_size as u64;

    let header = core::slice::from_raw_parts(header_ptr, sector_size);
    let format = detect_format_from_header(header, sector_size, false);
    if format != ImageFormat::Qcow2 {
        (call_table.verbose_print)(b"snapshot: non-qcow2 source rejected\n\0".as_ptr());
        return finish(
            call_table,
            config.mode,
            SnapshotResult::ERROR_UNSUPPORTED_FORMAT,
            0,
            bytes_read,
        );
    }

    let hdr = match qcow2::QcowHeader::parse(header) {
        Some(h) => h,
        None => {
            return finish(
                call_table,
                config.mode,
                SnapshotResult::ERROR_PARSE_FAILED,
                0,
                bytes_read,
            );
        }
    };
    let virtual_size = hdr.virtual_size;
    let nb_snapshots = hdr.nb_snapshots;
    let snapshots_offset = hdr.snapshots_offset;

    match config.mode {
        SnapshotConfig::MODE_LIST => {
            if nb_snapshots == 0 {
                return finish(
                    call_table,
                    SnapshotConfig::MODE_LIST,
                    SnapshotResult::ERROR_OK,
                    0,
                    bytes_read,
                );
            }

            let input_capacity = (call_table.get_input_capacity)(0);
            let cache_a = CACHE_BUF_A as *mut u8;
            let mut snapshots_emitted: u32 = 0;
            let all_visited = qcow2::for_each_snapshot_entry(
                call_table,
                0,
                nb_snapshots,
                snapshots_offset,
                sector_size,
                input_capacity,
                cache_a,
                &mut bytes_read,
                |entry| -> bool {
                    let record = qcow2::snapshot_entry_to_record(entry, virtual_size);
                    (call_table.send_snapshot_entry)(&record);
                    snapshots_emitted += 1;
                    true
                },
            );
            if !all_visited {
                return finish(
                    call_table,
                    SnapshotConfig::MODE_LIST,
                    SnapshotResult::ERROR_IO,
                    snapshots_emitted,
                    bytes_read,
                );
            }
            finish(
                call_table,
                SnapshotConfig::MODE_LIST,
                SnapshotResult::ERROR_OK,
                snapshots_emitted,
                bytes_read,
            )
        }
        SnapshotConfig::MODE_APPLY => {
            (call_table.verbose_print)(b"snapshot: mode 1 not implemented in v1\n\0".as_ptr());
            finish(
                call_table,
                SnapshotConfig::MODE_APPLY,
                SnapshotResult::ERROR_INVALID_CONFIG,
                0,
                bytes_read,
            )
        }
        SnapshotConfig::MODE_CREATE => {
            (call_table.verbose_print)(b"snapshot: mode 2 not implemented in v1\n\0".as_ptr());
            finish(
                call_table,
                SnapshotConfig::MODE_CREATE,
                SnapshotResult::ERROR_INVALID_CONFIG,
                0,
                bytes_read,
            )
        }
        SnapshotConfig::MODE_DELETE => {
            (call_table.verbose_print)(b"snapshot: mode 3 not implemented in v1\n\0".as_ptr());
            finish(
                call_table,
                SnapshotConfig::MODE_DELETE,
                SnapshotResult::ERROR_INVALID_CONFIG,
                0,
                bytes_read,
            )
        }
        _ => finish(
            call_table,
            config.mode,
            SnapshotResult::ERROR_INVALID_CONFIG,
            0,
            bytes_read,
        ),
    }
}
