//! Amend operation: change an existing qcow2 image's compat
//! version (`compat=0.10`/`1.1`) and/or lazy-refcounts state.
//!
//! Phase 3 of `PLAN-amend`. The guest:
//!  1. Reads the [`AmendConfig`] the host wrote at
//!     [`OPERATION_CONFIG_ADDR`].
//!  2. Reads the first header cluster of the output device (the
//!     image, opened read-write).
//!  3. Re-parses the header and cross-checks it against the
//!     host-probed summary in the config (version, refcount_bits,
//!     the two feature words). A disagreement is
//!     `ERROR_HEADER_MISMATCH` (defensive, mirrors rebase).
//!  4. Calls the pure planner [`amend::plan_amend_qcow2`], which
//!     owns every refusal decision and the byte-exact header
//!     rewrite, and applies the returned patch(es) back to the
//!     header cluster via `write_output_sector` (read-modify-write
//!     through a bounce buffer for the partial-sector lazy toggle).
//!  5. Reports the action, resulting version / lazy state, and
//!     error code to the host.
//!
//! The planner is `no_std` and does no I/O; this binary supplies
//! the device reads/writes and the two scratch buffers it borrows
//! from (the read-only header cluster and a separate rebuild
//! scratch — the version-change path copies-and-adjusts the source
//! into `scratch`, so the two regions must not alias).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use amend::{plan_amend_qcow2, AmendAction, AmendError, AmendPatch, Qcow2AmendOpts};
use shared::{
    validate_call_table, AmendConfig, AmendResult, CallTable, ImageFormat, CALL_TABLE_ADDR,
    OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
};

// ---------------------------------------------------------------------------
// Scratch layout
// ---------------------------------------------------------------------------
//
// Amend touches only the first header cluster, so it needs three
// small regions inside SCRATCH_MEM_BASE..SCRATCH_MEM_END:
//
//   BOUNCE_BUF      — one sector, the read-modify-write staging
//                     buffer for partial-sector device I/O.
//   HEADER_CLUSTER  — the read-only first cluster handed to the
//                     planner as `header_cluster`.
//   PLANNER_SCRATCH — the byte buffer the planner builds the
//                     rewritten header into (version-change path);
//                     returned patches borrow from it.  Must not
//                     alias HEADER_CLUSTER.
//
// qcow2 clusters are 512 B .. 2 MiB; a 2 MiB ceiling for each
// region is generous and well within the ~12.9 MiB scratch window.

const MAX_CLUSTER: usize = 2 * 1024 * 1024;

const BOUNCE_BUF: usize = SCRATCH_MEM_BASE;
const BOUNCE_LIMIT: usize = MAX_CLUSTER;
const HEADER_CLUSTER: usize = BOUNCE_BUF + BOUNCE_LIMIT;
const HEADER_CLUSTER_LIMIT: usize = MAX_CLUSTER;
const PLANNER_SCRATCH: usize = HEADER_CLUSTER + HEADER_CLUSTER_LIMIT;
const PLANNER_SCRATCH_LIMIT: usize = MAX_CLUSTER;

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// ---------------------------------------------------------------------------
// Result construction
// ---------------------------------------------------------------------------

fn make_result(
    target_format: u32,
    action: u32,
    resulting_version: u32,
    resulting_lazy_refcounts: bool,
    error: u32,
) -> AmendResult {
    AmendResult {
        magic: AmendResult::MAGIC,
        target_format,
        action,
        error,
        resulting_version,
        resulting_lazy_refcounts: resulting_lazy_refcounts as u32,
        _reserved: [0u8; 40],
    }
}

/// Build an error result for the given wire code. No version /
/// lazy state is meaningful on a refusal, so they are reported as
/// zero with a no-op action.
fn err_result(target_format: u32, error: u32) -> AmendResult {
    make_result(target_format, AmendResult::ACTION_NOOP, 0, false, error)
}

/// Map an [`AmendError`] to the matching `AmendResult::ERROR_*`.
/// The planner's `error_code()` is the single source of truth.
fn map_error(e: AmendError) -> u32 {
    e.error_code()
}

// ---------------------------------------------------------------------------
// Sector-level I/O helpers
// ---------------------------------------------------------------------------

/// Read `len` bytes starting at `byte_offset` into the buffer at
/// `dst_ptr`. Handles non-sector-aligned starts/ends via the
/// bounce buffer at `BOUNCE_BUF` (clobbered on every partial read).
unsafe fn read_byte_range(
    call_table: &CallTable,
    sector_size: usize,
    byte_offset: u64,
    dst_ptr: *mut u8,
    len: usize,
) -> bool {
    if len == 0 {
        return true;
    }
    let bounce_ptr = BOUNCE_BUF as *mut u8;
    let mut done: usize = 0;
    let mut cur_offset = byte_offset;
    while done < len {
        let sector = cur_offset / sector_size as u64;
        let in_sector_off = (cur_offset % sector_size as u64) as usize;
        let take = (sector_size - in_sector_off).min(len - done);

        if in_sector_off == 0 && take == sector_size {
            let dst = dst_ptr.add(done);
            if !(call_table.read_output_sector)(sector, dst, sector_size) {
                return false;
            }
        } else {
            if !(call_table.read_output_sector)(sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(bounce_ptr.add(in_sector_off), dst_ptr.add(done), take);
        }
        done += take;
        cur_offset += take as u64;
    }
    true
}

/// Write `bytes` starting at `byte_offset`. Handles partial
/// leading/trailing sectors via read-modify-write through the
/// bounce buffer at `BOUNCE_BUF` (clobbered).
unsafe fn write_byte_range(
    call_table: &CallTable,
    sector_size: usize,
    byte_offset: u64,
    bytes: &[u8],
) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let bounce_ptr = BOUNCE_BUF as *mut u8;
    let mut done: usize = 0;
    let mut cur_offset = byte_offset;
    while done < bytes.len() {
        let sector = cur_offset / sector_size as u64;
        let in_sector_off = (cur_offset % sector_size as u64) as usize;
        let take = (sector_size - in_sector_off).min(bytes.len() - done);

        if in_sector_off == 0 && take == sector_size {
            let src = bytes.as_ptr().add(done);
            if !(call_table.write_output_sector)(sector, src, sector_size) {
                return false;
            }
        } else {
            // Read-modify-write.
            if !(call_table.read_output_sector)(sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(done),
                bounce_ptr.add(in_sector_off),
                take,
            );
            if !(call_table.write_output_sector)(sector, bounce_ptr, sector_size) {
                return false;
            }
        }
        done += take;
        cur_offset += take as u64;
    }
    true
}

// ---------------------------------------------------------------------------
// qcow2 runner
// ---------------------------------------------------------------------------

/// Read the header cluster, cross-check against the host-probed
/// summary, run the planner, and apply its patches.
unsafe fn run_qcow2(
    call_table: &CallTable,
    config: &AmendConfig,
    sector_size: usize,
) -> AmendResult {
    let cluster_size = config.cluster_size as usize;
    if cluster_size == 0
        || cluster_size > HEADER_CLUSTER_LIMIT
        || cluster_size > PLANNER_SCRATCH_LIMIT
    {
        return err_result(config.target_format, AmendResult::ERROR_SCRATCH_TOO_SMALL);
    }

    // Read the whole first cluster into the read-only header buffer.
    let header_ptr = HEADER_CLUSTER as *mut u8;
    if !read_byte_range(call_table, sector_size, 0, header_ptr, cluster_size) {
        return err_result(config.target_format, AmendResult::ERROR_PARSE_FAILED);
    }
    let header_cluster = core::slice::from_raw_parts(HEADER_CLUSTER as *const u8, cluster_size);

    // Re-parse and cross-check against the host-probed summary. A
    // disagreement means the image changed under us or the host
    // mis-probed; refuse defensively (mirrors rebase).
    let parsed = match qcow2::QcowHeader::parse(header_cluster) {
        Some(p) => p,
        None => return err_result(config.target_format, AmendResult::ERROR_PARSE_FAILED),
    };
    if parsed.version != config.current_version
        || parsed.refcount_bits != config.current_refcount_bits
        || parsed.incompatible_features != config.current_incompatible_features
        || parsed.compatible_features != config.current_compatible_features
        || parsed.cluster_size != config.cluster_size as u64
        || parsed.virtual_size != config.virtual_size
    {
        return err_result(config.target_format, AmendResult::ERROR_HEADER_MISMATCH);
    }

    // Defensive layout guard: the planner rewrites the entire first
    // cluster, which is correct only if cluster 0 holds nothing but
    // the header / extensions / backing string. qemu always places
    // the refcount table and L1 table at later clusters; if either
    // lives inside cluster 0 we would clobber metadata, so refuse.
    // (`!= 0` so an unallocated L1 on a zero-size image is not a
    // false positive — an absent table cannot overlap cluster 0.)
    let cluster_size_u64 = config.cluster_size as u64;
    if (parsed.refcount_table_offset != 0 && parsed.refcount_table_offset < cluster_size_u64)
        || (parsed.l1_table_offset != 0 && parsed.l1_table_offset < cluster_size_u64)
    {
        return err_result(config.target_format, AmendResult::ERROR_PARSE_FAILED);
    }

    // Translate config flags into planner opts.
    let opts = Qcow2AmendOpts {
        header_cluster,
        cluster_size: config.cluster_size,
        set_compat: config.flags & AmendConfig::FLAG_SET_COMPAT != 0,
        target_v3: config.flags & AmendConfig::FLAG_COMPAT_V3 != 0,
        set_lazy: config.flags & AmendConfig::FLAG_SET_LAZY != 0,
        lazy_on: config.flags & AmendConfig::FLAG_LAZY_ON != 0,
    };

    // Plan against a scratch region distinct from header_cluster
    // (the rebuild path copies the source into scratch).
    let scratch =
        core::slice::from_raw_parts_mut(PLANNER_SCRATCH as *mut u8, PLANNER_SCRATCH_LIMIT);
    let plan = match plan_amend_qcow2(&opts, scratch) {
        Ok(p) => p,
        Err(e) => return err_result(config.target_format, map_error(e)),
    };

    let action = match plan.action {
        AmendAction::NoOp => AmendResult::ACTION_NOOP,
        AmendAction::Amended => AmendResult::ACTION_AMENDED,
    };
    let resulting_version = plan.resulting_version;
    let resulting_lazy = plan.resulting_lazy_refcounts;

    // Apply the patch(es) in order. A NoOp plan has zero patches.
    for patch in plan.patches() {
        let AmendPatch::Write { byte_offset, bytes } = patch;
        if !write_byte_range(call_table, sector_size, *byte_offset, bytes) {
            return err_result(config.target_format, AmendResult::ERROR_WRITE_FAILED);
        }
    }

    make_result(
        config.target_format,
        action,
        resulting_version,
        resulting_lazy,
        AmendResult::ERROR_OK,
    )
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the amend operation.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`AmendConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - Attached the output device (the image to amend, opened
///   read-write).
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "amend");
    (call_table.verbose_print)(b"amend: start\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const AmendConfig);
    if !config.is_valid() {
        let result = err_result(
            ImageFormat::Unknown as u32,
            AmendResult::ERROR_INVALID_OPTION,
        );
        (call_table.send_amend_result)(&result);
        (call_table.send_complete)(b"amend\0".as_ptr(), 0, false);
        return 0;
    }

    let sector_size = (call_table.get_output_sector_size)();

    // v1 is qcow2-only; the host launches the guest only for qcow2,
    // but defend in depth against any other target_format.
    let result = if config.target_format == ImageFormat::Qcow2 as u32 {
        run_qcow2(call_table, config, sector_size)
    } else {
        err_result(config.target_format, AmendResult::ERROR_UNSUPPORTED_FORMAT)
    };

    let ok = result.error == AmendResult::ERROR_OK;
    // Report the header cluster as the bytes processed when we
    // actually rewrote it; a no-op or refusal touched nothing.
    let bytes = if result.action == AmendResult::ACTION_AMENDED {
        config.cluster_size as u64
    } else {
        0
    };
    (call_table.send_amend_result)(&result);
    (call_table.send_complete)(b"amend\0".as_ptr(), bytes, ok);
    0
}
