//! Resize operation: in-place mutation of an existing disk image.
//!
//! Phase 7 of `PLAN-resize.md`.  Reads a `ResizeConfig` from
//! `OPERATION_CONFIG_ADDR`, reads sector 0 of the output device,
//! detects the format, runs the format-specific pre-pass that
//! stages every byte range the planner's opts struct needs,
//! calls the matching `crates/resize::plan_resize_*`, and
//! applies the resulting patches via `write_output_sector` (with
//! read-modify-write through the new `read_output_sector` call-
//! table primitive for partial-sector patches).
//!
//! Out of scope:
//!  - Preallocation modes (phase 9 handles host-side).
//!  - QCOW2 `Preallocation::Metadata` (deferred to phase 9 — the
//!    planner already rejects it with `PreallocationUnsupported`).
//!  - Backing-chain composition (resize doesn't touch backing
//!    references; matches qemu).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use resize::{
    plan_resize_qcow2, plan_resize_raw, plan_resize_vhd, plan_resize_vhdx, plan_resize_vmdk,
    Preallocation, Qcow2ResizeOpts, RawResizeOpts, ResizeAction, ResizeError, ResizePatch,
    ResizePlan, VhdResizeOpts, VhdSubformat, VhdxResizeOpts, VmdkResizeOpts, VmdkSubformat,
};
use shared::{
    be_u64, format_detection::detect_format_from_header, le_u32, le_u64, validate_call_table,
    CallTable, ImageFormat, ResizeConfig, ResizeResult, CALL_TABLE_ADDR, MAX_SECTOR_SIZE,
    OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
};

// ---------------------------------------------------------------------------
// Scratch layout
// ---------------------------------------------------------------------------
//
// The resize guest uses three contiguous scratch regions inside
// SCRATCH_MEM_BASE..SCRATCH_MEM_END (~12.9 MiB total):
//
//   HEADER_BUF        — first sector of the output device (format probe).
//   EXISTING_STATE    — staged existing-file metadata (L1, refcount
//                       table+blocks, BAT, descriptor, etc.) the
//                       planner borrows from.  4 MiB is enough for
//                       every realistic image at every format.
//   PLANNER_SCRATCH   — the byte buffer passed to plan_resize_*.
//                       8 MiB ceiling (mirrors GUEST_CREATE_SCRATCH_LIMIT).

const HEADER_BUF: usize = SCRATCH_MEM_BASE;
const EXISTING_STATE: usize = HEADER_BUF + MAX_SECTOR_SIZE;
const EXISTING_STATE_LIMIT: usize = 4 * 1024 * 1024;
const PLANNER_SCRATCH: usize = EXISTING_STATE + EXISTING_STATE_LIMIT;
const PLANNER_SCRATCH_LIMIT: usize = 8 * 1024 * 1024;

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

#[allow(clippy::too_many_arguments)]
unsafe fn send_result(
    call_table: &CallTable,
    target: u32,
    resolved_new_virtual_size: u64,
    file_size_before: u64,
    file_size_after: u64,
    action: u32,
    error: u32,
) {
    let result = ResizeResult {
        magic: ResizeResult::MAGIC,
        target_format: target,
        resolved_new_virtual_size,
        file_size_before,
        file_size_after,
        action,
        error,
    };
    (call_table.send_resize_result)(&result);
}

fn encode_action(a: ResizeAction) -> u32 {
    match a {
        ResizeAction::NoOp => ResizeResult::ACTION_NOOP,
        ResizeAction::Grow => ResizeResult::ACTION_GROW,
        ResizeAction::Shrink => ResizeResult::ACTION_SHRINK,
    }
}

/// Map a `ResizeError` to the matching `ResizeResult::ERROR_*`.
fn map_error(e: ResizeError) -> u32 {
    match e {
        ResizeError::InvalidNewVirtualSize => ResizeResult::ERROR_INVALID_NEW_SIZE,
        ResizeError::ShrinkWithoutFlag => ResizeResult::ERROR_SHRINK_WITHOUT_FLAG,
        ResizeError::ShrinkBelowAllocated => ResizeResult::ERROR_SHRINK_BELOW_ALLOCATED,
        ResizeError::UnsupportedFormat => ResizeResult::ERROR_UNSUPPORTED_FORMAT,
        ResizeError::UnsupportedSubformat => ResizeResult::ERROR_UNSUPPORTED_SUBFORMAT,
        ResizeError::UnsupportedShrink => ResizeResult::ERROR_UNSUPPORTED_SHRINK,
        ResizeError::PreallocationUnsupported => ResizeResult::ERROR_PREALLOCATION_UNSUPPORTED,
        ResizeError::Overflow => ResizeResult::ERROR_INVALID_NEW_SIZE,
        ResizeError::ScratchTooSmall => ResizeResult::ERROR_SCRATCH_TOO_SMALL,
        ResizeError::RequiresCheckFirst => ResizeResult::ERROR_PARSE_FAILED,
        ResizeError::HeaderMismatch => ResizeResult::ERROR_HEADER_MISMATCH,
        ResizeError::ParseFailed => ResizeResult::ERROR_PARSE_FAILED,
    }
}

fn map_prealloc(flags: u32) -> Preallocation {
    match flags & ResizeConfig::PREALLOC_MASK {
        ResizeConfig::PREALLOC_METADATA => Preallocation::Metadata,
        ResizeConfig::PREALLOC_FALLOC => Preallocation::Falloc,
        ResizeConfig::PREALLOC_FULL => Preallocation::Full,
        _ => Preallocation::Off,
    }
}

// ---------------------------------------------------------------------------
// Sector-level I/O helpers
// ---------------------------------------------------------------------------

/// Read `len` bytes starting at `byte_offset` into the buffer at
/// `dst_ptr`.  Handles non-sector-aligned starts/ends via a small
/// bounce buffer in `HEADER_BUF` (clobbered on every call —
/// caller must not depend on previous header contents).
#[allow(clippy::too_many_arguments)]
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
    let bounce_ptr = HEADER_BUF as *mut u8;
    let mut written: usize = 0;
    let mut cur_offset = byte_offset;
    while written < len {
        let sector = cur_offset / sector_size as u64;
        let in_sector_off = (cur_offset % sector_size as u64) as usize;
        let take = (sector_size - in_sector_off).min(len - written);

        if in_sector_off == 0 && take == sector_size {
            // Aligned full-sector read straight into dst.
            let dst = dst_ptr.add(written);
            if !(call_table.read_output_sector)(sector, dst, sector_size) {
                return false;
            }
        } else {
            // Partial-sector read: read via bounce buffer.
            if !(call_table.read_output_sector)(sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(
                bounce_ptr.add(in_sector_off),
                dst_ptr.add(written),
                take,
            );
        }
        written += take;
        cur_offset += take as u64;
    }
    true
}

/// Write `bytes` starting at `byte_offset`.  Handles partial
/// leading/trailing sectors via read-modify-write through the
/// bounce buffer at `HEADER_BUF` (clobbered).
unsafe fn write_byte_range(
    call_table: &CallTable,
    sector_size: usize,
    byte_offset: u64,
    bytes: &[u8],
) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let bounce_ptr = HEADER_BUF as *mut u8;
    let mut written: usize = 0;
    let mut cur_offset = byte_offset;
    while written < bytes.len() {
        let sector = cur_offset / sector_size as u64;
        let in_sector_off = (cur_offset % sector_size as u64) as usize;
        let take = (sector_size - in_sector_off).min(bytes.len() - written);

        if in_sector_off == 0 && take == sector_size {
            // Aligned full-sector write.
            let src = bytes.as_ptr().add(written);
            if !(call_table.write_output_sector)(sector, src, sector_size) {
                return false;
            }
        } else {
            // Read-modify-write.
            if !(call_table.read_output_sector)(sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(written),
                bounce_ptr.add(in_sector_off),
                take,
            );
            if !(call_table.write_output_sector)(sector, bounce_ptr, sector_size) {
                return false;
            }
        }
        written += take;
        cur_offset += take as u64;
    }
    true
}

/// Zero `len` bytes at `byte_offset`.
unsafe fn zero_byte_range(
    call_table: &CallTable,
    sector_size: usize,
    byte_offset: u64,
    len: u64,
) -> bool {
    if len == 0 {
        return true;
    }
    // Reuse the bounce buffer as a zero sector; for full-sector
    // ranges we issue a fresh zeroed write each iteration.
    let bounce_ptr = HEADER_BUF as *mut u8;
    let bounce = core::slice::from_raw_parts_mut(bounce_ptr, sector_size);
    bounce.fill(0);

    let mut written: u64 = 0;
    let mut cur_offset = byte_offset;
    while written < len {
        let sector = cur_offset / sector_size as u64;
        let in_sector_off = (cur_offset % sector_size as u64) as usize;
        let take = (sector_size as u64 - in_sector_off as u64).min(len - written);

        if in_sector_off == 0 && take == sector_size as u64 {
            if !(call_table.write_output_sector)(sector, bounce_ptr, sector_size) {
                return false;
            }
        } else {
            // Partial sector: RMW.  Read the sector into a separate
            // staging area (not the bounce we filled with zeros).
            // Reuse the tail of EXISTING_STATE for a one-sector
            // staging slot.
            let staging_ptr = (EXISTING_STATE + EXISTING_STATE_LIMIT - sector_size) as *mut u8;
            if !(call_table.read_output_sector)(sector, staging_ptr, sector_size) {
                return false;
            }
            core::ptr::write_bytes(staging_ptr.add(in_sector_off), 0, take as usize);
            if !(call_table.write_output_sector)(sector, staging_ptr, sector_size) {
                return false;
            }
        }
        written += take;
        cur_offset += take;
    }
    true
}

/// Apply a complete `ResizePlan` to the output device.  Patches
/// are emitted in slice order — the planner's prepare → commit →
/// cleanup partition is preserved unchanged.
unsafe fn apply_plan(call_table: &CallTable, plan: &ResizePlan<'_>) -> bool {
    let sector_size = (call_table.get_output_sector_size)();
    for patch in plan.patches() {
        let ok = match patch {
            ResizePatch::Write { byte_offset, bytes }
            | ResizePatch::Append { byte_offset, bytes } => {
                write_byte_range(call_table, sector_size, *byte_offset, bytes)
            }
            ResizePatch::ZeroFill { byte_offset, len } => {
                zero_byte_range(call_table, sector_size, *byte_offset, *len)
            }
        };
        if !ok {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Per-format runners
// ---------------------------------------------------------------------------

/// Raw resize is fully host-side; if the host launched the guest
/// for a raw image it's a bug, but we still return a clean NoOp
/// so the host gets a defined error path.
unsafe fn run_raw(config: &ResizeConfig) -> ResizeResult {
    let opts = RawResizeOpts {
        current_virtual_size: config.current_virtual_size,
        new_virtual_size: config.new_virtual_size,
        preallocation: map_prealloc(config.flags),
    };
    match plan_resize_raw(&opts) {
        Ok(plan) => ResizeResult {
            magic: ResizeResult::MAGIC,
            target_format: config.target_format,
            resolved_new_virtual_size: config.new_virtual_size,
            file_size_before: config.current_virtual_size,
            file_size_after: plan.total_file_size,
            action: encode_action(plan.action),
            error: ResizeResult::ERROR_OK,
        },
        Err(e) => err_result(config, map_error(e)),
    }
}

fn err_result(config: &ResizeConfig, error: u32) -> ResizeResult {
    ResizeResult {
        magic: ResizeResult::MAGIC,
        target_format: config.target_format,
        resolved_new_virtual_size: 0,
        file_size_before: config.current_virtual_size,
        file_size_after: 0,
        action: ResizeResult::ACTION_NOOP,
        error,
    }
}

// --- QCOW2 ---

/// QCOW2 pre-pass + planner dispatch + applicator.
unsafe fn run_qcow2(
    call_table: &CallTable,
    config: &ResizeConfig,
    file_size_before: u64,
) -> ResizeResult {
    let sector_size = (call_table.get_output_sector_size)();
    let header = core::slice::from_raw_parts(HEADER_BUF as *const u8, sector_size);
    let parsed = match qcow2::QcowHeader::parse(header) {
        Some(p) => p,
        None => return err_result(config, ResizeResult::ERROR_PARSE_FAILED),
    };

    let cluster_size = parsed.cluster_size as usize;
    if cluster_size == 0 || cluster_size > 2 * 1024 * 1024 {
        return err_result(config, ResizeResult::ERROR_PARSE_FAILED);
    }

    // Stage layout: L1 region + refcount table + N refcount blocks.
    let l1_bytes = (parsed.l1_size as usize) * 8;
    let rt_bytes = (parsed.refcount_table_clusters as usize) * cluster_size;

    let l1_off = 0usize;
    let l1_end = l1_off + l1_bytes;
    let rt_off = l1_end;
    let rt_end = rt_off + rt_bytes;
    if rt_end > EXISTING_STATE_LIMIT {
        return err_result(config, ResizeResult::ERROR_SCRATCH_TOO_SMALL);
    }

    let state_base = EXISTING_STATE as *mut u8;
    if !read_byte_range(
        call_table,
        sector_size,
        parsed.l1_table_offset,
        state_base.add(l1_off),
        l1_bytes,
    ) {
        return err_result(config, ResizeResult::ERROR_READ_FAILED);
    }
    if !read_byte_range(
        call_table,
        sector_size,
        parsed.refcount_table_offset,
        state_base.add(rt_off),
        rt_bytes,
    ) {
        return err_result(config, ResizeResult::ERROR_READ_FAILED);
    }

    // Determine which refcount blocks the planner needs.  Phase 7c
    // stages every block referenced by the refcount table — covers
    // every grow/shrink case at the cost of bandwidth.  Large
    // images can blow EXISTING_STATE_LIMIT; we return
    // ScratchTooSmall in that case.
    let rt_slice = core::slice::from_raw_parts(state_base.add(rt_off), rt_bytes);
    const MAX_RB_INDICES: usize = 1024;
    let mut block_indices: [u64; MAX_RB_INDICES] = [0; MAX_RB_INDICES];
    let mut block_count: usize = 0;
    let mut i = 0;
    while i + 8 <= rt_slice.len() {
        let entry = be_u64(rt_slice, i);
        if entry != 0 {
            if block_count >= MAX_RB_INDICES {
                return err_result(config, ResizeResult::ERROR_SCRATCH_TOO_SMALL);
            }
            block_indices[block_count] = (i / 8) as u64;
            block_count += 1;
        }
        i += 8;
    }

    let blocks_off = rt_end;
    let blocks_total = block_count * cluster_size;
    if blocks_off + blocks_total > EXISTING_STATE_LIMIT {
        return err_result(config, ResizeResult::ERROR_SCRATCH_TOO_SMALL);
    }
    for (slot, &block_idx) in block_indices[..block_count].iter().enumerate() {
        let block_file_off = be_u64(rt_slice, (block_idx as usize) * 8);
        if !read_byte_range(
            call_table,
            sector_size,
            block_file_off,
            state_base.add(blocks_off + slot * cluster_size),
            cluster_size,
        ) {
            return err_result(config, ResizeResult::ERROR_READ_FAILED);
        }
    }

    // L2 staging for shrink: stage every L2 the planner could
    // need.  Walk L1; for each non-zero entry whose coverage
    // intersects [new_virtual_size, current_virtual_size], stage
    // the L2 table.  We use the byte region after the refcount
    // blocks.
    let l2_off = blocks_off + blocks_total;
    let mut staged_l2: [u32; 256] = [0; 256];
    let mut staged_l2_count: usize = 0;
    let mut l2_bytes_total: usize = 0;

    if config.new_virtual_size < config.current_virtual_size {
        let l2_entry_size: u64 = if parsed.extended_l2 { 16 } else { 8 };
        let entries_per_l2 = parsed.cluster_size / l2_entry_size;
        let l2_coverage = parsed.cluster_size * entries_per_l2;

        let l1_slice = core::slice::from_raw_parts(state_base.add(l1_off), l1_bytes);
        for li in 0..parsed.l1_size as usize {
            let base_virtual = (li as u64) * l2_coverage;
            let l2_end_virtual = base_virtual + l2_coverage;
            if l2_end_virtual <= config.new_virtual_size {
                continue;
            }
            if base_virtual >= config.current_virtual_size {
                continue;
            }
            let entry = be_u64(l1_slice, li * 8);
            if entry == 0 {
                continue;
            }
            if staged_l2_count >= staged_l2.len() {
                return err_result(config, ResizeResult::ERROR_SCRATCH_TOO_SMALL);
            }
            let l2_host = entry & qcow2::L2_OFFSET_MASK;
            let slot = l2_off + staged_l2_count * cluster_size;
            if slot + cluster_size > EXISTING_STATE_LIMIT {
                return err_result(config, ResizeResult::ERROR_SCRATCH_TOO_SMALL);
            }
            if !read_byte_range(
                call_table,
                sector_size,
                l2_host,
                state_base.add(slot),
                cluster_size,
            ) {
                return err_result(config, ResizeResult::ERROR_READ_FAILED);
            }
            staged_l2[staged_l2_count] = li as u32;
            staged_l2_count += 1;
            l2_bytes_total += cluster_size;
        }
    }

    let existing_l1 = core::slice::from_raw_parts(state_base.add(l1_off), l1_bytes);
    let existing_rt = core::slice::from_raw_parts(state_base.add(rt_off), rt_bytes);
    let existing_rb = core::slice::from_raw_parts(state_base.add(blocks_off), blocks_total);
    let existing_l2 = core::slice::from_raw_parts(state_base.add(l2_off), l2_bytes_total);
    let existing_l2_indices = &staged_l2[..staged_l2_count];

    let opts = Qcow2ResizeOpts {
        current_virtual_size: config.current_virtual_size,
        new_virtual_size: config.new_virtual_size,
        cluster_size: parsed.cluster_size as u32,
        refcount_bits: parsed.refcount_bits as u8,
        extended_l2: parsed.extended_l2,
        preallocation: map_prealloc(config.flags),
        allow_shrink: config.allow_shrink(),
        existing_l1_bytes: existing_l1,
        existing_refcount_table_bytes: existing_rt,
        existing_refcount_block_bytes: existing_rb,
        existing_refcount_block_indices: &block_indices[..block_count],
        existing_l2_bytes: existing_l2,
        existing_l2_indices,
        current_file_size: file_size_before,
        current_l1_entries: parsed.l1_size,
        current_l1_table_offset: parsed.l1_table_offset,
        current_refcount_table_offset: parsed.refcount_table_offset,
        current_refcount_table_clusters: parsed.refcount_table_clusters,
        current_incompatible_features: parsed.incompatible_features,
        backing_file: None,
        backing_format: None,
        lazy_refcounts: parsed.lazy_refcounts,
    };

    let scratch =
        core::slice::from_raw_parts_mut(PLANNER_SCRATCH as *mut u8, PLANNER_SCRATCH_LIMIT);
    let plan = match plan_resize_qcow2(&opts, scratch) {
        Ok(p) => p,
        Err(e) => return err_result(config, map_error(e)),
    };
    let action = plan.action;
    let total = plan.total_file_size;
    if !apply_plan(call_table, &plan) {
        return err_result(config, ResizeResult::ERROR_WRITE_FAILED);
    }

    ResizeResult {
        magic: ResizeResult::MAGIC,
        target_format: config.target_format,
        resolved_new_virtual_size: config.new_virtual_size,
        file_size_before,
        file_size_after: total,
        action: encode_action(action),
        error: ResizeResult::ERROR_OK,
    }
}

// --- VHD ---

unsafe fn run_vhd(
    call_table: &CallTable,
    config: &ResizeConfig,
    file_size_before: u64,
) -> ResizeResult {
    let sector_size = (call_table.get_output_sector_size)();
    // VHD footer lives at the end of the file (last 512 bytes).
    // Read the tail footer for current_size verification.
    let state_base = EXISTING_STATE as *mut u8;
    let footer_off = 0usize;
    let dyn_hdr_off = footer_off + 512;
    let bat_off = dyn_hdr_off + 1024;

    if file_size_before < 512 {
        return err_result(config, ResizeResult::ERROR_PARSE_FAILED);
    }
    if !read_byte_range(
        call_table,
        sector_size,
        file_size_before - 512,
        state_base.add(footer_off),
        512,
    ) {
        return err_result(config, ResizeResult::ERROR_READ_FAILED);
    }
    let footer_slice = core::slice::from_raw_parts(state_base.add(footer_off), 512);
    let parsed_footer = match vhd::VhdFooter::parse(footer_slice) {
        Some(p) => p,
        None => return err_result(config, ResizeResult::ERROR_PARSE_FAILED),
    };

    let subformat = match parsed_footer.disk_type {
        vhd::DISK_TYPE_FIXED => VhdSubformat::Fixed,
        vhd::DISK_TYPE_DYNAMIC => VhdSubformat::Dynamic,
        vhd::DISK_TYPE_DIFFERENCING => {
            return err_result(config, ResizeResult::ERROR_UNSUPPORTED_SUBFORMAT)
        }
        _ => return err_result(config, ResizeResult::ERROR_UNSUPPORTED_FORMAT),
    };

    let (dyn_bytes, bat_bytes, current_table_offset, current_max_entries, block_size) =
        if matches!(subformat, VhdSubformat::Dynamic) {
            // Dynamic has the head footer at offset 0 + dynamic header at 512.
            if !read_byte_range(
                call_table,
                sector_size,
                512,
                state_base.add(dyn_hdr_off),
                1024,
            ) {
                return err_result(config, ResizeResult::ERROR_READ_FAILED);
            }
            let dyn_slice = core::slice::from_raw_parts(state_base.add(dyn_hdr_off), 1024);
            let parsed_dyn = match vhd::VhdDynamicHeader::parse(dyn_slice) {
                Some(p) => p,
                None => return err_result(config, ResizeResult::ERROR_PARSE_FAILED),
            };
            let bat_len = (parsed_dyn.max_table_entries as usize) * 4;
            let bat_aligned = bat_len.next_multiple_of(512);
            if bat_off + bat_aligned > EXISTING_STATE_LIMIT {
                return err_result(config, ResizeResult::ERROR_SCRATCH_TOO_SMALL);
            }
            if !read_byte_range(
                call_table,
                sector_size,
                parsed_dyn.table_offset,
                state_base.add(bat_off),
                bat_aligned,
            ) {
                return err_result(config, ResizeResult::ERROR_READ_FAILED);
            }
            (
                core::slice::from_raw_parts(state_base.add(dyn_hdr_off), 1024),
                core::slice::from_raw_parts(state_base.add(bat_off), bat_aligned),
                parsed_dyn.table_offset,
                parsed_dyn.max_table_entries,
                parsed_dyn.block_size,
            )
        } else {
            (&[] as &[u8], &[] as &[u8], 0u64, 0u32, 0u32)
        };

    let opts = VhdResizeOpts {
        current_virtual_size: config.current_virtual_size,
        new_virtual_size: config.new_virtual_size,
        block_size,
        subformat,
        allow_shrink: config.allow_shrink(),
        preallocation: map_prealloc(config.flags),
        existing_footer: footer_slice,
        existing_dynamic_header: dyn_bytes,
        existing_bat: bat_bytes,
        current_file_size: file_size_before,
        disk_type: parsed_footer.disk_type,
        current_table_offset,
        current_max_table_entries: current_max_entries,
    };

    let scratch =
        core::slice::from_raw_parts_mut(PLANNER_SCRATCH as *mut u8, PLANNER_SCRATCH_LIMIT);
    let plan = match plan_resize_vhd(&opts, scratch) {
        Ok(p) => p,
        Err(e) => return err_result(config, map_error(e)),
    };
    let action = plan.action;
    let total = plan.total_file_size;
    if !apply_plan(call_table, &plan) {
        return err_result(config, ResizeResult::ERROR_WRITE_FAILED);
    }
    ResizeResult {
        magic: ResizeResult::MAGIC,
        target_format: config.target_format,
        resolved_new_virtual_size: config.new_virtual_size,
        file_size_before,
        file_size_after: total,
        action: encode_action(action),
        error: ResizeResult::ERROR_OK,
    }
}

// --- VHDX ---

unsafe fn run_vhdx(
    call_table: &CallTable,
    config: &ResizeConfig,
    file_size_before: u64,
) -> ResizeResult {
    let sector_size = (call_table.get_output_sector_size)();
    let state_base = EXISTING_STATE as *mut u8;

    // Read both headers, pick the higher-sequence one.
    let header1_off = 0usize;
    let header2_off = 4096;
    let region_table_off = header2_off + 4096;
    let metadata_off = region_table_off + 64 * 1024;
    let bat_off = metadata_off + 1 * 1024 * 1024;

    if !read_byte_range(
        call_table,
        sector_size,
        0x10000,
        state_base.add(header1_off),
        4096,
    ) {
        return err_result(config, ResizeResult::ERROR_READ_FAILED);
    }
    if !read_byte_range(
        call_table,
        sector_size,
        0x20000,
        state_base.add(header2_off),
        4096,
    ) {
        return err_result(config, ResizeResult::ERROR_READ_FAILED);
    }

    let h1_slice = core::slice::from_raw_parts(state_base.add(header1_off), 4096);
    let h2_slice = core::slice::from_raw_parts(state_base.add(header2_off), 4096);
    let h1 = vhdx::VhdxHeader::parse(h1_slice);
    let h2 = vhdx::VhdxHeader::parse(h2_slice);

    let (active_offset, active_seq, active_bytes) = match (h1, h2) {
        (Some(a), Some(b)) if a.sequence_number >= b.sequence_number => {
            (vhdx::HEADER1_OFFSET, a.sequence_number, h1_slice)
        }
        (Some(_), Some(b)) => (vhdx::HEADER2_OFFSET, b.sequence_number, h2_slice),
        (Some(a), None) => (vhdx::HEADER1_OFFSET, a.sequence_number, h1_slice),
        (None, Some(b)) => (vhdx::HEADER2_OFFSET, b.sequence_number, h2_slice),
        (None, None) => return err_result(config, ResizeResult::ERROR_PARSE_FAILED),
    };

    // Region table copy 1 at 0x30000 (64 KiB).
    if !read_byte_range(
        call_table,
        sector_size,
        vhdx::REGION_TABLE1_OFFSET,
        state_base.add(region_table_off),
        64 * 1024,
    ) {
        return err_result(config, ResizeResult::ERROR_READ_FAILED);
    }
    let rt_slice = core::slice::from_raw_parts(state_base.add(region_table_off), 64 * 1024);
    let (entries, _count) = match vhdx::parse_region_table(rt_slice) {
        Some(v) => v,
        None => return err_result(config, ResizeResult::ERROR_PARSE_FAILED),
    };
    let bat_entry = &entries[0];
    let metadata_entry = &entries[1];

    // Read the metadata region (1 MiB) so we can decode
    // VirtualDiskSize directly.
    if !read_byte_range(
        call_table,
        sector_size,
        metadata_entry.file_offset,
        state_base.add(metadata_off),
        metadata_entry.length as usize,
    ) {
        return err_result(config, ResizeResult::ERROR_READ_FAILED);
    }
    let metadata_slice =
        core::slice::from_raw_parts(state_base.add(metadata_off), metadata_entry.length as usize);
    let _stored_vds = le_u64(metadata_slice, 0x10008);
    // (We trust the planner's HeaderMismatch check; no extra
    // validation here.)

    // Read the BAT region.
    let bat_len = bat_entry.length as usize;
    if bat_off + bat_len > EXISTING_STATE_LIMIT {
        return err_result(config, ResizeResult::ERROR_SCRATCH_TOO_SMALL);
    }
    if !read_byte_range(
        call_table,
        sector_size,
        bat_entry.file_offset,
        state_base.add(bat_off),
        bat_len,
    ) {
        return err_result(config, ResizeResult::ERROR_READ_FAILED);
    }
    let bat_slice = core::slice::from_raw_parts(state_base.add(bat_off), bat_len);
    let current_total_bat_entries = (bat_len / 8) as u32;

    // Read block_size from the FileParameters metadata item.
    let block_size = le_u32(metadata_slice, 0x10000);

    let opts = VhdxResizeOpts {
        current_virtual_size: config.current_virtual_size,
        new_virtual_size: config.new_virtual_size,
        block_size,
        preallocation: map_prealloc(config.flags),
        allow_shrink: config.allow_shrink(),
        existing_active_header: active_bytes,
        current_active_header_offset: active_offset,
        current_sequence_number: active_seq,
        existing_region_table: rt_slice,
        existing_bat: bat_slice,
        current_bat_offset: bat_entry.file_offset,
        current_bat_length: bat_entry.length,
        current_total_bat_entries,
        current_metadata_offset: metadata_entry.file_offset,
        current_metadata_length: metadata_entry.length,
        logical_sector_size: 512,
        physical_sector_size: 4096,
        has_parent: false,
        current_file_size: file_size_before,
    };

    let scratch =
        core::slice::from_raw_parts_mut(PLANNER_SCRATCH as *mut u8, PLANNER_SCRATCH_LIMIT);
    let plan = match plan_resize_vhdx(&opts, scratch) {
        Ok(p) => p,
        Err(e) => return err_result(config, map_error(e)),
    };
    let action = plan.action;
    let total = plan.total_file_size;
    if !apply_plan(call_table, &plan) {
        return err_result(config, ResizeResult::ERROR_WRITE_FAILED);
    }
    ResizeResult {
        magic: ResizeResult::MAGIC,
        target_format: config.target_format,
        resolved_new_virtual_size: config.new_virtual_size,
        file_size_before,
        file_size_after: total,
        action: encode_action(action),
        error: ResizeResult::ERROR_OK,
    }
}

// --- VMDK ---

unsafe fn run_vmdk(
    call_table: &CallTable,
    config: &ResizeConfig,
    file_size_before: u64,
) -> ResizeResult {
    let sector_size = (call_table.get_output_sector_size)();
    let state_base = EXISTING_STATE as *mut u8;
    let header_off = 0usize;
    let desc_off = header_off + 512;

    // Header is already in HEADER_BUF; copy the first 512 bytes
    // into staging.
    let header_src = core::slice::from_raw_parts(HEADER_BUF as *const u8, 512);
    core::ptr::copy_nonoverlapping(header_src.as_ptr(), state_base.add(header_off), 512);
    let header_slice = core::slice::from_raw_parts(state_base.add(header_off), 512);

    let parsed = match vmdk::Vmdk4HeaderFull::parse(header_slice) {
        Some(p) => p,
        None => return err_result(config, ResizeResult::ERROR_PARSE_FAILED),
    };
    let desc_bytes = (parsed.desc_size_sectors * 512) as usize;
    let desc_file_off = parsed.desc_offset_sectors * 512;
    let gd_off = desc_off + desc_bytes;
    if !read_byte_range(
        call_table,
        sector_size,
        desc_file_off,
        state_base.add(desc_off),
        desc_bytes,
    ) {
        return err_result(config, ResizeResult::ERROR_READ_FAILED);
    }
    let desc_slice = core::slice::from_raw_parts(state_base.add(desc_off), desc_bytes);

    let grain_size_sectors = parsed.grain_size_sectors;
    let sectors_per_gt = (parsed.num_gtes_per_gt as u64) * grain_size_sectors;
    let num_gd_entries = parsed.capacity_sectors.div_ceil(sectors_per_gt) as u32;
    let gd_file_off = parsed.gd_offset_sectors * 512;
    let gd_bytes = (num_gd_entries as usize) * 4;
    let gd_sectors = gd_bytes.div_ceil(512) as u32;
    if gd_off + gd_bytes > EXISTING_STATE_LIMIT {
        return err_result(config, ResizeResult::ERROR_SCRATCH_TOO_SMALL);
    }
    if gd_bytes > 0 {
        if !read_byte_range(
            call_table,
            sector_size,
            gd_file_off,
            state_base.add(gd_off),
            gd_bytes,
        ) {
            return err_result(config, ResizeResult::ERROR_READ_FAILED);
        }
    }
    let gd_slice = core::slice::from_raw_parts(state_base.add(gd_off), gd_bytes);

    let opts = VmdkResizeOpts {
        current_virtual_size: config.current_virtual_size,
        new_virtual_size: config.new_virtual_size,
        grain_size: (grain_size_sectors * 512) as u32,
        // For phase 7 we only handle MonolithicSparse — every
        // other subformat is rejected up-front by detect_format
        // or by the planner.
        subformat: VmdkSubformat::MonolithicSparse,
        allow_shrink: config.allow_shrink(),
        preallocation: map_prealloc(config.flags),
        existing_header: header_slice,
        existing_descriptor: desc_slice,
        existing_gd: gd_slice,
        current_num_gd_entries: num_gd_entries,
        current_gd_sectors: gd_sectors,
        current_file_size: file_size_before,
    };

    let scratch =
        core::slice::from_raw_parts_mut(PLANNER_SCRATCH as *mut u8, PLANNER_SCRATCH_LIMIT);
    let plan = match plan_resize_vmdk(&opts, scratch) {
        Ok(p) => p,
        Err(e) => return err_result(config, map_error(e)),
    };
    let action = plan.action;
    let total = plan.total_file_size;
    if !apply_plan(call_table, &plan) {
        return err_result(config, ResizeResult::ERROR_WRITE_FAILED);
    }
    ResizeResult {
        magic: ResizeResult::MAGIC,
        target_format: config.target_format,
        resolved_new_virtual_size: config.new_virtual_size,
        file_size_before,
        file_size_after: total,
        action: encode_action(action),
        error: ResizeResult::ERROR_OK,
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the resize operation.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`ResizeConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - Attached the output device (the file to resize, opened
///   read-write).
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "resize");
    (call_table.verbose_print)(b"resize: start\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const ResizeConfig);
    if !config.is_valid() {
        send_result(
            call_table,
            ImageFormat::Unknown as u32,
            0,
            0,
            0,
            ResizeResult::ACTION_NOOP,
            ResizeResult::ERROR_INVALID_OPTION,
        );
        (call_table.send_complete)(b"resize\0".as_ptr(), 0, false);
        return 0;
    }

    let sector_size = (call_table.get_output_sector_size)();
    let file_size_before = (call_table.get_output_capacity)()
        .checked_mul(sector_size as u64)
        .unwrap_or(0);

    // Read sector 0 to detect the format.
    if !(call_table.read_output_sector)(0, HEADER_BUF as *mut u8, sector_size) {
        send_result(
            call_table,
            config.target_format,
            0,
            file_size_before,
            0,
            ResizeResult::ACTION_NOOP,
            ResizeResult::ERROR_READ_FAILED,
        );
        (call_table.send_complete)(b"resize\0".as_ptr(), 0, false);
        return 0;
    }
    let header = core::slice::from_raw_parts(HEADER_BUF as *const u8, sector_size);
    let format = detect_format_from_header(header, sector_size, false);

    let result = match format {
        ImageFormat::Raw => run_raw(config),
        ImageFormat::Qcow2 => run_qcow2(call_table, config, file_size_before),
        ImageFormat::Vhd => run_vhd(call_table, config, file_size_before),
        ImageFormat::Vhdx => run_vhdx(call_table, config, file_size_before),
        ImageFormat::Vmdk3 | ImageFormat::Vmdk4 => run_vmdk(call_table, config, file_size_before),
        _ => err_result(config, ResizeResult::ERROR_UNSUPPORTED_FORMAT),
    };

    let ok = result.error == ResizeResult::ERROR_OK;
    (call_table.send_resize_result)(&result);
    (call_table.send_complete)(b"resize\0".as_ptr(), result.file_size_after, ok);
    0
}
