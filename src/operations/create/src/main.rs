//! Create operation: emit empty-image metadata for a target format.
//!
//! Reads a `CreateConfig` from `OPERATION_CONFIG_ADDR`, optionally
//! recovers the virtual size from a backing image's header (when the
//! host left `virtual_size = 0` and a backing reference is present),
//! calls the appropriate `crates/create::plan_*` to build a
//! `MetadataPlan`, then writes every plan entry to the output device.
//! Emits a `CreateResult` at completion describing what was written.
//!
//! Out of scope:
//!  - Preallocation modes (phase 6 handles host-side).
//!  - Backing-chain composition beyond a single immediate backing
//!    (matches qemu-img — only the immediate parent reference is
//!    recorded; the runtime opener resolves the chain).
//!  - LUKS / encryption.
//!
//! Phase 5 added VHDX-as-backing virtual_size extraction via
//! `vhdx::VhdxState::init`.
//!
//! Raw output short-circuits: the guest emits no writes (the host
//! ftruncates in phase 3); a defensive invocation returns a success
//! `CreateResult` with metadata_bytes_written = 0.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    format_detection::detect_format_from_header, validate_call_table, CallTable, CreateConfig,
    CreateResult, ImageFormat, CALL_TABLE_ADDR, CREATE_CONFIG_MAX_BACKING_FILE,
    GUEST_CREATE_SCRATCH_LIMIT, MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
};

use create::{
    plan_qcow2, plan_vhd, plan_vhdx, plan_vmdk, BackingRef, CreateError, MetadataPlan,
    Qcow2CreateOpts, VhdCreateOpts, VhdSubformat, VhdxCreateOpts, VmdkCreateOpts, VmdkSubformat,
};

// ---------------------------------------------------------------------------
// Scratch layout
// ---------------------------------------------------------------------------

/// First MAX_SECTOR_SIZE bytes: backing-file header probe buffer.
const HEADER_BUF: usize = SCRATCH_MEM_BASE;
/// Create planner scratch region (GUEST_CREATE_SCRATCH_LIMIT bytes,
/// starting one sector after the header probe).
const CREATE_SCRATCH: usize = HEADER_BUF + MAX_SECTOR_SIZE;

/// VHDX cache buffers (phase 5a). `VhdxState::init` needs two
/// `MAX_SECTOR_SIZE` scratch slots for its BAT and data caches.
/// Reuses the first two sector-sized chunks of `CREATE_SCRATCH`
/// because the planner doesn't run until after the backing-header
/// lookup returns — the two regions are mutually exclusive in time.
const VHDX_CACHE_A: usize = CREATE_SCRATCH;
const VHDX_CACHE_B: usize = CREATE_SCRATCH + MAX_SECTOR_SIZE;

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Build a `CreateResult` and send it via the call table.
///
/// # Safety
///
/// `call_table` must be a valid initialised [`CallTable`] — the
/// architectural invariant established by `_start`.
unsafe fn send_result(
    call_table: &CallTable,
    target: u32,
    resolved_virtual_size: u64,
    metadata_bytes_written: u64,
    file_size_after: u64,
    resolved_unit_size: u32,
    error: u32,
) {
    let result = CreateResult {
        magic: CreateResult::MAGIC,
        target_format: target,
        resolved_virtual_size,
        metadata_bytes_written,
        file_size_after,
        resolved_unit_size,
        error,
    };
    (call_table.send_create_result)(&result);
}

/// Map a `crates/create::CreateError` to a `CreateResult` error code.
fn map_create_error(e: CreateError) -> u32 {
    match e {
        CreateError::InvalidVirtualSize => CreateResult::ERROR_INVALID_SIZE,
        CreateError::InvalidClusterSize
        | CreateError::InvalidBlockSize
        | CreateError::InvalidGrainSize
        | CreateError::InvalidSubformat => CreateResult::ERROR_INVALID_OPTION,
        CreateError::BackingFileTooLong => CreateResult::ERROR_BACKING_TOO_LONG,
        CreateError::BackingFileUnsupported => CreateResult::ERROR_INVALID_OPTION,
        CreateError::Overflow => CreateResult::ERROR_INVALID_SIZE,
        CreateError::ScratchTooSmall => CreateResult::ERROR_SCRATCH_TOO_SMALL,
        // PreallocationUnsupported reuses INVALID_OPTION until 6c
        // adds a dedicated host-side message; the host already
        // rejects unsupported (target, mode) combinations at the
        // validator so this path is reached only from
        // qcow2 + extended_l2 + non-Off mode, which the validator
        // also catches via the per-target ceiling check.
        CreateError::PreallocationUnsupported => CreateResult::ERROR_INVALID_OPTION,
    }
}

/// Recover a backing image's `virtual_size` by reading and parsing its
/// header from input device 0. Returns `None` if the format is
/// unrecognised or the parse fails; the caller maps `None` to
/// `ERROR_BACKING_PARSE_FAILED`.
///
/// VHDX walks header → region table → metadata region via the
/// vhdx crate's `VhdxState::init`, which exposes
/// `virtual_disk_size` directly. The two cache buffers it needs
/// reuse `VHDX_CACHE_A` / `VHDX_CACHE_B` (overlapping with the
/// create scratch — safe because the planner doesn't run until
/// after this function returns).
///
/// # Safety
///
/// `call_table` must be valid and input device 0 must be attached
/// with non-zero capacity.
unsafe fn read_backing_virtual_size(call_table: &CallTable, sector_size: usize) -> Option<u64> {
    let header_ptr = HEADER_BUF as *mut u8;
    if !(call_table.read_input_sector)(0, 0, header_ptr, sector_size) {
        return None;
    }
    let header = core::slice::from_raw_parts(header_ptr, sector_size);
    let format = detect_format_from_header(header, sector_size, false);
    let capacity = (call_table.get_input_capacity)(0);
    match format {
        ImageFormat::Raw => capacity.checked_mul(sector_size as u64),
        ImageFormat::Qcow2 => qcow2::QcowHeader::parse(header).map(|h| h.virtual_size),
        ImageFormat::Vmdk4 => vmdk::Vmdk4Header::parse(header).map(|h| h.virtual_size),
        ImageFormat::Vhd => {
            // VHD's footer lives at the *end* of the file; read the
            // last sector and parse from there.
            if capacity == 0 {
                return None;
            }
            if !(call_table.read_input_sector)(0, capacity - 1, header_ptr, sector_size) {
                return None;
            }
            let last_sector = core::slice::from_raw_parts(header_ptr, sector_size);
            vhd::VhdFooter::parse(last_sector).map(|f| f.current_size)
        }
        ImageFormat::Vhdx => {
            if capacity == 0 {
                return None;
            }
            let mut bytes_read: u64 = 0;
            let state = vhdx::VhdxState::init(
                call_table,
                0,
                sector_size,
                capacity,
                VHDX_CACHE_A as *mut u8,
                VHDX_CACHE_B as *mut u8,
                &mut bytes_read,
            )?;
            Some(state.virtual_disk_size)
        }
        // Vdi / Qcow1 / Qed / Iso / Luks: unsupported as backing.
        _ => None,
    }
}

/// Translate `CreateConfig` into `crates/create::Qcow2CreateOpts`.
fn qcow2_opts_from<'a>(
    config: &CreateConfig,
    virtual_size: u64,
    backing: Option<BackingRef<'a>>,
) -> Qcow2CreateOpts<'a> {
    use qcow2::create::Preallocation;
    let preallocation = match config.preallocation() {
        CreateConfig::PREALLOC_METADATA => Preallocation::Metadata,
        CreateConfig::PREALLOC_FALLOC => Preallocation::Falloc,
        CreateConfig::PREALLOC_FULL => Preallocation::Full,
        _ => Preallocation::Off,
    };
    Qcow2CreateOpts {
        virtual_size,
        cluster_size: if config.qcow2_cluster_size == 0 {
            65536
        } else {
            config.qcow2_cluster_size
        },
        refcount_bits: if config.qcow2_refcount_bits == 0 {
            16
        } else {
            config.qcow2_refcount_bits
        },
        extended_l2: (config.flags & CreateConfig::FLAG_EXTENDED_L2) != 0,
        lazy_refcounts: (config.flags & CreateConfig::FLAG_LAZY_REFCOUNTS) != 0,
        // FLAG_COMPAT_V3 default-on when flags == 0 — matches qemu-img's
        // default of compat=1.1. Clear the bit explicitly for v2.
        compat_v3: config.flags == 0 || (config.flags & CreateConfig::FLAG_COMPAT_V3) != 0,
        backing,
        preallocation,
    }
}

fn vmdk_opts_from<'a>(
    config: &CreateConfig,
    virtual_size: u64,
    backing: Option<BackingRef<'a>>,
    parent_cid: Option<u32>,
) -> VmdkCreateOpts<'a> {
    VmdkCreateOpts {
        virtual_size,
        subformat: match config.vmdk_subformat {
            1 => VmdkSubformat::StreamOptimized,
            _ => VmdkSubformat::MonolithicSparse,
        },
        grain_size: if config.vmdk_grain_size == 0 {
            65536
        } else {
            config.vmdk_grain_size
        },
        backing,
        parent_cid,
    }
}

/// Read the parent vmdk's descriptor and extract its CID for the
/// new image's `parentCID=` line. Returns `None` if the backing
/// isn't a vmdk binary header, the descriptor can't be read, or
/// parsing fails. In every `None` case the caller falls back to
/// the `0xdeadbeef` sentinel in `build_vmdk_descriptor_with_backing`.
///
/// The vmdk crate's `read_and_parse_descriptor` does the heavy
/// lifting; this helper only reads the binary header to recover the
/// descriptor's sector offset / length, then forwards.
///
/// # Safety
///
/// `call_table` must be valid and input device 0 must be attached
/// with non-zero capacity.
unsafe fn read_vmdk_parent_cid(call_table: &CallTable, sector_size: usize) -> Option<u32> {
    let header_ptr = HEADER_BUF as *mut u8;
    if !(call_table.read_input_sector)(0, 0, header_ptr, sector_size) {
        return None;
    }
    let header = core::slice::from_raw_parts(header_ptr, sector_size);
    let parsed = vmdk::Vmdk4Header::parse(header)?;

    // The descriptor lives at `desc_offset_sectors * 512` for
    // `desc_size_sectors * 512` bytes. Cap at MAX_SECTOR_SIZE so a
    // bogus parent can't push us past the scratch slot — the real
    // descriptor we wrote in phase 1d is well under 10 KiB so a
    // single sector covers the populated portion.
    if parsed.desc_offset_sectors == 0 {
        return None;
    }
    if !(call_table.read_input_sector)(0, parsed.desc_offset_sectors, header_ptr, sector_size) {
        return None;
    }
    let desc_bytes = core::slice::from_raw_parts(header_ptr, sector_size);
    let mut info = shared::VmdkInfo::new();
    vmdk::parse_descriptor(desc_bytes, sector_size, &mut info);
    Some(info.cid)
}

fn vhd_opts_from<'a>(
    config: &CreateConfig,
    virtual_size: u64,
    backing: Option<BackingRef<'a>>,
) -> VhdCreateOpts<'a> {
    VhdCreateOpts {
        virtual_size,
        subformat: match config.vhd_subformat {
            1 => VhdSubformat::Fixed,
            _ => VhdSubformat::Dynamic,
        },
        block_size: if config.block_size == 0 {
            2 * 1024 * 1024
        } else {
            config.block_size
        },
        backing,
    }
}

fn vhdx_opts_from<'a>(
    config: &CreateConfig,
    virtual_size: u64,
    backing: Option<BackingRef<'a>>,
) -> VhdxCreateOpts<'a> {
    VhdxCreateOpts {
        virtual_size,
        block_size: if config.block_size == 0 {
            32 * 1024 * 1024
        } else {
            config.block_size
        },
        backing,
    }
}

/// Pre-flight check: can the target format address `virtual_size`
/// with the requested per-target options? Returns `true` when the
/// combination is at least plausibly supported; `false` only when
/// we can rule it out cheaply (e.g. qcow2 cluster_size + virtual
/// would exceed `QCOW2_MAX_L1_SIZE_ENTRIES`). Anything that returns
/// `true` here may still hit a deeper limit inside `plan_*`; this
/// is a clearer-message gate for the common case, not a complete
/// substitute for the planner's validation.
fn target_can_address(target: ImageFormat, virtual_size: u64, config: &CreateConfig) -> bool {
    match target {
        // Raw: no metadata, file is just `virtual_size` bytes.
        // No practical ceiling here; the host's ftruncate will
        // succeed up to the filesystem limit.
        ImageFormat::Raw => true,
        ImageFormat::Qcow2 => {
            let cluster_size: u64 = if config.qcow2_cluster_size == 0 {
                65536
            } else {
                config.qcow2_cluster_size as u64
            };
            // L2 entry size: 16 bytes for extended_l2, otherwise 8.
            let extended_l2 = (config.flags & CreateConfig::FLAG_EXTENDED_L2) != 0;
            let l2_entry_size: u64 = if extended_l2 { 16 } else { 8 };
            let entries_per_l2 = cluster_size / l2_entry_size;
            let l2_coverage = match cluster_size.checked_mul(entries_per_l2) {
                Some(v) if v > 0 => v,
                _ => return false,
            };
            let l1_entries = virtual_size.div_ceil(l2_coverage);
            // QCOW2_MAX_L1_SIZE_ENTRIES is 4 M per the qcow2 spec
            // and the parser cap.
            l1_entries <= qcow2::QCOW2_MAX_L1_SIZE_ENTRIES as u64
        }
        // VMDK / VHD / VHDX: per-format ceilings are far above any
        // practical virtual_size (vmdk's grain count is the dominant
        // cap and the supported grain sizes leave petabytes of
        // headroom). Accept and let the planner catch any pathological
        // case.
        ImageFormat::Vmdk4 | ImageFormat::Vhd | ImageFormat::Vhdx => true,
        // Any other target was already rejected by validate_create_args
        // / parse_create_o_options; treat as not addressable so we
        // surface a clear "unsupported format" error rather than
        // crashing the planner.
        _ => false,
    }
}

/// Write every entry in `plan` to the output device, one sector at
/// a time. Returns the total bytes written or `None` on I/O failure.
///
/// Every `byte_offset` in the plan is sector-aligned and every
/// `bytes.len()` is a multiple of 512 by construction (see phase 1's
/// per-format layouts); a debug_assert guards each call.
///
/// # Safety
///
/// `call_table` must be valid and the output device attached.
unsafe fn write_plan(call_table: &CallTable, plan: &MetadataPlan<'_>) -> Option<u64> {
    let output_sector_size = (call_table.get_output_sector_size)();
    let output_capacity = (call_table.get_output_capacity)();
    let mut bytes_written: u64 = 0;

    for w in plan.writes() {
        debug_assert_eq!(w.byte_offset % output_sector_size as u64, 0);
        debug_assert_eq!(w.bytes.len() % output_sector_size, 0);

        let first_sector = w.byte_offset / output_sector_size as u64;
        let sectors = (w.bytes.len() as u64).div_ceil(output_sector_size as u64);
        for i in 0..sectors {
            let sector = first_sector + i;
            if sector >= output_capacity {
                return None;
            }
            let src = w.bytes.as_ptr().add((i as usize) * output_sector_size);
            if !(call_table.write_output_sector)(sector, src, output_sector_size) {
                return None;
            }
        }
        bytes_written += w.bytes.len() as u64;
    }
    Some(bytes_written)
}

/// Entry point for the create operation.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`CreateConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - For non-raw targets, attached an output device.
/// - When `CreateConfig.virtual_size == 0` and a backing reference
///   is present, attached the backing file as input device 0.
///
/// These invariants hold by construction of the host-side VMM
/// (phase 3 wires `run_create`); no other caller is architecturally
/// possible.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "create");
    (call_table.verbose_print)(b"create: start\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const CreateConfig);
    let sector_size_ok = config.sector_size >= 512
        && config.sector_size as usize <= MAX_SECTOR_SIZE
        && config.sector_size.is_power_of_two();
    if !config.is_valid() || !sector_size_ok {
        send_result(
            call_table,
            ImageFormat::Unknown as u32,
            0,
            0,
            0,
            0,
            CreateResult::ERROR_INVALID_OPTION,
        );
        (call_table.send_complete)(b"create\0".as_ptr(), 0, false);
        return 0;
    }

    let target = ImageFormat::from_u32(config.target_format);

    // Defensive: reject overlong backing-file refs before anything
    // tries to slice into the buffer.
    if (config.backing_file_len as usize) > CREATE_CONFIG_MAX_BACKING_FILE {
        send_result(
            call_table,
            config.target_format,
            0,
            0,
            0,
            0,
            CreateResult::ERROR_BACKING_TOO_LONG,
        );
        (call_table.send_complete)(b"create\0".as_ptr(), 0, false);
        return 0;
    }

    // Resolve virtual size: explicit non-zero wins, otherwise infer
    // from the backing image if one is attached.
    let virtual_size: u64 = if config.virtual_size != 0 {
        config.virtual_size
    } else if config.has_backing() {
        match read_backing_virtual_size(call_table, config.sector_size as usize) {
            Some(vs) if vs > 0 => vs,
            Some(_) | None => {
                send_result(
                    call_table,
                    config.target_format,
                    0,
                    0,
                    0,
                    0,
                    CreateResult::ERROR_BACKING_PARSE_FAILED,
                );
                (call_table.send_complete)(b"create\0".as_ptr(), 0, false);
                return 0;
            }
        }
    } else {
        send_result(
            call_table,
            config.target_format,
            0,
            0,
            0,
            0,
            CreateResult::ERROR_INVALID_SIZE,
        );
        (call_table.send_complete)(b"create\0".as_ptr(), 0, false);
        return 0;
    };

    // Pre-flight ceiling check: a backing-derived virtual_size may
    // exceed the target's addressable range with the requested
    // options (e.g. qcow2 cluster_size=512 caps at QCOW2_MAX_L1
    // entries × L2 coverage). plan_*'s InvalidVirtualSize would
    // catch this too, but mapping it to a dedicated
    // ERROR_BACKING_SIZE_TOO_LARGE lets the host render a clearer
    // "try a larger cluster size" hint. Only runs in the
    // backing-derived path; user-supplied SIZE already passed the
    // host's pre-flight checks.
    if config.virtual_size == 0
        && config.has_backing()
        && !target_can_address(target, virtual_size, config)
    {
        send_result(
            call_table,
            config.target_format,
            virtual_size,
            0,
            0,
            0,
            CreateResult::ERROR_BACKING_SIZE_TOO_LARGE,
        );
        (call_table.send_complete)(b"create\0".as_ptr(), 0, false);
        return 0;
    }

    // Raw short-circuit: no metadata to emit. The host already
    // truncated the output file; we just confirm completion.
    if matches!(target, ImageFormat::Raw) {
        send_result(
            call_table,
            config.target_format,
            virtual_size,
            0,
            virtual_size,
            0,
            CreateResult::ERROR_OK,
        );
        (call_table.send_complete)(b"create\0".as_ptr(), 0, true);
        return 0;
    }

    let backing_ref = if config.has_backing() {
        Some(BackingRef {
            path: config.backing_file_bytes(),
            format: {
                let f = ImageFormat::from_u32(config.backing_format);
                if matches!(f, ImageFormat::Unknown) {
                    None
                } else {
                    Some(f)
                }
            },
        })
    } else {
        None
    };

    // Carve the create scratch region.
    let scratch =
        core::slice::from_raw_parts_mut(CREATE_SCRATCH as *mut u8, GUEST_CREATE_SCRATCH_LIMIT);

    let (plan, resolved_unit_size) = match target {
        ImageFormat::Qcow2 => {
            let opts = qcow2_opts_from(config, virtual_size, backing_ref);
            let unit = opts.cluster_size;
            match plan_qcow2(&opts, scratch) {
                Ok(p) => (p, unit),
                Err(e) => return fail_with(call_table, config.target_format, map_create_error(e)),
            }
        }
        ImageFormat::Vmdk4 => {
            // When the parent is itself a vmdk, extract its CID so
            // the new descriptor's parentCID matches. For non-vmdk
            // parents we pass None and the descriptor falls back to
            // the sentinel.
            let parent_cid = if config.has_backing()
                && matches!(
                    ImageFormat::from_u32(config.backing_format),
                    ImageFormat::Vmdk4
                ) {
                read_vmdk_parent_cid(call_table, config.sector_size as usize)
            } else {
                None
            };
            let opts = vmdk_opts_from(config, virtual_size, backing_ref, parent_cid);
            let unit = opts.grain_size;
            match plan_vmdk(&opts, scratch) {
                Ok(p) => (p, unit),
                Err(e) => return fail_with(call_table, config.target_format, map_create_error(e)),
            }
        }
        ImageFormat::Vhd => {
            let opts = vhd_opts_from(config, virtual_size, backing_ref);
            let unit = match opts.subformat {
                VhdSubformat::Fixed => 0,
                VhdSubformat::Dynamic => opts.block_size,
            };
            match plan_vhd(&opts, scratch) {
                Ok(p) => (p, unit),
                Err(e) => return fail_with(call_table, config.target_format, map_create_error(e)),
            }
        }
        ImageFormat::Vhdx => {
            let opts = vhdx_opts_from(config, virtual_size, backing_ref);
            let unit = opts.block_size;
            match plan_vhdx(&opts, scratch) {
                Ok(p) => (p, unit),
                Err(e) => return fail_with(call_table, config.target_format, map_create_error(e)),
            }
        }
        _ => {
            return fail_with(
                call_table,
                config.target_format,
                CreateResult::ERROR_UNSUPPORTED_FORMAT,
            )
        }
    };

    let file_size_after = plan.minimum_file_size;
    let mut bytes_written = match write_plan(call_table, &plan) {
        Some(n) => n,
        None => {
            return fail_with(
                call_table,
                config.target_format,
                CreateResult::ERROR_WRITE_FAILED,
            )
        }
    };

    // qcow2 + non-Off preallocation: L2 tables are NOT in the
    // MetadataPlan because they can sum to more than the guest's
    // scratch budget at large virtual sizes (e.g. 128 MiB at
    // 1 TiB virtual with default cluster size). Stream them
    // here using a reusable single-cluster scratch slot at
    // CREATE_SCRATCH, then extend the file to file_size_after by
    // writing a final zero sector at the last sector position.
    if matches!(target, ImageFormat::Qcow2) && config.preallocation() != CreateConfig::PREALLOC_OFF
    {
        match emit_qcow2_l2_and_extend(call_table, config, virtual_size, file_size_after) {
            Some(extra) => bytes_written = bytes_written.saturating_add(extra),
            None => {
                return fail_with(
                    call_table,
                    config.target_format,
                    CreateResult::ERROR_WRITE_FAILED,
                )
            }
        }
    }

    send_result(
        call_table,
        config.target_format,
        virtual_size,
        bytes_written,
        file_size_after,
        resolved_unit_size,
        CreateResult::ERROR_OK,
    );
    (call_table.send_complete)(b"create\0".as_ptr(), bytes_written, true);
    bytes_written
}

/// Emit the L2 tables for a preallocated qcow2 image and extend the
/// output file to `file_size_after` by writing a zero sector at the
/// last sector position. Used only when qcow2 + preallocation !=
/// Off; for Off mode no L2 tables exist and the plan's writes
/// already cover the (much smaller) total file size.
///
/// Returns `Some(bytes_written)` for the L2 + extension passes, or
/// `None` on I/O failure. The L2 buffer is a single cluster carved
/// out of `CREATE_SCRATCH` and reused across L1 entries.
///
/// # Safety
///
/// `call_table` must be valid and the output device attached.
unsafe fn emit_qcow2_l2_and_extend(
    call_table: &CallTable,
    config: &CreateConfig,
    virtual_size: u64,
    file_size_after: u64,
) -> Option<u64> {
    use qcow2::create::Preallocation;
    let prealloc = match config.preallocation() {
        CreateConfig::PREALLOC_METADATA => Preallocation::Metadata,
        CreateConfig::PREALLOC_FALLOC => Preallocation::Falloc,
        CreateConfig::PREALLOC_FULL => Preallocation::Full,
        _ => return Some(0),
    };
    let cluster_size = if config.qcow2_cluster_size == 0 {
        65536
    } else {
        config.qcow2_cluster_size
    };
    let refcount_bits = if config.qcow2_refcount_bits == 0 {
        16
    } else {
        config.qcow2_refcount_bits as u32
    };
    let cluster_bits = cluster_size.trailing_zeros();
    let layout = qcow2::create::compute_layout(
        virtual_size,
        cluster_bits,
        refcount_bits,
        (config.flags & CreateConfig::FLAG_EXTENDED_L2) != 0,
        prealloc,
    )
    .ok()?;

    let output_sector_size = (call_table.get_output_sector_size)();
    let output_capacity = (call_table.get_output_capacity)();
    let cluster_size_u = layout.cluster_size as usize;
    let l2_buf = core::slice::from_raw_parts_mut(CREATE_SCRATCH as *mut u8, cluster_size_u);
    let mut bytes_written: u64 = 0;

    for l1_index in 0..layout.l1_entries as u64 {
        qcow2::create::build_l2_table(l2_buf, &layout, l1_index).ok()?;
        let byte_offset = layout.l2_base_offset + l1_index * layout.cluster_size;
        if !write_sector_aligned(
            call_table,
            byte_offset,
            l2_buf,
            output_sector_size,
            output_capacity,
        )? {
            return None;
        }
        bytes_written += layout.cluster_size;
    }

    // Extend the file: write a zero sector at file_size_after -
    // sector_size so the file reaches the post-preallocation size.
    // The data region itself is sparse here; the host fill_zeros
    // pass in step 6c materialises it for falloc / full modes.
    if file_size_after > 0 {
        let zero_sector =
            core::slice::from_raw_parts_mut(CREATE_SCRATCH as *mut u8, output_sector_size);
        zero_sector.fill(0);
        let tail_offset = file_size_after - output_sector_size as u64;
        if !write_sector_aligned(
            call_table,
            tail_offset,
            zero_sector,
            output_sector_size,
            output_capacity,
        )? {
            return None;
        }
        bytes_written = bytes_written.saturating_add(output_sector_size as u64);
    }

    Some(bytes_written)
}

/// Write `bytes` (a multiple of `sector_size` long, starting at a
/// sector-aligned `byte_offset`) to the output device via repeated
/// `write_output_sector` calls. Returns `Some(true)` on success,
/// `Some(false)` on a per-sector write failure (caller maps to
/// ERROR_WRITE_FAILED), `None` only if the math overflows.
///
/// # Safety
///
/// `call_table` must be valid and the output device attached.
/// `bytes.len()` must be a multiple of `sector_size` and
/// `byte_offset` must be sector-aligned (debug-asserted).
unsafe fn write_sector_aligned(
    call_table: &CallTable,
    byte_offset: u64,
    bytes: &[u8],
    sector_size: usize,
    output_capacity: u64,
) -> Option<bool> {
    debug_assert_eq!(byte_offset % sector_size as u64, 0);
    debug_assert_eq!(bytes.len() % sector_size, 0);
    let first_sector = byte_offset / sector_size as u64;
    let sectors = (bytes.len() as u64).div_ceil(sector_size as u64);
    for i in 0..sectors {
        let sector = first_sector + i;
        if sector >= output_capacity {
            return Some(false);
        }
        let src = bytes.as_ptr().add((i as usize) * sector_size);
        if !(call_table.write_output_sector)(sector, src, sector_size) {
            return Some(false);
        }
    }
    Some(true)
}

/// Emit a failure result + send_complete and return 0. Pulled out so
/// the dispatch arms in `_start` stay terse.
///
/// # Safety
///
/// `call_table` must be valid.
unsafe fn fail_with(call_table: &CallTable, target: u32, error: u32) -> u64 {
    send_result(call_table, target, 0, 0, 0, 0, error);
    (call_table.send_complete)(b"create\0".as_ptr(), 0, false);
    0
}
