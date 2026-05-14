//! Measure operation: predict the file size required to convert a
//! source image (or a hypothetical empty image of given size) to a
//! target format.
//!
//! This operation reads `MeasureConfig` at `OPERATION_CONFIG_ADDR`.
//! If `virtual_size_override` is non-zero no source scan is performed
//! and the calculator runs on `(virtual_size = override, allocated = 0)`.
//! Otherwise the source format is detected via the first sector and
//! the matching parser's `scan_allocation` walks the metadata to
//! produce an `AllocationSummary`. The `crates/measure` calculator
//! then returns `required + fully_allocated` bytes for the target
//! format. The result is sent via `send_measure_result`.
//!
//! Out of scope for phase 3:
//! - Backing-chain composition (single-device source only).
//! - LUKS source decryption.
//! - Snapshot extraction.
//!
//! If the source format is unrecognised the result reports
//! `ERROR_INVALID_SIZE` so the host can render a clear error
//! message.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{
    format_detection::detect_format_from_header, validate_call_table, AllocationSummary, CallTable,
    ImageFormat, MeasureConfig, MeasureResult, CALL_TABLE_ADDR, MAX_SECTOR_SIZE,
    OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
};

use measure::{
    measure_qcow2, measure_raw, measure_vhd, measure_vhdx, measure_vmdk, MeasureError,
    MeasureOutput, Preallocation, Qcow2Opts, VhdOpts, VhdSubformat, VhdxOpts, VmdkOpts,
    VmdkSubformat,
};

/// Scratch memory layout for measure: one header buffer plus four
/// per-parser cache buffers (each `MAX_SECTOR_SIZE` bytes).
///
/// Parser cache requirements:
/// - qcow2: L1 + L2 cache (uses CACHE_A + CACHE_B).
/// - vmdk:  GD + GT cache (uses CACHE_A + CACHE_B).
/// - vhd:   BAT + data cache (uses CACHE_A + CACHE_B).
/// - vhdx:  BAT + data cache (uses CACHE_A + CACHE_B).
///
/// Only one parser runs per measure invocation so reusing two
/// buffers across parsers is safe.
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

/// Entry point. Returns the number of bytes read from the source
/// device, matching the convention of the other operation binaries.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`MeasureConfig`] at
///   [`OPERATION_CONFIG_ADDR`].
/// - Initialised at least input device 0 (or a stub for `--size`
///   mode) and routed virtio-block I/O through the call table.
///
/// These invariants hold by construction of the host-side VMM
/// (`src/vmm/src/main.rs::run_measure`); no other caller is
/// architecturally possible.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "measure");

    (call_table.verbose_print)(b"measure: start\n\0".as_ptr());

    let config = &*(OPERATION_CONFIG_ADDR as *const MeasureConfig);
    if !config.is_valid() {
        send_result(
            call_table,
            ImageFormat::Unknown as u32,
            0,
            Err(MeasureError::InvalidOption),
        );
        (call_table.send_complete)(b"measure\0".as_ptr(), 0, false);
        return 0;
    }

    // Track bytes read across the entire scan so the value can be
    // surfaced via send_complete (mirrors info/check semantics).
    let mut bytes_read: u64 = 0;

    // 1. Build AllocationSummary.
    let summary = if config.virtual_size_override != 0 {
        AllocationSummary {
            virtual_size: config.virtual_size_override,
            allocated_bytes: 0,
        }
    } else {
        match detect_and_scan(call_table, config, &mut bytes_read) {
            Some(s) => s,
            None => {
                send_result(
                    call_table,
                    config.target_format,
                    0,
                    Err(MeasureError::InvalidSize),
                );
                (call_table.send_complete)(b"measure\0".as_ptr(), bytes_read, false);
                return bytes_read;
            }
        }
    };

    // 2. Compute output for target format + resolve unit size.
    let target = ImageFormat::from_u32(config.target_format);
    let (out, unit): (Result<MeasureOutput, MeasureError>, u32) = match target {
        ImageFormat::Raw => (measure_raw(summary.virtual_size), 0u32),
        ImageFormat::Qcow2 => {
            let opts = qcow2_opts_from(config);
            (measure_qcow2(&summary, &opts), opts.cluster_size)
        }
        ImageFormat::Vmdk4 => {
            let opts = vmdk_opts_from(config);
            (measure_vmdk(&summary, &opts), opts.grain_size)
        }
        ImageFormat::Vhd => {
            let opts = vhd_opts_from(config);
            // For Fixed VHDs there is no block; report 0 in that case.
            let unit = match opts.subformat {
                VhdSubformat::Fixed => 0,
                VhdSubformat::Dynamic => opts.block_size,
            };
            (measure_vhd(&summary, &opts), unit)
        }
        ImageFormat::Vhdx => {
            let opts = vhdx_opts_from(config);
            (measure_vhdx(&summary, &opts), opts.block_size)
        }
        _ => (Err(MeasureError::InvalidOption), 0),
    };

    // 3. Send result and signal completion.
    let success = out.is_ok();
    send_result(call_table, config.target_format, unit, out);
    (call_table.send_complete)(b"measure\0".as_ptr(), bytes_read, success);
    bytes_read
}

fn map_error(e: MeasureError) -> u32 {
    match e {
        MeasureError::Overflow => MeasureResult::ERROR_OVERFLOW,
        MeasureError::InvalidOption => MeasureResult::ERROR_INVALID_OPTION,
        MeasureError::InvalidSize => MeasureResult::ERROR_INVALID_SIZE,
    }
}

/// Build a [`MeasureResult`] and emit it through the call table.
///
/// # Safety
///
/// `call_table` must be a valid initialised [`CallTable`] — the
/// architectural invariant established by `_start` (see its
/// `Safety` doc).
unsafe fn send_result(
    call_table: &CallTable,
    target: u32,
    unit: u32,
    out: Result<MeasureOutput, MeasureError>,
) {
    let result = match out {
        Ok(o) => MeasureResult {
            magic: MeasureResult::MAGIC,
            target_format: target,
            required: o.required,
            fully_allocated: o.fully_allocated,
            resolved_unit_size: unit,
            error: MeasureResult::ERROR_OK,
        },
        Err(e) => MeasureResult {
            magic: MeasureResult::MAGIC,
            target_format: target,
            required: 0,
            fully_allocated: 0,
            resolved_unit_size: 0,
            error: map_error(e),
        },
    };
    (call_table.send_measure_result)(&result);
}

fn qcow2_opts_from(c: &MeasureConfig) -> Qcow2Opts {
    let mut opts = Qcow2Opts::default();
    if c.qcow2_cluster_size != 0 {
        opts.cluster_size = c.qcow2_cluster_size;
    }
    if c.qcow2_refcount_bits != 0 {
        opts.refcount_bits = c.qcow2_refcount_bits;
    }
    opts.extended_l2 = (c.flags & MeasureConfig::FLAG_EXTENDED_L2) != 0;
    opts.lazy_refcounts = (c.flags & MeasureConfig::FLAG_LAZY_REFCOUNTS) != 0;
    // FLAG_COMPAT_V3 default-on: when the bit is clear we still default
    // to v3 (matches qemu-img). The flag is treated as "override to v2"
    // semantics by the host; here we just translate the bit directly.
    opts.compat_v3 = (c.flags & MeasureConfig::FLAG_COMPAT_V3) != 0
        // If the host never set any preallocation / compat flag the
        // entire flags word can be zero. Treat that as "use default
        // (compat_v3 = true)" so callers do not need to know the
        // wire-level encoding to get sane behaviour.
        || c.flags == 0;
    opts.compress = (c.flags & MeasureConfig::FLAG_COMPRESS) != 0;
    opts.preallocation = match c.preallocation() {
        MeasureConfig::PREALLOC_METADATA => Preallocation::Metadata,
        MeasureConfig::PREALLOC_FALLOC => Preallocation::Falloc,
        MeasureConfig::PREALLOC_FULL => Preallocation::Full,
        _ => Preallocation::Off,
    };
    if c.luks_header_overhead != 0 {
        opts.luks_header_overhead = Some(c.luks_header_overhead);
    }
    opts
}

fn vmdk_opts_from(c: &MeasureConfig) -> VmdkOpts {
    let mut opts = VmdkOpts {
        subformat: match c.vmdk_subformat {
            1 => VmdkSubformat::StreamOptimized,
            2 => VmdkSubformat::MonolithicFlat,
            _ => VmdkSubformat::MonolithicSparse,
        },
        grain_size: VmdkOpts::default().grain_size,
    };
    if c.vmdk_grain_size != 0 {
        opts.grain_size = c.vmdk_grain_size;
    }
    opts
}

fn vhd_opts_from(c: &MeasureConfig) -> VhdOpts {
    let mut opts = VhdOpts {
        subformat: match c.vhd_subformat {
            1 => VhdSubformat::Fixed,
            _ => VhdSubformat::Dynamic,
        },
        block_size: VhdOpts::default().block_size,
    };
    if c.block_size != 0 {
        opts.block_size = c.block_size;
    }
    opts
}

fn vhdx_opts_from(c: &MeasureConfig) -> VhdxOpts {
    let mut opts = VhdxOpts::default();
    if c.block_size != 0 {
        opts.block_size = c.block_size;
    }
    opts
}

/// Detect the source format from the first sector and dispatch to
/// the matching parser's `scan_allocation`. Returns `None` if the
/// format is unrecognised or the parser rejects the image.
/// Detect the source format on device 0 and run the matching
/// parser's `scan_allocation` to produce an [`AllocationSummary`].
///
/// # Safety
///
/// `call_table` must be a valid initialised [`CallTable`] — the
/// architectural invariant established by `_start` (see its
/// `Safety` doc). Input device 0 must be attached and have a
/// non-zero capacity; the function delegates to each parser
/// crate's `*State::init` + `scan_allocation` which carry their
/// own safety preconditions on the cache buffers passed in.
unsafe fn detect_and_scan(
    call_table: &CallTable,
    config: &MeasureConfig,
    bytes_read: &mut u64,
) -> Option<AllocationSummary> {
    let sector_size = config.sector_size as usize;
    let input_capacity = (call_table.get_input_capacity)(0);

    // Read first sector for format detection.
    let header_ptr = HEADER_BUF as *mut u8;
    if !(call_table.read_input_sector)(0, 0, header_ptr, sector_size) {
        return None;
    }
    *bytes_read += sector_size as u64;

    let header = core::slice::from_raw_parts(header_ptr, sector_size);
    // `extra_detail = false`: only formats supported by measure
    // (raw, qcow2, vmdk, vhd, vhdx) need to be recognised here.
    let format = detect_format_from_header(header, sector_size, false);

    let cache_a = CACHE_BUF_A as *mut u8;
    let cache_b = CACHE_BUF_B as *mut u8;

    match format {
        ImageFormat::Raw => {
            // Raw images carry no allocation metadata — treat every byte
            // as allocated. Virtual size is the device capacity.
            let virtual_size = input_capacity.checked_mul(sector_size as u64)?;
            Some(raw::scan_allocation(virtual_size))
        }
        ImageFormat::Qcow2 => {
            // Parse the header from the sector we already read to
            // recover the virtual size (Qcow2State does not store it).
            let parsed = qcow2::QcowHeader::parse(header)?;
            let mut state = qcow2::Qcow2State::init(
                call_table,
                0,
                sector_size,
                input_capacity,
                cache_a,
                cache_b,
                bytes_read,
            )?;
            state.scan_allocation(
                call_table,
                sector_size,
                input_capacity,
                parsed.virtual_size,
                bytes_read,
            )
        }
        ImageFormat::Vmdk4 => {
            // VMDK init needs an approximation of the actual file size
            // for footer lookup in stream-optimized images.
            let actual_file_size = input_capacity.checked_mul(sector_size as u64)?;
            let mut state = vmdk::VmdkState::init(
                call_table,
                0,
                sector_size,
                input_capacity,
                actual_file_size,
                cache_a,
                cache_b,
                bytes_read,
            )?;
            state.scan_allocation(call_table, sector_size, input_capacity, bytes_read)
        }
        ImageFormat::Vhd => {
            let mut state = vhd::VhdState::init(
                call_table,
                0,
                sector_size,
                input_capacity,
                cache_a,
                cache_b,
                bytes_read,
            )?;
            state.scan_allocation(call_table, sector_size, input_capacity, bytes_read)
        }
        ImageFormat::Vhdx => {
            let mut state = vhdx::VhdxState::init(
                call_table,
                0,
                sector_size,
                input_capacity,
                cache_a,
                cache_b,
                bytes_read,
            )?;
            state.scan_allocation(call_table, sector_size, input_capacity, bytes_read)
        }
        _ => None,
    }
}
