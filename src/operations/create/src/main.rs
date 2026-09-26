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
    footer_fallback_applies, parent_format_matches, plan_qcow2, plan_vhd, plan_vhdx, plan_vmdk,
    BackingRef, CreateError, MetadataPlan, Qcow2CreateOpts, VhdCreateOpts, VhdSubformat,
    VhdxCreateOpts, VmdkCreateOpts, VmdkSubformat,
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
        // Its own code rather than ERROR_BACKING_TOO_LONG: that one's
        // host message names a 1024-byte limit, and this refusal is
        // about a 512-byte UTF-16 field that a 300-byte ASCII path can
        // overflow. Telling a user their 300-byte path exceeded 1024
        // bytes is a false diagnostic.
        CreateError::ParentNameTooLong => CreateResult::ERROR_PARENT_NAME_TOO_LONG,
        // Also its own code: nothing about this path is too long, and
        // the fix a user needs (rename the file, or give an absolute
        // path) is not the fix ERROR_PARENT_NAME_TOO_LONG suggests.
        CreateError::ParentPathNotRepresentable => {
            CreateResult::ERROR_PARENT_PATH_NOT_REPRESENTABLE
        }
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

/// How a differencing child names the parent it was written against.
///
/// Only VHD and VHDX record a parent identity: a VHD child stores the
/// parent's footer `uuid` and `timestamp` in its own footer and dynamic
/// header, and a VHDX child stores the parent's active-header
/// `DataWriteGuid` as its `parent_linkage`. Every other format either
/// names its parent by path alone (qcow2, raw) or by a CID read
/// elsewhere (vmdk, via `read_vmdk_parent_cid`), so `None` is the
/// correct answer for them rather than a missing case.
#[derive(Clone, Copy)]
enum ParentIdentity {
    /// The parent carries no identity a child of it could record.
    None,
    /// A VHD parent's footer `uuid` and creation `timestamp`. The
    /// timestamp is the parent's own, in the VHD epoch, exactly as the
    /// footer stores it — a child records when its parent was made, not
    /// when the child was.
    Vhd { uuid: [u8; 16], timestamp: u32 },
    /// A VHDX parent's active-header `DataWriteGuid`.
    Vhdx { data_write_guid: [u8; 16] },
}

/// What one pass over a backing image's headers yields.
///
/// The probe reads those headers once and reports everything derived
/// from them together, rather than having each caller re-read the same
/// sectors and re-derive where a footer lives.
///
/// Every field is *what the probe could determine*, never *what the
/// caller needs*. That split matters because the probe now runs
/// whenever `-b` is given (#579) rather than only when a size has to
/// be inferred: a backing image it cannot size is not by itself an
/// error, since the user may have supplied the size and the target may
/// record its parent by path alone. Each consumer states its own
/// requirement instead — the size resolution refuses a `None` only
/// when it has to infer, and the parent-format check refuses a format
/// that is not the one a differencing child needs. Failing as a unit
/// here is what made `create -f qcow2 -b flat.vmdk -F vmdk child 64M`,
/// which `develop` and qemu-img both accept, report the parent as
/// truncated or corrupt.
struct BackingProbe {
    /// The parent's virtual size, for a child that inherits it, or
    /// `None` when the probe could not derive one — an unparseable
    /// format, an unreadable header, or a device whose capacity is
    /// zero. Only the size-inference path treats that as fatal.
    virtual_size: Option<u64>,
    /// The format detected in the parent's own header — not the
    /// `-F` hint, which is only populated when the user passes one.
    /// [`ImageFormat::Raw`] is `detect_format_from_header`'s catch-all
    /// as well as a real answer, and [`ImageFormat::Unknown`] means
    /// the header could not be read at all.
    format: ImageFormat,
    /// The parent's identity, if its format records one.
    identity: ParentIdentity,
}

/// Probe a backing image by reading and parsing its header from input
/// device 0: its virtual size, the format actually present in its
/// bytes, and the identity a differencing child of it would record.
/// On failure returns the `CreateResult` error code the caller should
/// report, so the reason survives the return rather than collapsing
/// into one generic code.
///
/// VHDX walks header → region table → metadata region via the
/// vhdx crate's `VhdxState::init`, which exposes
/// `virtual_disk_size` directly. The two cache buffers it needs
/// reuse `VHDX_CACHE_A` / `VHDX_CACHE_B` (overlapping with the
/// create scratch — safe because the planner doesn't run until
/// after this function returns).
///
/// A differencing VHD or VHDX is refused here, with its own
/// `ERROR_BACKING_DIFFERENCING` rather than the generic
/// `ERROR_BACKING_PARSE_FAILED`: the backing header parsed perfectly
/// well, and telling a user a valid image is "truncated, corrupted, or an
/// unrecognised format" is the undiagnosed failure this phase exists to
/// stop making. Every read path in instar that composes sector data
/// refuses such an image, so an overlay stacked on one would be a chain
/// that can never be read back.
/// Until parent composition exists
/// (`docs/plans/PLAN-differencing.md`), failing closed at create time is
/// the only outcome that does not hand the user a dead image. For VHDX
/// this preserves what `VhdxState::init`'s own `has_parent` rejection used
/// to do before that rejection moved out to the read entry points; the VHD
/// arm never had such a guard and gains one here so the two formats agree.
///
/// The only `Err` this returns is that differencing refusal. Anything
/// else the probe cannot work out is reported as an absent field, for
/// the caller that needs it to refuse: see [`BackingProbe`].
///
/// # Safety
///
/// `call_table` must be valid and input device 0 must be attached.
/// A zero capacity is tolerated — block and character devices stat as
/// zero-length, so the host attaches them with no capacity, and such a
/// parent yields a probe with no size rather than a failure.
unsafe fn probe_backing(
    call_table: &CallTable,
    sector_size: usize,
    hint: ImageFormat,
) -> Result<BackingProbe, u32> {
    const DIFFERENCING: u32 = CreateResult::ERROR_BACKING_DIFFERENCING;

    /// A parent whose format is known but whose size and identity are
    /// not: the header named a format whose deeper structures could
    /// not be read, or there is no parser for it. `Unknown` is the
    /// case where even the header could not be read.
    const fn unsized_probe(format: ImageFormat) -> BackingProbe {
        BackingProbe {
            virtual_size: None,
            format,
            identity: ParentIdentity::None,
        }
    }

    let header_ptr = HEADER_BUF as *mut u8;
    if !(call_table.read_input_sector)(0, 0, header_ptr, sector_size) {
        return Ok(unsized_probe(ImageFormat::Unknown));
    }
    // Everything the *header* can tell us is extracted here, inside a
    // scope that ends before anything writes through `header_ptr`
    // again. The footer fallback below reuses that buffer, and a
    // `&[u8]` still live across that write would alias it -- unsound
    // under Rust's rules whether or not the arm that reads it happens
    // to be reachable. Ending the borrow makes the invariant
    // structural rather than a property of which match arm runs.
    let (mut format, header_virtual_size) = {
        let header = core::slice::from_raw_parts(header_ptr, sector_size);
        let format = detect_format_from_header(header, sector_size, false);
        let virtual_size = match format {
            ImageFormat::Qcow2 => qcow2::QcowHeader::parse(header).map(|h| h.virtual_size),
            ImageFormat::Vmdk4 => vmdk::Vmdk4Header::parse(header).map(|h| h.virtual_size),
            _ => None,
        };
        (format, virtual_size)
    };
    let capacity = (call_table.get_input_capacity)(0);

    // Whether to look for a VHD footer in the last sector is decided
    // by `create::footer_fallback_applies`, which carries the reasoning
    // and is unit-tested there -- this binary is excluded from
    // `cargo test --workspace`, so a truth table written here would
    // never run.
    //
    // The read is hoisted out of the `Vhd` arm so both routes into it
    // share one read and one parse. It uses `vhd::find_footer_offset`
    // (via `parse_last_sector`) rather than
    // `shared::format_detection::detect_vhd_footer`, because the
    // latter only looks at offset 0 of the buffer: `capacity` is
    // `div_ceil(size_bytes, sector_size)` and reads past end-of-file
    // zero-pad, so above a 512-byte sector the footer sits at some
    // 512-aligned offset *inside* the last sector rather than at its
    // start (issue #578, which is the same defect on those other
    // paths). A failed read or a footerless file simply leaves
    // `format` alone: a raw parent stays raw, and a parent whose
    // header claimed VHD still fails below on the `None`.
    let mut vhd_footer = None;
    if footer_fallback_applies(format, hint)
        && capacity > 0
        && (call_table.read_input_sector)(0, capacity - 1, header_ptr, sector_size)
    {
        let last_sector = core::slice::from_raw_parts(header_ptr, sector_size);
        vhd_footer = vhd::VhdFooter::parse_last_sector(last_sector);
        if vhd_footer.is_some() {
            format = ImageFormat::Vhd;
        }
    }

    let (virtual_size, identity) = match format {
        ImageFormat::Raw => (
            // Zero capacity is a block or character device, which
            // stats as zero-length: no size, rather than a size of
            // zero. Overflow is likewise "no size we can state".
            capacity
                .checked_mul(sector_size as u64)
                .filter(|size| *size > 0),
            ParentIdentity::None,
        ),
        ImageFormat::Qcow2 | ImageFormat::Vmdk4 => (header_virtual_size, ParentIdentity::None),
        ImageFormat::Vhd => {
            // Located above, by header detection or by the footer
            // fallback. `None` here means the header claimed VHD and
            // the footer did not agree.
            let Some(footer) = vhd_footer else {
                return Ok(unsized_probe(format));
            };
            if footer.disk_type == vhd::DISK_TYPE_DIFFERENCING {
                return Err(DIFFERENCING);
            }
            (
                Some(footer.current_size),
                ParentIdentity::Vhd {
                    uuid: footer.uuid,
                    timestamp: footer.timestamp,
                },
            )
        }
        ImageFormat::Vhdx => {
            let state = if capacity == 0 {
                None
            } else {
                let mut bytes_read: u64 = 0;
                vhdx::VhdxState::init(
                    call_table,
                    0,
                    sector_size,
                    capacity,
                    VHDX_CACHE_A as *mut u8,
                    VHDX_CACHE_B as *mut u8,
                    &mut bytes_read,
                )
                .map(|state| (state, bytes_read))
            };
            let Some((state, mut bytes_read)) = state else {
                return Ok(unsized_probe(format));
            };
            if state.has_parent {
                return Err(DIFFERENCING);
            }
            // `init` selected an active header to walk the region table
            // with but kept none of its fields, so read the pair again
            // and select with the same rule — `read_active_header` is
            // the rule `init` itself calls, so the two cannot disagree
            // about which header is active. The reads cannot fail here
            // in practice: `init` just made them successfully.
            let Some(active) = vhdx::VhdxState::read_active_header(
                call_table,
                0,
                sector_size,
                capacity,
                &mut bytes_read,
            ) else {
                return Ok(unsized_probe(format));
            };
            (
                Some(state.virtual_disk_size),
                ParentIdentity::Vhdx {
                    data_write_guid: active.data_write_guid,
                },
            )
        }
        // Vdi / Qcow1 / Qed / Iso / Luks / Parallels / Bochs / cloop /
        // Vmdk3 / a VMDK text descriptor: formats the probe has no
        // parser for. Detected, and reported with no size — refusing
        // here would refuse every one of them as a *qcow2* or *vmdk*
        // parent, which `develop` and qemu-img both allow, since those
        // targets record a parent by path and never ask for its size.
        // A vpc or vhdx child still gets a refusal, from the
        // parent-format check, with a code that names the real reason.
        _ => (None, ParentIdentity::None),
    };
    Ok(BackingProbe {
        virtual_size,
        format,
        identity,
    })
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

/// # Errors
///
/// [`CreateResult::ERROR_PARENT_FORMAT_MISMATCH`] when a backing file
/// is present but its identity is not a VHD one. The caller's
/// format-and-identity checks make that unreachable -- a wrong format
/// is refused as a mismatch and a right format that did not parse is
/// refused as a parse failure, before this is reached -- but it is
/// checked here rather than argued for in a comment: the invariant is
/// relied on *here*, and the failure
/// mode if a future reordering broke it is a well-formed child carrying
/// an all-zero parent identity -- which, because every instar-written
/// VHD shares that identity (#566), would resolve against any of them.
/// That silent-wrong-output hazard is the one this phase exists to
/// close, so it fails loudly instead.
fn vhd_opts_from<'a>(
    config: &CreateConfig,
    virtual_size: u64,
    backing: Option<BackingRef<'a>>,
    identity: ParentIdentity,
) -> Result<VhdCreateOpts<'a>, u32> {
    // A vpc child records its parent's own footer `uuid` and
    // creation `timestamp`, so a reader can tell whether the parent it
    // resolved is the parent the child was written against. With no
    // backing file the planner writes no parent fields at all, so the
    // zeroes below are never read. See docs/plans/PLAN-differencing.md.
    // Matched on both dimensions. An identity present with no backing
    // ref cannot happen -- `probe` is `Some` exactly when
    // `config.has_backing()`, which is exactly when `backing_ref` is
    // `Some` -- but spelling the first arm `_` would have written a
    // real parent's uuid into an image with no parent if that ever
    // stopped being true. The `(_, false)` arm carries the no-parent
    // case alone.
    let (parent_unique_id, parent_timestamp) = match (identity, backing.is_some()) {
        (ParentIdentity::Vhd { uuid, timestamp }, true) => (uuid, timestamp),
        (_, false) => ([0u8; 16], 0),
        (_, true) => return Err(CreateResult::ERROR_PARENT_FORMAT_MISMATCH),
    };
    Ok(VhdCreateOpts {
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
        parent_unique_id,
        parent_timestamp,
    })
}

/// # Errors
///
/// As [`vhd_opts_from`]: a backing file whose identity is not a VHDX
/// one is [`CreateResult::ERROR_PARENT_FORMAT_MISMATCH`] rather than a
/// silent zero `parent_linkage`.
fn vhdx_opts_from<'a>(
    config: &CreateConfig,
    virtual_size: u64,
    backing: Option<BackingRef<'a>>,
    identity: ParentIdentity,
) -> Result<VhdxCreateOpts<'a>, u32> {
    // A vhdx child records its parent's active-header `DataWriteGuid`
    // as its own `parent_linkage`. With no backing file the planner
    // writes no parent metadata at all, so the zeroes below are never
    // read. See docs/plans/PLAN-differencing.md.
    // Matched on both dimensions, for the reason given in
    // `vhd_opts_from`.
    let parent_data_write_guid = match (identity, backing.is_some()) {
        (ParentIdentity::Vhdx { data_write_guid }, true) => data_write_guid,
        (_, false) => [0u8; 16],
        (_, true) => return Err(CreateResult::ERROR_PARENT_FORMAT_MISMATCH),
    };
    Ok(VhdxCreateOpts {
        virtual_size,
        block_size: if config.block_size == 0 {
            32 * 1024 * 1024
        } else {
            config.block_size
        },
        backing,
        parent_data_write_guid,
    })
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
        // VMDK: GD entry count must fit in u32. Each entry covers
        // (GTES_PER_GT * grain_size) bytes of address space, so the
        // ceiling is u32::MAX * GTES_PER_GT * grain_size. With the
        // default grain (64 KiB) the cap is 16 EiB; with the minimum
        // (4 KiB) it's 1 EiB. Either way well above any practical
        // virtual_size, but we check anyway so a malicious backing
        // image can't drive plan_vmdk into the Overflow path and
        // produce a generic "InvalidVirtualSize" surface — we want
        // the friendlier "backing too large for target" hint.
        ImageFormat::Vmdk4 => {
            let grain_size: u64 = if config.vmdk_grain_size == 0 {
                65536
            } else {
                config.vmdk_grain_size as u64
            };
            let gtes_per_gt: u64 = vmdk::DEFAULT_NUM_GTES_PER_GT as u64;
            let bytes_per_gd_entry = match grain_size.checked_mul(gtes_per_gt) {
                Some(v) if v > 0 => v,
                _ => return false,
            };
            let max_virtual = (u32::MAX as u64).checked_mul(bytes_per_gd_entry);
            match max_virtual {
                Some(cap) => virtual_size <= cap,
                None => true, // Cap exceeds u64::MAX; any virtual_size fits.
            }
        }
        // VHD dynamic: BAT entry count (u32) = virtual_size / block_size.
        // Cap = u32::MAX * block_size. With the min block_size (512 KiB)
        // the cap is 2 PiB; with the default (2 MiB) it's 8 PiB.
        ImageFormat::Vhd => {
            let block_size: u64 = if config.block_size == 0 {
                2 * 1024 * 1024
            } else {
                config.block_size as u64
            };
            let max_virtual = (u32::MAX as u64).checked_mul(block_size);
            match max_virtual {
                Some(cap) => virtual_size <= cap,
                None => true,
            }
        }
        // VHDX: defer to the parser crate's authoritative computation.
        // calculate_bat_layout returns None when either total_blocks or
        // chunk_ratio overflows u32, which is precisely the ceiling we
        // need to enforce.
        ImageFormat::Vhdx => {
            let block_size: u32 = if config.block_size == 0 {
                32 * 1024 * 1024
            } else {
                config.block_size
            };
            vhdx::calculate_bat_layout(virtual_size, block_size, 512).is_some()
        }
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
/// - Whenever a backing reference is present, attached the backing
///   file as input device 0. (Until #579 this was only required when
///   `CreateConfig.virtual_size == 0`; the probe now runs whenever
///   `-b` was given, so it dereferences the device regardless of how
///   the virtual size was resolved.)
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

    // Probe the backing image whenever one is attached, not only when
    // the virtual size has to be inferred from it. Every check on the
    // parent lives in the probe -- the differencing refusal, the parse
    // check, and the format detection the parent-format check reads --
    // so gating the probe on a missing size let a user skip all of them
    // by passing one. It also makes the parent's identity available to
    // the differencing planners regardless of how the size was
    // resolved. See docs/plans/PLAN-differencing.md.
    let probe = if config.has_backing() {
        match probe_backing(
            call_table,
            config.sector_size as usize,
            ImageFormat::from_u32(config.backing_format),
        ) {
            Ok(probe) => Some(probe),
            Err(code) => {
                send_result(call_table, config.target_format, 0, 0, 0, 0, code);
                (call_table.send_complete)(b"create\0".as_ptr(), 0, false);
                return 0;
            }
        }
    } else {
        None
    };

    // Resolve virtual size: explicit non-zero wins, otherwise infer
    // from the backing image if one is attached.
    let virtual_size: u64 = if config.virtual_size != 0 {
        config.virtual_size
    } else if let Some(probe) = probe.as_ref() {
        if let Some(size) = probe.virtual_size.filter(|size| *size > 0) {
            size
        } else {
            // No size, or a zero one, is as unusable as a failed
            // parse when the size has to come from here, and carries
            // no more specific reason than that. This is the *only*
            // place a missing size is fatal: an explicit size does not
            // depend on the probed one, so a parent the probe could
            // not size must not newly fail a create that never asked
            // it for a size (which is what it did until this check
            // moved here from the probe).
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

    // A differencing child must be the same format as its parent:
    // Hyper-V writes and resolves VHD parents for VHD children and
    // VHDX parents for VHDX children, and neither child format has a
    // way to say "my parent is some other format". Detection decides,
    // not the `-F` hint, because the hint is only populated when the
    // user passes one -- and when the user did pass one that the
    // parent's bytes disprove, refuse rather than silently prefer the
    // bytes. qcow2 and vmdk accept mixed-format parents and are
    // untouched. See docs/plans/PLAN-differencing.md.
    if let Some(probe) = probe.as_ref() {
        // An unreadable header is reported as `Unknown`, which the
        // format check below would refuse as a *mismatch* -- a wrong
        // diagnosis for a parent that might well be the right format
        // if it could be read. A vpc or vhdx child is the only case
        // that must read the parent (it needs the identity), so it is
        // the only one that turns this into a failure; qcow2 and vmdk
        // record a parent by path and are unaffected.
        if matches!(target, ImageFormat::Vhd | ImageFormat::Vhdx)
            && matches!(probe.format, ImageFormat::Unknown)
        {
            return fail_with(
                call_table,
                config.target_format,
                CreateResult::ERROR_BACKING_PARSE_FAILED,
            );
        }
        if !parent_format_matches(
            target,
            probe.format,
            ImageFormat::from_u32(config.backing_format),
        ) {
            return fail_with(
                call_table,
                config.target_format,
                CreateResult::ERROR_PARENT_FORMAT_MISMATCH,
            );
        }

        // The parent *is* the right format and still yielded no
        // identity, so its deeper structures did not parse: a VHD
        // whose trailing footer is missing or truncated, or a VHDX
        // whose headers or region table are unreadable. Without this
        // the failure would surface from `vhd_opts_from` as a format
        // mismatch -- telling the user their VHD parent is not a VHD,
        // which is both false and unactionable. The order matters:
        // the format check runs first, so a genuinely wrong-format
        // parent keeps the mismatch diagnosis rather than being
        // reported as corrupt.
        //
        // This is what makes the `(_, true)` arms of `vhd_opts_from`
        // and `vhdx_opts_from` unreachable. They stay as a belt-and-
        // braces refusal because the cost of being wrong there is a
        // child carrying an all-zero parent identity (#566), not an
        // error message.
        if matches!(target, ImageFormat::Vhd | ImageFormat::Vhdx)
            && matches!(probe.identity, ParentIdentity::None)
        {
            return fail_with(
                call_table,
                config.target_format,
                CreateResult::ERROR_BACKING_PARSE_FAILED,
            );
        }

        // A differencing child and its parent describe the *same*
        // disk: the child stores only the blocks that differ, and
        // every block it marks absent is read from the parent at the
        // same offset. A child declaring a different size is a chain
        // no implementation can compose, so an explicit SIZE that
        // disagrees with the parent is refused rather than written.
        //
        // This is not a hypothetical mismatch. instar writes
        // `current_size` verbatim while qemu-img rounds a VHD's size
        // up to CHS geometry, so a qemu-written "64M" parent declares
        // 67,125,248 -- and `create -f vpc -b parent.vhd -F vpc
        // child.vhd 64M`, the most natural way to type it, emitted a
        // child declaring 67,108,864 against it. No size at all is
        // the right way to ask for a differencing child; it inherits
        // the parent's, whatever that turns out to be.
        if matches!(target, ImageFormat::Vhd | ImageFormat::Vhdx)
            && config.virtual_size != 0
            && probe
                .virtual_size
                .is_some_and(|parent| parent != config.virtual_size)
        {
            return fail_with(
                call_table,
                config.target_format,
                CreateResult::ERROR_PARENT_SIZE_MISMATCH,
            );
        }
    }

    // The parent's identity travels to the VHD and VHDX planners; every
    // other target records its parent by path or by CID instead.
    let parent_identity = match probe.as_ref() {
        Some(probe) => probe.identity,
        None => ParentIdentity::None,
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
            let opts = match vhd_opts_from(config, virtual_size, backing_ref, parent_identity) {
                Ok(o) => o,
                Err(code) => return fail_with(call_table, config.target_format, code),
            };
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
            let opts = match vhdx_opts_from(config, virtual_size, backing_ref, parent_identity) {
                Ok(o) => o,
                Err(code) => return fail_with(call_table, config.target_format, code),
            };
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
