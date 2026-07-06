//! Bench operation: measure guest-side image read throughput
//! (`qemu-img bench` parity, read path).
//!
//! # Flow (Mission §1 of `PLAN-bench-phase-03-guest-read.md`)
//!
//! 1. Validate the call table and cast the [`shared::BenchConfig`] the
//!    host wrote at [`OPERATION_CONFIG_ADDR`]. Reject an invalid magic,
//!    a bad `bufsize`, or (until phase 5) a write request with
//!    `ERROR_BAD_CONFIG`.
//! 2. Cast the [`shared::ChainConfig`] at [`CHAIN_CONFIG_ADDR`], verify
//!    the input sector sizes agree, probe sector 0 of device 0 and
//!    cross-check the guest's own header parse against the host's
//!    format claims. Any format bench cannot read (LUKS, qcow1, vdi,
//!    qed, iso, the legacy vmdk3, unknown) is refused with
//!    `ERROR_UNSUPPORTED_FORMAT`.
//! 3. Build [`bench::BenchParams`] from the config and initialise the
//!    op-lifetime cached chain state ([`qcow2::ChainStates`] +
//!    [`qcow2::init_chain_states`]); a parse failure is
//!    `ERROR_PARSE_FAILED`.
//!
//! # Timing bracket
//!
//! `send_bench_start` is emitted **once, after all of the above and
//! immediately before the first request** — the host records the
//! start instant on its arrival (see the `send_bench_start` doc in
//! `shared`). The request loop issues exactly one
//! [`qcow2::read_chain_virtual_range`] per scheduled offset and sends
//! **no** progress messages, so the measured window carries no
//! instar-only per-request chatter. The terminal `send_bench_result`
//! closes the bracket. Every exit path — success or failure, before or
//! inside the loop — ends in a `BenchResult` followed by an
//! unconditional `send_complete`.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

// Bump allocator backed by scratch memory for the ruzstd / miniz_oxide
// decoders the compressed-cluster read path uses. HEAP_POS is reset to
// 0 before every read that may decompress (see the request loop).
shared::bump_allocator!();

use shared::{
    format_detection::detect_format_from_header, validate_call_table, verify_sector_sizes,
    BenchConfig, BenchResult, CallTable, ChainConfig, ImageFormat, ALLOC_HEAP_BASE,
    CALL_TABLE_ADDR, CHAIN_CONFIG_ADDR, COMPRESSED_BUF_SIZE, MAX_CHAIN_DEVICES, MAX_CLUSTER_SIZE,
    MAX_SECTOR_SIZE, OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE,
};

// ================================================================
// Scratch memory layout (Mission §4)
// ================================================================
// Buffers grow up from SCRATCH_MEM_BASE and must stay below
// ALLOC_HEAP_BASE (the top-of-scratch 512 KiB bump heap):
//
//   BUF_DEST        2 MiB    destination for every read (data is
//                            discarded, as qemu's is); also reused for
//                            the sector-0 format probe.
//   BUF_COMPRESSED  ~2 MiB   compressed-cluster scratch.
//   BUF_STAGING     2 MiB    decompression staging buffer.
//   DYNAMIC_START            per-device L1/L2 (etc.) caches consumed by
//                            init_chain_states (2 × MAX_SECTOR_SIZE per
//                            chain device).

/// Destination buffer: a fixed [`bench::BENCH_MAX_BUFSIZE`] region.
const BUF_DEST: usize = SCRATCH_MEM_BASE;
/// Compressed-cluster scratch, sized as the qcow2 reader expects.
const BUF_COMPRESSED: usize = BUF_DEST + bench::BENCH_MAX_BUFSIZE as usize;
/// Decompression staging buffer (one max cluster).
const BUF_STAGING: usize = BUF_COMPRESSED + COMPRESSED_BUF_SIZE;
/// Start of the dynamic region handed to `init_chain_states`.
const DYNAMIC_START: usize = BUF_STAGING + MAX_CLUSTER_SIZE;

// The dynamic caches (2 × MAX_SECTOR_SIZE per chain device) must fit
// below the bump heap.
const _: () = assert!(DYNAMIC_START + 2 * MAX_SECTOR_SIZE * MAX_CHAIN_DEVICES <= ALLOC_HEAP_BASE);

// The instar v1 buffer cap and the shared max cluster size are defined
// to be equal (the `crates/bench` crate is dependency-free and cannot
// reference `shared`, so the consumer asserts the equality here).
const _: () = assert!(bench::BENCH_MAX_BUFSIZE == MAX_CLUSTER_SIZE as u64);

fn get_call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Formats bench can read.
///
/// This is exactly the set the qcow2 chain reader
/// (`read_chain_virtual_cluster`) has an arm for: qcow2, vmdk (binary
/// `Vmdk4` and the monolithicFlat `VmdkDescriptor`), vhd, vhdx, and raw
/// (its `_ =>` fallback, which `read_raw_sectors` serves). Every other
/// format — LUKS, qcow1, vdi, qed, iso, the legacy COWD `Vmdk3` — would
/// be silently misread by that raw fallback, so bench refuses it.
///
/// Returns a family tag: distinct formats compare unequal, but `Vmdk4`
/// and `VmdkDescriptor` share a family so a descriptor whose flat
/// extents make the host declare either spelling still matches.
fn read_family(f: ImageFormat) -> Option<u8> {
    match f {
        ImageFormat::Raw => Some(0),
        ImageFormat::Qcow2 => Some(1),
        ImageFormat::Vmdk4 | ImageFormat::VmdkDescriptor => Some(2),
        ImageFormat::Vhd => Some(3),
        ImageFormat::Vhdx => Some(4),
        _ => None,
    }
}

/// Emit a `BenchResult` carrying `error` and terminate the op with a
/// failing `send_complete`. Used by every failure exit, before or
/// inside the timed loop; the ABI permits a `BenchResult` without a
/// preceding `BenchStart` for pre-loop failures.
///
/// # Safety
///
/// `call_table` must be the validated `CallTable` from `_start`.
unsafe fn fail(
    call_table: &CallTable,
    error: u32,
    requests_completed: u64,
    error_detail: u64,
    bytes_read: u64,
) -> u64 {
    let result = BenchResult {
        magic: BenchResult::MAGIC,
        error,
        requests_completed,
        flushes_issued: 0,
        error_detail,
        _reserved: [0; 32],
    };
    (call_table.send_bench_result)(&result);
    (call_table.send_complete)(b"bench\0".as_ptr(), bytes_read, false);
    bytes_read
}

/// Entry point.
///
/// # Safety
///
/// Called by `core.bin` after the VMM has:
/// - Written a populated [`CallTable`] at [`CALL_TABLE_ADDR`].
/// - Written a populated [`BenchConfig`] at [`OPERATION_CONFIG_ADDR`]
///   and a populated [`ChainConfig`] at [`CHAIN_CONFIG_ADDR`].
/// - Initialised the chain's input devices and routed virtio-block I/O
///   through the call table.
///
/// These invariants hold by construction of the host-side VMM (phase
/// 4's `run_bench`); no other caller is architecturally possible.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();
    validate_call_table!(call_table, "bench");

    (call_table.verbose_print)(b"bench: start\n\0".as_ptr());

    let mut bytes_read: u64 = 0;

    // ---- Config validation ----
    let config = &*(OPERATION_CONFIG_ADDR as *const BenchConfig);
    if !config.is_valid() {
        return fail(call_table, BenchResult::ERROR_BAD_CONFIG, 0, 0, bytes_read);
    }
    // Phase-5 placeholder: the write path will replace this branch. The
    // phase-4 host never sets FLAG_WRITE until phase 5 exists, so any
    // write request reaching this read-only build is out of contract
    // and refused as a bad config.
    if config.flags & BenchConfig::FLAG_WRITE != 0 {
        return fail(call_table, BenchResult::ERROR_BAD_CONFIG, 0, 0, bytes_read);
    }
    // Guard only what would break the guest: the qemu numeric bounds
    // (count/depth/step ranges) are the host's job in phase 4. A zero
    // or over-cap bufsize would overrun BUF_DEST.
    let bufsize = config.bufsize;
    if bufsize == 0 || bufsize > bench::BENCH_MAX_BUFSIZE {
        return fail(call_table, BenchResult::ERROR_BAD_CONFIG, 0, 0, bytes_read);
    }

    // ---- Chain config ----
    let chain_config = &*(CHAIN_CONFIG_ADDR as *const ChainConfig);
    if !chain_config.is_valid() {
        return fail(call_table, BenchResult::ERROR_BAD_CONFIG, 0, 0, bytes_read);
    }
    let device_count = chain_config.device_count as usize;
    if device_count > MAX_CHAIN_DEVICES {
        return fail(call_table, BenchResult::ERROR_BAD_CONFIG, 0, 0, bytes_read);
    }

    // ---- Sector sizes ----
    let sector_size = match verify_sector_sizes(call_table, device_count) {
        Some(ss) => ss,
        None => return fail(call_table, BenchResult::ERROR_BAD_CONFIG, 0, 0, bytes_read),
    };

    // ---- Format probe + gate ----
    // Read sector 0 of device 0 into BUF_DEST (reused before the loop
    // overwrites it) and parse it ourselves. A header read failure here
    // is the first request's byte 0 failing to load, so it is an I/O
    // read error at offset 0.
    let header_ptr = BUF_DEST as *mut u8;
    if !(call_table.read_input_sector)(0, 0, header_ptr, sector_size) {
        return fail(call_table, BenchResult::ERROR_IO_READ, 0, 0, bytes_read);
    }
    bytes_read += sector_size as u64;
    let header = core::slice::from_raw_parts(header_ptr as *const u8, sector_size);
    let probed = detect_format_from_header(header, sector_size, false);

    // The chain reader dispatches on the *host-declared* device-0
    // format, so that is the format that must be one bench can read.
    // `target_format` is the host's format hint; both are host-derived
    // from the same info parse and must agree. The guest's own sector-0
    // parse (`probed`) must corroborate them, with one legitimate
    // exception: a fixed VHD keeps its magic in a trailing footer, so
    // its first sector parses as Raw while the host (which reads the
    // footer) declares Vhd. That single Raw-probe divergence is
    // allowed; a probe that positively identifies a *different* family
    // than the host claims (e.g. LUKS bytes under a "raw" claim) is
    // refused.
    let dev0 = chain_config.devices[0].detected_format();
    let cfg = ImageFormat::from_u32(config.target_format);
    let (probed_fam, dev0_fam, cfg_fam) =
        (read_family(probed), read_family(dev0), read_family(cfg));
    let supported = probed_fam.is_some() && dev0_fam.is_some() && cfg_fam.is_some();
    let consistent =
        dev0_fam == cfg_fam && (probed_fam == dev0_fam || matches!(probed, ImageFormat::Raw));
    if !supported || !consistent {
        return fail(
            call_table,
            BenchResult::ERROR_UNSUPPORTED_FORMAT,
            0,
            0,
            bytes_read,
        );
    }

    // Virtual size is convert's source of truth: the top-of-chain
    // device's declared virtual size.
    let image_size = chain_config.devices[0].virtual_size;

    // ---- Bench parameters ----
    // Raw values straight from the config; the crate's effective_step()
    // / OffsetSchedule own the wrap resolution. FLAG_WRITE was already
    // rejected, so this is always a read test.
    let params = bench::BenchParams {
        count: config.count,
        depth: config.depth,
        bufsize,
        step: config.step,
        offset: config.offset,
        is_write: false,
        pattern: config.pattern as u8,
        flush_interval: config.flush_interval,
        no_drain: config.flags & BenchConfig::FLAG_NO_DRAIN != 0,
    };

    // ---- Op-lifetime cached chain state ----
    let mut chain_states = qcow2::ChainStates::default();
    if !qcow2::init_chain_states(
        call_table,
        chain_config,
        &mut chain_states,
        device_count,
        sector_size,
        DYNAMIC_START,
        &mut bytes_read,
    ) {
        return fail(
            call_table,
            BenchResult::ERROR_PARSE_FAILED,
            0,
            0,
            bytes_read,
        );
    }

    let schedule = bench::OffsetSchedule::new(&params, image_size);

    // ---- Timing bracket opens here ----
    // Emitted after all setup, immediately before the first request,
    // mirroring qemu's gettimeofday placement (see the send_bench_start
    // doc contract in `shared`).
    (call_table.send_bench_start)();

    // ---- Request loop: one read_chain_virtual_range per offset ----
    // No progress messages inside the timed window (Mission §3).
    let dest = BUF_DEST as *mut u8;
    let mut staging_cluster_offset: u64 = u64::MAX;
    let mut completed: u64 = 0;
    for offset in schedule {
        // Reset the bump allocator before a read that may decompress.
        HEAP_POS.store(0, Ordering::Relaxed);

        // EOF pre-check: read_chain_virtual_range does NOT bound-check
        // against the virtual size — a read past the device end is
        // silently zero-filled and returns true (see read_raw_sectors).
        // So the op must itself refuse a request whose window overruns
        // image_size, reproducing qemu's "Failed request" EIO. The wrap
        // rule keeps every offset after the first inside
        // [0, image_size - bufsize], so only the raw first `-o` (or a
        // degenerate image_size <= bufsize / image_size == 0) can reach
        // here.
        let overruns = match offset.checked_add(bufsize) {
            Some(end) => end > image_size,
            None => true,
        };
        let ok = !overruns
            && qcow2::read_chain_virtual_range(
                call_table,
                0,
                device_count,
                offset,
                dest,
                bufsize,
                sector_size,
                chain_config,
                &mut chain_states,
                BUF_COMPRESSED as *mut u8,
                BUF_STAGING as *mut u8,
                &mut staging_cluster_offset,
                None, // aes_key: bench refuses encrypted inputs at the gate
                None, // luks_key: ditto
                512,  // luks_sector_size: unused when luks_key is None
                &mut bytes_read,
            );
        if !ok {
            (call_table.send_error)(
                b"bench\0".as_ptr(),
                b"read\0".as_ptr(),
                offset / sector_size as u64,
                1,
            );
            return fail(
                call_table,
                BenchResult::ERROR_IO_READ,
                completed,
                offset,
                bytes_read,
            );
        }
        completed += 1;
    }

    // ---- Success: close the bracket ----
    let result = BenchResult {
        magic: BenchResult::MAGIC,
        error: BenchResult::ERROR_OK,
        requests_completed: params.count as u64,
        flushes_issued: 0,
        error_detail: 0,
        _reserved: [0; 32],
    };
    (call_table.send_bench_result)(&result);
    (call_table.send_complete)(b"bench\0".as_ptr(), bytes_read, true);
    bytes_read
}
