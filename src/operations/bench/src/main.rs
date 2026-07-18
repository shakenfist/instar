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

// Phase-6 step 6b: the qcow2 `-w` path is driven by the shared windowed
// planner (`qcow2-write`) and its literal guest executor
// (`qcow2-write-exec`). The moved refcount-growth planner lives in
// `qcow2_write::growth` (step 6a); `worst_case_touched` stays in
// `crates/bench` (BenchParams/schedule-coupled).
use qcow2_write::growth::{plan_refcount_growth, GrowthCaps, GrowthOverflow};
use qcow2_write::{
    check_envelope_with, new_state_cow, plan_flush, plan_write, DataSource, Gate, RegionId,
    StagedRegions, StagingConfig, Step, StepBuf, StepKind, TargetDevice, WriteError, WriteState,
    MAX_L2_SLOTS,
};
use qcow2_write_exec::{
    execute, fill_bytes, growth, read_bytes, CallTableIo, ExecCause, ExecError, Regions,
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

// ================================================================
// qcow2 write-mode scratch (phase 6 step 6b, Mission §1-§2)
// ================================================================
// Only the qcow2 `-w` path touches these regions; the read path and the
// raw `-w` path never reference them. They sit ABOVE the per-device
// L1/L2 caches `init_chain_states` consumes (2 × MAX_SECTOR_SIZE per
// chain device, growing up from DYNAMIC_START).
//
// The migration onto `qcow2-write` / `qcow2-write-exec` re-carves this
// region to hold the planner/executor staging (settled decision 5):
// the step program, the staged active L1, the fixed-slot L2 window, the
// staged refcount table (also the plan_flush writeback-offset source —
// so the old `WRITE_RB_OFFSETS` side table is RECLAIMED), the staged
// refblocks, and the executor's RMW + fill service sectors plus the
// (v1-filler) planner bounce region. The executor's `CallerData` region
// aliases BUF_DEST (the COW-fill cluster buffer, free on the write
// path); `read_chain_virtual_cluster` keeps using BUF_COMPRESSED /
// BUF_STAGING for backing-chain decompression during the decision-3
// try/refuse/fill/resubmit protocol.
//
// Preemptive setup-time refcount growth (PLAN-bench-refcount-growth,
// moved to `qcow2_write::growth` in step 6a) may extend the staged set
// before the timing bracket opens; the caps below ARE its refusal
// envelope.

/// First free byte above the dynamic per-device caches.
const WRITE_SCRATCH_BASE: usize = DYNAMIC_START + 2 * MAX_SECTOR_SIZE * MAX_CHAIN_DEVICES;

/// Upper bound on staged refcount blocks. Setup-time growth
/// (`qcow2_grow_refcounts`) preemptively provisions the whole schedule's
/// worst-case coverage, so this cap — together with the byte limits
/// below — IS the refusal envelope: a run needing more than 2048 slots,
/// more than `WRITE_REFBLOCKS_LIMIT` staged refblock bytes, or a grown
/// refcount table past `WRITE_RT_LIMIT` refuses with
/// `ERROR_ALLOC_EXHAUSTED` ("image too large for in-place bench write").
/// That is ~256 MiB of host file at 512-byte clusters and >= 64 GiB at
/// >= 64 KiB clusters.
const WRITE_MAX_REFBLOCKS: usize = 2048;

/// The windowed step program (`[Step; WRITE_STEP_CAPACITY]`). 64 KiB
/// holds well over 1000 steps (~100 worst-case allocating clusters per
/// refill); the decision-1 loop windows anything larger.
const WRITE_STEP_BUF: usize = WRITE_SCRATCH_BASE;
const WRITE_STEP_BUF_LIMIT: usize = 64 * 1024;
const WRITE_STEP_CAPACITY: usize = WRITE_STEP_BUF_LIMIT / core::mem::size_of::<Step>();

/// The staged active L1 table (`RegionId::L1`). 64 KiB = 8192 entries,
/// covering a 256 MiB image at cs=512 — matched to the refblock cap.
const WRITE_L1_BUF: usize = WRITE_STEP_BUF + WRITE_STEP_BUF_LIMIT;
const WRITE_L1_LIMIT: usize = 64 * 1024;

/// The fixed-slot staged-L2 window (`RegionId::L2Slot`). Sized to hold
/// exactly one slot at the maximum cluster size (decision 5's ≥1-slot
/// requirement at cs=2 MiB); more slots at smaller cluster sizes.
const WRITE_L2_WINDOW: usize = WRITE_L1_BUF + WRITE_L1_LIMIT;
const WRITE_L2_WINDOW_LIMIT: usize = MAX_CLUSTER_SIZE;

/// The staged refcount-table prefix (`RegionId::RefcountTable`). Also the
/// source `plan_flush` reads refblock writeback offsets from, which is
/// why the old `WRITE_RB_OFFSETS` side table is reclaimed.
const WRITE_RT_BUF: usize = WRITE_L2_WINDOW + WRITE_L2_WINDOW_LIMIT;
const WRITE_RT_LIMIT: usize = 64 * 1024;

/// The staged refcount blocks (`RegionId::Refblocks`; dense prefix,
/// mutated in place by the planner's allocator — decision 6).
const WRITE_REFBLOCKS_BUF: usize = WRITE_RT_BUF + WRITE_RT_LIMIT;
const WRITE_REFBLOCKS_LIMIT: usize = 2 * 1024 * 1024;

/// Executor sub-sector RMW bounce sector (`Regions::rmw_sector`).
const WRITE_RMW_BOUNCE: usize = WRITE_REFBLOCKS_BUF + WRITE_REFBLOCKS_LIMIT;
const WRITE_RMW_BOUNCE_LIMIT: usize = MAX_SECTOR_SIZE;

/// Executor fill-synthesis sector (`Regions::fill_sector`; `ZeroRange` /
/// `FillRange` — the patterned overwrite and fresh-cluster zero-fill).
const WRITE_FILL_SECTOR: usize = WRITE_RMW_BOUNCE + WRITE_RMW_BOUNCE_LIMIT;
const WRITE_FILL_SECTOR_LIMIT: usize = MAX_SECTOR_SIZE;

/// The planner bounce region (`Regions::bounce`, `RegionId::Bounce`). A
/// filler in v1 programs — bench's emitted steps never resolve it — but
/// it must be a disjoint, addressable slice; one sector suffices.
const WRITE_BOUNCE: usize = WRITE_FILL_SECTOR + WRITE_FILL_SECTOR_LIMIT;
const WRITE_BOUNCE_LIMIT: usize = MAX_SECTOR_SIZE;

const WRITE_SCRATCH_END: usize = WRITE_BOUNCE + WRITE_BOUNCE_LIMIT;

// The qcow2 write scratch must clear the bump-allocator heap. The carve
// is tight: reclaiming WRITE_RB_OFFSETS (16 KiB) and the old zero/pattern
// sectors, and aliasing CallerData over BUF_DEST, is what makes the
// staged L1 (64 KiB) + L2 window (2 MiB) + step buffer (64 KiB) fit.
const _: () = assert!(
    WRITE_SCRATCH_END <= ALLOC_HEAP_BASE,
    "bench qcow2 write scratch overlaps the allocator heap"
);
// A full cluster must fit the COW-fill buffer (BUF_DEST = CallerData) and
// one staged refblock / L2 slot (one cluster) must fit its region.
const _: () = assert!(MAX_CLUSTER_SIZE <= bench::BENCH_MAX_BUFSIZE as usize);
const _: () = assert!(WRITE_L2_WINDOW_LIMIT >= MAX_CLUSTER_SIZE);
const _: () = assert!(WRITE_REFBLOCKS_LIMIT >= MAX_CLUSTER_SIZE);
// The step buffer must be aligned for `[Step]` and hold a useful window.
const _: () = assert!(WRITE_STEP_BUF % core::mem::align_of::<Step>() == 0);
const _: () = assert!(WRITE_STEP_CAPACITY >= 512);
// The staging config the crate is handed must be in range.
const _: () = assert!(WRITE_MAX_REFBLOCKS <= qcow2_write::MAX_REFBLOCKS);

/// qcow2 write-envelope gate ids carried in `BenchResult::error_detail`
/// beside `ERROR_WRITE_UNSUPPORTED`. Mirrors the list documented on
/// `shared::BenchResult::ERROR_WRITE_UNSUPPORTED`; the host renders each
/// via `bench_write_gate_reason`. Gate id `0` ("format has no write
/// support") is emitted by the pre-bracket format fork in `_start`.
///
/// The ids 1-7 equal `qcow2_write::Gate::code()` for the corresponding
/// gates one-to-one (a phase-3 design), pinned by the const-asserts
/// below so a divergence is a build error — this is how the migration
/// keeps bench's `ERROR_WRITE_UNSUPPORTED` rendering while sourcing the
/// gate decisions from the shared `check_envelope`.
mod wgate {
    pub const REFCOUNT_BITS: u64 = 1;
    pub const COMPRESSION: u64 = 2;
    pub const EXTENDED_L2: u64 = 3;
    pub const EXTERNAL_DATA: u64 = 4;
    pub const ENCRYPTION: u64 = 5;
    pub const DIRTY_CORRUPT: u64 = 6;
    pub const SNAPSHOTS: u64 = 7;
}

// The wgate ids equal the crate's Gate codes one-to-one (decision 6's
// gate-code-equality pin — a build error if the crate ever renumbers).
const _: () = assert!(Gate::RefcountWidth.code() as u64 == wgate::REFCOUNT_BITS);
const _: () = assert!(Gate::UnknownIncompatible.code() as u64 == wgate::COMPRESSION);
const _: () = assert!(Gate::ExtendedL2.code() as u64 == wgate::EXTENDED_L2);
const _: () = assert!(Gate::ExternalDataFile.code() as u64 == wgate::EXTERNAL_DATA);
const _: () = assert!(Gate::Encryption.code() as u64 == wgate::ENCRYPTION);
const _: () = assert!(Gate::DirtyCorrupt.code() as u64 == wgate::DIRTY_CORRUPT);
const _: () = assert!(Gate::HasSnapshots.code() as u64 == wgate::SNAPSHOTS);

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
/// `Vmdk4` and the monolithicFlat `VmdkDescriptor`), vhd, vhdx, vdi,
/// parallels, qcow1, and raw (its `_ =>` fallback, which
/// `read_raw_sectors` serves). Every other format — LUKS, qed, iso, the
/// legacy COWD `Vmdk3` — would be silently misread by that raw fallback,
/// so bench refuses it.
///
/// vdi is served by the qcow2 crate's `vdi-input` arm, parallels by its
/// `parallels-input` arm, and qcow1 by its `qcow1-input` arm, which
/// bench enables in its Cargo.toml (alongside `vhd-input`/`vhdx-input`);
/// format-coverage phases 2, 3 and 4 graduate them here in lock-step
/// with the host `chain::ImageFormat` graduation so bench reads VDI,
/// Parallels and QCOW1 rather than refusing them.
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
        ImageFormat::Vdi => Some(5),
        ImageFormat::Parallels => Some(6),
        ImageFormat::Qcow1 => Some(7),
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

/// Write `len` bytes from `src_ptr` into read-write input device 0 at
/// an arbitrary `byte_offset`. A sector-aligned window (offset and
/// length both on a sector boundary) writes straight through; any
/// sub-sector window is a read-modify-write — read the covering sector
/// into `bounce_ptr`, patch the byte window, write it back.
///
/// This is the input-device analog of commit's
/// `write_output_byte_range`, and shares its structure exactly (only
/// the call-table slot differs: `write_input_sector(0, ..)` /
/// `read_input_sector(0, ..)` instead of the output-device pair). It
/// is the raw write primitive: a raw image is a flat file, so a bench
/// write just patches `[offset, offset + bufsize)` in place.
///
/// # Safety
///
/// `call_table` must be the validated `CallTable`; input slot 0 must
/// be attached read-write. `src_ptr` must point at `len` readable
/// bytes and `bounce_ptr` at `sector_size` writable bytes;
/// `sector_size` must be nonzero (guaranteed by `verify_sector_sizes`).
unsafe fn write_input_byte_range(
    call_table: &CallTable,
    sector_size: usize,
    byte_offset: u64,
    src_ptr: *const u8,
    len: usize,
    bounce_ptr: *mut u8,
) -> bool {
    if len == 0 {
        return true;
    }
    let mut written: usize = 0;
    let mut cur_offset = byte_offset;
    while written < len {
        let sector = cur_offset / sector_size as u64;
        let in_sector_off = (cur_offset % sector_size as u64) as usize;
        let take = (sector_size - in_sector_off).min(len - written);

        if in_sector_off == 0 && take == sector_size {
            if !(call_table.write_input_sector)(0, sector, src_ptr.add(written), sector_size) {
                return false;
            }
        } else {
            if !(call_table.read_input_sector)(0, sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(
                src_ptr.add(written),
                bounce_ptr.add(in_sector_off),
                take,
            );
            if !(call_table.write_input_sector)(0, sector, bounce_ptr, sector_size) {
                return false;
            }
        }
        written += take;
        cur_offset += take as u64;
    }
    true
}

// ================================================================
// qcow2 allocating-write path (phase 6 step 6b: migrated onto
// crates/qcow2-write + crates/qcow2-write-exec)
// ================================================================
//
// The per-cluster write path is now driven by the shared windowed
// planner (`plan_write` / `plan_flush`) and its literal guest executor
// (`execute`), replacing bench's hand-inlined disk walk + write-through
// metadata (settled decisions 2-6 of
// PLAN-qcow2-write-infrastructure-phase-06-bench.md). Setup (gates,
// refblock staging, preemptive refcount growth) stays op-side, but its
// gate checks come from the shared `check_envelope` and its growth
// planner from `qcow2_write::growth`; growth EXECUTION is re-pointed at
// the executor's byte-range layer. The `write_input_byte_range` helper
// above is retained solely for the untouched raw `-w` path.

/// Read a big-endian u64 from `buf` at `off`. Callers guarantee
/// `off + 8 <= buf.len()`.
fn read_u64_be(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Invalidate device-0's read-path Qcow2State L1/L2 sector caches so a
/// subsequent chain read (COW fill) observes every prior metadata write.
fn invalidate_dev0_caches(chain_states: &mut qcow2::ChainStates) {
    if let Some(s) = chain_states.qcow2_states[0].as_mut() {
        s.l1_cached_sector = u64::MAX;
        s.l2_cached_sector = u64::MAX;
    }
}

/// Byte geometry of the qcow2-write scratch carve for one run, threaded
/// to the [`StagedRegions`] / [`Regions`] view builders so the planner
/// and executor alias the exact same buffers (the two halves of the
/// qcow2-write decision-1 loop).
#[derive(Clone, Copy)]
struct WriteCarve {
    cluster_size: usize,
    /// Staged active L1 bytes (`hdr.l1_size * 8`) at `WRITE_L1_BUF`.
    l1_bytes: usize,
    /// L2 window bytes (`l2_slots * cluster_size`) at `WRITE_L2_WINDOW`.
    l2_window_bytes: usize,
    /// Staged refcount-table bytes (`refblock_count * 8`) at
    /// `WRITE_RT_BUF`.
    rt_bytes: usize,
    /// Staged refblock bytes (dense prefix) at `WRITE_REFBLOCKS_BUF`.
    rb_bytes: usize,
}

/// Initialise the step-program storage and return it as a `'static`
/// slice (scratch-address carved, never `static` — the .bss hazard
/// class). Every slot is written with a filler step so no slot is ever
/// read uninitialised.
///
/// # Safety
///
/// `WRITE_STEP_BUF` must be a live, `Step`-aligned scratch region of at
/// least `WRITE_STEP_CAPACITY` steps (asserted at const-eval time).
unsafe fn init_step_storage() -> &'static mut [Step] {
    let base = WRITE_STEP_BUF as *mut Step;
    let filler = Step {
        kind: StepKind::ZeroRange,
        device: TargetDevice::Input0,
        region: RegionId::Bounce,
        region_offset: 0,
        disk_offset: 0,
        len: 0,
        value: 0,
    };
    for i in 0..WRITE_STEP_CAPACITY {
        core::ptr::write(base.add(i), filler);
    }
    core::slice::from_raw_parts_mut(base, WRITE_STEP_CAPACITY)
}

/// The planner's view of the staged buffers.
///
/// # Safety
///
/// The returned slices alias the fixed scratch regions; the caller must
/// not hold a [`Regions`] view (or any other aliasing borrow) at the
/// same time. The decision-1 loop guarantees this: plan with the staged
/// view, drop it, execute with the regions view.
unsafe fn staged_view<'a>(carve: &WriteCarve) -> StagedRegions<'a> {
    StagedRegions {
        l1: core::slice::from_raw_parts(WRITE_L1_BUF as *const u8, carve.l1_bytes),
        l2_window: core::slice::from_raw_parts(WRITE_L2_WINDOW as *const u8, carve.l2_window_bytes),
        refcount_table: core::slice::from_raw_parts(WRITE_RT_BUF as *const u8, carve.rt_bytes),
        refblocks: core::slice::from_raw_parts_mut(WRITE_REFBLOCKS_BUF as *mut u8, carve.rb_bytes),
    }
}

/// Execute the emitted step window against the scratch-carved regions
/// and reset the buffer.
///
/// # Safety
///
/// As for [`staged_view`]: the regions alias the fixed scratch carve, so
/// no [`StagedRegions`] view may be live across this call. `CallerData`
/// aliases BUF_DEST (the COW-fill cluster buffer), so the caller must
/// have finished any COW fill into BUF_DEST before the emitted window
/// reads it (the decision-3 protocol does: fill, patch, THEN resubmit).
#[inline(never)]
unsafe fn exec_window(
    io: &mut CallTableIo<'_>,
    steps: &mut StepBuf<'_>,
    carve: &WriteCarve,
) -> Result<(), ExecError> {
    let mut regions = Regions {
        l1: core::slice::from_raw_parts_mut(WRITE_L1_BUF as *mut u8, carve.l1_bytes),
        l2_window: core::slice::from_raw_parts_mut(
            WRITE_L2_WINDOW as *mut u8,
            carve.l2_window_bytes,
        ),
        refcount_table: core::slice::from_raw_parts_mut(WRITE_RT_BUF as *mut u8, carve.rt_bytes),
        refblocks: core::slice::from_raw_parts_mut(WRITE_REFBLOCKS_BUF as *mut u8, carve.rb_bytes),
        bounce: core::slice::from_raw_parts_mut(WRITE_BOUNCE as *mut u8, WRITE_BOUNCE_LIMIT),
        caller_data: core::slice::from_raw_parts_mut(BUF_DEST as *mut u8, carve.cluster_size),
        rmw_sector: core::slice::from_raw_parts_mut(
            WRITE_RMW_BOUNCE as *mut u8,
            WRITE_RMW_BOUNCE_LIMIT,
        ),
        fill_sector: core::slice::from_raw_parts_mut(
            WRITE_FILL_SECTOR as *mut u8,
            WRITE_FILL_SECTOR_LIMIT,
        ),
        cluster_size: carve.cluster_size,
    };
    let r = execute(steps.steps(), &mut regions, io);
    steps.reset();
    r.map(|_| ())
}

/// Render a [`check_envelope_with`] / [`new_state_cow`] gate refusal to bench's
/// wire code. Gates 1-7 keep bench's `ERROR_WRITE_UNSUPPORTED` + gate-id
/// rendering (the ids equal the crate's `Gate::code()`, const-asserted
/// above); the parse-defended `UnsupportedVersion` and the op-controlled
/// `InvalidStagingConfig` are would-be internal bugs (`ERROR_PARSE_FAILED`,
/// bench's internal-bug convention). Exhaustive — a new `Gate` variant is
/// a build error (decision-6 completeness).
fn map_gate(g: Gate) -> (u32, u64) {
    match g {
        Gate::RefcountWidth => (BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::REFCOUNT_BITS),
        Gate::UnknownIncompatible => (BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::COMPRESSION),
        Gate::ExtendedL2 => (BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::EXTENDED_L2),
        Gate::ExternalDataFile => (BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::EXTERNAL_DATA),
        Gate::Encryption => (BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::ENCRYPTION),
        Gate::DirtyCorrupt => (BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::DIRTY_CORRUPT),
        Gate::HasSnapshots => (BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::SNAPSHOTS),
        Gate::UnsupportedVersion | Gate::InvalidStagingConfig => {
            (BenchResult::ERROR_PARSE_FAILED, 0)
        }
    }
}

/// Render a [`plan_write`] / [`plan_flush`] refusal to bench's wire code
/// (settled decision 6). `RefcountExhausted` keeps `ERROR_ALLOC_EXHAUSTED`;
/// `CompressedCluster` keeps bench's mid-run gate-2
/// `ERROR_WRITE_UNSUPPORTED` rendering; the crate classification refusals
/// bench had no prior rendering for map to the appended
/// `ERROR_IMAGE_INCONSISTENT` (code 9); planner-protocol errors are
/// internal bugs (`ERROR_PARSE_FAILED`). Exhaustive.
///
/// Phase 7 (7d) COW adoption: with `new_state_cow`, the crate classifies
/// snapshot-shared data clusters (`SnapshotShared`) and L2 tables
/// (`SnapshotSharedL2Table`) into COW emission instead of returning them
/// as errors, so those arms no longer fire on the `-w` path. They are
/// retained defensively (mapped to the gate-7 `ERROR_WRITE_UNSUPPORTED`
/// rendering a non-COW caller would see) so the match stays exhaustive.
fn map_write_error(e: WriteError) -> (u32, u64) {
    match e {
        WriteError::RefcountExhausted => (BenchResult::ERROR_ALLOC_EXHAUSTED, 0),
        WriteError::CompressedCluster => (BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::COMPRESSION),
        WriteError::SnapshotShared | WriteError::SnapshotSharedL2Table => {
            (BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::SNAPSHOTS)
        }
        WriteError::UnknownL1Entry
        | WriteError::UnknownL2Entry
        | WriteError::RefcountInconsistent
        | WriteError::RefcountCoverage
        | WriteError::StagedRegionsMismatch
        | WriteError::NeedsBackingFill => (BenchResult::ERROR_IMAGE_INCONSISTENT, 0),
        WriteError::BufFull
        | WriteError::NotImplemented
        | WriteError::OutOfBounds
        | WriteError::ResumeMismatch => (BenchResult::ERROR_PARSE_FAILED, 0),
    }
}

/// Render an [`execute`] failure to bench's wire code: device read /
/// write / fsync failures keep bench's `ERROR_IO_*` codes (the old inline
/// path's codes); structural executor-contract violations are guest
/// internal bugs (`ERROR_PARSE_FAILED`). Exhaustive.
fn map_exec_error(e: ExecError) -> (u32, u64) {
    match e.cause {
        ExecCause::ReadFailed => (BenchResult::ERROR_IO_READ, 0),
        ExecCause::WriteFailed => (BenchResult::ERROR_IO_WRITE, 0),
        ExecCause::FsyncFailed => (BenchResult::ERROR_IO_FLUSH, 0),
        ExecCause::RegionBounds
        | ExecCause::UnknownSlot
        | ExecCause::Geometry
        | ExecCause::Overflow
        | ExecCause::StepContract => (BenchResult::ERROR_PARSE_FAILED, 0),
    }
}

/// Derive the exclusive end of the host file, in clusters, from the
/// image's own metadata (new growth structures are placed at this
/// boundary). The virtio capacity hint cannot provide it (the host
/// inflates it so the guest can extend the file); instead take the max
/// over every host offset the metadata names: the highest nonzero staged
/// refcount, the refcount table's extent, the L1 table's extent, each
/// populated refblock cluster (offsets read from the staged RT), and the
/// header cluster.
#[inline(never)]
fn derive_file_end_clusters(
    refblocks: &[u8],
    rt: &[u8],
    refblock_count: usize,
    entries_per_refblock: u64,
    cluster_size: u64,
    hdr: &qcow2::QcowHeader,
) -> u64 {
    // (e) The header cluster always exists.
    let mut end: u64 = 1;
    // (a) Highest staged refblock entry with a nonzero refcount.
    for (slot, block) in refblocks.chunks_exact(cluster_size as usize).enumerate() {
        for e in 0..entries_per_refblock as usize {
            if block[e * 2] != 0 || block[e * 2 + 1] != 0 {
                let cluster_end = slot as u64 * entries_per_refblock + e as u64 + 1;
                end = end.max(cluster_end);
            }
        }
    }
    // (b) The refcount table's extent.
    let rt_end = hdr
        .refcount_table_offset
        .saturating_add((hdr.refcount_table_clusters as u64).saturating_mul(cluster_size));
    end = end.max(rt_end.div_ceil(cluster_size));
    // (c) The L1 table's extent.
    let l1_end = hdr
        .l1_table_offset
        .saturating_add((hdr.l1_size as u64).saturating_mul(8));
    end = end.max(l1_end.div_ceil(cluster_size));
    // (d) Each populated refblock cluster (offsets from the staged RT).
    for slot in 0..refblock_count {
        let off = read_u64_be(rt, slot * 8) & qcow2::L1_OFFSET_MASK;
        end = end.max(off / cluster_size + 1);
    }
    end
}

/// Render a shared [`growth::grow_refcounts`] failure to bench's wire
/// code, preserving the pre-migration inline codes exactly:
/// `StageOutOfCoverage` was the self-coverage-invariant internal-bug
/// path (`ERROR_PARSE_FAILED`); `WriteFailed` / `FsyncFailed` keep
/// bench's `ERROR_IO_WRITE` / `ERROR_IO_FLUSH`.
fn map_growth_error(e: growth::GrowthExecError) -> (u32, u64) {
    match e {
        growth::GrowthExecError::StageOutOfCoverage => (BenchResult::ERROR_PARSE_FAILED, 0),
        growth::GrowthExecError::WriteFailed => (BenchResult::ERROR_IO_WRITE, 0),
        growth::GrowthExecError::FsyncFailed => (BenchResult::ERROR_IO_FLUSH, 0),
    }
}

/// Parse the top image's header, apply the shared write envelope
/// ([`check_envelope_with`], decision 6), stage the refcount table +
/// refblocks + active L1 into scratch, and preemptively grow the
/// refcount structures to the schedule's worst-case coverage. All checks
/// are pre-bracket: a refusal returns before any BenchStart and leaves
/// the image byte-identical, and a schedule whose worst case already fits
/// the populated coverage performs no growth. Returns the parsed header
/// and the (possibly grown) staged refblock count.
///
/// # Safety
///
/// `call_table` / `io` valid; input slot 0 attached read-write.
#[inline(never)]
unsafe fn qcow2_write_setup(
    call_table: &CallTable,
    io: &mut CallTableIo<'_>,
    sector_size: usize,
    params: &bench::BenchParams,
    image_size: u64,
    bytes_read: &mut u64,
) -> Result<(qcow2::QcowHeader, usize), (u32, u64)> {
    // Read + parse sector 0 (carries every gate field). Parse yields an
    // owned QcowHeader, so WRITE_RMW_BOUNCE is free to reuse afterwards.
    if !(call_table.read_input_sector)(0, 0, WRITE_RMW_BOUNCE as *mut u8, sector_size) {
        return Err((BenchResult::ERROR_IO_READ, 0));
    }
    *bytes_read += sector_size as u64;
    let hdr = {
        let hdr_slice = core::slice::from_raw_parts(WRITE_RMW_BOUNCE as *const u8, sector_size);
        match qcow2::QcowHeader::parse(hdr_slice) {
            Some(h) => h,
            None => return Err((BenchResult::ERROR_PARSE_FAILED, 0)),
        }
    };

    // ---- Write-envelope gates (decision 6: the shared check_envelope,
    // rendered onto bench's ERROR_WRITE_UNSUPPORTED + gate-id wire). ----
    //
    // Phase 7 COW adoption (7d, decision 4a/4b, lifting the last of the
    // three interim snapshot-refusal gates): `allow_snapshots = true`
    // relaxes the `Gate::HasSnapshots` refusal so a snapshot-bearing image
    // reaches the COW planner instead of being refused with
    // `ERROR_WRITE_UNSUPPORTED` + gate id 7. Every other gate is
    // unconditional. Paired with `new_state_cow` below, the qcow2-write
    // classifier then emits COW steps for snapshot-shared data clusters
    // (C1) and L2 tables (C2) — bench writes into its own image's active
    // view, so every pre-existing snapshot is preserved (C8), matching a
    // qemu twin. bench already provisions the refcount growth the COW
    // allocations need (the preemptive growth pass below, sized from
    // `worst_case_touched`, which upper-bounds the fresh D'/T' clusters COW
    // allocates exactly as it bounds fresh allocations for unallocated
    // writes), so C9 is inherited unchanged. The `Gate::HasSnapshots`
    // rendering (`wgate::SNAPSHOTS`) is kept for defensive/non-COW callers
    // but no longer fires here.
    if let Err(gate) = check_envelope_with(&hdr, true) {
        return Err(map_gate(gate));
    }

    let cluster_size = hdr.cluster_size;
    let cluster_usize = cluster_size as usize;
    // The COW-fill/CallerData buffer is BUF_DEST (BENCH_MAX_BUFSIZE) and a
    // staged refblock / L2 slot is one cluster — a larger cluster cannot
    // be staged.
    if cluster_usize > bench::BENCH_MAX_BUFSIZE as usize {
        return Err((BenchResult::ERROR_ALLOC_EXHAUSTED, 0));
    }
    // The staged active L1 must fit its region (256 MiB image at cs=512,
    // matched to the refblock cap — this is the new L1 staging bound the
    // migration adds; the pre-migration disk walk had none).
    if (hdr.l1_size as usize).saturating_mul(8) > WRITE_L1_LIMIT {
        return Err((BenchResult::ERROR_ALLOC_EXHAUSTED, 0));
    }
    let entries_per_refblock = cluster_size * 8 / 16; // 16-bit refcounts

    // ---- Stage the refcount table (bounded, contiguous prefix) ----
    let rt_size = (hdr.refcount_table_clusters as usize).saturating_mul(cluster_usize);
    let rt_read = rt_size.min(WRITE_RT_LIMIT);
    if rt_read > 0 {
        let dst = core::slice::from_raw_parts_mut(WRITE_RT_BUF as *mut u8, rt_read);
        let rmw =
            core::slice::from_raw_parts_mut(WRITE_RMW_BOUNCE as *mut u8, WRITE_RMW_BOUNCE_LIMIT);
        if read_bytes(
            io,
            TargetDevice::Input0,
            hdr.refcount_table_offset,
            dst,
            rmw,
        )
        .is_err()
        {
            return Err((BenchResult::ERROR_IO_READ, 0));
        }
    }
    *bytes_read += rt_read as u64;

    // Populated refblocks must run gap-free from RT index 0 (v1
    // contiguity gate → ERROR_PARSE_FAILED, a recorded bench quirk kept
    // as a pure-refactor decision).
    let mut refblock_count: usize = 0;
    {
        let rt = core::slice::from_raw_parts(WRITE_RT_BUF as *const u8, rt_read);
        let mut i = 0usize;
        let mut seen_zero = false;
        while i + 8 <= rt_read {
            let entry = read_u64_be(rt, i) & qcow2::L1_OFFSET_MASK;
            if entry != 0 {
                if seen_zero {
                    return Err((BenchResult::ERROR_PARSE_FAILED, 0));
                }
                refblock_count += 1;
            } else {
                seen_zero = true;
            }
            i += 8;
        }
    }
    if refblock_count == 0 {
        return Err((BenchResult::ERROR_PARSE_FAILED, 0));
    }
    if refblock_count > WRITE_MAX_REFBLOCKS
        || refblock_count.saturating_mul(cluster_usize) > WRITE_REFBLOCKS_LIMIT
    {
        return Err((BenchResult::ERROR_ALLOC_EXHAUSTED, 0));
    }

    // Stage the refblock bytes (host offsets straight from the staged RT).
    for k in 0..refblock_count {
        let host_off = {
            let rt = core::slice::from_raw_parts(WRITE_RT_BUF as *const u8, rt_read);
            read_u64_be(rt, k * 8) & qcow2::L1_OFFSET_MASK
        };
        let dst = core::slice::from_raw_parts_mut(
            (WRITE_REFBLOCKS_BUF + k * cluster_usize) as *mut u8,
            cluster_usize,
        );
        let rmw =
            core::slice::from_raw_parts_mut(WRITE_RMW_BOUNCE as *mut u8, WRITE_RMW_BOUNCE_LIMIT);
        if read_bytes(io, TargetDevice::Input0, host_off, dst, rmw).is_err() {
            return Err((BenchResult::ERROR_IO_READ, 0));
        }
        *bytes_read += cluster_usize as u64;
    }

    // ---- Preemptive refcount growth (decision 1 + growth module) ----
    let mut exec = growth::GrowthExec::new(cluster_size, entries_per_refblock, refblock_count);
    let file_end_clusters = {
        let refblocks = core::slice::from_raw_parts(
            WRITE_REFBLOCKS_BUF as *const u8,
            refblock_count * cluster_usize,
        );
        let rt = core::slice::from_raw_parts(WRITE_RT_BUF as *const u8, refblock_count * 8);
        derive_file_end_clusters(
            refblocks,
            rt,
            refblock_count,
            entries_per_refblock,
            cluster_size,
            &hdr,
        )
    };
    let touched = bench::worst_case_touched(params, image_size, cluster_size);
    let caps = GrowthCaps {
        max_refblocks: WRITE_MAX_REFBLOCKS as u64,
        max_refblock_clusters: (WRITE_REFBLOCKS_LIMIT / cluster_usize) as u64,
        max_rt_slots: (WRITE_RT_LIMIT / 8) as u64,
    };
    let rt_capacity_slots = (hdr.refcount_table_clusters as u64).saturating_mul(cluster_size) / 8;
    let plan = match plan_refcount_growth(
        entries_per_refblock,
        cluster_size,
        file_end_clusters,
        refblock_count as u64,
        rt_capacity_slots,
        touched.data_clusters.saturating_add(touched.l2_tables),
        &caps,
    ) {
        Ok(p) => p,
        Err(GrowthOverflow) => return Err((BenchResult::ERROR_ALLOC_EXHAUSTED, 0)),
    };
    if plan.new_refblocks > 0 {
        // Growth's durability fsyncs must be REAL (the phase-6 census: 1
        // in-place / 2 relocation). The run's `io` is fsync-DISABLED (so
        // `plan_flush` emits zero fsyncs and bench owns the cadence); the
        // growth helper fsyncs through its `DeviceIo`, so it gets a
        // fsync-ENABLED `CallTableIo` on the same call table. Its writes
        // are identical either way — only the fsyncs differ.
        let mut grow_io = CallTableIo::new(call_table, true);
        let mut bufs = growth::GrowthBuffers {
            refcount_table: core::slice::from_raw_parts_mut(
                WRITE_RT_BUF as *mut u8,
                WRITE_RT_LIMIT,
            ),
            refblocks: core::slice::from_raw_parts_mut(
                WRITE_REFBLOCKS_BUF as *mut u8,
                WRITE_REFBLOCKS_LIMIT,
            ),
            rmw_sector: core::slice::from_raw_parts_mut(
                WRITE_RMW_BOUNCE as *mut u8,
                WRITE_RMW_BOUNCE_LIMIT,
            ),
        };
        let rt_table = growth::RefcountTable {
            offset: hdr.refcount_table_offset,
            clusters: hdr.refcount_table_clusters,
        };
        growth::grow_refcounts(
            &mut grow_io,
            TargetDevice::Input0,
            &mut exec,
            &plan,
            rt_table,
            &mut bufs,
        )
        .map_err(map_growth_error)?;
    }
    let refblock_count = exec.refblock_count();

    // ---- Stage the active L1 table for the planner ----
    // NOT counted in bytes_read: the pre-migration disk walk read L1/L2
    // entries per write without counting them, so counting this staging
    // read would perturb bench's reported byte total on the byte-identity
    // buckets. Growth never touches the L1, so its offset is stable.
    let l1_bytes = hdr.l1_size as usize * 8;
    if l1_bytes > 0 {
        let dst = core::slice::from_raw_parts_mut(WRITE_L1_BUF as *mut u8, l1_bytes);
        let rmw =
            core::slice::from_raw_parts_mut(WRITE_RMW_BOUNCE as *mut u8, WRITE_RMW_BOUNCE_LIMIT);
        if read_bytes(io, TargetDevice::Input0, hdr.l1_table_offset, dst, rmw).is_err() {
            return Err((BenchResult::ERROR_IO_READ, 0));
        }
    }

    Ok((hdr, refblock_count))
}

/// Outcome of driving one [`plan_write`] request to completion.
enum WriteOutcome {
    /// The request classified and its window(s) executed.
    Done,
    /// The planner refused `NeedsBackingFill`: a backed partial
    /// allocating write. The caller performs the decision-3 COW fill +
    /// full-cluster resubmit.
    NeedsFill,
    /// A refusal or I/O failure, rendered to (code, detail).
    Fail(u32, u64),
}

/// Drive one `plan_write` request to completion: plan into the step
/// window, execute each window on `BufFull` (resuming with identical
/// args, the decision-1 contract), and surface the outcome. On a
/// `NeedsBackingFill` refusal the benign decision-9 scaffolding (a fresh
/// L2 staged into the window) is executed first so the caller's resubmit
/// classifies against a consistent staged window.
///
/// # Safety
///
/// `state` / `io` / `steps` / `carve` describe one consistent run; the
/// caller must not hold any aliasing scratch borrow across the call.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn drive_plan_write(
    state: &mut WriteState,
    io: &mut CallTableIo<'_>,
    steps: &mut StepBuf<'_>,
    carve: &WriteCarve,
    voff: u64,
    len: u64,
    data: DataSource,
) -> WriteOutcome {
    loop {
        let planned = {
            let mut staged = staged_view(carve);
            plan_write(state, &mut staged, voff, len, data, steps)
        };
        match planned {
            Ok(_) => match exec_window(io, steps, carve) {
                Ok(()) => return WriteOutcome::Done,
                Err(e) => {
                    let (c, d) = map_exec_error(e);
                    return WriteOutcome::Fail(c, d);
                }
            },
            Err(WriteError::BufFull) => {
                if let Err(e) = exec_window(io, steps, carve) {
                    let (c, d) = map_exec_error(e);
                    return WriteOutcome::Fail(c, d);
                }
                // Resume with identical arguments.
            }
            Err(WriteError::NeedsBackingFill) => {
                if let Err(e) = exec_window(io, steps, carve) {
                    let (c, d) = map_exec_error(e);
                    return WriteOutcome::Fail(c, d);
                }
                return WriteOutcome::NeedsFill;
            }
            Err(e) => {
                // Execute the already-emitted window first (preserve the
                // pre-refusal bytes, phases 4-5 posture), then surface the
                // planner refusal — it dominates any exec failure.
                let _ = exec_window(io, steps, carve);
                let (c, d) = map_write_error(e);
                return WriteOutcome::Fail(c, d);
            }
        }
    }
}

/// Drive one full `plan_flush` epoch to completion (decision 4). All
/// Durability barriers degrade to Ordering on the fsync-disabled
/// executor, so the caller issues its own single op-side fsync afterward
/// (or none, at end of bracket).
///
/// # Safety
///
/// As for [`drive_plan_write`].
#[inline(never)]
unsafe fn drive_plan_flush(
    state: &mut WriteState,
    io: &mut CallTableIo<'_>,
    steps: &mut StepBuf<'_>,
    carve: &WriteCarve,
) -> Result<(), (u32, u64)> {
    loop {
        let planned = {
            let mut staged = staged_view(carve);
            plan_flush(state, &mut staged, steps)
        };
        match planned {
            Ok(_) => {
                exec_window(io, steps, carve).map_err(map_exec_error)?;
                return Ok(());
            }
            Err(WriteError::BufFull) => {
                exec_window(io, steps, carve).map_err(map_exec_error)?;
            }
            Err(e) => {
                let _ = exec_window(io, steps, carve);
                return Err(map_write_error(e));
            }
        }
    }
}

/// Self-contained qcow2 `-w` driver: gates + refblock staging +
/// preemptive refcount growth (all pre-bracket), then the per-request
/// allocating loop inside its own timing bracket, closing with the
/// `BenchResult`. Returns `bytes_read`.
///
/// The write path is driven by `crates/qcow2-write` (classification,
/// allocate-on-write, flush ordering) and `crates/qcow2-write-exec`
/// (the literal executor). The executor is fsync-DISABLED so the crate's
/// flush-epoch Durability barriers degrade to Ordering; bench issues its
/// own single op-side `fsync_input(0)` per count-based cadence point,
/// preserving today's fsync census exactly (decision 4).
///
/// # Safety
///
/// `call_table` valid; input slot 0 attached read-write; parents (if
/// any) read-only; `chain_states` initialised by `init_chain_states`.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn run_qcow2_write(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    params: &bench::BenchParams,
    device_count: usize,
    sector_size: usize,
    image_size: u64,
    chain_states: &mut qcow2::ChainStates,
    mut bytes_read: u64,
) -> u64 {
    // fsync-DISABLED executor I/O (decision 4): every plan_flush
    // Durability barrier on Input0 degrades to Ordering, so the executor
    // emits ZERO fsyncs and bench owns the cadence fsyncs itself.
    let mut io = CallTableIo::new(call_table, false);

    // ---- Pre-bracket setup + envelope gates + preemptive growth ----
    let (hdr, refblock_count) = match qcow2_write_setup(
        call_table,
        &mut io,
        sector_size,
        params,
        image_size,
        &mut bytes_read,
    ) {
        Ok(v) => v,
        Err((error, detail)) => return fail(call_table, error, 0, detail, bytes_read),
    };

    // ---- Build the planner state + carve over the GROWN staged set ----
    let cluster_size = hdr.cluster_size;
    let cluster_usize = cluster_size as usize;
    let l2_slots = (WRITE_L2_WINDOW_LIMIT / cluster_usize).min(MAX_L2_SLOTS);
    let staging_config = StagingConfig {
        l2_slots,
        max_refblocks: refblock_count,
        device: TargetDevice::Input0,
    };
    // COW-enabled (phase 7, 7d, decision 4b): snapshot-shared data
    // clusters (C1) and L2 tables (C2) classify into COW emission instead
    // of refusing, so `bench -w` into a snapshot-bearing image copies the
    // shared clusters and preserves every pre-existing snapshot (C8).
    let mut wstate = match new_state_cow(&hdr, &staging_config) {
        Ok(s) => s,
        Err(gate) => {
            let (error, detail) = map_gate(gate);
            return fail(call_table, error, 0, detail, bytes_read);
        }
    };
    let carve = WriteCarve {
        cluster_size: cluster_usize,
        l1_bytes: hdr.l1_size as usize * 8,
        l2_window_bytes: l2_slots * cluster_usize,
        rt_bytes: refblock_count * 8,
        rb_bytes: refblock_count * cluster_usize,
    };
    let steps_storage = init_step_storage();
    let mut step_buf = StepBuf::new(steps_storage);

    let virtual_size = wstate.geometry().virtual_size;
    let pattern = params.pattern;
    let bufsize = params.bufsize;
    let schedule = bench::OffsetSchedule::new(params, image_size);
    let mut staging_cluster_offset: u64 = u64::MAX;

    // ---- Timing bracket opens here ----
    (call_table.send_bench_start)();

    let mut completed: u64 = 0;
    let mut flushes_issued: u64 = 0;
    for offset in schedule {
        // EOF pre-check (matches the raw path).
        let overruns = match offset.checked_add(bufsize) {
            Some(end) => end > image_size,
            None => true,
        };
        if overruns {
            (call_table.send_error)(
                b"bench\0".as_ptr(),
                b"write\0".as_ptr(),
                offset / sector_size as u64,
                1,
            );
            return fail(
                call_table,
                BenchResult::ERROR_IO_WRITE,
                completed,
                offset,
                bytes_read,
            );
        }

        // Split the request at cluster boundaries and apply each cluster.
        let end = offset + bufsize;
        let mut voff = offset;
        while voff < end {
            let cluster_start = (voff / cluster_size) * cluster_size;
            let cluster_end = cluster_start + cluster_size;
            let win_end = cluster_end.min(end);
            let in_off = (voff - cluster_start) as usize;
            let win_len = win_end - voff;

            // Decision 3: submit the pattern window as-is.
            match drive_plan_write(
                &mut wstate,
                &mut io,
                &mut step_buf,
                &carve,
                voff,
                win_len,
                DataSource::Fill { byte: pattern },
            ) {
                WriteOutcome::Done => {}
                WriteOutcome::NeedsFill => {
                    // Backed partial allocating write: chain-read the
                    // pre-image cluster into BUF_DEST, patch the pattern
                    // window, and resubmit the whole cluster as
                    // CallerData (the resubmit classifies against the
                    // staged window and allocates L2-then-data).
                    invalidate_dev0_caches(chain_states);
                    HEAP_POS.store(0, Ordering::Relaxed);
                    let cow = BUF_DEST as *mut u8;
                    if !qcow2::read_chain_virtual_cluster(
                        call_table,
                        0,
                        device_count,
                        cluster_start,
                        cow,
                        cluster_size,
                        sector_size,
                        chain_config,
                        chain_states,
                        BUF_COMPRESSED as *mut u8,
                        BUF_STAGING as *mut u8,
                        &mut staging_cluster_offset,
                        None,
                        None,
                        512,
                        &mut bytes_read,
                    ) {
                        return fail(
                            call_table,
                            BenchResult::ERROR_IO_READ,
                            completed,
                            voff,
                            bytes_read,
                        );
                    }
                    core::ptr::write_bytes(cow.add(in_off), pattern, win_len as usize);
                    let resub_len = cluster_size.min(virtual_size - cluster_start);
                    match drive_plan_write(
                        &mut wstate,
                        &mut io,
                        &mut step_buf,
                        &carve,
                        cluster_start,
                        resub_len,
                        DataSource::CallerData { offset: 0 },
                    ) {
                        WriteOutcome::Done => {}
                        WriteOutcome::NeedsFill => {
                            // Defensive: a full-cluster resubmit must not
                            // re-refuse (decision 6).
                            return fail(
                                call_table,
                                BenchResult::ERROR_IMAGE_INCONSISTENT,
                                completed,
                                0,
                                bytes_read,
                            );
                        }
                        WriteOutcome::Fail(error, detail) => {
                            return fail(call_table, error, completed, detail, bytes_read);
                        }
                    }
                    // The new L1/L2 bytes are staged; invalidate again so
                    // the next COW read sees the flushed metadata.
                    invalidate_dev0_caches(chain_states);
                }
                WriteOutcome::Fail(error, detail) => {
                    return fail(call_table, error, completed, detail, bytes_read);
                }
            }
            voff = win_end;
        }
        completed += 1;
        bytes_read += bufsize;

        // Flush cadence (decision 4): drive ONE full plan_flush epoch
        // (staged dirty L2s + L1 + dirty refblocks reach disk — no
        // executor fsync) then issue exactly ONE op-side fsync.
        // `flushes_issued` counts cadence points only.
        if bench::flush_after_completion(params.count, completed as u32, params.flush_interval) {
            if let Err((error, detail)) =
                drive_plan_flush(&mut wstate, &mut io, &mut step_buf, &carve)
            {
                return fail(call_table, error, completed, detail, bytes_read);
            }
            if !(call_table.fsync_input)(0) {
                return fail(
                    call_table,
                    BenchResult::ERROR_IO_FLUSH,
                    completed,
                    completed,
                    bytes_read,
                );
            }
            flushes_issued += 1;
        }
    }

    // Final flush epoch (refcounts last), inside the bracket, NO fsync:
    // when the interval divides count the cadence already fsynced at
    // k == count, leaving nothing dirty here.
    if let Err((error, detail)) = drive_plan_flush(&mut wstate, &mut io, &mut step_buf, &carve) {
        return fail(call_table, error, completed, detail, bytes_read);
    }

    // ---- Success: close the bracket ----
    let result = BenchResult {
        magic: BenchResult::MAGIC,
        error: BenchResult::ERROR_OK,
        requests_completed: params.count as u64,
        flushes_issued,
        error_detail: 0,
        _reserved: [0; 32],
    };
    (call_table.send_bench_result)(&result);
    (call_table.send_complete)(b"bench\0".as_ptr(), bytes_read, true);
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
    // Write vs read mode (phase 5). FLAG_WRITE selects the write-mode
    // fork below; the raw-only gate (phase 5a) is applied after the
    // format probe, pre-bracket. FLAG_NO_DRAIN is read (and documented)
    // but is a no-op under serial execution.
    let is_write = config.flags & BenchConfig::FLAG_WRITE != 0;
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

    // ---- Write-mode format gate (pre-bracket) ----
    // Write mode supports RAW (phase 5a, in place) and QCOW2 (phase 5b,
    // allocating). Any other family-checked format reaching here under
    // FLAG_WRITE is refused with ERROR_WRITE_UNSUPPORTED and gate id 0
    // ("format has no write support yet"); the host already refuses
    // non-{raw,qcow2} before launching, so this is defence in depth.
    // The qcow2 envelope checks (refcount_bits, compression, extended-L2,
    // external data, LUKS, dirty/corrupt, snapshots) run inside
    // `run_qcow2_write` before its own BenchStart. `cfg` is the host's
    // format claim, already cross-checked against dev0 and the guest's
    // own sector-0 probe at the gate above.
    if is_write {
        match cfg {
            ImageFormat::Raw | ImageFormat::Qcow2 => {}
            _ => {
                return fail(
                    call_table,
                    BenchResult::ERROR_WRITE_UNSUPPORTED,
                    0,
                    0, // gate id 0: format has no write support yet
                    bytes_read,
                );
            }
        }
    }

    // Virtual size is convert's source of truth: the top-of-chain
    // device's declared virtual size.
    let image_size = chain_config.devices[0].virtual_size;

    // ---- Bench parameters ----
    // Raw values straight from the config; the crate's effective_step()
    // / OffsetSchedule own the wrap resolution. `is_write` selects the
    // write-mode loop below (raw-gated above).
    let params = bench::BenchParams {
        count: config.count,
        depth: config.depth,
        bufsize,
        step: config.step,
        offset: config.offset,
        is_write,
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

    // ---- Write path fork: qcow2 allocating writes (phase 5b) ----
    // qcow2 `-w` runs a self-contained driver: it parses the header,
    // applies the write-envelope gates (pre-bracket), stages the refcount
    // table + refblocks, then opens its OWN timing bracket around the
    // per-cluster allocating loop and closes it with the result. Split
    // out both to keep `_start` small enough to codegen correctly under
    // opt-level=z + lto (the sibling ops' inline(never) discipline) and
    // because its gate set differs from raw's. Raw and the read path fall
    // through to the shared bracket below.
    if params.is_write && matches!(cfg, ImageFormat::Qcow2) {
        return run_qcow2_write(
            call_table,
            chain_config,
            &params,
            device_count,
            sector_size,
            image_size,
            &mut chain_states,
            bytes_read,
        );
    }

    let schedule = bench::OffsetSchedule::new(&params, image_size);

    // ---- Timing bracket opens here ----
    // Emitted after all setup, immediately before the first request,
    // mirroring qemu's gettimeofday placement (see the send_bench_start
    // doc contract in `shared`).
    (call_table.send_bench_start)();

    // ---- Write path (phase 5a: raw, in place) ----
    // The raw-only gate above guarantees a write run reaching here is a
    // flat raw file; each request patches `[offset, offset + bufsize)`
    // with the pattern byte through RW input slot 0.
    if params.is_write {
        // Fill the pattern source once. Every request writes `bufsize`
        // bytes of the pattern's low byte — qemu fills its write buffer
        // with the pattern byte identically, so after equal-arg runs the
        // two images are byte-comparable. BUF_DEST is the pattern
        // source; BUF_COMPRESSED (unused on the write path — nothing
        // decompresses) doubles as the sub-sector RMW bounce.
        core::ptr::write_bytes(BUF_DEST as *mut u8, params.pattern, bufsize as usize);
        let src_ptr = BUF_DEST as *const u8;
        let bounce_ptr = BUF_COMPRESSED as *mut u8;

        let mut completed: u64 = 0;
        let mut flushes_issued: u64 = 0;
        for offset in schedule {
            // EOF pre-check: a write whose window overruns image_size is
            // refused, reproducing qemu's "Failed request" EIO on raw
            // (mapped to ERROR_IO_WRITE). The wrap rule keeps every
            // offset after the first inside [0, image_size - bufsize], so
            // only the raw first `-o` (or a degenerate image) reaches here.
            let overruns = match offset.checked_add(bufsize) {
                Some(end) => end > image_size,
                None => true,
            };
            let ok = !overruns
                && write_input_byte_range(
                    call_table,
                    sector_size,
                    offset,
                    src_ptr,
                    bufsize as usize,
                    bounce_ptr,
                );
            if !ok {
                (call_table.send_error)(
                    b"bench\0".as_ptr(),
                    b"write\0".as_ptr(),
                    offset / sector_size as u64,
                    1,
                );
                return fail(
                    call_table,
                    BenchResult::ERROR_IO_WRITE,
                    completed,
                    offset,
                    bytes_read,
                );
            }
            completed += 1;
            bytes_read += bufsize;

            // Flush cadence owned by crates/bench: flush after completion
            // k exactly when the schedule says so (this includes the
            // trailing flush at k == count, inside the timed window).
            // FLAG_NO_DRAIN is a no-op under serial execution — the queue
            // is always drained — but the flush still fires. A flush
            // failure is ERROR_IO_FLUSH with error_detail = k.
            if bench::flush_after_completion(params.count, completed as u32, params.flush_interval)
            {
                if !(call_table.fsync_input)(0) {
                    return fail(
                        call_table,
                        BenchResult::ERROR_IO_FLUSH,
                        completed,
                        completed,
                        bytes_read,
                    );
                }
                flushes_issued += 1;
            }
        }

        // ---- Success: close the bracket ----
        // `flushes_issued` was counted request-by-request; by
        // construction it equals bench::total_flushes(count, interval)
        // (the cadence unit-tested in crates/bench). Send the counted
        // value.
        let result = BenchResult {
            magic: BenchResult::MAGIC,
            error: BenchResult::ERROR_OK,
            requests_completed: params.count as u64,
            flushes_issued,
            error_detail: 0,
            _reserved: [0; 32],
        };
        (call_table.send_bench_result)(&result);
        (call_table.send_complete)(b"bench\0".as_ptr(), bytes_read, true);
        return bytes_read;
    }

    // ---- Read path: one read_chain_virtual_range per offset ----
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
