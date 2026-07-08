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

// ================================================================
// qcow2 write-mode scratch (phase 5b, Mission §1-§2)
// ================================================================
// Only the qcow2 `-w` path touches these regions; the read path and the
// raw `-w` path never reference them. They sit ABOVE the per-device
// L1/L2 caches `init_chain_states` consumes (2 × MAX_SECTOR_SIZE per
// chain device, growing up from DYNAMIC_START).
//
// The COW-fill cluster buffer reuses BUF_DEST (a full MAX_CLUSTER_SIZE
// region, free on the qcow2 write path — the pattern is patched into the
// COW-filled cluster directly, so no separate cluster-sized pattern
// buffer is needed), and `read_chain_virtual_cluster` keeps using
// BUF_COMPRESSED / BUF_STAGING for backing-chain decompression. The
// bounded refblock staging mirrors bitmap/snapshot exactly.

/// First free byte above the dynamic per-device caches.
const WRITE_SCRATCH_BASE: usize = DYNAMIC_START + 2 * MAX_SECTOR_SIZE * MAX_CHAIN_DEVICES;

/// Upper bound on staged refcount blocks (same bound as snapshot/bitmap):
/// 32 refblocks of a 64 KiB cluster cover 64 GiB of host address space
/// (a 16-bit refblock indexes `cluster_size * 8 / 16` entries), far past
/// anything bench writes end-to-end. A larger populated table refuses
/// with `ERROR_ALLOC_EXHAUSTED` ("image too large for in-place bench
/// write").
const WRITE_MAX_REFBLOCKS: usize = 32;

/// Staged refcount-table prefix. The contiguous populated run of refblock
/// offsets always lives in the first `WRITE_MAX_REFBLOCKS * 8` bytes.
const WRITE_RT_BUF: usize = WRITE_SCRATCH_BASE;
const WRITE_RT_LIMIT: usize = 64 * 1024;

/// Refblock host-offset array (`WRITE_MAX_REFBLOCKS` × u64).
const WRITE_RB_OFFSETS: usize = WRITE_RT_BUF + WRITE_RT_LIMIT;
const WRITE_RB_OFFSETS_LIMIT: usize = 16 * 1024;

/// Staged refcount blocks, dirty-tracked and written back refcounts-last
/// (Mission §2).
const WRITE_REFBLOCKS_BUF: usize = WRITE_RB_OFFSETS + WRITE_RB_OFFSETS_LIMIT;
const WRITE_REFBLOCKS_LIMIT: usize = 2 * 1024 * 1024;

/// One sector of zeros — the source for zeroing a freshly allocated L2
/// table cluster before the L1 entry points at it.
const WRITE_ZERO_SECTOR: usize = WRITE_REFBLOCKS_BUF + WRITE_REFBLOCKS_LIMIT;
const WRITE_ZERO_SECTOR_LIMIT: usize = MAX_SECTOR_SIZE;

/// One sector filled with the pattern byte — the source for the
/// overwrite-in-place fast path's sub-sector RMW writes.
const WRITE_PATTERN_SECTOR: usize = WRITE_ZERO_SECTOR + WRITE_ZERO_SECTOR_LIMIT;
const WRITE_PATTERN_SECTOR_LIMIT: usize = MAX_SECTOR_SIZE;

/// Sub-sector RMW bounce for the qcow2 metadata/data writes (kept
/// separate from the raw path's bounce, which reuses BUF_COMPRESSED).
const WRITE_RMW_BOUNCE: usize = WRITE_PATTERN_SECTOR + WRITE_PATTERN_SECTOR_LIMIT;
const WRITE_RMW_BOUNCE_LIMIT: usize = MAX_SECTOR_SIZE;

const WRITE_SCRATCH_END: usize = WRITE_RMW_BOUNCE + WRITE_RMW_BOUNCE_LIMIT;

// The qcow2 write scratch must clear the bump-allocator heap.
const _: () = assert!(
    WRITE_SCRATCH_END <= ALLOC_HEAP_BASE,
    "bench qcow2 write scratch overlaps the allocator heap"
);
// A single staged refblock (one cluster) must fit REFBLOCKS_LIMIT / count,
// and a full cluster must fit the COW-fill buffer (BUF_DEST).
const _: () = assert!(MAX_CLUSTER_SIZE <= bench::BENCH_MAX_BUFSIZE as usize);

/// qcow2 write-envelope gate ids carried in `BenchResult::error_detail`
/// beside `ERROR_WRITE_UNSUPPORTED`. Mirrors the list documented on
/// `shared::BenchResult::ERROR_WRITE_UNSUPPORTED`; the host renders each
/// via `bench_write_gate_reason`. Gate id `0` ("format has no write
/// support") is emitted by the pre-bracket format fork in `_start`.
mod wgate {
    pub const REFCOUNT_BITS: u64 = 1;
    pub const COMPRESSION: u64 = 2;
    pub const EXTENDED_L2: u64 = 3;
    pub const EXTERNAL_DATA: u64 = 4;
    pub const ENCRYPTION: u64 = 5;
    pub const DIRTY_CORRUPT: u64 = 6;
    pub const SNAPSHOTS: u64 = 7;
}

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
// qcow2 allocating-write path (phase 5b)
// ================================================================

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

/// Op-lifetime qcow2 write context: the header geometry the driver
/// needs plus the staged-refblock allocator state.
struct QcowWriteCtx {
    cluster_size: u64,
    l1_table_offset: u64,
    l1_size: u32,
    /// L2 entries per L2 table (`cluster_size / 8`; extended-L2 gated out).
    entries_per_l2: u64,
    /// Virtual bytes covered by one L2 table (`cluster_size * entries_per_l2`).
    l2_coverage: u64,
    /// Number of staged (contiguous-from-index-0) refcount blocks.
    refblock_count: usize,
    /// Refcount entries per refblock (`cluster_size * 8 / 16`).
    entries_per_refblock: u64,
    /// Host offset that staged-refblock index 0 covers (0 under the
    /// contiguous-from-index-0 gate).
    host_refblocks_start: u64,
    /// Linear-scan allocator cursor (snapshot's primitive).
    cursor: snapshot::qcow2::AllocCursor,
    /// Per-refblock dirty flags (write back at flush points / run end).
    dirty: [bool; WRITE_MAX_REFBLOCKS],
}

/// Read `len` bytes from input device 0 at `byte_offset` into
/// `dst_ptr`, routing sub-sector reads through `bounce_ptr`. The
/// read-side analog of [`write_input_byte_range`] (copied from
/// bitmap's `read_input_byte_range`), used for the uncached L1/L2
/// decision walk and the refblock staging reads.
///
/// # Safety
///
/// `call_table` must be the validated `CallTable`; `dst_ptr` must
/// point at `len` writable bytes and `bounce_ptr` at `sector_size`
/// writable bytes.
unsafe fn read_input_byte_range(
    call_table: &CallTable,
    sector_size: usize,
    byte_offset: u64,
    dst_ptr: *mut u8,
    len: usize,
    bounce_ptr: *mut u8,
) -> bool {
    if len == 0 {
        return true;
    }
    let mut done: usize = 0;
    let mut cur = byte_offset;
    while done < len {
        let sector = cur / sector_size as u64;
        let in_off = (cur % sector_size as u64) as usize;
        let take = (sector_size - in_off).min(len - done);
        if in_off == 0 && take == sector_size {
            if !(call_table.read_input_sector)(0, sector, dst_ptr.add(done), sector_size) {
                return false;
            }
        } else {
            if !(call_table.read_input_sector)(0, sector, bounce_ptr, sector_size) {
                return false;
            }
            core::ptr::copy_nonoverlapping(bounce_ptr.add(in_off), dst_ptr.add(done), take);
        }
        done += take;
        cur += take as u64;
    }
    true
}

/// Write a big-endian u64 `value` to the on-disk 8-byte L1/L2 entry at
/// `disk_off` via a covering-sector RMW (the entry is sub-sector).
///
/// # Safety
///
/// `call_table` valid; `bounce_ptr` points at `sector_size` writable
/// bytes.
unsafe fn write_qcow2_entry(
    call_table: &CallTable,
    sector_size: usize,
    disk_off: u64,
    value: u64,
    bounce_ptr: *mut u8,
) -> bool {
    let be = value.to_be_bytes();
    write_input_byte_range(
        call_table,
        sector_size,
        disk_off,
        be.as_ptr(),
        8,
        bounce_ptr,
    )
}

/// Write `cluster_size` bytes of the pre-zeroed [`WRITE_ZERO_SECTOR`]
/// buffer to `host_off`, sector by sector, zeroing a freshly allocated
/// L2 table cluster before the L1 entry points at it.
///
/// # Safety
///
/// `call_table` valid; `bounce_ptr` points at `sector_size` writable
/// bytes; [`WRITE_ZERO_SECTOR`] is filled with zeros by the driver.
unsafe fn zero_cluster(
    call_table: &CallTable,
    sector_size: usize,
    host_off: u64,
    cluster_size: u64,
    bounce_ptr: *mut u8,
) -> bool {
    let zsrc = WRITE_ZERO_SECTOR as *const u8;
    let mut done: u64 = 0;
    while done < cluster_size {
        let chunk = (cluster_size - done).min(sector_size as u64) as usize;
        if !write_input_byte_range(
            call_table,
            sector_size,
            host_off + done,
            zsrc,
            chunk,
            bounce_ptr,
        ) {
            return false;
        }
        done += chunk as u64;
    }
    true
}

/// Patch `len` pattern bytes at `host_off` from the pre-filled
/// [`WRITE_PATTERN_SECTOR`] buffer, chunking so each RMW sees `<=
/// sector_size` source bytes (the pattern is uniform, so the chunk's
/// alignment within the source is irrelevant).
///
/// # Safety
///
/// `call_table` valid; `bounce_ptr` points at `sector_size` writable
/// bytes; [`WRITE_PATTERN_SECTOR`] is filled with the pattern by the
/// driver.
unsafe fn write_pattern_range(
    call_table: &CallTable,
    sector_size: usize,
    host_off: u64,
    len: usize,
    bounce_ptr: *mut u8,
) -> bool {
    let psrc = WRITE_PATTERN_SECTOR as *const u8;
    let mut done: usize = 0;
    while done < len {
        let chunk = (len - done).min(sector_size);
        if !write_input_byte_range(
            call_table,
            sector_size,
            host_off + done as u64,
            psrc,
            chunk,
            bounce_ptr,
        ) {
            return false;
        }
        done += chunk;
    }
    true
}

/// Allocate one fresh cluster from the staged refblocks (snapshot's
/// linear-scan allocator, which also sets the claimed refcount to 1 in
/// the staged blocks). Marks the covering refblock dirty for the next
/// refcounts-last write-back. `RefcountExhausted` surfaces as
/// `ERROR_ALLOC_EXHAUSTED`.
fn alloc_one_cluster(ctx: &mut QcowWriteCtx) -> Result<u64, (u32, u64)> {
    let blocks = unsafe {
        core::slice::from_raw_parts_mut(
            WRITE_REFBLOCKS_BUF as *mut u8,
            ctx.refblock_count * ctx.cluster_size as usize,
        )
    };
    match snapshot::qcow2::alloc_contiguous_clusters_in_refblocks(
        blocks,
        ctx.cluster_size,
        16,
        ctx.refblock_count as u64,
        ctx.host_refblocks_start,
        1,
        &mut ctx.cursor,
    ) {
        Ok(off) => {
            let cluster_index = (off - ctx.host_refblocks_start) / ctx.cluster_size;
            let slot = (cluster_index / ctx.entries_per_refblock) as usize;
            if slot < ctx.refblock_count {
                ctx.dirty[slot] = true;
            }
            Ok(off)
        }
        Err(snapshot::SnapshotError::RefcountExhausted) => {
            Err((BenchResult::ERROR_ALLOC_EXHAUSTED, 0))
        }
        // InvalidConfig / Unsupported / arithmetic — all impossible for a
        // gated 16-bit image, but surface as a parse failure rather than
        // corrupt on a would-be internal bug.
        Err(_) => Err((BenchResult::ERROR_PARSE_FAILED, 0)),
    }
}

/// Write back every dirty staged refblock to its host offset (refcounts
/// last relative to the data / L2 they cover) and clear the dirty flags.
///
/// # Safety
///
/// `call_table` valid; the refblock host offsets live in
/// [`WRITE_RB_OFFSETS`] and the staged bytes in [`WRITE_REFBLOCKS_BUF`].
unsafe fn flush_dirty_refblocks(
    call_table: &CallTable,
    sector_size: usize,
    ctx: &mut QcowWriteCtx,
) -> bool {
    let cluster_usize = ctx.cluster_size as usize;
    let rb_offsets =
        core::slice::from_raw_parts(WRITE_RB_OFFSETS as *const u64, ctx.refblock_count);
    let bounce = WRITE_RMW_BOUNCE as *mut u8;
    for slot in 0..ctx.refblock_count {
        if !ctx.dirty[slot] {
            continue;
        }
        let src = (WRITE_REFBLOCKS_BUF + slot * cluster_usize) as *const u8;
        if !write_input_byte_range(
            call_table,
            sector_size,
            rb_offsets[slot],
            src,
            cluster_usize,
            bounce,
        ) {
            return false;
        }
        ctx.dirty[slot] = false;
    }
    true
}

/// Parse the top image's header, apply the write-envelope gates
/// (Mission §3), and stage the refcount table + refblocks into scratch.
/// All checks are pre-bracket: a refusal returns before any BenchStart
/// and leaves the image byte-identical.
///
/// # Safety
///
/// `call_table` valid; input slot 0 attached read-write.
#[inline(never)]
unsafe fn qcow2_write_setup(
    call_table: &CallTable,
    sector_size: usize,
    bytes_read: &mut u64,
) -> Result<QcowWriteCtx, (u32, u64)> {
    let bounce = WRITE_RMW_BOUNCE as *mut u8;

    // Read + parse sector 0 (carries every gate field). Parse yields an
    // owned QcowHeader, so the bounce buffer is free to reuse afterwards.
    if !(call_table.read_input_sector)(0, 0, bounce, sector_size) {
        return Err((BenchResult::ERROR_IO_READ, 0));
    }
    *bytes_read += sector_size as u64;
    let hdr = {
        let hdr_slice = core::slice::from_raw_parts(bounce as *const u8, sector_size);
        match qcow2::QcowHeader::parse(hdr_slice) {
            Some(h) => h,
            None => return Err((BenchResult::ERROR_PARSE_FAILED, 0)),
        }
    };

    // ---- Write-envelope gates (Mission §3) ----
    if hdr.refcount_bits != 16 {
        return Err((BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::REFCOUNT_BITS));
    }
    const KNOWN_INCOMPAT: u64 = qcow2::INCOMPAT_DIRTY
        | qcow2::INCOMPAT_CORRUPT
        | qcow2::INCOMPAT_EXTERNAL_DATA
        | qcow2::INCOMPAT_COMPRESSION
        | qcow2::INCOMPAT_EXTENDED_L2;
    if hdr.incompatible_features & qcow2::INCOMPAT_COMPRESSION != 0
        || hdr.incompatible_features & !KNOWN_INCOMPAT != 0
    {
        return Err((BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::COMPRESSION));
    }
    if hdr.extended_l2 {
        return Err((BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::EXTENDED_L2));
    }
    if hdr.has_external_data {
        return Err((BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::EXTERNAL_DATA));
    }
    if hdr.crypt_method != 0 {
        return Err((BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::ENCRYPTION));
    }
    if hdr.dirty || hdr.corrupt {
        return Err((BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::DIRTY_CORRUPT));
    }
    if hdr.nb_snapshots > 0 {
        return Err((BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::SNAPSHOTS));
    }

    let cluster_size = hdr.cluster_size;
    // The COW-fill cluster buffer is BUF_DEST (BENCH_MAX_BUFSIZE) and each
    // staged refblock is one cluster — a larger cluster cannot be staged.
    if cluster_size as usize > bench::BENCH_MAX_BUFSIZE as usize {
        return Err((BenchResult::ERROR_ALLOC_EXHAUSTED, 0));
    }
    let cluster_usize = cluster_size as usize;
    let entries_per_l2 = cluster_size / 8; // standard L2 (extended-L2 gated out)
    let l2_coverage = cluster_size * entries_per_l2;
    let entries_per_refblock = cluster_size * 8 / 16; // 16-bit refcounts

    // ---- Stage the refcount table (bounded, contiguous prefix) ----
    let rt_size = (hdr.refcount_table_clusters as usize).saturating_mul(cluster_usize);
    let rt_read = rt_size.min(WRITE_RT_LIMIT);
    if rt_read > 0
        && !read_input_byte_range(
            call_table,
            sector_size,
            hdr.refcount_table_offset,
            WRITE_RT_BUF as *mut u8,
            rt_read,
            bounce,
        )
    {
        return Err((BenchResult::ERROR_IO_READ, 0));
    }
    *bytes_read += rt_read as u64;
    let rt = core::slice::from_raw_parts(WRITE_RT_BUF as *const u8, rt_read);

    // Populated refblocks must run gap-free from refcount-table index 0
    // (v1 contiguity gate, so refblock slot == cluster / entries_per_rb).
    let mut refblock_count: usize = 0;
    {
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

    // Record the refblock host offsets, then stage the refblock bytes.
    let rb_offsets = core::slice::from_raw_parts_mut(WRITE_RB_OFFSETS as *mut u64, refblock_count);
    for (k, slot) in rb_offsets.iter_mut().enumerate() {
        *slot = read_u64_be(rt, k * 8) & qcow2::L1_OFFSET_MASK;
    }
    for k in 0..refblock_count {
        let host_off = rb_offsets[k];
        let dst = (WRITE_REFBLOCKS_BUF + k * cluster_usize) as *mut u8;
        if !read_input_byte_range(
            call_table,
            sector_size,
            host_off,
            dst,
            cluster_usize,
            bounce,
        ) {
            return Err((BenchResult::ERROR_IO_READ, 0));
        }
        *bytes_read += cluster_usize as u64;
    }

    Ok(QcowWriteCtx {
        cluster_size,
        l1_table_offset: hdr.l1_table_offset,
        l1_size: hdr.l1_size,
        entries_per_l2,
        l2_coverage,
        refblock_count,
        entries_per_refblock,
        // Refblocks contiguous from RT index 0 ⇒ index 0 covers cluster 0.
        host_refblocks_start: 0,
        cursor: snapshot::qcow2::AllocCursor::default(),
        dirty: [false; WRITE_MAX_REFBLOCKS],
    })
}

/// Invalidate device-0's read-path Qcow2State L1/L2 sector caches so a
/// subsequent chain read (COW fill) or the read path observes every
/// write-through. See the module cache-coherence note.
fn invalidate_dev0_caches(chain_states: &mut qcow2::ChainStates) {
    if let Some(s) = chain_states.qcow2_states[0].as_mut() {
        s.l1_cached_sector = u64::MAX;
        s.l2_cached_sector = u64::MAX;
    }
}

/// Apply one bench write to a single touched cluster: the overwrite
/// fast path, or the allocating path with chain-read COW fill and the
/// write-through L2/L1 update (Mission §1-§2).
///
/// `voff` is the virtual byte offset where this cluster's window starts,
/// `in_off` the byte offset within the cluster, `win_len` the window
/// length (all within one cluster). Returns `(error, detail)` on refusal
/// or I/O failure.
///
/// # Safety
///
/// `call_table` valid; input slot 0 attached read-write; `ctx` staged by
/// [`qcow2_write_setup`].
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn qcow2_write_cluster(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    chain_states: &mut qcow2::ChainStates,
    device_count: usize,
    sector_size: usize,
    ctx: &mut QcowWriteCtx,
    voff: u64,
    in_off: usize,
    win_len: usize,
    pattern: u8,
    staging_cluster_offset: &mut u64,
    bytes_read: &mut u64,
) -> Result<(), (u32, u64)> {
    let cs = ctx.cluster_size;
    let cluster_start = (voff / cs) * cs;
    let l1_idx = voff / ctx.l2_coverage;
    if l1_idx >= ctx.l1_size as u64 {
        // Would require growing the L1 table — unsupported (v1). Cannot
        // occur for offsets within virtual_size on a well-formed image.
        return Err((BenchResult::ERROR_ALLOC_EXHAUSTED, 0));
    }
    let l2_idx = (voff / cs) % ctx.entries_per_l2;
    let bounce = WRITE_RMW_BOUNCE as *mut u8;

    // ---- Fresh (uncached) L1/L2 decision walk ----
    // Reading straight from disk (not the read-path Qcow2State cache)
    // makes the fast-path/allocating decision reflect our own
    // write-throughs, so a revisited (already-allocated) cluster is never
    // re-allocated.
    let l1_disk = ctx.l1_table_offset + l1_idx * 8;
    let mut entry_bytes = [0u8; 8];
    if !read_input_byte_range(
        call_table,
        sector_size,
        l1_disk,
        entry_bytes.as_mut_ptr(),
        8,
        bounce,
    ) {
        return Err((BenchResult::ERROR_IO_READ, 0));
    }
    let l1_entry = u64::from_be_bytes(entry_bytes);
    let l2_table_off = l1_entry & qcow2::L1_OFFSET_MASK;

    let mut l2_entry = 0u64;
    if l2_table_off != 0 {
        let l2_disk = l2_table_off + l2_idx * 8;
        if !read_input_byte_range(
            call_table,
            sector_size,
            l2_disk,
            entry_bytes.as_mut_ptr(),
            8,
            bounce,
        ) {
            return Err((BenchResult::ERROR_IO_READ, 0));
        }
        l2_entry = u64::from_be_bytes(entry_bytes);
    }

    if l2_entry & qcow2::OFLAG_COMPRESSED != 0 {
        // A compressed data cluster cannot be overwritten in place
        // (Mission §3: entry-level detection during the run).
        return Err((BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::COMPRESSION));
    }
    let host_off = l2_entry & qcow2::L2_OFFSET_MASK;
    if l2_entry != 0 && host_off != 0 {
        // Allocated. The overwrite fast path requires OFLAG_COPIED
        // (refcount == 1). With nb_snapshots == 0 and no dirty/corrupt
        // bits every allocation is COPIED, so the miss is defensive:
        // treat a non-COPIED (snapshot-shared) cluster as gate 7 rather
        // than corrupt the shared data.
        if l2_entry & qcow2::OFLAG_COPIED == 0 {
            return Err((BenchResult::ERROR_WRITE_UNSUPPORTED, wgate::SNAPSHOTS));
        }
        if !write_pattern_range(
            call_table,
            sector_size,
            host_off + in_off as u64,
            win_len,
            bounce,
        ) {
            return Err((BenchResult::ERROR_IO_WRITE, voff));
        }
        return Ok(());
    }

    // ---- Allocating path ----
    // Invalidate device-0 caches so the COW-fill chain read observes
    // prior write-throughs (defence in depth; this cluster is genuinely
    // unallocated on disk).
    invalidate_dev0_caches(chain_states);

    let data_host = alloc_one_cluster(ctx)?;

    // COW fill: the cluster's current virtual content from device 0 down
    // the chain. This entry is unallocated, so device 0 falls through to
    // the backing chain (backing content) or yields zeros when there is
    // none — the one uniform rule that makes overlay COW correct and
    // covers the fresh-cluster zero-fill.
    HEAP_POS.store(0, Ordering::Relaxed);
    let cow = BUF_DEST as *mut u8;
    if !qcow2::read_chain_virtual_cluster(
        call_table,
        0,
        device_count,
        cluster_start,
        cow,
        cs,
        sector_size,
        chain_config,
        chain_states,
        BUF_COMPRESSED as *mut u8,
        BUF_STAGING as *mut u8,
        staging_cluster_offset,
        None,
        None,
        512,
        bytes_read,
    ) {
        return Err((BenchResult::ERROR_IO_READ, voff));
    }
    // Patch the pattern window into the COW-filled cluster, then write the
    // full data cluster.
    core::ptr::write_bytes(cow.add(in_off), pattern, win_len);
    if !write_input_byte_range(
        call_table,
        sector_size,
        data_host,
        cow as *const u8,
        cs as usize,
        bounce,
    ) {
        return Err((BenchResult::ERROR_IO_WRITE, voff));
    }

    // ---- Write-through metadata: data → L2 table → L1 → L2 entry ----
    // (Mission §2.) A crash between any two steps leaves at worst a
    // leaked cluster (refcounts are still staged / unwritten), never a
    // dangling pointer.
    if l2_table_off == 0 {
        // Allocate + zero a fresh L2 table, point L1 at it, then set the
        // data entry. L1 is written before the L2 data entry, which is
        // safe because the L2 table is written fully zeroed first.
        let l2_host = alloc_one_cluster(ctx)?;
        if !zero_cluster(call_table, sector_size, l2_host, cs, bounce) {
            return Err((BenchResult::ERROR_IO_WRITE, voff));
        }
        if !write_qcow2_entry(
            call_table,
            sector_size,
            l1_disk,
            l2_host | qcow2::OFLAG_COPIED,
            bounce,
        ) {
            return Err((BenchResult::ERROR_IO_WRITE, voff));
        }
        let l2_disk = l2_host + l2_idx * 8;
        if !write_qcow2_entry(
            call_table,
            sector_size,
            l2_disk,
            data_host | qcow2::OFLAG_COPIED,
            bounce,
        ) {
            return Err((BenchResult::ERROR_IO_WRITE, voff));
        }
    } else {
        let l2_disk = l2_table_off + l2_idx * 8;
        if !write_qcow2_entry(
            call_table,
            sector_size,
            l2_disk,
            data_host | qcow2::OFLAG_COPIED,
            bounce,
        ) {
            return Err((BenchResult::ERROR_IO_WRITE, voff));
        }
    }

    // The new L1/L2 bytes are on disk; invalidate again so the next
    // decision walk / COW read sees them.
    invalidate_dev0_caches(chain_states);
    Ok(())
}

/// Self-contained qcow2 `-w` driver: gates + refblock staging
/// (pre-bracket), then the per-request allocating loop inside its own
/// timing bracket, closing with the `BenchResult`. Returns `bytes_read`.
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
    // ---- Pre-bracket setup + envelope gates ----
    let mut ctx = match qcow2_write_setup(call_table, sector_size, &mut bytes_read) {
        Ok(c) => c,
        Err((error, detail)) => return fail(call_table, error, 0, detail, bytes_read),
    };

    // Fill the fast-path pattern sector and the L2-zeroing sector once.
    core::ptr::write_bytes(
        WRITE_PATTERN_SECTOR as *mut u8,
        params.pattern,
        MAX_SECTOR_SIZE,
    );
    core::ptr::write_bytes(WRITE_ZERO_SECTOR as *mut u8, 0, MAX_SECTOR_SIZE);

    let bufsize = params.bufsize;
    let schedule = bench::OffsetSchedule::new(params, image_size);
    let mut staging_cluster_offset: u64 = u64::MAX;

    // ---- Timing bracket opens here ----
    (call_table.send_bench_start)();

    let mut completed: u64 = 0;
    let mut flushes_issued: u64 = 0;
    for offset in schedule {
        // EOF pre-check (matches the raw path): a window past image_size
        // is refused as an I/O write error.
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
        let cs = ctx.cluster_size;
        let mut voff = offset;
        while voff < end {
            let cluster_end = (voff / cs) * cs + cs;
            let win_end = cluster_end.min(end);
            let in_off = (voff - (voff / cs) * cs) as usize;
            let win_len = (win_end - voff) as usize;
            if let Err((error, detail)) = qcow2_write_cluster(
                call_table,
                chain_config,
                chain_states,
                device_count,
                sector_size,
                &mut ctx,
                voff,
                in_off,
                win_len,
                params.pattern,
                &mut staging_cluster_offset,
                &mut bytes_read,
            ) {
                return fail(call_table, error, completed, detail, bytes_read);
            }
            voff = win_end;
        }
        completed += 1;
        bytes_read += bufsize;

        // Flush cadence (owned by crates/bench). Write back the dirty
        // staged refblocks BEFORE the fsync so a synced image never has a
        // reachable data/L2 cluster whose refcount write is still
        // pending; refcounts stay last relative to the data they cover.
        if bench::flush_after_completion(params.count, completed as u32, params.flush_interval) {
            if !flush_dirty_refblocks(call_table, sector_size, &mut ctx) {
                return fail(
                    call_table,
                    BenchResult::ERROR_IO_WRITE,
                    completed,
                    completed,
                    bytes_read,
                );
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

    // Final refblock write-back (refcounts last), inside the bracket. No
    // extra fsync: when the interval divides count the cadence already
    // fsynced at k == count, leaving no dirty refblocks here.
    if !flush_dirty_refblocks(call_table, sector_size, &mut ctx) {
        return fail(
            call_table,
            BenchResult::ERROR_IO_WRITE,
            completed,
            completed,
            bytes_read,
        );
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
