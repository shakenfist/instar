//! Shared types between core and operations.
//!
//! This crate defines the ABI between the core guest and operation binaries.
//! Both the core and operations link against this crate to share type definitions.

#![no_std]

pub mod bitmap;
pub mod format_detection;
pub mod virtio;

/// Define a bump allocator backed by a fixed address in guest memory.
///
/// This macro generates a `BumpAllocator` struct and registers it as
/// `#[global_allocator]`. Used by operations that need `alloc` support
/// (e.g., for ruzstd ZSTD decoding or miniz_oxide compression).
///
/// The heap lives at a fixed address in scratch memory (not a static
/// array) to avoid .bss bloat that can overlap with the config area
/// at 0xF0000. Guest memory is zeroed on creation, so no explicit
/// initialization is needed.
///
/// The allocator never frees; callers must reset `HEAP_POS` to 0
/// between logical operations that don't need persistent heap state.
///
/// # Example
///
/// ```ignore
/// shared::bump_allocator!();
///
/// // Reset before each decompression call:
/// HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);
/// ```
#[macro_export]
macro_rules! bump_allocator {
    () => {
        struct BumpAllocator;

        const HEAP_BASE: usize = shared::ALLOC_HEAP_BASE;
        const HEAP_SIZE: usize = shared::ALLOC_HEAP_SIZE;
        static HEAP_POS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

        unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
            unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
                let size = layout.size();
                let align = layout.align();

                let pos = HEAP_POS.load(core::sync::atomic::Ordering::Relaxed);
                let aligned = (pos + align - 1) & !(align - 1);
                let new_pos = aligned + size;

                if new_pos > HEAP_SIZE {
                    return core::ptr::null_mut();
                }

                HEAP_POS.store(new_pos, core::sync::atomic::Ordering::Relaxed);
                (HEAP_BASE + aligned) as *mut u8
            }

            unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
                // Bump allocator doesn't free individual allocations.
            }
        }

        #[global_allocator]
        static ALLOC: BumpAllocator = BumpAllocator;
    };
}

// ============================================================================
// Byte-order helpers
// ============================================================================

/// Read a big-endian u16 from a byte slice at the given offset.
#[inline]
pub fn be_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

/// Read a big-endian u32 from a byte slice at the given offset.
#[inline]
pub fn be_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read a big-endian u64 from a byte slice at the given offset.
#[inline]
pub fn be_u64(buf: &[u8], off: usize) -> u64 {
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

/// Read a little-endian u16 from a byte slice at the given offset.
#[inline]
pub fn le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Read a little-endian u32 from a byte slice at the given offset.
#[inline]
pub fn le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read a little-endian u64 from a byte slice at the given offset.
#[inline]
pub fn le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
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

/// Write a big-endian u16 to a byte slice at the given offset.
#[inline]
pub fn write_be_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_be_bytes());
}

/// Write a big-endian u32 to a byte slice at the given offset.
#[inline]
pub fn write_be_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_be_bytes());
}

/// Write a big-endian u64 to a byte slice at the given offset.
#[inline]
pub fn write_be_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_be_bytes());
}

/// Write a little-endian u16 to a byte slice at the given offset.
#[inline]
pub fn write_le_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

/// Write a little-endian u32 to a byte slice at the given offset.
#[inline]
pub fn write_le_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

/// Write a little-endian u64 to a byte slice at the given offset.
#[inline]
pub fn write_le_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

/// Generate a sector-cached read function for a given type and endianness.
///
/// All format crates (qcow2, vmdk, vhd) need to read typed values from
/// specific byte offsets within virtio-block devices. This macro generates
/// functions that cache the most recently read sector to minimize I/O when
/// reading consecutive values from the same sector.
///
/// # Parameters
///
/// - `$name`: function name to generate (e.g., `read_u32_le_cached`)
/// - `$ty`: return type (u8, u16, u32, u64)
/// - `$endian`: `be` for big-endian or `le` for little-endian
/// - `$width`: byte width (1, 2, 4, 8)
///
/// # Example
///
/// ```ignore
/// shared::cached_read!(read_u32_le_cached, u32, le, 4);
/// shared::cached_read!(read_u64_be_cached, u64, be, 8);
/// ```
///
/// The generated function has the signature:
/// ```ignore
/// pub unsafe fn $name(
///     call_table: &shared::CallTable,
///     device_idx: u32,
///     byte_offset: u64,
///     sector_size: usize,
///     input_capacity: u64,
///     cached_sector: &mut u64,
///     cache_buf: *mut u8,
///     bytes_read: &mut u64,
/// ) -> Option<$ty>
/// ```
#[macro_export]
macro_rules! cached_read {
    ($name:ident, u8, $endian:ident, 1) => {
        /// Read a single byte from a specific byte offset within a device,
        /// using a one-sector cache to minimize I/O.
        ///
        /// # Safety
        ///
        /// `cache_buf` must point to at least `sector_size` writable bytes.
        /// `call_table` must point to a valid initialized call table.
        pub unsafe fn $name(
            call_table: &shared::CallTable,
            device_idx: u32,
            byte_offset: u64,
            sector_size: usize,
            input_capacity: u64,
            cached_sector: &mut u64,
            cache_buf: *mut u8,
            bytes_read: &mut u64,
        ) -> Option<u8> {
            let sector = byte_offset / sector_size as u64;
            let off = (byte_offset % sector_size as u64) as usize;
            if off >= sector_size {
                return None;
            }
            if sector >= input_capacity {
                return None;
            }
            if *cached_sector != sector {
                if !(call_table.read_input_sector)(device_idx, sector, cache_buf, sector_size) {
                    return None;
                }
                *bytes_read += sector_size as u64;
                *cached_sector = sector;
            }
            Some(*cache_buf.add(off))
        }
    };
    ($name:ident, $ty:ty, be, $width:expr) => {
        /// Read a big-endian value from a specific byte offset within a device,
        /// using a one-sector cache to minimize I/O.
        ///
        /// # Safety
        ///
        /// `cache_buf` must point to at least `sector_size` writable bytes.
        /// `call_table` must point to a valid initialized call table.
        pub unsafe fn $name(
            call_table: &shared::CallTable,
            device_idx: u32,
            byte_offset: u64,
            sector_size: usize,
            input_capacity: u64,
            cached_sector: &mut u64,
            cache_buf: *mut u8,
            bytes_read: &mut u64,
        ) -> Option<$ty> {
            let sector = byte_offset / sector_size as u64;
            let off = (byte_offset % sector_size as u64) as usize;
            if off + $width > sector_size {
                return None;
            }
            if sector >= input_capacity {
                return None;
            }
            if *cached_sector != sector {
                if !(call_table.read_input_sector)(device_idx, sector, cache_buf, sector_size) {
                    return None;
                }
                *bytes_read += sector_size as u64;
                *cached_sector = sector;
            }
            let p = cache_buf.add(off);
            let mut bytes = [0u8; $width];
            let mut i = 0;
            while i < $width {
                bytes[i] = *p.add(i);
                i += 1;
            }
            Some(<$ty>::from_be_bytes(bytes))
        }
    };
    ($name:ident, $ty:ty, le, $width:expr) => {
        /// Read a little-endian value from a specific byte offset within a
        /// device, using a one-sector cache to minimize I/O.
        ///
        /// # Safety
        ///
        /// `cache_buf` must point to at least `sector_size` writable bytes.
        /// `call_table` must point to a valid initialized call table.
        pub unsafe fn $name(
            call_table: &shared::CallTable,
            device_idx: u32,
            byte_offset: u64,
            sector_size: usize,
            input_capacity: u64,
            cached_sector: &mut u64,
            cache_buf: *mut u8,
            bytes_read: &mut u64,
        ) -> Option<$ty> {
            let sector = byte_offset / sector_size as u64;
            let off = (byte_offset % sector_size as u64) as usize;
            if off + $width > sector_size {
                return None;
            }
            if sector >= input_capacity {
                return None;
            }
            if *cached_sector != sector {
                if !(call_table.read_input_sector)(device_idx, sector, cache_buf, sector_size) {
                    return None;
                }
                *bytes_read += sector_size as u64;
                *cached_sector = sector;
            }
            let p = cache_buf.add(off);
            let mut bytes = [0u8; $width];
            let mut i = 0;
            while i < $width {
                bytes[i] = *p.add(i);
                i += 1;
            }
            Some(<$ty>::from_le_bytes(bytes))
        }
    };
}

/// Address where the call table is located (set by core)
/// Placed just below the virtqueue region (VQ_BASE_START = 0x100000) so the
/// guest data pages sit above the operation region without touching it.
/// The core binary is loaded at 0x10000 and may extend to OPERATION_LOAD_ADDR
/// (0x30000, 128 KiB max). The operation binary is loaded at 0x30000 and may
/// extend to 0xF0000 (768 KiB max), so we place the data pages at 0xF0000:
/// call table (0xF0000), operation config (0xF1000), chain config (0xF2000),
/// VMM params (0xF3000). [0xF4000, 0x100000) is a 48 KiB guard gap below the
/// virtqueue region.
pub const CALL_TABLE_ADDR: usize = 0x000F0000;

/// Address where operation config is stored (set by VMM/core)
pub const OPERATION_CONFIG_ADDR: usize = 0x000F1000;

/// Maximum size of operation config in bytes
pub const OPERATION_CONFIG_MAX_SIZE: usize = 4096;

/// Address where chain config is stored (set by VMM)
/// This contains metadata about the backing chain for operations that need it.
pub const CHAIN_CONFIG_ADDR: usize = 0x000F2000;

/// Address where LUKS encrypt random data is stored (set by VMM).
/// Layout: master_key (64B) + mk_digest_salt (32B) + slot_salt (32B)
/// + uuid (36B) + AF random stripes (key_bytes * (stripes-1)).
///   Maximum size: 64 + 32 + 32 + 36 + 64*3999 = 256,100 bytes.
pub const LUKS_ENCRYPT_DATA_ADDR: usize = 0x01800000;

/// Address where the guest builds the LUKS v1 header output.
/// Placed at 24.25MB in guest address space, after the stack
/// (STACK_BASE = 0x01000000). The built header (592B header +
/// key material, ~260KB for AES-256-XTS) is written here, then
/// copied cluster-by-cluster to the output. Ends at ~0x01880000,
/// safely below guest memory end (GUEST_MEM_SIZE = 0x02000000).
pub const LUKS_HEADER_BUILD_ADDR: usize = 0x01840000;

/// Maximum size of chain config in bytes
pub const CHAIN_CONFIG_MAX_SIZE: usize = 1024;

/// Address where VMM parameters are stored (set by VMM before guest starts).
/// Layout: mmio_base (u64 at offset 0).
/// If mmio_base is 0, the guest uses the default (0x10000000).
pub const VMM_PARAMS_ADDR: usize = 0x000F3000;

/// Address where operation binaries are loaded.
///
/// This sits above core's region [GUEST_CODE_BASE, OPERATION_LOAD_ADDR).
/// It was raised from 0x20000 to 0x22000 because core's runtime memory
/// footprint (notably its `.bss`, which holds the `INPUT_DEVICES` /
/// `OUTPUT_DEVICE` virtio statics) overflowed the old 64 KiB core budget:
/// `OUTPUT_DEVICE` landed at 0x20380 and core's device init wrote the
/// VirtioBlock struct there, clobbering the loaded op's code at
/// 0x20380-0x203c7. The flat-binary size check missed it because the
/// flat image excludes `.bss`. Giving core 72 KiB keeps its `.bss` clear
/// of the op region; `scripts/check-binary-sizes.sh` now also validates
/// the `.bss`-inclusive ELF extent.
///
/// It was raised again from 0x22000 to 0x30000 (core budget 72 -> 128 KiB)
/// on 2026-07-06: after the bench ABI change core sat at 94% of its 72 KiB
/// budget, uncomfortably close to the op region. Rather than wait for the
/// next overflow, the core budget was lifted pre-emptively together with the
/// op region (CALL_TABLE_ADDR 0x80000 -> 0xF0000, op budget 376 -> 768 KiB).
/// Keep this in sync with the per-op `src/operations/*/linker.ld`
/// `OPERATION_BASE`.
pub const OPERATION_LOAD_ADDR: usize = 0x00030000;

/// Base address of the virtqueue memory region (consumed by vmm/main.rs and
/// core/main.rs, which previously duplicated this constant). Virtqueue memory
/// for up to 16 devices x 64 KiB occupies [VQ_BASE_START, DMA_POOL_BASE).
pub const VQ_BASE_START: usize = 0x00100000;

/// DMA pool base address (must match core/virtio.rs and vmm/main.rs).
/// Used for virtio request headers, data buffers, and status bytes.
pub const DMA_POOL_BASE: usize = 0x00200000;

// Compile-time check: operation load address must sit above core's load base.
const _: () = assert!(
    OPERATION_LOAD_ADDR > 0x10000,
    "OPERATION_LOAD_ADDR must be above the core load base (0x10000)"
);

// Compile-time check: the data pages must sit above the operation region.
const _: () = assert!(
    CALL_TABLE_ADDR > OPERATION_LOAD_ADDR,
    "CALL_TABLE_ADDR must be above OPERATION_LOAD_ADDR"
);

// Compile-time check: the data pages must end below the virtqueue region.
const _: () = assert!(
    VMM_PARAMS_ADDR + 0x1000 <= VQ_BASE_START,
    "guest data pages overlap the virtqueue region (VQ_BASE_START)"
);

// Compile-time check: virtqueue memory (16 devices x 64 KiB) must fit below
// the DMA pool.
const _: () = assert!(
    VQ_BASE_START + 16 * 0x10000 <= DMA_POOL_BASE,
    "virtqueue region overlaps the DMA pool"
);

/// DMA pool upper bound: header (16) + max sector (65536) + status (1), rounded up to 64KB.
pub const DMA_POOL_END: usize = DMA_POOL_BASE + 0x10000;

/// Stack base address (must match STACK_BASE in vmm/src/main.rs).
/// Duplicated here so compile-time asserts can validate the memory map.
pub const STACK_BASE: usize = 0x01000000; // 16 MiB

/// Scratch memory base address for operation use (after DMA pool).
/// Operations can use this region for temporary bitmaps and buffers.
pub const SCRATCH_MEM_BASE: usize = 0x00300000;

// Compile-time check: scratch memory must not overlap with the DMA pool.
const _: () = assert!(
    SCRATCH_MEM_BASE >= DMA_POOL_END,
    "SCRATCH_MEM_BASE overlaps with DMA pool"
);

/// Scratch memory end address.
/// Must stay below STACK_BASE with a guard gap so that an off-by-one or
/// small overrun cannot corrupt active stack frames.
pub const SCRATCH_MEM_END: usize = 0x00FF0000;

// Compile-time check: scratch region must end at least 64 KiB below the stack.
const _: () = assert!(
    SCRATCH_MEM_END + 0x10000 <= STACK_BASE,
    "SCRATCH_MEM_END is too close to STACK_BASE (need >= 64 KiB guard gap)"
);

/// Scratch memory size in bytes (~12.9 MiB)
pub const SCRATCH_MEM_SIZE: usize = SCRATCH_MEM_END - SCRATCH_MEM_BASE;

/// Size of the bump allocator heap (512 KiB).
/// Must be large enough for miniz_oxide CompressorOxide Box allocations
/// (~253 KiB) plus ruzstd ZSTD decoder allocations.
pub const ALLOC_HEAP_SIZE: usize = 512 * 1024;

/// Base address for the bump allocator heap in scratch memory.
/// Placed at the end of scratch memory to avoid conflicts with
/// operation-specific buffers that grow forward from SCRATCH_MEM_BASE.
pub const ALLOC_HEAP_BASE: usize = SCRATCH_MEM_END - ALLOC_HEAP_SIZE;

// Compile-time check: allocator heap must be within scratch memory.
const _: () = assert!(
    ALLOC_HEAP_BASE >= SCRATCH_MEM_BASE,
    "ALLOC_HEAP_BASE is below SCRATCH_MEM_BASE"
);

/// Base address for Argon2 working memory (above the standard 32MB layout).
/// When --max-guest-memory allocates more than 32MB, the extra memory
/// starting at this address is available for Argon2id key derivation.
pub const ARGON2_MEM_BASE: usize = 0x02000000; // 32 MiB

/// Maximum sector size supported
pub const MAX_SECTOR_SIZE: usize = 65536;

/// Guest-side scratch limit for the create operation (phase 2).
///
/// The create guest binary statically reserves this many bytes inside
/// the guest scratch region for the [`MetadataPlan`] returned by
/// [`crates/create`]'s `plan_*` functions. Most option combinations
/// fit comfortably; combinations that need more (notably qcow2 at
/// `cluster_size=512` with very large virtual sizes) are rejected
/// by the guest with `CreateResult::ERROR_SCRATCH_TOO_SMALL`.
///
/// Smaller than `crates/create::QCOW2_MAX_METADATA_SCRATCH` because
/// the guest cannot afford the theoretical worst case inside its
/// ~12 MiB scratch budget — `crates/create`'s const is the library's
/// upper bound for host-side allocations and tests, not the
/// constraint the guest enforces at runtime.
pub const GUEST_CREATE_SCRATCH_LIMIT: usize = 8 * 1024 * 1024;

/// Maximum QCOW2 cluster size supported.
/// QCOW2 allows cluster_bits 9-21 (512B to 2MB). Large clusters
/// are processed in MAX_SECTOR_SIZE-sized chunks rather than
/// buffered fully.
pub const MAX_CLUSTER_SIZE: usize = 2 * 1024 * 1024;

/// Compressed cluster read buffer size. Must hold the worst-case sector
/// reads for a compressed cluster: up to MAX_CLUSTER_SIZE of compressed
/// data, plus one extra sector because compressed data can straddle a
/// sector boundary.
pub const COMPRESSED_BUF_SIZE: usize = MAX_CLUSTER_SIZE + MAX_SECTOR_SIZE;

/// Summary of source-side allocation as seen by a parser.
///
/// Phase 2 of `PLAN-measure.md` produces this from a parsed source
/// image; the `measure` crate consumes it as input to the per-format
/// size calculators.
///
/// # Invariants
///
/// * `allocated_bytes <= virtual_size`. Callers that compute
///   `allocated_bytes` as `count * block_size` (or similar) must
///   cap the product — otherwise the per-format calculators
///   surface `MeasureError::InvalidSize` and the user sees
///   "measure: source image is unsupported format". See
///   `PLAN-fuzzing-bugs.md` phases 2 and 4.
/// * `target_units_with_data <=
///   virtual_size.div_ceil(target_unit_size)` when
///   `target_unit_size != 0`. The scanner is responsible for
///   honouring this bound; the struct does not know the target
///   unit size at construction time.
///
/// Prefer [`AllocationSummary::clamp`] over the struct literal
/// when computing from a count × size product; it enforces the
/// first invariant for you.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocationSummary {
    /// Total addressable size of the source image in bytes.
    pub virtual_size: u64,
    /// Bytes that the source has marked as allocated (whether or not they
    /// contain non-zero data). For raw input this equals `virtual_size`.
    /// For sparse inputs it may be less. Must not exceed `virtual_size`
    /// — use [`AllocationSummary::clamp`] when computing from a count ×
    /// block-size product to enforce that invariant.
    pub allocated_bytes: u64,
    /// Count of target-aligned regions that contain at least one byte of
    /// allocated source data, computed against a `target_unit_size`
    /// supplied at scan time.
    ///
    /// Required to correctly size the data area of formats whose target
    /// unit (qcow2 cluster, vhd/vhdx block, vmdk grain) is larger than
    /// the source unit: a fragmented source with N allocated source
    /// clusters spread across the address space needs the count of
    /// *target* units that touch those clusters, not
    /// `ceil(allocated_bytes / target_unit_size)`. See bug #286.
    ///
    /// `0` is a sentinel meaning "scanner did not compute this"; the
    /// measure calculators fall back to `ceil(allocated_bytes /
    /// target_unit)`. New scanners should always populate it.
    pub target_units_with_data: u64,
}

impl AllocationSummary {
    /// Build an `AllocationSummary` whose `allocated_bytes` is
    /// clamped to `virtual_size`.
    ///
    /// Scanners that compute `allocated_bytes` as `count *
    /// block_size` (or similar) routinely overshoot `virtual_size`
    /// when the block/grain size exceeds the image's virtual size —
    /// a single allocated 2 MiB VHD block in a 1 MiB image already
    /// blows the invariant. Use this constructor at the scanner's
    /// return site so the invariant is enforced once, rather than
    /// relying on each call site to remember `.min(virtual_size)`.
    ///
    /// `target_units_with_data` is not clamped here: the struct
    /// cannot know the relevant `target_unit_size`. Scanners that
    /// populate it must respect the second invariant themselves
    /// (see the struct-level docs).
    pub fn clamp(virtual_size: u64, allocated_bytes: u64, target_units_with_data: u64) -> Self {
        Self {
            virtual_size,
            allocated_bytes: allocated_bytes.min(virtual_size),
            target_units_with_data,
        }
    }
}

/// Allocation state of a virtual-address range in a source image,
/// emitted by the per-format `map_extents` walkers.
///
/// Mirrors the qemu-img map output classification minus the
/// backing-chain `depth` / `filename` fields, which the host
/// emits and the parser does not know. Single-image v1 only;
/// chain composition is deferred (see PLAN-map.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapExtentState {
    /// Region holds data and is backed by the source file at
    /// `file_offset`. Compressed qcow2 clusters count as Data;
    /// `file_offset` is the start of the (possibly compressed)
    /// on-disk bytes.
    Data { file_offset: u64 },
    /// Region reads as zero and is explicitly recorded as zero
    /// in the metadata (qcow2 ZERO_PLAIN / ZERO_ALLOC, vmdk
    /// grain marker `0xFFFFFFFE`, vhdx PAYLOAD_BLOCK_ZERO).
    ZeroAllocated,
    /// Region is unallocated — reads as zero but is not present
    /// in the source file (the qemu-img `present=false` case).
    Hole,
}

/// One contiguous extent of the source's virtual address space
/// with a single allocation state.
///
/// `length` is never zero — zero-length extents are dropped at
/// the coalescer. `start + length` must not overflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapExtent {
    /// Virtual offset of the extent's first byte, in bytes from
    /// the start of the source image.
    pub start: u64,
    /// Extent length in bytes.
    pub length: u64,
    /// Allocation state.
    pub state: MapExtentState,
}

/// Sink that swallows per-cluster `MapExtent`s and forwards
/// coalesced runs to an underlying emitter.
///
/// Usage: parser builds one wrapping the user's
/// `&mut FnMut(MapExtent) -> bool`, calls `push(extent)` for
/// each cluster/grain/block, and calls `finish()` at the end
/// to flush any trailing pending extent.
///
/// Both `push` and `finish` return `false` if the underlying
/// emitter returned `false` — the caller must stop walking
/// when it sees that.
///
/// Two adjacent extents merge when:
/// - Their virtual ranges are contiguous (`a.start + a.length
///   == b.start`).
/// - Their states match. For `Data` that requires the file
///   offsets to be contiguous too:
///   `a.state.file_offset + a.length == b.state.file_offset`.
///   For `ZeroAllocated` and `Hole`, state equality is enough.
///
/// Zero-length pushes are silently dropped (no merge, no
/// emit). Pushes whose virtual range would overflow are
/// silently dropped — the walker is responsible for clamping
/// inputs to valid ranges.
pub struct MapExtentCoalescer<'a, F: FnMut(MapExtent) -> bool> {
    pending: Option<MapExtent>,
    emit: &'a mut F,
    aborted: bool,
}

impl<'a, F: FnMut(MapExtent) -> bool> MapExtentCoalescer<'a, F> {
    pub fn new(emit: &'a mut F) -> Self {
        Self {
            pending: None,
            emit,
            aborted: false,
        }
    }

    /// Push one extent. Returns `false` if the underlying
    /// emitter has signalled abort (either on this push or any
    /// previous push). The caller must stop walking.
    pub fn push(&mut self, ext: MapExtent) -> bool {
        if self.aborted {
            return false;
        }
        if ext.length == 0 {
            return true;
        }
        if ext.start.checked_add(ext.length).is_none() {
            return true;
        }

        match self.pending {
            None => {
                self.pending = Some(ext);
                true
            }
            Some(prev) => {
                if extents_mergeable(&prev, &ext) {
                    self.pending = Some(MapExtent {
                        start: prev.start,
                        length: prev.length + ext.length,
                        state: prev.state,
                    });
                    true
                } else {
                    let cont = (self.emit)(prev);
                    if !cont {
                        self.aborted = true;
                        self.pending = None;
                        return false;
                    }
                    self.pending = Some(ext);
                    true
                }
            }
        }
    }

    /// Flush any pending extent. Returns `false` if the
    /// emitter signalled abort during the flush (or earlier).
    pub fn finish(self) -> bool {
        if self.aborted {
            return false;
        }
        if let Some(prev) = self.pending {
            return (self.emit)(prev);
        }
        true
    }
}

fn extents_mergeable(a: &MapExtent, b: &MapExtent) -> bool {
    let Some(a_end) = a.start.checked_add(a.length) else {
        return false;
    };
    if a_end != b.start {
        return false;
    }
    match (a.state, b.state) {
        (MapExtentState::Hole, MapExtentState::Hole) => true,
        (MapExtentState::ZeroAllocated, MapExtentState::ZeroAllocated) => true,
        (
            MapExtentState::Data { file_offset: a_off },
            MapExtentState::Data { file_offset: b_off },
        ) => a_off.checked_add(a.length) == Some(b_off),
        _ => false,
    }
}

/// Result from get_operation_config (FFI-safe alternative to tuple)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConfigResult {
    /// Pointer to the configuration data
    pub ptr: *const u8,
    /// Length of the configuration data in bytes
    pub len: usize,
}

/// Call table provided by core for operations to use.
///
/// The core writes this structure to CALL_TABLE_ADDR before jumping
/// to the operation. Operations read function pointers from here
/// to call back into the core for I/O and messaging.
#[repr(C)]
pub struct CallTable {
    /// Magic number to verify call table is initialized (0x494D4147 = "IMAG")
    pub magic: u32,

    /// Version of the call table ABI
    pub version: u32,

    // =========================================================================
    // Input device functions (device-indexed for backing chain support)
    // Device 0 is always the primary/top image.
    // For chain operations, devices 1..N-1 are backing files in order.
    // =========================================================================
    /// Get the number of input devices available.
    /// For single-image operations this returns 1.
    /// For chain operations this returns the number of images in the chain.
    pub get_input_device_count: unsafe extern "C" fn() -> u32,

    /// Read a sector from a specific input device.
    /// Args: device index (0 = top/primary), sector number, buffer pointer, buffer length
    /// Returns: true on success, false if device index invalid or I/O error
    pub read_input_sector: unsafe extern "C" fn(u32, u64, *mut u8, usize) -> bool,

    /// Get capacity in sectors for a specific input device.
    /// Args: device index (0 = top/primary)
    /// Returns: capacity in sectors, or 0 if device index invalid
    pub get_input_capacity: unsafe extern "C" fn(u32) -> u64,

    /// Get sector size in bytes for a specific input device.
    /// Args: device index (0 = top/primary)
    /// Returns: sector size in bytes, or 0 if device index invalid
    pub get_input_sector_size: unsafe extern "C" fn(u32) -> usize,

    // =========================================================================
    // Output device functions (single device)
    // =========================================================================
    /// Write a sector to the output device.
    /// Args: sector number, buffer pointer, buffer length
    /// Returns: true on success
    pub write_output_sector: unsafe extern "C" fn(u64, *const u8, usize) -> bool,

    /// Get output device capacity in sectors.
    pub get_output_capacity: unsafe extern "C" fn() -> u64,

    /// Get output sector size in bytes.
    pub get_output_sector_size: unsafe extern "C" fn() -> usize,

    /// Get progress reporting interval (0=every 10, 1-99=percent, 100=none).
    pub get_progress_interval: unsafe extern "C" fn() -> u32,

    /// Send progress update.
    /// Args: operation name (null-terminated), current, total, percent
    pub send_progress: unsafe extern "C" fn(*const u8, u64, u64, u32),

    /// Send error message.
    /// Args: operation (null-terminated), device (null-terminated), sector, status
    pub send_error: unsafe extern "C" fn(*const u8, *const u8, u64, u32),

    /// Send completion message.
    /// Args: operation name (null-terminated), bytes processed, success
    pub send_complete: unsafe extern "C" fn(*const u8, u64, bool),

    /// Debug print (null-terminated string). Always prints.
    pub debug_print: unsafe extern "C" fn(*const u8),

    /// Verbose print (null-terminated string). Only prints if verbose mode is enabled.
    /// Use this for diagnostic messages that should only appear with --verbose.
    pub verbose_print: unsafe extern "C" fn(*const u8),

    /// Get operation-specific configuration.
    /// Returns: ConfigResult with pointer and length.
    /// The config format is operation-specific.
    pub get_operation_config: unsafe extern "C" fn() -> ConfigResult,

    /// Get chain configuration (metadata about backing chain devices).
    /// Returns: ConfigResult with pointer and length.
    /// The config is a ChainConfig structure at CHAIN_CONFIG_ADDR.
    /// Returns len=0 if no chain config is available.
    pub get_chain_config: unsafe extern "C" fn() -> ConfigResult,

    /// Send info result message.
    /// Args: format (null-terminated), version, virtual_size, actual_size,
    ///       cluster_size, flags, backing_file (null-terminated),
    ///       external_data_file (null-terminated)
    pub send_info_result: unsafe extern "C" fn(
        *const u8, // format
        u32,       // version
        u64,       // virtual_size
        u64,       // actual_size
        u32,       // cluster_size
        u32,       // flags
        *const u8, // backing_file
        *const u8, // external_data_file
    ),

    /// Send info result message with QCOW2-specific information.
    /// Args: format (null-terminated), version, virtual_size, actual_size,
    ///       cluster_size, flags, backing_file (null-terminated),
    ///       external_data_file (null-terminated), qcow2_info pointer
    pub send_info_result_qcow2: unsafe extern "C" fn(
        *const u8,        // format
        u32,              // version
        u64,              // virtual_size
        u64,              // actual_size
        u32,              // cluster_size
        u32,              // flags
        *const u8,        // backing_file
        *const u8,        // external_data_file
        *const Qcow2Info, // qcow2_info
    ),

    /// Send info result message with VMDK-specific information.
    /// Args: format (null-terminated), version, virtual_size, actual_size,
    ///       cluster_size, flags, backing_file (null-terminated),
    ///       external_data_file (null-terminated), vmdk_info pointer
    pub send_info_result_vmdk: unsafe extern "C" fn(
        *const u8,       // format
        u32,             // version
        u64,             // virtual_size
        u64,             // actual_size
        u32,             // cluster_size
        u32,             // flags
        *const u8,       // backing_file
        *const u8,       // external_data_file
        *const VmdkInfo, // vmdk_info
    ),

    /// Send info result message with VDI-specific information.
    /// Args: format (null-terminated), version, virtual_size, actual_size,
    ///       cluster_size, flags, backing_file (null-terminated),
    ///       external_data_file (null-terminated), vdi_info pointer
    pub send_info_result_vdi: unsafe extern "C" fn(
        *const u8,      // format
        u32,            // version
        u64,            // virtual_size
        u64,            // actual_size
        u32,            // cluster_size
        u32,            // flags
        *const u8,      // backing_file
        *const u8,      // external_data_file
        *const VdiInfo, // vdi_info
    ),

    /// Send info result message with LUKS-specific information.
    /// Args: format (null-terminated), version, virtual_size, actual_size,
    ///       cluster_size, flags, backing_file (null-terminated),
    ///       external_data_file (null-terminated), luks_info pointer
    pub send_info_result_luks: unsafe extern "C" fn(
        *const u8,       // format
        u32,             // version
        u64,             // virtual_size
        u64,             // actual_size
        u32,             // cluster_size
        u32,             // flags
        *const u8,       // backing_file
        *const u8,       // external_data_file
        *const LuksInfo, // luks_info
    ),

    /// Send check result message.
    /// Args: check_result pointer containing all check results
    pub send_check_result: unsafe extern "C" fn(*const CheckResult),

    /// Send compare result message.
    /// Args: compare_result pointer containing comparison results
    pub send_compare_result: unsafe extern "C" fn(*const CompareResult),

    /// Send measure result message.
    /// Args: measure_result pointer containing required +
    /// fully_allocated bytes for the target format.
    pub send_measure_result: unsafe extern "C" fn(*const MeasureResult),

    /// Send create result message.
    /// Args: create_result pointer containing the resolved virtual
    /// size, bytes written, file size after, and resolved unit size
    /// for the target format. Appended at the end of CallTable so
    /// existing operation binaries do not need to recompile against
    /// shifted offsets to keep working.
    pub send_create_result: unsafe extern "C" fn(*const CreateResult),

    /// Read a sector from the *output* device. Resize is the
    /// first operation that reads from the file it writes to;
    /// rebase and commit will reuse this. Args:
    /// `(sector_number, buf_ptr, buf_len)`; returns `true` on
    /// success. Appended at the end of `CallTable` so existing
    /// operation binaries do not need to recompile against
    /// shifted offsets to keep working.
    pub read_output_sector: unsafe extern "C" fn(u64, *mut u8, usize) -> bool,

    /// Send the resize result message. Args: `resize_result`
    /// pointer containing the resolved new virtual size, the
    /// pre/post file sizes, the action (noop/grow/shrink), and
    /// the error code. Appended at the end of `CallTable` for
    /// the same back-compat reason as `send_create_result`.
    pub send_resize_result: unsafe extern "C" fn(*const ResizeResult),

    /// Send the rebase result message. Args: `rebase_result`
    /// pointer containing the mode (safe/unsafe), bytes/clusters
    /// copied (safe mode only), and the error code. Appended at
    /// the end of `CallTable` for the same back-compat reason as
    /// `send_resize_result`.
    pub send_rebase_result: unsafe extern "C" fn(*const RebaseResult),

    /// Send the commit result message. Args: `commit_result`
    /// pointer containing the clusters/bytes committed into the
    /// backing, the number of overlay L2 entries cleared, and
    /// the error code. Appended at the end of `CallTable` for
    /// the same back-compat reason as `send_rebase_result`.
    pub send_commit_result: unsafe extern "C" fn(*const CommitResult),

    /// Write a sector to an *input* device. Commit is the first
    /// operation to need writes against a device it also reads
    /// as an input: the overlay being committed is attached as
    /// input slot 0 (opened RW host-side) and the guest uses
    /// this primitive to clear the overlay's L2 / refcount
    /// tables after merging cluster data into the backing.
    /// Args: `(device_index, sector_number, buf_ptr, buf_len)`;
    /// returns `true` on success. The host-side stub returns
    /// `false` if `device_index` was not opened RW (see
    /// `open_chain_devices_rw` in the VMM). Appended at the end
    /// of `CallTable` for the same back-compat reason as
    /// `read_output_sector`.
    pub write_input_sector: unsafe extern "C" fn(u32, u64, *const u8, usize) -> bool,

    /// Send one coalesced map extent. Called once per extent
    /// emitted by the guest's per-format `map_extents` walker
    /// during the map operation. Args: `*const MapExtentRecord`
    /// carrying the extent's virtual start, length, state code,
    /// and (for `STATE_DATA` extents) the source file offset.
    /// Appended at the end of `CallTable` for the same
    /// back-compat reason as `write_input_sector`.
    pub send_map_extent: unsafe extern "C" fn(*const MapExtentRecord),

    /// Send the map operation's terminator summary. Called once
    /// per invocation, after the last `send_map_extent`. Args:
    /// `*const MapResult` carrying the extent count, virtual
    /// size, source format echo, and error code. Appended at the
    /// end of `CallTable` for the same back-compat reason as
    /// `send_map_extent`.
    pub send_map_result: unsafe extern "C" fn(*const MapResult),

    /// Send one snapshot record during `MODE_LIST`. Called once
    /// per snapshot, before the terminating
    /// `send_snapshot_result`. Args: `*const SnapshotEntryRecord`
    /// carrying the full v3 snapshot metadata (id, name,
    /// vm_state_size_large, disk_size, icount, date, vm_clock,
    /// l1 location). Appended at the end of `CallTable` for the
    /// same back-compat reason as `send_map_result`.
    pub send_snapshot_entry: unsafe extern "C" fn(*const SnapshotEntryRecord),

    /// Send the snapshot operation's terminator summary. Called
    /// once per invocation, after the last `send_snapshot_entry`
    /// (or as the only call for `MODE_APPLY` / `_CREATE` /
    /// `_DELETE`). Args: `*const SnapshotResult` carrying the
    /// mode echo, error code, emitted count (for list), and
    /// assigned id (for create). Appended at the end of
    /// `CallTable` for the same back-compat reason as
    /// `send_snapshot_entry`.
    pub send_snapshot_result: unsafe extern "C" fn(*const SnapshotResult),

    /// Request that the host fdatasync the named input device's
    /// backing file. Args: `device_index` (must refer to a slot
    /// opened RW via `open_chain_devices_rw`; the host stub
    /// returns `false` for read-only or invalid slots). Returns
    /// `true` on success.
    ///
    /// Mutating snapshot modes use this between the data-write
    /// pass and the header-pointer flip to enforce qemu's
    /// "old table still valid until header updated" durability
    /// contract. Appended at the end of `CallTable` for the
    /// same back-compat reason as `send_snapshot_result`.
    pub fsync_input: unsafe extern "C" fn(u32) -> bool,

    /// Send the amend result message. Args: `amend_result`
    /// pointer carrying the action (noop/amended), the resulting
    /// qcow2 version and lazy-refcounts state, and the error
    /// code. Appended at the end of `CallTable` for the same
    /// back-compat reason as `send_rebase_result`.
    pub send_amend_result: unsafe extern "C" fn(*const AmendResult),

    /// Send the bitmap result message. Args: `bitmap_result`
    /// pointer carrying the last applied action opcode, the number
    /// of actions applied, the resulting bitmap count, and the
    /// error code. Appended at the end of `CallTable` for the same
    /// back-compat reason as `send_amend_result`.
    pub send_bitmap_result: unsafe extern "C" fn(*const BitmapResult),

    /// Send the bench timing-bracket start marker. No arguments —
    /// the marker's *arrival time* is its entire payload. Appended
    /// at the end of `CallTable` for the same back-compat reason as
    /// `send_bitmap_result`.
    ///
    /// # Timing contract (the ABI-level meaning of this message)
    ///
    /// The guest emits this exactly once, after config validation,
    /// the format probe/open, cached-state setup, and buffer /
    /// transfer-plan setup — **immediately before submitting the
    /// first request**, mirroring qemu's `gettimeofday` bracket
    /// placement. Everything set up before the marker (parsing,
    /// allocation) is deliberately outside the measured window.
    ///
    /// The host records `Instant::now()` on receipt of this marker;
    /// elapsed is measured from here to receipt of the terminal
    /// [`send_bench_result`](Self::send_bench_result). The trailing
    /// flush (when `flush_interval` divides such that the final
    /// completion flushes) is **inside** the bracket, per phase 1's
    /// verified cadence.
    ///
    /// [`BenchResult`] **may arrive without a preceding
    /// `BenchStart`**: a validation/probe/parse failure before the
    /// timed loop emits only the result. The host must render that
    /// error without a timing line and must never assume the bracket
    /// opened.
    ///
    /// The marker's own cost (a few serial-port `IoOut` vmexits,
    /// ~µs) is noise at bench's ms-to-s scale — recorded here so
    /// nobody "optimizes" it away.
    pub send_bench_start: unsafe extern "C" fn(),

    /// Send the bench result message. Args: `bench_result` pointer
    /// carrying the number of requests completed, the number of
    /// flushes issued, an error-detail offset, and the error code.
    /// The terminal message of the bench operation; closes the
    /// timing bracket opened by
    /// [`send_bench_start`](Self::send_bench_start). Appended at the
    /// end of `CallTable` for the same back-compat reason as
    /// `send_bench_start`.
    pub send_bench_result: unsafe extern "C" fn(*const BenchResult),
}

/// Backing format type for QCOW2 header extension
#[repr(u8)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum BackingFormat {
    /// No backing format specified
    #[default]
    None = 0,
    /// QCOW2 format
    Qcow2 = 1,
    /// Raw format
    Raw = 2,
    /// VMDK format
    Vmdk = 3,
    /// QCOW format (version 1)
    Qcow = 4,
    /// VHD/VPC format
    Vpc = 5,
    /// VHDX format
    Vhdx = 6,
    /// Unknown format (not in our list)
    Unknown = 255,
}

impl BackingFormat {
    /// Get backing format as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            BackingFormat::None => "",
            BackingFormat::Qcow2 => "qcow2",
            BackingFormat::Raw => "raw",
            BackingFormat::Vmdk => "vmdk",
            BackingFormat::Qcow => "qcow",
            BackingFormat::Vpc => "vpc",
            BackingFormat::Vhdx => "vhdx",
            BackingFormat::Unknown => "unknown",
        }
    }

    /// Parse a format string (case-insensitive first 5 chars)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        // Quick check for common formats
        if bytes.is_empty() {
            return BackingFormat::None;
        }

        // Compare lowercase
        let len = bytes.len().min(5);
        let mut lower = [0u8; 5];
        for (i, &b) in bytes[..len].iter().enumerate() {
            lower[i] = if b.is_ascii_uppercase() { b + 32 } else { b };
        }

        if bytes.len() >= 5 && &lower[..5] == b"qcow2" {
            BackingFormat::Qcow2
        } else if bytes.len() >= 4 && &lower[..4] == b"qcow" {
            BackingFormat::Qcow
        } else if bytes.len() >= 3 && &lower[..3] == b"raw" {
            BackingFormat::Raw
        } else if bytes.len() >= 4 && &lower[..4] == b"vmdk" {
            BackingFormat::Vmdk
        } else if bytes.len() >= 3 && &lower[..3] == b"vpc" {
            BackingFormat::Vpc
        } else if bytes.len() >= 4 && &lower[..4] == b"vhdx" {
            BackingFormat::Vhdx
        } else {
            BackingFormat::Unknown
        }
    }
}

/// QCOW2 format-specific information (FFI-safe).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Qcow2Info {
    /// Compatibility version: 0 = "0.10", 1 = "1.1"
    pub compat: u8,
    /// Compression type: 0 = zlib, 1 = zstd
    pub compression_type: u8,
    /// Whether lazy refcounts are enabled
    pub lazy_refcounts: bool,
    /// Whether the image is marked dirty (not cleanly closed)
    pub dirty: bool,
    /// Whether the image is marked corrupt
    pub corrupt: bool,
    /// Whether extended L2 entries are used
    pub extended_l2: bool,
    /// Backing file format (from header extension)
    pub backing_format: BackingFormat,
    /// Padding for alignment
    pub _pad: [u8; 1],
    /// Number of refcount bits (typically 16)
    pub refcount_bits: u32,
    /// Number of snapshots in the snapshot table
    pub nb_snapshots: u32,
}

impl Qcow2Info {
    /// Create new QCOW2 info with defaults
    pub const fn new() -> Self {
        Self {
            compat: 0,
            compression_type: 0,
            lazy_refcounts: false,
            dirty: false,
            corrupt: false,
            extended_l2: false,
            backing_format: BackingFormat::None,
            _pad: [0; 1],
            refcount_bits: 16,
            nb_snapshots: 0,
        }
    }

    /// Get compat string for this info
    pub fn compat_str(&self) -> &'static str {
        match self.compat {
            0 => "0.10",
            1 => "1.1",
            _ => "unknown",
        }
    }

    /// Get compression type string for this info
    pub fn compression_type_str(&self) -> &'static str {
        match self.compression_type {
            0 => "zlib",
            1 => "zstd",
            _ => "unknown",
        }
    }

    /// Get backing format as a string
    pub fn backing_format_str(&self) -> &'static str {
        self.backing_format.as_str()
    }
}

/// VMDK format-specific information (FFI-safe).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VmdkInfo {
    /// Content ID (CID) - unique identifier for this disk
    pub cid: u32,
    /// Parent Content ID (parentCID) - 0xFFFFFFFF if no parent
    pub parent_cid: u32,
    /// Create type length (bytes used in create_type array)
    pub create_type_len: u8,
    /// Padding for alignment
    pub _pad: [u8; 3],
    /// Create type string (null-terminated, max 31 chars + null)
    pub create_type: [u8; 32],
}

impl VmdkInfo {
    /// Create new VMDK info with defaults
    pub const fn new() -> Self {
        Self {
            cid: 0,
            parent_cid: 0xFFFFFFFF,
            create_type_len: 0,
            _pad: [0; 3],
            create_type: [0; 32],
        }
    }

    /// Set the create type string
    pub fn set_create_type(&mut self, s: &[u8]) {
        let len = s.len().min(31);
        self.create_type[..len].copy_from_slice(&s[..len]);
        self.create_type[len] = 0;
        self.create_type_len = len as u8;
    }

    /// Get create type as a str slice (for display)
    pub fn create_type_str(&self) -> &str {
        let len = self.create_type_len as usize;
        // Safety: we control the contents and ensure it's valid UTF-8 ASCII
        core::str::from_utf8(&self.create_type[..len]).unwrap_or("")
    }
}

/// VDI format-specific information (FFI-safe).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VdiInfo {
    /// Image type: 1 = dynamic, 2 = fixed (normal)
    pub image_type: u32,
    /// Block size in bytes (typically 1 MiB)
    pub block_size: u32,
    /// Total number of blocks in the image
    pub blocks_in_image: u32,
    /// Number of blocks currently allocated
    pub blocks_allocated: u32,
    /// UUID of the image (16 bytes)
    pub uuid: [u8; 16],
}

impl VdiInfo {
    /// Create new VDI info with defaults
    pub const fn new() -> Self {
        Self {
            image_type: 0,
            block_size: 0,
            blocks_in_image: 0,
            blocks_allocated: 0,
            uuid: [0; 16],
        }
    }

    /// Get image type as a string
    pub fn image_type_str(&self) -> &'static str {
        match self.image_type {
            1 => "dynamic",
            2 => "fixed",
            _ => "unknown",
        }
    }
}

/// LUKS format-specific information (FFI-safe).
///
/// Contains parsed LUKS header fields for both v1 and v2.
/// String fields are null-terminated with fixed-size buffers
/// matching the LUKS on-disk format (32 bytes for cipher/mode/hash,
/// 37 bytes for UUID).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LuksInfo {
    /// Cipher name (null-terminated, e.g., "aes")
    pub cipher: [u8; 32],
    /// Cipher mode (null-terminated, e.g., "xts-plain64")
    pub cipher_mode: [u8; 32],
    /// Hash spec (null-terminated, e.g., "sha256")
    pub hash: [u8; 32],
    /// UUID (null-terminated, 36 chars + null)
    pub uuid: [u8; 37],
    /// Padding for alignment
    pub _pad: [u8; 3],
    /// Payload offset in 512-byte sectors (LUKS v1)
    pub payload_offset: u32,
    /// Master key length in bytes
    pub master_key_length: u32,
    /// Number of active key slots
    pub active_key_slots: u32,
    /// Detected inner format name after decryption (null-terminated)
    pub inner_format: [u8; 16],
    /// Virtual size of the inner format in bytes (0 if not detected)
    pub inner_virtual_size: u64,
}

impl Default for LuksInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl LuksInfo {
    /// Create new LUKS info with defaults
    pub const fn new() -> Self {
        Self {
            cipher: [0; 32],
            cipher_mode: [0; 32],
            hash: [0; 32],
            uuid: [0; 37],
            _pad: [0; 3],
            payload_offset: 0,
            master_key_length: 0,
            active_key_slots: 0,
            inner_format: [0; 16],
            inner_virtual_size: 0,
        }
    }

    /// Get cipher name as a str slice
    pub fn cipher_str(&self) -> &str {
        cstr_to_str(&self.cipher)
    }

    /// Get cipher mode as a str slice
    pub fn cipher_mode_str(&self) -> &str {
        cstr_to_str(&self.cipher_mode)
    }

    /// Get hash spec as a str slice
    pub fn hash_str(&self) -> &str {
        cstr_to_str(&self.hash)
    }

    /// Get UUID as a str slice
    pub fn uuid_str(&self) -> &str {
        cstr_to_str(&self.uuid)
    }

    /// Get inner format name as a str slice
    pub fn inner_format_str(&self) -> &str {
        cstr_to_str(&self.inner_format)
    }

    /// Set the inner format name from a string slice
    pub fn set_inner_format(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(self.inner_format.len() - 1);
        self.inner_format[..len].copy_from_slice(&bytes[..len]);
        self.inner_format[len] = 0;
    }
}

/// Extract a null-terminated string from a byte buffer.
fn cstr_to_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).unwrap_or("")
}

impl CallTable {
    /// Magic value indicating a valid call table
    pub const MAGIC: u32 = 0x494D4147; // "IMAG"

    /// Current ABI version (bumped: PLAN-map phase 2 appended
    /// `send_map_extent` and `send_map_result` to support the
    /// streaming-emit shape map needs; PLAN-snapshot phase 1
    /// appended `send_snapshot_entry`, `send_snapshot_result`,
    /// and `fsync_input` for the snapshot subcommand and its
    /// durability checkpoints; PLAN-amend phase 1 appended
    /// `send_amend_result` for the amend subcommand;
    /// PLAN-bitmap phase 2 appended `send_bitmap_result` for the
    /// bitmap subcommand; PLAN-bench phase 2 appended
    /// `send_bench_start` and `send_bench_result` for the bench
    /// subcommand's timing bracket).
    pub const VERSION: u32 = 20;
}

// ============================================================================
// Shared utility functions for guest operations
// ============================================================================

/// Check if a byte slice contains only zeros.
pub fn is_all_zeros(buffer: &[u8], len: usize) -> bool {
    for &byte in &buffer[..len] {
        if byte != 0 {
            return false;
        }
    }
    true
}

/// Check if a raw pointer buffer contains only zeros.
///
/// # Safety
///
/// `buf` must point to at least `len` readable bytes.
pub unsafe fn is_all_zeros_ptr(buf: *const u8, len: usize) -> bool {
    for i in 0..len {
        if *buf.add(i) != 0 {
            return false;
        }
    }
    true
}

/// Determine if progress should be reported based on interval
/// settings and current progress.
///
/// - `interval = 0`: report every 10 counts (legacy mode)
/// - `interval = 100`: never report
/// - `interval = N`: report every N percent
pub fn should_report_progress(interval: u32, percent: u32, last_percent: u32, count: u64) -> bool {
    match interval {
        0 => count % 10 == 9,
        100 => false,
        n => percent >= last_percent + n && percent > last_percent,
    }
}

/// Get the L1 cache buffer address for a given device index.
///
/// Each device gets 2 × MAX_SECTOR_SIZE of cache space (L1 + L2),
/// starting at `dynamic_bufs_start`.
pub fn l1_cache_addr(dynamic_bufs_start: usize, dev_idx: usize) -> *mut u8 {
    (dynamic_bufs_start + dev_idx * 2 * MAX_SECTOR_SIZE) as *mut u8
}

/// Get the L2 cache buffer address for a given device index.
pub fn l2_cache_addr(dynamic_bufs_start: usize, dev_idx: usize) -> *mut u8 {
    (dynamic_bufs_start + (dev_idx * 2 + 1) * MAX_SECTOR_SIZE) as *mut u8
}

// ============================================================================
// Operation-specific configuration structures
// ============================================================================

/// Configuration for the copy operation.
///
/// This structure is written to OPERATION_CONFIG_ADDR by the VMM.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CopyConfig {
    /// Magic number to verify config is valid (0x434F5059 = "COPY")
    pub magic: u32,

    /// Configuration flags
    pub flags: u32,

    /// Starting sector (0 = from beginning)
    pub start_sector: u64,

    /// Number of sectors to copy (0 = all remaining)
    pub sector_count: u64,
}

impl CopyConfig {
    /// Magic value for copy config
    pub const MAGIC: u32 = 0x434F5059; // "COPY"

    /// Flag: Verify data after copy (read back and compare)
    pub const FLAG_VERIFY: u32 = 1 << 0;

    /// Flag: Skip zero sectors (don't write all-zero sectors to output)
    pub const FLAG_SKIP_ZEROS: u32 = 1 << 1;

    /// Create a default config (copy everything, no special flags)
    pub const fn default_config() -> Self {
        Self {
            magic: Self::MAGIC,
            flags: 0,
            start_sector: 0,
            sector_count: 0, // 0 means all
        }
    }

    /// Check if config is valid
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Check if verify flag is set
    pub fn should_verify(&self) -> bool {
        (self.flags & Self::FLAG_VERIFY) != 0
    }

    /// Check if skip zeros flag is set
    pub fn should_skip_zeros(&self) -> bool {
        (self.flags & Self::FLAG_SKIP_ZEROS) != 0
    }
}

// ============================================================================
// Info operation configuration and results
// ============================================================================

/// Detected image format types.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageFormat {
    /// Format could not be determined
    Unknown = 0,
    /// Raw disk image (no header, identified as fallback)
    Raw = 1,
    /// QCOW2 format (magic: 0x514649fb)
    Qcow2 = 2,
    /// VMDK version 4 (magic: 0x564d444b "VMDK")
    Vmdk4 = 3,
    /// VMDK version 3 (magic: 0x434f5744 "COWD")
    Vmdk3 = 4,
    /// VHD/VPC format (magic at end of file)
    Vhd = 5,
    /// VHDX format (magic: 0x76686478 "vhdx")
    Vhdx = 6,
    /// QCOW version 1 (magic: 0x514649)
    Qcow1 = 7,
    /// VDI format (VirtualBox, magic: 0xbeda107f at offset 64)
    Vdi = 8,
    /// QED format (deprecated QEMU format, magic: 0x00444551 "QED\0")
    Qed = 9,
    /// ISO 9660 format (CD/DVD image, magic: "CD001" at offset 0x8001)
    Iso = 10,
    /// LUKS format (Linux encrypted container, magic: "LUKS\xba\xbe" at offset 0)
    Luks = 11,
    /// VMDK monolithicFlat descriptor file (text, starts with
    /// "# Disk DescriptorFile"). The descriptor itself holds no
    /// content; content lives in a separate flat extent file
    /// pointed to from the descriptor's extent line.
    VmdkDescriptor = 12,
}

impl ImageFormat {
    /// Convert from u32 (for FFI)
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => ImageFormat::Raw,
            2 => ImageFormat::Qcow2,
            3 => ImageFormat::Vmdk4,
            4 => ImageFormat::Vmdk3,
            5 => ImageFormat::Vhd,
            6 => ImageFormat::Vhdx,
            7 => ImageFormat::Qcow1,
            8 => ImageFormat::Vdi,
            9 => ImageFormat::Qed,
            10 => ImageFormat::Iso,
            11 => ImageFormat::Luks,
            12 => ImageFormat::VmdkDescriptor,
            _ => ImageFormat::Unknown,
        }
    }

    /// Get human-readable format name
    pub fn name(&self) -> &'static str {
        match self {
            ImageFormat::Unknown => "unknown",
            ImageFormat::Raw => "raw",
            ImageFormat::Qcow2 => "qcow2",
            ImageFormat::Vmdk4 => "vmdk",
            ImageFormat::Vmdk3 => "vmdk3",
            ImageFormat::Vhd => "vhd",
            ImageFormat::Vhdx => "vhdx",
            ImageFormat::Qcow1 => "qcow1",
            ImageFormat::Vdi => "vdi",
            ImageFormat::Qed => "qed",
            ImageFormat::Iso => "iso",
            ImageFormat::Luks => "luks",
            // Reports as "vmdk" to match qemu-img info output for
            // monolithicFlat — the user sees the container format,
            // not the descriptor/flat split.
            ImageFormat::VmdkDescriptor => "vmdk",
        }
    }
}

/// Configuration for the info operation.
///
/// This structure is written to OPERATION_CONFIG_ADDR by the VMM.
/// Maximum passphrase length for LUKS decryption.
pub const INFO_CONFIG_MAX_PASSPHRASE: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InfoConfig {
    /// Magic number to verify config is valid (0x494E464F = "INFO")
    pub magic: u32,

    /// Configuration flags
    pub flags: u32,

    /// LUKS passphrase length (0 = no passphrase provided)
    pub passphrase_len: u32,

    /// Padding for alignment
    pub _pad: u32,

    /// LUKS passphrase (null-padded, max 256 bytes)
    pub passphrase: [u8; INFO_CONFIG_MAX_PASSPHRASE],

    /// Size of Argon2 working memory in bytes (0 = not available).
    /// When non-zero, memory at ARGON2_MEM_BASE is available for
    /// Argon2id key derivation (LUKS v2 decryption).
    pub argon2_mem_size: u64,
}

impl InfoConfig {
    /// Magic value for info config
    pub const MAGIC: u32 = 0x494E464F; // "INFO"

    /// Flag: Report detailed metadata (backing files, encryption, etc.)
    pub const FLAG_DETAILED: u32 = 1 << 0;

    /// Flag: Check for potentially dangerous metadata (backing files, etc.)
    pub const FLAG_SECURITY_CHECK: u32 = 1 << 1;

    /// Flag: Enable unsafe quirks mode (accept any file as RAW without
    /// partition table validation). This matches qemu-img behavior but
    /// introduces security vulnerabilities. Use only for compatibility testing.
    pub const FLAG_UNSAFE_QUIRKS: u32 = 1 << 2;

    /// Flag: Enable extra detail mode for detecting formats that qemu-img
    /// doesn't recognize (e.g., LUKS). When not set, such formats are reported
    /// as their qemu-img equivalent (usually "raw") for compatibility.
    pub const FLAG_EXTRA_DETAIL: u32 = 1 << 3;

    /// Create a default config
    pub const fn default_config() -> Self {
        Self {
            magic: Self::MAGIC,
            flags: Self::FLAG_DETAILED | Self::FLAG_SECURITY_CHECK,
            passphrase_len: 0,
            _pad: 0,
            passphrase: [0; INFO_CONFIG_MAX_PASSPHRASE],
            argon2_mem_size: 0,
        }
    }

    /// Check if config is valid
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Check if detailed flag is set
    pub fn should_report_detailed(&self) -> bool {
        (self.flags & Self::FLAG_DETAILED) != 0
    }

    /// Check if security check flag is set
    pub fn should_check_security(&self) -> bool {
        (self.flags & Self::FLAG_SECURITY_CHECK) != 0
    }

    /// Check if unsafe quirks mode is enabled
    ///
    /// When enabled, any file will be accepted as a valid RAW image,
    /// matching qemu-img's insecure behavior. When disabled (default),
    /// files must have a valid partition table to be accepted as RAW.
    pub fn unsafe_quirks_enabled(&self) -> bool {
        (self.flags & Self::FLAG_UNSAFE_QUIRKS) != 0
    }

    /// Check if extra detail mode is enabled
    ///
    /// When enabled, formats that qemu-img doesn't recognize (like LUKS)
    /// are detected and reported. When disabled (default), such formats
    /// are reported as their qemu-img equivalent for compatibility.
    pub fn extra_detail_enabled(&self) -> bool {
        (self.flags & Self::FLAG_EXTRA_DETAIL) != 0
    }

    /// Check if a LUKS passphrase was provided
    pub fn has_passphrase(&self) -> bool {
        self.passphrase_len > 0
    }

    /// Get the passphrase bytes (empty slice if none)
    pub fn passphrase_bytes(&self) -> &[u8] {
        let len = (self.passphrase_len as usize).min(INFO_CONFIG_MAX_PASSPHRASE);
        &self.passphrase[..len]
    }
}

/// Result structure for the info operation.
///
/// This structure is written to OPERATION_CONFIG_ADDR after detection,
/// overwriting the config. The VMM reads it back to get results.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InfoResult {
    /// Magic number to verify result is valid (0x52455355 = "RESU")
    pub magic: u32,

    /// Detected format (ImageFormat as u32)
    pub format: u32,

    /// Virtual size in bytes (from image header, if available)
    pub virtual_size: u64,

    /// Actual file size in bytes
    pub actual_size: u64,

    /// Format version (e.g., QCOW2 version 2 or 3)
    pub version: u32,

    /// Flags indicating features/warnings
    pub flags: u32,

    /// QCOW2-specific: cluster size in bytes
    pub cluster_size: u32,

    /// Reserved for future use
    pub _reserved: u32,

    /// Offset of backing file path in result buffer (0 if none)
    pub backing_file_offset: u16,

    /// Length of backing file path (0 if none)
    pub backing_file_len: u16,

    /// Offset of external data file path (0 if none)
    pub external_data_offset: u16,

    /// Length of external data file path (0 if none)
    pub external_data_len: u16,
}

impl Default for InfoResult {
    fn default() -> Self {
        Self::new()
    }
}

impl InfoResult {
    /// Magic value for info result
    pub const MAGIC: u32 = 0x52455355; // "RESU"

    /// Flag: Image has backing file reference
    pub const FLAG_HAS_BACKING_FILE: u32 = 1 << 0;

    /// Flag: Image has external data file reference
    pub const FLAG_HAS_EXTERNAL_DATA: u32 = 1 << 1;

    /// Flag: Image is encrypted
    pub const FLAG_ENCRYPTED: u32 = 1 << 2;

    /// Flag: Image is compressed
    pub const FLAG_COMPRESSED: u32 = 1 << 3;

    /// Flag: Image has snapshots
    pub const FLAG_HAS_SNAPSHOTS: u32 = 1 << 4;

    /// Flag: Dirty bit is set (unclean shutdown)
    pub const FLAG_DIRTY: u32 = 1 << 5;

    /// Flag: Corrupt bit is set
    pub const FLAG_CORRUPT: u32 = 1 << 6;

    /// Flag: RAW image has MBR partition table
    pub const FLAG_HAS_MBR: u32 = 1 << 7;

    /// Flag: RAW image has GPT partition table
    pub const FLAG_HAS_GPT: u32 = 1 << 8;

    /// Create a new empty result
    pub const fn new() -> Self {
        Self {
            magic: Self::MAGIC,
            format: ImageFormat::Unknown as u32,
            virtual_size: 0,
            actual_size: 0,
            version: 0,
            flags: 0,
            cluster_size: 0,
            _reserved: 0,
            backing_file_offset: 0,
            backing_file_len: 0,
            external_data_offset: 0,
            external_data_len: 0,
        }
    }

    /// Check if result is valid
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Get the detected format
    pub fn detected_format(&self) -> ImageFormat {
        ImageFormat::from_u32(self.format)
    }
}

// ============================================================================
// Check operation configuration and results
// ============================================================================

/// Configuration for the check operation.
///
/// This structure is written to OPERATION_CONFIG_ADDR by the VMM.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CheckConfig {
    /// Magic number to verify config is valid (0x43484543 = "CHEC")
    pub magic: u32,

    /// Configuration flags
    pub flags: u32,
}

impl CheckConfig {
    /// Magic value for check config
    pub const MAGIC: u32 = 0x43484543; // "CHEC"

    /// Flag: Attempt to repair errors (future feature)
    pub const FLAG_REPAIR: u32 = 1 << 0;

    /// Flag: Suppress output (quiet mode)
    pub const FLAG_QUIET: u32 = 1 << 1;

    /// Flag: Enable unsafe quirks mode (qemu-img compatible behavior).
    /// When enabled, non-QCOW2 formats are treated as "raw" and validation
    /// is skipped for non-QCOW2 formats (matching qemu-img check behavior).
    /// When disabled (default), instar detects the real format and performs
    /// format-appropriate validation.
    pub const FLAG_UNSAFE_QUIRKS: u32 = 1 << 2;

    /// Flag: Validate backing chain (chain mode)
    pub const FLAG_CHAIN: u32 = 1 << 3;

    /// Flag: Select the lossy `all` repair tier.
    ///
    /// Repair intent is encoded by two bits, mirroring
    /// `qemu-img check -r leaks|all`:
    /// - [`FLAG_REPAIR`] alone selects the **leaks** tier — the
    ///   safe, lossless reclamation of allocated-but-unreferenced
    ///   clusters.
    /// - [`FLAG_REPAIR`] together with [`FLAG_REPAIR_ALL`] selects
    ///   the **all** tier — the leaks tier plus the lossy
    ///   refcount-structure rebuild and `corrupt`-bit clearing.
    /// - [`FLAG_REPAIR_ALL`] set *without* [`FLAG_REPAIR`] is
    ///   meaningless and is treated as **no repair**: the tier bit
    ///   only escalates an already-requested repair, it never
    ///   requests one on its own. [`should_repair_all`] enforces
    ///   this by requiring both bits.
    ///
    /// Bit 4 is free: bits 0-3 are
    /// REPAIR/QUIET/UNSAFE_QUIRKS/CHAIN here, and the VMM-side
    /// mirror's only other flag is VERBOSE at `1 << 31`.
    pub const FLAG_REPAIR_ALL: u32 = 1 << 4;

    /// Create a default config
    pub const fn default_config() -> Self {
        Self {
            magic: Self::MAGIC,
            flags: 0,
        }
    }

    /// Check if config is valid
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Check if repair flag is set
    pub fn should_repair(&self) -> bool {
        (self.flags & Self::FLAG_REPAIR) != 0
    }

    /// Check if the lossy `all` repair tier is requested.
    ///
    /// Returns true only when *both* [`FLAG_REPAIR`] and
    /// [`FLAG_REPAIR_ALL`] are set. [`FLAG_REPAIR_ALL`] on its own
    /// is meaningless (see its doc comment) and yields false here,
    /// so callers can branch on `should_repair()` for "any repair"
    /// and `should_repair_all()` for "escalate to the lossy tier".
    pub fn should_repair_all(&self) -> bool {
        (self.flags & Self::FLAG_REPAIR_ALL) != 0 && self.should_repair()
    }

    /// Check if quiet flag is set
    pub fn is_quiet(&self) -> bool {
        (self.flags & Self::FLAG_QUIET) != 0
    }

    /// Check if unsafe quirks flag is set
    pub fn unsafe_quirks_enabled(&self) -> bool {
        (self.flags & Self::FLAG_UNSAFE_QUIRKS) != 0
    }

    /// Check if chain validation flag is set
    pub fn chain_enabled(&self) -> bool {
        (self.flags & Self::FLAG_CHAIN) != 0
    }
}

/// Result structure for the check operation.
///
/// Returned via send_check_result call table function.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CheckResult {
    /// Magic number to verify result is valid (0x43485253 = "CHRS")
    pub magic: u32,

    /// Detected format (ImageFormat as u32)
    pub format: u32,

    /// Total number of errors found
    pub total_errors: u32,

    /// Number of corruptions (data integrity issues)
    pub corruptions: u32,

    /// Number of leaks (unreferenced allocated clusters)
    pub leaks: u32,

    /// Number of refcount inconsistencies
    pub refcount_errors: u32,

    /// Number of backing chain validation errors
    pub chain_errors: u32,

    /// Number of subcluster bitmap validation errors (extended L2)
    pub subcluster_errors: u32,

    /// Image end offset (highest byte offset in use)
    pub image_end_offset: u64,

    /// Total clusters checked
    pub clusters_checked: u64,

    /// Total allocated clusters
    pub clusters_allocated: u64,

    /// Fragmentation percentage (0-100)
    pub fragmentation: u32,

    /// Status flags
    pub flags: u32,

    /// Number of leaked clusters reclaimed during repair (0 when
    /// no repair ran). Folded in by the guest from the leak
    /// planner's [`RepairCounters`](../check/struct.RepairCounters.html).
    pub repaired_leaks: u32,

    /// Number of refcount inconsistencies corrected during repair
    /// (0 when no repair ran).
    pub repaired_refcounts: u32,

    /// Number of corruptions resolved during repair (0 when no
    /// repair ran).
    pub repaired_corruptions: u32,
}

impl Default for CheckResult {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckResult {
    /// Magic value for check result
    pub const MAGIC: u32 = 0x43485253; // "CHRS"

    /// Flag: Image is valid (no errors)
    pub const FLAG_VALID: u32 = 1 << 0;

    /// Flag: Image has leaks that could be fixed
    pub const FLAG_HAS_LEAKS: u32 = 1 << 1;

    /// Flag: Image has corruptions (data may be lost)
    pub const FLAG_HAS_CORRUPTIONS: u32 = 1 << 2;

    /// Flag: Image marked dirty (not cleanly closed)
    pub const FLAG_DIRTY: u32 = 1 << 3;

    /// Flag: Image marked corrupt in header
    pub const FLAG_CORRUPT_BIT: u32 = 1 << 4;

    /// Flag: Check was incomplete (e.g., format not supported)
    pub const FLAG_INCOMPLETE: u32 = 1 << 5;

    /// Flag: Format does not support check (e.g., raw)
    pub const FLAG_NOT_SUPPORTED: u32 = 1 << 6;

    /// Flag: Chain validation errors found
    pub const FLAG_CHAIN_ERRORS: u32 = 1 << 7;

    /// Flag: Repair ran but could not fully clean the image.
    ///
    /// Set when a `--repair` pass made progress but left findings
    /// behind — either a refuse-don't-guess boundary was hit, or
    /// the snapshot allocator returned `RefcountExhausted`. Bit 8
    /// is the first free bit: bits 0-7 are
    /// VALID/HAS_LEAKS/HAS_CORRUPTIONS/DIRTY/CORRUPT_BIT/INCOMPLETE/
    /// NOT_SUPPORTED/CHAIN_ERRORS.
    pub const FLAG_REPAIR_INCOMPLETE: u32 = 1 << 8;

    /// Create a new empty result
    pub const fn new() -> Self {
        Self {
            magic: Self::MAGIC,
            format: ImageFormat::Unknown as u32,
            total_errors: 0,
            corruptions: 0,
            leaks: 0,
            refcount_errors: 0,
            chain_errors: 0,
            subcluster_errors: 0,
            image_end_offset: 0,
            clusters_checked: 0,
            clusters_allocated: 0,
            fragmentation: 0,
            flags: 0,
            repaired_leaks: 0,
            repaired_refcounts: 0,
            repaired_corruptions: 0,
        }
    }

    /// Check if result is valid
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Check if a repair pass ran but could not fully clean the
    /// image (see [`FLAG_REPAIR_INCOMPLETE`]).
    pub fn repair_incomplete(&self) -> bool {
        (self.flags & Self::FLAG_REPAIR_INCOMPLETE) != 0
    }

    /// Get the detected format
    pub fn detected_format(&self) -> ImageFormat {
        ImageFormat::from_u32(self.format)
    }

    /// Check if the image passed validation (no errors)
    pub fn is_clean(&self) -> bool {
        (self.flags & Self::FLAG_VALID) != 0 && self.total_errors == 0
    }

    /// Check if the image has any corruption
    pub fn has_corruptions(&self) -> bool {
        (self.flags & Self::FLAG_HAS_CORRUPTIONS) != 0 || self.corruptions > 0
    }

    /// Check if the image has any leaks
    pub fn has_leaks(&self) -> bool {
        (self.flags & Self::FLAG_HAS_LEAKS) != 0 || self.leaks > 0
    }
}

// ============================================================================
// Compare operation configuration and results
// ============================================================================

/// Maximum passphrase length for compare config QCOW2 AES decryption.
pub const COMPARE_CONFIG_MAX_PASSPHRASE: usize = 256;

/// Configuration for the compare operation.
///
/// This structure is written to OPERATION_CONFIG_ADDR by the VMM.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompareConfig {
    /// Magic number to verify config is valid (0x434D5052 = "CMPR")
    pub magic: u32,

    /// Configuration flags
    pub flags: u32,

    /// Number of devices in image1's backing chain (0 = legacy/unset)
    /// Devices [0, image1_device_count) belong to image1's chain.
    pub image1_device_count: u32,

    /// Number of devices in image2's backing chain (0 = legacy/unset)
    /// Devices [image1_device_count, image1_device_count + image2_device_count)
    /// belong to image2's chain.
    pub image2_device_count: u32,

    /// QCOW2 AES passphrase length (0 = no passphrase provided)
    pub passphrase_len: u32,

    /// Padding for alignment
    pub _pad: u32,

    /// QCOW2 AES passphrase (null-padded, max 256 bytes)
    pub passphrase: [u8; COMPARE_CONFIG_MAX_PASSPHRASE],
}

impl CompareConfig {
    /// Magic value for compare config
    pub const MAGIC: u32 = 0x434D5052; // "CMPR"

    /// Flag: Strict mode (fail on size differences)
    pub const FLAG_STRICT: u32 = 1 << 0;

    /// Flag: Suppress output (quiet mode)
    pub const FLAG_QUIET: u32 = 1 << 1;

    /// Flag: Verbose logging
    pub const FLAG_VERBOSE: u32 = 1 << 31;

    /// Flag: Decrypt AES-encrypted QCOW2 input
    pub const FLAG_DECRYPT_AES: u32 = 1 << 2;

    /// Create a default config
    pub const fn default_config() -> Self {
        Self {
            magic: Self::MAGIC,
            flags: 0,
            image1_device_count: 1,
            image2_device_count: 1,
            passphrase_len: 0,
            _pad: 0,
            passphrase: [0; COMPARE_CONFIG_MAX_PASSPHRASE],
        }
    }

    /// Check if config is valid
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Check if strict mode is enabled
    pub fn is_strict(&self) -> bool {
        (self.flags & Self::FLAG_STRICT) != 0
    }

    /// Check if quiet flag is set
    pub fn is_quiet(&self) -> bool {
        (self.flags & Self::FLAG_QUIET) != 0
    }

    /// Check if a passphrase was provided for AES decryption.
    pub fn has_passphrase(&self) -> bool {
        self.passphrase_len > 0
    }

    /// Get the passphrase bytes (up to passphrase_len).
    pub fn passphrase_bytes(&self) -> &[u8] {
        let len = (self.passphrase_len as usize).min(COMPARE_CONFIG_MAX_PASSPHRASE);
        &self.passphrase[..len]
    }

    /// Number of devices in image1's backing chain.
    /// Returns 1 if unset (legacy config without chain fields).
    /// Legacy configs have these fields at zero because guest memory is
    /// zero-initialized. The zero-to-one fallback handles this case.
    pub fn image1_device_count(&self) -> u32 {
        if self.image1_device_count == 0 {
            1
        } else {
            self.image1_device_count
        }
    }

    /// Number of devices in image2's backing chain.
    /// Returns 1 if unset (legacy config without chain fields).
    /// Legacy configs have these fields at zero because guest memory is
    /// zero-initialized. The zero-to-one fallback handles this case.
    pub fn image2_device_count(&self) -> u32 {
        if self.image2_device_count == 0 {
            1
        } else {
            self.image2_device_count
        }
    }

    /// Starting device index for image2's chain.
    pub fn image2_start_device(&self) -> u32 {
        self.image1_device_count()
    }
}

/// Result structure for the compare operation.
///
/// Returned via send_compare_result call table function.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompareResult {
    /// Magic number to verify result is valid (0x434D5253 = "CMRS")
    pub magic: u32,

    /// Whether images are logically identical
    pub identical: u32, // u32 for FFI alignment (0=different, 1=identical)

    /// Byte offset of first content mismatch (only valid if not identical)
    pub first_mismatch_offset: u64,

    /// Total bytes compared
    pub total_bytes_compared: u64,

    /// Status flags
    pub flags: u32,

    /// Reserved for future use
    pub _reserved: u32,
}

impl Default for CompareResult {
    fn default() -> Self {
        Self::new()
    }
}

impl CompareResult {
    /// Magic value for compare result
    pub const MAGIC: u32 = 0x434D5253; // "CMRS"

    /// Flag: Images have different sizes
    pub const FLAG_SIZE_MISMATCH: u32 = 1 << 0;

    /// Create a new empty result (defaults to not identical)
    pub const fn new() -> Self {
        Self {
            magic: Self::MAGIC,
            identical: 0,
            first_mismatch_offset: 0,
            total_bytes_compared: 0,
            flags: 0,
            _reserved: 0,
        }
    }

    /// Check if result is valid
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Check if images are identical
    pub fn is_identical(&self) -> bool {
        self.identical != 0
    }

    /// Check if images have different sizes
    pub fn has_size_mismatch(&self) -> bool {
        (self.flags & Self::FLAG_SIZE_MISMATCH) != 0
    }
}

/// Maximum passphrase length for QCOW2 AES decryption.
pub const CONVERT_CONFIG_MAX_PASSPHRASE: usize = 256;
pub const CONVERT_CONFIG_MAX_SNAPSHOT_ID: usize = 64;

/// Configuration for the convert operation.
///
/// This structure is written to OPERATION_CONFIG_ADDR by the VMM.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConvertConfig {
    /// Magic number to verify config is valid (0x434F4E56 = "CONV")
    pub magic: u32,

    /// Configuration flags
    pub flags: u32,

    /// Number of input devices in the backing chain
    pub input_device_count: u32,

    /// Target output format (ImageFormat as u32)
    pub target_format: u32,

    /// Output cluster bits for QCOW2 output (0 = default 16 = 64KB).
    /// Valid range: 9..=16. Ignored for non-QCOW2 output formats.
    pub output_cluster_bits: u32,

    /// QCOW2 AES passphrase length (0 = no passphrase provided)
    pub passphrase_len: u32,

    /// Padding for alignment
    pub _pad: u32,

    /// QCOW2 AES passphrase (null-padded, max 256 bytes)
    pub passphrase: [u8; CONVERT_CONFIG_MAX_PASSPHRASE],

    /// Snapshot ID or name length (0 = no snapshot, use active image)
    pub snapshot_id_len: u32,

    /// Padding for alignment
    pub _pad2: u32,

    /// Snapshot ID or name (null-padded, max 64 bytes)
    pub snapshot_id: [u8; CONVERT_CONFIG_MAX_SNAPSHOT_ID],

    /// Padding for u64 alignment (offset 356 → 360)
    pub _pad3: u32,

    /// Extra guest memory available for Argon2id (bytes).
    /// When non-zero, memory at ARGON2_MEM_BASE is available for
    /// Argon2id key derivation (LUKS v2). Set via --max-guest-memory.
    /// Offset: 360
    pub argon2_mem_size: u64,

    /// PBKDF2 iteration count for LUKS output encryption.
    /// Only used when FLAG_ENCRYPT_LUKS is set.
    /// Offset: 368
    pub luks_encrypt_iterations: u32,

    /// Length of master key for LUKS output (32 or 64).
    /// Offset: 372
    pub luks_encrypt_key_bytes: u32,

    /// Address in guest memory where LUKS random data is stored.
    /// The VMM writes: master key (64 bytes) + MK digest salt (32 bytes)
    /// + slot salt (32 bytes) + UUID (36 bytes) + AF random stripes.
    ///   Offset: 376
    pub luks_random_data_addr: u64,

    /// Total size of the LUKS random data region.
    /// Offset: 384
    pub luks_random_data_size: u64,

    /// Output grain size in bytes for VMDK output (0 = default 64KB).
    /// Must be a power of 2, 4096..=65536.
    /// Offset: 392
    pub output_grain_size: u32,

    /// Output block size in bytes for VHD/VHDX output (0 = default per format:
    /// 2MB for VHD, 32MB for VHDX). Must be a power of 2.
    /// VHD: 512KB..=256MB. VHDX: 1MB..=256MB.
    /// Offset: 396
    pub output_block_size: u32,

    /// Inclusive VIRTUAL byte offset where the guest begins reading the input
    /// for a `dd` windowed copy. `0` when `FLAG_DD_WINDOW` is clear; only
    /// meaningful with that flag set.
    /// Offset: 400
    pub window_start: u64,

    /// Exclusive VIRTUAL byte offset where the guest stops reading. `0` when
    /// `FLAG_DD_WINDOW` is clear; with the flag set, `window_end == 0` means
    /// copy nothing (empty output).
    /// Offset: 408
    pub window_end: u64,
}

impl ConvertConfig {
    /// Magic value for convert config
    pub const MAGIC: u32 = 0x434F4E56; // "CONV"

    /// Flag: Skip writing zero-filled clusters to output
    pub const FLAG_SKIP_ZEROS: u32 = 1 << 0;

    /// Flag: Compress data clusters in QCOW2 output
    pub const FLAG_COMPRESS: u32 = 1 << 1;

    /// Flag: Decrypt AES-encrypted QCOW2 input
    pub const FLAG_DECRYPT_AES: u32 = 1 << 2;

    /// Flag: Write extended L2 entries (16-byte) in QCOW2 output
    pub const FLAG_EXTENDED_L2: u32 = 1 << 3;

    /// Flag: Write LUKS-encrypted QCOW2 output (crypt_method=2)
    pub const FLAG_ENCRYPT_LUKS: u32 = 1 << 4;

    /// Flag: Gates `window_start`/`window_end`; set only by the `dd` subcommand
    /// to mark a windowed (and dense) convert. When clear, the guest ignores the
    /// window fields and behaves identically to a plain `convert`.
    pub const FLAG_DD_WINDOW: u32 = 1 << 5;

    /// Flag: Verbose logging
    pub const FLAG_VERBOSE: u32 = 1 << 31;

    /// Create a default config
    pub const fn default_config() -> Self {
        Self {
            magic: Self::MAGIC,
            flags: 0,
            input_device_count: 1,
            target_format: 0,       // Raw
            output_cluster_bits: 0, // Default (16 = 64KB)
            passphrase_len: 0,
            _pad: 0,
            passphrase: [0; CONVERT_CONFIG_MAX_PASSPHRASE],
            snapshot_id_len: 0,
            _pad2: 0,
            snapshot_id: [0; CONVERT_CONFIG_MAX_SNAPSHOT_ID],
            _pad3: 0,
            argon2_mem_size: 0,
            luks_encrypt_iterations: 0,
            luks_encrypt_key_bytes: 0,
            luks_random_data_addr: 0,
            luks_random_data_size: 0,
            output_grain_size: 0,
            output_block_size: 0,
            window_start: 0,
            window_end: 0,
        }
    }

    /// Check if config is valid
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Check if skip-zeros is enabled
    pub fn should_skip_zeros(&self) -> bool {
        (self.flags & Self::FLAG_SKIP_ZEROS) != 0
    }

    /// Check if a `dd` input window (`window_start`/`window_end`) is active.
    pub fn has_dd_window(&self) -> bool {
        (self.flags & Self::FLAG_DD_WINDOW) != 0
    }

    /// Check if compression is enabled
    pub fn should_compress(&self) -> bool {
        (self.flags & Self::FLAG_COMPRESS) != 0
    }

    /// Check if extended L2 output is enabled
    pub fn extended_l2_output(&self) -> bool {
        (self.flags & Self::FLAG_EXTENDED_L2) != 0
    }

    /// Check if LUKS-encrypted output is enabled
    pub fn encrypt_luks_output(&self) -> bool {
        (self.flags & Self::FLAG_ENCRYPT_LUKS) != 0
    }

    /// Number of input devices in the backing chain.
    /// Returns 1 if unset (zero-initialized guest memory fallback).
    pub fn input_device_count(&self) -> u32 {
        if self.input_device_count == 0 {
            1
        } else {
            self.input_device_count
        }
    }

    /// Target output format.
    pub fn target_format(&self) -> ImageFormat {
        ImageFormat::from_u32(self.target_format)
    }

    /// Output cluster bits for QCOW2 output.
    /// Returns 16 (64KB) if unset or out of range.
    pub fn output_cluster_bits(&self) -> u32 {
        if self.output_cluster_bits >= 9 && self.output_cluster_bits <= 21 {
            self.output_cluster_bits
        } else {
            16
        }
    }

    /// Output grain size in bytes for VMDK output.
    /// Returns 65536 (64KB) if unset or out of range.
    pub fn output_grain_size(&self) -> u64 {
        let v = self.output_grain_size;
        if v != 0 && v.is_power_of_two() && (4096..=65536).contains(&v) {
            v as u64
        } else {
            65536
        }
    }

    /// Output block size in bytes for VHD output.
    /// Returns 2MB if unset or out of range.
    pub fn output_block_size_vhd(&self) -> u64 {
        let v = self.output_block_size;
        if v != 0 && v.is_power_of_two() && (512 * 1024..=256 * 1024 * 1024).contains(&v) {
            v as u64
        } else {
            2 * 1024 * 1024
        }
    }

    /// Output block size in bytes for VHDX output.
    /// Returns 32MB if unset or out of range.
    pub fn output_block_size_vhdx(&self) -> u64 {
        let v = self.output_block_size;
        if v != 0 && v.is_power_of_two() && (1024 * 1024..=256 * 1024 * 1024).contains(&v) {
            v as u64
        } else {
            32 * 1024 * 1024
        }
    }

    /// Check if a passphrase was provided for AES decryption.
    pub fn has_passphrase(&self) -> bool {
        self.passphrase_len > 0
    }

    /// Get the passphrase bytes (up to passphrase_len).
    pub fn passphrase_bytes(&self) -> &[u8] {
        let len = (self.passphrase_len as usize).min(CONVERT_CONFIG_MAX_PASSPHRASE);
        &self.passphrase[..len]
    }

    /// Check if a snapshot ID was provided.
    pub fn has_snapshot_id(&self) -> bool {
        self.snapshot_id_len > 0
    }

    /// Get the snapshot ID bytes (up to snapshot_id_len).
    pub fn snapshot_id_bytes(&self) -> &[u8] {
        let len = (self.snapshot_id_len as usize).min(CONVERT_CONFIG_MAX_SNAPSHOT_ID);
        &self.snapshot_id[..len]
    }
}

// ============================================================================
// Measure configuration and result structures
// ============================================================================

/// Configuration for the measure operation.
///
/// Written to `OPERATION_CONFIG_ADDR` by the VMM before launching the
/// measure guest binary. The guest reads this directly via
/// `&*(OPERATION_CONFIG_ADDR as *const MeasureConfig)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MeasureConfig {
    /// Magic number (`0x4D454153` = "MEAS").
    pub magic: u32,
    /// Target output format (`ImageFormat as u32`). Only RAW, QCOW2,
    /// VMDK, VHD, and VHDX are valid for measure.
    pub target_format: u32,
    /// Configuration flags (see `FLAG_*` / `PREALLOC_*` constants).
    pub flags: u32,
    /// Sector size for input I/O (typically 65536).
    pub sector_size: u32,

    /// Non-zero virtual size in `--size` mode (skip source scan).
    /// Zero means "scan source device".
    pub virtual_size_override: u64,

    /// qcow2 output cluster size in bytes. 0 = default (65536).
    pub qcow2_cluster_size: u32,
    /// qcow2 refcount entry width in bits. 0 = default (16).
    pub qcow2_refcount_bits: u8,
    /// vmdk subformat: 0=MonolithicSparse, 1=StreamOptimized, 2=MonolithicFlat.
    pub vmdk_subformat: u8,
    /// Reserved padding.
    pub _pad2: u16,
    /// vmdk grain size in bytes. 0 = default (65536).
    pub vmdk_grain_size: u32,
    /// vhd subformat: 0=Dynamic, 1=Fixed.
    pub vhd_subformat: u8,
    /// Reserved padding.
    pub _pad3: [u8; 3],
    /// vhd / vhdx block size in bytes. 0 = format default.
    pub block_size: u32,
    /// Reserved padding for 8-byte alignment of luks_header_overhead.
    pub _pad4: u32,
    /// LUKS-in-qcow2 header overhead in bytes. 0 = no LUKS.
    pub luks_header_overhead: u64,
}

impl MeasureConfig {
    /// Magic value for measure config.
    pub const MAGIC: u32 = 0x4D454153; // "MEAS"

    /// Flag: write extended-L2 entries in qcow2 output.
    pub const FLAG_EXTENDED_L2: u32 = 1 << 0;
    /// Flag: qcow2 lazy refcounts (accepted, no size effect).
    pub const FLAG_LAZY_REFCOUNTS: u32 = 1 << 1;
    /// Flag: produce qcow2 v3 (compat 1.1). Default true; clear for v2.
    pub const FLAG_COMPAT_V3: u32 = 1 << 2;
    /// Flag: qcow2 compressed output (no size effect, matches qemu-img).
    pub const FLAG_COMPRESS: u32 = 1 << 3;

    /// Preallocation mode is encoded in flags bits 4-5.
    pub const PREALLOC_MASK: u32 = 0b11 << 4;
    pub const PREALLOC_OFF: u32 = 0 << 4;
    pub const PREALLOC_METADATA: u32 = 1 << 4;
    pub const PREALLOC_FALLOC: u32 = 2 << 4;
    pub const PREALLOC_FULL: u32 = 3 << 4;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Extract the preallocation bits from `flags`.
    pub fn preallocation(&self) -> u32 {
        self.flags & Self::PREALLOC_MASK
    }
}

/// Result structure for the measure operation.
///
/// Returned via the `send_measure_result` call table function.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MeasureResult {
    /// Magic value (`0x4D524553` = "MRES").
    pub magic: u32,
    /// Target format echoed back so the host can render the right output.
    pub target_format: u32,
    /// Bytes required when only allocated extents are written.
    pub required: u64,
    /// Bytes required when every cluster/grain/block is allocated.
    pub fully_allocated: u64,
    /// Cluster / grain / block size actually used after resolving defaults
    /// (host renders this in JSON output where qemu-img varies).
    /// Zero for raw output (no unit).
    pub resolved_unit_size: u32,
    /// Error code: 0 = ok, non-zero mirrors `MeasureError`.
    pub error: u32,
}

impl MeasureResult {
    /// Magic value for measure result.
    pub const MAGIC: u32 = 0x4D524553; // "MRES"

    pub const ERROR_OK: u32 = 0;
    pub const ERROR_OVERFLOW: u32 = 1;
    pub const ERROR_INVALID_OPTION: u32 = 2;
    pub const ERROR_INVALID_SIZE: u32 = 3;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

// ============================================================================
// Map configuration and result structures
// ============================================================================

/// Configuration for the map operation.
///
/// Written to `OPERATION_CONFIG_ADDR` by the VMM before launching
/// the map guest binary. The guest reads this directly via
/// `&*(OPERATION_CONFIG_ADDR as *const MapConfig)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MapConfig {
    /// Magic (`0x4D41505F` = "MAP_").
    pub magic: u32,
    /// Configuration flags. Bit 31 is FLAG_VERBOSE; all other
    /// bits are reserved for future use (chain mode, SEEK_HOLE
    /// host pre-pass, etc.).
    pub flags: u32,
    /// Sector size for input I/O (typically 65536).
    pub sector_size: u32,
    /// Number of input devices in the backing chain. Reserved
    /// for the chain follow-up; phase 2 enforces
    /// `input_device_count == 1`.
    pub input_device_count: u32,
    /// Start the emission window at this virtual byte offset.
    /// Zero means "start at the beginning of the image".
    pub start_offset: u64,
    /// Stop the emission window after this many virtual bytes
    /// from `start_offset`. Zero means "emit to virtual_size".
    /// A non-zero value smaller than one source cluster /
    /// grain / block still emits the extent that overlaps the
    /// window; trimming happens at extent boundaries, matching
    /// qemu-img map.
    pub max_length: u64,
    /// Reserved padding for forward compat. Future fields:
    /// snapshot ID length + bytes, image-opts descriptor.
    pub _reserved: [u8; 32],
}

impl MapConfig {
    /// Magic value for map config.
    pub const MAGIC: u32 = 0x4D41505F; // "MAP_"

    /// Flag: verbose guest logging.
    pub const FLAG_VERBOSE: u32 = 1 << 31;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// One coalesced map extent in the on-wire FFI representation.
///
/// The parser-facing [`MapExtent`] type (Rust enum) is converted
/// at the guest's emit boundary into this `#[repr(C)]` form so
/// the call-table function pointer can take a plain pointer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MapExtentRecord {
    /// Magic (`0x4D584554` = "MXET").
    pub magic: u32,
    /// State code: 0 = Hole, 1 = ZeroAllocated, 2 = Data.
    pub state: u32,
    /// Virtual offset of the extent's first byte.
    pub start: u64,
    /// Extent length in bytes. Never zero.
    pub length: u64,
    /// Source file offset for `state == STATE_DATA`; zero
    /// otherwise. (Host renderer omits the JSON field when
    /// `state != STATE_DATA`.)
    pub file_offset: u64,
    /// Reserved padding for forward compat (compressed length,
    /// subcluster flags, chain depth).
    pub _reserved: [u8; 16],
}

impl MapExtentRecord {
    /// Magic value for map extent record.
    pub const MAGIC: u32 = 0x4D584554; // "MXET"

    /// Extent state: unallocated, reads as zero, not present in
    /// the source file.
    pub const STATE_HOLE: u32 = 0;
    /// Extent state: explicitly recorded as zero in the metadata
    /// (qcow2 ZERO_PLAIN / ZERO_ALLOC, vmdk grain marker, vhdx
    /// PAYLOAD_BLOCK_ZERO).
    pub const STATE_ZERO_ALLOCATED: u32 = 1;
    /// Extent state: contains data backed by the source file at
    /// `file_offset`.
    pub const STATE_DATA: u32 = 2;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Result structure for the map operation.
///
/// One per invocation, sent via the `send_map_result` call-table
/// function after every `send_map_extent`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MapResult {
    /// Magic (`0x4D505253` = "MPRS").
    pub magic: u32,
    /// Source format echoed back. ImageFormat-as-u32; the host
    /// translates to a name for the protobuf envelope.
    pub source_format: u32,
    /// Number of `send_map_extent` calls the guest made during
    /// this invocation. The host can sanity-check that it
    /// received exactly that many extent messages before the
    /// result.
    pub extents_emitted: u64,
    /// Virtual size of the source image, in bytes. The host uses
    /// this to verify the partition invariant (sum of received
    /// extent lengths == virtual_size minus any window trim).
    pub virtual_size: u64,
    /// Error code: 0 = ok, non-zero mirrors `MapResult::ERROR_*`.
    pub error: u32,
    /// Reserved padding for forward compat.
    pub _reserved: u32,
}

impl MapResult {
    /// Magic value for map result.
    pub const MAGIC: u32 = 0x4D505253; // "MPRS"

    pub const ERROR_OK: u32 = 0;
    /// Source format unrecognised or scan rejected the image.
    pub const ERROR_INVALID_SOURCE: u32 = 1;
    /// Invalid config (missing magic, bad sector_size,
    /// input_device_count != 1, oversized start_offset).
    pub const ERROR_INVALID_OPTION: u32 = 2;
    /// Source has a backing file / parent / multi-extent
    /// descriptor and chain composition is deferred.
    pub const ERROR_HAS_BACKING: u32 = 3;
    /// I/O failure during walk.
    pub const ERROR_IO: u32 = 4;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

// ============================================================================
// Snapshot configuration and result structures
// ============================================================================

/// Configuration for the snapshot operation.
///
/// Written to `OPERATION_CONFIG_ADDR` by the VMM before launching
/// the snapshot guest binary. The guest reads this directly via
/// `&*(OPERATION_CONFIG_ADDR as *const SnapshotConfig)`.
///
/// `mode` is the discriminator between list / apply / create /
/// delete. `arg` carries the snapshot ID or name as UTF-8 bytes
/// (no nul terminator); `arg_len` is the byte count actually used.
/// For `MODE_LIST` the argument is unused and `arg_len` should be 0.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnapshotConfig {
    /// Magic (`0x534E4150` = "SNAP").
    pub magic: u32,
    /// Mode discriminator: one of `MODE_LIST`, `MODE_APPLY`,
    /// `MODE_CREATE`, `MODE_DELETE`.
    pub mode: u32,
    /// Configuration flags: `FLAG_QUIET`, `FLAG_FORCE_SHARE`,
    /// or `FLAG_VERBOSE` (bit 31). Other bits are reserved.
    pub flags: u32,
    /// Sector size for input I/O (typically 512 or 65536).
    pub sector_size: u32,

    /// Bytes used in `arg` (0..=255). `MODE_LIST` accepts 0.
    pub arg_len: u32,
    /// Padding so `arg` is 8-byte aligned within the struct.
    pub _pad: u32,

    /// Snapshot ID or name (UTF-8, no nul). For `-a` / `-d` this
    /// is the ID or name to match. For `-c` this is the requested
    /// snapshot name.
    pub arg: [u8; 256],

    /// Host wall-clock seconds since the UNIX epoch at the moment
    /// of invocation. Written by the host for `MODE_CREATE`; stored
    /// verbatim in the new snapshot's on-disk `date_sec` field. Zero
    /// for every other mode (the guest has no clock). Truncated to a
    /// `u32` to match the qcow2 on-disk field width (qemu wraps in
    /// 2106 too).
    pub date_sec: u32,
    /// Host wall-clock sub-second component (nanoseconds) at the
    /// moment of invocation. Stored verbatim in the new snapshot's
    /// on-disk `date_nsec` field for `MODE_CREATE`; zero otherwise.
    /// The host truncates this to microsecond precision
    /// (`usec * 1000`) so it matches `qemu-img`'s
    /// `tv_usec * 1000` byte-for-byte.
    pub date_nsec: u32,

    /// Reserved padding for forward compat (image-opts descriptor,
    /// chain-depth tag, etc.).
    pub _reserved: [u8; 24],
}

impl SnapshotConfig {
    /// Magic value for snapshot config.
    pub const MAGIC: u32 = 0x534E4150; // "SNAP"

    /// Mode: list snapshots (read-only).
    pub const MODE_LIST: u32 = 0;
    /// Mode: apply / "goto" the named snapshot.
    pub const MODE_APPLY: u32 = 1;
    /// Mode: create a snapshot with the given name.
    pub const MODE_CREATE: u32 = 2;
    /// Mode: delete the named snapshot.
    pub const MODE_DELETE: u32 = 3;

    /// Flag: suppress the success line on stdout (host-side `-q`).
    pub const FLAG_QUIET: u32 = 1 << 0;
    /// Flag: skip image-lock check (host-side `-U`; the guest
    /// ignores this).
    pub const FLAG_FORCE_SHARE: u32 = 1 << 1;
    /// Flag: verbose guest logging. Matches the bit-31 convention
    /// used by `MapConfig::FLAG_VERBOSE` and friends.
    pub const FLAG_VERBOSE: u32 = 1 << 31;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// One snapshot record in the on-wire FFI representation.
///
/// Emitted once per snapshot during `MODE_LIST` via the
/// `send_snapshot_entry` call-table function pointer, before the
/// terminating `send_snapshot_result`. The host serialises the
/// record into a protobuf `SnapshotEntryMessage` so the guest does
/// not need to depend on the protobuf encoder.
///
/// `date_sec` is split into `date_sec_hi` and `date_sec_lo` to
/// match the on-disk qcow2 snapshot-header layout (two big-endian
/// u32s) and to avoid requiring a 64-bit aligned write on the FFI
/// boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnapshotEntryRecord {
    /// Magic (`0x534E4552` = "SNER").
    pub magic: u32,
    /// High 32 bits of the snapshot's `date_sec` (matches the
    /// qcow2 on-disk split).
    pub date_sec_hi: u32,
    /// Low 32 bits of the snapshot's `date_sec`.
    pub date_sec_lo: u32,
    /// Subsecond component of the snapshot date (nanoseconds).
    pub date_nsec: u32,

    /// VM clock at snapshot creation (nanoseconds).
    pub vm_clock_nsec: u64,
    /// 64-bit VM state size (qcow2 v3 extra-data offset 0).
    pub vm_state_size_large: u64,
    /// Virtual disk size at snapshot creation (qcow2 v3
    /// extra-data offset 8).
    pub disk_size: u64,
    /// qemu record/replay icount (qcow2 v3 extra-data offset 16).
    /// `u64::MAX` sentinel for "absent" (matches qemu's
    /// `qcow2_snapshot.icount = -1`).
    pub icount: u64,

    /// Host offset of the snapshot's L1 table.
    pub l1_table_offset: u64,
    /// Snapshot L1 size, in entries.
    pub l1_size: u32,
    /// Length of the source extra-data section, reported for
    /// forward-compat diagnostics.
    pub extra_data_size: u32,

    /// Bytes used in `id`.
    pub id_len: u32,
    /// Bytes used in `name`.
    pub name_len: u32,

    /// Snapshot ID (qemu uses small decimal strings; 32 is
    /// generous).
    pub id: [u8; 32],
    /// Snapshot tag/name (UTF-8, no nul).
    pub name: [u8; 256],

    /// Reserved padding for forward compat.
    pub _reserved: [u8; 32],
}

impl SnapshotEntryRecord {
    /// Magic value for snapshot entry record.
    pub const MAGIC: u32 = 0x534E4552; // "SNER"

    /// Sentinel indicating no icount is present on the source
    /// snapshot (matches qemu's `qcow2_snapshot.icount = -1`).
    pub const ICOUNT_ABSENT: u64 = u64::MAX;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Result structure for the snapshot operation.
///
/// One per invocation, sent via the `send_snapshot_result` call-
/// table function after every `send_snapshot_entry` (or as the
/// only call for `MODE_APPLY` / `_CREATE` / `_DELETE`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnapshotResult {
    /// Magic (`0x534E5253` = "SNRS").
    pub magic: u32,
    /// Echo of the requested `SnapshotConfig.mode`.
    pub mode: u32,
    /// Error code: 0 = ok, non-zero mirrors `SnapshotResult::ERROR_*`.
    pub error: u32,
    /// Padding so `snapshots_emitted` lands at a 4-byte boundary
    /// inside the struct.
    pub _pad: u32,

    /// Number of `send_snapshot_entry` calls the guest made
    /// during this invocation (populated for `MODE_LIST`; zero
    /// otherwise).
    pub snapshots_emitted: u32,
    /// Bytes used in `assigned_id` (populated for `MODE_CREATE`).
    pub assigned_id_len: u32,
    /// Auto-assigned snapshot ID returned by `MODE_CREATE`
    /// (qemu uses decimal strings: "0", "1", ...). Empty
    /// (`assigned_id_len == 0`) for the other modes.
    pub assigned_id: [u8; 64],

    /// Reserved padding for forward compat.
    pub _reserved: [u8; 96],
}

impl SnapshotResult {
    /// Magic value for snapshot result.
    pub const MAGIC: u32 = 0x534E5253; // "SNRS"

    /// Success.
    pub const ERROR_OK: u32 = 0;
    /// Source is not qcow2; `qemu-img snapshot` refuses all
    /// non-qcow2 formats.
    pub const ERROR_UNSUPPORTED_FORMAT: u32 = 1;
    /// qcow2 image has compressed clusters, encryption, an
    /// external data file, or bitmaps. Only the mutating modes
    /// refuse; `MODE_LIST` still works.
    pub const ERROR_UNSUPPORTED_FEATURE: u32 = 2;
    /// `-a` or `-d` argument matches neither an ID nor a name.
    pub const ERROR_NOT_FOUND: u32 = 3;
    /// `-c` with a name that already exists in the snapshot
    /// table.
    pub const ERROR_DUPLICATE_NAME: u32 = 4;
    /// A cluster's refcount would exceed `1 << refcount_bits`.
    /// Caught by the phase 5 dry-run pass.
    pub const ERROR_REFCOUNT_OVERFLOW: u32 = 5;
    /// Refcount table is full and cannot grow within v1's
    /// bounds.
    pub const ERROR_ALLOCATION_FAILED: u32 = 6;
    /// Would exceed the in-memory snapshot-table cap (phase 2
    /// picks the value; qcow2 spec allows up to 65536).
    pub const ERROR_SNAPSHOT_TABLE_FULL: u32 = 7;
    /// Sector read or write failed at the call-table boundary.
    pub const ERROR_IO: u32 = 8;
    /// `-a` target's L1 is larger than the active L1 allocation
    /// and growing would exceed the qcow2 spec cap.
    pub const ERROR_L1_SIZE_MISMATCH: u32 = 9;
    /// Name field in `SnapshotConfig.arg` is not valid UTF-8.
    pub const ERROR_INVALID_UTF8: u32 = 10;
    /// Magic / version mismatch in `SnapshotConfig`.
    pub const ERROR_INVALID_CONFIG: u32 = 11;
    /// qcow2 header / snapshot-table byte-level parse failed.
    pub const ERROR_PARSE_FAILED: u32 = 12;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

// ============================================================================
// Create configuration and result structures
// ============================================================================

/// Maximum permitted length of the backing-file path embedded in a
/// [`CreateConfig`]. Must match `create::MAX_BACKING_FILE_LEN` so the
/// host CLI, the call-table struct, and the create library all agree
/// on the cap.
pub const CREATE_CONFIG_MAX_BACKING_FILE: usize = 1024;

/// Configuration for the create operation.
///
/// Written to `OPERATION_CONFIG_ADDR` by the VMM before launching the
/// create guest binary. The guest reads this directly via
/// `&*(OPERATION_CONFIG_ADDR as *const CreateConfig)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CreateConfig {
    /// Magic (`0x43524541` = "CREA").
    pub magic: u32,
    /// Target output format (`ImageFormat as u32`).
    pub target_format: u32,
    /// Flags. See `FLAG_*` constants.
    pub flags: u32,
    /// Sector size for I/O (matches host sector_size).
    pub sector_size: u32,

    /// Virtual disk size in bytes. Zero means "infer from backing
    /// file" — the guest reads input device 0's header to recover the
    /// backing virtual size. Explicit non-zero values always win over
    /// backing inference, matching qemu-img's `-b BACKING SIZE`
    /// precedence.
    pub virtual_size: u64,

    /// qcow2 cluster size in bytes. 0 = default (65536).
    pub qcow2_cluster_size: u32,
    /// qcow2 refcount entry width in bits. 0 = default (16).
    pub qcow2_refcount_bits: u8,
    /// vmdk subformat: 0=MonolithicSparse, 1=StreamOptimized.
    pub vmdk_subformat: u8,
    /// vhd subformat: 0=Dynamic, 1=Fixed.
    pub vhd_subformat: u8,
    /// Reserved padding.
    pub _pad: u8,
    /// vmdk grain size in bytes. 0 = default (65536).
    pub vmdk_grain_size: u32,
    /// vhd/vhdx block size in bytes. 0 = format default.
    pub block_size: u32,

    /// Length of the backing-file path in bytes. 0 = no backing.
    pub backing_file_len: u32,
    /// Backing-file path (locale-bytes, no NUL terminator). Only the
    /// first `backing_file_len` bytes are valid.
    pub backing_file: [u8; CREATE_CONFIG_MAX_BACKING_FILE],
    /// Backing-file format (`ImageFormat as u32`). 0 = unset.
    pub backing_format: u32,

    /// Reserved padding for forward compatibility (zero-init).
    pub _reserved: [u8; 64],
}

impl CreateConfig {
    /// Magic value for create config.
    pub const MAGIC: u32 = 0x43524541; // "CREA"

    /// Flag: write extended-L2 entries in qcow2 output.
    pub const FLAG_EXTENDED_L2: u32 = 1 << 0;
    /// Flag: enable the qcow2 lazy-refcounts compat bit.
    pub const FLAG_LAZY_REFCOUNTS: u32 = 1 << 1;
    /// Flag: produce qcow2 v3 (compat 1.1). Default-on: when the
    /// entire flags word is zero the guest treats compat_v3 as set.
    /// Clear this bit explicitly to request qcow2 v2 (compat 0.10).
    pub const FLAG_COMPAT_V3: u32 = 1 << 2;
    /// Flag: backing-file existence/format check should be skipped
    /// (qemu-img's `-u` / `--backing-unsafe`). Phase 5 wires this up.
    pub const FLAG_BACKING_UNSAFE: u32 = 1 << 3;

    /// Preallocation mode encoded in flags bits 4-5 (phase 6).
    /// Mirrors `MeasureConfig::PREALLOC_*`'s layout exactly.
    pub const PREALLOC_MASK: u32 = 0b11 << 4;
    pub const PREALLOC_OFF: u32 = 0 << 4;
    pub const PREALLOC_METADATA: u32 = 1 << 4;
    pub const PREALLOC_FALLOC: u32 = 2 << 4;
    pub const PREALLOC_FULL: u32 = 3 << 4;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Extract the preallocation mode from `flags`.
    pub fn preallocation(&self) -> u32 {
        self.flags & Self::PREALLOC_MASK
    }

    /// Slice view over the populated portion of `backing_file`.
    pub fn backing_file_bytes(&self) -> &[u8] {
        let len = (self.backing_file_len as usize).min(CREATE_CONFIG_MAX_BACKING_FILE);
        &self.backing_file[..len]
    }

    /// True if a backing-file reference was supplied.
    pub fn has_backing(&self) -> bool {
        self.backing_file_len > 0
    }
}

/// Result structure for the create operation.
///
/// Passed by the guest into `call_table.send_create_result`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CreateResult {
    /// Magic value (`0x43524553` = "CRES").
    pub magic: u32,
    /// Target format echoed back so the host can render the right output.
    pub target_format: u32,
    /// Resolved virtual size in bytes (echoes the config, or the
    /// backing-file-derived size when the config had `virtual_size == 0`).
    pub resolved_virtual_size: u64,
    /// Bytes the guest wrote to the output device (sum of MetadataWrite
    /// lengths in the plan).
    pub metadata_bytes_written: u64,
    /// File size after the guest finishes (max byte_offset + len across
    /// the plan; the host may grow the file beyond this for
    /// preallocation in phase 6).
    pub file_size_after: u64,
    /// Resolved cluster/grain/block size. 0 for raw output.
    pub resolved_unit_size: u32,
    /// Error code: 0 = ok, non-zero mirrors `ERROR_*`.
    pub error: u32,
}

impl CreateResult {
    /// Magic value for create result.
    pub const MAGIC: u32 = 0x43524553; // "CRES"

    // Error codes are stable: only appended, never reordered.
    // Existing operation binaries depend on the numeric values
    // matching what the host renders.
    pub const ERROR_OK: u32 = 0;
    pub const ERROR_INVALID_OPTION: u32 = 1;
    pub const ERROR_INVALID_SIZE: u32 = 2;
    pub const ERROR_SCRATCH_TOO_SMALL: u32 = 3;
    pub const ERROR_BACKING_READ_FAILED: u32 = 4;
    pub const ERROR_BACKING_PARSE_FAILED: u32 = 5;
    pub const ERROR_BACKING_TOO_LONG: u32 = 6;
    pub const ERROR_WRITE_FAILED: u32 = 7;
    pub const ERROR_UNSUPPORTED_FORMAT: u32 = 8;
    /// Backing format was recognised but the guest can't extract
    /// `virtual_size` from it (e.g. a future regression breaks the
    /// vhdx walk). Distinguished from BACKING_PARSE_FAILED so the
    /// host can render "format X as backing is not supported"
    /// rather than "couldn't parse the backing header".
    pub const ERROR_BACKING_FORMAT_UNSUPPORTED: u32 = 9;
    /// Backing image's `virtual_size` exceeds the target format's
    /// addressable range with the chosen options. Surfaced by the
    /// guest's pre-flight ceiling check before plan_* runs, so the
    /// host can suggest "try a larger cluster size or a different
    /// target format" rather than the generic INVALID_SIZE.
    pub const ERROR_BACKING_SIZE_TOO_LARGE: u32 = 10;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

// ============================================================================
// Resize operation
// ============================================================================

/// Configuration for the resize operation.
///
/// Written to `OPERATION_CONFIG_ADDR` by the VMM before launching
/// the resize guest binary. The guest reads this directly via
/// `&*(OPERATION_CONFIG_ADDR as *const ResizeConfig)`.
///
/// Mirrors [`CreateConfig`]'s shape (flags layout, preallocation
/// bits at 4-5, sector_size, padding for forward compat) so the
/// host CLI and the guest planner share idioms across operations.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResizeConfig {
    /// Magic (`0x52455349` = "RESI").
    pub magic: u32,
    /// Source/target format (`ImageFormat as u32`). Resize is an
    /// in-place mutation: source and target format are identical.
    pub target_format: u32,
    /// Flags. See `FLAG_*` constants and `PREALLOC_*`.
    pub flags: u32,
    /// Sector size for I/O (matches host sector_size).
    pub sector_size: u32,

    /// Current virtual size in bytes. The host populates this
    /// from the existing image's header before launching the
    /// guest; if the guest's own parse disagrees, that mismatch
    /// is one of the conditions surfaced via
    /// [`ResizeResult::ERROR_HEADER_MISMATCH`].
    pub current_virtual_size: u64,
    /// Requested new virtual size in bytes. The host resolves
    /// `[+-]SIZE` syntax to an absolute byte count before
    /// populating this field.
    pub new_virtual_size: u64,

    /// qcow2 cluster size in bytes (from the existing header).
    /// 0 if the image isn't qcow2.
    pub qcow2_cluster_size: u32,
    /// qcow2 refcount entry width in bits (from the existing
    /// header). 0 if the image isn't qcow2.
    pub qcow2_refcount_bits: u8,
    /// vmdk subformat of the existing image: 0=MonolithicSparse,
    /// 1=StreamOptimized, 2=MonolithicFlat,
    /// 3=TwoGbMaxExtentSparse, 4=TwoGbMaxExtentFlat. 0 if not
    /// vmdk.
    pub vmdk_subformat: u8,
    /// vhd subformat of the existing image: 0=Dynamic, 1=Fixed.
    /// 0 if not vhd.
    pub vhd_subformat: u8,
    /// Reserved padding.
    pub _pad: u8,
    /// vmdk grain size in bytes (from the existing header). 0
    /// if not vmdk.
    pub vmdk_grain_size: u32,
    /// vhd/vhdx block size in bytes (from the existing header).
    /// 0 if not applicable.
    pub block_size: u32,

    /// Actual on-disk file size in bytes before resize. The host
    /// populates this from `stat()` after probing the target.
    /// The guest uses it for planning instead of deriving from
    /// the virtio device capacity (which is the host's capacity
    /// *hint*, not the actual file size).
    pub current_file_size: u64,

    /// Reserved padding for forward compatibility (zero-init).
    pub _reserved: [u8; 56],
}

impl ResizeConfig {
    /// Magic value for resize config.
    pub const MAGIC: u32 = 0x52455349; // "RESI"

    /// Flag: `--shrink` was passed by the user. Required for any
    /// resize where `new_virtual_size < current_virtual_size`,
    /// matching `qemu-img resize --shrink`.
    pub const FLAG_SHRINK: u32 = 1 << 0;
    /// Flag: the existing qcow2 image uses 16-byte extended L2
    /// entries.
    pub const FLAG_EXTENDED_L2: u32 = 1 << 1;
    /// Flag: quiet mode. Host-side only; the guest ignores this
    /// bit.
    pub const FLAG_QUIET: u32 = 1 << 2;

    /// Preallocation mode encoded in flags bits 4-5, exactly
    /// mirroring [`CreateConfig`] and [`MeasureConfig`].
    pub const PREALLOC_MASK: u32 = 0b11 << 4;
    pub const PREALLOC_OFF: u32 = 0 << 4;
    pub const PREALLOC_METADATA: u32 = 1 << 4;
    pub const PREALLOC_FALLOC: u32 = 2 << 4;
    pub const PREALLOC_FULL: u32 = 3 << 4;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Extract the preallocation mode from `flags`.
    pub fn preallocation(&self) -> u32 {
        self.flags & Self::PREALLOC_MASK
    }

    /// True if the user passed `--shrink`.
    pub fn allow_shrink(&self) -> bool {
        self.flags & Self::FLAG_SHRINK != 0
    }
}

/// Result structure for the resize operation.
///
/// Passed by the guest into `call_table.send_resize_result` (the
/// call-table field is added in phase 7).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResizeResult {
    /// Magic value (`0x52524553` = "RRES").
    pub magic: u32,
    /// Target format echoed back so the host can render the
    /// right output.
    pub target_format: u32,
    /// Resolved new virtual size in bytes (after the host
    /// translated any `+/-` relative input into an absolute
    /// value, and after the guest cross-checked).
    pub resolved_new_virtual_size: u64,
    /// File size before the host's post-pass `set_len` (the
    /// pre-resize EOF).
    pub file_size_before: u64,
    /// File size after the guest's last patch (but before the
    /// host post-pass).
    pub file_size_after: u64,
    /// Action taken. See `ACTION_*`.
    pub action: u32,
    /// Error code. See `ERROR_*`.
    pub error: u32,
}

impl ResizeResult {
    /// Magic value for resize result.
    pub const MAGIC: u32 = 0x52524553; // "RRES"

    /// Action: nothing changed (new == current).
    pub const ACTION_NOOP: u32 = 0;
    /// Action: file/virtual size grew.
    pub const ACTION_GROW: u32 = 1;
    /// Action: file/virtual size shrank.
    pub const ACTION_SHRINK: u32 = 2;

    // Error codes are stable: only appended, never reordered.
    // Existing operation binaries depend on the numeric values
    // matching what the host renders.
    pub const ERROR_OK: u32 = 0;
    pub const ERROR_INVALID_OPTION: u32 = 1;
    pub const ERROR_INVALID_NEW_SIZE: u32 = 2;
    pub const ERROR_SHRINK_WITHOUT_FLAG: u32 = 3;
    pub const ERROR_SHRINK_BELOW_ALLOCATED: u32 = 4;
    pub const ERROR_UNSUPPORTED_FORMAT: u32 = 5;
    pub const ERROR_UNSUPPORTED_SUBFORMAT: u32 = 6;
    pub const ERROR_UNSUPPORTED_SHRINK: u32 = 7;
    pub const ERROR_PREALLOCATION_UNSUPPORTED: u32 = 8;
    pub const ERROR_SCRATCH_TOO_SMALL: u32 = 9;
    pub const ERROR_READ_FAILED: u32 = 10;
    pub const ERROR_WRITE_FAILED: u32 = 11;
    pub const ERROR_PARSE_FAILED: u32 = 12;
    /// The image's staged metadata is internally inconsistent or
    /// disagrees with the host's pre-probe. Returned for: a
    /// host/guest `current_virtual_size` mismatch (race or host
    /// bug); a qcow2 file size that isn't a multiple of
    /// `cluster_size`; a qcow2 refcount-table entry the planner
    /// needs to update being zero; or vhd / vhdx / vmdk header
    /// fields that disagree with what the host pre-probed. See
    /// the `HeaderMismatch` variant in `crates/resize` for the
    /// authoritative breakdown.
    pub const ERROR_HEADER_MISMATCH: u32 = 13;
    /// The image carries persistent dirty bitmaps (qcow2 bitmaps
    /// autoclear bit set). resize refuses rather than silently
    /// discarding them (build_header would drop the extension).
    pub const ERROR_BITMAPS_UNSUPPORTED: u32 = 14;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Configuration structure for the rebase operation.
///
/// Written by the host at [`OPERATION_CONFIG_ADDR`] before the
/// guest is launched. The guest reads it via
/// `call_table.get_operation_config`.
///
/// The host attaches the old backing chain and the new backing
/// chain as input devices in a single contiguous range; the
/// `old_chain_*` / `new_chain_*` fields delimit which slot range
/// belongs to which chain. The overlay being rebased is the
/// output device, opened RW. In `-u` (unsafe) mode the guest
/// skips the chain comparison and only rewrites the overlay's
/// backing-file pointer; safe mode reads from both chains and
/// copies divergent clusters into the overlay before swapping
/// the pointer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RebaseConfig {
    /// Magic (`0x52454241` = "REBA").
    pub magic: u32,
    /// Overlay format (`ImageFormat as u32`).
    pub overlay_format: u32,
    /// New backing format (`ImageFormat as u32`); `0` means
    /// "auto-detect via the standard format-probe path".
    pub new_backing_format: u32,
    /// Flags. See `FLAG_*` constants.
    pub flags: u32,

    /// Sector size for I/O (matches host sector_size).
    pub sector_size: u32,
    /// qcow2 cluster size in bytes (from the overlay's existing
    /// header). 0 if the overlay isn't qcow2.
    pub overlay_cluster_size: u32,
    /// Overlay virtual size in bytes (from the existing header).
    pub overlay_virtual_size: u64,

    /// First input device slot belonging to the old chain.
    pub old_chain_first: u32,
    /// Number of input devices in the old chain
    /// (`old_chain_first .. old_chain_first + old_chain_count`).
    pub old_chain_count: u32,
    /// First input device slot belonging to the new chain.
    pub new_chain_first: u32,
    /// Number of input devices in the new chain
    /// (`new_chain_first .. new_chain_first + new_chain_count`).
    pub new_chain_count: u32,

    /// New backing-file path string the guest writes into the
    /// overlay's header. The first `new_backing_path_len` bytes
    /// are the path; the rest are zero-padding. A length of zero
    /// combined with [`FLAG_DETACH`] means the overlay becomes
    /// standalone.
    pub new_backing_path: [u8; 1024],
    /// Number of valid bytes in `new_backing_path`.
    pub new_backing_path_len: u32,

    /// Reserved padding for forward compatibility (zero-init).
    pub _reserved: [u8; 60],
}

impl RebaseConfig {
    /// Magic value for rebase config.
    pub const MAGIC: u32 = 0x52454241; // "REBA"

    /// Flag: `-u` unsafe / metadata-only mode. Guest rewrites
    /// only the backing-file pointer; no chain comparison or
    /// data copy.
    pub const FLAG_UNSAFE: u32 = 1 << 0;
    /// Flag: quiet mode. Host-side only; the guest ignores this
    /// bit.
    pub const FLAG_QUIET: u32 = 1 << 1;
    /// Flag: detach the overlay from its backing chain. Paired
    /// with `new_backing_path_len == 0`.
    pub const FLAG_DETACH: u32 = 1 << 2;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// True if the user passed `-u`.
    pub fn is_unsafe(&self) -> bool {
        self.flags & Self::FLAG_UNSAFE != 0
    }

    /// True if the rebase detaches the overlay.
    pub fn is_detach(&self) -> bool {
        self.flags & Self::FLAG_DETACH != 0
    }
}

/// Result structure for the rebase operation.
///
/// Passed by the guest into `call_table.send_rebase_result`
/// (added in phase 1 of `PLAN-rebase-commit`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RebaseResult {
    /// Magic value (`0x52425253` = "RBRS").
    pub magic: u32,
    /// Overlay format echoed back so the host can render the
    /// right output.
    pub overlay_format: u32,
    /// Mode taken. See `MODE_*`.
    pub mode: u32,
    /// Error code. See `ERROR_*`.
    pub error: u32,

    /// Number of clusters (overlay-cluster-size units) copied
    /// from the old chain into the overlay. Always zero in
    /// `-u` (unsafe) mode.
    pub clusters_copied: u64,
    /// Total bytes copied from the old chain into the overlay.
    /// Always zero in `-u` mode.
    pub bytes_copied: u64,

    /// Reserved padding for forward compatibility (zero-init).
    pub _reserved: [u8; 56],
}

impl RebaseResult {
    /// Magic value for rebase result.
    pub const MAGIC: u32 = 0x52425253; // "RBRS"

    /// Mode: `-u` unsafe / metadata-only mode.
    pub const MODE_UNSAFE: u32 = 0;
    /// Mode: safe / data-aware mode (default).
    pub const MODE_SAFE: u32 = 1;

    // Error codes are stable: only appended, never reordered.
    pub const ERROR_OK: u32 = 0;
    /// Overlay or new backing is not a format we accept for
    /// rebase (qcow2 v2/v3 and vmdk monolithicSparse only in
    /// v1).
    pub const ERROR_UNSUPPORTED_FORMAT: u32 = 1;
    /// New backing's virtual size is smaller than the overlay's,
    /// or its format is otherwise incompatible.
    pub const ERROR_NEW_BACKING_INCOMPATIBLE: u32 = 2;
    /// qcow2 with the external-data-file incompatible feature.
    /// Refused to match qemu-img.
    pub const ERROR_EXTERNAL_DATA_FILE: u32 = 3;
    /// Overlay or new backing is LUKS-wrapped. v1 of rebase
    /// refuses; a future plan can lift this.
    pub const ERROR_LUKS_UNSUPPORTED: u32 = 4;
    /// Old or new chain exceeds [`MAX_CHAIN_DEVICES`].
    pub const ERROR_CHAIN_DEPTH: u32 = 5;
    /// Overlay's header changed during the operation (defensive
    /// read-back check).
    pub const ERROR_HEADER_MISMATCH: u32 = 6;
    /// Overlay's metadata is internally inconsistent (e.g.
    /// `INCOMPAT_DIRTY` or `INCOMPAT_CORRUPT` set; cluster size
    /// of zero).
    pub const ERROR_OVERLAY_CORRUPT: u32 = 7;
    /// New backing path exceeds the format's cap (1024 bytes
    /// for qcow2; matches `CreateConfig`).
    pub const ERROR_BACKING_PATH_TOO_LONG: u32 = 8;
    /// Guest scratch buffer was too small for the requested
    /// layout. Indicates either an image larger than v1
    /// supports or a planner-side accounting bug.
    pub const ERROR_SCRATCH_TOO_SMALL: u32 = 9;
    /// Safe-mode allocator exhausted every existing refcount
    /// block (qcow2) or grain table (vmdk). v1 doesn't yet
    /// append new ones; the user can fall back to `-u` mode
    /// or `qemu-img rebase`.
    pub const ERROR_REFCOUNT_EXHAUSTED: u32 = 10;
    /// vmdk descriptor slot is too small to hold the rewrite.
    pub const ERROR_DESCRIPTOR_TOO_LARGE: u32 = 11;
    /// Format-specific parser (`QcowHeader::parse`,
    /// `Vmdk4HeaderFull::parse`) failed to interpret the
    /// staged header bytes.
    pub const ERROR_PARSE_FAILED: u32 = 12;
    /// Internal size or offset computation overflowed.
    /// Surfaces planner-side `Overflow` and guest-side
    /// arithmetic checks. Distinct from `ERROR_PARSE_FAILED`
    /// because the cause is a host or guest bug, not a
    /// malformed image.
    pub const ERROR_INTERNAL_OVERFLOW: u32 = 13;
    /// The overlay has internal snapshots (`nb_snapshots > 0`)
    /// and the rebase is safe-mode (no `-u`), including safe
    /// detach. Safe mode mutates snapshot-shared L2 tables in
    /// place and sets refcount=1 on clusters two L1 trees
    /// reference, so a later `qemu-img snapshot -d` frees live
    /// active-view data (GitHub issue #421). Refused as an
    /// interim phase-2 gate; the real fix (snapshot-aware COW)
    /// lands in phase 7 of `PLAN-qcow2-write-infrastructure`.
    /// `-u` metadata-only rebase never touches snapshot-shared
    /// clusters and stays allowed.
    pub const ERROR_OVERLAY_HAS_SNAPSHOTS: u32 = 14;
    /// The overlay uses qcow2 features the safe-mode rebase
    /// write envelope does not support: the extended-L2
    /// incompatible bit (16-byte L2 entries the walk would
    /// misread as 8-byte — previously silent corruption), the
    /// zstd compression-type bit, or any unknown incompatible
    /// bit (the spec requires refusal). Added by phase 5 of
    /// `PLAN-qcow2-write-infrastructure`
    /// (`qcow2_write::check_envelope` on the overlay header,
    /// pre-mutation). `-u` metadata-only rebase only rewrites
    /// header/path bytes and stays allowed.
    pub const ERROR_OVERLAY_UNSUPPORTED: u32 = 15;
    /// The overlay's metadata is inconsistent in a way the
    /// safe-mode write path cannot anchor a safe write on: a
    /// holed (non-contiguous) or malformed refcount table
    /// (previously a silent misallocation — the rebase sibling
    /// of GitHub issue #428), or a qcow2-write classification
    /// refusal (unknown L1/L2 entry bits, refcount
    /// inconsistencies, snapshot-shared clusters on an image
    /// claiming none). Refused before any image mutation where
    /// staging detects it. Added by phase 5 of
    /// `PLAN-qcow2-write-infrastructure`.
    pub const ERROR_OVERLAY_INCONSISTENT: u32 = 16;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Configuration structure for the amend operation.
///
/// Written by the host at [`OPERATION_CONFIG_ADDR`] before the
/// guest is launched (the same slot every other per-op config
/// uses); the guest reads it via `call_table.get_operation_config`.
/// amend reuses the existing `read_output_sector` /
/// `write_output_sector` primitives for its single-cluster header
/// rewrite, so no new address constant or device-I/O pointer is
/// introduced.
///
/// The host pre-probes the image's current header and passes a
/// summary (`current_version`, `current_refcount_bits`, the two
/// feature words, `virtual_size`) as a cross-check; the guest
/// re-parses the header and validates against these fields,
/// exactly as resize passes `current_virtual_size`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AmendConfig {
    /// Magic (`0x414D4E44` = "AMND").
    pub magic: u32,
    /// Target format (`ImageFormat as u32`); `Qcow2` in v1.
    pub target_format: u32,
    /// Flags. See `FLAG_*` constants.
    pub flags: u32,
    /// Sector size for I/O (matches host sector_size).
    pub sector_size: u32,

    /// qcow2 cluster size in bytes (the header-cluster span).
    pub cluster_size: u32,
    /// Current qcow2 version (2 or 3); host-probed cross-check.
    pub current_version: u32,
    /// Current refcount width in bits; host-probed cross-check.
    pub current_refcount_bits: u32,
    /// Padding to align the following `u64` fields.
    pub _pad: u32,

    /// Current incompatible feature word; host-probed cross-check.
    pub current_incompatible_features: u64,
    /// Current compatible feature word; host-probed cross-check.
    pub current_compatible_features: u64,
    /// Virtual size in bytes; host-probed cross-check.
    pub virtual_size: u64,

    /// Reserved padding for forward compatibility (zero-init).
    pub _reserved: [u8; 72],
}

impl AmendConfig {
    /// Magic value for amend config.
    pub const MAGIC: u32 = 0x414D4E44; // "AMND"

    /// Flag: quiet mode. Host-side only; the guest ignores this
    /// bit.
    pub const FLAG_QUIET: u32 = 1 << 0;
    /// Flag: the `compat=` option was given. When clear, the
    /// target version is left unchanged.
    pub const FLAG_SET_COMPAT: u32 = 1 << 1;
    /// Flag: target version is v3 (`1.1`) when set, v2 (`0.10`)
    /// when clear. Only meaningful when [`FLAG_SET_COMPAT`] is
    /// set.
    pub const FLAG_COMPAT_V3: u32 = 1 << 2;
    /// Flag: the `lazy_refcounts=` option was given. When clear,
    /// the lazy-refcounts state is left unchanged.
    pub const FLAG_SET_LAZY: u32 = 1 << 3;
    /// Flag: target lazy-refcounts state is on when set, off when
    /// clear. Only meaningful when [`FLAG_SET_LAZY`] is set.
    pub const FLAG_LAZY_ON: u32 = 1 << 4;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Result structure for the amend operation.
///
/// Passed by the guest into `call_table.send_amend_result`
/// (added in phase 1 of `PLAN-amend`). Carries the action taken,
/// the resulting version / lazy-refcounts state (so the host can
/// render the success line and phase-7 baselines can assert the
/// post-amend state without a second probe), and the error code.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AmendResult {
    /// Magic value (`0x414D5253` = "AMRS").
    pub magic: u32,
    /// Target format echoed back so the host can render the right
    /// output.
    pub target_format: u32,
    /// Action taken. See `ACTION_*`.
    pub action: u32,
    /// Error code. See `ERROR_*`.
    pub error: u32,

    /// qcow2 version (2 or 3) after the amend completes.
    pub resulting_version: u32,
    /// Lazy-refcounts state (0 / 1) after the amend completes.
    pub resulting_lazy_refcounts: u32,

    /// Reserved padding for forward compatibility (zero-init).
    pub _reserved: [u8; 40],
}

impl AmendResult {
    /// Magic value for amend result.
    pub const MAGIC: u32 = 0x414D5253; // "AMRS"

    /// Action: requested options already matched the header;
    /// nothing was rewritten.
    pub const ACTION_NOOP: u32 = 0;
    /// Action: the header was rewritten.
    pub const ACTION_AMENDED: u32 = 1;

    // Error codes are stable: only appended, never reordered.
    pub const ERROR_OK: u32 = 0;
    /// Input is not qcow2 (v1 is qcow2-only).
    pub const ERROR_UNSUPPORTED_FORMAT: u32 = 1;
    /// An unrecognised / unsupported `-o` key reached the guest
    /// (defence in depth; mostly rejected host-side in phase 4).
    pub const ERROR_INVALID_OPTION: u32 = 2;
    /// `compat=0.10` refused because a v3 incompatible feature is
    /// set (`DIRTY`, `CORRUPT`, `EXTERNAL_DATA`, `COMPRESSION`,
    /// `EXTENDED_L2`).
    pub const ERROR_DOWNGRADE_BLOCKED_FEATURE: u32 = 3;
    /// `compat=0.10` refused because `refcount_bits != 16` (v2
    /// supports 16-bit only; rewriting the refcount tree is out of
    /// v1 scope).
    pub const ERROR_DOWNGRADE_REFCOUNT_WIDTH: u32 = 4;
    /// `lazy_refcounts=on` requested against a v2 image, or while
    /// simultaneously downgrading to v2.
    pub const ERROR_LAZY_REQUIRES_V3: u32 = 5;
    /// The host-probed cross-check (version / features /
    /// refcount_bits / cluster_size) disagreed with the guest's
    /// re-read of the header (defensive, mirrors rebase).
    pub const ERROR_HEADER_MISMATCH: u32 = 6;
    /// `QcowHeader::parse` failed on the staged header.
    pub const ERROR_PARSE_FAILED: u32 = 7;
    /// `INCOMPAT_DIRTY` is set; refuse to amend an image another
    /// writer may hold open.
    pub const ERROR_DIRTY: u32 = 8;
    /// The image carries header extension(s) that a v2⇔v3
    /// transition would have to relocate, and v1 punts. Reserved
    /// in case phase 2 decides not to implement relocation.
    pub const ERROR_EXTENSION_RELOCATION_UNSUPPORTED: u32 = 9;
    /// A device write back to the header cluster failed.
    pub const ERROR_WRITE_FAILED: u32 = 10;
    /// Guest scratch buffer was too small for the requested
    /// layout.
    pub const ERROR_SCRATCH_TOO_SMALL: u32 = 11;
    /// Internal size or offset computation overflowed.
    pub const ERROR_INTERNAL_OVERFLOW: u32 = 12;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Maximum number of ordered actions carried in a single
/// `BitmapConfig` (e.g. `--add --disable`). Generous; real
/// `qemu-img bitmap` invocations use 1–3 actions. The host rejects
/// requests with more than this.
pub const MAX_BITMAP_ACTIONS: usize = 8;
/// Size of the target bitmap-name buffer. Holds a name of up to
/// 1023 bytes (the qemu limit); no trailing NUL is required
/// (`name_len` delimits the used prefix).
pub const BITMAP_NAME_BUF: usize = 1024;
/// Maximum number of `--merge` source bitmaps in a single
/// invocation. Real incremental-backup merges use 1–2 sources.
pub const MAX_MERGE_SOURCES: usize = 8;
/// Size of the concatenated merge-source name pool. Holds e.g. 8
/// short names or ~2 max-length names; the host rejects a total
/// source-name byte-count over this bound.
pub const MERGE_SOURCE_POOL: usize = 2048;

/// Configuration structure for the bitmap operation.
///
/// Written by the host at [`OPERATION_CONFIG_ADDR`] before the
/// guest is launched. The guest reads it via
/// `call_table.get_operation_config`.
///
/// Unlike single-mode operations, `qemu-img bitmap` applies an
/// **ordered, repeatable list of actions** in one invocation (e.g.
/// `--add --disable`), so the config carries an action *list*
/// (`num_actions` + [`actions`](BitmapConfig::actions)) rather than
/// a single mode. There is one positional target **name** (shared
/// by every action); each `ACTION_MERGE` consumes the next entry,
/// in order, from a length-delimited **merge-source pool**.
///
/// The host pre-probes the image header and bitmaps extension and
/// passes a cross-check (the feature words, `virtual_size`,
/// version / refcount width, cluster size, the bitmap-directory
/// location and count); the guest re-parses these itself and
/// validates against them, exactly as resize/amend do, emitting
/// [`ERROR_HEADER_MISMATCH`](BitmapResult::ERROR_HEADER_MISMATCH)
/// on disagreement. `bitmap` reuses the existing
/// `read_output_sector` / `write_output_sector` primitives, so no
/// new address constant or device-I/O pointer is introduced.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BitmapConfig {
    /// Magic (`0x424D5043` = "BMPC").
    pub magic: u32,
    /// Target format (`ImageFormat as u32`); `Qcow2` in v1.
    pub target_format: u32,
    /// Flags. See `FLAG_*` constants.
    pub flags: u32,
    /// Sector size for I/O (matches host sector_size).
    pub sector_size: u32,

    /// Number of populated entries in `actions` (1..=MAX_BITMAP_ACTIONS).
    pub num_actions: u32,
    /// Target bitmap name length in bytes (1..=1023).
    pub name_len: u32,
    /// Number of populated merge sources (0..=MAX_MERGE_SOURCES).
    pub num_merge_sources: u32,
    /// Padding to align the following `u64` fields.
    pub _pad0: u32,

    /// `--add` granularity in bytes; `0` = format default.
    pub granularity: u64,
    /// Current autoclear feature word; host-probed cross-check.
    pub current_autoclear_features: u64,
    /// Current incompatible feature word; host-probed cross-check.
    pub current_incompatible_features: u64,
    /// Virtual size in bytes; host-probed cross-check.
    pub virtual_size: u64,
    /// Byte offset of the bitmap directory; `0` if there is no
    /// bitmaps extension yet. Host-probed cross-check.
    pub bitmap_directory_offset: u64,
    /// Byte size of the bitmap directory. Host-probed cross-check.
    pub bitmap_directory_size: u64,

    /// Current qcow2 version (2 or 3); host-probed cross-check.
    pub current_version: u32,
    /// Current refcount width in bits; host-probed cross-check.
    pub current_refcount_bits: u32,
    /// qcow2 cluster size in bytes; host-probed cross-check.
    pub cluster_size: u32,
    /// Existing bitmap count (`0` if none); host-probed cross-check.
    pub nb_bitmaps: u32,

    /// Action opcodes, in CLI order. See `ACTION_*`. Entries at and
    /// beyond `num_actions` are `0`.
    pub actions: [u8; MAX_BITMAP_ACTIONS],
    /// Padding to align the name / pool region.
    pub _pad1: [u8; 8],

    /// Target bitmap name (UTF-8, no NUL); `name_len` bytes used.
    pub name: [u8; BITMAP_NAME_BUF],
    /// Byte lengths of each merge source, in order.
    pub merge_source_lens: [u16; MAX_MERGE_SOURCES],
    /// Concatenated merge-source names, delimited by
    /// `merge_source_lens`.
    pub merge_source_pool: [u8; MERGE_SOURCE_POOL],

    /// Reserved padding for forward compatibility (zero-init);
    /// pads the total to a round 3584 bytes.
    pub _reserved: [u8; 384],
}

impl BitmapConfig {
    /// Magic value for bitmap config.
    pub const MAGIC: u32 = 0x424D_5043; // "BMPC"

    /// Action: create a new bitmap (`--add`).
    pub const ACTION_ADD: u8 = 1;
    /// Action: delete a bitmap (`--remove`).
    pub const ACTION_REMOVE: u8 = 2;
    /// Action: clear a bitmap's contents (`--clear`).
    pub const ACTION_CLEAR: u8 = 3;
    /// Action: enable recording into a bitmap (`--enable`).
    pub const ACTION_ENABLE: u8 = 4;
    /// Action: disable recording into a bitmap (`--disable`).
    pub const ACTION_DISABLE: u8 = 5;
    /// Action: merge source bitmap(s) into the target (`--merge`).
    pub const ACTION_MERGE: u8 = 6;

    /// Flag: quiet mode. Host-side only; the guest ignores this bit
    /// (success is silent regardless, matching qemu).
    pub const FLAG_QUIET: u32 = 1 << 0;
    /// Flag: verbose mode. Mirrors the other configs' verbose bit.
    pub const FLAG_VERBOSE: u32 = 1 << 31;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Compile-time guard: `BitmapConfig` must fit the operation-config
/// region (see [`OPERATION_CONFIG_MAX_SIZE`]).
const _: () = assert!(core::mem::size_of::<BitmapConfig>() <= OPERATION_CONFIG_MAX_SIZE);

/// Result structure for the bitmap operation.
///
/// Passed by the guest into `call_table.send_bitmap_result`. Carries
/// the last applied opcode, how many actions succeeded, and the
/// resulting bitmap count (so the host can render a summary and
/// baselines can assert post-op state without a second probe), plus
/// the error code. `qemu-img bitmap` produces no list output and is
/// silent on success, so there is no per-entry streaming message.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BitmapResult {
    /// Magic value (`0x424D5253` = "BMRS").
    pub magic: u32,
    /// Target format echoed back so the host can render the right
    /// output.
    pub target_format: u32,
    /// Error code. See `ERROR_*`.
    pub error: u32,
    /// Last applied action opcode (`0` if none). See
    /// [`BitmapConfig`]'s `ACTION_*`.
    pub action: u32,

    /// How many actions succeeded before an error or the end.
    pub actions_applied: u32,
    /// Bitmap count after the operation completed.
    pub resulting_nb_bitmaps: u32,

    /// Reserved padding for forward compatibility (zero-init);
    /// pads the total to 64 bytes.
    pub _reserved: [u8; 40],
}

impl BitmapResult {
    /// Magic value for bitmap result.
    pub const MAGIC: u32 = 0x424D_5253; // "BMRS"

    // Error codes are stable: only appended, never reordered.
    /// Success.
    pub const ERROR_OK: u32 = 0;
    /// Input is not qcow2 (v1 is qcow2-only).
    pub const ERROR_UNSUPPORTED_FORMAT: u32 = 1;
    /// qcow2 v2 cannot store dirty bitmaps.
    pub const ERROR_UNSUPPORTED_VERSION: u32 = 2;
    /// `QcowHeader::parse` failed.
    pub const ERROR_PARSE_FAILED: u32 = 3;
    /// The host-probed cross-check disagreed with the guest's
    /// re-read of the header (defensive, mirrors rebase/amend).
    pub const ERROR_HEADER_MISMATCH: u32 = 4;
    /// A remove/clear/enable/disable/merge named a bitmap that does
    /// not exist.
    pub const ERROR_BITMAP_NOT_FOUND: u32 = 5;
    /// `--add` with an already-existing name.
    pub const ERROR_BITMAP_EXISTS: u32 = 6;
    /// An `in_use`/inconsistent bitmap was targeted by an action
    /// other than `--remove` (only remove is allowed; no `--force`).
    pub const ERROR_BITMAP_IN_USE: u32 = 7;
    /// Name longer than 1023 bytes.
    pub const ERROR_NAME_TOO_LONG: u32 = 8;
    /// Granularity bits outside `9..=31`.
    pub const ERROR_GRANULARITY_RANGE: u32 = 9;
    /// Would exceed 65535 bitmaps.
    pub const ERROR_TOO_MANY_BITMAPS: u32 = 10;
    /// Cluster allocation failed / bitmap too large for the
    /// granularity.
    pub const ERROR_NO_SPACE: u32 = 11;
    /// A device write back to the image failed.
    pub const ERROR_WRITE_FAILED: u32 = 12;
    /// A device read from the image failed.
    pub const ERROR_READ_FAILED: u32 = 13;
    /// Guest scratch buffer was too small for the requested layout.
    pub const ERROR_SCRATCH_TOO_SMALL: u32 = 14;
    /// Internal size or offset computation overflowed.
    pub const ERROR_INTERNAL_OVERFLOW: u32 = 15;
    /// A `--merge` source bitmap does not exist.
    pub const ERROR_MERGE_SOURCE_NOT_FOUND: u32 = 16;
    /// Reserved for a deferred action path (e.g. cross-file
    /// `--merge -b`, or an action the planner does not yet
    /// implement). Kept reserved even if unused at freeze time.
    pub const ERROR_UNSUPPORTED_ACTION: u32 = 17;
    /// qcow2 refcount width != 16; v1 reuses the 16-bit-only
    /// allocator and refuses other widths.
    pub const ERROR_UNSUPPORTED_REFCOUNT_WIDTH: u32 = 18;
    /// A `--merge` was requested between two bitmaps whose geometry
    /// is incompatible (unequal granularity, hence unequal bit-count
    /// / bitmap-table size). qemu requires equal granularity to
    /// merge; v1 refuses rather than resampling.
    pub const ERROR_INCOMPATIBLE_MERGE: u32 = 19;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Configuration structure for the bench operation.
///
/// Passed by the host into the guest's operation-config region and
/// cast by the bench guest op (phase 3). Unlike [`BitmapConfig`],
/// bench carries **pure CLI parameters — deliberately no host-probed
/// image cross-checks**: bench runs on all five input formats and the
/// guest derives `image_size` from its own format parse, so there is
/// nothing the host can probe without host-side parsing that the
/// security model exists to avoid.
///
/// Field additions discovered in later phases must go into
/// `_reserved`, never reorder existing fields (the host writes the
/// struct field-by-field at explicit byte offsets in phase 4).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BenchConfig {
    /// Magic (`0x424E4348` = "BNCH").
    pub magic: u32,
    /// Flags. See `FLAG_*`.
    pub flags: u32,
    /// Number of requests (1..=0x7fffffff, validated host-side).
    pub count: u32,
    /// Requested queue depth. Echoed in the header line and JSON
    /// only; the guest ignores it — v1 execution is serial
    /// (master plan Open question 1).
    pub depth: u32,

    /// Bytes per request (1..=BENCH_MAX_BUFSIZE).
    pub bufsize: u64,
    /// Raw step; `0` means "= bufsize" (`crates/bench`
    /// `effective_step()` — the guest resolves it, keeping the
    /// wrap arithmetic in one place).
    pub step: u64,
    /// Initial offset, raw and unwrapped (first request uses it
    /// as-is, matching qemu).
    pub offset: u64,

    /// Flush every N completions; `0` = never. Nonzero only with
    /// FLAG_WRITE (validated host-side).
    pub flush_interval: u32,
    /// Write-pattern byte in the low 8 bits.
    pub pattern: u32,
    /// Input format hint (`ImageFormat as u32`); the guest
    /// verifies against its own parse.
    pub target_format: u32,
    /// Sector size for I/O (matches host sector_size).
    pub sector_size: u32,

    /// Reserved padding for forward compatibility (zero-init);
    /// pads the total to a round 128 bytes.
    pub _reserved: [u8; 72],
}

impl BenchConfig {
    /// Magic value for bench config.
    pub const MAGIC: u32 = 0x424E_4348; // "BNCH"

    /// Flag: write test (`-w`). When clear, bench reads.
    pub const FLAG_WRITE: u32 = 1 << 0;
    /// Flag: skip the terminal drain/flush (`--no-drain`).
    pub const FLAG_NO_DRAIN: u32 = 1 << 1;
    /// Flag: verbose mode. Mirrors the other configs' verbose bit.
    pub const FLAG_VERBOSE: u32 = 1 << 31;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Compile-time guard: `BenchConfig` must fit the operation-config
/// region (see [`OPERATION_CONFIG_MAX_SIZE`]).
const _: () = assert!(core::mem::size_of::<BenchConfig>() <= OPERATION_CONFIG_MAX_SIZE);

/// Result structure for the bench operation.
///
/// Passed by the guest into `call_table.send_bench_result`. Mirrors
/// [`BitmapResult`]: numeric-only, the host renders any human-readable
/// summary from these codes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BenchResult {
    /// Magic (`0x424E5253` = "BNRS").
    pub magic: u32,
    /// Error code. See `ERROR_*`.
    pub error: u32,

    /// Requests fully completed (== count on success; the count
    /// reached when a mid-run request failed otherwise).
    pub requests_completed: u64,
    /// Flushes issued (`crates/bench` `total_flushes()` on
    /// success).
    pub flushes_issued: u64,
    /// Error detail: the byte offset of the failing request for
    /// the I/O errors, else 0.
    pub error_detail: u64,

    /// Reserved padding for forward compatibility (zero-init);
    /// pads the total to 64 bytes.
    pub _reserved: [u8; 32],
}

impl BenchResult {
    /// Magic value for bench result.
    pub const MAGIC: u32 = 0x424E_5253; // "BNRS"

    // Error codes are stable: only appended, never reordered.
    /// Success.
    pub const ERROR_OK: u32 = 0;
    /// Magic/flag validation failed in the guest.
    pub const ERROR_BAD_CONFIG: u32 = 1;
    /// Input format is not supported by bench.
    pub const ERROR_UNSUPPORTED_FORMAT: u32 = 2;
    /// The guest's format parse failed.
    pub const ERROR_PARSE_FAILED: u32 = 3;
    /// A device read from the image failed.
    pub const ERROR_IO_READ: u32 = 4;
    /// A device write back to the image failed.
    pub const ERROR_IO_WRITE: u32 = 5;
    /// A flush (`fsync_input`) of the image failed.
    pub const ERROR_IO_FLUSH: u32 = 6;
    /// A write test was requested against an image the guest cannot
    /// write. `error_detail` carries a small, stable gate-id enum
    /// identifying which envelope check refused the image. The host
    /// (`map_bench_error`) renders each id as a short reason:
    ///
    /// - `0` — the format itself has no write support yet (phase 5a:
    ///   a non-{raw,qcow2} family reaching the guest under `-w`).
    /// - `1` — qcow2 `refcount_bits != 16` (only 16-bit is supported).
    /// - `2` — qcow2 compression feature set, or an unknown
    ///   incompatible-features bit beyond the ones bench recognises
    ///   (also raised mid-run if a compressed L2 entry is hit).
    /// - `3` — qcow2 extended-L2 (subcluster) feature.
    /// - `4` — qcow2 external data file.
    /// - `5` — qcow2 LUKS / encryption.
    /// - `6` — qcow2 dirty / corrupt incompatible bits.
    /// - `7` — qcow2 has internal snapshots (`nb_snapshots > 0`);
    ///   bench overwrites in place and must not corrupt shared
    ///   clusters. Also used mid-run if an allocated cluster is found
    ///   without `OFLAG_COPIED` (a snapshot-shared cluster).
    ///
    /// The bench guest op mirrors these ids in its `wgate` const block;
    /// the two lists must stay in sync.
    pub const ERROR_WRITE_UNSUPPORTED: u32 = 7;
    /// A qcow2 allocating write could not obtain a free cluster because
    /// the refcount table is full and v1 never grows it (the host
    /// renders "image too large for in-place bench write"). Unused until
    /// the 5b allocating-write path exists.
    pub const ERROR_ALLOC_EXHAUSTED: u32 = 8;
    /// The qcow2 write planner (`crates/qcow2-write`) refused a cluster
    /// as internally inconsistent: an unknown L1/L2 entry bit pattern
    /// (including the v3 all-zeroes flag — issue #432 territory), a
    /// staged-refcount inconsistency, missing refcount coverage, a
    /// staging mismatch, or a defensive backing-fill refusal after the
    /// op's copy-on-write resubmit. Appended by phase 6 step 6b
    /// (`PLAN-qcow2-write-infrastructure-phase-06-bench.md`, decision 6)
    /// for the crate classification refusals bench had no prior
    /// rendering for. The host renders "image metadata is inconsistent".
    pub const ERROR_IMAGE_INCONSISTENT: u32 = 9;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Configuration structure for the commit operation.
///
/// Written by the host at [`OPERATION_CONFIG_ADDR`] before the
/// guest is launched. The guest reads it via
/// `call_table.get_operation_config`.
///
/// The overlay is attached as input device slot 0, opened RW
/// (the guest uses `write_input_sector(0, ...)` for the
/// overlay-clear pass). The backing being committed into is the
/// output device. Slots `backing_chain_first ..
/// backing_chain_first + backing_chain_count` carry the
/// backing's own ancestor chain, if any.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommitConfig {
    /// Magic (`0x434F4D4D` = "COMM").
    pub magic: u32,
    /// Overlay format (`ImageFormat as u32`).
    pub overlay_format: u32,
    /// Backing format (`ImageFormat as u32`).
    pub backing_format: u32,
    /// Flags. See `FLAG_*` constants.
    pub flags: u32,

    /// Sector size for I/O (matches host sector_size).
    pub sector_size: u32,
    /// qcow2 cluster size of the overlay (from its existing
    /// header). 0 if the overlay isn't qcow2.
    pub overlay_cluster_size: u32,
    /// qcow2 cluster size of the backing (from its existing
    /// header). 0 if the backing isn't qcow2.
    pub backing_cluster_size: u32,
    /// Reserved padding.
    pub _pad: u32,

    /// Overlay virtual size in bytes (from the existing header).
    pub overlay_virtual_size: u64,
    /// Backing virtual size in bytes (from the existing header).
    pub backing_virtual_size: u64,

    /// First input device slot belonging to the backing's own
    /// ancestor chain (typically slot 1, immediately after the
    /// overlay at slot 0).
    pub backing_chain_first: u32,
    /// Number of input devices in the backing's ancestor chain.
    /// 0 if the backing has no parents of its own.
    pub backing_chain_count: u32,

    /// Reserved padding for forward compatibility (zero-init).
    pub _reserved: [u8; 64],
}

impl CommitConfig {
    /// Magic value for commit config.
    pub const MAGIC: u32 = 0x434F4D4D; // "COMM"

    /// Flag: quiet mode. Host-side only; the guest ignores this
    /// bit.
    pub const FLAG_QUIET: u32 = 1 << 0;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

/// Result structure for the commit operation.
///
/// Passed by the guest into `call_table.send_commit_result`
/// (added in phase 1 of `PLAN-rebase-commit`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommitResult {
    /// Magic value (`0x434F5253` = "CORS").
    pub magic: u32,
    /// Overlay format echoed back so the host can render the
    /// right output.
    pub overlay_format: u32,
    /// Backing format echoed back so the host can render the
    /// right output.
    pub backing_format: u32,
    /// Error code. See `ERROR_*`.
    pub error: u32,

    /// Number of overlay clusters (overlay-cluster-size units)
    /// whose data was written into the backing.
    pub clusters_committed: u64,
    /// Total bytes written into the backing.
    pub bytes_committed: u64,
    /// Number of overlay L2 entries cleared as part of the
    /// overlay-clear pass.
    pub overlay_clusters_cleared: u64,

    /// Reserved padding for forward compatibility (zero-init).
    pub _reserved: [u8; 56],
}

impl CommitResult {
    /// Magic value for commit result.
    pub const MAGIC: u32 = 0x434F5253; // "CORS"

    // Error codes are stable: only appended, never reordered.
    pub const ERROR_OK: u32 = 0;
    /// Overlay or backing is not a format we accept for commit
    /// (qcow2 v2/v3 and vmdk monolithicSparse only in v1).
    pub const ERROR_UNSUPPORTED_FORMAT: u32 = 1;
    /// Overlay has no backing reference.
    pub const ERROR_NO_BACKING: u32 = 2;
    /// qcow2 with the external-data-file incompatible feature.
    /// Refused to match qemu-img.
    pub const ERROR_EXTERNAL_DATA_FILE: u32 = 3;
    /// Overlay or backing is LUKS-wrapped. v1 of commit
    /// refuses; a future plan can lift this.
    pub const ERROR_LUKS_UNSUPPORTED: u32 = 4;
    /// Backing's virtual size is smaller than the highest
    /// cluster the overlay has allocated.
    pub const ERROR_BACKING_TOO_SMALL: u32 = 5;
    /// Overlay's virtual size exceeds the backing's. Commit
    /// refuses.
    pub const ERROR_OVERLAY_LARGER_THAN_BACKING: u32 = 6;
    /// Overlay's or backing's header changed during the
    /// operation (defensive read-back check).
    pub const ERROR_HEADER_MISMATCH: u32 = 7;
    /// Overlay's metadata is internally inconsistent (e.g.
    /// `INCOMPAT_DIRTY` or `INCOMPAT_CORRUPT` set; cluster size
    /// of zero). Distinct from [`Self::ERROR_HEADER_MISMATCH`]
    /// because the host can render which file is at fault.
    pub const ERROR_OVERLAY_CORRUPT: u32 = 8;
    /// Backing's metadata is internally inconsistent.
    pub const ERROR_BACKING_CORRUPT: u32 = 9;
    /// Guest scratch buffer was too small for the requested
    /// layout. Indicates either an image larger than v1
    /// supports or a planner-side accounting bug.
    pub const ERROR_SCRATCH_TOO_SMALL: u32 = 10;
    /// Backing allocator exhausted every existing refcount
    /// block (qcow2) or grain table (vmdk). v1 doesn't yet
    /// append new ones; the user can fall back to
    /// `qemu-img commit` or run `qemu-img check -r` on the
    /// backing to reclaim leaked clusters.
    pub const ERROR_REFCOUNT_EXHAUSTED: u32 = 11;
    /// Format-specific parser (`QcowHeader::parse`,
    /// `Vmdk4HeaderFull::parse`) failed to interpret the
    /// staged header bytes.
    pub const ERROR_PARSE_FAILED: u32 = 12;
    /// Internal size or offset computation overflowed.
    /// Surfaces planner-side `Overflow` and guest-side
    /// arithmetic checks. Distinct from
    /// [`Self::ERROR_PARSE_FAILED`] because the cause is a
    /// host or guest bug, not a malformed image.
    pub const ERROR_INTERNAL_OVERFLOW: u32 = 13;
    /// The backing file has internal snapshots
    /// (`nb_snapshots > 0`). v1 commit writes into the backing
    /// without COWing snapshot-shared clusters or L2 tables, so
    /// proceeding would silently corrupt the snapshots (GitHub
    /// issue #420). Refused as an interim phase-2 gate; the
    /// real fix (COW into the backing) lands in phase 7 of
    /// `PLAN-qcow2-write-infrastructure`.
    pub const ERROR_BACKING_HAS_SNAPSHOTS: u32 = 14;
    /// The overlay has internal snapshots (`nb_snapshots > 0`).
    /// The post-commit overlay-clear pass zeroes active L2
    /// entries and decrements the data clusters they reference
    /// without accounting for the snapshot's reference, leaving
    /// snapshot-shared clusters at `refcount=0 reference=1`
    /// (proven by the phase-2 step-2a parity test; qemu-img
    /// stays check-clean on the same shape). This is the
    /// overlay-side sibling of issue #420 (issue #423).
    /// Refused as an interim phase-2 gate; the real fix
    /// (snapshot-aware refcounting) lands in phase 7 of
    /// `PLAN-qcow2-write-infrastructure`.
    pub const ERROR_OVERLAY_HAS_SNAPSHOTS: u32 = 15;
    /// The backing file's header carries feature bits the
    /// commit write envelope does not support: the zstd
    /// compression-type bit or any unknown incompatible bit
    /// (`qcow2_write::Gate::UnknownIncompatible`). The qcow2
    /// spec requires refusing unknown incompatible bits; commit
    /// previously proceeded in violation of the spec (phase-4
    /// divergence D1 of
    /// `PLAN-qcow2-write-infrastructure-phase-04-commit`).
    /// Refused before any staging or mutation.
    pub const ERROR_BACKING_UNSUPPORTED: u32 = 16;
    /// The backing file's metadata is inconsistent as a write
    /// substrate: a sparse (non-contiguous) refcount table,
    /// reserved bits in refcount-table/L1/L2 entries,
    /// snapshot-shared or refcount-zero clusters on an image
    /// whose header says `nb_snapshots == 0`, or refcounts
    /// outside the staged refblock set (phase-4 divergences
    /// D3/D4). Staging-time refusals (the sparse-RT gate — a
    /// live corruption before phase 4) leave the backing
    /// byte-untouched; mid-loop classification refusals leave
    /// previously committed cluster data in place, the same
    /// posture as [`Self::ERROR_REFCOUNT_EXHAUSTED`].
    pub const ERROR_BACKING_INCONSISTENT: u32 = 17;

    /// True if magic matches.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

// ============================================================================
// Chain configuration structures (for multi-device/backing chain operations)
// ============================================================================

/// Maximum number of devices in a backing chain.
pub const MAX_CHAIN_DEVICES: usize = 16;

/// Information about a single device in the backing chain.
///
/// This structure provides metadata about each image in the chain,
/// allowing operations to understand the format and capabilities of
/// each device without parsing image headers.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ChainDeviceInfo {
    /// Detected format (ImageFormat as u32)
    pub format: u32,

    /// Feature flags from the info operation
    pub flags: u32,

    /// Virtual size in bytes
    pub virtual_size: u64,

    /// Actual/disk size in bytes
    pub actual_size: u64,

    /// Cluster size in bytes (0 for raw images)
    pub cluster_size: u32,

    /// Device index holding this device's cluster data.
    /// 0 = data is in this device itself (normal case).
    /// Non-zero = device index of the external data file.
    /// Used for QCOW2 images with external data files where
    /// metadata (L1/L2/refcounts) and cluster data are separate.
    pub data_device_idx: u32,
}

impl ChainDeviceInfo {
    /// Create a new empty device info
    pub const fn new() -> Self {
        Self {
            format: 0,
            flags: 0,
            virtual_size: 0,
            actual_size: 0,
            cluster_size: 0,
            data_device_idx: 0,
        }
    }

    /// Get the detected format
    pub fn detected_format(&self) -> ImageFormat {
        ImageFormat::from_u32(self.format)
    }

    /// Check if this device has a backing file
    pub fn has_backing_file(&self) -> bool {
        (self.flags & InfoResult::FLAG_HAS_BACKING_FILE) != 0
    }

    /// Check if this device is encrypted
    pub fn is_encrypted(&self) -> bool {
        (self.flags & InfoResult::FLAG_ENCRYPTED) != 0
    }

    /// Check if this device has compressed clusters
    pub fn is_compressed(&self) -> bool {
        (self.flags & InfoResult::FLAG_COMPRESSED) != 0
    }

    /// Check if this device has an external data file on another device.
    /// When true, standard cluster reads should go to `data_device_idx`
    /// instead of this device.
    pub fn has_external_data_device(&self) -> bool {
        self.data_device_idx != 0
    }
}

/// Configuration for backing chain operations.
///
/// This structure is written to CHAIN_CONFIG_ADDR by the VMM when
/// an operation involves a backing chain. It provides metadata about
/// all devices in the chain, allowing operations to understand the
/// chain structure without parsing image headers.
///
/// Device indices match the call table device indices:
/// - Device 0: top/primary image
/// - Devices 1..N-1: backing files in order (closer to base = higher index)
///
/// # Size and ConfigResult.len
///
/// The actual struct size is 528 bytes, but `CHAIN_CONFIG_MAX_SIZE` is 1024
/// to allow room for future growth. Guest code should use `device_count`
/// to determine how many device entries are valid, not `ConfigResult.len`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChainConfig {
    /// Magic number to verify config is valid (0x4348414E = "CHAN")
    pub magic: u32,

    /// Number of devices in the chain (1 = no backing files)
    pub device_count: u32,

    /// Structure version for future extensibility (currently 1)
    pub version: u32,

    /// Reserved for future use (flags, etc.)
    pub _reserved: u32,

    /// Device information array (only first device_count entries are valid)
    pub devices: [ChainDeviceInfo; MAX_CHAIN_DEVICES],
}

impl ChainConfig {
    /// Magic value for chain config
    pub const MAGIC: u32 = 0x4348414E; // "CHAN"

    /// Current structure version (2 = data_device_idx field)
    pub const VERSION: u32 = 2;

    /// Create a new empty chain config
    pub const fn new() -> Self {
        Self {
            magic: Self::MAGIC,
            device_count: 0,
            version: Self::VERSION,
            _reserved: 0,
            devices: [ChainDeviceInfo::new(); MAX_CHAIN_DEVICES],
        }
    }

    /// Check if config is valid (correct magic and has at least one device)
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.device_count > 0
    }

    /// Get the number of devices in the chain
    pub fn len(&self) -> usize {
        self.device_count as usize
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.device_count == 0
    }

    /// Get device info by index
    pub fn get(&self, index: usize) -> Option<&ChainDeviceInfo> {
        if index < self.device_count as usize {
            Some(&self.devices[index])
        } else {
            None
        }
    }

    /// Check if this is a simple single-image operation (no backing chain)
    pub fn is_single_image(&self) -> bool {
        self.device_count == 1
    }

    /// Get the top (primary) image info
    pub fn top(&self) -> Option<&ChainDeviceInfo> {
        self.get(0)
    }

    /// Get the base image info (last in chain)
    pub fn base(&self) -> Option<&ChainDeviceInfo> {
        if self.device_count > 0 {
            self.get(self.device_count as usize - 1)
        } else {
            None
        }
    }
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Shared operation utilities
// ============================================================================

/// Validate the call table magic and version, printing an error and returning
/// 0 from the calling function if validation fails.
///
/// Usage: `validate_call_table!(call_table, "convert");`
#[macro_export]
macro_rules! validate_call_table {
    ($ct:expr, $name:literal) => {
        if $ct.magic != CallTable::MAGIC {
            ($ct.debug_print)(concat!($name, ": bad magic\n\0").as_ptr());
            return 0;
        }
        if $ct.version != CallTable::VERSION {
            ($ct.debug_print)(concat!($name, ": bad version\n\0").as_ptr());
            return 0;
        }
    };
}

/// Verify all input devices have the same sector size.
///
/// Returns `Some(sector_size)` if all devices agree, or `None` if there
/// is a mismatch. Caller is responsible for error reporting.
///
/// # Safety
///
/// Caller must ensure `call_table` points to a valid, initialized
/// `CallTable` and that `device_count` does not exceed the number of
/// attached input devices.
pub unsafe fn verify_sector_sizes(call_table: &CallTable, device_count: usize) -> Option<usize> {
    let sector_size = (call_table.get_input_sector_size)(0);
    for dev_idx in 1..device_count {
        let dev_ss = (call_table.get_input_sector_size)(dev_idx as u32);
        if dev_ss != sector_size {
            return None;
        }
    }
    Some(sector_size)
}

/// Operation entry point signature.
///
/// Operations must export a function with this signature at the start
/// of their binary. The core calls this after setting up the call table.
///
/// Returns: bytes processed (used for completion message)
pub type OperationEntry = unsafe extern "C" fn() -> u64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measure_config_magic_uniqueness() {
        assert_ne!(MeasureConfig::MAGIC, InfoConfig::MAGIC);
        assert_ne!(MeasureConfig::MAGIC, CopyConfig::MAGIC);
        assert_ne!(MeasureConfig::MAGIC, CheckConfig::MAGIC);
        assert_ne!(MeasureConfig::MAGIC, CompareConfig::MAGIC);
        assert_ne!(MeasureConfig::MAGIC, ConvertConfig::MAGIC);
        assert_ne!(MeasureConfig::MAGIC, MeasureResult::MAGIC);
    }

    #[test]
    fn measure_result_magic_uniqueness() {
        assert_ne!(MeasureResult::MAGIC, InfoResult::MAGIC);
        assert_ne!(MeasureResult::MAGIC, CheckResult::MAGIC);
        assert_ne!(MeasureResult::MAGIC, CompareResult::MAGIC);
    }

    #[test]
    fn measure_config_is_valid() {
        let mut cfg = MeasureConfig {
            magic: MeasureConfig::MAGIC,
            target_format: 0,
            flags: 0,
            sector_size: 0,
            virtual_size_override: 0,
            qcow2_cluster_size: 0,
            qcow2_refcount_bits: 0,
            vmdk_subformat: 0,
            _pad2: 0,
            vmdk_grain_size: 0,
            vhd_subformat: 0,
            _pad3: [0; 3],
            block_size: 0,
            _pad4: 0,
            luks_header_overhead: 0,
        };
        assert!(cfg.is_valid());
        cfg.magic = 0;
        assert!(!cfg.is_valid());
    }

    #[test]
    fn create_config_magic_uniqueness() {
        assert_ne!(CreateConfig::MAGIC, InfoConfig::MAGIC);
        assert_ne!(CreateConfig::MAGIC, CopyConfig::MAGIC);
        assert_ne!(CreateConfig::MAGIC, CheckConfig::MAGIC);
        assert_ne!(CreateConfig::MAGIC, CompareConfig::MAGIC);
        assert_ne!(CreateConfig::MAGIC, ConvertConfig::MAGIC);
        assert_ne!(CreateConfig::MAGIC, MeasureConfig::MAGIC);
        assert_ne!(CreateConfig::MAGIC, CreateResult::MAGIC);
    }

    #[test]
    fn create_config_layout_matches_host_writes() {
        // The host in src/vmm/src/main.rs::run_create_guest writes
        // CreateConfig fields at hardcoded byte offsets via
        // guest_mem.write_obj. The guest reads the struct via a
        // typed reference cast over OPERATION_CONFIG_ADDR, which
        // relies on the #[repr(C)] layout matching those offsets
        // exactly. This test catches any silent padding shift from
        // a future field reorder. PR #298 review item #7.
        use core::mem::offset_of;
        assert_eq!(offset_of!(CreateConfig, magic), 0);
        assert_eq!(offset_of!(CreateConfig, target_format), 4);
        assert_eq!(offset_of!(CreateConfig, flags), 8);
        assert_eq!(offset_of!(CreateConfig, sector_size), 12);
        assert_eq!(offset_of!(CreateConfig, virtual_size), 16);
        assert_eq!(offset_of!(CreateConfig, qcow2_cluster_size), 24);
        assert_eq!(offset_of!(CreateConfig, qcow2_refcount_bits), 28);
        assert_eq!(offset_of!(CreateConfig, vmdk_subformat), 29);
        assert_eq!(offset_of!(CreateConfig, vhd_subformat), 30);
        assert_eq!(offset_of!(CreateConfig, _pad), 31);
        assert_eq!(offset_of!(CreateConfig, vmdk_grain_size), 32);
        assert_eq!(offset_of!(CreateConfig, block_size), 36);
        assert_eq!(offset_of!(CreateConfig, backing_file_len), 40);
        assert_eq!(offset_of!(CreateConfig, backing_file), 44);
        assert_eq!(offset_of!(CreateConfig, backing_format), 1068);
        assert_eq!(offset_of!(CreateConfig, _reserved), 1072);
    }

    #[test]
    fn create_result_magic_uniqueness() {
        assert_ne!(CreateResult::MAGIC, InfoResult::MAGIC);
        assert_ne!(CreateResult::MAGIC, CheckResult::MAGIC);
        assert_ne!(CreateResult::MAGIC, CompareResult::MAGIC);
        assert_ne!(CreateResult::MAGIC, MeasureResult::MAGIC);
    }

    fn create_config_with(magic: u32) -> CreateConfig {
        CreateConfig {
            magic,
            target_format: 0,
            flags: 0,
            sector_size: 0,
            virtual_size: 0,
            qcow2_cluster_size: 0,
            qcow2_refcount_bits: 0,
            vmdk_subformat: 0,
            vhd_subformat: 0,
            _pad: 0,
            vmdk_grain_size: 0,
            block_size: 0,
            backing_file_len: 0,
            backing_file: [0; CREATE_CONFIG_MAX_BACKING_FILE],
            backing_format: 0,
            _reserved: [0; 64],
        }
    }

    #[test]
    fn create_config_is_valid() {
        let cfg = create_config_with(CreateConfig::MAGIC);
        assert!(cfg.is_valid());
        let bad = create_config_with(0);
        assert!(!bad.is_valid());
    }

    #[test]
    fn create_config_backing_helpers() {
        let mut cfg = create_config_with(CreateConfig::MAGIC);
        assert!(!cfg.has_backing());
        assert_eq!(cfg.backing_file_bytes(), b"");

        let path = b"backing.qcow2";
        cfg.backing_file[..path.len()].copy_from_slice(path);
        cfg.backing_file_len = path.len() as u32;
        assert!(cfg.has_backing());
        assert_eq!(cfg.backing_file_bytes(), path);

        // Defensive: an over-large backing_file_len gets clamped.
        cfg.backing_file_len = (CREATE_CONFIG_MAX_BACKING_FILE as u32) + 100;
        assert_eq!(
            cfg.backing_file_bytes().len(),
            CREATE_CONFIG_MAX_BACKING_FILE
        );
    }

    #[test]
    fn create_config_flag_bits() {
        let cfg = CreateConfig {
            flags: CreateConfig::FLAG_EXTENDED_L2 | CreateConfig::FLAG_BACKING_UNSAFE,
            ..create_config_with(CreateConfig::MAGIC)
        };
        assert_eq!(
            cfg.flags & CreateConfig::FLAG_EXTENDED_L2,
            CreateConfig::FLAG_EXTENDED_L2
        );
        assert_eq!(cfg.flags & CreateConfig::FLAG_LAZY_REFCOUNTS, 0);
        assert_eq!(cfg.flags & CreateConfig::FLAG_COMPAT_V3, 0);
        assert_eq!(
            cfg.flags & CreateConfig::FLAG_BACKING_UNSAFE,
            CreateConfig::FLAG_BACKING_UNSAFE
        );
    }

    #[test]
    fn create_result_is_valid() {
        let mut r = CreateResult {
            magic: CreateResult::MAGIC,
            target_format: 0,
            resolved_virtual_size: 0,
            metadata_bytes_written: 0,
            file_size_after: 0,
            resolved_unit_size: 0,
            error: 0,
        };
        assert!(r.is_valid());
        r.magic = 0;
        assert!(!r.is_valid());
    }

    #[test]
    fn call_table_carries_resize_function_pointers() {
        // Forward-compat tripwire: phase 7a appended
        // `read_output_sector` and `send_resize_result` at the
        // end of CallTable. The size budget asserts no field
        // sneaks in past them. Update the budget deliberately
        // when adding new fields and document the change.
        let expected_fn_ptr = core::mem::size_of::<usize>();
        let min_fn_ptrs_in_table = 25; // grew from 23 in phase 7a
        let min_size = core::mem::size_of::<u32>() * 2 // magic + version
            + expected_fn_ptr * min_fn_ptrs_in_table;
        assert!(
            core::mem::size_of::<CallTable>() >= min_size,
            "CallTable shrank to {} bytes",
            core::mem::size_of::<CallTable>()
        );
    }

    #[test]
    fn resize_config_magic() {
        assert_eq!(ResizeConfig::MAGIC, 0x5245_5349); // "RESI" LE
    }

    #[test]
    fn resize_result_magic() {
        assert_eq!(ResizeResult::MAGIC, 0x5252_4553); // "RRES" LE
    }

    #[test]
    fn resize_result_error_codes_are_stable() {
        // These are ABI: append-only, never renumber.
        assert_eq!(ResizeResult::ERROR_OK, 0);
        assert_eq!(ResizeResult::ERROR_PARSE_FAILED, 12);
        assert_eq!(ResizeResult::ERROR_HEADER_MISMATCH, 13);
        assert_eq!(ResizeResult::ERROR_BITMAPS_UNSUPPORTED, 14);
    }

    #[test]
    fn resize_config_size_budget() {
        // Forward-compat tripwire: if a future phase grows this
        // past 256 bytes that's a deliberate ABI change and the
        // assertion should fail on purpose so it's reviewed.
        assert!(
            core::mem::size_of::<ResizeConfig>() <= 256,
            "ResizeConfig grew to {} bytes",
            core::mem::size_of::<ResizeConfig>()
        );
    }

    #[test]
    fn resize_result_size_budget() {
        assert!(
            core::mem::size_of::<ResizeResult>() <= 64,
            "ResizeResult grew to {} bytes",
            core::mem::size_of::<ResizeResult>()
        );
    }

    #[test]
    fn resize_config_prealloc_layout_matches_create() {
        // The encoding must match CreateConfig and MeasureConfig
        // exactly so the host's preallocation translation can be
        // a single function across all three operations.
        assert_eq!(ResizeConfig::PREALLOC_MASK, CreateConfig::PREALLOC_MASK);
        assert_eq!(ResizeConfig::PREALLOC_OFF, CreateConfig::PREALLOC_OFF);
        assert_eq!(
            ResizeConfig::PREALLOC_METADATA,
            CreateConfig::PREALLOC_METADATA
        );
        assert_eq!(ResizeConfig::PREALLOC_FALLOC, CreateConfig::PREALLOC_FALLOC);
        assert_eq!(ResizeConfig::PREALLOC_FULL, CreateConfig::PREALLOC_FULL);
    }

    #[test]
    fn resize_config_shrink_flag() {
        let cfg = ResizeConfig {
            magic: ResizeConfig::MAGIC,
            target_format: 0,
            flags: ResizeConfig::FLAG_SHRINK,
            sector_size: 0,
            current_virtual_size: 0,
            new_virtual_size: 0,
            qcow2_cluster_size: 0,
            qcow2_refcount_bits: 0,
            vmdk_subformat: 0,
            vhd_subformat: 0,
            _pad: 0,
            vmdk_grain_size: 0,
            block_size: 0,
            current_file_size: 0,
            _reserved: [0; 56],
        };
        assert!(cfg.allow_shrink());
        assert_eq!(cfg.preallocation(), ResizeConfig::PREALLOC_OFF);
    }

    #[test]
    fn measure_preallocation_bits() {
        let cfg = MeasureConfig {
            magic: MeasureConfig::MAGIC,
            target_format: 0,
            flags: MeasureConfig::FLAG_EXTENDED_L2 | MeasureConfig::PREALLOC_FALLOC,
            sector_size: 0,
            virtual_size_override: 0,
            qcow2_cluster_size: 0,
            qcow2_refcount_bits: 0,
            vmdk_subformat: 0,
            _pad2: 0,
            vmdk_grain_size: 0,
            vhd_subformat: 0,
            _pad3: [0; 3],
            block_size: 0,
            _pad4: 0,
            luks_header_overhead: 0,
        };
        assert_eq!(cfg.preallocation(), MeasureConfig::PREALLOC_FALLOC);
    }

    #[test]
    fn rebase_config_magic() {
        assert_eq!(RebaseConfig::MAGIC, 0x5245_4241); // "REBA" LE
    }

    #[test]
    fn rebase_result_magic() {
        assert_eq!(RebaseResult::MAGIC, 0x5242_5253); // "RBRS" LE
    }

    #[test]
    fn commit_config_magic() {
        assert_eq!(CommitConfig::MAGIC, 0x434F_4D4D); // "COMM" LE
    }

    #[test]
    fn commit_result_magic() {
        assert_eq!(CommitResult::MAGIC, 0x434F_5253); // "CORS" LE
    }

    #[test]
    fn rebase_config_size_budget() {
        // RebaseConfig embeds a 1024-byte backing path; the rest
        // of the struct should stay under ~150 bytes so the total
        // fits comfortably below 1.2 KiB. If a future phase grows
        // it past 1200, that's a deliberate ABI change and the
        // assertion should fail on purpose so it's reviewed.
        assert!(
            core::mem::size_of::<RebaseConfig>() <= 1200,
            "RebaseConfig grew to {} bytes",
            core::mem::size_of::<RebaseConfig>()
        );
    }

    #[test]
    fn rebase_result_size_budget() {
        assert!(
            core::mem::size_of::<RebaseResult>() <= 96,
            "RebaseResult grew to {} bytes",
            core::mem::size_of::<RebaseResult>()
        );
    }

    #[test]
    fn commit_config_size_budget() {
        assert!(
            core::mem::size_of::<CommitConfig>() <= 160,
            "CommitConfig grew to {} bytes",
            core::mem::size_of::<CommitConfig>()
        );
    }

    #[test]
    fn commit_result_size_budget() {
        assert!(
            core::mem::size_of::<CommitResult>() <= 96,
            "CommitResult grew to {} bytes",
            core::mem::size_of::<CommitResult>()
        );
    }

    #[test]
    fn rebase_config_is_valid_checks_magic() {
        let mut cfg = RebaseConfig {
            magic: RebaseConfig::MAGIC,
            overlay_format: 0,
            new_backing_format: 0,
            flags: 0,
            sector_size: 0,
            overlay_cluster_size: 0,
            overlay_virtual_size: 0,
            old_chain_first: 0,
            old_chain_count: 0,
            new_chain_first: 0,
            new_chain_count: 0,
            new_backing_path: [0; 1024],
            new_backing_path_len: 0,
            _reserved: [0; 60],
        };
        assert!(cfg.is_valid());
        cfg.magic = 0;
        assert!(!cfg.is_valid());
    }

    #[test]
    fn rebase_config_flags() {
        let cfg = RebaseConfig {
            magic: RebaseConfig::MAGIC,
            overlay_format: 0,
            new_backing_format: 0,
            flags: RebaseConfig::FLAG_UNSAFE | RebaseConfig::FLAG_DETACH,
            sector_size: 0,
            overlay_cluster_size: 0,
            overlay_virtual_size: 0,
            old_chain_first: 0,
            old_chain_count: 0,
            new_chain_first: 0,
            new_chain_count: 0,
            new_backing_path: [0; 1024],
            new_backing_path_len: 0,
            _reserved: [0; 60],
        };
        assert!(cfg.is_unsafe());
        assert!(cfg.is_detach());
    }

    #[test]
    fn rebase_result_error_codes_distinct() {
        // Phase 3 added codes 7..=13; the phase-2 snapshot gate
        // (issue #421) added 14; phase 5 of
        // PLAN-qcow2-write-infrastructure added the overlay
        // classification codes 15 and 16. Confirm every code is
        // distinct so the host's match arms don't accidentally
        // alias.
        let codes = [
            RebaseResult::ERROR_OK,
            RebaseResult::ERROR_UNSUPPORTED_FORMAT,
            RebaseResult::ERROR_NEW_BACKING_INCOMPATIBLE,
            RebaseResult::ERROR_EXTERNAL_DATA_FILE,
            RebaseResult::ERROR_LUKS_UNSUPPORTED,
            RebaseResult::ERROR_CHAIN_DEPTH,
            RebaseResult::ERROR_HEADER_MISMATCH,
            RebaseResult::ERROR_OVERLAY_CORRUPT,
            RebaseResult::ERROR_BACKING_PATH_TOO_LONG,
            RebaseResult::ERROR_SCRATCH_TOO_SMALL,
            RebaseResult::ERROR_REFCOUNT_EXHAUSTED,
            RebaseResult::ERROR_DESCRIPTOR_TOO_LARGE,
            RebaseResult::ERROR_PARSE_FAILED,
            RebaseResult::ERROR_INTERNAL_OVERFLOW,
            RebaseResult::ERROR_OVERLAY_HAS_SNAPSHOTS,
            RebaseResult::ERROR_OVERLAY_UNSUPPORTED,
            RebaseResult::ERROR_OVERLAY_INCONSISTENT,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j], "codes {i} and {j} alias");
            }
        }
        // Confirm contiguous 0..=16 numbering.
        for (i, c) in codes.iter().enumerate() {
            assert_eq!(*c, i as u32);
        }
    }

    #[test]
    fn rebase_result_is_valid_checks_magic() {
        let mut r = RebaseResult {
            magic: RebaseResult::MAGIC,
            overlay_format: 0,
            mode: RebaseResult::MODE_SAFE,
            error: RebaseResult::ERROR_OK,
            clusters_copied: 0,
            bytes_copied: 0,
            _reserved: [0; 56],
        };
        assert!(r.is_valid());
        r.magic = 0;
        assert!(!r.is_valid());
    }

    #[test]
    fn commit_config_is_valid_checks_magic() {
        let mut cfg = CommitConfig {
            magic: CommitConfig::MAGIC,
            overlay_format: 0,
            backing_format: 0,
            flags: 0,
            sector_size: 0,
            overlay_cluster_size: 0,
            backing_cluster_size: 0,
            _pad: 0,
            overlay_virtual_size: 0,
            backing_virtual_size: 0,
            backing_chain_first: 0,
            backing_chain_count: 0,
            _reserved: [0; 64],
        };
        assert!(cfg.is_valid());
        cfg.magic = 0;
        assert!(!cfg.is_valid());
    }

    #[test]
    fn commit_result_error_codes_distinct() {
        // Phase 7 step 7a added codes 8..=13; the phase-2
        // snapshot gates added 14 (backing, issue #420) and 15
        // (overlay, issue #423); phase 4 of
        // PLAN-qcow2-write-infrastructure added the backing
        // classification codes 16 and 17. Confirm every code is
        // distinct so the host's match arms don't accidentally
        // alias.
        let codes = [
            CommitResult::ERROR_OK,
            CommitResult::ERROR_UNSUPPORTED_FORMAT,
            CommitResult::ERROR_NO_BACKING,
            CommitResult::ERROR_EXTERNAL_DATA_FILE,
            CommitResult::ERROR_LUKS_UNSUPPORTED,
            CommitResult::ERROR_BACKING_TOO_SMALL,
            CommitResult::ERROR_OVERLAY_LARGER_THAN_BACKING,
            CommitResult::ERROR_HEADER_MISMATCH,
            CommitResult::ERROR_OVERLAY_CORRUPT,
            CommitResult::ERROR_BACKING_CORRUPT,
            CommitResult::ERROR_SCRATCH_TOO_SMALL,
            CommitResult::ERROR_REFCOUNT_EXHAUSTED,
            CommitResult::ERROR_PARSE_FAILED,
            CommitResult::ERROR_INTERNAL_OVERFLOW,
            CommitResult::ERROR_BACKING_HAS_SNAPSHOTS,
            CommitResult::ERROR_OVERLAY_HAS_SNAPSHOTS,
            CommitResult::ERROR_BACKING_UNSUPPORTED,
            CommitResult::ERROR_BACKING_INCONSISTENT,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j], "codes {i} and {j} alias");
            }
        }
        // Confirm contiguous 0..=17 numbering (append-only wire
        // codes).
        for (i, c) in codes.iter().enumerate() {
            assert_eq!(*c, i as u32);
        }
    }

    #[test]
    fn commit_result_is_valid_checks_magic() {
        let mut r = CommitResult {
            magic: CommitResult::MAGIC,
            overlay_format: 0,
            backing_format: 0,
            error: CommitResult::ERROR_OK,
            clusters_committed: 0,
            bytes_committed: 0,
            overlay_clusters_cleared: 0,
            _reserved: [0; 56],
        };
        assert!(r.is_valid());
        r.magic = 0;
        assert!(!r.is_valid());
    }

    #[test]
    fn amend_config_magic() {
        assert_eq!(AmendConfig::MAGIC, 0x414D_4E44); // "AMND" LE
    }

    #[test]
    fn amend_result_magic() {
        assert_eq!(AmendResult::MAGIC, 0x414D_5253); // "AMRS" LE
    }

    #[test]
    fn amend_config_size_and_align() {
        // Source of truth: AmendConfig must be exactly 128 bytes
        // and 8-byte aligned (it carries u64 cross-check fields).
        assert_eq!(
            core::mem::size_of::<AmendConfig>(),
            128,
            "AmendConfig is {} bytes",
            core::mem::size_of::<AmendConfig>()
        );
        assert_eq!(core::mem::align_of::<AmendConfig>(), 8);
    }

    #[test]
    fn amend_result_size_and_align() {
        // Source of truth: AmendResult must be exactly 64 bytes
        // and 4-byte aligned (all u32 fields).
        assert_eq!(
            core::mem::size_of::<AmendResult>(),
            64,
            "AmendResult is {} bytes",
            core::mem::size_of::<AmendResult>()
        );
        assert_eq!(core::mem::align_of::<AmendResult>(), 4);
    }

    #[test]
    fn amend_config_is_valid_checks_magic() {
        let mut cfg = AmendConfig {
            magic: AmendConfig::MAGIC,
            target_format: 0,
            flags: 0,
            sector_size: 0,
            cluster_size: 0,
            current_version: 0,
            current_refcount_bits: 0,
            _pad: 0,
            current_incompatible_features: 0,
            current_compatible_features: 0,
            virtual_size: 0,
            _reserved: [0; 72],
        };
        assert!(cfg.is_valid());
        cfg.magic = 0;
        assert!(!cfg.is_valid());
    }

    #[test]
    fn amend_config_flags_distinct() {
        let flags = [
            AmendConfig::FLAG_QUIET,
            AmendConfig::FLAG_SET_COMPAT,
            AmendConfig::FLAG_COMPAT_V3,
            AmendConfig::FLAG_SET_LAZY,
            AmendConfig::FLAG_LAZY_ON,
        ];
        for i in 0..flags.len() {
            for j in (i + 1)..flags.len() {
                assert_ne!(flags[i], flags[j], "flags {i} and {j} alias");
            }
        }
    }

    #[test]
    fn amend_result_error_codes_distinct() {
        // Phase 1 defines codes 0..=12. Confirm every code is
        // distinct and contiguously numbered.
        let codes = [
            AmendResult::ERROR_OK,
            AmendResult::ERROR_UNSUPPORTED_FORMAT,
            AmendResult::ERROR_INVALID_OPTION,
            AmendResult::ERROR_DOWNGRADE_BLOCKED_FEATURE,
            AmendResult::ERROR_DOWNGRADE_REFCOUNT_WIDTH,
            AmendResult::ERROR_LAZY_REQUIRES_V3,
            AmendResult::ERROR_HEADER_MISMATCH,
            AmendResult::ERROR_PARSE_FAILED,
            AmendResult::ERROR_DIRTY,
            AmendResult::ERROR_EXTENSION_RELOCATION_UNSUPPORTED,
            AmendResult::ERROR_WRITE_FAILED,
            AmendResult::ERROR_SCRATCH_TOO_SMALL,
            AmendResult::ERROR_INTERNAL_OVERFLOW,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j], "codes {i} and {j} alias");
            }
        }
        for (i, c) in codes.iter().enumerate() {
            assert_eq!(*c, i as u32);
        }
    }

    #[test]
    fn amend_result_is_valid_checks_magic() {
        let mut r = AmendResult {
            magic: AmendResult::MAGIC,
            target_format: 0,
            action: AmendResult::ACTION_NOOP,
            error: AmendResult::ERROR_OK,
            resulting_version: 0,
            resulting_lazy_refcounts: 0,
            _reserved: [0; 40],
        };
        assert!(r.is_valid());
        r.magic = 0;
        assert!(!r.is_valid());
    }

    #[test]
    fn bitmap_config_magic() {
        assert_eq!(BitmapConfig::MAGIC, 0x424D_5043); // "BMPC"
        assert_eq!(BitmapConfig::MAGIC.to_be_bytes(), *b"BMPC");
    }

    #[test]
    fn bitmap_result_magic() {
        assert_eq!(BitmapResult::MAGIC, 0x424D_5253); // "BMRS"
        assert_eq!(BitmapResult::MAGIC.to_be_bytes(), *b"BMRS");
    }

    #[test]
    fn bitmap_config_size_and_align() {
        // Source of truth: BitmapConfig must be exactly 3584 bytes,
        // 8-byte aligned (it carries u64 cross-check fields), and
        // fit the operation-config region.
        assert_eq!(
            core::mem::size_of::<BitmapConfig>(),
            3584,
            "BitmapConfig is {} bytes",
            core::mem::size_of::<BitmapConfig>()
        );
        assert_eq!(core::mem::align_of::<BitmapConfig>(), 8);
        assert!(core::mem::size_of::<BitmapConfig>() <= OPERATION_CONFIG_MAX_SIZE);
    }

    #[test]
    fn bitmap_result_size_and_align() {
        // Source of truth: BitmapResult must be exactly 64 bytes.
        assert_eq!(
            core::mem::size_of::<BitmapResult>(),
            64,
            "BitmapResult is {} bytes",
            core::mem::size_of::<BitmapResult>()
        );
        assert_eq!(core::mem::align_of::<BitmapResult>(), 4);
    }

    #[test]
    fn bench_config_magic() {
        assert_eq!(BenchConfig::MAGIC, 0x424E_4348); // "BNCH"
        assert_eq!(BenchConfig::MAGIC.to_be_bytes(), *b"BNCH");
    }

    #[test]
    fn bench_result_magic() {
        assert_eq!(BenchResult::MAGIC, 0x424E_5253); // "BNRS"
        assert_eq!(BenchResult::MAGIC.to_be_bytes(), *b"BNRS");
    }

    #[test]
    fn bench_config_size_and_align() {
        // Source of truth: BenchConfig must be exactly 128 bytes,
        // 8-byte aligned (it carries u64 fields), and fit the
        // operation-config region.
        assert_eq!(
            core::mem::size_of::<BenchConfig>(),
            128,
            "BenchConfig is {} bytes",
            core::mem::size_of::<BenchConfig>()
        );
        assert_eq!(core::mem::align_of::<BenchConfig>(), 8);
        assert!(core::mem::size_of::<BenchConfig>() <= OPERATION_CONFIG_MAX_SIZE);
    }

    #[test]
    fn bench_result_size_and_align() {
        // Source of truth: BenchResult must be exactly 64 bytes.
        assert_eq!(
            core::mem::size_of::<BenchResult>(),
            64,
            "BenchResult is {} bytes",
            core::mem::size_of::<BenchResult>()
        );
        assert_eq!(core::mem::align_of::<BenchResult>(), 8);
    }

    #[test]
    fn bench_config_flags_distinct() {
        assert_eq!(BenchConfig::FLAG_WRITE, 1 << 0);
        assert_eq!(BenchConfig::FLAG_NO_DRAIN, 1 << 1);
        assert_eq!(BenchConfig::FLAG_VERBOSE, 1 << 31);
    }

    #[test]
    fn bench_result_error_codes_distinct() {
        // Phase 2 defines codes 0..=6; phase 5 appends 7..=8; phase 6
        // step 6b appends 9. Confirm every code is distinct and
        // contiguously numbered.
        let codes = [
            BenchResult::ERROR_OK,
            BenchResult::ERROR_BAD_CONFIG,
            BenchResult::ERROR_UNSUPPORTED_FORMAT,
            BenchResult::ERROR_PARSE_FAILED,
            BenchResult::ERROR_IO_READ,
            BenchResult::ERROR_IO_WRITE,
            BenchResult::ERROR_IO_FLUSH,
            BenchResult::ERROR_WRITE_UNSUPPORTED,
            BenchResult::ERROR_ALLOC_EXHAUSTED,
            BenchResult::ERROR_IMAGE_INCONSISTENT,
        ];
        for (i, c) in codes.iter().enumerate() {
            assert_eq!(*c, i as u32);
        }
    }

    #[test]
    fn bench_config_is_valid_checks_magic() {
        let mut cfg = BenchConfig {
            magic: BenchConfig::MAGIC,
            flags: 0,
            count: 0,
            depth: 0,
            bufsize: 0,
            step: 0,
            offset: 0,
            flush_interval: 0,
            pattern: 0,
            target_format: 0,
            sector_size: 0,
            _reserved: [0; 72],
        };
        assert!(cfg.is_valid());
        cfg.magic = 0;
        assert!(!cfg.is_valid());
    }

    #[test]
    fn bench_result_is_valid_checks_magic() {
        let mut r = BenchResult {
            magic: BenchResult::MAGIC,
            error: BenchResult::ERROR_OK,
            requests_completed: 0,
            flushes_issued: 0,
            error_detail: 0,
            _reserved: [0; 32],
        };
        assert!(r.is_valid());
        r.magic = 0;
        assert!(!r.is_valid());
    }

    #[test]
    fn bitmap_config_is_valid_checks_magic() {
        let mut cfg = BitmapConfig {
            magic: BitmapConfig::MAGIC,
            target_format: 0,
            flags: 0,
            sector_size: 0,
            num_actions: 0,
            name_len: 0,
            num_merge_sources: 0,
            _pad0: 0,
            granularity: 0,
            current_autoclear_features: 0,
            current_incompatible_features: 0,
            virtual_size: 0,
            bitmap_directory_offset: 0,
            bitmap_directory_size: 0,
            current_version: 0,
            current_refcount_bits: 0,
            cluster_size: 0,
            nb_bitmaps: 0,
            actions: [0; MAX_BITMAP_ACTIONS],
            _pad1: [0; 8],
            name: [0; BITMAP_NAME_BUF],
            merge_source_lens: [0; MAX_MERGE_SOURCES],
            merge_source_pool: [0; MERGE_SOURCE_POOL],
            _reserved: [0; 384],
        };
        assert!(cfg.is_valid());
        cfg.magic = 0;
        assert!(!cfg.is_valid());
    }

    #[test]
    fn bitmap_config_flags_distinct() {
        let flags = [BitmapConfig::FLAG_QUIET, BitmapConfig::FLAG_VERBOSE];
        for i in 0..flags.len() {
            for j in (i + 1)..flags.len() {
                assert_ne!(flags[i], flags[j], "flags {i} and {j} alias");
            }
        }
    }

    #[test]
    fn bitmap_config_action_opcodes() {
        // Opcodes are 1..=6, distinct, and stably numbered.
        let actions = [
            BitmapConfig::ACTION_ADD,
            BitmapConfig::ACTION_REMOVE,
            BitmapConfig::ACTION_CLEAR,
            BitmapConfig::ACTION_ENABLE,
            BitmapConfig::ACTION_DISABLE,
            BitmapConfig::ACTION_MERGE,
        ];
        for i in 0..actions.len() {
            for j in (i + 1)..actions.len() {
                assert_ne!(actions[i], actions[j], "actions {i} and {j} alias");
            }
        }
        for (i, a) in actions.iter().enumerate() {
            assert_eq!(*a, (i + 1) as u8);
        }
    }

    #[test]
    fn bitmap_result_error_codes_distinct() {
        // Phase 2 defines codes 0..=17; phase 3 appends 18 and 19.
        // Confirm every code is distinct and contiguously numbered
        // (append-only).
        let codes = [
            BitmapResult::ERROR_OK,
            BitmapResult::ERROR_UNSUPPORTED_FORMAT,
            BitmapResult::ERROR_UNSUPPORTED_VERSION,
            BitmapResult::ERROR_PARSE_FAILED,
            BitmapResult::ERROR_HEADER_MISMATCH,
            BitmapResult::ERROR_BITMAP_NOT_FOUND,
            BitmapResult::ERROR_BITMAP_EXISTS,
            BitmapResult::ERROR_BITMAP_IN_USE,
            BitmapResult::ERROR_NAME_TOO_LONG,
            BitmapResult::ERROR_GRANULARITY_RANGE,
            BitmapResult::ERROR_TOO_MANY_BITMAPS,
            BitmapResult::ERROR_NO_SPACE,
            BitmapResult::ERROR_WRITE_FAILED,
            BitmapResult::ERROR_READ_FAILED,
            BitmapResult::ERROR_SCRATCH_TOO_SMALL,
            BitmapResult::ERROR_INTERNAL_OVERFLOW,
            BitmapResult::ERROR_MERGE_SOURCE_NOT_FOUND,
            BitmapResult::ERROR_UNSUPPORTED_ACTION,
            BitmapResult::ERROR_UNSUPPORTED_REFCOUNT_WIDTH,
            BitmapResult::ERROR_INCOMPATIBLE_MERGE,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j], "codes {i} and {j} alias");
            }
        }
        for (i, c) in codes.iter().enumerate() {
            assert_eq!(*c, i as u32);
        }
    }

    #[test]
    fn bitmap_result_is_valid_checks_magic() {
        let mut r = BitmapResult {
            magic: BitmapResult::MAGIC,
            target_format: 0,
            error: BitmapResult::ERROR_OK,
            action: 0,
            actions_applied: 0,
            resulting_nb_bitmaps: 0,
            _reserved: [0; 40],
        };
        assert!(r.is_valid());
        r.magic = 0;
        assert!(!r.is_valid());
    }

    // ------------------------------------------------------------------
    // MapExtentCoalescer tests
    // ------------------------------------------------------------------

    fn data(start: u64, length: u64, file_offset: u64) -> MapExtent {
        MapExtent {
            start,
            length,
            state: MapExtentState::Data { file_offset },
        }
    }

    fn hole(start: u64, length: u64) -> MapExtent {
        MapExtent {
            start,
            length,
            state: MapExtentState::Hole,
        }
    }

    fn zero_alloc(start: u64, length: u64) -> MapExtent {
        MapExtent {
            start,
            length,
            state: MapExtentState::ZeroAllocated,
        }
    }

    /// Small fixed-size emitter that records each emitted extent
    /// into a stack-allocated buffer. Avoids requiring `alloc`
    /// in tests so the shared crate's no_std test build stays
    /// dependency-free.
    struct Recorder {
        buf: [MapExtent; 8],
        len: usize,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                buf: [hole(0, 0); 8],
                len: 0,
            }
        }

        fn record(&mut self, e: MapExtent) {
            assert!(self.len < self.buf.len(), "recorder overflow");
            self.buf[self.len] = e;
            self.len += 1;
        }

        fn slice(&self) -> &[MapExtent] {
            &self.buf[..self.len]
        }
    }

    /// Drive the coalescer with `pushes`, asserting no abort, and
    /// return the recorder's contents.
    fn collect(pushes: &[MapExtent]) -> Recorder {
        let mut rec = Recorder::new();
        let mut emit = |e: MapExtent| -> bool {
            rec.record(e);
            true
        };
        {
            let mut c = MapExtentCoalescer::new(&mut emit);
            for p in pushes {
                let cont = c.push(*p);
                assert!(cont, "coalescer aborted unexpectedly");
            }
            assert!(c.finish());
        }
        rec
    }

    #[test]
    fn coalescer_empty_emits_nothing() {
        let r = collect(&[]);
        assert_eq!(r.slice(), &[] as &[MapExtent]);
    }

    #[test]
    fn coalescer_single_data_passes_through() {
        let r = collect(&[data(0, 4096, 0)]);
        assert_eq!(r.slice(), &[data(0, 4096, 0)]);
    }

    #[test]
    fn coalescer_two_contiguous_data_merge() {
        let r = collect(&[data(0, 4096, 0), data(4096, 4096, 4096)]);
        assert_eq!(r.slice(), &[data(0, 8192, 0)]);
    }

    #[test]
    fn coalescer_two_data_with_noncontiguous_file_offset_split() {
        // Same virtual contiguity, but file offsets jump — qemu-img
        // splits these.
        let r = collect(&[data(0, 4096, 0), data(4096, 4096, 8192)]);
        assert_eq!(r.slice(), &[data(0, 4096, 0), data(4096, 4096, 8192)]);
    }

    #[test]
    fn coalescer_two_holes_merge() {
        let r = collect(&[hole(0, 4096), hole(4096, 4096)]);
        assert_eq!(r.slice(), &[hole(0, 8192)]);
    }

    #[test]
    fn coalescer_two_zero_alloc_merge() {
        let r = collect(&[zero_alloc(0, 4096), zero_alloc(4096, 4096)]);
        assert_eq!(r.slice(), &[zero_alloc(0, 8192)]);
    }

    #[test]
    fn coalescer_hole_then_data_splits() {
        let r = collect(&[hole(0, 4096), data(4096, 4096, 0)]);
        assert_eq!(r.slice(), &[hole(0, 4096), data(4096, 4096, 0)]);
    }

    #[test]
    fn coalescer_data_then_zero_alloc_splits() {
        let r = collect(&[data(0, 4096, 0), zero_alloc(4096, 4096)]);
        assert_eq!(r.slice(), &[data(0, 4096, 0), zero_alloc(4096, 4096)]);
    }

    #[test]
    fn coalescer_virtual_gap_splits() {
        // No virtual gap allowed even for matching state.
        let r = collect(&[data(0, 4096, 0), data(8192, 4096, 8192)]);
        assert_eq!(r.slice(), &[data(0, 4096, 0), data(8192, 4096, 8192)]);
    }

    #[test]
    fn coalescer_zero_length_push_dropped() {
        let r = collect(&[
            data(0, 4096, 0),
            data(4096, 0, 4096),
            data(4096, 4096, 4096),
        ]);
        assert_eq!(r.slice(), &[data(0, 8192, 0)]);
    }

    #[test]
    fn coalescer_abort_on_first_emit_stops_iteration() {
        let mut rec = Recorder::new();
        let mut emit = |e: MapExtent| -> bool {
            rec.record(e);
            false
        };
        {
            let mut c = MapExtentCoalescer::new(&mut emit);
            // First push fills pending — no emit yet.
            assert!(c.push(data(0, 4096, 0)));
            // Second push flushes pending; emitter returns false.
            assert!(!c.push(hole(4096, 4096)));
            // Subsequent pushes are dropped.
            assert!(!c.push(data(8192, 4096, 0)));
            assert!(!c.finish());
        }
        // Only the first (flushed) extent was emitted.
        assert_eq!(rec.slice(), &[data(0, 4096, 0)]);
    }

    #[test]
    fn coalescer_abort_on_finish_flush() {
        let mut emit = |_: MapExtent| -> bool { false };
        {
            let mut c = MapExtentCoalescer::new(&mut emit);
            assert!(c.push(data(0, 4096, 0)));
            // finish() flushes pending; emitter returns false.
            assert!(!c.finish());
        }
    }

    #[test]
    fn coalescer_overflow_push_dropped() {
        // start + length overflows u64 — silently dropped.
        let r = collect(&[
            data(0, 4096, 0),
            data(u64::MAX, 1, 0), // start + length overflows by 1
        ]);
        assert_eq!(r.slice(), &[data(0, 4096, 0)]);
    }

    #[test]
    fn coalescer_data_file_offset_overflow_does_not_merge() {
        // a_end virtual is fine, but a.file_offset + a.length overflows;
        // mergeable returns false rather than panicking.
        let r = collect(&[data(0, 4096, u64::MAX - 1000), data(4096, 4096, 0)]);
        assert_eq!(
            r.slice(),
            &[data(0, 4096, u64::MAX - 1000), data(4096, 4096, 0)]
        );
    }

    // ------------------------------------------------------------------
    // MapConfig / MapExtentRecord / MapResult tests
    // ------------------------------------------------------------------

    #[test]
    fn map_magic_values_are_unique_among_existing_magics() {
        // Cross-check the three new magic values against the
        // existing 21 in the crate. If a future config struct
        // accidentally picks the same magic, the static asserts
        // here will surface the collision.
        let map_magics = [MapConfig::MAGIC, MapExtentRecord::MAGIC, MapResult::MAGIC];
        let existing = [
            CallTable::MAGIC,
            CopyConfig::MAGIC,
            InfoConfig::MAGIC,
            InfoResult::MAGIC,
            CheckConfig::MAGIC,
            CheckResult::MAGIC,
            CompareConfig::MAGIC,
            CompareResult::MAGIC,
            ConvertConfig::MAGIC,
            MeasureConfig::MAGIC,
            MeasureResult::MAGIC,
            CreateConfig::MAGIC,
            CreateResult::MAGIC,
            ResizeConfig::MAGIC,
            ResizeResult::MAGIC,
            RebaseConfig::MAGIC,
            RebaseResult::MAGIC,
            CommitConfig::MAGIC,
            CommitResult::MAGIC,
            ChainConfig::MAGIC,
        ];
        // No new magic equals any existing magic.
        for m in &map_magics {
            for e in &existing {
                assert_ne!(*m, *e, "map magic 0x{:08x} collides with existing", m);
            }
        }
        // The three new magics are also mutually distinct.
        assert_ne!(MapConfig::MAGIC, MapExtentRecord::MAGIC);
        assert_ne!(MapConfig::MAGIC, MapResult::MAGIC);
        assert_ne!(MapExtentRecord::MAGIC, MapResult::MAGIC);
    }

    #[test]
    fn map_config_is_valid_accepts_magic_rejects_zero() {
        let mut c = MapConfig {
            magic: MapConfig::MAGIC,
            flags: 0,
            sector_size: 65536,
            input_device_count: 1,
            start_offset: 0,
            max_length: 0,
            _reserved: [0; 32],
        };
        assert!(c.is_valid());
        c.magic = 0;
        assert!(!c.is_valid());
        c.magic = 0xDEAD_BEEF;
        assert!(!c.is_valid());
    }

    #[test]
    fn map_extent_record_is_valid_accepts_magic_rejects_zero() {
        let mut r = MapExtentRecord {
            magic: MapExtentRecord::MAGIC,
            state: MapExtentRecord::STATE_DATA,
            start: 0,
            length: 4096,
            file_offset: 0,
            _reserved: [0; 16],
        };
        assert!(r.is_valid());
        r.magic = 0;
        assert!(!r.is_valid());
    }

    #[test]
    fn map_result_is_valid_accepts_magic_rejects_zero() {
        let mut r = MapResult {
            magic: MapResult::MAGIC,
            source_format: 0,
            extents_emitted: 0,
            virtual_size: 0,
            error: MapResult::ERROR_OK,
            _reserved: 0,
        };
        assert!(r.is_valid());
        r.magic = 0;
        assert!(!r.is_valid());
    }

    #[test]
    fn map_extent_record_state_codes_are_contiguous_from_zero() {
        // The host renderer maps state codes by table lookup; the
        // codes must stay contiguous from 0 and mutually disjoint.
        assert_eq!(MapExtentRecord::STATE_HOLE, 0);
        assert_eq!(MapExtentRecord::STATE_ZERO_ALLOCATED, 1);
        assert_eq!(MapExtentRecord::STATE_DATA, 2);
    }

    #[test]
    fn map_result_error_codes_have_expected_values() {
        // Pinned to keep the wire format stable across versions —
        // protobuf transports these directly.
        assert_eq!(MapResult::ERROR_OK, 0);
        assert_eq!(MapResult::ERROR_INVALID_SOURCE, 1);
        assert_eq!(MapResult::ERROR_INVALID_OPTION, 2);
        assert_eq!(MapResult::ERROR_HAS_BACKING, 3);
        assert_eq!(MapResult::ERROR_IO, 4);
    }

    #[test]
    fn map_config_flag_verbose_is_top_bit() {
        // The convention in this crate (cross-checked against
        // ConvertConfig::FLAG_VERBOSE) is that bit 31 carries
        // verbosity so subsequent flags can extend from bit 0
        // upwards without colliding.
        assert_eq!(MapConfig::FLAG_VERBOSE, 1 << 31);
    }

    // ------------------------------------------------------------------
    // SnapshotConfig / SnapshotEntryRecord / SnapshotResult tests
    // ------------------------------------------------------------------

    #[test]
    fn snapshot_magic_values_are_unique_among_existing_magics() {
        // Cross-check the three new magic values against the
        // existing set in the crate. If a future config struct
        // accidentally picks the same magic, this assertion will
        // surface the collision.
        let snapshot_magics = [
            SnapshotConfig::MAGIC,
            SnapshotEntryRecord::MAGIC,
            SnapshotResult::MAGIC,
        ];
        let existing = [
            CallTable::MAGIC,
            CopyConfig::MAGIC,
            InfoConfig::MAGIC,
            InfoResult::MAGIC,
            CheckConfig::MAGIC,
            CheckResult::MAGIC,
            CompareConfig::MAGIC,
            CompareResult::MAGIC,
            ConvertConfig::MAGIC,
            MeasureConfig::MAGIC,
            MeasureResult::MAGIC,
            CreateConfig::MAGIC,
            CreateResult::MAGIC,
            ResizeConfig::MAGIC,
            ResizeResult::MAGIC,
            RebaseConfig::MAGIC,
            RebaseResult::MAGIC,
            CommitConfig::MAGIC,
            CommitResult::MAGIC,
            ChainConfig::MAGIC,
            MapConfig::MAGIC,
            MapExtentRecord::MAGIC,
            MapResult::MAGIC,
        ];
        // No new magic equals any existing magic.
        for m in &snapshot_magics {
            for e in &existing {
                assert_ne!(*m, *e, "snapshot magic 0x{:08x} collides with existing", m);
            }
        }
        // The three new magics are also mutually distinct.
        assert_ne!(SnapshotConfig::MAGIC, SnapshotEntryRecord::MAGIC);
        assert_ne!(SnapshotConfig::MAGIC, SnapshotResult::MAGIC);
        assert_ne!(SnapshotEntryRecord::MAGIC, SnapshotResult::MAGIC);
    }

    #[test]
    fn snapshot_magic_values_match_ascii() {
        // The magics are intentionally readable as 4-byte ASCII
        // for ease of debugging hex dumps. Pin the bytes.
        assert_eq!(SnapshotConfig::MAGIC, 0x534E4150); // "SNAP"
        assert_eq!(SnapshotEntryRecord::MAGIC, 0x534E4552); // "SNER"
        assert_eq!(SnapshotResult::MAGIC, 0x534E5253); // "SNRS"
    }

    #[test]
    fn snapshot_config_layout_is_pinned() {
        // The host writes this struct field-by-field at fixed
        // offsets in the VMM (`run_snapshot_create` /
        // `run_snapshot_list`), so every offset and the total size
        // is load-bearing. PLAN-snapshot phase 6a carved
        // `date_sec` / `date_nsec` from the front of the old
        // `_reserved: [u8; 32]` without moving any pre-existing
        // field: total size, `arg` offset, and all earlier offsets
        // are unchanged.
        use core::mem::offset_of;
        assert_eq!(core::mem::size_of::<SnapshotConfig>(), 312);
        assert_eq!(offset_of!(SnapshotConfig, magic), 0);
        assert_eq!(offset_of!(SnapshotConfig, mode), 4);
        assert_eq!(offset_of!(SnapshotConfig, flags), 8);
        assert_eq!(offset_of!(SnapshotConfig, sector_size), 12);
        assert_eq!(offset_of!(SnapshotConfig, arg_len), 16);
        assert_eq!(offset_of!(SnapshotConfig, _pad), 20);
        assert_eq!(offset_of!(SnapshotConfig, arg), 24);
        // New date fields land in the space the old 32-byte
        // `_reserved` used to occupy; the residual reserve shrinks
        // to 24 bytes so the total size is unchanged.
        assert_eq!(offset_of!(SnapshotConfig, date_sec), 280);
        assert_eq!(offset_of!(SnapshotConfig, date_nsec), 284);
        assert_eq!(offset_of!(SnapshotConfig, _reserved), 288);
    }

    #[test]
    fn snapshot_config_is_valid_accepts_magic_rejects_zero() {
        let mut c = SnapshotConfig {
            magic: SnapshotConfig::MAGIC,
            mode: SnapshotConfig::MODE_LIST,
            flags: 0,
            sector_size: 65536,
            arg_len: 0,
            _pad: 0,
            arg: [0; 256],
            date_sec: 0,
            date_nsec: 0,
            _reserved: [0; 24],
        };
        assert!(c.is_valid());
        c.magic = 0;
        assert!(!c.is_valid());
        c.magic = 0xDEAD_BEEF;
        assert!(!c.is_valid());
    }

    #[test]
    fn snapshot_entry_record_is_valid_accepts_magic_rejects_zero() {
        let mut r = SnapshotEntryRecord {
            magic: SnapshotEntryRecord::MAGIC,
            date_sec_hi: 0,
            date_sec_lo: 0,
            date_nsec: 0,
            vm_clock_nsec: 0,
            vm_state_size_large: 0,
            disk_size: 0,
            icount: SnapshotEntryRecord::ICOUNT_ABSENT,
            l1_table_offset: 0,
            l1_size: 0,
            extra_data_size: 0,
            id_len: 0,
            name_len: 0,
            id: [0; 32],
            name: [0; 256],
            _reserved: [0; 32],
        };
        assert!(r.is_valid());
        r.magic = 0;
        assert!(!r.is_valid());
    }

    #[test]
    fn snapshot_result_is_valid_accepts_magic_rejects_zero() {
        let mut r = SnapshotResult {
            magic: SnapshotResult::MAGIC,
            mode: SnapshotConfig::MODE_LIST,
            error: SnapshotResult::ERROR_OK,
            _pad: 0,
            snapshots_emitted: 0,
            assigned_id_len: 0,
            assigned_id: [0; 64],
            _reserved: [0; 96],
        };
        assert!(r.is_valid());
        r.magic = 0;
        assert!(!r.is_valid());
    }

    #[test]
    fn snapshot_config_mode_codes_are_contiguous_from_zero() {
        // The host renderer and the guest dispatcher both rely
        // on mode codes being contiguous from 0 and mutually
        // disjoint.
        assert_eq!(SnapshotConfig::MODE_LIST, 0);
        assert_eq!(SnapshotConfig::MODE_APPLY, 1);
        assert_eq!(SnapshotConfig::MODE_CREATE, 2);
        assert_eq!(SnapshotConfig::MODE_DELETE, 3);
    }

    #[test]
    fn snapshot_config_flags_do_not_collide() {
        // Bit 31 is reserved for FLAG_VERBOSE across configs.
        assert_eq!(SnapshotConfig::FLAG_QUIET, 1 << 0);
        assert_eq!(SnapshotConfig::FLAG_FORCE_SHARE, 1 << 1);
        assert_eq!(SnapshotConfig::FLAG_VERBOSE, 1 << 31);
        assert_ne!(SnapshotConfig::FLAG_QUIET, SnapshotConfig::FLAG_FORCE_SHARE);
        assert_ne!(SnapshotConfig::FLAG_QUIET, SnapshotConfig::FLAG_VERBOSE);
        assert_ne!(
            SnapshotConfig::FLAG_FORCE_SHARE,
            SnapshotConfig::FLAG_VERBOSE
        );
    }

    #[test]
    fn snapshot_result_error_codes_have_expected_values() {
        // Pinned to keep the wire format stable across versions —
        // protobuf transports these directly.
        assert_eq!(SnapshotResult::ERROR_OK, 0);
        assert_eq!(SnapshotResult::ERROR_UNSUPPORTED_FORMAT, 1);
        assert_eq!(SnapshotResult::ERROR_UNSUPPORTED_FEATURE, 2);
        assert_eq!(SnapshotResult::ERROR_NOT_FOUND, 3);
        assert_eq!(SnapshotResult::ERROR_DUPLICATE_NAME, 4);
        assert_eq!(SnapshotResult::ERROR_REFCOUNT_OVERFLOW, 5);
        assert_eq!(SnapshotResult::ERROR_ALLOCATION_FAILED, 6);
        assert_eq!(SnapshotResult::ERROR_SNAPSHOT_TABLE_FULL, 7);
        assert_eq!(SnapshotResult::ERROR_IO, 8);
        assert_eq!(SnapshotResult::ERROR_L1_SIZE_MISMATCH, 9);
        assert_eq!(SnapshotResult::ERROR_INVALID_UTF8, 10);
        assert_eq!(SnapshotResult::ERROR_INVALID_CONFIG, 11);
        assert_eq!(SnapshotResult::ERROR_PARSE_FAILED, 12);
    }

    #[test]
    fn snapshot_result_error_codes_are_mutually_distinct() {
        let codes = [
            SnapshotResult::ERROR_OK,
            SnapshotResult::ERROR_UNSUPPORTED_FORMAT,
            SnapshotResult::ERROR_UNSUPPORTED_FEATURE,
            SnapshotResult::ERROR_NOT_FOUND,
            SnapshotResult::ERROR_DUPLICATE_NAME,
            SnapshotResult::ERROR_REFCOUNT_OVERFLOW,
            SnapshotResult::ERROR_ALLOCATION_FAILED,
            SnapshotResult::ERROR_SNAPSHOT_TABLE_FULL,
            SnapshotResult::ERROR_IO,
            SnapshotResult::ERROR_L1_SIZE_MISMATCH,
            SnapshotResult::ERROR_INVALID_UTF8,
            SnapshotResult::ERROR_INVALID_CONFIG,
            SnapshotResult::ERROR_PARSE_FAILED,
        ];
        for (i, a) in codes.iter().enumerate() {
            for (j, b) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "error codes at {} and {} collide", i, j);
                }
            }
        }
    }

    #[test]
    fn snapshot_entry_record_icount_absent_sentinel() {
        // The wire format reserves u64::MAX to mean "no icount
        // was present in the source"; pin the value because the
        // host-side renderer special-cases it.
        assert_eq!(SnapshotEntryRecord::ICOUNT_ABSENT, u64::MAX);
    }

    #[test]
    fn call_table_version_is_twenty() {
        // PLAN-snapshot phase 1 bumped the call-table ABI from
        // 16 to 17 by appending `send_snapshot_entry`,
        // `send_snapshot_result`, and `fsync_input`.
        // PLAN-amend phase 1 bumps 17 to 18 by appending
        // `send_amend_result`.
        // PLAN-bitmap phase 2 bumps 18 to 19 by appending
        // `send_bitmap_result`.
        // PLAN-bench phase 2 bumps 19 to 20 by appending
        // `send_bench_start` and `send_bench_result`.
        assert_eq!(CallTable::VERSION, 20);
    }

    #[test]
    fn check_config_flag_repair_all_bit_value() {
        // Bit 4: must not collide with the existing bits 0-3
        // (REPAIR/QUIET/UNSAFE_QUIRKS/CHAIN).
        assert_eq!(CheckConfig::FLAG_REPAIR_ALL, 1 << 4);
        assert_ne!(CheckConfig::FLAG_REPAIR_ALL, CheckConfig::FLAG_REPAIR);
        assert_ne!(CheckConfig::FLAG_REPAIR_ALL, CheckConfig::FLAG_QUIET);
        assert_ne!(
            CheckConfig::FLAG_REPAIR_ALL,
            CheckConfig::FLAG_UNSAFE_QUIRKS
        );
        assert_ne!(CheckConfig::FLAG_REPAIR_ALL, CheckConfig::FLAG_CHAIN);
    }

    #[test]
    fn check_config_should_repair_all_requires_both_bits() {
        let cfg = CheckConfig {
            magic: CheckConfig::MAGIC,
            flags: CheckConfig::FLAG_REPAIR | CheckConfig::FLAG_REPAIR_ALL,
        };
        assert!(cfg.should_repair());
        assert!(cfg.should_repair_all());
    }

    #[test]
    fn check_config_should_repair_all_false_when_only_all_set() {
        // FLAG_REPAIR_ALL without FLAG_REPAIR is meaningless and
        // must be treated as no repair at all.
        let cfg = CheckConfig {
            magic: CheckConfig::MAGIC,
            flags: CheckConfig::FLAG_REPAIR_ALL,
        };
        assert!(!cfg.should_repair());
        assert!(!cfg.should_repair_all());

        // FLAG_REPAIR alone is the leaks tier: repair yes, all no.
        let leaks = CheckConfig {
            magic: CheckConfig::MAGIC,
            flags: CheckConfig::FLAG_REPAIR,
        };
        assert!(leaks.should_repair());
        assert!(!leaks.should_repair_all());
    }

    #[test]
    fn check_result_repair_incomplete_accessor() {
        assert_eq!(CheckResult::FLAG_REPAIR_INCOMPLETE, 1 << 8);
        let mut result = CheckResult::new();
        assert!(!result.repair_incomplete());
        result.flags |= CheckResult::FLAG_REPAIR_INCOMPLETE;
        assert!(result.repair_incomplete());
    }

    #[test]
    fn check_result_new_zeroes_repair_counters() {
        let result = CheckResult::new();
        assert_eq!(result.repaired_leaks, 0);
        assert_eq!(result.repaired_refcounts, 0);
        assert_eq!(result.repaired_corruptions, 0);
    }

    #[test]
    fn check_result_repair_counters_round_trip_through_copy() {
        let mut result = CheckResult::new();
        result.repaired_leaks = 7;
        result.repaired_refcounts = 11;
        result.repaired_corruptions = 13;
        let copy = result;
        assert_eq!(copy.repaired_leaks, 7);
        assert_eq!(copy.repaired_refcounts, 11);
        assert_eq!(copy.repaired_corruptions, 13);
    }
}
