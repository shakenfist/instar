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
/// at 0x80000. Guest memory is zeroed on creation, so no explicit
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
/// Located at 512KB to avoid overlap with core binary (which can grow past 32KB).
/// The core binary is loaded at 0x10000 and may extend to 0x20000 (64KB max).
/// The operation binary is loaded at 0x20000, so we place data structures at 0x80000.
pub const CALL_TABLE_ADDR: usize = 0x00080000;

/// Address where operation config is stored (set by VMM/core)
pub const OPERATION_CONFIG_ADDR: usize = 0x00081000;

/// Maximum size of operation config in bytes
pub const OPERATION_CONFIG_MAX_SIZE: usize = 4096;

/// Address where chain config is stored (set by VMM)
/// This contains metadata about the backing chain for operations that need it.
pub const CHAIN_CONFIG_ADDR: usize = 0x00082000;

/// Address where LUKS encrypt random data is stored (set by VMM).
/// Layout: master_key (64B) + mk_digest_salt (32B) + slot_salt (32B)
/// + uuid (36B) + AF random stripes (key_bytes * (stripes-1)).
/// Maximum size: 64 + 32 + 32 + 36 + 64*3999 = 255,100 bytes.
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
pub const VMM_PARAMS_ADDR: usize = 0x00083000;

/// Address where operation binaries are loaded
pub const OPERATION_LOAD_ADDR: usize = 0x00020000;

/// DMA pool base address (must match core/virtio.rs and vmm/main.rs).
/// Used for virtio request headers, data buffers, and status bytes.
pub const DMA_POOL_BASE: usize = 0x00200000;

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

    /// Current ABI version (bumped: added send_compare_result)
    pub const VERSION: u32 = 12;
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
    /// When disabled (default), imago detects the real format and performs
    /// format-appropriate validation.
    pub const FLAG_UNSAFE_QUIRKS: u32 = 1 << 2;

    /// Flag: Validate backing chain (chain mode)
    pub const FLAG_CHAIN: u32 = 1 << 3;

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
            image_end_offset: 0,
            clusters_checked: 0,
            clusters_allocated: 0,
            fragmentation: 0,
            flags: 0,
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
    /// Offset: 376
    pub luks_random_data_addr: u64,

    /// Total size of the LUKS random data region.
    /// Offset: 384
    pub luks_random_data_size: u64,
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
