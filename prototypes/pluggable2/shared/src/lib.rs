//! Shared types between core and operations.
//!
//! This crate defines the ABI between the core guest and operation binaries.
//! Both the core and operations link against this crate to share type definitions.

#![no_std]

/// Address where the call table is located (set by core)
pub const CALL_TABLE_ADDR: usize = 0x00018000;

/// Address where operation config is stored (set by VMM/core)
pub const OPERATION_CONFIG_ADDR: usize = 0x00019000;

/// Maximum size of operation config in bytes
pub const OPERATION_CONFIG_MAX_SIZE: usize = 4096;

/// Address where operation binaries are loaded
pub const OPERATION_LOAD_ADDR: usize = 0x00020000;

/// Maximum sector size supported
pub const MAX_SECTOR_SIZE: usize = 65536;

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

    /// Read a sector from the input device.
    /// Args: sector number, buffer pointer, buffer length
    /// Returns: true on success
    pub read_input_sector: unsafe extern "C" fn(u64, *mut u8, usize) -> bool,

    /// Write a sector to the output device.
    /// Args: sector number, buffer pointer, buffer length
    /// Returns: true on success
    pub write_output_sector: unsafe extern "C" fn(u64, *const u8, usize) -> bool,

    /// Get input device capacity in sectors.
    pub get_input_capacity: unsafe extern "C" fn() -> u64,

    /// Get output device capacity in sectors.
    pub get_output_capacity: unsafe extern "C" fn() -> u64,

    /// Get input sector size in bytes.
    pub get_input_sector_size: unsafe extern "C" fn() -> usize,

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

    /// Debug print (null-terminated string).
    pub debug_print: unsafe extern "C" fn(*const u8),

    /// Get operation-specific configuration.
    /// Returns: ConfigResult with pointer and length.
    /// The config format is operation-specific.
    pub get_operation_config: unsafe extern "C" fn() -> ConfigResult,
}

impl CallTable {
    /// Magic value indicating a valid call table
    pub const MAGIC: u32 = 0x494D4147; // "IMAG"

    /// Current ABI version (bumped for get_operation_config addition)
    pub const VERSION: u32 = 2;
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

/// Operation entry point signature.
///
/// Operations must export a function with this signature at the start
/// of their binary. The core calls this after setting up the call table.
///
/// Returns: bytes processed (used for completion message)
pub type OperationEntry = unsafe extern "C" fn() -> u64;
