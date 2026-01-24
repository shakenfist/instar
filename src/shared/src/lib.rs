//! Shared types between core and operations.
//!
//! This crate defines the ABI between the core guest and operation binaries.
//! Both the core and operations link against this crate to share type definitions.

#![no_std]

pub mod virtio;

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
    /// Whether the image is marked corrupt
    pub corrupt: bool,
    /// Whether extended L2 entries are used
    pub extended_l2: bool,
    /// Padding for alignment
    pub _pad: [u8; 3],
    /// Number of refcount bits (typically 16)
    pub refcount_bits: u32,
}

impl Qcow2Info {
    /// Create new QCOW2 info with defaults
    pub const fn new() -> Self {
        Self {
            compat: 0,
            compression_type: 0,
            lazy_refcounts: false,
            corrupt: false,
            extended_l2: false,
            _pad: [0; 3],
            refcount_bits: 16,
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
}

impl CallTable {
    /// Magic value indicating a valid call table
    pub const MAGIC: u32 = 0x494D4147; // "IMAG"

    /// Current ABI version (bumped for send_info_result_qcow2 addition)
    pub const VERSION: u32 = 4;
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
        }
    }
}

/// Configuration for the info operation.
///
/// This structure is written to OPERATION_CONFIG_ADDR by the VMM.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InfoConfig {
    /// Magic number to verify config is valid (0x494E464F = "INFO")
    pub magic: u32,

    /// Configuration flags
    pub flags: u32,
}

impl InfoConfig {
    /// Magic value for info config
    pub const MAGIC: u32 = 0x494E464F; // "INFO"

    /// Flag: Report detailed metadata (backing files, encryption, etc.)
    pub const FLAG_DETAILED: u32 = 1 << 0;

    /// Flag: Check for potentially dangerous metadata (backing files, etc.)
    pub const FLAG_SECURITY_CHECK: u32 = 1 << 1;

    /// Create a default config
    pub const fn default_config() -> Self {
        Self {
            magic: Self::MAGIC,
            flags: Self::FLAG_DETAILED | Self::FLAG_SECURITY_CHECK,
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

/// Operation entry point signature.
///
/// Operations must export a function with this signature at the start
/// of their binary. The core calls this after setting up the call table.
///
/// Returns: bytes processed (used for completion message)
pub type OperationEntry = unsafe extern "C" fn() -> u64;
