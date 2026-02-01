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
}

/// Backing format type for QCOW2 header extension
#[repr(u8)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
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

impl CallTable {
    /// Magic value indicating a valid call table
    pub const MAGIC: u32 = 0x494D4147; // "IMAG"

    /// Current ABI version (bumped for send_info_result_vdi addition)
    pub const VERSION: u32 = 6;
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

    /// Flag: Enable unsafe quirks mode (accept any file as RAW without
    /// partition table validation). This matches qemu-img behavior but
    /// introduces security vulnerabilities. Use only for compatibility testing.
    pub const FLAG_UNSAFE_QUIRKS: u32 = 1 << 2;

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

    /// Check if unsafe quirks mode is enabled
    ///
    /// When enabled, any file will be accepted as a valid RAW image,
    /// matching qemu-img's insecure behavior. When disabled (default),
    /// files must have a valid partition table to be accepted as RAW.
    pub fn unsafe_quirks_enabled(&self) -> bool {
        (self.flags & Self::FLAG_UNSAFE_QUIRKS) != 0
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

/// Operation entry point signature.
///
/// Operations must export a function with this signature at the start
/// of their binary. The core calls this after setting up the call table.
///
/// Returns: bytes processed (used for completion message)
pub type OperationEntry = unsafe extern "C" fn() -> u64;
