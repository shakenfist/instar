//! Structured error types for the VMM.
//!
//! This module provides typed errors instead of `Box<dyn std::error::Error>`
//! for better error handling and more informative error messages.

use std::fmt;
use std::io;

/// Top-level VMM error type.
#[derive(Debug)]
#[allow(dead_code)]
pub enum VmmError {
    /// KVM-related errors
    Kvm(KvmError),
    /// Virtio device errors
    Virtio(VirtioError),
    /// Configuration validation errors
    Config(ConfigError),
    /// I/O errors (file operations, backing store)
    Io(io::Error),
    /// Guest binary loading errors
    GuestBinary(String),
}

impl fmt::Display for VmmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmmError::Kvm(e) => write!(f, "KVM error: {}", e),
            VmmError::Virtio(e) => write!(f, "virtio error: {}", e),
            VmmError::Config(e) => write!(f, "configuration error: {}", e),
            VmmError::Io(e) => write!(f, "I/O error: {}", e),
            VmmError::GuestBinary(msg) => write!(f, "guest binary error: {}", msg),
        }
    }
}

impl std::error::Error for VmmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VmmError::Kvm(e) => Some(e),
            VmmError::Virtio(e) => Some(e),
            VmmError::Config(e) => Some(e),
            VmmError::Io(e) => Some(e),
            VmmError::GuestBinary(_) => None,
        }
    }
}

impl From<io::Error> for VmmError {
    fn from(e: io::Error) -> Self {
        VmmError::Io(e)
    }
}

impl From<KvmError> for VmmError {
    fn from(e: KvmError) -> Self {
        VmmError::Kvm(e)
    }
}

impl From<VirtioError> for VmmError {
    fn from(e: VirtioError) -> Self {
        VmmError::Virtio(e)
    }
}

impl From<ConfigError> for VmmError {
    fn from(e: ConfigError) -> Self {
        VmmError::Config(e)
    }
}

/// KVM-related errors.
#[derive(Debug)]
#[allow(dead_code)]
pub enum KvmError {
    /// Failed to open /dev/kvm
    Open(io::Error),
    /// Failed to create a VM
    CreateVm(io::Error),
    /// Failed to create a vCPU
    CreateVcpu(io::Error),
    /// Failed to set up memory region
    SetUserMemoryRegion(io::Error),
    /// Failed to set registers
    SetRegisters(io::Error),
    /// Failed to set special registers
    SetSpecialRegisters(io::Error),
    /// VM entry failed with given reason
    VmEntryFailed { reason: u32, cpu: u32 },
    /// Unexpected VM exit
    UnexpectedExit(String),
}

impl fmt::Display for KvmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KvmError::Open(e) => write!(f, "failed to open /dev/kvm: {}", e),
            KvmError::CreateVm(e) => write!(f, "failed to create VM: {}", e),
            KvmError::CreateVcpu(e) => write!(f, "failed to create vCPU: {}", e),
            KvmError::SetUserMemoryRegion(e) => {
                write!(f, "failed to set user memory region: {}", e)
            }
            KvmError::SetRegisters(e) => write!(f, "failed to set registers: {}", e),
            KvmError::SetSpecialRegisters(e) => {
                write!(f, "failed to set special registers: {}", e)
            }
            KvmError::VmEntryFailed { reason, cpu } => {
                write!(f, "VM entry failed: reason=0x{:x}, cpu={}", reason, cpu)
            }
            KvmError::UnexpectedExit(desc) => write!(f, "unexpected VM exit: {}", desc),
        }
    }
}

impl std::error::Error for KvmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KvmError::Open(e)
            | KvmError::CreateVm(e)
            | KvmError::CreateVcpu(e)
            | KvmError::SetUserMemoryRegion(e)
            | KvmError::SetRegisters(e)
            | KvmError::SetSpecialRegisters(e) => Some(e),
            KvmError::VmEntryFailed { .. } | KvmError::UnexpectedExit(_) => None,
        }
    }
}

/// Virtio device errors.
#[derive(Debug)]
#[allow(dead_code)]
pub enum VirtioError {
    /// Missing required descriptor in chain
    MissingDescriptor(&'static str),
    /// Invalid descriptor flags
    InvalidDescriptorFlags {
        expected: &'static str,
        desc_idx: u16,
    },
    /// Failed to read/write guest memory
    GuestMemory(String),
    /// Backing store I/O error
    BackingIo(io::Error),
    /// Device is read-only but write was attempted
    ReadOnlyDevice,
    /// Invalid sector access
    InvalidSector { sector: u64, capacity: u64 },
}

impl fmt::Display for VirtioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VirtioError::MissingDescriptor(name) => {
                write!(f, "missing {} descriptor", name)
            }
            VirtioError::InvalidDescriptorFlags { expected, desc_idx } => {
                write!(
                    f,
                    "invalid descriptor flags: expected {} at index {}",
                    expected, desc_idx
                )
            }
            VirtioError::GuestMemory(msg) => write!(f, "guest memory error: {}", msg),
            VirtioError::BackingIo(e) => write!(f, "backing store I/O: {}", e),
            VirtioError::ReadOnlyDevice => write!(f, "device is read-only"),
            VirtioError::InvalidSector { sector, capacity } => {
                write!(
                    f,
                    "invalid sector {}: device capacity is {} sectors",
                    sector, capacity
                )
            }
        }
    }
}

impl std::error::Error for VirtioError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VirtioError::BackingIo(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for VirtioError {
    fn from(e: io::Error) -> Self {
        VirtioError::BackingIo(e)
    }
}

/// Configuration validation errors.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ConfigError {
    /// Invalid sector size
    InvalidSectorSize { value: u64, min: u64, max: u64 },
    /// Sector size must be power of 2
    SectorSizeNotPowerOfTwo(u64),
    /// Missing required file
    MissingFile { kind: &'static str, path: String },
    /// File not found
    FileNotFound(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidSectorSize { value, min, max } => {
                write!(
                    f,
                    "sector size {} is out of range [{}, {}]",
                    value, min, max
                )
            }
            ConfigError::SectorSizeNotPowerOfTwo(value) => {
                write!(f, "sector size {} is not a power of 2", value)
            }
            ConfigError::MissingFile { kind, path } => {
                write!(f, "missing {} file: {}", kind, path)
            }
            ConfigError::FileNotFound(path) => write!(f, "file not found: {}", path),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Result type alias using VmmError.
#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, VmmError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_vmm_error_display() {
        let err = VmmError::Config(ConfigError::InvalidSectorSize {
            value: 256,
            min: 512,
            max: 65536,
        });
        assert!(err.to_string().contains("sector size 256"));
    }

    #[test]
    fn test_virtio_error_display() {
        let err = VirtioError::MissingDescriptor("data");
        assert_eq!(err.to_string(), "missing data descriptor");
    }

    #[test]
    fn test_kvm_error_display() {
        let err = KvmError::VmEntryFailed {
            reason: 0x1234,
            cpu: 0,
        };
        assert!(err.to_string().contains("0x1234"));
    }

    #[test]
    fn test_error_chain() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "test");
        let vmm_err = VmmError::from(io_err);
        assert!(vmm_err.source().is_some());
    }
}
