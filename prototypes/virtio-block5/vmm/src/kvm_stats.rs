//! KVM binary statistics API support.
//!
//! This module provides access to KVM's binary statistics interface when
//! available. The KVM_GET_STATS_FD ioctl (capability KVM_CAP_BINARY_STATS_FD)
//! provides per-VM and per-vCPU statistics directly from the kernel.
//!
//! # Current Status
//!
//! As of kvm-ioctls 0.19, the `KVM_GET_STATS_FD` ioctl is not yet exposed
//! through the safe Rust API. This module provides:
//!
//! 1. Capability checking to detect if the kernel supports binary stats
//! 2. Structures for parsing the binary stats format
//! 3. A placeholder for future implementation
//!
//! # KVM Statistics Format
//!
//! The statistics file descriptor contains:
//! - Header: metadata about the stats (offsets, counts)
//! - ID string: identifies the VM or vCPU
//! - Descriptors: describes each statistic (name, type, unit)
//! - Data: actual counter values (64-bit unsigned integers)
//!
//! # References
//!
//! - [KVM API Documentation](https://docs.kernel.org/virt/kvm/api.html)
//! - [rust-vmm/kvm](https://github.com/rust-vmm/kvm)

use std::os::unix::io::AsRawFd;

use kvm_ioctls::Kvm;

/// KVM capability for binary statistics (value from Linux kernel headers).
/// This is KVM_CAP_BINARY_STATS_FD = 203.
const KVM_CAP_BINARY_STATS_FD: libc::c_ulong = 203;

/// KVM_CHECK_EXTENSION ioctl request code.
/// Calculated as _IO(KVMIO, 0x03) where KVMIO = 0xAE.
const KVM_CHECK_EXTENSION: libc::c_ulong = 0xAE03;

/// Statistics types (bits 0-3 of descriptor flags).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatsType {
    /// Cumulative counter (monotonically increasing).
    Cumulative = 0,
    /// Instantaneous value.
    Instant = 1,
    /// Peak (maximum) value seen.
    Peak = 2,
    /// Linear histogram.
    LinearHist = 3,
    /// Logarithmic histogram.
    LogHist = 4,
}

/// Statistics units (bits 4-7 of descriptor flags).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatsUnit {
    /// No unit (simple counter).
    None = 0,
    /// Bytes.
    Bytes = 1,
    /// Seconds.
    Seconds = 2,
    /// CPU cycles.
    Cycles = 3,
    /// Boolean (0 or 1).
    Boolean = 4,
}

/// Statistics base scaling (bits 8-11 of descriptor flags).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatsBase {
    /// Power of 10 scaling.
    Pow10 = 0,
    /// Power of 2 scaling.
    Pow2 = 1,
}

/// Parsed statistics descriptor.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct StatsDescriptor {
    /// Name of the statistic.
    pub name: String,
    /// Type of statistic.
    pub stats_type: StatsType,
    /// Unit of measurement.
    pub unit: StatsUnit,
    /// Base for scaling.
    pub base: StatsBase,
    /// Exponent for scaling.
    pub exponent: i16,
    /// Number of values (>1 for histograms).
    pub size: u16,
    /// Offset in the data block.
    pub offset: u32,
    /// Bucket size for linear histograms.
    pub bucket_size: u32,
}

/// KVM binary statistics support checker.
pub struct KvmStatsChecker {
    supported: bool,
}

impl KvmStatsChecker {
    /// Check if KVM binary statistics are supported.
    pub fn new(kvm: &Kvm) -> Self {
        // Check if the capability is available using raw ioctl.
        // KVM_CAP_BINARY_STATS_FD (203) is not yet exposed in kvm-ioctls,
        // so we use a direct ioctl call.
        let ret = unsafe {
            libc::ioctl(
                kvm.as_raw_fd(),
                KVM_CHECK_EXTENSION,
                KVM_CAP_BINARY_STATS_FD,
            )
        };
        let supported = ret > 0;
        Self { supported }
    }

    /// Returns true if KVM binary statistics are supported.
    #[allow(dead_code)]
    pub fn is_supported(&self) -> bool {
        self.supported
    }

    /// Display capability status.
    pub fn display_status(&self) {
        if self.supported {
            println!("KVM binary statistics: supported");
            println!("  Note: kvm-ioctls 0.19 does not expose stats_fd() yet.");
            println!("  Using internal VMM counters for statistics.");
        } else {
            println!("KVM binary statistics: not supported by kernel");
            println!("  Using internal VMM counters for statistics.");
        }
    }
}

/// Placeholder for future KVM statistics reader.
///
/// When kvm-ioctls exposes `VcpuFd::stats_fd()`, this struct will provide
/// methods to read and parse the binary statistics.
#[allow(dead_code)]
pub struct KvmStatsReader {
    // Will hold the stats file descriptor when available
    // stats_fd: RawFd,
    descriptors: Vec<StatsDescriptor>,
}

#[allow(dead_code)]
impl KvmStatsReader {
    /// Read statistics data.
    ///
    /// Returns a map of statistic name to value(s).
    pub fn read_stats(&self) -> std::collections::HashMap<String, Vec<u64>> {
        // Placeholder - will read from stats_fd when available
        std::collections::HashMap::new()
    }

    /// Get all descriptor names.
    pub fn stat_names(&self) -> Vec<&str> {
        self.descriptors.iter().map(|d| d.name.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_types() {
        assert_eq!(StatsType::Cumulative as u8, 0);
        assert_eq!(StatsType::Instant as u8, 1);
        assert_eq!(StatsType::Peak as u8, 2);
    }

    #[test]
    fn test_stats_units() {
        assert_eq!(StatsUnit::None as u8, 0);
        assert_eq!(StatsUnit::Bytes as u8, 1);
        assert_eq!(StatsUnit::Seconds as u8, 2);
    }
}
