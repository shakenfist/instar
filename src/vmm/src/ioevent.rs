//! I/O event handling for virtio devices.
//!
//! This module provides eventfd-based notification for virtqueue operations,
//! allowing queue notifications to be handled without full VM exits.
//!
//! # How ioeventfd Works
//!
//! 1. Create an eventfd for each virtqueue
//! 2. Register the eventfd with KVM for the QUEUE_NOTIFY MMIO address
//! 3. When guest writes to QUEUE_NOTIFY, KVM signals the eventfd
//! 4. VMM polls the eventfd to know when to process the queue
//!
//! This avoids the overhead of a full VM exit for queue notifications.

use std::os::unix::io::{AsRawFd, RawFd};

use kvm_bindings::kvm_ioeventfd;
use kvm_ioctls::VmFd;
use log::warn;
use vmm_sys_util::eventfd::EventFd;

/// KVM_IOEVENTFD ioctl number.
/// Calculated as: _IOW(KVMIO, 0x79, struct kvm_ioeventfd)
/// where KVMIO = 0xAE, and sizeof(kvm_ioeventfd) = 64 on x86_64.
/// Formula: (1 << 30) | (0xAE << 8) | 0x79 | (64 << 16) = 0x4040AE79
const KVM_IOEVENTFD: libc::c_ulong = 0x4040_AE79;

/// ioeventfd registration flags
const KVM_IOEVENTFD_FLAG_DATAMATCH: u32 = 1;
#[allow(dead_code)]
const KVM_IOEVENTFD_FLAG_PIO: u32 = 2;
const KVM_IOEVENTFD_FLAG_DEASSIGN: u32 = 4;

/// QUEUE_NOTIFY register offset (from shared crate)
const QUEUE_NOTIFY_OFFSET: u64 = shared::virtio::reg::QUEUE_NOTIFY;

/// Manages ioeventfd for a virtio device's queue notification.
pub struct IoEvent {
    /// The eventfd that gets signaled on queue notification
    eventfd: EventFd,
    /// MMIO base address of the device
    mmio_base: u64,
    /// Whether this ioevent is registered with KVM
    registered: bool,
}

impl IoEvent {
    /// Create a new IoEvent for a device at the given MMIO base address.
    pub fn new(mmio_base: u64) -> std::io::Result<Self> {
        let eventfd = EventFd::new(libc::EFD_NONBLOCK)?;
        Ok(Self {
            eventfd,
            mmio_base,
            registered: false,
        })
    }

    /// Register this ioevent with KVM.
    ///
    /// After registration, writes to the QUEUE_NOTIFY register will signal
    /// the eventfd instead of causing a VM exit.
    pub fn register(&mut self, vm: &VmFd) -> std::io::Result<()> {
        if self.registered {
            return Ok(());
        }

        let notify_addr = self.mmio_base + QUEUE_NOTIFY_OFFSET;

        let ioeventfd = kvm_ioeventfd {
            datamatch: 0,
            len: 4, // 32-bit write
            addr: notify_addr,
            fd: self.eventfd.as_raw_fd(),
            flags: 0, // No datamatch, MMIO (not PIO)
            ..Default::default()
        };

        // SAFETY: The kvm_ioeventfd struct is properly initialized
        let ret = unsafe { libc::ioctl(vm.as_raw_fd(), KVM_IOEVENTFD, &ioeventfd) };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.registered = true;
        Ok(())
    }

    /// Unregister this ioevent from KVM.
    #[allow(dead_code)]
    pub fn unregister(&mut self, vm: &VmFd) -> std::io::Result<()> {
        if !self.registered {
            return Ok(());
        }

        let notify_addr = self.mmio_base + QUEUE_NOTIFY_OFFSET;

        let ioeventfd = kvm_ioeventfd {
            datamatch: 0,
            len: 4,
            addr: notify_addr,
            fd: self.eventfd.as_raw_fd(),
            flags: KVM_IOEVENTFD_FLAG_DEASSIGN,
            ..Default::default()
        };

        let ret = unsafe { libc::ioctl(vm.as_raw_fd(), KVM_IOEVENTFD, &ioeventfd) };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.registered = false;
        Ok(())
    }

    /// Check if the eventfd has been signaled (non-blocking).
    ///
    /// Returns the number of signals if any, or None if no signal pending.
    pub fn poll(&self) -> Option<u64> {
        match self.eventfd.read() {
            Ok(count) => Some(count),
            Err(_) => None,
        }
    }

    /// Get the raw file descriptor for use with poll/epoll.
    #[allow(dead_code)]
    pub fn as_raw_fd(&self) -> RawFd {
        self.eventfd.as_raw_fd()
    }

    /// Check if this ioevent is registered with KVM.
    #[allow(dead_code)]
    pub fn is_registered(&self) -> bool {
        self.registered
    }
}

impl Drop for IoEvent {
    fn drop(&mut self) {
        // Note: We can't unregister here because we don't have the VmFd.
        // The caller should ensure unregister() is called before dropping.
        if self.registered {
            warn!(
                "IoEvent dropped while still registered (mmio_base=0x{:x})",
                self.mmio_base
            );
        }
    }
}

/// Manages ioeventfd with datamatch for specific queue notifications.
///
/// This variant only triggers when a specific value is written to QUEUE_NOTIFY,
/// allowing per-queue eventfds when multiple queues are used.
#[allow(dead_code)]
pub struct IoEventWithMatch {
    eventfd: EventFd,
    mmio_base: u64,
    queue_index: u32,
    registered: bool,
}

#[allow(dead_code)]
impl IoEventWithMatch {
    /// Create a new IoEvent that only triggers for a specific queue index.
    pub fn new(mmio_base: u64, queue_index: u32) -> std::io::Result<Self> {
        let eventfd = EventFd::new(libc::EFD_NONBLOCK)?;
        Ok(Self {
            eventfd,
            mmio_base,
            queue_index,
            registered: false,
        })
    }

    /// Register with KVM using datamatch for the queue index.
    pub fn register(&mut self, vm: &VmFd) -> std::io::Result<()> {
        if self.registered {
            return Ok(());
        }

        let notify_addr = self.mmio_base + QUEUE_NOTIFY_OFFSET;

        let ioeventfd = kvm_ioeventfd {
            datamatch: self.queue_index as u64,
            len: 4,
            addr: notify_addr,
            fd: self.eventfd.as_raw_fd(),
            flags: KVM_IOEVENTFD_FLAG_DATAMATCH,
            ..Default::default()
        };

        let ret = unsafe { libc::ioctl(vm.as_raw_fd(), KVM_IOEVENTFD, &ioeventfd) };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.registered = true;
        Ok(())
    }

    /// Unregister from KVM.
    pub fn unregister(&mut self, vm: &VmFd) -> std::io::Result<()> {
        if !self.registered {
            return Ok(());
        }

        let notify_addr = self.mmio_base + QUEUE_NOTIFY_OFFSET;

        let ioeventfd = kvm_ioeventfd {
            datamatch: self.queue_index as u64,
            len: 4,
            addr: notify_addr,
            fd: self.eventfd.as_raw_fd(),
            flags: KVM_IOEVENTFD_FLAG_DATAMATCH | KVM_IOEVENTFD_FLAG_DEASSIGN,
            ..Default::default()
        };

        let ret = unsafe { libc::ioctl(vm.as_raw_fd(), KVM_IOEVENTFD, &ioeventfd) };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.registered = false;
        Ok(())
    }

    /// Check if the eventfd has been signaled.
    pub fn poll(&self) -> Option<u64> {
        match self.eventfd.read() {
            Ok(count) => Some(count),
            Err(_) => None,
        }
    }

    /// Get the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.eventfd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioevent_creation() {
        let ioevent = IoEvent::new(0x10000000);
        assert!(ioevent.is_ok());
        let ioevent = ioevent.unwrap();
        assert!(!ioevent.is_registered());
    }

    #[test]
    fn test_ioevent_fd_valid() {
        let ioevent = IoEvent::new(0x10000000).unwrap();
        assert!(ioevent.as_raw_fd() >= 0);
    }
}
