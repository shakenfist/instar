//! I/O processing thread for virtio devices.
//!
//! This module provides a separate thread for processing virtqueue requests
//! when using ioeventfd. The thread polls the eventfds and processes queues
//! while the vCPU continues running.
//!
//! # Architecture
//!
//! ```text
//! Main Thread (vCPU)          I/O Thread
//! ─────────────────          ──────────────
//!      vcpu.run() ───────────> polls eventfds
//!           │                       │
//!      MMIO exits                   │ eventfd signaled
//!           │                       ▼
//!           │               process_queue()
//!           │               update used ring
//!           │               set interrupt_status
//!           │                       │
//!      read INTERRUPT_STATUS <──────┘
//! ```
//!
//! # Device Configuration
//!
//! The I/O thread supports variable numbers of devices per operation:
//! - `info`: 1 read-only input device
//! - `copy`: 1 read-only input + 1 read-write output
//! - Future operations may use multiple input devices (e.g., for backing files)

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use vm_memory::GuestMemoryMmap;

use crate::ioevent::IoEvent;
use crate::stats::VmmStats;
use crate::virtio::VirtioBlockDevice;

/// Role of a virtio-block device in an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    /// Primary input device (read-only).
    Input,
    /// Output device (read-write).
    Output,
    /// Backing file device (read-only, for COW images).
    /// The u32 is the backing level (0 = immediate backing, 1 = backing's backing, etc.)
    /// Reserved for future use when handling COW image chains.
    #[allow(dead_code)]
    Backing(u32),
}

impl DeviceRole {
    /// Returns true if this device role primarily performs reads.
    pub fn is_read_device(&self) -> bool {
        matches!(self, DeviceRole::Input | DeviceRole::Backing(_))
    }

    /// Returns true if this device role primarily performs writes.
    pub fn is_write_device(&self) -> bool {
        matches!(self, DeviceRole::Output)
    }
}

/// A configured device with its eventfd for the I/O thread.
pub struct IoDevice {
    /// Role of this device in the operation.
    pub role: DeviceRole,
    /// The virtio-block device (shared with main thread for MMIO handling).
    pub device: SharedDevice,
    /// The ioeventfd for queue notifications.
    pub ioevent: IoEvent,
}

/// Handle to the I/O processing thread.
pub struct IoThread {
    handle: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

/// Shared state for a virtio device that can be accessed from multiple threads.
pub type SharedDevice = Arc<Mutex<VirtioBlockDevice>>;

/// Shared statistics that can be accessed from multiple threads.
pub type SharedStats = Arc<Mutex<VmmStats>>;

impl IoThread {
    /// Create and start a new I/O processing thread for the given devices.
    ///
    /// The thread will poll the eventfds and process queues until `stop()` is called.
    /// Supports any number of devices with different roles.
    pub fn new(
        devices: Vec<IoDevice>,
        guest_mem: Arc<GuestMemoryMmap>,
        stats: SharedStats,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = thread::spawn(move || {
            Self::io_loop(running_clone, devices, guest_mem, stats);
        });

        Self {
            handle: Some(handle),
            running,
        }
    }

    /// The main I/O processing loop.
    fn io_loop(
        running: Arc<AtomicBool>,
        devices: Vec<IoDevice>,
        guest_mem: Arc<GuestMemoryMmap>,
        stats: SharedStats,
    ) {
        if devices.is_empty() {
            eprintln!("IoThread: no devices configured");
            return;
        }

        // Build a map from eventfd raw_fd to device index for quick lookup
        let mut fd_to_device: HashMap<i32, usize> = HashMap::new();
        for (idx, dev) in devices.iter().enumerate() {
            fd_to_device.insert(dev.ioevent.as_raw_fd(), idx);
        }

        // Set up epoll to wait on all eventfds
        let epoll_fd = match Self::setup_epoll(&devices) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("Failed to set up epoll: {:?}", e);
                return;
            }
        };

        // Allocate enough space for all devices
        let max_events = devices.len();
        let mut events: Vec<libc::epoll_event> =
            vec![libc::epoll_event { events: 0, u64: 0 }; max_events];

        while running.load(Ordering::Acquire) {
            // Wait for events with a timeout (so we can check `running`)
            let nfds =
                unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), max_events as i32, 100) };

            if nfds < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                eprintln!("epoll_wait error: {:?}", err);
                break;
            }

            for event in events.iter().take(nfds as usize) {
                let fd = event.u64 as i32;

                // Look up which device this eventfd belongs to
                if let Some(&dev_idx) = fd_to_device.get(&fd) {
                    let io_device = &devices[dev_idx];

                    // Consume the eventfd
                    let _ = io_device.ioevent.poll();

                    // Process the queue
                    if let Ok(mut device) = io_device.device.lock() {
                        device.set_queue_notify();
                        if let Ok(io_stats) = device.process_queue(&guest_mem) {
                            if let Ok(mut s) = stats.lock() {
                                // Record stats based on device role
                                if io_device.role.is_read_device() {
                                    s.record_read(io_stats.bytes_read, io_stats.sectors_read);
                                }
                                if io_device.role.is_write_device() {
                                    s.record_write(
                                        io_stats.bytes_written,
                                        io_stats.sectors_written,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Clean up
        unsafe {
            libc::close(epoll_fd);
        }
    }

    /// Set up epoll to monitor all device eventfds.
    fn setup_epoll(devices: &[IoDevice]) -> std::io::Result<libc::c_int> {
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        for io_device in devices {
            let mut event = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: io_device.ioevent.as_raw_fd() as u64,
            };
            if unsafe {
                libc::epoll_ctl(
                    epoll_fd,
                    libc::EPOLL_CTL_ADD,
                    io_device.ioevent.as_raw_fd(),
                    &mut event,
                )
            } < 0
            {
                unsafe { libc::close(epoll_fd) };
                return Err(std::io::Error::last_os_error());
            }
        }

        Ok(epoll_fd)
    }

    /// Stop the I/O thread and wait for it to finish.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for IoThread {
    fn drop(&mut self) {
        self.stop();
    }
}
