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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use vm_memory::GuestMemoryMmap;

use crate::ioevent::IoEvent;
use crate::stats::VmmStats;
use crate::virtio::VirtioBlockDevice;

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
    /// Create and start a new I/O processing thread.
    ///
    /// The thread will poll the eventfds and process queues until `stop()` is called.
    pub fn new(
        input_device: SharedDevice,
        output_device: SharedDevice,
        input_ioevent: IoEvent,
        output_ioevent: IoEvent,
        guest_mem: Arc<GuestMemoryMmap>,
        stats: SharedStats,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = thread::spawn(move || {
            Self::io_loop(
                running_clone,
                input_device,
                output_device,
                input_ioevent,
                output_ioevent,
                guest_mem,
                stats,
            );
        });

        Self {
            handle: Some(handle),
            running,
        }
    }

    /// The main I/O processing loop.
    fn io_loop(
        running: Arc<AtomicBool>,
        input_device: SharedDevice,
        output_device: SharedDevice,
        input_ioevent: IoEvent,
        output_ioevent: IoEvent,
        guest_mem: Arc<GuestMemoryMmap>,
        stats: SharedStats,
    ) {
        // Set up epoll to wait on both eventfds
        let epoll_fd = match Self::setup_epoll(&input_ioevent, &output_ioevent) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("Failed to set up epoll: {:?}", e);
                return;
            }
        };

        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];

        while running.load(Ordering::Relaxed) {
            // Wait for events with a timeout (so we can check `running`)
            let nfds = unsafe {
                libc::epoll_wait(epoll_fd, events.as_mut_ptr(), events.len() as i32, 100)
            };

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

                if fd == input_ioevent.as_raw_fd() {
                    // Consume the eventfd
                    let _ = input_ioevent.poll();

                    // Process the input queue
                    if let Ok(mut device) = input_device.lock() {
                        device.set_queue_notify();
                        if let Ok(io_stats) = device.process_queue(&guest_mem) {
                            if let Ok(mut s) = stats.lock() {
                                s.record_read(io_stats.bytes_read, io_stats.sectors_read);
                            }
                        }
                    }
                } else if fd == output_ioevent.as_raw_fd() {
                    // Consume the eventfd
                    let _ = output_ioevent.poll();

                    // Process the output queue
                    if let Ok(mut device) = output_device.lock() {
                        device.set_queue_notify();
                        if let Ok(io_stats) = device.process_queue(&guest_mem) {
                            if let Ok(mut s) = stats.lock() {
                                s.record_write(io_stats.bytes_written, io_stats.sectors_written);
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

    /// Set up epoll to monitor the eventfds.
    fn setup_epoll(
        input_ioevent: &IoEvent,
        output_ioevent: &IoEvent,
    ) -> std::io::Result<libc::c_int> {
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Add input eventfd
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: input_ioevent.as_raw_fd() as u64,
        };
        if unsafe {
            libc::epoll_ctl(
                epoll_fd,
                libc::EPOLL_CTL_ADD,
                input_ioevent.as_raw_fd(),
                &mut event,
            )
        } < 0
        {
            unsafe { libc::close(epoll_fd) };
            return Err(std::io::Error::last_os_error());
        }

        // Add output eventfd
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: output_ioevent.as_raw_fd() as u64,
        };
        if unsafe {
            libc::epoll_ctl(
                epoll_fd,
                libc::EPOLL_CTL_ADD,
                output_ioevent.as_raw_fd(),
                &mut event,
            )
        } < 0
        {
            unsafe { libc::close(epoll_fd) };
            return Err(std::io::Error::last_os_error());
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
