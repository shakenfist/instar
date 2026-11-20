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
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, JoinHandle};

use vm_memory::GuestMemoryMmap;

use crate::ioevent::IoEvent;
use crate::stats::VmmStats;
use crate::virtio::VirtioBlockDevice;

/// The signal that takes the vCPU thread out of `KVM_RUN`.
///
/// `SIGUSR1` is what QEMU uses for the same job (its `SIG_IPI`). The
/// handler does nothing: interrupting the ioctl is the whole point, and
/// `KVM_RUN` returning `EINTR` is what the run loop needs to see.
const KICK_SIGNAL: libc::c_int = libc::SIGUSR1;

static KICK_HANDLER: Once = Once::new();

/// Whether [`arm_kick_signal`] installed the handler.
static KICK_ARMED: AtomicBool = AtomicBool::new(false);

extern "C" fn kick_handler(_signum: libc::c_int) {}

/// Install the kick handler, once per process; report whether kicking
/// is now safe.
///
/// The default action for `SIGUSR1` is to terminate the process, so a
/// kick sent before the handler is installed would kill the run instead
/// of ending the wait. Nothing may kick until this has returned true.
fn arm_kick_signal() -> bool {
    KICK_HANDLER.call_once(|| {
        // SAFETY: `action` is fully initialized before sigaction reads
        // it, and sigaction is given a valid pointer to it and a null
        // old-action pointer.
        let installed = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = kick_handler as *const () as libc::sighandler_t;
            // No flags are needed. SA_RESTART is the one worth saying
            // something about, and it would make no difference either
            // way: KVM returns -EINTR from KVM_RUN when a signal is
            // pending, rather than the ERESTARTSYS that asks the kernel
            // to restart the call, so the ioctl always comes back to the
            // run loop. (poll(2), which the test for this blocks in, is
            // never restarted either, so no test can tell the flag's
            // setting apart.)
            action.sa_flags = 0;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(KICK_SIGNAL, &action, std::ptr::null_mut()) == 0
        };
        KICK_ARMED.store(installed, Ordering::SeqCst);
    });
    KICK_ARMED.load(Ordering::SeqCst)
}

/// A failure the I/O thread has no other way to report.
///
/// `VirtioBlockDevice::process_queue` completes a request it cannot
/// *service* with an error status, which the guest sees. A virtqueue it
/// cannot *read* -- a malformed descriptor chain, or a descriptor naming
/// an address outside guest memory -- is different: there is no status
/// descriptor it can trust, so nothing is written to the used ring and
/// the guest's wait for that request never ends. Since the guest's wait
/// became unbounded that is a hang rather than a bogus timeout, and the
/// I/O thread cannot fail the run by itself (issue #932).
///
/// So the failure is carried here instead. The I/O thread records it and
/// kicks the vCPU out of `KVM_RUN`; the run loop sees the interrupt,
/// finds the message and fails the run with it. That also makes the two
/// queue-service paths agree, where before the behaviour depended on
/// whether `IoEvent::register` had succeeded: the vCPU-exit fallback
/// propagated the same error and did fail the run.
///
/// Every trigger is an instar bug rather than anything a hostile image
/// can ask for -- the guest builds its own descriptor chains, and their
/// addresses come from its own fixed DMA pool -- so this is about
/// failing honestly rather than about defence.
pub struct FatalIoError {
    /// The first failure recorded. Later ones are dropped: the first is
    /// the one that explains the run, and the queue may well fail again
    /// in the same way before the vCPU gets out of `KVM_RUN`.
    message: Mutex<Option<String>>,
    /// The thread to kick, captured when the I/O thread is created,
    /// which every operation does on the thread that then runs the vCPU.
    vcpu_thread: libc::pthread_t,
    /// Whether the kick signal has a handler, so sending it ends a wait
    /// rather than killing the process.
    kick_armed: bool,
}

impl FatalIoError {
    /// Capture the calling thread as the one to kick.
    fn for_this_thread() -> Self {
        Self {
            message: Mutex::new(None),
            // SAFETY: pthread_self takes no arguments and cannot fail.
            vcpu_thread: unsafe { libc::pthread_self() },
            kick_armed: arm_kick_signal(),
        }
    }

    /// Record a failure and kick the vCPU thread.
    fn record(&self, message: String) {
        if let Ok(mut slot) = self.message.lock() {
            if slot.is_none() {
                *slot = Some(message);
            }
        }
        self.kick();
    }

    /// Take the vCPU out of `KVM_RUN`, if there is a failure to see.
    ///
    /// Sent repeatedly rather than once: a signal that arrives in the
    /// moment before the vCPU enters `KVM_RUN` is simply lost, and the
    /// guest would then spin on a request that will never complete. The
    /// I/O loop calls this on every wake while a failure is recorded, so
    /// the next one lands.
    fn kick(&self) {
        if !self.kick_armed {
            return;
        }
        // SAFETY: `vcpu_thread` is the id of the thread that created
        // this I/O thread, which outlives it: the run loop owns the
        // `IoThread` and joins it before returning. The signal has a
        // handler (`kick_armed`).
        unsafe {
            libc::pthread_kill(self.vcpu_thread, KICK_SIGNAL);
        }
    }

    /// Whether a failure has been recorded.
    fn is_set(&self) -> bool {
        self.message.lock().map(|m| m.is_some()).unwrap_or(false)
    }

    /// The recorded failure, if any.
    pub fn message(&self) -> Option<String> {
        self.message.lock().ok().and_then(|m| m.clone())
    }
}

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
    fatal: Arc<FatalIoError>,
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

        // Captured here, on the caller's thread, because every operation
        // creates its I/O thread on the thread that then runs the vCPU.
        let fatal = Arc::new(FatalIoError::for_this_thread());
        let fatal_clone = Arc::clone(&fatal);

        let handle = thread::spawn(move || {
            Self::io_loop(running_clone, devices, guest_mem, stats, fatal_clone);
        });

        Self {
            handle: Some(handle),
            running,
            fatal,
        }
    }

    /// The failure the I/O thread could not report any other way.
    ///
    /// The run loop reads this when its vCPU comes out of `KVM_RUN`
    /// without a reason of its own, which is how a recorded failure
    /// reaches the user instead of hanging the run.
    pub fn fatal_error(&self) -> Option<String> {
        self.fatal.message()
    }

    /// The main I/O processing loop.
    fn io_loop(
        running: Arc<AtomicBool>,
        devices: Vec<IoDevice>,
        guest_mem: Arc<GuestMemoryMmap>,
        stats: SharedStats,
        fatal: Arc<FatalIoError>,
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
                eprintln!("Failed to set up epoll: {e:?}");
                return;
            }
        };

        // Allocate enough space for all devices
        let max_events = devices.len();
        let mut events: Vec<libc::epoll_event> =
            vec![libc::epoll_event { events: 0, u64: 0 }; max_events];

        while running.load(Ordering::Acquire) {
            // Keep kicking while a failure is recorded and the run loop
            // has not acted on it yet. The vCPU may have been between
            // two `KVM_RUN` entries when the first kick was sent, in
            // which case the signal was lost and the guest is spinning
            // on a request that will never complete; the next kick, one
            // epoll timeout later, lands.
            if fatal.is_set() {
                fatal.kick();
            }

            // Wait for events with a timeout (so we can check `running`)
            // SAFETY: epoll_fd is a valid epoll FD from epoll_create1().
            // events has capacity for max_events epoll_event structs.
            let nfds =
                unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), max_events as i32, 100) };

            if nfds < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                eprintln!("epoll_wait error: {err:?}");
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
                        match device.process_queue(&guest_mem) {
                            Ok(io_stats) => {
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
                            // A request this device could not service is
                            // completed with an error status and never
                            // reaches here, so what does is a virtqueue
                            // the device could not read: a malformed
                            // descriptor chain or an unmapped guest
                            // address. Nothing was written to the used
                            // ring, so the guest's wait for this request
                            // will not end on its own. Hand the failure
                            // to the run loop, which is the only place
                            // that can fail the run, and take the vCPU
                            // out of `KVM_RUN` so it gets there.
                            Err(e) => {
                                fatal.record(format!(
                                    "the host could not read device {dev_idx}'s virtqueue: {e}"
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Clean up
        // SAFETY: epoll_fd is a valid open FD, closed exactly once here.
        unsafe {
            libc::close(epoll_fd);
        }
    }

    /// Set up epoll to monitor all device eventfds.
    fn setup_epoll(devices: &[IoDevice]) -> std::io::Result<libc::c_int> {
        // SAFETY: epoll_create1 is a simple syscall; return value is
        // checked for errors immediately below.
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        for io_device in devices {
            let mut event = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: io_device.ioevent.as_raw_fd() as u64,
            };
            // SAFETY: epoll_fd and ioevent FD are valid; event struct is
            // fully initialized on the stack. Error checked below.
            if unsafe {
                libc::epoll_ctl(
                    epoll_fd,
                    libc::EPOLL_CTL_ADD,
                    io_device.ioevent.as_raw_fd(),
                    &mut event,
                )
            } < 0
            {
                // SAFETY: epoll_fd is valid; closing on error before return.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The first failure is the one that explains the run. The queue may
    /// fail again in the same way before the vCPU is out of `KVM_RUN`,
    /// and those later failures must not overwrite it.
    #[test]
    fn only_the_first_failure_is_kept() {
        let fatal = FatalIoError::for_this_thread();
        assert!(!fatal.is_set());
        assert!(fatal.message().is_none());

        fatal.record("the host could not read device 0's virtqueue".to_string());
        fatal.record("a second, later failure".to_string());

        assert!(fatal.is_set());
        assert_eq!(
            fatal.message().as_deref(),
            Some("the host could not read device 0's virtqueue")
        );
    }

    /// Recording a failure must take the recorded thread out of the
    /// syscall it is blocked in -- which for the real vCPU thread is
    /// `KVM_RUN`, and here is a `poll` with nothing to report.
    ///
    /// Without the kick the guest spins on a request that will never
    /// complete and the run hangs, which is the whole of issue #932, so
    /// this asserts the interruption rather than only the bookkeeping.
    /// The wait is bounded so a kick that stops working fails the test
    /// instead of hanging the suite.
    #[test]
    fn recording_a_failure_interrupts_the_waiting_thread() {
        let fatal = Arc::new(FatalIoError::for_this_thread());
        assert!(
            fatal.kick_armed,
            "the kick signal has no handler, so sending it would kill the \
             process rather than end a wait"
        );

        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe is given a pointer to two writable ints.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

        let recorder = {
            let fatal = Arc::clone(&fatal);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                fatal.record("the host could not read the virtqueue".to_string());
            })
        };

        // Nothing is ever written to the pipe, so this poll can only end
        // by being interrupted or by timing out.
        let mut pollfd = libc::pollfd {
            fd: fds[0],
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd, count 1, millisecond timeout.
        let polled = unsafe { libc::poll(&mut pollfd, 1, 2_000) };
        let errno = std::io::Error::last_os_error();

        recorder.join().expect("recording thread panicked");
        // SAFETY: both ends were opened by the pipe call above and are
        // closed exactly once here.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        assert_eq!(
            polled, -1,
            "the wait ended with {polled} rather than being interrupted: a \
             kick that no longer interrupts the vCPU leaves the guest \
             spinning on a request that will never complete"
        );
        assert_eq!(
            errno.kind(),
            std::io::ErrorKind::Interrupted,
            "the wait failed with {errno} rather than EINTR"
        );
        assert_eq!(
            fatal.message().as_deref(),
            Some("the host could not read the virtqueue")
        );
    }
}
