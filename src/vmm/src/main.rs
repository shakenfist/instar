//! KVM VMM with separate core and operation binaries.
//!
//! This VMM loads two separate binaries:
//! - Core binary (0x10000): Device initialization, call table setup
//! - Operation binary (0x20000): Specific operation (copy, info, etc.)
//!
//! The core initializes virtio-block devices and sets up a call table at
//! 0x18000 with function pointers for I/O operations. The operation binary
//! reads this call table to perform its work.
//!
//! This architecture reduces attack surface by only loading the operation
//! needed for the current task.
//!
//! Features:
//! - Input virtio-block device (read-only)
//! - Optional output virtio-block device (writable, for copy operations)
//! - Configurable sector sizes
//! - Sparse output files (grow on demand)
//! - ioeventfd optimization for queue notifications
//! - InfoResult reading for info operations

mod backing;
mod chain;
mod config;
mod error;
mod io_thread;
mod ioevent;
mod kvm_stats;
mod stats;
mod version;
mod virtio;

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};

use clap::{Args, Parser, Subcommand};
use guest_protocol::{
    decode_framed, encode_vmm_config_framed, guest_, vmm_config, vmm_config_chain,
    vmm_config_chain_with_output, vmm_config_input_only, FRAME_HEADER_SIZE,
};
use kvm_bindings::{kvm_regs, kvm_segment, kvm_sregs, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit};
use log::{debug, info, warn};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use backing::BackingStore;
use chain::{
    check_chain_depth, check_circular_reference, validate_backing_path, BackingChain, ChainError,
    ChainImage, ImageFormat, InfoOperationResult,
};
use io_thread::{DeviceRole, IoDevice};
use ioevent::IoEvent;
use stats::VmmStats;
use virtio::VirtioBlockDevice;

// Memory layout constants (import shared ones from the shared crate)
const GDT_BASE: u64 = 0x1000;
const PAGE_TABLE_BASE: u64 = 0x2000;
const GUEST_CODE_BASE: u64 = 0x10000;
const OPERATION_LOAD_ADDR: u64 = shared::OPERATION_LOAD_ADDR as u64;
const OPERATION_CONFIG_ADDR: u64 = shared::OPERATION_CONFIG_ADDR as u64;
#[allow(dead_code)] // Infrastructure for Phase 1+ (check, compare, convert)
const CHAIN_CONFIG_ADDR: u64 = shared::CHAIN_CONFIG_ADDR as u64;

// CopyConfig constants (must match shared crate)
const COPY_CONFIG_MAGIC: u32 = 0x434F5059; // "COPY"
const COPY_CONFIG_FLAG_VERIFY: u32 = 1 << 0;
const COPY_CONFIG_FLAG_SKIP_ZEROS: u32 = 1 << 1;
#[allow(dead_code)]
const COPY_CONFIG_FLAG_VERBOSE: u32 = 1 << 31;

// InfoConfig constants (must match shared crate)
const INFO_CONFIG_MAGIC: u32 = 0x494E464F; // "INFO"
const INFO_CONFIG_FLAG_DETAILED: u32 = 1 << 0;
const INFO_CONFIG_FLAG_SECURITY_CHECK: u32 = 1 << 1;
const INFO_CONFIG_FLAG_UNSAFE_QUIRKS: u32 = 1 << 2;
const INFO_CONFIG_FLAG_EXTRA_DETAIL: u32 = 1 << 3;
const INFO_CONFIG_FLAG_VERBOSE: u32 = 1 << 31;

// CheckConfig constants (must match shared crate)
const CHECK_CONFIG_MAGIC: u32 = 0x43484543; // "CHEC"
#[allow(dead_code)]
const CHECK_CONFIG_FLAG_REPAIR: u32 = 1 << 0;
#[allow(dead_code)]
const CHECK_CONFIG_FLAG_QUIET: u32 = 1 << 1;
#[allow(dead_code)]
const CHECK_CONFIG_FLAG_UNSAFE_QUIRKS: u32 = 1 << 2;
const CHECK_CONFIG_FLAG_CHAIN: u32 = 1 << 3;
#[allow(dead_code)]
const CHECK_CONFIG_FLAG_VERBOSE: u32 = 1 << 31;

// CompareConfig constants (must match shared crate)
const COMPARE_CONFIG_MAGIC: u32 = 0x434D5052; // "CMPR"
const COMPARE_CONFIG_FLAG_STRICT: u32 = 1 << 0;
#[allow(dead_code)]
const COMPARE_CONFIG_FLAG_QUIET: u32 = 1 << 1;
#[allow(dead_code)]
const COMPARE_CONFIG_FLAG_VERBOSE: u32 = 1 << 31;

// ConvertConfig constants (must match shared crate)
const CONVERT_CONFIG_MAGIC: u32 = 0x434F4E56; // "CONV"
const CONVERT_CONFIG_FLAG_SKIP_ZEROS: u32 = 1 << 0;
#[allow(dead_code)]
const CONVERT_CONFIG_FLAG_VERBOSE: u32 = 1 << 31;

// CheckResult flag constants (must match shared crate)
const CHECK_RESULT_FLAG_VALID: u32 = 1 << 0;
#[allow(dead_code)]
const CHECK_RESULT_FLAG_HAS_LEAKS: u32 = 1 << 1;
#[allow(dead_code)]
const CHECK_RESULT_FLAG_HAS_CORRUPTIONS: u32 = 1 << 2;
#[allow(dead_code)]
const CHECK_RESULT_FLAG_DIRTY: u32 = 1 << 3;
#[allow(dead_code)]
const CHECK_RESULT_FLAG_CORRUPT_BIT: u32 = 1 << 4;
#[allow(dead_code)]
const CHECK_RESULT_FLAG_INCOMPLETE: u32 = 1 << 5;
const CHECK_RESULT_FLAG_NOT_SUPPORTED: u32 = 1 << 6;

// ChainConfig constants (must match shared crate)
// These are used by write_chain_config() which is infrastructure for Phase 1+
#[allow(dead_code)]
const CHAIN_CONFIG_MAGIC: u32 = 0x4348414E; // "CHAN"
#[allow(dead_code)]
const CHAIN_CONFIG_VERSION: u32 = 1;
#[allow(dead_code)]
const MAX_CHAIN_DEVICES: usize = 16;

// InfoResult constants (must match shared crate)
// These are defined for future use when parsing results from guest
#[allow(dead_code)]
const INFO_RESULT_MAGIC: u32 = 0x52455355; // "RESU"
#[allow(dead_code)]
const INFO_RESULT_FLAG_HAS_BACKING_FILE: u32 = 1 << 0;
#[allow(dead_code)]
const INFO_RESULT_FLAG_HAS_EXTERNAL_DATA: u32 = 1 << 1;
#[allow(dead_code)]
const INFO_RESULT_FLAG_ENCRYPTED: u32 = 1 << 2;
#[allow(dead_code)]
const INFO_RESULT_FLAG_COMPRESSED: u32 = 1 << 3;
#[allow(dead_code)]
const INFO_RESULT_FLAG_HAS_SNAPSHOTS: u32 = 1 << 4;
#[allow(dead_code)]
const INFO_RESULT_FLAG_DIRTY: u32 = 1 << 5;
#[allow(dead_code)]
const INFO_RESULT_FLAG_CORRUPT: u32 = 1 << 6;

// ImageFormat values (must match shared crate)
// These are defined for future use when interpreting guest results
#[allow(dead_code)]
const IMAGE_FORMAT_UNKNOWN: u32 = 0;
#[allow(dead_code)]
const IMAGE_FORMAT_RAW: u32 = 1;
#[allow(dead_code)]
const IMAGE_FORMAT_QCOW2: u32 = 2;
#[allow(dead_code)]
const IMAGE_FORMAT_VMDK4: u32 = 3;
#[allow(dead_code)]
const IMAGE_FORMAT_VMDK3: u32 = 4;
#[allow(dead_code)]
const IMAGE_FORMAT_VHD: u32 = 5;
#[allow(dead_code)]
const IMAGE_FORMAT_VHDX: u32 = 6;
#[allow(dead_code)]
const IMAGE_FORMAT_QCOW1: u32 = 7;
#[allow(dead_code)]
const IMAGE_FORMAT_VDI: u32 = 8;
#[allow(dead_code)]
const IMAGE_FORMAT_QED: u32 = 9;
#[allow(dead_code)]
const IMAGE_FORMAT_ISO: u32 = 10;
#[allow(dead_code)]
const IMAGE_FORMAT_LUKS: u32 = 11;

// Stack: generous allocation for complex operations like qemu-img info
// Place at 16MB with 4MB size to handle deep call stacks
const STACK_BASE: u64 = shared::STACK_BASE as u64;
const STACK_SIZE: u64 = 0x400000; // 4MB
const STACK_TOP: u64 = STACK_BASE + STACK_SIZE - 8;

// Virtio MMIO regions (must be OUTSIDE guest memory region for KVM to trap)
// Base address for all virtio devices: 256MB, outside 32MB guest memory
const MMIO_BASE_START: u64 = 0x10000000;
const MMIO_SIZE: u64 = 0x1000; // 4KB per device

// Virtqueue memory regions (inside guest memory)
// Each device gets 64KB for virtqueue structures
const VQ_BASE_START: u64 = 0x100000; // 1MB
const VQ_SIZE_PER_DEVICE: u64 = 0x10000; // 64KB per device

// Maximum number of devices in a backing chain (matches config default)
// This limits: MMIO range (16 * 4KB = 64KB) and VQ range (16 * 64KB = 1MB)
const MAX_CHAIN_DEPTH: usize = 16;

/// Calculate MMIO base address for device at given index.
/// Index 0 = first input device (top of chain), higher indices = backing files.
/// For operations with output, output device uses index after all inputs.
#[inline]
fn device_mmio_base(device_index: usize) -> u64 {
    MMIO_BASE_START + (device_index as u64 * MMIO_SIZE)
}

/// Calculate virtqueue base address for device at given index.
#[inline]
fn device_vq_base(device_index: usize) -> u64 {
    VQ_BASE_START + (device_index as u64 * VQ_SIZE_PER_DEVICE)
}

// DMA buffer pool (inside guest memory, used by guest not VMM)
#[allow(dead_code)]
const DMA_POOL_BASE: u64 = 0x200000;

// Total guest memory: 32MB (generous for complex operations)
const GUEST_MEM_SIZE: u64 = 0x2000000;

// Maximum sector size supported by guest (must match guest's MAX_SECTOR_SIZE)
const MAX_SECTOR_SIZE: u32 = 65536; // 64KB

// Serial port (COM1 - protobuf messages)
const SERIAL_PORT: u16 = 0x3f8;

// Debug port (COM2 - plain text debug output)
const DEBUG_PORT: u16 = 0x2f8;

// GDT segment selectors
const CODE_SELECTOR: u16 = 0x08;
const DATA_SELECTOR: u16 = 0x10;

// Control register bits
const CR0_PE: u64 = 1 << 0;
const CR0_PG: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

// Page table entry flags
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_PAGE_SIZE: u64 = 1 << 7;

// ============================================================================
// Multi-device management (Phase 0c)
//
// All operations use DeviceSet for device management. This provides:
// - Unified MMIO dispatch to correct device based on address
// - Support for N input devices (backing chains)
// - Consistent device index assignment
// ============================================================================

/// A managed device in the DeviceSet.
struct ManagedDevice {
    /// The virtio-block device
    device: Arc<Mutex<VirtioBlockDevice>>,
    /// MMIO base address for this device
    mmio_base: u64,
    /// Whether this is a read (input) or write (output) device
    is_input: bool,
}

/// Manages a set of virtio-block devices for an operation.
///
/// This struct handles MMIO dispatch to the correct device based on address,
/// and provides a unified interface for all operations.
///
/// # Device Layout
///
/// Devices are assigned sequential MMIO addresses starting at MMIO_BASE_START:
/// - Device 0: MMIO at 0x10000000, VQ at 0x100000 (typically top image/input)
/// - Device 1: MMIO at 0x10001000, VQ at 0x110000 (backing file or output)
/// - Device N: MMIO at 0x10000000 + N*0x1000, VQ at 0x100000 + N*0x10000
///
/// # Usage
///
/// - `info`: 1 input device (device 0)
/// - `copy`: 1 input + 1 output (devices 0 and 1)
/// - `convert` (future): N input devices for chain + 1 output
/// - `compare` (future): Two chains of input devices
struct DeviceSet {
    /// All managed devices in order of their device index
    devices: Vec<ManagedDevice>,
}

impl DeviceSet {
    /// Create a new empty device set.
    fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Add a device at the next available index.
    /// Returns the device index assigned.
    ///
    /// # Panics
    ///
    /// Panics if the maximum chain depth (MAX_CHAIN_DEPTH) would be exceeded.
    fn add_device(&mut self, device: Arc<Mutex<VirtioBlockDevice>>, is_input: bool) -> usize {
        assert!(
            self.devices.len() < MAX_CHAIN_DEPTH,
            "Maximum chain depth ({}) exceeded",
            MAX_CHAIN_DEPTH
        );
        let index = self.devices.len();
        let mmio_base = device_mmio_base(index);
        self.devices.push(ManagedDevice {
            device,
            mmio_base,
            is_input,
        });
        index
    }

    /// Get the number of devices.
    #[allow(dead_code)] // Will be used by convert/compare operations
    fn len(&self) -> usize {
        self.devices.len()
    }

    /// Check if the device set is empty.
    #[allow(dead_code)] // Will be used by convert/compare operations
    fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Get a device by index.
    #[allow(dead_code)] // Will be used by convert/compare operations
    fn get(&self, index: usize) -> Option<&Arc<Mutex<VirtioBlockDevice>>> {
        self.devices.get(index).map(|d| &d.device)
    }

    /// Find device index and offset for an MMIO address.
    /// Returns (device_index, offset_within_device) or None if address is invalid.
    ///
    /// O(n) linear scan is acceptable here: n ≤ MAX_CHAIN_DEPTH (16), and the
    /// simple iteration over a small contiguous Vec is cache-friendly and likely
    /// faster than a hash map for this size.
    fn find_device_for_mmio(&self, addr: u64) -> Option<(usize, u32)> {
        for (index, managed) in self.devices.iter().enumerate() {
            let range_start = managed.mmio_base;
            let range_end = range_start + MMIO_SIZE;
            if addr >= range_start && addr < range_end {
                return Some((index, (addr - range_start) as u32));
            }
        }
        None
    }

    /// Handle MMIO read, dispatching to the correct device.
    fn mmio_read(&self, addr: u64) -> u32 {
        if let Some((index, offset)) = self.find_device_for_mmio(addr) {
            self.devices[index].device.lock().unwrap().mmio_read(offset)
        } else {
            log::debug!("Unknown MMIO read at 0x{:x}", addr);
            0
        }
    }

    /// Handle MMIO write, dispatching to the correct device.
    /// Returns (device_index, should_process_queue) if a device was found.
    fn mmio_write(&self, addr: u64, value: u32) -> Option<(usize, bool)> {
        if let Some((index, offset)) = self.find_device_for_mmio(addr) {
            let mut device = self.devices[index].device.lock().unwrap();
            device.mmio_write(offset, value);
            Some((index, device.should_process_queue()))
        } else {
            log::debug!("Unknown MMIO write at 0x{:x}", addr);
            None
        }
    }

    /// Process queue for a device and record stats.
    fn process_queue_for_device(
        &self,
        index: usize,
        guest_mem: &GuestMemoryMmap,
        vmm_stats: &Arc<Mutex<VmmStats>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let managed = &self.devices[index];
        let io_stats = managed.device.lock().unwrap().process_queue(guest_mem)?;

        let mut stats = vmm_stats.lock().unwrap();
        if managed.is_input {
            stats.record_read(io_stats.bytes_read, io_stats.sectors_read);
        } else {
            stats.record_write(io_stats.bytes_written, io_stats.sectors_written);
        }
        Ok(())
    }

    /// Create IoDevice entries for the I/O thread.
    fn create_io_devices(&self, events: Vec<IoEvent>) -> Vec<IoDevice> {
        assert_eq!(
            events.len(),
            self.devices.len(),
            "Must provide one IoEvent per device"
        );

        self.devices
            .iter()
            .zip(events)
            .enumerate()
            .map(|(index, (managed, ioevent))| {
                let role = if managed.is_input {
                    if index == 0 {
                        DeviceRole::Input
                    } else {
                        DeviceRole::Backing(index as u32 - 1)
                    }
                } else {
                    DeviceRole::Output
                };
                IoDevice {
                    role,
                    device: Arc::clone(&managed.device),
                    ioevent,
                }
            })
            .collect()
    }
}

/// Serial decoder for framed protobuf messages.
///
/// Uses VecDeque for O(1) removal from the front when discarding invalid bytes
/// or draining consumed data, compared to Vec's O(n) operations.
struct SerialDecoder {
    buffer: VecDeque<u8>,
}

impl SerialDecoder {
    fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
        }
    }

    /// Add a byte and try to decode a message
    fn add_byte(&mut self, byte: u8) -> Option<guest_::GuestMessage> {
        self.buffer.push_back(byte);

        // Need at least header to check length
        if self.buffer.len() < FRAME_HEADER_SIZE {
            return None;
        }

        // Check if we have a complete message
        let msg_len = u16::from_le_bytes([self.buffer[0], self.buffer[1]]) as usize;
        let total_len = FRAME_HEADER_SIZE + msg_len;

        if self.buffer.len() < total_len {
            return None;
        }

        // Make buffer contiguous for decode_framed which needs &[u8]
        let slice = self.buffer.make_contiguous();

        // Try to decode
        if let Some((msg, consumed)) = decode_framed(slice) {
            self.buffer.drain(..consumed);
            return Some(msg);
        }

        // Decode failed - discard first byte and try again later (O(1) with VecDeque)
        self.buffer.pop_front();
        None
    }
}

/// Serial transmitter for sending config to guest
struct SerialTransmitter {
    buffer: Vec<u8>,
    position: usize,
}

impl SerialTransmitter {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            position: 0,
        }
    }

    /// Queue a config message for transmission
    fn queue_config(&mut self, config: &guest_::VmmConfig) {
        if let Some(encoded) = encode_vmm_config_framed(config) {
            self.buffer = encoded;
            self.position = 0;
        }
    }

    /// Get next byte to transmit, or None if buffer is empty
    fn next_byte(&mut self) -> Option<u8> {
        if self.position < self.buffer.len() {
            let byte = self.buffer[self.position];
            self.position += 1;
            Some(byte)
        } else {
            None
        }
    }

    /// Check if there's data to transmit
    fn has_data(&self) -> bool {
        self.position < self.buffer.len()
    }
}

/// Debug output buffer - collects characters until newline, then prints
struct DebugBuffer {
    line: String,
}

impl DebugBuffer {
    fn new() -> Self {
        Self {
            line: String::new(),
        }
    }

    /// Add a byte; if it's a newline, return the complete line
    fn add_byte(&mut self, byte: u8) -> Option<String> {
        if byte == b'\n' {
            let result = std::mem::take(&mut self.line);
            Some(result)
        } else {
            self.line.push(byte as char);
            None
        }
    }
}

/// Format a guest message for display
fn format_message(msg: &guest_::GuestMessage) -> String {
    let level = match msg.level {
        l if l == guest_::Level::Debug => "DEBUG",
        l if l == guest_::Level::Info => "INFO",
        l if l == guest_::Level::Progress => "PROGRESS",
        l if l == guest_::Level::Error => "ERROR",
        l if l == guest_::Level::Complete => "COMPLETE",
        _ => "UNKNOWN",
    };

    let payload_str = match &msg.payload {
        Some(guest_::GuestMessage_::Payload::Init(init)) => {
            format!(
                "init stage={} device={} address=0x{:x}",
                init.stage, init.device, init.address
            )
        }
        Some(guest_::GuestMessage_::Payload::Capacity(cap)) => {
            format!(
                "capacity device={} sectors={} bytes={}",
                cap.device, cap.sectors, cap.bytes
            )
        }
        Some(guest_::GuestMessage_::Payload::Progress(prog)) => {
            format!(
                "progress op={} {}/{} ({}%)",
                prog.operation, prog.current, prog.total, prog.percent
            )
        }
        Some(guest_::GuestMessage_::Payload::Error(err)) => {
            format!(
                "error op={} device={} sector={} status={}",
                err.operation, err.device, err.sector, err.status
            )
        }
        Some(guest_::GuestMessage_::Payload::Complete(comp)) => {
            format!(
                "complete op={} count={} success={}",
                comp.operation, comp.count, comp.success
            )
        }
        Some(guest_::GuestMessage_::Payload::InfoResult(info)) => {
            let mut details = format!(
                "info_result format={} version={} virtual_size={} actual_size={} cluster_size={} flags=0x{:x}",
                info.format, info.version, info.virtual_size, info.actual_size, info.cluster_size, info.flags
            );
            if !info.backing_file.is_empty() {
                details.push_str(&format!(" backing_file={}", info.backing_file));
            }
            if !info.external_data_file.is_empty() {
                details.push_str(&format!(" external_data_file={}", info.external_data_file));
            }
            details
        }
        Some(guest_::GuestMessage_::Payload::CheckResult(check)) => {
            format!(
                "check_result format={} errors={} corruptions={} leaks={} flags=0x{:x}",
                check.format, check.total_errors, check.corruptions, check.leaks, check.flags
            )
        }
        Some(guest_::GuestMessage_::Payload::CompareResult(cmp)) => {
            format!(
                "compare_result identical={} first_mismatch_offset={} total_bytes_compared={} flags=0x{:x}",
                cmp.identical, cmp.first_mismatch_offset, cmp.total_bytes_compared, cmp.flags
            )
        }
        None => "empty payload".to_string(),
    };

    format!("[{}] {}", level, payload_str)
}

/// Format a byte size as human-readable string
///
/// When `qemu_compat` is true, uses qemu-img's 3-significant-figure formatting.
/// When false, uses more accurate formatting with 1 decimal place when needed.
fn format_size_human(bytes: u64, qemu_compat: bool) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const TIB: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0;

    let bytes_f = bytes as f64;

    if bytes_f >= TIB {
        format_size_value(bytes_f / TIB, "TiB", qemu_compat)
    } else if bytes_f >= GIB {
        format_size_value(bytes_f / GIB, "GiB", qemu_compat)
    } else if bytes_f >= MIB {
        format_size_value(bytes_f / MIB, "MiB", qemu_compat)
    } else if bytes_f >= KIB {
        format_size_value(bytes_f / KIB, "KiB", qemu_compat)
    } else if bytes == 0 {
        // qemu-img outputs just "0" for zero bytes, no unit
        "0".to_string()
    } else {
        // qemu-img uses "B" for byte unit, not "bytes"
        format!("{} B", bytes)
    }
}

/// Round half to even (banker's rounding) - matches C printf behavior
fn round_half_to_even(value: f64) -> f64 {
    let floor = value.floor();
    let fract = value - floor;

    if (fract - 0.5).abs() < f64::EPSILON {
        // Exactly at midpoint - round to even
        if floor as i64 % 2 == 0 {
            floor // Already even, round down
        } else {
            floor + 1.0 // Odd, round up to even
        }
    } else {
        value.round() // Not at midpoint, use standard rounding
    }
}

/// Format a size value
///
/// When `qemu_compat` is true, uses 3 significant figures (like qemu-img's %0.3g).
/// When false, shows 1 decimal place when not a whole number.
fn format_size_value(value: f64, unit: &str, qemu_compat: bool) -> String {
    if qemu_compat {
        // qemu-img uses %0.3g format (3 significant figures)
        // C's printf uses "round half to even" (banker's rounding), which rounds
        // midpoints (like 192.5) to the nearest even number (192).
        let rounded = if value >= 100.0 {
            round_half_to_even(value)
        } else if value >= 10.0 {
            round_half_to_even(value * 10.0) / 10.0
        } else if value >= 1.0 {
            round_half_to_even(value * 100.0) / 100.0
        } else {
            round_half_to_even(value * 1000.0) / 1000.0
        };

        if rounded.fract() == 0.0 {
            format!("{} {}", rounded as u64, unit)
        } else {
            // Format and trim trailing zeros
            let s = format!("{}", rounded);
            let trimmed = s.trim_end_matches('0').trim_end_matches('.');
            format!("{} {}", trimmed, unit)
        }
    } else {
        // Accurate formatting: round to one decimal place
        let rounded = (value * 10.0).round() / 10.0;
        if rounded.fract() == 0.0 {
            format!("{} {}", rounded as u64, unit)
        } else {
            format!("{:.1} {}", rounded, unit)
        }
    }
}

/// Print InfoResult in qemu-img compatible format
#[allow(clippy::too_many_arguments)]
fn print_info_result(
    msg: &guest_::GuestMessage,
    filename: &str,
    file_size: u64,
    disk_blocks: u64,
    ignore_quirks: bool,
    extra_detail: bool,
    profile: &version::OutputProfile,
    output_format: &str,
) {
    if let Some(guest_::GuestMessage_::Payload::InfoResult(info)) = &msg.payload {
        // Get absolute path for filename
        let abs_path = std::fs::canonicalize(filename)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| filename.to_string());

        // Calculate disk size
        // qemu-img reports disk size based on st_blocks (actual disk blocks used),
        // which accounts for sparse files. st_blocks is in 512-byte units.
        // With --ignore-quirks, use the actual file size.
        let disk_size = if ignore_quirks {
            file_size
        } else {
            // st_blocks is in 512-byte units
            disk_blocks * 512
        };

        if output_format == "json" {
            // For child file length, qemu-img reports the larger of:
            // 1. The actual filesystem size
            // 2. The calculated size based on internal metadata (e.g., L1 table for QCOW2)
            // This handles both files with data beyond metadata (use actual size) and
            // minimal files where metadata calculation exceeds actual size.
            // With --ignore-quirks, use the actual filesystem size instead.
            let child_file_length = if ignore_quirks {
                file_size
            } else {
                std::cmp::max(file_size, info.actual_size)
            };
            print_info_result_json(
                info,
                &abs_path,
                child_file_length,
                disk_size,
                extra_detail,
                profile,
            );
            return;
        }

        // Line 1: image path
        println!("image: {}", abs_path);

        // Line 2: file format
        println!("file format: {}", info.format);

        // qemu_compat is the opposite of ignore_quirks
        let qemu_compat = !ignore_quirks;

        // For raw/unknown formats, qemu-img reports virtual-size as the file length
        // rounded up to 512-byte sectors. For structured formats (qcow2, vmdk, etc.),
        // use the virtual size from headers.
        let effective_virtual_size = if info.format == "raw" || info.format == "unknown" {
            // Round up to 512-byte sector boundary
            ((file_size + 511) / 512) * 512
        } else {
            info.virtual_size
        };

        // Line 3: virtual size (human-readable with bytes in parentheses)
        println!(
            "virtual size: {} ({} bytes)",
            format_size_human(effective_virtual_size, qemu_compat),
            effective_virtual_size
        );

        // Line 4: disk size
        // qemu-img reports disk size based on st_blocks (actual disk blocks used),
        // which accounts for sparse files. st_blocks is in 512-byte units.
        // With --ignore-quirks, use the actual file size.
        let disk_size = if ignore_quirks {
            file_size
        } else {
            // st_blocks is in 512-byte units
            disk_blocks * 512
        };
        println!("disk size: {}", format_size_human(disk_size, qemu_compat));

        // Line 5: cluster_size (with underscore, matching qemu-img)
        if info.cluster_size > 0 {
            println!("cluster_size: {}", info.cluster_size);
        }

        // QCOW2: "cleanly shut down: no" if dirty bit is set
        // This output was added in qemu-img 6.1 (not present in 6.0)
        if profile.include_dirty_flag && info.format == "qcow2" && info.qcow2_info.dirty {
            println!("cleanly shut down: no");
        }

        // Backing file (if present) - comes before Format specific information
        if info.flags & (1 << 0) != 0 && !info.backing_file.is_empty() {
            let backing_file_str = info.backing_file.as_str();
            // If backing file is relative, show both the stored name and actual path
            // (qemu-img shows "backing file: <name> (actual path: <resolved>)")
            if !std::path::Path::new(backing_file_str).is_absolute() {
                // Resolve relative to image's directory
                let image_dir = std::path::Path::new(&abs_path)
                    .parent()
                    .unwrap_or(std::path::Path::new("/"));
                let actual_path = image_dir
                    .join(backing_file_str)
                    .to_string_lossy()
                    .to_string();
                println!(
                    "backing file: {} (actual path: {})",
                    backing_file_str, actual_path
                );
            } else {
                println!("backing file: {}", backing_file_str);
            }
            // Show backing file format if available
            if !info.qcow2_info.backing_format.is_empty() {
                println!("backing file format: {}", info.qcow2_info.backing_format);
            }
        }

        // Format specific information (QCOW2)
        if info.format == "qcow2" {
            println!("Format specific information:");

            // compat: "0.10" or "1.1" (default to "0.10" for v2 if not set)
            let compat = if info.qcow2_info.compat.is_empty() {
                "0.10"
            } else {
                info.qcow2_info.compat.as_str()
            };
            let is_v3 = compat == "1.1";
            println!("    compat: {}", compat);

            // compression type (always shown)
            let compression = if info.qcow2_info.compression_type.is_empty() {
                "zlib"
            } else {
                info.qcow2_info.compression_type.as_str()
            };
            println!("    compression type: {}", compression);

            // lazy refcounts (only for v3/1.1 compat)
            if is_v3 {
                println!("    lazy refcounts: {}", info.qcow2_info.lazy_refcounts);
            }

            // refcount bits (default to 16 if not set)
            let refcount_bits = if info.qcow2_info.refcount_bits == 0 {
                16
            } else {
                info.qcow2_info.refcount_bits
            };
            println!("    refcount bits: {}", refcount_bits);

            // corrupt flag (only for v3/1.1 compat)
            if is_v3 {
                println!("    corrupt: {}", info.qcow2_info.corrupt);
            }

            // extended l2 (only for v3/1.1 compat)
            if is_v3 {
                println!("    extended l2: {}", info.qcow2_info.extended_l2);
            }
        }

        // Format specific information (VMDK)
        if info.format == "vmdk" {
            println!("Format specific information:");
            println!("    cid: {}", info.vmdk_info.cid);
            println!("    parent cid: {}", info.vmdk_info.parent_cid);
            println!("    create type: {}", info.vmdk_info.create_type.as_str());

            // Extents section - for monolithicSparse there's one extent
            // The extent info includes virtual size (in bytes), filename, cluster size, and format
            println!("    extents:");
            println!("        [0]:");
            // Output compressed: true if the extent is compressed (e.g., streamOptimized)
            if info.flags & INFO_RESULT_FLAG_COMPRESSED != 0 {
                println!("            compressed: true");
            }
            println!("            virtual size: {}", info.virtual_size);
            println!("            filename: {}", abs_path);
            println!("            cluster size: {}", info.cluster_size);
            // qemu-img outputs "format: " with trailing space for empty format
            print!("            format: ");
            println!();
        }

        // Format specific information (VDI)
        // Only output with --extra-detail flag since qemu-img doesn't show this
        if info.format == "vdi" && extra_detail {
            println!("Format specific information:");
            // Image type: 1=dynamic, 2=fixed
            let image_type_str = match info.vdi_info.image_type {
                1 => "dynamic",
                2 => "fixed",
                _ => "unknown",
            };
            println!("    image type: {}", image_type_str);
            println!("    block size: {}", info.vdi_info.block_size);
            println!("    blocks in image: {}", info.vdi_info.blocks_in_image);
            println!("    blocks allocated: {}", info.vdi_info.blocks_allocated);
            if !info.vdi_info.uuid.is_empty() {
                println!("    uuid: {}", info.vdi_info.uuid.as_str());
            }
        }

        // Child node '/file' section (qemu-img 8.0+)
        // This section exposes information about the underlying protocol layer.
        if profile.include_child_node {
            // For file length, qemu-img reports the larger of:
            // 1. The actual filesystem size
            // 2. The calculated size based on internal metadata (e.g., L1 table for QCOW2)
            // This handles both files with data beyond metadata (use actual size) and
            // minimal files where metadata calculation exceeds actual size.
            // With --ignore-quirks, use the actual filesystem size instead.
            let child_file_length = if ignore_quirks {
                file_size
            } else {
                std::cmp::max(file_size, info.actual_size)
            };
            // For raw format, round up to 512-byte sector boundary
            let effective_child_file_length = if info.format == "raw" {
                ((child_file_length + 511) / 512) * 512
            } else {
                child_file_length
            };
            println!("Child node '/file':");
            println!("    filename: {}", abs_path);
            println!("    protocol type: file");
            println!(
                "    file length: {} ({} bytes)",
                format_size_human(effective_child_file_length, qemu_compat),
                effective_child_file_length
            );
            println!(
                "    disk size: {}",
                format_size_human(disk_size, qemu_compat)
            );
        }
    }
}

/// Print info result in JSON format (matching qemu-img info --output=json)
fn print_info_result_json(
    info: &guest_::InfoResultMessage,
    abs_path: &str,
    child_file_length: u64,
    disk_size: u64,
    extra_detail: bool,
    profile: &version::OutputProfile,
) {
    // Build JSON output to match qemu-img's format exactly
    // qemu-img uses 4-space indentation

    // For raw/unknown formats, qemu-img reports virtual-size as the file length
    // rounded up to 512-byte sectors. For structured formats (qcow2, vmdk, etc.),
    // use the virtual size from headers. The "unknown" case is important: files
    // smaller than one guest sector (e.g., 512-byte LUKS headers with 64KB sectors)
    // report 0 capacity to the guest, so the guest's virtual_size will be 0. The
    // VMM must use the real file length instead.
    let is_unstructured = info.format == "raw" || info.format == "unknown";
    let effective_virtual_size = if is_unstructured {
        // Round up to 512-byte sector boundary
        ((child_file_length + 511) / 512) * 512
    } else {
        info.virtual_size
    };

    // For child file length in raw/unknown format, also round up to 512-byte sectors
    let effective_child_file_length = if is_unstructured {
        ((child_file_length + 511) / 512) * 512
    } else {
        child_file_length
    };

    println!("{{");

    // Check if we have a backing file
    let has_backing_file = info.flags & (1 << 0) != 0 && !info.backing_file.is_empty();

    // Children section (qemu-img 8.0+ only)
    if profile.include_child_node {
        println!("    \"children\": [");
        println!("        {{");
        println!("            \"name\": \"file\",");
        println!("            \"info\": {{");
        println!("                \"children\": [],");
        println!(
            "                \"virtual-size\": {},",
            effective_child_file_length
        );
        println!(
            "                \"filename\": \"{}\",",
            escape_json_string(abs_path)
        );
        println!("                \"format\": \"file\",");
        println!("                \"actual-size\": {},", disk_size);
        println!("                \"format-specific\": {{");
        println!("                    \"type\": \"file\",");
        println!("                    \"data\": {{}}");
        println!("                }},");
        println!("                \"dirty-flag\": false");
        println!("            }}");
        println!("        }}");
        println!("    ],");
    }

    // Backing file format - always output when there's a backing file
    // For QCOW2, this comes from header extensions (v3)
    if has_backing_file {
        // Use the format from header extension if available, otherwise default to qcow2
        let backing_format = if !info.qcow2_info.backing_format.is_empty() {
            info.qcow2_info.backing_format.as_str()
        } else {
            "qcow2"
        };
        println!("    \"backing-filename-format\": \"{}\",", backing_format);
    }

    println!("    \"virtual-size\": {},", effective_virtual_size);
    println!("    \"filename\": \"{}\",", escape_json_string(abs_path));

    if info.cluster_size > 0 {
        println!("    \"cluster-size\": {},", info.cluster_size);
    }

    println!("    \"format\": \"{}\",", info.format);
    println!("    \"actual-size\": {},", disk_size);

    // Format-specific section
    if info.format == "qcow2" {
        println!("    \"format-specific\": {{");
        println!("        \"type\": \"qcow2\",");
        println!("        \"data\": {{");

        let compat = if info.qcow2_info.compat.is_empty() {
            "0.10"
        } else {
            info.qcow2_info.compat.as_str()
        };
        let is_v3 = compat == "1.1";

        println!("            \"compat\": \"{}\",", compat);

        let compression = if info.qcow2_info.compression_type.is_empty() {
            "zlib"
        } else {
            info.qcow2_info.compression_type.as_str()
        };
        println!("            \"compression-type\": \"{}\",", compression);

        if is_v3 {
            println!(
                "            \"lazy-refcounts\": {},",
                info.qcow2_info.lazy_refcounts
            );
        }

        let refcount_bits = if info.qcow2_info.refcount_bits == 0 {
            16
        } else {
            info.qcow2_info.refcount_bits
        };

        if is_v3 {
            println!("            \"refcount-bits\": {},", refcount_bits);
            println!("            \"corrupt\": {},", info.qcow2_info.corrupt);
            println!(
                "            \"extended-l2\": {}",
                info.qcow2_info.extended_l2
            );
        } else {
            // For v2, refcount-bits is the last field (no trailing comma)
            println!("            \"refcount-bits\": {}", refcount_bits);
        }

        println!("        }}");
        println!("    }},");
    } else if info.format == "vmdk" {
        println!("    \"format-specific\": {{");
        println!("        \"type\": \"vmdk\",");
        println!("        \"data\": {{");
        println!("            \"cid\": {},", info.vmdk_info.cid);
        println!("            \"parent-cid\": {},", info.vmdk_info.parent_cid);
        println!(
            "            \"create-type\": \"{}\",",
            info.vmdk_info.create_type.as_str()
        );
        // Extents array - for monolithicSparse, there's one extent with the disk info
        println!("            \"extents\": [");
        println!("                {{");
        // Output compressed: true if the extent is compressed (e.g., streamOptimized)
        if info.flags & INFO_RESULT_FLAG_COMPRESSED != 0 {
            println!("                    \"compressed\": true,");
        }
        println!(
            "                    \"virtual-size\": {},",
            info.virtual_size
        );
        println!(
            "                    \"filename\": \"{}\",",
            escape_json_string(abs_path)
        );
        println!(
            "                    \"cluster-size\": {},",
            info.cluster_size
        );
        println!("                    \"format\": \"\"");
        println!("                }}");
        println!("            ]");
        println!("        }}");
        println!("    }},");
    } else if info.format == "vdi" && extra_detail {
        // VDI format-specific info is only output with --extra-detail flag.
        // qemu-img doesn't output format-specific for VDI, but we can provide
        // additional details when explicitly requested.
        println!("    \"format-specific\": {{");
        println!("        \"type\": \"vdi\",");
        println!("        \"data\": {{");
        // Image type: 1=dynamic, 2=fixed
        let image_type_str = match info.vdi_info.image_type {
            1 => "dynamic",
            2 => "fixed",
            _ => "unknown",
        };
        println!("            \"image-type\": \"{}\",", image_type_str);
        println!("            \"block-size\": {},", info.vdi_info.block_size);
        println!(
            "            \"blocks-in-image\": {},",
            info.vdi_info.blocks_in_image
        );
        println!(
            "            \"blocks-allocated\": {},",
            info.vdi_info.blocks_allocated
        );
        println!(
            "            \"uuid\": \"{}\"",
            escape_json_string(info.vdi_info.uuid.as_str())
        );
        println!("        }}");
        println!("    }},");
    }

    // Backing file paths (if present)
    if has_backing_file {
        // full-backing-filename is the resolved absolute path
        // If backing_file is relative, resolve it relative to the image's directory
        let backing_file_str = info.backing_file.as_str();
        let full_backing_filename = if std::path::Path::new(backing_file_str).is_absolute() {
            backing_file_str.to_string()
        } else {
            // Get the directory containing the image file
            let image_dir = std::path::Path::new(abs_path)
                .parent()
                .unwrap_or(std::path::Path::new("/"));
            image_dir
                .join(backing_file_str)
                .to_string_lossy()
                .to_string()
        };
        println!(
            "    \"full-backing-filename\": \"{}\",",
            escape_json_string(&full_backing_filename)
        );
        println!(
            "    \"backing-filename\": \"{}\",",
            escape_json_string(backing_file_str)
        );
    }

    // For QCOW2, use the dirty flag from the image header
    // For other formats, always report false
    // Note: dirty-flag output was added in qemu-img 6.1; for 6.0 compatibility,
    // always report false when profile.include_dirty_flag is false
    let dirty_flag = if profile.include_dirty_flag && info.format == "qcow2" {
        info.qcow2_info.dirty
    } else {
        false
    };
    println!("    \"dirty-flag\": {}", dirty_flag);
    println!("}}");
}

/// Escape a string for JSON output
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// Get the directory containing the imago executable
fn get_binary_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .expect("Failed to get executable path")
        .parent()
        .expect("Failed to get executable directory")
        .to_path_buf()
}

/// Get the path to a binary in the same directory as imago
fn get_binary_path(name: &str) -> std::path::PathBuf {
    get_binary_dir().join(name)
}

/// Execute the info operation on a single image file and capture the result.
///
/// This function sets up and runs the KVM guest with the info operation,
/// then captures and returns the result instead of printing it.
///
/// # Arguments
///
/// * `input_path` - Path to the image file to analyze
/// * `sector_size` - Sector size for the virtio-block device
/// * `unsafe_quirks` - Enable unsafe qemu-img compatibility mode (accepts any file as RAW)
///
/// # Returns
///
/// The captured info operation result, or an error if the operation failed.
fn execute_info_operation(
    input_path: &Path,
    sector_size: u32,
    unsafe_quirks: bool,
) -> Result<InfoOperationResult, Box<dyn std::error::Error>> {
    // Auto-discover binaries in same directory as executable
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("info.bin");

    // Load core binary (device init, call table setup)
    let core_code = load_guest_binary(core_path.to_str().unwrap())?;

    // Load operation binary (info)
    let operation_code = load_guest_binary(operation_path.to_str().unwrap())?;

    // Get input file metadata
    let input_metadata = std::fs::metadata(input_path)?;
    let input_size = input_metadata.len();

    // Open backing store (input only, read-only)
    let input_backing = BackingStore::open(input_path, true, None, false)?;

    // Open KVM
    let kvm = Kvm::new()?;

    // Create VM
    let vm = kvm.create_vm()?;

    // Create guest memory
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;

    // Get the memory region for KVM registration
    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    // Set up KVM memory region
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }

    // Set up GDT
    setup_gdt(&guest_mem)?;

    // Set up page tables (identity map)
    setup_page_tables(&guest_mem)?;

    // Load core binary at GUEST_CODE_BASE (0x10000)
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;

    // Load operation binary at OPERATION_LOAD_ADDR (0x20000)
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;

    // Write InfoConfig at OPERATION_CONFIG_ADDR (0x19000)
    let mut info_flags: u32 = INFO_CONFIG_FLAG_DETAILED | INFO_CONFIG_FLAG_SECURITY_CHECK;
    if unsafe_quirks {
        info_flags |= INFO_CONFIG_FLAG_UNSAFE_QUIRKS;
    }
    guest_mem.write_obj(INFO_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(info_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;

    // Create device set for managing virtio-block devices
    let mut device_set = DeviceSet::new();

    // Create virtio-block device (input only for info operation)
    let input_mmio = device_mmio_base(0);
    let input_vq = device_vq_base(0);
    let input_device = VirtioBlockDevice::new(
        input_backing,
        input_size,
        sector_size as u64,
        true, // read-only
        input_mmio,
        input_vq,
    );

    // Wrap device in Arc<Mutex<>> and add to device set
    let input_device = Arc::new(Mutex::new(input_device));
    device_set.add_device(Arc::clone(&input_device), true);

    // Wrap guest memory in Arc for sharing
    let guest_mem = Arc::new(guest_mem);

    // Create shared statistics tracker
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Set up ioeventfd for queue notifications
    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut input_evt = IoEvent::new(input_mmio)?;

    match input_evt.register(&vm) {
        Ok(()) => {
            // Create IoDevice entries via DeviceSet
            let io_devices = device_set.create_io_devices(vec![input_evt]);

            // Start the I/O thread
            io_thread = Some(io_thread::IoThread::new(
                io_devices,
                Arc::clone(&guest_mem),
                Arc::clone(&vmm_stats),
            ));
        }
        Err(_) => {
            // Fall back to VM exits for queue processing
        }
    }

    // Create vCPU
    let mut vcpu = vm.create_vcpu(0)?;

    // Set up registers
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;

    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;

    // Create serial decoder for protobuf messages from guest
    let mut serial_decoder = SerialDecoder::new();

    // Create serial transmitter for sending config to guest
    let mut serial_transmitter = SerialTransmitter::new();

    // Create debug buffer for COM2 output
    let mut debug_buffer = DebugBuffer::new();

    // Queue the configuration message for transmission
    let config = vmm_config_input_only(sector_size);
    serial_transmitter.queue_config(&config);

    // Variable to capture the result
    let mut captured_result: Option<InfoOperationResult> = None;

    // Run the vCPU loop
    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                break;
            }
            VcpuExit::IoOut(port, data) => {
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            // Capture InfoResult
                            if let Some(guest_::GuestMessage_::Payload::InfoResult(info)) =
                                &msg.payload
                            {
                                captured_result = Some(InfoOperationResult {
                                    format: info.format.to_string(),
                                    virtual_size: info.virtual_size,
                                    actual_size: info.actual_size,
                                    cluster_size: info.cluster_size,
                                    flags: info.flags,
                                    backing_file: if info.backing_file.is_empty() {
                                        None
                                    } else {
                                        Some(info.backing_file.to_string())
                                    },
                                });
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        debug_buffer.add_byte(byte);
                    }
                }
            }
            VcpuExit::IoIn(port, data) => {
                if port == SERIAL_PORT {
                    for byte in data.iter_mut() {
                        *byte = serial_transmitter.next_byte().unwrap_or(0);
                    }
                } else if port == SERIAL_PORT + 5 {
                    let mut lsr = 0x60u8;
                    if serial_transmitter.has_data() {
                        lsr |= 0x01;
                    }
                    data[0] = lsr;
                } else {
                    for byte in data {
                        *byte = 0;
                    }
                }
            }
            VcpuExit::MmioRead(addr, data) => {
                let value = device_set.mmio_read(addr);
                write_mmio_data(data, value);
            }
            VcpuExit::MmioWrite(addr, data) => {
                let value = read_mmio_data(data);
                if let Some((device_index, should_process)) = device_set.mmio_write(addr, value) {
                    if io_thread.is_none() && should_process {
                        device_set.process_queue_for_device(
                            device_index,
                            &guest_mem,
                            &vmm_stats,
                        )?;
                    }
                }
            }
            VcpuExit::Shutdown => {
                return Err("VM shutdown (possible triple fault)".into());
            }
            VcpuExit::FailEntry(reason, cpu) => {
                return Err(format!("VM entry failed: reason=0x{:x}, cpu={}", reason, cpu).into());
            }
            _ => {
                // Ignore other exits
            }
        }
    }

    if let Some(mut thread) = io_thread {
        thread.stop();
    }

    captured_result.ok_or_else(|| "No info result received from guest".into())
}

/// Discover the complete backing file chain for an image.
///
/// This function iteratively runs the sandboxed info operation to discover
/// the complete backing file chain. All format parsing happens in the KVM
/// guest; this function only coordinates the discovery and validates paths.
///
/// # Arguments
///
/// * `top_image` - Path to the top-level image
/// * `sector_size` - Sector size for virtio-block devices
/// * `security_config` - Security configuration with path allowlist
///
/// # Returns
///
/// A BackingChain containing all images from top to base, or an error.
fn discover_backing_chain(
    top_image: &Path,
    sector_size: u32,
    security_config: &config::SecurityConfig,
) -> Result<BackingChain, ChainError> {
    let mut chain = BackingChain::new();
    let mut seen_paths: Vec<std::path::PathBuf> = Vec::new();
    let mut current = top_image
        .canonicalize()
        .map_err(|e| ChainError::PathResolutionError(format!("{}: {}", top_image.display(), e)))?;

    loop {
        // Check for circular references
        check_circular_reference(&current, &seen_paths)?;

        // Check chain depth
        check_chain_depth(chain.len(), security_config)?;

        seen_paths.push(current.clone());

        // Run the sandboxed info operation
        // Always use secure mode (unsafe_quirks=false) for backing chain discovery
        let info_result = execute_info_operation(&current, sector_size, false)
            .map_err(|e| ChainError::InfoOperationFailed(e.to_string()))?;

        // Build chain image entry
        let chain_image = ChainImage {
            path: current.clone(),
            format: ImageFormat::from_str(&info_result.format),
            virtual_size: info_result.virtual_size,
            actual_size: info_result.actual_size,
            cluster_size: info_result.cluster_size,
            backing_file_raw: info_result.backing_file.clone(),
            flags: info_result.flags,
        };

        chain.push(chain_image);

        // Check for backing file
        match info_result.backing_file {
            Some(backing_path) => {
                // Validate and resolve the backing file path
                let backing_resolved =
                    validate_backing_path(&current, &backing_path, security_config)?;
                current = backing_resolved;
            }
            None => {
                // No backing file - end of chain
                break;
            }
        }
    }

    Ok(chain)
}

/// Print the backing chain in human-readable format
fn print_backing_chain(chain: &BackingChain) {
    println!("Chain: {} image(s)", chain.len());
    for (i, image) in chain.images().iter().enumerate() {
        let backing_info = match &image.backing_file_raw {
            Some(bf) => format!(" -> {}", bf),
            None => String::new(),
        };
        println!(
            "  [{}] {} ({}){}",
            i,
            image.path.display(),
            image.format,
            backing_info
        );
        println!(
            "      virtual size: {} ({} bytes)",
            format_size_human(image.virtual_size, false),
            image.virtual_size
        );
        println!(
            "      disk size: {} ({} bytes)",
            format_size_human(image.actual_size, false),
            image.actual_size
        );
        if image.cluster_size > 0 {
            println!("      cluster size: {} bytes", image.cluster_size);
        }
    }
}

/// Write a ChainConfig structure to guest memory at CHAIN_CONFIG_ADDR.
///
/// This populates the chain config with metadata about all devices in the
/// backing chain, allowing guest operations to understand the chain structure
/// without parsing image headers.
///
/// # Arguments
///
/// * `guest_mem` - Guest memory to write to
/// * `chain` - The backing chain to convert and write
///
/// # Returns
///
/// Ok(()) on success, error on memory write failure
fn write_chain_config(
    guest_mem: &GuestMemoryMmap,
    chain: &BackingChain,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build the ChainConfig structure
    // Layout matches shared::ChainConfig exactly:
    // - magic: u32 (offset 0)
    // - device_count: u32 (offset 4)
    // - version: u32 (offset 8)
    // - _reserved: u32 (offset 12)
    // - devices: [ChainDeviceInfo; 16] (offset 16)
    //
    // ChainDeviceInfo layout (32 bytes each):
    // - format: u32 (offset 0)
    // - flags: u32 (offset 4)
    // - virtual_size: u64 (offset 8)
    // - actual_size: u64 (offset 16)
    // - cluster_size: u32 (offset 24)
    // - _reserved: u32 (offset 28)

    let device_count = chain.len().min(MAX_CHAIN_DEVICES);

    if chain.len() > MAX_CHAIN_DEVICES {
        debug!(
            "Chain truncated: {} devices exceeds maximum of {}, only first {} will be passed",
            chain.len(),
            MAX_CHAIN_DEVICES,
            MAX_CHAIN_DEVICES
        );
    }

    // Write header
    guest_mem.write_obj(CHAIN_CONFIG_MAGIC, GuestAddress(CHAIN_CONFIG_ADDR))?;
    guest_mem.write_obj(device_count as u32, GuestAddress(CHAIN_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(CHAIN_CONFIG_VERSION, GuestAddress(CHAIN_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(0u32, GuestAddress(CHAIN_CONFIG_ADDR + 12))?; // reserved

    // Write each device's info
    let devices_base = CHAIN_CONFIG_ADDR + 16;
    for (i, image) in chain.images().iter().take(MAX_CHAIN_DEVICES).enumerate() {
        let device_offset = devices_base + (i as u64 * 32);

        guest_mem.write_obj(
            image.format.to_shared_format_u32(),
            GuestAddress(device_offset),
        )?;
        guest_mem.write_obj(image.flags, GuestAddress(device_offset + 4))?;
        guest_mem.write_obj(image.virtual_size, GuestAddress(device_offset + 8))?;
        guest_mem.write_obj(image.actual_size, GuestAddress(device_offset + 16))?;
        guest_mem.write_obj(image.cluster_size, GuestAddress(device_offset + 24))?;
        guest_mem.write_obj(0u32, GuestAddress(device_offset + 28))?; // reserved
    }

    debug!(
        "Wrote chain config at 0x{:x} ({} devices)",
        CHAIN_CONFIG_ADDR, device_count
    );

    Ok(())
}

/// Create a single-device BackingChain from image info for simple operations.
///
/// This is used to populate chain config even for operations on single images
/// without backing files, providing a consistent interface for operations.
#[allow(dead_code)] // Infrastructure for Phase 1+ (check, compare, convert)
fn create_single_image_chain(
    path: &Path,
    format: ImageFormat,
    virtual_size: u64,
    actual_size: u64,
    cluster_size: u32,
    flags: u32,
) -> BackingChain {
    let mut chain = BackingChain::new();
    chain.push(ChainImage {
        path: path.to_path_buf(),
        format,
        virtual_size,
        actual_size,
        cluster_size,
        backing_file_raw: None,
        flags,
    });
    chain
}

#[derive(Parser, Debug)]
#[command(name = "imago")]
#[command(about = "Safe, sandboxed disk image operations")]
struct Cli {
    /// Enable verbose output (debug information about KVM setup, memory, etc.)
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Detect image format and display information
    Info(InfoArgs),
    /// Copy/convert disk images
    Copy(CopyArgs),
    /// Check image structural integrity (partial L2 validation; see docs/quirks.md)
    Check(CheckArgs),
    /// Compare two disk images sector by sector
    Compare(CompareArgs),
    /// Convert a disk image to a different format (qcow2 -> raw)
    Convert(ConvertArgs),
    /// Display or validate configuration
    Config(ConfigArgs),
}

#[derive(Args, Debug)]
struct InfoArgs {
    /// Input image file
    input: String,

    /// Sector size for reading input (default: 65536)
    #[arg(long, default_value = "65536")]
    sector_size: u32,

    /// Report true filesystem size instead of qemu-img-compatible calculated size
    #[arg(long)]
    ignore_quirks: bool,

    /// Enable unsafe qemu-img compatibility mode.
    /// WARNING: This accepts any file as a valid RAW image, which enables
    /// security vulnerabilities like backing file disclosure attacks.
    /// Use only for compatibility testing, never in production.
    #[arg(long)]
    unsafe_quirks: bool,

    /// Target qemu-img version for output compatibility (e.g., "7.2", "8.0", "10.0").
    /// By default, imago detects the installed qemu-img version and matches its output format.
    #[arg(long, value_name = "VERSION")]
    qemu_version: Option<String>,

    /// Output format: human (default) or json
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,

    /// Discover and display the complete backing file chain
    #[arg(long)]
    chain: bool,

    /// Include extra format-specific details not provided by qemu-img.
    /// This outputs additional information like VDI format-specific fields
    /// that qemu-img doesn't include.
    #[arg(long)]
    extra_detail: bool,
}

#[derive(Args, Debug)]
struct CopyArgs {
    /// Input image file
    input: String,

    /// Output image file
    output: String,

    /// Sector size for input device in bytes (default: 65536)
    #[arg(long, default_value = "65536")]
    input_sector_size: u32,

    /// Sector size for output device in bytes (default: 65536)
    #[arg(long, default_value = "65536")]
    output_sector_size: u32,

    /// Maximum output file size in bytes (default: same as input file size)
    /// This sets the capacity exposed to the guest, but the file grows on demand.
    #[arg(long)]
    max_output_size: Option<u64>,

    /// Pre-allocate output file instead of sparse/on-demand growth
    #[arg(long)]
    preallocate_output: bool,

    /// Progress update interval as percentage (1-99=every N%, 0=every 10 sectors, 100=none)
    #[arg(long, default_value = "10")]
    progress_percent: u32,

    /// Verify data after copy (read back and compare)
    #[arg(long)]
    verify: bool,

    /// Skip writing zero sectors to output (sparse copy)
    #[arg(long)]
    skip_zeros: bool,

    /// Starting sector for copy (default: 0)
    #[arg(long, default_value = "0")]
    start_sector: u64,

    /// Number of sectors to copy (default: 0 = all)
    #[arg(long, default_value = "0")]
    sector_count: u64,
}

#[derive(Args, Debug)]
struct CheckArgs {
    /// Input image file
    input: String,

    /// Sector size for reading input (default: 65536)
    #[arg(long, default_value = "65536")]
    sector_size: u32,

    /// Output format: human (default) or json
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,

    /// Quiet mode: only show errors
    #[arg(short, long)]
    quiet: bool,

    /// Enable unsafe qemu-img compatible mode.
    /// WARNING: This treats all non-QCOW2 formats as "raw" and skips
    /// format-specific validation, matching qemu-img check behavior.
    /// Use only for compatibility testing, never in production.
    #[arg(long)]
    unsafe_quirks: bool,

    /// Validate the complete backing file chain
    #[arg(long)]
    chain: bool,
}

#[derive(Args, Debug)]
struct CompareArgs {
    /// First image file
    image1: String,

    /// Second image file
    image2: String,

    /// Sector size for reading images (default: 65536)
    #[arg(long, default_value = "65536")]
    sector_size: u32,

    /// Output format: human (default) or json
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,

    /// Strict mode: fail on size differences
    #[arg(short, long)]
    strict: bool,

    /// Quiet mode: only show errors
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args, Debug)]
struct ConvertArgs {
    /// Input image file
    input: String,

    /// Output image file
    output: String,

    /// Output format ("raw" or "qcow2")
    #[arg(short = 'O', long = "output-format", default_value = "raw")]
    output_format: String,

    /// Sector size for I/O (default: 65536)
    #[arg(long, default_value = "65536")]
    sector_size: u32,

    /// Output cluster size for QCOW2 (default: 65536)
    #[arg(long, default_value = "65536")]
    cluster_size: u32,

    /// Skip writing zero-filled clusters to output (sparse output)
    #[arg(short = 'S', long)]
    skip_zeros: bool,

    /// Progress update interval in percent (default: 10)
    #[arg(short = 'p', long, default_value = "10")]
    progress_percent: u32,

    /// Don't create output file (must already exist)
    #[arg(short = 'n', long)]
    no_create: bool,
}

#[derive(Args, Debug)]
struct ConfigArgs {
    /// Show which file each config value came from
    #[arg(long)]
    show_sources: bool,

    /// Validate config files for syntax errors
    #[arg(long)]
    validate: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let verbose = cli.verbose;

    // Initialize logger based on --verbose flag
    if verbose {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Debug)
            .format_target(false)
            .format_timestamp(None)
            .init();
    }

    match cli.command {
        Commands::Info(args) => run_info(args, verbose),
        Commands::Copy(args) => run_copy(args, verbose),
        Commands::Check(args) => run_check(args, verbose),
        Commands::Compare(args) => run_compare(args, verbose),
        Commands::Convert(args) => run_convert(args, verbose),
        Commands::Config(args) => run_config(args),
    }
}

/// Run the config operation (display or validate configuration)
fn run_config(args: ConfigArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.validate {
        // Validate config files
        let errors = config::validate_config_files();
        if errors.is_empty() {
            println!("All configuration files are valid.");
            Ok(())
        } else {
            eprintln!("Configuration errors found:");
            for (path, error) in &errors {
                eprintln!("  {}: {}", path.display(), error);
            }
            Err("configuration validation failed".into())
        }
    } else {
        // Display effective configuration
        let tracked = config::load_config();
        let output = config::format_config(&tracked, args.show_sources);
        print!("{}", output);
        Ok(())
    }
}

/// Run the info operation (format detection)
fn run_info(args: InfoArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Validate sector size (must be power of 2, 512 to 64KB)
    if !(512..=MAX_SECTOR_SIZE).contains(&args.sector_size) || !args.sector_size.is_power_of_two() {
        return Err(format!(
            "sector size must be a power of 2, 512 to {} (got {})",
            MAX_SECTOR_SIZE, args.sector_size
        )
        .into());
    }

    // Handle --chain flag: discover and display backing file chain
    if args.chain {
        let input_path = Path::new(&args.input);
        let security_config = config::load_config().config.security;

        match discover_backing_chain(input_path, args.sector_size, &security_config) {
            Ok(chain) => {
                print_backing_chain(&chain);
                return Ok(());
            }
            Err(e) => {
                return Err(format!("error discovering backing chain: {}", e).into());
            }
        }
    }

    // Determine output profile (from --qemu-version flag or by detection)
    let profile = if let Some(ref version_str) = args.qemu_version {
        match version::profile_for_version_str(version_str) {
            Some(p) => {
                debug!("Using output profile for qemu-img version {}", version_str);
                p
            }
            None => {
                return Err(format!(
                    "invalid qemu version '{}' (expected format: X.Y)",
                    version_str
                )
                .into());
            }
        }
    } else {
        let p = version::get_profile();
        if let Some(v) = &p.version {
            debug!(
                "Detected qemu-img version {}, using matching output profile",
                v
            );
        } else {
            debug!("qemu-img not found, using newest output profile");
        }
        p.clone()
    };

    // Auto-discover binaries in same directory as executable
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("info.bin");

    // Load core binary (device init, call table setup)
    let core_code = load_guest_binary(core_path.to_str().unwrap())?;
    debug!(
        "Loaded core binary: {} bytes from {}",
        core_code.len(),
        core_path.display()
    );

    // Load operation binary (info)
    let operation_code = load_guest_binary(operation_path.to_str().unwrap())?;
    debug!(
        "Loaded operation binary: {} bytes from {}",
        operation_code.len(),
        operation_path.display()
    );

    // Get input file metadata (size and disk blocks)
    let input_metadata = std::fs::metadata(&args.input)?;
    let input_size = input_metadata.len();
    // Get disk blocks allocated (for sparse file disk size calculation)
    #[cfg(unix)]
    let input_disk_blocks = {
        use std::os::unix::fs::MetadataExt;
        input_metadata.blocks()
    };
    #[cfg(not(unix))]
    let input_disk_blocks = (input_size + 511) / 512; // Fallback for non-Unix
    debug!(
        "Input file: {} ({} bytes, {} sectors @ {} bytes/sector)",
        args.input,
        input_size,
        input_size / args.sector_size as u64,
        args.sector_size
    );

    // Open backing store (input only, read-only)
    let input_backing = BackingStore::open(Path::new(&args.input), true, None, false)?;

    // Open KVM
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    // Check KVM binary statistics capability
    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    // Create VM
    let vm = kvm.create_vm()?;
    debug!("Created VM");

    // Create guest memory
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    debug!("Allocated {} bytes of guest memory", GUEST_MEM_SIZE);

    // Get the memory region for KVM registration
    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    // Set up KVM memory region
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    // Set up GDT
    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{:x}", GDT_BASE);

    // Set up page tables (identity map)
    setup_page_tables(&guest_mem)?;
    debug!("Set up page tables at 0x{:x}", PAGE_TABLE_BASE);

    // Load core binary at GUEST_CODE_BASE (0x10000)
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{:x}", GUEST_CODE_BASE);

    // Load operation binary at OPERATION_LOAD_ADDR (0x20000)
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{:x}", OPERATION_LOAD_ADDR);

    // Write InfoConfig at OPERATION_CONFIG_ADDR
    // Layout: magic (u32), flags (u32)
    let mut info_flags: u32 = INFO_CONFIG_FLAG_DETAILED | INFO_CONFIG_FLAG_SECURITY_CHECK;
    if args.unsafe_quirks {
        info_flags |= INFO_CONFIG_FLAG_UNSAFE_QUIRKS;
    }
    if args.extra_detail {
        info_flags |= INFO_CONFIG_FLAG_EXTRA_DETAIL;
    }
    if verbose {
        info_flags |= INFO_CONFIG_FLAG_VERBOSE;
    }
    guest_mem.write_obj(INFO_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(info_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    debug!(
        "Wrote info config at 0x{:x} (flags=0x{:x})",
        OPERATION_CONFIG_ADDR, info_flags
    );

    // Create device set for managing virtio-block devices
    let mut device_set = DeviceSet::new();

    // Create virtio-block device (input only for info operation)
    // Device index 0 = primary input
    let input_mmio = device_mmio_base(0);
    let input_vq = device_vq_base(0);
    let input_device = VirtioBlockDevice::new(
        input_backing,
        input_size,
        args.sector_size as u64,
        true, // read-only
        input_mmio,
        input_vq,
    );
    debug!(
        "Created virtio-block device at MMIO 0x{:x}, VQ 0x{:x}",
        input_mmio, input_vq
    );
    debug!("  Sector size: {} bytes", input_device.sector_size());

    // Wrap device in Arc<Mutex<>> and add to device set
    let input_device = Arc::new(Mutex::new(input_device));
    device_set.add_device(Arc::clone(&input_device), true);

    // Wrap guest memory in Arc for sharing
    let guest_mem = Arc::new(guest_mem);

    // Create shared statistics tracker
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Set up ioeventfd for queue notifications
    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut input_evt = IoEvent::new(input_mmio)?;

    match input_evt.register(&vm) {
        Ok(()) => {
            debug!("ioeventfd: enabled for queue notifications (with I/O thread)");

            // Create IoDevice entries via DeviceSet
            let io_devices = device_set.create_io_devices(vec![input_evt]);

            // Start the I/O thread
            io_thread = Some(io_thread::IoThread::new(
                io_devices,
                Arc::clone(&guest_mem),
                Arc::clone(&vmm_stats),
            ));
        }
        Err(e) => {
            debug!(
                "ioeventfd: failed to register ({:?}), falling back to VM exits",
                e
            );
        }
    }

    // Create vCPU
    let mut vcpu = vm.create_vcpu(0)?;
    debug!("Created vCPU");

    // Set up registers
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    debug!("Configured special registers for long mode");

    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;
    debug!(
        "Configured general registers (RIP=0x{:x}, RSP=0x{:x})",
        regs.rip, regs.rsp
    );

    // Create serial decoder for protobuf messages from guest
    let mut serial_decoder = SerialDecoder::new();

    // Create serial transmitter for sending config to guest
    let mut serial_transmitter = SerialTransmitter::new();

    // Create debug buffer for COM2 output
    let mut debug_buffer = DebugBuffer::new();

    // Queue the configuration message for transmission (info uses only input device)
    let config = vmm_config_input_only(args.sector_size);
    serial_transmitter.queue_config(&config);
    debug!(
        "Queued configuration message ({} bytes) for guest",
        serial_transmitter.buffer.len()
    );

    // Run the vCPU loop
    debug!("Starting guest execution");

    // Track VM errors - if set, we return an error instead of Ok(())
    let mut vm_error: Option<String> = None;

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                info!("Guest executed HLT");
                debug!("Info operation completed successfully!");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            // InfoResult is always shown, other messages only in verbose mode
                            let is_info_result = matches!(
                                &msg.payload,
                                Some(guest_::GuestMessage_::Payload::InfoResult(_))
                            );
                            if is_info_result {
                                print_info_result(
                                    &msg,
                                    &args.input,
                                    input_size,
                                    input_disk_blocks,
                                    args.ignore_quirks,
                                    args.extra_detail,
                                    &profile,
                                    &args.output,
                                );
                            } else {
                                debug!("{}", format_message(&msg));
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {}", line);
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{:x}, data={:?}", port, data);
                }
            }
            VcpuExit::IoIn(port, data) => {
                vmm_stats.lock().unwrap().record_io_in();
                if port == SERIAL_PORT {
                    for byte in data.iter_mut() {
                        *byte = serial_transmitter.next_byte().unwrap_or(0);
                    }
                } else if port == SERIAL_PORT + 5 {
                    let mut lsr = 0x60u8;
                    if serial_transmitter.has_data() {
                        lsr |= 0x01;
                    }
                    data[0] = lsr;
                } else {
                    for byte in data {
                        *byte = 0;
                    }
                }
            }
            VcpuExit::MmioRead(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_read();
                let value = device_set.mmio_read(addr);
                write_mmio_data(data, value);
            }
            VcpuExit::MmioWrite(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_write();
                let value = read_mmio_data(data);
                if let Some((device_index, should_process)) = device_set.mmio_write(addr, value) {
                    if io_thread.is_none() && should_process {
                        device_set.process_queue_for_device(
                            device_index,
                            &guest_mem,
                            &vmm_stats,
                        )?;
                    }
                }
            }
            VcpuExit::Shutdown => {
                vmm_stats.lock().unwrap().record_shutdown();
                eprintln!("\n--- VM Shutdown (triple fault?) ---");
                let regs = vcpu.get_regs()?;
                let sregs = vcpu.get_sregs()?;
                eprintln!(
                    "RIP=0x{:x}, RSP=0x{:x}, RBP=0x{:x}",
                    regs.rip, regs.rsp, regs.rbp
                );
                eprintln!(
                    "CR0=0x{:x}, CR3=0x{:x}, CR4=0x{:x}",
                    sregs.cr0, sregs.cr3, sregs.cr4
                );
                if regs.rsp < STACK_BASE || regs.rsp > STACK_TOP {
                    eprintln!();
                    eprintln!("*** LIKELY STACK OVERFLOW ***");
                    eprintln!("  RSP (0x{:x}) is outside stack region", regs.rsp);
                    eprintln!(
                        "  Stack region: 0x{:x} - 0x{:x} ({} bytes)",
                        STACK_BASE, STACK_TOP, STACK_SIZE
                    );
                }
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                eprintln!("VM Entry Failed! reason=0x{:x}, cpu={}", reason, cpu);
                vm_error = Some(format!(
                    "VM entry failed: reason=0x{:x}, cpu={}",
                    reason, cpu
                ));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {:?}", exit);
                vm_error = Some(format!("unexpected VM exit: {:?}", exit));
                break;
            }
        }
    }

    if let Some(mut thread) = io_thread {
        thread.stop();
    }

    if log::log_enabled!(log::Level::Debug) {
        vmm_stats.lock().unwrap().display();
    }

    // Return error if VM crashed or failed
    if let Some(error) = vm_error {
        return Err(error.into());
    }

    Ok(())
}

/// Run the copy operation
fn run_copy(args: CopyArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Validate sector sizes (must be powers of 2, 512 to 64KB)
    for (name, size) in [
        ("input", args.input_sector_size),
        ("output", args.output_sector_size),
    ] {
        if !(512..=MAX_SECTOR_SIZE).contains(&size) || !size.is_power_of_two() {
            return Err(format!(
                "{} sector size must be a power of 2, 512 to {} (got {})",
                name, MAX_SECTOR_SIZE, size
            )
            .into());
        }
    }

    // Determine if output should be sparse (default) or pre-allocated
    let sparse_output = !args.preallocate_output;

    // Auto-discover binaries in same directory as executable
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("copy.bin");

    // Load core binary (device init, call table setup)
    let core_code = load_guest_binary(core_path.to_str().unwrap())?;
    debug!(
        "Loaded core binary: {} bytes from {}",
        core_code.len(),
        core_path.display()
    );

    // Load operation binary (copy)
    let operation_code = load_guest_binary(operation_path.to_str().unwrap())?;
    debug!(
        "Loaded operation binary: {} bytes from {}",
        operation_code.len(),
        operation_path.display()
    );

    // Get input file size
    let input_size = std::fs::metadata(&args.input)?.len();
    debug!(
        "Input file: {} ({} bytes, {} sectors @ {} bytes/sector)",
        args.input,
        input_size,
        input_size / args.input_sector_size as u64,
        args.input_sector_size
    );

    // Determine output capacity (default to input size)
    let output_capacity = args.max_output_size.unwrap_or(input_size);

    // Open backing stores
    let input_backing = BackingStore::open(Path::new(&args.input), true, None, false)?;
    let output_backing = BackingStore::open(
        Path::new(&args.output),
        false,
        Some(output_capacity),
        sparse_output,
    )?;

    let output_mode_desc = if sparse_output {
        "sparse, grows on demand"
    } else {
        "pre-allocated"
    };
    debug!(
        "Output file: {} (capacity {} bytes, {} sectors @ {} bytes/sector, {})",
        args.output,
        output_capacity,
        output_capacity / args.output_sector_size as u64,
        args.output_sector_size,
        output_mode_desc
    );

    // Open KVM
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    // Check KVM binary statistics capability
    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    debug!("Created VM");

    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    debug!("Allocated {} bytes of guest memory", GUEST_MEM_SIZE);

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{:x}", GDT_BASE);

    setup_page_tables(&guest_mem)?;
    debug!("Set up page tables at 0x{:x}", PAGE_TABLE_BASE);

    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{:x}", GUEST_CODE_BASE);

    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{:x}", OPERATION_LOAD_ADDR);

    // Write CopyConfig at OPERATION_CONFIG_ADDR
    let mut copy_flags: u32 = 0;
    if args.verify {
        copy_flags |= COPY_CONFIG_FLAG_VERIFY;
    }
    if args.skip_zeros {
        copy_flags |= COPY_CONFIG_FLAG_SKIP_ZEROS;
    }
    if verbose {
        copy_flags |= COPY_CONFIG_FLAG_VERBOSE;
    }

    guest_mem.write_obj(COPY_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(copy_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(args.start_sector, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(args.sector_count, GuestAddress(OPERATION_CONFIG_ADDR + 16))?;
    debug!(
        "Wrote copy config at 0x{:x} (flags=0x{:x}, start={}, count={})",
        OPERATION_CONFIG_ADDR, copy_flags, args.start_sector, args.sector_count
    );

    // Create device set for managing virtio-block devices
    let mut device_set = DeviceSet::new();

    // Create virtio-block devices
    // Device 0: input (read-only)
    // Device 1: output (writable)
    let input_mmio = device_mmio_base(0);
    let input_vq = device_vq_base(0);
    let output_mmio = device_mmio_base(1);
    let output_vq = device_vq_base(1);

    let input_device = VirtioBlockDevice::new(
        input_backing,
        input_size,
        args.input_sector_size as u64,
        true,
        input_mmio,
        input_vq,
    );
    let output_device = VirtioBlockDevice::new(
        output_backing,
        output_capacity,
        args.output_sector_size as u64,
        false,
        output_mmio,
        output_vq,
    );
    debug!(
        "Created virtio-block devices at MMIO 0x{:x} and 0x{:x}",
        input_mmio, output_mmio
    );
    debug!(
        "  Input sector size: {} bytes, Output sector size: {} bytes",
        input_device.sector_size(),
        output_device.sector_size()
    );

    // Wrap devices and add to device set
    let input_device = Arc::new(Mutex::new(input_device));
    let output_device = Arc::new(Mutex::new(output_device));
    device_set.add_device(Arc::clone(&input_device), true); // is_input = true
    device_set.add_device(Arc::clone(&output_device), false); // is_input = false

    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Set up ioeventfd for queue notifications
    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut input_evt = IoEvent::new(input_mmio)?;
    let mut output_evt = IoEvent::new(output_mmio)?;

    match (input_evt.register(&vm), output_evt.register(&vm)) {
        (Ok(()), Ok(())) => {
            debug!("ioeventfd: enabled for queue notifications (with I/O thread)");

            // Create IoDevice entries via DeviceSet
            let io_devices = device_set.create_io_devices(vec![input_evt, output_evt]);

            // Start the I/O thread
            io_thread = Some(io_thread::IoThread::new(
                io_devices,
                Arc::clone(&guest_mem),
                Arc::clone(&vmm_stats),
            ));
        }
        (Err(e), _) | (_, Err(e)) => {
            debug!(
                "ioeventfd: failed to register ({:?}), falling back to VM exits",
                e
            );
        }
    }

    let mut vcpu = vm.create_vcpu(0)?;
    debug!("Created vCPU");

    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    debug!("Configured special registers for long mode");

    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;
    debug!(
        "Configured general registers (RIP=0x{:x}, RSP=0x{:x})",
        regs.rip, regs.rsp
    );

    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();

    let config = vmm_config(
        args.input_sector_size,
        args.output_sector_size,
        args.progress_percent,
    );
    serial_transmitter.queue_config(&config);
    let progress_desc = match args.progress_percent {
        0 => "every 10 sectors (legacy)".to_string(),
        100 => "none".to_string(),
        n => format!("every {}%", n),
    };
    debug!(
        "Queued configuration message ({} bytes) for guest, progress: {}",
        serial_transmitter.buffer.len(),
        progress_desc
    );

    // Run the vCPU loop
    debug!("Starting guest execution");

    // Track VM errors - if set, we return an error instead of Ok(())
    let mut vm_error: Option<String> = None;

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                info!("Guest executed HLT");
                debug!("Copy operation completed successfully!");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            debug!("{}", format_message(&msg));
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {}", line);
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{:x}, data={:?}", port, data);
                }
            }
            VcpuExit::IoIn(port, data) => {
                vmm_stats.lock().unwrap().record_io_in();
                if port == SERIAL_PORT {
                    for byte in data.iter_mut() {
                        *byte = serial_transmitter.next_byte().unwrap_or(0);
                    }
                } else if port == SERIAL_PORT + 5 {
                    let mut lsr = 0x60u8;
                    if serial_transmitter.has_data() {
                        lsr |= 0x01;
                    }
                    data[0] = lsr;
                } else {
                    for byte in data {
                        *byte = 0;
                    }
                }
            }
            VcpuExit::MmioRead(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_read();
                let value = device_set.mmio_read(addr);
                write_mmio_data(data, value);
            }
            VcpuExit::MmioWrite(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_write();
                let value = read_mmio_data(data);
                if let Some((device_index, should_process)) = device_set.mmio_write(addr, value) {
                    if io_thread.is_none() && should_process {
                        device_set.process_queue_for_device(
                            device_index,
                            &guest_mem,
                            &vmm_stats,
                        )?;
                    }
                }
            }
            VcpuExit::Shutdown => {
                vmm_stats.lock().unwrap().record_shutdown();
                eprintln!("\n--- VM Shutdown (triple fault?) ---");
                let regs = vcpu.get_regs()?;
                let sregs = vcpu.get_sregs()?;
                eprintln!(
                    "RIP=0x{:x}, RSP=0x{:x}, RBP=0x{:x}",
                    regs.rip, regs.rsp, regs.rbp
                );
                eprintln!(
                    "CR0=0x{:x}, CR3=0x{:x}, CR4=0x{:x}",
                    sregs.cr0, sregs.cr3, sregs.cr4
                );
                if regs.rsp < STACK_BASE || regs.rsp > STACK_TOP {
                    eprintln!();
                    eprintln!("*** LIKELY STACK OVERFLOW ***");
                    eprintln!("  RSP (0x{:x}) is outside stack region", regs.rsp);
                    eprintln!(
                        "  Stack region: 0x{:x} - 0x{:x} ({} bytes)",
                        STACK_BASE, STACK_TOP, STACK_SIZE
                    );
                    if regs.rsp < STACK_BASE {
                        let underflow = STACK_BASE - regs.rsp;
                        eprintln!("  Stack underflowed by {} bytes", underflow);
                    }
                } else {
                    let stack_used = STACK_TOP - regs.rsp;
                    let stack_percent = (stack_used * 100) / STACK_SIZE;
                    eprintln!();
                    eprintln!(
                        "Stack usage: {} / {} bytes ({}%)",
                        stack_used, STACK_SIZE, stack_percent
                    );
                    if stack_percent > 90 {
                        eprintln!("*** WARNING: Stack was nearly exhausted ***");
                    }
                }
                eprintln!();
                eprintln!(
                    "Guest memory: {} bytes (0x{:x})",
                    GUEST_MEM_SIZE, GUEST_MEM_SIZE
                );
                eprintln!("Code base: 0x{:x}", GUEST_CODE_BASE);
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                eprintln!("VM Entry Failed! reason=0x{:x}, cpu={}", reason, cpu);
                vm_error = Some(format!(
                    "VM entry failed: reason=0x{:x}, cpu={}",
                    reason, cpu
                ));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {:?}", exit);
                vm_error = Some(format!("unexpected VM exit: {:?}", exit));
                break;
            }
        }
    }

    if let Some(mut thread) = io_thread {
        thread.stop();
    }

    if log::log_enabled!(log::Level::Debug) {
        vmm_stats.lock().unwrap().display();
    }

    // Return error if VM crashed or failed
    if let Some(error) = vm_error {
        return Err(error.into());
    }

    Ok(())
}

/// Run the check operation (image integrity validation)
fn run_check(args: CheckArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Validate sector size (must be power of 2, 512 to 64KB)
    if !(512..=MAX_SECTOR_SIZE).contains(&args.sector_size) || !args.sector_size.is_power_of_two() {
        return Err(format!(
            "sector size must be a power of 2, 512 to {} (got {})",
            MAX_SECTOR_SIZE, args.sector_size
        )
        .into());
    }

    // Auto-discover binaries in same directory as executable
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("check.bin");

    // Load core binary (device init, call table setup)
    let core_code = load_guest_binary(core_path.to_str().unwrap())?;
    debug!(
        "Loaded core binary: {} bytes from {}",
        core_code.len(),
        core_path.display()
    );

    // Load operation binary (check)
    let operation_code = load_guest_binary(operation_path.to_str().unwrap())?;
    debug!(
        "Loaded operation binary: {} bytes from {}",
        operation_code.len(),
        operation_path.display()
    );

    // Handle --chain flag: discover backing chain before launching guest
    let chain = if args.chain {
        let input_path = Path::new(&args.input);
        let security_config = config::load_config().config.security;
        match discover_backing_chain(input_path, args.sector_size, &security_config) {
            Ok(chain) => {
                if verbose {
                    print_backing_chain(&chain);
                }
                Some(chain)
            }
            Err(e) => {
                return Err(format!("error discovering backing chain: {}", e).into());
            }
        }
    } else {
        None
    };

    // Get input file metadata
    let input_metadata = std::fs::metadata(&args.input)?;
    let input_size = input_metadata.len();
    debug!(
        "Input file: {} ({} bytes, {} sectors @ {} bytes/sector)",
        args.input,
        input_size,
        input_size / args.sector_size as u64,
        args.sector_size
    );

    // Open KVM
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    // Check KVM binary statistics capability
    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    // Create VM
    let vm = kvm.create_vm()?;
    debug!("Created VM");

    // Create guest memory
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    debug!("Allocated {} bytes of guest memory", GUEST_MEM_SIZE);

    // Get the memory region for KVM registration
    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    // Set up KVM memory region
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    // Set up GDT
    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{:x}", GDT_BASE);

    // Set up page tables (identity map)
    setup_page_tables(&guest_mem)?;
    debug!("Set up page tables at 0x{:x}", PAGE_TABLE_BASE);

    // Load core binary at GUEST_CODE_BASE (0x10000)
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{:x}", GUEST_CODE_BASE);

    // Load operation binary at OPERATION_LOAD_ADDR (0x20000)
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{:x}", OPERATION_LOAD_ADDR);

    // Write CheckConfig at OPERATION_CONFIG_ADDR
    // Layout: magic (u32), flags (u32)
    let mut check_flags: u32 = 0;
    if args.quiet {
        check_flags |= CHECK_CONFIG_FLAG_QUIET;
    }
    if verbose {
        check_flags |= CHECK_CONFIG_FLAG_VERBOSE;
    }
    if args.unsafe_quirks {
        check_flags |= CHECK_CONFIG_FLAG_UNSAFE_QUIRKS;
    }
    if args.chain {
        check_flags |= CHECK_CONFIG_FLAG_CHAIN;
    }
    guest_mem.write_obj(CHECK_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(check_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    debug!(
        "Wrote check config at 0x{:x} (flags=0x{:x})",
        OPERATION_CONFIG_ADDR, check_flags
    );

    // Create device set for managing virtio-block devices
    let mut device_set = DeviceSet::new();

    // Set up devices: either multi-device chain or single input
    let mut io_events: Vec<IoEvent> = Vec::new();

    if let Some(ref chain) = chain {
        // Multi-device chain mode: open each chain image as a separate device.
        // All devices use the same sector_size: this is the virtio-block
        // transport sector size (I/O granularity), not a format-level property.
        // The guest reconstructs file size as capacity * sector_size, which
        // works correctly regardless of the chosen sector_size value.
        for (i, image) in chain.images().iter().enumerate() {
            let backing = BackingStore::open(&image.path, true, None, false)?;
            let file_size = std::fs::metadata(&image.path)?.len();
            let mmio = device_mmio_base(i);
            let vq = device_vq_base(i);
            let device = VirtioBlockDevice::new(
                backing,
                file_size,
                args.sector_size as u64,
                true, // read-only
                mmio,
                vq,
            );
            debug!(
                "Created chain device [{}] at MMIO 0x{:x}, VQ 0x{:x}: {}",
                i,
                mmio,
                vq,
                image.path.display()
            );
            let device = Arc::new(Mutex::new(device));
            device_set.add_device(Arc::clone(&device), true);
            io_events.push(IoEvent::new(mmio)?);
        }

        // Write chain config to guest memory
        write_chain_config(&guest_mem, chain)?;
    } else {
        // Single-device mode (original behavior)
        let input_backing = BackingStore::open(Path::new(&args.input), true, None, false)?;
        let input_mmio = device_mmio_base(0);
        let input_vq = device_vq_base(0);
        let input_device = VirtioBlockDevice::new(
            input_backing,
            input_size,
            args.sector_size as u64,
            true, // read-only
            input_mmio,
            input_vq,
        );
        debug!(
            "Created virtio-block device at MMIO 0x{:x}, VQ 0x{:x}",
            input_mmio, input_vq
        );
        debug!("  Sector size: {} bytes", input_device.sector_size());
        let input_device = Arc::new(Mutex::new(input_device));
        device_set.add_device(Arc::clone(&input_device), true);
        io_events.push(IoEvent::new(input_mmio)?);
    }

    // Wrap guest memory in Arc for sharing
    let guest_mem = Arc::new(guest_mem);

    // Create shared statistics tracker
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Set up ioeventfd for queue notifications
    let mut io_thread: Option<io_thread::IoThread> = None;

    // Try to register all IoEvents with KVM.
    // Track how many succeeded so we can roll back on partial failure.
    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!(
                "ioeventfd: failed to register ({:?}), falling back to VM exits",
                e
            );
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }

    // If registration failed partway through, unregister the ones that
    // succeeded so they don't silently consume MMIO writes when falling
    // back to VM exits.
    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            if let Err(e) = evt.unregister(&vm) {
                warn!("ioeventfd: failed to unregister during rollback: {:?}", e);
            }
        }
    }

    let all_registered = !registration_failed;

    if all_registered && !io_events.is_empty() {
        debug!(
            "ioeventfd: enabled for {} device(s) (with I/O thread)",
            io_events.len()
        );

        // Create IoDevice entries via DeviceSet
        let io_devices = device_set.create_io_devices(io_events);

        // Start the I/O thread
        io_thread = Some(io_thread::IoThread::new(
            io_devices,
            Arc::clone(&guest_mem),
            Arc::clone(&vmm_stats),
        ));
    }

    // Create vCPU
    let mut vcpu = vm.create_vcpu(0)?;
    debug!("Created vCPU");

    // Set up registers
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    debug!("Configured special registers for long mode");

    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;
    debug!(
        "Configured general registers (RIP=0x{:x}, RSP=0x{:x})",
        regs.rip, regs.rsp
    );

    // Create serial decoder for protobuf messages from guest
    let mut serial_decoder = SerialDecoder::new();

    // Create serial transmitter for sending config to guest
    let mut serial_transmitter = SerialTransmitter::new();

    // Create debug buffer for COM2 output
    let mut debug_buffer = DebugBuffer::new();

    // Queue the configuration message for transmission
    let config = if let Some(ref chain) = chain {
        vmm_config_chain(args.sector_size, chain.len())
    } else {
        vmm_config_input_only(args.sector_size)
    };
    serial_transmitter.queue_config(&config);
    debug!(
        "Queued configuration message ({} bytes) for guest",
        serial_transmitter.buffer.len()
    );

    // Track check result for exit code (default to false - require explicit pass)
    let mut check_passed = false;

    // Track VM errors - if set, we return an error instead of Ok(())
    let mut vm_error: Option<String> = None;

    // Run the vCPU loop
    debug!("Starting guest execution");

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                info!("Guest executed HLT");
                debug!("Check operation completed!");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            // CheckResult is always shown (unless quiet), other messages only in verbose mode
                            let is_check_result = matches!(
                                &msg.payload,
                                Some(guest_::GuestMessage_::Payload::CheckResult(_))
                            );
                            if is_check_result {
                                if let Some(guest_::GuestMessage_::Payload::CheckResult(result)) =
                                    &msg.payload
                                {
                                    // Track if check passed
                                    check_passed = (result.flags & CHECK_RESULT_FLAG_VALID) != 0
                                        && result.total_errors == 0
                                        && result.chain_errors == 0;
                                }
                                if !args.quiet || !check_passed {
                                    print_check_result(
                                        &msg,
                                        &args.input,
                                        &args.output,
                                        args.unsafe_quirks,
                                    );
                                }
                            } else {
                                debug!("{}", format_message(&msg));
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {}", line);
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{:x}, data={:?}", port, data);
                }
            }
            VcpuExit::IoIn(port, data) => {
                vmm_stats.lock().unwrap().record_io_in();
                if port == SERIAL_PORT {
                    for byte in data.iter_mut() {
                        *byte = serial_transmitter.next_byte().unwrap_or(0);
                    }
                } else if port == SERIAL_PORT + 5 {
                    let mut lsr = 0x60u8;
                    if serial_transmitter.has_data() {
                        lsr |= 0x01;
                    }
                    data[0] = lsr;
                } else {
                    for byte in data {
                        *byte = 0;
                    }
                }
            }
            VcpuExit::MmioRead(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_read();
                let value = device_set.mmio_read(addr);
                write_mmio_data(data, value);
            }
            VcpuExit::MmioWrite(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_write();
                let value = read_mmio_data(data);
                if let Some((device_index, should_process)) = device_set.mmio_write(addr, value) {
                    if io_thread.is_none() && should_process {
                        device_set.process_queue_for_device(
                            device_index,
                            &guest_mem,
                            &vmm_stats,
                        )?;
                    }
                }
            }
            VcpuExit::Shutdown => {
                vmm_stats.lock().unwrap().record_shutdown();
                eprintln!("\n--- VM Shutdown (triple fault?) ---");
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                eprintln!("VM Entry Failed! reason=0x{:x}, cpu={}", reason, cpu);
                vm_error = Some(format!(
                    "VM entry failed: reason=0x{:x}, cpu={}",
                    reason, cpu
                ));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {:?}", exit);
                vm_error = Some(format!("unexpected VM exit: {:?}", exit));
                break;
            }
        }
    }

    if let Some(mut thread) = io_thread {
        thread.stop();
    }

    if log::log_enabled!(log::Level::Debug) {
        vmm_stats.lock().unwrap().display();
    }

    // Return error if VM crashed or failed
    if let Some(error) = vm_error {
        return Err(error.into());
    }

    // Return error if check failed (image has errors or is invalid)
    if !check_passed {
        return Err("image check failed: errors detected".into());
    }

    Ok(())
}

/// Print check result in human-readable or JSON format
fn print_check_result(
    msg: &guest_::GuestMessage,
    filename: &str,
    output_format: &str,
    unsafe_quirks: bool,
) {
    if let Some(guest_::GuestMessage_::Payload::CheckResult(result)) = &msg.payload {
        // Get absolute path for filename
        let abs_path = std::fs::canonicalize(filename)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| filename.to_string());

        if output_format == "json" {
            print_check_result_json(result, &abs_path, unsafe_quirks);
            return;
        }

        // Human-readable output (similar to qemu-img check)
        let has_errors = result.total_errors > 0;
        let is_valid = (result.flags & CHECK_RESULT_FLAG_VALID) != 0;
        let not_supported = (result.flags & CHECK_RESULT_FLAG_NOT_SUPPORTED) != 0;

        if not_supported {
            println!(
                "This image format ({}) does not support checks",
                result.format
            );
            return;
        }

        if has_errors {
            if result.corruptions > 0 {
                println!("{} errors were found on the image.", result.total_errors);
                println!("Data may be corrupted, or the image has been written incompletely.");
            }
            if result.leaks > 0 {
                println!("{} leaked clusters were found on the image.", result.leaks);
                println!("This means waste of disk space, but no harm to data.");
            }
        } else if is_valid && result.chain_errors == 0 {
            println!("No errors were found on the image.");
        }

        if result.chain_errors > 0 {
            println!("{} backing chain error(s) were found.", result.chain_errors);
        }

        // Show statistics
        if result.clusters_checked > 0 || result.clusters_allocated > 0 {
            println!(
                "{}/{} = {:.2}% allocated, {:.2}% fragmented",
                result.clusters_allocated,
                result.clusters_checked,
                if result.clusters_checked > 0 {
                    (result.clusters_allocated as f64 / result.clusters_checked as f64) * 100.0
                } else {
                    0.0
                },
                result.fragmentation as f64
            );
        }

        // Show image end offset
        if result.image_end_offset > 0 {
            println!("Image end offset: {}", result.image_end_offset);
        }
    }
}

/// Print check result in JSON format
///
/// When `unsafe_quirks` is true, fields with zero values (corruptions,
/// leaks, refcount-errors) are omitted to match qemu-img check's
/// conditional schema. When false, all fields are always emitted for a
/// consistent, predictable JSON schema.
fn print_check_result_json(
    result: &guest_protocol::guest_::CheckResultMessage,
    filename: &str,
    unsafe_quirks: bool,
) {
    // Extract flags for boolean fields
    let is_dirty = (result.flags & CHECK_RESULT_FLAG_DIRTY) != 0;
    let is_corrupt = (result.flags & CHECK_RESULT_FLAG_CORRUPT_BIT) != 0;

    println!("{{");
    println!("    \"filename\": \"{}\",", escape_json_string(filename));
    println!(
        "    \"format\": \"{}\",",
        escape_json_string(&result.format)
    );
    println!("    \"check-errors\": {},", result.total_errors);
    if !unsafe_quirks || result.corruptions > 0 {
        println!("    \"corruptions\": {},", result.corruptions);
    }
    if !unsafe_quirks || result.leaks > 0 {
        println!("    \"leaks\": {},", result.leaks);
    }
    if !unsafe_quirks || result.refcount_errors > 0 {
        println!("    \"refcount-errors\": {},", result.refcount_errors);
    }
    println!("    \"image-end-offset\": {},", result.image_end_offset);
    println!("    \"total-clusters\": {},", result.clusters_checked);
    println!("    \"allocated-clusters\": {},", result.clusters_allocated);
    println!("    \"fragmented-clusters\": {},", result.fragmentation);
    // QCOW2-specific flags (dirty bit = unclean shutdown, corrupt bit = known corruption)
    println!("    \"dirty\": {},", is_dirty);
    println!("    \"corrupt\": {},", is_corrupt);
    println!("    \"chain-errors\": {}", result.chain_errors);
    println!("}}");
}

fn run_compare(args: CompareArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Validate sector size (must be power of 2, 512 to 64KB)
    if !(512..=MAX_SECTOR_SIZE).contains(&args.sector_size) || !args.sector_size.is_power_of_two() {
        return Err(format!(
            "sector size must be a power of 2, 512 to {} (got {})",
            MAX_SECTOR_SIZE, args.sector_size
        )
        .into());
    }

    // Auto-discover binaries in same directory as executable
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("compare.bin");

    // Load core binary (device init, call table setup)
    let core_code = load_guest_binary(core_path.to_str().unwrap())?;
    debug!(
        "Loaded core binary: {} bytes from {}",
        core_code.len(),
        core_path.display()
    );

    // Load operation binary (compare)
    let operation_code = load_guest_binary(operation_path.to_str().unwrap())?;
    debug!(
        "Loaded operation binary: {} bytes from {}",
        operation_code.len(),
        operation_path.display()
    );

    // Discover backing chains for both images (includes format detection)
    let security_config = config::load_config().config.security;
    let chain1 =
        discover_backing_chain(Path::new(&args.image1), args.sector_size, &security_config)
            .map_err(|e| format!("error discovering backing chain for {}: {}", args.image1, e))?;
    let chain2 =
        discover_backing_chain(Path::new(&args.image2), args.sector_size, &security_config)
            .map_err(|e| format!("error discovering backing chain for {}: {}", args.image2, e))?;

    if verbose {
        debug!("Image 1 chain ({} image(s)):", chain1.len());
        print_backing_chain(&chain1);
        debug!("Image 2 chain ({} image(s)):", chain2.len());
        print_backing_chain(&chain2);
    }

    let total_devices = chain1.len() + chain2.len();
    debug!(
        "Total devices: {} (image1: {} + image2: {})",
        total_devices,
        chain1.len(),
        chain2.len()
    );

    if total_devices > MAX_CHAIN_DEVICES {
        return Err(format!(
            "combined chain depth {} (image1: {} + image2: {}) exceeds maximum of {} devices",
            total_devices,
            chain1.len(),
            chain2.len(),
            MAX_CHAIN_DEVICES
        )
        .into());
    }

    // Open KVM
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    // Check KVM binary statistics capability
    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    // Create VM
    let vm = kvm.create_vm()?;
    debug!("Created VM");

    // Create guest memory
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    debug!("Allocated {} bytes of guest memory", GUEST_MEM_SIZE);

    // Get the memory region for KVM registration
    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    // Set up KVM memory region
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    // Set up GDT
    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{:x}", GDT_BASE);

    // Set up page tables (identity map)
    setup_page_tables(&guest_mem)?;
    debug!("Set up page tables at 0x{:x}", PAGE_TABLE_BASE);

    // Load core binary at GUEST_CODE_BASE (0x10000)
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{:x}", GUEST_CODE_BASE);

    // Load operation binary at OPERATION_LOAD_ADDR (0x20000)
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{:x}", OPERATION_LOAD_ADDR);

    // Write CompareConfig at OPERATION_CONFIG_ADDR
    // Layout: magic (u32), flags (u32), image1_device_count (u32), image2_device_count (u32)
    let mut compare_flags: u32 = 0;
    if args.strict {
        compare_flags |= COMPARE_CONFIG_FLAG_STRICT;
    }
    if args.quiet {
        compare_flags |= COMPARE_CONFIG_FLAG_QUIET;
    }
    if verbose {
        compare_flags |= COMPARE_CONFIG_FLAG_VERBOSE;
    }
    guest_mem.write_obj(COMPARE_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(compare_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(chain1.len() as u32, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(
        chain2.len() as u32,
        GuestAddress(OPERATION_CONFIG_ADDR + 12),
    )?;
    debug!(
        "Wrote compare config at 0x{:x} (flags=0x{:x}, chain1={}, chain2={})",
        OPERATION_CONFIG_ADDR,
        compare_flags,
        chain1.len(),
        chain2.len()
    );

    // Write ChainConfig with format metadata for all chain images
    // Devices are laid out: [chain1 images...] [chain2 images...]
    guest_mem.write_obj(CHAIN_CONFIG_MAGIC, GuestAddress(CHAIN_CONFIG_ADDR))?;
    guest_mem.write_obj(total_devices as u32, GuestAddress(CHAIN_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(CHAIN_CONFIG_VERSION, GuestAddress(CHAIN_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(0u32, GuestAddress(CHAIN_CONFIG_ADDR + 12))?; // reserved

    let devices_base = CHAIN_CONFIG_ADDR + 16;
    let mut dev_idx: usize = 0;

    // Write chain1 device info entries
    for image in chain1.images().iter() {
        let dev_base = devices_base + (dev_idx as u64 * 32);
        guest_mem.write_obj(image.format.to_shared_format_u32(), GuestAddress(dev_base))?;
        guest_mem.write_obj(image.flags, GuestAddress(dev_base + 4))?;
        guest_mem.write_obj(image.virtual_size, GuestAddress(dev_base + 8))?;
        guest_mem.write_obj(image.actual_size, GuestAddress(dev_base + 16))?;
        guest_mem.write_obj(image.cluster_size, GuestAddress(dev_base + 24))?;
        guest_mem.write_obj(0u32, GuestAddress(dev_base + 28))?;
        dev_idx += 1;
    }

    // Write chain2 device info entries
    for image in chain2.images().iter() {
        let dev_base = devices_base + (dev_idx as u64 * 32);
        guest_mem.write_obj(image.format.to_shared_format_u32(), GuestAddress(dev_base))?;
        guest_mem.write_obj(image.flags, GuestAddress(dev_base + 4))?;
        guest_mem.write_obj(image.virtual_size, GuestAddress(dev_base + 8))?;
        guest_mem.write_obj(image.actual_size, GuestAddress(dev_base + 16))?;
        guest_mem.write_obj(image.cluster_size, GuestAddress(dev_base + 24))?;
        guest_mem.write_obj(0u32, GuestAddress(dev_base + 28))?;
        dev_idx += 1;
    }

    debug!(
        "Wrote chain config at 0x{:x}: device_count={}, chain1={}, chain2={}",
        CHAIN_CONFIG_ADDR,
        total_devices,
        chain1.len(),
        chain2.len()
    );

    // Create device set for managing virtio-block devices
    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    // Set up devices for image1's chain (devices 0..chain1.len()-1)
    for (i, image) in chain1.images().iter().enumerate() {
        let backing = BackingStore::open(&image.path, true, None, false)?;
        let file_size = std::fs::metadata(&image.path)?.len();
        let mmio = device_mmio_base(i);
        let vq = device_vq_base(i);
        let device = VirtioBlockDevice::new(
            backing,
            file_size,
            args.sector_size as u64,
            true, // read-only
            mmio,
            vq,
        );
        debug!(
            "Created chain1 device [{}] at MMIO 0x{:x}, VQ 0x{:x}: {}",
            i,
            mmio,
            vq,
            image.path.display()
        );
        let device = Arc::new(Mutex::new(device));
        device_set.add_device(Arc::clone(&device), true);
        io_events.push(IoEvent::new(mmio)?);
    }

    // Set up devices for image2's chain (devices chain1.len()..total_devices-1)
    for (j, image) in chain2.images().iter().enumerate() {
        let i = chain1.len() + j;
        let backing = BackingStore::open(&image.path, true, None, false)?;
        let file_size = std::fs::metadata(&image.path)?.len();
        let mmio = device_mmio_base(i);
        let vq = device_vq_base(i);
        let device = VirtioBlockDevice::new(
            backing,
            file_size,
            args.sector_size as u64,
            true, // read-only
            mmio,
            vq,
        );
        debug!(
            "Created chain2 device [{}] at MMIO 0x{:x}, VQ 0x{:x}: {}",
            i,
            mmio,
            vq,
            image.path.display()
        );
        let device = Arc::new(Mutex::new(device));
        device_set.add_device(Arc::clone(&device), true);
        io_events.push(IoEvent::new(mmio)?);
    }

    // Wrap guest memory in Arc for sharing
    let guest_mem = Arc::new(guest_mem);

    // Create shared statistics tracker
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Set up ioeventfd for queue notifications
    let mut io_thread: Option<io_thread::IoThread> = None;

    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!(
                "ioeventfd: failed to register ({:?}), falling back to VM exits",
                e
            );
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }

    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            if let Err(e) = evt.unregister(&vm) {
                warn!("ioeventfd: failed to unregister during rollback: {:?}", e);
            }
        }
    }

    let all_registered = !registration_failed;

    if all_registered && !io_events.is_empty() {
        debug!(
            "ioeventfd: enabled for {} device(s) (with I/O thread)",
            io_events.len()
        );

        let io_devices = device_set.create_io_devices(io_events);

        io_thread = Some(io_thread::IoThread::new(
            io_devices,
            Arc::clone(&guest_mem),
            Arc::clone(&vmm_stats),
        ));
    }

    // Create vCPU
    let mut vcpu = vm.create_vcpu(0)?;
    debug!("Created vCPU");

    // Set up registers
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    debug!("Configured special registers for long mode");

    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;
    debug!(
        "Configured general registers (RIP=0x{:x}, RSP=0x{:x})",
        regs.rip, regs.rsp
    );

    // Create serial decoder for protobuf messages from guest
    let mut serial_decoder = SerialDecoder::new();

    // Create serial transmitter for sending config to guest
    let mut serial_transmitter = SerialTransmitter::new();

    // Create debug buffer for COM2 output
    let mut debug_buffer = DebugBuffer::new();

    // Queue the configuration message for transmission (all chain devices)
    let config = vmm_config_chain(args.sector_size, total_devices);
    serial_transmitter.queue_config(&config);
    debug!(
        "Queued configuration message ({} bytes) for guest",
        serial_transmitter.buffer.len()
    );

    // Track compare result for exit code
    let mut compare_identical = false;
    let mut compare_result_received = false;

    // Track VM errors
    let mut vm_error: Option<String> = None;

    // Run the vCPU loop
    debug!("Starting guest execution");

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                info!("Guest executed HLT");
                debug!("Compare operation completed!");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            let is_compare_result = matches!(
                                &msg.payload,
                                Some(guest_::GuestMessage_::Payload::CompareResult(_))
                            );
                            if is_compare_result {
                                if let Some(guest_::GuestMessage_::Payload::CompareResult(result)) =
                                    &msg.payload
                                {
                                    let size_mismatch = (result.flags & 1) != 0;
                                    // In strict mode, size mismatch means not identical
                                    // regardless of content
                                    compare_identical =
                                        result.identical && !(args.strict && size_mismatch);
                                    compare_result_received = true;
                                }
                                print_compare_result(&msg, &args.output, args.strict);
                            } else {
                                debug!("{}", format_message(&msg));
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {}", line);
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{:x}, data={:?}", port, data);
                }
            }
            VcpuExit::IoIn(port, data) => {
                vmm_stats.lock().unwrap().record_io_in();
                if port == SERIAL_PORT {
                    for byte in data.iter_mut() {
                        *byte = serial_transmitter.next_byte().unwrap_or(0);
                    }
                } else if port == SERIAL_PORT + 5 {
                    let mut lsr = 0x60u8;
                    if serial_transmitter.has_data() {
                        lsr |= 0x01;
                    }
                    data[0] = lsr;
                } else {
                    for byte in data {
                        *byte = 0;
                    }
                }
            }
            VcpuExit::MmioRead(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_read();
                let value = device_set.mmio_read(addr);
                write_mmio_data(data, value);
            }
            VcpuExit::MmioWrite(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_write();
                let value = read_mmio_data(data);
                if let Some((device_index, should_process)) = device_set.mmio_write(addr, value) {
                    if io_thread.is_none() && should_process {
                        device_set.process_queue_for_device(
                            device_index,
                            &guest_mem,
                            &vmm_stats,
                        )?;
                    }
                }
            }
            VcpuExit::Shutdown => {
                vmm_stats.lock().unwrap().record_shutdown();
                eprintln!("\n--- VM Shutdown (triple fault?) ---");
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                eprintln!("VM Entry Failed! reason=0x{:x}, cpu={}", reason, cpu);
                vm_error = Some(format!(
                    "VM entry failed: reason=0x{:x}, cpu={}",
                    reason, cpu
                ));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {:?}", exit);
                vm_error = Some(format!("unexpected VM exit: {:?}", exit));
                break;
            }
        }
    }

    if let Some(mut thread) = io_thread {
        thread.stop();
    }

    if log::log_enabled!(log::Level::Debug) {
        vmm_stats.lock().unwrap().display();
    }

    // Return error if VM crashed or failed
    if let Some(error) = vm_error {
        return Err(error.into());
    }

    // Return error if no result was received
    if !compare_result_received {
        return Err("compare operation failed: no result received".into());
    }

    // Exit with code 1 if images differ (no error message, matching
    // qemu-img compare which just prints the mismatch info to stdout)
    if !compare_identical {
        std::process::exit(1);
    }

    Ok(())
}

fn run_convert(args: ConvertArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Parse and validate output format
    let target_format = match args.output_format.as_str() {
        "raw" => 1u32,   // ImageFormat::Raw
        "qcow2" => 2u32, // ImageFormat::Qcow2
        other => {
            return Err(format!(
                "unsupported output format '{}' \
                 (supported: 'raw', 'qcow2')",
                other
            )
            .into());
        }
    };
    let is_qcow2_output = target_format == 2;

    // Validate sector size (must be power of 2, 512 to 64KB)
    if !(512..=MAX_SECTOR_SIZE).contains(&args.sector_size) || !args.sector_size.is_power_of_two() {
        return Err(format!(
            "sector size must be a power of 2, 512 to {} (got {})",
            MAX_SECTOR_SIZE, args.sector_size
        )
        .into());
    }

    // Validate cluster size for QCOW2 output
    if is_qcow2_output
        && (!(512..=65536).contains(&args.cluster_size) || !args.cluster_size.is_power_of_two())
    {
        return Err(format!(
            "cluster size must be a power of 2, \
             512 to 65536 (got {})",
            args.cluster_size
        )
        .into());
    }

    // Auto-discover binaries
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("convert.bin");

    let core_code = load_guest_binary(core_path.to_str().unwrap())?;
    debug!(
        "Loaded core binary: {} bytes from {}",
        core_code.len(),
        core_path.display()
    );

    let operation_code = load_guest_binary(operation_path.to_str().unwrap())?;
    debug!(
        "Loaded operation binary: {} bytes from {}",
        operation_code.len(),
        operation_path.display()
    );

    // Discover input backing chain
    let security_config = config::load_config().config.security;
    let chain = discover_backing_chain(Path::new(&args.input), args.sector_size, &security_config)
        .map_err(|e| format!("error discovering backing chain for {}: {}", args.input, e))?;

    if verbose {
        debug!("Input chain ({} image(s)):", chain.len());
        print_backing_chain(&chain);
    }

    let input_device_count = chain.len();
    // Reserve one device slot for the output device to prevent its VQ
    // memory from colliding with DMA_POOL_BASE.
    if input_device_count + 1 > MAX_CHAIN_DEVICES {
        return Err(format!(
            "chain depth {} plus output device exceeds maximum of {} devices",
            input_device_count, MAX_CHAIN_DEVICES
        )
        .into());
    }

    // Reject images with cluster_size > MAX_SECTOR_SIZE (64KB).
    // The guest buffer is limited to MAX_SECTOR_SIZE, so larger clusters
    // cannot be processed correctly.
    for image in chain.images() {
        if image.cluster_size > MAX_SECTOR_SIZE {
            return Err(format!(
                "cluster size {}KB in {} exceeds maximum supported {}KB",
                image.cluster_size / 1024,
                image.path.display(),
                MAX_SECTOR_SIZE / 1024
            )
            .into());
        }
    }

    // Get virtual size from top of chain for output capacity
    let virtual_size = chain.images()[0].virtual_size;
    if virtual_size == 0 {
        return Err("input image has zero virtual size".into());
    }

    // Open output file.
    // For QCOW2 output the file is always sparse (the guest
    // writes clusters on demand) and the capacity needs headroom
    // for metadata (L1/L2 tables, refcount structures).
    let output_capacity = if is_qcow2_output {
        virtual_size
            .saturating_add(virtual_size / 100)
            .saturating_add(10 * 1024 * 1024)
    } else {
        virtual_size
    };

    let output_backing = if args.no_create {
        BackingStore::open(Path::new(&args.output), false, None, false)?
    } else if is_qcow2_output {
        BackingStore::open(
            Path::new(&args.output),
            false,
            Some(output_capacity),
            true, // always sparse for QCOW2
        )?
    } else {
        BackingStore::open(
            Path::new(&args.output),
            false,
            Some(virtual_size),
            // sparse when skipping zeros
            args.skip_zeros,
        )?
    };

    debug!(
        "Output file: {} (capacity {} bytes)",
        args.output, output_capacity
    );

    // Open KVM
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    debug!("Created VM");

    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    debug!("Allocated {} bytes of guest memory", GUEST_MEM_SIZE);

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{:x}", GDT_BASE);

    setup_page_tables(&guest_mem)?;
    debug!("Set up page tables at 0x{:x}", PAGE_TABLE_BASE);

    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{:x}", GUEST_CODE_BASE);

    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{:x}", OPERATION_LOAD_ADDR);

    // Write ConvertConfig at OPERATION_CONFIG_ADDR
    let mut convert_flags: u32 = 0;
    if args.skip_zeros {
        convert_flags |= CONVERT_CONFIG_FLAG_SKIP_ZEROS;
    }
    if verbose {
        convert_flags |= CONVERT_CONFIG_FLAG_VERBOSE;
    }
    let output_cluster_bits: u32 = if is_qcow2_output {
        args.cluster_size.trailing_zeros()
    } else {
        0
    };

    guest_mem.write_obj(CONVERT_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(convert_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(
        input_device_count as u32,
        GuestAddress(OPERATION_CONFIG_ADDR + 8),
    )?;
    guest_mem.write_obj(target_format, GuestAddress(OPERATION_CONFIG_ADDR + 12))?;
    guest_mem.write_obj(
        output_cluster_bits,
        GuestAddress(OPERATION_CONFIG_ADDR + 16),
    )?;
    debug!(
        "Wrote convert config at 0x{:x} \
         (flags=0x{:x}, chain={}, format={}, cluster_bits={})",
        OPERATION_CONFIG_ADDR,
        convert_flags,
        input_device_count,
        target_format,
        output_cluster_bits,
    );

    // Write ChainConfig for input chain
    write_chain_config(&guest_mem, &chain)?;

    // Create device set: input chain devices + output device
    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    // Set up input chain devices (read-only)
    for (i, image) in chain.images().iter().enumerate() {
        let backing = BackingStore::open(&image.path, true, None, false)?;
        let file_size = std::fs::metadata(&image.path)?.len();
        let mmio = device_mmio_base(i);
        let vq = device_vq_base(i);
        let device = VirtioBlockDevice::new(
            backing,
            file_size,
            args.sector_size as u64,
            true, // read-only
            mmio,
            vq,
        );
        debug!(
            "Created input device [{}] at MMIO 0x{:x}: {}",
            i,
            mmio,
            image.path.display()
        );
        let device = Arc::new(Mutex::new(device));
        device_set.add_device(Arc::clone(&device), true);
        io_events.push(IoEvent::new(mmio)?);
    }

    // Set up output device (writable).
    // For QCOW2 output, use the smaller of sector_size and
    // cluster_size so that cluster writes align to whole sectors.
    let output_sector_size = if is_qcow2_output {
        core::cmp::min(args.sector_size, args.cluster_size)
    } else {
        args.sector_size
    };
    let output_idx = input_device_count;
    let output_mmio = device_mmio_base(output_idx);
    let output_vq = device_vq_base(output_idx);
    let output_device = VirtioBlockDevice::new(
        output_backing,
        output_capacity,
        output_sector_size as u64,
        false, // writable
        output_mmio,
        output_vq,
    );
    debug!(
        "Created output device [{}] at MMIO 0x{:x}: {}",
        output_idx, output_mmio, args.output
    );
    let output_device = Arc::new(Mutex::new(output_device));
    device_set.add_device(Arc::clone(&output_device), false);
    io_events.push(IoEvent::new(output_mmio)?);

    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Set up ioeventfd for queue notifications
    let mut io_thread: Option<io_thread::IoThread> = None;

    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!(
                "ioeventfd: failed to register ({:?}), falling back to VM exits",
                e
            );
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }

    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            if let Err(e) = evt.unregister(&vm) {
                warn!("ioeventfd: failed to unregister during rollback: {:?}", e);
            }
        }
    }

    let all_registered = !registration_failed;

    if all_registered && !io_events.is_empty() {
        debug!(
            "ioeventfd: enabled for {} device(s) (with I/O thread)",
            io_events.len()
        );

        let io_devices = device_set.create_io_devices(io_events);

        io_thread = Some(io_thread::IoThread::new(
            io_devices,
            Arc::clone(&guest_mem),
            Arc::clone(&vmm_stats),
        ));
    }

    // Create vCPU
    let mut vcpu = vm.create_vcpu(0)?;
    debug!("Created vCPU");

    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    debug!("Configured special registers for long mode");

    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;
    debug!(
        "Configured general registers (RIP=0x{:x}, RSP=0x{:x})",
        regs.rip, regs.rsp
    );

    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();

    // Queue config with input chain devices + output device
    let config = vmm_config_chain_with_output(
        args.sector_size,
        output_sector_size,
        input_device_count,
        args.progress_percent,
    );
    serial_transmitter.queue_config(&config);
    debug!(
        "Queued configuration message ({} bytes) for guest",
        serial_transmitter.buffer.len()
    );

    // Track VM errors
    let mut vm_error: Option<String> = None;

    // Run the vCPU loop
    debug!("Starting guest execution");

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                info!("Guest executed HLT");
                debug!("Convert operation completed!");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            debug!("{}", format_message(&msg));
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {}", line);
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{:x}, data={:?}", port, data);
                }
            }
            VcpuExit::IoIn(port, data) => {
                vmm_stats.lock().unwrap().record_io_in();
                if port == SERIAL_PORT {
                    for byte in data.iter_mut() {
                        *byte = serial_transmitter.next_byte().unwrap_or(0);
                    }
                } else if port == SERIAL_PORT + 5 {
                    let mut lsr = 0x60u8;
                    if serial_transmitter.has_data() {
                        lsr |= 0x01;
                    }
                    data[0] = lsr;
                } else {
                    for byte in data {
                        *byte = 0;
                    }
                }
            }
            VcpuExit::MmioRead(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_read();
                let value = device_set.mmio_read(addr);
                write_mmio_data(data, value);
            }
            VcpuExit::MmioWrite(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_write();
                let value = read_mmio_data(data);
                if let Some((device_index, should_process)) = device_set.mmio_write(addr, value) {
                    if io_thread.is_none() && should_process {
                        device_set.process_queue_for_device(
                            device_index,
                            &guest_mem,
                            &vmm_stats,
                        )?;
                    }
                }
            }
            VcpuExit::Shutdown => {
                vmm_stats.lock().unwrap().record_shutdown();
                eprintln!("\n--- VM Shutdown (triple fault?) ---");
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                eprintln!("VM Entry Failed! reason=0x{:x}, cpu={}", reason, cpu);
                vm_error = Some(format!(
                    "VM entry failed: reason=0x{:x}, cpu={}",
                    reason, cpu
                ));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {:?}", exit);
                vm_error = Some(format!("unexpected VM exit: {:?}", exit));
                break;
            }
        }
    }

    if let Some(mut thread) = io_thread {
        thread.stop();
    }

    if log::log_enabled!(log::Level::Debug) {
        vmm_stats.lock().unwrap().display();
    }

    if let Some(error) = vm_error {
        return Err(error.into());
    }

    Ok(())
}

/// Print compare result in human-readable or JSON format.
///
/// Human output matches qemu-img compare (all output to stdout):
/// - Identical: "Images are identical.\n"
/// - Different: "Content mismatch at offset {offset}!\n"
/// - Size warning (non-strict): "Warning: Image size mismatch!\n"
/// - Size strict: "Strict mode: Image size mismatch!\n"
fn print_compare_result(msg: &guest_::GuestMessage, output_format: &str, strict: bool) {
    if let Some(guest_::GuestMessage_::Payload::CompareResult(result)) = &msg.payload {
        if output_format == "json" {
            print_compare_result_json(result);
            return;
        }

        // Human-readable output (matches qemu-img compare exactly)
        // All output goes to stdout to match qemu-img behavior
        let size_mismatch = (result.flags & 1) != 0; // FLAG_SIZE_MISMATCH

        if size_mismatch {
            if strict {
                println!("Strict mode: Image size mismatch!");
            } else {
                println!("Warning: Image size mismatch!");
            }
        }

        if !strict || !size_mismatch {
            if result.identical {
                println!("Images are identical.");
            } else {
                println!(
                    "Content mismatch at offset {}!",
                    result.first_mismatch_offset
                );
            }
        }
    }
}

/// Print compare result in JSON format
fn print_compare_result_json(result: &guest_protocol::guest_::CompareResultMessage) {
    let size_mismatch = (result.flags & 1) != 0;

    println!("{{");
    println!("    \"identical\": {},", result.identical);
    println!(
        "    \"first-mismatch-offset\": {},",
        result.first_mismatch_offset
    );
    println!(
        "    \"total-bytes-compared\": {},",
        result.total_bytes_compared
    );
    println!("    \"size-mismatch\": {}", size_mismatch);
    println!("}}");
}

fn load_guest_binary(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut code = Vec::new();
    file.read_to_end(&mut code)?;
    Ok(code)
}

fn create_guest_memory(size: u64) -> Result<GuestMemoryMmap, Box<dyn std::error::Error>> {
    let regions = vec![(GuestAddress(0), size as usize)];
    let guest_mem = GuestMemoryMmap::<()>::from_ranges(&regions)?;
    Ok(guest_mem)
}

fn setup_gdt(guest_mem: &GuestMemoryMmap) -> Result<(), Box<dyn std::error::Error>> {
    // Null descriptor
    guest_mem.write_obj(0u64, GuestAddress(GDT_BASE))?;
    // 64-bit code segment
    guest_mem.write_obj(0x00AF_9A00_0000_FFFFu64, GuestAddress(GDT_BASE + 8))?;
    // 64-bit data segment
    guest_mem.write_obj(0x00CF_9200_0000_FFFFu64, GuestAddress(GDT_BASE + 16))?;
    Ok(())
}

fn setup_page_tables(guest_mem: &GuestMemoryMmap) -> Result<(), Box<dyn std::error::Error>> {
    let pml4_addr = PAGE_TABLE_BASE;
    let pdpt_addr = PAGE_TABLE_BASE + 0x1000;
    let pd_addr = PAGE_TABLE_BASE + 0x2000;

    // PML4[0] -> PDPT
    guest_mem.write_obj(
        pdpt_addr | PTE_PRESENT | PTE_WRITABLE,
        GuestAddress(pml4_addr),
    )?;

    // PDPT[0] -> PD
    guest_mem.write_obj(
        pd_addr | PTE_PRESENT | PTE_WRITABLE,
        GuestAddress(pdpt_addr),
    )?;

    // PD entries: 512 x 2MB pages = 1GB identity mapped
    for i in 0..512u64 {
        let phys_addr = i * 0x200000;
        let entry = phys_addr | PTE_PRESENT | PTE_WRITABLE | PTE_PAGE_SIZE;
        guest_mem.write_obj(entry, GuestAddress(pd_addr + i * 8))?;
    }

    Ok(())
}

fn setup_sregs(sregs: &mut kvm_sregs) {
    sregs.cr0 = CR0_PE | CR0_PG;
    sregs.cr3 = PAGE_TABLE_BASE;
    sregs.cr4 = CR4_PAE;
    sregs.efer = EFER_LME | EFER_LMA;

    sregs.gdt.base = GDT_BASE;
    sregs.gdt.limit = 23;

    sregs.cs = make_segment(CODE_SELECTOR, 0, 0xFFFF_FFFF, 11, true);
    let data_seg = make_segment(DATA_SELECTOR, 0, 0xFFFF_FFFF, 3, false);
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;

    sregs.idt.base = 0;
    sregs.idt.limit = 0;
}

fn make_segment(selector: u16, base: u64, limit: u32, seg_type: u8, code: bool) -> kvm_segment {
    kvm_segment {
        base,
        limit,
        selector,
        type_: seg_type,
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: if code { 1 } else { 0 },
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

fn setup_regs(regs: &mut kvm_regs) {
    regs.rip = GUEST_CODE_BASE;
    regs.rsp = STACK_TOP;
    regs.rflags = 0x2;
    regs.rax = 0;
    regs.rbx = 0;
    regs.rcx = 0;
    regs.rdx = 0;
    regs.rsi = 0;
    regs.rdi = 0;
    regs.rbp = 0;
    regs.r8 = 0;
    regs.r9 = 0;
    regs.r10 = 0;
    regs.r11 = 0;
    regs.r12 = 0;
    regs.r13 = 0;
    regs.r14 = 0;
    regs.r15 = 0;
}

fn read_mmio_data(data: &[u8]) -> u32 {
    match data.len() {
        1 => data[0] as u32,
        2 => u16::from_le_bytes([data[0], data[1]]) as u32,
        4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        _ => 0,
    }
}

fn write_mmio_data(data: &mut [u8], value: u32) {
    match data.len() {
        1 => data[0] = value as u8,
        2 => {
            let bytes = (value as u16).to_le_bytes();
            data[0] = bytes[0];
            data[1] = bytes[1];
        }
        4 => {
            let bytes = value.to_le_bytes();
            data[..4].copy_from_slice(&bytes);
        }
        8 => {
            let bytes = (value as u64).to_le_bytes();
            data[..8].copy_from_slice(&bytes);
        }
        _ => {}
    }
}
