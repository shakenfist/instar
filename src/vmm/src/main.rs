//! KVM VMM with separate core and operation binaries.
//!
//! This VMM loads two separate binaries:
//! - Core binary (0x10000): Device initialization, call table setup
//! - Operation binary (0x22000): Specific operation (copy, info, etc.)
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

use clap::{Args, Parser, Subcommand, ValueEnum};
use guest_protocol::{
    decode_framed, encode_vmm_config_framed, guest_, vmm_config, vmm_config_chain,
    vmm_config_chain_with_output, vmm_config_input_only, FRAME_HEADER_SIZE,
};
use kvm_bindings::{kvm_regs, kvm_segment, kvm_sregs, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit};
use log::{debug, info, warn};
use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use backing::BackingStore;
use chain::{
    check_chain_depth, check_circular_reference, peek_is_qcow2_v3, peek_is_vmdk_descriptor,
    resolve_vmdk_flat_descriptor, validate_backing_path, BackingChain, ChainError, ChainImage,
    ExternalDataFile, ImageFormat, InfoOperationResult,
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
const VMM_PARAMS_ADDR: u64 = shared::VMM_PARAMS_ADDR as u64;

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
// Mirrors shared::CheckConfig::FLAG_REPAIR_ALL (1 << 4): selects the
// lossy `all` tier (refcount recount + COPIED reconciliation). Only
// meaningful in addition to CHECK_CONFIG_FLAG_REPAIR; set when the
// CLI receives `--repair=all`.
#[allow(dead_code)]
const CHECK_CONFIG_FLAG_REPAIR_ALL: u32 = 1 << 4;
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
const COMPARE_CONFIG_FLAG_DECRYPT_AES: u32 = 1 << 2;
#[allow(dead_code)]
const COMPARE_CONFIG_FLAG_VERBOSE: u32 = 1 << 31;

// ConvertConfig constants (must match shared crate)
const CONVERT_CONFIG_MAGIC: u32 = 0x434F4E56; // "CONV"
const CONVERT_CONFIG_FLAG_SKIP_ZEROS: u32 = 1 << 0;
const CONVERT_CONFIG_FLAG_COMPRESS: u32 = 1 << 1;
#[allow(dead_code)]
const CONVERT_CONFIG_FLAG_DECRYPT_AES: u32 = 1 << 2;
const CONVERT_CONFIG_FLAG_EXTENDED_L2: u32 = 1 << 3;
const CONVERT_CONFIG_FLAG_ENCRYPT_LUKS: u32 = 1 << 4;
#[allow(dead_code)]
const CONVERT_CONFIG_FLAG_VERBOSE: u32 = 1 << 31;

// MeasureConfig constants (must match shared crate)
const MEASURE_CONFIG_MAGIC: u32 = 0x4D454153; // "MEAS"
#[allow(dead_code)]
const MEASURE_CONFIG_FLAG_EXTENDED_L2: u32 = 1 << 0;
#[allow(dead_code)]
const MEASURE_CONFIG_FLAG_LAZY_REFCOUNTS: u32 = 1 << 1;
#[allow(dead_code)]
const MEASURE_CONFIG_FLAG_COMPAT_V3: u32 = 1 << 2;
#[allow(dead_code)]
const MEASURE_CONFIG_FLAG_COMPRESS: u32 = 1 << 3;
#[allow(dead_code)]
const MEASURE_CONFIG_PREALLOC_OFF: u32 = 0 << 4;
#[allow(dead_code)]
const MEASURE_CONFIG_PREALLOC_METADATA: u32 = 1 << 4;
#[allow(dead_code)]
const MEASURE_CONFIG_PREALLOC_FALLOC: u32 = 2 << 4;
#[allow(dead_code)]
const MEASURE_CONFIG_PREALLOC_FULL: u32 = 3 << 4;

// MeasureResult constants (must match shared crate)
const MEASURE_RESULT_MAGIC: u32 = 0x4D524553; // "MRES"
const MEASURE_RESULT_ERROR_OK: u32 = 0;
#[allow(dead_code)]
const MEASURE_RESULT_ERROR_OVERFLOW: u32 = 1;
#[allow(dead_code)]
const MEASURE_RESULT_ERROR_INVALID_OPTION: u32 = 2;
#[allow(dead_code)]
const MEASURE_RESULT_ERROR_INVALID_SIZE: u32 = 3;

// MapConfig constants (must match shared::MapConfig)
const MAP_CONFIG_MAGIC: u32 = 0x4D41505F; // "MAP_"
const MAP_CONFIG_FLAG_VERBOSE: u32 = 1 << 31;

// MapResult constants (must match shared::MapResult)
// Kept for symmetry with the other operations' magic constants
// and for future host-side use (e.g. directly inspecting a
// MapResult FFI struct in shared memory). The current host path
// consumes MapResultMessage from the serial channel, which
// doesn't carry the FFI magic.
#[allow(dead_code)]
const MAP_RESULT_MAGIC: u32 = 0x4D505253; // "MPRS"
const MAP_RESULT_ERROR_OK: u32 = 0;
const MAP_RESULT_ERROR_INVALID_SOURCE: u32 = 1;
const MAP_RESULT_ERROR_INVALID_OPTION: u32 = 2;
const MAP_RESULT_ERROR_HAS_BACKING: u32 = 3;
const MAP_RESULT_ERROR_IO: u32 = 4;

// SnapshotConfig constants (must match shared::SnapshotConfig)
const SNAPSHOT_CONFIG_MAGIC: u32 = 0x534E4150; // "SNAP"
const SNAPSHOT_CONFIG_MODE_LIST: u32 = 0;
#[allow(dead_code)]
const SNAPSHOT_CONFIG_MODE_APPLY: u32 = 1;
const SNAPSHOT_CONFIG_MODE_CREATE: u32 = 2;
#[allow(dead_code)]
const SNAPSHOT_CONFIG_MODE_DELETE: u32 = 3;
const SNAPSHOT_CONFIG_FLAG_QUIET: u32 = 1 << 0;
const SNAPSHOT_CONFIG_FLAG_FORCE_SHARE: u32 = 1 << 1;
const SNAPSHOT_CONFIG_FLAG_VERBOSE: u32 = 1 << 31;

// SnapshotResult constants (must match shared::SnapshotResult)
// The host consumes SnapshotResultMessage from the serial channel
// for the error code; the magic constant is retained for symmetry
// with the other operations.
#[allow(dead_code)]
const SNAPSHOT_RESULT_MAGIC: u32 = 0x534E5253; // "SNRS"
const SNAPSHOT_RESULT_ERROR_OK: u32 = 0;
const SNAPSHOT_RESULT_ERROR_UNSUPPORTED_FORMAT: u32 = 1;
const SNAPSHOT_RESULT_ERROR_UNSUPPORTED_FEATURE: u32 = 2;
const SNAPSHOT_RESULT_ERROR_NOT_FOUND: u32 = 3;
const SNAPSHOT_RESULT_ERROR_DUPLICATE_NAME: u32 = 4;
const SNAPSHOT_RESULT_ERROR_REFCOUNT_OVERFLOW: u32 = 5;
const SNAPSHOT_RESULT_ERROR_ALLOCATION_FAILED: u32 = 6;
const SNAPSHOT_RESULT_ERROR_SNAPSHOT_TABLE_FULL: u32 = 7;
const SNAPSHOT_RESULT_ERROR_IO: u32 = 8;
const SNAPSHOT_RESULT_ERROR_L1_SIZE_MISMATCH: u32 = 9;
const SNAPSHOT_RESULT_ERROR_INVALID_UTF8: u32 = 10;
const SNAPSHOT_RESULT_ERROR_INVALID_CONFIG: u32 = 11;
const SNAPSHOT_RESULT_ERROR_PARSE_FAILED: u32 = 12;

// CreateConfig constants (must match shared crate)
const CREATE_CONFIG_MAGIC: u32 = 0x43524541; // "CREA"
#[allow(dead_code)]
const CREATE_CONFIG_FLAG_EXTENDED_L2: u32 = 1 << 0;
#[allow(dead_code)]
const CREATE_CONFIG_FLAG_LAZY_REFCOUNTS: u32 = 1 << 1;
#[allow(dead_code)]
const CREATE_CONFIG_FLAG_COMPAT_V3: u32 = 1 << 2;
#[allow(dead_code)]
const CREATE_CONFIG_FLAG_BACKING_UNSAFE: u32 = 1 << 3;
// Preallocation mode lives at bits 4-5 of CreateConfig.flags, mirroring
// MeasureConfig. Decoded back into the Preallocation enum by the guest.
#[allow(dead_code)]
const CREATE_CONFIG_PREALLOC_OFF: u32 = 0 << 4;
#[allow(dead_code)]
const CREATE_CONFIG_PREALLOC_METADATA: u32 = 1 << 4;
#[allow(dead_code)]
const CREATE_CONFIG_PREALLOC_FALLOC: u32 = 2 << 4;
#[allow(dead_code)]
const CREATE_CONFIG_PREALLOC_FULL: u32 = 3 << 4;
const CREATE_CONFIG_MAX_BACKING_FILE: usize = 1024;

// CreateResult constants (must match shared crate)
#[allow(dead_code)]
const CREATE_RESULT_MAGIC: u32 = 0x43524553; // "CRES"
const CREATE_RESULT_ERROR_OK: u32 = 0;
const CREATE_RESULT_ERROR_INVALID_OPTION: u32 = 1;
const CREATE_RESULT_ERROR_INVALID_SIZE: u32 = 2;
const CREATE_RESULT_ERROR_SCRATCH_TOO_SMALL: u32 = 3;
const CREATE_RESULT_ERROR_BACKING_READ_FAILED: u32 = 4;
const CREATE_RESULT_ERROR_BACKING_PARSE_FAILED: u32 = 5;
const CREATE_RESULT_ERROR_BACKING_TOO_LONG: u32 = 6;
const CREATE_RESULT_ERROR_WRITE_FAILED: u32 = 7;
const CREATE_RESULT_ERROR_UNSUPPORTED_FORMAT: u32 = 8;
const CREATE_RESULT_ERROR_BACKING_FORMAT_UNSUPPORTED: u32 = 9;
const CREATE_RESULT_ERROR_BACKING_SIZE_TOO_LARGE: u32 = 10;

// ResizeConfig constants (must match shared crate)
const RESIZE_CONFIG_MAGIC: u32 = 0x52455349; // "RESI"
const REBASE_CONFIG_MAGIC: u32 = 0x52454241; // "REBA"
const REBASE_CONFIG_FLAG_UNSAFE: u32 = 1 << 0;
#[allow(dead_code)]
const REBASE_CONFIG_FLAG_QUIET: u32 = 1 << 1;
const REBASE_CONFIG_FLAG_DETACH: u32 = 1 << 2;
const COMMIT_CONFIG_MAGIC: u32 = 0x434F4D4D; // "COMM"
const COMMIT_CONFIG_FLAG_QUIET: u32 = 1 << 0;
const RESIZE_CONFIG_FLAG_SHRINK: u32 = 1 << 0;
#[allow(dead_code)]
const RESIZE_CONFIG_FLAG_EXTENDED_L2: u32 = 1 << 1;
#[allow(dead_code)]
const RESIZE_CONFIG_FLAG_QUIET: u32 = 1 << 2;
#[allow(dead_code)]
const RESIZE_CONFIG_PREALLOC_OFF: u32 = 0 << 4;
const RESIZE_CONFIG_PREALLOC_METADATA: u32 = 1 << 4;
const RESIZE_CONFIG_PREALLOC_FALLOC: u32 = 2 << 4;
const RESIZE_CONFIG_PREALLOC_FULL: u32 = 3 << 4;

// ResizeResult constants (must match shared crate)
#[allow(dead_code)]
const RESIZE_RESULT_MAGIC: u32 = 0x52524553; // "RRES"
const RESIZE_RESULT_ACTION_NOOP: u32 = 0;
const RESIZE_RESULT_ACTION_GROW: u32 = 1;
const RESIZE_RESULT_ACTION_SHRINK: u32 = 2;
const RESIZE_RESULT_ERROR_OK: u32 = 0;
const RESIZE_RESULT_ERROR_INVALID_OPTION: u32 = 1;
const RESIZE_RESULT_ERROR_INVALID_NEW_SIZE: u32 = 2;
const RESIZE_RESULT_ERROR_SHRINK_WITHOUT_FLAG: u32 = 3;
const RESIZE_RESULT_ERROR_SHRINK_BELOW_ALLOCATED: u32 = 4;
const RESIZE_RESULT_ERROR_UNSUPPORTED_FORMAT: u32 = 5;
const RESIZE_RESULT_ERROR_UNSUPPORTED_SUBFORMAT: u32 = 6;
const RESIZE_RESULT_ERROR_UNSUPPORTED_SHRINK: u32 = 7;
const RESIZE_RESULT_ERROR_PREALLOCATION_UNSUPPORTED: u32 = 8;
const RESIZE_RESULT_ERROR_SCRATCH_TOO_SMALL: u32 = 9;
const RESIZE_RESULT_ERROR_READ_FAILED: u32 = 10;
const RESIZE_RESULT_ERROR_WRITE_FAILED: u32 = 11;
const RESIZE_RESULT_ERROR_PARSE_FAILED: u32 = 12;
const RESIZE_RESULT_ERROR_HEADER_MISMATCH: u32 = 13;

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
// Set when an in-place --repair could not fully reconcile the image and
// some issues remain. Mirrors shared::CheckResult::FLAG_REPAIR_INCOMPLETE
// (1 << 8). This bit travels to the host inside CheckResult.flags,
// alongside the per-class repaired_leaks / repaired_refcounts /
// repaired_corruptions counters carried by the CheckResultMessage protobuf.
const CHECK_RESULT_FLAG_REPAIR_INCOMPLETE: u32 = 1 << 8;

// ChainConfig constants (must match shared crate)
// These are used by write_chain_config() which is infrastructure for Phase 1+
#[allow(dead_code)]
const CHAIN_CONFIG_MAGIC: u32 = 0x4348414E; // "CHAN"
#[allow(dead_code)]
const CHAIN_CONFIG_VERSION: u32 = 2;
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
// Default MMIO base for 32MB guest memory (256MB, well outside memory region).
// When guest memory exceeds this, MMIO is dynamically placed above guest memory.
const DEFAULT_MMIO_BASE: u64 = 0x10000000;
const MMIO_SIZE: u64 = 0x1000; // 4KB per device

// Virtqueue memory regions (inside guest memory)
// Each device gets 64KB for virtqueue structures
const VQ_BASE_START: u64 = 0x100000; // 1MB
const VQ_SIZE_PER_DEVICE: u64 = 0x10000; // 64KB per device

// Maximum number of devices in a backing chain (matches config default)
// This limits: MMIO range (16 * 4KB = 64KB) and VQ range (16 * 64KB = 1MB)
const MAX_CHAIN_DEPTH: usize = 16;

/// Active MMIO base address. Set once before creating devices.
/// Default is DEFAULT_MMIO_BASE (256MB), moved above guest memory when needed.
static mut ACTIVE_MMIO_BASE: u64 = DEFAULT_MMIO_BASE;

/// Set the MMIO base address based on guest memory size.
/// Must be called before any device creation.
fn set_mmio_base_for_mem_size(guest_mem_size: u64) {
    // SAFETY: Called once from main() before any device creation or
    // guest execution. No concurrent access is possible at this point.
    unsafe {
        ACTIVE_MMIO_BASE = if guest_mem_size <= DEFAULT_MMIO_BASE {
            DEFAULT_MMIO_BASE
        } else {
            // Place MMIO at next 1GB boundary above guest memory
            (guest_mem_size + (1 << 30) - 1) & !((1 << 30) - 1)
        };
    }
}

/// Calculate MMIO base address for device at given index.
/// Index 0 = first input device (top of chain), higher indices = backing files.
/// For operations with output, output device uses index after all inputs.
#[inline]
fn device_mmio_base(device_index: usize) -> u64 {
    // SAFETY: ACTIVE_MMIO_BASE is initialized by set_mmio_base_for_mem_size()
    // before any call to this function. After initialization, the value is
    // never modified, so concurrent reads are safe.
    unsafe { ACTIVE_MMIO_BASE + (device_index as u64 * MMIO_SIZE) }
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

// Maximum QCOW2 cluster size supported (must match guest's MAX_CLUSTER_SIZE)
const MAX_CLUSTER_SIZE: usize = 2 * 1024 * 1024; // 2MB

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

/// Parse a memory size string like "256M", "1G", "4096" into bytes.
fn parse_memory_size(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty memory size string".into());
    }
    let (num_str, multiplier) = match s.as_bytes().last() {
        Some(b'T' | b't') => (&s[..s.len() - 1], 1u64 << 40),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1u64 << 30),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1u64 << 20),
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1u64 << 10),
        _ => (s, 1u64),
    };
    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid memory size: '{s}'"))?;
    num.checked_mul(multiplier)
        .ok_or_else(|| format!("memory size overflow: '{s}'").into())
}

/// Parse a qemu-img size string with the full suffix set:
/// `b`=512, `k`/`K`=KiB, `M`/`m`=MiB, `G`/`g`=GiB, `T`/`t`=TiB,
/// `P`/`p`=PiB, `E`/`e`=EiB.  Used by `instar resize` for the
/// `[+-]SIZE` argument.  Strict superset of `parse_memory_size`
/// — kept as a sibling rather than replacing it to avoid
/// disturbing the create/measure call sites.
fn parse_qemu_img_size(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size string".into());
    }
    let (num_str, multiplier) = match s.as_bytes().last() {
        Some(b'E' | b'e') => (&s[..s.len() - 1], 1u64 << 60),
        Some(b'P' | b'p') => (&s[..s.len() - 1], 1u64 << 50),
        Some(b'T' | b't') => (&s[..s.len() - 1], 1u64 << 40),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1u64 << 30),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1u64 << 20),
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1u64 << 10),
        Some(b'b') => (&s[..s.len() - 1], 512u64),
        _ => (s, 1u64),
    };
    let num: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid size: '{s}'"))?;
    num.checked_mul(multiplier)
        .ok_or_else(|| format!("size overflow: '{s}'").into())
}

/// Parse `[+-]SIZE[bkKMGTPE]`.  Returns the parsed `ParsedResizeSize`
/// which the caller resolves against `current_virtual_size`.
fn parse_resize_size(s: &str) -> Result<ParsedResizeSize, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size string".into());
    }
    if let Some(rest) = s.strip_prefix('+') {
        Ok(ParsedResizeSize::Add(parse_qemu_img_size(rest)?))
    } else if let Some(rest) = s.strip_prefix('-') {
        Ok(ParsedResizeSize::Subtract(parse_qemu_img_size(rest)?))
    } else {
        Ok(ParsedResizeSize::Absolute(parse_qemu_img_size(s)?))
    }
}

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
            "Maximum chain depth ({MAX_CHAIN_DEPTH}) exceeded"
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
            log::debug!("Unknown MMIO read at 0x{addr:x}");
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
            log::debug!("Unknown MMIO write at 0x{addr:x}");
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

/// Maximum serial decoder buffer size: frame header + max protobuf message
/// plus a small margin. Rejects length prefixes claiming more than this.
const MAX_SERIAL_BUFFER: usize = FRAME_HEADER_SIZE + guest_protocol::MAX_MESSAGE_SIZE + 256;

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

        // Reject oversized length prefixes -- no valid message exceeds
        // MAX_MESSAGE_SIZE, so discard the leading byte and resync.
        if total_len > MAX_SERIAL_BUFFER {
            self.buffer.pop_front();
            return None;
        }

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

/// Debug output buffer - collects characters until newline, then prints.
/// Truncates lines longer than MAX_DEBUG_LINE to prevent unbounded growth.
struct DebugBuffer {
    line: String,
}

const MAX_DEBUG_LINE: usize = 4096;

impl DebugBuffer {
    fn new() -> Self {
        Self {
            line: String::new(),
        }
    }

    /// Add a byte; if it's a newline, return the complete line.
    /// Lines exceeding MAX_DEBUG_LINE are forcibly flushed.
    fn add_byte(&mut self, byte: u8) -> Option<String> {
        if byte == b'\n' || self.line.len() >= MAX_DEBUG_LINE {
            if byte != b'\n' {
                self.line.push(byte as char);
            }
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
        Some(guest_::GuestMessage_::Payload::MeasureResult(m)) => {
            format!(
                "measure_result target_format={} required={} fully_allocated={} \
                resolved_unit_size={} error={}",
                m.target_format, m.required, m.fully_allocated, m.resolved_unit_size, m.error
            )
        }
        Some(guest_::GuestMessage_::Payload::CreateResult(c)) => {
            format!(
                "create_result target_format={} resolved_virtual_size={} \
                metadata_bytes_written={} file_size_after={} resolved_unit_size={} error={}",
                c.target_format,
                c.resolved_virtual_size,
                c.metadata_bytes_written,
                c.file_size_after,
                c.resolved_unit_size,
                c.error
            )
        }
        Some(guest_::GuestMessage_::Payload::ResizeResult(r)) => {
            format!(
                "resize_result target_format={} resolved_new_virtual_size={} \
                file_size_before={} file_size_after={} action={} error={}",
                r.target_format,
                r.resolved_new_virtual_size,
                r.file_size_before,
                r.file_size_after,
                r.action,
                r.error
            )
        }
        Some(guest_::GuestMessage_::Payload::RebaseResult(r)) => {
            format!(
                "rebase_result overlay_format={} mode={} clusters_copied={} \
                bytes_copied={} error={}",
                r.overlay_format, r.mode, r.clusters_copied, r.bytes_copied, r.error
            )
        }
        Some(guest_::GuestMessage_::Payload::AmendResult(a)) => {
            format!(
                "amend_result target_format={} action={} resulting_version={} \
                lazy_refcounts={} error={}",
                a.target_format, a.action, a.resulting_version, a.lazy_refcounts, a.error
            )
        }
        Some(guest_::GuestMessage_::Payload::CommitResult(c)) => {
            format!(
                "commit_result overlay_format={} backing_format={} \
                clusters_committed={} bytes_committed={} \
                overlay_clusters_cleared={} error={}",
                c.overlay_format,
                c.backing_format,
                c.clusters_committed,
                c.bytes_committed,
                c.overlay_clusters_cleared,
                c.error
            )
        }
        Some(guest_::GuestMessage_::Payload::MapExtent(e)) => {
            format!(
                "map_extent start={} length={} state={} file_offset={}",
                e.start, e.length, e.state, e.file_offset
            )
        }
        Some(guest_::GuestMessage_::Payload::MapResult(r)) => {
            format!(
                "map_result source_format={} extents_emitted={} \
                virtual_size={} error={}",
                r.source_format, r.extents_emitted, r.virtual_size, r.error
            )
        }
        Some(guest_::GuestMessage_::Payload::SnapshotEntry(e)) => {
            format!(
                "snapshot_entry id={} name={} l1_table_offset={} \
                l1_size={} date_sec_hi={} date_sec_lo={} date_nsec={} \
                vm_clock_nsec={} vm_state_size={} disk_size={} \
                icount={} extra_data_size={}",
                e.id,
                e.name,
                e.l1_table_offset,
                e.l1_size,
                e.date_sec_hi,
                e.date_sec_lo,
                e.date_nsec,
                e.vm_clock_nsec,
                e.vm_state_size,
                e.disk_size,
                e.icount,
                e.extra_data_size
            )
        }
        Some(guest_::GuestMessage_::Payload::SnapshotResult(r)) => {
            format!(
                "snapshot_result mode={} error={} snapshots_emitted={} \
                assigned_id={}",
                r.mode, r.error, r.snapshots_emitted, r.assigned_id
            )
        }
        None => "empty payload".to_string(),
    };

    format!("[{level}] {payload_str}")
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
        format!("{bytes} B")
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
            let s = format!("{rounded}");
            let trimmed = s.trim_end_matches('0').trim_end_matches('.');
            format!("{trimmed} {unit}")
        }
    } else {
        // Accurate formatting: round to one decimal place
        let rounded = (value * 10.0).round() / 10.0;
        if rounded.fract() == 0.0 {
            format!("{} {}", rounded as u64, unit)
        } else {
            format!("{rounded:.1} {unit}")
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
    vmdk_flat: Option<&crate::chain::ResolvedVmdkDescriptor>,
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
                vmdk_flat,
            );
            return;
        }

        // Line 1: image path
        println!("image: {abs_path}");

        // Line 2: file format
        println!("file format: {}", info.format);

        // qemu_compat is the opposite of ignore_quirks
        let qemu_compat = !ignore_quirks;

        // For raw/unknown formats, qemu-img reports virtual-size as the file length
        // rounded up to 512-byte sectors. For structured formats (qcow2, vmdk, etc.),
        // use the virtual size from headers.
        let effective_virtual_size = if info.format == "raw" || info.format == "unknown" {
            // Round up to 512-byte sector boundary
            file_size.div_ceil(512) * 512
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
        if info.flags & INFO_RESULT_FLAG_HAS_BACKING_FILE != 0 && !info.backing_file.is_empty() {
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
                println!("backing file: {backing_file_str} (actual path: {actual_path})");
            } else {
                println!("backing file: {backing_file_str}");
            }
            // Show backing file format if available
            if !info.qcow2_info.backing_format.is_empty() {
                println!("backing file format: {}", info.qcow2_info.backing_format);
            }
        }

        // External data file (if present, QCOW2 v3)
        if info.flags & INFO_RESULT_FLAG_HAS_EXTERNAL_DATA != 0
            && !info.external_data_file.is_empty()
        {
            println!("data file: {}", info.external_data_file.as_str());
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
            println!("    compat: {compat}");

            // compression type (always shown)
            let compression = if info.qcow2_info.compression_type.is_empty() {
                "zlib"
            } else {
                info.qcow2_info.compression_type.as_str()
            };
            println!("    compression type: {compression}");

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
            println!("    refcount bits: {refcount_bits}");

            // corrupt flag (only for v3/1.1 compat)
            if is_v3 {
                println!("    corrupt: {}", info.qcow2_info.corrupt);
            }

            // extended l2 (only for v3/1.1 compat)
            if is_v3 {
                println!("    extended l2: {}", info.qcow2_info.extended_l2);
            }

            // snapshot count (only shown if > 0)
            if info.qcow2_info.nb_snapshots > 0 {
                println!("Snapshot count: {}", info.qcow2_info.nb_snapshots);
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
            println!("            filename: {abs_path}");
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
            println!("    image type: {image_type_str}");
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
                child_file_length.div_ceil(512) * 512
            } else {
                child_file_length
            };
            println!("Child node '/file':");
            println!("    filename: {abs_path}");
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
    vmdk_flat: Option<&crate::chain::ResolvedVmdkDescriptor>,
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
        child_file_length.div_ceil(512) * 512
    } else {
        info.virtual_size
    };

    // For child file length in raw/unknown format, also round up to 512-byte sectors
    let effective_child_file_length = if is_unstructured {
        child_file_length.div_ceil(512) * 512
    } else {
        child_file_length
    };

    println!("{{");

    // Check if we have a backing file
    let has_backing_file =
        info.flags & INFO_RESULT_FLAG_HAS_BACKING_FILE != 0 && !info.backing_file.is_empty();

    // Children section (qemu-img 8.0+ generally).
    //
    // VMDK monolithicFlat (and twoGbMaxExtentFlat in future) is the
    // exception — qemu-img has emitted per-extent children for these
    // images since at least 6.0 because they genuinely are multi-file
    // images. Emit children whenever we have resolved flat extents,
    // regardless of profile. The descriptor's virtual-size is rounded
    // up to the 512-byte sector boundary (qemu treats it as an
    // unstructured file). See bug #286 PR follow-up.
    if profile.include_child_node || vmdk_flat.is_some() {
        println!("    \"children\": [");
        let mut emitted_any_child = false;
        if let Some(resolved) = vmdk_flat {
            for (i, extent) in resolved.flat_extents.iter().enumerate() {
                let extent_disk = std::fs::metadata(&extent.flat_path)
                    .map(|m| {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            m.blocks() * 512
                        }
                        #[cfg(not(unix))]
                        {
                            m.len()
                        }
                    })
                    .unwrap_or(extent.extent_size);
                let extent_path = extent.flat_path.to_string_lossy();
                if emitted_any_child {
                    println!("        }},");
                }
                println!("        {{");
                println!("            \"name\": \"extents.{i}\",");
                println!("            \"info\": {{");
                println!("                \"children\": [],");
                println!("                \"virtual-size\": {},", extent.extent_size);
                println!(
                    "                \"filename\": \"{}\",",
                    escape_json_string(&extent_path)
                );
                println!("                \"format\": \"file\",");
                println!("                \"actual-size\": {extent_disk},");
                println!("                \"format-specific\": {{");
                println!("                    \"type\": \"file\",");
                println!("                    \"data\": {{}}");
                println!("                }},");
                println!("                \"dirty-flag\": false");
                println!("            }}");
                emitted_any_child = true;
            }
        }
        // Descriptor / file child. For VMDK flat we treat the
        // descriptor file as unstructured (qemu-img does) and round
        // its virtual-size up to a sector.
        let descriptor_vsize = if vmdk_flat.is_some() {
            effective_child_file_length.div_ceil(512) * 512
        } else {
            effective_child_file_length
        };
        if emitted_any_child {
            println!("        }},");
        }
        println!("        {{");
        println!("            \"name\": \"file\",");
        println!("            \"info\": {{");
        println!("                \"children\": [],");
        println!("                \"virtual-size\": {descriptor_vsize},");
        println!(
            "                \"filename\": \"{}\",",
            escape_json_string(abs_path)
        );
        println!("                \"format\": \"file\",");
        println!("                \"actual-size\": {disk_size},");
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
        println!("    \"backing-filename-format\": \"{backing_format}\",");
    }

    println!("    \"virtual-size\": {effective_virtual_size},");
    println!("    \"filename\": \"{}\",", escape_json_string(abs_path));

    if info.cluster_size > 0 {
        println!("    \"cluster-size\": {},", info.cluster_size);
    }

    println!("    \"format\": \"{}\",", info.format);
    println!("    \"actual-size\": {disk_size},");

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

        println!("            \"compat\": \"{compat}\",");

        let compression = if info.qcow2_info.compression_type.is_empty() {
            "zlib"
        } else {
            info.qcow2_info.compression_type.as_str()
        };
        println!("            \"compression-type\": \"{compression}\",");

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

        let has_data_file = info.flags & INFO_RESULT_FLAG_HAS_EXTERNAL_DATA != 0
            && !info.external_data_file.is_empty();

        if is_v3 {
            println!("            \"refcount-bits\": {refcount_bits},");
            println!("            \"corrupt\": {},", info.qcow2_info.corrupt);
            if has_data_file {
                println!(
                    "            \"extended-l2\": {},",
                    info.qcow2_info.extended_l2
                );
                println!(
                    "            \"data-file\": \"{}\"",
                    escape_json_string(info.external_data_file.as_str())
                );
            } else {
                println!(
                    "            \"extended-l2\": {}",
                    info.qcow2_info.extended_l2
                );
            }
        } else {
            // For v2, refcount-bits is the last field (no trailing comma)
            println!("            \"refcount-bits\": {refcount_bits}");
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
        println!("            \"extents\": [");
        if let Some(resolved) = vmdk_flat {
            // monolithicFlat / twoGbMaxExtentFlat — one entry per
            // resolved flat extent, "FLAT" format, no cluster-size.
            // Matches qemu-img info --output=json.
            for (idx, extent) in resolved.flat_extents.iter().enumerate() {
                if idx > 0 {
                    println!("                }},");
                }
                println!("                {{");
                println!(
                    "                    \"virtual-size\": {},",
                    extent.extent_size
                );
                println!(
                    "                    \"filename\": \"{}\",",
                    escape_json_string(&extent.flat_path.to_string_lossy())
                );
                println!("                    \"format\": \"FLAT\"");
            }
            println!("                }}");
        } else {
            // monolithicSparse / streamOptimized — single self-extent
            // record, format left blank to match qemu-img.
            println!("                {{");
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
        }
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
        println!("            \"image-type\": \"{image_type_str}\",");
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
    } else if info.format == "luks" && extra_detail {
        // LUKS format-specific info is only output with --extra-detail flag.
        // qemu-img doesn't output format-specific for LUKS.
        println!("    \"format-specific\": {{");
        println!("        \"type\": \"luks\",");
        println!("        \"data\": {{");
        if !info.luks_info.cipher.is_empty() {
            println!(
                "            \"cipher\": \"{}\",",
                escape_json_string(info.luks_info.cipher.as_str())
            );
            println!(
                "            \"cipher-mode\": \"{}\",",
                escape_json_string(info.luks_info.cipher_mode.as_str())
            );
            println!(
                "            \"hash\": \"{}\",",
                escape_json_string(info.luks_info.hash.as_str())
            );
        }
        if !info.luks_info.uuid.is_empty() {
            println!(
                "            \"uuid\": \"{}\",",
                escape_json_string(info.luks_info.uuid.as_str())
            );
        }
        if info.luks_info.payload_offset > 0 {
            println!(
                "            \"payload-offset\": {},",
                info.luks_info.payload_offset
            );
        }
        if info.luks_info.master_key_length > 0 {
            println!(
                "            \"master-key-length\": {},",
                info.luks_info.master_key_length
            );
        }
        let has_inner = !info.luks_info.inner_format.is_empty();
        if has_inner {
            println!(
                "            \"active-key-slots\": {},",
                info.luks_info.active_key_slots
            );
            println!(
                "            \"inner-format\": \"{}\",",
                escape_json_string(info.luks_info.inner_format.as_str())
            );
            println!(
                "            \"inner-virtual-size\": {}",
                info.luks_info.inner_virtual_size
            );
        } else {
            println!(
                "            \"active-key-slots\": {}",
                info.luks_info.active_key_slots
            );
        }
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
    println!("    \"dirty-flag\": {dirty_flag}");
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

/// Get the directory containing the instar guest binaries (.bin files).
///
/// Resolution order:
///   1. `INSTAR_BIN_DIR` environment variable, if set (testing/override).
///   2. The directory containing the instar executable (developer mode:
///      `make instar` writes the binaries alongside the VMM at
///      `src/target/release/`).
///   3. `/usr/lib/instar` (system install via .deb/.rpm).
///
/// The first candidate that contains `core.bin` wins. If none does,
/// the executable directory is returned so the subsequent load error
/// reports the developer-mode path that most users expect.
fn get_binary_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("INSTAR_BIN_DIR") {
        return std::path::PathBuf::from(dir);
    }

    let exe_dir = std::env::current_exe()
        .expect("Failed to get executable path")
        .parent()
        .expect("Failed to get executable directory")
        .to_path_buf();

    let system_dir = std::path::PathBuf::from("/usr/lib/instar");

    for candidate in [&exe_dir, &system_dir] {
        if candidate.join("core.bin").exists() {
            return candidate.clone();
        }
    }

    exe_dir
}

/// Get the path to a guest binary by file name.
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
    // SAFETY: mem_region.userspace_addr points to a valid GuestMemoryMmap
    // allocation that outlives the VM. The slot/guest_phys_addr are unique
    // per operation entry point. KVM requires this call to be unsafe but
    // the memory contract is satisfied.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }

    // Set up GDT
    setup_gdt(&guest_mem)?;

    // Set up page tables (identity map)
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;

    // Load core binary at GUEST_CODE_BASE (0x10000)
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;

    // Load operation binary at OPERATION_LOAD_ADDR (0x22000)
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
                                    external_data_file: if info.external_data_file.is_empty() {
                                        None
                                    } else {
                                        Some(info.external_data_file.to_string())
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
                return Err(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}").into());
            }
            exit => {
                return Err(format!("unexpected VM exit: {exit:?}").into());
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

        // VMDK flat descriptor short-circuit: a descriptor is pure
        // ASCII text (no binary magic) so the guest info operation
        // has no meaningful parse path for it. Detect it on the
        // host, resolve the flat extent file(s) against the backing
        // allowlist, and construct the chain entry directly.
        // If the descriptor has a parentFileNameHint, continue
        // chain discovery with the parent.
        if peek_is_vmdk_descriptor(&current).unwrap_or(false) {
            let resolved = resolve_vmdk_flat_descriptor(&current, security_config)?;
            debug!(
                "VMDK descriptor resolved: {} -> {} extent(s) ({} bytes virtual)",
                current.display(),
                resolved.flat_extents.len(),
                resolved.virtual_size
            );

            let descriptor_file_size = std::fs::metadata(&current).map(|m| m.len()).unwrap_or(0);

            chain.push(ChainImage {
                path: current.clone(),
                format: ImageFormat::VmdkDescriptor,
                virtual_size: resolved.virtual_size,
                actual_size: descriptor_file_size,
                cluster_size: 0,
                backing_file_raw: resolved.parent_hint.clone(),
                flags: 0,
                external_data_files: resolved
                    .flat_extents
                    .iter()
                    .map(|e| ExternalDataFile {
                        path: e.flat_path.clone(),
                        extent_size: e.extent_size,
                    })
                    .collect(),
            });

            // If the descriptor has a parent hint, continue
            // chain discovery with the parent image.
            if let Some(ref hint) = resolved.parent_hint {
                current = validate_backing_path(&current, hint, security_config)?;
                continue;
            }
            break;
        }

        // Run the sandboxed info operation
        // Always use secure mode (unsafe_quirks=false) for backing chain discovery
        let info_result = execute_info_operation(&current, sector_size, false)
            .map_err(|e| ChainError::InfoOperationFailed(e.to_string()))?;

        // Get actual filesystem size for the chain config. The guest
        // info operation may report actual_size=0 for non-QCOW2 formats
        // (by design), but the chain config needs the real file size so
        // format readers can locate structures relative to EOF (e.g.
        // streamOptimized VMDK footer).
        let file_size = std::fs::metadata(&current).map(|m| m.len()).unwrap_or(0);
        let actual_size = if info_result.actual_size > 0 {
            info_result.actual_size
        } else {
            file_size
        };

        // For the top image only, check for external data file.
        // External data files on backing images are not currently supported;
        // only the top image's data file is discovered and passed to the guest.
        // The data file path is untrusted (parsed from the QCOW2 header
        // inside the sandbox), so we validate it against the allowlist.
        // For the top image only, check for QCOW2 external data file.
        let mut data_files = Vec::new();
        if chain.images.is_empty() {
            if let Some(ref data_path) = info_result.external_data_file {
                let data_resolved = validate_backing_path(&current, data_path, security_config)?;
                let data_size = std::fs::metadata(&data_resolved)
                    .map(|m| m.len())
                    .unwrap_or(0);
                debug!(
                    "External data file validated: {} -> {}",
                    data_path,
                    data_resolved.display()
                );
                data_files.push(ExternalDataFile {
                    path: data_resolved,
                    extent_size: data_size,
                });
            }
        }

        // Build chain image entry
        let chain_image = ChainImage {
            path: current.clone(),
            format: ImageFormat::from_str(&info_result.format),
            virtual_size: info_result.virtual_size,
            actual_size,
            cluster_size: info_result.cluster_size,
            backing_file_raw: info_result.backing_file.clone(),
            flags: info_result.flags,
            external_data_files: data_files,
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
    for image in chain.images() {
        for data_file in &image.external_data_files {
            println!("  External data file: {}", data_file.path.display());
        }
    }
    for (i, image) in chain.images().iter().enumerate() {
        let backing_info = match &image.backing_file_raw {
            Some(bf) => format!(" -> {bf}"),
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

/// Write device info entries for a single backing chain to guest memory.
///
/// Writes ChainDeviceInfo entries starting at `devices_base + start_idx * 32`.
/// If the chain has an external data file, it is inserted as device `start_idx + 1`
/// (between the top image and the rest of the backing chain).
///
/// Returns the number of device entries written.
fn write_chain_device_entries(
    guest_mem: &GuestMemoryMmap,
    chain: &BackingChain,
    devices_base: u64,
    start_idx: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut idx = start_idx;

    for image in chain.images().iter() {
        if idx >= MAX_CHAIN_DEVICES {
            break;
        }

        let has_data_files = !image.external_data_files.is_empty();
        let dev_offset = devices_base + (idx as u64 * 32);
        guest_mem.write_obj(
            image.format.to_shared_format_u32(),
            GuestAddress(dev_offset),
        )?;
        guest_mem.write_obj(image.flags, GuestAddress(dev_offset + 4))?;
        guest_mem.write_obj(image.virtual_size, GuestAddress(dev_offset + 8))?;
        guest_mem.write_obj(image.actual_size, GuestAddress(dev_offset + 16))?;
        guest_mem.write_obj(image.cluster_size, GuestAddress(dev_offset + 24))?;

        // If this image has external data files, point to the next device
        let data_dev_idx: u32 = if has_data_files {
            (idx + 1) as u32
        } else {
            0 // data is in self
        };
        guest_mem.write_obj(data_dev_idx, GuestAddress(dev_offset + 28))?;
        idx += 1;

        // Insert external data file device entries after this image
        for data_file in &image.external_data_files {
            if idx >= MAX_CHAIN_DEVICES {
                break;
            }
            let data_size = std::fs::metadata(&data_file.path)
                .map(|m| m.len())
                .unwrap_or(0);
            let dev_offset = devices_base + (idx as u64 * 32);
            guest_mem.write_obj(
                ImageFormat::Raw.to_shared_format_u32(),
                GuestAddress(dev_offset),
            )?;
            guest_mem.write_obj(0u32, GuestAddress(dev_offset + 4))?;
            guest_mem.write_obj(data_file.extent_size, GuestAddress(dev_offset + 8))?;
            guest_mem.write_obj(data_size, GuestAddress(dev_offset + 16))?;
            guest_mem.write_obj(0u32, GuestAddress(dev_offset + 24))?;
            guest_mem.write_obj(0u32, GuestAddress(dev_offset + 28))?;
            idx += 1;
        }
    }

    Ok(idx - start_idx)
}

/// Open virtio-block devices for a backing chain, including data file if present.
///
/// After the top image (first in chain), if the chain has an external data file,
/// it is opened as a separate read-only device. Remaining backing chain images follow.
///
/// Returns the number of devices opened.
fn open_chain_devices(
    chain: &BackingChain,
    sector_size: u64,
    device_set: &mut DeviceSet,
    io_events: &mut Vec<IoEvent>,
    start_idx: usize,
    label: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut idx = start_idx;

    for image in chain.images().iter() {
        let backing = BackingStore::open(&image.path, true, None, false)?;
        let file_size = std::fs::metadata(&image.path)?.len();
        let mmio = device_mmio_base(idx);
        let vq = device_vq_base(idx);
        let device = VirtioBlockDevice::new(
            backing,
            file_size,
            sector_size,
            true, // read-only
            mmio,
            vq,
        );
        debug!(
            "Created {} device [{}] at MMIO 0x{:x}: {}",
            label,
            idx,
            mmio,
            image.path.display()
        );
        let device = Arc::new(Mutex::new(device));
        device_set.add_device(Arc::clone(&device), true);
        io_events.push(IoEvent::new(mmio)?);
        idx += 1;

        // Insert external data file devices after this image
        for data_file in &image.external_data_files {
            let data_backing = BackingStore::open(&data_file.path, true, None, false)?;
            let data_size = std::fs::metadata(&data_file.path)?.len();
            let mmio = device_mmio_base(idx);
            let vq = device_vq_base(idx);
            let device = VirtioBlockDevice::new(
                data_backing,
                data_size,
                sector_size,
                true, // read-only
                mmio,
                vq,
            );
            debug!(
                "Created {} data file device [{}] at MMIO 0x{:x}: {}",
                label,
                idx,
                mmio,
                data_file.path.display()
            );
            let device = Arc::new(Mutex::new(device));
            device_set.add_device(Arc::clone(&device), true);
            io_events.push(IoEvent::new(mmio)?);
            idx += 1;
        }
    }

    Ok(idx - start_idx)
}

/// Variant of [`open_chain_devices`] that opens specific slots
/// with read-write access instead of read-only.
///
/// `rw_slots` lists the device-slot indices (relative to
/// `start_idx`, i.e. 0 = first opened image, 1 = second, ...)
/// that should be attached via [`BackingStore::open_rw_existing`].
/// Every other slot is opened read-only just as
/// [`open_chain_devices`] does. The virtio device is also
/// constructed with `read_only=false` for RW slots so that the
/// guest's `write_input_sector` reaches the file rather than
/// being rejected by the device's read-only feature flag.
///
/// Designed for commit (phase 8 of PLAN-rebase-commit), where
/// the overlay attached as input slot 0 needs RW so the
/// overlay-clear pass can zero its L2 / refcount entries.
/// Rebase (phase 4) does not use this variant — the overlay
/// being rebased is the output device, not an input.
///
/// The `rw_slots` indices count chain images and external data
/// files in the same order they would be attached by
/// `open_chain_devices`, starting from `0`. Indices outside the
/// number of devices actually opened are ignored, matching the
/// "tolerate extra entries" convention used by the chain
/// helpers elsewhere in this file.
#[allow(dead_code)]
fn open_chain_devices_rw(
    chain: &BackingChain,
    sector_size: u64,
    device_set: &mut DeviceSet,
    io_events: &mut Vec<IoEvent>,
    start_idx: usize,
    label: &str,
    rw_slots: &[usize],
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut idx = start_idx;
    let mut slot_in_chain: usize = 0;

    for image in chain.images().iter() {
        let is_rw = rw_slots.contains(&slot_in_chain);
        let backing = if is_rw {
            BackingStore::open_rw_existing(&image.path, None)?
        } else {
            BackingStore::open(&image.path, true, None, false)?
        };
        let file_size = std::fs::metadata(&image.path)?.len();
        let mmio = device_mmio_base(idx);
        let vq = device_vq_base(idx);
        let device = VirtioBlockDevice::new(backing, file_size, sector_size, !is_rw, mmio, vq);
        debug!(
            "Created {} device [{}] at MMIO 0x{:x} ({}): {}",
            label,
            idx,
            mmio,
            if is_rw { "rw" } else { "ro" },
            image.path.display()
        );
        let device = Arc::new(Mutex::new(device));
        device_set.add_device(Arc::clone(&device), true);
        io_events.push(IoEvent::new(mmio)?);
        idx += 1;
        slot_in_chain += 1;

        for data_file in &image.external_data_files {
            let is_rw = rw_slots.contains(&slot_in_chain);
            let data_backing = if is_rw {
                BackingStore::open_rw_existing(&data_file.path, None)?
            } else {
                BackingStore::open(&data_file.path, true, None, false)?
            };
            let data_size = std::fs::metadata(&data_file.path)?.len();
            let mmio = device_mmio_base(idx);
            let vq = device_vq_base(idx);
            let device =
                VirtioBlockDevice::new(data_backing, data_size, sector_size, !is_rw, mmio, vq);
            debug!(
                "Created {} data file device [{}] at MMIO 0x{:x} ({}): {}",
                label,
                idx,
                mmio,
                if is_rw { "rw" } else { "ro" },
                data_file.path.display()
            );
            let device = Arc::new(Mutex::new(device));
            device_set.add_device(Arc::clone(&device), true);
            io_events.push(IoEvent::new(mmio)?);
            idx += 1;
            slot_in_chain += 1;
        }
    }

    Ok(idx - start_idx)
}

/// Write a ChainConfig structure to guest memory at CHAIN_CONFIG_ADDR.
///
/// This populates the chain config with metadata about all devices in the
/// backing chain, allowing guest operations to understand the chain structure
/// without parsing image headers. If the chain has an external data file,
/// it is inserted as device 1 between the top image and the backing chain.
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
    // - data_device_idx: u32 (offset 28)

    let device_count = chain.total_devices().min(MAX_CHAIN_DEVICES);

    if chain.total_devices() > MAX_CHAIN_DEVICES {
        debug!(
            "Chain truncated: {} devices exceeds maximum of {}, only first {} will be passed",
            chain.total_devices(),
            MAX_CHAIN_DEVICES,
            MAX_CHAIN_DEVICES
        );
    }

    // Write header
    guest_mem.write_obj(CHAIN_CONFIG_MAGIC, GuestAddress(CHAIN_CONFIG_ADDR))?;
    guest_mem.write_obj(device_count as u32, GuestAddress(CHAIN_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(CHAIN_CONFIG_VERSION, GuestAddress(CHAIN_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(0u32, GuestAddress(CHAIN_CONFIG_ADDR + 12))?; // reserved

    // Write device entries (handles data file insertion)
    let devices_base = CHAIN_CONFIG_ADDR + 16;
    write_chain_device_entries(guest_mem, chain, devices_base, 0)?;

    debug!("Wrote chain config at 0x{CHAIN_CONFIG_ADDR:x} ({device_count} devices)");

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
        external_data_files: Vec::new(),
    });
    chain
}

#[derive(Parser, Debug)]
#[command(name = "instar")]
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
    /// Measure the size required to convert an image to a target format
    Measure(MeasureArgs),
    /// Create a new empty disk image of the given format and size
    Create(CreateArgs),
    /// Resize an existing disk image in place
    Resize(ResizeArgs),
    /// Change an overlay's backing-file reference
    Rebase(RebaseArgs),
    /// Commit an overlay's data down into its backing file
    Commit(CommitArgs),
    /// Amend an existing qcow2 image's compat version / lazy refcounts
    Amend(AmendArgs),
    /// Emit the allocation map of a disk image
    Map(MapArgs),
    /// List, apply, create, or delete qcow2 internal snapshots
    Snapshot(SnapshotArgs),
    /// Display or validate configuration
    Config(ConfigArgs),
}

/// Arguments for `instar resize`.  Mirrors qemu-img resize's
/// surface (see PLAN-resize-phase-08-host-cli.md).
#[derive(Args, Debug)]
struct ResizeArgs {
    /// Image file to resize.
    filename: String,
    /// `[+-]SIZE[bkKMGTPE]`. Absent prefix is absolute; `+`
    /// adds to the current virtual size; `-` subtracts.
    ///
    /// `allow_hyphen_values` lets `-32M` reach this positional
    /// instead of being mis-parsed as a short flag by clap.
    #[arg(allow_hyphen_values = true)]
    size: String,
    /// Force the image format detection (raw / qcow2 / vmdk /
    /// vpc / vhdx).
    #[arg(short = 'f', long)]
    format: Option<String>,
    /// Allow shrink. Required when the new size is smaller
    /// than the current size.
    #[arg(long)]
    shrink: bool,
    /// Preallocation mode for newly-added regions.  Phase 8
    /// routes the flag through to the guest; falloc/full
    /// post-pass for raw lands in phase 9.
    #[arg(long, default_value = "off", value_parser = ["off", "metadata", "falloc", "full"])]
    preallocation: String,
    /// QEMU user-creatable object (e.g. encryption key).  Not
    /// yet supported; rejected at runtime.
    #[arg(long)]
    object: Option<String>,
    /// Indicates FILENAME is a complete image specification.
    /// Not yet supported; rejected at runtime.
    #[arg(long)]
    image_opts: bool,
    /// Suppress the success line on stdout.  Errors still go
    /// to stderr.
    #[arg(short = 'q', long)]
    quiet: bool,
    /// Output format.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,
}

/// Arguments for `instar rebase`. Mirrors `qemu-img rebase`'s
/// surface (see PLAN-rebase-commit-phase-04-rebase-host.md).
#[derive(Args, Debug)]
struct RebaseArgs {
    /// Overlay image file to rebase.
    filename: String,
    /// Force the overlay format detection (qcow2 / vmdk).
    #[arg(short = 'f', long)]
    format: Option<String>,
    /// New backing file path. Empty string detaches the
    /// overlay from its backing chain.
    #[arg(short = 'b', long = "backing", value_name = "BACKING")]
    backing: String,
    /// New backing file format hint (qcow2 / vmdk / raw).
    /// Optional; the guest probes either way.
    #[arg(short = 'F', long = "backing-format", value_name = "FMT")]
    backing_format: Option<String>,
    /// Unsafe / metadata-only rebase. Trusts the user that
    /// the new backing has the same content as the old; no
    /// chain comparison, no data copy.
    #[arg(short = 'u', long = "backing-unsafe")]
    unsafe_mode: bool,
    /// Suppress the success line on stdout. Errors still go
    /// to stderr.
    #[arg(short = 'q', long)]
    quiet: bool,
    /// Output format.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,
}

/// Host-side holder for the harvested `RebaseResultMessage`.
/// Mirrors `ResizeRunResult`.
struct RebaseRunResult {
    overlay_format: u32,
    mode: u32,
    clusters_copied: u64,
    bytes_copied: u64,
    error: u32,
}

/// Host-side holder for the harvested `AmendResultMessage`.
/// Mirrors `RebaseRunResult`. Not yet constructed by any
/// subcommand (the `amend` CLI entry point lands in phase 4);
/// the ABI and decode path are wired here so phases 2–4 build
/// against a frozen surface.
struct AmendRunResult {
    target_format: u32,
    action: u32,
    resulting_version: u32,
    resulting_lazy_refcounts: u32,
    error: u32,
}

/// Arguments for `instar amend`. Mirrors `qemu-img amend`'s
/// surface for the v1 supported keys (compat / lazy_refcounts);
/// see PLAN-amend-phase-04-host-cli.md.
#[derive(Args, Debug)]
struct AmendArgs {
    /// Image file to amend (qcow2 only).
    filename: String,
    /// Force the image format detection (qcow2 only).
    #[arg(short = 'f', long)]
    format: Option<String>,
    /// Suppress the success line on stdout. Errors still go to stderr.
    #[arg(short = 'q', long)]
    quiet: bool,
    /// Output format.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,
    /// qemu-img-style options, comma-separated key=value
    /// (e.g. -o compat=1.1,lazy_refcounts=on). Only compat and
    /// lazy_refcounts are supported.
    #[arg(short = 'o', long = "options", action = clap::ArgAction::Append,
          value_name = "KEY=VALUE,...")]
    option: Vec<String>,
}

/// Parsed, validated `-o` options for `instar amend`. Each
/// field is `None` when the corresponding key was not given,
/// leaving that aspect of the header unchanged.
#[derive(Debug)]
struct AmendOOptions {
    /// `Some(true)` for `compat=1.1`, `Some(false)` for
    /// `compat=0.10`, `None` if `compat=` was not given.
    compat_v3: Option<bool>,
    /// `Some(true)` for `lazy_refcounts=on`, `Some(false)` for
    /// off, `None` if `lazy_refcounts=` was not given.
    lazy_on: Option<bool>,
}

/// Parse the `-o key=value,...` strings for `instar amend`.
///
/// Only the qcow2 keys `compat` (`0.10`→v2 / `1.1`→v3) and
/// `lazy_refcounts` (on/off) are accepted; every other key is
/// rejected with a clear CLI error before any VM launch. At least
/// one supported option must be given.
fn parse_amend_o_options(raw: &[String]) -> Result<AmendOOptions, Box<dyn std::error::Error>> {
    let mut compat_v3: Option<bool> = None;
    let mut lazy_on: Option<bool> = None;

    for input in raw {
        for piece in input.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let (key, value) = match piece.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => {
                    return Err(format!(
                        "amend: -o option '{piece}' is missing a value (expected KEY=VALUE)"
                    )
                    .into())
                }
            };
            match key {
                "compat" => match value {
                    "0.10" => compat_v3 = Some(false),
                    "1.1" => compat_v3 = Some(true),
                    _ => {
                        return Err(format!(
                            "amend: bad value '{value}' for -o key 'compat' \
                             (expected 0.10 or 1.1)"
                        )
                        .into())
                    }
                },
                "lazy_refcounts" => match value.to_ascii_lowercase().as_str() {
                    "on" | "true" | "yes" => lazy_on = Some(true),
                    "off" | "false" | "no" => lazy_on = Some(false),
                    _ => {
                        return Err(format!(
                            "amend: bad value '{value}' for -o key 'lazy_refcounts' \
                             (expected on/off)"
                        )
                        .into())
                    }
                },
                other => {
                    return Err(format!(
                        "amend: -o key '{other}' is not supported (amend changes \
                         compat and lazy_refcounts only)"
                    )
                    .into())
                }
            }
        }
    }

    if compat_v3.is_none() && lazy_on.is_none() {
        return Err("amend: no supported -o options given \
                    (expected compat= and/or lazy_refcounts=)"
            .into());
    }
    Ok(AmendOOptions { compat_v3, lazy_on })
}

/// Arguments for `instar commit`. Mirrors `qemu-img commit`'s
/// surface (see PLAN-rebase-commit-phase-08-commit-host.md).
#[derive(Args, Debug)]
struct CommitArgs {
    /// Overlay image file to commit.
    filename: String,
    /// Force the overlay format detection (qcow2 / vmdk).
    #[arg(short = 'f', long)]
    format: Option<String>,
    /// Backing file to commit into. Optional; when omitted the
    /// host resolves the overlay's recorded immediate parent.
    /// v1 only supports the overlay's immediate parent;
    /// intermediate-image commits are deferred.
    #[arg(short = 'b', long = "base", value_name = "BASE")]
    base: Option<String>,
    /// Suppress the success line on stdout. Errors still go
    /// to stderr.
    #[arg(short = 'q', long)]
    quiet: bool,
    /// Output format.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,
}

/// Arguments for `instar map`. Mirrors `qemu-img map`'s
/// surface (FILENAME, -f, --output, --start-offset,
/// --max-length, --image-opts) plus an instar-specific
/// `--sector-size`.
#[derive(Args, Debug)]
struct MapArgs {
    /// Source image file. Required.
    input: String,

    /// Source format override (rare; usually auto-detected).
    /// Accepted for parity with qemu-img -f.
    #[arg(short = 'f', long = "format")]
    source_format: Option<String>,

    /// Output format: human (default) or json.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,

    /// Start emission at this virtual byte offset. Accepts
    /// K/M/G/T suffixes (parsed by parse_memory_size).
    /// Default: 0 (start of image).
    #[arg(long = "start-offset")]
    start_offset: Option<String>,

    /// Stop emission after this many virtual bytes from
    /// --start-offset. Accepts K/M/G/T suffixes. Default:
    /// emit to end of image.
    #[arg(long = "max-length")]
    max_length: Option<String>,

    /// Sector size for source I/O. Default: 65536. Not part
    /// of qemu-img's surface; instar-specific.
    #[arg(long, default_value = "65536")]
    sector_size: u32,

    /// Refused for parity-rejection: qemu-img's
    /// --image-opts descriptor-based source specification
    /// is deferred. Documented in docs/quirks.md.
    #[arg(long = "image-opts")]
    image_opts: bool,
}

/// Arguments for `instar snapshot`. Mirrors `qemu-img snapshot`'s
/// surface (FILENAME, -l/-a/-c/-d mode flags, -f, -q, -U,
/// --image-opts) plus instar-specific `--output` and
/// `--sector-size`.
///
/// The mode flags are mutually exclusive (clap ArgGroup,
/// `required = false`). When no mode flag is supplied, `run_snapshot`
/// defaults to list mode — matching `qemu-img snapshot`'s behaviour
/// (its `-l` is "the default"; see D2 in PLAN-snapshot-phase-09).
#[derive(Args, Debug)]
#[command(group(clap::ArgGroup::new("mode").required(false).multiple(false)))]
struct SnapshotArgs {
    /// Source image file. Required.
    filename: String,

    /// List all snapshots in the image.
    #[arg(short = 'l', long, group = "mode")]
    list: bool,

    /// Apply (goto) the named snapshot.
    #[arg(short = 'a', long, group = "mode", value_name = "SNAPSHOT")]
    apply: Option<String>,

    /// Create a new snapshot with the given name.
    #[arg(short = 'c', long, group = "mode", value_name = "NAME")]
    create: Option<String>,

    /// Delete the named snapshot.
    #[arg(short = 'd', long, group = "mode", value_name = "SNAPSHOT")]
    delete: Option<String>,

    /// Source format override (rare; usually auto-detected).
    /// Accepted for parity with qemu-img -f. Must be "qcow2"
    /// when supplied; non-qcow2 images do not support
    /// snapshots.
    #[arg(short = 'f', long)]
    format: Option<String>,

    /// Suppress the success line on stdout. Matches qemu-img
    /// snapshot -q.
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Skip the image-lock check. instar does not implement
    /// file locking, so the flag is a host-side no-op accepted
    /// for CLI parity; the bit is still forwarded to the guest
    /// via FLAG_FORCE_SHARE.
    #[arg(short = 'U', long = "force-share")]
    force_share: bool,

    /// Refused for parity-rejection: qemu-img's --image-opts
    /// descriptor-based source specification is deferred.
    /// Documented in docs/quirks.md.
    #[arg(long = "image-opts")]
    image_opts: bool,

    /// Output format: human (default) or json. The JSON form
    /// is an instar extension; qemu-img snapshot has no JSON
    /// output mode.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,

    /// Sector size for source I/O. Default: 65536. Not part
    /// of qemu-img's surface; instar-specific.
    #[arg(long, default_value = "65536")]
    sector_size: u32,
}

/// Host-side holder for the harvested `CommitResultMessage`.
/// Mirrors `RebaseRunResult`.
struct CommitRunResult {
    overlay_format: u32,
    backing_format: u32,
    clusters_committed: u64,
    bytes_committed: u64,
    overlay_clusters_cleared: u64,
    error: u32,
}

/// A parsed `[+-]SIZE` string, before resolution against the
/// existing image's current virtual size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedResizeSize {
    /// Absolute: `new_virtual_size = value`.
    Absolute(u64),
    /// Additive: `new_virtual_size = current + delta`.
    Add(u64),
    /// Subtractive: `new_virtual_size = current - delta`.
    Subtract(u64),
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
    /// By default, instar detects the installed qemu-img version and matches its output format.
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

    /// LUKS passphrase for decrypting the first payload sector to detect
    /// the inner format. When provided, instar decrypts and reports the
    /// format inside the LUKS container (e.g., qcow2, raw).
    #[arg(long, value_name = "PASSPHRASE")]
    luks_passphrase: Option<String>,

    /// Read LUKS passphrase from a file (first line, trailing newline stripped).
    #[arg(long, value_name = "PATH", conflicts_with = "luks_passphrase")]
    luks_passphrase_file: Option<String>,

    /// Maximum guest memory for LUKS2 Argon2 key derivation (e.g., "1G", "2G").
    /// LUKS2 uses Argon2id which is memory-hard — typical images require 1 GB.
    /// Without this flag, LUKS2 metadata is reported but decryption is skipped.
    #[arg(long, value_name = "SIZE")]
    max_guest_memory: Option<String>,
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

/// Repair tier selected by `--repair[=MODE]`.
///
/// `leaks` (the bare `--repair` default) frees only clusters the
/// integrity walk proved unreferenced — crash-safe, lossless.
/// `all` additionally corrects wrong refcounts (both directions)
/// and reconciles the refcount↔COPIED invariant under the crash-safe
/// `corrupt`-bit ordering; it is destructive (it rewrites image
/// metadata in place — back up valuable images first).
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum RepairMode {
    /// Safe leak-reclamation tier (qemu-img check -r leaks).
    Leaks,
    /// Lossy refcount + COPIED correction tier (qemu-img check -r all).
    All,
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

    /// Repair the image in place (qcow2 only): `--repair[=leaks|all]`.
    ///
    /// Bare `--repair` (or `--repair=leaks`) opens the image read-write
    /// and frees clusters the integrity walk proved unreferenced (the
    /// safe "leaks" tier), mirroring `qemu-img check -r leaks`; this is
    /// crash-safe and lossless.
    ///
    /// `--repair=all` is LOSSY: it rewrites image metadata in place,
    /// correcting wrong refcounts (both directions) and reconciling the
    /// refcount<->COPIED invariant under the crash-safe `corrupt`-bit
    /// ordering, mirroring `qemu-img check -r all`. Back up valuable
    /// images before using it.
    #[arg(long, value_name = "MODE", num_args = 0..=1, default_missing_value = "leaks")]
    repair: Option<RepairMode>,
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

    /// QCOW2 AES decryption password (for crypt_method=1 images)
    #[arg(long, value_name = "PASSWORD")]
    qcow2_password: Option<String>,

    /// Read QCOW2 AES decryption password from file
    #[arg(long, value_name = "PATH", conflicts_with = "qcow2_password")]
    qcow2_password_file: Option<String>,

    /// LUKS passphrase for QCOW2 crypt_method=2 decryption
    #[arg(long, value_name = "PASSPHRASE")]
    luks_passphrase: Option<String>,

    /// Read LUKS passphrase from file (for QCOW2 crypt_method=2)
    #[arg(long, value_name = "PATH", conflicts_with = "luks_passphrase")]
    luks_passphrase_file: Option<String>,
}

#[derive(Args, Debug)]
struct ConvertArgs {
    /// Input image file
    input: String,

    /// Output image file
    output: String,

    /// Output format ("raw", "qcow2", "vmdk", or "vpc")
    #[arg(short = 'O', long = "output-format", default_value = "raw")]
    output_format: String,

    /// Sector size for I/O (default: 65536)
    #[arg(long, default_value = "65536")]
    sector_size: u32,

    /// Output cluster size for QCOW2 (default: 65536)
    #[arg(long, default_value = "65536")]
    cluster_size: u32,

    /// Compress output data (QCOW2: zlib clusters, VMDK: streamOptimized)
    #[arg(short = 'c', long)]
    compress: bool,

    /// Skip writing zero-filled clusters to output (sparse output, default).
    /// This is enabled by default; use --no-skip-zeros to write dense output.
    #[arg(short = 'S', long, overrides_with = "no_skip_zeros")]
    skip_zeros: bool,

    /// Write full dense output (don't skip zero-filled clusters)
    #[arg(long, overrides_with = "skip_zeros")]
    no_skip_zeros: bool,

    /// Progress update interval in percent (default: 10)
    #[arg(short = 'p', long, default_value = "10")]
    progress_percent: u32,

    /// Don't create output file (must already exist)
    #[arg(short = 'n', long)]
    no_create: bool,

    /// QCOW2 AES decryption password (for crypt_method=1 images)
    #[arg(long, value_name = "PASSWORD")]
    qcow2_password: Option<String>,

    /// Read QCOW2 AES decryption password from file
    #[arg(long, value_name = "PATH", conflicts_with = "qcow2_password")]
    qcow2_password_file: Option<String>,

    /// LUKS passphrase for native LUKS or QCOW2 crypt_method=2 decryption
    #[arg(long, value_name = "PASSPHRASE")]
    luks_passphrase: Option<String>,

    /// Read LUKS passphrase from file (for native LUKS or QCOW2 crypt_method=2)
    #[arg(long, value_name = "PATH", conflicts_with = "luks_passphrase")]
    luks_passphrase_file: Option<String>,

    /// Write extended L2 entries (16-byte with subcluster bitmaps) in QCOW2 output
    #[arg(long)]
    extended_l2: bool,

    /// Passphrase for LUKS-encrypted QCOW2 output (crypt_method=2, AES-256-XTS).
    /// Cannot be used with --luks-passphrase or --qcow2-password (they share
    /// the same config field; use separate invocations to decrypt then re-encrypt).
    #[arg(
        long,
        value_name = "PASSPHRASE",
        conflicts_with_all = ["luks_passphrase", "luks_passphrase_file",
                              "qcow2_password", "qcow2_password_file"]
    )]
    luks_encrypt_passphrase: Option<String>,

    /// Read LUKS encryption passphrase from file
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["luks_encrypt_passphrase", "luks_passphrase",
                              "luks_passphrase_file", "qcow2_password",
                              "qcow2_password_file"]
    )]
    luks_encrypt_passphrase_file: Option<String>,

    /// PBKDF2 iteration count for LUKS output encryption (default: 20000)
    #[arg(long, default_value = "20000")]
    luks_encrypt_iterations: u32,

    /// Extract a specific snapshot (by ID or name) instead of the active image
    #[arg(long, value_name = "ID")]
    snapshot: Option<String>,

    /// Maximum guest memory for LUKS v2 Argon2id key derivation (e.g., "1G", "2G").
    /// LUKS v2 uses Argon2id which is memory-hard — typical images require 1 GB.
    /// Without this flag, native LUKS v2 conversion will fail.
    #[arg(long, value_name = "SIZE")]
    max_guest_memory: Option<String>,

    /// VMDK subformat for -O vmdk output. "monolithicSparse" (default),
    /// "streamOptimized" (when -c), or "monolithicFlat" (descriptor +
    /// raw extent file). Only valid with -O vmdk.
    #[arg(long, default_value = "")]
    subformat: String,

    /// Output grain size for VMDK in bytes (default: 65536).
    /// Must be a power of 2, 4096 to 65536. Only valid with -O vmdk.
    #[arg(long, default_value = "65536")]
    grain_size: u32,

    /// Output block size for VHD/VHDX in bytes.
    /// Defaults: 2097152 (2MB) for VHD, 33554432 (32MB) for VHDX.
    /// Must be a power of 2. Only valid with -O vpc or -O vhdx.
    #[arg(long, default_value = "0")]
    block_size: u32,
}

#[derive(Args, Debug)]
struct MeasureArgs {
    /// Source image file. Mutually exclusive with --size.
    #[arg(conflicts_with = "size")]
    input: Option<String>,

    /// Compute the measure for a hypothetical empty image of this size.
    /// Mutually exclusive with FILENAME.
    /// Accepts suffixes K, M, G, T (parsed by parse_memory_size).
    #[arg(long, short = 's', value_name = "SIZE", conflicts_with = "input")]
    size: Option<String>,

    /// Target output format. Supported: raw, qcow2, vmdk, vpc (VHD), vhdx.
    /// Default: raw (matching qemu-img).
    #[arg(short = 'O', long = "target-format", default_value = "raw",
          value_parser = ["raw", "qcow2", "vmdk", "vpc", "vhdx"])]
    target_format: String,

    /// Source format override (rare; usually auto-detected).
    /// Accepted for parity with qemu-img -f.
    #[arg(short = 'f', long = "format")]
    source_format: Option<String>,

    /// Output format: human (default) or json.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,

    /// Sector size for source I/O. Default: 65536.
    #[arg(long, default_value = "65536")]
    sector_size: u32,

    // --- per-target qcow2 options ---
    /// qcow2 cluster size in bytes. Power of two in [512, 2 MiB].
    /// Default (when -O qcow2): 65536.
    #[arg(long, default_value = "0")]
    cluster_size: u32,

    /// qcow2 refcount entry width in bits. Must be in {1,2,4,8,16,32,64}.
    /// Default (when -O qcow2): 16.
    #[arg(long, default_value = "0")]
    refcount_bits: u8,

    /// qcow2 extended L2 entries (16-byte with subcluster bitmaps).
    #[arg(long)]
    extended_l2: bool,

    /// qcow2 lazy refcounts. Accepted but does not affect required size.
    #[arg(long)]
    lazy_refcounts: bool,

    /// qcow2 compat level: "0.10" (v2) or "1.1" (v3, default).
    #[arg(long, default_value = "1.1", value_parser = ["0.10", "1.1"])]
    compat: String,

    /// qcow2 compression flag (does not change required; accepted for parity).
    #[arg(long)]
    compress: bool,

    /// qcow2 preallocation mode.
    #[arg(long, default_value = "off",
          value_parser = ["off", "metadata", "falloc", "full"])]
    preallocation: String,

    // --- per-target vmdk options ---
    /// vmdk subformat. Default (when -O vmdk): monolithicSparse.
    #[arg(long, default_value = "",
          value_parser = ["", "monolithicSparse", "streamOptimized",
                          "monolithicFlat"])]
    subformat: String,

    /// vmdk grain size in bytes. Power of two in [4 KiB, 64 KiB].
    /// Default (when -O vmdk): 65536.
    #[arg(long, default_value = "0")]
    grain_size: u32,

    // --- per-target vhd / vhdx options ---
    /// vhd / vhdx block size in bytes. Power of two; vhd: [512 KiB, 2 GiB],
    /// vhdx: [1 MiB, 256 MiB]. Default (when -O vpc): 2 MiB; default (when -O vhdx): 32 MiB.
    #[arg(long, default_value = "0")]
    block_size: u32,

    /// qemu-img-style options as comma-separated key=value pairs
    /// (e.g. -o cluster_size=64k,extended_l2=on). Values override
    /// the matching individual flags. Repeatable: each invocation
    /// contributes more keys.
    #[arg(short = 'o', long = "options", action = clap::ArgAction::Append,
          value_name = "KEY=VALUE,...")]
    option: Vec<String>,
}

#[derive(Args, Debug)]
struct CreateArgs {
    /// Path to the new image file to create. Overwrites if it
    /// already exists (matches qemu-img).
    filename: String,

    /// Virtual disk size (e.g. "1G", "512M", "1T"). Required unless
    /// -b BACKING is given, in which case it defaults to the backing
    /// file's virtual size.
    #[arg(value_name = "SIZE")]
    size: Option<String>,

    /// Target output format. Supported: raw, qcow2, vmdk, vpc (VHD), vhdx.
    #[arg(short = 'f', long = "format", default_value = "raw",
          value_parser = ["raw", "qcow2", "vmdk", "vpc", "vhdx"])]
    target_format: String,

    /// Backing file path. The path is embedded verbatim into the
    /// resulting image (so the metadata is portable) and resolved
    /// relative to the new image's directory for opening.
    #[arg(short = 'b', long = "backing", value_name = "BACKING")]
    backing: Option<String>,

    /// Backing file format hint (qcow2 / raw / vmdk / ...).
    #[arg(short = 'F', long = "backing-format", value_name = "FMT")]
    backing_format: Option<String>,

    /// Don't fail if the backing file isn't accessible / parseable.
    #[arg(short = 'u', long = "backing-unsafe")]
    backing_unsafe: bool,

    /// Suppress the "Created: ..." line on success (matches qemu-img -q).
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Result rendering: human (default) or json.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    output: String,

    /// Host I/O sector size. Phase 3 only supports 512 because the
    /// metadata layouts in `crates/create` are 512-byte aligned but
    /// not always aligned to larger sector sizes — multi-write
    /// metadata would clobber itself in a single bigger sector.
    /// Documented; phase 5 may relax this.
    #[arg(long, default_value = "512")]
    sector_size: u32,

    /// qcow2 cluster size in bytes. Power of two in [512, 2 MiB].
    /// Default (when -f qcow2): 65536.
    #[arg(long, default_value = "0")]
    cluster_size: u32,

    /// qcow2 refcount entry width in bits. Must be in {1,2,4,8,16,32,64}.
    /// Default (when -f qcow2): 16.
    #[arg(long, default_value = "0")]
    refcount_bits: u8,

    /// qcow2: emit extended-L2 entries (16-byte with subcluster bitmaps).
    #[arg(long)]
    extended_l2: bool,

    /// qcow2: enable the lazy-refcounts compat bit.
    #[arg(long)]
    lazy_refcounts: bool,

    /// qcow2 compat level: "0.10" (v2) or "1.1" (v3, default).
    #[arg(long, default_value = "1.1", value_parser = ["0.10", "1.1"])]
    compat: String,

    /// vmdk subformat (default: monolithicSparse). vhd subformat
    /// (default: dynamic). Other subformats are accepted in this
    /// argument name and validated against the chosen --format.
    #[arg(long, default_value = "",
          value_parser = ["", "monolithicSparse", "streamOptimized",
                          "monolithicFlat", "dynamic", "fixed"])]
    subformat: String,

    /// vmdk grain size in bytes. Power of two in [4 KiB, 64 KiB].
    /// Default (when -f vmdk): 65536.
    #[arg(long, default_value = "0")]
    grain_size: u32,

    /// vhd / vhdx block size in bytes. Power of two.
    /// vhd default: 2 MiB; vhdx default: 32 MiB.
    #[arg(long, default_value = "0")]
    block_size: u32,

    /// Preallocation mode. Phase 3 accepts "off" (default) and
    /// "falloc" (raw only); other modes return a clear "not yet
    /// supported" error pointing at phase 6 of PLAN-create.md.
    #[arg(long, default_value = "off",
          value_parser = ["off", "metadata", "falloc", "full"])]
    preallocation: String,

    /// qemu-img-style options as comma-separated key=value pairs.
    /// Phase 3 placeholder — the full parser ships in phase 4 of
    /// PLAN-create.md. Passing any -o option returns an error
    /// pointing users at the individual flags for now.
    #[arg(short = 'o', long = "options", action = clap::ArgAction::Append,
          value_name = "KEY=VALUE,...")]
    option: Vec<String>,
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
        Commands::Measure(args) => run_measure(args, verbose),
        Commands::Create(args) => run_create(args, verbose),
        Commands::Resize(args) => run_resize(args, verbose),
        Commands::Rebase(args) => run_rebase(args, verbose),
        Commands::Commit(args) => run_commit(args, verbose),
        Commands::Amend(args) => run_amend(args, verbose),
        Commands::Map(args) => run_map(args, verbose),
        Commands::Snapshot(args) => run_snapshot(args, verbose),
        Commands::Config(args) => run_config(args),
    }
}

/// Probed metadata for the overlay being rebased.
#[allow(dead_code)]
struct ProbedRebaseTarget {
    format: u32,
    current_virtual_size: u64,
    current_file_size: u64,
    overlay_cluster_size: u32,
}

/// Probe the overlay's format and key metadata. Reads the
/// first 4 KiB sector-0 region via the host (the same
/// pre-launch pattern resize uses).
fn probe_rebase_target(
    path: &Path,
    forced_format: Option<&str>,
) -> Result<ProbedRebaseTarget, Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut file = std::fs::OpenOptions::new().read(true).open(path)?;
    let current_file_size = file.metadata()?.len();

    let mut buf = vec![0u8; 4096];
    let read = file.read(&mut buf)?;
    buf.truncate(read);

    let detected = match forced_format {
        Some("qcow2") => shared::ImageFormat::Qcow2,
        Some("vmdk") => shared::ImageFormat::Vmdk4,
        Some(other) => {
            return Err(
                format!("rebase: format '{other}' is not supported (qcow2 and vmdk only)").into(),
            );
        }
        None => shared::format_detection::detect_format_from_header(&buf, buf.len(), false),
    };

    let (format_code, current_virtual_size, overlay_cluster_size) = match detected {
        shared::ImageFormat::Qcow2 => {
            let parsed = qcow2::QcowHeader::parse(&buf).ok_or_else(|| {
                Box::<dyn std::error::Error>::from("rebase: failed to parse qcow2 header")
            })?;
            (
                IMAGE_FORMAT_QCOW2,
                parsed.virtual_size,
                parsed.cluster_size as u32,
            )
        }
        shared::ImageFormat::Vmdk4 => {
            let parsed = vmdk::Vmdk4Header::parse(&buf).ok_or_else(|| {
                Box::<dyn std::error::Error>::from("rebase: failed to parse vmdk header")
            })?;
            (IMAGE_FORMAT_VMDK4, parsed.virtual_size, 0u32)
        }
        other => {
            return Err(format!(
                "rebase: format '{:?}' does not support rebase (qcow2 and vmdk only)",
                other
            )
            .into());
        }
    };

    Ok(ProbedRebaseTarget {
        format: format_code,
        current_virtual_size,
        current_file_size,
        overlay_cluster_size,
    })
}

/// Run the rebase operation.
///
/// Step 4c ships path resolution, format probing, chain
/// discovery (old + new), and pre-checks. The actual KVM
/// lifecycle that writes RebaseConfig, attaches the devices,
/// and runs the guest is step 4d — currently deferred. The
/// runner therefore errors out with a clear message at the
/// guest-launch point.
fn run_rebase(args: RebaseArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let _ = verbose;
    let overlay_path = Path::new(&args.filename);
    if !overlay_path.exists() {
        return Err(format!("rebase: overlay '{}' does not exist", args.filename).into());
    }

    let probed = probe_rebase_target(overlay_path, args.format.as_deref())?;

    // Resolve the new backing path. Empty string = detach.
    // Relative paths resolve against the overlay's parent
    // directory to match qemu-img's semantics.
    let is_detach = args.backing.is_empty();
    let resolved_new_backing = if is_detach {
        None
    } else {
        let p = Path::new(&args.backing);
        let resolved = if p.is_absolute() {
            p.to_path_buf()
        } else {
            overlay_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(p)
        };
        if !args.unsafe_mode && !resolved.exists() {
            return Err(format!(
                "rebase: new backing file '{}' does not exist; pass -u to skip this check",
                resolved.display()
            )
            .into());
        }
        Some(resolved)
    };

    // Validate the path length against the embedded buffer
    // size in RebaseConfig.
    if args.backing.len() > 1024 {
        return Err(format!(
            "rebase: backing path is {} bytes; maximum is 1024",
            args.backing.len()
        )
        .into());
    }

    // Discover the old chain (the overlay's current parent +
    // ancestors). discover_backing_chain returns a chain
    // that starts with the top image (the overlay); strip
    // that front entry so the chain is "parents only".
    let security_config = config::SecurityConfig::default();
    let sector_size = 512u32;

    let old_chain_full = discover_backing_chain(overlay_path, sector_size, &security_config)
        .map_err(|e| -> Box<dyn std::error::Error> { format!("rebase: {e}").into() })?;
    let old_chain_images = old_chain_full.images();
    let old_chain_parent_count = if old_chain_images.is_empty() {
        0
    } else {
        old_chain_images.len() - 1
    };

    // Discover the new chain (only if not detaching).
    let new_chain_full = if let Some(ref p) = resolved_new_backing {
        Some(
            discover_backing_chain(p, sector_size, &security_config)
                .map_err(|e| -> Box<dyn std::error::Error> { format!("rebase: {e}").into() })?,
        )
    } else {
        None
    };
    let new_chain_count = new_chain_full
        .as_ref()
        .map(|c| c.total_devices())
        .unwrap_or(0);

    // Combined device count check. MAX_CHAIN_DEVICES is the
    // shared cap (16); the overlay itself uses the output
    // slot, so the inputs are old_chain_parent_count +
    // new_chain_count.
    let total_input_devices = old_chain_parent_count + new_chain_count;
    if total_input_devices > shared::MAX_CHAIN_DEVICES {
        return Err(format!(
            "rebase: combined chain length ({} parents + {} new chain) exceeds the {}-device limit",
            old_chain_parent_count,
            new_chain_count,
            shared::MAX_CHAIN_DEVICES
        )
        .into());
    }

    // Build a parents-only sub-chain (strip the overlay itself
    // from the front of the discovered chain). The guest's old
    // chain is the parents only — the overlay is the output
    // device, not an input.
    let old_chain_parents = if old_chain_images.is_empty() {
        BackingChain::new()
    } else {
        let mut parents = BackingChain::new();
        for img in &old_chain_images[1..] {
            parents.push(img.clone());
        }
        parents
    };
    let old_chain_input_devices = old_chain_parents.total_devices();
    let new_chain_input_devices = new_chain_full
        .as_ref()
        .map(|c| c.total_devices())
        .unwrap_or(0);
    let total_input_devices_final = old_chain_input_devices + new_chain_input_devices;
    debug_assert_eq!(total_input_devices_final, total_input_devices);

    // Resolve the new-backing-format hint. None / "" → 0
    // (auto-detect by the guest probe path). Honour `-F`.
    let new_backing_format_code = match args.backing_format.as_deref() {
        None => 0u32,
        Some("qcow2") => IMAGE_FORMAT_QCOW2,
        Some("vmdk") => IMAGE_FORMAT_VMDK4,
        Some("raw") => IMAGE_FORMAT_RAW,
        Some(other) => {
            return Err(format!(
                "rebase: backing format '{other}' is not supported (qcow2, vmdk, raw only)"
            )
            .into());
        }
    };

    let mut flags: u32 = 0;
    if args.unsafe_mode {
        flags |= REBASE_CONFIG_FLAG_UNSAFE;
    }
    if args.quiet {
        flags |= REBASE_CONFIG_FLAG_QUIET;
    }
    if is_detach {
        flags |= REBASE_CONFIG_FLAG_DETACH;
    }

    // Load core + rebase guest binaries.
    let core_path = get_binary_path("core.bin");
    let core_code = load_guest_binary(
        core_path
            .to_str()
            .ok_or("rebase: core.bin path is not valid UTF-8")?,
    )?;
    let rebase_path = get_binary_path("rebase.bin");
    let rebase_code = load_guest_binary(
        rebase_path
            .to_str()
            .ok_or("rebase: rebase.bin path is not valid UTF-8")?,
    )?;

    // Open the overlay as the output device, RW. Expose a
    // generous capacity hint so safe mode can grow the file
    // (allocate clusters past EOF) without being rejected at
    // the virtio boundary. Unsafe mode never grows.
    let capacity_hint = probed.current_file_size.saturating_mul(2).max(1 << 30);
    let output_backing = BackingStore::open_rw_existing(overlay_path, Some(capacity_hint))?;

    let result = run_rebase_guest(
        &core_code,
        &rebase_code,
        probed.format,
        new_backing_format_code,
        flags,
        sector_size,
        probed.overlay_cluster_size,
        probed.current_virtual_size,
        args.backing.as_bytes(),
        output_backing,
        capacity_hint,
        &old_chain_parents,
        new_chain_full.as_ref(),
        old_chain_input_devices,
        new_chain_input_devices,
        verbose,
    )?;

    if result.error != shared::RebaseResult::ERROR_OK {
        return Err(format!(
            "rebase: guest reported error {}: {}",
            result.error,
            map_rebase_error(result.error)
        )
        .into());
    }

    render_rebase_success(
        &args,
        result.overlay_format,
        result.mode,
        result.clusters_copied,
        result.bytes_copied,
    );
    Ok(())
}

/// Probed metadata for an image involved in a commit (overlay
/// or backing). Mirrors `ProbedRebaseTarget` but adds the
/// recorded backing-file pointer so the host can resolve an
/// implicit `-b`.
#[allow(dead_code)]
struct ProbedCommitTarget {
    format: u32,
    virtual_size: u64,
    cluster_size: u32,
    backing_file_raw: Option<String>,
}

/// Probe an image's format + key metadata + recorded backing-
/// file pointer via the sandboxed info operation. Used for
/// both the overlay and the backing during commit pre-checks.
fn probe_commit_target(
    path: &Path,
    forced_format: Option<&str>,
    label: &str,
) -> Result<ProbedCommitTarget, Box<dyn std::error::Error>> {
    let info = execute_info_operation(path, 65536, false)
        .map_err(|e| -> Box<dyn std::error::Error> { format!("commit: {label}: {e}").into() })?;

    // Honour an explicit format override. Refuse anything other
    // than qcow2 / vmdk up-front so the user gets a clear error
    // before the per-format checks below.
    let detected = match forced_format {
        Some("qcow2") => "qcow2",
        Some("vmdk") => "vmdk",
        Some(other) => {
            return Err(format!(
                "commit: {label}: format '{other}' is not supported (qcow2 and vmdk only)"
            )
            .into());
        }
        None => info.format.as_str(),
    };

    let format_code = match detected {
        "qcow2" => IMAGE_FORMAT_QCOW2,
        "vmdk" => IMAGE_FORMAT_VMDK4,
        other => {
            return Err(format!(
                "commit: {label}: format '{other}' does not support commit \
                 (qcow2 and vmdk only)"
            )
            .into());
        }
    };

    Ok(ProbedCommitTarget {
        format: format_code,
        virtual_size: info.virtual_size,
        cluster_size: info.cluster_size,
        backing_file_raw: info.backing_file,
    })
}

/// Run the commit operation.
///
/// Step 8c ships path resolution, format probing, chain
/// discovery (on the backing only), and the pre-checks listed
/// in PLAN-rebase-commit-phase-08-commit-host.md. The actual
/// KVM lifecycle that writes `CommitConfig`, attaches the
/// devices, and runs the guest is step 8d — currently
/// deferred. The runner therefore errors out with a clear
/// message at the guest-launch point.
fn run_commit(args: CommitArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let _ = verbose;
    let overlay_path = Path::new(&args.filename);
    if !overlay_path.exists() {
        return Err(format!("commit: overlay '{}' does not exist", args.filename).into());
    }

    let overlay_probe = probe_commit_target(overlay_path, args.format.as_deref(), "overlay")?;

    // Resolve the backing path. -b BASE wins; otherwise fall
    // back to the overlay's recorded backing-file pointer.
    // Relative paths resolve against the overlay's parent
    // directory to match qemu-img semantics.
    let overlay_parent = overlay_path.parent().unwrap_or_else(|| Path::new("."));
    let resolve_relative = |raw: &str| -> std::path::PathBuf {
        let p = Path::new(raw);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            overlay_parent.join(p)
        }
    };

    let (resolved_backing_path, base_was_explicit) = match &args.base {
        Some(base) => (resolve_relative(base), true),
        None => match overlay_probe.backing_file_raw.as_deref() {
            Some(b) if !b.is_empty() => (resolve_relative(b), false),
            _ => {
                return Err("commit: overlay has no recorded backing file; \
                            pass -b BASE to name one"
                    .into());
            }
        },
    };

    if !resolved_backing_path.exists() {
        return Err(format!(
            "commit: backing file '{}' does not exist",
            resolved_backing_path.display()
        )
        .into());
    }

    // Backing-writability pre-check. We need O_RDWR for the
    // commit's data and metadata writes; surface a clearer
    // message than KVM-side EACCES.
    if std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&resolved_backing_path)
        .is_err()
    {
        return Err(format!(
            "commit: backing file '{}' is not writable",
            resolved_backing_path.display()
        )
        .into());
    }

    let backing_probe = probe_commit_target(&resolved_backing_path, None, "backing")?;

    // Cross-format refusal. v1 commits must be qcow2 → qcow2
    // or vmdk → vmdk. Cross-format commits need planner
    // extensions and are tracked as Future work.
    if overlay_probe.format != backing_probe.format {
        return Err(format!(
            "commit: cross-format commit is not yet supported (overlay is {}, backing is {})",
            image_format_name(overlay_probe.format),
            image_format_name(backing_probe.format),
        )
        .into());
    }

    // Cluster-size mismatch refusal. Phase 7's guest also
    // refuses with ERROR_UNSUPPORTED_FORMAT; the host catches
    // it earlier with a clearer message and saves a guest
    // launch.
    if overlay_probe.cluster_size != 0
        && backing_probe.cluster_size != 0
        && overlay_probe.cluster_size != backing_probe.cluster_size
    {
        return Err(format!(
            "commit: cluster-size mismatch is not yet supported (overlay {} B, backing {} B)",
            overlay_probe.cluster_size, backing_probe.cluster_size,
        )
        .into());
    }

    // Backing must be at least as large as the overlay or the
    // last cluster has nowhere to land.
    if backing_probe.virtual_size < overlay_probe.virtual_size {
        return Err(format!(
            "commit: overlay virtual size ({} B) exceeds backing virtual size ({} B)",
            overlay_probe.virtual_size, backing_probe.virtual_size,
        )
        .into());
    }

    // If -b was supplied, verify it names the overlay's
    // immediate parent. Intermediate-image commits are
    // deferred per the master plan; the comparison
    // canonicalises both sides so symlinks / `..` don't
    // produce false negatives.
    if base_was_explicit {
        let canonical_supplied = resolved_backing_path
            .canonicalize()
            .unwrap_or_else(|_| resolved_backing_path.clone());
        let recorded_parent = overlay_probe
            .backing_file_raw
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(resolve_relative);
        match recorded_parent {
            Some(recorded) => {
                let canonical_recorded = recorded.canonicalize().unwrap_or(recorded);
                if canonical_supplied != canonical_recorded {
                    return Err(format!(
                        "commit: commit through an intermediate layer is not yet \
                         supported (the overlay's immediate parent is '{}')",
                        canonical_recorded.display(),
                    )
                    .into());
                }
            }
            None => {
                // The overlay has no recorded parent, so any
                // explicit -b is necessarily a non-parent.
                return Err(format!(
                    "commit: overlay has no recorded backing file; '-b {}' would be \
                     a new backing reference, which commit does not support \
                     (use `instar rebase` to set a backing)",
                    resolved_backing_path.display(),
                )
                .into());
            }
        }
    }

    // Discover the backing's own ancestor chain. The backing
    // itself is the output device, not part of the input
    // chain — strip it from the front of the returned chain.
    // The v1 guest ignores these slots; populating them gives
    // the future "skip when chain already provides this data"
    // mode something to consume.
    let security_config = config::SecurityConfig::default();
    let sector_size = 512u32;
    let backing_chain_full =
        discover_backing_chain(&resolved_backing_path, sector_size, &security_config)
            .map_err(|e| -> Box<dyn std::error::Error> { format!("commit: {e}").into() })?;
    let backing_chain_images = backing_chain_full.images();
    let backing_parents = if backing_chain_images.is_empty() {
        BackingChain::new()
    } else {
        let mut parents = BackingChain::new();
        for img in &backing_chain_images[1..] {
            parents.push(img.clone());
        }
        parents
    };

    // Combined device count check. The overlay occupies input
    // slot 0; backing's parents fill input slots 1..N. The
    // backing-as-output isn't counted in MAX_CHAIN_DEVICES
    // (it's the output, not an input).
    let total_input_devices = 1 + backing_parents.total_devices();
    if total_input_devices > shared::MAX_CHAIN_DEVICES {
        return Err(format!(
            "commit: combined chain length (overlay + {} backing parents) exceeds the \
             {}-device limit",
            backing_parents.total_devices(),
            shared::MAX_CHAIN_DEVICES,
        )
        .into());
    }

    // Load core + commit guest binaries.
    let core_path = get_binary_path("core.bin");
    let core_code = load_guest_binary(
        core_path
            .to_str()
            .ok_or("commit: core.bin path is not valid UTF-8")?,
    )?;
    let commit_path = get_binary_path("commit.bin");
    let commit_code = load_guest_binary(
        commit_path
            .to_str()
            .ok_or("commit: commit.bin path is not valid UTF-8")?,
    )?;

    // Open the backing as the output device, RW. The commit
    // grows the backing past its current file size when the
    // overlay's allocator path appends new clusters (qcow2) or
    // grains (vmdk) at EOF — expose a generous capacity hint
    // so the virtio boundary doesn't reject those writes.
    let backing_file_size = std::fs::metadata(&resolved_backing_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let output_capacity_hint = backing_file_size.saturating_mul(2).max(1 << 30);
    let output_backing =
        BackingStore::open_rw_existing(&resolved_backing_path, Some(output_capacity_hint))?;

    let mut flags: u32 = 0;
    if args.quiet {
        flags |= COMMIT_CONFIG_FLAG_QUIET;
    }

    let backing_path_string = resolved_backing_path.to_string_lossy().into_owned();
    let overlay_format = overlay_probe.format;
    let backing_format = backing_probe.format;
    let overlay_cluster_size = overlay_probe.cluster_size;
    let backing_cluster_size = backing_probe.cluster_size;
    let overlay_virtual_size = overlay_probe.virtual_size;
    let backing_virtual_size = backing_probe.virtual_size;

    let result = run_commit_guest(
        &core_code,
        &commit_code,
        overlay_format,
        backing_format,
        flags,
        sector_size,
        overlay_cluster_size,
        backing_cluster_size,
        overlay_virtual_size,
        backing_virtual_size,
        overlay_path,
        output_backing,
        output_capacity_hint,
        &backing_parents,
        verbose,
    )?;

    if result.error != shared::CommitResult::ERROR_OK {
        return Err(format!(
            "commit: guest reported error {}: {}",
            result.error,
            map_commit_error(result.error)
        )
        .into());
    }

    render_commit_success(
        &args,
        &backing_path_string,
        result.overlay_format,
        result.backing_format,
        result.clusters_committed,
        result.bytes_committed,
        result.overlay_clusters_cleared,
    );
    Ok(())
}

/// Run the resize operation.
fn run_resize(args: ResizeArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Reject the unsupported surface up-front before any I/O.
    if args.object.is_some() {
        return Err("--object is not yet supported by instar resize".into());
    }
    if args.image_opts {
        return Err("--image-opts is not yet supported by instar resize".into());
    }

    let parsed_size = parse_resize_size(&args.size)?;
    let probed = probe_resize_target(Path::new(&args.filename), args.format.as_deref())?;
    let new_virtual_size = match parsed_size {
        ParsedResizeSize::Absolute(v) => v,
        ParsedResizeSize::Add(d) => probed
            .current_virtual_size
            .checked_add(d)
            .ok_or("resize: new virtual size overflows u64")?,
        ParsedResizeSize::Subtract(d) => probed
            .current_virtual_size
            .checked_sub(d)
            .ok_or("resize: new virtual size underflows below zero")?,
    };

    if probed.format == IMAGE_FORMAT_RAW {
        run_resize_raw(&args, &probed, new_virtual_size)
    } else {
        run_resize_nonraw(&args, &probed, new_virtual_size, verbose)
    }
}

/// Snapshot of what the host probed from the target file before
/// launching the guest.
struct ProbedResizeTarget {
    /// Numeric `IMAGE_FORMAT_*` constant.
    format: u32,
    /// Virtual disk size in bytes (= file length for raw; from
    /// the format header otherwise).
    current_virtual_size: u64,
    /// File size in bytes (pre-resize EOF).
    current_file_size: u64,
    /// QCOW2 only: extended_l2 bit from the header.  False for
    /// other formats.
    qcow2_extended_l2: bool,
}

/// Probe the resize target's format and current virtual size.
/// Honours `-f FMT` if given; otherwise auto-detects via
/// `shared::format_detection::detect_format_from_header`.
fn probe_resize_target(
    path: &Path,
    forced_format: Option<&str>,
) -> Result<ProbedResizeTarget, Box<dyn std::error::Error>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::OpenOptions::new().read(true).open(path)?;
    let current_file_size = file.metadata()?.len();

    // Read the first 4 KiB; covers every format's sector-0
    // header.  VHDX uses a bigger first-region magic but the
    // 8-byte file identifier still lives at offset 0.
    let mut buf = vec![0u8; 4096];
    let read = file.read(&mut buf)?;
    buf.truncate(read);

    let detected = match forced_format {
        Some("raw") => shared::ImageFormat::Raw,
        Some("qcow2") => shared::ImageFormat::Qcow2,
        Some("vmdk") => shared::ImageFormat::Vmdk4,
        Some("vpc") | Some("vhd") => shared::ImageFormat::Vhd,
        Some("vhdx") => shared::ImageFormat::Vhdx,
        Some(other) => return Err(format!("resize: unknown -f format '{other}'").into()),
        None => {
            let by_header =
                shared::format_detection::detect_format_from_header(&buf, buf.len(), false);
            // A fixed VHD has raw data at the head and its footer only at
            // the tail (last 512 bytes), so header detection returns Raw.
            // Probe the tail for a VHD footer before falling through to
            // raw, matching info/check and the resize guest — otherwise a
            // fixed VHD is routed to the raw resize path and loses its
            // footer.
            if by_header == shared::ImageFormat::Raw && current_file_size >= 512 {
                let mut tail = [0u8; 512];
                if file.seek(SeekFrom::Start(current_file_size - 512)).is_ok()
                    && file.read_exact(&mut tail).is_ok()
                    && shared::format_detection::detect_vhd_footer(&tail)
                        == shared::ImageFormat::Vhd
                {
                    shared::ImageFormat::Vhd
                } else {
                    by_header
                }
            } else {
                by_header
            }
        }
    };

    let (format_code, current_virtual_size, qcow2_extended_l2) = match detected {
        shared::ImageFormat::Raw => (IMAGE_FORMAT_RAW, current_file_size, false),
        shared::ImageFormat::Qcow2 => {
            let header = qcow2::QcowHeader::parse(&buf).ok_or("resize: invalid qcow2 header")?;
            // Defensive guard against silent backing-chain
            // orphaning. The qcow2 grow / shrink planners do not
            // thread the existing backing reference through to
            // `build_header`, so a resize would rewrite the
            // header with `backing_file_offset = 0` and the
            // overlay would lose its parent. Reject up-front
            // pending a follow-up phase that plumbs the backing
            // bytes + format through `ResizeConfig`. Mirrors
            // VHDX's `has_parent` rejection.
            if header.backing_file_offset != 0 || header.backing_file_size != 0 {
                return Err("resize: qcow2 images with a backing file are not yet \
                     supported (resize would orphan the backing reference); \
                     resize the base image directly or flatten via \
                     `instar convert` first"
                    .into());
            }
            (IMAGE_FORMAT_QCOW2, header.virtual_size, header.extended_l2)
        }
        shared::ImageFormat::Vmdk4 | shared::ImageFormat::Vmdk3 => {
            let header = vmdk::Vmdk4Header::parse(&buf).ok_or("resize: invalid vmdk header")?;
            (IMAGE_FORMAT_VMDK4, header.virtual_size, false)
        }
        shared::ImageFormat::Vhd => {
            // VHD footer lives at file end (last 512 bytes).
            if current_file_size < 512 {
                return Err("resize: file too small to contain a vhd footer".into());
            }
            file.seek(SeekFrom::Start(current_file_size - 512))?;
            let mut footer = [0u8; 512];
            file.read_exact(&mut footer)?;
            let parsed = vhd::VhdFooter::parse(&footer).ok_or("resize: invalid vhd footer")?;
            (IMAGE_FORMAT_VHD, parsed.current_size, false)
        }
        shared::ImageFormat::Vhdx => {
            // VHDX VirtualDiskSize lives in the metadata region;
            // walk header → region table → metadata to find it.
            let vds = probe_vhdx_virtual_size(&mut file, current_file_size)?;
            (IMAGE_FORMAT_VHDX, vds, false)
        }
        other => {
            return Err(format!(
                "resize: format {:?} is not supported for in-place resize",
                other
            )
            .into())
        }
    };
    Ok(ProbedResizeTarget {
        format: format_code,
        current_virtual_size,
        current_file_size,
        qcow2_extended_l2,
    })
}

/// Read the VHDX `VirtualDiskSize` metadata field by walking
/// the active header → region table → metadata layout.  This is
/// the host-side mirror of what the guest does during the
/// vhdx pre-pass — the host only needs the size, so we read
/// the minimum necessary regions.
fn probe_vhdx_virtual_size(
    file: &mut std::fs::File,
    current_file_size: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    use std::io::{Read, Seek, SeekFrom};
    if current_file_size < 0x40000 + 64 * 1024 {
        return Err("resize: file too small for vhdx layout".into());
    }
    // Read both headers (4 KiB each), pick the higher-seq one.
    let mut header1 = [0u8; 4096];
    file.seek(SeekFrom::Start(0x10000))?;
    file.read_exact(&mut header1)?;
    let mut header2 = [0u8; 4096];
    file.seek(SeekFrom::Start(0x20000))?;
    file.read_exact(&mut header2)?;
    let h1 = vhdx::VhdxHeader::parse(&header1);
    let h2 = vhdx::VhdxHeader::parse(&header2);
    let _active_seq = match (h1, h2) {
        (Some(a), Some(b)) => a.sequence_number.max(b.sequence_number),
        (Some(a), None) => a.sequence_number,
        (None, Some(b)) => b.sequence_number,
        (None, None) => return Err("resize: vhdx headers both invalid".into()),
    };
    // Read region table copy 1 (64 KiB at 0x30000).
    let mut rt = vec![0u8; 64 * 1024];
    file.seek(SeekFrom::Start(0x30000))?;
    file.read_exact(&mut rt)?;
    let (entries, _count) =
        vhdx::parse_region_table(&rt).ok_or("resize: vhdx region table invalid")?;
    // entries[1] is the metadata region per the create-crate
    // layout convention.
    let metadata = &entries[1];
    let mut meta = vec![0u8; metadata.length as usize];
    file.seek(SeekFrom::Start(metadata.file_offset))?;
    file.read_exact(&mut meta)?;
    // VirtualDiskSize lives at relative offset 0x10008 in the
    // metadata region as a u64 LE.
    if meta.len() < 0x10008 + 8 {
        return Err("resize: vhdx metadata too short".into());
    }
    let vds = shared::le_u64(&meta, 0x10008);
    Ok(vds)
}

/// Host-side raw resize: `set_len` to the new size, optional
/// `falloc`/`full` post-pass over the newly-added region, and
/// `sync_all`.
///
/// `metadata` is rejected for raw — there is no metadata to
/// preallocate.  `falloc`/`full` combined with shrink is rejected
/// as nonsensical (you can't preallocate space you're discarding).
fn run_resize_raw(
    args: &ResizeArgs,
    probed: &ProbedResizeTarget,
    new_virtual_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mode = args.preallocation.as_str();
    if mode == "metadata" {
        return Err("resize: --preallocation=metadata is not supported for raw".into());
    }
    if matches!(mode, "falloc" | "full") && new_virtual_size < probed.current_virtual_size {
        return Err(format!("resize: --preallocation={mode} is meaningless when shrinking").into());
    }
    if new_virtual_size < probed.current_virtual_size && !args.shrink {
        return Err(format!(
            "resize: shrinking from {} to {} bytes requires --shrink",
            probed.current_virtual_size, new_virtual_size
        )
        .into());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.filename)?;
    file.set_len(new_virtual_size)?;
    if new_virtual_size > probed.current_virtual_size {
        let added = new_virtual_size - probed.current_virtual_size;
        apply_preallocation(&file, "resize", mode, probed.current_virtual_size, added)?;
    }
    file.sync_all()?;

    let action = action_str(probed.current_virtual_size, new_virtual_size);
    render_resize_success(
        args,
        probed.format,
        probed.current_virtual_size,
        new_virtual_size,
        new_virtual_size,
        action,
    );
    Ok(())
}

fn action_str(old: u64, new: u64) -> &'static str {
    if new > old {
        "grow"
    } else if new < old {
        "shrink"
    } else {
        "noop"
    }
}

/// Map an `IMAGE_FORMAT_*` constant to its qemu-img-canonical
/// name (the same names the create / measure subcommands accept
/// on the CLI).
fn image_format_name(code: u32) -> &'static str {
    match code {
        IMAGE_FORMAT_RAW => "raw",
        IMAGE_FORMAT_QCOW2 => "qcow2",
        IMAGE_FORMAT_VMDK4 | IMAGE_FORMAT_VMDK3 => "vmdk",
        IMAGE_FORMAT_VHD => "vpc",
        IMAGE_FORMAT_VHDX => "vhdx",
        _ => "unknown",
    }
}

/// Render a success line.  Human form matches qemu's
/// `"Image resized."` byte-for-byte; JSON form emits a
/// structured envelope.
fn render_resize_success(
    args: &ResizeArgs,
    format: u32,
    old_size: u64,
    new_virtual_size: u64,
    new_file_size: u64,
    action: &'static str,
) {
    if args.quiet {
        return;
    }
    if args.output == "json" {
        println!(
            "{{\n  \"filename\": \"{}\",\n  \"format\": \"{}\",\n  \
             \"action\": \"{}\",\n  \"old_virtual_size\": {},\n  \
             \"new_virtual_size\": {},\n  \"new_file_size\": {}\n}}",
            json_escape_string(&args.filename),
            image_format_name(format),
            action,
            old_size,
            new_virtual_size,
            new_file_size,
        );
    } else {
        println!("Image resized.");
    }
}

/// Map a `ResizeResult::ERROR_*` code to a user-facing string.
fn map_resize_error(code: u32) -> String {
    match code {
        RESIZE_RESULT_ERROR_OK => "ok".into(),
        RESIZE_RESULT_ERROR_INVALID_OPTION => "invalid resize option".into(),
        RESIZE_RESULT_ERROR_INVALID_NEW_SIZE => "invalid new size".into(),
        RESIZE_RESULT_ERROR_SHRINK_WITHOUT_FLAG => {
            "shrinking requires --shrink (would discard data above the new size)".into()
        }
        RESIZE_RESULT_ERROR_SHRINK_BELOW_ALLOCATED => {
            "shrink rejected: allocated data lives above the new size".into()
        }
        RESIZE_RESULT_ERROR_UNSUPPORTED_FORMAT => "format does not support resize".into(),
        RESIZE_RESULT_ERROR_UNSUPPORTED_SUBFORMAT => "subformat does not support resize".into(),
        RESIZE_RESULT_ERROR_UNSUPPORTED_SHRINK => "shrink not yet supported for this format".into(),
        RESIZE_RESULT_ERROR_PREALLOCATION_UNSUPPORTED => {
            "preallocation mode not supported by this format".into()
        }
        RESIZE_RESULT_ERROR_SCRATCH_TOO_SMALL => {
            "image too large for the resize scratch buffer".into()
        }
        RESIZE_RESULT_ERROR_READ_FAILED => "I/O error reading the image".into(),
        RESIZE_RESULT_ERROR_WRITE_FAILED => "I/O error writing the image".into(),
        RESIZE_RESULT_ERROR_PARSE_FAILED => "the image header could not be parsed".into(),
        RESIZE_RESULT_ERROR_HEADER_MISMATCH => {
            "the image's metadata is internally inconsistent or \
             changed between the host's pre-probe and the guest's \
             read (concurrent modification, a pathological image, \
             or a planner accounting bug); retry the operation, or \
             run `instar check` if the image may be corrupt"
                .into()
        }
        _ => format!("unknown resize error code {code}"),
    }
}

/// Render a success line for `instar rebase`. Human form
/// matches qemu's `"Image rebased."` byte-for-byte (or
/// `"Image detached."` for a detach); JSON form emits a
/// structured envelope.
fn render_rebase_success(
    args: &RebaseArgs,
    overlay_format: u32,
    mode: u32,
    clusters_copied: u64,
    bytes_copied: u64,
) {
    if args.quiet {
        return;
    }
    let mode_str = if mode == shared::RebaseResult::MODE_SAFE {
        "safe"
    } else {
        "unsafe"
    };
    let is_detach = args.backing.is_empty();
    if args.output == "json" {
        if is_detach {
            println!(
                "{{\n  \"overlay\": \"{}\",\n  \"overlay_format\": \"{}\",\n  \
                 \"mode\": \"{}\",\n  \"clusters_copied\": {},\n  \
                 \"bytes_copied\": {},\n  \"detached\": true\n}}",
                json_escape_string(&args.filename),
                image_format_name(overlay_format),
                mode_str,
                clusters_copied,
                bytes_copied,
            );
        } else {
            println!(
                "{{\n  \"overlay\": \"{}\",\n  \"overlay_format\": \"{}\",\n  \
                 \"mode\": \"{}\",\n  \"clusters_copied\": {},\n  \
                 \"bytes_copied\": {},\n  \"new_backing\": \"{}\"\n}}",
                json_escape_string(&args.filename),
                image_format_name(overlay_format),
                mode_str,
                clusters_copied,
                bytes_copied,
                json_escape_string(&args.backing),
            );
        }
    } else if is_detach {
        println!("Image detached.");
    } else {
        println!("Image rebased.");
    }
}

/// Map a `RebaseResult::ERROR_*` code to a user-facing
/// string. Exhaustive on the constants from
/// `src/shared/src/lib.rs` (0..=13); the trailing catch-all
/// covers future code additions only.
fn map_rebase_error(code: u32) -> String {
    match code {
        c if c == shared::RebaseResult::ERROR_OK => "ok".into(),
        c if c == shared::RebaseResult::ERROR_UNSUPPORTED_FORMAT => {
            "format does not support rebase in this mode (qcow2 and vmdk only; \
             safe mode for qcow2 only; vmdk safe mode not yet supported -- try -u)"
                .into()
        }
        c if c == shared::RebaseResult::ERROR_NEW_BACKING_INCOMPATIBLE => {
            "new backing is incompatible with the overlay (virtual size too small \
             or format unsupported)"
                .into()
        }
        c if c == shared::RebaseResult::ERROR_EXTERNAL_DATA_FILE => {
            "qcow2 overlays with the external-data-file feature cannot be rebased".into()
        }
        c if c == shared::RebaseResult::ERROR_LUKS_UNSUPPORTED => {
            "LUKS-encrypted overlays and backings are not yet supported for rebase".into()
        }
        c if c == shared::RebaseResult::ERROR_CHAIN_DEPTH => {
            "the combined old and new backing chains exceed the maximum depth".into()
        }
        c if c == shared::RebaseResult::ERROR_HEADER_MISMATCH => {
            "the overlay's header changed during rebase, or a guest write failed; \
             retry, or run `instar check` if the image may be corrupt"
                .into()
        }
        c if c == shared::RebaseResult::ERROR_OVERLAY_CORRUPT => {
            "the overlay is marked dirty or corrupt; run `instar check` first".into()
        }
        c if c == shared::RebaseResult::ERROR_BACKING_PATH_TOO_LONG => {
            "the new backing path is longer than the overlay's existing slot, and \
             long-path relocation is not yet supported in this release"
                .into()
        }
        c if c == shared::RebaseResult::ERROR_SCRATCH_TOO_SMALL => {
            "the overlay is too large for the rebase scratch buffer".into()
        }
        c if c == shared::RebaseResult::ERROR_REFCOUNT_EXHAUSTED => {
            "the overlay's refcount blocks are full; v1 doesn't append new ones. \
             Fall back to -u or use `qemu-img rebase`"
                .into()
        }
        c if c == shared::RebaseResult::ERROR_DESCRIPTOR_TOO_LARGE => {
            "the vmdk descriptor slot is too small for the new backing reference".into()
        }
        c if c == shared::RebaseResult::ERROR_PARSE_FAILED => {
            "the overlay's header could not be parsed".into()
        }
        c if c == shared::RebaseResult::ERROR_INTERNAL_OVERFLOW => {
            "internal size or offset computation overflowed (host or guest bug)".into()
        }
        _ => format!("unknown rebase error code {code}"),
    }
}

/// Render a success line for `instar commit`. Human form
/// matches qemu's `"Image committed."` byte-for-byte; JSON
/// form emits a structured envelope. `--quiet` suppresses
/// the success line; errors still go to stderr.
fn render_commit_success(
    args: &CommitArgs,
    backing_path: &str,
    overlay_format: u32,
    backing_format: u32,
    clusters_committed: u64,
    bytes_committed: u64,
    overlay_clusters_cleared: u64,
) {
    if args.quiet {
        return;
    }
    if args.output == "json" {
        println!(
            "{{\n  \"overlay\": \"{}\",\n  \"overlay_format\": \"{}\",\n  \
             \"backing\": \"{}\",\n  \"backing_format\": \"{}\",\n  \
             \"clusters_committed\": {},\n  \"bytes_committed\": {},\n  \
             \"overlay_clusters_cleared\": {}\n}}",
            json_escape_string(&args.filename),
            image_format_name(overlay_format),
            json_escape_string(backing_path),
            image_format_name(backing_format),
            clusters_committed,
            bytes_committed,
            overlay_clusters_cleared,
        );
    } else {
        println!("Image committed.");
    }
}

/// Map a `CommitResult::ERROR_*` code to a user-facing string.
/// Exhaustive on the 14 constants from
/// `src/shared/src/lib.rs` (0..=13); the trailing catch-all
/// covers future code additions only.
fn map_commit_error(code: u32) -> String {
    match code {
        c if c == shared::CommitResult::ERROR_OK => "ok".into(),
        c if c == shared::CommitResult::ERROR_UNSUPPORTED_FORMAT => {
            "format does not support commit (qcow2 and vmdk only; commit between \
             mismatched formats or cluster sizes is not yet supported)"
                .into()
        }
        c if c == shared::CommitResult::ERROR_NO_BACKING => {
            "the overlay has no recorded backing file; pass -b to name one".into()
        }
        c if c == shared::CommitResult::ERROR_EXTERNAL_DATA_FILE => {
            "qcow2 overlays with the external-data-file feature cannot be committed".into()
        }
        c if c == shared::CommitResult::ERROR_LUKS_UNSUPPORTED => {
            "LUKS-encrypted overlays and backings are not yet supported for commit".into()
        }
        c if c == shared::CommitResult::ERROR_BACKING_TOO_SMALL => {
            "the backing file is smaller than the overlay; cannot commit".into()
        }
        c if c == shared::CommitResult::ERROR_OVERLAY_LARGER_THAN_BACKING => {
            "the overlay's virtual size exceeds the backing's virtual size".into()
        }
        c if c == shared::CommitResult::ERROR_HEADER_MISMATCH => {
            "the overlay or backing header changed during commit, or a guest write \
             failed; retry, or run `instar check` if the image may be corrupt"
                .into()
        }
        c if c == shared::CommitResult::ERROR_OVERLAY_CORRUPT => {
            "the overlay is marked dirty or corrupt; run `instar check` first".into()
        }
        c if c == shared::CommitResult::ERROR_BACKING_CORRUPT => {
            "the backing is marked dirty or corrupt; run `instar check` first".into()
        }
        c if c == shared::CommitResult::ERROR_SCRATCH_TOO_SMALL => {
            "the overlay or backing is too large for the commit scratch buffer".into()
        }
        c if c == shared::CommitResult::ERROR_REFCOUNT_EXHAUSTED => {
            "the backing's refcount blocks are full; v1 doesn't append new ones. \
             Fall back to `qemu-img commit`"
                .into()
        }
        c if c == shared::CommitResult::ERROR_PARSE_FAILED => {
            "the overlay or backing header could not be parsed".into()
        }
        c if c == shared::CommitResult::ERROR_INTERNAL_OVERFLOW => {
            "internal size or offset computation overflowed (host or guest bug)".into()
        }
        _ => format!("unknown commit error code {code}"),
    }
}

/// Host-side mirror of `ResizeResult` populated by the guest
/// dispatch.
struct ResizeRunResult {
    resolved_new_virtual_size: u64,
    file_size_before: u64,
    file_size_after: u64,
    action: u32,
    error: u32,
}

/// Run the resize guest for any non-raw format.  Opens the
/// output file `O_RDWR` (no truncate), launches the guest,
/// receives the `ResizeResultMessage`, then post-passes
/// `set_len(file_size_after)` to commit the planner's reported
/// EOF.
fn run_resize_nonraw(
    args: &ResizeArgs,
    probed: &ProbedResizeTarget,
    new_virtual_size: u64,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mode = args.preallocation.as_str();
    if matches!(mode, "falloc" | "full") && new_virtual_size < probed.current_virtual_size {
        return Err(format!("resize: --preallocation={mode} is meaningless when shrinking").into());
    }
    let core_path = get_binary_path("core.bin");
    let core_code = load_guest_binary(
        core_path
            .to_str()
            .ok_or("resize: core.bin path is not valid UTF-8")?,
    )?;
    let resize_path = get_binary_path("resize.bin");
    let resize_code = load_guest_binary(
        resize_path
            .to_str()
            .ok_or("resize: resize.bin path is not valid UTF-8")?,
    )?;

    // Expose a generous capacity hint to virtio so the guest
    // can append BAT / L1 / refcount regions past the
    // pre-resize EOF.  The planner upper-bound is governed by
    // the worst-case extension; double the larger of the two
    // sizes is comfortably above it.
    let capacity_hint = probed
        .current_file_size
        .max(new_virtual_size)
        .saturating_mul(2)
        .max(1 << 30);
    let output =
        backing::BackingStore::open_rw_existing(Path::new(&args.filename), Some(capacity_hint))?;

    let mut flags: u32 = 0;
    if args.shrink {
        flags |= RESIZE_CONFIG_FLAG_SHRINK;
    }
    if args.quiet {
        flags |= RESIZE_CONFIG_FLAG_QUIET;
    }
    if probed.qcow2_extended_l2 {
        flags |= RESIZE_CONFIG_FLAG_EXTENDED_L2;
    }
    flags |= match mode {
        "metadata" => RESIZE_CONFIG_PREALLOC_METADATA,
        "falloc" => RESIZE_CONFIG_PREALLOC_FALLOC,
        "full" => RESIZE_CONFIG_PREALLOC_FULL,
        _ => 0, // PREALLOC_OFF
    };

    let result = run_resize_guest(
        &core_code,
        &resize_code,
        probed.format,
        flags,
        probed.current_virtual_size,
        new_virtual_size,
        probed.current_file_size,
        output,
        capacity_hint,
        verbose,
    )?;
    if result.error != RESIZE_RESULT_ERROR_OK {
        return Err(format!(
            "resize: guest reported error {}: {}",
            result.error,
            map_resize_error(result.error)
        )
        .into());
    }

    // Defence in depth: clamp the guest-reported `file_size_after`
    // against the capacity hint we exposed via virtio. The guest is
    // on the user's side of the trust boundary, but a buggy planner
    // (or a fuzzer reaching an Ok path with corrupt outputs) could
    // return an out-of-range value; the SAFETY comment on
    // `apply_preallocation` claims its `data_len` is caller-clamped,
    // and that claim is enforced here.
    if result.file_size_after > capacity_hint {
        return Err(format!(
            "resize: guest reported file_size_after {} exceeds capacity hint \
             {} — refusing to truncate beyond the exposed device range",
            result.file_size_after, capacity_hint,
        )
        .into());
    }

    // Post-pass set_len: commit the planner's reported EOF.
    // Open read+write (not write-only) so apply_preallocation can
    // call posix_fallocate / fallocate(FALLOC_FL_ZERO_RANGE) on
    // the fd; those syscalls require the fd to be writable but
    // some kernels are picky about O_WRONLY for fallocate.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.filename)?;
    // Phase 9: post-pass the newly-appended file region only.
    // This is a deliberate divergence from qemu, which
    // preallocates the entire data-region span for the new
    // virtual size; see docs/quirks.md.  Bytes in
    // [file_size_before, file_size_after) are the physical
    // appended region the planner wrote past the pre-resize EOF.
    if matches!(mode, "falloc" | "full") && result.file_size_after > result.file_size_before {
        let added = result.file_size_after - result.file_size_before;
        apply_preallocation(&file, "resize", mode, result.file_size_before, added)?;
    }
    file.set_len(result.file_size_after)?;
    file.sync_all()?;

    let action_str = match result.action {
        RESIZE_RESULT_ACTION_GROW => "grow",
        RESIZE_RESULT_ACTION_SHRINK => "shrink",
        _ => "noop",
    };
    render_resize_success(
        args,
        probed.format,
        result.file_size_before,
        result.resolved_new_virtual_size,
        result.file_size_after,
        action_str,
    );
    Ok(())
}

/// Launch the resize guest binary, wait for the
/// `ResizeResultMessage`.  Modelled on `run_create_guest` but
/// with one output device (no input device) and the resize
/// payload variant.
#[allow(clippy::too_many_arguments)]
fn run_resize_guest(
    core_code: &[u8],
    operation_code: &[u8],
    target_format: u32,
    flags: u32,
    current_virtual_size: u64,
    new_virtual_size: u64,
    current_file_size: u64,
    output_backing: backing::BackingStore,
    output_capacity_hint: u64,
    verbose: bool,
) -> Result<ResizeRunResult, Box<dyn std::error::Error>> {
    // --- KVM / VM / guest memory setup ----------------------------------
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid
    // GuestMemoryMmap allocation that outlives the VM.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    setup_gdt(&guest_mem)?;
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    guest_mem.write_slice(core_code, GuestAddress(GUEST_CODE_BASE))?;
    guest_mem.write_slice(operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;

    // --- Write ResizeConfig at OPERATION_CONFIG_ADDR --------------------
    // Layout (must match shared::ResizeConfig exactly):
    //    0: magic                u32  ("RESI")
    //    4: target_format        u32
    //    8: flags                u32
    //   12: sector_size          u32
    //   16: current_virtual_size u64
    //   24: new_virtual_size     u64
    //   32: qcow2_cluster_size   u32  (0 = let guest re-read header)
    //   36: qcow2_refcount_bits  u8
    //   37: vmdk_subformat       u8
    //   38: vhd_subformat        u8
    //   39: _pad                 u8
    //   40: vmdk_grain_size      u32
    //   44: block_size           u32
    //   48: current_file_size    u64
    //   56: _reserved            [u8; 56]
    let sector_size: u32 = 512;
    guest_mem.write_obj(RESIZE_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(target_format, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(flags, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(sector_size, GuestAddress(OPERATION_CONFIG_ADDR + 12))?;
    guest_mem.write_obj(
        current_virtual_size,
        GuestAddress(OPERATION_CONFIG_ADDR + 16),
    )?;
    guest_mem.write_obj(new_virtual_size, GuestAddress(OPERATION_CONFIG_ADDR + 24))?;
    // qcow2_cluster_size / refcount_bits / vmdk_subformat / vhd_subformat /
    // _pad / vmdk_grain_size / block_size are left zero — the guest
    // re-reads the canonical values from the existing image header.
    guest_mem.write_obj(current_file_size, GuestAddress(OPERATION_CONFIG_ADDR + 48))?;
    // _reserved at offset 56 stays zero from the page-zeroed memory.

    debug!(
        "Wrote resize config at 0x{:x} (target={}, flags=0x{:x}, current_virtual_size={}, \
         new_virtual_size={}, current_file_size={})",
        OPERATION_CONFIG_ADDR,
        target_format,
        flags,
        current_virtual_size,
        new_virtual_size,
        current_file_size,
    );

    // --- Set up devices --------------------------------------------------
    // The guest core unconditionally probes input device 0
    // (see core/src/main.rs::_start), so even though resize
    // has no logical input we attach a 1-sector stub at slot 0
    // and place the real (read-write) output at slot 1.  The
    // resize guest reads via `read_output_sector` and writes
    // via `write_output_sector`, both of which dispatch to
    // slot 1.  The stub is never read.  Mirrors the pattern
    // in `run_create_nonraw`.
    struct ResizeStubInput(std::path::PathBuf);
    impl Drop for ResizeStubInput {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stub_path = std::env::temp_dir().join(format!("instar-resize-stub-{pid}-{nanos}"));
    let stub_file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&stub_path)?;
    stub_file.set_len(sector_size as u64)?;
    drop(stub_file);
    let _stub_input = ResizeStubInput(stub_path.clone());
    let input_backing = backing::BackingStore::open(&stub_path, true, None, false)?;

    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    let input_mmio = device_mmio_base(0);
    let input_vq = device_vq_base(0);
    let input_device = VirtioBlockDevice::new(
        input_backing,
        sector_size as u64,
        sector_size as u64,
        true, // read-only
        input_mmio,
        input_vq,
    );
    let input_device = Arc::new(Mutex::new(input_device));
    device_set.add_device(Arc::clone(&input_device), true);
    io_events.push(IoEvent::new(input_mmio)?);

    let output_mmio = device_mmio_base(1);
    let output_vq = device_vq_base(1);
    let output_device = VirtioBlockDevice::new(
        output_backing,
        output_capacity_hint,
        sector_size as u64,
        false, // writable
        output_mmio,
        output_vq,
    );
    let output_device = Arc::new(Mutex::new(output_device));
    device_set.add_device(Arc::clone(&output_device), false);
    io_events.push(IoEvent::new(output_mmio)?);

    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Try to register ioeventfds; fall back to VM exits on failure.
    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }
    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            let _ = evt.unregister(&vm);
        }
    }
    let all_registered = !registration_failed;
    if all_registered && !io_events.is_empty() {
        let io_devices = device_set.create_io_devices(io_events);
        io_thread = Some(io_thread::IoThread::new(
            io_devices,
            Arc::clone(&guest_mem),
            Arc::clone(&vmm_stats),
        ));
    }

    // --- vCPU setup ------------------------------------------------------
    let mut vcpu = vm.create_vcpu(0)?;
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;

    // --- Serial decoders / transmitter / debug buffer -------------------
    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();

    // 0 inputs + 1 output; progress reporting suppressed (resize
    // patches are few and complete near-instantly).
    let config = vmm_config(sector_size, sector_size, 100);
    serial_transmitter.queue_config(&config);

    // --- Run the vCPU loop ----------------------------------------------
    let mut result_seen = false;
    let mut harvested = ResizeRunResult {
        resolved_new_virtual_size: 0,
        file_size_before: 0,
        file_size_after: 0,
        action: RESIZE_RESULT_ACTION_NOOP,
        error: RESIZE_RESULT_ERROR_OK,
    };
    let mut vm_error: Option<String> = None;

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            if let Some(guest_::GuestMessage_::Payload::ResizeResult(r)) =
                                &msg.payload
                            {
                                harvested.resolved_new_virtual_size = r.resolved_new_virtual_size;
                                harvested.file_size_before = r.file_size_before;
                                harvested.file_size_after = r.file_size_after;
                                harvested.action = match r.action.as_str() {
                                    "grow" => RESIZE_RESULT_ACTION_GROW,
                                    "shrink" => RESIZE_RESULT_ACTION_SHRINK,
                                    _ => RESIZE_RESULT_ACTION_NOOP,
                                };
                                harvested.error = r.error;
                                result_seen = true;
                            } else if verbose {
                                debug!("{}", format_message(&msg));
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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
    if !result_seen {
        return Err("resize: guest did not return a result".into());
    }
    Ok(harvested)
}

/// Snapshot of what the host probed from the qcow2 target file
/// before launching the amend guest. Mirrors
/// `ProbedResizeTarget`; the fields populate `AmendConfig`'s
/// cross-check summary so the guest can re-validate its own
/// re-read of the header.
struct ProbedAmendTarget {
    /// qcow2 cluster size in bytes (header-cluster span).
    cluster_size: u32,
    /// Current qcow2 version (2 or 3).
    current_version: u32,
    /// Current refcount width in bits.
    current_refcount_bits: u32,
    /// Current incompatible feature word.
    current_incompatible_features: u64,
    /// Current compatible feature word.
    current_compatible_features: u64,
    /// Virtual disk size in bytes.
    virtual_size: u64,
}

/// Probe the amend target's format and header summary. Honours
/// `-f qcow2` if given; otherwise auto-detects via
/// `detect_format_from_header`. Amend is qcow2-only: any other
/// forced or detected format is rejected here, before a VM
/// launch. Mirrors `probe_resize_target`.
fn probe_amend_target(
    path: &Path,
    forced_format: Option<&str>,
) -> Result<ProbedAmendTarget, Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut file = std::fs::OpenOptions::new().read(true).open(path)?;

    // Read the first 4 KiB; covers the qcow2 sector-0 header.
    let mut buf = vec![0u8; 4096];
    let read = file.read(&mut buf)?;
    buf.truncate(read);

    let detected = match forced_format {
        Some("qcow2") => shared::ImageFormat::Qcow2,
        Some(_) => return Err("amend: only qcow2 images can be amended".into()),
        None => shared::format_detection::detect_format_from_header(&buf, buf.len(), false),
    };
    if detected != shared::ImageFormat::Qcow2 {
        return Err("amend: only qcow2 images can be amended".into());
    }

    let header = qcow2::QcowHeader::parse(&buf).ok_or("amend: invalid qcow2 header")?;
    Ok(ProbedAmendTarget {
        cluster_size: header.cluster_size as u32,
        current_version: header.version,
        current_refcount_bits: header.refcount_bits,
        current_incompatible_features: header.incompatible_features,
        current_compatible_features: header.compatible_features,
        virtual_size: header.virtual_size,
    })
}

/// Handler for `instar amend`. The host is thin: it parses `-o`,
/// probes the qcow2 header for the cross-check summary, builds
/// the flag set, launches the guest (which owns all the refusal /
/// downgrade / no-op logic), maps any guest error to a message,
/// fsyncs on a successful rewrite, and renders. Mirrors
/// `run_resize` / `run_resize_nonraw`.
fn run_amend(args: AmendArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let opts = parse_amend_o_options(&args.option)?;
    let probed = probe_amend_target(Path::new(&args.filename), args.format.as_deref())?;

    // Build the flag set from the parsed options + -q.
    let mut flags: u32 = 0;
    if let Some(v3) = opts.compat_v3 {
        flags |= shared::AmendConfig::FLAG_SET_COMPAT;
        if v3 {
            flags |= shared::AmendConfig::FLAG_COMPAT_V3;
        }
    }
    if let Some(on) = opts.lazy_on {
        flags |= shared::AmendConfig::FLAG_SET_LAZY;
        if on {
            flags |= shared::AmendConfig::FLAG_LAZY_ON;
        }
    }
    if args.quiet {
        flags |= shared::AmendConfig::FLAG_QUIET;
    }

    // Load the core + amend guest binaries.
    let core_path = get_binary_path("core.bin");
    let core_code = load_guest_binary(
        core_path
            .to_str()
            .ok_or("amend: core.bin path is not valid UTF-8")?,
    )?;
    let amend_path = get_binary_path("amend.bin");
    let amend_code = load_guest_binary(
        amend_path
            .to_str()
            .ok_or("amend: amend.bin path is not valid UTF-8")?,
    )?;

    // Open the target file O_RDWR as the output device. Amend
    // only rewrites the header cluster, so the existing file
    // size is the device capacity (no append past EOF). The virtio
    // capacity hint is expressed in BYTES (the device divides by
    // its sector size to advertise a sector count), matching the
    // resize/rebase convention.
    let current_file_size = std::fs::metadata(&args.filename)?.len();
    let output_capacity_hint = current_file_size;
    let output = backing::BackingStore::open_rw_existing(
        Path::new(&args.filename),
        Some(output_capacity_hint),
    )?;

    let result = run_amend_guest(
        &core_code,
        &amend_code,
        IMAGE_FORMAT_QCOW2,
        flags,
        probed.cluster_size,
        probed.current_version,
        probed.current_refcount_bits,
        probed.current_incompatible_features,
        probed.current_compatible_features,
        probed.virtual_size,
        output,
        output_capacity_hint,
        verbose,
    )?;

    if result.error != shared::AmendResult::ERROR_OK {
        return Err(format!("amend: {}", map_amend_error(result.error)).into());
    }

    // Durability fsync: a successful rewrite touched the header
    // cluster. Re-open read+write and `sync_all()` (resize's
    // pattern) so the change is on stable storage before we
    // report success. A NoOp wrote nothing, so no fsync.
    if result.action == shared::AmendResult::ACTION_AMENDED {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&args.filename)?;
        file.sync_all()?;
    }

    render_amend_success(
        &args,
        result.target_format,
        result.action,
        result.resulting_version,
        result.resulting_lazy_refcounts,
    );
    Ok(())
}

/// Map an `AmendResult::ERROR_*` code to a user-facing string.
/// Exhaustive on the constants from `src/shared/src/lib.rs`
/// (0..=12); the trailing catch-all covers future additions only.
fn map_amend_error(code: u32) -> &'static str {
    match code {
        c if c == shared::AmendResult::ERROR_OK => "ok",
        c if c == shared::AmendResult::ERROR_UNSUPPORTED_FORMAT => {
            "only qcow2 images can be amended"
        }
        c if c == shared::AmendResult::ERROR_INVALID_OPTION => {
            "an unsupported -o option reached the guest (amend changes \
             compat and lazy_refcounts only)"
        }
        c if c == shared::AmendResult::ERROR_DOWNGRADE_BLOCKED_FEATURE => {
            "cannot downgrade to compat=0.10: image uses a v3-only \
             incompatible feature (compression, extended L2, external \
             data, or is dirty/corrupt)"
        }
        c if c == shared::AmendResult::ERROR_DOWNGRADE_REFCOUNT_WIDTH => {
            "cannot downgrade to compat=0.10: image uses refcount_bits != 16 \
             (v2 supports 16-bit refcounts only; rewriting the refcount tree \
             is out of scope)"
        }
        c if c == shared::AmendResult::ERROR_LAZY_REQUIRES_V3 => {
            "lazy_refcounts=on requires compat=1.1 (lazy refcounts are a \
             v3-only feature); upgrade with -o compat=1.1 first or in the \
             same invocation"
        }
        c if c == shared::AmendResult::ERROR_HEADER_MISMATCH => {
            "the image's header changed between the host's pre-probe and the \
             guest's read, or a guest write failed; retry, or run \
             `instar check` if the image may be corrupt"
        }
        c if c == shared::AmendResult::ERROR_PARSE_FAILED => "the image header could not be parsed",
        c if c == shared::AmendResult::ERROR_DIRTY => {
            "the image is marked dirty (another writer may hold it open); \
             run `instar check` first"
        }
        c if c == shared::AmendResult::ERROR_EXTENSION_RELOCATION_UNSUPPORTED => {
            "this compat change would have to relocate a header extension, \
             which is not yet supported; use `qemu-img amend`"
        }
        c if c == shared::AmendResult::ERROR_SCRATCH_TOO_SMALL => {
            "the image is too large for the amend scratch buffer"
        }
        c if c == shared::AmendResult::ERROR_WRITE_FAILED => "I/O error writing the image header",
        c if c == shared::AmendResult::ERROR_INTERNAL_OVERFLOW => {
            "internal size or offset computation overflowed (host or guest bug)"
        }
        _ => "unknown amend error code",
    }
}

/// Render a success line for `instar amend`. Human form prints
/// `"Image amended."` (or `"No change."` for a no-op); JSON
/// form emits a structured envelope. `--quiet` suppresses the
/// success line; errors still go to stderr. Mirrors
/// `render_resize_success`.
fn render_amend_success(
    args: &AmendArgs,
    target_format: u32,
    action: u32,
    resulting_version: u32,
    resulting_lazy_refcounts: u32,
) {
    if args.quiet {
        return;
    }
    let action_str = if action == shared::AmendResult::ACTION_AMENDED {
        "amended"
    } else {
        "noop"
    };
    let compat_str = if resulting_version == 3 {
        "1.1"
    } else {
        "0.10"
    };
    let lazy_str = if resulting_lazy_refcounts != 0 {
        "on"
    } else {
        "off"
    };
    if args.output == "json" {
        println!(
            "{{\n  \"filename\": \"{}\",\n  \"format\": \"{}\",\n  \
             \"action\": \"{}\",\n  \"compat\": \"{}\",\n  \
             \"lazy_refcounts\": \"{}\"\n}}",
            json_escape_string(&args.filename),
            image_format_name(target_format),
            action_str,
            compat_str,
            lazy_str,
        );
    } else if action == shared::AmendResult::ACTION_AMENDED {
        println!("Image amended.");
    } else {
        println!("No change.");
    }
}

/// Launch the amend guest binary, wait for the
/// `AmendResultMessage`. Modelled on `run_resize_guest`: one
/// 1-sector stub input at slot 0 (the core unconditionally
/// probes input device 0) and the target file (opened O_RDWR)
/// as the output at slot 1. The amend guest reads via
/// `read_output_sector` and writes via `write_output_sector`,
/// both dispatching to slot 1.
#[allow(clippy::too_many_arguments)]
fn run_amend_guest(
    core_code: &[u8],
    operation_code: &[u8],
    target_format: u32,
    flags: u32,
    cluster_size: u32,
    current_version: u32,
    current_refcount_bits: u32,
    current_incompatible_features: u64,
    current_compatible_features: u64,
    virtual_size: u64,
    output_backing: backing::BackingStore,
    output_capacity_hint: u64,
    verbose: bool,
) -> Result<AmendRunResult, Box<dyn std::error::Error>> {
    // --- KVM / VM / guest memory setup ----------------------------------
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid
    // GuestMemoryMmap allocation that outlives the VM.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    setup_gdt(&guest_mem)?;
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    guest_mem.write_slice(core_code, GuestAddress(GUEST_CODE_BASE))?;
    guest_mem.write_slice(operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;

    // --- Write AmendConfig at OPERATION_CONFIG_ADDR ---------------------
    // Layout (must match shared::AmendConfig exactly):
    //    0: magic                         u32  ("AMND")
    //    4: target_format                 u32
    //    8: flags                         u32
    //   12: sector_size                   u32
    //   16: cluster_size                  u32
    //   20: current_version               u32
    //   24: current_refcount_bits         u32
    //   28: _pad                          u32
    //   32: current_incompatible_features u64
    //   40: current_compatible_features   u64
    //   48: virtual_size                  u64
    //   56: _reserved                     [u8; 72]
    let sector_size: u32 = 512;
    guest_mem.write_obj(
        shared::AmendConfig::MAGIC,
        GuestAddress(OPERATION_CONFIG_ADDR),
    )?;
    guest_mem.write_obj(target_format, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(flags, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(sector_size, GuestAddress(OPERATION_CONFIG_ADDR + 12))?;
    guest_mem.write_obj(cluster_size, GuestAddress(OPERATION_CONFIG_ADDR + 16))?;
    guest_mem.write_obj(current_version, GuestAddress(OPERATION_CONFIG_ADDR + 20))?;
    guest_mem.write_obj(
        current_refcount_bits,
        GuestAddress(OPERATION_CONFIG_ADDR + 24),
    )?;
    // _pad at offset 28 stays zero from the page-zeroed memory.
    guest_mem.write_obj(
        current_incompatible_features,
        GuestAddress(OPERATION_CONFIG_ADDR + 32),
    )?;
    guest_mem.write_obj(
        current_compatible_features,
        GuestAddress(OPERATION_CONFIG_ADDR + 40),
    )?;
    guest_mem.write_obj(virtual_size, GuestAddress(OPERATION_CONFIG_ADDR + 48))?;
    // _reserved at offset 56 stays zero from the page-zeroed memory.

    debug!(
        "Wrote amend config at 0x{:x} (target={}, flags=0x{:x}, cluster_size={}, \
         current_version={}, current_refcount_bits={}, incompat=0x{:x}, compat=0x{:x}, \
         virtual_size={})",
        OPERATION_CONFIG_ADDR,
        target_format,
        flags,
        cluster_size,
        current_version,
        current_refcount_bits,
        current_incompatible_features,
        current_compatible_features,
        virtual_size,
    );

    // --- Set up devices --------------------------------------------------
    // The guest core unconditionally probes input device 0
    // (see core/src/main.rs::_start), so even though amend has
    // no logical input we attach a 1-sector stub at slot 0 and
    // place the real (read-write) output at slot 1. The stub is
    // never read. Mirrors `run_resize_guest`.
    struct AmendStubInput(std::path::PathBuf);
    impl Drop for AmendStubInput {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stub_path = std::env::temp_dir().join(format!("instar-amend-stub-{pid}-{nanos}"));
    let stub_file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&stub_path)?;
    stub_file.set_len(sector_size as u64)?;
    drop(stub_file);
    let _stub_input = AmendStubInput(stub_path.clone());
    let input_backing = backing::BackingStore::open(&stub_path, true, None, false)?;

    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    let input_mmio = device_mmio_base(0);
    let input_vq = device_vq_base(0);
    let input_device = VirtioBlockDevice::new(
        input_backing,
        sector_size as u64,
        sector_size as u64,
        true, // read-only
        input_mmio,
        input_vq,
    );
    let input_device = Arc::new(Mutex::new(input_device));
    device_set.add_device(Arc::clone(&input_device), true);
    io_events.push(IoEvent::new(input_mmio)?);

    let output_mmio = device_mmio_base(1);
    let output_vq = device_vq_base(1);
    let output_device = VirtioBlockDevice::new(
        output_backing,
        output_capacity_hint,
        sector_size as u64,
        false, // writable
        output_mmio,
        output_vq,
    );
    let output_device = Arc::new(Mutex::new(output_device));
    device_set.add_device(Arc::clone(&output_device), false);
    io_events.push(IoEvent::new(output_mmio)?);

    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Try to register ioeventfds; fall back to VM exits on failure.
    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }
    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            let _ = evt.unregister(&vm);
        }
    }
    let all_registered = !registration_failed;
    if all_registered && !io_events.is_empty() {
        let io_devices = device_set.create_io_devices(io_events);
        io_thread = Some(io_thread::IoThread::new(
            io_devices,
            Arc::clone(&guest_mem),
            Arc::clone(&vmm_stats),
        ));
    }

    // --- vCPU setup ------------------------------------------------------
    let mut vcpu = vm.create_vcpu(0)?;
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;

    // --- Serial decoders / transmitter / debug buffer -------------------
    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();

    // 0 inputs + 1 output; progress reporting suppressed (amend
    // rewrites a single header cluster and completes instantly).
    let config = vmm_config(sector_size, sector_size, 100);
    serial_transmitter.queue_config(&config);

    // --- Run the vCPU loop ----------------------------------------------
    let mut result_seen = false;
    let mut harvested = AmendRunResult {
        target_format,
        action: shared::AmendResult::ACTION_NOOP,
        resulting_version: 0,
        resulting_lazy_refcounts: 0,
        error: shared::AmendResult::ERROR_OK,
    };
    let mut vm_error: Option<String> = None;

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            if let Some(guest_::GuestMessage_::Payload::AmendResult(a)) =
                                &msg.payload
                            {
                                // Harvest the numeric fields; the
                                // host already knows the format code
                                // it probed, so we keep `target_format`
                                // from the arg rather than parsing the
                                // echoed string.
                                harvested.action = a.action;
                                harvested.resulting_version = a.resulting_version;
                                harvested.resulting_lazy_refcounts = a.lazy_refcounts as u32;
                                harvested.error = a.error;
                                result_seen = true;
                            } else if verbose {
                                debug!("{}", format_message(&msg));
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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
    if !result_seen {
        return Err("amend: guest did not return a result".into());
    }
    Ok(harvested)
}

/// Launch the rebase guest binary, wait for the
/// `RebaseResultMessage`. Modelled on `run_resize_guest` but
/// with chain-of-inputs (old chain parents + new chain) + the
/// overlay attached as the output device.
#[allow(clippy::too_many_arguments)]
fn run_rebase_guest(
    core_code: &[u8],
    operation_code: &[u8],
    overlay_format: u32,
    new_backing_format: u32,
    flags: u32,
    sector_size: u32,
    overlay_cluster_size: u32,
    overlay_virtual_size: u64,
    new_backing_path: &[u8],
    output_backing: BackingStore,
    output_capacity_hint: u64,
    old_chain_parents: &BackingChain,
    new_chain: Option<&BackingChain>,
    old_chain_input_devices: usize,
    new_chain_input_devices: usize,
    verbose: bool,
) -> Result<RebaseRunResult, Box<dyn std::error::Error>> {
    // --- KVM / VM / guest memory setup ----------------------------------
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid
    // GuestMemoryMmap allocation that outlives the VM.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    setup_gdt(&guest_mem)?;
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    guest_mem.write_slice(core_code, GuestAddress(GUEST_CODE_BASE))?;
    guest_mem.write_slice(operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;

    // --- Write RebaseConfig at OPERATION_CONFIG_ADDR --------------------
    // Layout (must match shared::RebaseConfig exactly):
    //    0: magic                u32 ("REBA")
    //    4: overlay_format       u32
    //    8: new_backing_format   u32 (0 = guest auto-detect)
    //   12: flags                u32
    //   16: sector_size          u32
    //   20: overlay_cluster_size u32
    //   24: overlay_virtual_size u64
    //   32: old_chain_first      u32
    //   36: old_chain_count      u32
    //   40: new_chain_first      u32
    //   44: new_chain_count      u32
    //   48: new_backing_path     [u8; 1024]
    // 1072: new_backing_path_len u32
    // 1076: _reserved            [u8; 60]
    let old_chain_first = 0u32;
    let old_chain_count = old_chain_input_devices as u32;
    let new_chain_first = old_chain_count;
    let new_chain_count = new_chain_input_devices as u32;
    let path_len = new_backing_path.len();
    if path_len > 1024 {
        return Err(format!("rebase: backing path is {path_len} bytes; maximum is 1024").into());
    }

    guest_mem.write_obj(REBASE_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(overlay_format, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(new_backing_format, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(flags, GuestAddress(OPERATION_CONFIG_ADDR + 12))?;
    guest_mem.write_obj(sector_size, GuestAddress(OPERATION_CONFIG_ADDR + 16))?;
    guest_mem.write_obj(
        overlay_cluster_size,
        GuestAddress(OPERATION_CONFIG_ADDR + 20),
    )?;
    guest_mem.write_obj(
        overlay_virtual_size,
        GuestAddress(OPERATION_CONFIG_ADDR + 24),
    )?;
    guest_mem.write_obj(old_chain_first, GuestAddress(OPERATION_CONFIG_ADDR + 32))?;
    guest_mem.write_obj(old_chain_count, GuestAddress(OPERATION_CONFIG_ADDR + 36))?;
    guest_mem.write_obj(new_chain_first, GuestAddress(OPERATION_CONFIG_ADDR + 40))?;
    guest_mem.write_obj(new_chain_count, GuestAddress(OPERATION_CONFIG_ADDR + 44))?;
    if path_len > 0 {
        guest_mem.write_slice(new_backing_path, GuestAddress(OPERATION_CONFIG_ADDR + 48))?;
    }
    guest_mem.write_obj(
        path_len as u32,
        GuestAddress(OPERATION_CONFIG_ADDR + 48 + 1024),
    )?;
    // _reserved at offset 1076 stays zero from page-zeroed memory.

    debug!(
        "Wrote rebase config at 0x{:x} (overlay_format={}, flags=0x{:x}, \
         old_chain=[{}..+{}), new_chain=[{}..+{}), path_len={})",
        OPERATION_CONFIG_ADDR,
        overlay_format,
        flags,
        old_chain_first,
        old_chain_count,
        new_chain_first,
        new_chain_count,
        path_len,
    );

    // --- Set up devices --------------------------------------------------
    // Device layout (MMIO slot order):
    //   [0..old_chain_input_devices): old chain parents
    //   [old_chain_input_devices..total_inputs): new chain
    //   [total_inputs]: overlay (output, RW)
    //
    // If there are no inputs (detach with no parents and no new
    // chain) the core binary still unconditionally probes
    // input device 0 — attach a 1-sector stub at slot 0 just
    // like resize does, and place the output at slot 1.
    let total_input_devices = old_chain_input_devices + new_chain_input_devices;

    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    struct RebaseStubInput(std::path::PathBuf);
    impl Drop for RebaseStubInput {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _stub_input: Option<RebaseStubInput> = if total_input_devices == 0 {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stub_path = std::env::temp_dir().join(format!("instar-rebase-stub-{pid}-{nanos}"));
        let stub_file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&stub_path)?;
        stub_file.set_len(sector_size as u64)?;
        drop(stub_file);
        let stub = RebaseStubInput(stub_path.clone());
        let input_backing = BackingStore::open(&stub_path, true, None, false)?;
        let input_mmio = device_mmio_base(0);
        let input_vq = device_vq_base(0);
        let input_device = VirtioBlockDevice::new(
            input_backing,
            sector_size as u64,
            sector_size as u64,
            true,
            input_mmio,
            input_vq,
        );
        let input_device = Arc::new(Mutex::new(input_device));
        device_set.add_device(Arc::clone(&input_device), true);
        io_events.push(IoEvent::new(input_mmio)?);
        Some(stub)
    } else {
        let opened = open_chain_devices(
            old_chain_parents,
            sector_size as u64,
            &mut device_set,
            &mut io_events,
            0,
            "rebase-old",
        )?;
        if let Some(chain) = new_chain {
            open_chain_devices(
                chain,
                sector_size as u64,
                &mut device_set,
                &mut io_events,
                opened,
                "rebase-new",
            )?;
        }
        None
    };

    // Output device — overlay, attached at the slot after all
    // inputs. When `total_input_devices == 0` we have a 1-slot
    // stub, so the overlay sits at slot 1; otherwise it sits at
    // `total_input_devices`.
    let output_slot = if total_input_devices == 0 {
        1
    } else {
        total_input_devices
    };
    let output_mmio = device_mmio_base(output_slot);
    let output_vq = device_vq_base(output_slot);
    let output_device = VirtioBlockDevice::new(
        output_backing,
        output_capacity_hint,
        sector_size as u64,
        false,
        output_mmio,
        output_vq,
    );
    let output_device = Arc::new(Mutex::new(output_device));
    device_set.add_device(Arc::clone(&output_device), false);
    io_events.push(IoEvent::new(output_mmio)?);

    // --- Write the combined chain config at CHAIN_CONFIG_ADDR ----------
    // The guest's safe-mode runner indexes `chain_config.devices[]`
    // by input device slot; concatenate the old chain and the new
    // chain in the same order they were attached so slot N in the
    // guest matches `devices[N]`. Unsafe mode ignores chain config.
    let mut combined_chain = BackingChain::new();
    for img in old_chain_parents.images() {
        combined_chain.push(img.clone());
    }
    if let Some(chain) = new_chain {
        for img in chain.images() {
            combined_chain.push(img.clone());
        }
    }
    if combined_chain.total_devices() > 0 {
        write_chain_config(&guest_mem, &combined_chain)?;
    }

    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }
    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            let _ = evt.unregister(&vm);
        }
    }
    let all_registered = !registration_failed;
    if all_registered && !io_events.is_empty() {
        let io_devices = device_set.create_io_devices(io_events);
        io_thread = Some(io_thread::IoThread::new(
            io_devices,
            Arc::clone(&guest_mem),
            Arc::clone(&vmm_stats),
        ));
    }

    // --- vCPU setup ------------------------------------------------------
    let mut vcpu = vm.create_vcpu(0)?;
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;

    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();

    // Inputs + output device config. If we used a stub, treat
    // the stub as a single input so the guest's core init
    // matches what's actually attached.
    let input_device_count = if total_input_devices == 0 {
        1
    } else {
        total_input_devices
    };
    let config = vmm_config_chain_with_output(sector_size, sector_size, input_device_count, 100);
    serial_transmitter.queue_config(&config);

    // --- Run the vCPU loop ----------------------------------------------
    let mut result_seen = false;
    let mut harvested = RebaseRunResult {
        overlay_format,
        mode: if flags & REBASE_CONFIG_FLAG_UNSAFE != 0 {
            shared::RebaseResult::MODE_UNSAFE
        } else {
            shared::RebaseResult::MODE_SAFE
        },
        clusters_copied: 0,
        bytes_copied: 0,
        error: shared::RebaseResult::ERROR_OK,
    };
    let mut vm_error: Option<String> = None;

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            if let Some(guest_::GuestMessage_::Payload::RebaseResult(r)) =
                                &msg.payload
                            {
                                harvested.overlay_format = match r.overlay_format.as_str() {
                                    "qcow2" => IMAGE_FORMAT_QCOW2,
                                    "vmdk" => IMAGE_FORMAT_VMDK4,
                                    "raw" => IMAGE_FORMAT_RAW,
                                    _ => overlay_format,
                                };
                                harvested.mode = match r.mode.as_str() {
                                    "unsafe" => shared::RebaseResult::MODE_UNSAFE,
                                    _ => shared::RebaseResult::MODE_SAFE,
                                };
                                harvested.clusters_copied = r.clusters_copied;
                                harvested.bytes_copied = r.bytes_copied;
                                harvested.error = r.error;
                                result_seen = true;
                            } else if verbose {
                                debug!("{}", format_message(&msg));
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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
    if !result_seen {
        return Err("rebase: guest did not return a result".into());
    }
    Ok(harvested)
}

/// Map a u32 image-format code (as stored in CommitConfig and
/// the per-format probe results) back to the chain crate's
/// `ImageFormat` enum so the host can build `ChainImage`
/// entries for `write_chain_config` and `open_chain_devices_rw`.
fn image_format_from_u32(code: u32) -> ImageFormat {
    match code {
        IMAGE_FORMAT_QCOW2 => ImageFormat::Qcow2,
        IMAGE_FORMAT_VMDK4 => ImageFormat::Vmdk4,
        IMAGE_FORMAT_VMDK3 => ImageFormat::Vmdk3,
        IMAGE_FORMAT_VHD => ImageFormat::Vhd,
        IMAGE_FORMAT_VHDX => ImageFormat::Vhdx,
        IMAGE_FORMAT_QCOW1 => ImageFormat::Qcow1,
        IMAGE_FORMAT_LUKS => ImageFormat::Luks,
        IMAGE_FORMAT_RAW => ImageFormat::Raw,
        _ => ImageFormat::Unknown,
    }
}

/// Launch the commit guest binary, wait for the
/// `CommitResultMessage`. Modelled on `run_rebase_guest` with
/// the device layout flipped: the overlay is input slot 0
/// opened RW (the guest uses `write_input_sector(0, ...)` for
/// the overlay-clear pass), the backing's own ancestor chain
/// fills input slots 1..N opened RO (forward-compat — v1's
/// guest ignores those slots), and the backing being committed
/// into is the output device opened RW.
#[allow(clippy::too_many_arguments)]
fn run_commit_guest(
    core_code: &[u8],
    operation_code: &[u8],
    overlay_format: u32,
    backing_format: u32,
    flags: u32,
    sector_size: u32,
    overlay_cluster_size: u32,
    backing_cluster_size: u32,
    overlay_virtual_size: u64,
    backing_virtual_size: u64,
    overlay_path: &Path,
    output_backing: BackingStore,
    output_capacity_hint: u64,
    backing_parents: &BackingChain,
    verbose: bool,
) -> Result<CommitRunResult, Box<dyn std::error::Error>> {
    // --- KVM / VM / guest memory setup ----------------------------------
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid
    // GuestMemoryMmap allocation that outlives the VM.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    setup_gdt(&guest_mem)?;
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    guest_mem.write_slice(core_code, GuestAddress(GUEST_CODE_BASE))?;
    guest_mem.write_slice(operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;

    // --- Write CommitConfig at OPERATION_CONFIG_ADDR --------------------
    // Layout (must match shared::CommitConfig exactly):
    //    0: magic                  u32 ("COMM")
    //    4: overlay_format         u32
    //    8: backing_format         u32
    //   12: flags                  u32
    //   16: sector_size            u32
    //   20: overlay_cluster_size   u32
    //   24: backing_cluster_size   u32
    //   28: _pad                   u32
    //   32: overlay_virtual_size   u64
    //   40: backing_virtual_size   u64
    //   48: backing_chain_first    u32
    //   52: backing_chain_count    u32
    //   56: _reserved              [u8; 64]
    let backing_chain_first = 1u32; // slot 0 is the overlay
    let backing_chain_count = backing_parents.total_devices() as u32;

    guest_mem.write_obj(COMMIT_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(overlay_format, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(backing_format, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(flags, GuestAddress(OPERATION_CONFIG_ADDR + 12))?;
    guest_mem.write_obj(sector_size, GuestAddress(OPERATION_CONFIG_ADDR + 16))?;
    guest_mem.write_obj(
        overlay_cluster_size,
        GuestAddress(OPERATION_CONFIG_ADDR + 20),
    )?;
    guest_mem.write_obj(
        backing_cluster_size,
        GuestAddress(OPERATION_CONFIG_ADDR + 24),
    )?;
    // _pad at offset 28 stays zero from page-zeroed memory.
    guest_mem.write_obj(
        overlay_virtual_size,
        GuestAddress(OPERATION_CONFIG_ADDR + 32),
    )?;
    guest_mem.write_obj(
        backing_virtual_size,
        GuestAddress(OPERATION_CONFIG_ADDR + 40),
    )?;
    guest_mem.write_obj(
        backing_chain_first,
        GuestAddress(OPERATION_CONFIG_ADDR + 48),
    )?;
    guest_mem.write_obj(
        backing_chain_count,
        GuestAddress(OPERATION_CONFIG_ADDR + 52),
    )?;
    // _reserved at offset 56 stays zero from page-zeroed memory.

    debug!(
        "Wrote commit config at 0x{:x} (overlay_format={}, backing_format={}, \
         flags=0x{:x}, backing_chain=[{}..+{}))",
        OPERATION_CONFIG_ADDR,
        overlay_format,
        backing_format,
        flags,
        backing_chain_first,
        backing_chain_count,
    );

    // --- Set up devices --------------------------------------------------
    // Device layout (MMIO slot order):
    //   0:                       overlay (input, RW)
    //   [1..1+backing_parents):  backing's parents (input, RO)
    //   [1+backing_parents]:     backing (output, RW)
    //
    // The combined chain is what the guest's per-side decoder
    // consumes via `write_chain_config`. open_chain_devices_rw
    // takes `rw_slots = &[0]` so only the overlay is RW.
    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    // Build the overlay's ChainImage from the probe results
    // plus the file size from the filesystem. The guest's
    // chain_config consumer reads back format / virtual_size /
    // cluster_size / actual_size for each slot.
    let overlay_actual_size = std::fs::metadata(overlay_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let overlay_image = ChainImage {
        path: overlay_path.to_path_buf(),
        format: image_format_from_u32(overlay_format),
        virtual_size: overlay_virtual_size,
        actual_size: overlay_actual_size,
        cluster_size: overlay_cluster_size,
        backing_file_raw: None,
        flags: 0,
        external_data_files: Vec::new(),
    };

    let mut combined_chain = BackingChain::new();
    combined_chain.push(overlay_image);
    for img in backing_parents.images() {
        combined_chain.push(img.clone());
    }

    let total_input_devices = open_chain_devices_rw(
        &combined_chain,
        sector_size as u64,
        &mut device_set,
        &mut io_events,
        0,
        "commit",
        &[0],
    )?;

    // Output device — backing, attached at the slot
    // immediately after the combined input chain.
    let output_slot = total_input_devices;
    let output_mmio = device_mmio_base(output_slot);
    let output_vq = device_vq_base(output_slot);
    let output_device = VirtioBlockDevice::new(
        output_backing,
        output_capacity_hint,
        sector_size as u64,
        false,
        output_mmio,
        output_vq,
    );
    let output_device = Arc::new(Mutex::new(output_device));
    device_set.add_device(Arc::clone(&output_device), false);
    io_events.push(IoEvent::new(output_mmio)?);

    // --- Write the combined chain config at CHAIN_CONFIG_ADDR ----------
    // The guest's per-side decoder indexes
    // `chain_config.devices[]` by input slot; the order is
    // overlay (slot 0) + backing's ancestor chain (slots 1..N).
    if combined_chain.total_devices() > 0 {
        write_chain_config(&guest_mem, &combined_chain)?;
    }

    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }
    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            let _ = evt.unregister(&vm);
        }
    }
    let all_registered = !registration_failed;
    if all_registered && !io_events.is_empty() {
        let io_devices = device_set.create_io_devices(io_events);
        io_thread = Some(io_thread::IoThread::new(
            io_devices,
            Arc::clone(&guest_mem),
            Arc::clone(&vmm_stats),
        ));
    }

    // --- vCPU setup ------------------------------------------------------
    let mut vcpu = vm.create_vcpu(0)?;
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;

    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();

    let config = vmm_config_chain_with_output(sector_size, sector_size, total_input_devices, 100);
    serial_transmitter.queue_config(&config);

    // --- Run the vCPU loop ----------------------------------------------
    let mut result_seen = false;
    let mut harvested = CommitRunResult {
        overlay_format,
        backing_format,
        clusters_committed: 0,
        bytes_committed: 0,
        overlay_clusters_cleared: 0,
        error: shared::CommitResult::ERROR_OK,
    };
    let mut vm_error: Option<String> = None;

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            if let Some(guest_::GuestMessage_::Payload::CommitResult(r)) =
                                &msg.payload
                            {
                                harvested.overlay_format = match r.overlay_format.as_str() {
                                    "qcow2" => IMAGE_FORMAT_QCOW2,
                                    "vmdk" => IMAGE_FORMAT_VMDK4,
                                    "raw" => IMAGE_FORMAT_RAW,
                                    _ => overlay_format,
                                };
                                harvested.backing_format = match r.backing_format.as_str() {
                                    "qcow2" => IMAGE_FORMAT_QCOW2,
                                    "vmdk" => IMAGE_FORMAT_VMDK4,
                                    "raw" => IMAGE_FORMAT_RAW,
                                    _ => backing_format,
                                };
                                harvested.clusters_committed = r.clusters_committed;
                                harvested.bytes_committed = r.bytes_committed;
                                harvested.overlay_clusters_cleared = r.overlay_clusters_cleared;
                                harvested.error = r.error;
                                result_seen = true;
                            } else if verbose {
                                debug!("{}", format_message(&msg));
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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
    if !result_seen {
        return Err("commit: guest did not return a result".into());
    }
    Ok(harvested)
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
        print!("{output}");
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
                return Err(format!("error discovering backing chain: {e}").into());
            }
        }
    }

    // Determine output profile (from --qemu-version flag or by detection)
    let profile = if let Some(ref version_str) = args.qemu_version {
        match version::profile_for_version_str(version_str) {
            Some(p) => {
                debug!("Using output profile for qemu-img version {version_str}");
                p
            }
            None => {
                return Err(
                    format!("invalid qemu version '{version_str}' (expected format: X.Y)").into(),
                );
            }
        }
    } else {
        let p = version::get_profile();
        if let Some(v) = &p.version {
            debug!("Detected qemu-img version {v}, using matching output profile");
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

    // VMDK monolithicFlat descriptor pre-flight validation.
    //
    // The guest info operation parses descriptor text directly
    // (Phase 22c), but it can't run the security-sensitive
    // rejections — backing allowlist, multi-extent, parent-hint,
    // non-zero offset — because those all touch the host
    // filesystem. Do that here so an unsupported descriptor
    // fails cleanly before we launch the guest instead of
    // silently producing misleading output.
    //
    // The resolved descriptor (when present) is also threaded into
    // JSON info output so each flat extent appears as a separate
    // child entry, matching qemu-img.
    let input_path_for_preflight = Path::new(&args.input);
    let vmdk_flat_resolved: Option<crate::chain::ResolvedVmdkDescriptor> =
        if peek_is_vmdk_descriptor(input_path_for_preflight).unwrap_or(false) {
            let security_config = config::load_config().config.security;
            Some(
                resolve_vmdk_flat_descriptor(input_path_for_preflight, &security_config)
                    .map_err(|e| format!("error resolving VMDK descriptor: {e}"))?,
            )
        } else {
            None
        };

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

    // Parse --max-guest-memory for LUKS v2 Argon2id support
    let guest_mem_size: u64 = if let Some(ref mem_str) = args.max_guest_memory {
        let requested = parse_memory_size(mem_str)?;
        if requested < GUEST_MEM_SIZE {
            return Err(format!(
                "--max-guest-memory must be at least {}MB (got {})",
                GUEST_MEM_SIZE / (1024 * 1024),
                mem_str
            )
            .into());
        }
        debug!("Using {requested} bytes of guest memory (--max-guest-memory {mem_str})");
        requested
    } else {
        GUEST_MEM_SIZE
    };

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
    let guest_mem = create_guest_memory(guest_mem_size)?;
    debug!("Allocated {guest_mem_size} bytes of guest memory");

    // Get the memory region for KVM registration
    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    // Set up KVM memory region
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: guest_mem_size,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid GuestMemoryMmap
    // allocation that outlives the VM. The slot/guest_phys_addr are unique
    // per operation entry point. KVM requires this call to be unsafe but
    // the memory contract is satisfied.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    // Set MMIO base (must be above guest memory for KVM to trap accesses)
    set_mmio_base_for_mem_size(guest_mem_size);

    // Write MMIO base to VMM_PARAMS_ADDR so the guest can discover it
    // SAFETY: ACTIVE_MMIO_BASE was initialized before VM setup and is
    // never modified after initialization. Read-only access is safe.
    let mmio_base = unsafe { ACTIVE_MMIO_BASE };
    guest_mem.write_obj(mmio_base, GuestAddress(VMM_PARAMS_ADDR))?;
    debug!("Wrote MMIO base 0x{mmio_base:x} to VMM_PARAMS_ADDR");

    // Set up GDT
    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{GDT_BASE:x}");

    // Set up page tables (identity map, covers guest memory + MMIO region)
    setup_page_tables(&guest_mem, guest_mem_size)?;
    debug!("Set up page tables at 0x{PAGE_TABLE_BASE:x}");

    // Load core binary at GUEST_CODE_BASE (0x10000)
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{GUEST_CODE_BASE:x}");

    // Load operation binary at OPERATION_LOAD_ADDR (0x22000)
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{OPERATION_LOAD_ADDR:x}");

    // Write InfoConfig at OPERATION_CONFIG_ADDR
    // Layout: magic (u32), flags (u32), passphrase_len (u32), _pad (u32), passphrase (256 bytes)
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

    // Resolve LUKS passphrase from --luks-passphrase or --luks-passphrase-file
    let passphrase = if let Some(ref pp) = args.luks_passphrase {
        Some(pp.clone())
    } else if let Some(ref path) = args.luks_passphrase_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read passphrase file '{path}': {e}"))?;
        // Strip trailing newline (like how most tools read key files)
        Some(content.trim_end_matches('\n').to_string())
    } else {
        None
    };

    // Write passphrase to guest config if provided
    if let Some(ref pp) = passphrase {
        let pp_bytes = pp.as_bytes();
        if pp_bytes.len() > shared::INFO_CONFIG_MAX_PASSPHRASE {
            return Err(format!(
                "passphrase too long ({} bytes, max {})",
                pp_bytes.len(),
                shared::INFO_CONFIG_MAX_PASSPHRASE
            )
            .into());
        }
        guest_mem.write_obj(
            pp_bytes.len() as u32,
            GuestAddress(OPERATION_CONFIG_ADDR + 8),
        )?;
        guest_mem
            .write_slice(pp_bytes, GuestAddress(OPERATION_CONFIG_ADDR + 16))
            .map_err(|e| format!("failed to write passphrase to guest memory: {e}"))?;
        debug!(
            "Wrote LUKS passphrase ({} bytes) to guest config",
            pp_bytes.len()
        );
    }

    // Write argon2_mem_size to InfoConfig (offset 272 = 4+4+4+4+256)
    let argon2_mem_size: u64 = guest_mem_size.saturating_sub(GUEST_MEM_SIZE);
    guest_mem.write_obj(argon2_mem_size, GuestAddress(OPERATION_CONFIG_ADDR + 272))?;

    debug!(
        "Wrote info config at 0x{OPERATION_CONFIG_ADDR:x} (flags=0x{info_flags:x}, argon2_mem_size={argon2_mem_size})"
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
    debug!("Created virtio-block device at MMIO 0x{input_mmio:x}, VQ 0x{input_vq:x}");
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
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
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
                                    vmdk_flat_resolved.as_ref(),
                                );
                            } else {
                                debug!("{}", format_message(&msg));
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                        "  Stack region: 0x{STACK_BASE:x} - 0x{STACK_TOP:x} ({STACK_SIZE} bytes)"
                    );
                }
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                eprintln!("VM Entry Failed! reason=0x{reason:x}, cpu={cpu}");
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {exit:?}");
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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
                "{name} sector size must be a power of 2, 512 to {MAX_SECTOR_SIZE} (got {size})"
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
    debug!("Allocated {GUEST_MEM_SIZE} bytes of guest memory");

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid GuestMemoryMmap
    // allocation that outlives the VM. The slot/guest_phys_addr are unique
    // per operation entry point. KVM requires this call to be unsafe but
    // the memory contract is satisfied.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{GDT_BASE:x}");

    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    debug!("Set up page tables at 0x{PAGE_TABLE_BASE:x}");

    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{GUEST_CODE_BASE:x}");

    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{OPERATION_LOAD_ADDR:x}");

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
    debug!("Created virtio-block devices at MMIO 0x{input_mmio:x} and 0x{output_mmio:x}");
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
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
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
        n => format!("every {n}%"),
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
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                        "  Stack region: 0x{STACK_BASE:x} - 0x{STACK_TOP:x} ({STACK_SIZE} bytes)"
                    );
                    if regs.rsp < STACK_BASE {
                        let underflow = STACK_BASE - regs.rsp;
                        eprintln!("  Stack underflowed by {underflow} bytes");
                    }
                } else {
                    let stack_used = STACK_TOP - regs.rsp;
                    let stack_percent = (stack_used * 100) / STACK_SIZE;
                    eprintln!();
                    eprintln!("Stack usage: {stack_used} / {STACK_SIZE} bytes ({stack_percent}%)");
                    if stack_percent > 90 {
                        eprintln!("*** WARNING: Stack was nearly exhausted ***");
                    }
                }
                eprintln!();
                eprintln!("Guest memory: {GUEST_MEM_SIZE} bytes (0x{GUEST_MEM_SIZE:x})");
                eprintln!("Code base: 0x{GUEST_CODE_BASE:x}");
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                eprintln!("VM Entry Failed! reason=0x{reason:x}, cpu={cpu}");
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {exit:?}");
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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

/// Post-repair check counts captured from the guest's `CheckResult`,
/// used to map the operation to a qemu-img-parity process exit code.
///
/// These are the *post-repair* values: when `--repair` reclaims leaked
/// clusters the guest decrements `leaks`/`total_errors` before sending
/// the result, so a fully-repaired image reports zero here and exits 0,
/// matching `qemu-img check -r`'s re-check semantics.
struct CheckExit {
    corruptions: u32,
    refcount_errors: u32,
    chain_errors: u32,
    leaks: u32,
    not_supported: bool,
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

    // --repair and --chain are mutually exclusive: repair opens the
    // single input read-write to reclaim clusters in place, whereas the
    // chain path opens every chain image read-only. Combining them would
    // silently set the repair flag against a read-only device (repair
    // would fail-safe to INCOMPLETE), so reject the combination up front
    // with a clear message before any device is opened.
    if args.repair.is_some() && args.chain {
        return Err(
            "check: --repair cannot be combined with --chain (repair operates on a single image)"
                .into(),
        );
    }

    // --repair=all is the lossy tier: it rewrites image metadata in
    // place. Print a one-line stderr nudge before launching the guest so
    // the in-the-moment risk is visible (qemu-img does not prompt either).
    if matches!(args.repair, Some(RepairMode::All)) {
        eprintln!(
            "warning: --repair=all rewrites image metadata in place; back up valuable images first"
        );
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

    // Handle --chain flag: discover backing chain before launching guest.
    //
    // Chain discovery is also forced when the top input is a VMDK
    // monolithicFlat descriptor: that format inherently needs two
    // devices (descriptor + flat extent) so the single-device fast
    // path below can't represent it. The chain machinery then
    // treats the descriptor as a terminal chain node with an
    // external data file pointing at the flat extent.
    let input_path = Path::new(&args.input);
    let force_chain_for_descriptor = peek_is_vmdk_descriptor(input_path).unwrap_or(false);
    let chain = if args.chain || force_chain_for_descriptor {
        let security_config = config::load_config().config.security;
        match discover_backing_chain(input_path, args.sector_size, &security_config) {
            Ok(chain) => {
                if verbose {
                    print_backing_chain(&chain);
                }
                Some(chain)
            }
            Err(e) => {
                return Err(format!("error discovering backing chain: {e}").into());
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
    debug!("Allocated {GUEST_MEM_SIZE} bytes of guest memory");

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
    // SAFETY: mem_region.userspace_addr points to a valid GuestMemoryMmap
    // allocation that outlives the VM. The slot/guest_phys_addr are unique
    // per operation entry point. KVM requires this call to be unsafe but
    // the memory contract is satisfied.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    // Set up GDT
    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{GDT_BASE:x}");

    // Set up page tables (identity map)
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    debug!("Set up page tables at 0x{PAGE_TABLE_BASE:x}");

    // Load core binary at GUEST_CODE_BASE (0x10000)
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{GUEST_CODE_BASE:x}");

    // Load operation binary at OPERATION_LOAD_ADDR (0x22000)
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{OPERATION_LOAD_ADDR:x}");

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
    if args.repair.is_some() {
        // Any --repair[=MODE] selects the base repair flag (read-write
        // open + leaks tier). --repair=all additionally sets
        // FLAG_REPAIR_ALL to request the lossy recount + COPIED tier;
        // the guest still falls back to the leaks tier when the all
        // tier is unsupported for the image.
        check_flags |= CHECK_CONFIG_FLAG_REPAIR;
        if matches!(args.repair, Some(RepairMode::All)) {
            check_flags |= CHECK_CONFIG_FLAG_REPAIR_ALL;
        }
    }
    guest_mem.write_obj(CHECK_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(check_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    debug!("Wrote check config at 0x{OPERATION_CONFIG_ADDR:x} (flags=0x{check_flags:x})");

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
        // If the top image has an external data file, it's opened as a
        // separate device between the top image and the backing chain.
        open_chain_devices(
            chain,
            args.sector_size as u64,
            &mut device_set,
            &mut io_events,
            0,
            "chain",
        )?;

        // Write chain config to guest memory
        write_chain_config(&guest_mem, chain)?;
    } else if args.repair.is_some() {
        // Single-device repair mode: open the input read-write so the
        // guest can reclaim leaked clusters in place. Mirrors
        // run_snapshot_mutating_guest's read-write open
        // (BackingStore::open_rw_existing + VirtioBlockDevice::new(..,
        // false)). Leak reclamation only zeroes refcount entries in
        // place and never grows the file, so the capacity hint is the
        // current file size (the same value the read-only path passes
        // as the device capacity).
        let capacity_hint = input_size;
        let input_backing =
            BackingStore::open_rw_existing(Path::new(&args.input), Some(capacity_hint))?;
        let input_mmio = device_mmio_base(0);
        let input_vq = device_vq_base(0);
        let input_device = VirtioBlockDevice::new(
            input_backing,
            capacity_hint,
            args.sector_size as u64,
            false, // read-write (repair)
            input_mmio,
            input_vq,
        );
        debug!(
            "Created read-write virtio-block device at MMIO 0x{input_mmio:x}, VQ 0x{input_vq:x}"
        );
        debug!("  Sector size: {} bytes", input_device.sector_size());
        let input_device = Arc::new(Mutex::new(input_device));
        device_set.add_device(Arc::clone(&input_device), true);
        io_events.push(IoEvent::new(input_mmio)?);
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
        debug!("Created virtio-block device at MMIO 0x{input_mmio:x}, VQ 0x{input_vq:x}");
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
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
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
                warn!("ioeventfd: failed to unregister during rollback: {e:?}");
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
        vmm_config_chain(args.sector_size, chain.total_devices())
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

    // Capture the post-repair result counts for qemu-img-parity exit-code
    // mapping in the tail. None until a CheckResult arrives; a missing
    // result is treated as a failure (Err) below.
    let mut check_exit: Option<CheckExit> = None;

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

                                    // Capture the post-repair counts for the
                                    // exit-code mapping in the tail. These are
                                    // already post-repair: the guest decrements
                                    // leaks/total_errors for clusters it
                                    // reclaimed before sending the result.
                                    check_exit = Some(CheckExit {
                                        corruptions: result.corruptions,
                                        refcount_errors: result.refcount_errors,
                                        chain_errors: result.chain_errors,
                                        leaks: result.leaks,
                                        not_supported: (result.flags
                                            & CHECK_RESULT_FLAG_NOT_SUPPORTED)
                                            != 0,
                                    });
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
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                eprintln!("VM Entry Failed! reason=0x{reason:x}, cpu={cpu}");
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {exit:?}");
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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

    // Return error if VM crashed or failed (genuine VM/I-O failures keep
    // returning Err, i.e. exit 1, regardless of any check counts).
    if let Some(error) = vm_error {
        return Err(error.into());
    }

    // Map the post-repair CheckResult to a qemu-img-parity process exit
    // code. All cleanup above (I/O thread stop, stats display) has already
    // run and there is no critical work left after this point — the
    // function would otherwise just return — so std::process::exit here is
    // safe (this mirrors run_compare, which exits the same way). Returning
    // Err always maps to exit 1, so the 0/2/3 cases must use exit/Ok
    // directly rather than Err.
    //
    // qemu-img check exit codes: 0 = clean, 2 = corruptions/errors,
    // 3 = leaks only. We compute these from the post-repair counts.
    match check_exit {
        // No result was received from the guest: treat as a failure.
        None => Err("image check failed: no result received".into()),
        Some(exit) => {
            // Unsupported format: mirror `qemu-img check`, which exits 63
            // (EXIT_NOT_SUPPORTED) with a "does not support checks"
            // message. The not-supported message is already rendered above.
            if exit.not_supported {
                std::process::exit(63);
            }

            let errors = exit.corruptions > 0 || exit.refcount_errors > 0 || exit.chain_errors > 0;
            if errors {
                // Corruptions / refcount / chain errors => exit 2.
                std::process::exit(2);
            }
            if exit.leaks > 0 {
                // Leaks only (no other error class) => exit 3.
                std::process::exit(3);
            }

            // Clean image => exit 0.
            Ok(())
        }
    }
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

        if result.subcluster_errors > 0 {
            println!(
                "{} subcluster bitmap error(s) were found.",
                result.subcluster_errors
            );
        }

        // Repair section. The per-class repaired_* counters travel on the
        // CheckResultMessage protobuf, so a repair run reports what it
        // fixed; the post-repair leaks/errors counts above already reflect
        // those fixes (reclaimed clusters are subtracted before the result
        // is sent). The summary line is printed only when a repair
        // actually changed something, so a read-only check is unaffected.
        let repaired_total = result
            .repaired_leaks
            .saturating_add(result.repaired_refcounts)
            .saturating_add(result.repaired_corruptions);
        if repaired_total > 0 {
            println!(
                "Repaired {} leaked cluster(s), {} refcount correction(s), \
                 {} corruption(s).",
                result.repaired_leaks, result.repaired_refcounts, result.repaired_corruptions
            );
        }
        if (result.flags & CHECK_RESULT_FLAG_REPAIR_INCOMPLETE) != 0 {
            println!("Repair did not complete; some issues remain (re-run or use qemu-img).");
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
    println!("    \"dirty\": {is_dirty},");
    println!("    \"corrupt\": {is_corrupt},");
    println!("    \"chain-errors\": {},", result.chain_errors);
    println!("    \"subcluster-errors\": {},", result.subcluster_errors);
    // Per-class repair counters, carried on the CheckResultMessage
    // protobuf. Emitted only when a repair actually fixed something, so a
    // read-only check keeps its existing key set (the qemu-img parity
    // schema and the check-json baselines are unaffected).
    if result.repaired_leaks > 0 {
        println!("    \"repaired-leaks\": {},", result.repaired_leaks);
    }
    if result.repaired_refcounts > 0 {
        println!("    \"repaired-refcounts\": {},", result.repaired_refcounts);
    }
    if result.repaired_corruptions > 0 {
        println!(
            "    \"repaired-corruptions\": {},",
            result.repaired_corruptions
        );
    }
    // Repair signal. The incomplete flag is carried inside result.flags;
    // appended last (no trailing comma) after the existing keys so the
    // schema the parity tests parse is unchanged.
    let repair_incomplete = (result.flags & CHECK_RESULT_FLAG_REPAIR_INCOMPLETE) != 0;
    println!("    \"repair-incomplete\": {repair_incomplete}");
    println!("}}");
}

/// Print measure result in human-readable or JSON format.
///
/// `target_qcow2_with_source` is true when the target format is qcow2
/// AND there is a real source image (not `--size` mode). qemu-img emits
/// a `bitmaps` field in that case to report the count of persistent
/// QCOW2 bitmaps that the conversion would carry across; for our
/// purposes the value is always 0 because instar's source-scanning
/// path does not load bitmap metadata.
fn print_measure_result(
    msg: &guest_::GuestMessage,
    output_format: &str,
    target_qcow2_with_source: bool,
) {
    if let Some(guest_::GuestMessage_::Payload::MeasureResult(result)) = &msg.payload {
        // Error path: emit a clear stderr message; print nothing on stdout.
        if result.error != MEASURE_RESULT_ERROR_OK {
            let msg = match result.error {
                MEASURE_RESULT_ERROR_OVERFLOW => "measure: overflow computing target size",
                MEASURE_RESULT_ERROR_INVALID_OPTION => "measure: invalid option for target format",
                MEASURE_RESULT_ERROR_INVALID_SIZE => "measure: source image is unsupported format",
                _ => "measure: unknown error",
            };
            eprintln!("{}", msg);
            return;
        }

        if output_format == "json" {
            print_measure_result_json(result, target_qcow2_with_source);
        } else {
            // Human format must match qemu-img byte-for-byte:
            //   required size: <N>\n
            //   fully allocated size: <N>\n
            //   bitmaps size: 0\n              (qcow2 target + source only)
            println!("required size: {}", result.required);
            println!("fully allocated size: {}", result.fully_allocated);
            if target_qcow2_with_source {
                println!("bitmaps size: 0");
            }
        }
    }
}

/// Print measure result in JSON format matching qemu-img byte-for-byte.
///
/// 4-space indent, hyphenated `fully-allocated` key. When
/// `target_qcow2_with_source` is true, a leading `"bitmaps": 0,` field
/// is emitted to match `qemu-img measure -O qcow2 <source>`.
fn print_measure_result_json(
    result: &guest_::MeasureResultMessage,
    target_qcow2_with_source: bool,
) {
    println!("{{");
    if target_qcow2_with_source {
        println!("    \"bitmaps\": 0,");
    }
    println!("    \"required\": {},", result.required);
    println!("    \"fully-allocated\": {}", result.fully_allocated);
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

    let total_devices = chain1.total_devices() + chain2.total_devices();
    debug!(
        "Total devices: {} (image1: {} + image2: {})",
        total_devices,
        chain1.total_devices(),
        chain2.total_devices()
    );

    if total_devices > MAX_CHAIN_DEVICES {
        return Err(format!(
            "combined chain depth {} (image1: {} + image2: {}) exceeds maximum of {} devices",
            total_devices,
            chain1.total_devices(),
            chain2.total_devices(),
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
    debug!("Allocated {GUEST_MEM_SIZE} bytes of guest memory");

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
    // SAFETY: mem_region.userspace_addr points to a valid GuestMemoryMmap
    // allocation that outlives the VM. The slot/guest_phys_addr are unique
    // per operation entry point. KVM requires this call to be unsafe but
    // the memory contract is satisfied.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    // Set up GDT
    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{GDT_BASE:x}");

    // Set up page tables (identity map)
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    debug!("Set up page tables at 0x{PAGE_TABLE_BASE:x}");

    // Load core binary at GUEST_CODE_BASE (0x10000)
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{GUEST_CODE_BASE:x}");

    // Load operation binary at OPERATION_LOAD_ADDR (0x22000)
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{OPERATION_LOAD_ADDR:x}");

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
    guest_mem.write_obj(
        chain1.total_devices() as u32,
        GuestAddress(OPERATION_CONFIG_ADDR + 8),
    )?;
    guest_mem.write_obj(
        chain2.total_devices() as u32,
        GuestAddress(OPERATION_CONFIG_ADDR + 12),
    )?;

    // Resolve QCOW2 AES passphrase (--qcow2-password or --qcow2-password-file)
    let qcow2_passphrase = if let Some(ref pass) = args.qcow2_password {
        Some(pass.clone())
    } else if let Some(ref path) = args.qcow2_password_file {
        let mut data = std::fs::read_to_string(path)?;
        if data.ends_with('\n') {
            data.pop();
        }
        Some(data)
    } else {
        None
    };

    // Resolve LUKS passphrase (--luks-passphrase or --luks-passphrase-file)
    let luks_passphrase = if let Some(ref pp) = args.luks_passphrase {
        Some(pp.clone())
    } else if let Some(ref path) = args.luks_passphrase_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read LUKS passphrase file '{path}': {e}"))?;
        Some(content.trim_end_matches('\n').to_string())
    } else {
        None
    };

    // Use LUKS passphrase if no QCOW2 passphrase was provided
    let effective_passphrase = qcow2_passphrase.or(luks_passphrase);

    if let Some(ref passphrase) = effective_passphrase {
        let pass_bytes = passphrase.as_bytes();
        if pass_bytes.len() > 256 {
            return Err("passphrase too long (max 256 bytes)".into());
        }
        guest_mem.write_obj(
            pass_bytes.len() as u32,
            GuestAddress(OPERATION_CONFIG_ADDR + 16),
        )?;
        // _pad at offset 20 is zero-initialized
        guest_mem.write_slice(pass_bytes, GuestAddress(OPERATION_CONFIG_ADDR + 24))?;
        debug!(
            "Wrote passphrase ({} bytes) to compare config",
            pass_bytes.len()
        );
    }

    debug!(
        "Wrote compare config at 0x{:x} (flags=0x{:x}, chain1={}, chain2={})",
        OPERATION_CONFIG_ADDR,
        compare_flags,
        chain1.total_devices(),
        chain2.total_devices()
    );

    // Write ChainConfig with format metadata for all chain images
    // Devices are laid out: [chain1 devices...] [chain2 devices...]
    // Each chain may include an external data file device after its top image.
    guest_mem.write_obj(CHAIN_CONFIG_MAGIC, GuestAddress(CHAIN_CONFIG_ADDR))?;
    guest_mem.write_obj(total_devices as u32, GuestAddress(CHAIN_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(CHAIN_CONFIG_VERSION, GuestAddress(CHAIN_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(0u32, GuestAddress(CHAIN_CONFIG_ADDR + 12))?; // reserved

    let devices_base = CHAIN_CONFIG_ADDR + 16;
    let chain1_written = write_chain_device_entries(&guest_mem, &chain1, devices_base, 0)?;
    write_chain_device_entries(&guest_mem, &chain2, devices_base, chain1_written)?;

    debug!(
        "Wrote chain config at 0x{:x}: device_count={}, chain1={}, chain2={}",
        CHAIN_CONFIG_ADDR,
        total_devices,
        chain1.total_devices(),
        chain2.total_devices()
    );

    // Create device set for managing virtio-block devices
    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    // Set up devices for image1's chain (including data file if present)
    let chain1_devs = open_chain_devices(
        &chain1,
        args.sector_size as u64,
        &mut device_set,
        &mut io_events,
        0,
        "chain1",
    )?;

    // Set up devices for image2's chain (including data file if present)
    open_chain_devices(
        &chain2,
        args.sector_size as u64,
        &mut device_set,
        &mut io_events,
        chain1_devs,
        "chain2",
    )?;

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
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }

    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            if let Err(e) = evt.unregister(&vm) {
                warn!("ioeventfd: failed to unregister during rollback: {e:?}");
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
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                eprintln!("VM Entry Failed! reason=0x{reason:x}, cpu={cpu}");
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {exit:?}");
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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
        "vmdk" => 3u32,  // ImageFormat::Vmdk4
        "vpc" => 5u32,   // ImageFormat::Vhd
        "vhdx" => 6u32,  // ImageFormat::Vhdx
        other => {
            return Err(format!(
                "unsupported output format '{other}' \
                 (supported: 'raw', 'qcow2', 'vmdk', 'vpc', 'vhdx')"
            )
            .into());
        }
    };
    let is_qcow2_output = target_format == 2;
    let is_vmdk_output = target_format == 3;
    let is_vhd_output = target_format == 5;
    let is_vhdx_output = target_format == 6;

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
        && (!(512..=2097152).contains(&args.cluster_size) || !args.cluster_size.is_power_of_two())
    {
        return Err(format!(
            "cluster size must be a power of 2, \
             512 to 2097152 (got {})",
            args.cluster_size
        )
        .into());
    }

    // Validate -c requires -O qcow2 or -O vmdk
    if args.compress && !is_qcow2_output && !is_vmdk_output {
        return Err("compression (-c) is only supported with \
             QCOW2 (-O qcow2) or VMDK (-O vmdk) output"
            .into());
    }

    // Validate --extended-l2 requires -O qcow2
    if args.extended_l2 && !is_qcow2_output {
        return Err("--extended-l2 is only supported with QCOW2 (-O qcow2) output".into());
    }

    // Validate --grain-size for VMDK output
    if is_vmdk_output
        && (!(4096..=65536).contains(&args.grain_size) || !args.grain_size.is_power_of_two())
    {
        return Err(format!(
            "grain size must be a power of 2, \
             4096 to 65536 (got {})",
            args.grain_size
        )
        .into());
    }
    if args.grain_size != 65536 && !is_vmdk_output {
        return Err("--grain-size is only supported with VMDK (-O vmdk) output".into());
    }

    // Validate --subformat for VMDK output
    let is_vmdk_flat_output = if !args.subformat.is_empty() {
        if !is_vmdk_output {
            return Err("--subformat is only supported with VMDK (-O vmdk) output".into());
        }
        match args.subformat.as_str() {
            "monolithicFlat" => {
                if args.compress {
                    return Err(
                        "compression (-c) is not supported with monolithicFlat subformat".into(),
                    );
                }
                true
            }
            "monolithicSparse" | "streamOptimized" => false,
            other => {
                return Err(format!(
                    "unsupported VMDK subformat '{other}' (supported: \
                     'monolithicSparse', 'streamOptimized', \
                     'monolithicFlat')"
                )
                .into());
            }
        }
    } else {
        false
    };

    // Validate --block-size for VHD/VHDX output
    if args.block_size != 0 {
        if !is_vhd_output && !is_vhdx_output {
            return Err("--block-size is only supported with \
                 VHD (-O vpc) or VHDX (-O vhdx) output"
                .into());
        }
        if !args.block_size.is_power_of_two() {
            return Err(
                format!("block size must be a power of 2 (got {})", args.block_size).into(),
            );
        }
        if is_vhd_output && (args.block_size < 512 * 1024 || args.block_size > 256 * 1024 * 1024) {
            return Err(format!(
                "VHD block size must be 524288 to \
                 268435456 (got {})",
                args.block_size
            )
            .into());
        }
        if is_vhdx_output && (args.block_size < 1024 * 1024 || args.block_size > 256 * 1024 * 1024)
        {
            return Err(format!(
                "VHDX block size must be 1048576 to \
                 268435456 (got {})",
                args.block_size
            )
            .into());
        }
    }

    // Resolve LUKS encrypt passphrase
    let luks_encrypt_passphrase = if let Some(ref pp) = args.luks_encrypt_passphrase {
        Some(pp.clone())
    } else if let Some(ref path) = args.luks_encrypt_passphrase_file {
        let mut data = std::fs::read_to_string(path)?;
        if data.ends_with('\n') {
            data.pop();
        }
        Some(data)
    } else {
        None
    };

    // Validate --luks-encrypt-passphrase requires -O qcow2
    if luks_encrypt_passphrase.is_some() && !is_qcow2_output {
        return Err(
            "--luks-encrypt-passphrase is only supported with QCOW2 (-O qcow2) output".into(),
        );
    }

    // Validate --luks-encrypt-passphrase conflicts with -c
    if luks_encrypt_passphrase.is_some() && args.compress {
        return Err("--luks-encrypt-passphrase cannot be combined with -c (compression)".into());
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

    // Load configuration and resolve skip_zeros:
    //   CLI --no-skip-zeros > CLI --skip-zeros/-S > config convert.sparse > default(true)
    let tracked_config = config::load_config();
    let skip_zeros = if args.no_skip_zeros {
        false
    } else if args.skip_zeros {
        true
    } else {
        tracked_config.config.convert.sparse.unwrap_or(true)
    };
    debug!("skip_zeros = {skip_zeros}");

    // Discover input backing chain
    let security_config = tracked_config.config.security;
    let chain = discover_backing_chain(Path::new(&args.input), args.sector_size, &security_config)
        .map_err(|e| format!("error discovering backing chain for {}: {}", args.input, e))?;

    if verbose {
        debug!("Input chain ({} image(s)):", chain.len());
        print_backing_chain(&chain);
    }

    let input_device_count = chain.total_devices();
    // Reserve one device slot for the output device to prevent its VQ
    // memory from colliding with DMA_POOL_BASE.
    if input_device_count + 1 > MAX_CHAIN_DEVICES {
        return Err(format!(
            "chain depth {input_device_count} plus output device exceeds maximum of {MAX_CHAIN_DEVICES} devices"
        )
        .into());
    }

    // Reject images with cluster_size > MAX_CLUSTER_SIZE (2MB).
    // Large clusters are processed in MAX_SECTOR_SIZE-sized chunks by
    // the guest, but the QCOW2 header parser limits at MAX_CLUSTER_SIZE.
    // VHD and VHDX report their block_size in cluster_size which can
    // be much larger (e.g. 32MB for VHDX) — these formats use their
    // own block_lookup path that handles large blocks correctly.
    for image in chain.images() {
        if matches!(image.format, ImageFormat::Vhd | ImageFormat::Vhdx) {
            continue;
        }
        if image.cluster_size as usize > MAX_CLUSTER_SIZE {
            return Err(format!(
                "cluster size {}KB in {} exceeds maximum supported {}KB",
                image.cluster_size / 1024,
                image.path.display(),
                MAX_CLUSTER_SIZE / 1024
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
    // For monolithicFlat output, the guest writes raw sectors and
    // the host writes the descriptor afterwards. Override target
    // format to Raw and derive the flat extent filename.
    let (effective_target_format, flat_extent_path) = if is_vmdk_flat_output {
        // Derive flat extent filename: "foo.vmdk" -> "foo-flat.vmdk"
        let out_path = Path::new(&args.output);
        let stem = out_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("output");
        let flat_name = format!("{stem}-flat.vmdk");
        let flat_path = out_path.with_file_name(&flat_name);
        (1u32, Some((flat_path, flat_name))) // ImageFormat::Raw
    } else {
        (target_format, None)
    };

    let is_structured_output =
        (is_qcow2_output || is_vmdk_output || is_vhd_output || is_vhdx_output)
            && !is_vmdk_flat_output;
    let output_capacity = if is_vhdx_output {
        // VHDX uses 32MB blocks — data is rounded up to block_size
        // boundaries, plus ~4MB metadata overhead (file identifier,
        // headers, region tables, log, BAT, metadata region).
        let vhdx_block: u64 = 32 * 1024 * 1024;
        virtual_size
            .div_ceil(vhdx_block)
            .saturating_mul(vhdx_block)
            .saturating_add(10 * 1024 * 1024)
    } else if is_structured_output {
        // QCOW2, VMDK, and VHD need headroom for metadata (tables,
        // headers, descriptor, BAT, alignment padding).
        virtual_size
            .saturating_add(virtual_size / 100)
            .saturating_add(10 * 1024 * 1024)
    } else {
        virtual_size
    };

    // For monolithicFlat, the output device is the flat extent file.
    let output_file_path = if let Some((ref flat_path, _)) = flat_extent_path {
        flat_path.clone()
    } else {
        Path::new(&args.output).to_path_buf()
    };

    let output_backing = if args.no_create {
        BackingStore::open(&output_file_path, false, None, false)?
    } else if is_structured_output {
        BackingStore::open(
            &output_file_path,
            false,
            Some(output_capacity),
            true, // always sparse for structured formats
        )?
    } else {
        BackingStore::open(
            &output_file_path,
            false,
            Some(virtual_size),
            // sparse when skipping zeros (default: true)
            skip_zeros,
        )?
    };

    debug!(
        "Output file: {} (capacity {} bytes)",
        output_file_path.display(),
        output_capacity
    );

    // Parse --max-guest-memory for LUKS v2 Argon2id support
    let guest_mem_size: u64 = if let Some(ref mem_str) = args.max_guest_memory {
        let requested = parse_memory_size(mem_str)?;
        if requested < GUEST_MEM_SIZE {
            return Err(format!(
                "--max-guest-memory must be at least {}MB (got {})",
                GUEST_MEM_SIZE / (1024 * 1024),
                mem_str
            )
            .into());
        }
        debug!("Using {requested} bytes of guest memory (--max-guest-memory {mem_str})");
        requested
    } else {
        GUEST_MEM_SIZE
    };

    // Open KVM
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    debug!("Created VM");

    let guest_mem = create_guest_memory(guest_mem_size)?;
    debug!("Allocated {guest_mem_size} bytes of guest memory");

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: guest_mem_size,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid GuestMemoryMmap
    // allocation that outlives the VM. The slot/guest_phys_addr are unique
    // per operation entry point. KVM requires this call to be unsafe but
    // the memory contract is satisfied.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{GDT_BASE:x}");

    setup_page_tables(&guest_mem, guest_mem_size)?;
    debug!("Set up page tables at 0x{PAGE_TABLE_BASE:x}");

    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{GUEST_CODE_BASE:x}");

    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{OPERATION_LOAD_ADDR:x}");

    // Write ConvertConfig at OPERATION_CONFIG_ADDR
    let mut convert_flags: u32 = 0;
    if skip_zeros {
        convert_flags |= CONVERT_CONFIG_FLAG_SKIP_ZEROS;
    }
    if args.compress {
        convert_flags |= CONVERT_CONFIG_FLAG_COMPRESS;
    }
    if verbose {
        convert_flags |= CONVERT_CONFIG_FLAG_VERBOSE;
    }
    if args.extended_l2 {
        convert_flags |= CONVERT_CONFIG_FLAG_EXTENDED_L2;
    }
    if luks_encrypt_passphrase.is_some() {
        convert_flags |= CONVERT_CONFIG_FLAG_ENCRYPT_LUKS;
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
    guest_mem.write_obj(
        effective_target_format,
        GuestAddress(OPERATION_CONFIG_ADDR + 12),
    )?;
    guest_mem.write_obj(
        output_cluster_bits,
        GuestAddress(OPERATION_CONFIG_ADDR + 16),
    )?;

    // Resolve QCOW2 AES passphrase (--qcow2-password or --qcow2-password-file)
    let qcow2_passphrase = if let Some(ref pass) = args.qcow2_password {
        Some(pass.clone())
    } else if let Some(ref path) = args.qcow2_password_file {
        let mut data = std::fs::read_to_string(path)?;
        if data.ends_with('\n') {
            data.pop();
        }
        Some(data)
    } else {
        None
    };

    // Resolve LUKS passphrase (--luks-passphrase or --luks-passphrase-file)
    let luks_passphrase = if let Some(ref pp) = args.luks_passphrase {
        Some(pp.clone())
    } else if let Some(ref path) = args.luks_passphrase_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read LUKS passphrase file '{path}': {e}"))?;
        Some(content.trim_end_matches('\n').to_string())
    } else {
        None
    };

    // Write passphrase to ConvertConfig (same field for both crypt_method=1 and =2)
    let effective_passphrase = qcow2_passphrase.or(luks_passphrase);
    if let Some(ref passphrase) = effective_passphrase {
        let pass_bytes = passphrase.as_bytes();
        if pass_bytes.len() > 256 {
            return Err("passphrase too long (max 256 bytes)".into());
        }
        guest_mem.write_obj(
            pass_bytes.len() as u32,
            GuestAddress(OPERATION_CONFIG_ADDR + 20),
        )?;
        // _pad at offset 24 is zero-initialized
        guest_mem.write_slice(pass_bytes, GuestAddress(OPERATION_CONFIG_ADDR + 28))?;
        debug!(
            "Wrote passphrase ({} bytes) to convert config",
            pass_bytes.len()
        );
    }

    // Write snapshot ID if specified
    if let Some(ref snapshot_id) = args.snapshot {
        let snap_bytes = snapshot_id.as_bytes();
        if snap_bytes.len() > 64 {
            return Err("Snapshot ID too long (max 64 bytes)".into());
        }
        // snapshot_id_len at offset 284 (28 + 256)
        guest_mem.write_obj(
            snap_bytes.len() as u32,
            GuestAddress(OPERATION_CONFIG_ADDR + 284),
        )?;
        // _pad2 at offset 288 is zero-initialized
        // snapshot_id at offset 292
        guest_mem.write_slice(snap_bytes, GuestAddress(OPERATION_CONFIG_ADDR + 292))?;
        debug!(
            "Wrote snapshot ID '{}' ({} bytes) to convert config",
            snapshot_id,
            snap_bytes.len()
        );
    }

    // Write argon2_mem_size to ConvertConfig (offset 360 = 292 + 64 + 4 pad)
    let argon2_mem_size: u64 = guest_mem_size.saturating_sub(GUEST_MEM_SIZE);
    guest_mem.write_obj(argon2_mem_size, GuestAddress(OPERATION_CONFIG_ADDR + 360))?;

    // Write LUKS encrypt config fields (offsets 368-391)
    if let Some(ref encrypt_pp) = luks_encrypt_passphrase {
        use rand::RngExt;
        let mut rng = rand::rng();

        let key_bytes: usize = 64; // AES-256-XTS
        let stripes: usize = 4000;
        let af_random_size = (stripes - 1) * key_bytes;

        // Generate random data: master_key(64) + mk_salt(32) + slot_salt(32) + uuid(36)
        let random_header_size = 64 + 32 + 32 + 36;
        let total_random = random_header_size + af_random_size;

        let mut random_data = vec![0u8; total_random];
        rng.fill(&mut random_data[..]);

        // Format UUID as ASCII hex (bytes 128..164)
        let uuid_offset = 64 + 32 + 32;
        let uuid_template = b"00000000-0000-4000-8000-000000000000";
        random_data[uuid_offset..uuid_offset + 36].copy_from_slice(uuid_template);
        // Fill UUID hex digits from separate random bytes (not master key)
        let hex_chars = b"0123456789abcdef";
        let mut uuid_rand = [0u8; 32];
        rng.fill(&mut uuid_rand[..]);
        let mut ri = 0usize;
        for i in 0..36 {
            let c = random_data[uuid_offset + i];
            if c == b'-' {
                continue;
            }
            // Use random byte for hex positions (skip version/variant bits)
            if i == 14 {
                random_data[uuid_offset + i] = b'4'; // version
            } else if i == 19 {
                random_data[uuid_offset + i] = hex_chars[(8 + (uuid_rand[ri] & 0x03)) as usize]; // variant
                ri += 1;
            } else {
                random_data[uuid_offset + i] = hex_chars[(uuid_rand[ri] & 0x0F) as usize];
                ri += 1;
            }
        }

        // Write passphrase into ConvertConfig passphrase field
        // (reuses the existing passphrase field for LUKS encrypt passphrase)
        let pp_bytes = encrypt_pp.as_bytes();
        let pp_len = pp_bytes.len().min(256);
        guest_mem.write_obj(pp_len as u32, GuestAddress(OPERATION_CONFIG_ADDR + 20))?;
        guest_mem.write_slice(
            &pp_bytes[..pp_len],
            GuestAddress(OPERATION_CONFIG_ADDR + 28),
        )?;

        // Write LUKS encrypt config fields
        guest_mem.write_obj(
            args.luks_encrypt_iterations,
            GuestAddress(OPERATION_CONFIG_ADDR + 368),
        )?;
        guest_mem.write_obj(key_bytes as u32, GuestAddress(OPERATION_CONFIG_ADDR + 372))?;
        let luks_data_addr = shared::LUKS_ENCRYPT_DATA_ADDR as u64;
        guest_mem.write_obj(luks_data_addr, GuestAddress(OPERATION_CONFIG_ADDR + 376))?;
        guest_mem.write_obj(
            total_random as u64,
            GuestAddress(OPERATION_CONFIG_ADDR + 384),
        )?;

        // Write random data to guest memory
        guest_mem.write_slice(&random_data, GuestAddress(luks_data_addr))?;

        debug!(
            "LUKS encrypt: key_bytes={}, iterations={}, random_data={}B at 0x{:x}",
            key_bytes, args.luks_encrypt_iterations, total_random, luks_data_addr
        );
    }

    // Write grain size and block size at offsets 392 and 396
    guest_mem.write_obj(args.grain_size, GuestAddress(OPERATION_CONFIG_ADDR + 392))?;
    guest_mem.write_obj(args.block_size, GuestAddress(OPERATION_CONFIG_ADDR + 396))?;

    debug!(
        "Wrote convert config at 0x{:x} \
         (flags=0x{:x}, chain={}, format={}, cluster_bits={}, \
         grain_size={}, block_size={}, argon2_mem_size={})",
        OPERATION_CONFIG_ADDR,
        convert_flags,
        input_device_count,
        target_format,
        output_cluster_bits,
        args.grain_size,
        args.block_size,
        argon2_mem_size,
    );

    // Write ChainConfig for input chain
    write_chain_config(&guest_mem, &chain)?;

    // Create device set: input chain devices + output device
    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    // Set up input chain devices (read-only), including data file if present
    open_chain_devices(
        &chain,
        args.sector_size as u64,
        &mut device_set,
        &mut io_events,
        0,
        "input",
    )?;

    // Set up output device (writable).
    // For compressed QCOW2/VMDK output, use 512-byte sectors so
    // compressed clusters/grains can be packed at sector granularity.
    // For uncompressed QCOW2, use min(sector_size, cluster_size)
    // so that cluster writes align to whole sectors.
    // For uncompressed VMDK and raw, use sector_size (VMDK GTEs
    // always reference 512-byte sectors internally).
    let output_sector_size = if (is_qcow2_output || is_vmdk_output) && args.compress {
        512
    } else if is_qcow2_output {
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
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }

    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            if let Err(e) = evt.unregister(&vm) {
                warn!("ioeventfd: failed to unregister during rollback: {e:?}");
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

    // Track VM errors and guest-reported convert success
    let mut vm_error: Option<String> = None;
    let mut convert_success = true;

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
                            // Track convert operation success from
                            // the completion message
                            if let Some(guest_::GuestMessage_::Payload::Complete(comp)) =
                                &msg.payload
                            {
                                if comp.operation == "convert" && !comp.success {
                                    convert_success = false;
                                }
                            }
                            debug!("{}", format_message(&msg));
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                eprintln!("VM Entry Failed! reason=0x{reason:x}, cpu={cpu}");
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {exit:?}");
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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

    if !convert_success {
        return Err("convert operation failed".into());
    }

    // For monolithicFlat output, write the descriptor file on the
    // host. The guest already wrote raw sectors to the flat extent
    // file; now we create the small text descriptor that points at
    // the flat file.
    if let Some((ref _flat_path, ref flat_name)) = flat_extent_path {
        let capacity_sectors = virtual_size / 512;
        let mut desc_buf = [0u8; 1024];
        let n =
            vmdk::build_flat_descriptor(&mut desc_buf, 0, capacity_sectors, flat_name.as_bytes());
        std::fs::write(&args.output, &desc_buf[..n])?;
        debug!(
            "Wrote monolithicFlat descriptor: {} ({} bytes)",
            args.output, n
        );
    }

    // For sparse raw output, truncate to virtual size so the
    // apparent file size matches the image's virtual size (same
    // as qemu-img convert behavior).
    if skip_zeros && !is_structured_output && flat_extent_path.is_none() {
        let f = std::fs::OpenOptions::new().write(true).open(&args.output)?;
        f.set_len(virtual_size)?;
    }

    // For monolithicFlat output, truncate the flat extent file to
    // the virtual size (matching qemu-img behavior).
    if let Some((ref flat_path, _)) = flat_extent_path {
        let f = std::fs::OpenOptions::new().write(true).open(flat_path)?;
        f.set_len(virtual_size)?;
    }

    Ok(())
}

/// Parsed values for the size-relevant subset of `-o key=value,...`.
/// Each field is `Some(v)` if the user explicitly supplied that key,
/// `None` otherwise. Applied last in run_measure (after individual
/// clap flags) so `-o` wins on conflict.
#[derive(Default, Debug)]
struct MeasureOptionOverrides {
    cluster_size: Option<u32>,
    refcount_bits: Option<u8>,
    extended_l2: Option<bool>,
    lazy_refcounts: Option<bool>,
    compat_v3: Option<bool>,
    compression_used: Option<bool>,
    preallocation: Option<&'static str>,
    vmdk_subformat: Option<u8>,
    grain_size: Option<u32>,
    vhd_subformat: Option<u8>,
    block_size: Option<u32>,
}

/// Parse a boolean value in qemu-img -o syntax. Accepts (case-insensitive):
/// on / off / true / false / yes / no. Other inputs return an error.
fn parse_o_bool(key: &str, value: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match value.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" => Ok(true),
        "off" | "false" | "no" => Ok(false),
        _ => Err(format!(
            "measure: bad value '{}' for -o key '{}' (expected on/off)",
            value, key
        )
        .into()),
    }
}

/// Parse a size value (K/M/G/T suffixes) and bounds-check to u32.
fn parse_o_size_u32(key: &str, value: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let n = parse_memory_size(value)
        .map_err(|e| format!("measure: bad size '{}' for -o key '{}' ({})", value, key, e))?;
    if n > u32::MAX as u64 {
        return Err(format!("measure: size {} for -o key '{}' exceeds u32::MAX", n, key).into());
    }
    Ok(n as u32)
}

/// Parse a decimal numeric value (u8).
fn parse_o_u8(key: &str, value: &str) -> Result<u8, Box<dyn std::error::Error>> {
    value
        .parse::<u8>()
        .map_err(|_| -> Box<dyn std::error::Error> {
            format!("measure: bad number '{}' for -o key '{}'", value, key).into()
        })
}

/// Parse a vector of `-o key=value,...` strings into a
/// MeasureOptionOverrides for the given target format.
///
/// Returns an error on unknown keys, invalid values, or unsupported
/// features. Last-wins for repeated keys across all `-o` invocations.
fn parse_o_options(
    target: &str,
    raw: &[String],
) -> Result<MeasureOptionOverrides, Box<dyn std::error::Error>> {
    let mut out = MeasureOptionOverrides::default();

    // Raw target rejects any -o.
    if target == "raw" && !raw.is_empty() {
        return Err("measure: raw output does not support -o options".into());
    }

    for input in raw {
        for piece in input.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let (key, value) = match piece.split_once('=') {
                Some((k, v)) => (k.trim(), v),
                None => {
                    return Err(format!(
                        "measure: -o option '{}' is missing a value (expected KEY=VALUE)",
                        piece
                    )
                    .into())
                }
            };

            // Per-target whitelist with explicit key handling.
            match (target, key) {
                // -------- qcow2 --------
                ("qcow2", "cluster_size") => {
                    out.cluster_size = Some(parse_o_size_u32(key, value)?);
                }
                ("qcow2", "compat") => match value {
                    "0.10" => out.compat_v3 = Some(false),
                    "1.1" => out.compat_v3 = Some(true),
                    _ => {
                        return Err(format!(
                            "measure: bad value '{}' for -o key 'compat' \
                            (expected 0.10 or 1.1)",
                            value
                        )
                        .into())
                    }
                },
                ("qcow2", "refcount_bits") => {
                    out.refcount_bits = Some(parse_o_u8(key, value)?);
                }
                ("qcow2", "extended_l2") => {
                    out.extended_l2 = Some(parse_o_bool(key, value)?);
                }
                ("qcow2", "lazy_refcounts") => {
                    out.lazy_refcounts = Some(parse_o_bool(key, value)?);
                }
                ("qcow2", "compression_type") => match value {
                    "zlib" | "zstd" => out.compression_used = Some(false),
                    _ => {
                        return Err(format!(
                            "measure: bad value '{}' for -o key 'compression_type'",
                            value
                        )
                        .into())
                    }
                },
                ("qcow2", "preallocation") => match value {
                    "off" => out.preallocation = Some("off"),
                    "metadata" => out.preallocation = Some("metadata"),
                    "falloc" => out.preallocation = Some("falloc"),
                    "full" => out.preallocation = Some("full"),
                    _ => {
                        return Err(format!(
                            "measure: bad value '{}' for -o key 'preallocation'",
                            value
                        )
                        .into())
                    }
                },

                // qcow2 reject list
                ("qcow2", "backing_file")
                | ("qcow2", "backing_fmt")
                | ("qcow2", "data_file")
                | ("qcow2", "data_file_raw") => {
                    return Err(format!(
                        "measure: -o key '{}' is not supported \
                        (chain/external-data measurement not implemented)",
                        key
                    )
                    .into());
                }
                ("qcow2", k) if k.starts_with("encrypt.") => {
                    return Err(format!(
                        "measure: -o key '{}' is not yet supported \
                        (LUKS-aware measurement is future work)",
                        k
                    )
                    .into());
                }

                // -------- vmdk --------
                ("vmdk", "subformat") => match value {
                    "monolithicSparse" => out.vmdk_subformat = Some(0),
                    "streamOptimized" => out.vmdk_subformat = Some(1),
                    "monolithicFlat" => out.vmdk_subformat = Some(2),
                    _ => {
                        return Err(format!(
                            "measure: bad value '{}' for -o key 'subformat' \
                            (expected monolithicSparse / streamOptimized / monolithicFlat)",
                            value
                        )
                        .into())
                    }
                },
                ("vmdk", "grain_size") => {
                    out.grain_size = Some(parse_o_size_u32(key, value)?);
                }
                ("vmdk", "adapter_type")
                | ("vmdk", "hwversion")
                | ("vmdk", "toolsversion")
                | ("vmdk", "zeroed_grain") => {
                    // accept-ignore — no size effect
                }

                // -------- vpc (VHD) --------
                ("vpc", "subformat") => match value {
                    "dynamic" => out.vhd_subformat = Some(0),
                    "fixed" => out.vhd_subformat = Some(1),
                    _ => {
                        return Err(format!(
                            "measure: bad value '{}' for -o key 'subformat' \
                            (expected dynamic or fixed)",
                            value
                        )
                        .into())
                    }
                },
                ("vpc", "force_size") | ("vpc", "force_size_calc") => {
                    // accept-ignore
                }

                // -------- vhdx --------
                ("vhdx", "subformat") => match value {
                    "dynamic" => { /* default */ }
                    "fixed" => {
                        return Err(
                            "measure: -O vhdx -o subformat=fixed is not yet supported".into()
                        );
                    }
                    _ => {
                        return Err(format!(
                            "measure: bad value '{}' for -o key 'subformat' \
                            (expected dynamic or fixed)",
                            value
                        )
                        .into())
                    }
                },
                ("vhdx", "block_size") => {
                    out.block_size = Some(parse_o_size_u32(key, value)?);
                }
                ("vhdx", "log_size") | ("vhdx", "block_state_zero") => {
                    // accept-ignore
                }

                // -------- catch-all: unknown key for this target --------
                _ => {
                    return Err(format!(
                        "measure: unrecognised -o key '{}' for target {}",
                        key, target
                    )
                    .into())
                }
            }
        }
    }

    Ok(out)
}

// ============================================================================
// Create -o key=value parsing
// ============================================================================

/// Overrides parsed from `-o` for the create operation.
///
/// Mirrors `MeasureOptionOverrides` in shape: every field is
/// `Option<T>` so "user didn't set this key" is distinguishable
/// from "user set it to the default value". Overrides win over
/// the matching individual flag (last-wins, matches measure and
/// qemu-img).
#[derive(Default, Debug)]
struct CreateOptionOverrides {
    cluster_size: Option<u32>,
    refcount_bits: Option<u8>,
    extended_l2: Option<bool>,
    lazy_refcounts: Option<bool>,
    compat_v3: Option<bool>,
    vmdk_subformat: Option<u8>,
    grain_size: Option<u32>,
    vhd_subformat: Option<u8>,
    block_size: Option<u32>,
    preallocation: Option<&'static str>,

    // Create-specific keys with no individual-flag analogue.
    size: Option<u64>,
    backing_file: Option<String>,
    backing_fmt: Option<&'static str>,
}

/// Boolean parser for `-o key=value` (create variant of measure's helper).
/// Accepts on/off/true/false/yes/no, case-insensitive.
fn parse_create_o_bool(key: &str, value: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match value.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" => Ok(true),
        "off" | "false" | "no" => Ok(false),
        _ => Err(format!(
            "create: bad value '{}' for -o key '{}' (expected on/off)",
            value, key
        )
        .into()),
    }
}

/// Parse a size value (K/M/G/T) and bounds-check to u32. Used for
/// cluster_size, grain_size, block_size, refcount-related fields.
fn parse_create_o_size_u32(key: &str, value: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let n = parse_memory_size(value)
        .map_err(|e| format!("create: bad size '{}' for -o key '{}' ({})", value, key, e))?;
    if n > u32::MAX as u64 {
        return Err(format!("create: size {} for -o key '{}' exceeds u32::MAX", n, key).into());
    }
    Ok(n as u32)
}

/// Parse a size value (K/M/G/T) as a u64 — used for `-o size=N`
/// where virtual disk sizes can comfortably exceed u32.
fn parse_create_o_size_u64(key: &str, value: &str) -> Result<u64, Box<dyn std::error::Error>> {
    parse_memory_size(value)
        .map_err(|e| format!("create: bad size '{}' for -o key '{}' ({})", value, key, e).into())
}

/// Parse a decimal u8 — used for refcount_bits.
fn parse_create_o_u8(key: &str, value: &str) -> Result<u8, Box<dyn std::error::Error>> {
    value
        .parse::<u8>()
        .map_err(|_| -> Box<dyn std::error::Error> {
            format!("create: bad number '{}' for -o key '{}'", value, key).into()
        })
}

/// Parse one or more qemu-img-style `-o KEY=VAL,KEY=VAL,...`
/// strings into a [`CreateOptionOverrides`] for the given target
/// format.
///
/// Returns an error on unknown keys, invalid values, or
/// not-yet-supported features. Repeated keys across all `-o`
/// invocations are last-wins.
fn parse_create_o_options(
    target: &str,
    raw: &[String],
) -> Result<CreateOptionOverrides, Box<dyn std::error::Error>> {
    let mut out = CreateOptionOverrides::default();

    for input in raw {
        for piece in input.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let (key, value) = match piece.split_once('=') {
                Some((k, v)) => (k.trim(), v),
                None => {
                    return Err(format!(
                        "create: -o option '{}' is missing a value (expected KEY=VALUE)",
                        piece
                    )
                    .into())
                }
            };

            match (target, key) {
                // -------- common keys (every non-raw target) --------
                (_, "size") => {
                    out.size = Some(parse_create_o_size_u64(key, value)?);
                }
                ("qcow2" | "vmdk" | "vpc" | "vhdx", "backing_file") => {
                    out.backing_file = Some(value.to_string());
                }
                ("qcow2" | "vmdk" | "vpc" | "vhdx", "backing_fmt") => {
                    out.backing_fmt = Some(match value {
                        "raw" => "raw",
                        "qcow2" => "qcow2",
                        "vmdk" => "vmdk",
                        "vpc" | "vhd" => "vpc",
                        "vhdx" => "vhdx",
                        _ => {
                            return Err(format!(
                                "create: bad value '{}' for -o key 'backing_fmt' \
                                 (expected raw, qcow2, vmdk, vpc, or vhdx)",
                                value
                            )
                            .into())
                        }
                    });
                }

                // -------- raw --------
                ("raw", "preallocation") => match value {
                    "off" => out.preallocation = Some("off"),
                    "falloc" => out.preallocation = Some("falloc"),
                    "full" => out.preallocation = Some("full"),
                    "metadata" => {
                        return Err("create: -o preallocation=metadata is not valid for raw \
                             (raw has no metadata to preallocate)"
                            .into())
                    }
                    _ => {
                        return Err(format!(
                            "create: bad value '{}' for -o key 'preallocation' \
                             (expected off, falloc, or full)",
                            value
                        )
                        .into())
                    }
                },

                // -------- qcow2 --------
                ("qcow2", "cluster_size") => {
                    out.cluster_size = Some(parse_create_o_size_u32(key, value)?);
                }
                ("qcow2", "compat") => match value {
                    "0.10" => out.compat_v3 = Some(false),
                    "1.1" => out.compat_v3 = Some(true),
                    _ => {
                        return Err(format!(
                            "create: bad value '{}' for -o key 'compat' \
                             (expected 0.10 or 1.1)",
                            value
                        )
                        .into())
                    }
                },
                ("qcow2", "refcount_bits") => {
                    out.refcount_bits = Some(parse_create_o_u8(key, value)?);
                }
                ("qcow2", "extended_l2") => {
                    out.extended_l2 = Some(parse_create_o_bool(key, value)?);
                }
                ("qcow2", "lazy_refcounts") => {
                    out.lazy_refcounts = Some(parse_create_o_bool(key, value)?);
                }
                ("qcow2", "compression_type") => match value {
                    // No CreateConfig flag bit yet — accept-ignore so qemu-img
                    // command lines copy-paste. Phase 6 may wire this through
                    // when preallocation lands.
                    "zlib" | "zstd" => {}
                    _ => {
                        return Err(format!(
                            "create: bad value '{}' for -o key 'compression_type' \
                             (expected zlib or zstd)",
                            value
                        )
                        .into())
                    }
                },
                ("qcow2", "preallocation") => match value {
                    "off" => out.preallocation = Some("off"),
                    "metadata" => out.preallocation = Some("metadata"),
                    "falloc" => out.preallocation = Some("falloc"),
                    "full" => out.preallocation = Some("full"),
                    _ => {
                        return Err(format!(
                            "create: bad value '{}' for -o key 'preallocation' \
                             (expected off, metadata, falloc, or full)",
                            value
                        )
                        .into())
                    }
                },

                // qcow2 reject list (data files / encryption deferred).
                ("qcow2", "data_file") | ("qcow2", "data_file_raw") => {
                    return Err(format!(
                        "create: -o key '{}' is not yet supported \
                         (external data files are deferred — see \
                         PLAN-convert-followups.md and PLAN-create.md future work)",
                        key
                    )
                    .into());
                }
                ("qcow2", k) if k.starts_with("encrypt.") => {
                    return Err(format!(
                        "create: -o key '{}' is not yet supported \
                         (encrypted create is deferred — see PLAN-create.md future work)",
                        k
                    )
                    .into());
                }

                // -------- vmdk --------
                ("vmdk", "subformat") => match value {
                    "monolithicSparse" => out.vmdk_subformat = Some(0),
                    "streamOptimized" => out.vmdk_subformat = Some(1),
                    "monolithicFlat" => out.vmdk_subformat = Some(2),
                    _ => {
                        return Err(format!(
                            "create: bad value '{}' for -o key 'subformat' \
                             (expected monolithicSparse / streamOptimized / monolithicFlat)",
                            value
                        )
                        .into())
                    }
                },
                ("vmdk", "grain_size") => {
                    out.grain_size = Some(parse_create_o_size_u32(key, value)?);
                }
                ("vmdk", "adapter_type")
                | ("vmdk", "hwversion")
                | ("vmdk", "toolsversion")
                | ("vmdk", "zeroed_grain") => {
                    // accept-ignore — no effect on the empty-image bytes
                    // we emit
                }

                // -------- vpc (VHD) --------
                ("vpc", "subformat") => match value {
                    "dynamic" => out.vhd_subformat = Some(0),
                    "fixed" => out.vhd_subformat = Some(1),
                    _ => {
                        return Err(format!(
                            "create: bad value '{}' for -o key 'subformat' \
                             (expected dynamic or fixed)",
                            value
                        )
                        .into())
                    }
                },
                ("vpc", "block_size") => {
                    out.block_size = Some(parse_create_o_size_u32(key, value)?);
                }
                ("vpc", "force_size") | ("vpc", "force_size_calc") => {
                    // accept-ignore
                }

                // -------- vhdx --------
                ("vhdx", "subformat") => match value {
                    "dynamic" => { /* default */ }
                    "fixed" => {
                        return Err("create: -O vhdx -o subformat=fixed is not yet supported \
                                    (vhdx-fixed lands in phase 5 of PLAN-create.md)"
                            .into())
                    }
                    _ => {
                        return Err(format!(
                            "create: bad value '{}' for -o key 'subformat' \
                             (expected dynamic or fixed)",
                            value
                        )
                        .into())
                    }
                },
                ("vhdx", "block_size") => {
                    out.block_size = Some(parse_create_o_size_u32(key, value)?);
                }
                ("vhdx", "log_size") | ("vhdx", "block_state_zero") => {
                    // accept-ignore
                }

                // -------- non-qcow2 preallocation: deferred --------
                ("vmdk" | "vpc" | "vhdx", "preallocation") => match value {
                    "off" => out.preallocation = Some("off"),
                    "metadata" | "falloc" | "full" => {
                        return Err(format!(
                            "create: -o preallocation={} is not yet supported for {} \
                             (non-qcow2 preallocation is future work — see PLAN-create.md)",
                            value, target
                        )
                        .into())
                    }
                    _ => {
                        return Err(format!(
                            "create: bad value '{}' for -o key 'preallocation' \
                             (expected off, metadata, falloc, or full)",
                            value
                        )
                        .into())
                    }
                },

                // -------- catch-all --------
                _ => {
                    return Err(format!(
                        "create: unrecognised -o key '{}' for target {} \
                         (run with --help for the accepted flag set; \
                         qemu-img -o keys map 1:1 to the --flag form)",
                        key, target
                    )
                    .into())
                }
            }
        }
    }

    Ok(out)
}

/// Run the measure operation (predict output size for a target format).
fn run_measure(args: MeasureArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Touch the result magic constant so its presence is preserved for
    // future host-side validation; the magic is also checked by the guest.
    let _ = MEASURE_RESULT_MAGIC;

    // --- Validate args ---------------------------------------------------
    if args.input.is_none() && args.size.is_none() {
        return Err("measure: either --size or FILENAME must be provided".into());
    }

    if !(512..=MAX_SECTOR_SIZE).contains(&args.sector_size) || !args.sector_size.is_power_of_two() {
        return Err(format!(
            "sector size must be a power of 2, 512 to {} (got {})",
            MAX_SECTOR_SIZE, args.sector_size
        )
        .into());
    }

    // Light host-side sanity checks for obvious bogus options. The guest
    // performs full validation against the target format; here we just
    // catch trivial mistakes early.
    if args.cluster_size != 0 && (args.cluster_size < 512 || !args.cluster_size.is_power_of_two()) {
        return Err(format!(
            "measure: --cluster-size must be a power of 2 >= 512 (got {})",
            args.cluster_size
        )
        .into());
    }
    if args.refcount_bits != 0 && !matches!(args.refcount_bits, 1 | 2 | 4 | 8 | 16 | 32 | 64) {
        return Err(format!(
            "measure: --refcount-bits must be one of 1,2,4,8,16,32,64 (got {})",
            args.refcount_bits
        )
        .into());
    }
    if args.grain_size != 0 && (args.grain_size < 512 || !args.grain_size.is_power_of_two()) {
        return Err(format!(
            "measure: --grain-size must be a power of 2 >= 512 (got {})",
            args.grain_size
        )
        .into());
    }
    if args.block_size != 0 && (args.block_size < 512 || !args.block_size.is_power_of_two()) {
        return Err(format!(
            "measure: --block-size must be a power of 2 >= 512 (got {})",
            args.block_size
        )
        .into());
    }

    // Map the target format string to the numeric ImageFormat. Clap
    // already restricts the accepted set; this is defence-in-depth.
    let target_format: u32 = match args.target_format.as_str() {
        "raw" => IMAGE_FORMAT_RAW,
        "qcow2" => IMAGE_FORMAT_QCOW2,
        "vmdk" => IMAGE_FORMAT_VMDK4,
        "vpc" => IMAGE_FORMAT_VHD,
        "vhdx" => IMAGE_FORMAT_VHDX,
        other => {
            return Err(format!("measure: unsupported target format '{}'", other).into());
        }
    };

    // Parse -o key=value options; last-wins and overrides individual flags.
    let overrides = parse_o_options(&args.target_format, &args.option)?;

    // Local mutable copies of per-format scalars so -o can override them.
    let mut cluster_size: u32 = args.cluster_size;
    let mut refcount_bits: u8 = args.refcount_bits;
    let mut extended_l2: bool = args.extended_l2;
    let mut lazy_refcounts: bool = args.lazy_refcounts;
    let mut compat_v3: bool = args.compat == "1.1";
    let mut compress: bool = args.compress;
    let mut preallocation_str: String = args.preallocation.clone();
    let mut grain_size: u32 = args.grain_size;
    let mut block_size: u32 = args.block_size;

    // Apply -o overrides (last-wins over individual flags).
    if let Some(v) = overrides.cluster_size {
        cluster_size = v;
    }
    if let Some(v) = overrides.refcount_bits {
        refcount_bits = v;
    }
    if let Some(v) = overrides.extended_l2 {
        extended_l2 = v;
    }
    if let Some(v) = overrides.lazy_refcounts {
        lazy_refcounts = v;
    }
    if let Some(v) = overrides.compat_v3 {
        compat_v3 = v;
    }
    if let Some(v) = overrides.compression_used {
        compress = v;
    }
    if let Some(prealloc) = overrides.preallocation {
        preallocation_str = prealloc.to_string();
    }
    if let Some(v) = overrides.grain_size {
        grain_size = v;
    }
    if let Some(v) = overrides.block_size {
        block_size = v;
    }

    // Resolve flags + per-format byte fields from local (possibly overridden) values.
    let mut measure_flags: u32 = 0;
    if extended_l2 {
        measure_flags |= MEASURE_CONFIG_FLAG_EXTENDED_L2;
    }
    if lazy_refcounts {
        measure_flags |= MEASURE_CONFIG_FLAG_LAZY_REFCOUNTS;
    }
    // qcow2 compat: default is v3 (1.1). v2 (0.10) clears the bit.
    if compat_v3 {
        measure_flags |= MEASURE_CONFIG_FLAG_COMPAT_V3;
    }
    if compress {
        measure_flags |= MEASURE_CONFIG_FLAG_COMPRESS;
    }
    let prealloc_bits: u32 = match preallocation_str.as_str() {
        "" | "off" => MEASURE_CONFIG_PREALLOC_OFF,
        "metadata" => MEASURE_CONFIG_PREALLOC_METADATA,
        "falloc" => MEASURE_CONFIG_PREALLOC_FALLOC,
        "full" => MEASURE_CONFIG_PREALLOC_FULL,
        other => {
            return Err(format!("measure: unsupported preallocation mode '{}'", other).into());
        }
    };
    measure_flags |= prealloc_bits;

    let mut vmdk_subformat: u8 = match args.subformat.as_str() {
        "" | "monolithicSparse" => 0,
        "streamOptimized" => 1,
        "monolithicFlat" => 2,
        other => {
            return Err(format!("measure: unsupported vmdk subformat '{}'", other).into());
        }
    };
    if let Some(v) = overrides.vmdk_subformat {
        vmdk_subformat = v;
    }
    let mut vhd_subformat: u8 = 0; // Dynamic only in phase 4.
    if let Some(v) = overrides.vhd_subformat {
        vhd_subformat = v;
    }

    // Resolve --size into a u64 virtual size override; 0 means "scan source".
    let virtual_size_override: u64 = if let Some(ref s) = args.size {
        parse_memory_size(s)?
    } else {
        0
    };

    // --- VMDK monolithicFlat source rejection (FILENAME mode only) -------
    if let Some(ref input_str) = args.input {
        let input_path = Path::new(input_str);
        if peek_is_vmdk_descriptor(input_path).unwrap_or(false) {
            return Err(
                "measure: monolithicFlat source images are not yet supported \
                 (use convert -f / qemu-img instead)"
                    .into(),
            );
        }
    }

    // --- Load guest binaries --------------------------------------------
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("measure.bin");

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

    // --- KVM / VM / guest memory setup ----------------------------------
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    debug!("Created VM");

    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    debug!("Allocated {GUEST_MEM_SIZE} bytes of guest memory");

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid GuestMemoryMmap
    // allocation that outlives the VM. The slot/guest_phys_addr are unique
    // per operation entry point.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    setup_gdt(&guest_mem)?;
    debug!("Set up GDT at 0x{GDT_BASE:x}");

    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    debug!("Set up page tables at 0x{PAGE_TABLE_BASE:x}");

    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    debug!("Loaded core binary at 0x{GUEST_CODE_BASE:x}");

    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    debug!("Loaded operation binary at 0x{OPERATION_LOAD_ADDR:x}");

    // --- Write MeasureConfig (per-field at known offsets) ---------------
    // Layout (must match shared::MeasureConfig exactly, 56 bytes total):
    //   0:  magic               u32
    //   4:  target_format       u32
    //   8:  flags               u32
    //  12:  sector_size         u32
    //  16:  virtual_size_override u64
    //  24:  qcow2_cluster_size  u32
    //  28:  qcow2_refcount_bits u8
    //  29:  vmdk_subformat      u8
    //  30:  _pad2               u16
    //  32:  vmdk_grain_size     u32
    //  36:  vhd_subformat       u8
    //  37:  _pad3               [u8; 3]
    //  40:  block_size          u32
    //  44:  _pad4               u32
    //  48:  luks_header_overhead u64
    guest_mem.write_obj(MEASURE_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(target_format, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(measure_flags, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(args.sector_size, GuestAddress(OPERATION_CONFIG_ADDR + 12))?;
    guest_mem.write_obj(
        virtual_size_override,
        GuestAddress(OPERATION_CONFIG_ADDR + 16),
    )?;
    guest_mem.write_obj(cluster_size, GuestAddress(OPERATION_CONFIG_ADDR + 24))?;
    guest_mem.write_obj(refcount_bits, GuestAddress(OPERATION_CONFIG_ADDR + 28))?;
    guest_mem.write_obj(vmdk_subformat, GuestAddress(OPERATION_CONFIG_ADDR + 29))?;
    // _pad2 (offset 30, u16) intentionally left zero from page-zeroed memory.
    guest_mem.write_obj(grain_size, GuestAddress(OPERATION_CONFIG_ADDR + 32))?;
    guest_mem.write_obj(vhd_subformat, GuestAddress(OPERATION_CONFIG_ADDR + 36))?;
    // _pad3 (offsets 37..40) left zero.
    guest_mem.write_obj(block_size, GuestAddress(OPERATION_CONFIG_ADDR + 40))?;
    // _pad4 (offset 44, u32) left zero.
    // luks_header_overhead (offset 48): phase 4 does not expose LUKS measure;
    // leave at zero (no LUKS overhead added).
    debug!(
        "Wrote measure config at 0x{:x} (target={}, flags=0x{:x}, sector_size={}, \
         virtual_size_override={}, cluster_size={}, refcount_bits={}, \
         vmdk_subformat={}, grain_size={}, vhd_subformat={}, block_size={})",
        OPERATION_CONFIG_ADDR,
        target_format,
        measure_flags,
        args.sector_size,
        virtual_size_override,
        cluster_size,
        refcount_bits,
        vmdk_subformat,
        grain_size,
        vhd_subformat,
        block_size,
    );

    // --- Set up source device 0 -----------------------------------------
    // For FILENAME mode the source is the user's image. For --size mode
    // the guest short-circuits the scan path on virtual_size_override != 0
    // and never reads the device, but core's boot path still expects
    // device 0 to be present, so we attach a tiny tempfile as a stub.
    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    // Keep the stub file (if any) alive for the duration of the run so the
    // backing path remains valid until the VM exits. SizeModeStub deletes
    // its backing path on drop.
    struct SizeModeStub(std::path::PathBuf);
    impl Drop for SizeModeStub {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _size_mode_stub: Option<SizeModeStub>;

    let (input_path_buf, input_size) = if let Some(ref input_str) = args.input {
        let p = std::path::PathBuf::from(input_str);
        let md = std::fs::metadata(&p)?;
        let sz = md.len();
        _size_mode_stub = None;
        (p, sz)
    } else {
        // --size mode: create a 1-sector stub file as device 0. The guest's
        // measure binary short-circuits the scan path on
        // virtual_size_override != 0, so the device is never read; core's
        // boot path only needs the device to exist with a valid capacity.
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("instar-measure-stub-{}-{}", pid, nanos));
        let f = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&p)?;
        f.set_len(args.sector_size as u64)?;
        drop(f);
        let sz = args.sector_size as u64;
        _size_mode_stub = Some(SizeModeStub(p.clone()));
        (p, sz)
    };

    let input_backing = BackingStore::open(&input_path_buf, true, None, false)?;
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
        "Created source virtio-block device at MMIO 0x{input_mmio:x}, VQ 0x{input_vq:x} ({} bytes)",
        input_size
    );
    let input_device = Arc::new(Mutex::new(input_device));
    device_set.add_device(Arc::clone(&input_device), true);
    io_events.push(IoEvent::new(input_mmio)?);

    // Wrap guest memory in Arc for sharing with the I/O thread.
    let guest_mem = Arc::new(guest_mem);

    // Shared statistics tracker.
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Try to register ioeventfds; fall back to VM exits on failure.
    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }
    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            if let Err(e) = evt.unregister(&vm) {
                warn!("ioeventfd: failed to unregister during rollback: {e:?}");
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

    // --- vCPU setup ------------------------------------------------------
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

    // --- Serial decoders / transmitter / debug buffer -------------------
    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();

    let config = vmm_config_input_only(args.sector_size);
    serial_transmitter.queue_config(&config);
    debug!(
        "Queued configuration message ({} bytes) for guest",
        serial_transmitter.buffer.len()
    );

    // --- Run the vCPU loop ----------------------------------------------
    let mut measure_error: u32 = MEASURE_RESULT_ERROR_OK;
    let mut measure_result_seen = false;
    let mut vm_error: Option<String> = None;

    debug!("Starting guest execution");

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                info!("Guest executed HLT");
                debug!("Measure operation completed");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            let is_measure_result = matches!(
                                &msg.payload,
                                Some(guest_::GuestMessage_::Payload::MeasureResult(_))
                            );
                            if is_measure_result {
                                if let Some(guest_::GuestMessage_::Payload::MeasureResult(m)) =
                                    &msg.payload
                                {
                                    measure_error = m.error;
                                    measure_result_seen = true;
                                }
                                // qemu-img emits "bitmaps" only when the source
                                // is qcow2 v3 (persistent bitmaps are a v3
                                // feature; qcow2 v2 sources do not emit the
                                // field even though they share the magic).
                                let target_qcow2_with_qcow2v3_source = args.target_format
                                    == "qcow2"
                                    && args.input.as_deref().is_some_and(peek_is_qcow2_v3);
                                print_measure_result(
                                    &msg,
                                    &args.output,
                                    target_qcow2_with_qcow2v3_source,
                                );
                            } else if verbose {
                                debug!("{}", format_message(&msg));
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                eprintln!("VM Entry Failed! reason=0x{reason:x}, cpu={cpu}");
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {exit:?}");
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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

    if !measure_result_seen {
        return Err("measure: guest did not return a result".into());
    }

    if measure_error != MEASURE_RESULT_ERROR_OK {
        let detail = match measure_error {
            MEASURE_RESULT_ERROR_OVERFLOW => "overflow computing target size",
            MEASURE_RESULT_ERROR_INVALID_OPTION => "invalid option for target format",
            MEASURE_RESULT_ERROR_INVALID_SIZE => "source image is unsupported format",
            _ => "unknown error",
        };
        return Err(format!("measure failed: {}", detail).into());
    }

    Ok(())
}

/// Entry point for the `map` subcommand.
///
/// Streams the source image's allocation map by launching the
/// `map.bin` guest binary with a populated `MapConfig` and
/// consuming `MapExtentMessage` records followed by a
/// terminating `MapResultMessage`. Phase 3 ships a working
/// CLI with a placeholder renderer (step 3c); phase 4 polishes
/// the renderer to byte-for-byte qemu-img parity.
fn run_map(args: MapArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // --- Validate args ---------------------------------------------------
    if args.image_opts {
        return Err(
            "map: --image-opts is not supported (instar accepts FILENAME directly; \
             see docs/quirks.md)"
                .into(),
        );
    }

    if !(512..=MAX_SECTOR_SIZE).contains(&args.sector_size) || !args.sector_size.is_power_of_two() {
        return Err(format!(
            "sector size must be a power of 2, 512 to {} (got {})",
            MAX_SECTOR_SIZE, args.sector_size
        )
        .into());
    }

    // --- VMDK monolithicFlat source rejection ----------------------------
    // The guest's VmdkState::init naturally fails the VMDK4 binary header
    // parse for descriptor-driven layouts, but the resulting
    // ERROR_INVALID_SOURCE is less helpful than this host-side pre-check
    // pointing at qemu-img as an escape hatch.
    let input_path = Path::new(&args.input);
    if peek_is_vmdk_descriptor(input_path).unwrap_or(false) {
        return Err("map: monolithicFlat source images are not yet supported \
             (use qemu-img map instead)"
            .into());
    }

    // --- Resolve window bytes --------------------------------------------
    let start_offset: u64 = if let Some(ref s) = args.start_offset {
        parse_memory_size(s)?
    } else {
        0
    };
    let max_length: u64 = if let Some(ref s) = args.max_length {
        parse_memory_size(s)?
    } else {
        0
    };

    // Read the source file metadata to size the virtio device,
    // but do NOT pre-check start_offset against the file size:
    // for sparse qcow2 the on-disk file size is smaller than the
    // virtual size that start_offset is measured against. The
    // guest's clip_to_window silently emits nothing if
    // start_offset >= virtual_size, matching qemu-img map's
    // behaviour (verified against qemu-img 10.0.8: past-EOF
    // start-offset returns rc=0 with just the header / empty
    // JSON array).
    let input_meta = std::fs::metadata(input_path)?;
    let input_size = input_meta.len();

    // --- Load guest binaries --------------------------------------------
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("map.bin");

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

    // --- KVM / VM / guest memory setup ----------------------------------
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    debug!("Created VM");

    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    debug!("Allocated {GUEST_MEM_SIZE} bytes of guest memory");

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid GuestMemoryMmap
    // allocation that outlives the VM. The slot/guest_phys_addr are unique
    // per operation entry point.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    setup_gdt(&guest_mem)?;
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;

    // --- Write MapConfig (per-field at known offsets) --------------------
    // Layout must match shared::MapConfig exactly (64 bytes total):
    //   0:  magic                 u32
    //   4:  flags                 u32
    //   8:  sector_size           u32
    //  12:  input_device_count    u32  (always 1 in v1)
    //  16:  start_offset          u64
    //  24:  max_length            u64
    //  32..64: _reserved          [u8; 32]  (left zero from page-zeroed memory)
    let map_flags: u32 = if verbose { MAP_CONFIG_FLAG_VERBOSE } else { 0 };
    guest_mem.write_obj(MAP_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(map_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(args.sector_size, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(1u32, GuestAddress(OPERATION_CONFIG_ADDR + 12))?;
    guest_mem.write_obj(start_offset, GuestAddress(OPERATION_CONFIG_ADDR + 16))?;
    guest_mem.write_obj(max_length, GuestAddress(OPERATION_CONFIG_ADDR + 24))?;
    debug!(
        "Wrote map config at 0x{:x} (sector_size={}, start_offset={}, max_length={})",
        OPERATION_CONFIG_ADDR, args.sector_size, start_offset, max_length
    );

    // --- Set up source device 0 (read-only) -----------------------------
    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    let input_backing = BackingStore::open(input_path, true, None, false)?;
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
        "Created source virtio-block device at MMIO 0x{input_mmio:x}, VQ 0x{input_vq:x} ({} bytes)",
        input_size
    );
    let input_device = Arc::new(Mutex::new(input_device));
    device_set.add_device(Arc::clone(&input_device), true);
    io_events.push(IoEvent::new(input_mmio)?);

    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Register ioeventfds; fall back to VM exits on failure.
    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }
    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            if let Err(e) = evt.unregister(&vm) {
                warn!("ioeventfd: failed to unregister during rollback: {e:?}");
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

    // --- vCPU setup ------------------------------------------------------
    let mut vcpu = vm.create_vcpu(0)?;
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;

    // --- Serial decoders / transmitter / debug buffer -------------------
    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();

    let config = vmm_config_input_only(args.sector_size);
    serial_transmitter.queue_config(&config);
    debug!(
        "Queued configuration message ({} bytes) for guest",
        serial_transmitter.buffer.len()
    );

    // --- Run the vCPU loop ----------------------------------------------
    // Phase 4 streams each extent to stdout via MapRenderer as the
    // guest sends it; host memory stays O(1) regardless of how
    // fragmented the source is. The renderer's `begin()` writes the
    // header / opening "[" before the first extent arrives, so a
    // partial table on guest failure is the trade-off for keeping
    // the streaming path clean (documented in docs/quirks.md).
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    let mut renderer = MapRenderer::new(&mut writer, &args.output, args.input.clone());
    renderer.begin()?;

    let mut map_result: Option<guest_::MapResultMessage> = None;
    let mut vm_error: Option<String> = None;
    // Set to `true` once stdout has closed (e.g. user piped into
    // `head`). Subsequent extent emits become no-ops so we exit
    // cleanly without spamming BrokenPipe errors.
    let mut broken_pipe = false;

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                debug!("Map operation completed");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            match &msg.payload {
                                Some(guest_::GuestMessage_::Payload::MapExtent(e)) => {
                                    if !broken_pipe {
                                        match renderer.emit_extent(e) {
                                            Ok(()) => {}
                                            Err(err)
                                                if err.kind() == std::io::ErrorKind::BrokenPipe =>
                                            {
                                                // Downstream consumer closed
                                                // (head, less etc.). Stop
                                                // emitting; exit cleanly.
                                                broken_pipe = true;
                                            }
                                            Err(err) => return Err(err.into()),
                                        }
                                    }
                                }
                                Some(guest_::GuestMessage_::Payload::MapResult(r)) => {
                                    map_result = Some(r.clone());
                                }
                                _ => {
                                    if verbose {
                                        debug!("{}", format_message(&msg));
                                    }
                                }
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                eprintln!("VM Entry Failed! reason=0x{reason:x}, cpu={cpu}");
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {exit:?}");
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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

    // BrokenPipe short-circuit: the downstream consumer closed
    // before the guest finished. Skip the renderer's finish() (the
    // closing "]" would just fail again) and exit Ok so the
    // process status mirrors coreutils' behaviour for piped output.
    if broken_pipe {
        return Ok(());
    }

    let result = map_result.ok_or_else(|| "map: guest returned no MapResult".to_string())?;

    // Render: success path closes the streaming output via
    // renderer.finish(); error path writes a clear stderr message
    // and leaves any partial output in place.
    if let Some(msg) = map_error_message(result.error) {
        eprintln!("{}", msg);
        return Err(format!("map: guest reported error code {}", result.error).into());
    }
    renderer.finish()?;
    // Drop the BufWriter so its destructor flushes to stdout.
    drop(renderer);
    drop(writer);

    Ok(())
}

/// Translate a guest-side state code (the string sent in
/// `MapExtentMessage::state`) to the (present, zero, data,
/// emit_offset) tuple used by qemu-img map's JSON output.
///
/// "hole" → unallocated, reads as zero, no backing data.
/// "zero" → explicit zero record in metadata, no backing data.
/// "data" → present, contains data, emit `offset` in JSON.
fn map_state_triple(state: &str) -> (bool, bool, bool, bool) {
    match state {
        "hole" => (false, true, false, false),
        "zero" => (true, true, false, false),
        "data" => (true, false, true, true),
        // Defensive fallback for an unknown state code (the guest
        // emits only the three above). Treat as data so the offset
        // is preserved for debugging.
        _ => (true, false, true, true),
    }
}

/// Resolve a `MapResult::error` code to a stderr-friendly message.
/// Returns `None` for `ERROR_OK` (the caller renders the success
/// path instead).
fn map_error_message(error: u32) -> Option<&'static str> {
    match error {
        MAP_RESULT_ERROR_OK => None,
        MAP_RESULT_ERROR_INVALID_SOURCE => Some("map: source format unrecognised"),
        MAP_RESULT_ERROR_INVALID_OPTION => Some("map: invalid config"),
        MAP_RESULT_ERROR_HAS_BACKING => Some(
            "map: source has a backing/parent reference; \
             chain composition is deferred (see PLAN-map.md)",
        ),
        MAP_RESULT_ERROR_IO => Some("map: I/O failure walking the source"),
        _ => Some("map: unknown error"),
    }
}

/// Output format selector for [`MapRenderer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MapOutputFormat {
    Human,
    Json,
}

/// Streaming renderer for `instar map` output.
///
/// Phase 4 replaces the phase 3c `Vec`-buffered renderer with a
/// streaming writer that emits one extent at a time as the guest
/// sends it. Host memory stays O(1) regardless of how fragmented
/// the source is. Byte-for-byte output matches `qemu-img map`
/// modulo the documented divergences (see `docs/quirks.md`).
///
/// Lifecycle:
/// - [`MapRenderer::begin`] is called once before the first
///   `emit_extent` to write the format-specific header / opening
///   bracket.
/// - [`MapRenderer::emit_extent`] is called once per
///   `MapExtentMessage` arriving from the guest. Human mode emits
///   a row only for `data: true` extents; JSON mode emits every
///   extent.
/// - [`MapRenderer::finish`] is called once after the guest's
///   `MapResultMessage` arrives (and signals success) to write
///   the closing bracket.
///
/// The renderer's `extents_written` counter tracks rows actually
/// emitted (human mode skips holes / zero-allocated; the guest's
/// `MapResultMessage::extents_emitted` is a different number used
/// for the streaming-protocol audit).
struct MapRenderer<'a, W: std::io::Write> {
    writer: &'a mut W,
    output_format: MapOutputFormat,
    /// The argv string the user passed for the source. Used
    /// verbatim in the human-mode "File" column; qemu-img echoes
    /// whatever was on the command line (relative paths stay
    /// relative, etc.).
    filename: String,
    /// True until the first JSON object is emitted. Drives the
    /// `,\n` inter-object separator.
    first_extent_json: bool,
    /// Count of rows / objects this renderer has actually written
    /// (lower than the guest's `extents_emitted` in human mode
    /// because holes are skipped).
    extents_written: u64,
}

impl<'a, W: std::io::Write> MapRenderer<'a, W> {
    fn new(writer: &'a mut W, output_format: &str, filename: String) -> Self {
        let fmt = match output_format {
            "json" => MapOutputFormat::Json,
            _ => MapOutputFormat::Human,
        };
        Self {
            writer,
            output_format: fmt,
            filename,
            first_extent_json: true,
            extents_written: 0,
        }
    }

    /// Write the format-specific header / opening bracket. Called
    /// once before any `emit_extent`.
    fn begin(&mut self) -> std::io::Result<()> {
        match self.output_format {
            MapOutputFormat::Human => writeln!(
                self.writer,
                "Offset          Length          Mapped to       File"
            ),
            MapOutputFormat::Json => write!(self.writer, "["),
        }
    }

    /// Write one extent's representation. Human mode emits a row
    /// only when `data: true`; JSON mode emits every extent with
    /// the qemu-img-compatible field set.
    fn emit_extent(&mut self, ext: &guest_::MapExtentMessage) -> std::io::Result<()> {
        let (present, zero, data, has_offset) = map_state_triple(&ext.state);
        match self.output_format {
            MapOutputFormat::Human => {
                if !data {
                    // Holes and zero-allocated extents do not
                    // produce visible rows (matches qemu-img).
                    return Ok(());
                }
                let start_str = format_hex_or_zero(ext.start);
                let length_str = format_hex_or_zero(ext.length);
                let mapped_str = format_hex_or_zero(ext.file_offset);
                writeln!(
                    self.writer,
                    "{:<16}{:<16}{:<16}{}",
                    start_str, length_str, mapped_str, self.filename
                )?;
                self.extents_written += 1;
                Ok(())
            }
            MapOutputFormat::Json => {
                if !self.first_extent_json {
                    writeln!(self.writer, ",")?;
                }
                self.first_extent_json = false;
                if has_offset {
                    write!(
                        self.writer,
                        "{{ \"start\": {}, \"length\": {}, \"depth\": 0, \
                         \"present\": {}, \"zero\": {}, \"data\": {}, \
                         \"compressed\": false, \"offset\": {}}}",
                        ext.start, ext.length, present, zero, data, ext.file_offset
                    )?;
                } else {
                    write!(
                        self.writer,
                        "{{ \"start\": {}, \"length\": {}, \"depth\": 0, \
                         \"present\": {}, \"zero\": {}, \"data\": {}, \
                         \"compressed\": false}}",
                        ext.start, ext.length, present, zero, data
                    )?;
                }
                self.extents_written += 1;
                Ok(())
            }
        }
    }

    /// Write the format-specific closing bracket. Called once
    /// after the last `emit_extent` and only on the success path
    /// (on error, the caller writes a stderr message instead and
    /// leaves the partial output in place).
    ///
    /// JSON mode emits `]\n` (closing bracket followed by a
    /// trailing newline) to match qemu-img map exactly. Human mode
    /// is a no-op — the last data row's `writeln!` already
    /// produced its own trailing newline.
    fn finish(&mut self) -> std::io::Result<()> {
        match self.output_format {
            MapOutputFormat::Human => Ok(()),
            MapOutputFormat::Json => writeln!(self.writer, "]"),
        }
    }
}

/// Format a `u64` as the literal string `"0"` for zero values,
/// otherwise as lowercase `0x...` hex. Matches qemu-img map's
/// human-mode column formatting: the first row of a freshly-
/// allocated qcow2 emits `0` (not `0x0`) for the offset, and
/// subsequent rows use `0x...`.
fn format_hex_or_zero(n: u64) -> String {
    if n == 0 {
        "0".to_string()
    } else {
        format!("{:#x}", n)
    }
}

// ================================================================
// Snapshot subcommand (PLAN-snapshot phase 4).
//
// Phase 4 ships list mode (`instar snapshot -l`). Phases 6–8
// landed the mutating modes (-c/-d/-a). Phase 9 adds:
//   D1: `-U` with mutating modes refused before any file access.
//   D2: bare `instar snapshot FILE` defaults to list.
// ================================================================

/// Entry point for the `snapshot` subcommand.
fn run_snapshot(args: SnapshotArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    if args.image_opts {
        return Err(
            "snapshot: --image-opts is not supported (instar accepts FILENAME directly; \
             see docs/quirks.md)"
                .into(),
        );
    }

    if !(512..=MAX_SECTOR_SIZE).contains(&args.sector_size) || !args.sector_size.is_power_of_two() {
        return Err(format!(
            "sector size must be a power of 2, 512 to {} (got {})",
            MAX_SECTOR_SIZE, args.sector_size
        )
        .into());
    }

    // Format override (qemu-img -f). Snapshots only exist in qcow2;
    // anything else is refused with the qemu-equivalent message.
    if let Some(ref f) = args.format {
        if f != "qcow2" {
            return Err(format!(
                "snapshot: format driver '{}' does not support image snapshots \
                 (qcow2 only)",
                f
            )
            .into());
        }
    }

    // D1 (PLAN-snapshot-phase-09): `-U` (--force-share) is only safe
    // with read-only operations. qemu refuses `-U` combined with any
    // mutating mode with exit 1 ("force-share=on can only be used with
    // read-only images"); instar matches that substance here, before
    // any file access, image untouched. `-U -l` (and the bare-filename
    // default, which resolves to list) is accepted — instar takes no
    // image locks, so the flag is a no-op for the read path.
    if args.force_share && (args.create.is_some() || args.delete.is_some() || args.apply.is_some())
    {
        return Err(
            "snapshot: --force-share (-U) can only be used with read-only \
             operations; -l is the only sharing-safe mode"
                .into(),
        );
    }

    // Mode selection. D2 (PLAN-snapshot-phase-09): bare `instar
    // snapshot FILE` (no mode flag) defaults to list, matching
    // `qemu-img snapshot` which documents `-l` as "the default".
    // The clap ArgGroup is `required = false` so this path is
    // reachable; an absent mode resolves to list here, dispatching
    // to the real list path (not a reimplementation).
    if let Some(name) = args.create.clone() {
        return run_snapshot_create(&args, &name, verbose);
    }
    if let Some(needle) = args.delete.clone() {
        return run_snapshot_delete(&args, &needle, verbose);
    }
    if let Some(needle) = args.apply.clone() {
        return run_snapshot_apply(&args, &needle, verbose);
    }
    // Explicit `-l` or bare filename (no mode flag): both resolve to list.
    run_snapshot_list(&args, verbose)
}

/// Drive `MODE_LIST` end-to-end: launch the guest, consume
/// `SnapshotEntryMessage` records as they stream in, capture the
/// terminating `SnapshotResultMessage`, and render to stdout via
/// [`SnapshotRenderer`]. Modelled on `run_map`.
fn run_snapshot_list(args: &SnapshotArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = Path::new(&args.filename);
    let input_meta = std::fs::metadata(input_path)?;
    let input_size = input_meta.len();

    // --- Load guest binaries --------------------------------------------
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("snapshot.bin");

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

    // --- KVM / VM / guest memory setup ----------------------------------
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    debug!("Created VM");

    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    debug!("Allocated {GUEST_MEM_SIZE} bytes of guest memory");

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid
    // GuestMemoryMmap allocation that outlives the VM. The slot /
    // guest_phys_addr are unique per operation entry point.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    setup_gdt(&guest_mem)?;
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;

    // --- Write SnapshotConfig (per-field at known offsets) --------------
    // Layout must match shared::SnapshotConfig exactly (312 bytes total):
    //   0:   magic        u32
    //   4:   mode         u32
    //   8:   flags        u32
    //   12:  sector_size  u32
    //   16:  arg_len      u32
    //   20:  _pad         u32
    //   24..280:  arg       [u8; 256]
    //   280: date_sec     u32   (MODE_CREATE only; zero for list)
    //   284: date_nsec    u32   (MODE_CREATE only; zero for list)
    //   288..312: _reserved [u8; 24]
    // For MODE_LIST, arg_len = 0 and arg / date_* are left
    // page-zeroed (guest memory is zero-initialised).
    let mut snapshot_flags: u32 = 0;
    if verbose {
        snapshot_flags |= SNAPSHOT_CONFIG_FLAG_VERBOSE;
    }
    if args.quiet {
        snapshot_flags |= SNAPSHOT_CONFIG_FLAG_QUIET;
    }
    if args.force_share {
        snapshot_flags |= SNAPSHOT_CONFIG_FLAG_FORCE_SHARE;
    }
    guest_mem.write_obj(SNAPSHOT_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(
        SNAPSHOT_CONFIG_MODE_LIST,
        GuestAddress(OPERATION_CONFIG_ADDR + 4),
    )?;
    guest_mem.write_obj(snapshot_flags, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(args.sector_size, GuestAddress(OPERATION_CONFIG_ADDR + 12))?;
    guest_mem.write_obj(0u32, GuestAddress(OPERATION_CONFIG_ADDR + 16))?;
    guest_mem.write_obj(0u32, GuestAddress(OPERATION_CONFIG_ADDR + 20))?;
    debug!(
        "Wrote snapshot config at 0x{:x} (mode=LIST, sector_size={}, flags=0x{:x})",
        OPERATION_CONFIG_ADDR, args.sector_size, snapshot_flags
    );

    // --- Set up source device 0 (read-only) -----------------------------
    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    let input_backing = BackingStore::open(input_path, true, None, false)?;
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
        "Created source virtio-block device at MMIO 0x{input_mmio:x}, \
         VQ 0x{input_vq:x} ({} bytes)",
        input_size
    );
    let input_device = Arc::new(Mutex::new(input_device));
    device_set.add_device(Arc::clone(&input_device), true);
    io_events.push(IoEvent::new(input_mmio)?);

    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }
    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            if let Err(e) = evt.unregister(&vm) {
                warn!("ioeventfd: failed to unregister during rollback: {e:?}");
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

    // --- vCPU setup ------------------------------------------------------
    let mut vcpu = vm.create_vcpu(0)?;
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;

    // --- Serial decoders / transmitter / debug buffer -------------------
    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();

    let config = vmm_config_input_only(args.sector_size);
    serial_transmitter.queue_config(&config);
    debug!(
        "Queued configuration message ({} bytes) for guest",
        serial_transmitter.buffer.len()
    );

    // --- Streaming renderer ---------------------------------------------
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    // The renderer holds a &mut to writer and must be scoped so
    // the borrow ends before we drop writer for the final flush.
    let mut renderer = SnapshotRenderer::new(&mut writer, &args.output);
    renderer.begin()?;

    let mut snapshot_result: Option<guest_::SnapshotResultMessage> = None;
    let mut vm_error: Option<String> = None;
    let mut broken_pipe = false;

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                debug!("Snapshot operation completed");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            match &msg.payload {
                                Some(guest_::GuestMessage_::Payload::SnapshotEntry(e)) => {
                                    if !broken_pipe {
                                        match renderer.emit_snapshot(e) {
                                            Ok(()) => {}
                                            Err(err)
                                                if err.kind() == std::io::ErrorKind::BrokenPipe =>
                                            {
                                                broken_pipe = true;
                                            }
                                            Err(err) => return Err(err.into()),
                                        }
                                    }
                                }
                                Some(guest_::GuestMessage_::Payload::SnapshotResult(r)) => {
                                    snapshot_result = Some(r.clone());
                                }
                                _ => {
                                    if verbose {
                                        debug!("{}", format_message(&msg));
                                    }
                                }
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                eprintln!("VM Entry Failed! reason=0x{reason:x}, cpu={cpu}");
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                eprintln!("Unexpected VM exit: {exit:?}");
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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

    if broken_pipe {
        return Ok(());
    }

    let result =
        snapshot_result.ok_or_else(|| "snapshot: guest returned no SnapshotResult".to_string())?;

    if let Some(msg) = snapshot_error_message(SNAPSHOT_CONFIG_MODE_LIST, result.error) {
        eprintln!("{}", msg);
        return Err(format!("snapshot: guest reported error code {}", result.error).into());
    }
    renderer.finish()?;
    // Drop the BufWriter so its destructor flushes to stdout. The
    // renderer borrows the writer mutably and goes out of scope
    // naturally before this line (clippy refuses an explicit
    // drop() on it since SnapshotRenderer is not Drop).
    drop(writer);

    Ok(())
}

/// Drive `MODE_CREATE` end-to-end: validate the snapshot name,
/// compute the host wall-clock date fields, and delegate the
/// guest launch to [`run_snapshot_mutating_guest`].
///
/// Success is silent (matching `qemu-img snapshot -c`), so `-q`
/// has no visible effect.
fn run_snapshot_create(
    args: &SnapshotArgs,
    name: &str,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // --- Validate the snapshot name (open question 9) -------------------
    // qemu-img silently truncates names to 255 bytes; instar refuses
    // loudly instead (divergence noted in docs/quirks.md). An empty
    // name is also refused (the plan requires a non-empty name even
    // though qemu-img accepts it — documented divergence).
    let name_bytes = name.as_bytes();
    if name_bytes.is_empty() {
        return Err("snapshot: -c requires a non-empty snapshot name".into());
    }
    if name_bytes.len() > 255 {
        return Err(format!(
            "snapshot: snapshot name is {} bytes; the qcow2 on-disk limit is 255 \
             (qemu-img truncates silently; instar refuses; see docs/quirks.md)",
            name_bytes.len()
        )
        .into());
    }

    // --- Host wall-clock for the snapshot's date fields -----------------
    // Truncate nanoseconds to microsecond precision (usec * 1000) to
    // match qemu-img's `tv_usec * 1000` byte-for-byte.
    let (date_sec, date_nsec) =
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(dur) => {
                let secs = dur.as_secs() as u32;
                let usec = dur.subsec_micros();
                (secs, usec.saturating_mul(1000))
            }
            Err(_) => (0u32, 0u32),
        };

    run_snapshot_mutating_guest(
        args,
        SNAPSHOT_CONFIG_MODE_CREATE,
        name_bytes,
        date_sec,
        date_nsec,
        verbose,
    )
}

/// Drive `MODE_DELETE` end-to-end via
/// [`run_snapshot_mutating_guest`].
///
/// The argument is passed through verbatim — no emptiness or
/// length validation. qemu 10's delete matches snapshots by NAME
/// only (first match in table order; `bdrv_snapshot_find` has no
/// ID path), and qemu happily matches an empty name if a
/// qemu-created image carries one, so instar must too (instar
/// refuses *creating* empty names but still deletes them — see
/// docs/quirks.md). The date fields are zero: delete writes no
/// timestamps, which is what makes post-delete images
/// byte-comparable against qemu's. An argument longer than the
/// 256-byte wire buffer cannot name any matchable snapshot
/// (qemu-img truncates names to 255 bytes at creation), so it is
/// resolved as not-found without launching the guest.
fn run_snapshot_delete(
    args: &SnapshotArgs,
    needle: &str,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let needle_bytes = needle.as_bytes();
    if needle_bytes.len() > 256 {
        // Matches the guest's ERROR_NOT_FOUND surface (message +
        // non-zero exit), with the image untouched.
        if let Some(msg) =
            snapshot_error_message(SNAPSHOT_CONFIG_MODE_DELETE, SNAPSHOT_RESULT_ERROR_NOT_FOUND)
        {
            eprintln!("{}", msg);
        }
        return Err(format!(
            "snapshot: guest reported error code {}",
            SNAPSHOT_RESULT_ERROR_NOT_FOUND
        )
        .into());
    }
    run_snapshot_mutating_guest(
        args,
        SNAPSHOT_CONFIG_MODE_DELETE,
        needle_bytes,
        0,
        0,
        verbose,
    )
}

/// Drive `MODE_APPLY` end-to-end via
/// [`run_snapshot_mutating_guest`].
///
/// The argument is passed through verbatim. qemu's apply resolves
/// it via `find_snapshot_by_id_or_name`: a full pass comparing
/// IDs, then — only if no ID matched — a full pass comparing
/// names (the opposite asymmetry from delete's name-only matcher;
/// see docs/quirks.md). The date fields are zero: apply writes no
/// timestamps, no snapshot-table bytes, and no header bytes,
/// which is what makes post-apply images byte-comparable against
/// qemu's. An argument longer than the 256-byte wire buffer
/// cannot name any matchable snapshot, so it is resolved as
/// not-found without launching the guest. Success is silent
/// (matching `qemu-img snapshot -a`).
fn run_snapshot_apply(
    args: &SnapshotArgs,
    needle: &str,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let needle_bytes = needle.as_bytes();
    if needle_bytes.len() > 256 {
        if let Some(msg) =
            snapshot_error_message(SNAPSHOT_CONFIG_MODE_APPLY, SNAPSHOT_RESULT_ERROR_NOT_FOUND)
        {
            eprintln!("{}", msg);
        }
        return Err(format!(
            "snapshot: guest reported error code {}",
            SNAPSHOT_RESULT_ERROR_NOT_FOUND
        )
        .into());
    }
    run_snapshot_mutating_guest(
        args,
        SNAPSHOT_CONFIG_MODE_APPLY,
        needle_bytes,
        0,
        0,
        verbose,
    )
}

/// The shared mutating-mode guest launch: open the image RW with a
/// capacity hint (so the guest can allocate clusters past EOF and
/// grow the file), write a `SnapshotConfig` with the given mode /
/// argument bytes / date fields, launch the guest, and capture the
/// terminating `SnapshotResultMessage`. Success is silent for
/// every mutating mode (matching qemu-img).
///
/// Factored out of phase 6's `run_snapshot_create` so `-d`
/// (phase 7) and `-a` (phase 8) don't copy the launch body;
/// modelled on `run_snapshot_list` with the RW-open / config /
/// quiet-success deltas. Phase 9 consolidates the remaining
/// VM-setup boilerplate.
fn run_snapshot_mutating_guest(
    args: &SnapshotArgs,
    mode: u32,
    arg_bytes: &[u8],
    date_sec: u32,
    date_nsec: u32,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = Path::new(&args.filename);
    let input_meta = std::fs::metadata(input_path)?;
    let input_size = input_meta.len();

    // --- Load guest binaries --------------------------------------------
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("snapshot.bin");
    let core_code = load_guest_binary(core_path.to_str().unwrap())?;
    let operation_code = load_guest_binary(operation_path.to_str().unwrap())?;

    // --- KVM / VM / guest memory setup ----------------------------------
    let kvm = Kvm::new()?;
    let vm = kvm.create_vm()?;
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid
    // GuestMemoryMmap allocation that outlives the VM.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    setup_gdt(&guest_mem)?;
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;

    // --- Write SnapshotConfig (per-field at known offsets) --------------
    // Layout matches shared::SnapshotConfig (312 bytes; see the list
    // path for the full offset map). Mutating modes populate
    // arg_len / arg; create also populates date_sec (offset 280) /
    // date_nsec (offset 284) — delete passes them as zero (it
    // writes no timestamps).
    let mut snapshot_flags: u32 = 0;
    if verbose {
        snapshot_flags |= SNAPSHOT_CONFIG_FLAG_VERBOSE;
    }
    if args.quiet {
        snapshot_flags |= SNAPSHOT_CONFIG_FLAG_QUIET;
    }
    if args.force_share {
        snapshot_flags |= SNAPSHOT_CONFIG_FLAG_FORCE_SHARE;
    }
    guest_mem.write_obj(SNAPSHOT_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(mode, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(snapshot_flags, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(args.sector_size, GuestAddress(OPERATION_CONFIG_ADDR + 12))?;
    guest_mem.write_obj(
        arg_bytes.len() as u32,
        GuestAddress(OPERATION_CONFIG_ADDR + 16),
    )?;
    guest_mem.write_obj(0u32, GuestAddress(OPERATION_CONFIG_ADDR + 20))?;
    // arg bytes at offset 24.
    guest_mem.write_slice(arg_bytes, GuestAddress(OPERATION_CONFIG_ADDR + 24))?;
    // date_sec at 280, date_nsec at 284.
    guest_mem.write_obj(date_sec, GuestAddress(OPERATION_CONFIG_ADDR + 280))?;
    guest_mem.write_obj(date_nsec, GuestAddress(OPERATION_CONFIG_ADDR + 284))?;
    debug!(
        "Wrote snapshot config at 0x{:x} (mode={}, arg_len={}, sector_size={}, \
         date_sec={}, date_nsec={})",
        OPERATION_CONFIG_ADDR,
        mode,
        arg_bytes.len(),
        args.sector_size,
        date_sec,
        date_nsec
    );

    // --- Set up source device 0 (read-write, growable) ------------------
    // Generous capacity hint (file_size * 2, min 1 GiB) so the guest
    // can write past EOF to grow the file — same pattern as rebase /
    // commit (see src/vmm/src/main.rs rebase open path).
    let capacity_hint = input_size.saturating_mul(2).max(1 << 30);
    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    let input_backing = BackingStore::open_rw_existing(input_path, Some(capacity_hint))?;
    let input_mmio = device_mmio_base(0);
    let input_vq = device_vq_base(0);
    // Expose the capacity hint (not the current file size) as the
    // device capacity so the guest can write past EOF to grow the
    // file, exactly as the rebase / commit output device does.
    let input_device = VirtioBlockDevice::new(
        input_backing,
        capacity_hint,
        args.sector_size as u64,
        false, // read-write
        input_mmio,
        input_vq,
    );
    let input_device = Arc::new(Mutex::new(input_device));
    device_set.add_device(Arc::clone(&input_device), true);
    io_events.push(IoEvent::new(input_mmio)?);

    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }
    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            if let Err(e) = evt.unregister(&vm) {
                warn!("ioeventfd: failed to unregister during rollback: {e:?}");
            }
        }
    }
    let all_registered = !registration_failed;
    if all_registered && !io_events.is_empty() {
        let io_devices = device_set.create_io_devices(io_events);
        io_thread = Some(io_thread::IoThread::new(
            io_devices,
            Arc::clone(&guest_mem),
            Arc::clone(&vmm_stats),
        ));
    }

    // --- vCPU setup ------------------------------------------------------
    let mut vcpu = vm.create_vcpu(0)?;
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;

    // --- Serial decoders / transmitter / debug buffer -------------------
    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();
    let config = vmm_config_input_only(args.sector_size);
    serial_transmitter.queue_config(&config);

    let mut snapshot_result: Option<guest_::SnapshotResultMessage> = None;
    let mut vm_error: Option<String> = None;

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            match &msg.payload {
                                Some(guest_::GuestMessage_::Payload::SnapshotResult(r)) => {
                                    snapshot_result = Some(r.clone());
                                }
                                _ => {
                                    if verbose {
                                        debug!("{}", format_message(&msg));
                                    }
                                }
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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

    let result =
        snapshot_result.ok_or_else(|| "snapshot: guest returned no SnapshotResult".to_string())?;
    if let Some(msg) = snapshot_error_message(mode, result.error) {
        eprintln!("{}", msg);
        return Err(format!("snapshot: guest reported error code {}", result.error).into());
    }

    // Success is silent for every mutating mode, matching qemu-img
    // (so `-q` has no visible effect). For create, the assigned ID
    // is available in `result.assigned_id` for callers that want
    // it; we do not print it (qemu-img prints nothing).
    Ok(())
}

/// Resolve a `SnapshotResult::error` code to a stderr-friendly
/// message. Returns `None` for `ERROR_OK` (success path closes
/// the renderer instead).
///
/// `mode` (a `SNAPSHOT_CONFIG_MODE_*` value) selects per-mode
/// wording where the modes genuinely differ (phase 8):
/// `ERROR_NOT_FOUND` — delete matches by name only, apply by ID
/// then name — and `ERROR_L1_SIZE_MISMATCH` — apply's
/// disk-size / L1-geometry refusal where qemu-img would truncate.
fn snapshot_error_message(mode: u32, error: u32) -> Option<&'static str> {
    match error {
        SNAPSHOT_RESULT_ERROR_OK => None,
        SNAPSHOT_RESULT_ERROR_UNSUPPORTED_FORMAT => {
            Some("snapshot: source is not qcow2 (qemu-img refuses non-qcow2 sources too)")
        }
        SNAPSHOT_RESULT_ERROR_UNSUPPORTED_FEATURE => Some(
            "snapshot: this qcow2 image uses a feature instar cannot snapshot \
             (compressed clusters, encryption, an external data file, dirty \
             bitmaps, a dirty/corrupt header, or a refcount width other than \
             16 bits). List mode works regardless; the mutating modes refuse. \
             See docs/quirks.md.",
        ),
        SNAPSHOT_RESULT_ERROR_NOT_FOUND => {
            if mode == SNAPSHOT_CONFIG_MODE_APPLY {
                Some(
                    "snapshot: no snapshot with that ID or name (qemu-img 10 \
                     matches -a arguments by ID first, then by name; see \
                     docs/quirks.md)",
                )
            } else {
                Some(
                    "snapshot: no snapshot with that name (qemu-img 10 matches -d \
                     arguments by name only, not ID; see docs/quirks.md)",
                )
            }
        }
        SNAPSHOT_RESULT_ERROR_DUPLICATE_NAME => {
            Some("snapshot: a snapshot with that name already exists")
        }
        SNAPSHOT_RESULT_ERROR_REFCOUNT_OVERFLOW => Some(
            "snapshot: a cluster's refcount would exceed the 16-bit refcount cap \
             (65535); the image is too heavily shared to snapshot",
        ),
        SNAPSHOT_RESULT_ERROR_ALLOCATION_FAILED => Some(
            "snapshot: no free clusters available — the refcount table is full and \
             instar v1 does not grow it",
        ),
        SNAPSHOT_RESULT_ERROR_SNAPSHOT_TABLE_FULL => Some(
            "snapshot: the image already has 16 snapshots, the instar v1 cap \
             (qemu allows up to 65536); delete one first. See docs/quirks.md.",
        ),
        SNAPSHOT_RESULT_ERROR_IO => Some("snapshot: I/O failure reading the source"),
        SNAPSHOT_RESULT_ERROR_L1_SIZE_MISMATCH => {
            if mode == SNAPSHOT_CONFIG_MODE_APPLY {
                Some(
                    "snapshot: the snapshot's disk size or L1 geometry differs \
                     from the image's current state — the image was resized \
                     after the snapshot was taken. qemu-img truncates the image \
                     on apply; instar refuses. Resize the image back to the \
                     snapshot's size first. See docs/quirks.md.",
                )
            } else {
                Some("snapshot: target L1 size exceeds the active L1 allocation cap")
            }
        }
        SNAPSHOT_RESULT_ERROR_INVALID_UTF8 => Some("snapshot: argument is not valid UTF-8"),
        SNAPSHOT_RESULT_ERROR_INVALID_CONFIG => {
            Some("snapshot: invalid config (host-side bug; please report)")
        }
        SNAPSHOT_RESULT_ERROR_PARSE_FAILED => {
            Some("snapshot: qcow2 header / snapshot-table parse failed")
        }
        _ => Some("snapshot: unknown error"),
    }
}

/// Output format selector for [`SnapshotRenderer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotOutputFormat {
    Human,
    Json,
}

/// Streaming renderer for `instar snapshot -l` output.
///
/// Human mode is byte-exact against `qemu-img snapshot -l` as
/// produced by qemu-img 10.0.8 (the v10 `dump_one_snapshot`
/// layout: column titles `VM_SIZE` / `VM_CLOCK` with underscores;
/// widths 7/16/8/19/15/10; uniform single-space separators;
/// 4-digit hours in the clock; `"--"` literal for absent
/// `icount`). The `Snapshot list:` prefix and the header row are
/// emitted lazily on the first `emit_snapshot` so an empty list
/// produces no output (also matching qemu-img).
///
/// JSON mode is an instar extension; field names mirror qemu's
/// QMP `SnapshotInfo` (kebab-case `vm-state-size`, `vm-clock`).
struct SnapshotRenderer<'a, W: std::io::Write> {
    writer: &'a mut W,
    output_format: SnapshotOutputFormat,
    /// True until the first entry is emitted in human mode. Drives
    /// lazy header emission.
    first_entry_emitted: bool,
    /// True until the first JSON object is emitted. Drives the
    /// `,\n` inter-object separator.
    first_entry_json: bool,
}

impl<'a, W: std::io::Write> SnapshotRenderer<'a, W> {
    fn new(writer: &'a mut W, output_format: &str) -> Self {
        let fmt = match output_format {
            "json" => SnapshotOutputFormat::Json,
            _ => SnapshotOutputFormat::Human,
        };
        Self {
            writer,
            output_format: fmt,
            first_entry_emitted: false,
            first_entry_json: true,
        }
    }

    /// Write the format-specific opening (JSON only). Human mode
    /// holds the `Snapshot list:` prefix until the first emit so
    /// an empty list produces no output, matching qemu-img.
    fn begin(&mut self) -> std::io::Result<()> {
        match self.output_format {
            SnapshotOutputFormat::Human => Ok(()),
            SnapshotOutputFormat::Json => write!(self.writer, "["),
        }
    }

    /// Write one snapshot record. Human mode lazily writes the
    /// `Snapshot list:` prefix and the header row on the first
    /// call. JSON mode writes one comma-separated object per
    /// snapshot.
    fn emit_snapshot(&mut self, entry: &guest_::SnapshotEntryMessage) -> std::io::Result<()> {
        match self.output_format {
            SnapshotOutputFormat::Human => {
                if !self.first_entry_emitted {
                    writeln!(self.writer, "Snapshot list:")?;
                    writeln!(
                        self.writer,
                        "{:<7} {:<16} {:>8} {:>19} {:>15} {:>10}",
                        "ID", "TAG", "VM_SIZE", "DATE", "VM_CLOCK", "ICOUNT"
                    )?;
                    self.first_entry_emitted = true;
                }

                let date_sec: u64 = ((entry.date_sec_hi as u64) << 32) | (entry.date_sec_lo as u64);
                let date_str = format_qemu_snapshot_date_local(date_sec);
                let vm_size_str = format_snapshot_vm_size(entry.vm_state_size);
                let clock_str = format_qemu_snapshot_clock(entry.vm_clock_nsec);
                let icount_str = if entry.icount == u64::MAX {
                    "--".to_string()
                } else {
                    entry.icount.to_string()
                };

                // ID and TAG are left-justified to a minimum field
                // width measured in BYTES, matching qemu's C
                // printf("%-7s"/"%-16s"). Rust's `{:<7}` counts
                // chars, which diverges for multibyte UTF-8 names.
                // The right-aligned columns carry ASCII-only
                // generated strings, so `{:>N}` is safe there.
                writeln!(
                    self.writer,
                    "{}{} {}{} {:>8} {:>19} {:>15} {:>10}",
                    entry.id,
                    " ".repeat(7usize.saturating_sub(entry.id.len())),
                    entry.name,
                    " ".repeat(16usize.saturating_sub(entry.name.len())),
                    vm_size_str,
                    date_str,
                    clock_str,
                    icount_str
                )
            }
            SnapshotOutputFormat::Json => {
                if !self.first_entry_json {
                    writeln!(self.writer, ",")?;
                } else {
                    writeln!(self.writer)?;
                }
                self.first_entry_json = false;

                let date_sec: u64 = ((entry.date_sec_hi as u64) << 32) | (entry.date_sec_lo as u64);
                let clock_sec: u64 = entry.vm_clock_nsec / 1_000_000_000;
                let clock_nsec: u64 = entry.vm_clock_nsec % 1_000_000_000;
                let icount_field = if entry.icount == u64::MAX {
                    "null".to_string()
                } else {
                    entry.icount.to_string()
                };

                write!(
                    self.writer,
                    "{{ \"id\": \"{}\", \"name\": \"{}\", \
                     \"vm-state-size\": {}, \
                     \"date\": {{ \"seconds\": {}, \"nanoseconds\": {} }}, \
                     \"vm-clock\": {{ \"seconds\": {}, \"nanoseconds\": {} }}, \
                     \"icount\": {} }}",
                    json_escape(&entry.id),
                    json_escape(&entry.name),
                    entry.vm_state_size,
                    date_sec,
                    entry.date_nsec,
                    clock_sec,
                    clock_nsec,
                    icount_field
                )
            }
        }
    }

    /// Write the format-specific closing. JSON mode emits `]\n`
    /// (closing bracket + newline) matching the empty-list shape
    /// `[]\n`. Human mode is a no-op — the last row's `writeln!`
    /// already produced its trailing newline.
    fn finish(&mut self) -> std::io::Result<()> {
        match self.output_format {
            SnapshotOutputFormat::Human => Ok(()),
            SnapshotOutputFormat::Json => {
                if !self.first_entry_json {
                    writeln!(self.writer)?;
                }
                writeln!(self.writer, "]")
            }
        }
    }
}

/// Format the snapshot `vm_state_size` for the `VM_SIZE` column.
/// qemu-img's snapshot dump uses `size_to_str()` which emits
/// `"0 B"` for a zero size; the existing
/// `format_size_human(_, qemu_compat=true)` helper emits `"0"` in
/// that case (matching qemu-img's info output, not the snapshot
/// dump). Wrap the helper so the snapshot path matches qemu-img
/// snapshot's actual `0 B` output.
fn format_snapshot_vm_size(bytes: u64) -> String {
    if bytes == 0 {
        "0 B".to_string()
    } else {
        format_size_human(bytes, true)
    }
}

/// Format the snapshot VM clock as `HHHH:MM:SS.mmm`.
///
/// qemu-img 10.0.8 emits 4-digit hours (zero-padded), 2-digit
/// minutes and seconds, and 3-digit milliseconds. The minutes
/// and seconds fields wrap inside the hour / minute (a 90-second
/// clock prints as `0000:01:30.000`, not `0000:00:90.000`).
fn format_qemu_snapshot_clock(vm_clock_nsec: u64) -> String {
    let total_ms: u64 = vm_clock_nsec / 1_000_000;
    let ms: u64 = total_ms % 1000;
    let total_s: u64 = total_ms / 1000;
    let s: u64 = total_s % 60;
    let total_m: u64 = total_s / 60;
    let m: u64 = total_m % 60;
    let h: u64 = total_m / 60;
    format!("{:04}:{:02}:{:02}.{:03}", h, m, s, ms)
}

/// Format a snapshot creation timestamp as
/// `YYYY-MM-DD HH:MM:SS` in local time, matching qemu-img's
/// `strftime("%Y-%m-%d %H:%M:%S", localtime(&date_sec))`.
///
/// A zero `date_sec` is fed through `localtime_r` like any other
/// value and renders the Unix epoch in local time, exactly as
/// qemu does. (An earlier early-return rendered a blank DATE
/// column for this hand-crafted-only input; PLAN-snapshot phase
/// 14 removed it for byte-parity — see docs/quirks.md.)
fn format_qemu_snapshot_date_local(date_sec: u64) -> String {
    // SAFETY: `localtime_r` writes a fully-initialised `tm` into
    // the stack-allocated buffer when given a valid time_t; we
    // pass a stack reference and the kernel-provided tzdata is
    // process-wide TLS, so no locking is required. `strftime`
    // reads the same `tm` and writes at most `buf.len()` bytes
    // into our stack buffer. Both calls are guaranteed not to
    // touch memory outside the values we pass.
    let t: libc::time_t = date_sec as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 32];
    let written = unsafe {
        if libc::localtime_r(&t, &mut tm).is_null() {
            return String::new();
        }
        let fmt = b"%Y-%m-%d %H:%M:%S\0";
        libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            fmt.as_ptr() as *const libc::c_char,
            &tm,
        )
    };
    if written == 0 {
        return String::new();
    }
    // `strftime`'s return value excludes the trailing nul.
    String::from_utf8_lossy(&buf[..written]).into_owned()
}

/// Minimal JSON string escaping for the snapshot renderer's
/// instar-extension JSON output. qcow2 snapshot IDs are decimal
/// strings (no escapes needed); names are user-supplied UTF-8
/// and require escaping of `"`, `\`, and the C0 control range.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Entry point for the `create` subcommand.
///
/// Phase 4 wires `-o KEY=VAL,...` parsing on top of the phase-3
/// individual flags: parse `-o` first, then apply the overrides
/// to a mutable copy of the args (last-wins, matches qemu-img
/// and measure), then run the full validator. Raw output bypasses
/// the guest entirely; everything else dispatches into
/// `run_create_nonraw`.
fn run_create(mut args: CreateArgs, _verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let overrides = parse_create_o_options(&args.target_format, &args.option)?;
    apply_create_overrides(&mut args, overrides);
    validate_create_args(&args)?;

    // Raw output bypasses the guest entirely — there is no metadata
    // to emit. Open + ftruncate (+ optional posix_fallocate for the
    // falloc preallocation mode) is the whole job.
    if args.target_format == "raw" {
        return run_create_raw(&args);
    }

    run_create_nonraw(&args, _verbose)
}

/// Apply parsed `-o` overrides on top of the individual `--flag`
/// values. Overrides always win (last-wins on the command line,
/// matching qemu-img). Mutating `CreateArgs` in place keeps the
/// rest of `run_create_raw` / `run_create_nonraw` unchanged —
/// they read the same field set as before.
fn apply_create_overrides(args: &mut CreateArgs, overrides: CreateOptionOverrides) {
    if let Some(v) = overrides.cluster_size {
        args.cluster_size = v;
    }
    if let Some(v) = overrides.refcount_bits {
        args.refcount_bits = v;
    }
    if let Some(v) = overrides.extended_l2 {
        args.extended_l2 = v;
    }
    if let Some(v) = overrides.lazy_refcounts {
        args.lazy_refcounts = v;
    }
    if let Some(v) = overrides.compat_v3 {
        args.compat = if v { "1.1" } else { "0.10" }.to_string();
    }
    if let Some(v) = overrides.vmdk_subformat {
        args.subformat = match v {
            0 => "monolithicSparse",
            1 => "streamOptimized",
            2 => "monolithicFlat",
            _ => "monolithicSparse",
        }
        .to_string();
    }
    if let Some(v) = overrides.grain_size {
        args.grain_size = v;
    }
    if let Some(v) = overrides.vhd_subformat {
        args.subformat = match v {
            0 => "dynamic",
            1 => "fixed",
            _ => "dynamic",
        }
        .to_string();
    }
    if let Some(v) = overrides.block_size {
        args.block_size = v;
    }
    if let Some(v) = overrides.preallocation {
        args.preallocation = v.to_string();
    }
    if let Some(v) = overrides.size {
        // Encode the override as a decimal-bytes string so the
        // existing parse_memory_size call site picks it up
        // unchanged. -o size wins over the positional SIZE.
        args.size = Some(v.to_string());
    }
    if let Some(v) = overrides.backing_file {
        args.backing = Some(v);
    }
    if let Some(v) = overrides.backing_fmt {
        args.backing_format = Some(v.to_string());
    }
}

/// Map a backing-format string (the `-F` argument) to its numeric
/// ImageFormat code. Returns 0 ("Unknown") for an empty hint so the
/// guest sees "no format hint" rather than a bogus enum value.
fn create_backing_format_code(s: &str) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(match s {
        "" => IMAGE_FORMAT_UNKNOWN,
        "raw" => IMAGE_FORMAT_RAW,
        "qcow2" => IMAGE_FORMAT_QCOW2,
        "vmdk" => IMAGE_FORMAT_VMDK4,
        "vpc" | "vhd" => IMAGE_FORMAT_VHD,
        "vhdx" => IMAGE_FORMAT_VHDX,
        other => {
            return Err(format!(
                "create: -F {} is not a recognised backing format \
                 (expected raw, qcow2, vmdk, vpc, or vhdx)",
                other
            )
            .into());
        }
    })
}

/// Non-raw create dispatch: open the output, attach as a virtio
/// device, populate `CreateConfig`, launch the create guest binary,
/// and wait for the result.
///
/// Phase 3c ships the no-backing path. Phase 3d adds the backing
/// attach; phase 3e replaces the minimal error reporting here with
/// the full human / json / quiet renderer.
fn run_create_nonraw(args: &CreateArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // --- Resolve fields from args ---------------------------------------
    let target_format = create_target_format(&args.target_format)?;
    let virtual_size = args
        .size
        .as_ref()
        .map(|s| parse_memory_size(s))
        .transpose()?
        .unwrap_or(0);

    let mut flags: u32 = 0;
    if args.extended_l2 {
        flags |= CREATE_CONFIG_FLAG_EXTENDED_L2;
    }
    if args.lazy_refcounts {
        flags |= CREATE_CONFIG_FLAG_LAZY_REFCOUNTS;
    }
    if args.compat == "1.1" {
        flags |= CREATE_CONFIG_FLAG_COMPAT_V3;
    }
    if args.backing_unsafe {
        flags |= CREATE_CONFIG_FLAG_BACKING_UNSAFE;
    }
    flags |= match args.preallocation.as_str() {
        "metadata" => CREATE_CONFIG_PREALLOC_METADATA,
        "falloc" => CREATE_CONFIG_PREALLOC_FALLOC,
        "full" => CREATE_CONFIG_PREALLOC_FULL,
        _ => CREATE_CONFIG_PREALLOC_OFF,
    };

    let vmdk_subformat: u8 = match args.subformat.as_str() {
        "streamOptimized" => 1,
        _ => 0, // monolithicSparse default
    };
    let vhd_subformat: u8 = match args.subformat.as_str() {
        "fixed" => 1,
        _ => 0, // dynamic default
    };

    let cluster_size = args.cluster_size;
    let refcount_bits = args.refcount_bits;
    let grain_size = args.grain_size;
    let block_size = args.block_size;

    // --- Load guest binaries --------------------------------------------
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("create.bin");
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

    // --- Open and attach output device ----------------------------------
    let output_path = Path::new(&args.filename);
    // The output is sparse — the on-disk size is just the metadata
    // footprint (kilobytes typically), but virtio needs a capacity to
    // expose. Pass a generous upper bound (virtual_size + 64 MiB)
    // and let the file stay sparse. For the inferred-from-backing
    // path (virtual_size == 0; phase 3d) we fall back to 64 MiB —
    // the BAT/L1/refcount metadata is far smaller than that.
    let output_capacity_hint = virtual_size
        .saturating_add(64 * 1024 * 1024)
        .max(64 * 1024 * 1024);

    let output_backing =
        BackingStore::open(output_path, false, Some(output_capacity_hint), true)
            .map_err(|e| format!("create: open '{}' for write failed: {}", args.filename, e))?;

    // core unconditionally initialises input device 0 and places the
    // output device at MMIO index = active_input_count. The input
    // device 0 is either the real backing file (when -b is given) or
    // a 1-sector tempfile stub the guest ignores.
    struct CreateStubInput(std::path::PathBuf);
    impl Drop for CreateStubInput {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let mut backing_file_bytes: Vec<u8> = Vec::new();
    let mut backing_format_code: u32 = IMAGE_FORMAT_UNKNOWN;
    let _stub_input: Option<CreateStubInput>;

    let (input_backing, input_capacity) = if let Some(ref typed_backing) = args.backing {
        // Resolve the backing path relative to the output's parent
        // directory, matching qemu-img. The path the user typed is
        // embedded verbatim into the new image's metadata so the
        // backing reference stays portable across moves.
        let resolved = if Path::new(typed_backing).is_absolute() {
            Path::new(typed_backing).to_path_buf()
        } else {
            output_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(typed_backing)
        };

        // Single metadata() call serves both the is_file check (when
        // -u is absent) and the backing-size capture. Previously two
        // separate stats; deduped per PR #298 review item #4. Note
        // that this still has a small TOCTOU window vs the subsequent
        // BackingStore::open — eliminating that would require a
        // BackingStore::is_regular_file() helper that fstats the
        // opened fd. Tracked as a follow-up in PLAN-create.md.
        let backing_md_opt = std::fs::metadata(&resolved).ok();
        if !args.backing_unsafe {
            let md = backing_md_opt.as_ref().ok_or_else(|| {
                format!(
                    "create: backing file '{}' (resolved to '{}') not accessible \
                     (pass -u to skip this check)",
                    typed_backing,
                    resolved.display(),
                )
            })?;
            if !md.is_file() {
                return Err(format!(
                    "create: backing path '{}' is not a regular file",
                    resolved.display()
                )
                .into());
            }
        }
        let backing_md_size = backing_md_opt.as_ref().map(|m| m.len()).unwrap_or(0);
        let real_backing = BackingStore::open(&resolved, true, None, false).map_err(|e| {
            format!(
                "create: open backing '{}' failed: {}",
                resolved.display(),
                e
            )
        })?;

        // Embed the user-typed bytes verbatim. The host-resolved
        // path is *not* what ends up in the metadata.
        let typed_bytes = typed_backing.as_bytes();
        if typed_bytes.len() > CREATE_CONFIG_MAX_BACKING_FILE {
            return Err(format!(
                "create: backing path too long ({} bytes; max {})",
                typed_bytes.len(),
                CREATE_CONFIG_MAX_BACKING_FILE
            )
            .into());
        }
        backing_file_bytes = typed_bytes.to_vec();

        if let Some(ref fmt) = args.backing_format {
            backing_format_code = create_backing_format_code(fmt)?;
        }
        _stub_input = None;
        (real_backing, backing_md_size)
    } else {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stub_path = std::env::temp_dir().join(format!("instar-create-stub-{}-{}", pid, nanos));
        let stub_file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&stub_path)?;
        stub_file.set_len(args.sector_size as u64)?;
        drop(stub_file);
        _stub_input = Some(CreateStubInput(stub_path.clone()));
        let stub_backing = BackingStore::open(&stub_path, true, None, false)?;
        (stub_backing, args.sector_size as u64)
    };

    // Build the device-attach + guest-launch closure so any failure
    // along the way can hit the partial-output cleanup path.
    let result = run_create_guest(
        &core_code,
        &operation_code,
        args,
        target_format,
        flags,
        virtual_size,
        cluster_size,
        refcount_bits,
        vmdk_subformat,
        vhd_subformat,
        grain_size,
        block_size,
        input_backing,
        input_capacity,
        &backing_file_bytes,
        backing_format_code,
        output_backing,
        output_capacity_hint,
        verbose,
    );

    match result {
        Ok(create_result) => {
            if create_result.error != CREATE_RESULT_ERROR_OK {
                let _ = std::fs::remove_file(output_path);
                return Err(format!(
                    "create failed: {}",
                    create_error_detail(create_result.error)
                )
                .into());
            }

            // For qcow2 + falloc/full, apply the host-side post-pass
            // on the data region the guest just framed with metadata.
            // The guest laid out the file as
            //     header | L1 | refcount | L2 | data
            // so the data region runs from
            //     data_offset = file_size_after - data_len
            // where data_len is the virtual size rounded up to the
            // cluster boundary.
            //
            // Defence-in-depth: the size inputs come from the guest
            // (CreateResultMessage) and the host has its own
            // authoritative knowledge of virtual_size (when set via
            // --size) and the on-disk file length (via stat). We
            // clamp `data_len` against the host-known virtual_size
            // when available, fall back to the guest report bounded
            // by a sanity ceiling otherwise, and refuse to apply
            // preallocation past the observed end-of-file.
            if args.target_format == "qcow2"
                && matches!(args.preallocation.as_str(), "falloc" | "full")
            {
                // Use the host's own knowledge of virtual_size where
                // we have it; for backing-defaulted sizes (host saw
                // virtual_size=0 and the guest filled it in) fall
                // back to the guest report bounded by a sanity
                // ceiling (2^57 bytes = 128 PiB; comfortably above
                // any plausible image but below i64::MAX).
                const VIRTUAL_SIZE_SANITY_CEILING: u64 = 1u64 << 57;
                let trusted_virtual_size = if virtual_size != 0 {
                    virtual_size
                } else {
                    let reported = create_result.resolved_virtual_size;
                    if reported > VIRTUAL_SIZE_SANITY_CEILING {
                        return Err(format!(
                            "create: guest reported resolved_virtual_size={} \
                             exceeding the sanity ceiling ({} bytes); \
                             refusing preallocation",
                            reported, VIRTUAL_SIZE_SANITY_CEILING
                        )
                        .into());
                    }
                    reported
                };
                let cluster = cluster_size.max(1) as u64;
                let data_len = trusted_virtual_size
                    .div_ceil(cluster)
                    .saturating_mul(cluster);
                if let Err(e) = (|| -> Result<(), Box<dyn std::error::Error>> {
                    let postpass_file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(output_path)
                        .map_err(|e| {
                        format!("create: reopen for preallocation failed: {}", e)
                    })?;
                    // Anchor the preallocation range to the file's
                    // actual length on disk, not the guest's report.
                    let observed_file_size = postpass_file
                        .metadata()
                        .map_err(|e| {
                            format!("create: stat for preallocation bounds failed: {}", e)
                        })?
                        .len();
                    let data_offset = observed_file_size.saturating_sub(data_len);
                    let range_end = data_offset
                        .checked_add(data_len)
                        .ok_or("create: preallocation range overflows u64")?;
                    if range_end > observed_file_size {
                        return Err(format!(
                            "create: preallocation range [{}, {}) exceeds \
                             observed file size {}; refusing",
                            data_offset, range_end, observed_file_size
                        )
                        .into());
                    }
                    // Defence-in-depth (PR #298 review item #11): a
                    // qcow2 image always has at least one cluster of
                    // metadata at offset 0 (the header). If the guest
                    // emitted a short file the saturating_sub above
                    // could land data_offset at 0, and the post-pass
                    // would clobber the header. Require at least one
                    // cluster of headroom before the data region.
                    if data_offset < cluster {
                        return Err(format!(
                            "create: preallocation data_offset ({}) below \
                             minimum metadata footprint ({}); the guest may have \
                             emitted a short file. Refusing to preallocate.",
                            data_offset, cluster
                        )
                        .into());
                    }
                    apply_preallocation(
                        &postpass_file,
                        "create",
                        &args.preallocation,
                        data_offset,
                        data_len,
                    )?;
                    postpass_file
                        .sync_all()
                        .map_err(|e| format!("create: sync after preallocation failed: {}", e))?;
                    Ok(())
                })() {
                    let _ = std::fs::remove_file(output_path);
                    return Err(e);
                }
            }

            if !args.quiet {
                render_create_success(
                    args,
                    create_result.resolved_virtual_size,
                    create_result.metadata_bytes_written,
                    create_result.file_size_after,
                    create_result.resolved_unit_size,
                );
            }
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(output_path);
            Err(e)
        }
    }
}

/// Decode a target-format string into its numeric `ImageFormat`.
/// Errors on unsupported values; clap's value_parser already rules
/// out completely unknown strings.
fn create_target_format(s: &str) -> Result<u32, Box<dyn std::error::Error>> {
    match s {
        "raw" => Ok(IMAGE_FORMAT_RAW),
        "qcow2" => Ok(IMAGE_FORMAT_QCOW2),
        "vmdk" => Ok(IMAGE_FORMAT_VMDK4),
        "vpc" => Ok(IMAGE_FORMAT_VHD),
        "vhdx" => Ok(IMAGE_FORMAT_VHDX),
        other => Err(format!("create: unsupported target format '{}'", other).into()),
    }
}

/// Numeric host-side mirror of `CreateResult` populated by the guest
/// dispatch. We only need the fields the host renders.
struct CreateRunResult {
    resolved_virtual_size: u64,
    metadata_bytes_written: u64,
    file_size_after: u64,
    resolved_unit_size: u32,
    error: u32,
}

/// Build CreateConfig, set up KVM + virtio, launch the create guest
/// binary, and harvest the resulting `CreateResultMessage`.
///
/// Pulled out of `run_create_nonraw` so the partial-output cleanup
/// in the caller is a single match arm.
#[allow(clippy::too_many_arguments)]
fn run_create_guest(
    core_code: &[u8],
    operation_code: &[u8],
    args: &CreateArgs,
    target_format: u32,
    flags: u32,
    virtual_size: u64,
    cluster_size: u32,
    refcount_bits: u8,
    vmdk_subformat: u8,
    vhd_subformat: u8,
    grain_size: u32,
    block_size: u32,
    input_backing: BackingStore,
    input_capacity: u64,
    backing_file_bytes: &[u8],
    backing_format_code: u32,
    output_backing: BackingStore,
    output_capacity_hint: u64,
    verbose: bool,
) -> Result<CreateRunResult, Box<dyn std::error::Error>> {
    // --- KVM / VM / guest memory setup ----------------------------------
    let kvm = Kvm::new()?;
    debug!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    debug!("Created VM");

    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    debug!("Allocated {GUEST_MEM_SIZE} bytes of guest memory");

    let region = guest_mem.find_region(GuestAddress(0)).unwrap();
    let host_addr = region.as_ptr() as u64;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr,
        flags: 0,
    };
    // SAFETY: mem_region.userspace_addr points to a valid
    // GuestMemoryMmap allocation that outlives the VM.
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }
    debug!("Configured memory region");

    setup_gdt(&guest_mem)?;
    setup_page_tables(&guest_mem, GUEST_MEM_SIZE)?;

    guest_mem.write_slice(core_code, GuestAddress(GUEST_CODE_BASE))?;
    guest_mem.write_slice(operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;

    // --- Write CreateConfig at OPERATION_CONFIG_ADDR --------------------
    // Layout (must match shared::CreateConfig exactly):
    //    0: magic                u32
    //    4: target_format        u32
    //    8: flags                u32
    //   12: sector_size          u32
    //   16: virtual_size         u64
    //   24: qcow2_cluster_size   u32
    //   28: qcow2_refcount_bits  u8
    //   29: vmdk_subformat       u8
    //   30: vhd_subformat        u8
    //   31: _pad                 u8
    //   32: vmdk_grain_size      u32
    //   36: block_size           u32
    //   40: backing_file_len     u32
    //   44: backing_file         [u8; 1024]
    // 1068: backing_format       u32
    // 1072: _reserved            [u8; 64]
    guest_mem.write_obj(CREATE_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(target_format, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(flags, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(args.sector_size, GuestAddress(OPERATION_CONFIG_ADDR + 12))?;
    guest_mem.write_obj(virtual_size, GuestAddress(OPERATION_CONFIG_ADDR + 16))?;
    guest_mem.write_obj(cluster_size, GuestAddress(OPERATION_CONFIG_ADDR + 24))?;
    guest_mem.write_obj(refcount_bits, GuestAddress(OPERATION_CONFIG_ADDR + 28))?;
    guest_mem.write_obj(vmdk_subformat, GuestAddress(OPERATION_CONFIG_ADDR + 29))?;
    guest_mem.write_obj(vhd_subformat, GuestAddress(OPERATION_CONFIG_ADDR + 30))?;
    // _pad (offset 31) left zero from page-zeroed memory.
    guest_mem.write_obj(grain_size, GuestAddress(OPERATION_CONFIG_ADDR + 32))?;
    guest_mem.write_obj(block_size, GuestAddress(OPERATION_CONFIG_ADDR + 36))?;
    // Backing-file fields. backing_file_bytes is empty when no -b
    // was given (phase 3c's stub-input path); otherwise it holds the
    // user-typed path bytes and the guest reads input device 0 to
    // recover the backing's virtual size when CreateConfig.virtual_size
    // is zero.
    let backing_len = backing_file_bytes.len() as u32;
    guest_mem.write_obj(backing_len, GuestAddress(OPERATION_CONFIG_ADDR + 40))?;
    let mut backing_buf = [0u8; CREATE_CONFIG_MAX_BACKING_FILE];
    backing_buf[..backing_file_bytes.len()].copy_from_slice(backing_file_bytes);
    guest_mem.write_slice(&backing_buf, GuestAddress(OPERATION_CONFIG_ADDR + 44))?;
    guest_mem.write_obj(
        backing_format_code,
        GuestAddress(OPERATION_CONFIG_ADDR + 1068),
    )?;

    debug!(
        "Wrote create config at 0x{:x} (target={}, flags=0x{:x}, sector_size={}, \
         virtual_size={}, cluster_size={}, refcount_bits={}, vmdk_subformat={}, \
         vhd_subformat={}, grain_size={}, block_size={})",
        OPERATION_CONFIG_ADDR,
        target_format,
        flags,
        args.sector_size,
        virtual_size,
        cluster_size,
        refcount_bits,
        vmdk_subformat,
        vhd_subformat,
        grain_size,
        block_size,
    );

    // --- Set up devices --------------------------------------------------
    // core unconditionally initialises input device 0 (see core/src/
    // main.rs::_start), so even though phase 3c has no real backing we
    // attach a tiny stub at device index 0 and place the output at
    // index 1. The guest never reads from the stub.
    let mut device_set = DeviceSet::new();
    let mut io_events: Vec<IoEvent> = Vec::new();

    let input_mmio = device_mmio_base(0);
    let input_vq = device_vq_base(0);
    let input_device = VirtioBlockDevice::new(
        input_backing,
        input_capacity,
        args.sector_size as u64,
        true, // read-only
        input_mmio,
        input_vq,
    );
    let input_device = Arc::new(Mutex::new(input_device));
    device_set.add_device(Arc::clone(&input_device), true);
    io_events.push(IoEvent::new(input_mmio)?);

    let output_mmio = device_mmio_base(1);
    let output_vq = device_vq_base(1);
    let output_device = VirtioBlockDevice::new(
        output_backing,
        output_capacity_hint,
        args.sector_size as u64,
        false, // writable
        output_mmio,
        output_vq,
    );
    debug!(
        "Created output virtio-block device at MMIO 0x{output_mmio:x}, VQ 0x{output_vq:x} \
         (capacity hint {output_capacity_hint} bytes)"
    );
    let output_device = Arc::new(Mutex::new(output_device));
    device_set.add_device(Arc::clone(&output_device), false);
    io_events.push(IoEvent::new(output_mmio)?);

    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Try to register ioeventfds; fall back to VM exits on failure.
    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut registered_count = 0usize;
    let mut registration_failed = false;
    for evt in io_events.iter_mut() {
        if let Err(e) = evt.register(&vm) {
            debug!("ioeventfd: failed to register ({e:?}), falling back to VM exits");
            registration_failed = true;
            break;
        }
        registered_count += 1;
    }
    if registration_failed {
        for evt in io_events.iter_mut().take(registered_count) {
            let _ = evt.unregister(&vm);
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

    // --- vCPU setup ------------------------------------------------------
    let mut vcpu = vm.create_vcpu(0)?;
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;

    // --- Serial decoders / transmitter / debug buffer -------------------
    let mut serial_decoder = SerialDecoder::new();
    let mut serial_transmitter = SerialTransmitter::new();
    let mut debug_buffer = DebugBuffer::new();

    // 1 stub input + 1 output, no progress events (the metadata write
    // is tiny and instant). Phase 3d replaces the stub with the real
    // backing image when -b is given.
    let config = vmm_config(args.sector_size, args.sector_size, 100);
    serial_transmitter.queue_config(&config);
    debug!(
        "Queued configuration message ({} bytes) for guest",
        serial_transmitter.buffer.len()
    );

    // --- Run the vCPU loop ----------------------------------------------
    let mut create_result_seen = false;
    let mut harvested = CreateRunResult {
        resolved_virtual_size: 0,
        metadata_bytes_written: 0,
        file_size_after: 0,
        resolved_unit_size: 0,
        error: CREATE_RESULT_ERROR_OK,
    };
    let mut vm_error: Option<String> = None;

    debug!("Starting guest execution");

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                debug!("Create operation completed (HLT)");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            if let Some(guest_::GuestMessage_::Payload::CreateResult(c)) =
                                &msg.payload
                            {
                                harvested.resolved_virtual_size = c.resolved_virtual_size;
                                harvested.metadata_bytes_written = c.metadata_bytes_written;
                                harvested.file_size_after = c.file_size_after;
                                harvested.resolved_unit_size = c.resolved_unit_size;
                                harvested.error = c.error;
                                create_result_seen = true;
                            } else if verbose {
                                debug!("{}", format_message(&msg));
                            }
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            debug!("[GUEST] {line}");
                        }
                    }
                } else {
                    debug!("IO OUT: port=0x{port:x}, data={data:?}");
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
                vm_error = Some("VM shutdown (triple fault)".to_string());
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                vm_error = Some(format!("VM entry failed: reason=0x{reason:x}, cpu={cpu}"));
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                vm_error = Some(format!("unexpected VM exit: {exit:?}"));
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
    if !create_result_seen {
        return Err("create: guest did not return a result".into());
    }

    Ok(harvested)
}

/// User-facing message for each `CreateResult::ERROR_*` code.
fn create_error_detail(code: u32) -> &'static str {
    match code {
        CREATE_RESULT_ERROR_INVALID_OPTION => "invalid option for target format",
        CREATE_RESULT_ERROR_INVALID_SIZE => "virtual size out of range for format",
        CREATE_RESULT_ERROR_SCRATCH_TOO_SMALL => {
            "option combination exceeds guest scratch (try a larger cluster size)"
        }
        CREATE_RESULT_ERROR_BACKING_READ_FAILED => "failed to read backing file header",
        CREATE_RESULT_ERROR_BACKING_PARSE_FAILED => {
            "backing file header could not be parsed \
             (file may be truncated, corrupted, or an unrecognised format)"
        }
        CREATE_RESULT_ERROR_BACKING_TOO_LONG => "backing file path too long (max 1024 bytes)",
        CREATE_RESULT_ERROR_WRITE_FAILED => "write to output device failed",
        CREATE_RESULT_ERROR_UNSUPPORTED_FORMAT => "target format not supported",
        CREATE_RESULT_ERROR_BACKING_FORMAT_UNSUPPORTED => {
            "backing file format is recognised but virtual_size \
             extraction is not yet implemented for it"
        }
        CREATE_RESULT_ERROR_BACKING_SIZE_TOO_LARGE => {
            "backing file is too large for the target format with the \
             requested options (try a larger cluster size, switch to \
             a target format with greater virtual-size headroom, or \
             pass an explicit SIZE that fits)"
        }
        _ => "unknown error",
    }
}

/// Host-side raw image creation: `open(O_CREAT|O_TRUNC|O_RDWR)` +
/// `ftruncate(SIZE)`, plus `posix_fallocate` when the user asked
/// for preallocation=falloc. On any failure the partial output
/// file is removed before propagating the error.
fn run_create_raw(args: &CreateArgs) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::OpenOptionsExt;

    let size_str = args.size.as_ref().ok_or("create: -f raw requires SIZE")?;
    let virtual_size = parse_memory_size(size_str)?;

    let path = Path::new(&args.filename);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .mode(0o644)
        .open(path)
        .map_err(|e| format!("create: open '{}' failed: {}", args.filename, e))?;

    if let Err(e) = create_raw_finalize(&file, virtual_size, &args.preallocation) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    drop(file);

    if !args.quiet {
        render_create_success(args, virtual_size, 0, virtual_size, 0);
    }
    Ok(())
}

/// Apply ftruncate + optional preallocation pass + fsync. Split out
/// so `run_create_raw` can handle cleanup uniformly on any failure.
///
/// `preallocation` may be "off", "falloc", or "full". "metadata" is
/// rejected for raw at the validator (raw has no metadata to
/// preallocate); any other value is a no-op fallthrough handled the
/// same as "off".
fn create_raw_finalize(
    file: &std::fs::File,
    virtual_size: u64,
    preallocation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::AsRawFd;

    file.set_len(virtual_size)
        .map_err(|e| format!("create: ftruncate failed: {}", e))?;

    let fd = file.as_raw_fd();
    match preallocation {
        "falloc" => {
            // posix_fallocate returns 0 on success, errno on failure
            // (does not set errno; the return value IS the errno).
            // SAFETY: fd is the raw fd of `file`, which the caller
            // owns for the duration of this block. virtual_size has
            // been bounded to <= i64::MAX by validate_create_args, so
            // the cast to off_t (i64) is in-range.
            let rc = unsafe { libc::posix_fallocate(fd, 0, virtual_size as libc::off_t) };
            if rc != 0 {
                return Err(format!(
                    "create: posix_fallocate failed: {}",
                    std::io::Error::from_raw_os_error(rc)
                )
                .into());
            }
        }
        "full" => {
            fill_zeros(fd, 0, virtual_size)
                .map_err(|e| format!("create: zero-fill failed: {}", e))?;
        }
        _ => {}
    }

    file.sync_all()
        .map_err(|e| format!("create: sync failed: {}", e))?;
    Ok(())
}

/// Zero a byte range in `fd` from `offset` for `length` bytes.
///
/// Tries `fallocate(FALLOC_FL_ZERO_RANGE)` first (fast on btrfs /
/// ext4 / xfs — no actual writes). On `EOPNOTSUPP` (or kernels /
/// filesystems that don't support it: tmpfs, NFS, some FUSE),
/// falls back to a `pwrite` loop with a 64 KiB stack-allocated
/// zero buffer.
fn fill_zeros(fd: libc::c_int, offset: u64, length: u64) -> std::io::Result<()> {
    fill_zeros_inner(fd, offset, length, |fd, off, len| {
        // SAFETY: fd is a valid open file descriptor owned by the
        // caller (passed in as `file.as_raw_fd()` on a still-live
        // File). FALLOC_FL_ZERO_RANGE is a kernel constant. offset
        // and length are non-negative u64 values cast to off_t; an
        // out-of-range cast surfaces as EINVAL from the syscall
        // rather than UB.
        let rc = unsafe {
            libc::fallocate(
                fd,
                libc::FALLOC_FL_ZERO_RANGE,
                off as libc::off_t,
                len as libc::off_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    })
}

/// Inner implementation of [`fill_zeros`] with an injectable
/// `fallocate_fn` so tests can drive the `EOPNOTSUPP` fallback
/// path without depending on the host filesystem's
/// `FALLOC_FL_ZERO_RANGE` support.
///
/// `fallocate_fn(fd, offset, length)` is the operation the
/// production code maps to `libc::fallocate(FALLOC_FL_ZERO_RANGE)`.
/// When it returns `Ok(())`, `fill_zeros_inner` returns
/// immediately.  When it returns `EOPNOTSUPP` / `ENOSYS` /
/// `EINVAL`, the function falls through to the `pwrite` zero
/// loop.  Any other error propagates.
fn fill_zeros_inner<F>(
    fd: libc::c_int,
    offset: u64,
    length: u64,
    fallocate_fn: F,
) -> std::io::Result<()>
where
    F: FnOnce(libc::c_int, u64, u64) -> std::io::Result<()>,
{
    if length == 0 {
        return Ok(());
    }
    match fallocate_fn(fd, offset, length) {
        Ok(()) => return Ok(()),
        Err(err) => match err.raw_os_error() {
            Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EINVAL) => {
                // Fall through to the write loop.
            }
            _ => return Err(err),
        },
    }

    let zeros = [0u8; 65536];
    let mut written: u64 = 0;
    while written < length {
        let remaining = length - written;
        let chunk = remaining.min(zeros.len() as u64) as usize;
        // SAFETY: `zeros` is a stack-allocated [u8; 65536] live for
        // the duration of this call. `chunk` is bounded by
        // `zeros.len()` via the preceding .min(), so pwrite reads at
        // most that many bytes from the buffer. fd is caller-owned.
        let rc = unsafe {
            libc::pwrite(
                fd,
                zeros.as_ptr() as *const libc::c_void,
                chunk,
                (offset + written) as libc::off_t,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if rc == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "pwrite returned 0 during zero-fill",
            ));
        }
        written += rc as u64;
    }
    Ok(())
}

/// Apply the host-side portion of qcow2 preallocation, layered on
/// top of the metadata the guest already emitted.
///
/// - `off` / `metadata`: no-op (guest did all the work).
/// - `falloc`: `posix_fallocate` over the data region.
/// - `full`: zero-fill (via `fallocate(FALLOC_FL_ZERO_RANGE)`,
///   falling back to a `pwrite` loop).
///
/// Unknown modes are treated as no-ops; the validator rejects them
/// before reaching this function.
fn apply_preallocation(
    file: &std::fs::File,
    op_name: &str,
    mode: &str,
    data_offset: u64,
    data_len: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::AsRawFd;

    if data_len == 0 {
        return Ok(());
    }
    let fd = file.as_raw_fd();
    match mode {
        "falloc" => {
            // SAFETY: fd is the raw fd of `file`, caller-owned for
            // the duration of this call. data_offset and data_len
            // are bounded by the caller: `run_create_nonraw`
            // clamps against the planned file size; `run_resize_nonraw`
            // rejects guest-reported file sizes above the virtio
            // capacity hint before calling here, and the
            // `data_offset` derives from `file_size_before` (read
            // from `stat()`). Out-of-range casts surface as EINVAL
            // from posix_fallocate rather than UB.
            let rc = unsafe {
                libc::posix_fallocate(fd, data_offset as libc::off_t, data_len as libc::off_t)
            };
            if rc != 0 {
                return Err(format!(
                    "{}: posix_fallocate failed: {}",
                    op_name,
                    std::io::Error::from_raw_os_error(rc)
                )
                .into());
            }
        }
        "full" => {
            fill_zeros(fd, data_offset, data_len)
                .map_err(|e| format!("{}: zero-fill failed: {}", op_name, e))?;
        }
        _ => {}
    }
    Ok(())
}

/// Render a successful create to stdout in the user's chosen
/// format.
///
/// `human` (default) emits a qemu-img-style one-liner:
///     Created: foo.qcow2 (format=qcow2, virtual_size=1073741824, cluster_size=65536)
/// `json` emits a 4-space-indented object with a fixed key order.
/// `-q` (args.quiet) suppresses the human line; JSON output is
/// always emitted regardless of -q so scripts can rely on it.
fn render_create_success(
    args: &CreateArgs,
    virtual_size: u64,
    metadata_bytes_written: u64,
    file_size_after: u64,
    resolved_unit_size: u32,
) {
    if args.output == "json" {
        render_create_success_json(
            args,
            virtual_size,
            metadata_bytes_written,
            file_size_after,
            resolved_unit_size,
        );
        return;
    }
    if args.quiet {
        return;
    }
    if resolved_unit_size == 0 {
        println!(
            "Created: {} (format={}, virtual_size={})",
            args.filename, args.target_format, virtual_size
        );
    } else {
        println!(
            "Created: {} (format={}, virtual_size={}, unit_size={})",
            args.filename, args.target_format, virtual_size, resolved_unit_size
        );
    }
}

/// JSON object companion to the human-readable success line.
///
/// 4-space indent, key order: filename, format, virtual_size,
/// metadata_bytes_written, file_size_after, resolved_unit_size.
/// The escape pass on `filename` matches measure's JSON output for
/// strings containing backslashes or quotes.
fn render_create_success_json(
    args: &CreateArgs,
    virtual_size: u64,
    metadata_bytes_written: u64,
    file_size_after: u64,
    resolved_unit_size: u32,
) {
    let escaped = json_escape_string(&args.filename);
    println!("{{");
    println!("    \"filename\": \"{}\",", escaped);
    println!("    \"format\": \"{}\",", args.target_format);
    println!("    \"virtual_size\": {},", virtual_size);
    println!(
        "    \"metadata_bytes_written\": {},",
        metadata_bytes_written
    );
    println!("    \"file_size_after\": {},", file_size_after);
    println!("    \"resolved_unit_size\": {}", resolved_unit_size);
    println!("}}");
}

/// Minimal JSON-string escaping for `"` and `\`. Filenames may
/// contain either; the rest of the renderer assumes ASCII-safe
/// values for the other fields (numeric or controlled strings).
fn json_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Host-side defensive validation of `CreateArgs`. The guest
/// re-checks every critical field, but failing early at the host
/// gives a clearer user-facing error before any I/O or KVM setup.
fn validate_create_args(args: &CreateArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Filename + (size or backing).
    if args.filename.is_empty() {
        return Err("create: FILENAME is required".into());
    }
    if args.size.is_none() && args.backing.is_none() {
        return Err("create: either SIZE or -b BACKING must be provided".into());
    }

    // Sector size: phase 3 only supports 512. Larger sector sizes
    // are valid per the call-table ABI but the create metadata
    // layouts in `crates/create` were sized for 512-byte alignment
    // (per-format header / descriptor / footer offsets), and the
    // guest's sector-by-sector write loop would conflate multiple
    // metadata regions into a single big sector if asked. Phase 5
    // may relax this once the planner emits coalesced sector-sized
    // writes.
    if args.sector_size != 512 {
        return Err(format!(
            "create: --sector-size must be 512 in phase 3 \
             (larger sector sizes are deferred — see PLAN-create.md \
             phase 5; got {})",
            args.sector_size
        )
        .into());
    }

    // Per-format option validation. Each ignores the default 0
    // sentinel (filled in by the per-format handler later).
    if args.cluster_size != 0
        && (args.cluster_size < 512
            || args.cluster_size > (2 << 20)
            || !args.cluster_size.is_power_of_two())
    {
        return Err(format!(
            "create: --cluster-size must be a power of 2 in 512..=2 MiB (got {})",
            args.cluster_size
        )
        .into());
    }
    if args.refcount_bits != 0 && !matches!(args.refcount_bits, 1 | 2 | 4 | 8 | 16 | 32 | 64) {
        return Err(format!(
            "create: --refcount-bits must be one of 1,2,4,8,16,32,64 (got {})",
            args.refcount_bits
        )
        .into());
    }
    if args.grain_size != 0
        && (args.grain_size < 4096 || args.grain_size > 65536 || !args.grain_size.is_power_of_two())
    {
        return Err(format!(
            "create: --grain-size must be a power of 2 in [4 KiB, 64 KiB] (got {})",
            args.grain_size
        )
        .into());
    }
    if args.block_size != 0 && !args.block_size.is_power_of_two() {
        return Err(format!(
            "create: --block-size must be a power of 2 (got {})",
            args.block_size
        )
        .into());
    }

    // Subformat must be valid for the chosen target.
    match args.target_format.as_str() {
        "vmdk" => {
            if !matches!(
                args.subformat.as_str(),
                "" | "monolithicSparse" | "streamOptimized" | "monolithicFlat"
            ) {
                return Err(format!(
                    "create: --subformat '{}' is not valid for vmdk \
                     (expected monolithicSparse, streamOptimized, or monolithicFlat)",
                    args.subformat
                )
                .into());
            }
            if args.subformat == "monolithicFlat" {
                return Err("create: vmdk monolithicFlat is not yet supported \
                            (multi-file subformats land in phase 5 of \
                            PLAN-create.md; use instar convert -O vmdk for now)"
                    .into());
            }
        }
        "vpc" => {
            if !matches!(args.subformat.as_str(), "" | "dynamic" | "fixed") {
                return Err(format!(
                    "create: --subformat '{}' is not valid for vpc (expected dynamic or fixed)",
                    args.subformat
                )
                .into());
            }
        }
        _ => {
            if !args.subformat.is_empty() {
                return Err(format!(
                    "create: --subformat is only valid with -f vmdk or -f vpc (got -f {})",
                    args.target_format
                )
                .into());
            }
        }
    }

    // Preallocation accept set (phase 6):
    //   off       — any format (default)
    //   metadata  — qcow2 only (raw has no metadata to preallocate;
    //               vmdk/vpc/vhdx deferred)
    //   falloc    — raw or qcow2
    //   full      — raw or qcow2
    // Non-qcow2 sparse formats (vmdk/vpc/vhdx) reject all non-`off`
    // modes with a clear "future work" pointer.
    match (args.target_format.as_str(), args.preallocation.as_str()) {
        (_, "off") => {}
        ("raw", "metadata") => {
            return Err("create: --preallocation=metadata is not valid for raw \
                 (raw has no metadata to preallocate)"
                .into());
        }
        ("qcow2", "metadata") | ("raw" | "qcow2", "falloc") | ("raw" | "qcow2", "full") => {}
        ("vmdk" | "vpc" | "vhdx", mode @ ("metadata" | "falloc" | "full")) => {
            return Err(format!(
                "create: --preallocation={} is not yet supported for {} \
                 (non-qcow2 preallocation is future work — see PLAN-create.md)",
                mode, args.target_format
            )
            .into());
        }
        (_, other) => {
            return Err(format!("create: unknown --preallocation '{}'", other).into());
        }
    }

    // Raw doesn't support backing. Reject explicitly.
    if args.target_format == "raw" && args.backing.is_some() {
        return Err("create: -f raw does not support -b BACKING (raw images \
                    have no backing-file concept)"
            .into());
    }

    // Backing without -F and without -u: match modern qemu-img and refuse.
    if args.backing.is_some() && args.backing_format.is_none() && !args.backing_unsafe {
        return Err("create: -b BACKING requires either -F BACKING_FORMAT or \
                    -u (backing-unsafe). Refusing to guess the backing format \
                    matches modern qemu-img."
            .into());
    }

    // Size, when provided, must parse to a non-zero value and stay
    // within the host's off_t range — the preallocation path casts
    // virtual_size to libc::off_t (i64), and values above i64::MAX
    // wrap to negative offsets, which would fail with EINVAL but
    // shouldn't reach the syscall in the first place.
    if let Some(ref s) = args.size {
        let parsed = parse_memory_size(s)?;
        if parsed == 0 {
            return Err("create: SIZE must be greater than zero".into());
        }
        if parsed > i64::MAX as u64 {
            return Err(format!(
                "create: SIZE {parsed} exceeds the maximum representable \
                 size ({})",
                i64::MAX
            )
            .into());
        }
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
    println!("    \"size-mismatch\": {size_mismatch}");
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

fn setup_page_tables(
    guest_mem: &GuestMemoryMmap,
    guest_mem_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let pml4_addr = PAGE_TABLE_BASE;
    let pdpt_addr = PAGE_TABLE_BASE + 0x1000;
    let pd_base = PAGE_TABLE_BASE + 0x2000;

    // PML4[0] -> PDPT
    guest_mem.write_obj(
        pdpt_addr | PTE_PRESENT | PTE_WRITABLE,
        GuestAddress(pml4_addr),
    )?;

    // Coverage must include both guest memory AND the MMIO region.
    // MMIO is placed above guest memory when guest_mem_size > DEFAULT_MMIO_BASE.
    // SAFETY: ACTIVE_MMIO_BASE was initialized before VM setup and is
    // never modified after initialization. Read-only access is safe.
    let mmio_base = unsafe { ACTIVE_MMIO_BASE };
    let mmio_end = mmio_base + MMIO_SIZE * MAX_CHAIN_DEPTH as u64;
    let coverage = guest_mem_size.max(mmio_end);

    // For >1GB: multiple PD pages, each covering 1GB (512 × 2MB pages).
    // Page table area 0x2000-0x10000 fits PML4 + PDPT + up to 12 PD pages = 12GB.
    let num_gb = coverage.div_ceil(1 << 30);
    let num_pd_pages = num_gb.max(1);
    let max_pd_pages = (GUEST_CODE_BASE - pd_base) / 0x1000;
    if num_pd_pages > max_pd_pages {
        return Err(format!(
            "guest memory {num_gb}GB requires {num_pd_pages} PD pages, max {max_pd_pages} ({max_pd_pages}GB)"
        )
        .into());
    }

    // PDPT[i] -> PD[i] for each GB of memory
    for gb in 0..num_pd_pages {
        let pd_addr = pd_base + gb * 0x1000;
        guest_mem.write_obj(
            pd_addr | PTE_PRESENT | PTE_WRITABLE,
            GuestAddress(pdpt_addr + gb * 8),
        )?;
    }

    // PD entries: identity-map with 2MB pages (full PD pages)
    for gb in 0..num_pd_pages {
        let pd_addr = pd_base + gb * 0x1000;
        for j in 0..512u64 {
            let phys_addr = (gb * 512 + j) * 0x200000;
            let entry = phys_addr | PTE_PRESENT | PTE_WRITABLE | PTE_PAGE_SIZE;
            guest_mem.write_obj(entry, GuestAddress(pd_addr + j * 8))?;
        }
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

#[cfg(test)]
mod create_option_tests {
    //! Unit tests for `parse_create_o_options` and its helpers.
    //!
    //! Tests live next to the parser rather than in tests/ so they
    //! don't require the integration-test harness (no KVM, no
    //! testdata). Integration coverage of the wired path lives in
    //! tests/test_create.py.
    use super::*;

    fn s(v: &str) -> Vec<String> {
        vec![v.to_string()]
    }

    #[test]
    fn empty_overrides_parse_cleanly() {
        let o = parse_create_o_options("qcow2", &[]).unwrap();
        assert!(o.cluster_size.is_none());
        assert!(o.size.is_none());
        assert!(o.backing_file.is_none());
    }

    #[test]
    fn qcow2_all_keys_parse() {
        let o = parse_create_o_options(
            "qcow2",
            &s(
                "cluster_size=4k,refcount_bits=8,extended_l2=on,lazy_refcounts=yes,\
                compat=0.10,preallocation=off,size=64M,backing_file=p.qcow2,\
                backing_fmt=qcow2,compression_type=zlib",
            ),
        )
        .unwrap();
        assert_eq!(o.cluster_size, Some(4096));
        assert_eq!(o.refcount_bits, Some(8));
        assert_eq!(o.extended_l2, Some(true));
        assert_eq!(o.lazy_refcounts, Some(true));
        assert_eq!(o.compat_v3, Some(false));
        assert_eq!(o.preallocation, Some("off"));
        assert_eq!(o.size, Some(64 * 1024 * 1024));
        assert_eq!(o.backing_file.as_deref(), Some("p.qcow2"));
        assert_eq!(o.backing_fmt, Some("qcow2"));
    }

    #[test]
    fn vmdk_subformat_and_grain() {
        let o =
            parse_create_o_options("vmdk", &s("subformat=streamOptimized,grain_size=16k")).unwrap();
        assert_eq!(o.vmdk_subformat, Some(1));
        assert_eq!(o.grain_size, Some(16 * 1024));
    }

    #[test]
    fn vmdk_monolithic_flat_parses_but_host_will_reject() {
        // Phase 1's library and phase 3's host validator reject
        // monolithicFlat; the parser is permissive so the user gets
        // the more specific "deferred" error from the host pass.
        let o = parse_create_o_options("vmdk", &s("subformat=monolithicFlat")).unwrap();
        assert_eq!(o.vmdk_subformat, Some(2));
    }

    #[test]
    fn vpc_subformat_fixed() {
        let o = parse_create_o_options("vpc", &s("subformat=fixed")).unwrap();
        assert_eq!(o.vhd_subformat, Some(1));
    }

    #[test]
    fn vhdx_block_size() {
        let o = parse_create_o_options("vhdx", &s("block_size=8M")).unwrap();
        assert_eq!(o.block_size, Some(8 * 1024 * 1024));
    }

    #[test]
    fn raw_size_and_preallocation() {
        let o = parse_create_o_options("raw", &s("size=4M,preallocation=falloc")).unwrap();
        assert_eq!(o.size, Some(4 * 1024 * 1024));
        assert_eq!(o.preallocation, Some("falloc"));
    }

    #[test]
    fn unknown_key_errors_with_target_name() {
        let err = parse_create_o_options("qcow2", &s("nonsense=1"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("nonsense"), "error did not mention key: {err}");
        assert!(err.contains("qcow2"), "error did not mention target: {err}");
    }

    #[test]
    fn bad_cluster_size_value_errors() {
        let err = parse_create_o_options("qcow2", &s("cluster_size=zzz"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cluster_size"), "error mentions key: {err}");
    }

    #[test]
    fn bad_compat_value_errors() {
        let err = parse_create_o_options("qcow2", &s("compat=2.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("compat"));
    }

    #[test]
    fn last_wins_across_multiple_o_invocations() {
        let raw = vec![
            "cluster_size=512".to_string(),
            "cluster_size=4k".to_string(),
        ];
        let o = parse_create_o_options("qcow2", &raw).unwrap();
        assert_eq!(o.cluster_size, Some(4096));
    }

    #[test]
    fn last_wins_within_single_o_invocation() {
        let o = parse_create_o_options("qcow2", &s("cluster_size=512,cluster_size=4k")).unwrap();
        assert_eq!(o.cluster_size, Some(4096));
    }

    #[test]
    fn encrypt_keys_return_deferred_error() {
        let err = parse_create_o_options("qcow2", &s("encrypt.cipher=aes"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("encrypt"));
        assert!(err.contains("deferred"));
    }

    #[test]
    fn data_file_returns_deferred_error() {
        let err = parse_create_o_options("qcow2", &s("data_file=ext.bin"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("data_file"));
        assert!(err.contains("deferred"));
    }

    #[test]
    fn qcow2_preallocation_metadata_accepted() {
        let o = parse_create_o_options("qcow2", &s("preallocation=metadata")).unwrap();
        assert_eq!(o.preallocation, Some("metadata"));
    }

    #[test]
    fn qcow2_preallocation_falloc_accepted() {
        let o = parse_create_o_options("qcow2", &s("preallocation=falloc")).unwrap();
        assert_eq!(o.preallocation, Some("falloc"));
    }

    #[test]
    fn qcow2_preallocation_full_accepted() {
        let o = parse_create_o_options("qcow2", &s("preallocation=full")).unwrap();
        assert_eq!(o.preallocation, Some("full"));
    }

    #[test]
    fn raw_preallocation_metadata_rejected() {
        let err = parse_create_o_options("raw", &s("preallocation=metadata"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("raw has no metadata"));
    }

    #[test]
    fn raw_preallocation_full_accepted() {
        let o = parse_create_o_options("raw", &s("preallocation=full")).unwrap();
        assert_eq!(o.preallocation, Some("full"));
    }

    #[test]
    fn vmdk_preallocation_metadata_deferred() {
        let err = parse_create_o_options("vmdk", &s("preallocation=metadata"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("non-qcow2 preallocation is future work"));
    }

    #[test]
    fn raw_rejects_qcow2_keys() {
        let err = parse_create_o_options("raw", &s("cluster_size=4k"))
            .unwrap_err()
            .to_string();
        // raw target doesn't accept cluster_size; the catch-all
        // produces an "unrecognised -o key" error mentioning raw.
        assert!(err.contains("cluster_size"));
        assert!(err.contains("raw"));
    }

    #[test]
    fn boolean_accepts_off_on_true_false_yes_no() {
        for v in ["on", "ON", "True", "yes"] {
            assert_eq!(parse_create_o_bool("k", v).unwrap(), true);
        }
        for v in ["off", "OFF", "False", "no"] {
            assert_eq!(parse_create_o_bool("k", v).unwrap(), false);
        }
        assert!(parse_create_o_bool("k", "maybe").is_err());
    }

    #[test]
    fn size_u64_accepts_t_suffix() {
        assert_eq!(parse_create_o_size_u64("size", "1T").unwrap(), 1u64 << 40);
    }

    #[test]
    fn missing_value_errors_with_helpful_message() {
        let err = parse_create_o_options("qcow2", &s("cluster_size"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing a value"));
    }

    #[test]
    fn empty_pieces_are_skipped() {
        // Trailing or empty comma-separated pieces are ignored.
        let o = parse_create_o_options("qcow2", &s(",cluster_size=4k,,")).unwrap();
        assert_eq!(o.cluster_size, Some(4096));
    }

    #[test]
    fn backing_fmt_accepts_vhd_alias() {
        let o = parse_create_o_options("qcow2", &s("backing_fmt=vhd")).unwrap();
        // qemu-img uses "vpc" canonically for VHD; we accept "vhd"
        // as an alias and normalise to "vpc".
        assert_eq!(o.backing_fmt, Some("vpc"));
    }
}

#[cfg(test)]
mod resize_size_parser_tests {
    //! Unit tests for `parse_qemu_img_size` and `parse_resize_size`.
    //! Integration coverage of the wired CLI path lives in
    //! `tests/test_resize.py` once phase 11 lands.
    use super::*;

    #[test]
    fn qemu_img_size_bare_number_is_bytes() {
        assert_eq!(parse_qemu_img_size("1024").unwrap(), 1024);
    }

    #[test]
    fn qemu_img_size_suffixes() {
        assert_eq!(parse_qemu_img_size("1b").unwrap(), 512);
        assert_eq!(parse_qemu_img_size("1k").unwrap(), 1024);
        assert_eq!(parse_qemu_img_size("1K").unwrap(), 1024);
        assert_eq!(parse_qemu_img_size("1M").unwrap(), 1 << 20);
        assert_eq!(parse_qemu_img_size("1G").unwrap(), 1 << 30);
        assert_eq!(parse_qemu_img_size("1T").unwrap(), 1u64 << 40);
        assert_eq!(parse_qemu_img_size("1P").unwrap(), 1u64 << 50);
        assert_eq!(parse_qemu_img_size("1E").unwrap(), 1u64 << 60);
    }

    #[test]
    fn qemu_img_size_rejects_empty() {
        assert!(parse_qemu_img_size("").is_err());
        assert!(parse_qemu_img_size("   ").is_err());
    }

    #[test]
    fn qemu_img_size_rejects_garbage() {
        assert!(parse_qemu_img_size("abc").is_err());
        assert!(parse_qemu_img_size("1xq").is_err());
    }

    #[test]
    fn qemu_img_size_overflow() {
        // 16 EiB * 2 overflows u64.
        assert!(parse_qemu_img_size("32E").is_err());
    }

    #[test]
    fn resize_size_absolute() {
        match parse_resize_size("1G").unwrap() {
            ParsedResizeSize::Absolute(v) => assert_eq!(v, 1 << 30),
            other => panic!("expected Absolute, got {other:?}"),
        }
    }

    #[test]
    fn resize_size_additive() {
        match parse_resize_size("+512M").unwrap() {
            ParsedResizeSize::Add(v) => assert_eq!(v, 512 << 20),
            other => panic!("expected Add, got {other:?}"),
        }
    }

    #[test]
    fn resize_size_subtractive() {
        match parse_resize_size("-256k").unwrap() {
            ParsedResizeSize::Subtract(v) => assert_eq!(v, 256 << 10),
            other => panic!("expected Subtract, got {other:?}"),
        }
    }

    #[test]
    fn resize_size_rejects_empty() {
        assert!(parse_resize_size("").is_err());
        assert!(parse_resize_size("+").is_err());
        assert!(parse_resize_size("-").is_err());
    }

    #[test]
    fn image_format_names_match_qemu() {
        assert_eq!(image_format_name(IMAGE_FORMAT_RAW), "raw");
        assert_eq!(image_format_name(IMAGE_FORMAT_QCOW2), "qcow2");
        assert_eq!(image_format_name(IMAGE_FORMAT_VMDK4), "vmdk");
        assert_eq!(image_format_name(IMAGE_FORMAT_VMDK3), "vmdk");
        // qemu canonical name for VHD is "vpc" (Virtual PC).
        assert_eq!(image_format_name(IMAGE_FORMAT_VHD), "vpc");
        assert_eq!(image_format_name(IMAGE_FORMAT_VHDX), "vhdx");
        assert_eq!(image_format_name(999), "unknown");
    }

    #[test]
    fn resize_error_codes_have_messages() {
        // Forward-compat tripwire: every numeric error code we
        // ship has a non-empty human message.  If a future
        // ResizeResult::ERROR_* lands without a matching arm in
        // map_resize_error, the fallback returns "unknown
        // resize error code N" — we want every known code to
        // hit a specific message instead.
        for code in 0..=RESIZE_RESULT_ERROR_HEADER_MISMATCH {
            let msg = map_resize_error(code);
            assert!(!msg.is_empty(), "code {code} has empty message");
            assert!(
                !msg.starts_with("unknown"),
                "code {code} hit the unknown-fallback: {msg}"
            );
        }
    }

    #[test]
    fn resize_args_parse_via_clap() {
        // Smoke test: clap parses the documented flag set
        // without surprises.  Uses Cli::try_parse_from rather
        // than running main so we don't actually launch
        // anything.
        use clap::Parser;
        let argv = vec![
            "instar",
            "resize",
            "--shrink",
            "--preallocation",
            "off",
            "-q",
            "--output",
            "json",
            "foo.qcow2",
            "+1G",
        ];
        let cli = Cli::try_parse_from(argv).expect("clap parse");
        match cli.command {
            Commands::Resize(args) => {
                assert!(args.shrink);
                assert_eq!(args.preallocation, "off");
                assert!(args.quiet);
                assert_eq!(args.output, "json");
                assert_eq!(args.filename, "foo.qcow2");
                assert_eq!(args.size, "+1G");
            }
            other => panic!("expected Resize, got {other:?}"),
        }
    }

    #[test]
    fn resize_args_clap_accepts_every_preallocation_mode() {
        // Phase 9 ships post-pass handling for every documented
        // preallocation mode.  Verify clap accepts each one; the
        // post-pass logic itself is exercised by integration tests
        // in phase 11.
        use clap::Parser;
        for mode in ["off", "metadata", "falloc", "full"] {
            let argv = vec![
                "instar",
                "resize",
                "--preallocation",
                mode,
                "foo.qcow2",
                "+1G",
            ];
            let cli = Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("clap rejected --preallocation={mode}: {e}"));
            match cli.command {
                Commands::Resize(args) => {
                    assert_eq!(args.preallocation, mode);
                }
                other => panic!("expected Resize, got {other:?}"),
            }
        }
    }
}

#[cfg(test)]
mod amend_o_option_parser_tests {
    //! Unit tests for `parse_amend_o_options`. Integration
    //! coverage of the wired CLI path lives in
    //! `tests/test_amend.py` once phase 6 lands.
    use super::*;

    fn opts(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn compat_v2() {
        let parsed = parse_amend_o_options(&opts(&["compat=0.10"])).unwrap();
        assert_eq!(parsed.compat_v3, Some(false));
        assert_eq!(parsed.lazy_on, None);
    }

    #[test]
    fn compat_v3() {
        let parsed = parse_amend_o_options(&opts(&["compat=1.1"])).unwrap();
        assert_eq!(parsed.compat_v3, Some(true));
        assert_eq!(parsed.lazy_on, None);
    }

    #[test]
    fn lazy_on() {
        let parsed = parse_amend_o_options(&opts(&["lazy_refcounts=on"])).unwrap();
        assert_eq!(parsed.compat_v3, None);
        assert_eq!(parsed.lazy_on, Some(true));
    }

    #[test]
    fn lazy_off() {
        let parsed = parse_amend_o_options(&opts(&["lazy_refcounts=off"])).unwrap();
        assert_eq!(parsed.compat_v3, None);
        assert_eq!(parsed.lazy_on, Some(false));
    }

    #[test]
    fn both_in_one_o() {
        let parsed = parse_amend_o_options(&opts(&["compat=1.1,lazy_refcounts=on"])).unwrap();
        assert_eq!(parsed.compat_v3, Some(true));
        assert_eq!(parsed.lazy_on, Some(true));
    }

    #[test]
    fn multiple_o_entries() {
        let parsed = parse_amend_o_options(&opts(&["compat=0.10", "lazy_refcounts=off"])).unwrap();
        assert_eq!(parsed.compat_v3, Some(false));
        assert_eq!(parsed.lazy_on, Some(false));
    }

    #[test]
    fn bad_compat_value() {
        let err = parse_amend_o_options(&opts(&["compat=2.0"])).unwrap_err();
        assert!(err.to_string().contains("expected 0.10 or 1.1"), "{err}");
    }

    #[test]
    fn bad_lazy_value() {
        let err = parse_amend_o_options(&opts(&["lazy_refcounts=maybe"])).unwrap_err();
        assert!(err.to_string().contains("expected on/off"), "{err}");
    }

    #[test]
    fn unsupported_key_cluster_size() {
        let err = parse_amend_o_options(&opts(&["cluster_size=64k"])).unwrap_err();
        assert!(err.to_string().contains("is not supported"), "{err}");
    }

    #[test]
    fn unsupported_key_refcount_bits() {
        let err = parse_amend_o_options(&opts(&["refcount_bits=8"])).unwrap_err();
        assert!(err.to_string().contains("is not supported"), "{err}");
    }

    #[test]
    fn empty_input_is_error() {
        let err = parse_amend_o_options(&[]).unwrap_err();
        assert!(
            err.to_string().contains("no supported -o options given"),
            "{err}"
        );
    }

    #[test]
    fn only_blank_pieces_is_error() {
        // Empty/blank comma pieces are skipped, leaving no
        // supported option set.
        let err = parse_amend_o_options(&opts(&[" , "])).unwrap_err();
        assert!(
            err.to_string().contains("no supported -o options given"),
            "{err}"
        );
    }

    #[test]
    fn missing_value_is_error() {
        let err = parse_amend_o_options(&opts(&["compat"])).unwrap_err();
        assert!(err.to_string().contains("missing a value"), "{err}");
    }
}

#[cfg(test)]
mod preallocation_tests {
    //! Unit tests for `fill_zeros_inner`.
    //!
    //! The closure parameter lets us drive the EOPNOTSUPP fallback
    //! path without depending on the host filesystem's
    //! `FALLOC_FL_ZERO_RANGE` support, which is missing on tmpfs and
    //! some FUSE / NFS mounts where these tests might run.
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;

    #[test]
    fn fill_zeros_inner_fast_path() {
        // Closure returns Ok(()): the fallocate path "succeeds" and
        // we exit without falling through to the pwrite loop. The
        // file is never touched.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let fd = tmp.as_file().as_raw_fd();
        let called = std::cell::Cell::new(false);
        let result = fill_zeros_inner(fd, 0, 4096, |_fd, off, len| {
            called.set(true);
            assert_eq!(off, 0);
            assert_eq!(len, 4096);
            Ok(())
        });
        assert!(result.is_ok());
        assert!(called.get());
        // File is still empty: the closure didn't actually zero, and
        // the loop didn't fire.
        assert_eq!(tmp.as_file().metadata().unwrap().len(), 0);
    }

    #[test]
    fn fill_zeros_inner_eopnotsupp_falls_back_to_pwrite() {
        // Closure returns EOPNOTSUPP: we fall through to the pwrite
        // loop and verify the bytes are actually zeroed.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // Pre-fill with non-zero bytes so we can confirm the
        // fallback overwrites them with zeros.
        tmp.write_all(&[0xAAu8; 8192]).unwrap();
        tmp.flush().unwrap();
        let fd = tmp.as_file().as_raw_fd();
        let result = fill_zeros_inner(fd, 1024, 4096, |_fd, _off, _len| {
            Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP))
        });
        assert!(result.is_ok());
        let mut buf = vec![0u8; 8192];
        tmp.as_file().seek(SeekFrom::Start(0)).unwrap();
        tmp.as_file().read_exact(&mut buf).unwrap();
        // First 1024 bytes unchanged (0xAA).
        assert!(buf[..1024].iter().all(|&b| b == 0xAA));
        // Middle 4096 bytes zeroed.
        assert!(buf[1024..5120].iter().all(|&b| b == 0));
        // Trailing bytes unchanged (0xAA).
        assert!(buf[5120..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn fill_zeros_inner_unrelated_error_propagates() {
        // Closure returns EIO: not in the fallback whitelist, so the
        // error bubbles up unmodified and the pwrite loop never runs.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let fd = tmp.as_file().as_raw_fd();
        let result = fill_zeros_inner(fd, 0, 4096, |_fd, _off, _len| {
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        });
        let err = result.expect_err("EIO should propagate");
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        // File untouched.
        assert_eq!(tmp.as_file().metadata().unwrap().len(), 0);
    }

    #[test]
    fn fill_zeros_inner_zero_length_is_noop() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let fd = tmp.as_file().as_raw_fd();
        let called = std::cell::Cell::new(false);
        let result = fill_zeros_inner(fd, 0, 0, |_fd, _off, _len| {
            called.set(true);
            Ok(())
        });
        assert!(result.is_ok());
        assert!(!called.get(), "zero-length call must short-circuit");
    }
}

#[cfg(test)]
mod map_renderer_tests {
    //! Tests for the phase 3c placeholder map renderer
    //! (format_map_human, format_map_json, map_state_triple,
    //! map_error_message). Phase 4 will replace these with
    //! byte-for-byte qemu-img-compatible formatters; until then,
    //! these tests pin the placeholder's structural invariants
    //! (state-triple table, JSON field ordering, error-message
    //! table) so phase 4 can refactor with confidence.
    use super::*;

    /// Build a `MapExtentMessage` by routing through the
    /// public guest-protocol builder so the private `push_str`
    /// helper stays encapsulated.
    fn ext(start: u64, length: u64, state: &str, file_offset: u64) -> guest_::MapExtentMessage {
        let msg = guest_protocol::map_extent_message(start, length, state, file_offset);
        match msg.payload {
            Some(guest_::GuestMessage_::Payload::MapExtent(e)) => e,
            _ => panic!("map_extent_message must wrap a MapExtent payload"),
        }
    }

    // --- map_state_triple -----------------------------------------------

    #[test]
    fn state_triple_hole() {
        assert_eq!(map_state_triple("hole"), (false, true, false, false));
    }

    #[test]
    fn state_triple_zero() {
        assert_eq!(map_state_triple("zero"), (true, true, false, false));
    }

    #[test]
    fn state_triple_data() {
        assert_eq!(map_state_triple("data"), (true, false, true, true));
    }

    #[test]
    fn state_triple_unknown_falls_back_to_data() {
        // Defensive: an unknown state preserves the offset for
        // debugging rather than dropping it.
        assert_eq!(map_state_triple("future-state"), (true, false, true, true));
    }

    // The phase 3c format_map_human / format_map_json tests were
    // removed in step 4b; their byte-exact replacements live in
    // the "Phase 4: MapRenderer byte-exact tests" section below.

    // --- map_error_message ----------------------------------------------

    #[test]
    fn error_ok_returns_none() {
        assert!(map_error_message(MAP_RESULT_ERROR_OK).is_none());
    }

    #[test]
    fn error_codes_have_distinct_messages() {
        let codes = [
            MAP_RESULT_ERROR_INVALID_SOURCE,
            MAP_RESULT_ERROR_INVALID_OPTION,
            MAP_RESULT_ERROR_HAS_BACKING,
            MAP_RESULT_ERROR_IO,
        ];
        let messages: Vec<&'static str> = codes
            .iter()
            .map(|c| map_error_message(*c).expect("known error must have message"))
            .collect();
        // Each message is non-empty and contains the "map: " prefix.
        for m in &messages {
            assert!(!m.is_empty());
            assert!(m.starts_with("map: "), "missing prefix: {}", m);
        }
        // Messages must be mutually distinct so the user can tell
        // which failure occurred.
        for i in 0..messages.len() {
            for j in (i + 1)..messages.len() {
                assert_ne!(
                    messages[i], messages[j],
                    "error codes {} and {} share a message",
                    codes[i], codes[j]
                );
            }
        }
    }

    #[test]
    fn error_unknown_returns_generic_message() {
        let msg = map_error_message(999).expect("unknown error returns Some");
        assert!(msg.contains("unknown"));
    }

    #[test]
    fn error_has_backing_mentions_chain_followup() {
        let msg = map_error_message(MAP_RESULT_ERROR_HAS_BACKING)
            .expect("has-backing error must have message");
        assert!(msg.contains("chain") || msg.contains("PLAN-map"));
    }

    // ================================================================
    // Phase 4: MapRenderer byte-exact tests.
    //
    // Expected byte sequences were captured by running
    // `qemu-img map --output={human,json}` against synthetic
    // fixtures during phase 4a development. The renderer's job is
    // to match qemu-img byte-for-byte (modulo the documented
    // divergences in docs/quirks.md); these tests pin that
    // contract.
    // ================================================================

    fn render_human(extents: &[guest_::MapExtentMessage], filename: &str) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut r = MapRenderer::new(&mut buf, "human", filename.to_string());
            r.begin().unwrap();
            for e in extents {
                r.emit_extent(e).unwrap();
            }
            r.finish().unwrap();
        }
        buf
    }

    fn render_json(extents: &[guest_::MapExtentMessage]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut r = MapRenderer::new(&mut buf, "json", "<unused>".to_string());
            r.begin().unwrap();
            for e in extents {
                r.emit_extent(e).unwrap();
            }
            r.finish().unwrap();
        }
        buf
    }

    // --- format_hex_or_zero ---------------------------------------

    #[test]
    fn hex_or_zero_zero_is_literal_zero() {
        assert_eq!(format_hex_or_zero(0), "0");
    }

    #[test]
    fn hex_or_zero_nonzero_is_lowercase_hex() {
        assert_eq!(format_hex_or_zero(0x10000), "0x10000");
        assert_eq!(format_hex_or_zero(0x50000), "0x50000");
        assert_eq!(format_hex_or_zero(u64::MAX), "0xffffffffffffffff");
    }

    // --- Human-mode tests -----------------------------------------

    #[test]
    fn renderer_human_empty_extents_emits_header_only() {
        let out = render_human(&[], "any.qcow2");
        // 53 bytes: 4 columns, last unpadded, plus '\n'.
        assert_eq!(
            out,
            b"Offset          Length          Mapped to       File\n"
        );
    }

    #[test]
    fn human_single_data_extent_byte_exact() {
        // Matches qemu-img map output for an image with one
        // 64 KiB data extent at virtual offset 0 mapped to file
        // offset 0x50000.
        let out = render_human(&[ext(0, 0x10000, "data", 0x50000)], "m4.qcow2");
        let expected = "\
Offset          Length          Mapped to       File
0               0x10000         0x50000         m4.qcow2
";
        assert_eq!(out, expected.as_bytes());
    }

    #[test]
    fn human_zero_offset_renders_as_literal_zero() {
        // The "0" rule applies to every column: start=0 → "0",
        // length=0 still emits "0x..." because length is never
        // zero for a real extent (the coalescer drops zero-length
        // pushes), but file_offset=0 must render as "0" not "0x0".
        let out = render_human(&[ext(0, 0x10000, "data", 0)], "raw5.img");
        let expected = "\
Offset          Length          Mapped to       File
0               0x10000         0               raw5.img
";
        assert_eq!(out, expected.as_bytes());
    }

    #[test]
    fn human_holes_are_elided() {
        // qemu-img human output does not emit rows for holes or
        // zero-allocated extents; only data: true extents produce
        // visible rows.
        let out = render_human(
            &[
                ext(0, 0x10000, "hole", 0),
                ext(0x10000, 0x10000, "zero", 0),
                ext(0x20000, 0x10000, "data", 0x50000),
            ],
            "mix.qcow2",
        );
        let expected = "\
Offset          Length          Mapped to       File
0x20000         0x10000         0x50000         mix.qcow2
";
        assert_eq!(out, expected.as_bytes());
    }

    #[test]
    fn human_multiple_data_extents_preserve_order() {
        let out = render_human(
            &[
                ext(0, 0x10000, "data", 0x50000),
                ext(0x80000, 0x10000, "data", 0x60000),
            ],
            "m3.qcow2",
        );
        let expected = "\
Offset          Length          Mapped to       File
0               0x10000         0x50000         m3.qcow2
0x80000         0x10000         0x60000         m3.qcow2
";
        assert_eq!(out, expected.as_bytes());
    }

    #[test]
    fn human_filename_preserved_verbatim() {
        // qemu-img echoes the argv string in the File column —
        // relative paths stay relative, embedded chars survive.
        let out = render_human(&[ext(0, 0x10000, "data", 0)], "/tmp/has spaces/img.qcow2");
        let expected = "\
Offset          Length          Mapped to       File
0               0x10000         0               /tmp/has spaces/img.qcow2
";
        assert_eq!(out, expected.as_bytes());
    }

    #[test]
    fn human_large_offset_overflows_column_gracefully() {
        // 0xffffffffffffffff is 18 chars (with 0x prefix) which
        // overflows the 16-char column. {:<16} leaves the value
        // intact and the next column starts immediately after —
        // matches qemu-img's behaviour (no truncation, no panic).
        let out = render_human(&[ext(u64::MAX - 0xffff, 0x10000, "data", 0)], "big.img");
        let lines: Vec<&[u8]> = out.split(|&b| b == b'\n').collect();
        assert_eq!(
            lines[0],
            b"Offset          Length          Mapped to       File"
        );
        // Data row starts with the hex value; we just check
        // the value appears and the filename arrives at the end.
        assert!(lines[1].starts_with(b"0xffffffffffff"));
        assert!(lines[1].ends_with(b"big.img"));
    }

    // --- JSON-mode tests ------------------------------------------

    #[test]
    fn renderer_json_empty_extents_is_empty_array() {
        let out = render_json(&[]);
        assert_eq!(out, b"[]\n");
    }

    #[test]
    fn json_single_data_extent_byte_exact() {
        let out = render_json(&[ext(0, 0x10000, "data", 0x50000)]);
        // Field order: start, length, depth, present, zero, data,
        // compressed, offset. Single space after { and , — no
        // space before }. Trailing newline after `]` matches
        // qemu-img exactly.
        let expected = b"[{ \"start\": 0, \"length\": 65536, \"depth\": 0, \
                          \"present\": true, \"zero\": false, \"data\": true, \
                          \"compressed\": false, \"offset\": 327680}]\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn json_hole_omits_offset_but_includes_compressed_false() {
        let out = render_json(&[ext(0, 0x100000, "hole", 0)]);
        // Hole: present=false, zero=true, data=false. No offset.
        // compressed: false always emitted.
        let expected = b"[{ \"start\": 0, \"length\": 1048576, \"depth\": 0, \
                          \"present\": false, \"zero\": true, \"data\": false, \
                          \"compressed\": false}]\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn json_zero_state_is_present_no_offset() {
        // zero-allocated: present=true, zero=true, data=false.
        // No offset (data is false). compressed: false present.
        let out = render_json(&[ext(0, 0x10000, "zero", 0)]);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("\"present\": true"));
        assert!(s.contains("\"zero\": true"));
        assert!(s.contains("\"data\": false"));
        assert!(!s.contains("\"offset\""));
        assert!(s.contains("\"compressed\": false"));
    }

    #[test]
    fn json_inter_object_separator_is_comma_newline() {
        let out = render_json(&[
            ext(0, 0x10000, "data", 0x50000),
            ext(0x10000, 0x10000, "hole", 0),
        ]);
        let s = std::str::from_utf8(&out).unwrap();
        // The two objects are joined by },\n{
        assert!(s.contains("},\n{"));
        // No `},{` (without newline) — that would be wrong format.
        assert!(!s.contains("},{"));
    }

    #[test]
    fn json_multiple_extents_byte_exact() {
        // Matches qemu-img map output for the 3-extent qcow2
        // fixture (data + hole + data, 1 MiB total).
        let out = render_json(&[
            ext(0, 0x10000, "data", 0x50000),
            ext(0x10000, 0x10000, "hole", 0),
            ext(0x20000, 0x10000, "data", 0x70000),
        ]);
        let expected = b"[{ \"start\": 0, \"length\": 65536, \"depth\": 0, \
                          \"present\": true, \"zero\": false, \"data\": true, \
                          \"compressed\": false, \"offset\": 327680},\n\
                          { \"start\": 65536, \"length\": 65536, \"depth\": 0, \
                          \"present\": false, \"zero\": true, \"data\": false, \
                          \"compressed\": false},\n\
                          { \"start\": 131072, \"length\": 65536, \"depth\": 0, \
                          \"present\": true, \"zero\": false, \"data\": true, \
                          \"compressed\": false, \"offset\": 458752}]\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn json_trailing_newline_after_closing_bracket() {
        // qemu-img map --output=json emits a trailing newline
        // after the closing `]`; the phase 5 baselines confirm
        // this. Earlier plan-doc and quirks notes mistakenly said
        // "no trailing newline" — that was based on misreading
        // cat -A output (the $ marker appears before each
        // newline, not after). Updated 6b.
        let out = render_json(&[ext(0, 0x10000, "data", 0)]);
        assert!(
            out.ends_with(b"]\n"),
            "JSON output must end with `]\\n` to match qemu-img"
        );
    }

    #[test]
    fn json_compressed_false_emitted_for_every_state() {
        for state in ["hole", "zero", "data"] {
            let out = render_json(&[ext(0, 0x10000, state, 0)]);
            let s = std::str::from_utf8(&out).unwrap();
            assert!(
                s.contains("\"compressed\": false"),
                "state {} must emit compressed: false; got: {}",
                state,
                s,
            );
        }
    }

    #[test]
    fn json_field_order_is_canonical() {
        // Required field order: start, length, depth, present,
        // zero, data, compressed, offset. Subsequent phases (e.g.
        // when compressed becomes a real value) must not reorder.
        let out = render_json(&[ext(0, 4096, "data", 65536)]);
        let s = std::str::from_utf8(&out).unwrap();
        let order = [
            "\"start\":",
            "\"length\":",
            "\"depth\":",
            "\"present\":",
            "\"zero\":",
            "\"data\":",
            "\"compressed\":",
            "\"offset\":",
        ];
        let mut last_pos = 0usize;
        for field in order {
            let pos = s
                .find(field)
                .unwrap_or_else(|| panic!("missing field {} in JSON: {}", field, s));
            assert!(
                pos >= last_pos,
                "field {} appears out of order at byte {}: {}",
                field,
                pos,
                s
            );
            last_pos = pos;
        }
    }

    #[test]
    fn json_large_u64_offset_is_decimal() {
        // u64 values near 1 TiB must serialise as decimal, not
        // hex or scientific notation.
        let big = 1u64 << 40; // 1 TiB
        let out = render_json(&[ext(0, 4096, "data", big)]);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(&format!("\"offset\": {}", big)));
        // No accidental hex / 0x prefix.
        assert!(!s.contains("0x"));
    }

    // --- Lifecycle / counter tests --------------------------------

    #[test]
    fn renderer_extents_written_counts_data_only_in_human() {
        let mut buf: Vec<u8> = Vec::new();
        let mut r = MapRenderer::new(&mut buf, "human", "img".to_string());
        r.begin().unwrap();
        r.emit_extent(&ext(0, 0x10000, "hole", 0)).unwrap();
        r.emit_extent(&ext(0x10000, 0x10000, "data", 0x50000))
            .unwrap();
        r.emit_extent(&ext(0x20000, 0x10000, "zero", 0)).unwrap();
        r.finish().unwrap();
        // Only the data extent counted.
        assert_eq!(r.extents_written, 1);
    }

    #[test]
    fn renderer_extents_written_counts_all_in_json() {
        let mut buf: Vec<u8> = Vec::new();
        let mut r = MapRenderer::new(&mut buf, "json", "img".to_string());
        r.begin().unwrap();
        r.emit_extent(&ext(0, 0x10000, "hole", 0)).unwrap();
        r.emit_extent(&ext(0x10000, 0x10000, "data", 0x50000))
            .unwrap();
        r.emit_extent(&ext(0x20000, 0x10000, "zero", 0)).unwrap();
        r.finish().unwrap();
        // JSON mode counts every extent.
        assert_eq!(r.extents_written, 3);
    }

    // ================================================================
    // PLAN-snapshot phase 4: SnapshotRenderer tests.
    //
    // Human-mode fixtures are byte-exact against qemu-img 10.0.8's
    // `dump_one_snapshot` output (column titles `VM_SIZE`/`VM_CLOCK`
    // with underscores; widths 7/16/8/19/15/10; uniform single
    // separators; 4-digit hours; `"--"` for absent icount).
    // ================================================================

    fn snap(
        id: &str,
        name: &str,
        date_sec_hi: u32,
        date_sec_lo: u32,
        date_nsec: u32,
        vm_clock_nsec: u64,
        vm_state_size: u64,
        icount: u64,
    ) -> guest_::SnapshotEntryMessage {
        let msg = guest_protocol::snapshot_entry_message(
            id,
            name,
            0, // l1_table_offset
            0, // l1_size
            date_sec_hi,
            date_sec_lo,
            date_nsec,
            vm_clock_nsec,
            vm_state_size,
            0, // disk_size
            icount,
            0, // extra_data_size
        );
        match msg.payload {
            Some(guest_::GuestMessage_::Payload::SnapshotEntry(e)) => e,
            _ => panic!("snapshot_entry_message must wrap a SnapshotEntry payload"),
        }
    }

    fn render_snapshot_human(entries: &[guest_::SnapshotEntryMessage]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut r = SnapshotRenderer::new(&mut buf, "human");
            r.begin().unwrap();
            for e in entries {
                r.emit_snapshot(e).unwrap();
            }
            r.finish().unwrap();
        }
        buf
    }

    fn render_snapshot_json(entries: &[guest_::SnapshotEntryMessage]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut r = SnapshotRenderer::new(&mut buf, "json");
            r.begin().unwrap();
            for e in entries {
                r.emit_snapshot(e).unwrap();
            }
            r.finish().unwrap();
        }
        buf
    }

    #[test]
    fn snapshot_human_empty_list_emits_no_output() {
        // qemu-img produces zero output when nb_snapshots == 0
        // (it returns before the `Snapshot list:` prefix). instar
        // matches.
        let out = render_snapshot_human(&[]);
        assert!(out.is_empty(), "expected empty output, got {:?}", out);
    }

    #[test]
    fn snapshot_json_empty_list_emits_brackets() {
        // Empty JSON list: opening `[`, no entries, then `]\n`.
        let out = render_snapshot_json(&[]);
        assert_eq!(out, b"[]\n");
    }

    #[test]
    fn snapshot_human_single_snapshot_byte_exact() {
        // Reference fixture captured from `TZ=UTC qemu-img snapshot
        // -l` against a freshly-created qcow2 with one snapshot
        // (see PLAN-snapshot-phase-04-list-host.md smoke test):
        // qemu-img 10.0.8 columns: 7/16/8/19/15/10 with single
        // space separators, VM_SIZE/VM_CLOCK underscores, 4-digit
        // hours, `--` for absent icount.
        //
        // date_sec=0 renders the epoch in local time (19 bytes
        // under any TZ), so the row shape is deterministic even
        // though the DATE text is TZ-dependent; this test asserts
        // only the TZ-independent parts of the row. The
        // date_sec_zero test below pins the DATE column itself
        // under TZ=UTC.
        let e = snap("1", "snap1", 0, 0, 0, 0, 0, 0);
        let out = render_snapshot_human(&[e]);
        let text = String::from_utf8(out).unwrap();
        // Prefix and header are present.
        assert!(text.starts_with("Snapshot list:\n"), "got: {:?}", text);
        assert!(
            text.contains(
                "ID      TAG               VM_SIZE                DATE        VM_CLOCK     ICOUNT"
            ),
            "header column titles do not match qemu-img v10 layout: {:?}",
            text
        );
        // Data row uses uniform separators and renders `0` (not `--`) for
        // present icount.
        assert!(
            text.contains("1       snap1                 0 B"),
            "row: {:?}",
            text
        );
        assert!(text.contains("0000:00:00.000"), "clock: {:?}", text);
        assert!(text.ends_with("          0\n"), "icount tail: {:?}", text);
    }

    #[test]
    fn snapshot_human_two_snapshots_byte_exact() {
        // Two entries, deterministic vm_state_size and clock to
        // pin the per-row format.
        let e1 = snap("1", "first", 0, 0, 0, 0, 0, 0);
        let e2 = snap("2", "second", 0, 0, 0, 0, 0, 0);
        let out = render_snapshot_human(&[e1, e2]);
        let text = String::from_utf8(out).unwrap();
        // Prefix + header + 2 data rows = 4 lines.
        assert_eq!(text.matches('\n').count(), 4, "got: {:?}", text);
        assert!(text.contains("1       first"), "row 1: {:?}", text);
        assert!(text.contains("2       second"), "row 2: {:?}", text);
    }

    #[test]
    fn snapshot_json_two_snapshots_comma_separated() {
        let e1 = snap("1", "first", 0, 0, 0, 0, 0, 0);
        let e2 = snap("2", "second", 0, 0, 0, 0, 0, 0);
        let out = render_snapshot_json(&[e1, e2]);
        let text = String::from_utf8(out).unwrap();
        // Opening `[`, newline before first object, comma+newline
        // separator, newline before `]\n`.
        assert!(text.starts_with("[\n{"), "head: {:?}", text);
        assert!(text.contains("},\n{"), "separator: {:?}", text);
        assert!(text.ends_with("\n]\n"), "tail: {:?}", text);
        // Both ids present.
        assert!(text.contains("\"id\": \"1\""));
        assert!(text.contains("\"id\": \"2\""));
    }

    #[test]
    fn snapshot_human_date_sec_zero_renders_epoch() {
        // PLAN-snapshot phase 14 decision (open question 2):
        // qemu feeds a zero `date_sec` through `localtime` and
        // renders the Unix epoch in local time; instar matches.
        // Pin TZ=UTC (the integration tests' convention for the
        // local-time DATE column) so the rendered string is
        // deterministic, and call tzset() so libc re-reads the
        // variable. (The libc crate does not expose tzset on
        // unix targets, so declare it directly.)
        extern "C" {
            fn tzset();
        }
        std::env::set_var("TZ", "UTC");
        // SAFETY: tzset() takes no arguments, touches only libc's
        // process-global timezone state, and is called here after
        // TZ is pinned so the subsequent localtime_r reads the
        // test's timezone rather than the host's.
        unsafe { tzset() };
        let e = snap("1", "x", 0, 0, 0, 0, 0, 0);
        let out = render_snapshot_human(&[e]);
        let text = String::from_utf8(out).unwrap();
        // Locate the data row (line 2, 0-indexed).
        let row = text.lines().nth(2).expect("expected data row");
        assert_eq!(row.len(), 80, "row width: {:?}", row);
        // Check DATE column slot (cols 35..54, 1-indexed -> bytes
        // 34..53): the epoch, rendered like any other timestamp.
        let date_slot = &row[34..53];
        assert_eq!(
            date_slot, "1970-01-01 00:00:00",
            "date_sec == 0 must render the epoch like qemu: {:?}",
            date_slot
        );
    }

    #[test]
    fn snapshot_human_icount_absent_emits_double_dash() {
        // qemu-img 10.0.8 renders absent icount as the literal
        // string "--", not as a blank cell.
        let e = snap("1", "x", 0, 0, 0, 0, 0, u64::MAX);
        let out = render_snapshot_human(&[e]);
        let text = String::from_utf8(out).unwrap();
        // The ICOUNT slot is the last 10 columns of the data row.
        // With "--" right-aligned in width 10, the row ends with
        // 8 spaces then "--" then newline.
        assert!(text.ends_with("        --\n"), "tail: {:?}", text);
    }

    #[test]
    fn snapshot_json_icount_absent_emits_null() {
        let e = snap("1", "x", 0, 0, 0, 0, 0, u64::MAX);
        let out = render_snapshot_json(&[e]);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("\"icount\": null"),
            "JSON icount should be null: {:?}",
            text
        );
    }

    #[test]
    fn snapshot_human_long_id_shifts_later_columns_right() {
        // qemu-img's `%-7s` / `{:<7}` semantics treat the width as
        // a minimum: a long ID expands the column and shifts the
        // rest of the row right. The output remains parseable
        // (and matches qemu's behaviour for hand-crafted images
        // with long IDs).
        let e = snap("very-long-id", "name", 0, 0, 0, 0, 0, 0);
        let out = render_snapshot_human(&[e]);
        let text = String::from_utf8(out).unwrap();
        let row = text.lines().nth(2).expect("expected data row");
        // The ID is longer than 7, so the row is longer than 80.
        assert!(row.len() > 80, "row should expand: len={}", row.len());
        assert!(row.starts_with("very-long-id "), "id at head: {:?}", row);
    }

    #[test]
    fn snapshot_human_multibyte_name_pads_by_bytes() {
        // qemu's C printf("%-16s") pads the TAG column to a minimum
        // field width measured in BYTES; Rust's `{:<16}` counts
        // chars, which over-pads multibyte UTF-8 names (7 chars vs
        // 12 bytes here). Found by the phase 13 differential
        // fuzzer's first smoke run: `snäp-名前` drew 9 pad spaces
        // from instar but 4 from qemu-img.
        let e = snap("1", "snäp-名前", 0, 0, 0, 0, 0, 0);
        let out = render_snapshot_human(&[e]);
        let text = String::from_utf8(out).unwrap();
        let row = text.lines().nth(2).expect("expected data row");
        // 1-byte ID + 6 pad + separator; 12-byte name + 4 pad +
        // separator; "0 B" right-aligned in 8.
        let expected_prefix = format!("1{}snäp-名前{}0 B", " ".repeat(7), " ".repeat(10));
        assert!(
            row.starts_with(&expected_prefix),
            "byte-padded row: {:?}",
            row
        );
    }

    #[test]
    fn snapshot_human_vm_size_spot_checks() {
        // Spot-check the qemu-compat VM_SIZE rendering for a few
        // representative values. format_snapshot_vm_size returns
        // "0 B" for zero (matching qemu-img snapshot's
        // size_to_str output) and delegates to format_size_human
        // for the nonzero cases.
        assert_eq!(format_snapshot_vm_size(0), "0 B");
        assert_eq!(format_snapshot_vm_size(1024), "1 KiB");
        assert_eq!(format_snapshot_vm_size(64 * 1024), "64 KiB");
    }

    #[test]
    fn snapshot_human_clock_format_four_digit_hours() {
        // qemu-img 10.0.8 emits 4-digit hours. Verify the helper
        // produces the documented format directly.
        assert_eq!(format_qemu_snapshot_clock(0), "0000:00:00.000");
        // 1 hour 2 minutes 3 seconds 456 milliseconds:
        let nsec: u64 = (3600 + 2 * 60 + 3) * 1_000_000_000 + 456 * 1_000_000;
        assert_eq!(format_qemu_snapshot_clock(nsec), "0001:02:03.456");
        // Overflow past 9999 hours still formats with at least
        // 4-digit hours.
        let big_nsec: u64 = 12345u64 * 3_600_000_000_000;
        assert_eq!(format_qemu_snapshot_clock(big_nsec), "12345:00:00.000");
    }

    // --- snapshot_error_message -----------------------------------

    #[test]
    fn snapshot_error_ok_returns_none() {
        for mode in [
            SNAPSHOT_CONFIG_MODE_LIST,
            SNAPSHOT_CONFIG_MODE_APPLY,
            SNAPSHOT_CONFIG_MODE_CREATE,
            SNAPSHOT_CONFIG_MODE_DELETE,
        ] {
            assert!(snapshot_error_message(mode, SNAPSHOT_RESULT_ERROR_OK).is_none());
        }
    }

    #[test]
    fn snapshot_error_codes_have_distinct_messages() {
        let codes = [
            SNAPSHOT_RESULT_ERROR_UNSUPPORTED_FORMAT,
            SNAPSHOT_RESULT_ERROR_UNSUPPORTED_FEATURE,
            SNAPSHOT_RESULT_ERROR_NOT_FOUND,
            SNAPSHOT_RESULT_ERROR_DUPLICATE_NAME,
            SNAPSHOT_RESULT_ERROR_REFCOUNT_OVERFLOW,
            SNAPSHOT_RESULT_ERROR_ALLOCATION_FAILED,
            SNAPSHOT_RESULT_ERROR_SNAPSHOT_TABLE_FULL,
            SNAPSHOT_RESULT_ERROR_IO,
            SNAPSHOT_RESULT_ERROR_L1_SIZE_MISMATCH,
            SNAPSHOT_RESULT_ERROR_INVALID_UTF8,
            SNAPSHOT_RESULT_ERROR_INVALID_CONFIG,
            SNAPSHOT_RESULT_ERROR_PARSE_FAILED,
        ];
        for mode in [SNAPSHOT_CONFIG_MODE_APPLY, SNAPSHOT_CONFIG_MODE_DELETE] {
            let messages: Vec<&'static str> = codes
                .iter()
                .map(|c| snapshot_error_message(mode, *c).expect("known error must have message"))
                .collect();
            for m in &messages {
                assert!(!m.is_empty());
                assert!(m.starts_with("snapshot: "), "missing prefix: {}", m);
            }
            for i in 0..messages.len() {
                for j in (i + 1)..messages.len() {
                    assert_ne!(
                        messages[i], messages[j],
                        "mode {}: error codes {} and {} share a message",
                        mode, codes[i], codes[j]
                    );
                }
            }
        }
    }

    #[test]
    fn snapshot_error_unknown_returns_generic_message() {
        let msg = snapshot_error_message(SNAPSHOT_CONFIG_MODE_LIST, 999)
            .expect("unknown error returns Some");
        assert!(msg.contains("unknown"));
    }

    #[test]
    fn snapshot_not_found_message_is_name_only_for_delete() {
        // Phase 7 (fact 2): qemu 10's delete matches by name only —
        // the old "matches neither a snapshot ID nor a name" wording
        // was wrong and must not come back.
        let msg =
            snapshot_error_message(SNAPSHOT_CONFIG_MODE_DELETE, SNAPSHOT_RESULT_ERROR_NOT_FOUND)
                .expect("not-found has a message");
        assert!(msg.contains("name only"), "msg: {}", msg);
        assert!(!msg.contains("neither"), "msg: {}", msg);
    }

    #[test]
    fn snapshot_not_found_message_is_id_then_name_for_apply() {
        // Phase 8 (fact 2): qemu's apply resolves via
        // find_snapshot_by_id_or_name — ID first, then name.
        let msg =
            snapshot_error_message(SNAPSHOT_CONFIG_MODE_APPLY, SNAPSHOT_RESULT_ERROR_NOT_FOUND)
                .expect("not-found has a message");
        assert!(msg.contains("ID first, then by name"), "msg: {}", msg);
        assert!(!msg.contains("name only"), "msg: {}", msg);
    }

    #[test]
    fn snapshot_l1_mismatch_message_is_mode_aware() {
        // Apply's geometry refusal explains the qemu-truncates /
        // instar-refuses divergence and the resize-back workaround.
        let apply = snapshot_error_message(
            SNAPSHOT_CONFIG_MODE_APPLY,
            SNAPSHOT_RESULT_ERROR_L1_SIZE_MISMATCH,
        )
        .expect("apply mismatch has a message");
        assert!(apply.contains("resized"), "msg: {}", apply);
        assert!(apply.contains("truncates"), "msg: {}", apply);
        assert!(apply.contains("quirks"), "msg: {}", apply);
        let delete = snapshot_error_message(
            SNAPSHOT_CONFIG_MODE_DELETE,
            SNAPSHOT_RESULT_ERROR_L1_SIZE_MISMATCH,
        )
        .expect("delete mismatch has a message");
        assert_ne!(apply, delete);
    }

    // --- D1: force-share refusal for mutating modes ---------------

    /// Helper: build a minimal SnapshotArgs for refusal tests.
    /// The filename is intentionally bogus — the D1 check must fire
    /// before any file access.
    fn snapshot_args_for_d1(
        force_share: bool,
        create: Option<&str>,
        delete: Option<&str>,
        apply: Option<&str>,
        list: bool,
    ) -> SnapshotArgs {
        SnapshotArgs {
            filename: "/dev/null/no_such_image".to_string(),
            list,
            apply: apply.map(str::to_string),
            create: create.map(str::to_string),
            delete: delete.map(str::to_string),
            format: None,
            quiet: false,
            force_share,
            image_opts: false,
            output: "human".to_string(),
            sector_size: 65536,
        }
    }

    #[test]
    fn snapshot_force_share_with_create_is_refused_before_file() {
        // D1: -U -c must be rejected before any file access.
        let args = snapshot_args_for_d1(true, Some("snap1"), None, None, false);
        let err = run_snapshot(args, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("force-share") || msg.contains("-U"),
            "expected force-share refusal, got: {}",
            msg
        );
    }

    #[test]
    fn snapshot_force_share_with_delete_is_refused_before_file() {
        // D1: -U -d must be rejected before any file access.
        let args = snapshot_args_for_d1(true, None, Some("snap1"), None, false);
        let err = run_snapshot(args, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("force-share") || msg.contains("-U"),
            "expected force-share refusal, got: {}",
            msg
        );
    }

    #[test]
    fn snapshot_force_share_with_apply_is_refused_before_file() {
        // D1: -U -a must be rejected before any file access.
        let args = snapshot_args_for_d1(true, None, None, Some("snap1"), false);
        let err = run_snapshot(args, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("force-share") || msg.contains("-U"),
            "expected force-share refusal, got: {}",
            msg
        );
    }

    // --- Host-side name/needle validation (phase 6/7 quirks) ------
    // These fire before any file access, so the bogus D1 filename
    // proves the validation path (not file-not-found) produced the
    // error. Pre-push audit 2b: these previously had only harness
    // coverage (tools/snapshot-create-refusals.sh), which a silent
    // regression of the host-side check would not necessarily fail
    // deterministically in CI's unit lane.

    #[test]
    fn snapshot_create_empty_name_refused_host_side() {
        let args = snapshot_args_for_d1(false, Some(""), None, None, false);
        let err = run_snapshot(args, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("non-empty"),
            "expected empty-name refusal, got: {}",
            msg
        );
    }

    #[test]
    fn snapshot_create_over_255_byte_name_refused_host_side() {
        let long = "n".repeat(256);
        let args = snapshot_args_for_d1(false, Some(&long), None, None, false);
        let err = run_snapshot(args, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("255"),
            "expected over-length refusal, got: {}",
            msg
        );
    }

    #[test]
    fn snapshot_delete_apply_oversized_needle_not_found_host_side() {
        // A needle longer than the 256-byte wire buffer cannot name
        // any matchable snapshot; both modes resolve to the guest's
        // not-found surface without touching the file.
        let long = "n".repeat(257);
        for (delete, apply) in [(Some(long.as_str()), None), (None, Some(long.as_str()))] {
            let args = snapshot_args_for_d1(false, None, delete, apply, false);
            let err = run_snapshot(args, false).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains(&format!("error code {}", SNAPSHOT_RESULT_ERROR_NOT_FOUND)),
                "expected not-found surface, got: {}",
                msg
            );
        }
    }

    #[test]
    fn snapshot_force_share_with_list_proceeds_past_d1_check() {
        // D1: -U -l must NOT be refused at the force-share gate;
        // the error that follows is file-not-found (or similar),
        // NOT a force-share message.
        let args = snapshot_args_for_d1(true, None, None, None, true);
        let err = run_snapshot(args, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("force-share") && !msg.contains("sharing-safe"),
            "D1 gate must not fire for -U -l; got: {}",
            msg
        );
    }

    // --- D2: bare filename (no mode flag) defaults to list --------

    #[test]
    fn snapshot_bare_filename_dispatches_to_list() {
        // D2: no mode flag → list path. The list path fails because
        // the file doesn't exist, but the error must not be a
        // force-share or "required mode" clap error.
        let args = snapshot_args_for_d1(false, None, None, None, false);
        let err = run_snapshot(args, false).unwrap_err();
        let msg = err.to_string();
        // Must NOT be a mode-required clap error:
        assert!(
            !msg.contains("required") && !msg.contains("force-share"),
            "bare filename must reach list path, not mode-required gate; got: {}",
            msg
        );
        // Must be a file-access-level error (the I/O path fires):
        assert!(
            msg.contains("No such file") || msg.contains("not found") || msg.contains("os error"),
            "expected file-not-found after D2 dispatch, got: {}",
            msg
        );
    }

    // --- json_escape ----------------------------------------------

    #[test]
    fn snapshot_json_escape_basic() {
        assert_eq!(json_escape("abc"), "abc");
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("\x07"), "\\u0007");
    }
}
