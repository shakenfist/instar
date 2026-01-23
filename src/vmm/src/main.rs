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
mod io_thread;
mod ioevent;
mod kvm_stats;
mod stats;
mod virtio;

use std::path::Path;
use std::sync::{Arc, Mutex};

use clap::{Args, Parser, Subcommand};
use guest_protocol::{
    decode_framed, encode_vmm_config_framed, guest_, vmm_config, vmm_config_input_only,
    FRAME_HEADER_SIZE,
};
use kvm_bindings::{kvm_regs, kvm_segment, kvm_sregs, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use backing::BackingStore;
use io_thread::{DeviceRole, IoDevice};
use ioevent::IoEvent;
use stats::VmmStats;
use virtio::VirtioBlockDevice;

// Memory layout constants
const GDT_BASE: u64 = 0x1000;
const PAGE_TABLE_BASE: u64 = 0x2000;
const GUEST_CODE_BASE: u64 = 0x10000;
const OPERATION_CONFIG_ADDR: u64 = 0x19000;
const OPERATION_LOAD_ADDR: u64 = 0x20000;

// CopyConfig constants (must match shared crate)
const COPY_CONFIG_MAGIC: u32 = 0x434F5059; // "COPY"
const COPY_CONFIG_FLAG_VERIFY: u32 = 1 << 0;
const COPY_CONFIG_FLAG_SKIP_ZEROS: u32 = 1 << 1;

// InfoConfig constants (must match shared crate)
const INFO_CONFIG_MAGIC: u32 = 0x494E464F; // "INFO"
const INFO_CONFIG_FLAG_DETAILED: u32 = 1 << 0;
const INFO_CONFIG_FLAG_SECURITY_CHECK: u32 = 1 << 1;

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

// Stack: generous allocation for complex operations like qemu-img info
// Place at 16MB with 4MB size to handle deep call stacks
const STACK_BASE: u64 = 0x1000000; // 16MB
const STACK_SIZE: u64 = 0x400000; // 4MB
const STACK_TOP: u64 = STACK_BASE + STACK_SIZE - 8;

// Virtio MMIO regions (must be OUTSIDE guest memory region for KVM to trap)
const INPUT_MMIO_BASE: u64 = 0x10000000; // 256MB, outside 32MB guest memory
const OUTPUT_MMIO_BASE: u64 = 0x10001000; // 256MB + 4KB
const MMIO_SIZE: u64 = 0x1000;

// Virtqueue memory regions (inside guest memory)
const INPUT_VQ_BASE: u64 = 0x100000;
const OUTPUT_VQ_BASE: u64 = 0x110000;

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

/// Serial decoder for framed protobuf messages
struct SerialDecoder {
    buffer: Vec<u8>,
}

impl SerialDecoder {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Add a byte and try to decode a message
    fn add_byte(&mut self, byte: u8) -> Option<guest_::GuestMessage> {
        self.buffer.push(byte);

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

        // Try to decode
        if let Some((msg, consumed)) = decode_framed(&self.buffer) {
            self.buffer.drain(..consumed);
            return Some(msg);
        }

        // Decode failed - discard first byte and try again later
        if !self.buffer.is_empty() {
            self.buffer.remove(0);
        }
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
        None => "empty payload".to_string(),
    };

    format!("[{}] {}", level, payload_str)
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

#[derive(Parser, Debug)]
#[command(name = "imago")]
#[command(about = "Safe, sandboxed disk image operations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Detect image format and display information
    Info(InfoArgs),
    /// Copy/convert disk images
    Copy(CopyArgs),
}

#[derive(Args, Debug)]
struct InfoArgs {
    /// Input image file
    input: String,

    /// Sector size for reading input (default: 65536)
    #[arg(long, default_value = "65536")]
    sector_size: u32,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Info(args) => run_info(args),
        Commands::Copy(args) => run_copy(args),
    }
}

/// Run the info operation (format detection)
fn run_info(args: InfoArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Validate sector size (must be power of 2, 512 to 64KB)
    if !(512..=MAX_SECTOR_SIZE).contains(&args.sector_size) || !args.sector_size.is_power_of_two() {
        eprintln!(
            "Error: sector size must be a power of 2, 512 to {} (got {})",
            MAX_SECTOR_SIZE, args.sector_size
        );
        std::process::exit(1);
    }

    // Auto-discover binaries in same directory as executable
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("info.bin");

    // Load core binary (device init, call table setup)
    let core_code = load_guest_binary(core_path.to_str().unwrap())?;
    println!(
        "Loaded core binary: {} bytes from {}",
        core_code.len(),
        core_path.display()
    );

    // Load operation binary (info)
    let operation_code = load_guest_binary(operation_path.to_str().unwrap())?;
    println!(
        "Loaded operation binary: {} bytes from {}",
        operation_code.len(),
        operation_path.display()
    );

    // Get input file size
    let input_size = std::fs::metadata(&args.input)?.len();
    println!(
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
    println!("KVM API version: {}", kvm.get_api_version());

    // Check KVM binary statistics capability
    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    // Create VM
    let vm = kvm.create_vm()?;
    println!("Created VM");

    // Create guest memory
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    println!("Allocated {} bytes of guest memory", GUEST_MEM_SIZE);

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
    println!("Configured memory region");

    // Set up GDT
    setup_gdt(&guest_mem)?;
    println!("Set up GDT at 0x{:x}", GDT_BASE);

    // Set up page tables (identity map)
    setup_page_tables(&guest_mem)?;
    println!("Set up page tables at 0x{:x}", PAGE_TABLE_BASE);

    // Load core binary at GUEST_CODE_BASE (0x10000)
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    println!("Loaded core binary at 0x{:x}", GUEST_CODE_BASE);

    // Load operation binary at OPERATION_LOAD_ADDR (0x20000)
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    println!("Loaded operation binary at 0x{:x}", OPERATION_LOAD_ADDR);

    // Write InfoConfig at OPERATION_CONFIG_ADDR (0x19000)
    // Layout: magic (u32), flags (u32)
    let info_flags: u32 = INFO_CONFIG_FLAG_DETAILED | INFO_CONFIG_FLAG_SECURITY_CHECK;
    guest_mem.write_obj(INFO_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(info_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    println!(
        "Wrote info config at 0x{:x} (flags=0x{:x})",
        OPERATION_CONFIG_ADDR, info_flags
    );

    // Create virtio-block device (input only for info operation)
    let input_device = VirtioBlockDevice::new(
        input_backing,
        input_size,
        args.sector_size as u64,
        true, // read-only
        INPUT_MMIO_BASE,
        INPUT_VQ_BASE,
    );
    println!(
        "Created virtio-block device at MMIO 0x{:x}",
        INPUT_MMIO_BASE
    );
    println!("  Sector size: {} bytes", input_device.sector_size());

    // Wrap device in Arc<Mutex<>> for potential sharing with I/O thread
    let input_device = Arc::new(Mutex::new(input_device));

    // Wrap guest memory in Arc for sharing
    let guest_mem = Arc::new(guest_mem);

    // Create shared statistics tracker
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Set up ioeventfd for queue notifications
    // Info operation uses only one input device
    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut input_evt = IoEvent::new(INPUT_MMIO_BASE)?;

    match input_evt.register(&vm) {
        Ok(()) => {
            println!("ioeventfd: enabled for queue notifications (with I/O thread)");

            // Configure devices for I/O thread (info: 1 input device only)
            let devices = vec![IoDevice {
                role: DeviceRole::Input,
                device: Arc::clone(&input_device),
                ioevent: input_evt,
            }];

            // Start the I/O thread
            io_thread = Some(io_thread::IoThread::new(
                devices,
                Arc::clone(&guest_mem),
                Arc::clone(&vmm_stats),
            ));
        }
        Err(e) => {
            println!(
                "ioeventfd: failed to register ({:?}), falling back to VM exits",
                e
            );
        }
    }

    // Create vCPU
    let mut vcpu = vm.create_vcpu(0)?;
    println!("Created vCPU");

    // Set up registers
    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    println!("Configured special registers for long mode");

    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;
    println!(
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
    println!(
        "Queued configuration message ({} bytes) for guest",
        serial_transmitter.buffer.len()
    );

    // Run the vCPU loop
    println!("\n--- Starting guest execution ---\n");

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                println!("\n--- Guest executed HLT ---");
                println!("Info operation completed successfully!");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            println!("{}", format_message(&msg));
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            println!("[DEBUG] {}", line);
                        }
                    }
                } else {
                    println!("IO OUT: port=0x{:x}, data={:?}", port, data);
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
                let input_range = INPUT_MMIO_BASE..INPUT_MMIO_BASE + MMIO_SIZE;
                let value = if input_range.contains(&addr) {
                    input_device
                        .lock()
                        .unwrap()
                        .mmio_read((addr - INPUT_MMIO_BASE) as u32)
                } else {
                    println!("Unknown MMIO read at 0x{:x}", addr);
                    0
                };
                write_mmio_data(data, value);
            }
            VcpuExit::MmioWrite(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_write();
                let value = read_mmio_data(data);
                let input_range = INPUT_MMIO_BASE..INPUT_MMIO_BASE + MMIO_SIZE;
                if input_range.contains(&addr) {
                    let mut device = input_device.lock().unwrap();
                    device.mmio_write((addr - INPUT_MMIO_BASE) as u32, value);
                    if io_thread.is_none() && device.should_process_queue() {
                        let io_stats = device.process_queue(&guest_mem)?;
                        vmm_stats
                            .lock()
                            .unwrap()
                            .record_read(io_stats.bytes_read, io_stats.sectors_read);
                    }
                } else {
                    println!("Unknown MMIO write at 0x{:x}", addr);
                }
            }
            VcpuExit::Shutdown => {
                vmm_stats.lock().unwrap().record_shutdown();
                println!("\n--- VM Shutdown (triple fault?) ---");
                let regs = vcpu.get_regs()?;
                let sregs = vcpu.get_sregs()?;
                println!(
                    "RIP=0x{:x}, RSP=0x{:x}, RBP=0x{:x}",
                    regs.rip, regs.rsp, regs.rbp
                );
                println!(
                    "CR0=0x{:x}, CR3=0x{:x}, CR4=0x{:x}",
                    sregs.cr0, sregs.cr3, sregs.cr4
                );
                if regs.rsp < STACK_BASE || regs.rsp > STACK_TOP {
                    println!();
                    println!("*** LIKELY STACK OVERFLOW ***");
                    println!("  RSP (0x{:x}) is outside stack region", regs.rsp);
                    println!(
                        "  Stack region: 0x{:x} - 0x{:x} ({} bytes)",
                        STACK_BASE, STACK_TOP, STACK_SIZE
                    );
                }
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                println!("VM Entry Failed! reason=0x{:x}, cpu={}", reason, cpu);
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                println!("Unexpected VM exit: {:?}", exit);
                break;
            }
        }
    }

    if let Some(mut thread) = io_thread {
        thread.stop();
    }

    vmm_stats.lock().unwrap().display();

    Ok(())
}

/// Run the copy operation
fn run_copy(args: CopyArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Validate sector sizes (must be powers of 2, 512 to 64KB)
    for (name, size) in [
        ("input", args.input_sector_size),
        ("output", args.output_sector_size),
    ] {
        if !(512..=MAX_SECTOR_SIZE).contains(&size) || !size.is_power_of_two() {
            eprintln!(
                "Error: {} sector size must be a power of 2, 512 to {} (got {})",
                name, MAX_SECTOR_SIZE, size
            );
            std::process::exit(1);
        }
    }

    // Determine if output should be sparse (default) or pre-allocated
    let sparse_output = !args.preallocate_output;

    // Auto-discover binaries in same directory as executable
    let core_path = get_binary_path("core.bin");
    let operation_path = get_binary_path("copy.bin");

    // Load core binary (device init, call table setup)
    let core_code = load_guest_binary(core_path.to_str().unwrap())?;
    println!(
        "Loaded core binary: {} bytes from {}",
        core_code.len(),
        core_path.display()
    );

    // Load operation binary (copy)
    let operation_code = load_guest_binary(operation_path.to_str().unwrap())?;
    println!(
        "Loaded operation binary: {} bytes from {}",
        operation_code.len(),
        operation_path.display()
    );

    // Get input file size
    let input_size = std::fs::metadata(&args.input)?.len();
    println!(
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
    println!(
        "Output file: {} (capacity {} bytes, {} sectors @ {} bytes/sector, {})",
        args.output,
        output_capacity,
        output_capacity / args.output_sector_size as u64,
        args.output_sector_size,
        output_mode_desc
    );

    // Open KVM
    let kvm = Kvm::new()?;
    println!("KVM API version: {}", kvm.get_api_version());

    let kvm_stats_checker = kvm_stats::KvmStatsChecker::new(&kvm);
    kvm_stats_checker.display_status();

    let vm = kvm.create_vm()?;
    println!("Created VM");

    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    println!("Allocated {} bytes of guest memory", GUEST_MEM_SIZE);

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
    println!("Configured memory region");

    setup_gdt(&guest_mem)?;
    println!("Set up GDT at 0x{:x}", GDT_BASE);

    setup_page_tables(&guest_mem)?;
    println!("Set up page tables at 0x{:x}", PAGE_TABLE_BASE);

    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    println!("Loaded core binary at 0x{:x}", GUEST_CODE_BASE);

    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    println!("Loaded operation binary at 0x{:x}", OPERATION_LOAD_ADDR);

    // Write CopyConfig at OPERATION_CONFIG_ADDR
    let mut copy_flags: u32 = 0;
    if args.verify {
        copy_flags |= COPY_CONFIG_FLAG_VERIFY;
    }
    if args.skip_zeros {
        copy_flags |= COPY_CONFIG_FLAG_SKIP_ZEROS;
    }

    guest_mem.write_obj(COPY_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(copy_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(args.start_sector, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(args.sector_count, GuestAddress(OPERATION_CONFIG_ADDR + 16))?;
    println!(
        "Wrote copy config at 0x{:x} (flags=0x{:x}, start={}, count={})",
        OPERATION_CONFIG_ADDR, copy_flags, args.start_sector, args.sector_count
    );

    // Create virtio-block devices
    let input_device = VirtioBlockDevice::new(
        input_backing,
        input_size,
        args.input_sector_size as u64,
        true,
        INPUT_MMIO_BASE,
        INPUT_VQ_BASE,
    );
    let output_device = VirtioBlockDevice::new(
        output_backing,
        output_capacity,
        args.output_sector_size as u64,
        false,
        OUTPUT_MMIO_BASE,
        OUTPUT_VQ_BASE,
    );
    println!(
        "Created virtio-block devices at MMIO 0x{:x} and 0x{:x}",
        INPUT_MMIO_BASE, OUTPUT_MMIO_BASE
    );
    println!(
        "  Input sector size: {} bytes, Output sector size: {} bytes",
        input_device.sector_size(),
        output_device.sector_size()
    );

    let input_device = Arc::new(Mutex::new(input_device));
    let output_device = Arc::new(Mutex::new(output_device));
    let guest_mem = Arc::new(guest_mem);
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Set up ioeventfd for queue notifications
    // Copy operation uses 1 input device + 1 output device
    let mut io_thread: Option<io_thread::IoThread> = None;
    let mut input_evt = IoEvent::new(INPUT_MMIO_BASE)?;
    let mut output_evt = IoEvent::new(OUTPUT_MMIO_BASE)?;

    match (input_evt.register(&vm), output_evt.register(&vm)) {
        (Ok(()), Ok(())) => {
            println!("ioeventfd: enabled for queue notifications (with I/O thread)");

            // Configure devices for I/O thread (copy: 1 input + 1 output)
            let devices = vec![
                IoDevice {
                    role: DeviceRole::Input,
                    device: Arc::clone(&input_device),
                    ioevent: input_evt,
                },
                IoDevice {
                    role: DeviceRole::Output,
                    device: Arc::clone(&output_device),
                    ioevent: output_evt,
                },
            ];

            // Start the I/O thread
            io_thread = Some(io_thread::IoThread::new(
                devices,
                Arc::clone(&guest_mem),
                Arc::clone(&vmm_stats),
            ));
        }
        (Err(e), _) | (_, Err(e)) => {
            println!(
                "ioeventfd: failed to register ({:?}), falling back to VM exits",
                e
            );
        }
    }

    let mut vcpu = vm.create_vcpu(0)?;
    println!("Created vCPU");

    let mut sregs = vcpu.get_sregs()?;
    setup_sregs(&mut sregs);
    vcpu.set_sregs(&sregs)?;
    println!("Configured special registers for long mode");

    let mut regs = vcpu.get_regs()?;
    setup_regs(&mut regs);
    vcpu.set_regs(&regs)?;
    println!(
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
    println!(
        "Queued configuration message ({} bytes) for guest, progress: {}",
        serial_transmitter.buffer.len(),
        progress_desc
    );

    println!("\n--- Starting guest execution ---\n");

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                println!("\n--- Guest executed HLT ---");
                println!("Copy operation completed successfully!");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                vmm_stats.lock().unwrap().record_io_out();
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            println!("{}", format_message(&msg));
                        }
                    }
                } else if port == DEBUG_PORT {
                    for &byte in data {
                        if let Some(line) = debug_buffer.add_byte(byte) {
                            println!("[DEBUG] {}", line);
                        }
                    }
                } else {
                    println!("IO OUT: port=0x{:x}, data={:?}", port, data);
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
                let input_range = INPUT_MMIO_BASE..INPUT_MMIO_BASE + MMIO_SIZE;
                let output_range = OUTPUT_MMIO_BASE..OUTPUT_MMIO_BASE + MMIO_SIZE;
                let value = if input_range.contains(&addr) {
                    input_device
                        .lock()
                        .unwrap()
                        .mmio_read((addr - INPUT_MMIO_BASE) as u32)
                } else if output_range.contains(&addr) {
                    output_device
                        .lock()
                        .unwrap()
                        .mmio_read((addr - OUTPUT_MMIO_BASE) as u32)
                } else {
                    println!("Unknown MMIO read at 0x{:x}", addr);
                    0
                };
                write_mmio_data(data, value);
            }
            VcpuExit::MmioWrite(addr, data) => {
                vmm_stats.lock().unwrap().record_mmio_write();
                let value = read_mmio_data(data);
                let input_range = INPUT_MMIO_BASE..INPUT_MMIO_BASE + MMIO_SIZE;
                let output_range = OUTPUT_MMIO_BASE..OUTPUT_MMIO_BASE + MMIO_SIZE;
                if input_range.contains(&addr) {
                    let mut device = input_device.lock().unwrap();
                    device.mmio_write((addr - INPUT_MMIO_BASE) as u32, value);
                    if io_thread.is_none() && device.should_process_queue() {
                        let io_stats = device.process_queue(&guest_mem)?;
                        vmm_stats
                            .lock()
                            .unwrap()
                            .record_read(io_stats.bytes_read, io_stats.sectors_read);
                    }
                } else if output_range.contains(&addr) {
                    let mut device = output_device.lock().unwrap();
                    device.mmio_write((addr - OUTPUT_MMIO_BASE) as u32, value);
                    if io_thread.is_none() && device.should_process_queue() {
                        let io_stats = device.process_queue(&guest_mem)?;
                        vmm_stats
                            .lock()
                            .unwrap()
                            .record_write(io_stats.bytes_written, io_stats.sectors_written);
                    }
                } else {
                    println!("Unknown MMIO write at 0x{:x}", addr);
                }
            }
            VcpuExit::Shutdown => {
                vmm_stats.lock().unwrap().record_shutdown();
                println!("\n--- VM Shutdown (triple fault?) ---");
                let regs = vcpu.get_regs()?;
                let sregs = vcpu.get_sregs()?;
                println!(
                    "RIP=0x{:x}, RSP=0x{:x}, RBP=0x{:x}",
                    regs.rip, regs.rsp, regs.rbp
                );
                println!(
                    "CR0=0x{:x}, CR3=0x{:x}, CR4=0x{:x}",
                    sregs.cr0, sregs.cr3, sregs.cr4
                );
                if regs.rsp < STACK_BASE || regs.rsp > STACK_TOP {
                    println!();
                    println!("*** LIKELY STACK OVERFLOW ***");
                    println!("  RSP (0x{:x}) is outside stack region", regs.rsp);
                    println!(
                        "  Stack region: 0x{:x} - 0x{:x} ({} bytes)",
                        STACK_BASE, STACK_TOP, STACK_SIZE
                    );
                    if regs.rsp < STACK_BASE {
                        let underflow = STACK_BASE - regs.rsp;
                        println!("  Stack underflowed by {} bytes", underflow);
                    }
                } else {
                    let stack_used = STACK_TOP - regs.rsp;
                    let stack_percent = (stack_used * 100) / STACK_SIZE;
                    println!();
                    println!(
                        "Stack usage: {} / {} bytes ({}%)",
                        stack_used, STACK_SIZE, stack_percent
                    );
                    if stack_percent > 90 {
                        println!("*** WARNING: Stack was nearly exhausted ***");
                    }
                }
                println!();
                println!(
                    "Guest memory: {} bytes (0x{:x})",
                    GUEST_MEM_SIZE, GUEST_MEM_SIZE
                );
                println!("Code base: 0x{:x}", GUEST_CODE_BASE);
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                vmm_stats.lock().unwrap().record_fail_entry();
                println!("VM Entry Failed! reason=0x{:x}, cpu={}", reason, cpu);
                break;
            }
            exit => {
                vmm_stats.lock().unwrap().record_unknown();
                println!("Unexpected VM exit: {:?}", exit);
                break;
            }
        }
    }

    if let Some(mut thread) = io_thread {
        thread.stop();
    }

    vmm_stats.lock().unwrap().display();

    Ok(())
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
