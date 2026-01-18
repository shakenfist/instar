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
//! - Two virtio-block devices (input read-only, output writable)
//! - Configurable sector sizes
//! - Sparse output files (grow on demand)
//! - ioeventfd optimization for queue notifications

mod backing;
mod io_thread;
mod ioevent;
mod kvm_stats;
mod stats;
mod virtio;

use std::path::Path;
use std::sync::{Arc, Mutex};

use clap::Parser;
use guest_protocol::{
    decode_framed, encode_vmm_config_framed, guest_, vmm_config, FRAME_HEADER_SIZE,
};
use kvm_bindings::{kvm_regs, kvm_segment, kvm_sregs, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use backing::BackingStore;
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
        None => "empty payload".to_string(),
    };

    format!("[{}] {}", level, payload_str)
}

#[derive(Parser, Debug)]
#[command(name = "vmm")]
#[command(about = "Virtio-block VMM with sparse output support")]
struct Args {
    /// Input file (source for copy)
    #[arg(short, long)]
    input: String,

    /// Output file (destination for copy)
    #[arg(short, long)]
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

    /// Disable ioeventfd optimization
    #[arg(long)]
    no_ioeventfd: bool,

    /// Core guest binary (device init, call table)
    #[arg(long)]
    core: String,

    /// Operation binary to load (e.g., copy.bin)
    #[arg(long)]
    operation: String,

    // Copy operation flags
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
    let args = Args::parse();

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

    // Load core binary (device init, call table setup)
    let core_code = load_guest_binary(&args.core)?;
    println!(
        "Loaded core binary: {} bytes from {}",
        core_code.len(),
        args.core
    );

    // Load operation binary (copy, info, etc.)
    let operation_code = load_guest_binary(&args.operation)?;
    println!(
        "Loaded operation binary: {} bytes from {}",
        operation_code.len(),
        args.operation
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
    // Input: read-only, not sparse
    let input_backing = BackingStore::open(Path::new(&args.input), true, None, false)?;

    // Output: writable, sparse by default (grows on demand)
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

    // Set up page tables (identity map 8MB)
    setup_page_tables(&guest_mem)?;
    println!("Set up page tables at 0x{:x}", PAGE_TABLE_BASE);

    // Load core binary at GUEST_CODE_BASE (0x10000)
    guest_mem.write_slice(&core_code, GuestAddress(GUEST_CODE_BASE))?;
    println!("Loaded core binary at 0x{:x}", GUEST_CODE_BASE);

    // Load operation binary at OPERATION_LOAD_ADDR (0x20000)
    guest_mem.write_slice(&operation_code, GuestAddress(OPERATION_LOAD_ADDR))?;
    println!(
        "Loaded operation binary at 0x{:x}",
        OPERATION_LOAD_ADDR
    );

    // Write operation config at OPERATION_CONFIG_ADDR (0x19000)
    // Build flags from CLI arguments
    let mut copy_flags: u32 = 0;
    if args.verify {
        copy_flags |= COPY_CONFIG_FLAG_VERIFY;
    }
    if args.skip_zeros {
        copy_flags |= COPY_CONFIG_FLAG_SKIP_ZEROS;
    }

    // Write CopyConfig struct (must match shared::CopyConfig layout)
    // Layout: magic (u32), flags (u32), start_sector (u64), sector_count (u64)
    guest_mem.write_obj(COPY_CONFIG_MAGIC, GuestAddress(OPERATION_CONFIG_ADDR))?;
    guest_mem.write_obj(copy_flags, GuestAddress(OPERATION_CONFIG_ADDR + 4))?;
    guest_mem.write_obj(args.start_sector, GuestAddress(OPERATION_CONFIG_ADDR + 8))?;
    guest_mem.write_obj(args.sector_count, GuestAddress(OPERATION_CONFIG_ADDR + 16))?;
    println!(
        "Wrote operation config at 0x{:x} (flags=0x{:x}, start={}, count={})",
        OPERATION_CONFIG_ADDR, copy_flags, args.start_sector, args.sector_count
    );

    // Create virtio-block devices with configurable sector sizes
    let input_device = VirtioBlockDevice::new(
        input_backing,
        input_size,
        args.input_sector_size as u64,
        true, // read-only
        INPUT_MMIO_BASE,
        INPUT_VQ_BASE,
    );
    let output_device = VirtioBlockDevice::new(
        output_backing,
        output_capacity, // Use capacity, not input_size
        args.output_sector_size as u64,
        false, // read-write
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

    // Wrap devices in Arc<Mutex<>> for potential sharing with I/O thread
    let input_device = Arc::new(Mutex::new(input_device));
    let output_device = Arc::new(Mutex::new(output_device));

    // Wrap guest memory in Arc for sharing
    let guest_mem = Arc::new(guest_mem);

    // Create shared statistics tracker (shared with I/O thread if enabled)
    let vmm_stats = Arc::new(Mutex::new(VmmStats::new()));

    // Set up ioeventfd for queue notifications (if enabled)
    let use_ioeventfd = !args.no_ioeventfd;
    let mut io_thread: Option<io_thread::IoThread> = None;

    if use_ioeventfd {
        let mut input_evt = IoEvent::new(INPUT_MMIO_BASE)?;
        let mut output_evt = IoEvent::new(OUTPUT_MMIO_BASE)?;

        match (input_evt.register(&vm), output_evt.register(&vm)) {
            (Ok(()), Ok(())) => {
                println!("ioeventfd: enabled for queue notifications (with I/O thread)");

                // Start the I/O thread with shared stats
                io_thread = Some(io_thread::IoThread::new(
                    Arc::clone(&input_device),
                    Arc::clone(&output_device),
                    input_evt,
                    output_evt,
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
    } else {
        println!("ioeventfd: disabled by user");
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

    // Queue the configuration message for transmission
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

    // Run the vCPU loop
    println!("\n--- Starting guest execution ---\n");

    loop {
        // When using the I/O thread, queue processing happens asynchronously.
        // When not using ioeventfd, we process queues on MMIO writes below.
        match vcpu.run()? {
            VcpuExit::Hlt => {
                vmm_stats.lock().unwrap().record_hlt();
                println!("\n--- Guest executed HLT ---");
                println!("Guest completed successfully!");
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
                    // Debug output from guest (COM2) - buffer until newline
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
                    // Guest is reading from serial - send config bytes
                    for byte in data.iter_mut() {
                        *byte = serial_transmitter.next_byte().unwrap_or(0);
                    }
                } else if port == SERIAL_PORT + 5 {
                    // Line Status Register (LSR) - report data available
                    // Bit 0: Data Ready (DR) - set if data available to read
                    // Bit 5: Empty Transmitter Holding Register (ETHR)
                    // Bit 6: Empty Data Holding Registers (EDHR)
                    let mut lsr = 0x60u8; // Transmitter ready
                    if serial_transmitter.has_data() {
                        lsr |= 0x01; // Data ready
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
                    // Only process queue directly if I/O thread is not handling it
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
                    // Only process queue directly if I/O thread is not handling it
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

                // Check for stack overflow
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
                    // RSP is in range - show stack usage
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

                // Additional diagnostic info
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

    // Stop the I/O thread if running (this will also unregister ioeventfds)
    if let Some(mut thread) = io_thread {
        thread.stop();
    }

    // Display statistics
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
