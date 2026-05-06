//! Minimal KVM VMM with virtio-block device support.
//!
//! This VMM provides two virtio-block devices to the guest:
//! - Input device (read-only): backed by source file
//! - Output device (write): backed by destination file
//!
//! The guest reads from input and writes to output, implementing a simple
//! file copy operation. Progress and status are reported via structured
//! protobuf messages over the serial port.

mod virtio;

use clap::Parser;
use guest_protocol::{decode_framed, guest_, FRAME_HEADER_SIZE};
use kvm_bindings::{kvm_regs, kvm_segment, kvm_sregs, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit};
use std::fs::{File, OpenOptions};
use std::io::Read;
use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use virtio::VirtioBlockDevice;

// Memory layout constants
const GDT_BASE: u64 = 0x1000;
const PAGE_TABLE_BASE: u64 = 0x2000;
const GUEST_CODE_BASE: u64 = 0x10000;
const STACK_BASE: u64 = 0x20000;
const STACK_SIZE: u64 = 0x10000;
const STACK_TOP: u64 = STACK_BASE + STACK_SIZE - 8;

// Virtio MMIO regions (must be OUTSIDE guest memory region for KVM to trap)
const INPUT_MMIO_BASE: u64 = 0x10000000; // 256MB, outside 8MB guest memory
const OUTPUT_MMIO_BASE: u64 = 0x10001000; // 256MB + 4KB
const MMIO_SIZE: u64 = 0x1000;

// Virtqueue memory regions (inside guest memory)
const INPUT_VQ_BASE: u64 = 0x100000;
const OUTPUT_VQ_BASE: u64 = 0x110000;

// DMA buffer pool (inside guest memory, used by guest not VMM)
#[allow(dead_code)]
const DMA_POOL_BASE: u64 = 0x200000;

// Total guest memory: 8MB
const GUEST_MEM_SIZE: u64 = 0x800000;

// Serial port
const SERIAL_PORT: u16 = 0x3f8;

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
            format!(
                "info_result format={} version={} virtual_size={} actual_size={} cluster_size={} flags=0x{:x}",
                info.format, info.version, info.virtual_size, info.actual_size, info.cluster_size, info.flags
            )
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

    format!("[{level}] {payload_str}")
}

#[derive(Parser, Debug)]
#[command(name = "vmm")]
#[command(about = "Virtio-block VMM that copies files via a guest")]
struct Args {
    /// Input file (source for copy)
    #[arg(short, long)]
    input: String,

    /// Output file (destination for copy)
    #[arg(short, long)]
    output: String,

    /// Guest binary to run
    guest: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Load guest binary
    let guest_code = load_guest_binary(&args.guest)?;
    println!(
        "Loaded guest binary: {} bytes from {}",
        guest_code.len(),
        args.guest
    );

    // Open input file (read-only)
    let input_file = File::open(&args.input)?;
    let input_size = input_file.metadata()?.len();
    println!(
        "Input file: {} ({} bytes, {} sectors)",
        args.input,
        input_size,
        input_size / 512
    );

    // Open/create output file (read-write)
    let output_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.output)?;
    // Pre-allocate output file to match input size
    output_file.set_len(input_size)?;
    println!(
        "Output file: {} (pre-allocated {} bytes)",
        args.output, input_size
    );

    // Open KVM
    let kvm = Kvm::new()?;
    println!("KVM API version: {}", kvm.get_api_version());

    // Create VM
    let vm = kvm.create_vm()?;
    println!("Created VM");

    // Create guest memory
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    println!("Allocated {GUEST_MEM_SIZE} bytes of guest memory");

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
    println!("Set up GDT at 0x{GDT_BASE:x}");

    // Set up page tables (identity map 8MB)
    setup_page_tables(&guest_mem)?;
    println!("Set up page tables at 0x{PAGE_TABLE_BASE:x}");

    // Load guest code
    guest_mem.write_slice(&guest_code, GuestAddress(GUEST_CODE_BASE))?;
    println!("Loaded guest code at 0x{GUEST_CODE_BASE:x}");

    // Create virtio-block devices
    let mut input_device = VirtioBlockDevice::new(
        input_file,
        input_size,
        true, // read-only
        INPUT_MMIO_BASE,
        INPUT_VQ_BASE,
    );
    let mut output_device = VirtioBlockDevice::new(
        output_file,
        input_size,
        false, // read-write
        OUTPUT_MMIO_BASE,
        OUTPUT_VQ_BASE,
    );
    println!(
        "Created virtio-block devices at MMIO 0x{INPUT_MMIO_BASE:x} and 0x{OUTPUT_MMIO_BASE:x}"
    );

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

    // Create serial decoder for protobuf messages
    let mut serial_decoder = SerialDecoder::new();

    // Run the vCPU loop
    println!("\n--- Starting guest execution ---\n");

    loop {
        match vcpu.run()? {
            VcpuExit::Hlt => {
                println!("\n--- Guest executed HLT ---");
                println!("Guest completed successfully!");
                break;
            }
            VcpuExit::IoOut(port, data) => {
                if port == SERIAL_PORT {
                    for &byte in data {
                        if let Some(msg) = serial_decoder.add_byte(byte) {
                            println!("{}", format_message(&msg));
                        }
                    }
                } else {
                    println!("IO OUT: port=0x{port:x}, data={data:?}");
                }
            }
            VcpuExit::IoIn(port, data) => {
                println!("IO IN: port=0x{:x}, size={}", port, data.len());
                for byte in data {
                    *byte = 0;
                }
            }
            VcpuExit::MmioRead(addr, data) => {
                let input_range = INPUT_MMIO_BASE..INPUT_MMIO_BASE + MMIO_SIZE;
                let output_range = OUTPUT_MMIO_BASE..OUTPUT_MMIO_BASE + MMIO_SIZE;
                let value = if input_range.contains(&addr) {
                    input_device.mmio_read((addr - INPUT_MMIO_BASE) as u32)
                } else if output_range.contains(&addr) {
                    output_device.mmio_read((addr - OUTPUT_MMIO_BASE) as u32)
                } else {
                    println!("Unknown MMIO read at 0x{addr:x}");
                    0
                };
                write_mmio_data(data, value);
            }
            VcpuExit::MmioWrite(addr, data) => {
                let value = read_mmio_data(data);
                let input_range = INPUT_MMIO_BASE..INPUT_MMIO_BASE + MMIO_SIZE;
                let output_range = OUTPUT_MMIO_BASE..OUTPUT_MMIO_BASE + MMIO_SIZE;
                if input_range.contains(&addr) {
                    input_device.mmio_write((addr - INPUT_MMIO_BASE) as u32, value);
                    if input_device.should_process_queue() {
                        input_device.process_queue(&guest_mem)?;
                    }
                } else if output_range.contains(&addr) {
                    output_device.mmio_write((addr - OUTPUT_MMIO_BASE) as u32, value);
                    if output_device.should_process_queue() {
                        output_device.process_queue(&guest_mem)?;
                    }
                } else {
                    println!("Unknown MMIO write at 0x{addr:x}");
                }
            }
            VcpuExit::Shutdown => {
                println!("\n--- VM Shutdown (triple fault?) ---");
                let regs = vcpu.get_regs()?;
                let sregs = vcpu.get_sregs()?;
                println!("RIP=0x{:x}, RSP=0x{:x}", regs.rip, regs.rsp);
                println!(
                    "CR0=0x{:x}, CR3=0x{:x}, CR4=0x{:x}",
                    sregs.cr0, sregs.cr3, sregs.cr4
                );
                break;
            }
            VcpuExit::FailEntry(reason, cpu) => {
                println!("VM Entry Failed! reason=0x{reason:x}, cpu={cpu}");
                break;
            }
            exit => {
                println!("Unexpected VM exit: {exit:?}");
                break;
            }
        }
    }

    Ok(())
}

fn load_guest_binary(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
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
