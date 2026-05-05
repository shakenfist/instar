//! Minimal KVM VMM using rust-vmm crates for simplified guest memory management.
//!
//! This version uses vm-memory crate instead of raw pointer arithmetic,
//! demonstrating the rust-vmm ecosystem benefits.
//!
//! Key improvements over helloworld:
//! - GuestMemoryMmap for safe memory region management
//! - GuestAddress for type-safe address handling
//! - write_obj/write_slice for bounds-checked memory writes
//! - Automatic mmap allocation and cleanup

use kvm_bindings::{kvm_regs, kvm_segment, kvm_sregs, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit};
use std::fs::File;
use std::io::Read;
use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

// Memory layout constants (matching the handoff document)
const GDT_BASE: u64 = 0x1000;
const PAGE_TABLE_BASE: u64 = 0x2000; // PML4 at 0x2000
const GUEST_CODE_BASE: u64 = 0x10000;
const STACK_BASE: u64 = 0x20000;
const STACK_SIZE: u64 = 0x10000; // 64KB stack
const STACK_TOP: u64 = STACK_BASE + STACK_SIZE - 8; // 16-byte aligned

// Total guest memory: 2MB for simplicity
const GUEST_MEM_SIZE: u64 = 0x200000;

// Serial port
const SERIAL_PORT: u16 = 0x3f8;

// GDT segment selectors
const CODE_SELECTOR: u16 = 0x08;
const DATA_SELECTOR: u16 = 0x10;

// Control register bits
const CR0_PE: u64 = 1 << 0; // Protected Mode Enable
const CR0_PG: u64 = 1 << 31; // Paging Enable

const CR4_PAE: u64 = 1 << 5; // Physical Address Extension

const EFER_LME: u64 = 1 << 8; // Long Mode Enable
const EFER_LMA: u64 = 1 << 10; // Long Mode Active

// Page table entry flags
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_PAGE_SIZE: u64 = 1 << 7; // For 2MB pages in PD

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let guest_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "guest.bin".to_string());

    let guest_code = load_guest_binary(&guest_path)?;
    println!(
        "Loaded guest binary: {} bytes from {}",
        guest_code.len(),
        guest_path
    );

    // Open KVM
    let kvm = Kvm::new()?;
    println!("KVM API version: {}", kvm.get_api_version());

    // Create VM
    let vm = kvm.create_vm()?;
    println!("Created VM");

    // Create guest memory using vm-memory crate
    // This handles mmap allocation, page alignment, and cleanup automatically
    let guest_mem = create_guest_memory(GUEST_MEM_SIZE)?;
    println!("Allocated {GUEST_MEM_SIZE} bytes of guest memory via vm-memory");

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

    // Set up GDT using vm-memory's type-safe writes
    setup_gdt(&guest_mem)?;
    println!("Set up GDT at 0x{GDT_BASE:x}");

    // Set up page tables
    setup_page_tables(&guest_mem)?;
    println!("Set up page tables at 0x{PAGE_TABLE_BASE:x}");

    // Load guest code
    guest_mem.write_slice(&guest_code, GuestAddress(GUEST_CODE_BASE))?;
    println!("Loaded guest code at 0x{GUEST_CODE_BASE:x}");

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
                        print!("{}", byte as char);
                    }
                    std::io::Write::flush(&mut std::io::stdout())?;
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

    // guest_mem is automatically cleaned up when dropped
    Ok(())
}

fn load_guest_binary(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut code = Vec::new();
    file.read_to_end(&mut code)?;
    Ok(code)
}

/// Create guest memory using vm-memory's GuestMemoryMmap.
/// This provides automatic mmap allocation, page alignment, and cleanup.
fn create_guest_memory(size: u64) -> Result<GuestMemoryMmap, Box<dyn std::error::Error>> {
    let regions = vec![(GuestAddress(0), size as usize)];
    let guest_mem = GuestMemoryMmap::<()>::from_ranges(&regions)?;
    Ok(guest_mem)
}

/// Set up GDT using vm-memory's write_obj for type-safe memory writes.
///
/// GDT structure (8 bytes per entry):
/// - Entry 0: Null descriptor
/// - Entry 1: 64-bit code segment (selector 0x08)
/// - Entry 2: 64-bit data segment (selector 0x10)
fn setup_gdt(guest_mem: &GuestMemoryMmap) -> Result<(), Box<dyn std::error::Error>> {
    // Null descriptor
    guest_mem.write_obj(0u64, GuestAddress(GDT_BASE))?;

    // 64-bit code segment: executable, readable, long mode
    // Flags: G=1, L=1, P=1, DPL=0, S=1, Type=0xA (execute/read)
    // Limit and base are ignored in long mode
    guest_mem.write_obj(0x00AF_9A00_0000_FFFFu64, GuestAddress(GDT_BASE + 8))?;

    // 64-bit data segment: readable, writable
    // Flags: G=1, P=1, DPL=0, S=1, Type=0x2 (read/write)
    guest_mem.write_obj(0x00CF_9200_0000_FFFFu64, GuestAddress(GDT_BASE + 16))?;

    Ok(())
}

/// Set up identity-mapped page tables using vm-memory.
///
/// Page table structure for identity mapping with 2MB pages:
/// PML4 (at PAGE_TABLE_BASE) -> PDPT (at +0x1000) -> PD (at +0x2000)
///
/// Each 2MB page in the PD covers 2MB of physical memory.
/// 512 entries in PD = 1GB identity mapped.
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
        let phys_addr = i * 0x200000; // 2MB per entry
        let entry = phys_addr | PTE_PRESENT | PTE_WRITABLE | PTE_PAGE_SIZE;
        guest_mem.write_obj(entry, GuestAddress(pd_addr + i * 8))?;
    }

    Ok(())
}

fn setup_sregs(sregs: &mut kvm_sregs) {
    // Configure control registers for long mode

    // CR0: Protected mode + Paging
    sregs.cr0 = CR0_PE | CR0_PG;

    // CR3: Physical address of PML4
    sregs.cr3 = PAGE_TABLE_BASE;

    // CR4: PAE required for long mode
    sregs.cr4 = CR4_PAE;

    // EFER: Long Mode Enable + Long Mode Active
    sregs.efer = EFER_LME | EFER_LMA;

    // Configure GDT
    sregs.gdt.base = GDT_BASE;
    sregs.gdt.limit = 23; // 3 entries * 8 bytes - 1

    // Configure code segment (selector 0x08)
    sregs.cs = make_segment(CODE_SELECTOR, 0, 0xFFFF_FFFF, 11, true);

    // Configure data segments (selector 0x10)
    let data_seg = make_segment(DATA_SELECTOR, 0, 0xFFFF_FFFF, 3, false);
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;

    // IDT: Leave empty (no interrupt handling)
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
        db: 0,                       // Must be 0 for 64-bit segments
        s: 1,                        // Code/data segment (not system)
        l: if code { 1 } else { 0 }, // Long mode for code segment
        g: 1,                        // 4KB granularity
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

fn setup_regs(regs: &mut kvm_regs) {
    // Entry point
    regs.rip = GUEST_CODE_BASE;

    // Stack pointer (16-byte aligned)
    regs.rsp = STACK_TOP;

    // Flags: bit 1 is always set
    regs.rflags = 0x2;

    // Clear other registers
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
