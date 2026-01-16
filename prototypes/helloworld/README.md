# KVM Hello World Prototype

A minimal proof-of-concept demonstrating a bare-metal binary running as a KVM guest without any operating system.

## Overview

This prototype consists of two components:

1. **VMM** (Virtual Machine Monitor) - A host-side Rust application that:
   - Creates a VM via /dev/kvm
   - Sets up x86-64 long mode (GDT, page tables, control registers)
   - Loads and runs the guest binary
   - Handles VM exits (HLT, I/O)

2. **Guest** - A bare-metal Rust binary (`#![no_std]`) that:
   - Runs directly on the vCPU with no OS
   - Writes "Hello from KVM guest!" to serial port 0x3f8
   - Signals completion via HLT instruction

## Requirements

- Linux with KVM support (`/dev/kvm`)
- Rust nightly (for `build-std` feature)
- `rust-objcopy` (from `cargo-binutils`)

## Development Environment

### Option 1: DevContainer (Recommended)

This prototype includes a devcontainer configuration with all dependencies pre-installed.

1. Open this folder in VS Code
2. When prompted, click "Reopen in Container" (or run "Dev Containers: Reopen in Container" from the command palette)
3. The container includes:
   - Rust nightly with `rust-src` component
   - `cargo-binutils` (provides `rust-objcopy`)
   - KVM device passthrough

### Option 2: Manual Installation

Install dependencies on your host:

```bash
rustup install nightly
rustup component add rust-src --toolchain nightly
cargo install cargo-binutils
rustup component add llvm-tools-preview
```

## Building

```bash
./build.sh
```

This will:
1. Build the guest crate with `x86_64-unknown-none` target
2. Convert the ELF to a flat binary (`guest.bin`)
3. Build the VMM

## Running

```bash
sudo ./target/release/vmm guest.bin
```

Note: `sudo` is required for `/dev/kvm` access unless your user is in the `kvm` group.

Example output:
```
Loaded guest binary: 99 bytes from guest.bin
KVM API version: 12
Created VM
Allocated 2097152 bytes of guest memory
Configured memory region
Set up GDT at 0x1000
Set up page tables at 0x2000
Loaded guest code at 0x10000
Created vCPU
Configured special registers for long mode
Configured general registers (RIP=0x10000, RSP=0x2fff8)

--- Starting guest execution ---

Hello from KVM guest!

--- Guest executed HLT ---
Guest completed successfully!
```

## Memory Layout

| Address Range | Purpose |
|---------------|---------|
| 0x1000-0x1FFF | GDT (4KB) |
| 0x2000-0x5FFF | Page tables (16KB) |
| 0x10000-0x1FFFF | Guest code (64KB) |
| 0x20000-0x2FFFF | Stack (64KB) |

## Architecture Notes

- The guest runs in 64-bit long mode from the start
- Identity-mapped page tables (1GB using 2MB pages)
- No IDT - any exception causes a triple fault
- Serial port I/O (port 0x3f8) is trapped and printed by the VMM
- HLT instruction causes a VM exit, signaling completion
