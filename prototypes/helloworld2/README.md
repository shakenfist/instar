# KVM Hello World 2 - Using rust-vmm Crates

A second iteration of the KVM hello world prototype that uses the `vm-memory`
crate from the rust-vmm project for simplified and safer guest memory
management.

## Overview

This prototype demonstrates how rust-vmm crates can simplify VMM development.
Compared to the original helloworld prototype, this version:

- Uses `GuestMemoryMmap` for automatic memory allocation and cleanup
- Uses `GuestAddress` for type-safe address handling
- Uses `write_obj` and `write_slice` for bounds-checked memory writes
- Eliminates manual pointer arithmetic and unsafe memory operations

## Key Improvements

### Before (helloworld)

```rust
// Manual allocation
let layout = std::alloc::Layout::from_size_align(size, 4096)?;
let ptr = unsafe { std::alloc::alloc_zeroed(layout) };

// Raw pointer writes
unsafe {
    let gdt = guest_mem.add(GDT_BASE as usize) as *mut u64;
    ptr::write(gdt.add(0), 0u64);
}

// Manual cleanup required
```

### After (helloworld2)

```rust
// Automatic allocation with vm-memory
let guest_mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), size)])?;

// Type-safe writes
guest_mem.write_obj(0u64, GuestAddress(GDT_BASE))?;

// Automatic cleanup when dropped
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `kvm-ioctls` | Safe KVM API wrappers |
| `kvm-bindings` | KVM FFI bindings |
| `vm-memory` | Guest memory abstraction |

## Requirements

- Linux with KVM support (`/dev/kvm`)
- Rust nightly (for `build-std` feature)
- `rust-objcopy` (from `cargo-binutils`)

## Development Environment

### Option 1: DevContainer (Recommended)

This prototype includes a devcontainer configuration with all dependencies
pre-installed.

1. Open this folder in VS Code
2. When prompted, click "Reopen in Container" (or run "Dev Containers: Reopen
   in Container" from the command palette)
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
3. Build the VMM with vm-memory support

## Running

```bash
sudo ./target/release/vmm guest.bin
```

Example output:
```
Loaded guest binary: 99 bytes from guest.bin
KVM API version: 12
Created VM
Allocated 2097152 bytes of guest memory via vm-memory
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

## Code Comparison

| Metric | helloworld | helloworld2 |
|--------|------------|-------------|
| VMM lines | 325 | ~230 |
| Unsafe blocks | 8 | 1 |
| Manual ptr ops | Yes | No |
| Auto cleanup | No | Yes |

## Next Steps

Future prototypes will add more rust-vmm crates:

- `virtio-queue` - For virtqueue implementation
- `virtio-blk` - For block device parsing
- `virtio-drivers` - For guest-side virtio drivers

These crates will reduce virtio-block implementation from ~1600 lines to ~450
lines (72% reduction).
