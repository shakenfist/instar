# Virtio-Block6 Prototype (Sparse Output)

A minimal KVM virtual machine monitor (VMM) demonstrating virtio-block device
emulation with **sparse/dynamic output file support**. This prototype extends
virtio-block5 by adding support for output files that grow on demand rather
than being pre-allocated.

## Motivation

In real disk image operations (like qemu-img convert), we often don't know the
final size of the output image upfront, or we want to create sparse images
that only allocate space for sectors that are actually written. This prototype
explores dynamic file sizing:

1. **Sparse output**: Output file is not pre-allocated; it grows as sectors
   are written
2. **Configurable capacity**: Output capacity can be set independently of the
   input size via CLI option
3. **On-demand growth**: The file extends automatically when the guest writes
   beyond the current file size

## Overview

Key features:
- **Sparse output files**: Output file starts empty and grows on demand
- **Capacity vs actual size**: Device exposes a capacity to guest, but file
  only consumes space for written sectors
- **--max-output-size**: CLI option to set output capacity (default: input size)
- **--preallocate-output**: Option to pre-allocate for traditional behavior
- **ioeventfd optimization**: Queue notifications without VM exits (from virtio-block5)
- **Simplified I/O**: Uses buffered file I/O only (no O_DIRECT or mmap)

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                              VMM (Multi-threaded)                              │
│                                                                                │
│  Main Thread (vCPU)                        I/O Thread                          │
│  ┌─────────────────┐                       ┌─────────────────────────────────┐ │
│  │   KVM VM        │                       │  epoll_wait() on eventfds       │ │
│  │   + vCPU        │   ───eventfd───────>  │                                 │ │
│  │   vcpu.run()    │                       │  On signal:                     │ │
│  │                 │                       │    - Lock device                │ │
│  │   Handles:      │                       │    - process_queue()            │ │
│  │   - IO exits    │                       │    - Update used ring           │ │
│  │   - MMIO exits  │                       │    - Set interrupt_status       │ │
│  └────────┬────────┘                       └──────────────┬──────────────────┘ │
│           │                                               │                    │
│           │         Shared State (Arc<Mutex<>>)           │                    │
│           └───────────────────┬───────────────────────────┘                    │
│                               │                                                │
│  ┌────────────────────────────┴────────────────────────────────────────────┐  │
│  │  Input Device              Output Device              VmmStats          │  │
│  │  (read-only)               (sparse/writable)         (Arc<Mutex<>>)     │  │
│  │                            grows on demand                              │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────┘
```

## Sparse File Behavior

### How It Works

1. **Device capacity**: The virtio-block device reports a capacity to the guest
   (e.g., 1GB). This is required by the virtio protocol.

2. **Actual file size**: The output file starts at 0 bytes and grows only when
   sectors are written.

3. **Reading unwritten regions**: Reading a sector that hasn't been written
   returns zeros (like reading a sparse file).

4. **Writing**: When the guest writes beyond the current file size, the file
   is automatically extended to accommodate the write.

### Sparse vs Pre-allocated

| Mode | File Size at Start | After Writing 1MB at Offset 10MB |
|------|-------------------|----------------------------------|
| Sparse (default) | 0 bytes | ~11MB (sparse, with 10MB hole) |
| Pre-allocated | Full capacity | Full capacity |

## Building

Requirements:
- Nightly Rust toolchain
- `rust-src` and `llvm-tools-preview` components
- `cargo-binutils` for `rust-objcopy`
- Protocol Buffers compiler (`protoc`)

From the prototype directory:
```bash
./build.sh
```

Or from the project root:
```bash
make build PROTOTYPE=virtio-block6
```

## Running

### Basic Usage (sparse output, default)

```bash
dd if=/dev/urandom of=test.bin bs=4096 count=1000
sudo ./target/release/vmm --input test.bin --output out.bin guest.bin

# Check that output is sparse (may show smaller blocks than apparent size)
ls -lsh out.bin
```

### With Custom Output Capacity

```bash
# Create output with 10GB capacity (but only allocates what's written)
sudo ./target/release/vmm --input test.bin --output out.bin \
     --max-output-size 10737418240 guest.bin
```

### With Pre-allocation (traditional behavior)

```bash
sudo ./target/release/vmm --input test.bin --output out.bin \
     --preallocate-output guest.bin
```

### With Large Sector Sizes

```bash
sudo ./target/release/vmm --input test.bin --output out.bin \
     --input-sector-size 65536 --output-sector-size 65536 \
     --max-output-size 1073741824 guest.bin
```

## CLI Options

```
Usage: vmm [OPTIONS] --input <INPUT> --output <OUTPUT> <GUEST>

Arguments:
  <GUEST>  Guest binary to run

Options:
  -i, --input <INPUT>                  Input file (source for copy)
  -o, --output <OUTPUT>                Output file (destination for copy)
      --input-sector-size <SIZE>       Sector size for input device [default: 65536]
      --output-sector-size <SIZE>      Sector size for output device [default: 65536]
      --max-output-size <BYTES>        Maximum output file size in bytes [default: input size]
      --preallocate-output             Pre-allocate output file instead of sparse
      --progress-percent <PERCENT>     Progress update interval [default: 10]
      --no-ioeventfd                   Disable ioeventfd optimization
  -h, --help                           Print help
```

## Key Differences from virtio-block5

| Feature | virtio-block5 | virtio-block6 |
|---------|---------------|---------------|
| Output allocation | Pre-allocated | Sparse by default |
| Output capacity | Same as input | Configurable via --max-output-size |
| File growth | Fixed size | On-demand extension |
| I/O modes | Regular, O_DIRECT, mmap | Buffered I/O only |
| Unwritten reads | N/A (pre-allocated) | Returns zeros |

## Technical Notes

### Memory Layout

The VMM allocates generous memory for the guest to handle complex operations:

| Region | Address | Size | Purpose |
|--------|---------|------|---------|
| GDT | 0x1000 | 24 bytes | Global Descriptor Table |
| Page Tables | 0x2000 | 12KB | PML4 + PDPT + PD |
| Guest Code | 0x10000 | Variable | Loaded binary |
| Input VQ | 0x100000 | 64KB | Virtio queue for input device |
| Output VQ | 0x110000 | 64KB | Virtio queue for output device |
| DMA Pool | 0x200000 | Variable | Guest DMA buffers |
| Stack | 0x1000000 | 4MB | Guest stack (grows down) |
| Total | - | 32MB | Guest physical memory |

The 4MB stack and 32MB total memory provide headroom for complex operations like
`qemu-img info` which may construct large data structures.

### Crash Diagnostics

When the VM shuts down unexpectedly (triple fault), the VMM provides diagnostic
information to help identify the cause:

```
--- VM Shutdown (triple fault?) ---
RIP=0x12345, RSP=0xfff000, RBP=0xfff100
CR0=0x80000011, CR3=0x2000, CR4=0x20

*** LIKELY STACK OVERFLOW ***
  RSP (0xfff000) is outside stack region
  Stack region: 0x1000000 - 0x13ffff8 (4194304 bytes)
  Stack underflowed by 61440 bytes
```

This helps distinguish between stack overflow (RSP outside stack region) and
other causes of triple faults.

### Why Only Buffered I/O?

This prototype uses regular buffered file I/O exclusively because:

1. **Page cache benefits**: The kernel page cache provides read-ahead for
   sequential reads and write coalescing for small writes, both of which
   significantly improve throughput for file copy workloads.

2. **O_DIRECT is slower**: Testing showed O_DIRECT was slower for sequential
   I/O because it bypasses read-ahead and write combining. O_DIRECT is
   primarily beneficial for databases with their own caching layer.

3. **mmap incompatible with sparse**: Memory-mapped I/O requires the file to
   be sized upfront. Growing a mapped file requires remapping, which is
   complex and error-prone.

4. **Simplicity**: A single I/O path is easier to maintain and debug.

### Capacity in VIRTIO Protocol

The virtio-block specification requires devices to expose their capacity via
the config space. The guest uses this to know the valid sector range. We
cannot have a truly "unlimited" device, but we can set a large capacity
while only allocating space for sectors that are actually written.

### Sparse File Semantics on Linux

- `seek(offset); write(data)` automatically extends the file
- Reading holes (unwritten regions) returns zeros
- The file's apparent size differs from its allocated size (blocks on disk)
- Use `ls -lsh` to see both apparent and allocated sizes

## Dependencies

### Guest (no_std)
- `guest-protocol`: Protobuf encoding/decoding (no_std compatible)
- `heapless`: Fixed-capacity containers

### VMM (std)
- `guest-protocol` (with `std` feature): Protobuf encoding/decoding
- `kvm-ioctls`, `kvm-bindings`: KVM interface
- `vm-memory`: Guest memory management
- `vmm-sys-util`: EventFd for ioeventfd
- `clap`: CLI argument parsing
- `libc`: For epoll and eventfd

## Related Documentation

- [virtio-block5 prototype](../virtio-block5/)
- [Performance Counters](../../docs/performance-counters.md)
