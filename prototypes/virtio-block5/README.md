# Virtio-Block5 Prototype (I/O Optimizations)

A minimal KVM virtual machine monitor (VMM) demonstrating virtio-block device
emulation with **I/O path optimizations**. This prototype extends virtio-block4
by adding ioeventfd for reduced VM exits, O_DIRECT for bypass of the page
cache, and mmap-based file access.

## Motivation

The statistics from virtio-block4 showed that MMIO exits dominate the execution
time, with each sector requiring many exits for virtqueue operations. This
prototype explores three optimization strategies:

1. **ioeventfd**: Let KVM handle queue notifications in-kernel, avoiding full
   VM exits for QUEUE_NOTIFY writes
2. **O_DIRECT**: Bypass the kernel page cache for the backing file, reducing
   memory copies and cache pollution
3. **mmap**: Memory-map the backing file instead of using read/write syscalls

## Overview

Key features:
- **Multi-threaded VMM**: Separate I/O thread processes queues while vCPU runs
- **ioeventfd**: KVM signals an eventfd on MMIO writes to queue notify register
- **O_DIRECT**: Open backing files with O_DIRECT for direct I/O
- **mmap backing**: Option to mmap backing files instead of read/write
- **All virtio-block4 features**: Statistics tracking, configurable sector sizes

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
│  │  (Arc<Mutex<>>)            (Arc<Mutex<>>)            (Arc<Mutex<>>)     │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────┘
```

## Optimizations

### ioeventfd with I/O Thread

Without ioeventfd:
1. Guest writes to QUEUE_NOTIFY register
2. KVM exits to userspace (VM exit)
3. VMM handles the write
4. VMM processes virtqueue
5. VMM returns to KVM

With ioeventfd + I/O thread:
1. Guest writes to QUEUE_NOTIFY register
2. KVM signals eventfd (no exit!)
3. I/O thread wakes from epoll_wait()
4. I/O thread locks device, processes queue
5. Guest polls used_idx and sees completion
6. vCPU continues running throughout

### O_DIRECT

- Bypasses kernel page cache
- Reduces memory copies
- Avoids cache pollution from large I/O
- Requires aligned buffers

### mmap Backing

- Memory-map the entire backing file
- No syscall overhead per I/O
- Kernel handles page faults
- Good for random access patterns

## Building

Requirements:
- Nightly Rust toolchain
- `rust-src` and `llvm-tools-preview` components
- `cargo-binutils` for `rust-objcopy`
- Protocol Buffers compiler (`protoc`)

```bash
./build.sh
```

## Running

### Basic Usage (with ioeventfd)

```bash
dd if=/dev/urandom of=test.bin bs=4096 count=1000
sudo ./target/release/vmm --input test.bin --output out.bin guest.bin
```

### With O_DIRECT

```bash
sudo ./target/release/vmm --input test.bin --output out.bin \
     --direct-io guest.bin
```

### With mmap Backing

```bash
sudo ./target/release/vmm --input test.bin --output out.bin \
     --mmap-backing guest.bin
```

### Combined Optimizations

```bash
sudo ./target/release/vmm --input test.bin --output out.bin \
     --input-sector-size 65536 --output-sector-size 65536 \
     --progress-percent 100 \
     --direct-io guest.bin
```

## CLI Options

```
Usage: vmm [OPTIONS] --input <INPUT> --output <OUTPUT> <GUEST>

Arguments:
  <GUEST>  Guest binary to run

Options:
  -i, --input <INPUT>                  Input file (source for copy)
  -o, --output <OUTPUT>                Output file (destination for copy)
      --input-sector-size <SIZE>       Sector size for input device [default: 512]
      --output-sector-size <SIZE>      Sector size for output device [default: 512]
      --progress-percent <PERCENT>     Progress update interval [default: 0]
      --direct-io                      Use O_DIRECT for backing files
      --mmap-backing                   Use mmap for backing file access
      --no-ioeventfd                   Disable ioeventfd optimization
  -h, --help                           Print help
```

## Key Differences from virtio-block4

| Feature | virtio-block4 | virtio-block5 |
|---------|---------------|---------------|
| Threading | Single-threaded | Multi-threaded (I/O thread) |
| Queue notify | VM exit | ioeventfd + I/O thread |
| File I/O | read/write | Regular, O_DIRECT, or mmap |
| QUEUE_NOTIFY exits | Every notify | Bypassed with ioeventfd |
| Device access | Direct | Arc<Mutex<>> for thread safety |

## Expected Performance Impact

- **ioeventfd + I/O thread**: True parallelism - vCPU runs while I/O is processed
- **O_DIRECT**: Lower CPU usage, higher throughput for large sequential I/O
- **mmap**: Reduced syscall overhead, good for random access

## Dependencies

### Guest (no_std)
- `guest-protocol`: Protobuf encoding/decoding (no_std compatible)
- `heapless`: Fixed-capacity containers

### VMM (std)
- `guest-protocol` (with `std` feature): Protobuf encoding/decoding
- `kvm-ioctls`, `kvm-bindings`: KVM interface
- `vm-memory`: Guest memory management
- `vmm-sys-util`: EventFd for ioeventfd
- `memmap2`: Safe memory-mapped file handling
- `clap`: CLI argument parsing
- `libc`: For O_DIRECT and ioeventfd ioctls

## Related Documentation

- [Performance Counters](../../docs/performance_counters.md)
- [virtio-block4 prototype](../virtio-block4/)
