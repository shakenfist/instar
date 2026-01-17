# Virtio-Block Prototype

A minimal KVM virtual machine monitor (VMM) demonstrating virtio-block device
emulation. The guest copies data between two virtio-block devices, implementing
the world's least efficient `cp` command.

## Overview

This prototype explores:
- Virtio MMIO transport implementation
- Virtio-block device emulation
- Virtqueue descriptor chain processing
- Bare-metal guest virtio driver implementation

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        VMM                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   KVM VM    │  │  Input Dev  │  │   Output Dev    │  │
│  │   + vCPU    │  │  (read-only)│  │   (write)       │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         │                │                   │           │
│         │                │ Backed by        │ Backed by │
│         │                ▼ source file      ▼ dest file │
│  ┌──────┴───────────────────────────────────────────┐   │
│  │              Guest Memory (8MB)                   │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Memory Layout

| Address Range | Size | Purpose |
|---------------|------|---------|
| 0x1000-0x1FFF | 4KB | GDT |
| 0x2000-0x5FFF | 16KB | Page tables |
| 0x10000-0x1FFFF | 64KB | Guest code |
| 0x20000-0x2FFFF | 64KB | Stack |
| 0x100000-0x100FFF | 4KB | Input device MMIO |
| 0x101000-0x101FFF | 4KB | Output device MMIO |
| 0x200000-0x20FFFF | 64KB | Input virtqueue |
| 0x210000-0x21FFFF | 64KB | Output virtqueue |
| 0x300000-0x3FFFFF | 1MB | DMA buffer pool |

## Building

Requirements:
- Nightly Rust toolchain
- `rust-src` and `llvm-tools-preview` components
- `cargo-binutils` for `rust-objcopy`

From the prototype directory:
```bash
./build.sh
```

Or from the project root:
```bash
make build PROTOTYPE=virtio-block
```

Or manually:

```bash
# Build guest
cd guest
cargo +nightly build --release
cd ..

# Convert to flat binary
rust-objcopy -O binary target/x86_64-unknown-none/release/guest guest.bin

# Build VMM
cd vmm
cargo build --release
```

## Running

```bash
# Create a test file
dd if=/dev/urandom of=test.bin bs=512 count=100

# Run the copy
sudo ./target/release/vmm --input test.bin --output out.bin guest.bin

# Verify
sha256sum test.bin out.bin  # Should match
```

**Note:** Requires `/dev/kvm` access (root or kvm group membership).

## How It Works

### VMM Side

1. Creates a KVM VM with 8MB of guest memory
2. Sets up x86-64 long mode (GDT, page tables, registers)
3. Loads the guest binary at 0x10000
4. Creates two virtio-block devices:
   - Input device at MMIO 0x100000 (backed by source file)
   - Output device at MMIO 0x101000 (backed by destination file)
5. Runs the vCPU, handling:
   - Serial output (port 0x3f8) for guest debug messages
   - MMIO reads/writes for virtio device emulation
   - Virtqueue notifications for block I/O processing

### Guest Side

1. Probes and initializes both virtio-block devices via MMIO
2. Negotiates features (VIRTIO_F_VERSION_1)
3. Sets up virtqueues (descriptors, available ring, used ring)
4. Reads capacity from input device config space
5. For each sector:
   - Submits read request to input device
   - Waits for completion (polls used ring)
   - Submits write request to output device
   - Waits for completion
6. Reports progress and halts

## Virtio-Block Protocol

Each block request uses a 3-descriptor chain:

1. **Header** (device reads): type (IN/OUT), sector number
2. **Data** (device reads or writes): sector data (512 bytes)
3. **Status** (device writes): result (OK/IOERR/UNSUPP)

The guest adds descriptors to the available ring and notifies the device.
The VMM processes requests and adds results to the used ring.

## Key Differences from helloworld

- **Multiple MMIO devices**: Two virtio-block devices at different addresses
- **Virtqueue processing**: Full descriptor chain handling
- **File-backed storage**: Real file I/O through block device abstraction
- **Complex guest logic**: Initialization, I/O operations, polling

## Performance

This prototype is obviously not performant, a straight copy of my test data is quite fast:

```bash
mikal@kasm:.../prototypes/virtio-block$ time cp input.bin output.bin

real    0m5.015s
user    0m0.005s
sys     0m4.015s
```

But the KVM guest copy is not:

```bash
mikal@kasm:.../prototypes/virtio-block$ dd if=/dev/urandom of=input.bin bs=512 count=10000000
10000000+0 records in
10000000+0 records out
5120000000 bytes (5.1 GB, 4.8 GiB) copied, 24.2875 s, 211 MB/s

mikal@kasm:.../prototypes/virtio-block$ ls -lrth input.bin
-rw-rw-r-- 1 mikal mikal 4.8G Jan 17 06:23 input.bin

mikal@kasm:.../prototypes/virtio-block$ time ./target/release/vmm --input input.bin --output output.bin guest.bin | grep -v Progress
Loaded guest binary: 4360 bytes from guest.bin
Input file: input.bin (5120000000 bytes, 10000000 sectors)
Output file: output.bin (pre-allocated 5120000000 bytes)
KVM API version: 12
Created VM
Allocated 8388608 bytes of guest memory
Configured memory region
Set up GDT at 0x1000
Set up page tables at 0x2000
Loaded guest code at 0x10000
Created virtio-block devices at MMIO 0x10000000 and 0x10001000
Created vCPU
Configured special registers for long mode
Configured general registers (RIP=0x10000, RSP=0x2fff8)

--- Starting guest execution ---

Virtio-block copy starting...
Initializing input device...
Input device ready, capacity: 10000000 sectors
Initializing output device...
Output device ready
Copying 10000000 sectors...
       
Copy complete!
Copied: 10000000 sectors

--- Guest executed HLT ---
Guest completed successfully!

real    5m43.946s
user    1m56.380s
sys     3m54.704s
```

However, this is a proof of concept prototype and has not been optimised or tuned in any
way yet.

## Related Documentation

- [Virtio-Block Data Transfer](../../docs/data-transfer-virtio-block.md)
- [VIRTIO 1.1 Specification](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
