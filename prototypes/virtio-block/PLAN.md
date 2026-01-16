# Virtio-Block Prototype Implementation Plan

## Overview

Create a new prototype `prototypes/virtio-block/` that demonstrates virtio-block functionality by implementing a simple file copy operation: the guest reads sectors from an input block device and writes them to an output block device.

This prototype also introduces a **shared serial protocol crate** (`crates/guest-protocol/`) that defines a structured message format for guest-to-VMM communication. This crate lives at the project level so future prototypes can reuse it.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        VMM                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   KVM VM    │  │  Input Dev  │  │   Output Dev    │  │
│  │   + vCPU    │  │  (read-only)│  │   (write)       │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         │                │                  │           │
│         │ MMIO exits     │ Backed by        │ Backed by │
│         ▼                ▼ source file      ▼ dest file │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Guest Memory (8MB)                  │   │
│  │  ┌─────┐ ┌─────┐ ┌─────────┐ ┌─────────────────┐ │   │
│  │  │GDT  │ │PT   │ │Guest    │ │Virtio Regions   │ │   │
│  │  │     │ │     │ │Code     │ │MMIO + Queues    │ │   │
│  │  └─────┘ └─────┘ └─────────┘ └─────────────────┘ │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                  Guest Binary (no_std)                  │
│  1. Initialize virtio-block devices via MMIO            │
│  2. Read input device capacity                          │
│  3. Copy sectors: read from input → write to output     │
│  4. Report completion via serial port + HLT             │
└─────────────────────────────────────────────────────────┘
```

## Memory Layout (8MB total)

| Address Range | Size | Purpose |
|---------------|------|---------|
| 0x1000-0x1FFF | 4KB | GDT |
| 0x2000-0x5FFF | 16KB | Page tables (PML4/PDPT/PD) |
| 0x10000-0x1FFFF | 64KB | Guest code |
| 0x20000-0x2FFFF | 64KB | Stack |
| 0x100000-0x100FFF | 4KB | Input device MMIO |
| 0x101000-0x101FFF | 4KB | Output device MMIO |
| 0x200000-0x20FFFF | 64KB | Input virtqueue (desc/avail/used) |
| 0x210000-0x21FFFF | 64KB | Output virtqueue (desc/avail/used) |
| 0x300000-0x3FFFFF | 1MB | DMA buffer pool |

## Key Crates

### VMM Dependencies

```toml
[dependencies]
kvm-ioctls = "0.19"
kvm-bindings = "0.10"
vm-memory = "0.15"
virtio-queue = "0.14"
clap = "4.5"
```

### Guest Dependencies

```toml
[dependencies]
virtio-drivers = "0.8"
guest-protocol = { path = "../../crates/guest-protocol" }
```

### Shared Protocol Crate

```toml
# crates/guest-protocol/Cargo.toml
[package]
name = "guest-protocol"
version = "0.1.0"
edition = "2021"

[features]
default = []
std = []      # Enable for VMM parsing support

[dependencies]
micropb = "0.1"

[build-dependencies]
micropb-gen = "0.1"
```

The crate uses `micropb` for Protocol Buffers serialization - no_std and no_alloc compatible.

## File Structure

```
imago/
├── crates/                         # Shared crates (project-level)
│   └── guest-protocol/
│       ├── Cargo.toml              # no_std by default, std feature for VMM
│       ├── build.rs                # micropb-gen code generation
│       ├── proto/
│       │   └── guest.proto         # Protocol Buffers schema
│       └── src/
│           └── lib.rs              # Re-exports generated types + helpers
│
└── prototypes/
    └── virtio-block/
        ├── Cargo.toml              # Workspace: members = ["vmm", "guest"]
        ├── build.sh                # Build script
        ├── README.md               # Prototype documentation
        ├── .devcontainer/
        │   ├── Dockerfile          # Nightly Rust + tools
        │   └── devcontainer.json   # KVM passthrough
        ├── vmm/
        │   ├── Cargo.toml          # depends on guest-protocol with std feature
        │   └── src/
        │       ├── main.rs         # CLI, VM setup, run loop
        │       ├── memory.rs       # Memory layout setup
        │       ├── cpu.rs          # vCPU configuration
        │       └── virtio/
        │           ├── mod.rs
        │           ├── mmio.rs     # MMIO register emulation
        │           └── block.rs    # Block device backend
        └── guest/
            ├── Cargo.toml          # depends on guest-protocol (no_std)
            ├── .cargo/config.toml  # x86_64-unknown-none target
            ├── linker.ld           # Code at 0x10000
            └── src/
                ├── main.rs         # Copy logic
                ├── serial.rs       # Serial I/O (port 0x3f8)
                └── hal.rs          # virtio-drivers Hal implementation
```

## Implementation Steps

### Phase 1: Shared Protocol Crate
1. Create `crates/guest-protocol/` directory structure
2. Define `proto/guest.proto` schema with message types:
   - `Level` enum: DEBUG, INFO, PROGRESS, ERROR, COMPLETE
   - `GuestMessage` with oneof for: Init, Progress, Error, Complete
3. Create `build.rs` using `micropb-gen` to generate Rust code
4. Create `src/lib.rs` with re-exports and helper functions for encoding
5. Update `scripts/check-rust.sh` to lint the new crate

### Phase 2: Project Skeleton
6. Create virtio-block prototype directory structure based on helloworld2
7. Set up Cargo.toml workspace with dependencies including guest-protocol
8. Create devcontainer with nightly Rust
9. Update `scripts/check-rust.sh` to include virtio-block prototype
10. Create build.sh script

### Phase 3: VMM Virtio MMIO Device
11. Implement MMIO register state machine (per VIRTIO 1.1 spec)
12. Implement virtqueue descriptor chain processing
13. Implement block device read/write operations backed by files
14. Handle MMIO read/write VM exits in run loop

### Phase 4: Guest Virtio Driver
15. Implement `Hal` trait for `virtio-drivers` crate
16. Initialize both block devices via MMIO transport
17. Implement sector-by-sector copy loop
18. Use guest-protocol for all serial output:
    - Device initialization steps (MMIO probe, feature negotiation, queue setup)
    - Input device capacity and sector count
    - Copy progress (every N sectors or percentage milestones)
    - Any errors encountered with context (which device, which sector, error type)
    - Completion summary (total sectors copied, success/failure)

### Phase 5: Integration & Documentation
19. End-to-end testing with test files
20. Create docs/prototypes/virtio-block.md
21. Create docs/crates/guest-protocol.md
22. Update project README and docs/index.md

## Files to Modify

- `scripts/check-rust.sh`: Add `crates/guest-protocol` and `prototypes/virtio-block` to lint
- `docs/index.md`: Add links to new prototype and crate documentation
- `README.md`: Add mention of new prototype and shared crate

## Files to Create

- `crates/guest-protocol/` - Shared protocol crate (see file structure above)
- `prototypes/virtio-block/` - All files for the prototype
- `docs/prototypes/virtio-block.md` - Prototype documentation
- `docs/crates/guest-protocol.md` - Protocol crate documentation

## Serial Protocol Format

The `guest-protocol` crate uses Protocol Buffers (via `micropb`) for structured messages:
- Schema-defined with `.proto` file
- Compact binary encoding
- no_std + no_alloc compatible
- Interoperable with other languages if needed

**Protocol Schema (`proto/guest.proto`):**
```protobuf
syntax = "proto3";
package guest;

enum Level {
  DEBUG = 0;
  INFO = 1;
  PROGRESS = 2;
  ERROR = 3;
  COMPLETE = 4;
}

message InitMessage {
  string stage = 1;      // "probe", "features", "queue"
  string device = 2;     // "input", "output"
  uint64 address = 3;    // MMIO address or feature bits
}

message CapacityMessage {
  string device = 1;
  uint64 sectors = 2;
  uint64 bytes = 3;
}

message ProgressMessage {
  string operation = 1;  // "copy"
  uint64 current = 2;
  uint64 total = 3;
  uint32 percent = 4;
}

message ErrorMessage {
  string operation = 1;  // "read", "write"
  string device = 2;
  uint64 sector = 3;
  uint32 status = 4;
}

message CompleteMessage {
  string operation = 1;
  uint64 count = 2;      // sectors copied
  bool success = 3;
}

message GuestMessage {
  Level level = 1;
  oneof payload {
    InitMessage init = 2;
    CapacityMessage capacity = 3;
    ProgressMessage progress = 4;
    ErrorMessage error = 5;
    CompleteMessage complete = 6;
  }
}
```

**Message Types:**
| Level | Use Case |
|-------|----------|
| DEBUG | Verbose tracing (MMIO accesses, queue operations) |
| INFO | Initialization steps, configuration |
| PROGRESS | Periodic status updates during operations |
| ERROR | Failures with context |
| COMPLETE | Operation finished (success or failure summary) |

**API (guest side, no_std):**
```rust
use guest_protocol::{GuestMessage, Level, ProgressMessage, encode_message};

let msg = GuestMessage {
    level: Level::Progress,
    payload: Some(Payload::Progress(ProgressMessage {
        operation: "copy",
        current: 512,
        total: 2048,
        percent: 25,
    })),
};

let mut buf = [0u8; 128];
let len = encode_message(&msg, &mut buf);
serial_write(&buf[..len]);
```

**Note:** The binary output will need a simple framing mechanism (e.g., length prefix) so the VMM can parse message boundaries from the serial stream.

## Usage (after implementation)

```bash
cd prototypes/virtio-block
./build.sh
sudo ./target/release/vmm --input source.bin --output dest.bin guest.bin
# Output: Guest copies source.bin to dest.bin sector-by-sector
```

## Verification Steps

1. Build completes without errors: `./build.sh`
2. Pre-commit passes: `cd ../.. && ./scripts/check-rust.sh check`
3. Copy operation works:
   ```bash
   dd if=/dev/urandom of=test.bin bs=512 count=100
   sudo ./target/release/vmm --input test.bin --output out.bin guest.bin
   sha256sum test.bin out.bin  # Should match
   ```

## Key Challenges & Mitigations

| Challenge | Mitigation |
|-----------|------------|
| Virtio MMIO complexity | Follow VIRTIO 1.1 spec exactly; log all accesses for debugging |
| Guest Hal implementation | Use simple bump allocator from fixed DMA pool; identity mapping |
| No interrupts | Use polling: guest spins on used ring after submitting request |
| Large files | Sector-by-sector copy handles any size within capacity |

## Virtio MMIO Register Layout (Reference)

Per VIRTIO 1.1 specification, each device has a 4KB MMIO region:

| Offset | Name | R/W | Purpose |
|--------|------|-----|---------|
| 0x000 | MagicValue | R | 0x74726976 ("virt") |
| 0x004 | Version | R | 2 (modern) |
| 0x008 | DeviceID | R | 2 (block device) |
| 0x00C | VendorID | R | Implementation-defined |
| 0x010 | DeviceFeatures | R | Feature bits (selected page) |
| 0x014 | DeviceFeaturesSel | W | Feature page selector |
| 0x020 | DriverFeatures | W | Features accepted by driver |
| 0x024 | DriverFeaturesSel | W | Feature page selector |
| 0x030 | QueueSel | W | Queue selector |
| 0x034 | QueueNumMax | R | Max queue size (256) |
| 0x038 | QueueNum | W | Current queue size |
| 0x044 | QueueReady | RW | Queue ready flag |
| 0x050 | QueueNotify | W | Queue notification |
| 0x060 | InterruptStatus | R | Interrupt status |
| 0x064 | InterruptACK | W | Interrupt acknowledge |
| 0x070 | Status | RW | Device status |
| 0x080 | QueueDescLow | W | Descriptor table addr (low) |
| 0x084 | QueueDescHigh | W | Descriptor table addr (high) |
| 0x090 | QueueDriverLow | W | Available ring addr (low) |
| 0x094 | QueueDriverHigh | W | Available ring addr (high) |
| 0x0A0 | QueueDeviceLow | W | Used ring addr (low) |
| 0x0A4 | QueueDeviceHigh | W | Used ring addr (high) |
| 0x100+ | Config | RW | Device-specific config |

## Block Device Configuration Space

At offset 0x100 in the MMIO region:

| Offset | Field | Size | Purpose |
|--------|-------|------|---------|
| 0x100 | capacity | 8 bytes | Device size in 512-byte sectors |
| 0x108 | size_max | 4 bytes | Max segment size (optional) |
| 0x10C | seg_max | 4 bytes | Max segments per request (optional) |

## Block Request Format

Each request uses a descriptor chain:
1. **Header** (OUT): `{ type: u32, reserved: u32, sector: u64 }`
   - type: 0 = READ, 1 = WRITE
2. **Data** (IN for read, OUT for write): sector data
3. **Status** (IN): single byte, 0 = OK, 1 = IOERR, 2 = UNSUPP
