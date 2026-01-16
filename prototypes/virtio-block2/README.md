# Virtio-Block2 Prototype (with Protobuf)

A minimal KVM virtual machine monitor (VMM) demonstrating virtio-block device
emulation with structured protobuf messaging. The guest copies data between two
virtio-block devices, reporting progress via Protocol Buffers messages over the
serial port.

## Overview

This prototype extends virtio-block with:
- Structured guest-to-VMM communication via protobuf
- `guest-protocol` crate for no_std protobuf encoding/decoding
- Real-time progress reporting with typed messages

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
│                         │                                │
│                         ▼ Serial port (0x3f8)           │
│              ┌─────────────────────┐                    │
│              │ Protobuf decoder    │                    │
│              └─────────────────────┘                    │
└─────────────────────────────────────────────────────────┘
```

## Protocol Messages

The guest sends framed protobuf messages with a 2-byte length prefix:

```
[len_lo][len_hi][protobuf_data...]
```

Message types:
- **InitMessage**: Device initialization stages (probe, features, queue)
- **CapacityMessage**: Device capacity in sectors and bytes
- **ProgressMessage**: Copy progress (current/total, percent)
- **ErrorMessage**: I/O errors with operation, device, sector, status
- **CompleteMessage**: Operation completion with count and success flag

## Example Output

```
[INFO] init stage=probe device=input address=0x10000000
[INFO] init stage=features device=input address=0x100000020
[INFO] init stage=queue device=input address=0x100
[INFO] capacity device=input sectors=50 bytes=25600
[INFO] init stage=probe device=output address=0x10001000
[INFO] init stage=features device=output address=0x100000000
[INFO] init stage=queue device=output address=0x100
[INFO] capacity device=output sectors=50 bytes=25600
[PROGRESS] progress op=copy 1/50 (2%)
[PROGRESS] progress op=copy 11/50 (22%)
[PROGRESS] progress op=copy 21/50 (42%)
[PROGRESS] progress op=copy 31/50 (62%)
[PROGRESS] progress op=copy 41/50 (82%)
[PROGRESS] progress op=copy 50/50 (100%)
[COMPLETE] complete op=copy count=50 success=true
```

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

```bash
# Create a test file
dd if=/dev/urandom of=test.bin bs=512 count=100

# Run the copy
sudo ./target/release/vmm --input test.bin --output out.bin guest.bin

# Verify
sha256sum test.bin out.bin  # Should match
```

**Note:** Requires `/dev/kvm` access (root or kvm group membership).

## Key Differences from virtio-block

- **Structured messaging**: Protobuf instead of plain text serial output
- **guest-protocol crate**: Shared no_std/std protobuf definitions
- **Type-safe communication**: Enum-based message types with typed payloads
- **Machine-readable output**: VMM can parse and act on structured messages

## Dependencies

### Guest (no_std)
- `guest-protocol`: Protobuf encoding (no_std compatible)
- `heapless`: Fixed-capacity containers

### VMM (std)
- `guest-protocol` (with `std` feature): Protobuf decoding
- `kvm-ioctls`, `kvm-bindings`: KVM interface
- `vm-memory`: Guest memory management
- `clap`: CLI argument parsing

## Related Documentation

- [guest-protocol crate](../../crates/guest-protocol/)
- [Virtio-Block Data Transfer](../../docs/data-transfer-virtio-block.md)
- [VIRTIO 1.1 Specification](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
