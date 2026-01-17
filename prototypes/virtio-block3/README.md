# Virtio-Block3 Prototype (Configurable Sector Sizes)

A minimal KVM virtual machine monitor (VMM) demonstrating virtio-block device
emulation with **configurable sector sizes**. This prototype extends virtio-block2
by adding command-line options to configure the sector size for both input and
output devices, allowing performance testing with different I/O granularities.

## Motivation

The previous virtio-block prototypes used a fixed 512-byte sector size, which
results in high overhead for large file copies due to the small I/O size. This
prototype allows experimenting with larger sector sizes (e.g., 4KB, 64KB) to
validate whether increased sector size improves performance.

## Overview

Key features:
- **Configurable sector sizes**: Set via `--input-sector-size` and
  `--output-sector-size` CLI options
- **VMM-to-guest configuration**: Sector sizes are sent to the guest via
  protobuf messages over the serial port at startup
- **Bidirectional serial communication**: Guest reads config, writes status
- **Sector size translation**: Guest handles copying between devices with
  different sector sizes
- **Debug output**: Separate COM2 port for plain text debug messages,
  independent of the protobuf protocol on COM1

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                            VMM                                   │
│  ┌─────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │   KVM VM    │  │   Input Dev     │  │    Output Dev       │  │
│  │   + vCPU    │  │   (read-only)   │  │    (write)          │  │
│  │             │  │   sector_size:  │  │    sector_size:     │  │
│  │             │  │   configurable  │  │    configurable     │  │
│  └──────┬──────┘  └────────┬────────┘  └──────────┬──────────┘  │
│         │                  │                       │             │
│         │                  │ Backed by            │ Backed by   │
│         │                  ▼ source file          ▼ dest file   │
│  ┌──────┴─────────────────────────────────────────────────────┐ │
│  │                  Guest Memory (8MB)                         │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│         ┌────────────────────┴───────────────────┐              │
│         │ COM1 (0x3f8) - Protobuf Protocol       │              │
│         │   VMM → Guest: VmmConfig (sector sizes)│              │
│         │   Guest → VMM: Status/Progress messages│              │
│         ├────────────────────────────────────────┤              │
│         │ COM2 (0x2f8) - Debug Output            │              │
│         │   Guest → VMM: Plain text debug msgs   │              │
│         └────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

## Protocol

### VMM → Guest (at startup)

The VMM sends a `VmmConfig` protobuf message containing device configurations:

```protobuf
message DeviceConfig {
  string name = 1;           // "input" or "output"
  uint32 sector_size = 2;    // Sector size in bytes
}

message VmmConfig {
  repeated DeviceConfig devices = 1;
}
```

### Guest → VMM (during operation)

Same as virtio-block2:
- **InitMessage**: Device initialization stages
- **CapacityMessage**: Device capacity in sectors and bytes
- **ProgressMessage**: Copy progress
- **ErrorMessage**: I/O errors
- **CompleteMessage**: Operation completion

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

### Default (512-byte sectors)

```bash
dd if=/dev/urandom of=test.bin bs=512 count=1000
sudo ./target/release/vmm --input test.bin --output out.bin guest.bin
sha256sum test.bin out.bin  # Should match
```

### With larger sector sizes

```bash
# Create test file aligned to 4KB sectors
dd if=/dev/urandom of=test.bin bs=4096 count=1000

# Run with 4KB sectors
sudo ./target/release/vmm --input test.bin --output out.bin \
     --input-sector-size 4096 --output-sector-size 4096 guest.bin

sha256sum test.bin out.bin  # Should match
```

### Mixed sector sizes

The guest handles copying between devices with different sector sizes:

```bash
dd if=/dev/urandom of=test.bin bs=4096 count=1000

# Read 4KB sectors, write 512-byte sectors
sudo ./target/release/vmm --input test.bin --output out.bin \
     --input-sector-size 4096 --output-sector-size 512 guest.bin
```

**Note:** Requires `/dev/kvm` access (root or kvm group membership).

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
  -h, --help                           Print help
```

Valid sector sizes are powers of 2, from 512 bytes to 64KB (e.g., 512, 1024,
2048, 4096, 8192, 16384, 32768, 65536).

## Example Output

```
$ sudo ./target/release/vmm --input test.bin --output out.bin \
       --input-sector-size 4096 --output-sector-size 4096 guest.bin
Loaded guest binary: 17408 bytes from guest.bin
Input file: test.bin (4096000 bytes, 1000 sectors @ 4096 bytes/sector)
Output file: out.bin (pre-allocated 4096000 bytes, 1000 sectors @ 4096 bytes/sector)
KVM API version: 12
Created VM
Allocated 8388608 bytes of guest memory
Configured memory region
Set up GDT at 0x1000
Set up page tables at 0x2000
Loaded guest code at 0x10000
Created virtio-block devices at MMIO 0x10000000 and 0x10001000
  Input sector size: 4096 bytes, Output sector size: 4096 bytes
Created vCPU
Configured special registers for long mode
Configured general registers (RIP=0x10000, RSP=0x2fff8)
Queued configuration message (24 bytes) for guest

--- Starting guest execution ---

[INFO] init stage=config device=input address=0x1000
[INFO] init stage=config device=output address=0x1000
[INFO] init stage=probe device=input address=0x10000000
[INFO] init stage=features device=input address=0x100000020
[INFO] init stage=queue device=input address=0x100
[INFO] capacity device=input sectors=1000 bytes=4096000
[INFO] init stage=sector_size device=input address=0x1000
...
[PROGRESS] progress op=copy 1000/1000 (100%)
[COMPLETE] complete op=copy count=4096000 success=true

--- Guest executed HLT ---
Guest completed successfully!
```

## Key Differences from virtio-block2

| Feature | virtio-block2 | virtio-block3 |
|---------|---------------|---------------|
| Sector size | Fixed 512 bytes | Configurable per-device |
| Serial direction | Guest → VMM only | Bidirectional |
| VMM config | N/A | Protobuf over serial |
| Sector translation | N/A | Automatic |
| Debug output | N/A | COM2 (plain text) |

## Performance Testing

To test the hypothesis that larger sector sizes improve performance:

```bash
# Create a large test file
dd if=/dev/urandom of=large.bin bs=1M count=1024  # 1GB

# Test with 512-byte sectors
time sudo ./target/release/vmm --input large.bin --output out.bin \
     --input-sector-size 512 --output-sector-size 512 guest.bin

# Test with 4KB sectors
time sudo ./target/release/vmm --input large.bin --output out.bin \
     --input-sector-size 4096 --output-sector-size 4096 guest.bin

# Test with 64KB sectors
time sudo ./target/release/vmm --input large.bin --output out.bin \
     --input-sector-size 65536 --output-sector-size 65536 guest.bin
```

Compare the results to see if larger sector sizes reduce overhead.

## Dependencies

### Guest (no_std)
- `guest-protocol`: Protobuf encoding/decoding (no_std compatible)
- `heapless`: Fixed-capacity containers

### VMM (std)
- `guest-protocol` (with `std` feature): Protobuf encoding/decoding
- `kvm-ioctls`, `kvm-bindings`: KVM interface
- `vm-memory`: Guest memory management
- `clap`: CLI argument parsing

## Related Documentation

- [guest-protocol crate](../../crates/guest-protocol/)
- [virtio-block2 prototype](../virtio-block2/)
- [Virtio-Block Data Transfer](../../docs/data-transfer-virtio-block.md)
- [VIRTIO 1.1 Specification](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
