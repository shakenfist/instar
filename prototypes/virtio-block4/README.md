# Virtio-Block4 Prototype (Performance Statistics)

A minimal KVM virtual machine monitor (VMM) demonstrating virtio-block device
emulation with **comprehensive performance statistics**. This prototype extends
virtio-block3 by adding internal VMM counters and KVM binary statistics API
support for monitoring VM behavior and enabling resource limiting.

## Motivation

The security analysis in [docs/security.md](../../docs/security.md) identifies
DoS vulnerabilities where malicious disk images cause excessive resource
consumption. To mitigate these risks, we need:

- **CPU time limits**: Abort operations exceeding time thresholds
- **Exit rate detection**: Identify anomalous VM behavior patterns
- **Resource accounting**: Track I/O operations for tuning and debugging

Additionally, performance counters help identify bottlenecks when comparing
different sector sizes and I/O patterns.

## Overview

Key features:
- **Internal VMM counters**: Track exits by type, runtime, and throughput
- **KVM binary statistics**: Access kernel-level per-vCPU statistics
- **Statistics reporting**: Display detailed metrics on completion
- **Resource limit checking**: Detect excessive runtime or exit rates
- **All virtio-block3 features**: Configurable sector sizes, protobuf messaging

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                              VMM                                     │
│  ┌─────────────┐  ┌─────────────────┐  ┌─────────────────────────┐  │
│  │   KVM VM    │  │   Input Dev     │  │    Output Dev           │  │
│  │   + vCPU    │  │   (read-only)   │  │    (write)              │  │
│  │             │  │   sector_size:  │  │    sector_size:         │  │
│  │             │  │   configurable  │  │    configurable         │  │
│  └──────┬──────┘  └────────┬────────┘  └──────────┬──────────────┘  │
│         │                  │                       │                 │
│  ┌──────┴──────────────────┴───────────────────────┴──────────────┐ │
│  │                     VmmStats                                    │ │
│  │  - total_exits, io_exits, mmio_exits, hlt_exits               │ │
│  │  - bytes_read, bytes_written, sectors_processed               │ │
│  │  - runtime tracking, exit rate calculation                    │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                              │                                       │
│  ┌───────────────────────────┴─────────────────────────────────────┐│
│  │                  KVM Binary Stats (optional)                     ││
│  │  - Per-vCPU kernel statistics via KVM_GET_STATS_FD              ││
│  │  - Exit reasons, halt polling, interrupt injection              ││
│  └──────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

## Statistics Tracked

### Internal VMM Counters

| Counter | Description |
|---------|-------------|
| `total_exits` | Total number of VM exits |
| `io_exits` | Port I/O exits (serial communication) |
| `mmio_exits` | Memory-mapped I/O exits (virtio devices) |
| `hlt_exits` | HLT instruction exits |
| `shutdown_exits` | Shutdown/triple fault exits |
| `unknown_exits` | Unhandled exit types |
| `bytes_read` | Bytes read from input device |
| `bytes_written` | Bytes written to output device |
| `runtime_ns` | Wall-clock runtime in nanoseconds |

### Derived Metrics

| Metric | Calculation |
|--------|-------------|
| Throughput | bytes_written / runtime_secs |
| Exit rate | total_exits / runtime_secs |
| Exits per sector | mmio_exits / sectors_processed |
| I/O efficiency | bytes_transferred / total_exits |

### KVM Binary Statistics (when available)

Statistics exposed by the kernel via `KVM_CAP_BINARY_STATS_FD`:
- Exit counts by reason
- Halt polling statistics
- Interrupt injection counts
- Architecture-specific counters

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

### Basic Usage

```bash
dd if=/dev/urandom of=test.bin bs=4096 count=1000
sudo ./target/release/vmm --input test.bin --output out.bin guest.bin
```

### With Statistics Display

Statistics are displayed automatically on completion:

```bash
sudo ./target/release/vmm --input test.bin --output out.bin \
     --input-sector-size 4096 --output-sector-size 4096 guest.bin
```

### Example Output

```
...
--- Guest executed HLT ---
Guest completed successfully!

=== VMM Statistics ===
Runtime:        1.234 seconds
Total exits:    45,678
  IO exits:     2,345 (5.1%)
  MMIO exits:   42,333 (92.7%)
  HLT exits:    1 (0.0%)
  Other:        999 (2.2%)

Throughput:
  Bytes read:   4,096,000
  Bytes written: 4,096,000
  Read rate:    3.32 MB/s
  Write rate:   3.32 MB/s

Efficiency:
  Exits/sector: 42.3
  Bytes/exit:   89.7
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
  -h, --help                           Print help
```

## Key Differences from virtio-block3

| Feature | virtio-block3 | virtio-block4 |
|---------|---------------|---------------|
| Exit counting | None | By type |
| Runtime tracking | None | Wall-clock |
| Throughput metrics | None | Calculated |
| KVM statistics | None | Binary stats API |
| Statistics display | None | On completion |

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

- [Performance Counters](../../docs/performance_counters.md)
- [Security Vulnerabilities](../../docs/security.md)
- [guest-protocol crate](../../crates/guest-protocol/)
- [virtio-block3 prototype](../virtio-block3/)
