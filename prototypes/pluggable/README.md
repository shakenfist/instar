# Pluggable Prototype (Modular Operations)

A minimal KVM virtual machine monitor (VMM) demonstrating virtio-block device
emulation with a **pluggable operation architecture**. This prototype extends
virtio-block6 by separating the guest code into reusable infrastructure and
swappable operations.

## Motivation

Previous prototypes bundled the copy operation directly into the guest's main
function. This made the code hard to extend with new operations (like `info`,
`transcode`, or `convert`). This prototype explores a modular architecture where:

1. **Infrastructure is reusable**: Device initialization, communication, and
   memory management are shared across all operations
2. **Operations are pluggable**: Each operation (copy, info, etc.) is a separate
   module implementing a common trait
3. **Main is minimal**: The entry point just sets up devices and dispatches to
   the configured operation

## Architecture

### Guest Code Structure

```
guest/src/
├── main.rs           Entry point: device setup, operation dispatch
├── infra/            Reusable infrastructure
│   ├── mod.rs        Module exports
│   ├── mem.rs        Memory layout constants
│   ├── serial.rs     Serial communication, config parsing
│   └── virtio.rs     VirtioBlock device abstraction
└── operations/       Pluggable operations
    ├── mod.rs        Operation trait, dispatcher
    └── copy.rs       Copy operation implementation
```

### The GuestOperation Trait

Operations implement a simple trait:

```rust
pub trait GuestOperation {
    /// Name of this operation (for logging)
    fn name(&self) -> &'static str;

    /// Execute the operation with initialized devices
    fn execute(
        &self,
        input: &mut VirtioBlock,
        output: &mut VirtioBlock,
        config: &DeviceConfig,
    ) -> OperationResult;
}
```

### Adding a New Operation

1. Add a variant to `Operation` enum in `infra/serial.rs`:
   ```rust
   pub enum Operation {
       Copy,
       Info,   // Add your operation
   }
   ```

2. Create `operations/your_op.rs` implementing `GuestOperation`

3. Register in `operations/mod.rs` dispatcher:
   ```rust
   match config.operation {
       Operation::Copy => copy::CopyOperation.execute(...),
       Operation::Info => info::InfoOperation.execute(...),
   }
   ```

### What's Shared (infra/)

- **Memory layout**: MMIO addresses, virtqueue bases, DMA pool location
- **VirtioBlock**: Device initialization, read/write sector operations
- **Serial communication**: Config parsing, progress/error reporting
- **DeviceConfig**: Sector sizes, progress interval, operation selection

### What's Pluggable (operations/)

- **Copy**: Read from input, write to output with sector translation
- **Info** (future): Report device information without modification
- **Transcode** (future): Transform data between formats

## System Architecture

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

┌───────────────────────────────────────────────────────────────────────────────┐
│                           Guest (Bare-metal, no_std)                          │
│                                                                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ main.rs                                                                 │  │
│  │   1. Read config from VMM                                               │  │
│  │   2. Initialize input device (VirtioBlock)                              │  │
│  │   3. Initialize output device (VirtioBlock)                             │  │
│  │   4. Dispatch to operation                                              │  │
│  │   5. Report completion                                                  │  │
│  └──────────────────────────────────┬──────────────────────────────────────┘  │
│                                     │                                         │
│  ┌──────────────────────────────────┴──────────────────────────────────────┐  │
│  │ operations/                                                             │  │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │  │
│  │   │    copy     │  │    info     │  │  transcode  │  ...                │  │
│  │   │  (current)  │  │  (future)   │  │  (future)   │                     │  │
│  │   └─────────────┘  └─────────────┘  └─────────────┘                     │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│                                     │                                         │
│  ┌──────────────────────────────────┴──────────────────────────────────────┐  │
│  │ infra/                                                                  │  │
│  │   VirtioBlock   |   Serial Comms   |   Memory Layout                    │  │
│  │   (read/write)  |   (config/msgs)  |   (addresses)                      │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────┘
```

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
make build PROTOTYPE=pluggable
```

## Running

### Basic Usage (copy operation)

```bash
dd if=/dev/urandom of=test.bin bs=4096 count=1000
sudo ./target/release/vmm --input test.bin --output out.bin guest.bin

# Verify copy succeeded
sha256sum test.bin out.bin
```

### CLI Options

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

## Key Differences from virtio-block6

| Aspect | virtio-block6 | pluggable |
|--------|---------------|-----------|
| Guest structure | Monolithic main.rs | Modular: infra/ + operations/ |
| Copy code | Inline in _start() | Separate CopyOperation |
| Adding operations | Modify main.rs | Add new module, register |
| Code reuse | Limited | VirtioBlock, serial shared |

## Technical Notes

### Memory Layout

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

### Inherited Features

From virtio-block6:
- Sparse output files (grow on demand)
- ioeventfd optimization (queue notifications without VM exits)
- Configurable sector sizes
- Progress reporting

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

- [virtio-block6 prototype](../virtio-block6/) - Base for this prototype
- [Performance Counters](../../docs/performance_counters.md)
