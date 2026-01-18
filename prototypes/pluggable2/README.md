# Pluggable2 Prototype (Separate Operation Binaries)

A KVM virtual machine monitor exploring **separate binary loading** for
operations. Unlike pluggable (which compiles all operations into one guest
binary), this prototype loads operations as separate ELF files at runtime.

## Motivation

In the pluggable prototype, all operations are compiled into a single guest
binary. While modular in code structure, this means:

1. **Full attack surface** - All operation code is present in guest memory,
   even if only one operation runs
2. **Vulnerability exposure** - A bug in a complex operation (e.g., qcow2
   parsing) is present even when doing a simple raw copy
3. **Larger binary** - Guest includes code for operations that won't be used

This prototype explores loading operations as separate binaries:

1. **Minimal attack surface** - Only the executing operation's code is loaded
2. **Defense in depth** - Vulnerabilities in unloaded operations can't be
   exploited
3. **Smaller footprint** - Load only what you need

## Architecture

### Memory Layout

```
Guest Physical Memory (32MB)
┌─────────────────────────────────────────────────────────────┐
│ 0x00001000  GDT (24 bytes)                                  │
│ 0x00002000  Page Tables (12KB)                              │
│ 0x00010000  Core Guest Binary                               │
│             - Entry point (_start)                          │
│             - Device initialization                         │
│             - Call table for operations                     │
│             - Serial communication                          │
│                                                             │
│ 0x00020000  Operation Binary (loaded by VMM)                │
│             - Operation entry point                         │
│             - Operation-specific logic                      │
│             - Calls back to core via call table             │
│                                                             │
│ 0x00100000  Input Virtqueue (64KB)                          │
│ 0x00110000  Output Virtqueue (64KB)                         │
│ 0x00200000  DMA Pool                                        │
│ 0x01000000  Stack (4MB, grows down)                         │
└─────────────────────────────────────────────────────────────┘
```

### Call Table Interface

The core provides a call table at a fixed address that operations use to
access shared functionality:

```rust
/// Call table provided by core at CALL_TABLE_ADDR (0x00018000)
#[repr(C)]
pub struct CallTable {
    /// Read a sector from the input device
    /// fn(sector: u64, buffer: *mut u8, buffer_len: usize) -> bool
    pub read_input_sector: unsafe extern "C" fn(u64, *mut u8, usize) -> bool,

    /// Write a sector to the output device
    /// fn(sector: u64, buffer: *const u8, buffer_len: usize) -> bool
    pub write_output_sector: unsafe extern "C" fn(u64, *const u8, usize) -> bool,

    /// Get input device capacity in sectors
    pub get_input_capacity: unsafe extern "C" fn() -> u64,

    /// Get output device capacity in sectors
    pub get_output_capacity: unsafe extern "C" fn() -> u64,

    /// Get input sector size in bytes
    pub get_input_sector_size: unsafe extern "C" fn() -> usize,

    /// Get output sector size in bytes
    pub get_output_sector_size: unsafe extern "C" fn() -> usize,

    /// Send progress update
    /// fn(operation: *const u8, current: u64, total: u64, percent: u32)
    pub send_progress: unsafe extern "C" fn(*const u8, u64, u64, u32),

    /// Send error message
    /// fn(operation: *const u8, device: *const u8, sector: u64, status: u32)
    pub send_error: unsafe extern "C" fn(*const u8, *const u8, u64, u32),

    /// Send completion message
    /// fn(operation: *const u8, bytes: u64, success: bool)
    pub send_complete: unsafe extern "C" fn(*const u8, u64, bool),

    /// Debug print (null-terminated string)
    pub debug_print: unsafe extern "C" fn(*const u8),
}
```

### Operation Entry Point

Operations are compiled as separate binaries with a standard entry point:

```rust
/// Operation entry point signature
/// Called by core after devices are initialized
/// Returns: bytes processed (0 on error)
pub type OperationEntry = unsafe extern "C" fn() -> u64;

// Operation binary is loaded at OPERATION_LOAD_ADDR (0x00020000)
// Entry point must be at offset 0 of the binary
```

### Execution Flow

```
VMM                           Core Guest                    Operation
 │                                │                              │
 │  1. Load core.bin at 0x10000   │                              │
 │  2. Load copy.bin at 0x20000   │                              │
 │  3. Start vCPU                 │                              │
 │                                │                              │
 │                           _start()                            │
 │                                │                              │
 │                           Initialize devices                  │
 │                                │                              │
 │                           Set up call table                   │
 │                                │                              │
 │                           Jump to 0x20000 ──────────────────► │
 │                                │                         entry()
 │                                │                              │
 │                                │ ◄── read_input_sector() ─────│
 │                                │                              │
 │                                │ ◄── write_output_sector() ───│
 │                                │                              │
 │                                │ ◄── send_progress() ─────────│
 │                                │                              │
 │                                │ ◄── send_complete() ─────────│
 │                                │                              │
 │                           ◄─── return ────────────────────────│
 │                                │                              │
 │                           HLT (shutdown)                      │
 │                                │                              │
```

## Building

### Directory Structure

```
pluggable2/
├── core/                 # Core guest (device init, call table)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── operations/           # Separate operation binaries
│   ├── copy/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs
│   └── info/             # Future: info operation
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
├── shared/               # Shared types (call table definition)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
└── vmm/                  # VMM (loads core + operation)
```

### Build Process

```bash
./build.sh

# Produces:
#   core.bin      - Core guest binary (loaded at 0x10000)
#   copy.bin      - Copy operation (loaded at 0x20000)
```

Or from the project root:

```bash
make build PROTOTYPE=pluggable2
```

### Running

```bash
# Create a test file
dd if=/dev/urandom of=test.bin bs=4096 count=1000

# Run with copy operation
sudo ./target/release/vmm --core core.bin --operation copy.bin \
     --input test.bin --output out.bin

# Verify copy succeeded
sha256sum test.bin out.bin
```

### CLI Options

```
Usage: vmm [OPTIONS] --input <INPUT> --output <OUTPUT> --core <CORE> --operation <OPERATION>

Options:
  -i, --input <INPUT>              Input file (source for copy)
  -o, --output <OUTPUT>            Output file (destination for copy)
      --input-sector-size <SIZE>   Sector size for input device [default: 65536]
      --output-sector-size <SIZE>  Sector size for output device [default: 65536]
      --max-output-size <BYTES>    Maximum output file size in bytes [default: input size]
      --preallocate-output         Pre-allocate output file instead of sparse
      --progress-percent <PERCENT> Progress update interval [default: 10]
      --no-ioeventfd               Disable ioeventfd optimization
      --core <CORE>                Core guest binary (device init, call table)
      --operation <OPERATION>      Operation binary to load (e.g., copy.bin)
  -h, --help                       Print help
```

## Security Benefits

### Attack Surface Reduction

| Scenario | pluggable | pluggable2 |
|----------|-----------|------------|
| Running copy operation | All operation code loaded | Only copy code loaded |
| Vulnerability in info parser | Exploitable | Not present in memory |
| Buffer overflow in transcode | Exploitable | Not present in memory |

### Defense in Depth

Even if an attacker can:
1. Craft a malicious input file
2. Trigger a vulnerability in a specific operation

They cannot exploit vulnerabilities in operations that aren't loaded.

## Trade-offs

### Pros
- Minimal attack surface per operation
- Clear separation of concerns
- Operations can be updated independently
- Smaller per-operation memory footprint

### Cons
- More complex build system (multiple binaries)
- Fixed ABI between core and operations (harder to evolve)
- Slightly more complex VMM (loads two binaries)
- C-style ABI required for cross-binary calls

## Implementation Status

- [x] Restructure guest into core + operations
- [x] Define and implement call table ABI
- [x] Update VMM to load operation binary
- [x] Port copy operation to separate binary
- [x] Add --operation CLI flag to VMM
- [x] Update build system for multiple binaries
- [ ] Add info operation (future)
- [ ] Add transcode operation (future)

## Related

- [pluggable](../pluggable/) - Single-binary modular operations
- [virtio-block6](../virtio-block6/) - Base functionality
