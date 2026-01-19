# Info Prototype (Image Format Detection)

A KVM virtual machine monitor for **safe image format detection**, based on
the pluggable2 architecture. This prototype implements the equivalent of
`qemu-img info` within a KVM sandbox.

## Motivation

Image format auto-detection in `qemu-img` is considered unsafe because it
exposes format-specific parsing code to potentially malicious inputs. However,
imago's KVM sandbox architecture mitigates these risks by containing any
parsing vulnerabilities within an isolated guest environment.

See [docs/format-detection-safety.md](../../docs/format-detection-safety.md)
for our detailed security analysis.

## Features

- **Format detection** via magic number recognition
- **Header parsing** for format-specific metadata (virtual size, cluster size, etc.)
- **Feature flag reporting** (backing files, encryption, compression, dirty state)
- **Protobuf-based results** sent via serial command channel
- **Separate binary loading** - only the info operation code is loaded

## Supported Formats

| Format | Magic Detection | Header Parsing |
|--------|-----------------|----------------|
| QCOW2  | Yes | Version, virtual size, cluster size, features, flags |
| QCOW1  | Yes | Basic detection |
| VMDK4  | Yes | Version, capacity, grain size |
| VMDK3  | Yes | Basic detection |
| VHDX   | Yes | Basic detection |
| VHD    | No (footer at EOF) | Not supported |
| Raw    | Fallback | Virtual size = actual size |

## Architecture

This prototype extends pluggable2 with:

1. **New info operation** (`operations/info/`) - Detects format and parses headers
2. **InfoResultMessage** - Protobuf message for structured results
3. **Extended CallTable** - Includes `send_info_result()` function

### Call Table Extensions

The call table (version 3) adds:

```rust
/// Send info result message.
pub send_info_result: unsafe extern "C" fn(
    *const u8, // format (C string)
    u32,       // version
    u64,       // virtual_size
    u64,       // actual_size
    u32,       // cluster_size
    u32,       // flags (bitfield)
    *const u8, // backing_file (C string)
    *const u8, // external_data_file (C string)
),
```

### Result Flags

```rust
const FLAG_HAS_BACKING_FILE: u32   = 1 << 0;
const FLAG_HAS_EXTERNAL_DATA: u32  = 1 << 1;
const FLAG_ENCRYPTED: u32          = 1 << 2;
const FLAG_COMPRESSED: u32         = 1 << 3;
const FLAG_HAS_SNAPSHOTS: u32      = 1 << 4;
const FLAG_DIRTY: u32              = 1 << 5;
const FLAG_CORRUPT: u32            = 1 << 6;
```

## Building

```bash
# Build from project root
make build PROTOTYPE=info

# Or build directly in prototype directory
cd prototypes/info
./build.sh

# Produces (all in target/release/):
#   imago    - Safe, sandboxed disk image operations
#   core.bin - Core guest binary
#   info.bin - Info operation binary
#   copy.bin - Copy operation binary
```

## Running

```bash
# Detect format of a disk image
sudo ./target/release/imago info test.qcow2

# With custom sector size
sudo ./target/release/imago info --sector-size 4096 test.qcow2

# Copy a disk image
sudo ./target/release/imago copy input.qcow2 output.raw

# Copy with progress reporting every 5%
sudo ./target/release/imago copy --progress-percent 5 input.qcow2 output.raw

# View help
./target/release/imago --help
./target/release/imago info --help
./target/release/imago copy --help

# Example info output:
# Loaded core binary: 2048 bytes from /path/to/target/release/core.bin
# Loaded operation binary: 4096 bytes from /path/to/target/release/info.bin
# Input file: test.qcow2 (196608 bytes, 3 sectors @ 65536 bytes/sector)
# ...
# [DEBUG] info: detected format
# [INFO] info_result format=qcow2 version=3 virtual_size=10737418240 actual_size=196608 cluster_size=65536 flags=0x0
# [COMPLETE] complete op=info count=65536 success=true
```

## Command Line Interface

The `imago` binary uses a qemu-img-compatible subcommand structure:

```
imago info <INPUT>              Detect image format and display information
imago copy <INPUT> <OUTPUT>     Copy/convert disk images
```

### Info Subcommand Options

```
USAGE:
    imago info [OPTIONS] <INPUT>

ARGUMENTS:
    <INPUT>    Input image file

OPTIONS:
    --sector-size <SIZE>    Sector size for reading input (default: 65536)
    -h, --help              Print help information
```

### Copy Subcommand Options

```
USAGE:
    imago copy [OPTIONS] <INPUT> <OUTPUT>

ARGUMENTS:
    <INPUT>     Input image file
    <OUTPUT>    Output image file

OPTIONS:
    --input-sector-size <SIZE>     Sector size for input (default: 65536)
    --output-sector-size <SIZE>    Sector size for output (default: 65536)
    --max-output-size <SIZE>       Maximum output file size in bytes
    --preallocate-output           Pre-allocate output instead of sparse
    --progress-percent <N>         Progress interval (1-99=%, 0=every 10 sectors, 100=none)
    --verify                       Verify data after copy
    --skip-zeros                   Skip writing zero sectors (sparse copy)
    --start-sector <N>             Starting sector (default: 0)
    --sector-count <N>             Number of sectors to copy (default: 0 = all)
    -h, --help                     Print help information
```

## Protocol Messages

### InfoResultMessage (Guest -> VMM)

```protobuf
message InfoResultMessage {
  string format = 1;           // "qcow2", "raw", "vmdk", etc.
  uint32 version = 2;          // Format version (e.g., 2 or 3 for QCOW2)
  uint64 virtual_size = 3;     // Virtual disk size in bytes
  uint64 actual_size = 4;      // Actual file size in bytes
  uint32 cluster_size = 5;     // Cluster/grain size in bytes
  uint32 flags = 6;            // Feature flags bitfield
  string backing_file = 7;     // Backing file path (if present)
  string external_data_file = 8; // External data file (QCOW2 v3)
}
```

## Security Benefits

1. **Format parsers run in sandbox** - Any vulnerability in QCOW2/VMDK parsing
   is contained within the KVM guest
2. **Minimal attack surface** - Only the info operation code is loaded
3. **No host file access** - Guest cannot access arbitrary host paths even if
   backing file paths are malicious

## Implementation Status

- [x] Magic number detection for QCOW2, QCOW1, VMDK4, VMDK3, VHDX
- [x] QCOW2 header parsing (version, size, cluster bits, features)
- [x] VMDK4 header parsing (version, capacity, grain size)
- [x] InfoResultMessage protobuf encoding
- [x] Call table extension for send_info_result
- [x] VMM handling of InfoResultMessage
- [ ] VHD detection (requires reading file footer)
- [ ] Backing file path extraction from headers
- [ ] External data file path extraction (QCOW2 v3)

## Related

- [pluggable2](../pluggable2/) - Base architecture (separate binary loading)
- [docs/format-detection-safety.md](../../docs/format-detection-safety.md) - Security analysis
- [guest-protocol](../../crates/guest-protocol/) - Protobuf messaging crate
