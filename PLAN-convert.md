# Plan: Implementing `imago convert` (and Prerequisites)

## Status: Phase 22 Complete

**Completed:**
- Phase -1: Configuration file support
- Phase 0a: Chain discovery using sandboxed info operation
- Phase 0b: Security validation for backing file paths
- Phase 0c: Multi-device VMM support (N input devices)
- Phase 0d: Device-indexed call table functions for backing chain I/O
- Phase 0e: Chain configuration passing to guest
- Phase 1a: `imago check` QCOW2 structural validation
  - Full L2 table validation (all sectors, not just first)
  - Overlap detection via bitmap in scratch memory
  - Refcount validation (referenced clusters must have refcount > 0)
  - Leak detection (clusters with refcount > 0 but no L2 reference)
  - Scratch memory region (0x300000-0x1000000, ~13MB) for bitmaps
  - Format detection and validation for non-QCOW2 formats
  - Dirty/corrupt flag detection and JSON reporting
  - Hardened arithmetic (checked/saturating ops, DoS prevention)
  - Corrupt test images and integration tests
- Phase 1b: Backing chain validation in `imago check --chain`
- Phase 2a: `imago compare` raw-vs-raw comparison
  - Full pipeline: CLI -> VMM -> KVM guest -> protobuf result -> output
  - CompareResultMessage protobuf, CompareConfig/CompareResult in shared
  - Guest binary: sector-by-sector comparison with size mismatch handling
  - Human and JSON output modes
  - Strict mode (-s): fail on any size difference
  - Output is byte-for-byte identical with `qemu-img compare`
  - 15 integration tests with qemu-img cross-validation
  - CallTable VERSION bumped to 12

- Phase 2b: `imago compare` QCOW2 support - L1/L2 reader, zlib
  decompression
- Phase 2c: `imago compare` backing chain resolution - Flatten backing
  chains before comparison so images with backing files compare correctly.
  Both images' chains are discovered via `discover_backing_chain()`, all
  chain images are loaded as separate virtio-block devices, and a
  chain-walking read resolves unallocated clusters through backing images.
  38 compare tests (30 existing + 8 backing chain) all passing.

- Phase 2d: Extract per-format shared crates and migrate all
  operations. Created three `no_std` crates under `src/crates/`:
  - `qcow2/` - Header parsing (`QcowHeader::parse()`), L1/L2
    cluster lookup (`Qcow2State`, `ClusterLookup`), compressed
    cluster decompression (behind `decompress` feature flag),
    refcount table reading, backing file path extraction, header
    extension parsing. ~920 lines canonical implementation.
  - `raw/` - MBR/GPT partition table detection
    (`detect_partition_table()`).
  - `vmdk/` - VMDK4 binary header parsing (`Vmdk4Header::parse()`),
    descriptor I/O and text parsing (`read_and_parse_descriptor()`).

  Migrated all three operations:
  - **compare**: Replaced ~420 lines of duplicated QCOW2 code with
    `qcow2::` crate calls. Uses `qcow2 = { features = ["decompress"] }`.
  - **check**: Replaced header parsing, constants, cached read
    helpers, and refcount lookup (~150 lines) with `qcow2::` crate.
    Preserved check-specific refcount_order validation.
  - **info**: Replaced QCOW2 header parsing (~270→55 lines), VMDK
    parsing (~90→15 lines), and MBR/GPT detection with shared crate
    calls.

  Also fixed two pre-existing bugs found during migration:
  - **actual_size padding**: Non-QCOW2 formats incorrectly reported
    padded device capacity as file length (affected profiles with
    sector sizes > 512).
  - **Version parsing**: `Version::parse()` accepted 4+ part
    version strings like "1.2.3.4" (now rejects them).

  All 596 tests pass. Pre-commit clean. Binary sizes within limits.
- Phase 3: `imago convert` qcow2→raw with backing chain flattening
  - ConvertConfig in shared crate, vmm_config_chain_with_output() in
    guest-protocol
  - Convert guest binary: reads virtual content via chain-walking
    QCOW2 reader, writes to raw output device
  - Refactored shared utilities: read_raw_sectors(),
    read_chain_virtual_cluster() moved to qcow2 crate;
    is_all_zeros(), should_report_progress(), l1/l2_cache_addr()
    moved to shared crate
  - Fixed compressed buffer sizing: COMPRESSED_BUF_SIZE = 2 *
    MAX_SECTOR_SIZE to handle compressed data straddling sector
    boundaries (affects both compare and convert)
  - Fixed output device MMIO placement for chain operations
  - 19 integration tests (14 pass, 5 skip for cluster_size/space)
  - All 615+ tests pass. Pre-commit clean.
- Phase 4: `imago convert` QCOW2 output - Write valid QCOW2 v3
  output from any supported input (raw, qcow2, qcow2 with backing
  chains). Linear cluster allocation with OFLAG_COPIED, 16-bit
  refcounts, iterative convergence for refcount metadata sizing.
  See PLAN-convert-phase4.md for details.
  - ConvertConfig extended with output_cluster_bits and target_format
  - QCOW2 write helpers (write_be_u16/u32/u64) and construction
    constants added to qcow2 crate
  - VMM: --cluster-size flag, -O qcow2 support, sparse output file
  - Guest binary: convert_to_qcow2() with L2-on-demand allocation,
    data cluster writing, refcount table/block generation, header
  - 30+ new integration tests (raw-to-qcow2, round-trip, backing
    chain, cross-validation with qemu-img check, manifest-driven
    raw and qcow2 re-encoding tests)
- Phase 5: Compressed QCOW2 output (`-c` flag) - Zlib (raw deflate)
  compression for QCOW2 output, equivalent to `qemu-img convert -c`.
  See PLAN-convert-phase5.md for details.
  - FLAG_COMPRESS in shared crate, `-c`/`--compress` CLI flag in VMM
  - qcow2 crate: `compress` feature with `compress_cluster_zlib()`
    (raw deflate via miniz_oxide) and `encode_compressed_l2_entry()`
  - Guest binary: `convert_to_qcow2_compressed()` with sector-aligned
    compressed data packing, fallback to uncompressed for incompressible
    clusters, per-cluster refcount tracking via u16 array
  - Bare-metal bump allocator for miniz_oxide's internal alloc usage
  - 29 new integration tests (8 basic compressed output tests including
    cross-validation with qemu-img, 11 manifest-driven raw-to-compressed,
    10 manifest-driven qcow2-to-compressed re-encoding)
- Phase 6: QCOW2 v3 compatibility - Three improvements for handling
  real-world QCOW2 v3 images. See PLAN-convert-phase6.md for details.
  - Reject unsupported incompatible feature bits: SUPPORTED_INCOMPAT
    _FEATURES mask with cfg-gated expansion per feature. Operations
    reject images with unknown bits per the QCOW2 spec.
  - ZSTD decompression: `ruzstd` crate (pure Rust, no_std+alloc)
    with StreamingDecoder for QCOW2 compression_type=1. Enabled via
    `decompress-zstd` feature in compare and convert. Compare gains
    a bump allocator (256KB heap) for ruzstd's internal allocations.
  - Extended L2 entries: 16-byte L2 entries with 32-subcluster
    bitmaps. cluster_lookup() and check's L2 iteration use correct
    entry stride. Subcluster bitmap ignored (conservative but
    correct). SUPPORTED_INCOMPAT_FEATURES includes bit 4.
  - 12 new integration tests (feature bit rejection, ZSTD check/
    info/convert/compare, extended L2 check/info/convert/compare)
  - Binary sizes: compare 96KB, convert 129KB (within 384KB limit)
- Phase 7: Check correctness and cluster size support - Three fixes
  for real-world image handling. See PLAN-convert-phase7.md for details.
  - All QCOW2 refcount widths (1/2/4/8/16/32/64-bit) supported in
    check's refcount validation and leak detection. Sub-byte widths
    use QEMU-compatible little-endian bit ordering within bytes.
  - Compressed cluster host ranges tracked in overlap bitmap,
    eliminating false leak reports. AlreadySet ignored for compressed
    entries (sub-cluster packing is normal).
  - Cluster sizes up to 2MB supported via MAX_CLUSTER_SIZE constant.
    Standard clusters read in MAX_SECTOR_SIZE (64KB) chunks using
    intra-cluster offset calculation. Compressed clusters > 64KB
    unsupported for convert/compare (decompression buffer limit).
  - 15 new integration tests across check and convert operations.
- Phase 8: VMDK input/output (monolithicSparse, streamOptimized,
  compressed grains). See PLAN-convert-phases.md.
- Phase 9: VHD input/output (dynamic, fixed, differencing). See
  PLAN-convert-phases.md.
- Phase 10: VHDX input/output (full support with CRC-32C,
  skip-zeros optimization). See PLAN-convert-phases.md.
- Phase 11: oslo.utils format_inspector cross-validation testing.
- Phase 12: LUKS container inspection (v1/v2, inner format
  detection).
- Phase 13: QCOW2 external data file support.
- Phase 14: Byte-order consolidation & VHD integration tests.
- Phase 15: Test coverage gaps & minor optimizations.
- Phase 16: Compressed clusters >64KB, QCOW2 encryption,
  snapshots.
- Phase 17: LUKS v2 Argon2id, native LUKS containers,
  LUKS-wrapping-QCOW2.
- Phase 18: LUKS crate extraction & enhanced LUKS convert.
- Phase 19: Extended L2 subcluster support.
- Phase 21: Large cluster QCOW2 output (up to 2MB). Dynamic
  buffer layout via ScratchLayout struct, lifted VMM validation
  from 64KB to 2MB, 6 integration tests. Fixed three buffer
  aliasing bugs: VMDK GT marker overwrote GT entries via
  buf_multipurpose, VHD bitmap not re-initialized per block,
  VHD input read_offset_sectors buffer overflow corrupting
  device caches. All 7 previously-failing VMDK/VHD tests
  now pass.
- Phase 22: Enhanced VMDK/VHD/VHDX check validation. VMDK
  grain marker validation for compressed grains, redundant
  grain directory (RGD) consistency checking. VHD sector
  bitmap validation, CHS geometry cross-check, fragmentation
  measurement. VHDX dual region table validation with RT2
  fallback, dirty log entry scanning, fragmentation
  measurement. 19 new tests in TestCheckEnhancedValidation
  plus positive clean-image tests for all VMDK/VHD/VHDX
  test images.

**Known gaps (not yet scheduled):**

*Current limitations:*
- VMDK output grain size: Fixed at 64KB (128 sectors), not
  configurable. This is a VMDK format convention.
- VHD output block size: Fixed at 2MB, not configurable.
- VHDX output block size: Fixed at 32MB, not configurable.
- QCOW2 encrypted output: Decryption works (AES-128-CBC via
  --qcow2-password, LUKS via --luks-passphrase) but writing
  encrypted QCOW2 output is not supported.

*Check operation code quality:*
- Fragmentation tracking pattern (init, loop, compute) is
  duplicated across check_vmdk, check_vhdx, check_vhd, and
  check_qcow2. Could be extracted into a shared helper.
- Corruption recording pattern (result.corruptions += 1;
  result.total_errors += 1; debug_print) appears ~99 times.
  Could be a macro.

*Pre-existing check issues:*
- vmdk-v3 (iotest-version3.vmdk) reports 1 corruption during
  check. Root cause not yet investigated.
- vhd-d2v-zerofilled (d2v-zerofilled.vhd) reports 125 leaks.
  This is expected: the zerofilled disk2vhd image has cleared
  sector bitmap bits which bitmap validation correctly reports.

*Additional qemu-img subcommands (not yet implemented):*
- create: Create new disk images
- resize: Change virtual size of images
- snapshot: List/create/delete internal snapshots
- rebase: Change backing file references
- commit: Commit overlay changes to backing file
- map: Dump block allocation map
- measure: Pre-calculate space requirements for conversion

**`imago info --chain` command:**
- Iteratively runs sandboxed info operations to discover backing chain
- Validates backing file paths against security allowlist
- Enforces maximum chain depth (configurable, default 16)
- Detects circular references
- **Portable backing file resolution**: When an absolute backing path doesn't
  exist (e.g., image created on another machine), falls back to filename-only
  resolution relative to the parent image's directory. Security allowlist is
  always checked regardless of resolution strategy.

**Multi-device VMM infrastructure (Phase 0c):**
- `DeviceSet` struct manages N virtio-block devices with unified MMIO dispatch
- Dynamic MMIO address calculation: device N at 0x10000000 + N*0x1000
- Dynamic virtqueue address calculation: device N at 0x100000 + N*0x10000
- Maximum 16 devices per operation (MAX_CHAIN_DEPTH)
- All operations (info, copy, check) use DeviceSet for device management
- I/O thread integration for background queue processing

**Device-indexed call table (Phase 0d):**
- New CallTable functions for multi-device I/O (VERSION bumped to 7):
  - `get_input_device_count()`: Returns number of input devices available
  - `read_input_sector_from(idx, sector, buf, len)`: Read from device by index
  - `get_input_capacity_of(idx)`: Get capacity of specific device
  - `get_input_sector_size_of(idx)`: Get sector size of specific device
- Core guest binary updated with device array (max 16 devices)
- Legacy single-device functions delegate to indexed versions (index 0)

**Chain configuration passing (Phase 0e):**
- New `ChainConfig` and `ChainDeviceInfo` structures in shared crate
- `CHAIN_CONFIG_ADDR` (0x82000) for passing chain metadata to guest
- New call table function `get_chain_config()` (VERSION bumped to 9)
- VMM helper functions to convert `BackingChain` to guest-compatible
  `ChainConfig`
- Infrastructure ready for Phase 1+ operations (check, compare, convert)

**Phase 1a: `imago check` QCOW2 validation:**
- Full L2 table scan (all sectors, not just first 512 entries)
- Overlap detection via 1-bit-per-cluster bitmap in scratch memory
- Refcount validation: ensures referenced clusters have refcount > 0
- Leak detection: finds clusters with refcount > 0 but no L2 reference
- Bounds checking: L1 size, reftable entries, cluster_bits range
- Hardened against malicious inputs: checked arithmetic, DoS caps
- Compile-time memory layout asserts (DMA/scratch, scratch/stack gaps)
- Human-readable output (qemu-img compatible) and JSON output modes
- Non-QCOW2 formats: detects format, reports "not supported" gracefully

**Phase 1b: Backing chain validation in check:**
- `imago check --chain` discovers the full backing chain (reuses chain
  discovery from `imago info --chain`), loads each image as a separate
  virtio-block device, and validates:
  - Format consistency: backing image format matches chain discovery
  - Virtual size validity: backing images must have non-zero virtual size
  - QCOW2 header validation: magic, version, cluster_bits, L1/refcount
    table bounds, corrupt feature flag
- Chain errors reported separately as `chain-errors` in JSON output
- Backward compatible: without `--chain`, check behaves as before
- Security: chain discovery validates paths against the allowlist

**Test infrastructure:**
- `make test` runs all tests (Rust unit tests + Python integration)
- `make test-rust` runs Rust unit tests only
- `make test-integration` runs Python integration tests only
- 44 Rust unit tests (chain.rs path resolution, security, config,
  backing, ioevent, stats, kvm_stats, version, error)
- 692 Python integration tests across 8 test files:
  - test_info_safe.py: 516 manifest-driven tests (qemu-img baseline
    comparison)
  - test_compare.py: 45 compare tests (raw-vs-raw, QCOW2-vs-raw,
    QCOW2-vs-QCOW2, compressed, backing chains with qemu-img
    cross-validation)
  - test_convert.py: 81 convert tests (qcow2→raw, raw→qcow2,
    qcow2 re-encoding, compressed output with `-c` flag, backing
    chains, round-trip, raw passthrough, errors, manifest-driven
    raw-to-qcow2 and qcow2-to-qcow2 cross-validation against
    qemu-img, manifest-driven compressed output tests).
  - test_check_formats.py: 25 format detection, corruption,
    feature bit, ZSTD, and extended L2 tests
  - test_security.py: 10 path validation and allowlist tests
  - test_check_chain.py: 7 backing chain validation tests
  - test_version_detection.py: 4 qemu-img version compat tests
  - test_info_malicious.py: 1 malicious path rejection test
- All 692 tests passing as of Phase 6 completion (671 pass, 21 skip)
- 21 skipped tests:
  - 13 insufficient temp disk space: large Aurel32 images (10-25GB
    virtual size) need 20-50GB temp for raw cross-validation
    (test_convert 4, test_convert_to_qcow2_manifest 4,
    test_convert_compressed_manifest 5)
  - 6 unsupported cluster size: debian-12-sfagent has 2MB clusters
    and qcow2-min-cluster has 512-byte clusters, both exceed
    supported range (test_convert 2, test_convert_to_qcow2_manifest
    2, test_convert_compressed_manifest_qcow2 2)
  - 2 not yet implemented: security tests for QCOW2 external data
    file and VMDK descriptor handling (test_security 2)
  (Note: most of these skips were resolved in Phases 8-19. The
  above counts are from the Phase 7 snapshot.)

**Next Steps:**
- All convert phases (through Phase 22) are complete. Remaining
  work is additional qemu-img subcommands (create, resize, etc.),
  the security audit (PLAN-audit.md), and optional check code
  refactoring (fragmentation/corruption pattern deduplication).

## Executive Summary

Implement `imago convert` to enable format-aware disk image conversion
within the secure KVM sandbox. Before convert, we'll implement
`imago check` and `imago compare` to provide verification tools.
Testing will use both imago and qemu-img for validation.

## Implementation Order

1. **Phase -1: Configuration File Support** - Layered config: /etc/imago → ~/.config/imago → CLI
2. **Phase 0: Multi-device VMM & Chain Discovery** - Support N input devices, recursive backing file discovery
3. **Phase 1: `imago check`** - Validate image integrity (including backing chain validation)
4. **Phase 2: `imago compare`** - Compare two images for logical equivalence
5. **Phase 3: `imago convert` qcow2→raw** - With zlib decompression and backing chain flattening
6. **Phase 4: `imago convert` QCOW2 output** - Write valid qcow2 v3 output

## Background

### Imago Architecture

Imago uses a sandboxed architecture for security:
- **Host VMM** (`src/vmm/src/main.rs`): CLI, KVM setup, device emulation
- **KVM Guest**: Minimal x86-64 environment running operations
- **Operations**: `no_std` binaries loaded at 0x20000, communicate via call table
- **Call Table**: ABI at 0x18000 with I/O primitives

### Current Operations

1. **`info`**: Detects format via magic numbers, parses headers
2. **`copy`**: Raw sector-level copying with sector size translation
3. **`check`**: QCOW2 structural validation (L1/L2, refcounts, leaks, overlaps)
4. **`compare`**: Format-aware image comparison with backing chain resolution
5. **`convert`**: QCOW2→raw conversion with backing chain flattening

---

## Phase -1: Configuration File Support

**Goal**: Allow persistent configuration of imago options via config
files, reducing command-line verbosity for repeated operations.

### Configuration Hierarchy

Config files are read in order, with later values overriding earlier ones:

1. `/etc/imago/config` - System-wide defaults (set by admin)
2. `~/.config/imago/config` - User defaults
3. Command-line arguments - Per-invocation overrides

### Config File Format

Use TOML for readability and Rust ecosystem support:

```toml
# /etc/imago/config or ~/.config/imago/config

[global]
# Default output format for convert
output-format = "raw"

# Always ignore quirks mode
ignore-quirks = true

# QEMU version compatibility for info output
qemu-version = "8.0"

# Default output mode (human or json)
output = "human"

# Verbose logging
verbose = false

[security]
# Directories allowed for backing file resolution
# Special marker values:
#   $IMAGE_DIR - directory containing the input image
#   $CWD       - current working directory
# Default if not specified: ["$IMAGE_DIR"]
backing-path-allowlist = [
    "$IMAGE_DIR",                    # Keep the default behavior
    "/var/lib/libvirt/images",
    "/home/user/vm-images",
]

# To ONLY allow specific paths (excluding image directory):
# backing-path-allowlist = ["/var/lib/libvirt/images"]

# Maximum backing chain depth (default: 16)
max-chain-depth = 16

[convert]
# Default sparse handling
sparse = true

# Show progress during conversion
progress = true

[copy]
# Skip zero sectors by default
skip-zeros = true

# Verify after copy
verify = false
```

### Implementation

Use the `config` crate (or similar) for layered configuration:

```rust
use std::path::PathBuf;
use serde::Deserialize;

#[derive(Deserialize, Default)]
struct ImagoConfig {
    global: GlobalConfig,
    security: SecurityConfig,
    convert: ConvertConfig,
    copy: CopyConfig,
}

#[derive(Deserialize, Default)]
struct GlobalConfig {
    output_format: Option<String>,
    ignore_quirks: Option<bool>,
    qemu_version: Option<String>,
    output: Option<String>,
    verbose: Option<bool>,
}

#[derive(Deserialize, Default)]
struct SecurityConfig {
    backing_path_allowlist: Option<Vec<String>>,  // Strings to allow markers
    max_chain_depth: Option<u32>,
}

/// Expand marker values in allowlist
fn expand_allowlist(
    allowlist: &[String],
    image_path: &Path,
    cwd: &Path,
) -> Vec<PathBuf> {
    allowlist.iter().map(|entry| {
        match entry.as_str() {
            "$IMAGE_DIR" => image_path.parent().unwrap_or(cwd).to_path_buf(),
            "$CWD" => cwd.to_path_buf(),
            path => PathBuf::from(path),
        }
    }).collect()
}

/// Get effective allowlist (default: ["$IMAGE_DIR"])
fn get_backing_allowlist(
    config: &SecurityConfig,
    image_path: &Path,
) -> Vec<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let allowlist = config.backing_path_allowlist
        .as_ref()
        .map(|v| v.as_slice())
        .unwrap_or(&["$IMAGE_DIR".to_string()]);  // Default
    expand_allowlist(allowlist, image_path, &cwd)
}

fn load_config() -> ImagoConfig {
    let mut config = ImagoConfig::default();

    // Layer 1: System config
    if let Ok(sys) = std::fs::read_to_string("/etc/imago/config") {
        if let Ok(parsed) = toml::from_str(&sys) {
            config = merge_config(config, parsed);
        }
    }

    // Layer 2: User config
    if let Some(home) = dirs::home_dir() {
        let user_config = home.join(".config/imago/config");
        if let Ok(user) = std::fs::read_to_string(&user_config) {
            if let Ok(parsed) = toml::from_str(&user) {
                config = merge_config(config, parsed);
            }
        }
    }

    config
}
```

### CLI Integration with clap

Use clap's layered defaults:

```rust
use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[arg(long, env = "IMAGO_VERBOSE")]
    verbose: bool,

    // ... other args get defaults from config
}

fn main() {
    // Load config first
    let config = load_config();

    // Parse CLI with config as defaults
    let cli = Cli::parse();

    // CLI values override config values
    let verbose = cli.verbose || config.global.verbose.unwrap_or(false);
}
```

### Config Introspection Command

Add `imago config` subcommand to inspect effective configuration:

```bash
$ imago config
# Effective configuration (merged from all sources)

[global]
output-format = "raw"          # from: ~/.config/imago/config
ignore-quirks = true           # from: /etc/imago/config
qemu-version = "8.0"           # from: (default)
verbose = false                # from: (default)

[security]
backing-path-allowlist = [     # from: ~/.config/imago/config
    "/var/lib/libvirt/images",
    "/home/user/vm-images",
]

$ imago config --show-sources
# Shows which file each value came from

$ imago config --validate
# Validates all config files for syntax errors
```

### Phase -1 Deliverables

1. **Config loading** in VMM (`load_config()` function)
2. **Config merging** logic (later overrides earlier)
3. **TOML parsing** with serde
4. **CLI integration** - config provides defaults, CLI overrides
5. **`imago config`** subcommand for introspection
6. **Documentation** of all config options

### New Dependencies

Add to `src/vmm/Cargo.toml`:
```toml
[dependencies]
toml = "0.8"
dirs = "5.0"
```

### Testing Phase -1

```bash
# Create system config
sudo mkdir -p /etc/imago
sudo tee /etc/imago/config << 'EOF'
[global]
verbose = false

[security]
backing-path-allowlist = ["/var/lib/libvirt/images"]
EOF

# Create user config
mkdir -p ~/.config/imago
cat > ~/.config/imago/config << 'EOF'
[global]
verbose = true

[security]
backing-path-allowlist = ["/home/user/images", "/tmp/test"]
EOF

# Test effective config
imago config
# Should show verbose=true (user override) and combined allowlist

# Test CLI override
imago info --verbose=false test.qcow2
# Should use verbose=false despite config saying true
```

---

## Phase 0: Multi-Device VMM & Chain Discovery

**Goal**: Enable operations on images with backing file chains by:
1. Discovering and validating the complete backing chain
2. Supporting N input virtio-block devices in the VMM
3. Exposing chain information to guest operations

### The Backing File Problem

A qcow2 image can reference a backing file, which can reference another, forming a chain:
```
top.qcow2 → middle.qcow2 → base.qcow2 → base.raw
```

When reading cluster N from top.qcow2:
- If allocated in top.qcow2: return that data
- If unallocated: check middle.qcow2
- If unallocated: check base.qcow2
- If unallocated: check base.raw (or return zeros if raw)

**Current limitation**: VMM only supports 2 devices (input + output). We need N inputs.

### Phase 0a: Chain Discovery (Host-Side)

Before launching the KVM guest, the host must:

1. **Run `imago info`** on the top image to get backing file path
2. **Validate the backing file**:
   - Path is within allowed directories (security!)
   - File exists and is readable
   - Is a supported format
3. **Recursively discover** the full chain
4. **Build device list** for VMM

```rust
struct BackingChain {
    images: Vec<ChainImage>,  // Index 0 = top, last = base
}

struct ChainImage {
    path: PathBuf,
    format: ImageFormat,
    virtual_size: u64,
    backing_file: Option<String>,  // Raw path from header
}

fn discover_chain(top_image: &Path, allowed_paths: &[PathBuf]) -> Result<BackingChain> {
    let mut chain = Vec::new();
    let mut current = top_image.to_path_buf();

    loop {
        // Run imago info on current image
        let info = run_info(&current)?;

        // Validate path is allowed
        if !is_path_allowed(&current, allowed_paths) {
            return Err(Error::BackingFileNotAllowed(current));
        }

        chain.push(ChainImage {
            path: current.clone(),
            format: info.format,
            virtual_size: info.virtual_size,
            backing_file: info.backing_file.clone(),
        });

        // Follow backing file if present
        match &info.backing_file {
            Some(backing) => {
                current = resolve_backing_path(&current, backing)?;
            }
            None => break,  // End of chain
        }
    }

    Ok(BackingChain { images: chain })
}
```

### Phase 0b: Security Validation

Backing file paths are **untrusted data** from the image header. We must:

1. **Canonicalize paths** to prevent `../` escapes
2. **Check against allowlist** of directories
3. **Reject absolute paths** that escape allowed areas
4. **Handle relative paths** relative to parent image location

```rust
fn is_path_allowed(path: &Path, allowed: &[PathBuf]) -> bool {
    let canonical = path.canonicalize().ok()?;
    allowed.iter().any(|allowed_dir| canonical.starts_with(allowed_dir))
}
```

**Configuration**: Set via config file (`security.backing-path-allowlist`) or CLI (`--backing-path-allowlist`).

Special markers:
- `$IMAGE_DIR` - expands to directory containing the input image
- `$CWD` - expands to current working directory

Default if not specified: `["$IMAGE_DIR"]`

### Phase 0c: Multi-Device VMM Support

Extend VMM to support N input devices:

```rust
// Current: fixed 2 devices
const INPUT_MMIO_BASE: u64 = 0x10000000;
const OUTPUT_MMIO_BASE: u64 = 0x10001000;

// New: dynamic device array
struct VmmDevices {
    inputs: Vec<VirtioBlockDevice>,  // inputs[0] = top image, inputs[N-1] = base
    output: Option<VirtioBlockDevice>,
}

// MMIO regions: 0x10000000 + (device_index * 0x1000)
fn device_mmio_base(device_index: usize) -> u64 {
    0x10000000 + (device_index as u64 * 0x1000)
}
```

**Memory layout update**:
- Reserve MMIO space for up to 16 devices (reasonable chain limit)
- Each device gets its own virtqueue region

### Phase 0d: Call Table Extensions for Chain Access

Guest needs to know about the chain and read from specific devices:

```rust
// New call table functions
pub struct CallTable {
    // ... existing functions ...

    /// Get number of input devices (chain length)
    pub get_input_device_count: unsafe extern "C" fn() -> u32,

    /// Read sector from specific input device (0 = top, N-1 = base)
    pub read_input_sector_from: unsafe extern "C" fn(
        device_index: u32,
        sector: u64,
        buffer: *mut u8,
        len: usize
    ) -> bool,

    /// Get capacity of specific input device
    pub get_input_capacity_for: unsafe extern "C" fn(device_index: u32) -> u64,

    /// Get format of specific input device (passed via config)
    pub get_input_format: unsafe extern "C" fn(device_index: u32) -> u32,
}
```

### Phase 0e: Chain Configuration Passing

Pass chain metadata to guest via operation config:

```rust
#[repr(C)]
pub struct ChainConfig {
    pub device_count: u32,
    pub devices: [ChainDeviceInfo; 16],  // Max 16 devices
}

#[repr(C)]
pub struct ChainDeviceInfo {
    pub format: u32,        // ImageFormat
    pub virtual_size: u64,
    pub cluster_size: u32,  // 0 for raw
    pub flags: u32,         // compressed, encrypted, etc.
}
```

### Phase 0 Deliverables

1. **Chain discovery** in VMM (`discover_chain()` function)
2. **Path validation** with allowlist
3. **Multi-device VMM** supporting N inputs + 1 output
4. **Extended call table** with device-indexed I/O
5. **Chain config structure** for passing metadata to guest
6. **Updated `info` operation** to report backing file info (already done, but may need enhancement)

### Testing Phase 0

```bash
# Create a backing chain
qemu-img create -f raw base.raw 100M
qemu-img create -f qcow2 -b base.raw -F raw middle.qcow2 100M
qemu-img create -f qcow2 -b middle.qcow2 -F qcow2 top.qcow2 100M

# Test chain discovery
imago info --chain top.qcow2
# Should output:
# Chain: 3 images
#   [0] top.qcow2 (qcow2) -> middle.qcow2
#   [1] middle.qcow2 (qcow2) -> base.raw
#   [2] base.raw (raw)

# Test with disallowed backing path (should fail)
qemu-img create -f qcow2 -b /etc/passwd evil.qcow2 100M
imago info evil.qcow2
# ERROR: Backing file /etc/passwd is outside allowed paths
```

---

## Phase 1: `imago check`

**Goal**: Validate image structural integrity (equivalent to `qemu-img check`).

### What check Does

For qcow2 images:
1. Validate header magic and version
2. Verify L1/L2 table consistency
3. Check refcount table integrity
4. Detect cluster leaks (allocated but unreferenced)
5. Detect overlapping clusters
6. Verify backing file references (if present)
7. Check for corruption flags
8. **Validate backing chain** (uses Phase 0 discovery):
   - Each image in chain is valid
   - All backing files exist and are accessible
   - Virtual sizes are consistent through chain

For other formats:
- VMDK: Validate grain directory/tables
- VHD: Validate BAT and footer
- Raw: Always valid (no structure)

### check Output

Match qemu-img output format:
```
No errors were found on the image.
Image end offset: 262144
```

Or with errors:
```
ERROR cluster 5 refcount=0 reference=1
ERROR offset 0x50000 is referenced twice: as data block at offset 0x10000, as data block at offset 0x20000

2 errors were found on the image.
Data may be corrupted, or further writes may corrupt the image.
```

### New Files for check

```
src/operations/check/
├── Cargo.toml
├── src/
│   ├── main.rs           # Entry point
│   ├── qcow2_check.rs    # QCOW2 validation
│   ├── vmdk_check.rs     # VMDK validation (later)
│   └── vhd_check.rs      # VHD validation (later)
```

### Shared Crate Extensions for check

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CheckConfig {
    pub magic: u32,           // 0x43484543 = "CHEC"
    pub flags: u32,           // FLAG_REPAIR, FLAG_QUIET, etc.
}

impl CheckConfig {
    pub const MAGIC: u32 = 0x43484543;
    pub const FLAG_REPAIR: u32 = 1 << 0;      // Attempt repair (future)
    pub const FLAG_QUIET: u32 = 1 << 1;       // Suppress output
}
```

### Call Table Extensions for check

Need to send check results back to host:
```rust
pub send_check_result: unsafe extern "C" fn(
    errors: u32,              // Number of errors found
    leaks: u32,               // Number of cluster leaks
    corruptions: u32,         // Number of corruptions
    end_offset: u64,          // Image end offset
),

pub send_check_error: unsafe extern "C" fn(
    error_type: u32,          // Type of error
    cluster: u64,             // Affected cluster
    message: *const u8,       // Error message
),
```

### VMM Changes for check

```rust
#[derive(Subcommand, Debug)]
enum Commands {
    Info(InfoArgs),
    Copy(CopyArgs),
    Check(CheckArgs),  // NEW
}

#[derive(Args, Debug)]
struct CheckArgs {
    input: String,
    #[arg(short, long)]
    quiet: bool,
    #[arg(long, default_value = "human")]
    output: String,  // "human" or "json"
}
```

### Testing check

```bash
# Test with imago
imago check test.qcow2

# Cross-validate with qemu-img
qemu-img check test.qcow2

# Compare outputs (both should report same errors)
```

---

## Phase 2: `imago compare`

**Goal**: Compare two images for logical data equivalence (like `qemu-img compare`).

### What compare Does

1. Read both images sector by sector (or cluster by cluster)
2. Compare data content at each virtual offset
3. Handle sparse regions (both zero = match)
4. Report first difference found (if any)
5. Exit codes: 0=identical, 1=different, 2+=error

### Key Insight

**compare needs format-aware reading** - this is effectively the "read" half of convert:
- Must understand qcow2 L1/L2 tables to read clusters
- Must handle unallocated regions by reading from backing chain (Phase 0)
- Must decompress compressed clusters
- Must resolve the complete backing chain to get final data

This means compare will build the infrastructure convert needs.

### Backing Chain Resolution in compare

When comparing two images that have backing files:
1. Use Phase 0 chain discovery to enumerate both chains
2. Attach all devices from both chains to the guest
3. When reading unallocated cluster, walk the chain to find data
4. Two clusters are "equal" if they resolve to the same data (even if sparse representation differs)

### compare Output

Match qemu-img output:
```
Images are identical.
```
Or:
```
Content mismatch at offset 1048576!
```

### New Files for compare

```
src/operations/compare/
├── Cargo.toml
├── src/
│   ├── main.rs           # Entry point
│   ├── qcow2_reader.rs   # QCOW2 cluster reading (reused in convert)
│   ├── raw_reader.rs     # Raw sector reading
│   └── zlib.rs           # Zlib decompression (minimal no_std impl)
```

### Architecture: Multi-Device Support (from Phase 0)

Phase 0 provides multi-device VMM support, which compare uses:
- Image 1's chain: devices 0..N-1
- Image 2's chain: devices N..M-1
- Guest receives config telling it which device ranges belong to which image

This enables comparing two images that each have their own backing chains.

### Shared Crate Extensions for compare

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompareConfig {
    pub magic: u32,           // 0x434D5052 = "CMPR"
    pub flags: u32,
    pub max_errors: u32,      // Stop after N errors (0 = stop at first)
}

impl CompareConfig {
    pub const MAGIC: u32 = 0x434D5052;
    pub const FLAG_STRICT: u32 = 1 << 0;  // Fail on different sparse representation
    pub const FLAG_QUIET: u32 = 1 << 1;
}
```

### QCOW2 Reader Module

This is the core module that both compare and convert will use:

```rust
// src/operations/compare/src/qcow2_reader.rs

pub struct Qcow2Reader {
    cluster_bits: u32,
    cluster_size: u32,
    l1_table_offset: u64,
    l1_size: u32,
    // Small L2 cache (4-8 entries given 32MB guest memory)
    l2_cache: [L2CacheEntry; 8],
}

impl Qcow2Reader {
    /// Read virtual cluster, handling L1/L2 lookup and decompression
    pub fn read_cluster(&mut self, virtual_cluster: u64, buffer: &mut [u8]) -> ClusterStatus {
        // 1. Calculate L1/L2 indices
        // 2. Read L1 entry (may be cached)
        // 3. Read L2 entry (with caching)
        // 4. Handle: unallocated, standard, compressed
        // 5. Return data in buffer
    }
}

pub enum ClusterStatus {
    Data,           // Buffer contains actual data
    Zero,           // Cluster is unallocated (all zeros)
    Error(u32),     // Read error
}
```

### Zlib Decompression

Need minimal zlib for compressed clusters. Options:

1. **Port miniz** (public domain, ~4KB compiled)
2. **Use inflate-only implementation** (smaller)
3. **Custom minimal decoder** (smallest but more work)

Recommend miniz port - well-tested, small enough for guest.

### VMM Changes for compare

```rust
#[derive(Args, Debug)]
struct CompareArgs {
    image1: String,
    image2: String,
    #[arg(short, long)]
    strict: bool,
    #[arg(short, long)]
    quiet: bool,
}
```

### Testing compare

```bash
# Create test images
qemu-img create -f qcow2 a.qcow2 100M
qemu-img create -f raw b.raw 100M

# Write known pattern
qemu-io -c 'write -P 0x42 0 1M' a.qcow2
qemu-io -c 'write -P 0x42 0 1M' b.raw

# Compare with imago
imago compare a.qcow2 b.raw

# Cross-validate with qemu-img
qemu-img compare a.qcow2 b.raw

# Both should return 0 (identical)
```

---

## Phase 3: `imago convert` qcow2→raw

**Goal**: Convert qcow2 to raw format, leveraging the QCOW2 reader from compare.

### What Phase 3 Adds

Most of the work is done in Phases 0-2. Phase 3 adds:
1. New convert operation
2. Raw writer (trivial - sequential sector writes)
3. Progress reporting during conversion
4. **Backing chain flattening**: Resolves entire chain into single flat raw image

### Backing Chain Flattening

When converting qcow2→raw with backing files:
```
top.qcow2 → middle.qcow2 → base.raw  ===>  output.raw
```

For each virtual cluster:
1. Check if allocated in top.qcow2 → use that data
2. Else check middle.qcow2 → use that data
3. Else check base.raw → use that data
4. Else output zeros

The output.raw contains the fully resolved data with no external dependencies.

### New Files for convert

```
src/operations/convert/
├── Cargo.toml
├── src/
│   ├── main.rs           # Entry point, format dispatch
│   ├── qcow2_reader.rs   # Symlink or copy from compare (or shared lib)
│   ├── raw_writer.rs     # Sequential sector writes
│   └── zlib.rs           # Symlink or copy from compare
```

**Note**: Consider moving qcow2_reader.rs and zlib.rs to the shared crate to avoid duplication.

### Shared Crate Extensions for convert

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConvertConfig {
    pub magic: u32,           // 0x434F4E56 = "CONV"
    pub flags: u32,
    pub target_format: u32,   // ImageFormat as u32
    pub source_format: u32,   // 0 = auto-detect
    pub output_cluster_size: u32,  // For qcow2 output (Phase 4)
    pub _reserved: u32,
}

impl ConvertConfig {
    pub const MAGIC: u32 = 0x434F4E56;
    pub const FLAG_SPARSE: u32 = 1 << 0;      // Skip zero regions
    pub const FLAG_PROGRESS: u32 = 1 << 1;    // Report progress
}
```

### VMM Changes for convert

```rust
#[derive(Args, Debug)]
struct ConvertArgs {
    input: String,
    output: String,
    #[arg(short = 'O', long, default_value = "raw")]
    output_format: String,
    #[arg(long)]
    sparse: bool,
    #[arg(short, long)]
    progress: bool,
}
```

### Phase 3 Limitations

- Output format: raw only
- **Backing files**: Supported via Phase 0 chain discovery and flattening
- No encryption support (error if encrypted)
- Snapshots: converts active image only (snapshots ignored)

---

## Phase 4: `imago convert` QCOW2 output

**Goal**: Write valid QCOW2 v3 output from any supported input.

### QCOW2 Writer

Must generate valid qcow2 structure:
1. **Header** (104-112 bytes)
2. **Refcount table** and **refcount blocks**
3. **L1 table** and **L2 tables**
4. **Data clusters**

### Allocation Strategy

Two-pass approach for simplicity:
1. **First pass**: Calculate required metadata size based on input size
2. **Second pass**: Write header, tables, then stream data

Sequential layout:
```
Cluster 0:      Header
Cluster 1-N:    Refcount table
Cluster N+1-M:  Refcount blocks
Cluster M+1:    L1 table
Cluster M+2+:   L2 tables (allocated as data is written)
Cluster ...:    Data clusters
```

### Sparse Handling

1. Read raw input in cluster-sized chunks
2. Check if chunk is all zeros
3. If zero: Leave L2 entry as 0 (unallocated)
4. If data: Allocate cluster, update L2, update refcount, write data

---

## Files Summary

### New Operations

| Phase | Operation | Files |
|-------|-----------|-------|
| 1 | check | `src/operations/check/` |
| 2 | compare | `src/operations/compare/` (includes qcow2_reader, zlib) |
| 3-4 | convert | `src/operations/convert/` |

### Shared Crate Additions

- `CheckConfig` struct
- `CompareConfig` struct
- `ConvertConfig` struct
- New call table functions for check/compare results
- Consider moving format readers to shared crate

### VMM Additions

- **Config system** (`config.rs`): Load and merge config files
- `Config` command for config introspection
- `Check` command and `run_check()` function
- `Compare` command and `run_compare()` function
- `Convert` command and `run_convert()` function

### Build Changes

- Add all three operations to `build.sh`
- Update `Cargo.toml` workspace members

---

## Testing Strategy

### Cross-Validation Approach

Every test runs both imago and qemu-img, comparing results:

```python
def test_check_valid_qcow2(self):
    # Run imago check
    imago_rc, imago_out = run_imago('check', image_path)

    # Run qemu-img check
    qemu_rc, qemu_out = run_qemu_img('check', image_path)

    # Both should succeed
    self.assertEqual(0, imago_rc)
    self.assertEqual(0, qemu_rc)

    # Compare error counts (may differ in wording)
    self.assertEqual(
        parse_error_count(imago_out),
        parse_error_count(qemu_out)
    )

def test_compare_identical(self):
    # Both tools should return 0 for identical images
    imago_rc = run_imago('compare', img1, img2)
    qemu_rc = run_qemu_img('compare', img1, img2)
    self.assertEqual(imago_rc, qemu_rc)
```

### Test Cases by Phase

**Phase 1 (check)**:
- Valid qcow2 (no errors)
- Corrupt qcow2 (missing L2 table)
- Qcow2 with refcount inconsistency
- Qcow2 with overlapping clusters
- Raw image (always valid)
- VMDK validation

**Phase 2 (compare)**:
- Two identical qcow2 images
- qcow2 vs raw with same content
- Images with sparse regions
- Images with compressed clusters
- First byte differs
- Last byte differs
- Sparse vs explicit zeros

**Phase 3-4 (convert)**:
- qcow2→raw basic
- qcow2→raw with sparse regions
- qcow2→raw with compression
- raw→qcow2 basic
- raw→qcow2 with sparse detection
- Round-trip: qcow2→raw→qcow2→raw (compare first and last)

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Config file parsing errors | Graceful fallback to defaults; `imago config --validate` |
| Conflicting config values | Clear precedence: CLI > user > system; show sources |
| Guest memory limits (32MB) | Stream data, small L2 cache, careful allocation |
| Zlib in no_std | Use miniz (public domain, well-tested) |
| Backing chain complexity | Phase 0 handles discovery/validation before guest launch |
| Backing file path traversal | Strict path allowlist, canonicalization |
| Many devices (long chains) | Limit to 16 devices; error on longer chains |
| QCOW2 writer correctness | Extensive qemu-img check validation |
| Compressed cluster edge cases | Test with real-world compressed images |

---

## Appendix: QCOW2 Structure Reference

### Header (v2: 72 bytes, v3: 104+ bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic (0x514649fb) |
| 4 | 4 | Version (2 or 3) |
| 8 | 8 | Backing file offset |
| 16 | 4 | Backing file size |
| 20 | 4 | Cluster bits (usually 16 = 64KB) |
| 24 | 8 | Virtual size |
| 32 | 4 | Encryption method |
| 36 | 4 | L1 size (entries) |
| 40 | 8 | L1 table offset |
| 48 | 8 | Refcount table offset |
| 56 | 4 | Refcount table clusters |
| 60 | 4 | Nb snapshots |
| 64 | 8 | Snapshots offset |
| (v3) 72 | 8 | Incompatible features |
| (v3) 80 | 8 | Compatible features |
| (v3) 88 | 8 | Autoclear features |
| (v3) 96 | 4 | Refcount order |
| (v3) 100 | 4 | Header length |

### L2 Entry Flags

| Bit | Meaning |
|-----|---------|
| 62 | Compressed |
| 0 | Standard cluster (bit 62=0) |
| 55:0 | Host cluster offset |

### Compressed Cluster

When bit 62 is set:
- Bits 61:0 contain: offset (variable) and size (variable)
- Offset is to compressed data
- Size is in sectors (512 bytes)
- Decompress with zlib (or zstd for compression_type=1)
