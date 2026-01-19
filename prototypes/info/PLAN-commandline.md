# Plan: Refactor VMM CLI to qemu-img Style

## Goal

Change the VMM command line from:
```bash
vmm --core core.bin --operation info.bin --input test.qcow2 --output /dev/null
```

To qemu-img compatible style:
```bash
imago info test.qcow2
imago copy test.qcow2 output.raw
```

## Current State

The info prototype VMM ([vmm/src/main.rs:294-355](vmm/src/main.rs))
uses a flat clap argument structure with:
- `--input`, `--output` as required options
- `--core`, `--operation` to specify binaries
- Various operation-specific flags mixed together

## Proposed Design

### 1. Binary Auto-Discovery

Binaries (core.bin, info.bin, copy.bin) are auto-discovered in the same
directory as the imago executable:

```rust
fn get_binary_dir() -> PathBuf {
    std::env::current_exe()
        .expect("Failed to get executable path")
        .parent()
        .expect("Failed to get executable directory")
        .to_path_buf()
}

fn get_binary_path(name: &str) -> PathBuf {
    get_binary_dir().join(name)
}
```

### 2. Subcommand Structure

```rust
#[derive(Parser)]
#[command(name = "imago")]
#[command(about = "Safe, sandboxed disk image operations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Detect image format and display information
    Info(InfoArgs),
    /// Copy/convert disk images
    Copy(CopyArgs),
}
```

### 3. Info Subcommand Args

```rust
#[derive(Args)]
struct InfoArgs {
    /// Input image file
    input: String,

    /// Sector size for reading input (default: 65536)
    #[arg(long, default_value = "65536")]
    sector_size: u32,
}
```

Note: `progress_percent` is not needed for info since it only reads the first
sector (nearly instant).

### 4. Copy Subcommand Args

```rust
#[derive(Args)]
struct CopyArgs {
    /// Input image file
    input: String,

    /// Output image file
    output: String,

    #[arg(long, default_value = "65536")]
    input_sector_size: u32,

    #[arg(long, default_value = "65536")]
    output_sector_size: u32,

    #[arg(long)]
    max_output_size: Option<u64>,

    #[arg(long)]
    preallocate_output: bool,

    #[arg(long, default_value = "10")]
    progress_percent: u32,

    #[arg(long)]
    verify: bool,

    #[arg(long)]
    skip_zeros: bool,

    #[arg(long, default_value = "0")]
    start_sector: u64,

    #[arg(long, default_value = "0")]
    sector_count: u64,
}
```

### 5. Info Operation Changes

Since `info` doesn't need an output file, skip output device initialization
entirely for the info command. This is cleaner than using `/dev/null` as a
placeholder.

The device initialization code should be refactored to support variable numbers
of devices per operation:
- `info`: 1 input device only
- `copy`: 1 input + 1 output device
- Future operations (rebase, commit, etc.): may need multiple input devices
  for copy-on-write layers, backing files, etc.

## Implementation Steps

0. **Remove `--no-ioeventfd` flag entirely** - Always use ioeventfd optimization
   (the flag was only useful for A/B testing during development)
1. **Refactor Args to subcommands** in vmm/src/main.rs
2. **Add binary auto-discovery** function
3. **Create run_info() and run_copy()** functions to handle each operation
4. **Update main()** to dispatch based on subcommand
5. **Update Cargo.toml** to rename binary
6. **Update build.sh** if needed
7. **Update README.md** with new CLI examples

## Files to Modify

1. **[vmm/src/main.rs](vmm/src/main.rs)**
   - Remove `--no-ioeventfd` flag and always use ioeventfd
   - Refactor Args struct to use subcommands
   - Add binary auto-discovery
   - Refactor device initialization to support variable device counts per operation
   - Split main logic into run_info() and run_copy()

2. **[vmm/Cargo.toml](vmm/Cargo.toml)**
   - Change binary name from "vmm" to "imago"

3. **[build.sh](build.sh)**
   - Update to reference new binary name

4. **[README.md](README.md)**
   - Update CLI examples

## Build Script Changes

The build.sh currently:
- Builds core.bin and info.bin in the prototype root directory
- Builds VMM in target/release/vmm

Changes needed:
- Rename vmm to imago in output messages
- Copy core.bin and info.bin to target/release/ so they're co-located with imago
- Update usage instructions in the script

## Verification

1. Build: `cd prototypes/info && ./build.sh`
2. Test help: `./target/release/imago --help` and `./target/release/imago info --help`
3. Test info: `sudo ./target/release/imago info ../../testdata/benign/basic.qcow2`
4. Verify output shows detected format, version, sizes
