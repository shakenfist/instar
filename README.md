# Instar

A safe, sandboxed disk image format converter.

## Overview

Instar replaces unsafe calls to `qemu-img` with a safer, sandboxed approach.
Image format conversions are performed within a KVM execution context,
providing strong isolation from the host system.

Confused about how instar does these things? Perhaps read the
[technology primer](https://github.com/shakenfist/instar/blob/develop/docs/technology-primer.md). If you want a guided tour of
the source code, the [Lions-style commentary](https://github.com/shakenfist/instar/blob/develop/docs/commentary/index.md)
provides a reading order and annotated walkthrough of the codebase.

## Supported Formats

Initial target formats:
- **qcow2** - QEMU Copy-On-Write format (including external data files)
- **raw** - Raw disk images
- **vmdk** - VMware Virtual Machine Disk
- **vpc** (VHD) - Virtual Hard Disk (Hyper-V, Virtual PC)
- **vhdx** - VHDX Virtual Hard Disk v2 (Hyper-V)
- **luks** - LUKS encrypted containers (v1/v2, info + convert with decryption)
- **vdi** - VirtualBox Disk Image (read-only input: convert/compare/dd source; no create/write)

## Project Status

**Initial implementation** - The `info` prototype has been promoted to the main
instar implementation in `src/`. Operations include `info`, `copy`, `check`,
`compare`, `convert`, `dd`, `measure`, `create`, `resize`, `rebase`, `commit`,
`map`, `snapshot`, `amend`, `bitmap`, and `bench`. Prototypes remain available
for reference.

See [docs/measure.md](https://github.com/shakenfist/instar/blob/develop/docs/measure.md), [docs/create.md](https://github.com/shakenfist/instar/blob/develop/docs/create.md),
[docs/resize.md](https://github.com/shakenfist/instar/blob/develop/docs/resize.md), [docs/rebase.md](https://github.com/shakenfist/instar/blob/develop/docs/rebase.md),
[docs/commit.md](https://github.com/shakenfist/instar/blob/develop/docs/commit.md), [docs/map.md](https://github.com/shakenfist/instar/blob/develop/docs/map.md),
[docs/snapshot.md](https://github.com/shakenfist/instar/blob/develop/docs/snapshot.md), [docs/amend.md](https://github.com/shakenfist/instar/blob/develop/docs/amend.md),
[docs/bitmap.md](https://github.com/shakenfist/instar/blob/develop/docs/bitmap.md), and
[docs/bench.md](https://github.com/shakenfist/instar/blob/develop/docs/bench.md) for the per-subcommand user guides.

## Installation

Pre-built x86_64 Linux artifacts are published on every release at
[GitHub Releases](https://github.com/shakenfist/instar/releases). Pick
the format that matches your distro.

The published packages require **glibc 2.39 or newer**. Compatible
distributions include Debian 13 (trixie), Ubuntu 24.04 LTS, Fedora
40+, and Rocky/RHEL 10. Older releases (Debian 12, Ubuntu 22.04 LTS,
Rocky/RHEL 9) need to build instar from source until the project
lowers its glibc baseline.

### Debian / Ubuntu (.deb)

```bash
VERSION=0.2.0
curl -sLO "https://github.com/shakenfist/instar/releases/download/v${VERSION}/instar_${VERSION}-1_amd64.deb"
sudo apt install "./instar_${VERSION}-1_amd64.deb"
instar --help
```

### Fedora / RHEL / SUSE (.rpm)

```bash
VERSION=0.2.0
curl -sLO "https://github.com/shakenfist/instar/releases/download/v${VERSION}/instar-${VERSION}-1.x86_64.rpm"
sudo dnf install "./instar-${VERSION}-1.x86_64.rpm"
instar --help
```

The packages install the VMM at `/usr/bin/instar` and the six guest
binaries (loaded into the KVM sandbox at runtime) at
`/usr/lib/instar/`.

### Tarball (any Linux)

```bash
VERSION=0.2.0
curl -sL "https://github.com/shakenfist/instar/releases/download/v${VERSION}/instar-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
  | sudo tar xz -C /usr/local/bin/
instar --help
```

The tarball contains the VMM and guest `.bin` files together; instar
finds them by looking in the directory containing the executable.

### System requirements

- **Linux** (instar uses KVM for sandboxed image processing)
- **KVM access**: `/dev/kvm` must be accessible
- Your user must be in the `kvm` group (`sudo usermod -aG kvm $USER`)

### Build from source

If you prefer to build from source, see [Building Instar](#building-instar)
below. This requires Docker and a nightly Rust toolchain (handled
automatically by the build container).

## Building Instar

```bash
# Build the main instar project
make instar

# The binaries will be in src/target/release/
sudo src/target/release/instar info <IMAGE>
sudo src/target/release/instar copy <INPUT> <OUTPUT>
```

## Usage

### Image Information

```bash
# Display image format information (matches qemu-img info output)
instar info image.qcow2

# Discover and display the complete backing file chain
instar info --chain image.qcow2

# Inspect LUKS container with inner format detection
instar info --luks-passphrase 'secret' encrypted.luks
```

The `--chain` flag iteratively runs the sandboxed info operation on each image
in the backing chain, validating paths against a security allowlist to prevent
directory traversal attacks.

### Image Comparison

```bash
# Compare two images for identical content (matches qemu-img compare output)
instar compare image1.raw image2.raw

# Strict mode: fail if images differ in size (even if content matches)
instar compare -s image1.raw image2.raw

# JSON output for programmatic consumption
instar compare --output json image1.raw image2.raw

# Compare LUKS-encrypted QCOW2 against decrypted raw
instar compare --luks-passphrase secret encrypted.qcow2 decrypted.raw
```

Exit codes: 0 = identical, 1 = content differs.

The compare operation reads the virtual content of both images and reports the
first byte offset where content diverges. For QCOW2 and VMDK images, this
includes cluster/grain/block table lookup and compressed cluster decompression
(zlib, ZSTD, and DEFLATE), so comparisons work across formats (e.g., QCOW2
vs raw, VMDK vs raw, VHD vs raw, compressed QCOW2 vs uncompressed QCOW2).
LUKS-encrypted QCOW2 images (crypt_method=2) can be compared at the
plaintext level using `--luks-passphrase`. Backing chains are automatically
discovered and flattened: unallocated clusters/grains are resolved by walking
the backing chain, so overlay images compare correctly against their flattened
equivalents.
When images differ in size, non-strict mode (default) treats extra zero-filled
regions as matching, while strict mode (`-s`) fails immediately on any size
difference.

Output is byte-for-byte identical with `qemu-img compare`.

### Image Integrity Check

```bash
# Validate image structural integrity (matches qemu-img check output)
instar check image.qcow2

# JSON output for programmatic consumption
instar check --output json image.qcow2

# Validate the entire backing chain
instar check --chain image.qcow2

# Repair a qcow2 image in place: safe leak reclamation (the default tier)
instar check --repair image.qcow2

# Lossy repair: also rebuild refcounts and reconcile COPIED flags
instar check --repair=all image.qcow2
```

For QCOW2 images, check validates:
- Header integrity (version, cluster_bits, virtual_size)
- Incompatible feature bit validation (rejects unknown bits per spec)
- Full L1/L2 table consistency (all sectors, including extended L2)
- Extended L2 subcluster bitmap validation (alloc/zero overlap,
  alloc-without-host, host-without-ref, compressed non-zero bitmap)
- Overlap detection (two L2 entries referencing same host cluster)
- Refcount validation for all widths (1/2/4/8/16/32/64-bit refcounts)
- Leak detection (clusters with refcount > 0 but no L2 reference),
  including correct handling of compressed cluster host ranges
- Cluster sizes from 512B to 2MB (cluster_bits 9-21)
- Dirty/corrupt incompatible feature flags

For QCOW2 images, `instar check --repair[=leaks|all]` additionally repairs the
image in place: the safe `leaks` tier reclaims unreferenced clusters
(crash-safe, lossless), and the lossy `all` tier rebuilds refcounts and
reconciles COPIED flags under a crash-safe `corrupt`-bit write ordering —
mirroring `qemu-img check -r leaks`/`-r all`. It refuses rather than guessing:
snapshotted images are repaired by neither tier, and the lossy `all` tier
declines its rebuild on compressed, external-data, or already-corrupt images
(the safe leak reclamation still runs, and the result is reported incomplete).
See
[docs/qcow2/qcow2-refcount.md](https://github.com/shakenfist/instar/blob/develop/docs/qcow2/qcow2-refcount.md#repairing-refcount-inconsistencies).

For VMDK images (monolithicSparse, streamOptimized, and
monolithicFlat — including multi-extent twoGbMaxExtentFlat
and flat-in-backing-chain via parentFileNameHint), check validates:
- Full header parsing (version, capacity, grain size, flags, compression)
- Descriptor bounds and multi-extent detection (graceful rejection)
- Grain directory offset within file bounds
- Full grain directory and grain table walk
- Grain data offsets within file bounds
- Compressed grain marker validation (LBA consistency, compressed size
  bounds, marker-plus-data within file)
- Redundant Grain Directory (RGD) cross-check when FLAG_USE_RGD is set
- Overlap detection via 1-bit-per-grain bitmap (same pattern as QCOW2)
- streamOptimized footer validation (magic, GD offset)
- Fragmentation measurement

For VHD images (dynamic and fixed), check validates:
- Footer cookie and checksum (from first or last sector)
- Format version (must be 1.0) and features (reserved bit required)
- Disk type validity (fixed, dynamic, differencing)
- Fixed VHD: data_offset check, file size vs virtual size validation
- Dynamic header cookie, checksum, and version
- BAT offset within file bounds
- BAT entry validation: allocated block offsets within file
- Overlap detection (no two BAT entries reference same block)
- Fragmentation tracking (non-sequential block allocation)
- Footer copy consistency (start vs end of file)

For VHDX images, check validates:
- File identifier signature at offset 0 ("vhdxfile")
- Header 1 and Header 2: signature, CRC-32C checksum, active header
  selection by sequence number
- Dirty log detection (non-zero log GUID)
- Region table 1: signature, CRC-32C, BAT and metadata region presence
- Region table 2: cross-validation against region table 1
- Metadata: required items (FileParameters, VirtualDiskSize,
  LogicalSectorSize, PhysicalSectorSize)
- Differencing disk detection (unsupported)
- BAT entries: block offsets within file bounds, 1MB alignment,
  overlap detection, state validation
- Fragmentation tracking (non-sequential block allocation)

The `--chain` flag discovers the full backing chain (using the same chain
discovery infrastructure as `instar info --chain`), sets up each image as a
separate virtio-block device in the KVM guest, and validates:
- Format consistency: each backing image's format matches what chain
  discovery found
- Virtual size validity: backing images must have non-zero virtual size
- QCOW2 header validation: backing images that are QCOW2 get basic header
  checks (magic, version, cluster_bits, L1/refcount table bounds, corrupt
  feature flag)

Chain errors are reported separately as `chain-errors` in JSON output and
in human-readable output. Without `--chain`, `chain-errors` is always 0.

**Note:** The `chain-errors` field is always present in JSON output,
even when `--chain` is not used. This is a schema addition relative to
previous versions.

### Image Conversion

```bash
# Convert QCOW2 to raw (flattens backing chains)
instar convert input.qcow2 output.raw

# Convert any input to QCOW2 v3 output
instar convert -O qcow2 input.raw output.qcow2

# Convert QCOW2 with backing chain to standalone QCOW2
instar convert -O qcow2 overlay.qcow2 standalone.qcow2

# Convert with compressed QCOW2 output (zlib/deflate compression)
instar convert -c -O qcow2 input.raw output.qcow2

# Convert with dense output (write all clusters including zeros)
instar convert --no-skip-zeros input.qcow2 output.raw

# Specify output cluster size for QCOW2 (512 to 2097152, default: 65536)
instar convert -O qcow2 --cluster-size 4096 input.raw output.qcow2
instar convert -O qcow2 --cluster-size 2097152 input.raw output.qcow2

# Write QCOW2 output with extended L2 entries (16-byte entries with subcluster bitmaps)
instar convert -O qcow2 --extended-l2 input.raw output.qcow2

# Write LUKS-encrypted QCOW2 output (AES-256-XTS, crypt_method=2)
instar convert -O qcow2 --luks-encrypt-passphrase 'secret' input.raw encrypted.qcow2

# Decrypt LUKS-encrypted QCOW2 back to raw
instar convert --luks-passphrase 'secret' encrypted.qcow2 output.raw

# Convert to VHD dynamic format
instar convert -O vpc input.qcow2 output.vhd

# Convert to VHDX dynamic format
instar convert -O vhdx input.qcow2 output.vhdx

# Decrypt native LUKS v2 container (Argon2id KDF)
instar convert --luks-passphrase 'secret' --max-guest-memory 1G encrypted.luks output.raw

# Decrypt LUKS container wrapping a QCOW2 image
instar convert --luks-passphrase 'secret' luks-wrapped.img output.raw

# Specify VMDK grain size (4096 to 65536, default: 65536)
instar convert -O vmdk --grain-size 4096 input.raw output.vmdk

# Specify VHD block size (524288+, default: 2097152)
instar convert -O vpc --block-size 1048576 input.raw output.vhd

# Specify VHDX block size (1048576 to 268435456, default: 33554432)
instar convert -O vhdx --block-size 4194304 input.raw output.vhdx

# Progress reporting
instar convert -p 5 input.qcow2 output.raw
```

The convert operation reads the virtual content of an input image (including
backing chain flattening) and writes it in the requested output format.
Compressed clusters (zlib/deflate and ZSTD) are decompressed transparently,
including clusters up to 2MB. QCOW2 v3 images with extended L2 entries
(subclusters) are also supported. Legacy AES-128-CBC encrypted QCOW2 images
(`crypt_method=1`) can be decrypted with `--qcow2-password`. LUKS-in-QCOW2
images (`crypt_method=2`) and native LUKS containers can be decrypted with
`--luks-passphrase`. LUKS v2 containers using Argon2id KDF require
`--max-guest-memory` (e.g., `--max-guest-memory 1G`). Native LUKS
containers wrapping QCOW2 images are transparently detected and
decrypted, with the inner QCOW2 processed as the conversion source.
Individual snapshots can be extracted with `--snapshot <name-or-id>`.

By default, convert produces sparse output by skipping zero-filled clusters
(matching `qemu-img convert` behavior). Use `--no-skip-zeros` for dense output.
The default can also be set via `convert.sparse` in the config file.

Supported output formats:
- **raw** (default) - Flat raw output
- **qcow2** - QCOW2 v3 output with 16-bit refcounts, configurable cluster
  size (512 bytes to 64KB, default 64KB), optional zlib compression (`-c`)
- **vmdk** - VMDK monolithicSparse output (default), streamOptimized
  with `-c`, or monolithicFlat with `--subformat monolithicFlat`.
  Configurable grain size (4KB-64KB, default 64KB via `--grain-size`)
  for sparse/streamOptimized output
- **vpc** - VHD dynamic output, configurable block size (512KB+,
  default 2MB via `--block-size`)
- **vhdx** - VHDX dynamic output, configurable block size (1MB-256MB,
  default 32MB via `--block-size`)

### Block Copy (dd)

```bash
# Copy a whole image to raw output (-O defaults to raw, not the input format)
instar dd if=input.qcow2 of=output.raw

# Copy to QCOW2 output
instar dd -O qcow2 if=input.raw of=output.qcow2

# Windowed copy: skip the first 2 blocks, copy the next 4 blocks of 65536 bytes
instar dd bs=65536 skip=2 count=4 if=in.raw of=out.raw
```

Both `if=` (input) and `of=` (output) operands are mandatory; all other
operands (`bs`, `count`, `skip`) are optional. `bs` defaults to 512; `count`
clamps the copy down (the output is at most `count*bs` bytes); `skip` removes
`skip*bs` bytes from the front of the input window. `-O` sets the output
format and defaults to **raw** (not the input format). Supported output
formats: raw, qcow2, vmdk, vpc (VHD), vhdx. Output is byte- and size-identical
to `qemu-img dd` for all five formats. See [docs/dd.md](https://github.com/shakenfist/instar/blob/develop/docs/dd.md) for the
full reference.

### Image Rebase

```bash
# Unsafe (metadata-only) rebase to a new backing in the same dir
instar rebase -u -b new-backing.qcow2 disk.qcow2

# Safe rebase (walks chains, copies divergent clusters)
instar rebase -b new-backing.qcow2 -F qcow2 disk.qcow2

# Detach the overlay (zero its backing pointer)
instar rebase -u -b "" disk.qcow2
```

Changes the backing-file reference recorded in a qcow2 or vmdk overlay.
Unsafe mode (`-u`) rewrites only the header pointer; safe mode (default)
also walks the old and new chains and copies any divergent clusters into
the overlay so reads stay coherent. Detach is encoded as `-b ""`. See
[docs/rebase.md](https://github.com/shakenfist/instar/blob/develop/docs/rebase.md) for the full reference.

### Image Commit

```bash
# Commit into the overlay's recorded parent (implicit -b)
instar commit overlay.qcow2

# Commit with an explicit base (must match the recorded parent)
instar commit -b base.qcow2 overlay.qcow2

# JSON output for scripting
instar commit --output=json overlay.qcow2
```

Merges every allocated cluster from a qcow2 or vmdk overlay into its
backing image, then zeroes the overlay's metadata so the overlay reads
as empty against the (now-updated) backing. v1 supports only the
overlay's immediate parent; intermediate-image commit is deferred. See
[docs/commit.md](https://github.com/shakenfist/instar/blob/develop/docs/commit.md) for the full reference.

### Allocation Map

```bash
# Human-readable allocation table
instar map disk.qcow2

# JSON for scripting
instar map --output=json disk.qcow2
```

Emits the allocation map of a disk image as a stream of contiguous
extents covering `[0, virtual_size)`, mirroring `qemu-img map`. Each
extent is classified as data, zero-allocated, or hole. Window flags
`--start-offset` / `--max-length` clip the emission range. Single-
image v1; backing-chain `depth` composition is deferred. See
[docs/map.md](https://github.com/shakenfist/instar/blob/develop/docs/map.md) for the full reference.

### Internal Snapshots

```bash
# List snapshots (byte-identical to qemu-img snapshot -l)
instar snapshot -l disk.qcow2

# Create / apply / delete a snapshot
instar snapshot -c before-upgrade disk.qcow2
instar snapshot -a before-upgrade disk.qcow2
instar snapshot -d before-upgrade disk.qcow2

# JSON listing (instar extension; QMP SnapshotInfo key names)
instar snapshot -l --output=json disk.qcow2
```

Manages the internal snapshot table of a qcow2 image (qcow2 only,
like qemu-img). All parsing and every mutation — refcounts, L1
copies, COPIED flags, header writes — runs inside the KVM guest.
Mutating modes produce images bit-for-bit identical to `qemu-img
snapshot` given identical inputs (modulo documented freed-cluster
and file-tail notes). See [docs/snapshot.md](https://github.com/shakenfist/instar/blob/develop/docs/snapshot.md)
for the full reference, including the `-d` (name-only) vs `-a`
(ID-then-name) matcher asymmetry and the v1 limits.

### QCOW2 Header Amendment

```bash
# Upgrade a v2 image to qcow2 v3 (compat=1.1)
instar amend -o compat=1.1 disk.qcow2

# Downgrade a v3 image to v2 (refused if v3-only features are present)
instar amend -o compat=0.10 disk.qcow2

# Toggle lazy refcounts (v3 only)
instar amend -o lazy_refcounts=on disk.qcow2
```

Changes a qcow2 image's compatibility version (`compat=0.10`/`1.1`) and/or
the `lazy_refcounts` flag in place, rewriting only the header cluster — the
sandboxed equivalent of `qemu-img amend`. qcow2-only. See
[docs/amend.md](https://github.com/shakenfist/instar/blob/develop/docs/amend.md) for the full reference.

### QCOW2 Dirty Bitmaps

```bash
# Add an enabled, empty bitmap with the default granularity
instar bitmap --add disk.qcow2 backup0

# Add a bitmap with an explicit 64 KiB granularity
instar bitmap --add -g 64k disk.qcow2 backup0

# Remove a bitmap (and free its clusters)
instar bitmap --remove disk.qcow2 backup0

# Merge one bitmap into another within the same image
instar bitmap --merge incremental0 disk.qcow2 full0
```

Creates, deletes, clears, enables, disables, and merges qcow2 **persistent
dirty bitmaps** in place — the sandboxed equivalent of `qemu-img bitmap`.
Actions are applied in command-line order and the tool is silent on success.
qcow2 v3-only. See [docs/bitmap.md](https://github.com/shakenfist/instar/blob/develop/docs/bitmap.md) for the full reference.

### I/O Benchmarking (bench)

```bash
# Default read benchmark: 75000 requests, 4 KiB each, against a qcow2 image
instar bench -f qcow2 disk.qcow2

# A write benchmark modelled on Ceph's cli_migration.sh invocation
instar bench -w -c 65536 -d 16 --pattern 65 -s 4096 -f qcow2 disk.qcow2
```

Issues a scripted sequence of read or write requests against a disk image
and reports how long they took — the sandboxed equivalent of `qemu-img
bench`. **Read [docs/bench.md](https://github.com/shakenfist/instar/blob/develop/docs/bench.md) before trusting a number**:
`instar bench` times its own end-to-end sandboxed I/O path, not qemu's
block layer over the page cache, so the two tools' absolute numbers are
not directly comparable to each other.

### Version Compatibility

Different qemu-img versions produce slightly different output formats:
- **qemu-img 6.0-7.2** (Debian 12 bookworm): No "Child node '/file'" section
- **qemu-img 8.0+** (Debian 13 trixie): Includes "Child node '/file'" section

By default, instar detects the installed qemu-img version and emits matching output.
This ensures true drop-in replacement compatibility.

To explicitly specify which qemu-img version's output format to use:

```bash
# Emit output compatible with qemu-img 7.2 (no Child node section)
instar info --qemu-version 7.2 image.qcow2

# Emit output compatible with qemu-img 10.0 (includes Child node section)
instar info --qemu-version 10.0 image.qcow2
```

See [docs/output-formats.md](https://github.com/shakenfist/instar/blob/develop/docs/output-formats.md) for detailed documentation on
output format profiles.

## Prototypes

Working prototypes exploring the KVM-based sandboxing approach:

| Prototype | Description |
|-----------|-------------|
| [helloworld](https://github.com/shakenfist/instar/tree/develop/prototypes/helloworld/) | Minimal bare-metal KVM guest proof-of-concept |
| [helloworld2](https://github.com/shakenfist/instar/tree/develop/prototypes/helloworld2/) | Uses vm-memory crate for safer memory management |
| [virtio-block](https://github.com/shakenfist/instar/tree/develop/prototypes/virtio-block/) | Virtio-block device emulation with file copy |
| [virtio-block2](https://github.com/shakenfist/instar/tree/develop/prototypes/virtio-block2/) | Adds guest-protocol (protobuf) integration |
| [virtio-block3](https://github.com/shakenfist/instar/tree/develop/prototypes/virtio-block3/) | Adds configurable sector sizes |
| [virtio-block4](https://github.com/shakenfist/instar/tree/develop/prototypes/virtio-block4/) | Adds performance statistics tracking |
| [virtio-block5](https://github.com/shakenfist/instar/tree/develop/prototypes/virtio-block5/) | Adds ioeventfd optimization |
| [virtio-block6](https://github.com/shakenfist/instar/tree/develop/prototypes/virtio-block6/) | Sparse/dynamic output, recommended sector sizes, progress reporting |
| [pluggable](https://github.com/shakenfist/instar/tree/develop/prototypes/pluggable/) | Modular architecture separating core infrastructure from pluggable operations |
| [pluggable2](https://github.com/shakenfist/instar/tree/develop/prototypes/pluggable2/) | Separate binary loading for operations (reduced attack surface) |
| [info](https://github.com/shakenfist/instar/tree/develop/prototypes/info/) | Image format detection (qemu-img info equivalent) |

See [docs/index.md](https://github.com/shakenfist/instar/blob/develop/docs/index.md) for full prototype documentation.

## Development

### Pre-commit Hooks

This project uses pre-commit hooks for Rust code quality:

```bash
# Install pre-commit (if not already installed)
pip install pre-commit

# Install the hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

The hooks run rustfmt (formatting) and clippy (linting) on all Rust code via
Docker, ensuring consistent tooling regardless of local Rust installation.

To auto-fix formatting issues:
```bash
./scripts/check-rust.sh fix
```

### Makefile

A Makefile is provided for common development tasks:

```bash
# Show all available targets
make help

# List available prototypes
make list-prototypes
```

**Main Instar Project:**
```bash
# Build instar
make instar

# Clean instar build
make clean-instar

# Show how to run instar
make run-instar
```

**Prototypes:**
```bash
# Build a specific prototype
make build-prototype PROTOTYPE=virtio-block5

# Build all prototypes
make build-all

# Build the shared guest-protocol crate
make guest-protocol

# Build devcontainer for a prototype
make build-prototype-devcontainer PROTOTYPE=virtio-block5

# Build the rust-lint Docker container
make build-lint-container
```

**Cleaning:**
```bash
# Clean a specific prototype's target directory
make clean-prototype PROTOTYPE=virtio-block5

# Clean all build directories (main + prototypes)
make clean-all

# Remove all devcontainer Docker images
make clean-devcontainers

# Remove the rust-lint Docker image
make clean-lint-container

# Remove everything (all targets + all containers)
make distclean
```

**Linting:**
```bash
# Run rustfmt and clippy checks
make lint

# Run with auto-fix
make lint-fix

# Install pre-commit hooks
make install-hooks
```

**Integration Testing:**
```bash
# Create Python venv for tests (testtools/stestr)
make test-venv

# Run safe integration tests
make test

# Run tests with verbose output (shows diffs)
make test-report

# Run all tests including malicious images (explicit opt-in)
make test-malicious

# Run tests inside container (as CI does)
make test-container

# Run split test targets (used by CI for parallel execution)
make test-container-core              # info, check, security, oslo-crossval
make test-container-convert-qcow2    # QCOW2/VMDK/RAW convert + compare
make test-container-convert-vhd      # VHD/VHDX convert (slowest)

# Clean test artifacts
make clean-tests
```

**Fuzz Testing:**
```bash
# Build a single coverage-guided fuzz target (uses the devcontainer)
make fuzz-build FUZZ_TARGET=fuzz_resize_planners

# Build every coverage-guided fuzz target
make fuzz-build

# Run a single target for a bounded wall-clock budget (seconds; default 60)
make fuzz-run FUZZ_TARGET=fuzz_resize_planners FUZZ_DURATION=300

# Run the seven snapshot shell harnesses (live differential
# verification against qemu-img; needs a built instar + /dev/kvm)
make snapshot-harnesses
```

See the "Coverage-Guided Fuzzing" section below for the target list and the
nightly CI rotation.

The integration tests compare `instar info` output against `qemu-img info` to
verify drop-in replacement compatibility, validate `instar check` against
deliberately corrupt test images, cross-validate `instar compare` output
against `qemu-img compare`, and cross-validate `instar convert` output against
`qemu-img convert`. oslo.utils `format_inspector` cross-validation tests
verify that instar's format detection, safety checks, and virtual size
reporting agree with OpenStack's image safety gate. Adversarial image tests
verify safe handling of compression bombs, circular/deep backing chains,
integer overflow headers, boundary value edge cases (refcount order,
oversized virtual sizes, VMDK grain sizes, VHDX dual headers, BAT beyond EOF),
and format confusion attacks (polyglot files, truncated headers, VMDK
descriptor attacks). CVE reproduction tests verify that 6 known qemu-img CVEs
(CVE-2024-32498, CVE-2015-5163, CVE-2022-47951, CVE-2015-5162, CVE-2014-0223,
CVE-2024-4467) are fully mitigated by instar's architecture.
`tests/test_snapshot.py` (phase 11) adds 94 snapshot-subcommand tests: the
12-image list matrix against cross-version baselines, 12 JSON golden
comparisons with a structural cross-check, mutation round-trips
(create/delete/apply) with `qemu-img check` post-op assertions, error paths
and qcow2-only enforcement, and empty-table behaviour. JSON goldens live in
`tests/golden/snapshot-list/`. Test images are in the sibling
`instar-testdata/` repository.

**Running:**
```bash
# Show run instructions for a prototype
make run PROTOTYPE=virtio-block5
```

## Directory Structure

```
instar/
├── .devcontainer/  # Development containers
│   └── rust-lint/  # Stable Rust for linting
├── src/            # Main instar implementation
│   ├── vmm/        # Virtual machine monitor (host-side)
│   ├── core/       # Core guest initialization
│   ├── shared/     # Shared library code
│   ├── crates/     # Shared format parsing crates (no_std)
│   │   ├── qcow2/  # QCOW2 header, L1/L2, decompression, refcounts
│   │   ├── raw/    # MBR/GPT partition table detection
│   │   ├── vhd/    # VHD footer, dynamic header, BAT parsing
│   │   ├── vhdx/   # VHDX headers, region table, metadata, BAT, CRC-32C
│   │   ├── vmdk/   # VMDK4 header and descriptor parsing
│   │   ├── luks/   # LUKS header parsing, KDF, AFsplitter, decryption
│   │   └── ...     # Per-operation planner crates (measure, create,
│   │               # resize, rebase, commit, snapshot)
│   ├── operations/ # Pluggable operations (info, copy, check, compare, convert, measure, create, resize, rebase, commit, map, snapshot, amend, dd, bitmap, bench)
│   └── build.sh    # Build script
├── crates/         # Shared Rust crates
│   └── guest-protocol/ # Protocol Buffers messaging for guests
├── prototypes/     # Experimental implementations (reference)
│   ├── helloworld/     # Minimal KVM VMM with bare-metal guest
│   ├── helloworld2/    # Same, using rust-vmm vm-memory crate
│   ├── virtio-block/   # Virtio-block device emulation
│   ├── virtio-block2/  # With guest-protocol integration
│   ├── virtio-block3/  # With configurable sector sizes
│   ├── virtio-block4/  # With performance statistics
│   ├── virtio-block5/  # With ioeventfd optimization
│   ├── virtio-block6/  # With sparse/dynamic output support
│   ├── pluggable/      # Modular operations architecture
│   ├── pluggable2/     # Separate binary loading for operations
│   └── info/           # Image format detection (qemu-img info)
├── scripts/        # Build and check scripts
├── tests/          # Integration tests (Python/testtools)
│   ├── base.py         # Base test class
│   ├── manifest.json   # Test image definitions
│   ├── helpers/        # Test utilities
│   └── test_*.py       # Test files
├── docs/           # Design documents and research
│   ├── index.md    # Documentation index
│   ├── usage.md    # Platform usage analysis (oVirt, Proxmox, OpenStack)
│   ├── security.md # CVE analysis for image handling
│   ├── qcow2/      # QCOW2 format documentation
│   ├── vmdk/       # VMDK format documentation
│   └── raw/        # Raw format documentation
├── testdata/       # Test images for security validation
│   ├── benign/     # Safe test images (qcow2, raw, vmdk, vhdx, vpc)
│   ├── malicious/  # CVE exploit images (DANGEROUS)
│   └── downloaded/ # External test images (CirrOS, QEMU iotests, etc.)
├── Makefile        # Build and development automation
├── CHANGELOG.md    # Release history
├── SECURITY.md     # Vulnerability reporting and security policy
└── README.md
```

## Security Model

The core security principle is that untrusted disk images should never be
parsed or manipulated by code running with host privileges. Instead:

1. A minimal KVM guest handles all image parsing and conversion
2. The host only deals with opaque byte streams
3. Any vulnerabilities in format parsing are contained within the sandbox

### Secure RAW Format Detection

Unlike qemu-img, instar validates RAW format detection by requiring a valid
partition table (MBR or GPT). This prevents arbitrary files from being accepted
as disk images, which is the root cause of backing file disclosure attacks
(CVE-2015-5163, CVE-2024-32498).

```bash
# Default (secure): rejects files without valid format or partition table
instar info /etc/passwd
# Error: Unknown format (no valid disk image header or partition table)

# Unsafe mode: matches qemu-img behavior (for compatibility testing only)
instar info --unsafe-quirks /etc/passwd
# file format: raw
```

See [docs/quirks.md](https://github.com/shakenfist/instar/blob/develop/docs/quirks.md) for the classification of safe vs unsafe quirks.

### Security Audits

The codebase undergoes periodic security audits covering unsafe code review,
integer arithmetic analysis, adversarial image testing, CVE reproduction, and
VMM boundary auditing. Completed audit phases:

- **Static analysis:** All unsafe blocks classified, integer arithmetic reviewed,
  clippy/cargo-audit clean. 1 bug found and fixed (VHDX BAT overflow).
- **Adversarial images:** 61 hand-crafted malicious images across 12 attack
  categories, 0 bypasses.
- **CVE reproduction:** 6 known qemu-img CVEs verified as mitigated, 0 bypasses.
- **VMM boundary audit:** Full review of host-side code (virtio-block I/O,
  serial protocol, MMIO dispatch, KVM exit handling). 8 bugs found and fixed.

Audit results are published in [docs/security-audits.md](https://github.com/shakenfist/instar/blob/develop/docs/security-audits.md).
The audit methodology is documented in `PLAN-audit.md`.

## Test Data

The `testdata/` directory contains 44 disk images for security validation:

- **Benign images** - Basic valid images in various formats for functionality testing
- **Malicious images** - Crafted to exploit known CVEs (CVE-2015-5163, CVE-2024-32498,
  CVE-2022-47951, etc.) including backing file exploits, external data file exploits,
  and VMDK descriptor attacks
- **Edge cases** - Valid but unusual configurations (min/max cluster sizes, extended L2,
  various refcount widths, backing file chains)
- **AFL-discovered** - Malformed images from QEMU's fuzzing that trigger parser errors

See `testdata/README.md` for full documentation.

## Releases

See [CHANGELOG.md](https://github.com/shakenfist/instar/blob/develop/CHANGELOG.md) for release notes.

Release artifacts (pre-compiled Linux binaries) are published to
[GitHub Releases](https://github.com/shakenfist/instar/releases)
via the release workflow (`.github/workflows/release.yml`). Tags
are signed with Sigstore. To cut a release:

```bash
make release VERSION=0.2.0
git push origin HEAD
git push origin v0.2.0
```

## Documentation

The `docs/` directory contains:

- Format specifications derived from QEMU source analysis (QCOW2, VMDK, raw)
- Platform usage analysis showing how oVirt, Proxmox, and OpenStack use qemu-img
- Security vulnerability analysis covering ~35 CVEs related to image handling

See `docs/index.md` for the full documentation index.

## GitHub Automation

This project uses Claude Code-powered GitHub automation for PR management.

### Bot Commands

Comment on a PR with these commands (requires write access):

| Command | Description |
|---------|-------------|
| `@shakenfist-bot please re-review` | Request a fresh automated code review |
| `@shakenfist-bot please attempt to fix` | Attempt to fix failing tests |
| `@shakenfist-bot please address comments` | Address automated review comments |

The "address comments" command extracts the structured JSON review from the PR
comment (embedded in a collapsed `<details>` section) and creates one commit per
actionable item (those marked with `action: fix` or `action: document`). If Claude
disagrees with a suggestion, it will explain its rationale instead of making changes.

### GitHub Issues

The automated reviewer creates GitHub issues for actionable items (fix/document).
These issues are linked in the review comment with "Closes #N" syntax, so they're
automatically closed when the PR merges.

### Workflows

- **Automated Review**: PRs automatically receive code review after CI passes,
  and GitHub issues are created for actionable items
- **Test Fixing**: On-demand test failure resolution via PR comment
- **Comment Addressing**: On-demand resolution of review feedback via PR comment

See `.github/workflows/` for implementation details.

### Differential Fuzzing

On-demand differential fuzzing compares instar against qemu-img on randomly
generated images to find behavioral divergences:

```bash
# Run locally (requires instar binary and qemu-img)
python3 scripts/differential-fuzz.py \
    --instar src/target/release/instar \
    --iterations 100 \
    --seed 42

# Trigger via GitHub Actions (workflow_dispatch)
gh workflow run differential-fuzz.yml \
    -f iterations=1000 \
    -f seed=42
```

The fuzzer generates random images (varying format, size, cluster size,
compression, data patterns), runs chains of operations (info, check, convert)
against both tools, and reports divergences with full reproduction details.

When libyal tools are available (`vmdkinfo`, `vhdiinfo`, `qcowinfo`), the
fuzzer also cross-checks instar output against these independent forensic-grade
parsers. This provides a third opinion for QCOW2 (alongside qemu-img) and
fills the gap for VMDK/VHD/VHDX where qemu-img check is unavailable.

See `scripts/differential-fuzz.py` for implementation details.

### Coverage-Guided Fuzzing

Coverage-guided fuzzing uses `cargo-fuzz` (libFuzzer) to exercise the
parser crates directly without the VMM/KVM stack:

```bash
# Inside the instar-build container:
cd src/fuzz
cargo fuzz run fuzz_qcow2_header -- -max_total_time=60
```

32 fuzz targets cover all parser crates (QCOW2, VMDK, VHD, VHDX, RAW,
LUKS) including header parsing, L1/L2 lookup, refcount traversal, and
decompression, plus the create / resize / rebase / commit planners,
the qcow2 check-repair planners (`fuzz_check_repair`), the map extent
walkers, the snapshot table parser (`fuzz_snapshot_parse`), the
snapshot refcount mutators (`fuzz_snapshot_refcount`), the dd
window math (`fuzz_dd_window`), CHS geometry rounding
(`fuzz_chs_rounded_size`), windowed read primitives
(`fuzz_dd_read`), and the qcow2-write planner
(`fuzz_qcow2_write`, which drives the write/copy-on-write planner
through the crate's `sim` harness asserting the `max_rc < 3` COW
invariant oracle, and `fuzz_qcow2_write_growth`). Seed the corpus
from `instar-testdata`:

```bash
python3 scripts/extract-fuzz-corpus.py --testdata /path/to/instar-testdata
```

The CI workflow runs nightly at 04:00 UTC. Crashes are minimized and
filed as GitHub Issues with the `security-audit` label immediately.
See `src/fuzz/` for target implementations.

## Claude Code Integration

This project includes Claude Code skills for common development tasks:

- `/instar-new-op <name>` - Scaffold a new operation binary
- `/instar-format [format]` - Disk image format reference (qcow2, vmdk, raw)
- `/instar-debug [issue]` - Troubleshooting guide for guest operations
- `/instar-calltable [function]` - Call table API documentation
- `/instar-add-test-image` - Add a new image to the integration test suite
- `/verbose-print` - Guidelines for adding diagnostic verbose_print() calls
- `/error-handling` - Ensure all error conditions return proper exit codes

Additional development skills:
- `.claude/skills/build-and-test.md` - Correct build/test patterns (always use
  Makefile targets like `make instar`, `make test-ci`)
- `.claude/skills/testing-discipline.md` - Test verification workflow (never
  accept failures as "pre-existing" without verification)
- `.claude/skills/pr-preparation.md` - PR readiness checklist (zero test
  failures, no VM crashes, all checks passing)
- `.claude/skills/documentation-updates.md` - Documentation requirements (every
  user-visible change requires docs updates)
- `.claude/skills/correct-fixes.md` - Fix root causes, not symptoms (security
  project: always do things the right way, not the easy way)
- `.claude/skills/error-handling.md` - Error propagation patterns (never use
  exit(), always return errors with context)

See `.claude/skills/` for details.

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.
