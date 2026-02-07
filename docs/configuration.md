# Configuration Guide

This document describes imago's configuration options, including command-line
flags and configuration files.

## Command-Line Flags

### Output Control

| Flag | Description |
|------|-------------|
| `--output=human` | Human-readable output (default) |
| `--output=json` | Machine-parseable JSON output |
| `--extra-detail` | Include format-specific details not provided by qemu-img |

#### `--extra-detail`

Includes additional format-specific information that qemu-img does not output.
This provides more comprehensive details about the disk image while maintaining
compatibility with standard output.

Currently supported extra details:

- **VDI format**: image-type, block-size, blocks-in-image, blocks-allocated, uuid
- **LUKS format detection**: Detects LUKS encrypted volumes (qemu-img reports these as "raw")

```bash
# Default: matches qemu-img output
imago info image.vdi

# With --extra-detail: includes VDI-specific fields
imago info --extra-detail image.vdi
# format specific information:
#     image-type: dynamic
#     block-size: 1048576
#     blocks-in-image: 1024
#     blocks-allocated: 0
#     uuid: 12345678-1234-1234-1234-123456789abc
```

**LUKS Detection**

LUKS (Linux Unified Key Setup) encrypted volumes are detected by their magic
bytes but qemu-img does not recognize them, reporting them as "raw" format.
With `--extra-detail`, imago correctly identifies LUKS volumes:

```bash
# Default: matches qemu-img (reports as unknown due to no partition table)
imago info encrypted.luks
# file format: unknown

# With --extra-detail: detects LUKS format
imago info --extra-detail encrypted.luks
# file format: luks
```

### Quirk Control

imago categorizes qemu-img behaviors as "safe quirks" (formatting differences)
and "unsafe quirks" (security-affecting behaviors). See [quirks.md](quirks.md)
for the full classification.

| Flag | Safe Quirks | Unsafe Quirks | Use Case |
|------|-------------|---------------|----------|
| (default) | Enabled | Disabled | Production use |
| `--ignore-quirks` | Disabled | Disabled | Intuitive output |
| `--unsafe-quirks` | Enabled | Enabled | Compatibility testing |

#### `--ignore-quirks`

Disables safe quirks for more intuitive output:

- Reports actual file sizes instead of block-rounded values
- Uses standard rounding instead of banker's rounding
- Shows precise values instead of 3-significant-figure formatting

This flag is useful when you want accurate filesystem information rather
than qemu-img-compatible output.

```bash
# Default: matches qemu-img output
imago info image.qcow2
# disk size: 196 KiB (rounded to 4K blocks)

# With --ignore-quirks: actual values
imago info --ignore-quirks image.qcow2
# disk size: 191.2 KiB (actual file size)
```

#### `--unsafe-quirks`

Enables unsafe quirks that match qemu-img's behavior but introduce security
vulnerabilities. **Use only for compatibility testing, never in production.**

The primary unsafe quirk is "RAW as fallback format" - treating any file
without a recognized format header as a valid raw disk image. This behavior
enables backing file disclosure attacks (CVE-2015-5163, CVE-2024-32498).

```bash
# Default: rejects files without valid format or partition table
imago info /etc/passwd
# Error: Unknown format (no valid disk image header or partition table)

# With --unsafe-quirks: matches qemu-img (insecure)
imago info --unsafe-quirks /etc/passwd
# file format: raw
# virtual size: 2.5 KiB
```

**Warning**: Never use `--unsafe-quirks` when processing untrusted images.
It exists solely for verifying qemu-img output compatibility in test suites.

### Format Specification

| Flag | Description |
|------|-------------|
| `-f FORMAT` / `--format=FORMAT` | Explicitly specify input format |

When format is specified explicitly, imago skips format auto-detection and
parses the file using the specified format's parser directly.

```bash
imago info --format=qcow2 image.qcow2
```

### Backing Chain

| Flag | Description |
|------|-------------|
| `--chain` | Discover and report backing file chain |

See [chain-discovery.md](chain-discovery.md) for details on secure backing
chain discovery.

---

## Configuration File

imago can read configuration from a TOML file at:
- `~/.config/imago/config.toml` (user configuration)
- `/etc/imago/config.toml` (system configuration)

### Example Configuration

```toml
# ~/.config/imago/config.toml

[output]
# Default output format: "human" or "json"
format = "human"

[quirks]
# Disable safe quirks for more intuitive output
ignore_safe = false

# Enable unsafe quirks (NOT RECOMMENDED for production)
# This matches qemu-img's insecure behavior
enable_unsafe = false
```

### Configuration Precedence

Command-line flags override configuration file settings:

1. Command-line flags (highest priority)
2. User configuration (`~/.config/imago/config.toml`)
3. System configuration (`/etc/imago/config.toml`)
4. Built-in defaults (lowest priority)

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `IMAGO_CONFIG` | Override configuration file path |
| `IMAGO_TESTDATA_PATH` | Test data directory (for development) |
| `IMAGO_BINARY_PATH` | Override imago binary path (for testing) |

---

## Security Considerations

### Default Secure Configuration

imago's defaults are chosen for security:

1. **Format validation**: Files must have recognized format headers or valid
   partition tables to be accepted as disk images

2. **Backing file reporting**: Backing file paths are reported but never
   followed (KVM sandbox prevents filesystem access)

3. **Resource limits**: Operations are bounded by guest memory (32MB) and
   timeout mechanisms

### When to Use `--unsafe-quirks`

The only legitimate use case for `--unsafe-quirks` is compatibility testing
against qemu-img output. For example:

```bash
# In test suite: verify imago matches qemu-img for arbitrary files
imago info --unsafe-quirks test-file.bin > imago.out
qemu-img info test-file.bin > qemu.out
diff imago.out qemu.out
```

Never use `--unsafe-quirks` when:
- Processing user-uploaded images
- Running in production environments
- Handling images from untrusted sources

---

## Related Documentation

- [quirks.md](quirks.md) - Detailed quirk documentation and classification
- [format-detection-safety.md](format-detection-safety.md) - Security model
- [chain-discovery.md](chain-discovery.md) - Backing chain discovery
- [output-formats.md](output-formats.md) - Output format details
