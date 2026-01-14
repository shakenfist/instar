# qemu-img Usage in oVirt

Analysis of qemu-img usage patterns across the oVirt codebase, identifying
operations, parameters, and abstraction layers that imago would need to support.

## Summary Statistics

| Component | Files | Operations |
|-----------|-------|------------|
| VDSM | 30+ | info, create, convert, check, measure, commit, map, amend, bitmap |
| ovirt-engine | 7 | convert, measure, info, check (planned) |
| ovirt-imageio | 9 | create, convert, rebase, info, measure, compare, bitmap, map |
| Other repos | 13 | create, convert, info, measure, compare |

## VDSM - Primary qemu-img Wrapper

VDSM provides the most comprehensive abstraction layer for qemu-img operations.

### Wrapper Module: `lib/vdsm/storage/qemuimg.py`

**Binary Path Resolution:**
```python
_qemuimg = cmdutils.CommandPath(
    "qemu-img", "/usr/local/bin/qemu-img", "/usr/bin/qemu-img")
```

**Format Constants:**
```python
class FORMAT:
    QCOW2 = "qcow2"
    QCOW = "qcow"
    QED = "qed"
    RAW = "raw"

class PREALLOCATION:
    OFF = "off"
    METADATA = "metadata"
    FALLOC = "falloc"
    FULL = "full"
```

### Operations

#### info
```bash
qemu-img info --output json [-f FORMAT] [-U] [--backing-chain] <image>
```
- `-U`: Unsafe mode (skip image validation)
- `--backing-chain`: Show entire backing chain
- **Security**: Untrusted images run with resource limits (30s CPU, 1GiB memory)

#### create
```bash
qemu-img create -f FORMAT [-b BACKING] [-F BACKING_FORMAT] \
    [-o preallocation=MODE] [-o compat=VERSION] [-u] <image> [size]
```
- Preallocation modes: off, metadata, falloc, full
- QCOW2 compat versions: 0.10, 1.1

#### convert
```bash
qemu-img convert -f SRC_FMT -O DST_FMT [-p] [-t none] [-T none] \
    [-c] [-W] [-n] [--target-is-zero] [-b BACKING] [--bitmaps] \
    [--skip-broken-bitmaps] [-o OPTIONS] <src> <dst>
```
- `-p`: Progress reporting
- `-t/-T none`: Disable caching
- `-c`: Enable compression
- `-W`: Unordered writes (block devices)
- `-n`: Don't create destination
- `--target-is-zero`: Skip zeroing (qemu-img 5.1+)
- `--bitmaps`: Copy dirty bitmaps

#### check
```bash
qemu-img check --output json -f FORMAT <image>
```
- Return code 3 (leaked clusters) is non-fatal

#### measure
```bash
qemu-img measure --output json -O OUTPUT_FORMAT [--force-share] <image>
```
- Estimate space required for conversion

#### commit
```bash
qemu-img commit -p -t none [-b BASE] [-d] -f FORMAT <top_image>
```
- Merge snapshot chains

#### map
```bash
qemu-img map --output json <image>
```
- Get allocation map

#### amend
```bash
qemu-img amend -o compat=VERSION <image>
```
- Modify QCOW2 compatibility version

#### bitmap operations
```bash
qemu-img bitmap --add [-g GRANULARITY] [--enable] <image> <bitmap>
qemu-img bitmap --remove <image> <bitmap>
qemu-img bitmap --merge <src_bitmap> -b <src_image> -F <src_fmt> <dst_image> <dst_bitmap>
```

### Error Handling Patterns

```python
class InvalidOutput(cmdutils.Error):
    msg = "Command {self.cmd} returned invalid output: {self.out}: {self.reason}"
```

**Security for untrusted images:**
```python
if not trusted_image:
    cmd = cmdutils.prlimit(cmd, cpu_time=30, address_space=GiB)
```

## ovirt-engine

### OVA Extract (`extract_ova.py`)
```bash
qemu-img convert -O <format> <loop_device> <image_path>
```
- Runs as vdsm user via `su -p -c`

### OVA Pack (`pack_ova.py`)
```bash
qemu-img convert -p -T none -O qcow2 <path> <loop_device>
```
- Fixed output format: qcow2
- Progress reporting enabled

### Image Measure (Ansible)
```bash
qemu-img measure -O qcow2 <image_path>
```
- Used for resource planning

### Planned Operations
- `qemu-img check` for QCOW2 validation (not yet implemented)

## ovirt-imageio

### Wrapper Module: `ovirt_imageio/_internal/qemu_img.py`

Simpler wrapper using direct subprocess calls:

```python
def create(path, fmt, size=None, backing_file=None, backing_format=None, quiet=False)
def convert(src, dst, src_fmt, dst_fmt, progress=False, compressed=False)
def unsafe_rebase(path, backing, backing_fmt)
def info(path) -> dict
def measure(path, out_fmt) -> dict
def compare(a, b, format1=None, format2=None, strict=False)
def bitmap_add(path, bitmap)
```

### Custom Exceptions
```python
class ContentMismatch(Exception): pass
class OpenImageError(Exception): pass
```

### Dependencies
```
Requires: qemu-img >= 15:4.2.0
```

## Other oVirt Components

### ovirt-ansible-hosted-engine-setup
```bash
# Convert local VM disk to raw for shared storage
qemu-img convert -f qcow2 -O raw -t none -T none <src> <dst>

# Verify disk copy
qemu-img compare <src> <dst>

# Get appliance disk size
qemu-img info --output=json <path>
```

### ovirt-node-ng-image
```bash
# Create 65GB node disk
qemu-img create -q -f qcow2 <diskimg> 65G
```

### python-ovirt-engine-sdk4
```bash
# Get image info for upload validation
qemu-img info --output json <filename>

# Measure required space for format conversion
qemu-img measure -f <src_fmt> -O <dst_fmt> --output json <image>
```

### ovirt-hosted-engine-setup
```bash
# Transfer image with format conversion
qemu-img convert -n -O raw <src> <dst>
```

## Key Patterns for Imago

### Must Support

1. **Operations**: info, create, convert, check, measure, commit, map, amend, bitmap
2. **Formats**: raw, qcow2, qcow, qed (vmdk for import scenarios)
3. **Output**: JSON format for info, measure, check, map
4. **Progress**: Percentage-based progress for convert, commit
5. **Caching**: `-t none -T none` for direct I/O
6. **Preallocation**: off, metadata, falloc, full
7. **QCOW2 compat**: 0.10 and 1.1 versions
8. **Bitmaps**: Add, remove, merge, enable/disable

### Security Considerations

1. **Resource limits**: CPU time and memory limits for untrusted images
2. **Unsafe mode**: `-U` flag for images that may be in use
3. **User context**: Operations often run as vdsm:kvm user

### Error Handling

1. **Check return codes**: 0=success, 1=errors, 2=corruption, 3=leaks
2. **JSON validation**: Verify required fields in output
3. **Progress parsing**: Handle `(XX.XX/100%)` format

### Performance Patterns

1. **Unordered writes**: `-W` for block devices
2. **Target is zero**: `--target-is-zero` for preallocated targets
3. **No create**: `-n` when destination already exists
4. **Cache modes**: Direct I/O (`none`) for production workloads
