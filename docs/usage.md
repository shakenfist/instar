# qemu-img Usage Analysis

Analysis of qemu-img usage patterns across oVirt and Proxmox codebases,
identifying operations, parameters, and abstraction layers that imago would
need to support.

## Overall Summary

| Platform | Components | Primary Operations |
|----------|------------|-------------------|
| oVirt | VDSM, ovirt-engine, ovirt-imageio | info, create, convert, check, measure, commit, map, amend, bitmap |
| Proxmox | pve-storage, qemu-server, pve-qemu | convert, create, info, measure, resize, snapshot, dd, rebase, commit |

---

# oVirt

Analysis of qemu-img usage patterns across the oVirt codebase.

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

---

# Proxmox

Analysis of qemu-img usage patterns across the Proxmox VE codebase.

## Summary Statistics

| Component | Files | Operations |
|-----------|-------|------------|
| pve-storage | 6 | create, info, measure, resize, snapshot, commit, rebase |
| qemu-server | 5 | convert, dd, snapshot |
| pve-qemu | 12 patches | dd (extended), info, snapshot |
| proxmox-backup | 0 | Uses custom PBS block driver instead |
| Other (Ceph) | 10+ | create, convert, info, compare, bench, snapshot |

## pve-qemu - QEMU Patches

Proxmox extends qemu-img through patches rather than wrapper scripts.

### Extended `qemu-img dd` Command

**Location:** `debian/patches/pve/0009-PVE-Up-qemu-img-dd-add-osize-and-read-from-to-stdin-.patch`

```bash
qemu-img dd [--image-opts] [-U] [-f FMT] [-O OUTPUT_FMT] [-n] [-l SNAPSHOT]
    [bs=BLOCK_SIZE] [count=BLOCKS] [skip=BLOCKS] [osize=OUTPUT_SIZE]
    [isize=INPUT_SIZE] if=INPUT of=OUTPUT
```

**PVE-specific extensions:**
- `osize`: Output size parameter for stdin/stdout piping
- `isize`: Input size for writing small images to larger targets
- `-n`: Skip target volume creation (for pre-created volumes)
- `-l`: Load snapshot during dd operation
- Stdin/stdout support for raw format streaming

**Data structures:**
```c
struct DdInfo {
    unsigned int flags;
    int64_t count;
    int64_t osize;  // PVE extension
    int64_t isize;  // PVE extension
};
```

### Snapshot Info Return Code

**Location:** `debian/patches/pve/0008-PVE-Up-qemu-img-return-success-on-info-without-snaps.patch`

Modified `qemu-img info` to return success (0) instead of failure (1)
when no snapshots exist.

## pve-storage - Perl Wrapper Module

### Wrapper Module: `PVE/Storage/Common.pm`

**qemu_img_create:**
```perl
sub qemu_img_create {
    my ($fmt, $size, $path, $options) = @_;
    my $cmd = ['/usr/bin/qemu-img', 'create'];
    push @$cmd, '-o', "preallocation=$options->{preallocation}"
        if defined($options->{preallocation});
    push @$cmd, '-f', $fmt, $path, "${size}K";
    run_command($cmd, errmsg => "unable to create image");
}
```

**qemu_img_create_qcow2_backed:**
```perl
sub qemu_img_create_qcow2_backed {
    my ($path, $backing_path, $backing_format, $options) = @_;
    my $cmd = [
        '/usr/bin/qemu-img', 'create',
        '-F', $backing_format,
        '-b', $backing_path,
        '-f', 'qcow2',
        $path,
    ];
    my $opts = ['extended_l2=on', 'cluster_size=128k'];
    push @$opts, "preallocation=$options->{preallocation}"
        if defined($options->{preallocation});
    push @$cmd, '-o', join(',', @$opts) if @$opts > 0;
    run_command($cmd, errmsg => "unable to create image");
}
```

**Default QCOW2 options:**
- `extended_l2=on`: Extended L2 table support
- `cluster_size=128k`: 128KB clusters (vs default 64KB)

**qemu_img_info:**
```perl
sub qemu_img_info {
    my ($filename, $file_format, $timeout, $follow_backing_files) = @_;
    my $cmd = ['/usr/bin/qemu-img', 'info', '--output=json', $filename];
    push $cmd->@*, '-f', $file_format if $file_format;
    push $cmd->@*, '--backing-chain' if $follow_backing_files;
    return run_qemu_img_json($cmd, $timeout);
}
```

**qemu_img_measure:**
```perl
sub qemu_img_measure {
    my ($size, $fmt, $timeout, $options) = @_;
    my $cmd = ['/usr/bin/qemu-img', 'measure', '--output=json',
               '--size', "${size}K", '-O', $fmt];
    return run_qemu_img_json($cmd, $timeout);
}
```

**qemu_img_resize:**
```perl
sub qemu_img_resize {
    my ($path, $format, $size, $preallocation, $timeout) = @_;
    my $cmd = ['/usr/bin/qemu-img', 'resize'];
    push $cmd->@*, "--preallocation=$preallocation" if $preallocation;
    push $cmd->@*, '-f', $format, $path, $size;
    $timeout = 10 if !$timeout;
    run_command($cmd, timeout => $timeout);
}
```

### Snapshot Operations: `PVE/Storage/Plugin.pm`

```perl
# Create snapshot
my $cmd = ['/usr/bin/qemu-img', 'snapshot', '-c', $snap, $path];

# Rollback to snapshot
my $cmd = ['/usr/bin/qemu-img', 'snapshot', '-a', $snap, $path];

# Delete snapshot
$cmd = ['/usr/bin/qemu-img', 'snapshot', '-d', $snap, $path];

# Commit changes to backing file
$cmd = ['/usr/bin/qemu-img', 'commit', $childpath];

# Rebase to new backing file
$cmd = ['/usr/bin/qemu-img', 'rebase', '-b', $rel_parent_path,
        '-F', 'qcow2', '-f', 'qcow2', $childpath];
```

### Supported Formats

```perl
my @checked_qemu_img_formats = qw(raw qcow qcow2 qed vmdk cloop);
```

**Format restrictions:**
- Resize: raw, qcow2 only
- Snapshots: qcow2, qed only

### Security Validation for Untrusted Images

```perl
if ($untrusted) {
    if (my $format_specific = $info->{'format-specific'}) {
        if ($format_specific->{type} eq 'qcow2' &&
            $format_specific->{data}->{"data-file"}) {
            die "$filename: 'data-file' references are not allowed!\n";
        } elsif ($format_specific->{type} eq 'vmdk') {
            my $extents = $format_specific->{data}->{extents};
            die "$filename: multiple extents are not allowed!\n"
                if scalar($extents->@*) > 1;
        }
    }
}
```

## qemu-server - VM Disk Operations

### Image Conversion: `PVE/QemuServer/QemuImage.pm`

```perl
sub convert {
    my ($src_volid, $dst_volid, $size, $opts) = @_;
    my $cmd = [];
    push @$cmd, '/usr/bin/qemu-img', 'convert', '-p', '-n';
    push @$cmd, '-l', "snapshot.name=$snapname" if $snapname;
    push @$cmd, '-t', 'none' if $dst_scfg->{type} eq 'zfspool';
    push @$cmd, '-T', $cachemode if defined($cachemode);
    push @$cmd, '-r', "${bwlimit}K" if defined($bwlimit);
    # ...
}
```

**Features:**
- Progress reporting with `-p` and custom parser
- Bandwidth limiting with `-r`
- Snapshot support with `-l snapshot.name=`
- Cache modes: `none` for ZFS, `unsafe` otherwise
- Support for `--target-image-opts`

### DD-based EFI Disk Copy: `PVE/QemuServer.pm`

```perl
my $cmd = ['qemu-img', 'dd', '-n', '-f', $src_format, '-O', $dst_format];
push $cmd->@*, '-l', $snapname if $method eq 'qemu';
push $cmd->@*, "bs=$bs", "osize=$size", "if=$src_path", "of=$dst_path";
```

- Block size: 1MB for better Ceph performance
- Used specifically for EFI disk cloning

### Use Cases

1. **Disk cloning**: `clone_disk()` → `QemuImage::convert()`
2. **Disk import**: `ImportDisk::do_import()` → `QemuImage::convert()`
3. **EFI initialization**: `OVMF.pm` → `QemuImage::convert()`
4. **Backup restore**: `restore_vm_volumes()` → `QemuImage::convert()`

## proxmox-backup - Custom Block Driver

Proxmox Backup Server does **not** use qemu-img. Instead, it implements
a custom QEMU block driver (`pbs:` protocol) for direct archive access.

**PBS block driver URI format:**
```
pbs:repository=<repo>,snapshot=<snap>,archive=<archive>,password=<pw>
```

**Reason:** Enables streaming from backup archives without intermediate
image files or format conversion.

## Other Components (Ceph Integration)

### Test Scripts

**RBD Migration Tests:** `ceph/qa/workunits/rbd/cli_migration.sh`
```bash
qemu-img convert -f raw -O qcow rbd:rbd/${image} ${TEMPDIR}/${image}.qcow
qemu-img create -f qcow2 ${TEMPDIR}/${image}.qcow2 1G
qemu-img bench -f qcow2 -w -c 65536 -d 16 --pattern 65 -s 4096 ${image}.qcow2
qemu-img snapshot -c "snap1" ${image}.qcow2
qemu-img compare ${TEMPDIR}/large.raw rbd:rbd/${dest_image}
```

### Python Test Framework

**Location:** `qemu/tests/qemu-iotests/iotests.py`
```python
qemu_img_args = os.environ.get('QEMU_IMG', 'qemu-img').strip().split(' ')

def qemu_img(*args):
    '''Run qemu-img and return the exit code'''
    return subprocess.call(qemu_img_args + list(args))

def qemu_img_pipe(*args):
    '''Run qemu-img and return its output'''
    return subprocess.Popen(qemu_img_args + list(args),
                           stdout=subprocess.PIPE).communicate()[0]

def compare_images(img1, img2):
    return qemu_img('compare', '-f', imgfmt, '-F', imgfmt, img1, img2) == 0
```

## Key Patterns for Imago (Proxmox)

### Must Support

1. **Operations**: convert, create, info, measure, resize, snapshot, dd, rebase, commit
2. **Formats**: raw, qcow2, qcow, qed, vmdk, cloop
3. **PVE dd extensions**: osize, isize, stdin/stdout, -n, -l snapshot
4. **QCOW2 options**: extended_l2, cluster_size=128k, preallocation
5. **Progress**: `-p` with percentage parsing
6. **Bandwidth limiting**: `-r` option

### Storage Backend Integration

| Backend | Special Handling |
|---------|-----------------|
| ZFS | Cache mode: none |
| RBD/Ceph | 1MB block size for dd |
| iSCSI | Path conversion to QEMU format |
| LVM | Supports qcow2 snapshots on LV |

### Command-Line Options Summary

| Option | Purpose | Used By |
|--------|---------|---------|
| `-p` | Progress reporting | convert |
| `-n` | Skip target creation | convert, dd |
| `-f` | Source format | all |
| `-O` | Output format | convert, dd |
| `-t`/`-T` | Cache mode | convert |
| `-r` | Bandwidth limit | convert |
| `-l` | Load snapshot | convert, dd |
| `-b`/`-F` | Backing file | create, rebase |
| `-o` | Format options | create |
| `--output=json` | JSON output | info, measure |
| `--backing-chain` | Follow backing | info |
| `bs=`, `osize=`, `isize=` | DD parameters | dd |

---

# Combined Requirements for Imago

## Operations Matrix

| Operation | oVirt | Proxmox | Priority |
|-----------|-------|---------|----------|
| info | ✓ | ✓ | High |
| create | ✓ | ✓ | High |
| convert | ✓ | ✓ | High |
| measure | ✓ | ✓ | High |
| check | ✓ | - | Medium |
| commit | ✓ | ✓ | Medium |
| rebase | ✓ | ✓ | Medium |
| snapshot | - | ✓ | Medium |
| resize | - | ✓ | Medium |
| dd | - | ✓ (extended) | Medium |
| map | ✓ | - | Low |
| amend | ✓ | - | Low |
| bitmap | ✓ | - | Low |
| compare | ✓ | ✓ (tests) | Low |
| bench | - | ✓ (tests) | Low |

## Security Requirements

1. **Resource limits**: Both platforms limit CPU/memory for untrusted images
2. **Format validation**: Block data-file references, multiple extents
3. **User context**: Run as specific user (vdsm:kvm, www-data)
4. **Timeout handling**: Support operation timeouts

## Output Formats

- JSON output required for: info, measure, check, map
- Progress output: `(XX.XX/100%)` format parsing
