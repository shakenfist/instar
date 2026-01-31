# qemu-img Quirks

This document describes known behaviors in qemu-img that differ from what one
might expect, and how imago handles these cases.

## Quirk Classification: Safe vs Unsafe

Quirks are classified into two categories based on their security implications:

### Safe Quirks

Safe quirks affect output formatting or calculation methods but do not introduce
security vulnerabilities. Examples include:

- Size rounding (to block or sector boundaries)
- Number formatting (banker's rounding, significant figures)
- VHD size calculation methods

imago **mimics safe quirks by default** for qemu-img compatibility. Use
`--ignore-quirks` to get more intuitive behavior.

### Unsafe Quirks

Unsafe quirks are behaviors that can enable security vulnerabilities. The
primary example is:

- **RAW as fallback format** - Treating any unrecognized file as a valid
  raw disk image, which enables backing file disclosure attacks

imago **does NOT mimic unsafe quirks by default**. Instead, imago applies
additional validation (e.g., requiring MBR/GPT partition tables for raw images).
Use `--unsafe-quirks` to match qemu-img's insecure behavior for compatibility
testing.

### Summary

| Flag | Safe Quirks | Unsafe Quirks |
|------|-------------|---------------|
| (default) | Enabled (qemu-img compatible) | Disabled (secure) |
| `--ignore-quirks` | Disabled (intuitive output) | Disabled (secure) |
| `--unsafe-quirks` | Enabled (qemu-img compatible) | Enabled (insecure) |

See [configuration.md](configuration.md) for full flag documentation.

---

## QCOW2 disk_size Calculation

**Classification: Safe Quirk**

### Observed Behavior

For QCOW2 files, `qemu-img info` reports a `disk size` that may differ from the
actual file size on disk. For example, with a generated QCOW2 v2 test file:

- Actual file size (from `stat` or `ls -l`): 196616 bytes
- qemu-img reported disk size: 197120 bytes (192 KiB)
- Difference: 504 bytes

### Root Cause

qemu-img calculates the "disk size" based on the QCOW2 internal structure,
specifically by finding the highest allocated offset in the file's metadata
(L1 table, refcount table, etc.) and rounding up to a sector boundary (512
bytes).

For the test file:
- L1 table offset: 196608 (0x30000)
- L1 table has 1 entry (8 bytes)
- Actual file end: 196608 + 8 = 196616 bytes
- qemu-img calculation: 196608 + 512 = 197120 bytes (sector-aligned)

### Why This Happens

qemu-img appears to calculate "disk size" as the expected size based on the
image's internal structure, not the actual filesystem size. This calculation:

1. Finds the highest used offset in metadata structures
2. Rounds up to the nearest sector boundary (512 bytes)
3. Reports this as the "disk size"

This approach makes sense for images that might be sparse or have trailing
allocations, but can report larger sizes than the actual file.

### imago Behavior

**Default behavior**: imago matches qemu-img by calculating disk size based
on the image's internal metadata structure, rounded up to sector boundaries.
This ensures drop-in replacement compatibility.

**With `--ignore-quirks` flag**: imago reports the actual file size from the
underlying storage, matching what `stat` or `ls -l` reports.

### Why Match qemu-img?

Since imago aims to be a drop-in replacement for `qemu-img info`, matching
the output exactly (including this calculation) reduces friction for users
migrating from qemu-img. Scripts and tools that parse qemu-img output will
work unchanged.

The `--ignore-quirks` flag provides an escape hatch for users who need the
true filesystem size.

### Test Implications

The test file `qcow2_v2.qcow2` in imago-testdata was generated with qemu-img
(`qemu-img create -f qcow2 -o compat=0.10 ...`). By matching qemu-img's
calculation, tests can perform exact output comparison.

## Block-Rounded Disk Size

**Classification: Safe Quirk**

### Observed Behavior

qemu-img reports "disk size" rounded up to filesystem block boundaries (4096
bytes), not the actual file size.

For the QCOW2 v2 test file:
- Actual file size: 196616 bytes
- qemu-img disk size: 200704 bytes (196 KiB)
- Calculation: ceil(196616 / 4096) * 4096 = 49 * 4096 = 200704

### imago Behavior

**Default behavior**: imago matches qemu-img by rounding file size up to
4096-byte blocks.

**With `--ignore-quirks` flag**: imago reports the actual file size.

## Human-Readable Size Formatting

**Classification: Safe Quirk**

### Observed Behavior

qemu-img uses `%0.3g` printf format (3 significant figures) for human-readable
sizes. This rounds to 3 significant figures, with the number of decimal places
depending on the magnitude:

**For values >= 100** (displayed as integers):

Rounds to nearest integer using "round half to even" (banker's rounding):
- 126.998 GiB → "127 GiB" (rounds up from 126.998)
- 192.5 KiB → "192 KiB" (rounds to even from 192.5)
- 256.5 KiB → "256 KiB" (rounds to even from 256.5)
- 127.5 GiB → "128 GiB" (rounds to even from 127.5)

**For values 10-99** (displayed with 1 decimal place):

Standard rounding applies:
- 20.6875 MiB → "20.7 MiB" (rounds from 20.6875)
- 15.44 KiB → "15.4 KiB" (rounds from 15.44)

### Technical Details

This behavior stems from C printf's `%0.3g` format which:
1. Rounds to 3 significant figures using "round half to even" (banker's rounding)
2. Removes trailing zeros after the decimal point
3. For integer results, displays no decimal point

The key distinction is at exact midpoints (like 192.5): C rounds to the nearest
even number (192), while Rust's default `round()` rounds away from zero (193).

### imago Behavior

**Default behavior**: imago matches qemu-img's formatting using banker's rounding:
- Values >= 100: round to nearest integer (ties to even)
- Values 10-99: round to 1 decimal place (ties to even)
- Values 1-9: round to 2 decimal places (ties to even)
- Values < 1: round to 3 decimal places (ties to even)

**With `--ignore-quirks` flag**: imago uses consistent rounding with 1 decimal
place when the value is not a whole number (e.g., "192.5 KiB" instead of
"192 KiB").

## Child Node File Length

**Classification: Safe Quirk**

### Observed Behavior

In qemu-img 8.0+, the Child node '/file' section reports a "file length" (human)
or "virtual-size" (JSON) that may differ from the actual filesystem size.

qemu-img reports the **larger** of:
1. The actual filesystem file size
2. The calculated size based on internal metadata (e.g., L1 table offset
   rounded up to sector boundary for QCOW2)

For files with data beyond the metadata structures (like real disk images),
qemu-img reports the actual file size. For minimal files where the metadata
calculation exceeds the actual size (like empty test images), it reports the
metadata-based calculation.

### Example

For a minimal QCOW2 v2 test file:
- Actual file size: 196616 bytes
- L1 table calculation: (196608 + 512) = 197120 bytes
- qemu-img file length: max(196616, 197120) = 197120 bytes

For a real disk image (cirros):
- Actual file size: 21692416 bytes
- L1 table calculation: much smaller (metadata is at the start)
- qemu-img file length: max(21692416, calc) = 21692416 bytes

### imago Behavior

**Default behavior**: imago matches qemu-img by reporting the larger of the
actual file size and the internal metadata calculation.

**With `--ignore-quirks` flag**: imago reports the actual filesystem size.

## Summary of `--ignore-quirks` Effects

When `--ignore-quirks` is specified:

| Field | Default (qemu-img compatible) | With --ignore-quirks |
|-------|------------------------------|---------------------|
| disk size | Block-rounded (4096 bytes) | Actual file size |
| file length | max(actual, metadata calc) | Actual file size |
| Size formatting | 3 significant figures | 1 decimal place |

## File Sparseness and Git

**Classification: Safe Quirk** (environmental, not a qemu-img behavior)

### Observed Behavior

qemu-img's reported "disk size" depends on the actual allocation of sparse
files on disk. When disk images are transferred through git (clone, fetch),
sparse holes may be filled with zeros, increasing the reported disk size.

For example, the `iotest-dynamic-1G.vhdx` file:
- Original (sparse): disk size 66.1 MiB
- After git clone: disk size 100 MiB (holes filled with zeros)
- After `fallocate -d`: disk size 66.1 MiB (holes restored)

### Root Cause

Git stores file contents as blobs and does not preserve sparse file semantics.
When git writes a file during checkout, it writes all bytes sequentially,
effectively "filling in" sparse holes with actual zero bytes. This increases
the file's allocated blocks on disk.

### CI/Testing Implications

Test baselines are generated with sparse files. When the testdata repository
is cloned in CI, the files may lose sparseness, causing disk_size mismatches.

### Solution

After cloning the testdata repository, restore sparse holes using
`cp --sparse=always` which is more robust than `fallocate -d`:

```bash
find downloaded/ -type f \( \
    -name "*.qcow2" -o \
    -name "*.vmdk" -o \
    -name "*.vhd" -o \
    -name "*.vhdx" -o \
    -name "*.img" \
\) -print0 | while IFS= read -r -d '' file; do
    cp --sparse=always "$file" "$file.sparse"
    mv "$file.sparse" "$file"
done
```

**Why `cp --sparse=always` instead of `fallocate -d`?**

`fallocate -d` (FALLOC_FL_PUNCH_HOLE) can only punch holes in contiguous
zero-filled regions that are aligned to filesystem block boundaries. Files
with partial zero blocks (blocks containing mostly zeros but a few non-zero
bytes) cannot have those regions converted to holes.

`cp --sparse=always` reads the file content and writes a new file, skipping
zero-filled blocks entirely. This correctly handles files with complex sparse
patterns where `fallocate -d` would leave extra blocks allocated.

### Test Framework Handling

Even with `cp --sparse=always`, re-sparsified files may not have identical
block allocation patterns to the original. Different filesystems, kernel
versions, or sparse detection algorithms can result in significantly different
allocation patterns.

For this reason, the test comparison framework (`tests/helpers/comparators.py`)
**looks up the actual disk size** from the filesystem at test time using
`os.stat().st_blocks * 512` and substitutes this value into the expected
output before comparison. This ensures:

1. Tests compare against the filesystem's actual view of the file
2. No reliance on potentially stale baseline values for disk size
3. Exact matching instead of arbitrary tolerance thresholds

This approach is more scientifically correct than using tolerance, because:
1. `actual-size` reflects filesystem allocation, not image content
2. We're testing that imago correctly reports what the filesystem says
3. Both imago and the test framework query the same filesystem state

### Note

This is not a qemu-img quirk per se, but rather a filesystem/git interaction
that affects qemu-img output consistency in CI environments.

## VHD Virtual Size Calculation

**Classification: Safe Quirk**

### Observed Behavior

qemu-img calculates VHD virtual size differently depending on the creator
application that produced the VHD file. The VHD footer contains both a
"current size" field (explicit virtual size in bytes) and CHS geometry values
(cylinders, heads, sectors per track).

**For Virtual PC and legacy QEMU VHDs** (creator_app = "vpc " or "qemu"):

qemu-img calculates virtual size from CHS geometry:
```
virtual_size = cylinders × heads × sectors_per_track × 512
```

**For modern applications** (Hyper-V, Disk2vhd, XenServer, Azure, etc.):

qemu-img uses the disk_size field directly from the VHD footer.

### Example

For the `virtualpc-dynamic.vhd` test image (created by Virtual PC):
- Footer disk_size field: 136,365,211,648 bytes
- CHS geometry: 65,278 cylinders × 16 heads × 255 sectors
- CHS-calculated size: 65,278 × 16 × 255 × 512 = 136,363,130,880 bytes
- qemu-img reports: 136,363,130,880 bytes (CHS calculation)

The difference (2,080,768 bytes) exists because Virtual PC's geometry algorithm
cannot exactly represent the requested size, so it rounds down to the nearest
CHS-representable value.

### Why This Matters

Virtual PC and original QEMU create VHD files that rely on CHS geometry for
compatibility with legacy systems. Using the disk_size field directly for
these images would report a larger virtual size than the geometry can address,
potentially causing data corruption if writes exceed the CHS-addressable range.

### Maximum CHS Geometry

When CHS geometry reaches maximum values (65,535 × 16 × 255 = 267,382,800
sectors = ~127 GiB), qemu-img falls back to using the disk_size field
regardless of creator application. This prevents truncation for large disks.

### Known Creator Applications

| Creator App | Size Method | Application |
|-------------|-------------|-------------|
| `vpc `      | CHS         | Microsoft Virtual PC |
| `qemu`      | CHS         | QEMU (legacy) |
| `qem2`      | disk_size   | QEMU (modern) |
| `win `      | disk_size   | Microsoft Hyper-V |
| `d2v `      | disk_size   | Disk2vhd |
| `tap\0`     | disk_size   | XenServer |
| `CTXS`      | disk_size   | XenConverter |
| `wa\0\0`    | disk_size   | Microsoft Azure |

### imago Behavior

**Default behavior**: imago matches qemu-img by checking the creator_app field
and using CHS calculation for "vpc " and "qemu" creators (unless CHS is at
maximum), or disk_size field for all others.

**With `--ignore-quirks` flag**: Currently no change; the VHD size calculation
always matches qemu-img for maximum compatibility.

## RAW as Fallback Format

**Classification: Unsafe Quirk** - This behavior enables security vulnerabilities.

### Observed Behavior

qemu-img treats **any** file that does not match a known format's magic number
as a "raw" disk image. This includes:

- Actual raw disk images (with MBR/GPT partition tables)
- Plain text files
- Binary data files
- Corrupted or truncated images
- Random garbage

For example, a simple text file:

```bash
$ echo "This is just a plain text file." > /tmp/test.txt
$ qemu-img info /tmp/test.txt
image: /tmp/test.txt
file format: raw
virtual size: 512 B (512 bytes)
disk size: 4 KiB
```

### Why This Matters

This behavior has important implications:

1. **No format validation**: qemu-img cannot distinguish between a genuine raw
   disk image and arbitrary data. A user could upload a PDF, JPEG, or executable
   and qemu-img would happily call it a "raw" disk image.

2. **Testing considerations**: When testing format detection, any file that
   fails to match known formats will be reported as "raw" rather than
   "unknown" or generating an error.

### Security Implications: The Root Cause of Backing File Attacks

**This "raw as fallback" behavior is the fundamental design flaw that enables
backing file disclosure attacks (CVE-2015-5163, CVE-2024-32498, etc.).**

Consider what happens when qemu-img processes a QCOW2 image with
`backing_file = "/etc/shadow"`:

1. qemu-img opens the QCOW2 image and parses its header
2. qemu-img sees the backing file reference to `/etc/shadow`
3. qemu-img opens `/etc/shadow` and tries to detect its format
4. `/etc/shadow` has no recognized magic number (it's a text file)
5. qemu-img treats `/etc/shadow` as a "raw" disk image
6. qemu-img reads the file contents as disk data

If qemu-img instead **rejected** files that don't match any known disk image
format, the attack would fail at step 5. The backing file would be rejected
as "not a valid disk image" rather than being slurped up as "raw" data.

This design choice - treating unknown files as valid raw images rather than
rejecting them - is what transforms a simple path reference into a data
exfiltration vulnerability. A more defensive design would require backing
files to have recognizable disk image headers (QCOW2, VMDK, VHD, or at minimum
a valid MBR/GPT partition table for raw images).

**Note**: imago avoids this vulnerability entirely through its KVM sandbox
architecture - the guest cannot open arbitrary files regardless of format
detection behavior. See [format-detection-safety.md](format-detection-safety.md)
for details.

### Cloud Environment Implications

In cloud environments (OpenStack, etc.), format validation cannot rely solely
on qemu-img. OpenStack's Glance uses oslo.utils `format_inspector` which
detects GPT/MBR partition tables to distinguish "actual disk images" from
"files we don't recognize."

### Comparison with oslo.utils format_inspector

oslo.utils takes a different approach:

| File Type | qemu-img | oslo.utils |
|-----------|----------|------------|
| MBR-partitioned disk | raw | gpt (detects MBR) |
| GPT-partitioned disk | raw | gpt |
| FAT filesystem (no partition) | raw | raw |
| Plain text file | raw | raw |
| Random garbage | raw | raw |
| Corrupted QCOW2 | raw (usually) | error or raw |

oslo.utils can distinguish between "files with valid partition tables" (likely
real disk images) and "files we don't recognize" (both labeled "raw" but with
different confidence levels).

### imago Behavior

**Default behavior (secure)**: imago requires files detected as "raw" to have
a valid partition table (MBR or GPT). Files without recognized format headers
AND without valid partition tables are rejected as "unknown format" rather
than being silently accepted as raw images.

This prevents the backing file disclosure attacks described above, because
`/etc/shadow` would be rejected as "not a valid disk image" rather than
being treated as a raw disk.

**With `--unsafe-quirks` flag**: imago matches qemu-img's behavior, treating
any unrecognized file as a valid raw image. This is required for exact
qemu-img output compatibility but should only be used in controlled testing
environments, never in production.

**Partition table detection**: imago checks for:
- **MBR**: Valid 0xAA55 signature at offset 510-511, with at least one
  partition entry having a valid boot flag (0x00 or 0x80)
- **GPT**: Protective MBR with partition type 0xEE, followed by valid
  GPT header at LBA 1

See [format-coverage.md](format-coverage.md) for comparison with oslo.utils
format_inspector.

### Test Images

The imago-testdata repository includes several test cases for this behavior:

- `raw-random-garbage.raw` - Random bytes (detected as raw)
- `raw-misleading-header.raw` - QCOW2 magic but invalid header (detected as raw)
- `raw-minimal-1byte.raw` - Single byte file (detected as raw)

## Future Additions

Additional quirks will be documented here as they are discovered during
compatibility testing.
