# qemu-img Quirks

This document describes known behaviors in qemu-img that differ from what one
might expect, and how imago handles these cases.

## QCOW2 disk_size Calculation

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

### Observed Behavior

qemu-img uses `%0.3g` printf format (3 significant figures) for human-readable
sizes. This can display values smaller than the actual size.

For example:
- 197120 bytes / 1024 = 192.5 KiB
- With 3 significant figures: "192 KiB" (truncates to integer for values >= 100)

### imago Behavior

**Default behavior**: imago matches qemu-img's 3-significant-figure formatting.
For values >= 100, this floors to the nearest integer.

**With `--ignore-quirks` flag**: imago uses more accurate formatting, showing
1 decimal place when the value is not a whole number (e.g., "192.5 KiB").

## Summary of `--ignore-quirks` Effects

When `--ignore-quirks` is specified:

| Field | Default (qemu-img compatible) | With --ignore-quirks |
|-------|------------------------------|---------------------|
| disk size | Block-rounded (4096 bytes) | Actual file size |
| file length | L1 table calculation | Actual file size |
| Size formatting | 3 significant figures | 1 decimal place |

## Future Additions

Additional quirks will be documented here as they are discovered during
compatibility testing.
