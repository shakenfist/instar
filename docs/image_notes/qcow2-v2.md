# qcow2-v2 Test Image

**Image ID:** `qcow2-v2`
**Path:** `downloaded/edge-cases/qcow2_v2.qcow2`
**Format:** QCOW2 version 2 (compat=0.10)

## Creation

Generated with qemu-img:
```bash
qemu-img create -f qcow2 -o compat=0.10 qcow2_v2.qcow2 1M
```

## File Characteristics

- Actual file size: 196,616 bytes
- L1 table offset: 196,608 (0x30000)
- L1 table entries: 1 (8 bytes)
- Cluster size: 65,536 bytes

## Quirks Discovered

### 1. L1 Table-Based File Length Calculation

**Observed:** qemu-img reports `file length: 192 KiB (197120 bytes)` but the
actual file is 196,616 bytes.

**Analysis:**
- L1 table end: 196,608 + 8 = 196,616 bytes
- qemu-img calculation: ceil(196,616 / 512) × 512 = 197,120 bytes
- qemu-img rounds the L1 table end to a 512-byte sector boundary

**Implementation:** imago calculates the L1 table end and rounds to 512-byte
sectors for the "file length" field. Uses `max(actual_size, calculated)` to
handle files where actual content extends beyond the L1 table.

**Documentation:** [docs/quirks.md](../quirks.md#qcow2-disk_size-calculation)

### 2. Block-Rounded Disk Size

**Observed:** qemu-img reports `disk size: 196 KiB` (200,704 bytes) but the
actual file is 196,616 bytes.

**Analysis:**
- Actual file: 196,616 bytes
- Block-rounded: ceil(196,616 / 4096) × 4096 = 49 × 4096 = 200,704 bytes
- qemu-img rounds up to 4096-byte filesystem blocks

**Implementation:** imago rounds file size up to 4096-byte blocks for the
"disk size" field.

**Documentation:** [docs/quirks.md](../quirks.md#block-rounded-disk-size)

### 3. Integer Truncation for Values >= 100

**Observed:** qemu-img reports `file length: 192 KiB` for 197,120 bytes
(192.5 KiB), truncating the .5 instead of rounding to 193.

**Analysis:**
- 197,120 / 1024 = 192.5 KiB
- qemu-img's `%0.3g` format with 3 significant figures
- For values >= 100, the result is an integer, and C printf truncates
- Rust's `round()` would give 193, so imago uses `floor()` for this range

**Implementation:** imago uses floor() for values >= 100 to match qemu-img's
observed behavior.

**Documentation:** [docs/quirks.md](../quirks.md#human-readable-size-formatting)

## Test Value

This image is ideal for testing quirks because:
1. It's minimal (no actual data, just metadata)
2. The L1 table end is slightly less than a sector boundary
3. The resulting KiB value (192.5) is exactly at a rounding midpoint
