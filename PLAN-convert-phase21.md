# Phase 21: Large Cluster Output (>64KB) for QCOW2

## Status: Complete

All sub-steps (21a–21e) implemented and tested. QCOW2 output
supports cluster sizes from 512 bytes to 2MB. Six integration
tests validate round-trip fidelity for 128KB and 2MB clusters
with both uncompressed and compressed output.

Non-QCOW2 format limits documented:
- VMDK: 64KB grain size (fixed, 128 sectors)
- VHD: 2MB block size (fixed)
- VHDX: 32MB block size (fixed)

## Problem

QCOW2 output is currently limited to cluster sizes 512–65536
bytes. The VMM rejects `--cluster-size` values above 65536 (line
4166 of vmm/main.rs). This means `imago convert -O qcow2
--cluster-size 131072` fails, even though imago can **read**
images with cluster sizes up to 2MB (MAX_CLUSTER_SIZE).

The limitation matters because:
- Real-world images use large clusters (production Shaken Fist
  images use 2MB clusters)
- Round-trip fidelity: converting a 2MB-cluster image to QCOW2
  currently forces a downgrade to 64KB clusters
- qemu-img supports output cluster sizes up to 2MB

## Root Cause

The QCOW2 output path uses fixed 64KB (MAX_SECTOR_SIZE) buffers
for structures that are one-cluster-sized in the QCOW2 spec:

| Buffer | Current size | Required size | Purpose |
|--------|-------------|---------------|---------|
| BUF_DATA | 64KB | cluster_size | Data read/write buffer |
| BUF_L2_OUT | 64KB | cluster_size | Output L2 table under construction |
| BUF_HEADER | 64KB | cluster_size | Header cluster (written once) |
| BUF_REFCOUNT | 64KB | cluster_size | Refcount block buffer |

With 2MB clusters, the naive approach needs 5 × 2MB = 10MB of
fixed buffers plus 2MB+64KB for the compressed buffer, totalling
~12.1MB — nearly all of the 12.4MB usable scratch. After adding
input device caches (128KB per device), staging buffer (2MB for
decompression), compressor state (~300KB), L1 table, and refcount
array, the memory is exhausted.

## Design

### Key insight: buffer reuse by phase

The convert-to-QCOW2 operation has distinct phases:

1. **Header write** — uses BUF_HEADER (once, at the start)
2. **Data write loop** — uses BUF_DATA, BUF_L2_OUT,
   BUF_COMPRESSED (for compressed output)
3. **Refcount write** — uses BUF_REFCOUNT (at the end)
4. **Header rewrite** — uses BUF_HEADER (once, at the end)

BUF_HEADER and BUF_REFCOUNT are never used simultaneously with
each other or with the data loop. BUF_HEADER is only used at
start and end. BUF_REFCOUNT is only used at the end. This means
we can **overlay** them on the same memory.

### Revised scratch layout for large clusters

Replace the fixed-size buffer constants with a dynamic layout
computed at runtime based on the output cluster size:

```
SCRATCH_MEM_BASE (0x300000):
  BUF_COMPRESSED  : COMPRESSED_BUF_SIZE (cluster_size + 64KB)
  BUF_MULTIPURPOSE: cluster_size (shared by header/L2/refcount)
  BUF_DATA        : cluster_size (data read/write)
  [dynamic region]: input L1/L2 caches, staging buffer,
                    L1 table, compressor, refcount array
```

With 2MB clusters:
- BUF_COMPRESSED: 2MB + 64KB = 2,112KB
- BUF_MULTIPURPOSE: 2MB = 2,048KB
- BUF_DATA: 2MB = 2,048KB
- Dynamic start: ~6.1MB into scratch
- Remaining: ~6.3MB for caches + staging + L1 + compressor +
  refcount array

This fits comfortably. The BUF_MULTIPURPOSE buffer serves as:
- BUF_HEADER during header write (phase 1 and 4)
- BUF_L2_OUT during the data loop (phase 2)
- BUF_REFCOUNT during refcount write (phase 3)

These are already used in non-overlapping phases, so no
behavioural change is needed — just different buffer addresses.

### Memory budget (2MB clusters, 1 input device)

| Region | Size | Running total |
|--------|------|---------------|
| BUF_COMPRESSED | 2,112KB | 2,112KB |
| BUF_MULTIPURPOSE | 2,048KB | 4,160KB |
| BUF_DATA | 2,048KB | 6,208KB |
| Input caches (1 dev) | 128KB | 6,336KB |
| Staging buffer | 2,048KB | 8,384KB |
| Compressor state | ~300KB | 8,684KB |
| L1 table (8TB disk) | 128KB | 8,812KB |
| Refcount array | varies | ~9,000KB |
| **Remaining** | **~3.4MB** | |
| Heap (512KB) | reserved | starts at 0xF70000 |

With 16 input devices (worst case): caches = 2MB, total
~10.9MB, still fits within the 12.4MB budget.

### Backward compatibility

For cluster sizes ≤ 64KB, the layout is identical to today
(each buffer happens to be 64KB = MAX_SECTOR_SIZE). The change
is purely additive — existing behaviour is preserved.

## Implementation

### 21a: Dynamic buffer layout in convert operation

**Files:** `src/operations/convert/src/main.rs`,
`src/shared/src/lib.rs`

1. Replace the five fixed `const` buffer addresses
   (BUF_DATA, BUF_COMPRESSED_IN, BUF_L2_OUT, BUF_HEADER,
   BUF_REFCOUNT) with runtime-computed addresses based on
   output cluster size.

2. Add a `BufferLayout` struct that computes addresses from
   the output cluster size:
   ```rust
   struct BufferLayout {
       buf_compressed: usize,  // COMPRESSED_BUF_SIZE
       buf_multipurpose: usize, // cluster_size
       buf_data: usize,         // cluster_size
       dynamic_start: usize,    // after buf_data
   }
   ```

3. For raw output (no cluster_size concept), use
   MAX_SECTOR_SIZE as the effective cluster size (preserving
   current behaviour).

4. Update `init_qcow2_output_layout()` to accept and use the
   new buffer addresses.

5. Update `write_qcow2_header()`, the L2 flush logic, and the
   refcount write logic to use the multipurpose buffer instead
   of separate BUF_HEADER/BUF_L2_OUT/BUF_REFCOUNT constants.

6. Keep the compile-time static assert but adjust it to use
   MAX_CLUSTER_SIZE as the cluster size (worst case).

**Validation:** Existing tests pass unchanged (64KB clusters
use the same addresses as before).

### 21b: Lift VMM cluster size limit

**Files:** `src/vmm/src/main.rs`

1. Change the QCOW2 output cluster size validation from
   `512..=65536` to `512..=2097152` (MAX_CLUSTER_SIZE):
   ```rust
   if is_qcow2_output
       && (!(512..=2097152).contains(&args.cluster_size)
           || !args.cluster_size.is_power_of_two())
   ```

2. Update the error message to reflect the new range.

3. Ensure the cluster_size value is passed correctly to the
   guest ConvertConfig (it already is — `output_cluster_bits`
   is log2 of the cluster size, which handles up to 2MB
   = cluster_bits 21).

**Validation:** `imago convert -O qcow2 --cluster-size 131072`
no longer errors.

### 21c: Update data loop for large clusters

**Files:** `src/operations/convert/src/main.rs`

The uncompressed QCOW2 output path
(`convert_to_qcow2_uncompressed`) and compressed path
(`convert_to_qcow2_compressed`) both process data in
`chunk_size` chunks (64KB for clusters > 64KB). This is
correct for I/O, but:

1. **L2 table flushing**: Currently writes BUF_L2_OUT as a
   single `write_cluster_to_output()` call with cluster_size.
   With the multipurpose buffer, this still works — just verify
   the buffer address comes from BufferLayout.

2. **Compressed output**: `compress_cluster_zlib()` needs the
   full uncompressed cluster in BUF_DATA. Currently, when
   chunk_size < cluster_size, the code assembles the full
   cluster by reading chunks into BUF_DATA sequentially. Verify
   this works with BUF_DATA at the new (potentially different)
   address.

3. **Refcount block write**: Currently writes BUF_REFCOUNT as
   one cluster. With the multipurpose buffer, the refcount
   write phase must ensure no L2 data is still needed (it
   isn't — L2 writing is complete before refcount writing).

4. **Header rewrite**: The final header rewrite (to fill in
   refcount table offset) currently uses BUF_HEADER. With the
   multipurpose buffer, verify the L2/refcount phases are
   complete before rewriting.

**Key change**: The three separate write functions
(`write_qcow2_header`, L2 flush, refcount write) must all
agree on using the multipurpose buffer address from
BufferLayout. Pass the address explicitly rather than using
a compile-time constant.

### 21d: Integration tests

**Files:** `tests/test_convert.py`, `tests/manifest.json`,
test image generation scripts

1. Add integration tests for QCOW2 output with large clusters:
   - Convert raw → QCOW2 with `--cluster-size 131072` (128KB)
   - Convert raw → QCOW2 with `--cluster-size 2097152` (2MB)
   - Convert QCOW2 → QCOW2 with `--cluster-size 131072`
   - Compressed output: `--cluster-size 131072 -c`
   - Compressed output: `--cluster-size 2097152 -c`
   - Verify output with `qemu-img check`
   - Round-trip: convert to large-cluster QCOW2, convert back
     to raw, compare with `imago compare`

2. Add a test for converting a 2MB-cluster input image to
   2MB-cluster output (preserving cluster size).

3. Add a test for converting a compressed 2MB-cluster input
   to compressed 2MB-cluster output.

4. Cross-validate: for each test, verify that qemu-img can
   read the output image and reports correct virtual size,
   cluster size, and format.

### 21e: VMDK and VHD/VHDX output cluster sizes

**Files:** `src/vmm/src/main.rs`

Check whether VMDK, VHD, and VHDX output paths have similar
cluster/block size limitations. VMDK uses fixed 128-sector
grains (64KB); VHD and VHDX use block sizes. If any of these
also have artificial limits, document them but **do not fix
in this phase** — this phase focuses on QCOW2.

## Risks

1. **Memory pressure with backing chains**: A 16-device
   backing chain with 2MB output clusters uses ~10.9MB of
   scratch. This is tight but fits. Monitor the static assert
   at compile time.

2. **Compressed buffer overflow**: If a 2MB cluster compresses
   to > 2MB (expansion), the compressed output buffer needs
   COMPRESSED_BUF_SIZE = cluster_size + 64KB. This is already
   the case — `compress_cluster_zlib` returns 0 for
   incompressible data and the code falls back to uncompressed.

3. **L2 entry count per table**: With 2MB clusters and 8-byte
   L2 entries, each L2 table has 262,144 entries covering
   512GB of virtual space. L1 tables will be very small. This
   is a feature, not a bug.

## Success Criteria

- `imago convert -O qcow2 --cluster-size 131072` works
- `imago convert -O qcow2 --cluster-size 2097152` works
- `imago convert -O qcow2 --cluster-size 131072 -c` works
- `imago convert -O qcow2 --cluster-size 2097152 -c` works
- `qemu-img check` validates all outputs
- `imago compare` confirms round-trip fidelity
- All existing tests still pass
- Binary sizes remain within 384KB limit
