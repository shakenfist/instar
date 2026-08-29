---
name: instar-format
description: "Disk image format reference: magic numbers, header layouts, endianness and parsing details for qcow2, vmdk, raw and the other supported formats. Use when parsing or writing format structures."
---

# /instar-format - Disk Image Format Reference

Quick reference for disk image format structures, magic numbers, and parsing details.

## Usage

```
/instar-format [format]
```

Where `[format]` is optional: `qcow2`, `vmdk`, `raw`, or omit for overview.

## Instructions for Claude

When the user invokes this skill, provide format-specific reference information based on the requested format. If no format specified, give an overview of all supported formats.

---

## Format Overview

| Format | Magic | Endianness | Features |
|--------|-------|------------|----------|
| QCOW2 | `0x514649fb` ("QFI\xfb") | Big Endian | Sparse, snapshots, compression, encryption, backing files |
| VMDK4 | `0x564d444b` ("VMDK") | Little Endian | Sparse, multi-extent, compression, streaming |
| VMDK3 | `0x434f5744` ("COWD") | Little Endian | Legacy VMFS sparse |
| Raw | None | N/A | No header, direct sector access |

---

## QCOW2 Format

### Header (Offset 0)

```
Offset  Size  Field
0       4     magic (0x514649fb)
4       4     version (2 or 3)
8       8     backing_file_offset
16      4     backing_file_size
20      4     cluster_bits (9-21, log2 of cluster size)
24      8     size (virtual disk size)
32      4     crypt_method (0=none, 1=AES, 2=LUKS)
36      4     l1_size
40      8     l1_table_offset
48      8     refcount_table_offset
56      4     refcount_table_clusters
60      4     nb_snapshots
64      8     snapshots_offset
```

### Version 3 Additional Fields (Offset 72)

```
Offset  Size  Field
72      8     incompatible_features
80      8     compatible_features
88      8     autoclear_features
96      4     refcount_order (log2 of refcount bits)
100     4     header_length
104     1     compression_type (0=zlib, 1=zstd)
```

### Feature Flags

**Incompatible (must understand):**
- Bit 0: DIRTY - Image not closed cleanly
- Bit 1: CORRUPT - Metadata may be corrupted
- Bit 2: DATA_FILE - External data file
- Bit 3: COMPRESSION - Non-zlib compression
- Bit 4: EXTL2 - Extended L2 (subclusters)

### Key Constants

```rust
const QCOW_MAGIC: u32 = 0x514649fb;
const MIN_CLUSTER_BITS: u32 = 9;   // 512 bytes
const MAX_CLUSTER_BITS: u32 = 21;  // 2 MB
const DEFAULT_CLUSTER_SIZE: u32 = 65536;  // 64 KB
const L1E_SIZE: u32 = 8;
const L2E_SIZE_NORMAL: u32 = 8;
const L2E_SIZE_EXTENDED: u32 = 16;
```

### Security Concerns

- **backing_file_offset/size**: Can reference arbitrary host paths
- **external data file**: Can reference arbitrary host paths
- **encryption**: LUKS header may reference external keys

---

## VMDK Format

### VMDK4 Header (Offset 0)

```
Offset  Size  Field
0       4     magic (0x564d444b "VMDK")
4       4     version (1, 2, or 3)
8       4     flags
12      8     capacity (sectors)
20      8     granularity (sectors)
28      8     desc_offset (sectors)
36      8     desc_size (sectors)
44      4     num_gtes_per_gt (typically 512)
48      8     rgd_offset (redundant grain directory)
56      8     gd_offset (grain directory)
64      8     grain_offset (first grain data)
72      1     filler
73      4     check_bytes (0x0a 0x20 0x0d 0x0a)
77      2     compressAlgorithm
```

### Flags

```rust
const FLAG_NL_DETECT: u32 = 1 << 0;   // Newline detection
const FLAG_RGD: u32 = 1 << 1;         // Redundant grain directory
const FLAG_ZERO_GRAIN: u32 = 1 << 2;  // Zeroed-grain optimization
const FLAG_COMPRESS: u32 = 1 << 16;   // Compression enabled
const FLAG_MARKER: u32 = 1 << 17;     // Grain markers present
```

### Descriptor (Text-based)

The descriptor is a text section containing key-value pairs:

```
createType="monolithicSparse"
parentFileNameHint="backing.vmdk"
RW 4194304 SPARSE "disk-s001.vmdk"
```

### Security Concerns

- **Descriptor**: Can reference arbitrary extent files and parent images
- **parentFileNameHint**: Backing file path (arbitrary host paths)
- **Extent references**: Can point outside image directory

---

## Raw Format

### Structure

No header. File contains pure sector data from byte 0.

```
Sector 0: bytes 0-511 (often MBR/GPT)
Sector 1: bytes 512-1023
...
Sector N: last 512 bytes
```

### Detection

Raw is detected as last resort (lowest priority score). Always explicitly specify format when known.

### Key Facts

- No magic number - cannot be positively identified
- All sizes must be multiples of 512 bytes
- Best I/O performance (no metadata overhead)
- Supports sparse files on ext4/XFS/Btrfs

---

## Parsing Order for Format Detection

```rust
// Check formats in order of specificity:
1. QCOW2: Check bytes 0-3 for 0x514649fb
2. VMDK4: Check bytes 0-3 for 0x564d444b
3. VMDK3: Check bytes 0-3 for 0x434f5744
4. VHD: Check last 512 bytes for "conectix"
5. VHDX: Check bytes 0-7 for "vhdxfile"
6. Raw: Fallback if no other format matches
```

## See Also

- Full documentation: `docs/qcow2/`, `docs/vmdk/`, `docs/raw/`
- Format detection code: `src/operations/info/src/main.rs`
- Security notes: `docs/security.md`
