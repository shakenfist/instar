# Format Detection and Safety Check Coverage

This document compares imago's format detection and safety reporting capabilities
against OpenStack's oslo.utils `format_inspector` module. The goal is to ensure
imago can detect all the same security-relevant metadata that OpenStack uses for
image safety validation.

## Important Distinction: Detection vs Rejection

**oslo.utils format_inspector** performs **safety validation** - it rejects images
that fail safety checks (e.g., QCOW2 with backing files, VMDK with path traversal).

**imago** performs **safety detection** - it reports security-relevant metadata
to the caller but does not reject images. This is because imago's KVM sandbox
architecture makes following these references impossible, so detection and
reporting is sufficient. See [format-detection-safety.md](format-detection-safety.md)
for details on why this approach is secure.

---

## Format Detection Comparison

| Format | oslo.utils | imago | Test Images |
|--------|------------|-------|-------------|
| QCOW2 (v2/v3) | Yes | Yes | cirros-qcow2, qcow2-v2, many edge-cases |
| QCOW1 | No | Yes | (none - deprecated format) |
| VMDK (monolithic sparse) | Yes | Yes | plaso-vmdk, vmdk-multi-partition |
| VMDK (stream optimized) | Yes | Yes | vmdk-streamoptimized |
| VMDK (v3/COWD) | Yes | Yes | vmdk-v3 |
| VHD/VPC | Yes | Yes | hyperv-dynamic-vhd, virtualpc-vhd, vhd-d2v-zerofilled |
| VHDX | Yes | Yes | qemu-vhdx, vhdx-disk2vhd |
| RAW | Yes | Yes | raw-mbr-partitioned, raw-gpt-partitioned, etc. |
| MBR partition table | Yes | Yes | raw-mbr-partitioned |
| GPT partition table | Yes | Yes | raw-gpt-partitioned |
| VDI | Yes | Yes | vdi-simple |
| QED | Yes (banned) | Yes | qed-simple |
| ISO | Yes | Yes* | iso-simple |
| LUKS | Yes | Yes | (none - test image needed) |
| Parallels | No | **No** | parallels-v1, parallels-v2 (in testdata, not tested) |
| Bochs | No | **No** | empty.bochs (in testdata, not tested) |
| cloop | No | **No** | simple-pattern.cloop (in testdata, not tested) |

*\* ISO detection is controlled by `--unsafe-quirks` flag: by default imago reports "iso", but with `--unsafe-quirks` it reports "raw" to match qemu-img behavior. See [quirks.md](quirks.md) for details.*

### Formats Not Yet Detected by Imago

All formats detected by oslo.utils are now also detected by imago.

---

## Conversion Output Format Support

The `imago convert` operation supports writing output in the following formats:

| Output Format | Status | Key Features |
|---------------|--------|--------------|
| **raw** (default) | Supported | Flat byte-for-byte output, sparse output with `-S` |
| **qcow2** | Supported | QCOW2 v3, 16-bit refcounts, configurable cluster size (512B-64KB) |
| vmdk | Not yet | Planned: monolithicSparse with grain table writer |
| vhd | Not yet | Planned: dynamic VHD with BAT writer |
| vhdx | Not yet | Planned: VHDX with BAT, metadata, and log support |

### Input Format Support for Conversion

| Input Format | Status | Notes |
|--------------|--------|-------|
| raw | Supported | With MBR/GPT partition validation (unless `--unsafe-quirks`) |
| qcow2 (v2/v3) | Supported | Including compressed clusters (zlib), backing chain flattening |
| vmdk | Not yet | Needs grain table reader |
| vhd/vhdx | Not yet | Needs BAT reader |

### Limitations

- Input cluster sizes above 64KB are not supported (affects both convert and
  compare). The `debian-12-sfagent` image (2MB clusters) is skipped in tests.
- ZSTD-compressed QCOW2 clusters are not supported (only zlib/deflate).
- Extended L2 entries (subclusters) are not supported.
- Encrypted QCOW2 images are not supported.

---

## Safety Check Comparison

### QCOW2 Safety Checks

| Check | Description | oslo.utils | imago | Test Images |
|-------|-------------|------------|-------|-------------|
| backing_file | Detects external backing file reference | Rejects | Reports (FLAG_HAS_BACKING_FILE) | qcow2-overlay-chain, sf-vda, qcow2-backing-* |
| data_file | Detects external data file feature | Rejects | Reports (FLAG_HAS_EXTERNAL_DATA) | qcow2-external-data-file |
| unknown_features | Unknown incompatible feature bits | Rejects | Partial - reports known bits | qcow2-unknown-features |
| dirty | Image not cleanly closed | N/A | Reports (FLAG_DIRTY) | qcow2-dirty |
| corrupt | Image marked corrupt | N/A | Reports (FLAG_CORRUPT) | qcow2-corrupt |
| encrypted | Encryption enabled | N/A | Reports (FLAG_ENCRYPTED) | (none) |

#### QCOW2 Incompatible Feature Bits

| Bit | Name | oslo.utils | imago |
|-----|------|------------|-------|
| 0 | Dirty bit | N/A | QCOW2_INCOMPAT_DIRTY |
| 1 | Corrupt bit | N/A | QCOW2_INCOMPAT_CORRUPT |
| 2 | External data file | Rejects | QCOW2_INCOMPAT_EXTERNAL_DATA |
| 3 | Compression type | N/A | QCOW2_INCOMPAT_COMPRESSION |
| 4 | Extended L2 | N/A | QCOW2_INCOMPAT_EXTENDED_L2 |
| 5+ | Unknown | Rejects | **Not checked** |

### VMDK Safety Checks

| Check | Description | oslo.utils | imago | Test Images |
|-------|-------------|------------|-------|-------------|
| descriptor path traversal | Extent paths with `/` | Rejects | **Not checked** | vmdk-path-traversal |
| descriptor missing extents | No extent declarations | Rejects | **Not checked** | vmdk-no-extents |
| header/footer consistency | Signature mismatch | Rejects | **Not checked** | (none) |
| createType validation | Unsupported types | Partial | Reports createType | vmdk-streamoptimized |

### RAW/Partition Table Safety Checks

| Check | Description | oslo.utils | imago | Test Images |
|-------|-------------|------------|-------|-------------|
| MBR signature | 0xAA55 at offset 510 | Yes | Yes | raw-mbr-partitioned |
| MBR boot flag validity | Must be 0x00 or 0x80 | Rejects | Yes | raw-mbr-partitioned |
| GPT protective MBR | Partition type 0xEE detection | Yes | Yes | raw-gpt-partitioned |
| Partition table required | Reject files without valid table | N/A | Yes (default) | multiple raw-* images |

### Other Format Safety Checks

| Format | Check | oslo.utils | imago |
|--------|-------|------------|-------|
| QED | Banned entirely | Rejects | Detects format |
| LUKS | Version check (only v1) | Rejects v2+ | Detects format, version |
| VDI | None | Pass-through | Detects format, UUID |
| ISO | None | Pass-through | Detects format* |
| VHD | None | Pass-through | Detects creator app |
| VHDX | None | Pass-through | Detects block size |

---

## Test Image Coverage

### Current Test Images by Format

#### QCOW2 Images (25+)

| Image ID | Description | Safety | Key Features |
|----------|-------------|--------|--------------|
| cirros-qcow2 | CirrOS minimal cloud image | safe | Production-like |
| qcow2-v2 | QCOW2 version 2 (compat=0.10) | safe | Version 2 format |
| qcow2-extended-l2 | Extended L2 entries | safe | Subcluster allocation |
| qcow2-zstd | ZSTD compression | safe | Compression type |
| qcow2-lazy-refcounts | Lazy refcounts enabled | safe | Crash-consistent mode |
| qcow2-min-cluster | 512-byte cluster size | safe | Parser stress test |
| qcow2-max-cluster | 2MB cluster size | safe | Parser stress test |
| qcow2-refcount-bits-64 | 64-bit refcount width | safe | Refcount edge case |
| qcow2-refcount-bits-1 | 1-bit refcount width | safe | Refcount edge case |
| qcow2-overlay-chain | Overlay with backing file | safe | Backing chain |
| qcow2-base-for-chain | Base image (no backing) | safe | Backing chain base |
| sf-vda | Shaken Fist production overlay | safe | Large cluster, 30GB virtual |
| sf-vda-backing | Shaken Fist production base | safe | Large cluster |
| debian-12-sfagent | Debian 12 production image | safe | Cloud image |
| aurel32-* | Historic Debian images (4) | safe | Various architectures |
| chain-top-qcow2 | Three-layer backing chain | safe | Cross-format chain |
| chain-middle-qcow2 | QCOW2 with VMDK backing | safe | Cross-format chain |
| qcow2-dirty | Dirty bit set | safe | Unclean shutdown |
| qcow2-corrupt | Corrupt bit set | safe | Corrupt flag |
| qcow2-backing-textfile | Backing file to text file | malicious | CVE-2015-5163 |
| qcow2-backing-etc-passwd | Backing file to /etc/passwd | malicious | CVE-2015-5163 |
| qcow2-backing-garbage | Backing file to garbage | malicious | CVE-2015-5163 |
| qcow2-external-data-file | External data file feature | malicious | CVE-2024-32498 |
| qcow2-unknown-features | Unknown feature bit set | malicious | Unknown features |

#### VMDK Images (7)

| Image ID | Description | Safety | Key Features |
|----------|-------------|--------|--------------|
| plaso-vmdk | MonolithicSparse VMDK | safe | Basic VMDK |
| vmdk-multi-partition | Multi-partition VMDK | safe | Multiple partitions |
| vmdk-streamoptimized | streamOptimized VMDK | safe | OVA/OVF format |
| vmdk-v3 | VMDK version 3 | safe | Native version 3 |
| chain-base-vmdk | VMDK base for chain test | safe | Cross-format chain |
| vmdk-path-traversal | Path traversal in extent | malicious | /etc/passwd reference |
| vmdk-no-extents | Missing extent declarations | malformed | Invalid descriptor |

#### VHD/VPC Images (4)

| Image ID | Description | Safety | Key Features |
|----------|-------------|--------|--------------|
| hyperv-dynamic-vhd | Hyper-V 2012 R2 VHD | safe | Dynamic allocation |
| virtualpc-vhd | Virtual PC VHD | safe | Different creator |
| vhd-d2v-zerofilled | Disk2VHD zerofilled VHD | safe | Zerofilled |
| afl-vhd-max-table-entries | AFL-discovered malformed | malformed | Error handling |

#### VHDX Images (2)

| Image ID | Description | Safety | Key Features |
|----------|-------------|--------|--------------|
| qemu-vhdx | QEMU iotest VHDX | safe | Dynamic disk |
| vhdx-disk2vhd | Disk2VHD created VHDX | safe | Different creator |

#### VDI Images (1)

| Image ID | Description | Safety | Key Features |
|----------|-------------|--------|--------------|
| vdi-simple | Basic VirtualBox VDI | safe | Format detection test |

#### QED Images (1)

| Image ID | Description | Safety | Key Features |
|----------|-------------|--------|--------------|
| qed-simple | QED format image | safe | Deprecated format test |

#### ISO Images (1)

| Image ID | Description | Safety | Key Features |
|----------|-------------|--------|--------------|
| iso-simple | Basic ISO 9660 image | safe | Format detection test |

#### RAW Images (12)

| Image ID | Description | Safety | Partition Table |
|----------|-------------|--------|-----------------|
| raw-mbr-partitioned | MBR partition table | safe | MBR |
| raw-gpt-partitioned | GPT partition table | safe | GPT |
| raw-fat-no-partition | FAT16 without partition table | safe | None (requires --unsafe-quirks) |
| raw-sparse-empty | Sparse 100MB file | safe | None (requires --unsafe-quirks) |
| raw-zeros-1mb | 1MB zeros | safe | None (requires --unsafe-quirks) |
| raw-mbr-truncated | Truncated MBR | malformed | Invalid |
| raw-gpt-truncated | Truncated GPT | malformed | Invalid |
| raw-mbr-corrupted | Valid signature, garbage entries | malformed | Invalid |
| raw-random-garbage | Random bytes | malformed | None |
| raw-misleading-header | QCOW2 magic but invalid | malformed | None |
| raw-minimal-1byte | 1-byte file | malformed | None |
| raw-qcow2-magic-wrong-offset | QCOW2 magic at offset 512 | malformed | None |

### Remaining Test Images to Create

#### High Priority - Security Relevant

1. **qcow2-encrypted** - QCOW2 with encryption enabled

#### Medium Priority - Format Coverage

2. **luks-v1** - LUKS version 1 encrypted container
3. **luks-v2** - LUKS version 2 (for version rejection testing)

#### Lower Priority - Edge Cases

4. **vmdk-header-footer-mismatch** - VMDK with inconsistent signatures

---

## Implementation Status

### Completed

1. **MBR/GPT Partition Table Detection** - Implemented as part of `--unsafe-quirks`
   feature. By default, files without recognized format headers must have a valid
   partition table (MBR or GPT) to be accepted as RAW disk images.

   - MBR: Valid 0x55AA signature at offset 510, plus valid boot indicators (0x00/0x80)
   - GPT: Protective MBR with partition type 0xEE

   See [quirks.md](quirks.md#raw-as-fallback-format) for details.

2. **QCOW2 Backing File Detection** - Reports backing file path and format
   (from header extension). Tests include security-focused images that attempt
   path traversal attacks (CVE-2015-5163).

3. **QCOW2 Feature Bit Detection** - Reports dirty, corrupt, external data,
   compression type, and extended L2 feature bits.

4. **VMDK CreateType Detection** - Reports createType from descriptor for
   streamOptimized and other VMDK variants.

5. **Cross-Format Backing Chain Detection** - `--chain` flag discovers backing
   chains across format boundaries (e.g., QCOW2 -> VMDK).

6. **Comprehensive Test Image Suite** - Test images now cover:
   - QCOW2 external data file (CVE-2024-32498)
   - QCOW2 unknown features
   - QCOW2 dirty/corrupt bits
   - VMDK path traversal
   - VMDK missing extents
   - VDI, QED, and ISO format detection

### Detections to Add

All oslo.utils formats are now detected. No remaining format detections needed.

### Safety Checks to Add

1. **QCOW2 unknown features** - Warn on unknown incompatible feature bits
2. **VMDK path validation** - Detect path traversal in descriptors

### Reporting Enhancements

1. **Security warnings** - Flag images with security-relevant features in output
2. **JSON output for chain** - Add `--output json` support for `--chain` flag

---

## References

- [oslo.utils format_inspector.py](https://github.com/openstack/oslo.utils/blob/master/oslo_utils/imageutils/format_inspector.py)
- [Glance format inspector module](https://docs.openstack.org/glance/latest/_modules/glance/common/format_inspector.html)
- [format-detection-safety.md](format-detection-safety.md) - Why imago's detection-only approach is secure
- [security.md](security.md) - CVE analysis and threat model
- [testing.md](testing.md) - Test framework documentation
- [quirks.md](quirks.md) - Safe vs unsafe quirks classification

---

*Document updated: February 2026*
