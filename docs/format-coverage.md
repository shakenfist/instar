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
| VMDK (v3/COWD) | No | Yes | (none in test suite) |
| VHD/VPC | Yes | Yes | hyperv-dynamic-vhd, virtualpc-vhd |
| VHDX | Yes | Yes | qemu-vhdx, vhdx-disk2vhd |
| RAW | Yes | Yes | raw-mbr-partitioned, raw-gpt-partitioned, etc. |
| GPT/MBR | Yes (separate) | Partial | raw-mbr-partitioned, raw-gpt-partitioned |
| VDI | Yes | **No** | (none) |
| QED | Yes (banned) | **No** | (none) |
| ISO | Yes | **No** | (none) |
| LUKS | Yes | **No** | (none) |
| Parallels | No | **No** | parallels-v1, parallels-v2 (in testdata, not tested) |
| Bochs | No | **No** | empty.bochs (in testdata, not tested) |
| cloop | No | **No** | simple-pattern.cloop (in testdata, not tested) |

### Formats Not Yet Detected by Imago

The following formats are detected by oslo.utils but not imago:

1. **VDI (VirtualBox)** - Common virtualization format
2. **QED** - Deprecated QEMU format (oslo.utils bans it entirely)
3. **ISO** - CD/DVD image format
4. **LUKS** - Linux encrypted container format
5. **GPT/MBR** - oslo.utils detects these as distinct from "raw"

---

## Safety Check Comparison

### QCOW2 Safety Checks

| Check | Description | oslo.utils | imago | Test Images |
|-------|-------------|------------|-------|-------------|
| backing_file | Detects external backing file reference | Rejects | Reports (FLAG_HAS_BACKING_FILE) | qcow2-overlay-chain, sf-vda |
| data_file | Detects external data file feature | Rejects | Reports (FLAG_HAS_EXTERNAL_DATA) | (need to create) |
| unknown_features | Unknown incompatible feature bits | Rejects | Partial - reports known bits | (need to create) |
| dirty | Image not cleanly closed | N/A | Reports (FLAG_DIRTY) | (none) |
| corrupt | Image marked corrupt | N/A | Reports (FLAG_CORRUPT) | (none) |
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
| descriptor path traversal | Extent paths with `/` | Rejects | **Not checked** | (need to create) |
| descriptor missing extents | No extent declarations | Rejects | **Not checked** | (need to create) |
| header/footer consistency | Signature mismatch | Rejects | **Not checked** | (none) |
| createType validation | Unsupported types | Partial | Reports createType | vmdk-streamoptimized |

### GPT/MBR Safety Checks

| Check | Description | oslo.utils | imago | Test Images |
|-------|-------------|------------|-------|-------------|
| MBR signature | 0xAA55 at offset 510 | Yes | **Not checked** | raw-mbr-partitioned |
| Boot flag validity | Must be 0x00 or 0x80 | Rejects | **Not checked** | (need to create) |
| GPT protective MBR | CHS and LBA validation | Rejects | **Not checked** | raw-gpt-partitioned |

### Other Format Safety Checks

| Format | Check | oslo.utils | imago |
|--------|-------|------------|-------|
| QED | Banned entirely | Rejects | N/A (not detected) |
| LUKS | Version check (only v1) | Rejects v2+ | N/A (not detected) |
| VDI | None | Pass-through | N/A (not detected) |
| ISO | None | Pass-through | N/A (not detected) |
| VHD | None | Pass-through | Detects creator app |
| VHDX | None | Pass-through | Detects block size |

---

## Test Image Coverage

### Currently Tested RAW Images

| Image ID | Description | Safety | Tags |
|----------|-------------|--------|------|
| raw-mbr-partitioned | MBR partition table | safe | raw, mbr, partitioned |
| raw-gpt-partitioned | GPT partition table | safe | raw, gpt, partitioned |
| raw-fat-no-partition | FAT16 without partition table | safe | raw, fat, filesystem |
| raw-sparse-empty | Sparse 100MB file | safe | raw, sparse, empty |
| raw-zeros-1mb | 1MB zeros | safe | raw, zeros, minimal |
| raw-mbr-truncated | Truncated MBR (256 bytes) | malformed | raw, mbr, truncated |
| raw-gpt-truncated | Truncated GPT | malformed | raw, gpt, truncated |
| raw-mbr-corrupted | Valid signature, garbage entries | malformed | raw, mbr, corrupted |
| raw-random-garbage | Random bytes | malformed | raw, garbage |
| raw-misleading-header | QCOW2 magic but invalid | malformed | raw, misleading |
| raw-minimal-1byte | 1-byte file | malformed | raw, minimal, edge-case |
| raw-qcow2-magic-wrong-offset | QCOW2 magic at offset 512 | malformed | raw, misleading, offset |

### Missing Test Images (Priority Order)

#### High Priority - Security Relevant

1. **qcow2-external-data-file** - QCOW2 with data_file feature enabled
2. **qcow2-unknown-features** - QCOW2 with unknown incompatible feature bits
3. **vmdk-path-traversal** - VMDK descriptor with `/etc/passwd` in extent path
4. **vmdk-no-extents** - VMDK descriptor with no extent declarations
5. **raw-invalid-boot-flag** - MBR with boot flag != 0x00/0x80

#### Medium Priority - Format Coverage

6. **vdi-simple** - Basic VirtualBox VDI image
7. **qed-simple** - QED format (for rejection testing)
8. **luks-v1** - LUKS version 1 encrypted container
9. **luks-v2** - LUKS version 2 (for version rejection testing)
10. **iso-simple** - Basic ISO 9660 image

#### Lower Priority - Edge Cases

11. **raw-gpt-wrong-chs** - GPT with invalid protective MBR CHS values
12. **raw-gpt-wrong-lba** - GPT with incorrect start LBA
13. **vmdk-header-footer-mismatch** - VMDK with inconsistent signatures
14. **qcow2-dirty** - QCOW2 with dirty bit set
15. **qcow2-corrupt** - QCOW2 with corrupt bit set

---

## Implementation Gaps

### In Progress: MBR/GPT Partition Table Detection

As part of the `--unsafe-quirks` feature, imago will add MBR/GPT detection
to distinguish genuine raw disk images from arbitrary files. This addresses
the root cause of backing file disclosure attacks.

**Default behavior**: Files without recognized format headers must have a
valid partition table (MBR or GPT) to be accepted as raw disk images.

**With `--unsafe-quirks`**: Accept any file as raw (qemu-img compatible but
insecure).

See [quirks.md](quirks.md#raw-as-fallback-format) and
[configuration.md](configuration.md) for details.

### Detections to Add

1. **VDI format detection** - Magic number detection for VirtualBox images
2. **QED format detection** - Even if just to report "unsupported format"
3. **ISO format detection** - ISO 9660 / UDF detection
4. **LUKS format detection** - Encrypted container detection

### Safety Checks to Add

1. **QCOW2 unknown features** - Warn on unknown incompatible feature bits
2. **VMDK path validation** - Detect path traversal in descriptors
3. **MBR boot flag validation** - Detect invalid boot flags (in addition to presence)
4. **GPT protective MBR validation** - Validate CHS/LBA values

### Reporting Enhancements

1. **Distinguish GPT/MBR from raw** - Currently all non-header formats report as "raw"
2. **Report partition table type** - Could add metadata field for MBR/GPT detection
3. **Security warnings** - Flag images with security-relevant features in output

---

## References

- [oslo.utils format_inspector.py](https://github.com/openstack/oslo.utils/blob/master/oslo_utils/imageutils/format_inspector.py)
- [Glance format inspector module](https://docs.openstack.org/glance/latest/_modules/glance/common/format_inspector.html)
- [format-detection-safety.md](format-detection-safety.md) - Why imago's detection-only approach is secure
- [security.md](security.md) - CVE analysis and threat model
- [testing.md](testing.md) - Test framework documentation

---

*Document created: January 2026*
