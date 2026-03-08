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
| LUKS | Yes | Yes | luks-v1, luks-v2, luks-v1-raw-gpt, luks-v1-qcow2 |
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
| **raw** (default) | Supported | Flat byte-for-byte output, sparse by default (`--no-skip-zeros` for dense) |
| **qcow2** | Supported | QCOW2 v3, 16-bit refcounts, configurable cluster size (512B-64KB), optional zlib compression (`-c`) |
| **vmdk** | Supported | monolithicSparse (default), streamOptimized with `-c` (DEFLATE compressed) |
| **vpc** (VHD) | Supported | Dynamic VHD with 2 MiB blocks, BAT-based allocation, skip-zeros support |
| **vhdx** | Supported | Dynamic VHDX with 32 MiB blocks, CRC-32C checksums, 1MB-aligned structures |

### Input Format Support for Conversion

| Input Format | Status | Notes |
|--------------|--------|-------|
| raw | Supported | With MBR/GPT partition validation (unless `--unsafe-quirks`) |
| qcow2 (v2/v3) | Supported | Including compressed clusters (zlib and ZSTD), extended L2 entries, backing chain flattening |
| vmdk (monolithicSparse) | Supported | Grain directory/table two-level lookup, sector-cached reads |
| vmdk (streamOptimized) | Supported | DEFLATE decompression, footer-based GD offset resolution |
| vhd (fixed) | Supported | Raw sector reads with footer validation |
| vhd (dynamic) | Supported | BAT-based block lookup, sector-cached reads |
| vhdx (dynamic) | Supported | 64-bit BAT with interleaved SB entries, GUID-based metadata, CRC-32C validation |

### Limitations

- Compressed clusters with cluster sizes above 64KB cannot be decompressed
  (decompression buffer limited to 64KB). Uncompressed clusters up to 2MB are
  fully supported. The `debian-12-sfagent` image (2MB clusters with 692
  compressed clusters) is skipped in convert/compare tests for this reason.
- Encrypted QCOW2 images are not supported.
- Extended L2 images with partially-allocated subclusters may return stale host
  data for unallocated subclusters. The extended L2 support reads only the first
  8 bytes of each 16-byte entry (the cluster descriptor), ignoring the subcluster
  allocation bitmap. This treats the entire cluster as fully allocated, which is
  conservative (data is read rather than zeroed) but could produce incorrect
  output for convert/compare when subclusters matter.

---

## Safety Check Comparison

### QCOW2 Safety Checks

| Check | Description | oslo.utils | imago | Test Images |
|-------|-------------|------------|-------|-------------|
| backing_file | Detects external backing file reference | Rejects | Reports (FLAG_HAS_BACKING_FILE) | qcow2-overlay-chain, sf-vda, qcow2-backing-* |
| data_file | Detects external data file feature | Rejects | Reports (FLAG_HAS_EXTERNAL_DATA) | qcow2-external-data-file |
| unknown_features | Unknown incompatible feature bits | Rejects | Rejects in check/compare/convert; info reports | qcow2-unknown-features |
| dirty | Image not cleanly closed | N/A | Reports (FLAG_DIRTY) | qcow2-dirty |
| corrupt | Image marked corrupt | N/A | Reports (FLAG_CORRUPT) | qcow2-corrupt |
| encrypted | Encryption enabled | N/A | Reports (FLAG_ENCRYPTED) | (none) |

#### QCOW2 Incompatible Feature Bits

| Bit | Name | oslo.utils | imago |
|-----|------|------------|-------|
| 0 | Dirty bit | N/A | QCOW2_INCOMPAT_DIRTY |
| 1 | Corrupt bit | N/A | QCOW2_INCOMPAT_CORRUPT |
| 2 | External data file | Rejects | Supported (data file path in JSON, chain read) |
| 3 | Compression type | N/A | QCOW2_INCOMPAT_COMPRESSION |
| 4 | Extended L2 | N/A | QCOW2_INCOMPAT_EXTENDED_L2 |
| 5+ | Unknown | Rejects | Rejected by check/compare/convert |

### VMDK Safety Checks

| Check | Description | oslo.utils | imago | Test Images |
|-------|-------------|------------|-------|-------------|
| descriptor path traversal | Extent paths with `/` | Rejects | Detects multi-extent (FLAG_NOT_SUPPORTED) | vmdk-path-traversal |
| descriptor missing extents | No extent declarations | Rejects | Validated via GD/GT walk | vmdk-no-extents |
| header/footer consistency | Signature mismatch | Rejects | Footer magic validated (streamOptimized) | vmdk-streamoptimized |
| createType validation | Unsupported types | Partial | Reports createType | vmdk-streamoptimized |
| grain directory bounds | GD offset within file | N/A | Validated | plaso-vmdk, vmdk-multi-partition |
| grain table bounds | GT offsets within file | N/A | Validated per GD entry | plaso-vmdk, vmdk-multi-partition |
| grain data bounds | Grain offsets within file | N/A | Validated per GTE | plaso-vmdk, vmdk-multi-partition |
| grain overlap | Two grains at same offset | N/A | 1-bit-per-grain bitmap | plaso-vmdk, vmdk-multi-partition |
| multi-extent detection | Multiple extents in descriptor | N/A | Reports FLAG_NOT_SUPPORTED | vmdk-multi-extent |
| fragmentation | Non-sequential grain layout | N/A | Reports fragmentation count | plaso-vmdk, vmdk-multi-partition |

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
| LUKS | Version check (only v1) | Rejects v2+ | Detects format, version, cipher, hash, UUID, payload offset, key slots, inner format (with passphrase) |
| VDI | None | Pass-through | Detects format, UUID |
| ISO | None | Pass-through | Detects format* |
| VHD | None | Pass-through | Detects creator app; full check validation (footer/header checksums, BAT bounds, overlap detection) |
| VHDX | None | Pass-through | Detects block size; full check validation (header CRC-32C, region table CRC, metadata, BAT bounds/alignment/overlap) |

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

#### VMDK Images (8)

| Image ID | Description | Safety | Key Features |
|----------|-------------|--------|--------------|
| plaso-vmdk | MonolithicSparse VMDK | safe | Basic VMDK |
| vmdk-multi-partition | Multi-partition VMDK | safe | Multiple partitions |
| vmdk-streamoptimized | streamOptimized VMDK | safe | OVA/OVF format |
| vmdk-v3 | VMDK version 3 | safe | Native version 3 |
| vmdk-multi-extent | Binary VMDK4 with two extent lines | safe | Multi-extent detection |
| chain-base-vmdk | VMDK base for chain test | safe | Cross-format chain |
| vmdk-path-traversal | Path traversal in extent | malicious | /etc/passwd reference |
| vmdk-no-extents | Missing extent declarations | malformed | Invalid descriptor |

#### VHD/VPC Images (6)

| Image ID | Description | Safety | Key Features |
|----------|-------------|--------|--------------|
| hyperv-dynamic-vhd | Hyper-V 2012 R2 VHD | safe | Dynamic allocation |
| virtualpc-vhd | Virtual PC VHD | safe | Different creator |
| vhd-d2v-zerofilled | Disk2VHD zerofilled VHD | safe | Zerofilled |
| vhd-fixed | Fixed VHD (disk_type=2) | safe | Fixed allocation |
| vhd-differencing | Differencing VHD (disk_type=4) | safe | Differencing type |
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

#### LUKS Images (4)

| Image ID | Description | Safety | Key Features |
|----------|-------------|--------|--------------|
| luks-v1 | LUKS v1 header (synthetic) | safe | Header parsing test |
| luks-v2 | LUKS v2 header with JSON metadata (synthetic) | safe | JSON metadata parsing |
| luks-v1-raw-gpt | LUKS v1 wrapping GPT raw image | safe | Inner format detection (raw) |
| luks-v1-qcow2 | LUKS v1 wrapping QCOW2 image | safe | Inner format detection (qcow2) |

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

6. **QCOW2 Incompatible Feature Bit Validation** - check, compare, and convert
   operations reject images with unsupported incompatible feature bits (per QCOW2
   spec). Supported bits: dirty (0), corrupt (1), external data file (2),
   compression type (3), extended L2 (4). Unsupported: unknown bits (5+).

7. **ZSTD Compressed Cluster Decompression** - QCOW2 v3 images with
   `compression_type=1` (ZSTD) are now supported in compare and convert
   operations using the ruzstd pure-Rust decoder.

8. **Extended L2 Entry Support** - QCOW2 v3 images with 128-bit L2 entries
   (32 subclusters) are now correctly parsed. The 16-byte entry stride is
   used for L2 table iteration and cluster lookup.

9. **Comprehensive Test Image Suite** - Test images now cover:
   - QCOW2 external data file (CVE-2024-32498)
   - QCOW2 unknown features
   - QCOW2 dirty/corrupt bits
   - VMDK path traversal
   - VMDK missing extents
   - VDI, QED, and ISO format detection

10. **VMDK Input/Output Support** - Convert supports VMDK as both input and
    output format. Input: monolithicSparse (grain directory/table lookup) and
    streamOptimized (DEFLATE decompression). Output: monolithicSparse (default)
    and streamOptimized with `-c` flag (DEFLATE compressed).

11. **VMDK Structural Integrity Check** - Full GD/GT validation in check
    operation: grain directory bounds checking, grain table walk with offset
    validation, grain overlap detection (1-bit-per-grain bitmap in scratch
    memory), streamOptimized footer validation, multi-extent detection via
    descriptor parsing, fragmentation measurement.

12. **VHD Input/Output Support** - Convert supports VHD as both input and
    output format. Input: fixed VHD (raw sector reads) and dynamic VHD
    (BAT-based block lookup). Output: dynamic VHD with 2 MiB blocks,
    sector bitmaps, and skip-zeros support.

13. **VHD Structural Integrity Check** - Full BAT validation in check
    operation: footer cookie and checksum validation, dynamic header
    cookie and checksum validation, BAT offset and entry bounds checking,
    overlap detection (1-bit-per-block bitmap in scratch memory), footer
    copy consistency (start vs end of file).

14. **VHDX Input/Output Support** - Convert supports VHDX as both input
    and output format. Input: dynamic VHDX (64-bit BAT with interleaved
    sector bitmap entries, GUID-based metadata, CRC-32C header/region
    validation). Output: dynamic VHDX with 32 MiB blocks, 1MB-aligned
    structures, and skip-zeros support.

15. **VHDX Structural Integrity Check** - Full validation in check
    operation: dual header CRC-32C validation with active header
    selection by sequence number, dirty log detection, region table
    CRC-32C validation, GUID-based metadata parsing (all required items),
    BAT entry validation (offset bounds, 1MB alignment, overlap
    detection, state validation), differencing disk detection.

16. **LUKS Container Inspection** - Full LUKS v1 and v2 header parsing with
    cipher, cipher mode, hash algorithm, UUID, payload offset, master key
    length, and active key slot reporting. LUKS v2 JSON metadata parsing
    extracts cipher/hash from the JSON area. With `--luks-passphrase`, LUKS
    v1 images are decrypted (PBKDF2 + AES-XTS, pure Rust RustCrypto crates
    in no_std guest) and inner format is detected and reported (including
    inner virtual size). Synthetic test headers for header parsing; real
    LUKS containers (created via cryptsetup) for decryption testing.

17. **QCOW2 External Data File Support** - Full read support for QCOW2 v3
    images with external data files (incompatible feature bit 2). The DATA
    header extension (type 0x44415441) is parsed to extract the data file
    path, which is reported in both human and JSON output. Chain discovery
    validates the data file path against the allowlist (CVE-2024-32498
    prevention) and opens it as a separate virtio-block device. Standard
    cluster reads dispatch to the data device; compressed clusters and
    metadata (L1/L2/refcounts) remain in the metadata device. The check
    operation skips bounds/overlap/refcount validation for data clusters
    when the external data bit is set.

### Detections to Add

All oslo.utils formats are now detected. No remaining format detections needed.

### Safety Checks to Add

None currently outstanding. All VMDK safety checks are now implemented.

### Reporting Enhancements

1. **Security warnings** - Flag images with security-relevant features in output
2. **JSON output for chain** - Add `--output json` support for `--chain` flag

---

## oslo.utils Cross-Validation Testing

Automated tests in `tests/test_oslo_crossval.py` run both imago and
oslo.utils `format_inspector` against every test image and compare
results. Three test classes cover format detection, safety checks,
and virtual size.

### Running Locally

```bash
# With oslo.utils installed (included in tests/requirements.txt)
cd tests && ../.venv/bin/stestr run test_oslo_crossval

# Without oslo.utils — all tests skip gracefully
```

### Documented Divergences

| Area | Image(s) | imago | oslo.utils | Reason |
|------|----------|-------|-----------|--------|
| Format | raw-mbr-partitioned, raw-gpt-partitioned | raw | gpt | oslo GPTInspector detects partition tables; imago matches qemu-img |
| Format | vmdk-multi-partition | raw | gpt | File is raw with GPT despite .vmdk extension |
| Format | iso-simple | raw | iso | imago reports ISO as raw with --unsafe-quirks |
| Format | luks-v1, luks-v2 | luks | luks | Match (imago now reports LUKS format with full metadata) |
| Safety | QED images | pass | reject | oslo bans QED; imago uses KVM sandbox |
| Safety | LUKS v2 | pass | reject | oslo rejects LUKS v2+; imago detects both |
| Safety | qcow2-external-data-file | reports data-file | flags data_file | Match: both detect external data file path |
| Vsize | VPC/VHD images | - | - | CHS geometry rounding (up to 8 MB delta allowed) |

### CI Integration

The `oslo-crossval-master` job in `.github/workflows/functional-tests.yml`
installs oslo.utils from git master (over the PyPI release) and runs only
the crossval tests. It has `continue-on-error: true` so upstream changes
are surfaced as warnings rather than blocking PRs.

---

## References

- [oslo.utils format_inspector.py](https://github.com/openstack/oslo.utils/blob/master/oslo_utils/imageutils/format_inspector.py)
- [Glance format inspector module](https://docs.openstack.org/glance/latest/_modules/glance/common/format_inspector.html)
- [format-detection-safety.md](format-detection-safety.md) - Why imago's detection-only approach is secure
- [security.md](security.md) - CVE analysis and threat model
- [testing.md](testing.md) - Test framework documentation
- [quirks.md](quirks.md) - Safe vs unsafe quirks classification

---

*Document updated: March 2026*
