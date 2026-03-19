# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

Initial public release.

### Added

- **Operations:** info, copy, check, compare, convert
- **Input formats:**
  - Raw (with MBR/GPT partition table validation)
  - QCOW2 v2/v3 (zlib and ZSTD compression, extended L2
    subclusters, AES-CBC and LUKS encryption, external data
    files, snapshots, backing chains)
  - VMDK (monolithicSparse, streamOptimized with DEFLATE
    compression)
  - VHD (fixed, dynamic, differencing with backing chains)
  - VHDX (dynamic, with CRC-32C validation)
  - LUKS v1/v2 containers (PBKDF2 and Argon2id KDF,
    AES-XTS decryption, inner format detection)
- **Output formats:** raw, QCOW2 v3 (with optional zlib
  compression, configurable cluster size), VMDK
  monolithicSparse (with optional DEFLATE compression),
  VHD dynamic, VHDX dynamic
- **Security model:** all image parsing runs inside a KVM
  sandbox; the host only handles opaque byte streams
- **Backing chain support:** chain discovery, flattening on
  convert, chain validation on check, security allowlist for
  backing file paths
- **qemu-img CLI compatibility:** output format matches
  qemu-img info, check, compare, and convert; auto-detects
  installed qemu-img version for output compatibility
- **Configuration:** layered config files (system, user,
  per-directory) with TOML format
- **Security audits:** static analysis, adversarial image
  testing (61 images, 12 attack categories), CVE reproduction
  (6 CVEs verified mitigated), VMM boundary audit
- **Fuzzing:** 13 coverage-guided fuzz targets, differential
  fuzzing against qemu-img, cross-validation against
  oslo.utils format_inspector

[0.1.0]: https://github.com/shakenfist/imago/releases/tag/v0.1.0
