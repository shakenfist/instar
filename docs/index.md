# Imago Documentation

Technical documentation for disk image format handling.

## QCOW2 Format

Comprehensive documentation for the QEMU Copy-On-Write version 2 format,
derived from QEMU source code analysis.

| Document | Description |
|----------|-------------|
| [Format Specification](qcow2/qcow2-format.md) | Header structure, feature flags, constants |
| [L1/L2 Tables](qcow2/qcow2-l1l2-tables.md) | Address translation, cluster types, extended L2 |
| [Reference Counting](qcow2/qcow2-refcount.md) | Refcount tables, variable widths, COW semantics |
| [Snapshots](qcow2/qcow2-snapshots.md) | Snapshot table format, operations, VM state |
| [Compression](qcow2/qcow2-compression.md) | ZLIB/ZSTD implementation, compressed entries |
| [Encryption](qcow2/qcow2-encryption.md) | LUKS header, key slots, IV generation |
| [Implementation Notes](qcow2/qcow2-implementation-notes.md) | Common pitfalls, validation, external refs |

## Other Formats

Documentation for additional formats will be added as implemented:

- **raw** - Raw disk images (planned)
- **vmdk** - VMware Virtual Machine Disk (planned)
