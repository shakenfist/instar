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

## Raw Format

Documentation for raw disk images - the simplest format with no metadata.

| Document | Description |
|----------|-------------|
| [Format Specification](raw/raw-format.md) | Structure, sparse files, tools, performance |

## VMDK Format

Documentation for VMware Virtual Machine Disk format.

| Document | Description |
|----------|-------------|
| [Format Specification](vmdk/vmdk-format.md) | Header structures, magic numbers, disk types |
| [Extent Types](vmdk/vmdk-extents.md) | Descriptor format, flat vs sparse, multi-extent |
| [Grain Tables](vmdk/vmdk-grain-tables.md) | Address translation, GD/GT structure, COW |
| [Compression](vmdk/vmdk-compression.md) | DEFLATE compression, streamOptimized format |

## KVM Virtualization

Documentation for building custom VMMs using the Linux KVM API.

| Document | Description |
|----------|-------------|
| [KVM API Guide](kvm.md) | KVM ioctls, memory setup, x86-64 long mode, VM exits |

## Platform Analysis

Analysis of how major virtualization platforms use qemu-img and handle disk images.

| Document | Description |
|----------|-------------|
| [Usage Analysis](usage.md) | How oVirt, Proxmox, and OpenStack use qemu-img |
| [Security Vulnerabilities](security.md) | CVE analysis for image handling across platforms |

## Prototypes

Experimental implementations exploring secure isolated execution.

| Document | Description |
|----------|-------------|
| [KVM Hello World](prototypes/kvm-hello-world.md) | Minimal bare-metal KVM guest proof-of-concept |
