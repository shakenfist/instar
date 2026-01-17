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
| [Performance Counters](performance_counters.md) | KVM statistics, perf events, resource limiting |

## Guest Data Transfer

Methods for transferring data into and out of bare-metal KVM guests.

| Document | Description |
|----------|-------------|
| [Comparison](data-transfer-comparison.md) | Trade-offs, rust-vmm crates, and recommendations |
| [Direct Memory](data-transfer-direct-memory.md) | Shared memory regions, coalesced I/O, completion signaling |
| [Virtio-vsock](data-transfer-virtio-vsock.md) | Socket-based communication with CID addressing |
| [Virtio-block](data-transfer-virtio-block.md) | Block device interface for sector-based transfers |
| [Other Mechanisms](data-transfer-other.md) | Custom MMIO device, Port I/O, ioeventfd, virtio-fs, VFIO, hypercalls |

## Design Decisions

| Document | Description |
|----------|-------------|
| [Why Rust](rust-rationale.md) | Memory safety, bare-metal support, rust-vmm ecosystem |

## Rust Crate Ecosystem

The [rust-vmm](https://github.com/rust-vmm/community) project provides
production-tested virtualization components used by Firecracker, crosvm, and
Cloud Hypervisor. These crates reduce virtio implementation effort by 70%+.

| Crate | Side | Purpose |
|-------|------|---------|
| [kvm-ioctls](https://crates.io/crates/kvm-ioctls) | VMM | Safe KVM API wrappers |
| [vm-memory](https://crates.io/crates/vm-memory) | VMM | Guest memory abstraction |
| [virtio-queue](https://crates.io/crates/virtio-queue) | VMM | Virtqueue implementation |
| [virtio-blk](https://github.com/rust-vmm/vm-virtio) | VMM | Block device parsing |
| [virtio-vsock](https://crates.io/crates/virtio-vsock) | VMM | Vsock packet handling |
| [virtio-drivers](https://crates.io/crates/virtio-drivers) | Guest | `no_std` virtio drivers |

See [Comparison](data-transfer-comparison.md#rust-crate-ecosystem) for details
on how these crates affect implementation complexity.

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
| [KVM Hello World 2](prototypes/kvm-hello-world2.md) | Using vm-memory crate for safer memory management |
| [Virtio-Block](prototypes/virtio-block.md) | Virtio-block device emulation with file copy |
| [Virtio-Block2](prototypes/virtio-block2.md) | Virtio-block with protobuf messaging |
| [Virtio-Block3](prototypes/virtio-block3.md) | Virtio-block with configurable sector sizes |
| [Virtio-Block4](prototypes/virtio-block4.md) | Virtio-block with performance statistics |
| [Virtio-Block5](prototypes/virtio-block5.md) | Virtio-block with ioeventfd/irqfd optimizations |

## Shared Crates

Reusable Rust crates for the imago project.

| Document | Description |
|----------|-------------|
| [guest-protocol](crates/guest-protocol.md) | Protocol Buffers messaging for guest-VMM communication |

## Development

| Document | Description |
|----------|-------------|
| [Building with Docker](building-with-docker.md) | Build prototypes using Docker CLI without VSCode |
