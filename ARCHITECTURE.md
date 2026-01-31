# Imago Architecture

## Design Goals

1. **Security first** - Untrusted image data never touches host-privileged code
2. **Format fidelity** - Accurate conversion between qcow2, raw, and vmdk
3. **Performance** - Minimize overhead from sandboxing
4. **Simplicity** - Clean API that's easy to integrate

## Security Model

### The Problem with qemu-img

`qemu-img` is a powerful tool but runs with full host privileges. When
processing untrusted disk images, any vulnerability in format parsing code
could lead to host compromise. Historical CVEs in qemu-img include buffer
overflows, integer overflows, and other memory safety issues.

### Imago's Approach

```
┌─────────────────────────────────────────────────────────────┐
│                        Host System                          │
│                                                             │
│  ┌─────────────┐     ┌─────────────────────────────────┐   │
│  │   Imago     │     │        KVM Sandbox              │   │
│  │   Client    │────▶│  ┌─────────────────────────┐    │   │
│  │             │     │  │   Conversion Engine     │    │   │
│  │ (handles    │◀────│  │   (parses formats,      │    │   │
│  │  I/O only)  │     │  │    performs conversion) │    │   │
│  └─────────────┘     │  └─────────────────────────┘    │   │
│                      └─────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

The host-side client:
- Opens source and destination files
- Streams raw bytes to/from the sandbox
- Never interprets image format structures

The sandboxed conversion engine:
- Runs inside a minimal KVM guest
- Parses source format, writes destination format
- Any exploit is contained within the sandbox

### RAW Format Validation

A key security enhancement over qemu-img is partition table validation for RAW
format detection. qemu-img treats any unrecognized file as a valid RAW disk
image, which is the root cause of backing file disclosure attacks (CVE-2015-5163,
CVE-2024-32498).

**Imago's default behavior (secure):** Files without recognized format headers
must have a valid partition table (MBR or GPT) to be accepted as RAW disk images.
Files without valid partition tables are rejected as "unknown format."

**With `--unsafe-quirks`:** Matches qemu-img behavior for compatibility testing.
This flag should never be used in production.

Detection logic:
- MBR: Valid 0x55AA signature at offset 510, plus valid boot indicators (0x00/0x80)
- GPT: Protective MBR with partition type 0xEE

See [quirks.md](docs/quirks.md) for details on safe vs unsafe quirks classification.

## Communication Protocol

TBD - Options to explore:
- virtio-vsock for guest-host communication
- Shared memory regions with explicit synchronization
- Simple serial/console based protocol for prototyping

## Prototype Approaches

### Approach A: Minimal Linux Guest

Use a tiny Linux distribution (like Alpine or a custom initramfs) running
inside KVM. The guest runs a conversion daemon that communicates with the
host via virtio-vsock.

Pros:
- Can reuse existing libraries (e.g., qemu-img inside the guest)
- Familiar debugging environment
- Flexible

Cons:
- Larger attack surface (full Linux kernel)
- Higher memory/CPU overhead
- Boot time latency

### Approach B: Unikernel

Build a unikernel that only contains the conversion logic. No separate
kernel/userspace distinction.

Pros:
- Minimal attack surface
- Fast boot times
- Lower resource usage

Cons:
- More complex development
- Limited library ecosystem
- Harder to debug

### Approach C: Custom Bare-Metal (Active)

Write a minimal bare-metal program that runs directly under KVM with no OS.
Just enough code to handle virtio communication and format conversion.

**This is the approach being actively explored.**

Pros:
- Absolute minimum attack surface
- Fastest possible boot/execution
- Complete control

Cons:
- Significant development effort
- Must implement everything from scratch
- No existing tooling

**Progress:**
- [helloworld](prototypes/helloworld/) - Minimal KVM VMM with serial output
- [helloworld2](prototypes/helloworld2/) - Uses vm-memory crate for safer memory
- [virtio-block](prototypes/virtio-block/) - Virtio-block device emulation with file copy
- [virtio-block2](prototypes/virtio-block2/) - Adds guest-protocol (protobuf) integration
- [virtio-block3](prototypes/virtio-block3/) - Adds configurable sector sizes
- [virtio-block4](prototypes/virtio-block4/) - Adds performance statistics tracking
- [virtio-block5](prototypes/virtio-block5/) - Adds ioeventfd optimization
- [virtio-block6](prototypes/virtio-block6/) - Adds sparse/dynamic output file support
- [pluggable](prototypes/pluggable/) - Modular operations architecture
- [pluggable2](prototypes/pluggable2/) - Separate binary loading for operations
- [info](prototypes/info/) - Image format detection (qemu-img info equivalent)

**Current Implementation:**
The `info` prototype has been promoted to the main implementation in `src/`. This
provides a modular architecture with:
- **vmm/** - Host-side virtual machine monitor
- **core/** - Guest initialization (device init, call table)
- **operations/info/** - Format detection operation
- **operations/copy/** - File copy operation
- **shared/** - Shared library code between components

The rust-vmm project provides crates that reduce implementation effort by 70%+:
- `kvm-ioctls` - Safe KVM API wrappers
- `kvm-bindings` - KVM bindings
- `vm-memory` - Guest memory abstraction
- `virtio-queue` - Virtqueue implementation
- `virtio-bindings` - Virtio protocol bindings

## Format Support

### qcow2

QEMU Copy-On-Write version 2. Features:
- Sparse allocation
- Snapshots
- Compression (zlib, zstd)
- Encryption (LUKS)
- Backing files

### raw

Simple byte-for-byte disk representation. No metadata, just data.

### vmdk

VMware Virtual Machine Disk. Multiple sub-formats:
- monolithicSparse
- monolithicFlat
- twoGbMaxExtentSparse
- twoGbMaxExtentFlat
- streamOptimized

## Open Questions

1. How to handle backing files in qcow2? Flatten on conversion?
2. Should we support in-place format conversion or always copy?
3. What's the minimum viable protocol for host-guest communication?
4. How to handle progress reporting and cancellation?
5. Memory limits for the sandbox?
