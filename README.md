# Imago

A safe, sandboxed disk image format converter.

## Overview

Imago replaces unsafe calls to `qemu-img` with a safer, sandboxed approach.
Image format conversions are performed within a KVM execution context,
providing strong isolation from the host system.

The name "imago" comes from Latin (meaning "image") and biology (the final
adult stage of insect metamorphosis) - reflecting both the image handling
and transformation aspects of the tool.

## Supported Formats

Initial target formats:
- **qcow2** - QEMU Copy-On-Write format
- **raw** - Raw disk images
- **vmdk** - VMware Virtual Machine Disk

## Project Status

**Prototype phase** - Experimenting with different implementation approaches.

## Prototypes

Working prototypes exploring the KVM-based sandboxing approach:

| Prototype | Description |
|-----------|-------------|
| [helloworld](prototypes/helloworld/) | Minimal bare-metal KVM guest proof-of-concept |
| [helloworld2](prototypes/helloworld2/) | Uses vm-memory crate for safer memory management |
| [virtio-block](prototypes/virtio-block/) | Virtio-block device emulation with file copy |

See [docs/index.md](docs/index.md) for full prototype documentation.

## Development

### Pre-commit Hooks

This project uses pre-commit hooks for Rust code quality:

```bash
# Install pre-commit (if not already installed)
pip install pre-commit

# Install the hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

The hooks run rustfmt (formatting) and clippy (linting) on all Rust code via
Docker, ensuring consistent tooling regardless of local Rust installation.

To auto-fix formatting issues:
```bash
./scripts/check-rust.sh fix
```

## Directory Structure

```
imago/
├── .devcontainer/  # Development containers
│   └── rust-lint/  # Stable Rust for linting
├── crates/         # Shared Rust crates
│   └── guest-protocol/ # Protocol Buffers messaging for guests
├── prototypes/     # Experimental implementations
│   ├── helloworld/     # Minimal KVM VMM with bare-metal guest
│   ├── helloworld2/    # Same, using rust-vmm vm-memory crate
│   └── virtio-block/   # Virtio-block device emulation
├── scripts/        # Build and check scripts
├── docs/           # Design documents and research
│   ├── index.md    # Documentation index
│   ├── usage.md    # Platform usage analysis (oVirt, Proxmox, OpenStack)
│   ├── security.md # CVE analysis for image handling
│   ├── qcow2/      # QCOW2 format documentation
│   ├── vmdk/       # VMDK format documentation
│   └── raw/        # Raw format documentation
├── testdata/       # Test images for security validation
│   ├── benign/     # Safe test images (qcow2, raw, vmdk, vhdx, vpc)
│   ├── malicious/  # CVE exploit images (DANGEROUS)
│   └── downloaded/ # External test images (CirrOS, QEMU iotests, etc.)
└── README.md
```

## Security Model

The core security principle is that untrusted disk images should never be
parsed or manipulated by code running with host privileges. Instead:

1. A minimal KVM guest handles all image parsing and conversion
2. The host only deals with opaque byte streams
3. Any vulnerabilities in format parsing are contained within the sandbox

## Test Data

The `testdata/` directory contains 44 disk images for security validation:

- **Benign images** - Basic valid images in various formats for functionality testing
- **Malicious images** - Crafted to exploit known CVEs (CVE-2015-5163, CVE-2024-32498,
  CVE-2022-47951, etc.) including backing file exploits, external data file exploits,
  and VMDK descriptor attacks
- **Edge cases** - Valid but unusual configurations (min/max cluster sizes, extended L2,
  various refcount widths, backing file chains)
- **AFL-discovered** - Malformed images from QEMU's fuzzing that trigger parser errors

See `testdata/README.md` for full documentation.

## Documentation

The `docs/` directory contains:

- Format specifications derived from QEMU source analysis (QCOW2, VMDK, raw)
- Platform usage analysis showing how oVirt, Proxmox, and OpenStack use qemu-img
- Security vulnerability analysis covering ~35 CVEs related to image handling

See `docs/index.md` for the full documentation index.

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.
