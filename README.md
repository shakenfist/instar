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

## Directory Structure

```
imago/
├── prototypes/     # Experimental implementations
├── docs/           # Design documents and research
└── README.md
```

## Security Model

The core security principle is that untrusted disk images should never be
parsed or manipulated by code running with host privileges. Instead:

1. A minimal KVM guest handles all image parsing and conversion
2. The host only deals with opaque byte streams
3. Any vulnerabilities in format parsing are contained within the sandbox

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.
