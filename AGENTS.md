# Agents Guide for Imago

This document provides guidance for AI agents working on the imago codebase.

## Project Overview

Imago is a safe, sandboxed disk image format converter. It replaces unsafe
`qemu-img` calls with conversions performed inside a KVM sandbox.

## Repository Structure

```
imago/
├── prototypes/     # Experimental implementations in various languages
├── docs/           # Design documents and research notes
├── README.md       # Project overview
├── ARCHITECTURE.md # Technical design and security model
├── AGENTS.md       # This file
└── LICENSE         # Apache 2.0
```

## Current Status

The project is in early prototype phase. We are exploring different
implementation approaches before committing to a specific language or
architecture.

## Key Concepts

### Security Model

The core principle: **never parse untrusted data with host privileges**.

- Host code only handles opaque byte streams
- All format parsing happens inside a KVM sandbox
- Exploits in format parsers are contained within the sandbox

### Supported Formats

Target formats: qcow2, raw, vmdk

## Working on This Project

### When Adding Prototypes

1. Create a subdirectory under `prototypes/` with a descriptive name
2. Include a README explaining the approach being tested
3. Document any dependencies or build requirements

### Code Style

- Follow the conventions of whatever language is being used
- Prioritize clarity over cleverness
- Comment security-relevant decisions

### Testing Considerations

- Test with malformed/malicious input images
- Verify sandbox containment
- Check for resource exhaustion (memory, disk, CPU)
