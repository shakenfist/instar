# Instar

A safe, sandboxed disk image format converter.

Instar replaces unsafe calls to `qemu-img` with a safer, sandboxed
approach: untrusted disk images are never parsed or manipulated by code
running with host privileges. A minimal KVM guest handles all image
parsing and conversion, the host only deals with opaque byte streams,
and any vulnerabilities in format parsing are contained within the
sandbox. It will mostly be of interest to cloud and virtualization
platforms (OpenStack, oVirt, Proxmox and similar) that process disk
images uploaded by users.

Instar is a drop-in replacement for qemu-img: output is byte-for-byte
compatible, and operations include `info`, `check`, `compare`,
`convert`, `dd`, `measure`, `create`, `resize`, `rebase`, `commit`,
`map`, `snapshot`, `amend`, `bitmap`, and `bench`. Supported formats
include qcow2, raw, vmdk, vpc (VHD), vhdx, and LUKS containers, with
read-only input support for vdi, parallels, qcow (v1), and dmg — see
[docs/format-coverage.md](https://github.com/shakenfist/instar/blob/develop/docs/format-coverage.md)
for the full op × format matrix.

Confused about how instar does these things? Perhaps read the
[technology primer](https://github.com/shakenfist/instar/blob/develop/docs/technology-primer.md).
If you want a guided tour of the source code, the
[Lions-style commentary](https://github.com/shakenfist/instar/blob/develop/docs/commentary/index.md)
provides a reading order and annotated walkthrough of the codebase.

## Installation

```bash
VERSION=0.3.0
curl -sLO "https://github.com/shakenfist/instar/releases/download/v${VERSION}/instar_${VERSION}-1_amd64.deb"
sudo apt install "./instar_${VERSION}-1_amd64.deb"
```

RPM and tarball artifacts are also published; you need Linux with KVM
access (`/dev/kvm`) and glibc 2.39 or newer. See
[docs/installation.md](https://github.com/shakenfist/instar/blob/develop/docs/installation.md)
for all package formats, system requirements, and building from source.

## Usage

```bash
instar info image.qcow2                    # format information
instar check --repair image.qcow2          # validate and repair
instar compare image1.raw image2.raw       # content comparison
instar convert -O qcow2 in.raw out.qcow2   # format conversion
instar snapshot -l disk.qcow2              # internal snapshots
```

Each subcommand has a full reference under docs/:
[info](https://github.com/shakenfist/instar/blob/develop/docs/info.md),
[check](https://github.com/shakenfist/instar/blob/develop/docs/check.md),
[compare](https://github.com/shakenfist/instar/blob/develop/docs/compare.md),
[convert](https://github.com/shakenfist/instar/blob/develop/docs/convert.md),
[dd](https://github.com/shakenfist/instar/blob/develop/docs/dd.md),
[measure](https://github.com/shakenfist/instar/blob/develop/docs/measure.md),
[create](https://github.com/shakenfist/instar/blob/develop/docs/create.md),
[resize](https://github.com/shakenfist/instar/blob/develop/docs/resize.md),
[rebase](https://github.com/shakenfist/instar/blob/develop/docs/rebase.md),
[commit](https://github.com/shakenfist/instar/blob/develop/docs/commit.md),
[map](https://github.com/shakenfist/instar/blob/develop/docs/map.md),
[snapshot](https://github.com/shakenfist/instar/blob/develop/docs/snapshot.md),
[amend](https://github.com/shakenfist/instar/blob/develop/docs/amend.md),
[bitmap](https://github.com/shakenfist/instar/blob/develop/docs/bitmap.md), and
[bench](https://github.com/shakenfist/instar/blob/develop/docs/bench.md).

## Security

Security is the point of this project. Beyond the KVM sandbox, instar
tightens qemu-img's riskiest behaviours (for example, RAW files must
carry a valid partition table before being accepted — the root cause of
several backing-file disclosure CVEs), and the codebase undergoes
periodic security audits covering unsafe code review, adversarial
images, CVE reproduction, and the VMM boundary. See
[docs/format-detection-safety.md](https://github.com/shakenfist/instar/blob/develop/docs/format-detection-safety.md),
[docs/quirks.md](https://github.com/shakenfist/instar/blob/develop/docs/quirks.md),
[docs/security-audits.md](https://github.com/shakenfist/instar/blob/develop/docs/security-audits.md),
and
[SECURITY.md](https://github.com/shakenfist/instar/blob/develop/SECURITY.md)
for vulnerability reporting.

## Documentation

In the [docs/](https://github.com/shakenfist/instar/blob/develop/docs/index.md)
directory:

- [Documentation Index](https://github.com/shakenfist/instar/blob/develop/docs/index.md) - The full index: per-command guides, format internals, prototypes, and research
- [Installation](https://github.com/shakenfist/instar/blob/develop/docs/installation.md) - Packages, system requirements, and building from source
- [Technology Primer](https://github.com/shakenfist/instar/blob/develop/docs/technology-primer.md) - How the KVM sandbox works
- [Configuration Guide](https://github.com/shakenfist/instar/blob/develop/docs/configuration.md) - Command-line flags, config files, quirk control
- [Format Coverage](https://github.com/shakenfist/instar/blob/develop/docs/format-coverage.md) - The op × format parity matrix against qemu-img
- [Development](https://github.com/shakenfist/instar/blob/develop/docs/development.md) - Building, Makefile targets, tests, fuzzing, releases, and GitHub automation
- [Integration Testing](https://github.com/shakenfist/instar/blob/develop/docs/testing.md) - The differential test suite against qemu-img

Project reference files:

- [ARCHITECTURE.md](https://github.com/shakenfist/instar/blob/develop/ARCHITECTURE.md) - Design goals, the security model, and format support internals
- [AGENTS.md](https://github.com/shakenfist/instar/blob/develop/AGENTS.md) - Guide for AI coding assistants, including the project's Claude Code skills
- [CHANGELOG.md](https://github.com/shakenfist/instar/blob/develop/CHANGELOG.md) - Release history

This project includes Claude Code skills in `.claude/skills/` for
common development tasks (scaffolding operations, format references,
debugging, test images and more) — see
[AGENTS.md](https://github.com/shakenfist/instar/blob/develop/AGENTS.md)
for the list.

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.
