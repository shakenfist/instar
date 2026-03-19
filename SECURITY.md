# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in imago, please report
it responsibly via
[GitHub Security Advisories](https://github.com/shakenfist/imago/security/advisories/new).

Please **do not** open a public issue for security vulnerabilities.

We aim to acknowledge reports within 48 hours and provide a fix or
mitigation plan within 7 days for confirmed vulnerabilities.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | Yes                |
| 0.1     | No (internal only) |

## Security Model

Imago's core security principle is that untrusted disk images are
never parsed by code running with host privileges. All format
parsing and data transformation happens inside a KVM-isolated
guest. The host VMM only handles opaque byte streams via
virtio-block devices.

For a detailed description of the security model, see
[docs/security.md](docs/security.md).

For published audit results, see
[docs/security-audits.md](docs/security-audits.md).

## Scope

The following are in scope for security reports:

- Guest escape from the KVM sandbox
- Host memory disclosure via the serial protocol or virtio-block
  devices
- Denial of service via crafted images that crash the VMM
  (host-side process)
- Path traversal via backing chain discovery
- Any bypass of the backing file path allowlist

The following are **not** in scope:

- Crashes or hangs inside the KVM guest (these are contained by
  the sandbox and do not affect the host)
- Issues requiring root access to the host
- Issues in dependencies that do not affect imago's usage of them
