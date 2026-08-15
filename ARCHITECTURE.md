# Instar Architecture

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

### Instar's Approach

```
┌─────────────────────────────────────────────────────────────┐
│                        Host System                          │
│                                                             │
│  ┌─────────────┐     ┌─────────────────────────────────┐   │
│  │   Instar    │     │        KVM Sandbox              │   │
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
### Auditing the unsafe code

All `unsafe` code in the codebase has been audited and classified. The
VMM (host-side) code has undergone a full boundary audit covering
virtio-block device emulation, serial protocol handling, MMIO dispatch,
and KVM exit handling. Guest-side format parsing uses unsafe for pointer
arithmetic on binary data, with comprehensive bounds checking on all
image-derived offsets, and integer arithmetic on untrusted input uses
Rust's checked arithmetic (`checked_mul`, `checked_add`). Full results
are in [docs/security-audits.md](docs/security-audits.md); the threat
model is [docs/security.md](docs/security.md).


### RAW Format Validation

A key security enhancement over qemu-img is partition table validation for RAW
format detection. qemu-img treats any unrecognized file as a valid RAW disk
image, which is the root cause of backing file disclosure attacks (CVE-2015-5163,
CVE-2024-32498).

**Instar's default behavior (secure):** Files without recognized format headers
must have a valid partition table (MBR or GPT) to be accepted as RAW disk images.
Files without valid partition tables are rejected as "unknown format."

**With `--unsafe-quirks`:** Matches qemu-img behavior for compatibility testing.
This flag should never be used in production.

Detection logic:
- MBR: Valid 0x55AA signature at offset 510, plus valid boot indicators (0x00/0x80)
- GPT: Protective MBR with partition type 0xEE

See [quirks.md](docs/quirks.md) for details on safe vs unsafe quirks classification.
## Multi-Device Operations

Some operations (rebase, commit) mutate one image while reading from
others. The VMM exposes up to 16 virtio-block devices to the guest,
each with its own MMIO base, sector size, and capacity. A `ChainConfig`
structure at a fixed guest-physical address tells the guest which
device index holds what — the overlay being modified, the old backing
chain, the new backing chain, and so on. See
[docs/chain-config.md](docs/chain-config.md) for the binary layout and
[docs/chain-discovery.md](docs/chain-discovery.md) for how the VMM
discovers backing chains in the first place.

Commit is the only v1 operation that opens an **input** device RW: the
overlay attaches at input slot 0 RW so the guest's overlay-clear pass
can write through the call-table primitive `write_input_sector(0, ...)`.
Every other operation opens input devices read-only, with the
output-device pointer attached separately. The host's
`open_chain_devices_rw(rw_slots: &[usize], ...)` helper takes an
explicit list of slots to open RW; rebase passes the empty list,
commit passes `&[0]`.

## Communication protocol

Host and guest exchange typed messages over a shared-memory call table
rather than an ad-hoc serial protocol. The wire types live in the
`guest-protocol` crate — see
[docs/crates/guest-protocol.md](docs/crates/guest-protocol.md) — and the
call table, its versioning discipline and the guest memory map are
documented in
[docs/guest-architecture.md](docs/guest-architecture.md).

## Where the detail lives

| Topic | Document |
|-------|----------|
| VMM and guest internals, call table, memory map, prototype approaches | [docs/guest-architecture.md](docs/guest-architecture.md) |
| What each format parser supports | [docs/format-internals.md](docs/format-internals.md) |
| qemu-img parity and coverage matrix | [docs/format-coverage.md](docs/format-coverage.md) |
| Threat model | [docs/security.md](docs/security.md) |
| Unsafe-code audit results | [docs/security-audits.md](docs/security-audits.md) |
| Safe versus unsafe quirks | [docs/quirks.md](docs/quirks.md) |
| Building, dev containers, toolchain pinning, CI | [docs/development.md](docs/development.md) |
| Tests, test images, fuzzing | [docs/testing.md](docs/testing.md) |
| Backing chain discovery and config | [docs/chain-discovery.md](docs/chain-discovery.md), [docs/chain-config.md](docs/chain-config.md) |
| Why Rust | [docs/rust-rationale.md](docs/rust-rationale.md) |

[docs/index.md](docs/index.md) is the full index.

## Format support

Measurable target formats are raw, qcow2, vmdk and vpc (VHD), plus vhdx
where qemu-img has no `measure` implementation at all. Creatable target
formats are raw, qcow2, vmdk (monolithicSparse and streamOptimized), vpc
(dynamic and fixed) and vhdx (dynamic). Backing-file references are
supported on qcow2, vmdk, vpc and vhdx, matching qemu-img's permission
set.

Per-format feature detail is in
[docs/format-internals.md](docs/format-internals.md); the parity matrix
against qemu-img is in
[docs/format-coverage.md](docs/format-coverage.md); documented writer
divergences are in [docs/quirks.md](docs/quirks.md).

## Verification strategy

Three independent oracles check the parsers, all documented in
[docs/testing.md](docs/testing.md):

- **Cross-version qemu-img baselines** — expected output is captured per
  qemu-img version so a distro upgrade cannot silently change what
  "correct" means.
- **oslo.utils cross-validation** — `tests/test_oslo_crossval.py` runs
  both instar and oslo.utils `format_inspector` against every test
  image, comparing format detection, safety verdicts and virtual size.
  CI runs it against the PyPI release, and separately against
  oslo.utils git master to catch upstream drift early.
- **Differential and coverage-guided fuzzing** —
  `scripts/differential-fuzz.py` compares instar against qemu-img over
  random operation chains on random images, and `src/fuzz/` drives the
  `no_std` parser crates directly under `cargo-fuzz` with a mock call
  table.

## Open Questions

1. How to handle backing files in qcow2? Flatten on conversion?
2. Should we support in-place format conversion or always copy?
3. What's the minimum viable protocol for host-guest communication?
4. How to handle progress reporting and cancellation?
5. Memory limits for the sandbox?
