# Agents Guide for Instar

Conventions and gotchas for working on instar that you cannot infer by
reading the code. Everything else is documented elsewhere; this file
points you there rather than restating it.

## What instar is

Instar is a safe, sandboxed disk image format converter. It replaces
unsafe `qemu-img` calls with conversions performed inside a KVM sandbox.
The core principle is **never parse untrusted data with host
privileges**: host code handles opaque byte streams, all format parsing
happens inside the guest, and an exploit in a format parser is contained
there.

## Where the documentation lives

| Question | Document |
|----------|----------|
| How is it put together? | [ARCHITECTURE.md](ARCHITECTURE.md) |
| How do the VMM and guest work? | [docs/guest-architecture.md](docs/guest-architecture.md) |
| What does each format parser support? | [docs/format-internals.md](docs/format-internals.md) |
| How does it compare to qemu-img? | [docs/format-coverage.md](docs/format-coverage.md) |
| What is the threat model? | [docs/security.md](docs/security.md) |
| What did the unsafe-code audits find? | [docs/security-audits.md](docs/security-audits.md) |
| Which quirks are safe and which are not? | [docs/quirks.md](docs/quirks.md) |
| How do I build, lint and release? | [docs/development.md](docs/development.md) |
| How do I run and add tests? | [docs/testing.md](docs/testing.md) |
| How do I use the tool? | [docs/usage.md](docs/usage.md) and the per-operation pages |

[docs/index.md](docs/index.md) is the full index.

## Repository structure

```
instar/
├── .devcontainer/  # Development containers (rust-lint)
├── src/            # Main instar implementation
│   ├── vmm/        # Virtual machine monitor (host-side)
│   ├── core/       # Core guest initialization
│   ├── crates/     # Shared format crates (qcow2, raw, vmdk, vhd, vhdx, luks, vdi, parallels, qcow1, dmg)
│   ├── shared/     # Shared library code (byte-order helpers, configs)
│   ├── operations/ # Pluggable operations (info, copy, check, compare, convert, dd, measure, create, resize, rebase, commit, map, snapshot, amend, bitmap, bench)
│   └── build.sh    # Build script
├── crates/         # Shared Rust crates (guest-protocol)
├── prototypes/     # Experimental implementations (11 KVM prototypes)
├── scripts/        # Build, check, and test image generation scripts
├── tests/          # Integration tests (Python/testtools)
├── docs/           # Design documents, research notes, and Lions-style commentary
├── testdata/       # Test images for security validation
└── Makefile        # Build and development automation
```

The `info` prototype was promoted into `src/`; the rest of
`prototypes/` remains as reference material, not shipped code.

## Supported formats

Write formats (create / convert-output / dd-output): qcow2 (including
external data files), raw, vmdk, vpc (VHD), vhdx (VHDX).

luks: info + decrypting convert / compare / dd (v1/v2; no create/write).

Read-only input formats (convert / compare / dd / bench source; no
create/write): vdi, parallels (both magics), qcow (QCOW1, including
backing chains and compressed clusters), dmg (UDIF, zlib/raw/zero/ignore
chunk codecs).

Per-format feature detail is in
[docs/format-internals.md](docs/format-internals.md).

## Things that will bite you

- **Never call `.unwrap()` in production code.** The workspace enables
  clippy's `unwrap_used` lint and CI runs `-D warnings`, so a new unwrap
  fails lint. Use `?` and proper error propagation, or
  `.expect("why this cannot fail")` for provably-infallible cases
  (`.expect("lock poisoned")` for mutexes). Test code is exempt via
  `clippy.toml`'s `allow-unwrap-in-tests`.

- **Do not un-pin the Rust nightly, and do not bump it by hand.** Both
  devcontainer Dockerfiles pin the same nightly via
  `ARG RUST_NIGHTLY=nightly-YYYY-MM-DD`; a floating nightly has taken
  out from-scratch image builds before. Renovate cannot bump rustup
  toolchain pins, so the weekly `rust-nightly-bump` workflow rebuilds
  and tests both images before opening a bump PR. A bump can also change
  the .rpm's generated dependencies and make the package uninstallable,
  which nothing in the pull-request gate will catch — see "RPM
  dependency generation" in
  [docs/development.md](docs/development.md).

- **Devcontainer `cargo install` lines stay version-pinned and
  `--locked`.** An unpinned install re-resolves its whole dependency
  tree on every from-scratch image build, and a single broken upstream
  publish then fails CI on every PR. Each pin's `# renovate:` comment
  must stay directly above its `ARG` to remain managed, and Renovate
  bumps a crate across both Dockerfiles in one PR — never bump one file
  alone. See "Cargo tool pinning" in
  [docs/development.md](docs/development.md).

- **A new integration test module needs a CI partition.**
  `tools/ci/check-test-partition.sh` fails if any `test_*.py` test is run
  by no pull-request job. An orphan is a hard CI failure; deliberate
  exclusions live in an allowlist in
  `tools/ci/check-test-partition.py`.

- **`automated_reviewer`'s `needs` list must name every job that can
  fail a PR**, including `ci-tooling`. Three jobs are deliberately
  outside it, each for a stated reason in the comment above the list:
  `oslo-crossval-master` is `continue-on-error`, and `agent-context.yml`
  and `mermaid-lint.yml` are separate workflow files, which `needs:`
  cannot reach. Both of those are path-filtered and neither is a
  required check, so a red result on either is visible on the pull
  request and blocks nothing automatically.

- **The call table is append-at-end and versioned.** Adding an entry
  bumps `VERSION`; never reorder or reuse an index. The entries and
  their versioning discipline are in
  [docs/guest-architecture.md](docs/guest-architecture.md).

- **Comment security-relevant decisions.** Bounds checks and checked
  arithmetic on image-derived values exist for a reason; a future reader
  needs to know which invariant a check is protecting.

- **Prefer clarity over cleverness**, and follow the conventions of
  whatever language is being used. Rust code is formatted by `rustfmt`
  and linted by `clippy`, both enforced by the pre-commit hooks;
  `./scripts/check-rust.sh fix` auto-fixes formatting.

- **Diagrams of structure or flow are `mermaid` fences, not ASCII art**,
  and they fail at render time rather than at commit time, so run
  `tools/mermaid-lint.sh` before pushing. Character art whose meaning is
  its column alignment -- file trees, memory maps, register layouts, byte
  layouts, terminal output -- stays in a plain fence. `prototypes/*/README.md`
  is out of scope and keeps its original ASCII as a historical record.
  See "Diagrams" in [docs/development.md](docs/development.md).

## Adding a prototype

1. Create a subdirectory under `prototypes/` with a descriptive name
2. Include a README explaining the approach being tested
3. Document any dependencies or build requirements

## Planning documents

Tracked planning documents live in `docs/plans/` and follow the structure
in `PLAN-TEMPLATE.md` at the repo root. Each tracked plan is committed
alongside the work it describes, with phase plans named
`PLAN-<feature>-phase-NN-<descriptive>.md` next to the master plan.
`docs/plans/index.md` summarises every master plan; `docs/plans/order.yml`
controls the documentation navigation order.

`PUSH-AUDIT.md` at the repo root is the pre-push audit runbook — two
waves of build, lint and judgment checks over a change — and it runs as
the last phase of every master plan.

Plan phase numbers belong in plan documents only. Documentation
describes what the software does today; if a feature is not built yet,
link the master plan rather than citing a phase.

## Claude Code skills

Twelve skills in `.claude/skills/<name>/SKILL.md` cover the repetitive
work, seven of them the project's own conventions (error handling,
testing discipline, documentation updates, pull request preparation and
so on). They are selected by their `description` frontmatter rather than
invoked by name, so read the directory rather than a list here — an
enumeration in this file is a second copy that goes stale, and every
line here costs context on every task.

Two are worth knowing exist because they are hard to guess at:
`instar-new-op` scaffolds a complete operation skeleton with all its
required files, and `instar-add-test-image` walks through adding a disk
image to the integration suite, including `tests/manifest.json` and the
safe handling of expected output for malicious images.
