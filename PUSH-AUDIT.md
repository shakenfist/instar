Thanks for your work on this. I appreciate it. Some final
checks before I push.

## How to use this template

The pre-push audit splits into two waves:

**Wave 1 — mechanical.** Build verification, lint,
test suite, and the parts of style conformance that grep
can answer.  Wrapped in a single shell script so it runs
as one tool approval.  Always run wave 1 first; wave 2 is
only worth spending on if wave 1 passes.

**Wave 2 — judgment.** Code-quality, test-coverage,
documentation, and security review.  Some of this is
mechanical (TODO/FIXME/dead-code grep, unsafe block list)
and is wrapped in a second script; the rest needs sub-
agents to read code and apply judgment.  The four
judgment agents are independent and can be spawned in
parallel.

The management session reviews all findings, fixes any
issues, and confirms the push.

## Wave 1: Mechanical checks

Run the consolidated script (one approval):

```
tools/audit/wave1.sh
```

It performs (and exits non-zero on any failure):

- `pre-commit run --all-files`
- `./scripts/check-rust.sh check` (rustfmt + clippy via
  the rust-lint container)
- `make instar` (full build, including guest binaries
  via the devcontainer)
- `make check-binary-sizes` (768KB-per-operation cap)
- `make test-rust` (workspace unit tests, excluding the
  no_main guest binaries)
- `make fuzz-build` (compiles every libFuzzer target; the
  `src/fuzz` crate is outside the main workspace, so this
  catches a fuzz target drifting out of sync with a
  workspace struct change before it fails in coverage-fuzz CI)
- mechanical style checks: lines wrapped at 120
  characters in changed Rust files, no large inline
  scripts in CI workflow steps (advisory), single
  quotes in changed Python files (advisory).

Exit codes:

| Code | Meaning                          |
|------|----------------------------------|
| 0    | all wave 1 checks passed         |
| 1    | pre-commit failed                |
| 2    | rustfmt or clippy failed         |
| 3    | `make instar` failed             |
| 4    | binary size cap exceeded         |
| 5    | `make test-rust` failed          |
| 7    | `make fuzz-build` failed          |

If wave 1 fails, fix the cause and re-run before
spending on wave 2.

### Style conformance — judgment portion

The script covers what grep can prove.  The remaining
style questions need a sub-agent to read code:

| Setting | Value |
|---------|-------|
| Model | sonnet |
| Effort | low |

**Brief for sub-agent (only if wave 1 passes):**

Check `git diff develop...HEAD` for adherence to project
conventions in `AGENTS.md`:

- Call table boundary discipline: any new host-side
  call must have a matching guest-side handler and
  vice versa, with names and signatures consistent on
  both sides of the call table.
- Format crate conventions: format parsers in
  `src/crates/` stay `no_std`, take an `&CallTable`
  rather than reaching for the host filesystem
  directly, and surface bounds-checked accessors not
  raw pointer arithmetic.
- Guest operation conventions: each operation lives in
  `src/operations/<name>/`, links against the shared
  format crates, and stays under the 768KB binary cap.
- Field rename / unit-change discipline: did any field
  silently change units (e.g. bytes → sectors, sectors
  → clusters) without a rename or doc comment?
- No large scripts (>5 lines) inline in
  `.github/workflows/*.yml` — they belong in
  `tools/`.

Report a short list of any violations found.  If none,
say "Style checks passed."

## Wave 2: Deeper review

Only run wave 2 after wave 1 passes.

Start with the consolidated mechanical script (one
approval):

```
tools/audit/wave2-mechanical.sh
```

It reports (does not block; never exits non-zero on
findings):

- TODO / FIXME / HACK / XXX in changed source files.
- Newly added `#[allow(dead_code)]` annotations.
- Count of new `#[test]` functions vs Rust files
  changed.
- Documentation files touched (warns if none — the diff
  may have merited doc updates).
- New `unsafe {}` blocks (especially in VMM code,
  where they cross the host/guest boundary).
- New `.unwrap()` / `.expect()` in changed files (raw
  list — review whether each is in test code or panic-
  safe in production).
- Adversarial / CVE-reproduction files added under
  `src/`, `tests/`, or `scripts/` that should instead
  live in `shakenfist/instar-testdata`.

Then spawn the judgment agents below.  They can run in
parallel.

### 2a. Code quality

| Setting | Value |
|---------|-------|
| Model | sonnet |
| Effort | medium |

**Brief for sub-agent:**

The mechanical script (`tools/audit/wave2-mechanical.sh`)
already extracted TODO/FIXME comments, new
`#[allow(dead_code)]`, `unsafe{}` blocks, and unwrap/
expect lists.  Take that report as input.

Add the judgment-level review on the diff
(`git diff develop...HEAD`):

- **Duplicated code:** Are there significant blocks of
  duplicated logic that the mechanical scan can't see?
  Look for copy-paste patterns across format crates
  (qcow2/vmdk/vhd/vhdx) and across guest operations
  (info/copy/check/compare/convert).
- **Missed abstractions:** Should any new code be
  extracted into a shared crate in `src/crates/`?
  Look for logic that a second guest operation would
  likely need (e.g. format detection, I/O helpers,
  memory layout constants, refcount accounting).
- **Triage the script's raw findings:** for each
  TODO/unwrap/unsafe the mechanical script flagged, say
  blocking or advisory and why.  Skip ones in
  `#[cfg(test)]` blocks.  For VMM `unsafe{}` blocks
  specifically, blocking unless the safety invariant
  is documented in a `// SAFETY:` comment.

Report findings as a bullet list.  For each finding,
state the file, line, and whether it's blocking (must
fix before push) or advisory (can address later).

### 2b. Test review

| Setting | Value |
|---------|-------|
| Model | sonnet |
| Effort | medium |

**Brief for sub-agent:**

Review the diff (`git diff develop...HEAD`) for test
coverage:

- Does every new public function or significant code
  path have test coverage?
- Do the tests include adversarial cases (malformed
  input, oversized headers, refcount underflow,
  cluster offsets pointing outside the file, malformed
  snapshots/backing chains)? For new format support,
  is there at least one fixture in `instar-testdata`
  that exercises the parser end-to-end?
- Are there any assertions that test implementation
  details rather than behaviour (fragile tests)?
- Are there any new modules or functions with zero test
  coverage that should have at least basic tests?
- Are both Rust unit tests AND Python integration tests
  run by both pre-commit hooks and CI? We have had
  historical bugs where guest-operation Rust code
  silently dropped out of CI coverage.

Also verify:
- All existing tests still pass (wave 1 already
  confirmed `make test-rust`; check the wave 1
  result).
- If practical, note whether `make test-integration`
  should be run to verify end-to-end behaviour against
  `qemu-img` cross-validation.

Report findings as a bullet list grouped by file.

### 2c. Documentation review

| Setting | Value |
|---------|-------|
| Model | sonnet |
| Effort | medium |

**Brief for sub-agent:**

Check that documentation matches the current code state.
Read the diff (`git diff develop...HEAD`) and verify:

<!-- shared-block: readme-discipline v1 -->
README discipline (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/readme-discipline.md`):

- New user-visible features are documented in `docs/` (and
  `ARCHITECTURE.md` / `AGENTS.md` where appropriate), not by
  adding bullets to `README.md`.
- `README.md` is a pitch: what the project is, who it is for,
  minimal installation instructions, a small number of usage
  examples, and curated absolute links into `docs/`. It only
  changes when the pitch, the install story, or the
  documentation links change.
- README growth is itself a finding: if the diff adds README
  content that belongs in `docs/`, flag it as blocking and
  move it.
<!-- shared-block-end -->

- New or changed subcommand behaviour is reflected in that
  subcommand's page in `docs/` (e.g. `docs/convert.md`,
  `docs/check.md`), and the README still briefly mentions
  the `.claude/skills/` integration.
- `ARCHITECTURE.md` reflects any new or modified guest
  operations, shared crates, VMM components, call-table
  entries, or memory-layout decisions.
- `AGENTS.md` reflects any new dependencies, build
  commands, or conventions.
- `CHANGELOG.md` has an entry under the appropriate
  section (Added / Changed / Fixed / Packaging / CI).
- `docs/` has been updated for the affected format or
  topic — `docs/qcow2/`, `docs/vmdk/`, `docs/security/`,
  `docs/output-formats.md`, etc.
- `docs/commentary/` has been reviewed against the
  change. If architectural decisions or data flow have
  changed, update the relevant commentary document.
- Plan files in `docs/plans/` are up to date — completed
  phases are marked complete in the master plan's
  Execution table, deferred items are listed in the
  Future work section, and `docs/plans/index.md` reflects
  the current status.
- Deferred work from phase plans is also reflected in
  the master plan's Future work section. We won't refer
  to phase plans again, so deferred work needs to be
  centrally tracked on the master.

Report findings as a bullet list. "No documentation
gaps found" is a valid answer.

### 2d. Security review

| Setting | Value |
|---------|-------|
| Model | opus |
| Effort | high |

**Brief for sub-agent:**

Security review of the diff (`git diff develop...HEAD`).
This requires careful judgment — read the actual code,
not just the diff summary.

instar's primary security boundary is the KVM sandbox.
Bugs in VMM (host-side) code bypass the sandbox; bugs
in guest-side code are contained.  Weight findings
accordingly.

Check for:

- **VMM input validation:** Any host-side code that
  reads untrusted bytes from the guest (serial protocol
  messages, virtio descriptors, MMIO writes) must be
  bounds-checked. Look for unchecked indexing,
  unbounded allocations driven by attacker-controlled
  lengths, and arithmetic overflow in offset/length
  arithmetic.
- **Sector-bounds checking:** Any new virtio-block
  read/write path must validate the sector range
  against the configured device capacity before
  touching the backing file.
- **Backing chain handling:** Any change to chain
  resolution must respect the configured allowlist and
  the maximum chain depth (`MAX_CHAIN_DEVICES`).
- **External data files:** QCOW2 images with
  `INCOMPAT_EXTERNAL_DATA` open a second device; the
  data path must be validated by the same allowlist.
- **Decompression bounds:** zlib/zstd output must be
  capped at `MAX_CLUSTER_SIZE`. Decompressing a
  hostile cluster must not OOM the guest or the VMM.
- **Unsafe code:** Are there any new `unsafe` blocks?
  For each, is the safety invariant documented and
  sound? VMM unsafe blocks are higher risk than guest
  unsafe blocks.
- **Concurrency:** Are there new shared-state patterns
  in the VMM (Arc, Mutex, atomics)? Could they
  deadlock or race?
- **Resource exhaustion:** Could a malicious image
  cause unbounded memory growth, file-descriptor leaks,
  CPU spin, or guest hang in a way that the VMM
  doesn't detect via its KVM-exit timeout?

Report findings with severity (critical / high /
medium / low / informational). For each finding, state
the file, line, the vulnerability class, and a
recommended fix.  File any critical or high finding as
a `security-audit` GitHub issue (per
`PLAN-audit.md`'s vulnerability tracking conventions).

## Management session checklist

After all agents complete, the management session
should:

- [ ] Wave 1 passed (build, style, sizes, tests).
- [ ] Wave 2 findings reviewed.
- [ ] Any blocking findings from 2a/2b/2c have been
      fixed and re-verified.
- [ ] Any security findings from 2d have been assessed
      — critical and high must be fixed before push.
- [ ] The commit history is clean (no fixup commits
      that should be squashed, no accidental files,
      no committed PLAN-*.md drafts that should have
      stayed in `docs/plans/` only).
- [ ] The branch is up to date with the target branch
      (rebase if needed).
- [ ] Any required `shakenfist/instar-testdata`
      changes are committed and pushed there too.
- [ ] Ready to push.
