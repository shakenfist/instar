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
- `tools/mermaid-lint.sh` (renders every mermaid diagram in
  the tree through the upstream mermaid-cli container;
  mermaid fails at render time, so a broken diagram commits
  cleanly and nothing else here reads one. It also refuses a
  fence `mmdc` cannot read -- a tilde fence, or a space
  before the language -- which GitHub renders and the
  renderer does not, naming the file and the line)
- mechanical style checks: lines wrapped at 120
  characters in changed Rust files, no large inline
  scripts in CI workflow steps (advisory), single
  quotes in changed Python files (advisory).

Exit codes:

| Code | Meaning                        |
|------|--------------------------------|
| 0    | all wave 1 checks passed       |
| 1    | pre-commit failed              |
| 2    | rustfmt or clippy failed       |
| 3    | `make instar` failed           |
| 4    | binary size cap exceeded       |
| 5    | `make test-rust` failed        |
| 7    | `make fuzz-build` failed       |
| 8    | `tools/mermaid-lint.sh` failed |

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

<!-- shared-block: comment-proportion v1 -->
Comment proportion (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/comment-proportion.md`):

- A comment or docstring earns its length by saying what the code
  cannot: the contract, the units, the failure modes, the reason a
  surprising choice is correct. Restating the code in prose is not
  documentation.
- Treat as candidates any added comment or docstring that is longer
  than the code it documents, and any comment block over roughly
  fifteen lines attached to a body under ten. These are candidates,
  not verdicts -- a subtle algorithm, a public API contract, or a
  hard-won bug explanation can justify the length.
- Where the length is not justified the finding is advisory, and
  the fix is to cut the restatement rather than delete the comment:
  keep the why, drop the line-by-line narration of the what.
- Prose that documents user-visible behaviour rather than the
  implementation usually belongs in `docs/`, with the comment
  reduced to a pointer.
<!-- shared-block-end -->

<!-- shared-block: python-version-discipline v1 -->
Python version and typing (shared block; do not edit -- the
canonical copy lives in shakenfist/development at
`templates/shared-blocks/python-version-discipline.md`):

- No syntax or standard library API newer than the floor in
  `requires-python`. Structural pattern matching, `X | Y` unions in
  annotations evaluated at runtime, `tomllib`, and
  `datetime.UTC` each raise on an interpreter the package still
  claims to support, and none of them fail in CI when CI runs only
  the newest version. This is the finding to look for first: it is
  a real break on a real user's machine, not a style point.
- New and modified code carries type hints, and mypy is expected to
  be clean over it. A project part way through a staged rollout is
  held to the new code, not to the whole tree.
- Prefer the walrus operator and f-strings where they make the code
  read better, subject to the floor above.
- Raising the floor in `requires-python` is a supported-platforms
  decision, not a convenience: it drops users. If it is genuinely
  right, the platforms table, `requires-python` and
  `constraints.python` in `renovate.json` all move together.
<!-- shared-block-end -->

!!! note "In this project"

    instar ships no Python package: there is no `pyproject.toml`,
    `setup.py` or `setup.cfg`, and neither `requires-python` nor
    `constraints.python` appears anywhere in the tree. Python here is
    the integration test suite and the scripts under `tools/`, so the
    clauses about the declared floor and about moving `renovate.json`
    with it are inert — do not go looking for the files they name. The
    floor that does bite is the oldest `python3` on a supported
    distribution — Rocky 9 ships 3.9, which is why
    `tools/test-package-functional.sh` searches for a newer interpreter
    before running the suite there rather than taking `python3`. The
    typing clause applies normally.

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

<!-- shared-block: functional-test-coverage v1 -->
Functional test coverage (shared block; do not edit -- the
canonical copy lives in shakenfist/development at
`templates/shared-blocks/functional-test-coverage.md`):

- The standard is "do we run the code to do the real thing, and
  does it work as intended". Every subcommand exposed on the command
  line, and every endpoint exposed by an API, should have a test
  that exercises it for real rather than against a mock of itself.
- For a change that adds or alters user-visible behaviour, the
  question to answer is which functional test would have failed
  before it and passes after. If there is none, that is the finding,
  and it is a finding about this change rather than a note for
  later.
- Unit tests are held to no coverage percentage, but a branch that
  is reachable from outside the process and has no test is worth
  naming. Error paths and argument validation are where this bites:
  they are the code most often written once and never run again.
- Mocking the system under test proves nothing. Mock the boundary --
  the network, the clock, the hypervisor -- and let the code being
  tested actually run.
- Where a gap is real but out of scope for the change in hand, say
  so plainly and record it, rather than silently widening the
  change or silently leaving it unsaid.
<!-- shared-block-end -->

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

<!-- shared-block: llm-doc-discipline v1 -->
AGENTS.md and ARCHITECTURE.md discipline (shared block; do not
edit -- the canonical copy lives in shakenfist/development at
`templates/shared-blocks/llm-doc-discipline.md`):

- `AGENTS.md` is a working guide: the conventions, invariants and
  gotchas an agent cannot infer by reading the code, plus curated
  links into `docs/`. It is loaded into every session, so every
  line costs context on every task.
- `ARCHITECTURE.md` is a map: the component inventory, how data
  moves between components, and why the shape is the way it is.
  A deep dive on one subsystem belongs in `docs/`, where humans
  benefit from it too.
- One canonical home per fact. If `docs/` covers it, link to it
  instead of restating it -- and the same rule applies between
  `AGENTS.md` and `ARCHITECTURE.md`.
- Neither file is a reference manual, a runbook, or a changelog.
  CLI flags, configuration keys, wire protocols, step-by-step
  procedures and plan history go to `docs/`.
- Growth in either file is itself a finding: if the diff adds
  content that belongs in `docs/`, flag it as blocking and move
  it.
<!-- shared-block-end -->

<!-- shared-block: diagram-discipline v1 -->
Diagram discipline (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/diagram-discipline.md`):

- A diagram of *structure or flow* -- components and the arrows
  between them, an ordered exchange of messages, a state machine
  -- is written as a fenced `mermaid` block, not drawn in ASCII.
  GitHub renders those natively and the mkdocs sites render them
  through `pymdownx.superfences`, so the same source is a picture
  in both places.
- Not every box of characters is a diagram. These stay as plain
  code fences, because mermaid cannot express them and would lose
  what they show: directory and file trees; memory maps, address
  space layouts and register or bit-field diagrams, where column
  alignment carries the meaning; wire-format and on-disk byte
  layouts; captured terminal output; and tables. The test is
  whether the picture is nodes and edges. Something that is a
  table with lines drawn on it is a table.
- Pick the diagram type that matches the claim: `flowchart` for
  components and data flow, `sequenceDiagram` for an ordered
  exchange between parties, `stateDiagram-v2` for a state
  machine, `erDiagram` for data relationships. A sequence drawn
  as a flowchart has thrown away the ordering it existed to show.
- A new ASCII box-and-arrow diagram in the diff is a finding.
  Converting one the diff already touches is in scope; converting
  every other diagram in the file is not, because a sweep is its
  own change and its own review.
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

<!-- shared-block: plan-phase-references v1 -->
Plan phase references (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/plan-phase-references.md`):

- Documentation outside plans directories describes the current
  state of the software, not the history of how it was built. Do
  not write "implemented in phase 5" or "since phase 3 of the
  two-tier CI plan": a reader wants to know whether a feature
  exists, not which phase of which plan delivered it.
- If a documented behaviour is implemented, describe it plainly.
  If it is planned but not yet implemented, link to the master
  plan in `docs/plans/` instead of citing a phase number.
- Reserve the word "phase" for plan documents. A procedural
  document describing a live multi-stage process (a release
  runbook, say) should call its stages "steps" or "stages", so
  that a phase reference in `docs/` is always a plan smell.
- The consistency audit greps `README.md` and `docs/` (excluding
  plans directories) for "phase <number>". Append
  `<!-- audit-ok: phase-reference -->` to a line only when the
  reference is genuinely not about an implementation plan.
<!-- shared-block-end -->

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

<!-- shared-block: path-traversal-review v1 -->
Path construction from outside data (shared block; do not edit --
the canonical copy lives in shakenfist/development at
`templates/shared-blocks/path-traversal-review.md`):

- Treat as a candidate any filesystem path built from a value the
  process did not choose: a request parameter, an image name, tag or
  digest, a layer path, an archive member name, a filename out of a
  configuration file or a database row.
- The question is not whether the value looks dangerous but whether
  the resulting path is *proved* to stay inside its intended base
  directory. Resolve the joined path with `os.path.realpath()` and
  verify it still starts with the base; a check on the untrusted
  component alone is defeated by symlinks and by encodings the
  check did not anticipate.
- Prefer a helper that cannot be forgotten at a call site --
  `safe_path_join()` in occystrap, or the framework's own
  (`send_from_directory` in Flask) -- over an inline guard repeated
  at each join.
- Archive extraction is the case most often missed: a member name
  inside a tarball or zip is attacker-controlled in exactly the same
  way as a request parameter.
- Where a bare join is correct because every component is
  process-chosen, say so in a comment rather than leaving the
  reader to re-derive it.
<!-- shared-block-end -->

!!! note "In this project"

    `safe_path_join()` and `send_from_directory` are the occystrap and
    Flask helpers; instar is Rust with no web framework, so read those
    as the shape to look for rather than the API to call. There is no
    archive extraction here and no request parameter. The value that
    fits the block's description is the backing file path read out of a
    disk image header, which the chain walker resolves relative to the
    image it came from and then opens — an attacker-supplied path out of
    a file the tool was pointed at, in exactly the sense the block
    means. Everything else is a path the operator typed. The joins are
    all host side: the guest is handed block devices, not a filesystem.

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
