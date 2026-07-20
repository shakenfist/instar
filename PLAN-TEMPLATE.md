# Title for the plan

## Prompt

Before responding to questions or discussion points in this
document, explore the instar codebase thoroughly. Read relevant
source files, understand existing patterns (VMM structure, guest
operation layout, shared crate conventions, call table ABI,
format parsing, test infrastructure), and ground your answers in
what the code actually does today. Do not speculate about the
codebase when you could read it instead. Where a question touches
on external concepts (QCOW2, VMDK, VHD/VHDX, LUKS, KVM, virtio,
disk image formats), research as needed to give a confident
answer. Flag any uncertainty explicitly rather than guessing.

All planning documents should go into `docs/plans/`.

Consult `ARCHITECTURE.md` for the overall system structure
(host VMM, KVM guest, call table, device emulation).
Consult `AGENTS.md` for build commands, project conventions,
code organisation, and the security model summary. Consult
`docs/` for format-specific documentation (`docs/qcow2/`,
`docs/raw/`, etc.) and `docs/commentary/` for architectural
decisions and design rationale.

When we get to detailed planning, I prefer a separate plan
file per detailed phase. These separate files should be named
for the master plan, in the same directory as the master
plan, and simply have `-phase-NN-descriptive` appended before
the `.md` file extension. Tracking of these sub-phases should
be done via a table like this in this master plan under the
Execution section:

```
| Phase | Plan | Status |
|-------|------|--------|
| 1. Format parsing and detection | PLAN-thing-phase-01-parse.md | Not started |
| 2. Guest operation implementation | PLAN-thing-phase-02-guest.md | Not started |
| ...   | ...  | ...    |
```

I prefer one commit per logical change, and at minimum one
commit per phase. Do not batch unrelated changes into a
single commit. Each commit should be self-contained: it
should build, pass tests, and have a clear commit message
explaining what changed and why.

## Situation

...

## Mission and problem statement

...

## Open questions

...

## Execution

...

## Agent guidance

### Execution model

All implementation work is done by sub-agents, never
in the management session. The management session (this
conversation) is reserved for planning, review, and
decision-making. This keeps the management context lean
and avoids drowning it in implementation diffs.

The workflow is:

1. **Plan** at high effort in the management session.
2. **Spawn a sub-agent** for each implementation step
   with the brief from the plan, at the recommended
   effort level and model.
3. **Review** the sub-agent's output in the management
   session. Check the actual files — the sub-agent's
   summary describes what it intended, not necessarily
   what it did.
4. **Fix or retry** if the output is wrong. Diagnose
   whether the brief was insufficient (improve it) or
   the model was too light (upgrade it), then re-run.
5. **Commit** once the management session is satisfied
   with the result.

This applies to all steps, including high-effort ones.
If a sub-agent can't succeed even with a detailed brief
and the right model, that's a signal the brief needs
improving, not that the management session should do
the implementation itself.

Use `isolation: "worktree"` for sub-agents when the
change is risky or experimental. The worktree is
discarded if the output is unsatisfactory. For safe,
well-understood changes, sub-agents can work directly
in the main tree.

### Planning effort

The master plan itself should always be created at
**high effort** — it requires broad codebase
understanding, cross-referencing multiple source files,
and making judgment calls about scope and sequencing.

Each phase plan should specify the recommended effort
level for planning that phase. Phases involving deep
protocol research, format-spec interpretation, or
architectural decisions (call-table changes, new
operations, new shared crates, security boundary
changes) should be planned at high effort. Phases that
are mechanical or follow well-established patterns can
be planned at medium effort.

### Step-level guidance

Each phase plan should include a table like this:

```
| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1a   | medium | sonnet | none     | One-sentence summary of what to do and which files to touch |
| 1b   | high   | opus   | worktree | Why this needs high effort: requires understanding X to do Y |
```

**Effort levels:**
- **high** — Requires reading multiple files, making
  judgment calls, understanding non-obvious invariants,
  or researching external references (format specs,
  qemu-img source, KVM/virtio docs). The sub-agent
  needs to think carefully about edge cases.
- **medium** — The plan provides enough context that the
  sub-agent can follow a clear brief. May need to read
  a few files but the approach is well-defined.
- **low** — Purely mechanical changes (rename, reformat,
  add a log line). The brief is a complete instruction.

**Model choice:** The planner should recommend which
model is best suited for each step. This is a judgment
call, not a rigid rule — the right model depends on what
the step requires, not on whether it's "planning" or
"implementation".

- **opus** — Best for steps that require deep reasoning,
  cross-file architectural understanding, subtle
  correctness judgment, or complex format/protocol
  research. Also appropriate for intricate implementation
  where getting it wrong would be costly to debug
  (e.g. cluster-table writers, refcount management,
  call-table changes that bridge VMM and guest).
- **sonnet** — Good default for well-briefed
  implementation work. Faster and cheaper than opus.
  Works well when the plan front-loads the research
  and the brief is detailed enough that the agent
  doesn't need to make broad judgment calls.
- **haiku** — Suitable for purely mechanical tasks:
  search-and-replace, adding log lines, running
  commands. The brief must be a near-complete
  instruction.

The model choice interacts with effort level and brief
quality. A detailed brief compensates for a lighter
model — sonnet at medium effort with a thorough brief
often matches opus at medium effort with a vague brief.
The planner's job is to write briefs good enough that
the recommended model can succeed.

Note: the model also determines the context window
(opus has 1M tokens, sonnet and haiku have 200K). Steps
that require holding many files in context simultaneously
may need opus for that reason alone, even if the
reasoning itself is straightforward. Format-conversion
work in particular tends to span the source format
parser, the destination format writer, the call table,
and the host-side glue at the same time.

**When in doubt, skew to the more capable model.**
Saving money only matters if the outcome is still
acceptable. A failed or low-quality implementation
wastes more time (and therefore more money) than using
a heavier model would have cost. Only recommend a
lighter model when you are confident the brief is
detailed enough for it to succeed.

**Brief for sub-agent:** This is the key field. Write it
as if briefing a colleague who has never seen the
codebase. Include: what to change, which files to touch,
what patterns to follow, and any non-obvious constraints
(memory layout, the 768KB guest binary cap, the
no-`std` requirement of the format crates, the call
table boundary). The better the brief, the lower the
effort level needed and the lighter the model that can
succeed.

A good brief front-loads the research the planner already
did, so the implementing agent doesn't repeat it. For
example, instead of "add tests for the QCOW2 L2 parser",
write "add tests for `parse_l2_entry()` in
`src/crates/qcow2/src/lib.rs`. Use the adversarial
fixtures in `instar-testdata/adversarial/qcow2/` (cluster
boundary edges, OFLAG_COMPRESSED set with extended L2
cluster, refcount underflow). The function takes
`(entry: u64, cluster_bits: u32)` and returns
`Option<L2Entry>`."

### Management session review checklist

After a sub-agent completes, the management session
should verify:

- [ ] The files that were supposed to change actually
      changed (read them, don't trust the summary).
- [ ] No unrelated files were modified.
- [ ] `make instar` builds and `make lint` is clean.
- [ ] Guest binaries pass `make check-binary-sizes`
      (768KB limit per operation).
- [ ] `make test-rust` and the relevant
      `make test-integration` targets pass.
- [ ] `pre-commit run --all-files` passes.
- [ ] The changes match the intent of the brief — not
      just syntactically correct but semantically right.
- [ ] Commit message follows project conventions
      (including the Co-Authored-By line with model,
      context window, effort level, and other settings).

## Administration and logistics

### Success criteria

We will know when this plan has been successfully implemented
because the following statements will be true:

* `make instar` builds and `make lint` is clean.
* Guest binaries pass `make check-binary-sizes` (768KB limit).
* All Rust unit tests pass (`make test-rust`).
* All Python integration tests pass (`make test-integration`).
* `pre-commit run --all-files` passes.
* New format parsing is extracted into a shared crate under
  `src/crates/` where appropriate, and remains `no_std`
  compatible for guest use.
* Cross-validation against `qemu-img` is included for any new
  format or operation support.
* Documentation in `docs/` has been updated to describe the new
  features.
* `ARCHITECTURE.md`, `README.md`, `AGENTS.md`, and
  `CHANGELOG.md` have been updated as needed.

### Future work

We should list obvious extensions, known issues, unrelated bugs
we encountered, and anything else we should one day do but have
chosen to defer to here so that we don't forget them.

...

### Bugs fixed during this work

This section should list any bugs we encounter during
development that we fixed. You should also scan the relevant
github bug tracker to see if there are any directly related
bugs that we should either resolve as part of this master
plan, or at least be aware of when planning.

### Documentation index maintenance

When creating a new master plan from this template, update
the following files in `docs/plans/`:

* **`index.md`** — add a row to the *Master plans* table
  with the creation date, a link to the plan, a one-line
  intent summary, the initial status, and links to each
  phase plan file. Keep the table in chronological order.
* **`order.yml`** — add an entry for the new master plan
  so it appears in the documentation navigation bar. Phase
  files should *not* be added to `order.yml`.

When all phases of a plan are complete, update the status
column in `index.md` to *Complete*.

### Back brief

Before executing any step of this plan, please back brief
the operator as to your understanding of the plan and how
the work you intend to do aligns with that plan.
