# Phase 11: coverage and differential fuzzing

Phase 11 of [PLAN-bat-population.md](PLAN-bat-population.md). Read its
phase 11 paragraph of "Sequencing rationale" and the "Constraints that
apply throughout" section, in particular the `no_std` panic-free rule
and the requirement that every qemu-img behaviour claim is cited or
measured. This phase consumes what phases 6, 7 and 8 built: the
streaming BAT filler (`vhdx::fill_fixed_bat`), `create -f vhdx -o
subformat=fixed` and `convert -O vhdx --subformat fixed`.

Planning effort: high. The master plan's paragraph reads as four picker
edits; the survey found that two of the four are blocked on
preconditions it does not mention, and the convert half needs a new
comparison strategy rather than a new picker entry. Deciding what to
fuzz and what the oracle is, is the whole of this phase's judgement.

Review effort: high. A differential fuzzer that reports a known bug on
every iteration is worse than no coverage, because the next person
triages it; and a fuzz target whose invariants are too weak passes
forever while proving nothing. The review that matters is of the
oracles and the exclusions, not of the harness code.

## What the survey found

The master plan's phase 11 paragraph was written before phases 6 to 10
executed. Four of its claims are stale or incomplete, and two of them
are load-bearing. File and line references are against `e0b0fe13`.

### `fuzz_create_emitters` says fixed output reaches no caller

`src/fuzz/fuzz_targets/fuzz_create_emitters.rs:194-201` pins the VHDX
arm to `VhdxSubformat::Dynamic` and `block_state_zero: true`, with this
comment:

```rust
// The dynamic image the create op writes. Fixed
// output reaches no caller yet, and its BAT filler
// is not among the emitters this target checks.
```

The first sentence was true when phase 6 wrote it and is false now:
phase 7 shipped `create -f vhdx -o subformat=fixed` and phase 8 shipped
`convert -O vhdx --subformat fixed`. The second sentence is still true
and is this phase's work. Step 11a replaces the comment along with the
code it describes.

The target asserts five numbered invariants over the returned
`MetadataPlan` (`assert_invariants`, `:~230-290`): bookkeeping
consistency, every write inside `minimum_file_size`, no overflow, a
write-count bound, and no two writes overlapping. None of them says
anything about BAT contents, because no emitter it drives produces a
BAT.

### `fill_fixed_bat` is already reachable from the fuzz crate

`vhdx::fill_fixed_bat` is `pub`
(`src/crates/vhdx/src/lib.rs:4374`) and `src/fuzz/Cargo.toml` already
depends on the `vhdx` crate, so a new target needs no plumbing. Phase 6
left six unit tests beside it (`:5598-5784`) covering qemu pins,
buffer-size independence, the forward map, a mid-chunk start, a partial
last block and the error paths. They pin specific layouts; what a fuzz
target adds is arbitrary layouts crossed with arbitrary index ranges.

### The differential fuzzer excludes the `vhd` create target entirely

`scripts/differential-fuzz.py:1574-1592`, `_create_option_picker`:

```
Excludes:
    vhd target entirely        (CHS-geometry rounding divergence)
```

and `target = rng.choice(['qcow2', 'vmdk', 'vhdx', 'raw'])`. The
divergence is live, not historical: `tests/test_create.py:2658-2665`
still carries five `KNOWN_WRITER_DIVERGENCES` entries reading "qemu
rounds VHD virtual_size to CHS geometry", and the comment below them
records that the preallocation cases inherit it (qemu-img reports
1079296 for a 1M VHD where instar reports 1048576).

So "teach the pickers ... the non-qcow2 preallocation modes" cannot
include vpc's by adding an option: vpc is not a create target in this
fuzzer, and adding it would diverge on virtual-size on every iteration
for a reason that has nothing to do with preallocation. Decision 2
settles what to do.

Also measured in the same function: preallocation is offered only
inside the `qcow2` arm (`:1616-1631`), the `vmdk` arm offers only
`monolithicSparse` and `streamOptimized` (`:1637`), and the `vhdx` arm
offers only `block_size` (`:1641-1647`) — no subformat, no
`block_state_zero`. The master plan is right that all three are
missing.

### The fuzzer hand-mirrors `tests/helpers/info_json.py`, and the mirror has drifted

`scripts/differential-fuzz.py:1504-1505`:

```
# Mirrors tests/helpers/info_json.py — keep in sync by hand. A divergence
# whitelist change in either copy should also land in the other.
```

The field sets are equivalent today: the mirror's
`_CREATE_UNIVERSAL_STRIP` merges the canonical
`UNIVERSAL_DIVERGENCE` and `CACHE_HINT_FIELDS`, which
`info_json.py:208-210` also unions, and the per-target sets match (the
mirror omits a `vpc` key, but it looks up with `.get(target, set())`
and the canonical `vpc` set is empty, so the behaviour is the same).

The filename handling has not kept up. The mirror's
`_create_substitute_filename` (`:1533-1542`) substitutes only a value
exactly equal to `tmp_path`. Phase 10 taught the canonical copy to
recognise the sibling file a create subformat writes beside its output
— `SIBLING_NAME_SUFFIXES`, `_decompose_name` and the
`$FILENAME<suffix>` rule at `tests/helpers/info_json.py:72-160` — and
the mirror has none of it.

That is harmless today, because the mirror's only caller is `op_create`
and its vmdk arm never picks `monolithicFlat`. It stops being harmless
the moment this phase adds that pick, and the failure is not subtle:
`op_create` writes the two sides to **different names**,
`create-instar.vmdk` and `create-qemu.vmdk`
(`scripts/differential-fuzz.py:1668-1669`). A monolithicFlat
descriptor names its extent, so the two `info` outputs carry
`create-instar-flat.vmdk` and `create-qemu-flat.vmdk` — different
strings, neither equal to its side's `tmp_path`, so neither is
substituted and every monolithicFlat iteration reports a divergence
that is purely the temp name. Phase 10's rule handles exactly this
shape: it derives the sibling from the primary's own name, so both
sides normalise to `$FILENAME-flat`.

### Convert has no VHDX target, and its oracle is blind to layout

`op_convert` picks `target_fmt = rng.choice(['raw', 'qcow2'])`
(`scripts/differential-fuzz.py:1017`). VHDX is not a convert target at
all, so there is no picker to teach.

The deeper finding is the oracle. For any non-raw target, `op_convert`
flattens **both** outputs to raw with `qemu-img convert -O raw` and
compares the bytes (`:1066-1090`, "neutral ground — neither tool is
favoured"). That is a content comparison, and it is deliberately blind
to the container's layout. Every property the fixed subformat exists to
get right — `LeaveBlocksAllocated`, a BAT entry for every payload
block, `PAYLOAD_BLOCK_ZERO` against `FULLY_PRESENT`, strictly
increasing 1 MiB-aligned offsets, nothing written past the payload
region — survives a raw flatten identically whether instar got it right
or wrong. Adding `vhdx` to that `rng.choice` list would buy no coverage
of this plan's subject.

This is why the master plan says "comparing through the structural
comparator for VHDX", and the survey's correction is about size rather
than direction: it is a new comparison arm in `op_convert`, not a
picker entry. The comparator itself is ready —
`tests/helpers/vhdx_structure.py` exists and is used by five test
modules — and the import mechanism is already proven in this very
file, which does `sys.path.insert` on `tests/` and imports
`helpers.snapshot_readback` (`:41-47`).

### Corrected at source

The master plan's phase 11 paragraph and `docs/plans/index.md`'s phase
11 entry are rewritten by this plan's registration commit to say what
the survey found, so the next reader does not re-derive it.

## Decisions

1. **Delete the hand-mirror; import the canonical normaliser.** Step
   11c removes `_CREATE_UNIVERSAL_STRIP`, `_CREATE_TARGET_STRIP`,
   `_CREATE_NESTED_INFO_STRIP`, `_create_strip_keys`,
   `_create_substitute_filename` and `_normalise_create_info` from
   `scripts/differential-fuzz.py` and calls
   `helpers.info_json.normalise_info_json` instead, by the
   `sys.path`/`helpers.` pattern the file already uses for
   `snapshot_readback`. The alternative — port phase 10's sibling rule
   into the mirror — keeps a comment that asks a human to notice a
   change in another file, which is the mechanism that just failed.
   Importing is the root-cause fix, and it is what makes the
   monolithicFlat pick in 11d safe rather than merely tested.

2. **vpc stays out of the differential create picker; its
   preallocation no-op is covered by the host tests instead.** The CHS
   virtual-size divergence is a real, documented, unfixed difference,
   and nothing in this plan proposes to change instar's rounding. The
   options were to add a vpc arm restricted to CHS-exact sizes, to mask
   `virtual-size` for vpc in the normaliser, or to leave vpc out. This
   phase leaves it out. Masking the field would blind the comparison to
   the one thing most worth catching in a VHD writer, and restricting
   sizes would mean the fuzzer only ever generates the shapes where the
   bug cannot appear — coverage theatre. The non-qcow2 preallocation
   no-op is already asserted directly against the pinned qemu builds by
   `test_vpc_noop_preallocation` and `test_vpc_fixed_noop_preallocation`,
   and phase 10 added `1M-prealloc-falloc` / `1M-prealloc-full` create
   baselines for vhd across all 80 versions. **So this phase's
   preallocation fuzzing covers vmdk and vhdx only, and says so in the
   picker's docstring.** This is the decision most likely to be argued
   with: it means the master plan's "the non-qcow2 preallocation modes"
   lands two-thirds complete. The counter-argument is that a fuzzer
   which cannot reach vpc create at all is a gap worth closing on its
   own merits; it is, and it is recorded in Future work rather than
   bolted onto a phase about fixed VHDX.

3. **Convert gets a structural comparison arm, not a picker entry.**
   Step 11e adds a `vhdx` branch to `op_convert` that compares the two
   outputs through `helpers.vhdx_structure`, and keeps the existing
   raw-flatten path for `raw` and `qcow2`. Both comparisons run for the
   vhdx branch: content equality through the flatten (which proves the
   payload survived) and structural equality through the comparator
   (which proves the layout matches). Reporting which of the two
   diverged is what makes a finding triageable.

4. **No `preallocation=metadata` for non-qcow2 targets.** instar
   refuses it there and so does qemu-img, so a picker that generated it
   would be fuzzing two error paths against each other. This matches
   phase 10's decision 5 for the create cases. `falloc` and `full` are
   generated, and the expectation is that both are no-ops.

5. **The filler gets its own fuzz target.** `fill_fixed_bat` takes a
   layout, a block state, a first index and an output buffer; its input
   space is index ranges crossed with buffer sizes, which has nothing
   in common with `fuzz_create_emitters`' create-option bytes. Folding
   it in would mean one target whose input bytes mean two unrelated
   things. New target `fuzz_vhdx_fixed_bat`, named for what it fuzzes
   rather than for the function.

6. **The fixed convert picker avoids the #879 geometry, by number.**
   `convert -O vhdx --subformat fixed` fails on a partial last block
   holding data (#879, found by phase 9, recorded in the master plan's
   Future work). A picker that generated that geometry would report a
   known bug on every run and train the next reader to ignore the
   fuzzer. Step 11e confines the fixed convert sizes to whole multiples
   of the block size, with a comment naming #879 and saying to remove
   the restriction when it is fixed. Phase 10 made the same call for
   the same reason and did not add a create case at that geometry.

7. **Fuzz targets are not added to CI's fuzzing schedule by this
   phase.** The coverage-fuzz workflow's target list and time budget
   are a CI-cost decision, not a correctness one, and the merge queue
   is already the subject of its own live issue. The targets are
   committed, buildable and runnable by hand; wiring them into the
   schedule is one line and is recorded in Future work. Step 11f
   documents how to run them.

## Step plan

All steps work in this worktree. 11a and 11b both touch
`src/fuzz/`, and every Rust step needs the Docker build, so no two
Rust steps run concurrently. 11c is a precondition for 11d (the
monolithicFlat pick is unsafe without it) and for 11e (which imports
by the same mechanism). 11d and 11e both edit
`scripts/differential-fuzz.py` and so run in sequence. 11f runs last.
Each step is its own commit.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 11a | high | opus | none | Extend `src/fuzz/fuzz_targets/fuzz_create_emitters.rs` to the fixed VHDX subformat and add the BAT invariants. **(1)** Replace the hardcoded `subformat: VhdxSubformat::Dynamic` / `block_state_zero: true` at `:194-201` with values drawn from the corpus bytes, in the style of the `vhd_sub` and `vmdk_sub` draws above (`:102-110`): fixed and dynamic, and both `block_state_zero` values. Delete the comment at `:197-199` — its first sentence ("Fixed output reaches no caller yet") is false since the fixed create and convert CLI paths landed, and its second is what you are fixing. Write a comment that says what the arm now covers. **(2)** Add invariants to `assert_invariants` (`:~230-290`) for a plan that carries a BAT, guarded so dynamic plans are unaffected: every payload entry's offset lies inside the payload region and does not run past `minimum_file_size`; offsets are strictly increasing across payload entries; every offset is 1 MiB aligned; every sector-bitmap slot in the emitted region is zero; and the entry count matches the block count the layout implies. Number them continuing from invariant 5 and give each the one-sentence "what breaking this looks like" comment the existing five have. **(3)** Keep the target panic-free on bad input: a rejected plan must come back as `Err`, never a panic, so any arithmetic you add is checked. **Verification you must run and report:** build with `make lint` and the repo's fuzz build (find how `src/fuzz` is built — it is a Docker path, do not install a Rust toolchain on the host); run the target against its existing corpus for a bounded time under `timeout`; and prove the new invariants can fail by breaking each one in turn in a scratch copy of the vhdx crate (e.g. make one offset non-aligned, make offsets non-monotonic, write a non-zero sector-bitmap slot) and confirming the target reports the invariant you broke and not a different one. Restore from a copy, never with `git checkout <dir>`, and clear any stale build artefacts after restoring. Leave uncommitted. Report: the invariant list, the corpus run's iteration count, and one line per deliberate break naming which assertion fired. ≤400 words. |
| 11b | medium | opus | none | Add a new libfuzzer target `src/fuzz/fuzz_targets/fuzz_vhdx_fixed_bat.rs` for `vhdx::fill_fixed_bat` (`src/crates/vhdx/src/lib.rs:4374`), and register it in `src/fuzz/Cargo.toml` beside the existing targets. `src/fuzz` already depends on the `vhdx` crate, so no plumbing is needed. Read the six unit tests at `src/crates/vhdx/src/lib.rs:5598-5784` first: they pin specific layouts and this target's job is the arbitrary ones. Draw from the corpus bytes a virtual size, a block size, a block state, a first BAT index and an output buffer length, derive the layout with the shared VHDX layout function phase 5 introduced (find it; do not recompute the layout by hand in the target), and call the filler. Assert on success: every entry written parses; payload entries carry the state the call asked for; offsets are strictly increasing and 1 MiB aligned; sector-bitmap slots are zero; the call wrote exactly the number of entries the index range and buffer size imply; and calling across any partition of the same index range into two calls produces byte-identical output to one call (the property phase 6's `fill_fixed_bat_is_the_same_through_any_buffer_size` pins for one layout — generalise it). Assert on failure: the error is one of the declared variants and the output buffer is untouched, as `fill_fixed_bat_errors_leave_the_buffer_untouched` requires. Never panic on any input. **Verification:** build it, run it under `timeout` long enough to be meaningful, report the iteration count and any crash with its `iter_seed`; then mutate the filler in a scratch copy (drop the 1 MiB alignment, skip the last entry, leave a sector-bitmap slot non-zero) and show the target catches each, naming which assertion fired. Restore from a copy. Leave uncommitted. Report ≤350 words. |
| 11c | high | opus | none | In `scripts/differential-fuzz.py`, replace the hand-maintained mirror of `tests/helpers/info_json.py` with an import of it. This is decision 1 and it is a precondition for 11d. **The mirror** is `:1504-1572`: `_CREATE_UNIVERSAL_STRIP`, `_CREATE_TARGET_STRIP`, `_CREATE_NESTED_INFO_STRIP`, `_create_strip_keys`, `_create_substitute_filename`, `_normalise_create_info`, under a comment admitting it must be kept in sync by hand. Its one caller is `op_create` (`:1653`). **The mechanism already exists in this file:** `:41-47` inserts `tests/` on `sys.path` and imports `helpers.snapshot_readback`; follow it exactly rather than inventing a second pattern. Read `tests/helpers/info_json.py` and use its public normaliser; match its target-name vocabulary (it keys both `vhd` and `vpc`) and check what it expects for the primary path argument. Delete the mirror and its comment. **Before you change anything, prove the swap is behaviour-preserving for what runs today**, because this is a refactor of a comparison function and a silent widening of it would make the fuzzer stop reporting real divergences: capture the normaliser's output for both sides on a sample of each existing create target (`qcow2`, `vmdk`, `vhdx`, `raw`) with the real `qemu-img info --output=json`, through the old code and the new, and show them byte-identical. Where they are not identical, do not "fix" the canonical copy to match the mirror — report the difference and stop; the canonical copy is the reference and a difference is a finding about the mirror. Note in your report whether the canonical copy's extra handling (snapshot date fields, the sibling rule) can reach `op_create`'s inputs at all today. **Verification:** the comparison above; `pre-commit run --all-files`; and a bounded `--ops create` fuzz run under `timeout` at a fixed seed before and after the change, showing the same iteration count and the same divergence count (expect zero). Leave uncommitted. Report ≤350 words. |
| 11d | high | opus | none | Teach `_create_option_picker` in `scripts/differential-fuzz.py` (`:1574`) the shapes this plan added. Requires 11c committed. **(1) vhdx arm** (`:1641-1647`): draw `subformat=fixed` as well as dynamic, and when fixed, draw `block_state_zero=on` and `off`. Keep the existing `block_size` draw, including the `None` case. Note that a fixed VHDX is dense: hold fixed sizes to the small end of the existing list so an iteration does not write a gigabyte, and say so in a comment. **(2) vmdk arm** (`:1637`): add `monolithicFlat`. **(3) preallocation for vmdk and vhdx**: draw `falloc` and `full` as well as none. Do **not** draw `metadata` for these targets (decision 4: both tools refuse it). **(4)** Do **not** add a `vhd` target (decision 2, the CHS virtual-size divergence) — instead update the function's docstring `Excludes:` block to say that vpc create is excluded for that reason *and* that it is therefore the one target whose preallocation no-op the differential fuzzer does not cover, naming the two host tests that do (`test_vpc_noop_preallocation`, `test_vpc_fixed_noop_preallocation`). **(5)** The docstring's existing claims are part of the diff you own: check each against the code and correct any that the last five phases falsified. **Verification you must run and report:** a bounded `--ops create` run under `timeout` at a fixed seed with enough iterations to hit every new shape at least once — report the per-shape hit counts, and if any shape is unreachable say so, because an option that is never drawn is not coverage. Any divergence the run reports is the most important thing in your report: for each, say whether it is a real instar/qemu difference, a normaliser gap, or a picker mistake, and paste both sides. Do not add a divergence whitelist entry to make a run clean — a real divergence here is a finding for the management session. Leave uncommitted. Report ≤400 words. |
| 11e | high | opus | none | Add a VHDX arm to `op_convert` in `scripts/differential-fuzz.py` (`:1009`) that compares structure, not just content. Requires 11c committed. **Why this is not a picker edit:** `op_convert` picks only `['raw', 'qcow2']` (`:1017`), and for any non-raw target it flattens both outputs to raw with `qemu-img convert -O raw` and compares bytes (`:1066-1090`). A raw flatten erases every property the fixed subformat exists to get right, so adding `vhdx` to that list alone would buy no coverage. **(1)** Add `vhdx` to the target choice, with a `--subformat fixed` draw and a dynamic draw. **(2)** For the vhdx target, run both comparisons and report which diverged: the existing raw-flatten content comparison, and a structural comparison through `tests/helpers/vhdx_structure.py`, imported by the `sys.path`/`helpers.` pattern at `:41-47`. Read the comparator first and use what it already offers; if it needs a new accessor, add it there rather than parsing VHDX inline in the fuzzer, and keep its existing callers (five test modules) working. Emit distinct divergence `type` values for a content difference and a structural difference — a single `convert_vhdx_divergence` would make the triage read the payload to find out which. **(3)** Confine the fixed sizes to whole multiples of the block size (decision 6), with a comment naming **#879** — `convert -O vhdx --subformat fixed` fails on a partial last block holding data — and saying to lift the restriction when #879 closes. Verify by hand that the geometries you generate do not hit it: create one at an excluded geometry and confirm it still fails, so the comment is justified rather than inherited. **(4)** qemu-img cannot write VHDX, so there is no qemu side for the fixed convert output. Establish what the two sides actually are before you write the comparison (instar fixed against instar dynamic? against the phase 1 pin? against a qemu-written dynamic VHDX?) and say in your report which oracle you chose and why; if the honest answer is that there is no qemu oracle for this target, say so plainly and make the arm compare instar against the pinned expectations instead — do not invent a comparison that looks symmetric but is not. **Verification:** a bounded `--ops convert` run under `timeout` at a fixed seed, with per-shape hit counts; one deliberately corrupted instar output showing the structural arm reports it and names the field. Leave uncommitted. Report ≤400 words. |
| 11f | medium | sonnet | none | Document the fuzzing this phase added. **(1) `docs/testing.md`:** extend its fuzzing section with the two new targets (`fuzz_create_emitters`' fixed arm and `fuzz_vhdx_fixed_bat`), how to run a target by hand, and the differential fuzzer's new create and convert shapes. State plainly which targets the differential fuzzer does **not** cover and why — vpc create (CHS virtual-size rounding) and the partial-last-block fixed convert geometry (#879) — because an undocumented exclusion reads as coverage. Reference the issue by number; do not cite plan, phase, step or decision numbers or any `PLAN-*.md` file in user-facing documentation. **(2) `CHANGELOG.md`:** one entry for the new fuzz coverage. **(3)** Check whether `AGENTS.md` states a convention this phase changed — "how to add a fuzz target" is a convention, so if it says anything about the fuzz crate it needs one line and a link to `docs/testing.md`, not a copy. Do not touch `docs/format-coverage.md`, `docs/quirks.md` or `docs/format-internals.md`: phase 12 owns the cross-cutting pages. **(4)** Run `pre-commit run --all-files`. Leave uncommitted; report every file changed and the exact `AGENTS.md` wording you added, if any. ≤250 words. |

## Risks and mitigations

* **The refactor in 11c silently widens the comparison.** Replacing a
  normaliser with a different one can make the fuzzer stop reporting
  real divergences, and a clean run looks like success. Mitigation:
  11c's brief requires byte-identical normaliser output across all four
  existing targets before and after, and a fixed-seed run with the same
  divergence count. The management session re-runs one of those
  comparisons itself.

* **A new picker shape reports a real instar bug and the round gets
  spent debugging it.** This is the fuzzer working, but it can consume
  a phase. Mitigation: 11d and 11e are forbidden from adding whitelist
  entries to quieten a divergence; they report it. The management
  session decides whether it is a finding for a follow-up issue or a
  fix inside this phase, and records the decision in the execution
  notes.

* **An option is drawn so rarely that the run never hits it**, and the
  phase reports coverage it does not have. Mitigation: 11d and 11e both
  report per-shape hit counts, and an unreachable shape is a reportable
  failure of the step rather than a footnote.

* **The fixed convert arm has no honest qemu oracle.** qemu-img cannot
  write VHDX, so a symmetric differential comparison may not exist for
  this target. Mitigation: 11e's brief makes naming the oracle a
  required output and explicitly permits the answer "there is no qemu
  side", with the pinned expectations used instead. The management
  session checks that whatever the step built is what its report claims.

* **A fixed VHDX iteration writes its full length to disk.** Fixed
  output is dense by definition and the fuzzer runs many iterations.
  Mitigation: decision for small sizes in the picker, stated in 11d and
  11e's briefs, and the plan-wide constraint that no test allocates a
  test image's data region.

* **A fuzz target hangs rather than crashing.** A mutated loop guard
  hangs by design. Mitigation: every fuzz run and every mutant runs
  under `timeout`, one per run, and a timed-out mutant counts as
  killed.

## Definition of done

Each item is a command and its expected result. Rust builds go through
the Docker path; no Rust toolchain is installed on the host.

* `src/fuzz` builds with every target registered, and
  `fuzz_vhdx_fixed_bat` appears in `src/fuzz/Cargo.toml` and in the
  built target list.
* `grep -n 'Fixed output reaches no caller yet'
  src/fuzz/fuzz_targets/fuzz_create_emitters.rs` matches nothing.
* `fuzz_create_emitters` draws both VHDX subformats and both
  `block_state_zero` values: a bounded run reports a non-zero hit count
  for each of the four combinations.
* Each invariant added in 11a and 11b fails when the property it
  asserts is deliberately broken in a scratch copy, and the failure
  names that invariant rather than a different one. The mutation script
  is committed under the repository's usual scratch-script location or
  its path is recorded in the execution notes, and the running mutant
  count is stated in the commit message.
* `grep -n '_normalise_create_info\|_CREATE_UNIVERSAL_STRIP\|_create_substitute_filename'
  scripts/differential-fuzz.py` matches nothing, and the file imports
  the normaliser from `helpers.info_json`.
* Normalised `qemu-img info --output=json` output for `qcow2`, `vmdk`,
  `vhdx` and `raw` is byte-identical through the pre-11c and post-11c
  code paths.
* A fixed-seed bounded `--ops create` run reports a non-zero hit count
  for each of: vhdx fixed, vhdx dynamic, `block_state_zero` on and off,
  vmdk `monolithicFlat`, and `preallocation` `falloc` and `full` on
  both vmdk and vhdx — and zero divergences, or every divergence
  classified in the execution notes as a real difference, a normaliser
  gap or a picker mistake, with the decision taken about each.
* `_create_option_picker`'s docstring names vpc create as excluded, the
  CHS reason, and the two host tests that cover vpc preallocation
  instead.
* A fixed-seed bounded `--ops convert` run exercises the vhdx target,
  emits distinct divergence types for content and structural
  differences, and reports a structural divergence when one byte of an
  instar fixed output is corrupted, naming the field.
* No generated fixed convert geometry has a partial last block, and
  the restriction's comment names #879.
* `docs/testing.md` says how to run a fuzz target by hand and names
  both uncovered cases (vpc create, and the #879 geometry) as
  deliberate exclusions with their reasons.
* `make instar`, `make lint`, `pre-commit run --all-files` and the full
  integration suite pass with 0 failures, read from the stestr totals
  rather than the exit code (`make test-ci` exits 0 with failures).
* No plan-file reference, phase number, step number or decision number
  appears in any code, comment or user-facing document this phase adds
  or edits.

## Back brief

Points needing the operator's answer before any step runs:

1. **Decision 2 — vpc stays out of the create picker**, so the
   non-qcow2 preallocation fuzzing covers vmdk and vhdx only. The
   alternative is a vpc arm with `virtual-size` masked, which blinds
   the comparison to the field most worth checking in a VHD writer.
   Accept, or add vpc with masking?
2. **Decision 7 — the new targets are not wired into the CI fuzzing
   schedule** by this phase, only committed and documented. That is a
   CI-cost call rather than a correctness one. Accept, or wire them in?
3. **Decision 6 — the fixed convert picker avoids the #879 geometry**
   rather than generating it and expecting the failure. Accept?
4. **11e's oracle.** qemu-img cannot write VHDX, so the fixed convert
   arm may have no symmetric differential comparison. The brief lets
   the step report that and fall back to the pinned expectations. Is
   that the right shape, or should fixed convert fuzzing wait until
   there is a real oracle?
5. **Whether this session may push and open the pull request** when the
   phase is implemented, or should stop at the last commit.

## Out of scope

* **Adding a vpc create target to the differential fuzzer.** Decision
  2. It needs the CHS virtual-size divergence resolved or deliberately
  masked, which is a VHD-writer question with no bearing on fixed
  VHDX. Recorded in the master plan's Future work.
* **Fixing #879** (`convert -O vhdx --subformat fixed` on a partial
  last block holding data). Already recorded in Future work by phase 9;
  decision 6 routes around it and names it.
* **Wiring the new targets into the coverage-fuzz CI schedule.**
  Decision 7; recorded in Future work.
* **The cross-cutting documentation pages.** Phase 12 owns
  `docs/format-coverage.md`, `docs/quirks.md`,
  `docs/format-internals.md` and `ARCHITECTURE.md`. 11f touches only
  `docs/testing.md`, `CHANGELOG.md` and, if a convention changed, one
  line of `AGENTS.md`.
* **The `PLAN-*.md` citations in landed code.** The repository's own
  rule forbids them and roughly 95 occurrences across 34 files predate
  this plan, including one in `tests/test_measure.py` that phase 10
  edited around. It is a repository-wide consistency gap, not this
  phase's, and it wants its own task.
