# PLAN: Differencing phase 4 — read-side policy

Phase 4 of [PLAN-differencing.md](PLAN-differencing.md).

## Goal

Stop instar reading a differencing image as though it had no
parent. Every operation that composes data from a differencing VHD
or VHDX refuses it, by name, with an exit code that says so —
replacing today's silent wrong answer on VHD and today's
undiagnosed generic failure on VHDX.

This phase refuses. It does not compose: composition is phases 11
to 16, and phase 14 replaces each refusal added here with a real
read. The refusal is an interim state inside this plan, settled by
open question 1, and it is worth its own phase because it is the
only part of the read-side answer that has to be true before the
emitters in phases 5 and 6 ship.

Closes #547 and #548.

## Planning effort

High, as the master plan requires for this phase. The judgement is
not in any individual refusal — it is in choosing where the
refusal lives, and the survey below moved that answer twice.

## Review effort

High, concentrated on one question: **is there a read path that
still reaches sector composition on a differencing image?** A
refusal that covers seven callers out of eight is not a partial
fix, it is the original defect with a smaller footprint. The
management session should enumerate the entry points from the
source rather than from this plan's list, because this plan's list
is exactly the thing that would be wrong.

## Scope

In scope:

* A typed refusal reason, carried from the guest to the host and
  rendered as a message that names the format and the reason.
* Refusal at every read entry point that can reach sector
  composition on a differencing VHD (`disk_type == 4`) or a
  differencing VHDX (`HasParent` set), for `convert`, `compare`,
  `bench`, `check`, `measure` and `dd`.
* Making the VHDX path diagnosable rather than merely non-zero,
  which is what #548 is about.
* `instar info` reporting a parent it can now see, which phase 3
  taught the crates to read.
* Integration tests over the phase 2 fixtures asserting the
  refusal per operation.

Out of scope, and deliberately:

* **Composition.** No op reads through to a parent in this phase.
* **`map` and `resize`**, which already refuse — see the survey.
* **The emitters.** Nothing here writes a differencing image.
* **Host-side chain discovery.** `discover_backing_chain`
  (`src/vmm/src/main.rs:2416`) is phase 11's business; this phase
  does not call it, extend it, or configure it.
* **Changing what `crates/vhd` and `crates/vhdx` parse.** Phase 3
  settled that surface and this phase consumes it unchanged, with
  the single exception recorded in decision 3.

## What the survey found

The master plan's phase 4 material was written 2026-09-05, before
phase 3 executed. Most of it holds. Four things do not, and two of
them change the shape of the work.

**Confirmed unchanged:**

* `VhdState::init` still accepts `DISK_TYPE_DIFFERENCING`
  alongside `DISK_TYPE_DYNAMIC` (`src/crates/vhd/src/lib.rs:1346`).
  The silent misread is live.
* `VhdxState::init` still rejects `has_parent` by returning bare
  `None` (`src/crates/vhdx/src/lib.rs:1647`). Phase 3 added parent
  locator parsing without disturbing it.
* `discover_backing_chain` is at `src/vmm/src/main.rs:2416`, and
  `backing_path_allowlist` / `max_chain_depth` at
  `src/vmm/src/config.rs:65` and `:67`, exactly as claimed.
* Issues #547 and #548 are open.

**Stale claim 1 — `map` is done, and is the template.** The
master plan's success criteria list `map` among the ops phase 4
must fix. `map` has refused a differencing VHD since commit
`eb6e23f` (2026-06-03), well before this plan was written:
`src/operations/map/src/main.rs:462` returns
`MapResult::ERROR_HAS_BACKING`, which the host renders at
`src/vmm/src/main.rs:15053` as a sentence naming the reason and
pointing at the deferral. That is precisely the shape this phase
generalises, so `map` moves from *work* to *precedent*.
`resize` likewise already refuses, at
`src/operations/resize/src/main.rs:629`, with
`ResizeResult::ERROR_UNSUPPORTED_SUBFORMAT`.

**Stale claim 2 — `dd` is not an operation.** The master plan
lists `dd` as one of eight ops. There is no `src/operations/dd`.
`run_dd` (`src/vmm/src/main.rs:13958`) builds a convert execution
and calls `execute_convert`, so `dd` shares convert's guest binary
and inherits whatever convert does. It needs a test, not a fix.

**Structural finding 3 — there is one read entry point, not
eight.** This is the finding that reshaped the phase. `convert`,
`compare`, `bench` and `check` never call `VhdState::init` or
`VhdxState::init`; greping the operations for either name returns
nothing outside `map` and `measure`. They reach a VHD or VHDX
source through the generic chain-state initialiser in the qcow2
crate, which owns `vhd_states` and `vhdx_states` arrays
(`src/crates/qcow2/src/lib.rs:9385` and `:9387`) and dispatches on
`ImageFormat` at `:9478` and `:9494` under the `vhd-input` and
`vhdx-input` features. Only three real `VhdState::init` call sites
exist in the tree: that initialiser, `measure`
(`src/operations/measure/src/main.rs:388`) and `map` (`:438`).

So the refusal has two homes — the shared initialiser and
`measure` — rather than six. A per-op refusal would have been five
copies of one check, and would have been the wrong answer for the
same reason it is wrong to fix a caller five times instead of
fixing the callee once.

**Structural finding 4 — `info` is categorically different.**
`info` does not link the vhd crate at all (`src/operations/info/Cargo.toml`)
and parses the footer itself via `parse_vhd_footer`
(`src/operations/info/src/main.rs:434`). It therefore cannot
inherit any refusal added above, and it should not: `info` reports
metadata, it never composes sector data, so it has no wrong answer
to give. Its defect is an omission — it reports no parent for an
image that has one — which phase 3 made fixable. See decision 4.

**Mechanism finding 5 — the per-op result struct is *not* a
usable channel, and the right precedent is issue #375.** Both
`init` functions return `Option<Self>` and the chain initialiser
returns `bool`, so none of them can say *why* today; that is the
whole of #548. The obvious fix is a `u32` in the op's result
struct, the way `MapResult::ERROR_HAS_BACKING` (`:2924`) is
rendered by `map_error_message`
(`src/vmm/src/main.rs:15048`). **That does not generalise, and
this plan's first draft was wrong to assume it did.** Three of the
five operations have nowhere to put such a code:

* `convert` has no result struct at all. It reports through
  `send_complete("convert", 0, false)` and its module header
  states that no result message is needed. The host turns that
  into the bare string at `src/vmm/src/main.rs:13241`.
* `CompareResult` (`src/shared/src/lib.rs:2349`) carries a magic
  and flags, but no error constants.
* `CheckResult` (`:2069`) likewise has none.

Adding result structs to three operations to carry one boolean
fact would be a protocol change out of all proportion to the
phase.

The tree already solves this exact problem, for exactly this
reason, in issue #375: when the guest IDT catches a CPU fault, a
run loop that ends without a result must explain why instead of
printing "guest did not return a result". The mechanism is a
single capture in the message decoder — `last_cpu_exception` at
`src/vmm/src/main.rs:770`, set at `:833` when a `Payload::Error`
arrives whose `operation` field marks it — and a single formatter,
`no_result_error` at `:789`, that prefers the captured reason and
falls back to the generic text. `send_error(op, device, sector,
status)` is already on the call table
(`src/core/src/main.rs:430`), so every guest binary can raise it
today with no protocol change.

Phase 4 adds a sibling to that pair. This is op-agnostic, needs
one host-side capture point rather than five, and works for the
three operations that have no result struct.

**Naming hazard 6.** `src/vmm/src/main.rs:18659` and the
`MapRenderer` doc comment above it refer to "Phase 4". That is
**PLAN-map.md's** phase 4, not this one. An agent grepping for
phase 4 in the vmm will find map's streaming-renderer work and
should ignore it.

**Corrections made at source.** As part of the planning commit,
the master plan's phase 4 wording is corrected for `map` and `dd`,
and the phase 3 row's empty *Merged* column is filled in
(`42e879f`, #558). One phase 3 Definition-of-done item was also
false as merged — it asserted `git diff --name-only
develop...HEAD -- src/operations/` is empty, but the review round
that plumbed `metadata_length` into `parse_metadata` changed
`src/operations/check/src/main.rs`, a call-site-only edit with no
behaviour change. That bullet is annotated rather than deleted, so
the record shows what happened.

## Decisions

1. **Refuse at the shared chain initialiser and at `measure`, not
   in `VhdState::init`.** Making the crate's `init` reject
   `disk_type == 4` would close the hole in one line for every
   caller at once, and it is the obvious move. It is wrong here
   for three reasons: phase 3's parsing surface exists to be read
   *from* a successfully initialised differencing image, and `map`
   already depends on `init` succeeding so it can read
   `state.disk_type`; phases 11 to 16 need `init` to succeed in
   order to compose; and a crate-level `None` produces exactly the
   undiagnosed failure that #548 exists to complain about. The
   callee is not wrong — the callers are missing a policy check.

2. **One guest-side refusal signal, captured once on the host,
   following issue #375 — not a per-op result code.** The guest
   raises `send_error` with a reserved operation marker and a
   status naming the format; the host decoder captures it beside
   `last_cpu_exception`, and the failure paths render it in place
   of their generic text. Survey finding 5 records why the
   per-op-result-code shape, which this plan proposed in its first
   draft, cannot work: `convert` has no result struct and
   `CompareResult` and `CheckResult` have no error constants, so
   three of the five operations have nowhere to put a code. The
   message still names the operation, because the formatter takes
   the op name as an argument exactly as `no_result_error` does.
   `map` keeps its existing `ERROR_HAS_BACKING` and is not
   migrated: it works, it is already covered by a test, and
   changing it would put a working refusal at risk for
   tidiness.

3. **Make VHDX symmetric with VHD: `VhdxState::init` stops
   rejecting `has_parent`, and the entry points refuse instead.**
   This is the decision most likely to be argued with, because it
   deliberately removes a working safety net. Today a differencing
   VHDX fails closed with a useless message; the alternative of
   keeping the rejection and threading a reason out of `init`
   (changing `Option<Self>` to `Result<Self, Reason>` across
   twelve call sites) preserves fail-closed but leaves VHD and
   VHDX structurally different for phases 11 to 16 to reconcile
   later. Symmetry is worth more: after this change both formats
   initialise, both expose a parent flag (`has_parent` is already
   `pub` on the metadata at `src/crates/vhdx/src/lib.rs:935`), and
   one uniform check at each entry point covers both.

   **The hazard is real and the mitigation is structural**: the
   commit that removes the rejection must be the same commit that
   adds every entry-point refusal. Split across two commits, the
   tree passes through a state where a differencing VHDX is
   silently misread — converting a safe failure into the exact
   defect this phase exists to close. Step 4b is therefore
   indivisible, and the review checks that first.

4. **`info` reports; it does not refuse.** `info` composes
   nothing, so it has no wrong answer to give, and refusing would
   remove the only way to inspect an image the rest of the tool
   declines to read — which is precisely when a user needs `info`
   most. It gains a parent line instead. Note this changes `info`
   output for differencing images, so phase 3's parity script
   (`tools/verify-info-output-parity.sh`) will report differences
   on exactly the differencing fixtures and must be run with that
   expectation stated, not as a pass/fail gate.

5. **`dd` gets a test, not a fix.** It shares convert's guest
   binary. The test exists to catch a future divergence, since
   nothing in the tree records that dd and convert must stay
   linked.

6. **The refusal message points at the deferral.** Following
   map's text, each message says composition is deferred and names
   the plan, so a user who hits it learns it is a known boundary
   rather than a corrupt image.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 4a | medium | sonnet | none | Build the refusal channel, following issue #375's `last_cpu_exception` pair exactly. (i) In `src/shared/src/lib.rs` add a small module of stable constants: a reserved `send_error` operation marker (a short string such as `differencing`) and one `u32` status per format (VHD, VHDX), documented as append-only the way `BenchResult`'s error codes are at `:4232`. `src/shared` is `no_std`. (ii) In `src/vmm/src/main.rs` add a `last_differencing_refusal: Option<u32>` field beside `last_cpu_exception` (`:770`, initialised `:781`), capture it in `add_byte` beside the existing capture (`:829-835`) when the `Payload::Error`'s `operation` equals the marker, and add a formatter beside `no_result_error` (`:789`) that takes the op name and renders a sentence naming the operation, saying the source is a differencing image whose parent instar cannot yet compose, and saying composition is deferred to PLAN-differencing phases 11-16. Follow the wording of `map_error_message` (`:15053`). (iii) Unit-test the formatter both ways, mirroring the two tests at `:863` and `:872`. Nothing raises the error yet — this step adds no behaviour. |
| 4b | high | opus | worktree | **Indivisible — one commit.** (i) Remove the `has_parent` rejection at `src/crates/vhdx/src/lib.rs:1647` and expose the flag on `VhdxState` so callers can test it (`has_parent` is already `pub` on the metadata at `:935`). (ii) In the generic chain-state initialiser `src/crates/qcow2/src/lib.rs:9450-9520`, refuse a differencing source in both the `ImageFormat::Vhd` arm (`:9478`, test `state.disk_type == vhd::DISK_TYPE_DIFFERENCING`) and the `ImageFormat::Vhdx` arm (`:9494`, test the new flag), threading the reason out — the function returns `bool` today, so it needs an out-parameter or a small enum return; choose the one that touches fewer callers and say which in the commit message. (iii) Do the same at `measure`'s two direct call sites (`src/operations/measure/src/main.rs:388` and `:400`). (iv) At each refusal, call the call table's `send_error` with 4a's marker and the format's status before returning failure, so the host renders the specific message; `map`'s refusal at `src/operations/map/src/main.rs:459-470` shows the return shape, but use the 4a channel rather than a result code — `convert`, `compare` and `check` have nowhere to put one. (v) Wire the host's generic failure sites to the 4a formatter, at minimum `src/vmm/src/main.rs:13241` (convert) and `:12213` (compare). Constraints: both crates are `no_std`, panic-free, no allocator; the arms are behind the `vhd-input` and `vhdx-input` features, so check both feature combinations build. Do **not** touch `VhdState::init`. |
| 4c | medium | sonnet | none | Teach `info` to report the parent. `info` parses the footer itself (`parse_vhd_footer`, `src/operations/info/src/main.rs:434`) and does not link the vhd crate — decide with the management session whether to add the dependency or extend the local parser, and state the choice. Report the parent name for a differencing VHD and the parent locator's linkage for a differencing VHDX, in both human and `--output json` forms, following how qcow2's backing file is already reported. Refuse nothing. |
| 4d | high | opus | worktree | Integration tests over the phase 2 fixtures. For each of convert, compare, bench, check, measure and dd, assert a non-zero exit and the expected message on `vhd-differencing`, `vhd-diff-child-aligned` and `vhdx-diff-child`; assert `map` still refuses (regression guard on the precedent) and that `info` now reports a parent. Assert dd and convert produce the same refusal, which is the only thing recording that they share a binary. Use the existing integration harness rather than a new one. The composed goldens (`vhd-diff-aligned-composed.raw`, `vhdx-diff-composed.raw`) are phase 11-16 material — do not use them here. |
| 4e | medium | sonnet | none | Documentation and closeout. Update `docs/format-coverage.md` (divergence notes), `docs/quirks.md` and `CHANGELOG.md` to state that differencing VHD and VHDX are refused on read with composition deferred. Close #547 and #548 with a comment naming the commit and the message a user now sees. Do not touch `docs/create.md` or the emitter docs — phases 5, 6 and 10 own those. |

Steps 4a and 4c are independent of each other. 4b depends on 4a.
4d depends on 4b and 4c. 4e last.

## Risks and mitigations

* **A read path is missed, and one op still composes silently.**
  The likeliest failure of this phase, and the reason the entry
  points were enumerated from the source rather than from the
  master plan's op list. *Mitigation:* the management session
  re-derives the list of `VhdState::init` / `VhdxState::init`
  callers and `ImageFormat::Vhd|Vhdx` dispatch sites from the tree
  at review time and compares it against what 4b changed; 4d
  covers every op by name including dd.
* **The 4b window.** Removing the VHDX rejection before the
  refusals land makes the tree briefly worse than it is today.
  *Mitigation:* 4b is one commit, stated in the brief and checked
  first at review.
* **Feature-gate blindness.** The chain initialiser's arms are
  behind `vhd-input` and `vhdx-input`. A refusal added inside a
  gate that some op does not enable protects nothing. *Mitigation:*
  4b's brief requires building both feature combinations; the
  review greps which ops enable which features.
* **`info` parity churn.** Decision 4 deliberately changes `info`
  output for differencing images, which phase 3's parity script
  will report. *Mitigation:* stated in decision 4 and in the DoD;
  the run is read for *which* images changed, and any change
  outside the differencing fixtures is a defect.
* **Guest binary size.** Every guest binary has a 768KB cap and
  `make check-binary-sizes` enforces it. The additions are small,
  but `check` and `convert` are the largest binaries.
  *Mitigation:* in the DoD.

## Definition of done

* `instar convert -O raw`, `instar dd`, `instar compare`,
  `instar bench`, `instar check` and `instar measure` each exit
  non-zero on `vhd-differencing`, `vhd-diff-child-aligned` and
  `vhdx-diff-child`, with a message naming the operation and the
  parent reference. Verified by the 4d tests, not by hand.
* No operation writes output composed from a differencing source.
  Specifically, `instar convert -O raw` on `vhd-differencing`
  produces **no output file**, where today it produces a wrong one
  and exits 0.
* No operation gained a result struct or a new protocol message:
  the refusal travels on the existing `send_error` channel, and
  `git diff` touches neither `crates/guest-protocol` nor the
  `*Result` struct definitions in `src/shared/src/lib.rs` beyond
  the new constants module.
* `grep -rn 'VhdState::init\|VhdxState::init' --include=*.rs src/`
  and the `ImageFormat::Vhd`/`ImageFormat::Vhdx` dispatch arms in
  `src/crates/qcow2/src/lib.rs` together enumerate every read
  entry point, and each one either refuses a differencing source
  or is `create` (which writes) or a fuzz target. Checked by
  reading the code, not by the tests passing.
* `src/crates/vhdx/src/lib.rs` no longer rejects `has_parent` in
  `init`, and the commit that removed it is the same commit that
  added every entry-point refusal — verifiable with
  `git show --stat` on one SHA.
* `instar info` reports a parent for `vhd-differencing` and
  `vhdx-diff-child` in both human and JSON output, and
  `tools/verify-info-output-parity.sh` reports differences on the
  differencing fixtures **and on no others**.
* `instar map` still refuses `vhd-differencing` with its existing
  message, unchanged.
* Issues #547 and #548 are closed, each with a comment quoting the
  message a user now sees.
* `VhdState::init` is byte-for-byte unchanged.
* `make instar` builds, `make check-binary-sizes` passes,
  `make test-rust` passes, `make test-integration` passes, and
  `pre-commit run --all-files` passes.

## Back brief

Before executing any step of this plan, please back brief the
operator as to your understanding of the plan and how the work you
intend to do aligns with that plan.

In particular, back brief before starting **step 4b**: it removes
a working safety net and must land as a single commit, and the
choice of how to thread the refusal reason out of the chain
initialiser's `bool` return should be agreed before the editing
starts rather than discovered in review.
