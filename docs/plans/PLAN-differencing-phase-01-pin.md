# Phase 1 — semantics pin, oracle selection, and the doc correction

Phase 1 of [PLAN-differencing.md](PLAN-differencing.md).

## Goal

Establish that this plan can be validated at all, and decide the
things later phases would otherwise each decide differently.

Every write path instar has shipped was cross-validated against
qemu-img. This one cannot be: qemu-img creates neither
differencing VHD nor differencing VHDX, and reads both as though
the parent did not exist. Before an emitter is written, the plan
needs an external implementation that resolves a differencing
chain, or an honest statement that none is available and what we
are doing instead. That is this phase.

No source file under `src/` changes in this phase.

## Planning effort

High. The phase turns on format-spec interpretation and on a
go/no-go judgement that the rest of the plan depends on.

## Review effort

High for step 1a's oracle verdict and step 1b's structure pin --
the management session re-runs a sample of the measurements
rather than accepting the sub-agent's transcript. This repository
has a documented history of agents asserting plausible-but-wrong
qemu and format capabilities, and a wrong offset in a format
nobody else validates is exactly the error this plan is exposed
to.

Medium for the rest.

## Scope

In scope:

* Prove or disprove an external oracle for differencing VHD and
  VHDX chains, with recorded evidence.
* Pin the on-disk structures this plan will emit -- VHD dynamic
  header parent fields and locator table, VHDX parent locator
  metadata item -- against the specs and against real bytes.
* Pin qemu-img's and instar's current behaviour in
  `docs/quirks.md`.
* File the GitHub issue for the silent parent-ignoring read.
* Settle the master plan's remaining open questions.
* The `docs/create.md` correction, which has already landed as
  `a93615d`.

Out of scope:

* Any change under `src/`. The silent-read defect is filed here
  and fixed in phase 4; the temptation to fix it while it is in
  front of you is the thing this line exists to resist.
* Fixtures in `instar-testdata`. Phase 1 builds a throwaway chain
  in the scratchpad to test the oracle with; phase 2 owns the
  maintained generator.
* Documenting the structures in `docs/format-internals.md`. That
  page describes what instar implements, and in this phase instar
  implements none of it. Phase 10 writes it.

## What the survey found

The master plan's Situation section was written on 2026-09-05 and
re-verified line by line while planning this phase. Every claim in
it holds, with the file and line references below confirmed
against the tree at `d59cc40`:

* `src/crates/create/src/lib.rs:767` and `:919` reject a backing
  reference for vpc and vhdx respectively, each with a comment
  deferring the work as "too complex for phase 1" of
  `PLAN-create.md`.
* `src/crates/vhd/src/lib.rs:93` defines
  `DISK_TYPE_DIFFERENCING`; `:578` accepts it into `VhdState`;
  `:664-667` compute the per-block sector bitmap's size and
  `:766` skips past it to the payload. No bit of that bitmap is
  ever read.
* `src/crates/vhdx/src/lib.rs:462` derives `has_parent` from the
  file-parameter flags, `:517-519` discards the parent locator
  offset it just found, `:842` rejects differencing images, and
  `:654` skips the sector-bitmap BAT entries.
* The fixture
  `instar-testdata/custom/format-coverage/vhd-differencing.vhd`
  has `disk_type = 4` at footer offset 60 and zeroes in its
  parent unique id, parent unicode name (offset 576) and all
  eight locator entries (offset 1088). It is a type marker.

The survey did turn up one thing the master plan does not say,
and it is good news for phase 11: **the host already has generic
chain machinery, and it is not qcow2-only.**
`discover_backing_chain` (`src/vmm/src/main.rs:2416`) walks a
chain with circular-reference detection, a depth limit and a path
allowlist, and it already contains a non-qcow2 special case --
the VMDK flat-descriptor short-circuit that resolves
`parentFileNameHint`. The security knobs it uses,
`security.backing_path_allowlist` and `security.max_chain_depth`,
exist in `src/vmm/src/config.rs:65` and `:67`. Phase 11 extends
this function rather than writing one, and open question 5's
resolution rule is a description of what this code already does.

This finding has been added to the master plan's Situation
section as part of the planning commit, so the next reader does
not have to rediscover it.

## Decisions

1. **The oracle is libvhdi, subject to a written go/no-go.**
   Debian 13 packages `libvhdi-utils` (`vhdiinfo`, `vhdiexport`)
   and `python3-libvhdi` from libyal, which implements VHD and
   VHDX parent chains. It is accepted as this plan's oracle only
   if it passes both halves of step 1a: it resolves a chain
   *instar did not write* and reports the parent, and its
   composed export of a chain matches the content that chain was
   built to represent, byte for byte. Failing that, the fallbacks
   in order are a third-party-produced reference image used as
   ground truth, then structural-only assertions with the plan
   saying plainly that it has no content oracle.
2. **Phase 1's chain generator is disposable.** It lives in the
   scratchpad and its source is pasted into this plan's appendix
   when step 1a reports. Phase 2 lifts it into a maintained
   generator in `instar-testdata`. Blocking the go/no-go on a
   cross-repository, LFS-backed fixture review buys nothing.
3. **A generator we wrote cannot be the only input to the
   oracle test.** If libvhdi accepts our chain and we later emit
   the same misreading from `plan_vhd`, the oracle will have
   validated nothing. Step 1a must obtain at least one
   differencing image produced by something other than us --
   libyal's own test corpus, or a Hyper-V-produced sample -- or
   record that it could not, and downgrade the claim to "the
   oracle validates resolution, not conformance".
4. **The structure pin lives in this plan, not in `docs/`.**
   `docs/format-internals.md` documents what instar implements.
   Only the qemu-vs-instar divergences, which are true today, go
   to `docs/quirks.md` now.
5. **A differencing child must have a parent of its own format**
   (master plan open question 7, resolved yes). Hyper-V requires
   it, and emitting a chain no implementation can resolve is
   worse than a typed refusal. Phase 7 wires the error.
6. **Phase 1 writes no code.** The silent-read defect gets an
   issue number here and a fix in phase 4.
7. **This phase runs on the `vhd-differencing` branch, not a
   fresh phase branch.** The master plan is not yet on `develop`
   and phase 1's first deliverable is already on this branch, so
   a branch off `develop` would not contain the plan it
   implements. Phases 2 onward take their own branches off
   `develop` once this lands. The `Merged` cell for phase 1
   therefore records the merge commit of the pull request that
   carries the master plan and this phase together.

The decision most likely to be argued with is 2. Putting the
generator in the scratchpad means the evidence for the go/no-go
is reproducible only from this plan's appendix, not from a
checked-in script. The alternative -- open the testdata pull
request first -- makes the go/no-go wait on a review in another
repository, and if the answer is no-go, the fixtures were the
wrong thing to have built.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1a | high | opus | worktree | Establish the oracle. Install `libvhdi-utils` and record `vhdiinfo -V`. Write a throwaway Python generator in the session scratchpad (NOT in any repository) that produces (i) a dynamic VHD base plus a differencing child referencing it, and (ii) a dynamic VHDX base plus a differencing child, each small (16 MiB) with known content in known sectors, some sectors present in the child and some only in the parent. The VHD child needs `disk_type = 4` at footer offset 60, the parent unique id at absolute offset 552, parent timestamp at 568, parent unicode name (UTF-16BE) at 576, and locator entries from 1088; both footer and dynamic-header checksums are ones-complement sums over the structure with the checksum field zeroed. Then: run `vhdiinfo` and `vhdiexport` on each child and record verbatim output; compare the exported composition against the content you intended, byte for byte, with `cmp`. Separately, obtain at least one differencing image produced by something that is not this script -- try libyal's published test corpus first -- and run the same commands on it; if you cannot obtain one, say so explicitly rather than working around it. Report a go/no-go against decision 1's criterion, the tool version, every command line, and the generator source for pasting into the plan appendix. Do not modify any repository file. |
| 1b | high | opus | none | Pin the structures, against the specs and against real bytes. For VHD: the dynamic header's parent fields and the eight 24-byte parent locator entries (platform code, data space, data length, reserved, data offset), which platform codes Hyper-V writes, how `W2ru` relative paths are encoded, and the checksum algorithm. For VHDX: the parent locator metadata item -- its header, the `parent_linkage` GUID's meaning, and the key/value entry encoding -- plus which file-parameter bits must be set. Verify every offset you state against the images step 1a produced (`xxd` output in the report) and against `src/crates/vhd/src/lib.rs` / `src/crates/vhdx/src/lib.rs` where they already parse the surrounding structure. Cite a spec section or a measurement for every claim; where the spec is ambiguous -- `parent_linkage` is the likely one -- say so and state the interpretation phase 6 should implement. Output is a section appended to this plan, not a docs change. |
| 1c | medium | sonnet | none | Write the `docs/quirks.md` section recording current behaviour, following the shape of the existing "QED read-refusal as policy" section (`:4038`). Content, all of it measured on 2026-09-05 against qemu-img 10.0.11 and instar built from `d59cc40`, and to be re-run and quoted verbatim rather than copied from this plan: `qemu-img create -f vpc -b base.vhd -F vpc child.vhd 16M` fails with "Backing file not supported for file format 'vpc'" and the vhdx equivalent likewise; `qemu-img info` on a differencing child reports a plain image and never mentions a parent; `instar convert -O raw` on the same child exits 0 and writes an image composed without the parent; `instar map` refuses (`src/operations/map/src/main.rs:459-462`) and `instar check` refuses only the VHDX case (`:1555`). State plainly that instar's read is qemu-parity and that both are wrong, and link the issue from step 1d. |
| 1d | low | sonnet | none | File one GitHub issue against shakenfist/instar for the silent parent-ignoring read: title names `convert` reading a differencing VHD as if it had no parent and exiting 0, body carries the reproduction against `instar-testdata/custom/format-coverage/vhd-differencing.vhd` (noting that fixture's own limitation), the qemu-parity observation, and a pointer to phase 4 of this plan as the fix. Label `bug`. Do not fix it. Report the issue number. |
| 1e | medium | opus | none | Settle the master plan's open questions using the evidence from 1a and 1b. Rewrite questions 2 through 7 in `docs/plans/PLAN-differencing.md` as RESOLVED with the answer, the evidence, and the date, in the style question 1 already uses. Question 2 takes step 1a's verdict; question 3 takes whichever locator entries the oracle actually required; question 4 is resolved "no flag", consistent with the unflagged vmdk/vhd/vhdx `resize` divergence; question 5 is resolved as a description of `discover_backing_chain`'s existing rules, citing `src/vmm/src/main.rs:2416` and the two config keys; question 6 is resolved yes; question 7 is resolved yes per decision 5. If any answer contradicts a phase description later in the table, fix that description too and say so in the commit. |
| 1f | low | sonnet | none | Close the phase. Set phase 1's row to Complete in the master plan Execution table and the phase list in `docs/plans/index.md`, add the issue number from 1d to the master plan's *Bugs fixed during this work*, run `pre-commit run --all-files`, and confirm `git diff --name-only develop...HEAD -- src/` is empty. Present the commits. |

## Risks and mitigations

* **Correlated error.** Our generator and our future emitter
  could share a misreading that libvhdi tolerates, making the
  oracle look sound while validating nothing. Mitigated by
  decision 3: step 1a must test a differencing image we did not
  produce, or downgrade the claim in writing. The management
  session checks specifically that this was done, because it is
  the step most likely to be quietly skipped.
* **A tolerant oracle.** libvhdi may resolve chains that Hyper-V
  would reject, so passing it is necessary and not sufficient.
  Mitigated by keeping step 1b's structural assertions as a
  second, independent check, and by phase 8 asserting structure
  as well as content.
* **Spec ambiguity on VHDX `parent_linkage`.** Mitigated by
  step 1b naming the interpretation explicitly so phase 6
  implements a decision rather than a guess, and by flagging it
  for revisit if a Hyper-V sample later contradicts it.
* **Scope creep into phase 4.** The defect is in front of the
  sub-agent in steps 1c and 1d and it is a small fix. Mitigated
  by decision 6 and by the `git diff -- src/` check in the
  definition of done.
* **The go/no-go comes back no.** Then phases 8, 9 and 15 change
  shape and the operator should hear it immediately rather than
  after phase 5. Step 1a reports to the management session
  before 1b starts.

## Definition of done

* `vhdiinfo -V` output is recorded in this plan, and a go/no-go
  sentence names the oracle or the fallback taken.
* This plan contains, for both VHD and VHDX, the verbatim command
  lines and output of an oracle run against a differencing chain,
  and a `cmp` result against the intended composed content.
* This plan states whether a differencing image not produced by
  us was tested, and names it or says it could not be obtained.
* Every offset stated in the structure pin is backed by a spec
  citation or an `xxd` of a real image, both present in the plan.
* `docs/quirks.md` has a differencing section whose every factual
  claim quotes a command run during this phase, including tool
  versions.
* A GitHub issue exists for the silent parent-ignoring read, and
  its number appears in the master plan's *Bugs fixed during this
  work*.
* No open question in the master plan is left as a
  recommendation: each of questions 1 through 7 reads RESOLVED
  with an answer and its evidence.
* `git diff --name-only develop...HEAD -- src/` is empty.
* `pre-commit run --all-files` passes.

## Back brief

Before executing any step, back brief the operator on the
understanding of this phase and how the intended work aligns with
it. Step 1a additionally reports its go/no-go to the management
session before step 1b begins: the verdict changes the shape of
three later phases, and it is cheap to hear early and expensive
to discover late.
