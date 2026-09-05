# VHD and VHDX differencing output

## Status: In progress

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

This plan carries the mandatory push audit phase described in
`PLAN-TEMPLATE.md`, and the `Merged` column that phase needs. The
column is filled in as each phase lands, not reconstructed
afterwards.

## Situation

The 2026 technical goal *VHD/VMDK writers done* has four leaves:
VHD fixed output (shipped), VHD/VHDX differencing output, VMDK
`twoGbMaxExtent*` output, and vmdk/vpc/vhdx preallocation. This
plan takes the differencing leaf. It is the only one of the three
outstanding leaves that needs no call-table change, which is why
it goes first: multi-extent VMDK output is blocked on
multi-output-device support in the call table, and preallocation
is blocked on a per-format BAT population pattern.

What exists today, measured on 2026-09-05 against the binary
built from `d59cc40` and qemu-img 10.0.11:

* `instar create -f vpc -b parent.raw -F raw child.vhd 16M` fails
  with "create failed: invalid option for target format".
  `plan_vhd` (`src/crates/create/src/lib.rs:767`) and `plan_vhdx`
  (`:919`) both return `CreateError::BackingFileUnsupported` when
  a backing reference is present, each with a comment deferring
  the work as "too complex for phase 1" of `PLAN-create.md`.
* `src/crates/vhd/src/lib.rs` knows `DISK_TYPE_DIFFERENCING = 4`
  (`:93`) and `VhdState::init` accepts it (`:578`), but nothing
  in the crate parses the dynamic header's parent fields or its
  eight parent locator entries.
* `src/crates/vhdx/src/lib.rs` finds the parent locator metadata
  item and then discards it: `parent_loc_offset` and
  `found_parent_loc` are assigned and immediately `let _ = ...`
  at `:517-519`. Only the `HasParent` file-parameter bit survives,
  as `VhdxMetadata::has_parent` (`:462`), and `VhdxState::init`
  rejects any image that sets it (`:842`).
* Reading a differencing VHD therefore returns the child's
  allocated blocks and zeros everywhere else, with no diagnostic.
  `instar convert -O raw` on the `vhd-differencing.vhd` fixture
  exits 0 and writes a 10 MiB raw image composed as if the parent
  did not exist. `instar info` reports no parent. `map` is the
  only op that refuses (`src/operations/map/src/main.rs:459-462`),
  and `check` refuses only the VHDX case (`:1555`).
* `CHANGELOG.md:1922` claims VHD input support for "fixed,
  dynamic, differencing with backing chains". The chain half of
  that claim has never been true.

What the outside world does:

* qemu-img creates neither. `qemu-img create -f vpc -b base.vhd
  -F vpc child.vhd 16M` and the vhdx equivalent both fail with
  "Backing file not supported for file format 'vpc'" / "'vhdx'".
  qemu's vpc and vhdx drivers have no differencing write path at
  any shipped version.
* qemu-img *reads* a differencing VHD the same way instar does:
  `qemu-img info` on the fixture reports a plain 10 MiB vpc image
  and never mentions a parent. So instar's silent read is
  qemu-parity, but both are silently wrong rather than right.
* This makes differencing output an instar-only capability with
  **no qemu-img oracle**, like the vmdk/vhd/vhdx `resize` and
  vmdk `rebase` divergences already recorded as note 8 in
  `docs/format-coverage.md`. Every other write path instar has
  shipped was validated against qemu-img. This one cannot be, so
  the plan has to establish an oracle before it writes anything.
* Debian 13 packages `libvhdi-utils` (`vhdiinfo`, `vhdiexport`)
  and `python3-libvhdi` from the libyal project, which does
  implement VHD and VHDX parent chains. It is the leading oracle
  candidate and phase 1 has to prove it before phase 5 relies on
  it.

The fixtures are not usable as they stand.
`instar-testdata/custom/format-coverage/vhd-differencing.vhd` has
`disk_type = 4` in its footer but its parent unique id, parent
unicode name and all eight parent locator entries are zero: it is
a type marker, not a differencing disk, and its companion
`vhd-diff-base.vhd` is not referenced by it. Nothing in
`instar-testdata/scripts/` generates them. There is no VHDX
differencing fixture at all.

Related planned work lives in the testdata repository:
`instar-testdata/docs/plans/PLAN-extra-coverage.md` priority 7
proposes five adversarial parent-locator fixtures (absolute
`/etc/passwd`, `../../../etc/passwd`, UNC, and eight mutually
disagreeing locators). That priority is unstarted, and it becomes
directly relevant the moment instar parses a locator table.

There are no open GitHub issues on the differencing surface today.

## Mission and problem statement

Make `instar create -f vpc|vhdx -b PARENT -F FMT child` produce a
differencing disk that an independent implementation resolves
against its parent, and stop instar reading differencing children
as though they had none.

In scope:

* Differencing VHD output: `disk_type = 4`, parent unique id,
  parent timestamp, parent unicode name, and a populated parent
  locator table, with both checksums correct and the BAT wholly
  unallocated.
* Differencing VHDX output: the `HasParent` file-parameter bit, a
  populated parent locator metadata item carrying the
  `parent_linkage` GUID and the locator path entries.
* Parent-locator parsing in `crates/vhd` and `crates/vhdx`, to
  the standard the rest of the format crates hold: `no_std`,
  panic-free, every offset and length from the image
  bounds-checked before use.
* A defensible read-side answer for differencing children, so
  that no op silently composes the wrong image.
* An external oracle, and fixtures generated by a script that
  lives in the testdata repository rather than by hand.

Out of scope, and deliberately left to their own work:

* Chain composition on read for VHD/VHDX, unless open question 1
  is answered the other way. See *Future work*.
* Multi-extent VMDK output and vmdk/vpc/vhdx preallocation, the
  other two leaves of the same goal.
* `resize` of a differencing image, which
  `docs/resize.md:215-216` already defers pending the
  parent-locator update path this plan builds.
* VHDX log replay, which remains rejected as it is today.

## Open questions

1. **Read side: refuse, or compose?** instar can write a
   differencing disk it cannot itself read back correctly, or it
   can implement chain composition for VHD/VHDX the way it
   already does for qcow2 backing chains (the guest takes an
   `input_device_count` and the host attaches each chain member
   as its own virtio device). *Recommendation: refuse in this
   plan and compose in a follow-up.* Refusing closes the
   silent-wrong-data hole immediately, keeps this plan on the
   goal's output leaf, and leaves validation to the external
   oracle; composition is a larger piece of work that wants the
   parse layer this plan builds to already exist. The cost is
   that instar will, for a while, write images it declines to
   read.
2. **Is libvhdi a sufficient oracle?** It must resolve a chain
   instar wrote, for both VHD and VHDX, and export composed
   content that matches what instar intended. Phase 1 proves or
   disproves this. If it fails on VHDX, the fallbacks are a
   Windows/Hyper-V-produced reference sample checked into
   testdata as read-only evidence, or a hand-decoded structural
   assertion suite with no content-level oracle. Say which
   before phase 6 starts.
3. **Which locator entries do we emit?** The VHD spec allows
   eight entries in several platform codes; Hyper-V typically
   writes `W2ru` (relative) and `W2ku` (absolute) plus the
   Unicode parent name. *Recommendation: emit relative and
   absolute Unicode entries and leave the remaining slots zero*,
   which is the most portable minimum, but phase 1 should
   confirm against what libvhdi and any real Hyper-V sample
   accept.
4. **Does an instar-only capability need an opt-in flag?**
   qemu-img refuses this operation entirely. *Recommendation:
   no flag.* instar already performs vmdk/vhd/vhdx `resize` and
   vmdk `rebase` where qemu-img refuses, without a flag, and
   these are recorded divergences rather than hidden ones.
5. **Parent path resolution and its security posture.** A
   locator path is untrusted data, exactly as a qcow2 backing
   reference is. On write we control the path; on read (even to
   refuse) we parse attacker-controlled bytes. The plan must
   state that instar never opens a path it read out of an image
   without the same host-side resolution rule qcow2 backing
   files get (resolve relative to the child's directory, never
   follow into the guest), and phase 3 has to be
   bounds-check-clean against `PLAN-extra-coverage` priority 7
   inputs even before those fixtures exist.
6. **Do we pull in the adversarial fixtures now?** Priority 7 of
   the testdata plan is unstarted. *Recommendation: yes, as part
   of phase 2*, because phase 3 is the code that needs them and
   generating both sets from one script is cheaper than two
   passes.
7. **Must a differencing child's parent share its format?**
   Hyper-V requires VHD parents for VHD children and VHDX for
   VHDX. instar's `create -b` path currently accepts any
   detectable parent format. *Recommendation: require a matching
   parent format for differencing output and reject the rest
   with a typed error*, rather than emitting a chain no
   implementation can resolve.

## Execution

Each phase gets its own detailed plan file before implementation
begins; this table is the tracking source of truth. The `Merged`
column records what put each phase on `develop` -- the merge
commit of its pull request, or a `first..last` range for a phase
that landed directly -- because phase 11 audits the union of
those ranges, and `git diff develop...HEAD` is empty once the
phases have landed. A phase that lands in `instar-testdata`
records `instar-testdata <sha> (#pr)` and is audited there.

| Phase | Plan | Status | Merged |
|-------|------|--------|--------|
| 1. Semantics pin, oracle selection, and the doc correction | PLAN-differencing-phase-01-pin.md | In progress | |
| 2. Real differencing fixtures, happy-path and adversarial (instar-testdata) | PLAN-differencing-phase-02-fixtures.md | Not started | |
| 3. Parent-locator parsing in `crates/vhd` and `crates/vhdx` | PLAN-differencing-phase-03-parse.md | Not started | |
| 4. Read-side policy: close the silent parent-ignoring read | PLAN-differencing-phase-04-read-policy.md | Not started | |
| 5. `plan_vhd` differencing emitter | PLAN-differencing-phase-05-vhd-emitter.md | Not started | |
| 6. `plan_vhdx` differencing emitter | PLAN-differencing-phase-06-vhdx-emitter.md | Not started | |
| 7. Guest create op and host CLI wiring | PLAN-differencing-phase-07-guest-host.md | Not started | |
| 8. Rust unit tests and Python integration tests | PLAN-differencing-phase-08-tests.md | Not started | |
| 9. Coverage fuzzing of the locator parsers | PLAN-differencing-phase-09-fuzz.md | Not started | |
| 10. Documentation | PLAN-differencing-phase-10-docs.md | Not started | |
| 11. Push audit | PLAN-differencing-phase-11-push-audit.md | Not started | |

### Sequencing rationale

Phase 1 comes first because it is the only phase that can
invalidate the rest: if no oracle exists, the shape of phases 8
and 9 changes and the operator should know before any emitter is
written. It also answers open questions 1, 2, 3 and 7, and its
first deliverable has already landed -- commit `a93615d` on this
branch corrected `docs/create.md`, which claimed vpc and vhdx
honoured `backing_file` when both planners reject it.

Phase 2 precedes phase 3 because a parser with no real input is
a parser with no test. Phase 3 precedes both emitters because
parse-then-emit lets each emitter be checked by instar's own
reader before the external oracle is involved, which is how every
other format crate in this repository was built.

Phase 4 sits before the emitters deliberately. It is the phase
that fixes an existing defect rather than adding a feature, and
putting it first means the tree is never in a state where instar
writes differencing disks while still silently misreading them.

Phases 5 and 6 are independent of each other and could be
parallelised; VHD goes first because its parent locator table is
the simpler structure and the lessons carry into VHDX.

Phase 7 is the smallest of the implementation phases: the host
already attaches the backing file as input device 0 when `-b` is
given (`run_create_nonraw`, `src/vmm/src/main.rs:16612`), so the
guest can read the parent's footer for its unique id and
timestamp without any new call-table primitive. That is the fact
that makes this plan tractable, and phase 1 should confirm it
still holds before phase 7 is planned.

### Constraints that apply throughout

* Guest binaries stay under the 768KB per-operation cap
  (`make check-binary-sizes`). The create op has room, but the
  locator table walk is new guest code and wants budgeting.
* The format crates are `no_std` and panic-free. Every offset and
  length taken from an image is bounds-checked before use; the
  existing qcow2 and vmdk crates are the pattern.
* Parent locator paths are untrusted. Nothing in the guest ever
  opens one, and the host applies the same resolution rule it
  applies to qcow2 backing references.
* Every phase that changes user-visible behaviour updates the
  documentation that describes it in the same pull request.
  Phase 10 exists for the cross-cutting pages, not as a licence
  to leave the per-phase pages stale.

## Agent guidance

The canonical guidance -- execution model, planning effort, step
tables, model roster, review checklist -- is in
`PLAN-TEMPLATE.md`, and this plan follows it rather than
restating it. What is specific to this plan:

* **Execution model.** All implementation work is done by
  sub-agents; the management session plans, reviews the actual
  files rather than the sub-agent's summary, and commits.
* **Planning effort.** Phases 1, 3, 4, 5 and 6 are high effort:
  they turn on format-spec interpretation, an architectural
  decision about read behaviour, or emitting structures no
  reference implementation in reach will double-check for us.
  Phases 2, 8, 9 and 10 can be planned at medium effort with
  good briefs. Phase 7 is high effort only because it touches
  the guest/host boundary; the change itself is small.
* **Model choice.** Skew to opus for the emitters and the parse
  layer. Phase 5 and 6 briefs must name the exact byte offsets
  and the checksum algorithm, because a plausible-looking wrong
  offset in a format nobody else validates is precisely the
  failure this plan is exposed to.
* **A standing warning from this repository's history.** Agents
  assert plausible-but-wrong format and tool capabilities.
  Require cite-or-measure for every claim about what libvhdi,
  Hyper-V or qemu accepts, and re-measure a sample in the
  management session before it is written into a brief.

## Administration and logistics

### Success criteria

We will know this plan has been implemented because:

* `instar create -f vpc -b PARENT -F vpc child.vhd SIZE` and the
  vhdx equivalent produce images the phase 1 oracle resolves
  against their parent, with content matching what instar
  intended.
* No instar op silently composes a differencing image as though
  it had no parent; the behaviour chosen in open question 1 is
  implemented uniformly across `info`, `check`, `convert`,
  `compare`, `dd`, `bench`, `map` and `measure`.
* `crates/vhd` and `crates/vhdx` parse parent locator structures
  and are clean under the new fuzz targets, including the
  adversarial fixtures from phase 2.
* `make instar` builds, `make lint` is clean,
  `make check-binary-sizes` passes, `make test-rust` and
  `make test-integration` pass, and `pre-commit run --all-files`
  passes.
* `docs/create.md`, `docs/format-coverage.md` (both the output
  side table and the divergence notes), `docs/quirks.md`,
  `docs/resize.md`, `docs/guest-architecture.md`,
  `ARCHITECTURE.md` and `CHANGELOG.md` describe what shipped,
  and the false "differencing with backing chains" input claim
  at `CHANGELOG.md:1922` is reconciled by a current statement of
  what is actually supported.
* The push audit in phase 11 has run over the union of the
  merged ranges, and its findings are resolved or declined in
  writing.

### Documentation index maintenance

`docs/plans/index.md` carries a row for this plan in the *Master
plans* table, and `docs/plans/order.yml` carries an entry for the
master plan only. Phase files are linked from the index row and
from the Execution table above as they are written, and are not
added to `order.yml`. When every phase is complete the index
status becomes `Complete`.

### Future work

* Chain composition on read for VHD and VHDX, if open question 1
  is answered as recommended: teach `convert`, `compare`, `dd`,
  `bench`, `map` and `measure` to resolve a differencing child
  against its parent using the multi-input-device mechanism
  qcow2 backing chains already use, and extend `info --chain` to
  walk a VHD/VHDX chain.
* `resize` of a differencing image, which needs the
  parent-locator update path this plan builds
  (`docs/resize.md:215`).
* `rebase` for differencing VHD/VHDX -- repointing a child at a
  new parent -- which `PLAN-rebase-commit.md:236` deferred for
  want of exactly this parse and emit layer.
* The other two leaves of the same 2026 goal: multi-extent VMDK
  output, blocked on multi-output-device support in the call
  table, and vmdk/vpc/vhdx preallocation, blocked on a per-format
  BAT population pattern.
* Differencing-aware `check`, once a chain can be resolved:
  today `check` refuses VHDX differencing and validates a VHD
  differencing child as if it were dynamic.

### Bugs fixed during this work

* `docs/create.md` claimed vpc and vhdx honoured `backing_file`
  and `backing_fmt`, and marked both "Yes" for backing support,
  where both planners reject a backing reference outright. Fixed
  on this branch in `a93615d`, ahead of the phase 1 plan file.
* The silent parent-ignoring read of differencing VHDs is a live
  correctness defect, not merely a missing feature: `convert`
  produces a wrong image and exits 0. Phase 1 files it as a
  GitHub issue and phase 4 fixes it. There were no open issues
  on this surface when the plan was written.
* `instar-testdata/custom/format-coverage/vhd-differencing.vhd`
  is a `disk_type = 4` marker with an empty parent name and
  eight zeroed locator entries, so it does not exercise what its
  name implies. Phase 2 replaces or supplements it and records
  what the old fixture was actually testing.

### Back brief

Before executing any step of this plan, please back brief the
operator as to your understanding of the plan and how the work
you intend to do aligns with that plan.
