# Multi-extent VMDK phase 2: fixtures and baselines

## Status: Not started

Master plan: `PLAN-multi-extent-vmdk.md`.

## Planning effort

Medium. The phase follows a pattern `PLAN-bat-population-phase-02-fixtures.md`
established, and it writes no instar behaviour. What raised it above
mechanical is that the corpus already contains more multi-extent VMDK
than the master plan's intent assumes, and that one of the two obvious
fixture shapes cannot be stored at all -- both settled below by
measurement rather than left to the implementer.

## Decisions already taken by the operator

From the master plan, resolved 2026-11-16:

1. Sequential extent rotation, not simultaneous indexed output devices.
2. The read-side extent ceiling is fixed inside this plan, as phase 3.

Neither constrains this phase directly, but decision 2 is why a fixture
past the 15-extent ceiling is in scope here: phase 3 needs something to
prove itself against.

Open questions 3 to 6 remain open. This phase settles none of them; it
does not touch extent path derivation (question 4) or any instar-side
limit (question 5), because it writes no instar behaviour.

## Scope

In scope:

* Four qemu-written `twoGbMaxExtentSparse` fixtures in
  `instar-testdata/custom/format-coverage/`, with their
  `tests/manifest.json` entries.
* A generator script for them in instar's `scripts/`, pinned to a
  static qemu-img build rather than the host's.
* A test-time generator for `twoGbMaxExtentFlat` split images, which
  are measured below to be unstorable.
* Baselines for the four new fixtures across all 80 static qemu builds,
  for every image-driven command, with the derived profiles validated.
* An issue for the two `info` divergences the survey found, and the
  measurements recorded in the master plan.

Out of scope:

* Any change under `src/`. As in phase 1,
  `git diff --name-only origin/develop...HEAD -- src/` must be empty at
  the end of it.
* Fixing either divergence the survey found. Both predate this plan,
  both are in the multi-extent read path, and phase 3 owns that path.
  See decision 6.
* Giving `vmdk-multi-flat` and `vmdk-twogb-flat` baselines. They carry
  `skip_qemu_img` today, and un-flagging them is what would expose the
  divergences as a red suite. Same reason, same phase.
* Reading `twoGbMaxExtent*` images (phase 3) and the structural
  comparison arm of the differential fuzzer (phase 16).
* `instar map` on flat sources, refused for every flat source and wider
  than this plan.

## What the survey found

The master plan's phase 2 intent is **stale in three ways**, two of
them load-bearing. All three are corrected at source in the master plan
and `docs/plans/index.md` as part of this phase's planning commit;
a later step should not redo that.

### The past-the-ceiling fixture already exists

The intent says to add "at least one image past the current 15-extent
ceiling so phase 3 has something to prove itself against". The corpus
already has one: `osboxes-vmdk-split-sparse`
(`downloaded/osboxes/android-x86-5.1-rc1-split-sparse/`), a real VMware
Workstation `twoGbMaxExtentSparse` image of 26 extents, 100 GiB virtual
in 1.3 GiB, with full baselines -- 261 files each under
`expected-outputs/qemu-img-human` and `qemu-img-json`, 243 each under
`check-human`, `check-json` and `map-human`, 249 under `map-json`, and
486 each under `measure-human` and `measure-json`.

It is not a parity fixture, though, and the reason is worth recording:
**its extents are 8304640 sectors (3.96 GiB) each**, not 2 GiB, under a
descriptor that says `createType="twoGbMaxExtentSparse"`. The last is
2099200 sectors. So the create type does not imply an extent size, and
a reader that infers 2 GiB from the create type rather than reading each
extent's declared sector count is wrong on the one real-world image in
the corpus. That descriptor also carries `encoding="windows-1252"`,
`isNativeSnapshot="no"`, and extent filenames containing spaces.

It therefore covers the device-slot ceiling and the awkward real-world
spelling, and covers qemu's own geometry not at all.

### No qemu-written split fixture exists, and the flat one cannot

The intent reads as though both subformats can be added the same way.
Measured, they cannot.

A split-sparse extent is a small file: pinned case
`vmdk-multi-sparse-21G` is 11 extents totalling 3,473,408 bytes
(327,680 for each full extent, 196,608 for the 1 GiB tail). A split-flat
extent is a full-length sparse file: `vmdk-multi-flat-21G` totals
22,548,578,304 bytes apparent.

Sparse files do not survive git-LFS. Measured on
`downloaded/qemu-iotests/d2v-zerofilled.vhd`: 264,308,224 bytes
apparent, 512 KiB allocated in the checkout, and its LFS object at
`.git/lfs/objects/af/17/af17...` occupies 264,314,880 bytes. The
repository is already 32 GB with a 15 GB `.git`.

`scripts/create-vmdk-flat-testdata.sh:100-110` already works around
this: it creates a 3 GiB `twoGbMaxExtentFlat` with qemu-img and then
deletes both extents, keeping the descriptor alone
(`vmdk-twogb-flat.vmdk`, and the manifest says so). The small
`vmdk-multi-flat` beside it is hand-built -- three 1024-sector extents
filled 0xAA/0xBB/0xCC -- so neither is qemu-written and neither has a
partial last extent at qemu's geometry.

### The pin's structural oracle is sparse-only, by design

`tests/helpers/qemu_pins.py:711` captures `structure` only when a
descriptor declares a SPARSE extent, with the reason in the comment:
a sparse extent has a header whose fields decide how it is walked and
nothing in the descriptor says what they are. So every
`vmdk-multi-flat-*` pin case records descriptor text, extent names and
extent lengths with `structure: null`. That is not a gap to fill; it is
noted here so a later phase does not read the nulls as a defect.

### Two shipping `info` divergences, invisible today

Found while checking what instar does with the existing fixtures.
Measured with qemu-img 10.2.0 from the static builds and the instar
binary at `src/target/release/instar` **dated 2026-10-19**, which
predates several merges -- step 2b re-measures with a fresh build
before the issue is filed.

On `custom/format-coverage/vmdk-multi-flat.vmdk` (three 512 KiB
fully-written flat extents):

| Field | qemu-img 10.2.0 | instar |
|-------|-----------------|--------|
| top-level `actual-size` | 1576960 | 4096 |
| each child's `actual-size` | 524288, 524288, 524288, 4096 | same |
| `children[]` order | f003, f002, f001, descriptor | f001, f002, f003, descriptor |

qemu reports the sum over the descriptor and every extent; instar
reports the descriptor's allocation alone. The same holds for
monolithicFlat: on `vmdk-flat-1m.vmdk` qemu says `disk size: 1 MiB` and
instar says `disk size: 4 KiB`. In the human format instar additionally
prints the descriptor's 4 KiB for every extent, where qemu prints each
extent's own.

Both are invisible because every multi-file VMDK fixture carries
`skip_qemu_img`, and `generate-baselines.py:1043` never generates for
those -- 31 of the 124 safe images are flagged. And they would stay
invisible after the flag came off, because
`tests/helpers/comparators.py:139-168` substitutes a live
`get_disk_size()` into the baseline per dict that carries a `filename`:
the top-level dict's filename is the descriptor, so qemu's 1576960
would be rewritten to 4096 and instar's wrong answer would match. The
masking is single-file by construction, which is exactly the shape of
the defect it hides.

### What was right

The rest of the intent holds. `instar-testdata` does take direct
commits to `main` and is git-LFS backed. `generate-baselines.py` has
`--image` and `--case` exact-match filters that refuse to match nothing
(added by `PLAN-bat-population-phase-10-matrix.md`), `--no-commit`
exists and the script auto-commits without it, and
`scripts/validate-profiles.py` exists behind `make validate-profiles`.
The derived profile directories have twice been silently wrong while
the raw baselines were fine.

## Measurements this phase starts from

Taken 2026-11-18 against `ca4bfb52` with the static
`qemu-img-binaries/x86_64/10.2.0/qemu-img`, in the session scratchpad.

**Create geometry, 5 GiB sparse.** Three extents of 4194304, 4194304
and 2097152 sectors; files 327,680, 327,680 and 196,608 bytes apparent;
12,288 bytes allocated each on ext4, with a 417-byte descriptor.
`qemu-img info` reports `disk size: 40 KiB`, the sum of the four files'
allocations. This matches pinned case `vmdk-multi-sparse-5G` exactly.

**Data across an extent boundary is reachable with qemu-img alone.**
The static builds ship `qemu-img` and no `qemu-io`, so data cannot be
written into a sparse extent after the fact. Converting from a holey raw
source does it in one step: a 5 GiB raw file with 128 KiB of 0xAB
written at 2 GiB − 64 KiB, converted with
`qemu-img convert -f raw -O vmdk -o subformat=twoGbMaxExtentSparse`,
gives the identical three-extent descriptor and grows both of the first
two extents -- 393,216 bytes apparent and 81,920 / 77,824 allocated --
so the pattern genuinely straddles the boundary. `qemu-img info` reports
`disk size: 172 KiB`. Note that convert writes a 512-byte descriptor
where create writes 417.

**Allocation is not reproducible through LFS, and must not be fixed.**
qemu's sparse extents are hole-bearing (327,680 apparent against 12,288
allocated), so a fresh clone reports a different `disk size` than the
machine that generated the fixture. `resparsify_images()`
(`scripts/generate-baselines.py:925`) repairs that, but only under
`downloaded/`. Extending it to `custom/` would be wrong: it runs
`cp --sparse=always`, which punches holes wherever it finds zeroes, so
it would re-sparsify the deliberately dense hand-built fixtures --
`vmdk-flat-1m-flat.vmdk` is a megabyte of zeroes -- and churn their
baselines. Nothing needs to change, because `substitute_actual_size`
recomputes per file at test time. This paragraph exists so that nobody
later reads the mismatch as a bug in `resparsify_images`.

## Decisions

1. **Split-sparse fixtures are stored; split-flat fixtures are never
   stored.** The cost asymmetry above is three orders of magnitude, and
   git-LFS objects on `main` are effectively permanent. The existing
   generator's delete-the-extents trick is the precedent, and this
   phase makes the rule explicit rather than leaving the next person to
   rediscover it.

2. **Four fixtures**, all `twoGbMaxExtentSparse`, in
   `custom/format-coverage/`:

   | id | Size | Extents | Tail | Apparent cost | Why |
   |----|------|---------|------|---------------|-----|
   | `vmdk-split-sparse-2049m` | 2049M | 2 | 2048 sectors (1 MiB) | 393,216 B | The smallest non-multiple: a tail extent of one grain-and-a-bit |
   | `vmdk-split-sparse-5g` | 5G | 3 | 2097152 sectors (1 GiB) | 851,968 B | The reference geometry, identical to pinned `vmdk-multi-sparse-5G` |
   | `vmdk-split-sparse-5g-boundary` | 5G | 3 | 2097152 sectors | 983,040 B | 128 KiB of 0xAB straddling the 2 GiB boundary, so a rotation bug shows as wrong bytes rather than a wrong size |
   | `vmdk-split-sparse-33g` | 33G | 17 | 2097152 sectors (1 GiB) | 5,439,488 B | Past the 15-extent ceiling at qemu's own 2 GiB geometry, with a partial tail |

   About 7.5 MB in all, which LFS stores in full. The 33 GiB one is the
   phase 3 fixture; `osboxes-vmdk-split-sparse` is kept as the
   real-world foil, not replaced.

3. **The generator is pinned to the static 10.2.0 build**, overridable
   with `QEMU_IMG`, and fails loudly if the binary is absent -- unlike
   the existing VMDK generators, which call whatever `qemu-img` is on
   the host. The honest limit of that pin: the descriptor's `CID` is
   random, so a regeneration is never byte-identical to what is
   committed whatever build runs it. Pinning removes the host from the
   inputs for everything else (`ddb.toolsVersion` appears from 6.2.0,
   per the phase 1 pin), and the fixtures are generated once and
   committed, not regenerated casually.

4. **The new entries do not set `skip_qemu_img`**, so baselines
   generate, and each carries `instar_unsupported` with the refusal
   measured in step 2b. `test_info_safe.py:124` turns that key into an
   assertion that instar *fails*, so the suite stays green today and
   phase 3 removes the key as part of lifting the ceiling. That is the
   handoff: four fixtures whose manifest entries phase 3 must change to
   claim success.

5. **Split-flat coverage is a test-time generator, not a fixture.** A
   helper in `tests/helpers/` builds a split-flat image into a caller's
   temporary directory with the pinned qemu-img, for phases 3, 11 and 16
   to use. A 33 GiB split-flat image costs 17 files of 2 GiB apparent
   and about 4 KiB each allocated, which is free on a sparse filesystem
   and unstorable in LFS.

6. **The two `info` divergences are filed and left to phase 3.** This is
   the decision most likely to be argued with, so the reasoning in full:
   the fix is a few lines -- sum the descriptor's and every extent's
   allocation for the top-level figure, and stat each extent in the
   human path -- and a reviewer could fairly say to just do it. Three
   reasons not to. It is not this phase's blast radius: it changes
   `info` output for every monolithicFlat image instar has ever read,
   which is a baseline churn and a differential-fuzz exposure of its
   own. It cannot be proved without also teaching
   `comparators.get_disk_size` to sum siblings, and that change makes
   the oracle meaningful for images this phase is deliberately not
   un-flagging, so it would land red. And phase 3 is already inside
   extent resolution, which is where both the stat loop and the child
   ordering live. Phase 2's job is to leave the oracle in place -- the
   baselines are qemu's output and correct regardless of what instar
   does -- so that phase 3's fix has something to be measured against
   the day it is written.

7. **Baselines for all four image-driven commands across all 80
   builds** (`info`, `check`, `measure`, `map`), generated with
   `--no-commit` and `--image`, with `make validate-profiles` run
   afterwards and a profile spot-checked by hand. The testdata half
   lands as a direct commit to `main`, which the back brief gates.

## Step plan

Steps 2a and 2b are independent and may run in parallel: 2a writes only
into the testdata checkout, 2b only builds in the instar worktree and
reads. Everything after 2c is sequential, because 2d consumes the
manifest entries and 2f consumes 2d's counts. 2e touches only
`tests/helpers/` in the instar worktree and may run alongside 2d, which
works in the testdata clone.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 2a | medium | sonnet | none | Write `scripts/create-vmdk-split-testdata.sh` in the instar worktree and generate the four fixtures of decision 2 into `../instar-testdata/custom/format-coverage/`. Read `scripts/create-vmdk-flat-testdata.sh` first and follow its shape: `set -euo pipefail`, an output directory as `$1` defaulting to `../instar-testdata/custom/format-coverage`, `rm -f` of every file it is about to write (including the extents, whose names it must derive, not glob), and an `ls -la` of what it made at the end. Use `QEMU_IMG` from the environment, defaulting to `$INSTAR_TESTDATA_PATH/qemu-img-binaries/x86_64/10.2.0/qemu-img`, and exit non-zero with a message naming the path if it is not executable -- do not fall back to the host's `qemu-img`. Three fixtures are `qemu-img create -f vmdk -o subformat=twoGbMaxExtentSparse <out> <size>` at 2049M, 5G and 33G. The fourth, `vmdk-split-sparse-5g-boundary`, is made by writing a 5 GiB raw file with 128 KiB of 0xAB at offset 2147418112 (2 GiB − 64 KiB) via a short `python3 -c` heredoc exactly as the existing script seeds its flat extent, then `qemu-img convert -f raw -O vmdk -o subformat=twoGbMaxExtentSparse`, then deleting the raw source. Verify before finishing, and report the numbers: each descriptor's extent count and the declared sector count of its last extent; that every named extent file exists; and for the boundary fixture that `qemu-img map --output=json` reports a data range covering 2147418112 through 2147549184. Do NOT commit anything in either repository, and do not run `git add` in the testdata clone. Python inside the script follows this repo's conventions: single quotes, 120 columns. |
| 2b | medium | sonnet | none | Re-measure three things with a freshly built binary and report them verbatim, changing no files. Build with `make instar` in the instar worktree (it builds in Docker; see the `build-and-test` skill) and say what the binary's mtime and `git describe`/HEAD are, because the measurements in the phase plan were taken with a binary dated 2026-10-19 that predates several merges. (1) The exact refusal `instar info` gives for a multi-extent SPARSE descriptor, run against `downloaded/osboxes/android-x86-5.1-rc1-split-sparse/Android-x86 5.1 RC1.vmdk` in the testdata checkout -- quote the whole line. (2) `instar info` and `instar info --output json` against `custom/format-coverage/vmdk-multi-flat.vmdk` and `custom/format-coverage/vmdk-flat-1m.vmdk`, compared field by field with `qemu-img-binaries/x86_64/10.2.0/qemu-img` on the same files: report the top-level `actual-size`/`disk size`, every child's, and the order of `children[]`. Say for each whether the divergence in the phase plan's table still reproduces. (3) Whether `instar info` resolves `custom/format-coverage/vmdk-twogb-flat.vmdk`, whose extents do not exist, and what it says. Report only; file no issue and fix nothing. |
| 2c | low | sonnet | none | Add four image entries to `tests/manifest.json` in the instar worktree, for the fixtures step 2a generated. Copy the field set of the existing `vmdk-multi-flat` entry (around line 483) -- `id`, `path`, `format`, `safety: safe`, `run_in_ci: true`, `description`, `tags`, `generated_by` -- with two differences. Do **not** set `skip_qemu_img`: `generate-baselines.py:1043` never generates baselines for an image that has it, which is why the existing multi-extent entries have none. And set `instar_unsupported` to the refusal step 2b measured, worded like the `osboxes-vmdk-split-sparse` entry's (around line 2380), because `tests/test_info_safe.py:124` reads that key as an assertion that instar fails. Tags: `vmdk`, `twoGbMaxExtentSparse`, `multi-extent`, `format-coverage`, plus `extent-boundary` on the boundary fixture and `past-device-ceiling` on the 33G one. `generated_by` is `scripts/create-vmdk-split-testdata.sh`. Each description states the virtual size, the extent count, the tail extent's sector count and, for the boundary fixture, where the pattern sits. Then confirm `python3 -c "import json; json.load(open('tests/manifest.json'))"` succeeds and report the manifest's new image count. |
| 2d | high | opus | none | Generate and validate baselines for the four new fixtures in the testdata clone at `../instar-testdata` (branch `main`; do not create a worktree there). This step is the one with a history of silent wrongness, so it reports numbers, not assurances. For each of the four image ids and each of `info`, `check`, `measure`, `map`, run `scripts/generate-baselines.py --command <cmd> --image <id> ... --no-commit`. **`--no-commit` is not optional**: without it the script commits by itself (see its `main()` around line 4104). Both `--image` and `--case` refuse to match nothing, so a typo fails loudly rather than generating zero files. Expect every one of the 80 version directories under `qemu-img-binaries/x86_64/` to be covered; say so with a count per command, and name any version that produced nothing. Note that `info` baselines land under the legacy `expected-outputs/qemu-img-human` and `qemu-img-json` directories, not `info-*`. Then run `make validate-profiles` (it runs `scripts/validate-profiles.py`) and report its exit status and output in full, and open one derived profile for one new fixture by hand and confirm it matches the raw baseline it was derived from -- the derived directories have twice been silently wrong while the raw ones were fine. Report the wall time, the total file count added, and `git status --short | wc -l` in the testdata clone. Do NOT commit and do NOT push. |
| 2e | medium | sonnet | none | Add a test-time generator for split-flat images to the instar worktree, with unit tests. It belongs beside the existing helpers in `tests/helpers/`; read `tests/helpers/qemu_pins.py` for how that package already locates a static qemu-img build and runs it, and reuse rather than duplicate. The function takes a directory and a size, builds `qemu-img create -f vmdk -o subformat=twoGbMaxExtentFlat` there, and returns the descriptor path and the extent paths in descriptor order. It exists because a split-flat image cannot be stored: its extents are full-length sparse files -- 2 GiB each -- and git-LFS stores holes as bytes, so a 33 GiB fixture would be a 33 GiB LFS object. Say that in the module or function docstring, with the numbers. Add unit tests in `tests/test_helpers.py` (or a new file if that one is near 1500 lines -- check, `PUSH-AUDIT.md`'s source-size rule bites at 800 and 1500) asserting a 5 GiB image gives three extents whose declared sector counts are 4194304, 4194304 and 2097152 and whose file lengths are 2147483648, 2147483648 and 1073741824, that the directory is cleaned up, and that a missing qemu-img raises rather than silently skipping. Run the new tests with the venv at `tests/.venv` and `INSTAR_TESTDATA_PATH` set, under stestr, and report the "Ran: N" line. Python conventions: single quotes except docstrings, 120 columns, no trailing whitespace. |
| 2f | medium | sonnet | none | Record what this phase found, in three places, in the instar worktree. (1) File a GitHub issue for the two `info` divergences on multi-file VMDK, using step 2b's freshly measured numbers rather than the phase plan's: the top-level `actual-size` is the descriptor's allocation where qemu reports the sum over the descriptor and every extent, and `children[]` comes back in the opposite order. Include that it affects monolithicFlat as well as the split subformats, that it is invisible today because every multi-file VMDK fixture carries `skip_qemu_img`, and that `tests/helpers/comparators.py:139-168` would mask it even after the flag came off because it substitutes a per-file `get_disk_size()` into the baseline and the top-level dict's filename is the descriptor. Say that phase 3 of the multi-extent VMDK work is where it is expected to be fixed, but do not cite the plan, the phase number or the file -- that rule holds for issues as it does for code. (2) Add the issue to the master plan's *Bugs fixed during this work*, and a *Future work* entry only for whatever the issue does not cover. (3) Update `docs/testing.md` where it describes recording split-subformat behaviour (phase 1 added that paragraph): the LFS cost rule from decision 1, with the measured numbers, and the `skip_qemu_img`-blocks-baselines mechanism. Report the issue number and the sections you touched. |

## Risks and mitigations

* **An LFS object pushed to `main` is permanent.** 7.5 MB is small, but
  a wrong fixture cannot be cheaply unpublished. *Mitigation:* the back
  brief gates the fixture set and the push separately, and the
  management session checks each file's apparent size against the table
  in decision 2 before anything is added.
* **The baseline generator auto-commits.** Without `--no-commit` it
  commits to `main` by itself. *Mitigation:* stated in step 2d's brief
  as not optional; the management session checks `git log` in the
  testdata clone before reviewing the diff.
* **The derived profiles have twice been silently wrong while the raw
  baselines were fine.** *Mitigation:* step 2d runs
  `make validate-profiles` and additionally opens one profile by hand;
  the management session re-runs the validator itself.
* **A fixture that quietly joins the #845 cohort.** 31 of 124 safe
  images carry `skip_qemu_img` and generate nothing.
  *Mitigation:* decision 4 forbids the flag, and the definition of done
  counts the files that appear.
* **The 2 GiB-extent assumption.** The one real-world split-sparse
  image in the corpus has 3.96 GiB extents under a
  `twoGbMaxExtentSparse` create type. *Mitigation:* recorded in the
  survey above and carried into the master plan, so phase 3 reads
  declared sector counts rather than inferring from the create type.
* **Measuring instar with a stale binary.** The divergence table was
  taken with a binary dated 2026-10-19. *Mitigation:* step 2b rebuilds
  and re-measures before anything is filed, and step 2f uses 2b's
  numbers rather than the plan's.

## Definition of done

Falsifiable; each is checkable by someone who did not do the work.

1. `custom/format-coverage/vmdk-split-sparse-33g.vmdk` has 17
   `RW ... SPARSE` extent lines, the seventeenth declaring 2097152
   sectors, and every file it names exists.
2. `vmdk-split-sparse-2049m.vmdk` has exactly two extent lines, the
   second declaring 2048 sectors.
3. `qemu-img map --output=json` on `vmdk-split-sparse-5g-boundary.vmdk`
   reports a data range covering offsets 2147418112 to 2147549184, so
   the pattern straddles the first extent boundary.
4. None of the four new manifest entries sets `skip_qemu_img`, and all
   four set `instar_unsupported`.
5. `find expected-outputs -name 'vmdk-split-sparse-*' | wc -l` in the
   testdata clone equals the count step 2d reports, and every one of
   the 80 version directories appears for `info`, `check`, `measure`
   and `map`.
6. `measure-json` contains at least one file for each of the four ids,
   so none of them joins the 81 fixtures of #845.
7. `make validate-profiles` exits 0.
8. The instar python suite runs with "Ran: N" matching the selection
   and 0 failures, with `test_info_safe` asserting the refusal for all
   four new fixtures. The count is checked, not the exit code.
9. The split-flat test-time generator builds a 5 GiB image whose three
   extents have file lengths 2147483648, 2147483648 and 1073741824, and
   a unit test asserts it.
10. `pre-commit run --all-files` passes in the instar worktree.
11. `git diff --name-only origin/develop...HEAD -- src/` is empty.
12. The issue for the two `info` divergences exists, cites step 2b's
    numbers, and is linked from the master plan.
13. No plan, phase or step reference appears in anything landed outside
    `docs/plans/` -- including the issue body.
14. The master plan's phase 2 intent and the `docs/plans/index.md` row
    say what the survey found, not what the intent said before it.

## Back brief

Before implementation begins, the implementing session restates this
phase's scope and the four gates below, and the operator confirms.

1. **The fixture set.** Four split-sparse fixtures at 2049M, 5G, 5G
   with boundary data and 33G, about 7.5 MB in LFS, named and sized as
   decision 2 lists them. Cheap to change now, permanent once pushed.
2. **No stored split-flat fixture**, decision 1, with split-flat
   coverage provided by a test-time generator instead.
3. **The direct push to `instar-testdata` `main`.** That repository
   takes direct commits and no merge requests, so the fixtures and
   baselines reach `main` without review. The operator confirms before
   the push, and the phase's `Merged` record must carry both
   repositories -- the instar merge commit and the testdata
   `first..last` range -- which
   `PLAN-bat-population-phase-13-push-audit.md` found missing once.
4. **Decision 6**, leaving both `info` divergences to phase 3 rather
   than fixing them here.

## Execution notes

Filled in as the phase runs.
