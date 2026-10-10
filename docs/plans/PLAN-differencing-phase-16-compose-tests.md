# Differencing phase 16: composition tests and fuzz

## Prompt

Plan phase 16 of `PLAN-differencing.md`. Phase 15 landed in `f14554cf`
(#646) and closed the op-consistency boundary; phases 11 to 15 built
and rolled out composition, and every test that holds them is either a
crate test over a synthetic fixture or an integration test over one of
three real chains compared against a golden the project generated
itself.

This phase is the external check on all of it: cross-validation against
the phase 1 oracle for chains instar wrote and chains it did not, the
two fixture-blocked coverage gaps phase 15 handed over (#631 and #635),
the 4096-byte-sector geometry phase 13 left behind, and coverage
fuzzing of the compose path, which no fuzz target reaches today.

The phase plan is the deliverable; implementation is a separate ask.

## Planning effort

**High.** The master plan's phase 16 section makes four factual claims
about tooling and two of them are wrong, in ways that change the shape
of the phase rather than a line number — one of the two routes it
contrasts does not exist in the packaged libvhdi at all. The 4K gap it
inherits turns out to be unreachable from an integration fixture for
an arithmetic reason, and settling that needed the chunk-ratio sums
done rather than asserted. The oracle's agreement with the project's
own goldens had to be measured before anything could be built on it,
and it disagrees in exactly one place.

Review effort: **medium**. The master plan does not specify one. No
production code changes in this phase except the shared fuzz harness;
the judgement is in this document and in what the oracle is allowed to
disagree about.

## Scope

**In scope.**

* **Oracle cross-validation of composed *data*.** The existing
  `TestDifferencingLibvhdiOracle` checks that libvhdi reads instar's
  child as *naming* its parent — an identity check on metadata. Nothing
  compares a composed byte. This phase adds a third independent
  reader of the same chains.
* **The write-then-read loop over instar's own output.** `create -b`
  writes a differencing child; nothing ever reads one back. Phase 16
  composes an instar-written chain with both instar and libvhdi and
  compares all three answers (child, parent, oracle).
* **Issue #635**: no integration fixture for a parentless differencing
  VHDX, so the composing operations' "no parent behind it" refusal is
  driven end to end for VHD only.
* **Issue #631**: no CLI-level coverage of a differencing-over-
  differencing chain. Both formats, with golden compositions.
* **The 4096-byte logical sector geometry.** Crate level, for the
  reasons in decision 3.
* **A compose fuzz target**, and the multi-device mock call table it
  needs.
* `tools/mutate-differencing.sh` cases for every property added here,
  `docs/testing.md`, and `CHANGELOG.md`.
* `src/.devcontainer/Dockerfile`: `python3-libvhdi`.
* New fixtures and their generator entries, committed to
  `instar-testdata` (decision 5).

**Out of scope, with the reasons stated.**

* **Issue #628** — `create -b` refuses a differencing backing for a
  reason phase 14 falsified. It asks a question this phase cannot
  answer with a test: whether every output format `create` can write
  has a sensible relationship with a differencing backing image. It is
  a decision and then possibly a feature, and it also blocks nothing
  here — decision 5 builds the grandchild fixtures from bytes, not by
  asking instar to stack a child on a child.
* **Issue #632** — safe-mode rebase onto a raw new backing fails as an
  unparseable overlay header. A real defect with a wrong message, found
  during phase 14, and unrelated to differencing: it reproduces with a
  qcow2 old chain. Not this phase's.
* **Issues #641, #642, #643** — chain composition in `map` and
  `measure`, and whether `check` and `measure` should still refuse.
  Phase 15 filed all three as hand-offs; nothing here changes what any
  operation composes.
* **Documentation of the composition story** — phase 17. This phase
  touches `docs/testing.md` because it adds tests, and `CHANGELOG.md`
  because it adds fixtures and a fuzz target. The read-side rows of
  `docs/format-coverage.md`, `docs/chain-discovery.md` and
  `docs/chain-config.md` stay with 17.
* **Differential fuzzing against libvhdi.** `differential-fuzz.yml`
  compares instar with the libyal parsers on single images. Extending
  it to chains means teaching the harness to author a chain per
  iteration and is a plan's worth of work; the coverage fuzz target in
  16f is the cheaper half and the one the master plan asked for.

## What the survey found

The master plan's phase 16 bullet (`docs/plans/PLAN-differencing.md`,
the *Phase 16, tests and fuzz* item) was written on 2026-09-05, before
phases 11 to 15 executed. All references below are against `f14554cf`,
and the measurements were taken on 2026-10-11.

### The CLI export it contrasts does not exist

The bullet says the harness "drives the `python3-libvhdi` binding with
an explicit `set_parent()` rather than a CLI export". The conclusion is
right and the reason is not: Debian 13's `libvhdi-utils` 20240509-2+b1
ships exactly two binaries, `vhdiinfo` and `vhdimount`. There is no
`vhdiexport` to reject. The real alternative to the binding is
`vhdimount`, a FUSE mount, which is a worse thing to require of CI than
a Python module.

Measured by extracting the package rather than by reading the upstream
source: the `.deb` contains `/usr/bin/vhdiinfo`, `/usr/bin/vhdimount`,
`libvhdi.so.1.0.0` and a man page for `vhdiinfo` alone.

`python3-libvhdi` is a separate package and **is not installed** in the
devcontainer. `src/.devcontainer/Dockerfile:39` installs
`libvhdi-utils`, which is why `vhdiinfo` is available to
`tests/base.py:_require_vhdiinfo` and the binding is not.

The binding has what the phase needs. Probed against the extracted
module (`pyvhdi` 20240509, built for CPython 3.13, which matches the
host and the container):

```
file methods: bytes_per_sector, close, disk_type, format_version,
get_bytes_per_sector, get_disk_type, get_format_version,
get_identifier, get_media_size, get_offset, get_parent_filename,
get_parent_identifier, identifier, media_size, open, open_file_object,
parent_filename, parent_identifier, read, read_buffer,
read_buffer_at_offset, seek, seek_offset, set_parent, signal_abort,
tell
```

### The oracle agrees with the goldens, except in one sector

This is the premise the whole phase rests on, so it was measured before
anything was planned. Driving `pyvhdi.file.set_parent()` over the three
real chains in `instar-testdata/custom/format-coverage/` and comparing
the composed bytes with the recorded `*-composed.raw` goldens:

| chain | result |
|---|---|
| `vhd-diff-child-aligned.vhd` | MATCH, all 16777216 bytes |
| `vhdx-diff-child.vhdx` | MATCH, all 16777216 bytes |
| `vhd-diff-child-mixed.vhd` | differs in **512 bytes**: sector 2 alone |

The divergence is the libvhdi VHD sector-bitmap defect the master plan
already records under *Phases 8 and 16*
(`libvhdi_block_descriptor_read_sector_bitmap_data` decodes the
per-block bitmap with an unmasked shift). Its shape here is worth
writing down, because the master plan's description does not quite
predict it: the oracle returns **zeros** where the golden holds
`PARENT-sector-000002`. That is consistent — reading the sector as
"present in the child" means reading the child's block, which was never
written there — but a test author expecting the child's *data* would
look for the wrong bytes.

One sector, deterministic, on the one fixture built to put parent-owned
and child-owned sectors in the same bitmap byte. `vhd-diff-child-aligned`
is the fixture built to avoid that, and the oracle agrees with it
exactly, which is the control that tells us the defect and not the
harness is responsible.

### The composed goldens are independent, and the generator is in this repo

`tests/test_differencing.py:18` credits
`scripts/create-vhd-testdata.sh` with the goldens. That is accurate,
and the script is in **instar**, not in `instar-testdata` — 1318 lines,
building VHD dynamic headers and patching VHDX metadata in embedded
Python. `tests/manifest.json` records `generated_by` for each fixture.
So the goldens never passed through instar's read path, and extending
the generator is this repo's work even though the fixtures land in the
other one.

The script hardcodes `SECTOR = 512` and derives `chunk_ratio =
(0x800000 * SECTOR) // block_size` from it (`:1006`).

### The 4K gap is narrower than stated, and partly unreachable

The bullet says "every multi-group and partial-group VHDX compose test
runs at 512-byte logical sectors". One 4K case now exists —
`vhdx_map_and_measure_refuse_a_block_inside_a_region_at_4k_sectors`
(`src/crates/qcow2/src/lib.rs:10552`), added during phase 15's second
review round — and it is `build_vhdx_image(4096, false, 1, ...)` with a
single block: one chunk group, no stride, no padded bound. It is the
only call in the tree that passes 4096. So the gap is real and it is
specifically the *multi-group and partial-group* shapes, exactly as
written.

What the bullet could not know is that no integration fixture can close
it. `chunk_ratio = 2^23 × logical_sector_size / block_size`, so at 4096
with the crate fixture's 1 MiB block it is 32768, and reaching a second
chunk group needs 65536 payload blocks — a 64 GiB virtual disk. A crate
fixture declares that size and materialises only the blocks it lists; a
real file would have to carry a 512 KiB BAT. And nothing available
authors a 4K-logical-sector VHDX at any size:

* `qemu-img create -f vhdx -o help` on 10.0.13 offers `block_size`,
  `block_state_zero`, `log_size`, `size` and `subformat`. No sector
  size. Measured.
* `instar create` has no `logical_sector_size` key either — the vhdx
  `-o` parser takes `block_size` and nothing sector-shaped
  (`src/vmm/src/main.rs:14938`, `:14962`), and
  `src/crates/create/src/lib.rs` never mentions
  `logical_sector_size`.

Hence decision 3.

### Nothing fuzzes compose, and the harness is single-device by construction

42 fuzz targets, listed in `src/fuzz/Cargo.toml` as `[[bin]]` entries
and again in `.github/workflows/coverage-fuzz.yml`'s `TARGETS` array.
Both counts are 42 today and nothing cross-checks them —
`tools/ci/count-fuzz-targets.sh` counts the Cargo entries only, to size
the duration cap. `grep -l 'ChainStates\|read_chain_virtual_cluster\|
init_chain_states' src/fuzz/fuzz_targets/` returns nothing.

`fuzz_vhd_parent` and `fuzz_vhdx_parent` fuzz the locator *parsers*,
which is phase 9's work and a different input space, as the bullet
says.

The shared mock call table cannot drive a chain:
`mock_get_input_device_count` returns a hardcoded `1`
(`src/fuzz/src/lib.rs:105`), `mock_read_input_sector` ignores its
`_device_idx` and reads one thread-local buffer (`:109`), and
`mock_get_chain_config` returns a null pointer with length zero
(`:200`).

That last one is less of an obstacle than it looks. `init_chain_states`
(`src/crates/qcow2/src/lib.rs:14717`) and
`read_chain_virtual_cluster` (`:12768`) are both `pub unsafe` and both
take `&ChainConfig` as a Rust reference, not as serialised bytes;
`ChainConfig` and all its fields are `pub` (`src/shared/src/lib.rs:4934`)
and so is `ChainStates` (`:14647`). So a target constructs the config
directly and never calls `get_chain_config`. The harness work is
per-device read routing and nothing else.

### Everything else in the bullet holds

The VHD sector-bitmap caveat applies and is why `vhd-diff-child-mixed`
exists. The integration suite runs inside the `instar-build`
devcontainer via `make test-container-core`, with
`INSTAR_REQUIRE_LIBVHDI=1` turning the oracle's skip into a hard
failure (`.github/workflows/functional-tests.yml:803-817`) — so one
apt line reaches both the local and the CI path, and the existing
`_require_*` pattern extends to the binding unchanged.

`tools/ci/check-devcontainer-pins.sh` guards `cargo install` pins, the
nightly, and Renovate's visibility of them. The apt list is unpinned
and adding to it does not engage that hook.

### Corrected at source

Per the skill, the master plan's phase 16 bullet and the `index.md` row
are corrected in this phase's planning commit: the non-existent
`vhdiexport` contrast, the narrowed 4K statement with the arithmetic
reason it cannot be an integration fixture, and the oracle's measured
agreement including the one-sector divergence. A later step should not
redo this.

## Decisions

1. **The oracle is the `pyvhdi` binding, made mandatory in CI the same
   way `vhdiinfo` is.** There is no CLI export to prefer or reject
   (survey above), and `vhdimount` would put a FUSE mount in the test
   path. `python3-libvhdi` goes into
   `src/.devcontainer/Dockerfile` beside `libvhdi-utils`, and
   `tests/base.py` gains a `_require_pyvhdi` honouring the existing
   `INSTAR_REQUIRE_LIBVHDI` variable rather than a second one: the
   two come from the same upstream release and a container missing one
   is missing both. A skipped oracle and a passing oracle look
   identical in a green run, and this repository has shipped a green
   workflow that ran nothing (`autofix_green_runs_ran_nothing`).

2. **The one-sector VHD divergence is asserted as a pinned exception,
   not skipped and not smoothed over.** The cross-validation test
   compares the oracle's composition with instar's byte for byte, and
   carries a single named exception: sector 2 of
   `vhd-diff-child-mixed`, where libvhdi is expected to return 512
   zero bytes and instar the parent's `PARENT-sector-000002` pattern.
   The test fails if that sector agrees, if any other sector
   disagrees, or if the oracle's wrong bytes are anything other than
   zeros.

   The alternatives are worse in a way worth stating, because this is
   the decision most likely to be argued with. Skipping
   `vhd-diff-child-mixed` would drop the only fixture that exercises
   mixed ownership within a bitmap byte, which is the hardest thing
   the VHD reader does. Comparing only the sectors both agree about
   would make the test insensitive to the oracle's defect growing.
   Asserting "at most one sector differs" would pass if the wrong
   sector differed. Pinning it means that if libvhdi is ever fixed
   upstream, the devcontainer bump that picks the fix up turns this
   test red and someone deletes four lines with a clear conscience —
   which is the correct outcome, and the only one of the four that
   notices.

3. **4K-sector coverage stays at crate level.** Multi-group at 4096
   needs a 64 GiB virtual disk, and no tool in the project or outside
   it authors a 4K-logical-sector VHDX at all (survey above). The
   fixture builder already takes the sector size as its first argument
   and `build_vhdx_image_blocks` already takes a payload block count
   for partial groups, so the coverage is a handful of new cases
   rather than new infrastructure. The BAT region caps it:
   `VHDX_FIX_BAT_LENGTH` is 1 MiB, so a differencing fixture at 4096
   fits `group_count` up to 3 (`3 × (32768 + 1) × 8 = 786456`), and 4
   trips the builder's own assert.

   The alternative — synthesising a 4K fixture by patching the
   metadata item, which the generator already does for `HasParent` —
   was considered and rejected for the multi-group case on the
   arithmetic, and as redundant for the single-group case: a 16 MiB
   image at 4096 has 8 payload blocks against a chunk ratio of 16384,
   so it can only ever express one partial group, which is what the
   existing 4K crate test already covers.

4. **One compose fuzz target, and the mock call table keeps its
   present behaviour by default.** `fuzz_chain_compose` drives
   `init_chain_states` then `read_chain_virtual_cluster` over a
   two-device chain built from the fuzz input. The harness gains an
   opt-in multi-device mode; `set_fuzz_input` and `build_call_table`
   keep returning a one-device table, because 42 existing targets
   depend on that and a target that silently became two-device would
   lose coverage without failing.

5. **New fixtures are generated by extending
   `scripts/create-vhd-testdata.sh`, and the grandchild is built from
   bytes.** #631 suggests a Hyper-V-authored grandchild; no Hyper-V is
   available, and the generator already hand-builds VHD dynamic
   headers and patches VHDX metadata, including the `HasParent` bit at
   `:989`. Fixtures land in `instar-testdata` with a direct commit to
   `main` (that repository takes no merge requests), rebasing first
   because the fuzz automation moves `main` daily, and
   `tests/manifest.json` records the generator for each.

   Building the grandchild rather than asking `instar create -b` to
   stack a child on a child also sidesteps #628 entirely, which is why
   that issue blocks nothing here.

6. **Cross-validation is additive.** The golden comparisons stay
   exactly as they are. An oracle is a second opinion, not a
   replacement for an expectation the project can state itself — and
   the goldens are the stronger of the two, being independent of both
   readers.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|---|---|---|---|---|
| 16a | high | opus | none | Stand up the data oracle and cross-validate the three existing real chains. Add `python3-libvhdi` to the apt list in `src/.devcontainer/Dockerfile:38-48` (alphabetical, beside `libvhdi-utils`; the list is unpinned and `tools/ci/check-devcontainer-pins.sh` does not police it). In `tests/base.py`, add `_require_pyvhdi` modelled exactly on `_require_vhdiinfo` (`:496`) including the `INSTAR_REQUIRE_LIBVHDI` hard-failure behaviour (decision 1) — import `pyvhdi` inside the method, not at module scope, so collection still works without it. Add a helper that composes a chain: `f = pyvhdi.file(); f.open(child, 'r'); p = pyvhdi.file(); p.open(parent, 'r'); f.set_parent(p); f.read_buffer_at_offset(f.get_media_size(), 0)`. Then a `TestDifferencingOracleComposes` class in `tests/test_differencing.py` beside `TestDifferencingLibvhdiOracle` (`:3666`) that, for each of the three `DIFFERENCING_FIXTURES` chains with a parent, compares the oracle's composition with the recorded `*-composed.raw` golden *and* with `instar convert -O raw` output, three-way. Carry the single pinned exception from decision 2: `vhd-diff-child-mixed` sector 2, oracle returns 512 zero bytes, golden and instar hold the `PARENT-sector-000002` pattern — assert the exception positively (that sector *does* differ, and the oracle's bytes *are* zeros) so the test fails if upstream fixes the defect. Read `media_size` rather than assuming 16 MiB. The read is 16 MiB per fixture in one call; if that is slow enough to matter, read in 1 MiB windows rather than reducing coverage. |
| 16b | high | opus | none | Close the write-then-read loop over instar's own differencing output, which nothing does today: `test_create_vhd_and_vhdx_differencing_round_trip` (`tests/test_create.py:427`) asserts the child's recorded parent identity and never reads a byte back. Using the same third-party parents it uses (`vhd-diff-parent.vhd`, `vhdx-diff-parent.vhdx`, copied into a temp dir by `_copy_diff_parent`), create a child with `instar create -f vpc|vhdx -b <parent> -F <fmt>`, then assert three readers agree on the composition: `instar convert -O raw` of the child, the oracle from 16a, and `instar convert -O raw` of the *parent alone*. A freshly created child has a wholly unallocated BAT, so all three must be identical — which makes this a strong test with no new fixture, and the one case where a disagreement indicts instar's writer rather than its reader. Measure, do not assume, two things and record both in the commit message: whether `set_parent` accepts an instar-written child at all (libvhdi validates parent identity, and instar copies the real identity from the parent, so it should — but phase 1 found three libvhdi defects by measuring), and whether libvhdi copes with the chunk-group-padded BAT instar now writes for a differencing VHDX (`calculate_bat_layout`, #623). If either fails, the deliverable is the measurement plus a documented exception in the same shape as decision 2's, not a reworked test that avoids the question — and a new libvhdi defect letter in the oracle class's docstring, which already records three. |
| 16c | medium | sonnet | none | Close issue #635: a parentless differencing VHDX fixture. Add a `vhdx-differencing` entry to `scripts/create-vhd-testdata.sh` producing a VHDX with the `HasParent` file-parameters flag set and no usable parent locator — the script already sets that bit (`:989`, `fp_flags | 0x2`) for the real child, so this is the same patch applied to an image whose parent locator is absent. The crate-side shape to match is `build_vhdx_image(512, true, ...)` in `src/crates/qcow2/src/lib.rs`. Commit the fixture to `instar-testdata` per decision 5 and add it to `tests/manifest.json` with `generated_by`. It must land in `DIFFERENCING_FIXTURES` in `tests/test_differencing.py:295`; `PARENTLESS_DIFFERENCING_FIXTURES` is derived, so that is the only list to touch. Then assert `convert`, `compare` and `bench` each refuse it with `expected_refusal(op, 'VHDX')` — already parameterised over format — and that `check` and `measure` give their non-composing refusal for it, which is the half the issue does not mention and which costs one more loop. Confirm the refusal is the empty-chain path and not the unresolvable-parent path: those are different messages and the issue is explicit that copying the real child without its parent yields the wrong one. |
| 16d | high | opus | none | Close issue #631: CLI coverage of a differencing-over-differencing chain, both formats. Extend `scripts/create-vhd-testdata.sh` with `vhd-diff-grandchild.vhd` and `vhdx-diff-grandchild.vhdx`, each naming the existing differencing child as its parent, plus `vhd-diff-grandchild-composed.raw` and `vhdx-diff-grandchild-composed.raw`. The crate-level equivalents to mirror for the ownership pattern are `vhd_arm_composes_a_differencing_child_over_a_differencing_parent` and the vhdx one (`src/crates/qcow2/src/lib.rs`, named in #631). Spread sector ownership across all three levels so a reader that stops descending after one level produces visibly wrong bytes — the existing `CHAIN_PROBE_SECTORS` property. Two hard constraints: the VHD grandchild must keep parent-owned and child-owned sectors in **different bitmap bytes** at every level, or the 16a oracle disagrees with it for libvhdi's reasons rather than instar's (the master plan's *Phases 8 and 16* caveat, and the measured shape in this plan's survey); and the generator's existing parent-identity patching has to be applied twice, since the grandchild records the child's identity and the child records the parent's. Add a `TestDifferencingDepthThreeAllDifferencing` class driving `convert -O raw` over each grandchild against its golden, and extend 16a's three-way comparison to cover them — a three-level chain is where `set_parent` chaining either works or does not, and that is worth knowing. Keep `TestDifferencingDepthThree` as it is: a qcow2 overlay over a differencing chain is a different shape, not a weaker version of this one. |
| 16e | medium | sonnet | none | Close the 4096-byte logical sector gap at crate level (decision 3). Today `build_vhdx_image(4096, ...)` is called exactly once, at `src/crates/qcow2/src/lib.rs:10552`, with `group_count` 1 and a single block. Add cases at 4096 for: a block in the second chunk group (`group_count` 2, payload index `chunk_ratio`), the last payload index of a two-group image (`chunk_ratio * 2 - 1`), a partial final group via `build_vhdx_image_blocks` with a payload count that is not a multiple of `chunk_ratio`, and the differencing (`has_parent = true`) variants of each. The arithmetic to carry in the test comments: `vhdx_chunk_ratio(4096)` is 32768 against 4096 at 512 bytes, so `group_count` 2 declares a 64 GiB virtual disk while materialising only the listed blocks, and the fixture's 1 MiB BAT region caps `has_parent` fixtures at `group_count` 3. Mirror the existing 512-byte cases for each of the four walks — `block_lookup`, `sector_bitmap_lookup`, `map_extents` and `scan_allocation` — and remember that only `scan_allocation` and `count_allocated_in_bat_chunk` go through `for_each_payload_bat_entry`, while `map_extents` keeps its own copy of the group arithmetic (`src/crates/vhdx/src/lib.rs:3023-3024`): a test that only refuses cannot distinguish the two, which is what `vhdx_scan_counts_a_block_in_each_chunk_group` was added for in phase 15. At least one case must assert a *count* or an *extent offset*, not just a refusal. Add `tools/mutate-differencing.sh` cases for the ones that pin new behaviour. |
| 16f | high | opus | none | Add `fuzz_chain_compose`, the first fuzz target to reach the compose path. Harness first, in `src/fuzz/src/lib.rs`: add an opt-in multi-device mode — something like `set_fuzz_devices(&[&[u8]])` storing a `Vec<Vec<u8>>` thread-local — and make `mock_get_input_device_count` (`:105`) and `mock_read_input_sector` (`:109`) honour it, with `mock_get_input_capacity` and the rest consistent per device. Default behaviour must be byte-for-byte what it is now: one device, the single buffer, because 42 targets depend on it (decision 4) and a target that quietly became two-device would lose coverage silently. The target then splits the fuzz input into a child and a parent buffer, constructs a `ChainConfig` directly — it and all its fields are `pub` in `src/shared/src/lib.rs:4934`, the formats come from `ChainDeviceInfo::detected_format`, and `segments` must tile `[0, device_count)` or `init_chain_states` refuses by design — calls `init_chain_states` (`src/crates/qcow2/src/lib.rs:14717`) and then `read_chain_virtual_cluster` (`:12768`) at a few virtual offsets. Neither needs `get_chain_config`; both take the struct. Assert invariants, not merely the absence of a panic, following `fuzz_vhdx_parent`'s header: a composed read that reports success must have filled its whole buffer, a device that failed to initialise must not be read through, and a refusal must not look like a successful read of zeros — that last one is issue #547's shape and the single most valuable thing this target can catch. Register it in `src/fuzz/Cargo.toml` as a `[[bin]]` *and* in the `TARGETS` array in `.github/workflows/coverage-fuzz.yml:199`; both lists are 42 entries today, nothing cross-checks them, and the manual-dispatch budget is `450 * 60 / N_TARGETS` so adding one shortens every target's run slightly. Build with `tools/cargo-in-container.sh`; the fuzz crate needs the pinned nightly. |
| 16g | medium | sonnet | none | Harness, docs and changelog. Bring `tools/mutate-differencing.sh` up to date for everything the preceding steps added: `EXPECTED_CASES` is 102 today and is cross-checked against prose figures by `check_case_count`, with each search string pinned to exactly one landing site by `check_pattern` — run `--check-patterns` and `--self-test` and keep every new case PASS or a documented SURVIVOR, never BROKEN. Restore mutations from a copy, never with `git checkout <dir>`. Then `docs/testing.md`: the case count and its per-group figures (the bold-digit idiom signals machine-checked), the new fixtures and what each one is for, the oracle's new data role and the one pinned exception, and the new fuzz target in the target list. `CHANGELOG.md` gets entries for the new fixtures, the oracle cross-validation and the fuzz target — all under test and tooling, since no user-visible behaviour changes in this phase. Do not touch `AGENTS.md` (no convention changes) or `ARCHITECTURE.md` (no component or data-path changes). Do not pre-empt phase 17: the read-side rows of `docs/format-coverage.md` and the two chain pages are its work, and a half-update here would be worse than none. |

## Risks and mitigations

* **The oracle becomes a mandatory CI dependency, and a packaging
  change can turn the suite red for a reason unrelated to instar.**
  Decision 1 accepts that deliberately — the alternative is a skip
  nobody notices. *Mitigation*: the hard failure is tied to the
  existing `INSTAR_REQUIRE_LIBVHDI` variable rather than a new one, so
  there is one switch and one place to look; and the skip message
  names the package to install, as `_require_vhdiinfo` already does.
  If Debian ever drops `python3-libvhdi`, the failure says so.

* **16b may find libvhdi cannot read what instar writes.** The padded
  differencing BAT (#623) is instar's own interpretation of the spec
  and nothing third-party has read one. *Mitigation*: the step's brief
  makes the measurement the deliverable either way, with a documented
  exception in decision 2's shape and a new defect letter in the
  oracle docstring if the fault is libvhdi's. If instead the fault is
  *ours*, that is a defect found by exactly the cross-validation this
  phase exists to add, and it should be filed and fixed rather than
  absorbed into a test that avoids it.

* **16d's fixtures are the expensive, blocking part.** Two new
  generators, four new files, a second repository, and a bitmap-byte
  constraint that is easy to violate and whose symptom looks like an
  instar bug. *Mitigation*: the constraint is stated in the brief with
  the measured reason; the generator already carries the identity
  patching the grandchild needs twice; and 16a lands first so that the
  oracle is available to check the new fixtures as they are built
  rather than afterwards.

* **A test phase can grow without bound.** Every one of these steps
  could be twice as large. *Mitigation*: each closes a numbered issue
  or a named gap from the master plan, and the definition of done
  states a figure for each rather than "coverage improved". The two
  issues phase 15 handed over are the scope, not a starting point.

* **The fuzz harness change touches all 42 existing targets.**
  *Mitigation*: default behaviour is unchanged by construction
  (decision 4), and the step is accepted only once a second existing
  target has been built and run briefly to confirm it still reaches
  its usual coverage.

* **The repository's standing warning.** Agents in this project assert
  plausible-but-wrong tool and format capabilities — three times in one
  phase, which is why `qemu_capability_claims_sourcing_rule` exists.
  Every claim in this phase about what libvhdi, qemu-img or the
  generator can do must come from running it. This plan's survey
  measured each of the ones it relies on, including by extracting a
  `.deb` to see which binaries it actually contains.

## Definition of done

* `python3-libvhdi` is in `src/.devcontainer/Dockerfile` and
  `tests/base.py` fails rather than skips when
  `INSTAR_REQUIRE_LIBVHDI=1` and the module is absent. Falsifiable:
  temporarily rename the module in a built container, run the oracle
  class with the variable set, and get a failure that names the
  package.
* For every real differencing chain in `instar-testdata`, three
  readers agree on the composition byte for byte — the recorded
  golden, `instar convert -O raw`, and libvhdi via `set_parent` — with
  exactly one exception in the tree, pinned to sector 2 of
  `vhd-diff-child-mixed` and asserted positively. Falsifiable: a test
  that fails if that sector agrees, and a `grep -c` of the exception
  returning 1.
* A child instar created with `create -b` composes to exactly the
  parent's own content under all three readers, for both formats, and
  the commit message records whether libvhdi accepted instar's
  differencing VHDX BAT padding.
* `instar-testdata` holds `vhdx-differencing`, and
  `PARENTLESS_DIFFERENCING_FIXTURES` has two entries rather than one.
  Falsifiable: the VHDX empty-chain refusal is asserted at the CLI for
  `convert`, `compare` and `bench`, and #635 is closed by the commit
  that does it.
* `instar convert -O raw` over a three-level all-differencing chain
  equals its recorded golden, for both formats, and the goldens were
  not produced by instar. Falsifiable: `generated_by` in
  `tests/manifest.json` names the generator for each, and a mutation
  that stops the reader descending past the first parent fails the new
  test.
* `grep -c 'build_vhdx_image\(4096\|build_vhdx_image_blocks(4096'
  src/crates/qcow2/src/lib.rs` is at least 6, and at least one 4K case
  asserts an allocation count or an extent offset rather than a
  refusal — so a walk that miscounts chunk groups at the larger ratio
  fails something. The 512-byte equivalent of that case is
  `vhdx_scan_counts_a_block_in_each_chunk_group`.
* `fuzz_chain_compose` exists, appears in both
  `src/fuzz/Cargo.toml` and `.github/workflows/coverage-fuzz.yml`, and
  runs for 60 seconds without a crash. Falsifiable:
  `tools/ci/count-fuzz-targets.sh` returns 43 and the workflow's
  `TARGETS` array has 43 entries.
* The compose fuzz target reaches compose code, not just the
  constructor. Falsifiable: a 300-second run reports non-zero region
  coverage on `read_chain_virtual_cluster` — the same bar
  `fuzz_vhdx_parent`'s docstring sets for itself, and the reason it
  exists as a separate target.
* `tools/mutate-differencing.sh --check-patterns` reports every
  pattern landing, `--self-test` passes, `EXPECTED_CASES` has grown,
  and `docs/testing.md` agrees with the script's own figures rather
  than with a hand-maintained number.
* `make test-rust` passes with zero failures and the count is stated,
  against the 2474 phase 15 measured.
* `pre-commit run --all-files` is clean, and the full integration
  suite passes with `INSTAR_REQUIRE_LIBVHDI=1` set.
* Nothing this phase adds cites a plan file, phase, step or decision
  number, and no user-visible string contains `PLAN-`:

  ```
  git diff f14554cf..HEAD -- 'src/*' 'tests/*' 'tools/*' 'scripts/*' \
    | grep '^+' \
    | grep -iE 'PLAN-[a-z0-9-]+\.md|decision [0-9]|phase 1[0-9]|\b16[a-g]\b'
  ```

  is empty. `docs/plans/` is out of scope — plan files cite each other
  by design. Note that this is a diff-scoped check by necessity: the
  repository has around 58 files carrying such references already,
  `tests/test_create.py:436` among them, and sweeping them is a
  separate job (the fleet's `plan-references-in-code` block).

## Back brief

Before implementation starts, confirm:

1. **Decision 1, before 16a.** Making the Python binding a hard CI
   requirement adds a Debian package to the critical path of every
   integration run. It is the cheapest honest option and it is still a
   new dependency; if it should instead be a soft skip, say so now,
   because 16a and 16b are both written against a hard requirement and
   the definition of done asserts it.

2. **Decision 2, and the shape of the exception.** Pinning a known
   upstream defect into a test is a deliberate trade: the test knows
   something that is true of libvhdi 20240509 and may not be true of
   the next release. The alternative readings are argued in the
   decision; if the preference is to skip the fixture instead, 16a
   shrinks and the VHD reader loses its only mixed-ownership
   cross-check.

3. **Scope of #631 against its cost.** 16d is the largest step and the
   only one needing a second repository. It is in scope because phase
   15 handed it over explicitly and because a two-level-only test
   cannot catch a reader that stops descending. If it should be
   deferred to a fixtures phase of its own, that is a defensible call
   and it should be made before 16a rather than after, since 16a's
   three-way comparison is written to extend over the grandchildren.

4. **Step order.** 16a first — 16b, 16d and the definition of done all
   depend on the oracle existing. 16c is independent. 16e and 16f
   touch no fixture and can run at any point. 16g last by
   construction.

5. **Model and effort.** 16a, 16b, 16d and 16f are opus at high
   effort: three of them measure external tools whose behaviour is not
   documented anywhere we control, and the fourth changes a harness 42
   targets share. 16c and 16e are sonnet at medium with the briefs
   above. 16g is sonnet at medium rather than low, because the
   mutation harness's case accounting has drifted before. No step
   wants `fable`.

6. **The standing warning, restated for this phase.** Measure, do not
   reason, about what libvhdi can read and what the generator can
   author. The survey for this plan corrected two tooling claims in
   the master plan by extracting a package and by running `qemu-img
   create -o help`; both looked obviously true until they were
   checked.
