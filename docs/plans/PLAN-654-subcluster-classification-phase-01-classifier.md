# PLAN-654 phase 1: one subcluster classifier

Master plan: [PLAN-654-subcluster-classification.md](PLAN-654-subcluster-classification.md).
Read its Situation, Decisions D1-D6 and Open questions first. This
file assumes them.

Planning effort: high. The phase changes the read path that every
qcow2 input goes through, and it reverses a documented policy (D2).

## Scope

In:

* a pure, `no_std` classifier in `src/crates/qcow2` implementing
  qemu's seven subcluster types, including the data-file rule (D1, D3);
* `cluster_lookup` and the chain reader's narrow, wide and `Standard`
  arms rebuilt on it, with `INVALID` refused (D2), and the silent
  bitmap-read fallback removed (open question 3);
* map, measure and check moved onto the same classifier (D5);
* tests by construction (D6), and documentation.

Out: the data device's place in the chain (#792, phase 2), write
paths (unless step 1a finds one that interprets host offset 0 on an
entry it did not validate itself), and fuzz-target changes (see the
master plan's Future work).

Closes #653 and #654. Fixes rows C and D of the master plan's
measurements for read, map, measure and check.

## Steps

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1a | high | opus | none | **Pin qemu's behaviour and build the fixtures; no Rust changes.** (1) Write `tests/helpers/qcow2_subclusters.py`: builders that return paths to small qcow2 images of each shape in the master plan's table and of each of qemu's seven subcluster types, crossed with {no backing, raw backing filled with a known non-zero byte} × {no data file, data file} × {extended L2 off, on} where the combination is meaningful. Build well-formed shapes with `qemu-img create` and `qemu-io -c 'write -P …' / 'write -z …'`, never by hand. Build `INVALID` shapes by patching the L2 entry or bitmap of a qemu-built image with `struct`. Locate the L2 table from the header the way the master plan's measurement did (L1 offset at header byte 40, L2 offset = L1 entry & `0x00fffffffffffe00`, extended entries 16 bytes each). Each builder also returns the expected *ownership*: for each subcluster, which device its bytes should come from (child, data file, backing, zero) or `refuse`. That is what step 1e asserts against. (2) For every fixture, run `qemu-img convert -O raw`, `qemu-img map --output=json`, `qemu-img check` and `qemu-img measure -O qcow2`, and record the results as a table in this file under "Step 1a measurements": exit code, whether the converted bytes match the expected ownership, and qemu's map entries. Settle by measurement, not by reading: does `qemu-img check` report an entry with a non-zero host offset and a zero bitmap (instar's `HostWithoutRef`, `src/crates/qcow2/src/lib.rs:1420-1424`)? Does it report alloc-and-zero overlap, or a compressed entry with a non-zero bitmap? (3) Answer the master plan's open question 2: list every write path (`src/crates/snapshot`, `commit`, `rebase`, `resize`, `qcow2-write`, `src/operations/bench`) that can read an extended-L2 entry, cite where it refuses external data files, and say whether any interprets host offset 0 on an entry it did not validate itself. Record the answer here. Use the host `qemu-img` (10.0.13). If a finding depends on qemu version, say so and do not generalise. |
| 1b | high | opus | none | **The classifier.** In `src/crates/qcow2/src/lib.rs`, beside `ClusterLookup` (`:1379`), add `pub enum SubclusterType { Normal, ZeroAlloc, ZeroPlain, UnallocatedAlloc, UnallocatedPlain, Compressed, Invalid }` and `pub fn subcluster_type(l2_entry: u64, bitmap: u64, sc_index: u32, extended_l2: bool, has_data_file: bool) -> SubclusterType`. It transcribes `qcow2_get_cluster_type` and `qcow2_get_subcluster_type` from qemu v10.0.0 `block/qcow2.h:713-796` (fetch the file; do not work from memory) and cites those lines in its doc comment. Note that qemu's `INVALID` checks the *whole* entry and bitmap, not just the bits for `sc_index`. Add a range form, `subcluster_range(…, sc_from) -> (SubclusterType, u32 run_len)`, in the shape of `qcow2_get_subcluster_range_type` (`block/qcow2-cluster.c:395-429`), for run coalescing. Then change `Qcow2State::cluster_lookup` (`:2207-2322`): derive `has_data_file` from `self.incompatible_features & INCOMPAT_EXTERNAL_DATA`; add `ClusterLookup::Invalid`; return `Standard(h)` only when every subcluster is `Normal`, `Zero` when every one is a zero type, `Unallocated` when every one is unallocated, `Invalid` for an invalid entry, and `StandardSubclusters` only for a genuinely mixed bitmap. `Standard(0)` must now be possible only for a data-file image. Replace the bitmap read's `.unwrap_or(0)` (`:2279`) with `?`, so a failed read is a failed lookup. Unit tests: one per row of qemu's table, citing the qemu line; the #653 entry shape both with and without a data file; the row C entry (`0x8000000000000000`, bitmap `0x3`, data file), which qemu's table makes `Normal` for subclusters 0-1 and `UnallocatedAlloc` for 2-31, and `Invalid` without the data file. Keep it `no_std`; no allocation. Update `validate_subcluster_bitmap`'s doc comment to point at the classifier, but leave its callers to step 1d. Run `cargo test -p qcow2` with every feature the guest ops enable, through the build-and-test skill's Make targets. |
| 1c | xhigh | fable | worktree | **The chain reader.** Rebuild the `StandardSubclusters` arm of `read_chain_virtual_cluster` (`src/crates/qcow2/src/lib.rs:13279-13545`) on `subcluster_range` so the narrow and wide paths share one per-run decision: `Normal` reads from `data_device_idx` if set, else the device itself, at `host + offset` (host 0 is now legitimate, D3); `ZeroAlloc`/`ZeroPlain` zero-fill; `UnallocatedAlloc`/`UnallocatedPlain` descend through `devices_behind`, which already zero-fills at the bottom of the chain. Delete both `is_zero \|\| (!is_alloc && host_offset == 0)` conditions (`:13319`, `:13495`) and both "defensive" zero-fills (`:13394-13402`, `:13530-13540`). Keep the wide path's single chunk read for the `Normal` runs, the AES-CBC and LUKS-XTS decryption with their existing IV rules, and the narrow path's run coalescing. Handle `ClusterLookup::Invalid` by refusing. Resolve the master plan's open question 1 first: read how `send_differencing_refusal` (`:15160`) and `shared::DifferencingRefusal` (`src/shared/src/lib.rs:3115-3135`) reach the VMM and get rendered, and add the equivalent for an invalid qcow2 entry, with its renderer in the VMM and a message that names qemu's wording ("Invalid cluster entry found") and the virtual offset. Keep the reader's `bool` contract for its roughly ten callers. Crate tests: extend the #650 in-memory harness (`:5462` onward, `W650_*`) to a two-device chain whose backing device serves a known non-zero byte, plus a data-device variant. For each subcluster type, for the narrow arm (sector 256 or 512 against a subcluster of at least that size) and the wide arm (sector larger than the subcluster), assert where every byte comes from. Include #654's measured case (bitmap with only subcluster 0's zero bit set: subclusters 1-31 must be the backing byte), #653's case (refused without a data file, read from the data device with one), and row C. Run the full `cargo test -p qcow2`, then `make instar` and `make check-binary-sizes`: the classifier is linked into every guest op, which has a 768KB cap. Then re-run the master plan's measurements A-D on the built binary and paste the results here. |
| 1d | high | opus | none | **map, measure and check onto the classifier.** `classify_qcow2_l2_standard` (`lib.rs:1754`), `classify_qcow2_l2_extended` (`:1826`) and `count_allocated_in_l2_extended` (`:1675`) take `has_data_file` and classify through `subcluster_type`/`subcluster_range`. Follow their callers up to the map and measure ops and thread the flag through from the header. Map must report row C's and row D's cluster 0 as data at offset 0, as `qemu-img map` does. Measure must count it. For check (`src/operations/check/src/main.rs:2860-2935`): report the classifier's `Invalid` as the bitmap error it reports today, stop reporting row C as `AllocWithoutHost`, and make `HostWithoutRef`, alloc-and-zero overlap and compressed-with-bitmap follow step 1a's `qemu-img check` measurements. `validate_subcluster_bitmap` either becomes a thin wrapper over the classifier or is removed: do not leave two definitions of validity. Preserve check's existing error counts and wording for every shape qemu also reports, so the existing `tests/test_check_*.py` expectations keep passing unless step 1a showed they were wrong. If they were, change the test and say why in the commit. |
| 1e | medium | opus | none | **Integration tests.** Add `tests/test_qcow2_subclusters.py`, driven by step 1a's builders. For each fixture, run instar and qemu-img side by side: `convert -O raw` and compare bytes against both qemu's output and the builder's expected ownership; `compare` between the two outputs; `map --output json` against qemu's; `check` exit code and error class against qemu's; `measure` against qemu's. For `INVALID` fixtures, assert that instar refuses with the step 1c message and a non-zero exit, and that qemu-img also fails. Follow `tests/base.py` conventions and skip cleanly, with a stated reason, when `qemu-img` is missing, using `_require_qemu_img` from `tests/base.py:473`. `integration-core` is exclusion-based and will pick up a new module automatically, but run `tools/ci/check-test-partition.py` to confirm both partitions claim it. If the module is slow, add it to `tests/stestr-timing.txt` per that file's convention. Run the new module and the existing `test_convert`, `test_map`, `test_measure`, `test_check_formats`, `test_check_chain` and `test_compare` modules. All must pass at 0 failures; check "Ran: N" against the expected count, because a crashed stestr worker can exit 0. |
| 1f | low | sonnet | none | **Documentation.** Replace the `docs/quirks.md` entry "Malformed qcow2 subcluster: instar zero-fills where qemu-img errors" (`:4848` onward) with one that says instar now refuses what qemu calls an invalid entry, with the same message class, and keep a sentence on why (row C showed the zero-fill premise was wrong). Add `CHANGELOG.md` entries under the unreleased section: **Fixed**: extended-L2 reads that ignored the backing file (#654); a crafted entry that served the image header as data (#653); data-file images whose cluster 0 read as zeros, mapped as a hole, measured short, or failed `check`. **Changed**: invalid extended-L2 entries are now refused rather than zero-filled. Add a short subsection to `docs/qcow2/qcow2-format.md` on subcluster types that names the classifier as the single place they are decided and links to qemu's definition. Do not touch `AGENTS.md`, `ARCHITECTURE.md` or `README.md`: no convention or system shape changes. |

Commits: one per step, each passing `pre-commit run --all-files`
(`git add` new files first: pre-commit cannot see untracked files).
Step 1a's commit carries the fixture helper and the measurement table.
Step 1c's runs in a worktree because it is the riskiest change; review
its diff against the brief before merging it back.

## Step 1a measurements

To be filled in by step 1a.

## Success criteria for the phase

* Measurements A to D from the master plan give qemu's answer on the
  built binary, for read, map, measure and check.
* Every `INVALID` fixture is refused, with the named message, by every
  read operation that reaches it.
* No consumer outside the classifier tests host offset 0 on an L2
  entry: `grep -n "host_offset == 0" src/crates/qcow2/src/lib.rs`
  returns only the classifier and its tests, plus any line that step 1a
  records as a write path that is out of scope.
* `make instar`, `make lint`, `make check-binary-sizes`,
  `make test-rust` and the integration modules named in step 1e pass.
