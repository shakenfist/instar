# Phase 3: read side, lift the extent ceiling

## Status: Planned

Part of [PLAN-multi-extent-vmdk.md](PLAN-multi-extent-vmdk.md). Planned
at high effort, as that plan's *Planning effort* section requires for
the rotation and ABI phases.

## Scope

In scope:

* Remove the device-slot ceiling for a VMDK descriptor's extents, so a
  descriptor with any extent count up to the new documented bound is
  readable.
* Add `twoGbMaxExtentSparse` as a readable input.
* Read each extent's declared sector count rather than inferring 2 GiB
  from the create type.
* Retire the four over-deep-chain guards for the extent case, and make
  `DeviceSet::add_device`'s assert unreachable by construction for
  extents rather than by a caller remembering to check.
* Make the virtqueue-region compile-time assert derive from
  `MAX_CHAIN_DEVICES` instead of a hard-coded `16`
  ([#934](https://github.com/shakenfist/instar/issues/934)).
* Fix the chain printer's allocation figure
  ([#927](https://github.com/shakenfist/instar/issues/927)), which is
  the last unfixed member of #922's class and lands in this phase
  because this is the phase that touches the chain walk's extent
  handling.
* Un-flag the five `instar_unsupported` fixtures and give them live
  baseline comparisons.

Out of scope, and why:

* **The whole write path.** Phases 4 to 11 own it. Nothing here emits a
  descriptor or an extent.
* **`twoGbMaxExtent*` as a backing file or inside a backing chain.**
  Excluded by the master plan's scope. A split image is readable as the
  top image here; a split image *with a parent* stays refused.
* **`instar map` on flat sources**, refused today for every flat source
  and wider than this plan. Recorded in the master plan's Future work.
* **The oracle hardening in
  [#928](https://github.com/shakenfist/instar/issues/928).** Items 1 and
  2 there are latent until a chain baseline exists; this phase creates
  none. Item 3 is consumed by step 3f, which is a different change from
  the one #928 proposes, so #928 stays open for items 1 and 2.

## What the survey found

The master plan's phase 3 intent was written before phases 1 and 2 ran.
Six of its claims needed correcting, and the corrections are made at
source in the master plan and `index.md` as part of this phase's
registration commit, so a later reader does not trip over them.

**1. The line reference is stale.** The intent cites "the guard at
`src/vmm/src/main.rs:15088` and its siblings". That line now holds
sector-size validation. There are **four** guards, not one and some
unspecified siblings:

| Operation | Line | What it bounds |
|---|---|---|
| bench | `src/vmm/src/main.rs:6719` | the chain's own device count |
| check | `:13573` | the chain's own device count |
| compare | `:14405` | both inputs' chains combined |
| convert | `:15462` | input chain plus the output device |

**2. The real ceiling is a guest memory map, not `MAX_CHAIN_DEPTH`.**
The binding constraint is in `src/shared/src/lib.rs`: `VQ_BASE_START`
is `0x00100000` (line 637), `DMA_POOL_BASE` is `0x00200000` (641), and
a device's virtqueue takes 64 KiB (636). One mebibyte at 64 KiB each is
exactly sixteen devices, and a seventeenth would land on the DMA pool.
Four constants encode that 16 independently:

| Constant | Location |
|---|---|
| `MAX_CHAIN_DEPTH` | `src/vmm/src/main.rs:412` |
| `max_chain_depth` default | `src/vmm/src/config.rs:251` |
| `MAX_INPUT_DEVICES` | `src/core/src/main.rs:49` |
| `MAX_CHAIN_DEVICES` | `src/shared/src/lib.rs:5186` |

`MAX_INPUT_DEVICES` covers input and output slots together
(`src/core/src/main.rs:210-213`), which is where the intent's
"15-extent limit" comes from: an operation holding an output device has
fifteen slots left.

**3. The compile-time guard hard-codes its own 16.**
`src/shared/src/lib.rs:664` asserts
`VQ_BASE_START + 16 * 0x10000 <= DMA_POOL_BASE` with a literal rather
than with `MAX_CHAIN_DEVICES`, so raising the constant does not trip it
and the two silently disagree. Filed as #934 and fixed in step 3a.

**4. One extent already costs one device slot, by design.** The intent
reads as though extents were unsupported past a limit. In fact the host
attaches the descriptor as device 0 and each extent as its own marked
data device, and the guest's reader walks them as the descriptor's
content -- `src/crates/qcow2/src/lib.rs:15841`, with
`vmdk_descriptor_reads_each_of_its_extents` and
`vmdk_descriptor_extent_walk_stops_at_its_last_extent`. This phase
replaces a working, tested mechanism rather than filling a void, which
raises what the definition of done has to prove.

**5. A second refusal the intent does not mention.** Alongside the
non-`FLAT` refusal at `src/vmm/src/chain.rs:960`, a non-zero
`offset_sectors` is refused at `:967`. qemu's split subformats give each
extent its own file at offset 0, so lifting that one is not required
here; it stays refused and is noted in the master plan's Future work.

**6. "Inherits a VMM that already sums extent allocations" is half
true.** Phase 2 fixed the non-chain `info` paths. The chain walk still
reports the descriptor's own apparent length at
`src/vmm/src/main.rs:3809`. Measured against qemu-img 10.2.0 on
`vmdk-flat-with-parent.vmdk`: qemu reports 1052672 for both chain
members, instar reports 368. Filed as #927 during phase 2's review and
pulled into this phase's scope.

One further fact the intent could not have known, because phase 2
created it: **all five** `instar_unsupported` images in
`tests/manifest.json` are the split-sparse fixtures this phase makes
readable. Phase 2 added
`TestInstarUnsupportedIsStillUnsupported`, which asserts the field is
set on at least one image. When this phase succeeds, that assertion
fails. That is the test working as designed, and step 3f owns the
consequence.

## Decisions

1. **Host-side concatenation with a guest-visible extent table, not
   device-slot rotation.** `BackingStore`
   (`src/vmm/src/backing.rs:15`) holds exactly one `File` today. It
   gains an ordered list of extent files and routes a device offset to
   the file that owns it, so a descriptor and all its extents occupy
   **one** device slot whatever the extent count. `ChainConfig` goes to
   version 5 carrying the extent table, so the guest can still find and
   parse each sparse extent's own header at a computed device offset.

   The master plan's open question 1 resolved to rotation, and this
   departs from it for the read path with the operator's agreement
   (2026-11-19). The reasoning the resolution did not have: there is no
   guest-to-host request channel in this architecture at all. The host
   writes `CHAIN_CONFIG_ADDR` before the guest starts and the guest does
   I/O through virtio; rotation would require inventing a channel for
   the guest to say "bind extent k" and block until it was done, which
   is ABI work the master plan scoped to phase 6. Concatenation needs no
   new channel, because a virtio request already carries the offset the
   guest wants.

   This is the decision most likely to be argued with, on the ground
   that the read side was meant to rehearse the mechanism the write side
   would reuse. It no longer does. The honest position is that the
   rehearsal argument assumed the mechanism had to live at the
   device-slot level, and for reads it does not; whether the write path
   can also route host-side is a real question, but it is phases 6 to 8's
   to answer, and this phase does not prejudge it. Recorded in the master
   plan's open question 1 so the change of mechanism is visible there
   rather than only here.

2. **Concatenation alone is not enough, and the plan says so plainly.**
   For `FLAT` extents the extents are a plain concatenation and the
   guest needs nothing new. For `twoGbMaxExtentSparse` each extent
   carries its own header, grain directory and grain tables covering
   only its own span, so concatenated sparse bytes are not a valid
   image. The extent table is what makes sparse work: the guest resolves
   a virtual offset to an extent, then to that extent's own metadata at
   its own base. Any design that concatenates without telling the guest
   the boundaries reads sparse images wrongly, and would do it
   silently.

3. **The extent table carries three `u64`s and a kind per extent**: the
   device offset where the extent's bytes begin, the extent file's
   length, the extent's virtual span in bytes, and whether that file is
   flat or sparse. The span cannot be derived from the length, because a
   sparse extent's file is shorter than its span and phase 2 measured a
   real image declaring 3.96 GiB extents under `twoGbMaxExtentSparse`.
   Reading the declared sector count rather than assuming 2 GiB is
   therefore not a refinement, it is the only thing that works.

   **Amended 2026-11-19 by step 3c.** Three `u64`s cannot say whether an
   extent is flat or sparse, and a guest left to work it out has to
   guess from the bytes. Looking for a sparse header would read a flat
   extent whose first sector happens to hold one as sparse; comparing
   the file's length with its span would read a sparse extent padded out
   to its span as flat. Either way one file means different bytes to
   instar than to qemu, which believes the type on the descriptor's
   extent line -- a line only the host has read. So the host states it:
   `ChainExtent::kind` is `KIND_FLAT` or `KIND_SPARSE`, and zero, the
   value a writer that never set it leaves behind, is refused rather
   than read as either.

4. **`MAX_CHAIN_EXTENTS = 64`, and the refusal above it is
   documented.** `ChainConfig` lives at `CHAIN_CONFIG_ADDR`
   (`0x000F2000`) and the next region, `VMM_PARAMS_ADDR`, begins at
   `0x000F3000`, so the whole structure must fit in 4096 bytes. At 32
   bytes per entry -- 24 as first planned, plus the kind decision 3 now
   carries -- 64 extents costs 2048 bytes, which the page has room for;
   step 3a proves it with a free-standing `const _: () = assert!(..)` on
   `size_of::<ChainConfig>()` rather than by arithmetic in this plan.
   Sixty-four extents is 128 GiB at qemu's 2 GiB default and covers both
   corpus images (17 and 26 extents). qemu has no such limit, so this is
   a divergence: it is refused with a message naming the bound, recorded
   in the master plan's Future work, and lifting it means moving the
   config region rather than changing a constant.

5. **The guest's per-device extent walk is removed, not left
   alongside.** Keeping both paths would mean two ways to read the same
   image and a silent dependence on which one the host chose. The two
   tests at `src/crates/qcow2/src/lib.rs:15941` and `:15982` are
   rewritten against the extent table rather than deleted, because what
   they assert -- that a read past the last extent stops and returns
   zeros instead of taking the next device -- is still the contract.

6. **This phase does not raise any of the four 16s.** The ceiling stops
   applying to extents because extents stop consuming slots. Backing
   *chain* depth stays bounded at 16 and the four guards keep bounding
   it; what changes is that a descriptor's extents no longer count
   toward it. Raising the slot count is a separate change with a guest
   memory-map cost, and #934 records what it would involve.

7. **One live sparse-extent parser state at a time, not one per
   extent.** The guest keeps a format state per *device*:
   `chain_states.vmdk_states[dev_idx]`, and each device's grain
   directory and grain table caches come from
   `shared::l1_cache_addr`/`l2_cache_addr`, which hand out
   `2 * MAX_SECTOR_SIZE` -- 128 KiB -- per device slot from a region
   sized `2 * MAX_SECTOR_SIZE * MAX_CHAIN_DEVICES`, or 2 MiB in total.
   After step 3b a descriptor and all its extents are one device, so a
   state per extent would want 64 slots and 8 MiB of cache, which does
   not exist and cannot be made to exist inside the guest's memory map.

   So the descriptor device holds one `VmdkState` at a time, re-read
   when a read moves into a different extent, reusing that device's
   single pair of cache buffers. Sequential access pays for this once
   per extent boundary; a seeking workload pays per crossing, which is
   the honest cost and is bounded by a header read plus a grain
   directory read.

   Two consequences the implementer must not have to discover.
   `VmdkState::init` assumes its image begins at device offset 0, so it
   needs the extent's base offset -- everything it reads, header, grain
   directory and grain tables, is relative to that base. And the
   rotation this plan removed from the device slots reappears here, in
   the parser state. That is worth saying plainly: the master plan's
   instinct that this phase would rehearse a rotation was not wrong,
   only wrong about which layer rotates.

8. **Each extent file's place in the device is the running total of the
   lengths before it, rounded up to 512** (added 2026-11-19 by step 3d).
   The plan said the extent table's `device_offset` is where the
   extent's bytes begin and left the placement to the implementer, and
   those two things turned out to conflict: the reader requires a sparse
   extent's base to be a multiple of 512, because sparse VMDK counts
   512-byte sectors from the start of its own file, while a real extent
   file's length is whatever it is. Rounding every extent's contribution
   up to 512, unconditionally, satisfies that for every extent without
   the placement depending on what the *next* entry is -- the
   alternative, padding only before a sparse extent, makes one extent's
   address depend on its neighbour's kind, which is the kind of rule
   that is correct when written and wrong after an edit.

   The table still carries the file's own length, not the rounded one,
   so up to 511 bytes between two extents belong to neither. Nothing
   addresses them: a flat read stops at `file_length` and zero-fills the
   rest of the span, a sparse read stays inside its own file, and the
   backing store returns zeros for a member's declared length past the
   end of its file. The host test that pins this gives the first extent
   a 1000-byte file and asserts that reading at offset 1000 returns
   zeros rather than the second file's first bytes.

9. **`vmdk::MAX_EXTENTS` is the extent table's size, not a number of
   its own** (added 2026-11-19 in review of step 3d). The descriptor
   parser had its own cap of 32, justified in a comment that said
   twoGbMaxExtentFlat "caps at ~1TB/2GB extents per file so this limit
   comfortably covers any legitimate descriptor". That arithmetic is
   wrong -- 32 extents of 2 GiB is 64 GiB -- and it did not matter
   before this phase, because the 16-device ceiling refused such an
   image first. Lifting that ceiling promoted the parser's cap from
   dead to live, and would have shipped a phase that documents 64 and
   refuses at 33.

   So `MAX_EXTENTS` is now defined as `shared::MAX_CHAIN_EXTENTS`. The
   two bound the same thing, the smaller is what a user meets, and a
   constant defined in terms of the other cannot drift from it. It costs
   nothing measurable: the guest binaries are byte-identical, because
   the descriptor parser's array is transient rather than static. The
   corpus image that forced the question is 100 GiB in 26 extents of
   3.96 GiB; written with qemu's 2 GiB default the same image needs 50.

## Step plan

Steps run in sequence except where noted. 3a must land before 3b, 3c
and 3d, because all three consume the ABI it defines.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 3a | high | opus | none | Define the extent-table ABI in `src/shared/src/lib.rs`. Add `pub const MAX_CHAIN_EXTENTS: usize = 64;` and a `#[repr(C)] pub struct ChainExtent { pub device_offset: u64, pub file_length: u64, pub virtual_span: u64 }` with a `const fn new()` returning zeros, mirroring `ChainSegment` at line 5219. Add to `ChainConfig` (line 5391): `pub extent_count: u32`, and `pub extents: [ChainExtent; MAX_CHAIN_EXTENTS]`. Bump `ChainConfig::version` to 5 and extend the version comment at line 5422 in the established style. Per-descriptor ownership: add `pub first_extent: u32` and `pub extent_count: u32` to `ChainDeviceInfo` (line 5274), so a device names its slice of the table; document that both are zero for a device with no extents. Two asserts matter: change line 664's `VQ_BASE_START + 16 * 0x10000 <= DMA_POOL_BASE` to use `MAX_CHAIN_DEVICES` instead of the literal (this is #934), and add a new compile-time assert that `core::mem::size_of::<ChainConfig>()` is at most `VMM_PARAMS_ADDR - CHAIN_CONFIG_ADDR`, with a message saying the chain config must fit its page. The idiom in this file is a free-standing `const _: () = assert!(..)`, as at lines 650 and 656; there is no `const_assert!` macro in this codebase. This crate is `no_std` and is linked into the guest, so run `scripts/check-binary-sizes.sh` and report the before and after numbers. Do not change any consumer yet; the build must still pass with the new fields unread. |
| 3b | high | opus | worktree | Give `BackingStore` (`src/vmm/src/backing.rs:15`) the ability to span several files. It holds one `File` plus `capacity`, `current_size` and `sparse`. Add a constructor that takes an ordered `Vec` of (path, length) and keeps a `Vec<File>` with a running offset table, and route `read_at`/`write_at` to the file owning the offset, splitting a request that straddles a boundary into one call per file so every byte of the caller's buffer is filled. The single-file path must keep its exact current behaviour, including the zero-padding of reads past the file end that `src/vmm/src/virtio/block.rs:141` relies on; the cleanest shape is an internal enum with a `Single` and a `Concatenated` variant rather than a `Vec` of length one, so the common path keeps its current code. Every device in the VMM goes through this type, so this is the step where a mistake is widest: add unit tests in the file's existing `mod tests` style for a straddling read, a read entirely past the end, a boundary-aligned read, and a two-file store whose second file is shorter than its declared length. Read-only is the only mode this phase needs; make the multi-file constructor refuse a writable request rather than leaving it half-implemented. |
| 3c | xhigh | fable | worktree | Teach the guest's reader to use the extent table from step 3a, and remove the per-device extent walk. Today a VMDK flat descriptor's extents arrive as separate marked data devices and the reader walks them; after this step the descriptor and all its extents are one device and the boundaries come from `ChainConfig::extents` with the slice named by `ChainDeviceInfo::first_extent`/`extent_count`. Resolve a virtual offset to an extent, then read within that extent at `device_offset + (virtual offset - extent base)`. For a SPARSE extent, parse that extent's own header, grain directory and grain tables at offsets relative to its `device_offset`, because each extent is a self-contained sparse VMDK covering only its own span -- this is the part that makes `twoGbMaxExtentSparse` readable and it is the hardest thing in the phase. A read past the last extent must still stop and return zeros rather than continue into whatever follows: rewrite the two tests at `src/crates/qcow2/src/lib.rs:15941` and `:15982` against the new mechanism, keeping what they assert. Keep honouring each extent's declared span, which the present walk already does by using each data device's `virtual_size`; after this step it comes from the extent table's `virtual_span` instead. Do not "fix" an assumption of 2 GiB on this path -- there is not one. One real corpus image declares 3.96 GiB extents. The crate is `no_std`, the guest binary cap is 768KB, and the reader frame budget noted at `src/crates/qcow2/src/lib.rs:16943` is about 10.7KB per device against a 4MB stack -- say in the report what your change does to frame size. Run the consumer operation suites, not only the crate tests. |
| 3d | high | opus | none | Wire the VMM side. In `src/vmm/src/chain.rs`, let `resolve_vmdk_flat_descriptor` accept SPARSE extents (the refusal is at line 960) while keeping the non-zero `offset_sectors` refusal at line 967, and carry each extent's declared sector count through `ResolvedVmdkDescriptor`. In `src/vmm/src/main.rs`, attach a descriptor and its extents as one device built on step 3b's concatenated backing store instead of one device per extent, populate step 3a's extent table, and refuse an extent count above `MAX_CHAIN_EXTENTS` with a message naming the bound. Extents no longer count toward chain depth, so the four guards at `:6719`, `:13573`, `:14405` and `:15462` must now bound only real chain members -- change what they count, do not delete them, and keep their comments true by rewriting them. `DeviceSet::add_device`'s assert at `:738` should become unreachable for extents by construction; say in the report why it now cannot fire rather than asserting that it cannot. Both corpus images must read: `vmdk-split-sparse-33g` (17 extents) and `osboxes-vmdk-split-sparse` (26 extents of 8304640 sectors). |
| 3e | medium | sonnet | none | Fix #927. `src/vmm/src/main.rs:3809` sets a chain member's `actual_size` to `std::fs::metadata(&current).map(|m| m.len())` -- the descriptor's apparent length, omitting every extent and ignoring `--ignore-quirks`. Make it the descriptor's allocation plus each resolved extent's, which is what `InfoDiskSizes::new` already computes for the non-chain paths (see its call site near `src/vmm/src/main.rs:2458` and the `--ignore-quirks` convention at `:2449`, where the flag means apparent length rather than `st_blocks * 512`). The resolved extents are in scope at that point; they are stored into `external_data_files` a few lines below. `ignore_quirks` is not currently threaded into the chain walk, so thread it. Verify against qemu-img 10.2.0 on `custom/format-coverage/vmdk-flat-with-parent.vmdk`, where `qemu-img info --backing-chain --output=json` reports 1052672 for both members and instar reports 368 before the fix. |
| 3f | medium | sonnet | none | Un-flag the fixtures and resolve what that empties. Remove `instar_unsupported` from all five entries in `tests/manifest.json` that carry it (`vmdk-split-sparse-2049m`, `-5g`, `-5g-boundary`, `-33g`, and `osboxes-vmdk-split-sparse`) and give each a description of what it now proves. That empties the field across all 222 images, which makes `TestInstarUnsupportedIsStillUnsupported` in `tests/test_info_safe.py` fail by design -- it asserts the field is set somewhere. Nothing else in the suite reads the field except the skip at `tests/test_info_safe.py:126` and `is_instar_unsupported` in `tests/base.py`. Since no image is unsupported any more, remove the field's handling and that test together rather than leaving a mechanism with no subject, and say so in the commit message; if you find a reason to keep the field, keep the test too and say why. Then add the positive assertions the fixtures now support: each of the five reads, reports the virtual size its manifest entry declares, and for `-5g-boundary` the 131072 bytes of `0xAB` at offset 2147418112 straddling the first extent boundary read back correctly. |
| 3g | medium | sonnet | none | Generate baselines in `instar-testdata` for the five newly supported fixtures, across the version matrix, and validate them. That repository takes direct commits to `main`, never a merge request, and is git-LFS backed; rebase before pushing because the fuzz automation moves `main` daily. Run `generate-baselines.py --no-commit`, then `make profiles`, then `make validate-profiles`, and do not trust the derived `profiles/` directories -- they have twice been silently wrong while `raw/` was fine. Report the file count per operation and per version. Leave the work uncommitted in the instar worktree; the testdata commit is the management session's to make. |
| 3h | medium | sonnet | none | Records. Add a `### Fixed` entry to `CHANGELOG.md` under `[Unreleased]` for reading multi-extent VMDK (both split subformats) and for #927, as two separate entries because they are two faults. Document the new readable subformat in `docs/format-coverage.md` and wherever `docs/` states the extent or device limit, including the `MAX_CHAIN_EXTENTS` bound and that qemu has no equivalent. Do not cite plan, phase or step numbers anywhere outside `docs/plans/`. |

### What step 3c hands step 3d

The reader is in place and the host does not yet feed it. These are the
constraints the reader now imposes, found while writing it, and they are
step 3d's to satisfy rather than to rediscover:

* every entry must state `kind`, `KIND_FLAT` or `KIND_SPARSE`, from the
  type on the descriptor's extent line. An entry left at zero is
  refused;
* a sparse extent's `device_offset` must be a multiple of 512. Sparse
  VMDK counts in 512-byte sectors from the start of its own file, so
  only then does each header and table entry sit whole inside one
  device sector;
* step 3b's `declared_len` for an extent must be the file's own length.
  A fully allocated sparse file is longer than its span, and a span
  would truncate it;
* `vmdk::MAX_EXTENTS` is 32, below `MAX_CHAIN_EXTENTS`, so the
  descriptor parser is the tighter bound today. Whichever bound refuses
  an image, the message must name the one that actually applied;
* `ChainConfig::data_devices_are_owned` still permits a descriptor to
  own a run of marked data devices. Nothing reads a descriptor that way
  any more, so that clause and the VMM test pinning it are vestigial and
  3d should remove them with the attachment code they describe;
* a descriptor's `virtual_size` must still be the sum of its extents'
  spans, and the device's capacity the sum of their file lengths: the
  reader bounds a flat read with the device capacity, not the extent's.

Two refusals the reader makes that qemu would not, both deliberate and
both needing a message that names the bound rather than a bare failure:
a compressed sparse extent (nothing can hold a compressed grain to its
extent's file, and qemu only compresses the single-file stream-optimised
subformat), and a sparse extent whose header capacity is not the span
the descriptor line declares (qemu takes the span from the header and
the host has only the line, so where they differ every later extent sits
at a different virtual offset for each reader).

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| `BackingStore` is on every device's I/O path, so a mistake in step 3b corrupts reads for every format, not just VMDK. | The internal-enum shape keeps the single-file path byte-identical, and step 3b's unit tests cover the straddling cases. The management session re-runs the full integration suite before committing 3b, not only the crate tests, and replays any `test_convert` failure at low concurrency before attributing it. |
| Step 3c is the hardest change in the phase and sits in a `no_std` crate linked into every operation. | It is the one step at xhigh on fable, it runs in a worktree so a bad outcome is discarded, and its brief names the stack-frame budget. The consumer suites run, not just the crate tests. |
| Concatenating sparse extents without the extent table would read wrongly and silently. | Decision 2 states it. The definition of done checks a read that straddles an extent boundary against a known byte pattern, which a boundary-blind implementation fails. |
| Removing the guest's per-device extent walk could regress `monolithicFlat`, which uses the same path and is not a split subformat. | `vmdk-flat-1m`, `vmdk-flat-10m` and `vmdk-multi-flat` have full baselines and are compared at every version; they must stay green. Their presence is why step 3c rewrites the two walk tests rather than deleting them. |
| Un-flagging the fixtures empties `instar_unsupported` and fails a test phase 2 added on purpose. | Step 3f owns it, and the definition of done records which way it went. This is a designed signal, not an accident. |
| The extent-table fields are added to a structure the guest reads, so a host and guest that disagree about the layout fail confusingly. | `ChainConfig` is versioned and step 3a bumps it to 5; the guest already rejects a config whose magic or version it does not know. |

## Definition of done

Falsifiable; each is checkable by someone who did not do the work.

1. `instar info` succeeds on `custom/format-coverage/vmdk-split-sparse-33g.vmdk` (17 extents) and on `osboxes-vmdk-split-sparse` (26 extents), and reports the virtual size each descriptor declares.
2. `instar info --output json` on `vmdk-split-sparse-33g.vmdk` reports the same `virtual-size` as `qemu-img info --output=json` from the pinned 10.2.0 build.
3. Reading offsets 2147418112 to 2147549184 of `vmdk-split-sparse-5g-boundary.vmdk` returns the 131072 bytes of `0xAB` the fixture places across the first extent boundary, proving the read crosses an extent rather than stopping or repeating.
4. A descriptor with more than `MAX_CHAIN_EXTENTS` extents is refused with a message naming the bound, and the refusal is reached by a test rather than by inspection.
5. `core::mem::size_of::<ChainConfig>()` is at most `VMM_PARAMS_ADDR - CHAIN_CONFIG_ADDR`, enforced by a compile-time assert that fails the build if it is not.
6. `src/shared/src/lib.rs`'s virtqueue-region assert refers to `MAX_CHAIN_DEVICES` rather than a literal `16`; setting `MAX_CHAIN_DEVICES` to 17 fails the build. Checked by making that edit, observing the failure, and restoring from a copy.
7. No device is attached per extent: a 26-extent image reads with a chain device count that does not grow with the extent count, and the report states the count observed.
8. `qemu-img info --backing-chain --output=json` and `instar info --chain --output json` agree on `actual-size` for every member of `vmdk-flat-with-parent.vmdk`, where instar reported 368 against qemu's 1052672 before the fix.
9. `tests/manifest.json` sets `instar_unsupported` on no image, and neither `tests/base.py` nor `tests/test_info_safe.py` still reads the field; or, if the field was kept, the commit message says why and the test still asserts it.
10. The two walk contracts still hold: a read past the last extent returns zeros and does not read the following device. Proved by the rewritten tests at `src/crates/qcow2/src/lib.rs`, and by a mutation that makes the walk run one extent long, which must fail them.
11. `vmdk-flat-1m`, `vmdk-flat-10m` and `vmdk-multi-flat` compare clean against their existing baselines at every version in the matrix, so `monolithicFlat` did not regress.
12. `make validate-profiles` exits 0 in the testdata clone, and the five fixtures have baselines for `info`, `check`, `measure` and `map` at every version directory.
13. `pre-commit run --all-files` passes, and `make test` reports a "Ran: N" matching the selection with 0 failures. The count is checked, not the exit code.
14. `scripts/check-binary-sizes.sh` passes, with the before and after numbers recorded in the execution notes because steps 3a and 3c change a crate linked into the guest.
15. Breaking each of step 3b's routing cases and step 3c's extent resolution in turn makes a test fail, with the mutation script's path, a killed count, and no skip counted as a kill.

## Execution notes

Implementation began 2026-11-19 (AEDT).

**Back brief, answered 2026-11-19.** #927 stays in this phase as step
3e, rather than being split into its own pull request.
`MAX_CHAIN_EXTENTS` is confirmed at 64. Step 3f removes the
`instar_unsupported` mechanism outright once no image uses it, rather
than keeping the field and relaxing its test. This session may push the
testdata baselines after review, push the phase branch, and open the
pull request.

**Two facts this plan had wrong, corrected above at source.** The
compile-time assert idiom is a free-standing `const _: () = assert!(..)`
and not a `const_assert!` macro, which does not exist here. And
decision 4's page arithmetic was right about the page but missed a
second bound: `CHAIN_CONFIG_MAX_SIZE` was 1024, not the 4096-byte page,
with a test asserting the structure fits it, so 2392 bytes would have
failed. Step 3a raised that constant to
`VMM_PARAMS_ADDR - CHAIN_CONFIG_ADDR`, which is what the name meant all
along; its only consumer hands the guest a pointer and a length for the
region rather than copying into a buffer, so nothing was sized by the
old value.

**Step 3a could not quite "change no consumer".** The host wrote device
entries with a literal stride of 32 and the segment array at a literal
`+528`, in three places, with two VMM tests pinning those numbers.
Growing `ChainDeviceInfo` from 32 to 40 bytes moves both, and leaving
the literals would have had the host writing at the old stride while the
guest read at the new one -- a whole config misread rather than a
missing field. Both are now derived from
`size_of::<ChainDeviceInfo>()`. No behavioural consumer changed and
nothing yet reads the new fields.

**Definition of done items 5 and 6 were verified by the management
session**, not by the step, because the sub-agent's permission settings
refused the edit the check requires. Each mutant ran against a copy and
was restored from it: `MAX_CHAIN_DEVICES = 17` fails the build with
"virtqueue region overlaps the DMA pool", and `MAX_CHAIN_EXTENTS = 200`
fails it with "ChainConfig does not fit the page reserved for it at
CHAIN_CONFIG_ADDR". Both are the asserts the step added or rewired, so
the guard this phase relies on is proved rather than read.

**A design question the plan had not answered, decided before step 3c
ran** (decision 7). The guest keeps format parser state per device, with
128 KiB of grain-directory and grain-table cache per device slot out of
a 2 MiB region, so the 64 extents now sharing one device cannot each
have their own. The descriptor device keeps one extent's state at a
time and re-reads it at an extent crossing. Noted because it means the
rotation this phase removed from the device slots came back in the
parser state, one layer down.

**Step 3c carried the extent's kind, and the ten tests that fail until
step 3d.** The step found that nothing else in a table entry can say
whether an extent is flat or sparse; decision 3 is amended above and
decision 4's arithmetic with it. An entry grew from 24 to 32 bytes and
`ChainConfig` from 2392 to 2904, still inside the page, and the version
stays 5 because nothing has yet run against version 5's old shape.

The step also removed the per-device extent walk, which is what
decision 5 asked for, and the host does not fill the extent table until
step 3d. Between the two commits a flat descriptor is refused at guest
init rather than read, so ten integration tests fail by design:

| Test | File |
|---|---|
| `test_convert_vmdk_flat_1m`, `test_convert_vmdk_flat_10m` | `tests/test_convert.py` |
| `test_convert_vmdk_flat_roundtrip`, `test_convert_flat_to_vmdk_flat`, `test_convert_raw_to_vmdk_flat` | `tests/test_convert.py` |
| `test_convert_multi_extent_flat_to_raw`, `test_convert_flat_with_parent_chain` | `tests/test_convert.py` |
| `test_compare_qcow2_over_smaller_flat_vmdk`, `test_compare_reversed_qcow2_over_smaller_flat_vmdk`, `test_convert_qcow2_over_smaller_flat_vmdk` | `tests/test_qcow2_subclusters.py` |

Each fails as a clean refusal (`convert operation failed`), not as a
wrong answer, and step 3d restores all ten. Recorded here because the
branch is red in the middle of its own phase, which a reader of the
history is owed an explanation for, and because the definition of done
has to show these ten green before the phase is finished.

**Guest binary sizes across step 3c**, the "after" column measured by
the management session with `make check-binary-sizes` on its own build
and the "before" taken from the step's record at `b6f13211`, against the
cap of 768KB (`core`'s is 128KB). Only the operations that link the chain
reader move:

| Operation | Before | After |
|---|---|---|
| `convert` | 369KB | 372KB |
| `compare` | 244KB | 247KB |
| `bench` | 220KB | 224KB |
| `rebase` | 119KB | 120KB |
| `measure` | 41KB | 42KB |
| `core` | 70KB | 70KB |

The reader's own frame is unchanged at 10728 bytes against the ~10.7KB
per device the budget allows, because the new work is in a function of
its own that is not inlined and is not live across a descent. An extent
crossing costs a transient 66KB header read instead of a permanent
frame.

**The qcow2 crate's VMDK reader arms had never been tested.** The
feature matrix in `Makefile`, `scripts/check-rust.sh` and
`tools/ci/rust-feature-tests.sh` listed every input format's feature but
`vmdk-input`, so before step 3c the crate had no test gated on it at
all -- the arm shipped in the guest binaries and nothing exercised it in
either `make test-rust` or CI. The step added `vmdk-decompress`, which
implies `vmdk-input`, to all three. This is the failure class the CI
script's own comment names, and the same script is still missing the
`vhd-input,vhdx-input` the Makefile has, which predates this plan and is
left for an issue rather than fixed here.

**One step 3c premise the survey had backwards.** The plan asked for
each extent's declared sector count to be honoured "rather than
inferring 2 GiB from the create type". The read path never inferred
2 GiB: the walk at `src/crates/qcow2/src/lib.rs:18878` already uses each
data device's `virtual_size`. What changes is where the span comes
from, not that it starts being respected. The row is corrected above so
no one spends the step hunting a bug that is not there.

**Step 3d closed the ten tests step 3c opened**: `Ran: 4542`, 0 failed,
verified by the management session on its own build. The reader and the
host now agree, which is the first point in the phase at which a
multi-extent sparse image can be read at all.

**The suite is not clean yet, though, and 0 failed does not say so.**
One test, `test_every_unsupported_image_is_refused`, crashed its stestr
worker instead of failing -- "exited without returning a status" -- so
`make test-container` exits non-zero while the totals block reports
Failed: 0 and Worker 1 reports N/A. The cause is this phase working:
that test asserts every image the manifest flags `instar_unsupported`
really is refused, and all five of the flagged split-sparse fixtures
now succeed. Checked directly, outside the runner, each returns rc=0
with between 1480 and 14159 bytes of output. Step 3f is what resolves
it, by clearing the flag and removing the mechanism.

The lesson is worth keeping separate from the cause: a totals block
saying `Failed: 0` is not the same as a clean run, and neither is a
matching `Ran: N`. The line to look for is the one naming tests that
exited without a status, and the signal beside it is a worker whose
time reads N/A. Definition-of-done item 13 asks for the count rather
than the exit code; it needs both, plus that line.

Four things came out of the step that the plan had not said, two of
them recorded above as decisions 8 and 9. The other two:

* **`instar info` printed `format: FLAT` for every extent of a
  descriptor.** True while only flat descriptors resolved, false the
  moment sparse ones did, and qemu's JSON carries `"format": "SPARSE"`
  for these images. Fixed in the step. It changes `info` output for the
  five fixtures, so it has to land before their baselines are
  generated.
* **One parity gap confirmed, one not reproduced.** instar omits
  `cluster-size` for a split descriptor where qemu reports 65536, both
  at the top level and per extent -- measured against the pinned 10.2.0
  build on `vmdk-split-sparse-33g.vmdk`. The step also reported that a
  child node's `virtual-size` is the declared span where qemu reports
  the extent file's length; that did not reproduce on either
  `vmdk-split-sparse-33g.vmdk` or `vmdk-multi-flat.vmdk`, where both
  readers agree and report a single node. Treat it as unconfirmed and
  check it when the baselines are generated rather than carrying it as
  fact.

**One pre-existing fault fixed as a side effect, and kept.** The
device-slot budget was checked in `write_chain_config` alone, so the
two-chain paths (`compare` and `rebase`) kept a silent `break` that
passed the guest a prefix of the chain the user asked about -- a wrong
answer reported as success. The check now lives in
`write_chain_device_entries`, which every caller reaches the device
array through. No command reaches it today, because each counts its own
devices first; what it closes is a caller whose count drifts from the
chain it passes.

**A security test's refusal moved rather than weakened.**
`test_instar_handles_vmdk_descriptor_safely` used to pass because a
SPARSE extent was refused outright; SPARSE extents are now read, so
what refuses `vmdk-path-traversal` is the backing allowlist. Verified
by reading the resolver: `validate_backing_path` runs for every extent
of a descriptor, before anything opens a file, and its error is the one
the test now asserts by name rather than inferring from a non-zero exit.

**Two things left for later steps.** `print_backing_chain` still labels
a descriptor's extents "External data file", which step 3e owns along
with the rest of the chain printer. And `layout_descriptor_extents` is
computed twice per image, once to open the backing store and once to
write the table, so each extent is stat'd twice; the two cannot
disagree harmfully, because the backing store clamps a member to the
lesser of its declared length and the file's, but the duplication is a
wart worth removing when something else touches that code.

**Guest binary sizes are unchanged by this step** -- `core` 70KB,
`convert` 372KB, `compare` 247KB, `bench` 224KB, against a 768KB cap --
because the change is host-side. Raising the parser's extent bound did
not move them either.

## Back brief

Points needing the operator's answer before any step runs.

1. **The mechanism is settled** (decision 1, agreed 2026-11-19): host-side concatenation with a guest-visible extent table, not device-slot rotation. The back brief should confirm that the master plan's open question 1 is to be amended to record the change for the read path, leaving the write path's mechanism open for phases 6 to 8.
2. **`MAX_CHAIN_EXTENTS = 64`** (decision 4) is a divergence from qemu, which has no limit. Confirm 64, or name a different bound; above roughly 128 the config region has to move, which is a larger change than this phase.
3. **Whether #927 belongs here** (scope, and step 3e). It is a shipping bug in a different code path from the rest of the phase, and it could equally be its own small pull request landing sooner.
4. **Whether step 3f may remove the `instar_unsupported` mechanism** once no image uses it, or should leave the field and its test in place against future use.
5. **Testdata push** (step 3g): generated baselines are the management session's to commit and push to `main`. Confirm the usual arrangement -- push after review.
6. **Pull request**: whether this session may open it, or should stop at the push.
