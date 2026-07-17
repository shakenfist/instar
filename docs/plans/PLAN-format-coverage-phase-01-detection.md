# Format coverage phase 1: detection + info parity

Master plan: [PLAN-format-coverage.md](PLAN-format-coverage.md)

## Status: Planned, not started

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

I prefer one commit per logical change, and at minimum one
commit per phase. Do not batch unrelated changes into a
single commit. Each commit should be self-contained: it
should build, pass tests, and have a clear commit message
explaining what changed and why.

## Situation

instar detects ten on-disk formats today
(`src/shared/src/format_detection.rs:60`,
`detect_format_from_header`) but not Parallels, Bochs, cloop,
or DMG. The shared module is `no_std`, receives at least the
first sector of the file, and is linked by ten guest ops
(info, check, resize, measure, create, map, snapshot, commit,
rebase, bench) plus the host's in-place-op probes
(`src/vmm/src/main.rs:5925`, `:6555`, `:6201`, `:7878`,
`:7953`, each reading a 4096-byte prefix).

Research for this plan (verified against QEMU master source,
`block/{parallels,bochs,cloop,dmg}.c`, and cross-checked at
v6.0.0) established:

| Format | qemu probe | Score | Virtual size source |
|--------|-----------|-------|---------------------|
| parallels | content: 16-byte magic @0 + LE u32 version==2 @16 | 100 | LE u64 `nb_sectors` @36 (unaligned) × 512; masked to low 32 bits for old `WithoutFreeSpace` magic |
| bochs | content: `strcmp` of "Bochs Virtual HD Image" @0, "Redolog" @32, "Growing" @48 (NUL-terminated), LE u32 version @64 ∈ {0x00010000, 0x00020000}; requires 512-byte buffer | 100 | LE u64 disk-size-in-bytes @88 (v2) or @84 (v1), ÷512 truncating, ×512 |
| cloop | content: exact 87-byte V2.0 shell-script string @0 (`#!/bin/sh\n#V2.0 Format\nmodprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1\n`) | 2 | BE u32 `n_blocks` @132 × BE u32 `block_size` @128 |
| dmg | **filename only**: `*.dmg` → 2; content never probed | 2 | BE u64 SectorCount at koly+0x1ec × 512; koly trailer found by scanning the last 515 bytes (candidate start offsets [len−1023, len−512]) for `koly` |

All four probes and size computations are unchanged from QEMU
6.0.0 through 10.2.0, so cross-version baselines should
collapse into very few profiles. parallels is read-write in
qemu (`qemu-img create -f parallels` works); bochs, cloop, and
dmg are read-only drivers. None of the four has
format-specific `qemu-img info` fields — parity is format
name + virtual size.

Codebase facts that shape the design:

* **Trailer precedent.** Fixed VHD is already detected by
  reading the file's last 512 bytes when the header probe
  returns Raw: guest-side `info/src/main.rs:154-164`
  (`detect_vhd_footer`, `format_detection.rs:156`) and
  host-side `main.rs:6584-6600`. DMG's koly trailer is the
  same shape and reuses this pattern; master-plan OQ2 is
  settled below.
* **Detect-only info precedent.** VDI and QED have no crate:
  inline parsers in the info op (`info/src/main.rs:897`
  `parse_vdi_header`, `:974` `parse_qed_header`), a dispatch
  arm each (`:352`, `:409`), and a `format_to_str` entry
  (`:490`). Phase 1 follows this — no new `src/crates/`.
* **Consumer hole (pre-existing).** convert, compare, and dd
  do not probe on the host; they call
  `discover_backing_chain` (`main.rs:2174`) → guest info →
  `chain::ImageFormat::from_str` (`src/vmm/src/chain.rs:50`),
  which maps any unrecognised format string (today: `qed`,
  `vdi`, `iso`) to `Unknown`, and the guest chain reader's
  default arm reads `Unknown` devices as raw sectors
  (`src/crates/qcow2/src/lib.rs` dispatch, default arm near
  `:6516`). So detect-only formats appear to be silently
  **read as raw** by convert/compare/dd today rather than
  refused. Newly detected formats would flow into the same
  hole. Step 1a pins this empirically; step 3b closes it.
* **Fixtures.** `instar-testdata` (sibling checkout) already
  holds `downloaded/qemu-iotests/{parallels-v1 (327680B,
  WithoutFreeSpace), parallels-v2 (327680B, WithouFreSpacExt),
  empty.bochs (2560B), simple-pattern.cloop (1690B)}` —
  magics verified by hexdump — but none is registered in
  `tests/manifest.json`, so nothing tests them. No `.dmg`
  exists anywhere in testdata; qemu cannot create DMG, and
  `hdiutil` is unavailable, so DMG fixtures need a generator
  script (which lives in instar-testdata, per its
  ADVERSARIAL.md convention of keeping generators private).
* **Baselines.** info baselines live in
  `instar-testdata/expected-outputs/qemu-img-{human,json}/`
  (legacy names), generated by `generate-baselines.py`
  (always `--no-commit`) over 80 static qemu-img builds
  (6.0.0–10.2.0) and deduplicated by `detect-profiles.py`.
  Only manifest images with `safety: "safe"` and without
  `skip_qemu_img` are included. Unlike VDI/QED (which carry
  `skip_qemu_img: true`), all four new formats are
  qemu-detectable, so they get real cross-version baselines.
* **oslo crossval is unaffected.** oslo.utils detects none of
  the four; `_get_oslo_inspector` skips the scenario when
  oslo returns `None` (`tests/test_oslo_crossval.py:193-212`),
  so no `KNOWN_FORMAT_DIVERGENCES` entries are needed (an
  entry would in fact *fail*, since it asserts a concrete
  oslo format string).

## Mission

1. **Detection.** `detect_format_from_header` recognises
   Parallels, Bochs, and cloop by content at offset 0; a new
   trailer helper recognises DMG's koly block; the
   `ImageFormat` enum gains `Parallels`, `Bochs`, `Cloop`,
   `Dmg` variants.
2. **Info.** `instar info` reports format name and virtual
   size for all four (human + JSON), matching `qemu-img info`
   byte-for-byte on the baseline matrix, via inline parsers in
   the info op (VDI/QED pattern).
3. **No silent raw fallthrough.** convert, compare, and dd
   refuse detected-but-unsupported input formats with a typed
   error instead of reading them as raw; the in-place ops
   (resize, rebase, commit, amend, bitmap, snapshot, map,
   measure, bench, check) refuse via their existing default
   arms, verified by tests.
4. **Fixtures + baselines.** The four staged qemu-iotests
   images are registered in the manifest and exercised; DMG
   fixtures (valid + adversarial) are generated and
   registered; cross-version info baselines exist for all new
   images.
5. **Docs.** `docs/format-coverage.md` detection rows flip to
   Yes; `docs/quirks.md` records the deliberate divergences
   (below); CHANGELOG updated; master-plan table updated.

## Design

### OQ2 resolved: DMG detection is content-based trailer probing

instar detects DMG by content — scanning the final 1024 bytes
for the koly magic, mirroring qemu's `dmg_find_koly_offset`
window — and does **not** adopt qemu's filename-extension
probe. Rationale:

* instar has no extension-based detection anywhere; its
  charter is safety *detection*, and "this raw-looking file
  is actually a compressed container" is precisely the class
  of fact it exists to report (same stance as ISO).
* The fixed-VHD footer path is an exact structural precedent:
  trailer probing runs only when the header probe returned
  Raw, so it costs nothing for the common formats.
* Parity impact is confined to misnamed files: a DMG not named
  `*.dmg` probes as raw under qemu but dmg under instar. For
  baseline fixtures (named `*.dmg`) both tools agree.
  Recorded in `docs/quirks.md` as a safe quirk (instar is
  strictly more truthful); `--unsafe-quirks` does not change
  DMG detection.

Guest-side ordering in the info op, extending
`info/src/main.rs:154-190`: header probe → if Raw: VHD footer
(existing) → if still Raw: DMG koly trailer (new) → if still
Raw and not `--unsafe-quirks`: ISO at 32769 (existing) →
partition-table gate (existing; the four new formats, being
structured, bypass it like every non-Raw format).

### Detection rules (mirroring qemu probes)

* **Parallels**: `len >= 64`; 16 bytes @0 equal to
  `WithoutFreeSpace` or `WithouFreSpacExt` (no NUL); LE u32
  @16 == 2. Both magics map to one `Parallels` variant; the
  old-vs-new distinction matters only for size masking in the
  info parser.
* **Bochs**: `len >= 512` (qemu requires a full 512-byte
  header); NUL-terminated string compares: "Bochs Virtual HD
  Image" within bytes 0..32, "Redolog" within 32..48,
  "Growing" within 48..64; LE u32 @64 ∈ {0x00010000,
  0x00020000}.
* **cloop**: `len >= 87`; exact match of the 87-byte V2.0
  shell-script string @0. Deliberate divergence: qemu's probe
  compares `min(strlen(magic), buf_size)` bytes, so a file
  shorter than 87 bytes that prefix-matches still probes as
  cloop there; instar requires the full magic. Recorded in
  quirks.md (degenerate truncated files only).
* **DMG**: new `no_std` helper in `format_detection.rs`
  (sibling of `detect_vhd_footer`) that takes a buffer
  holding the file's final bytes plus the file length and
  scans qemu's candidate window ([len−1023, len−512]) for
  `koly`, returning the trailer offset. Files < 512 bytes are
  never DMG. The koly block is 512 bytes; SectorCount is BE
  u64 at koly+0x1ec and is rejected if the top bit is set
  (qemu rejects negative totals).

Insert the three header checks after the existing LUKS check
and before the VMDK text-descriptor check in
`detect_format_from_header` (all magics are mutually
disjoint; cloop's `#!` prefix does not collide with the
`# Disk DescriptorFile` text check but belongs with the
binary checks for clarity).

### Info parsing (inline, VDI/QED pattern)

* **parallels**: vsize = LE u64 @36 (unaligned read) × 512;
  if magic is `WithoutFreeSpace`, mask nb_sectors to the low
  32 bits first (qemu parallels.c:1270-1282).
* **bochs**: version from LE u32 @64; disk-size LE u64 @88
  (v2) or @84 (v1); vsize = (disk / 512) × 512 (truncating,
  matching qemu's total_sectors computation).
* **cloop**: block_size BE u32 @128, n_blocks BE u32 @132;
  vsize = n_blocks × block_size. Apply qemu's open-time
  bounds as parse-failure conditions: block_size non-zero,
  multiple of 512, ≤ 64 MiB; n_blocks ≤ (u32::MAX−1)/8.
* **dmg**: guest reads the tail of the input (reusing the
  VHD `footer_buffer` pattern at `info/src/main.rs:154-164`;
  with 512-byte sectors this means the last two sectors so
  the 1024-byte koly window is covered), locates koly, and
  reports vsize = SectorCount × 512. Note qemu's `info`
  additionally requires a parseable BLKX chunk table
  (rsrc-fork or XML plist) just to open; instar's info
  reports from the trailer alone. For well-formed fixtures
  both agree; for a DMG with a valid trailer but broken chunk
  table, qemu-img info errors while instar reports — an
  acceptable divergence for adversarial fixtures only
  (`skip_qemu_img: true` on any such fixture; noted in
  quirks.md).

All four report format name + virtual size only (qemu has no
format-specific info fields for them). `format_to_str`
(`info/src/main.rs:490`) gains `"parallels"`, `"bochs"`,
`"cloop"`, `"dmg"` — qemu's exact `format_name` strings.

### Consumer refusal gate

Step 1a first pins today's behaviour empirically (what do
convert/compare/dd/map/measure actually do with `qed-simple`
and `vdi-simple`?). Expected finding, per code reading: the
chain maps them to `Unknown` and the read path treats them as
raw. The fix (step 3b) refuses at the host after chain
discovery: if the chain head's guest-reported format string
is a format instar detects but has no read path for
(parallels, bochs, cloop, dmg, qed, vdi, iso — i.e. anything
mapping to `chain::ImageFormat::Unknown` whose info-format
string is not `raw`/`unknown`), convert/compare/dd exit with
a typed error naming the format, e.g.
`convert: input format 'bochs' is detected but not supported
for reading (detection and info only)`. Files that are
genuinely unidentifiable keep their current behaviour
(secure-mode partition gate / `--unsafe-quirks` raw
acceptance). This also retroactively closes the QED/VDI/ISO
hole; if step 1a shows tests depend on the current silent-raw
behaviour, that is a finding for the management session to
adjudicate before 3b lands, not a licence to keep the hole.

The in-place ops need no new refusal code — the new enum
variants fall into existing default arms (e.g.
`measure/src/main.rs:414`, host `main.rs:6648`) — but step 5a
adds tests proving at least resize, measure, and map refuse
each new format cleanly.

### Fixtures and baselines

* Register `parallels-v1`, `parallels-v2`, `empty.bochs`
  (id `bochs-growing`), `simple-pattern.cloop` (id
  `cloop-simple`) in `tests/manifest.json` with
  `safety: "safe"`, real sha256s, and **without**
  `skip_qemu_img` (unlike VDI/QED, qemu-img handles them, so
  they get real baselines). Follow existing id/tag style.
* New DMG fixtures via a generator script committed to
  instar-testdata: a minimal valid UDIF (zlib/UDZO or
  zero-chunk BLKX table in an XML plist + koly trailer, sized
  a few MiB virtual) named `*.dmg` so qemu-img detects it —
  this is the parity fixture. Adversarial variants (koly with
  huge/negative SectorCount, truncated trailer, koly present
  but no chunk table) registered `safety: "malformed"` with
  `skip_qemu_img: true` where qemu-img itself errors.
* Verify the static qemu-img builds actually compile the
  parallels/bochs/cloop/dmg drivers in (spot-check one old
  and one new version with `qemu-img info` on each fixture)
  **before** running the full 80-version baseline sweep.
* Baselines: `generate-baselines.py --command info` (and the
  json variant) over the matrix, then `detect-profiles.py`;
  commit to instar-testdata (operator pushes — protected
  branch, Maintainer token). Manifest sha256 must match the
  committed bytes or `test_info_safe` self-skips.

### Fuzzing

`src/fuzz/fuzz_targets/fuzz_format_detect.rs` already drives
`detect_format_from_header`; extend it to also call the new
DMG trailer helper so the new parsing is covered by the
existing coverage-fuzz workflow. The inline info parsers are
exercised by the adversarial fixtures at integration level;
deep parser fuzzing belongs to the read-path phases (2–5).

## Out of scope for this phase

* Read paths (convert-from) for any of the four — phases 2–5.
* vvfat detection (no on-disk magic exists to detect — it is
  a synthesised pseudo-format; phase 7 documents the refusal
  rationale).
* The QED read-or-refuse decision — phase 6. (Phase 1's
  consumer gate makes QED's current *de facto* raw-read into
  an explicit refusal, which is phase 6's option (a); phase 6
  can still choose a read path later.)
* New `src/crates/` parser crates — the read-path phases
  create them; info parsing stays inline until then.
* `map`/`measure`/`dd` *support* for the new formats
  (master-plan future work); phase 1 only ensures clean
  refusals.

## Resolved open questions (from the master plan)

* **OQ2 (DMG trailer probing)**: settled — content-based
  trailer detection via the fixed-VHD footer pattern; no
  extension-based detection; quirks.md records the
  misnamed-file divergence. The detection *API* change is one
  new helper beside `detect_vhd_footer`, not a signature
  change to `detect_format_from_header`.
* **OQ5 (testdata provenance), DMG part**: settled — a
  generator script in instar-testdata (hdiutil unavailable,
  qemu cannot write DMG); the four staged qemu-iotests images
  cover the other formats for this phase.

## Step-level guidance

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1a | high | opus | none | **Empirical pin, no production code.** Determine what convert, compare, dd, map, and measure do today with detect-only-format inputs: run the built instar against `qed-simple` and `vdi-simple` (ids in `tests/manifest.json`, files in the sibling instar-testdata checkout) for each op, in secure mode and with `--unsafe-quirks`. Read `discover_backing_chain` (`src/vmm/src/main.rs:2174`), `chain::ImageFormat::from_str` (`src/vmm/src/chain.rs:50`), and the guest chain-reader default arm (`src/crates/qcow2/src/lib.rs`, dispatch near `:5855`, default arm near `:6516`) and reconcile observed behaviour with the code. Also grep tests/ for anything converting/comparing qed/vdi/iso inputs. Deliverable: a findings section appended to this plan file (behaviour matrix, code-path explanation, list of tests that would break if convert/compare/dd refused these inputs), plus a recommendation. No source changes. |
| 2a | medium | sonnet | none | Shared detection layer. In `src/shared/src/lib.rs:1526` add `Parallels = 13, Bochs = 14, Cloop = 15, Dmg = 16` to `ImageFormat` (+ `from_u32` `:1562`, `name()` `:1581` returning "parallels"/"bochs"/"cloop"/"dmg"). In `src/shared/src/format_detection.rs`: add the magic constants and the three header checks per the Detection rules section above (exact offsets/guards there), inserted after the LUKS check; add a `no_std` DMG trailer helper beside `detect_vhd_footer` (`:156`) implementing the koly window scan ([len−1023, len−512]) and a SectorCount accessor (BE u64 at koly+0x1ec, reject top bit). Extend the in-module tests (`:192-225`): positive detection from real fixture header bytes (hexdumps in this plan's Situation section; fixtures under `instar-testdata/downloaded/qemu-iotests/`), wrong-version negatives (parallels version≠2, bochs version 0x30000), truncation negatives (parallels 63 bytes, bochs 511, cloop 86), koly-at-each-window-edge positives and a koly-outside-window negative. Extend `src/fuzz/fuzz_targets/fuzz_format_detect.rs` to call the new helper. Fix any exhaustive `match ImageFormat` arms the compiler surfaces across the 10 guest ops and host — new variants must land in the same arm as `Vdi`/`Qed` (detect-only), never in a read/write arm. `make instar`, `make lint`, `make test-rust`, `make fuzz-build` must pass. |
| 3a | high | opus | none | Guest info op wiring in `src/operations/info/src/main.rs`. Add the DMG trailer probe after the VHD-footer fallback (`:154-164`): when the format is still Raw, read the input tail covering the final 1024 bytes (two sectors at 512-byte sector size; one suffices at ≥1024 — reuse the `footer_buffer` pattern, mind `input_capacity` and non-sector-aligned lengths) and call the shared helper. Add dispatch arms (pattern: VDI `:352`, QED `:409`) and inline parsers (pattern: `parse_vdi_header` `:897`, `parse_qed_header` `:974`) for all four formats per the Info parsing section above (exact fields, endianness, masking, and cloop bounds are specified there — do not re-derive). Add the four `format_to_str` entries (`:490`). The new formats bypass the raw partition-table gate (`:200-238`) automatically by being non-Raw — verify, don't reimplement. Ensure `--unsafe-quirks` leaves all four detections active (only ISO is quirk-gated). Unit-test the parsers with in-file `#[cfg(test)]` byte-array fixtures per existing style. `make instar && make check-binary-sizes && make test-rust` clean; then hand-verify `instar info` (human + json) against `qemu-img info` for the four staged fixtures. |
| 3b | high | opus | worktree | Consumer refusal gate, contingent on 1a's findings (management session reviews 1a before dispatching this step). In the host: after `discover_backing_chain` returns for convert/compare/dd (`run_convert`, `run_compare`, `run_dd` `main.rs:13629`), refuse when the chain head's format string is detected-but-unreadable (maps to `chain::ImageFormat::Unknown` but is not `raw`/`unknown`): typed error `"{op}: input format '{fmt}' is detected but not supported for reading (detection and info only)"`, non-zero exit, matching the existing refusal message style (`main.rs:6648`, `:5967`, `:6217`). Decide with the 1a evidence whether the check belongs once in `discover_backing_chain` or per-op; backing files in mid-chain positions get the same refusal. Update any tests 1a identified as depending on silent-raw behaviour only after management sign-off. Add integration tests: convert/compare/dd on `qed-simple`, `vdi-simple`, and each new-format fixture must exit non-zero with the typed message. |
| 4a | high | opus | none | DMG fixture generator, in the **instar-testdata** repo (sibling checkout; scripts live there per its ADVERSARIAL.md convention — generators are not published in the instar repo). Python, following `generate-baselines.py` style (single quotes, 120-col). Emit: (1) `dmg-simple.dmg` — minimal valid UDIF: small data fork of zlib (UDZO) chunks or zero (UDZE) chunks, XML plist with base64 mish BLKX block (204-byte block header, 40-byte chunk entries, terminator chunk), koly trailer (BE fields; DataForkOffset/XMLOffset/XMLLength/SectorCount populated; XML strictly before the koly offset) — must satisfy `qemu-img info` on both qemu 6.0.0 and 10.2.0 static binaries from `qemu-img-binaries/x86_64/`; (2) adversarial variants: truncated koly, SectorCount with top bit set, huge SectorCount, valid koly but zero rsrc+XML lengths (qemu open fails, so these carry `skip_qemu_img: true` in the manifest). Deterministic output (fixed timestamps/UUIDs) so sha256s are stable. Do NOT commit to instar-testdata main — leave the working tree for operator review (protected branch; see repo conventions). |
| 4b | medium | sonnet | none | Manifest + baselines. Add `tests/manifest.json` entries: `parallels-v1`, `parallels-v2` (`downloaded/qemu-iotests/parallels-v{1,2}`), `bochs-growing` (`downloaded/qemu-iotests/empty.bochs`), `cloop-simple` (`downloaded/qemu-iotests/simple-pattern.cloop`), `dmg-simple` plus 4a's adversarial set — real sha256s, `safety` safe/malformed as appropriate, `run_in_ci: true` for the safe ones, no `skip_qemu_img` on qemu-readable images, style-matched to existing entries. First spot-check driver presence: run the 6.0.0 and 10.2.0 static qemu-img binaries' `info` on each safe fixture. Then `generate-baselines.py --command info` (human and json paths per its `COMMANDS` config) followed by `detect-profiles.py`; verify new profiles are few (probes are version-stable). Leave instar-testdata changes uncommitted for operator review. In-repo manifest change commits normally. |
| 5a | medium | sonnet | none | Integration tests. Confirm `tests/test_info_safe.py` auto-picks the new safe images (scenario generation is manifest-driven) and passes against the new baselines. Add refusal tests (may live with 3b's if that step landed first — do not duplicate): resize, measure, and map on each new-format fixture exit non-zero with their existing unsupported-format messages (`main.rs:6648`, `:11396`, map guest `ERROR_INVALID_SOURCE`). Add adversarial coverage for the malformed DMG fixtures via the `run_adversarial` harness (`tests/base.py:1066` — no hang, no crash, bounded memory; info on them may succeed or fail). Run the info-related suites and `test_oslo_crossval` locally; oslo scenarios for the new images must skip (oslo returns None), not fail. |
| 6a | medium | sonnet | none | Docs + close-out. `docs/format-coverage.md`: flip the Parallels/Bochs/cloop rows to Yes, add a DMG row, note "(in testdata, not tested)" is obsolete, and add the new images to the test-image tables. `docs/quirks.md`: three entries per the Design section (DMG content-vs-extension detection; cloop full-87-byte magic vs qemu prefix-match; DMG trailer-only info vs qemu's chunk-table requirement). `CHANGELOG.md` entry. Master plan `PLAN-format-coverage.md`: Execution table row 1 → Complete with commit refs; record step-1a findings in "Bugs fixed during this work" if 3b fixed the silent-raw hole. `docs/plans/index.md`: link this phase file in the master plan's row. Wrap at the file's existing column width. |

Sequencing: 1a first (its findings gate 3b's shape and can
run while nothing else is in flight); 2a → 3a strictly
ordered; 3b after management review of 1a; 4a/4b can proceed
in parallel with 3a once 2a lands (baseline generation only
needs qemu-img, not instar); 5a after 3a+3b+4b; 6a last.

## Verification (management-session review checklist)

- [ ] The files that were supposed to change actually changed
      (read them, don't trust the summary).
- [ ] No unrelated files were modified; instar-testdata
      changes are left uncommitted for operator review.
- [ ] `make instar` builds and `make lint` is clean.
- [ ] Guest binaries pass `make check-binary-sizes` (768KB
      limit per operation; info grows but has ~640KB
      headroom).
- [ ] `make test-rust`, `make fuzz-build`, and the info /
      adversarial / oslo-crossval integration suites pass.
- [ ] `pre-commit run --all-files` passes.
- [ ] `instar info` output for all new safe fixtures is
      byte-identical to `qemu-img info` (human and json)
      across the baseline profiles.
- [ ] convert/compare/dd refuse every detect-only format with
      the typed message; nothing reads them as raw any more.
- [ ] Step-1a findings are recorded in this file and, if a
      defect was fixed, in the master plan's "Bugs fixed
      during this work".
- [ ] Commit messages follow project conventions (Prompt
      paragraph, Signed-off-by, Co-Authored-By with model /
      context window / effort level).

## Success criteria

Phase 1 is complete when:

* `instar info` detects and sizes Parallels (v1+v2 magics),
  Bochs (growing), cloop (V2.0), and DMG images, matching
  qemu-img across the 80-version baseline matrix.
* The four staged qemu-iotests images and the new DMG
  fixtures are manifest-registered and exercised in CI.
* The koly trailer helper exists in the shared `no_std`
  detection module with unit-test and fuzz coverage.
* No instar subcommand silently reads a detected-but-
  unsupported format as raw; refusals are typed and tested.
* Quirks, format-coverage, and CHANGELOG docs record the new
  state; the master plan table row is Complete.

## Hand-off to later phases

* Phases 2–5 (read paths) lift each format's inline info
  parser into a `src/crates/<format>/` crate as they build
  the guest read path; the detection layer from 2a is final.
* Phase 5 (DMG read) inherits the koly helper and the
  fixture generator; it adds BLKX/mish chunk-table parsing
  (204-byte block header, 40-byte chunk entries, UDZO=zlib
  first; UDBZ/ULFO refusals per master-plan OQ3) and the
  plist walk.
* Phase 6 (QED decision) starts from the explicit refusal 3b
  put in place; choosing a read path reverses that refusal
  for QED only.
* If 1a reveals the silent-raw hole affects other formats or
  subcommands beyond convert/compare/dd, that goes to the
  master plan's "Bugs fixed during this work" and, if large,
  its own follow-up plan.

## Back brief

Before executing any step of this plan, back brief the
operator: confirm the OQ2 resolution (content-based trailer
probing, no extension detection), the consumer-refusal scope
(3b changes behaviour for pre-existing QED/VDI/ISO inputs,
gated on 1a's evidence and management review), and that
instar-testdata commits are operator-reviewed, never pushed
by sub-agents.
