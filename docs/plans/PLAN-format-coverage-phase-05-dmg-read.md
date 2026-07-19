# Format coverage phase 5: DMG convert-from (read path)

Master plan: [PLAN-format-coverage.md](PLAN-format-coverage.md)

## Status: Ready for execution (planned 2026-07-19)

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

DMG (Apple UDIF) is detect + info only, from phase 1. **This
plan references
[PLAN-format-coverage-phase-04-qcow1-read.md](PLAN-format-coverage-phase-04-qcow1-read.md)
(and through it phases 2–3) for everything structural** — the
chain-reader pattern, graduation ordering, the bench
`read_family` allowlist, the fixture/baseline/oslo workflow,
and the fuzzing shapes. Only DMG facts and deltas follow.
Research was done 2026-07-19 by two grounding passes: a
codebase survey of the phase-1 DMG state and an empirical
verification against qemu `block/dmg.c` (v7.0.0 + master,
plus `dmg.h`/`dmg-bz2.c`/`dmg-lzfse.c`) with ~22 hand-built
UDIF images run against the static qemu-img matrix (6.0.0 /
6.2.0 / 7.0.0 / 7.2.0 / 8.0.0 / 8.2.0 / 9.0.0 / 10.2.0) and
host 10.0.11.

### Phase-1 state (survey facts)

* Detection is a **guest-info-op koly-trailer probe**, not a
  header signature: shared helpers
  `detect_dmg_koly_offset`/`dmg_sector_count`
  (`src/shared/src/format_detection.rs:317-363`, with the
  qemu candidate window `[len-1023, len-512]`) driven by
  `probe_dmg_trailer`
  (`src/operations/info/src/main.rs:1474-1526`), which reads
  the last 1–2 device sectors and finds the LAST `koly` to
  recover the true file length (virtio capacity is
  sector-rounded-up, so the trailer sits mid-buffer with a
  zero tail — a deliberate deviation from the VHD-footer
  path).
* Info parses ONLY the trailer: virtual_size = SectorCount ×
  512; no plist/mish parsing, no cluster_size, no version.
  Host emitters already handle "dmg" (protocol-length
  512-rounding sets; dirty-flag suppression set).
* `chain::ImageFormat` has **no Dmg variant**; `from_str`
  maps "dmg" → Unknown → the issue-#444 gate refuses
  convert/compare/dd today (pinned:
  `test_convert_refuses_dmg`, compare/dd equivalents).
  **map/measure/resize pass DMG through as raw** (their
  probe paths never see the trailer) — pinned by
  `test_map.py:679`, `test_measure.py:1140`,
  `test_resize.py:834`, recorded as master-plan future work.
* `shared::ImageFormat::Dmg = 16`. bench `read_family`'s
  next free family number is **8**. No `src/crates/dmg/`
  exists. No dmg fuzz target beyond `fuzz_format_detect`'s
  trailer-helper coverage; the differential fuzzer has no
  dmg (qemu-img cannot create DMG).
* Testdata already has
  `scripts/generate-dmg-fixtures.py` (hand-built UDIF:
  koly + XML plist + base64 mish; zlib level 9,
  byte-deterministic), the safe `dmg-simple` fixture (4 MiB,
  two zlib chunks + terminator) with full baselines, and
  four malformed trailer fixtures (`dmg-truncated-koly`,
  `dmg-sectorcount-negative`, `dmg-sectorcount-huge`,
  `dmg-no-chunk-table`) pinned in test_adversarial.
* Ordering hazard (the qcow1 lesson, hand-off note in the
  phase-4 plan): adding the chain `Dmg` variant without a
  reader arm flips DMG from gate-refusal to **silent raw
  reads**. The reader arm (5b) must land before graduation
  (5c).

### DMG format facts (all empirically verified)

**koly trailer** (512 bytes BE, must occupy the file's final
512-aligned region; scan window as in phase 1). Fields qemu
reads: magic @0, DataForkOffset u64 @0x18, RsrcForkOffset
@0x28, RsrcForkLength @0x30, XMLOffset @0xD8, XMLLength
@0xE0, SectorCount s64 @0x1EC (negative refused). Validated:
DataForkOffset ≤ koly offset; rsrc/xml region bounds.
Ignored: version, header size, flags, DataForkLength, all
checksums. Path selection: RsrcForkLength != 0 → the **old
resource-fork path (supported by qemu — verified by
hand-built image)**: u32 rsrc_data_offset, u32 count, then
`[u32 size][mish]` resources; else XMLLength != 0 → plist
path; else EINVAL. XMLLength bounds: 0 < len ≤ 16 MiB.

**plist parsing is string scanning, not XML**: qemu strstr's
every `<data>…</data>`, base64-decodes each block with a
LENIENT decoder (glib skips invalid characters rather than
erroring), and keeps blocks whose decoded bytes carry the
mish magic and length ≥ 244; everything else is silently
ignored. No `<key>blkx</key>` or plist well-formedness
required. A missing `</data>` is "malformed XML" EINVAL.
**Malformed base64 does NOT error** — it just yields a
non-mish buffer, i.e. zero chunks.

**mish/BLKX**: magic 0x6D697368 @0, out_offset u64 @0x08
(added to each chunk's sector number), data_offset u64 @0x18
(added, together with DataForkOffset, to each compressed
offset), 204-byte header, then 40-byte BE chunk entries:
type u32, comment u32, sector u64, sector_count u64,
comp_offset u64, comp_len u64. chunk_count = (decoded_len −
204) / 40. Multiple mish blocks compose one virtual disk;
sector numbers are absolute after +out_offset; convert of a
multipart image equals raw concatenation (md5-verified).
**Virtual size: koly SectorCount always wins** over mish
coverage; uncovered tail sectors then read as errors.

**Chunk types** (dispositions verified per version):

| code | name | qemu behaviour |
|------|------|----------------|
| 0x00000000 | zero | memset zeros |
| 0x00000001 | raw | pread copy |
| 0x00000002 | ignore | zeros (same as zero) |
| 0x80000004 | ADC | enum-named but never implemented → dropped at open → gap |
| 0x80000005 | zlib (UDZO) | inflate — **zlib-WRAPPED** (0x78 header; raw deflate fails) |
| 0x80000006 | bzip2 (UDBZ) | **build-dependent module** |
| 0x80000007 | lzfse (ULFO) | build-dependent module |
| 0x80000008 | (zstd) | unknown → dropped → gap |
| 0x7FFFFFFE | comment | dropped, harmless |
| 0xFFFFFFFF | terminator | dropped, harmless |

**Codec support is compile-flag dependent across the
matrix**: bzip2 decodes only on static 6.0.0 and host
10.0.11; every other static build lacks the module; lzfse is
absent everywhere. Unsupported/unknown chunks are dropped
from the sector table at open (with stderr warnings only
from 7.2.0 on), leaving gaps.

**Error semantics — the big delta from phases 2–4**: DMG
reads ERROR where the other formats zero-fill.
* A sector covered by no chunk (gap, dropped chunk,
  koly-vs-mish mismatch tail) → **EIO at read; never
  zero-fill** (convert exits 1, "error while reading …
  I/O error").
* Compressed offset past EOF / truncated data fork → short
  read → EIO at read (open succeeds).
* Overlapping chunks: no error — binary search silently
  picks one (deterministic; verified).
* **qemu CRASH (universal, 6.0.0 through host 10.0.11): an
  image with a valid koly but ZERO parsed chunks (bad mish
  magic, broken base64, no `<data>` blocks) segfaults
  (SIGSEGV, rc 139) on any read** — a NULL `sectors[]`
  deref. `info` is fine (never touches the table). instar
  must NOT mirror this: refuse an empty chunk table cleanly
  at reader init. Candidate upstream report.

**Limits**: per-chunk comp_len ≤ 64 MiB
(`DMG_LENGTHS_MAX`, "length N for chunk C is larger than
max (67108864)"); per-chunk sector_count ≤ 131072 (64 MiB
uncompressed, "sector count N … larger than max (131072)");
zero/ignore chunks are EXEMPT from the sector cap. Both
stable across versions.

**Reads**: chunk-granular; qemu caches exactly one
uncompressed chunk and binary-searches the table per sector.

**Probe**: qemu's dmg probe is **pure `.dmg` filename
extension**. An extensionless valid DMG probes as raw (and
converts as container bytes); a `.dmg`-named non-DMG selects
the dmg driver and fails hard. instar's trailer-based
detection is strictly stronger — a real divergence for
extensionless files, to document (phase 1 established the
detection; convert inherits it this phase).

**info output**: no cluster-size, no format-specific block,
no dmg-level dirty-flag at any version; JSON `children[]`
from 8.0.0 (existing profile machinery covers it). Phase-1
baselines confirmed consistent.

**Other subcommands** (host + spot versions): check → "This
image format does not support checks" **rc 63** (parity with
instar's not-supported exit, as for qcow1); map works (with
a compressed-clusters stderr warning; JSON field drift:
`present` @7.0.0, `compressed` @8.2.0); measure works; dd
and bench read normally; compare works. Convert-to-raw md5
is version-stable for every openable image.

**oslo.utils** (git master, live): no DMG inspector → raw
fallback, virtual_size = min(file_size, 262144) —
consistent with the phase-1 entries; new fixtures follow the
same rule.

## Design

### Scope

convert, compare, dd, and bench gain DMG input. Chunk codec
scope (master plan Open question 3): **zero, raw, ignore,
zlib (zlib-wrapped inflate), comment/terminator handling** —
plus **typed reader-init refusals naming the codec for
UDBZ/ULFO/ADC/zstd/unknown types**. This diverges from
qemu's drop-at-open-then-EIO-at-read shape, deliberately:
both fail convert with rc 1, instar's failure names the
codec instead of a bare I/O error, and it cannot mis-serve a
partial image. bzip2/lzfse decode support stays future work
(and qemu's own support is build-dependent, so there is no
single parity target anyway). check stays rc-63 (parity).
**map/measure/resize keep their raw-pass-through behaviour**
— their probe paths still never see the trailer; the
master-plan future-work bullet stays open (this phase's
graduation only affects the chain-discovery consumers).
No write/create/output support; DMG stays absent from
convert's output roster.

### Graduation = the chain variant (reader arm first)

Chain discovery probes each position via the guest info op,
which already detects DMG. Adding `chain::ImageFormat::Dmg`
(+ from_str "dmg", to_shared_format_u32 => 16, Display)
lifts the #444 gate for convert/compare/dd — so exactly as
in phase 4, the variant lands strictly AFTER the 5b reader
arm. bench `read_family` gains `Dmg => Some(8)` in
lock-step.

### New `src/crates/dmg/` crate

no_std, panic-free, mirroring the sibling crates. Parses,
from the device via the call table:

1. **koly** (reusing the shared trailer helpers' constants
   and the info op's last-two-sectors true-length recovery
   technique — factor the shared logic rather than
   duplicating): validate exactly qemu's field set, ignore
   exactly qemu's ignored set.
2. **Chunk-table source**: XML-plist path AND the old
   resource-fork path (both qemu-supported). String-scan
   `<data>`/`</data>`; lenient base64 (skip invalid chars,
   matching glib — parity requires opening the same images);
   accept only decoded blocks with mish magic and len ≥ 244.
3. **mish** blocks → one flat chunk table: entries with
   out_offset/data_offset/DataForkOffset applied, qemu's
   per-chunk caps enforced with the exact limits (comp_len
   ≤ 64 MiB, sector_count ≤ 131072 with zero/ignore exempt),
   comment/terminator dropped, unknown/unsupported codecs →
   **typed init refusal naming the code** (see Scope).
4. **instar's own bounded-memory caps** (typed refusals,
   documented divergences — the sandbox has ~12.9 MiB of
   scratch, and qemu-legal chunks can be 64 MiB
   uncompressed + 64 MiB compressed, which cannot be staged):
   * plist/resource-fork region staged for parsing: cap at
     **1 MiB** (real-world plists are KBs; qemu's own cap is
     16 MiB).
   * chunk table: compact entries, capped at **32768 chunks**
     (~32 GiB of default 1 MiB-chunk UDZO coverage; the
     table fits ~1 MiB of scratch).
   * per-chunk staging: uncompressed sector_count ≤ **4096
     sectors (2 MiB, = staging_buf)** and comp_len ≤
     compressed_buf for non-zero/ignore chunks. hdiutil's
     default UDZO chunking is 1 MiB, so real images fit with
     2× headroom; a qemu-legal-but-over-cap image gets a
     typed refusal, pinned by a divergence fixture.
5. **Empty-table refusal**: a valid koly with zero parsed
   chunks refuses cleanly at init (where qemu segfaults —
   pinned by the existing `dmg-no-chunk-table`-class
   fixtures, whose convert expectations change from
   gate-refusal to reader-refusal in 5c/5e).
6. **Table ordering**: qemu builds the table in mish order
   and binary-searches, assuming sortedness; real images are
   sorted. instar verifies sorted-by-sector at init and
   refuses unsorted/overlapping tables (typed; qemu's
   behaviour there is silent-arbitrary). No overlap fixture
   ships; recorded as a corner.

Lookup API: `DmgState::init` (stages the chunk table into a
caller-provided scratch region) + `chunk_lookup(sector)` →
Zero / Raw { host_offset } / Zlib { host_offset, comp_len }
per-span results with the containing chunk's bounds, so the
arm can walk span-by-span.

### Reader arm shape

Per-chunk walk (chunk sizes vary per entry; chunks are
routinely ≥ chunk-size > chunk_size of the read loop):
* Zero/ignore spans → write zeros.
* Raw spans → capacity-clamped read? **No — EIO parity**: a
  raw span whose bytes lie past EOF must FAIL the read
  (qemu short-pread → EIO), not zero-fill. `return false`
  when the device cannot supply the bytes. This inverts the
  phase 2–4 zero-fill posture and must be commented
  prominently in the arm.
* Zlib spans → read comp_len bytes (byte-accurate,
  possibly unaligned) into compressed_buf, inflate
  **zlib-wrapped** (TINFL_FLAG_PARSE_ZLIB_HEADER — the
  qcow2 helper's first-try flags; NOT the qcow1 raw-only
  call) into staging_buf, verify exact uncompressed length,
  cache the decompressed chunk via the staging cache
  (invalidate `staging_cluster_offset` correctly — and
  since consecutive reads usually hit the same chunk,
  consider keying the cache so re-inflation is avoided
  within a chunk; qemu caches one chunk the same way).
* Gap (no covering chunk, including the koly-wins
  SectorCount tail) → **return false** (EIO parity).
* No backing files in DMG — no chain descent from this arm.

Feature: `dmg-input = ["dep:dmg", "decompress"]` in the
qcow2 crate; enabled by convert/compare/bench/rebase;
`read_offset_sectors` cfg widened; Makefile feature line
extended.

### Fixtures and baselines

Extend `generate-dmg-fixtures.py` (same deterministic
approach). New safe (full baselines + convert parity):

* `dmg-mixed` — one mish mixing zero + raw + zlib + ignore
  + a comment entry + terminator.
* `dmg-multipart` — two mish blocks; convert equals
  concatenation.
* `dmg-rsrc-fork` — the old resource-fork path (no XML).
* `dmg-gap` — koly SectorCount exceeding mish coverage:
  info baselines fine (qemu info rc 0); convert FAILS on
  both sides (qemu EIO, instar clean gap failure) — pinned
  as an error-parity fixture, not a byte-parity one.

New malformed/refused (skip_qemu_img + expected_error):

* `dmg-chunk-len-over` (comp_len = 64 MiB + 1; qemu
  "larger than max (67108864)") and `dmg-sc-over`
  (sector_count 131073; "larger than max (131072)") — qemu
  refuses at open, instar at init.
* `dmg-codec-bzip2`, `dmg-codec-lzfse`, `dmg-codec-adc` —
  instar's typed codec refusals. skip_qemu_img because
  qemu's behaviour is build-dependent (6.0.0 and host
  decode bzip2; the rest EIO) — note this in the manifest
  descriptions.
* `dmg-overcap-chunk` — qemu-LEGAL (sector_count 8192 =
  4 MiB uncompressed zlib chunk) but over instar's staging
  cap: the documented capacity-divergence fixture (qemu
  converts it; instar refuses typed). skip_qemu_img with an
  explicit divergence note.

Existing malformed trailer fixtures keep their manifest
entries; their convert/compare/dd expectations move from
gate-refusal messages to reader-refusal messages in 5e.
Oslo: new safe fixtures get KNOWN_FORMAT_DIVERGENCES
('dmg', 'raw') + vsize entries per the min(file_size,
262144) rule (verify live); malformed → OSLO_SKIP_IMAGES.

### Fuzzing

Coverage-guided: `fuzz_dmg_table` (koly→plist→base64→mish→
table build + lookups; asserts caps, sortedness handling,
and no panics — the plist scanner and lenient base64 are the
juicy attack surface) and `fuzz_dmg_chunk` (arm-level:
lookup + inflate invariants). Differential: qemu-img cannot
create DMG, so `generate_image` gains a dmg branch that
BUILDS images with a ported mini-generator (random chunk
type mixes / multipart / gaps excluded, sizes within caps,
deterministic from the iteration rng) — run convert/dd/
compare differentially; gate op_map and op_measure for
'dmg' (instar's map/measure still treat DMG as raw — the
retained divergence). If the harness makes the custom
builder fragile, 5f may land the fuzz targets and a
REDUCED differential (convert-only) with a comment, but
must state what was dropped. ~200-iteration forced burn-in.

## Out of scope for this phase

* bzip2 (UDBZ) / lzfse (ULFO) / ADC decode support (typed
  refusals instead; master-plan future work — and qemu's
  own support is build-dependent).
* Wiring the koly probe into map/measure/resize and the
  host prefix probes (raw-pass-through stays pinned;
  master-plan future-work bullet remains open).
* Streaming decompression for over-cap chunks (the typed
  refusal + divergence fixture stands in; revisit only if
  real-world images exceed the 2 MiB staging cap).
* DMG write/create/output; encrypted DMGs (a different
  container — FileVault/AES — not part of UDIF chunk
  parsing; detection unaffected).

## Step-level guidance

Steps mirror phase 4; briefs assume the agent reads the
phase-4 plan's corresponding step and the referenced
commits first.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 5a | high | opus | none | New `src/crates/dmg/` crate. Read src/crates/qcow1/ + parallels first for the shape, plus the shared DMG trailer helpers (format_detection.rs:317-363) and probe_dmg_trailer (info op :1474) — factor/reuse the koly window+true-length logic per the Design (shared helpers grow if needed; do NOT duplicate the window math). Implement: koly parse with qemu's exact validated/ignored field sets; path selection (rsrc-fork path AND xml path); the `<data>` string scan; lenient base64 (glib semantics: skip invalid chars; no error on garbage); mish parse per the Situation layout with out_offset/data_offset/DataForkOffset application; qemu's per-chunk caps with exact limits and zero/ignore sector-cap exemption; instar's bounded-memory caps (1 MiB plist stage, 32768-chunk table, 4096-sector/compressed_buf per-chunk staging caps) as DISTINCT typed refusals from qemu's caps; unknown/unsupported codec types (ADC 0x80000004, bzip2 0x80000006, lzfse 0x80000007, zstd 0x80000008, anything else) → typed refusal naming the code; comment/terminator dropped; empty-table refusal (the qemu-segfault case — comment it); sorted-by-sector verification with refusal on unsorted/overlap. `DmgState::init(call_table, dev_idx, sector_size, capacity, scratch_region_ptr/len, bytes_read)` staging the compact chunk table into caller scratch; `chunk_lookup(sector)` returning span-typed results (Zero/Raw/Zlib with host offsets, span bounds). All arithmetic checked; no_std; panic-free. Unit tests (~25+): every koly validation accept/reject; both table paths; lenient-base64 cases (invalid chars skipped, truncated `</data>` refused); mish boundary caps at qemu's exact limits both sides; instar-cap refusals; codec refusals per code; empty table; unsorted refusal; multipart absolute sectors; the out_offset/data_offset arithmetic; lookup walks incl. gap spans. Workspace member; make instar/lint/test-rust clean. |
| 5b | high | opus | none | Guest integration: `dmg-input = ["dep:dmg", "decompress"]` feature; `ChainStates.dmg_states`; init arm (decide + document the scratch placement for the chunk table — read the convert memory-layout compile-assert (src/operations/convert/src/main.rs:100-117) and shared memory map (src/shared/src/lib.rs:324-468); the table budget is ~1.25 MiB (32768 × 40 B) and must not collide with the worst-case layout; extend the compile-assert). Reader arm per the Design: per-chunk walk; Zero/ignore → zeros; Raw → read, but **EIO parity: missing bytes (past capacity, short) → return false, NOT zero-fill — comment prominently that this inverts the phase 2-4 posture**; Zlib → byte-accurate comp_len read into compressed_buf, zlib-WRAPPED inflate (TINFL_FLAG_PARSE_ZLIB_HEADER | NON_WRAPPING — not qcow1's raw-only call) into staging_buf with exact-length verification and staging-cache keying so consecutive reads within one chunk avoid re-inflation (study the staging_cluster_offset semantics; report what you did); Gap → return false; no backing descent. Widen read_offset_sectors cfg; enable feature in convert/compare/bench/rebase; Makefile line. Unit tests (feature-gated, mirroring q1_arm_*): mixed-type chunk walk, zlib chunk cached across two reads (assert single inflation via bytes_read accounting), raw-span EIO on truncation, gap EIO, zero spans, multipart-table reads, over-cap init refusal propagates. Behaviour unchanged this step (no chain variant yet — the #444 gate still refuses; three refusal tests still green). make instar/check-binary-sizes/test-rust/lint; report binary deltas. |
| 5c | high | opus | none | Graduation + pins, separate commits. Commit 1: chain.rs `Dmg` variant + from_str "dmg" + to_shared_format_u32 => 16 + Display "dmg"; bench read_family `Dmg => Some(8)` + doc comment. NO info changes (info already emits dmg correctly; run full test_info_safe to prove zero drift). Commit 2 (pins): delete test_convert_refuses_dmg / compare / dd refusal tests, replacing with dmg-simple convert/compare/dd parity smokes vs qemu-img (the fixture has baselines and .dmg extension so qemu probes it); check on dmg → expect exit 63 "This image format (dmg) does not support checks" (record exact); map/measure/resize raw-pass-through pins UNCHANGED (re-run those three tests; they must still pass — graduation only affects chain-discovery consumers; if any flips, STOP for management review); the existing four malformed trailer fixtures' adversarial convert expectations change from the gate message to reader-init failures — update TestAdversarialDmgManifest accordingly (info expectations unchanged); a dmg-no-chunk-table convert must fail CLEANLY (this is the qemu-segfault case — assert no crash, clean rc). Run the touched suites + full test_info_safe. |
| 5d | high | opus | none | Testdata, mirroring 4d (read its brief/findings; --no-commit posture, --output-type surgical detect-profiles, integrity spot-check; NEVER commit). Extend scripts/generate-dmg-fixtures.py with the eight new fixtures per Design (four safe: mixed, multipart, rsrc-fork, gap; four+ refused: chunk-len-over, sc-over, codec-bzip2/lzfse/adc, overcap-chunk), all byte-deterministic (three-run identical). Validate: safe fixtures info + convert md5 on 6.0.0 AND 10.2.0 (dmg-gap: info rc 0 both, convert rc 1 both — record messages); codec fixtures: record the per-version matrix honestly (bzip2 DECODES on 6.0.0; EIO elsewhere) in the manifest descriptions; overcap-chunk: qemu CONVERTS it fine (it is legal) — record its md5 as the divergence evidence. Baselines for the four safe fixtures (restricted manifest, --no-commit; dmg-gap's baseline meta will record qemu rc 0 for info — fine); detect-profiles + spot-check. Instar-side (only after 5c lands — coordinate with management): manifest entries for the eight (safe run_in_ci; refused skip_qemu_img + expected_error = instar's typed messages, with build-dependence notes for codecs and the capacity-divergence note for overcap); oslo entries: KNOWN_FORMAT_DIVERGENCES ('dmg','raw') + KNOWN_VSIZE_DIVERGENCES per min(file_size, 262144) — verify each pair live in the venv; refused set → OSLO_SKIP_IMAGES. |
| 5e | medium | opus | none | Integration matrix mirroring 4e: convert-to-raw parity for dmg-simple + the three byte-parity safe fixtures (mixed, multipart, rsrc-fork); multipart-equals-concatenation pin; convert dmg-mixed to qcow2 + vpc (flatten-compare); compare dmg-simple vs its raw conversion identical, mixed vs multipart differ; windowed dd crossing a zlib/raw chunk boundary and a zero span (count absolute from 0); dmg-gap: convert AND dd fail non-zero cleanly on both instar and qemu (error-parity, messages differ — comment); adversarial: all refused fixtures (old four + new codec/cap ones) refuse convert/compare/dd non-zero cleanly, no hang, no crash; bench on dmg-simple (header parity); the extensionless-file divergence pin: copy dmg-simple to a non-.dmg name, qemu convert (no -f) treats it as RAW while instar detects dmg — pin both behaviours with a comment citing the plan (qemu probe is extension-only). Full sequential suite matrix (the twelve suites of 4e; build once, then suites one at a time). Isolated re-run before believing any failure. |
| 5f | medium | sonnet | none | Fuzzing mirroring 4f: fuzz_dmg_table + fuzz_dmg_chunk per the Design (the plist scanner + lenient base64 + mish caps are the priority surface; drive both table paths — xml and rsrc-fork — from fuzz bytes); Cargo wiring; make fuzz-build + 60s runs (exec/s, crashes blocking). Differential: generate_image dmg branch using a ported deterministic mini-builder (seeded from the iteration rng: chunk-type mixes zero/raw/zlib, 1-3 mish blocks, chunk sizes within instar caps, NO gaps, valid images only), FORMATS += 'dmg'; gate op_map ('raw','vdi','parallels','qcow','dmg') and op_measure ('vdi','parallels','qcow','dmg') citing this plan (instar map/measure treat dmg as raw — retained divergence); if the builder proves fragile in the harness, land fuzz targets + a convert-only differential and SAY SO. ~200-iteration forced burn-in, zero divergences expected, isolated replay for hits. |
| 5g | medium | sonnet | none | Docs close-out mirroring 4g: format-coverage.md (dmg input row, fixture inventory now 13 dmg images, narrative); quirks.md phase-5 section (EIO-not-zero-fill error semantics; the qemu zero-chunk segfault instar refuses cleanly — upstream-report candidate; codec typed refusals + qemu's build-dependent bzip2; instar's capacity caps + the overcap divergence fixture; extension-only qemu probe vs instar trailer detection incl. the extensionless convert divergence; resource-fork path support; map/measure/resize raw-pass-through retained; lenient base64 parity; koly-wins virtual size); README (dmg read-only input); CHANGELOG; ARCHITECTURE (crates/dmg); master plan row 5 Complete + future-work updates (bzip2/lzfse decode; the qemu segfault upstream report; streaming decompression note) + move the DMG line out of "formats that don't" phrasing where applicable; index.md phases 1-5; this file Status Complete + Findings sections. Consistency grep for stale dmg claims ("detect + info only", the refusal-test names). |

Sequencing: 5a → 5b → 5c strictly (reader before variant);
5d's testdata portion parallel with 5a-5c, its instar-side
edits after 5c; 5e after 5c + 5d; 5f after 5c; 5g last.

## Verification (management-session review checklist)

- [ ] Files that were supposed to change changed (read them);
      no unrelated modifications; testdata reviewed before
      the operator-authorised commit to its main.
- [ ] make instar / lint / test-rust / check-binary-sizes /
      fuzz-build clean; pre-commit clean per commit.
- [ ] Byte parity for dmg-simple/mixed/multipart/rsrc-fork
      convert; multipart == concatenation; error parity for
      dmg-gap (both sides fail, no instar crash on the
      qemu-segfault fixtures).
- [ ] Codec and capacity refusals typed and pinned;
      overcap divergence fixture documented.
- [ ] Info output byte-unchanged (full test_info_safe);
      check rc 63; map/measure/resize raw-pass-through pins
      unchanged.
- [ ] Differential dmg burn-in clean (or the reduced-scope
      fallback explicitly recorded).
- [ ] Commit messages follow conventions.

## Success criteria

Phase 5 is complete when:

* instar convert, compare, dd, and bench read DMG with byte
  parity against qemu-img for zero/raw/ignore/zlib chunk
  images including multipart and the resource-fork path.
* Gap/truncation reads fail cleanly on both sides (EIO
  parity, no zero-fill); the qemu zero-chunk segfault class
  is a clean instar refusal.
* Unsupported codecs and over-cap chunks get typed,
  documented, fixture-pinned refusals.
* Detection/info behaviour is byte-unchanged; check is
  rc 63; map/measure/resize pins unchanged.
* `src/crates/dmg/` exists (no_std, panic-free) with unit +
  fuzz coverage; the differential fuzzer exercises dmg via
  the custom builder (or the recorded reduced scope).
* Docs and the master plan record the new state.

## Hand-off to later phases

* Phase 6 (QED decision) inherits a complete
  convert/compare/dd/bench graduation checklist and the
  reader-before-variant ordering rule; QED's check/map/
  measure behaviour pins should reference qcow1's and dmg's
  rc-63 parity notes.
* Phase 7 (docs) collects the cross-phase divergence tables
  (map/measure scope refusals; dmg capacity caps; codec
  refusals) into the qemu-img-parity axis document.
* Master-plan future work after this phase: bzip2/lzfse
  decode; the qemu zero-chunk segfault upstream report; the
  in-place-op trailer probing bullet remains open.

## Back brief

Before executing any step of this plan, back brief the
operator: confirm the codec scope (zlib/zero/raw/ignore
with typed refusals for the rest), the EIO-parity error
semantics (no zero-fill for gaps/truncation — inverted from
phases 2-4), the bounded-memory caps and their divergence
fixture, the reader-before-variant ordering, that
map/measure/resize keep their raw-pass-through pins, and
that instar-testdata changes are management-reviewed before
the authorised commit to its main.
