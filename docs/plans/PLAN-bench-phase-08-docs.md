# PLAN-bench phase 08: docs

## Prompt

Before responding to questions or discussion points in this
document, explore the instar codebase thoroughly. Read relevant
source files, understand existing patterns (`docs/bitmap.md` as
the per-subcommand guide template, the CHANGELOG/README/AGENTS
wiring the bitmap phase-10 commit `30d43e7` performed), and
ground your answers in what the code actually does today. The
factual content comes from the completed phases' capture
sections and the shipped code — never from memory of what was
planned. Do not speculate when you could read instead.

Phase plans live alongside the master plan
([PLAN-bench.md](PLAN-bench.md)) in `docs/plans/`. This is the
eighth and final phase; completing it closes the master plan and
the 15/15 qemu-img parity roster.

I prefer one commit per logical change, and at minimum one commit
per phase. Each commit should be self-contained: it should build,
pass tests, and have a clear commit message explaining what
changed and why.

## Situation

Surveyed grounding:

- **Template**: `docs/bitmap.md` (334 lines) is the newest
  per-subcommand guide — title + framing prose, `## Synopsis`
  with an options block, content sections, `## Refusals and
  errors` as host-side/guest-side tables with **verbatim**
  messages, `## Known divergences` as prose bullets each naming
  its `KNOWN_*_DIVERGENCES` registry key, `## Examples` with
  `$`-prefixed transcripts including refusals, `## Future work`,
  and a closing see-also paragraph pointing at the code.
- **Wiring surface** (the bitmap phase-10 pattern, commit
  `30d43e7`): `docs/index.md` guide row; `docs/usage.md`
  `### bench` under `## instar Operations` (after `### bitmap`,
  ~line 1002; the Ceph invocation at `:510` — `qemu-img bench -f
  qcow2 -w -c 65536 -d 16 --pattern 65 -s 4096` — is the
  real-world example bench emulates); `README.md` Project-Status
  prose list (~:29, bench absent) + guide-links block (~:34) +
  optionally a `## Usage` block; `AGENTS.md` ops tree comment
  (~:20), `### Operations` bullet, and the test-file list
  (~:314, `tests/test_bench.py` missing); `CHANGELOG.md`
  `### Added` entry in the bitmap style (bold lead naming the
  plan + phase range, feature prose, coverage, the VERSION bump,
  doc link).
- **ARCHITECTURE.md is stale in two ways this phase fixes**:
  the `### Guest Memory Map` (~:623-646) still shows the
  pre-2026-07-06 layout (core 64 KiB at 0x10000, ops 384 KiB at
  0x20000) — it must be rewritten for the lifted map (core
  128 KiB [0x10000, 0x30000), ops 768 KiB [0x30000, 0xF0000),
  data pages at 0xF0000, guard gap to VQ_BASE_START 0x100000 —
  source of truth: `src/shared/src/lib.rs`'s constants and the
  `3a5e1e2` commit message); and the call-table VERSION prose
  (~:571) stops at 19 — bench appended `send_bench_start`/
  `send_bench_result` at VERSION 20 (`8ca0dc6`). Plus the
  missing `operations/bench/` bullet (bench.bin 160224 B).
- **Close-out convention**: the completed master-plan row in
  `docs/plans/index.md` reads like bitmap's (`Complete (phases
  1-10): ...` summary + all phase links ✓); the master plan's
  own Execution row 8 and the Success criteria section are the
  final tick-through. `order.yml` already lists PLAN-bench.md —
  no edit.
- **`docs/openstack-announcement-email.md` is a frozen
  pre-release draft** (its roster description predates dd) —
  it is NOT updated; `docs/bench.md` carries the reproducible
  sandbox-overhead methodology that email's claim lacked.

## Mission

### 1. `docs/bench.md` (the substantive artifact)

Bitmap-template structure with bench-specific content. Required
sections and their load-bearing points:

- **Title + framing**: `# instar bench — benchmark the sandboxed
  I/O path`. The honest reframing up front: instar bench does
  NOT measure what qemu-img bench measures (qemu's block layer
  over the page cache); it measures **instar's own end-to-end
  sandboxed path** (guest format layer → virtio-block →
  ioeventfd → host I/O thread → file I/O), and running both
  tools on the same image with the same arguments IS the
  reproducible sandbox-overhead measurement.
- **Synopsis + options** (fenced blocks; the full accepted
  surface incl. the no-ops `-q`/`-U` and the dd-style `-f`
  posture).
- **What the number means** (the section the master plan names):
  the timing bracket (host wall-clock between the guest's
  start marker — emitted after all setup, mirroring qemu's
  gettimeofday placement — and the result message; boot, image
  open, and table loads excluded), and the measurement caveats,
  each stated plainly:
  - `-d` is echoed for output parity but execution is serial
    (`effective-depth: 1` in JSON); the guest driver is
    synchronous single-buffer.
  - the virtio transport granularity is 64 KiB sectors —
    sub-sector requests RMW through covering sectors; one bench
    request may be several virtio round trips.
  - write tests: per-touched-cluster metadata decisions read
    L1/L2 uncached from disk, and refcount write-back is
    concentrated at flush points and run end, all inside the
    bracket — qemu amortises metadata through its cache, so
    write timings are not like-for-like at fine grain.
  - numbers are comparable across instar versions on the same
    host/image (the perf-regression use), and instar-vs-qemu on
    the same invocation is the sandbox-overhead measurement;
    nothing else is comparable.
- **Sandbox-overhead methodology**: a worked example (both
  tools, same image, `-c`/`-s` chosen, repeat N times, compare
  medians), with the honest note about which caveats apply.
- **Write tests (`-w`)**: the destructive warning (mutates the
  image in place with no confirmation, matching qemu); the
  raw+qcow2 v1 envelope and the guest-side gate table (verbatim
  refusal messages + `error_detail` gate reasons from
  `map_bench_error`); the qcow2 write-back design in one
  paragraph (write-through L2/L1 data-first, refcounts staged
  and last — a crash mid-bench leaves repairable leaks, never
  dangling pointers); overlay COW correctness.
- **Refusals and errors**: host-side table (the §2 validation
  messages incl. echo/range forms, cache/aio/image-opts
  postures) and guest-side table (unsupported format, parse
  failed, Failed request, the write gates) — verbatim strings
  from the phase-4/5 captures.
- **`--output json`**: the schema table (all keys, the fixed
  `effective-depth`, derived rates, µs-precision
  elapsed-seconds) and a note that the human path is byte-parity
  with qemu and json replaces it entirely.
- **Known divergences from qemu-img bench**: prose bullets, one
  per `KNOWN_BENCH_DIVERGENCES` entry (11), each naming the
  registry key and quoting the messages, in the bitmap style.
- **Examples**: default read run; the Ceph-style write
  invocation (adapted from usage.md:510, with the
  serialized-depth note); `--flush-interval`; `--output json`;
  two refusal transcripts (a validation error and a write gate).
- **Future work**: from the master plan — true queue depth
  (guest driver rework), TSC-based per-request latencies,
  `-t none`/O_DIRECT, vmdk/vhd/vhdx writes, the CI perf-tracking
  job consuming `--output json`, buffers above 2 MiB, an
  explicit host-path measurement mode.
- Closing see-also: `src/crates/bench/`, `src/operations/bench/`,
  `tests/test_bench.py`'s registry, `[usage](usage.md)`.

### 2. The wiring sweep

Per the Situation checklist: `docs/index.md` row;
`docs/usage.md` `### bench` section (fenced synopsis, the Ceph
caller tie-in, the read-all-formats/write-raw-qcow2 restriction,
`See [docs/bench.md](bench.md)...`); `README.md` (prose list +
guide link + a short `## Usage` block mirroring dd's); `AGENTS.md`
(tree comment, Operations bullet, test list); `CHANGELOG.md`
`### Added` (bitmap-style: plan + phases 1-8, the reframed
measurement in one sentence, read formats and the raw+qcow2
write envelope, VERSION 19→20 for the two appended senders, the
62-test suite + two fuzz surfaces, `docs/bench.md` link — plus
mention the memory-map lift and the vmdk-flat info fix if the
Unreleased section doesn't already carry them: CHECK and add
under the right heading if missing, they shipped on this
branch); ARCHITECTURE.md (the `operations/bench/` bullet, the
VERSION-20 prose, and the **memory-map rewrite** — verify every
number against `src/shared/src/lib.rs`, not the plans).

### 3. Close-out

Walk the master plan's **Success criteria** list item by item,
verifying each against the shipped tree (suite counts, binary
sizes, the fuzz registrations, the doc files) — annotate the
master plan's Execution row 8 → Complete and flip the top-line
if any; `docs/plans/index.md` bench row → the bitmap-style
`Complete (phases 1-8): ...` summary ending with the
roster-closing sentence (instar now implements all 15 qemu-img
subcommands). `order.yml` needs no edit (verify). The email doc
stays frozen.

## Steps

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 8a | high | sonnet | none | Write `docs/bench.md` per Mission §1 (bitmap.md's structure; every message/number verified against the shipped code and the phase-4/5 capture sections — verbatim strings, real sizes, the actual JSON keys from render_bench_json) + the `docs/index.md` row + the `docs/usage.md` section. High effort for the "what the number means" honesty — this section is the plan's raison d'être and must be accurate about every caveat. pre-commit. Commit 1. |
| 8b | medium | sonnet | none | The wiring sweep per Mission §2: README, AGENTS, CHANGELOG (checking whether the memory-map lift and vmdk-flat fix already have entries), and the ARCHITECTURE.md updates including the stale memory-map rewrite verified against src/shared/src/lib.rs constants. pre-commit; make lint/test-rust unaffected but run to confirm. Commit 2. |
| 8c | low | sonnet | none | Close-out per Mission §3: success-criteria walk (report each criterion → evidence), master plan row 8 + index → Complete with the roster-closing summary, order.yml verified untouched. pre-commit. Commit 3 — the plan-closing commit. |
