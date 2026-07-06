# PLAN-bench phase 04: host CLI

## Prompt

Before responding to questions or discussion points in this
document, explore the instar codebase thoroughly. Read relevant
source files, understand existing patterns (the clap arg structs
and dispatch in `src/vmm/src/main.rs`, bitmap's guest-launch and
harvest loop, convert's read-only chain attach, the hand-built
JSON renderers), and ground your answers in what the code
actually does today. The authoritative output/validation contract
is the **captured qemu-img 10.0.8 message contract** in
[PLAN-bench-phase-01-crate.md](PLAN-bench-phase-01-crate.md)
(step 1e) — read it in full before writing any message string.
Do not speculate when you could read instead; flag uncertainty
explicitly.

Phase plans for the parent master plan live alongside it in
`docs/plans/`. The master plan is [PLAN-bench.md](PLAN-bench.md).
This is the fourth of eight phases; phases 1-3 landed the
schedule crate, the ABI (call-table VERSION 20), and the guest
read op (`bench.bin`).

I prefer one commit per logical change, and at minimum one commit
per phase. Each commit should be self-contained: it should build,
pass tests, and have a clear commit message explaining what
changed and why.

## Situation

This phase makes `instar bench` runnable: `BenchArgs`, the
qemu-parity validation surface, `run_bench` (chain discovery,
read-only attach, config population, launch, the host half of the
timing bracket, output rendering, `--output json`), and the
**first end-to-end smoke verification** against the local
qemu-img 10.0.8.

Grounding (surveyed on the current tree; all line numbers in
`src/vmm/src/main.rs` unless noted):

- **Assembly model**: bench's host side = bitmap's single-result
  guest-launch/harvest shape (`run_bitmap_guest`, :6284 — the
  leanest single-input template: KVM setup :6308-6548, vcpu loop
  :6571-6657, `result_seen` tracking :6561/:6670, error mapping
  via `map_bitmap_error` :5536) grafted onto convert's
  **read-only chain attach** (`discover_backing_chain` :2126 →
  `open_chain_devices` :2372, which opens `BackingStore::open(...,
  true /* read-only */, ...)` and attaches each chain image as an
  input device; `write_chain_config` :2546). Bench has **no
  output device** (`vmm_config_input_only`, :6557).
- **Chain discovery takes no format hint** — it walks backing
  files by running the sandboxed info op per image and
  auto-detects. dd's posture for `-f` is warn-then-ignore
  (:11337-11343). `BenchConfig.target_format` is therefore set
  from the *discovered* top format; the guest's family
  cross-check still guards host/guest disagreement.
- **Timing**: `Instant` is not currently imported in `main.rs`;
  `VmmStats.start_time` is private and measures whole-VM runtime
  — bench needs its own `use std::time::Instant`. The phase-2 ABI
  contract (doc on `send_bench_start` in `src/shared/src/lib.rs`)
  requires: start captured on `BenchStart` arrival, **elapsed
  captured on `BenchResult` arrival** — both inside the vcpu
  loop's serial-decode arms, never after HLT, so post-result
  teardown vmexits stay outside the bracket. `BenchResult` may
  arrive without a preceding `BenchStart` (pre-loop guest
  failure): `start` is an `Option`, and that path renders the
  error with no timing line.
- **Size parsing**: `parse_qemu_img_size` (:476-497) is the
  qemu-suffix parser (`b/k/K/m/M/g/G/t/T/p/P/e/E`, plain bytes)
  already used by dd and bitmap — bench uses it for `-s`/`-S`/
  `-o`. Plain integers (`-c`, `-d`, `--flush-interval`,
  `--pattern`) parse via string capture + explicit range check
  (NOT typed clap fields — qemu's out-of-range message must be
  produced by *our* check, not clap's, and negative values must
  reach our check to collapse into the same message per the 1e
  capture).
- **Refusal idioms**: `--image-opts` runtime rejections exist in
  resize/bitmap/map/snapshot (e.g. :5348); `-U`/`--force-share`
  is an accepted no-op for read-only modes (snapshot :3059,
  :12567); there is **no `-t`/`-i`/`-n` handling anywhere yet**
  — bench introduces the cache/aio postures per master-plan OQ6.
  House error style: `return Err("...".into())` from `run_*`;
  `main` propagates → `Error: ...` on stderr, exit 1.
- **JSON**: hand-built `println!` with `escape_json_string`
  (:1803); the human-vs-json fork per `print_measure_result`
  (:9068). No serde.
- **Binary resolution**: `get_binary_path("bench.bin")`
  (:1856; `INSTAR_BIN_DIR` → exe dir → `/usr/lib/instar`).
- **The 1e capture** (phase-01 plan) pins: the eight qemu
  message texts, check precedence (qemu bound before instar cap —
  invocation 5), header printed unconditionally once the image
  opens (even when the first request will fail — invocation 19,
  zero-byte image), `-S 0` rendered as the effective step
  (invocation 24), `-o` suffix values echoed as decimal bytes
  (invocation 18), completion line `%.3f` precision, exit 1 on
  every failure.

## Mission

### 1. CLI surface (`BenchArgs`)

```
instar bench [-c COUNT] [-d DEPTH] [-f FMT] [--flush-interval NUM]
             [-i AIO] [-n] [--no-drain] [-o OFFSET] [--pattern NUM]
             [-q] [-s BUFFER_SIZE] [-S STEP_SIZE] [-t CACHE] [-w]
             [-U] [--image-opts] [--output human|json] FILENAME
```

clap notes: filename as `Vec<String>` (trailing positional,
`num_args(0..)`) so *we* own the count check and can reproduce
qemu's message; `-c/-d/--flush-interval/--pattern/-s/-S/-o` all
as `Option<String>` (parsed and range-checked by our code);
`-w/-q/-U/-n/--no-drain/--image-opts` as bools; `-i AIO` and
`-t CACHE` as `Option<String>`; `--output` with
`value_parser = ["human", "json"]` (house idiom). `-w` is
**accepted by the parser** but `run_bench` refuses it in phase 4
with `bench: write tests (-w) are not yet supported` — phase 5
removes that refusal (declaring the flag now keeps the phase-5
diff additive and the help text complete; the refusal is a
temporary instar-only message, recorded for the phase-6
divergence registry).

### 2. Validation: exact messages, exact precedence

A `validate_bench_args` helper (pure, unit-testable) produces
either a validated parameter set or the error string. Messages
come from the 1e capture **byte-for-byte** (bare qemu text, no
`bench:` prefix, so the phase-6 parity tests compare cleanly;
instar-only refusals below DO carry the `bench:` prefix to mark
them as instar postures):

Each numeric option has TWO failure forms (Supplement 2 of the
1e capture — the original "parse failures collapse into the range
message" assumption was disproven during 4a and is corrected
here): an **unparseable** value produces the value-echoing form
`Invalid <name> specified: '<value>'.`, an out-of-range *number*
produces the `Must be between` form. Display names: `request
count`, `queue depth`, `buffer size`, `step size`, `offset`,
`pattern byte`, `flush interval`.

| Check (in order) | Message |
|---|---|
| `-c` unparseable | `Invalid request count specified: '<v>'.` |
| `-c` < 1 / > 2147483647 | `Invalid request count specified. Must be between 1 and 2147483647.` |
| `-d` unparseable / out of range | `Invalid queue depth specified: '<v>'.` / `Invalid queue depth specified. Must be between 1 and 2147483647.` |
| `-s` unparseable | `Invalid buffer size specified: '<v>'.` |
| `-s` < 1 / > 2147483647 (qemu bound FIRST) | `Invalid buffer size specified. Must be between 1 and 2147483647.` |
| `-s` in qemu range but > `BENCH_MAX_BUFSIZE` (2 MiB) | `bench: buffer sizes above 2 MiB are not yet supported` |
| `-S` unparseable / > 2147483647 (0 is valid) | `Invalid step size specified: '<v>'.` / `Invalid step size specified. Must be between 0 and 2147483647.` |
| `-o` unparseable / negative / > i64::MAX | `Invalid offset specified: '<v>'.` / `Invalid offset specified. Must be between 0 and 9223372036854775807.` |
| `--pattern` unparseable / outside [0, 255] | `Invalid pattern byte specified: '<v>'.` / `Invalid pattern byte specified. Must be between 0 and 255.` |
| `--flush-interval` unparseable / outside [0, 2147483647] | `Invalid flush interval specified: '<v>'.` / `Invalid flush interval specified. Must be between 0 and 2147483647.` |
| **nonzero** flush interval without `-w` (`--flush-interval 0` without `-w` is silently fine — verified live; the check gates on the value, matching the crate's `FlushRequiresWrite`) | `--flush-interval is only available in write tests` |
| nonzero flush interval < depth | `Flush interval can't be smaller than depth` |
| filename count ≠ 1 | `Expecting one image file name` + second line `Try 'instar bench --help' for more info` (hint line names instar, not qemu-img — divergence-registry entry) |

The flush-interval range check fires before the cross-option
rules (verified live). Where
`BenchParams::validate` covers a rule (count/depth/bufsize/step
ranges, the two cross-option rules, the cap ordering), call it
and map `BenchParamError` → the table; host-only rules (pattern
range pre-u8, offset bound, filename count) are checked directly.

Instar-only postures (all `bench:`-prefixed, all exit 1, all
recorded for the divergence registry):

- `-t writeback` accepted silently (qemu's default); `-t` with
  another *valid qemu cache mode* (`none`, `writethrough`,
  `directsync`, `unsafe`) → `bench: cache mode '<v>' is not yet
  supported`; `-t` with anything else → `Invalid cache mode`
  (qemu's own text, invocation 11).
- `-i <anything>` → `bench: aio backend '<v>' is not yet
  supported`; `-n` → `bench: native AIO (-n) is not yet
  supported`.
- `--image-opts` together with `-f` → `--image-opts and --format
  are mutually exclusive` (qemu parity, invocation 14);
  `--image-opts` alone → `bench: --image-opts is not yet
  supported` (house posture).
- `-q` and `-U`: accepted no-ops (qemu's `-q` is a no-op for
  bench per the phase-1 verification; instar has no locking).
- `-f`: dd's warn-then-ignore (`bench: -f <v> is accepted but
  ignored; the input format is auto-detected`) **only when the
  hint disagrees with the discovered format**; silent when it
  matches (the common `-f raw`/`-f qcow2` invocations stay
  clean).

### 3. Output rendering (pure helpers, unit-tested)

- Header: `Sending {count} {read|write} requests, {bufsize} bytes
  each, {depth} in parallel (starting at offset {offset}, step
  size {step})` — offset as the parsed decimal byte value, step
  as the **effective** step (`-S 0` → bufsize; invocation 24),
  `{read|write}` from `-w`. Byte-identical to qemu for equal
  arguments.
- Optional `Sending flush every {n} requests` when
  flush-interval is nonzero (write tests only — unreachable in
  phase 4, but the renderer supports it now; phase 5 just stops
  refusing `-w`).
- Completion: `Run completed in {:.3} seconds.`
- Print order: header (+ flush line) go to stdout **after
  discovery/validation succeed and before the guest launches** —
  mirroring qemu, which prints them before submitting requests
  (and unconditionally even when the first request will fail,
  invocation 19). Boot time between header and completion is
  excluded from the bracket anyway.
- `--output json` **replaces** the three human lines entirely
  (master-plan OQ11; the default path is byte-parity with qemu
  and nothing else). Schema (hyphenated keys, hand-built JSON,
  `escape_json_string` for the filename/format):

  ```
  {
    "filename": ..., "format": ...,
    "count": N, "depth": N, "effective-depth": 1,
    "buffer-size": N, "step-size": N(effective), "offset": N,
    "write": false, "pattern": N,
    "flush-interval": N, "no-drain": bool, "flushes-issued": N,
    "elapsed-seconds": {:.6},
    "requests-per-second": {:.2}, "bytes-per-second": {:.2}
  }
  ```

  Derived rates are **included** (OQ11 resolved: the
  perf-tracking consumer wants them; recomputation invites
  rounding drift). `elapsed-seconds` carries µs precision — the
  human line's `%.3f` rounding is a qemu-parity constraint, not
  an information ceiling.

### 4. `run_bench` / `run_bench_guest`

`run_bench`: validate per §2 → `discover_backing_chain` (auto
detect; `-f` posture per §2) → print header (+ flush line) or
defer to JSON → `run_bench_guest` → render.

`run_bench_guest` (clone `run_bitmap_guest`, swap attach):
core.bin + bench.bin via `get_binary_path`; KVM/memory/vcpu setup
per the bitmap template; `open_chain_devices` read-only,
input-only (no output device); `write_chain_config`; write
`BenchConfig` **field-by-field at explicit byte offsets** with an
offset map comment (bitmap's :6277-6302 idiom) — magic 0x424E4348
@0, flags @4 (FLAG_NO_DRAIN from `--no-drain`; FLAG_VERBOSE per
house convention; never FLAG_WRITE in phase 4), count @8, depth
@12, bufsize @16, step @24 (raw, 0 preserved), offset @32,
flush_interval @40, pattern @44, target_format @48 (discovered
top format as u32), sector_size @52 — then zero `_reserved`.
`sector_size` and the attach sector size are **the same value
convert's input path uses** (do not invent a bench-special
value; record what it is in the 4c measurements — it is part of
the measurement's definition).

vcpu loop arms (bitmap's loop + two payload arms):

```rust
Some(Payload::BenchStart(_))  => { bench_start = Some(Instant::now()); }
Some(Payload::BenchResult(r)) => {
    elapsed = bench_start.map(|s| s.elapsed());   // captured AT ARRIVAL
    harvested = ...; result_seen = true;
}
```

After the loop: `vm_error` → Err; `!result_seen` → `bench: guest
did not return a result`; `harvested.error != ERROR_OK` → map
via `map_bench_error` and exit 1 — with **`ERROR_IO_READ`
rendering as `Failed request: Input/output error`** (bare, qemu
parity with invocation 19; the header has already printed on
stdout by then, reproducing qemu's exact zero-byte-image
transcript). Other codes get instar-worded `bench:` messages
(bad config, unsupported format, parse failed). Success: human →
completion line from `elapsed` (missing `elapsed` with
`ERROR_OK` is a guest contract violation → error, not a zero
timing); json → §3 object with `flushes-issued` from the result.

### 5. Resolved open questions

- **OQ6 (`-t`/`-i`/`-n`)**: accept `-t writeback` silently;
  refuse valid-but-unsupported cache modes, all `-i`, and `-n`
  with `bench:`-prefixed not-yet-supported messages; qemu's own
  `Invalid cache mode` text for unknown `-t` values (§2).
- **OQ11 (JSON schema)**: §3's schema, derived rates included,
  json replaces human output entirely.

## Steps

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 4a | medium | sonnet | none | The pure layer: `BenchArgs` (clap surface per §1, NOT yet added to `Commands`), `validate_bench_args` implementing §2's table exactly (calling `bench::BenchParams::validate` where it applies), the §3 renderers (header/flush/completion/json as pure functions), and `#[cfg(test)]` unit tests in main.rs pinning every message string byte-for-byte against the 1e capture plus header-rendering cases (effective step, offset decimal, read/write word, filename-count message). Mark the new items `#[allow(dead_code)]` with a `// wired in 4b` note so the commit is warning-clean. Gates: make lint + make test-rust. Commit 1. |
| 4b | high | opus | none | Wire it end-to-end per §4: `Commands::Bench` + dispatch arm, `run_bench`, `run_bench_guest` (bitmap template + convert's read-only chain attach, input-only), the BenchConfig field-by-field write with offset-map comment, the two vcpu-loop payload arms with arrival-time Instant capture, error mapping incl. the `Failed request: Input/output error` parity path, human/json fork, removal of 4a's allow(dead_code). High effort: the bracket capture points are the product's semantics and the attach/config plumbing crosses the KVM boundary. Gates: make instar + lint + test-rust; plus a minimal manual run (`instar bench -c 100 <raw image>`) proving the three-line transcript works. Commit 2. |
| 4c | medium | sonnet | none | The smoke verification (documented, not pytest — phase 6 owns the test suite). Against the local qemu-img 10.0.8 and scratch images: header BYTE-parity for identical args across defaults / `-o 1k` / `-S 0` / `-s 65537` (multi-transfer) / `-d 1` / qcow2 with backing chain / compressed qcow2 / vmdk / vhd / vhdx; completion-line shape (`Run completed in \d+\.\d{3} seconds\.`); exit codes and message parity for the §2 table including the `-c abc` parse-failure assumption; the zero-byte-image transcript (header then Failed request, exit 1); `--output json` well-formedness (python -m json.tool). Append a `## Captured smoke results (step 4c)` section to this plan (per-invocation, qemu vs instar), including the attach sector_size value per §4, update the master plan row + index, pre-commit. Any parity mismatch is a stop-and-report, not a silent fix. Commit 3. |
