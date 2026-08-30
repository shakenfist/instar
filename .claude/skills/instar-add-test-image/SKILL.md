---
name: instar-add-test-image
description: "Add a disk image to the instar integration test suite, safe or malicious, including tests/manifest.json and the handling of expected output. Use when adding a test image or expanding format or edge-case coverage."
---

# Skill: Add Test Image to instar Test Suite

Add a new disk image to the instar integration test suite. Images live in the
`instar-testdata` repository; `tests/manifest.json` in *this* repository is the
inventory that makes them visible to the tests. An image that is not in the
manifest is never opened by anything.

## When to Use

- Adding a new test image to verify instar compatibility
- Adding a malformed or malicious image for security testing
- Expanding test coverage for a specific format or edge case

## The Two Paths

How much work an image needs depends entirely on its safety class, because
only `safe` images are driven automatically:

| Safety | Baselines | How it gets tested |
|--------|-----------|--------------------|
| `safe` | Yes, all 7 profiles | Automatically. `test_info_safe.py` discovers every `safety: safe` manifest entry and multiplies it across profiles |
| `malformed` | No | Only by a test you write by hand |
| `malicious` | No | Only by a test you write by hand |

There is no `caution` level despite what older docs say; the manifest uses
`safe`, `malformed` and `malicious` only.

## Step 1: Gather Image Information

1. **Image location** — path relative to the instar-testdata root
   (e.g. `downloaded/edge-cases/myimage.qcow2`)
2. **Safety classification** — see the table above
3. **Format** — qcow2, vmdk, vhd, vhdx, raw, vdi, parallels, qcow, dmg, luks
4. **Description** — what makes this image interesting. Be specific about the
   property being pinned; these descriptions are the main documentation of why
   a fixture exists
5. **Tags** — searchable tags (e.g. `["qcow2", "backing-file", "v3"]`)

## Step 2: Generate Image ID

Kebab-case, derived from what the image *is*. This ID becomes a filename for
every baseline, so keep it filesystem-safe:

- `cirros-qcow2`
- `osboxes-vmdk-split-sparse`
- `vmdk-path-traversal`

## Step 3: Compute the Hash

```bash
sha256sum ../instar-testdata/<path-to-image>
```

Verified at test time (`tests/base.py:360`). If the image changes without its
baselines being regenerated, the test skips with a clear message rather than
failing with a confusing diff.

## Step 4: Update the Manifest

Add an entry to `tests/manifest.json`:

```json
{
    "id": "<image-id>",
    "path": "<relative-path-in-testdata>",
    "format": "<format>",
    "safety": "<safe|malformed|malicious>",
    "run_in_ci": <true for safe, false for malformed/malicious>,
    "description": "<description>",
    "tags": ["<tag1>", "<tag2>"],
    "sha256": "<sha256-hash-from-step-3>"
}
```

Optional fields, all of which appear in real entries: `skip_qemu_img` (never
generate baselines, even for a `safe` image — use when qemu crashes or when
instar diverges by design), `expected_error`, `generated_by` (the script that
created the fixture), `cve_references`, `unsafe_quirks_required`, `passphrase`,
`data_file`, `instar_unsupported`.

**`instar_unsupported` is for formats qemu-img reads but instar does not
implement yet.** Set it to a human-readable reason. The image stays
`safety: safe` and baselines are still generated, so the parity gap stays
measured; `test_info_safe.py` skips the comparison instead of failing. Reach for
it only when the format is genuinely unimplemented and that fact is recorded in
`docs/format-coverage.md` — never to silence a real regression, and never by
relabelling a benign image's `safety` to dodge the test. Clearing the field is
all that is needed to switch the tests back on once support lands.

**Choosing between `instar_unsupported` and a `KNOWN_*_DIVERGENCES` entry.**
`test_map.py` and `test_measure.py` keep in-module dicts
(`KNOWN_MAP_DIVERGENCES`, `KNOWN_SOURCE_SCANNER_DIVERGENCES`) for gaps where one
command's *output* differs but instar still opens the image. Use those for
per-command divergence. Use the manifest field when instar cannot open the
format at all, so the gap applies to every command at once and would otherwise
have to be repeated in each dict. Note that `test_map.py` and `test_measure.py`
already skip on a non-zero instar exit by design, so a whole-format gap only
turns into a hard failure in `test_info_safe.py`.

**Edit the file as text, not by reserialising it.** `json.dump` will reflow
every `tags` array onto separate lines and produce a 1200-line diff for a
six-entry addition. Insert the new objects before the closing `]` and keep the
existing formatting (4-space indent, `tags` inline on one line).

Older versions of this skill described an `expected_override` field. It does
not exist and never did; the field you want is `expected_error`.

## Step 5: Safe Images — Generate Baselines

Tests do **not** run qemu-img live. They compare instar's output against
baselines captured from all 80 qemu-img builds in
`instar-testdata/qemu-img-binaries/<arch>/`, deduplicated into 7 profiles.

There is nothing to add to `test_info_safe.py` — it calls
`_get_safe_images_from_manifest()` and picks up the new entry automatically. It
also guards on the baseline existing, so a manifest entry without baselines
silently contributes no test cases rather than failing.

### Generate only your image

`generate-baselines.py` has no per-image filter and overwrites every output it
produces, so running it unfiltered rewrites baselines for all ~190 images.
Drive it with a filtered manifest instead:

```bash
cd ../instar-testdata
python3 - <<'PY' > /tmp/manifest-new-only.json
import json
m = json.load(open('../instar/tests/manifest.json'))
keep = {'<image-id>'}
m['images'] = [i for i in m['images'] if i['id'] in keep]
print(json.dumps(m, indent=4))
PY

for cmd in info check compare map measure; do
    python3 scripts/generate-baselines.py --command "$cmd" \
        --manifest /tmp/manifest-new-only.json --no-commit
done
```

Those five commands are what a `safe` image needs; `--manifest` does not change
where output lands, so this produces exactly the new files and touches nothing
else. Confirm with `git status --short expected-outputs` — you want only `??`
lines and zero ` M` lines.

**Always pass `--no-commit`.** The script auto-commits the generated baselines
otherwise.

### Fold raw outputs into profiles

```bash
python3 scripts/detect-profiles.py
```

`generate-baselines.py` writes `<type>/raw/<version>/`; `detect-profiles.py`
groups versions producing identical output into `<type>/profiles/<profile>/`
and rewrites `version-map.json`. The tests read only `profiles/`, so this step
is not optional. It has no image filter — run it after all generation is done
and check the diff.

Watch for a **profile split**: profiles group versions that are identical
across the whole corpus, so a new image that distinguishes two previously
identical qemu versions creates a new profile, and every existing image gains a
baseline copy in it. That is correct behaviour but a large diff, and worth
calling out in the commit message rather than letting it look like churn.

## Step 6: Malformed and Malicious Images

These get **no baselines** — every malformed entry in the manifest has zero,
which is why `--all-images` is not part of the workflow above.

Be aware of what registering one does and does not buy you. `expected_error` is
parsed into the `TestImage` dataclass (`tests/helpers/types.py:20`) but no test
asserts against it; it is documentation of the contract, not an executable one.
`tests/test_info_malicious.py` is a stub whose `scenarios` list is entirely
commented out, so it always skips. There is no `tests/expected_outputs/`
directory.

So a manifest entry alone makes the image *registered and hashed*, not
*tested*. To actually exercise it, write an explicit test method alongside the
existing hand-written ones in `tests/test_adversarial.py`, following the local
pattern (`test_info_compression_bomb_zlib`, `test_check_chain_circular_2`, …).

**Never run qemu-img on a `malicious` image.** That is the entire point of
instar. Malformed images are safe to run qemu-img against — that is how the AFL
fixtures were characterised — but they still get no baselines.

## Step 7: Run the Tests

```bash
make test
```

For a safe image, verify your new scenarios actually appeared rather than
being silently skipped — a missing baseline produces no test case and no error.

## Step 8: Document Any Quirks Discovered

If the image reveals qemu-img behaviour that required compatibility work:

1. Create `docs/image_notes/<image-id>.md` — the values that revealed it, how
   qemu-img behaves, how instar now behaves.
2. Update `docs/quirks.md` if the quirk is new, including `--ignore-quirks`
   behaviour.
3. Add the image to `docs/image_notes/README.md`.

## Step 9: Verify Nothing Else Broke

```bash
make test
```

If existing images fail after a compatibility change, that is a regression, not
a baseline problem — do not regenerate baselines to make a failure go away.

If your *new* image fails because instar does not implement its format at all,
that is not a regression either. Confirm the gap is real (read the error back to
the source — for VMDK descriptors, `src/vmm/src/chain.rs`), record it in
`docs/format-coverage.md`, and mark the entry `instar_unsupported`. Registering
a fixture ahead of support is deliberate: the baselines are what a future
implementation gets graded against.

## Gotchas

**Fields normalised before comparison.** Do not chase diffs in these:

- `disk size` / `actual-size` is substituted from the live filesystem
  (`tests/helpers/comparators.py:111`), because it is allocation state, not a
  format decision. Baseline values for it are cosmetic.
- vmdk `cid`/`parent-cid`, the dirty flag and vhdx log-size are stripped by
  `assert_info_equivalent`. A vmdk content ID is a random nonce.

**`generate-baselines.py` resparsifies `downloaded/` before running** (not
`custom/`). It rewrites allocation, never content, so pinned hashes survive —
but it is why `custom/` fixtures accumulate `disk size` drift against their
baselines while `downloaded/` ones do not.

**Multi-file images.** Formats with external extents (vmdk `twoGbMaxExtent*`,
`monolithicFlat`) resolve extent filenames relative to the descriptor. Keep the
extent filenames exactly as the descriptor names them; rename the containing
directory if you need a friendlier path. `osboxes-vmdk-split-sparse` is the
worked example, and its extent names contain spaces.

**Paths with spaces** work throughout — the generator uses `subprocess.run`
argument lists, never `shell=True`.

## Output Profiles

Seven profiles, regenerated by `detect-profiles.py`; treat this list as
illustrative and read `version-map.json` for the current grouping:

`profile-6-0-0`, `profile-6-1-0`, `profile-7-2-19`, `profile-8-0-0`,
`profile-8-1-0`, `profile-10-0-0`, `profile-10-2-0`

Adjacent profiles often differ *only* in normalised fields, so a profile
mis-assignment stays invisible to the assertions until a genuinely
version-gated field changes. See `docs/output-formats.md`.

## Key Files

| File | Purpose |
|------|---------|
| `tests/manifest.json` | Test image inventory — the entry point for everything |
| `tests/test_info_safe.py` | Safe images; auto-discovers from the manifest |
| `tests/test_adversarial.py` | Hand-written tests for malformed/malicious images |
| `tests/test_info_malicious.py` | Stub, currently always skips |
| `tests/helpers/types.py` | `TestImage` dataclass — the authoritative field list |
| `tests/helpers/comparators.py` | Normalisation applied before comparison |
| `tests/base.py` | Manifest loading, hash verification, baseline lookup |
| `docs/testing.md` | Fuller testing documentation |
| `docs/image_notes/` | Per-image documentation of quirks discovered |
| `instar-testdata/scripts/generate-baselines.py` | Captures raw baselines |
| `instar-testdata/scripts/detect-profiles.py` | Folds raw into profiles |
| `instar-testdata/expected-outputs/` | Stored baselines, raw and per-profile |
| `instar-testdata/README.md` | Per-image provenance and manifest-id index |
