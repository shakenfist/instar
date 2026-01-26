# Skill: Add Test Image to imago Test Suite

Add a new disk image to the imago integration test suite. This skill handles
both safe images (compared against stored baseline outputs) and malicious images
(compared against stored expected output files).

## When to Use

- Adding a new test image to verify imago compatibility
- Adding a malicious/crafted image for security testing
- Expanding test coverage for a specific format or edge case

## Process Overview

### Step 1: Gather Image Information

Ask the user for:
1. **Image location** - Path relative to imago-testdata root (e.g., `downloaded/edge-cases/myimage.qcow2`)
2. **Safety classification**:
   - `safe` - Known-good image, can run qemu-img on it
   - `caution` - Potentially problematic, test in isolation
   - `malicious` - Known exploit/attack image, never run qemu-img
3. **Format** - qcow2, vmdk, vhd, vhdx, raw, etc.
4. **Description** - What makes this image interesting for testing
5. **Tags** - Searchable tags (e.g., `["qcow2", "backing-file", "v3"]`)

### Step 2: Generate Image ID

Create a kebab-case ID from the description:
- `cirros-qcow2` for CirrOS QCOW2 image
- `qcow2-backing-passwd` for QCOW2 with /etc/passwd backing file
- `vmdk-monolithic-sparse` for monolithicSparse VMDK

### Step 3: Update Manifest

Add entry to `tests/manifest.json`:

```json
{
    "id": "<image-id>",
    "path": "<relative-path-in-testdata>",
    "format": "<format>",
    "safety": "<safe|caution|malicious>",
    "run_in_ci": <true for safe, false for malicious>,
    "description": "<description>",
    "tags": ["<tag1>", "<tag2>"]
}
```

For malicious images, also add:
```json
    "expected_override": "expected_outputs/<image-id>.txt"
```

### Step 4: For Safe Images - Generate Baseline Outputs

Safe images are tested against stored baseline outputs in the `imago-testdata`
repository. The test suite iterates all known output profiles (qemu-img version
groups) and verifies that imago produces matching output for each profile.

**Important**: Tests do NOT run qemu-img live. They compare against pre-generated
baselines stored in `imago-testdata/expected-outputs/`.

1. **Add to test_images list** in `tests/test_info_safe.py`:
   ```python
   test_images = [
       'cirros-qcow2',
       'qcow2-v2',
       '<image-id>',  # Add your new image
   ]
   ```

2. **Generate baseline outputs** in the `imago-testdata` repository:
   - For each profile (profile-6-0-0, profile-8-0-0), run qemu-img on the image
     using a qemu-img version that matches that profile
   - Store outputs in `expected-outputs/qemu-img-human/profiles/<profile>/<image-id>.stdout.txt`

3. **Alternatively**, run the baseline generation scripts in imago-testdata:
   ```bash
   cd ../imago-testdata
   ./scripts/capture-outputs.sh
   ./scripts/generate-profiles.sh
   ```

### Step 5: For Malicious Images - Create Expected Output

**CRITICAL**: Never run qemu-img on malicious images.

1. Run `imago info` on the image to get output:
   ```bash
   ./src/target/release/imago info <path-to-image>
   ```

2. Verify the output is correct (format detected, backing files reported, etc.)

3. Save to `tests/expected_outputs/<image-id>.txt`

4. Add scenario to `tests/test_info_malicious.py`:
   ```python
   scenarios = [
       # ... existing scenarios ...
       ('<image-id>', {'image_id': '<image-id>'}),
   ]
   ```

### Step 6: Run Tests

```bash
# For safe images
make test

# For malicious images (explicit opt-in)
make test-malicious
```

### Step 7: Verify Output Matches

For safe images, the test iterates all output profiles and compares imago output
(when run with `--qemu-version X.Y`) against stored baseline outputs.
Any difference fails the test.

For malicious images, the test compares imago output against the stored
expected output file.

### Step 8: Document Any Quirks Discovered

If the test reveals unexpected qemu-img behavior that required compatibility
work in imago:

1. **Create image notes** in `docs/image_notes/<image-id>.md`:
   - Document the specific values that revealed the behavior
   - Explain how qemu-img handles the case
   - Explain how imago now handles it
   - Link to relevant quirks documentation

2. **Update docs/quirks.md** if this is a new quirk:
   - Document the observed behavior
   - Explain the root cause (if known)
   - Document imago's default behavior
   - Document `--ignore-quirks` behavior

3. **Update docs/image_notes/README.md** to add the new image to the index

See existing files like `docs/image_notes/qcow2-v2.md` for examples.

### Step 9: Verify All Tests Still Pass

After making any changes to support the new image, run the full test suite
to ensure existing images still pass:

```bash
make test
```

If any existing tests fail after your changes, you may have introduced a
regression. Check that your compatibility fix doesn't break other images.

## Example: Adding a Safe Image

```
User: Add the CirrOS 0.6.3 image to the test suite

1. Image path: downloaded/cirros/cirros-0.6.3-x86_64-disk.img
2. Safety: safe
3. Format: qcow2
4. Description: CirrOS minimal cloud image, real-world qcow2 example
5. Tags: qcow2, cloud-image, production-like
```

Steps:
1. Add to manifest.json
2. Add image ID to test_images list in test_info_safe.py
3. Generate baseline outputs in imago-testdata for all profiles
4. Run `make test` to verify

## Example: Adding a Malicious Image

```
User: Add a QCOW2 image with backing file pointing to /etc/passwd

1. Image path: malicious/qcow2-backing-passwd.qcow2
2. Safety: malicious
3. Format: qcow2
4. Description: QCOW2 with backing file reference to /etc/passwd
5. Tags: qcow2, backing-file, security, path-traversal
```

For malicious images:
- Create the expected output file FIRST
- Run imago (not qemu-img) to generate expected output
- Verify backing file path is correctly reported
- Verify no actual file content from /etc/passwd appears

## Output Profiles

The test suite verifies imago output against multiple qemu-img version profiles:

| Profile | qemu-img Versions | Key Feature |
|---------|-------------------|-------------|
| `profile-6-0-0` | 6.0 - 7.x | No "Child node '/file'" section |
| `profile-8-0-0` | 8.0+ | Includes "Child node '/file'" section |

See `docs/output-formats.md` for detailed profile documentation.

## Key Files

| File | Purpose |
|------|---------|
| `tests/manifest.json` | Test image definitions |
| `tests/test_info_safe.py` | Safe image test - iterates profiles and baselines |
| `tests/test_info_malicious.py` | Malicious image test scenarios |
| `tests/expected_outputs/` | Expected output files for malicious images |
| `tests/helpers/types.py` | TestImage dataclass |
| `docs/quirks.md` | qemu-img quirks and `--ignore-quirks` documentation |
| `docs/image_notes/` | Per-image documentation of quirks discovered |
| `docs/image_notes/README.md` | Index of image notes |
| `imago-testdata/expected-outputs/` | Stored baseline outputs for all profiles |
| `imago-testdata/expected-outputs/qemu-img-human/version-map.json` | Profile definitions |

## Safety Reminders

1. **Never run qemu-img on malicious images** - This defeats the purpose of imago
2. **Always verify expected output** - Malicious images should report dangerous
   references but not leak actual file contents
3. **Mark CI appropriately** - Malicious images should have `run_in_ci: false`
4. **Document the threat** - Description should explain what makes the image
   malicious and what security property is being tested
