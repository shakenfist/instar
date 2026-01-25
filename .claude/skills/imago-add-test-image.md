# Skill: Add Test Image to imago Test Suite

Add a new disk image to the imago integration test suite. This skill handles
both safe images (compared against live qemu-img output) and malicious images
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

### Step 4: For Safe Images - Add Test Scenario

Add scenario to `tests/test_info_safe.py`:

```python
class TestInfoSafe(testscenarios.WithScenarios, ImagoTestBase):
    scenarios = [
        # ... existing scenarios ...
        ('<image-id>', {'image_id': '<image-id>'}),
    ]
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

For safe images, the test compares imago output against qemu-img output.
Any difference fails the test.

For malicious images, the test compares imago output against the stored
expected output file.

## Example: Adding a Safe Image

```
User: Add the CirrOS 0.6.3 image to the test suite

1. Image path: downloaded/cirros/cirros-0.6.3-x86_64-disk.img
2. Safety: safe
3. Format: qcow2
4. Description: CirrOS minimal cloud image, real-world qcow2 example
5. Tags: qcow2, cloud-image, production-like
```

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

## Key Files

| File | Purpose |
|------|---------|
| `tests/manifest.json` | Test image definitions |
| `tests/test_info_safe.py` | Safe image test scenarios |
| `tests/test_info_malicious.py` | Malicious image test scenarios |
| `tests/expected_outputs/` | Expected output files for malicious images |
| `tests/helpers/types.py` | TestImage dataclass |

## Safety Reminders

1. **Never run qemu-img on malicious images** - This defeats the purpose of imago
2. **Always verify expected output** - Malicious images should report dangerous
   references but not leak actual file contents
3. **Mark CI appropriately** - Malicious images should have `run_in_ci: false`
4. **Document the threat** - Description should explain what makes the image
   malicious and what security property is being tested
