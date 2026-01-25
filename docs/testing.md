# Integration Test Suite

The imago project includes a Python-based integration test suite that verifies
`imago info` produces output identical to `qemu-img info`. Since imago aims to
be a drop-in replacement, any difference in output is considered a bug.

## Architecture

The test suite uses:

- **testtools** - Extended unittest framework with better assertions
- **testscenarios** - Parameterized test scenarios
- **stestr** - Parallel test runner with result storage

Tests compare imago output against either:
1. Live `qemu-img info` output (for safe images)
2. Stored expected output files (for malicious images)

## Test Categories

### Safe Images (`test_info_safe.py`)

Tests against known-safe disk images. These run `qemu-img` directly and
compare outputs character-for-character.

### Malicious Images (`test_info_malicious.py`)

Tests against images designed to exploit vulnerabilities (e.g., backing file
references to `/etc/passwd`). These use pre-stored expected output files
instead of running `qemu-img`, since running `qemu-img` on malicious images
defeats the security purpose of imago.

### Security Tests (`test_security.py`)

Tests verifying imago's security properties:
- Backing file references are detected but not followed
- External data file references are reported but not read
- VMDK descriptor extent paths are not accessed

## Running Tests

### Make Targets

```bash
# Create Python virtual environment (first time only)
make test-venv

# Run safe tests (default, suitable for development)
make test

# Run CI-suitable tests
make test-ci

# Run all tests including malicious images (explicit opt-in)
make test-malicious

# Run with verbose output (useful for debugging diffs)
make test-report

# Clean test artifacts
make clean-tests
```

### Direct stestr Usage

```bash
cd tests
source .venv/bin/activate

# Run all tests
stestr run

# Run specific test module
stestr run test_info_safe

# Run with verbose output
stestr run --serial -- --verbose

# List available tests
stestr list
```

## Test Image Manifest

Test images are defined in `tests/manifest.json`:

```json
{
    "id": "cirros-qcow2",
    "path": "downloaded/cirros/cirros-0.6.3-x86_64-disk.img",
    "format": "qcow2",
    "safety": "safe",
    "run_in_ci": true,
    "description": "CirrOS minimal cloud image",
    "tags": ["qcow2", "cloud-image"]
}
```

### Manifest Fields

| Field | Description |
|-------|-------------|
| `id` | Unique identifier for the test image |
| `path` | Path relative to testdata root |
| `format` | Expected disk format (qcow2, vmdk, vhd, etc.) |
| `safety` | `safe`, `caution`, or `malicious` |
| `run_in_ci` | Whether to include in CI test runs |
| `description` | Human-readable description |
| `tags` | Searchable tags for filtering |
| `expected_override` | Path to expected output file (for malicious images) |

## Test Data Location

Test images are stored in a separate repository (`imago-testdata`) to keep
the main repository small. The location is resolved in order:

1. `IMAGO_TESTDATA_PATH` environment variable
2. `../imago-testdata` (sibling directory)

## Expected Output Overrides

For malicious images where running `qemu-img` would be dangerous, store the
expected output in `tests/expected_outputs/`:

```
tests/expected_outputs/
└── qcow2_backing_etc_passwd.txt
```

Reference this file in the manifest:

```json
{
    "id": "qcow2-backing-passwd",
    "expected_override": "expected_outputs/qcow2_backing_etc_passwd.txt"
}
```

## Adding New Test Images

1. Add the image to `imago-testdata` repository
2. Add entry to `tests/manifest.json`
3. For safe images: add scenario to `test_info_safe.py`
4. For malicious images:
   - Create expected output file in `tests/expected_outputs/`
   - Add scenario to `test_info_malicious.py`

## Output Comparison

The test suite performs exact string comparison. On failure, it shows:

- Unified diff with whitespace made visible
- `␣` for trailing spaces
- `→` for tabs
- `↵` for trailing newlines
- Raw repr() of both outputs for debugging

## Environment Variables

| Variable | Description |
|----------|-------------|
| `IMAGO_TESTDATA_PATH` | Override default testdata location |
| `IMAGO_BINARY_PATH` | Override default imago binary location |
