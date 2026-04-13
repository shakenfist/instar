# Instar Testing Discipline

## Golden Rule

**Never accept test failures as "pre-existing" without verification.**

Before committing any changes, you MUST:

1. Stash your changes
2. Run the test suite on the clean codebase
3. Note the baseline failure count
4. Restore your changes
5. Run the test suite again
6. Compare results - your changes must not increase failures

## Testing Workflow

### Before Starting Work

Always establish a baseline before making changes:

```bash
cd /srv/kasm_profiles/mikal/vscode/src/shakenfist/instar
make test-ci 2>&1 | tail -20
```

Note the results (passed/failed/skipped counts).

### After Making Changes

Before committing, verify you haven't introduced regressions:

```bash
# Rebuild with your changes
make instar

# Run tests
make test-ci 2>&1 | tail -20
```

Compare with your baseline. If failures increased:
- **DO NOT COMMIT**
- Investigate and fix the regression
- If uncertain, ask the user for guidance

### Verifying Pre-existing Failures

If you suspect failures are pre-existing, verify by testing without your changes:

```bash
# Stash your work
git stash

# Rebuild clean
make instar

# Test clean
make test-ci 2>&1 | tail -20

# Note results, then restore
git stash pop
```

Only if the failure count matches can you consider failures pre-existing.

## Test Commands

| Command | Purpose |
|---------|---------|
| `make test-ci` | Run safe integration tests (recommended) |
| `make test-report` | Run with verbose output (shows diffs) |
| `make test-malicious` | Include malicious image tests |

## Understanding Test Results

Test output shows:
- **Passed**: Tests that succeeded
- **Failed**: Tests that failed (investigate these!)
- **Skipped**: Tests skipped (missing images, etc.)

Example output:
```
Ran: 516 tests in 77.3567 sec.
 - Passed: 156
 - Skipped: 0
 - Failed: 360
```

## What To Do When Tests Fail

1. **Read the failure output** - The test shows expected vs actual output
2. **Identify the cause** - Is it your change or something else?
3. **Fix if possible** - Adjust your code to produce correct output
4. **Ask if uncertain** - Don't guess, ask the user for guidance

## Test Data

Tests compare `instar` output against baselines stored in `instar-testdata/`.

Key manifest properties:
- `run_in_ci: false` - Excluded from CI tests
- `skip_qemu_img: true` - Has custom baselines (not qemu-img comparison)
- `unsafe_quirks_required: true` - Needs `--unsafe-quirks` flag

## Important Notes

- Tests run inside Docker (via Makefile) - don't run pytest directly
- Test images are in sibling directory `instar-testdata/`
- Some tests may fail due to missing test images - this is expected
- VM crash messages in stderr don't indicate test failure (check exit code)

## Commit Checklist

Before committing, verify:

- [ ] `make instar` builds successfully
- [ ] `pre-commit run --all-files` passes
- [ ] `make test-ci` shows same or fewer failures than baseline
- [ ] Any new failures are understood and intentional
