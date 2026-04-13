# Instar PR Preparation

## Overview

Before pushing a PR, you MUST verify the code is in a shippable state. This
catches issues before CI and saves review cycles.

## PR Readiness Checklist

Before creating or updating a PR, complete ALL of these steps:

### 1. Build Successfully

```bash
make instar
```

Must complete with no errors.

### 2. Pre-commit Passes

```bash
pre-commit run --all-files
```

Must show all checks passing. Fix any failures before proceeding.

### 3. Test Suite Passes

```bash
make test-ci 2>&1 | tee /tmp/test-output.txt
```

Review the output:
- **Zero failures required** - Do not push with any test failures
- Check the summary line: `Passed: X, Failed: 0, Skipped: Y`

If there are failures:
- Investigate and fix them
- If you believe they're pre-existing, verify per `testing-discipline.md`
- Ask the user before proceeding with any failures

### 4. Manual Smoke Test

Run instar manually on a test image to verify basic functionality:

```bash
src/target/release/instar info /path/to/test.qcow2
```

Verify:
- Command completes successfully (exit code 0)
- Output looks reasonable
- No unexpected error messages

### 5. No VM Crashes in Normal Operation

While VM crash messages on stderr after successful completion are sometimes
acceptable during development, a PR-ready build should not produce them in
normal operation.

If you see crash messages like:
```
--- VM Shutdown (triple fault?) ---
RIP=0xfff0, RSP=0x0, RBP=0x0
```

This indicates a problem that should be investigated before pushing.

## Creating the PR

Only after all checks pass:

```bash
# Ensure branch is up to date
git fetch origin
git rebase origin/main  # or appropriate base branch

# Push
git push -u origin <branch-name>

# Create PR
gh pr create --title "..." --body "..."
```

## PR Description Template

Include in the PR body:

```markdown
## Summary
[Brief description of changes]

## Testing
- [ ] `make instar` builds successfully
- [ ] `pre-commit run --all-files` passes
- [ ] `make test-ci` passes with 0 failures
- [ ] Manual smoke test completed

## Changes
- [List of key changes]
```

## What To Do If Checks Fail

| Issue | Action |
|-------|--------|
| Build fails | Fix compilation errors |
| Pre-commit fails | Run `pre-commit run --all-files` and fix issues |
| Tests fail | Investigate, fix, or verify pre-existing per testing-discipline.md |
| VM crashes | Investigate the cause - this indicates a guest/VMM issue |
| Smoke test fails | Debug the specific operation |

## Red Flags - Do NOT Push

Never push a PR if:

- Build fails
- Pre-commit has failures
- Test suite has NEW failures (more than baseline)
- VM crashes occur during normal operation
- Basic commands (info, check, copy) don't work

## Asking for Help

If you're uncertain whether the code is ready:

1. Summarize the current state to the user
2. List any issues you've found
3. Ask explicitly: "Should I proceed with the PR despite [issue]?"

Do not assume issues are acceptable - always ask.
