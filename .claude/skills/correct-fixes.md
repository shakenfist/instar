# Correct Fixes Over Easy Fixes

## Philosophy

Instar is a security-focused project. **Always prefer the correct fix over the
easy fix.** Quick workarounds may hide deeper issues, introduce technical debt,
or create security vulnerabilities.

## Guiding Principles

### 1. Fix the Root Cause, Not the Symptom

When encountering a bug:

- **Wrong**: Add a check or conversion at the point where the error manifests
- **Right**: Trace back to find why the wrong value was produced and fix there

Example:
```rust
// WRONG: Converting at the receiver
fn process_data(data: &[u8]) {
    let data = if data.is_empty() { &[0u8] } else { data };  // Papering over
    // ...
}

// RIGHT: Fix the caller to never pass empty data
fn caller() {
    if !data.is_empty() {
        process_data(&data);
    }
}
```

### 2. Maintain Type Safety

- **Wrong**: Add type conversions to make things compile
- **Right**: Fix the type mismatch at its source

Type mismatches often indicate design issues. Investigate why the types don't
match rather than adding conversions.

### 3. Don't Suppress Warnings Without Understanding

- **Wrong**: Add `#[allow(unused)]` to silence a warning
- **Right**: Understand why the code is unused and either use it or remove it

Warnings are valuable signals. Each suppression should be justified.

### 4. Refactor When Needed

If a fix requires touching multiple files or restructuring code:

- **Wrong**: Add a workaround to avoid the refactor
- **Right**: Do the refactor - it's usually the right approach

The extra effort now saves debugging time later.

### 5. Security Over Convenience

In a security-focused project:

- **Wrong**: Disable validation to make tests pass
- **Right**: Fix the test or the validation logic

- **Wrong**: Add an escape hatch for problematic inputs
- **Right**: Understand why the input is problematic and handle it properly

## Red Flags - Stop and Reconsider

If you find yourself doing any of these, stop and think:

| Red Flag | Better Approach |
|----------|-----------------|
| Adding `as` casts to silence type errors | Fix the type mismatch at source |
| Adding `unwrap()` without justification | Handle the error properly |
| Commenting out code instead of removing | Remove it or fix it |
| Adding special cases for "weird" inputs | Understand why inputs are weird |
| Copying code instead of refactoring | Create proper abstractions |
| Ignoring test failures as "flaky" | Investigate the root cause |
| Adding `#[allow(...)]` liberally | Understand and fix the warnings |
| Using `unsafe` without clear justification | Find a safe alternative |

## Decision Framework

When faced with a bug or issue:

1. **Understand**: What is the actual problem?
2. **Trace**: Where does the problem originate?
3. **Evaluate**: What is the correct fix vs the easy fix?
4. **Choose correctly**: Even if it's more work

Ask yourself:
- "If I were reviewing this PR, would I accept this fix?"
- "Does this fix address the root cause or just hide it?"
- "Will this fix be obvious to the next person who reads this code?"
- "Could this fix introduce security issues?"

## When Easy Fixes Are Acceptable

Sometimes the easy fix IS the right fix:

- Typo corrections
- Simple off-by-one errors with obvious fixes
- Adding missing imports
- Formatting fixes

The key distinction: Does the fix address the actual problem, or does it hide it?

## Examples in Instar Context

### Format Detection

- **Wrong**: If a format isn't detected, default to "raw"
- **Right**: Return "unknown" and investigate why detection failed

### Error Handling

- **Wrong**: Catch errors and return success anyway
- **Right**: Propagate errors with context so they can be debugged

### Test Failures

- **Wrong**: Mark test as `#[ignore]` or skip in CI
- **Right**: Fix the code or fix the test

### Configuration Flags

- **Wrong**: Add a flag to disable security checks for problematic cases
- **Right**: Understand why the security check is failing and fix properly

## Asking for Guidance

If you're unsure whether to take the easy path or the correct path:

1. Explain both approaches to the user
2. List the trade-offs
3. Recommend the correct fix
4. Ask: "Should I proceed with the proper fix even though it requires more changes?"

Never assume the user wants the quick fix. Security-focused projects prioritize
correctness over speed.
