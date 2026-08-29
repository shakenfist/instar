---
name: documentation-updates
description: "Work out which documentation a change must update, and update it. Use when adding or changing a CLI flag, subcommand, format behaviour, output format or security behaviour, and before committing any user-visible change."
---

# Instar Documentation Updates

## Golden Rule

**Every user-visible change requires documentation updates.**

When adding or modifying features, flags, behaviors, or APIs, you MUST update
the relevant documentation before committing.

## Documentation Locations

| Change Type | Documentation to Update |
|-------------|------------------------|
| New CLI flag | `docs/configuration.md` |
| New command | `docs/configuration.md`, `README.md` |
| Format detection | `docs/configuration.md`, format-specific docs |
| Security behavior | `docs/configuration.md`, `docs/quirks.md` |
| Output format changes | `docs/output-formats.md` |
| Backing chain behavior | `docs/chain-discovery.md` |
| New operation | `README.md`, `ARCHITECTURE.md` |
| API changes | `docs/` relevant file, code comments |

## Checklist for Feature Changes

When implementing a new feature or changing behavior:

- [ ] Update `docs/configuration.md` if it affects CLI flags or behavior
- [ ] Update `README.md` if it affects basic usage
- [ ] Update `ARCHITECTURE.md` if it changes system design
- [ ] Update format-specific docs if it affects format handling
- [ ] Add examples showing before/after behavior
- [ ] Update `AGENTS.md` if relevant to AI assistant usage

## Documentation Style

### Flag Documentation

When documenting a new flag in `docs/configuration.md`:

```markdown
#### `--flag-name`

Brief description of what the flag does and why you'd use it.

**Behavior:**
- What changes when this flag is set
- What the default behavior is without the flag

**Example:**

\`\`\`bash
# Without flag
instar info image.qcow2
# [output without flag]

# With flag
instar info --flag-name image.qcow2
# [output with flag]
\`\`\`
```

### Format Detection

When adding detection for a new format:

1. Add to the "Currently supported extra details" list in configuration.md
2. Include example showing detection behavior
3. Explain any differences from qemu-img behavior

## Common Omissions

These are frequently forgotten - always check:

1. **`--extra-detail` changes** - Update the supported formats list
2. **Quirk behavior changes** - Update `docs/quirks.md`
3. **Error message changes** - Document new error conditions
4. **Output format changes** - Update `docs/output-formats.md`

## Verification

Before committing, verify documentation is complete:

```bash
# Check if docs mention the feature/flag you added
grep -r "flag-name" docs/

# Review configuration.md for completeness
cat docs/configuration.md | grep -A5 "extra-detail"
```

## Examples of Good Documentation Updates

### Adding LUKS Detection

When LUKS detection was added to `--extra-detail`, the documentation should
include:

1. Entry in "Currently supported extra details" list
2. Explanation that qemu-img doesn't detect LUKS
3. Example showing behavior with and without the flag
4. Note about the "unknown" vs "luks" output difference

### Adding a New Quirk

When adding a new quirk behavior:

1. Classify as safe or unsafe in `docs/quirks.md`
2. Document the flag that controls it in `docs/configuration.md`
3. Explain security implications if unsafe
4. Provide examples of behavior difference
