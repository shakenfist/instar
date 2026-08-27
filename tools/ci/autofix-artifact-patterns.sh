#!/usr/bin/env bash
#
# Which files a Claude Code autofix run creates that are not part of
# its fix. Sourced, never executed.
#
# Its own file rather than a block inside stage-autofix-changes.sh,
# which is its only consumer today: it was shared with the comment
# addresser until that was retired, and a second automation staging a
# Claude Code run's output needs exactly this list. A private copy
# would drift, and the direction it drifts in is a run that refuses or
# commits routine build output.
#
# shellcheck disable=SC2034  # every variable here is used by the sourcing script

# Editor backups and merge leftovers. `pre-commit run --all-files` is
# in both prompts and its hooks produce these, so treating them as part
# of a fix would refuse or commit routine runs.
ARTIFACT_NAMES='(^|/)(\.#[^/]*|[^/]*~|[^/]*\.(orig|rej|bak|tmp|swp|swo))$'

# Build and test output directories. The prompts tell Claude to run
# `make instar` and `make test-container-core`, and the latter writes
# tests/.stestr/ and tests/__pycache__/ into the tree -- neither of
# which exists when a baseline is taken, because nothing runs the tests
# beforehand. Without this, every attempt that follows its own
# instructions is caught. These are names no regression fixture would
# legitimately live under: a pattern list, not a judgement about which
# new files are worth keeping.
CI_OUTPUT_DIRS='(^|/)(\.stestr|__pycache__|target|\.cargo-cache|fuzz-logs|\.venv)/'

# The same idea by filename, because .gitignore hides by pattern too.
# `**/Cargo.lock` is the one that bites: any cargo invocation in a
# workspace directory nothing built before the baseline creates one.
CI_OUTPUT_NAMES='(^|/)(Cargo\.lock|\.DS_Store|[^/]*\.py[cod])$'
