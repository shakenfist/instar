#!/usr/bin/env bash
#
# Tiered per-target duration planning for the coverage-guided fuzzing
# nightly run (.github/workflows/coverage-fuzz.yml).
#
# A handful of targets exercise tiny, quickly-saturated input spaces —
# pure window math, CHS-geometry rounding, and the planner/emitter
# crates. They reach steady coverage in well under a minute, so handing
# them an equal slice of the nightly wall-clock budget is wasted. The
# deep parser/format targets, by contrast, keep finding new coverage for
# much longer. This script gives the fast tier a short fixed budget and
# splits the remaining budget across the deep targets, so the targets
# that benefit from more time actually get it.
#
# When the deep duration computed from the budget would fall below the
# fast-tier floor, the run no longer fits its time budget usefully — that
# is the signal to shard targets across multiple CI jobs rather than keep
# cutting per-target time (see docs/testing.md, "CI integration").
#
# Usage:
#   fuzz-tier.sh plan <budget_seconds> <fast_seconds> <target>...
#       Print "<target> <duration_seconds>" for every target.
#   fuzz-tier.sh is-fast <target>
#       Exit 0 if <target> is in the fast tier, 1 otherwise.
#
set -euo pipefail

# Fast-saturating targets: small input spaces / pure logic that reach
# steady coverage quickly. Anything NOT listed here is treated as a deep
# target and receives the larger share of the budget. Keep this list in
# sync with src/fuzz/Cargo.toml as targets are added. Parser/format
# targets that consume raw image bytes (including fuzz_map_iter, which
# parses an image before walking its extents) are deliberately deep.
FAST_TIER=(
  fuzz_dd_window
  fuzz_chs_rounded_size
  fuzz_measure_calc
  fuzz_create_emitters
  fuzz_resize_planners
  fuzz_rebase_planners
  fuzz_commit_planners
  fuzz_amend_planners
  fuzz_snapshot_refcount
  fuzz_check_repair
)

is_fast() {
  local needle="$1" t
  for t in "${FAST_TIER[@]}"; do
    [ "$t" = "$needle" ] && return 0
  done
  return 1
}

plan() {
  local budget="$1" fast_seconds="$2"
  shift 2
  local targets=("$@")
  local t n_fast=0 n_deep=0
  for t in "${targets[@]}"; do
    if is_fast "$t"; then
      n_fast=$((n_fast + 1))
    else
      n_deep=$((n_deep + 1))
    fi
  done

  # Remaining budget after the fast tier, split across the deep targets.
  # Floor the deep duration at fast_seconds: if the budget cannot give
  # the deep targets at least the fast-tier slice, more time-cutting is
  # counter-productive and the target set should be sharded instead.
  local deep_seconds="$fast_seconds"
  if [ "$n_deep" -gt 0 ]; then
    local remaining=$((budget - n_fast * fast_seconds))
    local computed=$((remaining / n_deep))
    if [ "$computed" -gt "$fast_seconds" ]; then
      deep_seconds="$computed"
    fi
  fi

  for t in "${targets[@]}"; do
    if is_fast "$t"; then
      echo "$t $fast_seconds"
    else
      echo "$t $deep_seconds"
    fi
  done
}

cmd="${1:-}"
case "$cmd" in
  plan)
    shift
    if [ "$#" -lt 3 ]; then
      echo "usage: $0 plan <budget_seconds> <fast_seconds> <target>..." >&2
      exit 2
    fi
    plan "$@"
    ;;
  is-fast)
    if [ "$#" -ne 2 ]; then
      echo "usage: $0 is-fast <target>" >&2
      exit 2
    fi
    is_fast "$2"
    ;;
  *)
    echo "usage: $0 {plan <budget_s> <fast_s> <target>...|is-fast <target>}" >&2
    exit 2
    ;;
esac
