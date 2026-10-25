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
# A plan never asks for more than its budget, though. When the budget
# cannot give every target even the fast-tier slice, every target gets an
# equal share of it instead, with a warning. The nightly's budget is what
# is left of the job's timeout (see `budget` below), so a plan that
# overran it would be killed part way through, taking the corpus push
# after it down too -- which is #519, and what a fixed budget did once
# setup slowed down.
#
# Usage:
#   fuzz-tier.sh plan <budget_seconds> <fast_seconds> <target>...
#       Print "<target> <duration_seconds>" for every target.
#   fuzz-tier.sh budget <deadline_epoch> <reserve_seconds> <cap_seconds>
#       Print the seconds of fuzzing that still fit before <deadline_epoch>
#       with <reserve_seconds> left over for the steps after it, and no
#       more than <cap_seconds>. Never negative. FUZZ_TIER_NOW overrides
#       the clock, for the self-test.
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
#
# fuzz_vhd_parent and fuzz_vhdx_parent are the exception, and are listed
# below on purpose: neither takes a whole image. One reads a fixed
# 1024-byte dynamic header plus a short synthesised window, the other a
# single metadata item, so both saturate like the planner targets rather
# than like a format parser. Do not copy their placement for a target
# that opens an image.
FAST_TIER=(
  fuzz_dd_window
  fuzz_chs_rounded_size
  fuzz_measure_calc
  fuzz_create_emitters
  fuzz_vhd_parent
  fuzz_vhdx_parent
  fuzz_resize_planners
  fuzz_rebase_planners
  fuzz_commit_planners
  fuzz_amend_planners
  fuzz_snapshot_refcount
  fuzz_check_repair
  fuzz_bitmap_parse
  fuzz_bitmap_planners
  fuzz_bench_schedule
  fuzz_qcow2_write
  fuzz_qcow2_write_growth
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

  # A budget too small for every target to have the fast-tier slice is
  # shared equally instead, so the plan still fits it. One second is the
  # least a target is given: libFuzzer reads -max_total_time=0 as "no
  # limit", which is the one value that must never reach it.
  local n_all=$((n_fast + n_deep))
  if [ "$n_all" -gt 0 ] && [ "$budget" -lt $((n_all * fast_seconds)) ]; then
    local share=$((budget / n_all))
    [ "$share" -lt 1 ] && share=1
    echo "::warning::fuzz budget of ${budget}s cannot give ${n_all} targets" \
      "${fast_seconds}s each; giving each ${share}s" >&2
    fast_seconds="$share"
  fi

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

budget() {
  local deadline="$1" reserve="$2" cap="$3"
  local now="${FUZZ_TIER_NOW:-$(date +%s)}"
  local left=$((deadline - now - reserve))
  [ "$left" -lt 0 ] && left=0
  [ "$left" -gt "$cap" ] && left="$cap"
  echo "$left"
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
  budget)
    if [ "$#" -ne 4 ]; then
      echo "usage: $0 budget <deadline_epoch> <reserve_s> <cap_s>" >&2
      exit 2
    fi
    shift
    budget "$@"
    ;;
  is-fast)
    if [ "$#" -ne 2 ]; then
      echo "usage: $0 is-fast <target>" >&2
      exit 2
    fi
    is_fast "$2"
    ;;
  *)
    echo "usage: $0 {plan <budget_s> <fast_s> <target>...|budget <deadline> <reserve_s> <cap_s>|is-fast <target>}" >&2
    exit 2
    ;;
esac
