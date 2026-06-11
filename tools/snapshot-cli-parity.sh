#!/usr/bin/env bash
# Phase 9c CLI parity harness for `instar snapshot`.
# Codifies D1/D2/D3 divergences (per PLAN-snapshot-phase-09) and
# confirmed parities as assertions against both tools where
# applicable. Exits non-zero on any failure.
#
# Assertion groups:
#   1. -U with -c/-d/-a refused (exit non-zero), image bit-identical.
#   2. -U -l exit 0 under both tools.
#   3. Bare `snapshot FILE` — three-way byte-identity (instar, instar
#      -l, qemu-img) on a snapshot-bearing fixture (TZ=UTC).
#   4. Bare form with --output=json equals -l --output=json.
#   5. -q on a failing delete still prints to stderr and exits 1;
#      -q on a successful create is silent under both tools.
#   6. Mixed -c x -d y exits non-zero under both, image untouched.
#   7. Not-found -d / -a exit 1 under both tools.
#   8. --image-opts rejected by instar.
#   9. -f qcow2 accepted; -f vmdk refused with format-driver message.
set -uo pipefail

INSTAR="${INSTAR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/src/target/release/instar}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0
FAIL=0

note() { printf '  %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  PASS: %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL: %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Setup: a snapshot-bearing qcow2 fixture and a plain qcow2.
# ---------------------------------------------------------------------------
note "Creating test fixtures..."
qemu-img create -f qcow2 "$WORK/snap.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write -P 0xab 0 64k" "$WORK/snap.qcow2" >/dev/null 2>&1
qemu-img snapshot -c snap1 "$WORK/snap.qcow2" >/dev/null 2>&1
qemu-img snapshot -c snap2 "$WORK/snap.qcow2" >/dev/null 2>&1

qemu-img create -f qcow2 "$WORK/plain.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/plain.qcow2" >/dev/null 2>&1

# ---------------------------------------------------------------------------
# Group 1: -U with mutating modes refused, image bit-identical.
# ---------------------------------------------------------------------------
printf '\n=== Group 1: -U with mutating modes refused (D1) ===\n'

for mode_flag in "-c s_new" "-d snap1" "-a snap1"; do
    mode_word="${mode_flag%% *}"
    mode_name="${mode_word#-}"

    # --- instar: must refuse, image unchanged ---
    cp "$WORK/snap.qcow2" "$WORK/g1_${mode_name}.qcow2"
    before=$(sha256sum "$WORK/g1_${mode_name}.qcow2" | awk '{print $1}')
    # shellcheck disable=SC2086
    "$INSTAR" snapshot -U $mode_flag "$WORK/g1_${mode_name}.qcow2" \
        >"$WORK/g1_${mode_name}.out" 2>&1
    rc=$?
    after=$(sha256sum "$WORK/g1_${mode_name}.qcow2" | awk '{print $1}')
    if [ "$rc" -ne 0 ]; then
        if [ "$before" = "$after" ]; then
            ok "-U $mode_word refused by instar (exit $rc), image untouched"
        else
            bad "-U $mode_word: instar refused but image was MUTATED"
        fi
    else
        bad "-U $mode_word: instar did not refuse (exit 0) — D1 regression"
        note "    output: $(tail -1 "$WORK/g1_${mode_name}.out")"
    fi

    # --- qemu-img: must also refuse ---
    cp "$WORK/snap.qcow2" "$WORK/g1_q_${mode_name}.qcow2"
    before_q=$(sha256sum "$WORK/g1_q_${mode_name}.qcow2" | awk '{print $1}')
    # shellcheck disable=SC2086
    qemu-img snapshot -U $mode_flag "$WORK/g1_q_${mode_name}.qcow2" \
        >"$WORK/g1_q_${mode_name}.out" 2>&1
    rc_q=$?
    after_q=$(sha256sum "$WORK/g1_q_${mode_name}.qcow2" | awk '{print $1}')
    if [ "$rc_q" -ne 0 ] && [ "$before_q" = "$after_q" ]; then
        ok "-U $mode_word refused by qemu-img (exit $rc_q), image untouched"
    else
        bad "-U $mode_word: qemu-img exit=$rc_q image_changed=$([ "$before_q" != "$after_q" ] && echo yes || echo no)"
    fi
done

# ---------------------------------------------------------------------------
# Group 2: -U -l exit 0 under both tools.
# ---------------------------------------------------------------------------
printf '\n=== Group 2: -U -l accepted (read-only, no-op) ===\n'

"$INSTAR" snapshot -U -l "$WORK/snap.qcow2" >"$WORK/g2_instar.out" 2>&1
rc=$?
if [ "$rc" -eq 0 ]; then
    ok "-U -l exit 0 under instar"
else
    bad "-U -l unexpected exit $rc under instar: $(cat "$WORK/g2_instar.out")"
fi

qemu-img snapshot -U -l "$WORK/snap.qcow2" >"$WORK/g2_qemu.out" 2>&1
rc=$?
if [ "$rc" -eq 0 ]; then
    ok "-U -l exit 0 under qemu-img"
else
    bad "-U -l unexpected exit $rc under qemu-img: $(cat "$WORK/g2_qemu.out")"
fi

# ---------------------------------------------------------------------------
# Group 3: Bare `snapshot FILE` — three-way byte-identity (TZ=UTC).
# ---------------------------------------------------------------------------
printf '\n=== Group 3: bare FILE defaults to list (D2, TZ=UTC) ===\n'

TZ=UTC "$INSTAR" snapshot "$WORK/snap.qcow2" >"$WORK/g3_bare.out" 2>&1
rc_bare=$?
TZ=UTC "$INSTAR" snapshot -l "$WORK/snap.qcow2" >"$WORK/g3_list.out" 2>&1
rc_list=$?
TZ=UTC qemu-img snapshot "$WORK/snap.qcow2" >"$WORK/g3_qemu.out" 2>&1
rc_qemu=$?

if [ "$rc_bare" -eq 0 ] && [ "$rc_list" -eq 0 ] && [ "$rc_qemu" -eq 0 ]; then
    if diff -q "$WORK/g3_bare.out" "$WORK/g3_list.out" >/dev/null 2>&1; then
        ok "bare FILE output == -l output (instar internal parity)"
    else
        bad "bare FILE output != -l output:"
        diff "$WORK/g3_bare.out" "$WORK/g3_list.out" | head -20 | sed 's/^/    /'
    fi
    if diff -q "$WORK/g3_bare.out" "$WORK/g3_qemu.out" >/dev/null 2>&1; then
        ok "bare FILE output == qemu-img bare output (three-way byte-identity)"
    else
        bad "bare FILE output != qemu-img:"
        diff "$WORK/g3_bare.out" "$WORK/g3_qemu.out" | head -20 | sed 's/^/    /'
    fi
else
    bad "group 3 exits: bare=$rc_bare list=$rc_list qemu=$rc_qemu"
fi

# ---------------------------------------------------------------------------
# Group 4: Bare form with --output=json equals -l --output=json.
# ---------------------------------------------------------------------------
printf '\n=== Group 4: bare FILE --output=json == -l --output=json ===\n'

TZ=UTC "$INSTAR" snapshot --output=json "$WORK/snap.qcow2" \
    >"$WORK/g4_bare.out" 2>&1
TZ=UTC "$INSTAR" snapshot -l --output=json "$WORK/snap.qcow2" \
    >"$WORK/g4_list.out" 2>&1

if diff -q "$WORK/g4_bare.out" "$WORK/g4_list.out" >/dev/null 2>&1; then
    ok "bare --output=json == -l --output=json"
else
    bad "bare --output=json != -l --output=json:"
    diff "$WORK/g4_bare.out" "$WORK/g4_list.out" | head -20 | sed 's/^/    /'
fi

# ---------------------------------------------------------------------------
# Group 5: -q semantics.
# ---------------------------------------------------------------------------
printf '\n=== Group 5: -q semantics (no-op confirmed) ===\n'

# 5a: -q on a failing delete still prints to stderr and exits 1.
cp "$WORK/snap.qcow2" "$WORK/g5_del.qcow2"

"$INSTAR" snapshot -q -d "nosuchsnap" "$WORK/g5_del.qcow2" \
    >"$WORK/g5_del.out" 2>&1
rc=$?
stderr_out=$(cat "$WORK/g5_del.out")
if [ "$rc" -ne 0 ]; then
    ok "-q on failing delete exits non-zero ($rc) under instar"
else
    bad "-q on failing delete: expected non-zero, got exit 0"
fi
if [ -n "$stderr_out" ]; then
    ok "-q on failing delete still emits diagnostic under instar"
else
    bad "-q on failing delete: no diagnostic emitted (expected error msg)"
fi

qemu-img snapshot -q -d "nosuchsnap" "$WORK/g5_del.qcow2" \
    >"$WORK/g5_del_qemu.out" 2>&1
rc_q=$?
stderr_q=$(cat "$WORK/g5_del_qemu.out")
if [ "$rc_q" -ne 0 ]; then
    ok "-q on failing delete exits non-zero ($rc_q) under qemu-img"
else
    bad "-q on failing delete: qemu-img expected non-zero, got exit 0"
fi
if [ -n "$stderr_q" ]; then
    ok "-q on failing delete still emits diagnostic under qemu-img"
else
    bad "-q on failing delete: qemu-img emitted no diagnostic"
fi

# 5b: -q on a successful create is silent under both tools.
cp "$WORK/plain.qcow2" "$WORK/g5_cre.qcow2"
"$INSTAR" snapshot -q -c "qtest" "$WORK/g5_cre.qcow2" \
    >"$WORK/g5_cre.out" 2>&1
rc=$?
output=$(cat "$WORK/g5_cre.out")
if [ "$rc" -eq 0 ]; then
    ok "-q on successful create exits 0 under instar"
else
    bad "-q on successful create: expected 0, got exit $rc"
fi
if [ -z "$output" ]; then
    ok "-q on successful create is silent under instar"
else
    bad "-q on successful create: instar produced output: $output"
fi

cp "$WORK/plain.qcow2" "$WORK/g5_cre_q.qcow2"
qemu-img snapshot -q -c "qtest" "$WORK/g5_cre_q.qcow2" \
    >"$WORK/g5_cre_q.out" 2>&1
rc_q=$?
output_q=$(cat "$WORK/g5_cre_q.out")
if [ "$rc_q" -eq 0 ]; then
    ok "-q on successful create exits 0 under qemu-img"
else
    bad "-q on successful create: qemu-img expected 0, got $rc_q"
fi
if [ -z "$output_q" ]; then
    ok "-q on successful create is silent under qemu-img"
else
    bad "-q on successful create: qemu-img produced output: $output_q"
fi

# ---------------------------------------------------------------------------
# Group 6: Mixed mode flags exits non-zero, image untouched (D3).
# ---------------------------------------------------------------------------
printf '\n=== Group 6: mixed mode flags non-zero (D3) ===\n'

cp "$WORK/snap.qcow2" "$WORK/g6.qcow2"
before=$(sha256sum "$WORK/g6.qcow2" | awk '{print $1}')
"$INSTAR" snapshot -c "newsnap" -d "snap1" "$WORK/g6.qcow2" \
    >"$WORK/g6_instar.out" 2>&1
rc=$?
after=$(sha256sum "$WORK/g6.qcow2" | awk '{print $1}')
if [ "$rc" -ne 0 ]; then
    if [ "$before" = "$after" ]; then
        ok "mixed -c/-d refused by instar (exit $rc), image untouched"
    else
        bad "mixed -c/-d: instar refused but image was MUTATED"
    fi
else
    bad "mixed -c/-d: instar did not refuse (exit 0)"
fi

cp "$WORK/snap.qcow2" "$WORK/g6q.qcow2"
before_q=$(sha256sum "$WORK/g6q.qcow2" | awk '{print $1}')
qemu-img snapshot -c "newsnap" -d "snap1" "$WORK/g6q.qcow2" \
    >"$WORK/g6_qemu.out" 2>&1
rc_q=$?
after_q=$(sha256sum "$WORK/g6q.qcow2" | awk '{print $1}')
if [ "$rc_q" -ne 0 ] && [ "$before_q" = "$after_q" ]; then
    ok "mixed -c/-d refused by qemu-img (exit $rc_q), image untouched"
else
    bad "mixed -c/-d: qemu-img exit=$rc_q mutated=$([ "$before_q" != "$after_q" ] && echo yes || echo no)"
fi

# ---------------------------------------------------------------------------
# Group 7: Not-found -d / -a exit 1 under both tools.
# ---------------------------------------------------------------------------
printf '\n=== Group 7: not-found exits 1 under both tools ===\n'

for mode_flag in "-d nosuch" "-a nosuch"; do
    mode_word="${mode_flag%% *}"
    mode_name="${mode_word#-}"

    cp "$WORK/snap.qcow2" "$WORK/g7_${mode_name}.qcow2"
    before=$(sha256sum "$WORK/g7_${mode_name}.qcow2" | awk '{print $1}')

    # shellcheck disable=SC2086
    "$INSTAR" snapshot $mode_flag "$WORK/g7_${mode_name}.qcow2" \
        >"$WORK/g7_${mode_name}.out" 2>&1
    rc=$?
    after=$(sha256sum "$WORK/g7_${mode_name}.qcow2" | awk '{print $1}')
    if [ "$rc" -eq 1 ] && [ "$before" = "$after" ]; then
        ok "not-found $mode_word exits 1, image untouched under instar"
    else
        bad "not-found $mode_word: instar exit=$rc image_changed=$([ "$before" != "$after" ] && echo yes || echo no)"
        note "    output: $(cat "$WORK/g7_${mode_name}.out")"
    fi

    cp "$WORK/snap.qcow2" "$WORK/g7_q_${mode_name}.qcow2"
    before_q=$(sha256sum "$WORK/g7_q_${mode_name}.qcow2" | awk '{print $1}')
    # shellcheck disable=SC2086
    qemu-img snapshot $mode_flag "$WORK/g7_q_${mode_name}.qcow2" \
        >"$WORK/g7_q_${mode_name}.out" 2>&1
    rc_q=$?
    after_q=$(sha256sum "$WORK/g7_q_${mode_name}.qcow2" | awk '{print $1}')
    if [ "$rc_q" -eq 1 ] && [ "$before_q" = "$after_q" ]; then
        ok "not-found $mode_word exits 1, image untouched under qemu-img"
    else
        bad "not-found $mode_word: qemu-img exit=$rc_q image_changed=$([ "$before_q" != "$after_q" ] && echo yes || echo no)"
    fi
done

# ---------------------------------------------------------------------------
# Group 8: --image-opts rejected by instar.
# ---------------------------------------------------------------------------
printf '\n=== Group 8: --image-opts rejected by instar ===\n'

"$INSTAR" snapshot --image-opts "$WORK/snap.qcow2" \
    >"$WORK/g8.out" 2>&1
rc=$?
output=$(cat "$WORK/g8.out")
if [ "$rc" -ne 0 ]; then
    ok "--image-opts rejected by instar (exit $rc)"
else
    bad "--image-opts: instar accepted it (exit 0), expected refusal"
fi
if echo "$output" | grep -qi "image-opts"; then
    ok "--image-opts rejection message mentions image-opts"
else
    bad "--image-opts rejection message does not mention image-opts: $output"
fi

# ---------------------------------------------------------------------------
# Group 9: -f qcow2 accepted; -f vmdk refused.
# ---------------------------------------------------------------------------
printf '\n=== Group 9: -f qcow2 accepted, -f vmdk refused ===\n'

TZ=UTC "$INSTAR" snapshot -f qcow2 -l "$WORK/snap.qcow2" \
    >"$WORK/g9_qcow2.out" 2>&1
rc=$?
if [ "$rc" -eq 0 ]; then
    ok "-f qcow2 accepted by instar"
else
    bad "-f qcow2 rejected unexpectedly: $(cat "$WORK/g9_qcow2.out")"
fi

# Create a raw image to test -f vmdk refusal (we don't need a real
# vmdk — the -f flag is validated before the guest runs, so any
# image path works for this host-side check).
"$INSTAR" snapshot -f vmdk -l "$WORK/snap.qcow2" \
    >"$WORK/g9_vmdk.out" 2>&1
rc=$?
output=$(cat "$WORK/g9_vmdk.out")
if [ "$rc" -ne 0 ]; then
    ok "-f vmdk refused by instar (exit $rc)"
else
    bad "-f vmdk: instar accepted it (exit 0), expected refusal"
fi
if echo "$output" | grep -qi "vmdk\|format.*driver\|does not support"; then
    ok "-f vmdk refusal message mentions format/vmdk"
else
    bad "-f vmdk refusal message unexpected: $output"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n=== CLI parity result: %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
