"""Normalisation + comparison helpers for `qemu-img info`-shape JSON.

Phase 8 of PLAN-create.md compares JSON produced by two writers
(instar create, qemu-img create) read by either parser (instar
info, qemu-img info). Some fields legitimately diverge between
runs — random per-invocation IDs, filesystem-dependent block
counts, absolute paths — and must be excluded before comparison.

`normalise_info_json()` is the canonical pre-comparison filter.
`assert_info_equivalent()` wraps `assertEqual` on the normalised
forms with a readable diff on failure.
"""

import copy
import json


# Fields whose values are filesystem-dependent or absolute-path-
# dependent and so are stripped universally regardless of target.
UNIVERSAL_DIVERGENCE = {
    'actual-size',
    'dirty-flag',
}

# Additional fields stripped from children[*].info nodes only.
# The wrapping-file `virtual-size` there is the physical file length,
# which depends on the writer's metadata layout choices (e.g. refcount
# table sizing); it is not the format's virtual disk size, which lives
# at the top level and must match exactly.
NESTED_INFO_DIVERGENCE = {
    'virtual-size',
}

# Per-target additional divergence sets (random per-invocation IDs).
TARGET_DIVERGENCE = {
    'vmdk': {'cid', 'parent-cid'},
    'vhdx': {'log-size'},
    'vhd': set(),
    'vpc': set(),
    'qcow2': set(),
    'raw': set(),
}

# Cache/hint fields qemu emits inconsistently across versions.
CACHE_HINT_FIELDS = {
    'refcount-block-cache-size',
    'l2-cache-size',
    'l2-cache-entry-size',
    'cache-clean-interval',
}

# Wall-clock capture fields inside top-level snapshots[] entries.
# Two fixtures built by identical command sequences carry identical
# snapshot metadata EXCEPT the `snapshot -c` timestamp, so these are
# stripped (scoped to the snapshots array only — everything else in a
# snapshot entry, e.g. name/id/vm-state-size, must still match).
SNAPSHOT_DIVERGENCE = {
    'date-sec',
    'date-nsec',
}

FILENAME_PLACEHOLDER = '$FILENAME'


def _strip_keys(obj, keys):
    """Recursively delete `keys` wherever they appear as dict keys."""
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            if k in keys:
                del obj[k]
            else:
                _strip_keys(obj[k], keys)
    elif isinstance(obj, list):
        for item in obj:
            _strip_keys(item, keys)


def _substitute_path(obj, tmp_path):
    """Recursively replace `filename` fields equalling `tmp_path` with
    the FILENAME_PLACEHOLDER sentinel.

    Matches the baseline-recording convention from phase 7's generator.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == 'filename' and isinstance(v, str) and v == tmp_path:
                obj[k] = FILENAME_PLACEHOLDER
            else:
                _substitute_path(v, tmp_path)
    elif isinstance(obj, list):
        for item in obj:
            _substitute_path(item, tmp_path)


def normalise_info_json(obj, target, tmp_path=None):
    """Return a deep-copied dict with divergence fields stripped and
    `tmp_path` substituted to `$FILENAME` in any `filename` field.

    Args:
        obj: parsed JSON dict.
        target: the create-time target format ('qcow2', 'vmdk', 'vhd',
            'vpc', 'vhdx', 'raw'). Determines the per-target whitelist.
        tmp_path: absolute path to substitute with `$FILENAME`. Pass
            None to skip path substitution (the baseline already has
            `$FILENAME` in it).

    Returns:
        Normalised dict.
    """
    result = copy.deepcopy(obj)

    strip = set(UNIVERSAL_DIVERGENCE)
    strip.update(CACHE_HINT_FIELDS)
    strip.update(TARGET_DIVERGENCE.get(target, set()))

    _strip_keys(result, strip)

    # Snapshot entries: strip the wall-clock capture timestamps (see
    # SNAPSHOT_DIVERGENCE above).
    if isinstance(result, dict):
        snapshots = result.get('snapshots')
        if isinstance(snapshots, list):
            for snap in snapshots:
                if isinstance(snap, dict):
                    for k in SNAPSHOT_DIVERGENCE:
                        snap.pop(k, None)

    # Children's nested file-info: strip the physical-file virtual-size
    # (writer-dependent layout artefact, not the qcow2 virtual size).
    if isinstance(result, dict):
        children = result.get('children')
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    info = child.get('info')
                    if isinstance(info, dict):
                        for k in NESTED_INFO_DIVERGENCE:
                            info.pop(k, None)

    # Sort the qcow2 bitmaps array by name (and each entry's flags) so
    # the comparison is order-insensitive: instar and qemu-img write the
    # on-disk bitmap directory in whatever order the op sequence created
    # the bitmaps, which need not match. Guarded for absent keys — a
    # missing bitmaps array (e.g. the remove-last case) is a no-op.
    if isinstance(result, dict):
        data = result.get('format-specific')
        if isinstance(data, dict):
            data = data.get('data')
            if isinstance(data, dict):
                bitmaps = data.get('bitmaps')
                if isinstance(bitmaps, list):
                    for b in bitmaps:
                        if isinstance(b, dict) and isinstance(
                                b.get('flags'), list):
                            b['flags'] = sorted(b['flags'])
                    bitmaps.sort(key=lambda b: b.get('name', '')
                                 if isinstance(b, dict) else '')

    if tmp_path is not None:
        _substitute_path(result, tmp_path)

    return result


def assert_info_equivalent(test_case, actual_json_str, expected_json_str,
                           target, tmp_path=None, expected_tmp_path=None,
                           msg=''):
    """assertEqual on the normalised forms of two qemu-img-info-shape
    JSON strings.

    Args:
        test_case: the testtools/unittest TestCase instance (for
            assertEqual and the readable diff).
        actual_json_str: JSON output from the produced file.
        expected_json_str: JSON output from the baseline or a second
            live invocation.
        target: target format ('qcow2' / 'vmdk' / 'vhd' / 'vpc' /
            'vhdx' / 'raw').
        tmp_path: absolute path to substitute in `actual_json_str`.
            Pass None if the actual side already has `$FILENAME`.
        expected_tmp_path: absolute path to substitute in
            `expected_json_str`. Pass None if the expected side
            already has `$FILENAME` (the baseline-comparison case);
            pass the qemu-img tmp file path when both sides are
            live (cross-validation case).
        msg: extra context prepended to the diff on failure.
    """
    actual_obj = json.loads(actual_json_str)
    expected_obj = json.loads(expected_json_str)

    actual_norm = normalise_info_json(actual_obj, target, tmp_path=tmp_path)
    expected_norm = normalise_info_json(
        expected_obj, target, tmp_path=expected_tmp_path)

    if actual_norm != expected_norm:
        diff_msg = (
            f'{msg}\n'
            f'--- actual (normalised) ---\n'
            f'{json.dumps(actual_norm, indent=2, sort_keys=True)}\n'
            f'--- expected (normalised) ---\n'
            f'{json.dumps(expected_norm, indent=2, sort_keys=True)}'
        )
        # testtools' assertEqual signature is (expected, observed, msg).
        test_case.assertEqual(expected_norm, actual_norm, diff_msg)
