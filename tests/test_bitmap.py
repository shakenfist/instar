"""Integration tests for `instar bitmap`.

Phase 7 of PLAN-bitmap.md. The live differential suite: for each
case in `BITMAP_CASES`, create a qcow2 image with `qemu-img`, copy
it to A (instar) and B (qemu), apply the same sequence of bitmap
actions to each -- `instar bitmap ...` on A and `qemu-img bitmap
...` on B -- then assert `qemu-img check` passes on the instar
output and the two images carry an equivalent `bitmaps` array (read
via `qemu-img info --output=json` on *both* copies).

CRITICAL: instar's `info` emits no bitmaps (Phase-1 step 1e was
deferred), so the info cross-check is **qemu-vs-qemu**: both A and B
are read with `qemu-img info` and their `format-specific.data.bitmaps`
arrays compared, sorted by name (the on-disk directory order may
differ between the two independently-produced images).

This is the *live* differential against the locally-installed
`qemu-img` (10.0.8). `bitmap` launches a guest VM, so the test
classes guard on `/dev/kvm` (mirroring amend's guest-needs-kvm
skip). Fixtures are built with `qemu-img create` at compat=1.1
(bitmaps require qcow2 v3).

Step 7a covers the metadata-action + ordered-sequence + empty-merge
matrix across a cluster-size spread. The bits-set merge oracle
(7b) and the refusal suite (7c) are added in later steps.
"""

import copy  # noqa: F401  (registry-style symmetry with test_amend.py)
import json  # noqa: F401  (used by helpers/future steps)
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


# ----------------------------------------------------------------------
# KNOWN_BITMAP_DIVERGENCES -- registry of intentional instar-vs-qemu
# differences (populated in step 7c's refusal suite). Mirrors
# `KNOWN_AMEND_DIVERGENCES`. Keyed by a descriptive string -> reason.
# A cross-validation case that fails while NOT registered here is a
# real regression to investigate, not to silence.
# ----------------------------------------------------------------------
KNOWN_BITMAP_DIVERGENCES = {}


class TestBitmapSmoke(InstarTestBase):
    """Parent class for the bitmap test families.

    Owns the `instar bitmap` runner, the `/dev/kvm` skip guard, the
    `qemu-img create` fixture helper, the `qemu-img bitmap` oracle,
    the JSON-info helper, and the bitmaps-array comparison. Child
    classes (the cross-validation matrix and later the merge-bits and
    refusal suites) inherit all of it.
    """

    def run_instar_bitmap(self, *args, timeout=120):
        """Helper: invoke `instar bitmap` with the given args.

        Returns (stdout, stderr, returncode). Timeout 120s because
        bitmap spins up the guest VMM.
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'bitmap', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def _require_kvm(self):
        """Skip the test when `/dev/kvm` is not readable+writable.

        bitmap launches a guest VM; mirror amend's guest-needs-kvm
        skip so the suite degrades gracefully where kvm is
        unavailable.
        """
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            self.skipTest('/dev/kvm not readable+writable')

    def _qemu_create(self, path, cluster_size=65536, compat='1.1',
                     size='64M'):
        """Create a qcow2 fixture with `qemu-img create`.

        Bitmaps require qcow2 v3, so the default is compat=1.1. The
        cluster size is parametrised so the cross-validation matrix
        can sweep the sizes that surfaced the amend `.bss` bug.
        """
        cmd = ['qemu-img', 'create', '-f', 'qcow2',
               '-o', f'compat={compat},cluster_size={cluster_size}',
               str(path), str(size)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0,
            f'qemu-img create failed for {path}: {r.stderr!r}')

    def _qemu_info_json(self, path, timeout=30):
        """Run `qemu-img info --output=json` and return the parsed dict.

        instar `info` emits no bitmaps, so the bitmaps cross-check
        reads *both* copies with qemu-img.
        """
        r = subprocess.run(
            ['qemu-img', 'info', '--output=json', str(path)],
            capture_output=True, text=True, timeout=timeout)
        self.assertEqual(
            r.returncode, 0,
            f'qemu-img info --output=json failed for {path}: {r.stderr!r}')
        return json.loads(r.stdout)

    def _qemu_bitmap(self, *args, timeout=60):
        """Run `qemu-img bitmap` (the oracle side).

        Returns (stdout, stderr, returncode). Positional shape mirrors
        instar: `qemu-img bitmap [ACTIONS] FILENAME BITMAP`.
        """
        cmd = ['qemu-img', 'bitmap', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def _bitmaps_of(self, info_json):
        """Extract the normalised, name-sorted bitmaps list from a
        parsed `qemu-img info --output=json` dict.

        Each entry is `{name, granularity, flags}`; the `flags` list is
        sorted so flag ordering never causes a false mismatch, and the
        overall list is sorted by name so on-disk directory order (which
        may differ between two independently-produced images) is
        irrelevant. Missing keys collapse to an empty list.
        """
        data = (info_json.get('format-specific', {}) or {}).get('data', {}) or {}
        bitmaps = data.get('bitmaps', []) or []
        normalised = []
        for b in bitmaps:
            normalised.append({
                'name': b.get('name'),
                'granularity': b.get('granularity'),
                'flags': sorted(b.get('flags', []) or []),
            })
        normalised.sort(key=lambda e: (e['name'] is None, e['name']))
        return normalised

    def assert_bitmaps_equivalent(self, path_a, path_b, msg=''):
        """Assert the bitmaps arrays of two images match (qemu-vs-qemu).

        Reads both `path_a` (instar output) and `path_b` (qemu output)
        with `qemu-img info --output=json`, extracts and name-sorts the
        `format-specific.data.bitmaps` arrays, and asserts equality.
        This is the Open-question-1 order-safe comparison; corruption is
        caught separately by `qemu-img check`.
        """
        ba = self._bitmaps_of(self._qemu_info_json(path_a))
        bb = self._bitmaps_of(self._qemu_info_json(path_b))
        self.assertEqual(
            bb, ba,
            f'{msg}\n--- instar A bitmaps ---\n'
            f'{json.dumps(ba, indent=2, sort_keys=True)}\n'
            f'--- qemu B bitmaps ---\n'
            f'{json.dumps(bb, indent=2, sort_keys=True)}')


# ----------------------------------------------------------------------
# BITMAP_CASES -- the differential matrix.
#
# Each case is `(case_name, ops)` where `ops` is a list of bitmap
# invocations to apply, in order, to BOTH copies. Each op is a tuple
# of argument tokens that follow the subcommand but PRECEDE the
# positional `<FILENAME> <BITMAP>`; the factory appends `str(path)`
# and the bitmap name from the op's last token. To keep instar and
# qemu perfectly parallel we express each op as:
#
#     (flags..., bitmap_name)
#
# and, for --merge, as ('--merge', source_name, bitmap_name) with the
# filename spliced between source and bitmap by the factory. See
# `_make_bitmap_diff_test` for the exact splicing.
# ----------------------------------------------------------------------
BITMAP_CASES = [
    # name              ops (each: list of (flag-tokens..., final positional))
    ('add',             [('--add', 'b0')]),
    ('add_gran',        [('--add', '-g', '131072', 'b0')]),
    ('remove',          [('--add', 'b0'), ('--remove', 'b0')]),
    ('clear',           [('--add', 'b0'), ('--clear', 'b0')]),
    ('disable',         [('--add', 'b0'), ('--disable', 'b0')]),
    ('enable',          [('--add', 'b0'), ('--disable', 'b0'),
                         ('--enable', 'b0')]),
    ('add_disable_seq', [('--add', '--disable', 'b1')]),
    ('two_bitmaps',     [('--add', 'b0'), ('--add', '-g', '131072', 'b1')]),
    ('empty_merge',     [('--add', 'src'), ('--add', 'dst'),
                         ('--merge', 'src', 'dst')]),
]

# Cluster sizes to sweep. Every case runs at the 64 KiB default; a
# subset (the pure metadata add/remove/add-disable ops) also runs at
# 512 / 4096 / 1 MiB to catch cluster-size-dependent corruption of
# the class the amend `.bss` bug belonged to.
DEFAULT_CLUSTER_SIZE = 65536
EXTRA_CLUSTER_SIZES = [512, 4096, 1048576]
EXTRA_CLUSTER_CASES = {'add', 'remove', 'add_disable_seq'}


class TestBitmapCrossValidation(TestBitmapSmoke):
    """Live cross-validation against the system qemu-img.

    For each `(case, cluster_size)` in the matrix, builds a start
    image, copies it to A (instar) and B (qemu), applies the same op
    sequence to each, then asserts `qemu-img check(A)` passes and the
    two images' bitmaps arrays are equivalent (sorted by name).
    """

    pass


def _make_bitmap_diff_test(case, cluster_size):
    """Factory: one differential test method per (case, cluster_size)."""
    case_name, ops = case

    def test(self):
        self._require_kvm()

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            start = td / 'start.qcow2'
            self._qemu_create(start, cluster_size=cluster_size)

            path_a = td / 'a.qcow2'  # instar
            path_b = td / 'b.qcow2'  # qemu
            shutil.copy2(start, path_a)
            shutil.copy2(start, path_b)

            for op in ops:
                if op[0] == '--merge':
                    # ('--merge', source, bitmap) -> instar/qemu shape is
                    # `bitmap --merge <source> <FILENAME> <BITMAP>`.
                    _, source, bitmap = op
                    i_out, i_err, i_rc = self.run_instar_bitmap(
                        '--merge', source, str(path_a), bitmap)
                    q_out, q_err, q_rc = self._qemu_bitmap(
                        '--merge', source, str(path_b), bitmap)
                else:
                    # (flags..., bitmap) -> `bitmap <flags...> <FILE> <BITMAP>`.
                    flags = list(op[:-1])
                    bitmap = op[-1]
                    i_out, i_err, i_rc = self.run_instar_bitmap(
                        *flags, str(path_a), bitmap)
                    q_out, q_err, q_rc = self._qemu_bitmap(
                        *flags, str(path_b), bitmap)

                self.assertEqual(
                    i_rc, 0,
                    f'instar bitmap {op} failed for {case_name} '
                    f'(cluster_size={cluster_size}): stderr={i_err!r}')
                self.assertEqual(
                    q_rc, 0,
                    f'qemu-img bitmap {op} failed for {case_name} '
                    f'(cluster_size={cluster_size}): stderr={q_err!r}')

            # The instar output must pass qemu-img check.
            _, chk_err, chk_rc = self.run_qemu_img_check(path_a)
            self.assertEqual(
                chk_rc, 0,
                f'qemu-img check failed on instar output for {case_name} '
                f'(cluster_size={cluster_size}): stderr={chk_err}')

            # Bitmaps-array equivalence (qemu-vs-qemu, sorted by name).
            self.assert_bitmaps_equivalent(
                path_a, path_b,
                msg=f'bitmap cross-validation {case_name} '
                    f'(cluster_size={cluster_size})')

    safe = case_name.replace('-', '_')
    test.__name__ = f'test_diff_{safe}_cs{cluster_size}'
    test.__doc__ = (
        f'instar bitmap vs qemu-img bitmap for {case_name} at '
        f'cluster_size={cluster_size}: apply {ops}, then check + '
        f'bitmaps-array equivalence.')
    return test


def _install_bitmap_diff_tests():
    """Install the (case x cluster-size) differential matrix."""
    for case in BITMAP_CASES:
        case_name = case[0]
        sizes = [DEFAULT_CLUSTER_SIZE]
        if case_name in EXTRA_CLUSTER_CASES:
            sizes = sizes + EXTRA_CLUSTER_SIZES
        for cs in sizes:
            t = _make_bitmap_diff_test(case, cs)
            setattr(TestBitmapCrossValidation, t.__name__, t)


_install_bitmap_diff_tests()
