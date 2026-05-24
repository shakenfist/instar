"""Integration tests for `instar resize`.

Phase 11 of PLAN-resize.md. Structurally a sibling of
`test_create.py`'s phase-8 matrix: a top-level `RESIZE_CASES`
mirror, factory-generated per-(target, case) tests, plus a
small fixed set of error-path tests pinning the host CLI
rejection contracts established in phases 8 and 9.

Step 11a (this file's initial commit) ships the parent class,
the schema-drift tripwire, and the targeted error-path tests.
The baseline matrix factory + cross-validation + round-trip +
consistency surfaces land in 11b / 11c.

Tests require `/dev/kvm` access for the non-raw paths.
"""

import json
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


# ----------------------------------------------------------------------
# RESIZE_CASES mirror — keep in sync with
# instar-testdata/scripts/generate-baselines.py:RESIZE_CASES.
# ----------------------------------------------------------------------
#
# Each entry: (case_name, start_size, end_spec, create_opts, prealloc).
# Drift between this mirror and the generator is caught by
# TestResizeBaselineMatrix.test_resize_cases_match_baselines.
RESIZE_CASES = {
    'qcow2': [
        ('1M-to-4M-default',              '1M',  '4M',   [],                                None),
        ('1M-to-64M-default',             '1M',  '64M',  [],                                None),
        ('64M-to-256M-default',           '64M', '256M', [],                                None),
        ('1M-to-64M-cs-512',              '1M',  '64M',  ['cluster_size=512'],              None),
        ('1M-to-64M-cs-4k',               '1M',  '64M',  ['cluster_size=4k'],               None),
        ('1M-to-64M-cs-1M',               '1M',  '64M',  ['cluster_size=1M'],               None),
        ('1M-to-64M-rb-1',                '1M',  '64M',  ['refcount_bits=1'],               None),
        ('1M-to-64M-rb-64',               '1M',  '64M',  ['refcount_bits=64'],              None),
        ('1M-to-64M-extended-l2',         '1M',  '64M',
            ['extended_l2=on,cluster_size=64k'], None),
        ('1M-to-64M-compat-v2',           '1M',  '64M',  ['compat=0.10'],                   None),
        ('1M-to-64M-lazy-refcounts',      '1M',  '64M',  ['lazy_refcounts=on'],             None),
        ('1M-plus-63M-default',           '1M',  '+63M', [],                                None),
        ('64M-minus-32M-shrink',          '64M', '-32M', [],                                None),
        ('1M-to-4M-prealloc-off',         '1M',  '4M',   [],                                'off'),
        ('1M-to-4M-prealloc-metadata',    '1M',  '4M',   [],                                'metadata'),
        ('1M-to-4M-prealloc-falloc',      '1M',  '4M',   [],                                'falloc'),
        ('1M-to-4M-prealloc-full',        '1M',  '4M',   [],                                'full'),
        ('64M-to-64M-noop',               '64M', '64M',  [],                                None),
        ('64M-to-1M-no-shrink',           '64M', '1M',   [],                                None),
    ],
    'vmdk': [
        ('1M-to-64M-default',             '1M',  '64M',  [],                                None),
        ('64M-to-256M-default',           '64M', '256M', [],                                None),
        ('1M-plus-63M-default',           '1M',  '+63M', [],                                None),
    ],
    'vhd': [
        ('1M-to-64M-default',             '1M',  '64M',  [],                                None),
        ('64M-to-256M-default',           '64M', '256M', [],                                None),
        ('1M-to-4M-fixed',                '1M',  '4M',   ['subformat=fixed'],               None),
        ('1M-plus-63M-default',           '1M',  '+63M', [],                                None),
        ('1M-to-4M-prealloc-off',         '1M',  '4M',   [],                                'off'),
        ('1M-to-4M-prealloc-full',        '1M',  '4M',   [],                                'full'),
    ],
    'vhdx': [
        ('1M-to-64M-default',             '1M',  '64M',  [],                                None),
        ('64M-to-256M-default',           '64M', '256M', [],                                None),
        ('1M-to-64M-block-16M',           '1M',  '64M',  ['block_size=16M'],                None),
        ('1M-plus-63M-default',           '1M',  '+63M', [],                                None),
        ('1M-to-4M-prealloc-off',         '1M',  '4M',   [],                                'off'),
    ],
    'raw': [
        ('1M-to-64M-default',             '1M',  '64M',  [],                                None),
        ('64M-to-256M-default',           '64M', '256M', [],                                None),
        ('1M-plus-63M-default',           '1M',  '+63M', [],                                None),
        ('64M-to-1M-shrink',              '64M', '1M',   [],                                None),
        ('1M-to-4M-prealloc-off',         '1M',  '4M',   [],                                'off'),
        ('1M-to-4M-prealloc-falloc',      '1M',  '4M',   [],                                'falloc'),
        ('1M-to-4M-prealloc-full',        '1M',  '4M',   [],                                'full'),
        ('64M-to-1M-no-shrink',           '64M', '1M',   [],                                None),
    ],
}


# qemu-img size-suffix grammar; ported from
# instar-testdata/scripts/generate-baselines.py.
_SIZE_SUFFIX_MULTIPLIERS = {
    'b': 512,
    'k': 1024,
    'K': 1024,
    'M': 1024 ** 2,
    'G': 1024 ** 3,
    'T': 1024 ** 4,
    'P': 1024 ** 5,
    'E': 1024 ** 6,
}


def parse_qemu_size(size_str):
    """Parse a qemu-img SIZE string to bytes.

    Same grammar as qemu-img: optional integer + single-letter
    suffix (b/k/K/M/G/T/P/E). Bare integers are bytes.
    """
    s = size_str.strip()
    if not s:
        raise ValueError('empty size string')
    if s[-1] in _SIZE_SUFFIX_MULTIPLIERS:
        return int(s[:-1]) * _SIZE_SUFFIX_MULTIPLIERS[s[-1]]
    return int(s)


def resolve_resize_end_bytes(start_size, end_spec):
    """Resolve a resize end_spec to an absolute byte count.

    `+N` is additive against start, `-N` is subtractive,
    bare N (with or without suffix) is absolute. Mirrors the
    helper of the same name in the baseline generator so the
    mirror-vs-meta sanity check can recompute byte sizes
    without re-parsing qemu's grammar.
    """
    start_bytes = parse_qemu_size(start_size)
    s = end_spec.strip()
    if s.startswith('+'):
        return start_bytes + parse_qemu_size(s[1:])
    if s.startswith('-'):
        return start_bytes - parse_qemu_size(s[1:])
    return parse_qemu_size(s)


def _instar_target_name(target):
    """Translate the RESIZE_CASES key to instar's CLI -f value.

    The dict uses 'vhd' for symmetry with the on-disk baseline
    directory layout; instar accepts 'vpc' for the VHD format
    (qemu's canonical name).
    """
    return 'vpc' if target == 'vhd' else target


_EXT_FOR_TARGET = {
    'qcow2': 'qcow2',
    'vmdk':  'vmdk',
    'vhd':   'vhd',
    'vhdx':  'vhdx',
    'raw':   'raw',
}


class TestResizeSmoke(InstarTestBase):
    """End-to-end smoke tests for `instar resize`.

    Parent class for the matrix / cross-validation / round-trip /
    consistency subclasses landing in 11b / 11c. The
    `run_instar_resize` and `run_instar_create` helpers here are
    reused by every child class.
    """

    def run_instar_resize(self, *args, timeout=120):
        """Helper: invoke `instar resize` with the given args.

        Returns (stdout, stderr, returncode). Timeout 120s
        because a non-raw resize spins up the guest VMM
        (~5–8 s per case).
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'resize', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def run_instar_create(self, *args, timeout=60):
        """Helper: invoke `instar create` with the given args.

        Returns (stdout, stderr, returncode). Modelled on the
        identically-named helper in test_create.py.
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'create', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    # ------------------------------------------------------------------
    # Per-case helpers used by 11b / 11c factories.
    # ------------------------------------------------------------------

    @classmethod
    def _baseline_root(cls, target):
        return (cls._testdata_root / 'expected-outputs' /
                'resize-info-json' / target)

    def _baseline_version_dir(self, target):
        """Pick the version dir under <target>/ matching the
        installed qemu-img; fall back to the most-recent
        recorded version. Mirrors the create harness's logic at
        tests/test_create.py:_baseline_version_dir.
        """
        root = self._baseline_root(target)
        if not root.exists():
            return None
        names = [p.name for p in root.iterdir() if p.is_dir()]
        if not names:
            return None
        names.sort(key=lambda v: tuple(int(p) for p in v.split('.')))
        if self._qemu_version is not None:
            major, minor = self._qemu_version
            prefix = f'{major}.{minor}.'
            matches = [n for n in names if n.startswith(prefix)]
            if matches:
                return root / matches[0]
        return root / names[-1]

    def _baseline_stdout(self, target, case_name):
        v_dir = self._baseline_version_dir(target)
        if v_dir is None:
            return None
        p = v_dir / f'{case_name}.stdout.txt'
        return p if p.exists() else None

    def _baseline_meta(self, target, case_name):
        v_dir = self._baseline_version_dir(target)
        if v_dir is None:
            return None
        p = v_dir / f'{case_name}.meta.json'
        if not p.exists():
            return None
        with open(p) as f:
            return json.load(f)

    def _apply_resize_args_for_case(self, target, case, path):
        """Build the resize CLI argv from a case tuple.

        --shrink is auto-applied when the resolved end is
        smaller than the start (subtractive end_spec always
        implies shrink), except for cases ending '-no-shrink'
        which deliberately exercise the rejection path.
        --preallocation is added when the case sets a non-None
        prealloc.
        """
        case_name, start_size, end_spec, _, prealloc = case
        start_bytes = parse_qemu_size(start_size)
        end_bytes = resolve_resize_end_bytes(start_size, end_spec)
        suppress_shrink = case_name.endswith('-no-shrink')
        apply_shrink = (end_bytes < start_bytes) and not suppress_shrink

        args = ['-f', _instar_target_name(target)]
        if apply_shrink:
            args.append('--shrink')
        if prealloc is not None:
            args.extend(['--preallocation', prealloc])
        args.extend([str(path), end_spec])
        return args, apply_shrink, end_bytes

    def _assert_case_matches_meta(self, target, case, meta):
        """Sanity-check that the in-test mirror agrees with the
        recorded meta. Catches drift between the mirror and the
        baseline generator before more expensive invocations.
        """
        case_name, start_size, end_spec, _, prealloc = case
        start_bytes = parse_qemu_size(start_size)
        end_bytes = resolve_resize_end_bytes(start_size, end_spec)
        suppress_shrink = case_name.endswith('-no-shrink')
        expected_shrink = (end_bytes < start_bytes) and not suppress_shrink

        self.assertEqual(
            meta.get('start_size_str'), start_size,
            f'{target}/{case_name}: mirror start_size '
            f'{start_size!r} != meta {meta.get("start_size_str")!r}',
        )
        self.assertEqual(
            meta.get('end_spec'), end_spec,
            f'{target}/{case_name}: mirror end_spec '
            f'{end_spec!r} != meta {meta.get("end_spec")!r}',
        )
        self.assertEqual(
            meta.get('preallocation'), prealloc,
            f'{target}/{case_name}: mirror prealloc '
            f'{prealloc!r} != meta {meta.get("preallocation")!r}',
        )
        self.assertEqual(
            meta.get('expected_final_size'), end_bytes,
            f'{target}/{case_name}: mirror end_bytes '
            f'{end_bytes} != meta {meta.get("expected_final_size")}',
        )
        self.assertEqual(
            meta.get('applied_shrink_flag'), expected_shrink,
            f'{target}/{case_name}: mirror shrink {expected_shrink} '
            f'!= meta {meta.get("applied_shrink_flag")}',
        )


# ----------------------------------------------------------------------
# Surface 1: schema-drift tripwire.
# ----------------------------------------------------------------------

class TestResizeBaselineMatrix(TestResizeSmoke):
    """Cross-version baseline comparison + schema-drift tripwire.

    Step 11a ships only the tripwire; the per-(target, case)
    factory lands in 11b.
    """

    def test_resize_cases_match_baselines(self):
        """Every baseline on disk must have a matching RESIZE_CASES entry.

        Walks <testdata>/expected-outputs/resize-info-json/<target>/<version>/
        for each known target and asserts the on-disk case-name
        set matches the in-test mirror. Catches drift between
        this mirror and the testdata baseline generator.
        """
        for target, cases in RESIZE_CASES.items():
            v_dir = self._baseline_version_dir(target)
            if v_dir is None:
                self.skipTest(f'no baseline dir for target {target}')
            on_disk = {
                p.stem.rsplit('.stdout', 1)[0]
                for p in v_dir.glob('*.stdout.txt')
            }
            in_mirror = {c[0] for c in cases}
            missing_from_mirror = on_disk - in_mirror
            missing_from_disk = in_mirror - on_disk
            self.assertEqual(
                missing_from_mirror, set(),
                f'{target}: baselines on disk not in RESIZE_CASES: '
                f'{missing_from_mirror}'
            )
            self.assertEqual(
                missing_from_disk, set(),
                f'{target}: RESIZE_CASES entries with no baseline: '
                f'{missing_from_disk}. Regenerate baselines via '
                f'instar-testdata.'
            )


# ----------------------------------------------------------------------
# Surface 6: targeted error-path tests.
# ----------------------------------------------------------------------
#
# Each pins a host CLI rejection contract established in phase 8 or 9.
# The baseline matrix in 11b skips the shrink-without-flag cases (a
# baseline-diff on an error message is too brittle); these tests pin
# the user-facing stderr substring instead.

class TestResizeErrorPaths(TestResizeSmoke):
    """Host CLI rejection contracts (phases 8 and 9)."""

    # ----------- Shrink-without-flag rejections (phase 8 contract) -----------

    def test_shrink_without_flag_rejected_raw(self):
        """`instar resize -f raw foo.raw 1M` on a 64M file requires --shrink."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            _, _, c_rc = self.run_instar_create('-f', 'raw', str(path), '64M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_resize(
                '-f', 'raw', str(path), '1M')
            self.assertNotEqual(rc, 0,
                                'expected raw shrink without --shrink to fail')
            self.assertIn('shrink', stderr.lower())

    def test_shrink_without_flag_rejected_qcow2(self):
        """qcow2 shrink without --shrink is rejected by the guest planner."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, _, c_rc = self.run_instar_create('-f', 'qcow2', str(path), '64M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_resize(
                '-f', 'qcow2', str(path), '1M')
            self.assertNotEqual(rc, 0,
                                'expected qcow2 shrink without --shrink to fail')
            self.assertIn('shrink', stderr.lower())

    def test_subtractive_size_without_shrink_rejected_raw(self):
        """`-32M` end_spec implies shrink; without --shrink, rejected."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            _, _, c_rc = self.run_instar_create('-f', 'raw', str(path), '64M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_resize(
                '-f', 'raw', str(path), '-32M')
            self.assertNotEqual(rc, 0)
            self.assertIn('shrink', stderr.lower())

    # ----------- Invalid size strings (phase 8 parser) -----------

    def test_invalid_size_string_empty_rejected(self):
        """Empty size is a CLI parse error (clap rejects)."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            _, _, c_rc = self.run_instar_create('-f', 'raw', str(path), '4M')
            self.assertEqual(c_rc, 0)
            _, _, rc = self.run_instar_resize(
                '-f', 'raw', str(path), '')
            self.assertNotEqual(rc, 0)

    def test_invalid_size_string_nonsense_rejected(self):
        """`abc` is not a valid SIZE."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            _, _, c_rc = self.run_instar_create('-f', 'raw', str(path), '4M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_resize(
                '-f', 'raw', str(path), 'abc')
            self.assertNotEqual(rc, 0,
                                f'expected nonsense SIZE to fail; stderr={stderr}')

    # ----------- Preallocation rejections (phase 9 contract) -----------

    def test_metadata_on_raw_rejected(self):
        """`-f raw --preallocation metadata` rejected (no metadata to populate)."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            _, _, c_rc = self.run_instar_create('-f', 'raw', str(path), '1M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_resize(
                '-f', 'raw', '--preallocation', 'metadata', str(path), '4M')
            self.assertNotEqual(rc, 0)
            self.assertIn('metadata', stderr.lower())
            self.assertIn('raw', stderr.lower())

    def test_preallocation_falloc_with_shrink_rejected_raw(self):
        """`--preallocation falloc` + shrink is rejected as meaningless."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            _, _, c_rc = self.run_instar_create('-f', 'raw', str(path), '64M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_resize(
                '-f', 'raw', '--preallocation', 'falloc', '--shrink',
                str(path), '1M')
            self.assertNotEqual(rc, 0)
            self.assertIn('meaningless when shrinking', stderr)

    def test_preallocation_full_with_shrink_rejected_qcow2(self):
        """qcow2 + --preallocation full + shrink is rejected."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, _, c_rc = self.run_instar_create('-f', 'qcow2', str(path), '64M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_resize(
                '-f', 'qcow2', '--preallocation', 'full', '--shrink',
                str(path), '1M')
            self.assertNotEqual(rc, 0)
            self.assertIn('meaningless when shrinking', stderr)

    # ----------- --object / --image-opts deferral (phase 8) -----------

    def test_object_flag_rejected(self):
        """`--object` is rejected with the documented deferral message."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            _, _, c_rc = self.run_instar_create('-f', 'raw', str(path), '4M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_resize(
                '-f', 'raw', '--object', 'foo=bar', str(path), '8M')
            self.assertNotEqual(rc, 0)
            self.assertIn('object', stderr.lower())

    def test_image_opts_flag_rejected(self):
        """`--image-opts` is rejected with the documented deferral message."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            _, _, c_rc = self.run_instar_create('-f', 'raw', str(path), '4M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_resize(
                '--image-opts', f'file.filename={path}', '8M')
            self.assertNotEqual(rc, 0)
            self.assertIn('image-opts', stderr.lower())
