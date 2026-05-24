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
from helpers.info_json import assert_info_equivalent
from test_create import KNOWN_WRITER_DIVERGENCES  # noqa: F401  (reserved for future per-case create-side lookup)


# Cases where `instar create` produces a file that `instar check`
# already rejects (independent of resize). The resize round-trip
# test inherits the failure, so it skips these. Re-stated here
# because the resize case names differ from the create names.
KNOWN_CREATE_CHECK_FAILURES = {
    # instar emits refcount_bits=64 in the header but writes
    # 16-bit refcount entries on disk; instar check spots the
    # mismatch. Same root cause as ('qcow2', '1G-rb-64') in
    # test_create.py:KNOWN_CHECK_FAILURES.
    ('qcow2', '1M-to-64M-rb-64'):
        'instar emits refcount_bits=64 header but 16-bit on-disk '
        'entries — check rejects (independent of resize)',
}


# Cases where the post-resize info JSON diverges from qemu's
# baseline for a documented reason. Three categories:
#
# 1. **Create-time divergence carries forward.** instar's create
#    writer hardcodes refcount_bits=16 and compat=1.1 (see
#    KNOWN_WRITER_DIVERGENCES in test_create.py), so the post-
#    resize info reports those values rather than what the
#    -o flags requested. The resize case names differ from the
#    create case names, so we re-list them here.
# 2. **Resize-time planner gaps.** Documented Future-work items
#    from the master plan; the resize op rejects rather than
#    silently producing the wrong layout.
#
# A case NOT in this dict that fails the diff is a real
# regression and must be investigated, not silenced.
KNOWN_RESIZE_DIVERGENCES = {
    # Create-time divergence carry-forward
    # ----------------------------------------
    # instar's qcow2 build_header hardcodes refcount_order=4
    # (-> refcount_bits=16); -o refcount_bits=N is ignored.
    ('qcow2', '1M-to-64M-rb-1'):  'instar hardcodes refcount_bits=16',
    ('qcow2', '1M-to-64M-rb-64'): 'instar hardcodes refcount_bits=16',
    # instar's qcow2 build_header hardcodes compat=1.1; the
    # -o compat=0.10 flag is silently ignored.
    ('qcow2', '1M-to-64M-compat-v2'): 'instar hardcodes compat=1.1',

    # Resize-time planner gap (master-plan Future work)
    # ----------------------------------------
    # qcow2 + preallocation=metadata on resize is rejected by
    # the planner (PreallocationUnsupported, deferred from
    # phase 2c). qemu accepts it.
    ('qcow2', '1M-to-4M-prealloc-metadata'):
        'qcow2 metadata preallocation deferred (master-plan Future work)',
}


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
# Surface 1 + 2: schema-drift tripwire + per-(target, case) baseline diff.
# ----------------------------------------------------------------------

class TestResizeBaselineMatrix(TestResizeSmoke):
    """Cross-version baseline comparison + schema-drift tripwire.

    For each entry in RESIZE_CASES, the per-case factory runs
    `instar create` to produce the start image, then `instar
    resize` with the recorded flag set, then system
    `qemu-img info --output=json` on the post-resize file, and
    asserts byte-equivalence against the version-matched baseline
    (modulo the divergence whitelist already established by
    phase 8's create matrix and reused here via
    `KNOWN_WRITER_DIVERGENCES`).

    Bypasses get_output_profiles() and reads the per-target
    bucket directly, matching the create harness's approach in
    tests/test_create.py:TestCreateBaselineMatrix.
    """

    @staticmethod
    def _run_qemu_img_info(path, timeout=30):
        """Run system qemu-img info --output=json. No -f flag so
        the auto-detect path matches what the baseline generator
        recorded. Returns (stdout, stderr, rc).
        """
        try:
            r = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(path)],
                capture_output=True, text=True, timeout=timeout,
            )
            return r.stdout, r.stderr, r.returncode
        except FileNotFoundError:
            return '', 'qemu-img not installed', -1
        except subprocess.TimeoutExpired:
            return '', f'qemu-img info timeout after {timeout}s', -1

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


def _make_resize_baseline_test(target, case):
    """Factory: one test method per (target, case) tuple.

    Skips the case when:
    - The baseline isn't on disk (matrix not populated for this
      installed qemu version).
    - The baseline records a non-zero qemu-img create / resize /
      info rc (qemu-img couldn't produce a comparable artefact —
      vmdk / vhd / vhdx baselines all land here because qemu
      doesn't support resize on those formats; covered by
      TestResizeConsistency in 11c).
    - The case is a `-no-shrink` rejection (covered by
      TestResizeErrorPaths instead — a baseline-diff on an error
      message is too brittle).
    - The case hits a known instar-vs-qemu create-time writer
      divergence (the divergence carries forward into the post-
      resize info).
    """
    case_name, start_size, end_spec, create_opts, prealloc = case

    def test(self):
        meta = self._baseline_meta(target, case_name)
        if meta is None:
            self.skipTest(
                f'no baseline meta for {target}/{case_name} '
                f'(installed qemu version not in matrix?)'
            )
        if meta.get('create_return_code', 0) != 0:
            self.skipTest(
                f'baseline create_rc={meta["create_return_code"]} '
                f'(qemu rejected create); no comparable artefact'
            )
        if meta.get('resize_return_code', 0) != 0:
            self.skipTest(
                f"qemu-img cannot resize {target} "
                f"(meta resize_rc={meta['resize_return_code']}); "
                f"covered by TestResizeConsistency"
            )
        if meta.get('info_return_code', 0) != 0:
            self.skipTest(
                f'baseline info_rc={meta["info_return_code"]} '
                f'(no comparable JSON)'
            )

        if case_name.endswith('-no-shrink'):
            self.skipTest(
                'rejection case; covered by TestResizeErrorPaths'
            )

        known = KNOWN_RESIZE_DIVERGENCES.get((target, case_name))
        if known is not None:
            self.skipTest(f'known resize divergence: {known}')

        baseline_path = self._baseline_stdout(target, case_name)
        if baseline_path is None:
            self.skipTest(f'no baseline stdout for {target}/{case_name}')

        # Mirror-vs-meta sanity: catches drift between this in-test
        # mirror and the testdata generator before more expensive
        # invocations fire.
        self._assert_case_matches_meta(target, case, meta)

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / f'image.{_EXT_FOR_TARGET[target]}'

            # 1. Create the start image with instar.
            c_args = ['-f', _instar_target_name(target)]
            for opt in create_opts:
                c_args.extend(['-o', opt])
            c_args.extend([str(path), start_size])
            _, c_stderr, c_rc = self.run_instar_create(*c_args)
            self.assertEqual(
                c_rc, 0,
                f'instar create failed for {target}/{case_name}: '
                f'stderr={c_stderr}'
            )

            # 2. Resize via instar.
            r_args, _, _ = self._apply_resize_args_for_case(target, case, path)
            _, r_stderr, r_rc = self.run_instar_resize(*r_args)
            self.assertEqual(
                r_rc, 0,
                f'instar resize failed for {target}/{case_name}: '
                f'stderr={r_stderr}'
            )

            # 3. Run system qemu-img info and diff against the baseline.
            info_stdout, info_stderr, info_rc = self._run_qemu_img_info(path)
            if info_rc == -1 and 'not installed' in info_stderr:
                self.skipTest('system qemu-img not installed')
            self.assertEqual(
                info_rc, 0,
                f'qemu-img info failed on instar output for '
                f'{target}/{case_name}: stderr={info_stderr}'
            )
            expected = baseline_path.read_text()
            assert_info_equivalent(
                self, info_stdout, expected,
                _instar_target_name(target),
                tmp_path=str(path),
                msg=f'{target}/{case_name}',
            )

    test.__name__ = (
        f'test_baseline_{target}_{case_name.replace("-", "_")}'
    )
    test.__doc__ = (
        f'instar create -f {target} {" ".join(create_opts)} {start_size} '
        f'-> resize {end_spec} (prealloc={prealloc}) matches '
        f'phase-10 baseline.'
    )
    return test


for _target, _cases in RESIZE_CASES.items():
    for _case in _cases:
        _name = (
            f'test_baseline_{_target}_{_case[0].replace("-", "_")}'
        )
        setattr(
            TestResizeBaselineMatrix, _name,
            _make_resize_baseline_test(_target, _case),
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


# ----------------------------------------------------------------------
# Surface 3: live cross-validation against the system qemu-img.
# ----------------------------------------------------------------------
#
# Curated subset chosen to exercise the qcow2 + raw paths qemu
# actually supports for resize. For each case, run the full
# `create -> resize` pipeline once via instar and once via
# qemu-img, then compare both outputs via `instar info` (not
# qemu info — we're measuring writer agreement, not reader
# agreement). Mirrors TestCreateCrossValidation in
# tests/test_create.py.
RESIZE_CROSS_VALIDATION_CASES = [
    # qcow2 (qemu supports resize)
    ('qcow2', ('1M-to-4M-default',     '1M',  '4M',   [],     None)),
    ('qcow2', ('1M-to-64M-default',    '1M',  '64M',  [],     None)),
    ('qcow2', ('1M-to-4M-prealloc-full','1M', '4M',   [],     'full')),
    ('qcow2', ('64M-minus-32M-shrink', '64M', '-32M', [],     None)),
    # raw paths
    ('raw',   ('1M-to-64M-default',    '1M',  '64M',  [],     None)),
    ('raw',   ('64M-to-1M-shrink',     '64M', '1M',   [],     None)),
    ('raw',   ('1M-to-4M-prealloc-full','1M', '4M',   [],     'full')),
]


class TestResizeCrossValidation(TestResizeSmoke):
    """Live cross-validation against the system qemu-img.

    For each entry in RESIZE_CROSS_VALIDATION_CASES, runs the
    full create -> resize pipeline twice (once via instar, once
    via qemu-img), then `instar info` on both outputs and
    asserts byte-equivalence of the normalised JSONs. Catches
    writer divergences that surface against the *currently
    installed* qemu-img version rather than the frozen phase-10
    matrix.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            r = subprocess.run(
                ['qemu-img', '--version'],
                capture_output=True, text=True,
            )
            cls._system_qemu_available = (r.returncode == 0)
        except FileNotFoundError:
            cls._system_qemu_available = False

    def _run_qemu_create(self, target, size_str, options_list, out_path,
                         timeout=60):
        qemu_target = 'vpc' if target == 'vhd' else target
        cmd = ['qemu-img', 'create', '-f', qemu_target]
        for opt in options_list:
            cmd.extend(['-o', opt])
        cmd.extend([str(out_path), size_str])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'qemu-img create timeout after {timeout}s', -1

    def _run_qemu_resize(self, target, end_spec, apply_shrink, prealloc,
                         out_path, timeout=60):
        qemu_target = 'vpc' if target == 'vhd' else target
        cmd = ['qemu-img', 'resize', '-f', qemu_target]
        if apply_shrink:
            cmd.append('--shrink')
        if prealloc is not None:
            cmd.extend(['--preallocation', prealloc])
        cmd.extend([str(out_path), end_spec])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'qemu-img resize timeout after {timeout}s', -1


def _make_resize_xval_test(target, case):
    case_name, start_size, end_spec, create_opts, prealloc = case

    def test(self):
        if not getattr(type(self), '_system_qemu_available', False):
            self.skipTest('system qemu-img not available')
        known = KNOWN_RESIZE_DIVERGENCES.get((target, case_name))
        if known is not None:
            self.skipTest(f'known resize divergence: {known}')

        ext = _EXT_FOR_TARGET[target]
        with tempfile.TemporaryDirectory() as td_a, \
                tempfile.TemporaryDirectory() as td_b:
            inst_path = Path(td_a) / f'instar.{ext}'
            qemu_path = Path(td_b) / f'qemu.{ext}'

            # instar pipeline
            i_args = ['-f', _instar_target_name(target)]
            for opt in create_opts:
                i_args.extend(['-o', opt])
            i_args.extend([str(inst_path), start_size])
            _, c_stderr, c_rc = self.run_instar_create(*i_args)
            self.assertEqual(
                c_rc, 0,
                f'instar create failed: {c_stderr}'
            )
            r_args, apply_shrink, _ = self._apply_resize_args_for_case(
                target, case, inst_path)
            _, r_stderr, r_rc = self.run_instar_resize(*r_args)
            self.assertEqual(
                r_rc, 0,
                f'instar resize failed: {r_stderr}'
            )

            # qemu pipeline
            _, qc_stderr, qc_rc = self._run_qemu_create(
                target, start_size, create_opts, qemu_path)
            if qc_rc != 0:
                self.skipTest(
                    f'qemu-img create rejected: {qc_stderr.strip()}'
                )
            _, qr_stderr, qr_rc = self._run_qemu_resize(
                target, end_spec, apply_shrink, prealloc, qemu_path)
            if qr_rc != 0:
                self.skipTest(
                    f'qemu-img resize rejected: {qr_stderr.strip()}'
                )

            # Compare via instar info on both outputs.
            inst_info, inst_err, inst_rc = self.run_instar_info(
                inst_path, output_format='json')
            self.assertEqual(
                inst_rc, 0, f'instar info on instar output failed: {inst_err}'
            )
            qemu_info, qemu_err, qemu_rc = self.run_instar_info(
                qemu_path, output_format='json')
            self.assertEqual(
                qemu_rc, 0, f'instar info on qemu output failed: {qemu_err}'
            )

            assert_info_equivalent(
                self, inst_info, qemu_info,
                _instar_target_name(target),
                tmp_path=str(inst_path),
                expected_tmp_path=str(qemu_path),
                msg=(f'cross-validation {target}/{case_name}: '
                     f'instar={inst_path}, qemu={qemu_path}'),
            )

    test.__name__ = f'test_xval_{target}_{case_name.replace("-", "_")}'
    test.__doc__ = (
        f'instar create+resize vs qemu-img create+resize for '
        f'-f {target} {start_size} -> {end_spec} '
        f'(prealloc={prealloc}) agree via instar info.'
    )
    return test


for _target, _case in RESIZE_CROSS_VALIDATION_CASES:
    _name = f'test_xval_{_target}_{_case[0].replace("-", "_")}'
    setattr(TestResizeCrossValidation, _name,
            _make_resize_xval_test(_target, _case))


# ----------------------------------------------------------------------
# Surface 4: round-trip check across the full matrix.
# ----------------------------------------------------------------------
#
# For every (target, case) in RESIZE_CASES, instar create -> resize
# -> check, expect rc==0. Catches a resize emitter regression that
# produces a file qemu-img info accepts but the instar reader flags.
# Skips raw (instar check is a no-op for raw) and the -no-shrink
# rejection cases.


class TestResizeRoundTripCheck(TestResizeSmoke):
    """`instar create -> resize -> check` for every meaningful case."""

    pass


def _make_resize_check_test(target, case):
    case_name, start_size, end_spec, create_opts, prealloc = case

    def test(self):
        if target == 'raw':
            self.skipTest('instar check does not apply to raw images')
        if case_name.endswith('-no-shrink'):
            self.skipTest(
                'rejection case; resize would fail before check could run'
            )
        known = KNOWN_RESIZE_DIVERGENCES.get((target, case_name))
        if known is not None and 'rejected' in known.lower() or \
                known is not None and 'deferred' in known.lower():
            self.skipTest(f'resize itself is rejected: {known}')
        create_check_fail = KNOWN_CREATE_CHECK_FAILURES.get((target, case_name))
        if create_check_fail is not None:
            self.skipTest(create_check_fail)

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / f'image.{_EXT_FOR_TARGET[target]}'

            c_args = ['-f', _instar_target_name(target)]
            for opt in create_opts:
                c_args.extend(['-o', opt])
            c_args.extend([str(path), start_size])
            _, c_stderr, c_rc = self.run_instar_create(*c_args)
            if c_rc != 0:
                self.skipTest(
                    f'instar create rejected {target}/{case_name}: '
                    f'{c_stderr.strip()}'
                )

            r_args, _, _ = self._apply_resize_args_for_case(target, case, path)
            _, r_stderr, r_rc = self.run_instar_resize(*r_args)
            self.assertEqual(
                r_rc, 0,
                f'instar resize failed for {target}/{case_name}: '
                f'stderr={r_stderr}'
            )

            _, k_stderr, k_rc = self.run_instar_check(path)
            self.assertEqual(
                k_rc, 0,
                f'instar check failed on freshly-resized '
                f'{target}/{case_name}: stderr={k_stderr}'
            )

    test.__name__ = f'test_check_{target}_{case_name.replace("-", "_")}'
    test.__doc__ = (
        f'instar check passes on instar create+resize -f {target} '
        f'{start_size} -> {end_spec} (prealloc={prealloc}).'
    )
    return test


for _target, _cases in RESIZE_CASES.items():
    for _case in _cases:
        _name = (
            f'test_check_{_target}_{_case[0].replace("-", "_")}'
        )
        setattr(TestResizeRoundTripCheck, _name,
                _make_resize_check_test(_target, _case))


# ----------------------------------------------------------------------
# Surface 5: internal-consistency suite for vmdk / vhd / vhdx.
# ----------------------------------------------------------------------
#
# qemu-img can't resize these formats, so the baseline matrix
# (surface 2) skips them entirely. This suite is the substitute:
# create -> resize -> info -> (check), all via instar, asserting
# the post-resize virtual-size matches expected_final_size and
# the file passes integrity checks.
#
# vhd's virtual-size diverges from expected_final_size for *create*
# in some cases (qemu rounds to CHS-aligned multiples; instar uses
# the exact byte count). The resize planner preserves whatever the
# create writer chose, so we assert against the round-trip:
# post-resize virtual-size should equal what instar would have
# produced for a fresh create at the target size. Since we have no
# fresh-create comparison here, we assert the looser invariant that
# virtual-size is non-zero and the file is at least as big as the
# requested final size (modulo format overhead).


class TestResizeConsistency(TestResizeSmoke):
    """Internal consistency for vmdk / vhd / vhdx (qemu rejects)."""

    pass


# Targets where qemu rejects resize; for these the consistency suite
# is the only coverage surface for the cross-tool matrix.
_CONSISTENCY_TARGETS = ('vmdk', 'vhd', 'vhdx')


def _make_resize_consistency_test(target, case):
    case_name, start_size, end_spec, create_opts, prealloc = case

    def test(self):
        # Sanity: only run when the matching baseline meta records
        # a qemu rejection — otherwise the baseline matrix is the
        # right place for this case.
        meta = self._baseline_meta(target, case_name)
        if meta is None:
            self.skipTest(f'no baseline meta for {target}/{case_name}')
        if meta.get('resize_return_code') == 0:
            self.skipTest(
                'qemu supports this resize; covered by baseline matrix'
            )

        end_bytes = resolve_resize_end_bytes(start_size, end_spec)

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / f'image.{_EXT_FOR_TARGET[target]}'

            c_args = ['-f', _instar_target_name(target)]
            for opt in create_opts:
                c_args.extend(['-o', opt])
            c_args.extend([str(path), start_size])
            _, c_stderr, c_rc = self.run_instar_create(*c_args)
            if c_rc != 0:
                self.skipTest(
                    f'instar create rejected {target}/{case_name}: '
                    f'{c_stderr.strip()}'
                )

            r_args, _, _ = self._apply_resize_args_for_case(target, case, path)
            _, r_stderr, r_rc = self.run_instar_resize(*r_args)
            self.assertEqual(
                r_rc, 0,
                f'instar resize failed for {target}/{case_name}: '
                f'stderr={r_stderr}'
            )

            info_stdout, info_err, info_rc = self.run_instar_info(
                path, output_format='json')
            self.assertEqual(
                info_rc, 0,
                f'instar info failed on post-resize {target}/{case_name}: '
                f'{info_err}'
            )
            info = json.loads(info_stdout)

            # vhd virtual-size may be rounded up to a CHS-aligned
            # multiple by the writer (documented in
            # KNOWN_WRITER_DIVERGENCES). For non-vhd targets, the
            # post-resize virtual-size must equal the requested
            # end_bytes exactly; for vhd, allow >= (the writer may
            # have rounded up).
            actual_vs = info.get('virtual-size')
            self.assertIsNotNone(
                actual_vs,
                f'{target}/{case_name}: info JSON missing virtual-size'
            )
            if target == 'vhd':
                self.assertGreaterEqual(
                    actual_vs, end_bytes,
                    f'{target}/{case_name}: virtual-size {actual_vs} '
                    f'< expected_final_size {end_bytes} (CHS-rounded '
                    f'value should be >=, never <)'
                )
            else:
                self.assertEqual(
                    actual_vs, end_bytes,
                    f'{target}/{case_name}: virtual-size {actual_vs} '
                    f'!= expected_final_size {end_bytes}'
                )

            # Check on vhd / vhdx (vmdk check is a no-op today, same
            # policy as test_create's round-trip check).
            if target in ('vhd', 'vhdx'):
                _, k_stderr, k_rc = self.run_instar_check(path)
                self.assertEqual(
                    k_rc, 0,
                    f'instar check failed on freshly-resized '
                    f'{target}/{case_name}: stderr={k_stderr}'
                )

    test.__name__ = (
        f'test_consistency_{target}_{case_name.replace("-", "_")}'
    )
    test.__doc__ = (
        f'instar create+resize+info+check round-trip for -f {target} '
        f'{start_size} -> {end_spec} (qemu rejects this; consistency '
        f'check is the substitute for baseline diff).'
    )
    return test


for _target in _CONSISTENCY_TARGETS:
    for _case in RESIZE_CASES.get(_target, []):
        _name = (
            f'test_consistency_{_target}_{_case[0].replace("-", "_")}'
        )
        setattr(TestResizeConsistency, _name,
                _make_resize_consistency_test(_target, _case))
