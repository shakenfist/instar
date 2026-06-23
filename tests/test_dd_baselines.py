"""Phase-7c: cross-version baseline tests for ``instar dd``.

For each ``DD_CASES`` entry the test:
  1. Creates a fresh fixture with ``qemu-img create -f <input_format>
     <tmp_in> <input_size>`` (empty — no data needed; virtual-size
     rounding is data-independent).
  2. Runs ``instar dd <window_operands> -O <instar_output_format>
     if=<tmp_in> of=<tmp_out>``.
  3. Asserts exit 0 (unless the baseline meta recorded a non-zero
     qemu ``dd_return_code``, in which case the case is skipped).
  4. Runs ``qemu-img info --output=json <tmp_out>`` on the result.
  5. Normalises via ``assert_info_equivalent`` (strips ``actual-size``,
     ``dirty-flag``, target-specific divergences, and substitutes
     ``$FILENAME`` for the temp path).
  6. Asserts the normalised JSON equals the loaded baseline.

Format naming:
  DD_CASES (and the generator) use 'vhd' for the VHD format (matching
  the instar create / baseline directory convention). instar dd's -O
  flag uses 'vpc' (qemu's canonical name); the test translates via
  ``_INSTAR_DD_OUTPUT_FORMAT`` at call time. The info_json normaliser
  also uses 'vpc'.

Special case ``1M-raw-count0-vhdx``: instar's empty vhdx is rejected
by ``qemu-img info`` (known phase-4 limitation). For that case only
``instar dd`` exit 0 is asserted; the info comparison is skipped.

Known writer divergences (``KNOWN_DD_DIVERGENCES``):
  vhdx whole/windowed cases: instar uses a default block-size of 32 MiB
  for all virtual sizes; qemu-img uses 8 MiB for small images (≤ 1 GiB
  in older versions). The ``cluster-size`` field in the info JSON
  therefore differs. This matches the pattern documented for 'create'
  in ``KNOWN_WRITER_DIVERGENCES`` in ``test_create.py``. Cases listed
  here are skipped rather than compared. Do NOT add new entries to this
  dict to silence genuine regressions; add them only for pre-existing,
  documented instar/qemu design differences.

The whole class skips cleanly if the ``dd-info-json`` directory or
``version-map.json`` is absent (e.g. before the testdata commit from
step 7b lands).

``DD_CASES`` is an exact mirror of the same constant in
``instar-testdata/scripts/generate-baselines.py`` — the two must
stay in sync. Drift is surfaced by ``test_dd_cases_match_baselines``.
"""

import json
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase
from helpers.info_json import assert_info_equivalent


# ---------------------------------------------------------------------------
# Mirror of generate-baselines.py:DD_CASES (must stay in sync).
# ---------------------------------------------------------------------------

DD_CASES = [
    # --- Whole-image (no window) ---------------------------------
    # raw->raw: sanity baseline; no rounding needed.
    ('1M-raw-whole-raw',   '1M', 'raw',   [], 'raw'),
    # raw->{qcow2,vmdk,vhd,vhdx}: whole-image output-format sweep.
    ('1M-raw-whole-qcow2', '1M', 'raw',   [], 'qcow2'),
    ('1M-raw-whole-vmdk',  '1M', 'raw',   [], 'vmdk'),
    ('1M-raw-whole-vhd',   '1M', 'raw',   [], 'vhd'),
    ('1M-raw-whole-vhdx',  '1M', 'raw',   [], 'vhdx'),
    # qcow2->raw: exercises a non-raw input format.
    ('1M-qcow2-whole-raw', '1M', 'qcow2', [], 'raw'),

    # --- Non-512 window (bs=1000 count=3) -> out_vsize 3000 ------
    # qcow2/vmdk/vhdx round up to 3072; vpc rounds to CHS 34816.
    # These are the highest-value cross-version rounding cases.
    ('1M-raw-bs1000-count3-raw',
        '1M', 'raw', ['bs=1000', 'count=3'], 'raw'),
    ('1M-raw-bs1000-count3-qcow2',
        '1M', 'raw', ['bs=1000', 'count=3'], 'qcow2'),
    ('1M-raw-bs1000-count3-vmdk',
        '1M', 'raw', ['bs=1000', 'count=3'], 'vmdk'),
    ('1M-raw-bs1000-count3-vhd',
        '1M', 'raw', ['bs=1000', 'count=3'], 'vhd'),
    ('1M-raw-bs1000-count3-vhdx',
        '1M', 'raw', ['bs=1000', 'count=3'], 'vhdx'),

    # --- Aligned window (bs=65536 skip=2 count=4) -> 262144 bytes -
    ('1M-raw-bs65536-skip2-count4-raw',
        '1M', 'raw', ['bs=65536', 'skip=2', 'count=4'], 'raw'),
    ('1M-raw-bs65536-skip2-count4-qcow2',
        '1M', 'raw', ['bs=65536', 'skip=2', 'count=4'], 'qcow2'),

    # --- Empty window (count=0) ----------------------------------
    # Records per-format behaviour for zero-byte output: qcow2/vpc
    # produce a readable vsize=0 image; vmdk exits 1 on some
    # versions; vhdx behaviour varies.
    ('1M-raw-count0-raw',   '1M', 'raw', ['count=0'], 'raw'),
    ('1M-raw-count0-qcow2', '1M', 'raw', ['count=0'], 'qcow2'),
    ('1M-raw-count0-vmdk',  '1M', 'raw', ['count=0'], 'vmdk'),
    ('1M-raw-count0-vhd',   '1M', 'raw', ['count=0'], 'vhd'),
    ('1M-raw-count0-vhdx',  '1M', 'raw', ['count=0'], 'vhdx'),
]


# ---------------------------------------------------------------------------
# Format name translation tables.
# ---------------------------------------------------------------------------

# DD_CASES and the baseline directories use 'vhd' for the VHD format
# (matching instar create's user-facing vocabulary and the testdata dir
# layout). instar dd's -O flag uses 'vpc' (qemu's canonical name for
# VHD). Translate at run_instar_dd call time only.
_INSTAR_DD_OUTPUT_FORMAT = {
    'vhd': 'vpc',
}

# The info_json normaliser (helpers/info_json.py) uses 'vpc' for VHD
# internally (it matches what qemu-img info reports as "format").
_INSTAR_TO_INFO_JSON_FMT = {
    'vhd': 'vpc',
}

# File-suffix for each output format (for NamedTemporaryFile).
_FMT_SUFFIX = {
    'raw':   '.raw',
    'qcow2': '.qcow2',
    'vmdk':  '.vmdk',
    'vhd':   '.vpc',
    'vhdx':  '.vhdx',
}


# ---------------------------------------------------------------------------
# Known writer divergences (instar vs qemu-img baseline).
# ---------------------------------------------------------------------------

# Cases where instar dd's writer is known to diverge from qemu-img dd's
# writer in a documented way. Each entry maps case_name to a reason the
# test skips. Do NOT add new entries here to silence genuine regressions;
# these cover only pre-existing, documented design differences.
#
# vhdx default block-size: instar uses 32 MiB for all virtual sizes;
# qemu-img uses 8 MiB for small images (< ~31 GiB threshold). This is
# the same divergence documented in KNOWN_WRITER_DIVERGENCES in
# test_create.py for ('vhdx', '1M-default') etc. The cluster-size field
# in qemu-img info therefore differs, so the normalised comparison fails.
KNOWN_DD_DIVERGENCES = {
    '1M-raw-whole-vhdx': (
        'instar default vhdx block-size (32 MiB) differs from '
        'qemu-img (8 MiB for small images); same divergence as '
        'KNOWN_WRITER_DIVERGENCES in test_create.py'
    ),
    '1M-raw-bs1000-count3-vhdx': (
        'instar default vhdx block-size (32 MiB) differs from '
        'qemu-img (8 MiB for small images); same divergence as '
        'KNOWN_WRITER_DIVERGENCES in test_create.py'
    ),
}


# ---------------------------------------------------------------------------
# The single special-cased case (count=0 vhdx known limitation).
# ---------------------------------------------------------------------------

# count=0 -O vhdx: instar's empty vhdx is rejected by qemu-img info
# (known phase-4 / phase-7 limitation). Assert instar exit 0 only; do
# not run qemu-img info or compare against the baseline.
_SKIP_INFO_COMPARE = {'1M-raw-count0-vhdx'}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _qemu_img_info_json(path: str, timeout: int = 30) -> tuple:
    """Run ``qemu-img info --output=json`` and return (stdout, stderr, rc)."""
    try:
        r = subprocess.run(
            ['qemu-img', 'info', '--output=json', path],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return '', f'qemu-img info timeout after {timeout}s', -1
    except FileNotFoundError:
        return '', 'qemu-img not found', -1


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestDdBaselines(InstarTestBase):
    """Phase-7c: assert instar dd info JSON matches the qemu-img dd baselines.

    The whole class skips cleanly when the ``dd-info-json`` directory or
    ``version-map.json`` is absent so the test suite can run before the
    testdata commit from step 7b lands.
    """

    # ----------------------------------------------------------------
    # Class-level skip guard: absent baselines -> skip the whole class
    # ----------------------------------------------------------------

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Probe for the version-map.json; absent means baselines not
        # yet committed.
        version_map_path = (
            cls._testdata_root / 'expected-outputs' /
            'dd-info-json' / 'version-map.json'
        )
        if not version_map_path.exists():
            cls._baselines_absent = True
        else:
            cls._baselines_absent = False

    def setUp(self):
        super().setUp()
        if getattr(self.__class__, '_baselines_absent', False):
            self.skipTest(
                'dd-info-json baselines not present in testdata repo; '
                'run `make baselines-dd && make profiles` in instar-testdata '
                'to generate them (PLAN-dd step 7b).'
            )

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    def _load_baseline_meta(self, case_name: str, profile: str) -> dict:
        """Load the meta.json for *case_name* in *profile*.

        Returns the meta dict, or None if the file is absent.
        """
        meta_path = (
            self._testdata_root / 'expected-outputs' /
            'dd-info-json' / 'profiles' / profile /
            f'{case_name}.meta.json'
        )
        if not meta_path.exists():
            return None
        with meta_path.open() as f:
            return json.load(f)

    def _load_baseline_stdout(self, case_name: str, profile: str) -> str:
        """Return the baseline stdout text for *case_name* / *profile*.

        Raises FileNotFoundError (propagated to the caller) when absent.
        """
        return self.get_expected_output(
            case_name, profile,
            output_type='json', command='dd',
        )

    # ----------------------------------------------------------------
    # Sanity: DD_CASES mirror matches what's on disk
    # ----------------------------------------------------------------

    def test_dd_cases_match_baselines(self):
        """Every baseline on disk must have a matching DD_CASES entry.

        Walks ``expected-outputs/dd-info-json/profiles/<first-profile>/``
        and asserts the ``*.stdout.txt`` stems match the case-name set in
        DD_CASES.  Catches drift between this mirror and the generator.
        """
        profiles_dir = (
            self._testdata_root / 'expected-outputs' /
            'dd-info-json' / 'profiles'
        )
        if not profiles_dir.exists():
            self.skipTest('dd-info-json/profiles directory absent')

        profile_dirs = sorted(profiles_dir.iterdir())
        if not profile_dirs:
            self.skipTest('no profiles in dd-info-json/profiles')

        # Use the first profile directory as the reference set.
        ref_dir = profile_dirs[0]
        on_disk = {
            p.name.replace('.stdout.txt', '')
            for p in ref_dir.glob('*.stdout.txt')
        }
        in_mirror = {c[0] for c in DD_CASES}

        missing_from_mirror = on_disk - in_mirror
        missing_from_disk = in_mirror - on_disk

        self.assertEqual(
            missing_from_mirror, set(),
            f'baselines on disk not in DD_CASES: {missing_from_mirror}',
        )
        self.assertEqual(
            missing_from_disk, set(),
            f'DD_CASES entries with no baseline: {missing_from_disk}. '
            f'Regenerate baselines or update DD_CASES.',
        )

    # ----------------------------------------------------------------
    # Per-case baseline factory (appended below)
    # ----------------------------------------------------------------


# ---------------------------------------------------------------------------
# Per-case test factory
# ---------------------------------------------------------------------------

def _make_dd_baseline_test(case):
    """Factory: produce one test method for a single DD_CASES entry."""
    (case_name, input_size, input_format,
     window_operands, output_format) = case

    # instar dd's -O argument uses 'vpc' for VHD (not 'vhd').
    instar_out_fmt = _INSTAR_DD_OUTPUT_FORMAT.get(output_format, output_format)

    # info_json normaliser uses 'vpc' for the VHD format.
    info_fmt = _INSTAR_TO_INFO_JSON_FMT.get(output_format, output_format)

    skip_info = case_name in _SKIP_INFO_COMPARE

    out_suffix = _FMT_SUFFIX.get(output_format, f'.{output_format}')
    in_suffix = _FMT_SUFFIX.get(input_format, f'.{input_format}')

    def test(self):
        # Check KNOWN_DD_DIVERGENCES before resolving profile to keep
        # the skip message informative.
        divergence_reason = KNOWN_DD_DIVERGENCES.get(case_name)
        if divergence_reason is not None:
            self.skipTest(
                f'known writer divergence for {case_name!r}: '
                f'{divergence_reason}'
            )

        # Resolve profile once per test; already guarded by setUp.
        profile = self.get_profile_for_installed_qemu(
            output_type='json', command='dd',
        )

        # Load meta.json for this case/profile to check exit codes.
        meta = self._load_baseline_meta(case_name, profile)
        if meta is None:
            self.skipTest(
                f'no meta.json for {case_name!r} in profile {profile!r}'
            )

        dd_rc_baseline = meta.get('dd_return_code', 0)
        if dd_rc_baseline != 0:
            # qemu-img dd itself exited non-zero (e.g. count=0 vmdk,
            # or very old qemu without dd -O). Skip comparison.
            self.skipTest(
                f'baseline dd_return_code={dd_rc_baseline} for '
                f'{case_name!r} (profile {profile!r}): '
                f'qemu-img dd could not produce output — '
                f'no comparable baseline available.'
            )

        # Special case: count=0 vhdx — instar's empty vhdx is rejected
        # by qemu-img info (known phase-4 limitation). Assert exit 0 only.
        if skip_info:
            with (
                tempfile.NamedTemporaryFile(suffix=in_suffix) as tmp_in,
                tempfile.NamedTemporaryFile(suffix=out_suffix) as tmp_out,
            ):
                subprocess.run(
                    ['qemu-img', 'create', '-f', input_format,
                     tmp_in.name, input_size],
                    capture_output=True, check=True,
                )
                _stdout, _stderr, rc = self.run_instar_dd(
                    window_operands + [
                        f'if={tmp_in.name}',
                        f'of={tmp_out.name}',
                    ],
                    output_format=instar_out_fmt,
                )
                # Known limitation: instar empty vhdx (count=0) is rejected
                # by qemu-img info. Assert exit 0 only; do not compare info.
                self.assertEqual(
                    rc, 0,
                    f'[{case_name}] instar dd exit {rc} != 0; '
                    f'stderr={_stderr!r}',
                )
            return

        # Normal path: create fixture, run instar dd, info-compare.
        with (
            tempfile.NamedTemporaryFile(suffix=in_suffix) as tmp_in,
            tempfile.NamedTemporaryFile(suffix=out_suffix) as tmp_out,
        ):
            # Create the fixture (no data needed — virtual-size rounding
            # is data-independent; actual-size is normalised at compare time).
            subprocess.run(
                ['qemu-img', 'create', '-f', input_format,
                 tmp_in.name, input_size],
                capture_output=True, check=True,
            )

            # Run instar dd with the window and output format.
            # Note: 'vhd' in DD_CASES -> 'vpc' in instar_out_fmt.
            _stdout, stderr, rc = self.run_instar_dd(
                window_operands + [
                    f'if={tmp_in.name}',
                    f'of={tmp_out.name}',
                ],
                output_format=instar_out_fmt,
            )
            self.assertEqual(
                rc, 0,
                f'[{case_name}] instar dd exit {rc} != 0; '
                f'profile={profile}; stderr={stderr!r}',
            )

            # Run qemu-img info on the output.
            info_stdout, info_stderr, info_rc = _qemu_img_info_json(
                tmp_out.name,
            )
            if info_rc == -1 and 'not found' in info_stderr:
                self.skipTest('qemu-img not installed')
            self.assertEqual(
                info_rc, 0,
                f'[{case_name}] qemu-img info failed (rc={info_rc}): '
                f'{info_stderr!r}',
            )

            # Load the expected baseline.
            try:
                expected = self._load_baseline_stdout(case_name, profile)
            except FileNotFoundError:
                self.skipTest(
                    f'no baseline stdout for {case_name!r} in profile '
                    f'{profile!r}'
                )

            # Normalise and compare. assert_info_equivalent strips
            # actual-size, dirty-flag, target-specific divergences (e.g.
            # vmdk cid/parent-cid, vhdx log-size), and substitutes
            # $FILENAME for the temp-file path.
            # Note: info_fmt uses 'vpc' for 'vhd' cases.
            assert_info_equivalent(
                self,
                info_stdout,
                expected,
                info_fmt,
                tmp_path=tmp_out.name,
                # expected side already has $FILENAME in the baseline.
                expected_tmp_path=None,
                msg=f'{case_name} (profile {profile})',
            )

    test.__name__ = f'test_baseline_{case_name.replace("-", "_")}'
    test.__doc__ = (
        f'instar dd {" ".join(window_operands)} -O {output_format} '
        f'on a {input_size} {input_format} fixture matches the '
        f'phase-7 baseline.'
    )
    return test


for _case in DD_CASES:
    _name = f'test_baseline_{_case[0].replace("-", "_")}'
    setattr(TestDdBaselines, _name, _make_dd_baseline_test(_case))
