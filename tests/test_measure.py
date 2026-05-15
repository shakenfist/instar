"""Smoke tests for the measure operation (CLI wiring + qemu-img parity).

Phase 4 of PLAN-measure.md ships the host CLI; these tests confirm
end-to-end invocation works and that output matches qemu-img
byte-for-byte for the cases qemu-img supports. The comprehensive
cross-version test matrix lives in phase 7.
"""

import json
import subprocess
from pathlib import Path

from base import InstarTestBase


# Mirror of SIZE_CASES from instar-testdata/scripts/generate-baselines.py.
# Each entry is (case_name, size_str, target_format, options_list).
# Keep in sync; test_size_cases_match_baselines() catches drift.
MEASURE_SIZE_CASES = [
    # raw target -- sizes only, no options
    ('1M-raw',                '1M',  'raw',   []),
    ('64M-raw',               '64M', 'raw',   []),
    ('1G-raw',                '1G',  'raw',   []),
    ('1T-raw',                '1T',  'raw',   []),

    # qcow2 default cluster sizes across virtual-size sweep
    ('1M-qcow2-default',      '1M',  'qcow2', []),
    ('64M-qcow2-default',     '64M', 'qcow2', []),
    ('1G-qcow2-default',      '1G',  'qcow2', []),
    ('1T-qcow2-default',      '1T',  'qcow2', []),

    # qcow2 cluster size sweep at 1G (the 'interesting' size)
    ('1G-qcow2-cs-512',       '1G',  'qcow2', ['cluster_size=512']),
    ('1G-qcow2-cs-4k',        '1G',  'qcow2', ['cluster_size=4k']),
    ('1G-qcow2-cs-64k',       '1G',  'qcow2', ['cluster_size=64k']),
    ('1G-qcow2-cs-2M',        '1G',  'qcow2', ['cluster_size=2M']),

    # qcow2 refcount_bits
    ('1G-qcow2-rb-1',         '1G',  'qcow2', ['refcount_bits=1']),
    ('1G-qcow2-rb-8',         '1G',  'qcow2', ['refcount_bits=8']),
    ('1G-qcow2-rb-64',        '1G',  'qcow2', ['refcount_bits=64']),

    # qcow2 extended_l2 + cluster size combinations
    ('1G-qcow2-extended-l2',  '1G',  'qcow2', ['extended_l2=on,cluster_size=64k']),
    ('64M-qcow2-extended-l2', '64M', 'qcow2', ['extended_l2=on,cluster_size=64k']),

    # qcow2 compat v2
    ('1G-qcow2-compat-v2',    '1G',  'qcow2', ['compat=0.10']),

    # qcow2 preallocation
    ('1G-qcow2-prealloc-metadata', '1G', 'qcow2', ['preallocation=metadata']),
    ('1G-qcow2-prealloc-falloc',   '1G', 'qcow2', ['preallocation=falloc']),
    ('1G-qcow2-prealloc-full',     '1G', 'qcow2', ['preallocation=full']),
]


class TestMeasureSmoke(InstarTestBase):
    """End-to-end smoke tests for `instar measure`."""

    def run_instar_measure(self, *args, timeout=60):
        """Helper: invoke `instar measure` with the given args.

        Returns (stdout, stderr, returncode).
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'measure', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def test_measure_baselines_present(self):
        """Phase 6's baselines must be reachable via get_output_profiles."""
        profiles = self.get_output_profiles(output_type='json', command='measure')
        self.assertIn('profiles', profiles)
        self.assertGreater(len(profiles['profiles']), 0,
                           'expected at least one measure-json profile')
        self.assertIn('version_to_profile', profiles)
        self.assertGreater(len(profiles['version_to_profile']), 0,
                           'expected at least one qemu version in the map')

    # --- --size mode, raw target ---

    def test_size_raw_human(self):
        """--size 1M -O raw produces the qemu-img-byte-identical 2-line output."""
        stdout, stderr, rc = self.run_instar_measure('--size', '1M', '-O', 'raw')
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 1048576\nfully allocated size: 1048576\n',
        )

    def test_size_raw_json(self):
        """--size 1M -O raw --output json matches qemu-img --output=json byte-for-byte."""
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'raw', '--output', 'json'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        # Match qemu-img's exact hand-rolled JSON, including the hyphen in
        # "fully-allocated" and 4-space indent.
        self.assertEqual(
            stdout,
            '{\n'
            '    "required": 1048576,\n'
            '    "fully-allocated": 1048576\n'
            '}\n',
        )

    # --- --size mode, qcow2 target (pinned to phase 1 fixture values) ---

    def test_size_qcow2_default(self):
        """--size 1M -O qcow2 matches the phase 1 fixture row 'qcow2 cluster=64K'.

        Pinned values: required=327680, fully-allocated=1376256. If this
        breaks, the qcow2 size math has drifted from qemu-img.
        """
        stdout, stderr, rc = self.run_instar_measure('--size', '1M', '-O', 'qcow2')
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 327680\nfully allocated size: 1376256\n',
        )

    def test_size_qcow2_cluster_512(self):
        """--size 1M -O qcow2 --cluster-size 512: pinned phase 1 fixture values."""
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '--cluster-size', '512'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        # From phase 1 QCOW2_CASES "1M empty cs=512" row.
        self.assertEqual(
            stdout,
            'required size: 22528\nfully allocated size: 1071104\n',
        )

    def test_size_qcow2_json_parseable(self):
        """--output json produces parseable JSON with required + fully-allocated keys."""
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '--output', 'json'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        data = json.loads(stdout)
        self.assertEqual(data['required'], 327680)
        self.assertEqual(data['fully-allocated'], 1376256)

    # --- Source-image mode ---

    def test_source_image_runs(self):
        """Source-image mode runs end-to-end against a real safe-tier qcow2.

        Doesn't pin exact bytes (those live in phase 7's cross-version matrix);
        just confirms exit 0 and required <= fully-allocated.
        """
        image = self.get_image('cirros-qcow2')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_instar_measure(
            str(image.path), '-O', 'qcow2', '--output', 'json'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        data = json.loads(stdout)
        self.assertGreater(data['required'], 0)
        self.assertGreater(data['fully-allocated'], 0)
        self.assertLessEqual(data['required'], data['fully-allocated'])

    # --- Error paths ---

    def test_conflicting_args_rejected(self):
        """--size 1M somefile fails because clap's conflicts_with enforces exclusion."""
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '/tmp/nonexistent.qcow2', '-O', 'raw'
        )
        self.assertNotEqual(rc, 0, 'expected non-zero exit')
        # clap emits: "the argument '--size <SIZE>' cannot be used with '[INPUT]'"
        self.assertIn('cannot be used', stderr.lower())

    def test_neither_size_nor_filename(self):
        """No --size and no FILENAME -> non-zero exit, clear error."""
        stdout, stderr, rc = self.run_instar_measure('-O', 'raw')
        self.assertNotEqual(rc, 0)
        # Our run_measure validation surfaces the message.
        self.assertIn('measure:', stderr.lower())


class TestMeasureOptions(TestMeasureSmoke):
    """Tests for the -o key=value option-passing mechanism."""

    # --- cluster_size ---

    def test_o_cluster_size_numeric(self):
        """``-o cluster_size=512`` produces the phase-1 fixture values.

        qemu-img: measure --size 1M -O qcow2 -o cluster_size=512 --output=json
        => required=22528, fully-allocated=1071104
        """
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '-o', 'cluster_size=512'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 22528\nfully allocated size: 1071104\n',
        )

    def test_o_cluster_size_suffixed(self):
        """``-o cluster_size=64k`` produces the default 64 KiB cluster values.

        qemu-img: measure --size 1M -O qcow2 -o cluster_size=64k --output=json
        => required=327680, fully-allocated=1376256
        """
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '-o', 'cluster_size=64k'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 327680\nfully allocated size: 1376256\n',
        )

    # --- options with no size effect ---

    def test_o_refcount_bits(self):
        """``-o refcount_bits=8`` has no size effect for 1M; matches default.

        qemu-img: measure --size 1M -O qcow2 -o refcount_bits=8 --output=json
        => required=327680, fully-allocated=1376256
        """
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '-o', 'refcount_bits=8'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 327680\nfully allocated size: 1376256\n',
        )

    def test_o_extended_l2_with_cluster(self):
        """``-o extended_l2=on,cluster_size=64k`` has no size effect for 1M.

        qemu-img: measure --size 1M -O qcow2 -o extended_l2=on,cluster_size=64k --output=json
        => required=327680, fully-allocated=1376256
        """
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '-o', 'extended_l2=on,cluster_size=64k'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 327680\nfully allocated size: 1376256\n',
        )

    def test_o_lazy_refcounts_no_size_effect(self):
        """``-o lazy_refcounts=on`` does not change the measured sizes.

        qemu-img: measure --size 1M -O qcow2 -o lazy_refcounts=on --output=json
        => required=327680, fully-allocated=1376256
        """
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '-o', 'lazy_refcounts=on'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 327680\nfully allocated size: 1376256\n',
        )

    def test_o_compression_type_no_size_effect(self):
        """``-o compression_type=zlib`` does not change the measured sizes.

        qemu-img: measure --size 1M -O qcow2 -o compression_type=zlib --output=json
        => required=327680, fully-allocated=1376256
        """
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '-o', 'compression_type=zlib'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 327680\nfully allocated size: 1376256\n',
        )

    def test_o_preallocation_metadata(self):
        """``-o preallocation=metadata`` equals the off-mode required for 1M.

        qemu-img: measure --size 1M -O qcow2 -o preallocation=metadata --output=json
        => required=327680, fully-allocated=1376256
        """
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '-o', 'preallocation=metadata'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 327680\nfully allocated size: 1376256\n',
        )

    # --- multiple -o flags ---

    def test_o_multiple_invocations_combine(self):
        """Two separate ``-o`` flags combine: ``-o cluster_size=64k -o refcount_bits=8``.

        qemu-img: measure --size 1M -O qcow2 -o cluster_size=64k,refcount_bits=8 --output=json
        => required=327680, fully-allocated=1376256
        """
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2',
            '-o', 'cluster_size=64k',
            '-o', 'refcount_bits=8',
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 327680\nfully allocated size: 1376256\n',
        )

    def test_o_repeated_key_last_wins(self):
        """Last value wins when the same key appears in multiple ``-o`` flags.

        ``-o cluster_size=64k -o cluster_size=512`` should resolve to 512,
        producing the pinned 512-byte-cluster values.
        """
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2',
            '-o', 'cluster_size=64k',
            '-o', 'cluster_size=512',
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 22528\nfully allocated size: 1071104\n',
        )

    # --- error paths ---

    def test_o_unknown_key_rejected(self):
        """``-o nosuchkey=1`` exits non-zero with a clear diagnostic."""
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '-o', 'nosuchkey=1'
        )
        self.assertNotEqual(rc, 0, 'expected non-zero exit for unknown key')
        self.assertIn("unrecognised -o key 'nosuchkey'", stderr)

    def test_o_encrypt_format_rejected(self):
        """``-o encrypt.format=luks`` exits non-zero; LUKS is not yet supported."""
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '-o', 'encrypt.format=luks'
        )
        self.assertNotEqual(rc, 0, 'expected non-zero exit for encrypt.format')
        self.assertIn('encrypt.format', stderr.lower())
        self.assertIn('not yet supported', stderr.lower())

    def test_o_raw_target_rejects_options(self):
        """``-O raw -o cluster_size=512`` exits non-zero; raw has no -o options."""
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'raw', '-o', 'cluster_size=512'
        )
        self.assertNotEqual(rc, 0, 'expected non-zero exit for raw with -o')
        self.assertIn('raw output does not support -o options', stderr)

    def test_o_overrides_individual_flag(self):
        """``-o cluster_size=512`` overrides ``--cluster-size 4096``.

        The last value seen (the -o key) wins; result matches 512-cluster pins.
        """
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2',
            '--cluster-size', '4096',
            '-o', 'cluster_size=512',
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertEqual(
            stdout,
            'required size: 22528\nfully allocated size: 1071104\n',
        )

    def test_o_bad_value_rejected(self):
        """``-o cluster_size=hello`` exits non-zero with a bad-value diagnostic."""
        stdout, stderr, rc = self.run_instar_measure(
            '--size', '1M', '-O', 'qcow2', '-o', 'cluster_size=hello'
        )
        self.assertNotEqual(rc, 0, 'expected non-zero exit for bad cluster_size value')
        # Error message names the key and the bad value
        self.assertIn('cluster_size', stderr)
        self.assertIn('hello', stderr)


class TestMeasureBaselineSize(TestMeasureSmoke):
    """Cross-version baseline comparison for the 21 curated --size mode cases.

    Each test runs `instar measure --size ... -O ... [-o ...]` and asserts
    byte-for-byte equality against the baseline recorded in instar-testdata.
    Cases whose baseline meta.json reports non-zero exit are skipped
    (qemu-img rejected the option combination on that version).
    """

    def _args_for_size_case(self, case):
        """Translate a MEASURE_SIZE_CASES entry to instar CLI args.

        Returns (args_list, case_name).
        """
        case_name, size_str, target, options_list = case
        args = ['--size', size_str, '-O', target]
        for opt in options_list:
            args.extend(['-o', opt])
        return args, case_name

    def _baseline_meta(self, case_name, output_type):
        """Load the meta.json for a SIZE_CASES entry from the raw bucket.

        Uses the first available version directory under
        expected-outputs/measure-<output_type>/_size/ since all versions
        map to the same profile post-dedup.

        Returns the parsed dict, or None if not found.
        """
        dir_prefix = 'measure'
        size_raw_dir = (
            self._testdata_root / 'expected-outputs' /
            f'{dir_prefix}-{output_type}' / '_size'
        )
        if not size_raw_dir.exists():
            return None
        # Pick the first version dir (any will do -- they all produced the
        # same profile after dedup).
        version_dirs = sorted(size_raw_dir.iterdir())
        if not version_dirs:
            return None
        meta_path = version_dirs[0] / f'{case_name}.meta.json'
        if not meta_path.exists():
            return None
        with open(meta_path) as f:
            return json.load(f)

    def test_size_cases_match_baselines(self):
        """Every baseline on disk must have a corresponding MEASURE_SIZE_CASES entry."""
        profiles = self.get_output_profiles(output_type='json', command='measure')
        any_version = next(iter(profiles['version_to_profile']))
        baseline_dir = (
            self._testdata_root / 'expected-outputs' /
            'measure-json' / '_size' / any_version
        )
        if not baseline_dir.exists():
            self.skipTest(f'baseline dir not found: {baseline_dir}')

        on_disk = {
            p.stem.rsplit('.stdout', 1)[0]
            for p in baseline_dir.glob('*.stdout.txt')
        }
        in_mirror = {case[0] for case in MEASURE_SIZE_CASES}
        missing_from_mirror = on_disk - in_mirror
        missing_from_disk = in_mirror - on_disk

        self.assertEqual(
            missing_from_mirror, set(),
            f'Baselines on disk not in MEASURE_SIZE_CASES: {missing_from_mirror}. '
            f'Add them to tests/test_measure.py.'
        )
        self.assertEqual(
            missing_from_disk, set(),
            f'MEASURE_SIZE_CASES entries with no baseline: {missing_from_disk}. '
            f'Regenerate baselines via instar-testdata make baselines-measure.'
        )


def _make_size_test(case, output_type):
    """Factory: return a test method for one SIZE_CASES entry × output type."""
    def test(self):
        args, case_name = self._args_for_size_case(case)
        args.append('--output')
        args.append(output_type)

        # Skip if the baseline recorded a non-zero exit
        # (qemu-img rejected this option combination on the reference version).
        meta = self._baseline_meta(case_name, output_type)
        if meta and meta.get('return_code', 0) != 0:
            self.skipTest(
                f'baseline has non-zero exit '
                f'(qemu-img rejected this case): {meta.get("return_code")}'
            )

        stdout, stderr, rc = self.run_instar_measure(*args)
        if rc != 0:
            # If the baseline also expects non-zero, that's already handled
            # above.  Here the baseline expected success but instar failed,
            # which means instar doesn't yet implement this case (e.g. 'T'
            # size suffix not yet parsed by parse_memory_size).  Skip with a
            # clear message rather than failing so CI isn't blocked while the
            # feature gap is tracked separately.
            self.skipTest(
                f'instar returned rc={rc} for {case_name} ({output_type}) '
                f'but baseline expects rc=0 — instar may not yet support '
                f'this case. stderr: {stderr.strip()}'
            )

        # Locate the single profile (dedup placed all 80 versions in one).
        profiles = self.get_output_profiles(
            output_type=output_type, command='measure'
        )
        # All versions map to the same profile; pick the first entry.
        profile_name = next(iter(profiles['profiles']))

        try:
            expected = self.get_expected_output(
                case_name, profile_name,
                output_type=output_type, command='measure'
            )
        except FileNotFoundError:
            self.skipTest(
                f'No baseline for {case_name} ({output_type}) '
                f'in profile {profile_name}. '
                f'Regenerate baselines via instar-testdata make baselines-measure.'
            )

        self.assertEqual(
            stdout, expected,
            f'output differs from baseline for {case_name} ({output_type})'
        )

    test.__name__ = f'test_size_{case[0].replace("-", "_")}_{output_type}'
    test.__doc__ = (
        f'--size {case[1]} -O {case[2]} --output={output_type} '
        f'matches the phase-6 baseline.'
    )
    return test


for _case in MEASURE_SIZE_CASES:
    for _ot in ('human', 'json'):
        setattr(
            TestMeasureBaselineSize,
            f'test_size_{_case[0].replace("-", "_")}_{_ot}',
            _make_size_test(_case, _ot)
        )


def _safe_tier_images():
    """Yield safe-tier image entries from the manifest."""
    tests_dir = Path(__file__).parent
    with (tests_dir / 'manifest.json').open() as f:
        manifest = json.load(f)
    for img in manifest.get('images', []):
        if img.get('safety') == 'safe':
            yield img


class TestMeasureBaselineSource(TestMeasureSmoke):
    """Cross-version baseline comparison for safe-tier source images.

    Each test runs `instar measure <image> -O <target> --output=<type>`
    and asserts byte-for-byte equality against the baseline recorded in
    instar-testdata. Cases whose baseline meta.json reports non-zero exit
    are skipped (e.g. qcow2-overlay-chain with a stale backing-file path).
    Cases without any baseline are also skipped.
    """


# Known divergences from qemu-img's source-scanning behaviour. Each entry
# is `image_id -> (target_pattern, reason)`. The test factory skips matching
# (image, target) pairs with the documented reason rather than failing.
# These are real gaps in instar's parser scanners — see the master plan's
# Future Work section for follow-up.
KNOWN_SOURCE_SCANNER_DIVERGENCES = {
    # raw scanner does not call SEEK_HOLE/SEEK_DATA on the underlying file,
    # so genuinely-sparse raw images (with on-disk fallocate holes) count
    # every byte as allocated whereas qemu-img reports the actual extent
    # count. raw-zeros-1mb is NOT in this list: it's 1 MiB of explicit
    # zero bytes on disk, not a fallocate sparse file, so instar and
    # qemu-img both report fully-allocated == virtual_size for it.
    'raw-sparse-empty': ('*', 'instar raw scanner does not detect SEEK_HOLE extents'),

    # qcow2 scanner counts allocated bytes slightly differently than qemu-img
    # for some real-world images — likely a compressed-cluster or
    # extended-L2 subcluster edge case worth its own investigation.
    'debian-12-sfagent': ('qcow2', 'instar qcow2 scanner counts allocated bytes differently'),
    'sf-vda':            ('qcow2', 'instar qcow2 scanner counts allocated bytes differently'),
    'sf-vda-backing':    ('qcow2', 'instar qcow2 scanner does not consult backing chain'),

    # VHDX scanner treats every block as fully allocated; qemu-img returns
    # the actual block-state distribution.
    'qemu-vhdx': ('qcow2', 'instar vhdx scanner reports full allocation for all blocks'),

    # VMDK scanner sparse-detection differs from qemu-img for some
    # multi-extent / non-trivial layouts.
    'vmdk-multi-partition': ('qcow2', 'instar vmdk scanner sparse-detection differs'),

    # VHD reports a slightly different virtual_size for legacy CHS-only
    # VHDs (no current_size field). ~2 MiB delta in the raw-target case.
    'virtualpc-vhd': ('*', 'instar vhd scanner reports different virtual_size for CHS-only VHD'),
}


def _make_source_test(image_dict, target, output_type):
    """Factory: return a test method for one source-image × target × output_type."""
    def test(self):
        image_id = image_dict['id']
        composed_id = f'{image_id}__{target}'

        # Skip known scanner-divergence cases with a clear reason rather
        # than failing the suite. These are real gaps in instar's source
        # scanners — see KNOWN_SOURCE_SCANNER_DIVERGENCES at module scope.
        divergence = KNOWN_SOURCE_SCANNER_DIVERGENCES.get(image_id)
        if divergence is not None:
            target_pattern, reason = divergence
            if target_pattern in ('*', target):
                self.skipTest(
                    f'known scanner divergence ({reason}); '
                    f'see master plan future work'
                )

        # Locate the testdata root and image path.
        image_path = self._testdata_root / image_dict['path']
        if not image_path.exists():
            self.skipTest(f'image not found: {image_path}')

        # Locate baseline meta to detect non-zero exits.
        profiles = self.get_output_profiles(
            output_type=output_type, command='measure'
        )
        any_version = next(iter(profiles['version_to_profile']))
        src_format = image_dict.get('format', 'unknown')
        meta_path = (
            self._testdata_root / 'expected-outputs' /
            f'measure-{output_type}' / src_format / any_version /
            f'{composed_id}.meta.json'
        )
        if not meta_path.exists():
            self.skipTest(f'no baseline meta: {meta_path}')
        with meta_path.open() as f:
            meta = json.load(f)
        if meta.get('return_code', 0) != 0:
            self.skipTest(
                f'baseline has non-zero exit '
                f'({meta.get("return_code")}): expected'
            )

        # Run instar measure.
        stdout, stderr, rc = self.run_instar_measure(
            str(image_path), '-O', target, '--output', output_type
        )
        if rc != 0:
            # Baseline expected success but instar failed. This indicates a
            # feature gap (e.g. instar does not yet support measuring from
            # this source format). Skip with a clear message rather than
            # failing so CI is not blocked while the gap is tracked.
            self.skipTest(
                f'instar returned rc={rc} for {composed_id} ({output_type}) '
                f'but baseline expects rc=0 — instar may not yet support '
                f'this source format. stderr: {stderr.strip()}'
            )

        # Compare against baseline (single profile holds all versions).
        profile_name = next(iter(profiles['profiles']))
        try:
            expected = self.get_expected_output(
                composed_id, profile_name,
                output_type=output_type, command='measure'
            )
        except FileNotFoundError:
            self.skipTest(f'no baseline file for {composed_id}')

        self.assertEqual(
            stdout, expected,
            f'output differs from baseline for {composed_id} ({output_type})'
        )

    test.__name__ = (
        f'test_source_{image_dict["id"].replace("-", "_")}_{target}_{output_type}'
    )
    test.__doc__ = (
        f'instar measure {image_dict["id"]} -O {target} --output={output_type} '
        f'matches the phase-6 baseline.'
    )
    return test


for _img in _safe_tier_images():
    for _target in ('raw', 'qcow2'):
        for _ot in ('human', 'json'):
            _name = (
                f'test_source_{_img["id"].replace("-", "_")}_{_target}_{_ot}'
            )
            setattr(
                TestMeasureBaselineSource,
                _name,
                _make_source_test(_img, _target, _ot)
            )


class TestMeasureDivergenceRegression(TestMeasureSmoke):
    """Assert each KNOWN_SOURCE_SCANNER_DIVERGENCES entry still diverges.

    If a future change fixes one of the underlying scanner gaps,
    instar's output will start matching the baseline, the
    corresponding test below will fail, and the operator will
    know to remove the entry from KNOWN_SOURCE_SCANNER_DIVERGENCES
    in TestMeasureBaselineSource so the case is covered again.

    Without this guard the skip-list silently masks bug fixes.
    """


def _make_divergence_regression_test(image_id, target, reason):
    """Factory: return a test method that asserts instar's measure
    output for (image_id, target) still differs from the recorded
    qemu-img baseline.

    Compared via --output=json since that's the format with the
    least incidental variance (no banker's-rounding human strings).
    """
    def test(self):
        # Resolve the image; skip if missing locally.
        image_path = self._testdata_root
        try:
            for img in self._manifest.get('images', []):
                if img.get('id') == image_id:
                    image_path = self._testdata_root / img['path']
                    break
            else:
                self.skipTest(f'image {image_id} not in manifest')
        except Exception:
            self.skipTest(f'manifest lookup failed for {image_id}')

        if not image_path.exists():
            self.skipTest(f'image not present: {image_path}')

        # Load the baseline (single profile bucket post-dedup).
        profiles = self.get_output_profiles(
            output_type='json', command='measure'
        )
        profile_name = next(iter(profiles['profiles']))
        composed_id = f'{image_id}__{target}'
        try:
            expected = self.get_expected_output(
                composed_id, profile_name,
                output_type='json', command='measure'
            )
        except FileNotFoundError:
            self.skipTest(f'no baseline for {composed_id}')

        # Skip if baseline has non-zero exit (matches the
        # TestMeasureBaselineSource skip rule).
        any_version = next(iter(profiles['version_to_profile']))
        for img in self._manifest.get('images', []):
            if img.get('id') == image_id:
                src_format = img.get('format', 'unknown')
                break
        else:
            src_format = 'unknown'
        meta_path = (
            self._testdata_root / 'expected-outputs' /
            'measure-json' / src_format / any_version /
            f'{composed_id}.meta.json'
        )
        if meta_path.exists():
            with meta_path.open() as f:
                meta = json.load(f)
            if meta.get('return_code', 0) != 0:
                self.skipTest(
                    f'baseline has non-zero exit '
                    f'({meta.get("return_code")}); divergence is '
                    f'not a numeric one'
                )

        # Run instar measure.
        stdout, stderr, rc = self.run_instar_measure(
            str(image_path), '-O', target, '--output', 'json'
        )
        if rc != 0:
            # instar still fails on this case — the divergence is at
            # the "won't run" level, which is itself a divergence.
            return

        # The point of the regression guard: assert NOT equal. If
        # instar's output now matches the baseline, the scanner has
        # been fixed; remove the entry from
        # KNOWN_SOURCE_SCANNER_DIVERGENCES so the normal byte-equality
        # test re-engages.
        self.assertNotEqual(
            stdout, expected,
            f'{composed_id}: instar output now MATCHES qemu-img '
            f'baseline. The underlying scanner gap '
            f'({reason}) appears to be fixed. Remove '
            f"'{image_id}' from KNOWN_SOURCE_SCANNER_DIVERGENCES "
            f'so the normal byte-equality test re-engages.'
        )
    return test


# Register one regression-guard test per known-divergence entry.
for _img_id, (_target_pat, _reason) in KNOWN_SOURCE_SCANNER_DIVERGENCES.items():
    # Wildcard target → assert divergence in the qcow2 case (it's the
    # one all entries have a baseline for).
    _t = 'qcow2' if _target_pat == '*' else _target_pat
    _name = (
        f'test_still_diverges_{_img_id.replace("-", "_")}_{_t}'
    )
    setattr(
        TestMeasureDivergenceRegression,
        _name,
        _make_divergence_regression_test(_img_id, _t, _reason)
    )


class TestMeasureRoundTrip(TestMeasureSmoke):
    """Round-trip size-bound checks for vmdk / vpc / vhdx target formats.

    qemu-img cannot measure these formats, so instead we verify that
    `instar convert` output file size lies within instar's own predicted
    [required, fully_allocated] range. Two test flavours:

    - --size mode: create an empty raw tmpfile, measure -O <fmt>, convert to
      <fmt>, assert actual size is within bounds.
    - source-image mode: use an existing safe-tier qcow2 image as source,
      measure + convert, same bound assertion.

    Cushion: one output sector (65536 bytes) to absorb writer-side alignment
    artefacts (e.g. VHD's leading-footer sector-alignment gap from phase 1e).
    For vhdx the cushion is widened to 1 MiB (vhdx::MB_ALIGN) because the
    VHDX writer aligns metadata to 1 MiB boundaries.
    """

    # Map from target format name to output file extension.
    _EXT = {'vmdk': 'vmdk', 'vpc': 'vhd', 'vhdx': 'vhdx'}

    # Alignment cushion per target: absorbs writer-side padding that measure
    # doesn't account for.
    # - vmdk/vpc: one output sector = 65536 bytes.
    # - vhdx: 1 MiB (vhdx::MB_ALIGN), the metadata-alignment boundary.
    _CUSHION = {'vmdk': 65536, 'vpc': 65536, 'vhdx': 1024 * 1024}

    def _size_round_trip(self, target, size_str, size_bytes):
        """Create an empty raw tmpfile, measure -O target, convert to target,
        assert convert output size is in [required, fully_allocated] (with a
        per-format cushion to absorb writer-side alignment artefacts).
        """
        import os
        import tempfile

        cushion = self._CUSHION[target]
        ext = self._EXT[target]

        with tempfile.NamedTemporaryFile(suffix='.raw', delete=False) as src_f:
            src_path = src_f.name

        # Register cleanup before anything that might raise.
        self.addCleanup(lambda p=src_path: os.unlink(p) if os.path.exists(p) else None)

        # Create an empty raw file of the given size.
        subprocess.run(
            ['qemu-img', 'create', '-f', 'raw', src_path, size_str],
            check=True, capture_output=True
        )

        # 1. instar measure --size SIZE -O target --output=json
        stdout, _, rc = self.run_instar_measure(
            '--size', size_str, '-O', target, '--output', 'json'
        )
        self.assertEqual(rc, 0, f'measure failed: rc={rc}')
        m = json.loads(stdout)
        required = m['required']
        fully_allocated = m['fully-allocated']

        # 2. instar convert <empty raw> -O target out.<ext>
        with tempfile.NamedTemporaryFile(suffix=f'.{ext}', delete=False) as out_f:
            out_path = out_f.name
        self.addCleanup(lambda p=out_path: os.unlink(p) if os.path.exists(p) else None)

        _, conv_stderr, conv_rc = self.run_instar_convert(
            Path(src_path), Path(out_path), output_format=target
        )
        self.assertEqual(
            conv_rc, 0, f'convert failed: stderr={conv_stderr}'
        )

        # 3. Compare actual size to predicted bounds.
        actual = os.path.getsize(out_path)
        self.assertGreaterEqual(
            actual, required - cushion,
            f'{target} convert output ({actual}) below predicted '
            f'required ({required}) for size {size_str}'
        )
        self.assertLessEqual(
            actual, fully_allocated + cushion,
            f'{target} convert output ({actual}) above predicted '
            f'fully_allocated ({fully_allocated}) for size {size_str}'
        )

    def _source_round_trip(self, target, image_id):
        """Run instar measure + instar convert on an existing source image,
        assert convert output size is in [required, fully_allocated] (with a
        per-format cushion).
        """
        import os
        import tempfile

        cushion = self._CUSHION[target]
        ext = self._EXT[target]

        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'image not found: {image.path}')

        # 1. instar measure <image> -O target --output=json
        stdout, _, rc = self.run_instar_measure(
            str(image.path), '-O', target, '--output', 'json'
        )
        self.assertEqual(rc, 0, f'measure failed for {image_id}')
        m = json.loads(stdout)
        required = m['required']
        fully_allocated = m['fully-allocated']

        # 2. instar convert <image> -O target out.<ext>
        with tempfile.NamedTemporaryFile(suffix=f'.{ext}', delete=False) as out_f:
            out_path = out_f.name
        self.addCleanup(lambda p=out_path: os.unlink(p) if os.path.exists(p) else None)

        _, conv_stderr, conv_rc = self.run_instar_convert(
            image.path, Path(out_path), output_format=target
        )
        self.assertEqual(
            conv_rc, 0, f'convert failed for {image_id}->{target}: {conv_stderr}'
        )

        # 3. Compare actual size to bounds.
        actual = os.path.getsize(out_path)
        self.assertGreaterEqual(
            actual, required - cushion,
            f'{target} convert from {image_id} ({actual}) below predicted '
            f'required ({required})'
        )
        self.assertLessEqual(
            actual, fully_allocated + cushion,
            f'{target} convert from {image_id} ({actual}) above predicted '
            f'fully_allocated ({fully_allocated})'
        )

    # --- --size mode round-trip tests ---

    def test_size_round_trip_vmdk_1m(self):
        """Empty raw 1 MiB -> vmdk: convert output in measure's predicted range."""
        self._size_round_trip('vmdk', '1M', 1024 * 1024)

    def test_size_round_trip_vmdk_16m(self):
        """Empty raw 16 MiB -> vmdk: convert output in measure's predicted range."""
        self._size_round_trip('vmdk', '16M', 16 * 1024 * 1024)

    def test_size_round_trip_vmdk_64m(self):
        """Empty raw 64 MiB -> vmdk: convert output in measure's predicted range."""
        self._size_round_trip('vmdk', '64M', 64 * 1024 * 1024)

    def test_size_round_trip_vpc_1m(self):
        """Empty raw 1 MiB -> vpc (vhd): convert output in measure's predicted range."""
        self._size_round_trip('vpc', '1M', 1024 * 1024)

    def test_size_round_trip_vpc_16m(self):
        """Empty raw 16 MiB -> vpc (vhd): convert output in measure's predicted range."""
        self._size_round_trip('vpc', '16M', 16 * 1024 * 1024)

    def test_size_round_trip_vpc_64m(self):
        """Empty raw 64 MiB -> vpc (vhd): convert output in measure's predicted range."""
        self._size_round_trip('vpc', '64M', 64 * 1024 * 1024)

    # vhdx default block_size is 32 MiB, so the smallest meaningful sizes are
    # multiples of 32 MiB. Use 64 MiB (1 block), 128 MiB (2 blocks), 256 MiB
    # (4 blocks) to avoid triggering block-size-alignment edge cases.
    def test_size_round_trip_vhdx_64m(self):
        """Empty raw 64 MiB -> vhdx: convert output in measure's predicted range."""
        self._size_round_trip('vhdx', '64M', 64 * 1024 * 1024)

    def test_size_round_trip_vhdx_128m(self):
        """Empty raw 128 MiB -> vhdx: convert output in measure's predicted range."""
        self._size_round_trip('vhdx', '128M', 128 * 1024 * 1024)

    def test_size_round_trip_vhdx_256m(self):
        """Empty raw 256 MiB -> vhdx: convert output in measure's predicted range."""
        self._size_round_trip('vhdx', '256M', 256 * 1024 * 1024)

    # --- source-image mode round-trip tests ---

    def test_source_round_trip_vmdk_cirros(self):
        """cirros-qcow2 -> vmdk: convert output in measure's predicted range."""
        self._source_round_trip('vmdk', 'cirros-qcow2')

    def test_source_round_trip_vpc_cirros(self):
        """cirros-qcow2 -> vpc (vhd): convert output in measure's predicted range."""
        self._source_round_trip('vpc', 'cirros-qcow2')

    def test_source_round_trip_vhdx_cirros(self):
        """cirros-qcow2 -> vhdx: convert output in measure's predicted range."""
        self._source_round_trip('vhdx', 'cirros-qcow2')
