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
