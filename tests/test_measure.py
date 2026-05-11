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
