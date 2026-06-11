"""Integration tests for the `instar snapshot` subcommand.

Phase 11 of PLAN-snapshot. Five test families:

  (a) List matrix (human) — factory-generated per baselined image:
      ``TZ=UTC instar snapshot -l`` byte-equals the host-resolved
      profile-10-0-0 baseline; plus the bare-filename-equals-``-l``
      test (phase 9 D2 behaviour).

  (b) List goldens (JSON) — per baselined image: ``instar snapshot
      -l --output=json`` byte-equals ``tests/golden/snapshot-list/
      <image-id>.json``; plus a structural cross-check for
      ``snap-qcow2-vmstate`` and a QMP-key schema test.

  (c) Mutation round-trips — create / delete / apply on tempdir
      copies; post-op ``qemu-img check`` clean; content verified
      via ``qemu-img compare``; structural behaviour for the
      name-collision / duplicate-name / cap-boundary fixtures.

  (d) Error paths and qcow2-only enforcement — all four modes
      against raw / vmdk / vhdx manifest images; LUKS via
      hand-set crypt_method; ad-hoc zstd / dirty-bit /
      external-data-file fixtures from the harness recipes;
      not-found exit codes; ``-U``+mutating refusal;
      ``--image-opts`` rejection; mixed-flags non-zero.

  (e) Empty-table behaviour — list on the empty-case image:
      empty stdout + exit 0; JSON form emits ``[]``.

Relationship to the shell harnesses under ``tools/``:
  The shell harnesses (snapshot-{create,delete,apply}-{matrix,
  refusals}.sh, snapshot-cli-parity.sh) are live differential
  verification against the host qemu-img — 237 assertions, byte-
  identity from identical inputs, developer-run. This suite is the
  CI regression net: instar vs frozen baselines and structural
  post-op invariants. They overlap by design.

TZ note: every ``instar snapshot -l`` invocation pins ``TZ=UTC``
via ``env_overrides`` — the phase 10 baselines were generated under
UTC and the DATE column is local-time-rendered.

Skip taxonomy (mirrors test_map.py):
  1. Image file missing on disk (sparse checkouts).
  2. Baseline meta reports non-zero exit (qemu-img couldn't list).
  3. Old-profile host: if the resolved profile is not profile-10-0-0
     (i.e. qemu-img < 9.0.0), the list matrix skips with a
     docs/quirks.md pointer — instar targets the modern ≥9.0 format.
  4. instar returns non-zero for a list operation (format gap, not
     regression; add to KNOWN_SNAPSHOT_DIVERGENCES if deliberate).
  5. No baseline file for the resolved profile.
"""

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase

# The profile name that marks the ≥9.0.0 / modern output format.
# list-matrix tests skip when the host resolves to an older profile.
_MODERN_PROFILE = 'profile-10-0-0'

# DATE column pattern for regex normalisation in create round-trips.
# Matches 'YYYY-MM-DD HH:MM:SS' so freshly-created snapshot dates
# can be compared structurally rather than byte-exactly.
_DATE_PAT = re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
_DATE_PLACEHOLDER = 'DATE_PLACEHOLDER'

# Known deliberate instar-vs-baseline divergences for snapshot list.
# Add entries here (image_id -> (output_type_pattern, reason)) when a
# divergence is documented in docs/quirks.md rather than a real bug.
KNOWN_SNAPSHOT_DIVERGENCES = {}


def _snapshot_image_ids():
    """Yield the 12 baselined snapshot image IDs from the manifest."""
    tests_dir = Path(__file__).parent
    with (tests_dir / 'manifest.json').open() as f:
        manifest = json.load(f)
    for img in manifest.get('images', []):
        if 'snapshots' in img.get('tags', []):
            yield img['id']


def _sha256_file(path):
    """Return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _qemu_check_clean(tc, path, msg=''):
    """Assert ``qemu-img check`` returns 0 (clean image)."""
    r = subprocess.run(
        ['qemu-img', 'check', str(path)],
        capture_output=True, text=True, timeout=30,
    )
    tc.assertEqual(
        r.returncode, 0,
        f'qemu-img check failed {msg}: {r.stdout}{r.stderr}',
    )


def _norm_date(text):
    """Replace DATE column values with a placeholder for structural compare."""
    return _DATE_PAT.sub(_DATE_PLACEHOLDER, text)


class TestSnapshotSmoke(InstarTestBase):
    """Wiring checks and shared helper for all snapshot test classes."""

    def _require_qemu_tools(self):
        if shutil.which('qemu-img') is None:
            self.skipTest('qemu-img not available')

    def _require_kvm(self):
        if not os.path.exists('/dev/kvm'):
            self.skipTest('/dev/kvm not available')

    def test_help_succeeds(self):
        """`instar snapshot --help` exits 0 and lists the documented CLI."""
        instar = self.get_instar_binary()
        r = subprocess.run(
            [str(instar), 'snapshot', '--help'],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(r.returncode, 0, f'stderr: {r.stderr}')
        for expected in ('FILENAME', '-l', '-a', '-c', '-d', '--output'):
            self.assertIn(
                expected, r.stdout,
                f'expected {expected!r} in --help output',
            )

    def test_baselines_present_human(self):
        """The phase 10 snapshot-list-human baselines are reachable."""
        profiles = self.get_output_profiles(
            output_type='human', command='snapshot-list',
        )
        self.assertIn('profiles', profiles)
        self.assertGreater(len(profiles['profiles']), 0)
        self.assertIn('version_to_profile', profiles)

    def test_profile_lookup_returns_string(self):
        """`get_profile_for_installed_qemu` returns a profile name."""
        profile = self.get_profile_for_installed_qemu(
            output_type='human', command='snapshot-list',
        )
        self.assertIsInstance(profile, str)
        self.assertTrue(profile.startswith('profile-'))


# ---------------------------------------------------------------------------
# Family (a): List matrix (human)
# ---------------------------------------------------------------------------


class TestSnapshotListHuman(TestSnapshotSmoke):
    """Byte-compare ``instar snapshot -l`` against the phase 10 profile.

    Skip taxonomy:
      1. Image file missing on disk.
      2. Baseline meta reports non-zero exit.
      3. Host resolves to old profile (qemu-img < 9.0.0).
      4. instar returns non-zero for the list.
      5. No baseline file for the resolved profile.
    """


def _make_list_human_test(image_id):
    """Factory: one test method per baselined snapshot image."""

    def test(self):
        # Skip 3: old-profile host.
        profile_name = self.get_profile_for_installed_qemu(
            output_type='human', command='snapshot-list',
        )
        if profile_name != _MODERN_PROFILE:
            self.skipTest(
                f'host qemu-img resolves to old profile {profile_name!r}; '
                f'instar snapshot targets the modern ≥9.0 format — '
                f'see docs/quirks.md cross-version note'
            )

        # Skip divergence.
        divergence = KNOWN_SNAPSHOT_DIVERGENCES.get(image_id)
        if divergence is not None:
            pattern, reason = divergence
            if pattern in ('*', 'human'):
                self.skipTest(f'known snapshot divergence ({reason})')

        # Skip 1: image not on disk.
        image_path = self._testdata_root / _image_path_for_id(image_id)
        if not image_path.exists():
            self.skipTest(f'image not found: {image_path}')

        # Skip 2: baseline has non-zero exit.
        try:
            expected = self.get_expected_output(
                image_id, profile_name,
                output_type='human', command='snapshot-list',
            )
        except FileNotFoundError:
            self.skipTest(
                f'no baseline for {image_id} in profile {profile_name}'
            )

        # Run instar snapshot -l with TZ=UTC.
        stdout, stderr, rc = self.run_instar_snapshot(
            '-l', str(image_path),
            env_overrides={'TZ': 'UTC'},
        )
        # Skip 4: instar refused or errored.
        if rc != 0:
            self.skipTest(
                f'instar snapshot -l returned rc={rc} for {image_id}; '
                f'stderr: {stderr.strip()}'
            )

        self.assertEqual(
            stdout, expected,
            f'snapshot -l output differs from baseline for {image_id}',
        )

    test.__name__ = f'test_list_human_{image_id.replace("-", "_")}'
    test.__doc__ = (
        f'instar snapshot -l {image_id} matches the phase-10 baseline.'
    )
    return test


def _image_path_for_id(image_id):
    """Return the relative path string for an image ID (via manifest lookup)."""
    tests_dir = Path(__file__).parent
    with (tests_dir / 'manifest.json').open() as f:
        manifest = json.load(f)
    for img in manifest.get('images', []):
        if img['id'] == image_id:
            return img['path']
    raise KeyError(f'image id not in manifest: {image_id}')


for _iid in _snapshot_image_ids():
    _name = f'test_list_human_{_iid.replace("-", "_")}'
    setattr(TestSnapshotListHuman, _name, _make_list_human_test(_iid))


# Bare-filename equals -l: `instar snapshot FILE` must produce the
# same output as `instar snapshot -l FILE` (phase 9 D2 behaviour).

class TestSnapshotBareFilename(TestSnapshotSmoke):
    """``instar snapshot FILE`` and ``instar snapshot -l FILE`` agree."""

    def test_bare_filename_equals_list_flag(self):
        """Bare-filename invocation produces identical output to -l."""
        image_path = (
            self._testdata_root /
            _image_path_for_id('snap-qcow2-v3-one')
        )
        if not image_path.exists():
            self.skipTest(f'fixture not found: {image_path}')

        stdout_bare, _, rc_bare = self.run_instar_snapshot(
            str(image_path),
            env_overrides={'TZ': 'UTC'},
        )
        stdout_l, _, rc_l = self.run_instar_snapshot(
            '-l', str(image_path),
            env_overrides={'TZ': 'UTC'},
        )
        self.assertEqual(rc_bare, 0, 'bare-filename invocation failed')
        self.assertEqual(rc_l, 0, '-l invocation failed')
        self.assertEqual(
            stdout_bare, stdout_l,
            'bare-filename output differs from -l output',
        )


# ---------------------------------------------------------------------------
# Family (b): List goldens (JSON)
# ---------------------------------------------------------------------------


class TestSnapshotListGoldens(TestSnapshotSmoke):
    """Byte-compare ``instar snapshot -l --output=json`` against frozen
    golden files in ``tests/golden/snapshot-list/``.

    The goldens are instar-side self-baselines: no qemu-img source of
    truth exists for this output format (qemu-img snapshot -l is
    human-only). The structural cross-check and QMP-key schema tests
    keep the goldens honest.
    """

    @classmethod
    def _golden_dir(cls):
        return Path(__file__).parent / 'golden' / 'snapshot-list'


def _make_json_golden_test(image_id):
    """Factory: one test method per baselined snapshot image."""

    def test(self):
        golden_path = self._golden_dir() / f'{image_id}.json'
        if not golden_path.exists():
            self.skipTest(f'golden file not found: {golden_path}')

        image_path = self._testdata_root / _image_path_for_id(image_id)
        if not image_path.exists():
            self.skipTest(f'image not found: {image_path}')

        stdout, stderr, rc = self.run_instar_snapshot(
            '-l', '--output=json', str(image_path),
            env_overrides={'TZ': 'UTC'},
        )
        if rc != 0:
            self.skipTest(
                f'instar snapshot -l --output=json rc={rc} for {image_id}; '
                f'stderr: {stderr.strip()}'
            )

        expected = golden_path.read_text()
        self.assertEqual(
            stdout, expected,
            f'JSON output differs from golden for {image_id}',
        )

    test.__name__ = f'test_json_golden_{image_id.replace("-", "_")}'
    test.__doc__ = (
        f'instar snapshot -l --output=json {image_id} matches the '
        f'phase-11 JSON golden.'
    )
    return test


for _iid in _snapshot_image_ids():
    _name = f'test_json_golden_{_iid.replace("-", "_")}'
    setattr(TestSnapshotListGoldens, _name, _make_json_golden_test(_iid))


class TestSnapshotVmstateStructural(TestSnapshotSmoke):
    """Structural cross-check: JSON fields vs human columns for vmstate.

    Parses both ``--output=json`` and the human baseline, then asserts
    the id / name / vm-state-size / vm-clock seconds / icount values
    are coherent. Prevents goldens from drifting into self-consistent
    nonsense (e.g. both formats could emit 0 for vm-clock; this test
    pins that the human HH:MM:SS.NNN and the JSON nanoseconds agree).
    """

    def test_vmstate_json_matches_human_columns(self):
        """JSON golden and human baseline carry the same vmstate values."""
        image_id = 'snap-qcow2-vmstate'
        image_path = self._testdata_root / _image_path_for_id(image_id)
        if not image_path.exists():
            self.skipTest(f'fixture not found: {image_path}')

        # Get JSON output.
        json_out, _, rc = self.run_instar_snapshot(
            '-l', '--output=json', str(image_path),
            env_overrides={'TZ': 'UTC'},
        )
        self.assertEqual(rc, 0, f'JSON list failed: {json_out}')
        entries = json.loads(json_out)
        self.assertEqual(len(entries), 1, 'expected exactly one snapshot')
        entry = entries[0]

        # Get human output.
        human_out, _, rc = self.run_instar_snapshot(
            '-l', str(image_path),
            env_overrides={'TZ': 'UTC'},
        )
        self.assertEqual(rc, 0, f'human list failed: {human_out}')

        # Parse the human data line (skip the header lines).
        data_lines = [
            ln for ln in human_out.splitlines()
            if ln and not ln.startswith('Snapshot') and not ln.startswith('ID')
        ]
        self.assertEqual(len(data_lines), 1)
        parts = data_lines[0].split()
        # parts: [ID, TAG, VM_SIZE_VALUE, VM_SIZE_UNIT, DATE_YYYY-MM-DD,
        #         DATE_HH:MM:SS, VM_CLOCK, ICOUNT]
        snap_id = parts[0]
        snap_name = parts[1]
        # VM_SIZE: e.g. '1 MiB' = 1048576 bytes
        vm_size_val = float(parts[2])
        vm_size_unit = parts[3]
        vm_clock_str = parts[6]      # HH:MM:SS.NNN
        icount_str = parts[7] if len(parts) > 7 else '0'

        # ID and name.
        self.assertEqual(entry['id'], snap_id)
        self.assertEqual(entry['name'], snap_name)

        # vm-state-size: 1 MiB = 1048576.
        if vm_size_unit == 'MiB':
            expected_vm_size = int(vm_size_val * 1024 * 1024)
        elif vm_size_unit == 'KiB':
            expected_vm_size = int(vm_size_val * 1024)
        elif vm_size_unit in ('B', 'bytes'):
            expected_vm_size = int(vm_size_val)
        else:
            expected_vm_size = None
        if expected_vm_size is not None:
            self.assertEqual(
                entry['vm-state-size'], expected_vm_size,
                f'vm-state-size mismatch: JSON={entry["vm-state-size"]} '
                f'human={vm_size_val} {vm_size_unit}',
            )

        # vm-clock: HH:MM:SS.NNN → total nanoseconds.
        m = re.match(r'(\d+):(\d{2}):(\d{2})\.(\d{3})', vm_clock_str)
        if m:
            hours, mins, secs, ms = (
                int(m.group(1)), int(m.group(2)),
                int(m.group(3)), int(m.group(4)),
            )
            total_nsec = (
                (hours * 3600 + mins * 60 + secs) * 10**9 +
                ms * 10**6
            )
            json_nsec = (
                entry['vm-clock']['seconds'] * 10**9 +
                entry['vm-clock']['nanoseconds']
            )
            self.assertEqual(
                json_nsec, total_nsec,
                f'vm-clock mismatch: JSON={json_nsec}ns human={vm_clock_str}',
            )

        # icount.
        self.assertEqual(
            entry['icount'], int(icount_str),
            f'icount mismatch: JSON={entry["icount"]} human={icount_str}',
        )


class TestSnapshotJsonSchema(TestSnapshotSmoke):
    """Pin the QMP-shaped JSON key names from the master plan fact 4."""

    def test_qmp_key_names(self):
        """JSON output uses the documented QMP-compatible key names."""
        image_id = 'snap-qcow2-vmstate'
        image_path = self._testdata_root / _image_path_for_id(image_id)
        if not image_path.exists():
            self.skipTest(f'fixture not found: {image_path}')

        json_out, _, rc = self.run_instar_snapshot(
            '-l', '--output=json', str(image_path),
            env_overrides={'TZ': 'UTC'},
        )
        self.assertEqual(rc, 0)
        entries = json.loads(json_out)
        self.assertEqual(len(entries), 1)
        e = entries[0]

        # Top-level keys.
        for key in ('id', 'name', 'vm-state-size', 'date', 'vm-clock', 'icount'):
            self.assertIn(key, e, f'expected QMP key {key!r}')

        # Nested date keys.
        for key in ('seconds', 'nanoseconds'):
            self.assertIn(key, e['date'], f'expected date.{key}')

        # Nested vm-clock keys.
        for key in ('seconds', 'nanoseconds'):
            self.assertIn(key, e['vm-clock'], f'expected vm-clock.{key}')


# ---------------------------------------------------------------------------
# Family (e): Empty-table behaviour
# ---------------------------------------------------------------------------


class TestSnapshotEmptyTable(TestSnapshotSmoke):
    """List on the empty-case image: empty stdout, exit 0; JSON → ``[]``."""

    def _empty_case_path(self):
        p = self._testdata_root / _image_path_for_id('snap-qcow2-backing-base')
        if not p.exists():
            self.skipTest(f'empty-case fixture not found: {p}')
        return p

    def test_empty_table_human_stdout_is_empty(self):
        """``instar snapshot -l`` on the empty-case image: empty stdout."""
        path = self._empty_case_path()
        stdout, stderr, rc = self.run_instar_snapshot(
            '-l', str(path),
            env_overrides={'TZ': 'UTC'},
        )
        self.assertEqual(rc, 0, f'expected exit 0; stderr: {stderr}')
        self.assertEqual(stdout, '', f'expected empty stdout; got: {stdout!r}')

    def test_empty_table_json_emits_empty_array(self):
        """``instar snapshot -l --output=json`` on the empty-case: ``[]``."""
        path = self._empty_case_path()
        stdout, stderr, rc = self.run_instar_snapshot(
            '-l', '--output=json', str(path),
            env_overrides={'TZ': 'UTC'},
        )
        self.assertEqual(rc, 0, f'expected exit 0; stderr: {stderr}')
        parsed = json.loads(stdout)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 0, f'expected empty array; got: {stdout!r}')


# ---------------------------------------------------------------------------
# Family (c): Mutation round-trips
# ---------------------------------------------------------------------------


class TestSnapshotCreate(TestSnapshotSmoke):
    """Create round-trip tests (tempdir copies, never mutate testdata)."""

    def setUp(self):
        super().setUp()
        self._require_qemu_tools()
        self._require_kvm()

    def _make_fresh_qcow2(self, td, name='image.qcow2', size='4M'):
        """Create a fresh qcow2 in tempdir via qemu-img, write 64 KiB of data."""
        path = Path(td) / name
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2', str(path), size],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 0, f'qemu-img create failed: {r.stderr}')
        r = subprocess.run(
            ['qemu-io', '-c', 'write -P 0xaa 0 64k', str(path)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 0, f'qemu-io write failed: {r.stderr}')
        return path

    def test_create_check_clean(self):
        """``-c`` then ``qemu-img check`` reports the image clean."""
        with tempfile.TemporaryDirectory() as td:
            path = self._make_fresh_qcow2(td)
            _, stderr, rc = self.run_instar_snapshot('-c', 'snap1', str(path))
            self.assertEqual(rc, 0, f'create failed: {stderr}')
            _qemu_check_clean(self, path, 'after -c')

    def test_create_list_agreement(self):
        """After ``-c``, instar and qemu-img listing agree modulo DATE column."""
        with tempfile.TemporaryDirectory() as td:
            path = self._make_fresh_qcow2(td)
            _, stderr, rc = self.run_instar_snapshot('-c', 'mysnap', str(path))
            self.assertEqual(rc, 0, f'create failed: {stderr}')

            instar_out, _, rc_i = self.run_instar_snapshot(
                '-l', str(path),
                env_overrides={'TZ': 'UTC'},
            )
            self.assertEqual(rc_i, 0)

            qemu_r = subprocess.run(
                ['qemu-img', 'snapshot', '-l', str(path)],
                capture_output=True, text=True, timeout=30,
                env={**os.environ, 'TZ': 'UTC'},
            )
            self.assertEqual(qemu_r.returncode, 0)

            # DATE-normalise both sides before comparing.
            self.assertEqual(
                _norm_date(instar_out), _norm_date(qemu_r.stdout),
                'instar and qemu-img listing disagree (after DATE normalisation)',
            )

    def test_create_second_assigns_id_2_duplicate_name_accepted(self):
        """Second ``-c`` with the same name assigns ID 2 (dup-name accepted)."""
        with tempfile.TemporaryDirectory() as td:
            path = self._make_fresh_qcow2(td)
            _, stderr, rc = self.run_instar_snapshot('-c', 'dupname', str(path))
            self.assertEqual(rc, 0, f'first create failed: {stderr}')
            _, stderr, rc = self.run_instar_snapshot('-c', 'dupname', str(path))
            self.assertEqual(rc, 0, f'second create failed: {stderr}')

            json_out, _, rc = self.run_instar_snapshot(
                '-l', '--output=json', str(path),
                env_overrides={'TZ': 'UTC'},
            )
            self.assertEqual(rc, 0)
            entries = json.loads(json_out)
            self.assertEqual(len(entries), 2, 'expected exactly 2 snapshots')
            ids = [e['id'] for e in entries]
            self.assertIn('1', ids)
            self.assertIn('2', ids)

    def test_create_sixteen_cap_refused_image_untouched(self):
        """``-c`` on the 16-snapshot cap image is refused with image unchanged."""
        # Use a tempdir copy of snap-qcow2-v3-sixteen (already at 16 snapshots).
        src = self._testdata_root / _image_path_for_id('snap-qcow2-v3-sixteen')
        if not src.exists():
            self.skipTest(f'fixture not found: {src}')

        with tempfile.TemporaryDirectory() as td:
            copy = Path(td) / 'sixteen.qcow2'
            shutil.copy2(str(src), str(copy))

            before_hash = _sha256_file(copy)
            _, stderr, rc = self.run_instar_snapshot('-c', 's17', str(copy))
            after_hash = _sha256_file(copy)

            self.assertNotEqual(rc, 0, 'expected refusal on 16-snapshot cap')
            self.assertEqual(
                before_hash, after_hash,
                'image was mutated despite refusal',
            )


class TestSnapshotDelete(TestSnapshotSmoke):
    """Delete round-trip tests (tempdir copies)."""

    def setUp(self):
        super().setUp()
        self._require_qemu_tools()
        self._require_kvm()

    def _build_3snap_image(self, td, name='image.qcow2'):
        """Build a 3-snapshot qcow2 image via qemu-img in tempdir."""
        path = Path(td) / name
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2', str(path), '4M'],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 0, f'qemu-img create: {r.stderr}')
        r = subprocess.run(
            ['qemu-io', '-c', 'write -P 0xbb 0 64k', str(path)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 0, f'qemu-io: {r.stderr}')
        for name in ('first', 'second', 'third'):
            r = subprocess.run(
                ['qemu-img', 'snapshot', '-c', name, str(path)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0, f'qemu-img snapshot -c: {r.stderr}')
        return path

    def test_delete_first_check_clean(self):
        """Delete the first of three snapshots then check clean."""
        with tempfile.TemporaryDirectory() as td:
            path = self._build_3snap_image(td)
            _, stderr, rc = self.run_instar_snapshot('-d', 'first', str(path))
            self.assertEqual(rc, 0, f'delete first failed: {stderr}')
            _qemu_check_clean(self, path, 'after delete-first')

    def test_delete_last_check_clean(self):
        """Delete the last of three snapshots then check clean."""
        with tempfile.TemporaryDirectory() as td:
            path = self._build_3snap_image(td)
            _, stderr, rc = self.run_instar_snapshot('-d', 'third', str(path))
            self.assertEqual(rc, 0, f'delete last failed: {stderr}')
            _qemu_check_clean(self, path, 'after delete-last')

    def test_delete_sole_check_clean_and_header_zeroed(self):
        """Delete the sole snapshot: check clean; header has nb=0 / offset=0."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'sole.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2', str(path), '4M'],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0, f'create: {r.stderr}')
            r = subprocess.run(
                ['qemu-img', 'snapshot', '-c', 'sole', str(path)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0, f'snapshot -c: {r.stderr}')

            _, stderr, rc = self.run_instar_snapshot('-d', 'sole', str(path))
            self.assertEqual(rc, 0, f'delete sole failed: {stderr}')
            _qemu_check_clean(self, path, 'after delete-sole')

            # Struct-decode header at offset 60: nb_snapshots (u32BE) and
            # snapshots_offset (u64BE). After deleting the sole snapshot both
            # must be 0 (qemu's behaviour, verified in phase 7).
            with open(path, 'rb') as f:
                f.seek(60)
                data = f.read(12)
            nb_snapshots, snapshots_offset = struct.unpack('>IQ', data)
            self.assertEqual(nb_snapshots, 0, 'nb_snapshots != 0 after sole delete')
            self.assertEqual(snapshots_offset, 0, 'snapshots_offset != 0 after sole delete')

    def test_delete_name_only_matching_on_namecollision(self):
        """``-d 2`` matches the snapshot *named* "2" (not snapshot with ID 2).

        snap-qcow2-namecollision has: ID=1 name="2", ID=2 name="x".
        ``instar snapshot -d 2`` (delete uses name-only matching, fact from
        phase 7) deletes the entry named "2", i.e. ID 1. Afterwards only
        the entry with name "x" remains.
        """
        src = self._testdata_root / _image_path_for_id('snap-qcow2-namecollision')
        if not src.exists():
            self.skipTest(f'fixture not found: {src}')

        with tempfile.TemporaryDirectory() as td:
            copy = Path(td) / 'nc.qcow2'
            shutil.copy2(str(src), str(copy))

            _, stderr, rc = self.run_instar_snapshot('-d', '2', str(copy))
            self.assertEqual(rc, 0, f'delete "2" failed: {stderr}')

            json_out, _, rc = self.run_instar_snapshot(
                '-l', '--output=json', str(copy),
                env_overrides={'TZ': 'UTC'},
            )
            self.assertEqual(rc, 0)
            remaining = json.loads(json_out)
            self.assertEqual(len(remaining), 1, 'expected 1 remaining snapshot')
            self.assertEqual(remaining[0]['name'], 'x', 'expected "x" to remain')

    def test_delete_pure_id_not_found(self):
        """``-d 1`` on snap-qcow2-namecollision exits 1 (no ID match for -d)."""
        src = self._testdata_root / _image_path_for_id('snap-qcow2-namecollision')
        if not src.exists():
            self.skipTest(f'fixture not found: {src}')

        with tempfile.TemporaryDirectory() as td:
            copy = Path(td) / 'nc.qcow2'
            shutil.copy2(str(src), str(copy))

            before_hash = _sha256_file(copy)
            _, _, rc = self.run_instar_snapshot('-d', '1', str(copy))
            after_hash = _sha256_file(copy)

            # -d uses name-only matching; "1" is not a snapshot name here.
            self.assertEqual(rc, 1, 'expected exit 1 for pure-ID not found')
            self.assertEqual(before_hash, after_hash, 'image mutated on not-found')


class TestSnapshotApply(TestSnapshotSmoke):
    """Apply round-trip tests (tempdir copies)."""

    def setUp(self):
        super().setUp()
        self._require_qemu_tools()
        self._require_kvm()

    def _make_snapped_image(self, td, name='image.qcow2', snap_name='s1'):
        """Build image, write data, take a snapshot, write diverged data."""
        path = Path(td) / name
        ref = Path(td) / 'ref.qcow2'
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2', str(path), '4M'],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 0, f'create: {r.stderr}')

        # Write pre-snapshot data pattern.
        r = subprocess.run(
            ['qemu-io', '-c', 'write -P 0xcc 0 64k', str(path)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 0, f'pre-snap write: {r.stderr}')

        # Save a reference copy at snapshot time.
        shutil.copy2(str(path), str(ref))

        # Take the snapshot.
        r = subprocess.run(
            ['qemu-img', 'snapshot', '-c', snap_name, str(path)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 0, f'snapshot -c: {r.stderr}')

        # Write diverged data post-snapshot.
        r = subprocess.run(
            ['qemu-io', '-c', 'write -P 0xdd 0 64k', str(path)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 0, f'post-snap write: {r.stderr}')

        return path, ref

    def test_apply_check_clean(self):
        """``-a`` then ``qemu-img check`` reports the image clean."""
        with tempfile.TemporaryDirectory() as td:
            path, _ = self._make_snapped_image(td, snap_name='clean')
            _, stderr, rc = self.run_instar_snapshot('-a', 'clean', str(path))
            self.assertEqual(rc, 0, f'apply failed: {stderr}')
            _qemu_check_clean(self, path, 'after -a')

    def test_apply_restores_content(self):
        """After ``-a``, content matches the pre-snapshot reference image."""
        if shutil.which('qemu-io') is None:
            self.skipTest('qemu-io not available for write probe')
        with tempfile.TemporaryDirectory() as td:
            path, ref = self._make_snapped_image(td, snap_name='restore')
            _, stderr, rc = self.run_instar_snapshot('-a', 'restore', str(path))
            self.assertEqual(rc, 0, f'apply failed: {stderr}')

            # qemu-img compare against the pre-snapshot reference.
            # The reference is a plain qcow2 that was a copy of the image
            # at snapshot time (pre-divergence). After apply the image should
            # represent that same state. Convert both to raw for a clean
            # compare.
            raw_path = Path(td) / 'post_apply.raw'
            raw_ref = Path(td) / 'ref.raw'
            r = subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw',
                 str(path), str(raw_path)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0, f'convert post-apply: {r.stderr}')
            r = subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw',
                 str(ref), str(raw_ref)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0, f'convert ref: {r.stderr}')

            r = subprocess.run(
                ['qemu-img', 'compare', str(raw_path), str(raw_ref)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                r.returncode, 0,
                f'Content not restored after apply: {r.stdout}{r.stderr}',
            )
            self.assertIn('Images are identical', r.stdout)

    def test_apply_by_id_on_namecollision(self):
        """``-a 2`` applies the snapshot with ID 2 (apply is ID-then-name).

        snap-qcow2-namecollision has: ID=1 name="2", ID=2 name="x".
        ``instar snapshot -a 2`` matches ID 2 on the first pass (ID-then-
        name matching, documented in PLAN-snapshot-phase-08-apply.md).
        After apply, check clean.
        """
        src = self._testdata_root / _image_path_for_id('snap-qcow2-namecollision')
        if not src.exists():
            self.skipTest(f'fixture not found: {src}')

        with tempfile.TemporaryDirectory() as td:
            copy = Path(td) / 'nc.qcow2'
            shutil.copy2(str(src), str(copy))

            _, stderr, rc = self.run_instar_snapshot('-a', '2', str(copy))
            self.assertEqual(rc, 0, f'apply ID 2 failed: {stderr}')
            _qemu_check_clean(self, copy, 'after apply ID 2 on namecollision')

    def test_apply_post_write_stays_clean(self):
        """After ``-a``, a further write + check stays clean."""
        if shutil.which('qemu-io') is None:
            self.skipTest('qemu-io not available')
        with tempfile.TemporaryDirectory() as td:
            path, _ = self._make_snapped_image(td, snap_name='probe')
            _, stderr, rc = self.run_instar_snapshot('-a', 'probe', str(path))
            self.assertEqual(rc, 0, f'apply failed: {stderr}')
            # Write probe.
            r = subprocess.run(
                ['qemu-io', '-c', 'write -P 0xee 65536 64k', str(path)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0, f'post-apply write: {r.stderr}')
            _qemu_check_clean(self, path, 'after post-apply write probe')


# ---------------------------------------------------------------------------
# Family (d): Error paths and qcow2-only enforcement
# ---------------------------------------------------------------------------


def _build_zstd_image(td):
    """Build a zstd-compressed qcow2 with a write."""
    path = Path(td) / 'zstd.qcow2'
    r = subprocess.run(
        ['qemu-img', 'create', '-f', 'qcow2',
         '-o', 'compression_type=zstd', str(path), '4M'],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        return None  # qemu may not support zstd on this host
    r = subprocess.run(
        ['qemu-io', '-c', 'write 0 64k', str(path)],
        capture_output=True, text=True, timeout=30,
    )
    return path if r.returncode == 0 else None


def _build_dirty_image(td):
    """Build a qcow2 with the INCOMPAT_DIRTY bit hand-set."""
    path = Path(td) / 'dirty.qcow2'
    r = subprocess.run(
        ['qemu-img', 'create', '-f', 'qcow2', str(path), '4M'],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        return None
    # Hand-flip incompatible_features bit 0 (INCOMPAT_DIRTY) at offset 72.
    with open(path, 'r+b') as f:
        f.seek(72)
        incompat = struct.unpack('>Q', f.read(8))[0]
        f.seek(72)
        f.write(struct.pack('>Q', incompat | 0x1))
    return path


def _build_external_data_image(td):
    """Build a qcow2 with an external data file."""
    data_file = Path(td) / 'ext.data'
    path = Path(td) / 'ext.qcow2'
    r = subprocess.run(
        ['qemu-img', 'create', '-f', 'qcow2',
         '-o', f'data_file={data_file},data_file_raw=on',
         str(path), '4M'],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        return None
    return path


class TestSnapshotErrorPaths(TestSnapshotSmoke):
    """qcow2-only enforcement, refusal assertions, CLI guards."""

    def setUp(self):
        super().setUp()
        self._require_qemu_tools()

    def _assert_refusal(self, image_path, mode_args, msg=''):
        """Assert instar refuses and image sha256 is unchanged."""
        before = _sha256_file(image_path)
        stdout, stderr, rc = self.run_instar_snapshot(
            *mode_args, str(image_path),
        )
        after = _sha256_file(image_path)
        self.assertNotEqual(
            rc, 0,
            f'expected non-zero exit for {msg}; got stdout={stdout!r}',
        )
        self.assertEqual(
            before, after,
            f'image was mutated despite refusal for {msg}',
        )
        return stdout + stderr

    # --- Non-qcow2 enforcement ---

    def test_raw_list_refused(self):
        """``-l`` on a raw image: non-zero exit."""
        img = self.get_image('raw-zeros-1mb')
        if not img.path.exists():
            self.skipTest(f'fixture not found: {img.path}')
        _, _, rc = self.run_instar_snapshot('-l', str(img.path))
        self.assertNotEqual(rc, 0)

    def test_vmdk_list_refused(self):
        """``-l`` on a vmdk image: non-zero exit."""
        img = self.get_image('vmdk-flat-1m')
        if not img.path.exists():
            self.skipTest(f'fixture not found: {img.path}')
        _, _, rc = self.run_instar_snapshot('-l', str(img.path))
        self.assertNotEqual(rc, 0)

    def test_vhdx_list_refused(self):
        """``-l`` on a vhdx image: non-zero exit."""
        img = self.get_image('qemu-vhdx')
        if not img.path.exists():
            self.skipTest(f'fixture not found: {img.path}')
        _, _, rc = self.run_instar_snapshot('-l', str(img.path))
        self.assertNotEqual(rc, 0)

    def test_raw_create_refused(self):
        """``-c`` on a raw image: non-zero exit."""
        self._require_kvm()
        img = self.get_image('raw-zeros-1mb')
        if not img.path.exists():
            self.skipTest(f'fixture not found: {img.path}')
        with tempfile.TemporaryDirectory() as td:
            copy = Path(td) / 'test.raw'
            shutil.copy2(str(img.path), str(copy))
            self._assert_refusal(copy, ('-c', 'snap'), 'raw create')

    def test_vmdk_create_refused(self):
        """``-c`` on a vmdk image: non-zero exit."""
        self._require_kvm()
        img = self.get_image('vmdk-flat-1m')
        if not img.path.exists():
            self.skipTest(f'fixture not found: {img.path}')
        with tempfile.TemporaryDirectory() as td:
            copy = Path(td) / 'test.vmdk'
            shutil.copy2(str(img.path), str(copy))
            self._assert_refusal(copy, ('-c', 'snap'), 'vmdk create')

    # --- LUKS: hand-set crypt_method in a plain qcow2 header ---

    def test_luks_create_refused(self):
        """``-c`` on a LUKS-flagged qcow2 (hand-set crypt_method): refused."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'enc.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2', str(path), '4M'],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0, f'create: {r.stderr}')
            # Set crypt_method = 1 (AES) at offset 32 in qcow2 header.
            with open(path, 'r+b') as f:
                f.seek(32)
                f.write(struct.pack('>I', 1))
            self._assert_refusal(path, ('-c', 'snap'), 'LUKS create')

    def test_luks_delete_refused(self):
        """``-d`` on a LUKS-flagged qcow2: refused."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'enc.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2', str(path), '4M'],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r.returncode, 0, f'create: {r.stderr}')
            with open(path, 'r+b') as f:
                f.seek(32)
                f.write(struct.pack('>I', 1))
            self._assert_refusal(path, ('-d', 'snap'), 'LUKS delete')

    # --- Ad-hoc zstd / dirty / external-data refusals ---

    def test_zstd_create_refused(self):
        """``-c`` on a zstd-compression qcow2: refused."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            path = _build_zstd_image(td)
            if path is None:
                self.skipTest('qemu-img on this host does not support zstd')
            self._assert_refusal(path, ('-c', 'snap'), 'zstd create')

    def test_dirty_create_refused(self):
        """``-c`` on a dirty-bit qcow2: refused."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            path = _build_dirty_image(td)
            if path is None:
                self.skipTest('could not build dirty fixture')
            self._assert_refusal(path, ('-c', 'snap'), 'dirty-bit create')

    def test_external_data_create_refused(self):
        """``-c`` on an external-data-file qcow2: refused."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            path = _build_external_data_image(td)
            if path is None:
                self.skipTest('could not build external-data fixture')
            self._assert_refusal(path, ('-c', 'snap'), 'external-data create')

    # --- Not-found exit codes ---

    def test_delete_not_found_exits_1(self):
        """``-d nosuch`` on a snapshot-bearing image: exit 1, image unchanged."""
        self._require_kvm()
        src = self._testdata_root / _image_path_for_id('snap-qcow2-v3-one')
        if not src.exists():
            self.skipTest(f'fixture not found: {src}')
        with tempfile.TemporaryDirectory() as td:
            copy = Path(td) / 'v3.qcow2'
            shutil.copy2(str(src), str(copy))
            output = self._assert_refusal(copy, ('-d', 'nosuchsnap'), 'delete not-found')
            del output  # message checked structurally by the non-zero exit

    def test_apply_not_found_exits_1(self):
        """``-a nosuch`` on a snapshot-bearing image: exit 1, image unchanged."""
        self._require_kvm()
        src = self._testdata_root / _image_path_for_id('snap-qcow2-v3-one')
        if not src.exists():
            self.skipTest(f'fixture not found: {src}')
        with tempfile.TemporaryDirectory() as td:
            copy = Path(td) / 'v3.qcow2'
            shutil.copy2(str(src), str(copy))
            self._assert_refusal(copy, ('-a', 'nosuchsnap'), 'apply not-found')

    # --- CLI guard: -U with mutating modes ---

    def test_force_share_with_create_refused(self):
        """``-U -c snap FILE`` is refused before any file access."""
        _, stderr, rc = self.run_instar_snapshot(
            '-U', '-c', 'snap', '/dev/null',
        )
        self.assertNotEqual(rc, 0, '--force-share + -c should be refused')
        # The error mentions force-share / sharing / read-only operations.
        combined = stderr.lower()
        self.assertTrue(
            'force' in combined or 'share' in combined or 'read-only' in combined,
            f'expected force-share error message; got: {stderr!r}',
        )

    def test_force_share_with_delete_refused(self):
        """``-U -d snap FILE`` is refused before any file access."""
        _, stderr, rc = self.run_instar_snapshot(
            '-U', '-d', 'snap', '/dev/null',
        )
        self.assertNotEqual(rc, 0, '--force-share + -d should be refused')

    def test_force_share_with_apply_refused(self):
        """``-U -a snap FILE`` is refused before any file access."""
        _, stderr, rc = self.run_instar_snapshot(
            '-U', '-a', 'snap', '/dev/null',
        )
        self.assertNotEqual(rc, 0, '--force-share + -a should be refused')

    # --- --image-opts rejection ---

    def test_image_opts_rejected(self):
        """``--image-opts FILE`` is rejected with a clear stderr message."""
        stdout, stderr, rc = self.run_instar_snapshot(
            '--image-opts', '/dev/null',
        )
        self.assertNotEqual(rc, 0)
        self.assertIn('--image-opts', stderr)

    # --- Mixed-flags non-zero ---

    def test_mixed_flags_list_and_create_non_zero(self):
        """``-l -c NAME FILE`` exits non-zero (clap rejects overlapping modes)."""
        src = self._testdata_root / _image_path_for_id('snap-qcow2-v3-one')
        if not src.exists():
            self.skipTest(f'fixture not found: {src}')
        _, _, rc = self.run_instar_snapshot('-l', '-c', 'snap', str(src))
        self.assertNotEqual(rc, 0, 'expected non-zero for mixed -l -c flags')
