"""Differential tests for qcow2 subcluster classification.

Every fixture in `helpers.qcow2_subclusters.BUILDERS` is run through instar
and qemu-img side by side, one test method per (operation, fixture), so a
stestr id names both. The fixtures know, by construction, which device each
subcluster's bytes must come from, so convert is checked against that
expectation as well as against qemu-img:

* convert -O raw: byte-equal to the fixture's `expected_raw` and to
  `qemu-img convert`; an invalid entry is refused by name, as qemu refuses it.
* compare: instar compare of the fixture against qemu-img's raw output says
  identical; an invalid entry is refused by name.
* map --output json: equal to `qemu-img map`. instar map reads one image on
  its own, so a fixture with a backing file is checked for that refusal.
* check: exit code and corruption count agree with `qemu-img check`. The
  allocation counts and qemu's leak count are not compared: qemu's check
  stops before counting a compressed cluster whose bitmap it reports, and so
  also reports the cluster as leaked, which is an artefact of its error path.
* measure -O qcow2: equal to `qemu-img measure`. instar measures the top
  layer only (#642), so a fixture with a backing file is compared against
  qemu measuring the image opened with its backing link cut.

Known divergences are listed in `EXPECTED_FAILURES` and marked with
`unittest.expectedFailure`, which testtools honours: when one starts passing
it is reported as an unexpected success, which fails the run, so whoever fixes
it has to remove the entry.

The fixtures in `HOST_OFFSET_REFUSAL_BUILDERS` are deliberately not run here.
They classify as valid, and qemu refuses them through its host-offset rules
(a compressed entry with a data file, a data-file host offset different from
the guest offset), which instar does not implement yet (#803); that is not
classification.
"""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from base import InstarTestBase
from helpers import qcow2_subclusters

# The phrase instar's refusal of an invalid qcow2 entry carries, in qemu's
# words, whichever operation reaches it.
INVALID_ENTRY_MESSAGE = 'Invalid cluster entry found'

OPERATIONS = ('convert', 'compare', 'map', 'check', 'measure')

_ISSUE_792 = ('#792: an unallocated cluster in a data-file image falls through to the next device in the chain, '
              'which is the data file, instead of reading zeros or the backing file')
_COMPRESSED_MAP = ('instar map reports compressed clusters with compressed: false and a host offset; see '
                   'docs/quirks.md "qcow2 compressed clusters report compressed: false" and the compressed '
                   'entries of KNOWN_MAP_DIVERGENCES in tests/test_map.py')

# (operation, fixture) -> why instar does not yet agree with qemu-img.
EXPECTED_FAILURES = {}
for _fixture in ('mixed_classic_backing_datafile', 'mixed_ext_backing_datafile', 'data_file_partial_backing',
                 'data_file_partial_32k', 'data_file_classic_no_copied_backing', 'data_file_classic_no_copied'):
    for _operation in ('convert', 'compare'):
        EXPECTED_FAILURES[(_operation, _fixture)] = _ISSUE_792
for _fixture in ('mixed_classic_nobacking_nodatafile', 'mixed_ext_nobacking_nodatafile',
                 'compressed_bitmap_all_alloc', 'compressed_bitmap_arbitrary'):
    EXPECTED_FAILURES[('map', _fixture)] = _COMPRESSED_MAP


def _run(argv, timeout=120):
    """Run a command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return '', f'Timeout after {timeout}s', -1
    return result.stdout, result.stderr, result.returncode


class TestQcow2Subclusters(InstarTestBase):
    """instar against qemu-img on every subcluster-classification fixture."""

    _tmpdir = None
    _fixtures = None
    _qemu_raw = None

    @classmethod
    def setUpClass(cls):
        """Build every fixture once, and qemu-img's raw conversion of each."""
        super().setUpClass()
        if shutil.which('qemu-img') is None or shutil.which('qemu-io') is None:
            # setUp skips each test with the reason; the builders need both.
            return
        cls._tmpdir = Path(tempfile.mkdtemp(prefix='qcow2-subclusters.'))
        cls._fixtures = qcow2_subclusters.build_all(cls._tmpdir / 'fixtures')
        cls._qemu_raw = {}
        for name, fixture in cls._fixtures.items():
            out = cls._tmpdir / f'{name}.qemu.raw'
            stdout, stderr, rc = _run(['qemu-img', 'convert', '-O', 'raw', fixture.path, out])
            cls._qemu_raw[name] = (out if rc == 0 else None, rc, stderr)

    @classmethod
    def tearDownClass(cls):
        if cls._tmpdir is not None:
            shutil.rmtree(cls._tmpdir, ignore_errors=True)
            cls._tmpdir = None
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        # The fixtures are written by qemu-io as well as qemu-img.
        self._require_qemu_tools()
        self.instar = self.get_instar_binary()

    def _instar(self, *args):
        return _run([self.instar, *args])

    def _assert_refused(self, stdout, stderr, rc, what):
        self.assertNotEqual(rc, 0, f'{what}: instar did not refuse an invalid entry; stdout={stdout[:500]!r}')
        self.assertIn(INVALID_ENTRY_MESSAGE, stderr, f'{what}: refusal does not name the invalid entry')

    def _assert_backing_refused(self, stdout, stderr, rc, what):
        self.assertNotEqual(rc, 0, f'{what}: instar map did not refuse a backing chain; stdout={stdout[:500]!r}')
        combined = (stdout + stderr).lower()
        self.assertTrue('backing' in combined or 'chain' in combined,
                        f'{what}: refusal does not mention the backing chain; stderr={stderr!r}')

    # ---------------------------------------------------------------- convert

    def check_convert(self, name):
        fixture = self._fixtures[name]
        qemu_out, qemu_rc, qemu_stderr = self._qemu_raw[name]
        out = self._tmpdir / f'{name}.convert.instar.raw'
        stdout, stderr, rc = self._instar('convert', '-O', 'raw', fixture.path, out)
        if fixture.refuses:
            self.assertNotEqual(qemu_rc, 0, f'{name}: qemu-img convert unexpectedly read an invalid entry')
            self._assert_refused(stdout, stderr, rc, f'{name} convert')
            return
        self.assertEqual(qemu_rc, 0, f'{name}: qemu-img convert failed: {qemu_stderr}')
        self.assertEqual(rc, 0, f'{name}: instar convert failed: {stderr}')
        actual = out.read_bytes()
        self.assert_bytes_identical(actual, fixture.expected_raw, f'{name}: instar convert vs expected ownership')
        self.assert_bytes_identical(actual, qemu_out.read_bytes(), f'{name}: instar convert vs qemu-img convert')

    # ---------------------------------------------------------------- compare

    def check_compare(self, name):
        fixture = self._fixtures[name]
        qemu_out = self._qemu_raw[name][0]
        if fixture.refuses:
            # qemu cannot produce a raw image of an invalid fixture; compare
            # against an all-zero one, since the refusal must come first.
            qemu_out = self._tmpdir / f'{name}.blank.raw'
            with open(qemu_out, 'wb') as f:
                f.truncate(fixture.virtual_size)
            stdout, stderr, rc = self.run_instar_compare(fixture.path, qemu_out)
            self._assert_refused(stdout, stderr, rc, f'{name} compare')
            return
        stdout, stderr, rc = self.run_instar_compare(fixture.path, qemu_out)
        self.assertEqual(rc, 0, f'{name}: instar compare says the fixture differs from qemu-img convert: '
                                f'stdout={stdout!r} stderr={stderr!r}')

    # -------------------------------------------------------------------- map

    def check_map(self, name):
        fixture = self._fixtures[name]
        stdout, stderr, rc = self._instar('map', '--output', 'json', fixture.path)
        if fixture.backing is not None:
            self._assert_backing_refused(stdout, stderr, rc, f'{name} map')
            return
        q_stdout, q_stderr, q_rc = _run(['qemu-img', 'map', '--output=json', fixture.path])
        if fixture.refuses:
            self.assertNotEqual(q_rc, 0, f'{name}: qemu-img map unexpectedly read an invalid entry')
            self._assert_refused(stdout, stderr, rc, f'{name} map')
            return
        self.assertEqual(q_rc, 0, f'{name}: qemu-img map failed: {q_stderr}')
        self.assertEqual(rc, 0, f'{name}: instar map failed: {stderr}')
        self.assertEqual(json.loads(stdout), json.loads(q_stdout), f'{name}: instar map vs qemu-img map')

    # ------------------------------------------------------------------ check

    def check_check(self, name):
        fixture = self._fixtures[name]
        stdout, stderr, rc = self.run_instar_check(fixture.path, output_format='json')
        q_stdout, q_stderr, q_rc = self.run_qemu_img_check(fixture.path, output_format='json')
        self.assertEqual(rc, q_rc, f'{name}: check exit code: instar={rc} qemu-img={q_rc}; '
                                   f'instar stderr={stderr!r} qemu-img stderr={q_stderr!r}')
        instar_json = json.loads(stdout)
        qemu_json = json.loads(q_stdout)
        # qemu-img omits the key when there are none.
        self.assertEqual(instar_json.get('corruptions', 0), qemu_json.get('corruptions', 0),
                         f'{name}: check corruption count: instar={instar_json} qemu-img={qemu_json}; '
                         f'qemu-img stderr={q_stderr!r}')

    # ---------------------------------------------------------------- measure

    def check_measure(self, name):
        fixture = self._fixtures[name]
        stdout, stderr, rc = self._instar('measure', '-O', 'qcow2', '--output', 'json', fixture.path)
        source = str(fixture.path)
        if fixture.backing is not None:
            # Cut the backing link so qemu measures the top layer alone, as
            # instar does. The data file is still found through the header.
            source = 'json:' + json.dumps({'driver': 'qcow2', 'backing': None,
                                           'file': {'driver': 'file', 'filename': source}})
        q_stdout, q_stderr, q_rc = _run(['qemu-img', 'measure', '-O', 'qcow2', '--output=json', source])
        if fixture.refuses:
            self.assertNotEqual(q_rc, 0, f'{name}: qemu-img measure unexpectedly read an invalid entry')
            self._assert_refused(stdout, stderr, rc, f'{name} measure')
            return
        self.assertEqual(q_rc, 0, f'{name}: qemu-img measure failed: {q_stderr}')
        self.assertEqual(rc, 0, f'{name}: instar measure failed: {stderr}')
        instar_json = json.loads(stdout)
        qemu_json = json.loads(q_stdout)
        for key in ('required', 'fully-allocated'):
            self.assertEqual(instar_json.get(key), qemu_json.get(key),
                             f'{name}: measure {key}: instar={instar_json} qemu-img={qemu_json}')


def _make_test(operation, name):
    def test(self):
        getattr(self, f'check_{operation}')(name)
    fixture_doc = f'{operation}: instar agrees with qemu-img on the {name} fixture.'
    reason = EXPECTED_FAILURES.get((operation, name))
    if reason is not None:
        test.__doc__ = f'{fixture_doc} Expected to fail: {reason}.'
        return unittest.expectedFailure(test)
    test.__doc__ = fixture_doc
    return test


for _name in qcow2_subclusters.BUILDERS:
    for _operation in OPERATIONS:
        setattr(TestQcow2Subclusters, f'test_{_operation}_{_name}', _make_test(_operation, _name))

_unknown = {key for key in EXPECTED_FAILURES if key[1] not in qcow2_subclusters.BUILDERS}
if _unknown:
    raise RuntimeError(f'EXPECTED_FAILURES names fixtures that do not exist: {sorted(_unknown)}')
