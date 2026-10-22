"""Differential tests for qcow2 subcluster classification.

Every fixture in `helpers.qcow2_subclusters.BUILDERS` is run through instar
and qemu-img side by side, one test method per (operation, fixture), so a
stestr id names both. The fixtures know, by construction, which device each
subcluster's bytes must come from, so convert is checked against that
expectation as well as against qemu-img:

* convert -O raw: byte-equal to the fixture's `expected_raw` and to
  `qemu-img convert`; an entry qemu refuses is refused by name, as qemu
  refuses it: an invalid entry, or a data-file entry that is compressed or
  not at its guest offset (#803).
* compare: instar compare of the fixture against qemu-img's raw output says
  identical; an entry qemu refuses is refused by name.
* map --output json: equal to `qemu-img map`. instar map reads one image on
  its own, so a fixture with a backing file is checked for that refusal.
* check: exit code and corruption count agree with `qemu-img check`. The
  allocation counts and qemu's leak count are not compared: qemu's check
  stops before counting a compressed cluster whose bitmap it reports, and so
  also reports the cluster as leaked, which is an artefact of its error path.
* measure -O qcow2: equal to `qemu-img measure`. instar measures the top
  layer only (#642), so a fixture with a backing file is compared against
  qemu measuring the image opened with its backing link cut.

Three narrower sets of tests sit beside those:

* every pair in `helpers.qcow2_subclusters.COMPARE_PAIRS` is compared in
  both argument orders, and instar must agree with `qemu-img compare`;
* the data-file images in `CHECK_CHAIN_FIXTURES`, all over qcow2 backing
  files, pass `check --chain` with no chain error, as `qemu-img check` does:
  a data file is not a chain layer (a raw backing file always reports a
  chain error, #808);
* the fixtures in `REVERSED_COMPARE_FIXTURES` are also compared with
  qemu-img's raw output as the first input, so the fixture's devices follow
  the other input's.

Known divergences are listed in `EXPECTED_FAILURES` and marked with
`unittest.expectedFailure`, which testtools honours: when one starts passing
it is reported as an unexpected success, which fails the run, so whoever fixes
it has to remove the entry. A fixture qemu reads and instar refuses is listed
in `FAILS_CLOSED` instead, and pinned to that refusal: an expected failure
absorbs every failure, including a regression to wrong bytes under exit 0.

`TestQcow2RefusalReaders` drives an invalid entry and a data-file entry through
the readers the table above does not reach, dd, bench and rebase, and checks
each renders the refusal by name, at the offset of the refused cluster.
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

# The fixtures qemu refuses through a data-file rule rather than as an invalid
# entry, and the phrase instar's refusal carries for each, in qemu's words
# (block/qcow2-cluster.c:670-673 and :698-702 at v10.0.0, #803).
DATA_FILE_REFUSAL_MESSAGES = {
    'data_file_compressed': 'Compressed cluster entry found in image with external data file',
    'data_file_offset_mismatch': 'External data file host cluster offset does not match guest cluster offset',
}

QCOW2_MAGIC = b'QFI\xfb'

OPERATIONS = ('convert', 'compare', 'map', 'check', 'measure')

_COMPRESSED_MAP = ('instar map reports compressed clusters with compressed: false and a host offset; see '
                   'docs/quirks.md "qcow2 compressed clusters report compressed: false" and the compressed '
                   'entries of KNOWN_MAP_DIVERGENCES in tests/test_map.py')

# (operation, fixture) -> why instar does not yet agree with qemu-img.
EXPECTED_FAILURES = {}
for _fixture in ('mixed_classic_nobacking_nodatafile', 'mixed_ext_nobacking_nodatafile',
                 'compressed_bitmap_all_alloc', 'compressed_bitmap_arbitrary'):
    EXPECTED_FAILURES[('map', _fixture)] = _COMPRESSED_MAP

# (operation, fixture) -> why instar refuses a fixture qemu-img reads. Each is
# checked by `check_<operation>_fails_closed`: qemu reads the fixture, instar
# exits non-zero, and no output is claimed correct. When instar starts reading
# one, that check fails, and the entry has to move back to the ordinary check.
FAILS_CLOSED = {}
_MID_CHAIN = 'the VMM discovers no external data file below the top image, so the read fails closed (#806)'
for _operation in ('convert', 'compare'):
    FAILS_CLOSED[(_operation, 'data_file_mid_chain')] = _MID_CHAIN

# Data-file images over qcow2 backing files that check --chain must pass
# without a chain error.
CHECK_CHAIN_FIXTURES = ('mixed_ext_backing_datafile_over_64k_qcow2', 'data_file_holds_qcow2_header',
                        'data_file_empty')

# Fixtures that are also compared with qemu-img's raw output given first. A
# monolithicFlat VMDK smaller than its overlay is followed in the device array
# by the other input when it is given second, and a read past its extent must
# not reach that input.
REVERSED_COMPARE_FIXTURES = ('qcow2_over_smaller_flat_vmdk',)


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
    _pairs = None

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
        cls._pairs = qcow2_subclusters.build_compare_pairs(cls._tmpdir / 'pairs')

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

    def _assert_refused(self, name, stdout, stderr, rc, what):
        message = DATA_FILE_REFUSAL_MESSAGES.get(name, INVALID_ENTRY_MESSAGE)
        self.assertNotEqual(rc, 0, f'{what}: instar did not refuse the entry; stdout={stdout[:500]!r}')
        self.assertIn(message, stderr, f'{what}: refusal does not name the entry qemu refuses; stderr={stderr!r}')

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
            self.assertNotEqual(qemu_rc, 0, f'{name}: qemu-img convert unexpectedly read a refused entry')
            self._assert_refused(name, stdout, stderr, rc, f'{name} convert')
            return
        self.assertEqual(qemu_rc, 0, f'{name}: qemu-img convert failed: {qemu_stderr}')
        self.assertEqual(rc, 0, f'{name}: instar convert failed: {stderr}')
        actual = out.read_bytes()
        self.assert_bytes_identical(actual, fixture.expected_raw, f'{name}: instar convert vs expected ownership')
        self.assert_bytes_identical(actual, qemu_out.read_bytes(), f'{name}: instar convert vs qemu-img convert')

    def check_convert_fails_closed(self, name):
        qemu_rc, qemu_stderr = self._qemu_raw[name][1:]
        self.assertEqual(qemu_rc, 0, f'{name}: qemu-img convert failed: {qemu_stderr}')
        out = self._tmpdir / f'{name}.convert.instar.raw'
        stdout, stderr, rc = self._instar('convert', '-O', 'raw', self._fixtures[name].path, out)
        # Exit 0 is a failure whatever the bytes: if they are right, the entry
        # belongs in the ordinary check, and if they are wrong, this is the
        # regression the pin exists for.
        self.assertNotEqual(rc, 0, f'{name}: instar convert exited 0 where it is known to fail closed '
                                   f'({FAILS_CLOSED[("convert", name)]}); stdout={stdout!r} stderr={stderr!r}')
        self.assertNotIn('Invalid cluster entry found', stderr, f'{name}: qemu reads this chain, so no entry in it '
                                                                f'is invalid; stderr={stderr!r}')

    # ---------------------------------------------------------------- compare

    def check_compare_fails_closed(self, name):
        qemu_out, qemu_rc, qemu_stderr = self._qemu_raw[name]
        self.assertEqual(qemu_rc, 0, f'{name}: qemu-img convert failed: {qemu_stderr}')
        stdout, stderr, rc = self.run_instar_compare(self._fixtures[name].path, qemu_out)
        # The fixture and qemu's conversion of it are identical, so any exit 0
        # says so; while the read fails closed, instar must not say it.
        self.assertNotEqual(rc, 0, f'{name}: instar compare exited 0 where it is known to fail closed '
                                   f'({FAILS_CLOSED[("compare", name)]}); stdout={stdout!r} stderr={stderr!r}')
        self.assertNotIn('identical', stdout.lower(), f'{name}: instar compare claims the images are identical '
                                                      f'under a non-zero exit; stdout={stdout!r}')

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
            self._assert_refused(name, stdout, stderr, rc, f'{name} compare')
            return
        if fixture.expected_raw[:4] == QCOW2_MAGIC:
            # A raw file whose guest bytes start with a qcow2 header is probed
            # as qcow2, by qemu-img compare without -F raw as much as by instar
            # compare, which has no format option. Compare against qemu's
            # qcow2 conversion instead, which nothing can mistake.
            qemu_out = self._tmpdir / f'{name}.qemu.qcow2'
            q_stdout, q_stderr, q_rc = _run(['qemu-img', 'convert', '-O', 'qcow2', fixture.path, qemu_out])
            self.assertEqual(q_rc, 0, f'{name}: qemu-img convert -O qcow2 failed: {q_stderr}')
        stdout, stderr, rc = self.run_instar_compare(fixture.path, qemu_out)
        self.assertEqual(rc, 0, f'{name}: instar compare says the fixture differs from qemu-img convert: '
                                f'stdout={stdout!r} stderr={stderr!r}')

    def check_compare_reversed(self, name):
        qemu_out, qemu_rc, qemu_stderr = self._qemu_raw[name]
        self.assertEqual(qemu_rc, 0, f'{name}: qemu-img convert failed: {qemu_stderr}')
        stdout, stderr, rc = self.run_instar_compare(qemu_out, self._fixtures[name].path)
        self.assertEqual(rc, 0, f'{name}: instar compare of qemu-img convert against the fixture says they differ: '
                                f'stdout={stdout!r} stderr={stderr!r}')

    def check_compare_pair(self, name):
        pair = self._pairs[name]
        expected_rc = 0 if pair.identical else 1
        for first, second in ((pair.left, pair.right), (pair.right, pair.left)):
            what = f'{name}: compare {first.name} {second.name}'
            q_stdout, q_stderr, q_rc = _run(['qemu-img', 'compare', first.path, second.path])
            self.assertEqual(q_rc, expected_rc, f'{what}: qemu-img exit code {q_rc}; stdout={q_stdout!r} '
                                                f'stderr={q_stderr!r}')
            stdout, stderr, rc = self.run_instar_compare(first.path, second.path)
            self.assertEqual(rc, q_rc, f'{what}: instar exit code {rc}, qemu-img {q_rc}; stdout={stdout!r} '
                                       f'stderr={stderr!r}')

    # -------------------------------------------------------------------- map

    def check_map(self, name):
        fixture = self._fixtures[name]
        stdout, stderr, rc = self._instar('map', '--output', 'json', fixture.path)
        if fixture.backing is not None:
            self._assert_backing_refused(stdout, stderr, rc, f'{name} map')
            return
        q_stdout, q_stderr, q_rc = _run(['qemu-img', 'map', '--output=json', fixture.path])
        if fixture.refuses:
            self.assertNotEqual(q_rc, 0, f'{name}: qemu-img map unexpectedly read a refused entry')
            self._assert_refused(name, stdout, stderr, rc, f'{name} map')
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

    def check_check_chain(self, name):
        fixture = self._fixtures[name]
        stdout, stderr, rc = self.run_instar_check(fixture.path, output_format='json', chain=True)
        q_stdout, q_stderr, q_rc = self.run_qemu_img_check(fixture.path, output_format='json')
        self.assertEqual(rc, q_rc, f'{name}: check --chain exit code: instar={rc} qemu-img={q_rc}; '
                                   f'instar stdout={stdout!r} stderr={stderr!r}')
        instar_json = json.loads(stdout)
        self.assertEqual(instar_json.get('chain-errors'), 0,
                         f'{name}: check --chain reports a chain error: {instar_json}; stderr={stderr!r}')
        self.assertEqual(instar_json.get('corruptions', 0), json.loads(q_stdout).get('corruptions', 0),
                         f'{name}: check --chain corruption count: instar={instar_json} qemu-img={q_stdout}')

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
            self.assertNotEqual(q_rc, 0, f'{name}: qemu-img measure unexpectedly read a refused entry')
            self._assert_refused(name, stdout, stderr, rc, f'{name} measure')
            return
        self.assertEqual(q_rc, 0, f'{name}: qemu-img measure failed: {q_stderr}')
        self.assertEqual(rc, 0, f'{name}: instar measure failed: {stderr}')
        instar_json = json.loads(stdout)
        qemu_json = json.loads(q_stdout)
        for key in ('required', 'fully-allocated'):
            self.assertEqual(instar_json.get(key), qemu_json.get(key),
                             f'{name}: measure {key}: instar={instar_json} qemu-img={qemu_json}')


_OPERATION_LABELS = {
    'compare_reversed': 'compare with qemu-img\'s raw output first',
    'compare_pair': 'compare in both argument orders',
    'check_chain': 'check --chain',
}


def _make_test(operation, name):
    label = _OPERATION_LABELS.get(operation, operation)
    fails_closed = FAILS_CLOSED.get((operation, name))
    if fails_closed is not None:
        def test(self):
            getattr(self, f'check_{operation}_fails_closed')(name)
        test.__doc__ = (f'{label}: qemu-img reads the {name} fixture and instar refuses it, with no output claimed '
                        f'correct: {fails_closed}.')
        return test

    def test(self):
        getattr(self, f'check_{operation}')(name)
    fixture_doc = f'{label}: instar agrees with qemu-img on the {name} fixture.'
    reason = EXPECTED_FAILURES.get((operation, name))
    if reason is not None:
        test.__doc__ = f'{fixture_doc} Expected to fail: {reason}.'
        return unittest.expectedFailure(test)
    test.__doc__ = fixture_doc
    return test


for _name in qcow2_subclusters.BUILDERS:
    for _operation in OPERATIONS:
        setattr(TestQcow2Subclusters, f'test_{_operation}_{_name}', _make_test(_operation, _name))
for _operation, _names in (('compare_reversed', REVERSED_COMPARE_FIXTURES), ('check_chain', CHECK_CHAIN_FIXTURES),
                           ('compare_pair', qcow2_subclusters.COMPARE_PAIRS)):
    for _name in _names:
        setattr(TestQcow2Subclusters, f'test_{_operation}_{_name}', _make_test(_operation, _name))

for _label, _table in (('EXPECTED_FAILURES', EXPECTED_FAILURES), ('FAILS_CLOSED', FAILS_CLOSED)):
    _unknown = {key for key in _table if key[1] not in qcow2_subclusters.BUILDERS}
    if _unknown:
        raise RuntimeError(f'{_label} names fixtures that do not exist: {sorted(_unknown)}')
_both = set(EXPECTED_FAILURES) & set(FAILS_CLOSED)
if _both:
    raise RuntimeError(f'EXPECTED_FAILURES and FAILS_CLOSED both name: {sorted(_both)}')
for _label, _names in (('DATA_FILE_REFUSAL_MESSAGES', DATA_FILE_REFUSAL_MESSAGES),
                       ('REVERSED_COMPARE_FIXTURES', REVERSED_COMPARE_FIXTURES),
                       ('CHECK_CHAIN_FIXTURES', CHECK_CHAIN_FIXTURES)):
    _unknown = set(_names) - set(qcow2_subclusters.BUILDERS)
    if _unknown:
        raise RuntimeError(f'{_label} names fixtures that do not exist: {sorted(_unknown)}')


class TestQcow2RefusalReaders(InstarTestBase):
    """dd, bench and rebase refuse an invalid entry and a data-file entry by name.

    convert, compare, map and measure are covered above. The other three
    readers render the same refusal from the same captured signal, so each is
    driven through both kinds of entry, at cluster 1 of a 64K-cluster image.
    dd and bench start their reads 4K into that cluster, and the refusal must
    still name the cluster's offset, 65536, as map and measure name it for the
    same entry, not the offset the read began at.
    """

    _tmpdir = None
    _invalid = None
    _data_file = None
    _old_base = None
    _new_base = None

    # The refused cluster, and the offset 4K into it where dd and bench start.
    _CLUSTER = 65536
    _START = _CLUSTER + 4096
    _OFFSET_TEXT = 'at virtual offset 65536 (0x10000)'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if shutil.which('qemu-img') is None or shutil.which('qemu-io') is None:
            return
        cls._tmpdir = Path(tempfile.mkdtemp(prefix='qcow2-refusal-readers.'))
        fixtures = cls._tmpdir / 'fixtures'
        # COPIED at host offset 0 with every alloc bit set and no data file:
        # alloc bits with no host cluster behind them, which qemu calls an
        # invalid entry. Cluster 0 is written so the L2 table exists.
        cls._invalid = qcow2_subclusters.build_fixture(
            fixtures, 'refused_invalid_cluster_1',
            'Extended L2, no data file; cluster 0 written, cluster 1 patched to COPIED|0 with every alloc bit set.',
            ops=[('write', 0x77, 0, cls._CLUSTER)],
            patches=[(1, qcow2_subclusters.QCOW_OFLAG_COPIED, qcow2_subclusters.L2_BITMAP_ALL_ALLOC)],
            expect_types=frozenset({qcow2_subclusters.INVALID}))
        cls._data_file = qcow2_subclusters.BUILDERS['data_file_offset_mismatch'](fixtures)
        # Empty qcow2 backing files to rebase from and onto. rebase writes the
        # new backing path into the overlay's existing slot, so the old one is
        # named to be longer than any new one.
        cls._old_base = cls._tmpdir / f'old-base-{"x" * 64}.qcow2'
        cls._new_base = cls._tmpdir / 'new-base.qcow2'
        for base in (cls._old_base, cls._new_base):
            _, stderr, rc = _run(['qemu-img', 'create', '-q', '-f', 'qcow2', base, str(cls._invalid.virtual_size)])
            if rc != 0:
                raise RuntimeError(f'qemu-img create of {base} failed: {stderr}')

    @classmethod
    def tearDownClass(cls):
        if cls._tmpdir is not None:
            shutil.rmtree(cls._tmpdir, ignore_errors=True)
            cls._tmpdir = None
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self._require_qemu_tools()
        self.instar = self.get_instar_binary()

    def _assert_refusal(self, op, message, stdout, stderr, rc):
        self.assertNotEqual(rc, 0, f'{op}: the refused entry was read; stdout={stdout[:500]!r} stderr={stderr!r}')
        self.assertIn(f'{op}: {message} {self._OFFSET_TEXT}', stderr,
                      f'{op}: the refusal is not rendered by name at the refused cluster; stderr={stderr!r}')

    def _overlay(self, name, backing):
        """Return an empty qcow2 overlay on `backing`, so every read of it reaches the backing file."""
        overlay = self._tmpdir / f'{name}.overlay.qcow2'
        _, stderr, rc = _run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', backing, overlay])
        self.assertEqual(rc, 0, f'qemu-img create of the overlay failed: {stderr}')
        return overlay

    def _dd(self, fixture, message):
        out = self._tmpdir / f'{fixture.name}.dd.raw'
        # count is applied before skip, so the window is blocks skip to count:
        # from 4K into the refused cluster to its end.
        stdout, stderr, rc = self.run_instar_dd(
            [f'if={fixture.path}', f'of={out}', 'bs=4096', f'skip={self._START // 4096}',
             f'count={2 * self._CLUSTER // 4096}'],
            output_format='raw')
        self._assert_refusal('dd', message, stdout, stderr, rc)

    def _bench(self, fixture, message):
        stdout, stderr, rc = self._instar('bench', '-c', '4', '-s', '4096', '-o', str(self._START), fixture.path)
        self._assert_refusal('bench', message, stdout, stderr, rc)

    def _instar(self, *args):
        return _run([self.instar, *args])

    def test_dd_refuses_an_invalid_entry(self):
        """dd renders an invalid entry's refusal, naming the refused cluster."""
        self._dd(self._invalid, INVALID_ENTRY_MESSAGE)

    def test_dd_refuses_a_data_file_entry(self):
        """dd renders a data-file entry's refusal, naming the refused cluster."""
        self._dd(self._data_file, DATA_FILE_REFUSAL_MESSAGES['data_file_offset_mismatch'])

    def test_bench_refuses_an_invalid_entry(self):
        """bench renders an invalid entry's refusal, naming the refused cluster."""
        self._bench(self._invalid, INVALID_ENTRY_MESSAGE)

    def test_bench_refuses_a_data_file_entry(self):
        """bench renders a data-file entry's refusal, naming the refused cluster."""
        self._bench(self._data_file, DATA_FILE_REFUSAL_MESSAGES['data_file_offset_mismatch'])

    def test_rebase_refuses_an_invalid_entry_in_the_old_chain(self):
        """rebase renders the refusal of an invalid entry in the backing file it rebases away from."""
        overlay = self._overlay('invalid', self._invalid.path)
        stdout, stderr, rc = self.run_instar_rebase(overlay, '-F', 'qcow2', '-b', self._new_base)
        self._assert_refusal('rebase', INVALID_ENTRY_MESSAGE, stdout, stderr, rc)

    def test_rebase_refuses_a_data_file_entry_in_the_new_chain(self):
        """rebase renders the refusal of a data-file entry in the backing file it rebases onto.

        The data file of the old chain's backing file is not discovered (#806),
        but the new backing file is the top of its own chain, whose data file
        is, so the entry is reached there.
        """
        overlay = self._overlay('data_file', self._old_base)
        stdout, stderr, rc = self.run_instar_rebase(overlay, '-F', 'qcow2', '-b', self._data_file.path)
        self._assert_refusal('rebase', DATA_FILE_REFUSAL_MESSAGES['data_file_offset_mismatch'], stdout, stderr, rc)
