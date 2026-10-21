"""Check the committed qemu-img create pins against real qemu-img builds.

`golden/qemu-create-pins.json` records what every static qemu-img build in
instar-testdata writes for the commands in `helpers.qemu_pins.CASES`. These
tests keep the pin honest: it must cover every build that is present, a
spread of those builds and the host qemu-img must still produce what it
says, and every VHDX create case must have one answer across versions
unless a test says otherwise.
"""

import tempfile
from pathlib import Path

from base import InstarTestBase
from helpers import qemu_pins

REPIN_HINT = 're-run tools/sweep-qemu-create.py --write tests/golden/qemu-create-pins.json'

# VHDX create cases that qemu refuses. Their result is an error message,
# whose wording a qemu release may change without it mattering to instar,
# so they are left to the pinned-version tests rather than required to
# have one answer across every version.
VHDX_SINGLE_ANSWER_EXCLUDED = {'vhdx-dynamic-65T', 'vhdx-fixed-backing', 'vhdx-fixed-prealloc-metadata'}


class TestQemuCreatePins(InstarTestBase):
    """The pin file agrees with the qemu-img builds it describes."""

    def _binaries_root(self):
        return self._testdata_root / 'qemu-img-binaries' / 'x86_64'

    def _present_versions(self):
        """Return {version: qemu-img path} for every executable build present."""
        root = self._binaries_root()
        if not root.is_dir():
            self.skipTest(f'no pinned qemu-img binaries under {root}')
        found = qemu_pins.qemu_img_builds(root)
        if not found:
            self.skipTest(f'no executable pinned qemu-img binaries under {root}')
        return found

    def _compare(self, qemu_img, case_name, version, workdir, what=None, remedy=None):
        """Fail unless `qemu_img` still produces what `version`'s group pins for the case."""
        want = qemu_pins.expected(case_name, version)
        got = qemu_pins.run_case(qemu_img, case_name, workdir)
        differences = qemu_pins.result_diff(want, got)
        what = what or f'qemu-img {version}'
        remedy = remedy or f'if qemu is right, {REPIN_HINT}'
        self.assertEqual([], differences,
                         f'{case_name} under {what} differs from the pin (pinned != measured); {remedy}:\n'
                         + '\n'.join(differences))

    def test_every_present_build_is_pinned(self):
        present = self._present_versions()
        pinned = set(qemu_pins.load_pin()['versions'])
        missing = sorted(set(present) - pinned, key=qemu_pins.version_key)
        self.assertEqual([], missing, f'qemu-img builds {missing} are not in the pin; {REPIN_HINT}')

    def _check_version(self, version):
        present = self._present_versions()
        if version not in present:
            self.skipTest(f'qemu-img {version} is not present under {self._binaries_root()}')
        with tempfile.TemporaryDirectory() as workdir:
            for case in qemu_pins.CASES:
                with self.subTest(version=version, case=case['name']):
                    self._compare(present[version], case['name'], version, Path(workdir))

    # The versions run against their pinned groups in CI: the oldest, the
    # first with ddb.toolsVersion in a monolithicFlat descriptor, the newest
    # and one between, so a writer change anywhere in the range shows up.
    # One test per version rather than one loop, so stestr can spread them
    # across workers; each takes over 20 seconds (tests/stestr-timing.txt
    # has the measured times).
    def test_pinned_6_0_0_reproduces(self):
        self._check_version('6.0.0')

    def test_pinned_6_2_0_reproduces(self):
        self._check_version('6.2.0')

    def test_pinned_8_2_0_reproduces(self):
        self._check_version('8.2.0')

    def test_pinned_10_2_0_reproduces(self):
        self._check_version('10.2.0')

    def test_host_qemu_img_matches_nearest_pin(self):
        self._require_qemu_img()
        self.skip_unless_qemu_supports('vpc', 'vmdk', 'vhdx')
        host_version = qemu_pins.qemu_img_version('qemu-img')
        pinned = qemu_pins.newest_pinned_at_or_below(host_version)
        if pinned is None:
            self.skipTest(f'host qemu-img {host_version} is older than every pinned version')
        # The sweep measures only the static builds, so re-pinning cannot
        # clear a host difference: it is either a qemu change the static
        # builds do not cover yet, or a distribution patch.
        newest = max(qemu_pins.load_pin()['versions'], key=qemu_pins.version_key)
        newer = (f'; the host is newer than every pinned build ({newest})'
                 if qemu_pins.version_key(host_version) > qemu_pins.version_key(newest) else '')
        remedy = ('re-pinning will not help, since the sweep does not measure the host. Either a qemu release '
                  f'after {pinned} changed it, so add its build to instar-testdata and re-pin, or '
                  f'the distribution patched qemu{newer}')
        with tempfile.TemporaryDirectory() as workdir:
            for case in qemu_pins.CASES:
                with self.subTest(host=host_version, pinned=pinned, case=case['name']):
                    self._compare('qemu-img', case['name'], pinned, Path(workdir),
                                  what=f'the host qemu-img {host_version} (compared with the {pinned} pin)',
                                  remedy=remedy)

    def test_vhdx_create_cases_have_one_answer(self):
        names = [case['name'] for case in qemu_pins.CASES
                 if case['kind'] == qemu_pins.KIND_VHDX_CREATE and case['name'] not in VHDX_SINGLE_ANSWER_EXCLUDED]
        self.assertTrue(names)
        pin = qemu_pins.load_pin()
        for name in names:
            with self.subTest(case=name):
                try:
                    qemu_pins.expected(name, pin=pin)
                except qemu_pins.PinError as e:
                    self.fail(f'{e}; a boundary in the VHDX writer needs handling before this can pass')
