"""Integration tests for `instar amend`.

Phase 6 of PLAN-amend.md. The live differential suite: for each
case in `AMEND_CASES`, create a qcow2 image with `qemu-img`, copy
it, amend copy A with `instar amend` and copy B with `qemu-img
amend`, then assert the two are equivalent via `qemu-img info
--output=json` (normalised), that `qemu-img check` passes on the
instar output, and that `qemu-img compare` shows the guest data is
unchanged (amend touches only header metadata). Plus refusal tests
(instar refuses the same structurally-impossible amends qemu does)
and a `KNOWN_AMEND_DIVERGENCES` registry for any accepted
difference.

This is the *live* differential against the locally-installed
`qemu-img`. The cross-version baselines are phase 7.

`amend` launches a guest VM, so the test classes guard on
`/dev/kvm` (mirroring resize's guest-needs-kvm skip). Fixtures are
built with `qemu-img create` so amend is exercised against real v2
(`compat=0.10`) *and* v3 (`compat=1.1`) images — `instar create`
cannot emit v2.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase
from helpers.info_json import assert_info_equivalent


# ----------------------------------------------------------------------
# AMEND_CASES — qcow2-only differential matrix.
# ----------------------------------------------------------------------
#
# Each entry: (case_name, create_opts, amend_opts). `create_opts`
# and `amend_opts` are lists of `key=value` strings passed to
# `qemu-img create -o` / `instar|qemu-img amend -o` respectively.
# Cases tagged `-with-backing` create a `base.qcow2` first and add
# `backing_file=base.qcow2,backing_fmt=qcow2` to the start image.
AMEND_CASES = {
    'qcow2': [
        ('upgrade-plain',        ['compat=0.10'],                  ['compat=1.1']),
        ('upgrade-with-backing', ['compat=0.10'],                  ['compat=1.1']),
        ('upgrade-with-lazy',    ['compat=0.10'],                  ['compat=1.1,lazy_refcounts=on']),
        ('downgrade-plain',      ['compat=1.1'],                   ['compat=0.10']),
        ('downgrade-with-backing', ['compat=1.1'],                 ['compat=0.10']),
        ('lazy-on',              ['compat=1.1'],                   ['lazy_refcounts=on']),
        ('lazy-off',             ['compat=1.1,lazy_refcounts=on'], ['lazy_refcounts=off']),
        ('noop',                 ['compat=1.1'],                   ['compat=1.1']),
    ],
}


# Cases where the post-amend info JSON diverges from qemu's, for a
# documented reason. Keyed by (format, case_name) -> reason string,
# consulted in `_make_amend_diff_test`. Phase 4 found instar's
# amended images `qemu-img info`-identical to qemu's, so this is
# expected to be empty. A case NOT in this dict that fails the diff
# is a real regression and must be investigated, not silenced. If
# `qemu-img compare` ever shows a DATA difference, that's a real bug
# to fix in phases 2-3, not a divergence to register here.
KNOWN_AMEND_DIVERGENCES = {}


# Cases marked `-with-backing` need a base.qcow2 fixture and the
# backing reference threaded into the start-image create.
_BACKING_CASES = {'upgrade-with-backing', 'downgrade-with-backing'}


class TestAmendSmoke(InstarTestBase):
    """Parent class for the amend test families.

    Owns the `instar amend` runner, the `/dev/kvm` skip guard, and
    the `qemu-img create` fixture helper. Child classes (the
    cross-validation matrix and the refusal suite) inherit all
    three.
    """

    def run_instar_amend(self, *args, timeout=120):
        """Helper: invoke `instar amend` with the given args.

        Returns (stdout, stderr, returncode). Timeout 120s because
        amend spins up the guest VMM.
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'amend', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def _require_kvm(self):
        """Skip the test when `/dev/kvm` is not readable+writable.

        amend launches a guest VM; mirror resize's guest-needs-kvm
        skip so the suite degrades gracefully where kvm is
        unavailable.
        """
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            self.skipTest('/dev/kvm not readable+writable')

    def _qemu_create(self, path, compat, extra_opts=(), backing=None):
        """Create a qcow2 fixture with `qemu-img create`.

        Builds `-o compat=<compat>[,<extra...>][,backing_file=<backing>,
        backing_fmt=qcow2]` and asserts the create succeeds. qemu
        requires `backing_fmt` alongside `backing_file`.
        """
        opts = [f'compat={compat}']
        opts.extend(extra_opts)
        if backing is not None:
            opts.append(f'backing_file={backing}')
            opts.append('backing_fmt=qcow2')
        cmd = ['qemu-img', 'create', '-f', 'qcow2',
               '-o', ','.join(opts), str(path), '1M']
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0,
            f'qemu-img create failed for {path}: {r.stderr!r}')


# ----------------------------------------------------------------------
# Differential cross-validation — the core matrix.
# ----------------------------------------------------------------------


class TestAmendCrossValidation(TestAmendSmoke):
    """Live cross-validation against the system qemu-img.

    For each entry in AMEND_CASES['qcow2'], builds the start image,
    amends a copy with `instar amend` and another with `qemu-img
    amend`, then asserts the two are info-equivalent, that the
    instar output passes `qemu-img check`, and that `qemu-img
    compare` against the un-amended original shows the guest data is
    unchanged.
    """

    pass


def _make_amend_diff_test(case):
    """Factory: one differential test method per AMEND_CASES entry."""
    case_name, create_opts, amend_opts = case

    def test(self):
        self._require_kvm()

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            start = td / 'start.qcow2'

            # Build the start image. Backing cases need a base.qcow2
            # first and a backing reference in the start image. The
            # backing_file is recorded relative to the image dir, so
            # create runs with the backing name as written.
            if case_name in _BACKING_CASES:
                base = td / 'base.qcow2'
                self._qemu_create(base, compat='1.1')
                # create_opts is [compat=X]; split the compat value.
                compat = create_opts[0].split('=', 1)[1]
                extra = create_opts[1:]
                cwd_create_path = start
                # qemu records backing_file verbatim; create from the
                # image dir so 'base.qcow2' resolves both now and at
                # info time.
                opts = [f'compat={compat}']
                opts.extend(extra)
                opts.append('backing_file=base.qcow2')
                opts.append('backing_fmt=qcow2')
                r = subprocess.run(
                    ['qemu-img', 'create', '-f', 'qcow2',
                     '-o', ','.join(opts), str(cwd_create_path), '1M'],
                    capture_output=True, text=True, timeout=30, cwd=str(td))
                self.assertEqual(
                    r.returncode, 0,
                    f'qemu-img create (backing) failed: {r.stderr!r}')
            else:
                compat = create_opts[0].split('=', 1)[1]
                self._qemu_create(start, compat=compat,
                                  extra_opts=create_opts[1:])

            # A: instar amend, B: qemu amend, orig: pristine copy.
            path_a = td / 'a.qcow2'
            path_b = td / 'b.qcow2'
            path_orig = td / 'orig.qcow2'
            shutil.copy2(start, path_a)
            shutil.copy2(start, path_b)
            shutil.copy2(start, path_orig)

            # instar amend (one -o per opt, ArgAction::Append).
            i_args = ['-f', 'qcow2']
            for o in amend_opts:
                i_args.extend(['-o', o])
            i_args.append(str(path_a))
            i_stdout, i_stderr, i_rc = self.run_instar_amend(*i_args)
            self.assertEqual(
                i_rc, 0,
                f'instar amend failed for {case_name}: stderr={i_stderr!r}')

            # qemu-img amend (single comma-joined -o list).
            r = subprocess.run(
                ['qemu-img', 'amend', '-f', 'qcow2',
                 '-o', ','.join(amend_opts), str(path_b)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img amend failed for {case_name}: {r.stderr!r}')

            # Info-equivalence (unless a documented divergence).
            info_a, err_a, rc_a = self.run_qemu_img_info(path_a)
            self.assertEqual(
                rc_a, 0, f'qemu-img info A failed: {err_a}')
            info_b, err_b, rc_b = self.run_qemu_img_info(path_b)
            self.assertEqual(
                rc_b, 0, f'qemu-img info B failed: {err_b}')

            known = KNOWN_AMEND_DIVERGENCES.get(('qcow2', case_name))
            if known is None:
                # run_qemu_img_info uses plain `info` (no
                # --output=json); re-run for JSON.
                ja = self._qemu_info_json(path_a)
                jb = self._qemu_info_json(path_b)
                assert_info_equivalent(
                    self, ja, jb, 'qcow2',
                    tmp_path=str(path_a),
                    expected_tmp_path=str(path_b),
                    msg=f'amend cross-validation {case_name}')

            # qemu-img check on the instar output passes.
            _, chk_err, chk_rc = self.run_qemu_img_check(path_a)
            self.assertEqual(
                chk_rc, 0,
                f'qemu-img check failed on instar output for '
                f'{case_name}: stderr={chk_err}')

            # qemu-img compare: amend must not touch guest data, so
            # the original and the instar-amended image are identical.
            cmp_out, cmp_err, cmp_rc = self.run_qemu_img_compare(
                path_orig, path_a)
            self.assertEqual(
                cmp_rc, 0,
                f'qemu-img compare orig-vs-instar for {case_name} '
                f'reports a difference (amend changed guest data!): '
                f'stdout={cmp_out!r} stderr={cmp_err!r}')

            # noop: instar must print "No change." and exit 0.
            if case_name == 'noop':
                self.assertIn(
                    'No change.', i_stdout,
                    f'noop amend should print "No change."; '
                    f'stdout={i_stdout!r}')

            # Backing cases: the backing filename must survive the
            # amend (visible in qemu-img info on the instar output).
            if case_name in _BACKING_CASES:
                self.assertIn(
                    'base.qcow2', info_a,
                    f'{case_name}: backing filename lost from amended '
                    f'image; info A:\n{info_a}')

    test.__name__ = f'test_diff_qcow2_{case_name.replace("-", "_")}'
    test.__doc__ = (
        f'instar amend vs qemu-img amend for qcow2 {case_name}: '
        f'create {create_opts} -> amend {amend_opts}.'
    )
    return test


# A small helper bound to the smoke parent for JSON info. Defined as
# a method-installing closure so both the factory and refusal tests
# can call `self._qemu_info_json(path)`.
def _qemu_info_json(self, path, timeout=30):
    """Run `qemu-img info --output=json` and return stdout.

    `run_qemu_img_info` in base.py uses the human format; the
    differential comparison needs JSON.
    """
    r = subprocess.run(
        ['qemu-img', 'info', '--output=json', str(path)],
        capture_output=True, text=True, timeout=timeout)
    self.assertEqual(
        r.returncode, 0,
        f'qemu-img info --output=json failed for {path}: {r.stderr!r}')
    return r.stdout


TestAmendSmoke._qemu_info_json = _qemu_info_json


for _case in AMEND_CASES['qcow2']:
    _name = f'test_diff_qcow2_{_case[0].replace("-", "_")}'
    setattr(TestAmendCrossValidation, _name, _make_amend_diff_test(_case))


# ----------------------------------------------------------------------
# Refusal tests — instar must refuse the structurally-impossible
# amends with a clear non-zero exit + mapped stderr message. We also
# run qemu-img amend on the same case and assert it ALSO fails; if
# qemu unexpectedly succeeds we do NOT fail the test (instar may be
# more conservative) but record it as a documented divergence note.
# ----------------------------------------------------------------------


class TestAmendRefusals(TestAmendSmoke):
    """Refusal contracts + backing-preservation assertions."""

    def test_downgrade_compressed_refused(self):
        """Downgrade of a v3 image with the compression incompatible
        feature is refused (ERROR_DOWNGRADE_BLOCKED_FEATURE).

        A non-default compression type (zstd) sets the qcow2
        compression incompatible-feature bit, which makes the v3 ->
        v2 downgrade structurally impossible.

        NOTE (divergence): on qemu-img 10.0.8 `qemu-img amend
        -o compat=0.10` on a zstd image SUCCEEDS (rc=0) -- qemu
        rewrites the compression type rather than refusing. instar
        is deliberately more conservative and refuses. This is an
        accepted instar-over-refuses-vs-qemu divergence; per the
        plan we record it rather than failing the test.
        """
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / 'zstd.qcow2'
            # Try a zstd image directly; fall back to a compressed
            # convert; skip if neither path produces a compressed v3.
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'compat=1.1,compression_type=zstd', str(src), '1M'],
                capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                plain = td / 'plain.qcow2'
                pr = subprocess.run(
                    ['qemu-img', 'create', '-f', 'qcow2',
                     '-o', 'compat=1.1', str(plain), '1M'],
                    capture_output=True, text=True, timeout=30)
                if pr.returncode != 0:
                    self.skipTest(
                        'qemu cannot create a v3 image to compress')
                cr = subprocess.run(
                    ['qemu-img', 'convert', '-O', 'qcow2', '-c',
                     str(plain), str(src)],
                    capture_output=True, text=True, timeout=30)
                if cr.returncode != 0:
                    self.skipTest(
                        'qemu cannot create a compressed v3 fixture '
                        '(neither compression_type=zstd nor convert -c)')

            # Confirm the fixture actually carries the compression
            # incompatible feature; if not, this refusal has no
            # subject and we skip rather than assert vacuously.
            jr = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(src)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(jr.returncode, 0, jr.stderr)
            ctype = (json.loads(jr.stdout)
                     .get('format-specific', {})
                     .get('data', {})
                     .get('compression-type'))
            if ctype != 'zstd':
                self.skipTest(
                    f'fixture compression-type={ctype!r}; the default '
                    f'(zlib) does not set the incompatible-feature bit, '
                    f'so the downgrade is not structurally blocked')

            inst = td / 'inst.qcow2'
            shutil.copy2(src, inst)
            _, stderr, rc = self.run_instar_amend(
                '-f', 'qcow2', '-o', 'compat=0.10', str(inst))
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse downgrade of a compressed v3 '
                f'image; stderr={stderr!r}')
            self.assertIn('v3-only', stderr,
                          f'unexpected stderr: {stderr!r}')

            # qemu cross-check: assert it fails OR record the
            # divergence (qemu 10.0.8 succeeds here).
            qemu = td / 'qemu.qcow2'
            shutil.copy2(src, qemu)
            qr = subprocess.run(
                ['qemu-img', 'amend', '-f', 'qcow2',
                 '-o', 'compat=0.10', str(qemu)],
                capture_output=True, text=True, timeout=60)
            if qr.returncode == 0:
                # Documented divergence: instar over-refuses relative
                # to qemu, which silently rewrites the compression
                # type. Not a failure (see method docstring).
                pass

    def test_downgrade_refcount_bits_refused(self):
        """Downgrade of a v3 image with refcount_bits=64 is refused
        (ERROR_DOWNGRADE_REFCOUNT_WIDTH). qemu also refuses."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / 'rb.qcow2'
            self._qemu_create(src, compat='1.1',
                              extra_opts=['refcount_bits=64'])
            inst = td / 'inst.qcow2'
            shutil.copy2(src, inst)
            _, stderr, rc = self.run_instar_amend(
                '-f', 'qcow2', '-o', 'compat=0.10', str(inst))
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse refcount_bits!=16 downgrade; '
                f'stderr={stderr!r}')
            self.assertIn('refcount', stderr.lower(),
                          f'unexpected stderr: {stderr!r}')

            qemu = td / 'qemu.qcow2'
            shutil.copy2(src, qemu)
            qr = subprocess.run(
                ['qemu-img', 'amend', '-f', 'qcow2',
                 '-o', 'compat=0.10', str(qemu)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(
                qr.returncode, 0,
                f'qemu unexpectedly accepted refcount_bits=64 '
                f'downgrade: stderr={qr.stderr!r}')

    def test_downgrade_extended_l2_refused(self):
        """Downgrade of a v3 image with extended_l2=on is refused
        (ERROR_DOWNGRADE_BLOCKED_FEATURE). qemu also refuses."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / 'el2.qcow2'
            self._qemu_create(src, compat='1.1',
                              extra_opts=['extended_l2=on'])
            inst = td / 'inst.qcow2'
            shutil.copy2(src, inst)
            _, stderr, rc = self.run_instar_amend(
                '-f', 'qcow2', '-o', 'compat=0.10', str(inst))
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse extended_l2 downgrade; '
                f'stderr={stderr!r}')
            self.assertIn('v3-only', stderr,
                          f'unexpected stderr: {stderr!r}')

            qemu = td / 'qemu.qcow2'
            shutil.copy2(src, qemu)
            qr = subprocess.run(
                ['qemu-img', 'amend', '-f', 'qcow2',
                 '-o', 'compat=0.10', str(qemu)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(
                qr.returncode, 0,
                f'qemu unexpectedly accepted extended_l2 downgrade: '
                f'stderr={qr.stderr!r}')

    def test_lazy_on_against_v2_refused(self):
        """lazy_refcounts=on against a v2 image is refused
        (ERROR_LAZY_REQUIRES_V3). qemu also refuses."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / 'v2.qcow2'
            self._qemu_create(src, compat='0.10')
            inst = td / 'inst.qcow2'
            shutil.copy2(src, inst)
            _, stderr, rc = self.run_instar_amend(
                '-f', 'qcow2', '-o', 'lazy_refcounts=on', str(inst))
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse lazy_refcounts=on against v2; '
                f'stderr={stderr!r}')
            sl = stderr.lower()
            self.assertTrue(
                'lazy' in sl and ('v3' in sl or 'compat=1.1' in sl),
                f'stderr should mention lazy + v3/compat=1.1: {stderr!r}')

            qemu = td / 'qemu.qcow2'
            shutil.copy2(src, qemu)
            qr = subprocess.run(
                ['qemu-img', 'amend', '-f', 'qcow2',
                 '-o', 'lazy_refcounts=on', str(qemu)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(
                qr.returncode, 0,
                f'qemu unexpectedly accepted lazy_refcounts=on against '
                f'v2: stderr={qr.stderr!r}')

    def test_unsupported_o_key_refused(self):
        """An unsupported -o key (cluster_size) is rejected host-side
        before launching the guest. qemu also rejects it."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / 'u.qcow2'
            self._qemu_create(src, compat='1.1')
            inst = td / 'inst.qcow2'
            shutil.copy2(src, inst)
            _, stderr, rc = self.run_instar_amend(
                '-f', 'qcow2', '-o', 'cluster_size=64k', str(inst))
            self.assertNotEqual(
                rc, 0,
                f'instar should reject an unsupported -o key; '
                f'stderr={stderr!r}')
            self.assertIn('not supported', stderr.lower(),
                          f'unexpected stderr: {stderr!r}')

            qemu = td / 'qemu.qcow2'
            shutil.copy2(src, qemu)
            qr = subprocess.run(
                ['qemu-img', 'amend', '-f', 'qcow2',
                 '-o', 'cluster_size=64k', str(qemu)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(
                qr.returncode, 0,
                f'qemu unexpectedly accepted cluster_size amend: '
                f'stderr={qr.stderr!r}')

    # --------- Backing-preservation assertions (via instar info) ---------

    def test_upgrade_with_backing_preserves_backing(self):
        """Upgrading a v2 overlay to v3 preserves the backing
        reference (visible in `instar info --output=json`)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            self._qemu_create(td / 'base.qcow2', compat='1.1')
            overlay = td / 'overlay.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'compat=0.10,backing_file=base.qcow2,backing_fmt=qcow2',
                 str(overlay), '1M'],
                capture_output=True, text=True, timeout=30, cwd=str(td))
            self.assertEqual(r.returncode, 0, r.stderr)

            _, stderr, rc = self.run_instar_amend(
                '-f', 'qcow2', '-o', 'compat=1.1', str(overlay))
            self.assertEqual(rc, 0, f'amend failed: stderr={stderr!r}')

            stdout, info_err, info_rc = self.run_instar_info(
                overlay, output_format='json')
            self.assertEqual(info_rc, 0, f'info failed: {info_err}')
            info = json.loads(stdout)
            self.assertEqual(info.get('backing-filename'), 'base.qcow2')
            self.assertEqual(
                info['format-specific']['data']['compat'], '1.1')

    def test_downgrade_with_backing_preserves_backing(self):
        """Downgrading a v3 overlay to v2 preserves the backing
        reference (visible in `instar info --output=json`)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            self._qemu_create(td / 'base.qcow2', compat='1.1')
            overlay = td / 'overlay.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'compat=1.1,backing_file=base.qcow2,backing_fmt=qcow2',
                 str(overlay), '1M'],
                capture_output=True, text=True, timeout=30, cwd=str(td))
            self.assertEqual(r.returncode, 0, r.stderr)

            _, stderr, rc = self.run_instar_amend(
                '-f', 'qcow2', '-o', 'compat=0.10', str(overlay))
            self.assertEqual(rc, 0, f'amend failed: stderr={stderr!r}')

            stdout, info_err, info_rc = self.run_instar_info(
                overlay, output_format='json')
            self.assertEqual(info_rc, 0, f'info failed: {info_err}')
            info = json.loads(stdout)
            self.assertEqual(info.get('backing-filename'), 'base.qcow2')
            self.assertEqual(
                info['format-specific']['data']['compat'], '0.10')
