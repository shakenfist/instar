#!/usr/bin/env python3
"""Unit tests for the differential fuzzer's oracle detection.

Runs with plain `python3 -m unittest` (stdlib only, no venv), like the
other `test_*.py` files next to it, in the `ci-tooling` job.

The libyal tools are the only independent reference for VHD, VHDX and
VMDK, and every consumer in the fuzzer guards on their presence, so a
missing one removes that format's cross-check and the run still reports
"N iterations, 0 divergences" (#590). These tests hold the guard that
stops that being silent in CI: with INSTAR_REQUIRE_LIBYAL set, a
missing tool raises; without it, the run degrades as before.

`shutil.which` is replaced rather than relying on what this host has
installed, so the tests give the same answer on a developer machine and
in the container.
"""

import os
import types
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_DF_PATH = os.path.join(_HERE, '..', '..', 'scripts', 'differential-fuzz.py')


def _load(path, name):
    """Execute a hyphenated script as a module, compiling from source.

    Compiled from the text every time rather than imported, for the
    reason test_extract_fuzz_corpus.py gives: the bytecode cache can
    serve a same-size edit made within the same second, which is what a
    mutation check of this file looks like.
    """
    module = types.ModuleType(name)
    module.__file__ = path
    with open(path, encoding='utf-8') as f:
        source = f.read()
    exec(compile(source, path, 'exec'), module.__dict__)
    return module


df = _load(_DF_PATH, 'differential_fuzz')
# The detector warns about every missing tool, which is right in a run
# and only noise in a test.
df.logger.disabled = True

ALL_TOOLS = ('vmdkinfo', 'vhdiinfo', 'qcowinfo')


class WhichStub:
    """Stand in for shutil.which over a fixed set of installed tools."""

    def __init__(self, installed):
        self.installed = set(installed)

    def __call__(self, name):
        return f'/usr/bin/{name}' if name in self.installed else None


class DetectLibyalToolsTest(unittest.TestCase):

    def setUp(self):
        self.real_which = df.shutil.which
        self.addCleanup(setattr, df.shutil, 'which', self.real_which)
        self.real_environ = dict(os.environ)
        self.addCleanup(self._restore_environ)

    def _restore_environ(self):
        os.environ.clear()
        os.environ.update(self.real_environ)

    def _detect(self, installed, **kwargs):
        df.shutil.which = WhichStub(installed)
        return df.detect_libyal_tools(**kwargs)

    def test_all_present_returns_every_path(self):
        tools = self._detect(ALL_TOOLS, require=True)
        self.assertEqual(sorted(tools), sorted(ALL_TOOLS))
        self.assertEqual(tools['vhdiinfo'], '/usr/bin/vhdiinfo')

    def test_missing_tool_degrades_when_not_required(self):
        tools = self._detect(('vmdkinfo', 'qcowinfo'), require=False)
        self.assertEqual(sorted(tools), ['qcowinfo', 'vmdkinfo'])
        self.assertNotIn('vhdiinfo', tools)

    def test_missing_tool_raises_when_required(self):
        with self.assertRaises(df.MissingOracleError) as caught:
            self._detect(('vmdkinfo', 'qcowinfo'), require=True)
        message = str(caught.exception)
        # The message has to name the tool, the package that provides
        # it and the formats that lost their cross-check, because the
        # person reading it is looking at a red nightly and nothing
        # else says what broke.
        self.assertIn('vhdiinfo', message)
        self.assertIn('libvhdi-utils', message)
        self.assertIn('vpc', message)
        self.assertIn('vhdx', message)
        self.assertIn(df.REQUIRE_LIBYAL_ENV, message)

    def test_every_missing_tool_is_named(self):
        with self.assertRaises(df.MissingOracleError) as caught:
            self._detect((), require=True)
        message = str(caught.exception)
        for tool in ALL_TOOLS:
            self.assertIn(tool, message)
        for package in ('libvmdk-utils', 'libvhdi-utils', 'libqcow-utils'):
            self.assertIn(package, message)

    def test_environment_variable_makes_the_tools_mandatory(self):
        os.environ[df.REQUIRE_LIBYAL_ENV] = '1'
        with self.assertRaises(df.MissingOracleError):
            self._detect(('vmdkinfo', 'qcowinfo'))

    def test_unset_environment_variable_leaves_the_run_degrading(self):
        os.environ.pop(df.REQUIRE_LIBYAL_ENV, None)
        tools = self._detect(('vmdkinfo', 'qcowinfo'))
        self.assertNotIn('vhdiinfo', tools)

    def test_every_tool_in_the_format_map_has_a_package(self):
        # A new format arm that names a tool with no package entry
        # would raise KeyError while building the error message, in the
        # one code path that only runs when something is already wrong.
        for tool in set(df.LIBYAL_TOOLS.values()):
            self.assertIn(tool, df.LIBYAL_PACKAGES)


if __name__ == '__main__':
    unittest.main()
