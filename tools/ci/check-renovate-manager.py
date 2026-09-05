#!/usr/bin/env python3
"""Run renovate.json's own customManager over the devcontainer Dockerfiles.

check-devcontainer-pins.sh asserts the *format* each pin must take for
Renovate's regex customManager to see it: an unquoted value, and a
`# renovate: datasource=crate depName=<crate>` comment directly above
the ARG. That is this repository's memory of what the manager needs,
and it leaves the manager itself unguarded -- a typo in `matchStrings`,
or a `managerFilePatterns` entry that stops naming these files, freezes
every pin forever while the shell guard still reports them visible. A
frozen pin is worse than the floating installs the pins replaced,
because nothing errors anywhere.

So take the regex that is actually in renovate.json today, run it over
the two Dockerfiles, and require it to find exactly the pins the shell
guard found by its own parse -- same crates, same versions, no more and
no fewer. The two halves are then derived from different sources and
have to agree.

Usage:
    check-renovate-manager.py RENOVATE_JSON PINS_TSV DOCKERFILE...

PINS_TSV holds one `path<TAB>crate<TAB>version` row per pin the shell
guard validated. Exits 0 when the manager reproduces that set exactly,
1 otherwise, describing the difference.
"""

import fnmatch
import json
import re
import sys

# Renovate regexes are JS-flavoured, where a named group is `(?<name>...)`.
# Python spells it `(?P<name>...)`. Lookbehind -- `(?<=` and `(?<!` -- uses
# the same opening characters and must not be rewritten.
NAMED_GROUP = re.compile(r'\(\?<(?![=!])')


def to_python_regex(pattern):
    return NAMED_GROUP.sub('(?P<', pattern)


def covers(patterns, path):
    """Whether a managerFilePatterns list names `path`.

    Renovate 41+ accepts a glob, or a regex delimited by slashes. Only
    the forms this repository actually uses are interpreted; anything
    else is reported rather than quietly treated as a miss, so a
    reviewer sees that the cross-check stopped being able to read the
    config instead of seeing a spurious pass.
    """
    for pattern in patterns:
        if pattern.startswith('/') and pattern.endswith('/') and len(pattern) > 1:
            if re.search(pattern[1:-1], path):
                return True
        elif pattern == path or fnmatch.fnmatch(path, pattern):
            return True
    return False


def main(argv):
    if len(argv) < 4:
        print(__doc__, file=sys.stderr)
        return 1

    renovate_json, pins_tsv = argv[1], argv[2]
    dockerfiles = argv[3:]

    with open(renovate_json) as handle:
        config = json.load(handle)

    expected = set()
    with open(pins_tsv) as handle:
        for line in handle:
            line = line.rstrip('\n')
            if not line:
                continue
            path, crate, version = line.split('\t')
            expected.add((path, crate, version))

    problems = []
    found = set()

    for path in dockerfiles:
        managers = [
            manager for manager in config.get('customManagers', [])
            if covers(manager.get('managerFilePatterns', manager.get('fileMatch', [])), path)
        ]
        if not managers:
            problems.append(
                'no customManagers entry in %s has a managerFilePatterns that names %s, '
                'so none of its pins are managed' % (renovate_json, path))
            continue

        with open(path) as handle:
            content = handle.read()

        for manager in managers:
            if manager.get('customType') != 'regex':
                problems.append(
                    '%s: the customManagers entry covering %s is customType=%r; this '
                    'cross-check only understands regex managers'
                    % (renovate_json, path, manager.get('customType')))
                continue
            for pattern in manager.get('matchStrings', []):
                try:
                    compiled = re.compile(to_python_regex(pattern))
                except re.error as err:
                    problems.append('%s: matchStrings entry does not compile: %s\n  %s'
                                    % (renovate_json, err, pattern))
                    continue
                for match in compiled.finditer(content):
                    groups = match.groupdict()
                    datasource = groups.get('datasource') or manager.get('datasourceTemplate')
                    if datasource != 'crate':
                        problems.append(
                            '%s: %s is matched with datasource=%r, not "crate"'
                            % (path, groups.get('depName'), datasource))
                    found.add((path, groups.get('depName'), groups.get('currentValue')))

    for path, crate, version in sorted(expected - found):
        problems.append(
            '%s: %s@%s is pinned in the Dockerfile but the customManager in %s does not '
            'match it, so Renovate will never bump it' % (path, crate, version, renovate_json))
    for path, crate, version in sorted(found - expected):
        problems.append(
            '%s: the customManager in %s matches %s@%s, which is not a pin this guard '
            'validated -- the regex is matching something it should not'
            % (path, renovate_json, crate, version))

    if problems:
        for problem in problems:
            print('ERROR: %s' % problem, file=sys.stderr)
        return 1

    print('renovate.json matches all %d pins' % len(found))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
