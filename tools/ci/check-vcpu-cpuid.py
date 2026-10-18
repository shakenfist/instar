#!/usr/bin/env python3
"""Assert every vCPU is given a guest CPUID before its control registers.

A freshly created KVM vCPU has an empty guest CPUID, which advertises no
long mode. Since Linux 6.12.112 the kernel validates EFER against the
guest's capabilities when userspace calls KVM_SET_SREGS, so the
EFER.LME|EFER.LMA that setup_sregs writes is refused with EINVAL unless
KVM_SET_CPUID2 has already run on that vCPU. Every instar operation
starts a guest, so missing it breaks all of them at once, and the only
symptom is `Error: Error(22)`.

The VMM creates a vCPU in every operation's setup path -- seventeen of
them when this guard was written -- so the risk is not the call sites
that exist today but the eighteenth, added later, that forgets. This
guard reads the source rather than running anything: it needs no
/dev/kvm, so it can run on a lightweight runner alongside the other CI
tooling guards.

Two properties are checked:

  1. Between each `create_vcpu(` and the `set_sregs(` that follows it,
     there is a `setup_cpuid(` call.
  2. `setup_cpuid` itself still calls `set_cpuid2`, so the helper cannot
     be hollowed out into something that satisfies property 1 while
     setting nothing.

Both properties are read from code rather than from text: a commented-out
call does not count towards property 1, and property 2 looks only inside
the helper's own braces, so a mention of set_cpuid2 in a neighbouring
function cannot vouch for a helper that no longer makes the call.
"""

import argparse
import re
import sys

CREATE = re.compile(r'\bcreate_vcpu\s*\(')
SET_SREGS = re.compile(r'\bset_sregs\s*\(')
SETUP_CPUID = re.compile(r'\bsetup_cpuid\s*\(')
SET_CPUID2 = re.compile(r'\.set_cpuid2\s*\(')
HELPER_DEF = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?fn setup_cpuid\b')
LINE_COMMENT = re.compile(r'//.*$')


def code(line):
    """Return the line with any trailing line comment removed.

    This is deliberately naive: it would also truncate a string literal
    containing '//', which none of the lines these patterns match
    contain. The point is that commenting a call out -- the most likely
    way the call gets lost while someone is debugging -- stops counting
    as a call.
    """
    return LINE_COMMENT.sub('', line)


def helper_body(lines, index):
    """Return the helper's own lines, from its `fn` line to its closing brace.

    rustfmt closes a function with a `}` at the same indentation as the
    `fn` that opened it, so that brace is where the body ends. Returns
    None if there is no such brace, which means the source is not shaped
    the way this guard can read.
    """
    opener = lines[index]
    indent = opener[:len(opener) - len(opener.lstrip())]
    body = [opener]
    for line in lines[index + 1:]:
        body.append(line)
        if line == f'{indent}}}':
            return body
    return None


def check_call_sites(lines):
    """Return a list of complaints about vCPUs that reach SREGS unprepared."""
    problems = []
    for index, line in enumerate(lines):
        if not CREATE.search(code(line)):
            continue
        prepared = False
        for offset in range(index + 1, len(lines)):
            follower = code(lines[offset])
            if SETUP_CPUID.search(follower):
                prepared = True
                break
            if SET_SREGS.search(follower) or CREATE.search(follower):
                break
        if not prepared:
            problems.append(
                f'line {index + 1}: this vCPU reaches set_sregs without a '
                f'setup_cpuid call, so KVM_SET_SREGS will fail with EINVAL '
                f'on Linux 6.12.112 and newer'
            )
    return problems


def check_helper(lines):
    """Return a complaint if setup_cpuid no longer sets a CPUID at all."""
    for index, line in enumerate(lines):
        if not HELPER_DEF.match(line):
            continue
        body = helper_body(lines, index)
        if body is None:
            return [
                f'line {index + 1}: setup_cpuid has no closing brace at its '
                f'own indentation, so this guard cannot tell what its body '
                f'does'
            ]
        if SET_CPUID2.search('\n'.join(code(part) for part in body)):
            return []
        return [
            f'line {index + 1}: setup_cpuid no longer calls set_cpuid2, so '
            f'the call sites below are satisfied by a helper that sets '
            f'nothing'
        ]
    return ['setup_cpuid is not defined; every vCPU reaches set_sregs unprepared']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', default='src/vmm/src/main.rs',
                        help='the VMM source to read (default: %(default)s)')
    args = parser.parse_args()

    with open(args.source, encoding='utf-8') as source:
        lines = source.read().splitlines()

    problems = check_helper(lines) + check_call_sites(lines)
    vcpus = sum(1 for line in lines if CREATE.search(code(line)))

    if problems:
        print(f'{args.source}: guest CPUID setup is missing or incomplete:',
              file=sys.stderr)
        for problem in problems:
            print(f'  {problem}', file=sys.stderr)
        return 1

    print(f'{args.source}: all {vcpus} vCPU(s) are given a guest CPUID '
          f'before their control registers')
    return 0


if __name__ == '__main__':
    sys.exit(main())
