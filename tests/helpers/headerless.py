"""Bytes no format probe identifies, for headerless raw fixtures.

Chain discovery names a file with no magic and no partition table
`unknown`, and the tests that cover how such a member is read need
one. Pseudo-random bytes rather than a pattern: a file of repeated
bytes could match a probe by accident, which is the one thing the
fixture must not do. The seed is fixed so a failure replays with the
same bytes, and the result is cached because every caller wants the
same bytes and some want 16 MiB of them.
"""

import functools
import random

_SEED = 0x6054


@functools.lru_cache(maxsize=None)
def headerless_bytes(size: int) -> bytes:
    """Return `size` deterministic bytes that identify as no format."""
    return random.Random(_SEED).randbytes(size)
