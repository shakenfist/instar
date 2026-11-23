"""A NamedTemporaryFile whose cleanup tolerates the file being gone.

A failed `convert`, `dd` or `copy` removes an output file it left
empty (#849). A test that hands instar the path of a
`tempfile.NamedTemporaryFile` and expects a refusal then reaches the
end of its `with` block with the file already unlinked, and what
happens next depends on the Python running the suite: 3.12 and later
ignore the missing file, while 3.10 and 3.11 raise FileNotFoundError
from the context manager's exit and fail the test (#959).

The PR gate runs the suite on Debian 13's Python 3.13, so it cannot
see the difference; only the merge queue's Debian 12 and Ubuntu 22.04
legs can, and they ejected every PR queued after #945 landed. Tests
use `ScratchFile` instead, which behaves the same on every Python, and
tools/ci/check-no-named-temporary-file.sh keeps
`tempfile.NamedTemporaryFile` out of tests/.
"""

import os
import tempfile
import weakref


def _remove(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        # Already gone, typically because instar removed an output it
        # left empty (#849). That is the case this module exists for.
        pass


class ScratchFile:
    """A drop-in for `tempfile.NamedTemporaryFile`.

    It takes the same arguments, can be used as a context manager or
    closed by hand, exposes `name`, and passes every other attribute
    through to the underlying file. The one difference is that a file
    already removed by the time it is cleaned up is not an error, on
    any Python. With `delete=False` the file is kept, as it is by
    NamedTemporaryFile.

    `delete_on_close` (Python 3.12 and later) is refused: ScratchFile
    always removes the file on close, and forwarding the argument would
    be a TypeError on 3.10 and 3.11 -- the version-dependent failure
    this class exists to remove.
    """

    def __init__(self, *args, delete=True, **kwargs):
        if 'delete_on_close' in kwargs:
            raise TypeError(
                'ScratchFile manages deletion itself; delete_on_close is not supported')
        self._file = tempfile.NamedTemporaryFile(*args, delete=False, **kwargs)
        self.name = self._file.name
        # The wrapper's own answer, not the underlying file's, which is
        # always False because ScratchFile does the deleting.
        self.delete = delete
        # Like NamedTemporaryFile, a ScratchFile nobody closed is still
        # removed when it is garbage collected or the interpreter exits.
        self._finalizer = weakref.finalize(
            self, ScratchFile._cleanup, self._file, self.name, delete)

    @staticmethod
    def _cleanup(file, name, delete):
        file.close()
        if delete:
            _remove(name)

    def close(self):
        self._finalizer()

    def __enter__(self):
        self._file.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def __iter__(self):
        return iter(self._file)

    def __getattr__(self, attr):
        # Only reached for attributes ScratchFile does not have itself.
        # Private names are never passed through: if __init__ failed
        # before binding _file, or copy or pickle built an instance
        # without running it, looking up self._file here would re-enter
        # __getattr__ and recurse until RecursionError hid the real fault.
        if attr.startswith('_'):
            raise AttributeError(attr)
        return getattr(self._file, attr)
