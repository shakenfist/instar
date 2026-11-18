"""Split-flat VMDK images, created when a test runs.

A `twoGbMaxExtentFlat` image cannot be stored as a fixture. Its extents are
full-length sparse files, 2 GiB each, and git-LFS stores holes as bytes.
Measured on `downloaded/qemu-iotests/d2v-zerofilled.vhd`: 264,308,224 bytes
apparent, 512 KiB allocated in the checkout, and 264,314,880 bytes of LFS
object. So a 33 GiB split-flat image would be a 33 GiB LFS object, while the
split-SPARSE extents of the same image are a few hundred KiB each and are
stored as fixtures. A test that needs a split-flat image makes one with this
module, against a named qemu-img, and the image is removed afterwards.
"""

import contextlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import List, NamedTuple

from helpers.qemu_pins import IMAGE_STEM, run_command
from helpers.vmdk_structure import descriptor_extents, read_descriptor, resolve_extent_path


class SplitFlatImage(NamedTuple):
    """A split-flat image: its descriptor and its extents, in descriptor order."""

    descriptor: Path
    extents: List[Path]


@contextlib.contextmanager
def split_flat_image(qemu_img, size: str, workdir):
    """Create a split-flat VMDK of `size` (such as '5G') and yield a `SplitFlatImage`.

    The image is made by `qemu-img create -f vmdk -o subformat=twoGbMaxExtentFlat`
    in a fresh directory under `workdir`, and that directory is removed on
    leaving the block, so a 33 GiB image does not outlive its test.

    A missing or non-executable `qemu-img` raises FileNotFoundError, and a
    failed create raises RuntimeError. Neither skips: a helper that skips
    when its oracle is absent turns a missing dependency into a green run.
    """
    # The path is checked rather than looked up: shutil.which would search
    # PATH for a bare name and quietly hand back the host's qemu-img, whose
    # version decides what the created image looks like.
    resolved = Path(qemu_img)
    if not (resolved.is_file() and os.access(resolved, os.X_OK)):
        raise FileNotFoundError(f'no executable qemu-img at {qemu_img}')
    directory = Path(tempfile.mkdtemp(prefix='split-flat-', dir=workdir))
    try:
        image = directory / f'{IMAGE_STEM}.vmdk'
        proc = run_command([resolved.resolve(), 'create', '-f', 'vmdk', '-o', 'subformat=twoGbMaxExtentFlat',
                            image, size], directory)
        if proc.returncode != 0:
            raise RuntimeError(f'qemu-img create of a {size} split-flat VMDK failed: {proc.stderr.strip()}')
        text, _ = read_descriptor(image)
        extents = [Path(resolve_extent_path(one['filename'], directory, 'extent'))
                   for one in descriptor_extents(text)]
        yield SplitFlatImage(image, extents)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
