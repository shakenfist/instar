"""Snapshot read-back oracle (COW parity contract C6/C7/C8).

Extract a named internal snapshot's *virtual view* as a raw sha256,
WITHOUT ever mutating the original image: copy the image, apply the
snapshot on the copy, convert the copy to raw, sha256 the raw. This is
the Python port of ``scratchpad/7p/oracle/readback.sh`` (phase 7 probe
7p), landed here by step 7b as the reusable oracle the later COW parity
steps (7c/7e) extend.

The oracle constrains snapshot *content*, never image bytes: qemu's COW
placement is nondeterministic (Q3), so the phase-7 proof is qemu-parity
(``qemu-img compare`` + ``qemu-img check`` + this read-back), not
before/after byte identity (C11). Compare a post-op image's snapshot
read-back against the SAME snapshot read-back of a ``qemu-img``-committed
twin computed with the identical pinned ``qemu-img`` binary; the expected
value is per-op (commit preserves; rebase reads through the new backing).

Usage::

    from helpers.snapshot_readback import snapshot_readback
    sha = snapshot_readback('qemu-img', image_path, 'snap1')
"""

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def _backing_filename(qemu_img, image):
    """Return the image's recorded backing filename, or '' if none."""
    out = subprocess.run(
        [str(qemu_img), 'info', '--output=json', str(image)],
        capture_output=True, text=True, check=True).stdout
    return json.loads(out).get('backing-filename') or ''


def snapshot_readback(qemu_img, image, snapshot):
    """Return the sha256 hex of ``snapshot``'s virtual view in ``image``.

    Never mutates ``image``. The read-back copy is rebased (metadata
    only) onto the ABSOLUTE backing path first, so a relative-backing
    chain still resolves once the copy has moved to a temp directory.

    Args:
        qemu_img: Path to the ``qemu-img`` binary to use (pin the same
            binary for the instar image and its qemu twin).
        image: Path to the snapshot-bearing image (read only).
        snapshot: Name/tag of the internal snapshot to apply.

    Returns:
        The 64-character lowercase sha256 hex digest of the snapshot's
        raw virtual view.
    """
    qemu_img = str(qemu_img)
    image = Path(image)
    image_dir = image.resolve().parent
    with tempfile.TemporaryDirectory() as td:
        copy = Path(td) / 'copy.qcow2'
        shutil.copyfile(image, copy)

        backing = _backing_filename(qemu_img, image)
        if backing:
            if not Path(backing).is_absolute():
                backing = str(image_dir / backing)
            subprocess.run(
                [qemu_img, 'rebase', '-u', '-f', 'qcow2',
                 '-b', backing, '-F', 'qcow2', str(copy)],
                capture_output=True, text=True, check=True)

        subprocess.run(
            [qemu_img, 'snapshot', '-a', snapshot, str(copy)],
            capture_output=True, text=True, check=True)

        raw = Path(td) / 'out.raw'
        subprocess.run(
            [qemu_img, 'convert', '-f', 'qcow2', '-O', 'raw',
             str(copy), str(raw)],
            capture_output=True, text=True, check=True)

        h = hashlib.sha256()
        with open(raw, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()
