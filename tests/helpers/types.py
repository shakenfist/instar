"""Type definitions for instar test framework."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class TestImage:
    """Represents a test image from the manifest."""
    id: str
    path: Path
    format: str
    safety: str
    run_in_ci: bool
    description: str
    tags: list = field(default_factory=list)
    expected_override: Optional[str] = None
    skip_qemu_img: bool = False
    expected_error: Optional[str] = None
    cve_references: list = field(default_factory=list)
    sha256: Optional[str] = None
    unsafe_quirks_required: bool = False
    data_file: Optional[str] = None

    @property
    def data_file_path(self) -> Optional[Path]:
        """Return the absolute path to the companion data file, if any."""
        if self.data_file is None:
            return None
        return self.path.parent / self.data_file

    @property
    def is_safe(self) -> bool:
        """Return True if this is a safe image."""
        return self.safety == 'safe'

    @property
    def is_malicious(self) -> bool:
        """Return True if this is a malicious image."""
        return self.safety == 'malicious'

    @property
    def requires_unsafe_quirks(self) -> bool:
        """Return True if this image requires --unsafe-quirks mode for testing.

        Images without valid partition tables or format headers need this flag
        to be accepted as RAW disk images. Without the flag, instar rejects them
        as unknown format (secure default behavior).
        """
        return self.unsafe_quirks_required

    @classmethod
    def from_dict(cls, data: dict, testdata_root: Path) -> 'TestImage':
        """Create TestImage from manifest dictionary."""
        return cls(
            id=data['id'],
            path=testdata_root / data['path'],
            format=data['format'],
            safety=data['safety'],
            run_in_ci=data['run_in_ci'],
            description=data['description'],
            tags=data.get('tags', []),
            expected_override=data.get('expected_override'),
            skip_qemu_img=data.get('skip_qemu_img', False),
            expected_error=data.get('expected_error'),
            cve_references=data.get('cve_references', []),
            sha256=data.get('sha256'),
            unsafe_quirks_required=data.get('unsafe_quirks_required', False),
            data_file=data.get('data_file'),
        )
