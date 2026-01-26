"""Type definitions for imago test framework."""

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

    @property
    def is_safe(self) -> bool:
        """Return True if this is a safe image."""
        return self.safety == 'safe'

    @property
    def is_malicious(self) -> bool:
        """Return True if this is a malicious image."""
        return self.safety == 'malicious'

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
        )
