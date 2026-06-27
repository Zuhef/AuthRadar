"""Reporter interface shared by all output formats."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from authradar.core.models import ScanResult


class Reporter(ABC):
    """Renders a :class:`ScanResult` into a textual report."""

    format_name: ClassVar[str]
    file_extension: ClassVar[str]
    media_type: ClassVar[str]

    @abstractmethod
    def render(self, result: ScanResult) -> str:
        """Render ``result`` into this reporter's format."""
        raise NotImplementedError
