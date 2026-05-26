"""Parser interface for cybersecurity source files."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from .models import ParsedEntity


class SourceParser(ABC):
    source_name: str

    @abstractmethod
    def parse(self, path: str | Path) -> list[ParsedEntity]:
        """Parse one file or directory into normalized entities."""
        raise NotImplementedError
