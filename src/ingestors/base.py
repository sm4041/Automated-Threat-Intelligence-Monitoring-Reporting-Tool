"""Base ingestor interface."""

from abc import ABC, abstractmethod
from typing import List


class BaseIngestor(ABC):
    source_name: str = "unknown"

    @abstractmethod
    def fetch(self) -> List[dict]:
        """Fetch raw advisory data and return as list of dicts."""
        ...
