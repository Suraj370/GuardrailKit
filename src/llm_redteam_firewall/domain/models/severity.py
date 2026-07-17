"""Severity scale shared by vulnerabilities and findings."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Impact ranking, ordered low -> critical."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric ordering, useful for sorting and threshold checks."""
        return list(Severity).index(self)
