"""InMemoryStorage: the reference FindingsStorage implementation.

Backed by a plain Python list. Findings do not survive process exit —
useful for examples, tests, and CI runs where persistence is not the
point.
"""

from __future__ import annotations

from llm_redteam_firewall.domain.models import Finding
from llm_redteam_firewall.plugins import STORAGE


@STORAGE.register("in_memory")
class InMemoryStorage:
    """Process-local, non-persistent FindingsStorage."""

    name = "in_memory"

    def __init__(self) -> None:
        self._findings: list[Finding] = []

    def save(self, finding: Finding) -> None:
        self._findings.append(finding)

    def list(self, campaign_name: str | None = None) -> list[Finding]:
        if campaign_name is None:
            return list(self._findings)
        return [f for f in self._findings if f.campaign_name == campaign_name]
