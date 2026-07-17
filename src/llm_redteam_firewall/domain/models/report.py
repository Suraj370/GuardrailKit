"""The Report entity: the immutable, final output of a completed Campaign run."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .finding import Finding


@dataclass(frozen=True, slots=True)
class Report:
    """A complete, immutable record of one campaign run.

    Unlike the other entities here, a ``Report`` cannot be assembled
    incrementally: the orchestrator collects findings in a local list
    while the campaign runs and constructs exactly one ``Report`` once
    every vulnerability has been processed. This keeps the domain
    model honest — a ``Report`` either fully describes a finished
    campaign or does not exist yet — at the cost of the orchestrator
    doing its own bookkeeping during the run (see ``application``).
    """

    campaign_name: str
    findings: tuple[Finding, ...]
    started_at: datetime
    finished_at: datetime

    @property
    def total_attacks(self) -> int:
        return len(self.findings)

    @property
    def vulnerable_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.is_vulnerable)

    @property
    def pass_rate(self) -> float:
        if not self.findings:
            return 1.0
        resisted = len(self.findings) - len(self.vulnerable_findings)
        return resisted / len(self.findings)
