"""Campaign entities: the unit of work the orchestrator runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from .finding import Finding
from .vulnerability import Vulnerability


@dataclass(frozen=True, slots=True)
class Campaign:
    """A named, reproducible red-team run against one target.

    A Campaign is pure configuration: which vulnerabilities to probe,
    how many attacks to generate per vulnerability, and how long to
    let each execution run. It says nothing about *which* generator,
    target, evaluator, storage, or reporter implementations are used —
    that wiring lives in the composition root
    (:mod:`llm_redteam_firewall.config.loader`), not the domain.
    """

    name: str
    vulnerabilities: tuple[Vulnerability, ...]
    max_attacks_per_vulnerability: int = 5
    concurrency: int = 5
    description: str = ""


@dataclass(slots=True)
class CampaignResult:
    """The aggregate output of running a :class:`Campaign` to completion."""

    campaign_name: str
    findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None

    @property
    def total_attacks(self) -> int:
        return len(self.findings)

    @property
    def vulnerable_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_vulnerable]

    @property
    def pass_rate(self) -> float:
        if not self.findings:
            return 1.0
        resisted = len(self.findings) - len(self.vulnerable_findings)
        return resisted / len(self.findings)
