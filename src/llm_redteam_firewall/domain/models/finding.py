"""The Finding entity: a stored, actionable result of a campaign run."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from .attack import Attack
from .evaluation import Evaluation
from .response import Response
from .severity import Severity
from .vulnerability import Vulnerability


class FindingStatus(StrEnum):
    """Lifecycle status of a finding, mirrored by most bug trackers."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"


@dataclass(frozen=True, slots=True)
class Finding:
    """A vulnerability confirmed (or observed) by a single attack run.

    A Finding binds together every fact needed to reproduce and triage
    a result: which vulnerability was targeted, which attack was used,
    what the target returned, and how it was graded. This is the unit
    that :mod:`~llm_redteam_firewall.domain.ports.storage` persists and
    that :mod:`~llm_redteam_firewall.domain.ports.reporter` renders.
    """

    vulnerability: Vulnerability
    attack: Attack
    response: Response
    evaluation: Evaluation
    campaign_name: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: Severity = Severity.MEDIUM
    status: FindingStatus = FindingStatus.OPEN
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_vulnerable(self) -> bool:
        """True when the attack defeated the target (evaluation failed)."""
        return not self.evaluation.passed
