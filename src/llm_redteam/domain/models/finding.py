"""The Finding entity: a stored, actionable result of a campaign run."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .attack import Attack
from .attack_result import AttackResult
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
    that :mod:`~llm_redteam.domain.ports.storage` persists and
    that :mod:`~llm_redteam.domain.ports.reporter` renders.

    Findings are produced by two independent sources — an
    :class:`~llm_redteam.domain.ports.evaluator.Evaluator`
    grading a named vulnerability probe, or a
    :class:`~llm_redteam.domain.ports.policy.Policy` flagging a
    standing rule violation — so the verdict is carried here as plain
    fields (``passed``/``reasoning``/``score``/``source``) rather than a
    nested :class:`~llm_redteam.domain.models.evaluation_result.EvaluationResult`.
    That keeps the two worlds decoupled: neither ``Policy`` nor
    ``Finding`` needs to know that ``EvaluationResult`` exists.
    """

    vulnerability: Vulnerability
    attack: Attack
    attack_result: AttackResult
    campaign_name: str
    passed: bool
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: Severity = Severity.MEDIUM
    status: FindingStatus = FindingStatus.OPEN
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    reasoning: str = ""
    score: float = 0.0
    source: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_vulnerable(self) -> bool:
        """True when the attack defeated the target or violated a policy."""
        return not self.passed
