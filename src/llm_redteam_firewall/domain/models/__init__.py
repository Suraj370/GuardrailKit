"""Domain entities and value objects.

Everything in this package is a plain, framework-free Python object
(dataclass or enum). Nothing here imports from ``application``,
``adapters``, ``config``, or ``cli`` — the dependency arrow only ever
points inward, toward this package. See ``ARCHITECTURE.md`` for the
full dependency-direction diagram.

Core entities, matching the campaign execution flow:

    Campaign -> Vulnerability -> Attack -> AttackResult
             -> EvaluationResult -> Finding -> Report
"""

from .attack import Attack
from .attack_result import AttackResult
from .campaign import Campaign
from .evaluation_result import EvaluationResult
from .execution_context import ExecutionContext
from .finding import Finding, FindingStatus
from .report import Report
from .severity import Severity
from .vulnerability import Vulnerability

__all__ = [
    "Attack",
    "AttackResult",
    "Campaign",
    "EvaluationResult",
    "ExecutionContext",
    "Finding",
    "FindingStatus",
    "Report",
    "Severity",
    "Vulnerability",
]
