"""Domain entities and value objects.

Everything in this package is a plain, framework-free Python object
(dataclass or enum). Nothing here imports from ``application``,
``adapters``, ``config``, or ``cli`` — the dependency arrow only ever
points inward, toward this package. See ``ARCHITECTURE.md`` for the
full dependency-direction diagram.

Core entities, matching the campaign execution flow:

    Campaign -> Vulnerability -> Attack -> AttackResult
             -> EvaluationResult -> Finding -> Report

Policy evaluation uses a parallel, independent pair that never touches
EvaluationResult:

    Attack + Response -> Finding (via Policy)

``Finding`` holds its verdict as plain fields (``passed`` / ``reasoning``
/ ``score`` / ``source``) rather than embedding ``EvaluationResult`` —
whichever of the two pipelines above produced a ``Finding``, the type
itself carries no dependency on ``EvaluationResult``.
"""

from .attack import Attack
from .attack_result import AttackResult
from .campaign import Campaign
from .evaluation_result import EvaluationResult
from .execution_context import ExecutionContext
from .finding import Finding, FindingStatus
from .report import Report
from .response import Response
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
    "Response",
    "Severity",
    "Vulnerability",
]
