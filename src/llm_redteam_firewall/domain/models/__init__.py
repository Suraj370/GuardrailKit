"""Domain entities and value objects.

Everything in this package is a plain, framework-free Python object
(dataclass or enum). Nothing here imports from ``application``,
``adapters``, ``config``, or ``cli`` — the dependency arrow only ever
points inward, toward this package. See ``ARCHITECTURE.md`` for the
full dependency-direction diagram.
"""

from .attack import Attack
from .campaign import Campaign, CampaignResult
from .evaluation import Evaluation
from .execution_context import ExecutionContext
from .finding import Finding, FindingStatus
from .response import Response
from .severity import Severity
from .vulnerability import Vulnerability

__all__ = [
    "Attack",
    "Campaign",
    "CampaignResult",
    "Evaluation",
    "ExecutionContext",
    "Finding",
    "FindingStatus",
    "Response",
    "Severity",
    "Vulnerability",
]
