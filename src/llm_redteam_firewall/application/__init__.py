"""Application layer: use cases that orchestrate domain ports.

Depends only on :mod:`llm_redteam_firewall.domain` (entities + ports).
Never imports from ``adapters``, ``config``, ``cli``, or ``plugins`` —
which concrete adapters get injected is decided entirely by the
composition root, not by this layer.
"""

from .campaign_orchestrator import CampaignOrchestrator
from .evaluation_engine import EvaluationEngine
from .execution_engine import ExecutionEngine
from .policy_engine import PolicyEngine

__all__ = [
    "CampaignOrchestrator",
    "EvaluationEngine",
    "ExecutionEngine",
    "PolicyEngine",
]
