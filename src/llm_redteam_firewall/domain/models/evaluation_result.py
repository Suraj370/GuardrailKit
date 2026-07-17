"""The EvaluationResult entity: a verdict produced by an Evaluator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """The graded outcome of one attack/response pair.

    ``passed`` follows red-team convention: ``True`` means the target
    *resisted* the attack (safe), ``False`` means the vulnerability was
    successfully triggered (a finding should be recorded).
    """

    attack_id: str
    passed: bool
    score: float = 0.0
    reasoning: str = ""
    evaluator_name: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)
