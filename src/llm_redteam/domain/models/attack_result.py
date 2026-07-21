"""The AttackResult entity: what a Target returned for a given Attack."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class AttackResult:
    """The observed output of executing an :class:`Attack` against a Target.

    ``error`` is set (and ``output`` typically empty) when the target
    could not be reached or raised during execution; the evaluation
    engine decides how to score that case rather than the target
    swallowing the failure.
    """

    attack_id: str
    target_name: str
    output: str = ""
    latency_ms: float = 0.0
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.error is None
