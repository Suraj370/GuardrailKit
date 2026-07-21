"""The Response entity: observed target output for a single Attack."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .attack_result import AttackResult


@dataclass(frozen=True, slots=True)
class Response:
    """What the system-under-test produced for a given :class:`Attack`.

    Distinct from :class:`AttackResult` so policy evaluation can talk
    about "attack + response" without depending on execution-engine
    plumbing. Convert freely with :meth:`from_attack_result` /
    :meth:`to_attack_result`.
    """

    attack_id: str
    content: str
    target_name: str = "unknown"
    latency_ms: float = 0.0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        """True when the target produced a response without error."""
        return self.error is None

    def to_attack_result(self) -> AttackResult:
        """Project this response into an :class:`AttackResult` for storage."""
        return AttackResult(
            attack_id=self.attack_id,
            target_name=self.target_name,
            output=self.content,
            latency_ms=self.latency_ms,
            error=self.error,
            raw=dict(self.metadata),
        )

    @classmethod
    def from_attack_result(cls, result: AttackResult) -> Response:
        """Build a :class:`Response` from an execution-engine result."""
        return cls(
            attack_id=result.attack_id,
            content=result.output,
            target_name=result.target_name,
            latency_ms=result.latency_ms,
            error=result.error,
            metadata=dict(result.raw),
        )
