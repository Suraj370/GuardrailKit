"""The Attack entity: a single probe produced by an AttackGenerator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Attack:
    """One concrete prompt (or prompt sequence) aimed at a vulnerability.

    Attacks are the output of the attack-generation port and the input
    to the execution engine. They are immutable and self-contained so
    that any :class:`~llm_redteam.domain.ports.target.Target`
    implementation can execute them without knowing which generator
    produced them.
    """

    id: str
    vulnerability_id: str
    prompt: str
    technique: str = "direct"
    generator_name: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)
