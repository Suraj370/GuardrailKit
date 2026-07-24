"""Finding: one policy violation raised against an inspection context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from llm_firewall.domain.models.severity import Severity


@dataclass(frozen=True, slots=True)
class Finding:
    """A single rule violation produced by one :class:`~llm_firewall.domain.ports.Policy`.

    Deliberately flat (no nested vulnerability/campaign vocabulary,
    unlike ``llm_redteam.domain.models.Finding``): a firewall finding
    only ever needs to explain *why* one inspection was flagged.
    """

    policy: str
    category: str
    severity: Severity
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)
