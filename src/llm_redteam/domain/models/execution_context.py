"""ExecutionContext: the ``ctx`` passed to Target.execute and friends."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Cross-cutting call context for a single attack execution.

    Mirrors the role a ``context.Context`` plays in other ecosystems:
    it carries identifiers, timeouts, and arbitrary trace metadata
    through the execution/evaluation engines without the domain
    entities themselves needing to know about campaigns or tracing.

    Deliberately does not carry cancellation primitives here; async
    timeout/cancellation is left to the caller (e.g. ``asyncio.wait_for``)
    to keep this a plain, serializable value object.
    """

    campaign_name: str
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timeout_seconds: float = 30.0
    metadata: dict[str, Any] = field(default_factory=dict)
