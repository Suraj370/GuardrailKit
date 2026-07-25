"""Policy interface: rule-based (or later ML/LLM-judge) checks over an inspection.

Single responsibility: inspect one :class:`~llm_firewall.domain.models.InspectionContext`
and return zero or more :class:`~llm_firewall.domain.models.Finding` objects
when the policy is violated. Policies are pure and side-effect free by
contract — no I/O, no mutation of the context.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any

from llm_firewall.domain.models import Finding, InspectionContext, Severity


class Policy(ABC):
    """Inspects one prompt/response pair and emits findings on violation."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name this policy registers under."""
        raise NotImplementedError

    @property
    def severity(self) -> Severity:
        """Default severity assigned to findings this policy produces."""
        return Severity.MEDIUM

    @property
    def category(self) -> str:
        """Finding category tag; defaults to the policy's own name."""
        return self.name

    @property
    def expensive(self) -> bool:
        """Whether this policy does I/O (e.g. an LLM call) rather than pure computation.

        :class:`~llm_firewall.application.guard.FirewallGuard` runs
        expensive policies after cheap ones, and skips remaining
        policies once earlier findings already guarantee a ``BLOCK``
        decision -- so an accurate answer here avoids paying for a
        network call whose result can't change the outcome.
        """
        return False

    @abstractmethod
    def evaluate(self, context: InspectionContext) -> list[Finding]:
        """Return findings for any violation of this policy.

        An empty list means the context is clean with respect to this
        policy.
        """
        raise NotImplementedError

    async def aevaluate(self, context: InspectionContext) -> list[Finding]:
        """Async counterpart to :meth:`evaluate`.

        Default implementation runs the sync :meth:`evaluate` in a
        thread, which is fine for pure-computation policies (every
        regex-based one in this package) -- there's no shared I/O
        client for concurrent calls to collide over. Policies that do
        real async I/O of their own (e.g.
        :class:`~llm_firewall.adapters.policies.nemo_guardrails_policy.NemoGuardrailsPolicy`
        calling an LLM) should override this directly instead, so a
        concurrent caller (:class:`~llm_redteam.adapters.targets.firewall_target.FirewallTarget`)
        can await it natively rather than bouncing through a thread
        pool and a nested sync-wrapped event loop -- the latter is what
        actually caused ``RuntimeError: cannot schedule new futures
        after shutdown`` under concurrent campaign runs.
        """
        return await asyncio.to_thread(self.evaluate, context)

    def _finding(
        self,
        *,
        message: str,
        severity: Severity | None = None,
        category: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """Build a :class:`Finding` representing a violation of this policy."""
        return Finding(
            policy=self.name,
            category=category if category is not None else self.category,
            severity=severity if severity is not None else self.severity,
            message=message,
            metadata=dict(metadata or {}),
        )
