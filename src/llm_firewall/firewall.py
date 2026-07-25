"""Firewall: the package's public facade.

Most callers only need this: build one from a config file (or with the
in-tree defaults) and call :meth:`inspect` on each prompt/response pair::

    from llm_firewall import Firewall

    fw = Firewall.from_config("firewall.yaml")
    result = fw.inspect(prompt=user_input, response=model_output)
    if result.blocked:
        raise BlockedByFirewall(result.findings)

An ``ainspect()`` counterpart exists too, for callers already running on
an event loop with many concurrent inspections in flight (e.g.
:class:`~llm_redteam.adapters.targets.firewall_target.FirewallTarget`)
-- see :meth:`Firewall.ainspect`.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from llm_firewall.application import FirewallGuard
from llm_firewall.domain.models import InspectionContext, InspectionResult, Severity, ToolCall


class Firewall:
    """Ergonomic wrapper around a :class:`FirewallGuard` for host applications."""

    def __init__(self, guard: FirewallGuard) -> None:
        self._guard = guard

    @classmethod
    def from_config(cls, path: str | Path) -> Firewall:
        """Build a Firewall from a YAML config file (see :mod:`llm_firewall.config`)."""
        from llm_firewall.config import load_guard

        return cls(load_guard(path))

    @classmethod
    def with_default_policies(
        cls,
        *,
        block_severity: Severity = Severity.HIGH,
        flag_severity: Severity = Severity.LOW,
    ) -> Firewall:
        """Build a Firewall running every in-tree policy with the given thresholds."""
        from llm_firewall import adapters  # noqa: F401 - registers in-tree policies
        from llm_firewall.plugins import POLICIES

        guard = FirewallGuard(
            POLICIES.all(), block_severity=block_severity, flag_severity=flag_severity
        )
        return cls(guard)

    @property
    def guard(self) -> FirewallGuard:
        return self._guard

    def inspect(
        self,
        prompt: str,
        response: str | None = None,
        *,
        system_prompt: str | None = None,
        tool_calls: Sequence[ToolCall] = (),
        **metadata: object,
    ) -> InspectionResult:
        """Run every configured policy over one prompt/response (and optional extras).

        ``system_prompt`` and ``tool_calls`` are optional context for
        policies that need them (e.g. detecting system-prompt leakage or
        unsafe tool calls) -- omit either when they don't apply.
        """
        context = InspectionContext(
            prompt=prompt,
            response=response,
            system_prompt=system_prompt,
            tool_calls=tuple(tool_calls),
            metadata=dict(metadata),
        )
        return self._guard.inspect(context)

    async def ainspect(
        self,
        prompt: str,
        response: str | None = None,
        *,
        system_prompt: str | None = None,
        tool_calls: Sequence[ToolCall] = (),
        **metadata: object,
    ) -> InspectionResult:
        """Async counterpart to :meth:`inspect` -- same arguments and semantics.

        Prefer this over :meth:`inspect` when calling from inside a
        concurrent caller (e.g. many attacks running at once) and a
        configured policy does real async I/O -- see
        :meth:`~llm_firewall.domain.ports.Policy.aevaluate`.
        """
        context = InspectionContext(
            prompt=prompt,
            response=response,
            system_prompt=system_prompt,
            tool_calls=tuple(tool_calls),
            metadata=dict(metadata),
        )
        return await self._guard.ainspect(context)
