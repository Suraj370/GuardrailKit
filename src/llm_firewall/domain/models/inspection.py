"""InspectionContext / Decision / InspectionResult: the guard's core vocabulary.

An inspection runs over a prompt and, optionally, the model's response
to it (policies that only care about user input, e.g. prompt-injection
detection, can fire before a response even exists). The guard then
reduces every policy's findings down to one :class:`Decision`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from llm_firewall.domain.models.finding import Finding
from llm_firewall.domain.models.severity import Severity
from llm_firewall.domain.models.tool_call import ToolCall


@dataclass(frozen=True, slots=True)
class InspectionContext:
    """What a :class:`~llm_firewall.domain.ports.Policy` inspects.

    ``response`` is ``None`` when only the inbound prompt is available
    yet (e.g. a pre-call guard checking for prompt injection before
    the request is ever sent to the model). ``system_prompt``, when
    given, lets policies like
    :class:`~llm_firewall.adapters.policies.system_prompt_leak_policy.SystemPromptLeakPolicy`
    check whether ``response`` echoes it back. ``tool_calls`` carries
    any tool/function calls the model attempted in this turn, for
    policies like
    :class:`~llm_firewall.adapters.policies.unsafe_tool_call_policy.UnsafeToolCallPolicy`.
    """

    prompt: str
    response: str | None = None
    system_prompt: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


class Decision(StrEnum):
    """The guard's verdict for one inspection."""

    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class InspectionResult:
    """Outcome of running every configured policy over one :class:`InspectionContext`."""

    decision: Decision
    context: InspectionContext
    findings: tuple[Finding, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    @property
    def flagged(self) -> bool:
        return self.decision == Decision.FLAG

    @property
    def blocked(self) -> bool:
        return self.decision == Decision.BLOCK

    @property
    def max_severity(self) -> Severity | None:
        """Highest severity among findings, or ``None`` if clean."""
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
