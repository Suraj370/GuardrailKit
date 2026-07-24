"""UnsafeToolCallPolicy: rule-based detection of dangerous tool/function calls.

Two independent checks per :class:`~llm_firewall.domain.models.ToolCall`:

- the tool *name* matches a high-risk action pattern (code execution,
  destructive file/data operations, privilege escalation) -- catching
  the model invoking a dangerous capability at all, regardless of args.
- an argument *value* looks like a shell-injection payload or a leaked
  secret (the latter reusing
  :data:`~llm_firewall.adapters.policies.secret_policy.SECRET_PATTERNS`
  rather than duplicating that pattern list).
"""

from __future__ import annotations

import re
from typing import Any

from llm_firewall.adapters.policies.secret_policy import SECRET_PATTERNS
from llm_firewall.domain.models import Finding, InspectionContext, Severity
from llm_firewall.domain.models.tool_call import ToolCall
from llm_firewall.domain.ports import Policy
from llm_firewall.plugins import POLICIES

_DANGEROUS_NAME_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(exec|eval|shell|subprocess|run[_-]?command|run[_-]?code)\b",
        r"\bsystem\b",
        r"\b(delete|drop|remove|rm)[_-]?(file|table|database|db|record|dir(ectory)?)?\b",
        r"\bsudo\b",
        r"\bchmod\b",
        r"\bformat[_-]?(disk|drive)\b",
    )
)

_SHELL_INJECTION_PATTERN = re.compile(r"(;|\|\||&&|\$\(|`|>\s*/dev/)")


def _flatten_string_values(value: Any) -> list[str]:
    """Collect every string leaf value out of a (possibly nested) argument payload."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _flatten_string_values(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _flatten_string_values(v)]
    return []


@POLICIES.register
class UnsafeToolCallPolicy(Policy):
    """Flags tool calls with high-risk names or shell-injection/secret-bearing arguments."""

    name = "unsafe_tool_call"
    severity = Severity.HIGH
    category = "unsafe_tool_call"

    def evaluate(self, context: InspectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for call in context.tool_calls:
            findings.extend(self._check_name(call))
            findings.extend(self._check_arguments(call))
        return findings

    def _check_name(self, call: ToolCall) -> list[Finding]:
        matched = [p.pattern for p in _DANGEROUS_NAME_PATTERNS if p.search(call.name)]
        if not matched:
            return []
        return [
            self._finding(
                message=f"tool call {call.name!r} matches a high-risk action pattern",
                metadata={"tool_name": call.name, "matched_patterns": matched},
            )
        ]

    def _check_arguments(self, call: ToolCall) -> list[Finding]:
        findings: list[Finding] = []
        for value in _flatten_string_values(call.arguments):
            if _SHELL_INJECTION_PATTERN.search(value):
                findings.append(
                    self._finding(
                        message=f"tool call {call.name!r} has an argument resembling "
                        "shell-injection payload",
                        metadata={"tool_name": call.name, "argument_value": value},
                    )
                )

            matched_secrets = [label for label, pattern in SECRET_PATTERNS if pattern.search(value)]
            if matched_secrets:
                findings.append(
                    self._finding(
                        message=f"tool call {call.name!r} argument appears to leak secrets "
                        f"({', '.join(matched_secrets)})",
                        severity=Severity.CRITICAL,
                        metadata={
                            "tool_name": call.name,
                            "matched_secret_types": matched_secrets,
                        },
                    )
                )
        return findings
