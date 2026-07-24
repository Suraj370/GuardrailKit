"""InspectionResult: decision helpers and max_severity reduction."""

from __future__ import annotations

from llm_firewall.domain.models import (
    Decision,
    Finding,
    InspectionContext,
    InspectionResult,
    Severity,
)


def _finding(severity: Severity, policy: str = "p") -> Finding:
    return Finding(policy=policy, category=policy, severity=severity, message="x")


def test_allowed_when_no_findings() -> None:
    context = InspectionContext(prompt="hello")
    result = InspectionResult(decision=Decision.ALLOW, context=context)

    assert result.allowed
    assert not result.flagged
    assert not result.blocked
    assert result.max_severity is None


def test_max_severity_picks_highest() -> None:
    context = InspectionContext(prompt="hello")
    result = InspectionResult(
        decision=Decision.BLOCK,
        context=context,
        findings=(_finding(Severity.LOW), _finding(Severity.CRITICAL), _finding(Severity.MEDIUM)),
    )

    assert result.blocked
    assert result.max_severity == Severity.CRITICAL


def test_response_defaults_to_none() -> None:
    context = InspectionContext(prompt="hello")
    assert context.response is None
    assert context.metadata == {}


def test_system_prompt_and_tool_calls_default_empty() -> None:
    context = InspectionContext(prompt="hello")
    assert context.system_prompt is None
    assert context.tool_calls == ()
