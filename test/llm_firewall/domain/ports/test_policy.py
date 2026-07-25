"""Policy: abc.ABC contract."""

from __future__ import annotations

import pytest

from llm_firewall.adapters.policies.secret_policy import SecretPolicy
from llm_firewall.domain.models import Finding, InspectionContext, Severity
from llm_firewall.domain.ports import Policy


def test_cannot_instantiate_the_interface_directly() -> None:
    with pytest.raises(TypeError):
        Policy()  # type: ignore[abstract]


def test_subclass_missing_evaluate_cannot_be_instantiated() -> None:
    class _Incomplete(Policy):
        name = "incomplete"

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


def test_subclass_missing_name_cannot_be_instantiated() -> None:
    class _Incomplete(Policy):
        def evaluate(self, context: InspectionContext) -> list[Finding]:
            return []

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


def test_complete_subclass_can_be_instantiated_and_used() -> None:
    class _Complete(Policy):
        name = "complete"

        def evaluate(self, context: InspectionContext) -> list[Finding]:
            return []

    policy = _Complete()
    context = InspectionContext(prompt="p")

    assert isinstance(policy, Policy)
    assert policy.evaluate(context) == []


def test_secret_policy_satisfies_the_interface() -> None:
    assert isinstance(SecretPolicy(), Policy)


def test_expensive_defaults_to_false() -> None:
    class _Complete(Policy):
        name = "complete"

        def evaluate(self, context: InspectionContext) -> list[Finding]:
            return []

    assert _Complete().expensive is False


@pytest.mark.asyncio
async def test_aevaluate_default_wraps_sync_evaluate() -> None:
    class _AlwaysFlag(Policy):
        name = "always_flag"
        severity = Severity.CRITICAL

        def evaluate(self, context: InspectionContext) -> list[Finding]:
            return [self._finding(message="flagged")]

    findings = await _AlwaysFlag().aevaluate(InspectionContext(prompt="p"))

    assert len(findings) == 1
    assert findings[0].message == "flagged"


def test_finding_helper_builds_finding_with_defaults() -> None:
    class _AlwaysFlag(Policy):
        name = "always_flag"
        severity = Severity.CRITICAL

        def evaluate(self, context: InspectionContext) -> list[Finding]:
            return [self._finding(message="flagged")]

    [finding] = _AlwaysFlag().evaluate(InspectionContext(prompt="p"))

    assert finding.policy == "always_flag"
    assert finding.category == "always_flag"
    assert finding.severity == Severity.CRITICAL
    assert finding.message == "flagged"
