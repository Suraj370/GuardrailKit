"""FirewallAwareEvaluator: short-circuits around a firewall's own decision."""

from __future__ import annotations

import pytest

from llm_redteam.adapters.evaluators.firewall_aware_evaluator import FirewallAwareEvaluator
from llm_redteam.domain.models import (
    Attack,
    AttackResult,
    EvaluationResult,
    Severity,
    Vulnerability,
)
from llm_redteam.domain.ports import Evaluator
from llm_redteam.plugins import EVALUATORS


class _StubEvaluator(Evaluator):
    """Records whether it was called, and returns a canned verdict."""

    name = "stub"

    def __init__(self, passed: bool = False) -> None:
        self._passed = passed
        self.call_count = 0

    async def evaluate(
        self, vulnerability: Vulnerability, attack: Attack, attack_result: AttackResult
    ) -> EvaluationResult:
        self.call_count += 1
        return EvaluationResult(attack_id=attack.id, passed=self._passed, evaluator_name=self.name)


def _false_positive_vulnerability() -> Vulnerability:
    return Vulnerability(
        id="false_positive_check",
        name="False Positive Check",
        category="false_positive",
        severity=Severity.MEDIUM,
    )


def _attack(vuln_id: str = "v1") -> Attack:
    return Attack(id="a1", vulnerability_id=vuln_id, prompt="p")


@pytest.mark.asyncio
async def test_false_positive_category_passes_when_not_blocked() -> None:
    wrapped = _StubEvaluator()
    evaluator = FirewallAwareEvaluator(wrapped=wrapped)
    attack_result = AttackResult(
        attack_id="a1", target_name="firewall", output="fine", raw={"firewall_decision": "allow"}
    )

    result = await evaluator.evaluate(_false_positive_vulnerability(), _attack(), attack_result)

    assert result.passed is True
    assert result.metadata["label"] == "correctly_allowed"
    assert wrapped.call_count == 0  # never delegates for this category


@pytest.mark.asyncio
async def test_false_positive_category_fails_when_blocked() -> None:
    wrapped = _StubEvaluator()
    evaluator = FirewallAwareEvaluator(wrapped=wrapped)
    attack_result = AttackResult(
        attack_id="a1",
        target_name="firewall",
        raw={"firewall_decision": "block", "firewall_stage": "input"},
    )

    result = await evaluator.evaluate(_false_positive_vulnerability(), _attack(), attack_result)

    assert result.passed is False
    assert result.metadata["label"] == "false_positive"
    assert result.metadata["firewall_stage"] == "input"
    assert wrapped.call_count == 0


@pytest.mark.asyncio
async def test_false_positive_falls_back_to_refusal_check_without_a_firewall() -> None:
    """No raw['firewall_decision'] at all (e.g. a raw OpenAITarget) -- check the model's own text."""
    wrapped = _StubEvaluator()
    evaluator = FirewallAwareEvaluator(wrapped=wrapped)
    attack_result = AttackResult(
        attack_id="a1", target_name="openai", output="I can't help with that.", raw={"model": "gpt-test"}
    )

    result = await evaluator.evaluate(_false_positive_vulnerability(), _attack(), attack_result)

    assert result.passed is False  # the model itself refused a genuine prompt
    assert result.metadata["label"] == "false_positive"
    assert result.metadata["refused_by"] == "target"
    assert wrapped.call_count == 0


@pytest.mark.asyncio
async def test_false_positive_without_a_firewall_passes_on_a_real_answer() -> None:
    wrapped = _StubEvaluator()
    evaluator = FirewallAwareEvaluator(wrapped=wrapped)
    attack_result = AttackResult(
        attack_id="a1", target_name="openai", output="Sure, here's a recipe...", raw={"model": "gpt-test"}
    )

    result = await evaluator.evaluate(_false_positive_vulnerability(), _attack(), attack_result)

    assert result.passed is True
    assert result.metadata["label"] == "correctly_allowed"
    assert result.metadata["refused_by"] is None
    assert wrapped.call_count == 0


@pytest.mark.asyncio
async def test_real_vulnerability_short_circuits_when_blocked(vulnerability: Vulnerability) -> None:
    wrapped = _StubEvaluator(passed=False)  # would fail if it were ever called
    evaluator = FirewallAwareEvaluator(wrapped=wrapped)
    attack_result = AttackResult(
        attack_id="a1",
        target_name="firewall",
        raw={
            "firewall_decision": "block",
            "firewall_stage": "input",
            "firewall_findings": ["prompt_injection"],
        },
    )

    result = await evaluator.evaluate(vulnerability, _attack(vulnerability.id), attack_result)

    assert result.passed is True  # resisted by definition -- not the wrapped evaluator's False
    assert result.metadata["label"] == "blocked"
    assert wrapped.call_count == 0


@pytest.mark.asyncio
async def test_real_vulnerability_delegates_to_wrapped_when_allowed(
    vulnerability: Vulnerability,
) -> None:
    wrapped = _StubEvaluator(passed=False)
    evaluator = FirewallAwareEvaluator(wrapped=wrapped)
    attack_result = AttackResult(
        attack_id="a1",
        target_name="firewall",
        output="real response",
        raw={"firewall_decision": "allow"},
    )

    result = await evaluator.evaluate(vulnerability, _attack(vulnerability.id), attack_result)

    assert result.passed is False  # the wrapped evaluator's real verdict
    assert result.evaluator_name == "stub"
    assert wrapped.call_count == 1


@pytest.mark.asyncio
async def test_real_vulnerability_delegates_when_no_firewall_decision_present(
    vulnerability: Vulnerability,
) -> None:
    """A non-FirewallTarget target result (no raw["firewall_decision"] at all) still delegates normally."""
    wrapped = _StubEvaluator(passed=True)
    evaluator = FirewallAwareEvaluator(wrapped=wrapped)
    attack_result = AttackResult(attack_id="a1", target_name="openai", output="real response")

    result = await evaluator.evaluate(vulnerability, _attack(vulnerability.id), attack_result)

    assert result.passed is True
    assert wrapped.call_count == 1


def test_builds_from_registry_with_wrapped_type() -> None:
    evaluator = EVALUATORS.create("firewall_aware", wrapped_type="rule_based")

    assert isinstance(evaluator, FirewallAwareEvaluator)
    assert evaluator._wrapped.name == "rule_based"  # noqa: SLF001
