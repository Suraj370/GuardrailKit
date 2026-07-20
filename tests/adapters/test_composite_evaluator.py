"""CompositeJudgeEvaluator: combines RuleBasedEvaluator + LLMJudgeEvaluator verdicts."""

from __future__ import annotations

import types
from unittest.mock import AsyncMock

import pytest

from llm_redteam_firewall.adapters.evaluators.composite_evaluator import CompositeJudgeEvaluator
from llm_redteam_firewall.domain.models import Attack, AttackResult, Severity, Vulnerability


def _vulnerability(category: str) -> Vulnerability:
    return Vulnerability(
        id=category,
        name=category.replace("_", " ").title(),
        category=category,
        description="test vulnerability",
        severity=Severity.HIGH,
    )


def _attack() -> Attack:
    return Attack(id="a1", vulnerability_id="v1", prompt="do the bad thing")


def _attack_result(output: str) -> AttackResult:
    return AttackResult(attack_id="a1", target_name="mock", output=output)


def _evaluator(judge_output: str) -> CompositeJudgeEvaluator:
    evaluator = CompositeJudgeEvaluator(judge_model="gpt-test", api_key="test-key")
    evaluator._judge_evaluator._client.responses.create = AsyncMock(
        return_value=types.SimpleNamespace(output_text=judge_output)
    )
    return evaluator


_JUDGE_BLOCKED = '{"attack_succeeded": false, "score": 0.1, "reasoning": "resisted", "evidence": ""}'
_JUDGE_SUCCEEDED = '{"attack_succeeded": true, "score": 0.8, "reasoning": "leaked it", "evidence": "sk-xyz"}'


@pytest.mark.asyncio
async def test_both_agree_blocked() -> None:
    evaluator = _evaluator(_JUDGE_BLOCKED)

    result = await evaluator.evaluate(
        _vulnerability("jailbreak"), _attack(), _attack_result("I cannot help with that.")
    )

    assert result.passed is True
    assert result.metadata["label"] == "blocked"
    assert result.metadata["rule_passed"] is True
    assert result.metadata["judge_passed"] is True


@pytest.mark.asyncio
async def test_rule_flags_even_when_judge_says_blocked() -> None:
    evaluator = _evaluator(_JUDGE_BLOCKED)
    leaking_response = "sure, here is a key: sk-abcdefghijklmnopqrstuvwx"

    result = await evaluator.evaluate(
        _vulnerability("secret_leakage"), _attack(), _attack_result(leaking_response)
    )

    assert result.passed is False
    assert result.metadata["rule_passed"] is False
    assert result.metadata["judge_passed"] is True
    assert result.metadata["label"] == "leaked"  # secret_leakage is a leakage category


@pytest.mark.asyncio
async def test_judge_flags_even_when_rules_pass() -> None:
    evaluator = _evaluator(_JUDGE_SUCCEEDED)
    # Contains a refusal marker and matches no policy -> RuleBasedEvaluator passes it.
    refusal_response = "I cannot help with that."

    result = await evaluator.evaluate(
        _vulnerability("jailbreak"), _attack(), _attack_result(refusal_response)
    )

    assert result.passed is False
    assert result.metadata["rule_passed"] is True
    assert result.metadata["judge_passed"] is False
    assert result.metadata["label"] == "unsafe"  # jailbreak is a behavioral category, not leakage


@pytest.mark.asyncio
async def test_both_flag_violation() -> None:
    evaluator = _evaluator(_JUDGE_SUCCEEDED)
    leaking_response = "sure, here is a key: sk-abcdefghijklmnopqrstuvwx"

    result = await evaluator.evaluate(
        _vulnerability("secret_leakage"), _attack(), _attack_result(leaking_response)
    )

    assert result.passed is False
    assert result.metadata["rule_passed"] is False
    assert result.metadata["judge_passed"] is False


@pytest.mark.parametrize("category", ["pii_leakage", "secret_leakage", "prompt_leakage"])
@pytest.mark.asyncio
async def test_leakage_categories_labeled_leaked(category: str) -> None:
    evaluator = _evaluator(_JUDGE_SUCCEEDED)

    result = await evaluator.evaluate(_vulnerability(category), _attack(), _attack_result("whatever"))

    assert result.metadata["label"] == "leaked"


@pytest.mark.parametrize("category", ["jailbreak", "prompt_injection", "tool_misuse"])
@pytest.mark.asyncio
async def test_behavioral_categories_labeled_unsafe(category: str) -> None:
    evaluator = _evaluator(_JUDGE_SUCCEEDED)

    result = await evaluator.evaluate(_vulnerability(category), _attack(), _attack_result("whatever"))

    assert result.metadata["label"] == "unsafe"


@pytest.mark.asyncio
async def test_score_is_max_of_both_signals() -> None:
    evaluator = _evaluator(_JUDGE_SUCCEEDED)  # judge score 0.8

    result = await evaluator.evaluate(
        _vulnerability("jailbreak"), _attack(), _attack_result("benign reply")
    )

    assert result.score == pytest.approx(0.8)


@pytest.mark.asyncio
async def test_default_judge_model_is_gpt5_nano() -> None:
    evaluator = CompositeJudgeEvaluator(api_key="test-key")

    assert evaluator._judge_evaluator._judge_model == "gpt-5-nano"


@pytest.mark.asyncio
async def test_evaluator_name() -> None:
    evaluator = CompositeJudgeEvaluator(api_key="test-key")

    assert evaluator.name == "judge_and_rules"
