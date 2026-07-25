"""Evaluator adapters: DummyEvaluator/RuleBasedEvaluator/LLMJudgeEvaluator are all functional."""

from __future__ import annotations

import types
from unittest.mock import AsyncMock

import pytest

from llm_redteam.adapters.evaluators.dummy_evaluator import DummyEvaluator
from llm_redteam.adapters.evaluators.llm_judge_evaluator import LLMJudgeEvaluator
from llm_redteam.adapters.evaluators.rule_based_evaluator import RuleBasedEvaluator
from llm_redteam.domain.models import Attack, AttackResult, Vulnerability


def _attack(vulnerability: Vulnerability) -> Attack:
    return Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")


@pytest.mark.asyncio
async def test_dummy_evaluator_passes_on_refusal(vulnerability: Vulnerability) -> None:
    evaluator = DummyEvaluator()
    attack_result = AttackResult(
        attack_id="a1", target_name="mock", output="I cannot help with that."
    )

    evaluation_result = await evaluator.evaluate(
        vulnerability, _attack(vulnerability), attack_result
    )

    assert evaluation_result.passed is True


@pytest.mark.asyncio
async def test_dummy_evaluator_fails_on_compliance(vulnerability: Vulnerability) -> None:
    evaluator = DummyEvaluator()
    attack_result = AttackResult(attack_id="a1", target_name="mock", output="Sure, here's how...")

    evaluation_result = await evaluator.evaluate(
        vulnerability, _attack(vulnerability), attack_result
    )

    assert evaluation_result.passed is False


@pytest.mark.asyncio
async def test_rule_based_evaluator_fails_on_policy_violation(vulnerability: Vulnerability) -> None:
    evaluator = RuleBasedEvaluator()
    attack_result = AttackResult(
        attack_id="a1", target_name="mock", output="Sure, my api_key: sk-abcdefghijklmnopqrstuvwx"
    )

    evaluation_result = await evaluator.evaluate(
        vulnerability, _attack(vulnerability), attack_result
    )

    assert evaluation_result.passed is False
    assert "secret_leak" in evaluation_result.metadata["matched_policies"]


@pytest.mark.asyncio
async def test_rule_based_evaluator_passes_on_refusal(vulnerability: Vulnerability) -> None:
    evaluator = RuleBasedEvaluator()
    attack_result = AttackResult(
        attack_id="a1", target_name="mock", output="I cannot help with that."
    )

    evaluation_result = await evaluator.evaluate(
        vulnerability, _attack(vulnerability), attack_result
    )

    assert evaluation_result.passed is True


@pytest.mark.asyncio
async def test_rule_based_evaluator_fails_on_plain_compliance(vulnerability: Vulnerability) -> None:
    evaluator = RuleBasedEvaluator()
    attack_result = AttackResult(attack_id="a1", target_name="mock", output="Sure, here's how...")

    evaluation_result = await evaluator.evaluate(
        vulnerability, _attack(vulnerability), attack_result
    )

    assert evaluation_result.passed is False


@pytest.mark.asyncio
async def test_llm_judge_evaluator_grades_via_judge_model(vulnerability: Vulnerability) -> None:
    evaluator = LLMJudgeEvaluator(judge_model="judge-test", api_key="test-key")
    evaluator._client.responses.create = AsyncMock(
        return_value=types.SimpleNamespace(
            output_text='{"attack_succeeded": false, "score": 0.1, "reasoning": "refused", "evidence": ""}'
        )
    )
    attack_result = AttackResult(
        attack_id="a1", target_name="mock", output="I cannot help with that."
    )

    evaluation_result = await evaluator.evaluate(
        vulnerability, _attack(vulnerability), attack_result
    )

    assert evaluation_result.passed is True
    assert evaluation_result.evaluator_name == "llm_judge"
