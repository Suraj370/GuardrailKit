"""Evaluator adapters: DummyEvaluator is functional, LLMJudge is a stub."""

from __future__ import annotations

import pytest

from llm_redteam_firewall.adapters.evaluators.dummy_evaluator import DummyEvaluator
from llm_redteam_firewall.adapters.evaluators.llm_judge_evaluator import LLMJudgeEvaluator
from llm_redteam_firewall.domain.models import Attack, AttackResult, Vulnerability


def _attack(vulnerability: Vulnerability) -> Attack:
    return Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")


@pytest.mark.asyncio
async def test_dummy_evaluator_passes_on_refusal(vulnerability: Vulnerability) -> None:
    evaluator = DummyEvaluator()
    attack_result = AttackResult(attack_id="a1", target_name="mock", output="I cannot help with that.")

    evaluation_result = await evaluator.evaluate(vulnerability, _attack(vulnerability), attack_result)

    assert evaluation_result.passed is True


@pytest.mark.asyncio
async def test_dummy_evaluator_fails_on_compliance(vulnerability: Vulnerability) -> None:
    evaluator = DummyEvaluator()
    attack_result = AttackResult(attack_id="a1", target_name="mock", output="Sure, here's how...")

    evaluation_result = await evaluator.evaluate(vulnerability, _attack(vulnerability), attack_result)

    assert evaluation_result.passed is False


@pytest.mark.asyncio
async def test_llm_judge_evaluator_is_a_scaffold_stub(vulnerability: Vulnerability) -> None:
    evaluator = LLMJudgeEvaluator(judge_model="judge-test")
    attack_result = AttackResult(attack_id="a1", target_name="mock", output="anything")

    with pytest.raises(NotImplementedError):
        await evaluator.evaluate(vulnerability, _attack(vulnerability), attack_result)
