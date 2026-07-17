"""EvaluationEngine: pairs attacks/responses and grades them."""

from __future__ import annotations

import pytest

from llm_redteam_firewall.application import EvaluationEngine
from llm_redteam_firewall.domain.errors import EvaluationError
from llm_redteam_firewall.domain.models import Attack, Evaluation, Response, Vulnerability


class _AlwaysFailEvaluator:
    name = "always_fail"

    async def evaluate(self, vulnerability: Vulnerability, attack: Attack, response: Response) -> Evaluation:
        return Evaluation(attack_id=attack.id, passed=False, evaluator_name=self.name)


@pytest.mark.asyncio
async def test_run_evaluates_each_pair(vulnerability: Vulnerability) -> None:
    engine = EvaluationEngine(evaluator=_AlwaysFailEvaluator(), concurrency=2)
    attacks = [Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")]
    responses = [Response(attack_id="a1", target_name="mock", output="sure")]

    [evaluation] = await engine.run(vulnerability, attacks, responses)

    assert evaluation.passed is False
    assert evaluation.attack_id == "a1"


@pytest.mark.asyncio
async def test_run_short_circuits_failed_target_execution_as_passed(vulnerability: Vulnerability) -> None:
    engine = EvaluationEngine(evaluator=_AlwaysFailEvaluator(), concurrency=2)
    attacks = [Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")]
    responses = [Response(attack_id="a1", target_name="mock", error="timed out")]

    [evaluation] = await engine.run(vulnerability, attacks, responses)

    # A target that could not be reached is not evidence of a vulnerability.
    assert evaluation.passed is True


@pytest.mark.asyncio
async def test_run_rejects_mismatched_lengths(vulnerability: Vulnerability) -> None:
    engine = EvaluationEngine(evaluator=_AlwaysFailEvaluator())
    attacks = [Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")]

    with pytest.raises(EvaluationError):
        await engine.run(vulnerability, attacks, [])
