"""EvaluationEngine: pairs attacks/attack_results and grades them."""

from __future__ import annotations

import pytest

from llm_redteam.application import EvaluationEngine
from llm_redteam.domain.errors import EvaluationError
from llm_redteam.domain.models import Attack, AttackResult, EvaluationResult, Vulnerability


class _AlwaysFailEvaluator:
    name = "always_fail"

    async def evaluate(
        self, vulnerability: Vulnerability, attack: Attack, attack_result: AttackResult
    ) -> EvaluationResult:
        return EvaluationResult(attack_id=attack.id, passed=False, evaluator_name=self.name)


@pytest.mark.asyncio
async def test_run_evaluates_each_pair(vulnerability: Vulnerability) -> None:
    engine = EvaluationEngine(evaluator=_AlwaysFailEvaluator(), concurrency=2)
    attacks = [Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")]
    attack_results = [AttackResult(attack_id="a1", target_name="mock", output="sure")]

    [evaluation_result] = await engine.run(vulnerability, attacks, attack_results)

    assert evaluation_result.passed is False
    assert evaluation_result.attack_id == "a1"


@pytest.mark.asyncio
async def test_run_short_circuits_failed_target_execution_as_passed(
    vulnerability: Vulnerability,
) -> None:
    engine = EvaluationEngine(evaluator=_AlwaysFailEvaluator(), concurrency=2)
    attacks = [Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")]
    attack_results = [AttackResult(attack_id="a1", target_name="mock", error="timed out")]

    [evaluation_result] = await engine.run(vulnerability, attacks, attack_results)

    # A target that could not be reached is not evidence of a vulnerability.
    assert evaluation_result.passed is True
    # ...but it's tagged distinctly so reporting can exclude it from
    # success-rate math instead of silently inflating "Blocked".
    assert evaluation_result.metadata["outcome"] == "errored"
    assert evaluation_result.metadata["error"] == "timed out"


@pytest.mark.asyncio
async def test_run_rejects_mismatched_lengths(vulnerability: Vulnerability) -> None:
    engine = EvaluationEngine(evaluator=_AlwaysFailEvaluator())
    attacks = [Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")]

    with pytest.raises(EvaluationError):
        await engine.run(vulnerability, attacks, [])
