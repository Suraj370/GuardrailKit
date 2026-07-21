"""Evaluator: abc.ABC contract."""

from __future__ import annotations

import pytest

from llm_redteam.adapters.evaluators.dummy_evaluator import DummyEvaluator
from llm_redteam.domain.models import Attack, AttackResult, EvaluationResult, Vulnerability
from llm_redteam.domain.ports import Evaluator


def test_cannot_instantiate_the_interface_directly() -> None:
    with pytest.raises(TypeError):
        Evaluator()  # type: ignore[abstract]


def test_subclass_missing_evaluate_cannot_be_instantiated() -> None:
    class _Incomplete(Evaluator):
        name = "incomplete"

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


def test_subclass_missing_name_cannot_be_instantiated() -> None:
    class _Incomplete(Evaluator):
        async def evaluate(
            self, vulnerability: Vulnerability, attack: Attack, attack_result: AttackResult
        ) -> EvaluationResult:
            return EvaluationResult(attack_id=attack.id, passed=True)

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


@pytest.mark.asyncio
async def test_complete_subclass_can_be_instantiated_and_used(vulnerability: Vulnerability) -> None:
    class _Complete(Evaluator):
        name = "complete"

        async def evaluate(
            self, vulnerability: Vulnerability, attack: Attack, attack_result: AttackResult
        ) -> EvaluationResult:
            return EvaluationResult(attack_id=attack.id, passed=True, evaluator_name=self.name)

    evaluator = _Complete()
    attack = Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")
    attack_result = AttackResult(attack_id="a1", target_name="mock", output="ok")

    assert isinstance(evaluator, Evaluator)
    result = await evaluator.evaluate(vulnerability, attack, attack_result)
    assert result.passed is True


def test_dummy_evaluator_satisfies_the_interface() -> None:
    assert isinstance(DummyEvaluator(), Evaluator)
