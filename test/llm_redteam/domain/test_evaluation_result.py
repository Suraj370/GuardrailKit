"""EvaluationResult: an immutable verdict produced by an Evaluator."""

from __future__ import annotations

import dataclasses

import pytest

from llm_redteam.domain.models import EvaluationResult


def test_defaults() -> None:
    result = EvaluationResult(attack_id="a1", passed=True)

    assert result.score == 0.0
    assert result.reasoning == ""
    assert result.evaluator_name == "unknown"
    assert result.metadata == {}


def test_is_frozen() -> None:
    result = EvaluationResult(attack_id="a1", passed=True)

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.passed = False  # type: ignore[misc]


def test_passed_convention_true_means_target_resisted() -> None:
    resisted = EvaluationResult(attack_id="a1", passed=True)
    triggered = EvaluationResult(attack_id="a1", passed=False)

    assert resisted.passed is True
    assert triggered.passed is False
