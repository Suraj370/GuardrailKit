"""AttackResult: an immutable record of what a Target returned."""

from __future__ import annotations

import dataclasses

import pytest

from llm_redteam.domain.models import AttackResult


def test_defaults() -> None:
    result = AttackResult(attack_id="a1", target_name="mock")

    assert result.output == ""
    assert result.latency_ms == 0.0
    assert result.error is None
    assert result.raw == {}


def test_succeeded_is_true_when_no_error() -> None:
    result = AttackResult(attack_id="a1", target_name="mock", output="hi")

    assert result.succeeded is True


def test_succeeded_is_false_when_error_set() -> None:
    result = AttackResult(attack_id="a1", target_name="mock", error="timed out")

    assert result.succeeded is False


def test_is_frozen() -> None:
    result = AttackResult(attack_id="a1", target_name="mock")

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.output = "changed"  # type: ignore[misc]


def test_default_raw_dict_is_not_shared_between_instances() -> None:
    a = AttackResult(attack_id="a1", target_name="mock")
    b = AttackResult(attack_id="a2", target_name="mock")

    a.raw["mutated"] = True

    assert "mutated" not in b.raw
