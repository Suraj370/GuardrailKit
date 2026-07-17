"""Finding: an immutable, actionable result of a single attack run."""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime

import pytest

from llm_redteam_firewall.domain.models import (
    Attack,
    AttackResult,
    EvaluationResult,
    Finding,
    FindingStatus,
    Severity,
    Vulnerability,
)


def _finding(*, passed: bool, vulnerability: Vulnerability) -> Finding:
    attack = Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")
    attack_result = AttackResult(attack_id="a1", target_name="mock", output="sure")
    evaluation_result = EvaluationResult(attack_id="a1", passed=passed)
    return Finding(
        vulnerability=vulnerability,
        attack=attack,
        attack_result=attack_result,
        evaluation_result=evaluation_result,
        campaign_name="c1",
    )


def test_is_vulnerable_true_when_evaluation_failed(vulnerability: Vulnerability) -> None:
    finding = _finding(passed=False, vulnerability=vulnerability)

    assert finding.is_vulnerable is True


def test_is_vulnerable_false_when_evaluation_passed(vulnerability: Vulnerability) -> None:
    finding = _finding(passed=True, vulnerability=vulnerability)

    assert finding.is_vulnerable is False


def test_defaults(vulnerability: Vulnerability) -> None:
    finding = _finding(passed=False, vulnerability=vulnerability)

    assert finding.severity == Severity.MEDIUM
    assert finding.status == FindingStatus.OPEN
    assert isinstance(finding.created_at, datetime)
    assert finding.created_at.tzinfo is not None  # must be timezone-aware
    uuid.UUID(finding.id)  # id defaults to a valid uuid4 string


def test_id_is_unique_per_instance(vulnerability: Vulnerability) -> None:
    a = _finding(passed=False, vulnerability=vulnerability)
    b = _finding(passed=False, vulnerability=vulnerability)

    assert a.id != b.id


def test_is_frozen(vulnerability: Vulnerability) -> None:
    finding = _finding(passed=False, vulnerability=vulnerability)

    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.status = FindingStatus.CONFIRMED  # type: ignore[misc]
