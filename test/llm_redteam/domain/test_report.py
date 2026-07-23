"""Report: the immutable, final output of a completed Campaign run."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from llm_redteam.domain.models import (
    Attack,
    AttackResult,
    Finding,
    Report,
    Vulnerability,
)


def _finding(*, passed: bool, vulnerability: Vulnerability, attack_id: str) -> Finding:
    attack = Attack(id=attack_id, vulnerability_id=vulnerability.id, prompt="p")
    attack_result = AttackResult(attack_id=attack_id, target_name="mock", output="sure")
    return Finding(
        vulnerability=vulnerability,
        attack=attack,
        attack_result=attack_result,
        campaign_name="c1",
        passed=passed,
    )


def test_empty_report_has_full_pass_rate() -> None:
    report = Report(
        campaign_name="c1",
        findings=(),
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )

    assert report.total_attacks == 0
    assert report.vulnerable_findings == ()
    assert report.pass_rate == 1.0


def test_pass_rate_and_vulnerable_findings_with_mixed_results(vulnerability: Vulnerability) -> None:
    findings = (
        _finding(passed=False, vulnerability=vulnerability, attack_id="a1"),
        _finding(passed=True, vulnerability=vulnerability, attack_id="a2"),
        _finding(passed=True, vulnerability=vulnerability, attack_id="a3"),
    )
    report = Report(
        campaign_name="c1",
        findings=findings,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )

    assert report.total_attacks == 3
    assert len(report.vulnerable_findings) == 1
    assert report.pass_rate == pytest.approx(2 / 3)


def test_all_vulnerable_gives_zero_pass_rate(vulnerability: Vulnerability) -> None:
    findings = (
        _finding(passed=False, vulnerability=vulnerability, attack_id="a1"),
        _finding(passed=False, vulnerability=vulnerability, attack_id="a2"),
    )
    report = Report(
        campaign_name="c1",
        findings=findings,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )

    assert report.pass_rate == 0.0


def test_is_frozen() -> None:
    report = Report(
        campaign_name="c1",
        findings=(),
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        report.campaign_name = "changed"  # type: ignore[misc]
