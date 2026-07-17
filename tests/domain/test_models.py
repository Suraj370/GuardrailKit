"""Domain models are plain, dependency-free value objects."""

from __future__ import annotations

from llm_redteam_firewall.domain.models import (
    Attack,
    Campaign,
    CampaignResult,
    Evaluation,
    Finding,
    Response,
    Severity,
    Vulnerability,
)


def test_severity_rank_orders_low_to_critical() -> None:
    assert Severity.LOW.rank < Severity.MEDIUM.rank < Severity.HIGH.rank < Severity.CRITICAL.rank


def test_response_succeeded_reflects_error_field() -> None:
    ok = Response(attack_id="a1", target_name="mock", output="hi")
    failed = Response(attack_id="a1", target_name="mock", error="boom")

    assert ok.succeeded is True
    assert failed.succeeded is False


def test_finding_is_vulnerable_when_evaluation_failed(vulnerability: Vulnerability) -> None:
    attack = Attack(id="a1", vulnerability_id=vulnerability.id, prompt="do it")
    response = Response(attack_id="a1", target_name="mock", output="sure, here you go")

    vulnerable_finding = Finding(
        vulnerability=vulnerability,
        attack=attack,
        response=response,
        evaluation=Evaluation(attack_id="a1", passed=False),
        campaign_name="c1",
    )
    safe_finding = Finding(
        vulnerability=vulnerability,
        attack=attack,
        response=response,
        evaluation=Evaluation(attack_id="a1", passed=True),
        campaign_name="c1",
    )

    assert vulnerable_finding.is_vulnerable is True
    assert safe_finding.is_vulnerable is False


def test_campaign_result_pass_rate_and_vulnerable_findings(vulnerability: Vulnerability) -> None:
    attack = Attack(id="a1", vulnerability_id=vulnerability.id, prompt="do it")
    response = Response(attack_id="a1", target_name="mock", output="ok")

    result = CampaignResult(campaign_name="c1")
    assert result.pass_rate == 1.0  # no findings yet -> vacuously "safe"

    result.findings.append(
        Finding(
            vulnerability=vulnerability,
            attack=attack,
            response=response,
            evaluation=Evaluation(attack_id="a1", passed=False),
            campaign_name="c1",
        )
    )
    result.findings.append(
        Finding(
            vulnerability=vulnerability,
            attack=attack,
            response=response,
            evaluation=Evaluation(attack_id="a1", passed=True),
            campaign_name="c1",
        )
    )

    assert len(result.vulnerable_findings) == 1
    assert result.pass_rate == 0.5


def test_campaign_is_immutable(vulnerability: Vulnerability) -> None:
    campaign = Campaign(name="c1", vulnerabilities=(vulnerability,))
    try:
        campaign.name = "changed"  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError("Campaign should be frozen")
