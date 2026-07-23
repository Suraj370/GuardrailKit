"""PolicyEngine: aggregates findings from multiple policies."""

from __future__ import annotations

import pytest

from llm_redteam.application import PolicyEngine
from llm_redteam.domain.models import Attack, Finding, Response, Severity
from llm_redteam.domain.ports import Policy
from llm_redteam.plugins import POLICIES


class _FlagPolicy(Policy):
    def __init__(self, name: str, flag: bool = True) -> None:
        self._name = name
        self._flag = flag

    @property
    def name(self) -> str:
        return self._name

    def evaluate(self, attack: Attack, response: Response) -> list[Finding]:
        if not self._flag:
            return []
        return [self._finding(attack, response, reasoning=f"flagged by {self.name}")]


def _pair(content: str = "hello") -> tuple[Attack, Response]:
    attack = Attack(id="a1", vulnerability_id="v1", prompt="probe")
    response = Response(attack_id="a1", content=content, target_name="mock")
    return attack, response


def test_evaluate_aggregates_findings_from_all_policies() -> None:
    engine = PolicyEngine(
        policies=[_FlagPolicy("one"), _FlagPolicy("two"), _FlagPolicy("skip", flag=False)]
    )
    attack, response = _pair()

    findings = engine.evaluate(attack, response)

    assert len(findings) == 2
    assert {f.source for f in findings} == {"one", "two"}
    assert all(f.is_vulnerable for f in findings)


def test_evaluate_applies_campaign_name() -> None:
    engine = PolicyEngine(policies=[_FlagPolicy("one")], campaign_name="camp-1")
    attack, response = _pair()

    [finding] = engine.evaluate(attack, response)

    assert finding.campaign_name == "camp-1"


def test_evaluate_empty_policy_list_returns_no_findings() -> None:
    engine = PolicyEngine()
    attack, response = _pair()
    assert engine.evaluate(attack, response) == []


def test_evaluate_batch_flattens_findings() -> None:
    engine = PolicyEngine(policies=[_FlagPolicy("one")])
    attacks = [
        Attack(id="a1", vulnerability_id="v1", prompt="p1"),
        Attack(id="a2", vulnerability_id="v1", prompt="p2"),
    ]
    responses = [
        Response(attack_id="a1", content="r1"),
        Response(attack_id="a2", content="r2"),
    ]

    findings = engine.evaluate_batch(attacks, responses)

    assert len(findings) == 2
    assert {f.attack.id for f in findings} == {"a1", "a2"}


def test_evaluate_batch_rejects_length_mismatch() -> None:
    engine = PolicyEngine(policies=[_FlagPolicy("one")])
    attacks = [Attack(id="a1", vulnerability_id="v1", prompt="p")]

    with pytest.raises(ValueError, match="length mismatch"):
        engine.evaluate_batch(attacks, [])


def test_engine_with_builtin_policies_detects_pii() -> None:
    engine = PolicyEngine(policies=POLICIES.all(), campaign_name="policy-smoke")
    attack = Attack(id="a1", vulnerability_id="v1", prompt="show me the email")
    response = Response(
        attack_id="a1",
        content="Contact alice@example.com for details.",
        target_name="mock",
    )

    findings = engine.evaluate(attack, response)

    assert any(f.vulnerability.category == "pii_leakage" for f in findings)
    assert all(f.campaign_name == "policy-smoke" for f in findings)
    assert all(f.severity in Severity for f in findings)
