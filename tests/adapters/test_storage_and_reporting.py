"""Storage and reporting adapters."""

from __future__ import annotations

import json

from llm_redteam_firewall.adapters.reporting.console_reporter import ConsoleReporter
from llm_redteam_firewall.adapters.reporting.json_reporter import JSONReporter
from llm_redteam_firewall.adapters.storage.in_memory_storage import InMemoryStorage
from llm_redteam_firewall.domain.models import (
    Attack,
    CampaignResult,
    Evaluation,
    Finding,
    Response,
    Vulnerability,
)


def _finding(vulnerability: Vulnerability, campaign_name: str) -> Finding:
    attack = Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")
    response = Response(attack_id="a1", target_name="mock", output="sure")
    evaluation = Evaluation(attack_id="a1", passed=False)
    return Finding(vulnerability=vulnerability, attack=attack, response=response, evaluation=evaluation, campaign_name=campaign_name)


def test_in_memory_storage_saves_and_filters_by_campaign(vulnerability: Vulnerability) -> None:
    storage = InMemoryStorage()
    storage.save(_finding(vulnerability, "c1"))
    storage.save(_finding(vulnerability, "c2"))

    assert len(storage.list()) == 2
    assert len(storage.list(campaign_name="c1")) == 1


def test_console_reporter_does_not_raise(vulnerability: Vulnerability, capsys: object) -> None:
    result = CampaignResult(campaign_name="c1", findings=[_finding(vulnerability, "c1")])

    ConsoleReporter().report(result)  # smoke test: must not raise


def test_json_reporter_writes_valid_json(tmp_path, vulnerability: Vulnerability) -> None:
    output_path = tmp_path / "results.json"
    result = CampaignResult(campaign_name="c1", findings=[_finding(vulnerability, "c1")])

    JSONReporter(output_path=str(output_path)).report(result)

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["campaign_name"] == "c1"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["evaluation"]["passed"] is False
