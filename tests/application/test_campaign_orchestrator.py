"""CampaignOrchestrator: wiring test using fakes for every port.

Verifies the orchestration *sequence* (generate -> execute -> evaluate
-> store -> report) rather than any grading logic, which belongs to
adapters, not this layer.
"""

from __future__ import annotations

import pytest

from llm_redteam_firewall.application import CampaignOrchestrator, EvaluationEngine, ExecutionEngine
from llm_redteam_firewall.domain.models import (
    Attack,
    Campaign,
    CampaignResult,
    Evaluation,
    ExecutionContext,
    Finding,
    Response,
    Vulnerability,
)


class _FakeGenerator:
    name = "fake"

    def generate(self, vulnerability: Vulnerability, max_attacks: int) -> list[Attack]:
        return [
            Attack(id=f"{vulnerability.id}-{i}", vulnerability_id=vulnerability.id, prompt="p")
            for i in range(max_attacks)
        ]


class _FakeTarget:
    name = "fake"

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> Response:
        return Response(attack_id=attack.id, target_name=self.name, output="response")


class _FakeEvaluator:
    name = "fake"

    async def evaluate(self, vulnerability, attack: Attack, response: Response) -> Evaluation:
        return Evaluation(attack_id=attack.id, passed=False, evaluator_name=self.name)


class _FakeStorage:
    name = "fake"

    def __init__(self) -> None:
        self.saved: list[Finding] = []

    def save(self, finding: Finding) -> None:
        self.saved.append(finding)

    def list(self, campaign_name: str | None = None) -> list[Finding]:
        return list(self.saved)


class _FakeReporter:
    name = "fake"

    def __init__(self) -> None:
        self.reported: CampaignResult | None = None

    def report(self, result: CampaignResult) -> None:
        self.reported = result


@pytest.mark.asyncio
async def test_orchestrator_runs_full_pipeline_and_reports(vulnerability: Vulnerability) -> None:
    storage = _FakeStorage()
    reporter = _FakeReporter()
    orchestrator = CampaignOrchestrator(
        generator=_FakeGenerator(),
        execution_engine=ExecutionEngine(target=_FakeTarget()),
        evaluation_engine=EvaluationEngine(evaluator=_FakeEvaluator()),
        storage=storage,
        reporters=[reporter],
    )
    campaign = Campaign(name="c1", vulnerabilities=(vulnerability,), max_attacks_per_vulnerability=2)

    result = await orchestrator.run(campaign)

    assert result.campaign_name == "c1"
    assert result.total_attacks == 2
    assert len(result.vulnerable_findings) == 2  # _FakeEvaluator always fails the target
    assert len(storage.saved) == 2
    assert reporter.reported is result
    assert result.finished_at is not None
