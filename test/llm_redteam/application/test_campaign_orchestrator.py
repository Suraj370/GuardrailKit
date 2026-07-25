"""CampaignOrchestrator: wiring test using fakes for every port.

Verifies the orchestration *sequence* (generate -> execute -> evaluate
-> store -> report) rather than any grading logic, which belongs to
adapters, not this layer.
"""

from __future__ import annotations

import pytest

from llm_redteam.application import CampaignOrchestrator, EvaluationEngine, ExecutionEngine
from llm_redteam.domain.models import (
    Attack,
    AttackResult,
    Campaign,
    EvaluationResult,
    ExecutionContext,
    Finding,
    Report,
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

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        return AttackResult(attack_id=attack.id, target_name=self.name, output="response")


class _FakeEvaluator:
    name = "fake"

    async def evaluate(
        self, vulnerability, attack: Attack, attack_result: AttackResult
    ) -> EvaluationResult:
        return EvaluationResult(attack_id=attack.id, passed=False, evaluator_name=self.name)


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
        self.reported: Report | None = None

    def report(self, report: Report) -> None:
        self.reported = report


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
    campaign = Campaign(
        name="c1", vulnerabilities=(vulnerability,), max_attacks_per_vulnerability=2
    )

    report = await orchestrator.run(campaign)

    assert report.campaign_name == "c1"
    assert report.total_attacks == 2
    assert len(report.vulnerable_findings) == 2  # _FakeEvaluator always fails the target
    assert len(storage.saved) == 2
    assert reporter.reported is report
    assert report.finished_at >= report.started_at
