"""CampaignOrchestrator: the top-level use case that ties everything together.

This is the only class in the framework that knows the *shape* of a
full campaign run (generate -> execute -> evaluate -> store -> report).
It depends exclusively on domain ports and the two engine services —
never on a concrete generator, target, evaluator, storage backend, or
reporter. Which concrete adapters are plugged in is decided entirely
by the composition root in :mod:`llm_redteam_firewall.config.loader`.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime

from llm_redteam_firewall.domain.campaigns import AttackCampaign
from llm_redteam_firewall.domain.models import Campaign, Finding, Report
from llm_redteam_firewall.domain.ports import AttackGenerator, FindingsStorage, Reporter

from .evaluation_engine import EvaluationEngine
from .execution_engine import ExecutionEngine

logger = logging.getLogger(__name__)


class CampaignOrchestrator:
    """Runs a :class:`Campaign` end to end and returns its :class:`Report`.

    ``Report`` is immutable, so unlike a mutable "result" object it
    cannot be built incrementally: findings are accumulated in a plain
    local list while the campaign runs, and exactly one ``Report`` is
    constructed once every vulnerability has been processed.
    """

    def __init__(
        self,
        generator: AttackGenerator,
        execution_engine: ExecutionEngine,
        evaluation_engine: EvaluationEngine,
        storage: FindingsStorage,
        reporters: Sequence[Reporter] = (),
    ) -> None:
        self._generator = generator
        self._execution_engine = execution_engine
        self._evaluation_engine = evaluation_engine
        self._storage = storage
        self._reporters = tuple(reporters)

    async def run(self, campaign: Campaign) -> Report:
        started_at = datetime.now(UTC)
        findings: list[Finding] = []

        for vulnerability in campaign.vulnerabilities:
            logger.info("generating attacks for vulnerability=%s", vulnerability.id)
            generated_attacks = self._generator.generate(
                vulnerability, campaign.max_attacks_per_vulnerability
            )
            if not generated_attacks:
                logger.warning("generator produced no attacks for vulnerability=%s", vulnerability.id)
                continue

            # Wrap the generator's flat output in an AttackCampaign so the
            # orchestrator iterates the planning layer rather than the raw
            # list directly. from_attacks() puts every attack in a single
            # AttackBatch, so this loop runs once per vulnerability with the
            # exact same attacks, in the exact same order, as before —
            # no behavior change, only the intermediate abstraction.
            attack_campaign = AttackCampaign.from_attacks(campaign.name, generated_attacks)

            for batch in attack_campaign:
                batch_attacks = batch.attacks
                attack_results = await self._execution_engine.run(campaign.name, batch_attacks)
                evaluation_results = await self._evaluation_engine.run(
                    vulnerability, batch_attacks, attack_results
                )

                for attack, attack_result, evaluation_result in zip(
                    batch_attacks, attack_results, evaluation_results, strict=True
                ):
                    finding = Finding(
                        vulnerability=vulnerability,
                        attack=attack,
                        attack_result=attack_result,
                        campaign_name=campaign.name,
                        passed=evaluation_result.passed,
                        severity=vulnerability.severity,
                        reasoning=evaluation_result.reasoning,
                        score=evaluation_result.score,
                        source=evaluation_result.evaluator_name,
                        metadata=dict(evaluation_result.metadata),
                    )
                    self._storage.save(finding)
                    findings.append(finding)

        report = Report(
            campaign_name=campaign.name,
            findings=tuple(findings),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )

        for reporter in self._reporters:
            reporter.report(report)

        return report
