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

from llm_redteam_firewall.domain.models import Campaign, CampaignResult, Finding
from llm_redteam_firewall.domain.ports import AttackGenerator, FindingsStorage, Reporter

from .evaluation_engine import EvaluationEngine
from .execution_engine import ExecutionEngine

logger = logging.getLogger(__name__)


class CampaignOrchestrator:
    """Runs a :class:`Campaign` end to end and returns its result."""

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

    async def run(self, campaign: Campaign) -> CampaignResult:
        result = CampaignResult(campaign_name=campaign.name)

        for vulnerability in campaign.vulnerabilities:
            logger.info("generating attacks for vulnerability=%s", vulnerability.id)
            attacks = self._generator.generate(
                vulnerability, campaign.max_attacks_per_vulnerability
            )
            if not attacks:
                logger.warning("generator produced no attacks for vulnerability=%s", vulnerability.id)
                continue

            responses = await self._execution_engine.run(campaign.name, attacks)
            evaluations = await self._evaluation_engine.run(vulnerability, attacks, responses)

            for attack, response, evaluation in zip(attacks, responses, evaluations, strict=True):
                finding = Finding(
                    vulnerability=vulnerability,
                    attack=attack,
                    response=response,
                    evaluation=evaluation,
                    campaign_name=campaign.name,
                    severity=vulnerability.severity,
                )
                self._storage.save(finding)
                result.findings.append(finding)

        result.finished_at = datetime.now(UTC)

        for reporter in self._reporters:
            reporter.report(result)

        return result
