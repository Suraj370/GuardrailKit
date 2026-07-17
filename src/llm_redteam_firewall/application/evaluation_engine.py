"""EvaluationEngine: grades attack/response pairs with bounded concurrency.

Kept symmetric with :class:`~llm_redteam_firewall.application.execution_engine.ExecutionEngine`
for the same reason: evaluators may call out to an LLM judge or a
moderation API and need the same concurrency/timeout discipline as
targets do.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

from llm_redteam_firewall.domain.errors import EvaluationError
from llm_redteam_firewall.domain.models import Attack, Evaluation, Response, Vulnerability
from llm_redteam_firewall.domain.ports import Evaluator


class EvaluationEngine:
    """Scores a batch of attack/response pairs against one vulnerability."""

    def __init__(self, evaluator: Evaluator, concurrency: int = 5) -> None:
        self._evaluator = evaluator
        self._concurrency = concurrency

    async def run(
        self,
        vulnerability: Vulnerability,
        attacks: Sequence[Attack],
        responses: Sequence[Response],
    ) -> list[Evaluation]:
        """Evaluate paired ``attacks``/``responses`` (same order, same length)."""
        if len(attacks) != len(responses):
            raise EvaluationError(
                f"attacks/responses length mismatch: {len(attacks)} vs {len(responses)}"
            )

        semaphore = asyncio.Semaphore(self._concurrency)

        async def _evaluate_one(attack: Attack, response: Response) -> Evaluation:
            async with semaphore:
                if not response.succeeded:
                    return Evaluation(
                        attack_id=attack.id,
                        passed=True,
                        reasoning=f"target execution failed, treated as non-vulnerable: {response.error}",
                        evaluator_name=self._evaluator.name,
                    )
                return await self._evaluator.evaluate(vulnerability, attack, response)

        return list(
            await asyncio.gather(
                *(_evaluate_one(a, r) for a, r in zip(attacks, responses, strict=True))
            )
        )
