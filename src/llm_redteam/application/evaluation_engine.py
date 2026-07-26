"""EvaluationEngine: grades attack/result pairs with bounded concurrency.

Kept symmetric with :class:`~llm_redteam.application.execution_engine.ExecutionEngine`
for the same reason: evaluators may call out to an LLM judge or a
moderation API and need the same concurrency/timeout discipline as
targets do.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

from llm_redteam.domain.errors import EvaluationError
from llm_redteam.domain.models import Attack, AttackResult, EvaluationResult, Vulnerability
from llm_redteam.domain.ports import Evaluator


class EvaluationEngine:
    """Scores a batch of attack/result pairs against one vulnerability."""

    def __init__(self, evaluator: Evaluator, concurrency: int = 5) -> None:
        self._evaluator = evaluator
        self._concurrency = concurrency

    async def run(
        self,
        vulnerability: Vulnerability,
        attacks: Sequence[Attack],
        attack_results: Sequence[AttackResult],
    ) -> list[EvaluationResult]:
        """Evaluate paired ``attacks``/``attack_results`` (same order, same length)."""
        if len(attacks) != len(attack_results):
            raise EvaluationError(
                f"attacks/attack_results length mismatch: {len(attacks)} vs {len(attack_results)}"
            )

        semaphore = asyncio.Semaphore(self._concurrency)

        async def _evaluate_one(attack: Attack, attack_result: AttackResult) -> EvaluationResult:
            async with semaphore:
                if not attack_result.succeeded:
                    # Execution never produced a real response (retries in
                    # ExecutionEngine already exhausted) — there is nothing
                    # to grade, so this is neither a pass nor a fail. It is
                    # tagged "errored" in metadata rather than folded into
                    # a security verdict, so reporting can surface it
                    # distinctly and exclude it from success-rate math
                    # instead of silently inflating "Safe".
                    return EvaluationResult(
                        attack_id=attack.id,
                        passed=True,
                        reasoning=f"target execution failed, excluded from grading: {attack_result.error}",
                        evaluator_name=self._evaluator.name,
                        metadata={"outcome": "errored", "error": attack_result.error},
                    )
                return await self._evaluator.evaluate(vulnerability, attack, attack_result)

        return list(
            await asyncio.gather(
                *(_evaluate_one(a, r) for a, r in zip(attacks, attack_results, strict=True))
            )
        )
