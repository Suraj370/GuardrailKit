"""ExecutionEngine: runs attacks against a Target with bounded concurrency.

This is deliberately a separate application service from
:class:`~llm_redteam_firewall.application.campaign_orchestrator.CampaignOrchestrator`
so that execution concerns (concurrency, timeouts, retries) can evolve
independently of campaign-level sequencing, and so either can be
tested or reused in isolation.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence

from llm_redteam_firewall.domain.errors import TargetExecutionError
from llm_redteam_firewall.domain.models import Attack, ExecutionContext, Response
from llm_redteam_firewall.domain.ports import Target


class ExecutionEngine:
    """Executes a batch of attacks against a single :class:`Target`.

    Concurrency is bounded by a semaphore rather than firing every
    attack at once, since real targets (hosted LLM APIs) enforce rate
    limits. A failed individual execution is captured as a
    ``Response`` with ``error`` set rather than aborting the batch —
    see :class:`llm_redteam_firewall.domain.errors.TargetExecutionError`.
    """

    def __init__(self, target: Target, concurrency: int = 5, timeout_seconds: float = 30.0) -> None:
        self._target = target
        self._concurrency = concurrency
        self._timeout_seconds = timeout_seconds

    async def run(self, campaign_name: str, attacks: Sequence[Attack]) -> list[Response]:
        """Execute ``attacks`` and return responses in the same order."""
        semaphore = asyncio.Semaphore(self._concurrency)

        async def _run_one(attack: Attack) -> Response:
            async with semaphore:
                ctx = ExecutionContext(
                    campaign_name=campaign_name,
                    timeout_seconds=self._timeout_seconds,
                )
                started = time.perf_counter()
                try:
                    return await asyncio.wait_for(
                        self._target.execute(ctx, attack), timeout=self._timeout_seconds
                    )
                except TargetExecutionError as exc:
                    return Response(
                        attack_id=attack.id,
                        target_name=self._target.name,
                        error=str(exc),
                        latency_ms=(time.perf_counter() - started) * 1000,
                    )
                except TimeoutError:
                    return Response(
                        attack_id=attack.id,
                        target_name=self._target.name,
                        error=f"execution timed out after {self._timeout_seconds}s",
                        latency_ms=(time.perf_counter() - started) * 1000,
                    )

        return list(await asyncio.gather(*(_run_one(attack) for attack in attacks)))
