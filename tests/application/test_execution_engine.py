"""ExecutionEngine: concurrency-bounded target execution."""

from __future__ import annotations

import pytest

from llm_redteam_firewall.application import ExecutionEngine
from llm_redteam_firewall.domain.errors import TargetExecutionError
from llm_redteam_firewall.domain.models import Attack, AttackResult, ExecutionContext


class _EchoTarget:
    name = "echo"

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        return AttackResult(attack_id=attack.id, target_name=self.name, output=f"echo: {attack.prompt}")


class _FailingTarget:
    name = "failing"

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        raise TargetExecutionError("simulated failure")


def _attacks(n: int) -> list[Attack]:
    return [Attack(id=f"a{i}", vulnerability_id="v1", prompt=f"prompt {i}") for i in range(n)]


@pytest.mark.asyncio
async def test_run_preserves_order_and_maps_output() -> None:
    engine = ExecutionEngine(target=_EchoTarget(), concurrency=2)
    attacks = _attacks(4)

    results = await engine.run("campaign-1", attacks)

    assert [r.attack_id for r in results] == [a.id for a in attacks]
    assert results[0].output == "echo: prompt 0"


@pytest.mark.asyncio
async def test_target_execution_error_becomes_error_result() -> None:
    engine = ExecutionEngine(target=_FailingTarget(), concurrency=2)

    [result] = await engine.run("campaign-1", _attacks(1))

    assert result.succeeded is False
    assert "simulated failure" in (result.error or "")
