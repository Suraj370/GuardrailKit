"""ExecutionEngine: concurrency-bounded target execution."""

from __future__ import annotations

from unittest.mock import patch

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


class _FlakyTarget:
    """Fails ``fail_times`` calls, then succeeds -- simulates a transient outage."""

    name = "flaky"

    def __init__(self, fail_times: int) -> None:
        self._fail_times = fail_times
        self.calls = 0

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        self.calls += 1
        if self.calls <= self._fail_times:
            raise TargetExecutionError(f"transient failure {self.calls}")
        return AttackResult(attack_id=attack.id, target_name=self.name, output="recovered")


class _CountingFailingTarget:
    name = "counting-failing"

    def __init__(self) -> None:
        self.calls = 0

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        self.calls += 1
        raise TargetExecutionError("always fails")


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
    engine = ExecutionEngine(target=_FailingTarget(), concurrency=2, max_retries=0)

    [result] = await engine.run("campaign-1", _attacks(1))

    assert result.succeeded is False
    assert "simulated failure" in (result.error or "")


@pytest.mark.asyncio
async def test_retries_recover_from_a_transient_failure() -> None:
    target = _FlakyTarget(fail_times=2)
    engine = ExecutionEngine(target=target, concurrency=1, max_retries=2, retry_backoff_seconds=0.0)

    with patch("llm_redteam_firewall.application.execution_engine.asyncio.sleep"):
        [result] = await engine.run("campaign-1", _attacks(1))

    assert result.succeeded is True
    assert result.output == "recovered"
    assert target.calls == 3  # 1 initial attempt + 2 retries


@pytest.mark.asyncio
async def test_retries_are_capped_at_max_retries() -> None:
    target = _CountingFailingTarget()
    engine = ExecutionEngine(target=target, concurrency=1, max_retries=2, retry_backoff_seconds=0.0)

    with patch("llm_redteam_firewall.application.execution_engine.asyncio.sleep"):
        [result] = await engine.run("campaign-1", _attacks(1))

    assert result.succeeded is False
    assert "always fails" in (result.error or "")
    assert target.calls == 3  # 1 initial attempt + 2 retries, then give up


@pytest.mark.asyncio
async def test_no_retries_by_default_config_still_works_with_zero() -> None:
    target = _CountingFailingTarget()
    engine = ExecutionEngine(target=target, concurrency=1, max_retries=0)

    [result] = await engine.run("campaign-1", _attacks(1))

    assert result.succeeded is False
    assert target.calls == 1


@pytest.mark.asyncio
async def test_successful_first_attempt_does_not_retry() -> None:
    target = _FlakyTarget(fail_times=0)
    engine = ExecutionEngine(target=target, concurrency=1, max_retries=2, retry_backoff_seconds=0.0)

    [result] = await engine.run("campaign-1", _attacks(1))

    assert result.succeeded is True
    assert target.calls == 1
