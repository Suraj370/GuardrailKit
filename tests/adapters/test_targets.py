"""Target adapters: MockTarget and CallbackTarget are functional; the rest are stubs."""

from __future__ import annotations

import pytest

from llm_redteam_firewall.adapters.targets.callback_target import CallbackTarget
from llm_redteam_firewall.adapters.targets.mock_target import MockTarget
from llm_redteam_firewall.adapters.targets.openai_target import OpenAITarget
from llm_redteam_firewall.domain.errors import TargetExecutionError
from llm_redteam_firewall.domain.models import Attack, ExecutionContext


def _attack() -> Attack:
    return Attack(id="a1", vulnerability_id="v1", prompt="hello")


@pytest.mark.asyncio
async def test_mock_target_returns_canned_response() -> None:
    target = MockTarget(canned_response="no.")
    ctx = ExecutionContext(campaign_name="c1")

    result = await target.execute(ctx, _attack())

    assert result.output == "no."
    assert result.succeeded is True


@pytest.mark.asyncio
async def test_callback_target_wraps_sync_callable() -> None:
    target = CallbackTarget(callback=lambda prompt: f"you said: {prompt}")
    ctx = ExecutionContext(campaign_name="c1")

    result = await target.execute(ctx, _attack())

    assert result.output == "you said: hello"


@pytest.mark.asyncio
async def test_callback_target_wraps_async_callable() -> None:
    async def _callback(prompt: str) -> str:
        return f"async: {prompt}"

    target = CallbackTarget(callback=_callback)
    ctx = ExecutionContext(campaign_name="c1")

    result = await target.execute(ctx, _attack())

    assert result.output == "async: hello"


@pytest.mark.asyncio
async def test_callback_target_wraps_exceptions_as_target_execution_error() -> None:
    def _boom(prompt: str) -> str:
        raise ValueError("nope")

    target = CallbackTarget(callback=_boom)
    ctx = ExecutionContext(campaign_name="c1")

    with pytest.raises(TargetExecutionError):
        await target.execute(ctx, _attack())


@pytest.mark.asyncio
async def test_openai_target_is_a_scaffold_stub() -> None:
    target = OpenAITarget(model="gpt-test")
    ctx = ExecutionContext(campaign_name="c1")

    with pytest.raises(NotImplementedError):
        await target.execute(ctx, _attack())
