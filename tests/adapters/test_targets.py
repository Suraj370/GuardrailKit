"""Target adapters: MockTarget, CallbackTarget, and OpenAITarget are functional; the rest are stubs."""

from __future__ import annotations

import sys
import types
from unittest.mock import AsyncMock, patch

import pytest

from llm_redteam.adapters.targets.callback_target import CallbackTarget
from llm_redteam.adapters.targets.mock_target import MockTarget
from llm_redteam.adapters.targets.openai_target import OpenAINotInstalledError, OpenAITarget
from llm_redteam.domain.models import Attack, ExecutionContext


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
    assert result.succeeded is True
    assert result.error is None


@pytest.mark.asyncio
async def test_callback_target_wraps_async_callable() -> None:
    async def _callback(prompt: str) -> str:
        return f"async: {prompt}"

    target = CallbackTarget(callback=_callback)
    ctx = ExecutionContext(campaign_name="c1")

    result = await target.execute(ctx, _attack())

    assert result.output == "async: hello"
    assert result.succeeded is True


@pytest.mark.asyncio
async def test_callback_target_populates_attack_result_fields() -> None:
    target = CallbackTarget(callback=lambda prompt: f"echo: {prompt}", name="my-model")
    attack = _attack()
    ctx = ExecutionContext(campaign_name="c1")

    result = await target.execute(ctx, attack)

    assert result.attack_id == attack.id
    assert result.target_name == "my-model"
    assert result.output == "echo: hello"
    assert result.error is None
    assert result.raw == {"return_type": "str"}
    assert result.latency_ms >= 0.0


@pytest.mark.asyncio
async def test_callback_target_defaults_name_to_callback() -> None:
    target = CallbackTarget(callback=lambda prompt: prompt)

    assert target.name == "callback"


@pytest.mark.asyncio
async def test_callback_target_catches_sync_exceptions_without_raising() -> None:
    def _boom(prompt: str) -> str:
        raise ValueError("nope")

    target = CallbackTarget(callback=_boom, name="flaky")
    attack = _attack()
    ctx = ExecutionContext(campaign_name="c1")

    result = await target.execute(ctx, attack)

    assert result.attack_id == attack.id
    assert result.target_name == "flaky"
    assert result.output == ""
    assert result.succeeded is False
    assert result.error is not None
    assert "ValueError" in result.error
    assert "nope" in result.error
    assert result.raw == {"exception_type": "ValueError"}


@pytest.mark.asyncio
async def test_callback_target_catches_async_exceptions_without_raising() -> None:
    async def _boom(prompt: str) -> str:
        raise RuntimeError("async nope")

    target = CallbackTarget(callback=_boom)
    ctx = ExecutionContext(campaign_name="c1")

    result = await target.execute(ctx, _attack())

    assert result.succeeded is False
    assert "RuntimeError" in result.error
    assert result.raw == {"exception_type": "RuntimeError"}


@pytest.mark.asyncio
async def test_callback_target_measures_latency_on_success() -> None:
    times = iter([10.0, 10.25])

    def _fake_perf_counter() -> float:
        return next(times)

    target = CallbackTarget(callback=lambda prompt: "ok")
    ctx = ExecutionContext(campaign_name="c1")

    with patch("llm_redteam.adapters.targets.callback_target.time.perf_counter", _fake_perf_counter):
        result = await target.execute(ctx, _attack())

    assert result.latency_ms == pytest.approx(250.0)


@pytest.mark.asyncio
async def test_callback_target_measures_latency_on_error() -> None:
    times = iter([5.0, 5.1])

    def _fake_perf_counter() -> float:
        return next(times)

    def _boom(prompt: str) -> str:
        raise ValueError("nope")

    target = CallbackTarget(callback=_boom)
    ctx = ExecutionContext(campaign_name="c1")

    with patch("llm_redteam.adapters.targets.callback_target.time.perf_counter", _fake_perf_counter):
        result = await target.execute(ctx, _attack())

    assert result.latency_ms == pytest.approx(100.0)


@pytest.mark.asyncio
async def test_callback_target_stringifies_non_string_return_values() -> None:
    target = CallbackTarget(callback=lambda prompt: 42)
    ctx = ExecutionContext(campaign_name="c1")

    result = await target.execute(ctx, _attack())

    assert result.output == "42"
    assert result.raw == {"return_type": "int"}


@pytest.mark.asyncio
async def test_openai_target_returns_output_text() -> None:
    target = OpenAITarget(model="gpt-test", api_key="test-key")
    target._client.responses.create = AsyncMock(
        return_value=types.SimpleNamespace(output_text="hi there")
    )
    attack = _attack()
    ctx = ExecutionContext(campaign_name="c1")

    result = await target.execute(ctx, attack)

    assert result.attack_id == attack.id
    assert result.target_name == "openai"
    assert result.output == "hi there"
    assert result.succeeded is True
    assert result.error is None
    assert result.raw == {"model": "gpt-test"}
    assert result.latency_ms >= 0.0
    target._client.responses.create.assert_awaited_once_with(model="gpt-test", input="hello")


@pytest.mark.asyncio
async def test_openai_target_uses_custom_name() -> None:
    target = OpenAITarget(model="gpt-test", api_key="test-key", name="prod-openai")

    assert target.name == "prod-openai"


@pytest.mark.asyncio
async def test_openai_target_catches_sdk_exceptions_without_raising() -> None:
    target = OpenAITarget(model="gpt-test", api_key="test-key")
    target._client.responses.create = AsyncMock(side_effect=RuntimeError("rate limited"))
    attack = _attack()
    ctx = ExecutionContext(campaign_name="c1")

    result = await target.execute(ctx, attack)

    assert result.attack_id == attack.id
    assert result.output == ""
    assert result.succeeded is False
    assert result.error is not None
    assert "RuntimeError" in result.error
    assert "rate limited" in result.error
    assert result.raw == {"exception_type": "RuntimeError", "model": "gpt-test"}


@pytest.mark.asyncio
async def test_openai_target_measures_latency_on_success() -> None:
    times = iter([10.0, 10.3])

    def _fake_perf_counter() -> float:
        return next(times)

    target = OpenAITarget(model="gpt-test", api_key="test-key")
    target._client.responses.create = AsyncMock(
        return_value=types.SimpleNamespace(output_text="ok")
    )
    ctx = ExecutionContext(campaign_name="c1")

    with patch("llm_redteam.adapters.targets.openai_target.time.perf_counter", _fake_perf_counter):
        result = await target.execute(ctx, _attack())

    assert result.latency_ms == pytest.approx(300.0)


@pytest.mark.asyncio
async def test_openai_target_measures_latency_on_error() -> None:
    times = iter([2.0, 2.2])

    def _fake_perf_counter() -> float:
        return next(times)

    target = OpenAITarget(model="gpt-test", api_key="test-key")
    target._client.responses.create = AsyncMock(side_effect=RuntimeError("boom"))
    ctx = ExecutionContext(campaign_name="c1")

    with patch("llm_redteam.adapters.targets.openai_target.time.perf_counter", _fake_perf_counter):
        result = await target.execute(ctx, _attack())

    assert result.latency_ms == pytest.approx(200.0)


def test_openai_target_raises_clear_error_when_sdk_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "openai", None)

    with pytest.raises(OpenAINotInstalledError):
        OpenAITarget(model="gpt-test", api_key="test-key")
