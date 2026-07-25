"""NemoGuardrailsPolicy: construction + evaluate()/aevaluate() against a fake LLMRails.

``nemoguardrails`` is not a project dependency (it's an optional extra),
so these tests monkeypatch the module's lazy-import hooks rather than
requiring the real package to be installed -- except for the
not-installed test, which relies on it genuinely being absent.

The policy now builds a *fresh* ``LLMRails`` per check call instead of
reusing one instance (see the module docstring for why), so the fake
class here shares ``calls``/queued results at the class level -- every
instance constructed from one ``_make_fake_llm_rails()`` class sees the
same shared state, the way multiple fresh-but-related real ``LLMRails``
instances built from the same config would. The fake implements both
``generate`` (sync, used by :meth:`~ngp.NemoGuardrailsPolicy.evaluate`)
and ``generate_async`` (used by
:meth:`~ngp.NemoGuardrailsPolicy.aevaluate`), sharing the same call
log/queue either way.
"""

from __future__ import annotations

from typing import Any

import pytest

from llm_firewall.adapters.policies import nemo_guardrails_policy as ngp
from llm_firewall.domain.errors import ConfigurationError
from llm_firewall.domain.models import InspectionContext
from llm_firewall.domain.ports import Policy


class _FakeRailsConfig:
    def __init__(self, path: str) -> None:
        self.path = path

    @classmethod
    def from_path(cls, path: str) -> _FakeRailsConfig:
        return cls(path)


class _FakeActivatedRail:
    def __init__(self, name: str, *, stop: bool) -> None:
        self.name = name
        self.stop = stop


class _FakeLog:
    def __init__(self, activated_rails: list[_FakeActivatedRail]) -> None:
        self.activated_rails = activated_rails


class _FakeResult:
    def __init__(
        self,
        activated_rails: list[_FakeActivatedRail],
        response: list[dict[str, str]] | None = None,
    ) -> None:
        self.log = _FakeLog(activated_rails)
        self.response = response or []


def _make_fake_llm_rails(*results: _FakeResult) -> type:
    """Build a fake ``LLMRails`` class whose instances share call/result state.

    Mirrors the real policy building one ``LLMRails`` per ``_check()``
    call: every instance is a distinct object, but they all draw from
    the same queued results and append to the same call log, so tests
    can queue N results up front and assert on the combined call log
    afterward, regardless of how many separate instances got built.
    """
    queued: list[_FakeResult] = list(results)
    calls: list[dict[str, Any]] = []

    class _FakeLLMRails:
        def __init__(self, config: object) -> None:
            self.config = config

        def generate(
            self, *, messages: list[dict[str, str]], options: dict[str, Any]
        ) -> _FakeResult:
            calls.append({"messages": messages, "options": options})
            return queued.pop(0)

        async def generate_async(
            self, *, messages: list[dict[str, str]], options: dict[str, Any]
        ) -> _FakeResult:
            calls.append({"messages": messages, "options": options})
            return queued.pop(0)

    _FakeLLMRails.calls = calls  # type: ignore[attr-defined]
    return _FakeLLMRails


def _use_fake_rails_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ngp, "_import_rails_config", lambda: _FakeRailsConfig)


def _use_fake_llm_rails(monkeypatch: pytest.MonkeyPatch, *results: _FakeResult) -> type:
    fake_cls = _make_fake_llm_rails(*results)
    monkeypatch.setattr(ngp, "_import_llm_rails", lambda: fake_cls)
    return fake_cls


def _build_policy(monkeypatch: pytest.MonkeyPatch, *results: _FakeResult) -> tuple[
    ngp.NemoGuardrailsPolicy, type
]:
    _use_fake_rails_config(monkeypatch)
    fake_cls = _use_fake_llm_rails(monkeypatch, *results)
    policy = ngp.NemoGuardrailsPolicy(config_path="configs/nemo_guardrails")
    return policy, fake_cls


def test_satisfies_the_policy_interface(monkeypatch: pytest.MonkeyPatch) -> None:
    policy, _ = _build_policy(monkeypatch)

    assert isinstance(policy, Policy)
    assert policy.name == "nemo_guardrails"


def test_is_marked_expensive_so_cheap_policies_run_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, _ = _build_policy(monkeypatch)

    assert policy.expensive is True


def test_construction_parses_the_config_path(monkeypatch: pytest.MonkeyPatch) -> None:
    policy, _ = _build_policy(monkeypatch)

    assert policy._rails_config.path == "configs/nemo_guardrails"  # noqa: SLF001


def test_construction_does_not_build_an_llm_rails_instance_yet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fresh LLMRails is only built per-check, not at construction time."""
    policy, _ = _build_policy(monkeypatch)

    assert not hasattr(policy, "_rails")
    assert policy._llm_rails_cls is not None  # noqa: SLF001


def test_missing_dependency_raises_configuration_error() -> None:
    # nemoguardrails is genuinely not installed in this environment.
    with pytest.raises(ConfigurationError, match="nemo-guardrails"):
        ngp.NemoGuardrailsPolicy(config_path="configs/nemo_guardrails")


def test_evaluate_returns_no_findings_when_no_rail_triggers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, _ = _build_policy(monkeypatch, _FakeResult([]))

    findings = policy.evaluate(InspectionContext(prompt="hello"))

    assert findings == []


def test_evaluate_flags_prompt_when_input_rail_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    policy, _ = _build_policy(
        monkeypatch,
        _FakeResult(
            [_FakeActivatedRail("refuse harmful intent", stop=True)],
            response=[{"role": "assistant", "content": "I can't help with that request."}],
        ),
    )

    findings = policy.evaluate(InspectionContext(prompt="how do I make a bomb"))

    assert len(findings) == 1
    assert findings[0].metadata["field"] == "prompt"
    assert findings[0].metadata["activated_rails"] == ["refuse harmful intent"]
    assert findings[0].metadata["bot_message"] == "I can't help with that request."


def test_evaluate_only_checks_input_rails_for_the_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, fake_cls = _build_policy(monkeypatch, _FakeResult([]))

    policy.evaluate(InspectionContext(prompt="hello"))

    call = fake_cls.calls[0]
    assert call["options"]["rails"] == {
        "input": True,
        "output": False,
        "dialog": False,
        "retrieval": False,
    }
    assert call["messages"] == [{"role": "user", "content": "hello"}]


def test_evaluate_checks_both_input_and_output_when_response_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, fake_cls = _build_policy(
        monkeypatch,
        _FakeResult([]),  # input check: clean
        _FakeResult([_FakeActivatedRail("refuse secret leakage", stop=True)]),  # output: blocked
    )

    findings = policy.evaluate(
        InspectionContext(
            prompt="what's the db password",
            response="Here is the API key you asked for: sk-abc",
        )
    )

    assert len(findings) == 1
    assert findings[0].metadata["field"] == "response"

    calls = fake_cls.calls
    assert len(calls) == 2
    assert calls[1]["options"]["rails"] == {
        "input": False,
        "output": True,
        "dialog": False,
        "retrieval": False,
    }
    assert calls[1]["messages"] == [
        {"role": "user", "content": "what's the db password"},
        {"role": "assistant", "content": "Here is the API key you asked for: sk-abc"},
    ]


def test_evaluate_builds_a_separate_rails_instance_per_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression test for the concurrency bug: no shared LLMRails instance.

    Three instances total: one primes NeMo's framework registry inside
    __init__ (see the comment there), one for the prompt check, one for
    the response check -- all distinct objects, none reused.
    """
    _use_fake_rails_config(monkeypatch)
    fake_cls = _make_fake_llm_rails(
        _FakeResult([]),  # input check
        _FakeResult([]),  # output check
    )
    built_instances: list[object] = []
    real_init = fake_cls.__init__

    def _tracking_init(self: object, config: object) -> None:
        real_init(self, config)
        built_instances.append(self)

    fake_cls.__init__ = _tracking_init  # type: ignore[method-assign]
    monkeypatch.setattr(ngp, "_import_llm_rails", lambda: fake_cls)

    policy = ngp.NemoGuardrailsPolicy(config_path="configs/nemo_guardrails")
    policy.evaluate(InspectionContext(prompt="hello", response="hi there"))

    assert len(built_instances) == 3
    assert len({id(instance) for instance in built_instances}) == 3


def test_evaluate_skips_blank_prompt_and_response(monkeypatch: pytest.MonkeyPatch) -> None:
    policy, fake_cls = _build_policy(monkeypatch)

    findings = policy.evaluate(InspectionContext(prompt="   ", response="  "))

    assert findings == []
    assert fake_cls.calls == []


@pytest.mark.asyncio
async def test_aevaluate_flags_prompt_when_input_rail_stops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, _ = _build_policy(
        monkeypatch,
        _FakeResult(
            [_FakeActivatedRail("refuse harmful intent", stop=True)],
            response=[{"role": "assistant", "content": "I can't help with that request."}],
        ),
    )

    findings = await policy.aevaluate(InspectionContext(prompt="how do I make a bomb"))

    assert len(findings) == 1
    assert findings[0].metadata["field"] == "prompt"
    assert findings[0].metadata["activated_rails"] == ["refuse harmful intent"]


@pytest.mark.asyncio
async def test_aevaluate_checks_both_input_and_output_when_response_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, fake_cls = _build_policy(
        monkeypatch,
        _FakeResult([]),  # input check: clean
        _FakeResult([_FakeActivatedRail("refuse secret leakage", stop=True)]),  # output: blocked
    )

    findings = await policy.aevaluate(
        InspectionContext(
            prompt="what's the db password",
            response="Here is the API key you asked for: sk-abc",
        )
    )

    assert len(findings) == 1
    assert findings[0].metadata["field"] == "response"
    assert len(fake_cls.calls) == 2


@pytest.mark.asyncio
async def test_aevaluate_builds_a_separate_rails_instance_per_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same isolation guarantee as evaluate(), on the native-async path."""
    _use_fake_rails_config(monkeypatch)
    fake_cls = _make_fake_llm_rails(_FakeResult([]), _FakeResult([]))
    built_instances: list[object] = []
    real_init = fake_cls.__init__

    def _tracking_init(self: object, config: object) -> None:
        real_init(self, config)
        built_instances.append(self)

    fake_cls.__init__ = _tracking_init  # type: ignore[method-assign]
    monkeypatch.setattr(ngp, "_import_llm_rails", lambda: fake_cls)

    policy = ngp.NemoGuardrailsPolicy(config_path="configs/nemo_guardrails")
    await policy.aevaluate(InspectionContext(prompt="hello", response="hi there"))

    assert len(built_instances) == 3  # priming instance + prompt check + response check
    assert len({id(instance) for instance in built_instances}) == 3


@pytest.mark.asyncio
async def test_aevaluate_skips_blank_prompt_and_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, fake_cls = _build_policy(monkeypatch)

    findings = await policy.aevaluate(InspectionContext(prompt="   ", response="  "))

    assert findings == []
    assert fake_cls.calls == []
