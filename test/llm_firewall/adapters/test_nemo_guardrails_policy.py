"""NemoGuardrailsPolicy: construction + evaluate() against a fake LLMRails.

``nemoguardrails`` is not a project dependency (it's an optional extra),
so these tests monkeypatch the module's lazy-import hooks rather than
requiring the real package to be installed -- except for the
not-installed test, which relies on it genuinely being absent.
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


class _FakeLLMRails:
    """Records every ``generate`` call and returns queued results in order."""

    def __init__(self, config: object) -> None:
        self.config = config
        self.calls: list[dict[str, Any]] = []
        self._results: list[_FakeResult] = []

    def queue(self, *results: _FakeResult) -> None:
        self._results.extend(results)

    def generate(
        self, *, messages: list[dict[str, str]], options: dict[str, Any]
    ) -> _FakeResult:
        self.calls.append({"messages": messages, "options": options})
        return self._results.pop(0)


def _use_fake_rails_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ngp, "_import_rails_config", lambda: _FakeRailsConfig)


def _use_fake_llm_rails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ngp, "_import_llm_rails", lambda: _FakeLLMRails)


def _build_policy(monkeypatch: pytest.MonkeyPatch) -> ngp.NemoGuardrailsPolicy:
    _use_fake_rails_config(monkeypatch)
    _use_fake_llm_rails(monkeypatch)
    return ngp.NemoGuardrailsPolicy(config_path="configs/nemo_guardrails")


def test_satisfies_the_policy_interface(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _build_policy(monkeypatch)

    assert isinstance(policy, Policy)
    assert policy.name == "nemo_guardrails"


def test_is_marked_expensive_so_cheap_policies_run_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _build_policy(monkeypatch)

    assert policy.expensive is True


def test_construction_parses_the_config_path(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _build_policy(monkeypatch)

    assert policy._rails_config.path == "configs/nemo_guardrails"  # noqa: SLF001


def test_missing_dependency_raises_configuration_error() -> None:
    # nemoguardrails is genuinely not installed in this environment.
    with pytest.raises(ConfigurationError, match="nemo-guardrails"):
        ngp.NemoGuardrailsPolicy(config_path="configs/nemo_guardrails")


def test_evaluate_returns_no_findings_when_no_rail_triggers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _build_policy(monkeypatch)
    policy._rails.queue(_FakeResult([]))  # noqa: SLF001

    findings = policy.evaluate(InspectionContext(prompt="hello"))

    assert findings == []


def test_evaluate_flags_prompt_when_input_rail_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _build_policy(monkeypatch)
    policy._rails.queue(  # noqa: SLF001
        _FakeResult(
            [_FakeActivatedRail("refuse harmful intent", stop=True)],
            response=[{"role": "assistant", "content": "I can't help with that request."}],
        )
    )

    findings = policy.evaluate(InspectionContext(prompt="how do I make a bomb"))

    assert len(findings) == 1
    assert findings[0].metadata["field"] == "prompt"
    assert findings[0].metadata["activated_rails"] == ["refuse harmful intent"]
    assert findings[0].metadata["bot_message"] == "I can't help with that request."


def test_evaluate_only_checks_input_rails_for_the_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _build_policy(monkeypatch)
    policy._rails.queue(_FakeResult([]))  # noqa: SLF001

    policy.evaluate(InspectionContext(prompt="hello"))

    call = policy._rails.calls[0]  # noqa: SLF001
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
    policy = _build_policy(monkeypatch)
    policy._rails.queue(  # noqa: SLF001
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

    calls = policy._rails.calls  # noqa: SLF001
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


def test_evaluate_skips_blank_prompt_and_response(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _build_policy(monkeypatch)

    findings = policy.evaluate(InspectionContext(prompt="   ", response="  "))

    assert findings == []
    assert policy._rails.calls == []  # noqa: SLF001
