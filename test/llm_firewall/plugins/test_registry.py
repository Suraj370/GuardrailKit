"""PolicyRegistry: multi-policy instance collection."""

from __future__ import annotations

import pytest

from llm_firewall.domain.errors import PluginNotFoundError
from llm_firewall.domain.models import Finding, InspectionContext
from llm_firewall.domain.ports import Policy
from llm_firewall.plugins import POLICIES
from llm_firewall.plugins.registry import PolicyRegistry


class _NamedPolicy(Policy):
    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def evaluate(self, context: InspectionContext) -> list[Finding]:
        return []


def test_add_and_get() -> None:
    registry = PolicyRegistry()
    policy = _NamedPolicy("alpha")
    registry.add(policy)

    assert registry.get("alpha") is policy
    assert "alpha" in registry
    assert len(registry) == 1
    assert registry.names() == ["alpha"]


def test_register_decorator_instantiates() -> None:
    registry = PolicyRegistry()

    @registry.register
    class _Decorated(Policy):
        name = "decorated"

        def evaluate(self, context: InspectionContext) -> list[Finding]:
            return []

    assert "decorated" in registry
    assert isinstance(registry.get("decorated"), _Decorated)


def test_get_unknown_raises_plugin_not_found() -> None:
    registry = PolicyRegistry()
    registry.add(_NamedPolicy("known"))

    with pytest.raises(PluginNotFoundError, match="known"):
        registry.get("unknown")


def test_all_returns_sorted_by_name() -> None:
    registry = PolicyRegistry()
    registry.add(_NamedPolicy("zeta"))
    registry.add(_NamedPolicy("alpha"))

    assert [p.name for p in registry.all()] == ["alpha", "zeta"]
    assert [p.name for p in registry] == ["alpha", "zeta"]


def test_clear() -> None:
    registry = PolicyRegistry()
    registry.add(_NamedPolicy("x"))
    registry.clear()
    assert len(registry) == 0


def test_builtin_policies_are_registered() -> None:
    # conftest imports adapters, which register the rule-based policies.
    # (NemoGuardrailsPolicy needs a config_path, so it isn't auto-registered.)
    for name in ("secret", "prompt_injection", "system_prompt_leak", "unsafe_tool_call"):
        assert name in POLICIES
