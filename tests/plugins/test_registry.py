"""Registry: the plugin lookup/instantiation mechanism itself."""

from __future__ import annotations

import pytest

from llm_redteam_firewall.domain.errors import PluginNotFoundError
from llm_redteam_firewall.plugins.registry import Registry


class _Widget:
    def __init__(self, size: int = 1) -> None:
        self.size = size


def test_register_decorator_and_create() -> None:
    registry: Registry[_Widget] = Registry("widgets")

    @registry.register("small")
    class _SmallWidget(_Widget):
        pass

    widget = registry.create("small", size=3)

    assert isinstance(widget, _SmallWidget)
    assert widget.size == 3


def test_register_factory_imperative() -> None:
    registry: Registry[_Widget] = Registry("widgets")
    registry.register_factory("plain", _Widget)

    assert registry.names() == ["plain"]
    assert isinstance(registry.create("plain"), _Widget)


def test_get_unknown_plugin_raises_plugin_not_found_error() -> None:
    registry: Registry[_Widget] = Registry("widgets")
    registry.register_factory("known", _Widget)

    with pytest.raises(PluginNotFoundError, match="known"):
        registry.get("unknown")
