"""Generic plugin registry with optional entry-point discovery.

This is what makes ``GarakAttackGenerator`` addable later "without
modifying any other package": a plugin registers itself under a
string name (either in-tree via the ``@registry.register("name")``
decorator, or out-of-tree via a ``pyproject.toml``
``[project.entry-points."llm_redteam.generators"]`` entry),
and the config loader / composition root looks adapters up by that
name. Orchestration code never imports adapter classes directly.
"""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import entry_points

from llm_redteam.domain.errors import PluginNotFoundError

_ENTRY_POINT_NAMESPACE = "llm_redteam"


class Registry[T]:
    """Name -> factory registry for one plugin category (e.g. "targets").

    Usage as a decorator on in-tree adapters::

        TARGETS: Registry[Target] = Registry("targets")

        @TARGETS.register("mock")
        class MockTarget:
            ...

    Out-of-tree packages (e.g. a future ``llm-redteam-garak`` package)
    register the same way via entry points, declared in *their own*
    ``pyproject.toml``::

        [project.entry-points."llm_redteam.generators"]
        garak = "llm_redteam_garak.generator:GarakAttackGenerator"

    Those are discovered lazily on first :meth:`get`/:meth:`create`
    call via :meth:`discover_entry_points`, so importing this module
    never has side effects on installed third-party packages.
    """

    def __init__(self, category: str) -> None:
        self._category = category
        self._factories: dict[str, Callable[..., T]] = {}
        self._entry_points_discovered = False

    def register(self, name: str) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Class/factory decorator: ``@registry.register("name")``."""

        def _decorator(factory: Callable[..., T]) -> Callable[..., T]:
            self._factories[name] = factory
            return factory

        return _decorator

    def register_factory(self, name: str, factory: Callable[..., T]) -> None:
        """Imperative equivalent of the :meth:`register` decorator."""
        self._factories[name] = factory

    def discover_entry_points(self) -> None:
        """Load out-of-tree plugins registered under this category's group.

        Group name convention: ``llm_redteam.<category>``,
        e.g. ``llm_redteam.generators``. Idempotent and cheap
        after the first call.
        """
        if self._entry_points_discovered:
            return
        group = f"{_ENTRY_POINT_NAMESPACE}.{self._category}"
        for ep in entry_points(group=group):
            if ep.name not in self._factories:
                self._factories[ep.name] = ep.load()
        self._entry_points_discovered = True

    def names(self) -> list[str]:
        self.discover_entry_points()
        return sorted(self._factories)

    def get(self, name: str) -> Callable[..., T]:
        self.discover_entry_points()
        try:
            return self._factories[name]
        except KeyError as exc:
            available = ", ".join(sorted(self._factories)) or "<none registered>"
            raise PluginNotFoundError(
                f"no {self._category} plugin named {name!r}; available: {available}"
            ) from exc

    def create(self, name: str, /, **kwargs: object) -> T:
        """Instantiate the plugin registered under ``name`` with ``kwargs``."""
        factory = self.get(name)
        return factory(**kwargs)
