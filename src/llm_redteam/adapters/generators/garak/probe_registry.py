"""ProbeRegistry: discovers installed Garak probes via Garak's own plugin system.

This module is the only place in the framework, besides
:mod:`.generator`, that imports ``garak`` — and even here the import is
lazy (inside methods, not at module scope) so that
``llm_redteam.adapters`` (imported eagerly by the config
loader, the CLI, and every test's ``conftest.py``) never fails to
import just because Garak is not installed. Only calling
:class:`ProbeRegistry`'s methods requires Garak.

Discovery has two verified building blocks, from Garak's own source
(``garak/_plugins.py``, ``garak/probes/base.py``):

* ``garak._plugins.enumerate_plugins("probes")`` returns
  ``list[(dotted_plugin_name, active_bool)]`` by walking the
  ``garak.probes`` package — no probe name is ever hardcoded here.
* A probe's descriptive metadata (``tags``, ``goal``,
  ``primary_detector``, ``extended_detectors``, ``doc_uri``, ``tier``)
  is set at *class* scope on every concrete ``garak.probes.Probe``
  subclass (directly or via a metaclass), so it can be read with
  ``getattr`` on the imported class object — without instantiating it.
  This matters because instantiating a probe runs its ``__init__``,
  which is where the (sometimes expensive: large JSON/dataset loads)
  prompt corpus gets built; metadata browsing should not pay that cost
  for every installed probe.

Reading ``.prompts`` (the actual prompt corpus) is a different,
explicitly opt-in operation — :meth:`ProbeRegistry.load_probe_instance`
— used only by :mod:`.generator` for probes that were actually
selected to run.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Iterable
from types import ModuleType
from typing import Any, cast

from llm_redteam.domain.errors import ConfigurationError

from .models import GarakProbeInfo

logger = logging.getLogger(__name__)


class GarakNotInstalledError(ConfigurationError):
    """Raised when Garak-backed functionality is used but ``garak`` is not installed."""

    def __init__(self, cause: Exception | None = None) -> None:
        super().__init__(
            "garak is not installed; install the 'garak' extra "
            "(pip install 'llm-redteam-firewall[garak]') to use the garak "
            "attack generator"
        )
        self.__cause__ = cause


def _import_garak_plugins() -> ModuleType:
    """Lazily import ``garak._plugins``, translating ``ImportError`` into a clear domain error."""
    try:
        from garak import _plugins as garak_plugins  # type: ignore[import-not-found]
    except ImportError as exc:
        raise GarakNotInstalledError(exc) from exc
    return cast(ModuleType, garak_plugins)


class ProbeRegistry:
    """Discovers Garak probes by asking Garak, never by hardcoding a probe list."""

    def __init__(self) -> None:
        self._cache: dict[str, GarakProbeInfo] | None = None

    def _ensure_loaded(self) -> dict[str, GarakProbeInfo]:
        if self._cache is not None:
            return self._cache

        garak_plugins = _import_garak_plugins()
        infos: dict[str, GarakProbeInfo] = {}
        for plugin_name, active in garak_plugins.enumerate_plugins(category="probes"):
            info = self._read_probe_info(plugin_name, active)
            if info is not None:
                infos[plugin_name] = info

        self._cache = infos
        return infos

    def _read_probe_info(self, plugin_name: str, active: bool) -> GarakProbeInfo | None:
        parts = plugin_name.split(".")
        if len(parts) != 3 or parts[0] != "probes":
            # Garak's own enumerate_plugins contract (verified): every probe
            # is "probes.<module>.<ClassName>". Skip anything unexpected
            # rather than guess at its shape.
            logger.debug("skipping unexpected garak plugin name shape: %r", plugin_name)
            return None
        _, module_name, class_name = parts

        try:
            module = importlib.import_module(f"garak.probes.{module_name}")
            probe_cls = getattr(module, class_name)
        except Exception:
            # Some probe modules require Garak's own optional extras
            # (audio/image processing, etc.) that may not be installed
            # even when the base `garak` package is. Discovery should
            # degrade gracefully rather than fail entirely.
            logger.warning("could not import garak probe %r for metadata; skipping", plugin_name)
            return None

        return GarakProbeInfo(
            plugin_name=plugin_name,
            module=module_name,
            class_name=class_name,
            active=active,
            description=_first_doc_line(probe_cls),
            tags=tuple(getattr(probe_cls, "tags", ()) or ()),
            goal=getattr(probe_cls, "goal", "") or "",
            primary_detector=getattr(probe_cls, "primary_detector", None),
            extended_detectors=tuple(getattr(probe_cls, "extended_detectors", ()) or ()),
            doc_uri=getattr(probe_cls, "doc_uri", "") or "",
            tier=_tier_name(getattr(probe_cls, "tier", None)),
        )

    def list_probes(self) -> list[GarakProbeInfo]:
        """List every discovered probe, in stable (dotted-name) order."""
        return sorted(self._ensure_loaded().values(), key=lambda p: p.plugin_name)

    def get_probe(self, name: str) -> GarakProbeInfo:
        """Look up one probe by dotted name (``probes.dan.Dan_11_0`` or ``dan.Dan_11_0``)."""
        infos = self._ensure_loaded()
        if name in infos:
            return infos[name]
        qualified = f"probes.{name}"
        if qualified in infos:
            return infos[qualified]
        available = ", ".join(sorted(infos)) or "<none discovered>"
        raise ConfigurationError(f"no garak probe named {name!r}; available: {available}")

    def filter_by_category(self, category: str) -> list[GarakProbeInfo]:
        """List every probe in Garak module ``category`` (e.g. ``"dan"``, ``"promptinject"``)."""
        return [p for p in self.list_probes() if p.module == category]

    def filter_by_tags(self, tags: Iterable[str]) -> list[GarakProbeInfo]:
        """List every probe whose ``tags`` intersect ``tags``."""
        wanted = set(tags)
        if not wanted:
            return []
        return [p for p in self.list_probes() if wanted & set(p.tags)]

    def load_probe_instance(self, plugin_name: str) -> Any:
        """Instantiate one probe (via ``garak._plugins.load_plugin``), populating ``.prompts``.

        This is the only place a probe is actually constructed. It is
        called once per probe :mod:`.generator` has already decided to
        use — never during discovery/filtering.
        """
        garak_plugins = _import_garak_plugins()
        return garak_plugins.load_plugin(plugin_name)


def _first_doc_line(cls: type) -> str:
    doc = cls.__doc__
    if not doc:
        return ""
    return doc.strip().split("\n", 1)[0].strip()


def _tier_name(tier: Any) -> str | None:
    if tier is None:
        return None
    name = getattr(tier, "name", None)
    return name if isinstance(name, str) else str(tier)
