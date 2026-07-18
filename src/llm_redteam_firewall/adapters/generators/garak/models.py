"""Plain data types shared by the Garak adapter modules.

Nothing in this module imports ``garak``. It exists so
:mod:`.probe_registry`, :mod:`.probe_selector`, and :mod:`.mapper` can
share the same shapes without importing each other's implementation
details, and so the adapter's public data shapes are easy to construct
in tests without a real Garak install.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class GarakProbeInfo:
    """Metadata about one discovered Garak probe *class*, read without instantiating it.

    ``plugin_name`` is Garak's own dotted plugin path, exactly as
    returned by ``garak._plugins.enumerate_plugins("probes")``, e.g.
    ``"probes.dan.Dan_11_0"``. ``module``/``class_name`` are that path
    split apart for convenience (``"dan"`` / ``"Dan_11_0"``).

    Every other field mirrors a class-level attribute already defined
    on ``garak.probes.Probe`` (verified against Garak's source): a
    probe's ``tags``/``goal``/``primary_detector``/``extended_detectors``/
    ``doc_uri``/``tier`` are set at class scope (directly, or via a
    metaclass), so reading them via ``getattr`` costs nothing and never
    runs a probe's ``__init__`` (which is where the expensive part —
    loading its prompt corpus — happens).
    """

    plugin_name: str
    module: str
    class_name: str
    active: bool
    description: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    goal: str = ""
    primary_detector: str | None = None
    extended_detectors: tuple[str, ...] = field(default_factory=tuple)
    doc_uri: str = ""
    tier: str | None = None

    @property
    def short_name(self) -> str:
        """``module.ClassName`` without the ``probes.`` category prefix."""
        return f"{self.module}.{self.class_name}"


@dataclass(frozen=True, slots=True)
class ProbeMappingRule:
    """One vulnerability id's configurable mapping onto Garak probes.

    ``include_patterns`` are matched against
    :attr:`GarakProbeInfo.short_name` (``module.ClassName``) using
    shell-glob syntax (``fnmatch``). A pattern with no ``.`` (e.g.
    ``"dan"``) is shorthand for "every class in that module"
    (``"dan.*"``) — see :func:`.probe_selector.normalize_pattern`.
    """

    include_patterns: tuple[str, ...] = field(default_factory=tuple)
    include_tags: tuple[str, ...] = field(default_factory=tuple)
    exclude_tags: tuple[str, ...] = field(default_factory=tuple)
