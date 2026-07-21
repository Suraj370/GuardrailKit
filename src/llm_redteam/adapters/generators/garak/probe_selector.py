"""ProbeSelector: maps our VulnerabilityDefinition ids onto Garak probes.

Imports no ``garak`` module directly — it only calls
:class:`~.probe_registry.ProbeRegistry`, which already isolates the
lazy Garak import. This module is pure selection logic over
:class:`~.models.GarakProbeInfo` objects.

The mapping is data (:data:`DEFAULT_PROBE_MAPPING`, a
``dict[str, ProbeMappingRule]``), constructor-injected into
:class:`ProbeSelector` — not a chain of
``if vulnerability_id == "jailbreak": ...`` branches. A caller (in
practice, :class:`~.generator.GarakAttackGenerator`, wired from YAML)
can replace it entirely or override individual entries without editing
this file.

``DEFAULT_PROBE_MAPPING`` itself is a best-effort starting point, built
from real Garak probe module names verified against the Garak source
at integration time (``dan``, ``promptinject``, ``encoding``, ...) —
not from Garak's own documentation of "which probe covers which risk"
(Garak does not publish one canonical such mapping). Two of our six
built-in vulnerability categories (``pii_leakage``, ``tool_misuse``)
have no exact Garak module equivalent; the mapped modules are the
closest approximation available and are flagged as such in
``ARCHITECTURE.md``.
"""

from __future__ import annotations

from collections.abc import Iterable
from fnmatch import fnmatch

from .models import GarakProbeInfo, ProbeMappingRule
from .probe_registry import ProbeRegistry

DEFAULT_PROBE_MAPPING: dict[str, ProbeMappingRule] = {
    "prompt_injection": ProbeMappingRule(
        include_patterns=("promptinject.*", "latentinjection.*"),
    ),
    "jailbreak": ProbeMappingRule(
        include_patterns=("dan.*", "encoding.*", "suffix.*", "grandma.*", "dra.*"),
    ),
    "prompt_leakage": ProbeMappingRule(
        include_patterns=("leakreplay.*", "sysprompt_extraction.*", "divergence.*"),
    ),
    # No dedicated Garak PII-leakage module exists; leakreplay is the
    # closest approximation (see module docstring).
    "pii_leakage": ProbeMappingRule(
        include_patterns=("leakreplay.*",),
    ),
    "secret_leakage": ProbeMappingRule(
        include_patterns=("apikey.*",),
    ),
    # No dedicated Garak "excessive agency" module exists; exploitation/
    # packagehallucination are the closest approximation (see module
    # docstring).
    "tool_misuse": ProbeMappingRule(
        include_patterns=("exploitation.*", "packagehallucination.*"),
    ),
    # donotanswer.* tests whether the target can be made to produce
    # discriminatory/hateful/offensive/toxic content -- distinct from
    # jailbreak (generic guardrail bypass) and unrelated to pii_leakage
    # (personal data disclosure), so it gets its own category rather
    # than being folded into either.
    "hateful_content": ProbeMappingRule(
        include_patterns=("donotanswer.*",),
    ),
}


def normalize_pattern(pattern: str) -> str:
    """A bare module name (``"dan"``) means "every class in that module" (``"dan.*"``)."""
    return pattern if "." in pattern else f"{pattern}.*"


class ProbeSelector:
    """Resolves a vulnerability id into concrete, sorted :class:`GarakProbeInfo` objects."""

    def __init__(
        self,
        registry: ProbeRegistry,
        mapping: dict[str, ProbeMappingRule] | None = None,
    ) -> None:
        self._registry = registry
        self._mapping = dict(mapping) if mapping is not None else dict(DEFAULT_PROBE_MAPPING)

    def rule_for(self, vulnerability_id: str) -> ProbeMappingRule | None:
        """Return the configured mapping rule for ``vulnerability_id``, if any."""
        return self._mapping.get(vulnerability_id)

    def select(
        self,
        vulnerability_id: str,
        *,
        include_tags: Iterable[str] = (),
        exclude_tags: Iterable[str] = (),
    ) -> list[GarakProbeInfo]:
        """Return every probe matching ``vulnerability_id``'s rule, filtered and sorted.

        Deterministic: results are always sorted by
        :attr:`GarakProbeInfo.plugin_name`, so callers get the same
        probe order on every run regardless of Garak's own internal
        discovery order.
        """
        rule = self._mapping.get(vulnerability_id)
        if rule is None:
            return []

        candidates = self._registry.list_probes()

        patterns = tuple(normalize_pattern(p) for p in rule.include_patterns)
        if patterns:
            candidates = [
                p for p in candidates if any(fnmatch(p.short_name, pattern) for pattern in patterns)
            ]

        merged_include_tags = set(rule.include_tags) | set(include_tags)
        if merged_include_tags:
            candidates = [p for p in candidates if merged_include_tags & set(p.tags)]

        merged_exclude_tags = set(rule.exclude_tags) | set(exclude_tags)
        if merged_exclude_tags:
            candidates = [p for p in candidates if not (merged_exclude_tags & set(p.tags))]

        return sorted(candidates, key=lambda p: p.plugin_name)
