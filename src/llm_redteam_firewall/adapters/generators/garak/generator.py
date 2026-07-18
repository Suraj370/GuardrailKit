"""GarakAttackGenerator: AttackGenerator backed by Garak's probe corpus.

This is the only class in this package that is a plugin
(``@GENERATORS.register("garak")``); everything else in this package
is a plain collaborator it owns. It implements
:class:`~llm_redteam_firewall.domain.ports.attack_generator.AttackGenerator`
exactly like :class:`~llm_redteam_firewall.adapters.generators.dummy_generator.DummyAttackGenerator`
does — ``generate(vulnerability, max_attacks) -> list[Attack]``,
synchronous, no side effects on any target.

Critically, it never calls Garak's ``Probe.probe(generator)``. That
method (verified against Garak's source) both mints attempts *and*
executes them against whatever generator is passed in — it is Garak's
own execution stage, and calling it here would mean asking Garak to
run attacks against a Garak-specific model wrapper, duplicating (and
conflicting with) this framework's own
:class:`~llm_redteam_firewall.application.execution_engine.ExecutionEngine`.
Instead, this generator only ever reads a probe's ``.prompts`` — its
static/generated attack corpus — which Garak populates during a
probe's ``__init__``, before ``probe()`` is ever called. Garak's
``Generator``, ``Harness``, and ``Detector`` types are never
instantiated by this framework.
"""

from __future__ import annotations

import logging

from llm_redteam_firewall.domain.models import Attack, Vulnerability
from llm_redteam_firewall.domain.ports import AttackGenerator
from llm_redteam_firewall.plugins import GENERATORS

from .mapper import garak_prompts_to_attacks
from .models import ProbeMappingRule
from .probe_registry import ProbeRegistry
from .probe_selector import ProbeSelector

logger = logging.getLogger(__name__)


def _parse_probe_mapping(raw: dict[str, object]) -> dict[str, ProbeMappingRule]:
    """Parse a YAML-shaped ``probe_mapping`` param into ``ProbeMappingRule`` objects.

    Expected shape per entry::

        prompt_injection:
          include_patterns: ["promptinject.*"]
          include_tags: ["owasp:llm01"]
          exclude_tags: ["deprecated"]
    """
    parsed: dict[str, ProbeMappingRule] = {}
    for vulnerability_id, rule_spec in raw.items():
        if not isinstance(rule_spec, dict):
            continue
        parsed[vulnerability_id] = ProbeMappingRule(
            include_patterns=tuple(rule_spec.get("include_patterns", ()) or ()),
            include_tags=tuple(rule_spec.get("include_tags", ()) or ()),
            exclude_tags=tuple(rule_spec.get("exclude_tags", ()) or ()),
        )
    return parsed


@GENERATORS.register("garak")
class GarakAttackGenerator(AttackGenerator):
    """Produces attacks by reading prompts out of selected Garak probes.

    Parameters mirror the YAML ``generator.params`` shape (see
    ``ARCHITECTURE.md`` for a worked example):

    - ``vulnerabilities``: restrict this generator instance to only
      these vulnerability ids; ``generate()`` returns ``[]`` for any
      other vulnerability (so it can safely sit alongside other
      generators in a multi-generator campaign, once that is
      supported). Omit to use :data:`~.probe_selector.DEFAULT_PROBE_MAPPING`'s
      full id set.
    - ``include_tags`` / ``exclude_tags``: applied on top of (unioned
      with) whatever ``ProbeMappingRule`` is configured per
      vulnerability id.
    - ``max_attacks``: an overall cap for this generator, independent
      of the per-call ``max_attacks`` argument the orchestrator passes
      (which comes from ``Campaign.max_attacks_per_vulnerability``);
      the effective limit for a call is the smaller of the two.
    - ``probe_mapping``: overrides/extends
      :data:`~.probe_selector.DEFAULT_PROBE_MAPPING` — see
      :func:`_parse_probe_mapping`.
    """

    name = "garak"

    def __init__(
        self,
        vulnerabilities: list[str] | None = None,
        include_tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        max_attacks: int | None = None,
        probe_mapping: dict[str, object] | None = None,
        registry: ProbeRegistry | None = None,
    ) -> None:
        self._allowed_vulnerabilities = set(vulnerabilities) if vulnerabilities else None
        self._include_tags = tuple(include_tags or ())
        self._exclude_tags = tuple(exclude_tags or ())
        self._max_attacks = max_attacks
        self._registry = registry if registry is not None else ProbeRegistry()
        mapping = _parse_probe_mapping(probe_mapping) if probe_mapping else None
        self._selector = ProbeSelector(self._registry, mapping=mapping)

    def generate(self, vulnerability: Vulnerability, max_attacks: int) -> list[Attack]:
        if (
            self._allowed_vulnerabilities is not None
            and vulnerability.id not in self._allowed_vulnerabilities
        ):
            logger.debug(
                "garak generator not configured for vulnerability=%s (configured: %s); skipping",
                vulnerability.id,
                sorted(self._allowed_vulnerabilities),
            )
            return []

        effective_max = (
            max_attacks if self._max_attacks is None else min(max_attacks, self._max_attacks)
        )
        if effective_max <= 0:
            return []

        probes = self._selector.select(
            vulnerability.id,
            include_tags=self._include_tags,
            exclude_tags=self._exclude_tags,
        )
        if not probes:
            logger.warning(
                "no garak probes matched vulnerability=%s (no mapping rule, or all filtered out)",
                vulnerability.id,
            )
            return []

        attacks: list[Attack] = []
        for probe_info in probes:  # ProbeSelector.select() already sorts -> deterministic order
            if len(attacks) >= effective_max:
                break
            probe_instance = self._registry.load_probe_instance(probe_info.plugin_name)
            prompts = list(getattr(probe_instance, "prompts", None) or [])
            remaining = effective_max - len(attacks)
            attacks.extend(
                garak_prompts_to_attacks(probe_info, prompts, vulnerability, max_attacks=remaining)
            )

        return attacks[:effective_max]
