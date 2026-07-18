"""VulnerabilityRegistry: id -> VulnerabilityDefinition lookup of known vulnerability types.

This is a reference catalog, not a factory of live plugin instances
like :class:`~llm_redteam_firewall.plugins.registry.Registry` or
:class:`~llm_redteam_firewall.plugins.policy_registry.PolicyRegistry`:
entries are plain data (:class:`~.definitions.VulnerabilityDefinition`).
It exists so campaigns can reference a vulnerability by id — decoupling
"which vulnerabilities does this campaign probe" from "which attack
generator / attack categories / policies implement that probe" — the
same way :mod:`~llm_redteam_firewall.plugins` decouples a campaign's
choice of ``target: {type: mock}`` from the ``MockTarget`` class.

Nothing here imports :mod:`llm_redteam_firewall.plugins` or
:mod:`llm_redteam_firewall.adapters`: this module only deals in plugin
*names* (strings), never live instances, so it stays a pure domain
concept and does not violate the domain layer's "stdlib only" import
rule.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from llm_redteam_firewall.domain.errors import PluginNotFoundError
from llm_redteam_firewall.domain.models import Severity, Vulnerability

from .definitions import BUILTIN_VULNERABILITY_DEFINITIONS, VulnerabilityDefinition


class VulnerabilityRegistry:
    """Id -> :class:`VulnerabilityDefinition` registry of known vulnerability types."""

    def __init__(self) -> None:
        self._definitions: dict[str, VulnerabilityDefinition] = {}

    def register(self, definition: VulnerabilityDefinition) -> VulnerabilityDefinition:
        """Register ``definition`` under ``definition.id``."""
        self._definitions[definition.id] = definition
        return definition

    def get(self, id: str) -> VulnerabilityDefinition:
        """Retrieve the definition registered under ``id``."""
        try:
            return self._definitions[id]
        except KeyError as exc:
            available = ", ".join(sorted(self._definitions)) or "<none registered>"
            raise PluginNotFoundError(
                f"no vulnerability definition registered under id {id!r}; available: {available}"
            ) from exc

    def all(self) -> list[VulnerabilityDefinition]:
        """List every registered definition, in stable id order."""
        return [self._definitions[key] for key in sorted(self._definitions)]

    def names(self) -> list[str]:
        """List every registered definition id, sorted."""
        return sorted(self._definitions)

    def clear(self) -> None:
        """Remove every registered definition (primarily for tests)."""
        self._definitions.clear()

    def __contains__(self, id: str) -> bool:
        return id in self._definitions

    def __len__(self) -> int:
        return len(self._definitions)

    def __iter__(self) -> Iterator[VulnerabilityDefinition]:
        return iter(self.all())


def to_vulnerability(
    definition: VulnerabilityDefinition,
    *,
    id: str | None = None,
    description: str | None = None,
    severity: Severity | None = None,
    metadata: dict[str, Any] | None = None,
) -> Vulnerability:
    """Project a :class:`VulnerabilityDefinition` into a concrete campaign :class:`Vulnerability`.

    This is how a campaign resolves "reference vulnerability
    ``prompt_injection`` by id" into the full domain object the
    existing ``CampaignOrchestrator`` / ``AttackGenerator`` /
    ``Evaluator`` pipeline already understands, without any of those
    ports changing shape. The definition's implementation defaults
    (generator/categories/policies/tags) are carried in
    ``Vulnerability.metadata`` rather than as new dataclass fields, so
    this needs no change to the existing ``Vulnerability`` entity or
    anything that already consumes it.

    ``id``/``description``/``severity``/``metadata`` let a caller
    override individual fields (e.g. a campaign-specific description)
    while still inheriting the rest from the definition.
    """
    resolved_metadata: dict[str, Any] = {
        "default_attack_generator": definition.default_attack_generator,
        "default_attack_categories": list(definition.default_attack_categories),
        "default_policies": list(definition.default_policies),
        "tags": list(definition.tags),
    }
    if metadata:
        resolved_metadata.update(metadata)

    category = definition.default_attack_categories[0] if definition.default_attack_categories else definition.id

    return Vulnerability(
        id=id if id is not None else definition.id,
        name=definition.name,
        category=category,
        description=description if description is not None else definition.description,
        severity=severity if severity is not None else definition.severity,
        metadata=resolved_metadata,
    )


def _build_default_registry() -> VulnerabilityRegistry:
    registry = VulnerabilityRegistry()
    for definition in BUILTIN_VULNERABILITY_DEFINITIONS:
        registry.register(definition)
    return registry


VULNERABILITY_REGISTRY: VulnerabilityRegistry = _build_default_registry()
