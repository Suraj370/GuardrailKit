"""domain.vulnerabilities: a reference catalog of known vulnerability types.

Decouples "which vulnerabilities does this campaign probe" from "which
attack generator / attack categories / policies implement that probe":
a :class:`~.definitions.VulnerabilityDefinition` describes the latter
once, by id, and :func:`~.registry.to_vulnerability` projects it into
the concrete :class:`~llm_redteam.domain.models.vulnerability.Vulnerability`
the rest of the pipeline already understands. Campaign authors can
still build a ``Vulnerability`` by hand with full inline detail — this
package adds a lookup-by-id path, it does not replace the existing one.
"""

from .definitions import BUILTIN_VULNERABILITY_DEFINITIONS, VulnerabilityDefinition
from .registry import VULNERABILITY_REGISTRY, VulnerabilityRegistry, to_vulnerability

__all__ = [
    "BUILTIN_VULNERABILITY_DEFINITIONS",
    "VULNERABILITY_REGISTRY",
    "VulnerabilityDefinition",
    "VulnerabilityRegistry",
    "to_vulnerability",
]
