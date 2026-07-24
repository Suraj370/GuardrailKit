"""llm_firewall: an in-process runtime guard for LLM prompts/responses.

Unlike ``llm_redteam`` (which *attacks* a target offline to find
weaknesses), this package is meant to run inline in a host application:
call :meth:`Firewall.inspect` with a prompt (and, once available, the
model's response) and get back a :class:`~llm_firewall.domain.models.InspectionResult`
telling the caller whether to allow, flag, or block it.

Public API surface is intentionally small::

    from llm_firewall import Firewall

    fw = Firewall.from_config("firewall.yaml")
    result = fw.inspect(prompt=user_input, response=model_output)
    if result.blocked:
        raise BlockedByFirewall(result.findings)

See ``ARCHITECTURE.md`` for the full package map. This package is
independent of ``llm_redteam`` by design: same hexagonal shape
(domain -> application <- adapters/plugins/config/cli), but its own
domain models and its own ``Policy`` port, so the two can evolve and
ship separately.
"""

from llm_firewall.firewall import Firewall

__version__ = "0.1.0"

__all__ = ["Firewall", "__version__"]
