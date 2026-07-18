"""Adapters: concrete implementations of the domain ports.

This is the outer ring of the hexagon. Each subpackage here
(``generators``, ``targets``, ``evaluators``, ``policies``, ``storage``,
``reporting``) implements exactly one port from
:mod:`llm_redteam_firewall.domain.ports` and depends inward on
``domain`` plus, optionally, third-party SDKs specific to that
adapter (an OpenAI client, an HTTP client, ...). Adapters never import
from ``application`` or from each other — the application layer is
wired to adapters only through the plugin registry
(:mod:`llm_redteam_firewall.plugins`), never by direct import.

Importing this package (or any of its subpackages) registers all
in-tree adapters as a side effect. The composition root
(:mod:`llm_redteam_firewall.config.loader`) imports this package
before resolving any campaign configuration.
"""

from . import evaluators, generators, policies, reporting, storage, targets  # noqa: F401

__all__ = [
    "evaluators",
    "generators",
    "policies",
    "reporting",
    "storage",
    "targets",
]
