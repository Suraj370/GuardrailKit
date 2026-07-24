"""Plugin registry: the well-known extension point of this package.

Adding a new policy means registering it in-tree (import the module so
its ``@POLICIES.register`` decorator runs) or out-of-tree via a
setuptools entry point under ``llm_firewall.policies`` (see
``ARCHITECTURE.md``). No change to ``application`` or ``domain`` is
required either way.
"""

from .registry import PolicyRegistry

POLICIES: PolicyRegistry = PolicyRegistry()

__all__ = ["PolicyRegistry", "POLICIES"]
