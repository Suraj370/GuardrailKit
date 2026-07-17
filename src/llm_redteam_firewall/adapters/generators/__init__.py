"""AttackGenerator implementations.

Importing this package registers all in-tree generators with
:data:`llm_redteam_firewall.plugins.GENERATORS`. Out-of-tree
generators (e.g. a real Garak integration shipped separately) do not
need to be imported here — they are discovered via entry points.
"""

from . import dummy_generator, garak_generator  # noqa: F401  (import for registration side effect)

__all__ = ["dummy_generator", "garak_generator"]
