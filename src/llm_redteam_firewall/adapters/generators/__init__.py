"""AttackGenerator implementations.

Importing this package registers all in-tree generators with
:data:`llm_redteam_firewall.plugins.GENERATORS`. Out-of-tree
generators do not need to be imported here — they are discovered via
entry points. ``dummy`` is a single-file adapter; ``garak`` lives in
its own :mod:`.garak` subpackage (it needed several collaborator
modules — probe discovery, selection, and mapping — not just one
file), but both register into this same ``GENERATORS`` registry.
"""

from . import dummy_generator, garak  # noqa: F401  (import for registration side effect)

__all__ = ["dummy_generator", "garak"]
