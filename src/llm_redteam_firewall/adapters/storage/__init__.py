"""FindingsStorage implementations.

Importing this package registers all in-tree storage backends with
:data:`llm_redteam_firewall.plugins.STORAGE`. Of these, only
:class:`.in_memory_storage.InMemoryStorage` is functional out of the box.
"""

from . import in_memory_storage, sqlite_storage  # noqa: F401  (import for registration side effect)

__all__ = ["in_memory_storage", "sqlite_storage"]
