"""SQLiteStorage: extension-point stub for durable local persistence.

Not implemented. When implemented, this would serialize each
:class:`Finding` (including its nested Vulnerability/Attack/Response/
Evaluation) into a small relational schema so findings survive process
restarts and can be queried across campaign runs. Uses only the
standard library ``sqlite3`` module — no extra dependency required.
"""

from __future__ import annotations

from llm_redteam_firewall.domain.models import Finding
from llm_redteam_firewall.plugins import STORAGE


@STORAGE.register("sqlite")
class SQLiteStorage:
    """Placeholder for a future SQLite-backed FindingsStorage."""

    name = "sqlite"

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    def save(self, finding: Finding) -> None:
        raise NotImplementedError(
            "SQLiteStorage is a scaffold placeholder. Implement by opening "
            "self._db_path with sqlite3, creating a findings table on first "
            "use, and inserting a serialized row per finding."
        )

    def list(self, campaign_name: str | None = None) -> list[Finding]:
        raise NotImplementedError(
            "SQLiteStorage is a scaffold placeholder. Implement by querying "
            "and deserializing rows from self._db_path, optionally filtered "
            "by campaign_name."
        )
