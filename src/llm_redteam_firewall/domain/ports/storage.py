"""FindingsStorage port: persistence for campaign findings."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_redteam_firewall.domain.models import Finding


@runtime_checkable
class FindingsStorage(Protocol):
    """Persists and retrieves :class:`Finding` records.

    Kept deliberately narrow (save + list) so that trivial backends
    (in-memory, JSON file) and heavier ones (SQLite, Postgres, a
    hosted findings API) all satisfy the same contract.
    """

    name: str

    def save(self, finding: Finding) -> None:
        """Persist a single finding. Must be safe to call repeatedly."""
        ...

    def list(self, campaign_name: str | None = None) -> list[Finding]:
        """Return stored findings, optionally filtered by campaign."""
        ...
