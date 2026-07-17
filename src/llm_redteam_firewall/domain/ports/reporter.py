"""Reporter port: renders a finished campaign Report somewhere."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_redteam_firewall.domain.models import Report


@runtime_checkable
class Reporter(Protocol):
    """Renders a :class:`Report` to some output surface.

    Multiple reporters can be attached to a single campaign (e.g.
    console + markdown file + JSON export) — the orchestrator simply
    calls ``report`` on each one it was configured with.
    """

    name: str

    def report(self, report: Report) -> None:
        """Render ``report``. Must not mutate it (it is immutable anyway)."""
        ...
