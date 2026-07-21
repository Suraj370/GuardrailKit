"""Reporter interface: renders a finished campaign Report somewhere.

Single responsibility: take a completed, immutable ``Report`` and
render it to some output surface (stdout, a file, a webhook, ...). It
knows nothing about how the campaign was run or how findings were
graded.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from llm_redteam.domain.models import Report


class Reporter(ABC):
    """Renders a :class:`Report` to some output surface.

    Multiple reporters can be attached to a single campaign (e.g.
    console + markdown file + JSON export) — the orchestrator simply
    calls ``report`` on each one it was configured with.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name this reporter registers under."""
        raise NotImplementedError

    @abstractmethod
    def report(self, report: Report) -> None:
        """Render ``report``. Must not mutate it (it is immutable anyway)."""
        raise NotImplementedError
