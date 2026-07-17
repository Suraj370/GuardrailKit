"""MarkdownReporter: extension-point stub for a formatted Markdown report.

Not implemented. When implemented, this would render a ``Report`` as
a Markdown document (summary table, per-finding detail sections)
suitable for attaching to a pull request or wiki page.
"""

from __future__ import annotations

from llm_redteam_firewall.domain.models import Report
from llm_redteam_firewall.plugins import REPORTERS


@REPORTERS.register("markdown")
class MarkdownReporter:
    """Placeholder for a future Markdown-file Reporter."""

    name = "markdown"

    def __init__(self, output_path: str) -> None:
        self._output_path = output_path

    def report(self, report: Report) -> None:
        raise NotImplementedError(
            "MarkdownReporter is a scaffold placeholder. Implement by "
            "rendering report as Markdown and writing it to self._output_path."
        )
