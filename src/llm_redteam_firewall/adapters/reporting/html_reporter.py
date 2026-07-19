"""HTMLReporter: renders a campaign Report as a standalone HTML file.

Pure serialization/templating, same spirit as :mod:`.json_reporter` and
:mod:`.console_reporter` — no grading or business logic lives here.
Useful for attaching a human-readable summary to CI artifacts or
opening directly in a browser.

Presentation details (CSS, charts, filters, data shaping) live under
:mod:`.html_report` so this module stays a thin adapter around the
:class:`~llm_redteam_firewall.domain.ports.reporter.Reporter` port.
"""

from __future__ import annotations

from pathlib import Path

from llm_redteam_firewall.domain.models import Report
from llm_redteam_firewall.domain.ports import Reporter
from llm_redteam_firewall.plugins import REPORTERS

from .html_report import prepare_report_data, render_html


@REPORTERS.register("html")
class HTMLReporter(Reporter):
    """Writes the campaign report to ``output_path`` as a standalone HTML page."""

    name = "html"

    def __init__(self, output_path: str) -> None:
        self._output_path = Path(output_path)

    def report(self, report: Report) -> None:
        prepared = prepare_report_data(report)
        page = render_html(prepared)
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._output_path.write_text(page, encoding="utf-8")
