"""Internal building blocks for the standalone HTML campaign report.

Public entry point remains :class:`~llm_redteam_firewall.adapters.reporting.html_reporter.HTMLReporter`.
"""

from .data import PreparedReport, prepare_report_data
from .template import render_html

__all__ = ["PreparedReport", "prepare_report_data", "render_html"]
