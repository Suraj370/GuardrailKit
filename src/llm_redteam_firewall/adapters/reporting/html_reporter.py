"""HTMLReporter: renders a campaign Report as a standalone HTML file.

Pure serialization/templating, same spirit as :mod:`.json_reporter` and
:mod:`.console_reporter` — no grading or business logic lives here.
Useful for attaching a human-readable summary to CI artifacts or
opening directly in a browser.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from llm_redteam_firewall.domain.models import Finding, Report
from llm_redteam_firewall.domain.ports import Reporter
from llm_redteam_firewall.plugins import REPORTERS

_PAGE_TEMPLATE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Campaign report: {campaign_name}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
  h1 {{ margin-bottom: 0.25rem; }}
  .summary {{ color: #444; margin-bottom: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; }}
  th {{ background: #f5f5f5; }}
  tr.vulnerable {{ background: #fff3f3; }}
  .severity {{ font-weight: 600; text-transform: uppercase; }}
</style>
</head>
<body>
<h1>{campaign_name}</h1>
<p class="summary">
  attacks run: {total_attacks} &middot;
  vulnerable: {vulnerable_count} &middot;
  pass rate: {pass_rate:.0%}
</p>
{table}
</body>
</html>
"""

_ROW_TEMPLATE = """\
<tr class="{row_class}">
  <td class="severity">{severity}</td>
  <td>{vulnerability}</td>
  <td>{category}</td>
  <td>{attack_id}</td>
  <td>{passed}</td>
  <td>{reasoning}</td>
</tr>
"""


def _render_rows(findings: tuple[Finding, ...]) -> str:
    rows = "\n".join(
        _ROW_TEMPLATE.format(
            row_class="vulnerable" if finding.is_vulnerable else "",
            severity=escape(finding.severity.value),
            vulnerability=escape(finding.vulnerability.name),
            category=escape(finding.vulnerability.category),
            attack_id=escape(finding.attack.id),
            passed=finding.passed,
            reasoning=escape(finding.reasoning),
        )
        for finding in findings
    )
    return (
        "<table>\n"
        "<thead><tr>"
        "<th>Severity</th><th>Vulnerability</th><th>Category</th>"
        "<th>Attack</th><th>Passed</th><th>Reasoning</th>"
        "</tr></thead>\n"
        f"<tbody>\n{rows}\n</tbody>\n"
        "</table>"
    )


@REPORTERS.register("html")
class HTMLReporter(Reporter):
    """Writes the campaign report to ``output_path`` as a standalone HTML page."""

    name = "html"

    def __init__(self, output_path: str) -> None:
        self._output_path = Path(output_path)

    def report(self, report: Report) -> None:
        page = _PAGE_TEMPLATE.format(
            campaign_name=escape(report.campaign_name),
            total_attacks=report.total_attacks,
            vulnerable_count=len(report.vulnerable_findings),
            pass_rate=report.pass_rate,
            table=_render_rows(report.findings),
        )
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._output_path.write_text(page, encoding="utf-8")
