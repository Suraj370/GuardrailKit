"""HTML template assembly for campaign reports.

Builds a standalone HTML document from :class:`PreparedReport` data,
inlined CSS, and client-side JavaScript. No external assets.
"""

from __future__ import annotations

import json
from html import escape
from typing import Any

from .data import (
    AttackEvidenceView,
    FindingView,
    PreparedReport,
    VulnerabilityBreakdownRow,
)
from .scripts import JS
from .styles import CSS


def _e(value: Any) -> str:
    """HTML-escape a value for text content / attribute use."""
    return escape("" if value is None else str(value), quote=True)


def _pct(rate: float) -> str:
    return f"{rate * 100:.1f}%"


def _format_score(score: float | None) -> str:
    if score is None:
        return "—"
    return f"{score:.3f}"


def _chips(items: tuple[str, ...]) -> str:
    if not items:
        return '<span class="chip">—</span>'
    return "".join(f'<span class="chip">{_e(item)}</span>' for item in items)


def _option_list(values: tuple[str, ...], blank_label: str = "All") -> str:
    options = [f'<option value="">{_e(blank_label)}</option>']
    for value in values:
        options.append(f'<option value="{_e(value)}">{_e(value)}</option>')
    return "\n".join(options)


def _metadata_block(metadata: dict[str, Any]) -> str:
    if not metadata:
        return '<pre class="mono-block">(none)</pre>'
    pretty = json.dumps(metadata, indent=2, ensure_ascii=False, default=str)
    return f'<pre class="mono-block">{_e(pretty)}</pre>'


def _render_executive_summary(data: PreparedReport) -> str:
    s = data.executive_summary
    return f"""
<section id="executive-summary">
  <h2>Executive Summary</h2>
  <div class="card">
    <div class="summary-grid">
      <div class="summary-item"><div class="label">Campaign</div><div class="value">{_e(s.campaign_name)}</div></div>
      <div class="summary-item"><div class="label">Started</div><div class="value">{_e(s.started_at)}</div></div>
      <div class="summary-item"><div class="label">Finished</div><div class="value">{_e(s.finished_at)}</div></div>
      <div class="summary-item"><div class="label">Duration</div><div class="value">{_e(s.duration_display)}</div></div>
      <div class="summary-item"><div class="label">Total attacks executed</div><div class="value">{s.total_attacks}</div></div>
      <div class="summary-item"><div class="label">Total findings</div><div class="value">{s.total_findings}</div></div>
      <div class="summary-item"><div class="label">Blocked</div><div class="value">{s.passed}</div></div>
      <div class="summary-item"><div class="label">Compromised</div><div class="value">{s.failed}</div></div>
      <div class="summary-item"><div class="label">Errored</div><div class="value">{s.errored}</div></div>
      <div class="summary-item"><div class="label">Success rate</div><div class="value">{_pct(s.success_rate)}</div></div>
    </div>
    <div class="summary-grid">
      <div class="summary-item">
        <div class="label">Vulnerabilities tested</div>
        <div class="chip-list">{_chips(s.vulnerabilities_tested)}</div>
      </div>
      <div class="summary-item">
        <div class="label">Attack generators used</div>
        <div class="chip-list">{_chips(s.attack_generators)}</div>
      </div>
      <div class="summary-item">
        <div class="label">Targets tested</div>
        <div class="chip-list">{_chips(s.targets_tested)}</div>
      </div>
    </div>
  </div>
</section>
"""


def _render_statistics(data: PreparedReport) -> str:
    sc = data.severity_counts
    s = data.executive_summary
    return f"""
<section id="statistics">
  <h2>Overall Statistics</h2>
  <div class="stat-grid">
    <div class="stat-card"><div class="stat-value">{s.total_attacks}</div><div class="stat-label">Total attacks</div></div>
    <div class="stat-card"><div class="stat-value">{s.total_findings}</div><div class="stat-label">Total findings</div></div>
    <div class="stat-card critical"><div class="stat-value">{sc.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card high"><div class="stat-value">{sc.high}</div><div class="stat-label">High</div></div>
    <div class="stat-card medium"><div class="stat-value">{sc.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card low"><div class="stat-value">{sc.low}</div><div class="stat-label">Low</div></div>
    <div class="stat-card informational"><div class="stat-value">{sc.informational}</div><div class="stat-label">Informational</div></div>
  </div>
</section>
"""


def _render_charts() -> str:
    return """
<section id="charts">
  <h2>Charts</h2>
  <div class="chart-grid">
    <div class="chart-card">
      <h3>Findings by severity</h3>
      <canvas id="chart-severity" aria-label="Findings by severity chart" role="img"></canvas>
    </div>
    <div class="chart-card">
      <h3>Findings by vulnerability</h3>
      <canvas id="chart-findings-vuln" aria-label="Findings by vulnerability chart" role="img"></canvas>
    </div>
    <div class="chart-card">
      <h3>Outcome breakdown</h3>
      <canvas id="chart-pass-fail" aria-label="Blocked versus compromised versus errored chart" role="img"></canvas>
    </div>
    <div class="chart-card">
      <h3>Attacks per vulnerability</h3>
      <canvas id="chart-attacks-vuln" aria-label="Attacks per vulnerability chart" role="img"></canvas>
    </div>
  </div>
</section>
"""


def _render_vulnerability_row(row: VulnerabilityBreakdownRow) -> str:
    avg = _format_score(row.average_score)
    return (
        "<tr>"
        f"<td>{_e(row.vulnerability)}</td>"
        f"<td>{row.attacks}</td>"
        f"<td>{row.passed}</td>"
        f"<td>{row.failed}</td>"
        f"<td>{row.errored}</td>"
        f"<td>{_pct(row.success_rate)}</td>"
        f"<td>{avg}</td>"
        "</tr>"
    )


def _render_vulnerabilities(data: PreparedReport) -> str:
    if not data.vulnerability_breakdown:
        body = '<tr><td colspan="7">No vulnerabilities tested.</td></tr>'
    else:
        body = "\n".join(_render_vulnerability_row(r) for r in data.vulnerability_breakdown)
    return f"""
<section id="vulnerabilities">
  <h2>Vulnerability Breakdown</h2>
  <div class="table-wrap">
    <table class="data-table" id="vulnerability-table">
      <thead>
        <tr>
          <th>Vulnerability</th>
          <th>Number of attacks</th>
          <th>Blocked</th>
          <th>Compromised</th>
          <th>Errored</th>
          <th>Success rate</th>
          <th>Average score</th>
        </tr>
      </thead>
      <tbody>
        {body}
      </tbody>
    </table>
  </div>
</section>
"""


def _render_filters(data: PreparedReport) -> str:
    opts = data.filter_options
    return f"""
<div class="filters" id="report-filters" role="search" aria-label="Report filters">
  <label>Vulnerability
    <select id="filter-vulnerability">{_option_list(opts.get("vulnerabilities", ()))}</select>
  </label>
  <label>Severity
    <select id="filter-severity">{_option_list(opts.get("severities", ()))}</select>
  </label>
  <label>Status
    <select id="filter-status">{_option_list(opts.get("statuses", ()))}</select>
  </label>
  <label>Result
    <select id="filter-result">{_option_list(opts.get("result_labels", ()))}</select>
  </label>
  <label>Search
    <input type="search" id="filter-search" placeholder="Search text…" autocomplete="off">
  </label>
  <button type="button" class="btn" id="filter-clear">Clear filters</button>
</div>
"""


def _detail(title: str, content: str, open_by_default: bool = False) -> str:
    open_attr = " open" if open_by_default else ""
    return f"""
<div class="detail-block">
  <details{open_attr}>
    <summary>{_e(title)}</summary>
    {content}
  </details>
</div>
"""


def _render_finding_card(finding: FindingView) -> str:
    result_badge = f"badge-{finding.status_label.lower()}"
    search_blob = " ".join(
        [
            finding.id,
            finding.vulnerability,
            finding.severity,
            finding.status,
            finding.status_label,
            finding.attack_prompt,
            finding.model_response,
            finding.policy_reasoning,
            finding.evaluation_reasoning,
            finding.source,
            finding.attack_id,
            finding.target,
            json.dumps(finding.metadata, default=str),
        ]
    )
    body = f"""
<div class="finding-body">
  <div class="kv-grid">
    <div class="k">Finding ID</div><div class="v">{_e(finding.id)}</div>
    <div class="k">Vulnerability</div><div class="v">{_e(finding.vulnerability)}</div>
    <div class="k">Severity</div><div class="v"><span class="badge badge-{_e(finding.severity)}">{_e(finding.severity)}</span></div>
    <div class="k">Status</div><div class="v"><span class="badge badge-status">{_e(finding.status)}</span></div>
    <div class="k">Result</div><div class="v"><span class="badge {result_badge}">{_e(finding.status_label)}</span></div>
    <div class="k">Score</div><div class="v">{_format_score(finding.score)}</div>
    <div class="k">Source</div><div class="v">{_e(finding.source)}</div>
    <div class="k">Timestamp</div><div class="v">{_e(finding.timestamp)}</div>
    <div class="k">Attack ID</div><div class="v">{_e(finding.attack_id)}</div>
    <div class="k">Target</div><div class="v">{_e(finding.target)}</div>
    <div class="k">Generator</div><div class="v">{_e(finding.generator)}</div>
  </div>
  {_detail("Attack prompt", f'<pre class="mono-block">{_e(finding.attack_prompt)}</pre>')}
  {_detail("Model response", f'<pre class="mono-block">{_e(finding.model_response)}</pre>')}
  {_detail("Policy reasoning", f'<pre class="mono-block">{_e(finding.policy_reasoning or "(none)")}</pre>')}
  {_detail("Evaluation reasoning", f'<pre class="mono-block">{_e(finding.evaluation_reasoning or "(none)")}</pre>')}
  {_detail("Metadata", _metadata_block(finding.metadata))}
</div>
"""
    return f"""
<details class="finding-card"
  data-vulnerability="{_e(finding.vulnerability)}"
  data-severity="{_e(finding.severity)}"
  data-status="{_e(finding.status)}"
  data-passed="{str(finding.passed).lower()}"
  data-result-label="{_e(finding.status_label)}"
  data-search="{_e(search_blob)}">
  <summary>
    <span class="badge badge-{_e(finding.severity)}">{_e(finding.severity)}</span>
    <span class="finding-title">{_e(finding.vulnerability)}</span>
    <span class="badge {result_badge}">{_e(finding.status_label)}</span>
    <div class="finding-meta">
      <span class="finding-id">{_e(finding.id)}</span>
      <span class="badge badge-status">{_e(finding.status)}</span>
      <span>{_e(finding.timestamp)}</span>
    </div>
  </summary>
  {body}
</details>
"""


def _render_findings(data: PreparedReport) -> str:
    if not data.findings:
        cards = '<div class="empty-state">No findings recorded for this campaign.</div>'
    else:
        cards = "\n".join(_render_finding_card(f) for f in data.findings)
    return f"""
<section id="findings">
  <h2>Findings</h2>
  {_render_filters(data)}
  <p class="filter-meta" id="findings-filter-meta"></p>
  <div class="findings-list" id="findings-list">
    {cards}
  </div>
</section>
"""


def _render_evidence_card(attack: AttackEvidenceView) -> str:
    result_badge = f"badge-{attack.result_label.lower()}"
    result_label = attack.result_label
    search_blob = " ".join(
        [
            attack.attack_id,
            attack.prompt,
            attack.target,
            attack.response,
            attack.vulnerability,
            attack.generator,
            attack.error or "",
            json.dumps(attack.execution_metadata, default=str),
        ]
    )
    meta_pretty = json.dumps(attack.execution_metadata, indent=2, ensure_ascii=False, default=str)
    error_block = (
        _detail("Error", f'<pre class="mono-block">{_e(attack.error)}</pre>')
        if attack.error
        else ""
    )
    body = f"""
<div class="evidence-body">
  <div class="kv-grid">
    <div class="k">Attack ID</div><div class="v">{_e(attack.attack_id)}</div>
    <div class="k">Target</div><div class="v">{_e(attack.target)}</div>
    <div class="k">Vulnerability</div><div class="v">{_e(attack.vulnerability)}</div>
    <div class="k">Duration</div><div class="v">{attack.duration_ms:.2f} ms</div>
    <div class="k">Generator</div><div class="v">{_e(attack.generator)}</div>
    <div class="k">Finding ID</div><div class="v">{_e(attack.finding_id)}</div>
  </div>
  {_detail("Prompt", f'<pre class="mono-block">{_e(attack.prompt)}</pre>', open_by_default=True)}
  {_detail("Response", f'<pre class="mono-block">{_e(attack.response)}</pre>')}
  {_detail("Execution metadata", f'<pre class="mono-block">{_e(meta_pretty)}</pre>')}
  {error_block}
</div>
"""
    return f"""
<details class="evidence-card"
  data-vulnerability="{_e(attack.vulnerability)}"
  data-severity="{_e(attack.severity)}"
  data-passed="{str(attack.passed).lower()}"
  data-result-label="{_e(attack.result_label)}"
  data-search="{_e(search_blob)}">
  <summary>
    <span class="badge badge-{_e(attack.severity)}">{_e(attack.severity)}</span>
    <span class="finding-title">{_e(attack.attack_id)} · {_e(attack.target)}</span>
    <span class="badge {result_badge}">{result_label}</span>
    <div class="finding-meta">
      <span>{_e(attack.vulnerability)}</span>
      <span>{attack.duration_ms:.1f} ms</span>
    </div>
  </summary>
  {body}
</details>
"""


def _render_attack_evidence(data: PreparedReport) -> str:
    if not data.attack_evidence:
        cards = '<div class="empty-state">No attack evidence recorded.</div>'
    else:
        cards = "\n".join(_render_evidence_card(a) for a in data.attack_evidence)
    return f"""
<section id="attack-evidence">
  <h2>Attack Evidence</h2>
  <p class="filter-meta" id="evidence-filter-meta">
    Search and filters above also apply to attack evidence.
  </p>
  <div class="evidence-list" id="evidence-list">
    {cards}
  </div>
</section>
"""


def render_html(data: PreparedReport) -> str:
    """Assemble a complete standalone HTML document."""
    report_json = data.to_json()
    # Embed as a JS assignment; JSON is safe inside a <script> when not closed by </script>.
    safe_json = report_json.replace("</", "<\\/")

    s = data.executive_summary
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Campaign report: {_e(s.campaign_name)}</title>
<style>
{CSS}
</style>
</head>
<body>
<button type="button" class="btn menu-toggle no-print" id="menu-toggle" aria-label="Open navigation">☰ Menu</button>
<div class="sidebar-backdrop" id="sidebar-backdrop"></div>
<div class="app">
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-brand">
      LLM Red Team Firewall
      <span>Security campaign report</span>
    </div>
    <nav aria-label="Report sections">
      <a href="#executive-summary">Executive Summary</a>
      <a href="#statistics">Statistics</a>
      <a href="#charts">Charts</a>
      <a href="#vulnerabilities">Vulnerabilities</a>
      <a href="#findings">Findings</a>
      <a href="#attack-evidence">Attack Evidence</a>
    </nav>
    <div class="sidebar-actions no-print">
      <button type="button" class="btn btn-primary" id="export-html">Export HTML</button>
      <button type="button" class="btn" id="export-print">Print / PDF</button>
      <button type="button" class="btn" id="theme-toggle">Toggle theme</button>
    </div>
  </aside>
  <main class="main">
    <header class="page-header">
      <div>
        <h1>{_e(s.campaign_name)}</h1>
        <p class="subtitle">
          {_e(s.started_at)} · {s.total_attacks} attacks ·
          {s.total_findings} findings · success rate {_pct(s.success_rate)}
        </p>
      </div>
    </header>
    {_render_executive_summary(data)}
    {_render_statistics(data)}
    {_render_charts()}
    {_render_vulnerabilities(data)}
    {_render_findings(data)}
    {_render_attack_evidence(data)}
  </main>
</div>
<script>
window.__REPORT_DATA__ = {safe_json};
{JS}
</script>
</body>
</html>
"""
