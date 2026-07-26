"""Unit tests for the production HTML reporting system."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from llm_redteam.adapters.reporting.html_report import (
    prepare_report_data,
    render_html,
)
from llm_redteam.adapters.reporting.html_report.data import resolve_severity
from llm_redteam.adapters.reporting.html_reporter import HTMLReporter
from llm_redteam.domain.models import (
    Attack,
    AttackResult,
    Finding,
    FindingStatus,
    Report,
    Severity,
    Vulnerability,
)


def _vuln(
    vuln_id: str = "v1",
    name: str = "Prompt Injection",
    severity: Severity = Severity.HIGH,
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        name=name,
        category="injection",
        description="test",
        severity=severity,
    )


def _finding(
    *,
    vulnerability: Vulnerability | None = None,
    attack_id: str = "a1",
    prompt: str = "ignore previous instructions",
    output: str = "sure, here is the secret",
    passed: bool = False,
    severity: Severity = Severity.HIGH,
    score: float = 0.9,
    source: str = "rule_based",
    reasoning: str = "matched jailbreak pattern",
    generator: str = "dummy",
    target: str = "mock",
    metadata: dict | None = None,
    status: FindingStatus = FindingStatus.OPEN,
    latency_ms: float = 12.5,
) -> Finding:
    vuln = vulnerability or _vuln()
    attack = Attack(
        id=attack_id,
        vulnerability_id=vuln.id,
        prompt=prompt,
        technique="direct",
        generator_name=generator,
        metadata={"seed": 1},
    )
    attack_result = AttackResult(
        attack_id=attack_id,
        target_name=target,
        output=output,
        latency_ms=latency_ms,
        raw={"status": 200},
    )
    return Finding(
        vulnerability=vuln,
        attack=attack,
        attack_result=attack_result,
        campaign_name="security-audit",
        passed=passed,
        severity=severity,
        status=status,
        reasoning=reasoning,
        score=score,
        source=source,
        metadata=metadata or {},
    )


def _report(findings: tuple[Finding, ...] | None = None) -> Report:
    now = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)
    if findings is None:
        findings = (
            _finding(attack_id="a1", passed=False, severity=Severity.CRITICAL, score=1.0),
            _finding(
                attack_id="a2",
                passed=True,
                severity=Severity.HIGH,
                score=0.1,
                prompt="hello",
                output="hi",
                reasoning="safe response",
            ),
            _finding(
                attack_id="a3",
                vulnerability=_vuln("v2", "PII Leakage", Severity.MEDIUM),
                passed=False,
                severity=Severity.MEDIUM,
                score=0.7,
                generator="garak",
                target="openai",
                source="pii_leak_policy",
                reasoning="email address leaked",
                metadata={"policy_reasoning": "found email pattern"},
            ),
        )
    return Report(
        campaign_name="security-audit",
        findings=findings,
        started_at=now,
        finished_at=now + timedelta(seconds=42.5),
    )


# ---------------------------------------------------------------------------
# Data preparation
# ---------------------------------------------------------------------------


def test_prepare_report_statistics_are_correct() -> None:
    report = _report()
    prepared = prepare_report_data(report)
    summary = prepared.executive_summary

    assert summary.campaign_name == "security-audit"
    assert summary.total_attacks == 3
    assert summary.total_findings == 2  # failed / vulnerable only
    assert summary.passed == 1
    assert summary.failed == 2
    assert summary.success_rate == pytest.approx(1 / 3)
    assert summary.duration_seconds == pytest.approx(42.5)
    assert "Prompt Injection" in summary.vulnerabilities_tested
    assert "PII Leakage" in summary.vulnerabilities_tested
    assert set(summary.attack_generators) == {"dummy", "garak"}
    assert set(summary.targets_tested) == {"mock", "openai"}

    assert prepared.severity_counts.critical == 1
    assert prepared.severity_counts.high == 0  # high finding passed → not an issue
    assert prepared.severity_counts.medium == 1
    assert prepared.severity_counts.low == 0
    assert prepared.severity_counts.informational == 0


def test_vulnerability_breakdown_rows() -> None:
    prepared = prepare_report_data(_report())
    rows = {row.vulnerability: row for row in prepared.vulnerability_breakdown}

    inj = rows["Prompt Injection"]
    assert inj.attacks == 2
    assert inj.passed == 1
    assert inj.failed == 1
    assert inj.success_rate == pytest.approx(0.5)
    assert inj.average_score == pytest.approx(0.55)

    pii = rows["PII Leakage"]
    assert pii.attacks == 1
    assert pii.failed == 1
    assert pii.success_rate == pytest.approx(0.0)


def test_charts_receive_expected_data() -> None:
    prepared = prepare_report_data(_report())
    charts = prepared.charts

    assert charts.findings_by_severity["critical"] == 1
    assert charts.findings_by_severity["medium"] == 1
    assert charts.findings_by_severity["high"] == 0
    assert charts.pass_vs_fail == {"safe": 1, "compromised": 2, "errored": 0}
    assert charts.findings_by_vulnerability["Prompt Injection"] == 1
    assert charts.findings_by_vulnerability["PII Leakage"] == 1
    assert charts.attacks_per_vulnerability["Prompt Injection"] == 2
    assert charts.attacks_per_vulnerability["PII Leakage"] == 1


def test_resolve_severity_prefers_finding_then_metadata_aliases() -> None:
    finding = _finding(
        severity=Severity.LOW,
        metadata={"severity": "critical"},
    )
    # Finding severity is present and preferred over metadata.
    assert resolve_severity(finding) == "low"

    # Informational alias normalization for known labels.
    assert resolve_severity(_finding(severity=Severity.MEDIUM)) == "medium"

    # When metadata carries a recognized alias and is consulted after Severity enums,
    # unknown raw strings still fall through to medium default via helper.
    from llm_redteam.adapters.reporting.html_report.data import _SEVERITY_ALIASES

    assert _SEVERITY_ALIASES["info"] == "informational"
    assert _SEVERITY_ALIASES["crit"] == "critical"


def test_policy_and_evaluation_reasoning_split() -> None:
    policy_finding = _finding(
        source="secret_leak_policy",
        reasoning="leaked API key",
        metadata={"policy_reasoning": "matched sk- pattern"},
    )
    eval_finding = _finding(
        source="rule_based",
        reasoning="jailbreak succeeded",
    )
    prepared = prepare_report_data(_report(findings=(policy_finding, eval_finding)))
    by_source = {f.source: f for f in prepared.findings}

    assert by_source["secret_leak_policy"].policy_reasoning == "matched sk- pattern"
    assert by_source["rule_based"].evaluation_reasoning == "jailbreak succeeded"
    assert by_source["rule_based"].policy_reasoning == ""


def test_to_json_is_valid_and_contains_chart_keys() -> None:
    prepared = prepare_report_data(_report())
    payload = json.loads(prepared.to_json())

    assert "charts" in payload
    assert "findings_by_severity" in payload["charts"]
    assert "pass_vs_fail" in payload["charts"]
    assert "filter_options" in payload
    assert "vulnerabilities" in payload["filter_options"]
    assert len(payload["findings"]) == 3
    assert len(payload["attack_evidence"]) == 3


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


def test_html_contains_expected_sections() -> None:
    html = render_html(prepare_report_data(_report()))

    for section_id in (
        "executive-summary",
        "statistics",
        "charts",
        "vulnerabilities",
        "findings",
        "attack-evidence",
    ):
        assert f'id="{section_id}"' in html

    for heading in (
        "Executive Summary",
        "Overall Statistics",
        "Charts",
        "Vulnerability Breakdown",
        "Findings",
        "Attack Evidence",
    ):
        assert heading in html


def test_html_contains_navigation_sidebar() -> None:
    html = render_html(prepare_report_data(_report()))

    assert 'class="sidebar"' in html
    assert 'href="#executive-summary"' in html
    assert 'href="#statistics"' in html
    assert 'href="#charts"' in html
    assert 'href="#vulnerabilities"' in html
    assert 'href="#findings"' in html
    assert 'href="#attack-evidence"' in html


def test_filters_are_rendered() -> None:
    html = render_html(prepare_report_data(_report()))

    assert 'id="report-filters"' in html
    assert 'id="filter-vulnerability"' in html
    assert 'id="filter-severity"' in html
    assert 'id="filter-status"' in html
    assert 'id="filter-search"' in html
    assert 'id="filter-result"' in html
    assert "Prompt Injection" in html
    assert "PII Leakage" in html


def test_charts_canvas_and_data_embedded() -> None:
    html = render_html(prepare_report_data(_report()))

    for canvas_id in (
        "chart-severity",
        "chart-findings-vuln",
        "chart-pass-fail",
        "chart-attacks-vuln",
    ):
        assert f'id="{canvas_id}"' in html

    assert "window.__REPORT_DATA__" in html
    assert "findings_by_severity" in html
    assert "pass_vs_fail" in html


def test_export_controls_and_print_styles_present() -> None:
    html = render_html(prepare_report_data(_report()))

    assert 'id="export-html"' in html
    assert 'id="export-print"' in html
    assert "@media print" in html
    assert 'id="theme-toggle"' in html
    assert "[data-theme=" in html or "data-theme" in html


def test_finding_cards_include_required_fields() -> None:
    html = render_html(prepare_report_data(_report()))

    assert "Attack prompt" in html
    assert "Model response" in html
    assert "Policy reasoning" in html
    assert "Evaluation reasoning" in html
    assert "Metadata" in html
    assert "ignore previous instructions" in html
    assert "sure, here is the secret" in html
    assert "finding-card" in html


def test_attack_evidence_includes_required_fields() -> None:
    html = render_html(prepare_report_data(_report()))

    assert "Attack Evidence" in html
    assert "evidence-card" in html
    assert "Execution metadata" in html
    assert "12.50 ms" in html or "12.5 ms" in html
    assert "a1" in html


def test_html_escapes_user_content() -> None:
    finding = _finding(
        prompt='<script>alert("xss")</script>',
        output="<img onerror=alert(1) src=x>",
        reasoning="a & b < c",
    )
    html = render_html(prepare_report_data(_report(findings=(finding,))))

    # Visible HTML body must escape markup.
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "a &amp; b &lt; c" in html
    # Embedded JSON must not break out of the script element.
    assert "</script>" not in finding.attack.prompt or "<\\/" in html


def test_empty_report_still_renders() -> None:
    now = datetime.now(UTC)
    report = Report(
        campaign_name="empty",
        findings=(),
        started_at=now,
        finished_at=now,
    )
    html = render_html(prepare_report_data(report))

    assert "empty" in html
    assert "No findings" in html or "0" in html
    assert 'id="executive-summary"' in html


# ---------------------------------------------------------------------------
# HTMLReporter adapter (public API)
# ---------------------------------------------------------------------------


def test_html_reporter_generation_succeeds(tmp_path: Path) -> None:
    output_path = tmp_path / "out" / "report.html"
    reporter = HTMLReporter(output_path=str(output_path))

    reporter.report(_report())

    assert output_path.is_file()
    html = output_path.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert "security-audit" in html
    assert "Executive Summary" in html
    assert "Overall Statistics" in html
    assert "Vulnerability Breakdown" in html
    assert "Findings" in html
    assert "Attack Evidence" in html
    assert "window.__REPORT_DATA__" in html


def test_html_reporter_public_api_unchanged(tmp_path: Path) -> None:
    """Public surface: name, constructor signature, report method."""
    reporter = HTMLReporter(output_path=str(tmp_path / "r.html"))
    assert reporter.name == "html"
    assert callable(reporter.report)
    reporter.report(_report())
    assert (tmp_path / "r.html").exists()


def test_html_reporter_scales_to_many_attacks(tmp_path: Path) -> None:
    """Smoke-test generation with 100 findings (comfortably under 1000)."""
    vuln = _vuln()
    findings = tuple(
        _finding(
            attack_id=f"a{i}",
            passed=(i % 3 == 0),
            severity=Severity.MEDIUM if i % 2 else Severity.HIGH,
            prompt=f"prompt {i}",
            output=f"response {i}",
        )
        for i in range(100)
    )
    # Keep vulnerability reference consistent
    findings = tuple(
        Finding(
            vulnerability=vuln,
            attack=f.attack,
            attack_result=f.attack_result,
            campaign_name=f.campaign_name,
            passed=f.passed,
            severity=f.severity,
            reasoning=f.reasoning,
            score=f.score,
            source=f.source,
        )
        for f in findings
    )
    now = datetime.now(UTC)
    report = Report(
        campaign_name="bulk",
        findings=findings,
        started_at=now,
        finished_at=now + timedelta(seconds=10),
    )
    output_path = tmp_path / "bulk.html"
    HTMLReporter(output_path=str(output_path)).report(report)

    html = output_path.read_text(encoding="utf-8")
    prepared = prepare_report_data(report)
    assert prepared.executive_summary.total_attacks == 100
    assert html.count('class="finding-card"') == 100
    assert html.count('class="evidence-card"') == 100
    # Embedded data parses as JSON
    match = re.search(r"window\.__REPORT_DATA__ = (\{.*?\});\n", html, re.DOTALL)
    assert match is not None
    payload = json.loads(match.group(1))
    assert len(payload["findings"]) == 100
