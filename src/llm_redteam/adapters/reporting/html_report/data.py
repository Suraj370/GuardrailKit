"""Data preparation for HTML campaign reports.

Transforms a domain :class:`~llm_redteam.domain.models.Report`
into plain, JSON-serializable structures consumed by the HTML template
and client-side charts/filters. No I/O lives here.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from llm_redteam.domain.models import Finding, Report, Severity

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")

_SEVERITY_ALIASES: dict[str, str] = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
    "information": "informational",
}


def _isoformat(value: datetime) -> str:
    return value.isoformat()


def _duration_seconds(started_at: datetime, finished_at: datetime) -> float:
    delta = finished_at - started_at
    return max(0.0, delta.total_seconds())


def _format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    return f"{minutes}m {secs}s"


def resolve_severity(finding: Finding) -> str:
    """Return a normalized severity label for a finding.

    Prefers the finding's own severity, then vulnerability severity,
    then common metadata keys. Falls back to ``medium``.
    """
    candidates: list[Any] = [
        getattr(finding.severity, "value", finding.severity),
        getattr(finding.vulnerability.severity, "value", finding.vulnerability.severity),
        finding.metadata.get("severity"),
        finding.metadata.get("severity_level"),
        finding.metadata.get("risk"),
        finding.attack.metadata.get("severity"),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        if isinstance(candidate, Severity):
            return candidate.value
        key = str(candidate).strip().lower()
        if key in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[key]
    return Severity.MEDIUM.value


def _policy_reasoning(finding: Finding) -> str:
    meta = finding.metadata
    for key in ("policy_reasoning", "policy_reason", "policy"):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return value
    source = (finding.source or "").lower()
    if "policy" in source:
        return finding.reasoning
    return ""


def _evaluation_reasoning(finding: Finding) -> str:
    meta = finding.metadata
    for key in ("evaluation_reasoning", "evaluator_reasoning", "evaluation_reason"):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return value
    source = (finding.source or "").lower()
    if "policy" in source:
        # Keep evaluation section empty when reasoning already attributed to policy.
        return meta.get("evaluation_reasoning", "") or ""
    return finding.reasoning


def _is_errored(finding: Finding) -> bool:
    """True when execution never produced a gradable response (see ``EvaluationEngine``)."""
    return finding.metadata.get("outcome") == "errored"


def _result_label(finding: Finding) -> str:
    """The label shown for a finding's outcome: Errored, a judge/rule label, or Safe/Compromised.

    Prefers ``metadata["label"]`` (set by :class:`.CompositeJudgeEvaluator`
    as ``"safe"``/``"leaked"``/``"unsafe"``) over the plain boolean
    ``passed``, so evaluators with finer-grained verdicts show them; any
    evaluator that doesn't set a label falls back to the original
    two-state Safe/Compromised split. "Safe" covers both a correctly
    blocked attack and a response the evaluator found to be no threat.
    """
    if _is_errored(finding):
        return "Errored"
    label = finding.metadata.get("label")
    if isinstance(label, str) and label:
        return label.capitalize()
    return "Safe" if finding.passed else "Compromised"


def _safe_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _safe_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_jsonable(v) for v in value]
    return str(value)


@dataclass(frozen=True, slots=True)
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "informational": self.informational,
        }


@dataclass(frozen=True, slots=True)
class VulnerabilityBreakdownRow:
    vulnerability: str
    vulnerability_id: str
    attacks: int
    passed: int
    failed: int
    errored: int
    success_rate: float
    average_score: float | None


@dataclass(frozen=True, slots=True)
class FindingView:
    id: str
    vulnerability: str
    vulnerability_id: str
    severity: str
    status: str
    passed: bool
    status_label: str
    attack_prompt: str
    model_response: str
    policy_reasoning: str
    evaluation_reasoning: str
    metadata: dict[str, Any]
    timestamp: str
    score: float
    source: str
    attack_id: str
    target: str
    generator: str
    technique: str


@dataclass(frozen=True, slots=True)
class AttackEvidenceView:
    attack_id: str
    prompt: str
    target: str
    response: str
    execution_metadata: dict[str, Any]
    duration_ms: float
    vulnerability: str
    vulnerability_id: str
    error: str | None
    generator: str
    finding_id: str
    passed: bool
    result_label: str
    severity: str


@dataclass(frozen=True, slots=True)
class ExecutiveSummary:
    campaign_name: str
    started_at: str
    finished_at: str
    duration_seconds: float
    duration_display: str
    total_attacks: int
    total_findings: int
    passed: int
    failed: int
    errored: int
    success_rate: float
    vulnerabilities_tested: tuple[str, ...]
    attack_generators: tuple[str, ...]
    targets_tested: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChartData:
    findings_by_severity: dict[str, int]
    findings_by_vulnerability: dict[str, int]
    pass_vs_fail: dict[str, int]
    attacks_per_vulnerability: dict[str, int]


@dataclass(frozen=True, slots=True)
class PreparedReport:
    """Fully prepared, presentation-ready report payload."""

    executive_summary: ExecutiveSummary
    severity_counts: SeverityCounts
    vulnerability_breakdown: tuple[VulnerabilityBreakdownRow, ...]
    findings: tuple[FindingView, ...]
    attack_evidence: tuple[AttackEvidenceView, ...]
    charts: ChartData
    filter_options: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize chart/filter payload for embedding in the HTML page."""
        payload = {
            "executive_summary": asdict(self.executive_summary),
            "severity_counts": self.severity_counts.as_dict(),
            "vulnerability_breakdown": [asdict(row) for row in self.vulnerability_breakdown],
            "findings": [asdict(f) for f in self.findings],
            "attack_evidence": [asdict(a) for a in self.attack_evidence],
            "charts": asdict(self.charts),
            "filter_options": {k: list(v) for k, v in self.filter_options.items()},
        }
        return json.dumps(payload, default=str, ensure_ascii=False)


def prepare_report_data(report: Report) -> PreparedReport:
    """Build presentation data from a domain :class:`Report`."""
    findings = report.findings
    # Errored findings (execution never produced a gradable response —
    # see EvaluationEngine) are excluded from pass/fail/success-rate math
    # so unrelated infra failures (timeouts, rate limits) can't inflate
    # the Safe count with attacks that were never actually graded.
    graded_findings = tuple(f for f in findings if not _is_errored(f))
    errored = len(findings) - len(graded_findings)
    passed = sum(1 for f in graded_findings if f.passed)
    failed = len(graded_findings) - passed
    # "Findings" in security-report sense: confirmed issues (failed / vulnerable).
    issue_findings = tuple(f for f in graded_findings if f.is_vulnerable)
    total_findings = len(issue_findings)

    severity_counter: Counter[str] = Counter()
    for finding in issue_findings:
        severity_counter[resolve_severity(finding)] += 1
    severity_counts = SeverityCounts(
        critical=severity_counter.get("critical", 0),
        high=severity_counter.get("high", 0),
        medium=severity_counter.get("medium", 0),
        low=severity_counter.get("low", 0),
        informational=severity_counter.get("informational", 0),
    )

    vuln_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "name": "",
            "id": "",
            "attacks": 0,
            "passed": 0,
            "failed": 0,
            "errored": 0,
            "scores": [],
        }
    )
    for finding in findings:
        key = finding.vulnerability.id
        bucket = vuln_stats[key]
        bucket["name"] = finding.vulnerability.name
        bucket["id"] = finding.vulnerability.id
        bucket["attacks"] += 1
        if _is_errored(finding):
            bucket["errored"] += 1
        elif finding.passed:
            bucket["passed"] += 1
        else:
            bucket["failed"] += 1
        bucket["scores"].append(finding.score)

    breakdown_rows: list[VulnerabilityBreakdownRow] = []
    for key in sorted(vuln_stats.keys(), key=lambda k: vuln_stats[k]["name"].lower()):
        bucket = vuln_stats[key]
        attacks = bucket["attacks"]
        graded = attacks - bucket["errored"]
        scores: list[float] = bucket["scores"]
        avg_score = (sum(scores) / len(scores)) if scores else None
        success_rate = (bucket["passed"] / graded) if graded else 1.0
        breakdown_rows.append(
            VulnerabilityBreakdownRow(
                vulnerability=bucket["name"],
                vulnerability_id=bucket["id"],
                attacks=attacks,
                passed=bucket["passed"],
                failed=bucket["failed"],
                errored=bucket["errored"],
                success_rate=success_rate,
                average_score=avg_score,
            )
        )

    finding_views: list[FindingView] = []
    attack_views: list[AttackEvidenceView] = []
    for finding in findings:
        severity = resolve_severity(finding)
        status_label = _result_label(finding)
        metadata = _safe_jsonable(dict(finding.metadata))
        if not isinstance(metadata, dict):
            metadata = {"value": metadata}

        finding_views.append(
            FindingView(
                id=finding.id,
                vulnerability=finding.vulnerability.name,
                vulnerability_id=finding.vulnerability.id,
                severity=severity,
                status=finding.status.value
                if hasattr(finding.status, "value")
                else str(finding.status),
                passed=finding.passed,
                status_label=status_label,
                attack_prompt=finding.attack.prompt,
                model_response=finding.attack_result.output,
                policy_reasoning=_policy_reasoning(finding),
                evaluation_reasoning=_evaluation_reasoning(finding),
                metadata=metadata,
                timestamp=_isoformat(finding.created_at),
                score=finding.score,
                source=finding.source,
                attack_id=finding.attack.id,
                target=finding.attack_result.target_name,
                generator=finding.attack.generator_name,
                technique=finding.attack.technique,
            )
        )

        exec_meta = {
            "latency_ms": finding.attack_result.latency_ms,
            "error": finding.attack_result.error,
            "succeeded": finding.attack_result.succeeded,
            "raw": _safe_jsonable(finding.attack_result.raw),
            "attack_metadata": _safe_jsonable(dict(finding.attack.metadata)),
            "technique": finding.attack.technique,
            "generator": finding.attack.generator_name,
        }
        attack_views.append(
            AttackEvidenceView(
                attack_id=finding.attack.id,
                prompt=finding.attack.prompt,
                target=finding.attack_result.target_name,
                response=finding.attack_result.output,
                execution_metadata=exec_meta,
                duration_ms=float(finding.attack_result.latency_ms),
                vulnerability=finding.vulnerability.name,
                vulnerability_id=finding.vulnerability.id,
                error=finding.attack_result.error,
                generator=finding.attack.generator_name,
                finding_id=finding.id,
                passed=finding.passed,
                result_label=status_label,
                severity=severity,
            )
        )

    vulnerabilities_tested = tuple(sorted({f.vulnerability.name for f in findings}, key=str.lower))
    attack_generators = tuple(
        sorted(
            {f.attack.generator_name for f in findings if f.attack.generator_name}, key=str.lower
        )
    )
    targets_tested = tuple(
        sorted(
            {f.attack_result.target_name for f in findings if f.attack_result.target_name},
            key=str.lower,
        )
    )

    duration_s = _duration_seconds(report.started_at, report.finished_at)
    executive = ExecutiveSummary(
        campaign_name=report.campaign_name,
        started_at=_isoformat(report.started_at),
        finished_at=_isoformat(report.finished_at),
        duration_seconds=duration_s,
        duration_display=_format_duration(duration_s),
        total_attacks=report.total_attacks,
        total_findings=total_findings,
        passed=passed,
        failed=failed,
        errored=errored,
        success_rate=(passed / len(graded_findings)) if graded_findings else 1.0,
        vulnerabilities_tested=vulnerabilities_tested,
        attack_generators=attack_generators,
        targets_tested=targets_tested,
    )

    findings_by_severity = {level: severity_counter.get(level, 0) for level in _SEVERITY_ORDER}
    findings_by_vuln: dict[str, int] = Counter(f.vulnerability.name for f in issue_findings)
    attacks_per_vuln: dict[str, int] = Counter(f.vulnerability.name for f in findings)

    charts = ChartData(
        findings_by_severity=findings_by_severity,
        findings_by_vulnerability=dict(sorted(findings_by_vuln.items())),
        pass_vs_fail={"safe": passed, "compromised": failed, "errored": errored},
        attacks_per_vulnerability=dict(sorted(attacks_per_vuln.items())),
    )

    filter_options = {
        "vulnerabilities": vulnerabilities_tested,
        "severities": tuple(
            level
            for level in _SEVERITY_ORDER
            if any(resolve_severity(f) == level for f in findings)
        )
        or ("medium",),
        "statuses": tuple(
            sorted(
                {f.status.value if hasattr(f.status, "value") else str(f.status) for f in findings}
            )
        ),
        "result_labels": tuple(sorted({fv.status_label for fv in finding_views})),
    }

    return PreparedReport(
        executive_summary=executive,
        severity_counts=severity_counts,
        vulnerability_breakdown=tuple(breakdown_rows),
        findings=tuple(finding_views),
        attack_evidence=tuple(attack_views),
        charts=charts,
        filter_options=filter_options,
    )
