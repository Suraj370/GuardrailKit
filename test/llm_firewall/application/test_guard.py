"""FirewallGuard: aggregates findings and reduces them to a Decision."""

from __future__ import annotations

import pytest

from llm_firewall.application import FirewallGuard
from llm_firewall.domain.errors import PolicyExecutionError
from llm_firewall.domain.models import Decision, Finding, InspectionContext, Severity
from llm_firewall.domain.ports import Policy
from llm_firewall.plugins import POLICIES


class _FlagPolicy(Policy):
    def __init__(self, name: str, severity: Severity = Severity.HIGH, flag: bool = True) -> None:
        self._name = name
        self._severity = severity
        self._flag = flag

    @property
    def name(self) -> str:
        return self._name

    @property
    def severity(self) -> Severity:
        return self._severity

    def evaluate(self, context: InspectionContext) -> list[Finding]:
        if not self._flag:
            return []
        return [self._finding(message=f"flagged by {self.name}")]


class _BrokenPolicy(Policy):
    name = "broken"

    def evaluate(self, context: InspectionContext) -> list[Finding]:
        raise RuntimeError("boom")


class _CountingPolicy(Policy):
    """Tracks how many times ``evaluate`` actually ran, to prove skips happened."""

    def __init__(
        self, name: str, severity: Severity = Severity.LOW, expensive: bool = False
    ) -> None:
        self._name = name
        self._severity = severity
        self._expensive = expensive
        self.call_count = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def severity(self) -> Severity:
        return self._severity

    @property
    def expensive(self) -> bool:
        return self._expensive

    def evaluate(self, context: InspectionContext) -> list[Finding]:
        self.call_count += 1
        return [self._finding(message=f"flagged by {self.name}")]


def test_inspect_aggregates_findings_from_all_policies() -> None:
    # block_severity=CRITICAL so the HIGH findings below don't trigger the
    # early-exit (that behavior has its own tests further down) and this
    # one stays focused on aggregation.
    guard = FirewallGuard(
        [_FlagPolicy("one"), _FlagPolicy("two"), _FlagPolicy("skip", flag=False)],
        block_severity=Severity.CRITICAL,
    )

    result = guard.inspect(InspectionContext(prompt="probe"))

    assert {f.policy for f in result.findings} == {"one", "two"}


def test_inspect_with_no_findings_allows() -> None:
    guard = FirewallGuard([_FlagPolicy("skip", flag=False)])

    result = guard.inspect(InspectionContext(prompt="probe"))

    assert result.decision == Decision.ALLOW
    assert result.findings == ()


def test_inspect_below_block_threshold_flags() -> None:
    guard = FirewallGuard([_FlagPolicy("low", severity=Severity.LOW)])

    result = guard.inspect(InspectionContext(prompt="probe"))

    assert result.decision == Decision.FLAG


def test_inspect_at_or_above_block_threshold_blocks() -> None:
    guard = FirewallGuard([_FlagPolicy("crit", severity=Severity.CRITICAL)])

    result = guard.inspect(InspectionContext(prompt="probe"))

    assert result.decision == Decision.BLOCK


def test_inspect_respects_custom_thresholds() -> None:
    guard = FirewallGuard(
        [_FlagPolicy("med", severity=Severity.MEDIUM)],
        block_severity=Severity.CRITICAL,
    )

    result = guard.inspect(InspectionContext(prompt="probe"))

    assert result.decision == Decision.FLAG


def test_inspect_wraps_policy_exceptions() -> None:
    guard = FirewallGuard([_BrokenPolicy()])

    with pytest.raises(PolicyExecutionError, match="broken"):
        guard.inspect(InspectionContext(prompt="probe"))


def test_policies_property_runs_expensive_ones_last() -> None:
    expensive = _CountingPolicy("expensive", expensive=True)
    cheap = _CountingPolicy("cheap", expensive=False)
    guard = FirewallGuard([expensive, cheap])

    assert [p.name for p in guard.policies] == ["cheap", "expensive"]


def test_inspect_runs_all_policies_when_nothing_blocks_yet() -> None:
    low1 = _CountingPolicy("low1", severity=Severity.LOW)
    low2 = _CountingPolicy("low2", severity=Severity.LOW)
    guard = FirewallGuard([low1, low2])

    result = guard.inspect(InspectionContext(prompt="probe"))

    assert result.decision == Decision.FLAG
    assert low1.call_count == 1
    assert low2.call_count == 1


def test_inspect_skips_remaining_policies_once_block_is_locked_in() -> None:
    critical = _CountingPolicy("critical", severity=Severity.CRITICAL)
    never_called = _CountingPolicy("never", severity=Severity.LOW)
    guard = FirewallGuard([critical, never_called])

    result = guard.inspect(InspectionContext(prompt="probe"))

    assert result.decision == Decision.BLOCK
    assert critical.call_count == 1
    assert never_called.call_count == 0


def test_expensive_policy_skipped_once_a_cheap_policy_already_blocks() -> None:
    expensive = _CountingPolicy("expensive", severity=Severity.CRITICAL, expensive=True)
    cheap = _CountingPolicy("cheap", severity=Severity.CRITICAL, expensive=False)
    # Constructed in "wrong" order on purpose -- FirewallGuard is responsible
    # for reordering so the cheap policy still runs first.
    guard = FirewallGuard([expensive, cheap])

    result = guard.inspect(InspectionContext(prompt="probe"))

    assert result.decision == Decision.BLOCK
    assert cheap.call_count == 1
    assert expensive.call_count == 0


def test_guard_with_builtin_policies_detects_secret_leak() -> None:
    guard = FirewallGuard(POLICIES.all())

    result = guard.inspect(
        InspectionContext(prompt="what's my key", response=f"It's sk-{'a' * 20}")
    )

    assert any(f.category == "secret_leakage" for f in result.findings)
