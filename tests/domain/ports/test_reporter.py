"""Reporter: abc.ABC contract."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from llm_redteam_firewall.adapters.reporting.console_reporter import ConsoleReporter
from llm_redteam_firewall.domain.models import Report
from llm_redteam_firewall.domain.ports import Reporter


def _report() -> Report:
    now = datetime.now(UTC)
    return Report(campaign_name="c1", findings=(), started_at=now, finished_at=now)


def test_cannot_instantiate_the_interface_directly() -> None:
    with pytest.raises(TypeError):
        Reporter()  # type: ignore[abstract]


def test_subclass_missing_report_cannot_be_instantiated() -> None:
    class _Incomplete(Reporter):
        name = "incomplete"

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


def test_subclass_missing_name_cannot_be_instantiated() -> None:
    class _Incomplete(Reporter):
        def report(self, report: Report) -> None:
            pass

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


def test_complete_subclass_can_be_instantiated_and_used() -> None:
    class _Complete(Reporter):
        name = "complete"

        def __init__(self) -> None:
            self.received: Report | None = None

        def report(self, report: Report) -> None:
            self.received = report

    reporter = _Complete()
    report = _report()

    assert isinstance(reporter, Reporter)
    reporter.report(report)
    assert reporter.received is report


def test_console_reporter_satisfies_the_interface() -> None:
    assert isinstance(ConsoleReporter(), Reporter)
