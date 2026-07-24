"""Severity: ordering invariant used by threshold checks."""

from __future__ import annotations

from llm_firewall.domain.models import Severity


def test_rank_is_low_to_critical() -> None:
    assert Severity.LOW.rank < Severity.MEDIUM.rank < Severity.HIGH.rank < Severity.CRITICAL.rank
