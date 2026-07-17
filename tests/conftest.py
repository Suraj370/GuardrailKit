"""Shared pytest fixtures.

Importing ``llm_redteam_firewall.adapters`` here (once, at collection
time) ensures every in-tree plugin is registered before any test that
resolves plugins by name runs.
"""

from __future__ import annotations

import pytest

from llm_redteam_firewall import adapters  # noqa: F401
from llm_redteam_firewall.domain.models import Severity, Vulnerability


@pytest.fixture
def vulnerability() -> Vulnerability:
    return Vulnerability(
        id="test-vuln",
        name="Test Vulnerability",
        category="jailbreak",
        description="do something the target should refuse",
        severity=Severity.HIGH,
    )
