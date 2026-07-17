"""Campaign: immutable configuration for a red-team run."""

from __future__ import annotations

import dataclasses

import pytest

from llm_redteam_firewall.domain.models import Campaign, Vulnerability


def test_defaults(vulnerability: Vulnerability) -> None:
    campaign = Campaign(name="c1", vulnerabilities=(vulnerability,))

    assert campaign.max_attacks_per_vulnerability == 5
    assert campaign.concurrency == 5
    assert campaign.description == ""


def test_is_frozen(vulnerability: Vulnerability) -> None:
    campaign = Campaign(name="c1", vulnerabilities=(vulnerability,))

    with pytest.raises(dataclasses.FrozenInstanceError):
        campaign.name = "changed"  # type: ignore[misc]


def test_vulnerabilities_is_a_tuple(vulnerability: Vulnerability) -> None:
    campaign = Campaign(name="c1", vulnerabilities=(vulnerability,))

    assert isinstance(campaign.vulnerabilities, tuple)
