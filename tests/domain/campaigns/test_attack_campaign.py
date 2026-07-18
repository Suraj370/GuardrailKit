"""AttackCampaign: an ordered execution plan of AttackBatch objects."""

from __future__ import annotations

import dataclasses

import pytest

from llm_redteam_firewall.domain.campaigns import AttackBatch, AttackCampaign, ExecutionStrategy
from llm_redteam_firewall.domain.models import Attack


def _attack(id: str) -> Attack:
    return Attack(id=id, vulnerability_id="v1", prompt="p")


def test_defaults() -> None:
    campaign = AttackCampaign(name="c1")

    assert campaign.batches == ()
    assert campaign.execution_strategy == ExecutionStrategy.SEQUENTIAL
    assert campaign.metadata == {}
    assert campaign.attacks == ()


def test_is_frozen() -> None:
    campaign = AttackCampaign(name="c1")

    with pytest.raises(dataclasses.FrozenInstanceError):
        campaign.name = "changed"  # type: ignore[misc]


def test_from_attacks_wraps_a_flat_list_in_one_batch() -> None:
    a1, a2, a3 = _attack("a1"), _attack("a2"), _attack("a3")

    campaign = AttackCampaign.from_attacks("c1", [a1, a2, a3])

    assert len(campaign) == 1
    assert campaign.batches[0].attacks == (a1, a2, a3)


def test_from_attacks_with_empty_list_produces_no_batches() -> None:
    campaign = AttackCampaign.from_attacks("c1", [])

    assert campaign.batches == ()
    assert campaign.attacks == ()


def test_attacks_property_flattens_batches_in_order() -> None:
    a1, a2, a3, a4 = _attack("a1"), _attack("a2"), _attack("a3"), _attack("a4")
    campaign = AttackCampaign(
        name="c1",
        batches=(AttackBatch(attacks=(a1, a2)), AttackBatch(attacks=(a3, a4))),
    )

    assert campaign.attacks == (a1, a2, a3, a4)


def test_iterating_a_campaign_yields_its_batches() -> None:
    batch1 = AttackBatch(attacks=(_attack("a1"),))
    batch2 = AttackBatch(attacks=(_attack("a2"),))
    campaign = AttackCampaign(name="c1", batches=(batch1, batch2))

    assert list(campaign) == [batch1, batch2]
    assert len(campaign) == 2


def test_from_attacks_preserves_order_exactly_for_execution_engine_compatibility() -> None:
    attacks = [_attack(f"a{i}") for i in range(5)]

    campaign = AttackCampaign.from_attacks("c1", attacks)

    assert campaign.attacks == tuple(attacks)


def test_from_attacks_supports_execution_strategy_and_metadata() -> None:
    campaign = AttackCampaign.from_attacks(
        "c1",
        [_attack("a1")],
        execution_strategy=ExecutionStrategy.PARALLEL,
        batch_metadata={"batch_source": "fuzzer"},
        metadata={"campaign_owner": "redteam"},
    )

    assert campaign.execution_strategy == ExecutionStrategy.PARALLEL
    assert campaign.metadata == {"campaign_owner": "redteam"}
    assert campaign.batches[0].metadata == {"batch_source": "fuzzer"}
