"""Attack: an immutable probe produced by an AttackGenerator."""

from __future__ import annotations

import dataclasses

import pytest

from llm_redteam_firewall.domain.models import Attack


def test_defaults() -> None:
    attack = Attack(id="a1", vulnerability_id="v1", prompt="do the thing")

    assert attack.technique == "direct"
    assert attack.generator_name == "unknown"
    assert attack.metadata == {}


def test_is_frozen() -> None:
    attack = Attack(id="a1", vulnerability_id="v1", prompt="do the thing")

    with pytest.raises(dataclasses.FrozenInstanceError):
        attack.prompt = "changed"  # type: ignore[misc]


def test_equality_is_value_based() -> None:
    a = Attack(id="a1", vulnerability_id="v1", prompt="p")
    b = Attack(id="a1", vulnerability_id="v1", prompt="p")

    assert a == b


def test_default_metadata_dict_is_not_shared_between_instances() -> None:
    a = Attack(id="a1", vulnerability_id="v1", prompt="p")
    b = Attack(id="a2", vulnerability_id="v1", prompt="p")

    a.metadata["mutated"] = True

    assert "mutated" not in b.metadata
