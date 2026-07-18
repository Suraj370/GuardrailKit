"""AttackBatch: an immutable, plannable group of Attacks."""

from __future__ import annotations

import dataclasses

import pytest

from llm_redteam_firewall.domain.campaigns import AttackBatch, ExecutionStrategy, RetryPolicy
from llm_redteam_firewall.domain.models import Attack


def _attack(id: str = "a1") -> Attack:
    return Attack(id=id, vulnerability_id="v1", prompt="p")


def test_defaults() -> None:
    batch = AttackBatch(attacks=(_attack(),))

    assert batch.execution_strategy == ExecutionStrategy.SEQUENTIAL
    assert batch.retry_policy == RetryPolicy(max_retries=0, backoff_seconds=0.0)
    assert batch.timeout_seconds is None
    assert batch.max_concurrency is None
    assert batch.metadata == {}


def test_requires_at_least_one_attack() -> None:
    with pytest.raises(ValueError, match="at least one Attack"):
        AttackBatch(attacks=())


def test_is_frozen() -> None:
    batch = AttackBatch(attacks=(_attack(),))

    with pytest.raises(dataclasses.FrozenInstanceError):
        batch.timeout_seconds = 5.0  # type: ignore[misc]


def test_len_and_iter_expose_attacks_in_order() -> None:
    a1, a2 = _attack("a1"), _attack("a2")
    batch = AttackBatch(attacks=(a1, a2))

    assert len(batch) == 2
    assert list(batch) == [a1, a2]


def test_supports_execution_strategy_retry_timeout_and_concurrency() -> None:
    batch = AttackBatch(
        attacks=(_attack(),),
        execution_strategy=ExecutionStrategy.PARALLEL,
        retry_policy=RetryPolicy(max_retries=3, backoff_seconds=1.5),
        timeout_seconds=30.0,
        max_concurrency=4,
        metadata={"source": "fuzzer"},
    )

    assert batch.execution_strategy == ExecutionStrategy.PARALLEL
    assert batch.retry_policy.max_retries == 3
    assert batch.retry_policy.backoff_seconds == 1.5
    assert batch.timeout_seconds == 30.0
    assert batch.max_concurrency == 4
    assert batch.metadata == {"source": "fuzzer"}


def test_default_metadata_dict_is_not_shared_between_instances() -> None:
    a = AttackBatch(attacks=(_attack("a1"),))
    b = AttackBatch(attacks=(_attack("a2"),))

    a.metadata["mutated"] = True

    assert "mutated" not in b.metadata
