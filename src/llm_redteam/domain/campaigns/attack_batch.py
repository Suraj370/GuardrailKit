"""AttackBatch: a plannable, ordered group of Attacks with its own execution knobs.

This is planning data only. Nothing in this module runs an attack,
retries a failure, enforces a timeout, or limits concurrency — those
remain :class:`~llm_redteam.application.execution_engine.ExecutionEngine`'s
job, unchanged. An ``AttackBatch`` exists so a future scheduler has
somewhere to *read* per-group intent (strategy, retries, timeout,
concurrency cap) instead of that intent being implicit in a flat
``list[Attack]``.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from llm_redteam.domain.models import Attack


class ExecutionStrategy(StrEnum):
    """Declared intent for how a batch's (or campaign's) attacks should run.

    Descriptive only today: no scheduler reads this field yet. It lets
    an :class:`AttackBatch` / :class:`~.attack_campaign.AttackCampaign`
    state *how it wants to run* now, ahead of anything that acts on it.
    """

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Declared retry intent for a batch. Not yet enforced by any engine.

    ``max_retries=0`` (the default) means "no retries", matching
    today's actual behavior: :class:`~llm_redteam.application.execution_engine.ExecutionEngine`
    does not retry failed executions.
    """

    max_retries: int = 0
    backoff_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class AttackBatch:
    """One or more :class:`Attack` objects planned to run together.

    Immutable and self-contained, like ``Attack`` itself. Flattening a
    batch back into a plain ``tuple[Attack, ...]`` (via
    :class:`~.attack_campaign.AttackCampaign.attacks`) recovers exactly
    the shape :class:`~llm_redteam.application.execution_engine.ExecutionEngine.run`
    already accepts, so introducing this type changes nothing about
    how attacks actually execute.
    """

    attacks: tuple[Attack, ...]
    execution_strategy: ExecutionStrategy = ExecutionStrategy.SEQUENTIAL
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    timeout_seconds: float | None = None
    max_concurrency: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.attacks:
            raise ValueError("AttackBatch requires at least one Attack")

    def __len__(self) -> int:
        return len(self.attacks)

    def __iter__(self) -> Iterator[Attack]:
        return iter(self.attacks)
