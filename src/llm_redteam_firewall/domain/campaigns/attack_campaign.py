"""AttackCampaign: the execution plan for a Campaign, as an ordered list of AttackBatch.

Sits between :class:`~llm_redteam_firewall.domain.models.campaign.Campaign`
(*what* to probe: which vulnerabilities, how many attacks each) and
:class:`~llm_redteam_firewall.application.execution_engine.ExecutionEngine`
(*how* to run one flat sequence of :class:`Attack`) as a planning layer.

Today ``CampaignOrchestrator`` still calls one
:class:`~llm_redteam_firewall.domain.ports.attack_generator.AttackGenerator`
per vulnerability exactly as before, wraps the resulting ``list[Attack]``
in a single-batch ``AttackCampaign`` via :meth:`AttackCampaign.from_attacks`,
and passes :attr:`AttackCampaign.attacks` (the flattened attack list) to
``ExecutionEngine.run`` — the same input, in the same order, that engine
already accepted. No scheduling, retrying, or concurrency logic reads
``execution_strategy``/``retry_policy``/``max_concurrency`` yet; this
type only introduces a place for that intent to live.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from llm_redteam_firewall.domain.models import Attack

from .attack_batch import AttackBatch, ExecutionStrategy


@dataclass(frozen=True, slots=True)
class AttackCampaign:
    """An ordered execution plan: a campaign's attacks, grouped into :class:`AttackBatch` objects."""

    name: str
    batches: tuple[AttackBatch, ...] = ()
    execution_strategy: ExecutionStrategy = ExecutionStrategy.SEQUENTIAL
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_attacks(
        cls,
        name: str,
        attacks: Iterable[Attack],
        *,
        execution_strategy: ExecutionStrategy = ExecutionStrategy.SEQUENTIAL,
        batch_metadata: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AttackCampaign:
        """Wrap a flat attack list (one ``AttackGenerator.generate()`` call) into a single-batch plan.

        This is the compatibility path: it preserves attack order
        exactly, so flattening the result back out via
        :attr:`attacks` reproduces the original list unchanged.
        """
        attacks_tuple = tuple(attacks)
        batches = (
            (AttackBatch(attacks=attacks_tuple, metadata=dict(batch_metadata or {})),)
            if attacks_tuple
            else ()
        )
        return cls(
            name=name,
            batches=batches,
            execution_strategy=execution_strategy,
            metadata=dict(metadata or {}),
        )

    @property
    def attacks(self) -> tuple[Attack, ...]:
        """Every attack across every batch, flattened in execution order."""
        return tuple(attack for batch in self.batches for attack in batch.attacks)

    def __iter__(self) -> Iterator[AttackBatch]:
        return iter(self.batches)

    def __len__(self) -> int:
        return len(self.batches)
