"""AttackGenerator port: the attack-generation interface.

This is the seam the whole framework is built around. The
orchestrator only ever depends on this ``Protocol`` — never on a
concrete generator — so that swapping ``DummyAttackGenerator`` for a
``GarakAttackGenerator`` (or a fuzzing generator, an LLM-driven
generator, a dataset-replay generator, ...) is purely a config change.

Design note: ``generate`` is synchronous and takes no ``ExecutionContext``.
Generators that need I/O (e.g. calling a model to mutate seed prompts,
or shelling out to an external tool like Garak) are expected to manage
that internally rather than push async concerns onto every trivial
generator like :class:`DummyAttackGenerator`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_redteam_firewall.domain.models import Attack, Vulnerability


@runtime_checkable
class AttackGenerator(Protocol):
    """Produces candidate attacks for a given vulnerability.

    Implementations MUST be side-effect free with respect to the
    target under test — generation and execution are separate
    pipeline stages (see ``ARCHITECTURE.md``).
    """

    name: str

    def generate(self, vulnerability: Vulnerability, max_attacks: int) -> list[Attack]:
        """Return up to ``max_attacks`` attacks for ``vulnerability``.

        Implementations may return fewer than ``max_attacks`` (e.g. a
        static/dataset-backed generator that has exhausted its
        templates) but must never return more.
        """
        ...
