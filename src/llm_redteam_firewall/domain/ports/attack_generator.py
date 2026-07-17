"""AttackGenerator interface: the attack-generation abstraction.

This is the seam the whole framework is built around. The
orchestrator only ever depends on this abstract base class — never on
a concrete generator — so that swapping ``DummyAttackGenerator`` for a
``GarakAttackGenerator`` (or a fuzzing generator, an LLM-driven
generator, a dataset-replay generator, ...) is purely a config change.

Single responsibility: turn a ``Vulnerability`` into a bounded list of
``Attack``s. It knows nothing about how those attacks get executed
against a target or how the results get graded — that is the
``Target`` and ``Evaluator`` interfaces' job, respectively.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from llm_redteam_firewall.domain.models import Attack, Vulnerability


class AttackGenerator(ABC):
    """Produces candidate attacks for a given vulnerability.

    Implementations MUST be side-effect free with respect to the
    target under test — generation and execution are separate
    pipeline stages (see ``ARCHITECTURE.md``).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name this generator registers under."""
        raise NotImplementedError

    @abstractmethod
    def generate(self, vulnerability: Vulnerability, max_attacks: int) -> list[Attack]:
        """Return up to ``max_attacks`` attacks for ``vulnerability``.

        Implementations may return fewer than ``max_attacks`` (e.g. a
        static/dataset-backed generator that has exhausted its
        templates) but must never return more.
        """
        raise NotImplementedError
