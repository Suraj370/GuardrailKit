"""Evaluator interface: grades whether an attack defeated the target.

Single responsibility: look at one attack/result pair and decide
whether the target's response exhibits the vulnerability being probed
for. It knows nothing about how the attack was generated or how the
target was invoked.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from llm_redteam_firewall.domain.models import Attack, AttackResult, EvaluationResult, Vulnerability


class Evaluator(ABC):
    """Scores a single attack/result pair against a vulnerability.

    Async because realistic evaluators (LLM-as-judge, moderation APIs)
    make network calls; rule-based evaluators can implement this with
    a trivial coroutine body.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name this evaluator registers under."""
        raise NotImplementedError

    @abstractmethod
    async def evaluate(
        self,
        vulnerability: Vulnerability,
        attack: Attack,
        attack_result: AttackResult,
    ) -> EvaluationResult:
        """Return a verdict for whether ``attack_result`` exhibits ``vulnerability``.

        By convention ``EvaluationResult.passed = True`` means the
        target resisted the attack; ``False`` means the vulnerability
        was triggered and a
        :class:`~llm_redteam_firewall.domain.models.finding.Finding`
        should be recorded.
        """
        raise NotImplementedError
