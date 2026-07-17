"""Evaluator port: grades whether an attack defeated the target."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_redteam_firewall.domain.models import Attack, AttackResult, EvaluationResult, Vulnerability


@runtime_checkable
class Evaluator(Protocol):
    """Scores a single attack/result pair against a vulnerability.

    Async because realistic evaluators (LLM-as-judge, moderation APIs)
    make network calls; rule-based evaluators can implement this with
    a trivial coroutine body.
    """

    name: str

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
        ...
