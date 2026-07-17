"""Evaluator port: grades whether an attack defeated the target."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_redteam_firewall.domain.models import Attack, Evaluation, Response, Vulnerability


@runtime_checkable
class Evaluator(Protocol):
    """Scores a single attack/response pair against a vulnerability.

    Async because realistic evaluators (LLM-as-judge, moderation APIs)
    make network calls; rule-based evaluators can implement this with
    a trivial coroutine body.
    """

    name: str

    async def evaluate(
        self,
        vulnerability: Vulnerability,
        attack: Attack,
        response: Response,
    ) -> Evaluation:
        """Return a verdict for whether ``response`` exhibits ``vulnerability``.

        By convention ``Evaluation.passed = True`` means the target
        resisted the attack; ``False`` means the vulnerability was
        triggered and a :class:`~llm_redteam_firewall.domain.models.finding.Finding`
        should be recorded.
        """
        ...
