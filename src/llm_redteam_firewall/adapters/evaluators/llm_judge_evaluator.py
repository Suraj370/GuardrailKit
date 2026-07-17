"""LLMJudgeEvaluator: extension-point stub for model-graded evaluation.

Not implemented. When implemented, this would send the vulnerability
description, attack prompt, and target response to a judge model with
a grading rubric and parse a structured verdict back into an
``EvaluationResult``. No dependency on a specific LLM SDK is declared
here; add one under an appropriate extra in ``pyproject.toml``.
"""

from __future__ import annotations

from llm_redteam_firewall.domain.models import Attack, AttackResult, EvaluationResult, Vulnerability
from llm_redteam_firewall.plugins import EVALUATORS


@EVALUATORS.register("llm_judge")
class LLMJudgeEvaluator:
    """Placeholder for a future LLM-as-judge Evaluator."""

    name = "llm_judge"

    def __init__(self, judge_model: str) -> None:
        self._judge_model = judge_model

    async def evaluate(
        self,
        vulnerability: Vulnerability,
        attack: Attack,
        attack_result: AttackResult,
    ) -> EvaluationResult:
        raise NotImplementedError(
            "LLMJudgeEvaluator is a scaffold placeholder. Implement by "
            "prompting self._judge_model with a grading rubric derived from "
            "vulnerability, attack, and attack_result, then parsing its verdict."
        )
