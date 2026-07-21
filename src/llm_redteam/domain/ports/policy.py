"""Policy interface: rule-based (or later ML) checks over attack/response pairs.

Single responsibility: inspect one :class:`~llm_redteam.domain.models.attack.Attack`
and its :class:`~llm_redteam.domain.models.response.Response` and
return zero or more :class:`~llm_redteam.domain.models.finding.Finding`
objects when the policy is violated.

Policies are deliberately separate from :class:`Evaluator`:

* An evaluator grades whether a *named vulnerability probe* succeeded.
* A policy is a standing safety/firewall rule that can fire on any
  attack/response pair, independent of the campaign's vulnerability list.

This separation holds at the type level, not just conceptually: this
module never imports or constructs
:class:`~llm_redteam.domain.models.evaluation_result.EvaluationResult`
— that type belongs exclusively to :class:`Evaluator` implementations.
``Finding`` carries its verdict as plain fields, so ``_finding()`` below
builds one without depending on the Evaluator's vocabulary at all.

Rule-based adapters live under ``adapters.policies``; an LLM-judge
policy is intentionally out of scope for now.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from llm_redteam.domain.models import (
    Attack,
    Finding,
    Response,
    Severity,
    Vulnerability,
)


class Policy(ABC):
    """Inspects one attack/response pair and emits findings on violation.

    Implementations MUST be side-effect free and pure with respect to
    external I/O when rule-based. Async LLM-backed policies (if added
    later) would still implement this same synchronous contract by
    running their awaitables at the call site, or a future async
    variant of this port.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name this policy registers under."""
        raise NotImplementedError

    @property
    def severity(self) -> Severity:
        """Default severity assigned to findings this policy produces."""
        return Severity.MEDIUM

    @property
    def category(self) -> str:
        """Vulnerability category tag written into produced findings."""
        return self.name

    @abstractmethod
    def evaluate(self, attack: Attack, response: Response) -> list[Finding]:
        """Return findings for any violation of this policy.

        An empty list means the pair is clean with respect to this
        policy. Implementations should typically return no findings
        when ``response.succeeded`` is false (no content to grade).
        """
        raise NotImplementedError

    def _finding(
        self,
        attack: Attack,
        response: Response,
        *,
        reasoning: str,
        severity: Severity | None = None,
        category: str | None = None,
        campaign_name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """Build a :class:`Finding` representing a violation of this policy."""
        sev = severity if severity is not None else self.severity
        cat = category if category is not None else self.category
        return Finding(
            vulnerability=Vulnerability(
                id=f"policy:{self.name}",
                name=self.name.replace("_", " ").title(),
                category=cat,
                description=f"Rule-based policy violation: {self.name}",
                severity=sev,
            ),
            attack=attack,
            attack_result=response.to_attack_result(),
            campaign_name=campaign_name,
            passed=False,
            severity=sev,
            reasoning=reasoning,
            source=self.name,
            metadata=dict(metadata or {}),
        )
