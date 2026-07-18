"""PolicyEngine: runs every registered Policy over an attack/response pair.

Symmetric to :class:`~llm_redteam_firewall.application.evaluation_engine.EvaluationEngine`
but multi-rule: a single pair may produce findings from several policies
at once (e.g. both PII and secret leakage in one response).

Depends only on domain ports/models — callers inject the concrete policy
list (typically ``POLICIES.all()`` from the plugin registry).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from llm_redteam_firewall.domain.models import Attack, Finding, Response
from llm_redteam_firewall.domain.ports import Policy


class PolicyEngine:
    """Evaluates an attack/response pair against a set of :class:`Policy` rules.

    Construct with an explicit sequence of policies, e.g.::

        engine = PolicyEngine(POLICIES.all(), campaign_name="my-campaign")
    """

    def __init__(
        self,
        policies: Sequence[Policy] = (),
        *,
        campaign_name: str = "",
    ) -> None:
        self._policies: tuple[Policy, ...] = tuple(policies)
        self._campaign_name = campaign_name

    @property
    def policies(self) -> tuple[Policy, ...]:
        """The policies this engine will execute, in registration order."""
        return self._policies

    def evaluate(self, attack: Attack, response: Response) -> list[Finding]:
        """Run every policy and aggregate findings.

        Findings that leave ``campaign_name`` empty inherit this
        engine's configured campaign name (when set).
        """
        findings: list[Finding] = []
        for policy in self._policies:
            for finding in policy.evaluate(attack, response):
                if self._campaign_name and not finding.campaign_name:
                    finding = replace(finding, campaign_name=self._campaign_name)
                findings.append(finding)
        return findings

    def evaluate_batch(
        self,
        attacks: Sequence[Attack],
        responses: Sequence[Response],
    ) -> list[Finding]:
        """Evaluate paired attacks/responses and flatten all findings.

        Raises:
            ValueError: if the two sequences differ in length.
        """
        if len(attacks) != len(responses):
            raise ValueError(
                f"attacks/responses length mismatch: {len(attacks)} vs {len(responses)}"
            )
        findings: list[Finding] = []
        for attack, response in zip(attacks, responses, strict=True):
            findings.extend(self.evaluate(attack, response))
        return findings
