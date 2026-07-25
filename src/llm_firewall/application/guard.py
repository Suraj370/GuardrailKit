"""FirewallGuard: runs every configured Policy over one inspection and decides.

Depends only on domain ports/models — callers inject the concrete
policy list (typically ``POLICIES.all()`` from the plugin registry).
"""

from __future__ import annotations

from collections.abc import Sequence

from llm_firewall.domain.errors import PolicyExecutionError
from llm_firewall.domain.models import (
    Decision,
    Finding,
    InspectionContext,
    InspectionResult,
    Severity,
)
from llm_firewall.domain.ports import Policy


class FirewallGuard:
    """Evaluates an :class:`InspectionContext` against a set of :class:`Policy` rules.

    ``block_severity`` is the minimum finding severity that flips the
    decision to :attr:`Decision.BLOCK`; anything below that but at or
    above ``flag_severity`` is surfaced as :attr:`Decision.FLAG` (allowed,
    but worth logging/alerting on). A clean inspection is always
    :attr:`Decision.ALLOW`.

    Policies run cheap-first: :meth:`__init__` stable-sorts ``policies``
    so any with :attr:`Policy.expensive` set run after the rest.
    :meth:`inspect` then stops early once the findings so far already
    guarantee ``BLOCK`` -- ``BLOCK`` is the worst possible outcome, so
    no later policy's findings could change the decision anyway. This
    means an expensive (e.g. LLM-backed) policy is skipped whenever a
    cheap one already produced a block-worthy finding.
    """

    def __init__(
        self,
        policies: Sequence[Policy] = (),
        *,
        block_severity: Severity = Severity.HIGH,
        flag_severity: Severity = Severity.LOW,
    ) -> None:
        self._policies: tuple[Policy, ...] = tuple(
            sorted(policies, key=lambda policy: policy.expensive)
        )
        self._block_severity = block_severity
        self._flag_severity = flag_severity

    @property
    def policies(self) -> tuple[Policy, ...]:
        """The policies this guard will run, cheap ones first."""
        return self._policies

    def inspect(self, context: InspectionContext) -> InspectionResult:
        """Run policies over ``context``, stopping early once ``BLOCK`` is already locked in."""
        findings: list[Finding] = []
        max_rank = -1
        for policy in self._policies:
            if max_rank >= self._block_severity.rank:
                break

            try:
                policy_findings = policy.evaluate(context)
            except Exception as exc:  # noqa: BLE001 - re-raised as a domain-level error
                raise PolicyExecutionError(f"policy {policy.name!r} failed: {exc}") from exc

            findings.extend(policy_findings)
            for finding in policy_findings:
                max_rank = max(max_rank, finding.severity.rank)

        return InspectionResult(
            decision=self._decide(findings),
            context=context,
            findings=tuple(findings),
        )

    async def ainspect(self, context: InspectionContext) -> InspectionResult:
        """Async counterpart to :meth:`inspect` -- same cheap-first ordering and early-exit.

        Awaits each policy's :meth:`~llm_firewall.domain.ports.Policy.aevaluate`
        instead of calling :meth:`~llm_firewall.domain.ports.Policy.evaluate`
        directly, so a policy doing real async I/O (e.g. an LLM call) runs
        natively on the caller's event loop instead of needing a thread-pool
        detour -- see :meth:`Policy.aevaluate` for why that detour is
        unsafe under concurrent callers.
        """
        findings: list[Finding] = []
        max_rank = -1
        for policy in self._policies:
            if max_rank >= self._block_severity.rank:
                break

            try:
                policy_findings = await policy.aevaluate(context)
            except Exception as exc:  # noqa: BLE001 - re-raised as a domain-level error
                raise PolicyExecutionError(f"policy {policy.name!r} failed: {exc}") from exc

            findings.extend(policy_findings)
            for finding in policy_findings:
                max_rank = max(max_rank, finding.severity.rank)

        return InspectionResult(
            decision=self._decide(findings),
            context=context,
            findings=tuple(findings),
        )

    def _decide(self, findings: list[Finding]) -> Decision:
        if not findings:
            return Decision.ALLOW
        max_rank = max(f.severity.rank for f in findings)
        if max_rank >= self._block_severity.rank:
            return Decision.BLOCK
        if max_rank >= self._flag_severity.rank:
            return Decision.FLAG
        return Decision.ALLOW
