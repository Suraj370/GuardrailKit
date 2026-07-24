"""PromptInjectionPolicy: rule-based detection of jailbreak/injection attempts.

Unlike :class:`~llm_firewall.adapters.policies.secret_policy.SecretPolicy`
(which checks both prompt and response), this only inspects the
*prompt* — the goal is to catch an attempted attack before it ever
reaches the model.
"""

from __future__ import annotations

import re

from llm_firewall.domain.models import Finding, InspectionContext, Severity
from llm_firewall.domain.ports import Policy
from llm_firewall.plugins import POLICIES

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bignore (all|any|the) (previous|prior|above) instructions\b",
        r"\bdisregard (all|any|the) (previous|prior|above) (instructions|rules)\b",
        r"\byou are now\b.{0,30}\b(dan|jailbreak(ed)?)\b",
        r"\bpretend (that )?you (are|have) no (restrictions|rules|guidelines)\b",
        r"\bact as if you (have|had) no (content policy|restrictions|filter)\b",
        r"\breveal your (system prompt|hidden instructions)\b",
        r"\bnew instructions?\s*:\s*",
        r"\boverride (your|all) (previous )?(instructions|programming)\b",
    )
)


@POLICIES.register
class PromptInjectionPolicy(Policy):
    """Flags prompts that match common jailbreak / instruction-override phrasing."""

    name = "prompt_injection"
    severity = Severity.HIGH
    category = "prompt_injection"

    def evaluate(self, context: InspectionContext) -> list[Finding]:
        if not context.prompt.strip():
            return []

        matches = [p.pattern for p in _INJECTION_PATTERNS if p.search(context.prompt)]
        if not matches:
            return []

        return [
            self._finding(
                message="prompt matches known jailbreak/instruction-override phrasing",
                metadata={"matched_patterns": matches},
            )
        ]
