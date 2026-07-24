"""SystemPromptLeakPolicy: detects the response echoing back the system prompt.

Verbatim-only by design: this looks for contiguous runs of words from
``system_prompt`` reappearing in ``response`` (a "shingle" overlap
check), not paraphrase or semantic leakage -- that's a job for a
classifier, e.g.
:class:`~llm_firewall.adapters.policies.nemo_guardrails_policy.NemoGuardrailsPolicy`.
"""

from __future__ import annotations

from llm_firewall.domain.models import Finding, InspectionContext, Severity
from llm_firewall.domain.ports import Policy
from llm_firewall.plugins import POLICIES

# Number of consecutive words that must reappear verbatim before we call
# it a leak rather than incidental phrase overlap.
_SHINGLE_SIZE = 6


def _normalize(text: str) -> str:
    return " ".join(text.lower().split())


def _shingles(text: str, size: int) -> set[str]:
    words = text.split()
    if len(words) < size:
        return set()
    return {" ".join(words[i : i + size]) for i in range(len(words) - size + 1)}


@POLICIES.register
class SystemPromptLeakPolicy(Policy):
    """Flags responses that reproduce chunks of the system prompt verbatim."""

    name = "system_prompt_leak"
    severity = Severity.HIGH
    category = "system_prompt_leak"

    def evaluate(self, context: InspectionContext) -> list[Finding]:
        if not context.system_prompt or not context.response:
            return []
        if not context.system_prompt.strip() or not context.response.strip():
            return []

        system_shingles = _shingles(_normalize(context.system_prompt), _SHINGLE_SIZE)
        response_shingles = _shingles(_normalize(context.response), _SHINGLE_SIZE)
        matched = system_shingles & response_shingles
        if not matched:
            return []

        evidence = sorted(matched, key=len, reverse=True)[:3]
        return [
            self._finding(
                message="response reproduces verbatim text from the system prompt",
                metadata={"matched_phrases": evidence},
            )
        ]
