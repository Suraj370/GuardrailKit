"""MixedAttackGenerator: routes false_positive_check to genuine prompts, else delegates.

:class:`~llm_redteam.application.campaign_orchestrator.CampaignOrchestrator`
uses exactly one :class:`~llm_redteam.domain.ports.AttackGenerator` for
every vulnerability in a campaign (see ``self._generator.generate(...)``)
-- there's no per-vulnerability generator override in the config schema.
That's fine as long as a campaign only probes for real vulnerabilities,
but it breaks the moment ``false_positive_check`` rides along in the same
run: a real attack generator (garak, dummy, ...) doesn't know how to
produce "genuine traffic," and :class:`~.genuine_generator.GenuinePromptGenerator`
only knows how to produce genuine traffic, not real attacks.

This wraps another generator and dispatches by
``vulnerability.category`` -- the same way
:class:`~llm_redteam.adapters.evaluators.firewall_aware_evaluator.FirewallAwareEvaluator`
dispatches by category on the evaluation side -- so one campaign config
can mix real attacks with false-positive checks without either generator
needing to know the other exists.
"""

from __future__ import annotations

from llm_redteam.domain.models import Attack, Vulnerability
from llm_redteam.domain.ports import AttackGenerator
from llm_redteam.plugins import GENERATORS

from .genuine_generator import FALSE_POSITIVE_CATEGORY, GenuinePromptGenerator


class MixedAttackGenerator(AttackGenerator):
    """Routes ``false_positive_check`` to genuine prompts, everything else to ``wrapped``."""

    name = "mixed"

    def __init__(self, wrapped: AttackGenerator) -> None:
        self._wrapped = wrapped
        self._genuine = GenuinePromptGenerator()

    def generate(self, vulnerability: Vulnerability, max_attacks: int) -> list[Attack]:
        if vulnerability.category == FALSE_POSITIVE_CATEGORY:
            return self._genuine.generate(vulnerability, max_attacks)
        return self._wrapped.generate(vulnerability, max_attacks)


@GENERATORS.register("mixed")
def _build_from_config(
    *,
    wrapped_type: str = "garak",
    wrapped_params: dict[str, object] | None = None,
) -> MixedAttackGenerator:
    """YAML/CLI-safe factory for ``GENERATORS.create("mixed", ...)``."""
    wrapped = GENERATORS.create(wrapped_type, **(wrapped_params or {}))
    return MixedAttackGenerator(wrapped=wrapped)
