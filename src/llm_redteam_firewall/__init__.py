"""llm-redteam-firewall: a pluggable LLM red-team harness.

See ``ARCHITECTURE.md`` for the full package map and dependency
direction. In short:

    domain      <- application <- adapters
                                <- config, cli, plugins (composition root)

Public API surface is intentionally small; most usage goes through
:mod:`llm_redteam_firewall.config` (build a campaign from YAML) or by
constructing :class:`llm_redteam_firewall.application.CampaignOrchestrator`
directly for programmatic use (see ``examples/run_example_campaign.py``).
"""

__version__ = "0.1.0"
