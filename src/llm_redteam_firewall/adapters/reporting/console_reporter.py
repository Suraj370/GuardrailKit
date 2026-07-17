"""ConsoleReporter: the reference Reporter implementation.

Prints a short human-readable summary of a campaign result to stdout.
Formatting only — no grading or business logic lives here.
"""

from __future__ import annotations

from llm_redteam_firewall.domain.models import CampaignResult
from llm_redteam_firewall.plugins import REPORTERS


@REPORTERS.register("console")
class ConsoleReporter:
    """Prints a plain-text campaign summary to stdout."""

    name = "console"

    def report(self, result: CampaignResult) -> None:
        vulnerable = result.vulnerable_findings
        print(f"Campaign: {result.campaign_name}")
        print(f"  attacks run   : {result.total_attacks}")
        print(f"  vulnerable    : {len(vulnerable)}")
        print(f"  pass rate     : {result.pass_rate:.0%}")
        for finding in vulnerable:
            print(
                f"  [{finding.severity.value.upper()}] {finding.vulnerability.name} "
                f"({finding.vulnerability.category}) - attack {finding.attack.id}"
            )
