"""GarakAttackGenerator: extension-point stub, not implemented yet.

This file exists to prove out the plugin seam described in
``ARCHITECTURE.md``: it satisfies the
:class:`~llm_redteam_firewall.domain.ports.attack_generator.AttackGenerator`
protocol and registers itself under the name ``"garak"``, but raises
``NotImplementedError`` until real Garak integration is written.

When implemented, this adapter (or an equivalent shipped as a
separate ``llm-redteam-garak`` package using the entry-points
mechanism in :mod:`llm_redteam_firewall.plugins.registry`) would:

1. Map a :class:`Vulnerability.category` to one or more Garak probe
   classes.
2. Run the relevant probes to obtain candidate prompts.
3. Wrap each prompt as an :class:`Attack` with
   ``technique="garak:<probe_name>"`` and ``generator_name="garak"``.

No orchestration, execution-engine, or evaluation-engine code needs to
change to support this — only this file (or an out-of-tree package).
"""

from __future__ import annotations

from llm_redteam_firewall.domain.models import Attack, Vulnerability
from llm_redteam_firewall.plugins import GENERATORS


@GENERATORS.register("garak")
class GarakAttackGenerator:
    """Placeholder for a future Garak-probe-backed AttackGenerator."""

    name = "garak"

    def __init__(self, probe_names: list[str] | None = None) -> None:
        self._probe_names = probe_names or []

    def generate(self, vulnerability: Vulnerability, max_attacks: int) -> list[Attack]:
        raise NotImplementedError(
            "GarakAttackGenerator is a scaffold placeholder. Implement probe "
            "selection and execution here, or ship it as a separate package "
            "registered under the 'llm_redteam_firewall.generators' entry-point "
            "group instead of editing this file."
        )
