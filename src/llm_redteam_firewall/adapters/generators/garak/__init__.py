"""Garak-backed AttackGenerator: reads Garak's probe corpus into Attack objects.

Importing this package registers ``GarakAttackGenerator`` under the
name ``"garak"`` with :data:`llm_redteam_firewall.plugins.GENERATORS`
— the same registry every other ``AttackGenerator`` uses, so
``generator: {type: garak}`` in a campaign YAML needs no other change
anywhere in the framework.

Importing this package does **not** require ``garak`` to be installed:
every module here only imports ``garak`` lazily, inside the methods
that actually need it (see :mod:`.probe_registry`). Only calling
those methods — which happens when a campaign actually resolves
``type: garak`` and calls ``generate()`` — raises a clear
``ConfigurationError`` if Garak is missing.

Submodules, in dependency order:

- :mod:`.models` — plain data (``GarakProbeInfo``, ``ProbeMappingRule``).
- :mod:`.probe_registry` — ``ProbeRegistry``: discovers Garak probes.
- :mod:`.probe_selector` — ``ProbeSelector``: maps a vulnerability id
  onto a filtered, sorted list of probes.
- :mod:`.mapper` — converts one probe's ``.prompts`` into ``Attack``
  objects.
- :mod:`.generator` — ``GarakAttackGenerator``, the plugin itself.
"""

from . import generator  # noqa: F401  (import for registration side effect)
from .mapper import garak_prompts_to_attacks
from .models import GarakProbeInfo, ProbeMappingRule
from .probe_registry import GarakNotInstalledError, ProbeRegistry
from .probe_selector import DEFAULT_PROBE_MAPPING, ProbeSelector

__all__ = [
    "DEFAULT_PROBE_MAPPING",
    "GarakNotInstalledError",
    "GarakProbeInfo",
    "ProbeMappingRule",
    "ProbeRegistry",
    "ProbeSelector",
    "garak_prompts_to_attacks",
    "generator",
]
