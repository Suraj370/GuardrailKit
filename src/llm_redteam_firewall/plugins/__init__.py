"""Plugin registries, one per port category.

These are the well-known extension points of the framework. Adding a
new implementation of a port means registering it under one of these
registries — either in-tree (import the module so its
``@REGISTRY.register("name")`` decorator runs) or out-of-tree via
setuptools entry points (see :mod:`.registry`).

Adding ``GarakAttackGenerator`` later means, in full::

    # in a new file, e.g. adapters/generators/garak_generator.py
    from llm_redteam_firewall.plugins import GENERATORS

    @GENERATORS.register("garak")
    class GarakAttackGenerator:
        name = "garak"
        def generate(self, vulnerability, max_attacks):
            ...  # call into garak's probe library

No change to ``application``, ``domain``, or the CLI is required.

``POLICIES`` is a :class:`PolicyRegistry` (instance collection) rather
than a factory :class:`Registry`, because the policy engine runs *all*
registered rules against each attack/response pair.
"""

from llm_redteam_firewall.domain.ports import (
    AttackGenerator,
    Evaluator,
    FindingsStorage,
    Reporter,
    Target,
)

from .policy_registry import PolicyRegistry
from .registry import Registry

GENERATORS: Registry[AttackGenerator] = Registry("generators")
TARGETS: Registry[Target] = Registry("targets")
EVALUATORS: Registry[Evaluator] = Registry("evaluators")
STORAGE: Registry[FindingsStorage] = Registry("storage")
REPORTERS: Registry[Reporter] = Registry("reporters")
POLICIES: PolicyRegistry = PolicyRegistry()

__all__ = [
    "Registry",
    "PolicyRegistry",
    "GENERATORS",
    "TARGETS",
    "EVALUATORS",
    "STORAGE",
    "REPORTERS",
    "POLICIES",
]
