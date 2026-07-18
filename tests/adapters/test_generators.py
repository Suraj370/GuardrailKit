"""Generator adapters: DummyAttackGenerator is functional.

The Garak-backed generator has its own test suite under
``tests/adapters/generators/garak/`` (it needs mocked Garak
objects, unlike this simple dependency-free generator).
"""

from __future__ import annotations

from llm_redteam_firewall.adapters.generators.dummy_generator import DummyAttackGenerator
from llm_redteam_firewall.domain.models import Vulnerability
from llm_redteam_firewall.plugins import GENERATORS


def test_dummy_generator_respects_max_attacks(vulnerability: Vulnerability) -> None:
    generator = DummyAttackGenerator()

    attacks = generator.generate(vulnerability, max_attacks=2)

    assert len(attacks) == 2
    assert all(a.vulnerability_id == vulnerability.id for a in attacks)
    assert all(vulnerability.description in a.prompt for a in attacks)


def test_dummy_generator_is_registered_by_name() -> None:
    assert GENERATORS.get("dummy") is DummyAttackGenerator
