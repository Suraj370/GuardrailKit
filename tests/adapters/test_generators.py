"""Generator adapters: DummyAttackGenerator is functional, Garak is a stub."""

from __future__ import annotations

import pytest

from llm_redteam_firewall.adapters.generators.dummy_generator import DummyAttackGenerator
from llm_redteam_firewall.adapters.generators.garak_generator import GarakAttackGenerator
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


def test_garak_generator_is_registered_but_not_implemented(vulnerability: Vulnerability) -> None:
    assert GENERATORS.get("garak") is GarakAttackGenerator
    with pytest.raises(NotImplementedError):
        GarakAttackGenerator().generate(vulnerability, max_attacks=1)
