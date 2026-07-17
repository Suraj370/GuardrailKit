"""AttackGenerator: abc.ABC contract."""

from __future__ import annotations

import pytest

from llm_redteam_firewall.adapters.generators.dummy_generator import DummyAttackGenerator
from llm_redteam_firewall.domain.models import Attack, Vulnerability
from llm_redteam_firewall.domain.ports import AttackGenerator


def test_cannot_instantiate_the_interface_directly() -> None:
    with pytest.raises(TypeError):
        AttackGenerator()  # type: ignore[abstract]


def test_subclass_missing_generate_cannot_be_instantiated() -> None:
    class _Incomplete(AttackGenerator):
        name = "incomplete"

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


def test_subclass_missing_name_cannot_be_instantiated() -> None:
    class _Incomplete(AttackGenerator):
        def generate(self, vulnerability: Vulnerability, max_attacks: int) -> list[Attack]:
            return []

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


def test_complete_subclass_can_be_instantiated_and_used(vulnerability: Vulnerability) -> None:
    class _Complete(AttackGenerator):
        name = "complete"

        def generate(self, vulnerability: Vulnerability, max_attacks: int) -> list[Attack]:
            return [Attack(id="a1", vulnerability_id=vulnerability.id, prompt="p")]

    generator = _Complete()

    assert isinstance(generator, AttackGenerator)
    assert generator.generate(vulnerability, 1)[0].id == "a1"


def test_dummy_attack_generator_satisfies_the_interface() -> None:
    assert isinstance(DummyAttackGenerator(), AttackGenerator)
