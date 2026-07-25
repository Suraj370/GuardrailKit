"""Generator adapters: DummyAttackGenerator is functional.

The Garak-backed generator has its own test suite under
``tests/adapters/generators/garak/`` (it needs mocked Garak
objects, unlike this simple dependency-free generator).
"""

from __future__ import annotations

from llm_redteam.adapters.generators.dummy_generator import DummyAttackGenerator
from llm_redteam.adapters.generators.genuine_generator import (
    GENUINE_PROMPTS,
    GenuinePromptGenerator,
)
from llm_redteam.adapters.generators.mixed_generator import MixedAttackGenerator
from llm_redteam.domain.models import Attack, Severity, Vulnerability
from llm_redteam.plugins import GENERATORS


def test_dummy_generator_respects_max_attacks(vulnerability: Vulnerability) -> None:
    generator = DummyAttackGenerator()

    attacks = generator.generate(vulnerability, max_attacks=2)

    assert len(attacks) == 2
    assert all(a.vulnerability_id == vulnerability.id for a in attacks)
    assert all(vulnerability.description in a.prompt for a in attacks)


def test_dummy_generator_is_registered_by_name() -> None:
    assert GENERATORS.get("dummy") is DummyAttackGenerator


def _false_positive_vulnerability() -> Vulnerability:
    return Vulnerability(
        id="false_positive_check",
        name="False Positive Check",
        category="false_positive",
        description="genuine traffic the firewall should allow",
        severity=Severity.MEDIUM,
    )


def test_genuine_generator_returns_curated_prompts() -> None:
    generator = GenuinePromptGenerator()
    vulnerability = _false_positive_vulnerability()

    attacks = generator.generate(vulnerability, max_attacks=3)

    assert len(attacks) == 3
    assert [a.prompt for a in attacks] == list(GENUINE_PROMPTS[:3])
    assert all(a.vulnerability_id == vulnerability.id for a in attacks)
    assert all(a.technique == "genuine" for a in attacks)


def test_genuine_generator_is_registered_by_name() -> None:
    assert GENERATORS.get("genuine") is GenuinePromptGenerator


def test_mixed_generator_routes_false_positive_check_to_genuine_prompts() -> None:
    wrapped = DummyAttackGenerator()
    generator = MixedAttackGenerator(wrapped=wrapped)

    attacks = generator.generate(_false_positive_vulnerability(), max_attacks=2)

    assert [a.prompt for a in attacks] == list(GENUINE_PROMPTS[:2])


def test_mixed_generator_delegates_everything_else_to_wrapped(vulnerability: Vulnerability) -> None:
    class _StubGenerator(DummyAttackGenerator):
        def generate(self, vulnerability: Vulnerability, max_attacks: int) -> list[Attack]:
            return [
                Attack(
                    id="stub-1", vulnerability_id=vulnerability.id, prompt="stub", technique="stub"
                )
            ]

    generator = MixedAttackGenerator(wrapped=_StubGenerator())

    attacks = generator.generate(vulnerability, max_attacks=5)

    assert len(attacks) == 1
    assert attacks[0].technique == "stub"


def test_mixed_generator_builds_from_registry_with_primitive_params() -> None:
    generator = GENERATORS.create("mixed", wrapped_type="dummy")

    assert isinstance(generator, MixedAttackGenerator)
