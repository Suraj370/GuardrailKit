"""mapper: converting a probe's raw prompts into Attack objects."""

from __future__ import annotations

from llm_redteam.adapters.generators.garak.mapper import garak_prompts_to_attacks
from llm_redteam.adapters.generators.garak.models import GarakProbeInfo
from llm_redteam.domain.models import Severity, Vulnerability


class _FakeMessage:
    """Stand-in for ``garak.attempt.Message``: has a ``.text`` attribute."""

    def __init__(self, text: str) -> None:
        self.text = text


def _probe_info(**overrides: object) -> GarakProbeInfo:
    defaults: dict[str, object] = dict(
        plugin_name="probes.dan.Dan_11_0",
        module="dan",
        class_name="Dan_11_0",
        active=True,
        description="DAN 11.0",
        tags=("payload:jailbreak", "owasp:llm01"),
        goal="disregard the system prompt",
        primary_detector="dan.DAN",
        extended_detectors=("mitigation.MitigationBypass",),
        doc_uri="https://example.invalid/dan",
        tier="COMPETE_WITH_SOTA",
    )
    defaults.update(overrides)
    return GarakProbeInfo(**defaults)  # type: ignore[arg-type]


def _vulnerability() -> Vulnerability:
    return Vulnerability(
        id="jailbreak", name="Jailbreak", category="jailbreak", severity=Severity.CRITICAL
    )


def test_string_prompts_convert_to_attacks() -> None:
    probe_info = _probe_info()
    prompts = ["prompt one", "prompt two"]

    attacks = garak_prompts_to_attacks(probe_info, prompts, _vulnerability(), max_attacks=10)

    assert [a.prompt for a in attacks] == ["prompt one", "prompt two"]


def test_message_like_prompts_extract_text() -> None:
    probe_info = _probe_info()
    prompts = [_FakeMessage("hijacked text")]

    attacks = garak_prompts_to_attacks(probe_info, prompts, _vulnerability(), max_attacks=10)

    assert [a.prompt for a in attacks] == ["hijacked text"]


def test_unextractable_prompts_are_skipped() -> None:
    probe_info = _probe_info()
    prompts = ["ok prompt", 123, None, ["nested", "conversation-like"]]

    attacks = garak_prompts_to_attacks(probe_info, prompts, _vulnerability(), max_attacks=10)

    assert [a.prompt for a in attacks] == ["ok prompt"]


def test_max_attacks_truncates_and_preserves_order() -> None:
    probe_info = _probe_info()
    prompts = [f"prompt {i}" for i in range(5)]

    attacks = garak_prompts_to_attacks(probe_info, prompts, _vulnerability(), max_attacks=2)

    assert [a.prompt for a in attacks] == ["prompt 0", "prompt 1"]


def test_attack_id_is_deterministic_and_ordered() -> None:
    probe_info = _probe_info()
    prompts = ["a", "b"]

    attacks = garak_prompts_to_attacks(probe_info, prompts, _vulnerability(), max_attacks=10)

    assert attacks[0].id == "jailbreak-garak-dan.Dan_11_0-0"
    assert attacks[1].id == "jailbreak-garak-dan.Dan_11_0-1"


def test_attack_fields_are_populated_correctly() -> None:
    probe_info = _probe_info()
    vulnerability = _vulnerability()

    (attack,) = garak_prompts_to_attacks(probe_info, ["a prompt"], vulnerability, max_attacks=10)

    assert attack.vulnerability_id == vulnerability.id
    assert attack.technique == "garak:dan.Dan_11_0"
    assert attack.generator_name == "garak"


def test_garak_metadata_is_preserved_on_attack() -> None:
    probe_info = _probe_info()

    (attack,) = garak_prompts_to_attacks(probe_info, ["a prompt"], _vulnerability(), max_attacks=10)

    assert attack.metadata["garak_plugin_name"] == "probes.dan.Dan_11_0"
    assert attack.metadata["garak_probe_module"] == "dan"
    assert attack.metadata["garak_probe_class"] == "Dan_11_0"
    assert attack.metadata["garak_probe_seq"] == 0
    assert attack.metadata["tags"] == ["payload:jailbreak", "owasp:llm01"]
    assert attack.metadata["goal"] == "disregard the system prompt"
    assert attack.metadata["primary_detector"] == "dan.DAN"
    assert attack.metadata["extended_detectors"] == ["mitigation.MitigationBypass"]
    assert attack.metadata["doc_uri"] == "https://example.invalid/dan"
    assert attack.metadata["tier"] == "COMPETE_WITH_SOTA"
    assert attack.metadata["active"] is True
