"""ProbeSelector: mapping vulnerability ids onto Garak probes."""

from __future__ import annotations

from llm_redteam_firewall.adapters.generators.garak.models import ProbeMappingRule
from llm_redteam_firewall.adapters.generators.garak.probe_registry import ProbeRegistry
from llm_redteam_firewall.adapters.generators.garak.probe_selector import (
    DEFAULT_PROBE_MAPPING,
    ProbeSelector,
    normalize_pattern,
)


def test_normalize_pattern_bare_module_name_means_every_class() -> None:
    assert normalize_pattern("dan") == "dan.*"


def test_normalize_pattern_leaves_explicit_glob_untouched() -> None:
    assert normalize_pattern("promptinject.*") == "promptinject.*"
    assert normalize_pattern("dan.Dan_11_0") == "dan.Dan_11_0"


def test_unmapped_vulnerability_id_returns_nothing(fake_garak: None) -> None:
    selector = ProbeSelector(ProbeRegistry())

    assert selector.select("not-a-mapped-vulnerability") == []


def test_select_matches_module_glob_pattern(fake_garak: None) -> None:
    registry = ProbeRegistry()
    mapping = {"jailbreak": ProbeMappingRule(include_patterns=("dan.*",))}
    selector = ProbeSelector(registry, mapping=mapping)

    selected = selector.select("jailbreak")

    assert [p.plugin_name for p in selected] == ["probes.dan.Dan_11_0"]


def test_select_bare_module_name_pattern_matches_like_glob(fake_garak: None) -> None:
    registry = ProbeRegistry()
    mapping = {"jailbreak": ProbeMappingRule(include_patterns=("dan",))}
    selector = ProbeSelector(registry, mapping=mapping)

    selected = selector.select("jailbreak")

    assert [p.plugin_name for p in selected] == ["probes.dan.Dan_11_0"]


def test_select_applies_rule_exclude_tags(fake_garak: None) -> None:
    registry = ProbeRegistry()
    mapping = {
        "jailbreak": ProbeMappingRule(
            include_patterns=("dan.*", "promptinject.*"),
            exclude_tags=("payload:jailbreak",),
        )
    }
    selector = ProbeSelector(registry, mapping=mapping)

    selected = selector.select("jailbreak")

    assert [p.plugin_name for p in selected] == ["probes.promptinject.HijackKillHumans"]


def test_select_merges_caller_include_tags_with_rule(fake_garak: None) -> None:
    registry = ProbeRegistry()
    mapping = {
        "jailbreak": ProbeMappingRule(include_patterns=("dan.*", "promptinject.*", "encoding.*"))
    }
    selector = ProbeSelector(registry, mapping=mapping)

    # Only dan.Dan_11_0 carries "payload:jailbreak".
    selected = selector.select("jailbreak", include_tags=["payload:jailbreak"])

    assert [p.plugin_name for p in selected] == ["probes.dan.Dan_11_0"]


def test_select_merges_caller_exclude_tags_with_rule(fake_garak: None) -> None:
    registry = ProbeRegistry()
    mapping = {"jailbreak": ProbeMappingRule(include_patterns=("dan.*", "promptinject.*"))}
    selector = ProbeSelector(registry, mapping=mapping)

    selected = selector.select("jailbreak", exclude_tags=["payload:jailbreak"])

    assert [p.plugin_name for p in selected] == ["probes.promptinject.HijackKillHumans"]


def test_select_result_is_sorted_regardless_of_pattern_order(fake_garak: None) -> None:
    registry = ProbeRegistry()
    mapping = {
        "jailbreak": ProbeMappingRule(include_patterns=("promptinject.*", "dan.*", "encoding.*"))
    }
    selector = ProbeSelector(registry, mapping=mapping)

    selected = selector.select("jailbreak")

    assert [p.plugin_name for p in selected] == sorted(p.plugin_name for p in selected)


def test_default_mapping_covers_all_six_builtin_vulnerability_ids() -> None:
    expected = {
        "prompt_injection",
        "jailbreak",
        "prompt_leakage",
        "pii_leakage",
        "secret_leakage",
        "tool_misuse",
    }

    assert expected.issubset(DEFAULT_PROBE_MAPPING.keys())


def test_no_mapping_given_defaults_to_default_probe_mapping(fake_garak: None) -> None:
    registry = ProbeRegistry()
    selector = ProbeSelector(registry)

    assert selector.rule_for("jailbreak") == DEFAULT_PROBE_MAPPING["jailbreak"]
