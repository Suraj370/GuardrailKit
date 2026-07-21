"""Developer verification utility: exercise the Garak adapter against a *real* Garak install.

This is NOT part of the framework's public API and is not covered by the
test suite (which runs against a mocked Garak — see
``tests/adapters/generators/garak/conftest.py``). It exists purely so a
developer can run, on a machine with the real ``garak`` package installed:

    python scripts/verify_garak_installation.py

and see, end to end, exactly what our existing adapter (``ProbeRegistry``,
``ProbeSelector``, ``GarakAttackGenerator``, ``garak_prompts_to_attacks``)
discovers, selects, loads, and generates from the real Garak plugin corpus.

It calls only the framework's existing public classes/functions and
reimplements none of their logic -- it is a report, not a reimplementation.
"""

from __future__ import annotations

import argparse
import sys
from importlib import metadata as importlib_metadata

from llm_redteam.adapters.generators.garak.generator import GarakAttackGenerator
from llm_redteam.adapters.generators.garak.models import GarakProbeInfo
from llm_redteam.adapters.generators.garak.probe_registry import (
    GarakNotInstalledError,
    ProbeRegistry,
)
from llm_redteam.adapters.generators.garak.probe_selector import ProbeSelector
from llm_redteam.domain.models import Attack, Vulnerability
from llm_redteam.domain.vulnerabilities import VULNERABILITY_REGISTRY, to_vulnerability

DEFAULT_MAX_ATTACKS_PER_VULNERABILITY = 20


def _print_header(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def _print_section_rule(label: str) -> None:
    print("-" * 36)
    print(label)
    print("-" * 36)


def section_environment() -> bool:
    """Section 1: environment. Returns True if Garak is usable, False otherwise."""
    _print_header("SECTION 1: Environment")

    print(f"Python version: {sys.version.splitlines()[0]}")

    try:
        import garak  # noqa: F401
    except ImportError as exc:
        print("Garak imported successfully: NO")
        print(f"  Import error: {exc}")
        print()
        print("Garak is not installed in this environment.")
        print("Install it with: pip install 'llm-redteam[garak]'")
        return False

    try:
        garak_version = importlib_metadata.version("garak")
    except importlib_metadata.PackageNotFoundError:
        garak_version = getattr(garak, "__version__", "<unknown>")

    print(f"Garak version: {garak_version}")
    print("Garak imported successfully: YES")
    return True


def section_probe_discovery(registry: ProbeRegistry) -> list[GarakProbeInfo]:
    _print_header("SECTION 2: Probe Discovery")

    probes = registry.list_probes()  # already sorted by plugin_name
    print(f"Total discovered probes: {len(probes)}")
    print()

    for probe in probes:
        tags = ", ".join(probe.tags) if probe.tags else "(none)"
        print(f"- {probe.plugin_name}")
        print(f"    module: {probe.module}")
        print(f"    tags:   {tags}")

    return probes


def section_vulnerability_mapping(
    selector: ProbeSelector,
) -> dict[str, list[GarakProbeInfo]]:
    _print_header("SECTION 3: Built-in Vulnerability Mapping")

    matches_by_vulnerability: dict[str, list[GarakProbeInfo]] = {}

    for definition in VULNERABILITY_REGISTRY.all():
        print()
        _print_section_rule(f"Vulnerability: {definition.id}")

        matched = selector.select(definition.id)
        matches_by_vulnerability[definition.id] = matched

        print()
        print("Matched probes:")
        print()
        if matched:
            for probe in matched:
                print(f"- {probe.plugin_name}")
        else:
            print("(none)")
        print()
        print("Total probes matched:")
        print(len(matched))

    return matches_by_vulnerability


def section_probe_loading(
    registry: ProbeRegistry, matches_by_vulnerability: dict[str, list[GarakProbeInfo]]
) -> tuple[dict[str, object], dict[str, Exception]]:
    _print_header("SECTION 4: Probe Loading")

    matched_probes: dict[str, GarakProbeInfo] = {}
    for probes in matches_by_vulnerability.values():
        for probe in probes:
            matched_probes[probe.plugin_name] = probe

    loaded: dict[str, object] = {}
    failed: dict[str, Exception] = {}

    for plugin_name in sorted(matched_probes):
        probe_info = matched_probes[plugin_name]
        print()
        print(f"Probe: {plugin_name}")
        try:
            instance = registry.load_probe_instance(plugin_name)
        except Exception as exc:  # noqa: BLE001 - report and continue, never abort
            failed[plugin_name] = exc
            print("  Status: FAILED")
            print(f"  Exception: {exc!r}")
            continue

        prompts = list(getattr(instance, "prompts", None) or [])
        loaded[plugin_name] = instance
        print("  Status: loaded successfully")
        print(f"  Prompt count: {len(prompts)}")
        print(f"  Metadata: module={probe_info.module} class={probe_info.class_name} "
              f"active={probe_info.active} tier={probe_info.tier} "
              f"primary_detector={probe_info.primary_detector}")

    return loaded, failed


def section_attack_generation(
    registry: ProbeRegistry, max_attacks: int
) -> dict[str, list[Attack]]:
    _print_header("SECTION 5: Attack Generation")

    generator = GarakAttackGenerator(registry=registry)
    attacks_by_vulnerability: dict[str, list[Attack]] = {}

    for definition in VULNERABILITY_REGISTRY.all():
        vulnerability: Vulnerability = to_vulnerability(definition)

        print()
        _print_section_rule(f"Vulnerability: {definition.id}")

        try:
            attacks = generator.generate(vulnerability, max_attacks=max_attacks)
        except Exception as exc:  # noqa: BLE001 - report and continue, never abort
            print(f"  Generation FAILED: {exc!r}")
            attacks = []

        attacks_by_vulnerability[definition.id] = attacks

        print()
        print("Generated attacks:")
        print(len(attacks))

        for attack in attacks[:5]:
            print()
            print(f"  Attack ID: {attack.id}")
            print(f"  Prompt: {attack.prompt!r}")
            print(f"  Metadata: {attack.metadata}")
            print(f"  Originating Garak probe: {attack.metadata.get('garak_plugin_name')}")

    return attacks_by_vulnerability


def section_statistics(
    all_probes: list[GarakProbeInfo],
    loaded: dict[str, object],
    failed: dict[str, Exception],
    attacks_by_vulnerability: dict[str, list[Attack]],
) -> None:
    _print_header("SECTION 6: Statistics")

    total_attacks = sum(len(attacks) for attacks in attacks_by_vulnerability.values())

    print(f"Total probes discovered:     {len(all_probes)}")
    print(f"Successfully loaded probes:  {len(loaded)}")
    print(f"Failed probes:               {len(failed)}")
    print(f"Total attacks generated:     {total_attacks}")
    print()
    print("Attacks generated per vulnerability:")
    for vulnerability_id, attacks in attacks_by_vulnerability.items():
        print(f"  {vulnerability_id}: {len(attacks)}")


def section_validation(
    all_probes: list[GarakProbeInfo],
    matches_by_vulnerability: dict[str, list[GarakProbeInfo]],
    attacks_by_vulnerability: dict[str, list[Attack]],
) -> bool:
    _print_header("SECTION 7: Validation")

    checks: list[tuple[str, bool]] = []

    checks.append(("probe discovery returned something", len(all_probes) > 0))

    all_probe_names = {p.plugin_name for p in all_probes}
    matched_probes_exist = all(
        probe.plugin_name in all_probe_names
        for probes in matches_by_vulnerability.values()
        for probe in probes
    )
    checks.append(("every mapped probe exists in discovery results", matched_probes_exist))

    expected_mapped = {"prompt_injection", "jailbreak", "prompt_leakage", "secret_leakage"}
    vulnerabilities_have_matches = all(
        len(matches_by_vulnerability.get(vulnerability_id, [])) > 0
        for vulnerability_id in expected_mapped
        if vulnerability_id in matches_by_vulnerability
    )
    checks.append(
        ("vulnerabilities map to at least one probe (where expected)", vulnerabilities_have_matches)
    )

    all_attacks = [attack for attacks in attacks_by_vulnerability.values() for attack in attacks]
    checks.append(("every generated Attack has a prompt", all(bool(a.prompt) for a in all_attacks)))
    checks.append(("every generated Attack has metadata", all(bool(a.metadata) for a in all_attacks)))
    checks.append(("every generated Attack has an ID", all(bool(a.id) for a in all_attacks)))

    print()
    all_passed = True
    for label, passed in checks:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"[{status}] {label}")

    return all_passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-attacks",
        type=int,
        default=DEFAULT_MAX_ATTACKS_PER_VULNERABILITY,
        help="Max attacks to generate per vulnerability in Section 5 (default: %(default)s).",
    )
    args = parser.parse_args()

    garak_available = section_environment()
    if not garak_available:
        return 1

    registry = ProbeRegistry()
    try:
        all_probes = section_probe_discovery(registry)
    except GarakNotInstalledError as exc:
        print(f"\nGarak is not installed: {exc}")
        return 1

    selector = ProbeSelector(registry)
    matches_by_vulnerability = section_vulnerability_mapping(selector)

    loaded, failed = section_probe_loading(registry, matches_by_vulnerability)

    attacks_by_vulnerability = section_attack_generation(registry, args.max_attacks)

    section_statistics(all_probes, loaded, failed, attacks_by_vulnerability)

    validation_passed = section_validation(all_probes, matches_by_vulnerability, attacks_by_vulnerability)

    _print_header("SECTION 8: Exit")
    if validation_passed:
        print("Real Garak integration verification completed successfully.")
        return 0

    print("Real Garak integration verification completed with FAILED checks (see Section 7).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
