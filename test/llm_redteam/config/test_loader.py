"""Config loader: YAML parsing + the DI composition root."""

from __future__ import annotations

from pathlib import Path

import pytest

from llm_redteam.config import (
    CampaignConfig,
    build_campaign_runner,
    load_campaign_config,
    load_campaign_runner,
)
from llm_redteam.domain.errors import ConfigurationError
from llm_redteam.domain.vulnerabilities import VULNERABILITY_REGISTRY

_EXAMPLE_CONFIG_PATH = Path(__file__).resolve().parents[3] / "configs" / "example_campaign.yaml"


def test_load_campaign_config_parses_example_file() -> None:
    config = load_campaign_config(_EXAMPLE_CONFIG_PATH)

    assert config.name == "example-campaign"
    assert config.generator.type == "dummy"
    assert config.target.type == "mock"
    assert len(config.vulnerabilities) == 2


def test_load_campaign_config_missing_file_raises_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        load_campaign_config(tmp_path / "does-not-exist.yaml")


def test_load_campaign_config_invalid_yaml_raises_configuration_error(tmp_path: Path) -> None:
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text("name: only-a-name\n", encoding="utf-8")

    with pytest.raises(ConfigurationError):
        load_campaign_config(bad_config)


def test_build_campaign_runner_wires_a_runnable_campaign() -> None:
    config = load_campaign_config(_EXAMPLE_CONFIG_PATH)

    runner = build_campaign_runner(config)

    assert runner.campaign.name == "example-campaign"
    assert len(runner.campaign.vulnerabilities) == 2


def test_vulnerability_referenced_by_id_resolves_from_registry() -> None:
    config = CampaignConfig.model_validate(
        {
            "name": "id-ref-campaign",
            "generator": {"type": "dummy"},
            "target": {"type": "mock"},
            "evaluator": {"type": "dummy"},
            "vulnerabilities": [{"id": "pii_leakage"}],
        }
    )

    runner = build_campaign_runner(config)

    (vulnerability,) = runner.campaign.vulnerabilities
    definition = VULNERABILITY_REGISTRY.get("pii_leakage")
    assert vulnerability.name == definition.name
    assert vulnerability.category == definition.default_attack_categories[0]
    assert vulnerability.severity == definition.severity
    assert vulnerability.metadata["default_policies"] == list(definition.default_policies)


def test_vulnerability_with_explicit_name_and_category_ignores_registry() -> None:
    config = CampaignConfig.model_validate(
        {
            "name": "explicit-campaign",
            "generator": {"type": "dummy"},
            "target": {"type": "mock"},
            "evaluator": {"type": "dummy"},
            "vulnerabilities": [
                {"id": "pii_leakage", "name": "Custom Name", "category": "custom_category"}
            ],
        }
    )

    runner = build_campaign_runner(config)

    (vulnerability,) = runner.campaign.vulnerabilities
    assert vulnerability.name == "Custom Name"
    assert vulnerability.category == "custom_category"
    assert vulnerability.metadata == {}


def test_vulnerability_unresolvable_id_raises_configuration_error() -> None:
    config = CampaignConfig.model_validate(
        {
            "name": "bad-campaign",
            "generator": {"type": "dummy"},
            "target": {"type": "mock"},
            "evaluator": {"type": "dummy"},
            "vulnerabilities": [{"id": "not-a-registered-id"}],
        }
    )

    with pytest.raises(ConfigurationError):
        build_campaign_runner(config)


@pytest.mark.asyncio
async def test_load_campaign_runner_executes_end_to_end(tmp_path: Path) -> None:
    # Point the JSON reporter at a temp path so the test doesn't write
    # into the repo's build/ directory.
    config_text = _EXAMPLE_CONFIG_PATH.read_text(encoding="utf-8").replace(
        "build/example-campaign-results.json", str(tmp_path / "results.json")
    )
    config_path = tmp_path / "campaign.yaml"
    config_path.write_text(config_text, encoding="utf-8")

    runner = load_campaign_runner(config_path)
    result = await runner.run()

    assert result.campaign_name == "example-campaign"
    assert result.total_attacks == 6  # 2 vulnerabilities x 3 max_attacks_per_vulnerability
    assert (tmp_path / "results.json").exists()
