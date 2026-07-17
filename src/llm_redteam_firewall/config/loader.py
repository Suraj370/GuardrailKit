"""Composition root: turns a campaign config file into a runnable orchestrator.

This module is deliberately the *only* place in the framework, other
than adapter registration itself, that is allowed to import
``llm_redteam_firewall.adapters`` and reach into
``llm_redteam_firewall.plugins`` registries by name. Everything
upstream of here (``domain``, ``application``) stays ignorant of which
concrete classes exist; everything downstream (the CLI, the example
script) only calls into this module rather than constructing adapters
itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

# Importing the adapters package registers every in-tree plugin with
# the registries in llm_redteam_firewall.plugins as a side effect.
from llm_redteam_firewall import adapters  # noqa: F401
from llm_redteam_firewall.application import CampaignOrchestrator, EvaluationEngine, ExecutionEngine
from llm_redteam_firewall.domain.errors import ConfigurationError
from llm_redteam_firewall.domain.models import Campaign, Report, Vulnerability
from llm_redteam_firewall.domain.ports import (
    AttackGenerator,
    Evaluator,
    FindingsStorage,
    Reporter,
    Target,
)
from llm_redteam_firewall.plugins import EVALUATORS, GENERATORS, REPORTERS, STORAGE, TARGETS

from .schema import CampaignConfig, PluginSpec


@dataclass(slots=True)
class CampaignRunner:
    """A fully-wired campaign, ready to execute.

    Bundles the :class:`Campaign` domain object with the
    :class:`CampaignOrchestrator` that was built for it, so callers
    (CLI, examples) have a single object to hold onto.
    """

    campaign: Campaign
    orchestrator: CampaignOrchestrator

    async def run(self) -> Report:
        return await self.orchestrator.run(self.campaign)


def load_campaign_config(path: str | Path) -> CampaignConfig:
    """Parse and validate a campaign YAML file into a :class:`CampaignConfig`."""
    raw_path = Path(path)
    try:
        raw_text = raw_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"could not read campaign config at {raw_path}: {exc}") from exc

    data = yaml.safe_load(raw_text) or {}
    try:
        return CampaignConfig.model_validate(data)
    except Exception as exc:  # noqa: BLE001 - re-raised as a domain-level ConfigurationError
        raise ConfigurationError(f"invalid campaign config at {raw_path}: {exc}") from exc


def _build_generator(spec: PluginSpec) -> AttackGenerator:
    return GENERATORS.create(spec.type, **spec.params)


def _build_target(spec: PluginSpec) -> Target:
    return TARGETS.create(spec.type, **spec.params)


def _build_evaluator(spec: PluginSpec) -> Evaluator:
    return EVALUATORS.create(spec.type, **spec.params)


def _build_storage(spec: PluginSpec) -> FindingsStorage:
    return STORAGE.create(spec.type, **spec.params)


def _build_reporters(specs: list[PluginSpec]) -> list[Reporter]:
    return [REPORTERS.create(spec.type, **spec.params) for spec in specs]


def build_campaign_runner(config: CampaignConfig) -> CampaignRunner:
    """Wire a validated :class:`CampaignConfig` into a runnable :class:`CampaignRunner`.

    This is the dependency-injection boundary: every concrete adapter
    is resolved here, by name, through the plugin registries, and
    passed into application-layer constructors. Swap ``config.target.type``
    from ``"mock"`` to ``"openai"`` (once implemented) and nothing here
    or upstream changes.
    """
    generator = _build_generator(config.generator)
    target = _build_target(config.target)
    evaluator = _build_evaluator(config.evaluator)
    storage = _build_storage(config.storage)
    reporters = _build_reporters(config.reporters)

    execution_engine = ExecutionEngine(
        target=target,
        concurrency=config.concurrency,
        timeout_seconds=config.timeout_seconds,
    )
    evaluation_engine = EvaluationEngine(evaluator=evaluator, concurrency=config.concurrency)

    orchestrator = CampaignOrchestrator(
        generator=generator,
        execution_engine=execution_engine,
        evaluation_engine=evaluation_engine,
        storage=storage,
        reporters=reporters,
    )

    campaign = Campaign(
        name=config.name,
        description=config.description,
        vulnerabilities=tuple(
            Vulnerability(
                id=v.id,
                name=v.name,
                category=v.category,
                description=v.description,
                severity=v.severity,
                metadata=v.metadata,
            )
            for v in config.vulnerabilities
        ),
        max_attacks_per_vulnerability=config.max_attacks_per_vulnerability,
        concurrency=config.concurrency,
    )

    return CampaignRunner(campaign=campaign, orchestrator=orchestrator)


def load_campaign_runner(path: str | Path) -> CampaignRunner:
    """Convenience: :func:`load_campaign_config` + :func:`build_campaign_runner`."""
    return build_campaign_runner(load_campaign_config(path))
