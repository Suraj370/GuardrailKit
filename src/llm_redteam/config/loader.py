"""Composition root: turns a campaign config file into a runnable orchestrator.

This module is deliberately the *only* place in the framework, other
than adapter registration itself, that is allowed to import
``llm_redteam.adapters`` and reach into
``llm_redteam.plugins`` registries by name. Everything
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
# the registries in llm_redteam.plugins as a side effect.
from llm_redteam import adapters  # noqa: F401
from llm_redteam.application import CampaignOrchestrator, EvaluationEngine, ExecutionEngine
from llm_redteam.domain.errors import ConfigurationError, PluginNotFoundError
from llm_redteam.domain.models import Campaign, Report, Severity, Vulnerability
from llm_redteam.domain.ports import (
    AttackGenerator,
    Evaluator,
    FindingsStorage,
    Reporter,
    Target,
)
from llm_redteam.domain.vulnerabilities import VULNERABILITY_REGISTRY, to_vulnerability
from llm_redteam.plugins import EVALUATORS, GENERATORS, REPORTERS, STORAGE, TARGETS

from .schema import CampaignConfig, PluginSpec, VulnerabilityConfig


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


def _build_vulnerability(spec: VulnerabilityConfig) -> Vulnerability:
    """Resolve one :class:`VulnerabilityConfig` into a domain :class:`Vulnerability`.

    If ``name`` and ``category`` are both given inline, they are used
    as-is (the original, fully-explicit form). Otherwise ``spec.id`` is
    looked up in :data:`VULNERABILITY_REGISTRY` and projected via
    :func:`to_vulnerability`, so a campaign can reference a well-known
    vulnerability by id instead of embedding its implementation
    details.
    """
    if spec.name is not None and spec.category is not None:
        return Vulnerability(
            id=spec.id,
            name=spec.name,
            category=spec.category,
            description=spec.description or "",
            severity=spec.severity if spec.severity is not None else Severity.MEDIUM,
            metadata=spec.metadata,
        )

    try:
        definition = VULNERABILITY_REGISTRY.get(spec.id)
    except PluginNotFoundError as exc:
        raise ConfigurationError(
            f"vulnerability {spec.id!r} has no name/category and is not a registered "
            "vulnerability definition; either provide both name and category, or "
            f"reference a registered id (available: {', '.join(VULNERABILITY_REGISTRY.names())})"
        ) from exc

    return to_vulnerability(
        definition,
        description=spec.description,
        severity=spec.severity,
        metadata=spec.metadata or None,
    )


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
        max_retries=config.max_retries,
        retry_backoff_seconds=config.retry_backoff_seconds,
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
        vulnerabilities=tuple(_build_vulnerability(v) for v in config.vulnerabilities),
        max_attacks_per_vulnerability=config.max_attacks_per_vulnerability,
        concurrency=config.concurrency,
    )

    return CampaignRunner(campaign=campaign, orchestrator=orchestrator)


def load_campaign_runner(path: str | Path) -> CampaignRunner:
    """Convenience: :func:`load_campaign_config` + :func:`build_campaign_runner`."""
    return build_campaign_runner(load_campaign_config(path))
