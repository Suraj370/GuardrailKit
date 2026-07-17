"""Pydantic schema for campaign configuration files.

This is the only place in the framework that uses Pydantic: it is the
right tool at the config boundary (parsing/validating untrusted YAML
input from the filesystem), whereas the domain layer uses plain
dataclasses because domain entities are internal, already-validated
values with no need for coercion or a validation framework.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from llm_redteam_firewall.domain.models import Severity


class PluginSpec(BaseModel):
    """A named plugin lookup plus the kwargs to construct it with.

    ``type`` is looked up in the relevant
    :class:`~llm_redteam_firewall.plugins.registry.Registry` (e.g.
    ``"mock"``, ``"openai"``, ``"dummy"``); ``params`` are passed as
    keyword arguments to that plugin's constructor.
    """

    model_config = ConfigDict(extra="forbid")

    type: str
    params: dict[str, object] = Field(default_factory=dict)


class VulnerabilityConfig(BaseModel):
    """Config-file representation of a
    :class:`~llm_redteam_firewall.domain.models.vulnerability.Vulnerability`."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    category: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    metadata: dict[str, object] = Field(default_factory=dict)


class CampaignConfig(BaseModel):
    """Top-level schema for a campaign YAML file.

    Validated, then handed to
    :func:`llm_redteam_firewall.config.loader.build_campaign_runner`,
    which is the actual dependency-injection composition root.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    generator: PluginSpec
    target: PluginSpec
    evaluator: PluginSpec
    storage: PluginSpec = Field(default_factory=lambda: PluginSpec(type="in_memory"))
    reporters: list[PluginSpec] = Field(default_factory=lambda: [PluginSpec(type="console")])
    vulnerabilities: list[VulnerabilityConfig]
    max_attacks_per_vulnerability: int = 5
    concurrency: int = 5
    timeout_seconds: float = 30.0
