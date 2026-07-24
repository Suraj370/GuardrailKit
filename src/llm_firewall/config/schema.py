"""Pydantic schema for firewall configuration files.

This is the only place in the package that uses Pydantic: the right
tool at the config boundary (parsing/validating untrusted YAML from
the filesystem), whereas the domain layer uses plain dataclasses
because domain entities are internal, already-validated values.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from llm_firewall.domain.models import Severity


class NemoGuardrailsSettings(BaseModel):
    """Points :func:`~llm_firewall.config.loader.build_guard` at a Colang rails directory.

    Presence of this block (as opposed to ``config_path`` being a bare
    string field on :class:`FirewallConfig`) is what tells the loader
    to construct and register a
    :class:`~llm_firewall.adapters.policies.nemo_guardrails_policy.NemoGuardrailsPolicy`
    — it has no sensible default ``config_path``, so it is opt-in.
    """

    model_config = ConfigDict(extra="forbid")

    config_path: str


class FirewallConfig(BaseModel):
    """Top-level schema for a firewall YAML config file.

    ``policies`` names which registered :class:`~llm_firewall.domain.ports.Policy`
    plugins to run, in :data:`~llm_firewall.plugins.POLICIES` lookup
    order; leave it unset (or empty) to run every registered policy.
    Include ``"nemo_guardrails"`` here only once ``nemo_guardrails`` is
    also set below.
    """

    model_config = ConfigDict(extra="forbid")

    policies: list[str] = Field(default_factory=list)
    block_severity: Severity = Severity.HIGH
    flag_severity: Severity = Severity.LOW
    nemo_guardrails: NemoGuardrailsSettings | None = None
