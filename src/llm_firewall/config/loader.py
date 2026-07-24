"""Composition root: turns a firewall config file into a ready-to-use Firewall.

This module is deliberately the only place in the package, other than
adapter registration itself, that is allowed to import
``llm_firewall.adapters`` and reach into ``llm_firewall.plugins`` by
name. Everything upstream of here (``domain``, ``application``) stays
ignorant of which concrete policies exist; downstream callers (CLI,
host applications) just call into this module.
"""

from __future__ import annotations

from pathlib import Path

import yaml

# Importing the adapters package registers every in-tree policy with
# POLICIES as a side effect.
from llm_firewall import adapters  # noqa: F401
from llm_firewall.adapters.policies.nemo_guardrails_policy import NemoGuardrailsPolicy
from llm_firewall.application import FirewallGuard
from llm_firewall.domain.errors import ConfigurationError
from llm_firewall.plugins import POLICIES

from .schema import FirewallConfig


def load_firewall_config(path: str | Path) -> FirewallConfig:
    """Parse and validate a firewall YAML file into a :class:`FirewallConfig`."""
    raw_path = Path(path)
    try:
        raw_text = raw_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"could not read firewall config at {raw_path}: {exc}") from exc

    data = yaml.safe_load(raw_text) or {}
    try:
        return FirewallConfig.model_validate(data)
    except Exception as exc:  # noqa: BLE001 - re-raised as a domain-level ConfigurationError
        raise ConfigurationError(f"invalid firewall config at {raw_path}: {exc}") from exc


def build_guard(config: FirewallConfig) -> FirewallGuard:
    """Wire a validated :class:`FirewallConfig` into a runnable :class:`FirewallGuard`.

    If ``config.nemo_guardrails`` is set, this constructs a
    :class:`NemoGuardrailsPolicy` from its ``config_path`` and adds it
    to :data:`POLICIES` (registering it under the name
    ``"nemo_guardrails"``, alongside the eagerly-registered in-tree
    rule-based policies) before resolving ``config.policies`` by name.
    """
    if config.nemo_guardrails is not None:
        POLICIES.add(NemoGuardrailsPolicy(config_path=config.nemo_guardrails.config_path))

    policies = (
        [POLICIES.get(name) for name in config.policies] if config.policies else POLICIES.all()
    )
    return FirewallGuard(
        policies,
        block_severity=config.block_severity,
        flag_severity=config.flag_severity,
    )


def load_guard(path: str | Path) -> FirewallGuard:
    """Convenience: :func:`load_firewall_config` + :func:`build_guard`."""
    return build_guard(load_firewall_config(path))
