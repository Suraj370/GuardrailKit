"""Composition root: YAML config -> wired FirewallGuard."""

from llm_firewall.config.loader import build_guard, load_firewall_config, load_guard
from llm_firewall.config.schema import FirewallConfig, NemoGuardrailsSettings

__all__ = [
    "FirewallConfig",
    "NemoGuardrailsSettings",
    "build_guard",
    "load_firewall_config",
    "load_guard",
]
