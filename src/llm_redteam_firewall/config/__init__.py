"""Configuration layer: YAML schema + composition root.

This is the outermost ring of the hexagon, alongside ``cli``. It is
the only layer allowed to know about *all* other layers at once —
domain, application, adapters, and plugins — because its job is to
wire them together from a config file. No other package imports from
here.
"""

from .loader import (
    CampaignRunner,
    build_campaign_runner,
    load_campaign_config,
    load_campaign_runner,
)
from .schema import CampaignConfig, PluginSpec, VulnerabilityConfig

__all__ = [
    "CampaignConfig",
    "CampaignRunner",
    "PluginSpec",
    "VulnerabilityConfig",
    "build_campaign_runner",
    "load_campaign_config",
    "load_campaign_runner",
]
