"""Shared pytest fixtures.

Importing ``llm_firewall.adapters`` here (once, at collection time)
ensures every in-tree policy is registered before any test that
resolves policies by name runs.
"""

from __future__ import annotations

from llm_firewall import adapters  # noqa: F401
