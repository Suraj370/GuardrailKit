"""Concrete adapters. Importing this package registers every in-tree policy.

Application/domain code never imports this package directly; only the
composition root (:mod:`llm_firewall.config.loader`) and the CLI do.
"""

from llm_firewall.adapters import policies  # noqa: F401
