"""Campaign entity: the unit of work the orchestrator runs."""

from __future__ import annotations

from dataclasses import dataclass

from .vulnerability import Vulnerability


@dataclass(frozen=True, slots=True)
class Campaign:
    """A named, reproducible red-team run against one target.

    A Campaign is pure configuration: which vulnerabilities to probe,
    how many attacks to generate per vulnerability, and how long to
    let each execution run. It says nothing about *which* generator,
    target, evaluator, storage, or reporter implementations are used —
    that wiring lives in the composition root
    (:mod:`llm_redteam_firewall.config.loader`), not the domain.
    """

    name: str
    vulnerabilities: tuple[Vulnerability, ...]
    max_attacks_per_vulnerability: int = 5
    concurrency: int = 5
    description: str = ""
