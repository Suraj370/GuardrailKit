"""Domain-level exceptions.

Kept small and generic on purpose: adapters translate their own
failure modes (HTTP errors, SDK exceptions, timeouts) into these so
that the application layer never has to import adapter-specific
exception types.
"""

from __future__ import annotations


class RedTeamError(Exception):
    """Base class for all errors raised by this framework."""


class AttackGenerationError(RedTeamError):
    """Raised when an AttackGenerator fails to produce attacks."""


class TargetExecutionError(RedTeamError):
    """Raised when a Target fails to execute an attack.

    Adapters may choose to raise this *or* return a
    :class:`~llm_redteam_firewall.domain.models.response.Response`
    with ``error`` set. Raising should be reserved for failures the
    execution engine should treat as retryable/fatal rather than a
    graded outcome.
    """


class EvaluationError(RedTeamError):
    """Raised when an Evaluator fails to score a response."""


class StorageError(RedTeamError):
    """Raised when a FindingsStorage backend fails to persist or read."""


class ConfigurationError(RedTeamError):
    """Raised when campaign configuration is invalid or incomplete."""


class PluginNotFoundError(RedTeamError):
    """Raised when a requested plugin name is not registered."""
