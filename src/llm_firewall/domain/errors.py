"""Domain-level exceptions.

Kept small and generic on purpose: adapters translate their own
failure modes into these so the application layer never has to import
adapter-specific exception types.
"""

from __future__ import annotations


class FirewallError(Exception):
    """Base class for all errors raised by this package."""


class PolicyExecutionError(FirewallError):
    """Raised when a Policy raises while evaluating an inspection context.

    Rule-based policies are expected to be pure and side-effect free;
    this wraps any unexpected exception so the guard can decide
    whether to fail open or fail closed rather than propagating an
    arbitrary adapter exception.
    """


class ConfigurationError(FirewallError):
    """Raised when firewall configuration is invalid or incomplete."""


class PluginNotFoundError(FirewallError):
    """Raised when a requested plugin name is not registered."""
