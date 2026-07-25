"""PolicyRegistry: name -> live Policy instance collection.

Unlike the generic factory :class:`~llm_redteam.plugins.registry.Registry`
(used when config picks *one* plugin by type), a policy campaign typically
runs *every* registered safety rule against each attack/response pair.
This registry therefore stores concrete :class:`Policy` instances, and
:class:`~llm_redteam.application.policy_engine.PolicyEngine`
iterates :meth:`all` of them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TypeVar

from llm_redteam.domain.errors import PluginNotFoundError
from llm_redteam.domain.ports import Policy

P = TypeVar("P", bound=Policy)


class PolicyRegistry:
    """Name -> :class:`Policy` instance registry for firewall rules.

    Usage as a class decorator (instantiates with no-arg constructor)::

        POLICIES = PolicyRegistry()

        @POLICIES.register
        class PromptLeakPolicy(Policy):
            name = "prompt_leak"
            ...

    Or register a pre-built instance::

        POLICIES.add(PromptLeakPolicy())
    """

    def __init__(self) -> None:
        self._policies: dict[str, Policy] = {}

    def add(self, policy: Policy) -> Policy:
        """Register a live policy instance under ``policy.name``."""
        self._policies[policy.name] = policy
        return policy

    def register(
        self, policy_cls: type[P] | None = None, /, **kwargs: object
    ) -> type[P] | Callable[[type[P]], type[P]]:
        """Class decorator: instantiate and :meth:`add` the policy.

        Supports ``@registry.register`` and ``@registry.register(foo=1)``.
        """

        def _decorator(cls: type[P]) -> type[P]:
            instance = cls(**kwargs)  # type: ignore[arg-type]
            self.add(instance)
            return cls

        if policy_cls is not None:
            return _decorator(policy_cls)
        return _decorator

    def get(self, name: str) -> Policy:
        """Return the policy registered under ``name``."""
        try:
            return self._policies[name]
        except KeyError as exc:
            available = ", ".join(sorted(self._policies)) or "<none registered>"
            raise PluginNotFoundError(f"no policy named {name!r}; available: {available}") from exc

    def all(self) -> list[Policy]:
        """Return all registered policies in stable name order."""
        return [self._policies[name] for name in sorted(self._policies)]

    def names(self) -> list[str]:
        """Return sorted registered policy names."""
        return sorted(self._policies)

    def clear(self) -> None:
        """Remove every registered policy (primarily for tests)."""
        self._policies.clear()

    def __contains__(self, name: str) -> bool:
        return name in self._policies

    def __len__(self) -> int:
        return len(self._policies)

    def __iter__(self) -> Iterator[Policy]:
        return iter(self.all())
