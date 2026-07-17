"""Target port: the system-under-test abstraction.

The orchestrator and execution engine never know whether a Target is
backed by the OpenAI API, Anthropic API, a raw HTTP endpoint, a
locally-hosted model, a LangGraph agent, or a plain Python callback —
they only call :meth:`Target.execute`. This is what makes the harness
usable against arbitrary systems: adding a new kind of target never
touches orchestration code.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_redteam_firewall.domain.models import Attack, ExecutionContext, Response


@runtime_checkable
class Target(Protocol):
    """A system under test that can be sent an attack prompt.

    ``execute`` is async because real-world targets are network calls
    (LLM APIs, HTTP services); synchronous adapters (e.g. an in-process
    local model) can still implement this by wrapping their call in a
    trivial coroutine.
    """

    name: str

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> Response:
        """Send ``attack.prompt`` to the target and return its response.

        Implementations should prefer returning a ``Response`` with
        ``error`` set over raising, so a single failed attack does not
        abort an entire campaign. See
        :class:`llm_redteam_firewall.domain.errors.TargetExecutionError`
        for the raise-vs-return-error contract.
        """
        ...
