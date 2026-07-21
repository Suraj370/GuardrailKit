"""CallbackTarget: wraps an arbitrary Python callable as a Target.

Unlike the other target adapters, this one is fully functional rather
than a stub — it has no external dependency to wait on. It exists so
that (a) users can point the harness at any in-process function or a
thin wrapper around any LLM provider's SDK without writing a new
adapter, and (b) examples and tests have a real, working target to
exercise the full pipeline against.

Per the :class:`~llm_redteam.domain.ports.target.Target`
contract's stated preference, exceptions raised by the wrapped
callable are caught here and reported as ``AttackResult.error`` rather
than propagated as :class:`~llm_redteam.domain.errors.TargetExecutionError`
— a single misbehaving callback should not abort an entire campaign.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable

from llm_redteam.domain.models import Attack, AttackResult, ExecutionContext
from llm_redteam.domain.ports import Target
from llm_redteam.plugins import TARGETS

PromptCallback = Callable[[str], "str | Awaitable[str]"]


@TARGETS.register("callback")
class CallbackTarget(Target):
    """Adapts a plain ``str -> str`` (or ``str -> Awaitable[str]``) callable.

    Use this to point a campaign at anything callable in-process: a
    thin wrapper around an LLM provider's SDK, an internal service
    client, a LangChain chain's ``.invoke``, etc. This adapter knows
    nothing about *which* system the callback talks to, which keeps it
    reusable across providers without this framework depending on any
    of their SDKs — construct it in code (see
    ``examples/run_callback_target_campaign.py``) rather than from a
    YAML config, since a Python callable has no YAML representation.
    """

    def __init__(self, callback: PromptCallback, *, name: str = "callback") -> None:
        self._callback = callback
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        started = time.perf_counter()
        try:
            result = self._callback(attack.prompt)
            raw_output = await result if inspect.isawaitable(result) else result
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any callback failure becomes a graded AttackResult, not a crashed campaign
            return AttackResult(
                attack_id=attack.id,
                target_name=self.name,
                latency_ms=(time.perf_counter() - started) * 1000,
                error=f"callback target {self.name!r} raised {type(exc).__name__}: {exc}",
                raw={"exception_type": type(exc).__name__},
            )

        return AttackResult(
            attack_id=attack.id,
            target_name=self.name,
            output=str(raw_output),
            latency_ms=(time.perf_counter() - started) * 1000,
            raw={"return_type": type(raw_output).__name__},
        )
