"""CallbackTarget: wraps an arbitrary Python callable as a Target.

Unlike the other target adapters, this one is fully functional rather
than a stub — it has no external dependency to wait on. It exists so
that (a) users can point the harness at any in-process function
without writing a new adapter, and (b) examples and tests have a real,
working target to exercise the full pipeline against.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable

from llm_redteam_firewall.domain.errors import TargetExecutionError
from llm_redteam_firewall.domain.models import Attack, ExecutionContext, Response
from llm_redteam_firewall.plugins import TARGETS

PromptCallback = Callable[[str], "str | Awaitable[str]"]


@TARGETS.register("callback")
class CallbackTarget:
    """Adapts a plain ``str -> str`` (or ``str -> Awaitable[str]``) callable."""

    def __init__(self, callback: PromptCallback, name: str = "callback") -> None:
        self._callback = callback
        self.name = name

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> Response:
        started = time.perf_counter()
        try:
            result = self._callback(attack.prompt)
            output = await result if inspect.isawaitable(result) else result
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any user callback error becomes a TargetExecutionError
            raise TargetExecutionError(f"callback target {self.name!r} raised: {exc}") from exc

        return Response(
            attack_id=attack.id,
            target_name=self.name,
            output=str(output),
            latency_ms=(time.perf_counter() - started) * 1000,
        )
