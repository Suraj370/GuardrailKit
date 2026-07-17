"""MockTarget: the zero-configuration Target implementation.

The "dummy implementation" of the Target port — needs no callable, no
API key, no network. Useful as a default in examples and tests where
the point is to exercise the pipeline, not the system under test.
Compare with :class:`.callback_target.CallbackTarget`, which is also
functional but requires the caller to supply behavior.
"""

from __future__ import annotations

from llm_redteam_firewall.domain.models import Attack, ExecutionContext, Response
from llm_redteam_firewall.plugins import TARGETS


@TARGETS.register("mock")
class MockTarget:
    """Always returns the same canned response, regardless of input."""

    def __init__(self, canned_response: str = "I cannot help with that request.", name: str = "mock") -> None:
        self._canned_response = canned_response
        self.name = name

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> Response:
        return Response(
            attack_id=attack.id,
            target_name=self.name,
            output=self._canned_response,
            latency_ms=0.0,
        )
