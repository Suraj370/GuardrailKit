"""OpenAITarget: extension-point stub for the OpenAI Chat Completions API.

Not implemented — this file establishes the shape (constructor args,
registration name) so wiring it up later is a matter of filling in
``execute``, not designing a new adapter from scratch. The ``openai``
SDK is intentionally not a hard dependency of this package; add it
under the ``openai`` extra in ``pyproject.toml`` when implementing.
"""

from __future__ import annotations

from llm_redteam_firewall.domain.models import Attack, AttackResult, ExecutionContext
from llm_redteam_firewall.plugins import TARGETS


@TARGETS.register("openai")
class OpenAITarget:
    """Sends attack prompts to an OpenAI-compatible chat completions endpoint."""

    name = "openai"

    def __init__(self, model: str, api_key: str | None = None, base_url: str | None = None) -> None:
        self._model = model
        self._api_key = api_key
        self._base_url = base_url

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        raise NotImplementedError(
            "OpenAITarget is a scaffold placeholder. Implement by calling the "
            "OpenAI chat completions API with attack.prompt and mapping the "
            "result onto an AttackResult."
        )
