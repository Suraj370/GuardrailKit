"""AnthropicTarget: extension-point stub for the Anthropic Messages API.

Same status as :mod:`.openai_target` — not implemented. The
``anthropic`` SDK is not a hard dependency; add it under the
``anthropic`` extra in ``pyproject.toml`` when implementing.
"""

from __future__ import annotations

from llm_redteam.domain.models import Attack, AttackResult, ExecutionContext
from llm_redteam.domain.ports import Target
from llm_redteam.plugins import TARGETS


@TARGETS.register("anthropic")
class AnthropicTarget(Target):
    """Sends attack prompts to the Anthropic Messages API."""

    name = "anthropic"

    def __init__(self, model: str, api_key: str | None = None) -> None:
        self._model = model
        self._api_key = api_key

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        raise NotImplementedError(
            "AnthropicTarget is a scaffold placeholder. Implement by calling "
            "the Anthropic Messages API with attack.prompt and mapping the "
            "result onto an AttackResult."
        )
