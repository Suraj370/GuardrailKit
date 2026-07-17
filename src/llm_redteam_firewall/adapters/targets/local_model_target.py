"""LocalModelTarget: extension-point stub for an in-process local model.

For targets loaded directly into the process (e.g. via
``transformers``, ``llama.cpp`` bindings, or ``vllm``) rather than
called over the network. Not implemented; add the relevant local
inference dependency when implementing.
"""

from __future__ import annotations

from typing import Any

from llm_redteam_firewall.domain.models import Attack, AttackResult, ExecutionContext
from llm_redteam_firewall.domain.ports import Target
from llm_redteam_firewall.plugins import TARGETS


@TARGETS.register("local_model")
class LocalModelTarget(Target):
    """Runs attack prompts against a locally-loaded model."""

    name = "local_model"

    def __init__(self, model_path: str, generation_kwargs: dict[str, Any] | None = None) -> None:
        self._model_path = model_path
        self._generation_kwargs = generation_kwargs or {}

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        raise NotImplementedError(
            "LocalModelTarget is a scaffold placeholder. Implement by loading "
            "the model from self._model_path (likely once, lazily, not per "
            "call) and running attack.prompt through it."
        )
