"""Target implementations.

Importing this package registers all in-tree targets with
:data:`llm_redteam_firewall.plugins.TARGETS`. Of these, only
:class:`.mock_target.MockTarget` and :class:`.callback_target.CallbackTarget`
are functional out of the box — the rest (openai, anthropic, http,
local_model, langgraph) are extension-point stubs that raise
``NotImplementedError``.
"""

from . import (  # noqa: F401  (import for registration side effect)
    anthropic_target,
    callback_target,
    http_target,
    langgraph_target,
    local_model_target,
    mock_target,
    openai_target,
)

__all__ = [
    "anthropic_target",
    "callback_target",
    "http_target",
    "langgraph_target",
    "local_model_target",
    "mock_target",
    "openai_target",
]
