"""Target implementations.

Importing this package registers all in-tree targets with
:data:`llm_redteam.plugins.TARGETS`. Of these,
:class:`.mock_target.MockTarget`, :class:`.callback_target.CallbackTarget`,
:class:`.firewall_target.FirewallTarget`, and :class:`.openai_target.OpenAITarget`
are functional out of the box (``OpenAITarget`` requires the ``openai``
extra) — the rest (anthropic, http, local_model, langgraph) are
extension-point stubs that raise ``NotImplementedError``.
"""

from . import (  # noqa: F401  (import for registration side effect)
    anthropic_target,
    callback_target,
    firewall_target,
    http_target,
    langgraph_target,
    local_model_target,
    mock_target,
    openai_target,
)

__all__ = [
    "anthropic_target",
    "callback_target",
    "firewall_target",
    "http_target",
    "langgraph_target",
    "local_model_target",
    "mock_target",
    "openai_target",
]
