"""ToolCall: one tool/function call attempted by the model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool call reported in the model's response, as the host app parsed it.

    ``arguments`` is whatever the host app already parsed out of the
    model's tool-call payload (e.g. ``json.loads``'d OpenAI function-call
    arguments, or an Anthropic ``tool_use`` block's ``input``) -- this
    package never parses raw provider-specific wire formats itself.
    """

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
