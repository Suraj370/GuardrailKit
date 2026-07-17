"""LangGraphTarget: extension-point stub for a LangGraph-based agent.

Distinct from :mod:`.local_model_target` because an agent under test
may take multiple internal steps (tool calls, sub-graph traversal)
per single attack prompt — the ``Response.raw`` field is intended to
carry that trace once implemented. Not implemented; add ``langgraph``
as a dependency when implementing.
"""

from __future__ import annotations

from typing import Any

from llm_redteam_firewall.domain.models import Attack, ExecutionContext, Response
from llm_redteam_firewall.plugins import TARGETS


@TARGETS.register("langgraph")
class LangGraphTarget:
    """Invokes a compiled LangGraph graph with an attack prompt as input."""

    name = "langgraph"

    def __init__(self, graph: Any, input_key: str = "input") -> None:
        self._graph = graph
        self._input_key = input_key

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> Response:
        raise NotImplementedError(
            "LangGraphTarget is a scaffold placeholder. Implement by invoking "
            "self._graph.ainvoke({self._input_key: attack.prompt}) (or the "
            "sync equivalent) and mapping the final state onto a Response, "
            "optionally recording intermediate steps in Response.raw."
        )
