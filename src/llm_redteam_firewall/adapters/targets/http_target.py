"""HTTPTarget: extension-point stub for an arbitrary HTTP(S) endpoint.

Generalizes "a FastAPI endpoint" (or any other framework's HTTP
service) to "some JSON-over-HTTP endpoint that accepts a prompt and
returns text" — the target under test does not need to be written in
Python or know anything about this framework. Not implemented; add an
HTTP client dependency (e.g. ``httpx``) when implementing.
"""

from __future__ import annotations

from llm_redteam_firewall.domain.models import Attack, AttackResult, ExecutionContext
from llm_redteam_firewall.domain.ports import Target
from llm_redteam_firewall.plugins import TARGETS


@TARGETS.register("http")
class HTTPTarget(Target):
    """Posts attack prompts to an HTTP endpoint (e.g. a FastAPI service)."""

    name = "http"

    def __init__(self, url: str, prompt_field: str = "prompt", response_field: str = "response") -> None:
        self._url = url
        self._prompt_field = prompt_field
        self._response_field = response_field

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        raise NotImplementedError(
            "HTTPTarget is a scaffold placeholder. Implement by POSTing "
            "{self._prompt_field: attack.prompt} to self._url and reading "
            "self._response_field from the JSON response."
        )
