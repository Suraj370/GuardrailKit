"""OpenAITarget: sends attack prompts to OpenAI's Responses API.

The ``openai`` SDK is only imported when this target is actually
constructed (inside ``__init__``), not at module scope — mirroring
:mod:`~llm_redteam_firewall.adapters.generators.garak.probe_registry`'s
lazy-import pattern — so importing ``llm_redteam_firewall.adapters``
never requires the ``openai`` extra to be installed; only creating an
``OpenAITarget`` does. Install with
``pip install 'llm-redteam-firewall[openai]'``.
"""

from __future__ import annotations

import time
from typing import Any

from llm_redteam_firewall.domain.errors import ConfigurationError
from llm_redteam_firewall.domain.models import Attack, AttackResult, ExecutionContext
from llm_redteam_firewall.domain.ports import Target
from llm_redteam_firewall.plugins import TARGETS


class OpenAINotInstalledError(ConfigurationError):
    """Raised when ``OpenAITarget`` is used but the ``openai`` package is not installed."""

    def __init__(self, cause: Exception | None = None) -> None:
        super().__init__(
            "openai is not installed; install the 'openai' extra "
            "(pip install 'llm-redteam-firewall[openai]') to use the openai target"
        )
        self.__cause__ = cause


def _import_async_openai_client() -> type[Any]:
    try:
        from openai import AsyncOpenAI
    except ImportError as exc:
        raise OpenAINotInstalledError(exc) from exc
    return AsyncOpenAI


@TARGETS.register("openai")
class OpenAITarget(Target):
    """Sends attack prompts to an OpenAI-compatible Responses API endpoint.

    Exceptions raised by the SDK (auth errors, rate limits, timeouts,
    network failures) are caught here and reported as
    ``AttackResult.error`` rather than propagated, per the
    :class:`~llm_redteam_firewall.domain.ports.target.Target` contract's
    stated preference — a single failed call should not abort an
    entire campaign.
    """

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        base_url: str | None = None,
        name: str = "openai",
    ) -> None:
        self._model = model
        self._name = name
        async_openai_cls = _import_async_openai_client()
        self._client = async_openai_cls(api_key=api_key, base_url=base_url)

    @property
    def name(self) -> str:
        return self._name

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        started = time.perf_counter()
        try:
            response = await self._client.responses.create(model=self._model, input=attack.prompt)
            output = response.output_text
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any SDK failure becomes a graded AttackResult, not a crashed campaign
            return AttackResult(
                attack_id=attack.id,
                target_name=self.name,
                latency_ms=(time.perf_counter() - started) * 1000,
                error=f"openai target {self.name!r} raised {type(exc).__name__}: {exc}",
                raw={"exception_type": type(exc).__name__, "model": self._model},
            )

        return AttackResult(
            attack_id=attack.id,
            target_name=self.name,
            output=output,
            latency_ms=(time.perf_counter() - started) * 1000,
            raw={"model": self._model},
        )
