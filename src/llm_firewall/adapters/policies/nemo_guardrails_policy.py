"""NemoGuardrailsPolicy: runs a NeMo Guardrails Colang config as a firewall policy.

The ``nemoguardrails`` package is lazily imported (only when this policy
is actually constructed, not at module scope) mirroring
:mod:`~llm_redteam.adapters.targets.openai_target`'s lazy-import pattern
-- so importing ``llm_firewall.adapters`` never requires the
``nemo-guardrails`` extra. Construction *does* parse the given Colang
rails directory via ``RailsConfig.from_path`` (so a broken config fails
fast at wiring time) and builds an ``LLMRails`` instance from it.

``evaluate`` checks the prompt and response with separate
``LLMRails.generate()`` calls (the synchronous counterpart to
``generate_async``, matching the sync :class:`Policy` contract), each
restricting ``GenerationOptions.rails`` to just the one rail category
being checked (``dialog`` disabled throughout). Disabling dialog rails
means NeMo never generates its own completion -- for the response check,
the caller-supplied response is passed as the trailing message and
checked against the output rails as-is. A rail counts as a block when
any ``ActivatedRail`` in the returned ``GenerationLog`` has ``stop=True``.

See ``configs/nemo_guardrails/`` for a minimal example config.
"""

from __future__ import annotations

from typing import Any

from llm_firewall.domain.errors import ConfigurationError
from llm_firewall.domain.models import Finding, InspectionContext, Severity
from llm_firewall.domain.ports import Policy


class NemoGuardrailsNotInstalledError(ConfigurationError):
    """Raised when ``NemoGuardrailsPolicy`` is used but ``nemoguardrails`` is not installed."""

    def __init__(self, cause: Exception | None = None) -> None:
        super().__init__(
            "nemoguardrails is not installed; install the 'nemo-guardrails' extra "
            "(pip install 'llm-redteam[nemo-guardrails]') to use this policy"
        )
        self.__cause__ = cause


def _import_rails_config() -> type[Any]:
    try:
        from nemoguardrails import RailsConfig  # type: ignore[import-not-found]
    except ImportError as exc:
        raise NemoGuardrailsNotInstalledError(exc) from exc
    return RailsConfig  # type: ignore[no-any-return]


def _import_llm_rails() -> type[Any]:
    try:
        from nemoguardrails import LLMRails  # type: ignore[import-not-found]
    except ImportError as exc:
        raise NemoGuardrailsNotInstalledError(exc) from exc
    return LLMRails  # type: ignore[no-any-return]


class NemoGuardrailsPolicy(Policy):
    """Runs a NeMo Guardrails Colang config's input/output rails as a firewall policy.

    Unlike the no-arg rule-based policies in this package, this one
    requires a ``config_path`` (there is no sensible default), so it is
    not auto-registered on import -- build one explicitly, or set
    ``nemo_guardrails.config_path`` in a firewall YAML config, which
    :func:`~llm_firewall.config.loader.build_guard` wires up for you.
    """

    name = "nemo_guardrails"
    severity = Severity.HIGH
    category = "nemo_guardrails"
    expensive = True

    def __init__(self, config_path: str) -> None:
        self._config_path = config_path
        rails_config_cls = _import_rails_config()
        self._rails_config = rails_config_cls.from_path(config_path)
        llm_rails_cls = _import_llm_rails()
        self._rails = llm_rails_cls(self._rails_config)

    def evaluate(self, context: InspectionContext) -> list[Finding]:
        findings: list[Finding] = []
        if context.prompt.strip():
            findings.extend(
                self._check(
                    field="prompt",
                    messages=[{"role": "user", "content": context.prompt}],
                    rail_type="input",
                )
            )
        if context.response is not None and context.response.strip():
            findings.extend(
                self._check(
                    field="response",
                    messages=[
                        {"role": "user", "content": context.prompt},
                        {"role": "assistant", "content": context.response},
                    ],
                    rail_type="output",
                )
            )
        return findings

    def _check(
        self, *, field: str, messages: list[dict[str, str]], rail_type: str
    ) -> list[Finding]:
        rails_flags = {"input": False, "output": False, "dialog": False, "retrieval": False}
        rails_flags[rail_type] = True
        options = {"rails": rails_flags, "log": {"activated_rails": True}}

        result = self._rails.generate(messages=messages, options=options)
        return self._findings_from_result(field, result)

    def _findings_from_result(self, field: str, result: Any) -> list[Finding]:
        # Defensive getattr chain: the exact shape of a nemoguardrails
        # GenerationResponse is third-party and unverified against a live
        # install, so treat anything unexpected as "no rail fired" rather
        # than raising out of a policy that must stay side-effect free.
        log = getattr(result, "log", None)
        activated_rails = getattr(log, "activated_rails", None) or []
        stopped = [rail for rail in activated_rails if getattr(rail, "stop", False)]
        if not stopped:
            return []

        bot_message = ""
        response_messages = getattr(result, "response", None) or []
        if response_messages:
            last = response_messages[-1]
            bot_message = last.get("content", "") if isinstance(last, dict) else str(last)

        return [
            self._finding(
                message=f"{field} triggered NeMo Guardrails rail(s): "
                + ", ".join(rail.name for rail in stopped),
                metadata={
                    "field": field,
                    "activated_rails": [rail.name for rail in stopped],
                    "bot_message": bot_message,
                },
            )
        ]
