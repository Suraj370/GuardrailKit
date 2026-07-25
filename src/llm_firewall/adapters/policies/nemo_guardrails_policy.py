"""NemoGuardrailsPolicy: runs a NeMo Guardrails Colang config as a firewall policy.

The ``nemoguardrails`` package is lazily imported (only when this policy
is actually constructed, not at module scope) mirroring
:mod:`~llm_redteam.adapters.targets.openai_target`'s lazy-import pattern
-- so importing ``llm_firewall.adapters`` never requires the
``nemo-guardrails`` extra. Construction *does* parse the given Colang
rails directory via ``RailsConfig.from_path`` (so a broken config fails
fast at wiring time).

Both ``evaluate`` (sync) and ``aevaluate`` (async, see
:meth:`~llm_firewall.domain.ports.Policy.aevaluate`) check the prompt
and response with separate ``LLMRails.generate()``/``generate_async()``
calls, each restricting ``GenerationOptions.rails`` to just the one rail
category being checked (``dialog`` disabled throughout). Disabling
dialog rails means NeMo never generates its own completion -- for the
response check, the caller-supplied response is passed as the trailing
message and checked against the output rails as-is. A rail counts as a
block when any ``ActivatedRail`` in the returned ``GenerationLog`` has
``stop=True``.

**Two distinct concurrency bugs showed up under real, concurrent
campaign runs, and both are worked around here:**

1. Reusing one persistent ``LLMRails`` instance's underlying async HTTP
   client across concurrent calls corrupts its event-loop-bound state
   (``RuntimeError: cannot schedule new futures after shutdown`` --
   matches `NVIDIA-NeMo/Guardrails#320 <https://github.com/NVIDIA-NeMo/Guardrails/issues/320>`_).
   Fix: build a fresh ``LLMRails`` for every check instead of reusing
   one.
2. NeMo's global LLM-framework registry
   (``nemoguardrails.llm.frameworks.registry``) does an unsynchronized
   check-then-register the first time any ``LLMRails`` is built in the
   process; two threads racing to build the very first one can both see
   "not registered" and both try to register, and the loser raises
   ``ValueError("Framework 'default' is already registered.")``. Fix:
   ``__init__`` builds one throwaway instance up front, single-threaded,
   so that race can never happen later.

Bug 1's fix (fresh instance per check) turned out to be necessary but
not sufficient: even with a fresh ``LLMRails`` per call, going through
the *sync* ``generate()`` wrapper from :meth:`evaluate` means NeMo
internally does its own ``loop.run_until_complete(...)``, and
:class:`~llm_redteam.adapters.targets.firewall_target.FirewallTarget`
was calling that sync method via ``asyncio.to_thread`` -- whose default
executor *reuses OS threads* across many different attacks in a
campaign. A worker thread that ran one NeMo call earlier can hand a
stale, already-shut-down loop to the next unrelated call that happens
to land on the same thread later, reproducing the exact same
"cannot schedule new futures" failure one layer up. That's what
:meth:`aevaluate` actually fixes: it calls ``generate_async`` natively
on the caller's own event loop, with no thread and no nested loop at
all, so there's nothing to hand off. ``FirewallTarget`` uses
:meth:`~llm_firewall.firewall.Firewall.ainspect` specifically to reach
this path. :meth:`evaluate` (the sync entry point, used by the CLI and
any synchronous caller) keeps the thread-per-call-safe fresh-instance
fix from Bug 1, since it has no native async caller to hand off to.

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
        # Resolved once and reused, but *not* instantiated here -- see the
        # module docstring for why a fresh LLMRails is built per check.
        self._llm_rails_cls = _import_llm_rails()
        # Build (and discard) one instance now, on this single construction
        # thread, purely to force NeMo's global LLM-framework registry
        # (nemoguardrails.llm.frameworks.registry) to register itself once.
        # That registry's get_framework() does an unsynchronized
        # check-then-register: two threads racing to build the *first*
        # LLMRails at the same time can both see "not registered yet" and
        # both call register_framework(), and the loser raises
        # ValueError("Framework 'default' is already registered."). Once
        # registered, later lookups are plain dict reads and are safe to
        # race -- so paying for one throwaway instance here avoids the
        # race entirely for every real, concurrent _check() call later.
        self._llm_rails_cls(self._rails_config)

    def evaluate(self, context: InspectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for field, messages, rail_type in self._checks_for(context):
            rails = self._llm_rails_cls(self._rails_config)
            result = rails.generate(messages=messages, options=self._options_for(rail_type))
            findings.extend(self._findings_from_result(field, result))
        return findings

    async def aevaluate(self, context: InspectionContext) -> list[Finding]:
        """Async counterpart to :meth:`evaluate` -- see the module docstring.

        Calls NeMo's native ``generate_async`` directly instead of the
        sync ``generate()`` wrapper, so no thread-pool detour or nested
        event loop is ever involved.
        """
        findings: list[Finding] = []
        for field, messages, rail_type in self._checks_for(context):
            rails = self._llm_rails_cls(self._rails_config)
            result = await rails.generate_async(
                messages=messages, options=self._options_for(rail_type)
            )
            findings.extend(self._findings_from_result(field, result))
        return findings

    @staticmethod
    def _checks_for(
        context: InspectionContext,
    ) -> list[tuple[str, list[dict[str, str]], str]]:
        """Build the ``(field, messages, rail_type)`` tuples this context needs checked."""
        checks: list[tuple[str, list[dict[str, str]], str]] = []
        if context.prompt.strip():
            checks.append(("prompt", [{"role": "user", "content": context.prompt}], "input"))
        if context.response is not None and context.response.strip():
            checks.append(
                (
                    "response",
                    [
                        {"role": "user", "content": context.prompt},
                        {"role": "assistant", "content": context.response},
                    ],
                    "output",
                )
            )
        return checks

    @staticmethod
    def _options_for(rail_type: str) -> dict[str, Any]:
        rails_flags = {"input": False, "output": False, "dialog": False, "retrieval": False}
        rails_flags[rail_type] = True
        return {"rails": rails_flags, "log": {"activated_rails": True}}

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
