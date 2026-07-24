"""FirewallTarget: gates a wrapped Target behind llm_firewall's input/output checks.

Puts an ``llm_firewall.Firewall`` in front of a real Target so a
campaign grades the model *and* its firewall together, rather than the
raw model alone: a blocked attack never reaches the wrapped Target at
all, and a response the firewall would have withheld never reaches the
evaluator either.

``Firewall.inspect()`` is synchronous and, once NeMo Guardrails is
configured, can block on a real network call -- so it's run via
``asyncio.to_thread`` here rather than called directly, to avoid
stalling the event loop (and every other attack sharing it) for the
duration of that call. See
:class:`~llm_redteam.application.execution_engine.ExecutionEngine`,
which runs many attacks concurrently via ``asyncio.gather``.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence

from llm_firewall import Firewall
from llm_firewall.domain.models import Finding as FirewallFinding
from llm_redteam.domain.models import Attack, AttackResult, ExecutionContext
from llm_redteam.domain.ports import Target
from llm_redteam.plugins import TARGETS


class FirewallTarget(Target):
    """Runs an attack through a pre-call check, the wrapped Target, then a post-call check.

    Two ways to build one:

    - **In code**, with already-constructed instances -- useful for
      tests or when ``inner`` needs something a YAML file can't express
      (e.g. :class:`~.callback_target.CallbackTarget`)::

            target = FirewallTarget(
                inner=OpenAITarget(model="gpt-4o"),
                firewall=Firewall.from_config("firewall.yaml"),
            )

    - **From a campaign YAML config**, via the ``"firewall"`` entry in
      :data:`~llm_redteam.plugins.TARGETS` (see :func:`_build_from_config`
      below) -- ``inner_type``/``inner_params`` name another registered
      Target the same way ``target.type``/``target.params`` do anywhere
      else, and ``firewall_config_path`` points at a
      :mod:`llm_firewall` YAML config::

            target:
              type: firewall
              params:
                inner_type: openai
                inner_params: {model: gpt-5.4-nano}
                firewall_config_path: firewall.yaml

    A blocked pre-call check short-circuits before ``inner`` is ever
    invoked -- the wrapped model never sees the attack. A blocked
    post-call check withholds ``inner``'s real output from the
    returned :class:`AttackResult` -- the leak never reaches the
    evaluator or the campaign transcript. Either way the block is
    reported via ``raw["firewall_decision"] == "block"`` rather than
    ``error``, since a block is the defense working, not a failure.
    """

    def __init__(self, inner: Target, firewall: Firewall, *, name: str = "firewall") -> None:
        self._inner = inner
        self._firewall = firewall
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        started = time.perf_counter()

        pre = await asyncio.to_thread(self._firewall.inspect, prompt=attack.prompt)
        if pre.blocked:
            return self._blocked_result(attack, started, stage="input", findings=pre.findings)

        result = await self._inner.execute(ctx, attack)
        if not result.succeeded:
            # Nothing to firewall-check -- the inner target itself failed.
            return result

        post = await asyncio.to_thread(
            self._firewall.inspect, prompt=attack.prompt, response=result.output
        )
        if post.blocked:
            return self._blocked_result(attack, started, stage="output", findings=post.findings)

        return AttackResult(
            attack_id=attack.id,
            target_name=self.name,
            output=result.output,
            latency_ms=(time.perf_counter() - started) * 1000,
            raw={**result.raw, "firewall_decision": "allow"},
        )

    def _blocked_result(
        self,
        attack: Attack,
        started: float,
        *,
        stage: str,
        findings: Sequence[FirewallFinding],
    ) -> AttackResult:
        return AttackResult(
            attack_id=attack.id,
            target_name=self.name,
            latency_ms=(time.perf_counter() - started) * 1000,
            raw={
                "firewall_decision": "block",
                "firewall_stage": stage,
                "firewall_findings": [f.category for f in findings],
            },
        )


@TARGETS.register("firewall")
def _build_from_config(
    *,
    inner_type: str,
    firewall_config_path: str,
    inner_params: dict[str, object] | None = None,
    name: str = "firewall",
) -> FirewallTarget:
    """YAML/CLI-safe factory for ``TARGETS.create("firewall", ...)``.

    Resolves ``inner_type``/``inner_params`` through :data:`TARGETS`
    itself (so the wrapped target can be anything already registered,
    e.g. ``"openai"``) and ``firewall_config_path`` through
    :meth:`Firewall.from_config`, then builds a :class:`FirewallTarget`
    from the results. Registered as a plain function rather than on the
    class, so :class:`FirewallTarget` itself stays directly constructible
    with already-built ``Target``/``Firewall`` instances (e.g. in tests).
    """
    inner = TARGETS.create(inner_type, **(inner_params or {}))
    firewall = Firewall.from_config(firewall_config_path)
    return FirewallTarget(inner=inner, firewall=firewall, name=name)
