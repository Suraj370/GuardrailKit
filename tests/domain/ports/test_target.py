"""Target: abc.ABC contract."""

from __future__ import annotations

import pytest

from llm_redteam.adapters.targets.mock_target import MockTarget
from llm_redteam.domain.models import Attack, AttackResult, ExecutionContext
from llm_redteam.domain.ports import Target


def test_cannot_instantiate_the_interface_directly() -> None:
    with pytest.raises(TypeError):
        Target()  # type: ignore[abstract]


def test_subclass_missing_execute_cannot_be_instantiated() -> None:
    class _Incomplete(Target):
        name = "incomplete"

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


def test_subclass_missing_name_cannot_be_instantiated() -> None:
    class _Incomplete(Target):
        async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
            return AttackResult(attack_id=attack.id, target_name="incomplete")

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


@pytest.mark.asyncio
async def test_complete_subclass_can_be_instantiated_and_used() -> None:
    class _Complete(Target):
        name = "complete"

        async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
            return AttackResult(attack_id=attack.id, target_name=self.name, output="ok")

    target = _Complete()
    ctx = ExecutionContext(campaign_name="c1")
    attack = Attack(id="a1", vulnerability_id="v1", prompt="p")

    assert isinstance(target, Target)
    result = await target.execute(ctx, attack)
    assert result.output == "ok"


def test_mock_target_satisfies_the_interface() -> None:
    assert isinstance(MockTarget(), Target)
