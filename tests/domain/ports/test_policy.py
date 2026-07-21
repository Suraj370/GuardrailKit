"""Policy: abc.ABC contract."""

from __future__ import annotations

import pytest

from llm_redteam.adapters.policies.prompt_leak_policy import PromptLeakPolicy
from llm_redteam.domain.models import Attack, Finding, Response
from llm_redteam.domain.ports import Policy


def test_cannot_instantiate_the_interface_directly() -> None:
    with pytest.raises(TypeError):
        Policy()  # type: ignore[abstract]


def test_subclass_missing_evaluate_cannot_be_instantiated() -> None:
    class _Incomplete(Policy):
        name = "incomplete"

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


def test_subclass_missing_name_cannot_be_instantiated() -> None:
    class _Incomplete(Policy):
        def evaluate(self, attack: Attack, response: Response) -> list[Finding]:
            return []

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


def test_complete_subclass_can_be_instantiated_and_used() -> None:
    class _Complete(Policy):
        name = "complete"

        def evaluate(self, attack: Attack, response: Response) -> list[Finding]:
            return []

    policy = _Complete()
    attack = Attack(id="a1", vulnerability_id="v1", prompt="p")
    response = Response(attack_id="a1", content="ok")

    assert isinstance(policy, Policy)
    assert policy.evaluate(attack, response) == []


def test_prompt_leak_policy_satisfies_the_interface() -> None:
    assert isinstance(PromptLeakPolicy(), Policy)


def test_finding_helper_builds_vulnerable_finding() -> None:
    class _AlwaysFlag(Policy):
        name = "always_flag"

        def evaluate(self, attack: Attack, response: Response) -> list[Finding]:
            return [self._finding(attack, response, reasoning="flagged")]

    policy = _AlwaysFlag()
    attack = Attack(id="a1", vulnerability_id="v1", prompt="p")
    response = Response(attack_id="a1", content="bad", target_name="mock")

    [finding] = policy.evaluate(attack, response)

    assert finding.is_vulnerable is True
    assert finding.passed is False
    assert finding.reasoning == "flagged"
    assert finding.vulnerability.id == "policy:always_flag"
    assert finding.attack_result.output == "bad"
