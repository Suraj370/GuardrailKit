"""UnsafeToolCallPolicy: dangerous tool names, shell-injection args, leaked secrets."""

from __future__ import annotations

from llm_firewall.adapters.policies.unsafe_tool_call_policy import UnsafeToolCallPolicy
from llm_firewall.domain.models import InspectionContext, ToolCall


def test_flags_dangerous_tool_name() -> None:
    policy = UnsafeToolCallPolicy()

    findings = policy.evaluate(
        InspectionContext(
            prompt="delete the logs",
            tool_calls=(ToolCall(name="run_command", arguments={"cmd": "ls"}),),
        )
    )

    assert len(findings) == 1
    assert findings[0].metadata["tool_name"] == "run_command"


def test_flags_shell_injection_in_argument() -> None:
    policy = UnsafeToolCallPolicy()

    findings = policy.evaluate(
        InspectionContext(
            prompt="read this file",
            tool_calls=(
                ToolCall(name="read_file", arguments={"path": "report.txt; rm -rf /"}),
            ),
        )
    )

    assert len(findings) == 1
    assert findings[0].metadata["argument_value"] == "report.txt; rm -rf /"


def test_flags_secret_in_nested_argument() -> None:
    policy = UnsafeToolCallPolicy()

    findings = policy.evaluate(
        InspectionContext(
            prompt="send this",
            tool_calls=(
                ToolCall(
                    name="send_email",
                    arguments={"headers": {"Authorization": f"sk-{'a' * 20}"}},
                ),
            ),
        )
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert findings[0].metadata["matched_secret_types"] == ["openai_api_key"]


def test_allows_benign_tool_call() -> None:
    policy = UnsafeToolCallPolicy()

    findings = policy.evaluate(
        InspectionContext(
            prompt="what's the weather",
            tool_calls=(ToolCall(name="get_weather", arguments={"city": "Paris"}),),
        )
    )

    assert findings == []


def test_noop_without_tool_calls() -> None:
    policy = UnsafeToolCallPolicy()

    findings = policy.evaluate(InspectionContext(prompt="hi"))

    assert findings == []
