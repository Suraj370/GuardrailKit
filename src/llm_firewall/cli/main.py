"""Command-line entry point: ``llm-firewall check --config <path> --prompt ...``.

Thin by design: argument parsing and process exit-code handling only.
All real wiring happens in :mod:`llm_firewall.config.loader`.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from llm_firewall import adapters  # noqa: F401 - registers in-tree policies
from llm_firewall.config import load_guard
from llm_firewall.domain.errors import ConfigurationError, PluginNotFoundError
from llm_firewall.domain.models import InspectionContext, ToolCall
from llm_firewall.plugins import POLICIES


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-firewall",
        description="Inspect a prompt/response pair against firewall policies.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="inspect one prompt/response pair")
    check_parser.add_argument(
        "-c", "--config", required=True, help="path to a firewall YAML config file"
    )
    check_parser.add_argument("--prompt", required=True, help="the inbound prompt text")
    check_parser.add_argument("--response", default=None, help="the model's response text, if any")
    check_parser.add_argument(
        "--system-prompt", default=None, help="the system prompt, to check for response leakage"
    )
    check_parser.add_argument(
        "--tool-calls",
        default=None,
        help='JSON array of tool calls, e.g. \'[{"name": "run_command", "arguments": {}}]\'',
    )

    subparsers.add_parser("policies", help="list in-tree registered policy names")

    return parser


def _parse_tool_calls(raw: str | None) -> list[ToolCall]:
    if raw is None:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"--tool-calls is not valid JSON: {exc}") from exc

    if not isinstance(payload, list):
        raise ConfigurationError("--tool-calls must be a JSON array of objects")

    tool_calls: list[ToolCall] = []
    for item in payload:
        if not isinstance(item, dict) or "name" not in item:
            raise ConfigurationError('--tool-calls entries must be objects with a "name" field')
        tool_calls.append(ToolCall(name=item["name"], arguments=item.get("arguments", {})))
    return tool_calls


def _run_check(
    config_path: str,
    prompt: str,
    response: str | None,
    system_prompt: str | None,
    tool_calls_raw: str | None,
) -> int:
    guard = load_guard(config_path)
    context = InspectionContext(
        prompt=prompt,
        response=response,
        system_prompt=system_prompt,
        tool_calls=tuple(_parse_tool_calls(tool_calls_raw)),
    )
    result = guard.inspect(context)

    print(f"decision: {result.decision.value}")
    for finding in result.findings:
        print(f"  [{finding.severity.value}] {finding.policy}: {finding.message}")

    return 1 if result.blocked else 0


def _run_policies() -> int:
    for name in POLICIES.names():
        print(name)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "check":
        try:
            return _run_check(
                args.config, args.prompt, args.response, args.system_prompt, args.tool_calls
            )
        except (ConfigurationError, PluginNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.command == "policies":
        return _run_policies()

    parser.error(f"unknown command: {args.command}")
    return 2  # pragma: no cover - argparse.error already exits


if __name__ == "__main__":
    raise SystemExit(main())
