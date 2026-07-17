"""Command-line entry point: ``llm-redteam-firewall run --config <path>``.

Thin by design: argument parsing and process exit-code handling only.
All real wiring happens in :mod:`llm_redteam_firewall.config.loader`.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from llm_redteam_firewall.config import load_campaign_runner
from llm_redteam_firewall.domain.errors import ConfigurationError, PluginNotFoundError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-redteam-firewall",
        description="Run LLM red-team campaigns from a YAML config file.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable debug logging"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run a campaign")
    run_parser.add_argument(
        "-c", "--config", required=True, help="path to a campaign YAML config file"
    )

    return parser


async def _run(config_path: str) -> int:
    runner = load_campaign_runner(config_path)
    result = await runner.run()
    return 1 if result.vulnerable_findings else 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "run":
        try:
            return asyncio.run(_run(args.config))
        except (ConfigurationError, PluginNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    parser.error(f"unknown command: {args.command}")
    return 2  # pragma: no cover - argparse.error already exits


if __name__ == "__main__":
    raise SystemExit(main())
