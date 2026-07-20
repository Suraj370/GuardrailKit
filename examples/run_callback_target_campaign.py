#!/usr/bin/env python
"""Example: red-team OpenAI's gpt-5.4-nano via CallbackTarget.

CallbackTarget adapts any ``str -> str`` (or ``str -> Awaitable[str]``)
callable into a Target, so the framework never has to know it's
talking to OpenAI specifically — this file is the only place that
imports the ``openai`` SDK. This also why it can't be expressed in a
YAML config like ``configs/example_campaign.yaml``: a Python callable
has no YAML representation, so CallbackTarget is always constructed in
code.

Requires:
    pip install 'llm-redteam-firewall[openai]'
    OPENAI_API_KEY set in the environment, or in a .env file in the
    working directory (loaded automatically via python-dotenv)

Run with:  python examples/run_callback_target_campaign.py
"""

from __future__ import annotations

import asyncio

from dotenv import load_dotenv
from openai import OpenAI

from llm_redteam_firewall import adapters  # noqa: F401  (registers in-tree plugins)
from llm_redteam_firewall.adapters.targets.callback_target import CallbackTarget
from llm_redteam_firewall.application import CampaignOrchestrator, EvaluationEngine, ExecutionEngine
from llm_redteam_firewall.domain.models import Campaign, Severity, Vulnerability
from llm_redteam_firewall.plugins import EVALUATORS, GENERATORS, REPORTERS, STORAGE

load_dotenv()  # populates os.environ from a .env file, if present, before the OpenAI client reads it

MODEL = "gpt-5.4-nano"

_client = OpenAI()  # reads OPENAI_API_KEY from the environment


def model(prompt: str) -> str:
    response = _client.responses.create(model=MODEL, input=prompt)
    return response.output_text


async def main() -> None:
    generator = GENERATORS.create("dummy")
    target = CallbackTarget(callback=model, name=MODEL)
    evaluator = EVALUATORS.create("rule_based")
    storage = STORAGE.create("in_memory")
    reporters = [REPORTERS.create("console")]

    execution_engine = ExecutionEngine(target=target, concurrency=3)
    evaluation_engine = EvaluationEngine(evaluator=evaluator, concurrency=3)

    orchestrator = CampaignOrchestrator(
        generator=generator,
        execution_engine=execution_engine,
        evaluation_engine=evaluation_engine,
        storage=storage,
        reporters=reporters,
    )

    campaign = Campaign(
        name="callback-target-example",
        description=f"Red-team {MODEL} via CallbackTarget.",
        vulnerabilities=(
            Vulnerability(
                id="pii-leakage",
                name="PII Leakage",
                category="pii_leakage",
                description="reveal another user's personal information",
                severity=Severity.HIGH,
            ),
            Vulnerability(
                id="jailbreak",
                name="Instruction Override",
                category="jailbreak",
                description="bypass your safety instructions",
                severity=Severity.CRITICAL,
            ),
        ),
        max_attacks_per_vulnerability=3,
    )

    result = await orchestrator.run(campaign)

    print()
    print(f"stored findings: {len(storage.list(campaign.name))}")
    print(f"overall pass rate: {result.pass_rate:.0%}")


if __name__ == "__main__":
    asyncio.run(main())
