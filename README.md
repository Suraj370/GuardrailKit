# llm-redteam-firewall

A pluggable, hexagonal-architecture LLM red-team harness that  runs security-style attack campaigns against LLM apps, grades the responses, stores findings, and reports them.
> **Status:** scaffold. Interfaces, domain models, plugin registry, wiring,
> and reference (dummy/mock) implementations are in place and tested.
> Real integrations (OpenAI, Anthropic, HTTP, local models, LangGraph
> agents, Garak, an LLM-judge evaluator) are intentionally left as
> `NotImplementedError` stubs — see `ARCHITECTURE.md` → *Future extension
> points*.

## Why this exists

Red-teaming an LLM application means running the same shape of pipeline
against wildly different things: different *targets* (a hosted API, an
in-house agent, a RAG pipeline), different *attack sources* (static
prompts, a fuzzing library, an LLM-driven mutator), and different
*graders* (keyword rules, a judge model, a classifier). This framework
treats all three as swappable plugins behind narrow interfaces, so the
orchestration logic — "for each vulnerability, generate attacks, run
them, grade them, record findings, report" — never has to change.

## Campaign execution flow

```
Campaign → Vulnerability → AttackGenerator → Target → Evaluator → Reporter
                                                          ↓
                                                    FindingsStorage

Attack + Response → Policy (×N via PolicyEngine) → Finding(s)
```

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
make install-dev

# Run the example campaign programmatically (no config file, no network):
make run-example

# ...or the equivalent, driven by a YAML config file via the CLI:
make run-example-cli
```

Both run the same pipeline using only dependency-free reference
adapters: `DummyAttackGenerator`, `MockTarget`, `DummyEvaluator`,
`InMemoryStorage`, and `ConsoleReporter`/`JSONReporter`.

## Package layout

| Package                          | Responsibility                                                                 | Depends on |
|-----------------------------------|---------------------------------------------------------------------------------|------------|
| `domain.models`                   | Entities/value objects: `Campaign`, `Vulnerability`, `Attack`, `AttackResult`, `Response`, `EvaluationResult`, `Finding`, `Report` | *(nothing)* |
| `domain.ports`                    | Interfaces (`ABC`/`Protocol`): `AttackGenerator`, `Target`, `Evaluator`, `Policy`, `FindingsStorage`, `Reporter` | `domain.models` |
| `domain.errors`                   | Shared exception hierarchy                                                     | *(nothing)* |
| `domain.vulnerabilities`          | `VulnerabilityDefinition` catalog + `VulnerabilityRegistry` (`VULNERABILITY_REGISTRY`), `to_vulnerability(...)` — lets a campaign reference a vulnerability by id instead of inlining its generator/categories/policies | `domain.models`, `domain.errors` |
| `domain.campaigns`                | `AttackCampaign`/`AttackBatch` planning layer between `AttackGenerator` output and `ExecutionEngine` (declared, not-yet-enforced execution strategy/retry/concurrency) | `domain.models` |
| `application`                     | Use cases: `CampaignOrchestrator`, `ExecutionEngine`, `EvaluationEngine`, `PolicyEngine` | `domain` |
| `application.policy_engine`       | `PolicyEngine`: runs every registered `Policy` over an attack/response pair, aggregating multi-rule findings (symmetric to `EvaluationEngine`, but many-to-one) | `domain` |
| `adapters.generators`             | `AttackGenerator` implementations (`dummy`, `garak` stub)                       | `domain`, `plugins` |
| `adapters.targets`                | `Target` implementations (`mock`, `callback`, `openai`/`anthropic`/`http`/`local_model`/`langgraph` stubs) | `domain`, `plugins` |
| `adapters.evaluators`             | `Evaluator` implementations (`dummy`, `rule_based`, `llm_judge` stub)            | `domain`, `plugins` |
| `adapters.policies`               | Rule-based `Policy` implementations (`prompt_leak`, `pii_leak`, `secret_leak`, `tool_misuse`) | `domain`, `plugins` |
| `adapters.storage`                | `FindingsStorage` implementations (`in_memory`, `sqlite` stub)                  | `domain`, `plugins` |
| `adapters.reporting`              | `Reporter` implementations (`console`, `json`, `html`, `markdown` stub)          | `domain`, `plugins` |
| `plugins`                         | Factory `Registry` per port + `PolicyRegistry` for multi-rule policy runs       | `domain.ports` |
| `config`                          | Pydantic YAML schema + the DI **composition root** (`build_campaign_runner`)    | everything |
| `cli`                             | `llm-redteam-firewall run --config <file>`                                      | `config` |

Full dependency-direction diagram, sequence diagram, and extension-point
details: see [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Adding a target: the pattern for every extension point

```python
# src/llm_redteam_firewall/adapters/targets/my_target.py
from llm_redteam_firewall.domain.models import Attack, AttackResult, ExecutionContext
from llm_redteam_firewall.plugins import TARGETS

@TARGETS.register("my_target")
class MyTarget:
    name = "my_target"

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint

    async def execute(self, ctx: ExecutionContext, attack: Attack) -> AttackResult:
        ...  # call your system, return an AttackResult
```

Then reference it by name in a campaign config:

```yaml
target:
  type: my_target
  params:
    endpoint: "https://my-service.internal/chat"
```

No orchestrator, engine, or CLI code changes. The same pattern applies to
`AttackGenerator` (e.g. a future `GarakAttackGenerator`), `Evaluator`,
`Policy`, `FindingsStorage`, and `Reporter`.

## Development

```bash
make lint        # ruff check
make format       # ruff format + ruff --fix
make typecheck    # mypy --strict
make test          # pytest
make check         # lint + typecheck + test
```

## License

MIT — see [`LICENSE`](LICENSE).
