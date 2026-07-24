"""Rule-based Policy adapters. Importing this module registers all of them.

There are deliberately no regex-based PII or hateful/sexual-content
policies here: NeMo Guardrails' built-in rails cover both more reliably
than hand-rolled patterns would --  Sensitive Data Detection
(Presidio-backed) for PII, and its Content Safety rail (NIM
classifiers, hate/sexual/violence taxonomy) for hateful and
sexual/explicit content. Both are left to
:class:`~llm_firewall.adapters.policies.nemo_guardrails_policy.NemoGuardrailsPolicy`
once its ``evaluate()`` is implemented, rather than duplicated here --
which means, until then, this firewall has no coverage for either
category (see the coverage-gap analysis this decision was based on).

:class:`NemoGuardrailsPolicy` is also the exception to "importing this
module registers all of them": it requires a ``config_path`` with no
sensible default, so it is importable here but not eagerly
instantiated/registered — see its docstring and
:func:`~llm_firewall.config.loader.build_guard`.
"""

from llm_firewall.adapters.policies.nemo_guardrails_policy import NemoGuardrailsPolicy
from llm_firewall.adapters.policies.prompt_injection_policy import PromptInjectionPolicy
from llm_firewall.adapters.policies.secret_policy import SecretPolicy
from llm_firewall.adapters.policies.system_prompt_leak_policy import SystemPromptLeakPolicy
from llm_firewall.adapters.policies.unsafe_tool_call_policy import UnsafeToolCallPolicy

__all__ = [
    "NemoGuardrailsPolicy",
    "PromptInjectionPolicy",
    "SecretPolicy",
    "SystemPromptLeakPolicy",
    "UnsafeToolCallPolicy",
]
