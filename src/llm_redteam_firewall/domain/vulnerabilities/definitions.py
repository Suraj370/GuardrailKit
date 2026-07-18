"""VulnerabilityDefinition: a known vulnerability type and its recommended defaults.

Distinct from :class:`~llm_redteam_firewall.domain.models.vulnerability.Vulnerability`,
which is a concrete probe target authored inside one
:class:`~llm_redteam_firewall.domain.models.campaign.Campaign` (an id, a
category tag, a severity, as written in campaign YAML): a
``VulnerabilityDefinition`` is reference data describing a *kind* of
vulnerability in the abstract — what it is, which attack generator and
attack categories are typically used to probe it, and which policies
typically grade it — so that a campaign can reference it by id instead
of restating those implementation details inline every time.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from llm_redteam_firewall.domain.models import Severity


@dataclass(frozen=True, slots=True)
class VulnerabilityDefinition:
    """A well-known class of vulnerability, with recommended defaults for probing it.

    ``default_attack_generator`` and ``default_policies`` name plugins
    by the same string keys used in campaign YAML / the plugin
    registries (:data:`~llm_redteam_firewall.plugins.GENERATORS`,
    :data:`~llm_redteam_firewall.plugins.POLICIES`) — this module does
    not import those registries, so it stays a pure domain description
    rather than a live wiring of adapters.
    """

    id: str
    name: str
    description: str
    default_attack_generator: str
    default_attack_categories: tuple[str, ...]
    default_policies: tuple[str, ...]
    severity: Severity = Severity.MEDIUM
    tags: tuple[str, ...] = field(default_factory=tuple)


BUILTIN_VULNERABILITY_DEFINITIONS: tuple[VulnerabilityDefinition, ...] = (
    VulnerabilityDefinition(
        id="prompt_injection",
        name="Prompt Injection",
        description=(
            "Attempts to override, ignore, or bypass the target's system "
            "instructions via crafted user input."
        ),
        default_attack_generator="dummy",
        default_attack_categories=("prompt_injection",),
        default_policies=("prompt_leak",),
        severity=Severity.HIGH,
        tags=("owasp-llm01", "instruction-override"),
    ),
    VulnerabilityDefinition(
        id="jailbreak",
        name="Jailbreak",
        description=(
            "Attempts to bypass safety guardrails to elicit content the "
            "target is instructed to refuse."
        ),
        default_attack_generator="dummy",
        default_attack_categories=("jailbreak",),
        default_policies=(),
        severity=Severity.CRITICAL,
        tags=("owasp-llm01", "guardrail-bypass"),
    ),
    VulnerabilityDefinition(
        id="prompt_leakage",
        name="System Prompt Leakage",
        description="Attempts to extract the target's hidden system prompt or instructions.",
        default_attack_generator="dummy",
        default_attack_categories=("prompt_leakage",),
        default_policies=("prompt_leak",),
        severity=Severity.HIGH,
        tags=("owasp-llm07",),
    ),
    VulnerabilityDefinition(
        id="pii_leakage",
        name="PII Leakage",
        description=(
            "Attempts to make the target disclose personally identifiable "
            "information about a real or fictional person."
        ),
        default_attack_generator="dummy",
        default_attack_categories=("pii_leakage",),
        default_policies=("pii_leak",),
        severity=Severity.HIGH,
        tags=("owasp-llm06", "privacy"),
    ),
    VulnerabilityDefinition(
        id="secret_leakage",
        name="Secret / Credential Leakage",
        description=(
            "Attempts to make the target disclose API keys, tokens, "
            "passwords, or other credentials."
        ),
        default_attack_generator="dummy",
        default_attack_categories=("secret_leakage",),
        default_policies=("secret_leak",),
        severity=Severity.CRITICAL,
        tags=("owasp-llm06", "credentials"),
    ),
    VulnerabilityDefinition(
        id="tool_misuse",
        name="Tool Misuse / Excessive Agency",
        description=(
            "Attempts to induce unsafe or destructive tool calls via a "
            "target with connected tools."
        ),
        default_attack_generator="dummy",
        default_attack_categories=("tool_misuse",),
        default_policies=("tool_misuse",),
        severity=Severity.HIGH,
        tags=("owasp-llm08", "excessive-agency"),
    ),
)
