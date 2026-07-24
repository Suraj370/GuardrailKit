"""SecretPolicy: rule-based detection of credentials and API keys."""

from __future__ import annotations

import re

from llm_firewall.domain.models import Finding, InspectionContext, Severity
from llm_firewall.domain.ports import Policy
from llm_firewall.plugins import POLICIES

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*"
            r"['\"]?[^\s'\"]{8,}"
        ),
    ),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*\b")),
)


@POLICIES.register
class SecretPolicy(Policy):
    """Flags prompts or responses that appear to leak API keys, tokens, or private keys."""

    name = "secret"
    severity = Severity.CRITICAL
    category = "secret_leakage"

    def evaluate(self, context: InspectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for field_name, text in (("prompt", context.prompt), ("response", context.response)):
            if not text or not text.strip():
                continue

            matched = [label for label, pattern in SECRET_PATTERNS if pattern.search(text)]
            if matched:
                findings.append(
                    self._finding(
                        message=f"{field_name} appears to leak secrets ({', '.join(matched)})",
                        metadata={"field": field_name, "matched_secret_types": matched},
                    )
                )
        return findings
