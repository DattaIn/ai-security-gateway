"""Data Loss Prevention (DLP) scanning and redaction.

Detects and redacts common categories of sensitive data in both
directions (user input -> LLM, and LLM output -> user):
  - Credentials & secrets (API keys, private keys, JWTs, passwords)
  - PII (email, phone, SSN-like, credit-card-like numbers)
  - Internal identifiers that hint at proprietary infrastructure

This module intentionally errs toward pattern-based, explainable
detection rather than opaque ML classifiers -- for a security gateway,
"why did it flag this" needs a one-line answer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    CRITICAL = "critical"


@dataclass
class DlpRule:
    name: str
    pattern: re.Pattern
    severity: Severity
    redaction_label: str


_RULES: list[DlpRule] = [
    DlpRule(
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        "[REDACTED_AWS_KEY]",
    ),
    DlpRule(
        "generic_api_key",
        re.compile(r"\b(?:api|apikey|secret)[_-]?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}", re.IGNORECASE),
        Severity.CRITICAL,
        "[REDACTED_API_KEY]",
    ),
    DlpRule(
        "private_key_block",
        re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP)?\s?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "[REDACTED_PRIVATE_KEY]",
    ),
    DlpRule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        Severity.CRITICAL,
        "[REDACTED_JWT]",
    ),
    DlpRule(
        "credit_card",
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        Severity.CRITICAL,
        "[REDACTED_CARD_NUMBER]",
    ),
    DlpRule(
        "ssn_like",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        Severity.CRITICAL,
        "[REDACTED_SSN]",
    ),
    DlpRule(
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        Severity.MEDIUM,
        "[REDACTED_EMAIL]",
    ),
    DlpRule(
        "phone_number",
        re.compile(r"\b(?:\+?\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}\b"),
        Severity.MEDIUM,
        "[REDACTED_PHONE]",
    ),
    DlpRule(
        "internal_hostname",
        re.compile(r"\b[a-zA-Z0-9-]+\.(internal|corp|local)\b", re.IGNORECASE),
        Severity.LOW,
        "[REDACTED_INTERNAL_HOST]",
    ),
]


@dataclass
class DlpFinding:
    rule_name: str
    severity: Severity
    count: int


@dataclass
class DlpScanResult:
    findings: list[DlpFinding] = field(default_factory=list)
    redacted_text: str = ""
    has_critical: bool = False

    def as_dict(self) -> dict:
        return {
            "has_critical": self.has_critical,
            "findings": [
                {"rule": f.rule_name, "severity": f.severity.value, "count": f.count}
                for f in self.findings
            ],
        }


def scan_and_redact(text: str) -> DlpScanResult:
    redacted = text
    findings: list[DlpFinding] = []
    has_critical = False

    for rule in _RULES:
        matches = rule.pattern.findall(text)
        if matches:
            count = len(matches) if isinstance(matches[0], str) else len(rule.pattern.findall(text))
            findings.append(DlpFinding(rule.name, rule.severity, count))
            redacted = rule.pattern.sub(rule.redaction_label, redacted)
            if rule.severity == Severity.CRITICAL:
                has_critical = True

    return DlpScanResult(findings=findings, redacted_text=redacted, has_critical=has_critical)
