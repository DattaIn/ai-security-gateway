"""Heuristic prompt-injection detector.

This is intentionally NOT a single regex "gotcha" list. It scores a
request across several independent signal families and combines them,
because real injection attempts rarely rely on just one technique.

Signal families:
  1. Instruction-override phrases  ("ignore previous instructions", etc.)
  2. Role / persona hijack attempts ("you are now DAN", "act as system")
  3. System-prompt / canary extraction attempts
  4. Delimiter / context-escape attempts (fake "</system>" tags, etc.)
  5. Encoding-obfuscation smells (base64/hex blobs, excessive escapes)
  6. Excessive-agency requests (asking the model to take real-world action
     it should not have: send emails, execute code, spend money, etc.)

Each family contributes a weighted score in [0, 1]. The final score is a
capped weighted sum, not an average, so multiple weak signals can still
add up to a block -- this mirrors how real attacks stack techniques.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field


@dataclass
class DetectionSignal:
    family: str
    weight: float
    matched: list[str] = field(default_factory=list)

    @property
    def score_contribution(self) -> float:
        return self.weight if self.matched else 0.0


@dataclass
class InjectionResult:
    score: float
    signals: list[DetectionSignal]
    matched_families: list[str]

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 3),
            "matched_families": self.matched_families,
            "details": [
                {"family": s.family, "matched": s.matched}
                for s in self.signals
                if s.matched
            ],
        }


_OVERRIDE_PATTERNS = [
    r"ignore (all|any|the)?\s*(previous|prior|above|earlier)\s*(instructions|prompts|rules)",
    r"disregard (all|any|the)?\s*(previous|prior|above)\s*(instructions|rules)",
    r"forget (everything|all)\s*(you (were|have been)\s*told|instructions)",
    r"new instructions?\s*[:\-]",
    r"override\s+(your|the)\s+(system|previous)\s+(prompt|instructions)",
    r"from now on,?\s*(you|ignore|disregard)",
]

_ROLE_HIJACK_PATTERNS = [
    r"\byou are now\b",
    r"\bact as\b.{0,40}\b(system|root|admin|developer mode|unfiltered)\b",
    r"\bpretend (to be|you are)\b",
    r"\bDAN\b",
    r"\bjailbreak\b",
    r"\bdeveloper mode\b",
    r"\bno (restrictions|filters|rules) mode\b",
    r"\bunrestricted (mode|ai)\b",
]

_SYSTEM_EXTRACTION_PATTERNS = [
    r"(repeat|print|reveal|show|output)\s+(your|the)\s+(system prompt|instructions|initial prompt)",
    r"what (are|were)\s+your\s+(original\s+)?instructions",
    r"what is your system prompt",
    r"repeat everything (above|before) this",
    r"print the (text|content) above",
]

_DELIMITER_ESCAPE_PATTERNS = [
    r"</?(system|assistant|user|instructions?)>",
    r"\[/?(system|assistant|inst)\]",
    r"```system",
    r"^\s*#\s*system\s*$",
]

_EXCESSIVE_AGENCY_PATTERNS = [
    r"\bsend (an? )?(email|money|payment|wire transfer)\b",
    r"\bexecute (this|the following) (code|script|command)\b",
    r"\bdelete (all|the)\s+(files|database|records)\b",
    r"\btransfer \$?\d",
    r"\bgrant (me|admin|root) access\b",
]


def _find_matches(text: str, patterns: list[str]) -> list[str]:
    hits = []
    for pat in patterns:
        if re.search(pat, text, flags=re.IGNORECASE | re.MULTILINE):
            hits.append(pat)
    return hits


def _encoding_obfuscation_score(text: str) -> list[str]:
    """Flag long base64-looking blobs or heavy unicode-escape usage,
    which are common ways to smuggle instructions past naive filters."""
    hits = []
    b64_candidates = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    for candidate in b64_candidates:
        try:
            decoded = base64.b64decode(candidate, validate=True)
            decoded.decode("utf-8")
            hits.append("base64_blob")
            break
        except (ValueError, UnicodeDecodeError):
            continue
    if len(re.findall(r"\\u[0-9a-fA-F]{4}", text)) >= 5:
        hits.append("excessive_unicode_escapes")
    return hits


def detect_prompt_injection(text: str, system_prompt_canary: str | None = None) -> InjectionResult:
    """Score `text` for likely prompt-injection intent.

    `system_prompt_canary` (a unique token planted in the real system
    prompt) lets us catch cases where a model's *output* echoes back a
    secret it should never have exposed -- callers should also run this
    over completions, not just user input.
    """
    # Weights are calibrated so that a single, unambiguous high-confidence
    # signal (a direct override phrase, a role-hijack attempt, an explicit
    # system-prompt extraction request, or an excessive-agency request) is
    # enough to cross the default block threshold on its own -- these are
    # rarely produced by benign traffic. Weaker/more-ambiguous signals
    # (delimiter escapes, encoding obfuscation) contribute enough to FLAG
    # a request but need to stack with something else to BLOCK it.
    signals = [
        DetectionSignal("instruction_override", 0.80, _find_matches(text, _OVERRIDE_PATTERNS)),
        DetectionSignal("role_hijack", 0.75, _find_matches(text, _ROLE_HIJACK_PATTERNS)),
        DetectionSignal("system_prompt_extraction", 0.80, _find_matches(text, _SYSTEM_EXTRACTION_PATTERNS)),
        DetectionSignal("delimiter_escape", 0.45, _find_matches(text, _DELIMITER_ESCAPE_PATTERNS)),
        DetectionSignal("encoding_obfuscation", 0.45, _encoding_obfuscation_score(text)),
        DetectionSignal("excessive_agency", 0.80, _find_matches(text, _EXCESSIVE_AGENCY_PATTERNS)),
    ]

    if system_prompt_canary and system_prompt_canary in text:
        signals.append(DetectionSignal("canary_leak", 1.0, [system_prompt_canary]))

    raw_score = sum(s.score_contribution for s in signals)
    score = min(raw_score, 1.0)
    matched_families = [s.family for s in signals if s.matched]

    return InjectionResult(score=score, signals=signals, matched_families=matched_families)
