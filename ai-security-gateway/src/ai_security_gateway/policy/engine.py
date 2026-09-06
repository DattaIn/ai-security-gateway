"""Policy decision engine.

This is the component that turns raw detector signals into an
actionable, explainable decision. Keeping it separate from the
detectors means the *thresholds and business logic* can be reviewed
and changed independently of the *detection heuristics* -- which
matters a lot when someone asks "why did the gateway block this?"
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ai_security_gateway.config import GatewaySettings
from ai_security_gateway.detectors.dlp import DlpScanResult
from ai_security_gateway.detectors.prompt_injection import InjectionResult


class Decision(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"       # allowed through, but logged for review
    BLOCK = "block"


@dataclass
class PolicyOutcome:
    decision: Decision
    reasons: list[str] = field(default_factory=list)
    injection_score: float = 0.0
    dlp_summary: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "reasons": self.reasons,
            "injection_score": round(self.injection_score, 3),
            "dlp": self.dlp_summary,
        }


def evaluate_input(
    injection_result: InjectionResult,
    dlp_result: DlpScanResult,
    settings: GatewaySettings,
) -> PolicyOutcome:
    reasons: list[str] = []
    decision = Decision.ALLOW

    if dlp_result.has_critical and settings.dlp_block_on_critical:
        decision = Decision.BLOCK
        reasons.append("Critical sensitive data detected in input (credentials/secrets).")

    if injection_result.score >= settings.injection_block_threshold:
        decision = Decision.BLOCK
        reasons.append(
            f"Prompt-injection score {injection_result.score:.2f} >= block threshold "
            f"{settings.injection_block_threshold:.2f} (families: {', '.join(injection_result.matched_families)})."
        )
    elif injection_result.score >= settings.injection_flag_threshold and decision != Decision.BLOCK:
        decision = Decision.FLAG
        reasons.append(
            f"Prompt-injection score {injection_result.score:.2f} >= flag threshold "
            f"{settings.injection_flag_threshold:.2f} (families: {', '.join(injection_result.matched_families)})."
        )

    if not reasons:
        reasons.append("No policy violations detected.")

    return PolicyOutcome(
        decision=decision,
        reasons=reasons,
        injection_score=injection_result.score,
        dlp_summary=dlp_result.as_dict(),
    )


def evaluate_output(
    injection_result: InjectionResult,
    dlp_result: DlpScanResult,
    settings: GatewaySettings,
) -> PolicyOutcome:
    """Output-side policy is stricter on DLP (never let secrets leak out)
    and treats any canary leak as an automatic block, since that means
    the system prompt itself was exfiltrated."""
    reasons: list[str] = []
    decision = Decision.ALLOW

    if "canary_leak" in injection_result.matched_families:
        decision = Decision.BLOCK
        reasons.append("System-prompt canary token detected in model output -- prompt leak confirmed.")

    if dlp_result.has_critical:
        decision = Decision.BLOCK
        reasons.append("Critical sensitive data detected in model output; response withheld and redacted.")

    if not reasons:
        reasons.append("Output passed DLP and leak checks.")

    return PolicyOutcome(
        decision=decision,
        reasons=reasons,
        injection_score=injection_result.score,
        dlp_summary=dlp_result.as_dict(),
    )
