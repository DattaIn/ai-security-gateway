"""Central configuration for the gateway.

All thresholds live here so security tuning is auditable in one place
rather than scattered across detector modules.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class GatewaySettings:
    # -- Rate limiting --------------------------------------------------
    rate_limit_requests: int = int(os.getenv("GATEWAY_RATE_LIMIT_REQUESTS", "60"))
    rate_limit_window_seconds: int = int(os.getenv("GATEWAY_RATE_LIMIT_WINDOW", "60"))

    # -- Prompt-injection detection --------------------------------------
    # Score >= block_threshold => request is rejected outright.
    # Score >= flag_threshold  => request is allowed but logged/flagged.
    injection_block_threshold: float = float(os.getenv("GATEWAY_INJECTION_BLOCK", "0.75"))
    injection_flag_threshold: float = float(os.getenv("GATEWAY_INJECTION_FLAG", "0.4"))

    # -- DLP --------------------------------------------------------------
    dlp_redact_on_input: bool = os.getenv("GATEWAY_DLP_REDACT_INPUT", "true").lower() == "true"
    dlp_redact_on_output: bool = os.getenv("GATEWAY_DLP_REDACT_OUTPUT", "true").lower() == "true"
    dlp_block_on_critical: bool = os.getenv("GATEWAY_DLP_BLOCK_CRITICAL", "true").lower() == "true"

    # -- Output validation --------------------------------------------------
    max_output_tokens_estimate: int = int(os.getenv("GATEWAY_MAX_OUTPUT_TOKENS", "4096"))

    # -- Audit ----------------------------------------------------------------
    audit_log_path: str = os.getenv("GATEWAY_AUDIT_LOG_PATH", "logs/audit.jsonl")

    system_prompt_canary: str = field(
        default_factory=lambda: os.getenv(
            "GATEWAY_SYSTEM_PROMPT_CANARY", "SYS-CANARY-4471-DO-NOT-REVEAL"
        )
    )


settings = GatewaySettings()
