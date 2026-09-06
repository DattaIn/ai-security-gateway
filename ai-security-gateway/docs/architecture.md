# Architecture

## Overview

The AI Security Gateway is a reverse proxy that sits between a client
application and an LLM backend. It never trusts the client's input or
the model's output — every request and response passes through the
same defense-in-depth pipeline.

## Request/response pipeline

```
Client
  |
  v
[1] Rate Limiter        --> 429 if client exceeds sliding-window quota
  |
  v
[2] Input DLP Scan       --> detect + redact secrets/PII in the prompt
  |
  v
[3] Prompt-Injection      --> score the (redacted) prompt across 6 signal
    Detection                 families (override, role-hijack, extraction,
  |                           delimiter escape, encoding obfuscation,
  |                           excessive agency)
  v
[4] Input Policy Decision --> BLOCK / FLAG / ALLOW, with human-readable reasons
  |
  v  (only if not BLOCK)
[5] LLM Backend Call       --> pluggable adapter; system prompt carries a
  |                            unique canary token
  v
[6] Output DLP Scan        --> detect + redact secrets/PII in the completion
  |
  v
[7] Output Leak Detection  --> did the completion echo the canary or show
  |                            injection-style content?
  v
[8] Output Policy Decision --> BLOCK / ALLOW
  |
  v
[9] Audit Log (both stages) --> tamper-evident, hash-chained JSONL
  |
  v
Response to client
```

## Component responsibilities

| Component | File | Responsibility |
|---|---|---|
| Rate Limiter | `middleware/rate_limiter.py` | Per-client sliding-window throttling |
| DLP Scanner | `detectors/dlp.py` | Pattern-based detection + redaction of secrets/PII |
| Injection Detector | `detectors/prompt_injection.py` | Multi-signal scoring of injection intent |
| Policy Engine | `policy/engine.py` | Converts detector output into an explainable decision |
| Audit Logger | `audit/logger.py` | Hash-chained, append-only structured logging |
| LLM Backend | `llm_backend.py` | Pluggable adapter to the actual model provider |
| API Layer | `main.py` | FastAPI routes wiring the pipeline together |

## Why the pipeline is split this way

- **Detectors are stateless and pure** (text in, score/findings out). They
  have no opinion on what to *do* about a finding — that keeps them easy
  to unit-test and easy to swap for an ML-based classifier later without
  touching policy logic.
- **The policy engine is the only place decisions are made.** Thresholds
  live in `config.py`, not scattered across detectors, so a security
  reviewer can audit "what do we block on" in one place.
- **The LLM backend is an abstract interface.** The gateway's security
  guarantees don't depend on which model is behind it.
- **Both directions get the same scrutiny.** Most real-world incidents
  involve *indirect* injection (a malicious document or tool result
  that manipulates the model), which shows up in the model's output or
  behavior, not the user's original prompt — hence output-side DLP and
  leak detection, not just input filtering.

## Deployment topology

```
                    +-------------------+
   Client App  ---->|   AI Security      |----> LLM Provider
                    |   Gateway (this)    |      (OpenAI / Anthropic /
                    |                     |       self-hosted vLLM)
                    +----------+----------+
                               |
                               v
                     Audit Log (JSONL,
                     hash-chained) -> SIEM
```

In production, the gateway would run as a sidecar or standalone service
in front of any LLM-calling application, with its audit log shipped to
a central SIEM (see the companion `mini-soc-detection-response-lab`
project for how those events could feed detection rules).
