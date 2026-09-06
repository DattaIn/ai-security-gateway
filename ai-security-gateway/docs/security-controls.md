# Security Controls Reference

A control-by-control index, for anyone auditing what this gateway
actually enforces and where it's implemented.

| Control | Implementation | Configurable via |
|---|---|---|
| Rate limiting (sliding window, per-client) | `middleware/rate_limiter.py` | `GATEWAY_RATE_LIMIT_REQUESTS`, `GATEWAY_RATE_LIMIT_WINDOW` |
| Input length bound | `main.py` (`ChatRequest.prompt` max_length) | Pydantic field constraint |
| Input DLP scan + redaction | `detectors/dlp.py` | `GATEWAY_DLP_REDACT_INPUT`, `GATEWAY_DLP_BLOCK_CRITICAL` |
| Output DLP scan + redaction | `detectors/dlp.py` (same rule set, run again on completions) | `GATEWAY_DLP_REDACT_OUTPUT` |
| Prompt-injection scoring | `detectors/prompt_injection.py` | `GATEWAY_INJECTION_BLOCK`, `GATEWAY_INJECTION_FLAG` |
| System-prompt canary / leak detection | `main.py` + `detectors/prompt_injection.py` | `GATEWAY_SYSTEM_PROMPT_CANARY` |
| Policy decisioning (BLOCK/FLAG/ALLOW) with human-readable rationale | `policy/engine.py` | thresholds above |
| Tamper-evident audit logging | `audit/logger.py` | `GATEWAY_AUDIT_LOG_PATH` |
| Audit chain integrity verification | `audit/logger.py::verify_chain()`, exposed at `GET /audit/verify` | n/a |
| Pluggable LLM backend (no vendor lock-in in the security layer) | `llm_backend.py` | swap `MockLlmBackend` for a real adapter |

## DLP rule catalog

| Rule | Severity | Redaction label |
|---|---|---|
| AWS access key | Critical | `[REDACTED_AWS_KEY]` |
| Generic API key pattern | Critical | `[REDACTED_API_KEY]` |
| PEM private key block | Critical | `[REDACTED_PRIVATE_KEY]` |
| JWT | Critical | `[REDACTED_JWT]` |
| Credit-card-shaped number | Critical | `[REDACTED_CARD_NUMBER]` |
| SSN-shaped number | Critical | `[REDACTED_SSN]` |
| Email address | Medium | `[REDACTED_EMAIL]` |
| Phone number | Medium | `[REDACTED_PHONE]` |
| Internal hostname (`*.internal`/`*.corp`/`*.local`) | Low | `[REDACTED_INTERNAL_HOST]` |

Critical findings trigger a BLOCK by default (`GATEWAY_DLP_BLOCK_CRITICAL=true`);
medium/low findings are redacted but allowed through.

## Prompt-injection signal families

| Family | What it targets | Default weight |
|---|---|---|
| `instruction_override` | "ignore previous instructions", "new instructions:", etc. | 0.80 |
| `role_hijack` | "you are now...", "act as unrestricted...", "DAN", "jailbreak" | 0.75 |
| `system_prompt_extraction` | "repeat your system prompt", "what are your instructions" | 0.80 |
| `delimiter_escape` | Fake `</system>`, `[INST]`, fenced "system" blocks | 0.45 |
| `encoding_obfuscation` | Long base64 blobs, excessive `\uXXXX` escapes | 0.45 |
| `excessive_agency` | Requests to send money/email, execute code, delete data, grant access | 0.80 |
| `canary_leak` (output only) | The planted system-prompt canary token appears in the completion | 1.00 (forces BLOCK) |

Scores are summed (capped at 1.0), not averaged, so multiple weaker
signals can still cross the block threshold even if no single family
does — see `docs/design-decisions.md` for the rationale.

## CI/CD security gates

Defined in `.github/workflows/ci.yml`:

1. **Ruff** — static lint
2. **Bandit** — SAST for Python
3. **Gitleaks** — secret scanning across the diff/history
4. **pytest** — unit tests + the OWASP-mapped attack simulation suite
5. **pip-audit** — dependency/SCA vulnerability check

All five must pass before the `security-gate` job reports green.
