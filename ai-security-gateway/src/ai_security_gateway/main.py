"""AI Security Gateway -- FastAPI application.

Pipeline:
  Client -> Rate Limit -> Input DLP -> Prompt-Injection Detection
         -> Policy Decision -> (BLOCK|FLAG|ALLOW) -> LLM Backend
         -> Output DLP -> Output Leak Detection -> Policy Decision
         -> Response -> Audit Log

The "LLM backend" here is a pluggable interface (`llm_backend.py`) so
this can be pointed at any provider without changing security logic.
"""
from __future__ import annotations

import uuid

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from ai_security_gateway.audit.logger import AuditLogger
from ai_security_gateway.config import settings
from ai_security_gateway.detectors.dlp import scan_and_redact
from ai_security_gateway.detectors.prompt_injection import detect_prompt_injection
from ai_security_gateway.llm_backend import LlmBackend, MockLlmBackend
from ai_security_gateway.middleware.rate_limiter import SlidingWindowRateLimiter
from ai_security_gateway.policy.engine import Decision, evaluate_input, evaluate_output

app = FastAPI(
    title="AI Security Gateway",
    description="Defense-in-depth reverse proxy for LLM applications.",
    version="0.1.0",
)

rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds,
)
audit_logger = AuditLogger(settings.audit_log_path)
llm_backend: LlmBackend = MockLlmBackend()


class ChatRequest(BaseModel):
    client_id: str = Field(..., description="Identifier of the calling application/user for rate limiting & audit.")
    prompt: str = Field(..., min_length=1, max_length=32_000)


class ChatResponse(BaseModel):
    request_id: str
    decision: str
    response: str | None = None
    policy: dict


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": app.version}


@app.get("/audit/verify")
def verify_audit_chain():
    return {"chain_intact": audit_logger.verify_chain()}


@app.post("/v1/chat", response_model=ChatResponse)
def chat(req: ChatRequest, request: Request):
    request_id = str(uuid.uuid4())

    # 1. Rate limiting
    rl_decision = rate_limiter.allow(req.client_id)
    if not rl_decision.allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Retry after {rl_decision.retry_after_seconds:.1f}s.",
        )

    # 2. Input DLP scan + redaction
    input_dlp = scan_and_redact(req.prompt)
    safe_prompt = input_dlp.redacted_text if settings.dlp_redact_on_input else req.prompt

    # 3. Prompt-injection detection
    input_injection = detect_prompt_injection(safe_prompt, settings.system_prompt_canary)

    # 4. Input policy decision
    input_policy = evaluate_input(input_injection, input_dlp, settings)
    audit_logger.log(
        request_id=request_id,
        client_id=req.client_id,
        stage="input",
        decision=input_policy.decision.value,
        reasons=input_policy.reasons,
        injection_score=input_policy.injection_score,
        dlp_summary=input_policy.dlp_summary,
    )

    if input_policy.decision == Decision.BLOCK:
        return ChatResponse(
            request_id=request_id,
            decision=Decision.BLOCK.value,
            response=None,
            policy=input_policy.as_dict(),
        )

    # 5. Call the LLM backend with the (possibly redacted) safe prompt,
    #    injecting the canary into the system prompt so we can detect
    #    if the model is later tricked into repeating it.
    system_prompt = f"You are a helpful assistant. [{settings.system_prompt_canary}]"
    raw_completion = llm_backend.complete(system_prompt=system_prompt, user_prompt=safe_prompt)

    # 6. Output DLP scan + redaction
    output_dlp = scan_and_redact(raw_completion)
    safe_completion = output_dlp.redacted_text if settings.dlp_redact_on_output else raw_completion

    # 7. Output leak / injection-echo detection
    output_injection = detect_prompt_injection(raw_completion, settings.system_prompt_canary)

    # 8. Output policy decision
    output_policy = evaluate_output(output_injection, output_dlp, settings)
    audit_logger.log(
        request_id=request_id,
        client_id=req.client_id,
        stage="output",
        decision=output_policy.decision.value,
        reasons=output_policy.reasons,
        injection_score=output_policy.injection_score,
        dlp_summary=output_policy.dlp_summary,
    )

    if output_policy.decision == Decision.BLOCK:
        return ChatResponse(
            request_id=request_id,
            decision=Decision.BLOCK.value,
            response=None,
            policy=output_policy.as_dict(),
        )

    final_decision = Decision.FLAG if input_policy.decision == Decision.FLAG else Decision.ALLOW
    return ChatResponse(
        request_id=request_id,
        decision=final_decision.value,
        response=safe_completion,
        policy=output_policy.as_dict(),
    )
