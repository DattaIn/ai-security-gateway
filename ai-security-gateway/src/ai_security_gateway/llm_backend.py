"""Pluggable LLM backend interface.

The gateway's security logic must not care which model it's protecting.
Swap `MockLlmBackend` for a real provider adapter (Anthropic, OpenAI,
a local vLLM server, etc.) without touching anything else.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class LlmBackend(ABC):
    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        ...


class MockLlmBackend(LlmBackend):
    """Deterministic stand-in used for local dev, CI, and the attack
    test suite -- so the security pipeline can be fully exercised
    without calling a real, billed LLM API."""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return f"[mock-llm-response] Acknowledged: {user_prompt[:200]}"
