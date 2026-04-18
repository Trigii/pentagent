"""Unified LLM client interface + factory.

The rest of the code only talks to `LLMClient`. To add a new backend, implement
the `chat()` method and register it in `build_client()`.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from ..config import LLMConfig, LLMProviderConfig


class LLMError(RuntimeError):
    pass


@dataclass
class LLMMessage:
    role: str     # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    text: str
    model: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0
    raw: Any = None

    def json(self) -> Any:
        """Best-effort JSON extraction. Raises LLMError if not parseable."""
        text = self.text.strip()
        # Strip markdown code fences if the model wrapped the JSON
        fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
        if fence:
            text = fence.group(1).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            # Try to extract the first JSON object/array in the response
            m = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(1))
                except json.JSONDecodeError:
                    pass
            raise LLMError(f"model output was not valid JSON: {e}\n---\n{text}") from e


@runtime_checkable
class LLMClient(Protocol):
    provider: str
    model: str

    def chat(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        expect_json: bool = False,
    ) -> LLMResponse:
        ...


def _api_key(env_name: str | None) -> str | None:
    if not env_name:
        return None
    return os.environ.get(env_name)


def build_client(role: str, cfg: LLMConfig) -> LLMClient:
    """Factory: returns a client for the given role, using routing rules."""
    provider_name = cfg.provider_name_for(role)
    provider_cfg = cfg.provider_for(role)
    if provider_name == "anthropic":
        from .anthropic_client import AnthropicClient
        return AnthropicClient(provider_cfg)
    if provider_name == "openai":
        from .openai_client import OpenAIClient
        return OpenAIClient(provider_cfg)
    if provider_name == "local":
        from .local_client import LocalOpenAICompatClient
        return LocalOpenAICompatClient(provider_cfg)
    raise LLMError(f"unknown LLM provider: {provider_name!r}")


# ------------------------- Offline stub -----------------------------------

class DummyLLMClient:
    """Deterministic stub used in tests and dry-run mode.

    It returns a JSON envelope that the planner knows how to accept so that
    the orchestrator can loop without real API calls.
    """

    provider = "dummy"
    model = "dummy-1"

    def chat(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        expect_json: bool = False,
    ) -> LLMResponse:
        if expect_json:
            text = json.dumps({"actions": [], "done": False, "reason": "dummy"})
        else:
            text = "dummy response"
        return LLMResponse(text=text, model=self.model, provider=self.provider)
