"""Local / self-hosted OpenAI-compatible client (Ollama, vLLM, LM Studio)."""
from __future__ import annotations

from ..config import LLMProviderConfig
from .base import LLMError, LLMMessage, LLMResponse


class LocalOpenAICompatClient:
    provider = "local"

    def __init__(self, cfg: LLMProviderConfig) -> None:
        try:
            from openai import OpenAI
        except ImportError as e:  # pragma: no cover
            raise LLMError("openai package required for OpenAI-compatible local servers") from e
        if not cfg.base_url:
            raise LLMError("local LLM provider requires base_url (e.g. http://127.0.0.1:11434/v1)")
        # Most local servers don't care about the API key but the SDK requires one.
        import os
        api_key = os.environ.get(cfg.api_key_env or "", "local")
        self._client = OpenAI(api_key=api_key, base_url=cfg.base_url)
        self.model = cfg.model
        self._max_tokens = cfg.max_tokens

    def chat(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        expect_json: bool = False,
    ) -> LLMResponse:
        payload_messages = [{"role": m.role, "content": m.content} for m in messages]
        kwargs: dict = {
            "model": self.model,
            "messages": payload_messages,
            "temperature": temperature,
            "max_tokens": max_tokens or self._max_tokens,
        }
        if expect_json:
            # Not every local server implements response_format; try it and
            # fall back if it barfs.
            try:
                resp = self._client.chat.completions.create(
                    **kwargs, response_format={"type": "json_object"}
                )
            except Exception:
                # Nudge via prompt instead
                payload_messages.append(
                    {"role": "user", "content": "Respond with valid JSON only, no prose."}
                )
                resp = self._client.chat.completions.create(**kwargs)
        else:
            resp = self._client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        text = choice.message.content or ""
        usage = getattr(resp, "usage", None)
        return LLMResponse(
            text=text,
            model=self.model,
            provider=self.provider,
            input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
            raw=resp,
        )
