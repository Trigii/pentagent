"""OpenAI (chat.completions) client."""
from __future__ import annotations

from tenacity import retry, stop_after_attempt, wait_exponential

from ..config import LLMProviderConfig
from .base import LLMError, LLMMessage, LLMResponse, _api_key


class OpenAIClient:
    provider = "openai"

    def __init__(self, cfg: LLMProviderConfig) -> None:
        try:
            from openai import OpenAI
        except ImportError as e:  # pragma: no cover
            raise LLMError("openai package not installed; pip install openai") from e
        api_key = _api_key(cfg.api_key_env)
        if not api_key:
            raise LLMError(f"OpenAI API key not in env var {cfg.api_key_env!r}")
        self._client = OpenAI(api_key=api_key, base_url=cfg.base_url)
        self.model = cfg.model
        self._max_tokens = cfg.max_tokens

    @retry(stop=stop_after_attempt(4), wait=wait_exponential(multiplier=1, min=1, max=30))
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
            kwargs["response_format"] = {"type": "json_object"}
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
