"""Anthropic Claude client."""
from __future__ import annotations

from tenacity import retry, stop_after_attempt, wait_exponential

from ..config import LLMProviderConfig
from .base import LLMError, LLMMessage, LLMResponse, _api_key


class AnthropicClient:
    provider = "anthropic"

    def __init__(self, cfg: LLMProviderConfig) -> None:
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise LLMError("anthropic package not installed; pip install anthropic") from e
        api_key = _api_key(cfg.api_key_env)
        if not api_key:
            raise LLMError(
                f"Anthropic API key not found in env var {cfg.api_key_env!r}. "
                "Set it or switch routing.* to another provider."
            )
        self._client = anthropic.Anthropic(api_key=api_key)
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
        system_chunks: list[str] = []
        convo: list[dict] = []
        for m in messages:
            if m.role == "system":
                system_chunks.append(m.content)
            else:
                convo.append({"role": m.role, "content": m.content})
        if expect_json:
            system_chunks.append(
                "Respond with a single valid JSON value only, with no prose and no code fences."
            )
        resp = self._client.messages.create(
            model=self.model,
            system="\n\n".join(system_chunks) if system_chunks else None,
            messages=convo,
            temperature=temperature,
            max_tokens=max_tokens or self._max_tokens,
        )
        text = "".join(
            getattr(block, "text", "") for block in resp.content if getattr(block, "type", "") == "text"
        )
        return LLMResponse(
            text=text,
            model=self.model,
            provider=self.provider,
            input_tokens=getattr(resp.usage, "input_tokens", 0) or 0,
            output_tokens=getattr(resp.usage, "output_tokens", 0) or 0,
            raw=resp,
        )
