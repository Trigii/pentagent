"""Configuration loading and validation.

The config is the user-editable YAML; `Settings` is the validated Pydantic
view that the rest of the code consumes. No other module should read YAML
directly — always go through `Settings.load()`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class LLMProviderConfig(BaseModel):
    model: str
    api_key_env: str | None = None
    base_url: str | None = None
    max_tokens: int = 4096


class LLMConfig(BaseModel):
    default: str = "anthropic"
    providers: dict[str, LLMProviderConfig]
    routing: dict[str, str] = Field(default_factory=dict)

    def provider_for(self, role: str) -> LLMProviderConfig:
        name = self.routing.get(role, self.default)
        if name not in self.providers:
            raise KeyError(f"LLM provider {name!r} is not configured")
        return self.providers[name]

    def provider_name_for(self, role: str) -> str:
        return self.routing.get(role, self.default)


class ToolConfig(BaseModel):
    enabled: bool = True
    default_flags: list[str] = Field(default_factory=list)
    timeout_seconds: int = 300
    extras: dict[str, Any] = Field(default_factory=dict)

    # Allow unknown tool-specific keys to survive validation
    model_config = {"extra": "allow"}


class SessionConfig(BaseModel):
    max_iterations: int = 50
    wallclock_minutes: int = 60
    max_cost_usd: float = 5.0
    mode: Literal["safe", "aggressive"] = "safe"


class SafetyConfig(BaseModel):
    per_host_rate_limit_rps: int = 20
    global_rate_limit_rps: int = 100
    deny_private_ranges_unless_explicit: bool = True
    require_authorization_flag: bool = True


class OutputConfig(BaseModel):
    dir: str = "./runs"
    report_format: list[str] = Field(default_factory=lambda: ["markdown", "json"])


class Settings(BaseModel):
    session: SessionConfig = SessionConfig()
    llm: LLMConfig
    tools: dict[str, ToolConfig] = Field(default_factory=dict)
    safety: SafetyConfig = SafetyConfig()
    output: OutputConfig = OutputConfig()

    @field_validator("tools", mode="before")
    @classmethod
    def _coerce_tools(cls, v: Any) -> Any:
        # Each tool section in YAML is a plain dict; push unknown keys into
        # `extras` so custom tool options survive round-tripping.
        if not isinstance(v, dict):
            return v
        coerced: dict[str, dict[str, Any]] = {}
        known = set(ToolConfig.model_fields.keys())
        for name, section in v.items():
            if not isinstance(section, dict):
                coerced[name] = section
                continue
            out: dict[str, Any] = {}
            extras: dict[str, Any] = {}
            for k, val in section.items():
                (out if k in known else extras)[k] = val
            if extras:
                out["extras"] = {**out.get("extras", {}), **extras}
            coerced[name] = out
        return coerced

    @classmethod
    def load(cls, path: str | Path) -> "Settings":
        raw = yaml.safe_load(Path(path).read_text())
        return cls.model_validate(raw)

    def tool(self, name: str) -> ToolConfig:
        """Return the tool config or a default-disabled one."""
        return self.tools.get(name, ToolConfig(enabled=False))
