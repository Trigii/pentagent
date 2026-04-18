"""subfinder wrapper — passive subdomain enumeration.

Params:
  - domain: str (required)
  - flags:  list[str]
"""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolSpec
from .registry import register_tool


@register_tool
class SubfinderTool(Tool):
    spec = ToolSpec(
        name="subfinder",
        binary="subfinder",
        supports_modes=("safe", "aggressive"),
        category="recon-passive",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        domain = params["domain"]
        argv = ["-silent", "-d", domain]
        argv.extend(params.get("flags") or [])
        return argv

    def targets(self, params: dict[str, Any]) -> list[str]:
        return [params["domain"]]
