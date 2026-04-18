"""amass wrapper — active/passive subdomain enumeration.

Params:
  - domain: str
  - mode:   "passive" | "active" (default passive)
  - flags:  list[str]
"""
from __future__ import annotations

from typing import Any

from .base import Mode, Tool, ToolSpec
from .registry import register_tool


@register_tool
class AmassTool(Tool):
    spec = ToolSpec(
        name="amass",
        binary="amass",
        supports_modes=("safe", "aggressive"),
        category="recon-passive",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        domain = params["domain"]
        mode = params.get("mode", "passive")
        argv = ["enum", "-silent", "-d", domain]
        if mode == "passive":
            argv.append("-passive")
        argv.extend(params.get("flags") or [])
        return argv

    def targets(self, params: dict[str, Any]) -> list[str]:
        return [params["domain"]]

    def mode_required(self, params: dict[str, Any]) -> Mode:
        return "aggressive" if params.get("mode") == "active" else "safe"
