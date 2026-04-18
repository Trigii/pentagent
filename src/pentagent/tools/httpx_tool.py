"""httpx (projectdiscovery) wrapper — HTTP liveness, title, tech, status.

Params:
  - targets: list[str] | str  — URLs or hosts
  - flags:   list[str]        — extra flags
  - ports:   str              — comma-separated ports (default 80,443)
"""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolSpec
from .registry import register_tool


@register_tool
class HttpxTool(Tool):
    spec = ToolSpec(
        name="httpx",
        binary="httpx",
        supports_modes=("safe", "aggressive"),
        category="web-liveness",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        argv: list[str] = []
        targets = params.get("targets") or params.get("target")
        if isinstance(targets, str):
            targets = [targets]
        if not targets:
            raise ValueError("httpx requires `targets` or `target`")
        argv.extend(["-silent", "-sc", "-title", "-tech-detect", "-json", "-no-color"])
        argv.extend(params.get("flags") or [])
        if ports := params.get("ports"):
            argv.extend(["-ports", str(ports)])
        # Pass targets on stdin-like fashion via -list; we inline them via -u
        for t in targets:
            argv.extend(["-u", t])
        return argv

    def targets(self, params: dict[str, Any]) -> list[str]:
        targets = params.get("targets") or params.get("target")
        if isinstance(targets, str):
            return [targets]
        return list(targets or [])
