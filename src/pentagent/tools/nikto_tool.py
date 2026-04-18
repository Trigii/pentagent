"""nikto wrapper."""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolSpec
from .registry import register_tool


@register_tool
class NiktoTool(Tool):
    spec = ToolSpec(
        name="nikto",
        binary="nikto",
        supports_modes=("safe", "aggressive"),
        category="vuln-scan",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        host = params["target"]
        argv = ["-host", host, "-Format", "json", "-nointeractive", "-ask", "no"]
        if "port" in params:
            argv.extend(["-port", str(params["port"])])
        argv.extend(params.get("flags") or [])
        return argv

    def targets(self, params: dict[str, Any]) -> list[str]:
        return [params["target"]]
