"""gobuster wrapper — directory/vhost/dns brute force."""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolSpec
from .registry import register_tool


@register_tool
class GobusterTool(Tool):
    spec = ToolSpec(
        name="gobuster",
        binary="gobuster",
        supports_modes=("safe", "aggressive"),
        category="content-discovery",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        submode = params.get("submode", "dir")
        wordlist = params["wordlist"]
        argv = [submode, "-w", wordlist, "-q", "-z"]
        if submode == "dir":
            argv.extend(["-u", params["url"]])
        elif submode == "dns":
            argv.extend(["-d", params["domain"]])
        elif submode == "vhost":
            argv.extend(["-u", params["url"]])
        argv.extend(params.get("flags") or [])
        return argv

    def targets(self, params: dict[str, Any]) -> list[str]:
        for key in ("url", "domain"):
            v = params.get(key)
            if v:
                return [v]
        return []
