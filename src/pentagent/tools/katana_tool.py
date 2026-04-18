"""katana wrapper — crawling for endpoint discovery."""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolSpec
from .registry import register_tool


@register_tool
class KatanaTool(Tool):
    spec = ToolSpec(
        name="katana",
        binary="katana",
        supports_modes=("safe", "aggressive"),
        category="crawler",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        url = params["url"]
        depth = int(params.get("depth", 2))
        argv = [
            "-u", url,
            "-silent",
            "-jsonl",
            "-d", str(depth),
            "-no-color",
        ]
        if js := params.get("js_crawl"):
            if js:
                argv.append("-jc")
        argv.extend(params.get("flags") or [])
        return argv

    def targets(self, params: dict[str, Any]) -> list[str]:
        return [params["url"]]
