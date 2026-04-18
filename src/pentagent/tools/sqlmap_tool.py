"""sqlmap wrapper — always aggressive, always gated on per-target opt-in."""
from __future__ import annotations

from typing import Any

from .base import Mode, Tool, ToolSpec
from .registry import register_tool


@register_tool
class SqlmapTool(Tool):
    spec = ToolSpec(
        name="sqlmap",
        binary="sqlmap",
        supports_modes=("aggressive",),
        category="exploitation",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        url = params["url"]
        argv = [
            "-u", url,
            "--batch",
            "--random-agent",
            "--level", str(params.get("level", 1)),
            "--risk", str(params.get("risk", 1)),
            "--smart",
            "--output-dir", params.get("output_dir", "/tmp/sqlmap-out"),
        ]
        if data := params.get("data"):
            argv.extend(["--data", data])
        if cookie := params.get("cookie"):
            argv.extend(["--cookie", cookie])
        if tamper := params.get("tamper"):
            argv.extend(["--tamper", tamper])
        argv.extend(params.get("flags") or [])
        return argv

    def targets(self, params: dict[str, Any]) -> list[str]:
        return [params["url"]]

    def mode_required(self, params: dict[str, Any]) -> Mode:
        return "aggressive"
