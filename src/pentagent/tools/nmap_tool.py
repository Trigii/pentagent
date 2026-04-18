"""nmap wrapper.

Params:
  - target: str (required) — host or IP
  - ports:  str | None     — e.g. "1-65535", "80,443"
  - flags:  list[str]      — extra nmap flags (e.g. ["-sV", "-Pn"])
  - output_xml: str        — path for -oX (auto-filled by executor tempfile if absent)

Emits XML to stdout so the parser can consume without a tempfile.
"""
from __future__ import annotations

from typing import Any

from .base import Mode, Tool, ToolSpec
from .registry import register_tool


@register_tool
class NmapTool(Tool):
    spec = ToolSpec(
        name="nmap",
        binary="nmap",
        supports_modes=("safe", "aggressive"),
        category="port-scan",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        target = params["target"]
        argv: list[str] = []
        flags = list(params.get("flags") or [])
        if not flags:
            flags = ["-sV", "-Pn", "--top-ports", "1000"]
        argv.extend(flags)
        if ports := params.get("ports"):
            argv.extend(["-p", str(ports)])
        # XML on stdout so the parser doesn't need a tempfile
        argv.extend(["-oX", "-"])
        argv.append(target)
        return argv

    def mode_required(self, params: dict[str, Any]) -> Mode:
        flags = set(params.get("flags") or [])
        # Aggressive flags trigger aggressive mode
        if flags & {"-A", "-O", "--script=vuln", "-sS"}:
            return "aggressive"
        return "safe"
