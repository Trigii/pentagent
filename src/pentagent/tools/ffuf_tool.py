"""ffuf wrapper — content/parameter fuzzing.

Params:
  - url:       str (must include FUZZ placeholder, e.g. "https://x/FUZZ")
  - wordlist:  str
  - mode:      "content" | "params" | "vhost" (affects default filters)
  - rate:      int requests/sec (default 20)
  - flags:     list[str]
"""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolSpec
from .registry import register_tool


@register_tool
class FfufTool(Tool):
    spec = ToolSpec(
        name="ffuf",
        binary="ffuf",
        supports_modes=("safe", "aggressive"),
        category="content-discovery",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        url = params["url"]
        wordlist = params["wordlist"]
        if "FUZZ" not in url:
            raise ValueError("ffuf url must include the FUZZ placeholder")
        rate = int(params.get("rate", 20))
        mode = params.get("mode", "content")
        argv = [
            "-u", url,
            "-w", wordlist,
            "-rate", str(rate),
            "-of", "json",
            "-o", "-",                  # JSON to stdout
            "-noninteractive",
            "-s",                       # silent / only matches
        ]
        # Sensible default filter: drop 404s, drop response size 0
        argv.extend(["-mc", "200,204,301,302,307,401,403,405"])
        if mode == "params":
            argv.extend(["-fs", "0"])
        argv.extend(params.get("flags") or [])
        return argv

    def targets(self, params: dict[str, Any]) -> list[str]:
        return [params["url"].replace("FUZZ", "")]
