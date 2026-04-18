"""httpx (projectdiscovery) wrapper — HTTP liveness, title, tech, status.

Params:
  - targets: list[str] | str  — URLs *or* bare hosts. Bare hosts are
    auto-expanded to both http:// and https:// URLs because a naked
    `-u host` can silently fail on HTB/lab targets (httpx picks a scheme
    heuristically and if the first fails, the second often isn't tried).
    Callers that already pass full URLs (e.g. from WebApp rows) pass
    through untouched.
  - flags:   list[str]        — extra flags appended verbatim
  - ports:   str              — comma-separated ports. If unset, httpx
    uses the scheme default (80 for http://, 443 for https://).
  - include_common_ports: bool — adds a common web-port set so e.g.
    8080/8443/3000 are also probed. Off by default to keep scans fast.
  - timeout: int              — per-request timeout (default 7s)
"""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolSpec
from .registry import register_tool


_COMMON_WEB_PORTS = "80,443,8000,8080,8443,3000,5000,9000"


def _has_scheme(t: str) -> bool:
    return "://" in t


def _expand_bare(t: str) -> list[str]:
    """Bare hostname `example.com` becomes both http:// and https:// URLs;
    full URLs pass through. Strips trailing slashes for cleaner argv."""
    t = t.strip().rstrip("/")
    if not t:
        return []
    if _has_scheme(t):
        return [t]
    return [f"http://{t}", f"https://{t}"]


@register_tool
class HttpxTool(Tool):
    spec = ToolSpec(
        name="httpx",
        binary="httpx",
        supports_modes=("safe", "aggressive"),
        category="web-liveness",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        targets = params.get("targets") or params.get("target")
        if isinstance(targets, str):
            targets = [targets]
        if not targets:
            raise ValueError("httpx requires `targets` or `target`")

        # Expand bare hostnames into both schemes; dedupe.
        expanded: list[str] = []
        seen: set[str] = set()
        for t in targets:
            for u in _expand_bare(str(t)):
                if u not in seen:
                    seen.add(u)
                    expanded.append(u)

        argv: list[str] = [
            "-silent",
            "-sc",
            "-title",
            "-tech-detect",
            "-location",               # emit redirect target
            "-follow-redirects",
            "-timeout", str(int(params.get("timeout", 7))),
            "-json",
            "-no-color",
        ]
        argv.extend(params.get("flags") or [])

        if ports := params.get("ports"):
            argv.extend(["-ports", str(ports)])
        elif params.get("include_common_ports"):
            argv.extend(["-ports", _COMMON_WEB_PORTS])

        for t in expanded:
            argv.extend(["-u", t])
        return argv

    def targets(self, params: dict[str, Any]) -> list[str]:
        """Return the *original* targets so ScopeGuard checks the hostnames
        we were asked about, not each expanded scheme variant (which would
        duplicate scope checks). ScopeGuard accepts URLs or hosts either
        way."""
        targets = params.get("targets") or params.get("target")
        if isinstance(targets, str):
            return [targets]
        return list(targets or [])
