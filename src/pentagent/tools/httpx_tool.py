"""httpx (projectdiscovery) wrapper — HTTP liveness, title, tech, status.

Params:
  - targets: list[str] | str  — URLs *or* bare hosts. Bare hosts are
    auto-expanded to both http:// and https:// URLs because a naked
    `-u host` can silently fail on HTB/lab targets (httpx picks a scheme
    heuristically and if the first fails, the second often isn't tried).
    Callers that already pass full URLs (e.g. from WebApp rows) pass
    through untouched.
  - flags:   list[str]        — extra flags appended verbatim
  - ports:   str              — comma-separated ports. If unset we still
    probe a common web-port set (see `_COMMON_WEB_PORTS`) so non-standard
    ports (8000/8080/8443/3000/5000) don't silently get skipped. This
    was the most common failure mode on HTB/lab boxes — httpx would
    probe :80 + :443 and report 0 webapps while nuclei (which took the
    raw seed URL with port) still found 26 things.
  - include_common_ports: bool — legacy opt-in; ignored now that common
    ports are on by default. Keep accepting it for backward compatibility.
  - skip_common_ports: bool   — explicitly disable the common-port set
    (pass only scheme defaults). Use on massive targets where the broader
    port sweep would blow the time budget.
  - timeout: int              — per-request timeout (default 10s — a
    few seconds of headroom because WAF-fronted sites often stall the
    first byte)
  - retries: int              — retry count for transient failures
    (default 2). Set to 0 to disable.
  - user_agent: str           — override the default UA. Many WAFs 403
    the string "httpx" outright; we send a normal browser UA by default
    so liveness probes actually complete.
"""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolSpec
from .registry import register_tool


_COMMON_WEB_PORTS = "80,443,8000,8080,8443,3000,5000,9000"

# Default UA: a recent Firefox on Linux. Chosen because most Bugcrowd/HTB
# programs ask researchers to avoid headless-scanner signatures, and
# many WAFs (Cloudflare, Akamai) return 403 on the literal "httpx" UA.
# If you need the test UA for legal/attribution, pass user_agent=...
_DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0"
)


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
            "-cl",                     # content length
            "-ct",                     # content type
            "-location",               # emit redirect target
            "-follow-redirects",
            "-timeout", str(int(params.get("timeout", 10))),
            "-retries", str(int(params.get("retries", 2))),
            "-json",
            "-no-color",
        ]
        # Realistic UA (WAF-friendly). Override per-call if a program
        # mandates a researcher-id UA.
        ua = params.get("user_agent") or _DEFAULT_UA
        argv.extend(["-H", f"User-Agent: {ua}"])

        argv.extend(params.get("flags") or [])

        # Ports: explicit > skip > common (default). The previous default
        # of "scheme-only" was the silent-0 failure mode on non-standard
        # web ports (flowise on :3000, jenkins on :8080, etc.).
        if ports := params.get("ports"):
            argv.extend(["-ports", str(ports)])
        elif not params.get("skip_common_ports"):
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
