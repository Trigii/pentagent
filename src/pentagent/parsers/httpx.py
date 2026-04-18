"""httpx JSONL parser → Host + WebApp + root Endpoint observations.

Each line of httpx output is a JSON object with keys like:
    url, host, port, scheme, status_code, content_length, title, tech, ...
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from ..memory import Endpoint, Host, Observation, WebApp
from ..tools.base import ToolResult


def parse(result: ToolResult, context: dict) -> Observation:
    obs = Observation(source_tool="httpx", raw_excerpt=result.stdout[:2000])
    host_idx_by_key: dict[tuple, int] = {}

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = rec.get("url") or ""
        if not url:
            continue
        parsed = urlparse(url)
        scheme = parsed.scheme or rec.get("scheme") or "http"
        hostname = rec.get("host") or parsed.hostname
        ip = rec.get("a", [None])[0] if isinstance(rec.get("a"), list) else None

        # Host (dedupe within this observation)
        key = (ip, hostname)
        if key not in host_idx_by_key:
            obs.hosts.append(Host(ip=ip, hostname=hostname))
            host_idx_by_key[key] = len(obs.hosts) - 1
        host_placeholder = -(host_idx_by_key[key] + 1)

        # WebApp
        base_url = f"{scheme}://{hostname}"
        if parsed.port and parsed.port not in (80, 443):
            base_url = f"{scheme}://{hostname}:{parsed.port}"
        webapp = WebApp(
            host_id=host_placeholder,
            scheme=scheme if scheme in ("http", "https") else "http",
            base_url=base_url,
            title=rec.get("title"),
            tech=list(rec.get("tech") or []),
            status_code=rec.get("status_code") or rec.get("status-code"),
        )
        obs.webapps.append(webapp)
        webapp_placeholder = -(len(obs.webapps))

        # A root endpoint at "/"
        obs.endpoints.append(
            Endpoint(
                webapp_id=webapp_placeholder,
                method="GET",
                path=parsed.path or "/",
                status=rec.get("status_code") or rec.get("status-code"),
                length=rec.get("content_length") or rec.get("content-length"),
                content_type=rec.get("content_type") or rec.get("content-type"),
            )
        )

    return obs
