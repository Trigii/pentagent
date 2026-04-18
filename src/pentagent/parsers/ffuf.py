"""ffuf JSON output parser → Endpoint observations.

Context:
  - `webapp_id` (int) — the webapp these endpoints belong to (passed by the
    orchestrator when dispatching ffuf against a known webapp). If absent,
    we still emit the observation but the orchestrator must fill in the
    webapp_id before commit.
"""
from __future__ import annotations

import json

from ..memory import Endpoint, Observation
from ..tools.base import ToolResult


def parse(result: ToolResult, context: dict) -> Observation:
    obs = Observation(source_tool="ffuf", raw_excerpt=result.stdout[:2000])
    try:
        doc = json.loads(result.stdout)
    except json.JSONDecodeError:
        return obs

    webapp_id = context.get("webapp_id")
    if webapp_id is None:
        return obs

    for item in doc.get("results") or []:
        url = item.get("url") or ""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path or "/"
        obs.endpoints.append(
            Endpoint(
                webapp_id=webapp_id,
                method=item.get("method", "GET"),
                path=path,
                status=item.get("status"),
                length=item.get("length"),
                content_type=item.get("content-type"),
            )
        )
    return obs
