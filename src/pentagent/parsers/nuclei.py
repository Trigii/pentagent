"""nuclei JSONL parser → Finding + Evidence observations."""
from __future__ import annotations

import json

from ..memory import Evidence, Finding, Observation, Severity
from ..tools.base import ToolResult


_SEVERITY_MAP = {
    "info": Severity.info,
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
    "unknown": Severity.info,
}


def parse(result: ToolResult, context: dict) -> Observation:
    obs = Observation(source_tool="nuclei", raw_excerpt=result.stdout[:4000])

    entity_type = context.get("entity_type", "WebApp")
    entity_id = context.get("entity_id")

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = rec.get("info") or {}
        severity = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), Severity.info)
        template_id = rec.get("template-id") or rec.get("templateID")
        name = info.get("name") or template_id or "nuclei finding"
        description = info.get("description") or ""
        remediation = info.get("remediation") or ""

        ev = Evidence(
            request=rec.get("request"),
            response=rec.get("response"),
            payload=rec.get("matcher-name") or rec.get("matcher_name"),
            raw_excerpt=json.dumps(rec)[:4000],
        )
        obs.evidence.append(ev)
        # The store commits evidence before findings; we wire evidence_id via
        # the orchestrator after commit, since placeholders there would be
        # more complex than we want. For now leave evidence_id=None and have
        # the orchestrator stitch.
        if entity_id is None:
            continue
        obs.findings.append(
            Finding(
                kind=template_id or name,
                severity=severity,
                entity_type=entity_type,
                entity_id=entity_id,
                title=name,
                description=description,
                recommendation=remediation,
                source_tool="nuclei",
                template_id=template_id,
                confidence=0.9 if severity in (Severity.high, Severity.critical) else 0.7,
            )
        )
    return obs
