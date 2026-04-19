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

# Severity is a (str, Enum) so .value is a string — we need an explicit
# rank for ordered comparisons in the escalator.
_SEV_RANK: dict[Severity, int] = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


def _bump(current: Severity, floor: Severity) -> Severity:
    """Return max(current, floor) by severity rank. Never downgrades."""
    return current if _SEV_RANK[current] >= _SEV_RANK[floor] else floor

# Template-id substrings that indicate a high-value exposure. Nuclei files
# these as "info" by default, but for pentest triage they're chase-worthy —
# an admin/login panel is a credentialed-attack surface, and exposed service
# consoles (flowise, grafana, kibana, jenkins, rabbitmq, etc.) are routinely
# the shortest path to compromise. We bump info→medium for these so they
# don't get lost in the info noise in the final report.
_HIGH_VALUE_TEMPLATE_PATTERNS: tuple[str, ...] = (
    # Management/admin consoles
    "admin-panel",
    "exposed-panel",
    "login-panel",
    "flowise-panel",
    "grafana-detect",
    "kibana-detect",
    "jenkins-",
    "rabbitmq-",
    "kubernetes-dashboard",
    "portainer",
    "phpmyadmin",
    "wp-login",
    # Exposed VCS / backups / env
    "exposed-git",
    ".git-config",
    ".env-file",
    "exposed-backup",
    "exposed-sql",
    # Default creds / weak auth templates ship as info but are high-value
    "default-login",
    "default-credential",
)

# Substrings that should escalate to HIGH regardless of nuclei's label.
# These represent direct-impact exposures where severity=info is just wrong.
_CRITICAL_TEMPLATE_PATTERNS: tuple[str, ...] = (
    "exposed-git-config",
    ".git-config-exposed",
    "env-file-exposed",
    "aws-credentials",
    "private-key-exposed",
)


def _escalate_severity(template_id: str | None, tags: list[str] | None, sev: Severity) -> Severity:
    """Bump severity for high-value fingerprint templates that nuclei files
    as info. We only escalate upward, and only when the current severity is
    below the target — a template that nuclei already rates high/critical is
    left alone."""
    if not template_id:
        return sev
    tid = template_id.lower()
    tag_set = {t.lower() for t in (tags or []) if isinstance(t, str)}

    # Critical-path exposures (secrets, configs leaking creds)
    if any(p in tid for p in _CRITICAL_TEMPLATE_PATTERNS):
        return _bump(sev, Severity.high)

    # High-value recon hits: admin consoles, login portals, exposed services
    if any(p in tid for p in _HIGH_VALUE_TEMPLATE_PATTERNS):
        return _bump(sev, Severity.medium)

    # Tag-based fallback: nuclei templates often tag `panel`+`exposure` or
    # `login`+`default-login`. Catch what the substring list misses.
    if "exposure" in tag_set and ("panel" in tag_set or "config" in tag_set):
        return _bump(sev, Severity.medium)
    if "default-login" in tag_set:
        return _bump(sev, Severity.medium)

    return sev


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
        raw_severity = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), Severity.info)
        template_id = rec.get("template-id") or rec.get("templateID")
        tags = info.get("tags")
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        severity = _escalate_severity(template_id, tags if isinstance(tags, list) else None, raw_severity)
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
