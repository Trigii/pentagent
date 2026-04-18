"""Parsers for tools with simpler output formats."""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ..memory import Endpoint, Evidence, Finding, Host, Observation, Severity
from ..tools.base import ToolResult


def parse_subdomain_list(result: ToolResult, context: dict) -> Observation:
    """subfinder / amass: one subdomain per line on stdout."""
    obs = Observation(raw_excerpt=result.stdout[:2000])
    for line in result.stdout.splitlines():
        name = line.strip().lower()
        if not name or " " in name or "." not in name:
            continue
        obs.hosts.append(Host(hostname=name))
    return obs


def parse_gobuster(result: ToolResult, context: dict) -> Observation:
    """Lines look like: `/admin (Status: 301) [Size: 238]`."""
    obs = Observation(raw_excerpt=result.stdout[:2000])
    webapp_id = context.get("webapp_id")
    if webapp_id is None:
        return obs
    pat = re.compile(r"^(?P<path>\S+)\s+\(Status:\s+(?P<status>\d+)\)\s+\[Size:\s+(?P<size>\d+)\]")
    for line in result.stdout.splitlines():
        m = pat.match(line.strip())
        if not m:
            continue
        obs.endpoints.append(
            Endpoint(
                webapp_id=webapp_id,
                method="GET",
                path=m.group("path"),
                status=int(m.group("status")),
                length=int(m.group("size")),
            )
        )
    return obs


def parse_katana(result: ToolResult, context: dict) -> Observation:
    obs = Observation(raw_excerpt=result.stdout[:2000])
    webapp_id = context.get("webapp_id")
    if webapp_id is None:
        return obs
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            # katana may emit plain URLs too
            if line.startswith("http"):
                parsed = urlparse(line)
                obs.endpoints.append(Endpoint(webapp_id=webapp_id, method="GET", path=parsed.path or "/"))
            continue
        request = rec.get("request") or {}
        url = request.get("endpoint") or rec.get("endpoint") or ""
        method = (request.get("method") or "GET").upper()
        if not url:
            continue
        parsed = urlparse(url)
        obs.endpoints.append(
            Endpoint(webapp_id=webapp_id, method=method, path=parsed.path or "/")
        )
    return obs


def parse_nikto(result: ToolResult, context: dict) -> Observation:
    obs = Observation(raw_excerpt=result.stdout[:4000])
    entity_id = context.get("entity_id")
    entity_type = context.get("entity_type", "WebApp")
    if entity_id is None:
        return obs
    try:
        doc = json.loads(result.stdout)
    except json.JSONDecodeError:
        # Nikto sometimes emits multiple JSON docs; try line-wise
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            _ingest_nikto_doc(doc, obs, entity_type, entity_id)
        return obs
    _ingest_nikto_doc(doc, obs, entity_type, entity_id)
    return obs


def _ingest_nikto_doc(doc: dict, obs: Observation, entity_type: str, entity_id: int) -> None:
    for vuln in doc.get("vulnerabilities", []):
        obs.findings.append(
            Finding(
                kind="nikto:" + str(vuln.get("id", "unknown")),
                severity=Severity.low,
                entity_type=entity_type,
                entity_id=entity_id,
                title=vuln.get("msg") or "nikto finding",
                description=str(vuln),
                source_tool="nikto",
                template_id=str(vuln.get("id")),
                confidence=0.5,
            )
        )


def parse_sqlmap(result: ToolResult, context: dict) -> Observation:
    """Crude stdout scrape for sqlmap.

    We look for lines like:
        [INFO] Parameter 'id' is vulnerable. ...
    and emit a high-confidence SQLi Finding. Evidence is the stdout excerpt.
    """
    obs = Observation(raw_excerpt=result.stdout[:4000])
    entity_id = context.get("entity_id")
    entity_type = context.get("entity_type", "Endpoint")
    if entity_id is None:
        return obs
    param_hits: list[str] = []
    for line in result.stdout.splitlines():
        m = re.search(r"Parameter '([^']+)'.*(?:is|appears) vulnerable", line, re.IGNORECASE)
        if m:
            param_hits.append(m.group(1))
    if not param_hits:
        return obs

    ev = Evidence(raw_excerpt=result.stdout[:4000])
    obs.evidence.append(ev)
    obs.findings.append(
        Finding(
            kind="sqli",
            severity=Severity.high,
            entity_type=entity_type,
            entity_id=entity_id,
            title=f"SQL injection in parameter(s): {', '.join(param_hits)}",
            description="sqlmap reports one or more parameters are injectable.",
            recommendation="Use parameterized queries / ORM binding; audit server-side "
                           "sanitization; review database user privileges.",
            source_tool="sqlmap",
            confidence=0.95,
        )
    )
    return obs
