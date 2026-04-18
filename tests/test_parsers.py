"""Parser smoke tests with realistic fixtures."""
from __future__ import annotations

import json

from pentagent.parsers import parse_for
from pentagent.tools.base import ToolResult


def _result(tool: str, stdout: str) -> ToolResult:
    return ToolResult(tool=tool, argv=[], stdout=stdout, stderr="", exit_code=0, duration_s=0.1)


def test_httpx_parser_builds_webapp_and_host():
    line = json.dumps({
        "url": "https://api.example.com/",
        "host": "api.example.com",
        "scheme": "https",
        "status_code": 200,
        "content_length": 123,
        "title": "hi",
        "tech": ["nginx", "cloudflare"],
        "content_type": "text/html",
    })
    obs = parse_for("httpx", _result("httpx", line))
    assert len(obs.hosts) == 1 and obs.hosts[0].hostname == "api.example.com"
    assert len(obs.webapps) == 1 and obs.webapps[0].base_url == "https://api.example.com"
    # WebApp's host_id should be the placeholder for obs.hosts[0]
    assert obs.webapps[0].host_id == -1
    assert obs.endpoints and obs.endpoints[0].path == "/"


def test_nmap_parser_builds_hosts_and_services():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <hostnames><hostname name="x.example.com"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.21"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    obs = parse_for("nmap", _result("nmap", xml))
    assert len(obs.hosts) == 1
    assert len(obs.services) == 1  # closed port dropped
    svc = obs.services[0]
    assert svc.port == 443 and svc.product == "nginx" and svc.version == "1.21"
    assert svc.host_id == -1


def test_subfinder_parser_creates_hosts():
    stdout = "a.example.com\nb.example.com\n  \nevil.com\n"
    obs = parse_for("subfinder", _result("subfinder", stdout))
    names = {h.hostname for h in obs.hosts}
    assert names == {"a.example.com", "b.example.com", "evil.com"}


def test_nuclei_parser_builds_findings():
    line = json.dumps({
        "template-id": "http-missing-security-headers",
        "info": {"name": "Missing Security Headers", "severity": "low",
                 "description": "desc", "remediation": "fix it"},
        "matched-at": "https://example.com/",
        "request": "GET /",
        "response": "HTTP/1.1 200 OK",
    })
    obs = parse_for("nuclei", _result("nuclei", line), {"entity_type": "WebApp", "entity_id": 7})
    assert obs.findings and obs.findings[0].kind == "http-missing-security-headers"
    assert obs.findings[0].entity_id == 7
    assert obs.evidence  # evidence record emitted
