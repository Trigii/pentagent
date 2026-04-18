"""Typed domain models for the knowledge graph.

We use pydantic so that parsers can happily return dicts that get
validated at the store boundary, and so LLM prompts can include JSON
schemas derived from the models.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Target(BaseModel):
    kind: Literal["domain", "ip", "url", "cidr"]
    value: str


class Host(BaseModel):
    id: Optional[int] = None
    ip: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None

    def natural_key(self) -> tuple:
        return (self.ip or "", self.hostname or "")


class Service(BaseModel):
    id: Optional[int] = None
    host_id: int
    port: int
    proto: Literal["tcp", "udp"] = "tcp"
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None

    def natural_key(self) -> tuple:
        return (self.host_id, self.port, self.proto)


class WebApp(BaseModel):
    id: Optional[int] = None
    host_id: int
    scheme: Literal["http", "https"]
    base_url: str          # e.g. "https://example.com:443"
    title: Optional[str] = None
    tech: list[str] = Field(default_factory=list)
    status_code: Optional[int] = None

    def natural_key(self) -> tuple:
        return (self.host_id, self.base_url)


class Endpoint(BaseModel):
    id: Optional[int] = None
    webapp_id: int
    path: str
    method: str = "GET"
    status: Optional[int] = None
    length: Optional[int] = None
    content_type: Optional[str] = None
    params: list[str] = Field(default_factory=list)

    def natural_key(self) -> tuple:
        return (self.webapp_id, self.method.upper(), self.path)


class Parameter(BaseModel):
    id: Optional[int] = None
    endpoint_id: int
    name: str
    location: Literal["query", "body", "header", "cookie", "path"] = "query"
    reflected: bool = False
    taints: list[str] = Field(default_factory=list)

    def natural_key(self) -> tuple:
        return (self.endpoint_id, self.name, self.location)


class Evidence(BaseModel):
    id: Optional[int] = None
    request: Optional[str] = None
    response: Optional[str] = None
    payload: Optional[str] = None
    raw_excerpt: Optional[str] = None


class Finding(BaseModel):
    id: Optional[int] = None
    kind: str                            # free-form: "xss", "sqli", "open-redirect"
    severity: Severity = Severity.info
    entity_type: str                     # "Host" | "Endpoint" | "WebApp" | ...
    entity_id: int
    evidence_id: Optional[int] = None
    confidence: float = 0.5              # 0.0 – 1.0
    title: str
    description: str = ""
    recommendation: str = ""
    source_tool: Optional[str] = None
    template_id: Optional[str] = None    # e.g. nuclei template-id

    def natural_key(self) -> tuple:
        return (self.kind, self.entity_type, self.entity_id, self.template_id or "")


class Hypothesis(BaseModel):
    id: Optional[int] = None
    target_ref: str                      # e.g. "Endpoint:42"
    vuln_class: str                      # "sqli", "xss", "ssrf", ...
    reasoning: str
    attempted: list[str] = Field(default_factory=list)
    status: Literal["open", "confirmed", "refuted", "inconclusive"] = "open"


class Observation(BaseModel):
    """A bundle of new/updated entities emitted by a parser."""
    hosts: list[Host] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    webapps: list[WebApp] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    source_tool: str = ""
    raw_excerpt: Optional[str] = None
    notes: Optional[str] = None

    def summary(self) -> dict[str, Any]:
        return {
            "source_tool": self.source_tool,
            "hosts": len(self.hosts),
            "services": len(self.services),
            "webapps": len(self.webapps),
            "endpoints": len(self.endpoints),
            "parameters": len(self.parameters),
            "findings": len(self.findings),
        }
