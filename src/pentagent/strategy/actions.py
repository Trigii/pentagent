"""Action = a ranked proposal for the next tool invocation.

Two distinct identity keys exist:

* **dedup_key** — strict equality over the full (tool, params) blob. Used
  by the cache: only an *identical* invocation is considered already-run.
  Different severities / wordlists / rates all produce different keys.

* **signature** — canonical (tool, primary-target) identity. Used by the
  planner to prevent proposing the same tool against the same target over
  and over with cosmetic param variations (e.g. LLM-proposed nuclei with
  severity='high' then severity='medium,high' then severity='high,middle').
  Signatures collapse those into one logical "have we scanned X with tool
  Y yet" question.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any
from urllib.parse import urlparse


class ActionPriority(IntEnum):
    low = 1
    normal = 5
    high = 8
    critical = 10


def _canonical_target(params: dict[str, Any]) -> str:
    """Extract a stable target identifier from a params dict.

    The rule: prefer whatever field points at "the thing we're aiming at",
    lowercase it, strip scheme and trailing slashes so http://x.com/ and
    x.com collapse. For multi-target tools (list of URLs/hosts), we sort
    and join so order doesn't matter.
    """
    def _one(v: Any) -> str:
        s = str(v).strip().lower().rstrip("/")
        if "://" in s:
            p = urlparse(s)
            host = p.netloc or p.path
            path = p.path if p.netloc else ""
            return (host + path).rstrip("/")
        return s

    # Single-target keys, in priority order
    for key in ("url", "target", "domain", "host"):
        v = params.get(key)
        if isinstance(v, str) and v:
            return _one(v)

    # Multi-target keys
    v = params.get("targets")
    if isinstance(v, (list, tuple)) and v:
        return ",".join(sorted({_one(x) for x in v if x}))

    # Fall back to entity-id hints (e.g. webapp_id=42)
    for key in ("webapp_id", "endpoint_id", "host_id"):
        if key in params:
            return f"{key}={params[key]}"

    return ""


@dataclass
class Action:
    tool: str
    params: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    expected_signal: str = ""
    priority: int = ActionPriority.normal
    # Parser context — passed through to parse_for() so parsers can know
    # which webapp/endpoint this tool run belongs to.
    parser_context: dict[str, Any] = field(default_factory=dict)

    def dedup_key(self) -> str:
        """Exact (tool, params) hash — used by the execution cache."""
        import hashlib
        import json
        blob = json.dumps({"tool": self.tool, "params": self.params}, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def signature(self) -> str:
        """Logical identity: tool + canonical target. Used by the planner to
        avoid proposing the same tool-against-target twice, regardless of
        severity/wordlist/rate variations."""
        return f"{self.tool}::{_canonical_target(self.params)}"
