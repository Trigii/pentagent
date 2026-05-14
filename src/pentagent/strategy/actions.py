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

    A *facet* suffix may be appended when the action qualifies its target
    with a tag-set, service port, or vuln-class — so that a generic
    nuclei sweep and a tag-targeted follow-up against the same URL land
    on distinct signatures. Without this, the planner would collapse the
    tag-targeted runs into the catch-all and skip them.
    """
    def _one(v: Any) -> str:
        s = str(v).strip().lower().rstrip("/")
        if "://" in s:
            p = urlparse(s)
            host = p.netloc or p.path
            path = p.path if p.netloc else ""
            return (host + path).rstrip("/")
        return s

    # Compute the primary target.
    target = ""
    for key in ("url", "target", "domain", "host"):
        v = params.get(key)
        if isinstance(v, str) and v:
            target = _one(v)
            break
    if not target:
        v = params.get("targets")
        if isinstance(v, (list, tuple)) and v:
            target = ",".join(sorted({_one(x) for x in v if x}))
    if not target:
        for key in ("webapp_id", "endpoint_id", "host_id"):
            if key in params:
                target = f"{key}={params[key]}"
                break
    if not target:
        return ""

    # Compute the facet suffix. A handful of keys split the target into
    # distinct runs: vuln_class, tags, service_port. Priority order
    # matters (most-specific first).
    facet_parts: list[str] = []
    vc = params.get("vuln_class")
    if isinstance(vc, str) and vc:
        facet_parts.append(f"class={vc.lower()}")
    else:
        tags = params.get("tags")
        if isinstance(tags, str) and tags:
            # Normalize tag order so permutations collapse.
            norm = ",".join(sorted({t.strip().lower() for t in tags.split(",") if t.strip()}))
            if norm:
                facet_parts.append(f"tags={norm}")
        elif isinstance(tags, (list, tuple)) and tags:
            norm = ",".join(sorted({str(t).strip().lower() for t in tags if str(t).strip()}))
            if norm:
                facet_parts.append(f"tags={norm}")
    sp = params.get("service_port")
    if sp is not None:
        facet_parts.append(f"port={sp}")
    # Scan profile (e.g. nmap "deep" vs. initial discovery)
    sprof = params.get("scan_profile")
    if isinstance(sprof, str) and sprof:
        facet_parts.append(f"profile={sprof.lower()}")

    if facet_parts:
        return f"{target}:{'|'.join(facet_parts)}"
    return target


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

    def phase(self):
        """Attack-lifecycle phase (recon/enum/vuln/exploit/report). Derived
        from the tool — late-import to avoid a circular dependency with
        strategy.phases which otherwise imports Action for typing."""
        from .phases import phase_of
        return phase_of(self.tool)

    def sort_key(self) -> tuple[int, int]:
        """Tuple used by planners to order candidates.
        Earlier phase first (lower number), then higher priority first.
        Bundle this in one place so LLM rerank + heuristic sort agree."""
        return (int(self.phase()), -int(self.priority))
