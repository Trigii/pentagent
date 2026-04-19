"""Finding-driven follow-up action synthesis.

When a parser commits a Finding, this module turns that signal into
concrete next-step Actions. The heuristic planner only sees graph state
(hosts/webapps/endpoints), not findings — without this module, a nuclei
hit like `flowise-panel` would just sit in the report with no further
investigation.

Design:
  * Each entry in `FOLLOWUPS` is a (pattern-matcher, factory) pair. The
    matcher is a predicate over a finding's `kind`; the factory receives
    the Finding + a lookup map of WebApp rows and yields zero-or-more
    Actions. Factories may return an empty list when context is missing
    (e.g., we can't look up the base_url).
  * The orchestrator/planner calls `synthesize(findings, webapps)` once
    per planning round. Dedupe happens via Action.signature() after the
    heuristic's own candidates are collected.

Explicitly *not* in scope:
  * Running unregistered tools. Every factory emits actions with tool
    names from the core registry (nuclei, ffuf, sqlmap). The LLM-planner's
    `_known_tools()` filter will drop anything else, and the factories
    themselves stick to the registry.
  * Inferring scope. All actions target existing WebApp/Endpoint rows;
    scope was already enforced when those were committed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..memory import Finding, WebApp
from .actions import Action, ActionPriority


# ---- factories --------------------------------------------------------------

def _panel_followup(f: Finding, webapps_by_id: dict[int, WebApp]) -> list[Action]:
    """Admin / exposed / login panels: a panel is a credentialed-attack
    surface. Propose a tech-tagged nuclei scan on the hosting webapp so
    we pick up panel-specific CVEs and default-cred checks. We prefer
    tag-targeted over re-running the full sweep because the catchall
    nuclei run for this webapp has already happened (that's how we got
    this finding in the first place).
    """
    if f.entity_type != "WebApp" or f.entity_id is None:
        return []
    wa = webapps_by_id.get(int(f.entity_id))
    if wa is None or not wa.base_url:
        return []

    # Derive a tag from the template id. flowise-panel → flowise,
    # admin-panel-X → panel, exposed-panel → panel. Default-cred sweep
    # also fires on panels.
    tid = (f.template_id or f.kind or "").lower()
    tags: list[str] = []
    if "flowise" in tid:
        tags.append("flowise")
    if "grafana" in tid:
        tags.append("grafana")
    if "kibana" in tid:
        tags.append("kibana")
    if "jenkins" in tid:
        tags.append("jenkins")
    if "rabbit" in tid:
        tags.append("rabbitmq")
    if "phpmyadmin" in tid:
        tags.append("phpmyadmin")
    if "wp-login" in tid or "wordpress" in tid:
        tags.append("wordpress")
    # Always add "panel" + "default-login" so we catch auth-weakness
    # templates nuclei only ships under those tag roots.
    tags.extend(("panel", "default-login"))
    # Dedupe preserving order
    seen: set[str] = set()
    tags = [t for t in tags if not (t in seen or seen.add(t))]

    return [
        Action(
            tool="nuclei",
            params={
                "targets": [wa.base_url],
                "tags": ",".join(tags),
                # Keep severity low-bar because default-login/panel templates
                # often ship as info but are what we actually care about here.
                "severity": "info,low,medium,high,critical",
                "rate": 30,
                "webapp_id": wa.id,
            },
            parser_context={"entity_type": "WebApp", "entity_id": wa.id},
            reason=(
                f"followup: panel detected ({f.template_id or f.kind}) on "
                f"{wa.base_url} — running tag-targeted nuclei "
                f"[{','.join(tags)}] to surface app-specific CVEs and "
                f"default-credential checks"
            ),
            expected_signal="app-specific CVEs, default credentials",
            priority=ActionPriority.high,
        )
    ]


def _exposed_vcs_followup(f: Finding, webapps_by_id: dict[int, WebApp]) -> list[Action]:
    """An exposed .git / .env is near-guaranteed critical-impact. The
    right follow-up is to *fetch the exposed content* — but we don't want
    to register a new tool here (that's scope for the tool layer, not the
    planner). Instead, propose a deep nuclei + ffuf sweep looking for
    sibling exposures (.svn, .hg, config.bak, .DS_Store, backup.zip).
    """
    if f.entity_type != "WebApp" or f.entity_id is None:
        return []
    wa = webapps_by_id.get(int(f.entity_id))
    if wa is None or not wa.base_url:
        return []

    return [
        Action(
            tool="nuclei",
            params={
                "targets": [wa.base_url],
                "tags": "exposure,backup,config,files",
                "severity": "info,low,medium,high,critical",
                "rate": 30,
                "webapp_id": wa.id,
            },
            parser_context={"entity_type": "WebApp", "entity_id": wa.id},
            reason=(
                f"followup: {f.template_id or f.kind} on {wa.base_url} — "
                f"sweep for sibling exposures (backups, .svn, config files)"
            ),
            expected_signal="additional leaked secrets / configs",
            priority=ActionPriority.critical,
        )
    ]


def _cve_followup(f: Finding, webapps_by_id: dict[int, WebApp]) -> list[Action]:
    """A CVE finding often has *known* exploitation templates. Re-run
    nuclei scoped to the CVE's tag pool (if we can derive one) to pick
    up related CVEs for the same software.
    """
    tid = (f.template_id or "").upper()
    if not tid.startswith("CVE-"):
        return []
    if f.entity_type != "WebApp" or f.entity_id is None:
        return []
    wa = webapps_by_id.get(int(f.entity_id))
    if wa is None or not wa.base_url:
        return []
    return [
        Action(
            tool="nuclei",
            params={
                "targets": [wa.base_url],
                "tags": "cve",
                "severity": "medium,high,critical",
                "rate": 30,
                "webapp_id": wa.id,
            },
            parser_context={"entity_type": "WebApp", "entity_id": wa.id},
            reason=(
                f"followup: {tid} confirmed on {wa.base_url} — running "
                f"broader CVE sweep (medium+ severity) for related issues"
            ),
            expected_signal="chained CVEs in same software stack",
            priority=ActionPriority.high,
        )
    ]


# ---- dispatch table ---------------------------------------------------------

# Each entry: (predicate over finding kind/template_id, factory).
# Predicate runs against the lowercased kind-or-template. Short-circuits
# on first match per finding to keep things deterministic — if a finding
# matches both "panel" and "exposed", we want the more specific panel
# follow-up (ordering matters).

_PANEL_KEYS = (
    "flowise-panel", "grafana-detect", "kibana-detect", "jenkins-login",
    "admin-panel", "exposed-panel", "login-panel", "phpmyadmin-panel",
    "wp-login", "portainer", "kubernetes-dashboard", "rabbitmq",
)
_VCS_KEYS = (
    "exposed-git", "git-config", "env-file-exposed", "aws-credentials",
    "private-key-exposed", "exposed-backup", "exposed-sql",
)


def _matches(keys: Iterable[str], sig: str) -> bool:
    return any(k in sig for k in keys)


FOLLOWUPS: list[tuple[Callable[[str], bool], Callable[[Finding, dict[int, WebApp]], list[Action]]]] = [
    (lambda sig: _matches(_VCS_KEYS, sig), _exposed_vcs_followup),   # most urgent
    (lambda sig: _matches(_PANEL_KEYS, sig), _panel_followup),
    (lambda sig: sig.startswith("cve-") or "cve-" in sig, _cve_followup),
]


# ---- public API -------------------------------------------------------------

def synthesize(findings: list[Finding], webapps: list[WebApp]) -> list[Action]:
    """Turn a findings list into a flat list of follow-up Action candidates.

    The caller (HeuristicPlanner) is responsible for dedupe and scope —
    this function just emits everything the rules suggest.
    """
    webapps_by_id: dict[int, WebApp] = {
        int(w.id): w for w in webapps if w.id is not None
    }

    out: list[Action] = []
    for f in findings:
        sig = f"{f.template_id or ''} {f.kind or ''}".lower().strip()
        if not sig:
            continue
        for matcher, factory in FOLLOWUPS:
            if matcher(sig):
                out.extend(factory(f, webapps_by_id))
                break  # first-match-wins
    return out
