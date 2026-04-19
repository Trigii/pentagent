"""Deterministic rule-based planner.

Produces a baseline set of candidate Actions from the current knowledge
graph state. This is the fallback if the LLM fails or is disabled, and it
also provides the candidate pool the LLM re-ranks.

The planner is intentionally versatile — it proposes **every** sensible
next step simultaneously and lets the LLM (or priority ordering) pick one
per iteration. Over a long-running session this drives the agent through:

    Passive recon   — subfinder (domain enumeration)
    Triage          — httpx (alive / tech fingerprint)
    Port surface    — nmap (service discovery per host)
    Content disc.   — ffuf → gobuster fallback → ffuf-bigwordlist retry
    Crawl           — katana (link + JS discovery)
    Vuln triage     — nuclei (low/medium/high templates — severity is
                      clamped by tool config, so UA stays at info/low/med)
    Web audit       — nikto (safe mode only, disabled by default for UA)
    Exploit         — sqlmap (aggressive + per-target opt-in only)

Rules learn from prior outcomes: a WebApp that got zero endpoints from a
common-wordlist ffuf earns a "try harder" escalation with a bigger list;
a WebApp that's been crawled and scanned gets deprioritized; a Host with
services already discovered doesn't get re-nmapped.
"""
from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Any

from ..config import Settings
from ..memory import KnowledgeStore
from ..safety import Scope
from .actions import Action, ActionPriority


# -- wordlists used for the "try harder" ladder --------------------------------
# Paths follow SecLists' default Kali layout. If you ship a different
# wordlist set, override via cfg.tool("ffuf").extras["wordlist_big"].
_DEFAULT_WORDLIST_SMALL = "/usr/share/seclists/Discovery/Web-Content/common.txt"
_DEFAULT_WORDLIST_BIG = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"


@dataclass
class _State:
    subfinder_done: set[str] = field(default_factory=set)
    amass_done: set[str] = field(default_factory=set)
    httpx_done: set[str] = field(default_factory=set)
    nmap_done: set[str] = field(default_factory=set)          # host key (ip or hostname)
    content_disc_done: set[int] = field(default_factory=set)  # webapp_ids touched by ffuf/gobuster/katana
    ffuf_done_small: set[int] = field(default_factory=set)    # webapp_ids hit with small wordlist
    ffuf_done_big: set[int] = field(default_factory=set)      # webapp_ids hit with big wordlist
    gobuster_done: set[int] = field(default_factory=set)
    katana_done: set[int] = field(default_factory=set)
    nuclei_done: set[int] = field(default_factory=set)
    nikto_done: set[int] = field(default_factory=set)
    sqlmap_done: set[int] = field(default_factory=set)


class HeuristicPlanner:
    def __init__(self, settings: Settings, scope: Scope) -> None:
        self.settings = settings
        self.scope = scope

    # ------------------------------------------------------------------
    # The planner is stateless per-call. It reconstructs "what's done"
    # from the action_log kept in the KnowledgeStore.
    # ------------------------------------------------------------------
    def _state_from_store(self, store: KnowledgeStore) -> _State:
        st = _State()
        cur = store._conn.execute("SELECT tool, params FROM action_log")
        for row in cur:
            tool = row["tool"]
            try:
                p = _json.loads(row["params"]) if row["params"] else {}
            except Exception:
                p = {}
            if tool == "subfinder":
                st.subfinder_done.add(str(p.get("domain", "")))
            elif tool == "amass":
                st.amass_done.add(str(p.get("domain", "")))
            elif tool == "httpx":
                targets = p.get("targets") or ([p["target"]] if p.get("target") else [])
                for t in targets:
                    if t:
                        st.httpx_done.add(str(t))
            elif tool == "nmap":
                tgt = p.get("target")
                if tgt:
                    st.nmap_done.add(str(tgt))
            elif tool == "ffuf":
                if "webapp_id" in p:
                    wid = int(p["webapp_id"])
                    st.content_disc_done.add(wid)
                    if str(p.get("wordlist_tier", "small")) == "big":
                        st.ffuf_done_big.add(wid)
                    else:
                        st.ffuf_done_small.add(wid)
            elif tool == "gobuster":
                if "webapp_id" in p:
                    wid = int(p["webapp_id"])
                    st.content_disc_done.add(wid)
                    st.gobuster_done.add(wid)
            elif tool == "katana":
                if "webapp_id" in p:
                    wid = int(p["webapp_id"])
                    st.content_disc_done.add(wid)
                    st.katana_done.add(wid)
            elif tool == "nuclei":
                if "webapp_id" in p:
                    st.nuclei_done.add(int(p["webapp_id"]))
            elif tool == "nikto":
                if "webapp_id" in p:
                    st.nikto_done.add(int(p["webapp_id"]))
            elif tool == "sqlmap":
                if "endpoint_id" in p:
                    st.sqlmap_done.add(int(p["endpoint_id"]))
        return st

    # ------------------------------------------------------------------

    def propose(self, store: KnowledgeStore, seed_targets: list[str]) -> list[Action]:
        """Return candidate actions, roughly in priority order."""
        out: list[Action] = []
        done = self._state_from_store(store)
        cfg = self.settings

        hosts = store.hosts()
        webapps = store.webapps()
        endpoints = store.endpoints()

        # endpoint count per webapp (drives the "try harder" ladder)
        ep_count_by_webapp: dict[int, int] = {}
        for e in endpoints:
            ep_count_by_webapp[e.webapp_id] = ep_count_by_webapp.get(e.webapp_id, 0) + 1

        # Per-host open-port presence from services (for nmap "done" signal)
        svc_by_host: dict[int, int] = {}
        for s in store.services():
            svc_by_host[s.host_id] = svc_by_host.get(s.host_id, 0) + 1

        # -----------------------------------------------------------------
        # 1. Passive enumeration: subfinder on every seed **domain**.
        #    We also run subfinder on apex hostnames discovered later so
        #    that e.g. a CT-log-sourced child can backfill siblings.
        # -----------------------------------------------------------------
        seed_domains: set[str] = set()
        import ipaddress as _ip
        for t in seed_targets:
            host = t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
            if not host or "." not in host:
                continue
            # Skip bare IP addresses — subfinder would just burn a request.
            try:
                _ip.ip_address(host)
                continue
            except ValueError:
                pass
            seed_domains.add(host)
        for dom in sorted(seed_domains):
            if dom in done.subfinder_done or not cfg.tool("subfinder").enabled:
                continue
            out.append(
                Action(
                    tool="subfinder",
                    params={"domain": dom},
                    reason=f"passive subdomain enumeration for {dom}",
                    expected_signal="list of subdomains",
                    priority=ActionPriority.high,
                )
            )

        # -----------------------------------------------------------------
        # 2. HTTP triage: batch httpx on every Host we haven't probed yet.
        #    Dedupe by resolved target string — bootstrap can produce
        #    multiple Host rows for the same hostname (one hostname-only
        #    row plus one row per resolved IP that reuses the hostname).
        # -----------------------------------------------------------------
        host_targets: list[str] = []
        seen_targets: set[str] = set()
        for h in hosts:
            key = h.hostname or h.ip
            if not key or key in done.httpx_done or key in seen_targets:
                continue
            if not self._in_scope(key):
                continue
            seen_targets.add(key)
            host_targets.append(key)
        if host_targets and cfg.tool("httpx").enabled:
            out.append(
                Action(
                    tool="httpx",
                    params={"targets": host_targets},
                    reason=f"{len(host_targets)} host(s) not yet probed over HTTP",
                    expected_signal="live webapps + tech detection",
                    priority=ActionPriority.critical,
                )
            )

        # -----------------------------------------------------------------
        # 3. Port surface: nmap per Host. Port-scan hostname OR IP
        #    depending on what we've got — preferring hostname so SNI /
        #    vhost behavior is observable. Skip if services already known.
        #    Dedupe by target string (same hostname may appear on
        #    multiple Host rows via DNS-resolution bootstrap).
        # -----------------------------------------------------------------
        nmap_seen: set[str] = set()
        if cfg.tool("nmap").enabled:
            for h in hosts:
                target = h.hostname or h.ip
                if not target or target in nmap_seen:
                    continue
                if target in done.nmap_done:
                    continue
                if h.id is not None and svc_by_host.get(h.id, 0) > 0:
                    # already have services for this host — skip top-1000
                    continue
                if not self._in_scope(target):
                    continue
                nmap_seen.add(target)
                out.append(
                    Action(
                        tool="nmap",
                        params={
                            "target": target,
                            # flags are driven by cfg; default_flags live in tool config
                            "flags": list(cfg.tool("nmap").default_flags
                                          or ["-sV", "-Pn", "--top-ports", "1000", "-T3"]),
                        },
                        reason=f"no port-scan yet for {target}",
                        expected_signal="open TCP services + versions",
                        priority=ActionPriority.high,
                    )
                )

        # -----------------------------------------------------------------
        # 4. Content discovery on WebApps that have none yet. First try
        #    ffuf with the configured wordlist (small/common).
        # -----------------------------------------------------------------
        if cfg.tool("ffuf").enabled:
            small_list = (
                cfg.tool("ffuf").extras.get("wordlist")
                or getattr(cfg.tool("ffuf"), "wordlist", None)
                or _DEFAULT_WORDLIST_SMALL
            )
            rps = cfg.tool("ffuf").extras.get("requests_per_second", 20)
            for w in webapps:
                if w.id is None or w.id in done.ffuf_done_small:
                    continue
                if not self._in_scope(w.base_url):
                    continue
                out.append(
                    Action(
                        tool="ffuf",
                        params={
                            "url": f"{w.base_url}/FUZZ",
                            "wordlist": small_list,
                            "rate": rps,
                            "mode": "content",
                            "wordlist_tier": "small",
                            "webapp_id": w.id,
                        },
                        parser_context={"webapp_id": w.id},
                        reason=f"no content discovery on {w.base_url}",
                        expected_signal="new endpoints (200/301/302/401/403)",
                        priority=ActionPriority.high,
                    )
                )

        # -----------------------------------------------------------------
        # 5. Crawl: katana. Complementary to ffuf (follows links, parses JS).
        # -----------------------------------------------------------------
        if cfg.tool("katana").enabled:
            for w in webapps:
                if w.id is None or w.id in done.katana_done:
                    continue
                if not self._in_scope(w.base_url):
                    continue
                out.append(
                    Action(
                        tool="katana",
                        params={
                            "url": w.base_url,
                            "depth": 2,
                            "js_crawl": True,
                            "webapp_id": w.id,
                        },
                        parser_context={"webapp_id": w.id},
                        reason=f"crawl {w.base_url} for link- and JS-derived endpoints",
                        expected_signal="new endpoints via link discovery",
                        priority=ActionPriority.normal,
                    )
                )

        # -----------------------------------------------------------------
        # 6. Try harder — ffuf with a larger wordlist when the first pass
        #    came up thin, but only if the big wordlist hasn't run yet.
        # -----------------------------------------------------------------
        if cfg.tool("ffuf").enabled:
            big_list = cfg.tool("ffuf").extras.get("wordlist_big") or _DEFAULT_WORDLIST_BIG
            rps = cfg.tool("ffuf").extras.get("requests_per_second", 20)
            for w in webapps:
                if w.id is None:
                    continue
                if w.id not in done.ffuf_done_small:
                    continue        # hasn't tried the small list yet
                if w.id in done.ffuf_done_big:
                    continue        # already escalated
                if ep_count_by_webapp.get(w.id, 0) >= 8:
                    continue        # got plenty of content — no need to escalate
                if not self._in_scope(w.base_url):
                    continue
                out.append(
                    Action(
                        tool="ffuf",
                        params={
                            "url": f"{w.base_url}/FUZZ",
                            "wordlist": big_list,
                            "rate": rps,
                            "mode": "content",
                            "wordlist_tier": "big",
                            "webapp_id": w.id,
                        },
                        parser_context={"webapp_id": w.id},
                        reason=(
                            f"small wordlist found only "
                            f"{ep_count_by_webapp.get(w.id, 0)} endpoint(s) "
                            f"on {w.base_url} — escalating to {big_list.split('/')[-1]}"
                        ),
                        expected_signal="deeper endpoint set",
                        priority=ActionPriority.normal,
                    )
                )

        # -----------------------------------------------------------------
        # 7. gobuster fallback: different algorithm, different false-
        #    positive profile. Only run if ffuf produced nothing.
        # -----------------------------------------------------------------
        if cfg.tool("gobuster").enabled:
            wl = (
                cfg.tool("gobuster").extras.get("wordlist")
                or getattr(cfg.tool("gobuster"), "wordlist", None)
                or _DEFAULT_WORDLIST_SMALL
            )
            for w in webapps:
                if w.id is None or w.id in done.gobuster_done:
                    continue
                # Only run when ffuf has already tried AND came up empty
                if w.id not in done.ffuf_done_small:
                    continue
                if ep_count_by_webapp.get(w.id, 0) > 0:
                    continue
                if not self._in_scope(w.base_url):
                    continue
                out.append(
                    Action(
                        tool="gobuster",
                        params={
                            "submode": "dir",
                            "url": w.base_url,
                            "wordlist": wl,
                            "webapp_id": w.id,
                        },
                        parser_context={"webapp_id": w.id},
                        reason=f"ffuf found nothing on {w.base_url} — try gobuster",
                        expected_signal="endpoints via a different matcher",
                        priority=ActionPriority.low,
                    )
                )

        # -----------------------------------------------------------------
        # 8. Vuln triage with nuclei. Severity + tag-excludes come from
        #    the tool config, so UA's restrictive profile is respected.
        # -----------------------------------------------------------------
        if cfg.tool("nuclei").enabled:
            severity = (
                cfg.tool("nuclei").extras.get("severity")
                or "low,medium,high,critical"
            )
            exclude_tags = cfg.tool("nuclei").extras.get("exclude_tags") or []
            rate = cfg.tool("nuclei").extras.get("rate_limit", 50)
            for w in webapps:
                if w.id is None or w.id in done.nuclei_done:
                    continue
                if not self._in_scope(w.base_url):
                    continue
                out.append(
                    Action(
                        tool="nuclei",
                        params={
                            "targets": [w.base_url],
                            "severity": severity,
                            "exclude_tags": list(exclude_tags),
                            "rate": rate,
                            "webapp_id": w.id,
                        },
                        parser_context={"entity_type": "WebApp", "entity_id": w.id},
                        reason=f"nuclei {severity} sweep on {w.base_url}",
                        expected_signal="CVE / misconfig findings",
                        priority=ActionPriority.high,
                    )
                )

        # -----------------------------------------------------------------
        # 9. nikto — respect the config flag. UA config disables it.
        # -----------------------------------------------------------------
        if cfg.tool("nikto").enabled:
            for w in webapps:
                if w.id is None or w.id in done.nikto_done:
                    continue
                if not self._in_scope(w.base_url):
                    continue
                out.append(
                    Action(
                        tool="nikto",
                        params={"url": w.base_url, "webapp_id": w.id},
                        parser_context={"webapp_id": w.id},
                        reason=f"nikto web audit on {w.base_url}",
                        expected_signal="misconfig / dangerous files",
                        priority=ActionPriority.low,
                    )
                )

        # -----------------------------------------------------------------
        # 10. Endpoints with query strings → sqlmap. Gated by session.mode:
        #   - aggressive: requires per-target `aggressive_opt_in` in scope
        #   - ctf:        auto-opt-in (owned lab machines, HTB, THM, etc.)
        # -----------------------------------------------------------------
        if cfg.session.mode in ("aggressive", "ctf") and cfg.tool("sqlmap").enabled:
            for e in endpoints:
                if e.id in done.sqlmap_done:
                    continue
                if "?" not in e.path and not e.params:
                    continue
                webapp = next((w for w in webapps if w.id == e.webapp_id), None)
                if not webapp:
                    continue
                full = f"{webapp.base_url}{e.path}"
                # CTF mode bypasses per-target opt-in; aggressive still honors it.
                if cfg.session.mode == "aggressive" and not self._aggressive_opt_in(full):
                    continue
                out.append(
                    Action(
                        tool="sqlmap",
                        params={
                            "url": full,
                            "risk": 1,
                            "level": 1,
                            "endpoint_id": e.id,
                        },
                        parser_context={"entity_type": "Endpoint", "entity_id": e.id},
                        reason=f"parameterized endpoint {e.path} with aggressive opt-in",
                        expected_signal="SQLi confirmation + dbms fingerprint",
                        priority=ActionPriority.critical,
                    )
                )

        # Phase-aware ordering: earlier phase wins, ties broken by priority.
        out.sort(key=lambda a: a.sort_key())
        return out

    # ------------------------------------------------------------------

    def _in_scope(self, target: str) -> bool:
        from ..safety.scope import ScopeGuard, ScopeViolation
        guard = ScopeGuard(self.scope)
        try:
            guard.check(target)
            return True
        except ScopeViolation:
            return False

    def _aggressive_opt_in(self, target: str) -> bool:
        from ..safety.scope import ScopeGuard, ScopeViolation
        guard = ScopeGuard(self.scope)
        try:
            guard.check(target, aggressive=True)
            return True
        except ScopeViolation:
            return False
