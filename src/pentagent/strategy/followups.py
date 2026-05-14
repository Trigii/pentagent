"""Reactive planner — turns observations into targeted next-step Actions.

This is the agent's responsiveness layer. The base HeuristicPlanner only
considers graph state (hosts/webapps/endpoints) when proposing work. On
its own it would drive a shallow sweep: one httpx, one nmap, one nuclei
per entity. Real pentest methodology requires *reacting* to what each
scan uncovers — and that's what this module does.

Four synthesis channels:

  1. **Finding-driven**  — a panel/exposure/CVE finding lands, propose a
     tag-targeted nuclei run to dig deeper.
  2. **Service-driven**  — nmap returns SSH/FTP/SMB/MySQL/etc.; propose
     per-service nuclei sweeps that use the right template tags.
  3. **Tech-driven / CMS-specific** — httpx tech_detect reports
     WordPress/Joomla/Drupal/Magento/etc.; run the matching CMS tag so
     we pick up CMS-specific CVEs and default-credential checks.
  4. **Vuln-class profiles** — once a webapp has had a generic nuclei
     sweep, systematically run per-class profiles (lfi, sqli, xss,
     ssrf, rce, idor, xxe, open-redirect, ssti, csrf). This is step 5
     of the standard methodology — "test every class of web vuln".

All four paths emit Actions using tools already registered in the core
registry (`nuclei`, `ffuf`). Unknown-tool hallucinations would be filtered
by the LLM-planner path, but the heuristic path doesn't know about the
registry at import time — so everything here sticks to the core tools.

Dedupe is the caller's responsibility: HeuristicPlanner.propose() unions
every source of candidates, then filters via Action.signature() against
`action_log`. A follow-up whose signature matches a prior run is dropped.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..memory import Finding, Host, Service, WebApp
from .actions import Action, ActionPriority


# ============================================================================
# 1. Finding-driven followups
# ============================================================================

def _panel_followup(f: Finding, webapps_by_id: dict[int, WebApp]) -> list[Action]:
    """Admin / exposed / login panels are credentialed-attack surface.
    Propose a tech-tagged nuclei scan on the hosting webapp so we pick
    up panel-specific CVEs and default-cred checks."""
    if f.entity_type != "WebApp" or f.entity_id is None:
        return []
    wa = webapps_by_id.get(int(f.entity_id))
    if wa is None or not wa.base_url:
        return []

    tid = (f.template_id or f.kind or "").lower()
    tags: list[str] = []
    if "flowise" in tid: tags.append("flowise")
    if "grafana" in tid: tags.append("grafana")
    if "kibana" in tid: tags.append("kibana")
    if "jenkins" in tid: tags.append("jenkins")
    if "rabbit" in tid: tags.append("rabbitmq")
    if "phpmyadmin" in tid: tags.append("phpmyadmin")
    if "wp-login" in tid or "wordpress" in tid: tags.append("wordpress")
    if "portainer" in tid: tags.append("portainer")
    if "gitlab" in tid: tags.append("gitlab")
    tags.extend(("panel", "default-login"))
    seen: set[str] = set()
    tags = [t for t in tags if not (t in seen or seen.add(t))]

    return [
        Action(
            tool="nuclei",
            params={
                "targets": [wa.base_url],
                "tags": ",".join(tags),
                "severity": "info,low,medium,high,critical",
                "rate": 30,
                "webapp_id": wa.id,
            },
            parser_context={"entity_type": "WebApp", "entity_id": wa.id},
            reason=(
                f"followup: panel detected ({f.template_id or f.kind}) on "
                f"{wa.base_url} — tag-targeted nuclei [{','.join(tags)}]"
            ),
            expected_signal="app-specific CVEs, default credentials",
            priority=ActionPriority.high,
        )
    ]


def _exposed_vcs_followup(f: Finding, webapps_by_id: dict[int, WebApp]) -> list[Action]:
    """Exposed .git/.env/backup/etc. → sweep for sibling exposures."""
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
    """A confirmed CVE → broader CVE sweep for related issues in same stack."""
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
                f"followup: {tid} confirmed on {wa.base_url} — "
                f"broader CVE sweep (medium+ severity)"
            ),
            expected_signal="chained CVEs in same software stack",
            priority=ActionPriority.high,
        )
    ]


_PANEL_KEYS = (
    "flowise-panel", "grafana-detect", "kibana-detect", "jenkins-login",
    "admin-panel", "exposed-panel", "login-panel", "phpmyadmin-panel",
    "wp-login", "portainer", "kubernetes-dashboard", "rabbitmq", "gitlab-login",
)
_VCS_KEYS = (
    "exposed-git", "git-config", "env-file-exposed", "aws-credentials",
    "private-key-exposed", "exposed-backup", "exposed-sql",
)


def _matches(keys: Iterable[str], sig: str) -> bool:
    return any(k in sig for k in keys)


_FINDING_FOLLOWUPS: list[tuple[Callable[[str], bool], Callable[[Finding, dict[int, WebApp]], list[Action]]]] = [
    (lambda sig: _matches(_VCS_KEYS, sig), _exposed_vcs_followup),
    (lambda sig: _matches(_PANEL_KEYS, sig), _panel_followup),
    (lambda sig: sig.startswith("cve-") or "cve-" in sig, _cve_followup),
]


def _finding_driven(findings: list[Finding], webapps: list[WebApp]) -> list[Action]:
    webapps_by_id: dict[int, WebApp] = {int(w.id): w for w in webapps if w.id is not None}
    out: list[Action] = []
    for f in findings:
        sig = f"{f.template_id or ''} {f.kind or ''}".lower().strip()
        if not sig:
            continue
        for matcher, factory in _FINDING_FOLLOWUPS:
            if matcher(sig):
                out.extend(factory(f, webapps_by_id))
                break
    return out


# ============================================================================
# 2. Service-driven followups (methodology step 4: fingerprint → known vulns)
# ============================================================================

# Per-port/product → (nuclei tag, expected_signal, priority)
# Keyed on the *product* field nmap -sV emits when confident; falls back
# to port-based rules for well-known ports when product is unknown.
_SERVICE_PROFILES: dict[str, tuple[str, str, int]] = {
    "ssh": (
        "ssh,network",
        "weak ciphers, outdated OpenSSH CVEs, auth method leakage",
        ActionPriority.normal,
    ),
    "ftp": (
        "ftp,network,default-login",
        "anonymous login, FTP banner CVEs, default creds",
        ActionPriority.high,
    ),
    "smb": (
        "smb,network,cve",
        "null sessions, EternalBlue, SMB signing disabled",
        ActionPriority.high,
    ),
    "netbios": (
        "smb,network",
        "NetBIOS leakage",
        ActionPriority.normal,
    ),
    "mysql": (
        "mysql,network,default-login",
        "mysql empty password, default creds, version CVEs",
        ActionPriority.high,
    ),
    "postgres": (
        "postgres,network,default-login",
        "default postgres creds, trust-auth misconfig",
        ActionPriority.high,
    ),
    "mssql": (
        "mssql,network,default-login",
        "sa/blank password, version CVEs",
        ActionPriority.high,
    ),
    "mongodb": (
        "mongodb,network,default-login",
        "no-auth mongo, default creds",
        ActionPriority.high,
    ),
    "redis": (
        "redis,network,default-login",
        "no-auth redis, lua sandbox escape CVEs",
        ActionPriority.high,
    ),
    "elasticsearch": (
        "elasticsearch,network",
        "open ES cluster, version CVEs",
        ActionPriority.high,
    ),
    "memcached": (
        "memcached,network",
        "UDP-amp vector, unauth access",
        ActionPriority.normal,
    ),
    "smtp": (
        "smtp,network",
        "smtp user-enum, open-relay, starttls stripping",
        ActionPriority.normal,
    ),
    "snmp": (
        "snmp,network",
        "public community, SNMP walk leakage",
        ActionPriority.normal,
    ),
    "rdp": (
        "rdp,network,cve",
        "BlueKeep, NLA-off, version CVEs",
        ActionPriority.high,
    ),
    "vnc": (
        "vnc,network,default-login",
        "no-auth VNC, default creds",
        ActionPriority.high,
    ),
    "telnet": (
        "telnet,network,default-login",
        "default creds, cleartext auth",
        ActionPriority.high,
    ),
    "dns": (
        "dns,network",
        "version.bind leakage, open recursion",
        ActionPriority.low,
    ),
    "ldap": (
        "ldap,network",
        "anonymous bind, base DN enumeration",
        ActionPriority.normal,
    ),
    "kerberos": (
        "kerberos,network",
        "username leakage, ASREPRoast candidates",
        ActionPriority.normal,
    ),
}

# Well-known-port → service-key fallback when product field is empty.
_PORT_TO_SERVICE: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp",
    636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2181: "zookeeper",
    2375: "docker", 2376: "docker",
    3306: "mysql", 3389: "rdp", 5000: "upnp", 5432: "postgres",
    5601: "kibana", 5672: "rabbitmq", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 6667: "irc", 8009: "ajp", 8086: "influxdb",
    8089: "splunk", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 15672: "rabbitmq", 27017: "mongodb",
}


def _service_key(s: Service) -> str | None:
    """Map a service to a known profile key — prefer product, fall back
    to port. Returns None if nothing useful."""
    if s.product:
        p = s.product.lower()
        # Normalize common nmap product strings: "OpenSSH 8.2p1" → "ssh"
        for k in _SERVICE_PROFILES:
            if k in p:
                return k
    if s.port in _PORT_TO_SERVICE:
        key = _PORT_TO_SERVICE[s.port]
        # Only return if we actually have a profile for it
        if key in _SERVICE_PROFILES:
            return key
    return None


def _service_driven(services: list[Service], hosts: list[Host]) -> list[Action]:
    """One nuclei run per (host, service-profile) pair we haven't seen.

    nuclei `-u <ip>:<port>` works for network services too — templates
    tagged `ssh`, `ftp`, etc. probe the right protocol.
    """
    if not services:
        return []
    hosts_by_id: dict[int, Host] = {int(h.id): h for h in hosts if h.id is not None}
    out: list[Action] = []

    # Dedupe by (host_key, service_key) so a host with two MySQL ports
    # doesn't get double-tagged.
    seen: set[tuple[str, str]] = set()
    for s in services:
        key = _service_key(s)
        if not key:
            continue
        tags, expected, prio = _SERVICE_PROFILES[key]
        host = hosts_by_id.get(int(s.host_id))
        if host is None:
            continue
        host_label = host.hostname or host.ip
        if not host_label:
            continue
        dedup = (host_label, key)
        if dedup in seen:
            continue
        seen.add(dedup)
        target = f"{host_label}:{s.port}"
        out.append(
            Action(
                tool="nuclei",
                params={
                    "targets": [target],
                    "tags": tags,
                    "severity": "low,medium,high,critical",
                    "rate": 30,
                    "host_id": host.id,
                    "service_port": s.port,
                },
                parser_context={"entity_type": "Host", "entity_id": host.id},
                reason=(
                    f"service followup: {key} on {target} "
                    f"(product={s.product or '-'}, version={s.version or '-'}) "
                    f"— nuclei [{tags}]"
                ),
                expected_signal=expected,
                priority=prio,
            )
        )
    return out


# ============================================================================
# 3. Tech-driven / CMS-specific followups
# ============================================================================

# WebApp.tech list → nuclei tag. When httpx tech-detect reports one of
# these, trigger the matching CMS/framework sweep.
_TECH_TAGS: dict[str, str] = {
    # CMS
    "wordpress": "wordpress,wp-plugin,wp-theme,cve",
    "joomla":    "joomla,cve",
    "drupal":    "drupal,cve",
    "magento":   "magento,cve",
    "shopify":   "shopify,cve",
    "ghost":     "ghost,cve",
    "typo3":     "typo3,cve",
    # Web frameworks / language runtimes
    "laravel":   "laravel,php,cve",
    "symfony":   "symfony,php,cve",
    "codeigniter": "codeigniter,php",
    "django":    "django,cve",
    "flask":     "flask,python",
    "rails":     "rails,ruby,cve",
    "spring":    "spring,java,cve",
    "struts":    "struts,java,cve",
    "tomcat":    "tomcat,java,cve",
    "jboss":     "jboss,java,cve",
    "weblogic":  "weblogic,oracle,cve",
    "websphere": "websphere,ibm,cve",
    "nodejs":    "nodejs,cve",
    "express":   "express,nodejs",
    "aspnet":    "aspnet,microsoft,cve",
    "iis":       "iis,microsoft,cve",
    # Web servers
    "apache":    "apache,cve",
    "nginx":     "nginx,cve",
    "lighttpd":  "lighttpd,cve",
    "litespeed": "litespeed,cve",
    # Proxies / gateways
    "haproxy":   "haproxy,cve",
    "traefik":   "traefik,cve",
    "cloudflare": "cloudflare",
    # DevTools / dashboards
    "jenkins":   "jenkins,cve",
    "gitlab":    "gitlab,cve",
    "grafana":   "grafana,cve",
    "kibana":    "kibana,cve",
    "flowise":   "flowise,cve",
}


def _normalize_tech(t: str) -> str:
    """httpx tech entries are strings like 'WordPress', 'Apache/2.4.54',
    'PHP/7.4.3'. Lowercase and strip version tails."""
    return t.split("/", 1)[0].split(":", 1)[0].strip().lower()


def _tech_driven(webapps: list[WebApp]) -> list[Action]:
    """One nuclei run per (webapp, tech) pair we haven't seen."""
    out: list[Action] = []
    seen: set[tuple[int, str]] = set()
    for w in webapps:
        if w.id is None or not w.base_url:
            continue
        for tech_raw in (w.tech or []):
            if not isinstance(tech_raw, str):
                continue
            tech = _normalize_tech(tech_raw)
            if tech not in _TECH_TAGS:
                continue
            dedup = (int(w.id), tech)
            if dedup in seen:
                continue
            seen.add(dedup)
            tags = _TECH_TAGS[tech]
            out.append(
                Action(
                    tool="nuclei",
                    params={
                        "targets": [w.base_url],
                        "tags": tags,
                        "severity": "low,medium,high,critical",
                        "rate": 30,
                        "webapp_id": w.id,
                    },
                    parser_context={"entity_type": "WebApp", "entity_id": w.id},
                    reason=(
                        f"tech followup: {tech} detected on {w.base_url} "
                        f"— nuclei [{tags}]"
                    ),
                    expected_signal=f"{tech}-specific CVEs & misconfigs",
                    priority=ActionPriority.high,
                )
            )
    return out


# ============================================================================
# 4. Vuln-class profiles (methodology step 5: test each web-vuln class)
# ============================================================================

# Each profile is a (name, tags, severity-floor) triple.
#
# severity is kept low-bar because half the point of class-specific runs is
# catching the `info` / `low` templates that got masked by the earlier
# "low,medium,high,critical" sweep. For example, nuclei ships many SSRF
# detection templates as `info` until exploited.
_VULN_CLASS_PROFILES: list[tuple[str, str, str, int]] = [
    # (name, tags, severity_str, priority)
    ("lfi",           "lfi,file-inclusion,path-traversal",   "info,low,medium,high,critical", ActionPriority.high),
    ("sqli",          "sqli,sql-injection",                  "info,low,medium,high,critical", ActionPriority.high),
    ("xss",           "xss,reflected,stored",                "low,medium,high,critical",       ActionPriority.normal),
    ("ssrf",          "ssrf",                                "info,low,medium,high,critical", ActionPriority.high),
    ("rce",           "rce,code-injection,command-injection","medium,high,critical",           ActionPriority.critical),
    ("xxe",           "xxe",                                 "medium,high,critical",           ActionPriority.high),
    ("open-redirect", "redirect,open-redirect",              "low,medium,high,critical",       ActionPriority.normal),
    ("ssti",          "ssti,template-injection",             "medium,high,critical",           ActionPriority.high),
    ("idor",          "idor",                                "low,medium,high,critical",       ActionPriority.high),
    ("deserialization","deserialization,unserialize",        "medium,high,critical",           ActionPriority.critical),
    ("auth-bypass",   "auth-bypass,authentication",          "medium,high,critical",           ActionPriority.high),
    ("js-secrets",    "exposure,token,js",                   "info,low,medium,high,critical", ActionPriority.high),
    ("takeover",      "takeover",                            "high,critical",                   ActionPriority.critical),
    ("tls",           "tls,ssl,misconfig",                   "low,medium,high,critical",       ActionPriority.normal),
]


def _vuln_class_driven(webapps: list[WebApp]) -> list[Action]:
    """Emit one action per (webapp, vuln-class) pair. The planner's
    signature-based dedupe makes re-runs a no-op."""
    out: list[Action] = []
    for w in webapps:
        if w.id is None or not w.base_url:
            continue
        for name, tags, severity, prio in _VULN_CLASS_PROFILES:
            out.append(
                Action(
                    tool="nuclei",
                    params={
                        "targets": [w.base_url],
                        "tags": tags,
                        "severity": severity,
                        "rate": 30,
                        "webapp_id": w.id,
                        "vuln_class": name,
                    },
                    parser_context={"entity_type": "WebApp", "entity_id": w.id},
                    reason=(
                        f"vuln-class probe: {name} on {w.base_url} "
                        f"— nuclei [{tags}]"
                    ),
                    expected_signal=f"{name} findings",
                    priority=prio,
                )
            )
    return out


# ============================================================================
# Public API
# ============================================================================

def synthesize(
    findings: list[Finding],
    webapps: list[WebApp],
    *,
    services: list[Service] | None = None,
    hosts: list[Host] | None = None,
    include_vuln_classes: bool = False,
    include_tech: bool = True,
) -> list[Action]:
    """One-stop reactive planner. Returns Action candidates from every
    synthesis channel. Order within the list is stable but not priority-
    sorted — the caller applies `Action.sort_key()` after dedupe.

    Backward-compat: the old two-arg signature `(findings, webapps)` is
    preserved. When called positionally with no services/hosts, the
    service-driven channel is a no-op; vuln-class probes default off so
    the caller must opt in once the earlier phases have produced enough
    state to make class-sweeps productive.
    """
    out: list[Action] = []
    out.extend(_finding_driven(findings, webapps))
    if services and hosts:
        out.extend(_service_driven(services, hosts))
    if include_tech:
        out.extend(_tech_driven(webapps))
    if include_vuln_classes:
        out.extend(_vuln_class_driven(webapps))
    return out
