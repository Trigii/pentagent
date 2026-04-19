"""Typer-based CLI.

Usage:
    pentagent run \\
        --config ./config/config.yaml \\
        --scope ./config/scope.yaml \\
        --target https://api.example.com \\
        --i-have-authorization

    pentagent report \\
        --session ./runs/2026-04-18-abc123

    pentagent verify-audit --session ./runs/...

    pentagent list-tools
"""
from __future__ import annotations

import datetime as dt
import secrets
import sys
from pathlib import Path

import typer
from rich.console import Console

from .config import Settings
from .llm import build_client
from .logging_setup import configure_logging, get_logger
from .orchestrator import Orchestrator
from .reporting import Reporter
from .safety import AuditLog, Scope
from .tools import default_registry


# ---------------------------------------------------------------------------
# Scan profiles — mutate a Settings object in-place to widen or narrow the
# scope of automation. Keeps user config as the baseline and layers changes
# on top so a single YAML can serve every scan depth.
# ---------------------------------------------------------------------------
def _apply_profile(settings: Settings, name: str) -> str:
    """Return a human description of the applied profile."""
    name = name.lower()
    tools = settings.tools
    def t(tool_name):
        # Ensure a tool section exists we can mutate
        if tool_name not in tools:
            from .config import ToolConfig
            tools[tool_name] = ToolConfig()
        return tools[tool_name]

    if name == "fast":
        # 20-min triage designed to actually *find things*: shallow but
        # productive. Earlier iterations of this profile disabled every
        # content-discovery tool, which left the agent looping on nuclei
        # variants with nothing new to do. We now keep ffuf + a one-deep
        # katana crawl so the graph grows past httpx's initial tech-detect.
        settings.session.wallclock_minutes = min(settings.session.wallclock_minutes, 20)
        settings.session.max_iterations = min(settings.session.max_iterations, 25)
        settings.session.parallel_actions = max(settings.session.parallel_actions, 4)
        # nmap: top-100 TCP only, aggressive timing — finishes in ~30s per host
        t("nmap").default_flags = ["-sV", "-Pn", "--top-ports", "100", "-T4"]
        # ffuf: small wordlist, one pass, moderate RPS
        ffuf = t("ffuf")
        ffuf.enabled = True
        ffuf.extras.setdefault(
            "wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt"
        )
        ffuf.extras["requests_per_second"] = max(int(ffuf.extras.get("requests_per_second", 30)), 30)
        # katana: minimal crawl — just the landing page + inline JS
        katana = t("katana")
        katana.enabled = True
        katana.extras["depth"] = 1
        # gobuster/nikto: skip (redundant in a triage budget)
        t("gobuster").enabled = False
        t("nikto").enabled = False
        # nuclei: info through medium (dos/intrusive/fuzz excluded always)
        nuclei = t("nuclei")
        nuclei.enabled = True
        nuclei.extras["severity"] = "info,low,medium"
        nuclei.extras["rate_limit"] = max(int(nuclei.extras.get("rate_limit", 50)), 50)
        nuclei.extras.setdefault("exclude_tags", ["dos", "intrusive", "fuzz"])
        return (
            "fast: httpx + subfinder + nmap top-100 + ffuf common + katana d=1 "
            "+ nuclei info/low/medium (20m/25 iter, parallel=4)"
        )

    if name == "standard":
        # Leave the user's YAML as-is — it's the reference profile.
        return "standard: as configured in YAML"

    if name == "deep":
        # Multi-hour thorough pass: full-port nmap on hosts with open 443,
        # bigger wordlists, katana depth 3, nuclei through medium (and high
        # when session.mode == aggressive AND the scope opts in).
        settings.session.wallclock_minutes = max(settings.session.wallclock_minutes, 180)
        settings.session.max_iterations = max(settings.session.max_iterations, 100)
        t("nmap").default_flags = ["-sV", "-Pn", "-p-", "-T3", "--min-rate", "500"]
        ffuf = t("ffuf")
        ffuf.enabled = True
        ffuf.extras.setdefault(
            "wordlist_big", "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
        )
        ffuf.extras["requests_per_second"] = max(int(ffuf.extras.get("requests_per_second", 10)), 15)
        t("katana").enabled = True
        t("katana").extras["depth"] = 3
        t("gobuster").enabled = True
        nuclei = t("nuclei")
        nuclei.enabled = True
        # "medium" is the highest we'll run in safe mode — keep dos/intrusive
        # exclusions on to stay inside UA's rules.
        if settings.session.mode == "aggressive":
            nuclei.extras["severity"] = "info,low,medium,high"
        else:
            nuclei.extras["severity"] = "info,low,medium"
        nuclei.extras.setdefault(
            "exclude_tags", ["dos", "intrusive", "fuzz", "rce", "sqli"]
        )
        return (
            "deep: full-port nmap + raft-large wordlists + katana d=3 + "
            "nuclei through medium (180m/100 iter)"
        )

    raise typer.BadParameter(f"unknown profile {name!r}; expected fast|standard|deep")


# ---------------------------------------------------------------------------
# CTF / lab posture — unlocks aggressive-class tools without per-target opt-in,
# relaxes RFC1918 scope guard (HTB/THM live in 10.10.x.x), bumps rate limits,
# and tells httpx to probe common non-default web ports. This is deliberately
# a separate gear above --profile; it applies on top of any profile.
# ---------------------------------------------------------------------------
def _apply_ctf_posture(settings: Settings) -> str:
    tools = settings.tools
    def t(tool_name):
        if tool_name not in tools:
            from .config import ToolConfig
            tools[tool_name] = ToolConfig()
        return tools[tool_name]

    settings.session.mode = "ctf"
    # Rate limits loosened — lab boxes aren't production
    settings.safety.per_host_rate_limit_rps = max(settings.safety.per_host_rate_limit_rps, 100)
    settings.safety.global_rate_limit_rps = max(settings.safety.global_rate_limit_rps, 500)
    # HTB/THM live in private ranges
    settings.safety.deny_private_ranges_unless_explicit = False
    # Wider nuclei sweep; drop the safe-mode exclusions except the truly
    # destructive ones (dos could brick a shared lab)
    nuclei = t("nuclei")
    nuclei.enabled = True
    nuclei.extras["severity"] = "info,low,medium,high,critical"
    nuclei.extras["exclude_tags"] = ["dos"]
    nuclei.extras["rate_limit"] = max(int(nuclei.extras.get("rate_limit", 50)), 150)
    # httpx: probe common non-default ports — lab webapps are often on 8080/8443
    t("httpx").extras["include_common_ports"] = True
    # sqlmap: on. Heuristic bypasses per-target opt-in in ctf mode (see heuristics.py)
    t("sqlmap").enabled = True
    # ffuf: bigger wordlist, more rps
    ffuf = t("ffuf")
    ffuf.enabled = True
    ffuf.extras.setdefault(
        "wordlist", "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
    )
    ffuf.extras["requests_per_second"] = max(int(ffuf.extras.get("requests_per_second", 50)), 50)
    # gobuster fallback still on
    t("gobuster").enabled = True
    # katana: depth 2, happy to parse JS
    katana = t("katana")
    katana.enabled = True
    katana.extras["depth"] = max(int(katana.extras.get("depth", 2)), 2)
    return (
        "ctf: mode=ctf, private ranges allowed, aggressive tools unlocked, "
        "httpx probes common ports, sqlmap auto-opt-in"
    )


app = typer.Typer(no_args_is_help=True, help="Authorized pentesting agent.")
console = Console()
logger = get_logger(__name__)


_BANNER = """\
──────────────────────────────────────────────────────────────────────────────
 pentagent — AI-assisted penetration testing agent
 AUTHORIZED USE ONLY. You are responsible for ensuring written permission
 to test every host listed in your scope file. Unauthorized testing is
 illegal in most jurisdictions and explicitly out of scope for this tool.
──────────────────────────────────────────────────────────────────────────────
"""


def _load(settings_path: Path, scope_path: Path) -> tuple[Settings, Scope]:
    if not settings_path.exists():
        raise typer.BadParameter(f"config not found: {settings_path}")
    if not scope_path.exists():
        raise typer.BadParameter(f"scope file not found: {scope_path}")
    return Settings.load(settings_path), Scope.load(scope_path)


@app.command()
def run(
    config: Path = typer.Option("config/config.yaml", "--config", "-c"),
    scope: Path = typer.Option("config/scope.yaml", "--scope", "-s"),
    target: list[str] = typer.Option(..., "--target", "-t", help="Seed target (URL, host, IP)"),
    i_have_authorization: bool = typer.Option(
        False,
        "--i-have-authorization",
        help="You attest you have written authorization for all targets in scope.",
    ),
    mode: str = typer.Option(None, "--mode", help="Override session.mode from config (safe|aggressive|ctf)"),
    profile: str = typer.Option(
        "standard",
        "--profile",
        help="Scan depth profile: fast (20m triage) | standard (as configured) | deep (multi-hour).",
    ),
    ctf: bool = typer.Option(
        False,
        "--ctf",
        help="CTF/lab posture: unlocks aggressive tools without per-target opt-in, "
             "allows RFC1918 targets, loosens rate limits. Use only on boxes you own "
             "or a platform you are actively playing (HTB, THM, labs).",
    ),
    parallel: int = typer.Option(
        None,
        "--parallel",
        help="Actions to run concurrently per iteration (default from config, usually 4).",
    ),
    log_level: str = typer.Option("INFO", "--log-level"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Build orchestrator but do not iterate."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM planner; pure heuristics."),
    resume: Path = typer.Option(
        None,
        "--resume",
        help="Resume an existing session directory: reuse its knowledge.db + "
             "audit.jsonl instead of creating a fresh session. The planner will "
             "dedupe against actions already recorded, so new work picks up where "
             "the previous run left off.",
    ),
) -> None:
    """Run the agent against one or more seed targets."""
    console.print(_BANNER, style="bold")
    configure_logging(log_level)

    if not i_have_authorization:
        console.print(
            "[bold red]refused:[/bold red] pass --i-have-authorization to attest you have "
            "written permission for every target in scope. pentagent will not run without it."
        )
        raise typer.Exit(code=2)

    settings, scope_obj = _load(config, scope)
    if mode:
        settings.session.mode = mode
    profile_desc = _apply_profile(settings, profile)
    console.print(f"[cyan]profile[/cyan] {profile_desc}")
    if ctf:
        ctf_desc = _apply_ctf_posture(settings)
        console.print(f"[cyan]posture[/cyan] {ctf_desc}")
    if parallel is not None:
        settings.session.parallel_actions = max(1, int(parallel))

    # Pre-flight: each seed target must pass scope
    from .safety import ScopeGuard, ScopeViolation
    guard = ScopeGuard(scope_obj, deny_private_unless_explicit=settings.safety.deny_private_ranges_unless_explicit)
    for t in target:
        try:
            guard.check(t)
        except ScopeViolation as e:
            console.print(f"[bold red]scope rejects seed target {t!r}:[/bold red] {e}")
            raise typer.Exit(code=3)

    # Session dir — either a fresh one or an existing dir being resumed
    if resume is not None:
        session_dir = resume
        if not session_dir.is_dir():
            console.print(f"[bold red]--resume: session dir not found: {session_dir}[/bold red]")
            raise typer.Exit(code=2)
        if not (session_dir / "knowledge.db").exists():
            console.print(
                f"[bold red]--resume: no knowledge.db inside {session_dir} — "
                f"can't resume what doesn't exist[/bold red]"
            )
            raise typer.Exit(code=2)
        console.print(f"[cyan]resuming session[/cyan] {session_dir}")
    else:
        stamp = dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        session_id = f"{stamp}_{secrets.token_hex(3)}"
        session_dir = Path(settings.output.dir) / session_id

    # LLM for planner & reporter
    planner_llm = None
    if not no_llm:
        try:
            planner_llm = build_client("planner", settings.llm)
        except Exception as e:
            console.print(f"[yellow]LLM unavailable; continuing with heuristics only ({e})[/yellow]")

    orchestrator = Orchestrator(
        settings=settings,
        scope=scope_obj,
        planner_llm=planner_llm,
        session_dir=session_dir,
        seed_targets=target,
        parallel_actions=settings.session.parallel_actions,
    )

    if dry_run:
        console.print("[yellow]dry-run: not iterating[/yellow]")
        orchestrator.close()
        return

    try:
        summary = orchestrator.run()
    finally:
        orchestrator.close()

    # Headline summary — formatted for fast human triage
    risk = summary.get("overall_risk", "INFORMATIONAL")
    risk_colour = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFORMATIONAL": "dim",
    }.get(risk, "dim")
    console.print()
    console.print(f"[bold green]═══ session complete ═══[/bold green]")
    console.print(f"  reason: {summary.get('reason', 'unknown')}")
    console.print(f"  last phase: {summary.get('last_phase', '?')}")
    console.print(f"  overall risk: [{risk_colour}]{risk}[/{risk_colour}]")
    sev = summary.get("severity_breakdown", {})
    if sev:
        parts = [f"{k}={v}" for k, v in sev.items() if v]
        if parts:
            console.print(f"  findings: {', '.join(parts)}")
    console.print(
        f"  graph: {summary.get('hosts', 0)} host(s), "
        f"{summary.get('endpoints', 0)} endpoint(s), "
        f"{summary.get('findings', 0)} finding(s)"
    )
    for kind, p in (summary.get("report_artifacts") or {}).items():
        console.print(f"  deterministic {kind}: [dim]{p}[/dim]")
    console.print()

    # Auto-generate report
    reporter_llm = None
    if not no_llm:
        try:
            reporter_llm = build_client("reporter", settings.llm)
        except Exception:
            pass
    from .memory import KnowledgeStore
    store = KnowledgeStore(session_dir / "knowledge.db")
    reporter = Reporter(
        store=store,
        session_dir=session_dir,
        llm=reporter_llm,
        program_name=scope_obj.program_name or "",
        authorized_by=scope_obj.authorized_by or "",
        authorized_on=scope_obj.authorized_on or "",
        operator=scope_obj.operator or "",
        seed_targets=list(target),
        session_mode=settings.session.mode,
    )
    written = reporter.generate(formats=settings.output.report_format)
    for kind, p in written.items():
        console.print(f"[bold]report[/bold] ({kind}): {p}")
    store.close()


@app.command()
def report(
    session: Path = typer.Option(..., "--session", "-s"),
    config: Path = typer.Option("config/config.yaml", "--config", "-c"),
    scope: Path = typer.Option(None, "--scope", help="Optional scope file to stamp the report header."),
    no_llm: bool = typer.Option(False, "--no-llm"),
    formats: str = typer.Option(
        "",
        "--formats",
        help="Comma-separated output formats (markdown,json,html). Default from config.",
    ),
) -> None:
    """Re-generate the report for an existing session."""
    configure_logging("INFO")
    settings = Settings.load(config)
    llm = None
    if not no_llm:
        try:
            llm = build_client("reporter", settings.llm)
        except Exception as e:
            console.print(f"[yellow]LLM unavailable ({e})[/yellow]")
    scope_obj = Scope.load(scope) if scope else None
    from .memory import KnowledgeStore
    store = KnowledgeStore(session / "knowledge.db")
    reporter = Reporter(
        store=store,
        session_dir=session,
        llm=llm,
        program_name=(scope_obj.program_name if scope_obj else "") or "",
        authorized_by=(scope_obj.authorized_by if scope_obj else "") or "",
        authorized_on=(scope_obj.authorized_on if scope_obj else "") or "",
        operator=(scope_obj.operator if scope_obj else "") or "",
        session_mode=settings.session.mode,
    )
    fmt_list = [f.strip() for f in formats.split(",") if f.strip()] or settings.output.report_format
    written = reporter.generate(formats=fmt_list)
    for kind, p in written.items():
        console.print(f"[bold]{kind}[/bold]: {p}")
    store.close()


@app.command()
def status(session: Path = typer.Argument(..., help="path to a session directory")) -> None:
    """Print a dashboard summary of a completed or in-flight session.

    Read-only: inspects knowledge.db + audit.jsonl + report artifacts and
    reports overall risk, severity breakdown, tool inventory, phase
    progression, and elapsed time. Handy for reviewing a past run without
    re-running anything.
    """
    import json as _json
    from collections import Counter
    if not session.exists() or not session.is_dir():
        console.print(f"[red]session dir not found: {session}[/red]")
        raise typer.Exit(code=1)

    kdb = session / "knowledge.db"
    audit_path = session / "audit.jsonl"
    if not kdb.exists():
        console.print(f"[red]no knowledge.db at {kdb}[/red]")
        raise typer.Exit(code=1)

    from .memory import KnowledgeStore
    store = KnowledgeStore(kdb)
    try:
        hosts = store.hosts()
        webapps = store.webapps()
        endpoints = store.endpoints()
        services = store.services()
        findings = store.findings()
    finally:
        store.close()

    # Severity breakdown
    sev_counts: Counter[str] = Counter()
    for f in findings:
        v = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_counts[v] += 1
    overall = "INFORMATIONAL"
    for s in ("critical", "high", "medium", "low"):
        if sev_counts.get(s, 0) > 0:
            overall = s.upper()
            break
    risk_colour = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFORMATIONAL": "dim",
    }.get(overall, "dim")

    # Audit timeline → tool runs + phase transitions + session bounds
    tool_counts: Counter[str] = Counter()
    phases_seen: list[str] = []
    session_start = None
    session_end = None
    session_reason = None
    if audit_path.exists():
        for line in audit_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = _json.loads(line)
            except Exception:
                continue
            evt = rec.get("event", "")
            data = rec.get("data", {})
            if evt == "session_start":
                session_start = rec.get("ts") or data.get("ts")
            elif evt == "session_end":
                session_end = rec.get("ts") or data.get("ts")
                session_reason = data.get("reason")
            elif evt == "iter_summary":
                tool = (data.get("action") or {}).get("tool", "")
                if tool:
                    tool_counts[tool] += 1
            elif evt == "phase_transition":
                to_ph = data.get("to", "")
                if to_ph and (not phases_seen or phases_seen[-1] != to_ph):
                    phases_seen.append(to_ph)

    # Render
    console.print()
    console.print(f"[bold green]═══ session status: {session.name} ═══[/bold green]")
    console.print(f"  overall risk: [{risk_colour}]{overall}[/{risk_colour}]")
    if sev_counts:
        parts = [f"{k}={v}" for k, v in sev_counts.items() if v]
        if parts:
            console.print(f"  findings: {', '.join(parts)}")
    console.print(
        f"  graph: {len(hosts)} host(s), {len(webapps)} webapp(s), "
        f"{len(endpoints)} endpoint(s), {len(services)} service(s), "
        f"{len(findings)} finding(s)"
    )
    if phases_seen:
        console.print(f"  phases: {' → '.join(phases_seen)}")
    if tool_counts:
        console.print(f"  tool inventory:")
        for tool, n in tool_counts.most_common():
            console.print(f"    [dim]•[/dim] {tool:<12} [cyan]{n}[/cyan]")
    if session_start and session_end:
        try:
            elapsed = float(session_end) - float(session_start)
            console.print(f"  elapsed: {elapsed/60:.1f} minute(s)")
        except Exception:
            pass
    if session_reason:
        console.print(f"  stop reason: {session_reason}")

    # Report artifacts
    artifacts = []
    for kind, name in [("markdown", "report.md"), ("json", "report.json"), ("html", "report.html")]:
        p = session / name
        if p.exists():
            artifacts.append((kind, p))
    if artifacts:
        console.print(f"  report artifacts:")
        for kind, p in artifacts:
            console.print(f"    [dim]•[/dim] {kind:<8} [dim]{p}[/dim]")
    else:
        console.print(f"  [dim]no report artifacts — run `pentagent report --session {session}` to generate[/dim]")

    # Top-3 findings preview
    if findings:
        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        top = sorted(findings, key=lambda f: (
            _sev_order.get(f.severity.value if hasattr(f.severity, "value") else str(f.severity), 99),
            -f.confidence,
        ))[:3]
        console.print(f"  top findings:")
        for f in top:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            console.print(f"    [dim]•[/dim] [{sev.upper()}] {f.title}")
    console.print()


@app.command("verify-audit")
def verify_audit(session: Path = typer.Option(..., "--session", "-s")) -> None:
    """Verify the hash chain of a session's audit.jsonl."""
    path = session / "audit.jsonl"
    if not path.exists():
        console.print(f"[red]no audit log at {path}[/red]")
        raise typer.Exit(code=1)
    log = AuditLog(path)
    ok, n = log.verify()
    if ok:
        console.print(f"[green]audit OK — {n} records[/green]")
    else:
        console.print(f"[bold red]audit chain BROKEN at record {n}[/bold red]")
        raise typer.Exit(code=1)


@app.command("list-tools")
def list_tools() -> None:
    """List every registered tool and its category."""
    for name in default_registry.names():
        inst = default_registry.get(name)
        spec = inst.spec
        console.print(
            f"  [bold]{spec.name:<12}[/bold] binary={spec.binary:<10} "
            f"category={spec.category} modes={spec.supports_modes}"
        )


def main() -> None:  # pragma: no cover
    try:
        app()
    except KeyboardInterrupt:
        console.print("[yellow]interrupted[/yellow]")
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
