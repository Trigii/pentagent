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
        # 15-min triage: only the fastest recon. No content discovery, no
        # crawling, minimal nuclei, top-100 port scan. Good for a smoke test.
        settings.session.wallclock_minutes = min(settings.session.wallclock_minutes, 15)
        settings.session.max_iterations = min(settings.session.max_iterations, 15)
        t("nmap").default_flags = ["-sV", "-Pn", "--top-ports", "100", "-T4"]
        nuclei = t("nuclei")
        nuclei.enabled = True
        nuclei.extras["severity"] = "info,low"
        nuclei.extras["rate_limit"] = 40
        t("ffuf").enabled = False
        t("gobuster").enabled = False
        t("katana").enabled = False
        t("nikto").enabled = False
        return "fast: httpx + subfinder + nmap top-100 + nuclei info/low (15m/15 iter)"

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
    mode: str = typer.Option(None, "--mode", help="Override session.mode from config (safe|aggressive)"),
    profile: str = typer.Option(
        "standard",
        "--profile",
        help="Scan depth profile: fast (15m triage) | standard (as configured) | deep (multi-hour).",
    ),
    log_level: str = typer.Option("INFO", "--log-level"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Build orchestrator but do not iterate."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM planner; pure heuristics."),
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

    # Pre-flight: each seed target must pass scope
    from .safety import ScopeGuard, ScopeViolation
    guard = ScopeGuard(scope_obj, deny_private_unless_explicit=settings.safety.deny_private_ranges_unless_explicit)
    for t in target:
        try:
            guard.check(t)
        except ScopeViolation as e:
            console.print(f"[bold red]scope rejects seed target {t!r}:[/bold red] {e}")
            raise typer.Exit(code=3)

    # Session dir
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
    )

    if dry_run:
        console.print("[yellow]dry-run: not iterating[/yellow]")
        orchestrator.close()
        return

    try:
        summary = orchestrator.run()
    finally:
        orchestrator.close()
    console.print(f"[bold green]session complete:[/bold green] {summary}")

    # Auto-generate report
    reporter_llm = None
    if not no_llm:
        try:
            reporter_llm = build_client("reporter", settings.llm)
        except Exception:
            pass
    from .memory import KnowledgeStore
    store = KnowledgeStore(session_dir / "knowledge.db")
    reporter = Reporter(store=store, session_dir=session_dir, llm=reporter_llm)
    written = reporter.generate(formats=settings.output.report_format)
    for kind, p in written.items():
        console.print(f"[bold]report[/bold] ({kind}): {p}")
    store.close()


@app.command()
def report(
    session: Path = typer.Option(..., "--session", "-s"),
    config: Path = typer.Option("config/config.yaml", "--config", "-c"),
    no_llm: bool = typer.Option(False, "--no-llm"),
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
    from .memory import KnowledgeStore
    store = KnowledgeStore(session / "knowledge.db")
    reporter = Reporter(store=store, session_dir=session, llm=llm)
    written = reporter.generate(formats=settings.output.report_format)
    for kind, p in written.items():
        console.print(f"[bold]{kind}[/bold]: {p}")
    store.close()


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
