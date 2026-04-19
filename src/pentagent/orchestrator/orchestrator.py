"""The central loop: observe → plan → act → parse → update → iterate.

Keeps no state of its own — everything observable is in the KnowledgeStore
and everything recorded is in the AuditLog. That makes a session
resumable and fully reproducible from disk.

**Concurrency model.** Each iteration picks up to `parallel_actions`
signature-distinct candidates and dispatches them through a thread pool.
Subprocess tool runs are overwhelmingly I/O-bound (waiting on nmap/nuclei
to finish their own work), so threads give near-linear speedup without
touching the GIL. Safety layers are inside `Executor.run()` and are
thread-safe (AuditLog and RateLimiter both hold their own locks).

**Stall detection.** If `stall_patience` consecutive iterations commit
zero new entities AND produce no new candidates, the session ends with
`stop_reason='no_progress'` rather than burning wallclock on identical
nuclei sweeps.

**Cache handling.** Cache hits return a ToolResult with `argv=[]`; we
skip parse+commit for those so an empty stdout doesn't churn the DB or
drown the logs in `committed 0` lines.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Settings
from ..llm import LLMClient
from ..logging_setup import get_logger
from ..memory import Host, KnowledgeStore, Observation, WebApp
from ..parsers import parse_for
from ..safety import AuditLog, RateLimiter, Scope, ScopeGuard
from ..safety.scope import ScopeViolation
from ..strategy import Action, HeuristicPlanner, HybridPlanner, LLMPlanner
from ..strategy.phases import Phase, dominant_phase, phase_of
from ..knowledge import map_tool
from ..enrichment import CVEEnricher, enrich_webapps_and_services
from ..tools import Executor, ExecutionError, default_registry


logger = get_logger(__name__)


@dataclass
class SessionBudget:
    max_iterations: int
    wallclock_seconds: int
    max_cost_usd: float
    started_at: float = field(default_factory=time.time)
    iterations: int = 0
    spent_usd: float = 0.0

    def tick(self, n: int = 1) -> None:
        self.iterations += n

    def wall_remaining(self) -> float:
        return self.wallclock_seconds - (time.time() - self.started_at)

    def exhausted(self) -> tuple[bool, str]:
        if self.iterations >= self.max_iterations:
            return True, "max_iterations"
        if self.wall_remaining() <= 0:
            return True, "wallclock"
        if self.spent_usd >= self.max_cost_usd > 0:
            return True, "cost_cap"
        return False, ""

    def snapshot(self) -> dict:
        return {
            "iterations": self.iterations,
            "wall_remaining_s": round(self.wall_remaining(), 1),
            "spent_usd": round(self.spent_usd, 4),
            "max_iterations": self.max_iterations,
            "max_cost_usd": self.max_cost_usd,
        }


class Orchestrator:
    def __init__(
        self,
        *,
        settings: Settings,
        scope: Scope,
        planner_llm: LLMClient | None,
        session_dir: Path,
        seed_targets: list[str],
        parallel_actions: int | None = None,
        stall_patience: int = 3,
    ) -> None:
        self.settings = settings
        self.scope = scope
        self.session_dir = session_dir
        self.seed_targets = seed_targets
        self.parallel_actions = int(
            parallel_actions if parallel_actions is not None
            else getattr(settings.session, "parallel_actions", 4) or 4
        )
        self.stall_patience = int(stall_patience)

        session_dir.mkdir(parents=True, exist_ok=True)
        self.store = KnowledgeStore(session_dir / "knowledge.db")
        self.audit = AuditLog(session_dir / "audit.jsonl")
        self.rate_limiter = RateLimiter(
            per_host_rps=settings.safety.per_host_rate_limit_rps,
            global_rps=settings.safety.global_rate_limit_rps,
        )
        self.scope_guard = ScopeGuard(
            scope,
            deny_private_unless_explicit=settings.safety.deny_private_ranges_unless_explicit,
        )
        self.executor = Executor(
            registry=default_registry,
            scope_guard=self.scope_guard,
            rate_limiter=self.rate_limiter,
            audit=self.audit,
            store=self.store,
            session_mode=settings.session.mode,
        )
        heuristics = HeuristicPlanner(settings, scope)
        llm_planner = LLMPlanner(llm=planner_llm) if planner_llm else None
        self.planner = HybridPlanner(heuristics=heuristics, llm_planner=llm_planner)

        self.budget = SessionBudget(
            max_iterations=settings.session.max_iterations,
            wallclock_seconds=settings.session.wallclock_minutes * 60,
            max_cost_usd=settings.session.max_cost_usd,
        )

        # CVE enrichment — one instance per session, cached on disk so
        # repeated iterations against the same tech don't burn NVD quota.
        import os
        api_key_env = settings.enrichment.cve.api_key_env
        api_key = os.environ.get(api_key_env) if api_key_env else None
        self.cve_enricher = CVEEnricher(
            cache_path=session_dir / "cve_cache.json",
            enabled=settings.enrichment.cve.enabled,
            timeout_s=settings.enrichment.cve.timeout_s,
            min_cvss=settings.enrichment.cve.min_cvss,
            api_key=api_key,
        )
        # Per-session dedup so we don't re-file the same CVE finding each iter
        self._cve_seen: set[str] = set()

        # Tools whose binary is missing get marked dead for the rest of the
        # session. Otherwise the planner proposes them every iteration, we
        # burn a thread-pool slot to fail fast, and the log fills with
        # identical warnings. Stops the "katana failed x6" noise.
        self._dead_tools: set[str] = set()

        # Authorization banner — burned into the audit log
        self.audit.log(
            "session_start",
            {
                "program_name": scope.program_name,
                "authorized_by": scope.authorized_by,
                "authorized_on": scope.authorized_on,
                "authorization_source": scope.authorization_source,
                "operator": scope.operator,
                "seed_targets": seed_targets,
                "mode": settings.session.mode,
                "session_dir": str(session_dir),
                "parallel_actions": self.parallel_actions,
            },
        )

    # ---------------------------------------------------------------- close
    def close(self) -> None:
        self.store.close()

    # ------------------------------------------------------------ bootstrap
    def _bootstrap_seeds(self) -> None:
        """Seed the knowledge graph with the Hosts/WebApps implied by the
        user-supplied seed targets. Without this, a leaf subdomain with no
        subfinder hits would leave the graph empty and the planner idle.

        For each seed we also attempt DNS resolution. Resolved IPs are
        recorded for reporting regardless of scope, but the planner will
        only schedule tools on IPs that pass ScopeGuard — out-of-scope IPs
        are annotated as "observed, not probed".
        """
        from urllib.parse import urlparse
        import socket

        obs = Observation(
            source_tool="bootstrap",
            notes="seed bootstrap: Host/WebApp for every --target plus DNS-resolved IPs",
        )
        seen_host_keys: set[tuple[str, str]] = set()

        for t in self.seed_targets:
            t = t.strip()
            if not t:
                continue
            if "://" in t:
                p = urlparse(t)
                scheme = p.scheme if p.scheme in ("http", "https") else "https"
                hostname = (p.hostname or "").lower()
                port = p.port
            else:
                scheme = "https"
                hostname = t.split("/", 1)[0].split(":", 1)[0].lower()
                port = None
            if not hostname:
                continue
            base_url = f"{scheme}://{hostname}" + (
                f":{port}" if port and port not in (80, 443) else ""
            )

            # Host for the hostname itself
            key = ("", hostname)
            if key not in seen_host_keys:
                seen_host_keys.add(key)
                obs.hosts.append(Host(hostname=hostname))
                host_ph = -(len(obs.hosts))
            else:
                host_ph = -(list(seen_host_keys).index(key) + 1)

            obs.webapps.append(
                WebApp(host_id=host_ph, scheme=scheme, base_url=base_url)
            )

            # DNS resolve — best-effort
            resolved: set[str] = set()
            try:
                for info in socket.getaddrinfo(hostname, None):
                    ip = info[4][0]
                    resolved.add(ip.split("%", 1)[0])
            except (socket.gaierror, UnicodeError, OSError) as e:
                logger.debug(f"DNS resolve failed for {hostname}: {e}")

            for ip in sorted(resolved):
                k = (ip, hostname)
                if k in seen_host_keys:
                    continue
                seen_host_keys.add(k)
                try:
                    self.scope_guard.check(ip)
                    obs.hosts.append(Host(ip=ip, hostname=hostname))
                except ScopeViolation:
                    obs.hosts.append(
                        Host(ip=ip, hostname=hostname, os_guess="OOS (resolved only)")
                    )

        counts = self.store.commit(obs)
        self.audit.log(
            "bootstrap",
            {"seeds": self.seed_targets, "committed": counts},
        )
        logger.info(
            f"[bold]bootstrap[/bold] seeds → {counts['hosts']} host(s), "
            f"{counts['webapps']} webapp(s) in graph"
        )

    # ---------------------------------------------------------------- loop
    def run(self) -> dict[str, Any]:
        logger.info(f"[bold green]pentagent[/bold green] starting session {self.session_dir.name}")
        logger.info(
            f"[bold]program[/bold]={self.scope.program_name} "
            f"[bold]mode[/bold]={self.settings.session.mode} "
            f"[bold]parallel[/bold]={self.parallel_actions}"
        )
        self._bootstrap_seeds()
        stop_reason = "unknown"
        stall_counter = 0
        current_phase: Phase = Phase.recon
        phase_entity_counts: dict[str, dict[str, int]] = {}
        report_artifacts: dict = {}
        try:
            while True:
                exhausted, why = self.budget.exhausted()
                if exhausted:
                    stop_reason = why
                    break

                candidates = self.planner.propose(
                    self.store, self.seed_targets, budget=self.budget.snapshot()
                )
                if not candidates:
                    stop_reason = "no_more_actions"
                    break

                # Emit a phase-transition audit record if the dominant phase
                # in the candidate pool has advanced since last iteration.
                # This is observability — it does not gate execution.
                dom = dominant_phase(candidates)
                if dom > current_phase:
                    self.audit.log(
                        "phase_transition",
                        {"from": current_phase.label, "to": dom.label,
                         "candidates": len(candidates)},
                    )
                    logger.info(
                        f"[bold cyan]phase →[/bold cyan] "
                        f"{current_phase.label} → {dom.label}"
                    )
                    current_phase = dom

                # Pick a batch of signature-distinct candidates to run in
                # parallel. Planner already dedupes against the action_log;
                # this extra pass keeps sibling duplicates from sneaking in
                # AND filters out tools we've proved dead this session.
                batch: list[Action] = []
                sigs: set[str] = set()
                skipped_dead: list[str] = []
                for a in candidates:
                    if len(batch) >= self.parallel_actions:
                        break
                    if a.tool in self._dead_tools:
                        skipped_dead.append(a.tool)
                        continue
                    s = a.signature()
                    if s in sigs:
                        continue
                    sigs.add(s)
                    batch.append(a)
                if skipped_dead:
                    logger.debug(f"skipped dead tools: {sorted(set(skipped_dead))}")

                iter_start_total = len(self.store.hosts()) + len(self.store.webapps()) + \
                                   len(self.store.endpoints()) + len(self.store.findings()) + \
                                   len(self.store.services())

                counts_total = self._execute_batch(batch)
                self.budget.tick(len(batch))

                # Post-batch enrichment: match new tech fingerprints against
                # NVD. Runs once per iteration, not per tool, so one NVD
                # round-trip covers any webapp/service discoveries made in
                # this batch. Network failures are absorbed silently.
                self._run_cve_enrichment()

                # Stall detection: compare graph totals before/after.
                iter_end_total = len(self.store.hosts()) + len(self.store.webapps()) + \
                                 len(self.store.endpoints()) + len(self.store.findings()) + \
                                 len(self.store.services())
                if iter_end_total == iter_start_total:
                    stall_counter += 1
                    logger.info(f"[dim]no new entities this iteration ({stall_counter}/{self.stall_patience})[/dim]")
                    if stall_counter >= self.stall_patience:
                        stop_reason = "no_progress"
                        break
                else:
                    stall_counter = 0

        except KeyboardInterrupt:
            stop_reason = "user_interrupt"
            logger.warning("[bold red]interrupted — shutting down cleanly[/bold red]")
        finally:
            self.audit.log(
                "session_end",
                {
                    "reason": stop_reason,
                    "budget": self.budget.snapshot(),
                    "last_phase": current_phase.label,
                },
            )
            # Final phase: report. Runs even on interrupt so partial work
            # is captured as a deliverable rather than lost. Failures are
            # logged but never abort shutdown — the knowledge DB is always
            # the source of truth and a later `pentagent report` can retry.
            report_artifacts = self._auto_report()

        summary = {
            "reason": stop_reason,
            "budget": self.budget.snapshot(),
            "findings": len(self.store.findings()),
            "endpoints": len(self.store.endpoints()),
            "hosts": len(self.store.hosts()),
            "last_phase": current_phase.label,
            "report_artifacts": {k: str(v) for k, v in (report_artifacts or {}).items()},
        }
        # Headline summary — by severity breakdown + risk
        breakdown = self._severity_breakdown()
        summary["severity_breakdown"] = breakdown
        summary["overall_risk"] = self._overall_risk_label()
        return summary

    # -------------------------------------------------------------- report
    def _auto_report(self) -> dict[str, Path]:
        """Transition to the report phase and write markdown + json + html
        to the session directory. Exceptions are swallowed so a reporting
        bug can't corrupt a completed scan."""
        try:
            from ..reporting import Reporter
        except Exception as e:
            logger.debug(f"reporter unavailable: {e}")
            return {}
        self.audit.log(
            "phase_transition",
            {"from": "exploit", "to": "report", "driver": "session_end"},
        )
        try:
            reporter = Reporter(
                store=self.store,
                session_dir=self.session_dir,
                llm=None,   # final deterministic pass; LLM polish is opt-in via `pentagent report`
                program_name=getattr(self.scope, "program_name", ""),
                authorized_by=getattr(self.scope, "authorized_by", ""),
                authorized_on=getattr(self.scope, "authorized_on", ""),
                operator=getattr(self.scope, "operator", ""),
                seed_targets=list(self.seed_targets),
                session_mode=self.settings.session.mode,
            )
            artifacts = reporter.generate(formats=["markdown", "json", "html"])
            for kind, path in artifacts.items():
                logger.info(f"[bold cyan]report[/bold cyan] {kind} → {path}")
            self.audit.log(
                "report_written",
                {k: str(v) for k, v in artifacts.items()},
            )
            return artifacts
        except Exception as e:
            logger.warning(f"[yellow]auto-report failed:[/yellow] {e}")
            self.audit.log("report_error", {"error": str(e)})
            return {}

    def _severity_breakdown(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.store.findings():
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _overall_risk_label(self) -> str:
        b = self._severity_breakdown()
        for sev in ("critical", "high", "medium", "low"):
            if b.get(sev, 0) > 0:
                return sev.upper()
        return "INFORMATIONAL"

    # ---------------------------------------------------------------- batch
    def _execute_batch(self, batch: list[Action]) -> dict[str, int]:
        """Run a set of independent actions concurrently. Each is:
           execute → parse → commit (under lock, inside KnowledgeStore)."""
        if not batch:
            return {}

        # Announce the whole batch up-front so the log reads naturally.
        for a in batch:
            logger.info(
                f"[bold]iter {self.budget.iterations + 1}+[/bold] → "
                f"{a.tool} phase={a.phase().label} "
                f"priority={a.priority} reason={a.reason!r}"
            )

        totals: dict[str, int] = {}
        with ThreadPoolExecutor(max_workers=max(1, len(batch))) as pool:
            futures: list[tuple[Action, Future]] = []
            for a in batch:
                timeout = int(self.settings.tool(a.tool).timeout_seconds)
                futures.append((a, pool.submit(self._run_one, a, timeout)))

            for a, fut in futures:
                try:
                    counts = fut.result()
                except Exception as e:
                    err_msg = str(e)
                    logger.warning(f"[yellow]{a.tool} failed:[/yellow] {err_msg}")
                    self.audit.log(
                        "iter_error", {"action": {"tool": a.tool, "params": a.params}, "error": err_msg}
                    )
                    # Permanent failures: mark the tool dead so we stop
                    # re-proposing it. Anything involving missing binaries,
                    # unknown tools, or unsupported modes is never going to
                    # fix itself mid-session.
                    lowered = err_msg.lower()
                    if any(phrase in lowered for phrase in (
                        "not found in path", "unknown tool", "does not support mode",
                    )):
                        if a.tool not in self._dead_tools:
                            self._dead_tools.add(a.tool)
                            logger.info(
                                f"[dim]  {a.tool} marked dead for session "
                                f"(will not be re-proposed)[/dim]"
                            )
                            self.audit.log(
                                "tool_dead",
                                {"tool": a.tool, "reason": err_msg},
                            )
                    # Record the attempt in the action log so signature dedupe
                    # catches it too — belt-and-suspenders defense against
                    # LLM re-proposals with slightly different params.
                    try:
                        import json as _json, time as _t
                        self.store.record_action(
                            tool=a.tool,
                            params_json=_json.dumps(a.params, sort_keys=True, default=str),
                            started_at=_t.time(),
                            finished_at=_t.time(),
                            exit_code=-1,
                            cache_key=f"FAILED::{a.tool}::{a.signature()}",
                        )
                    except Exception:
                        pass
                    continue
                for k, v in counts.items():
                    totals[k] = totals.get(k, 0) + v
        return totals

    def _run_cve_enrichment(self) -> None:
        """Post-batch pass: match current tech against NVD. Findings are
        committed alongside normal observations so the report consumes them
        uniformly. Failures are soft — offline runs get zero CVEs, not an
        exception."""
        if not self.cve_enricher.enabled:
            return
        try:
            obs, self._cve_seen = enrich_webapps_and_services(
                self.store, self.cve_enricher, already_seen=self._cve_seen,
            )
        except Exception as e:
            logger.debug(f"cve enrichment pass failed: {e}")
            return
        if obs.findings:
            counts = self.store.commit(obs)
            logger.info(
                f"[cyan]  cve-enricher committed[/cyan] {counts['findings']} CVE "
                f"finding(s) across {counts['evidence']} evidence record(s)"
            )
            self.audit.log(
                "cve_enrichment",
                {
                    "committed": {
                        "findings": counts["findings"],
                        "evidence": counts["evidence"],
                    },
                    "cache_hits_total": len(self._cve_seen),
                },
            )

    def _run_one(self, action: Action, timeout: int) -> dict[str, int]:
        """Execute a single action: exec → parse → commit → return counts.
        Runs inside the thread pool; must not touch orchestrator mutable
        state directly — only the KnowledgeStore (which locks internally)."""
        result = self.executor.run(action.tool, action.params, timeout=timeout)
        attack = map_tool(action.tool)
        self.audit.log(
            "iter_summary",
            {
                "action": {
                    "tool": action.tool,
                    "phase": action.phase().label,
                    "params": action.params,
                    "reason": action.reason,
                    "mitre": {
                        "tactic_id": attack["tactic_id"],
                        "tactic": attack["tactic"],
                        "techniques": list(attack["techniques"]),
                    },
                },
                "result": result.summary(),
            },
        )

        # Cache hit: executor returns argv=[] as the marker. No parsing.
        if not result.argv:
            logger.info(f"[dim]  {action.tool} cache hit — skipping parse[/dim]")
            return {}

        # Empty stdout from a successful exec is usually a signal: wrong
        # scheme, unreachable host, misconfigured VPN. Surface it.
        if result.exit_code == 0 and not result.stdout.strip():
            stderr_tail = (result.stderr or "").strip().splitlines()[-3:]
            logger.warning(
                f"[yellow]{action.tool} produced no stdout[/yellow] "
                f"(exit=0, duration={result.duration_s:.1f}s). "
                f"stderr tail: {stderr_tail!r}"
            )

        try:
            obs = parse_for(action.tool, result, action.parser_context)
        except Exception as e:
            logger.warning(f"parse failed for {action.tool}: {e}")
            obs = Observation(source_tool=action.tool, raw_excerpt=result.stdout[:2000])

        counts = self.store.commit(obs)
        logger.info(
            f"[green]  {action.tool} committed[/green] {counts}  "
            f"(excerpt_len={len(obs.raw_excerpt or '')})"
        )
        return counts
