"""The central loop: observe → plan → act → parse → update → iterate.

Keeps no state of its own — everything observable is in the KnowledgeStore
and everything recorded is in the AuditLog. That makes a session
resumable and fully reproducible from disk.
"""
from __future__ import annotations

import time
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

    def tick(self) -> None:
        self.iterations += 1

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
    ) -> None:
        self.settings = settings
        self.scope = scope
        self.session_dir = session_dir
        self.seed_targets = seed_targets

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
                # find existing placeholder
                host_ph = -(list(seen_host_keys).index(key) + 1)

            # WebApp only if the seed looks web-oriented
            obs.webapps.append(
                WebApp(host_id=host_ph, scheme=scheme, base_url=base_url)
            )

            # DNS resolve — best-effort, 2s timeout via socket default
            resolved: set[str] = set()
            try:
                for info in socket.getaddrinfo(hostname, None):
                    ip = info[4][0]
                    # strip zone id on link-local
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
                    # In scope → will be probe-eligible
                    obs.hosts.append(Host(ip=ip, hostname=hostname))
                except ScopeViolation:
                    # Record it for the report, but mark os_guess so the
                    # planner's _in_scope check is the one that filters it
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
            f"[bold]mode[/bold]={self.settings.session.mode}"
        )
        self._bootstrap_seeds()
        stop_reason = "unknown"
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

                action = candidates[0]
                logger.info(
                    f"[bold]iter {self.budget.iterations + 1}[/bold]: {action.tool} "
                    f"priority={action.priority} reason={action.reason!r}"
                )
                try:
                    self._execute(action)
                except ExecutionError as e:
                    logger.warning(f"execution failed: {e}")
                    self.audit.log(
                        "iter_error", {"action": action.__dict__, "error": str(e)}
                    )
                self.budget.tick()
        except KeyboardInterrupt:
            stop_reason = "user_interrupt"
            logger.warning("[bold red]interrupted — shutting down cleanly[/bold red]")
        finally:
            self.audit.log(
                "session_end",
                {"reason": stop_reason, "budget": self.budget.snapshot()},
            )
        return {
            "reason": stop_reason,
            "budget": self.budget.snapshot(),
            "findings": len(self.store.findings()),
            "endpoints": len(self.store.endpoints()),
            "hosts": len(self.store.hosts()),
        }

    # ---------------------------------------------------------------- step
    def _execute(self, action: Action) -> None:
        timeout = int(self.settings.tool(action.tool).timeout_seconds)
        result = self.executor.run(action.tool, action.params, timeout=timeout)
        self.audit.log(
            "iter_summary",
            {
                "action": {"tool": action.tool, "params": action.params, "reason": action.reason},
                "result": result.summary(),
            },
        )

        # Parse -> Observation -> commit
        try:
            obs = parse_for(action.tool, result, action.parser_context)
        except Exception as e:
            logger.warning(f"parse failed for {action.tool}: {e}")
            obs = Observation(source_tool=action.tool, raw_excerpt=result.stdout[:2000])

        counts = self.store.commit(obs)
        logger.info(
            f"[green]  committed[/green] {counts}  (excerpt_len={len(obs.raw_excerpt or '')})"
        )
