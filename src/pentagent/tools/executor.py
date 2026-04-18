"""Process executor with scope + rate-limit + mode enforcement.

Every tool run flows through this single choke point:

    executor.run(tool_name, params)

Before spawning anything it:
  - resolves the Tool from the registry
  - extracts targets and runs them past ScopeGuard
  - checks the session mode against the tool's required mode
  - consults the rate limiter per-host
  - checks the cache (skip if we've already run an identical invocation)

It logs the full argv, exit code, and a stdout/stderr excerpt to the
audit log. Nothing is executed that doesn't pass these checks.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..logging_setup import get_logger
from ..memory import KnowledgeStore
from ..safety import AuditLog, RateLimiter, ScopeGuard, ScopeViolation
from .base import Mode, Tool, ToolResult
from .registry import ToolRegistry


logger = get_logger(__name__)


class ExecutionError(RuntimeError):
    pass


class Executor:
    def __init__(
        self,
        *,
        registry: ToolRegistry,
        scope_guard: ScopeGuard,
        rate_limiter: RateLimiter,
        audit: AuditLog,
        store: KnowledgeStore,
        session_mode: Mode = "safe",
        default_timeout: int = 300,
    ) -> None:
        self.registry = registry
        self.scope = scope_guard
        self.rate_limiter = rate_limiter
        self.audit = audit
        self.store = store
        self.session_mode = session_mode
        self.default_timeout = default_timeout

    # ------------------------ public ------------------------------------

    def run(
        self,
        tool_name: str,
        params: dict[str, Any],
        *,
        timeout: int | None = None,
    ) -> ToolResult:
        tool = self.registry.get(tool_name)

        # 1. Scope check
        required_mode = tool.mode_required(params)
        aggressive = required_mode == "aggressive"
        self._scope_check(tool, params, aggressive=aggressive)

        # 2. Mode gate. "ctf" mode is a superset of "aggressive" for gating
        # purposes — labs/CTF targets are owned by the operator and
        # destructive tools are acceptable without per-target opt-in.
        elevated_session = self.session_mode in ("aggressive", "ctf")
        if aggressive and not elevated_session and not tool.spec.bypasses_mode_gate:
            self._audit_reject(tool, params, reason="mode_gate_denied")
            raise ExecutionError(
                f"tool {tool.name} requires aggressive mode but session is {self.session_mode!r}"
            )
        if required_mode not in tool.spec.supports_modes:
            raise ExecutionError(
                f"tool {tool.name} does not support mode {required_mode!r}"
            )

        # 3. Binary exists?
        if not shutil.which(tool.spec.binary):
            self._audit_reject(tool, params, reason="binary_missing")
            raise ExecutionError(
                f"required binary {tool.spec.binary!r} not found in PATH (tool={tool.name})"
            )

        # 4. Cache
        cache_key = tool.cache_key(params)
        if self.store.action_cached(cache_key):
            logger.info(f"[dim]cache hit for {tool.name} params={list(params)}[/dim]")
            self._audit(tool, params, event="cache_hit", extra={"cache_key": cache_key})
            # Return an empty result marker; the orchestrator should skip re-parsing.
            return ToolResult(
                tool=tool.name,
                argv=[],
                stdout="",
                stderr="",
                exit_code=0,
                duration_s=0.0,
                cache_key=cache_key,
            )

        # 5. Rate limit (once per distinct target host)
        for t in tool.targets(params):
            host = self._host_of(t)
            if host:
                self.rate_limiter.acquire(host)

        # 6. Build & execute
        argv = [tool.spec.binary, *tool.build_argv(params)]
        logger.info(f"[bold cyan]→ {tool.name}[/bold cyan] argv={argv!r}")
        start = time.time()
        self._audit(tool, params, event="exec_start", extra={"argv": argv, "cache_key": cache_key})
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout or self.default_timeout,
                check=False,
            )
            exit_code = proc.returncode
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
        except subprocess.TimeoutExpired as e:
            exit_code = -1
            stdout = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, (bytes, bytearray)) else (e.stdout or "")
            stderr = (e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, (bytes, bytearray)) else (e.stderr or "")) + f"\n[timed out after {timeout}s]"
        except FileNotFoundError as e:
            self._audit(tool, params, event="exec_error", extra={"error": str(e)})
            raise ExecutionError(f"cannot exec {argv[0]!r}: {e}") from e

        end = time.time()
        result = ToolResult(
            tool=tool.name,
            argv=argv,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_s=end - start,
            cache_key=cache_key,
        )

        # 7. Persist & audit
        self.store.record_action(
            tool=tool.name,
            params_json=json.dumps(params, sort_keys=True, default=str),
            started_at=start,
            finished_at=end,
            exit_code=exit_code,
            cache_key=cache_key,
        )
        self._audit(
            tool,
            params,
            event="exec_done",
            extra={
                "exit_code": exit_code,
                "duration_s": round(end - start, 3),
                "stdout_excerpt": stdout[:2000],
                "stderr_excerpt": stderr[:1000],
            },
        )
        return result

    # ------------------------ helpers -----------------------------------

    def _scope_check(self, tool: Tool, params: dict, *, aggressive: bool) -> None:
        if not tool.spec.requires_target_in_scope:
            return
        targets = tool.targets(params)
        if not targets:
            # A tool that claimed to need a target but emitted none — refuse.
            raise ExecutionError(f"tool {tool.name}: no targets found in params")
        for t in targets:
            try:
                self.scope.check(t, aggressive=aggressive)
            except ScopeViolation as e:
                self._audit_reject(tool, params, reason=f"scope_reject: {e}")
                raise ExecutionError(f"scope rejects {t!r}: {e}") from e

    def _host_of(self, target: str) -> str:
        if "://" in target:
            return urlparse(target).hostname or ""
        return target.split("/", 1)[0].split(":", 1)[0]

    def _audit(self, tool: Tool, params: dict, *, event: str, extra: dict | None = None) -> None:
        self.audit.log(
            event,
            {
                "tool": tool.name,
                "params": params,
                **(extra or {}),
            },
        )

    def _audit_reject(self, tool: Tool, params: dict, *, reason: str) -> None:
        self._audit(tool, params, event="exec_rejected", extra={"reason": reason})
