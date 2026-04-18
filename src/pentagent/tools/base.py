"""Tool interface.

A Tool is a pure description object. It doesn't spawn processes — it builds
argv and knows how to make sense of the result. The Executor runs things.
This separation lets us unit-test tools without touching the filesystem.
"""
from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal


Mode = Literal["safe", "aggressive"]


@dataclass
class ToolSpec:
    """Declaration of a tool — what it needs, what it costs, what it emits."""
    name: str
    binary: str
    supports_modes: tuple[Mode, ...] = ("safe", "aggressive")
    requires_target_in_scope: bool = True
    # Whether the tool may be called with aggressive semantics even if the
    # surrounding session is in "safe" mode (almost always False).
    bypasses_mode_gate: bool = False
    # Free-form category, used by the planner for budgeting.
    category: str = "misc"


@dataclass
class ToolResult:
    tool: str
    argv: list[str]
    stdout: str
    stderr: str
    exit_code: int
    duration_s: float
    output_paths: dict[str, str] = field(default_factory=dict)   # extra artifacts
    cache_key: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 or self.exit_code in (0,)

    def summary(self) -> dict:
        return {
            "tool": self.tool,
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 2),
            "stdout_len": len(self.stdout),
            "stderr_len": len(self.stderr),
        }


class Tool(ABC):
    """Implement `build_argv()` and (usually) `parse()` in each tool."""

    spec: ToolSpec

    @property
    def name(self) -> str:
        return self.spec.name

    @abstractmethod
    def build_argv(self, params: dict[str, Any]) -> list[str]:
        """Build the subprocess argv for the given params."""

    def targets(self, params: dict[str, Any]) -> list[str]:
        """Return the scope-relevant targets embedded in `params`.

        Default implementation looks at common keys; override if your tool
        stores targets elsewhere.
        """
        out: list[str] = []
        for key in ("target", "url", "host", "domain", "ip"):
            val = params.get(key)
            if isinstance(val, str):
                out.append(val)
            elif isinstance(val, list):
                out.extend(str(x) for x in val)
        return out

    def mode_required(self, params: dict[str, Any]) -> Mode:
        """Return "aggressive" if these params imply destructive behavior."""
        return "safe"

    def cache_key(self, params: dict[str, Any]) -> str:
        payload = json.dumps(
            {"name": self.name, "params": params}, sort_keys=True, default=str
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
