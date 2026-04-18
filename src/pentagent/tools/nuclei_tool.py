"""nuclei wrapper — template-driven vulnerability scanning."""
from __future__ import annotations

from typing import Any

from .base import Mode, Tool, ToolSpec
from .registry import register_tool


def _csv(v: Any) -> str:
    """Coerce list/tuple values to comma-joined strings; pass scalars through."""
    if isinstance(v, (list, tuple)):
        return ",".join(str(x) for x in v)
    return str(v)


@register_tool
class NucleiTool(Tool):
    spec = ToolSpec(
        name="nuclei",
        binary="nuclei",
        supports_modes=("safe", "aggressive"),
        category="vuln-scan",
    )

    def build_argv(self, params: dict[str, Any]) -> list[str]:
        targets = params.get("targets") or params.get("target")
        if isinstance(targets, str):
            targets = [targets]
        if not targets:
            raise ValueError("nuclei requires `targets` or `target`")
        severity = _csv(params.get("severity", "low,medium,high,critical"))
        rate = int(params.get("rate", 50))
        argv = [
            "-silent",
            "-jsonl",
            "-severity", severity,
            "-rate-limit", str(rate),
            "-no-color",
        ]
        if tags := params.get("tags"):
            argv.extend(["-tags", _csv(tags)])
        if exclude_tags := params.get("exclude_tags"):
            argv.extend(["-exclude-tags", _csv(exclude_tags)])
        if templates := params.get("templates"):
            argv.extend(["-t", _csv(templates)])
        # Dedupe target list defensively — upstream may double-add.
        seen: set[str] = set()
        for t in targets:
            t = str(t)
            if t in seen:
                continue
            seen.add(t)
            argv.extend(["-u", t])
        # flatten `flags` if the caller passed a list-of-lists
        for f in params.get("flags") or []:
            if isinstance(f, (list, tuple)):
                argv.extend(str(x) for x in f)
            else:
                argv.append(str(f))
        return argv

    def targets(self, params: dict[str, Any]) -> list[str]:
        t = params.get("targets") or params.get("target")
        if isinstance(t, str):
            return [t]
        return list(t or [])

    def mode_required(self, params: dict[str, Any]) -> Mode:
        # Fuzz templates or intrusive tags flip the switch
        tags = (params.get("tags") or "").lower()
        if any(x in tags for x in ("fuzz", "intrusive", "dos", "bruteforce")):
            return "aggressive"
        if "critical" in (params.get("severity") or "") and params.get("include_fuzz"):
            return "aggressive"
        return "safe"
