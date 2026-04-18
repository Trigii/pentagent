"""Reporting engine — turns the knowledge graph into human + machine docs.

The reporter has two stages:

1. Deterministic: for every Finding, produce a Markdown section with its
   raw fields. This always works, even without an LLM.
2. LLM-enhanced: if an LLM client is provided, the reporter asks it for an
   impact / steps / PoC / remediation block per finding, using the reporter
   prompt. The JSON response is validated and merged; on failure, we keep
   the deterministic version.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..llm import LLMClient, LLMMessage
from ..logging_setup import get_logger
from ..memory import Finding, KnowledgeStore, Severity
from ..prompts import SYSTEM_PROMPT, render_reporter_prompt


logger = get_logger(__name__)


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Reporter:
    store: KnowledgeStore
    session_dir: Path
    llm: LLMClient | None = None

    # --------------------------------------------------------------- public

    def generate(self, *, formats: list[str] | None = None) -> dict[str, Path]:
        formats = formats or ["markdown", "json"]
        findings = self._sorted_findings()
        written: dict[str, Path] = {}

        if "json" in formats:
            p = self.session_dir / "report.json"
            p.write_text(json.dumps(self._json_report(findings), indent=2, default=str))
            written["json"] = p

        if "markdown" in formats:
            p = self.session_dir / "report.md"
            p.write_text(self._markdown_report(findings))
            written["markdown"] = p

        return written

    # -------------------------------------------------------------- helpers

    def _sorted_findings(self) -> list[Finding]:
        findings = self.store.findings()
        findings.sort(
            key=lambda f: (
                _SEV_ORDER.get(
                    f.severity.value if isinstance(f.severity, Severity) else str(f.severity), 99
                ),
                -f.confidence,
            )
        )
        return findings

    def _finding_context(self, f: Finding) -> dict[str, Any]:
        ctx: dict[str, Any] = {"finding": f.model_dump()}
        try:
            # evidence
            if f.evidence_id:
                row = self.store._conn.execute(
                    "SELECT * FROM evidence WHERE id = ?", (f.evidence_id,)
                ).fetchone()
                if row:
                    ctx["evidence"] = dict(row)
            # entity backref
            if f.entity_type == "Endpoint":
                row = self.store._conn.execute(
                    "SELECT e.*, w.base_url FROM endpoints e JOIN webapps w ON e.webapp_id = w.id "
                    "WHERE e.id = ?",
                    (f.entity_id,),
                ).fetchone()
                if row:
                    ctx["endpoint"] = dict(row)
            elif f.entity_type == "WebApp":
                row = self.store._conn.execute(
                    "SELECT * FROM webapps WHERE id = ?", (f.entity_id,)
                ).fetchone()
                if row:
                    ctx["webapp"] = dict(row)
        except Exception as e:  # pragma: no cover
            logger.debug(f"reporter context lookup failed: {e}")
        return ctx

    def _enhanced_section(self, f: Finding) -> dict[str, Any] | None:
        if not self.llm:
            return None
        ctx = self._finding_context(f)
        prompt = render_reporter_prompt(
            finding=ctx.get("finding") or {},
            evidence=ctx.get("evidence") or {},
            context={k: ctx[k] for k in ctx if k not in ("finding", "evidence")},
        )
        try:
            resp = self.llm.chat(
                [
                    LLMMessage(role="system", content=SYSTEM_PROMPT),
                    LLMMessage(role="user", content=prompt),
                ],
                expect_json=True,
                temperature=0.2,
            )
            data = resp.json()
            if not isinstance(data, dict):
                return None
            return data
        except Exception as e:
            logger.debug(f"reporter LLM enhancement failed: {e}")
            return None

    # ------------------------------------------------------------ renderers

    def _json_report(self, findings: list[Finding]) -> dict[str, Any]:
        return {
            "session_dir": str(self.session_dir),
            "hosts": [h.model_dump() for h in self.store.hosts()],
            "webapps": [w.model_dump() for w in self.store.webapps()],
            "endpoints": [e.model_dump() for e in self.store.endpoints()],
            "findings": [
                {**f.model_dump(), "enhanced": self._enhanced_section(f)} for f in findings
            ],
            "hypotheses": [h.model_dump() for h in self.store.hypotheses()],
        }

    def _markdown_report(self, findings: list[Finding]) -> str:
        lines: list[str] = []
        lines.append("# Penetration Test Report\n")
        lines.append("> Generated by `pentagent`. This report is based on automated\n"
                     "> tooling run under written authorization. Evidence excerpts are\n"
                     "> included verbatim from tool outputs.\n")
        # Summary
        by_sev: dict[str, int] = {}
        for f in findings:
            key = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            by_sev[key] = by_sev.get(key, 0) + 1
        lines.append("## Summary\n")
        lines.append(f"- hosts: **{len(self.store.hosts())}**")
        lines.append(f"- webapps: **{len(self.store.webapps())}**")
        lines.append(f"- endpoints: **{len(self.store.endpoints())}**")
        lines.append(f"- findings: **{len(findings)}**")
        for sev in ("critical", "high", "medium", "low", "info"):
            if by_sev.get(sev):
                lines.append(f"  - {sev}: {by_sev[sev]}")
        lines.append("")

        # Findings
        lines.append("## Findings\n")
        if not findings:
            lines.append("_No findings were produced in this session._\n")
        for i, f in enumerate(findings, 1):
            enh = self._enhanced_section(f) or {}
            sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            title = enh.get("title") or f.title
            lines.append(f"### {i}. [{sev.upper()}] {title}\n")
            lines.append(f"- **kind:** `{f.kind}`")
            lines.append(f"- **entity:** {f.entity_type}#{f.entity_id}")
            lines.append(f"- **confidence:** {f.confidence:.2f}")
            if f.template_id:
                lines.append(f"- **template:** `{f.template_id}`")
            if f.source_tool:
                lines.append(f"- **source tool:** `{f.source_tool}`")
            lines.append("")
            if impact := enh.get("impact") or f.description:
                lines.append(f"**Impact.** {impact}\n")
            steps = enh.get("steps_to_reproduce")
            if steps:
                lines.append("**Steps to reproduce:**\n")
                for step in steps:
                    lines.append(f"1. {step}")
                lines.append("")
            poc = enh.get("proof_of_concept")
            if poc:
                lines.append("**Proof of concept:**\n")
                lines.append("```")
                lines.append(poc)
                lines.append("```\n")
            rem = enh.get("remediation") or f.recommendation
            if rem:
                lines.append(f"**Remediation.** {rem}\n")
            refs = enh.get("references") or []
            if refs:
                lines.append("**References:**")
                for r in refs:
                    lines.append(f"- {r}")
                lines.append("")
            lines.append("---\n")
        return "\n".join(lines)
