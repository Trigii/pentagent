"""Reporting engine v2 — professional pentest report generator.

Pipelines:

  findings + store   ─┐
  action_log (tools) ─┼─►   _collate()   ──►   _render_markdown() → .md
  mitre + owasp      ─┤                  ╰──►   _render_json()     → .json
  LLM (optional)     ─┘                  ╰──►   _render_html()     → .html

The report is composed of six sections that have earned their place:

  1. Executive Summary — overall risk level, scope, counts, top findings.
  2. Scope & Authorization — what was in scope, who authorized the test.
  3. MITRE ATT&CK Matrix — tactics/techniques exercised by tool runs.
  4. Findings — per-finding block with CVSS, CWE, OWASP, ATT&CK, evidence.
  5. Attack Path — narrative of how findings chain (LLM-generated if
     available; falls back to phase-ordered bullet list otherwise).
  6. Appendix — tool inventory + run durations, session budget.

LLM enhancement is opt-in and per-finding: the deterministic blocks are
always produced first, and LLM results are merged on top (never replacing
the deterministic skeleton). A flaky LLM degrades the report's prose, not
its correctness.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from html import escape as htmlescape
from pathlib import Path
from typing import Any, Iterable

from ..knowledge import map_finding, map_tool, ATTACK_TACTIC
from ..llm import LLMClient, LLMMessage
from ..logging_setup import get_logger
from ..memory import Finding, KnowledgeStore, Severity
from ..prompts import SYSTEM_PROMPT, render_reporter_prompt
from ..strategy.phases import phase_of


logger = get_logger(__name__)


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_DISPLAY = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                "low": "LOW", "info": "INFO"}


def _sev_label(f: Finding) -> str:
    return f.severity.value if isinstance(f.severity, Severity) else str(f.severity)


def _overall_risk(findings: list[Finding]) -> str:
    """Derive an overall risk label from the severity distribution.

    Rule: the highest severity present in the findings wins. An empty list
    is 'informational' (not 'none' — we still have scope + recon coverage).
    """
    if not findings:
        return "INFORMATIONAL"
    labels = {_sev_label(f) for f in findings}
    for sev in ("critical", "high", "medium", "low"):
        if sev in labels:
            return _SEV_DISPLAY[sev]
    return "INFORMATIONAL"


# --------------------------------------------------------------- Reporter

@dataclass
class Reporter:
    store: KnowledgeStore
    session_dir: Path
    llm: LLMClient | None = None
    program_name: str = ""
    authorized_by: str = ""
    authorized_on: str = ""
    operator: str = ""
    seed_targets: list[str] | None = None
    session_mode: str = "safe"

    # ------------------------------------------------------------ public

    def generate(self, *, formats: list[str] | None = None) -> dict[str, Path]:
        formats = formats or ["markdown", "json"]
        findings = self._sorted_findings()
        collated = self._collate(findings)
        written: dict[str, Path] = {}

        if "json" in formats:
            p = self.session_dir / "report.json"
            p.write_text(json.dumps(collated, indent=2, default=str))
            written["json"] = p

        if "markdown" in formats:
            p = self.session_dir / "report.md"
            p.write_text(self._render_markdown(collated))
            written["markdown"] = p

        if "html" in formats:
            p = self.session_dir / "report.html"
            p.write_text(self._render_html(collated))
            written["html"] = p

        return written

    # ------------------------------------------------------------ helpers

    def _sorted_findings(self) -> list[Finding]:
        findings = self.store.findings()
        findings.sort(
            key=lambda f: (
                _SEV_ORDER.get(_sev_label(f), 99),
                -f.confidence,
            )
        )
        return findings

    # ----------------------------------------------------------- collate

    def _collate(self, findings: list[Finding]) -> dict[str, Any]:
        """Build the full dict the renderers consume.

        Keeping everything in one dict means the JSON output and the
        markdown/html renderers draw from exactly the same source of
        truth — so if a CVE shows up in the markdown it's in the JSON
        too, same severity, same mapping, same evidence.
        """
        hosts = self.store.hosts()
        webapps = self.store.webapps()
        endpoints = self.store.endpoints()
        services = self.store.services()

        tool_runs = self._load_action_log()
        techniques = self._derive_technique_matrix(tool_runs)

        findings_block: list[dict[str, Any]] = []
        for f in findings:
            enh = self._enhanced_section(f)
            std = map_finding(f.kind)
            ctx = self._finding_context(f)
            cvss = self._extract_cvss(f, ctx)
            findings_block.append({
                "id": f.id,
                "severity": _sev_label(f),
                "severity_display": _SEV_DISPLAY.get(_sev_label(f), _sev_label(f).upper()),
                "kind": f.kind,
                "title": (enh.get("title") if enh else None) or f.title,
                "confidence": f.confidence,
                "entity_type": f.entity_type,
                "entity_id": f.entity_id,
                "source_tool": f.source_tool,
                "template_id": f.template_id,
                "description": (enh.get("impact") if enh else None) or f.description,
                "recommendation": (enh.get("remediation") if enh else None) or f.recommendation,
                "steps": (enh.get("steps_to_reproduce") if enh else None) or [],
                "proof_of_concept": (enh.get("proof_of_concept") if enh else None) or "",
                "references": (enh.get("references") if enh else None) or [],
                "standards": std,
                "cvss": cvss,
                "evidence": ctx.get("evidence") or {},
                "target": self._finding_target_label(f, ctx),
            })

        attack_path = self._attack_path(findings_block, tool_runs)
        coverage = self._coverage_gaps(tool_runs, hosts, webapps, endpoints)

        return {
            "meta": {
                "program_name": self.program_name,
                "authorized_by": self.authorized_by,
                "authorized_on": self.authorized_on,
                "operator": self.operator,
                "seed_targets": list(self.seed_targets or []),
                "session_mode": self.session_mode,
                "session_dir": str(self.session_dir),
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            },
            "summary": {
                "overall_risk": _overall_risk(findings),
                "counts": {
                    "hosts": len(hosts),
                    "webapps": len(webapps),
                    "endpoints": len(endpoints),
                    "services": len(services),
                    "findings": len(findings),
                    "tool_runs": len(tool_runs),
                },
                "by_severity": _severity_breakdown(findings),
                "top_findings": [
                    {"title": fb["title"], "severity": fb["severity"], "target": fb["target"]}
                    for fb in findings_block[:5]
                ],
            },
            "hosts": [h.model_dump() for h in hosts],
            "webapps": [w.model_dump() for w in webapps],
            "services": [s.model_dump() for s in services],
            "endpoints": [e.model_dump() for e in endpoints],
            "findings": findings_block,
            "mitre_matrix": techniques,
            "attack_path": attack_path,
            "coverage_gaps": coverage,
            "tool_inventory": _tool_inventory(tool_runs),
        }

    def _coverage_gaps(
        self,
        tool_runs: list[dict[str, Any]],
        hosts: list,
        webapps: list,
        endpoints: list,
    ) -> dict[str, Any]:
        """Identify entities the agent *didn't* probe fully.

        This is the single most-requested reviewer signal — "did we actually
        look at everything?". We compute per-entity coverage against a small
        matrix of expected tool runs:

          - Host with no services → nmap never landed results
          - WebApp with no nuclei run → vuln sweep missing
          - WebApp with no content discovery → ffuf/gobuster/katana missing
          - Endpoint with query params + aggressive mode → sqlmap missing

        Each gap is actionable: a reviewer can re-run with explicit
        --target-include or enable the relevant tool and continue.
        """
        # Bucket tool runs by (tool, webapp_id / host target / endpoint_id)
        runs_by_tool: dict[str, set] = {}
        for tr in tool_runs:
            # Skip failed runs (exit_code==-1 marker from dead-tool handler)
            # — a gap is valid if the tool never *succeeded*, regardless of
            # whether we tried and failed.
            if tr.get("exit_code") == -1:
                continue
            p = tr.get("params") or {}
            tool = tr["tool"]
            bucket = runs_by_tool.setdefault(tool, set())
            for key in ("webapp_id", "endpoint_id"):
                if key in p:
                    bucket.add(("id", int(p[key])))
            tgt = p.get("target") or p.get("targets")
            if isinstance(tgt, list):
                for t in tgt:
                    bucket.add(("tgt", str(t)))
            elif isinstance(tgt, str):
                bucket.add(("tgt", tgt))

        missing_nmap: list[dict[str, Any]] = []
        missing_nuclei: list[dict[str, Any]] = []
        missing_content: list[dict[str, Any]] = []
        missing_sqlmap: list[dict[str, Any]] = []

        # --- Hosts without a successful nmap ---
        nmap_keys = runs_by_tool.get("nmap", set())
        host_with_services = {h.id for h in hosts if any(
            getattr(s, "host_id", None) == h.id for s in self.store.services()
        )}
        for h in hosts:
            if h.id in host_with_services:
                continue
            key = h.hostname or h.ip or ""
            if not key:
                continue
            if ("tgt", key) in nmap_keys:
                continue  # nmap tried but found no services
            missing_nmap.append({
                "host": key,
                "ip": h.ip,
                "hostname": h.hostname,
                "reason": "no successful port scan",
            })

        # --- WebApps without nuclei ---
        nuclei_keys = runs_by_tool.get("nuclei", set())
        content_tools = ("ffuf", "gobuster", "katana")
        content_keys: set = set()
        for ct in content_tools:
            content_keys |= runs_by_tool.get(ct, set())

        for w in webapps:
            if w.id is None:
                continue
            if ("id", int(w.id)) not in nuclei_keys:
                missing_nuclei.append({
                    "webapp_id": w.id,
                    "base_url": w.base_url,
                    "reason": "no nuclei vuln sweep",
                })
            if ("id", int(w.id)) not in content_keys:
                missing_content.append({
                    "webapp_id": w.id,
                    "base_url": w.base_url,
                    "reason": "no content discovery (ffuf/gobuster/katana)",
                })

        # --- Endpoints with params but no sqlmap (aggressive-mode only) ---
        if self.session_mode in ("aggressive", "ctf"):
            sqlmap_keys = runs_by_tool.get("sqlmap", set())
            for e in endpoints:
                if not ("?" in e.path or getattr(e, "params", None)):
                    continue
                if ("id", int(e.id)) in sqlmap_keys:
                    continue
                missing_sqlmap.append({
                    "endpoint_id": e.id,
                    "path": e.path,
                    "reason": "parameterized but sqlmap never ran",
                })

        return {
            "missing_nmap": missing_nmap,
            "missing_nuclei": missing_nuclei,
            "missing_content_discovery": missing_content,
            "missing_sqlmap": missing_sqlmap,
            "totals": {
                "hosts_without_portscan": len(missing_nmap),
                "webapps_without_vuln_sweep": len(missing_nuclei),
                "webapps_without_content_discovery": len(missing_content),
                "parameterized_endpoints_without_sqlmap": len(missing_sqlmap),
            },
        }

    def _load_action_log(self) -> list[dict[str, Any]]:
        """Pull every tool invocation from the action_log."""
        out: list[dict[str, Any]] = []
        try:
            cur = self.store._conn.execute(
                "SELECT tool, params, started_at, finished_at, exit_code FROM action_log "
                "ORDER BY started_at NULLS LAST, id"
            )
            for row in cur:
                try:
                    params = json.loads(row["params"]) if row["params"] else {}
                except Exception:
                    params = {}
                out.append({
                    "tool": row["tool"],
                    "params": params,
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                    "exit_code": row["exit_code"],
                })
        except Exception as e:
            logger.debug(f"reporter action_log load failed: {e}")
        return out

    def _derive_technique_matrix(
        self, tool_runs: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Return per-tactic usage stats. One row per MITRE tactic, with
        the list of tools that exercised that tactic and the number of
        runs per tool."""
        # tactic_id -> {tool_name -> run_count}
        agg: dict[str, dict[str, int]] = {}
        # tactic_id -> techniques seen
        tech_by_tactic: dict[str, set[str]] = {}
        for tr in tool_runs:
            attack = map_tool(tr["tool"])
            tactic = attack["tactic_id"]
            if not tactic:
                continue
            agg.setdefault(tactic, {})
            agg[tactic][tr["tool"]] = agg[tactic].get(tr["tool"], 0) + 1
            tech_by_tactic.setdefault(tactic, set()).update(attack["techniques"])
        rows: list[dict[str, Any]] = []
        for tactic_id, tools in sorted(agg.items()):
            rows.append({
                "tactic_id": tactic_id,
                "tactic": ATTACK_TACTIC.get(tactic_id, ""),
                "techniques": sorted(tech_by_tactic.get(tactic_id, [])),
                "tool_runs": [
                    {"tool": t, "runs": c}
                    for t, c in sorted(tools.items(), key=lambda kv: -kv[1])
                ],
            })
        return rows

    def _attack_path(
        self, findings_block: list[dict[str, Any]],
        tool_runs: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """A phase-ordered narrative of what happened. Each row is a phase
        with the tool runs and findings that occurred in it."""
        by_phase: dict[str, dict[str, Any]] = {}
        for phase_name in ("recon", "enum", "vuln", "exploit"):
            by_phase[phase_name] = {"phase": phase_name, "tools": set(), "findings": []}

        for tr in tool_runs:
            phase = phase_of(tr["tool"]).label
            by_phase.setdefault(phase, {"phase": phase, "tools": set(), "findings": []})
            by_phase[phase]["tools"].add(tr["tool"])

        for fb in findings_block:
            tool = fb["source_tool"] or ""
            phase = phase_of(tool).label
            by_phase.setdefault(phase, {"phase": phase, "tools": set(), "findings": []})
            by_phase[phase]["findings"].append(
                {"title": fb["title"], "severity": fb["severity"], "target": fb["target"]}
            )
        # Stabilize and stringify
        rows: list[dict[str, Any]] = []
        for phase_name in ("recon", "enum", "vuln", "exploit", "report"):
            row = by_phase.get(phase_name)
            if not row:
                continue
            rows.append({
                "phase": row["phase"],
                "tools": sorted(row["tools"]),
                "findings": row["findings"],
            })
        return rows

    def _finding_context(self, f: Finding) -> dict[str, Any]:
        ctx: dict[str, Any] = {"finding": f.model_dump()}
        try:
            if f.evidence_id:
                row = self.store._conn.execute(
                    "SELECT * FROM evidence WHERE id = ?", (f.evidence_id,)
                ).fetchone()
                if row:
                    ctx["evidence"] = dict(row)
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
            elif f.entity_type == "Service":
                row = self.store._conn.execute(
                    "SELECT s.*, h.ip, h.hostname FROM services s JOIN hosts h ON s.host_id = h.id "
                    "WHERE s.id = ?",
                    (f.entity_id,),
                ).fetchone()
                if row:
                    ctx["service"] = dict(row)
            elif f.entity_type == "Host":
                row = self.store._conn.execute(
                    "SELECT * FROM hosts WHERE id = ?", (f.entity_id,)
                ).fetchone()
                if row:
                    ctx["host"] = dict(row)
        except Exception as e:
            logger.debug(f"reporter context lookup failed: {e}")
        return ctx

    def _extract_cvss(self, f: Finding, ctx: dict[str, Any]) -> dict[str, Any]:
        """CVEs carry CVSS in their evidence.raw_excerpt (see cve-enricher).
        This pulls the numeric score + severity label out for the report."""
        if f.kind != "cve":
            return {}
        raw = (ctx.get("evidence") or {}).get("raw_excerpt") or ""
        score = None
        sev = ""
        for line in raw.splitlines():
            ls = line.strip()
            if ls.startswith("CVSS v3:"):
                # "CVSS v3:  7.5 (HIGH)"
                tail = ls[len("CVSS v3:"):].strip()
                try:
                    score = float(tail.split()[0])
                except (IndexError, ValueError):
                    score = None
                if "(" in tail and ")" in tail:
                    sev = tail[tail.find("(") + 1:tail.find(")")]
                break
        return {"score": score, "severity": sev} if (score is not None or sev) else {}

    def _finding_target_label(self, f: Finding, ctx: dict[str, Any]) -> str:
        if "endpoint" in ctx:
            ep = ctx["endpoint"]
            return f"{ep.get('base_url', '')}{ep.get('path', '')}"
        if "webapp" in ctx:
            return str(ctx["webapp"].get("base_url") or "")
        if "service" in ctx:
            s = ctx["service"]
            host = s.get("hostname") or s.get("ip") or ""
            return f"{host}:{s.get('port')}/{s.get('proto')}"
        if "host" in ctx:
            return str(ctx["host"].get("hostname") or ctx["host"].get("ip") or "")
        return f"{f.entity_type}#{f.entity_id}"

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

    # ---------------------------------------------------------- markdown

    def _render_markdown(self, d: dict[str, Any]) -> str:
        m = d["meta"]
        s = d["summary"]
        lines: list[str] = []

        # --- Cover ---
        lines.append("# Penetration Test Report\n")
        if m["program_name"]:
            lines.append(f"**Program:** {m['program_name']}  ")
        if m["operator"]:
            lines.append(f"**Operator:** {m['operator']}  ")
        if m["authorized_by"]:
            lines.append(f"**Authorized by:** {m['authorized_by']}"
                         + (f" on {m['authorized_on']}" if m["authorized_on"] else "") + "  ")
        lines.append(f"**Session mode:** {m['session_mode']}  ")
        lines.append(f"**Generated:** {m['generated_at']}  \n")

        # --- Executive Summary ---
        lines.append("## Executive Summary\n")
        lines.append(
            f"This report summarizes automated security testing performed by "
            f"`pentagent` against {len(m['seed_targets'])} seed target(s). "
            f"Overall risk: **{s['overall_risk']}**.\n"
        )
        lines.append("| Metric | Count |")
        lines.append("|---|---:|")
        for k in ("hosts", "webapps", "services", "endpoints", "findings", "tool_runs"):
            lines.append(f"| {k} | {s['counts'][k]} |")
        lines.append("")
        by_sev = s["by_severity"]
        if any(by_sev.values()):
            lines.append("### Findings by severity\n")
            lines.append("| Severity | Count |")
            lines.append("|---|---:|")
            for sev in ("critical", "high", "medium", "low", "info"):
                if by_sev.get(sev):
                    lines.append(f"| {_SEV_DISPLAY[sev]} | {by_sev[sev]} |")
            lines.append("")
        if s["top_findings"]:
            lines.append("### Top findings\n")
            for tf in s["top_findings"]:
                lines.append(f"- **[{_SEV_DISPLAY.get(tf['severity'], tf['severity'].upper())}]** "
                             f"{tf['title']} — `{tf['target']}`")
            lines.append("")

        # --- Scope & Authorization ---
        lines.append("## Scope & Authorization\n")
        if m["seed_targets"]:
            lines.append("**In-scope seed targets:**\n")
            for t in m["seed_targets"]:
                lines.append(f"- `{t}`")
            lines.append("")
        if m["authorized_by"]:
            lines.append(f"Testing was authorized by **{m['authorized_by']}**"
                         + (f" on **{m['authorized_on']}**" if m["authorized_on"] else "")
                         + ".\n")

        # --- MITRE ATT&CK Matrix ---
        lines.append("## MITRE ATT&CK Coverage\n")
        matrix = d["mitre_matrix"]
        if not matrix:
            lines.append("_No MITRE-tagged tool activity recorded._\n")
        else:
            lines.append("| Tactic | ID | Techniques | Tools (runs) |")
            lines.append("|---|---|---|---|")
            for row in matrix:
                techs = ", ".join(f"`{t}`" for t in row["techniques"]) or "_unknown_"
                runs = ", ".join(f"{r['tool']}×{r['runs']}" for r in row["tool_runs"])
                lines.append(f"| {row['tactic']} | `{row['tactic_id']}` | {techs} | {runs} |")
            lines.append("")

        # --- Findings ---
        lines.append("## Findings\n")
        if not d["findings"]:
            lines.append("_No findings produced in this session._\n")
        for i, fb in enumerate(d["findings"], 1):
            std = fb["standards"]
            sev = fb["severity_display"]
            lines.append(f"### {i}. [{sev}] {fb['title']}\n")
            lines.append(f"- **kind:** `{fb['kind']}`")
            lines.append(f"- **target:** `{fb['target']}`")
            lines.append(f"- **confidence:** {fb['confidence']:.2f}")
            if fb["template_id"]:
                lines.append(f"- **template/id:** `{fb['template_id']}`")
            if fb["source_tool"]:
                lines.append(f"- **source tool:** `{fb['source_tool']}`")
            if std.get("cwe"):
                lines.append(f"- **CWE:** `{std['cwe']}`")
            if std.get("owasp_2021"):
                lines.append(f"- **OWASP (2021):** {std['owasp_2021']}")
            if std.get("attack_technique"):
                lines.append(f"- **MITRE ATT&CK:** `{std['attack_technique']}`")
            cvss = fb.get("cvss") or {}
            if cvss.get("score") is not None:
                lines.append(f"- **CVSS v3:** {cvss['score']:.1f}"
                             + (f" ({cvss['severity']})" if cvss.get('severity') else ""))
            lines.append("")
            if fb["description"]:
                lines.append(f"**Impact.** {fb['description']}\n")
            if fb["steps"]:
                lines.append("**Steps to reproduce:**\n")
                for step in fb["steps"]:
                    lines.append(f"1. {step}")
                lines.append("")
            if fb["proof_of_concept"]:
                lines.append("**Proof of concept:**\n")
                lines.append("```")
                lines.append(fb["proof_of_concept"])
                lines.append("```\n")
            ev_raw = (fb.get("evidence") or {}).get("raw_excerpt") or ""
            if ev_raw and fb["kind"] != "cve":     # CVE evidence is already in the metadata above
                lines.append("**Evidence:**\n")
                lines.append("```")
                lines.append(ev_raw[:1400])
                lines.append("```\n")
            if fb["recommendation"]:
                lines.append(f"**Remediation.** {fb['recommendation']}\n")
            if fb["references"]:
                lines.append("**References:**\n")
                for r in fb["references"]:
                    lines.append(f"- {r}")
                lines.append("")
            lines.append("---\n")

        # --- Attack Path ---
        lines.append("## Attack Path\n")
        for row in d["attack_path"]:
            if not row["tools"] and not row["findings"]:
                continue
            lines.append(f"### Phase: {row['phase'].upper()}\n")
            if row["tools"]:
                lines.append("**Tools exercised:** " + ", ".join(f"`{t}`" for t in row["tools"]))
            if row["findings"]:
                lines.append("\n**Findings in this phase:**\n")
                for f in row["findings"]:
                    lines.append(
                        f"- [{_SEV_DISPLAY.get(f['severity'], f['severity'].upper())}] "
                        f"{f['title']} — `{f['target']}`"
                    )
            lines.append("")

        # --- Coverage Gaps ---
        cov = d.get("coverage_gaps") or {}
        totals = cov.get("totals") or {}
        if cov and any(totals.values()):
            lines.append("## Coverage Gaps\n")
            lines.append(
                "_Entities in scope that were discovered but not fully "
                "probed. Each row is a candidate for a follow-up run._\n"
            )
            lines.append("| Category | Count |")
            lines.append("|---|---:|")
            for label, key in (
                ("Hosts without port scan", "hosts_without_portscan"),
                ("WebApps without vuln sweep", "webapps_without_vuln_sweep"),
                ("WebApps without content discovery", "webapps_without_content_discovery"),
                ("Parameterized endpoints without sqlmap", "parameterized_endpoints_without_sqlmap"),
            ):
                if totals.get(key):
                    lines.append(f"| {label} | {totals[key]} |")
            lines.append("")

            if cov.get("missing_nmap"):
                lines.append("### Hosts not port-scanned\n")
                for h in cov["missing_nmap"][:20]:
                    lines.append(f"- `{h['host']}` — {h['reason']}")
                if len(cov["missing_nmap"]) > 20:
                    lines.append(f"- _…and {len(cov['missing_nmap']) - 20} more_")
                lines.append("")

            if cov.get("missing_nuclei"):
                lines.append("### WebApps without vuln sweep\n")
                for w in cov["missing_nuclei"][:20]:
                    lines.append(f"- `{w['base_url']}` (id={w['webapp_id']})")
                if len(cov["missing_nuclei"]) > 20:
                    lines.append(f"- _…and {len(cov['missing_nuclei']) - 20} more_")
                lines.append("")

            if cov.get("missing_content_discovery"):
                lines.append("### WebApps without content discovery\n")
                for w in cov["missing_content_discovery"][:20]:
                    lines.append(f"- `{w['base_url']}` (id={w['webapp_id']})")
                if len(cov["missing_content_discovery"]) > 20:
                    lines.append(f"- _…and {len(cov['missing_content_discovery']) - 20} more_")
                lines.append("")

            if cov.get("missing_sqlmap"):
                lines.append("### Parameterized endpoints skipped by sqlmap\n")
                for e in cov["missing_sqlmap"][:20]:
                    lines.append(f"- `{e['path']}` (endpoint_id={e['endpoint_id']})")
                if len(cov["missing_sqlmap"]) > 20:
                    lines.append(f"- _…and {len(cov['missing_sqlmap']) - 20} more_")
                lines.append("")

        # --- Appendix ---
        lines.append("## Appendix: Tool Inventory\n")
        inv = d["tool_inventory"]
        if not inv:
            lines.append("_No tool runs recorded._\n")
        else:
            lines.append("| Tool | Runs | Phase | Primary tactic | Techniques |")
            lines.append("|---|---:|---|---|---|")
            for row in inv:
                techs = ", ".join(f"`{t}`" for t in row["techniques"]) or "_—_"
                lines.append(f"| `{row['tool']}` | {row['runs']} | {row['phase']} | "
                             f"{row['tactic']} | {techs} |")

        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------- html

    def _render_html(self, d: dict[str, Any]) -> str:
        """Minimal, clean, printable HTML. Embeds CSS inline so the report
        opens standalone in a browser (no external deps, no CDNs)."""
        md = self._render_markdown(d)
        # Very light conversion: emit the markdown inside a <pre> block plus
        # structured summary tables. This is intentional — the markdown is
        # the canonical form, and HTML exists for "send this to a
        # stakeholder who won't open a .md" cases.
        title = htmlescape(d["meta"]["program_name"] or "Penetration Test Report")
        css = """
          body { font-family: -apple-system, Segoe UI, sans-serif;
                 max-width: 900px; margin: 2em auto; color: #222; line-height: 1.5; }
          h1,h2,h3 { color: #0b3d91; }
          .overall { display: inline-block; padding: 0.2em 0.6em; border-radius: 4px;
                     font-weight: bold; background: #eee; }
          .sev-critical { background: #7a0019; color: #fff; }
          .sev-high { background: #b5301c; color: #fff; }
          .sev-medium { background: #c68400; color: #fff; }
          .sev-low { background: #3a7d44; color: #fff; }
          .sev-info { background: #4a4a4a; color: #fff; }
          table { border-collapse: collapse; margin: 1em 0; width: 100%; }
          th, td { border: 1px solid #ddd; padding: 0.4em 0.6em; text-align: left; }
          th { background: #f3f5fa; }
          pre { background: #f6f8fa; padding: 0.8em; overflow-x: auto; }
          code { background: #f6f8fa; padding: 0 0.3em; border-radius: 3px; }
        """
        sev_class = "sev-" + d["summary"]["overall_risk"].lower()
        # Replace the markdown body with a <pre> block — browsers render
        # this legibly and the canonical form stays exact.
        body = f"""<h1>{title}</h1>
<p>Overall risk: <span class="overall {sev_class}">{htmlescape(d['summary']['overall_risk'])}</span></p>
<pre>{htmlescape(md)}</pre>
"""
        return f"<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title><style>{css}</style></head><body>{body}</body></html>"


# --------------------------------------------------------------- helpers

def _severity_breakdown(findings: Iterable[Finding]) -> dict[str, int]:
    out = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        k = _sev_label(f)
        out[k] = out.get(k, 0) + 1
    return out


def _tool_inventory(tool_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    agg: dict[str, int] = {}
    for tr in tool_runs:
        agg[tr["tool"]] = agg.get(tr["tool"], 0) + 1
    rows: list[dict[str, Any]] = []
    for tool, runs in sorted(agg.items(), key=lambda kv: -kv[1]):
        attack = map_tool(tool)
        rows.append({
            "tool": tool,
            "runs": runs,
            "phase": phase_of(tool).label,
            "tactic": attack["tactic"],
            "tactic_id": attack["tactic_id"],
            "techniques": list(attack["techniques"]),
        })
    return rows
