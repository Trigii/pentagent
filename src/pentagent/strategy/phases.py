"""Phase state machine for the attack lifecycle.

Every tool lives in a phase, and the planner prefers lower-numbered phases
until they run out of candidates. This gives a natural progression through
the classic pentest arc without hand-coding ordering into the orchestrator:

    recon  → passive intel, DNS, subdomain enumeration
    enum   → active surface mapping: HTTP triage, port scan, content disc.
    vuln   → signature-based scanning + CVE correlation (nuclei, nikto)
    exploit → interactive/active attacks (sqlmap, metasploit, custom PoC)
    report → terminal state; orchestrator stops

The phase is *not* a hard gate — if enum is still producing new entities and
the LLM reranker decides a vuln-phase action is the highest-leverage next
step, we honor that. The phase is a tiebreaker: among otherwise-equally-
priority candidates, the earlier-phase one wins. This preserves the
emergent, knowledge-graph-driven loop while giving progress a spine.

We also track per-phase exhaustion in the orchestrator: when a phase has
produced zero new candidates for N consecutive iterations and no entities
are being committed from it, we consider it exhausted and emit a
`phase_transition` audit record. That's observability, not gating.
"""
from __future__ import annotations

from enum import IntEnum


class Phase(IntEnum):
    """The five canonical phases. Ordered so `Phase.recon < Phase.enum` is
    meaningful — the lower the number, the earlier it runs."""
    recon = 1
    enum = 2
    vuln = 3
    exploit = 4
    report = 5

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def from_label(cls, s: str) -> "Phase":
        try:
            return cls[s.strip().lower()]
        except (KeyError, AttributeError):
            return cls.enum


# Canonical tool → phase mapping. When adding a new tool, put it here too.
# Unknown tools default to enum (safer than vuln/exploit).
TOOL_PHASE: dict[str, Phase] = {
    # Recon
    "subfinder": Phase.recon,
    "amass": Phase.recon,
    "dnsx": Phase.recon,
    "waybackurls": Phase.recon,
    "gau": Phase.recon,
    "theharvester": Phase.recon,
    # Enum
    "httpx": Phase.enum,
    "nmap": Phase.enum,
    "masscan": Phase.enum,
    "naabu": Phase.enum,
    "rustscan": Phase.enum,
    "ffuf": Phase.enum,
    "gobuster": Phase.enum,
    "feroxbuster": Phase.enum,
    "dirsearch": Phase.enum,
    "katana": Phase.enum,
    "hakrawler": Phase.enum,
    "whatweb": Phase.enum,
    "wafw00f": Phase.enum,
    # Vuln
    "nuclei": Phase.vuln,
    "nikto": Phase.vuln,
    "wpscan": Phase.vuln,
    "trivy": Phase.vuln,
    "testssl": Phase.vuln,
    # Exploit
    "sqlmap": Phase.exploit,
    "hydra": Phase.exploit,
    "metasploit": Phase.exploit,
    "medusa": Phase.exploit,
    "crackmapexec": Phase.exploit,
    "nxc": Phase.exploit,
    "impacket-secretsdump": Phase.exploit,
    "impacket-psexec": Phase.exploit,
    "bloodhound": Phase.exploit,
    "kerbrute": Phase.exploit,
    "responder": Phase.exploit,
}


def phase_of(tool: str) -> Phase:
    """Return the phase for `tool`, falling back to enum for unknown tools."""
    if not tool:
        return Phase.enum
    return TOOL_PHASE.get(tool.strip().lower(), Phase.enum)


def dominant_phase(candidates) -> Phase:
    """Return the lowest (earliest) phase among a list of Actions.

    The planner uses this to decide "what phase are we in right now" purely
    from the candidate set — no external state required. If candidates is
    empty we report `report` (terminal) to signal "nothing left to do".
    """
    best = Phase.report
    for a in candidates:
        p = phase_of(getattr(a, "tool", ""))
        if p < best:
            best = p
    return best
