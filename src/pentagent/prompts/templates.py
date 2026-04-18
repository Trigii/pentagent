"""Prompt templates.

Each render function returns a single string. Keep prompts deterministic —
no f-string-injected natural-language opinions, only structured context. The
LLM is asked to output JSON, and we validate that JSON downstream.
"""
from __future__ import annotations

import json
from typing import Any


SYSTEM_PROMPT = """You are the planning brain of an authorized penetration-testing agent.

RULES:
1. You NEVER execute commands. You only emit structured action descriptions
   that a separate sandboxed executor will validate and run.
2. You operate strictly within the provided authorization scope. Assume every
   target listed in the context is pre-authorized; do not propose actions
   against hosts not present in the candidate list or knowledge graph.
3. You prefer high-signal, low-noise actions. Don't propose the same tool
   twice against the same target if the knowledge graph already records it.
4. Prefer reading / observing over writing / changing state. Destructive
   actions (sqlmap, fuzz templates, bruteforce) are only acceptable if the
   candidate list already includes them (meaning scope allows them).
5. You always respond in valid JSON. No prose, no commentary, no code fences.

Your goal is to help the operator find real, reportable vulnerabilities
efficiently. Reason like a competent bug bounty hunter: enumerate, form
hypotheses, test cheap ones first, escalate only with evidence.
"""


def _truncate(doc: Any, max_chars: int) -> str:
    s = json.dumps(doc, default=str)
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 3] + "..."


def render_planner_prompt(
    *, graph: dict, candidates: list, budget: dict[str, Any]
) -> str:
    cand_dicts = [
        {
            "dedup_key": c.dedup_key(),
            "tool": c.tool,
            "params": c.params,
            "reason": c.reason,
            "expected_signal": c.expected_signal,
            "priority": int(c.priority),
        }
        for c in candidates
    ]
    payload = {
        "role": "planner",
        "budget": budget,
        "graph_snapshot": graph,
        "candidates": cand_dicts,
        "schema": {
            "ranking": [{"dedup_key": "str", "priority": "int 1..10"}],
            "new_actions": [
                {
                    "tool": "str (must be one of the tool names already seen in candidates)",
                    "params": "object",
                    "reason": "str",
                    "expected_signal": "str",
                    "priority": "int 1..10",
                    "parser_context": "object (optional)",
                }
            ],
            "done": "bool",
            "reason": "str",
        },
        "instructions": (
            "Re-rank the candidate actions by how informative each is likely "
            "to be in THIS graph state. Use priority 10 for the most valuable "
            "next move, 1 for noise. You MAY propose up to 3 new_actions but "
            "only if the tool already appears in the candidate list — do not "
            "invent new tools. If the graph already contains enough evidence "
            "for a useful report, set done=true."
        ),
    }
    return _truncate(payload, 20000)


def render_analyzer_prompt(*, observation: dict, graph_delta: dict) -> str:
    payload = {
        "role": "analyzer",
        "observation": observation,
        "graph_delta": graph_delta,
        "schema": {
            "summary": "str (2–5 sentences)",
            "anomalies": ["str"],
            "suggested_hypotheses": [
                {
                    "target_ref": "str (e.g. 'Endpoint:42')",
                    "vuln_class": "str (xss|sqli|ssrf|lfi|rfi|ssti|idor|auth|misc)",
                    "reasoning": "str",
                }
            ],
        },
        "instructions": (
            "Briefly summarize what this observation changes about our picture "
            "of the target. List anomalies worth probing. Propose up to 5 "
            "hypotheses; be concrete about WHY (headers, technology, status "
            "code pattern, response length diff, etc.). Output JSON."
        ),
    }
    return _truncate(payload, 12000)


def render_hypothesizer_prompt(
    *, endpoint: dict, param_samples: list[dict], existing_hypotheses: list[dict]
) -> str:
    payload = {
        "role": "hypothesizer",
        "endpoint": endpoint,
        "param_samples": param_samples,
        "existing_hypotheses": existing_hypotheses,
        "schema": {
            "hypotheses": [
                {
                    "vuln_class": "xss|sqli|ssrf|lfi|rfi|ssti|idor|cmdi|openredirect|misc",
                    "confidence": "0.0–1.0",
                    "reasoning": "str",
                    "probe_suggestion": {
                        "tool": "str (must be registered)",
                        "params": "object",
                    },
                }
            ]
        },
        "instructions": (
            "Given this endpoint and param response samples, propose ranked "
            "vulnerability hypotheses. For each, suggest a minimal probe — "
            "prefer low-risk reflection / error-diff / time-diff tests before "
            "heavy tools. Skip classes already confirmed or refuted in "
            "existing_hypotheses. Output JSON only."
        ),
    }
    return _truncate(payload, 12000)


def render_reporter_prompt(*, finding: dict, evidence: dict, context: dict) -> str:
    payload = {
        "role": "reporter",
        "finding": finding,
        "evidence": evidence,
        "context": context,
        "schema": {
            "title": "str (<=100 chars)",
            "severity": "info|low|medium|high|critical",
            "impact": "str (2–4 sentences)",
            "steps_to_reproduce": ["str"],
            "proof_of_concept": "str (code or curl block)",
            "remediation": "str",
            "references": ["str (URLs or CWE/OWASP ids)"],
        },
        "instructions": (
            "Write a concise, professional bug-bounty-style report section "
            "for this finding. Ground every claim in the supplied evidence; "
            "do not invent. Output JSON only."
        ),
    }
    return _truncate(payload, 12000)
