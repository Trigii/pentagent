# pentagent

An AI-assisted penetration-testing agent for **authorized** offensive security
work: bug bounty programs, vulnerability disclosure programs, sanctioned
penetration tests, CTFs, and lab environments you own.

> **Authorized use only.** This tool refuses to start without a filled-in
> `scope.yaml` and an explicit `--i-have-authorization` flag. Running it
> against targets you do not have written permission to test is illegal in
> most jurisdictions and is explicitly outside the design envelope of this
> project. You are responsible for compliance.

## Ethics & legal

pentagent is published as a research and defensive-tooling project. By using,
forking, or distributing it you agree to the following:

1. **Written authorization is mandatory.** You will only run pentagent
   against systems for which you hold explicit written permission from the
   asset owner (e.g. a published bug-bounty program scope, a signed
   engagement letter, your own lab, or a CTF). Verbal agreements are not
   sufficient.
2. **Respect program rules.** Many bug-bounty programs forbid active
   exploitation, automated scanning, fuzzing, or DoS-adjacent activity.
   Configure `session.mode: safe` and enable/disable tools accordingly. Read
   the program policy before each run.
3. **Stay in scope.** `scope.yaml` is the source of truth. `ScopeGuard`
   rejects out-of-scope targets before any tool is spawned; do not try to
   bypass it.
4. **Preserve audit integrity.** Every run produces a hash-chained
   `audit.jsonl`. Do not edit it. Use `pentagent verify-audit` to confirm
   a session before sharing results.
5. **No offensive weaponization.** This project is not intended to be a
   launchpad for unauthorized access, credential stuffing, mass scanning,
   or attacks on infrastructure you do not own. Contributions that move in
   that direction will not be accepted.

Unauthorized testing is illegal under, among others, the U.S. Computer Fraud
and Abuse Act (CFAA), the UK Computer Misuse Act, the EU NIS2 Directive, and
analogous statutes in most jurisdictions. The authors disclaim all liability
for misuse.

## Highlights

- **Iterative pentest loop** — recon → enumerate → analyze → hypothesize →
  exploit → validate → store → iterate. The loop is recursive and driven by
  the current knowledge graph.
- **Hybrid planner** — a deterministic heuristic planner produces candidate
  actions from the graph; an LLM re-ranks them and may propose up to 3
  extra actions from a closed tool vocabulary. If the LLM fails or is
  disabled, the heuristic plan runs alone.
- **Typed knowledge graph** — SQLite-backed store of Hosts, Services,
  WebApps, Endpoints, Parameters, Evidence, Findings, Hypotheses with
  natural-key deduplication.
- **Structural safety** — `ScopeGuard` sits between every planner action
  and the executor. All activity is written to a hash-chained `audit.jsonl`
  that `pentagent verify-audit` can validate.
- **Pluggable tools** — nmap, httpx, subfinder, amass, ffuf, gobuster,
  nuclei, sqlmap, nikto, katana out of the box. Add one by writing a
  `Tool` subclass and decorating it with `@register_tool`.
- **Multi-model** — Anthropic, OpenAI, and any OpenAI-compatible local
  server (Ollama, vLLM, LM Studio). Per-task routing in `config.yaml`.
- **Report-ready output** — `report.md` and `report.json` generated from
  the graph, with LLM-enriched impact / PoC / remediation when available.

## Layout

```
ai-pentest-agent/
├── ARCHITECTURE.md        — full system design
├── WALKTHROUGH.md         — end-to-end example run
├── config/
│   ├── config.example.yaml
│   └── scope.example.yaml
├── pyproject.toml
├── requirements.txt
└── src/pentagent/
    ├── cli.py             — typer CLI (run, report, verify-audit, list-tools)
    ├── config.py          — pydantic settings
    ├── safety/            — Scope, ScopeGuard, RateLimiter, AuditLog
    ├── llm/               — Anthropic / OpenAI / local adapters
    ├── memory/            — models + SQLite KnowledgeStore
    ├── tools/             — Executor + tool wrappers (nmap, httpx, ...)
    ├── parsers/           — tool-specific output parsers
    ├── strategy/          — heuristics + LLM planner + actions
    ├── prompts/           — system / planner / analyzer / reporter prompts
    ├── reporting/         — Markdown + JSON report generator
    └── orchestrator/      — the main loop
```

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[anthropic,openai]
```

External binaries must be on `PATH`: `nmap`, `httpx`, `subfinder`, `amass`,
`ffuf`, `gobuster`, `nuclei`, `sqlmap`, `nikto`, `katana`. Missing tools
simply cannot be scheduled; the executor detects their absence at spawn
time and logs an `exec_rejected/binary_missing` audit event.

## Minimal usage

```bash
cp config/config.example.yaml config/config.yaml
cp config/scope.example.yaml   config/scope.yaml

# 1. Edit scope.yaml — fill program_name, authorized_by, authorized_on,
#    authorization_source, operator, include, exclude, aggressive_opt_in.

export ANTHROPIC_API_KEY=sk-ant-...

pentagent run \
    -c config/config.yaml \
    -s config/scope.yaml \
    -t https://api.example.com \
    --i-have-authorization
```

## Without an LLM

```bash
pentagent run -t ... --no-llm --i-have-authorization
```

The agent uses only the heuristic planner; the reporting step falls back
to deterministic sections (no LLM-written impact/PoC/remediation blocks).

## Verifying a session is intact

```bash
pentagent verify-audit -s runs/2026-04-18_12-00-00_abc123
```

## Future extensions

See ARCHITECTURE.md §9 — Active Directory, cloud, containers, exploit dev,
authenticated crawler via headless Chromium, multi-operator Redis-backed
graph, HITL approval gate for aggressive mode.
