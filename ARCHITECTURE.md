# pentagent — AI-Powered Penetration Testing Agent

## 0. Authorization & Safety Contract

This system exists to assist **authorized** offensive security work (bug bounty
programs with defined scope, VDPs, sanctioned pentests, CTFs, and lab
environments you own). Unauthorized scanning or exploitation is illegal in most
jurisdictions and is **explicitly outside the design envelope of this tool**.

Enforcement is structural, not just advisory:

1. The agent refuses to start without a signed `scope.yaml` and a
   `--i-have-authorization` flag at invocation.
2. Every tool invocation flows through the `ScopeGuard` — hosts/IPs/URLs not in
   the allowlist are hard-rejected before the executor is reached.
3. A tamper-evident `audit.jsonl` records every action, including rejected ones.
4. `safe` mode is the default and disables high-impact modules (sqlmap with
   risk>1, aggressive nuclei templates, auth fuzzing, etc.).
5. Exploitation modules require `aggressive` mode **and** a per-target opt-in.

If you cannot produce written authorization for a target, the agent should not
run against it. This is non-negotiable and is reiterated in the CLI banner.

---

## 1. High-Level Architecture

```
                         ┌──────────────────────────┐
                         │         CLI / API        │
                         └──────────────┬───────────┘
                                        │ scope, target, mode
                                        ▼
   ┌───────────────────────────────────────────────────────────────┐
   │                       ORCHESTRATOR (brain)                    │
   │    loop: observe → plan → act → parse → update → iterate      │
   └───────┬───────────┬───────────────┬────────────────┬──────────┘
           │           │               │                │
           ▼           ▼               ▼                ▼
   ┌───────────┐ ┌───────────┐ ┌───────────────┐ ┌──────────────┐
   │  Strategy │ │    LLM    │ │  Tool Layer   │ │   Memory /   │
   │  Planner  │◄┤  Adapter  │ │  (executor +  │ │  Knowledge   │
   │ (rules +  │ │ (Anthropic│ │   wrappers)   │ │    Graph     │
   │  LLM)     │ │ /OpenAI/  │ └──────┬────────┘ │   (SQLite)   │
   └─────┬─────┘ │  local)   │        │          └──────┬───────┘
         │       └───────────┘        ▼                 │
         │                     ┌─────────────┐          │
         │                     │   Parsers   │          │
         │                     │ (normalize) │          │
         │                     └──────┬──────┘          │
         │                            │ normalized      │
         └────────────────────────────┼─────────────────┘
                                      │ findings
                                      ▼
                              ┌──────────────┐
                              │   Reporting  │
                              │  (MD / JSON) │
                              └──────────────┘
              ▲                                           ▲
              │                                           │
              └──────── ScopeGuard + AuditLog ────────────┘
                    (wraps every tool invocation)
```

### Data flow in one sentence

A `Target` and a scope enter the orchestrator, which repeatedly asks the
strategy planner for the next `Action`, runs it through the scope-guarded
tool executor, parses the output into `Observation` records that mutate the
knowledge graph, and asks the planner again — until a stopping condition is
reached or budget is exhausted — then hands the graph to the reporter.

---

## 2. Components

### 2.1 Orchestrator
Central loop. Owns the `Session`, ticks the strategy planner, commits
observations, and enforces budgets (wall clock, request count, cost).
Stateless-ish: all persistent state lives in the knowledge store so a run can
be paused/resumed.

### 2.2 Strategy Planner
Hybrid rules-plus-LLM. A deterministic `HeuristicPlanner` generates a baseline
set of candidate actions from the current graph state (e.g. "hosts exist but
no HTTP probe done → schedule httpx"). The `LLMPlanner` then re-ranks or
augments them with reasoning ("this header says Nginx + PHP, so prioritize
LFI fuzzing"). Either planner alone is runnable — the LLM is an
intelligence amplifier, not a hard dependency.

### 2.3 Tool Execution Layer
A `Tool` is an object with `name`, `requires`, `supports(mode)`,
`build_command(params)` and `postprocess(raw)`. Tools are run by a single
`Executor` that handles subprocess spawning, stdout/stderr capture,
timeout, retries, tempfile output, and exit-code semantics. All tools share a
cache key derived from `(tool, normalized_args)` so repeated invocations are
deduplicated.

Baseline tools:

| Phase               | Tool(s)                                         |
|---------------------|-------------------------------------------------|
| Passive recon       | subfinder, amass, crt.sh fetch                  |
| Host / port scan    | nmap                                            |
| Web liveness + tech | httpx (with `-tech-detect`, `-title`, `-sc`)    |
| Content discovery   | ffuf, gobuster, dirsearch, katana (crawl)       |
| Vulnerability scan  | nuclei (with `-severity`, `-tags` control)      |
| Specific probes     | sqlmap, nikto, wpscan                           |
| LLM-driven probes   | request fuzzer that uses response heuristics    |

### 2.4 Parser Layer
Each tool has a parser that emits normalized records into the knowledge graph:

- `nmap` → `Host`, `Service`, `Port`
- `httpx` → `WebApp`, `Endpoint`, `Tech`
- `ffuf`/`gobuster` → `Endpoint`, `Status`, `Length`
- `nuclei` → `Finding`, with template id, severity, matcher-name, request/
   response.
- `sqlmap` → `Finding` + `Evidence` (payload, dbms, technique).

Parsers never mutate the graph directly — they return `Observation`s that the
orchestrator commits through the memory layer so writes are ordered and
auditable.

### 2.5 Knowledge / Memory Graph
A typed entity-relationship store backed by SQLite (fast, single-file,
zero-ops). Entities:

```
Target      (id, kind, value, scope_ref)
Host        (id, ip, hostname, os_guess)
Service     (id, host_id, port, proto, product, version, banner)
WebApp      (id, host_id, scheme, base_url, title, tech[])
Endpoint    (id, webapp_id, path, method, status, length, params[])
Parameter   (id, endpoint_id, name, location, reflected, taints[])
Finding     (id, kind, severity, entity_ref, evidence_id, confidence, notes)
Evidence    (id, request, response, payload, raw_excerpt)
Hypothesis  (id, target_ref, vuln_class, reasoning, attempted[], status)
Action      (id, kind, params, caused_findings[], started_at, finished_at)
```

Invariants:
- Entities are **deduplicated** by natural key (e.g. `(host, port, proto)`).
- Every Finding points at an Evidence row — no evidence, no finding.
- Hypotheses are first-class so the planner can retire a line of attack and
  come back to a different one without forgetting.

### 2.6 LLM Adapter
A single `LLMClient` protocol, implemented by `AnthropicClient`,
`OpenAIClient`, and `LocalOpenAICompatClient` (for Ollama / vLLM / LM Studio /
any provider that speaks the OpenAI chat-completions API). Features:

- `chat(system, messages, *, json_schema=None)` returning `LLMResponse`.
- Exponential backoff on rate-limit / transient errors.
- Token and cost bookkeeping into the audit log.
- Per-task routing: e.g. planning uses a strong model, bulk parsing can use a
  cheap/local one. Configured in `config.yaml`.

### 2.7 Safety Layer
`ScopeGuard` (allowlist resolver), `RateLimiter` (token bucket per host),
`ModeGate` (safe vs aggressive), and `AuditLog` (append-only JSONL + hash
chain). `ScopeGuard.check(target_url_or_ip)` is the single choke point
between the planner and the executor.

### 2.8 Reporting Engine
Consumes the knowledge graph post-run and produces:

- `report.md` — human-readable findings with PoC, impact, remediation.
- `report.json` — machine-readable, one object per finding, plus session
  metadata.
- Optional Markdown matching your Obsidian vault's writeup template.

---

## 3. Workflow Model (the loop)

```
while not done(session):
    obs   = session.knowledge.snapshot()
    cands = heuristics.propose(obs)            # deterministic candidates
    cands = llm_planner.rerank(obs, cands)     # LLM-aware priorities
    act   = budget.pick(cands)                 # respect wall-clock/cost
    if not scope.check(act.targets):           # hard reject OOS
        audit.log("scope_reject", act); continue
    raw   = executor.run(act)                  # subprocess + timeout
    obs2  = parser.for_tool(act.tool).parse(raw)
    session.knowledge.commit(obs2)             # dedup + invariant check
    session.hypotheses.update(obs2)            # update attack theories
    budget.charge(act, raw)
```

Stopping conditions (ANY): budget exhausted, heuristics + LLM produce no
new high-value candidate, explicit `--max-iters`, Ctrl-C (graceful),
or `done_reason="report_ready"` emitted by the LLM.

### Per-web-endpoint mini-loop

For each new `Endpoint`:

1. Enumerate methods (`HEAD`, `OPTIONS`, `GET`, `POST`).
2. Discover parameters (Arjun-style, or LLM-guided from response bodies).
3. For each parameter, classify by tainting (reflected / not reflected /
   error-differential / time-differential).
4. Propose vuln classes (XSS, SQLi, SSTI, LFI, SSRF, IDOR, Open Redirect,
   Command Injection). LLM reasoning plus a rules matrix.
5. Probe with minimal, clearly marked payloads. Evaluate response via
   response-diff heuristics — never just "regex `<script>` back".
6. On signal: escalate to the specialized tool (`sqlmap`, targeted fuzz).
7. Record Finding + Evidence; chain (e.g. LFI → /proc/self/environ → RCE
   pivot).

---

## 4. Decision-Making Logic

The planner takes a compact JSON snapshot of the graph and asks the LLM:

> "Given state X and budget Y, what are the top-K most informative next
> actions? Return a ranked JSON list with `tool`, `params`, `reason`, and
> `expected_signal`."

The response is validated against a JSON schema. Invalid output falls back
to the heuristic candidate list. This prevents LLM hallucination from
stalling the run and gives us a deterministic floor.

Key design rules:

- The LLM never executes commands. It only emits structured action objects
  from a **closed vocabulary** of tool+param shapes.
- The planner is allowed to emit `done` or `need_human` — the former ends
  the run, the latter pauses for input in interactive mode.
- Every LLM call includes the current **hypothesis list** so the model
  doesn't re-propose discarded lines of attack.

---

## 5. Memory Design

SQLite file per session (`sessions/<session-id>/knowledge.db`) plus a
mirror JSON export for diffing across runs. Entity tables use natural
unique constraints; observation writes are wrapped in a single
transaction per parser call so partial failures don't corrupt state.

Read API is a thin Python layer (`KnowledgeStore`) with typed accessors
(`hosts()`, `endpoints_for(webapp)`, `findings(severity_gte=...)`) so the
rest of the code never touches raw SQL.

---

## 6. Prompt Engineering

Four prompt roles:

1. **System** — hard-coded rules: authorization assumption, JSON-only
   output, no executing commands, no fabricating evidence.
2. **Planner** — given graph snapshot + budget, rank candidate actions.
3. **Analyzer** — given raw parsed output + existing state, summarize
   what changed and raise anomalies.
4. **Hypothesizer** — given endpoint + parameter + response samples,
   propose ranked vuln classes with expected probes.
5. **Reporter** — given findings + evidence, write the human section of
   the report (title, impact, remediation).

Prompts live in `prompts/*.md` so they can be iterated on without code
changes. Each is versioned; the version is stamped into the audit log.

---

## 7. Modularity & Plugins

Tools, parsers, and planners are discovered via a simple registry:

```python
@register_tool
class NmapTool(Tool):
    name = "nmap"
    ...
```

Third-party plugins can ship as pip-installable packages that expose
`pentagent.plugins` entry points. The config file can enable/disable any
registered tool and override its defaults.

---

## 8. Multi-Model Support

`config.yaml`:

```yaml
llm:
  default: anthropic
  providers:
    anthropic:
      model: claude-opus-4-6
      api_key_env: ANTHROPIC_API_KEY
    openai:
      model: gpt-4.1
      api_key_env: OPENAI_API_KEY
    local:
      base_url: http://127.0.0.1:11434/v1   # Ollama
      model: llama3.1:70b
      api_key_env: OLLAMA_API_KEY           # optional
  routing:
    planner:     anthropic
    analyzer:    anthropic
    reporter:    anthropic
    hypothesizer: local    # cheap/offline fine
```

Swapping providers is a one-line change; the `LLMClient` protocol keeps the
rest of the code ignorant of who's answering.

---

## 9. Future Extensions

- **Active Directory**: add a `windomain/` module pack — enumerate with
  `nxc`/`netexec`, BloodHound ingest, graph merging. Memory already supports
  directed relationships (user→group→machine).
- **Cloud**: AWS/GCP/Azure reconnaissance modules using their SDKs; findings
  become `Cloud*` entity subclasses. ScopeGuard extended to match account IDs
  and resource ARNs.
- **Containers**: Trivy/Grype wrappers + a Dockerfile/Compose analyzer.
- **Exploit dev**: structured debugger driver (`pwndbg`/`gef`/`WinDbg`)
  integrated as a tool, with LLM-driven pattern-offset and ROP-chain
  reasoning. Guardrailed behind `aggressive` + explicit lab scope.
- **Chrome driver**: authenticated crawling via headless Chromium for SPAs.
- **Collaboration**: multi-operator mode with Redis-backed knowledge graph.
- **HITL review gate**: require human approval before anything runs in
  `aggressive` mode, even if scope allows.
