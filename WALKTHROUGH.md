# Example Execution Walkthrough

Target: `https://api.example.com` under the bug bounty program `example-bounty-program`, which has the following scope file:

```yaml
include:   ["*.example.com", "example.com"]
exclude:   ["admin.example.com", "*.staff.example.com"]
aggressive_opt_in: ["api.example.com"]
```

Invocation:

```bash
pentagent run \
    --config ./config/config.yaml \
    --scope ./config/scope.yaml \
    --target https://api.example.com \
    --mode aggressive \
    --i-have-authorization
```

## Iter 0 — session bootstrap

1. CLI prints the banner + authorization reminder.
2. `Settings.load()` + `Scope.load()` succeed. The scope file must have
   `program_name`, `authorized_by`, `authorized_on`, `authorization_source`,
   `operator` filled in or the agent refuses to start.
3. `ScopeGuard.check("https://api.example.com")` passes because
   `api.example.com` matches `*.example.com` in include and is also in the
   `aggressive_opt_in` list.
4. A `sessions/2026-04-18_HH-MM-SS_abc/` directory is created. `audit.jsonl`
   and `knowledge.db` are initialized. The `session_start` record is written
   with program name, operator email, scope hash, and seed targets.

## Iter 1 — passive subdomain enumeration

- Heuristic planner sees: no subfinder results for `api.example.com`'s
  parent domain.
- Proposes `Action(tool="subfinder", params={"domain": "example.com"}, priority=high)`.
- LLM planner re-ranks: keeps it at 10 (correct — we have nothing else yet).
- `Executor.run("subfinder", ...)` checks scope (`example.com` is in
  include), rate-limits (first request, no wait), spawns `subfinder -silent -d example.com`.
- Parser emits `Observation` with `hosts=[...]` for each discovered
  subdomain. `commit()` inserts unique hosts; duplicates collapse on the
  `(ip, hostname)` natural key.

## Iter 2 — HTTP probe

- Heuristic planner sees: N hosts in the graph without an httpx probe.
- Proposes one batched `Action(tool="httpx", params={"targets": [...]})`.
- Scope check filters the list — `admin.example.com` and anything under
  `*.staff.example.com` are dropped here.
- httpx runs, emits JSONL lines. Parser builds `Host` + `WebApp` + root
  `Endpoint` records with tech fingerprints (`["nginx", "php", "jquery"]`).

## Iter 3 — content discovery

- For each new `WebApp`, heuristic proposes `ffuf` against
  `${base_url}/FUZZ` with the configured wordlist.
- LLM sees the tech stack (`nginx + php`) and bumps the priority on
  `www.example.com` (where PHP is present) and reasons: _"PHP typically has
  `/admin/`, `/uploads/`, `/phpinfo.php` worth probing"_. It emits a
  `new_action` proposing an extra ffuf run with a PHP-oriented wordlist;
  the action is validated (tool name is in the vocabulary, params shape
  matches) before being accepted.
- ffuf emits JSON, parser creates `Endpoint` rows bound to the correct
  `webapp_id` via parser context.

## Iter 4 — vulnerability scan

- Heuristic proposes `nuclei` for each webapp.
- Scope check re-applies (on every iteration).
- nuclei's JSONL stream is parsed into `Finding` + `Evidence` records,
  entity-bound to the `WebApp`. Template ids provide the natural-key
  dedup so a re-run won't duplicate rows.

## Iter 5 — parameter-based exploitation (aggressive only)

- Planner enumerates endpoints with query strings on
  `api.example.com` (the only host in `aggressive_opt_in`).
- `Action(tool="sqlmap", params={"url": ".../items?id=1", "risk": 1, "level": 1})`.
- Mode gate permits (session is aggressive). Scope re-checks with
  `aggressive=True` — passes for this host.
- sqlmap runs; parser finds _"Parameter 'id' is vulnerable"_ and emits a
  `Finding(kind="sqli", severity=high, confidence=0.95)`.

## Iter 6..N — iterate

The loop continues. The LLM may eventually return `done=true`, or the
wall-clock / iteration / cost budget is hit.

## Report

After `session_end`:

- `runs/<session>/report.md` is written with summary + per-finding sections.
- `runs/<session>/report.json` contains machine-readable data.
- `runs/<session>/audit.jsonl` contains every proposed / rejected /
  executed action with a hash chain — `pentagent verify-audit` confirms
  nothing was edited.

## What the LLM never does

- It never receives shell access and never has a `run_command` capability.
- Its responses are validated against a JSON schema. Anything not matching
  is dropped, falling back to the heuristic plan.
- Tool names it proposes must already appear in the candidate list.
- Scope and mode gates re-check every action independently of anything
  the LLM said.

## What the scope guard stops

A few real examples of rejection events that would appear in `audit.jsonl`:

- LLM proposed `httpx` against `admin.example.com` → `exec_rejected`
  (`reason="scope_reject: admin.example.com is in the scope EXCLUDE list"`).
- An endpoint lookup leaked an IP `10.0.0.5` that isn't in include → same.
- An aggressive `sqlmap` was proposed against `www.example.com`, which is
  in include but not in `aggressive_opt_in` → `exec_rejected`
  (`reason="scope_reject: not in aggressive_opt_in"`).
