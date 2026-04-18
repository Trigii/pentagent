"""SQLite-backed KnowledgeStore.

One DB per session. All entity writes go through `commit(observation)` which
applies upsert-by-natural-key semantics so the same host/service/endpoint is
never stored twice. Reads are offered as simple typed accessors.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

from .models import (
    Endpoint,
    Evidence,
    Finding,
    Host,
    Hypothesis,
    Observation,
    Parameter,
    Service,
    Severity,
    WebApp,
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    hostname TEXT,
    os_guess TEXT,
    UNIQUE(ip, hostname)
);
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    product TEXT,
    version TEXT,
    banner TEXT,
    UNIQUE(host_id, port, proto),
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);
CREATE TABLE IF NOT EXISTS webapps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    scheme TEXT NOT NULL,
    base_url TEXT NOT NULL,
    title TEXT,
    tech TEXT,               -- JSON list
    status_code INTEGER,
    UNIQUE(host_id, base_url),
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    webapp_id INTEGER NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER,
    length INTEGER,
    content_type TEXT,
    params TEXT,             -- JSON list
    UNIQUE(webapp_id, method, path),
    FOREIGN KEY (webapp_id) REFERENCES webapps(id)
);
CREATE TABLE IF NOT EXISTS parameters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    reflected INTEGER DEFAULT 0,
    taints TEXT,             -- JSON list
    UNIQUE(endpoint_id, name, location),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request TEXT,
    response TEXT,
    payload TEXT,
    raw_excerpt TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    evidence_id INTEGER,
    confidence REAL DEFAULT 0.5,
    title TEXT NOT NULL,
    description TEXT,
    recommendation TEXT,
    source_tool TEXT,
    template_id TEXT,
    UNIQUE(kind, entity_type, entity_id, template_id),
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
);
CREATE TABLE IF NOT EXISTS hypotheses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ref TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    reasoning TEXT,
    attempted TEXT,          -- JSON list
    status TEXT DEFAULT 'open',
    UNIQUE(target_ref, vuln_class)
);
CREATE TABLE IF NOT EXISTS action_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    params TEXT NOT NULL,    -- JSON
    started_at REAL,
    finished_at REAL,
    exit_code INTEGER,
    cache_key TEXT,
    UNIQUE(cache_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_endpoints_webapp ON endpoints(webapp_id);
"""


def _json(val) -> str:
    import json as _json_mod
    return _json_mod.dumps(val or [])


def _parse_json(val) -> list:
    import json as _json_mod
    if not val:
        return []
    try:
        return _json_mod.loads(val)
    except Exception:
        return []


class KnowledgeStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.Lock()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ------------------------ commit pipeline -----------------------------

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def commit(self, obs: Observation) -> dict[str, int]:
        """Upsert all entities in the observation; return counts by kind.

        Parsers may emit placeholder `host_id`/`webapp_id`/`endpoint_id`
        values (negative integers treated as references into obs.hosts/
        obs.webapps/obs.endpoints by order). We remap those to real row
        ids here, so parsers don't have to care about DB state.
        """
        counts = {k: 0 for k in ("hosts", "services", "webapps", "endpoints",
                                 "parameters", "evidence", "findings")}
        # Placeholder convention: negative ids point at indexes
        #   host_id = -(i+1)   -> obs.hosts[i]
        #   webapp_id = -(i+1) -> obs.webapps[i]
        #   endpoint_id = -(i+1) -> obs.endpoints[i]
        def resolve(pid: int, bucket: list) -> int:
            if pid >= 0:
                return pid
            idx = -pid - 1
            if 0 <= idx < len(bucket) and bucket[idx].id is not None:
                return int(bucket[idx].id)
            raise ValueError(f"unresolved placeholder id {pid}")

        with self._tx() as c:
            # Hosts first — children FK into them
            for h in obs.hosts:
                h.id = self._upsert_host(c, h)
                counts["hosts"] += 1
            # Services
            for s in obs.services:
                s.host_id = resolve(s.host_id, obs.hosts)
                s.id = self._upsert_service(c, s)
                counts["services"] += 1
            # WebApps (host_id must exist)
            for w in obs.webapps:
                w.host_id = resolve(w.host_id, obs.hosts)
                w.id = self._upsert_webapp(c, w)
                counts["webapps"] += 1
            # Endpoints
            for e in obs.endpoints:
                e.webapp_id = resolve(e.webapp_id, obs.webapps)
                e.id = self._upsert_endpoint(c, e)
                counts["endpoints"] += 1
            # Parameters
            for p in obs.parameters:
                p.endpoint_id = resolve(p.endpoint_id, obs.endpoints)
                p.id = self._upsert_parameter(c, p)
                counts["parameters"] += 1
            # Evidence (must precede findings that reference it)
            for ev in obs.evidence:
                ev.id = self._insert_evidence(c, ev)
                counts["evidence"] += 1
            # Findings
            for f in obs.findings:
                f.id = self._upsert_finding(c, f)
                counts["findings"] += 1
        return counts

    # ------------------------ upserts -------------------------------------

    def _upsert_host(self, c, h: Host) -> int:
        row = c.execute(
            "SELECT id FROM hosts WHERE (ip IS ? OR ip = ?) AND (hostname IS ? OR hostname = ?)",
            (h.ip, h.ip, h.hostname, h.hostname),
        ).fetchone()
        if row:
            if h.os_guess:
                c.execute("UPDATE hosts SET os_guess = ? WHERE id = ?", (h.os_guess, row["id"]))
            return int(row["id"])
        cur = c.execute(
            "INSERT INTO hosts(ip, hostname, os_guess) VALUES (?, ?, ?)",
            (h.ip, h.hostname, h.os_guess),
        )
        return int(cur.lastrowid)

    def _upsert_service(self, c, s: Service) -> int:
        row = c.execute(
            "SELECT id FROM services WHERE host_id = ? AND port = ? AND proto = ?",
            (s.host_id, s.port, s.proto),
        ).fetchone()
        if row:
            c.execute(
                "UPDATE services SET product = COALESCE(?, product), "
                "version = COALESCE(?, version), banner = COALESCE(?, banner) WHERE id = ?",
                (s.product, s.version, s.banner, row["id"]),
            )
            return int(row["id"])
        cur = c.execute(
            "INSERT INTO services(host_id, port, proto, product, version, banner) VALUES (?, ?, ?, ?, ?, ?)",
            (s.host_id, s.port, s.proto, s.product, s.version, s.banner),
        )
        return int(cur.lastrowid)

    def _upsert_webapp(self, c, w: WebApp) -> int:
        row = c.execute(
            "SELECT id FROM webapps WHERE host_id = ? AND base_url = ?",
            (w.host_id, w.base_url),
        ).fetchone()
        if row:
            c.execute(
                "UPDATE webapps SET scheme = ?, title = COALESCE(?, title), "
                "tech = ?, status_code = COALESCE(?, status_code) WHERE id = ?",
                (w.scheme, w.title, _json(w.tech), w.status_code, row["id"]),
            )
            return int(row["id"])
        cur = c.execute(
            "INSERT INTO webapps(host_id, scheme, base_url, title, tech, status_code) VALUES (?, ?, ?, ?, ?, ?)",
            (w.host_id, w.scheme, w.base_url, w.title, _json(w.tech), w.status_code),
        )
        return int(cur.lastrowid)

    def _upsert_endpoint(self, c, e: Endpoint) -> int:
        row = c.execute(
            "SELECT id FROM endpoints WHERE webapp_id = ? AND method = ? AND path = ?",
            (e.webapp_id, e.method.upper(), e.path),
        ).fetchone()
        if row:
            c.execute(
                "UPDATE endpoints SET status = COALESCE(?, status), length = COALESCE(?, length), "
                "content_type = COALESCE(?, content_type), params = ? WHERE id = ?",
                (e.status, e.length, e.content_type, _json(e.params), row["id"]),
            )
            return int(row["id"])
        cur = c.execute(
            "INSERT INTO endpoints(webapp_id, method, path, status, length, content_type, params) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (e.webapp_id, e.method.upper(), e.path, e.status, e.length, e.content_type, _json(e.params)),
        )
        return int(cur.lastrowid)

    def _upsert_parameter(self, c, p: Parameter) -> int:
        row = c.execute(
            "SELECT id FROM parameters WHERE endpoint_id = ? AND name = ? AND location = ?",
            (p.endpoint_id, p.name, p.location),
        ).fetchone()
        if row:
            c.execute(
                "UPDATE parameters SET reflected = ?, taints = ? WHERE id = ?",
                (int(p.reflected), _json(p.taints), row["id"]),
            )
            return int(row["id"])
        cur = c.execute(
            "INSERT INTO parameters(endpoint_id, name, location, reflected, taints) VALUES (?, ?, ?, ?, ?)",
            (p.endpoint_id, p.name, p.location, int(p.reflected), _json(p.taints)),
        )
        return int(cur.lastrowid)

    def _insert_evidence(self, c, ev: Evidence) -> int:
        cur = c.execute(
            "INSERT INTO evidence(request, response, payload, raw_excerpt) VALUES (?, ?, ?, ?)",
            (ev.request, ev.response, ev.payload, ev.raw_excerpt),
        )
        return int(cur.lastrowid)

    def _upsert_finding(self, c, f: Finding) -> int:
        row = c.execute(
            "SELECT id FROM findings WHERE kind = ? AND entity_type = ? AND entity_id = ? AND "
            "(template_id IS ? OR template_id = ?)",
            (f.kind, f.entity_type, f.entity_id, f.template_id, f.template_id),
        ).fetchone()
        if row:
            c.execute(
                "UPDATE findings SET severity = ?, evidence_id = COALESCE(?, evidence_id), "
                "confidence = ?, title = ?, description = ?, recommendation = ?, source_tool = ? "
                "WHERE id = ?",
                (
                    f.severity.value if isinstance(f.severity, Severity) else str(f.severity),
                    f.evidence_id,
                    f.confidence,
                    f.title,
                    f.description,
                    f.recommendation,
                    f.source_tool,
                    row["id"],
                ),
            )
            return int(row["id"])
        cur = c.execute(
            "INSERT INTO findings(kind, severity, entity_type, entity_id, evidence_id, confidence, "
            "title, description, recommendation, source_tool, template_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f.kind,
                f.severity.value if isinstance(f.severity, Severity) else str(f.severity),
                f.entity_type,
                f.entity_id,
                f.evidence_id,
                f.confidence,
                f.title,
                f.description,
                f.recommendation,
                f.source_tool,
                f.template_id,
            ),
        )
        return int(cur.lastrowid)

    # ------------------------ hypotheses ----------------------------------

    def upsert_hypothesis(self, h: Hypothesis) -> int:
        with self._tx() as c:
            row = c.execute(
                "SELECT id FROM hypotheses WHERE target_ref = ? AND vuln_class = ?",
                (h.target_ref, h.vuln_class),
            ).fetchone()
            if row:
                c.execute(
                    "UPDATE hypotheses SET reasoning = ?, attempted = ?, status = ? WHERE id = ?",
                    (h.reasoning, _json(h.attempted), h.status, row["id"]),
                )
                return int(row["id"])
            cur = c.execute(
                "INSERT INTO hypotheses(target_ref, vuln_class, reasoning, attempted, status) "
                "VALUES (?, ?, ?, ?, ?)",
                (h.target_ref, h.vuln_class, h.reasoning, _json(h.attempted), h.status),
            )
            return int(cur.lastrowid)

    # ------------------------ reads ---------------------------------------

    def hosts(self) -> list[Host]:
        rows = self._conn.execute("SELECT * FROM hosts").fetchall()
        return [Host(**dict(r)) for r in rows]

    def webapps(self) -> list[WebApp]:
        rows = self._conn.execute("SELECT * FROM webapps").fetchall()
        return [WebApp(**{**dict(r), "tech": _parse_json(r["tech"])}) for r in rows]

    def services(self, host_id: int | None = None) -> list[Service]:
        if host_id is None:
            rows = self._conn.execute("SELECT * FROM services").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM services WHERE host_id = ?", (host_id,)
            ).fetchall()
        return [Service(**dict(r)) for r in rows]

    def endpoints(self, webapp_id: int | None = None) -> list[Endpoint]:
        if webapp_id is None:
            rows = self._conn.execute("SELECT * FROM endpoints").fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM endpoints WHERE webapp_id = ?", (webapp_id,)).fetchall()
        return [Endpoint(**{**dict(r), "params": _parse_json(r["params"])}) for r in rows]

    def findings(self, *, severity_gte: Severity | None = None) -> list[Finding]:
        order = ["info", "low", "medium", "high", "critical"]
        if severity_gte is None:
            rows = self._conn.execute("SELECT * FROM findings").fetchall()
        else:
            floor = order.index(severity_gte.value)
            allowed = ",".join(f"'{s}'" for s in order[floor:])
            rows = self._conn.execute(
                f"SELECT * FROM findings WHERE severity IN ({allowed})"
            ).fetchall()
        return [Finding(**dict(r)) for r in rows]

    def hypotheses(self, *, status: str | None = None) -> list[Hypothesis]:
        if status:
            rows = self._conn.execute(
                "SELECT * FROM hypotheses WHERE status = ?", (status,)
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM hypotheses").fetchall()
        return [
            Hypothesis(**{**dict(r), "attempted": _parse_json(r["attempted"])}) for r in rows
        ]

    # ------------------------ action caching ------------------------------

    def action_cached(self, cache_key: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM action_log WHERE cache_key = ?", (cache_key,)
        ).fetchone()
        return row is not None

    def record_action(
        self, *, tool: str, params_json: str, started_at: float, finished_at: float,
        exit_code: int, cache_key: str,
    ) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT OR IGNORE INTO action_log(tool, params, started_at, finished_at, exit_code, cache_key) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (tool, params_json, started_at, finished_at, exit_code, cache_key),
            )

    # ------------------------ snapshot for LLM ----------------------------

    def snapshot(self) -> dict:
        """Compact JSON-serializable view of the graph, fed to the planner."""
        return {
            "hosts": [h.model_dump() for h in self.hosts()],
            "webapps": [w.model_dump() for w in self.webapps()],
            "endpoints": [e.model_dump() for e in self.endpoints()],
            "findings": [f.model_dump() for f in self.findings()],
            "hypotheses": [h.model_dump() for h in self.hypotheses()],
        }
