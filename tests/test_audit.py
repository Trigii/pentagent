"""Audit log hash chain."""
from __future__ import annotations

from pentagent.safety import AuditLog


def test_audit_chain_verifies(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    log.log("a", {"i": 1})
    log.log("b", {"i": 2})
    log.log("c", {"i": 3})
    ok, n = log.verify()
    assert ok and n == 3


def test_audit_detects_tamper(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    log.log("a", {"i": 1})
    log.log("b", {"i": 2})
    # Tamper with the second record
    lines = p.read_text().splitlines()
    import json
    rec = json.loads(lines[1])
    rec["payload"]["i"] = 99
    lines[1] = json.dumps(rec, sort_keys=True, default=str)
    p.write_text("\n".join(lines) + "\n")
    log2 = AuditLog(p)
    ok, _ = log2.verify()
    assert not ok
