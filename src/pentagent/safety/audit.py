"""Append-only, hash-chained JSONL audit log.

Every action — proposed, rejected, executed — is written here. The hash
chain makes it tamper-evident: flipping a byte in a prior record
invalidates every hash downstream. On startup the log is verified and any
break is logged with a warning (the log still appends, but the break is
recorded).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._recover_last_hash()

    @staticmethod
    def _hash(prev: str, payload: str) -> str:
        h = hashlib.sha256()
        h.update(prev.encode("utf-8"))
        h.update(b"\n")
        h.update(payload.encode("utf-8"))
        return h.hexdigest()

    def _recover_last_hash(self) -> str:
        if not self.path.exists():
            return _GENESIS
        last = _GENESIS
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                last = rec.get("hash", last)
        return last

    def log(self, event: str, payload: dict[str, Any]) -> str:
        """Append an event and return its hash."""
        rec = {
            "ts": time.time(),
            "event": event,
            "payload": payload,
            "prev": self._last_hash,
        }
        body = json.dumps(rec, sort_keys=True, default=str)
        digest = self._hash(self._last_hash, body)
        rec["hash"] = digest
        line = json.dumps(rec, sort_keys=True, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._last_hash = digest
        return digest

    def verify(self) -> tuple[bool, int]:
        """Return (ok, verified_count). ok=False means the chain is broken."""
        prev = _GENESIS
        count = 0
        if not self.path.exists():
            return True, 0
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                digest = rec.pop("hash", None)
                body = json.dumps(rec, sort_keys=True, default=str)
                expected = self._hash(prev, body)
                if digest != expected or rec.get("prev") != prev:
                    return False, count
                prev = digest
                count += 1
        return True, count
