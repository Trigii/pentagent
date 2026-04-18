"""Token-bucket rate limiter with per-host and global caps.

Used by the executor to prevent the agent from hammering targets. The
limiter exposes a synchronous `acquire()` that sleeps as needed; tools that
want async behavior can call it off the event loop via `anyio.to_thread`.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    capacity: float
    tokens: float
    rate_per_sec: float
    last_refill: float

    def _refill(self, now: float) -> None:
        elapsed = now - self.last_refill
        if elapsed <= 0:
            return
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)
        self.last_refill = now

    def take(self, n: float = 1.0) -> float:
        """Return how long the caller should sleep to obtain `n` tokens."""
        now = time.monotonic()
        self._refill(now)
        if self.tokens >= n:
            self.tokens -= n
            return 0.0
        needed = n - self.tokens
        sleep = needed / self.rate_per_sec
        self.tokens = 0.0
        self.last_refill = now + sleep
        return sleep


class RateLimiter:
    """Per-host + global token-bucket limiter."""

    def __init__(self, *, per_host_rps: int, global_rps: int) -> None:
        self._per_host_rps = per_host_rps
        self._global_rps = global_rps
        now = time.monotonic()
        self._global = _Bucket(
            capacity=global_rps, tokens=global_rps, rate_per_sec=global_rps, last_refill=now
        )
        self._host_buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _bucket_for(self, host: str) -> _Bucket:
        b = self._host_buckets.get(host)
        if b is None:
            now = time.monotonic()
            b = _Bucket(
                capacity=self._per_host_rps,
                tokens=self._per_host_rps,
                rate_per_sec=self._per_host_rps,
                last_refill=now,
            )
            self._host_buckets[host] = b
        return b

    def acquire(self, host: str, cost: float = 1.0) -> None:
        """Blocking acquire; sleeps if necessary to stay under rate caps."""
        with self._lock:
            host_sleep = self._bucket_for(host).take(cost)
            global_sleep = self._global.take(cost)
        sleep = max(host_sleep, global_sleep)
        if sleep > 0:
            time.sleep(sleep)
