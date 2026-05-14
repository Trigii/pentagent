"""Passive reconnaissance — stdlib-only DNS & certificate transparency.

Design goals mirror `cve.py`:

1. **Offline-safe.** Every network call is wrapped in a try/except. A run
   with no internet must not crash — lookups that fail return empty.

2. **Zero extra dependencies.** Uses `urllib` for HTTP (crt.sh) and
   `socket` for DNS. `dnspython` is *optional* — if present we upgrade
   to TXT/MX/NS lookups, otherwise we degrade gracefully to A/AAAA +
   reverse DNS. A pentester on a locked-down VM still gets useful data.

3. **Cache-first.** crt.sh is a public CT log that rate-limits
   aggressive querying. Every successful lookup is cached to the
   session directory's `passive_recon_cache/` folder. Re-runs hit the
   cache instantly and avoid burning credit at crt.sh.

4. **Scope-aware callers.** This module *discovers* — it does not
   *touch*. Callers pair the returned subdomains with ScopeGuard to
   decide which newly-learned hosts are in-scope for active probing.
   Out-of-scope subdomains are still worth recording (they're evidence
   of adjacent attack surface) but the orchestrator won't target them.

5. **Actionable output.** Returned as plain dicts so the orchestrator
   can trivially feed them into the `Observation` graph (new Host rows,
   optionally new WebApp rows once httpx confirms 80/443 is open).

References:
  - crt.sh JSON API: https://crt.sh/?q=<domain>&output=json
  - RFC 1035 (DNS): https://www.rfc-editor.org/rfc/rfc1035
"""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..logging_setup import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# crt.sh — certificate transparency subdomain enumeration
# ---------------------------------------------------------------------------

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CRTSH_TIMEOUT_S = 15.0
CRTSH_MAX_RETRIES = 2
CRTSH_UA = (
    "pentagent-passive-recon/1.0 (+https://github.com/anthropics/pentagent)"
)


@dataclass
class CrtshEntry:
    common_name: str
    name_value: list[str] = field(default_factory=list)
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""


def _cache_path(cache_dir: Path, kind: str, key: str) -> Path:
    """Deterministic cache filename per (kind, key)."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in key.lower())
    return cache_dir / f"{kind}_{safe}.json"


def _http_get_json(url: str, timeout: float = CRTSH_TIMEOUT_S) -> object | None:
    req = urllib.request.Request(url, headers={"User-Agent": CRTSH_UA})
    for attempt in range(CRTSH_MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.debug(f"crt.sh non-200: {resp.status} for {url}")
                    return None
                body = resp.read().decode("utf-8", errors="replace")
                if not body.strip():
                    return []
                return json.loads(body)
        except json.JSONDecodeError as e:
            logger.debug(f"crt.sh JSON decode failed: {e}")
            return None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt < CRTSH_MAX_RETRIES:
                backoff = 1.5 * (attempt + 1)
                logger.debug(f"crt.sh retry {attempt + 1} after {backoff}s: {e}")
                time.sleep(backoff)
                continue
            logger.debug(f"crt.sh gave up on {url}: {e}")
            return None
    return None


def crtsh_subdomains(
    domain: str,
    *,
    cache_dir: Path | None = None,
    force_refresh: bool = False,
) -> list[str]:
    """Return the unique, lowercased subdomain set for `domain` from
    certificate transparency logs. Includes the bare apex.

    Wildcards (`*.foo.bar.com`) are stripped — the `*` prefix is removed
    and the remainder joins the set.

    Best-effort: returns `[]` if crt.sh is unreachable or empty.
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain or "." not in domain:
        return []

    cached: list[str] | None = None
    if cache_dir and not force_refresh:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cp = _cache_path(cache_dir, "crtsh", domain)
        if cp.exists():
            try:
                cached = json.loads(cp.read_text(encoding="utf-8"))
                if isinstance(cached, list):
                    return sorted({str(x).lower() for x in cached if x})
            except (json.JSONDecodeError, OSError) as e:
                logger.debug(f"crt.sh cache read failed for {domain}: {e}")
                cached = None

    url = CRTSH_URL.format(domain=domain)
    data = _http_get_json(url)
    if data is None:
        return []

    subs: set[str] = set()
    if isinstance(data, list):
        for row in data:
            if not isinstance(row, dict):
                continue
            # Both `common_name` and newline-separated `name_value` can
            # carry subdomains. crt.sh returns duplicates — the set dedupes.
            for field_name in ("common_name", "name_value"):
                v = row.get(field_name)
                if isinstance(v, str):
                    for name in v.splitlines():
                        n = name.strip().lower().lstrip("*.").rstrip(".")
                        # Only keep names under the queried domain — crt.sh
                        # wildcards sometimes return unrelated entries.
                        if n and (n == domain or n.endswith("." + domain)):
                            subs.add(n)

    result = sorted(subs)
    if cache_dir and result:
        try:
            _cache_path(cache_dir, "crtsh", domain).write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
        except OSError as e:
            logger.debug(f"crt.sh cache write failed for {domain}: {e}")

    return result


# ---------------------------------------------------------------------------
# DNS — stdlib A/AAAA, reverse PTR, optional dnspython for MX/TXT/NS
# ---------------------------------------------------------------------------

@dataclass
class DnsRecord:
    name: str
    record_type: str
    value: str


def dns_a_aaaa(host: str) -> list[DnsRecord]:
    """Resolve A and AAAA records via socket.getaddrinfo (always stdlib)."""
    host = host.strip().lower()
    if not host:
        return []
    out: list[DnsRecord] = []
    seen: set[tuple[str, str]] = set()
    try:
        for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
            family = info[0]
            ip = info[4][0].split("%", 1)[0]
            rtype = "AAAA" if family == socket.AF_INET6 else "A"
            k = (rtype, ip)
            if k in seen:
                continue
            seen.add(k)
            out.append(DnsRecord(name=host, record_type=rtype, value=ip))
    except (socket.gaierror, UnicodeError, OSError) as e:
        logger.debug(f"DNS A/AAAA lookup failed for {host}: {e}")
    return out


def dns_ptr(ip: str) -> list[DnsRecord]:
    """Reverse DNS — return the PTR record(s) for `ip`."""
    ip = ip.strip()
    if not ip:
        return []
    try:
        name, _aliases, _addrs = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError) as e:
        logger.debug(f"DNS PTR lookup failed for {ip}: {e}")
        return []
    return [DnsRecord(name=ip, record_type="PTR", value=name.lower().rstrip("."))]


def dns_extended(host: str) -> list[DnsRecord]:
    """TXT / MX / NS / CNAME lookups via dnspython when available.

    Returns [] when dnspython isn't installed — the caller shouldn't
    treat that as an error. A/AAAA is still available via
    `dns_a_aaaa`.
    """
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except ImportError:
        logger.debug("dnspython not installed — skipping TXT/MX/NS lookups")
        return []

    host = host.strip().lower().rstrip(".")
    if not host:
        return []

    out: list[DnsRecord] = []
    for rtype in ("CNAME", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=5.0)
        except Exception as e:  # dns.resolver raises many subclasses
            logger.debug(f"DNS {rtype} for {host} failed: {e}")
            continue
        for a in answers:
            val = str(a).strip().strip('"').rstrip(".")
            if val:
                out.append(DnsRecord(name=host, record_type=rtype, value=val))
    return out


# ---------------------------------------------------------------------------
# High-level entry point
# ---------------------------------------------------------------------------

@dataclass
class PassiveReconResult:
    apex: str
    subdomains: list[str] = field(default_factory=list)   # from crt.sh
    dns_records: list[DnsRecord] = field(default_factory=list)  # per subdomain
    # Per-subdomain resolved IPs, useful for the orchestrator to add Host rows
    resolved: dict[str, list[str]] = field(default_factory=dict)


def enumerate_domain(
    apex: str,
    *,
    cache_dir: Path | None = None,
    include_extended_dns: bool = True,
    max_subdomains: int = 500,
) -> PassiveReconResult:
    """End-to-end passive enumeration of `apex`:
        1. crt.sh → subdomain list
        2. A/AAAA resolve each subdomain
        3. Optional TXT/MX/NS for the apex (dnspython if available)

    `max_subdomains` is a guard against pathological CT-log dumps that
    can return 10k+ names; the agent caps to the first N lexically-
    sorted (which tends to bias toward short-named infra like `api.`,
    `mail.`, `admin.`, which is what we want).
    """
    apex = apex.strip().lower().rstrip(".")
    out = PassiveReconResult(apex=apex)
    if not apex or "." not in apex:
        return out

    # 1. Certificate transparency
    subs = crtsh_subdomains(apex, cache_dir=cache_dir)
    if len(subs) > max_subdomains:
        logger.debug(f"crt.sh returned {len(subs)} for {apex}; truncating to {max_subdomains}")
        subs = subs[:max_subdomains]
    out.subdomains = subs

    # Always include the apex itself
    targets = [apex] + [s for s in subs if s != apex]

    # 2. A/AAAA per subdomain
    for host in targets:
        records = dns_a_aaaa(host)
        if not records:
            continue
        out.dns_records.extend(records)
        ips = sorted({r.value for r in records})
        out.resolved[host] = ips

    # 3. Apex TXT/MX/NS (optional, only meaningful for the apex)
    if include_extended_dns:
        out.dns_records.extend(dns_extended(apex))

    return out


__all__ = [
    "CrtshEntry",
    "DnsRecord",
    "PassiveReconResult",
    "crtsh_subdomains",
    "dns_a_aaaa",
    "dns_ptr",
    "dns_extended",
    "enumerate_domain",
]
