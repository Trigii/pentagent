"""CVE enrichment via NVD 2.0 REST API.

Design goals:

1. **Offline-safe.** A run with no internet must not crash; lookups that
   fail return an empty list and the caller continues with whatever
   intel the scanners produced.

2. **Zero extra dependencies.** Uses stdlib `urllib` so this module works
   on any environment with Python 3.11+. No `requests`, no `httpx-python`.

3. **Cache-first.** Every lookup is cached to a JSON file in the session
   directory. Re-runs of the same session hit the cache instantly; a new
   session starts fresh. This matters because NVD rate-limits
   unauthenticated callers to 5 req/30s — a busy pentest on a target with
   a big tech stack would otherwise trip the limit.

4. **Best-effort CPE construction.** We don't require the user to know
   CPE syntax. Given a product/version pair, we synthesize a loose CPE
   string and fall back to keyword search if that returns nothing. The
   keyword path is less precise but cheap insurance against vendor-name
   mismatches (e.g. "Apache" vs "apache-httpd").

5. **Actionable output.** Each `CVERecord` carries a CVSS v3 base score,
   severity label, and a boolean `has_exploit` heuristic (true if any
   reference tag mentions "Exploit"). Downstream consumers use these to
   prioritize findings in the report and the planner.

Notes on ATT&CK mapping: CVEs created here carry `finding.kind = "cve"`
which routes through FINDING_MAPPING → CWE-1395 / OWASP A06 / T1190. That
tag is applied downstream by the reporter, not here.

References:
  - NVD 2.0 API: https://nvd.nist.gov/developers/vulnerabilities
  - CVSS 3.1: https://www.first.org/cvss/v3.1/specification-document
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any

from ..logging_setup import get_logger
from ..memory import Evidence, Finding, KnowledgeStore, Observation, Service, Severity, WebApp


logger = get_logger(__name__)


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "pentagent-cve-enricher/1.0 (+https://github.com/tristan/pentagent)"
DEFAULT_TIMEOUT_S = 6.0
# Hard ceiling on CVEs per product — NVD can return thousands for old
# well-known products; more than 25 is usually just noise for a report.
MAX_CVES_PER_PRODUCT = 25
# Minimum CVSS to keep — filters out positional/info noise during triage.
DEFAULT_MIN_CVSS = 4.0


_CVSS_TO_SEVERITY: list[tuple[float, Severity]] = [
    (9.0, Severity.critical),
    (7.0, Severity.high),
    (4.0, Severity.medium),
    (0.1, Severity.low),
]


def _sev_for_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.info
    for threshold, sev in _CVSS_TO_SEVERITY:
        if score >= threshold:
            return sev
    return Severity.info


@dataclass
class CVERecord:
    cve_id: str
    cvss_v3: float | None = None
    cvss_severity: str = "UNKNOWN"      # NVD label: NONE/LOW/MEDIUM/HIGH/CRITICAL
    summary: str = ""
    published: str | None = None
    has_exploit: bool = False           # heuristic from reference tags
    references: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------- Enricher

class CVEEnricher:
    """Wraps NVD queries with caching. One instance per session.

    Cache file layout::

        {
            "by_key": {
                "<product>|<version|*>": [<CVERecord dict>, ...],
                ...
            },
            "negative": {
                "<product>|<version|*>": <epoch seconds>
                (a short-lived "no results" TTL; avoids repeat burns on
                 products NVD doesn't know about)
            }
        }

    The cache is append-only per session and survives process restarts as
    long as the session directory is reused.
    """

    NEGATIVE_TTL_S = 3600 * 24      # "no results" valid for 24h

    def __init__(
        self,
        cache_path: Path,
        *,
        enabled: bool = True,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        min_cvss: float = DEFAULT_MIN_CVSS,
        api_key: str | None = None,
    ) -> None:
        self.cache_path = Path(cache_path)
        self.enabled = bool(enabled)
        self.timeout_s = float(timeout_s)
        self.min_cvss = float(min_cvss)
        self.api_key = api_key
        self._cache: dict[str, Any] = {"by_key": {}, "negative": {}}
        if self.cache_path.exists():
            try:
                self._cache = json.loads(self.cache_path.read_text())
                self._cache.setdefault("by_key", {})
                self._cache.setdefault("negative", {})
            except Exception as e:
                logger.debug(f"CVE cache read failed, starting fresh: {e}")
                self._cache = {"by_key": {}, "negative": {}}

    # ---------------------------------------------------------- cache I/O

    def _save(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache, indent=2))
        except Exception as e:
            logger.debug(f"CVE cache write failed: {e}")

    @staticmethod
    def _cache_key(product: str, version: str | None) -> str:
        return f"{(product or '').strip().lower()}|{(version or '*').strip().lower()}"

    # ---------------------------------------------------------- public API

    def lookup(self, product: str, version: str | None = None) -> list[CVERecord]:
        """Return a list of CVERecords for `product`/`version`, empty on miss.

        Cache order:
          1. Positive hit → return cached list.
          2. Negative hit within TTL → return [] without hitting the network.
          3. Cold → query NVD, store result (positive or negative), return.

        If the enricher is disabled or network calls fail, we return [].
        """
        if not self.enabled or not product:
            return []
        key = self._cache_key(product, version)

        hit = self._cache["by_key"].get(key)
        if hit is not None:
            return [CVERecord(**h) for h in hit]

        neg = self._cache["negative"].get(key)
        if neg is not None and (time.time() - float(neg)) < self.NEGATIVE_TTL_S:
            return []

        records = self._query_nvd(product, version)
        if records:
            self._cache["by_key"][key] = [r.as_dict() for r in records]
        else:
            self._cache["negative"][key] = time.time()
        self._save()
        return records

    # ---------------------------------------------------------- NVD query

    def _build_params(self, product: str, version: str | None) -> dict[str, str]:
        """Prefer CPE-based query; fall back to keyword search when no
        version (keyword is less precise but catches more hits)."""
        if version:
            # cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
            # We don't always know the vendor — wildcard it; NVD accepts.
            cpe = f"cpe:2.3:a:*:{product.lower()}:{version}:*:*:*:*:*:*:*"
            return {
                "cpeName": cpe,
                "resultsPerPage": str(MAX_CVES_PER_PRODUCT),
            }
        # Keyword search: get the top hits for the product name.
        return {
            "keywordSearch": product,
            "keywordExactMatch": "",
            "resultsPerPage": str(MAX_CVES_PER_PRODUCT),
        }

    def _query_nvd(self, product: str, version: str | None) -> list[CVERecord]:
        params = self._build_params(product, version)
        # Strip empty values NVD rejects
        params = {k: v for k, v in params.items() if v != "" or k == "keywordExactMatch"}
        qs = urllib.parse.urlencode(params)
        url = f"{NVD_URL}?{qs}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        if self.api_key:
            req.add_header("apiKey", self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = resp.read().decode("utf-8", "replace")
            data = json.loads(body)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            logger.debug(f"NVD lookup failed for {product} {version or '*'}: {e}")
            return []
        except Exception as e:
            logger.debug(f"NVD unexpected error for {product}: {e}")
            return []

        items = data.get("vulnerabilities") or []
        out: list[CVERecord] = []
        for entry in items:
            cve = entry.get("cve") or {}
            cve_id = cve.get("id") or ""
            if not cve_id:
                continue
            # Pick the best-available CVSS v3 score (NVD nests v31 then v30)
            metrics = cve.get("metrics") or {}
            score: float | None = None
            sev_label = "UNKNOWN"
            for k in ("cvssMetricV31", "cvssMetricV30"):
                arr = metrics.get(k) or []
                if arr:
                    data3 = arr[0].get("cvssData") or {}
                    score = _safe_float(data3.get("baseScore"))
                    sev_label = str(data3.get("baseSeverity") or "UNKNOWN")
                    break
            if score is not None and score < self.min_cvss:
                continue
            # Description (English)
            desc = ""
            for d in cve.get("descriptions") or []:
                if d.get("lang") == "en":
                    desc = d.get("value") or ""
                    break
            # References + exploit heuristic
            refs: list[str] = []
            has_exploit = False
            for r in cve.get("references") or []:
                u = r.get("url") or ""
                if u:
                    refs.append(u)
                tags = [t.lower() for t in (r.get("tags") or [])]
                if any("exploit" in t for t in tags):
                    has_exploit = True
            published = cve.get("published")
            out.append(CVERecord(
                cve_id=cve_id,
                cvss_v3=score,
                cvss_severity=sev_label,
                summary=desc[:400],
                published=published,
                has_exploit=has_exploit,
                references=refs[:6],
            ))
            if len(out) >= MAX_CVES_PER_PRODUCT:
                break
        # Sort: exploit-available first, then by CVSS desc
        out.sort(key=lambda r: (-(1 if r.has_exploit else 0), -(r.cvss_v3 or 0)))
        return out


def _safe_float(v: Any) -> float | None:
    try:
        if v is None:
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- Helpers

# Tech tokens that show up in httpx output but aren't worth querying
# (marketing/CSS/low-value framework tags). Keeps NVD calls focused.
_TECH_NOISE = {
    "html", "html5", "http", "https", "http/2", "tls", "javascript", "css",
    "ajax", "jquery-ui", "bootstrap-theme", "font-awesome", "google-analytics",
    "cookie", "json", "rss", "xml", "gzip", "chunked",
}

# Very rough parser for "Apache/2.4.54" or "nginx 1.18.0" style strings.
_RE_PRODUCT_VERSION = re.compile(
    r"^\s*([A-Za-z][\w\-.]*)\s*[/\s]\s*([0-9][\w\-.]*)\s*$"
)


def _split_tech(token: str) -> tuple[str, str | None]:
    """Split a tech string into (product, version) if a version is present.

    Handles common shapes:
      'Apache/2.4.54'     → ('Apache', '2.4.54')
      'nginx 1.18.0'      → ('nginx', '1.18.0')
      'WordPress'         → ('WordPress', None)
    """
    t = (token or "").strip()
    if not t:
        return ("", None)
    m = _RE_PRODUCT_VERSION.match(t)
    if m:
        return (m.group(1), m.group(2))
    return (t, None)


def enrich_webapps_and_services(
    store: KnowledgeStore,
    enricher: CVEEnricher,
    *,
    already_seen: set[str] | None = None,
) -> tuple[Observation, set[str]]:
    """Walk current WebApps + Services and emit CVE Findings for tech we
    haven't looked up yet.

    Returns `(observation, seen)` where `observation` is safe to pass to
    `store.commit()` and `seen` is the updated lookup-dedup set (caller
    should hand the same set back in on the next call).

    The hashing key is `(entity_type, entity_id, cache_key)` so the same
    product on the same host doesn't generate duplicate findings, but the
    same product on a *different* webapp still does (different entity).
    """
    seen = set(already_seen or ())
    obs = Observation(source_tool="cve-enricher")
    if not enricher.enabled:
        return obs, seen

    # --- WebApp tech fingerprints ------------------------------------------
    for w in store.webapps():
        if w.id is None or not w.tech:
            continue
        for token in w.tech:
            product, version = _split_tech(str(token))
            if not product or product.lower() in _TECH_NOISE:
                continue
            key = f"WebApp|{w.id}|{CVEEnricher._cache_key(product, version)}"
            if key in seen:
                continue
            seen.add(key)
            recs = enricher.lookup(product, version)
            for r in recs:
                obs.evidence.append(_evidence_for(r))
                obs.findings.append(_finding_for(r, entity_type="WebApp", entity_id=w.id,
                                                product=product, version=version))

    # --- Service product/version fingerprints (from nmap -sV etc.) ---------
    for s in store.services():
        if s.id is None or not s.product:
            continue
        product = s.product
        version = s.version
        key = f"Service|{s.id}|{CVEEnricher._cache_key(product, version)}"
        if key in seen:
            continue
        seen.add(key)
        recs = enricher.lookup(product, version)
        for r in recs:
            obs.evidence.append(_evidence_for(r))
            obs.findings.append(_finding_for(r, entity_type="Service", entity_id=s.id,
                                            product=product, version=version))

    return obs, seen


def _evidence_for(r: CVERecord) -> Evidence:
    lines = [
        f"CVE ID:   {r.cve_id}",
        f"CVSS v3:  {r.cvss_v3} ({r.cvss_severity})",
        f"Exploit:  {'yes' if r.has_exploit else 'no (per NVD refs)'}",
        f"Pub:      {r.published or 'unknown'}",
        f"Summary:  {r.summary}",
    ]
    if r.references:
        lines.append("Refs:")
        for u in r.references:
            lines.append(f"  - {u}")
    return Evidence(raw_excerpt="\n".join(lines))


def _finding_for(
    r: CVERecord, *, entity_type: str, entity_id: int,
    product: str, version: str | None,
) -> Finding:
    sev = _sev_for_cvss(r.cvss_v3)
    title = f"{r.cve_id}: {product}{(' ' + version) if version else ''}"
    confidence = 0.95 if r.cvss_v3 else 0.6
    description = r.summary or "Vulnerability reported in NVD."
    rec = (
        "Upgrade to a patched release of the affected component. Consult the "
        "referenced advisory links for vendor guidance and confirmed fixed "
        "versions. Until patching is possible, restrict network exposure "
        "and apply compensating controls (WAF rules, IDS signatures)."
    )
    return Finding(
        kind="cve",
        severity=sev,
        entity_type=entity_type,
        entity_id=entity_id,
        confidence=confidence,
        title=title,
        description=description,
        recommendation=rec,
        source_tool="cve-enricher",
        template_id=r.cve_id,
    )
