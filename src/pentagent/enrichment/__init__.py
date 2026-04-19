"""Post-commit enrichment — turn raw tool output into actionable intel.

Today this module provides:
  - `cve`: correlates detected products/versions against NVD and produces
    Finding objects with CVSS scores, exploit-availability hints, and ref
    links. Safe to call repeatedly — lookups are cached on disk per session.

Planned:
  - `exploitdb`: searchsploit-style lookup against the local ExploitDB mirror
    if installed, otherwise a GitHub-hosted index. Attaches local PoC
    paths to matching Findings.
  - `wappalyzer_offline`: enrich WebApp.tech from JS fingerprints when
    httpx didn't have the patterns it needed.
"""
from .cve import CVEEnricher, CVERecord, enrich_webapps_and_services

__all__ = ["CVEEnricher", "CVERecord", "enrich_webapps_and_services"]
