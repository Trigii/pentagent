"""MITRE ATT&CK + OWASP + CWE mappings.

Two independent maps:

1. `TOOL_TECHNIQUES` — each tool we invoke maps to one or more MITRE
   ATT&CK technique IDs + a primary tactic. This is used by the report's
   "techniques exercised" matrix and by the audit log so each tool-run
   is annotated with what it's doing in standard terminology.

2. `FINDING_MAPPING` — each finding *kind* (free-form string like "xss",
   "sqli", "open-redirect", "default-creds") maps to CWE id, OWASP Top 10
   (2021) category, and primary MITRE ATT&CK technique. Used by the report
   to give each finding a standards lineage.

Both maps are conservative — when a tool's technique is ambiguous we pick
the *primary* tactic (e.g. nmap is Reconnaissance, not Discovery — it's
external pre-compromise enumeration). For a real red-team audit you may
want to expand these; the structure is designed to be easy to extend.

References:
  - ATT&CK Enterprise: https://attack.mitre.org/techniques/enterprise/
  - ATT&CK PRE (pre-compromise): https://attack.mitre.org/matrices/enterprise/PRE/
  - OWASP Top 10 2021: https://owasp.org/Top10/
  - CWE: https://cwe.mitre.org/data/index.html
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# MITRE ATT&CK tactics we reference. The IDs are stable; the string labels
# match the ATT&CK navigator tactic column headers.
ATTACK_TACTIC: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


@dataclass(frozen=True)
class ToolAttack:
    """How a tool maps onto the ATT&CK framework."""
    primary_tactic: str                   # one of ATTACK_TACTIC keys
    techniques: tuple[str, ...]           # technique IDs ("T1595.001" etc.)
    description: str = ""


# Canonical tool → ATT&CK mapping.
# Techniques chosen to reflect the *dominant* behavior of the tool when run
# unauthenticated against an external target during a pentest/bug bounty.
TOOL_TECHNIQUES: dict[str, ToolAttack] = {
    # --- Reconnaissance (TA0043) --------------------------------------------
    "subfinder": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1590.005", "T1596.001"),
        description="Gather victim infrastructure: DNS (T1590.005), "
                    "Search Open Technical Databases: DNS/Passive DNS (T1596.001)",
    ),
    "amass": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1590.005", "T1595.002", "T1596.001"),
        description="Passive + active DNS enumeration, vulnerability scanning",
    ),
    "dnsx": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1590.005",),
        description="DNS resolution batch",
    ),
    "waybackurls": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1593.003",),
        description="Search Open Websites/Domains: Code Repositories (archival URLs)",
    ),
    "gau": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1593.003",),
        description="GetAllUrls from archives + CT logs",
    ),
    "theharvester": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1589.001", "T1589.002"),
        description="Gather victim identity: credentials/email addresses",
    ),

    # --- Reconnaissance → Discovery (TA0043 + TA0007) -----------------------
    "nmap": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.001", "T1595.002", "T1046"),
        description="Active scanning: scanning IP blocks (T1595.001) + "
                    "vulnerability scanning (T1595.002); also Network Service "
                    "Discovery (T1046)",
    ),
    "masscan": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.001", "T1046"),
        description="High-speed active IP/port scanning",
    ),
    "naabu": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.001", "T1046"),
    ),
    "rustscan": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.001", "T1046"),
    ),

    # --- Reconnaissance: web triage + content disc. -------------------------
    "httpx": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.002", "T1592.004"),
        description="HTTP probe + tech fingerprint: vulnerability scanning "
                    "(T1595.002), Client Configurations (T1592.004)",
    ),
    "whatweb": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1592.004", "T1595.002"),
    ),
    "wafw00f": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.002",),
    ),
    "ffuf": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.003",),
        description="Active scanning: Wordlist Scanning (T1595.003) — "
                    "brute-forcing URL paths",
    ),
    "gobuster": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.003",),
    ),
    "feroxbuster": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.003",),
    ),
    "dirsearch": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.003",),
    ),
    "katana": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1593.002", "T1595.002"),
        description="Link + JS crawl of reachable web content",
    ),
    "hakrawler": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1593.002",),
    ),

    # --- Vuln scanning ------------------------------------------------------
    "nuclei": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.002",),
        description="Template-driven vulnerability scanning",
    ),
    "nikto": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.002",),
    ),
    "wpscan": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.002", "T1589.001"),
    ),
    "trivy": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.002",),
    ),
    "testssl": ToolAttack(
        primary_tactic="TA0043",
        techniques=("T1595.002",),
    ),

    # --- Exploit-phase tools (post-compromise or interactive) --------------
    "sqlmap": ToolAttack(
        primary_tactic="TA0001",
        techniques=("T1190",),
        description="Exploit Public-Facing Application via SQL injection",
    ),
    "hydra": ToolAttack(
        primary_tactic="TA0006",
        techniques=("T1110.001", "T1110.003"),
        description="Brute force: password guessing / password spraying",
    ),
    "medusa": ToolAttack(
        primary_tactic="TA0006",
        techniques=("T1110.001", "T1110.003"),
    ),
    "metasploit": ToolAttack(
        primary_tactic="TA0002",
        techniques=("T1190", "T1210"),
        description="Exploitation of Public-Facing Application / Remote Services",
    ),
    "crackmapexec": ToolAttack(
        primary_tactic="TA0008",
        techniques=("T1021.002", "T1210"),
        description="Remote Services: SMB/Windows Admin Shares",
    ),
    "nxc": ToolAttack(
        primary_tactic="TA0008",
        techniques=("T1021.002", "T1210"),
    ),
    "kerbrute": ToolAttack(
        primary_tactic="TA0006",
        techniques=("T1110.003", "T1558.003"),
        description="Kerberos pre-auth brute / AS-REP roasting user enum",
    ),
    "bloodhound": ToolAttack(
        primary_tactic="TA0007",
        techniques=("T1087.002", "T1069.002", "T1482"),
        description="Domain trust / account / group discovery via LDAP",
    ),
    "impacket-secretsdump": ToolAttack(
        primary_tactic="TA0006",
        techniques=("T1003.002", "T1003.003"),
        description="OS Credential Dumping: SAM / NTDS",
    ),
    "impacket-psexec": ToolAttack(
        primary_tactic="TA0008",
        techniques=("T1021.002",),
    ),
    "responder": ToolAttack(
        primary_tactic="TA0006",
        techniques=("T1557.001", "T1187"),
        description="LLMNR/NBT-NS poisoning + forced authentication",
    ),
}


def map_tool(tool: str) -> dict[str, Any]:
    """Return an ATT&CK dict for `tool`, or an empty-but-typed fallback.

    Callers should never need to None-check; missing tools get an empty
    tuple of techniques so `len(x["techniques"]) == 0` works uniformly.
    """
    if not tool:
        return {"tactic_id": "", "tactic": "", "techniques": (), "description": ""}
    t = TOOL_TECHNIQUES.get(tool.strip().lower())
    if not t:
        return {"tactic_id": "", "tactic": "", "techniques": (), "description": ""}
    return {
        "tactic_id": t.primary_tactic,
        "tactic": ATTACK_TACTIC.get(t.primary_tactic, ""),
        "techniques": t.techniques,
        "description": t.description,
    }


# --- Finding-kind → standards lineage ---------------------------------------

@dataclass(frozen=True)
class FindingStandards:
    """Standards metadata for a finding kind. All optional — unknown kinds
    return empty strings so reports don't need to guard."""
    cwe: str = ""                         # "CWE-89"
    owasp_2021: str = ""                  # "A03:2021 – Injection"
    attack_technique: str = ""            # "T1190"
    description: str = ""


# Keys are lowercased; the `map_finding()` wrapper does the lowering.
FINDING_MAPPING: dict[str, FindingStandards] = {
    # Injection (OWASP A03)
    "sqli": FindingStandards(
        cwe="CWE-89",
        owasp_2021="A03:2021 – Injection",
        attack_technique="T1190",
        description="SQL injection — server-side interpreter abuse",
    ),
    "sql-injection": FindingStandards(
        cwe="CWE-89", owasp_2021="A03:2021 – Injection", attack_technique="T1190",
    ),
    "nosqli": FindingStandards(
        cwe="CWE-943", owasp_2021="A03:2021 – Injection", attack_technique="T1190",
    ),
    "command-injection": FindingStandards(
        cwe="CWE-78", owasp_2021="A03:2021 – Injection", attack_technique="T1190",
    ),
    "cmdi": FindingStandards(
        cwe="CWE-78", owasp_2021="A03:2021 – Injection", attack_technique="T1190",
    ),
    "ldap-injection": FindingStandards(
        cwe="CWE-90", owasp_2021="A03:2021 – Injection", attack_technique="T1190",
    ),
    "xxe": FindingStandards(
        cwe="CWE-611", owasp_2021="A05:2021 – Security Misconfiguration",
        attack_technique="T1190",
    ),
    "xss": FindingStandards(
        cwe="CWE-79",
        owasp_2021="A03:2021 – Injection",
        attack_technique="T1059.007",
        description="Cross-site scripting (client-side JS injection)",
    ),
    "stored-xss": FindingStandards(
        cwe="CWE-79", owasp_2021="A03:2021 – Injection", attack_technique="T1059.007",
    ),
    "reflected-xss": FindingStandards(
        cwe="CWE-79", owasp_2021="A03:2021 – Injection", attack_technique="T1059.007",
    ),
    "dom-xss": FindingStandards(
        cwe="CWE-79", owasp_2021="A03:2021 – Injection", attack_technique="T1059.007",
    ),

    # Broken Access Control (OWASP A01)
    "idor": FindingStandards(
        cwe="CWE-639", owasp_2021="A01:2021 – Broken Access Control",
        attack_technique="T1190",
    ),
    "path-traversal": FindingStandards(
        cwe="CWE-22", owasp_2021="A01:2021 – Broken Access Control",
        attack_technique="T1083",
    ),
    "lfi": FindingStandards(
        cwe="CWE-22", owasp_2021="A01:2021 – Broken Access Control",
        attack_technique="T1083",
    ),
    "rfi": FindingStandards(
        cwe="CWE-98", owasp_2021="A01:2021 – Broken Access Control",
        attack_technique="T1190",
    ),
    "open-redirect": FindingStandards(
        cwe="CWE-601", owasp_2021="A01:2021 – Broken Access Control",
        attack_technique="T1566.002",
    ),
    "ssrf": FindingStandards(
        cwe="CWE-918", owasp_2021="A10:2021 – Server-Side Request Forgery",
        attack_technique="T1190",
    ),
    "cors": FindingStandards(
        cwe="CWE-942", owasp_2021="A05:2021 – Security Misconfiguration",
    ),

    # Cryptographic failures (OWASP A02)
    "weak-tls": FindingStandards(
        cwe="CWE-326", owasp_2021="A02:2021 – Cryptographic Failures",
    ),
    "weak-cipher": FindingStandards(
        cwe="CWE-327", owasp_2021="A02:2021 – Cryptographic Failures",
    ),
    "cleartext-transmission": FindingStandards(
        cwe="CWE-319", owasp_2021="A02:2021 – Cryptographic Failures",
    ),

    # Identification & Authentication Failures (OWASP A07)
    "default-creds": FindingStandards(
        cwe="CWE-798", owasp_2021="A07:2021 – Identification and Authentication Failures",
        attack_technique="T1078.001",
        description="Default or well-known credentials accepted",
    ),
    "weak-password": FindingStandards(
        cwe="CWE-521", owasp_2021="A07:2021 – Identification and Authentication Failures",
        attack_technique="T1110.001",
    ),
    "no-mfa": FindingStandards(
        cwe="CWE-308", owasp_2021="A07:2021 – Identification and Authentication Failures",
    ),

    # Security Misconfiguration (OWASP A05)
    "exposed-config": FindingStandards(
        cwe="CWE-200", owasp_2021="A05:2021 – Security Misconfiguration",
        attack_technique="T1082",
    ),
    "exposed-git": FindingStandards(
        cwe="CWE-527", owasp_2021="A05:2021 – Security Misconfiguration",
    ),
    "exposed-env": FindingStandards(
        cwe="CWE-540", owasp_2021="A05:2021 – Security Misconfiguration",
    ),
    "dir-listing": FindingStandards(
        cwe="CWE-548", owasp_2021="A05:2021 – Security Misconfiguration",
    ),
    "info-disclosure": FindingStandards(
        cwe="CWE-200", owasp_2021="A05:2021 – Security Misconfiguration",
    ),
    "default-page": FindingStandards(
        cwe="CWE-1188", owasp_2021="A05:2021 – Security Misconfiguration",
    ),
    "header-missing": FindingStandards(
        cwe="CWE-693", owasp_2021="A05:2021 – Security Misconfiguration",
    ),

    # Vulnerable & Outdated Components (OWASP A06)
    "outdated-software": FindingStandards(
        cwe="CWE-1104", owasp_2021="A06:2021 – Vulnerable and Outdated Components",
    ),
    "cve": FindingStandards(
        cwe="CWE-1395", owasp_2021="A06:2021 – Vulnerable and Outdated Components",
        attack_technique="T1190",
    ),

    # SSRF already covered (A10); include for completeness under 'forgery'
    "csrf": FindingStandards(
        cwe="CWE-352", owasp_2021="A01:2021 – Broken Access Control",
    ),

    # Logging & monitoring (OWASP A09)
    "no-logging": FindingStandards(
        cwe="CWE-778", owasp_2021="A09:2021 – Security Logging and Monitoring Failures",
    ),
}


def map_finding(kind: str) -> dict[str, Any]:
    """Return a dict of standards metadata for a finding `kind`.

    Matching is case-insensitive and tolerant of light synonyms (e.g.
    'sql-injection' vs 'sqli'). Unknown kinds return empty strings so the
    report renders without needing guards.
    """
    if not kind:
        return {"cwe": "", "owasp_2021": "", "attack_technique": "", "description": ""}
    k = kind.strip().lower()
    fs = FINDING_MAPPING.get(k)
    if not fs:
        # A couple of handwritten normalizations
        if "sql" in k and "inject" in k:
            fs = FINDING_MAPPING["sqli"]
        elif k.endswith("-xss") or k == "xss" or "xss" in k:
            fs = FINDING_MAPPING["xss"]
        elif "traversal" in k:
            fs = FINDING_MAPPING["path-traversal"]
    if not fs:
        return {"cwe": "", "owasp_2021": "", "attack_technique": "", "description": ""}
    return {
        "cwe": fs.cwe,
        "owasp_2021": fs.owasp_2021,
        "attack_technique": fs.attack_technique,
        "description": fs.description,
    }
