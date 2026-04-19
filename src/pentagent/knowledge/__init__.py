"""Static knowledge bases — MITRE ATT&CK, OWASP, CWE, CVE enrichment.

These are *data* modules. They don't talk to the network on import; any
online lookup (NVD, ExploitDB) is encapsulated in enrichment clients with
offline fallbacks so a pentagent run with no internet still produces
sensible output.
"""
from .mitre import (
    ATTACK_TACTIC,
    FINDING_MAPPING,
    TOOL_TECHNIQUES,
    map_finding,
    map_tool,
)

__all__ = [
    "ATTACK_TACTIC",
    "FINDING_MAPPING",
    "TOOL_TECHNIQUES",
    "map_finding",
    "map_tool",
]
